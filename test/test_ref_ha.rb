# frozen_string_literal: true

# Replays the TS-reference oracle of guardian high availability (test-data/ref-ha.json.gz, 753 cases): liveness, quorum, degrade mode, signer
# selection, failover, the guardian-set validator, the fence guard, the lease op scripts (acquire / renew / release / fence / fenced signer over
# an in-memory store with a settable clock and injected faults) and the raw compare-and-swap of the key/value store. Every fn and every lease
# op has a handler; the totals are asserted.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefHa < Minitest::Test
  A = AtlasPca
  H = AtlasPca::Ha
  BY_FN = Ref.load('ha')
  KEY = 'ha/lease'
  TOTALS = { 'liveGuardians' => 144, 'quorumStatus' => 144, 'selectSigners' => 144, 'failoverPlan' => 144, 'degradeMode' => 70, 'lease' => 45,
             'validateGuardianSet' => 33, 'kvCas' => 17, 'fenceGuard' => 11, 'constants' => 1 }.freeze
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze
  SEEN_OPS = []

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  # A lease store over the reference store with a settable clock and faults injected at read / now / cas, or one lost compare-and-swap.
  class FaultStore
    attr_accessor :clock, :fault, :lose

    def initialize(kvs)
      @kvs = kvs
      @clock = 0
      @fault = 'none'
      @lose = false
    end

    def read = @fault == 'read' ? raise('boom') : @kvs.read
    def now = @fault == 'now' ? raise('boom') : @kvs.now

    def cas(expected, nxt)
      raise 'boom' if @fault == 'cas'

      if @lose
        @lose = false
        return false
      end
      @kvs.cas(expected, nxt)
    end
  end

  def self.lease(ops)
    kv = A::MemoryAtomicKv.new
    st = nil
    kvs = A::KvLeaseStore.new(kv, now: -> { st.clock })
    st = FaultStore.new(kvs)
    refs = {}
    res = ->(x) { x.is_a?(String) ? refs[x] : x }
    ops.map do |op|
      SEEN_OPS << op[0]
      case op[0]
      when 'clock'
        st.clock = op[1]
        nil
      when 'fault'
        op[1] == 'loseCas' ? st.lose = true : st.fault = op[1]
        nil
      when 'raw'
        kv.set(KEY, op[1])
        nil
      when 'read' then kv.get(KEY)
      when 'acquire'
        r = H.acquire_lease(st, op[2], op[3])
        refs[op[1]] = r['lease'] if r['ok']
        r
      when 'renew', 'release'
        r = op[0] == 'renew' ? H.renew_lease(st, res.call(op[1]), op[2]) : H.release_lease(st, res.call(op[1]))
        refs[op[1]] = r['lease'] if r['ok'] && op[1].is_a?(String)
        r
      when 'fence' then op[2].nil? ? H.assert_fence(st, res.call(op[1])) : H.assert_fence(st, res.call(op[1]), op[2])
      when 'signer'
        lease = op[1].nil? ? nil : res.call(op[1])
        sign = lambda do
          st.clock += op[3]
          raise 'sign' if op[4]

          'signed'
        end
        f = op[2].nil? ? H.fenced_signer(st, -> { lease }, sign) : H.fenced_signer(st, -> { lease }, sign, op[2])
        begin
          r = f.call
          { 'ok' => true, 'result' => r['result'], 'epoch' => r['epoch'] }
        rescue H::FenceError => e
          { 'ok' => false, 'reason' => e.reason }
        rescue RuntimeError => e
          { 'ok' => false, 'error' => e.message }
        end
      else { '$err' => 'bad op' }
      end
    end
  end

  def self.kv_cas(prev, exp, nxt)
    kv = A::MemoryAtomicKv.new
    kv.set(KEY, prev) unless prev.nil?
    ok = A::KvLeaseStore.new(kv, now: -> { 0 }).cas(exp, nxt)
    { 'ok' => ok, 'stored' => kv.get(KEY) }
  end

  def self.fence_guard(init, epochs)
    g = A::Ha.create_fence_guard(init.nil? ? 0 : init)
    { 'admits' => epochs.map { |e| g.admit(e) }, 'highest' => g.highest }
  end

  HANDLERS = {
    'liveGuardians' => ->(s, n, o) { H.live_guardians(s, n, o.nil? ? {} : o) },
    'quorumStatus' => ->(s, n, o) { H.quorum_status(s, n, o.nil? ? {} : o) },
    'selectSigners' => ->(s, n, o) { H.select_signers(s, n, o.nil? ? {} : o) },
    'failoverPlan' => ->(s, n, o) { H.failover_plan(s, n, o.nil? ? {} : o) },
    'degradeMode' => ->(st, p) { H.degrade_mode(st, p.nil? ? {} : p) },
    'validateGuardianSet' => ->(s) { H.validate_guardian_set(s) },
    'fenceGuard' => ->(init, epochs) { fence_guard(init, epochs) },
    'lease' => ->(ops) { lease(ops) },
    'constants' => -> { { 'MAX_LEASE_TTL_MS' => H::MAX_LEASE_TTL_MS, 'DEFAULT_LEASE_SKEW_MS' => H::DEFAULT_LEASE_SKEW_MS } },
    'kvCas' => ->(prev, exp, nxt) { kv_cas(prev, exp, nxt) }
  }.freeze

  def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 753, BY_FN.values.sum(&:length)
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      ran = Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| self.class.dnum(a) }) })
      assert_equal TOTALS.fetch(fn), ran
    end
  end

  def test_every_lease_op_was_replayed
    test_replay_lease
    assert_equal %w[acquire bogus clock fault fence read release renew signer raw].sort, SEEN_OPS.uniq.sort
  end

  # ICU root collation orders what the Latin-text approximation cannot (the order within punctuation); skipped where ffi-icu / libicu is absent
  def test_guardian_ids_order_by_icu_root_collation_when_it_is_available
    skip 'ffi-icu / libicu is not available' unless AtlasPca::Collation.available?
    assert_equal(-1, AtlasPca::Collation.compare('a_b', 'a-b'))
    assert_equal(1, AtlasPca::Collation.compare('a-b', 'a_b'))
    assert_equal(-1, AtlasPca::Collation.compare('a', 'A'))
    assert_equal(-1, AtlasPca::Collation.compare('A', 'b'))
    assert_equal(0, AtlasPca::Collation.compare('same', 'same'))
    assert_nil AtlasPca::Collation.compare("\xff", 'a')
    assert_equal(-1, AtlasPca::Ha.locale_compare('g_1', 'g-1'))
  end

  def test_the_collation_module_never_raises_without_icu
    assert_nil AtlasPca::Collation.compare(1, 'a')
    assert_nil AtlasPca::Collation.compare('a', nil)
  end

end
