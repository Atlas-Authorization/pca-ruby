# frozen_string_literal: true

# Replays the TS-reference oracle of the liveness beacons (test-data/ref-beacons.json.gz, 174 cases): issuing a beacon under the Ed25519, ML-DSA-65
# and hybrid suites (byte for byte), the signed message, the beacon reference, verification (every refusal reason compared exactly, odd clocks and
# issuer lists included), monotonic acceptance, the frozen-liveness check, the durable acceptor over an atomic kv (replay, per-scope / issuer /
# instance independence, a failing store, junk in the sequence slot) and its constructor. Every fn has a handler and the totals are asserted.
# Encodings: {"$num": ...} a non-finite number; {"$bytes": {"$seed": label}} the 32-byte Ed25519 secret; a suite is {alg, pqSeed?}. The one case the
# reference accepts only through its `allowUnboundPq` switch (a PQ beacon whose issuer key is not pinned) is asserted REFUSED. Cases that sign or verify
# with ML-DSA need a runtime that has it (OpenSSL >= 3.5).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefBeacons < Minitest::Test
  A = AtlasPca
  B = AtlasPca::BeaconsApi
  BY_FN = Ref.load('beacons')
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze
  PQ = A.supported_suites.include?('ml-dsa-65')

  # a kv whose next update can be made to fail (the reference's `["fail"]` op)
  class FlakyKv
    def initialize = (@kv = A.create_memory_durable_kv) && (@fail = false)
    def fail_next! = @fail = true
    def set(k, v) = @kv.set(k, v)

    def update(k, &blk)
      if @fail
        @fail = false
        raise 'store down'
      end
      @kv.update(k, &blk)
    end
  end

  class FnKv
    def update(*) = nil
  end

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  def self.issue(args)
    a = args.dup
    if a['suite'].is_a?(Hash)
      s = a['suite'].dup
      s['pq'] = A::PqKeyPair.from_seed('ML-DSA-65', s['pqSeed']) if s['pqSeed']
      a['suite'] = s
    end
    B.issue_liveness_beacon(a)
  end

  def self.acceptor(ops)
    kv = FlakyKv.new
    acc = B.create_beacon_acceptor(kv)
    ops.map do |op, b, extra|
      case op
      when 'accept' then acc.accept(b, extra)
      when 'raw' then kv.set(B::Acceptor.slot(b), extra) && nil
      when 'fail' then kv.fail_next! && nil
      else { '$err' => 'op' }
      end
    end
  end

  def self.ctor(spec)
    kv = case spec
         when 'ok' then A.create_memory_durable_kv
         when Hash then spec['update'] == 'fn' ? FnKv.new : Object.new
         end
    B.create_beacon_acceptor(kv)
    { 'built' => true }
  rescue TypeError
    { 'built' => false }
  end

  HANDLERS = {
    'constants' => -> { { 'GLOBAL_SCOPE' => B::GLOBAL_SCOPE, 'BEACON_EPOCH_MS' => B::BEACON_EPOCH_MS, 'BEACON_MAX_VALIDITY_MS' => B::BEACON_MAX_VALIDITY_MS, 'BEACON_CLOCK_SKEW_MS' => B::BEACON_CLOCK_SKEW_MS } },
    'issueLivenessBeacon' => ->(a) { issue(a) },
    'livenessBeaconMessage' => ->(b) { { '$bytes' => Ref.b64e(B.liveness_beacon_message(b)) } },
    'beaconRef' => ->(b) { B.beacon_ref(b) },
    'verifyLivenessBeacon' => ->(b, o) { B.verify_liveness_beacon(b, o) },
    'acceptBeacon' => ->(prev, nxt) { B.accept_beacon(prev, nxt) },
    'isFrozenLiveness' => ->(bs, o) { B.frozen_liveness?(bs, o) },
    'acceptor' => ->(ops) { acceptor(ops) },
    'ctor' => ->(spec) { ctor(spec) }
  }.freeze

  TOTALS = { 'constants' => 1, 'issueLivenessBeacon' => 36, 'livenessBeaconMessage' => 12, 'beaconRef' => 8, 'verifyLivenessBeacon' => 67, 'acceptBeacon' => 18,
             'isFrozenLiveness' => 8, 'acceptor' => 19, 'ctor' => 5 }.freeze

  def self.pq_case?(c) = Ref.canon(c['args']).match?(/ml-dsa/)

  # the case the reference accepts only through allowUnboundPq
  def self.unbound?(c) = c['fn'] == 'verifyLivenessBeacon' && c['args'][1]['allowUnboundPq'] == true && c['out'].is_a?(Hash) && c['out']['ok'] == true

  def self.same?(got, out, c)
    return got == { 'ok' => false, 'reason' => 'bad signature' } if unbound?(c)

    Ref.canon(got) == Ref.canon(out)
  end

  def test_every_fn_of_the_corpus_has_a_handler_and_the_totals_are_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 174, BY_FN.values.sum(&:length)
    assert_equal 1, BY_FN.values.flatten.count { |c| self.class.unbound?(c) }, 'the cases the reference accepts only under allowUnboundPq'
  end

  def test_the_post_quantum_cases_run_where_required
    assert PQ, 'this runtime must have ML-DSA-65' if ENV['PCA_REQUIRE_PQ'] == '1'
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      k = self.class
      Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| k.dnum(a) }) }, skip: ->(c) { (!PQ && k.pq_case?(c)) },
              compare: ->(got, out, c) { k.same?(got, out, c) })
    end
  end
end
