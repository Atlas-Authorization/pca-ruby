# frozen_string_literal: true

# Replays the TS-reference oracle of networked FROST signing (test-data/ref-frost-net.json.gz, 634 cases): the allow token, the signer proof of
# possession, enrollment, the equivocation guard, the wire decoders, the signer service (round 1 / round 2, the nonce store, restarts, the stale-session
# guard), the network coordinator (scripted signers: delays, unreachable transports, hostile rewrites of a response, canned replies), the nonce-store
# contract (the memory store and stores with exactly one defect), the group-algorithm registry, the signer-set digest, the hybrid co-sign and the post-quantum
# quorum. Every fn has a handler and the totals are asserted. Encodings: {"$bytes": ...} bytes ({"$seed": label} the 32 bytes sha256("atlas-pca-conformance/"
# + label)); {"$share": {t, n, secret, coefficients, identifiers, id}} the trusted-dealer share of participant `id`; {"$rng": [...]} as the LAST argument the
# 32-byte values the reference drew, in draw order (fed to the randomness seam of the call); {"$num": ...} a non-finite number. A refusal is {"$throws": message,
# class?, ...fields}: the native must refuse, a typed error's class and fields compare exactly, the message is informative; "reasonOpen": true on a refusal
# reason marks library text (the native must refuse there, the text is not compared); the "(fail closed): <detail>" tail of an allow-token reason is open.
# Cases that sign or verify with ML-DSA need a runtime that has it (OpenSSL >= 3.5).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefFrostNet < Minitest::Test
  A = AtlasPca
  FN = AtlasPca::FrostNet
  FP = AtlasPca::FrostPqApi
  NS = AtlasPca::FrostNonceStore
  PT = AtlasPca::PqThreshold
  BY_FN = Ref.load('frost-net')
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze
  PQ = A.supported_suites.include?('ml-dsa-65')
  SHARES = {}

  # ---- argument hydration -----------------------------------------------------------------------------------------------------

  def self.dealer_share(d)
    key = d.inspect
    SHARES[key] ||= begin
      kg = A::Frost.trusted_dealer_keygen(d['t'], d['n'], d['secret'], d['coefficients'], d['identifiers'])
      kg['participantShares'].find { |p| p['identifier'] == d['id'] }['share']
    end
  end

  def self.hydrate(v)
    case v
    when Hash
      return dealer_share(v['$share']) if v.size == 1 && v.key?('$share')
      return NUM.fetch(v['$num']) if v.size == 1 && v.key?('$num')

      v.transform_values { |x| hydrate(x) }
    when Array then v.map { |x| hydrate(x) }
    else v
    end
  end

  # the trailing {"$rng": [...]} argument as a randomness seam (a draw past the script is a bug)
  def self.split_rng(args)
    last = args.last
    return [args, nil] unless last.is_a?(Hash) && last.key?('$rng')

    [args[0...-1], queue(last['$rng'])]
  end

  def self.queue(values)
    q = values.dup
    ->(_n = 32) { q.shift || raise('a draw past the randomness script') }
  end

  # ---- output encoding and comparison ------------------------------------------------------------------------------------------

  def self.enc(v)
    case v
    when String then v.encoding == Encoding::BINARY ? { '$bytes' => Ref.b64e(v) } : v
    when Hash then v.transform_values { |x| enc(x) }
    when Array then v.map { |x| enc(x) }
    else v
    end
  end

  def self.err_out(e)
    o = { '$throws' => e.message }
    case e
    when FN::PoPError then o.merge!('class' => 'PoPError', 'identifier' => e.identifier).compact!
    when FN::EquivocationError
      o.merge!('class' => 'EquivocationError', 'session_id' => e.session_id, 'round' => e.round, 'identifier' => e.identifier, 'previousDigest' => e.previous_digest,
               'offendingDigest' => e.offending_digest)
    when FN::CoordinatorTimeoutError
      o.merge!('class' => 'CoordinatorTimeoutError', 'refusals' => e.refusals, 'timeoutMs' => e.timeout_ms)
    when FN::CoordinatorError then o.merge!('class' => 'CoordinatorError', 'refusals' => e.refusals)
    end
    o
  end

  def self.capture
    enc(yield)
  rescue StandardError => e
    enc(err_out(e))
  end

  # got equals out, where a refusal's message text and the open reason text are not compared
  def self.eq(got, out)
    case out
    when Hash
      return false unless got.is_a?(Hash)

      if out.key?('$throws')
        return got.key?('$throws') && eq(got.reject { |k, _| k == '$throws' }, out.reject { |k, _| k == '$throws' })
      end
      if out['reasonOpen']
        return got['reason'].is_a?(String) && eq(got.reject { |k, _| k == 'reason' }, out.reject { |k, _| %w[reason reasonOpen].include?(k) })
      end
      if out['reason'].is_a?(String) && out['reason'].start_with?('allow token verification error (fail closed)')
        return got['reason'].to_s.start_with?('allow token verification error (fail closed)') && eq(got.reject { |k, _| k == 'reason' }, out.reject { |k, _| k == 'reason' })
      end
      got.keys.sort == out.keys.sort && out.all? { |k, v| eq(got[k], v) }
    when Array then got.is_a?(Array) && got.length == out.length && got.each_with_index.all? { |g, i| eq(g, out[i]) }
    when Float then got.is_a?(Numeric) && got == out
    else got == out
    end
  end

  # ---- handlers ----------------------------------------------------------------------------------------------------------------

  def self.guard(ops)
    g = FN::EquivocationGuard.new
    ops.map do |op|
      case op['op']
      when 'observe' then g.observe(op['session_id'], op['round'], op['identifier'], op['message'])
      when 'forget' then g.forget(op['session_id'])
      else raise 'bad op'
      end
      { 'ok' => true }
    rescue StandardError => e
      err_out(e)
    end
  end

  def self.store_run(ops)
    s = NS::MemoryNonceStore.new
    ops.map do |op|
      case op['op']
      when 'create'
        s.create(op['sid'], op['rec'])
        %w[hiding hidingCommitment].each { |k| op['rec'][k].replace("\xEE".b * 32) } if op['mutateInputAfter']
        { 'ok' => true }
      when 'load'
        r = s.load(op['sid'])
        out = { 'value' => r.nil? ? nil : Marshal.load(Marshal.dump(r)) } # the answer as the reference serialized it, before the caller scribbles on it
        r.each_value { |x| x.is_a?(String) && x.replace("\xEE".b * x.bytesize) } if r && op['mutate']
        out
      when 'spend'
        s.spend(op['sid'])
        { 'ok' => true }
      when 'drop'
        s.drop(op['sid'])
        { 'ok' => true }
      when 'isSpent' then { 'value' => s.spent?(op['sid']) }
      else raise 'bad op'
      end
    rescue StandardError => e
      err_out(e)
    end
  end

  # a store with exactly one defect (the contract must catch it)
  class BrokenStore
    def initialize(kind)
      @kind = kind
      @live = {}
      @spent = {}
    end

    attr_reader :kind

    def cp(r) = r.transform_values { |x| x.is_a?(String) ? x.dup : x }

    def create(id, r)
      raise 'exists' if @kind != 'create-overwrites' && @live.key?(id)
      raise 'spent' if @kind != 'create-over-spent' && @spent.key?(id)

      @live[id] = @kind == 'create-aliases-input' ? r : cp(r)
      nil
    end

    def load(id)
      r = @live[id]
      return nil unless r

      @kind == 'load-aliases' ? r : cp(r)
    end

    def spend(id)
      unless @live.key?(id)
        return nil if @kind == 'spend-unknown-ok' || (@kind == 'spend-twice-ok' && @spent.key?(id))

        raise 'not live'
      end
      @live.delete(id)
      @spent[id] = true
      nil
    end

    def drop(id)
      @live.delete(id)
      @spent[id] = true if @kind == 'drop-marks-spent'
      nil
    end

    def spent?(id) = @kind == 'unknown-reports-spent' ? true : @spent.key?(id)

    def reopen
      @spent.clear if @kind == 'spent-forgotten-on-restart'
      @live.clear if @kind == 'live-lost-on-restart'
      self
    end
  end

  def self.contract(a)
    if a['store'] == 'memory'
      NS.assert_nonce_store_contract(-> { NS::MemoryNonceStore.new })
    else
      b = BrokenStore.new(a['store'].delete_prefix('broken:'))
      NS.assert_nonce_store_contract(-> { b }, ->(s) { s.reopen })
    end
    nil
  end

  class FailStore < NS::MemoryNonceStore
    def initialize(method_name)
      super()
      @fail = method_name
    end

    %i[create load spend drop].each do |m|
      define_method(m) do |*a|
        raise 'store down' if @fail == m.to_s

        super(*a)
      end
    end

    def spent?(id)
      raise 'store down' if @fail == 'isSpent'

      super
    end
  end

  def self.mk_store(k)
    return nil if k.nil? || k == 'none'
    return NS::MemoryNonceStore.new if k == 'memory'
    return Struct.new(:x) { def create(*) = nil; def load(*) = nil; def drop(*) = nil; def spent?(*) = nil }.new(0) if k == 'invalid-no-spend'
    return FailStore.new(k.delete_prefix('fail-')) if k.start_with?('fail-')

    raise "store #{k}"
  end

  def self.service(cfg, store, clock, random)
    FN::GuardianSignerService.new(identifier: cfg['identifier'], share: cfg['share'], group_public_key: cfg['groupPublicKey'], threshold: cfg['threshold'],
                                  policy_authority_public_key: cfg['policyAuthorityPublicKey'], session_ttl_ms: cfg['sessionTtlMs'], now: clock, nonce_store: store, random: random)
  end

  def self.signer_service(cfg, steps, random)
    clock = cfg['clock'] || 1_000_000
    store = mk_store(cfg['store'])
    out = { 'ctor' => nil, 'steps' => [] }
    mk = -> { service(cfg, store, -> { clock }, random) }
    begin
      svc = mk.call
      out['ctor'] = enc({ 'verificationShare' => svc.verification_share, 'pop' => svc.proof_of_possession, 'enrollment' => svc.enrollment })
    rescue StandardError => e
      out['ctor'] = enc(err_out(e))
      return out
    end
    steps.each do |st|
      case st['op']
      when 'round1' then out['steps'] << enc(svc.round1(st['req']))
      when 'round2' then out['steps'] << enc(svc.round2(st['req']))
      when 'clock'
        clock += st['ms']
        out['steps'] << { 'clock' => clock }
      when 'restart'
        svc = mk.call
        out['steps'] << { 'restarted' => true, 'pop' => svc.proof_of_possession }
      when 'storeLoad' then out['steps'] << { 'live' => !store.load(st['sid']).nil? }
      when 'storeIsSpent' then out['steps'] << { 'spent' => store.spent?(st['sid']) }
      else raise 'bad step'
      end
    rescue StandardError => e
      out['steps'] << enc(err_out(e))
    end
    out
  end

  # a scripted transport: delays, unreachable, hostile rewrites of a response, canned replies, or a real signer service
  class ScriptedTransport
    attr_reader :identifier

    def initialize(spec, clock)
      @spec = spec
      @clock = clock
      @identifier = spec['identifier']
      @counters = { 'r1' => 0, 'r2' => 0 }
      @service = spec['canned'] ? nil : TestRefFrostNet.service(spec, TestRefFrostNet.mk_store(spec['store']), -> { 1_000_000 }, TestRefFrostNet.queue(spec['rng']))
      @lock = Mutex.new
    end

    def round1(req) = respond(1, req)
    def round2(req) = respond(2, req)

    def respond(round, req)
      key = round == 1 ? 'r1' : 'r2'
      n = @lock.synchronize { (@counters[key] += 1) - 1 }
      @clock.sleep(@spec['delay'][key]) if @spec['delay'] && @spec['delay'][key]
      raise 'unreachable' if @spec['throws'] && @spec['throws'][key]

      if @spec['canned']
        c = @spec['canned'][round == 1 ? 'round1' : 'round2'][n]
        raise 'unreachable' if c == 'throw' || c.nil?

        resp = c
      else
        resp = JSON.parse(JSON.generate(TestRefFrostNet.enc(round == 1 ? @service.round1(req) : @service.round2(req))))
      end
      edits(resp, round)
    end

    def edits(resp, round)
      r = JSON.parse(JSON.generate(resp))
      (@spec['edits'] || []).each do |e|
        next unless e['round'] == round

        path = e['path']
        parent = path[0...-1].reduce(r) { |a, k| a.is_a?(Hash) ? a[k] : nil }
        key = path.last
        next unless parent.is_a?(Hash)

        case e['op']
        when 'set' then parent[key] = e['value']
        when 'delete' then parent.delete(key)
        when 'flip'
          b = A.b64d(parent[key])
          b.setbyte(0, b.getbyte(0) ^ 1)
          parent[key] = A.b64e(b)
        end
      end
      r
    end
  end

  # virtual time of a coordinator replay: no case waits on the wall clock. The deadline and every transport delay start at virtual time 0, so a delay
  # longer than the deadline lets the deadline fire first (the delayed transport stays blocked until the case ends); any other delay returns at once.
  class FakeClock
    def initialize
      @deadline = nil
      @queue = nil
      @fired = false
      @end = Thread::Queue.new
      @lock = Mutex.new
    end

    def new_timer(ms, queue)
      @lock.synchronize { @deadline = ms; @queue = queue; @fired = false }
    end

    # a call with no session window: a delay just elapses
    def reset = @lock.synchronize { @deadline = nil }

    def sleep(ms)
      late = @lock.synchronize { @deadline && ms > @deadline }
      return unless late

      fire = @lock.synchronize { (@fired ? false : (@fired = true)) }
      @queue << [:expired, nil] if fire
      @end.pop
    end

    def release = @end.close
  end

  def self.coordinator(cfg)
    out = { 'calls' => [] }
    clock = FakeClock.new
    transports = cfg['signers'].map { |s| ScriptedTransport.new(s, clock) }
    sids = (cfg['sessionIds'] || []).dup
    begin
      kw = { group_public_key: cfg['groupPublicKey'], threshold: cfg['threshold'], signers: transports, timeout_ms: cfg['timeoutMs'], new_timer: clock.method(:new_timer),
             new_session_id: -> { sids.shift || raise('no more scripted session ids') } }
      kw[:verification_shares] = cfg['verificationShares'] if cfg.key?('verificationShares')
      kw[:enroll] = cfg['enroll'] if cfg.key?('enroll')
      coord = FN::NetworkCoordinator.new(**kw)
    rescue StandardError => e
      out['ctor'] = enc(err_out(e))
      return out
    end
    cfg['calls'].each do |c|
      clock.reset
      r = coord.sign(c['message'], c['allow'], signer_ids: c['signerIds'], timeout_ms: c['timeoutMs'])
      out['calls'] << enc({ 'signature' => r['signature'], 'sessionId' => r['sessionId'], 'signers' => r['signers'] })
    rescue StandardError => e
      out['calls'] << enc(err_out(e))
    end
    out
  ensure
    clock&.release
  end

  def self.sign_hybrid(gpk, quorum, message, opts)
    o = opts.dup
    o['guardianMlDsa'] = A::PqKeyPair.from_seed('ML-DSA-65', o.delete('guardianMlDsaSeed')) if o['guardianMlDsaSeed']
    o['guardianMlDsa'] = nil if o.key?('guardianMlDsa') && o['guardianMlDsa'] == {}
    r = FP.sign_hybrid_frost_cosign(gpk, quorum, message, o)
    r.merge('sigVerifies' => A.verify_b64u(A.b64e(gpk), message, r['sig']), 'sigLength' => A.b64d(r['sig']).bytesize).reject { |k, _| k == 'sig' }
  end

  def self.sign_pq_quorum(message, seeds, pq_t)
    PT.sign_pq_quorum(message, seeds.map { |s| A::PqKeyPair.from_seed('ML-DSA-65', s) }, pq_t)
  end

  HANDLERS = {
    'constants' => ->(*) { FP.constants_view },
    # the reference takes bytes (a Uint8Array): a corpus value that is text (a UTF-8 String, not the binary of a {$bytes} member) is refused
    'frostActionDigest' => ->(m) { raise TypeError, 'frostActionDigest: message must be bytes' if m.is_a?(String) && m.encoding != Encoding::BINARY; FN.frost_action_digest(m) },
    'issueAllowToken' => ->(secret, opts, rng) { FN.issue_allow_token(secret, opts, random: rng) },
    'verifyAllowToken' => ->(token, expect) { FN.verify_allow_token(token, expect) },
    'createSignerPoP' => ->(id, share, opts, rng) { FN.create_signer_pop(id, share, opts, random: rng) },
    'verifySignerPoP' => ->(pop, expect) { FN.verify_signer_pop(pop, expect) },
    'enrollVerificationShares' => ->(enr, expect) { FN.enroll_verification_shares(enr, expect) },
    'equivocationGuard' => ->(ops) { guard(ops) },
    'decodeCommitment' => ->(w) { FN.decode_commitment(w) },
    'decodeCommitments' => ->(l) { FN.decode_commitments(l) },
    'decodeVerificationShares' => ->(l) { FN.decode_verification_shares(l) },
    'signerService' => ->(cfg, steps, rng) { signer_service(cfg, steps, rng) },
    'coordinator' => ->(cfg) { coordinator(cfg) },
    'nonceStore' => ->(ops) { store_run(ops) },
    'assertNonceStoreContract' => ->(a) { contract(a) },
    'resolveFrostGroupAlg' => ->(*x) { FP.resolve_frost_group_alg(x.empty? ? A::IntentV2::UNDEF : x[0]) },
    'frostSignerSetDigest' => ->(ids) { FP.frost_signer_set_digest(ids) },
    'frostCosignRepresentative' => ->(gpk, m, ids, alg) { FP.frost_cosign_representative(gpk, m, ids, alg) },
    'verifyHybridFrostCosign' => ->(art, m, gpk, set, opts) { FP.verify_hybrid_frost_cosign(art, m, gpk, set, opts) },
    'signHybridFrostCosign' => ->(gpk, quorum, m, opts, _rng) { sign_hybrid(gpk, quorum, m, opts) },
    'pqQuorumRepresentative' => ->(m) { PT.pq_quorum_representative(m) },
    'signPqQuorum' => ->(m, seeds, t) { sign_pq_quorum(m, seeds, t) },
    'normalizePqQuorumPool' => ->(l) { PT.normalize_pq_quorum_pool(l).to_a },
    'verifyPqQuorum' => ->(block, m, pool, t) { PT.verify_pq_quorum(block, m, Set.new(pool), t) }
  }.freeze

  # the handlers that take the trailing randomness seam as an argument
  RNG_FNS = %w[issueAllowToken createSignerPoP signerService signHybridFrostCosign].freeze

  TOTALS = { 'constants' => 1, 'frostActionDigest' => 7, 'issueAllowToken' => 25, 'verifyAllowToken' => 58, 'createSignerPoP' => 24, 'verifySignerPoP' => 36,
             'enrollVerificationShares' => 23, 'equivocationGuard' => 27, 'decodeCommitment' => 22, 'decodeCommitments' => 10, 'decodeVerificationShares' => 16,
             'signerService' => 95, 'coordinator' => 86, 'nonceStore' => 16, 'assertNonceStoreContract' => 11, 'resolveFrostGroupAlg' => 16,
             'frostSignerSetDigest' => 17, 'frostCosignRepresentative' => 13, 'verifyHybridFrostCosign' => 60, 'signHybridFrostCosign' => 18,
             'pqQuorumRepresentative' => 4, 'signPqQuorum' => 7, 'normalizePqQuorumPool' => 6, 'verifyPqQuorum' => 36 }.freeze

  def self.needs_pq?(c)
    return true if %w[signPqQuorum verifyPqQuorum].include?(c['fn'])

    Ref.canon(c['args']).match?(/ml-dsa|guardianMlDsa|guardianPq/)
  end

  def test_every_fn_of_the_corpus_has_a_handler_and_the_totals_are_pinned
    assert_equal TOTALS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 634, BY_FN.values.sum(&:length)
    assert_empty BY_FN.keys - HANDLERS.keys
  end

  def test_the_post_quantum_cases_run_where_required
    assert PQ, 'this runtime must have ML-DSA-65' if ENV['PCA_REQUIRE_PQ'] == '1'
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      k = self.class
      call = lambda do |*args|
        a = args.map { |x| k.hydrate(x) }
        a, rng = k.split_rng(a) if RNG_FNS.include?(fn)
        a << rng if RNG_FNS.include?(fn)
        k.capture { handler.call(*a) }
      end
      Ref.run(self, BY_FN.fetch(fn), call, skip: ->(c) { !PQ && k.needs_pq?(c) },
              compare: ->(got, out, _c) { k.eq(got, out) }, refused: ->(got, c) { k.eq(got, c['out']) })
    end
  end
end
