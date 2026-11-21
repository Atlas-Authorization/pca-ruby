# frozen_string_literal: true

# Replays the TS-reference oracle of the software attestation layer (test-data/ref-attestation-soft.json.gz, 512 cases): the report_data
# binding, the dev attestor and its documents (Ed25519, ML-DSA-65, hybrid), the registry, the bounded nonce store (op scripts with an injected
# clock), the nonce entropy gate, requires / binds / match of the agent binding, verify_attestation (every reason compares exactly; a reason
# that starts with the fail-closed prefix carries the reference's own exception text, so only the prefix is compared), the attestation hook
# (one hook, nonce store state persisting across the contexts of a case), the multi-root verifier, the evidence digest and the anchoring.
# Every fn has a handler and the totals are asserted. Encodings: {"$num": ...} is a non-finite number; {"$bytes": {"$seed": label}} the
# 32-byte secret sha256("atlas-pca-conformance/" + label); a suite is {alg, pqSeed?} (the ML-DSA-65 key generation seed; signing is
# deterministic, so signatures compare byte for byte). Hardware verifiers are constants of the corpus: {result} or {throws}. The two
# verify cases the reference accepts only through its `allowUnboundPq` switch are replayed with the refusal this SDK must give (it has no
# such switch: a document's own PQ key is never enough); the count is asserted.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefAttestationSoft < Minitest::Test
  A = AtlasPca
  P = AtlasPca::Attestation
  BY_FN = Ref.load('attestation-soft')
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze
  PQ = A.supported_suites.include?('ml-dsa-65')
  FAIL_PREFIX = 'attestation verification error (fail closed):'
  UNBOUND_REFUSAL = 'attestation signature does not verify'

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  # a constant hardware verifier of the corpus: {result: ...} answers it, {throws: msg} raises
  class Hw
    def initialize(spec) = @spec = spec
    def verify(_document, _expected, _now_ms)
      raise @spec['throws'] if @spec.key?('throws')

      @spec['result']
    end
  end

  def self.hw(h) = h.nil? ? nil : Hw.new(h)

  def self.suite(s)
    return {} unless s.is_a?(Hash)

    { alg: s['alg'], pq: s['pqSeed'] ? A::PqKeyPair.from_seed('ML-DSA-65', s['pqSeed']) : nil }
  end

  def self.verify(i)
    P.verify_attestation(document: i['document'], ctx: i['ctx'], expected: i['expected'], now_ms: i['nowMs'], trusted_attestor_keys: i['trustedAttestorKeys'],
                         pq_pins: i['pqPins'], hardware_verifier: hw(i['hardware']), max_nonce_age_ms: i['maxNonceAgeMs'], clock_skew_ms: i['clockSkewMs'])
  end

  def self.nonce_store(max, opts, ops)
    t = 0
    st = P::MemoryNonceStore.new(max, retention_ms: opts.is_a?(Hash) ? opts['retentionMs'] : nil, now: -> { t })
    ops.map do |op, arg|
      if op == 'clock'
        t = arg
        nil
      else
        st.consume(arg)
      end
    end
  end

  # a store that always gives one answer
  class ConstStore
    def initialize(answer) = @answer = answer
    def consume(_nonce) = @answer
  end

  def self.hook(opts, ctxs)
    now = opts['now']
    store = nil
    if opts['store']
      store = P::MemoryNonceStore.new(opts['store']['max'], retention_ms: opts['store']['retentionMs'], now: -> { now })
    end
    store = ConstStore.new(opts['storeConsume']) if opts.key?('storeConsume')
    b = opts['binding']
    expected = if b == 'throws' then ->(_c) { raise 'boom' }
               elsif b then ->(c) { b['byNonce'][P.dg(c, 'pcactn', 'attestation', 'quote_digest')] }
               end
    h = P.create_attestation_verifier(trusted_attestor_keys: opts['trustedAttestorKeys'], nonce_store: store, min_nonce_bytes: opts['minNonceBytes'],
                                      hardware_verifier: hw(opts['hardware']), resolve_document: P.attestation_registry(opts['docs'] || []),
                                      expected_binding: expected, insecure_self_declared_nonce: opts['insecure_selfDeclaredNonce'],
                                      max_nonce_age_ms: opts['maxNonceAgeMs'], now: -> { now }, clock_skew_ms: opts['clockSkewMs'],
                                      pq_pins: opts['pqPins'])
    ctxs.map { |c| h.call(c) }
  end

  def self.multi_root(pol, inp)
    roots = pol['roots'].map do |r|
      m = { 'id' => r['id'], 'verifier' => hw(r['hw']) }
      m['required'] = r['required'] if r.key?('required')
      m['suite'] = r['suite'] if r.key?('suite')
      m
    end
    v = P.create_multi_root_verifier({ 'threshold' => pol['threshold'], 'roots' => roots })
    return { 'built' => true } if inp.nil?

    v.verify(inp['document'], inp['expected'], inp['nowMs'])
  end

  def self.anchor(ev, op)
    ledger = op['ledger'] == 'ok' ? A::TransparencyLedger.new(op['principal'] || '') : nil
    (op['preload'] || 0).times { |i| ledger.append_commitment("c#{i}") }
    P.anchor_attestation_evidence(ev, ledger: ledger, guardian: op['guardianSeed'] ? A::KeyPair.new(op['guardianSeed']) : nil, instance_id: op['instanceId'],
                                      now: op.key?('now') ? -> { op['now'] } : nil, required: op['required'])
  end

  HANDLERS = {
    'attestationBinding' => ->(e) { P.attestation_binding(e) },
    'attestationBindingB64u' => ->(e) { P.attestation_binding_b64u(e) },
    'attest' => ->(secret, su, claims) { P.create_dev_attestor(secret, **suite(su)).attest(claims) },
    'attestorPublicKey' => ->(secret, su) { P.create_dev_attestor(secret, **suite(su)).public_key },
    'attestationDigest' => ->(d) { P.attestation_digest(d) },
    'registry' => lambda { |docs, qs|
      r = P.attestation_registry(docs)
      qs.map { |q| r.call({ 'pcactn' => { 'attestation' => { 'quote_digest' => q } } }) }
    },
    'nonceStore' => ->(max, opts, ops) { nonce_store(max, opts, ops) },
    'nonceEntropyOk' => ->(n, m) { P.nonce_entropy_ok?(n, m) },
    'requiresAttestation' => ->(b) { P.requires_attestation?(b) },
    'matchAgentBinding' => ->(id, b) { P.match_agent_binding(id, b) },
    'nonceBinds' => ->(d, c) { P.nonce_binds?(d, c) },
    'verifyAttestation' => ->(i) { verify(i) },
    'attestationHook' => ->(opts, ctxs) { hook(opts, ctxs) },
    'multiRoot' => ->(pol, inp) { multi_root(pol, inp) },
    'attestationEvidenceDigest' => ->(e) { P.attestation_evidence_digest(e) },
    'anchorEvidence' => ->(ev, op) { anchor(ev, op) },
    'constants' => lambda {
      { 'ATTEST_BIND_DOMAIN' => P::ATTEST_BIND_DOMAIN, 'MAX_ATTESTATION_AGE_MS' => P::MAX_ATTESTATION_AGE_MS,
        'DEFAULT_NONCE_RETENTION_MS' => P::DEFAULT_NONCE_RETENTION_MS, 'MIN_ATTESTATION_NONCE_BYTES' => P::MIN_ATTESTATION_NONCE_BYTES,
        'ATTEST_ANCHOR_DOMAIN' => P::ATTEST_ANCHOR_DOMAIN }
    }
  }.freeze

  TOTALS = { 'attestationBinding' => 27, 'attestationBindingB64u' => 27, 'attest' => 18, 'attestorPublicKey' => 3, 'attestationDigest' => 6,
             'registry' => 6, 'nonceStore' => 23, 'nonceEntropyOk' => 32, 'requiresAttestation' => 29, 'matchAgentBinding' => 170,
             'nonceBinds' => 8, 'verifyAttestation' => 91, 'attestationHook' => 23, 'multiRoot' => 27, 'attestationEvidenceDigest' => 11,
             'anchorEvidence' => 10, 'constants' => 1 }.freeze

  def self.unbound?(c) = c['fn'] == 'verifyAttestation' && c['args'][0]['allowUnboundPq'] == true && c['out']['ok'] == true

  # a case that signs or verifies with ML-DSA needs a runtime that has it (OpenSSL >= 3.5)
  def self.pq_case?(c) = Ref.canon(c['args']).match?(/ml-dsa|pqSeed/)

  # a reason with the reference's own exception text after the fail-closed prefix compares by prefix; a throwing case needs a native raise
  def self.same?(got, out, c)
    return Ref.canon(got) == Ref.canon({ 'ok' => false, 'present' => true, 'bound' => false, 'reason' => UNBOUND_REFUSAL }) if unbound?(c)

    if out.is_a?(Hash) && out['reason'].is_a?(String) && out['reason'].start_with?(FAIL_PREFIX)
      return got.is_a?(Hash) && got['reason'].to_s.start_with?(FAIL_PREFIX) &&
             Ref.canon(got.merge('reason' => FAIL_PREFIX)) == Ref.canon(out.merge('reason' => FAIL_PREFIX))
    end
    Ref.canon(got) == Ref.canon(out)
  end

  def test_every_fn_of_the_corpus_has_a_handler_and_the_totals_are_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 512, BY_FN.values.sum(&:length)
    assert_equal 2, BY_FN.values.flatten.count { |c| self.class.unbound?(c) }, 'the cases the reference accepts only under allowUnboundPq'
  end

  def test_the_post_quantum_cases_run_where_required
    assert PQ, 'this runtime must have ML-DSA-65' if ENV['PCA_REQUIRE_PQ'] == '1'
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      k = self.class
      Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| k.dnum(a) }) }, compare: ->(got, out, c) { k.same?(got, out, c) },
              skip: ->(c) { !PQ && k.pq_case?(c) })
    end
  end
end
