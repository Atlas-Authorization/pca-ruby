# frozen_string_literal: true

# Replays every case of the TS-reference zk oracle (test-data/ref-zk.json.gz, 1429 cases, 32 fns) against AtlasPca::Zk and
# AtlasPca::ZkCeremony: commitments, the binding tag, struct and risk hashes, the quantizers, public-signal decoding, context
# pins, the canonical envelope gate, proof verification, the four backends, the hook, the attested prover, circuit versions,
# the ceremony checks and the prover contract. A fn without a handler fails the run, and so does a changed case total.
#
# Corpus conventions: {"$bigint": d} is that Integer, {"$num": n} that Float, {"$bytes": {"$seed": l}} a 32-byte secret,
# {"$expectThunk": x} a callable returning x ("throw": one that raises), "$absent" an argument not given. The reference
# options object is given as keywords, except to the quantizers, which get it as it is (their `opts` argument): null included.
#
# The pairing check: with libpcazk (ATLAS_PCA_LIBPCAZK; required when ATLAS_PCA_LIBPCAZK_REQUIRED is 1) every case runs on the
# library. Without it a recorded engine answers the pairing question with the verdict the corpus recorded for that case, so
# the final outcome of every case is still asserted. In both modes a case must reach the pairing check exactly when the
# reference does (PAIRING_REFUSES lists the refused proofs that pass every gate in front of it): a gate that lets a refused
# case through, or stops an accepted one, fails here.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/zk_native'
require 'minitest/autorun'

class TestRefZk < Minitest::Test
  Z = AtlasPca::Zk
  C = AtlasPca::ZkCeremony
  BY_FN = Ref.load('zk')
  TOTAL = 1429
  NATIVE = AtlasPca::ZkNative.available?

  OPTS = { 'verbCodes' => :verb_codes, 'resourceCodes' => :resource_codes, 'strictCatalog' => :strict_catalog,
           'paramScalarField' => :param_scalar_field, 'verificationKey' => :verification_key, 'expect' => :expect,
           'expectRiskHash' => :expect_risk_hash, 'expectActionHash' => :expect_action_hash, 'expectPolicyHash' => :expect_policy_hash,
           'expectPlanHash' => :expect_plan_hash, 'ceremony' => :ceremony }.freeze
  PROV = { 'circuit' => :circuit, 'sourceSha256' => :source_sha256, 'r1csSha256' => :r1cs_sha256, 'vkey' => :vkey }.freeze
  TRANSCRIPT_OPTS = { 'minContributions' => :min_contributions, 'r1csSha256' => :r1cs_sha256, 'circuit' => :circuit }.freeze
  SNARK = { 'groth16' => :create_groth16_snark_backend, 'policyvm' => :create_policy_vm_snark_backend,
            'policyvm-bls' => :create_policy_vm_snark_backend_bls12381, 'policyvm-bound' => :create_policy_vm_bound_snark_backend }.freeze
  POLICY_FIELDS = %w[wAlpha wBeta wGamma wDelta wEpsilon wZeta theta1 theta2 kappa budgetB policyVerb policyResource policyParamBound
                     expiresAt notBefore maxBlast maxDepth revMax rateMax allocParent].freeze
  NUMS = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze

  # refused by the pairing check itself: every gate in front of it passes (by case name)
  PAIRING_REFUSES = [
    %r{\AverifyPolicyVmProof/(?:bn|bls)/(?:signal(?!9\+)\d+\+1|pi_[ac]\.[xy]\+1|pi_[ac]\.y-neg|pi_b\.(?:x0\+1|y1\+1|conj)|pi_a-is-pi_c|pi_a-zero-xy|pi_b-zero|vkey-.+|pi_[abc]-on-(?:curve|twist)-not-in-g[12])\z},
    %r{\AverifyPolicyVmProof/v2/(?:valid-shape-wrong-key|risk-hash-match-wrong-key)\z},
    %r{\AcreatePolicyVmSnarkBackend(?:Bls12381)?/(?:bn|bls)/(?:other-curve-proof|vkey-wrong)\z},
    %r{\AcreateGroth16SnarkBackend/bound-wrong-key\z},
    %r{\AcreatePolicyVmBoundSnarkBackend/(?:pinned|unpinned)-wrong-key\z},
    %r{\AcreateZkVerifier/snark/policyvm-(?:bn-tampered|bls-bn-proof)\z}
  ].freeze

  # corpus argument -> Ruby value
  def self.rv(v)
    case v
    when Array then v.map { |x| rv(x) }
    when Hash
      return Integer(v['$bigint']) if v.size == 1 && v['$bigint'].is_a?(String)
      return NUMS.fetch(v['$num']) if v.size == 1 && v.key?('$num')

      v.transform_values { |x| rv(x) }
    else v
    end
  end

  def self.expect_of(e)
    return Z::ABSENT if e == '$absent'
    return e unless e.is_a?(Hash) && e.key?('$expectThunk')

    e['$expectThunk'] == 'throw' ? -> { raise 'thunk' } : -> { e['$expectThunk'] }
  end

  # the reference options object as keywords (a member it does not have is an option not given; an unknown member fails)
  def self.kw(opts, map = OPTS)
    opts.to_h { |k, v| [map.fetch(k), k == 'expect' ? expect_of(v) : v] }
  end

  def self.some(h, map) = map.each_with_object({}) { |(k, s), out| out[s] = h[k] if h.is_a?(Hash) && h.key?(k) }
  def self.prune(v) = v.is_a?(Hash) ? v.compact.transform_values { |x| prune(x) } : v

  def self.backend(make)
    lambda do |opts, input|
      b = Z.public_send(make, **kw(opts))
      { 'verified' => b.verify(input['proof'], input['publicInputs'], input['ctx']), 'label' => AtlasPca.assurance_label_of(b) }
    end
  end

  # the pairing verdict the corpus recorded for a case (false when the case is refused, by a gate or by the pairing check)
  def self.verdict(c)
    out = c['out']
    case c['fn']
    when 'verifyPolicyVmProof' then out == true
    when 'createZkVerifier' then c['args'][0].key?('snark') && out['result']['ok'] == true
    else out.is_a?(Hash) && out['verified'] == true
    end
  end

  PRUNED = ->(got, out, _c) { Ref.canon(prune(got)) == Ref.canon(out) }

  # fn => [handler, case count, compare?]
  HANDLERS = {
    'constants' => [lambda {
      { 'ZK_PROVER_BINDING_REF' => Z::ZK_PROVER_BINDING_REF, 'POLICYVM_PUBLIC_SIGNAL' => Z::POLICYVM_PUBLIC_SIGNAL,
        'POLICYVM_PUBLIC_SIGNAL_COUNT' => Z::POLICYVM_PUBLIC_SIGNAL_COUNT, 'POLICYVM_BOUND_PUBLIC_SIGNAL' => Z::POLICYVM_BOUND_PUBLIC_SIGNAL,
        'POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT' => Z::POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT, 'POLICYVM_BOUND_RISK_FIELDS' => Z::POLICYVM_BOUND_RISK_FIELDS,
        'POLICYVM_REVERSIBILITY_ORDER' => Z::POLICYVM_REVERSIBILITY_ORDER,
        'paths' => Z::PATHS.keys.to_h { |k| [k, "circuits/#{Z.path(k).delete_prefix("#{Z.circuits_dir}/")}"] } }
    }, 1],
    'commitmentField' => [->(c = nil) { Z.commitment_field(c) }, 26],
    'policyCommitment' => [->(g = nil) { Z.policy_commitment(g) }, 7],
    'pinnedPolicyCommitment' => [->(g = nil) { Z.pinned_policy_commitment(g) }, 7],
    'actionCommitment' => [->(a = nil) { Z.action_commitment(a) }, 5],
    'proverKeyBinding' => [->(pub, epoch, nonce) { Z.prover_key_binding(pub, epoch, nonce) }, 7],
    'policyVmStructHash' => [->(f = nil) { Z.policy_vm_struct_hash(f) }, 23],
    'policyVmRiskHash' => [->(f = nil) { Z.policy_vm_risk_hash(f) }, 9],
    'quantizeActionStruct' => [->(a = nil, *o) { Z.quantize_action_struct(a, *o) }, 54],
    'policyVmCommitmentFromAction' => [->(a = nil, *o) { Z.policy_vm_commitment_from_action(a, *o) }, 54],
    'quantizePlanStruct' => [->(p = nil, *o) { Z.quantize_plan_struct(p, *o) }, 11],
    'quantizePolicyStruct' => [->(p = nil, *o) { Z.quantize_policy_struct(p, *o) }, 17],
    'quantizePolicyVmInputs' => [->(i = nil, *o) { Z.quantize_policy_vm_inputs(i, *o) }, 11],
    'decodePolicyVmPublic' => [->(ps = nil) { Z.decode_policy_vm_public(ps) }, 6, PRUNED],
    'decodePolicyVmBoundPublic' => [->(ps = nil) { Z.decode_policy_vm_bound_public(ps) }, 3, PRUNED],
    'policyVmContextMatches' => [lambda { |ps, e, l = nil|
      Z.policy_vm_context_matches?(ps, expect_of(e), l == 'bound' ? Z::POLICYVM_BOUND_PUBLIC_SIGNAL : Z::POLICYVM_PUBLIC_SIGNAL)
    }, 66],
    'isCanonicalGroth16Envelope' => [->(env = nil, curve = nil) { Z.canonical_groth16_envelope?(env, curve) }, 409],
    'verifyPolicyVmProof' => [->(env = nil, opts = nil) { Z.verify_policy_vm_proof(env, **kw(opts || {})) }, 169],
    'createPolicyVmSnarkBackend' => [backend(:create_policy_vm_snark_backend), 20],
    'createPolicyVmSnarkBackendBls12381' => [backend(:create_policy_vm_snark_backend_bls12381), 15],
    'createGroth16SnarkBackend' => [backend(:create_groth16_snark_backend), 14],
    'createPolicyVmBoundSnarkBackend' => [backend(:create_policy_vm_bound_snark_backend), 7],
    'createAttestedComplianceProver' => [lambda { |secret, po|
      prover = Z.create_attested_compliance_prover(secret)
      { 'publicKey' => prover.public_key,
        'statement' => prover.prove(pcactn: po['pcactn'], decide_input: po['decideInput'], issued_at: po['issued_at'], expires_at: po['expires_at']) }
    }, 6],
    'createZkVerifier' => [lambda { |spec, ctx|
      snark = spec['snark'] && Z.public_send(SNARK.fetch(spec['snark']['kind']), **kw(spec['snark']['opts'] || {}))
      hook = Z.create_zk_verifier(trusted_prover_keys: spec['trustedProverKeys'], policy_commitments: spec['policyCommitments'],
                                  revoked_prover_keys: spec['revokedProverKeys'], clock_skew_ms: spec['clockSkewMs'],
                                  now: -> { spec['nowMs'] }, snark_backend: snark)
      result = hook.call(ctx)
      # the text after the fail-closed prefix is the engine's own
      result = result.merge('reason' => result['reason'].sub(/(zk verification error \(fail closed\)): .*\z/m, '\1')) if result['reason'].is_a?(String)
      { 'result' => result, 'label' => AtlasPca.assurance_label_of(hook) }
    }, 147],
    'circuitVersion' => [->(id = nil) { Z.circuit_version(id) }, 13],
    'vkId' => [->(vkey) { C.vk_id(vkey) }, 10],
    'circuitProvenance' => [->(a) { C.circuit_provenance(circuit: nil, source_sha256: nil, r1cs_sha256: nil, **some(a, PROV)) }, 13, PRUNED],
    'checkCircuitProvenance' => [->(prov, e) { C.check_circuit_provenance(prov, circuit: nil, source_sha256: nil, vkey: nil, **some(e, PROV)) }, 19],
    'transcriptSha256' => [->(t) { C.transcript_sha256(t) }, 3],
    'checkTranscript' => [->(t, opts = nil) { C.check_transcript(t, **some(opts, TRANSCRIPT_OPTS)) }, 257],
    'ceremonyOf' => [->(vkey, evidence = nil) { C.ceremony_of(vkey, evidence) }, 19],
    'provePolicyVmCompliance' => [nil, 1] # test_replay_provePolicyVmCompliance: the prover contract
  }.freeze
  ENGINE_FNS = %w[verifyPolicyVmProof createPolicyVmSnarkBackend createPolicyVmSnarkBackendBls12381 createGroth16SnarkBackend
                  createPolicyVmBoundSnarkBackend createZkVerifier].freeze

  def replay(fn, cases)
    handler, _count, compare = HANDLERS.fetch(fn)
    # the oracle runs this fn on the unrevived arguments: a {"$bigint"} pin is a plain object there, never a number
    raw = fn == 'policyVmContextMatches'
    Ref.run(self, cases, ->(*a) { handler.call(*(raw ? a : self.class.rv(a))) },
            compare: compare || ->(got, out, _c) { Ref.canon(got) == Ref.canon(self.class.rv(out)) })
  end

  def fixture(name) = BY_FN.fetch('verifyPolicyVmProof').find { |c| c['name'] == "verifyPolicyVmProof/#{name}" }['args']

  def test_every_fn_is_handled_and_the_total_is_the_corpus
    assert_empty BY_FN.keys - HANDLERS.keys, 'corpus fns without a handler'
    assert_empty HANDLERS.keys - BY_FN.keys, 'handlers without cases'
    assert_equal TOTAL, BY_FN.values.sum(&:length)
    assert_equal TOTAL, HANDLERS.values.sum { |h| h[1] }
  end

  def test_the_library_is_there_when_it_is_required
    assert NATIVE, 'libpcazk is required here (ATLAS_PCA_LIBPCAZK_REQUIRED) and could not be loaded' if ENV['ATLAS_PCA_LIBPCAZK_REQUIRED'] == '1'
  end

  (HANDLERS.keys - ENGINE_FNS - ['provePolicyVmCompliance']).each do |fn|
    define_method("test_replay_#{fn}") do
      cases = BY_FN.fetch(fn)
      assert_equal HANDLERS.fetch(fn)[1], cases.length
      assert_equal cases.length, replay(fn, cases)
    end
  end

  ENGINE_FNS.each do |fn|
    define_method("test_replay_#{fn}") do
      cases = BY_FN.fetch(fn)
      assert_equal HANDLERS.fetch(fn)[1], cases.length
      cases.each do |c|
        verdict = self.class.verdict(c)
        reached = false
        Z.groth16_engine = lambda do |vkey, signals, proof|
          reached = true
          NATIVE ? Z.native_groth16_verify(vkey, signals, proof) : verdict
        end
        replay(fn, [c])
        assert_equal verdict || PAIRING_REFUSES.any? { |r| r.match?(c['name']) }, reached, "#{c['name']}: reaches the pairing check"
      ensure
        Z.groth16_engine = nil
      end
    end
  end

  # No prover output is replayable (a proof carries fresh randomness, the proving key is a build product). The contract: the
  # committed sample witness gives exactly these public signals, and the proof verifies under the bundled BN254 key.
  def test_replay_provePolicyVmCompliance
    cases = BY_FN.fetch('provePolicyVmCompliance')
    assert_equal 1, cases.length
    witness = cases[0]['args'][0]
    out = cases[0]['out']
    signals = out['publicSignals']
    halves = ->(names) { Z.policy_vm_struct_hash(names.map { |k| witness.fetch(k) }).values_at('hi', 'lo') }
    assert_equal signals[0, 2], halves.call(%w[verb resource reversibility paramScalar])
    assert_equal signals[2, 2], halves.call(POLICY_FIELDS)
    assert_equal signals[4, 2], halves.call(%w[planVerb planResource semanticDist planSalt])
    assert_equal signals[9, 6], %w[allow now blast delegationDepth recentCount allocChild].map { |k| witness.fetch(k) }
    assert_equal %w[VK_BN pca-policyvm-v1], out.values_at('verifiesUnder', 'sampleProofCircuit')
    assert_equal Z::POLICYVM_PUBLIC_SIGNAL_COUNT, signals.length

    wasm = ENV['PCA_ZK_POLICYVM_WASM']
    zkey = ENV['PCA_ZK_POLICYVM_ZKEY']
    if NATIVE && wasm && zkey
      env = Z.prove_policy_vm_compliance(witness, wasm_path: wasm, zkey_path: zkey)
      assert_equal %w[groth16-bn254 pca-policyvm-v1], env.values_at('system', 'circuit')
      assert_equal signals, env['publicSignals']
      assert_equal true, Z.verify_policy_vm_proof(env)
    else
      # nothing to prove with: the prover refuses (no library, or no proving key), it never answers
      missing = File.join(Z.circuits_dir, 'build', 'not-built')
      refusal = NATIVE ? SystemCallError : AtlasPca::ZkNative::BackendMissing
      assert_raises(refusal) { Z.prove_policy_vm_compliance(witness, wasm_path: missing, zkey_path: missing) }
      assert_raises(refusal) { Z.prove_policy_vm_bound_compliance(witness, wasm_path: missing, zkey_path: missing) }
    end
  end

  # the library reads the key's curve name as snarkjs does: every spelling of the same curve verifies, an unknown name is invalid (bad_curve), strict mode
  # takes no curve from the key
  def test_the_curve_is_read_from_the_key_by_the_library
    skip 'libpcazk is not available' unless NATIVE
    env, = fixture('bn/valid')
    vkey = JSON.parse(AtlasPca::ZkBundled::POLICYVM_VKEY_JSON)
    verdict = ->(name) { AtlasPca::ZkNative.verify(AtlasPca::ZkNative::FROM_KEY, vkey.merge('curve' => name), env['proof'], env['publicSignals']) }
    ['bn128', 'BN254', 'Alt_Bn-128', 'altbn128'].each { |name| assert_equal({ 'valid' => true, 'reason' => 'ok' }, verdict.call(name), name) }
    assert_equal({ 'valid' => false, 'reason' => 'bad_curve' }, verdict.call('p256'))
    assert_equal({ 'valid' => false, 'reason' => 'bad_curve' }, verdict.call(7))
    assert_raises(ArgumentError) { AtlasPca::ZkNative.verify(AtlasPca::ZkNative::FROM_KEY, vkey, env['proof'], env['publicSignals'], strict: true) }
  end

  def test_the_bundled_keys_are_the_reference_keys_and_the_default
    { 'bn' => AtlasPca::ZkBundled::POLICYVM_VKEY_JSON, 'bls' => AtlasPca::ZkBundled::POLICYVM_BLS12381_VKEY_JSON }.each do |curve, text|
      env, opts = fixture("#{curve}/valid")
      assert_equal opts['verificationKey'], JSON.parse(text), curve
      seen = nil
      Z.groth16_engine = lambda do |vkey, signals, proof|
        seen = [vkey, signals, proof]
        true
      end
      assert_equal true, Z.verify_policy_vm_proof(env)
      assert_equal [opts['verificationKey'], env['publicSignals'], env['proof']], seen, "#{curve}: the pairing check gets the bundled key"
    end
  ensure
    Z.groth16_engine = nil
  end

  def test_a_nil_pin_matches_nothing
    env, opts = fixture('bn/valid')
    Z.groth16_engine = ->(*) { true }
    key = opts['verificationKey']
    assert_equal true, Z.verify_policy_vm_proof(env, verification_key: key)
    assert_equal false, Z.verify_policy_vm_proof(env, verification_key: key, expect: nil)
    assert_equal false, Z.verify_policy_vm_proof(env, verification_key: key, expect_risk_hash: nil) # a v1 proof carries none
    v2 = fixture('v2/valid-shape-wrong-key')[0]
    assert_raises(TypeError) { Z.verify_policy_vm_proof(v2, verification_key: key, expect_risk_hash: nil) } # as the reference on null
    assert_equal false, Z.verify_policy_vm_proof(v2, verification_key: key, expect_risk_hash: 'x')
    bound = Z.create_policy_vm_bound_snark_backend(verification_key: key, expect_risk_hash: nil)
    assert_equal 'unknown', AtlasPca.assurance_label_of(bound)['level']
    assert_raises(TypeError) { bound.verify(v2) }
    assert_equal true, Z.create_policy_vm_bound_snark_backend(verification_key: key).verify(v2)
    assert_equal false, Z.verify_policy_vm_proof(env, verification_key: key, expect: -> {})
    assert_equal true, Z.verify_policy_vm_proof(env, verification_key: key, expect: { 'now' => 1_000_000_000, 'requireAdmit' => true })
    assert_equal false, Z.verify_policy_vm_proof(env, verification_key: key, expect: { 'now' => 1_000_000_001 })
  ensure
    Z.groth16_engine = nil
  end

  def test_quantizer_options_as_keywords_or_as_the_reference_object
    action = { 'verb' => 'read', 'resource' => 'doc:1', 'params' => { 'amount' => 100 } }
    by_object = Z.quantize_action_struct(action, { 'verbCodes' => { 'read' => 7 }, 'strictCatalog' => false, 'paramScalarField' => 'amount' })
    assert_equal by_object, Z.quantize_action_struct(action, verb_codes: { 'read' => 7 }, param_scalar_field: 'amount')
    assert_equal [7, 100], by_object.values_at(0, 3)
    assert_equal Z.policy_vm_struct_hash(by_object), Z.policy_vm_commitment_from_action(action, verb_codes: { 'read' => 7 }, param_scalar_field: 'amount')
    assert_raises(TypeError) { Z.quantize_plan_struct({ 'verb' => 'a', 'resource' => 'b', 'semanticDist' => 0, 'planSalt' => 1 }, nil) }
    assert_raises(ArgumentError) { Z.quantize_action_struct(action, verb_code: {}) }
    assert_raises(ArgumentError) { Z.quantize_action_struct(action, strict_catalog: true) }
  end

  # Core without the library: nothing verifies, and the hook denies.
  def test_without_a_pairing_backend_nothing_verifies
    skip 'libpcazk is available' if NATIVE
    env, opts = fixture('bn/valid')
    assert_nil Z.groth16_engine
    assert_equal false, Z.verify_policy_vm_proof(env, verification_key: opts['verificationKey'])
    assert_equal false, Z.verify_policy_vm_proof(env)
    assert_equal false, Z.create_policy_vm_snark_backend.verify(env)
    g = BY_FN.fetch('createGroth16SnarkBackend').find { |c| c['name'].end_with?('/bound-wrong-key') }['args']
    backend = Z.create_groth16_snark_backend(verification_key: g[0]['verificationKey'])
    assert_raises(AtlasPca::ZkNative::BackendMissing) { backend.verify(g[1]['proof'], g[1]['publicInputs']) }
    raising = Object.new # a backend that reaches the pairing check: the hook turns its refusal to answer into a denial
    raising.define_singleton_method(:verify) { |proof, inputs, _ctx| backend.verify(proof, inputs.merge(g[1]['publicInputs'])) }
    hook = Z.create_zk_verifier(trusted_prover_keys: [], snark_backend: raising)
    res = hook.call({ 'pcactn' => { 'zk_compliance' => g[1]['proof'] }, 'grant' => nil })
    assert_equal [true, false], res.values_at('enforced', 'ok')
    assert_match(/\Azk verification error \(fail closed\): /, res['reason'])
    hook = Z.create_zk_verifier(trusted_prover_keys: [], snark_backend: Z.create_policy_vm_snark_backend)
    assert_equal({ 'enforced' => true, 'ok' => false, 'reason' => 'snark backend rejected the proof' },
                 hook.call({ 'pcactn' => { 'zk_compliance' => env }, 'grant' => nil }))
  end

  def test_a_verifier_keeps_the_configuration_it_was_built_with
    c = BY_FN.fetch('createZkVerifier').find { |x| x['name'] == 'createZkVerifier/ok' }
    spec, ctx = c['args']
    trusted = spec['trustedProverKeys'].map(&:dup)
    hook = Z.create_zk_verifier(trusted_prover_keys: trusted, policy_commitments: spec['policyCommitments'], now: -> { spec['nowMs'] })
    assert_equal({ 'enforced' => true, 'ok' => true }, hook.call(ctx))
    trusted[0] << 'x'
    trusted.clear
    assert_equal({ 'enforced' => true, 'ok' => true }, hook.call(ctx))
    assert_equal 'prover key is revoked',
                 Z.create_zk_verifier(trusted_prover_keys: spec['trustedProverKeys'], revoked_prover_keys: spec['trustedProverKeys'],
                                      now: -> { spec['nowMs'] }).call(ctx)['reason']
  end

  def test_prover_attestation_binds_the_prover_key_to_hardware
    c = BY_FN.fetch('createZkVerifier').find { |x| x['name'] == 'createZkVerifier/ok' }
    spec, ctx = c['args']
    prover = ctx['pcactn']['zk_compliance']['prover']
    answer = { 'ok' => true, 'bound' => true, 'measured' => { 'runtime_measurement' => 'm1' } }
    calls = []
    verifier = Object.new
    verifier.define_singleton_method(:verify) do |document, expected, now_ms|
      calls << [document, expected, now_ms]
      answer
    end
    make = lambda do |v = verifier, measurements = %w[m1]|
      Z.create_zk_verifier(trusted_prover_keys: spec['trustedProverKeys'], now: -> { spec['nowMs'] },
                           prover_attestation: { 'hardware_verifier' => v, 'measurements' => measurements,
                                                 'expected_binding' => ->(key) { Z.prover_key_binding(key, 3, 'n') } })
    end
    assert_raises(ArgumentError) { make.call } # an unlabelled verifier is refused at construction
    AtlasPca.set_assurance_label(verifier, 'hardware', vendor: 'amd-sev-snp')
    assert_raises(ArgumentError) { make.call(verifier, []) }
    assert_raises(ArgumentError) { make.call(verifier, ['']) }
    hook = make.call
    assert_equal({ 'level' => 'attested_vm_hw', 'vendor' => 'hardware-bound:amd-sev-snp' }, AtlasPca.assurance_label_of(hook))
    assert_equal({ 'enforced' => true, 'ok' => true }, hook.call(ctx))
    assert_equal [[{ 'attestor' => prover, 'mode' => 'hardware' }, Z.prover_key_binding(prover, 3, 'n'), spec['nowMs']]], calls
    { { 'ok' => false, 'reason' => 'stale' } => 'prover hardware evidence invalid: stale',
      { 'ok' => false } => 'prover hardware evidence invalid: no reason given',
      nil => 'prover hardware evidence invalid: no result',
      { 'ok' => true, 'bound' => false } => 'prover hardware evidence does not bind the prover key',
      { 'ok' => true, 'bound' => true } => 'prover hardware evidence carries no measured identity',
      { 'ok' => true, 'bound' => true, 'measured' => { 'runtime_measurement' => 'm2' } } => 'prover VM measurement is not allowlisted' }.each do |a, reason|
      answer = a
      assert_equal({ 'enforced' => true, 'ok' => false, 'reason' => reason }, hook.call(ctx))
    end
  end
end
