# frozen_string_literal: true

require 'digest'
require 'json'
require_relative 'js_compat'

module AtlasPca
  # Zero-knowledge proof of compliance: the resource server learns "authorized", not the policy, the plan or the reasoning.
  #
  # Two realisations, both checked against COMMITMENTS only:
  #
  # * the attested-VM statement (create_attested_compliance_prover / create_zk_verifier): an attested VM runs the Policy VM and
  #   signs a statement that it released the action. Same privacy, weaker trust (the verifier trusts the prover key, optionally
  #   bound to hardware evidence). Needs no native library;
  # * real Groth16 proofs made by snarkjs / circom: pca-compliance-v1 (BN254), the full Policy VM circuit pca-policyvm-v1 (BN254
  #   and BLS12-381, verifying keys bundled) and the risk-bound pca-policyvm-v2 (BN254, no bundled key). The pairing check and
  #   the prover are the opt-in native module ZkNative (libpcazk); everything else here is plain Ruby: the canonical envelope
  #   gate, the context pins, the struct hashes and the deterministic action quantisation that binds a proof to the action.
  #
  # Envelopes, statements, verifying keys, pins and the quantisable action / plan / policy are Hashes with String keys under
  # the reference member names ('publicSignals', 'action_commit', 'delegationDepth', 'budgetB', ...); function options are
  # keywords. Without a pairing backend nothing verifies: verify_policy_vm_proof answers false and the first-circuit backend
  # raises, so the hook of create_zk_verifier denies.
  module Zk
    DOMAIN = "atlas-pca/zk-compliance/v1\0".b
    # grantRef of the binding a prover VM's hardware quote carries (see prover_key_binding).
    ZK_PROVER_BINDING_REF = 'atlas-pca/zk-prover/v1'

    BN254_FR = 21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617
    BN254_FQ = 21_888_242_871_839_275_222_246_405_745_257_275_088_696_311_157_297_823_662_689_037_894_645_226_208_583
    BLS12381_FQ = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    BLS12381_FR = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    CANON_DEC = /\A(?:0|[1-9][0-9]*)\z/
    U64 = 1 << 64
    # an option that was not given (nil is a value: a nil pin matches nothing)
    ABSENT = ZkCeremony::ABSENT
    # members every object inherits in the reference runtime: a param named like one of them is not a number there
    INHERITED = %w[constructor __proto__ hasOwnProperty isPrototypeOf propertyIsEnumerable toLocaleString toString valueOf
                   __defineGetter__ __defineSetter__ __lookupGetter__ __lookupSetter__].freeze

    # Public-signal layout of pca-policyvm-v1 (circuit outputs, then the declared public inputs).
    POLICYVM_PUBLIC_SIGNAL = { 'actionHi' => 0, 'actionLo' => 1, 'policyHi' => 2, 'policyLo' => 3, 'planHi' => 4, 'planLo' => 5,
                               'r' => 6, 't' => 7, 'admit' => 8, 'allow' => 9, 'now' => 10, 'blast' => 11, 'delegationDepth' => 12,
                               'recentCount' => 13, 'allocChild' => 14 }.freeze
    POLICYVM_PUBLIC_SIGNAL_COUNT = 15
    # Public-signal layout of the risk-bound pca-policyvm-v2: the v1 statement plus the risk commitment riskHi / riskLo.
    POLICYVM_BOUND_PUBLIC_SIGNAL = { 'actionHi' => 0, 'actionLo' => 1, 'policyHi' => 2, 'policyLo' => 3, 'planHi' => 4, 'planLo' => 5,
                                     'r' => 6, 't' => 7, 'admit' => 8, 'riskHi' => 9, 'riskLo' => 10, 'allow' => 11, 'now' => 12,
                                     'blast' => 13, 'delegationDepth' => 14, 'recentCount' => 15, 'allocChild' => 16 }.freeze
    POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT = 17
    # The risk magnitudes the v2 circuit commits to, in struct order.
    POLICYVM_BOUND_RISK_FIELDS = %w[revScore taint conf age rFloorIn].freeze
    # The reversibility-class order the circuit's reversibility field and revMax caveat encode (index = class code).
    POLICYVM_REVERSIBILITY_ORDER = %w[reversible rate_limited irreversible].freeze
    CONTEXT_SIGNALS = %w[now blast delegationDepth recentCount allocChild].freeze
    # the reference's quantizer option names
    QUANTIZE_OPTS = { 'verbCodes' => :verb_codes, 'resourceCodes' => :resource_codes, 'strictCatalog' => :strict_catalog,
                      'paramScalarField' => :param_scalar_field }.freeze

    # Where each circuit artifact lives under circuits_dir, by the reference's name for the location. The two Policy VM
    # verifying keys and the circuit versions are bundled in the gem; everything else is a build product read from disk.
    PATHS = {
      'DEFAULT_VKEY_PATH' => %w[build verification_key.json],
      'DEFAULT_WASM_PATH' => %w[build compliance_js compliance.wasm],
      'DEFAULT_ZKEY_PATH' => %w[build compliance_final.zkey],
      'POLICYVM_VKEY_PATH' => %w[policyvm_vkey.json],
      'POLICYVM_SAMPLE_PROOF_PATH' => %w[policyvm_sample_proof.json],
      'POLICYVM_WASM_PATH' => %w[build policyvm_js policyvm.wasm],
      'POLICYVM_ZKEY_PATH' => %w[build policyvm_final.zkey],
      'POLICYVM_BLS12381_VKEY_PATH' => %w[policyvm_bls12381_vkey.json],
      'POLICYVM_BLS12381_SAMPLE_PROOF_PATH' => %w[policyvm_bls12381_sample_proof.json],
      'POLICYVM_BOUND_VKEY_PATH' => %w[build policyvm_bound_vkey.json],
      'POLICYVM_BOUND_SAMPLE_PROOF_PATH' => %w[build policyvm_bound_sample_proof.json],
      'POLICYVM_BOUND_WASM_PATH' => %w[build policyvm_bound_js policyvm_bound.wasm],
      'POLICYVM_BOUND_ZKEY_PATH' => %w[build policyvm_bound_final.zkey]
    }.freeze

    # A proof-system backend for create_zk_verifier: verify(proof, public_inputs, ctx) -> true / false, where `proof` is the
    # opaque value carried in pcactn['zk_compliance'] and `public_inputs` the three commitments. It carries an assurance label.
    class SnarkBackend
      def initialize(label, &verify)
        @verify = verify
        AtlasPca.set_assurance_label(self, label['level'], vendor: label['vendor'], ceremony: label['ceremony'])
      end

      def verify(proof, public_inputs = nil, ctx = nil) = @verify.call(proof, public_inputs, ctx)
    end

    # The attested-VM stand-in for a SNARK prover: it signs that the Policy VM released the action. Only commitments enter the
    # statement, never the plaintext policy or plan.
    class AttestedComplianceProver
      # base64url Ed25519 public key a verifier lists in trusted_prover_keys
      attr_reader :public_key

      def initialize(attestor_secret)
        @key = KeyPair.new(attestor_secret)
        @public_key = @key.public
      end

      # a JS number that is a whole value is an integer on the wire (the strict canonical form refuses 0.0)
      def whole(n) = n.is_a?(Float) && n.finite? && n == n.floor && n.abs <= 2**53 - 1 && !(n.zero? && (1.0 / n).negative?) ? n.to_i : n

      def inspect = "#<AtlasPca::Zk::AttestedComplianceProver public_key=#{@public_key}>" # never print the secret

      # The signed statement for `pcactn`, IFF the Policy VM releases it under `decide_input` (the input of AtlasPca.decide; its
      # grant is the committed policy). Raises ArgumentError otherwise: a false statement cannot be proven.
      def prove(pcactn:, decide_input:, issued_at:, expires_at:)
        decision = AtlasPca.decide(decide_input)
        unless Js.truthy?(decision['releaseGuardianShare'])
          raise ArgumentError, "createAttestedComplianceProver: action is not compliant, nothing to prove (#{Array(decision['reasons']).join('; ')})"
        end

        body = { 'v' => 1, 'mode' => 'attested-vm', 'action_commit' => Zk.action_commitment(pcactn),
                 'policy_commit' => Zk.policy_commitment(decide_input.is_a?(Hash) ? decide_input['grant'] : nil),
                 'plan_commit' => Zk.plan_commit(pcactn), 'released' => true, 'r' => whole(decision['r']), 'issued_at' => whole(issued_at),
                 'expires_at' => whole(expires_at), 'prover' => @public_key }
        body.merge('sig' => AtlasPca.b64e(@key.sign(Zk.statement_message(body))))
      end
    end

    class << self
      # The Groth16 pairing check behind every verifier here. nil (the default) is libpcazk through ZkNative, under the rules of
      # the reference verifier. Otherwise a callable (verification_key, public_signals, proof) -> true / false that raises when
      # it cannot decide; anything but true is a refusal.
      attr_accessor :groth16_engine
    end

    module_function

    # ---- commitments and the attested-VM statement ----

    # Commitment to the policy: the grant's content address (what a verifier may KNOW about the grant without reading it).
    def policy_commitment(grant) = grant.is_a?(Hash) && grant['id'].is_a?(String) ? grant['id'] : AtlasPca.hash_canonical(grant)

    # The policy commitment a verifier pins when it is not allowed to read the grant's plaintext.
    def pinned_policy_commitment(grant) = policy_commitment(grant)

    # Commitment to the action: content address of the PCActn's action descriptor.
    def action_commitment(pcactn) = AtlasPca.hash_canonical(pcactn.is_a?(Hash) ? pcactn['action'] : nil)

    # the committed plan: the PCActn's plan root ('' when it has none)
    def plan_commit(pcactn)
      plan = pcactn.is_a?(Hash) ? pcactn['plan'] : nil
      root = plan.is_a?(Hash) ? plan['root'] : nil
      root.is_a?(String) ? root : ''
    end

    # what a statement's signature covers: the domain tag and the canonical JSON of every member but the signature
    def statement_message(body) = DOMAIN + AtlasPca.canon_bytes(body)

    # The attested-VM reference prover for the 32-byte Ed25519 secret of the VM (see AttestedComplianceProver#prove).
    def create_attested_compliance_prover(attestor_secret) = AttestedComplianceProver.new(attestor_secret)

    # The binding a prover VM's hardware quote must carry so that the quote vouches for ITS key: a quote taken for another key,
    # epoch or nonce does not bind.
    def prover_key_binding(prover_public_key, epoch, nonce)
      { 'holderPub' => prover_public_key, 'grantRef' => ZK_PROVER_BINDING_REF, 'epoch' => epoch, 'nonce' => nonce }
    end

    # a list as it was at construction: later edits by the caller must not change what a built verifier enforces
    def snapshot(list) = list.is_a?(Array) ? list.map { |x| x.is_a?(String) ? x.dup.freeze : x }.uniq.freeze : nil

    # The zk hook: hook.call({'pcactn' => ..., 'grant' => ...}) -> {'enforced' => true, 'ok' => bool, 'reason' => String?} over
    # the proof carried in pcactn['zk_compliance']. It fails closed and uses commitments only.
    #
    # With `snark_backend` the proof is opaque: the hook binds the public inputs (action / policy / plan commitments) to this
    # PCActn and delegates. Otherwise the proof is an attested-VM statement: well-formed, signed by one of
    # `trusted_prover_keys` and none of `revoked_prover_keys`, fresh (`now`: a callable giving epoch ms; `clock_skew_ms`), bound
    # to this action and plan, and committing to one of `policy_commitments` (default: the commitment derived from
    # ctx['grant']; pinning bare hashes lets a verifier enforce a policy it may not read).
    #
    # `prover_attestation` (attested-VM mode only) also requires hardware evidence for the prover key:
    # {'hardware_verifier' => a verifier labelled hardware or multi_root (verify(document, expected, now_ms)),
    #  'expected_binding' => callable(prover_key) -> binding, 'measurements' => [allowlisted runtime measurements]}.
    # Raises ArgumentError when that configuration is unusable. The configuration is copied at construction.
    def create_zk_verifier(trusted_prover_keys:, policy_commitments: nil, snark_backend: nil, revoked_prover_keys: nil,
                           prover_attestation: nil, now: nil, clock_skew_ms: nil)
      cfg = { trusted: snapshot(trusted_prover_keys) || [], revoked: snapshot(revoked_prover_keys) || [],
              policy: snapshot(policy_commitments), backend: snark_backend,
              skew: Risk.fin?(clock_skew_ms) ? [0, clock_skew_ms].max : 0, clock: now || -> { (Time.now.to_f * 1000).floor } }
      hw_label = nil
      if snark_backend.nil? && !prover_attestation.nil?
        pa = prover_attestation.to_h { |k, v| [k.to_s, v] }
        hw_label = AtlasPca.assurance_label_of(pa['hardware_verifier'])
        unless hw_label && %w[hardware multi_root].include?(hw_label['level'])
          raise ArgumentError, 'createZkVerifier: proverAttestation.hardwareVerifier must carry a hardware or multi_root assurance label'
        end

        ms = pa['measurements']
        unless ms.is_a?(Array) && !ms.empty? && ms.all? { |m| m.is_a?(String) && !m.empty? }
          raise ArgumentError, 'createZkVerifier: proverAttestation.measurements must be a non-empty allowlist'
        end
        raise ArgumentError, 'createZkVerifier: proverAttestation.expectedBinding must be a function' unless pa['expected_binding'].respond_to?(:call)

        cfg[:hardware] = { verifier: pa['hardware_verifier'], binding: pa['expected_binding'], measurements: snapshot(ms) }
      end
      cfg.freeze
      hook = lambda do |ctx|
        zk_check(cfg, ctx)
      rescue StandardError, SystemStackError => e
        zk_fail("zk verification error (fail closed): #{e.message.to_s.empty? ? 'unknown' : e.message}")
      end
      label = if !snark_backend.nil? then AtlasPca.assurance_label_of(snark_backend) || { 'level' => 'unknown' }
              elsif hw_label then { 'level' => 'attested_vm_hw', 'vendor' => "hardware-bound:#{hw_label['vendor'] || hw_label['level']}" }
              else { 'level' => 'attested_vm' }
              end
      AtlasPca.set_assurance_label(hook, label['level'], vendor: label['vendor'], awaiting_audit: label['awaiting_audit'], ceremony: label['ceremony'])
    end

    def zk_fail(reason) = { 'enforced' => true, 'ok' => false, 'reason' => reason }

    # one run of the hook (create_zk_verifier turns anything raised here into a denial)
    def zk_check(cfg, ctx)
      pcactn = ctx.is_a?(Hash) ? ctx['pcactn'] : nil
      proof = pcactn.is_a?(Hash) ? pcactn['zk_compliance'] : nil
      return zk_fail('no zk_compliance proof present') if proof.nil?

      grant = ctx['grant']
      action_commit = action_commitment(pcactn)
      plan = plan_commit(pcactn)
      want_policy = cfg[:policy] || [policy_commitment(grant)]

      unless cfg[:backend].nil? # the proof is opaque: bind the public inputs to THIS action and plan, then delegate
        policy_commit = cfg[:policy] && cfg[:policy].length == 1 ? cfg[:policy][0] : policy_commitment(grant)
        ok = cfg[:backend].verify(proof, { 'action_commit' => action_commit, 'policy_commit' => policy_commit, 'plan_commit' => plan }, ctx)
        return Js.truthy?(ok) ? { 'enforced' => true, 'ok' => true } : zk_fail('snark backend rejected the proof')
      end

      st = proof.is_a?(Hash) ? proof : {}
      return zk_fail('unrecognized compliance statement') unless st['v'].is_a?(Numeric) && st['v'] == 1 && st['mode'] == 'attested-vm'
      return zk_fail('statement does not assert release') unless st['released'] == true

      prover = st['prover']
      return zk_fail('prover key is not trusted') unless prover.is_a?(String) && cfg[:trusted].include?(prover)
      return zk_fail('prover key is revoked') if cfg[:revoked].include?(prover)

      sig = st['sig']
      unless sig.is_a?(String) && AtlasPca.verify_b64u(prover, statement_message(st.reject { |k, _| k == 'sig' }), sig)
        return zk_fail('compliance statement signature does not verify')
      end

      issued = st['issued_at']
      expires = st['expires_at']
      return zk_fail('malformed statement validity window') unless Risk.fin?(issued) && Risk.fin?(expires) && expires >= issued

      now_ms = cfg[:clock].call
      return zk_fail('compliance statement cannot be dated: the clock is not a finite number') unless Risk.fin?(now_ms)
      return zk_fail('compliance statement not yet valid') if now_ms + cfg[:skew] < issued
      return zk_fail('compliance statement expired') if now_ms - cfg[:skew] > expires
      # commitment binding: these hashes are the only policy / plan knowledge the verifier needs
      return zk_fail('statement does not bind to this action') unless st['action_commit'] == action_commit
      return zk_fail('statement does not bind to this plan commitment') unless st['plan_commit'] == plan

      policy = st['policy_commit']
      return zk_fail('statement policy commitment is not an expected policy') unless policy.is_a?(String) && want_policy.include?(policy)

      hw_reason = cfg[:hardware] && prover_hardware_refusal(cfg[:hardware], prover, now_ms)
      hw_reason ? zk_fail(hw_reason) : { 'enforced' => true, 'ok' => true }
    end

    # nil when hardware evidence binds this prover key to an allowlisted measured VM, else why not (the expensive check, last)
    def prover_hardware_refusal(hardware, prover, now_ms)
      hw = hardware[:verifier].verify({ 'attestor' => prover, 'mode' => 'hardware' }, hardware[:binding].call(prover), now_ms)
      unless hw.is_a?(Hash) && hw['ok'] == true
        return "prover hardware evidence invalid: #{hw.is_a?(Hash) ? (hw['reason'] || 'no reason given') : 'no result'}"
      end
      return 'prover hardware evidence does not bind the prover key' unless hw['bound'] == true

      measured = hw['measured']
      return 'prover hardware evidence carries no measured identity' unless measured.is_a?(Hash) && measured['runtime_measurement'].is_a?(String)
      return 'prover VM measurement is not allowlisted' unless hardware[:measurements].include?(measured['runtime_measurement'])

      nil
    end

    # ---- binding tag and the canonical envelope gate ----

    # A base64url commitment as a BN254 scalar-field element (decimal): the circuit's public binding tag. Bytes of any length
    # are reduced mod the field (at most 6 commitments of 32 bytes share a tag: a binding tag, not a hiding commitment).
    # Raises ArgumentError when the text is not canonical unpadded base64url.
    def commitment_field(b64u_commit)
      bytes = AtlasPca.b64d(b64u_commit) or raise ArgumentError, 'commitmentField: not base64url'
      (bytes.unpack1('H*').to_i(16) % BN254_FR).to_s
    end

    def text?(v, want) = v.is_a?(String) && v == want

    def canon_dec_below?(v, bound)
      v.is_a?(String) && v.valid_encoding? && v.length <= 120 && v.match?(CANON_DEC) && v.to_i < bound
    end

    # a Hash with exactly these members
    def members?(v, names) = v.is_a?(Hash) && v.size == names.length && names.all? { |k| v.key?(k) }

    def g1_canonical?(a, fq)
      a.is_a?(Array) && a.length == 3 && canon_dec_below?(a[0], fq) && canon_dec_below?(a[1], fq) && text?(a[2], '1')
    end

    # True iff `env` is exactly the one canonical Groth16 envelope for `curve` ('bn254' | 'bls12-381'): the exact member sets,
    # canonical decimals below the field modulus, z == 1. A valid proof has many other encodings (x + p, leading zeros, hex,
    # extra members) that the pairing check alone would accept; this gate refuses them all.
    def canonical_groth16_envelope?(env, curve)
      return false unless members?(env, %w[system circuit proof publicSignals])

      bn = curve == 'bn254'
      fq = bn ? BN254_FQ : BLS12381_FQ
      fr = bn ? BN254_FR : BLS12381_FR
      ps = env['publicSignals']
      return false unless ps.is_a?(Array) && ps.all? { |x| canon_dec_below?(x, fr) }

      pr = env['proof']
      return false unless members?(pr, %w[pi_a pi_b pi_c protocol curve])
      return false unless text?(pr['protocol'], 'groth16') && text?(pr['curve'], bn ? 'bn128' : 'bls12381')
      return false unless g1_canonical?(pr['pi_a'], fq) && g1_canonical?(pr['pi_c'], fq)

      b = pr['pi_b']
      return false unless b.is_a?(Array) && b.length == 3
      return false unless b[0, 2].all? { |row| row.is_a?(Array) && row.length == 2 && canon_dec_below?(row[0], fq) && canon_dec_below?(row[1], fq) }

      b[2].is_a?(Array) && b[2].length == 2 && text?(b[2][0], '1') && text?(b[2][1], '0')
    end

    # ---- fixture locations, bundled keys, circuit versions ----

    # Where circuit build products are read from: ATLAS_PCA_CIRCUITS_DIR, else `circuits` beside lib.
    def circuits_dir
      dir = ENV['ATLAS_PCA_CIRCUITS_DIR']
      dir.nil? || dir.empty? ? File.expand_path('../../circuits', __dir__) : dir
    end

    # The location of one circuit artifact by its reference name (a key of PATHS), e.g. path('POLICYVM_BOUND_VKEY_PATH').
    def path(name) = File.join(circuits_dir, *PATHS.fetch(name))

    # an explicit key, else the file at `key_path`, else the bundled key (when the circuit has one), else the build product
    def resolve_vkey(explicit, key_path, bundled, default_name)
      return explicit unless explicit.nil?
      return JSON.parse(bundled) if key_path.nil? && bundled

      JSON.parse(File.read(key_path || path(default_name), encoding: 'UTF-8'))
    end

    # The committed version of a circuit id ('pca-compliance-v1', 'pca-policyvm-v1', 'pca-policyvm-v2'): the SHA-256 over its
    # whole source set and the pinned compiler. Raises ArgumentError on an unknown id.
    def circuit_version(id)
      v = JSON.parse(ZkBundled::CIRCUIT_VERSIONS_JSON)
      c = id.is_a?(String) ? v['circuits'][id] : nil
      raise ArgumentError, "circuitVersion: unknown circuit #{id.is_a?(String) ? id.inspect : Js.string(id)}" if c.nil?

      { 'circuit' => id, 'sourceSha256' => c['source_sha256'], 'circom' => v['circom'], 'circomlib' => v['circomlib'] }
    end

    # ---- pairing check ----

    # the pairing check: the engine set with Zk.groth16_engine=, else libpcazk. Callers that must not raise turn a raise into a
    # refusal
    def groth16_verify(vkey, public_signals, proof)
      engine = Zk.groth16_engine
      engine.nil? ? native_groth16_verify(vkey, public_signals, proof) : engine.call(vkey, public_signals, proof) == true
    end

    # The pairing check of the reference verifier through libpcazk: the curve is the one the KEY names (the library reads the name as snarkjs does,
    # so every spelling the reference accepts works and a name it does not know is an invalid proof), and the key's protocol and nPublic members and
    # surplus IC entries are not checked. Raises ZkNative::BackendMissing without the library.
    def native_groth16_verify(vkey, public_signals, proof)
      require_relative 'zk_native'
      ZkNative.verify(ZkNative::FROM_KEY, vkey, proof, public_signals)['valid'] == true
    end

    # 'multi-party' only for an explicit verifying key backed by pinned ceremony evidence; the bundled keys are single-party
    def ceremony_label(verification_key, ceremony, circuit)
      ZkCeremony.ceremony_of(verification_key, ceremony.is_a?(Hash) ? ceremony.merge('circuit' => circuit) : nil)
    end

    # ---- first circuit: pca-compliance-v1 (BN254) ----
    # Public signals: [0] policyCommit [1] planCommit [2] actionCommit (Poseidon openings), [3] shaPolicy [4] shaPlan
    # [5] shaAction (binding tags), [6] allow.

    # The Groth16 backend of pca-compliance-v1: a well-formed envelope, allow == 1, binding tags equal to commitment_field of
    # the verifier's own commitments (a proof for other commitments is refused), the canonical encoding, then the pairing check
    # under `verification_key` (a snarkjs key Hash) or the file `verification_key_path`. There is no bundled key. `ceremony`
    # ({'transcript', 'sha256'}) is evidence that the key came from a multi-party ceremony; without it the label says
    # single-party. verify raises when no pairing backend is available.
    def create_groth16_snark_backend(verification_key: nil, verification_key_path: nil, ceremony: nil)
      key = nil
      label = { 'level' => 'groth16', 'ceremony' => ceremony_label(verification_key, ceremony, 'pca-compliance-v1') }
      SnarkBackend.new(label) do |env, public_inputs, _ctx|
        next false unless env.is_a?(Hash) && text?(env['system'], 'groth16-bn254') && text?(env['circuit'], 'pca-compliance-v1')

        ps = env['publicSignals']
        next false unless ps.is_a?(Array) && ps.length == 7 && !env['proof'].nil? && text?(ps[6], '1')
        next false unless text?(ps[3], commitment_field(public_inputs['policy_commit']))
        next false unless text?(ps[4], commitment_field(public_inputs['plan_commit']))
        next false unless text?(ps[5], commitment_field(public_inputs['action_commit']))
        next false unless canonical_groth16_envelope?(env, 'bn254')

        groth16_verify(key ||= resolve_vkey(verification_key, verification_key_path, nil, 'DEFAULT_VKEY_PATH'), ps, env['proof'])
      end
    end

    # String(v) of a witness value, as the circuit input wants it
    def witness_text(witness) = witness.to_h { |k, v| [k.to_s, v.is_a?(Integer) ? v.to_s : Js.string(v)] }

    def prove(circuit_input, wasm_path, zkey_path, circuit, seed)
      require_relative 'zk_native'
      ZkNative.lib # no backend: refuse before reading a proving key
      out = ZkNative.prove('bn254', File.binread(wasm_path), File.binread(zkey_path), circuit_input, seed: seed)
      { 'system' => 'groth16-bn254', 'circuit' => circuit, 'proof' => out['proof'], 'publicSignals' => out['publicSignals'] }
    end

    # A pca-compliance-v1 proof from the private witness {'action_commit', 'policy_commit', 'plan_commit', 'verb', 'resource',
    # 'planVerb', 'policySalt', 'planSalt', 'actionSalt', 'risk', 'budget'}. Raises on a non-compliant witness (verb mismatch or
    # risk > budget): a false statement is unprovable. Needs libpcazk, the witness wasm and the proving key (build products).
    # `seed` (32 bytes) makes the proof deterministic and is for tests only.
    def prove_groth16_compliance(inp, wasm_path: nil, zkey_path: nil, seed: nil)
      input = witness_text(%w[verb resource planVerb policySalt planSalt actionSalt risk budget].to_h { |k| [k, inp[k]] })
      input.update('shaPolicy' => commitment_field(inp['policy_commit']), 'shaPlan' => commitment_field(inp['plan_commit']),
                   'shaAction' => commitment_field(inp['action_commit']), 'allow' => '1')
      prove(input, wasm_path || path('DEFAULT_WASM_PATH'), zkey_path || path('DEFAULT_ZKEY_PATH'), 'pca-compliance-v1', seed)
    end

    # ---- the Policy VM circuits ----

    # {'hi', 'lo'}: SHA-256 of the fields laid out as the circuit does (each an unsigned 64-bit big-endian integer), split into
    # the two 128-bit halves the circuit exposes, as decimal strings. A field is an Integer, an integral Float or integer text.
    # Raises on a field outside 0 .. 2^64 - 1 or one that is no integer.
    def policy_vm_struct_hash(fields)
      raise TypeError, 'policyVmStructHash: fields must be a list' unless fields.is_a?(Array)

      bytes = fields.map do |f|
        v = Js.bigint(f)
        raise RangeError, 'policyVmStructHash: field out of uint64 range' if v.negative? || v >= U64

        [v].pack('Q>')
      end.join
      digest = Digest::SHA256.hexdigest(bytes)
      { 'hi' => digest[0, 32].to_i(16).to_s, 'lo' => digest[32, 32].to_i(16).to_s }
    end

    # The risk commitment of pca-policyvm-v2 (riskHi / riskLo): the five risk magnitudes (fixed-point, scale 1e6) in
    # POLICYVM_BOUND_RISK_FIELDS order. A verifier that knows the attested values pins it, so the proven risk, tier and admit
    # bit cannot come from magnitudes the prover chose.
    def policy_vm_risk_hash(fields)
      unless fields.is_a?(Array) && fields.length == POLICYVM_BOUND_RISK_FIELDS.length
        raise ArgumentError, 'policyVmRiskHash: need exactly 5 risk fields'
      end

      policy_vm_struct_hash(fields)
    end

    def decode_public(public_signals, layout)
      raise TypeError, 'public signals must be a list' unless public_signals.is_a?(Array)

      s = ->(name) { public_signals[layout.fetch(name)] }
      out = %w[action policy plan risk].select { |n| layout.key?("#{n}Hi") }.to_h { |n| ["#{n}Hash", { 'hi' => s.call("#{n}Hi"), 'lo' => s.call("#{n}Lo") }] }
      %w[r t admit allow now blast delegationDepth recentCount allocChild].each { |name| out[name] = s.call(name) }
      out
    end

    # The proven statement of a pca-policyvm-v1 proof: the three struct hashes ('actionHash', 'policyHash', 'planHash', each
    # {'hi', 'lo'}), 'r', 't', 'admit', 'allow' and the context. A signal the list is too short for is nil.
    def decode_policy_vm_public(public_signals) = decode_public(public_signals, POLICYVM_PUBLIC_SIGNAL)

    # As decode_policy_vm_public for pca-policyvm-v2, plus the risk commitment 'riskHash'.
    def decode_policy_vm_bound_public(public_signals) = decode_public(public_signals, POLICYVM_BOUND_PUBLIC_SIGNAL)

    # ---- deterministic action quantisation (binds a proof to the action in hand) ----

    # uint64 content address of a domain-tagged string: the first 8 bytes of its SHA-256
    def content_address(domain, value) = Digest::SHA256.digest(Js.utf8("atlas-pca/policyvm-quantize/#{domain}:#{value}")).unpack1('Q>')

    def u64(v, what)
      ok = v.is_a?(Integer) || (v.is_a?(Float) && v.finite? && v == v.floor)
      raise ArgumentError, "policyvm quantize: #{what} is not a uint64" unless ok && v >= 0 && v < U64

      v.to_i
    end

    def code_for(domain, value, codes, strict)
      raise ArgumentError, "policyvm quantize: #{domain} must be a string" unless value.is_a?(String)
      return u64(codes[value], "#{domain} code") if codes.is_a?(Hash) && codes.key?(value)
      raise ArgumentError, "policyvm quantize: #{domain} \"#{value}\" is not in the catalog (strict)" if strict

      content_address(domain, value)
    end

    def param_scalar(params, field)
      return 0 unless Js.truthy?(field)

      own = params.is_a?(Hash) && params.key?(field)
      raise ArgumentError, 'policyvm quantize: paramScalar is not a non-negative integer' if !own && Js.truthy?(params) && INHERITED.include?(field)

      v = own ? params[field] : nil
      return 0 if v.nil?
      return u64(v.to_i, 'paramScalar') if v.is_a?(String) && v.match?(/\A[0-9]+\z/)
      raise ArgumentError, 'policyvm quantize: paramScalar is not a non-negative integer' unless v.is_a?(Integer) || v.is_a?(Float)
      if (v.is_a?(Float) && (!v.finite? || v != v.floor || Js.neg_zero?(v))) || v.negative?
        raise ArgumentError, 'policyvm quantize: paramScalar must be a non-negative integer'
      end

      u64(v, 'paramScalar')
    end

    def reversibility_index(rc, what)
      POLICYVM_REVERSIBILITY_ORDER.index(rc) or raise ArgumentError, "policyvm quantize: unknown #{what} class \"#{Js.string(rc)}\""
    end

    # The live action {'verb', 'resource', 'reversibility_class'?, 'params'?} as the circuit's 4-field struct: [verb code,
    # resource code, reversibility-class index, param scalar]. Codes come from the shared catalogs `verb_codes` /
    # `resource_codes` ({text => uint64}); a string absent from them is content-addressed (first 8 bytes of a domain-tagged
    # SHA-256) unless `strict_catalog`. The scalar is the non-negative integer in params[param_scalar_field] (0 when unset).
    # MUST equal the map the prover used. Raises ArgumentError (fail closed) on anything that cannot be quantised.
    # Every quantizer takes its options as the keywords verb_codes:, resource_codes:, strict_catalog:, param_scalar_field:, or
    # as `opts`, the reference's options object ({'verbCodes', 'resourceCodes', 'strictCatalog', 'paramScalarField'}); a nil
    # `opts` raises TypeError, as the reference throws on null options.
    def quantize_action_struct(action, opts = ABSENT, **keywords)
      o = quantize_opts(opts, keywords)
      raise ArgumentError, 'policyvm quantize: action is missing' unless action.is_a?(Hash)

      strict = o[:strict_catalog] == true
      rc = action['reversibility_class']
      [code_for('verb', action['verb'], o[:verb_codes], strict), code_for('resource', action['resource'], o[:resource_codes], strict),
       reversibility_index(rc.nil? ? 'reversible' : rc, 'reversibility'), param_scalar(action['params'], o[:param_scalar_field])]
    end

    # the options of a quantizer as {verb_codes:, resource_codes:, strict_catalog:, param_scalar_field:} (members given only)
    def quantize_opts(opts, keywords)
      unknown = keywords.keys - QUANTIZE_OPTS.values
      raise ArgumentError, "unknown keyword: #{unknown.first.inspect}" unless unknown.empty?
      return keywords if opts.equal?(ABSENT)
      raise TypeError, 'policyvm quantize: the options are nil' if opts.nil?

      QUANTIZE_OPTS.each_with_object(keywords.dup) { |(name, key), out| out[key] = opts[name] if opts.is_a?(Hash) && opts.key?(name) }
    end

    # The plan node {'verb', 'resource', 'semanticDist', 'planSalt'} as the circuit's 4-field plan struct. The salt is the
    # prover's: a verifier binds the ACTION.
    def quantize_plan_struct(plan, opts = ABSENT, **keywords)
      o = quantize_opts(opts, keywords)
      raise ArgumentError, 'policyvm quantize: plan is missing' unless plan.is_a?(Hash)

      strict = o[:strict_catalog] == true
      [code_for('verb', plan['verb'], o[:verb_codes], strict), code_for('resource', plan['resource'], o[:resource_codes], strict),
       u64(plan['semanticDist'], 'semanticDist'), u64(plan['planSalt'], 'planSalt')]
    end

    # The policy {'weights' => {'alpha' .. 'zeta'}, 'theta1', 'theta2', 'kappa', 'budgetB', 'policyVerb', 'policyResource',
    # 'policyParamBound', 'expiresAt', 'notBefore', 'maxBlast', 'maxDepth', 'revMax', 'rateMax', 'allocParent'} as the circuit's
    # 20-field struct (the policy's own fixed-point integers).
    def quantize_policy_struct(policy, opts = ABSENT, **keywords)
      o = quantize_opts(opts, keywords)
      w = policy.is_a?(Hash) ? policy['weights'] : nil
      raise ArgumentError, 'policyvm quantize: policy or its weights are missing' unless w.is_a?(Hash)

      strict = o[:strict_catalog] == true
      %w[alpha beta gamma delta epsilon zeta].map { |k| u64(w[k], "w#{k.capitalize}") } +
        %w[theta1 theta2 kappa budgetB].map { |k| u64(policy[k], k) } +
        [code_for('verb', policy['policyVerb'], o[:verb_codes], strict), code_for('resource', policy['policyResource'], o[:resource_codes], strict)] +
        %w[policyParamBound expiresAt notBefore maxBlast maxDepth].map { |k| u64(policy[k], k) } +
        [reversibility_index(policy['revMax'], 'revMax'), u64(policy['rateMax'], 'rateMax'), u64(policy['allocParent'], 'allocParent')]
    end

    # {'action' => ..., 'plan'? => ..., 'policy'? => ...}: the action struct always, the plan and policy structs when `inp`
    # carries them. Takes the options of quantize_action_struct.
    def quantize_policy_vm_inputs(inp, opts = ABSENT, **keywords)
      o = quantize_opts(opts, keywords)
      raise ArgumentError, 'policyvm quantize: action is missing' unless inp.is_a?(Hash)

      out = { 'action' => quantize_action_struct(inp['action'], **o) }
      out['plan'] = quantize_plan_struct(inp['plan'], **o) if Js.truthy?(inp['plan'])
      out['policy'] = quantize_policy_struct(inp['policy'], **o) if Js.truthy?(inp['policy'])
      out
    end

    # The circuit's action commitment (actionHi / actionLo) recomputed from the LIVE action. Requiring a proof's halves to
    # equal it binds the proof to this action: a proof minted for another action mismatches. Takes the options of
    # quantize_action_struct and raises as it does.
    def policy_vm_commitment_from_action(action, opts = ABSENT, **keywords)
      policy_vm_struct_hash(quantize_action_struct(action, opts, **keywords))
    end

    # ---- context pins ----

    # a pin value as an integer; nil when it is none (a Float is exact only in the safe-integer range)
    def pin_integer(v)
      return nil if v.is_a?(Float) && !Js.safe_integer?(v)

      Js.bigint(v)
    rescue StandardError
      nil
    end

    def signal_matches_pin?(signal, pin)
      return false unless signal.is_a?(String) && signal.valid_encoding? && signal.match?(CANON_DEC)
      raise TypeError, 'a pin is a value or a {min, max} window, not nil' if pin.nil?

      x = signal.to_i
      if pin.is_a?(Hash) || pin.is_a?(Array)
        lo = pin_integer(pin.is_a?(Hash) ? pin['min'] : nil)
        hi = pin_integer(pin.is_a?(Hash) ? pin['max'] : nil)
        return !lo.nil? && !hi.nil? && lo <= x && x <= hi
      end
      x == pin_integer(pin)
    end

    # Do the public signals satisfy `expect`? `expect` is a Hash (or a callable returning one, evaluated at each call so 'now'
    # can track a live clock) pinning 'now', 'blast', 'delegationDepth', 'recentCount', 'allocChild', 'r', 't' to an exact value
    # (Integer, integral Float, decimal text) or an inclusive {'min', 'max'} window, plus 'requireAdmit' / 'requireTier1'. Not
    # given: no pins; nil (or a callable that raises or returns nil) matches nothing. Even with no pins, a context signal that
    # is not a canonical decimal below 2^64 is refused: the circuit's comparators run on un-range-checked inputs, so a
    # field-negative 'now' would otherwise pass now < expiresAt. `layout` is POLICYVM_PUBLIC_SIGNAL (default) or
    # POLICYVM_BOUND_PUBLIC_SIGNAL. A verifier that serves real traffic should pin at least 'now' and 'recentCount'.
    def policy_vm_context_matches?(public_signals, expect = ABSENT, layout = POLICYVM_PUBLIC_SIGNAL)
      raise TypeError, 'public signals must be a list' if public_signals.nil?
      return false unless public_signals.is_a?(Array)

      at = ->(name) { public_signals[layout.fetch(name)] }
      return false unless CONTEXT_SIGNALS.all? { |n| canon_dec_below?(at.call(n), U64) }
      return true if expect.equal?(ABSENT)

      if expect.respond_to?(:call)
        expect = begin
          expect.call
        rescue StandardError
          nil
        end
      end
      expect = {} if expect.is_a?(Array)
      return false unless expect.is_a?(Hash)
      return false unless (CONTEXT_SIGNALS + %w[r t]).all? { |n| !expect.key?(n) || signal_matches_pin?(at.call(n), expect[n]) }
      return false if Js.truthy?(expect['requireAdmit']) && !text?(at.call('admit'), '1')

      !Js.truthy?(expect['requireTier1']) || text?(at.call('t'), '1')
    end

    # the two 128-bit halves of one commitment equal the expected digest (or no expectation was set)
    def halves_match?(public_signals, layout, name, want)
      return true unless Js.truthy?(want)

      want.is_a?(Hash) && %w[Hi Lo].all? { |h| ZkCeremony.same?(public_signals[layout.fetch(name + h)], want[h.downcase]) }
    end

    # ---- verification ----

    # Verify a Policy VM Groth16 proof offline: {'system' => 'groth16-bn254' | 'groth16-bls12-381', 'circuit' =>
    # 'pca-policyvm-v1' | 'pca-policyvm-v2', 'proof', 'publicSignals'}. false (fail closed) on anything malformed, on a proof
    # the pairing check refuses, and when no pairing backend is available.
    #
    # Order: shape, circuit and system tags (the risk-bound circuit is BN254 only), signal count, allow == 1, the risk-hash pin
    # (`expect_risk_hash` {'hi', 'lo'} from policy_vm_risk_hash; only v2 carries one, so a v1 proof is refused when it is set;
    # nil is not "no pin": it refuses a v1 proof and raises TypeError on a v2 proof, as the reference does on null),
    # the canonical envelope gate, the context pins (`expect`, see policy_vm_context_matches?), then the pairing check under
    # `verification_key` (a snarkjs key Hash), else the file `verification_key_path`, else the bundled key of the proof's curve
    # (the risk-bound circuit has none and reads path('POLICYVM_BOUND_VKEY_PATH')).
    def verify_policy_vm_proof(env, verification_key: nil, verification_key_path: nil, expect: ABSENT, expect_risk_hash: ABSENT)
      return false unless env.is_a?(Hash)

      bound = text?(env['circuit'], 'pca-policyvm-v2')
      return false unless bound || text?(env['circuit'], 'pca-policyvm-v1')

      bls = text?(env['system'], 'groth16-bls12-381')
      return false unless text?(env['system'], 'groth16-bn254') || (bls && !bound)

      layout = bound ? POLICYVM_BOUND_PUBLIC_SIGNAL : POLICYVM_PUBLIC_SIGNAL
      ps = env['publicSignals']
      return false unless ps.is_a?(Array) && ps.length == layout.size && !env['proof'].nil?
      return false unless text?(ps[layout['allow']], '1')
      unless expect_risk_hash.equal?(ABSENT)
        return false unless bound
        raise TypeError, 'verifyPolicyVmProof: expectRiskHash is nil' if expect_risk_hash.nil? # the reference reads its halves

        return false unless expect_risk_hash.is_a?(Hash) && halves_match?(ps, layout, 'risk', expect_risk_hash)
      end
      return false unless canonical_groth16_envelope?(env, bls ? 'bls12-381' : 'bn254')
      return false unless policy_vm_context_matches?(ps, expect, layout)

      bundled = if bound then nil
                else bls ? ZkBundled::POLICYVM_BLS12381_VKEY_JSON : ZkBundled::POLICYVM_VKEY_JSON
                end
      vkey = resolve_vkey(verification_key, verification_key_path, bundled, 'POLICYVM_BOUND_VKEY_PATH')
      begin
        groth16_verify(vkey, ps, env['proof'])
      rescue StandardError
        false # a key or proof the check cannot read, or no backend: a refusal
      end
    end

    # the shared backend of both curves of pca-policyvm-v1 and of the risk-bound circuit: `hashes` {name => expected halves}
    def policy_vm_backend(circuit, layout, bundled, default_name, hashes, verification_key, verification_key_path, expect, ceremony, risk = ABSENT)
      key = nil
      cer = ceremony_label(verification_key, ceremony, circuit)
      bound = hashes.values.all? { |w| Js.truthy?(w) }
      label = bound ? { 'level' => 'policyvm_snark', 'ceremony' => cer } : { 'level' => 'unknown', 'vendor' => 'policyvm-unbound', 'ceremony' => cer }
      SnarkBackend.new(label) do |env, _public_inputs, _ctx|
        next false unless env.is_a?(Hash) && text?(env['circuit'], circuit)

        ps = env['publicSignals']
        next false if hashes.key?('risk') && !ps.is_a?(Array)
        next false unless !ps.is_a?(Array) || hashes.all? { |name, want| halves_match?(ps, layout, name, want) }

        key ||= resolve_vkey(verification_key, verification_key_path, bundled, default_name)
        verify_policy_vm_proof(env, verification_key: key, expect: expect, expect_risk_hash: risk)
      end
    end

    # A backend over the full Policy VM circuit (BN254 key bundled). It verifies the proof and allow == 1 and, when given,
    # binds the proof's public struct-hash halves to `expect_action_hash` / `expect_policy_hash` / `expect_plan_hash` ({'hi',
    # 'lo'} from policy_vm_struct_hash / policy_vm_commitment_from_action). It does NOT bind the canonical-JSON commitments of
    # the hook: the circuit commits to a fixed-layout struct. The label is policyvm_snark only with all three pinned; otherwise
    # a valid proof may be for another compliant action and the label is unknown. `expect` pins the context (see
    # policy_vm_context_matches?); `ceremony` as in create_groth16_snark_backend.
    def create_policy_vm_snark_backend(verification_key: nil, verification_key_path: nil, expect: ABSENT, ceremony: nil,
                                       expect_action_hash: nil, expect_policy_hash: nil, expect_plan_hash: nil)
      policy_vm_backend('pca-policyvm-v1', POLICYVM_PUBLIC_SIGNAL, ZkBundled::POLICYVM_VKEY_JSON, 'POLICYVM_VKEY_PATH',
                        { 'action' => expect_action_hash, 'policy' => expect_policy_hash, 'plan' => expect_plan_hash },
                        verification_key, verification_key_path, expect, ceremony)
    end

    # The BLS12-381 (128-bit) counterpart of create_policy_vm_snark_backend: same binding and verification, BLS12-381 key bundled.
    def create_policy_vm_snark_backend_bls12381(verification_key: nil, verification_key_path: nil, expect: ABSENT, ceremony: nil,
                                                expect_action_hash: nil, expect_policy_hash: nil, expect_plan_hash: nil)
      policy_vm_backend('pca-policyvm-v1', POLICYVM_PUBLIC_SIGNAL, ZkBundled::POLICYVM_BLS12381_VKEY_JSON, 'POLICYVM_BLS12381_VKEY_PATH',
                        { 'action' => expect_action_hash, 'policy' => expect_policy_hash, 'plan' => expect_plan_hash },
                        verification_key, verification_key_path, expect, ceremony)
    end

    # A backend over the risk-bound circuit (pca-policyvm-v2, BN254): the checks of create_policy_vm_snark_backend plus the risk
    # commitment `expect_risk_hash` (policy_vm_risk_hash over the attested magnitudes). policyvm_snark only with all four
    # pinned; a nil `expect_risk_hash` pins nothing here and then raises at verification, as the reference. There is no bundled key: pass `verification_key` / `verification_key_path`, or path('POLICYVM_BOUND_VKEY_PATH')
    # is read.
    def create_policy_vm_bound_snark_backend(verification_key: nil, verification_key_path: nil, expect: ABSENT, ceremony: nil,
                                             expect_action_hash: nil, expect_policy_hash: nil, expect_plan_hash: nil, expect_risk_hash: ABSENT)
      policy_vm_backend('pca-policyvm-v2', POLICYVM_BOUND_PUBLIC_SIGNAL, nil, 'POLICYVM_BOUND_VKEY_PATH',
                        { 'action' => expect_action_hash, 'policy' => expect_policy_hash, 'plan' => expect_plan_hash,
                          'risk' => expect_risk_hash.equal?(ABSENT) ? nil : expect_risk_hash },
                        verification_key, verification_key_path, expect, ceremony, expect_risk_hash)
    end

    # A pca-policyvm-v1 proof (BN254) from the complete fixed-point witness (every circuit input, the division witnesses
    # included). Raises on a non-compliant witness: a denied action cannot be proven. Needs libpcazk, the witness wasm and the
    # proving key (build products; the bundled verifying key is enough to VERIFY). `seed` is for tests only.
    def prove_policy_vm_compliance(witness, wasm_path: nil, zkey_path: nil, seed: nil)
      prove(witness_text(witness), wasm_path || path('POLICYVM_WASM_PATH'), zkey_path || path('POLICYVM_ZKEY_PATH'), 'pca-policyvm-v1', seed)
    end

    # A risk-bound pca-policyvm-v2 proof; same witness inputs as prove_policy_vm_compliance. Raises on a non-compliant witness.
    def prove_policy_vm_bound_compliance(witness, wasm_path: nil, zkey_path: nil, seed: nil)
      prove(witness_text(witness), wasm_path || path('POLICYVM_BOUND_WASM_PATH'), zkey_path || path('POLICYVM_BOUND_ZKEY_PATH'), 'pca-policyvm-v2', seed)
    end
  end
end
