# frozen_string_literal: true

require 'digest'
require 'openssl'
require 'securerandom'
require_relative '../atlas_pca'

module AtlasPca
  # The pure, scheme-independent parts of the homomorphic risk gate (the TypeScript reference, @atlasauth/pca-fhe): risk-input
  # transformation and fixed-point quantization, the public gate policy, the risk claim binding read from a signed action, the
  # plaintext reference verdict, and (Fhe::Origin) the signed-claim / verdict-attestation layer with its replay guard. Values are
  # parsed JSON (Hash, Array, Integer, Float); a JavaScript number that is not finite is the fail-closed worst case, as in the
  # reference.
  #
  # NOT ported: the BFV evaluation itself (key generation, encryption of the risk inputs, the homomorphic weighted sum and slack,
  # decryption of the verdict). The reference runs it on Microsoft SEAL (WebAssembly); the vetted wire-compatible native route is
  # SEAL's own C export API built from the pinned SEAL tag and bound through ffi, which belongs to the FHE track, and a hand-written
  # BFV would be a hand-rolled lattice cryptosystem. The signed-claim layer is scheme-independent: a Ruby verifier can check a claim
  # produced by the reference and attest a verdict over a ciphertext it never opens.
  module Fhe
    POLY_MODULUS_DEGREE = 8192
    PLAIN_MODULUS_BITS = 30
    PLAIN_MODULUS = 1_073_692_673
    SIGNED_BOUND = PLAIN_MODULUS / 2
    DEFAULT_SCALE = 1000
    RISK_DIM = 6
    INPUT_FIELDS = %w[semanticDistance reversibility blastRadius taint confidence age].freeze

    module_function

    # the JavaScript number value of a parsed JSON number; NaN for anything that is not a number (Number.isFinite fails)
    def num(o) = o.is_a?(Numeric) ? o.to_f : Float::NAN

    def finite?(x) = !x.nan? && !x.infinite?
    def clamp01(x) = x < 0 ? 0.0 : (x > 1 ? 1.0 : x)
    def unit(x, worst) = finite?(x) ? clamp01(x) : worst
    def wt(x) = finite?(x) && x > 0 ? x : 0.0

    def obj(o)
      raise ArgumentError, 'not an object' unless o.is_a?(Hash)

      o
    end

    def field(m, k)
      raise ArgumentError, 'cannot read a member of null' if m.nil?

      num(obj(m)[k])
    end

    # [d, 1 - rev, bl, taint, 1 - conf, age], each through unit with the worst case of the risk score
    def transformed_inputs(i)
      [unit(field(i, 'semanticDistance'), 1.0), 1 - unit(field(i, 'reversibility'), 0.0), unit(field(i, 'blastRadius'), 1.0),
       unit(field(i, 'taint'), 1.0), 1 - unit(field(i, 'confidence'), 0.0), unit(field(i, 'age'), 1.0)]
    end

    # the weight vector of the risk score in canonical order with its clamp applied
    def weight_vector(w) = %w[alpha beta gamma delta epsilon zeta].map { |k| wt(field(w, k)) }

    # JavaScript Math.round (ties toward +infinity), exact
    def js_round(x)
      return x unless finite?(x)

      f = x.floor.to_f
      x - f >= 0.5 ? f + 1 : f
    end

    def require_scale(scale)
      raise ArgumentError, 'scale must be a positive integer' unless finite?(scale) && scale == scale.round && scale.positive?
    end

    # round(x_i * scale) for each transformed input: the integer vector the agent encrypts
    def quantize_risk_inputs(i, scale = DEFAULT_SCALE)
      s = num(scale)
      require_scale(s)
      transformed_inputs(i).map { |t| js_round(t * s) }
    end

    # a JSON number value for a JavaScript number: a safe integer as an Integer, else the Float
    def num_val(d) = finite?(d) && d == d.round && d.abs <= MAX_SAFE ? d.to_i : d

    # The public gate policy from a risk policy {weights, kappa} and the trust budget B, at fixed-point scale S: weights round(w_i S),
    # kappa-weighted weights round(kappa w_i S), budget round(B S^2). Refuses a policy whose scaled values could overflow the signed
    # plain-modulus range (a wrap would silently corrupt the verdict).
    def fhe_risk_policy(core, budget, scale_arg = DEFAULT_SCALE)
      scale = num(scale_arg)
      require_scale(scale)
      b = num(budget)
      raise ArgumentError, 'budget must be finite and >= 0' unless finite?(b) && b >= 0

      kappa = field(core, 'kappa')
      raise ArgumentError, 'policy.kappa must be finite and > 0' unless finite?(kappa) && kappa > 0

      w = weight_vector(obj(core['weights']))
      ws = w.map { |x| js_round(x * scale) }
      kws = w.map { |x| js_round(kappa * x * scale) }
      budget_scaled = js_round(b * scale * scale)
      max_abs = [ws.reduce(0.0) { |a, x| a + x } * scale, kws.reduce(0.0) { |a, x| a + x } * scale, budget_scaled].max # plain left-to-right sums (Array#sum is compensated)
      if max_abs >= SIGNED_BOUND
        raise ArgumentError, "policy/scale overflow the plain modulus: max |value| #{max_abs} must be < SIGNED_BOUND #{SIGNED_BOUND}. Lower the scale or the weights/budget."
      end

      { 'scale' => num_val(scale), 'dim' => RISK_DIM, 'weightsScaled' => ws.map { |x| num_val(x) }, 'kappaWeightsScaled' => kws.map { |x| num_val(x) },
        'budgetScaled' => num_val(budget_scaled), 'kappa' => num_val(kappa) }
    end

    # the six normalized risk inputs of a signed action's risk claim; a missing or non-numeric field is NaN (fail-closed)
    def risk_inputs_from_pcactn(p)
      src = obj(obj(obj(p)['risk_claim'])['inputs'])
      INPUT_FIELDS.to_h { |k| [k, src[k].is_a?(Numeric) ? src[k] : Float::NAN] }
    end

    # the replay binding of a signed action: audience, action digest, counter and the optional nonce
    def binding_from_pcactn(p)
      p = obj(p)
      m = { 'aud' => p['aud'], 'actionRef' => obj(p['action'])['params_digest'], 'counter' => p['counter'] }
      m['nonce'] = p['nonce'] if p.key?('nonce')
      m
    end

    # the plaintext reference verdict: r = risk score, admit iff kappa-cost(r) <= budget. Returns {r, admit}.
    def plaintext_verdict(inputs, core, budget)
      w = obj(core['weights'])
      r = clamp01(wt(field(w, 'alpha')) * unit(field(inputs, 'semanticDistance'), 1.0) +
                  wt(field(w, 'beta')) * (1 - unit(field(inputs, 'reversibility'), 0.0)) +
                  wt(field(w, 'gamma')) * unit(field(inputs, 'blastRadius'), 1.0) +
                  wt(field(w, 'delta')) * unit(field(inputs, 'taint'), 1.0) +
                  wt(field(w, 'epsilon')) * (1 - unit(field(inputs, 'confidence'), 0.0)) +
                  wt(field(w, 'zeta')) * unit(field(inputs, 'age'), 1.0))
      kappa = field(core, 'kappa')
      cost = (finite?(kappa) && kappa > 0 ? kappa : 0.0) * clamp01(finite?(r) ? r : 1.0)
      { 'r' => num_val(r), 'admit' => finite?(num(budget)) && cost <= num(budget) }
    end

    # Origin authentication of an encrypted risk claim (scheme-independent): the encryptor signs the ciphertext, the binding to one
    # action, the gate policy, a context and a one-time nonce; the verifier checks the signature, the context, the binding, the policy
    # and a replay guard BEFORE spending any evaluator work; the key holder signs the verdict over the exact claim and gate output it
    # opened.
    module Origin
      CLAIM_DOMAIN = "atlas-pca-fhe/signed-claim/v1\0".b.freeze
      VERDICT_DOMAIN = "atlas-pca-fhe/verdict-attestation/v1\0".b.freeze
      NONCE_BYTES = 16
      MAX_CONTEXT_LEN = 512

      # ok with the claim and its digest, or not ok with a reason
      ClaimCheck = Struct.new(:ok, :claim, :digest, :reason)
      # ok with the attested admit bit, or not ok with a reason
      AttestationCheck = Struct.new(:ok, :admit, :reason)
      # what the verifier expects: trusted encryptor keys, the grant context, the action binding, the gate policy and the replay guard
      ClaimExpectations = Struct.new(:trusted_signers, :context, :binding, :policy, :nonces)

      # a bounded set of nonces already seen; claim(key) is false when the key was seen or the window is full
      class NonceGuard
        def initialize(max_entries = 100_000)
          @max = max_entries
          @seen = {}
          @lock = Mutex.new
        end

        def claim(key)
          @lock.synchronize do
            return false if @seen.key?(key) || @seen.size >= @max

            @seen[key] = true
          end
        end
      end

      module_function

      def memory_nonce_guard(max_entries = 100_000) = NonceGuard.new(max_entries)

      def bytes_digest(s) = AtlasPca.b64e(AtlasPca.sha(s.b))
      def prefixed(domain, body) = domain + AtlasPca.canon_bytes(body)
      def object?(o) = o.is_a?(Hash) || o.is_a?(Array)

      # the exact bytes the encryptor signs
      def claim_statement(claim, context, nonce, signer)
        prefixed(CLAIM_DOMAIN, { 'v' => 1, 'context' => context, 'nonce' => nonce, 'signer' => signer, 'binding' => claim['binding'],
                                 'policy' => AtlasPca.hash_canonical(claim['policy']), 'enc_inputs' => bytes_digest(claim['encInputs']) })
      end

      # the content digest of a signed claim (what the key holder's attestation commits to)
      def signed_claim_digest(signed) = AtlasPca.hash_canonical(signed)

      def signing_key(secret_key)
        raise ArgumentError, 'signing key must be a 32-byte Ed25519 secret key' unless secret_key.is_a?(String) && secret_key.bytesize == 32

        OpenSSL::PKey.new_raw_private_key('ED25519', secret_key.b)
      end

      # signs an encrypted risk claim; a caller-supplied nonce is for tests and replay of recorded vectors (an all-zero nonce is
      # refused as an RNG failure), else a fresh random one-time nonce is drawn
      def sign_risk_claim(claim, signer_secret_key, context, nonce = nil)
        nonce ||= SecureRandom.random_bytes(NONCE_BYTES)
        unless context.is_a?(String) && !context.empty? && Js.len16(context) <= MAX_CONTEXT_LEN
          raise ArgumentError, "context must be a non-empty string of at most #{MAX_CONTEXT_LEN} characters"
        end
        raise 'signRiskClaim: random source returned all zeros (RNG failure)' if nonce.b.bytes.all?(&:zero?)

        key = signing_key(signer_secret_key)
        signer = AtlasPca.b64e(key.raw_public_key)
        n = AtlasPca.b64e(nonce.b)
        { 'claim' => claim, 'context' => context, 'nonce' => n, 'signer' => signer,
          'sig' => AtlasPca.b64e(key.sign(nil, claim_statement(claim, context, n, signer))) }
      end

      # Evaluator: verify the signed claim, then run the gate. The ciphertext is not loaded into SEAL unless the signature, signer, context,
      # binding, policy and nonce all check out; the claim path has no unsigned entry. `eval_keys`: {'public_key', 'galois_keys'}. Returns
      # {'ok' => true, 'gate' =>, 'claim_digest' =>} or {'ok' => false, 'reason' =>}.
      def eval_signed_risk_claim(eval_keys, signed, exp)
        chk = verify_signed_risk_claim(signed, exp)
        return { 'ok' => false, 'reason' => chk.reason } unless chk.ok

        gate = AtlasPca::FheSeal.eval_risk_gate(eval_keys['public_key'], eval_keys['galois_keys'], chk.claim['encInputs'], chk.claim['policy'])
        { 'ok' => true, 'gate' => gate, 'claim_digest' => chk.digest }
      rescue StandardError => e
        { 'ok' => false, 'reason' => "evaluation failed: #{e.message}" }
      end

      def fail_claim(reason) = ClaimCheck.new(false, nil, nil, reason)

      # verifies a signed claim; never raises (a malformed or hostile input is a not-ok result)
      def verify_signed_risk_claim(s, exp)
        return fail_claim('claim is not signed: malformed envelope') unless s.is_a?(Hash)

        claim = s['claim']
        unless s['context'].is_a?(String) && s['nonce'].is_a?(String) && s['signer'].is_a?(String) && s['sig'].is_a?(String) &&
               claim.is_a?(Hash) && claim['encInputs'].is_a?(String) && object?(claim['binding']) && object?(claim['policy'])
          return fail_claim('claim is not signed: malformed envelope')
        end

        context = s['context']
        nonce = s['nonce']
        signer = s['signer']
        return fail_claim('malformed nonce') if AtlasPca.b64d(nonce, NONCE_BYTES).nil?

        signer_bytes = AtlasPca.b64d(signer, 32)
        sig_bytes = AtlasPca.b64d(s['sig'], 64)
        return fail_claim('malformed signer key or signature') if signer_bytes.nil? || sig_bytes.nil?
        return fail_claim('signer is not a trusted encryptor') unless exp.trusted_signers.include?(signer)

        unless AtlasPca::Ed25519Strict.verify(signer_bytes, claim_statement(claim, context, nonce, signer), sig_bytes)
          return fail_claim('signature does not verify (ciphertext, binding, policy, context or nonce was altered, or wrong signer)')
        end
        return fail_claim('context mismatch: claim was signed for a different grant/policy') unless context == exp.context
        return fail_claim('binding mismatch: claim is bound to a different action') unless AtlasPca.hash_canonical(claim['binding']) == AtlasPca.hash_canonical(exp.binding)
        return fail_claim('policy mismatch: claim was signed for a different gate policy') unless AtlasPca.hash_canonical(claim['policy']) == AtlasPca.hash_canonical(exp.policy)
        return fail_claim('replay: nonce already used (or the replay window is full)') unless exp.nonces.claim("#{signer}:#{nonce}")

        ClaimCheck.new(true, claim, signed_claim_digest(s), nil)
      rescue StandardError
        fail_claim('claim could not be verified (malformed)')
      end

      def verdict_statement(claim_digest, gate_digest, admit, holder)
        prefixed(VERDICT_DOMAIN, { 'v' => 1, 'claim' => claim_digest, 'gate' => gate_digest, 'admit' => admit, 'holder' => holder })
      end

      # the key holder's signed attestation of the verdict it opened, bound to the exact claim and gate output
      def attest_verdict(holder_secret_key, signed, gate, admit)
        gate_digest = { 'encRiskRaw' => bytes_digest(gate['encRiskRaw']), 'encSlack' => bytes_digest(gate['encSlack']) }
        claim_digest = signed_claim_digest(signed)
        key = signing_key(holder_secret_key)
        holder = AtlasPca.b64e(key.raw_public_key)
        { 'claimDigest' => claim_digest, 'gateDigest' => gate_digest, 'admit' => admit, 'holder' => holder,
          'sig' => AtlasPca.b64e(key.sign(nil, verdict_statement(claim_digest, gate_digest, admit, holder))) }
      end

      def fail_attest(reason) = AttestationCheck.new(false, false, reason)

      # verifies an attestation: trusted holder, signature, the expected claim digest and (when given) the expected gate output
      def verify_verdict_attestation(a, trusted_holders, claim_digest, gate = nil)
        return fail_attest('malformed attestation') unless a.is_a?(Hash)

        gd = a['gateDigest']
        unless a['claimDigest'].is_a?(String) && a['holder'].is_a?(String) && a['sig'].is_a?(String) && [true, false].include?(a['admit']) &&
               gd.is_a?(Hash) && gd['encRiskRaw'].is_a?(String) && gd['encSlack'].is_a?(String)
          return fail_attest('malformed attestation')
        end

        holder_s = a['holder']
        return fail_attest('attestation holder is not trusted') unless trusted_holders.include?(holder_s)

        holder = AtlasPca.b64d(holder_s, 32)
        sig = AtlasPca.b64d(a['sig'], 64)
        return fail_attest('malformed holder key or signature') if holder.nil? || sig.nil?
        return fail_attest('attestation signature does not verify') unless AtlasPca::Ed25519Strict.verify(holder, verdict_statement(a['claimDigest'], gd, a['admit'], holder_s), sig)
        return fail_attest('attestation is for a different claim') unless a['claimDigest'] == claim_digest
        if gate && !(gd['encRiskRaw'] == bytes_digest(gate['encRiskRaw']) && gd['encSlack'] == bytes_digest(gate['encSlack']))
          return fail_attest('attestation is for a different gate output')
        end

        AttestationCheck.new(true, a['admit'], nil)
      rescue StandardError
        fail_attest('attestation could not be verified (malformed)')
      end
    end
  end
end
