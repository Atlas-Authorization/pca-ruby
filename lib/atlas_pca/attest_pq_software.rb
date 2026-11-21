# frozen_string_literal: true

module AtlasPca
  # The post-quantum software / HSM attestation root (the reference's `attest-pq-software`): a statement over the measured workload and the
  # holder / grant / epoch / nonce binding, signed by an HSM-held root under a post-quantum (ML-DSA, SLH-DSA) or hybrid suite, and the
  # verifier that trusts a fixed set of the root's PUBLIC keys. It plugs into the multi-root policy beside the hardware roots; it is a
  # SOFTWARE root (its measurements are software-measured and then signed), so the identity it yields always has weights_measured false.
  # `alg`, `pq_pk` and `attestor_ed25519` are signed into the statement: a suite downgrade or a key swap invalidates it, and a hybrid
  # statement needs both halves to verify. Records are String-keyed Hashes with the reference's wire members.
  module AttestPqSoftware
    # Domain separator of the signed statement body.
    PQ_ATTEST_DOMAIN = "atlas-pca/attest-pq/v1\0"
    PQ_PRIMS_WITH_COMPONENT = %w[ML-DSA-65 ML-DSA-87 SLH-DSA-SHA2-128f SLH-DSA-SHA2-256s].freeze

    module_function

    # [needs PQ public key, hybrid (carries an Ed25519 half), PQ primitive] of a registered suite, nil when unregistered.
    def suite_of(alg)
      return nil unless alg.is_a?(String) && REGISTERED_SUITES.include?(alg) && SIG_SUITES.key?(alg)

      _len, needs_pk, hybrid, prim, = SIG_SUITES[alg]
      [needs_pk, hybrid || alg == 'ed25519', prim]
    end

    def has_pq?(suite) = PQ_PRIMS_WITH_COMPONENT.include?(suite[2])

    def statement_message(body) = PQ_ATTEST_DOMAIN.b + AtlasPca.canon_bytes(body)

    # An attestor built from an HSM-held key (provided, never generated here): `alg` must carry a post-quantum component (a classical
    # suite is refused: this is the PQ root); `pq` is the key pair of the suite's primitive (a PqKeyPair; ML-DSA-65, ML-DSA-87 or SLH-DSA);
    # `ed` the Ed25519 KeyPair (hybrid suites need it). Raises RangeError / TypeError like the reference.
    class Attestor
      attr_reader :pq_public_key, :ed25519_public_key

      def initialize(alg:, pq: nil, ed: nil)
        suite = AttestPqSoftware.suite_of(alg)
        raise RangeError, "createPqSoftwareAttestor: unknown signature alg '#{Attestation.jstr(alg)}'" if suite.nil?
        raise RangeError, "createPqSoftwareAttestor: '#{alg}' is classical; the PQ root requires a post-quantum suite" unless AttestPqSoftware.has_pq?(suite)

        pk = pq.respond_to?(:prim) && pq.prim == suite[2] ? pq.public : nil
        raise TypeError, "createPqSoftwareAttestor: '#{alg}' requires the matching PQ key material" if suite[0] && pk.nil?
        raise TypeError, "createPqSoftwareAttestor: hybrid suite '#{alg}' requires edSecret" if suite[1] && !ed.is_a?(AtlasPca::KeyPair)

        @alg = alg
        @pq = pq
        @ed = ed
        @pq_pk = pk
        @pq_public_key = pk.nil? ? '' : pk
        @ed25519_public_key = ed.is_a?(AtlasPca::KeyPair) ? ed.public : nil
      end

      # Mint a signed statement over `claims` {measurement, weights_digest?, system_prompt_digest?, tool_manifest_digest?, model_id?,
      # operator?, holder_pub, grant_ref, epoch, nonce}. Raises on a binding that cannot be constructed.
      def attest(claims)
        c = claims.is_a?(Hash) ? claims : {}
        binding = Attestation.attestation_binding_b64u({ 'holderPub' => c['holder_pub'], 'grantRef' => c['grant_ref'], 'epoch' => c['epoch'],
                                                          'nonce' => c['nonce'] })
        body = { 'measurement' => c.key?('measurement') ? c['measurement'] : Attestation::UNDEF, 'binding' => binding, 'alg' => @alg }
        body['pq_pk'] = @pq_pk unless @pq_pk.nil?
        body['attestor_ed25519'] = @ed25519_public_key unless @ed25519_public_key.nil?
        %w[weights_digest system_prompt_digest tool_manifest_digest model_id operator].each { |k| body[k] = c[k] if c.key?(k) }
        sig, pq_sig = AtlasPca.sign_with_suite(@alg, @ed, @pq, AttestPqSoftware.statement_message(body))
        out = body.merge('sig' => sig)
        out['pq_sig'] = pq_sig unless pq_sig.nil?
        out
      end
    end

    def create_pq_software_attestor(alg:, pq: nil, ed: nil) = Attestor.new(alg: alg, pq: pq, ed: ed)

    # A hardware-verifier (verify(document, expected, now_ms)) over the PQ software root. Given the signed statement from `resolve_evidence`
    # (a callable taking the document; none configured fails closed): the suite is resolved and the post-quantum requirement
    # (`require_pq`, default true: a classical-only statement is denied), the hybrid requirement and the `allowed_suites` list are enforced
    # before anything else; the statement's attestor keys must be in the trusted sets; the PQ (or hybrid) signature over the canonical
    # statement body must verify, under the trusted PQ key only; `binding` must equal attestation_binding(expected); then the policy
    # (a non-empty `measurements` allowlist is required at construction; `weightsMeasurements` optional; `derive_identity` maps a statement
    # to the measured identity). Fails closed with a specific reason. Raises TypeError at construction on an empty measurement allowlist or
    # no trusted PQ key.
    class Verifier
      def initialize(trusted_pq_public_keys: nil, trusted_ed25519_public_keys: nil, require_pq: nil, require_hybrid: nil, allowed_suites: nil,
                     policy: nil, resolve_evidence: nil, derive_identity: nil)
        pol = policy.is_a?(Hash) ? policy : {}
        meas = pol['measurements']
        unless meas.is_a?(Array) && !meas.empty?
          raise TypeError, 'createPqSoftwareVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)'
        end

        @measurements = meas.dup.freeze # an allowlist emptied after construction must not become accept-all
        @weights = pol['weightsMeasurements'].is_a?(Array) ? pol['weightsMeasurements'].dup.freeze : nil
        @trusted_pq = trusted_pq_public_keys.is_a?(Array) ? trusted_pq_public_keys.dup : []
        raise TypeError, 'createPqSoftwareVerifier: at least one trusted PQ public key is required (fail closed)' if @trusted_pq.empty?

        @trusted_ed = trusted_ed25519_public_keys.is_a?(Array) ? trusted_ed25519_public_keys.dup : []
        @require_pq = require_pq != false
        @require_hybrid = require_hybrid == true
        @allowed = allowed_suites.nil? ? nil : (allowed_suites.is_a?(Array) ? allowed_suites.dup : [])
        @resolve = resolve_evidence
        @derive = derive_identity || AttestPqSoftware.method(:default_identity)
        AtlasPca.set_assurance_label(self, 'software', vendor: 'pq-software')
      end

      def verify(document, expected, _now_ms = nil)
        refuse = ->(reason) { { 'ok' => false, 'reason' => reason } }
        return refuse.call('no PQ-software evidence resolver configured (fail closed)') if @resolve.nil?

        st = @resolve.call(document)
        return refuse.call('no PQ-software attestation statement for this action') unless st.is_a?(Hash) && st['alg'].is_a?(String)

        suite = AttestPqSoftware.suite_of(st['alg'])
        return refuse.call("PQ statement declares an unknown signature alg '#{Attestation.jstr(st['alg'])}'") if suite.nil?

        has_pq = AttestPqSoftware.has_pq?(suite)
        return refuse.call("PQ required: a classical-only suite '#{st['alg']}' is not accepted by the post-quantum root") if @require_pq && !has_pq
        if @require_hybrid && !(suite[1] && has_pq && st['alg'] != 'ed25519')
          return refuse.call("hybrid required: suite '#{st['alg']}' is not a classical+PQ hybrid")
        end
        return refuse.call("suite '#{st['alg']}' is not in the allowed-suites list") if @allowed && !@allowed.include?(st['alg'])

        trusted_pq = st['pq_pk'].is_a?(String) && @trusted_pq.include?(st['pq_pk'])
        if suite[0] && !trusted_pq
          return refuse.call('PQ attestor key is not trusted')
        end
        if suite[1] && !(st['attestor_ed25519'].is_a?(String) && @trusted_ed.include?(st['attestor_ed25519']))
          return refuse.call('hybrid Ed25519 attestor key is not trusted')
        end

        body = st.reject { |k, _| %w[sig pq_sig].include?(k) }
        message = AttestPqSoftware.statement_message(body)
        pq = suite[0] ? AtlasPca.resolve_pq_key('', nil, trusted_pk: st['pq_pk']) : nil
        parts = { 'alg' => st['alg'], 'sig' => st['sig'] }
        parts['pq_sig'] = st['pq_sig'] if st.key?('pq_sig')
        return refuse.call('PQ attestation signature does not verify') unless st['sig'].is_a?(String) && AtlasPca.verify_suite(parts, st['attestor_ed25519'], message, pq)

        return refuse.call('no expected attestation binding supplied') unless Attestation.truthy?(expected)

        begin
          want = Attestation.attestation_binding_b64u(expected)
        rescue StandardError => e
          return refuse.call("binding not constructible: #{e.message}")
        end
        return refuse.call('PQ statement is not bound (binding absent)') unless st['binding'].is_a?(String) && !st['binding'].empty?
        return refuse.call('PQ statement binding mismatch (holder/grant/epoch/nonce)') unless st['binding'] == want
        return refuse.call('measurement not in policy allowlist') unless @measurements.any? { |m| Attestation.same_value_zero?(m, st['measurement']) }
        if @weights && !@weights.empty? && !(st['weights_digest'].is_a?(String) && @weights.include?(st['weights_digest']))
          return refuse.call('measured weights digest not in policy allowlist')
        end

        { 'ok' => true, 'bound' => true, 'measured' => @derive.call(st), 'hostAsserted' => { 'suite' => st['alg'] } }
      rescue StandardError => e
        refuse.call("pq-software verification error (fail closed): #{e.message}")
      end
    end

    def create_pq_software_verifier(**opts) = Verifier.new(**opts)

    # The default identity of a verified statement: weights_measured is ALWAYS false (a software root is not a silicon TEE).
    def default_identity(st)
      id = { 'model_id' => st['model_id'].is_a?(String) ? st['model_id'] : '',
             'weights_digest' => st['weights_digest'].is_a?(String) ? st['weights_digest'] : '', 'weights_measured' => false,
             'runtime_measurement' => st['measurement'], 'operator' => st['operator'].is_a?(String) ? st['operator'] : '' }
      id['system_prompt_digest'] = st['system_prompt_digest'] if st['system_prompt_digest'].is_a?(String)
      id['tool_manifest_digest'] = st['tool_manifest_digest'] if st['tool_manifest_digest'].is_a?(String)
      id
    end
  end
end
