# frozen_string_literal: true

module AtlasPca
  # The post-quantum half of FROST signing (the reference's `frost-pq`): the group-algorithm registry (`ed25519` | `hybrid-ed25519-ml-dsa-65`), the
  # signer-set digest, the hybrid co-sign (a guardian ML-DSA-65 signature over a representative that binds the group key, sha256(message) and the signer
  # set) and its verification; the PQ quorum block functions are `AtlasPca::PqThreshold`'s (re-exported here by name). Bytes are binary Strings.
  module FrostPqApi
    UNDEF = IntentV2::UNDEF
    DEFAULT_FROST_GROUP_ALG = 'ed25519'
    HYBRID_FROST_GROUP_ALG = 'hybrid-ed25519-ml-dsa-65'
    FROST_COSIGN_DOMAIN = "atlas-pca/frost-pq-cosign/v1\0"
    FROST_SIGNER_SET_DOMAIN = "atlas-pca/frost-signer-set/v1\0"

    module_function

    def known?(alg) = alg == DEFAULT_FROST_GROUP_ALG || alg == HYBRID_FROST_GROUP_ALG

    # the group algorithm: absent is the default; an unknown value is nil
    def resolve_frost_group_alg(alg = UNDEF)
      return DEFAULT_FROST_GROUP_ALG if UNDEF.equal?(alg)

      known?(alg) ? alg : nil
    end

    # sha256(domain || canonical JSON of the sorted distinct participant ids). Raises RangeError on an empty set or a non-positive-safe-integer id.
    def frost_signer_set_digest(signer_set)
      raise RangeError, 'frostSignerSetDigest: empty signer set' if !signer_set.is_a?(Array) || signer_set.empty?

      ids = signer_set.map { |x| x.is_a?(Float) && Attestation.safe_int?(x) ? x.to_i : x }.uniq
      ids.each do |id|
        raise RangeError, 'frostSignerSetDigest: participant identifiers must be positive safe integers' unless id.is_a?(Numeric) && Attestation.safe_int?(id) && id.positive?
      end
      Digest::SHA256.digest(FROST_SIGNER_SET_DOMAIN.b + AtlasPca.canon_bytes(ids.sort))
    end

    # The bytes the guardian's ML-DSA-65 co-signature covers.
    def frost_cosign_representative(group_public_key_b64u, message, signer_set, group_alg)
      gpk = group_public_key_b64u.is_a?(String) ? AtlasPca.b64d(group_public_key_b64u, 32) : nil
      raise RangeError, 'frostCosignRepresentative: groupPublicKey must be a 32-byte base64url point' if gpk.nil?

      FROST_COSIGN_DOMAIN.b + Attestation.jstr(group_alg).b + "\0".b + gpk + Digest::SHA256.digest(message.b) + frost_signer_set_digest(signer_set)
    end

    # The group signature (a FROST aggregate over the quorum) and, for the hybrid algorithm, the guardian's ML-DSA-65 co-signature:
    # {sig} or {sig, groupAlg, pq_sig, pq_pk}. `opts`: 'groupAlg'?, 'guardianMlDsa' (a PqKeyPair), 'threshold'?.
    def sign_hybrid_frost_cosign(group_public_key, quorum, message, opts = {})
      alg = opts.is_a?(Hash) && opts.key?('groupAlg') && !opts['groupAlg'].nil? ? opts['groupAlg'] : DEFAULT_FROST_GROUP_ALG
      raise RangeError, "signHybridFrostCosign: unknown groupAlg '#{Attestation.jstr(alg)}'" unless known?(alg)

      threshold = opts.is_a?(Hash) ? opts['threshold'] : nil
      sig = AtlasPca.b64e(Frost.cosign(group_public_key, quorum, message, threshold))
      return { 'sig' => sig } if alg == DEFAULT_FROST_GROUP_ALG

      kp = opts['guardianMlDsa']
      raise TypeError, "signHybridFrostCosign: '#{alg}' requires a guardian ML-DSA-65 key pair" unless kp.respond_to?(:sign) && kp.respond_to?(:public)

      rep = frost_cosign_representative(AtlasPca.b64e(group_public_key), message, quorum.map { |p| p['identifier'] }, alg)
      { 'sig' => sig, 'groupAlg' => alg, 'pq_sig' => AtlasPca.b64e(kp.sign(rep)), 'pq_pk' => kp.public }
    end

    # {ok, groupAlg?, edOk, pqOk, reason?}: the Ed25519 group signature under the group key and, for the hybrid algorithm, the guardian ML-DSA-65
    # co-signature under the REGISTERED guardian key (`opts['guardianPqPublicKey']`; an artifact's own pq_pk never selects the key).
    def verify_hybrid_frost_cosign(artifact, message, group_public_key_b64u, signer_set, opts = {})
      deny = lambda do |reason, alg = nil|
        out = { 'ok' => false, 'edOk' => false, 'pqOk' => false, 'reason' => reason }
        out['groupAlg'] = alg if alg
        out
      end
      return deny.call('malformed artifact') unless artifact.is_a?(Hash) && artifact['sig'].is_a?(String)
      return deny.call('malformed group public key') unless group_public_key_b64u.is_a?(String) && !AtlasPca.b64d(group_public_key_b64u, 32).nil?

      alg = resolve_frost_group_alg(artifact.key?('groupAlg') ? artifact['groupAlg'] : UNDEF)
      return deny.call("unknown groupAlg '#{Attestation.jstr(artifact['groupAlg'])}'") if alg.nil?

      expect = opts.is_a?(Hash) && opts.key?('expectGroupAlg') ? opts['expectGroupAlg'] : UNDEF
      unless UNDEF.equal?(expect)
        return deny.call("unknown expected groupAlg '#{Attestation.jstr(expect)}'") unless known?(expect)
        return deny.call("groupAlg '#{alg}' does not match the required '#{expect}'", alg) if expect != alg
      end
      ed_ok = begin
        AtlasPca.verify_b64u(group_public_key_b64u, message, artifact['sig'])
      rescue StandardError
        false
      end
      if alg == DEFAULT_FROST_GROUP_ALG
        return deny.call('FROST Ed25519 group signature did not verify', alg) unless ed_ok

        return { 'ok' => true, 'groupAlg' => alg, 'edOk' => true, 'pqOk' => false }
      end
      registered = opts.is_a?(Hash) ? opts['guardianPqPublicKey'] : nil
      return deny.call('hybrid groupAlg requires a registered guardian ML-DSA-65 public key', alg) unless registered.is_a?(String) && !AtlasPca.b64d(registered, PqThreshold::ML_DSA_65_PUBLIC_KEY_BYTES).nil?
      return deny.call('artifact pq_pk does not match the registered guardian ML-DSA key', alg) if artifact.key?('pq_pk') && artifact['pq_pk'] != registered
      return deny.call('hybrid groupAlg declared but the guardian ML-DSA co-signature is missing', alg) unless artifact['pq_sig'].is_a?(String)

      pq_ok = begin
        rep = frost_cosign_representative(group_public_key_b64u, message, signer_set, alg)
        AtlasPca.mldsa65_verify_pinned(AtlasPca::PinnedPq.mint(registered, 'trusted'), rep, artifact['pq_sig'])
      rescue StandardError
        false
      end
      return { 'ok' => false, 'groupAlg' => alg, 'edOk' => ed_ok, 'pqOk' => pq_ok, 'reason' => ed_ok ? 'guardian ML-DSA-65 co-signature did not verify' : 'FROST Ed25519 group signature did not verify' } unless ed_ok && pq_ok

      { 'ok' => true, 'groupAlg' => alg, 'edOk' => true, 'pqOk' => true }
    end

    def constants_view
      { 'ALLOW_TOKEN_TYP' => FrostNet::ALLOW_TOKEN_TYP, 'SIGNER_POP_DST' => FrostNet::SIGNER_POP_DST, 'MAX_FROST_SIGNING_SET' => FrostNet::MAX_FROST_SIGNING_SET,
        'DEFAULT_FROST_GROUP_ALG' => DEFAULT_FROST_GROUP_ALG, 'PQ_QUORUM_VERSION' => PqThreshold::PQ_QUORUM_VERSION, 'PQ_QUORUM_ALG' => PqThreshold::PQ_QUORUM_ALG,
        'MAX_PQ_QUORUM_ENTRIES' => PqThreshold::MAX_PQ_QUORUM_ENTRIES }
    end
  end
end
