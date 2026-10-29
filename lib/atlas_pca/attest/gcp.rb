# frozen_string_literal: true

# Google Cloud Confidential Space attestation-token verifier (native counterpart of `createGcpConfidentialSpaceVerifier`).
#
# The token's signing key must be anchored to a CONFIGURED anchor (a pinned JWKS, an SPKI SHA-256 pin or an `x5c` chain to a
# root); the JWS (RS256 / ES256) is verified under it, then `iss` / time window, `submods.confidential_space`, `swname` /
# `swversion`, `hwmodel`, `dbgstat`, the `eat_nonce` binding and the NON-EMPTY `image_digest` allowlist. Fails closed with the
# reference's reason strings.
require_relative 'cert'

module AtlasPca
  module Attest
    module Gcp
      SUITE = 'gcp-confidential-space-jwt'
      DEFAULT_ISSUER = 'https://confidentialcomputing.googleapis.com'
      SEVSNP_HWMODELS = %w[GCP_AMD_SEV GCP_AMD_SEV_SNP GCP_AMD_SEV_ES].freeze
      TDX_HWMODELS = ['GCP_INTEL_TDX'].freeze
      DBGSTAT_DISABLED = 'disabled-since-boot'
      JWK_CURVES = { 'P-256' => 'prime256v1', 'P-384' => 'secp384r1', 'P-521' => 'secp521r1' }.freeze

      module_function

      def tee_type_of_hwmodel(hwmodel)
        return 'sev-snp' if SEVSNP_HWMODELS.include?(hwmodel)
        return 'tdx' if TDX_HWMODELS.include?(hwmodel)

        up = hwmodel.upcase
        return 'sev-snp' if up.start_with?('GCP_AMD_SEV')
        return 'tdx' if up.start_with?('GCP_INTEL_TDX')

        nil
      end

      def kty_name(key)
        t = Common.key_type(key)
        { 'ec' => 'EC', 'rsa' => 'RSA' }.fetch(t, t)
      end

      def be_int(bytes) = bytes.empty? ? 0 : bytes.unpack1('H*').to_i(16)

      # A public key from a JWK (RSA n/e, EC x/y, or the leaf of an x5c chain); raises on anything unusable, nil when it carries none.
      def jwk_key(jwk)
        if jwk['n'].is_a?(String) && jwk['e'].is_a?(String)
          n = be_int(Common.node_b64decode(jwk['n']))
          e = be_int(Common.node_b64decode(jwk['e']))
          return OpenSSL::PKey::RSA.new(OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(n), OpenSSL::ASN1::Integer(e)]).to_der)
        end
        if jwk['kty'] == 'EC' && jwk['crv'].is_a?(String) && jwk['x'].is_a?(String) && jwk['y'].is_a?(String)
          raise ArgumentError, "unsupported curve #{jwk['crv']}" unless JWK_CURVES.key?(jwk['crv'])

          group = OpenSSL::PKey::EC::Group.new(JWK_CURVES[jwk['crv']])
          size = (group.degree + 7) / 8
          x = be_int(Common.node_b64decode(jwk['x']))
          y = be_int(Common.node_b64decode(jwk['y']))
          raise ArgumentError, 'point is not on the curve' if x >= (1 << (8 * size)) || y >= (1 << (8 * size))

          point = "\x04".b + [x.to_s(16).rjust(size * 2, '0')].pack('H*') + [y.to_s(16).rjust(size * 2, '0')].pack('H*')
          pt = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(point, 2))
          raise ArgumentError, 'point is not on the curve' unless pt.on_curve?

          spki = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId(Common::EC_OID), OpenSSL::ASN1::ObjectId(JWK_CURVES[jwk['crv']])]),
                                          OpenSSL::ASN1::BitString(pt.to_octet_string(:uncompressed))])
          return OpenSSL::PKey.read(spki.to_der)
        end
        x5c = jwk['x5c']
        return Cert.new(Common.node_b64decode(x5c[0])).public_key if x5c.is_a?(Array) && !x5c.empty? && x5c[0].is_a?(String)

        nil
      end

      def key_from_jwk(jwk)
        key = jwk_key(jwk)
        return { 'reason' => 'JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate' } if key.nil?

        { 'key' => key }
      rescue StandardError => e
        { 'reason' => "JWKS key is not a usable public key: #{e.message}" }
      end

      # The SHA-256 of a key's SubjectPublicKeyInfo, as hex.
      def key_spki_sha256(key) = Common.spki_sha(key, 'sha256')

      # A JWK's `x5c` chain to a configured root PEM / SPKI anchor; a failure reason or nil.
      def verify_jwk_x5c_chain(x5c, anchors, now_ms, skew_ms)
        return 'empty x5c certificate chain' if !x5c.is_a?(Array) || x5c.empty?

        certs = []
        x5c.each_with_index do |b64, i|
          return "empty x5c entry at index #{i}" if !b64.is_a?(String) || b64.empty?

          begin
            cert = Cert.new(Common.node_b64decode(b64))
          rescue StandardError => e
            return "malformed x5c certificate at index #{i}: #{e.message}"
          end
          return "x5c certificate at index #{i} is outside its validity window" unless Der.x509_valid_at?(cert.raw, now_ms, skew_ms)

          certs << cert
        end
        (certs.length - 1).times do |i|
          return "x5c link #{i} is not signed by the certificate above it" unless certs[i].verify(certs[i + 1].public_key)
        end
        pins = (anchors['trustedKeySpki'] || []).map(&:downcase)
        certs.each { |c| return nil if pins.include?(c.spki_sha('sha256')) }
        top = certs[-1]
        (anchors['rootCertsPem'] || []).each do |pem|
          root_key = begin
            Cert.from_pem(pem).public_key
          rescue StandardError
            begin
              OpenSSL::PKey.read(pem)
            rescue StandardError
              next
            end
          end
          return nil if top.verify(root_key)
        end
        'x5c chain does not anchor in a configured GCP trust root'
      end

      def keys_of(jwks)
        keys = jwks.is_a?(Hash) ? jwks['keys'] : nil
        return [] unless keys.is_a?(Array)

        keys.map { |k| k.is_a?(Hash) ? k : {} }
      end

      def resolve_trusted_signing_key(header, evidence_jwks, anchors, now_ms, skew_ms)
        trusted_keys = keys_of(anchors['trustedJwks'])
        evidence_keys = keys_of(evidence_jwks)
        kid = header['kid']
        has_kid = kid.is_a?(String) && !kid.empty?
        pick_from = lambda do |keys|
          next keys.find { |k| k['kid'] == kid } if has_kid

          keys.length == 1 ? keys[0] : nil
        end

        jwk = pick_from.call(evidence_keys)
        from_trusted = false
        if jwk.nil?
          jwk = pick_from.call(trusted_keys)
          from_trusted = !jwk.nil?
        end
        hx = header['x5c']
        if jwk.nil? && has_kid && hx && !hx.empty?
          jwk = { 'x5c' => hx, 'kid' => kid }
        elsif jwk.nil? && !has_kid && hx && !hx.empty?
          jwk = { 'x5c' => hx }
        end
        if jwk.nil?
          return { 'reason' => "no JWKS key matches the token kid '#{kid}' (untrusted signer)" } if has_kid

          return { 'reason' => 'no kid on the token and no unambiguous single signing key available' }
        end

        built = key_from_jwk(jwk)
        return built if built.key?('reason')

        key = built['key']
        spki = key_spki_sha256(key)
        return { 'key' => key } if from_trusted

        pins = (anchors['trustedKeySpki'] || []).map(&:downcase)
        return { 'key' => key } if pins.include?(spki)

        trusted_keys.each do |tk|
          tb = key_from_jwk(tk)
          next if tb.key?('reason')
          return { 'key' => key } if key_spki_sha256(tb['key']) == spki
        end
        x5c = jwk['x5c']
        if x5c.is_a?(Array) && !x5c.empty? && (!(anchors['rootCertsPem'] || []).empty? || !pins.empty?)
          chain_err = verify_jwk_x5c_chain(x5c, anchors, now_ms, skew_ms)
          return { 'key' => key } if chain_err.nil?

          return { 'reason' => "signing key not trusted: #{chain_err}" }
        end
        { 'reason' => 'signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)' }
      end

      def verify_jws_signature(parsed, key)
        alg = parsed['header']['alg']
        if alg == 'RS256'
          return "RS256 token but signing key is #{kty_name(key)} (not RSA)" if Common.key_type(key) != 'rsa'

          ok = Common.rsa_pkcs1_verify(key, parsed['signature'], parsed['signingInput'], 'sha256')
          return ok ? nil : 'JWS RS256 signature does not verify under the Confidential Space signing key'
        end
        if alg == 'ES256'
          if Common.key_type(key) != 'ec' || Common.jwk_curve(key) != 'P-256'
            return "ES256 token but signing key is #{kty_name(key)}/#{Common.jwk_curve(key) || 'undefined'} (not EC P-256)"
          end
          return "ES256 signature is #{parsed['signature'].bytesize} bytes (expected 64: r‖s)" if parsed['signature'].bytesize != 64

          ok = Common.ecdsa_verify_raw(key, parsed['signature'], parsed['signingInput'], 'sha256')
          return ok ? nil : 'JWS ES256 signature does not verify under the Confidential Space signing key'
        end
        "unsupported JWS alg '#{alg}' (Confidential Space uses RS256)"
      end

      def nonce_candidates(v)
        return v.empty? ? [] : [v] if v.is_a?(String)

        arr = Common.as_str_list(v)
        arr.nil? ? [] : arr.reject(&:empty?)
      end
    end

    # `verify(document, expected, now_ms)` -> {ok, bound?, reason?, measured?, hostAsserted?}.
    class GcpConfidentialSpaceVerifier
      def initialize(opts)
        ti = opts['trustedIssuers']
        if !ti.is_a?(Array) || ti.empty?
          raise AttestConstructError, 'createGcpConfidentialSpaceVerifier: trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs'
        end
        ti.each do |iss|
          if !iss.is_a?(String) || iss.empty?
            raise AttestConstructError, 'createGcpConfidentialSpaceVerifier: every trusted issuer must be a non-empty URL string'
          end
        end
        anchors = opts['trustAnchors']
        a = anchors.is_a?(Hash) ? anchors : {}
        tj = a['trustedJwks']
        count = (tj.is_a?(Hash) && tj['keys'].is_a?(Array) ? tj['keys'].length : 0) + (a['trustedKeySpki'] || []).length + (a['rootCertsPem'] || []).length
        if count.zero?
          raise AttestConstructError, 'createGcpConfidentialSpaceVerifier: trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted'
        end

        policy = opts['policy']
        if !policy.is_a?(Hash) || !policy['imageDigests'].is_a?(Array) || policy['imageDigests'].empty?
          raise AttestConstructError, 'createGcpConfidentialSpaceVerifier: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)'
        end

        att = policy['allowedTeeTypes']
        if att.is_a?(Array) && att.empty?
          raise AttestConstructError, 'createGcpConfidentialSpaceVerifier: policy.allowedTeeTypes, when present, must be non-empty'
        end

        @anchors = a
        @policy = policy
        @issuers = ti.dup
        skew = opts['clockSkewMs']
        @skew = Common.num?(skew) ? [0, skew].max : 0
        @images = policy['imageDigests'].map(&:downcase)
        @tee_types = att.is_a?(Array) ? att : nil
        sw = policy['expectedSwName']
        @sw_name = sw.is_a?(String) ? sw : 'CONFIDENTIAL_SPACE'
        asv = policy['allowedSwVersions']
        @sw_versions = asv.is_a?(Array) ? asv : nil
        @resolve = opts['resolve_evidence']
      end

      def verify(document, expected, now_ms)
        fail_with = ->(reason) { { 'ok' => false, 'reason' => reason } }
        policy = @policy
        return fail_with.call('no GCP Confidential Space evidence resolver configured (fail closed)') if @resolve.nil?

        evidence = @resolve.call(document)
        if !evidence.is_a?(Hash) || !evidence['token'].is_a?(String) || evidence['token'].empty?
          return fail_with.call('no GCP Confidential Space token for this action')
        end

        begin
          parsed = Common.parse_jws(evidence['token'], 'parseGcpCsJwt')
        rescue JsTypeError => e
          return fail_with.call("Confidential Space token parse failed: #{e.message}")
        end
        alg = parsed['header']['alg']
        return fail_with.call("unsupported JWS alg '#{alg}' (Confidential Space uses RS256)") if alg != 'RS256' && alg != 'ES256'

        resolved = Gcp.resolve_trusted_signing_key(parsed['header'], evidence['jwks'], @anchors, now_ms, @skew)
        return fail_with.call("Confidential Space signing key invalid: #{resolved['reason']}") unless resolved.key?('key')

        sig_err = Gcp.verify_jws_signature(parsed, resolved['key'])
        return fail_with.call(sig_err) if sig_err

        payload = parsed['payload']
        iss = Common.as_str(payload['iss'])
        if iss.nil? || iss.empty? || !@issuers.include?(iss)
          return fail_with.call("token iss '#{iss.nil? ? 'undefined' : iss}' is not a configured trusted Google attestation issuer")
        end

        now_sec = (now_ms / 1000.0).floor
        skew_sec = (@skew / 1000.0).ceil
        exp = Common.num?(payload['exp']) ? payload['exp'] : nil
        iat = Common.num?(payload['iat']) ? payload['iat'] : nil
        nbf = Common.num?(payload['nbf']) ? payload['nbf'] : nil
        return fail_with.call('token has no exp (cannot bound validity — fail closed)') if exp.nil?
        return fail_with.call('Confidential Space token expired') if now_sec - skew_sec > exp
        return fail_with.call('Confidential Space token not yet valid (nbf)') if !nbf.nil? && now_sec + skew_sec < nbf
        return fail_with.call('Confidential Space token issued in the future (iat)') if !iat.nil? && now_sec + skew_sec < iat

        submods = payload['submods'].is_a?(Hash) ? payload['submods'] : nil
        cs = !submods.nil? && submods['confidential_space'].is_a?(Hash) ? submods['confidential_space'] : nil
        return fail_with.call('token carries no submods.confidential_space (not a Confidential Space token)') if cs.nil?

        swname = Common.as_str(payload['swname'])
        return fail_with.call("unexpected swname '#{swname.nil? ? 'undefined' : swname}' (expected '#{@sw_name}')") if swname != @sw_name

        unless @sw_versions.nil?
          v = payload['swversion']
          versions = Common.as_str_list(v)
          versions = (Common.as_str(v) && !v.empty? ? [v] : []) if versions.nil?
          return fail_with.call('swversion not in policy allowlist') unless versions.any? { |x| @sw_versions.include?(x) }
        end

        hwmodel = Common.as_str(payload['hwmodel'])
        return fail_with.call('token carries no hwmodel claim') if hwmodel.nil? || hwmodel.empty?

        tee_type = Gcp.tee_type_of_hwmodel(hwmodel)
        return fail_with.call("unrecognized hwmodel '#{hwmodel}' (not a known AMD SEV-SNP / Intel TDX model)") if tee_type.nil?
        if !@tee_types.nil? && !@tee_types.include?(tee_type)
          return fail_with.call("attestation type '#{tee_type}' (hwmodel '#{hwmodel}') is not in the policy allowlist")
        end

        dbgstat = Common.as_str(payload['dbgstat'])
        if policy['allowDebug'] != true && dbgstat != Gcp::DBGSTAT_DISABLED
          return fail_with.call("token dbgstat '#{dbgstat.nil? ? 'undefined' : dbgstat}' is not '#{Gcp::DBGSTAT_DISABLED}' (debug build — no confidentiality)")
        end
        return fail_with.call('no expected attestation binding supplied') if expected.nil?

        begin
          binding_bytes = Common.transform_binding(Common.attestation_binding(expected), policy['nonceHash'])
        rescue JsTypeError => e
          return fail_with.call("binding not constructible: #{e.message}")
        end
        candidates = Gcp.nonce_candidates(payload['eat_nonce'])
        return fail_with.call('token carries no eat_nonce claim to bind the PCA challenge') if candidates.empty?

        bound = candidates.any? do |cand|
          b = Common.decode_claim_bytes(cand)
          !b.nil? && b == binding_bytes
        end
        return fail_with.call('eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)') unless bound

        container = submods['container'].is_a?(Hash) ? submods['container'] : {}
        image_digest = Common.first_string(container, ['image_digest'])
        return fail_with.call('token carries no submods.container.image_digest to measure the workload') if image_digest.nil? || image_digest.empty?
        return fail_with.call('workload image_digest not in policy allowlist') unless @images.include?(image_digest.downcase)

        measured = { 'model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => image_digest, 'operator' => '' }
        host = { 'attestation_type' => tee_type, 'hwmodel' => hwmodel, 'image_digest' => image_digest }
        image_ref = Common.first_string(container, ['image_reference'])
        host['image_reference'] = image_ref if image_ref && !image_ref.empty?
        { 'ok' => true, 'bound' => true, 'measured' => measured, 'hostAsserted' => host }
      rescue StandardError => e
        fail_with.call("gcp-confidential-space verification error (fail closed): #{e.message}")
      end
    end
  end
end
