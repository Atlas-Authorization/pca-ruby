# frozen_string_literal: true

# Microsoft Azure Attestation (MAA) JWT verifier (native counterpart of `createAzureMaaVerifier`).
#
# The token-signing `x5c` chain is verified link by link to a CONFIGURED trust anchor (an SPKI SHA-256 pin or an external root
# certificate), the JWS (ES256 / RS256) under the leaf key, the `iss` / time window, the isolation-type claims (`sevsnpvm` /
# `tdxvm`), the PCA binding and the NON-EMPTY measurement allowlist. Fails closed with the reference's reason strings.
require_relative 'cert'

module AtlasPca
  module Attest
    module Azure
      SUITE = 'azure-maa-jwt'
      SEVSNP_MEASUREMENT_KEYS = ['x-ms-sevsnpvm-launchmeasurement'].freeze
      SEVSNP_REPORTDATA_KEYS = ['x-ms-sevsnpvm-reportdata'].freeze
      SEVSNP_HOSTDATA_KEYS = ['x-ms-sevsnpvm-hostdata'].freeze
      SEVSNP_DEBUG_KEY = 'x-ms-sevsnpvm-is-debuggable'
      SEVSNP_TCB_CLAIMS = [%w[bootloader x-ms-sevsnpvm-bootloader-svn bootloader_svn], %w[snp x-ms-sevsnpvm-snpfw-svn snpfw_svn],
                           %w[microcode x-ms-sevsnpvm-microcode-svn microcode_svn], %w[tee x-ms-sevsnpvm-tee-svn tee_svn]].freeze
      TDX_MRTD_KEYS = %w[tdx_mrtd x-ms-tdx-mrtd].freeze
      TDX_REPORTDATA_KEYS = %w[tdx_report_data x-ms-tdx-report-data x-ms-tdx-reportdata].freeze
      TDX_RTMR0_KEYS = %w[tdx_rtmr0 x-ms-tdx-rtmr0].freeze

      module_function

      def kty(key)
        t = Common.key_type(key)
        { 'ec' => 'EC', 'rsa' => 'RSA' }.fetch(t, t)
      end

      def kty_crv(key) = "#{kty(key)}/#{Common.jwk_curve(key) || 'undefined'}"

      # An `x5c` chain (base64 DER, leaf first) to a configured trust anchor; every certificate valid at `now` (+- skew).
      def verify_x5c_chain(x5c, anchors, now_ms, skew_ms = 0)
        return { 'ok' => false, 'reason' => 'empty x5c certificate chain' } if !x5c.is_a?(Array) || x5c.empty?

        skew = Common.num?(skew_ms) ? [0, skew_ms].max : 0
        certs = []
        x5c.each_with_index do |b64, i|
          return { 'ok' => false, 'reason' => "empty x5c entry at index #{i}" } if !b64.is_a?(String) || b64.empty?

          begin
            cert = Cert.new(Common.node_b64decode(b64))
          rescue StandardError => e
            return { 'ok' => false, 'reason' => "malformed x5c certificate at index #{i}: #{e.message}" }
          end
          unless Der.x509_valid_at?(cert.raw, now_ms, skew)
            return { 'ok' => false, 'reason' => "x5c certificate at index #{i} is outside its validity window" }
          end

          certs << cert
        end

        fingerprints = {}
        root_keys = []
        a = anchors.is_a?(Hash) ? anchors : {}
        (a['rootSpkiSha256'] || []).each { |fp| fingerprints[fp.downcase] = true if fp.is_a?(String) && !fp.empty? }
        (a['rootCertsPem'] || []).each do |pem|
          rc = Cert.from_pem(pem)
          root_keys << rc.public_key
          fingerprints[rc.spki_sha('sha256')] = true
        end
        return { 'ok' => false, 'reason' => 'no MAA trust anchor configured (fail closed)' } if fingerprints.empty? && root_keys.empty?

        anchor_idx = certs.index { |c| fingerprints.key?(c.spki_sha('sha256')) } || -1
        if anchor_idx >= 0
          anchor_idx.times do |i|
            unless certs[i].verify(certs[i + 1].public_key)
              return { 'ok' => false, 'reason' => "x5c link #{i} is not signed by the certificate above it" }
            end
          end
          return { 'ok' => true, 'leaf' => certs[0] }
        end

        (certs.length - 1).times do |i|
          unless certs[i].verify(certs[i + 1].public_key)
            return { 'ok' => false, 'reason' => "x5c link #{i} is not signed by the certificate above it" }
          end
        end
        top = certs[-1]
        return { 'ok' => false, 'reason' => 'x5c chain does not anchor in a configured MAA trust root' } unless root_keys.any? { |k| top.verify(k) }

        { 'ok' => true, 'leaf' => certs[0] }
      rescue StandardError => e
        { 'ok' => false, 'reason' => "x5c chain verification error (fail closed): #{e.message}" }
      end

      def verify_jws_signature(parsed, leaf)
        alg = parsed['header']['alg']
        key = leaf.public_key
        if alg == 'ES256'
          if Common.key_type(key) != 'ec' || Common.jwk_curve(key) != 'P-256'
            return "ES256 token but signing key is #{kty_crv(key)} (not EC P-256)"
          end
          return "ES256 signature is #{parsed['signature'].bytesize} bytes (expected 64: r‖s)" if parsed['signature'].bytesize != 64

          ok = Common.ecdsa_verify_raw(key, parsed['signature'], parsed['signingInput'], 'sha256')
          return ok ? nil : 'JWS ES256 signature does not verify under the MAA signing key'
        end
        if alg == 'RS256'
          return "RS256 token but signing key is #{kty(key)} (not RSA)" if Common.key_type(key) != 'rsa'

          ok = Common.rsa_pkcs1_verify(key, parsed['signature'], parsed['signingInput'], 'sha256')
          return ok ? nil : 'JWS RS256 signature does not verify under the MAA signing key'
        end
        "unsupported JWS alg '#{alg}' (MAA uses ES256 / RS256)"
      end

      def resolve_signing_x5c(header, jwks)
        keys = jwks.is_a?(Hash) ? jwks['keys'] : nil
        if keys.is_a?(Array) && !keys.empty?
          kid = header['kid']
          if !kid.is_a?(String) || kid.empty?
            only = keys.length == 1 ? keys[0] : nil
            return { 'reason' => 'token has no kid and the JWKS publishes multiple keys (ambiguous)' } if only.nil?

            x5c = only.is_a?(Hash) ? only['x5c'] : nil
            return x5c.is_a?(Array) && !x5c.empty? ? { 'x5c' => x5c } : { 'reason' => 'JWKS key carries no x5c chain' }
          end
          match = keys.find { |k| k.is_a?(Hash) && k['kid'] == kid }
          return { 'reason' => "no JWKS key matches the token kid '#{kid}' (untrusted signer)" } if match.nil?

          x5c = match['x5c']
          return { 'reason' => "JWKS key '#{kid}' carries no x5c chain" } if !x5c.is_a?(Array) || x5c.empty?

          return { 'x5c' => x5c }
        end
        hx = header['x5c']
        return { 'x5c' => hx } if hx && !hx.empty?

        { 'reason' => 'no signing x5c available (no JWKS and no header x5c)' }
      end

      def lower(lst) = lst.map(&:downcase)
    end

    # `verify(document, expected, now_ms)` -> {ok, bound?, reason?, measured?, hostAsserted?}.
    class AzureMaaVerifier
      def initialize(opts)
        ti = opts['trustedIssuers']
        if !ti.is_a?(Array) || ti.empty?
          raise AttestConstructError, 'createAzureMaaVerifier: trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs'
        end
        ti.each do |iss|
          raise AttestConstructError, 'createAzureMaaVerifier: every trusted issuer must be a non-empty URL string' if !iss.is_a?(String) || iss.empty?
        end
        anchors = opts['trustAnchors']
        a = anchors.is_a?(Hash) ? anchors : {}
        count = (a['rootCertsPem'].nil? ? 0 : (a['rootCertsPem'] || []).length) + (a['rootSpkiSha256'].nil? ? 0 : (a['rootSpkiSha256'] || []).length)
        if count.zero?
          raise AttestConstructError, 'createAzureMaaVerifier: trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted'
        end

        policy = opts['policy']
        has_sev = policy.is_a?(Hash) && policy['sevSnpMeasurements'].is_a?(Array) && !policy['sevSnpMeasurements'].empty?
        has_tdx = policy.is_a?(Hash) && policy['tdxMrtds'].is_a?(Array) && !policy['tdxMrtds'].empty?
        if !policy.is_a?(Hash) || (!has_sev && !has_tdx)
          raise AttestConstructError, 'createAzureMaaVerifier: policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)'
        end
        if policy.key?('sevSnpMinTcb')
          m = policy['sevSnpMinTcb']
          raise AttestConstructError, 'createAzureMaaVerifier: policy.sevSnpMinTcb must be an object' unless m.is_a?(Hash)

          m.each do |k, v|
            unless Azure::SEVSNP_TCB_CLAIMS.any? { |name, _c, _h| name == k }
              raise AttestConstructError, "createAzureMaaVerifier: policy.sevSnpMinTcb.#{k} is not a known field (bootloader | snp | microcode | tee)"
            end
            unless Common.num?(v) && v == v.floor && v >= 0
              raise AttestConstructError, "createAzureMaaVerifier: policy.sevSnpMinTcb.#{k} must be a non-negative integer"
            end
          end
        end
        @anchors = a
        @policy = policy.dup
        @has_sev = has_sev
        @has_tdx = has_tdx
        @issuers = ti.dup
        skew = opts['clockSkewMs']
        @skew = Common.num?(skew) ? [0, skew].max : 0
        @resolve = opts['resolve_evidence']
      end

      def verify(document, expected, now_ms)
        fail_with = ->(reason) { { 'ok' => false, 'reason' => reason } }
        policy = @policy
        return fail_with.call('no Azure MAA evidence resolver configured (fail closed)') if @resolve.nil?

        evidence = @resolve.call(document)
        if !evidence.is_a?(Hash) || !evidence['token'].is_a?(String) || evidence['token'].empty?
          return fail_with.call('no Azure MAA token for this action')
        end

        begin
          parsed = Common.parse_jws(evidence['token'], 'parseMaaJwt')
        rescue JsTypeError => e
          return fail_with.call("MAA token parse failed: #{e.message}")
        end
        alg = parsed['header']['alg']
        return fail_with.call("unsupported JWS alg '#{alg}' (MAA uses ES256 / RS256)") if alg != 'ES256' && alg != 'RS256'

        signing = Azure.resolve_signing_x5c(parsed['header'], evidence['jwks'])
        return fail_with.call(signing['reason'] || 'no signing x5c available') unless signing.key?('x5c')

        chain = Azure.verify_x5c_chain(signing['x5c'], @anchors, now_ms, @skew)
        return fail_with.call("MAA signing chain invalid: #{chain['reason'] || 'untrusted'}") if !chain['ok'] || !chain.key?('leaf')

        sig_err = Azure.verify_jws_signature(parsed, chain['leaf'])
        return fail_with.call(sig_err) if sig_err

        payload = parsed['payload']
        iss = Common.as_str(payload['iss'])
        return fail_with.call("token iss '#{iss.nil? ? 'undefined' : iss}' is not a configured trusted MAA instance") if iss.nil? || iss.empty? || !@issuers.include?(iss)

        now_sec = (now_ms / 1000.0).floor
        skew_sec = (@skew / 1000.0).ceil
        exp = Common.num?(payload['exp']) ? payload['exp'] : nil
        iat = Common.num?(payload['iat']) ? payload['iat'] : nil
        nbf = Common.num?(payload['nbf']) ? payload['nbf'] : nil
        return fail_with.call('token has no exp (cannot bound validity — fail closed)') if exp.nil?
        return fail_with.call('MAA token expired') if now_sec - skew_sec > exp
        return fail_with.call('MAA token not yet valid (nbf)') if !nbf.nil? && now_sec + skew_sec < nbf
        return fail_with.call('MAA token issued in the future (iat)') if !iat.nil? && now_sec + skew_sec < iat

        isolation = payload['x-ms-isolation-tee']
        tee = isolation.is_a?(Hash) ? isolation : payload
        itype = Common.as_str(tee['x-ms-attestation-type'])
        itype = Common.as_str(payload['x-ms-attestation-type']) if itype.nil?
        if itype != 'sevsnpvm' && itype != 'tdxvm'
          return fail_with.call("unexpected x-ms-attestation-type '#{itype.nil? ? 'undefined' : itype}' (expected sevsnpvm | tdxvm)")
        end
        return fail_with.call('no expected attestation binding supplied') if expected.nil?

        if policy['runtimeUserDataBinding'] == true
          begin
            raw_binding = Common.attestation_binding(expected)
          rescue JsTypeError => e
            return fail_with.call("binding not constructible: #{e.message}")
          end
          runtime = payload['x-ms-runtime']
          unless runtime.is_a?(Hash)
            return fail_with.call('token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)')
          end

          user_data = Common.as_str(runtime['user-data'])
          return fail_with.call('x-ms-runtime carries no user-data to bind the PCA challenge') if user_data.nil? || user_data.empty?

          ud = Common.decode_claim_bytes(user_data)
          if ud.nil? || ud != raw_binding
            return fail_with.call('runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound token)')
          end
        else
          begin
            binding_bytes = Common.transform_binding(Common.attestation_binding(expected), policy['reportDataHash'])
          rescue JsTypeError => e
            return fail_with.call("binding not constructible: #{e.message}")
          end
          rd_claim = Common.first_string(tee, itype == 'sevsnpvm' ? Azure::SEVSNP_REPORTDATA_KEYS : Azure::TDX_REPORTDATA_KEYS)
          return fail_with.call('token carries no report-data claim to bind the PCA challenge') if rd_claim.nil? || rd_claim.empty?

          rd = Common.decode_claim_bytes(rd_claim)
          return fail_with.call('report-data claim is not decodable (hex/base64)') if rd.nil?
          return fail_with.call('report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)') if rd != binding_bytes
        end

        return sev_result(policy, tee, fail_with) if itype == 'sevsnpvm'

        tdx_result(policy, tee, fail_with)
      rescue StandardError => e
        fail_with.call("azure-maa verification error (fail closed): #{e.message}")
      end

      private

      def sev_result(policy, tee, fail_with)
        return fail_with.call('sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)') unless @has_sev

        measurement = Common.first_string(tee, Azure::SEVSNP_MEASUREMENT_KEYS)
        return fail_with.call('sevsnpvm token carries no launch-measurement claim') if measurement.nil? || measurement.empty?

        m_hex = measurement.downcase
        return fail_with.call('SEV-SNP launch measurement not in policy allowlist') unless Azure.lower(policy['sevSnpMeasurements']).include?(m_hex)

        debuggable = tee[Azure::SEVSNP_DEBUG_KEY]
        return fail_with.call('SEV-SNP guest is debuggable (no confidentiality)') if policy['allowDebug'] != true && debuggable == true

        host_data = Common.first_string(tee, Azure::SEVSNP_HOSTDATA_KEYS)
        hd_list = policy['sevSnpHostData']
        if hd_list.is_a?(Array) && !hd_list.empty? && (host_data.nil? || host_data.empty? || !Azure.lower(hd_list).include?(host_data.downcase))
          return fail_with.call('SEV-SNP host-data not in policy allowlist')
        end

        tcb_reported = {}
        floors = policy['sevSnpMinTcb']
        Azure::SEVSNP_TCB_CLAIMS.each do |name, claim, host_key|
          raw = tee[claim]
          is_svn = Common.num?(raw) && raw == raw.floor && raw >= 0
          tcb_reported[host_key] = Common.js_num_str(raw) if is_svn
          floor = floors.is_a?(Hash) ? floors[name] : nil
          next if floor.nil?
          unless is_svn
            return fail_with.call("SEV-SNP #{name} SVN claim '#{claim}' is missing or not a non-negative integer (policy requires a minimum)")
          end
          if raw < floor
            return fail_with.call("SEV-SNP #{name} SVN #{Common.js_num_str(raw)} is below the policy minimum #{Common.js_num_str(floor)}")
          end
        end
        measured = { 'model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => m_hex, 'operator' => '' }
        host = { 'attestation_type' => 'sevsnpvm' }.merge(tcb_reported)
        host['host_data'] = host_data.downcase if host_data && !host_data.empty?
        { 'ok' => true, 'bound' => true, 'measured' => measured, 'hostAsserted' => host }
      end

      def tdx_result(policy, tee, fail_with)
        return fail_with.call('tdxvm token but policy configures no TDX MRTD allowlist (fail closed)') unless @has_tdx

        mrtd = Common.first_string(tee, Azure::TDX_MRTD_KEYS)
        return fail_with.call('tdxvm token carries no MRTD claim') if mrtd.nil? || mrtd.empty?

        mrtd_hex = mrtd.downcase
        return fail_with.call('TDX MRTD not in policy allowlist') unless Azure.lower(policy['tdxMrtds']).include?(mrtd_hex)

        td_debug = tee['tdx_td_attributes_debug']
        dbgstat = Common.as_str(tee['dbgstat'])
        if policy['allowDebug'] != true && (td_debug == true || (!dbgstat.nil? && dbgstat != 'disabled'))
          return fail_with.call('TDX guest is debuggable (no confidentiality)')
        end

        tcb_status = Common.as_str(tee['attester_tcb_status'])
        unless tcb_status.nil?
          ok_statuses = policy['tdxAllowedTcbStatuses']
          ok_statuses = %w[UpToDate SWHardeningNeeded] if ok_statuses.nil?
          return fail_with.call("TDX platform TCB status '#{tcb_status}' is not accepted by policy") unless ok_statuses.include?(tcb_status)
        end
        rtmr0 = Common.first_string(tee, Azure::TDX_RTMR0_KEYS)
        rt_list = policy['tdxRtmrs']
        if rt_list.is_a?(Array) && !rt_list.empty? && (rtmr0.nil? || rtmr0.empty? || !Azure.lower(rt_list).include?(rtmr0.downcase))
          return fail_with.call('TDX RTMR0 not in policy allowlist')
        end

        measured = { 'model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => mrtd_hex, 'operator' => '' }
        host = { 'attestation_type' => 'tdxvm' }
        host['tcb_status'] = tcb_status if tcb_status && !tcb_status.empty?
        host['rtmr0'] = rtmr0.downcase if rtmr0 && !rtmr0.empty?
        { 'ok' => true, 'bound' => true, 'measured' => measured, 'hostAsserted' => host }
      end
    end
  end
end
