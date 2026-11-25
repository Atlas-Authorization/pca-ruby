# frozen_string_literal: true

require 'digest'
require_relative 'attest'

module AtlasPca
  # The public surface of the NVIDIA GPU confidential-computing attestation (the reference's `attest-nvidia-spdm`, `attest-nvidia-rim` and
  # `attest-nvidia-ocsp`), over the verifiers of atlas_pca/attest: the SPDM GET_MEASUREMENTS transcript parse, the device chain to a pinned root, the
  # report signature and the PCA challenge; Reference Integrity Manifests (XMLDSig over C14N 1.1, ECDSA P-384 / SHA-384), the RIM ids a report
  # needs, the golden comparison, CRL revocation and the collateral hook; the OCSP request, response and per-chain policy; and the guarded fetch
  # helpers over an INJECTED transport (nothing here touches the network on its own). Records are String-keyed Hashes with the reference's member
  # names; a refusal of a verify function is a result ({'ok' => false, 'reason'}), a malformed input raises.
  #
  # A transport is a callable taking (url, options) and answering {'ok' => bool, 'status' => Integer, 'body' => the bytes}; `options` holds
  # 'method' ('POST' for OCSP), 'headers' and 'body'. Pass `fetch: nil` for the built-in Net::HTTP one, `fetch: false` for none (refused).
  module AttestNvidia
    NVIDIA_SPDM_SUITE = Attest::Nvidia::SUITE
    NVIDIA_OPAQUE = { 'CERT_ISSUER_NAME' => 1, 'CERT_AUTHORITY_KEY_IDENTIFIER' => 2, 'DRIVER_VERSION' => 3, 'GPU_INFO' => 4, 'SKU' => 5,
                      'VBIOS_VERSION' => 6, 'MANUFACTURER_ID' => 7, 'TAMPER_DETECTION' => 8, 'MSRSCNT' => 12, 'BOARD_ID' => 14, 'FWID' => 20,
                      'OPAQUE_DATA_VERSION' => 34, 'CHIP_INFO' => 35, 'FEATURE_FLAG' => 36 }.freeze
    NVIDIA_RIM_BASE_URL = 'https://rim.attestation.nvidia.com/v1/rim/'
    NVIDIA_GH100_CRL_URLS = %w[https://crl.ndis.nvidia.com/crl/l2-gh100.crl https://crl.ndis.nvidia.com/crl/l1-root.crl].freeze
    NVIDIA_GB100_CRL_URLS = %w[https://crl.ndis.nvidia.com/crl/l2-gb100.crl https://crl.ndis.nvidia.com/crl/l1-root.crl].freeze
    NVIDIA_OCSP_URL = 'http://ocsp.ndis.nvidia.com/'
    NVIDIA_OCSP_DEFAULT_MAX_AGE_MS = Attest::Ocsp::DEFAULT_MAX_AGE_MS
    OCSP_HASH_OIDS = { 'sha1' => '1.3.14.3.2.26', 'sha256' => '2.16.840.1.101.3.4.2.1', 'sha384' => '2.16.840.1.101.3.4.2.2',
                       'sha512' => '2.16.840.1.101.3.4.2.3' }.freeze
    OCSP_NONCE_OID = '1.3.6.1.5.5.7.48.1.2'

    module_function

    # ---- SPDM ----

    # The parsed transcript: {'request' => {version, code, param1, param2, nonce, slot}, 'response_version', 'response_code', 'num_blocks',
    # 'measurements' => [{index, valueType, digest}], 'responder_nonce', 'opaque' => {type => bytes}, 'signature', 'signedBytes'}. Raises on any
    # structural problem; nothing is verified.
    def parse_nvidia_spdm_evidence(bytes)
      raise TypeError, 'parseNvidiaSpdmEvidence: expected Uint8Array' unless bytes.is_a?(String)

      r = Attest::Nvidia.parse_nvidia_spdm_evidence(bytes)
      b = bytes.b
      resp = b.byteslice(Attest::Nvidia::REQ_LEN..) # the layout is validated: the extra fields sit at fixed offsets
      rec_end = 8 + Attest::Nvidia.u24_at(resp, 5)
      r.merge('request' => r['request'].merge('code' => b.getbyte(1), 'param1' => b.getbyte(2), 'param2' => b.getbyte(3), 'slot' => b.getbyte(36)),
              'response_code' => resp.getbyte(1), 'num_blocks' => resp.getbyte(4), 'responder_nonce' => resp.byteslice(rec_end, Attest::Nvidia::NONCE_LEN))
    end

    def format_vbios_version(raw) = Attest::Nvidia.format_vbios_version(raw)

    # The lowercase hex of the SHA-256 of a certificate's SubjectPublicKeyInfo (`cert` is a PEM text or an Attest::Cert).
    def spki_sha256_hex(cert) = (cert.is_a?(String) ? Attest::Cert.from_pem(cert) : cert).spki_sha256

    def parse_pem_chain(pem) = Attest::Nvidia.parse_pem_chain(pem)

    # {'ok' => true, 'leaf', 'chain'} or {'ok' => false, 'reason'}: every certificate valid at `now_ms` and an ECDSA P-384 key, every link signed by
    # its issuer (a CA), the strict chain profile, and a self-signed root whose SPKI is one of `root_spki_sha256`.
    def verify_nvidia_device_chain(pem, root_spki_sha256, now_ms) = Attest::Nvidia.verify_nvidia_device_chain(pem, root_spki_sha256, now_ms)

    # The report's ECDSA P-384 / SHA-384 signature (IEEE P1363) over the transcript before it, under the device identity key.
    def verify_nvidia_spdm_signature(report, device_public_key)
      Attest::Common.ecdsa_verify_raw(device_public_key, report['signature'], report['signedBytes'], 'sha384')
    end

    # SHA-256 of the report_data binding: the nonce the verifier puts in the SPDM request so a report cannot be relayed.
    def nvidia_spdm_challenge(expected) = Attest::Common.attestation_challenge_sha256(expected)

    # ---- RIM ----

    # A Reference Integrity Manifest checked and read: {'ok' => true, 'rim' => {tagId, product, version, golden => {index => {...}}, signerSubject}}.
    def verify_nvidia_rim(xml, rim_root_spki_sha256:, now_ms:) = Attest::Nvidia.verify_nvidia_rim(xml, rim_root_spki_sha256, now_ms, true)

    def nvidia_rim_ids_for_report(report) = Attest::Nvidia.nvidia_rim_ids_for_report(report)
    def compare_report_to_rims(report, driver, vbios) = Attest::Nvidia.compare_report_to_rims(report, driver, vbios, true)

    def check_nvidia_chain_revocation(chain, crls, now_ms, require_issuers = [], require_for = 'cdp')
      Attest::Nvidia.check_nvidia_chain_revocation(chain, crls, now_ms, require_issuers, require_for)
    end

    # The post-verification hook: `opts` {'rimRootSpkiSha256', 'resolve' (a callable (ids, evidence) -> the bundle {driverRimXml, vbiosRimXml,
    # crls?, ocsp?} or nil), 'revocation'?, 'requireCrls'?, 'requireCrlIssuers'?, 'requireCrlFor'?, 'firmware'?}; #call(ctx) answers nil when the
    # collateral checks out, else the refusal text.
    def nvidia_collateral_hook(opts) = Attest::NvidiaCollateralHook.new(opts)

    # ---- the guarded fetch helpers ----

    def default_fetch(url, init)
      require 'net/http'
      uri = URI(url)
      req = (init['method'] == 'POST' ? Net::HTTP::Post : Net::HTTP::Get).new(uri)
      (init['headers'] || {}).each { |k, v| req[k] = v }
      req.body = init['body'] if init['body']
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') { |h| h.request(req) }
      { 'ok' => res.is_a?(Net::HTTPSuccess), 'status' => res.code.to_i, 'body' => res.body.to_s.b }
    end

    def transport(fetch, name)
      raise "#{name}: no fetch implementation available" if fetch == false

      fetch || method(:default_fetch)
    end

    # The RIM text of `id`. Raises on an id outside [A-Za-z0-9_.-], a non-2xx answer or a body without a string `rim` member (base64 of the XML).
    def fetch_nvidia_rim(id, fetch: nil, base_url: nil)
      f = transport(fetch, 'fetchNvidiaRim')
      raise TypeError, 'fetchNvidiaRim: invalid RIM id' unless id.is_a?(String) && id.match?(/\A[A-Za-z0-9_.-]+\z/)

      res = f.call("#{base_url.nil? ? NVIDIA_RIM_BASE_URL : base_url}#{id}", {})
      raise "RIM fetch failed: HTTP #{res['status']} for #{id}" unless res['ok']

      body = Attest::Common.js_json_loads(res['body'].to_s.dup.force_encoding(Encoding::UTF_8))
      raise 'RIM fetch: response has no rim field' unless body.is_a?(Hash) && body['rim'].is_a?(String)

      Attest::Common.node_b64decode(body['rim']).force_encoding(Encoding::UTF_8).scrub("�")
    end

    # The bytes of a CRL. Raises on a non-2xx answer.
    def fetch_nvidia_crl(url, fetch: nil)
      f = transport(fetch, 'fetchNvidiaCrl')
      res = f.call(url, {})
      raise "CRL fetch failed: HTTP #{res['status']} for #{url}" unless res['ok']

      res['body'].to_s.b
    end

    # ---- OCSP ----

    def tlv(tag, content)
      n = content.bytesize
      len = if n < 128 then [n].pack('C')
            else
              b = [n].pack('N').sub(/\A\x00+/n, '')
              [0x80 | b.bytesize].pack('C') + b
            end
      [tag].pack('C') + len + content.b
    end

    # A DER OCSPRequest for `cert` (issued by `issuer`): a CertID over SHA-384 unless `hash` (sha1 / sha256 / sha384 / sha512) says otherwise, the
    # hash algorithm identifier with explicit NULL parameters, an optional nonce (1..32 bytes) as the OCSP nonce request extension, no requestor
    # name, no signature.
    def build_nvidia_ocsp_request(cert, issuer, nonce: nil, hash: nil)
      c = cert.is_a?(String) ? Attest::Cert.from_pem(cert) : cert
      i = issuer.is_a?(String) ? Attest::Cert.from_pem(issuer) : issuer
      hname = hash.nil? ? 'sha384' : hash
      raise RangeError, "unsupported CertID hash #{hname}" unless hname.is_a?(String) && OCSP_HASH_OIDS.key?(hname) # md5 and every unnamed hash are refused, never written
      name_hash, key_hash = Attest::Ocsp.cert_id_hashes(i, hname)
      alg = tlv(0x30, OpenSSL::ASN1::ObjectId(OCSP_HASH_OIDS[hname]).to_der + "\x05\x00".b)
      cert_id = tlv(0x30, alg + tlv(0x04, name_hash) + tlv(0x04, key_hash) + tlv(0x02, c.serial))
      tbs = tlv(0x30, tlv(0x30, tlv(0x30, cert_id)))
      unless nonce.nil?
        raise RangeError, 'nonce must be 1..32 bytes' unless (1..32).cover?(nonce.bytesize)

        ext = tlv(0x30, OpenSSL::ASN1::ObjectId(OCSP_NONCE_OID).to_der + tlv(0x04, tlv(0x04, nonce)))
        tbs = tlv(0x30, tlv(0x30, tlv(0x30, cert_id)) + tlv(0xA2, tlv(0x30, ext)))
      end
      tlv(0x30, tbs)
    end

    # One OCSP response checked for `cert` (issued by `issuer`, with `chain` the trusted NVIDIA chain): {'ok' => true, 'status' (good | revoked |
    # unknown), 'thisUpdate', 'nextUpdate'?, 'producedAt', 'revokedAt'?, 'revocationReason'?, 'responder' (issuer | delegated)} or {'ok' => false,
    # 'reason'}. With `expected_nonce` the response MUST echo it. Never raises.
    def verify_nvidia_ocsp_response(response_der, cert:, issuer:, chain:, now_ms:, max_age_ms: nil, expected_nonce: nil, clock_skew_ms: nil)
      Attest::Ocsp.verify_ocsp_response(response_der, cert, issuer, chain, now_ms, max_age_ms, clock_skew_ms.nil? ? 0 : clock_skew_ms, expected_nonce, true)
    end

    def nvidia_cert_ocsp_urls(cert) = Attest::Ocsp.cert_ocsp_urls(cert)

    # The chain against OCSP responses: every response must verify for exactly one chain certificate, a REVOKED one fails, the certificates
    # `require_good` names ('aia' (default): those advertising an OCSP URL, 'all', or chain indices) need a GOOD one. `expected_nonces`: per chain index.
    def check_nvidia_chain_ocsp(chain, responses, now_ms, require_good: nil, max_age_ms: nil, clock_skew_ms: nil, expected_nonces: nil)
      Attest::Ocsp.check_nvidia_chain_ocsp(chain, responses, now_ms, max_age_ms, require_good: require_good, clock_skew_ms: clock_skew_ms,
                                                                                 expected_nonces: expected_nonces)
    end

    # POST an OCSP request for `cert` to `url` (default NVIDIA's responder): {'request', 'response'} bytes. Raises on a non-2xx answer.
    def fetch_nvidia_ocsp(cert, issuer, fetch: nil, url: nil, nonce: nil)
      f = transport(fetch, 'fetchNvidiaOcsp')
      request = build_nvidia_ocsp_request(cert, issuer, nonce: nonce)
      res = f.call(url.nil? ? NVIDIA_OCSP_URL : url, { 'method' => 'POST', 'headers' => { 'content-type' => 'application/ocsp-request' }, 'body' => request })
      raise "OCSP fetch failed: HTTP #{res['status']}" unless res['ok']

      { 'request' => request, 'response' => res['body'].to_s.b }
    end

    # True iff every GeneralizedTime / UTCTime inside the DER value is a well-formed DER time with in-range fields (no calendar roll-over; the
    # contents of OCTET STRING and BIT STRING are opaque); a time the reader itself refuses is false.
    def all_asn1_times_well_formed?(der)
      b = der.b
      Attest::Ocsp.all_times_well_formed?(b, 0, b.bytesize)
    rescue StandardError
      false
    end

    # ---- a certificate as the reference prints it (node's X509Certificate fields) ----

    NODE_MONTHS = %w[Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec].freeze

    def node_time(ms)
      t = Time.at(ms / 1000).utc
      format('%<m>s %<d>2d %<H>02d:%<M>02d:%<S>02d %<Y>d GMT', m: NODE_MONTHS[t.month - 1], d: t.day, H: t.hour, M: t.min, S: t.sec, Y: t.year)
    end

    def cert_summary(cert)
      from, to = Attest::Der.der_validity_ms(cert.raw)
      { 'subject' => cert.subject, 'issuer' => cert.issuer, 'serial' => OpenSSL::BN.new(cert.serial, 2).to_s(16), 'notBefore' => node_time(from),
        'notAfter' => node_time(to), 'spkiSha256' => cert.spki_sha256, 'rawSha256' => Digest::SHA256.hexdigest(cert.raw), 'ca' => cert.ca }
    end
  end
end
