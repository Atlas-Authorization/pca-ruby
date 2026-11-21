# frozen_string_literal: true

module AtlasPca
  # The public facade of the vendor attestation modules under the reference's function names (camelCase become snake_case): the Intel TDX / DCAP quote and
  # report parsers, the PCK chain and genuine-quote checks, the PCS collateral verification, the Azure runtime-data binding, the Azure MAA and Google
  # Confidential Space JWT parsers, chain checks and JWKS fetchers over an injected transport, and the suite / pin constants. Bytes are binary Strings, objects
  # String-keyed Hashes; a result is shaped as the reference's. Nothing here verifies beyond what the vendor modules do: each method adapts one of them.
  module AttestVendors
    Common = Attest::Common
    Intel = Attest::Intel

    module_function

    # not `constants`: that would shadow Module#constants (which reflection over the module calls with an argument)
    def vendor_constants
      { 'INTEL_DCAP_SUITE' => Intel::SUITE, 'AZURE_MAA_SUITE' => Attest::Azure::SUITE, 'AZURE_MAA_SUITES' => Attest::Azure::SUITES,
        'GCP_CS_SUITE' => Attest::Gcp::SUITE, 'GCP_CS_SUITES' => Attest::Gcp::SUITES, 'GCP_CS_DEFAULT_ISSUER' => Attest::Gcp::DEFAULT_ISSUER,
        'INTEL_SGX_ROOT_CA_SPKI_SHA256' => Intel::SGX_ROOT_CA_SPKI_SHA256, 'AMD_SNP_SUITE' => Attest::Amd::SUITE,
        'AMD_ARK_SPKI_SHA384' => Attest::Amd::ARK_SPKI_SHA384, 'DEFAULT_ACCEPTED_STATUSES' => Intel::DEFAULT_ACCEPTED_STATUSES }
    end

    def to_hex(bytes) = Common.to_hex(bytes)

    # The DER of the FIRST certificate block of a PEM text; raises when there is none.
    def pem_to_der(pem) = Common.pem_to_der(pem)

    # {'point' => the 65-byte uncompressed SEC1 point} (a compressed point is expanded); raises off the curve.
    def ecdsa_p256_public_key(sec1) = Intel.ecdsa_p256_public_key(sec1)

    # The TD report fields past what the vendor parser keeps (the fixed TDX 1.0 report layout).
    def full_report(body, parsed)
      parsed.merge('mrConfigId' => body.byteslice(184, 48), 'rtmr1' => body.byteslice(376, 48), 'rtmr2' => body.byteslice(424, 48),
                   'rtmr3' => body.byteslice(472, 48), 'raw' => body.byteslice(0, 584))
    end

    def parse_dcap_td_report(body) = full_report(body, Intel.parse_dcap_td_report(body))

    def parse_dcap_quote(quote)
      quote = quote.b
      Intel.parse_dcap_quote(quote).merge('version' => quote.byteslice(0, 2).unpack1('v'), 'attKeyType' => quote.byteslice(2, 2).unpack1('v'),
                                          'teeType' => quote.byteslice(4, 4).unpack1('V'))
    end

    def extract_pck_fmspc_and_tcb(leaf_der)
      Intel.extract_pck_fmspc_and_tcb(leaf_der)
    end

    def anchor_of(args) = args['trustAnchorRootCaSpkiSha256'].is_a?(String) ? args['trustAnchorRootCaSpkiSha256'] : nil

    # args: {pckChainPem, trustAnchorRootCaSpkiSha256?, nowMs}
    def verify_intel_pck_chain_x509(args)
      r = Intel.verify_intel_pck_chain(args['pckChainPem'], anchor_of(args), args['nowMs'])
      return r.slice('ok', 'reason', 'failure') unless r['ok']

      { 'ok' => true, 'leafKey' => { 'point' => Common.ec_point(r['leafKey'], 'P-256') }, 'leafDer' => r['leafDer'], 'depth' => r['depth'] }
    end

    # args: {quote, trustAnchorRootCaSpkiSha256?, expected?, policy?, nowMs}
    def verify_genuine_tdx_quote(args)
      quote = args['quote']
      policy = args['policy']
      r = Intel.verify_genuine_tdx_quote(quote, anchor_of(args), args['expected'], policy.is_a?(Hash) ? policy : nil, args['nowMs'])
      return { 'ok' => false, 'reason' => r['reason'] } unless r['ok']

      q = Intel.parse_dcap_quote(quote)
      r.merge('report' => full_report(q['tdReportBody'], r['report']), 'pckTcb' => r['pckTcb'],
              'akPub' => { 'point' => "\x04".b + q['akPubRaw'] })
    end

    # {ok, revoked: sorted lowercase hex serials without leading zeros} or {ok: false, reason}
    def verify_crl(crl_der, spki_der, now_ms)
      r = Intel.verify_crl(crl_der, Common.load_public_key(spki_der), now_ms)
      r['ok'] ? { 'ok' => true, 'revoked' => r['revoked'].keys.sort } : r
    end

    def serial_is_revoked(revoked, serial_hex) = Intel.serial_is_revoked?(revoked.to_h { |s| [s, true] }, serial_hex)

    # {body} or {error}: the named object's exact source bytes signed ECDSA P-256 / SHA-256 (r||s) under the key
    def verify_signed_json(text, name, spki_der) = Intel.verify_signed_json(text, name, Common.load_public_key(spki_der))

    def decode_issuer_chain_header(value) = Intel.decode_issuer_chain_header(value)

    # args: {quote, collateral, nowMs, policy?, trustAnchorRootCaSpkiSha256?, allowDebug?}
    def verify_intel_tdx_collateral(args)
      collateral = args['collateral']
      policy = args['policy']
      detail = {}
      r = Intel.verify_intel_tdx_collateral(args['quote'], collateral.is_a?(Hash) ? collateral : nil, args['nowMs'], policy.is_a?(Hash) ? policy : nil,
                                            anchor_of(args), args['allowDebug'] == true, detail)
      r.merge(detail)
    end

    # The failure reason of an Azure runtime-data binding, or nil.
    def check_azure_runtime_data_binding(report_data, runtime_data, expected = nil)
      Attest::Amd.check_azure_runtime_data_binding(report_data, runtime_data, expected)
    end

    def parse_maa_jwt(token) = Attest::Azure.parse_maa_jwt(token)
    def parse_gcp_cs_jwt(token) = Attest::Gcp.parse_gcp_cs_jwt(token)

    # opts: {nowMs, clockSkewMs?}; the reference returns the leaf certificate, answered here as its DER.
    def verify_x5c_chain(x5c, anchors, opts)
      r = Attest::Azure.verify_x5c_chain(x5c, anchors, opts['nowMs'], opts['clockSkewMs'])
      return { 'ok' => false, 'reason' => r['reason'] } unless r['ok']

      { 'ok' => true, 'leafDer' => r['leaf'].raw, 'leafSpkiSha256' => r['leaf'].spki_sha('sha256') }
    end

    # The failure reason of a JWK x5c chain, or nil. opts: {nowMs, skewMs}
    def verify_jwk_x5c_chain(x5c, anchors, opts)
      Attest::Gcp.verify_jwk_x5c_chain(x5c, anchors, opts['nowMs'], opts['skewMs'].nil? ? 0 : opts['skewMs'])
    end

    def tee_type_of_hw_model(hwmodel) = Attest::Gcp.tee_type_of_hwmodel(hwmodel)

    # The MAA JWKS over `fetch` (->(url) { {'ok', 'status', 'body'} }) and `certs_path`.
    def fetch_maa_jwks(issuer, fetch: nil, certs_path: nil) = Attest::Azure.fetch_maa_jwks(issuer, fetch: fetch, certs_path: certs_path)

    # The Confidential Space JWKS over `fetch` and `jwks_uri` (resolved from the issuer's OpenID configuration when absent).
    def fetch_gcp_confidential_space_jwks(issuer, fetch: nil, jwks_uri: nil)
      Attest::Gcp.fetch_gcp_confidential_space_jwks(issuer, fetch: fetch, jwks_uri: jwks_uri)
    end
  end
end
