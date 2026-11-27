# frozen_string_literal: true

# The public facades of the Intel TDX / DCAP / PCS-collateral, Azure MAA, Google Confidential Space and AMD SNP vendor attestation modules against the TS
# reference: every case of test-data/ref-attest-vendors.json.gz (758 cases, the 22 functions of the generator's porting contract), totals asserted.
# Strings over 400 characters are {"$blob": id} (the corpus header's table, hydrated by Ref.load), bytes are {"$bytes": b64url}. A text that comes from a
# library (an OpenSSL error:... line, a JSON.parse message, the P-256 library's point errors, URI malformed) is compared by presence only. Counted
# deviation (asserted, never skipped): the cases whose certificate bytes are not valid DER at all only require a refusal, whatever stack parses them.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefAttestVendors < Minitest::Test
  V = AtlasPca::AttestVendors
  BY_FN = Ref.load('attest-vendors')
  FNS = { 'constants' => 1, 'toHex' => 8, 'pemToDer' => 10, 'ecdsaP256PublicKey' => 12, 'parseDcapTdReport' => 11, 'parseDcapQuote' => 45,
          'extractPckFmspcAndTcb' => 25, 'verifyIntelPckChainX509' => 46, 'verifyGenuineTdxQuote' => 64, 'verifyCrl' => 34, 'serialIsRevoked' => 10,
          'verifySignedJson' => 31, 'decodeIssuerChainHeader' => 13, 'verifyIntelTdxCollateral' => 159, 'checkAzureRuntimeDataBinding' => 24,
          'parseMaaJwt' => 57, 'parseGcpCsJwt' => 57, 'verifyX5cChain' => 61, 'verifyJwkX5cChain' => 27, 'teeTypeOfHwModel' => 15, 'fetchMaaJwks' => 22,
          'fetchGcpConfidentialSpaceJwks' => 26 }.freeze
  # cases whose certificate bytes are not DER at all: a refusal is all that is required
  REFUSAL_ONLY = %w[verifyIntelPckChainX509/pem-malformed-block verifyX5cChain/malformed-certificate verifyX5cChain/malformed-base64-certificate
                    verifyX5cChain/malformed-second-certificate verifyX5cChain/anchor-malformed-pem verifyJwkX5cChain/malformed-certificate].freeze

  LIB = [/error:[0-9A-Fa-f]{8}:[^;)]*/, /Unexpected token [\s\S]*? is not valid JSON/, /Unexpected end of JSON input/, /Expected [^"]*? in JSON at position \d+/,
         /Unexpected (?:string|number) in JSON at position \d+/, /Unexpected non-whitespace character after JSON at position \d+/].freeze

  def self.mask(s)
    return 'LIB' if s.match?(/\A(bad point|invalid Point|URI malformed)/)

    LIB.reduce(s) { |acc, re| acc.gsub(re, 'LIB') }
  end

  def self.masked(v)
    case v
    when Hash then v.transform_values { |x| masked(x) }
    when Array then v.map { |x| masked(x) }
    when String then mask(v)
    else v
    end
  end

  def self.canon(v) = Ref.canon(masked(Ref.norm(v)))

  def self.response(r)
    raise r['$throws'] if r.key?('$throws')

    b = r['body']
    status = r.fetch('status', 200)
    { 'ok' => status >= 200 && status < 300, 'status' => status, 'body' => b.is_a?(Hash) && b.key?('$text') ? b['$text'] : JSON.generate(b) }
  end

  def self.fetch_case(fn, a)
    log = []
    script = a['script']
    i = -1
    fetch = lambda do |url|
      log << url
      response(script[[i += 1, script.length - 1].min])
    end
    opts = a['opts'] || {}
    jwks = if fn == 'fetchMaaJwks' then V.fetch_maa_jwks(a['issuer'], fetch: fetch, certs_path: opts['certsPath'])
           else V.fetch_gcp_confidential_space_jwks(a['issuer'], fetch: fetch, jwks_uri: opts['jwksUri'])
           end
    { 'ok' => true, 'jwks' => jwks, 'requests' => log }
  rescue StandardError => e
    { 'ok' => false, 'error' => e.message, 'requests' => log }
  end

  CALL = {
    'constants' => -> { V.vendor_constants },
    'toHex' => ->(b) { V.to_hex(b) },
    'pemToDer' => ->(p) { V.pem_to_der(p) },
    'ecdsaP256PublicKey' => ->(b) { V.ecdsa_p256_public_key(b) },
    'parseDcapTdReport' => ->(b) { V.parse_dcap_td_report(b) },
    'parseDcapQuote' => ->(b) { V.parse_dcap_quote(b) },
    'extractPckFmspcAndTcb' => ->(b) { V.extract_pck_fmspc_and_tcb(b) },
    'verifyIntelPckChainX509' => ->(a) { V.verify_intel_pck_chain_x509(a) },
    'verifyGenuineTdxQuote' => ->(a) { V.verify_genuine_tdx_quote(a) },
    'verifyCrl' => ->(crl, key, now) { V.verify_crl(crl, key['spkiDer'], now) },
    'serialIsRevoked' => ->(list, serial) { V.serial_is_revoked(list, serial) },
    'verifySignedJson' => ->(text, name, key) { V.verify_signed_json(text, name, key['spkiDer']) },
    'decodeIssuerChainHeader' => ->(v) { V.decode_issuer_chain_header(v) },
    'verifyIntelTdxCollateral' => ->(a) { V.verify_intel_tdx_collateral(a) },
    'checkAzureRuntimeDataBinding' => ->(rd, run, exp = nil) { V.check_azure_runtime_data_binding(rd, run, exp) },
    'parseMaaJwt' => ->(t) { V.parse_maa_jwt(t) },
    'parseGcpCsJwt' => ->(t) { V.parse_gcp_cs_jwt(t) },
    'verifyX5cChain' => ->(x5c, anchors = nil, opts = nil) { V.verify_x5c_chain(x5c, anchors, opts || {}) },
    'verifyJwkX5cChain' => ->(x5c, anchors = nil, opts = nil) { V.verify_jwk_x5c_chain(x5c, anchors, opts || {}) },
    'teeTypeOfHwModel' => ->(m) { V.tee_type_of_hw_model(m) }
  }.freeze

  def self.call(fn, args)
    return fetch_case(fn, args[0]) if fn.start_with?('fetch')

    CALL.fetch(fn).call(*args)
  end

  # nil when the case agrees, else a description of the mismatch
  def self.check(c)
    fn = c['fn']
    name = c['name']
    args = Ref.dec(c['args'])
    want = Ref.dec(c['out'])
    have = nil
    err = nil
    begin
      have = call(fn, args)
    rescue StandardError => e
      err = e
    end
    if REFUSAL_ONLY.include?(name)
      refused = !err.nil? || (have.is_a?(Hash) ? have['ok'] == false : have.is_a?(String))
      return refused ? nil : "#{name}: a refusal is required, have #{canon(have)[0, 300]}"
    end
    if Ref.throws?(want)
      return "#{name}: want throw #{want['$throws']}, have #{canon(have)[0, 300]}" if err.nil?

      return mask(err.message) == mask(want['$throws']) ? nil : "#{name}: want throw '#{want['$throws']}', have '#{err.message}'"
    end
    return "#{name}: raised #{err.class}: #{err.message}" unless err.nil?

    canon(have) == canon(want) ? nil : "#{name}\n   want #{canon(want)[0, 500]}\n   have #{canon(have)[0, 500]}"
  end

  FNS.each_key do |fn|
    define_method("test_replay_#{fn}") do
      bad = BY_FN.fetch(fn).filter_map { |c| self.class.check(c) }
      assert_empty bad.first(25), "#{bad.length} mismatches in #{fn}"
    end
  end

  def test_every_function_is_replayed_in_full
    assert_equal FNS, BY_FN.transform_values(&:length)
    assert_equal 758, BY_FN.values.sum(&:length)
    assert_equal REFUSAL_ONLY.length, BY_FN.values.flatten.count { |c| REFUSAL_ONLY.include?(c['name']) },
                 'counted deviations: refusal-only cases (certificate bytes that are not DER)'
  end
end
