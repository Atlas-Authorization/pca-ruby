# frozen_string_literal: true
# Exact-outcome kill tests for lib/atlas_pca/attest/gcp.rb (GCP Confidential Space verifier, TS attest-gcp-confidential-space.ts)
# and lib/atlas_pca/attest/xml.rb (strict XML subset + C14N for the NVIDIA RIM XMLDSig check). Every library constant is
# resolved at CALL time (the oracle drops and re-evaluates AtlasPca for each mutant). Keys and certificates are generated here.
require 'atlas_pca/attest'
require 'json'
require 'openssl'
require 'timeout'
module MutationKill
  module C10
    module_function

    NOW = 1_800_000_000_000
    SEC = 1_800_000_000
    ISS = 'https://confidentialcomputing.googleapis.com'

    def a = AtlasPca::Attest

    def file?(*names)
      f = ENV['MUT_FILE']
      f.nil? || f.empty? || names.include?(f)
    end

    # run every row ([label, lambda, expected]); raise listing the rows whose result differs
    def check(rows)
      bad = rows.filter_map do |label, act, want|
        got = begin
          act.call
        rescue StandardError => e
          "RAISED #{e.class}: #{e.message}"
        end
        "#{label}: got #{got.inspect[0, 300]} want #{want.inspect[0, 300]}" unless got == want
      end
      bad.empty? || raise(bad.join("\n"))
    end

    # ---- keys / encodings (generated lazily, memoised per process)
    def b64u(s) = [s].pack('m0').tr('+/', '-_').delete('=')
    def b64(s) = [s].pack('m0')
    def ek(n = 0) = ((@ek ||= {})[n] ||= OpenSSL::PKey::EC.generate('prime256v1'))
    def e384 = (@e384 ||= OpenSSL::PKey::EC.generate('secp384r1'))
    def e521 = (@e521 ||= OpenSSL::PKey::EC.generate('secp521r1'))
    def rk = (@rk ||= OpenSSL::PKey::RSA.generate(2048))
    def sp(k) = a::Common.spki_sha(k, 'sha256')

    # a P-256 key whose public point has a first coordinate byte below 0x10 (x) / (y): the hex form is then shorter than 64 chars
    def short_key(coord)
      (@short ||= {})[coord] ||= loop do
        k = OpenSSL::PKey::EC.generate('prime256v1')
        pt = k.public_key.to_octet_string(:uncompressed)
        break k if pt.getbyte(coord == :x ? 1 : 33) < 16
      end
    end

    def jwk_ec(k, size = 32, crv = 'P-256', **extra)
      pt = k.public_key.to_octet_string(:uncompressed)
      { 'kty' => 'EC', 'crv' => crv, 'x' => b64u(pt.byteslice(1, size)), 'y' => b64u(pt.byteslice(1 + size, size)) }.merge(extra)
    end

    def jwk_rsa(k, **extra) = { 'kty' => 'RSA', 'n' => b64u(k.n.to_s(2)), 'e' => b64u(k.e.to_s(2)) }.merge(extra)

    def sign_es(k, data)
      OpenSSL::ASN1.decode(k.sign('SHA256', data)).value.map { |i| i.value.to_s(2).rjust(32, "\x00".b) }.join
    end

    def tok(payload, header = { 'alg' => 'ES256', 'kid' => 'k' }, key: nil, sig: nil)
      si = "#{b64u(JSON.generate(header))}.#{b64u(JSON.generate(payload))}"
      s = sig || (header['alg'] == 'RS256' ? rk.sign('SHA256', si) : sign_es(key || ek, si))
      "#{si}.#{b64u(s)}"
    end

    # ---- certificates (P-256, valid around NOW; the profile of the strict chain: CA / keyCertSign above, CA:FALSE leaf)
    def ext(sn, v) = OpenSSL::X509::ExtensionFactory.new.create_extension(sn, v, true)
    def ca(v = 'CA:TRUE') = ext('basicConstraints', v)
    def ku = ext('keyUsage', 'keyCertSign,cRLSign')
    def ckey(n) = ((@ck ||= {})[n] ||= OpenSSL::PKey::EC.generate('prime256v1'))

    def mkcert(name, key, issuer, signer, exts, nb: 1_700_000_000, na: 1_900_000_000)
      c = OpenSSL::X509::Certificate.new
      c.version = 2
      c.serial = OpenSSL::BN.new(name.sum + 1)
      c.subject = OpenSSL::X509::Name.parse("/CN=#{name}")
      c.issuer = OpenSSL::X509::Name.parse("/CN=#{issuer}")
      c.public_key = key
      c.not_before = Time.at(nb)
      c.not_after = Time.at(na)
      exts.each { |e| c.add_extension(e) }
      c.sign(signer, OpenSSL::Digest.new('SHA256'))
    end

    # [leaf, inter, root]
    def chain(inter_na: 1_900_000_000, leaf_signer: nil, inter_signer: nil)
      [mkcert('leaf', ckey('leaf'), 'inter', leaf_signer || ckey('inter'), [ca('CA:FALSE')]),
       mkcert('inter', ckey('inter'), 'root', inter_signer || ckey('root'), [ca, ku], na: inter_na),
       mkcert('root', ckey('root'), 'root', ckey('root'), [ca, ku])]
    end

    def good = (@good ||= chain)
    def other_root = (@other_root ||= mkcert('root', ckey('other'), 'root', ckey('other'), [ca, ku]))
    def x5c(certs) = certs.map { |c| b64(c.to_der) }
    def cpin(c) = a::Cert.new(c.to_der).spki_sha('sha256')

    # ---- token payloads / verifier
    def binding = { 'holder_pub' => 'h', 'grant_ref' => 'g', 'epoch' => 1, 'nonce' => 'n' }

    def base_payload
      { 'iss' => ISS, 'exp' => SEC + 1000, 'iat' => SEC - 10, 'nbf' => SEC - 10,
        'submods' => { 'confidential_space' => {}, 'container' => { 'image_digest' => 'SHA256:ABCD', 'image_reference' => 'gcr.io/x/y' } },
        'swname' => 'CONFIDENTIAL_SPACE', 'swversion' => ['240101'], 'hwmodel' => 'GCP_AMD_SEV', 'dbgstat' => 'disabled-since-boot',
        'eat_nonce' => [a::Common.to_hex(a::Common.attestation_binding(binding))] }
    end

    def over(base, o)
      o.each { |k, v| v == :del ? base.delete(k) : base[k] = v }
      base
    end

    def pay(o = {}) = over(base_payload, o)

    def ev(o = {}, header: nil, key: nil, sig: nil, jwks: :default)
      { 'token' => tok(pay(o), header || { 'alg' => 'ES256', 'kid' => 'k' }, key: key, sig: sig),
        'jwks' => jwks == :default ? { 'keys' => [jwk_ec(ek, 32, 'P-256', 'kid' => 'k')] } : jwks }
    end

    def opts(o = {})
      over({ 'trustedIssuers' => [ISS], 'trustAnchors' => { 'trustedKeySpki' => [sp(ek)] }, 'policy' => { 'imageDigests' => ['sha256:abcd'] } }, o)
    end

    def mk(o, evidence) = a::GcpConfidentialSpaceVerifier.new(o.merge('resolve_evidence' => ->(_d) { evidence }))
    def run(evidence, o = opts, expected = binding, now = NOW) = mk(o, evidence).verify({}, expected, now)
    def bad(reason) = { 'ok' => false, 'reason' => reason }

    def ok_res(tee: 'sev-snp', hw: 'GCP_AMD_SEV', img: 'SHA256:ABCD', ref: 'gcr.io/x/y')
      host = { 'attestation_type' => tee, 'hwmodel' => hw, 'image_digest' => img }
      host['image_reference'] = ref if ref
      { 'ok' => true, 'bound' => true,
        'measured' => { 'model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => img, 'operator' => '' },
        'hostAsserted' => host }
    end

    def pol(o = {}) = opts('policy' => over({ 'imageDigests' => ['sha256:abcd'] }, o))

    def construct(o)
      a::GcpConfidentialSpaceVerifier.new(o)
      :ok
    rescue StandardError => e
      [e.class, e.message]
    end

    # resolve_trusted_signing_key -> reason, or [:key, spki-hex]
    def res(header, jwks, anchors, now = NOW, skew = 0)
      r = a::Gcp.resolve_trusted_signing_key(header, jwks, anchors, now, skew)
      r.key?('key') ? [:key, sp(r['key'])] : r['reason']
    end

    def kinfo(k) = k.nil? ? nil : [a::Common.key_type(k), sp(k)]
    def mal(b64s)
      a::Cert.new(a::Common.node_b64decode(b64s))
      'NOERR'
    rescue StandardError => e
      e.message
    end

    NOKID = 'no kid on the token and no unambiguous single signing key available'
    NOANCH = 'signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)'
    CHAIN_FAIL = 'x5c chain does not anchor in a configured GCP trust root'
    P = 'createGcpConfidentialSpaceVerifier: '
  end

  # ------------------------------------------------------------------ GCP: constants and small helpers
  t('gcp: constants, frozen tables and hwmodel -> tee type') do
    next true unless C10.file?('gcp.rb')
    g = AtlasPca::Attest::Gcp
    C10.check([
      ['suite', -> { g::SUITE }, 'gcp-confidential-space-jwt'],
      ['issuer', -> { g::DEFAULT_ISSUER }, 'https://confidentialcomputing.googleapis.com'],
      ['dbgstat', -> { g::DBGSTAT_DISABLED }, 'disabled-since-boot'],
      ['sev', -> { g::SEVSNP_HWMODELS }, %w[GCP_AMD_SEV GCP_AMD_SEV_SNP GCP_AMD_SEV_ES]],
      ['tdx', -> { g::TDX_HWMODELS }, ['GCP_INTEL_TDX']],
      ['curves', -> { g::JWK_CURVES }, { 'P-256' => 'prime256v1', 'P-384' => 'secp384r1', 'P-521' => 'secp521r1' }],
      ['frozen', -> { [g::SEVSNP_HWMODELS, g::TDX_HWMODELS, g::JWK_CURVES].map(&:frozen?) }, [true, true, true]],
      *{ 'GCP_AMD_SEV' => 'sev-snp', 'GCP_AMD_SEV_SNP' => 'sev-snp', 'GCP_AMD_SEV_ES' => 'sev-snp', 'GCP_INTEL_TDX' => 'tdx',
         'gcp_amd_sev' => 'sev-snp', 'gcp_amd_sev_snp' => 'sev-snp', 'GCP_AMD_SEV_X' => 'sev-snp', 'gcp_intel_tdx' => 'tdx',
         'GCP_INTEL_TDX_V2' => 'tdx', 'GCP_AMD' => nil, 'GCP_INTEL' => nil, 'AMD' => nil, '' => nil, 'XGCP_AMD_SEV' => nil, 'XGCP_INTEL_TDX' => nil }
        .map { |hw, tee| ["tee #{hw}", -> { g.tee_type_of_hwmodel(hw) }, tee] },
      ['be_int empty', -> { g.be_int(''.b) }, 0],
      ['be_int 256', -> { g.be_int("\x01\x00".b) }, 256],
      ['be_int lead zero', -> { g.be_int("\x00\x05".b) }, 5],
      ['nonce str', -> { g.nonce_candidates('x') }, ['x']],
      ['nonce empty str', -> { g.nonce_candidates('') }, []],
      ['nonce list', -> { g.nonce_candidates(['a', '', 'b']) }, %w[a b]],
      ['nonce list all empty', -> { g.nonce_candidates(['']) }, []],
      ['nonce mixed list', -> { g.nonce_candidates(['a', 1]) }, []],
      ['nonce int', -> { g.nonce_candidates(5) }, []],
      ['nonce nil', -> { g.nonce_candidates(nil) }, []],
      ['keys_of nil', -> { g.keys_of(nil) }, []],
      ['keys_of array', -> { g.keys_of([1]) }, []],
      ['keys_of string', -> { g.keys_of('keys') }, []],
      ['keys_of non-array keys', -> { g.keys_of({ 'keys' => 'abc' }) }, []],
      ['keys_of filter', -> { g.keys_of({ 'keys' => [{ 'a' => 1 }, 5, nil, 'x'] }) }, [{ 'a' => 1 }, {}, {}, {}]]
    ])
  end

  t('gcp: verify_jws_signature picks the check by alg and answers nil on success') do
    next true unless C10.file?('gcp.rb')
    c = C10
    g = AtlasPca::Attest::Gcp
    data = 'data'.b
    es = ->(k, sig = c.sign_es(c.ek, data)) { g.verify_jws_signature({ 'header' => { 'alg' => 'ES256' }, 'signature' => sig, 'signingInput' => data }, k) }
    rs = ->(k, sig = c.rk.sign('SHA256', data)) { g.verify_jws_signature({ 'header' => { 'alg' => 'RS256' }, 'signature' => sig, 'signingInput' => data }, k) }
    c.check([
      ['es ok', -> { es.(c.ek) }, nil],
      ['es wrong key', -> { es.(c.ek(1)) }, 'JWS ES256 signature does not verify under the Confidential Space signing key'],
      ['es 63 bytes', -> { es.(c.ek, 'x' * 63) }, "ES256 signature is 63 bytes (expected 64: r‖s)"],
      ['es 65 bytes', -> { es.(c.ek, 'x' * 65) }, "ES256 signature is 65 bytes (expected 64: r‖s)"],
      ['es rsa key', -> { es.(c.rk) }, 'ES256 token but signing key is RSA/undefined (not EC P-256)'],
      ['es p384 key', -> { es.(c.e384) }, 'ES256 token but signing key is EC/P-384 (not EC P-256)'],
      ['rs ok', -> { rs.(c.rk) }, nil],
      ['rs ec key', -> { rs.(c.ek) }, 'RS256 token but signing key is EC (not RSA)'],
      ['rs bad sig', -> { rs.(c.rk, "\x00".b * 256) }, 'JWS RS256 signature does not verify under the Confidential Space signing key'],
      ['alg HS256', -> { g.verify_jws_signature({ 'header' => { 'alg' => 'HS256' }, 'signature' => 'x', 'signingInput' => data }, c.ek) },
       "unsupported JWS alg 'HS256' (Confidential Space uses RS256)"],
      ['alg none', -> { g.verify_jws_signature({ 'header' => { 'alg' => 'none' }, 'signature' => 'x', 'signingInput' => data }, c.rk) },
       "unsupported JWS alg 'none' (Confidential Space uses RS256)"],
      ['kty names', -> { [g.kty_name(c.ek), g.kty_name(c.rk)] }, %w[EC RSA]]
    ])
  end

  # ------------------------------------------------------------------ GCP: JWK -> key
  t('gcp: jwk_key / key_from_jwk build RSA, EC (every curve, padded coordinates) and x5c keys, and refuse the rest') do
    next true unless C10.file?('gcp.rb')
    c = C10
    g = AtlasPca::Attest::Gcp
    ec = ->(k, size = 32, crv = 'P-256') { c.jwk_ec(k, size, crv) }
    big = "\x01".b + ("\x00".b * 32) # 2^256: one bit too wide for a P-256 coordinate
    ok = c.jwk_ec(c.ek)
    c.check([
      ['rsa', -> { c.kinfo(g.jwk_key(c.jwk_rsa(c.rk))) }, ['rsa', c.sp(c.rk)]],
      ['rsa n only', -> { g.jwk_key({ 'n' => 'AQAB' }) }, nil],
      ['rsa e only', -> { g.jwk_key({ 'e' => 'AQAB' }) }, nil],
      ['rsa n not string', -> { g.jwk_key({ 'n' => 5, 'e' => 'AQAB' }) }, nil],
      ['rsa e not string', -> { g.jwk_key({ 'n' => 'AQAB', 'e' => 5 }) }, nil],
      ['ec p256', -> { c.kinfo(g.jwk_key(ec.(c.ek))) }, ['ec', c.sp(c.ek)]],
      ['ec p384', -> { c.kinfo(g.jwk_key(ec.(c.e384, 48, 'P-384'))) }, ['ec', c.sp(c.e384)]],
      ['ec p521', -> { c.kinfo(g.jwk_key(ec.(c.e521, 66, 'P-521'))) }, ['ec', c.sp(c.e521)]],
      ['ec short x', -> { c.kinfo(g.jwk_key(ec.(c.short_key(:x)))) }, ['ec', c.sp(c.short_key(:x))]],
      ['ec short y', -> { c.kinfo(g.jwk_key(ec.(c.short_key(:y)))) }, ['ec', c.sp(c.short_key(:y))]],
      ['ec no kty', -> { g.jwk_key(ok.reject { |k, _| k == 'kty' }) }, nil],
      ['ec kty RSA', -> { g.jwk_key(ok.merge('kty' => 'RSA')) }, nil],
      ['ec no crv', -> { g.jwk_key(ok.reject { |k, _| k == 'crv' }) }, nil],
      ['ec crv not string', -> { g.jwk_key(ok.merge('crv' => 5)) }, nil],
      ['ec no x', -> { g.jwk_key(ok.reject { |k, _| k == 'x' }) }, nil],
      ['ec x not string', -> { g.jwk_key(ok.merge('x' => 5)) }, nil],
      ['ec no y', -> { g.jwk_key(ok.reject { |k, _| k == 'y' }) }, nil],
      ['ec y not string', -> { g.jwk_key(ok.merge('y' => 5)) }, nil],
      ['x5c leaf', -> { c.kinfo(g.jwk_key({ 'x5c' => c.x5c(c.good) })) }, ['ec', c.sp(c.ckey('leaf'))]],
      ['x5c empty', -> { g.jwk_key({ 'x5c' => [] }) }, nil],
      ['x5c string', -> { g.jwk_key({ 'x5c' => 'x' }) }, nil],
      ['x5c non-string entry', -> { g.jwk_key({ 'x5c' => [5] }) }, nil],
      ['nothing', -> { g.jwk_key({}) }, nil],
      ['kfj neither', -> { g.key_from_jwk({}) }, { 'reason' => 'JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate' }],
      ['kfj key', -> { g.key_from_jwk(ok).keys }, ['key']],
      ['kfj curve', -> { g.key_from_jwk(ok.merge('crv' => 'P-999')) }, { 'reason' => 'JWKS key is not a usable public key: unsupported curve P-999' }],
      ['kfj x too wide', -> { g.key_from_jwk(ok.merge('x' => c.b64u(big))) }, { 'reason' => 'JWKS key is not a usable public key: point is not on the curve' }],
      ['kfj y too wide', -> { g.key_from_jwk(ok.merge('y' => c.b64u(big))) }, { 'reason' => 'JWKS key is not a usable public key: point is not on the curve' }],
      ['kfj off curve', -> { r = g.key_from_jwk(ok.merge('y' => c.b64u(("\x01".b * 32)))); r['reason'].to_s.start_with?('JWKS key is not a usable public key: ') },
       true]
    ])
  end

  t('gcp: a point that decodes but is not on the curve is refused by the explicit on_curve? check (seam over Point.new)') do
    next true unless C10.file?('gcp.rb')
    c = C10
    pt_class = OpenSSL::PKey::EC::Point
    dummy = Object.new
    dummy.define_singleton_method(:on_curve?) { false }
    pt_class.define_singleton_method(:new) { |*| dummy }
    got = begin
      AtlasPca::Attest::Gcp.key_from_jwk(c.jwk_ec(c.ek))
    ensure
      pt_class.singleton_class.send(:remove_method, :new)
    end
    got == { 'reason' => 'JWKS key is not a usable public key: point is not on the curve' }
  end

  # ------------------------------------------------------------------ GCP: x5c chain to an anchor
  t('gcp: verify_jwk_x5c_chain checks entries, validity window (skew), links, pins and root anchors in order') do
    next true unless C10.file?('gcp.rb')
    c = C10
    g = AtlasPca::Attest::Gcp
    good = c.x5c(c.good)
    root_pin = { 'trustedKeySpki' => [c.cpin(c.good[2])] }
    chain = ->(x, anchors = root_pin, now = C10::NOW, skew = 0) { g.verify_jwk_x5c_chain(x, anchors, now, skew) }
    hi = 1_900_000_000_000
    lo = 1_700_000_000_000
    wrong = { 'trustedKeySpki' => ['00' * 32] }
    kp = ->(k) { k.public_to_pem }
    c.check([
      ['ok', -> { chain.(good) }, nil],
      ['upper pin', -> { chain.(good, { 'trustedKeySpki' => [c.cpin(c.good[2]).upcase] }) }, nil],
      ['nil', -> { chain.(nil) }, 'empty x5c certificate chain'],
      ['string', -> { chain.('x') }, 'empty x5c certificate chain'],
      ['empty list', -> { chain.([]) }, 'empty x5c certificate chain'],
      ['entry int', -> { chain.([5]) }, 'empty x5c entry at index 0'],
      ['entry empty', -> { chain.(['']) }, 'empty x5c entry at index 0'],
      ['entry 1 empty', -> { chain.([good[0], '']) }, 'empty x5c entry at index 1'],
      ['entry 1 int', -> { chain.([good[0], 7]) }, 'empty x5c entry at index 1'],
      ['malformed 0', -> { chain.(['AAAA']) }, "malformed x5c certificate at index 0: #{c.mal('AAAA')}"],
      ['malformed 1', -> { chain.([good[0], 'AAAA']) }, "malformed x5c certificate at index 1: #{c.mal('AAAA')}"],
      ['hi edge ok', -> { chain.(good, root_pin, hi + 1000, 1000) }, nil],
      ['hi edge out', -> { chain.(good, root_pin, hi + 1000, 999) }, 'x5c certificate at index 0 is outside its validity window'],
      ['lo edge ok', -> { chain.(good, root_pin, lo - 1000, 1000) }, nil],
      ['lo edge out', -> { chain.(good, root_pin, lo - 1000, 999) }, 'x5c certificate at index 0 is outside its validity window'],
      ['expired inter', -> { chain.(c.x5c(c.chain(inter_na: 1_750_000_000))) }, 'x5c certificate at index 1 is outside its validity window'],
      ['bad link 0', -> { chain.(c.x5c(c.chain(leaf_signer: c.ckey('attacker')))) }, 'x5c link 0 is not signed by the certificate above it'],
      ['bad link 1', -> { chain.(c.x5c(c.chain(inter_signer: c.ckey('attacker')))) }, 'x5c link 1 is not signed by the certificate above it'],
      ['pin leaf', -> { chain.(good, { 'trustedKeySpki' => [c.cpin(c.good[0])] }) }, nil],
      ['pin inter', -> { chain.(good, { 'trustedKeySpki' => [c.cpin(c.good[1])] }) }, nil],
      ['pin wrong', -> { chain.(good, wrong) }, C10::CHAIN_FAIL],
      ['no anchors', -> { chain.(good, {}) }, C10::CHAIN_FAIL],
      ['root pem', -> { chain.(good, { 'rootCertsPem' => [c.good[2].to_pem] }) }, nil],
      ['other root pem', -> { chain.(good, { 'rootCertsPem' => [c.other_root.to_pem] }) }, C10::CHAIN_FAIL],
      ['root key pem', -> { chain.(good, { 'rootCertsPem' => [kp.(c.ckey('root'))] }) }, nil],
      ['junk then root', -> { chain.(good, { 'rootCertsPem' => ['junk', c.good[2].to_pem] }) }, nil],
      ['junk only', -> { chain.(good, { 'rootCertsPem' => ['junk'] }) }, C10::CHAIN_FAIL],
      ['wrong key then root', -> { chain.(good, { 'rootCertsPem' => [kp.(c.ckey('other')), c.good[2].to_pem] }) }, nil],
      ['wrong key only', -> { chain.(good, { 'rootCertsPem' => [kp.(c.ckey('other'))] }) }, C10::CHAIN_FAIL],
      ['pin miss, root ok', -> { chain.(good, wrong.merge('rootCertsPem' => [c.good[2].to_pem])) }, nil]
    ])
  end

  # ------------------------------------------------------------------ GCP: signing-key resolution
  t('gcp: resolve_trusted_signing_key (kid/single-key pick, trusted JWKS, header x5c, anchors)') do
    next true unless C10.file?('gcp.rb')
    c = C10
    ja = c.jwk_ec(c.ek, 32, 'P-256', 'kid' => 'k')
    ja_nokid = c.jwk_ec(c.ek)
    jb = c.jwk_ec(c.ek(1), 32, 'P-256', 'kid' => 'k')
    pin_a = { 'trustedKeySpki' => [c.sp(c.ek)] }
    sa = c.sp(c.ek)
    xs = c.x5c(c.good)
    leaf = c.sp(c.ckey('leaf'))
    root_pin = { 'trustedKeySpki' => [c.cpin(c.good[2])] }
    other_trusted = { 'trustedJwks' => { 'keys' => [c.jwk_ec(c.ek(1), 32, 'P-256', 'kid' => 'z'), c.jwk_ec(c.ek(2), 32, 'P-256', 'kid' => 'y')] } }
    c.check([
      ['kid pinned', -> { c.res({ 'kid' => 'k' }, { 'keys' => [ja] }, pin_a) }, [:key, sa]],
      ['kid pinned upper', -> { c.res({ 'kid' => 'k' }, { 'keys' => [ja] }, { 'trustedKeySpki' => [sa.upcase] }) }, [:key, sa]],
      ['kid mismatch', -> { c.res({ 'kid' => 'zz' }, { 'keys' => [ja] }, pin_a) }, "no JWKS key matches the token kid 'zz' (untrusted signer)"],
      ['kid among several', -> { c.res({ 'kid' => 'k' }, { 'keys' => [jb.merge('kid' => 'q'), ja] }, pin_a) }, [:key, sa]],
      ['no kid single', -> { c.res({}, { 'keys' => [ja_nokid] }, pin_a) }, [:key, sa]],
      ['no kid two', -> { c.res({}, { 'keys' => [ja_nokid, jb] }, pin_a) }, C10::NOKID],
      ['no kid none', -> { c.res({}, { 'keys' => [] }, pin_a) }, C10::NOKID],
      ['no jwks at all', -> { c.res({}, nil, pin_a) }, C10::NOKID],
      ['empty kid single', -> { c.res({ 'kid' => '' }, { 'keys' => [ja_nokid] }, pin_a) }, [:key, sa]],
      ['int kid single', -> { c.res({ 'kid' => 5 }, { 'keys' => [ja_nokid] }, pin_a) }, [:key, sa]],
      ['not anchored', -> { c.res({ 'kid' => 'k' }, { 'keys' => [ja] }, { 'trustedKeySpki' => [c.sp(c.ek(1))] }) }, C10::NOANCH],
      ['trusted equal', -> { c.res({ 'kid' => 'k' }, { 'keys' => [ja] }, { 'trustedJwks' => { 'keys' => [ja_nokid] } }) }, [:key, sa]],
      ['trusted unusable first', -> { c.res({ 'kid' => 'k' }, { 'keys' => [ja] }, { 'trustedJwks' => { 'keys' => [{ 'kid' => 'z' }, ja_nokid] } }) }, [:key, sa]],
      ['trusted other key', -> { c.res({ 'kid' => 'k' }, { 'keys' => [ja] }, { 'trustedJwks' => { 'keys' => [jb] } }) }, C10::NOANCH],
      ['trusted by kid', -> { c.res({ 'kid' => 'k' }, nil, { 'trustedJwks' => { 'keys' => [ja] } }) }, [:key, sa]],
      ['trusted single, no kid', -> { c.res({}, nil, { 'trustedJwks' => { 'keys' => [ja_nokid] } }) }, [:key, sa]],
      ['jwk without material', -> { c.res({ 'kid' => 'k' }, { 'keys' => [{ 'kid' => 'k' }] }, pin_a) },
       'JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate'],
      ['jwk unusable curve', -> { c.res({ 'kid' => 'k' }, { 'keys' => [ja.merge('crv' => 'P-999')] }, pin_a) },
       'JWKS key is not a usable public key: unsupported curve P-999'],
      # the header's x5c chain
      ['hdr x5c + kid', -> { c.res({ 'kid' => 'k', 'x5c' => xs }, nil, root_pin) }, [:key, leaf]],
      ['hdr x5c no kid', -> { c.res({ 'x5c' => xs }, nil, root_pin) }, [:key, leaf]],
      ['hdr x5c roots', -> { c.res({ 'kid' => 'k', 'x5c' => xs }, nil, { 'rootCertsPem' => [c.good[2].to_pem] }) }, [:key, leaf]],
      ['hdr x5c wrong pin', -> { c.res({ 'kid' => 'k', 'x5c' => xs }, nil, { 'trustedKeySpki' => ['00' * 32] }) }, "signing key not trusted: #{C10::CHAIN_FAIL}"],
      ['hdr x5c wrong root', -> { c.res({ 'x5c' => xs }, nil, { 'rootCertsPem' => [c.other_root.to_pem] }) }, "signing key not trusted: #{C10::CHAIN_FAIL}"],
      ['hdr x5c, only trusted jwks', -> { c.res({ 'kid' => 'k', 'x5c' => xs }, nil, other_trusted) }, C10::NOANCH],
      ['hdr x5c no kid, only trusted jwks', -> { c.res({ 'x5c' => xs }, nil, other_trusted) }, C10::NOANCH],
      ['hdr x5c empty + kid', -> { c.res({ 'kid' => 'k', 'x5c' => [] }, nil, root_pin) }, "no JWKS key matches the token kid 'k' (untrusted signer)"],
      ['hdr x5c empty no kid', -> { c.res({ 'x5c' => [] }, nil, root_pin) }, C10::NOKID],
      ['hdr x5c nil + kid', -> { c.res({ 'kid' => 'k' }, nil, root_pin) }, "no JWKS key matches the token kid 'k' (untrusted signer)"],
      ['hdr x5c nil no kid', -> { c.res({}, nil, root_pin) }, C10::NOKID],
      ['evidence key beats hdr x5c (kid)', -> { c.res({ 'kid' => 'k', 'x5c' => xs }, { 'keys' => [ja] }, pin_a) }, [:key, sa]],
      ['evidence key beats hdr x5c (no kid)', -> { c.res({ 'x5c' => xs }, { 'keys' => [ja_nokid] }, pin_a) }, [:key, sa]],
      # a jwk that carries x5c next to usable key material
      ['jwk x5c: key must be the leaf', -> { c.res({ 'kid' => 'k' }, { 'keys' => [ja.merge('x5c' => xs)] }, root_pin) },
       'signing key not trusted: the JWK key is not the key of its x5c leaf'],
      ['jwk x5c junk string, anchors present', -> { c.res({ 'kid' => 'k' }, { 'keys' => [ja.merge('x5c' => 'junk')] }, { 'trustedKeySpki' => [c.sp(c.ek(1))] }) }, C10::NOANCH],
      ['jwk x5c empty list, anchors present', -> { c.res({ 'kid' => 'k' }, { 'keys' => [ja.merge('x5c' => [])] }, { 'trustedKeySpki' => [c.sp(c.ek(1))] }) }, C10::NOANCH],
      ['jwk x5c chain, no pins or roots', -> { c.res({ 'kid' => 'k' }, { 'keys' => [ja.merge('x5c' => xs)] }, other_trusted) }, C10::NOANCH]
    ])
  end

  # ------------------------------------------------------------------ GCP: constructor
  t('gcp: constructor refuses accept-all configurations with the reference messages') do
    next true unless C10.file?('gcp.rb')
    c = C10
    e = AtlasPca::Attest::AttestConstructError
    ti = "#{C10::P}trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs"
    ie = "#{C10::P}every trusted issuer must be a non-empty URL string"
    an = "#{C10::P}trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted"
    pl = "#{C10::P}policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)"
    tt = "#{C10::P}policy.allowedTeeTypes, when present, must be non-empty"
    con = ->(o) { c.construct(o) }
    jw = { 'trustedJwks' => { 'keys' => [{}] } }
    c.check([
      ['base ok', -> { con.(c.opts) }, :ok],
      ['issuers nil', -> { con.(c.opts('trustedIssuers' => nil)) }, [e, ti]],
      ['issuers missing', -> { con.(c.opts('trustedIssuers' => :del)) }, [e, ti]],
      ['issuers empty', -> { con.(c.opts('trustedIssuers' => [])) }, [e, ti]],
      ['issuers string', -> { con.(c.opts('trustedIssuers' => 'x')) }, [e, ti]],
      ['issuer int', -> { con.(c.opts('trustedIssuers' => [5])) }, [e, ie]],
      ['issuer empty', -> { con.(c.opts('trustedIssuers' => [''])) }, [e, ie]],
      ['issuer nil', -> { con.(c.opts('trustedIssuers' => [nil])) }, [e, ie]],
      ['second issuer bad', -> { con.(c.opts('trustedIssuers' => [C10::ISS, ''])) }, [e, ie]],
      ['anchors nil', -> { con.(c.opts('trustAnchors' => nil)) }, [e, an]],
      ['anchors empty', -> { con.(c.opts('trustAnchors' => {})) }, [e, an]],
      ['anchors array', -> { con.(c.opts('trustAnchors' => [1])) }, [e, an]],
      ['anchors string naming a key', -> { con.(c.opts('trustAnchors' => 'trustedKeySpki')) }, [e, an]],
      ['jwks no keys', -> { con.(c.opts('trustAnchors' => { 'trustedJwks' => { 'keys' => [] } })) }, [e, an]],
      ['jwks keys string', -> { con.(c.opts('trustAnchors' => { 'trustedJwks' => { 'keys' => 'abc' } })) }, [e, an]],
      ['jwks array', -> { con.(c.opts('trustAnchors' => { 'trustedJwks' => ['x'] })) }, [e, an]],
      ['anchor spki only', -> { con.(c.opts('trustAnchors' => { 'trustedKeySpki' => ['a'] })) }, :ok],
      ['anchor roots only', -> { con.(c.opts('trustAnchors' => { 'rootCertsPem' => ['b'] })) }, :ok],
      ['anchor jwks only', -> { con.(c.opts('trustAnchors' => jw)) }, :ok],
      ['anchor jwks + spki', -> { con.(c.opts('trustAnchors' => jw.merge('trustedKeySpki' => ['a']))) }, :ok],
      ['anchor spki + roots', -> { con.(c.opts('trustAnchors' => { 'trustedKeySpki' => ['a'], 'rootCertsPem' => ['b'] })) }, :ok],
      ['anchor all three', -> { con.(c.opts('trustAnchors' => jw.merge('trustedKeySpki' => ['a'], 'rootCertsPem' => ['b']))) }, :ok],
      ['policy nil', -> { con.(c.opts('policy' => nil)) }, [e, pl]],
      ['policy missing', -> { con.(c.opts('policy' => :del)) }, [e, pl]],
      ['policy array', -> { con.(c.opts('policy' => [])) }, [e, pl]],
      ['policy string', -> { con.(c.opts('policy' => 'imageDigests')) }, [e, pl]],
      ['policy no digests', -> { con.(c.opts('policy' => {})) }, [e, pl]],
      ['policy digests empty', -> { con.(c.opts('policy' => { 'imageDigests' => [] })) }, [e, pl]],
      ['policy digests string', -> { con.(c.opts('policy' => { 'imageDigests' => 'x' })) }, [e, pl]],
      ['tee empty', -> { con.(c.pol('allowedTeeTypes' => [])) }, [e, tt]],
      ['tee list', -> { con.(c.pol('allowedTeeTypes' => ['tdx'])) }, :ok],
      ['tee int', -> { con.(c.pol('allowedTeeTypes' => 5)) }, :ok],
      ['tee string', -> { con.(c.pol('allowedTeeTypes' => 'tdx')) }, :ok],
      ['skew junk', -> { con.(c.opts('clockSkewMs' => 'x')) }, :ok]
    ])
  end

  # ------------------------------------------------------------------ GCP: verify
  t('gcp: verify answers the reference result and reason for every claim check') do
    next true unless C10.file?('gcp.rb')
    c = C10
    f = ->(r) { c.bad(r) }
    rs = lambda do |pl, o = c.opts, header = { 'alg' => 'ES256', 'kid' => 'k' }|
      c.run(c.ev(pl, header: header), o)
    end
    dash = "—"
    notiss = ->(i) { "token iss '#{i}' is not a configured trusted Google attestation issuer" }
    c.check([
      ['success', -> { rs.({}) }, c.ok_res],
      ['no resolver', -> { c.a::GcpConfidentialSpaceVerifier.new(c.opts).verify({}, c.binding, C10::NOW) },
       f.('no GCP Confidential Space evidence resolver configured (fail closed)')],
      ['resolver raises', -> { c.a::GcpConfidentialSpaceVerifier.new(c.opts.merge('resolve_evidence' => ->(_d) { raise 'boom' })).verify({}, c.binding, C10::NOW) },
       f.('gcp-confidential-space verification error (fail closed): boom')],
      ['evidence nil', -> { c.run(nil) }, f.('no GCP Confidential Space token for this action')],
      ['evidence string', -> { c.run('token') }, f.('no GCP Confidential Space token for this action')],
      ['evidence empty hash', -> { c.run({}) }, f.('no GCP Confidential Space token for this action')],
      ['token int', -> { c.run({ 'token' => 5 }) }, f.('no GCP Confidential Space token for this action')],
      ['token empty', -> { c.run({ 'token' => '' }) }, f.('no GCP Confidential Space token for this action')],
      ['token malformed', -> { c.run({ 'token' => 'a.b' }) },
       f.('Confidential Space token parse failed: parseGcpCsJwt: a compact JWS has exactly three dot-separated parts')],
      ['alg HS256 (key not resolvable)', -> { c.run({ 'token' => c.tok(c.pay, { 'alg' => 'HS256' }, sig: 'x'), 'jwks' => nil }) },
       f.("unsupported JWS alg 'HS256' (Confidential Space uses RS256)")],
      ['alg ES384', -> { c.run({ 'token' => c.tok(c.pay, { 'alg' => 'ES384', 'kid' => 'k' }, sig: 'x'), 'jwks' => nil }) },
       f.("unsupported JWS alg 'ES384' (Confidential Space uses RS256)")],
      ['no key (kid)', -> { c.run(c.ev({}, jwks: nil)) },
       f.("Confidential Space signing key invalid: no JWKS key matches the token kid 'k' (untrusted signer)")],
      ['no key (no kid)', -> { c.run(c.ev({}, header: { 'alg' => 'ES256' }, jwks: nil)) }, f.("Confidential Space signing key invalid: #{C10::NOKID}")],
      ['key unanchored', -> { rs.({}, c.opts('trustAnchors' => { 'trustedKeySpki' => [c.sp(c.ek(1))] })) },
       f.("Confidential Space signing key invalid: #{C10::NOANCH}")],
      ['signature by another key', -> { c.run(c.ev({}, key: c.ek(1))) }, f.('JWS ES256 signature does not verify under the Confidential Space signing key')],
      ['signature 63 bytes', -> { c.run(c.ev({}, sig: 'x' * 63)) }, f.("ES256 signature is 63 bytes (expected 64: r‖s)")],
      ['RS256 with an EC key', -> { c.run(c.ev({}, header: { 'alg' => 'RS256', 'kid' => 'k' })) }, f.('RS256 token but signing key is EC (not RSA)')],
      ['RS256 ok', -> { c.run(c.ev({}, header: { 'alg' => 'RS256', 'kid' => 'k' }, jwks: { 'keys' => [c.jwk_rsa(c.rk, 'kid' => 'k')] }),
                              c.opts('trustAnchors' => { 'trustedKeySpki' => [c.sp(c.rk)] })) }, c.ok_res],
      ['ES256 with an RSA key', -> { c.run(c.ev({}, jwks: { 'keys' => [c.jwk_rsa(c.rk, 'kid' => 'k')] }), c.opts('trustAnchors' => { 'trustedKeySpki' => [c.sp(c.rk)] })) },
       f.('ES256 token but signing key is RSA/undefined (not EC P-256)')],
      ['ES256 with a P-384 key', -> { c.run(c.ev({}, jwks: { 'keys' => [c.jwk_ec(c.e384, 48, 'P-384', 'kid' => 'k')] }), c.opts('trustAnchors' => { 'trustedKeySpki' => [c.sp(c.e384)] })) },
       f.('ES256 token but signing key is EC/P-384 (not EC P-256)')],
      # issuer
      ['iss missing', -> { rs.('iss' => :del) }, f.(notiss.('undefined'))],
      ['iss int', -> { rs.('iss' => 5) }, f.(notiss.('undefined'))],
      ['iss empty', -> { rs.('iss' => '') }, f.(notiss.(''))],
      ['iss other', -> { rs.('iss' => 'https://evil') }, f.(notiss.('https://evil'))],
      ['iss list mutated after construct', lambda {
        ti = [C10::ISS]
        v = c.mk(c.opts('trustedIssuers' => ti), c.ev({ 'iss' => 'https://evil' }))
        ti << 'https://evil'
        v.verify({}, c.binding, C10::NOW)
      }, f.(notiss.('https://evil'))],
      ['issuers hold an empty string (seam)', lambda {
        v = c.mk(c.opts, c.ev({ 'iss' => '' }))
        v.instance_variable_set(:@issuers, [''])
        v.verify({}, c.binding, C10::NOW)
      }, f.(notiss.(''))],
      ['issuers hold nil (seam)', lambda {
        v = c.mk(c.opts, c.ev({ 'iss' => :del }))
        v.instance_variable_set(:@issuers, [nil])
        v.verify({}, c.binding, C10::NOW)
      }, f.(notiss.('undefined'))],
      # time window
      ['exp missing', -> { rs.('exp' => :del) }, f.("token has no exp (cannot bound validity #{dash} fail closed)")],
      ['exp string', -> { rs.('exp' => '9999999999') }, f.("token has no exp (cannot bound validity #{dash} fail closed)")],
      ['exp null', -> { rs.('exp' => nil) }, f.("token has no exp (cannot bound validity #{dash} fail closed)")],
      ['exp == now', -> { rs.('exp' => C10::SEC) }, c.ok_res],
      ['exp float', -> { rs.('exp' => C10::SEC + 10.5) }, c.ok_res],
      ['exp now-1', -> { rs.('exp' => C10::SEC - 1) }, f.('Confidential Space token expired')],
      ['exp floor of now', -> { c.run(c.ev({ 'exp' => C10::SEC }), c.opts, c.binding, C10::NOW + 500) }, c.ok_res],
      ['exp now-1 at +999ms', -> { c.run(c.ev({ 'exp' => C10::SEC - 1 }), c.opts, c.binding, C10::NOW + 999) }, f.('Confidential Space token expired')],
      ['skew 1500 ceil, exp-2', -> { rs.({ 'exp' => C10::SEC - 2 }, c.opts('clockSkewMs' => 1500)) }, c.ok_res],
      ['skew 1500, exp-3', -> { rs.({ 'exp' => C10::SEC - 3 }, c.opts('clockSkewMs' => 1500)) }, f.('Confidential Space token expired')],
      ['no skew, exp-2', -> { rs.('exp' => C10::SEC - 2) }, f.('Confidential Space token expired')],
      ['skew 0, exp-1', -> { rs.({ 'exp' => C10::SEC - 1 }, c.opts('clockSkewMs' => 0)) }, f.('Confidential Space token expired')],
      ['skew junk is zero', -> { rs.({ 'exp' => C10::SEC - 1 }, c.opts('clockSkewMs' => 'x')) }, f.('Confidential Space token expired')],
      ['skew negative is zero', -> { rs.({ 'exp' => C10::SEC + 2 }, c.opts('clockSkewMs' => -5000)) }, c.ok_res],
      ['nbf == now', -> { rs.('nbf' => C10::SEC) }, c.ok_res],
      ['nbf now+1', -> { rs.('nbf' => C10::SEC + 1) }, f.('Confidential Space token not yet valid (nbf)')],
      ['nbf now+1, skew 1000', -> { rs.({ 'nbf' => C10::SEC + 1 }, c.opts('clockSkewMs' => 1000)) }, c.ok_res],
      ['nbf now+2, skew 1000', -> { rs.({ 'nbf' => C10::SEC + 2 }, c.opts('clockSkewMs' => 1000)) }, f.('Confidential Space token not yet valid (nbf)')],
      ['nbf string ignored', -> { rs.('nbf' => 'x') }, c.ok_res],
      ['nbf missing', -> { rs.('nbf' => :del) }, c.ok_res],
      ['iat == now', -> { rs.('iat' => C10::SEC) }, c.ok_res],
      ['iat now+1', -> { rs.('iat' => C10::SEC + 1) }, f.('Confidential Space token issued in the future (iat)')],
      ['iat now+1, skew 1000', -> { rs.({ 'iat' => C10::SEC + 1 }, c.opts('clockSkewMs' => 1000)) }, c.ok_res],
      ['iat now+2, skew 1000', -> { rs.({ 'iat' => C10::SEC + 2 }, c.opts('clockSkewMs' => 1000)) }, f.('Confidential Space token issued in the future (iat)')],
      ['iat string ignored', -> { rs.('iat' => 'x') }, c.ok_res],
      ['iat missing', -> { rs.('iat' => :del) }, c.ok_res],
      # submods
      *[nil, 'x', [], 5].map { |sm| ["submods #{sm.inspect}", -> { rs.('submods' => sm) }, f.('token carries no submods.confidential_space (not a Confidential Space token)')] },
      ['submods missing', -> { rs.('submods' => :del) }, f.('token carries no submods.confidential_space (not a Confidential Space token)')],
      *[nil, 'x', [], 5].map { |cs|
        ["confidential_space #{cs.inspect}", -> { rs.('submods' => { 'confidential_space' => cs, 'container' => { 'image_digest' => 'sha256:abcd' } }) },
         f.('token carries no submods.confidential_space (not a Confidential Space token)')]
      },
      ['confidential_space absent', -> { rs.('submods' => { 'container' => { 'image_digest' => 'sha256:abcd' } }) },
       f.('token carries no submods.confidential_space (not a Confidential Space token)')],
      # swname / swversion
      ['swname missing', -> { rs.('swname' => :del) }, f.("unexpected swname 'undefined' (expected 'CONFIDENTIAL_SPACE')")],
      ['swname int', -> { rs.('swname' => 5) }, f.("unexpected swname 'undefined' (expected 'CONFIDENTIAL_SPACE')")],
      ['swname other', -> { rs.('swname' => 'OTHER') }, f.("unexpected swname 'OTHER' (expected 'CONFIDENTIAL_SPACE')")],
      ['swname custom ok', -> { rs.({ 'swname' => 'X' }, c.pol('expectedSwName' => 'X')) }, c.ok_res],
      ['swname custom refuses default', -> { rs.({}, c.pol('expectedSwName' => 'X')) }, f.("unexpected swname 'CONFIDENTIAL_SPACE' (expected 'X')")],
      ['swname custom int ignored', -> { rs.({}, c.pol('expectedSwName' => 5)) }, c.ok_res],
      ['swversion allowed', -> { rs.({}, c.pol('allowedSwVersions' => ['240101'])) }, c.ok_res],
      ['swversion not allowed', -> { rs.({ 'swversion' => ['9'] }, c.pol('allowedSwVersions' => ['240101'])) }, f.('swversion not in policy allowlist')],
      ['swversion any of list', -> { rs.({ 'swversion' => %w[9 240101] }, c.pol('allowedSwVersions' => ['240101'])) }, c.ok_res],
      ['swversion as string', -> { rs.({ 'swversion' => '240101' }, c.pol('allowedSwVersions' => ['240101'])) }, c.ok_res],
      ['swversion empty string', -> { rs.({ 'swversion' => '' }, c.pol('allowedSwVersions' => [''])) }, f.('swversion not in policy allowlist')],
      ['swversion missing', -> { rs.({ 'swversion' => :del }, c.pol('allowedSwVersions' => ['240101'])) }, f.('swversion not in policy allowlist')],
      ['swversion int', -> { rs.({ 'swversion' => 5 }, c.pol('allowedSwVersions' => [5])) }, f.('swversion not in policy allowlist')],
      ['swversion mixed list', -> { rs.({ 'swversion' => ['240101', 1] }, c.pol('allowedSwVersions' => ['240101'])) }, f.('swversion not in policy allowlist')],
      ['allowedSwVersions not a list = none', -> { rs.({ 'swversion' => ['999'] }, c.pol('allowedSwVersions' => 'x')) }, c.ok_res],
      # hwmodel / tee type
      ['hwmodel missing', -> { rs.('hwmodel' => :del) }, f.('token carries no hwmodel claim')],
      ['hwmodel empty', -> { rs.('hwmodel' => '') }, f.('token carries no hwmodel claim')],
      ['hwmodel int', -> { rs.('hwmodel' => 5) }, f.('token carries no hwmodel claim')],
      ['hwmodel unknown', -> { rs.('hwmodel' => 'FOO') }, f.("unrecognized hwmodel 'FOO' (not a known AMD SEV-SNP / Intel TDX model)")],
      ['hwmodel tdx', -> { rs.('hwmodel' => 'GCP_INTEL_TDX') }, c.ok_res(tee: 'tdx', hw: 'GCP_INTEL_TDX')],
      ['hwmodel lower sev', -> { rs.('hwmodel' => 'gcp_amd_sev_snp') }, c.ok_res(tee: 'sev-snp', hw: 'gcp_amd_sev_snp')],
      ['tee allowed', -> { rs.({}, c.pol('allowedTeeTypes' => ['sev-snp'])) }, c.ok_res],
      ['tee refused', -> { rs.({}, c.pol('allowedTeeTypes' => ['tdx'])) }, f.("attestation type 'sev-snp' (hwmodel 'GCP_AMD_SEV') is not in the policy allowlist")],
      ['tee refused (tdx token)', -> { rs.({ 'hwmodel' => 'GCP_INTEL_TDX' }, c.pol('allowedTeeTypes' => ['sev-snp'])) },
       f.("attestation type 'tdx' (hwmodel 'GCP_INTEL_TDX') is not in the policy allowlist")],
      ['tee list is not a list = no limit', -> { rs.({}, c.pol('allowedTeeTypes' => 'tdx')) }, c.ok_res],
      ['tee int = no limit', -> { rs.({}, c.pol('allowedTeeTypes' => 5)) }, c.ok_res],
      # debug status
      ['dbgstat missing', -> { rs.('dbgstat' => :del) }, f.("token dbgstat 'undefined' is not 'disabled-since-boot' (debug build #{dash} no confidentiality)")],
      ['dbgstat int', -> { rs.('dbgstat' => 5) }, f.("token dbgstat 'undefined' is not 'disabled-since-boot' (debug build #{dash} no confidentiality)")],
      ['dbgstat enabled', -> { rs.('dbgstat' => 'enabled') }, f.("token dbgstat 'enabled' is not 'disabled-since-boot' (debug build #{dash} no confidentiality)")],
      ['allowDebug true', -> { rs.({ 'dbgstat' => 'enabled' }, c.pol('allowDebug' => true)) }, c.ok_res],
      ['allowDebug true, dbgstat missing', -> { rs.({ 'dbgstat' => :del }, c.pol('allowDebug' => true)) }, c.ok_res],
      ['allowDebug "true" is not true', -> { rs.({ 'dbgstat' => 'enabled' }, c.pol('allowDebug' => 'true')) },
       f.("token dbgstat 'enabled' is not 'disabled-since-boot' (debug build #{dash} no confidentiality)")],
      # binding
      ['no expected', -> { c.run(c.ev, c.opts, nil) }, f.('no expected attestation binding supplied')],
      ['expected empty hash', -> { c.run(c.ev, c.opts, {}) }, f.('binding not constructible: binding: holderPub required')],
      ['expected not a hash', -> { c.run(c.ev, c.opts, 'x') }, f.('binding not constructible: binding: holderPub required')],
      ['eat_nonce missing', -> { rs.('eat_nonce' => :del) }, f.('token carries no eat_nonce claim to bind the PCA challenge')],
      ['eat_nonce empty string', -> { rs.('eat_nonce' => '') }, f.('token carries no eat_nonce claim to bind the PCA challenge')],
      ['eat_nonce empty list', -> { rs.('eat_nonce' => []) }, f.('token carries no eat_nonce claim to bind the PCA challenge')],
      ['eat_nonce [""]', -> { rs.('eat_nonce' => ['']) }, f.('token carries no eat_nonce claim to bind the PCA challenge')],
      ['eat_nonce int', -> { rs.('eat_nonce' => 5) }, f.('token carries no eat_nonce claim to bind the PCA challenge')],
      ['eat_nonce wrong', -> { rs.('eat_nonce' => ['00' * 64]) }, f.('eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)')],
      ['eat_nonce undecodable', -> { rs.('eat_nonce' => ['A']) }, f.('eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)')],
      ['eat_nonce as a string', -> { rs.('eat_nonce' => c.a::Common.to_hex(c.a::Common.attestation_binding(c.binding))) }, c.ok_res],
      ['eat_nonce second candidate', -> { rs.('eat_nonce' => ['00' * 64, c.a::Common.to_hex(c.a::Common.attestation_binding(c.binding))]) }, c.ok_res],
      ['eat_nonce base64url', -> { rs.('eat_nonce' => [c.b64u(c.a::Common.attestation_binding(c.binding))]) }, c.ok_res],
      ['nonceHash sha256 binds the digest', -> { rs.({ 'eat_nonce' => [c.a::Common.to_hex(Digest::SHA256.digest(c.a::Common.attestation_binding(c.binding)))] }, c.pol('nonceHash' => 'sha256')) },
       c.ok_res],
      ['nonceHash sha256 refuses the raw binding', -> { rs.({}, c.pol('nonceHash' => 'sha256')) },
       f.('eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)')],
      # workload image
      ['container missing', -> { rs.('submods' => { 'confidential_space' => {} }) }, f.('token carries no submods.container.image_digest to measure the workload')],
      ['container list', -> { rs.('submods' => { 'confidential_space' => {}, 'container' => [] }) },
       f.('token carries no submods.container.image_digest to measure the workload')],
      ['container string', -> { rs.('submods' => { 'confidential_space' => {}, 'container' => 'image_digest' }) },
       f.('token carries no submods.container.image_digest to measure the workload')],
      ['image_digest empty', -> { rs.('submods' => { 'confidential_space' => {}, 'container' => { 'image_digest' => '' } }) },
       f.('token carries no submods.container.image_digest to measure the workload')],
      ['image_digest int', -> { rs.('submods' => { 'confidential_space' => {}, 'container' => { 'image_digest' => 5 } }) },
       f.('token carries no submods.container.image_digest to measure the workload')],
      ['image not allowed', -> { rs.('submods' => { 'confidential_space' => {}, 'container' => { 'image_digest' => 'sha256:ffff' } }) },
       f.('workload image_digest not in policy allowlist')],
      ['image case-insensitive both ways', -> { rs.({ 'submods' => { 'confidential_space' => {}, 'container' => { 'image_digest' => 'sha256:abcd' } } }, c.pol('imageDigests' => ['SHA256:ABCD'])) },
       c.ok_res(img: 'sha256:abcd', ref: nil)],
      ['image_reference absent', -> { rs.('submods' => { 'confidential_space' => {}, 'container' => { 'image_digest' => 'SHA256:ABCD' } }) }, c.ok_res(ref: nil)],
      ['image_reference empty', -> { rs.('submods' => { 'confidential_space' => {}, 'container' => { 'image_digest' => 'SHA256:ABCD', 'image_reference' => '' } }) },
       c.ok_res(ref: nil)],
      ['image_reference int', -> { rs.('submods' => { 'confidential_space' => {}, 'container' => { 'image_digest' => 'SHA256:ABCD', 'image_reference' => 5 } }) },
       c.ok_res(ref: nil)]
    ])
  end

  # ================================================================== XML
  module C10X
    module_function

    def x = AtlasPca::Attest::Xml
    def dl(&blk) = Timeout.timeout(2, &blk)
    def parse(t) = dl { x.parse_xml(t) }

    # the XmlError message, :ok when it parses
    def perr(t)
      parse(t)
      :ok
    rescue AtlasPca::Attest::XmlError => e
      e.message
    end

    def unesc(s, attr) = dl { x.unescape(s, attr) }

    def uerr(s, attr)
      unesc(s, attr)
      :ok
    rescue AtlasPca::Attest::XmlError => e
      e.message
    end

    def canon(t, *args) = dl { x.canonicalize(parse(t).root, *args) }
  end

  t('xml: unescape decodes the five entities and character references, normalises attribute whitespace and keeps the early return') do
    next true unless C10.file?('xml.rb')
    u = C10X
    x = u.x
    plain = +'abc'
    c = C10
    c.check([
      ['lt', -> { u.unesc('a&lt;b', false) }, 'a<b'],
      ['gt', -> { u.unesc('a&gt;b', false) }, 'a>b'],
      ['amp', -> { u.unesc('a&amp;b', false) }, 'a&b'],
      ['quot', -> { u.unesc('a&quot;b', false) }, 'a"b'],
      ['apos', -> { u.unesc('a&apos;b', false) }, "a'b"],
      ['all', -> { u.unesc('x&amp;y&lt;z&gt;w&quot;v&apos;u', false) }, %(x&y<z>w"v'u)],
      ['entities in attr', -> { u.unesc('&amp;&lt;', true) }, '&<'],
      ['decimal', -> { u.unesc('&#65;&#97;', false) }, 'Aa'],
      ['hex lower and upper digits', -> { u.unesc('&#x4a;&#x4A;&#xe9;&#x1F600;', false) }, "JJé\u{1F600}"],
      ['decimal wide', -> { u.unesc('&#233;&#128512;', false) }, "é\u{1F600}"],
      ['tab/lf/cr by reference', -> { u.unesc('&#9;&#10;&#13;', false) }, "\t\n\r"],
      ['plain text is returned as is (same object)', -> { u.unesc(plain, false).equal?(plain) }, true],
      ['plain text in attr is copied', -> { r = u.unesc(plain, true); [r, r.equal?(plain)] }, ['abc', false]],
      ['text keeps whitespace', -> { u.unesc("a\tb\nc\rd", false) }, "a\tb\nc\rd"],
      ['attr normalises whitespace', -> { u.unesc("a\tb\nc\rd", true) }, 'a b c d'],
      ['attr keeps whitespace by reference', -> { u.unesc("&#9;a\tb", true) }, "\ta b"],
      ['text with entity and whitespace', -> { u.unesc("&amp;\t", false) }, "&\t"],
      ['text keeps <', -> { u.unesc('a<b', false) }, 'a<b'],
      ['attr refuses <', -> { u.uerr('a<b', true) }, "'<' in an attribute value"],
      ['attr refuses < next to an entity', -> { u.uerr('&amp;<', true) }, "'<' in an attribute value"],
      ['consecutive entities', -> { u.unesc('&amp;&lt;&gt;', false) }, '&<>'],
      ['entity then text', -> { u.unesc('&amp;ab', false) }, '&ab'],
      ['unterminated', -> { u.uerr('&amp', false) }, 'unterminated entity reference'],
      ['unterminated after text', -> { u.uerr('ab&c', false) }, 'unterminated entity reference'],
      ['semicolon before the ampersand', -> { u.uerr('a;&b', false) }, 'unterminated entity reference'],
      ['empty name', -> { u.uerr('&;', false) }, 'unknown entity &;'],
      ['unknown entity', -> { u.uerr('&foo;', false) }, 'unknown entity &foo;'],
      ['entity names are case-sensitive', -> { u.uerr('&AMP;', false) }, 'unknown entity &AMP;'],
      ['name that only ends like one', -> { u.uerr('&xamp;', false) }, 'unknown entity &xamp;'],
      *['&#+65;', '&#-65;', '&#x+41;', '&#x-41;', '&# 65;', '&#x 41;', '&#;', '&#x;', '&#X41;', '&#99999999999;', '&#x110000;', '&#0;', '&#x0;',
        '&#55296;', '&#xD800;', '&#xDFFF;', '&#65534;', '&#65535;', '&#8;', '&#xB;', '&#xC;', '&#xE;', '&#x1F;', '&#6a;', '&#xg;', '&#x4g;'].map { |r|
        ["refuse #{r}", -> { u.uerr(r, false) }, 'bad character reference']
      },
      *[['&#x9;', "\t"], ['&#xA;', "\n"], ['&#xD;', "\r"], ['&#x20;', ' '], ['&#xD7FF;', "퟿"], ['&#xE000;', ""], ['&#xFFFD;', "�"],
        ['&#x10000;', "\u{10000}"], ['&#x10FFFF;', "\u{10FFFF}"], ['&#000065;', 'A'], ['&#x000041;', 'A']].map { |r, want|
        ["accept #{r}", -> { u.unesc(r, false) }, want]
      }
    ])
  end

  t('xml: helpers (strip_ws, skip_ws, sw?) and constants') do
    next true unless C10.file?('xml.rb')
    u = C10X
    x = u.x
    C10.check([
      ['xml ns', -> { x::XML_NS }, 'http://www.w3.org/XML/1998/namespace'],
      ['entities', -> { x::ENTITIES }, { 'lt' => '<', 'gt' => '>', 'amp' => '&', 'quot' => '"', 'apos' => "'" }],
      ['entities frozen', -> { x::ENTITIES.frozen? }, true],
      ['ws', -> { x::WS }, " \t\r\n"],
      ['strip both ends', -> { x.strip_ws(" \t\r\n a b \n\t ") }, 'a b'],
      ['strip leading only', -> { x.strip_ws('  a') }, 'a'],
      ['strip trailing only', -> { x.strip_ws('a  ') }, 'a'],
      ['strip nothing', -> { x.strip_ws('a') }, 'a'],
      ['strip all', -> { x.strip_ws(" \n ") }, ''],
      ['strip keeps other whitespace', -> { x.strip_ws(" a ") }, " a "],
      ['skip_ws', -> { u.dl { x.skip_ws(" \t\r\nabc", 0) } }, 4],
      ['skip_ws none', -> { u.dl { x.skip_ws('abc', 0) } }, 0],
      ['skip_ws from offset', -> { u.dl { x.skip_ws('a  b', 1) } }, 3],
      ['skip_ws to the end', -> { u.dl { x.skip_ws('  ', 0) } }, 2],
      ['skip_ws empty', -> { u.dl { x.skip_ws('', 0) } }, 0],
      ['sw? hit', -> { x.sw?('abcd', 'bc', 1) }, true],
      ['sw? miss', -> { x.sw?('abcd', 'bc', 0) }, false],
      ['sw? past the end', -> { x.sw?('ab', 'abc', 0) }, false]
    ])
  end

  t('xml: parse errors carry the exact message') do
    next true unless C10.file?('xml.rb')
    u = C10X
    errs = {
      '' => 'no root element', '<!-- c -->' => 'no root element', 'x<r/>' => 'text outside the root element', '<r/>x' => 'text outside the root element',
      '<a/><b/>' => 'more than one root element', '<a/><a/>' => 'more than one root element', '<a>' => 'unclosed element <a>',
      '<a><b></b>' => 'unclosed element <a>', '<a><b>' => 'unclosed element <b>',
      '<a><b></a>' => 'mismatched end tag </a>', '</a>' => 'mismatched end tag </a>', '<a></b>' => 'mismatched end tag </b>',
      '<a><b></a></b>' => 'mismatched end tag </a>', '<a></a' => 'bad end tag', '<a></>' => 'bad end tag', '<a></a x>' => 'bad end tag',
      '<' => 'bad start tag', '<1/>' => 'bad start tag', '<a' => 'unterminated start tag', '<a ' => 'unterminated start tag',
      '<a b="1"c="2"/>' => 'missing whitespace before an attribute', '<a b="1"/ >' => 'missing whitespace before an attribute',
      '<a 1="x"/>' => 'bad attribute name', '<a b/>' => 'attribute without a value', '<a b' => 'attribute without a value',
      '<a b =' => 'unquoted attribute value', '<a b=1/>' => 'unquoted attribute value', '<a b=' => 'unquoted attribute value',
      '<a b="x' => 'unterminated attribute value', "<a b='x" => 'unterminated attribute value',
      '<a b="1" b="2"/>' => 'duplicate attribute b', '<a b="<"/>' => "'<' in an attribute value",
      '<a xmlns:p=""/>' => 'namespace prefix cannot be undeclared', '<p:a/>' => 'unbound namespace prefix p',
      '<a q:b="1"/>' => 'unbound namespace prefix q', '<a><![CDATA[x</a>' => 'bad CDATA section', '<![CDATA[x]]><a/>' => 'bad CDATA section',
      '<a><!-- x</a>' => 'unterminated comment', '<r><!--></r>' => 'unterminated comment', '<r><!---></r>' => 'unterminated comment',
      '<a><? x</a>' => 'unterminated processing instruction', '<r><?></r>' => 'unterminated processing instruction',
      '<!DOCTYPE a' => 'unterminated declaration', '<!DOCTYPE a [' => 'unterminated declaration', '<!DOCTYPE a [<!ELEMENT b ANY>' => 'unterminated declaration',
      '<a b="&bad;"/>' => 'unknown entity &bad;', '<a>&amp</a>' => 'unterminated entity reference', '<a>&#x110000;</a>' => 'bad character reference',
      '<a b="&#0;"/>' => 'bad character reference'
    }
    C10.check(errs.map { |text, msg| ["parse #{text.inspect}", -> { u.perr(text) }, msg] })
  end

  t('xml: well-formed forms that parse') do
    next true unless C10.file?('xml.rb')
    u = C10X
    ok = ['<a/>', '<a></a>', " \n<a/>\r\n\t", '<a />', '<a b="1" c=\'2\'/>', '<a b = "1" />', '<a></a >', '<a><b/></a>', '<a:b xmlns:a="u"/>',
          '<a xmlns="u"><b xmlns=""/></a>', '<a.b-c_d/>', "<é/>", '<a b="x&amp;y"/>', '<a><![CDATA[]]></a>', '<a><!----></a>', '<a><??></a>', '<a><?p d?></a>',
          '<!DOCTYPE a><a/>', '<!DOCTYPE a [<!ELEMENT a ANY>]><a/>', '<!><a/>', '<?xml version="1.0"?><a/>', '<a xml:lang="en"/>']
    C10.check(ok.map { |text| ["parse #{text.inspect}", -> { u.perr(text) }, :ok] })
  end

  t('xml: parse builds the exact tree, namespaces, text/CDATA children and profile violations in document order') do
    next true unless C10.file?('xml.rb')
    u = C10X
    text = %(<?xml version="1.0"?>\n<!DOCTYPE r [<!ELEMENT a (b)> [x] <!ELEMENT b (#PCDATA)>]>\n<!-- c --><r xmlns="urn:d" xmlns:p="urn:p" a="1" p:b='2' xml:lang="en"><p:c d="x&amp;y"/>t&lt;<![CDATA[<&amp;>]]><e xmlns=""/><?pi x?></r>\n)
    d = u.parse(text)
    r = d.root
    pc, t1, cd, e = r.children
    kids = r.children.map { |k| k.is_a?(String) ? k : k.qname }
    C10.check([
      ['violations', -> { d.violations }, ['XML processing instructions are not permitted', 'DTD / DOCTYPE is not permitted', 'XML comments are not permitted',
                                           "xml:* attribute 'xml:lang' is not permitted (C14N 1.1 profile)", 'XML processing instructions are not permitted']],
      ['root name', -> { [r.qname, r.prefix, r.local, r.ns, r.parent] }, ['r', '', 'r', 'urn:d', nil]],
      ['root decls', -> { r.decls }, { '' => 'urn:d', 'p' => 'urn:p' }],
      ['root scope', -> { r.scope }, { '' => 'urn:d', 'p' => 'urn:p' }],
      ['root attrs', -> { r.attrs.map { |a| [a.qname, a.prefix, a.local, a.ns, a.value] } },
       [['a', '', 'a', '', '1'], ['p:b', 'p', 'b', 'urn:p', '2'], ['xml:lang', 'xml', 'lang', 'http://www.w3.org/XML/1998/namespace', 'en']]],
      ['children', -> { kids }, ['p:c', 't<', '<&amp;>', 'e']],
      ['prefixed child', -> { [pc.prefix, pc.local, pc.ns, pc.parent.equal?(r), pc.decls, pc.scope, pc.children] }, ['p', 'c', 'urn:p', true, {}, { '' => 'urn:d', 'p' => 'urn:p' }, []]],
      ['child attr', -> { pc.attrs.map { |a| [a.qname, a.ns, a.value] } }, [['d', '', 'x&y']]],
      ['text and CDATA', -> { [t1, cd] }, ['t<', '<&amp;>']],
      ['undeclared default', -> { [e.ns, e.decls, e.scope, e.parent.equal?(r)] }, ['', { '' => '' }, { 'p' => 'urn:p' }, true]],
      ['text_content', -> { r.text_content }, 't<<&amp;>'],
      ['canonical form', -> { u.dl { u.x.canonicalize(r) } },
       '<r xmlns="urn:d" xmlns:p="urn:p" a="1" xml:lang="en" p:b="2"><p:c d="x&amp;y"></p:c>t&lt;&lt;&amp;amp;&gt;<e xmlns=""></e></r>'],
      ['doc empty', -> { [u.x::Document.new.root, u.x::Document.new.violations] }, [nil, []]],
      ['uppercase XML: prefix still counts as an xml attribute', lambda {
        u.parse('<r xmlns:XML="urn:x" XML:a="1"/>').violations
      }, ["xml:* attribute 'XML:a' is not permitted (C14N 1.1 profile)"]],
      ['xml: attribute needs no declaration', -> { u.parse('<r xml:space="preserve"/>').root.attrs.first.ns }, 'http://www.w3.org/XML/1998/namespace'],
      ['prefixed attr uses the in-scope binding', -> { u.parse('<r xmlns:q="urn:q" q:a="1"/>').root.attrs.first.ns }, 'urn:q'],
      ['no violation for a normal document', -> { u.parse('<r a="1"><c/></r>').violations }, []],
      ['two comments, two violations', -> { u.parse('<!--a--><r><!--b--></r>').violations }, ['XML comments are not permitted', 'XML comments are not permitted']],
      ['inner default namespace', -> { u.parse('<r xmlns="d"><c/></r>').root.children[0].ns }, 'd'],
      ['plain element has empty ns', -> { u.parse('<r/>').root.ns }, ''],
      ['child scope is a copy', lambda {
        rr = u.parse('<r xmlns:p="u"><c xmlns:q="v"/></r>').root
        [rr.scope, rr.children[0].scope]
      }, [{ 'p' => 'u' }, { 'p' => 'u', 'q' => 'v' }]]
    ])
  end

  t('xml: comments, CDATA and processing instructions: offsets, text after them, nesting') do
    next true unless C10.file?('xml.rb')
    u = C10X
    kid = ->(t) { u.parse(t).root.children.map { |k| k.is_a?(String) ? k : k.qname } }
    C10.check([
      ['text after a comment', -> { kid.('<r><!-- c -->x</r>') }, ['x']],
      ['empty comment then text', -> { kid.('<r><!---->x</r>') }, ['x']],
      ['comment between texts', -> { kid.('<r>a<!--b-->c</r>') }, %w[a c]],
      ['comment then element', -> { kid.('<r><!--b--><c/></r>') }, ['c']],
      ['CDATA nested: attached to the innermost open element', lambda {
        rr = u.parse('<r><a><![CDATA[x]]></a>y</r>').root
        [rr.children[0].children, rr.children[1], rr.children.length]
      }, [['x'], 'y', 2]],
      ['empty CDATA', -> { kid.('<r><![CDATA[]]>z</r>') }, ['', 'z']],
      ['CDATA content kept verbatim', -> { kid.('<r><![CDATA[a<b>&amp;]]></r>') }, ['a<b>&amp;']],
      ['CDATA then text', -> { kid.('<r><![CDATA[a]]>b</r>') }, %w[a b]],
      ['CDATA then element', -> { kid.('<r><![CDATA[a]]><c/></r>') }, %w[a c]],
      ['CDATA first char matters', -> { kid.('<r><![CDATA[abc]]></r>') }, ['abc']],
      ['PI inside then text', -> { kid.('<r><?p d?>z</r>') }, ['z']],
      ['empty PI then text', -> { kid.('<r><??>z</r>') }, ['z']],
      ['PI then element', -> { kid.('<r><?p?><c/></r>') }, ['c']],
      ['DOCTYPE then root', -> { u.parse('<!DOCTYPE r><r/>').root.qname }, 'r'],
      ['DOCTYPE with subset then text-free root', -> { u.parse('<!DOCTYPE r [<!ELEMENT r ANY>]><r/>').root.qname }, 'r'],
      ['DOCTYPE with nested brackets', -> { u.parse('<!DOCTYPE r [<!ELEMENT a (b)> [x] <!ELEMENT b ANY>]><r/>').root.qname }, 'r'],
      ['empty declaration', -> { u.parse('<!><r/>').violations }, ['DTD / DOCTYPE is not permitted']],
      ['declaration inside the root', -> { u.parse('<r><!DOCTYPE x>t</r>').root.children }, ['t']],
      ['text chunks', -> { u.parse('<r>a<b/>c<d/>e</r>').root.children.map { |k| k.is_a?(String) ? k : k.qname } }, %w[a b c d e]],
      ['text entity', -> { kid.('<r>a&amp;b</r>') }, ['a&b']],
      ['whitespace text kept inside', -> { kid.("<r> <c/>\n</r>") }, [' ', 'c', "\n"]],
      ['attribute value with > and quote of the other kind', -> { u.parse(%(<r a="x>y" b='p"q'/>)).root.attrs.map(&:value) }, ['x>y', 'p"q']],
      ['attribute whitespace normalised', -> { u.parse(%(<r a="x\ty\nz"/>)).root.attrs[0].value }, 'x y z'],
      ['attribute reference whitespace kept', -> { u.parse('<r a="x&#9;y"/>').root.attrs[0].value }, "x\ty"]
    ])
  end

  t('xml: Element / Attr API (get_attribute, element_children, descendants, text_content)') do
    next true unless C10.file?('xml.rb')
    u = C10X
    x = u.x
    r = u.parse('<r xmlns:p="u" a="1" p:b="2"><a/><p:a/><b><a/><p:a/></b>x</r>').root
    b = r.children[2]
    nest = u.parse('<r><a><a/></a></r>').root
    qn = ->(l) { l.map(&:qname) }
    C10.check([
      ['Element defaults', -> { e = x::Element.new('p:a', nil); [e.qname, e.prefix, e.local, e.ns, e.attrs, e.decls, e.scope, e.children, e.parent] },
       ['p:a', 'p', 'a', '', [], {}, {}, [], nil]],
      ['Element unprefixed', -> { e = x::Element.new('a', 7); [e.prefix, e.local, e.parent] }, ['', 'a', 7]],
      ['Attr defaults', -> { a = x::Attr.new('p:b', 'v'); [a.qname, a.prefix, a.local, a.ns, a.value] }, ['p:b', 'p', 'b', '', 'v']],
      ['Attr unprefixed', -> { a = x::Attr.new('b', 'v'); [a.prefix, a.local] }, ['', 'b']],
      ['get_attribute', -> { [r.get_attribute('a'), r.get_attribute('p:b'), r.get_attribute('zz'), r.get_attribute('xmlns:p'), r.get_attribute('b')] }, ['1', '2', '', '', '']],
      ['element_children all', -> { qn.(r.element_children) }, %w[a p:a b]],
      ['element_children ns', -> { qn.(r.element_children('u')) }, ['p:a']],
      ['element_children empty ns', -> { qn.(r.element_children('')) }, %w[a b]],
      ['element_children local', -> { qn.(r.element_children(nil, 'a')) }, %w[a p:a]],
      ['element_children ns and local', -> { [qn.(r.element_children('', 'a')), qn.(r.element_children('u', 'a')), qn.(r.element_children('u', 'b'))] }, [['a'], ['p:a'], []]],
      ['element_children skips text', -> { r.element_children.length }, 3],
      ['descendants ns', -> { r.descendants('u', 'a') == [r.children[1], b.children[1]] }, true],
      ['descendants empty ns', -> { r.descendants('', 'a') == [r.children[0], b.children[0]] }, true],
      ['descendants other local', -> { r.descendants('', 'b') == [b] }, true],
      ['descendants none', -> { r.descendants('u', 'b') }, []],
      ['descendants recursion', -> { nest.descendants('', 'a') == [nest.children[0], nest.children[0].children[0]] }, true],
      ['text_content', -> { u.parse('<r>a<b>c<d>e</d></b>f</r>').root.text_content }, 'acef'],
      ['text_content of an empty element', -> { u.parse('<r/>').root.text_content }, '']
    ])
  end

  t('xml: canonicalization (namespace/attribute ordering, escaping, undeclared default, skip, apex scope)') do
    next true unless C10.file?('xml.rb')
    u = C10X
    x = u.x
    doc2 = u.parse('<r xmlns:b="u2" xmlns:a="u1" xmlns="d" z="1" a:y="2" b:x="3"><c xmlns:a="u1" xmlns:b="u3"/></r>')
    sib = u.parse('<r><a/><b/></r>').root
    ap = u.parse('<r xmlns:p="u" xmlns="d"><c a="1"/></r>').root.children[0]
    esc = "<r b=\"x&amp;&lt;&quot;&#x9;&#xA;&#xD;>y\" d=\"p q\">a&amp;b&lt;c&gt;d&#xD;e\tf\ng\"h</r>"
    C10.check([
      ['empty element', -> { u.canon('<a/>') }, '<a></a>'],
      ['nested plain', -> { u.canon('<r><c/></r>') }, '<r><c></c></r>'],
      ['text and attribute escaping', lambda {
        u.canon(%(<r b="x&amp;&lt;&quot;&#9;&#10;&#13;&gt;y" d="p\tq">a&amp;b&lt;c&gt;d&#xD;e&#9;f&#10;g&quot;h</r>))
      }, esc],
      ['namespaces and attributes sorted, child declares only what changed', -> { u.dl { x.canonicalize(doc2.root) } },
       '<r xmlns="d" xmlns:a="u1" xmlns:b="u2" z="1" a:y="2" b:x="3"><c xmlns:b="u3"></c></r>'],
      ['attributes sorted by namespace then local name', -> { u.canon('<r z="1" a="2" p:b="3" q:a="4" xmlns:p="urn:z" xmlns:q="urn:a"/>') },
       '<r xmlns:p="urn:z" xmlns:q="urn:a" a="2" z="1" q:a="4" p:b="3"></r>'],
      ['undeclared default namespace', -> { u.canon('<r xmlns="d"><c xmlns=""/></r>') }, '<r xmlns="d"><c xmlns=""></c></r>'],
      ['redeclared equal default is not repeated', -> { u.canon('<r xmlns="d"><c xmlns="d"/></r>') }, '<r xmlns="d"><c></c></r>'],
      ['changed default is repeated', -> { u.canon('<r xmlns="d"><c xmlns="e"/></r>') }, '<r xmlns="d"><c xmlns="e"></c></r>'],
      ['no default above: nothing to undeclare', -> { u.canon('<r><c xmlns=""/></r>') }, '<r><c></c></r>'],
      ['default below only', -> { u.canon('<r><c xmlns="d"/></r>') }, '<r><c xmlns="d"></c></r>'],
      ['grandchild keeps the default', -> { u.canon('<r xmlns="d"><c><g/></c></r>') }, '<r xmlns="d"><c><g></g></c></r>'],
      ['undeclared default then a grandchild', -> { u.canon('<r xmlns="d"><c xmlns=""><g/></c></r>') }, '<r xmlns="d"><c xmlns=""><g></g></c></r>'],
      ['prefix declared only on the child', -> { u.canon('<r><c xmlns:q="v"/></r>') }, '<r><c xmlns:q="v"></c></r>'],
      ['xml attribute sorts by its namespace', -> { u.canon('<r xmlns:p="urn:p" p:b="1" xml:lang="en"/>') }, '<r xmlns:p="urn:p" xml:lang="en" p:b="1"></r>'],
      ['skip drops one descendant', -> { u.dl { x.canonicalize(sib, sib.children[1]) } }, '<r><a></a></r>'],
      ['skip nil keeps all', -> { u.dl { x.canonicalize(sib) } }, '<r><a></a><b></b></r>'],
      ['apex inherits every in-scope namespace', -> { u.dl { x.canonicalize(ap) } }, '<c xmlns="d" xmlns:p="u" a="1"></c>'],
      ['apex scope override', -> { u.dl { x.canonicalize(ap, nil, { 'q' => 'w' }) } }, '<c xmlns:q="w" a="1"></c>'],
      ['apex scope override with a child', lambda {
        rr = u.parse('<r xmlns:p="u"><c/></r>').root
        u.dl { x.canonicalize(rr, nil, { 'q' => 'w' }) }
      }, '<r xmlns:q="w"><c xmlns:p="u"></c></r>'],
      ['enc_text', -> { x.enc_text("a&b<c>d\re\tf\ng\"h") }, "a&amp;b&lt;c&gt;d&#xD;e\tf\ng\"h"],
      ['enc_attr', -> { x.enc_attr("a&b<c>d\"e\tf\ng\rh") }, "a&amp;b&lt;c>d&quot;e&#x9;f&#xA;g&#xD;h"]
    ])
  end

  t('xml: deadlines (a parser loop that stops advancing must time out)') do
    next true unless C10.file?('xml.rb')
    u = C10X
    docs = ['<a/>', '<a b="1"> text &amp; more <!-- c --><![CDATA[x]]><?p d?></a>', "<!DOCTYPE a [<!ELEMENT a ANY>]>\n<a>\n  <b/>\n</a>\n", "  <a\n b = '1' />  "]
    docs.each { |d| u.dl { u.x.parse_xml(d) } }
    u.dl { u.unesc("abc \t def", true) }
    u.dl { u.unesc('a&amp;b', false) }
    u.dl { u.x.skip_ws("   x", 0) }
    u.dl { u.x.canonicalize(u.x.parse_xml('<a><b/>t</a>').root) }
    true
  end
end
