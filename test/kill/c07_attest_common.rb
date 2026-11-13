# frozen_string_literal: true

# Exact-outcome kill tests for lib/atlas_pca/attest.rb (the vendor factory and its evidence mapping) and lib/atlas_pca/attest/common.rb
# (the binding, the JS-faithful number / string / base64 / JSON helpers, the OpenSSL glue and the compact-JWS reader). Expected values are
# read from Node (Buffer.from, Number, BigInt, String(number), the report_data hash) and from the TypeScript reference
# (packages/pca/src/attestation.ts attestationBinding, test-support/attestation-wire.ts evidenceFor / verifierFromConfig); the JSON error
# wording is the V8 11 (Node 20) wording the conformance vectors were generated with. AtlasPca is dropped and re-evaluated for every
# mutant, so every module is resolved at CALL time (never cached in a constant).
require 'timeout'
require 'tmpdir'
require 'fileutils'
require 'json'
require 'base64'
require 'digest'
require 'rbconfig'
require 'atlas_pca/attest'

module MutationKill
  module C07
    module_function

    def att = AtlasPca::Attest
    def cm = AtlasPca::Attest::Common

    # These tests bear on attest.rb and attest/common.rb only (the oracle exports MUT_FILE; run_kill.rb leaves it unset).
    def skip? = (f = ENV['MUT_FILE']) && !f.empty? && !%w[attest.rb common.rb].include?(f)
    def mutating? = (f = ENV['MUT_FILE']) && !f.empty?

    def err
      yield
      nil
    rescue Exception => e # rubocop:disable Lint/RescueException
      [e.class, e.message]
    end

    def tm(&) = Timeout.timeout(2, &)

    def same?(got, want)
      case want
      when Float then got.is_a?(Float) && (want.nan? ? got.nan? : got == want && (want != 0 || (1.0 / got) == (1.0 / want)))
      when Integer then got.is_a?(Integer) && got == want
      when Array then got.is_a?(Array) && got.size == want.size && got.zip(want).all? { |g, w| same?(g, w) }
      when Hash then got.is_a?(Hash) && got.size == want.size && want.all? { |k, v| got.key?(k) && same?(got[k], v) }
      else got == want && got.class == want.class
      end
    end

    # rows: [label, got, want]; true when all agree, else raises with the first mismatches (the kill runner prints it).
    def check(rows)
      bad = rows.reject { |_l, got, want| same?(got, want) }
      return true if bad.empty?

      raise "mismatch: #{bad.first(4).map { |l, g, w| "#{l}: got #{g.inspect} want #{w.inspect}" }.join(' | ')}"
    end

    # ---- a fresh Ruby that loads the library with only the file under mutation replaced (an in-process require is already satisfied)
    LIB = File.expand_path('../../lib', __dir__)

    def source(rel)
      path = File.join(LIB, rel)
      if defined?(::Oracle) && (tgt = ::Oracle.instance_variable_get(:@target)) && File.expand_path(tgt) == path
        ::Oracle.instance_variable_get(:@text)
      else
        File.read(path)
      end
    end

    def header_changed?(rel, nlines)
      source(rel).lines.first(nlines) != File.read(File.join(LIB, rel)).lines.first(nlines)
    end

    def fresh(rel, code)
      Dir.mktmpdir('c07fresh') do |d|
        FileUtils.cp_r(LIB, d)
        File.write(File.join(d, 'lib', rel), source(rel))
        gems = Gem.loaded_specs.values.flat_map(&:full_require_paths).flat_map { |g| ['-I', g] }
        out = IO.popen([RbConfig.ruby, '--disable-gems', '-I', File.join(d, 'lib'), *gems, '-e', code], 'r', err: File::NULL, &:read)
        [out, $?.success?]
      end
    end

    # ---- keys, generated once at load
    EC256 = OpenSSL::PKey::EC.generate('prime256v1')
    EC384 = OpenSSL::PKey::EC.generate('secp384r1')
    EC521 = OpenSSL::PKey::EC.generate('secp521r1')
    ECK1 = OpenSSL::PKey::EC.generate('secp256k1')
    ED = OpenSSL::PKey.generate_key('ED25519')
    RSAK = OpenSSL::PKey::RSA.generate(2048)

    def pub(key) = cm.load_public_key(key.public_to_der)

    def b64(s) = [s].pack('m0')
    def b64u(s) = Base64.urlsafe_encode64(s, padding: false)

    def raw_sig(key, data, digest, half)
      der = key.sign(OpenSSL::Digest.new(digest), data)
      OpenSSL::ASN1.decode(der).value.map { |i| i.value.to_s(2).rjust(half, "\x00".b) }.join
    end

    # the five verifier classes (and the NVIDIA hook) answer `new` with a marker, recording the arguments
    NAMES = %i[AmdSnpVerifier AzureMaaVerifier IntelDcapVerifier NvidiaSpdmVerifier GcpConfidentialSpaceVerifier NvidiaCollateralHook].freeze

    def stubbed
      seen = {}
      klasses = NAMES.map { |n| att.const_get(n) }
      klasses.each_with_index do |k, i|
        name = NAMES[i]
        k.define_singleton_method(:new) { |*args| seen[name] = args; [:built, name] }
      end
      yield seen
    ensure
      klasses&.each { |k| k.singleton_class.send(:remove_method, :new) if k.singleton_class.instance_methods(false).include?(:new) }
    end

    def parse_err(text) = err { tm { cm.js_json_loads(text) } }
  end

  # ============================================================================================================== loading
  t('attest.rb requires its parts in dependency order and loads nothing else (fresh ruby over the mutated text)') do
    next true if C07.skip?
    next true if C07.mutating? && !C07.header_changed?('atlas_pca/attest.rb', 25)

    out, ok = C07.fresh('atlas_pca/attest.rb',
                        "require 'atlas_pca/attest'; puts $LOADED_FEATURES.filter_map { |f| f[%r{/lib/(atlas_pca/.*)}, 1] }")
    want = %w[common der cert amd azure gcp intel ocsp xml nvidia].map { |n| "atlas_pca/attest/#{n}.rb" } + ['atlas_pca/attest.rb']
    ok && out == "#{want.join("\n")}\n"
  end

  t('attest/common.rb requires what it uses: Base64, JSON and OpenSSL are loaded by it alone (fresh ruby over the mutated text)') do
    next true if C07.skip?
    next true if C07.mutating? && !C07.header_changed?('atlas_pca/attest/common.rb', 12)

    code = <<~'RUBY'
      require 'atlas_pca/attest/common'
      c = AtlasPca::Attest::Common
      puts c.attestation_binding({ 'holder_pub' => 'h', 'grant_ref' => 'g', 'epoch' => 0, 'nonce' => 'n' }).unpack1('H*')
      puts c.decode_canonical_b64url('AQID').unpack1('H*')
      puts c.js_json_loads('{"a":[7]}').dig('a', 0)
      puts c.hash_alg('sha256').hexdigest('abc')
    RUBY
    out, ok = C07.fresh('atlas_pca/attest/common.rb', code)
    ok && out == "3aa0fd6a3f9b14c6568858ba9db5b4e508ed236c9c6b7a381b2321612f08f6b40c5570ca4367bc4d043286bd659b13dcb9a0fea347eeab450ff3cc433d05da2e\n" \
                 "010203\n7\nba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"
  end

  # ============================================================================================================== attest.rb
  t('attest: VENDORS, MISSING and the domain constants are frozen with the exact content') do
    next true if C07.skip?

    a = C07.att
    C07.check([['vendors', a::VENDORS, %w[amd-sev-snp intel-tdx-dcap azure-maa gcp-confidential-space nvidia-gpu-spdm]],
               ['vendors frozen', a::VENDORS.frozen?, true], ['missing frozen', a::MISSING.frozen?, true],
               ['domain', C07.cm::ATTEST_BIND_DOMAIN, "atlas-pca/attest-bind/v1\x00".b], ['domain frozen', C07.cm::ATTEST_BIND_DOMAIN.frozen?, true],
               ['domain enc', C07.cm::ATTEST_BIND_DOMAIN.encoding, Encoding::BINARY], ['max safe', C07.cm::MAX_SAFE, 9_007_199_254_740_991],
               ['special', C07.cm::SPECIAL_JSON, ['NaN', 'Infinity', 'undefined', '[object Object]']], ['special frozen', C07.cm::SPECIAL_JSON.frozen?, true],
               ['jwk', C07.cm::JWK_CURVE, { 'prime256v1' => 'P-256', 'secp384r1' => 'P-384', 'secp521r1' => 'P-521' }],
               ['jwk frozen', C07.cm::JWK_CURVE.frozen?, true], ['curve oid', C07.cm::CURVE_OID, { 'P-256' => 'prime256v1', 'P-384' => 'secp384r1' }],
               ['curve oid frozen', C07.cm::CURVE_OID.frozen?, true]])
  end

  t('attest.attestation_binding is Common.attestation_binding over the same expected binding (TS attestationBinding hash)') do
    next true if C07.skip?

    e = { 'holder_pub' => 'holder-pub', 'grant_ref' => 'grant-ref', 'epoch' => 7, 'nonce' => 'nonce-1' }
    want = ['3a54d96f593f2f19de6518a2b63078b876acd3cb5acdc56ba8088c4097347066684fca2b4a9b039c6ddb0e3ff41e84ec2d3c7d4b9ff558f769f3fa8a12c828b9'].pack('H*')
    C07.check([['snake', C07.att.attestation_binding(e), want],
               ['camel', C07.att.attestation_binding({ 'holderPub' => 'holder-pub', 'grantRef' => 'grant-ref', 'epoch' => 7, 'nonce' => 'nonce-1' }), want]])
  end

  t('attest.unb64: a binary string is kept as bytes (a copy), any other string is base64, anything else is a Node TypeError') do
    next true if C07.skip?

    a = C07.att
    bin = "\x01\xFF\x00AQID".b
    got = a.unb64(bin)
    msg = ->(r) { "The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received #{r}" }
    te = a::JsTypeError
    C07.check([['binary kept', got, bin], ['binary is a copy', got.equal?(bin), false], ['binary enc', got.encoding, Encoding::BINARY],
               ['ascii binary not decoded', a.unb64('AQID'.b), 'AQID'.b], ['utf8 decoded', a.unb64('AQID'), "\x01\x02\x03".b],
               ['utf8 enc', a.unb64('AQID').encoding, Encoding::BINARY],
               ['nil', C07.err { a.unb64(nil) }, [te, msg.call('null')]], ['missing', C07.err { a.unb64(a::MISSING) }, [te, msg.call('undefined')]],
               ['int', C07.err { a.unb64(5) }, [te, msg.call('type number (5)')]], ['float', C07.err { a.unb64(1.5) }, [te, msg.call('type number (1.5)')]],
               ['true', C07.err { a.unb64(true) }, [te, msg.call('type boolean (true)')]], ['false', C07.err { a.unb64(false) }, [te, msg.call('type boolean (false)')]],
               ['hash', C07.err { a.unb64({ 'a' => 1 }) }, [te, msg.call('an instance of Object')]], ['symbol', C07.err { a.unb64(:s) }, [te, msg.call('type symbol')]]])
  end

  t('attest.opt_bytes: a string is base64, everything else is nil') do
    next true if C07.skip?

    a = C07.att
    C07.check([['str', a.opt_bytes('AQID'), "\x01\x02\x03".b], ['nil', a.opt_bytes(nil), nil], ['int', a.opt_bytes(5), nil], ['hash', a.opt_bytes({}), nil],
               ['false', a.opt_bytes(false), nil], ['empty', a.opt_bytes(''), ''.b]])
  end

  t('attest.evidence_for maps the wire evidence of each vendor to the verifier input, exactly (TS evidenceFor)') do
    next true if C07.skip?

    a = C07.att
    f = a.method(:evidence_for)
    b = ->(s) { C07.b64(s) }
    te = a::JsTypeError
    msg = ->(r) { "The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received #{r}" }
    col = { 'tcbInfoJson' => 't', 'tcbInfoIssuerChainPem' => 'tc', 'qeIdentityJson' => 'q', 'qeIdentityIssuerChainPem' => 'qc',
            'pckCrlDer' => b.call('P'), 'rootCrlDer' => b.call('Rr') }
    nvc = { 'driverRimXml' => 'd', 'vbiosRimXml' => 'v', 'crls' => [b.call('c1'), b.call('c2')], 'ocsp' => [b.call('o1')] }
    C07.check([
                 ['nil ev', f.call('amd-sev-snp', nil), nil], ['nil ev unknown vendor', f.call('bogus', nil), nil],
                 ['amd full', f.call('amd-sev-snp', { 'report' => b.call('R'), 'vcekDer' => b.call('V'), 'askArkPem' => 'PEM', 'runtimeData' => b.call('D'), 'x' => 1 }),
                  { 'report' => 'R'.b, 'vcekDer' => 'V'.b, 'askArkPem' => 'PEM', 'runtimeData' => 'D'.b }],
                 ['amd empty', f.call('amd-sev-snp', {}), {}], ['amd bad runtime', f.call('amd-sev-snp', { 'runtimeData' => 5 }), {}],
                 ['amd report nil', C07.err { f.call('amd-sev-snp', { 'report' => nil }) }, [te, msg.call('null')]],
                 ['intel full', f.call('intel-tdx-dcap', { 'quote' => b.call('Q'), 'runtimeData' => b.call('D'), 'collateral' => col }),
                  { 'quote' => 'Q'.b, 'runtimeData' => 'D'.b,
                    'collateral' => { 'tcbInfoJson' => 't', 'tcbInfoIssuerChainPem' => 'tc', 'qeIdentityJson' => 'q', 'qeIdentityIssuerChainPem' => 'qc',
                                      'pckCrlDer' => 'P'.b, 'rootCrlDer' => 'Rr'.b } }],
                 ['intel empty', f.call('intel-tdx-dcap', {}), {}], ['intel collateral not hash', f.call('intel-tdx-dcap', { 'collateral' => 'x' }), {}],
                 ['intel no pck crl', C07.err { f.call('intel-tdx-dcap', { 'collateral' => col.reject { |k, _| k == 'pckCrlDer' } }) }, [te, msg.call('undefined')]],
                 ['intel no root crl', C07.err { f.call('intel-tdx-dcap', { 'collateral' => col.reject { |k, _| k == 'rootCrlDer' } }) }, [te, msg.call('undefined')]],
                 ['nvidia full', f.call('nvidia-gpu-spdm', { 'evidence' => b.call('E'), 'certChainPem' => 'CP', 'collateral' => nvc }),
                  { 'evidence' => 'E'.b, 'certChainPem' => 'CP',
                    'collateral' => { 'driverRimXml' => 'd', 'vbiosRimXml' => 'v', 'crls' => %w[c1 c2].map(&:b), 'ocsp' => ['o1'.b] } }],
                 ['nvidia empty', f.call('nvidia-gpu-spdm', {}), {}],
                 ['nvidia empty lists', f.call('nvidia-gpu-spdm', { 'collateral' => { 'driverRimXml' => 'd', 'crls' => [], 'ocsp' => [] } }),
                  { 'collateral' => { 'driverRimXml' => 'd', 'vbiosRimXml' => nil } }],
                 ['nvidia absent lists', f.call('nvidia-gpu-spdm', { 'collateral' => {} }), { 'collateral' => { 'driverRimXml' => nil, 'vbiosRimXml' => nil } }],
                 ['nvidia collateral not hash', f.call('nvidia-gpu-spdm', { 'collateral' => 'x' }), {}],
                 ['azure', f.call('azure-maa', { 'token' => 'T', 'jwks' => { 'keys' => [] }, 'x' => 1 }), { 'token' => 'T', 'jwks' => { 'keys' => [] } }],
                 ['azure empty', f.call('azure-maa', {}), {}], ['azure token only', f.call('azure-maa', { 'token' => 'T' }), { 'token' => 'T' }],
                 ['gcp', f.call('gcp-confidential-space', { 'token' => 'T', 'jwks' => { 'keys' => [] } }), { 'token' => 'T', 'jwks' => { 'keys' => [] } }],
                 ['gcp empty', f.call('gcp-confidential-space', {}), {}], ['gcp jwks only', f.call('gcp-confidential-space', { 'jwks' => 1 }), { 'jwks' => 1 }],
                 ['unknown', C07.err { f.call('bogus', {}) }, [a::AttestConstructError, 'unknown attestation vendor bogus']],
                 ['unknown nil', C07.err { f.call(nil, {}) }, [a::AttestConstructError, 'unknown attestation vendor undefined']],
                 ['unknown int', C07.err { f.call(5, {}) }, [a::AttestConstructError, 'unknown attestation vendor 5']],
                 ['unknown true', C07.err { f.call(true, {}) }, [a::AttestConstructError, 'unknown attestation vendor true']]
               ])
  end

  t('attest.WithIdentity: a verified result gets the override merged over measured, anything else passes through untouched') do
    next true if C07.skip?

    a = C07.att
    mk = lambda do |ret|
      inner = Object.new
      calls = []
      inner.define_singleton_method(:verify) { |*args| calls << args; ret }
      [inner, calls]
    end
    ov = { 'b' => 9, 'c' => 3 }
    ok_r = { 'ok' => true, 'bound' => true, 'measured' => { 'a' => 1, 'b' => 2 } }
    rows = []
    inner, calls = mk.call(ok_r)
    got = a::WithIdentity.new(inner, ov).verify(:doc, :exp, 42)
    rows << ['merged', got, { 'ok' => true, 'bound' => true, 'measured' => { 'a' => 1, 'b' => 9, 'c' => 3 } }]
    rows << ['args', calls, [[:doc, :exp, 42]]]
    rows << ['source untouched', ok_r['measured'], { 'a' => 1, 'b' => 2 }]
    [{ 'ok' => false, 'measured' => { 'a' => 1 } }, { 'ok' => true }, { 'ok' => true, 'measured' => nil }, { 'ok' => false }].each_with_index do |r, i|
      inner, = mk.call(r)
      res = a::WithIdentity.new(inner, ov).verify(1, 2, 3)
      rows << ["passthrough #{i}", res.equal?(r), true]
    end
    C07.check(rows)
  end

  t('attest.present copies exactly the listed keys that are present (nil values included)') do
    next true if C07.skip?

    a = C07.att
    C07.check([['some', a.present({ 'a' => 1, 'b' => nil, 'z' => 3 }, 'a', 'b', 'c'), { 'a' => 1, 'b' => nil }], ['none', a.present({}, 'a'), {}],
               ['no keys', a.present({ 'a' => 1 }), {}]])
  end

  t('attest.verifier_from_config refuses an unknown vendor first, then a non-object config; the refusals are AttestConstructError') do
    next true if C07.skip?

    a = C07.att
    ce = a::AttestConstructError
    rows = [['unknown', C07.err { a.verifier_from_config('bogus', {}) }, [ce, 'unknown attestation vendor bogus']],
            ['unknown before config', C07.err { a.verifier_from_config('bogus', 'notahash') }, [ce, 'unknown attestation vendor bogus']],
            ['unknown nil', C07.err { a.verifier_from_config(nil, {}) }, [ce, 'unknown attestation vendor undefined']]]
    a::VENDORS.each do |v|
      [nil, 5, 'x', [], true].each do |bad|
        rows << ["#{v} #{bad.inspect}", C07.err { a.verifier_from_config(v, bad) }, [ce, 'verifier_from_config: config must be an object']]
      end
    end
    # the case's own else (a vendor that passes the list but has no builder): reached by widening the list
    orig = a::VENDORS
    a.send(:remove_const, :VENDORS)
    a.const_set(:VENDORS, [nil].freeze)
    begin
      rows << ['no builder', C07.err { a.verifier_from_config(nil, {}) }, [ce, 'unknown attestation vendor undefined']]
    ensure
      a.send(:remove_const, :VENDORS)
      a.const_set(:VENDORS, orig)
    end
    C07.check(rows)
  end

  t('attest.verifier_from_config hands each verifier exactly its configuration keys and an evidence resolver') do
    next true if C07.skip?

    a = C07.att
    b = ->(s) { C07.b64(s) }
    rows = []
    C07.stubbed do |seen|
      # amd
      cfg = { 'family' => 'genoa', 'binding' => 'report-data', 'policy' => { 'measurements' => ['aa'] }, 'clockSkewMs' => 5, 'junk' => 1,
              'trustAnchorArkSpkiSha384' => 'ff', 'collateral' => {} }
      rows << ['amd returns', a.verifier_from_config('amd-sev-snp', cfg), [:built, :AmdSnpVerifier]]
      o = seen[:AmdSnpVerifier].first
      rows << ['amd args', seen[:AmdSnpVerifier].size, 1]
      rows << ['amd opts', o.reject { |k, _| k == 'resolve_evidence' }, { 'family' => 'genoa', 'binding' => 'report-data', 'policy' => { 'measurements' => ['aa'] }, 'clockSkewMs' => 5 }]
      rows << ['amd resolver keyed', o.key?('resolve_evidence'), true]
      rows << ['amd resolves', o['resolve_evidence'].call({ 'evidence' => { 'report' => b.call('R') } }), { 'report' => 'R'.b }]
      rows << ['amd resolves non-hash string', o['resolve_evidence'].call('has evidence'), nil]
      rows << ['amd resolves array', o['resolve_evidence'].call([1]), nil]
      rows << ['amd resolves int', o['resolve_evidence'].call(5), nil]
      rows << ['amd resolves nil', o['resolve_evidence'].call(nil), nil]
      rows << ['amd resolves no evidence', o['resolve_evidence'].call({}), nil]
      rows << ['amd resolves nil evidence', o['resolve_evidence'].call({ 'evidence' => nil }), nil]
      a.verifier_from_config('amd-sev-snp', { 'family' => 'milan' })
      rows << ['amd minimal', seen[:AmdSnpVerifier].first.keys.sort, %w[family resolve_evidence]]
      # azure
      cfg = { 'trustedIssuers' => ['i'], 'trustAnchors' => { 'rootSpkiSha256' => ['ab'] }, 'policy' => { 'tdxMrtds' => ['c'] }, 'clockSkewMs' => 7, 'family' => 'x' }
      rows << ['azure returns', a.verifier_from_config('azure-maa', cfg), [:built, :AzureMaaVerifier]]
      o = seen[:AzureMaaVerifier].first
      rows << ['azure opts', o.reject { |k, _| k == 'resolve_evidence' }, { 'trustedIssuers' => ['i'], 'trustAnchors' => { 'rootSpkiSha256' => ['ab'] }, 'policy' => { 'tdxMrtds' => ['c'] }, 'clockSkewMs' => 7 }]
      rows << ['azure resolves', o['resolve_evidence'].call({ 'evidence' => { 'token' => 'T' } }), { 'token' => 'T' }]
      rows << ['azure custom resolver', a.verifier_from_config('azure-maa', {}, ->(d) { { 'token' => d } }) && seen[:AzureMaaVerifier].first['resolve_evidence'].call(:doc), { 'token' => :doc }]
      a.verifier_from_config('azure-maa', {})
      rows << ['azure minimal', seen[:AzureMaaVerifier].first.keys, ['resolve_evidence']]
      # gcp
      rows << ['gcp returns', a.verifier_from_config('gcp-confidential-space', cfg), [:built, :GcpConfidentialSpaceVerifier]]
      o = seen[:GcpConfidentialSpaceVerifier].first
      rows << ['gcp opts', o.reject { |k, _| k == 'resolve_evidence' }, { 'trustedIssuers' => ['i'], 'trustAnchors' => { 'rootSpkiSha256' => ['ab'] }, 'policy' => { 'tdxMrtds' => ['c'] }, 'clockSkewMs' => 7 }]
      rows << ['gcp resolves', o['resolve_evidence'].call({ 'evidence' => { 'jwks' => 1 } }), { 'jwks' => 1 }]
      a.verifier_from_config('gcp-confidential-space', {})
      rows << ['gcp minimal', seen[:GcpConfidentialSpaceVerifier].first.keys, ['resolve_evidence']]
      # intel
      cfg = { 'binding' => 'report-data', 'policy' => { 'mrtds' => ['m'] }, 'trustAnchorRootCaSpkiSha256' => 'ab', 'allowMissingCollateral' => true, 'clockSkewMs' => 3 }
      rows << ['intel returns', a.verifier_from_config('intel-tdx-dcap', cfg), [:built, :IntelDcapVerifier]]
      o = seen[:IntelDcapVerifier].first
      rows << ['intel opts', o.reject { |k, _| k == 'resolve_evidence' }, { 'binding' => 'report-data', 'policy' => { 'mrtds' => ['m'] }, 'trustAnchorRootCaSpkiSha256' => 'ab', 'allowMissingCollateral' => true }]
      rows << ['intel resolves', o['resolve_evidence'].call({ 'evidence' => { 'quote' => b.call('Q') } }), { 'quote' => 'Q'.b }]
      a.verifier_from_config('intel-tdx-dcap', {})
      rows << ['intel minimal', seen[:IntelDcapVerifier].first.keys, ['resolve_evidence']]
      # identity overrides
      ov = { 'operator' => 'o' }
      r = a.verifier_from_config('gcp-confidential-space', { 'identity_overrides' => ov })
      rows << ['wrapped', r.is_a?(a::WithIdentity), true]
      rows << ['wrapped inner', r.instance_variable_get(:@inner), [:built, :GcpConfidentialSpaceVerifier]]
      rows << ['wrapped overrides', r.instance_variable_get(:@ov), ov]
      rows << ['empty overrides', a.verifier_from_config('gcp-confidential-space', { 'identity_overrides' => {} }), [:built, :GcpConfidentialSpaceVerifier]]
      rows << ['nil overrides', a.verifier_from_config('gcp-confidential-space', { 'identity_overrides' => nil }), [:built, :GcpConfidentialSpaceVerifier]]
    end
    C07.check(rows)
  end

  t('attest.verifier_from_config builds the NVIDIA verifier from root pins, a measurement policy and an optional collateral hook') do
    next true if C07.skip?

    a = C07.att
    b = ->(s) { C07.b64(s) }
    rows = []
    C07.stubbed do |seen|
      nv = lambda do |cfg|
        seen.clear
        r = a.verifier_from_config('nvidia-gpu-spdm', cfg)
        [r, seen[:NvidiaSpdmVerifier].first, seen[:NvidiaCollateralHook]&.first]
      end
      strip = ->(o) { o.reject { |k, _| k == 'resolve_evidence' } }
      r, o, h = nv.call({ 'rootSpkiSha256' => ['ab'] })
      rows << ['base returns', r, [:built, :NvidiaSpdmVerifier]]
      rows << ['base opts', strip.call(o), { 'rootSpkiSha256' => ['ab'], 'policy' => { 'measurements' => {} } }]
      rows << ['base no hook', h, nil]
      rows << ['base resolves', o['resolve_evidence'].call({ 'evidence' => { 'evidence' => b.call('E') } }), { 'evidence' => 'E'.b }]
      rows << ['base resolves non-hash', o['resolve_evidence'].call('evidence'), nil]
      [nil, 5, 'measurements leafSubjectIncludes', [], false].each do |pol|
        _, o, = nv.call({ 'rootSpkiSha256' => ['ab'], 'policy' => pol })
        rows << ["policy #{pol.inspect}", strip.call(o)['policy'], { 'measurements' => {} }]
      end
      _, o, = nv.call({ 'rootSpkiSha256' => ['ab'], 'policy' => { 'measurements' => { '0' => 'ab' }, 'leafSubjectIncludes' => 'GPU' } })
      rows << ['policy full', strip.call(o)['policy'], { 'measurements' => { '0' => 'ab' }, 'leafSubjectIncludes' => 'GPU' }]
      _, o, = nv.call({ 'rootSpkiSha256' => ['ab'], 'policy' => { 'measurements' => nil, 'leafSubjectIncludes' => nil } })
      rows << ['policy nils', strip.call(o)['policy'], { 'measurements' => {} }]
      _, o, = nv.call({ 'rootSpkiSha256' => ['ab'], 'policy' => { 'measurements' => {} } })
      rows << ['policy empty measurements', strip.call(o)['policy'], { 'measurements' => {} }]
      [nil, false].each do |col|
        _, o, h = nv.call({ 'rootSpkiSha256' => ['ab'], 'collateral' => col })
        rows << ["collateral #{col.inspect} no hook", [h, o.key?('postVerify')], [nil, false]]
      end
      rows << ['collateral true refused', C07.err { nv.call({ 'rootSpkiSha256' => ['ab'], 'collateral' => true }) },
               [a::AttestConstructError, 'createNvidiaSpdmVerifier: collateral must be an object']]
      _, o, h = nv.call({ 'rootSpkiSha256' => ['ab'], 'collateral' => {} })
      rows << ['collateral empty hash post verify', o['postVerify'], [:built, :NvidiaCollateralHook]]
      rows << ['collateral empty hash opts', h.reject { |k, _| k == 'resolve' }, { 'rimRootSpkiSha256' => nil }]
      lam = h['resolve']
      rows << ['hook resolve nil evidence', lam.call(:ids, nil), nil]
      rows << ['hook resolve empty evidence', lam.call(:ids, {}), nil]
      rows << ['hook resolve evidence', lam.call(:ids, { 'collateral' => :bundle }), :bundle]
      col = { 'rimRootSpkiSha256' => ['r'], 'revocation' => 'ocsp', 'requireCrls' => false, 'requireCrlIssuers' => ['x'],
              'firmware' => { 'minDriverVersion' => '1' }, 'other' => 1 }
      _, o, h = nv.call({ 'rootSpkiSha256' => ['ab'], 'collateral' => col })
      rows << ['collateral hash post verify', o['postVerify'], [:built, :NvidiaCollateralHook]]
      rows << ['collateral hash opts', h.reject { |k, _| k == 'resolve' },
               { 'rimRootSpkiSha256' => ['r'], 'revocation' => 'ocsp', 'requireCrls' => false, 'requireCrlIssuers' => ['x'], 'firmware' => { 'minDriverVersion' => '1' } }]
      _, o, h = nv.call({ 'rootSpkiSha256' => ['ab'], 'collateral' => {} })
      rows << ['collateral empty hash', [o['postVerify'], h.reject { |k, _| k == 'resolve' }], [[:built, :NvidiaCollateralHook], { 'rimRootSpkiSha256' => nil }]]
      rows << ['collateral resolve key', h.key?('resolve'), true]
      _, o, = nv.call({ 'rootSpkiSha256' => ['ab'], 'identity_overrides' => { 'k' => 'v' } })
      rows << ['overrides not in opts', o.key?('identity_overrides'), false]
    end
    C07.check(rows)
  end

  t('attest.run_x509_vector refuses an unknown function with the exact row') do
    next true if C07.skip?

    C07.check([['unknown', C07.att.run_x509_vector('nope', {}), { 'ok' => false, 'error' => 'unknown x509 function nope' }]])
  end

  # ============================================================================================================== common: binding
  t('Common.lp is the u32be length and the UTF-8 bytes, an invalid byte becoming U+FFFD') do
    next true if C07.skip?

    c = C07.cm
    C07.check([['ascii', c.lp('ab'), "\x00\x00\x00\x02ab".b], ['empty', c.lp(''), "\x00\x00\x00\x00".b],
               ['multibyte', c.lp('é'), "\x00\x00\x00\x02\xC3\xA9".b], ['invalid byte', c.lp("\xFF".b), "\x00\x00\x00\x03\xEF\xBF\xBD".b],
               ['invalid inside', c.lp("a\xFFb".b), "\x00\x00\x00\x05a\xEF\xBF\xBDb".b], ['enc multibyte', c.lp('é').encoding, Encoding::BINARY],
               ['enc invalid', c.lp("\xFF".b).encoding, Encoding::BINARY], ['frozen input', c.lp('x'), "\x00\x00\x00\x01x".b]])
  end

  t('Common.expected_parts: a non-object gives four nils, an object gives the snake_case field before the camelCase one') do
    next true if C07.skip?

    c = C07.cm
    C07.check([['nil', c.expected_parts(nil), [nil, nil, nil, nil]], ['int', c.expected_parts(5), [nil, nil, nil, nil]], ['str', c.expected_parts('x'), [nil, nil, nil, nil]],
               ['array', c.expected_parts([1]), [nil, nil, nil, nil]],
               ['snake', c.expected_parts({ 'holder_pub' => 'h', 'grant_ref' => 'g', 'epoch' => 1, 'nonce' => 'n' }), ['h', 'g', 1, 'n']],
               ['camel', c.expected_parts({ 'holderPub' => 'h', 'grantRef' => 'g', 'epoch' => 1, 'nonce' => 'n' }), ['h', 'g', 1, 'n']],
               ['snake wins', c.expected_parts({ 'holder_pub' => 'a', 'holderPub' => 'b', 'grant_ref' => 'c', 'grantRef' => 'd' }), ['a', 'c', nil, nil]],
               ['snake nil wins', c.expected_parts({ 'holder_pub' => nil, 'holderPub' => 'b', 'grant_ref' => nil, 'grantRef' => 'd' }), [nil, nil, nil, nil]],
               ['empty hash', c.expected_parts({}), [nil, nil, nil, nil]]])
  end

  t('Common.safe_nonneg_int is Number.isSafeInteger and >= 0, an integral float becoming an Integer') do
    next true if C07.skip?

    c = C07.cm
    max = 9_007_199_254_740_991
    rows = [[-1, nil], [0, 0], [1, 1], [max, max], [max + 1, nil], [2**64, nil], [true, nil], [false, nil], [nil, nil], ['5', nil], [[], nil],
            [3.0, 3], [0.0, 0], [-0.0, 0], [2.5, nil], [-1.0, nil], [9_007_199_254_740_991.0, max], [9_007_199_254_740_992.0, nil],
            [Float::INFINITY, nil], [-Float::INFINITY, nil], [Float::NAN, nil], [1e300, nil], [1.0, 1]].map { |i, w| ["safe #{i.inspect}", c.safe_nonneg_int(i), w] }
    C07.check(rows)
  end

  t('Common.attestation_binding: the TS hash, and each malformed field refused with its own message in the TS order') do
    next true if C07.skip?

    c = C07.cm
    te = C07.att::JsTypeError
    good = { 'holder_pub' => 'h', 'grant_ref' => 'g', 'epoch' => 0, 'nonce' => 'n' }
    hex = ->(e) { c.attestation_binding(e).unpack1('H*') }
    holder = [te, 'binding: holderPub required']
    rows = [['hash 0', hex.call(good), '3aa0fd6a3f9b14c6568858ba9db5b4e508ed236c9c6b7a381b2321612f08f6b40c5570ca4367bc4d043286bd659b13dcb9a0fea347eeab450ff3cc433d05da2e'],
            ['hash max', hex.call(good.merge('epoch' => 9_007_199_254_740_991)),
             '36468caf5ca3b3cda11f2eb30737ee26f0dfc1338a1e6662c119d1ff49cd6a2ef0f94d3c54f2e9c296368be6eae1c098dc3405461fcac4d30dad0585e06b6746'],
            ['hash utf8', hex.call({ 'holderPub' => 'hé', 'grantRef' => 'g', 'epoch' => 1, 'nonce' => 'n' }),
             'fa83033c97d96062eed8cd12455337cbcedda57be3a868043c438f7520fef8c701da16ee91a7af66791dfdb44f435467d7d37c5ff122907bf13f3c409ef4039b'],
            ['float epoch', hex.call(good.merge('epoch' => 0.0)), hex.call(good)], ['enc', c.attestation_binding(good).encoding, Encoding::BINARY],
            ['challenge', c.attestation_challenge_sha256(good), Digest::SHA256.digest(c.attestation_binding(good))]]
    [nil, 5, 'x', [], { 'grant_ref' => 'g', 'epoch' => 0, 'nonce' => 'n' }].each { |e| rows << ["exp #{e.inspect}", C07.err { c.attestation_binding(e) }, holder] }
    [nil, 5, '', 1.5, [], :x].each { |h| rows << ["holder #{h.inspect}", C07.err { c.attestation_binding(good.merge('holder_pub' => h)) }, holder] }
    [nil, 5, '', 1.5, []].each do |g|
      rows << ["grant #{g.inspect}", C07.err { c.attestation_binding(good.merge('grant_ref' => g)) }, [te, 'binding: grantRef required']]
      rows << ["nonce #{g.inspect}", C07.err { c.attestation_binding(good.merge('nonce' => g)) }, [te, 'binding: nonce required']]
    end
    [-1, 1.5, 2**53, true, false, nil, '1', Float::NAN, Float::INFINITY, 9_007_199_254_740_992.0].each do |ep|
      rows << ["epoch #{ep.inspect}", C07.err { c.attestation_binding(good.merge('epoch' => ep)) }, [te, 'binding: epoch must be a non-negative safe integer']]
    end
    rows << ['order', C07.err { c.attestation_binding({ 'holder_pub' => nil, 'grant_ref' => nil, 'epoch' => -1, 'nonce' => nil }) }, holder]
    rows << ['order grant', C07.err { c.attestation_binding({ 'holder_pub' => 'h', 'grant_ref' => nil, 'epoch' => -1, 'nonce' => nil }) }, [te, 'binding: grantRef required']]
    rows << ['order nonce', C07.err { c.attestation_binding({ 'holder_pub' => 'h', 'grant_ref' => 'g', 'epoch' => -1, 'nonce' => nil }) }, [te, 'binding: nonce required']]
    C07.check(rows)
  end

  # ============================================================================================================== common: JS helpers
  t('Common.num? and int? are Number.isFinite and Number.isInteger over JSON values') do
    next true if C07.skip?

    c = C07.cm
    nums = [[3, true], [-2, true], [0, true], [2**70, true], [1.5, true], [-0.0, true], [Float::NAN, false], [Float::INFINITY, false], [-Float::INFINITY, false],
            ['1', false], [nil, false], [true, false], [false, false], [[], false]]
    ints = [[3, true], [3.0, true], [3.5, false], [-2.0, true], [0, true], [2**70, true], [1e300, true], ['3', false], [nil, false], [true, false], [false, false],
            [Float::NAN, false], [Float::INFINITY, false], [[], false]]
    C07.check(nums.map { |v, w| ["num? #{v.inspect}", c.num?(v), w] } + ints.map { |v, w| ["int? #{v.inspect}", c.int?(v), w] })
  end

  t('Common.js_str is String(v): undefined for nil, JS number formatting for floats (checked against Node)') do
    next true if C07.skip?

    c = C07.cm
    floats = [[5.0, '5'], [-0.0, '0'], [0.0, '0'], [1.5, '1.5'], [-2.5, '-2.5'], [100.0, '100'], [1e20, '100000000000000000000'], [1e21, '1e+21'], [-1e21, '-1e+21'],
              [1.2345678901234568e20, '123456789012345680000'], [123_456.789, '123456.789'], [1e-6, '0.000001'], [1e-7, '1e-7'], [1.5e-7, '1.5e-7'], [0.5, '0.5'],
              [0.30000000000000004, '0.30000000000000004'], [1.5e300, '1.5e+300'], [5e-324, '5e-324'], [1.7976931348623157e308, '1.7976931348623157e+308'],
              [1e16, '10000000000000000'], [123_456_789_012_345_678.0, '123456789012345680'], [0.0001, '0.0001'], [0.00001, '0.00001'], [12_345.5, '12345.5'],
              [12_345.0, '12345'], [0.1, '0.1'], [-1.25e-10, '-1.25e-10'], [9.999999999999999e20, '999999999999999900000'], [1e22, '1e+22'], [2.5e-7, '2.5e-7'],
              [100_000.0, '100000'], [1e15, '1000000000000000'], [-0.000001, '-0.000001'], [Float::NAN, 'NaN'], [Float::INFINITY, 'Infinity'],
              [-Float::INFINITY, '-Infinity']]
    rows = floats.map { |v, w| ["float #{v}", c.js_str(v), w] }
    rows += [[nil, 'undefined'], [true, 'true'], [false, 'false'], [5, '5'], [-7, '-7'], ['s', 's'], [{}, '[object Object]'], [{ 'a' => 1 }, '[object Object]']].map { |v, w| ["js_str #{v.inspect}", c.js_str(v), w] }
    rows << ['js_num_str', c.js_num_str(1e21), '1e+21']
    C07.check(rows)
  end

  t('Common.node_b64decode is Buffer.from(s, "base64"): both alphabets, illegal characters skipped, stops at "=", partial groups kept (Node)') do
    next true if C07.skip?

    c = C07.cm
    cases = { 'AQID' => '010203', 'A' => '', 'AAAAA' => '000000', 'AA' => '00', 'AAA' => '0000', 'AAAAAAAAA' => '000000000000', "AQ ID\n" => '010203',
              'AQ!ID' => '010203', '-_-_' => 'fbffbf', '' => '', '=AQID' => '', 'AQID=AQID' => '010203', 'AQI=' => '0102', 'AQIDBA' => '01020304', 'AQIDB' => '010203',
              "AQ\u00e9ID" => '010203', 'QUJD' => '414243', '_-8=' => 'ffef', 'Zm9vYg' => '666f6f62', 'Zm9v Ym Fy' => '666f6f626172', '+/+/' => 'fbffbf',
              'A=B' => '', 'AQ=ID' => '01', '~~AQID~~' => '010203' }
    rows = cases.map { |s, h| ["b64 #{s.inspect}", c.node_b64decode(s).unpack1('H*'), h] }
    rows << ['binary input', c.node_b64decode("AQ\xFFID".b).unpack1('H*'), '010203']
    rows << ['encoding', c.node_b64decode('AQID').encoding, Encoding::BINARY]
    rows << ['empty encoding', c.node_b64decode('').encoding, Encoding::BINARY]
    refused = Seam.with(Base64, { strict_decode64: ->(*) { raise ArgumentError, 'seam' } }) { c.node_b64decode('AQID') }
    rows << ['decoder refusal is empty', refused, ''.b]
    rows << ['decoder refusal enc', refused.encoding, Encoding::BINARY]
    C07.check(rows)
  end

  t('Common.js_trim strips exactly the ECMAScript whitespace, from both ends, on any input encoding; it terminates') do
    next true if C07.skip?

    c = C07.cm
    ws = [0x9, 0xa, 0xb, 0xc, 0xd, 0x20, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029,
          0x202f, 0x205f, 0x3000, 0xfeff].map { |cp| [cp].pack('U') }
    not_ws = [0x85, 0x180e, 0x200b, 0x2060, 0x1c, 0x0].map { |cp| [cp].pack('U') }
    rows = ws.map { |w| ["ws U+#{w.ord.to_s(16)}", C07.tm { c.js_trim("#{w}x y#{w}") }, 'x y'] }
    rows += not_ws.map { |w| ["not ws U+#{w.ord.to_s(16)}", C07.tm { c.js_trim("#{w}x#{w}") }, "#{w}x#{w}"] }
    rows << ['all ws', C07.tm { c.js_trim(ws.join) }, '']
    rows << ['empty', C07.tm { c.js_trim('') }, '']
    rows << ['leading only', C07.tm { c.js_trim('  ab') }, 'ab']
    rows << ['trailing only', C07.tm { c.js_trim("ab \t") }, 'ab']
    rows << ['inner kept', C07.tm { c.js_trim(" a \t b ") }, "a \t b"]
    rows << ['binary input', C07.tm { c.js_trim("\u00a0abc\u3000".b) }, 'abc']
    rows << ['binary input enc', C07.tm { c.js_trim("\u00a0abc".b) }.encoding, Encoding::UTF_8]
    rows << ['frozen input', C07.tm { c.js_trim('  z  ') }, 'z']
    C07.check(rows)
  end

  t('Common.js_number is Number(string): JS forms, NaN for the rest, every result a Float (checked against Node)') do
    next true if C07.skip?

    c = C07.cm
    nan = Float::NAN
    inf = Float::INFINITY
    cases = [['', 0.0], ['  ', 0.0], ['0x10', 16.0], ['0X1f', 31.0], ['0o17', 15.0], ['0O7', 7.0], ['0b101', 5.0], ['0B11', 3.0], ['0xFF', 255.0], ['0x', nan], ['0b2', nan],
             ['0o8', nan], ['+0x1', nan], ['-0x1', nan], ['1e3', 1000.0], ['.5', 0.5], ['-.5', -0.5], ['+.5', 0.5], ['5.', 5.0], ['1.e3', 1000.0], ['+5', 5.0], ['-5', -5.0],
             ['1_0', nan], ['Infinity', inf], ['-Infinity', -inf], ['+Infinity', inf], ['infinity', nan], [' 12 ', 12.0], ['1e999', inf], ['-1e999', -inf], ['1e-999', 0.0],
             ['abc', nan], ['1 2', nan], ['0x20000000000001', 9_007_199_254_740_992.0], ["0x#{'f' * 300}", inf], ["0b#{'1' * 1100}", inf], ['007', 7.0], ['1.5e3', 1500.0],
             ['1E3', 1000.0], ['5e', nan], ['.e3', nan], ['-', nan], ['+', nan], ['0.0', 0.0], ['-0', -0.0], ['00x1', nan], ['0x1g', nan], ['1.2.3', nan],
             ["\u00a07\u3000", 7.0], ['0x1F5', 501.0], ['0b0', 0.0], ['0o0', 0.0], ['1e+3', 1000.0], ['1e-3', 0.001], ['5.e-1', 0.5]]
    rows = cases.map { |s, w| ["number #{s[0, 12].inspect}", c.js_number(s), w] }
    seam = lambda do |klass|
      C07.cm.then do |cm|
        Seam.with(cm, { Float: ->(*) { raise klass, 'seam' } }) { cm.js_number('5') }
      ensure
        # Seam restores by defining the Kernel method on the module; drop that copy so nothing leaks between tests
        cm.singleton_class.send(:remove_method, :Float) if cm.singleton_class.instance_methods(false).include?(:Float)
      end
    end
    rows << ['argument error is NaN', seam.call(ArgumentError), nan]
    rows << ['float domain error is NaN', seam.call(FloatDomainError), nan]
    C07.check(rows)
  end

  t('Common.big_int is BigInt(v): booleans, integers, integral floats, trimmed strings and the JS error text (checked against Node)') do
    next true if C07.skip?

    c = C07.cm
    je = C07.att::JsError
    cv = ->(s) { [je, "Cannot convert #{s} to a BigInt"] }
    ni = ->(s) { [je, "The number #{s} cannot be converted to a BigInt because it is not an integer"] }
    rows = [[true, 1], [false, 0], [5, 5], [-3, -3], [2**70, 2**70], [5.0, 5], [-0.0, 0], [1e20, 100_000_000_000_000_000_000], ['12', 12], ['  12 ', 12], ['', 0],
            ['   ', 0], ['+5', 5], ['-5', -5], ['007', 7], ['0x1F', 31], ['0o17', 15], ['0b101', 5], ["\u00a0 9\t", 9]].map { |v, w| ["big #{v.inspect}", c.big_int(v), w] }
    rows << ['nil', C07.err { c.big_int(nil) }, [je, 'Cannot convert null to a BigInt']]
    rows << ['float', C07.err { c.big_int(5.5) }, ni.call('5.5')]
    rows << ['nan', C07.err { c.big_int(Float::NAN) }, ni.call('NaN')]
    rows << ['inf', C07.err { c.big_int(Float::INFINITY) }, ni.call('Infinity')]
    rows << ['-inf', C07.err { c.big_int(-Float::INFINITY) }, ni.call('-Infinity')]
    ['1.5', 'abc', '-0x1', '0x', '1e3', ' 1.5 ', "\u0663", '0xg', '00x1', '1 2', '0b2', '0o8'].each { |s| rows << ["str #{s.inspect}", C07.err { c.big_int(s) }, cv.call(s)] }
    rows << ['hash', C07.err { c.big_int({}) }, cv.call('[object Object]')]
    C07.check(rows)
  end

  # ============================================================================================================== common: JSON
  t('Common.v8_json_message is the V8 11 wording: end of input, special values, string / number, and the token with its context window') do
    next true if C07.skip?

    c = C07.cm
    rows = [
      ["", 0, "Unexpected end of JSON input"],
      ["x", 1, "Unexpected end of JSON input"],
      ["abc", 3, "Unexpected end of JSON input"],
      ["abc", 4, "Unexpected end of JSON input"],
      ["NaN", 0, "\"NaN\" is not valid JSON"],
      ["NaN", 2, "\"NaN\" is not valid JSON"],
      ["undefined", 3, "\"undefined\" is not valid JSON"],
      ["[object Object]", 1, "\"[object Object]\" is not valid JSON"],
      ["Infinity", 0, "\"Infinity\" is not valid JSON"],
      ["[1 \"x\"]", 3, "Unexpected string in JSON at position 3"],
      ["{\"a\" 1}", 5, "Unexpected number in JSON at position 5"],
      ["-", 0, "Unexpected number in JSON at position 0"],
      ["9", 0, "Unexpected number in JSON at position 0"],
      ["a", 0, "Unexpected token 'a', \"a\" is not valid JSON"],
      ["xaaaaaaaaaa", 0, "Unexpected token 'x', \"xaaaaaaaaaa\" is not valid JSON"],
      ["xaaaaaaaaaaa", 0, "Unexpected token 'x', \"xaaaaaaaaaaa\" is not valid JSON"],
      ["xaaaaaaaaaaaaaa", 0, "Unexpected token 'x', \"xaaaaaaaaaaaaaa\" is not valid JSON"],
      ["xaaaaaaaaaaaaaaaaaa", 0, "Unexpected token 'x', \"xaaaaaaaaaaaaaaaaaa\" is not valid JSON"],
      ["xaaaaaaaaaaaaaaaaaaa", 0, "Unexpected token 'x', \"xaaaaaaaaaaaaaaaaaaa\" is not valid JSON"],
      ["xaaaaaaaaaaaaaaaaaaaa", 0, "Unexpected token 'x', \"xaaaaaaaaa\"... is not valid JSON"],
      ["xaaaaaaaaaaaaaaaaaaaaa", 0, "Unexpected token 'x', \"xaaaaaaaaa\"... is not valid JSON"],
      ["xaaaaaaaaaaaaaaaaaaaaaaaa", 0, "Unexpected token 'x', \"xaaaaaaaaa\"... is not valid JSON"],
      ["xaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0, "Unexpected token 'x', \"xaaaaaaaaa\"... is not valid JSON"],
      ["xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0, "Unexpected token 'x', \"xaaaaaaaaa\"... is not valid JSON"],
      ["xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0, "Unexpected token 'x', \"xaaaaaaaaa\"... is not valid JSON"],
      ["     xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 5, "Unexpected token 'x', \"     xaaaaaaaaa\"... is not valid JSON"],
      ["         xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 9, "Unexpected token 'x', \"         xaaaaaaaaa\"... is not valid JSON"],
      ["          xaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 10, "Unexpected token 'x', ...\"          xaaaaaaaaa\"... is not valid JSON"],
      ["           xaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 11, "Unexpected token 'x', ...\"          xaaaaaaaaa\"... is not valid JSON"],
      ["                            xaaaaaaaaaaa", 28, "Unexpected token 'x', ...\"          xaaaaaaaaa\"... is not valid JSON"],
      ["                             xaaaaaaaaaa", 29, "Unexpected token 'x', ...\"          xaaaaaaaaa\"... is not valid JSON"],
      ["                              xaaaaaaaaa", 30, "Unexpected token 'x', ...\"          xaaaaaaaaa\" is not valid JSON"],
      ["                               xaaaaaaaa", 31, "Unexpected token 'x', ...\"          xaaaaaaaa\" is not valid JSON"],
      ["                                       x", 39, "Unexpected token 'x', ...\"          x\" is not valid JSON"]
    ].map { |text, pos, want| ["v8 #{text[0, 14].inspect} #{pos}", c.v8_json_message(text, pos), want] }
    C07.check(rows)
  end

  t('Common.js_json_loads: valid documents parse (whitespace anywhere, no nesting limit); malformed ones raise the V8 wording; it terminates') do
    next true if C07.skip?

    c = C07.cm
    je = C07.att::JsError
    valid = [[' 1 ', 1], ['[ 1 , 2 ]', [1, 2]], ['[]', []], ['[ ]', []], ['{ }', {}], ['{}', {}], ['{ "a" : 1 , "b" : [ true , null , false ] }', { 'a' => 1, 'b' => [true, nil, false] }],
             ['"x"', 'x'], ['-1.5e3', -1500.0], ['[1,"a\\n\\u0041\\"b"]', [1, "a\nA\"b"]], ["\t\r\n[\t1\r\n]\n", [1]], ['null', nil], ['true', true], ['false', false],
             ['0', 0], ['{"a":{"b":[]}}', { 'a' => { 'b' => [] } }], ['{"a":1,"b":2}', { 'a' => 1, 'b' => 2 }], ['[[1],[2]]', [[1], [2]]], ['{ "a":1}', { 'a' => 1 }],
             ['{"a" :1}', { 'a' => 1 }], ['{"a": 1}', { 'a' => 1 }], ['{"a":1 }', { 'a' => 1 }], ['{"a":1, "b":2}', { 'a' => 1, 'b' => 2 }], ['[1 ]', [1]], ['[ 1]', [1]],
             ['[1, 2]', [1, 2]], ['"a\\/b\\\\c\\b\\f\\n\\r\\t"', "a/b\\c\b\f\n\r\t"], ['"\\u00e9"', 'é'], ['{"":""}', { '' => '' }], ['0.5', 0.5], ['1E2', 100.0],
             ['1e+3', 1000.0], ['1.5E-2', 0.015], ['"a b"', 'a b'], ['"\\u00aE"', "\u00ae"], ['"\\uABCD"', "\uabcd"], ['{"a":-1}', { 'a' => -1 }], ['[0.5,10]', [0.5, 10]]]
    rows = valid.map { |t, w| ["parse #{t[0, 20].inspect}", C07.tm { c.js_json_loads(t) }, w] }
    deep = C07.tm { c.js_json_loads(('[' * 150) + (']' * 150)) }
    depth = 0
    while deep.is_a?(Array) && !deep.empty?
      deep = deep[0]
      depth += 1
    end
    rows << ['deep 150', depth, 149]
    [
      ["", "Unexpected end of JSON input"],
      ["   ", "Unexpected end of JSON input"],
      ["[", "Unexpected end of JSON input"],
      ["{", "Unexpected end of JSON input"],
      ["{x", "Unexpected token 'x', \"{x\" is not valid JSON"],
      ["{\"a\"", "Unexpected end of JSON input"],
      ["{\"a\":", "Unexpected end of JSON input"],
      ["{\"a\":1", "Unexpected end of JSON input"],
      ["[1,", "Unexpected end of JSON input"],
      ["[1 2]", "Unexpected number in JSON at position 3"],
      ["tru", "Unexpected end of JSON input"],
      ["nulx", "Unexpected token 'x', \"nulx\" is not valid JSON"],
      ["true x", "Unexpected non-whitespace character after JSON at position 5"],
      ["1 2", "Unexpected non-whitespace character after JSON at position 2"],
      ["\"abc", "Unexpected end of JSON input"],
      ["\"a\\q\"", "Unexpected token 'q', \"\"a\\q\"\" is not valid JSON"],
      ["\"a\\u12\"", "Unexpected token '\\', \"\"a\\u12\"\" is not valid JSON"],
      ["\"a\nb\"", "Unexpected token '\n', \"\"a\nb\"\" is not valid JSON"],
      ["01", "Unexpected non-whitespace character after JSON at position 1"],
      ["-", "Unexpected end of JSON input"],
      ["-x", "Unexpected token 'x', \"-x\" is not valid JSON"],
      ["x", "Unexpected token 'x', \"x\" is not valid JSON"],
      ["+1", "Unexpected token '+', \"+1\" is not valid JSON"],
      ["abcdefghijklmnopqrstuvwxyz", "Unexpected token 'a', \"abcdefghij\"... is not valid JSON"],
      ["{\"a\":1,}", "Unexpected token '}', \"{\"a\":1,}\" is not valid JSON"],
      ["[1,]", "Unexpected token ']', \"[1,]\" is not valid JSON"],
      ["{\"abcdefghijklmnopq\":x}", "Unexpected token 'x', ...\"jklmnopq\":x}\" is not valid JSON"],
      ["  x", "Unexpected token 'x', \"  x\" is not valid JSON"],
      ["{1:2}", "Unexpected number in JSON at position 1"],
      ["{\"a\" 1}", "Unexpected number in JSON at position 5"],
      ["NaN", "\"NaN\" is not valid JSON"],
      ["Infinity", "\"Infinity\" is not valid JSON"],
      ["undefined", "\"undefined\" is not valid JSON"],
      ["[object Object]", "\"[object Object]\" is not valid JSON"],
      ["{\"a\":1} x", "Unexpected non-whitespace character after JSON at position 8"],
      ["[\"a\" \"b\"]", "Unexpected string in JSON at position 5"],
      ["{\"a\":1 \"b\":2}", "Unexpected string in JSON at position 7"],
      ["[,1]", "Unexpected token ',', \"[,1]\" is not valid JSON"],
      ["{\"a\":1,\"b\"}", "Unexpected token '}', \"{\"a\":1,\"b\"}\" is not valid JSON"],
      ["[1] x", "Unexpected non-whitespace character after JSON at position 4"],
      ["\"\\u00zz\"", "Unexpected token '\\', \"\"\\u00zz\"\" is not valid JSON"],
      ["[1,2", "Unexpected end of JSON input"],
      ["{\"a\":[1,2}", "Unexpected token '}', \"{\"a\":[1,2}\" is not valid JSON"],
      ["[[1],", "Unexpected end of JSON input"],
      ["{\"a\":{\"b\":}", "Unexpected token '}', \"{\"a\":{\"b\":}\" is not valid JSON"],
      ["truex", "Unexpected non-whitespace character after JSON at position 4"],
      ["nul", "Unexpected end of JSON input"],
      [".5", "Unexpected token '.', \".5\" is not valid JSON"],
      ["1.", "Unexpected non-whitespace character after JSON at position 1"],
      ["1e", "Unexpected non-whitespace character after JSON at position 1"],
      ["\t\n x", "Unexpected token 'x', \"\t\n x\" is not valid JSON"],
      ["[1,\n2,\n3,\nx]", "Unexpected token 'x', \"[1,\n2,\n3,\nx]\" is not valid JSON"],
      ["\"abc\" \"def\"", "Unexpected non-whitespace character after JSON at position 6"],
      ["falsx", "Unexpected token 'x', \"falsx\" is not valid JSON"],
      ["nu", "Unexpected end of JSON input"],
      ["[tru]", "Unexpected token ']', \"[tru]\" is not valid JSON"],
      ["{\"a\":tru}", "Unexpected token '}', \"{\"a\":tru}\" is not valid JSON"],
      ["\"\\", "Unexpected end of JSON input"],
      ["\"\\u", "Unexpected token '\\', \"\"\\u\" is not valid JSON"],
      ["\"\\u004", "Unexpected token '\\', \"\"\\u004\" is not valid JSON"],
      ["[ \"a\" , \"b\" ] z", "Unexpected non-whitespace character after JSON at position 14"],
      ["{\"k\":\"v\"}}", "Unexpected non-whitespace character after JSON at position 9"],
      ["  [  1  ,  x  ]", "Unexpected token 'x', \"  [  1  ,  x  ]\" is not valid JSON"],
      ["-0x", "Unexpected non-whitespace character after JSON at position 2"],
      ["\"\u001f\"", "Unexpected token '\u001f', \"\"\u001f\"\" is not valid JSON"],
      ["[1e]", "Unexpected token 'e', \"[1e]\" is not valid JSON"],
      ["[-]", "Unexpected token ']', \"[-]\" is not valid JSON"],
      ["{\"a\":-}", "Unexpected token '}', \"{\"a\":-}\" is not valid JSON"],
      ["nx", "Unexpected token 'x', \"nx\" is not valid JSON"],
      ["{\"a\":}", "Unexpected token '}', \"{\"a\":}\" is not valid JSON"],
      ["[1,2,3,4,5,6,7,8,9,10,11,x]", "Unexpected token 'x', ...\"8,9,10,11,x]\" is not valid JSON"]
    ].each { |t, w| rows << ["error #{t[0, 20].inspect}", C07.parse_err(t), [je, w]] }
    C07.check(rows)
  end

  t('Common::JsonProbe: check answers true / false with the first error position and whether it is trailing text') do
    next true if C07.skip?

    pr = C07.cm::JsonProbe
    rows = []
    ok = pr.new('[1, {"a": "b"}]')
    rows << ['valid', ok.check, true]
    rows << ['valid pos', ok.pos, nil]
    rows << ['valid extra', ok.extra, false]
    bad = pr.new('[1,]')
    rows << ['bad', [bad.check, bad.pos, bad.extra], [false, 3, false]]
    trail = pr.new('1 2')
    rows << ['trailing', [trail.check, trail.pos, trail.extra], [false, 2, true]]
    minus = pr.new('-x')
    rows << ['minus', [minus.check, minus.pos], [false, 1]]
    plain = pr.new('x')
    rows << ['plain', [plain.check, plain.pos], [false, 0]]
    esc = pr.new('"a\\q"')
    rows << ['bad escape', [esc.check, esc.pos], [false, 3]]
    uni = pr.new('"a\\u12"')
    rows << ['bad unicode', [uni.check, uni.pos], [false, 2]]
    ctl = pr.new("\"a\u0001\"")
    rows << ['control char', [ctl.check, ctl.pos], [false, 2]]
    unt = pr.new('"abc')
    rows << ['unterminated', [unt.check, unt.pos], [false, 4]]
    C07.check(rows)
  end

  t('Common.js_json_loads parses with the H4 depth cap (max_nesting 512) and turns a parser fault into a JsError carrying its message (seam)') do
    next true if C07.skip?

    c = C07.cm
    seen = []
    got = Seam.with(JSON, { parse: ->(src, **o) { seen << [src, o]; [:ok] } }) { c.js_json_loads('[1]') }
    perr = Seam.with(JSON, { parse: ->(*, **) { raise JSON::ParserError, 'boom' } }) { C07.err { c.js_json_loads('[1]') } }
    nerr = Seam.with(JSON, { parse: ->(*, **) { raise JSON::NestingError, 'deep' } }) { C07.err { c.js_json_loads('[1]') } }
    C07.check([['result', got, [:ok]], ['args', seen, [['[1]', { allow_nan: false, max_nesting: 512 }]]], ['parser error', perr, [C07.att::JsError, 'boom']], ['nesting error', nerr, [C07.att::JsError, 'deep']]])
  end

  # ============================================================================================================== common: PEM, hex, OpenSSL glue
  t('Common.pem_to_der decodes the first certificate block, ignoring whitespace, and refuses a missing or empty one') do
    next true if C07.skip?

    c = C07.cm
    pem = ->(body) { "junk\n-----BEGIN CERTIFICATE-----#{body}-----END CERTIFICATE-----\n" }
    ae = ArgumentError
    C07.check([['plain', c.pem_to_der(pem.call("\nAQID\n")), "\x01\x02\x03".b], ['inner whitespace', c.pem_to_der(pem.call("\nAQ\r\n ID\n")), "\x01\x02\x03".b],
               ['first block', c.pem_to_der("#{pem.call('AQID')}#{pem.call('BAUG')}"), "\x01\x02\x03".b],
               ['whitespace body', c.pem_to_der(pem.call("\n")), ''.b],
               ['none', C07.err { c.pem_to_der('no pem here') }, [ae, 'pemToDer: no certificate found']],
               ['empty body', C07.err { c.pem_to_der(pem.call('')) }, [ae, 'pemToDer: no certificate found']],
               ['blocks', c.pem_blocks("#{pem.call('AQID')}#{pem.call('BAUG')}"), ["-----BEGIN CERTIFICATE-----AQID-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----BAUG-----END CERTIFICATE-----"]]])
  end

  t('Common.hex? is even-length hex digits only; decode_claim_bytes tries hex (0x prefix allowed) before base64') do
    next true if C07.skip?

    c = C07.cm
    C07.check([['hex ok', c.hex?('0aFf'), true], ['odd', c.hex?('0af'), false], ['empty', c.hex?(''), false], ['non hex', c.hex?('zz'), false], ['space', c.hex?('0a '), false],
               ['0x', c.decode_claim_bytes('0xAbCd'), "\xAB\xCD".b], ['0X', c.decode_claim_bytes('0XAbCd'), "\xAB\xCD".b], ['hex', c.decode_claim_bytes('abcd'), "\xAB\xCD".b],
               ['b64', c.decode_claim_bytes('QUJD'), 'ABC'.b], ['trimmed', c.decode_claim_bytes(" \u00a0QUJD\t"), 'ABC'.b], ['nothing', c.decode_claim_bytes(''), nil],
               ['junk', c.decode_claim_bytes('!!!'), nil]])
  end

  t('Common.hash_alg maps each name to its digest and refuses the rest') do
    next true if C07.skip?

    c = C07.cm
    want = { 'sha1' => 'a9993e364706816aba3e25717850c26c9cd0d89d', 'sha224' => '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7',
             'sha256' => 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
             'sha384' => 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
             'sha512' => 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f' }
    rows = want.map { |n, h| ["digest #{n}", c.hash_alg(n).hexdigest('abc'), h] }
    rows << ['unknown', C07.err { c.hash_alg('md5') }&.first, KeyError]
    rows << ['upper case', C07.err { c.hash_alg('SHA256') }&.first, KeyError]
    C07.check(rows)
  end

  t('Common.load_public_key reads an SPKI and nothing else (no PEM, no private key, no other structure)') do
    next true if C07.skip?

    c = C07.cm
    ec = c.load_public_key(C07::EC256.public_to_der)
    rsa = c.load_public_key(C07::RSAK.public_to_der)
    ed = c.load_public_key(C07::ED.public_to_der)
    odd = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(5)]), OpenSSL::ASN1::BitString("\x00".b)]).to_der
    C07.check([['ec', [ec.class, ec.public_to_der], [OpenSSL::PKey::EC, C07::EC256.public_to_der]], ['rsa', [rsa.class, rsa.public_to_der], [OpenSSL::PKey::RSA, C07::RSAK.public_to_der]],
               ['ed25519', ed.public_to_der, C07::ED.public_to_der],
               ['not an spki', C07.err { c.load_public_key(odd) }&.first, NoMethodError], ['nil', C07.err { c.load_public_key(nil) }&.first, NoMethodError],
               ['private key der', C07.err { c.load_public_key(C07::EC256.private_to_der) } ? true : false, true],
               ['pem', C07.err { c.load_public_key(C07::EC256.public_to_pem) } ? true : false, true],
               ['garbage', C07.err { c.load_public_key("\x01\x02".b) } ? true : false, true]])
  end

  t('Common.key_type / node_curve / jwk_curve / spki_of / spki_sha / ec_point name keys the way Node does') do
    next true if C07.skip?

    c = C07.cm
    k = lambda do |key|
      c.load_public_key(key.public_to_der)
    end
    e256 = k.call(C07::EC256)
    e384 = k.call(C07::EC384)
    e521 = k.call(C07::EC521)
    k1 = k.call(C07::ECK1)
    rsa = k.call(C07::RSAK)
    ed = k.call(C07::ED)
    te = C07.att::JsTypeError
    pt = e256.public_key.to_octet_string(:uncompressed)
    C07.check([['type ec', c.key_type(e256), 'ec'], ['type rsa', c.key_type(rsa), 'rsa'], ['type ed25519', c.key_type(ed), 'ed25519'],
               ['curve p256', c.node_curve(e256), 'prime256v1'], ['curve p384', c.node_curve(e384), 'secp384r1'], ['curve p521', c.node_curve(e521), 'secp521r1'],
               ['curve rsa', c.node_curve(rsa), nil], ['curve ed', c.node_curve(ed), nil], ['curve k1', c.node_curve(k1), 'secp256k1'],
               ['jwk p256', c.jwk_curve(e256), 'P-256'], ['jwk p384', c.jwk_curve(e384), 'P-384'], ['jwk p521', c.jwk_curve(e521), 'P-521'], ['jwk k1', c.jwk_curve(k1), 'secp256k1'],
               ['jwk rsa', c.jwk_curve(rsa), nil], ['jwk ed', c.jwk_curve(ed), nil],
               ['spki_of', c.spki_of(e256), C07::EC256.public_to_der],
               ['sha256', c.spki_sha(e256, 'sha256'), Digest::SHA256.hexdigest(C07::EC256.public_to_der)], ['sha384', c.spki_sha(e384, 'sha384'), Digest::SHA384.hexdigest(C07::EC384.public_to_der)],
               ['sha1', c.spki_sha(rsa, 'sha1'), Digest::SHA1.hexdigest(C07::RSAK.public_to_der)],
               ['ec point', c.ec_point(e256, 'P-256'), pt], ['ec point size', pt.bytesize, 65],
               ['point rsa', C07.err { c.ec_point(rsa, 'P-256') }, [te, 'public key is not EC (got rsa)']],
               ['point ed', C07.err { c.ec_point(ed, 'P-256') }, [te, 'public key is not EC (got ed25519)']],
               ['point curve', C07.err { c.ec_point(e384, 'P-256') }, [te, 'public key is not on P-256 (got P-384)']],
               ['point k1', C07.err { c.ec_point(k1, 'P-256') }, [te, 'public key is not on P-256 (got secp256k1)']]])
  end

  t('Common.ec_key_from_point loads a point of the named curve and refuses the rest with an ArgumentError') do
    next true if C07.skip?

    c = C07.cm
    p256 = C07::EC256.public_key.to_octet_string(:uncompressed)
    p384 = C07::EC384.public_key.to_octet_string(:uncompressed)
    off = "\x04".b + ("\xFF".b * 64)
    # a Point.new that accepts any octets, to reach the on-curve guard behind the library's own decoding
    fake = Class.new { def on_curve? = false }.new
    guard = begin
      OpenSSL::PKey::EC::Point.define_singleton_method(:new) { |*| fake }
      C07.err { c.ec_key_from_point('P-256', p256) }
    ensure
      OpenSSL::PKey::EC::Point.singleton_class.send(:remove_method, :new)
    end
    seen = []
    orig = OpenSSL::PKey::EC::Point.method(:new)
    begin
      OpenSSL::PKey::EC::Point.define_singleton_method(:new) { |*a| seen << a[1]; orig.call(*a) }
      c.ec_key_from_point('P-256', p256)
    ensure
      OpenSSL::PKey::EC::Point.singleton_class.send(:remove_method, :new)
    end
    pt_err = begin
      OpenSSL::PKey::EC::Point.define_singleton_method(:new) { |*| raise OpenSSL::PKey::EC::Point::Error, 'seam point' }
      C07.err { c.ec_key_from_point('P-256', p256) }
    ensure
      OpenSSL::PKey::EC::Point.singleton_class.send(:remove_method, :new)
    end
    C07.check([['point arg is a BN of the octets', [seen.map(&:class), seen.map { |x| x.to_s(2) }], [[OpenSSL::BN], [p256]]], ['point error', pt_err, [ArgumentError, 'seam point']],
               ['nil point', C07.err { c.ec_key_from_point('P-256', nil) }&.first, NoMethodError],
               ['p256', c.ec_key_from_point('P-256', p256).public_to_der, C07::EC256.public_to_der], ['p384', c.ec_key_from_point('P-384', p384).public_to_der, C07::EC384.public_to_der],
               ['off curve', C07.err { c.ec_key_from_point('P-256', off) }&.first, ArgumentError],
               ['wrong curve', C07.err { c.ec_key_from_point('P-384', p256) }&.first, ArgumentError],
               ['unknown curve', C07.err { c.ec_key_from_point('P-521', p256) }&.first, KeyError], ['guard', guard, [ArgumentError, 'point is not on the curve']]])
  end

  t('Common.ecdsa_verify_der / rsa_pkcs1_verify answer exactly true or false: right key type, right digest, any fault is false') do
    next true if C07.skip?

    c = C07.cm
    ec = C07.pub(C07::EC256)
    rsa = C07.pub(C07::RSAK)
    ed = C07.pub(C07::ED)
    data = 'signed data'
    esig = C07::EC256.sign(OpenSSL::Digest.new('SHA256'), data)
    rsig = C07::RSAK.sign(OpenSSL::Digest.new('SHA256'), data)
    faults = [OpenSSL::OpenSSLError, ArgumentError, TypeError].flat_map do |k|
      [Seam.with(c, { hash_alg: ->(*) { raise k, 'seam' } }) { c.ecdsa_verify_der(ec, esig, data, 'sha256') },
       Seam.with(c, { hash_alg: ->(*) { raise k, 'seam' } }) { c.rsa_pkcs1_verify(rsa, rsig, data, 'sha256') }]
    end
    C07.check([['faults are false', faults, [false] * 6], ['ec nil sig is a NoMethodError', C07.err { c.ecdsa_verify_der(ec, nil, data, 'sha256') }&.first, NoMethodError],
               ['ec nil data is a NoMethodError', C07.err { c.ecdsa_verify_der(ec, esig, nil, 'sha256') }&.first, NoMethodError],
               ['rsa nil sig is a NoMethodError', C07.err { c.rsa_pkcs1_verify(rsa, nil, data, 'sha256') }&.first, NoMethodError],
               ['rsa nil data is a NoMethodError', C07.err { c.rsa_pkcs1_verify(rsa, rsig, nil, 'sha256') }&.first, NoMethodError],
               ['ec ok', c.ecdsa_verify_der(ec, esig, data, 'sha256'), true], ['ec bad data', c.ecdsa_verify_der(ec, esig, 'other', 'sha256'), false],
               ['ec wrong digest', c.ecdsa_verify_der(ec, esig, data, 'sha384'), false], ['ec garbage sig', c.ecdsa_verify_der(ec, "\x01\x02".b, data, 'sha256'), false],
               ['ec given rsa key and valid rsa sig', c.ecdsa_verify_der(rsa, rsig, data, 'sha256'), false], ['ec given ed key', c.ecdsa_verify_der(ed, esig, data, 'sha256'), false],
               ['rsa ok', c.rsa_pkcs1_verify(rsa, rsig, data, 'sha256'), true], ['rsa bad data', c.rsa_pkcs1_verify(rsa, rsig, 'other', 'sha256'), false],
               ['rsa garbage sig', c.rsa_pkcs1_verify(rsa, "\x01".b, data, 'sha256'), false],
               ['rsa given ec key and valid ec sig', c.rsa_pkcs1_verify(ec, esig, data, 'sha256'), false], ['rsa given ed key', c.rsa_pkcs1_verify(ed, rsig, data, 'sha256'), false]])
  end

  t('Common.ecdsa_verify_raw: r||s of exactly 2*ceil(bits/8) bytes, both non-zero, over an EC key; P-521 included') do
    next true if C07.skip?

    c = C07.cm
    data = 'raw signed data'
    p256 = C07.pub(C07::EC256)
    p521 = C07.pub(C07::EC521)
    rsa = C07.pub(C07::RSAK)
    r256 = C07.raw_sig(C07::EC256, data, 'SHA256', 32)
    r521 = C07.raw_sig(C07::EC521, data, 'SHA512', 66)
    rows = [['p256 ok', c.ecdsa_verify_raw(p256, r256, data, 'sha256'), true], ['p521 ok', c.ecdsa_verify_raw(p521, r521, data, 'sha512'), true],
            ['bad data', c.ecdsa_verify_raw(p256, r256, 'other', 'sha256'), false], ['short', c.ecdsa_verify_raw(p256, r256[0, 63], data, 'sha256'), false],
            ['long', c.ecdsa_verify_raw(p256, r256 + "\x00".b, data, 'sha256'), false], ['p521 short', c.ecdsa_verify_raw(p521, r521[0, 131], data, 'sha512'), false],
            ['p521 as p256 length', c.ecdsa_verify_raw(p521, r521[0, 64], data, 'sha512'), false], ['rsa key', c.ecdsa_verify_raw(rsa, r256, data, 'sha256'), false]]
    one = ("\x00".b * 31) + "\x01".b
    two = ("\x00".b * 31) + "\x02".b
    zero = "\x00".b * 32
    calls = []
    spy = ->(*a) { calls << a; true }
    Seam.with(c, { ecdsa_verify_der: spy }) do
      rows << ['r zero', c.ecdsa_verify_raw(p256, zero + two, data, 'sha256'), false]
      rows << ['s zero', c.ecdsa_verify_raw(p256, one + zero, data, 'sha256'), false]
      rows << ['both zero', c.ecdsa_verify_raw(p256, zero + zero, data, 'sha256'), false]
      rows << ['no verify for zero', calls.dup, []]
      rows << ['non zero is delegated', c.ecdsa_verify_raw(p256, one + two, data, 'sha256'), true]
      rows << ['delegated args', calls, [[p256, "\x30\x06\x02\x01\x01\x02\x01\x02".b, data, 'sha256']]]
    end
    C07.check(rows)
  end

  t('Common.result, as_str_list and first_string') do
    next true if C07.skip?

    c = C07.cm
    C07.check([['result ok', c.result(true, a: 1, b: 'x'), { 'ok' => true, 'a' => 1, 'b' => 'x' }], ['result false', c.result(false), { 'ok' => false }],
               ['result reason', c.result(false, reason: 'r'), { 'ok' => false, 'reason' => 'r' }],
               ['list', c.as_str_list(%w[a b]), %w[a b]], ['list empty', c.as_str_list([]), []], ['list mixed', c.as_str_list(['a', 1]), nil], ['list nil', c.as_str_list(nil), nil],
               ['list int', c.as_str_list(5), nil], ['list str', c.as_str_list('a'), nil], ['as_str', c.as_str('a'), 'a'], ['as_str int', c.as_str(5), nil],
               ['first', c.first_string({ 'a' => '', 'b' => 'x', 'c' => 'y' }, %w[a b c]), 'x'], ['first skips non string', c.first_string({ 'a' => 5, 'b' => 'y' }, %w[a b]), 'y'],
               ['first none', c.first_string({ 'a' => '' }, %w[a b]), nil], ['first nil value', c.first_string({ 'a' => nil, 'b' => 'z' }, %w[a b]), 'z'],
               ['first order', c.first_string({ 'a' => 'p', 'b' => 'q' }, %w[b a]), 'q']])
  end

  t('Common.parse_jws reads a compact JWS: exact header / payload / signing input / signature, and the reference message for each refusal') do
    next true if C07.skip?

    c = C07.cm
    te = C07.att::JsTypeError
    h = ->(o) { C07.b64u(o.is_a?(String) ? o : JSON.generate(o)) }
    sig = C07.b64u('SIG')
    tok = ->(hd, pl, sg = sig) { "#{hd}.#{pl}.#{sg}" }
    pl = h.call({ 'x' => 1 })
    full = h.call({ 'alg' => 'ES256', 'kid' => 'k1', 'typ' => 'JWT', 'jku' => 'u', 'x5c' => %w[a b], 'other' => 1 })
    min = h.call({ 'alg' => 'ES256' })
    got = c.parse_jws(tok.call(full, pl), 'f')
    f = 'f: '
    jm = "#{f}malformed JSON segment: "
    rows = [['full header', got['header'], { 'alg' => 'ES256', 'kid' => 'k1', 'typ' => 'JWT', 'jku' => 'u', 'x5c' => %w[a b] }], ['payload', got['payload'], { 'x' => 1 }],
            ['signing input', got['signingInput'], "#{full}.#{pl}".b], ['signing input enc', got['signingInput'].encoding, Encoding::BINARY], ['signature', got['signature'], 'SIG'.b],
            ['keys', got.keys.sort, %w[header payload signature signingInput]],
            ['minimal', c.parse_jws(tok.call(min, pl), 'f')['header'], { 'alg' => 'ES256' }],
            ['non string optional', c.parse_jws(tok.call(h.call({ 'alg' => 'A', 'kid' => 5, 'typ' => nil, 'jku' => [], 'x5c' => [1] }), pl), 'f')['header'], { 'alg' => 'A' }],
            ['x5c not list', c.parse_jws(tok.call(h.call({ 'alg' => 'A', 'x5c' => 'a' }), pl), 'f')['header'], { 'alg' => 'A' }],
            ['x5c empty', c.parse_jws(tok.call(h.call({ 'alg' => 'A', 'x5c' => [] }), pl), 'f')['header'], { 'alg' => 'A', 'x5c' => [] }],
            ['invalid utf8 header', c.parse_jws(tok.call(h.call("{\"alg\":\"X\xFFY\"}".b), pl), 'f')['header'], { 'alg' => "X\u{FFFD}Y" }],
            ['invalid utf8 payload', c.parse_jws(tok.call(min, h.call("{\"k\":\"\xFF\"}".b)), 'f')['payload'], { 'k' => "\u{FFFD}" }]]
    [nil, 5, '', [], 12.5].each { |t| rows << ["empty token #{t.inspect}", C07.err { c.parse_jws(t, 'f') }, [te, "#{f}empty token"]] }
    ['a.b', 'a', 'a.b.c.d', 'a.b.c.d.e', 'a.b.c.d.e.f'].each { |t| rows << ["parts #{t}", C07.err { c.parse_jws(t, 'f') }, [te, "#{f}a compact JWS has exactly three dot-separated parts"]] }
    ['.b.c', 'a..c', 'a.b.', '..'].each { |t| rows << ["segment #{t}", C07.err { c.parse_jws(t, 'f') }, [te, "#{f}empty JWS segment"]] }
    rows << ['header not json', C07.err { c.parse_jws(tok.call(h.call('nope'), pl), 'f') }, [te, "#{jm}Unexpected token 'o', \"nope\" is not valid JSON"]]
    rows << ['payload not json', C07.err { c.parse_jws(tok.call(min, h.call('not json')), 'f') }, [te, "#{jm}Unexpected token 'o', \"not json\" is not valid JSON"]]
    rows << ['header bad char', C07.err { c.parse_jws(tok.call('a!b', pl), 'f') }, [te, "#{jm}non-canonical compact JWS: bad-character"]]
    rows << ['header impossible length', C07.err { c.parse_jws(tok.call('A', pl), 'f') }, [te, "#{jm}non-canonical compact JWS: non-canonical-base64url (impossible length)"]]
    rows << ['payload non canonical', C07.err { c.parse_jws(tok.call(min, 'QR'), 'f') }, [te, "#{jm}non-canonical compact JWS: non-canonical-base64url"]]
    rows << ['header array', C07.err { c.parse_jws(tok.call(h.call('[]'), pl), 'f') }, [te, "#{f}header is not a JSON object"]]
    rows << ['payload array', C07.err { c.parse_jws(tok.call(min, h.call('[]')), 'f') }, [te, "#{f}payload is not a JSON object"]]
    rows << ['header string', C07.err { c.parse_jws(tok.call(h.call('"s"'), pl), 'f') }, [te, "#{f}header is not a JSON object"]]
    [{}, { 'alg' => '' }, { 'alg' => 5 }, { 'alg' => nil }].each { |o| rows << ["alg #{o}", C07.err { c.parse_jws(tok.call(h.call(o), pl), 'f') }, [te, "#{f}header has no alg"]] }
    rows << ['sig bad char', C07.err { c.parse_jws(tok.call(min, pl, 'a!'), 'f') }, [te, "#{f}malformed signature segment: non-canonical compact JWS: bad-character"]]
    rows << ['sig impossible length', C07.err { c.parse_jws(tok.call(min, pl, 'A'), 'f') },
             [te, "#{f}malformed signature segment: non-canonical compact JWS: non-canonical-base64url (impossible length)"]]
    rows << ['sig non canonical', C07.err { c.parse_jws(tok.call(min, pl, 'QR'), 'f') }, [te, "#{f}malformed signature segment: non-canonical compact JWS: non-canonical-base64url"]]
    rows << ['json before signature', C07.err { c.parse_jws(tok.call(h.call('nope'), pl, 'a!'), 'f') }, [te, "#{jm}Unexpected token 'o', \"nope\" is not valid JSON"]]
    rows << ['fn in message', C07.err { c.parse_jws('', 'parseX') }, [te, 'parseX: empty token']]
    real = c.method(:decode_canonical_b64url)
    empty_sig = Seam.with(c, { decode_canonical_b64url: ->(seg) { seg == sig ? ''.b : real.call(seg) } }) { C07.err { c.parse_jws(tok.call(min, pl), 'f') } }
    rows << ['empty signature', empty_sig, [te, "#{f}empty signature"]]
    C07.check(rows)
  end

  t('Common.transform_binding hashes the binding as configured, anything else leaves it') do
    next true if C07.skip?

    c = C07.cm
    C07.check([['sha256', c.transform_binding('x', 'sha256'), Digest::SHA256.digest('x')], ['sha512', c.transform_binding('x', 'sha512'), Digest::SHA512.digest('x')],
               ['none', c.transform_binding('x', 'none'), 'x'], ['nil', c.transform_binding('x', nil), 'x']])
  end

  t('CanonicalJwsError messages carry the reason and the optional detail') do
    next true if C07.skip?

    e = C07.att::CanonicalJwsError
    C07.check([['reason', e.new('r').message, 'non-canonical compact JWS: r'], ['detail', e.new('r', 'd').message, 'non-canonical compact JWS: r (d)'],
               ['nil detail', e.new('r', nil).message, 'non-canonical compact JWS: r']])
  end
end
