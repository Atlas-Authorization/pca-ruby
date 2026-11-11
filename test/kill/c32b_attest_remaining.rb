# frozen_string_literal: true

# c32b: mutation-kill tests for the survivors left in lib/atlas_pca/attest.rb and attest/{common,der,cert,ocsp,xml,gcp,azure,amd,intel,nvidia}.rb
# after c07..c13, plus deadline tests (Timeout.timeout, an ordinary StandardError = a kill) for every mutant that loops or allocates without bound.
# Everything resolves AtlasPca at CALL time (the oracle re-evaluates AtlasPca per mutant). Helpers of c07..c13 are reused (all are module functions
# of MutationKill::C07 / C08DerCert / C09 / C10 / C11Intel / C12Ocsp / C13, loaded before this file).
require 'timeout'
require 'openssl'
require 'digest'
require 'atlas_pca/attest'

module MutationKill
  module C32B
    module_function

    # true when the mutated file (MUT_FILE basename) is none of `names`: the test then passes at once
    def skip?(*names)
      f = ENV['MUT_FILE']
      !f.nil? && !f.empty? && !names.include?(f)
    end

    def mutating? = (f = ENV['MUT_FILE']) && !f.empty?
    def tm(secs = 2, &) = Timeout.timeout(secs, &)

    def ck(label, got, want)
      got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    end

    # an exception class whose #message and #to_s differ: `"#{e}"` instead of `"#{e.message}"` is then visible
    def msgc(base, text)
      Class.new(base) do
        define_method(:message) { text }
        define_method(:to_s) { 'TOS' }
      end
    end

    def a = AtlasPca::Attest
    def cm = AtlasPca::Attest::Common
    def rf(reason) = { 'ok' => false, 'reason' => reason }
  end

  # ================================================================================================ attest.rb / common.rb
  t('c32b attest.unb64: a Float is described by its JavaScript string form (2.0 is "2")') do
    next true if C32B.skip?('attest.rb')

    m = begin
      C32B.a.unb64(2.0)
      nil
    rescue C32B.a::JsTypeError => e
      e.message
    end
    C32B.ck('float', m, 'The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received type number (2)')
  end

  t('c32b common: js_trim, the JSON probe (whitespace, strings, literal scan) end at once (deadline) and give the exact values') do
    next true if C32B.skip?('common.rb')

    cm = C32B.cm
    err = lambda do |txt|
      C32B.tm { cm.js_json_loads(txt) }
      nil
    rescue C32B.a::JsError => e
      e.message
    end
    C32B.ck('trim both ends', C32B.tm { cm.js_trim("\t \n a b \r ") }, 'a b') &&
      C32B.ck('trim leading only', C32B.tm { cm.js_trim('  x') }, 'x') && C32B.ck('trim trailing only', C32B.tm { cm.js_trim('x  ') }, 'x') &&
      C32B.ck('trim none', C32B.tm { cm.js_trim('xy') }, 'xy') && C32B.ck('trim all blank', C32B.tm { cm.js_trim(" \n ") }, '') &&
      C32B.ck('parse', C32B.tm { cm.js_json_loads(" [1, \"a\\n\\u00e9\", {\"k\": \"v\"}] ") }, [1, "a\né", { 'k' => 'v' }]) &&
      C32B.ck('parse plain string', C32B.tm { cm.js_json_loads('"abc"') }, 'abc') &&
      C32B.ck('cut literal', err.call('tru'), 'Unexpected end of JSON input') &&
      C32B.ck('wrong literal', err.call('tzzz'), "Unexpected token 'z', \"tzzz\" is not valid JSON")
  end

  # ================================================================================================ der.rb
  t('c32b der: a GeneralSubtree base is never read as an INTEGER; the readers advance (deadline)') do
    next true if C32B.skip?('der.rb')

    k = C08DerCert
    d = k.der
    base = k.tlv(0x86, k.bin(0x80))
    nc = k.raised { d.name_constraints!(k.tlv(0x30, k.tlv(0xA0, k.tlv(0x30, base)))) }
    nc_min = k.raised { d.name_constraints!(k.tlv(0x30, k.tlv(0xA0, k.tlv(0x30, base, k.tlv(0x80, k.bin(0x80)))))) }
    bcx = k.ext('2.5.29.19', k.tlv(0x30, k.tlv(1, k.bin(0xff))))
    info = C32B.tm(1) { d.read_cert_role_info(k.role_cert(bcx)) }
    kids = C32B.tm(0.5) { d.children_of(k.tlv(0x30, k.tlv(4, 'a'), k.tlv(4, 'b')), d.read_tlv(k.tlv(0x30, k.tlv(4, 'a'), k.tlv(4, 'b')), 0)) }
    e1 = k.ext('2.5.29.19', k.tlv(0x30), k.bin(0xff))
    e2 = k.ext('2.5.29.15', k.tlv(3, k.bin(0, 4)))
    parsed = C32B.tm(1) { d.parse_tbs_extensions(k.tlv(0x30, k.tlv(2, k.bin(1)), k.ext_block(e1, e2))) }
    C32B.ck('base is not an integer', nc, nil) && C32B.ck('a bad bound is still refused', nc_min, ['DerError', 'not a positive DER INTEGER']) &&
      C32B.ck('role info', info, { 'hasBasicConstraints' => true, 'ca' => true, 'hasKeyUsage' => false, 'keyCertSign' => false }) &&
      C32B.ck('children_of', kids.map { |t| t.tag }, [4, 4]) && C32B.ck('extensions', parsed.keys, %w[2.5.29.19 2.5.29.15])
  end

  # ================================================================================================ cert.rb
  t('c32b cert: a signature algorithm that is not a SEQUENCE is refused on its own; unknown value tags keep the bytes that follow; readers advance (deadline)') do
    next true if C32B.skip?('cert.rb')

    k = C08DerCert
    c = k.cert
    bad_alg = k.tlv(0x31, k.oid('1.2.840.10045.4.3.3'))
    outer_only = k.raised { c.new(k.mk(alg_outer: bad_alg, alg_inner: k.alg)[:der]) }
    name = k.tlv(0x30, k.tlv(0x31, k.tlv(0x30, k.cn, k.tlv(0x04, 'ab'))), k.tlv(0x31, k.tlv(0x30, k.cn, k.u8('x'))))
    rendered = k.dl { c.render_name(name) }
    tail_ok = k.raised { k.dl { c.new(k.mk(tail: [k.tlv(0xA3, k.tlv(0x30))])[:der]) } }
    pss = k.tlv(0x30, k.oid(k::PSS), k.tlv(0x30, k.tlv(0xA0, k.tlv(0x30, k.oid(k::HASHES['sha256']))),
                                         k.tlv(0xA1, k.tlv(0x30, k.oid('1.2.840.113549.1.1.8'), k.tlv(0x30, k.oid(k::HASHES['sha384'])))),
                                         k.tlv(0xA2, k.tlv(2, k.bin(0x20)))))
    ph = k.dl { c.pss_params(pss, c.alg_parts(pss)[1]) }
    C32B.ck('outer algorithm', outer_only, ['CertError', k::NSL]) && C32B.ck('unknown tag renders the TLV bytes only', rendered, "CN=#04026162\nCN=x") &&
      C32B.ck('tail element', tail_ok, nil) && C32B.ck('pss', ph, ['sha256', 'sha384', 32])
  end

  # ================================================================================================ ocsp.rb
  t('c32b ocsp: spki_key_bits cuts exactly the key bits; time walk, child walk and zero strip end (deadline)') do
    next true if C32B.skip?('ocsp.rb')

    o = C12Ocsp
    spki = o.key(:inter).public_to_der
    want = OpenSSL::ASN1.decode(spki).value[1].value
    gu = o.tlv(0x17, '270115080000Z')
    gg = o.tlv(0x18, '20270115080000Z')
    dd = o.tlv(0x30, gu, gg)
    top = AtlasPca::Attest::Der.tlv_at(dd, 0)
    C32B.ck('bits with trailing bytes', o.oc.spki_key_bits(spki + 'JUNKJUNK'.b), want) && C32B.ck('bits', o.oc.spki_key_bits(spki), want) &&
      C32B.ck('times', C32B.tm(1) { o.oc.all_times_well_formed?(dd, 2, dd.bytesize) }, true) &&
      C32B.ck('children', C32B.tm(1) { o.oc.children(dd, top).map { |c, p| [c.tag, p] } }, [[0x17, 2], [0x18, 17]]) &&
      C32B.ck('strip', [[5], [5, 6], [0, 0, 5], [0, 0]].map { |b| C32B.tm(1) { o.oc.strip_zeros(b.pack('C*')) }.bytes }, [[5], [5, 6], [5], [0]])
  end

  # ================================================================================================ xml.rb
  t('c32b xml: "<" in element text with an entity is kept; the parser and skip_ws advance (deadline)') do
    next true if C32B.skip?('xml.rb')

    x = AtlasPca::Attest::Xml
    doc = C32B.tm(1) { x.parse_xml('<a x="1"> t <b y="2"/> u </a>') }
    r = doc.root
    C32B.ck('lt with entity', C32B.tm(1) { x.unescape('<&amp;', false) }, '<&') && C32B.ck('attr still refuses <', (begin
      x.unescape('<&amp;', true)
    rescue AtlasPca::Attest::XmlError => e
      e.message
    end), "'<' in an attribute value") &&
      C32B.ck('root', [r.qname, r.get_attribute('x'), r.children[0], r.element_children.map(&:qname), r.children[2]], ['a', '1', ' t ', ['b'], ' u ']) &&
      C32B.ck('cdata', C32B.tm(1) { x.parse_xml('<a><![CDATA[q]]></a>').root.text_content }, 'q') &&
      C32B.ck('skip_ws', [C32B.tm(1) { x.skip_ws("  \t a", 0) }, C32B.tm(1) { x.skip_ws('a', 0) }, C32B.tm(1) { x.skip_ws('  ', 0) }], [4, 0, 2])
  end

  # ================================================================================================ gcp.rb
  t('c32b gcp: a failing step reports e.message (not e.to_s) in every reason') do
    next true if C32B.skip?('gcp.rb')

    g = C32B.a::Gcp
    c = C10
    me = C32B.msgc(StandardError, 'MSG')
    mj = C32B.msgc(C32B.a::JsTypeError, 'JM')
    ev = c.ev
    key_from = Seam.with(g, { jwk_key: ->(_j) { raise me } }) { g.key_from_jwk({}) }
    x5c = Seam.with(C32B.cm, { node_b64decode: ->(_s) { raise me } }) { g.verify_jwk_x5c_chain(['AAAA'], {}, c::NOW, 0) }
    parse = Seam.with(C32B.cm, { parse_jws: ->(*_a) { raise mj } }) { c.run(ev) }
    bind = Seam.with(C32B.cm, { attestation_binding: ->(_e) { raise mj } }) { c.run(ev) }
    outer = Seam.with(g, { resolve_trusted_signing_key: ->(*_a) { raise me } }) { c.run(ev) }
    C32B.ck('key_from_jwk', key_from, { 'reason' => 'JWKS key is not a usable public key: MSG' }) &&
      C32B.ck('x5c', x5c, 'malformed x5c certificate at index 0: MSG') &&
      C32B.ck('parse', parse, C32B.rf('Confidential Space token parse failed: JM')) && C32B.ck('binding', bind, C32B.rf('binding not constructible: JM')) &&
      C32B.ck('outer', outer, C32B.rf('gcp-confidential-space verification error (fail closed): MSG'))
  end

  # ================================================================================================ azure.rb
  t('c32b azure verify_x5c_chain: anchors that are not a Hash are no anchors (an Array is never indexed by name)') do
    next true if C32B.skip?('azure.rb')

    r = Seam.with(C09.der, { x509_valid_at?: ->(*_a) { true } }) { C09.az.verify_x5c_chain(C09.x5c(:leaf), [1], 5) }
    C32B.ck('array anchors', r, C32B.rf('no MAA trust anchor configured (fail closed)'))
  end

  # ================================================================================================ amd.rb
  t('c32b amd verify_amd_cert_chain: the VCEK handed to the role check is a binary copy, whatever its encoding tag') do
    next true if C32B.skip?('amd.rb')

    r = C09.row('amd-sev-snp', 'snp-real-positive')
    cx = C09.amd_ctx(r)
    ev = cx[:ev]
    enc = nil
    res = Seam.with(AtlasPca::Attest::Der, { check_chain_roles: ->(ders) { enc = ders.map(&:encoding); 'STOP' } }) do
      C09.amd.verify_amd_cert_chain(ev['vcekDer'].dup.force_encoding('UTF-8'), ev['askArkPem'], cx[:pin], cx[:now])
    end
    C32B.ck('binary vcek', enc.first, Encoding::BINARY) && C32B.ck('result', res, C32B.rf('AMD chain role check failed: STOP'))
  end

  # ================================================================================================ nvidia.rb
  t('c32b nvidia: firmware policy radix is decimal for driver deny lists and reports; the SPDM host block holds a String digest') do
    next true if C32B.skip?('nvidia.rb')

    c = C13
    n = c.nv
    ce = begin
      n.compile_firmware_policy({ 'denyDriverVersions' => ['ab'] })
      nil
    rescue C32B.a::AttestConstructError => e
      e.message
    end
    f = n.compile_firmware_policy({})
    d1 = "\xA1".b * 48
    bind = { 'holder_pub' => 'h', 'grant_ref' => 'g', 'epoch' => 1, 'nonce' => 'n' }
    nonce = C32B.cm.attestation_challenge_sha256(bind)
    t0 = c.tx(blocks: [c.block(1, d1)], opaque: { 3 => "595.71.05\0".b }, rq: 0x11, rs: 0x11, nonce: nonce)
    signed = t0.byteslice(0, t0.bytesize - 96)
    evidence = signed + c.raw_sig(c.key(c::LEAF), signed)
    chain = c.chain3
    doc = { 'evidence' => evidence, 'certChainPem' => c.pem(chain) }
    v = C32B.a::NvidiaSpdmVerifier.new({ 'rootSpkiSha256' => [c.pin(chain[2])], 'policy' => { 'measurements' => { '1' => d1.unpack1('H*') } },
                                         'resolve_evidence' => ->(_d) { doc } })
    res = v.verify('doc', bind, c::NOW)
    dig = res['ok'] ? res['hostAsserted']['gpu_measurements_sha384'] : res
    C32B.ck('deny entry radix', ce, "nvidiaCollateralHook: malformed denyDriverVersions entry 'ab'") &&
      C32B.ck('report driver radix', f.call({ 'driverVersion' => 'ab', 'vbiosVersion' => '1' }), "driver version 'ab' in the GPU report is not parseable") &&
      C32B.ck('digest class', dig.class, String) && C32B.ck('digest', dig, Digest::SHA384.hexdigest(d1))
  end

  t('c32b nvidia: the transcript parser advances over measurement blocks and opaque TLVs (deadline)') do
    next true if C32B.skip?('nvidia.rb')

    c = C13
    d1 = "\xA1".b * 48
    t0 = c.tx(blocks: [c.block(1, d1), c.block(2, d1)], opaque: { 3 => "595.71.05\0".b, 6 => 'v'.b * 8, 17 => ''.b })
    r = C32B.tm(1) { c.parse(t0) }
    C32B.ck('blocks', r['measurements'].map { |m| m['index'] }, [1, 2]) && C32B.ck('opaque', r['opaque'].keys.sort, [3, 6, 17])
  end

  # the requires at the top of cert.rb and nvidia.rb are the only thing that makes each load on its own (a fresh Ruby over the mutated text)
  t('c32b cert.rb requires common and der, nvidia.rb requires intel (amd), ocsp and xml: each loads alone') do
    next true if C32B.skip?('cert.rb', 'nvidia.rb')

    code = ->(name) { "require 'atlas_pca/attest/#{name}'; puts $LOADED_FEATURES.filter_map { |f| f[%r{/lib/(atlas_pca/attest/[a-z]+)\\.rb}, 1] }.sort.inspect" }
    cert_ok = if C32B.mutating? && !C09.header_changed?('atlas_pca/attest/cert.rb', 12)
                true
              else
                out, ok = C09.fresh('atlas_pca/attest/cert.rb', code.call('cert'))
                ok && out == %(["atlas_pca/attest/cert", "atlas_pca/attest/common", "atlas_pca/attest/der"]\n)
              end
    nv_ok = if C32B.mutating? && !C13.header_changed?
              true
            else
              out, ok = C13.fresh(code.call('nvidia'))
              ok && %w[amd cert common der intel nvidia ocsp xml].all? { |n| out.include?("\"atlas_pca/attest/#{n}\"") }
            end
    C32B.ck('cert alone', cert_ok, true) && C32B.ck('nvidia alone', nv_ok, true)
  end

  # ================================================================================================ intel.rb
  module C32BIntel
    module_function

    def c = C11Intel
    def i = C11Intel.i
    def err_arg = C32B.msgc(ArgumentError, 'MSG')
    def err_std = C32B.msgc(StandardError, 'MSG')
  end

  t('c32b intel: every PCK chain refusal reports exactly its reason; the wall clock is read in milliseconds') do
    next true if C32B.skip?('intel.rb')

    c = C11Intel
    i = c.i
    pem = i.parse_dcap_quote(c.real_quote)['pckChainPem']
    now = c.real_now
    leaf_pem, _ca_pem, root_pem = c.parts(pem)
    cert = AtlasPca::Attest::Cert
    der = AtlasPca::Attest::Der
    orig = cert.method(:from_pem)
    run = lambda do |which = nil, tweak = nil, der_stubs = {}|
      Seam.with(cert, { from_pem: ->(b) { x = orig.call(b); tweak.call(x) if tweak && b == which; x } }) do
        Seam.with(der, der_stubs) { i.verify_intel_pck_chain(pem, nil, now) }
      end
    end
    no_verify = ->(x) { x.define_singleton_method(:verify) { |_k| false } }
    rsa = OpenSSL::PKey.read(c.rsa.public_to_der)
    rsa_key = ->(x) { x.define_singleton_method(:public_key) { rsa } }
    seen = []
    at = Time.at(Rational(1_800_000_000_500, 1000))
    Seam.with(der, { x509_valid_at?: ->(*a) { seen << a[1]; true } }) { Seam.with(Time, { now: -> { at } }) { i.verify_intel_pck_chain(pem) } }
    C32B.ck('leaf not signed', run.call(leaf_pem, no_verify), C32B.rf('certificate at depth 0 is not signed by its issuer')) &&
      C32B.ck('root not self-signed', run.call(root_pem, no_verify), C32B.rf('root certificate is not self-signed')) &&
      C32B.ck('role', run.call(nil, nil, { check_chain_roles: ->(_d) { 'ROLE' } }), C32B.rf('ROLE')) &&
      C32B.ck('critical', run.call(nil, nil, { unrecognised_critical_extension: ->(_d) { '1.2.3' } }),
              C32B.rf('PCK chain certificate at depth 0 has an unrecognised critical extension 1.2.3')) &&
      C32B.ck('leaf key', run.call(leaf_pem, rsa_key), C32B.rf('PCK leaf key is not EC (got rsa)')) &&
      C32B.ck('clock in ms', seen.uniq, [1_800_000_000_500.0])
  end

  t('c32b intel: verify_genuine_tdx_quote reports each failing step with e.message; a chain refusal wins over leftover keys; the binding is compared') do
    next true if C32B.skip?('intel.rb')

    c = C11Intel
    i = c.i
    q = c.real_quote
    now = c.real_now
    parsed = i.parse_dcap_quote(q)
    rd = i.parse_dcap_td_report(parsed['tdReportBody'])['reportData']
    ea = C32BIntel.err_arg
    es = C32BIntel.err_std
    run = -> { i.verify_genuine_tdx_quote(q, nil, nil, nil, now) }
    with = ->(stubs) { Seam.with(i, stubs) { run.call } }
    bound = Seam.with(C32B.cm, { attestation_binding: ->(_e) { rd } }) do
      i.verify_genuine_tdx_quote(q, nil, { 'holder_pub' => 'h', 'grant_ref' => 'g', 'epoch' => 1, 'nonce' => 'n' }, nil, now)
    end
    C32B.ck('quote parse', with.call({ parse_dcap_quote: ->(*_a) { raise ea } }), C32B.rf('quote parse failed: MSG')) &&
      C32B.ck('td parse', with.call({ parse_dcap_td_report: ->(*_a) { raise ea } }), C32B.rf('TD report parse failed: MSG')) &&
      C32B.ck('extract', with.call({ extract_pck_fmspc_and_tcb: ->(*_a) { raise ea } }), C32B.rf('PCK FMSPC/TCB extraction failed: MSG')) &&
      C32B.ck('outer', with.call({ parse_dcap_quote: ->(*_a) { raise es } }), C32B.rf('genuine TDX verification error (fail closed): MSG')) &&
      C32B.ck('chain refusal with keys', with.call({ verify_intel_pck_chain: ->(*_a) { { 'ok' => false, 'reason' => 'why', 'leafKey' => 'x', 'leafDer' => 'junk'.b } } }),
              C32B.rf('PCK chain invalid: why')) &&
      C32B.ck('matching binding', bound['ok'], true)
  end

  t('c32b intel: date_utc keeps negative years, as_status refuses a duck, worst keeps its first of two equals, evaluate_tcb needs a list of module levels') do
    next true if C32B.skip?('intel.rb')

    c = C11Intel
    i = c.i
    duck = Object.new
    def duck.to_str = 'UpToDate'
    def duck.==(_other) = true
    a1 = +'UpToDate'
    a2 = +'UpToDate'
    info = { 'tcbLevels' => [c.level], 'tdxModuleIdentities' => [{ 'id' => 'TDX_01', 'tcbLevels' => 'x' }] }
    tcb = c.tm { i.evaluate_tcb(info, c.pck, c.tdr(minor: 1, svn0: 3)) }
    C32B.ck('date_utc', i.date_utc(-1, 0, 1, 0, 0, 0), AtlasPca::Attest::Der.days_from_civil(-1, 1, 1) * 86_400_000) &&
      C32B.ck('as_status duck', i.as_status(duck).nil?, true) && C32B.ck('worst first', i.worst(a1, a2).equal?(a1), true) &&
      C32B.ck('worst second', i.worst(a2, a1).equal?(a2), true) && C32B.ck('module levels', tcb, { 'error' => 'TDX module TDX_01 SVN 3 is below every known level' })
  end

  t('c32b intel: parse_crl, raw_json_object and evaluate_tcb end (deadline); signer_key_from_chain refuses a failed chain that still carries a leaf') do
    next true if C32B.skip?('intel.rb')

    c = C11Intel
    i = c.i
    der = c.crl(c.base(c.utc(C11Intel::THIS), c.utc(C11Intel::NEXT), c.tlv(0x30, c.entry("\x01".b), c.entry("\x02".b))))
    crl = c.tm(1) { i.parse_crl(der) }
    raw = c.tm(1) { i.raw_json_object('{"a":{"b":"x\\"y"}}', 'a') }
    tcb = c.tm(1) { i.evaluate_tcb(c.info_of([c.level]), c.pck, c.tdr) }
    signer = Seam.with(i, { verify_intel_pck_chain: ->(*_a) { { 'ok' => false, 'reason' => 'why', 'leafDer' => 'x' } } }) { i.signer_key_from_chain('', nil, c.real_now, {}) }
    C32B.ck('crl', crl['revoked'], { '1' => true, '2' => true }) && C32B.ck('raw', raw, '{"b":"x\\"y"}') && C32B.ck('tcb', tcb['platform'], 'UpToDate') &&
      C32B.ck('signer', signer, { 'error' => 'issuer chain invalid: why' })
  end

  t('c32b intel: collateral and verifier wrappers report their refusals exactly (a failed quote check wins; exceptions carry e.message)') do
    next true if C32B.skip?('intel.rb')

    c = C11Intel
    i = c.i
    q = c.real_quote
    now = c.real_now
    es = C32BIntel.err_std
    mj = C32B.msgc(C32B.a::JsTypeError, 'JM')
    quote_fail = Seam.with(i, { verify_genuine_tdx_quote: ->(*_a) { { 'ok' => false, 'reason' => 'why', 'pckTcb' => {}, 'fmspc' => 'aa' } } }) do
      i.verify_intel_tdx_collateral(q, c.real_col, now)
    end
    coll_raise = Seam.with(i, { verify_genuine_tdx_quote: ->(*_a) { raise es } }) { i.verify_intel_tdx_collateral(q, c.real_col, now) }
    mrtd = c.cm.to_hex(i.verify_genuine_tdx_quote(q, nil, nil, nil, now)['report']['mrTd'])
    mk = lambda do |quote|
      C32B.a::IntelDcapVerifier.new({ 'binding' => 'report-data', 'policy' => { 'mrtds' => [mrtd] }, 'resolve_evidence' => ->(_d) { { 'quote' => quote } } })
    end
    bnd = { 'holder_pub' => 'h', 'grant_ref' => 'g', 'epoch' => 1, 'nonce' => 'n' }
    not_constructible = Seam.with(C32B.cm, { attestation_binding: ->(_e) { raise mj } }) { mk.call(q).verify('doc', bnd, now) }
    outer = Seam.with(i, { verify_genuine_tdx_quote: ->(*_a) { raise es } }) { mk.call('x'.b).verify('doc', bnd, now) }
    C32B.ck('quote invalid', quote_fail, C32B.rf('quote invalid: why')) &&
      C32B.ck('collateral error', coll_raise, C32B.rf('collateral verification error (fail closed): MSG')) &&
      C32B.ck('binding', not_constructible, C32B.rf('binding not constructible: JM')) &&
      C32B.ck('verifier error', outer, C32B.rf('intel-dcap verification error (fail closed): MSG'))
  end
end
