# frozen_string_literal: true

# Exact-outcome kill tests for lib/atlas_pca/attest/ocsp.rb (RFC 6960 offline verification, native counterpart of
# attest-nvidia-ocsp.ts checkNvidiaChainOcsp). Every response here is built and genuinely signed in the test (keys and
# certificates are generated at load of the fixture, never committed). AtlasPca is dropped and re-evaluated for every mutant, so
# every library object is resolved at CALL time (never captured in a constant).
require 'openssl'
require 'digest'
require 'timeout'
require 'tmpdir'
require 'fileutils'
require 'rbconfig'
require 'atlas_pca/attest'

module MutationKill
  module C12Ocsp
    module_function

    NOW = 1_800_000_000_000
    NOW_S = 1_800_000_000
    SHA384_EC = '1.2.840.10045.4.3.3'
    OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1'
    HASH_OID = { 'sha1' => '1.3.14.3.2.26', 'sha256' => '2.16.840.1.101.3.4.2.1', 'sha384' => '2.16.840.1.101.3.4.2.2',
                 'sha512' => '2.16.840.1.101.3.4.2.3' }.freeze
    P = 'OCSP response rejected: '
    NO_MATCH = 'no SingleResponse matches the certificate (serial / issuer hashes differ)'
    LIB = File.expand_path('../../lib', __dir__)
    DuckCert = Struct.new(:extensions)
    DuckSubject = Struct.new(:subject)

    def oc = AtlasPca::Attest::Ocsp
    def att = AtlasPca::Attest
    def dr = AtlasPca::Attest::Der
    def cm = AtlasPca::Attest::Common
    def skip? = (f = ENV['MUT_FILE']) && !f.empty? && f != 'ocsp.rb'
    def mutating? = (f = ENV['MUT_FILE']) && !f.empty?
    def tm(&) = Timeout.timeout(2, &)

    def err
      yield
      nil
    rescue Exception => e # rubocop:disable Lint/RescueException
      [e.class, e.message]
    end

    def same?(got, want) = want == got && want.class == got.class

    # rows: [label, got, want]
    def chk(rows)
      bad = rows.reject { |_l, got, want| same?(got, want) }
      return true if bad.empty?

      raise "c12 mismatch (#{bad.length}): #{bad.first(3).map { |l, g, w| "#{l}: got #{g.inspect} want #{w.inspect}" }.join(' | ')}"
    end

    # replaces module singleton methods for the duration of the block
    def with(mod, stubs)
      orig = stubs.keys.to_h { |n| [n, mod.method(n)] }
      stubs.each { |n, impl| mod.define_singleton_method(n, &impl) }
      yield
    ensure
      orig&.each { |n, m| mod.define_singleton_method(n, m) }
    end

    # ---- a fresh Ruby over the mutated text of one library file
    def source(rel)
      path = File.join(LIB, rel)
      if defined?(::Oracle) && (tgt = ::Oracle.instance_variable_get(:@target)) && File.expand_path(tgt) == path
        ::Oracle.instance_variable_get(:@text)
      else
        File.read(path)
      end
    end

    def header_changed?(rel, nlines) = source(rel).lines.first(nlines) != File.read(File.join(LIB, rel)).lines.first(nlines)

    def fresh(rel, code)
      Dir.mktmpdir('c12fresh') do |d|
        FileUtils.cp_r(LIB, d)
        File.write(File.join(d, 'lib', rel), source(rel))
        gems = Gem.loaded_specs.values.flat_map(&:full_require_paths).flat_map { |g| ['-I', g] }
        out = IO.popen([RbConfig.ruby, '--disable-gems', '-I', File.join(d, 'lib'), *gems, '-e', code], 'r', err: File::NULL, &:read)
        [out, $?.success?]
      end
    end

    # ---- DER builders
    def tlv(tag, *parts)
      b = parts.map { |x| x.to_s.b }.join.b
      n = [b.bytesize].pack('N').sub(/\A\0+/, '')
      len = b.bytesize < 128 ? [b.bytesize].pack('C') : [0x80 | n.bytesize].pack('C') + n
      [tag].pack('C') + len + b
    end

    def oid(o) = OpenSSL::ASN1::ObjectId.new(o).to_der

    def gt(ms)
      s, f = ms.divmod(1000)
      txt = Time.at(s).utc.strftime('%Y%m%d%H%M%S')
      txt += ".#{format('%03d', f).sub(/0+\z/, '')}" unless f.zero?
      tlv(0x18, "#{txt}Z")
    end

    def tt(x) = x.is_a?(Integer) ? gt(x) : x

    # ---- keys and certificates
    def key(n)
      @keys ||= {}
      @keys[n] ||= case n
                   when :rsa then OpenSSL::PKey::RSA.generate(2048)
                   when :ed then OpenSSL::PKey.generate_key('ED25519')
                   else OpenSSL::PKey::EC.generate('secp384r1')
                   end
    end

    def ext(sn, v, critical = false) = OpenSSL::X509::ExtensionFactory.new.create_extension(sn, v, critical)

    def mk(cn, key_name, signer, issuer_cn, serial, exts, nb = 1_700_000_000, na = 1_900_000_000)
      c = OpenSSL::X509::Certificate.new
      c.version = 2
      c.serial = serial
      c.subject = OpenSSL::X509::Name.parse("/CN=#{cn}")
      c.issuer = OpenSSL::X509::Name.parse("/CN=#{issuer_cn}")
      c.public_key = key(key_name)
      c.not_before = Time.at(nb)
      c.not_after = Time.at(na)
      exts.each { |e| c.add_extension(e) }
      c.sign(key(signer), OpenSSL::Digest.new('SHA384'))
      c.to_der
    end

    # root -> inter -> leaf (serial 0x9234, so its INTEGER carries a leading 00), leaf_aia (advertises an OCSP URL), inter2 (not in the chain)
    def fx
      @fx ||= begin
        ca = [ext('basicConstraints', 'CA:TRUE', true), ext('keyUsage', 'keyCertSign,cRLSign', true)]
        ee = [ext('basicConstraints', 'CA:FALSE', true)]
        aia = ext('authorityInfoAccess', 'OCSP;URI:http://ocsp.example/r,caIssuers;URI:http://ca.example/c')
        { root: mk('root', :root, :root, 'root', 1, ca), inter: mk('inter', :inter, :root, 'root', 2, ca),
          inter2: mk('inter2', :inter2, :root, 'root', 3, ca), leaf: mk('leaf', :leaf, :inter, 'inter', 0x9234, ee),
          leaf_aia: mk('leaf', :leaf, :inter, 'inter', 0x9235, ee + [aia]) }
      end
    end

    def cder(x) = x.is_a?(Symbol) ? fx.fetch(x) : x
    def co(x) = x.respond_to?(:raw) ? x : AtlasPca::Attest::Cert.new(cder(x))

    # a delegated responder certificate
    def dcert(cn: 'responder', key: :resp, signer: :inter, issuer_cn: 'inter', eku: 'OCSPSigning', nb: NOW_S - 100_000,
              na: NOW_S + 100_000, serial: 77)
      @dc ||= {}
      @dc[[cn, key, signer, issuer_cn, eku, nb, na, serial]] ||= begin
        exts = [ext('basicConstraints', 'CA:FALSE', true)]
        exts << ext('extendedKeyUsage', eku) if eku
        mk(cn, key, signer, issuer_cn, serial, exts, nb, na)
      end
    end

    # ---- OCSP builders
    def spki_bits(der) = OpenSSL::ASN1.decode(OpenSSL::X509::Certificate.new(der).public_key.public_to_der).value[1].value
    def subj_der(der) = OpenSSL::X509::Certificate.new(der).subject.to_der
    def dg(h, data) = OpenSSL::Digest.new(h.upcase).digest(data)

    def cid(c, i, hash: 'sha1', serial: nil, name: nil, key: nil, alg: nil)
      tlv(0x30, alg || tlv(0x30, oid(HASH_OID.fetch(hash))), tlv(0x04, name || dg(hash, subj_der(i))),
          tlv(0x04, key || dg(hash, spki_bits(i))),
          serial || OpenSSL::ASN1::Integer.new(OpenSSL::X509::Certificate.new(c).serial).to_der)
    end

    def rid_name(der) = tlv(0xA1, subj_der(der))
    def rid_key(der) = tlv(0xA2, tlv(0x04, Digest::SHA1.digest(spki_bits(der))))
    def good = tlv(0x80)

    def single(id, status = tlv(0x80), this = NOW - 1000, *after) = tlv(0x30, id, status, tt(this), *after)

    def tbs(rid, produced, singles, version: nil) = tlv(0x30, *[version].compact, rid, tt(produced), tlv(0x30, *singles))

    def basic(tbs_der, signer = :inter, certs: nil, certs_tag: 0xA0, alg: SHA384_EC, digest: 'SHA384')
      sg = key(signer).sign(OpenSSL::Digest.new(digest), tbs_der)
      parts = [tbs_der, tlv(0x30, oid(alg)), tlv(0x03, "\0", sg)]
      parts << tlv(certs_tag, tlv(0x30, *certs)) if certs
      tlv(0x30, *parts)
    end

    def wrap(basic_der, rtype: OCSP_BASIC, status: 0, bytes: nil)
      rb = bytes || tlv(0xA0, tlv(0x30, oid(rtype), tlv(0x04, basic_der)))
      tlv(0x30, tlv(0x0A, [status].pack('C')), rb)
    end

    def resp(cert: :leaf, issuer: :inter, id: nil, status: nil, this: NOW - 1000, after: [], produced: NOW - 1000, rid: nil,
             version: nil, singles: nil, signer: :inter, certs: nil, certs_tag: 0xA0, alg: SHA384_EC, digest: 'SHA384')
      c = cder(cert)
      i = cder(issuer)
      s = singles || [single(id || cid(c, i), status || good, this, *after)]
      wrap(basic(tbs(rid || rid_name(i), produced, s, version: version), signer, certs: certs, certs_tag: certs_tag, alg: alg,
                                                                                   digest: digest))
    end

    # a response whose ResponseData is exactly `kids`
    def shape(*kids) = wrap(basic(tlv(0x30, *kids)))

    def dresp(d, **o) = resp(rid: rid_name(d), signer: :resp, certs: [d], **o)

    def run(der, cert: :leaf, issuer: :inter, chain: %i[leaf inter root], now: NOW, max_age: nil, skew: nil)
      args = [der, co(cert), co(issuer), chain.map { |x| co(x) }, now, max_age]
      args << skew unless skew.nil?
      oc.verify_ocsp_response(*args)
    end

    def ok(status = 'good', responder = 'issuer') = { 'ok' => true, 'status' => status, 'responder' => responder }
    def no(reason) = { 'ok' => false, 'reason' => reason }
    def rej(reason) = no("#{P}#{reason}")
  end

  # ================================================================================================ constants and loading
  t('OCSP constants: OIDs, algorithm tables, default maximum age') do
    next true if C12Ocsp.skip?

    o = C12Ocsp.oc
    C12Ocsp.chk([
                  ['basic', o::OID_OCSP_BASIC, '1.3.6.1.5.5.7.48.1.1'], ['aia', o::OID_AIA, '1.3.6.1.5.5.7.1.1'],
                  ['ad ocsp', o::OID_AD_OCSP, '1.3.6.1.5.5.7.48.1'], ['eku ocsp', o::OID_EKU_OCSP_SIGNING, '1.3.6.1.5.5.7.3.9'],
                  ['eku', o::OID_EKU, '2.5.29.37'],
                  ['hashes', o::HASHES, { '1.3.14.3.2.26' => 'sha1', '2.16.840.1.101.3.4.2.1' => 'sha256',
                                          '2.16.840.1.101.3.4.2.2' => 'sha384', '2.16.840.1.101.3.4.2.3' => 'sha512' }],
                  ['sig algs', o::SIG_ALGS, { '1.2.840.10045.4.3.2' => %w[sha256 ec], '1.2.840.10045.4.3.3' => %w[sha384 ec],
                                              '1.2.840.10045.4.3.4' => %w[sha512 ec], '1.2.840.113549.1.1.11' => %w[sha256 rsa],
                                              '1.2.840.113549.1.1.12' => %w[sha384 rsa], '1.2.840.113549.1.1.13' => %w[sha512 rsa] }],
                  ['hashes frozen', o::HASHES.frozen?, true], ['sig algs frozen', o::SIG_ALGS.frozen?, true],
                  ['max age', o::DEFAULT_MAX_AGE_MS, 604_800_000]
                ])
  end

  t('attest/ocsp.rb loads the certificate model it uses (fresh ruby over the mutated text)') do
    next true if C12Ocsp.skip?
    next true if C12Ocsp.mutating? && !C12Ocsp.header_changed?('atlas_pca/attest/ocsp.rb', 10)

    out, ok = C12Ocsp.fresh('atlas_pca/attest/ocsp.rb',
                            "require 'atlas_pca/attest/common'; require 'atlas_pca/attest/der'; require 'atlas_pca/attest/ocsp'; " \
                            'puts defined?(AtlasPca::Attest::Cert); puts AtlasPca::Attest::Ocsp::OID_AIA')
    ok && out == "constant\n1.3.6.1.5.5.7.1.1\n"
  end

  # ================================================================================================ small helpers
  t('OCSP time_in_range?: field order, every bound, leap years and both time forms') do
    next true if C12Ocsp.skip?

    o = C12Ocsp.oc
    g = ->(s) { o.time_in_range?(s, false) }
    u = ->(s) { o.time_in_range?(s, true) }
    gen_true = %w[20270115080000Z 20240229000000Z 20000229000000Z 20270131235959Z 20271231000000Z 20270430000000Z
                  20270228000000Z 20270101000000Z 20270115080000.5Z]
    gen_false = ['20270229000000Z', '20270431000000Z', '20270230000000Z', '20270132000000Z', '20271301000000Z', '20270001000000Z',
                 '20270100000000Z', '20270115240000Z', '20270115086000Z', '20270115080060Z', '19000229000000Z', '21000229000000Z',
                 'junk', '', '20270115080000', '20270115080000.0Z', '270115080000Z']
    utc_true = %w[270115080000Z 240229000000Z 000229000000Z 960229000000Z 990101000000Z 491231235959Z 500101000000Z 270131235959Z]
    utc_false = %w[230229000000Z 970229000000Z 270115240000Z 271301000000Z 270115086000Z 270115080060Z 2701150800Z
                   20270115080000Z]
    C12Ocsp.chk(gen_true.map { |s| ["gen #{s}", g.(s), true] } + gen_false.map { |s| ["gen #{s}", g.(s), false] } +
                utc_true.map { |s| ["utc #{s}", u.(s), true] } + utc_false.map { |s| ["utc #{s}", u.(s), false] })
  end

  t('OCSP latin1: ISO-8859-1 bytes become UTF-8 text and the input is left alone') do
    next true if C12Ocsp.skip?

    s = [0xE9, 0x41].pack('C*')
    got = C12Ocsp.oc.latin1(s)
    C12Ocsp.chk([['text', got, "éA"], ['enc', got.encoding, Encoding::UTF_8], ['input enc', s.encoding, Encoding::BINARY],
                 ['input', s, [0xE9, 0x41].pack('C*')]])
  end

  t('OCSP all_times_well_formed?: every UTCTime / GeneralizedTime anywhere, only universal primitive times, overruns refused') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    awf = ->(*kids) { d = o.tlv(0x30, *kids); o.tm { o.oc.all_times_well_formed?(d, 2, d.bytesize) } }
    gu = o.tlv(0x17, '270115080000Z')
    bu = o.tlv(0x17, '271315080000Z')
    gg = o.tlv(0x18, '20270115080000Z')
    bg = o.tlv(0x18, '20271315080000Z')
    d = o.tlv(0x30, o.tlv(0x04, 'abcd'))
    C12Ocsp.chk([
                  ['valid', awf.(gu, gg), true], ['bad utc', awf.(bu), false], ['bad gen', awf.(bg), false],
                  ['valid then bad', awf.(gu, bg), false], ['empty', awf.(), true],
                  ['nested bad', awf.(o.tlv(0xA0, bu)), false], ['nested valid', awf.(o.tlv(0xA0, o.tlv(0x30, gu))), true],
                  ['deep bad', awf.(o.tlv(0xA0, o.tlv(0xA1, bg))), false],
                  ['context class', awf.(o.tlv(0x97, 'garbage'), o.tlv(0x98, 'garbage'), o.tlv(0x57, 'x'), o.tlv(0xD7, 'x')), true],
                  ['other universal', awf.(o.tlv(0x16, 'garbage'), o.tlv(0x19, 'x'), o.tlv(0x04, 'x')), true],
                  ['constructed time tag', awf.(o.tlv(0x37, o.tlv(0x04, 'x')), o.tlv(0x38, o.tlv(0x04, 'x'))), true],
                  ['constructed time tag nested bad', awf.(o.tlv(0x37, bu)), false],
                  ['empty range', o.tm { o.oc.all_times_well_formed?(d, 2, 2) }, true],
                  ['overrun', o.err { o.oc.all_times_well_formed?(d, 2, 4) }, [AtlasPca::Attest::OcspError, 'element overruns its parent']]
                ])
  end

  t('OCSP gen_time_ms: epoch milliseconds, fraction truncated to three digits, UTCTime century pivot at 50') do
    next true if C12Ocsp.skip?

    o = C12Ocsp.oc
    tu = ->(y, mo, d, h, mi, s, ms = 0) { (Time.utc(y, mo, d, h, mi, s).to_i * 1000) + ms }
    gm = ->(s) { o.gen_time_ms(s) }
    C12Ocsp.chk([
                  ['gen', gm.('20270115080000Z'), tu.(2027, 1, 15, 8, 0, 0)],
                  ['frac .5', gm.('20270115080000.5Z'), tu.(2027, 1, 15, 8, 0, 0, 500)],
                  ['frac .25', gm.('20270115080000.25Z'), tu.(2027, 1, 15, 8, 0, 0, 250)],
                  ['frac .123456', gm.('20270115080000.123456Z'), tu.(2027, 1, 15, 8, 0, 0, 123)],
                  ['frac .001', gm.('20270115080000.001Z'), tu.(2027, 1, 15, 8, 0, 0, 1)],
                  ['frac .0001', gm.('20270115080000.0001Z'), tu.(2027, 1, 15, 8, 0, 0)],
                  ['frac .9', gm.('20270115080000.9Z'), tu.(2027, 1, 15, 8, 0, 0, 900)],
                  ['gen fields', gm.('20311130081537Z'), tu.(2031, 11, 30, 8, 15, 37)],
                  ['utc', gm.('270115080000Z'), tu.(2027, 1, 15, 8, 0, 0)],
                  ['utc 00', gm.('000101000000Z'), tu.(2000, 1, 1, 0, 0, 0)],
                  ['utc 49', gm.('491231235959Z'), tu.(2049, 12, 31, 23, 59, 59)],
                  ['utc 50', gm.('500101000000Z'), tu.(1950, 1, 1, 0, 0, 0)],
                  ['utc 99', gm.('991231120000Z'), tu.(1999, 12, 31, 12, 0, 0)],
                  ['utc fields', gm.('311130081537Z'), tu.(2031, 11, 30, 8, 15, 37)],
                  ['junk', C12Ocsp.err { gm.('junk') }, [AtlasPca::Attest::OcspError, 'response times are not parseable']],
                  ['empty', C12Ocsp.err { gm.('') }, [AtlasPca::Attest::OcspError, 'response times are not parseable']]
                ])
  end

  t('OCSP children: child TLVs with header offsets, an overrunning child refused, the cursor advances') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    der = o.tlv(0x30, o.tlv(0x04, 'ab'), o.tlv(0x02, "\x05"))
    top = AtlasPca::Attest::Der.tlv_at(der, 0)
    got = o.tm { o.oc.children(der, top) }.map { |c, off| [c.tag, c.start, c.end_, off] }
    short = AtlasPca::Attest::Der::Tlv.new(0x30, 2, 4)
    big = o.tlv(0x30, o.tlv(0x04, 'abcd'))
    C12Ocsp.chk([['children', got, [[4, 4, 6, 2], [2, 8, 9, 6]]],
                 ['empty', o.tm { o.oc.children(o.tlv(0x30), AtlasPca::Attest::Der.tlv_at(o.tlv(0x30), 0)) }, []],
                 ['overrun', o.err { o.tm { o.oc.children(big, short) } }, [AtlasPca::Attest::OcspError, 'element overruns its parent']]])
  end

  t('OCSP strip_zeros: only leading zero bytes, always keeps the last byte') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    sz = ->(*bytes) { o.tm { o.oc.strip_zeros(bytes.pack('C*')) } }
    b = ->(*bytes) { bytes.pack('C*') }
    C12Ocsp.chk([['empty', sz.(), ''], ['one', sz.(5), b.(5)], ['zero', sz.(0), b.(0)], ['two zeros', sz.(0, 0), b.(0)],
                 ['three zeros', sz.(0, 0, 0), b.(0)], ['lead zero', sz.(0, 5), b.(5)], ['lead zeros', sz.(0, 0, 5), b.(5)],
                 ['four', sz.(0, 0, 0, 5), b.(5)], ['no lead', sz.(5, 6), b.(5, 6)], ['trailing zero', sz.(1, 0), b.(1, 0)],
                 ['trailing zeros', sz.(5, 0, 0), b.(5, 0, 0)], ['inner zero', sz.(0, 5, 0, 7), b.(5, 0, 7)]])
  end

  t('OCSP spki_key_bits: the BIT STRING content after the unused-bits byte; anything but {alg, BIT STRING} refused') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    spki = o.key(:inter).public_to_der
    want = OpenSSL::ASN1.decode(spki).value[1].value
    bad = [o.tlv(0x30, o.tlv(0x30, o.oid('1.2.3'))), o.tlv(0x30, o.tlv(0x30, o.oid('1.2.3')), o.tlv(0x04, 'xy')), o.tlv(0x30)]
    msg = [AtlasPca::Attest::OcspError, 'malformed SubjectPublicKeyInfo']
    C12Ocsp.chk([['bits', o.oc.spki_key_bits(spki), want], ['non-empty', want.bytesize > 1, true]] +
                bad.each_with_index.map { |d, i| ["bad #{i}", o.err { o.oc.spki_key_bits(d) }, msg] })
  end

  t('OCSP verify_sig: each algorithm with its hash, key type must match, unknown algorithm and unusable key are false') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    pub = ->(n) { o.cm.load_public_key(o.key(n).public_to_der) }
    ec = pub.(:inter)
    rsa = pub.(:rsa)
    m = 'to-be-signed'
    sg = ->(n, h) { o.key(n).sign(OpenSSL::Digest.new(h), m) }
    ec_algs = [['1.2.840.10045.4.3.2', 'SHA256'], ['1.2.840.10045.4.3.3', 'SHA384'], ['1.2.840.10045.4.3.4', 'SHA512']]
    rsa_algs = [['1.2.840.113549.1.1.11', 'SHA256'], ['1.2.840.113549.1.1.12', 'SHA384'], ['1.2.840.113549.1.1.13', 'SHA512']]
    rows = []
    ec_algs.each do |a, h|
      rows << ["ec #{h}", o.oc.verify_sig(a, m, sg.(:inter, h), ec), true]
      rows << ["ec #{h} tampered", o.oc.verify_sig(a, "#{m}x", sg.(:inter, h), ec), false]
    end
    rsa_algs.each do |a, h|
      rows << ["rsa #{h}", o.oc.verify_sig(a, m, sg.(:rsa, h), rsa), true]
      rows << ["rsa #{h} tampered", o.oc.verify_sig(a, "#{m}x", sg.(:rsa, h), rsa), false]
    end
    rows << ['ec wrong hash', o.oc.verify_sig('1.2.840.10045.4.3.3', m, sg.(:inter, 'SHA256'), ec), false]
    rows << ['rsa wrong hash', o.oc.verify_sig('1.2.840.113549.1.1.12', m, sg.(:rsa, 'SHA256'), rsa), false]
    rows << ['ec alg rsa key', o.oc.verify_sig('1.2.840.10045.4.3.3', m, sg.(:rsa, 'SHA384'), rsa), false]
    rows << ['rsa alg ec key', o.oc.verify_sig('1.2.840.113549.1.1.12', m, sg.(:inter, 'SHA384'), ec), false]
    rows << ['unknown alg', o.oc.verify_sig('1.2.840.10045.4.3.1', m, sg.(:inter, 'SHA384'), ec), false]
    rows << ['unusable key', o.oc.verify_sig('1.2.840.10045.4.3.3', m, 'x', Object.new), false]
    # the key-type gates are decided before any verification: spies prove nothing past them is reached
    rec = []
    ed = o.key(:ed)
    res = o.with(o.cm, ecdsa_verify_der: ->(*a) { rec << [:ec, *a]; true }, rsa_pkcs1_verify: ->(*a) { rec << [:rsa, *a]; true }) do
      [o.oc.verify_sig('1.2.840.10045.4.3.3', 'm', 's', ec), o.oc.verify_sig('1.2.840.10045.4.3.3', 'm', 's', rsa),
       o.oc.verify_sig('1.2.840.113549.1.1.12', 'm', 's', rsa), o.oc.verify_sig('1.2.840.113549.1.1.12', 'm', 's', ed),
       o.oc.verify_sig('1.2.840.113549.1.1.12', 'm', 's', ec), o.oc.verify_sig('9.9.9', 'm', 's', rsa),
       o.oc.verify_sig('9.9.9', 'm', 's', ec)]
    end
    rows << ['spy results', res, [true, false, true, false, false, false, false]]
    rows << ['spy calls', rec.length, 2]
    rows << ['spy ec', [rec[0][0], rec[0][1].equal?(ec), rec[0][2..]], [:ec, true, ['s', 'm', 'sha384']]]
    rows << ['spy rsa', [rec[1][0], rec[1][1].equal?(rsa), rec[1][2..]], [:rsa, true, ['s', 'm', 'sha384']]]
    C12Ocsp.chk(rows)
  end

  t('OCSP cert_id_hashes: SHA-1/256/384/512 of the issuer name and of its key bits') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    i = o.co(:inter)
    rows = %w[sha1 sha256 sha384 sha512].map do |h|
      ["hash #{h}", o.oc.cert_id_hashes(i, h), [o.dg(h, o.subj_der(o.fx[:inter])), o.dg(h, o.spki_bits(o.fx[:inter]))]]
    end
    C12Ocsp.chk(rows)
  end

  t('OCSP eku_of: the EKU OIDs in order; absent, not a SEQUENCE or malformed is nil') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    ce = ->(v) { C12Ocsp::DuckCert.new({ '2.5.29.37' => AtlasPca::Attest::Der::CertExtension.new(false, v) }) }
    ocsp = '1.3.6.1.5.5.7.3.9'
    srv = '1.3.6.1.5.5.7.3.1'
    pad = ("\x00" * 10).b
    C12Ocsp.chk([
                  ['real ocsp+server', o.tm { o.oc.eku_of(o.co(o.dcert(eku: 'serverAuth,OCSPSigning'))) }, [srv, ocsp]],
                  ['real ocsp', o.oc.eku_of(o.co(o.dcert)), [ocsp]], ['real none', o.oc.eku_of(o.co(o.dcert(eku: nil))), nil],
                  ['leaf none', o.oc.eku_of(o.co(:leaf)), nil], ['absent', o.oc.eku_of(C12Ocsp::DuckCert.new({})), nil],
                  ['duck oids', o.tm { o.oc.eku_of(ce.(o.tlv(0x30, o.oid(srv), o.oid(ocsp)))) }, [srv, ocsp]],
                  ['empty seq', o.tm { o.oc.eku_of(ce.(o.tlv(0x30))) }, []],
                  ['not a sequence', o.oc.eku_of(ce.(o.tlv(0x31, o.oid(ocsp)))), nil], ['empty value', o.oc.eku_of(ce.('')), nil],
                  ['truncated child', o.oc.eku_of(ce.(o.tlv(0x30, "\x06"))), nil],
                  ['child past the sequence', o.oc.eku_of(ce.(("\x30\x03\x06\x05\x2b".b) + pad)), nil],
                  ['not an oid', o.oc.eku_of(ce.(o.tlv(0x30, o.tlv(0x04, 'x')))), nil],
                  ['good then bad', o.oc.eku_of(ce.(o.tlv(0x30, o.oid(ocsp), o.tlv(0x04, 'x')))), nil]
                ])
  end

  t('OCSP cert_ocsp_urls: only OCSP access methods with a uniformResourceIdentifier, in order; anything malformed is empty') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    ce = ->(v) { C12Ocsp::DuckCert.new({ '1.3.6.1.5.5.7.1.1' => AtlasPca::Attest::Der::CertExtension.new(false, v) }) }
    ad = ->(oid, loc) { o.tlv(0x30, o.oid(oid), loc) }
    ocsp = '1.3.6.1.5.5.7.48.1'
    ca = '1.3.6.1.5.5.7.48.2'
    full = o.tlv(0x30, ad.(ocsp, o.tlv(0x86, 'http://ocsp.example/a')), ad.(ca, o.tlv(0x86, 'http://ca.example/c')),
                 ad.(ocsp, o.tlv(0x82, 'dns.example')), ad.(ocsp, o.tlv(0x86, 'http://ocsp.example/b')))
    C12Ocsp.chk([
                  ['two urls', o.tm { o.oc.cert_ocsp_urls(ce.(full)) }, ['http://ocsp.example/a', 'http://ocsp.example/b']],
                  ['absent', o.oc.cert_ocsp_urls(C12Ocsp::DuckCert.new({})), []],
                  ['not a sequence', o.oc.cert_ocsp_urls(ce.(o.tlv(0x31, ad.(ocsp, o.tlv(0x86, 'http://x'))))), []],
                  ['empty', o.oc.cert_ocsp_urls(ce.(o.tlv(0x30))), []],
                  ['truncated access description', o.oc.cert_ocsp_urls(ce.(o.tlv(0x30, o.tlv(0x30, "\x06")))), []],
                  ['valid then malformed', o.oc.cert_ocsp_urls(ce.(o.tlv(0x30, ad.(ocsp, o.tlv(0x86, 'http://x')), o.tlv(0x30, "\x06")))), []],
                  ['real certificate', o.oc.cert_ocsp_urls(o.co(:leaf_aia)), ['http://ocsp.example/r']],
                  ['real without', o.oc.cert_ocsp_urls(o.co(:leaf)), []]
                ])
  end

  t('OCSP subj: a distinguished name on one line, newlines joined by comma and space') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    C12Ocsp.chk([['two lines', o.oc.subj(C12Ocsp::DuckSubject.new("CN=a\nO=b")), 'CN=a, O=b'],
                 ['three', o.oc.subj(C12Ocsp::DuckSubject.new("CN=a\nO=b\nC=c")), 'CN=a, O=b, C=c'],
                 ['one', o.oc.subj(C12Ocsp::DuckSubject.new('CN=a')), 'CN=a'], ['real', o.oc.subj(o.co(:leaf)), 'CN=leaf']])
  end

  # ================================================================================================ the response envelope
  t('OCSP verify_ocsp_response: DER envelope, responseStatus and responseBytes refusals, exact reasons') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    good = o.resp
    flipped = good.dup
    flipped.setbyte(0, 0x31)
    e0 = o.tlv(0x0A, "\0")
    basic_oid = o.oid(o::OCSP_BASIC)
    tb = o.tbs(o.rid_name(o.fx[:inter]), o::NOW - 1000, [o.single(o.cid(o.fx[:leaf], o.fx[:inter]))])
    alg = o.tlv(0x30, o.oid(o::SHA384_EC))
    sigbs = o.tlv(0x03, "\0", 'x')
    r = ->(d) { o.run(d) }
    bsc = o.basic(tb)
    flipped_basic = bsc.dup
    flipped_basic.setbyte(0, 0x31)
    # the BasicOCSPResponse is cut short and only the bytes of a following sibling complete it
    cut = bsc.byteslice(0, bsc.bytesize - 5)
    sibling = o.wrap(nil, bytes: o.tlv(0xA0, o.tlv(0x30, basic_oid, o.tlv(0x04, cut), o.tlv(0x04, "\xAA".b * 10))))
    C12Ocsp.chk([
                  ['ok', r.(good), o.ok],
                  ['empty', r.(''), o.no('response is not valid DER')],
                  ['truncated', r.("\x30\x05\x00".b), o.no('response is not valid DER')],
                  ['trailing', r.(good + "\0".b), o.no('trailing bytes after OCSPResponse')],
                  ['not a sequence', r.(flipped), o.rej('OCSPResponse is not a SEQUENCE')],
                  ['no children', r.(o.tlv(0x30)), o.rej('responseStatus is not an ENUMERATED')],
                  ['status not enumerated', r.(o.tlv(0x30, o.tlv(0x02, "\0"))), o.rej('responseStatus is not an ENUMERATED')],
                  ['status 1', r.(o.tlv(0x30, o.tlv(0x0A, "\x01"))), o.no('OCSP responseStatus is 1 (not successful)')],
                  ['status 6', r.(o.tlv(0x30, o.tlv(0x0A, "\x06"))), o.no('OCSP responseStatus is 6 (not successful)')],
                  ['status 16', r.(o.tlv(0x30, o.tlv(0x0A, "\x10"))), o.no('OCSP responseStatus is 16 (not successful)')],
                  ['no responseBytes', r.(o.tlv(0x30, e0)), o.no('successful response carries no responseBytes')],
                  ['responseBytes tag', r.(o.tlv(0x30, e0, o.tlv(0xA1, o.tlv(0x30)))),
                   o.no('successful response carries no responseBytes')],
                  ['empty responseBytes', r.(o.tlv(0x30, e0, o.tlv(0xA0))), o.rej('responseBytes is not a SEQUENCE')],
                  ['responseBytes not a seq', r.(o.tlv(0x30, e0, o.tlv(0xA0, o.tlv(0x04, 'x')))),
                   o.rej('responseBytes is not a SEQUENCE')],
                  ['one element', r.(o.tlv(0x30, e0, o.tlv(0xA0, o.tlv(0x30, basic_oid)))), o.rej('responseBytes is malformed')],
                  ['first not an oid', r.(o.tlv(0x30, e0, o.tlv(0xA0, o.tlv(0x30, o.tlv(0x04, 'x'), o.tlv(0x04, 'y'))))),
                   o.rej('responseBytes is malformed')],
                  ['second not an octet string', r.(o.tlv(0x30, e0, o.tlv(0xA0, o.tlv(0x30, basic_oid, o.tlv(0x02, "\x01"))))),
                   o.rej('responseBytes is malformed')],
                  ['other response type', r.(o.wrap(bsc, rtype: '1.3.6.1.5.5.7.48.1.2')),
                   o.no('responseType is not id-pkix-ocsp-basic')],
                  ['basic truncated', r.(o.wrap("\x30\x05\x00".b)), o.no('BasicOCSPResponse is not valid DER')],
                  ['basic empty', r.(o.wrap('')), o.no('BasicOCSPResponse is not valid DER')],
                  ['basic completed by a sibling', r.(sibling), o.no('BasicOCSPResponse is not valid DER')],
                  ['basic not a sequence', r.(o.wrap(flipped_basic)), o.rej('BasicOCSPResponse is not a SEQUENCE')],
                  ['basic two elements', r.(o.wrap(o.tlv(0x30, tb, alg))), o.rej('BasicOCSPResponse is malformed')],
                  ['basic tbs tag', r.(o.wrap(o.tlv(0x30, o.tlv(0x04, 'x'), alg, sigbs))), o.rej('BasicOCSPResponse is malformed')],
                  ['basic alg tag', r.(o.wrap(o.tlv(0x30, tb, o.tlv(0x04, 'x'), sigbs))), o.rej('BasicOCSPResponse is malformed')],
                  ['basic sig tag', r.(o.wrap(o.tlv(0x30, tb, alg, o.tlv(0x04, 'x')))), o.rej('BasicOCSPResponse is malformed')],
                  ['unsupported signature algorithm', r.(o.resp(alg: '1.2.840.10045.4.3.1', digest: 'SHA224')),
                   o.no('unsupported OCSP signature algorithm 1.2.840.10045.4.3.1')],
                  ['utf-8 tagged input', r.(o.resp.force_encoding('UTF-8')), o.ok]
                ])
  end

  t('OCSP verify_ocsp_response: an out-of-range time anywhere in the response is refused before anything else') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    msg = o.no('response carries a malformed (out-of-range) ASN.1 time')
    C12Ocsp.chk([
                  ['thisUpdate month 13', o.run(o.resp(this: o.tlv(0x18, '20271301000000Z'))), msg],
                  ['nextUpdate utc month 13', o.run(o.resp(after: [o.tlv(0xA0, o.tlv(0x17, '271301000000Z'))])), msg],
                  ['producedAt feb 30', o.run(o.resp(produced: o.tlv(0x18, '20270230000000Z'))), msg],
                  ['in-range', o.run(o.resp(after: [o.tlv(0xA0, o.tlv(0x18, '20270115075959Z'))])), o.no('response is stale (past nextUpdate)')]
                ])
  end

  t('OCSP ResponseData and SingleResponse structure: each missing or mistyped element, version skipped, byKey responder') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    pr = o.gt(o::NOW - 1000)
    sg = o.tlv(0x30, o.single(o.cid(o.fx[:leaf], o.fx[:inter])))
    rid = o.rid_name(o.fx[:inter])
    id = o.cid(o.fx[:leaf], o.fx[:inter])
    alg = o.tlv(0x30, o.oid(o::HASH_OID['sha1']))
    sh = ->(*k) { o.run(o.shape(*k)) }
    C12Ocsp.chk([
                  ['no elements', sh.(), o.rej('responderID is malformed')],
                  ['version only', sh.(o.tlv(0xA0, o.tlv(0x02, "\0"))), o.rej('responderID is malformed')],
                  ['responder tag', sh.(o.tlv(0x04, 'x'), pr, sg), o.rej('responderID is malformed')],
                  ['no producedAt', sh.(rid), o.rej('producedAt is malformed')],
                  ['producedAt as utc', sh.(rid, o.tlv(0x17, '270115080000Z'), sg), o.rej('producedAt is malformed')],
                  ['no responses', sh.(rid, pr), o.rej('responses is malformed')],
                  ['responses tag', sh.(rid, pr, o.tlv(0x04, 'x')), o.rej('responses is malformed')],
                  ['version and byKey', o.run(o.resp(version: o.tlv(0xA0, o.tlv(0x02, "\0")), rid: o.rid_key(o.fx[:inter]))), o.ok],
                  ['byKey', o.run(o.resp(rid: o.rid_key(o.fx[:inter]))), o.ok],
                  ['single of two', o.run(o.resp(singles: [o.tlv(0x30, id, o.good)])), o.rej('SingleResponse is malformed')],
                  ['single first tag', o.run(o.resp(singles: [o.tlv(0x30, o.tlv(0x04, 'x'), o.good, o.gt(o::NOW - 1000))])),
                   o.rej('SingleResponse is malformed')],
                  ['certid of three', o.run(o.resp(singles: [o.tlv(0x30, o.tlv(0x30, alg, o.tlv(0x04, 'a'), o.tlv(0x04, 'b')), o.good,
                                                                    o.gt(o::NOW - 1000))])), o.rej('CertID is malformed')],
                  ['no singles', o.run(o.resp(singles: [])), o.no(C12Ocsp::NO_MATCH)]
                ])
  end

  t('OCSP CertID matching: serial, name hash and key hash each decide; every hash algorithm; unknown hash skipped; ambiguity refused') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    l = o.fx[:leaf]
    i = o.fx[:inter]
    mine = ->(**kw) { o.single(o.cid(l, i, **kw)) }
    bad_serial = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(0x9235)).to_der
    unknown = o.single(o.cid(l, i, alg: o.tlv(0x30, o.oid('1.2.3.4'))))
    rows = [
      ['serial differs', o.run(o.resp(singles: [mine.(serial: bad_serial)])), o.no(C12Ocsp::NO_MATCH)],
      ['name hash differs', o.run(o.resp(singles: [mine.(name: ("\x00" * 20).b)])), o.no(C12Ocsp::NO_MATCH)],
      ['key hash differs', o.run(o.resp(singles: [mine.(key: ("\x01" * 20).b)])), o.no(C12Ocsp::NO_MATCH)],
      ['leading zero serial', o.run(o.resp(singles: [mine.(serial: o.tlv(0x02, "\x00\x00\x92\x34"))])), o.ok],
      ['null parameters', o.run(o.resp(singles: [mine.(alg: o.tlv(0x30, o.oid(o::HASH_OID['sha1']), o.tlv(0x05)))])), o.ok],
      ['unknown hash skipped', o.run(o.resp(singles: [unknown, mine.()])), o.ok],
      ['only unknown hash', o.run(o.resp(singles: [unknown])), o.no(C12Ocsp::NO_MATCH)],
      ['non matching skipped', o.run(o.resp(singles: [mine.(serial: bad_serial), mine.()])), o.ok],
      ['ambiguous', o.run(o.resp(singles: [mine.(), mine.()])), o.no('ambiguous: multiple SingleResponses match the certificate')]
    ]
    %w[sha256 sha384 sha512].each { |h| rows << ["hash #{h}", o.run(o.resp(singles: [mine.(hash: h)])), o.ok] }
    C12Ocsp.chk(rows)
  end

  t('OCSP responder identity and issuer signature: byName / byKey exact, a wrong signature or responder is refused with its reason') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    i = o.fx[:inter]
    none = o.no('no embedded responder certificate verifies the response')
    C12Ocsp.chk([
                  ['sha256 ec', o.run(o.resp(alg: '1.2.840.10045.4.3.2', digest: 'SHA256')), o.ok],
                  ['sha512 ec', o.run(o.resp(alg: '1.2.840.10045.4.3.4', digest: 'SHA512')), o.ok],
                  ['hash does not match algorithm', o.run(o.resp(alg: '1.2.840.10045.4.3.2', digest: 'SHA384')),
                   o.no('OCSP response signature does not verify under the issuer key')],
                  ['wrong signing key', o.run(o.resp(signer: :resp)), o.no('OCSP response signature does not verify under the issuer key')],
                  ['byName other certificate', o.run(o.resp(rid: o.rid_name(o.fx[:leaf]))), none],
                  ['byName two names', o.run(o.resp(rid: o.tlv(0xA1, o.subj_der(i), o.subj_der(i)))), none],
                  ['byKey wrong hash', o.run(o.resp(rid: o.tlv(0xA2, o.tlv(0x04, Digest::SHA1.digest('x'))))), none],
                  ['byKey not an octet string', o.run(o.resp(rid: o.tlv(0xA2, o.tlv(0x0C, Digest::SHA1.digest(o.spki_bits(i)))))), none],
                  ['byKey wrong signature', o.run(o.resp(rid: o.rid_key(i), signer: :resp)),
                   o.no('OCSP response signature does not verify under the issuer key')]
                ])
  end

  # ================================================================================================ delegated responders
  t('OCSP delegated responder: embedded certificate must match, carry the OCSPSigning EKU, be valid and chain-signed') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    d = o.dcert
    deleg = o.ok('good', 'delegated')
    inv = o.no('delegated responder certificate is outside its validity window')
    nochain = o.no('delegated responder certificate is not signed by the supplied NVIDIA chain')
    s = o::NOW_S
    rows = [
      ['delegated by inter', o.run(o.dresp(d)), deleg],
      ['delegated by root', o.run(o.dresp(o.dcert(signer: :root, issuer_cn: 'root', serial: 78))), deleg],
      ['delegated by byKey', o.run(o.resp(rid: o.rid_key(d), signer: :resp, certs: [d])), deleg],
      ['no certificates', o.run(o.resp(rid: o.rid_name(d), signer: :resp)), o.no('no embedded responder certificate verifies the response')],
      ['certificates under the wrong tag', o.run(o.resp(rid: o.rid_name(d), signer: :resp, certs: [d], certs_tag: 0xA1)),
       o.no('no embedded responder certificate verifies the response')],
      ['responder id differs', o.run(o.resp(rid: o.rid_name(o.fx[:leaf]), signer: :resp, certs: [d])),
       o.no('embedded certificates do not match the responderID')],
      ['no EKU', o.run(o.dresp(o.dcert(eku: nil))), o.no('delegated responder certificate lacks the id-kp-OCSPSigning EKU')],
      ['other EKU', o.run(o.dresp(o.dcert(eku: 'serverAuth'))), o.no('delegated responder certificate lacks the id-kp-OCSPSigning EKU')],
      ['two EKUs', o.run(o.dresp(o.dcert(eku: 'serverAuth,OCSPSigning'))), deleg],
      ['notBefore = now', o.run(o.dresp(o.dcert(nb: s))), deleg],
      ['notAfter = now', o.run(o.dresp(o.dcert(na: s))), deleg],
      ['notBefore after now', o.run(o.dresp(o.dcert(nb: s + 1))), inv],
      ['notAfter before now', o.run(o.dresp(o.dcert(na: s - 1))), inv],
      ['notBefore within skew', o.run(o.dresp(o.dcert(nb: s + 2)), skew: 2000), deleg],
      ['notBefore beyond skew', o.run(o.dresp(o.dcert(nb: s + 3)), skew: 2000), inv],
      ['notAfter is not skewed', o.run(o.dresp(o.dcert(na: s - 1)), skew: 2000), inv],
      ['signed by the leaf', o.run(o.dresp(o.dcert(signer: :leaf, issuer_cn: 'leaf'))), nochain],
      ['forged signature', o.run(o.dresp(o.dcert(signer: :other, issuer_cn: 'inter'))), nochain],
      ['wrong issuer name', o.run(o.dresp(o.dcert(signer: :inter, issuer_cn: 'notinter'))), nochain],
      ['response signed by another key', o.run(o.resp(rid: o.rid_name(d), signer: :other, certs: [d])),
       o.no('OCSP response signature does not verify under the delegated responder key')],
      ['issuer outside the chain', o.run(o.resp(issuer: :inter2, rid: o.rid_name(o.dcert(signer: :inter2, issuer_cn: 'inter2', serial: 79)),
                                                 signer: :resp, certs: [o.dcert(signer: :inter2, issuer_cn: 'inter2', serial: 79)]),
                                         issuer: :inter2), deleg],
      ['issuer first in the chain', o.run(o.resp(cert: :root, issuer: :leaf, rid: o.rid_name(o.dcert(signer: :root, issuer_cn: 'root', serial: 78)),
                                                 signer: :resp, certs: [o.dcert(signer: :root, issuer_cn: 'root', serial: 78)]),
                                         cert: :root, issuer: :leaf), deleg]
    ]
    C12Ocsp.chk(rows)
  end

  t('OCSP delegated responder: an unparseable validity bound is outside the window (seam over the validity reader)') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    der = o.dresp(o.dcert)
    r = lambda do |v|
      o.with(AtlasPca::Attest::Der, der_validity_ms: ->(_x) { v }) { o.run(der) }
    end
    inv = o.no('delegated responder certificate is outside its validity window')
    C12Ocsp.chk([['nil start', r.([nil, o::NOW + (10**9)]), inv], ['nil end', r.([o::NOW - (10**9), nil]), inv],
                 ['both', r.([nil, nil]), inv], ['control', r.([o::NOW - (10**9), o::NOW + (10**9)]), o.ok('good', 'delegated')]])
  end

  t('OCSP delegated responder: the first certificate that verifies ends the search (later ones are never read)') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    d = o.dcert
    der = o.resp(rid: o.rid_name(d), signer: :resp, certs: [d, d])
    cert = o.co(:leaf)
    issuer = o.co(:inter)
    chain = %i[leaf inter root].map { |x| o.co(x) }
    cls = AtlasPca::Attest::Cert
    orig = cls.method(:new)
    n = 0
    got = begin
      cls.define_singleton_method(:new) do |*a|
        x = orig.call(*a)
        n += 1
        x.define_singleton_method(:public_key) { raise AtlasPca::Attest::CertError, 'seam: unusable key' } if n == 2
        x
      end
      o.oc.verify_ocsp_response(der, cert, issuer, chain, o::NOW)
    ensure
      cls.singleton_class.send(:remove_method, :new)
    end
    C12Ocsp.chk([['result', got, o.ok('good', 'delegated')], ['both parsed', n, 2]])
  end

  t('OCSP an empty tbsResponseData is refused as missing (seam over the child reader)') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    oc = o.oc
    orig = oc.method(:children)
    n = 0
    got = o.with(oc, children: lambda { |d, t|
      n += 1
      r = orig.call(d, t)
      r[0] = [AtlasPca::Attest::Der::Tlv.new(r[0][0].tag, r[0][1], r[0][1]), r[0][1]] if n == 4
      r
    }) { o.run(o.resp) }
    o.chk([['missing', got, o.no('missing tbsResponseData')]])
  end

  # ================================================================================================ freshness and certStatus
  t('OCSP freshness: thisUpdate / producedAt not in the future, nextUpdate order, maximum age, each boundary and the skew') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    n = o::NOW
    nu = ->(ms) { [o.tlv(0xA0, o.gt(ms))] }
    fut_this = o.no('response thisUpdate is in the future')
    fut_prod = o.no('response producedAt is in the future')
    old = o.no('response is older than the maximum accepted age')
    day7 = 604_800_000
    C12Ocsp.chk([
                  ['this = now', o.run(o.resp(this: n)), o.ok], ['this one ms ahead', o.run(o.resp(this: n + 1)), fut_this],
                  ['produced = now', o.run(o.resp(produced: n)), o.ok], ['produced one ms ahead', o.run(o.resp(produced: n + 1)), fut_prod],
                  ['skew allows this', o.run(o.resp(this: n + 1000), skew: 1000), o.ok],
                  ['skew exceeded this', o.run(o.resp(this: n + 1001), skew: 1000), fut_this],
                  ['skew allows produced', o.run(o.resp(produced: n + 1000), skew: 1000), o.ok],
                  ['skew exceeded produced', o.run(o.resp(produced: n + 1001), skew: 1000), fut_prod],
                  ['next before this', o.run(o.resp(after: nu.(n - 2000))), o.no('response nextUpdate is invalid')],
                  ['next = now', o.run(o.resp(after: nu.(n))), o.ok],
                  ['next one ms past', o.run(o.resp(after: nu.(n - 1))), o.no('response is stale (past nextUpdate)')],
                  ['seven days old', o.run(o.resp(this: n - day7)), o.ok], ['seven days and a ms', o.run(o.resp(this: n - day7 - 1)), old],
                  ['explicit age equal', o.run(o.resp(this: n - 1000), max_age: 1000), o.ok],
                  ['explicit age exceeded', o.run(o.resp(this: n - 1001), max_age: 1000), old],
                  ['explicit age smaller than default', o.run(o.resp(this: n - 1000), max_age: 500), old]
                ])
  end

  t('OCSP revoked certStatus: the revocation time must be a plain GeneralizedTime') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    n = o::NOW
    bad = o.no('malformed revoked certStatus')
    C12Ocsp.chk([['revoked', o.run(o.resp(status: o.tlv(0xA1, o.gt(n - 5000)))), o.ok('revoked')],
                 ['fraction', o.run(o.resp(status: o.tlv(0xA1, o.gt(n - 5001)))), bad],
                 ['not a time', o.run(o.resp(status: o.tlv(0xA1, o.tlv(0x04, 'x')))), bad], ['empty', o.run(o.resp(status: o.tlv(0xA1))), bad],
                 ['thisUpdate as utc', o.run(o.resp(this: o.tlv(0x17, '270115075000Z'))), o.rej('thisUpdate is malformed')]])
  end

  t('OCSP default clock skew is zero') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    cert = o.co(:leaf)
    issuer = o.co(:inter)
    chain = %i[leaf inter root].map { |x| o.co(x) }
    fut = o.no('response thisUpdate is in the future')
    C12Ocsp.chk([['equal', o.oc.verify_ocsp_response(o.resp(this: o::NOW), cert, issuer, chain, o::NOW), o.ok],
                 ['one ms ahead', o.oc.verify_ocsp_response(o.resp(this: o::NOW + 1), cert, issuer, chain, o::NOW), fut],
                 ['explicit nil age', o.oc.verify_ocsp_response(o.resp(this: o::NOW + 1), cert, issuer, chain, o::NOW, nil), fut]])
  end

  # ================================================================================================ the chain check
  t('OCSP check_nvidia_chain_ocsp: every refusal with its exact reason and statuses, counts on success') do
    next true if C12Ocsp.skip?

    o = C12Ocsp
    c3 = %i[leaf inter root].map { |x| o.co(x) }
    c3a = %i[leaf_aia inter root].map { |x| o.co(x) }
    c2 = c3.first(2)
    ck = ->(chain, resps, age = nil) { o.oc.check_nvidia_chain_ocsp(chain, resps, o::NOW, age) }
    r_leaf = o.resp
    r_int = o.resp(cert: :inter, issuer: :root, signer: :root, rid: o.rid_name(o.fx[:root]))
    r_aia = o.resp(cert: :leaf_aia)
    r_aia_unknown = o.resp(cert: :leaf_aia, status: o.tlv(0x82))
    r_rev = o.resp(status: o.tlv(0xA1, o.gt(o::NOW - 5000)))
    r_stale = o.resp(after: [o.tlv(0xA0, o.gt(o::NOW - 500))])
    r_other = o.resp(id: o.cid(o.fx[:leaf], o.fx[:inter], serial: OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(5)).to_der))
    d = o.dcert(signer: :root, issuer_cn: 'root', serial: 78)
    r_both = o.resp(singles: [o.single(o.cid(o.fx[:leaf], o.fx[:inter])), o.single(o.cid(o.fx[:inter], o.fx[:root]))],
                    rid: o.rid_name(d), signer: :resp, certs: [d])
    C12Ocsp.chk([
                  ['too short', ck.([c3[0]], [r_leaf]), { 'ok' => false, 'reason' => 'chain too short for OCSP' }],
                  ['no responses', ck.(c3, []), { 'ok' => false, 'reason' => 'no OCSP responses supplied' }],
                  ['two certificates', ck.(c2, [r_leaf]),
                   { 'ok' => true, 'verifiedCrls' => 0, 'verifiedOcsp' => 1, 'statuses' => { 0 => 'good' } }],
                  ['both certificates', ck.(c3, [r_leaf, r_int]),
                   { 'ok' => true, 'verifiedCrls' => 0, 'verifiedOcsp' => 2, 'statuses' => { 0 => 'good', 1 => 'good' } }],
                  ['one of two', ck.(c3, [r_leaf]),
                   { 'ok' => true, 'verifiedCrls' => 0, 'verifiedOcsp' => 1, 'statuses' => { 0 => 'good', 1 => 'absent' } }],
                  ['required missing', ck.(c3a, [r_int]),
                   { 'ok' => false, 'reason' => "no GOOD OCSP response for required certificate 'CN=leaf' (status: absent)",
                     'statuses' => { 0 => 'absent', 1 => 'good' } }],
                  ['required unknown', ck.(c3a, [r_aia_unknown]),
                   { 'ok' => false, 'reason' => "no GOOD OCSP response for required certificate 'CN=leaf' (status: unknown)",
                     'statuses' => { 0 => 'unknown', 1 => 'absent' } }],
                  ['required good', ck.(c3a, [r_aia]),
                   { 'ok' => true, 'verifiedCrls' => 0, 'verifiedOcsp' => 1, 'statuses' => { 0 => 'good', 1 => 'absent' } }],
                  ['revoked', ck.(c3, [r_rev]),
                   { 'ok' => false, 'reason' => "chain certificate 'CN=leaf' is revoked (OCSP)", 'statuses' => { 0 => 'revoked', 1 => 'absent' } }],
                  ['duplicate', ck.(c3, [r_leaf, r_leaf]),
                   { 'ok' => false, 'reason' => 'duplicate OCSP responses for chain certificate #0',
                     'statuses' => { 0 => 'good', 1 => 'absent' } }],
                  ['matches nothing', ck.(c3, [r_other]),
                   { 'ok' => false, 'reason' => "OCSP response #0 rejected: #{C12Ocsp::NO_MATCH}", 'statuses' => { 0 => 'absent', 1 => 'absent' } }],
                  ['rejected response', ck.(c3, [r_stale]),
                   { 'ok' => false, 'reason' => "OCSP response #0 for 'CN=leaf' rejected: response is stale (past nextUpdate)",
                     'statuses' => { 0 => 'absent', 1 => 'absent' } }],
                  ['rejected second response', ck.(c3, [r_leaf, r_stale]),
                   { 'ok' => false, 'reason' => "OCSP response #1 for 'CN=leaf' rejected: response is stale (past nextUpdate)",
                     'statuses' => { 0 => 'good', 1 => 'absent' } }],
                  ['more than one certificate', ck.(c3, [r_both]),
                   { 'ok' => false, 'reason' => 'OCSP response #0 matches more than one chain certificate',
                     'statuses' => { 0 => 'good', 1 => 'absent' } }],
                  ['maximum age passed on', ck.(c3, [r_leaf], 500),
                   { 'ok' => false, 'reason' => "OCSP response #0 for 'CN=leaf' rejected: response is older than the maximum accepted age",
                     'statuses' => { 0 => 'absent', 1 => 'absent' } }]
                ])
  end
end
