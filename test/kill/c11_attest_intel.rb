# frozen_string_literal: true

# Exact-outcome kill tests for lib/atlas_pca/attest/intel.rb (Intel TDX DCAP quote, PCK chain, PCS collateral, the verifier).
# Expected values pin the TypeScript reference (packages/pca/src/attest-intel-tdx.ts, attest-intel-collateral.ts, attest-intel-dcap.ts):
#  * every row of the intel-tdx-dcap vendor of packages/pca/conformance/attestation-evidence-vectors.json, copied to
#    test-data/c11-intel-rows.json.gz (the mutation checkout may not carry packages/pca), replayed through the native verifier;
#  * unit tests of the pure helpers (DER readers, quote parser, CRL parser, JSON object scanner, date parser, TCB / QE evaluation)
#    on hand-built bytes, with the reference's messages.
# AtlasPca is dropped and re-evaluated for every mutant, so every module is resolved at CALL time (never cached in a constant).
require 'timeout'
require 'json'
require 'zlib'
require 'tmpdir'
require 'fileutils'
require 'rbconfig'
require 'openssl'
require 'digest'
require 'base64'
require 'atlas_pca/attest'

module MutationKill
  module C11Intel
    module_function

    DATA = File.expand_path('../../test-data/c11-intel-rows.json.gz', __dir__)
    LIB = File.expand_path('../../lib', __dir__)

    # These tests bear on attest/intel.rb only (the oracle exports MUT_FILE; run_kill.rb leaves it unset).
    def skip? = (f = ENV['MUT_FILE']) && !f.empty? && f != 'intel.rb'
    def mutating? = (f = ENV['MUT_FILE']) && !f.empty?

    def i = AtlasPca::Attest::Intel
    def cm = AtlasPca::Attest::Common
    def tm(secs = 2, &) = Timeout.timeout(secs, &)

    def err
      yield
      nil
    rescue Exception => e # rubocop:disable Lint/RescueException
      [e.class, e.message]
    end

    # rows: [label, got, want]; true when all agree, else raises with the first mismatches.
    def ck(rows)
      bad = rows.reject { |_l, got, want| got == want }
      return true if bad.empty?

      raise "mismatch: #{bad.first(3).map { |l, g, w| "#{l}: got #{g.inspect} want #{w.inspect}" }.join(' | ')}"
    end

    def b(*bytes) = bytes.pack('C*')
    def ms(*a) = Time.utc(*a).to_i * 1000

    def tlv(tag, *parts)
      body = parts.map(&:b).join.b
      n = body.bytesize
      len = if n < 128 then [n].pack('C')
            elsif n < 256 then b(0x81, n)
            else b(0x82, n >> 8, n & 0xFF)
            end
      [tag].pack('C') + len + body
    end

    # ---- data

    def doc
      @doc ||= JSON.parse(Zlib::GzipReader.open(DATA, &:read), max_nesting: false)
    end

    def hydrate(x)
      case x
      when Array then x.map { |e| hydrate(e) }
      when Hash then x.keys == ['$blob'] ? doc['blobs'].fetch(x['$blob']) : x.to_h { |k, v| [k, hydrate(v)] }
      else x
      end
    end

    def row(id) = hydrate(doc['rows'].find { |r| r['id'] == id })
    def real = row('tdx-real-positive')
    def real_quote = cm.node_b64decode(real['evidence']['quote'])
    def real_now = real['now']
    def real_col = real['evidence']['collateral']

    # ---- EC helpers
    def ec = (@ec ||= OpenSSL::PKey::EC.generate('prime256v1'))
    def ec2 = (@ec2 ||= OpenSSL::PKey::EC.generate('prime256v1'))
    def rsa = (@rsa ||= OpenSSL::PKey::RSA.generate(2048))

    def compact(key, data)
      OpenSSL::ASN1.decode(key.sign(OpenSSL::Digest.new('sha256'), data)).value.map { |v| v.value.to_s(2).rjust(32, "\x00".b) }.join
    end

    # ---- DCAP quote builder
    def hdr(version: 4, key: 2, tee: 0x81) = [version, key].pack('vv') + [tee].pack('V') + ("\x55".b * 40)
    def td = "\x66".b * 584

    def sigdata(auth: ''.b, pck: ''.b, outer_type: 6, inner_type: 5, outer_size: nil, inner_size: nil)
      nat = 384 + 64 + 2 + auth.bytesize + 6 + pck.bytesize
      ("\x11".b * 64) + ("\x22".b * 64) + [outer_type].pack('v') + [outer_size || nat].pack('V') + ("\x33".b * 384) + ("\x44".b * 64) +
        [auth.bytesize].pack('v') + auth + [inner_type].pack('v') + [inner_size || pck.bytesize].pack('V') + pck
    end

    def quote(sd, pad: ''.b, sig_len: nil, **h) = hdr(**h) + td + [sig_len || sd.bytesize].pack('V') + sd + pad

    def trunc(sig_len, outer_size, auth_size)
      full = ("\x11".b * 64) + ("\x22".b * 64) + [6].pack('v') + [outer_size].pack('V') + ("\x33".b * 384) + ("\x44".b * 64) +
             [auth_size].pack('v') + ('A'.b * auth_size) + [5].pack('v') + [0].pack('V')
      quote(full.byteslice(0, sig_len))
    end

    def parse_err(q) = err { i.parse_dcap_quote(q) }

    # ---- JSON signed documents
    def signed(name, raw, key, hex: nil)
      sig = hex || compact(key, raw).unpack1('H*')
      %({"#{name}":#{raw},"signature":"#{sig}"})
    end

    # ---- CRL builder
    SIG_ALG = [0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02].pack('C*').freeze

    def dn(cn = 'root') = tlv(0x30, tlv(0x31, tlv(0x30, tlv(0x06, "\x55\x04\x03".b), tlv(0x0c, cn))))
    def utc(s) = tlv(0x17, s)
    def gen(s) = tlv(0x18, s)
    def entry(serial_bytes, t = '261008212848Z') = tlv(0x30, tlv(0x02, serial_bytes), utc(t))

    def crl(parts, key = ec, sig_alg: SIG_ALG)
      tbs = tlv(0x30, *parts)
      tlv(0x30, tbs, sig_alg, tlv(0x03, "\x00".b, key.sign(OpenSSL::Digest.new('sha256'), tbs)))
    end

    THIS = '261008212848Z'
    NEXT = '261107212848Z'

    def base(this = utc(THIS), nxt = utc(NEXT), *rest, version: true)
      [*(version ? [tlv(0x02, "\x01".b)] : []), SIG_ALG, dn, this, nxt, *rest]
    end

    def vc(der, now, key = ec) = i.verify_crl(der, key, now)

    # ---- fresh Ruby over the mutated text (an in-process require is already satisfied)
    def source(rel)
      path = File.join(LIB, rel)
      if defined?(::Oracle) && (tgt = ::Oracle.instance_variable_get(:@target)) && File.expand_path(tgt) == path
        ::Oracle.instance_variable_get(:@text)
      else
        File.read(path)
      end
    end

    def fresh(rel, code)
      Dir.mktmpdir('c11fresh') do |d|
        FileUtils.cp_r(LIB, d)
        File.write(File.join(d, 'lib', rel), source(rel))
        gems = Gem.loaded_specs.values.flat_map(&:full_require_paths).flat_map { |g| ['-I', g] }
        out = IO.popen([RbConfig.ruby, '--disable-gems', '-I', File.join(d, 'lib'), *gems, '-e', code], 'r', err: File::NULL, &:read)
        [out, $?.success?]
      end
    end


    # ---- PCK extension builder
    def sgx_ext(fmspc: "\x01\x02\x03\xF4\xE5\xD6".b, pairs: [], fmspc_oid: true, tcb_oid: true)
      f = fmspc_oid ? i::OID_SGX_FMSPC + tlv(0x04, fmspc) : ''.b
      t = tcb_oid ? i::OID_SGX_TCB + tlv(0x30, *pairs) : ''.b
      'junk'.b + f + 'mid'.b + t
    end

    def pair(idx, value_tlv) = tlv(0x30, tlv(0x06, "\x2A\x86\x48\x86\xF8\x4D\x01\x0D\x01\x02".b + [idx].pack('C')), value_tlv)
    def intv(*bytes) = tlv(0x02, bytes.pack('C*'))

    # [leaf, platform CA, root] PEM blocks of a quote's chain, by role (not by position)
    def parts(pem)
      blocks = cm.pem_blocks(pem)
      certs = blocks.map { |bl| AtlasPca::Attest::Cert.from_pem(bl) }
      root = certs.index { |x| x.subject == x.issuer }
      leaf = certs.index { |x| certs.none? { |y| y.issuer == x.subject } }
      ca = (0...certs.size).find { |k| k != root && k != leaf }
      [blocks[leaf], blocks[ca], blocks[root]]
    end

    # a DER element: [tag, start, end] (own reader, so a mutated reader cannot bend the fixtures)
    def rd(b, off)
      l = b.getbyte(off + 1)
      return [b.getbyte(off), off + 2, off + 2 + l] if l < 128

      n = l & 0x7F
      len = b.byteslice(off + 2, n).bytes.inject(0) { |a, x| (a * 256) + x }
      [b.getbyte(off), off + 2 + n, off + 2 + n + len]
    end

    # ---- TCB / QE fixtures
    Z16 = ([0] * 16).freeze
    MOD = { 'mrsigner' => 'ab' * 48, 'attributes' => '00' * 8, 'attributesMask' => 'ff' * 8 }.freeze

    def comps(arr) = arr.map { |v| { 'svn' => v } }

    def level(sgx = Z16, tdx = Z16, pce = 0, st = 'UpToDate', adv = nil)
      l = { 'tcb' => { 'sgxtcbcomponents' => comps(sgx), 'tdxtcbcomponents' => comps(tdx), 'pcesvn' => pce }, 'tcbStatus' => st }
      l['advisoryIDs'] = adv unless adv.nil?
      l
    end

    def pck(sgx = Z16, pce = 0) = { 'sgx' => sgx.pack('C*'), 'pcesvn' => pce }

    def tdr(minor: 0, svn0: 0, rest: nil, signer: "\xab".b * 48, attr: "\x00".b * 8)
      svn = [svn0, minor] + (rest || ([0] * 14))
      { 'teeTcbSvn' => svn.pack('C*'), 'mrSignerSeam' => signer, 'seamAttributes' => attr }
    end

    def etcb(info, p = pck, t = tdr) = tm { i.evaluate_tcb(info, p, t) }
    def info_of(levels, mod = MOD) = { 'tdxModule' => mod, 'tcbLevels' => levels }

    def qe_bytes(misc: [1, 2, 3, 4], attrs: (1..16).to_a, signer: ("\xcd".b * 32), prod: 0x0102, isv: 0x0304)
      q = "\x00".b * 384
      q[16, 4] = misc.pack('C*')
      q[48, 16] = attrs.pack('C*')
      q[128, 32] = signer
      q[256, 2] = [prod].pack('v')
      q[258, 2] = [isv].pack('v')
      q
    end

    def qe_ident(**o)
      { 'id' => 'TD_QE', 'version' => 2, 'miscselect' => '01020304', 'miscselectMask' => 'ffffffff', 'attributes' => (1..16).to_a.pack('C*').unpack1('H*'),
        'attributesMask' => 'ff' * 16, 'mrsigner' => 'cd' * 32, 'isvprodid' => 0x0102,
        'tcbLevels' => [{ 'tcb' => { 'isvsvn' => 0x0304 }, 'tcbStatus' => 'UpToDate', 'advisoryIDs' => ['Q1'] }] }.merge(o.transform_keys(&:to_s))
    end
  end

  # ================================================================================================ constants and loading
  t('c11: intel constants, frozen tables, and the module loads amd on its own (fresh ruby over the mutated text)') do
    next true if C11Intel.skip?

    i = C11Intel.i
    C11Intel.ck([
                  ['suite', i::SUITE, 'intel-tdx-dcap-ecdsa-p256'],
                  ['pin', i::SGX_ROOT_CA_SPKI_SHA256, 'a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e'],
                  ['sizes', [i::HEADER_LEN, i::TD_REPORT_LEN, i::QE_ATTRIBUTES_OFF, i::QE_REPORT_DATA_OFF, i::SGX_REPORT_LEN], [48, 584, 48, 0x140, 384]],
                  ['fmspc oid', i::OID_SGX_FMSPC.bytes, [6, 10, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 1, 0x0D, 1, 4]],
                  ['tcb oid', i::OID_SGX_TCB.bytes, [6, 10, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 1, 0x0D, 1, 2]],
                  ['status order', i::STATUS_ORDER, %w[UpToDate SWHardeningNeeded ConfigurationNeeded ConfigurationAndSWHardeningNeeded OutOfDateConfigurationNeeded OutOfDate Revoked]],
                  ['default accepted', i::DEFAULT_ACCEPTED_STATUSES, %w[UpToDate SWHardeningNeeded]],
                  ['frozen', [i::OID_SGX_FMSPC.frozen?, i::OID_SGX_TCB.frozen?, i::STATUS_ORDER.frozen?, i::DEFAULT_ACCEPTED_STATUSES.frozen?], [true] * 4]
                ])
    rel = 'atlas_pca/attest/intel.rb'
    next true if C11Intel.mutating? && C11Intel.source(rel).lines.first(10) == File.read(File.join(C11Intel::LIB, rel)).lines.first(10)

    out, ok = C11Intel.fresh(rel, "require 'atlas_pca/attest/intel'; puts $LOADED_FEATURES.filter_map { |f| f[%r{/lib/(atlas_pca/.*)}, 1] }; puts AtlasPca::Attest::Intel::SUITE")
    want = %w[common der cert amd intel].map { |n| "atlas_pca/attest/#{n}.rb" }
    ok && out == "#{want.join("\n")}\nintel-tdx-dcap-ecdsa-p256\n"
  end

  # ================================================================================================ small readers
  t('c11: u16 / u32 are little endian, at an offset') do
    next true if C11Intel.skip?

    i = C11Intel.i
    C11Intel.ck([['u16', i.u16("\x00\x01\x02\x03".b, 1), 0x0201], ['u32', i.u32("\x00\x01\x02\x03\x04".b, 1), 0x04030201],
                 ['zero?', [i.zero?("\x00\x00".b), i.zero?(''.b), i.zero?("\x00\x01".b), i.zero?("\x01\x00".b)], [true, true, false, false]]])
  end

  t('c11: parse_dcap_td_report slices every field at its offset; a body one byte short is refused') do
    next true if C11Intel.skip?

    i = C11Intel.i
    body = (0...600).map { |k| ((k * 7) + 3) & 0xFF }.pack('C*')
    r = i.parse_dcap_td_report(body)
    C11Intel.ck([
                  ['teeTcbSvn', r['teeTcbSvn'], body.byteslice(0, 16)], ['mrSeam', r['mrSeam'], body.byteslice(16, 48)],
                  ['mrSignerSeam', r['mrSignerSeam'], body.byteslice(64, 48)], ['tdAttributes', r['tdAttributes'], body.byteslice(120, 8)],
                  ['mrTd', r['mrTd'], body.byteslice(136, 48)], ['rtmr0', r['rtmr0'], body.byteslice(328, 48)],
                  ['reportData', r['reportData'], body.byteslice(520, 64)], ['keys', r.keys, %w[teeTcbSvn mrSeam mrSignerSeam tdAttributes mrTd rtmr0 reportData]],
                  ['584 ok', i.parse_dcap_td_report(body.byteslice(0, 584))['reportData'], body.byteslice(520, 64)],
                  ['583', C11Intel.err { i.parse_dcap_td_report(body.byteslice(0, 583)) }, [ArgumentError, 'parseDcapTdReport: body too short (583 < 584)']]
                ])
  end

  # ================================================================================================ quote parser
  t('c11: parse_dcap_quote returns every part exactly, binary, from a binary or a UTF-8-tagged quote') do
    next true if C11Intel.skip?

    c = C11Intel
    auth = 'xy'.b
    pck = "-----PEM \xE9-----".b
    q = c.quote(c.sigdata(auth: auth, pck: pck), pad: "\x00".b * 70)
    [q, q.dup.force_encoding('UTF-8')].map do |input|
      r = c.i.parse_dcap_quote(input)
      c.ck([
             ['header', r['header'], c.hdr], ['td', r['tdReportBody'], c.td], ['sig', r['quoteSignature'], "\x11".b * 64], ['ak', r['akPubRaw'], "\x22".b * 64],
             ['qe', r['qeReportBody'], "\x33".b * 384], ['qesig', r['qeReportSignature'], "\x44".b * 64], ['auth', r['qeAuthData'], auth],
             ['pem', r['pckChainPem'], "-----PEM \u00e9-----"], ['pem enc', r['pckChainPem'].encoding, Encoding::UTF_8],
             ['keys', r.keys, %w[header tdReportBody quoteSignature akPubRaw qeReportBody qeReportSignature qeAuthData pckChainPem]],
             ['binary', r.reject { |k, _| k == 'pckChainPem' }.values.map(&:encoding).uniq, [Encoding::BINARY]]
           ])
    end.all?
  end

  t('c11: parse_dcap_quote: header and structure refusals, exact messages and boundaries') do
    next true if C11Intel.skip?

    c = C11Intel
    a = ArgumentError
    ok = c.sigdata(auth: 'xy'.b, pck: 'ABC'.b)
    n = ok.bytesize
    short = 'parseDcapQuote: too short for header + TD report + sig length'
    c.ck([
           ['635', c.parse_err(c.hdr + c.td + "\x00\x00\x00".b), [a, short]],
           ['636', c.parse_err(c.hdr + c.td + "\x00\x00\x00\x00".b), [a, 'parseDcapQuote: truncated reading quote signature']],
           ['empty', c.parse_err(''.b), [a, short]],
           ['version 3', c.parse_err(c.quote(ok, version: 3)), [a, 'parseDcapQuote: unsupported quote version 3 (expected 4)']],
           ['version 5', c.parse_err(c.quote(ok, version: 5)), [a, 'parseDcapQuote: unsupported quote version 5 (expected 4)']],
           ['version first', c.parse_err(c.quote(ok, version: 3, key: 3, tee: 0)), [a, 'parseDcapQuote: unsupported quote version 3 (expected 4)']],
           ['key 3', c.parse_err(c.quote(ok, key: 3)), [a, 'parseDcapQuote: unsupported attestation key type 3 (expected ECDSA-P256 = 2)']],
           ['key before tee', c.parse_err(c.quote(ok, key: 1, tee: 0)), [a, 'parseDcapQuote: unsupported attestation key type 1 (expected ECDSA-P256 = 2)']],
           ['tee 0x82', c.parse_err(c.quote(ok, tee: 0x82)), [a, 'parseDcapQuote: unexpected TEE type 0x82 (expected TDX = 0x81)']],
           ['tee 0', c.parse_err(c.quote(ok, tee: 0)), [a, 'parseDcapQuote: unexpected TEE type 0x0 (expected TDX = 0x81)']],
           ['tee 0x181', c.parse_err(c.quote(ok, tee: 0x181)), [a, 'parseDcapQuote: unexpected TEE type 0x181 (expected TDX = 0x81)']],
           ['sig overruns', c.parse_err(c.quote(ok, sig_len: n + 1)), [a, "parseDcapQuote: signature data (#{n + 1}) overruns the quote"]],
           ['sig fits', c.parse_err(c.quote(ok, sig_len: n)), nil],
           ['outer type', c.parse_err(c.quote(c.sigdata(auth: 'xy'.b, pck: 'ABC'.b, outer_type: 7))),
            [a, 'parseDcapQuote: outer cert-data type 7 (expected QE-report-cert-data = 6)']],
           ['outer overruns', c.parse_err(c.quote(c.sigdata(auth: 'xy'.b, pck: 'ABC'.b, outer_size: (384 + 64 + 2 + 2 + 6 + 3) + 1))),
            [a, 'parseDcapQuote: outer cert-data overruns signature data']],
           ['outer exact', c.parse_err(c.quote(c.sigdata(auth: 'xy'.b, pck: 'ABC'.b, outer_size: 384 + 64 + 2 + 2 + 6 + 3))), nil],
           ['inner type', c.parse_err(c.quote(c.sigdata(auth: 'xy'.b, pck: 'ABC'.b, inner_type: 6))),
            [a, 'parseDcapQuote: inner cert-data type 6 (expected PCK-cert-chain = 5)']],
           ['inner overruns', c.parse_err(c.quote(c.sigdata(auth: 'xy'.b, pck: 'ABC'.b, inner_size: 4))),
            [a, 'parseDcapQuote: inner cert-data overruns outer cert-data']],
           ['inner exact', c.parse_err(c.quote(c.sigdata(auth: 'xy'.b, pck: 'ABC'.b, inner_size: 3))), nil],
           ['inner short', c.i.parse_dcap_quote(c.quote(c.sigdata(auth: 'xy'.b, pck: 'ABC'.b, inner_size: 2)))['pckChainPem'], 'AB'],
           ['pad zero', c.parse_err(c.quote(ok, pad: "\x00\x00\x00".b)), nil],
           ['pad last', c.parse_err(c.quote(ok, pad: "\x00\x00\x01".b)), [a, 'parseDcapQuote: non-zero bytes after the signature data']],
           ['pad first', c.parse_err(c.quote(ok, pad: "\x01\x00\x00".b)), [a, 'parseDcapQuote: non-zero bytes after the signature data']],
           ['pad one', c.parse_err(c.quote(ok, pad: "\x01".b)), [a, 'parseDcapQuote: non-zero bytes after the signature data']]
         ])
  end

  t('c11: parse_dcap_quote: a signature data block cut at every field boundary names the field it truncates') do
    next true if C11Intel.skip?

    c = C11Intel
    a = ArgumentError
    m = ->(w) { [a, "parseDcapQuote: truncated reading #{w}"] }
    cases = [[63, 0, 0, 'quote signature'], [64, 0, 0, 'attestation public key'], [127, 0, 0, 'attestation public key'],
             [128, 0, 0, 'outer cert-data header'], [133, 0, 0, 'outer cert-data header'], [134, 0, 0, 'QE report'], [517, 0, 0, 'QE report'],
             [518, 0, 0, 'QE report signature'], [581, 0, 0, 'QE report signature'], [582, 0, 0, 'QE auth-data size'], [583, 0, 0, 'QE auth-data size'],
             [584, 0, 0, 'inner cert-data header'], [589, 0, 0, 'inner cert-data header'], [584, 0, 1, 'QE auth-data'], [588, 0, 5, 'QE auth-data'],
             [585, 0, 1, 'inner cert-data header'], [589, 0, 5, 'inner cert-data header']]
    rows = cases.map { |sl, os, as, w| ["cut #{sl}/#{as}", c.parse_err(c.trunc(sl, os, as)), m.call(w)] }
    rows << ['inner header whole, outer empty', c.parse_err(c.trunc(590, 0, 0)), [a, 'parseDcapQuote: inner cert-data overruns outer cert-data']]
    c.ck(rows)
  end

  # ================================================================================================ DER readers
  t('c11: read_der_tlv: tags, short and long lengths, every nil, boundary on both sides') do
    next true if C11Intel.skip?

    c = C11Intel
    r = ->(s, o = 0) { c.i.read_der_tlv(s.b, o) }
    h = ->(tag, st, en) { { 'tag' => tag, 'start' => st, 'end' => en } }
    c.ck([
           ['short', r.call("\x30\x03abc"), h.call(0x30, 2, 5)], ['empty body', r.call("\x30\x00"), h.call(0x30, 2, 2)],
           ['offset', r.call("zz\x04\x01a", 2), h.call(4, 4, 5)], ['one byte', r.call("\x30"), nil], ['offset past', r.call("\x30\x00", 1), nil],
           ['offset exact', r.call("\x30\x00\x30\x00", 2), h.call(0x30, 4, 4)],
           ['long 1', r.call("\x30\x81\x05abcde"), h.call(0x30, 3, 8)], ['long 2', r.call("\x30\x82\x00\x00"), h.call(0x30, 4, 4)],
           ['long 4 empty', r.call("\x30\x84\x00\x00\x00\x00"), h.call(0x30, 6, 6)],
           ['long 4 body', r.call("\x30\x84\x00\x00\x00\x02ab"), h.call(0x30, 6, 8)],
           ['256', r.call("\x30\x82\x01\x00" + ('a' * 256)), h.call(0x30, 4, 260)], ['258', r.call("\x30\x82\x01\x02" + ('a' * 258)), h.call(0x30, 4, 262)],
           ['257 short', r.call("\x30\x82\x01\x01" + ('a' * 256)), nil],
           ['n=0', r.call("\x30\x80\x00"), nil], ['n=5', r.call("\x30\x85\x00\x00\x00\x00\x00"), nil], ['n beyond', r.call("\x30\x82\x01"), nil],
           ['n=1 beyond', r.call("\x30\x81"), nil], ['overrun', r.call("\x30\x02\x00"), nil], ['exact', r.call("\x30\x02\x00\x00"), h.call(0x30, 2, 4)]
         ])
  end

  t('c11: tlv (the CRL reader): same shapes, errors raised with their messages, a limit narrower than the buffer is honoured') do
    next true if C11Intel.skip?

    c = C11Intel
    t3 = ->(s, o = 0, lim = nil) { r = c.i.tlv(s.b, o, lim); [r.tag, r.start, r.end_, r.next_] }
    e = ->(s, o = 0, lim = nil) { c.err { c.i.tlv(s.b, o, lim) } }
    a = ArgumentError
    c.ck([
           ['short', t3.call("\x30\x03abc"), [0x30, 2, 5, 5]], ['empty', t3.call("\x30\x00"), [0x30, 2, 2, 2]], ['offset', t3.call("zz\x04\x01a", 2), [4, 4, 5, 5]],
           ['long 1', t3.call("\x30\x81\x05abcde"), [0x30, 3, 8, 8]], ['long 2 empty', t3.call("\x30\x82\x00\x00"), [0x30, 4, 4, 4]],
           ['long 4', t3.call("\x30\x84\x00\x00\x00\x01a"), [0x30, 6, 7, 7]], ['258', t3.call("\x30\x82\x01\x02" + ('a' * 258)), [0x30, 4, 262, 262]],
           ['256', t3.call("\x30\x82\x01\x00" + ('a' * 256)), [0x30, 4, 260, 260]],
           ['trunc 1', e.call("\x30"), [a, 'DER truncated']], ['trunc offset', e.call("\x30\x00", 1), [a, 'DER truncated']],
           ['trunc limit', e.call("\x30\x00\x00\x00", 1, 2), [a, 'DER truncated']], ['limit exact', t3.call("\x30\x00\x00\x00", 0, 2), [0x30, 2, 2, 2]],
           ['n=0', e.call("\x30\x80\x00"), [a, 'DER bad length']], ['n=5', e.call("\x30\x85\x00\x00\x00\x00\x00"), [a, 'DER bad length']],
           ['n beyond', e.call("\x30\x82\x01"), [a, 'DER bad length']], ['n beyond limit', e.call("\x30\x82\x00\x00", 0, 3), [a, 'DER bad length']],
           ['n=1 at limit', e.call("\x30\x81\x00", 0, 3), nil],
           ['overrun', e.call("\x30\x02\x00"), [a, 'DER overrun']], ['overrun limit', e.call("\x30\x05abcde", 0, 4), [a, 'DER overrun']],
           ['exact', t3.call("\x30\x02\x00\x00"), [0x30, 2, 4, 4]]
         ])
  end

  # ================================================================================================ PCK extension reader
  t('c11: extract_pck_fmspc_and_tcb reads the FMSPC and the 16 components + PCESVN (shifts, ranges, ignored indexes, 64-pair bound)') do
    next true if C11Intel.skip?

    c = C11Intel
    m = ->(s) { c.err { c.i.extract_pck_fmspc_and_tcb(s) } }
    a = ArgumentError
    pre = 'extractPckFmspcAndTcb: '
    good_pairs = (1..16).map { |k| c.pair(k, c.intv(k + 100)) }
    pairs = good_pairs + [c.pair(17, c.intv(0x01, 0x12, 0x34)), c.pair(0, c.intv(9)), c.pair(18, c.intv(9)), c.pair(16, c.tlv(0x04, "\x55".b)), c.pair(1, c.intv(0x01, 0x02))]
    r = c.i.extract_pck_fmspc_and_tcb(c.sgx_ext(fmspc: "\x01\x02\x03\xF4\xE5\xD6".b, pairs: pairs).dup.force_encoding('UTF-8'))
    want_sgx = (1..16).map { |k| k + 100 }
    want_sgx[0] = 2 # the later two-byte INTEGER 0x0102 & 0xFF
    pcesvn_only = c.i.extract_pck_fmspc_and_tcb(c.sgx_ext(pairs: [c.pair(17, c.intv(0))]))
    # 64 pairs of filler, then the 65th (still processed) carries the PCESVN, the 66th is beyond the bound
    filler = Array.new(64) { c.pair(1, c.intv(1)) }
    bound = c.i.extract_pck_fmspc_and_tcb(c.sgx_ext(pairs: filler + [c.pair(17, c.intv(7)), c.pair(2, c.intv(0x77))]))
    no_pce_in_64 = m.call(c.sgx_ext(pairs: Array.new(63) { c.pair(1, c.intv(1)) } + [c.pair(17, c.intv(7))]))
    c.ck([
           ['fmspc', r['fmspc'], "\x01\x02\x03\xF4\xE5\xD6".b], ['sgx', r['sgxTcbComponents'].bytes, want_sgx], ['pcesvn', r['pcesvn'], 0x1234],
           ['keys', r.keys, %w[fmspc sgxTcbComponents pcesvn]], ['sgx len', r['sgxTcbComponents'].bytesize, 16],
           ['pcesvn 0', pcesvn_only['pcesvn'], 0], ['zeros', pcesvn_only['sgxTcbComponents'], "\x00".b * 16],
           ['bound sgx', bound['sgxTcbComponents'].bytes, [1] + ([0] * 15)], ['bound pce', bound['pcesvn'], 7], ['63 filler fine', no_pce_in_64, nil],
           ['no fmspc oid', m.call(c.sgx_ext(fmspc_oid: false, pairs: [c.pair(17, c.intv(1))])), [a, "#{pre}FMSPC OID not found in certificate"]],
           ['fmspc 5', m.call(c.sgx_ext(fmspc: 'abcde', pairs: [c.pair(17, c.intv(1))])), [a, "#{pre}malformed FMSPC OCTET STRING"]],
           ['fmspc 7', m.call(c.sgx_ext(fmspc: 'abcdefg', pairs: [c.pair(17, c.intv(1))])), [a, "#{pre}malformed FMSPC OCTET STRING"]],
           ['fmspc tag', m.call(c.i::OID_SGX_FMSPC + c.tlv(0x0c, 'abcdef') + c.i::OID_SGX_TCB + c.tlv(0x30)), [a, "#{pre}malformed FMSPC OCTET STRING"]],
           ['fmspc cut', m.call("x".b + c.i::OID_SGX_FMSPC), [a, "#{pre}malformed FMSPC OCTET STRING"]],
           ['no tcb oid', m.call(c.sgx_ext(tcb_oid: false)), [a, "#{pre}TCB OID not found in certificate"]],
           ['tcb cut', m.call(c.i::OID_SGX_FMSPC + c.tlv(0x04, 'abcdef') + c.i::OID_SGX_TCB), [a, "#{pre}malformed TCB SEQUENCE"]],
           ['tcb tag', m.call(c.i::OID_SGX_FMSPC + c.tlv(0x04, 'abcdef') + c.i::OID_SGX_TCB + c.tlv(0x31)), [a, "#{pre}malformed TCB SEQUENCE"]],
           ['pce missing', m.call(c.sgx_ext(pairs: good_pairs)), [a, "#{pre}PCESVN not found in TCB extension"]],
           ['empty seq', m.call(c.sgx_ext(pairs: [])), [a, "#{pre}PCESVN not found in TCB extension"]],
           ['pair tag', m.call(c.sgx_ext(pairs: [c.tlv(0x31, 'ab')])), [a, "#{pre}malformed TCB component"]],
           ['pair overruns', m.call(c.i::OID_SGX_FMSPC + c.tlv(0x04, 'abcdef') + c.i::OID_SGX_TCB + "\x30\x03\x30\x05\x00".b), [a, "#{pre}malformed TCB component"]],
           ['oid tag', m.call(c.sgx_ext(pairs: [c.tlv(0x30, c.tlv(0x04, 'ab'), c.intv(1))])), [a, "#{pre}TCB component missing OID"]],
           ['oid absent', m.call(c.i::OID_SGX_FMSPC + c.tlv(0x04, 'abcdef') + c.i::OID_SGX_TCB + "\x30\x02\x30\x00".b), [a, "#{pre}TCB component missing OID"]],
           ['value absent', m.call(c.i::OID_SGX_FMSPC + c.tlv(0x04, 'abcdef') + c.i::OID_SGX_TCB + c.tlv(0x30, c.tlv(0x30, c.tlv(0x06, "\x01".b)))),
            [a, "#{pre}TCB component missing value"]]
         ])
  end

  # ================================================================================================ PCK chain and signer chains (real chain from the shared vectors)
  t('c11: verify_intel_pck_chain on the genuine chain: success shape, pins, clocks, orderings, junk input') do
    next true if C11Intel.skip?

    c = C11Intel
    i = c.i
    pem = i.parse_dcap_quote(c.real_quote)['pckChainPem']
    leaf_pem, ca_pem, root_pem = c.parts(pem)
    now = c.real_now
    ok = i.verify_intel_pck_chain(pem, nil, now)
    leaf_der = AtlasPca::Attest::Cert.from_pem(leaf_pem).raw
    reason = ->(r) { r['reason'] }
    shuffled = [root_pem, leaf_pem, ca_pem].join("\n")
    root_only = i.verify_intel_pck_chain(root_pem, nil, now)
    c.ck([
           ['ok', ok['ok'], true], ['depth', ok['depth'], 3], ['leafDer', ok['leafDer'], leaf_der], ['leafKey', ok['leafKey'].class, OpenSSL::PKey::EC],
           ['leafCert', ok['leafCert'].raw, leaf_der], ['keys', ok.keys, %w[ok leafKey leafDer leafCert depth]],
           ['shuffled', i.verify_intel_pck_chain(shuffled, nil, now)['depth'], 3],
           ['upper pin', i.verify_intel_pck_chain(pem, i::SGX_ROOT_CA_SPKI_SHA256.upcase, now)['ok'], true],
           ['wrong pin', i.verify_intel_pck_chain(pem, '00' * 32, now), { 'ok' => false, 'reason' => 'Intel SGX Root CA does not match the pinned trust anchor' }],
           ['nil pem', i.verify_intel_pck_chain(nil, nil, now), { 'ok' => false, 'reason' => 'no PEM certificates in the PCK chain' }],
           ['empty pem', i.verify_intel_pck_chain('', nil, now), { 'ok' => false, 'reason' => 'no PEM certificates in the PCK chain' }],
           ['text pem', i.verify_intel_pck_chain('not a pem', nil, now), { 'ok' => false, 'reason' => 'no PEM certificates in the PCK chain' }],
           ['int pem', i.verify_intel_pck_chain(5, nil, now), { 'ok' => false, 'reason' => 'no PEM certificates in the PCK chain' }],
           ['leaf only', i.verify_intel_pck_chain(leaf_pem, nil, now), { 'ok' => false, 'reason' => 'PCK chain does not terminate in a self-signed root' }],
           ['orphan', i.verify_intel_pck_chain("#{pem}\n#{leaf_pem}", nil, now),
            { 'ok' => false, 'reason' => 'PCK chain is not a single connected path (orphan/duplicate certificates)' }],
           ['nan now', i.verify_intel_pck_chain(pem, nil, Float::NAN), { 'ok' => false, 'reason' => 'nowMs is not a finite number' }],
           ['str now', i.verify_intel_pck_chain(pem, nil, 'x'), { 'ok' => false, 'reason' => 'nowMs is not a finite number' }],
           ['inf now', i.verify_intel_pck_chain(pem, nil, Float::INFINITY), { 'ok' => false, 'reason' => 'nowMs is not a finite number' }],
           ['expired', i.verify_intel_pck_chain(pem, nil, 0),
            { 'ok' => false, 'reason' => 'PCK chain certificate outside its validity period', 'failure' => 'validity' }],
           ['root only', reason.call(root_only).to_s.include?('verification error'), false]
         ])
  end

  t('c11: verify_intel_pck_chain without a clock reads the wall clock in milliseconds (seam on Time.now at the last instant every certificate is valid)') do
    next true if C11Intel.skip?

    c = C11Intel
    i = c.i
    pem = i.parse_dcap_quote(c.real_quote)['pckChainPem']
    last = c.cm.pem_blocks(pem).map { |bl| AtlasPca::Attest::Der.der_validity_ms(AtlasPca::Attest::Cert.from_pem(bl).raw)[1] }.min
    at = Time.at(last / 1000)
    r = MutationKill::Seam.with(Time, { now: -> { at } }) { i.verify_intel_pck_chain(pem) }
    # every optional argument omitted: no pin override, the wall clock, no binding, no policy
    g = MutationKill::Seam.with(Time, { now: -> { at } }) { i.verify_genuine_tdx_quote(c.real_quote) } if c.real_now / 1000 <= last / 1000
    r['ok'] == true && r['depth'] == 3 && (g.nil? || g['ok'] == true)
  end

  t('c11: verify_intel_pck_chain: a throw while checking is a fail-closed reason carrying the message') do
    next true if C11Intel.skip?

    c = C11Intel
    r = MutationKill::Seam.with(c.cm, { pem_blocks: ->(*_a) { ['not a pem'] } }) { c.i.verify_intel_pck_chain('x', nil, 1) }
    r['ok'] == false && r['reason'].start_with?('PCK chain X.509 verification error (fail closed): ') &&
      r['reason'].length > 'PCK chain X.509 verification error (fail closed): '.length && r.keys == %w[ok reason]
  end

  t('c11: verify_p256 is true for a good compact signature, false for a bad one and for a fault') do
    next true if C11Intel.skip?

    c = C11Intel
    sig = c.compact(c.ec, 'msg')
    pub = OpenSSL::PKey.read(c.ec.public_to_der)
    c.ck([['good', c.i.verify_p256('msg', sig, pub), true], ['other msg', c.i.verify_p256('msn', sig, pub), false],
          ['other key', c.i.verify_p256('msg', sig, c.ec2), false], ['fault', c.i.verify_p256('msg', sig, nil).equal?(false), true]])
  end

  t('c11: signer_key_from_chain: key on success, exact errors (validity, pin, revocation of each certificate, unknown reason, validity re-check)') do
    next true if C11Intel.skip?

    c = C11Intel
    i = c.i
    chain = c.real_col['tcbInfoIssuerChainPem']
    now = c.real_now
    serials = c.cm.pem_blocks(chain).map { |bl| i.norm_serial(AtlasPca::Attest::Cert.from_pem(bl).serial_hex) }
    ok = i.signer_key_from_chain(chain, nil, now, {})
    der = AtlasPca::Attest
    flag = [false]
    orig = i.method(:verify_intel_pck_chain)
    rechecked = MutationKill::Seam.with(i, { verify_intel_pck_chain: ->(*a) { r = orig.call(*a); flag[0] = true; r } }) do
      MutationKill::Seam.with(der::Der, { x509_valid_at?: ->(*_a) { !flag[0] } }) { i.signer_key_from_chain(chain, nil, now, {}) }
    end
    unknown = MutationKill::Seam.with(i, { verify_intel_pck_chain: ->(*_a) { { 'ok' => false } } }) { i.signer_key_from_chain(chain, nil, now, {}) }
    no_der = MutationKill::Seam.with(i, { verify_intel_pck_chain: ->(*_a) { { 'ok' => true } } }) { i.signer_key_from_chain(chain, nil, now, {}) }
    c.ck([
           ['ok', ok.keys, ['key']], ['key class', ok['key'].class, OpenSSL::PKey::EC],
           ['validity', i.signer_key_from_chain(chain, nil, 0, {}), { 'error' => 'issuer chain certificate outside its validity period' }],
           ['pin', i.signer_key_from_chain(chain, '00' * 32, now, {}),
            { 'error' => 'issuer chain invalid: Intel SGX Root CA does not match the pinned trust anchor' }],
           ['revoked leaf', i.signer_key_from_chain(chain, nil, now, { serials[0] => true }),
            { 'error' => 'issuer chain certificate is revoked by the Intel Root CA CRL' }],
           ['revoked root', i.signer_key_from_chain(chain, nil, now, { serials[1] => true }),
            { 'error' => 'issuer chain certificate is revoked by the Intel Root CA CRL' }],
           ['unrelated revoked', i.signer_key_from_chain(chain, nil, now, { 'deadbeef' => true }).keys, ['key']],
           ['recheck', rechecked, { 'error' => 'issuer chain certificate outside its validity period' }],
           ['unknown', unknown, { 'error' => 'issuer chain invalid: unknown' }], ['no leaf der', no_der, { 'error' => 'issuer chain invalid: unknown' }]
         ])
  end

  # ================================================================================================ genuine quote
  t('c11: verify_genuine_tdx_quote on the genuine quote: result shape, policy allowlists (match, upper case, mismatch, empty list), binding') do
    next true if C11Intel.skip?

    c = C11Intel
    i = c.i
    q = c.real_quote
    now = c.real_now
    v = ->(pol, exp = nil, pin = nil) { i.verify_genuine_tdx_quote(q, pin, exp, pol, now) }
    base = v.call(nil)
    rep = base['report']
    fm = base['fmspc']
    rtmr = c.cm.to_hex(rep['rtmr0'])
    seam = c.cm.to_hex(rep['mrSeam'])
    sseam = c.cm.to_hex(rep['mrSignerSeam'])
    mrtd = 'a2e61f1316e9e367e9c1f7a0adc98c48eb13875c399c85d286cee5ea2b05e57f2df9f61d903b0ae7ac5607d843dfffc1'
    rf = ->(m) { { 'ok' => false, 'reason' => m } }
    zero96 = '00' * 48
    parsed = i.parse_dcap_quote(q)
    c.ck([
           ['ok', base['ok'], true], ['keys', base.keys, %w[ok report fmspc pckTcb chainDepth measured]], ['mrtd', c.cm.to_hex(rep['mrTd']), mrtd],
           ['report', rep, i.parse_dcap_td_report(parsed['tdReportBody'])], ['depth', base['chainDepth'], 3], ['fmspc hex', fm, c.cm.to_hex(base['pckTcb']['fmspc'])],
           ['pck tcb', base['pckTcb'], i.extract_pck_fmspc_and_tcb(AtlasPca::Attest::Cert.from_pem(c.parts(parsed['pckChainPem'])[0]).raw)],
           ['measured', base['measured'], { 'model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => mrtd, 'operator' => '' }],
           ['empty policy', v.call({})['ok'], true],
           ['mrtds ok', v.call({ 'mrtds' => [mrtd] })['ok'], true], ['mrtds upper', v.call({ 'mrtds' => [mrtd.upcase] })['ok'], true],
           ['mrtds second', v.call({ 'mrtds' => [zero96, mrtd] })['ok'], true],
           ['mrtds other', v.call({ 'mrtds' => [zero96] }), rf.call('MRTD not in policy allowlist')],
           ['mrtds empty', v.call({ 'mrtds' => [] })['ok'], true], ['mrtds string', v.call({ 'mrtds' => mrtd })['ok'], true],
           ['fmspcs ok', v.call({ 'fmspcs' => [fm.upcase] })['ok'], true], ['fmspcs other', v.call({ 'fmspcs' => ['000000000000'] }), rf.call('FMSPC not in policy allowlist')],
           ['fmspcs empty', v.call({ 'fmspcs' => [] })['ok'], true],
           ['rtmrs ok', v.call({ 'rtmrs' => [rtmr] })['ok'], true], ['rtmrs other', v.call({ 'rtmrs' => ['11' * 48] }), rf.call('RTMR0 not in policy allowlist')],
           ['rtmrs empty', v.call({ 'rtmrs' => [] })['ok'], true],
           ['seams ok', v.call({ 'mrSeams' => [seam.upcase] })['ok'], true], ['seams other', v.call({ 'mrSeams' => ['11' * 48] }), rf.call('MRSEAM not in policy allowlist')],
           ['seams empty refuses', v.call({ 'mrSeams' => [] }), rf.call('MRSEAM not in policy allowlist')],
           ['signer ok', v.call({ 'mrSignerSeams' => [sseam] })['ok'], true],
           ['signer other', v.call({ 'mrSignerSeams' => ['11' * 48] }), rf.call('MRSIGNERSEAM not in policy allowlist')],
           ['signer empty refuses', v.call({ 'mrSignerSeams' => [] }), rf.call('MRSIGNERSEAM not in policy allowlist')],
           ['order mrtd first', v.call({ 'mrtds' => [zero96], 'fmspcs' => ['000000000000'], 'mrSeams' => ['11' * 48], 'rtmrs' => ['11' * 48] }), rf.call('MRTD not in policy allowlist')],
           ['order fmspc', v.call({ 'fmspcs' => ['000000000000'], 'mrSeams' => ['11' * 48], 'rtmrs' => ['11' * 48] }), rf.call('FMSPC not in policy allowlist')],
           ['order seam', v.call({ 'mrSeams' => ['11' * 48], 'mrSignerSeams' => ['11' * 48], 'rtmrs' => ['11' * 48] }), rf.call('MRSEAM not in policy allowlist')],
           ['order signer', v.call({ 'mrSignerSeams' => ['11' * 48], 'rtmrs' => ['11' * 48] }), rf.call('MRSIGNERSEAM not in policy allowlist')],
           ['binding mismatch', v.call(nil, { 'holder_pub' => 'h', 'grant_ref' => 'g', 'epoch' => 1, 'nonce' => 'n' }),
            rf.call('report_data does not bind holder/grant/epoch/nonce')],
           ['binding bad', v.call(nil, { 'holder_pub' => '', 'grant_ref' => 'g', 'epoch' => 1, 'nonce' => 'n' }),
            rf.call('binding not constructible: binding: holderPub required')],
           ['pin', v.call(nil, nil, '00' * 32), rf.call('PCK chain invalid: Intel SGX Root CA does not match the pinned trust anchor')],
           ['pin upper', v.call(nil, nil, i::SGX_ROOT_CA_SPKI_SHA256.upcase)['ok'], true],
           ['parse', i.verify_genuine_tdx_quote('abc'.b, nil, nil, nil, now),
            rf.call('quote parse failed: parseDcapQuote: too short for header + TD report + sig length')],
           ['chain expired', i.verify_genuine_tdx_quote(q, nil, nil, nil, 0), rf.call('PCK chain invalid: PCK chain certificate outside its validity period')]
         ])
  end

  t('c11: verify_genuine_tdx_quote: each fail-closed step is reached through a seam and reports its exact reason') do
    next true if C11Intel.skip?

    c = C11Intel
    i = c.i
    q = c.real_quote
    now = c.real_now
    rf = ->(m) { { 'ok' => false, 'reason' => m } }
    with = lambda do |stubs, &blk|
      MutationKill::Seam.with(i, stubs) { blk.call }
    end
    run = -> { i.verify_genuine_tdx_quote(q, nil, nil, nil, now) }
    c.ck([
           ['td parse', with.call({ parse_dcap_td_report: ->(*_a) { raise ArgumentError, 'boom' } }, &run), rf.call('TD report parse failed: boom')],
           ['chain unknown 1', with.call({ verify_intel_pck_chain: ->(*_a) { { 'ok' => false } } }, &run), rf.call('PCK chain invalid: unknown')],
           ['chain no key', with.call({ verify_intel_pck_chain: ->(*_a) { { 'ok' => true, 'leafDer' => 'x' } } }, &run), rf.call('PCK chain invalid: unknown')],
           ['chain no der', with.call({ verify_intel_pck_chain: ->(*_a) { { 'ok' => true, 'leafKey' => 'x' } } }, &run), rf.call('PCK chain invalid: unknown')],
           ['chain reason', with.call({ verify_intel_pck_chain: ->(*_a) { { 'ok' => false, 'reason' => 'why' } } }, &run), rf.call('PCK chain invalid: why')],
           ['extract', with.call({ verify_intel_pck_chain: ->(*_a) { { 'ok' => true, 'leafKey' => 'x', 'leafDer' => 'junk'.b } } }, &run),
            rf.call('PCK FMSPC/TCB extraction failed: extractPckFmspcAndTcb: FMSPC OID not found in certificate')],
           ['qe sig', with.call({ verify_p256: ->(*_a) { false } }, &run), rf.call('QE report signature does not verify under the PCK leaf')]
         ]) &&
      c.err { i.verify_genuine_tdx_quote(nil, nil, nil, nil, now) }.nil? &&
      i.verify_genuine_tdx_quote(nil, nil, nil, nil, now)['reason'].start_with?('genuine TDX verification error (fail closed): ')
  end

  # ================================================================================================ CRL
  t('c11: norm_serial and serial_is_revoked? normalise case and leading zeros') do
    next true if C11Intel.skip?

    i = C11Intel.i
    C11Intel.ck([['n1', i.norm_serial('00aB'), 'ab'], ['n2', i.norm_serial('0'), ''], ['n3', i.norm_serial(''), ''], ['n4', i.norm_serial('a0b'), 'a0b'],
                 ['n5', i.norm_serial('000'), ''], ['n6', i.norm_serial('ABC'), 'abc'],
                 ['rev', i.serial_is_revoked?({ 'abcdef' => true }, 'ABCDEF'), true], ['rev0', i.serial_is_revoked?({ 'abcdef' => true }, '00abcdef'), true],
                 ['not', i.serial_is_revoked?({ 'abcdef' => true }, '0abcdee'), false], ['empty', i.serial_is_revoked?({}, 'ab'), false]])
  end

  t('c11: date_utc follows Date.UTC (two-digit years, month and day and hour overflow, negative months)') do
    next true if C11Intel.skip?

    c = C11Intel
    d = ->(*a) { c.i.date_utc(*a) }
    c.ck([
           ['plain', d.call(2026, 9, 8, 21, 28, 48), c.ms(2026, 10, 8, 21, 28, 48)], ['y99', d.call(99, 0, 1, 0, 0, 0), c.ms(1999, 1, 1)],
           ['y0', d.call(0, 0, 1, 0, 0, 0), c.ms(1900, 1, 1)], ['y100', d.call(100, 0, 1, 0, 0, 0), c.ms(100, 1, 1)],
           ['y1', d.call(1, 5, 1, 0, 0, 0), c.ms(1901, 6, 1)], ['y2026', d.call(2026, 0, 1, 0, 0, 0), c.ms(2026, 1, 1)],
           ['mon12', d.call(2026, 12, 8, 1, 2, 3), c.ms(2027, 1, 8, 1, 2, 3)], ['mon25', d.call(2026, 25, 1, 0, 0, 0), c.ms(2028, 2, 1)],
           ['mon-1', d.call(2026, -1, 15, 0, 0, 0), c.ms(2025, 12, 15)], ['mon11', d.call(2026, 11, 31, 0, 0, 0), c.ms(2026, 12, 31)],
           ['day32', d.call(2026, 9, 32, 0, 0, 0), c.ms(2026, 11, 1)], ['day0', d.call(2026, 9, 0, 0, 0, 0), c.ms(2026, 9, 30)],
           ['h25', d.call(2026, 9, 8, 25, 0, 0), c.ms(2026, 10, 9, 1)], ['mi61', d.call(2026, 9, 8, 0, 61, 0), c.ms(2026, 10, 8, 1, 1)],
           ['s61', d.call(2026, 9, 8, 0, 0, 61), c.ms(2026, 10, 8, 0, 1, 1)]
         ])
  end

  t('c11: der_time reads UTCTime (50..99 is 19xx, 00..49 is 20xx) and GeneralizedTime strictly, with the reference messages') do
    next true if C11Intel.skip?

    c = C11Intel
    dt = lambda do |tag, s|
      b = c.tlv(tag, s)
      c.i.der_time(b, c.i.tlv(b, 0))
    end
    a = ArgumentError
    e = ->(tag, s) { c.err { dt.call(tag, s) } }
    c.ck([
           ['u 2026', dt.call(0x17, '261008212848Z'), c.ms(2026, 10, 8, 21, 28, 48)], ['u 1999', dt.call(0x17, '991231235959Z'), c.ms(1999, 12, 31, 23, 59, 59)],
           ['u 1950', dt.call(0x17, '500101000000Z'), c.ms(1950, 1, 1)], ['u 2049', dt.call(0x17, '491231235959Z'), c.ms(2049, 12, 31, 23, 59, 59)],
           ['u 2000', dt.call(0x17, '000101000000Z'), c.ms(2000, 1, 1)], ['u 2050-', dt.call(0x17, '500101000000Z') < dt.call(0x17, '491231235959Z'), true],
           ['g 2026', dt.call(0x18, '20261008212848Z'), c.ms(2026, 10, 8, 21, 28, 48)], ['g 1999', dt.call(0x18, '19991231235959Z'), c.ms(1999, 12, 31, 23, 59, 59)],
           ['g 0099', dt.call(0x18, '00990101000000Z'), c.ms(1999, 1, 1)], ['g 0100', dt.call(0x18, '01000101000000Z'), c.ms(100, 1, 1)],
           ['g mon13', dt.call(0x18, '20261308212848Z'), c.ms(2027, 1, 8, 21, 28, 48)], ['g mon00', dt.call(0x18, '20260015000000Z'), c.ms(2025, 12, 15)],
           ['g day32', dt.call(0x18, '20261032000000Z'), c.ms(2026, 11, 1)], ['g h25', dt.call(0x18, '20261008250000Z'), c.ms(2026, 10, 9, 1)],
           ['g fields', dt.call(0x18, '20270304050607Z'), c.ms(2027, 3, 4, 5, 6, 7)],
           ['u lead', e.call(0x17, 'xx261008212848Z'), [a, 'bad UTCTime']], ['u trail', e.call(0x17, '261008212848Zxx'), [a, 'bad UTCTime']],
           ['u short', e.call(0x17, '2610082128Z'), [a, 'bad UTCTime']], ['u noz', e.call(0x17, '261008212848'), [a, 'bad UTCTime']],
           ['u nl', e.call(0x17, "261008212848Z\n"), [a, 'bad UTCTime']], ['u alpha', e.call(0x17, '26100821284AZ'), [a, 'bad UTCTime']],
           ['u gen form', e.call(0x17, '20261008212848Z'), [a, 'bad UTCTime']], ['u high byte', e.call(0x17, "26100821284\xE9Z".b), [a, 'bad UTCTime']],
           ['g high byte', e.call(0x18, "2026100821284\xE9Z".b), [a, 'bad GeneralizedTime']],
           ['g lead', e.call(0x18, 'xx20261008212848Z'), [a, 'bad GeneralizedTime']], ['g trail', e.call(0x18, '20261008212848Zxx'), [a, 'bad GeneralizedTime']],
           ['g short', e.call(0x18, '2026100821284Z'), [a, 'bad GeneralizedTime']], ['g utc form', e.call(0x18, '261008212848Z'), [a, 'bad GeneralizedTime']],
           ['g nl', e.call(0x18, "20261008212848Z\n"), [a, 'bad GeneralizedTime']],
           ['tag 4', e.call(0x04, '261008212848Z'), [a, 'not a DER time']], ['tag 0x19', e.call(0x19, '20261008212848Z'), [a, 'not a DER time']],
           ['tag 0x16', e.call(0x16, '261008212848Z'), [a, 'not a DER time']], ['latin1', dt.call(0x17, '261008212848Z').class, Integer]
         ])
  end

  t('c11: parse_crl / verify_crl: a good CRL, its revoked serials, optional parts, and the structure refusals') do
    next true if C11Intel.skip?

    c = C11Intel
    a = ArgumentError
    now = c.ms(2026, 10, 20)
    pf = ->(m) { { 'ok' => false, 'reason' => "CRL parse failed: #{m}" } }
    good = c.crl(c.base(c.utc(C11Intel::THIS), c.utc(C11Intel::NEXT), c.tlv(0x30, c.entry("\x00\xAA\xBB".b), c.entry("\xCD\x01".b), c.entry("\x0A".b), c.entry("\x00".b))))
    r = c.vc(good, now)
    plain = c.crl(c.base)
    o_tag, o_st, o_en = c.rd(good, 0)
    _ = o_tag
    content = good.byteslice(o_st, o_en - o_st)
    wrapped = [0x30, 0x84, 0, 0, content.bytesize >> 8, content.bytesize & 0xFF].pack('C*') + content
    _t, t_st, t_en = c.rd(content, 0)
    tbs_raw = content.byteslice(0, t_en)
    tbs_body = content.byteslice(t_st, t_en - t_st)
    rest = content.byteslice(t_en..)
    sig_alg = c::SIG_ALG
    c.ck([
           ['good', r, { 'ok' => true, 'revoked' => { 'aabb' => true, 'cd01' => true, 'a' => true, '' => true } }],
           ['plain', c.vc(plain, now), { 'ok' => true, 'revoked' => {} }],
           ['4-octet length', c.vc(wrapped, now)['ok'], true],
           ['no version', c.vc(c.crl(c.base(version: false)), now), { 'ok' => true, 'revoked' => {} }],
           ['gen nextUpdate', c.vc(c.crl(c.base(c.utc(C11Intel::THIS), c.gen('20261107212848Z'))), now), { 'ok' => true, 'revoked' => {} }],
           ['extension tail', c.vc(c.crl(c.base(c.utc(C11Intel::THIS), c.utc(C11Intel::NEXT), c.tlv(0xA0, 'ab'))), now), { 'ok' => true, 'revoked' => {} }],
           ['tag outer', c.vc(good.dup.tap { |g| g.setbyte(0, 0x31) }, now), pf.call('CRL: bad outer SEQUENCE')],
           ['trailing', c.vc(good + "\x00".b, now), pf.call('CRL: bad outer SEQUENCE')],
           ['one byte', c.vc("\x30".b, now), pf.call('DER truncated')], ['n=0', c.vc("\x30\x80\x00".b, now), pf.call('DER bad length')],
           ['n over', c.vc("\x30\x82\x01".b, now), pf.call('DER bad length')], ['n=5', c.vc("\x30\x85\x00\x00\x00\x00\x00".b, now), pf.call('DER bad length')],
           ['empty long', c.vc("\x30\x81\x00".b, now), pf.call('DER truncated')], ['overrun', c.vc("\x30\x05\x00".b, now), pf.call('DER overrun')],
           ['tbs tag', c.vc(c.tlv(0x30, c.tlv(0x31, tbs_body), rest), now), pf.call('CRL: bad TBSCertList')],
           ['sig tag', c.vc(c.tlv(0x30, tbs_raw, sig_alg, c.tlv(0x05)), now), pf.call('CRL: bad signature')],
           ['sig extra', c.vc(c.tlv(0x30, tbs_raw, sig_alg, c.tlv(0x03, "\x00".b), "\x05\x00".b), now), pf.call('CRL: bad signature')],
           ['issuer tag', c.vc(c.crl([c.tlv(0x02, "\x01".b), sig_alg, c.tlv(0x31), c.utc(C11Intel::THIS), c.utc(C11Intel::NEXT)]), now), pf.call('CRL: bad issuer')],
           ['entry serial tag', c.vc(c.crl(c.base(c.utc(C11Intel::THIS), c.utc(C11Intel::NEXT), c.tlv(0x30, c.tlv(0x30, c.tlv(0x04, "\x01".b))))), now), pf.call('CRL: bad revoked entry')],
           ['only thisUpdate', c.vc(c.crl([c.tlv(0x02, "\x01".b), sig_alg, c.dn, c.utc(C11Intel::THIS)]), now), pf.call('CRL: missing nextUpdate')],
           ['revoked, no next', c.vc(c.crl([c.tlv(0x02, "\x01".b), sig_alg, c.dn, c.utc(C11Intel::THIS), c.tlv(0x30, c.entry("\x05".b))]), now), pf.call('CRL: missing nextUpdate')],
           ['time tag', c.vc(c.crl([c.tlv(0x02, "\x01".b), sig_alg, c.dn, c.tlv(0x04, "\x01".b), c.utc(C11Intel::NEXT)]), now), pf.call('not a DER time')],
           ['bad utc', c.vc(c.crl(c.base(c.utc('xx261008212848Z'))), now), pf.call('bad UTCTime')],
           ['bad gen', c.vc(c.crl(c.base(c.utc(C11Intel::THIS), c.gen('2026110721284Z'))), now), pf.call('bad GeneralizedTime')]
         ])
  end

  t('c11: parse_crl walks several revoked entries and a version-less list without hanging (deadline)') do
    next true if C11Intel.skip?

    c = C11Intel
    der = c.crl(c.base(c.utc(C11Intel::THIS), c.utc(C11Intel::NEXT), c.tlv(0x30, c.entry("\x01".b), c.entry("\x02".b), c.entry("\x03".b))))
    r = c.tm { c.i.parse_crl(der) }
    nov = c.tm { c.i.parse_crl(c.crl(c.base(version: false))) }
    _o, o_st, = c.rd(der, 0)
    _t, _s, t_en = c.rd(der, o_st)
    c.ck([['revoked', r['revoked'], { '1' => true, '2' => true, '3' => true }], ['this', r['thisUpdate'], c.ms(2026, 10, 8, 21, 28, 48)],
          ['next', r['nextUpdate'], c.ms(2026, 11, 7, 21, 28, 48)], ['keys', r.keys, %w[tbs thisUpdate nextUpdate revoked sigDer]],
          ['tbs', r['tbs'], der.byteslice(o_st, t_en - o_st)], ['no version', nov['revoked'], {}]])
  end

  t('c11: verify_crl: signature (ec / rsa / other key), clock boundaries, UTCTime century mapping') do
    next true if C11Intel.skip?

    c = C11Intel
    der = c.crl(c.base)
    this_ms = c.ms(2026, 10, 8, 21, 28, 48)
    next_ms = c.ms(2026, 11, 7, 21, 28, 48)
    rsa_der = c.crl(c.base, c.rsa)
    ed = OpenSSL::PKey.generate_key('ED25519')
    old = c.crl(c.base(c.utc('700101000000Z'), c.utc('991231235959Z')))
    c.ck([
           ['wrong key', c.vc(der, this_ms, c.ec2), { 'ok' => false, 'reason' => 'CRL signature does not verify under the issuer' }],
           ['at this', c.vc(der, this_ms)['ok'], true], ['before this', c.vc(der, this_ms - 1),
                                                         { 'ok' => false, 'reason' => 'CRL thisUpdate is in the future' }],
           ['at next', c.vc(der, next_ms)['ok'], true], ['after next', c.vc(der, next_ms + 1), { 'ok' => false, 'reason' => 'CRL is stale (nextUpdate passed)' }],
           ['rsa ok', c.vc(rsa_der, this_ms, c.rsa), { 'ok' => true, 'revoked' => {} }],
           ['rsa under ec', c.vc(rsa_der, this_ms, c.ec), { 'ok' => false, 'reason' => 'CRL signature does not verify under the issuer' }],
           ['ec under rsa', c.vc(der, this_ms, c.rsa), { 'ok' => false, 'reason' => 'CRL signature does not verify under the issuer' }],
           ['ed25519 issuer', c.vc(der, this_ms, ed), { 'ok' => false, 'reason' => 'CRL signature does not verify under the issuer' }],
           ['1975', c.vc(old, c.ms(1975, 1, 1)), { 'ok' => true, 'revoked' => {} }],
           ['1965', c.vc(old, c.ms(1965, 1, 1)), { 'ok' => false, 'reason' => 'CRL thisUpdate is in the future' }],
           ['1950 this', c.vc(c.crl(c.base(c.utc('500101000000Z'), c.utc('491231235959Z'))), c.ms(2026, 1, 1))['ok'], true],
           ['2049 this', c.vc(c.crl(c.base(c.utc('491231235959Z'), c.utc('491231235959Z'))), c.ms(2026, 1, 1)),
            { 'ok' => false, 'reason' => 'CRL thisUpdate is in the future' }],
           ['1999 next', c.vc(c.crl(c.base(c.utc(C11Intel::THIS), c.utc('991231235959Z'))), c.ms(2026, 10, 20)),
            { 'ok' => false, 'reason' => 'CRL is stale (nextUpdate passed)' }],
           ['2049 next', c.vc(c.crl(c.base(c.utc(C11Intel::THIS), c.utc('491231235959Z'))), c.ms(2026, 10, 20))['ok'], true],
           ['2000 this', c.vc(c.crl(c.base(c.utc('000101000000Z'), c.utc('491231235959Z'))), c.ms(2026, 10, 20))['ok'], true],
           ['frozen der', c.vc(der.dup.force_encoding('UTF-8'), this_ms)['ok'], true]
         ])
  end

  # ================================================================================================ signed JSON
  t('c11: raw_json_object finds the first member by name and returns its balanced object (strings, escapes, whitespace, deadline)') do
    next true if C11Intel.skip?

    c = C11Intel
    r = ->(s, n = 'a') { c.tm { c.i.raw_json_object(s, n) } }
    c.ck([
           ['simple', r.call('{"a":{"b":1}}'), '{"b":1}'], ['spaces', r.call(" \n{ \"a\" \n:\t{ \"b\" : \"}\" } , \"c\":1}"), '{ "b" : "}" }'],
           ['escape', r.call('{"a":{"s":"\"}"}}'), '{"s":"\"}"}'], ['double backslash', r.call('{"a":{"s":"\\\\"}}'), '{"s":"\\\\"}'],
           ['nested', r.call('{"a":{"b":{"c":1}}}'), '{"b":{"c":1}}'], ['brace in string', r.call('{"a":{"s":"{{"}}'), '{"s":"{{"}'],
           ['nbsp', r.call("\u00a0{\u00a0\"a\"\u00a0:\u00a0{\"b\":1}}"), '{"b":1}'], ['bom', r.call("\ufeff{\"a\":{\"b\":1}}"), '{"b":1}'],
           ['ideographic', r.call("\u3000{\"a\"\u3000:\u3000{}}"), '{}'],
           ['regex name', r.call('{"axb":{"x":1}}', 'a.b'), nil], ['dot name', r.call('{"a.b":{"x":1}}', 'a.b'), '{"x":1}'],
           ['not first', r.call('{"z":1,"a":{}}'), nil], ['scalar', r.call('{"a":1}'), nil], ['at end', r.call('{"a":'), nil],
           ['unbalanced', r.call('{"a":{"b":1'), nil], ['no start', r.call('x{"a":{}}'), nil], ['empty', r.call(''), nil],
           ['trailing', r.call('{"a":{"b":1}} trailing'), '{"b":1}'], ['multibyte', r.call('{"a":{"é":"ü"}}'), '{"é":"ü"}'],
           ['empty obj', r.call('{"a":{}}'), '{}'], ['unterminated string', r.call('{"a":{"s":"x}}'), nil],
           ['scalar then later object', r.call('{"a":1,"b":{}}'), nil], ['escaped quote then close', r.call('{"a":{"s":"\\""}}'), '{"s":"\\""}'],
           ['escape before brace', r.call('{"a":{"s":"\\\\"},"t":"}"}'), '{"s":"\\\\"}']
         ])
  end

  t('c11: verify_signed_json: the body is the signed first member; every refusal has its message') do
    next true if C11Intel.skip?

    c = C11Intel
    k = c.ec
    pub = OpenSSL::PKey.read(k.public_to_der)
    raw = '{"id":"TDX","n":1,"s":"é"}'
    v = ->(text, key = pub) { c.i.verify_signed_json(text, 'tcbInfo', key) }
    err = ->(m) { { 'error' => m } }
    good = c.signed('tcbInfo', raw, k)
    sig = c.compact(k, raw).unpack1('H*')
    body = v.call(good)['body']
    dup = %({"tcbInfo":#{raw},"signature":"#{sig}","tcbInfo":{"id":"EVIL"}})
    c.ck([
           ['body', [v.call(good).keys, body['id'], body['n'], body['s']], [['body'], 'TDX', 1, 'é']],
           ['upper hex', v.call(c.signed('tcbInfo', raw, k, hex: sig.upcase)).keys, ['body']],
           ['dup member', v.call(dup)['body']['id'], 'TDX'],
           ['missing name', c.i.verify_signed_json(good, 'enclaveIdentity', pub), err.call('enclaveIdentity not found / malformed')],
           ['not json', v.call(%({"tcbInfo":{"a":1},)), err.call('tcbInfo document is not valid JSON')],
           ['no sig', v.call(%({"tcbInfo":#{raw}})), err.call('tcbInfo signature missing or malformed')],
           ['sig number', v.call(%({"tcbInfo":#{raw},"signature":5})), err.call('tcbInfo signature missing or malformed')],
           ['sig 127', v.call(c.signed('tcbInfo', raw, k, hex: sig[0, 127])), err.call('tcbInfo signature missing or malformed')],
           ['sig 129', v.call(c.signed('tcbInfo', raw, k, hex: sig + '0')), err.call('tcbInfo signature missing or malformed')],
           ['sig nonhex', v.call(c.signed('tcbInfo', raw, k, hex: 'g' * 128)), err.call('tcbInfo signature missing or malformed')],
           ['sig newline', v.call(c.signed('tcbInfo', raw, k, hex: "#{sig}\\n")), err.call('tcbInfo signature missing or malformed')],
           ['wrong key', v.call(good, c.ec2), err.call('tcbInfo signature does not verify under the TCB Signing certificate')],
           ['tampered', v.call(good.sub('"n":1', '"n":2')), err.call('tcbInfo signature does not verify under the TCB Signing certificate')],
           ['not hash doc', c.i.verify_signed_json('{"tcbInfo":{}} ', 'tcbInfo', pub), err.call('tcbInfo signature missing or malformed')]
         ])
  end

  # ================================================================================================ dates and freshness
  t('c11: js_date_parse: ISO forms, fractions truncated to ms, 24:00, zones, calendar limits, nil for anything else') do
    next true if C11Intel.skip?

    c = C11Intel
    p = ->(s) { c.i.js_date_parse(s) }
    base = c.ms(2026, 10, 20, 1, 2, 3)
    mn = 60_000
    c.ck([
           ['date', p.call('2026-10-20'), c.ms(2026, 10, 20)], ['hm', p.call('2026-10-20T01:02Z'), c.ms(2026, 10, 20, 1, 2)], ['hms', p.call('2026-10-20T01:02:03Z'), base],
           ['frac 1', p.call('2026-10-20T01:02:03.5Z'), base + 500], ['frac 2', p.call('2026-10-20T01:02:03.12Z'), base + 120],
           ['frac 3', p.call('2026-10-20T01:02:03.123Z'), base + 123], ['frac 6', p.call('2026-10-20T01:02:03.123456Z'), base + 123],
           ['frac 0', p.call('2026-10-20T01:02:03.0Z'), base], ['frac 9999', p.call('2026-10-20T01:02:03.9999Z'), base + 999],
           ['frac 07', p.call('2026-10-20T01:02:03.07Z'), base + 70],
           ['plus', p.call('2026-10-20T01:02:03+02:30'), base - (150 * mn)], ['minus', p.call('2026-10-20T01:02:03-02:30'), base + (150 * mn)],
           ['plus 0', p.call('2026-10-20T01:02:03+00:00'), base], ['plus 23:59', p.call('2026-10-20T01:02:03+23:59'), base - (((23 * 60) + 59) * mn)],
           ['minus 23:59', p.call('2026-10-20T01:02:03-23:59'), base + (((23 * 60) + 59) * mn)],
           ['plus 24', p.call('2026-10-20T01:02:03+24:00'), nil], ['plus 60 min', p.call('2026-10-20T01:02:03+23:60'), nil],
           ['minus 24', p.call('2026-10-20T01:02:03-24:00'), nil], ['minus 60', p.call('2026-10-20T01:02:03-00:60'), nil],
           ['plus min only', p.call('2026-10-20T01:02:03+00:59'), base - (59 * mn)],
           ['24:00', p.call('2026-10-20T24:00Z'), c.ms(2026, 10, 21)], ['24:00:00', p.call('2026-10-20T24:00:00Z'), c.ms(2026, 10, 21)],
           ['24:00:00.000', p.call('2026-10-20T24:00:00.000Z'), c.ms(2026, 10, 21)], ['24:01', p.call('2026-10-20T24:01Z'), nil],
           ['24:00:01', p.call('2026-10-20T24:00:01Z'), nil], ['24:00:00.001', p.call('2026-10-20T24:00:00.001Z'), nil], ['25:00', p.call('2026-10-20T25:00Z'), nil],
           ['23:60', p.call('2026-10-20T23:60Z'), nil], ['23:59:60', p.call('2026-10-20T23:59:60Z'), nil],
           ['23:59:59', p.call('2026-10-20T23:59:59Z'), c.ms(2026, 10, 20, 23, 59, 59)], ['00:00:00', p.call('2026-10-20T00:00:00Z'), c.ms(2026, 10, 20)],
           ['23:59', p.call('2026-10-20T23:59Z'), c.ms(2026, 10, 20, 23, 59)], ['00:30', p.call('2026-10-20T00:30Z'), c.ms(2026, 10, 20, 0, 30)],
           ['00:00:30', p.call('2026-10-20T00:00:30Z'), c.ms(2026, 10, 20, 0, 0, 30)], ['00:00:00.5', p.call('2026-10-20T00:00:00.5Z'), c.ms(2026, 10, 20) + 500],
           ['m13', p.call('2026-13-01'), nil], ['m00', p.call('2026-00-01'), nil], ['m12', p.call('2026-12-01'), c.ms(2026, 12, 1)], ['m01', p.call('2026-01-01'), c.ms(2026, 1, 1)],
           ['d00', p.call('2026-01-00'), nil], ['d32', p.call('2026-01-32'), nil], ['d31', p.call('2026-01-31'), c.ms(2026, 1, 31)],
           ['feb 29 2026', p.call('2026-02-29'), nil], ['feb 29 2024', p.call('2024-02-29'), c.ms(2024, 2, 29)], ['feb 28', p.call('2026-02-28'), c.ms(2026, 2, 28)],
           ['feb 30', p.call('2024-02-30'), nil], ['feb 29 1900', p.call('1900-02-29'), nil], ['feb 29 2000', p.call('2000-02-29'), c.ms(2000, 2, 29)],
           ['feb 29 2100', p.call('2100-02-29'), nil], ['apr 31', p.call('2026-04-31'), nil], ['apr 30', p.call('2026-04-30'), c.ms(2026, 4, 30)],
           ['dec 31', p.call('2026-12-31'), c.ms(2026, 12, 31)], ['sep 31', p.call('2026-09-31'), nil], ['nov 31', p.call('2026-11-31'), nil],
           ['jun 31', p.call('2026-06-31'), nil], ['jun 30', p.call('2026-06-30'), c.ms(2026, 6, 30)],
           ['hour only', p.call('2026-10-20T01Z'), nil], ['space', p.call('2026-10-20 01:02'), nil], ['empty', p.call(''), nil], ['junk', p.call('abc'), nil],
           ['dot no digits', p.call('2026-10-20T01:02:03.Z'), nil], ['trailing', p.call("2026-10-20\n"), nil], ['short year', p.call('26-10-20'), nil],
           ['date + zone', p.call('2026-10-20Z'), nil]
         ])
  end

  t('c11: check_fresh: window boundaries, missing / non-string / unparsable dates, the label in the reason') do
    next true if C11Intel.skip?

    c = C11Intel
    f = ->(body, now = c.ms(2026, 10, 15), what = 'TCB info') { c.i.check_fresh(body, what, now) }
    body = { 'issueDate' => '2026-10-01T00:00:00Z', 'nextUpdate' => '2026-11-01T00:00:00Z' }
    iss = c.ms(2026, 10, 1)
    nxt = c.ms(2026, 11, 1)
    miss = 'TCB info: issueDate/nextUpdate missing'
    c.ck([
           ['inside', f.call(body), nil], ['at issue', f.call(body, iss), nil], ['before issue', f.call(body, iss - 1), 'TCB info: issueDate is in the future'],
           ['at next', f.call(body, nxt), nil], ['after next', f.call(body, nxt + 1), 'TCB info: stale (nextUpdate passed)'],
           ['label', f.call(body, nxt + 1, 'QE identity'), 'QE identity: stale (nextUpdate passed)'],
           ['label future', f.call(body, iss - 1, 'QE identity'), 'QE identity: issueDate is in the future'],
           ['label missing', f.call({}, iss, 'QE identity'), 'QE identity: issueDate/nextUpdate missing'],
           ['no issue', f.call({ 'nextUpdate' => body['nextUpdate'] }), miss], ['no next', f.call({ 'issueDate' => body['issueDate'] }), miss],
           ['issue number', f.call(body.merge('issueDate' => 5)), miss], ['next number', f.call(body.merge('nextUpdate' => 5)), miss],
           ['issue junk', f.call(body.merge('issueDate' => 'soon')), miss], ['next junk', f.call(body.merge('nextUpdate' => 'later')), miss],
           ['issue nil', f.call(body.merge('issueDate' => nil)), miss], ['next nil', f.call(body.merge('nextUpdate' => nil)), miss]
         ])
  end

  # ================================================================================================ status helpers
  t('c11: as_status, worst, svns, hex_bytes, advisories, masked_eq?, hit_level, text_of') do
    next true if C11Intel.skip?

    c = C11Intel
    i = c.i
    lv = ->(sv) { { 'tcb' => { 'isvsvn' => sv } } }
    o = Object.new
    duck = Object.new
    def duck.to_str = 'UpToDate'
    def duck.==(_other) = true
    ok16 = Array.new(16) { |k| { 'svn' => k } }
    frozen = 'abc'.freeze
    c.ck([
           ['status each', i::STATUS_ORDER.map { |s| i.as_status(s) }, i::STATUS_ORDER], ['status junk', [i.as_status('Bogus'), i.as_status(5), i.as_status(nil), i.as_status(:UpToDate)], [nil] * 4],
           ['worst', [i.worst('OutOfDate', 'UpToDate'), i.worst('UpToDate', 'OutOfDate'), i.worst('Revoked', 'OutOfDate'), i.worst('SWHardeningNeeded', 'ConfigurationNeeded'),
                      i.worst('ConfigurationNeeded', 'SWHardeningNeeded'), i.worst('UpToDate', 'UpToDate')],
            %w[OutOfDate OutOfDate Revoked ConfigurationNeeded ConfigurationNeeded UpToDate]],
           ['svns ok', i.svns(ok16), (0...16).to_a], ['svns float', i.svns(Array.new(16) { { 'svn' => 1.5 } }), [1.5] * 16],
           ['svns 15', i.svns(ok16.first(15)), nil], ['svns 17', i.svns(ok16 + [{ 'svn' => 1 }]), nil], ['svns nil', i.svns(nil), nil], ['svns hash', i.svns({}), nil],
           ['svns elem', i.svns(ok16.first(15) + [5]), nil], ['svns str', i.svns(ok16.first(15) + [{ 'svn' => '1' }]), nil],
           ['svns true', i.svns(ok16.first(15) + [{ 'svn' => true }]), nil], ['svns nan', i.svns(ok16.first(15) + [{ 'svn' => Float::NAN }]), nil],
           ['svns missing', i.svns(ok16.first(15) + [{}]), nil], ['svns first bad', i.svns([{}] + ok16.first(15)), nil],
           ['hex ok', i.hex_bytes('0aFf', 2), "\x0A\xFF".b], ['hex len+', i.hex_bytes('0aff0', 2), nil], ['hex len-', i.hex_bytes('0af', 2), nil],
           ['hex nonhex', i.hex_bytes('0aFg', 2), nil], ['hex nil', i.hex_bytes(nil, 2), nil], ['hex int', i.hex_bytes(1234, 2), nil], ['hex empty', i.hex_bytes('', 0), nil],
           ['hex nl', i.hex_bytes("0a\n0", 2), nil], ['hex plus', i.hex_bytes('+a00', 2), nil],
           ['adv', i.advisories({ 'advisoryIDs' => ['a', 1, nil, 'b'] }), %w[a b]], ['adv non-array', i.advisories({ 'advisoryIDs' => 'x' }), []], ['adv none', i.advisories({}), []],
           ['mask ok', i.masked_eq?("\xFF".b, "\x0F".b, "\x0F".b), true], ['mask ignore', i.masked_eq?("\xF0".b, "\x0F".b, "\x00".b), true],
           ['mask bit', i.masked_eq?("\x01".b, "\x01".b, "\x00".b), false], ['mask later', i.masked_eq?("\x00\x01".b, "\xFF\xFF".b, "\x00\x00".b), false],
           ['mask first', i.masked_eq?("\x01\x00".b, "\xFF\xFF".b, "\x00\x00".b), false], ['mask empty', i.masked_eq?(''.b, ''.b, ''.b), true],
           ['mask expected', i.masked_eq?("\x00".b, "\x80".b, "\x80".b), false], ['mask exp-ignored', i.masked_eq?("\x00".b, "\x00".b, "\xFF".b), true],
           ['hit first', i.hit_level([lv.call(9), lv.call(5), lv.call(1)], 5), lv.call(5)], ['hit equal', i.hit_level([lv.call(5)], 5), lv.call(5)],
           ['hit above', i.hit_level([lv.call(6)], 5), nil], ['hit empty', i.hit_level([], 5), nil],
           ['hit skips junk', i.hit_level([5, { 'tcb' => 'x' }, { 'tcb' => { 'isvsvn' => '1' } }, { 'tcb' => {} }, lv.call(2)], 9), lv.call(2)],
           ['hit zero', i.hit_level([lv.call(0)], 0), lv.call(0)],
           ['hit tcb int', i.hit_level([{ 'tcb' => 5 }, { 'tcb' => [1] }, { 'tcb' => nil }, lv.call(1)], 9), lv.call(1)],
           ['status duck', i.as_status(duck), nil], ['svns string', i.svns('x' * 16), nil], ['svns hash', i.svns(Array.new(16) { |k| [k, k] }.to_h), nil],
           ['text', i.text_of('abc'), 'abc'], ['text frozen', i.text_of(frozen), 'abc'], ['text frozen unchanged', frozen.encoding, Encoding::UTF_8],
           ['text invalid', i.text_of("a\xFFb".b), "a\u{FFFD}b"], ['text enc', i.text_of("a\xFFb".b).encoding, Encoding::UTF_8], ['text valid', i.text_of("\xC3\xA9".b), "\u00e9"],
           ['text int', i.text_of(5), 5], ['text nil', i.text_of(nil), nil], ['text obj', i.text_of(o).equal?(o), true]
         ])
  end

  # ================================================================================================ TCB evaluation
  t('c11: evaluate_tcb: the matching level, per-position comparisons, ignored positions for a module minor, first match wins') do
    next true if C11Intel.skip?

    c = C11Intel
    z = C11Intel::Z16
    one_at = ->(j) { Array.new(16) { |k| k == j ? 1 : 0 } }
    res = ->(platform, mod = 'UpToDate', adv = []) { { 'platform' => platform, 'module' => mod, 'advisories' => adv } }
    below = { 'error' => 'platform TCB is below every level in the TCB info' }
    rows = [['plain', c.etcb(c.info_of([c.level])), res.call('UpToDate')]]
    16.times do |j|
      rows << ["sgx #{j} short", c.etcb(c.info_of([c.level(one_at.call(j))])), below]
      rows << ["sgx #{j} met", c.etcb(c.info_of([c.level(one_at.call(j))]), c.pck(one_at.call(j))), res.call('UpToDate')]
      rows << ["sgx #{j} above", c.etcb(c.info_of([c.level(one_at.call(j))]), c.pck(Array.new(16, 7))), res.call('UpToDate')]
      rows << ["tdx #{j} short", c.etcb(c.info_of([c.level(z, one_at.call(j))])), below]
      next if j == 1

      rows << ["tdx #{j} met", c.etcb(c.info_of([c.level(z, one_at.call(j))]), c.pck, c.tdr(svn0: j.zero? ? 1 : 0, rest: j.zero? ? nil : Array.new(14) { |k| k + 2 == j ? 1 : 0 })), res.call('UpToDate')]
    end
    rows << ['tdx 1 needs minor', c.etcb(c.info_of([c.level(z, one_at.call(1))]), c.pck, c.tdr(minor: 1)), { 'error' => 'TDX module identity TDX_01 not present in TCB info' }]
    rows += [
      ['pce short', c.etcb(c.info_of([c.level(z, z, 5)]), c.pck(z, 4)), below], ['pce equal', c.etcb(c.info_of([c.level(z, z, 5)]), c.pck(z, 5)), res.call('UpToDate')],
      ['pce above', c.etcb(c.info_of([c.level(z, z, 5)]), c.pck(z, 9)), res.call('UpToDate')],
      ['first match wins', c.etcb(c.info_of([c.level(Array.new(16, 9), z, 0, 'UpToDate'), c.level(z, z, 0, 'OutOfDate', %w[B A A]), c.level(z, z, 0, 'Revoked')])), res.call('OutOfDate', 'UpToDate', %w[A B])],
      ['adv junk', c.etcb(c.info_of([c.level(z, z, 0, 'SWHardeningNeeded', ['x', 5, nil])])), res.call('SWHardeningNeeded', 'UpToDate', ['x'])],
      ['later junk unseen', c.etcb(c.info_of([c.level, 'garbage'])), res.call('UpToDate')],
      ['no levels', [nil, [], 'x', {}].map { |l| c.etcb({ 'tdxModule' => c::MOD, 'tcbLevels' => l }) }.uniq, [{ 'error' => 'TCB info has no tcbLevels' }]],
      ['no levels key', c.etcb({ 'tdxModule' => c::MOD }), { 'error' => 'TCB info has no tcbLevels' }],
      ['no module', c.etcb({ 'tcbLevels' => [c.level] }), { 'error' => 'TCB info missing tdxModule' }],
      ['module str', c.etcb({ 'tcbLevels' => [c.level], 'tdxModule' => 'x' }), { 'error' => 'TCB info missing tdxModule' }],
      ['level str', c.etcb(c.info_of(['x'])), { 'error' => 'malformed TCB level' }], ['level tcb str', c.etcb(c.info_of([{ 'tcb' => 'x' }])), { 'error' => 'malformed TCB level' }],
      ['junk after miss', c.etcb(c.info_of([c.level(Array.new(16, 9)), 'x'])), { 'error' => 'malformed TCB level' }],
      ['sgx 15', c.etcb(c.info_of([c.level(z.first(15))])), { 'error' => 'malformed TCB level components' }],
      ['tdx 15', c.etcb(c.info_of([c.level(z, z.first(15))])), { 'error' => 'malformed TCB level components' }],
      ['pce str', c.etcb(c.info_of([c.level(z, z, '5')])), { 'error' => 'malformed TCB level components' }],
      ['pce nil', c.etcb(c.info_of([c.level(z, z, nil)])), { 'error' => 'malformed TCB level components' }],
      ['status', c.etcb(c.info_of([c.level(z, z, 0, 'Bogus')])), { 'error' => 'TCB level has an unknown tcbStatus' }],
      ['status after miss', c.etcb(c.info_of([c.level(Array.new(16, 9), z, 0, 'Bogus')])), { 'error' => 'TCB level has an unknown tcbStatus' }]
    ]
    c.ck(rows)
  end

  t('c11: evaluate_tcb: the module identity (base module vs a minor identity), mask, signer, advisories merge') do
    next true if C11Intel.skip?

    c = C11Intel
    z = C11Intel::Z16
    m = C11Intel::MOD
    res = ->(platform, mod, adv) { { 'platform' => platform, 'module' => mod, 'advisories' => adv } }
    ident = lambda do |id = 'TDX_01', levels = [{ 'tcb' => { 'isvsvn' => 5 }, 'tcbStatus' => 'SWHardeningNeeded', 'advisoryIDs' => %w[M2 M1] }], **o|
      { 'id' => id, 'tcbLevels' => levels }.merge(m).merge(o.transform_keys(&:to_s))
    end
    info = ->(ids, levels = [c.level(z, z, 0, 'UpToDate', ['P1'])]) { { 'tcbLevels' => levels, 'tdxModuleIdentities' => ids } }
    td1 = c.tdr(minor: 1, svn0: 5)
    no_ident = ->(id) { { 'error' => "TDX module identity #{id} not present in TCB info" } }
    c.ck([
           ['minor merge', c.etcb(info.call([ident.call]), c.pck, td1), res.call('UpToDate', 'SWHardeningNeeded', %w[M1 M2 P1])],
           ['minor first level', c.etcb(info.call([ident.call('TDX_01', [{ 'tcb' => { 'isvsvn' => 7 }, 'tcbStatus' => 'OutOfDate' }, { 'tcb' => { 'isvsvn' => 5 }, 'tcbStatus' => 'Revoked' }])]), c.pck, td1),
            res.call('UpToDate', 'Revoked', %w[P1])],
           ['svn equal', c.etcb(info.call([ident.call('TDX_01', [{ 'tcb' => { 'isvsvn' => 5 }, 'tcbStatus' => 'UpToDate' }])]), c.pck, td1)['module'], 'UpToDate'],
           ['minor uses start 2', c.etcb(info.call([ident.call], [c.level(z, [9, 9] + ([0] * 14), 0, 'UpToDate')]), c.pck, td1)['platform'], 'UpToDate'],
           ['minor start 2 blocks', c.etcb(info.call([ident.call], [c.level(z, ([0] * 2) + [1] + ([0] * 13), 0, 'UpToDate')]), c.pck, td1),
            { 'error' => 'platform TCB is below every level in the TCB info' }],
           ['minor ignores base module', c.etcb(info.call([ident.call]), c.pck, td1).key?('error'), false],
           ['id format 10', c.etcb(info.call([ident.call('TDX_0A')]), c.pck, c.tdr(minor: 10, svn0: 5))['module'], 'SWHardeningNeeded'],
           ['id format 255', c.etcb(info.call([ident.call('TDX_FF')]), c.pck, c.tdr(minor: 255, svn0: 5))['module'], 'SWHardeningNeeded'],
           ['id lower', c.etcb(info.call([ident.call('TDX_0a')]), c.pck, c.tdr(minor: 10, svn0: 5)), no_ident.call('TDX_0A')],
           ['id absent', c.etcb(info.call([ident.call('TDX_02')]), c.pck, td1), no_ident.call('TDX_01')],
           ['ids nil', c.etcb(info.call(nil), c.pck, td1), no_ident.call('TDX_01')], ['ids str', c.etcb(info.call('x'), c.pck, td1), no_ident.call('TDX_01')],
           ['ids junk first', c.etcb(info.call([5, nil, 'x', ident.call]), c.pck, td1)['module'], 'SWHardeningNeeded'],
           ['ident levels nil', c.etcb(info.call([ident.call('TDX_01', nil)]), c.pck, td1), { 'error' => 'TDX module TDX_01 SVN 5 is below every known level' }],
           ['ident levels below', c.etcb(info.call([ident.call('TDX_01', [{ 'tcb' => { 'isvsvn' => 6 }, 'tcbStatus' => 'UpToDate' }])]), c.pck, td1),
            { 'error' => 'TDX module TDX_01 SVN 5 is below every known level' }],
           ['ident status', c.etcb(info.call([ident.call('TDX_01', [{ 'tcb' => { 'isvsvn' => 5 }, 'tcbStatus' => 'Bogus' }])]), c.pck, td1),
            { 'error' => 'TDX module level has an unknown tcbStatus' }],
           ['ident fields', c.etcb(info.call([ident.call(attributes: nil)]), c.pck, td1), { 'error' => 'TDX module identity fields malformed' }],
           ['ident signer', c.etcb(info.call([ident.call(mrsigner: 'cd' * 48)]), c.pck, td1),
            { 'error' => 'TD report MRSIGNERSEAM does not match the TDX module identity' }],
           ['base fields 1', c.etcb(c.info_of([c.level], m.merge('mrsigner' => 'ab' * 47))), { 'error' => 'TDX module identity fields malformed' }],
           ['base fields 2', c.etcb(c.info_of([c.level], m.merge('mrsigner' => 'zz' * 48))), { 'error' => 'TDX module identity fields malformed' }],
           ['base fields 3', c.etcb(c.info_of([c.level], m.merge('attributes' => '00' * 7))), { 'error' => 'TDX module identity fields malformed' }],
           ['base fields 4', c.etcb(c.info_of([c.level], m.merge('attributesMask' => nil))), { 'error' => 'TDX module identity fields malformed' }],
           ['base fields 5', c.etcb(c.info_of([c.level], m.merge('attributesMask' => 'ff' * 9))), { 'error' => 'TDX module identity fields malformed' }],
           ['signer', c.etcb(c.info_of([c.level]), c.pck, c.tdr(signer: "\xac".b * 48)), { 'error' => 'TD report MRSIGNERSEAM does not match the TDX module identity' }],
           ['signer last byte', c.etcb(c.info_of([c.level]), c.pck, c.tdr(signer: ("\xab".b * 47) + "\xac".b)),
            { 'error' => 'TD report MRSIGNERSEAM does not match the TDX module identity' }],
           ['attr', c.etcb(c.info_of([c.level]), c.pck, c.tdr(attr: "\x01".b + ("\x00".b * 7))), { 'error' => 'TD report SEAM attributes do not match the TDX module identity' }],
           ['attr last byte', c.etcb(c.info_of([c.level]), c.pck, c.tdr(attr: ("\x00".b * 7) + "\x01".b)),
            { 'error' => 'TD report SEAM attributes do not match the TDX module identity' }],
           ['attr masked', c.etcb(c.info_of([c.level], m.merge('attributesMask' => 'fe' + ('ff' * 7))), c.pck, c.tdr(attr: "\x01".b + ("\x00".b * 7)))['platform'], 'UpToDate'],
           ['attr mask 0', c.etcb(c.info_of([c.level], m.merge('attributesMask' => '00' * 8)), c.pck, c.tdr(attr: "\xFF".b * 8))['platform'], 'UpToDate'],
           ['attr expected', c.etcb(c.info_of([c.level], m.merge('attributes' => '80' + ('00' * 7), 'attributesMask' => '80' + ('00' * 7))), c.pck, c.tdr(attr: "\x80".b + ("\x00".b * 7)))['platform'], 'UpToDate'],
           ['fields before signer', c.etcb(c.info_of([c.level], m.merge('mrsigner' => 'zz' * 48)), c.pck, c.tdr(signer: "\xac".b * 48)), { 'error' => 'TDX module identity fields malformed' }]
         ])
  end

  t('c11: evaluate_qe: identity fields, report slices, ISVPRODID / ISVSVN little endian, first reached level, every refusal') do
    next true if C11Intel.skip?

    c = C11Intel
    duck = Object.new
    def duck.==(_other) = true
    q = ->(ident = c.qe_ident, qe = c.qe_bytes) { c.i.evaluate_qe(ident, qe) }
    e = ->(m) { { 'error' => m } }
    lv = ->(sv, st = 'UpToDate', adv = nil) { { 'tcb' => { 'isvsvn' => sv }, 'tcbStatus' => st }.merge(adv ? { 'advisoryIDs' => adv } : {}) }
    c.ck([
           ['ok', q.call, { 'status' => 'UpToDate', 'advisories' => ['Q1'] }],
           ['picks first reached', q.call(c.qe_ident(tcbLevels: [lv.call(0x0400, 'OutOfDate'), lv.call(0x0304, 'SWHardeningNeeded', %w[B A]), lv.call(0, 'UpToDate')])),
            { 'status' => 'SWHardeningNeeded', 'advisories' => %w[B A] }],
           ['no advisories', q.call(c.qe_ident(tcbLevels: [lv.call(0)])), { 'status' => 'UpToDate', 'advisories' => [] }],
           ['id', q.call(c.qe_ident(id: 'TD_QE2')), e.call('QE identity id is not TD_QE')], ['id nil', q.call(c.qe_ident(id: nil)), e.call('QE identity id is not TD_QE')],
           ['version 1', q.call(c.qe_ident(version: 1)), e.call('unsupported QE identity version')], ['version 3', q.call(c.qe_ident(version: 3)), e.call('unsupported QE identity version')],
           ['version str', q.call(c.qe_ident(version: '2')), e.call('unsupported QE identity version')], ['version nil', q.call(c.qe_ident(version: nil)), e.call('unsupported QE identity version')],
           ['version 2.0', q.call(c.qe_ident(version: 2.0))['status'], 'UpToDate'], ['version true', q.call(c.qe_ident(version: true)), e.call('unsupported QE identity version')],
           ['version duck', q.call(c.qe_ident(version: duck)), e.call('unsupported QE identity version')],
           ['prod duck', q.call(c.qe_ident(isvprodid: duck)), e.call('QE identity fields malformed')],
           ['misc len', q.call(c.qe_ident(miscselect: '010203')), e.call('QE identity fields malformed')],
           ['misc mask len', q.call(c.qe_ident(miscselectMask: 'ffffffff00')), e.call('QE identity fields malformed')],
           ['attr len', q.call(c.qe_ident(attributes: 'ab' * 15)), e.call('QE identity fields malformed')],
           ['attr mask len', q.call(c.qe_ident(attributesMask: 'ff' * 17)), e.call('QE identity fields malformed')],
           ['mrsigner len', q.call(c.qe_ident(mrsigner: 'cd' * 31)), e.call('QE identity fields malformed')],
           ['mrsigner nonhex', q.call(c.qe_ident(mrsigner: 'zz' * 32)), e.call('QE identity fields malformed')],
           ['prod str', q.call(c.qe_ident(isvprodid: '258')), e.call('QE identity fields malformed')], ['prod nil', q.call(c.qe_ident(isvprodid: nil)), e.call('QE identity fields malformed')],
           ['malformed before length', q.call(c.qe_ident(miscselect: 'zz'), c.qe_bytes.byteslice(0, 383)), e.call('QE identity fields malformed')],
           ['len 383', q.call(c.qe_ident, c.qe_bytes.byteslice(0, 383)), e.call('QE report has wrong length')],
           ['len 385', q.call(c.qe_ident, c.qe_bytes + "\x00".b), e.call('QE report has wrong length')],
           ['misc', q.call(c.qe_ident, c.qe_bytes(misc: [1, 2, 3, 5])), e.call('QE MISCSELECT does not match the QE identity')],
           ['misc first', q.call(c.qe_ident, c.qe_bytes(misc: [0, 2, 3, 4])), e.call('QE MISCSELECT does not match the QE identity')],
           ['misc masked', q.call(c.qe_ident(miscselectMask: 'ff000000'), c.qe_bytes(misc: [1, 9, 9, 9]))['status'], 'UpToDate'],
           ['misc slice', q.call(c.qe_ident, c.qe_bytes.tap { |b| b[20, 1] = "\x09".b })['status'], 'UpToDate'],
           ['attrs', q.call(c.qe_ident, c.qe_bytes(attrs: (1..15).to_a + [99])), e.call('QE ATTRIBUTES do not match the QE identity')],
           ['attrs first', q.call(c.qe_ident, c.qe_bytes(attrs: [99] + (2..16).to_a)), e.call('QE ATTRIBUTES do not match the QE identity')],
           ['attrs masked', q.call(c.qe_ident(attributesMask: 'ff' * 15 + '00'), c.qe_bytes(attrs: (1..15).to_a + [99]))['status'], 'UpToDate'],
           ['attrs slice', q.call(c.qe_ident, c.qe_bytes.tap { |b| b[64, 1] = "\x09".b })['status'], 'UpToDate'],
           ['mrsigner', q.call(c.qe_ident, c.qe_bytes(signer: ("\xcd".b * 31) + "\xce".b)), e.call('QE MRSIGNER does not match the QE identity')],
           ['mrsigner first', q.call(c.qe_ident, c.qe_bytes(signer: "\xce".b + ("\xcd".b * 31))), e.call('QE MRSIGNER does not match the QE identity')],
           ['prod', q.call(c.qe_ident, c.qe_bytes(prod: 0x0103)), e.call('QE ISVPRODID does not match the QE identity')],
           ['prod high byte', q.call(c.qe_ident, c.qe_bytes(prod: 0x0202)), e.call('QE ISVPRODID does not match the QE identity')],
           ['prod low byte', q.call(c.qe_ident, c.qe_bytes(prod: 0x0101)), e.call('QE ISVPRODID does not match the QE identity')],
           ['isvsvn equal', q.call(c.qe_ident(tcbLevels: [lv.call(0x0304)]))['status'], 'UpToDate'],
           ['isvsvn below', q.call(c.qe_ident(tcbLevels: [lv.call(0x0305)])), e.call('QE ISVSVN is below every known level')],
           ['isvsvn high byte', q.call(c.qe_ident(tcbLevels: [lv.call(0x0204)]))['status'], 'UpToDate'],
           ['isvsvn high byte up', q.call(c.qe_ident(tcbLevels: [lv.call(0x0304)]), c.qe_bytes(isv: 0x0204)), e.call('QE ISVSVN is below every known level')],
           ['levels nil', q.call(c.qe_ident(tcbLevels: nil)), e.call('QE ISVSVN is below every known level')],
           ['levels str', q.call(c.qe_ident(tcbLevels: 'x')), e.call('QE ISVSVN is below every known level')],
           ['status', q.call(c.qe_ident(tcbLevels: [lv.call(0, 'Bogus')])), e.call('QE level has an unknown tcbStatus')]
         ])
  end

  # ================================================================================================ collateral entry
  t('c11: verify_intel_tdx_collateral: incomplete collateral, quote step reasons, the debug and pin arguments reach the quote check') do
    next true if C11Intel.skip?

    c = C11Intel
    i = c.i
    full = %w[tcbInfoJson qeIdentityJson pckCrlDer rootCrlDer tcbInfoIssuerChainPem qeIdentityIssuerChainPem].to_h { |k| [k, 'x'] }
    incomplete = { 'ok' => false, 'reason' => 'collateral incomplete (fail closed)' }
    qinv = ->(m) { { 'ok' => false, 'reason' => "quote invalid: #{m}" } }
    rows = [['nil', i.verify_intel_tdx_collateral('q'.b, nil, 1), incomplete], ['empty', i.verify_intel_tdx_collateral('q'.b, {}, 1), incomplete],
            ['empty array', i.verify_intel_tdx_collateral('q'.b, [], 1), incomplete]]
    full.each_key do |k|
      [nil, false, ''].each { |bad| rows << ["#{k}=#{bad.inspect}", i.verify_intel_tdx_collateral('q'.b, full.merge(k => bad), 1), incomplete] }
    end
    seen = []
    stub = ->(ret) { ->(*a) { seen << a; ret } }
    run = ->(ret, *rest) { seen.clear; MutationKill::Seam.with(i, { verify_genuine_tdx_quote: stub.call(ret) }) { i.verify_intel_tdx_collateral('Q'.b, full, 77, *rest) } }
    rows += [
      ['bad quote', i.verify_intel_tdx_collateral('abc'.b, full, 1), qinv.call('quote parse failed: parseDcapQuote: too short for header + TD report + sig length')],
      ['unknown', run.call({ 'ok' => false }), qinv.call('unknown')], ['unknown ok no tcb', run.call({ 'ok' => true, 'fmspc' => 'ab' }), qinv.call('unknown')],
      ['unknown no fmspc', run.call({ 'ok' => true, 'pckTcb' => {} }), qinv.call('unknown')], ['unknown empty fmspc', run.call({ 'ok' => true, 'pckTcb' => {}, 'fmspc' => '' }), qinv.call('unknown')],
      ['reason', run.call({ 'ok' => false, 'reason' => 'why' }), qinv.call('why')]
    ]
    run.call({ 'ok' => false })
    rows << ['args default', seen.map(&:dup), [['Q'.b, nil, nil, nil, 77]]]
    run.call({ 'ok' => false }, nil, 'PIN', true)
    rows << ['args pin debug', seen.map(&:dup), [['Q'.b, 'PIN', nil, { 'allowDebug' => true }, 77]]]
    run.call({ 'ok' => false }, nil, nil, false)
    rows << ['args debug false', seen.map(&:dup), [['Q'.b, nil, nil, nil, 77]]]
    run.call({ 'ok' => false }, nil, nil, 'true')
    rows << ['args debug string', seen.map(&:dup), [['Q'.b, nil, nil, nil, 77]]]
    c.ck(rows)
  end

  t('c11: verify_intel_tdx_collateral on the genuine collateral: floor given as a number or a numeric string, accepted statuses, quote chain clock') do
    next true if C11Intel.skip?

    c = C11Intel
    i = c.i
    quote = c.real_quote
    col = c.real_col.merge('pckCrlDer' => c.cm.node_b64decode(c.real_col['pckCrlDer']), 'rootCrlDer' => c.cm.node_b64decode(c.real_col['rootCrlDer']))
    now = c.real_now
    base = i.verify_intel_tdx_collateral(quote, col, now)
    info = c.cm.js_json_loads(i.raw_json_object(c.real_col['tcbInfoJson'], 'tcbInfo'))
    qe = c.cm.js_json_loads(i.raw_json_object(c.real_col['qeIdentityJson'], 'enclaveIdentity'))
    lo = [info['tcbEvaluationDataNumber'], qe['tcbEvaluationDataNumber']].min
    f = ->(pol) { i.verify_intel_tdx_collateral(quote, col, now, pol) }
    below = { 'ok' => false, 'reason' => 'tcbEvaluationDataNumber below policy minimum' }
    st = base['status']
    notacc = { 'ok' => false, 'status' => st, 'advisoryIds' => base['advisoryIds'], 'reason' => "TCB status #{st} is not accepted by policy" }
    c.ck([
           ['base ok', base['ok'], true], ['base keys', base.keys, %w[ok status advisoryIds]], ['base status in order', i::STATUS_ORDER.include?(st), true],
           ['floor eq', f.call({ 'minTcbEvaluationDataNumber' => lo })['ok'], true], ['floor above', f.call({ 'minTcbEvaluationDataNumber' => lo + 1 }), below],
           ['floor str eq', f.call({ 'minTcbEvaluationDataNumber' => lo.to_s })['ok'], true], ['floor str space', f.call({ 'minTcbEvaluationDataNumber' => " #{lo} " })['ok'], true],
           ['floor str above', f.call({ 'minTcbEvaluationDataNumber' => (lo + 1).to_s }), below], ['floor str junk', f.call({ 'minTcbEvaluationDataNumber' => 'abc' }), below],
           ['floor str empty', f.call({ 'minTcbEvaluationDataNumber' => '' })['ok'], true], ['floor nil', f.call({ 'minTcbEvaluationDataNumber' => nil })['ok'], true],
           ['accept empty', f.call({ 'acceptStatuses' => [] }), notacc], ['accept other', f.call({ 'acceptStatuses' => ['Revoked'] }), notacc],
           ['accept status', f.call({ 'acceptStatuses' => [st] })['ok'], true],
           ['pin wrong', i.verify_intel_tdx_collateral(quote, col, now, nil, '00' * 32), { 'ok' => false, 'reason' => 'quote invalid: PCK chain invalid: Intel SGX Root CA does not match the pinned trust anchor' }],
           ['chain clock', i.verify_intel_tdx_collateral(quote, col, 0)['reason'], 'quote invalid: PCK chain invalid: PCK chain certificate outside its validity period'],
           ['rescue', i.verify_intel_tdx_collateral(quote, col.merge('rootCrlDer' => 5), now)['reason'].start_with?('collateral verification error (fail closed): '), true]
         ])
  end

  # ================================================================================================ the verifier object
  t('c11: IntelDcapVerifier.new: binding, allowlist and policy refusals with their messages; what it keeps') do
    next true if C11Intel.skip?

    c = C11Intel
    v = AtlasPca::Attest::IntelDcapVerifier
    m96 = 'ab' * 48
    mk = ->(o) { c.err { v.new({ 'binding' => 'report-data', 'policy' => { 'mrtds' => [m96] } }.merge(o)) } }
    pre = 'createIntelDcapVerifier: '
    cls = ->(r) { r.nil? ? nil : [r[0].name.split('::').last, r[1]] }
    ce = ->(msg) { ['AttestConstructError', "#{pre}#{msg}"] }
    ok = v.new({ 'binding' => 'azure-runtime-data', 'policy' => { 'mrtds' => [m96.upcase, 'cd' * 48], 'allowDebug' => true }, 'trustAnchorRootCaSpkiSha256' => 'AB' * 32,
                 'allowMissingCollateral' => true, 'resolve_evidence' => :r })
    plain = v.new({ 'binding' => 'report-data', 'policy' => { 'mrtds' => [m96] } })
    iv = ->(o, n) { o.instance_variable_get(n) }
    c.ck([
           ['binding bad', cls.call(c.err { v.new({ 'binding' => 'x', 'policy' => { 'mrtds' => [m96] } }) }), ce.call("binding must be 'report-data' or 'azure-runtime-data'")],
           ['binding nil', cls.call(c.err { v.new({ 'policy' => { 'mrtds' => [m96] } }) }), ce.call("binding must be 'report-data' or 'azure-runtime-data'")],
           ['no policy', cls.call(mk.call('policy' => nil)), ce.call('policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)')],
           ['policy str', cls.call(mk.call('policy' => 'x')), ce.call('policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)')],
           ['mrtds empty', cls.call(mk.call('policy' => { 'mrtds' => [] })), ce.call('policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)')],
           ['mrtds str', cls.call(mk.call('policy' => { 'mrtds' => m96 })), ce.call('policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)')],
           ['mrtds short', cls.call(mk.call('policy' => { 'mrtds' => ['ab' * 47] })), ce.call('every MRTD must be 96 hex chars (48 bytes)')],
           ['mrtds long', cls.call(mk.call('policy' => { 'mrtds' => ['ab' * 49] })), ce.call('every MRTD must be 96 hex chars (48 bytes)')],
           ['mrtds nonhex', cls.call(mk.call('policy' => { 'mrtds' => ['zz' * 48] })), ce.call('every MRTD must be 96 hex chars (48 bytes)')],
           ['mrtds second bad', cls.call(mk.call('policy' => { 'mrtds' => [m96, 'ab' * 47] })), ce.call('every MRTD must be 96 hex chars (48 bytes)')],
           ['mrtds nl', cls.call(mk.call('policy' => { 'mrtds' => [m96[0, 95] + "\n"] })), ce.call('every MRTD must be 96 hex chars (48 bytes)')],
           ['upper ok', mk.call('policy' => { 'mrtds' => [m96.upcase] }), nil]
         ] + %w[mrSeams mrSignerSeams].flat_map do |n|
           [["#{n} empty", cls.call(mk.call('policy' => { 'mrtds' => [m96], n => [] })), ce.call("policy.#{n}, if given, must be a NON-EMPTY list")],
            ["#{n} nil", cls.call(mk.call('policy' => { 'mrtds' => [m96], n => nil })), ce.call("policy.#{n}, if given, must be a NON-EMPTY list")],
            ["#{n} str", cls.call(mk.call('policy' => { 'mrtds' => [m96], n => m96 })), ce.call("policy.#{n}, if given, must be a NON-EMPTY list")],
            ["#{n} int", cls.call(mk.call('policy' => { 'mrtds' => [m96], n => [5] })), ce.call("every #{n} entry must be 96 hex chars (48 bytes)")],
            ["#{n} short", cls.call(mk.call('policy' => { 'mrtds' => [m96], n => ['ab' * 47] })), ce.call("every #{n} entry must be 96 hex chars (48 bytes)")],
            ["#{n} nonhex", cls.call(mk.call('policy' => { 'mrtds' => [m96], n => ['zz' * 48] })), ce.call("every #{n} entry must be 96 hex chars (48 bytes)")],
            ["#{n} second bad", cls.call(mk.call('policy' => { 'mrtds' => [m96], n => [m96, 'ab' * 47] })), ce.call("every #{n} entry must be 96 hex chars (48 bytes)")],
            ["#{n} upper ok", mk.call('policy' => { 'mrtds' => [m96], n => [m96.upcase] }), nil],
            ["#{n} absent ok", mk.call('policy' => { 'mrtds' => [m96] }), nil]]
         end + [
           ['kept binding', iv.call(ok, :@binding), 'azure-runtime-data'], ['kept mrtds', iv.call(ok, :@mrtds), [m96, 'cd' * 48]],
           ['kept pin', iv.call(ok, :@pin), 'ab' * 32], ['default pin', iv.call(plain, :@pin), c.i::SGX_ROOT_CA_SPKI_SHA256],
           ['kept policy', iv.call(ok, :@policy), { 'mrtds' => [m96.upcase, 'cd' * 48], 'allowDebug' => true }], ['kept resolver', iv.call(ok, :@resolve), :r],
           ['allow missing', iv.call(ok, :@allow_missing), true], ['allow missing default', iv.call(plain, :@allow_missing), false],
           ['allow missing str', iv.call(v.new({ 'binding' => 'report-data', 'policy' => { 'mrtds' => [m96] }, 'allowMissingCollateral' => 'true' }), :@allow_missing), false],
           ['allow missing 1', iv.call(v.new({ 'binding' => 'report-data', 'policy' => { 'mrtds' => [m96] }, 'allowMissingCollateral' => 1 }), :@allow_missing), false],
           ['plain policy', iv.call(plain, :@policy), { 'mrtds' => [m96] }], ['no resolver', iv.call(plain, :@resolve), nil],
           ['array policy is {}', cls.call(c.err { v.new({ 'binding' => 'report-data', 'policy' => [m96] }) }), ce.call('policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)')],
           ['truthy', [:nil, :f, :t, :s, :e].zip([nil, false, true, 'x', '']).map { |(_k, val)| plain.send(:mesh_truthy, val) }, [false, false, true, true, false]]
         ])
  end

  t('c11: IntelDcapVerifier#verify: resolver, evidence and expected-binding refusals, quote failures, missing-collateral policy') do
    next true if C11Intel.skip?

    c = C11Intel
    v = AtlasPca::Attest::IntelDcapVerifier
    m96 = 'ab' * 48
    rf = ->(m) { { 'ok' => false, 'reason' => m } }
    opts = { 'binding' => 'report-data', 'policy' => { 'mrtds' => [m96] } }
    mk = ->(ev, o = {}) { v.new(opts.merge('resolve_evidence' => ->(_d) { ev }).merge(o)) }
    exp = { 'holder_pub' => 'h', 'grant_ref' => 'g', 'epoch' => 1, 'nonce' => 'n' }
    q = c.real_quote
    now = c.real_now
    real_mrtd = 'a2e61f1316e9e367e9c1f7a0adc98c48eb13875c399c85d286cee5ea2b05e57f2df9f61d903b0ae7ac5607d843dfffc1'
    real_opts = { 'binding' => 'report-data', 'policy' => { 'mrtds' => [real_mrtd] } }
    real = ->(o = {}) { v.new(real_opts.merge('resolve_evidence' => ->(_d) { { 'quote' => q } }).merge(o)) }
    bound = lambda do |ver|
      want = c.cm.attestation_binding(exp)
      MutationKill::Seam.with(c.i, { verify_genuine_tdx_quote: lambda { |*_a|
        { 'ok' => true, 'report' => { 'reportData' => want }, 'measured' => { 'm' => 1 }, 'fmspc' => 'ab12' }
      } }) { ver.verify({}, exp, now) }
    end
    c.ck([
           ['no resolver', v.new(opts).verify({}, exp, now), rf.call('no Intel DCAP evidence resolver configured (fail closed)')],
           ['ev nil', mk.call(nil).verify({}, exp, now), rf.call('no Intel DCAP quote for this action')],
           ['ev str', mk.call('x').verify({}, exp, now), rf.call('no Intel DCAP quote for this action')],
           ['ev array', mk.call([]).verify({}, exp, now), rf.call('no Intel DCAP quote for this action')],
           ['ev no quote', mk.call({}).verify({}, exp, now), rf.call('no Intel DCAP quote for this action')],
           ['quote int', mk.call({ 'quote' => 5 }).verify({}, exp, now), rf.call('no Intel DCAP quote for this action')],
           ['expected nil', mk.call({ 'quote' => 'x' }).verify({}, nil, now), rf.call('no expected attestation binding supplied')],
           ['quote junk', mk.call({ 'quote' => 'abc' }).verify({}, exp, now),
            rf.call('DCAP quote invalid: quote parse failed: parseDcapQuote: too short for header + TD report + sig length')],
           ['real, bad binding', real.call.verify({}, { 'holder_pub' => '', 'grant_ref' => 'g', 'epoch' => 1, 'nonce' => 'n' }, now),
            rf.call('binding not constructible: binding: holderPub required')],
           ['real, wrong binding', real.call.verify({}, exp, now), rf.call('report_data does not bind holder/grant/epoch/nonce')],
           ['real, azure no runtime', real.call('binding' => 'azure-runtime-data').verify({}, exp, now), rf.call('azure-runtime-data binding needs the runtime-data JSON bytes')],
           ['no collateral', bound.call(mk.call({ 'quote' => 'x' })), rf.call('Intel PCS collateral required but not supplied (set allowMissingCollateral to opt out explicitly)')],
           ['opt out', bound.call(mk.call({ 'quote' => 'x' }, 'allowMissingCollateral' => true)),
            { 'ok' => true, 'bound' => true, 'measured' => { 'm' => 1 }, 'hostAsserted' => { 'attestation_type' => 'tdx-dcap', 'fmspc' => 'ab12', 'tcb_status' => 'unevaluated' } }],
           ['collateral false', bound.call(mk.call({ 'quote' => 'x', 'collateral' => false })), rf.call('Intel PCS collateral required but not supplied (set allowMissingCollateral to opt out explicitly)')],
           ['collateral empty str', bound.call(mk.call({ 'quote' => 'x', 'collateral' => '' })), rf.call('Intel PCS collateral required but not supplied (set allowMissingCollateral to opt out explicitly)')],
           ['unknown fmspc', MutationKill::Seam.with(c.i, { verify_genuine_tdx_quote: ->(*_a) { { 'ok' => true, 'report' => {}, 'measured' => {}, 'fmspc' => '' } } }) do
             mk.call({ 'quote' => 'x' }).verify({}, exp, now)
           end, rf.call('DCAP quote invalid: unknown')],
           ['no report', MutationKill::Seam.with(c.i, { verify_genuine_tdx_quote: ->(*_a) { { 'ok' => true, 'measured' => {}, 'fmspc' => 'ab' } } }) do
             mk.call({ 'quote' => 'x' }).verify({}, exp, now)
           end, rf.call('DCAP quote invalid: unknown')],
           ['no measured', MutationKill::Seam.with(c.i, { verify_genuine_tdx_quote: ->(*_a) { { 'ok' => true, 'report' => {}, 'fmspc' => 'ab' } } }) do
             mk.call({ 'quote' => 'x' }).verify({}, exp, now)
           end, rf.call('DCAP quote invalid: unknown')],
           ['not ok', MutationKill::Seam.with(c.i, { verify_genuine_tdx_quote: ->(*_a) { { 'ok' => false, 'report' => {}, 'measured' => {}, 'fmspc' => 'ab' } } }) do
             mk.call({ 'quote' => 'x' }).verify({}, exp, now)
           end, rf.call('DCAP quote invalid: unknown')],
           ['no fmspc', MutationKill::Seam.with(c.i, { verify_genuine_tdx_quote: ->(*_a) { { 'ok' => true, 'report' => {}, 'measured' => {} } } }) do
             mk.call({ 'quote' => 'x' }).verify({}, exp, now)
           end, rf.call('DCAP quote invalid: unknown')],
           ['azure runtime int', real.call('binding' => 'azure-runtime-data', 'resolve_evidence' => ->(_d) { { 'quote' => q, 'runtimeData' => 5 } }).verify({}, exp, now),
            rf.call('azure-runtime-data binding needs the runtime-data JSON bytes')],
           ['rescue', v.new(opts.merge('resolve_evidence' => ->(_d) { raise 'boom' })).verify({}, exp, now),
            rf.call('intel-dcap verification error (fail closed): boom')]
         ])
  end

  t('c11: IntelDcapVerifier#verify hands the quote check its allowlists (truthy only), the debug flag and the pin') do
    next true if C11Intel.skip?

    c = C11Intel
    v = AtlasPca::Attest::IntelDcapVerifier
    m96 = 'ab' * 48
    seen = []
    exp = { 'holder_pub' => 'h', 'grant_ref' => 'g', 'epoch' => 1, 'nonce' => 'n' }
    mk = lambda do |pol|
      v.new({ 'binding' => 'report-data', 'policy' => { 'mrtds' => [m96.upcase] }.merge(pol), 'trustAnchorRootCaSpkiSha256' => 'AA' * 32,
              'resolve_evidence' => ->(_d) { { 'quote' => "Qq".dup.force_encoding('UTF-8') } } })
    end
    run = lambda do |pol|
      seen.clear
      MutationKill::Seam.with(c.i, { verify_genuine_tdx_quote: ->(*a) { seen << a; { 'ok' => false, 'reason' => 'stop' } } }) { mk.call(pol).verify({}, exp, 55) }
      seen.first
    end
    s1 = run.call({ 'fmspcs' => ['AB'], 'rtmrs' => ['cd'], 'mrSeams' => [m96], 'mrSignerSeams' => [m96], 'allowDebug' => true })
    s2 = run.call({ 'fmspcs' => nil, 'allowDebug' => 'true' })
    s3 = run.call({ 'fmspcs' => [] })
    c.ck([
           ['quote binary', [s1[0], s1[0].encoding], ['Qq'.b, Encoding::BINARY]], ['pin', s1[1], 'aa' * 32], ['no expected', s1[2], nil], ['now', s1[4], 55],
           ['policy all', s1[3], { 'mrtds' => [m96], 'mrSeams' => [m96], 'mrSignerSeams' => [m96], 'fmspcs' => ['AB'], 'rtmrs' => ['cd'], 'allowDebug' => true }],
           ['policy falsy', s2[3], { 'mrtds' => [m96] }], ['policy empty list kept', s3[3], { 'mrtds' => [m96], 'fmspcs' => [] }]
         ])
  end

  # ================================================================================================ genuine quote, steps a genuine quote never fails
  # A genuine quote with chosen bytes changed and the two ECDSA checks stubbed (the chain is still verified for real).
  module C11Mod
    module_function

    OFF_TD = 48
    OFF_AK = 636 + 64
    OFF_QE = 636 + 64 + 64 + 6
    OFF_QE_RD = OFF_QE + 0x140

    def with_p256(results)
      calls = []
      i = C11Intel.i
      stub = ->(msg, sig, key) { calls << [msg, sig, key]; results.is_a?(Proc) ? results.call(calls.size) : results }
      [MutationKill::Seam.with(i, { verify_p256: stub }) { yield }, calls]
    end

    def run(q, pol = nil, results = true)
      with_p256(results) { C11Intel.i.verify_genuine_tdx_quote(q, nil, nil, pol, C11Intel.real_now) }
    end

    def mod
      q = C11Intel.real_quote
      yield q
      q
    end

    def auth_of(q) = q.byteslice(OFF_QE + 384 + 64 + 2, q.byteslice(OFF_QE + 384 + 64, 2).unpack1('v'))
  end

  t('c11: verify_genuine_tdx_quote: debug QE, AK binding, AK point, TD signature, TD debug flag (ECDSA stubbed, chain real)') do
    next true if C11Intel.skip?

    c = C11Intel
    m = C11Mod
    rf = ->(r) { { 'ok' => false, 'reason' => r } }
    real = c.real_quote
    dbg_q = m.mod { |q| q.setbyte(m::OFF_QE + 48, q.getbyte(m::OFF_QE + 48) | 0x02) }
    odd_q = m.mod { |q| q.setbyte(m::OFF_QE + 48, q.getbyte(m::OFF_QE + 48) | 0x05) }
    bind = rf.call('QE report_data does not bind the attestation key (AK not endorsed by this QE)')
    ak_q = m.mod { |q| q.setbyte(m::OFF_AK, q.getbyte(m::OFF_AK) ^ 1) }
    tail_q = m.mod { |q| q.setbyte(m::OFF_QE_RD + 32, 1) }
    tail_last_q = m.mod { |q| q.setbyte(m::OFF_QE_RD + 63, 1) }
    zero_ak = m.mod do |q|
      q[m::OFF_AK, 64] = "\x00".b * 64
      q[m::OFF_QE_RD, 32] = Digest::SHA256.digest(("\x00".b * 64) + m.auth_of(q))
    end
    td_dbg = m.mod { |q| q.setbyte(m::OFF_TD + 120, q.getbyte(m::OFF_TD + 120) | 1) }
    td_other = m.mod { |q| q.setbyte(m::OFF_TD + 120, 0x02) }
    r_dbg, = m.run(dbg_q)
    r_odd, = m.run(odd_q)
    r_ak, = m.run(ak_q)
    r_tail, = m.run(tail_q)
    r_tail_last, = m.run(tail_last_q)
    r_zero, = m.run(zero_ak)
    r_td_sig, calls = m.run(real, nil, ->(n) { n == 1 })
    parsed = c.i.parse_dcap_quote(real)
    r_tdd, = m.run(td_dbg)
    td_dbg_pol = ->(pol) { m.run(td_dbg, pol).first }
    c.ck([
           ['debug QE', r_dbg, rf.call('QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)')], ['other QE attribute bits', r_odd['ok'], true],
           ['AK binding', r_ak, bind], ['QE data tail', r_tail, bind], ['QE data tail last byte', r_tail_last, bind],
           ['AK off curve', r_zero, rf.call('attestation public key is not a valid P-256 point')],
           ['TD signature', r_td_sig, rf.call('TD quote signature does not verify under the attestation key')],
           ['p256 calls', calls.size, 2],
           ['qe check args', [calls[0][0], calls[0][1], calls[0][2].class], [parsed['qeReportBody'], parsed['qeReportSignature'], OpenSSL::PKey::EC]],
           ['td check args', [calls[1][0], calls[1][1], calls[1][2].class], [parsed['header'] + parsed['tdReportBody'], parsed['quoteSignature'], OpenSSL::PKey::EC]],
           ['TD debug', r_tdd, rf.call('TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)')],
           ['TD debug allowed', td_dbg_pol.call({ 'allowDebug' => true })['ok'], true],
           ['TD debug allow false', td_dbg_pol.call({ 'allowDebug' => false }), rf.call('TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)')],
           ['TD debug allow string', td_dbg_pol.call({ 'allowDebug' => 'true' }), rf.call('TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)')],
           ['TD other attribute bit', m.run(td_other).first['ok'], true]
         ])
  end

  # ================================================================================================ collateral pipeline with chosen documents
  module C11Col
    module_function

    def c = C11Intel
    def quote = c.real_quote
    def now = c.real_now

    def col
      c.real_col.merge('pckCrlDer' => c.cm.node_b64decode(c.real_col['pckCrlDer']), 'rootCrlDer' => c.cm.node_b64decode(c.real_col['rootCrlDer']))
    end

    def fmspc = c.real['expect']['hostAsserted']['fmspc']
    def info = c.cm.js_json_loads(c.i.raw_json_object(c.real_col['tcbInfoJson'], 'tcbInfo'))
    def qe = c.cm.js_json_loads(c.i.raw_json_object(c.real_col['qeIdentityJson'], 'enclaveIdentity'))
    ALL = %w[UpToDate SWHardeningNeeded ConfigurationNeeded ConfigurationAndSWHardeningNeeded OutOfDateConfigurationNeeded OutOfDate Revoked].freeze

    # runs the collateral check on `q`; the quote step answers {ok} (fmspc of the genuine quote), the signed documents are rewritten
    # by info_fn / qe_fn after their real signature check
    def run(q = quote, info_fn: nil, qe_fn: nil, policy: nil, collateral: col, genuine: true, valid_at: nil)
      i = c.i
      orig = i.method(:verify_signed_json)
      fm = fmspc
      stubs = {}
      stubs[:verify_genuine_tdx_quote] = ->(*_a) { { 'ok' => true, 'pckTcb' => {}, 'fmspc' => fm } } if genuine
      stubs[:verify_signed_json] = lambda { |text, name, key|
        r = orig.call(text, name, key)
        fn = name == 'tcbInfo' ? info_fn : qe_fn
        r.key?('body') && fn ? { 'body' => fn.call(r['body']) } : r
      }
      MutationKill::Seam.with(i, stubs) do
        if valid_at
          MutationKill::Seam.with(AtlasPca::Attest::Der, { x509_valid_at?: valid_at }) { i.verify_intel_tdx_collateral(q, collateral, now, policy) }
        else
          i.verify_intel_tdx_collateral(q, collateral, now, policy)
        end
      end
    end

    def bad(reason) = { 'ok' => false, 'reason' => reason }

    # a TCB info whose single level matches anything, with the base TDX module of `td`
    def simple_info(signer_hex, adv = nil)
      lvl = { 'tcb' => { 'sgxtcbcomponents' => Array.new(16) { { 'svn' => 0 } }, 'tdxtcbcomponents' => Array.new(16) { { 'svn' => 0 } }, 'pcesvn' => 0 }, 'tcbStatus' => 'UpToDate' }
      lvl['advisoryIDs'] = adv if adv
      ->(b) { b.reject { |k, _| k == 'tdxModuleIdentities' }.merge('tdxModule' => { 'mrsigner' => signer_hex, 'attributes' => '00' * 8, 'attributesMask' => 'ff' * 8 }, 'tcbLevels' => [lvl]) }
    end
  end

  t('c11: verify_intel_tdx_collateral: TCB info document checks (id, version, FMSPC) and evaluation numbers, on the genuine collateral with rewritten bodies') do
    next true if C11Intel.skip?

    k = C11Col
    base = k.run
    num = ->(v) { ->(b) { b.merge('tcbEvaluationDataNumber' => v) } }
    qnum = ->(v) { ->(b) { b.merge('tcbEvaluationDataNumber' => v) } }
    miss = k.bad('tcbEvaluationDataNumber missing')
    below = k.bad('tcbEvaluationDataNumber below policy minimum')
    nodoc = k.bad('TCB info is not a TDX v3 document')
    nofm = k.bad('TCB info FMSPC does not match the quote PCK')
    pol = ->(n) { { 'minTcbEvaluationDataNumber' => n, 'acceptStatuses' => C11Col::ALL } }
    gone = ->(key) { ->(b) { b.reject { |kk, _| kk == key } } }
    k.c.ck([
             ['harness', base['ok'], true], ['harness status', base['status'].class, String],
             ['id', k.run(info_fn: ->(b) { b.merge('id' => 'SGX') }), nodoc], ['id nil', k.run(info_fn: gone.call('id')), nodoc],
             ['version 2', k.run(info_fn: ->(b) { b.merge('version' => 2) }), nodoc], ['version 4', k.run(info_fn: ->(b) { b.merge('version' => 4) }), nodoc],
             ['version str', k.run(info_fn: ->(b) { b.merge('version' => '3') }), nodoc], ['version nil', k.run(info_fn: gone.call('version')), nodoc],
             ['version 3.0', k.run(info_fn: ->(b) { b.merge('version' => 3.0) })['ok'], true],
             ['fmspc int', k.run(info_fn: ->(b) { b.merge('fmspc' => 5) }), nofm], ['fmspc nil', k.run(info_fn: gone.call('fmspc')), nofm],
             ['fmspc other', k.run(info_fn: ->(b) { b.merge('fmspc' => 'ffffffffffff') }), nofm],
             ['fmspc upper', k.run(info_fn: ->(b) { b.merge('fmspc' => k.fmspc.upcase) })['ok'], true],
             ['info number str', k.run(info_fn: num.call('5')), miss], ['info number nil', k.run(info_fn: gone.call('tcbEvaluationDataNumber')), miss],
             ['qe number str', k.run(qe_fn: qnum.call('5')), miss], ['qe number nil', k.run(qe_fn: gone.call('tcbEvaluationDataNumber')), miss],
             ['info number -1', k.run(info_fn: num.call(-1)), miss], ['qe number 0 ok', k.run(qe_fn: qnum.call(0))['ok'], true],
             ['info number 0 ok', k.run(info_fn: num.call(0))['ok'], true],
             ['floor info low', k.run(info_fn: num.call(1), qe_fn: qnum.call(100), policy: pol.call(50)), below],
             ['floor qe low', k.run(info_fn: num.call(100), qe_fn: qnum.call(1), policy: pol.call(50)), below],
             ['floor both ok', k.run(info_fn: num.call(100), qe_fn: qnum.call(100), policy: pol.call(50))['ok'], true],
             ['floor equal', k.run(info_fn: num.call(50), qe_fn: qnum.call(50), policy: pol.call(50))['ok'], true],
             ['floor str low', k.run(info_fn: num.call(49), qe_fn: qnum.call(100), policy: pol.call('50')), below],
             ['floor nan', k.run(info_fn: num.call(100), qe_fn: qnum.call(100), policy: pol.call('x')), below],
             ['floor float nan', k.run(info_fn: num.call(100), qe_fn: qnum.call(100), policy: pol.call(Float::NAN)), below]
           ])
  end

  t('c11: verify_intel_tdx_collateral: the seam attributes and TCB bytes of the TD report reach the TDX module and platform evaluation') do
    next true if C11Intel.skip?

    k = C11Col
    c = k.c
    signer = "\xAB".b * 48
    sh = signer.unpack1('H*')
    mk = lambda do |&edit|
      q = c.real_quote
      q[48, 16] = ([5, 0] + ([0] * 14)).pack('C*') # minor 0: the base module identity
      q[48 + 64, 48] = signer
      q[48 + 112, 8] = "\x00".b * 8
      edit&.call(q)
      q
    end
    pol = { 'acceptStatuses' => C11Col::ALL }
    run = ->(q, adv = nil, qe_fn = nil) { k.run(q, info_fn: k.simple_info(sh, adv), qe_fn: qe_fn, policy: pol) }
    ok = run.call(mk.call)
    qe_status = c.i.evaluate_qe(k.qe, c.i.parse_dcap_quote(c.real_quote)['qeReportBody'])
    adv_q = ->(ids) { ->(b) { b.merge('tcbLevels' => [{ 'tcb' => { 'isvsvn' => 0 }, 'tcbStatus' => 'UpToDate', 'advisoryIDs' => ids }]) } }
    k.c.ck([
             ['ok', [ok['ok'], ok['status']], [true, qe_status['status']]],
             ['attr last byte', run.call(mk.call { |q| q.setbyte(48 + 119, 1) }), k.bad('TCB evaluation: TD report SEAM attributes do not match the TDX module identity')],
             ['attr first byte', run.call(mk.call { |q| q.setbyte(48 + 112, 1) }), k.bad('TCB evaluation: TD report SEAM attributes do not match the TDX module identity')],
             ['signer first byte', run.call(mk.call { |q| q.setbyte(48 + 64, 0xAC) }), k.bad('TCB evaluation: TD report MRSIGNERSEAM does not match the TDX module identity')],
             ['signer last byte', run.call(mk.call { |q| q.setbyte(48 + 111, 0xAC) }), k.bad('TCB evaluation: TD report MRSIGNERSEAM does not match the TDX module identity')],
             ['advisories sorted and merged', run.call(mk.call, ['M'], adv_q.call(%w[Z A]))['advisoryIds'], %w[A M Z]],
             ['advisories from qe only', run.call(mk.call, nil, adv_q.call(%w[Z A]))['advisoryIds'], %w[A Z]],
             ['qe level wins in status', run.call(mk.call, nil, adv_q.call([]))['status'], 'UpToDate'],
             ['tcb refusal prefix', k.run(mk.call, info_fn: ->(b) { b.merge('tcbLevels' => []) }, policy: pol), k.bad('TCB evaluation: TCB info has no tcbLevels')],
             ['qe refusal prefix', k.run(mk.call, info_fn: k.simple_info(sh), qe_fn: ->(b) { b.merge('id' => 'x') }, policy: pol), k.bad('QE identity: QE identity id is not TD_QE')]
           ])
  end

  t('c11: verify_intel_tdx_collateral: quote chain checks (validity re-check, leaf / CA / root not found) and the issuer chains of the documents') do
    next true if C11Intel.skip?

    k = C11Col
    c = k.c
    leaf, ca, root = c.parts(c.i.parse_dcap_quote(c.real_quote)['pckChainPem'])
    chain_q = ->(*pems) { c.quote(c.sigdata(pck: pems.join("\n").b)) }
    expired = k.run(valid_at: ->(*_a) { false })
    tcb_chain = c.real_col['tcbInfoIssuerChainPem']
    first_block = c.cm.pem_blocks(tcb_chain)[0]
    c.ck([
           ['validity re-check', expired, k.bad('PCK chain certificate outside its validity period')],
           ['leaf not found', k.run(chain_q.call(root)), k.bad('PCK leaf not found')],
           ['ca not found', k.run(chain_q.call(leaf)), k.bad('PCK CA not found in the quote chain')],
           ['root not found', k.run(chain_q.call(leaf, ca)), k.bad('Intel root not found in the quote chain')],
           ['tcb chain', k.run(collateral: k.col.merge('tcbInfoIssuerChainPem' => first_block)),
            k.bad('TCB info: issuer chain invalid: PCK chain does not terminate in a self-signed root')],
           ['qe chain', k.run(collateral: k.col.merge('qeIdentityIssuerChainPem' => first_block)),
            k.bad('QE identity: issuer chain invalid: PCK chain does not terminate in a self-signed root')],
           ['tcb signature', k.run(collateral: k.col.merge('tcbInfoJson' => k.col['tcbInfoJson'].sub(/"signature"\s*:\s*"/) { |m| "#{m}00" })),
            k.bad('TCB info: tcbInfo signature missing or malformed')],
           ['qe signature', k.run(collateral: k.col.merge('qeIdentityJson' => k.col['qeIdentityJson'].sub(/"signature"\s*:\s*"/) { |m| "#{m}00" })),
            k.bad('QE identity: enclaveIdentity signature missing or malformed')],
           ['stale tcb info', k.run(info_fn: ->(b) { b.merge('nextUpdate' => '2000-01-01T00:00:00Z') }), k.bad('TCB info: stale (nextUpdate passed)')],
           ['stale qe', k.run(qe_fn: ->(b) { b.merge('nextUpdate' => '2000-01-01T00:00:00Z') }), k.bad('QE identity: stale (nextUpdate passed)')]
         ])
  end

  # ================================================================================================ verifier: what it reports from the collateral check
  t('c11: IntelDcapVerifier#verify reports the collateral status and advisories, hands over the collateral policy, pin and debug flag') do
    next true if C11Intel.skip?

    c = C11Intel
    v = AtlasPca::Attest::IntelDcapVerifier
    m96 = 'ab' * 48
    exp = { 'holder_pub' => 'h', 'grant_ref' => 'g', 'epoch' => 1, 'nonce' => 'n' }
    want = c.cm.attestation_binding(exp)
    seen = []
    ok_quote = ->(*_a) { { 'ok' => true, 'report' => { 'reportData' => want }, 'measured' => { 'm' => 1 }, 'fmspc' => 'ab12' } }
    run = lambda do |col_result, pol = {}|
      seen.clear
      ver = v.new({ 'binding' => 'report-data', 'policy' => { 'mrtds' => [m96] }.merge(pol), 'trustAnchorRootCaSpkiSha256' => 'AA' * 32,
                    'resolve_evidence' => ->(_d) { { 'quote' => "Qq".b, 'collateral' => { 'k' => 1 } } } })
      stubs = { verify_genuine_tdx_quote: ok_quote, verify_intel_tdx_collateral: ->(*a) { seen << a; col_result } }
      MutationKill::Seam.with(c.i, stubs) { ver.verify({}, exp, 77) }
    end
    host = ->(extra = {}) { { 'attestation_type' => 'tdx-dcap', 'fmspc' => 'ab12' }.merge(extra) }
    good = ->(h) { { 'ok' => true, 'bound' => true, 'measured' => { 'm' => 1 }, 'hostAsserted' => h } }
    r_full = run.call({ 'ok' => true, 'status' => 'UpToDate', 'advisoryIds' => %w[A B] })
    args_default = seen.first
    r_bare = run.call({ 'ok' => true })
    r_empty = run.call({ 'ok' => true, 'status' => '', 'advisoryIds' => [] })
    r_adv_only = run.call({ 'ok' => true, 'advisoryIds' => ['X'] })
    r_status_only = run.call({ 'ok' => true, 'status' => 'SWHardeningNeeded' })
    run.call({ 'ok' => true }, { 'collateral' => { 'minTcbEvaluationDataNumber' => 3 }, 'allowDebug' => true })
    args_pol = seen.first
    falsy = {}
    [nil].each_with_index do |val, n|
      run.call({ 'ok' => true }, { 'collateral' => val })
      falsy[n] = seen.first[3]
    end
    c.ck([
           ['full', r_full, good.call(host.call('tcb_status' => 'UpToDate', 'advisory_ids' => 'A,B'))], ['bare', r_bare, good.call(host.call)],
           ['empty', r_empty, good.call(host.call)], ['advisories only', r_adv_only, good.call(host.call('advisory_ids' => 'X'))],
           ['status only', r_status_only, good.call(host.call('tcb_status' => 'SWHardeningNeeded'))],
           ['refused', run.call({ 'ok' => false, 'reason' => 'why' }), { 'ok' => false, 'reason' => 'Intel collateral: why' }],
           ['refused, no reason', run.call({ 'ok' => false }), { 'ok' => false, 'reason' => 'Intel collateral: rejected' }],
           ['refused with status', run.call({ 'ok' => false, 'status' => 'OutOfDate', 'advisoryIds' => ['X'], 'reason' => 'TCB status OutOfDate is not accepted by policy' }),
            { 'ok' => false, 'reason' => 'Intel collateral: TCB status OutOfDate is not accepted by policy' }],
           ['args default', args_default, ['Qq'.b, { 'k' => 1 }, 77, nil, 'aa' * 32, false]],
           ['args policy and debug', args_pol, ['Qq'.b, { 'k' => 1 }, 77, { 'minTcbEvaluationDataNumber' => 3 }, 'aa' * 32, true]],
           ['nil collateral policy is nil', falsy, { 0 => nil }]
         ])
  end

  # ================================================================================================ PCK chain: cycles and the parent-subject check
  t('c11: verify_intel_pck_chain: a subject cycle terminates, a parent whose subject changes is refused (deadline, wrapped certificates)') do
    next true if C11Intel.skip?

    require 'delegate'
    c = C11Intel
    i = c.i
    key = c.ec
    mkcert = lambda do |subj, iss|
      x = OpenSSL::X509::Certificate.new
      x.version = 2
      x.serial = 1
      x.subject = OpenSSL::X509::Name.parse("/CN=#{subj}")
      x.issuer = OpenSSL::X509::Name.parse("/CN=#{iss}")
      x.public_key = key
      x.not_before = Time.utc(2020, 1, 1)
      x.not_after = Time.utc(2040, 1, 1)
      x.sign(key, OpenSSL::Digest.new('sha256'))
      x.to_pem
    end
    cyc = mkcert.call('A', 'B') + mkcert.call('B', 'A')
    r_cycle = c.tm { i.verify_intel_pck_chain(cyc, nil, c.ms(2026, 1, 1)) }

    pem = i.parse_dcap_quote(c.real_quote)['pckChainPem']
    flag = [false]
    count = [0]
    wrapper = Class.new(SimpleDelegator) do
      define_method(:subject) { flag[0] ? "#{__getobj__.subject}!" : __getobj__.subject }
    end
    orig = AtlasPca::Attest::Cert.method(:from_pem)
    valid = lambda do |*_a|
      count[0] += 1
      flag[0] = true if count[0] >= 3
      true
    end
    r_flaky = MutationKill::Seam.with(AtlasPca::Attest::Cert, { from_pem: ->(b) { wrapper.new(orig.call(b)) } }) do
      MutationKill::Seam.with(AtlasPca::Attest::Der, { x509_valid_at?: valid }) { i.verify_intel_pck_chain(pem, nil, c.real_now) }
    end
    c.ck([
           ['cycle', r_cycle, { 'ok' => false, 'reason' => 'PCK chain does not terminate in a self-signed root' }],
           ['parent subject changed', r_flaky, { 'ok' => false, 'reason' => 'certificate at depth 0 issuer does not match its parent subject' }]
         ])
  end

  # ================================================================================================ evaluate_tcb on short inputs, signed JSON with a non-object document
  t('c11: evaluate_tcb stops comparing once a level cannot match (short sgx / TD inputs would raise otherwise)') do
    next true if C11Intel.skip?

    c = C11Intel
    z = C11Intel::Z16
    below = { 'error' => 'platform TCB is below every level in the TCB info' }
    info = c.info_of([c.level(z, z, 5)])
    short_sgx = { 'sgx' => ''.b, 'pcesvn' => 0 }
    short_td = c.tdr.merge('teeTcbSvn' => "\x00\x00".b)
    c.ck([['short sgx, pcesvn too low', c.etcb(info, short_sgx), below], ['short td, pcesvn too low', c.etcb(info, c.pck(z, 0), short_td), below],
          ['short td, sgx too low', c.etcb(c.info_of([c.level(Array.new(16, 1), z, 0)]), c.pck, short_td), below]])
  end

  t('c11: verify_signed_json: a signed document that does not decode to an object has no signature (seam over the JSON decoder)') do
    next true if C11Intel.skip?

    c = C11Intel
    k = c.ec
    pub = OpenSSL::PKey.read(k.public_to_der)
    good = c.signed('tcbInfo', '{"id":"TDX"}', k)
    n = 0
    r = MutationKill::Seam.with(c.cm, { js_json_loads: ->(_t) { (n += 1) == 1 ? [] : {} } }) { c.i.verify_signed_json(good, 'tcbInfo', pub) }
    r == { 'error' => 'tcbInfo signature missing or malformed' }
  end

  # ================================================================================================ rows (the shared vectors; last, so the cheap deadline tests above kill a hanging mutant first)
  t('c11: every intel-tdx-dcap evidence row of the shared vectors (self-contained copy)') do
    next true if C11Intel.skip?

    bad = []
    C11Intel.doc['rows'].each do |r|
      h = C11Intel.hydrate(r)
      got = begin
        Timeout.timeout(5) { AtlasPca::Attest.run_attestation_vector(h) }
      rescue StandardError, SystemStackError
        nil
      end
      want = h['expect'].dup
      if want.delete('reason_match') == 'prefix'
        prefix = want.delete('reason_prefix')
        ok = !got.nil? && got['reason'].is_a?(String) && got['reason'].start_with?(prefix) &&
             got.reject { |k, _| k == 'reason' } == want.reject { |k, _| k == 'reason' }
      else
        ok = got == want
      end
      next if ok

      bad << h['id']
      break if bad.size >= 3
    end
    raise "rows differ: #{bad.join(', ')}" unless bad.empty?

    true
  end
end
