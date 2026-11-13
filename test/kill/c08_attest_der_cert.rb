# frozen_string_literal: true
# Exact-outcome kill tests for lib/atlas_pca/attest/der.rb and attest/cert.rb: the strict DER readers, the validity-time parser, the
# distinguished-name renderer, the RSASSA-PSS parameter reader and the certificate model. Certificates are built here byte for byte
# (EC keys generated at load, nothing committed). Expected values are the reference's: x509-strict.ts / x509-validity.ts (the epoch
# values below were computed with the reference's own Date arithmetic).
require 'timeout'
require 'openssl'
require 'atlas_pca/attest'

module MutationKill
  module C08DerCert
    module_function

    PSS = '1.2.840.113549.1.1.10'
    HASHES = { 'sha1' => '1.3.14.3.2.26', 'sha224' => '2.16.840.1.101.3.4.2.4', 'sha256' => '2.16.840.1.101.3.4.2.1',
               'sha384' => '2.16.840.1.101.3.4.2.2', 'sha512' => '2.16.840.1.101.3.4.2.3' }.freeze
    NSL = 'error:0480006C:PEM routines::no start line'
    EOC = 'error:0680009F:asn1 encoding routines::unexpected eoc'

    # resolved per call: the oracle reloads the library for each mutant
    def der = AtlasPca::Attest::Der
    def cert = AtlasPca::Attest::Cert
    def com = AtlasPca::Attest::Common

    def tlv(tag, *parts)
      body = parts.map(&:b).join.b
      n = [body.bytesize].pack('N').sub(/\A\0+/, '')
      len = body.bytesize < 128 ? [body.bytesize].pack('C') : [0x80 | n.bytesize].pack('C') + n
      [tag].pack('C') + len + body
    end

    def oid(dotted) = OpenSSL::ASN1::ObjectId.new(dotted).to_der
    def bin(*bytes) = bytes.pack('C*')
    def u8(s) = tlv(0x0C, s)
    def cn = oid('2.5.4.3')
    def nm(text, tag = 0x0C) = tlv(0x30, tlv(0x31, tlv(0x30, cn, tlv(tag, text))))

    # [error class (unqualified), message] of the StandardError the block raises, nil when it raises nothing
    def raised
      yield
      nil
    rescue StandardError => e
      [e.class.name.split('::').last, e.message]
    end

    def dl(&blk) = Timeout.timeout(2, &blk)

    def tl(t) = [t.tag, t.start, t.end_]

    def ec = (@ec ||= OpenSSL::PKey::EC.generate('prime256v1'))
    def ec_pub = OpenSSL::PKey.read(ec.public_to_der)

    def alg(dotted = '1.2.840.10045.4.3.3', *params) = tlv(0x30, oid(dotted), *params)
    def ext(dotted, value, crit = nil) = tlv(0x30, oid(dotted), *(crit.nil? ? [] : [tlv(1, crit)]), tlv(4, value))
    def ext_block(*exts) = tlv(0xA3, tlv(0x30, *exts))
    def role_cert(*exts) = tlv(0x30, tlv(0x30, ext_block(*exts)))

    # A certificate DER built from parts; every part can be replaced to break exactly one thing.
    def mk(version: true, serial: tlv(2, bin(5)), alg_outer: alg, alg_inner: nil, issuer: nm('iss'),
           validity: tlv(0x30, tlv(0x17, '260101000000Z'), tlv(0x17, '360101000000Z')), subject: nm('sub'),
           spki: ec.public_to_der, tail: [], sig: 'SIGNA', sig_prefix: bin(0), sig_tag: 3, outer_tag: 0x30, tbs_tag: 0x30,
           after_sig: '', sign: false)
      parts = []
      parts << tlv(0xA0, tlv(2, bin(2))) if version
      parts.push(serial, alg_inner || alg_outer, issuer, validity, subject, spki, *tail)
      tbs = tlv(tbs_tag, *parts)
      sig = ec.sign('SHA384', tbs) if sign
      { der: tlv(outer_tag, tbs, alg_outer, tlv(sig_tag, sig_prefix, sig), after_sig), tbs: tbs, alg: alg_outer, sig: sig.b,
        issuer: issuer, subject: subject, spki: spki }
    end

    def new_cert(**kw) = cert.new(mk(**kw)[:der])

    # a validity-only certificate for der_validity_ms
    def vc(version: true, serial: tlv(2, bin(5)), sigalg: alg, issuer: nm('i'), validity: nil, outer: 0x30, tbs: 0x30,
           nb: tlv(0x17, '260101000000Z'), na: tlv(0x18, '20360101000000Z'))
      parts = []
      parts << tlv(0xA0, tlv(2, bin(2))) if version
      parts.push(serial, sigalg, issuer, validity || tlv(0x30, nb, na))
      tlv(outer, tlv(tbs, *parts), sigalg, tlv(3, bin(0, 1)))
    end
  end

  GATE08 = lambda do
    f = ENV['MUT_FILE']
    !f.nil? && !f.empty? && !%w[der.rb cert.rb].include?(f)
  end

  def self.k08(name, &blk) = t(name) { GATE08.call || blk.call }

  # ---------------------------------------------------------------- der.rb

  k08('c08 der/cert: constants are frozen and pinned') do
    d = C08DerCert.der
    c = C08DerCert.cert
    sig_algs = {
      '1.2.840.10045.4.1' => %w[ec sha1], '1.2.840.10045.4.3.1' => %w[ec sha224], '1.2.840.10045.4.3.2' => %w[ec sha256],
      '1.2.840.10045.4.3.3' => %w[ec sha384], '1.2.840.10045.4.3.4' => %w[ec sha512],
      '1.2.840.113549.1.1.5' => %w[rsa sha1], '1.2.840.113549.1.1.14' => %w[rsa sha224], '1.2.840.113549.1.1.11' => %w[rsa sha256],
      '1.2.840.113549.1.1.12' => %w[rsa sha384], '1.2.840.113549.1.1.13' => %w[rsa sha512]
    }
    hash_oids = {
      '1.3.14.3.2.26' => 'sha1', '2.16.840.1.101.3.4.2.4' => 'sha224', '2.16.840.1.101.3.4.2.1' => 'sha256',
      '2.16.840.1.101.3.4.2.2' => 'sha384', '2.16.840.1.101.3.4.2.3' => 'sha512'
    }
    short = {
      '2.5.4.3' => 'CN', '2.5.4.4' => 'SN', '2.5.4.5' => 'serialNumber', '2.5.4.6' => 'C', '2.5.4.7' => 'L', '2.5.4.8' => 'ST',
      '2.5.4.9' => 'street', '2.5.4.10' => 'O', '2.5.4.11' => 'OU', '2.5.4.12' => 'title', '2.5.4.13' => 'description',
      '2.5.4.15' => 'businessCategory', '2.5.4.17' => 'postalCode', '2.5.4.41' => 'name', '2.5.4.42' => 'GN',
      '2.5.4.43' => 'initials', '2.5.4.44' => 'generationQualifier', '2.5.4.46' => 'dnQualifier', '2.5.4.65' => 'pseudonym',
      '1.2.840.113549.1.9.1' => 'emailAddress', '0.9.2342.19200300.100.1.25' => 'DC', '0.9.2342.19200300.100.1.1' => 'UID',
      '1.3.6.1.4.1.311.60.2.1.1' => 'jurisdictionL', '1.3.6.1.4.1.311.60.2.1.2' => 'jurisdictionST',
      '1.3.6.1.4.1.311.60.2.1.3' => 'jurisdictionC'
    }
    [d::OID_BASIC_CONSTRAINTS, d::OID_KEY_USAGE, d::RECOGNISED_CRITICAL_EXTENSIONS, d::CHAIN_CRITICAL_OK, d::NAME_STRING_TAGS,
     c::SIG_ALGS, c::HASH_OIDS, c::SHORT_NAMES].all?(&:frozen?) &&
      d::OID_BASIC_CONSTRAINTS == "\x55\x1d\x13".b && d::OID_KEY_USAGE == "\x55\x1d\x0f".b &&
      d::RECOGNISED_CRITICAL_EXTENSIONS == %w[2.5.29.19 2.5.29.15] && d::CHAIN_CRITICAL_OK == %w[2.5.29.19 2.5.29.15 2.5.29.37] &&
      d::NAME_STRING_TAGS == [0x0C, 0x13, 0x14, 0x16] &&
      c::SIG_ALGS == sig_algs && c::HASH_OIDS == hash_oids && c::SHORT_NAMES == short &&
      c::OID_PSS == '1.2.840.113549.1.1.10' && c::OID_MGF1 == '1.2.840.113549.1.1.8' && c::NO_START_LINE == C08DerCert::NSL
  end

  k08('c08 der: read_tlv lengths, limits and every refusal') do
    d = C08DerCert.der
    c = C08DerCert
    ok = ->(*a) { c.tl(d.read_tlv(*a)) }
    er = ->(*a) { c.raised { d.read_tlv(*a) } }
    e = ->(m) { ['DerError', m] }
    x = ->(n) { 'x' * n }
    [
      [ok.("\x04\x01a".b, 0), [4, 2, 3]],
      [ok.("zz\x04\x01a".b, 2), [4, 4, 5]],
      [er.("\x30".b, 0), e.('DER: truncated header')],
      [er.("\x30\x00".b, 0, 1), e.('DER: truncated header')],
      [ok.("\x30\x00".b, 0, 2), [0x30, 2, 2]],
      [er.("\x1f\x00".b, 0), e.('DER: multi-byte tags are not supported')],
      [er.("\x30\x80\x00\x00\x00\x00\x00".b, 0), e.('DER: unsupported length form')],
      [er.("\x30\x84\x00\x00\x00\x01\x00".b, 0), e.('DER: unsupported length form')],
      [er.("\x30\x85\x00\x00\x00\x00\x01\x00".b, 0), e.('DER: unsupported length form')],
      [ok.("\x30\x83\x01\x00\x00".b + x.(65_536), 0), [0x30, 5, 65_541]],
      [er.("\x30\x82\x01".b, 0), e.('DER: truncated length')],
      [er.("\x30\x81\x00".b, 0), e.('DER: non-minimal length (long form below 128)')],
      [er.("\x30\x82\x00\x80".b + x.(128), 0), e.('DER: non-minimal length (leading zero)')],
      [er.("\x30\x81\x7f".b + x.(127), 0), e.('DER: non-minimal length (long form below 128)')],
      [ok.("\x30\x81\x80".b + x.(128), 0), [0x30, 3, 131]],
      [er.("\x30\x81\x80".b, 0), e.('DER: element overruns its parent')],
      [er.("\x04\x05ab".b, 0), e.('DER: element overruns its parent')],
      [er.("\x04\x03abc".b, 0, 4), e.('DER: element overruns its parent')]
    ].all? { |got, want| got == want }
  end

  k08('c08 der: tlv_at (the validity reader) boundaries and refusals') do
    d = C08DerCert.der
    c = C08DerCert
    ok = ->(*a) { c.tl(d.tlv_at(*a)) }
    er = ->(*a) { c.raised { d.tlv_at(*a) } }
    [
      [er.("\x30".b, 0), %w[DerError truncated]],
      [er.(''.b, 0), %w[DerError truncated]],
      [ok.("\x05\x00".b, 0), [5, 2, 2]],
      [er.("\x05\x00".b, 1), %w[DerError truncated]],
      [er.("\x30\x80\x00\x00".b, 0), ['DerError', 'bad length']],
      [er.("\x30\x85\x00\x00\x00\x00\x01\x00".b, 0), ['DerError', 'bad length']],
      [ok.("\x30\x84\x00\x00\x00\x01\x00".b, 0), [0x30, 6, 7]],
      [er.("\x30\x82\x01".b, 0), ['DerError', 'bad length']],
      [ok.("\x30\x81\x00".b, 0), [0x30, 3, 3]],
      [ok.("\x04\x82\x01\x02".b + ('x' * 258), 0), [4, 4, 262]],
      [er.("\x04\x05\x00".b, 0), %w[DerError truncated]]
    ].all? { |got, want| got == want }
  end

  k08('c08 der: oid_equals?, minimal_integer?, oid_to_dotted') do
    d = C08DerCert.der
    c = C08DerCert
    oid_b = "\x55\x1d\x13".b
    dotted = lambda do |*bytes|
      b = c.bin(*bytes)
      d.oid_to_dotted(b, d::Tlv.new(0x06, 0, b.bytesize))
    end
    err = lambda do |tag, *bytes|
      b = c.bin(*bytes)
      c.raised { d.oid_to_dotted(b, d::Tlv.new(tag, 0, b.bytesize)) }
    end
    d.oid_equals?(oid_b, d::Tlv.new(0x06, 0, 3), oid_b).equal?(true) &&
      d.oid_equals?(oid_b, d::Tlv.new(0x04, 0, 3), oid_b).equal?(false) &&
      d.oid_equals?(oid_b, d::Tlv.new(0x06, 0, 3), "\x55\x1d\x0f".b).equal?(false) &&
      d.minimal_integer?(''.b).equal?(false) && d.minimal_integer?("\x00".b).equal?(true) && d.minimal_integer?("\x80".b).equal?(true) &&
      d.minimal_integer?("\x00\x00".b).equal?(false) && d.minimal_integer?("\x00\x7f".b).equal?(false) && d.minimal_integer?("\x00\x80".b).equal?(true) &&
      d.minimal_integer?("\xff\x80".b).equal?(false) && d.minimal_integer?("\xff\x7f".b).equal?(true) && d.minimal_integer?("\x05\x80".b).equal?(true) &&
      [
        [dotted.(0x27), '0.39'], [dotted.(0x28), '1.0'], [dotted.(0x4F), '1.39'], [dotted.(0x50), '2.0'], [dotted.(0x55, 4, 3), '2.5.4.3'],
        [dotted.(0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 3), '1.2.840.10045.4.3.3'], [dotted.(0x55, 0x81, 0x80, 0x01), '2.5.16385'],
        [dotted.(0x88, 0x37), '2.999'], [dotted.(0x81, 0x80, 0x01), '2.16305'],
        [err.(0x06, 0x80, 0x01), ['DerError', 'extension OID has a non-minimal arc']],
        [err.(0x06, 0x55, 0x80, 0x01), ['DerError', 'extension OID has a non-minimal arc']],
        [err.(0x06, 0x55, 0x81), ['DerError', 'extension OID is truncated']],
        [err.(0x04, 0x55, 4, 3), ['DerError', 'extension OID is malformed']],
        [err.(0x06), ['DerError', 'extension OID is malformed']]
      ].all? { |got, want| got == want }
  end

  k08('c08 der: in_order!, bit_string_content!, top_sequence, positive_integer!') do
    d = C08DerCert.der
    c = C08DerCert
    io = ->(tags, allowed) { c.raised { d.in_order!(tags.map { |g| d::Tlv.new(g, 0, 0) }, allowed) } }
    order = ['DerError', 'member out of order or of no allowed type']
    bits = c.bin(0, 7, 8)
    bsc = ->(s, e) { c.raised { d.bit_string_content!(bits, d::Tlv.new(3, s, e)) } }
    mal = ['DerError', 'BIT STRING is malformed']
    pi = lambda do |content|
      b = c.tlv(0x30, c.tlv(2, content), c.tlv(4, c.bin(5, 6)))
      c.raised { d.positive_integer!(b, d.top_sequence(b)[0]) }
    end
    npos = ['DerError', 'not a positive DER INTEGER']
    [
      [io.([], [1, 2]), nil], [io.([1, 2], [1, 2]), nil], [io.([2], [1, 2]), nil], [io.([0x82], [0x80]), order], [io.([0xA1, 0x80], [0x80, 0xA1, 0x82]), order],
      [io.([0x80, 0x80], [0x80, 0xA1]), order], [io.([0x80, 0x82], [0x80, 0xA1, 0x82]), nil],
      [bsc.(0, 1), nil], [bsc.(1, 2), nil], [bsc.(2, 3), mal], [bsc.(0, 0), mal],
      [c.raised { d.top_sequence(c.tlv(0x31, c.tlv(4, 'a'))) }, ['DerError', 'extension is not a SEQUENCE']],
      [d.top_sequence(c.tlv(0x30, c.tlv(4, 'a'), c.tlv(2, c.bin(1)))).map(&:tag), [4, 2]],
      [pi.(c.bin(0)), nil], [pi.(c.bin(0x7f)), nil], [pi.(c.bin(0, 0x80)), nil], [pi.(c.bin(0x80)), npos], [pi.(c.bin(0xff)), npos],
      [pi.(c.bin(0, 1)), npos], [pi.(''.b), npos]
    ].all? { |got, want| got == want }
  end

  k08('c08 der: rdn! and general_name! refusals, exact') do
    d = C08DerCert.der
    c = C08DerCert
    atv = ->(*p) { c.tlv(0x30, *p) }
    rd = lambda do |*atvs|
      b = c.tlv(0x31, *atvs)
      c.raised { d.rdn!(b, d.read_tlv(b, 0)) }
    end
    gn = ->(b) { c.raised { d.general_name!(b, d.read_tlv(b, 0)) } }
    dn = ->(*r) { c.tlv(0x30, *r) }
    rdn_err = ->(m) { ['DerError', m] }
    nr = rdn_err.('attribute is not {type, value}')
    name_err = ['DerError', 'directoryName is not one Name']
    other_err = ['DerError', 'otherName is not {type, [0] value}']
    [
      [rd.(atv.(c.cn, c.u8('x'))), nil], [rd.(atv.(c.cn, c.tlv(0x13, 'x'))), nil], [rd.(atv.(c.cn, c.tlv(0x14, 'x'))), nil],
      [rd.(atv.(c.cn, c.tlv(0x16, 'x')), atv.(c.cn, c.u8('y'))), nil],
      [rd.(atv.(c.cn)), nr], [rd.(atv.(c.cn, c.u8('x'), c.u8('y'))), nr], [rd.(c.tlv(4, c.cn, c.u8('x'))), nr],
      [rd.(atv.(c.cn, c.tlv(2, c.bin(1)))), rdn_err.('attribute value type')], [rd.(atv.(c.cn, c.tlv(0x1E, c.bin(0, 65)))), rdn_err.('attribute value type')],
      [rd.(atv.(c.cn, c.tlv(0x0C, "\xC3\x28".b))), rdn_err.('attribute value is not UTF-8')],
      [d.general_name!(c.tlv(0x81, 'a'), d.read_tlv(c.tlv(0x81, 'a'), 0)), nil], [d.general_name!(c.tlv(0x82, 'a'), d.read_tlv(c.tlv(0x82, 'a'), 0)), nil],
      [d.general_name!(c.tlv(0x86, 'a'), d.read_tlv(c.tlv(0x86, 'a'), 0)), nil], [d.general_name!(c.tlv(0x87, 'a'), d.read_tlv(c.tlv(0x87, 'a'), 0)), nil],
      [gn.(c.tlv(0xA0, c.cn, c.tlv(0xA0, c.u8('x')))), nil],
      [gn.(c.tlv(0xA0, c.cn)), other_err], [gn.(c.tlv(0xA0, c.cn, c.tlv(0xA1, c.u8('x')))), other_err],
      [gn.(c.tlv(0xA0, c.cn, c.tlv(0xA0, c.u8('x'), c.u8('y')))), other_err],
      [gn.(c.tlv(0xA4, dn.())), nil], [gn.(c.tlv(0xA4, dn.(c.tlv(0x31, atv.(c.cn, c.u8('a')))))), nil],
      [gn.(c.tlv(0xA4, c.tlv(4))), name_err], [gn.(c.tlv(0xA4, c.tlv(0x31))), name_err], [gn.(c.tlv(0xA4, dn.(), dn.())), name_err],
      [gn.(c.tlv(0xA4)), ['DerError', 'DER: truncated header']],
      [gn.(c.tlv(0xA4, dn.(c.tlv(0x30)))), ['DerError', 'Name member is not an RDN']],
      [gn.(c.tlv(0x88, 'x')), ['DerError', 'not a supported GeneralName']], [gn.(c.tlv(0xA5)), ['DerError', 'not a supported GeneralName']]
    ].all? { |got, want| got == want }
  end

  k08('c08 der: basic_constraints!, key_usage!, name_constraints!, distribution_points!, cached_extension!') do
    d = C08DerCert.der
    c = C08DerCert
    de = ->(m) { ['DerError', m] }
    bc = ->(*kids) { c.raised { d.basic_constraints!(c.tlv(0x30, *kids)) } }
    ku = ->(v) { c.raised { d.key_usage!(v) } }
    uri = c.tlv(0x86, 'u')
    nc = ->(*lists) { c.raised { d.name_constraints!(c.tlv(0x30, *lists)) } }
    sub = ->(*p) { c.tlv(0x30, *p) }
    dpx = ->(*dps) { c.raised { d.distribution_points!(c.tlv(0x30, *dps)) } }
    sq = ->(*k) { c.tlv(0x30, *k) }
    full = c.tlv(0xA0, c.tlv(0xA0, uri))
    order = de.('member out of order or of no allowed type')
    [
      [bc.(), nil], [bc.(c.tlv(1, c.bin(0xff))), nil], [bc.(c.tlv(1, c.bin(0xff)), c.tlv(2, c.bin(3))), nil], [bc.(c.tlv(2, c.bin(3))), nil],
      [bc.(c.tlv(1, c.bin(0xff, 0xff))), de.('cA is not one byte')], [bc.(c.tlv(1)), de.('cA is not one byte')],
      [bc.(c.tlv(2, c.bin(3)), c.tlv(1, c.bin(0xff))), order], [bc.(c.tlv(2, c.bin(0x80))), de.('not a positive DER INTEGER')],
      [ku.(c.tlv(3, c.bin(0, 4))), nil], [ku.(c.tlv(3, c.bin(7, 0x80))), nil], [ku.(c.tlv(4, c.bin(0, 4))), de.('keyUsage is not a BIT STRING')],
      [ku.(c.tlv(3)), de.('BIT STRING is malformed')], [ku.(c.tlv(3, c.bin(8, 4))), de.('BIT STRING is malformed')], [ku.(c.tlv(3, c.bin(0))), de.('keyUsage has no bits')],
      [nc.(), nil], [nc.(c.tlv(0xA0, sub.(uri))), nil], [nc.(c.tlv(0xA0, sub.(uri, c.tlv(0x80, c.bin(1)), c.tlv(0x81, c.bin(2))))), nil],
      [nc.(c.tlv(0xA0, sub.(uri)), c.tlv(0xA1, sub.(uri))), nil],
      [nc.(c.tlv(0xA0, c.tlv(4, uri))), de.('GeneralSubtree has no base')], [nc.(c.tlv(0xA0, sub.())), de.('GeneralSubtree has no base')],
      [nc.(c.tlv(0xA0, sub.(c.tlv(0x88, 'x')))), de.('not a supported GeneralName')],
      [nc.(c.tlv(0xA0, sub.(uri, c.tlv(0x81, c.bin(1)), c.tlv(0x80, c.bin(1))))), order],
      [nc.(c.tlv(0xA0, sub.(uri, c.tlv(0x80, c.bin(0x80))))), de.('not a positive DER INTEGER')],
      [nc.(c.tlv(0xA1, sub.(uri)), c.tlv(0xA0, sub.(uri))), order],
      [dpx.(), nil], [dpx.(sq.(full)), nil], [dpx.(sq.(full, c.tlv(0x81, c.bin(0, 4)))), nil], [dpx.(sq.(c.tlv(0xA2, uri))), nil],
      [dpx.(sq.(c.tlv(0xA0, c.tlv(0xA1, c.tlv(0x30, c.cn, c.u8('x')))))), nil],
      [dpx.(c.tlv(0x31)), de.('DistributionPoint is not a SEQUENCE')], [dpx.(sq.()), de.('DistributionPoint has no name or issuer')],
      [dpx.(sq.(c.tlv(0x81, c.bin(0, 4)))), de.('DistributionPoint has no name or issuer')], [dpx.(sq.(c.tlv(0xA2))), de.('cRLIssuer is empty')],
      [dpx.(sq.(c.tlv(0xA0, c.tlv(0xA0, uri), c.tlv(0xA0, uri)))), de.('distributionPoint is not one name')],
      [dpx.(sq.(c.tlv(0xA0, c.tlv(4, 'x')))), de.('distributionPoint is not a name')], [dpx.(sq.(c.tlv(0xA2, uri), full)), order],
      [c.raised { d.cached_extension!('1.3.6.1.5.5.7.1.14', ''.b) }, de.('proxyCertInfo is not supported')],
      [d.cached_extension!('1.2.3.4', 'junk'.b), nil]
    ].all? { |got, want| got == want }
  end

  k08('c08 der: read_cert_role_info decodes BasicConstraints and keyUsage exactly') do
    d = C08DerCert.der
    c = C08DerCert
    bcx = ->(*kids) { c.ext('2.5.29.19', c.tlv(0x30, *kids)) }
    kux = ->(*bytes) { c.ext('2.5.29.15', c.tlv(3, c.bin(*bytes))) }
    info = ->(*exts) { d.read_cert_role_info(c.role_cert(*exts)) }
    err = ->(*exts) { c.raised { info.(*exts) } }
    none = { 'hasBasicConstraints' => false, 'ca' => false, 'hasKeyUsage' => false, 'keyCertSign' => false }
    pl_bad = ['DerError', 'BasicConstraints pathLenConstraint malformed']
    ca_t = c.tlv(1, c.bin(0xff))
    c.dl do
      [
        [d.read_cert_role_info(c.tlv(0x30, c.tlv(0x30))), none],
        [info.(bcx.(ca_t)), none.merge('hasBasicConstraints' => true, 'ca' => true)],
        [info.(bcx.(c.tlv(1, c.bin(0)))), none.merge('hasBasicConstraints' => true)],
        [info.(bcx.(c.tlv(1, c.bin(0xff)))), none.merge('hasBasicConstraints' => true, 'ca' => true)],
        [err.(bcx.(c.tlv(1, c.bin(1)))), ['DerError', 'BasicConstraints cA is not a DER BOOLEAN']], # O3: only 0x00 and 0xFF
        [info.(bcx.(c.tlv(2, c.bin(5)))), none.merge('hasBasicConstraints' => true, 'pathLen' => 5)],
        [info.(bcx.(ca_t, c.tlv(2, c.bin(0)))), none.merge('hasBasicConstraints' => true, 'ca' => true, 'pathLen' => 0)],
        [info.(bcx.(ca_t, c.tlv(2, c.bin(1, 0)))), none.merge('hasBasicConstraints' => true, 'ca' => true, 'pathLen' => 256)],
        [info.(bcx.(ca_t, c.tlv(2, c.bin(1, 2)))), none.merge('hasBasicConstraints' => true, 'ca' => true, 'pathLen' => 258)],
        [info.(bcx.(ca_t, c.tlv(2, c.bin(0, 0x80)))), none.merge('hasBasicConstraints' => true, 'ca' => true, 'pathLen' => 128)],
        [err.(bcx.(ca_t, c.tlv(4, c.bin(5)))), pl_bad], [err.(bcx.(ca_t, c.tlv(2))), pl_bad], [err.(bcx.(ca_t, c.tlv(2, c.bin(0, 0, 5)))), pl_bad],
        [err.(bcx.(ca_t, c.tlv(2, c.bin(0x80)))), pl_bad], [err.(bcx.(ca_t, c.tlv(2, c.bin(0x80, 0)))), pl_bad], [err.(bcx.(c.tlv(4, c.bin(5)))), pl_bad],
        [err.(bcx.(c.tlv(1, c.bin(0xff, 0xff)))), ['DerError', 'BasicConstraints cA is not one byte']],
        [err.(bcx.(ca_t, c.tlv(2, c.bin(1)), c.tlv(5))), ['DerError', 'BasicConstraints has trailing data']],
        [info.(kux.(0, 4)), none.merge('hasKeyUsage' => true, 'keyCertSign' => true)],
        [info.(kux.(0, 1)), none.merge('hasKeyUsage' => true)], [info.(kux.(0, 5)), none.merge('hasKeyUsage' => true, 'keyCertSign' => true)],
        [info.(kux.(7, 0x80)), none.merge('hasKeyUsage' => true)],
        [err.(c.ext('2.5.29.15', c.tlv(4, c.bin(0, 4)))), ['DerError', 'keyUsage is not a BIT STRING']],
        [err.(c.ext('2.5.29.15', c.tlv(3, c.bin(0)))), ['DerError', 'keyUsage is not a BIT STRING']],
        [err.(kux.(8, 4)), ['DerError', 'keyUsage BIT STRING has more than 7 unused bits']],
        [err.(bcx.(ca_t), bcx.(ca_t)), ['DerError', 'duplicate BasicConstraints extension']],
        [err.(kux.(0, 4), kux.(0, 4)), ['DerError', 'duplicate keyUsage extension']],
        [info.(c.ext('2.5.29.19', c.tlv(0x30, ca_t), c.bin(0xff)), kux.(0, 4)),
         none.merge('hasBasicConstraints' => true, 'ca' => true, 'hasKeyUsage' => true, 'keyCertSign' => true)],
        [c.raised { d.read_cert_role_info(c.tlv(0x30, c.tlv(0x31))) }, ['DerError', 'certificate has no tbsCertificate']],
        [c.raised { d.read_cert_role_info(c.tlv(0x31, c.tlv(0x30))) }, ['DerError', 'certificate is not a DER SEQUENCE']],
        [c.raised { d.read_cert_role_info(c.tlv(0x30, c.tlv(0x30)) + c.bin(0)) }, ['DerError', 'trailing bytes after the certificate']]
      ].all? { |got, want| got == want }
    end
  end

  k08('c08 der: parse_tbs_extensions, tbs_of_certificate, chain profile refusals') do
    d = C08DerCert.der
    c = C08DerCert
    de = ->(m) { ['DerError', m] }
    tbs = ->(*parts) { c.tlv(0x30, c.tlv(2, c.bin(1)), *parts) }
    pt = ->(t) { c.raised { d.parse_tbs_extensions(t) } }
    flag = ->(v) { c.tlv(0x30, c.oid('2.5.29.19'), c.tlv(1, v), c.tlv(4, '')) }
    e1 = c.ext('2.5.29.19', c.tlv(0x30), c.bin(0xff))
    e2 = c.ext('2.5.29.15', c.tlv(3, c.bin(0, 4)))
    cert_der = c.tlv(0x30, c.tlv(0x30, c.tlv(2, c.bin(1))), c.alg, c.tlv(3, c.bin(0)))
    bad_flag = c.role_cert(c.tlv(0x30, c.oid('2.5.29.35'), c.tlv(1, c.bin(1)), c.tlv(4, '')))
    strict = ->(*ders) { d.strict_chain_error(ders) }
    c.dl do
      parsed = d.parse_tbs_extensions(tbs.(c.ext_block(e1, e2)))
      [
        [parsed.keys, %w[2.5.29.19 2.5.29.15]], [parsed['2.5.29.19'].critical, true], [parsed['2.5.29.19'].value, c.tlv(0x30)],
        [parsed['2.5.29.15'].critical, false], [parsed['2.5.29.15'].value, c.tlv(3, c.bin(0, 4))],
        [pt.(c.tlv(0x31, c.ext_block(e1))), de.('tbsCertificate is not a SEQUENCE')],
        [pt.(tbs.(c.ext_block(e1)) + c.bin(0)), de.('trailing bytes after tbsCertificate')],
        [pt.(tbs.(c.ext_block(c.tlv(0x31, c.oid('2.5.29.19'), c.tlv(4, ''))))), de.('extension is not a SEQUENCE')],
        [pt.(tbs.(c.ext_block(flag.(c.bin(0xff, 0xff))))), de.('extension 2.5.29.19 has a non-DER critical flag')],
        [pt.(tbs.(c.ext_block(flag.(c.bin(1))))), de.('extension 2.5.29.19 has a non-DER critical flag')],
        [pt.(tbs.(c.ext_block(flag.(''.b)))), de.('extension 2.5.29.19 has a non-DER critical flag')],
        [pt.(tbs.(c.ext_block(flag.(c.bin(0xff))))), nil],
        [pt.(tbs.(c.ext_block(e1, e1))), de.('duplicate extension 2.5.29.19')],
        [pt.(tbs.(c.ext_block(e1), c.ext_block(e2))), de.('duplicate [3] extensions block')],
        [pt.(tbs.(c.ext_block(e1), c.tlv(4, ''))), de.('extensions block is not the last TBS element')],
        [pt.(tbs.(c.tlv(0xA3, c.tlv(0x30)))), de.('empty Extensions SEQUENCE')],
        [d.parse_tbs_extensions(tbs.()), {}],
        [d.tbs_of_certificate(cert_der), c.tlv(0x30, c.tlv(2, c.bin(1)))],
        [c.raised { d.tbs_of_certificate(c.tlv(0x31, c.tlv(0x30))) }, de.('certificate is not a DER SEQUENCE')],
        [c.raised { d.tbs_of_certificate(c.tlv(0x30, c.tlv(0x31))) }, de.('certificate has no tbsCertificate')],
        [c.raised { d.tbs_of_certificate(cert_der + c.bin(0)) }, de.('trailing bytes after the certificate')],
        [strict.(bad_flag), 'certificate extension parse failed: extension 2.5.29.35 has a non-DER critical flag'],
        [strict.(c.role_cert(c.ext('1.2.3.4', ''.b, c.bin(0xff)))), 'certificate at depth 0 has an unrecognised critical extension 1.2.3.4'],
        [strict.(c.tlv(0x30, c.tlv(0x30, c.tlv(2, c.bin(1))))), nil], [d.strict_chain_error([]), nil]
      ].all? { |got, want| got == want }
    end
  end

  k08('c08 der: strict_chain_error / check_chain_roles messages use the DerError text') do
    d = C08DerCert.der
    c = C08DerCert
    leaf = c.tlv(0x30, c.tlv(0x30, c.tlv(2, c.bin(1))))
    ca = c.role_cert(c.ext('2.5.29.19', c.tlv(0x30, c.tlv(1, c.bin(0xff)))))
    broken = c.tlv(0x30, c.tlv(0x31))
    [
      [d.check_chain_roles([leaf, broken]), 'certificate extension parse failed: certificate has no tbsCertificate'],
      [d.check_chain_roles([leaf, ca]), nil], [d.check_chain_roles([ca, ca]), 'leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)'],
      [d.check_chain_roles([ca]), nil], [d.check_chain_roles([]), nil],
      [d.check_chain_roles([leaf, leaf]), 'issuer certificate at depth 1 has no BasicConstraints (not a CA)']
    ].all? { |got, want| got == want }
  end

  # validity (x509-validity.ts)
  k08('c08 der: digits?, days_in_month, days_from_civil') do
    d = C08DerCert.der
    civil = [
      [1970, 1, 1, 0], [1969, 12, 31, -1], [2000, 2, 29, 11_016], [2000, 3, 1, 11_017], [1900, 3, 1, -25_508], [2100, 3, 1, 47_541],
      [1600, 3, 1, -135_080], [2300, 6, 15, 120_695], [1700, 1, 1, -98_615], [2400, 3, 1, 157_114], [0, 1, 1, -719_528], [1, 1, 1, -719_162],
      [2024, 2, 29, 19_782], [1999, 12, 31, 10_956], [2026, 1, 1, 20_454], [2038, 1, 19, 24_855], [400, 3, 1, -573_371], [399, 12, 31, -573_432]
    ]
    months = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    d.digits?('12') && d.digits?('0') && !d.digits?('') && !d.digits?('1a') && !d.digits?('a1') && !d.digits?("12\n") && !d.digits?('-1') &&
      civil.all? { |y, m, dd, want| d.days_from_civil(y, m, dd) == want } &&
      months.each_with_index.all? { |want, i| d.days_in_month(2025, i + 1) == want } &&
      [[2024, 29], [2000, 29], [2400, 29], [1600, 29], [1900, 28], [2100, 28], [2023, 28], [2200, 28]].all? { |y, want| d.days_in_month(y, 2) == want } &&
      d.days_in_month(2024, 1) == 31 && d.days_in_month(2000, 12) == 31
  end

  k08('c08 der: parse_der_time accepts exactly RFC 5280 times') do
    d = C08DerCert.der
    good = [
      [0x17, '260101000000Z', 1_767_225_600_000], [0x17, '500101000000Z', -631_152_000_000], [0x17, '491231235959Z', 2_524_607_999_000],
      [0x17, '000229120000Z', 951_825_600_000], [0x18, '20260101000000Z', 1_767_225_600_000], [0x18, '00010101000000Z', -62_135_596_800_000],
      [0x18, '00000101000000Z', -62_167_219_200_000], [0x18, '20240229000000Z', 1_709_164_800_000], [0x18, '20000229235959Z', 951_868_799_000],
      [0x18, '24000229000000Z', 13_574_563_200_000], [0x18, '20250430000000Z', 1_745_971_200_000], [0x18, '20250630000000Z', 1_751_241_600_000],
      [0x18, '20250930000000Z', 1_759_190_400_000], [0x18, '20251130000000Z', 1_764_460_800_000], [0x18, '20250131000000Z', 1_738_281_600_000],
      [0x18, '20250331000000Z', 1_743_379_200_000], [0x18, '20250531000000Z', 1_748_649_600_000], [0x18, '20250731000000Z', 1_753_920_000_000],
      [0x18, '20250831000000Z', 1_756_598_400_000], [0x18, '20251031000000Z', 1_761_868_800_000], [0x18, '20251231235959Z', 1_767_225_599_000],
      [0x18, '20250228000000Z', 1_740_700_800_000], [0x18, '20360101000000Z', 2_082_758_400_000], [0x18, '23000101000000Z', 10_413_792_000_000]
    ]
    bad = [
      [0x17, '260231000000Z'], [0x17, '20260101000000Z'], [0x18, '260101000000Z'], [0x19, '20260101000000Z'], [0x17, 'ab0101000000Z'],
      [0x18, 'abcd0101000000Z'], [0x17, '260101000000X'], [0x17, '26010100000aZ'], [0x17, '2601010000Z'], [0x17, ''], [0x18, ''],
      [0x17, '260101240000Z'], [0x17, '260101006000Z'], [0x17, '260101000060Z'], [0x17, '260001000000Z'], [0x17, '261301000000Z'],
      [0x17, '260100000000Z'], [0x17, '230229000000Z'], [0x18, '19000229000000Z'], [0x18, '21000229000000Z'], [0x18, '20230229000000Z'],
      [0x18, '20250431000000Z'], [0x18, '20250631000000Z'], [0x18, '20250931000000Z'], [0x18, '20251131000000Z'], [0x18, '20250132000000Z'],
      [0x18, '20250229000000Z'], [0x18, '20260101000000z'], [0x18, '20260101240000Z'], [0x18, '20260101006000Z'], [0x18, '20260101000060Z']
    ]
    good.all? { |tag, text, want| d.parse_der_time(tag, text) == want } && bad.all? { |tag, text| d.parse_der_time(tag, text).nil? }
  end

  k08('c08 der: der_validity_ms reads the validity of the certificate\'s own DER, nil members when malformed') do
    d = C08DerCert.der
    c = C08DerCert
    lo = 1_767_225_600_000
    hi = 2_082_758_400_000
    v = ->(**kw) { d.der_validity_ms(c.vc(**kw)) }
    junk = c.tlv(0x17, 'abcdefghijklm')
    nil2 = [nil, nil]
    sig = c.alg
    ver = c.tlv(0xA0, c.tlv(2, c.bin(2)))
    val = c.tlv(0x30, c.tlv(0x17, '260101000000Z'), c.tlv(0x18, '20360101000000Z'))
    overrun = c.tlv(0x30, c.tlv(0x30, ver, c.tlv(2, c.bin(5)), sig, c.nm('i')), val, sig, c.tlv(3, c.bin(0, 1)))
    non_ascii = c.vc(nb: c.tlv(0x17, "2601010\xE90000Z".b))
    [
      [v.(), [lo, hi]], [v.(version: false), [lo, hi]], [v.(outer: 0x31), nil2], [v.(tbs: 0x31), nil2], [v.(serial: c.tlv(4, c.bin(5))), nil2],
      [v.(sigalg: c.tlv(0x31, c.oid('1.2.3.4'))), nil2], [v.(issuer: c.tlv(0x31)), nil2],
      [v.(validity: c.tlv(0x31, c.tlv(0x17, '260101000000Z'), c.tlv(0x18, '20360101000000Z'))), nil2],
      [v.(validity: c.tlv(0x30, c.tlv(0x17, '260101000000Z'), c.tlv(0x18, '20360101000000Z'), c.tlv(0x17, '260101000000Z'))), nil2],
      [d.der_validity_ms(overrun), nil2], [v.(nb: junk), [nil, hi]], [v.(na: junk), [lo, nil]], [d.der_validity_ms('junk'.b), nil2], [d.der_validity_ms(''.b), nil2],
      [d.der_validity_ms(non_ascii), [nil, hi]], [d.der_validity_ms(non_ascii.dup.force_encoding('UTF-8')), [nil, hi]]
    ].all? { |got, want| got == want }
  end

  k08('c08 der: x509_valid_at? window, skew and fail-closed') do
    d = C08DerCert.der
    c = C08DerCert
    lo = 1_767_225_600_000
    hi = 2_082_758_400_000
    ok = c.vc
    bad_lo = c.vc(nb: c.tlv(0x17, 'abcdefghijklm'))
    bad_hi = c.vc(na: c.tlv(0x18, 'abcdefghijklmno'))
    both = c.vc(nb: c.tlv(0x17, 'abcdefghijklm'), na: c.tlv(0x18, 'abcdefghijklmno'))
    [
      [d.x509_valid_at?(ok, lo), true], [d.x509_valid_at?(ok, lo - 1), false], [d.x509_valid_at?(ok, hi), true], [d.x509_valid_at?(ok, hi + 1), false],
      [d.x509_valid_at?(ok, lo + 5), true], [d.x509_valid_at?(ok, lo - 1_000, 1_000), true], [d.x509_valid_at?(ok, lo - 1_001, 1_000), false],
      [d.x509_valid_at?(ok, hi + 1_000, 1_000), true], [d.x509_valid_at?(ok, hi + 1_001, 1_000), false],
      [d.x509_valid_at?(bad_lo, lo + 5), false], [d.x509_valid_at?(bad_hi, lo + 5), false], [d.x509_valid_at?(both, lo + 5), false],
      [d.x509_valid_at?('junk'.b, lo + 5), false]
    ].all? { |got, want| got.equal?(want) }
  end

  # ---------------------------------------------------------------- cert.rb

  k08('c08 cert: escape follows the OpenSSL text form') do
    c = C08DerCert.cert
    [
      ['plain', 'plain'], ["a\x01b", 'a\\01b'], ["\x1f", '\\1F'], ["\x00", '\\00'], ["\x7f", '\\7F'], ['a b', 'a b'], ['a~b', 'a~b'], ["a\x20b", 'a b'],
      ['a,b', 'a\\,b'], ['a+b', 'a\\+b'], ['a"b', 'a\\"b'], ['a\\b', 'a\\\\b'], ['a<b', 'a\\<b'], ['a>b', 'a\\>b'], ['a;b', 'a\\;b'],
      ['#ab', '\\#ab'], [' ab', '\\ ab'], ['a#b', 'a#b'], ['ab ', 'ab\\ '], [' ', '\\ '], ['  ', '\\ \\ '], ['caf' + "é", 'caf' + "é"],
      ["é ", "é\\ "], ['a b c', 'a b c'], ['', '']
    ].all? { |s, want| c.escape(s) == want }
  end

  k08('c08 cert: name_value decodes every string type') do
    c = C08DerCert.cert
    k = C08DerCert
    nv = lambda do |tag, raw|
      der = 'xyz'.b + k.tlv(tag, raw)
      c.name_value(der, 3, AtlasPca::Attest::Der.tlv_at(der, 3))
    end
    fffd = "\u{FFFD}"
    odd = nv.(0x1E, "\xD8\x00".b)
    odd32 = nv.(0x1C, "\x00\x11\x00\x00".b)
    [
      [nv.(0x0C, 'caf' + "\xC3\xA9".b), 'caf' + "é"], [nv.(0x0C, "a\xFFb".b), "a#{fffd}b"], [nv.(0x0C, 'a,b'), 'a\\,b'],
      [nv.(0x13, "\xE9".b), "é"], [nv.(0x16, "\xE9".b), "é"], [nv.(0x1A, "\xE9".b), "é"], [nv.(0x12, "\xE9".b), "é"], [nv.(0x14, "\xE9".b), "é"],
      [nv.(0x1E, "\x00\x41\x00\x42".b), 'AB'], [nv.(0x1C, "\x00\x00\x00\x41".b), 'A'], [nv.(0x1E, "\x00\x41".b), 'A'],
      [nv.(0x02, "\xAB".b), '#0201AB'], [nv.(0x05, ''.b), '#0500'], [nv.(0x13, "\xE9".b).encoding, Encoding::UTF_8],
      [nv.(0x1E, "\x00\x41".b).encoding, Encoding::UTF_8], [nv.(0x1C, "\x00\x00\x00\x41".b).encoding, Encoding::UTF_8]
    ].all? { |got, want| got == want } && odd.include?(fffd) && odd.valid_encoding? && odd32.include?(fffd) && odd32.valid_encoding?
  end

  k08('c08 cert: render_name prints OpenSSL\'s multi-line DN, exact errors') do
    c = C08DerCert.cert
    k = C08DerCert
    atv = ->(dotted, text) { k.tlv(0x30, k.oid(dotted), k.u8(text)) }
    multi = k.tlv(0x30, k.tlv(0x31, atv.('2.5.4.3', 'a')), k.tlv(0x31, atv.('2.5.4.10', 'b'), atv.('2.5.4.6', 'c')))
    me = ->(m) { ['CertError', m] }
    k.dl do
      [
        [c.render_name(k.nm('a')), 'CN=a'], [c.render_name(multi), "CN=a\nO=b + C=c"], [c.render_name(k.tlv(0x30)), ''],
        [c.render_name(k.tlv(0x30, k.tlv(0x31, atv.('1.2.3.4', 'x')))), '1.2.3.4=x'], [c.render_name(k.nm(' a,b ')), 'CN=\\ a\\,b\\ '],
        [c.render_name(k.nm("\xE9".b, 0x13)), "CN=é"], [c.render_name(k.tlv(0x30, k.tlv(0x31, k.tlv(0x30, k.cn, k.tlv(2, k.bin(5)))))), 'CN=#020105'],
        [k.raised { c.render_name(k.tlv(0x31)) }, me.('name is not a SEQUENCE')],
        [k.raised { c.render_name(k.tlv(0x30, k.tlv(0x30, atv.('2.5.4.3', 'a')))) }, me.('RDN is not a SET')]
      ].all? { |got, want| got == want }
    end
  end

  k08('c08 cert: from_pem takes exactly one DER certificate') do
    c = C08DerCert.cert
    k = C08DerCert
    pem = ->(der) { "-----BEGIN CERTIFICATE-----\n#{[der].pack('m')}-----END CERTIFICATE-----\n" }
    good = k.mk[:der]
    [
      [c.from_pem(pem.(good)).raw, good],
      [k.raised { c.from_pem(pem.(good + k.bin(0))) }, ['CertError', 'error:0680007B:asn1 encoding routines::header too long']],
      [k.raised { c.from_pem('junk') }, ['CertError', k::NSL]],
      [k.raised { c.from_pem(pem.("\x30\x05".b)) }, ['CertError', k::NSL]],
      [k.raised { c.from_pem("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----") }, ['CertError', k::NSL]]
    ].all? { |got, want| got == want }
  end

  k08('c08 cert: alg_parts, hash_of_alg_id, pss_params') do
    c = C08DerCert.cert
    k = C08DerCert
    ce = ->(m) { ['CertError', m] }
    hid = ->(h) { k.tlv(0x30, k.oid(k::HASHES.fetch(h))) }
    pss = ->(*elts) { k.tlv(0x30, k.oid(k::PSS), k.tlv(0x30, *elts)) }
    a0 = ->(h) { k.tlv(0xA0, hid.(h)) }
    a1 = ->(h, mgf = '1.2.840.113549.1.1.8') { k.tlv(0xA1, k.tlv(0x30, k.oid(mgf), hid.(h))) }
    a2 = ->(*salt) { k.tlv(0xA2, k.tlv(2, k.bin(*salt))) }
    a3 = ->(*v) { k.tlv(0xA3, k.tlv(2, k.bin(*v))) }
    plain = k.tlv(0x30, k.oid(k::PSS))
    ph = ->(alg_der) { c.pss_params(alg_der, c.alg_parts(alg_der)[1]) }
    pe = ->(alg_der) { k.raised { ph.(alg_der) } }
    defaults = ['sha1', 'sha1', 20]
    hash_tlv = k.tlv(0x30, k.oid(k::HASHES['sha256']))
    sha_alg = k.tlv(0x30, k.oid('1.2.840.113549.1.1.11'), k.tlv(5))
    [
      [c.alg_parts(sha_alg)[0], '1.2.840.113549.1.1.11'], [c.alg_parts(sha_alg)[1].tag, 5], [c.alg_parts(plain), [k::PSS, nil]],
      [c.hash_of_alg_id(hash_tlv, AtlasPca::Attest::Der.tlv_at(hash_tlv, 0)), 'sha256'],
      [k.raised { c.hash_of_alg_id(k.tlv(0x31, k.oid(k::HASHES['sha256'])), AtlasPca::Attest::Der.tlv_at(k.tlv(0x31, k.oid(k::HASHES['sha256'])), 0)) },
       ce.('hash algorithm is not a SEQUENCE')],
      [k.raised { c.hash_of_alg_id(k.tlv(0x30, k.oid('1.2.840.113549.2.5')), AtlasPca::Attest::Der.tlv_at(k.tlv(0x30, k.oid('1.2.840.113549.2.5')), 0)) },
       ce.('unsupported hash algorithm')],
      [ph.(plain), defaults], [c.pss_params(plain, nil), defaults], [ph.(k.tlv(0x30, k.oid(k::PSS), k.tlv(5))), defaults],
      [ph.(k.tlv(0x30, k.oid(k::PSS), k.tlv(4, a0.('sha256')))), defaults],
      [ph.(pss.(a0.('sha256'), a1.('sha384'), a2.(0x20))), ['sha256', 'sha384', 32]], [ph.(pss.(a2.(1, 0))), ['sha1', 'sha1', 256]],
      [ph.(pss.(a3.(1), a0.('sha512'))), ['sha512', 'sha1', 20]], [ph.(pss.(a3.(0, 1))), defaults],
      [ph.(pss.(a0.('sha1'), a0.('sha224'))), ['sha224', 'sha1', 20]], [ph.(pss.(a1.('sha512'))), ['sha1', 'sha512', 20]], [ph.(pss.(a0.('sha384'))), ['sha384', 'sha1', 20]],
      [pe.(pss.(k.tlv(0xA0))), ce.('empty PSS parameter')], [pe.(pss.(k.tlv(0xA1, k.tlv(2, k.bin(5))))), ce.('mask generation function is not a SEQUENCE')],
      [pe.(pss.(a1.('sha256', '1.2.3'))), ce.('unsupported mask generation function')], [pe.(pss.(k.tlv(0xA0, k.tlv(2, k.bin(1))))), ce.('hash algorithm is not a SEQUENCE')],
      [pe.(pss.(k.tlv(0xA0, k.tlv(0x30, k.oid('1.2.840.113549.2.5'))))), ce.('unsupported hash algorithm')],
      [pe.(pss.(k.tlv(0xA2, k.tlv(4, k.bin(5))))), ce.('salt length is not an INTEGER')],
      [pe.(pss.(k.tlv(0xA3, k.tlv(4, k.bin(1))))), ce.('trailer field is not 1')], [pe.(pss.(a3.(2))), ce.('trailer field is not 1')],
      [pe.(pss.(a3.(0x1f))), ce.('trailer field is not 1')], [pe.(pss.(a3.(0x10))), ce.('trailer field is not 1')],
      [pe.(pss.(k.tlv(0xA4, k.tlv(2, k.bin(1))))), ce.('unknown PSS parameter')]
    ].all? { |got, want| got == want }
  end

  k08('c08 cert: verify_signature maps each algorithm to its kind and hash') do
    c = C08DerCert.cert
    k = C08DerCert
    n = NodeX509
    msg = 'message to sign'
    ecp = k.ec_pub
    rsa = n.rsa
    ec_oids = { 'SHA224' => '1.2.840.10045.4.3.1', 'SHA256' => '1.2.840.10045.4.3.2', 'SHA384' => '1.2.840.10045.4.3.3', 'SHA512' => '1.2.840.10045.4.3.4' }
    rsa_oids = { 'SHA256' => '1.2.840.113549.1.1.11', 'SHA384' => '1.2.840.113549.1.1.12', 'SHA512' => '1.2.840.113549.1.1.13' }
    ec_ok = ec_oids.all? { |h, o| c.verify_signature(k.alg(o), msg, k.ec.sign(h, msg), ecp).equal?(true) }
    ec_cross = c.verify_signature(k.alg(ec_oids['SHA256']), msg, k.ec.sign('SHA384', msg), ecp).equal?(false) &&
               c.verify_signature(k.alg(rsa_oids['SHA384']), msg, k.ec.sign('SHA384', msg), ecp).equal?(false)
    rsa_ok = rsa_oids.all? { |h, o| c.verify_signature(k.alg(o, k.tlv(5)), msg, rsa.sign(h, msg), rsa).equal?(true) } &&
             c.verify_signature(k.alg(rsa_oids['SHA384'], k.tlv(5)), msg, rsa.sign('SHA256', msg), rsa).equal?(false)
    pss_ok = c.verify_signature(n.pss_alg, NodeX509::MSG, n.pss_sig, rsa).equal?(true) && c.verify_signature(n.pss_alg, NodeX509::MSG, n.pss_sig, n.pss_key).equal?(true) &&
             c.verify_signature(n.pss_alg, NodeX509::MSG, n.pss_sig, ecp).equal?(false) && c.verify_signature(n.pss_alg(20), NodeX509::MSG, n.pss_sig, rsa).equal?(false)
    seq = AtlasPca::Attest::Der.tlv_at(n.pss_alg, 0)
    oid_t = AtlasPca::Attest::Der.tlv_at(n.pss_alg, seq.start)
    unknown = k.tlv(0x30, k.oid('1.2.3.4'), n.pss_alg.byteslice(oid_t.end_, seq.end_ - oid_t.end_))
    unknown_ok = c.verify_signature(unknown, NodeX509::MSG, n.pss_sig, rsa).equal?(false) &&
                 c.verify_signature(k.tlv(0x30, k.oid('1.2.3.4')), msg, k.ec.sign('SHA256', msg), ecp).equal?(false)
    ec_ok && ec_cross && rsa_ok && pss_ok && unknown_ok
  end

  k08('c08 cert: verify_signature RSA-PSS reaches key.verify with the exact arguments and only for RSA keys (seam)') do
    c = C08DerCert.cert
    k = C08DerCert
    com = k.com
    seen = []
    spy = Object.new
    spy.define_singleton_method(:verify) do |*a|
      seen << a
      true
    end
    hid = ->(h) { k.tlv(0x30, k.oid(k::HASHES.fetch(h))) }
    alg = k.tlv(0x30, k.oid(k::PSS), k.tlv(0x30, k.tlv(0xA0, hid.('sha256')), k.tlv(0xA1, k.tlv(0x30, k.oid('1.2.840.113549.1.1.8'), hid.('sha384'))), k.tlv(0xA2, k.tlv(2, k.bin(0x21)))))
    rsa_res = {}
    %w[rsa rsa-pss].each do |kt|
      Seam.with(com, { key_type: ->(_key) { kt }, rsa_key_ok?: ->(_key) { true } }) { rsa_res[kt] = c.verify_signature(alg, 'msg', 'sig', spy) }
    end
    weak = nil
    Seam.with(com, { key_type: ->(_key) { 'rsa' }, rsa_key_ok?: ->(_key) { false } }) { weak = c.verify_signature(alg, 'msg', 'sig', spy) } # H1: a weak RSA key never reaches verify
    first = seen[0]
    ec_res = nil
    n_before = seen.length
    Seam.with(com, { key_type: ->(_key) { 'ec' } }) { ec_res = c.verify_signature(alg, 'msg', 'sig', spy) }
    raised = [OpenSSL::PKey::PKeyError, ArgumentError, TypeError].map do |klass|
      boom = Object.new
      boom.define_singleton_method(:verify) { |*_a| raise klass, 'seam' }
      Seam.with(com, { key_type: ->(_key) { 'rsa' }, rsa_key_ok?: ->(_key) { true } }) { c.verify_signature(alg, 'msg', 'sig', boom) }
    end
    rsa_res == { 'rsa' => true, 'rsa-pss' => true } && weak.equal?(false) && seen.length == 2 && n_before == 2 && ec_res.equal?(false) && seen.length == 2 &&
      first == ['SHA256', 'sig', 'msg', { rsa_padding_mode: 'pss', rsa_pss_saltlen: 33, rsa_mgf1_md: 'SHA384' }] &&
      first[1].encoding == Encoding::BINARY && first[2].encoding == Encoding::BINARY && first[0].encoding != Encoding::BINARY &&
      raised.all? { |r| r.equal?(false) }
  end

  k08('c08 cert: verify_with_alg is false, exactly, on a malformed identifier') do
    c = C08DerCert.cert
    k = C08DerCert
    c.verify_with_alg('junk'.b, 'm', 's', k.ec_pub).equal?(false) && c.verify_with_alg(''.b, 'm', 's', nil).equal?(false) &&
      c.verify_with_alg(k.alg('1.2.840.10045.4.3.2'), 'm', k.ec.sign('SHA256', 'm'), k.ec_pub).equal?(true)
  end

  k08('c08 cert: new exposes the parsed parts and keeps the bytes binary') do
    c = C08DerCert.cert
    k = C08DerCert
    h = k.mk(sign: true)
    x = c.new(h[:der])
    utf8 = c.new(h[:der].dup.force_encoding('UTF-8'))
    trailing = c.new(h[:der] + 'trailing')
    v1 = c.new(k.mk(version: false)[:der])
    no_sig = c.new(k.mk(sig_prefix: k.bin(0), sig: '')[:der])
    [
      [x.raw, h[:der]], [x.tbs_der, h[:tbs]], [x.sig_alg_der, h[:alg]], [x.inner_sig_alg_der, h[:alg]], [x.sig_unused, 0], [x.signature, h[:sig]],
      [x.serial, k.bin(5)], [x.issuer_der, h[:issuer]], [x.subject_der, h[:subject]], [x.spki_der, h[:spki]],
      [utf8.raw.encoding, Encoding::BINARY], [utf8.raw, h[:der]], [trailing.raw, h[:der]], [v1.serial, k.bin(5)], [v1.tbs_der.bytesize < x.tbs_der.bytesize, true],
      [no_sig.signature, ''.b], [no_sig.sig_unused, 0], [x.subject, 'CN=sub'], [x.issuer, 'CN=iss'], [x.subject.equal?(x.subject), true], [x.issuer.equal?(x.issuer), true],
      [x.spki_sha256, OpenSSL::Digest.new('SHA256').hexdigest(h[:spki])], [x.spki_sha('sha384'), OpenSSL::Digest.new('SHA384').hexdigest(h[:spki])]
    ].all? { |got, want| got == want }
  end

  k08('c08 cert: spki_sha names the digest in upper case (seam)') do
    k = C08DerCert
    x = k.new_cert
    seen = []
    orig = OpenSSL::Digest.method(:new)
    r = Seam.with(OpenSSL::Digest, { new: ->(a) { seen << a; orig.call(a) } }) { x.spki_sha('sha256') }
    seen == ['SHA256'] && r == OpenSSL::Digest.new('SHA256').hexdigest(x.spki_der)
  end

  k08('c08 cert: new refuses every structural defect with the no-start-line text') do
    c = C08DerCert.cert
    k = C08DerCert
    bad_alg = k.tlv(0x31, k.oid('1.2.840.10045.4.3.3'))
    cases = [
      { outer_tag: 0x31 }, { tbs_tag: 0x31 }, { alg_outer: bad_alg }, { sig_tag: 4 }, { sig_prefix: ''.b, sig: '' }, { after_sig: k.tlv(4, 'x') },
      { serial: k.tlv(4, k.bin(5)) }, { alg_inner: bad_alg }, { issuer: k.tlv(0x31, k.tlv(0x31)) },
      { validity: k.tlv(0x31, k.tlv(0x17, '260101000000Z'), k.tlv(0x17, '360101000000Z')) }, { subject: k.tlv(0x31, k.tlv(0x31)) },
      { spki: k.tlv(0x31, k.tlv(0x30, k.oid('1.2.840.10045.2.1')), k.tlv(3, k.bin(0, 4))) }, { serial: k.tlv(2, k.bin(0, 0x11)) }, { serial: k.tlv(2, '') }
    ]
    cases.all? { |kw| k.raised { c.new(k.mk(**kw)[:der]) } == ['CertError', k::NSL] } &&
      k.raised { c.new('junk'.b) } == ['CertError', k::NSL] && k.raised { c.new(''.b) } == ['CertError', k::NSL] &&
      k.raised { c.new(k.mk[:der].byteslice(0, 20)) } == ['CertError', k::NSL] &&
      k.raised { c.new(k.mk(sig_prefix: k.bin(0), sig: '')[:der]) }.nil? && k.raised { c.new(k.mk(version: false)[:der]) }.nil?
  end

  k08('c08 cert: new reads SubjectPublicKeyInfo as exactly {algorithm, key} and the tail as [1] [2] [3] only') do
    c = C08DerCert.cert
    k = C08DerCert
    ec_alg = k.tlv(0x30, k.oid('1.2.840.10045.2.1'), k.oid('1.2.840.10045.3.1.7'))
    bits = k.tlv(3, k.bin(0, 4))
    eoc = ['CertError', k::EOC]
    sp = ->(**kw) { k.raised { c.new(k.mk(**kw)[:der]) } }
    overrun = lambda do
      alg = k.alg
      sigbits = k.tlv(3, k.bin(0), 'SIGNA')
      prefix = [k.tlv(0xA0, k.tlv(2, k.bin(2))), k.tlv(2, k.bin(5)), alg, k.nm('iss'), k.tlv(0x30, k.tlv(0x17, '260101000000Z'), k.tlv(0x17, '360101000000Z')),
                k.nm('sub'), k.ec.public_to_der].map(&:b).join
      tail = [0xA3, 2 + alg.bytesize + sigbits.bytesize].pack('C*') + k.bin(0, 0)
      tbs = k.tlv(0x30, prefix + tail)
      k.raised { c.new(k.tlv(0x30, tbs + alg + sigbits)) }
    end
    k.dl do
      [
        [sp.(spki: k.tlv(0x30, ec_alg), tail: [k.bin(0x30, 0x84)]), eoc], [sp.(spki: k.tlv(0x30, ec_alg)), eoc],
        [sp.(spki: k.tlv(0x30, k.tlv(0x31, k.oid('1.2.840.10045.2.1')), bits)), eoc], [sp.(spki: k.tlv(0x30, ec_alg, k.tlv(4, k.bin(0, 4)))), eoc],
        [sp.(spki: k.tlv(0x30, ec_alg, bits, k.tlv(4, 'x'))), eoc], [sp.(spki: k.tlv(0x30, ec_alg, bits)), nil],
        [sp.(tail: [k.tlv(0xA1, 'x')]), nil], [sp.(tail: [k.tlv(0xA2, 'x')]), nil], [sp.(tail: [k.tlv(0xA3, 'x')]), nil],
        [sp.(tail: [k.tlv(0xA1, 'x'), k.tlv(0xA2, 'y'), k.tlv(0xA3, 'z')]), nil],
        [sp.(tail: [k.tlv(0xA0, 'x')]), eoc], [sp.(tail: [k.tlv(0xA4, 'x')]), eoc], [sp.(tail: [k.tlv(0x30, 'x')]), eoc],
        [sp.(tail: [k.tlv(0xA3, 'x'), k.tlv(4, 'x')]), eoc], [sp.(tail: [k.tlv(0xA1, 'x'), k.tlv(0xA0, 'x')]), eoc],
        [overrun.call, eoc]
      ].all? { |got, want| got == want }
    end
  end

  k08('c08 cert: serial_hex strips leading zeros') do
    k = C08DerCert
    sh = ->(*b) { k.new_cert(serial: k.tlv(2, k.bin(*b))).serial_hex }
    [[sh.(0, 0x80), '80'], [sh.(1, 0), '100'], [sh.(0), ''], [sh.(0x7f), '7f'], [sh.(5), '5'], [sh.(0, 0xff, 1), 'ff01']].all? { |got, want| got == want }
  end

  k08('c08 cert: public_key is decoded once and an undecodable key is a CertError') do
    c = C08DerCert.cert
    k = C08DerCert
    x = k.new_cert
    bad = c.new(k.mk(spki: k.tlv(0x30, k.tlv(0x30, k.oid('1.2.3.4')), k.tlv(3, k.bin(0, 1))))[:der])
    r = k.raised { bad.public_key }
    x.public_key.public_to_der == k.ec.public_to_der && x.public_key.equal?(x.public_key) && !r.nil? && r[0] == 'CertError' &&
      r[1].start_with?('error:1E08010C:DECODER routines::unsupported (') && r[1].end_with?(')')
  end

  k08('c08 cert: extensions are parsed once, a failure is remembered and reads as empty') do
    k = C08DerCert
    d = k.der
    good = k.mk(tail: [k.ext_block(k.ext('2.5.29.19', k.tlv(0x30), k.bin(0xff)), k.ext('2.5.29.15', k.tlv(3, k.bin(0, 4))))])[:der]
    broken = k.mk(tail: [k.ext_block(k.tlv(0x31, k.oid('2.5.29.19'), k.tlv(4, '')))])[:der]
    none = k.mk[:der]
    calls = 0
    orig = d.method(:parse_tbs_extensions)
    out = Seam.with(d, { parse_tbs_extensions: ->(t) { calls += 1; orig.call(t) } }) do
      g = k.cert.new(good)
      b = k.cert.new(broken)
      z = k.cert.new(none)
      r = [g.extensions.keys, g.extensions.keys, calls]
      r2 = [b.extensions, b.extensions, calls]
      r3 = [z.extensions, z.extensions, calls]
      [r, r2, r3]
    end
    out == [[%w[2.5.29.19 2.5.29.15], %w[2.5.29.19 2.5.29.15], 1], [{}, {}, 2], [{}, {}, 3]]
  end

  k08('c08 cert: key_cert_sign and ca read keyUsage and BasicConstraints exactly') do
    k = C08DerCert
    ku = ->(v) { k.ext('2.5.29.15', v) }
    bc = ->(v) { k.ext('2.5.29.19', v) }
    ca_t = k.tlv(1, k.bin(0xff))
    kcs = ->(*exts) { k.new_cert(tail: exts.empty? ? [] : [k.ext_block(*exts)]).key_cert_sign }
    cas = ->(*exts) { k.new_cert(tail: exts.empty? ? [] : [k.ext_block(*exts)]).ca }
    [
      [kcs.(), nil], [kcs.(ku.(k.tlv(3, k.bin(0, 4)))), true], [kcs.(ku.(k.tlv(3, k.bin(0, 1)))), false], [kcs.(ku.(k.tlv(3, k.bin(7, 0x80)))), false],
      [kcs.(ku.(k.tlv(3, k.bin(0, 5)))), true], [kcs.(ku.(k.tlv(3, k.bin(0)))), false], [kcs.(ku.(k.tlv(4, k.bin(0, 4)))), false], [kcs.(ku.(''.b)), nil],
      [cas.(), false], [cas.(bc.(k.tlv(0x30, ca_t))), true], [cas.(bc.(k.tlv(0x30, ca_t)), ku.(k.tlv(3, k.bin(0, 4)))), true],
      [cas.(bc.(k.tlv(0x30, ca_t)), ku.(k.tlv(3, k.bin(0, 1)))), false], [cas.(bc.(k.tlv(0x30, ca_t)), ku.(k.tlv(4, k.bin(0, 4)))), false],
      [cas.(bc.(k.tlv(0x30, k.tlv(1, k.bin(0))))), false], [cas.(bc.(k.tlv(0x30, k.tlv(1, k.bin(1))))), true], [cas.(bc.(k.tlv(0x30))), false],
      [cas.(bc.(k.tlv(0x31, ca_t))), false], [cas.(bc.(k.tlv(0x30, k.tlv(2, k.bin(5))))), false], [cas.(bc.(k.tlv(0x30, k.tlv(1)))), false],
      [cas.(bc.(''.b)), false], [cas.(bc.(k.bin(0x30, 5, 1))), false], [cas.(bc.(k.tlv(0x30, ca_t, k.tlv(2, k.bin(1))))), true]
    ].all? { |got, want| got.equal?(want) }
  end

  k08('c08 cert: check_issued answers exactly true or false, the link rules are the reference\'s') do
    n = NodeX509
    k = C08DerCert
    c = k.cert
    up = c.new(n.cert(n.root, n.up_name, [n.skid], n.b(0x11)))
    leaf = ->(iss) { c.new(n.cert(iss, n.name('leaf'), [], n.b(0x22), subject_key: StrictChain.key('nx-leaf'), signer: StrictChain.key('nx-up'))) }
    ku_no = c.new(n.cert(n.root, n.up_name, [n.skid, n.x(0x0f, n.tlv(0x03, n.b(5, 0xa0)))], n.b(0x11)))
    [
      [leaf.(n.up_name).check_issued(up), true], [leaf.(n.other).check_issued(up), false], [leaf.(n.up_name).check_issued(ku_no), false],
      [n.issued?([]), true], [n.issued?([n.ak(n.keyid)]), true], [n.issued?([n.ak(n.tlv(0x80, n.b(8, 8, 8, 8)))]), false],
      [n.issued?([n.ak(n.keyid, n.ser(0x12))]), false], [n.issued?([n.ak(n.keyid, n.names(n.dir(n.other)))]), false]
    ].all? { |got, want| got.equal?(want) } && n.issued?([n.ak(n.keyid, n.names(n.dir(n.root)), n.ser(0x11))]).equal?(true)
  end

  k08('c08 cert: link_extensions!, subject_key_id and authority_key_id decode or raise DerError') do
    k = C08DerCert
    c = k.cert
    de = ->(m) { ['DerError', m] }
    with = ->(*exts) { k.new_cert(tail: [k.ext_block(*exts)]) }
    skid = ->(v) { k.ext('2.5.29.14', v) }
    akid = ->(*m) { k.ext('2.5.29.35', k.tlv(0x30, *m)) }
    root = k.nm('root')
    dirn = k.tlv(0xA4, root)
    kid = k.tlv(0x80, k.bin(0xaa, 0xbb))
    broken = k.new_cert(tail: [k.ext_block(k.tlv(0x31, k.oid('2.5.29.19'), k.tlv(4, '')))])
    [
      [k.raised { broken.link_extensions! }, de.('extensions do not decode')],
      [c.new(k.mk[:der]).subject_key_id, nil], [with.(skid.(k.tlv(4, k.bin(0xaa, 0xbb)))).subject_key_id, k.bin(0xaa, 0xbb)],
      [k.raised { with.(skid.(k.tlv(0x30))).subject_key_id }, de.('SKID is not an OCTET STRING')],
      [c.new(k.mk[:der]).authority_key_id, []],
      [k.raised { with.(k.ext('2.5.29.35', k.tlv(4, k.bin(5)))).authority_key_id }, de.('AKID is not a SEQUENCE')],
      [with.(akid.(kid, k.tlv(0xA1, dirn), k.tlv(0x82, k.bin(0x11)))).authority_key_id, [k.bin(0xaa, 0xbb), k.bin(0x11), root]],
      [with.(akid.(kid)).authority_key_id, [k.bin(0xaa, 0xbb), nil, nil]],
      [with.(akid.(k.tlv(0xA1, k.tlv(0x82, 'a'), dirn))).authority_key_id, [nil, nil, root]],
      [with.(akid.(k.tlv(0x82, k.bin(0x11)))).authority_key_id, [nil, k.bin(0x11), nil]],
      [k.raised { with.(akid.(kid, k.tlv(0x82, k.bin(0, 0x11)))).authority_key_id }, de.('AKID serial is not a DER INTEGER')],
      [k.raised { with.(akid.(kid, k.tlv(0x82))).authority_key_id }, de.('AKID serial is not a DER INTEGER')],
      [k.raised { with.(akid.(kid, k.tlv(0x82, k.bin(0xff, 0x80)))).authority_key_id }, de.('AKID serial is not a DER INTEGER')]
    ].all? { |got, want| got == want }
  end

  k08('c08 cert: verify checks both algorithm copies, the unused bits, then the signature') do
    k = C08DerCert
    c = k.cert
    plain = c.new(k.mk(sign: true)[:der])
    mismatch = c.new(k.mk(sign: true, alg_inner: k.alg('1.2.840.10045.4.3.3', k.tlv(5)))[:der])
    unused = c.new(k.mk(sign: true, sig_prefix: k.bin(1))[:der])
    garbage = c.new(k.mk(sign: true, alg_outer: k.tlv(0x30))[:der])
    other_key = OpenSSL::PKey::EC.generate('prime256v1')
    [
      [plain.verify(plain.public_key), true], [plain.verify_self, true], [plain.verify(OpenSSL::PKey.read(other_key.public_to_der)), false],
      [mismatch.verify(mismatch.public_key), false], [unused.verify(unused.public_key), false], [garbage.verify(garbage.public_key), false],
      [plain.verify(nil), false]
    ].all? { |got, want| got.equal?(want) }
  end
end

MutationKill::C08DerCert.ec # generated once in the parent, not in every forked mutant run
