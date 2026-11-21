# frozen_string_literal: true
# Exact-outcome kill tests for lib/atlas_pca/attest/nvidia.rb (SPDM transcript parser, device chain, RIM XMLDSig, RIM ids, golden
# comparison, CRL chain revocation, firmware policy, the collateral hook and the SPDM verifier). Reference: attest-nvidia-spdm.ts,
# attest-nvidia-rim.ts. Certificates, CRLs, RIMs and transcripts are built here (P-384, generated at load, never committed) and
# every AtlasPca constant is resolved at call time (the oracle re-evaluates the library per mutant).
require 'atlas_pca/attest'
require 'openssl'
require 'timeout'
require 'digest'
require 'tmpdir'
require 'fileutils'
require 'rbconfig'
module MutationKill
  module C13
    module_function

    NOW = 1_800_000_000_000
    DS = 'http://www.w3.org/2000/09/xmldsig#'
    C14 = 'http://www.w3.org/2006/12/xml-c14n11'
    ENVS = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
    ECD = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384'
    SHA = 'http://www.w3.org/2001/04/xmldsig-more#sha384'

    def run? = (f = ENV['MUT_FILE']).nil? || f.empty? || f == 'nvidia.rb'
    def a = AtlasPca::Attest
    def nv = AtlasPca::Attest::Nvidia

    # a fresh Ruby that loads the library with only nvidia.rb replaced by the text being mutated (an in-process require is already satisfied)
    LIB = File.expand_path('../../lib', __dir__)
    REL = 'atlas_pca/attest/nvidia.rb'

    def mutating? = (f = ENV['MUT_FILE']) && !f.empty?

    def source
      if defined?(::Oracle) && (tgt = ::Oracle.instance_variable_get(:@target)) && File.expand_path(tgt) == File.join(LIB, REL)
        ::Oracle.instance_variable_get(:@text)
      else
        File.read(File.join(LIB, REL))
      end
    end

    def header_changed? = source.lines.first(12) != File.read(File.join(LIB, REL)).lines.first(12)

    def fresh(code)
      Dir.mktmpdir('c13fresh') do |d|
        FileUtils.cp_r(LIB, d)
        File.write(File.join(d, 'lib', REL), source)
        gems = Gem.loaded_specs.values.flat_map(&:full_require_paths).flat_map { |g| ['-I', g] }
        out = IO.popen([RbConfig.ruby, '--disable-gems', '-I', File.join(d, 'lib'), *gems, '-e', code], 'r', err: File::NULL, &:read)
        [out, $?.success?]
      end
    end

    # raises (an exception fails the kill test) with both values when they differ
    def chk(label, got, want)
      raise "#{label}: got #{got.inspect}, want #{want.inspect}" unless got == want

      true
    end

    def err_of
      yield
      nil
    rescue StandardError => e
      [e.class.name, e.message]
    end

    def msg
      yield
      nil
    rescue StandardError => e
      e.message
    end

    # ---- certificates

    def key(n, curve = 'secp384r1') = (@keys ||= {})[[n, curve]] ||= OpenSSL::PKey::EC.generate(curve)
    def ext(sn, v, critical = true) = OpenSSL::X509::ExtensionFactory.new.create_extension(sn, v, critical)
    def crit(oid = '1.2.3.4') = OpenSSL::X509::Extension.new(oid, OpenSSL::ASN1::Null.new(nil).to_der, true)
    def ca_exts = [ext('basicConstraints', 'CA:TRUE'), ext('keyUsage', 'keyCertSign,cRLSign')]
    def leaf_exts = [ext('basicConstraints', 'CA:FALSE')]

    def cert(name, issuer, exts, sign_with: issuer, key_of: name, curve: 'secp384r1', nb: 1_700_000_000, na: 1_900_000_000, serial: nil)
      c = OpenSSL::X509::Certificate.new
      c.version = 2
      c.serial = OpenSSL::BN.new(serial || (name.sum + 1))
      c.subject = OpenSSL::X509::Name.parse("/CN=#{name}")
      c.issuer = OpenSSL::X509::Name.parse("/CN=#{issuer}")
      c.public_key = key(key_of, curve)
      c.not_before = Time.at(nb)
      c.not_after = Time.at(na)
      exts.each { |e| c.add_extension(e) }
      c.sign(key(sign_with), OpenSSL::Digest.new('SHA384'))
    end

    LEAF = 'GPU GH100 leaf'
    MID = 'NVIDIA Mid CA'
    ROOT = 'NVIDIA Root CA'

    def chain3 = @chain3 ||= [cert(LEAF, MID, leaf_exts), cert(MID, ROOT, ca_exts), cert(ROOT, ROOT, ca_exts)]
    def pem(certs) = certs.map(&:to_pem).join("\n")
    def lib_cert(c) = a::Cert.new(c.to_der)
    def pin(c) = lib_cert(c).spki_sha256
    def vchain(certs, pins = nil, now = NOW) = nv.verify_nvidia_device_chain(pem(certs), pins || [pin(certs.last)], now)

    def raw_sig(k, data)
      seq = OpenSSL::ASN1.decode(k.sign(OpenSSL::Digest.new('SHA384'), data))
      seq.value.map { |i| i.value.to_s(2).rjust(48, "\0".b) }.join.b
    end

    def b64(s) = [s].pack('m0')

    # ---- SPDM transcripts

    def u16(n) = [n].pack('v')
    def u24(n) = [n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF].pack('C3')

    def block(idx, digest, vtype: 1, vsize: nil, size: nil)
      body = [vtype].pack('C') + u16(vsize || digest.bytesize) + digest
      [idx, 0].pack('CC') + u16(size || body.bytesize) + body
    end

    def tlvs(h) = h.map { |t, v| u16(t) + u16(v.bytesize) + v }.inject(''.b, :+)

    def tx(blocks: [], rq: 0x11, rs: 0x11, rqc: 0xE0, rsc: 0x60, rec: nil, num: nil, rec_delta: 0, opaque: {}, op_raw: nil, op_delta: 0,
           nonce: ("\xF0".b * 32), sig: ("S".b * 96))
      recb = rec || blocks.inject(''.b, :+)
      op = op_raw || tlvs(opaque)
      head = [rq, rqc, 0, 0].pack('C4') + nonce + "\0".b
      head + [rs, rsc, 0, 0, num || blocks.length].pack('C5') + u24(recb.bytesize + rec_delta) + recb + ('M'.b * 32) + u16(op.bytesize + op_delta) + op + sig
    end

    def parse(t) = nv.parse_nvidia_spdm_evidence(t)
    def perr(t) = msg { parse(t) }

    # ---- RIM documents

    def rkey = key('RIM signer')
    def rim_certs = @rim_certs ||= [cert('RIM signer', 'RIM root', leaf_exts), cert('RIM root', 'RIM root', ca_exts)]
    def rim_pin = [pin(rim_certs.last)]

    DEF = {
      root: 'SoftwareIdentity', root_attrs: ' tagId="TAG1"', meta: '<Meta product="GH100" colloquialVersion="1.2.3"/>',
      payload: '<Payload><Resource type="Measurement" index="0" alternatives="1" size="2" active="true" Hash0="abcd"/></Payload>',
      canon: %(<CanonicalizationMethod Algorithm="#{C14}"/>), sigm: %(<SignatureMethod Algorithm="#{ECD}"/>), uri: ' URI=""',
      transforms: %(<Transforms><Transform Algorithm="#{ENVS}"/><Transform Algorithm="#{C14}"/></Transforms>),
      dm: %(<DigestMethod Algorithm="#{SHA}"/>), ref_extra: '', dv: :auto, sv: :auto, keyinfo: nil, si: nil, sig_count: 1, sig_in_payload: false,
      pre: '', certs: nil
    }.freeze

    def assemble(d, dv, sv)
      dvx = dv.nil? ? '' : "<DigestValue>#{dv}</DigestValue>"
      si = d[:si] || "<SignedInfo>#{d[:canon]}#{d[:sigm]}<Reference#{d[:uri]}>#{d[:transforms]}#{d[:dm]}#{dvx}</Reference>#{d[:ref_extra]}</SignedInfo>"
      svx = sv.nil? ? '' : "<SignatureValue>#{sv}</SignatureValue>"
      cs = (d[:certs] || rim_certs).map { |c| "<X509Certificate>#{b64(c.to_der)}</X509Certificate>" }.join
      ki = d[:keyinfo] || "<KeyInfo><X509Data>#{cs}</X509Data></KeyInfo>"
      sig = %(<Signature xmlns="#{DS}">#{si}#{svx}#{ki}</Signature>)
      sigs = sig * d[:sig_count]
      payload = d[:payload]
      payload = payload.sub('</Payload>', "#{sigs}</Payload>") if d[:sig_in_payload]
      "#{d[:pre]}<#{d[:root]}#{d[:root_attrs]}>#{d[:meta]}#{payload}#{d[:sig_in_payload] ? '' : sigs}</#{d[:root]}>"
    end

    def rim(o = {})
      (@rims ||= {})[o.inspect] ||= begin
        d = DEF.merge(o)
        dv = d[:dv]
        sv = d[:sv]
        if dv == :auto
          doc = a::Xml.parse_xml(assemble(d, '', nil))
          sg = doc.root.element_children(DS, 'Signature')[0]
          dv = b64(Digest::SHA384.digest(a::Xml.canonicalize(doc.root, sg).b))
        end
        dv = dv.scan(/.{1,20}/).join("\n  ") if d[:ws] && dv.is_a?(String)
        if sv == :auto
          doc = a::Xml.parse_xml(assemble(d, dv, nil))
          si = doc.root.element_children(DS, 'Signature')[0].element_children(DS, 'SignedInfo')[0]
          sv = b64(raw_sig(rkey, a::Xml.canonicalize(si).b))
        end
        sv = sv.scan(/.{1,20}/).join("\n  ") if d[:ws] && sv.is_a?(String)
        assemble(d, dv, sv)
      end
    end

    def vrim(xml, pins = nil, now = NOW) = nv.verify_nvidia_rim(xml, pins || rim_pin, now)
    def why(xml, pins = nil) = (r = vrim(xml, pins))['ok'] ? r : r['reason']

    def res(index: '0', alts: '1', size: '2', active: 'true', type: 'Measurement', hashes: { 'Hash0' => 'abcd' }, tag: 'Resource')
      hs = hashes.map { |k, v| %( #{k}="#{v}") }.join
      %(<#{tag} type="#{type}" index="#{index}" alternatives="#{alts}" size="#{size}" active="#{active}"#{hs}/>)
    end

    def pay(*rs) = "<Payload>#{rs.join}</Payload>"

    # ---- CRLs

    def crl(issuer, revoked: [], this: 1_790_000_000, nxt: 1_810_000_000, signer: issuer)
      c = OpenSSL::X509::CRL.new
      c.version = 1
      c.issuer = OpenSSL::X509::Name.parse("/CN=#{issuer}")
      c.last_update = Time.at(this)
      c.next_update = Time.at(nxt)
      revoked.each do |s|
        r = OpenSSL::X509::Revoked.new
        r.serial = OpenSSL::BN.new(s)
        r.time = Time.at(1_780_000_000)
        c.add_revoked(r)
      end
      c.sign(key(signer), OpenSSL::Digest.new('SHA256')).to_der
    end

    def serial(name) = name.sum + 1
  end
end

module MutationKill
  c = C13

  t('nvidia.rb requires Intel, Ocsp and Xml itself (fresh ruby over the mutated text)') do
    next true unless c.run?
    next true if c.mutating? && !c.header_changed?

    code = "require 'atlas_pca/attest/nvidia'; puts [defined?(AtlasPca::Attest::Intel), defined?(AtlasPca::Attest::Ocsp), defined?(AtlasPca::Attest::Xml), defined?(AtlasPca::Attest::Nvidia)].inspect"
    c.chk('fresh load', c.fresh(code), ["[\"constant\", \"constant\", \"constant\", \"constant\"]\n", true])
  end

  t('nvidia: constants, byte readers and the SPDM version reason') do
    next true unless c.run?

    n = c.nv
    c.chk('suite', n::SUITE, 'nvidia-gpu-spdm-ecdsa-p384-sha384')
    c.chk('consts', [n::REQ_LEN, n::NONCE_LEN, n::SIG_LEN, n::MAX_CHAIN, n::OPAQUE_DRIVER_VERSION, n::OPAQUE_VBIOS_VERSION, n::OPAQUE_CHIP_INFO, n::NVDEC0_DISABLED, n::NVDEC_BLOCK_INDEX],
          [37, 32, 96, 5, 3, 6, 35, 0x55, 35])
    b = "\x05\x06".b
    c.chk('b_at', [n.b_at(b, -1), n.b_at(b, 0), n.b_at(b, 1), n.b_at(b, 2), n.b_at(b, 99)], [0, 5, 6, 0, 0])
    c.chk('u16', n.u16_at("\x01\x02\x03".b, 0), 0x0201)
    c.chk('u16 tail', n.u16_at("\x01\x02\x03".b, 2), 0x03)
    c.chk('u24', n.u24_at("\x01\x02\x03\x04".b, 0), 0x030201)
    c.chk('u24 off', n.u24_at("\x01\x02\x03\x04".b, 1), 0x040302)
    c.chk('u24 past end', n.u24_at("\xFF".b, 0), 0xFF)
    rep = ->(rq, rs) { { 'request' => { 'version' => rq }, 'response_version' => rs } }
    c.chk('ver ok', [n.spdm_version_reason(rep.call(0x11, 0x11)), n.spdm_version_reason(rep.call(0x12, 0x12))], [nil, nil])
    c.chk('ver 0x10', n.spdm_version_reason(rep.call(0x10, 0x10)), 'SPDM version 0x10/0x10 is not an accepted GET_MEASUREMENTS version')
    c.chk('ver mismatch', n.spdm_version_reason(rep.call(0x12, 0x11)), 'SPDM version 0x12/0x11 is not an accepted GET_MEASUREMENTS version')
    c.chk('ver mismatch 2', n.spdm_version_reason(rep.call(0x11, 0x12)), 'SPDM version 0x11/0x12 is not an accepted GET_MEASUREMENTS version')
    true
  end

  t('nvidia: parse_nvidia_spdm_evidence returns the exact structure (high bytes, UTF-8 tagged input, 16-bit tags)') do
    next true unless c.run?

    d1 = (1..48).map { |i| 0xF0 + (i % 16) }.pack('C*')
    d2 = ("\xFF".b * 32)
    nonce = ("\xF0".b * 32)
    sg = (0...96).map { |i| (i * 7 + 128) & 0xFF }.pack('C*')
    op = { 3 => '595'.b, 6 => "\x01\x02".b, 300 => ''.b, 17 => "\xE9".b }
    t = c.tx(blocks: [c.block(1, d1), c.block(2, d2, vtype: 2)], opaque: op, sig: sg, nonce: nonce, rq: 0x12, rs: 0x12)
    want = { 'request' => { 'version' => 0x12, 'nonce' => nonce }, 'response_version' => 0x12,
             'measurements' => [{ 'index' => 1, 'valueType' => 1, 'digest' => d1 }, { 'index' => 2, 'valueType' => 2, 'digest' => d2 }],
             'opaque' => op, 'signature' => sg, 'signedBytes' => t.byteslice(0, t.bytesize - 96) }
    got = Timeout.timeout(1) { c.parse(t) }
    c.chk('parse', got, want)
    u = Timeout.timeout(1) { c.parse(t.dup.force_encoding('UTF-8')) }
    c.chk('parse utf8', u, want)
    c.chk('binary', [u['request']['nonce'].encoding, u['signature'].encoding, u['signedBytes'].encoding, u['measurements'][0]['digest'].encoding, u['opaque'][3].encoding],
          [Encoding::BINARY] * 5)
    z = c.parse(c.tx)
    c.chk('minimal', [z['measurements'], z['opaque'], z['request']['version']], [[], {}, 0x11])
    c.chk('minimal size', c.tx.bytesize, 175)
    true
  end

  t('nvidia: parse_nvidia_spdm_evidence refuses each structural defect with the exact message') do
    next true unless c.run?

    ok = c.tx(blocks: [c.block(1, 'D'.b * 4)])
    c.chk('short 174', c.perr(c.tx[0, 174]), 'parseNvidiaSpdmEvidence: transcript too short (174)')
    c.chk('short 0', c.perr(''), 'parseNvidiaSpdmEvidence: transcript too short (0)')
    c.chk('short long', c.perr(ok[0, 150]), 'parseNvidiaSpdmEvidence: transcript too short (150)')
    c.chk('req code', c.perr(c.tx(rqc: 0xE1)), 'parseNvidiaSpdmEvidence: request code 0xe1 is not GET_MEASUREMENTS')
    c.chk('req code 0', c.perr(c.tx(rqc: 0x00)), 'parseNvidiaSpdmEvidence: request code 0x0 is not GET_MEASUREMENTS')
    c.chk('resp code', c.perr(c.tx(rsc: 0x61)), 'parseNvidiaSpdmEvidence: response code is not MEASUREMENTS')
    # the record length claims one byte more than the transcript holds
    c.chk('overrun', c.perr(c.tx(blocks: [c.block(1, 'D'.b * 4)], rec_delta: 1)), 'parseNvidiaSpdmEvidence: measurement record length overruns transcript')
    c.chk('overrun big', c.perr(c.tx(rec_delta: 1)), 'parseNvidiaSpdmEvidence: measurement record length overruns transcript')
    # three stray bytes after a block: fewer than a block header
    blk = c.block(1, 'D'.b * 4)
    c.chk('trunc header', c.perr(c.tx(rec: blk + "\0\0\0".b, num: 1)), 'parseNvidiaSpdmEvidence: truncated measurement block header')
    # exactly a header (size 0): the header fits but the block is too small
    c.chk('size 0', c.perr(c.tx(rec: blk + [2, 0, 0, 0].pack('C4'), num: 2)), 'parseNvidiaSpdmEvidence: measurement block overruns record')
    # block bigger than the record, with a self-consistent DMTF value (vsize 0)
    c.chk('block overruns', c.perr(c.tx(rec: [1, 0].pack('CC') + c.u16(9) + [1].pack('C') + c.u16(0) + "\0\0\0".b, num: 1)), 'parseNvidiaSpdmEvidence: measurement block overruns record')
    # block size 2 (< 3) with room in the record
    c.chk('size 2', c.perr(c.tx(rec: [1, 0].pack('CC') + c.u16(2) + "\0\0".b + "\0\0".b, num: 1)), 'parseNvidiaSpdmEvidence: measurement block overruns record')
    # size exactly 3 with an empty digest is valid
    e = c.parse(c.tx(blocks: [c.block(1, ''.b)]))
    c.chk('size 3', e['measurements'], [{ 'index' => 1, 'valueType' => 1, 'digest' => ''.b }])
    c.chk('dmtf overrun', c.perr(c.tx(blocks: [c.block(1, 'D'.b * 4, vsize: 5)])), 'parseNvidiaSpdmEvidence: DMTF value overruns measurement block')
    c.chk('dmtf exact', c.parse(c.tx(blocks: [c.block(1, 'D'.b * 4, vsize: 4)]))['measurements'][0]['digest'], 'DDDD'.b)
    c.chk('dmtf short vsize', c.parse(c.tx(blocks: [c.block(1, 'DDDD'.b, vsize: 3)]))['measurements'][0]['digest'], 'DDD'.b)
    c.chk('num', c.perr(c.tx(blocks: [c.block(1, 'D'.b)], num: 2)), 'parseNvidiaSpdmEvidence: header says 2 blocks, parsed 1')
    c.chk('num 0', c.perr(c.tx(blocks: [c.block(1, 'D'.b)], num: 0)), 'parseNvidiaSpdmEvidence: header says 0 blocks, parsed 1')
    fill = 'parseNvidiaSpdmEvidence: opaque length + signature do not exactly fill the transcript'
    c.chk('op long', c.perr(c.tx(op_delta: 1)), fill)
    c.chk('op short', c.perr(c.tx(opaque: { 3 => 'abc'.b }, op_delta: -1)), fill)
    c.chk('tail byte', c.perr(c.tx + "\0".b), fill)
    c.chk('tlv header', c.perr(c.tx(op_raw: "\x03\x00\x00".b)), 'parseNvidiaSpdmEvidence: truncated opaque TLV header')
    c.chk('tlv header exact', c.parse(c.tx(op_raw: [9, 0].pack('v*')))['opaque'], { 9 => ''.b })
    c.chk('tlv overrun', c.perr(c.tx(op_raw: c.u16(3) + c.u16(2) + 'a'.b)), 'parseNvidiaSpdmEvidence: opaque TLV overruns opaque data')
    c.chk('tlv exact', c.parse(c.tx(op_raw: c.u16(3) + c.u16(2) + 'ab'.b))['opaque'], { 3 => 'ab'.b })
    c.chk('tlv dup tag keeps last', c.parse(c.tx(op_raw: c.u16(3) + c.u16(1) + 'a'.b + c.u16(3) + c.u16(1) + 'b'.b))['opaque'], { 3 => 'b'.b })
    true
  end

  t('nvidia: format_vbios_version byte-reverses (UTF-8 tagged raw too)') do
    next true unless c.run?

    n = c.nv
    c.chk('vb', n.format_vbios_version([0x00, 0x9f, 0x00, 0x96, 0x04, 0xAA, 0xBB, 0xCC].pack('C*')), '96.00.9f.00.04')
    raw = "éABCDEF" # bytes C3 A9 41 42 43 44 45 46, a valid multi-byte character
    by = raw.bytes
    c.chk('vb utf8', n.format_vbios_version(raw), [by[3], by[2], by[1], by[0], by[4]].map { |x| format('%02x', x) }.join('.'))
    c.chk('vb 6', n.format_vbios_version([1, 2, 3, 4, 5, 6].pack('C*')), '03.02.01.04')
    true
  end

  t('nvidia: parse_pem_chain bounds the chain and device chain verification reports each defect') do
    next true unless c.run?

    n = c.nv
    ch = c.chain3
    one = ch[0].to_pem
    c.chk('0', c.msg { n.parse_pem_chain('') }, 'parsePemChain: no certificates found')
    c.chk('5', n.parse_pem_chain(([one] * 5).join("\n")).length, 5)
    c.chk('6', c.msg { n.parse_pem_chain(([one] * 6).join("\n")) }, 'parsePemChain: chain longer than 5')
    c.chk('6 via verify', c.vchain([ch[0]] * 6, ['x']), { 'ok' => false, 'reason' => 'device chain unparseable: parsePemChain: chain longer than 5' })
    c.chk('empty via verify', n.verify_nvidia_device_chain('', ['x'], c::NOW), { 'ok' => false, 'reason' => 'device chain unparseable: parsePemChain: no certificates found' })
    g = n.verify_nvidia_device_chain("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----", ['x'], c::NOW)
    c.chk('garbage', [g['ok'], g['reason'].start_with?('device chain unparseable: ')], [false, true])

    r = c.vchain(ch)
    c.chk('ok keys', r.keys, %w[ok leaf chain])
    c.chk('ok', [r['ok'], r['chain'].length, r['leaf'].raw, r['chain'][2].raw], [true, 3, ch[0].to_der, ch[2].to_der])
    up = c.vchain(ch, [c.pin(ch[2]).upcase])
    c.chk('upcase pin', up['ok'], true)
    c.chk('other pin', c.vchain(ch, ['0' * 64]), { 'ok' => false, 'reason' => 'chain root is not a pinned NVIDIA root' })
    c.chk('no pin', c.vchain(ch, []), { 'ok' => false, 'reason' => 'chain root is not a pinned NVIDIA root' })
    c.chk('second pin', c.vchain(ch, ['0' * 64, c.pin(ch[2])])['ok'], true)

    # validity window per index
    lv = ->(i, nb, na) { x = c.chain3.dup; x[i] = c.cert([c::LEAF, c::MID, c::ROOT][i], [c::MID, c::ROOT, c::ROOT][i], i.zero? ? c.leaf_exts : c.ca_exts, nb: nb, na: na); x }
    [[0, 1_700_000_000, 1_790_000_000], [1, 1_700_000_000, 1_790_000_000], [1, 1_810_000_000, 1_900_000_000]].each do |i, nb, na|
      c.chk("validity #{i}", c.vchain(lv.call(i, nb, na), [c.pin(ch[2])]), { 'ok' => false, 'reason' => "device chain cert ##{i} is outside its validity window" })
    end
    c.chk('validity root', c.vchain(lv.call(2, 1_700_000_000, 1_790_000_000), [c.pin(ch[2])]), { 'ok' => false, 'reason' => 'device chain cert #2 is outside its validity window' })

    # not P-384
    p256 = c.cert(c::LEAF, c::MID, c.leaf_exts, curve: 'prime256v1', key_of: 'leaf p256')
    c.chk('p256 leaf', c.vchain([p256, ch[1], ch[2]], [c.pin(ch[2])]), { 'ok' => false, 'reason' => 'device chain cert #0 is not an ECDSA P-384 key' })
    mid256 = c.cert(c::MID, c::ROOT, c.ca_exts, curve: 'prime256v1', key_of: 'mid p256')
    c.chk('p256 mid', c.vchain([ch[0], mid256, ch[2]], [c.pin(ch[2])]), { 'ok' => false, 'reason' => 'device chain cert #1 is not an ECDSA P-384 key' })

    # an issuer that is not a CA
    notca = c.cert(c::MID, c::ROOT, c.leaf_exts)
    c.chk('issuer not ca', c.vchain([ch[0], notca, ch[2]], [c.pin(ch[2])]), { 'ok' => false, 'reason' => 'device chain cert #1 issues a certificate but is not a CA' })
    # a link signed by another key
    other = c.cert(c::LEAF, c::MID, c.leaf_exts, sign_with: 'some other signer')
    c.chk('link', c.vchain([other, ch[1], ch[2]], [c.pin(ch[2])]), { 'ok' => false, 'reason' => 'device chain link #0 signature does not verify under its issuer' })
    other1 = c.cert(c::MID, c::ROOT, c.ca_exts, sign_with: 'some other signer')
    c.chk('link 1', c.vchain([ch[0], other1, ch[2]], [c.pin(ch[2])]), { 'ok' => false, 'reason' => 'device chain link #1 signature does not verify under its issuer' })

    # the strict profile
    crit = c.cert(c::LEAF, c::MID, c.leaf_exts + [c.crit])
    prof = c.a::Der.strict_chain_error([crit, ch[1], ch[2]].map(&:to_der))
    c.chk('profile text', prof.to_s.start_with?('certificate at depth 0 has an unrecognised critical extension'), true)
    c.chk('profile', c.vchain([crit, ch[1], ch[2]], [c.pin(ch[2])]), { 'ok' => false, 'reason' => "device chain profile: #{prof}" })
    c.chk('profile before pin', c.vchain([crit, ch[1], ch[2]], [])['reason'], "device chain profile: #{prof}")

    # root checks (single certificate chains skip the role profile)
    rn = c.cert(c::ROOT, c::ROOT, c.leaf_exts)
    c.chk('root not ca', c.vchain([rn], [c.pin(rn)]), { 'ok' => false, 'reason' => 'device chain root is not a self-signed CA' })
    rs = c.cert(c::ROOT, c::ROOT, c.ca_exts, sign_with: 'some other signer')
    c.chk('root not self-signed', c.vchain([rs], [c.pin(rs)]), { 'ok' => false, 'reason' => 'device chain root is not a self-signed CA' })
    rr = c.cert(c::ROOT, c::ROOT, c.ca_exts)
    c.chk('root only', c.vchain([rr], [c.pin(rr)])['ok'], true)
    true
  end

  t('nvidia: int_value? and pem_of_der_b64') do
    next true unless c.run?

    n = c.nv
    rows = [[1.0, true], [-2.0, true], [0.0, true], [1.5, false], [Float::NAN, false], [Float::INFINITY, false], [-Float::INFINITY, false], [1e30, true],
            [3, true], [-3, true], ['3', false], [nil, false], [true, false], [[], false]]
    rows.each { |v, want| c.chk("int_value? #{v.inspect}", n.int_value?(v), want) }
    c.chk('pem', n.pem_of_der_b64("#{'A' * 100}\n  #{'B' * 30}\t"), "-----BEGIN CERTIFICATE-----\n#{'A' * 64}\n#{'A' * 36}#{'B' * 28}\n#{'B' * 2}\n-----END CERTIFICATE-----")
    c.chk('pem 64', n.pem_of_der_b64('A' * 64), "-----BEGIN CERTIFICATE-----\n#{'A' * 64}\n-----END CERTIFICATE-----")
    true
  end
end

module MutationKill
  c = C13
  st = { dv: 'AAAA', sv: 'AAAA' }

  t('nvidia: verify_nvidia_rim accepts a signed RIM and returns the exact structure') do
    next true unless c.run?

    r = c.vrim(c.rim)
    c.chk('rim', r, { 'ok' => true, 'rim' => { 'tagId' => 'TAG1', 'product' => 'GH100', 'version' => '1.2.3',
                                               'golden' => { 0 => { 'index' => 0, 'active' => true, 'alternatives' => 1, 'size' => 2, 'hashes' => ['abcd'] } } } })
    c.chk('upcase pin', c.vrim(c.rim, [c.rim_pin[0].upcase])['ok'], true)
    c.chk('whitespace in values', c.why(c.rim(ws: true))['ok'], true)
    c.chk('absent URI is the whole document', c.vrim(c.rim(uri: ''))['ok'], true)
    c.chk('first CanonicalizationMethod only', c.vrim(c.rim(canon: %(#{C13::DEF[:canon]}<CanonicalizationMethod Algorithm="x"/>)))['ok'], true)
    c.chk('first SignatureMethod only', c.vrim(c.rim(sigm: %(#{C13::DEF[:sigm]}<SignatureMethod Algorithm="x"/>)))['ok'], true)
    c.chk('first DigestMethod only', c.vrim(c.rim(dm: %(#{C13::DEF[:dm]}<DigestMethod Algorithm="x"/>)))['ok'], true)
    tr = C13::DEF[:transforms]
    c.chk('first Transforms only', c.vrim(c.rim(transforms: %(#{tr}<Transforms><Transform Algorithm="x"/></Transforms>)))['ok'], true)
    flat = %(<Transform Algorithm="#{C13::ENVS}"/><Transform Algorithm="#{C13::C14}"/>)
    c.chk('transforms directly under Reference', c.vrim(c.rim(transforms: flat))['ok'], true)
    c.chk('second Meta ignored', c.vrim(c.rim(meta: '<Meta product="A" colloquialVersion="1"/><Meta product="B" colloquialVersion="2"/>'))['rim'].values_at('product', 'version'), %w[A 1])
    p2 = c.pay(c.res) + c.pay(c.res(index: '1'))
    c.chk('first Payload only', c.vrim(c.rim(payload: p2))['rim']['golden'].keys, [0])
    e = c.vrim(c.rim(meta: '<Meta/>', root_attrs: ''))
    c.chk('absent attributes', e['rim'].values_at('tagId', 'product', 'version'), ['', '', ''])
    true
  end

  t('nvidia: verify_nvidia_rim input and XML structure refusals carry the exact reasons') do
    next true unless c.run?

    n = c.nv
    ok = c.rim
    ['', nil, 5, 'x' * 4_000_001].each { |x| c.chk("bad doc #{x.class} #{x.to_s.length}", n.verify_nvidia_rim(x, c.rim_pin, c::NOW), { 'ok' => false, 'reason' => 'RIM: empty or oversized document' }) }
    c.chk('empty doc wins over pins', n.verify_nvidia_rim('', [], c::NOW)['reason'], 'RIM: empty or oversized document')
    c.chk('4_000_000 is not oversized', n.verify_nvidia_rim('x' * 4_000_000, c.rim_pin, c::NOW), { 'ok' => false, 'reason' => 'RIM: verification error (fail closed): text outside the root element' })
    [nil, [], 'x', {}].each { |p| c.chk("pins #{p.inspect}", n.verify_nvidia_rim(ok, p, c::NOW), { 'ok' => false, 'reason' => 'RIM: no pinned RIM root configured' }) }
    c.chk('xml error', n.verify_nvidia_rim('<a', c.rim_pin, c::NOW), { 'ok' => false, 'reason' => 'RIM: verification error (fail closed): unterminated start tag' })
    c.chk('standard error', c.a::Xml.then { |x| MutationKill::Seam.with(x, { parse_xml: ->(_t) { raise 'boom' } }) { n.verify_nvidia_rim(ok, c.rim_pin, c::NOW) } },
          { 'ok' => false, 'reason' => 'RIM: verification error (fail closed): boom' })
    c.chk('comment', c.why(c.rim(pre: '<!--x-->')), 'RIM: XML comments are not permitted')
    c.chk('pi first', c.why(c.rim(pre: '<?x?><!--y-->')), 'RIM: XML processing instructions are not permitted')
    c.chk('doctype', c.why(c.rim(pre: '<!DOCTYPE a>')), 'RIM: DTD / DOCTYPE is not permitted')
    c.chk('root', c.why(c.rim(root: 'Other')), 'RIM: root element is not SoftwareIdentity')
    one = 'RIM: expected exactly one Signature element'
    c.chk('no signature', c.why(c.rim(st.merge(sig_count: 0))), one)
    c.chk('two signatures', c.why(c.rim(st.merge(sig_count: 2))), one)
    c.chk('nested signature', c.why(c.rim(st.merge(sig_in_payload: true))), 'RIM: the Signature must be a direct child of the root')
    c.chk('no SignedInfo', c.why(c.rim(st.merge(si: ''))), 'RIM: expected exactly one SignedInfo')
    c.chk('two SignedInfo', c.why(c.rim(st.merge(si: '<SignedInfo/><SignedInfo/>'))), 'RIM: expected exactly one SignedInfo')
    bad = '<%s Algorithm="x"/>'
    good = C13::DEF
    cm = 'RIM: CanonicalizationMethod must be C14N 1.1'
    c.chk('canon wrong', c.why(c.rim(st.merge(canon: format(bad, 'CanonicalizationMethod')))), cm)
    c.chk('canon absent', c.why(c.rim(st.merge(canon: ''))), cm)
    c.chk('canon first wrong', c.why(c.rim(st.merge(canon: format(bad, 'CanonicalizationMethod') + good[:canon]))), cm)
    sm = 'RIM: SignatureMethod must be ECDSA-SHA384'
    c.chk('sigm wrong', c.why(c.rim(st.merge(sigm: format(bad, 'SignatureMethod')))), sm)
    c.chk('sigm absent', c.why(c.rim(st.merge(sigm: ''))), sm)
    c.chk('sigm first wrong', c.why(c.rim(st.merge(sigm: format(bad, 'SignatureMethod') + good[:sigm]))), sm)
    c.chk('canon checked before sigm', c.why(c.rim(st.merge(canon: '', sigm: ''))), cm)
    rf = 'RIM: expected exactly one Reference'
    c.chk('no Reference', c.why(c.rim(st.merge(si: "<SignedInfo>#{good[:canon]}#{good[:sigm]}</SignedInfo>"))), rf)
    c.chk('two References', c.why(c.rim(st.merge(ref_extra: '<Reference URI=""/>'))), rf)
    c.chk('URI', c.why(c.rim(st.merge(uri: ' URI="#x"'))), 'RIM: Reference URI must be "" (the whole document)')
    env = %(<Transform Algorithm="#{C13::ENVS}"/>)
    c14 = %(<Transform Algorithm="#{C13::C14}"/>)
    tm = 'RIM: transforms must be exactly [enveloped-signature, C14N 1.1]'
    { 'swapped' => c14 + env, 'one' => env, 'three' => env + c14 + c14, 'none' => '', 'env env' => env + env, 'c14 c14' => c14 + c14,
      'unknown first' => %(<Transform Algorithm="x"/>) + c14, 'unknown second' => env + %(<Transform Algorithm="x"/>) }.each do |label, inner|
      c.chk("transforms #{label}", c.why(c.rim(st.merge(transforms: "<Transforms>#{inner}</Transforms>"))), tm)
    end
    c.chk('transforms absent', c.why(c.rim(st.merge(transforms: ''))), tm)
    c.chk('first Transforms is the one checked', c.why(c.rim(st.merge(transforms: "<Transforms>#{c14}</Transforms>" + good[:transforms]))), tm)
    c.chk('digest method', c.why(c.rim(st.merge(dm: format(bad, 'DigestMethod')))), 'RIM: DigestMethod must be SHA-384')
    c.chk('digest method absent', c.why(c.rim(st.merge(dm: ''))), 'RIM: DigestMethod must be SHA-384')
    c.chk('digest method first wrong', c.why(c.rim(st.merge(dm: format(bad, 'DigestMethod') + good[:dm]))), 'RIM: DigestMethod must be SHA-384')
    mv = 'RIM: missing DigestValue / SignatureValue'
    [nil, '', " \n "].each do |v|
      c.chk("dv #{v.inspect}", c.why(c.rim(dv: v, sv: 'AAAA')), mv)
      c.chk("sv #{v.inspect}", c.why(c.rim(dv: 'AAAA', sv: v)), mv)
    end
    cert_xml = "<X509Certificate>#{c.b64(c.rim_certs[0].to_der)}</X509Certificate>"
    ki = 'RIM: no signer certificates in KeyInfo'
    c.chk('no KeyInfo', c.why(c.rim(st.merge(keyinfo: '<Other/>'))), ki)
    c.chk('empty KeyInfo', c.why(c.rim(st.merge(keyinfo: '<KeyInfo/>'))), ki)
    c.chk('empty X509Data', c.why(c.rim(st.merge(keyinfo: '<KeyInfo><X509Data/></KeyInfo>'))), ki)
    c.chk('X509Data without certificate', c.why(c.rim(st.merge(keyinfo: '<KeyInfo><X509Data><Other/></X509Data></KeyInfo>'))), ki)
    c.chk('first X509Data is the one read', c.why(c.rim(st.merge(keyinfo: "<KeyInfo><X509Data/><X509Data>#{cert_xml}</X509Data></KeyInfo>"))), ki)
    c.chk('first KeyInfo is the one read', c.why(c.rim(st.merge(keyinfo: "<KeyInfo/><KeyInfo><X509Data>#{cert_xml}</X509Data></KeyInfo>"))), ki)
    true
  end

  t('nvidia: verify_nvidia_rim signer chain, signature and digest refusals carry the exact reasons') do
    next true unless c.run?

    c.chk('wrong pin', c.why(c.rim, ['0' * 64]), 'RIM signer chain: chain root is not a pinned NVIDIA root')
    old = c.cert('RIM signer', 'RIM root', c.leaf_exts, na: 1_790_000_000)
    c.chk('signer expired', c.why(c.rim(certs: [old, c.rim_certs[1]])), 'RIM signer chain: device chain cert #0 is outside its validity window')
    sz = 'RIM: SignatureValue is not a 96-byte P-384 signature'
    ['AAAA', c.b64("\x01".b * 95), c.b64("\x01".b * 97)].each { |v| c.chk("sv size #{v.length}", c.why(c.rim(sv: v)), sz) }
    c.chk('sv unverifiable', c.why(c.rim(sv: c.b64("\x01".b * 96))), 'RIM: SignedInfo signature does not verify under the signer certificate')
    c.chk('digest mismatch', c.why(c.rim(dv: c.b64('x' * 48))), 'RIM: document digest does not match the signed DigestValue')
    c.chk('digest wrong form', c.why(c.rim(dv: 'AAAA')), 'RIM: document digest does not match the signed DigestValue')
    mp = 'RIM: missing Meta / Payload'
    c.chk('no Meta', c.why(c.rim(meta: '')), mp)
    c.chk('no Payload', c.why(c.rim(payload: '')), mp)
    c.chk('neither', c.why(c.rim(meta: '', payload: '')), mp)
    c.chk('Meta only inside Payload', c.why(c.rim(meta: '', payload: "<Payload>#{C13::DEF[:meta]}#{c.res}</Payload>")), mp)
    true
  end

  t('nvidia: verify_nvidia_rim reads Measurement resources strictly') do
    next true unless c.run?

    mal = 'RIM: malformed Measurement resource'
    %w[-1 abc 1.5 Infinity].each { |i| c.chk("index #{i}", c.why(c.rim(payload: c.pay(c.res(index: i)))), mal) }
    %w[0 -1 1.5 x].each { |v| c.chk("alts #{v}", c.why(c.rim(payload: c.pay(c.res(alts: v)))), mal) }
    %w[0 -1 1.5 x].each { |v| c.chk("size #{v}", c.why(c.rim(payload: c.pay(c.res(size: v)))), mal) }
    no_alts = '<Payload><Resource type="Measurement" index="0" size="2" active="true" Hash0="abcd"/></Payload>'
    no_size = '<Payload><Resource type="Measurement" index="0" alternatives="1" active="true" Hash0="abcd"/></Payload>'
    c.chk('alts absent', c.why(c.rim(payload: no_alts)), mal)
    c.chk('size absent', c.why(c.rim(payload: no_size)), mal)
    no_idx = '<Payload><Resource type="Measurement" alternatives="1" size="2" active="true" Hash0="abcd"/></Payload>'
    c.chk('index absent is 0', c.vrim(c.rim(payload: no_idx))['rim']['golden'].keys, [0])
    inc = ->(i) { "RIM: Measurement #{i} hash list is inconsistent with alternatives/size" }
    c.chk('too few hashes', c.why(c.rim(payload: c.pay(c.res(index: '7', alts: '2')))), inc.call(7))
    c.chk('too many hashes', c.why(c.rim(payload: c.pay(c.res(index: '2.0', hashes: { 'Hash0' => 'abcd', 'Hash1' => 'abcd' })))), inc.call(2))
    c.chk('non-hex hash', c.why(c.rim(payload: c.pay(c.res(index: '0x10', size: '1', hashes: { 'Hash0' => 'zz' })))), inc.call(16))
    c.chk('hash too short', c.why(c.rim(payload: c.pay(c.res(hashes: { 'Hash0' => 'abc' })))), inc.call(0))
    c.chk('hash too long', c.why(c.rim(payload: c.pay(c.res(hashes: { 'Hash0' => 'abcdef' })))), inc.call(0))
    c.chk('second hash bad', c.why(c.rim(payload: c.pay(c.res(alts: '2', hashes: { 'Hash0' => 'abcd', 'Hash1' => 'abzz' })))), inc.call(0))
    c.chk('duplicate', c.why(c.rim(payload: c.pay(c.res, c.res))), 'RIM: duplicate Measurement index 0')
    c.chk('duplicate later', c.why(c.rim(payload: c.pay(c.res(index: '1'), c.res(index: '2'), c.res(index: '1')))), 'RIM: duplicate Measurement index 1')
    nm = 'RIM: no measurements'
    c.chk('no resources', c.why(c.rim(payload: '<Payload/>')), nm)
    c.chk('other type', c.why(c.rim(payload: c.pay(c.res(type: 'Other')))), nm)
    c.chk('type case', c.why(c.rim(payload: c.pay(c.res(type: 'measurement')))), nm)
    c.chk('other element', c.why(c.rim(payload: c.pay(c.res(tag: 'Foo')))), nm)
    r = c.vrim(c.rim(payload: c.pay(c.res(type: 'Other', index: 'zzz'), c.res(tag: 'Foo', index: 'zzz'), c.res(index: '2.0', alts: '1.0', size: '2.0'))))
    g = r['rim']['golden']
    c.chk('skipped resources', g, { 2 => { 'index' => 2, 'active' => true, 'alternatives' => 1, 'size' => 2, 'hashes' => ['abcd'] } })
    c.chk('integers', [g[2]['index'].class, g[2]['alternatives'].class, g[2]['size'].class, g.keys[0].class], [Integer] * 4)
    act = ->(v) { c.vrim(c.rim(payload: c.pay(c.res(active: v))))['rim']['golden'][0]['active'] }
    c.chk('active', %w[true TRUE True false yes 1 ].map { |v| act.call(v) } << act.call(''), [true, true, true, false, false, false, false])
    sorted = c.res(alts: '3', size: '1', hashes: { 'Hash10' => 'AA', 'Hash2' => 'bb', 'Hash1' => 'cc', 'hash3' => 'zz', 'Hash' => 'zz', 'Hash0a' => 'zz', 'Other' => 'zz' })
    c.chk('hash order and case', c.vrim(c.rim(payload: c.pay(sorted)))['rim']['golden'][0]['hashes'], %w[cc bb aa])
    two = c.pay(c.res(index: '5', active: 'false'), c.res(index: '1', alts: '2', size: '1', hashes: { 'Hash0' => 'aa', 'Hash1' => 'bb' }))
    c.chk('two resources', c.vrim(c.rim(payload: two))['rim']['golden'], { 5 => { 'index' => 5, 'active' => false, 'alternatives' => 1, 'size' => 2, 'hashes' => ['abcd'] },
                                                                          1 => { 'index' => 1, 'active' => true, 'alternatives' => 2, 'size' => 1, 'hashes' => %w[aa bb] } })
    true
  end
end

module MutationKill
  c = C13

  t('nvidia: ascii and nvidia_rim_ids_for_report name the RIMs from the signed opaque data') do
    next true unless c.run?

    n = c.nv
    c.chk('ascii nil', n.ascii(nil), '')
    c.chk('ascii nul', n.ascii("ab\0\0".b), 'ab')
    c.chk('ascii leading nul kept', n.ascii("\0ab".b), "\0ab")
    c.chk('ascii trims after nul strip', n.ascii("a \0".b), 'a')
    c.chk('ascii trailing space then nul', n.ascii("a\0 ".b), "a\0")
    c.chk('ascii trim both', n.ascii("  a b  ".b), 'a b')
    c.chk('ascii latin1', [n.ascii("\xE9".b), n.ascii("\xE9".b).encoding], ["é", Encoding::UTF_8])
    c.chk('ascii frozen input', n.ascii('x'.b.freeze), 'x')
    vb = [0x00, 0x9f, 0x00, 0x96, 0x04, 0xAA, 0xBB, 0xCC].pack('C*')
    base = { 3 => "595.71.05\0\0".b, 6 => vb, 17 => "proj \0".b, 18 => 'sku1'.b, 15 => 'csku'.b }
    ids = ->(o) { n.nvidia_rim_ids_for_report({ 'opaque' => o }) }
    c.chk('ids', ids.call(base), { 'chip' => 'GH100', 'driver' => 'NV_GPU_DRIVER_GH100_595.71.05', 'vbios' => 'NV_GPU_VBIOS_PROJ_SKU1_CSKU_96009F0004',
                                    'driverVersion' => '595.71.05', 'vbiosVersion' => '96.00.9f.00.04' })
    c.chk('chip tag', ids.call(base.merge(35 => "GB100\0".b)), { 'chip' => 'GB100', 'driver' => 'NV_GPU_CC_DRIVER_GB100_595.71.05', 'vbios' => 'NV_GPU_VBIOS_PROJ_SKU1_CSKU_96009F0004',
                                                                  'driverVersion' => '595.71.05', 'vbiosVersion' => '96.00.9f.00.04' })
    c.chk('chip tag GH100', ids.call(base.merge(35 => 'GH100'.b))['driver'], 'NV_GPU_DRIVER_GH100_595.71.05')
    c.chk('lowercase fields upcased', ids.call(base.merge(17 => 'proj'.b, 18 => 'sku'.b, 15 => 'cs'.b))['vbios'], 'NV_GPU_VBIOS_PROJ_SKU_CS_96009F0004')
    %w[ABC ABCDEFGHIJKL A1B2C3].each { |ch| c.chk("chip #{ch}", ids.call(base.merge(35 => ch.b))['chip'], ch) }
    ['gb100', 'AB', 'ABCDEFGHIJKLM', '1ABC', 'AB-C', 'AB_C', '', "A\nBC", 'ABC D'].each { |ch| c.chk("chip refused #{ch.inspect}", ids.call(base.merge(35 => ch.b)), nil) }
    [3, 6, 17, 18, 15].each { |k| c.chk("missing #{k}", ids.call(base.reject { |kk, _| kk == k }), nil) }
    [3, 17, 18, 15].each do |k|
      c.chk("empty #{k}", ids.call(base.merge(k => ''.b)), nil)
      c.chk("nul only #{k}", ids.call(base.merge(k => "\0\0".b)), nil)
      c.chk("blank #{k}", ids.call(base.merge(k => '  '.b)), nil)
    end
    true
  end

  t('nvidia: compare_report_to_rims applies NVIDIA merge, alternatives and NVDEC0 rules') do
    next true unless c.run?

    n = c.nv
    g = ->(i, active, size, hashes) { { 'index' => i, 'active' => active, 'alternatives' => hashes.length, 'size' => size, 'hashes' => hashes } }
    rim = ->(*gs) { { 'golden' => gs.to_h { |x| [x['index'], x] } } }
    rep = ->(blocks, nvdec = nil) { { 'measurements' => blocks.map { |i, d| { 'index' => i, 'digest' => d } }, 'opaque' => nvdec.nil? ? {} : { 11 => nvdec } } }
    cmp = ->(r, d, v) { n.compare_report_to_rims(r, d, v) }
    ok = { 'ok' => true }
    d0 = "\x01\x02".b
    h0 = '0102'
    c.chk('match', cmp.call(rep.call([[1, d0]]), rim.call(g.call(0, true, 2, [h0])), rim.call), ok)
    c.chk('match vbios side', cmp.call(rep.call([[1, d0]]), rim.call, rim.call(g.call(0, true, 2, ['ffff', h0]))), ok)
    c.chk('both active', cmp.call(rep.call([[1, d0]]), rim.call(g.call(0, true, 2, [h0])), rim.call(g.call(0, true, 2, [h0]))),
          { 'ok' => false, 'reason' => 'driver and VBIOS RIMs both have an active measurement at index 0' })
    c.chk('same index, one inactive', cmp.call(rep.call([[1, d0]]), rim.call(g.call(0, true, 2, [h0])), rim.call(g.call(0, false, 2, ['ffff']))), ok)
    c.chk('inactive driver does not block', cmp.call(rep.call([[1, d0]]), rim.call(g.call(0, false, 2, ['ffff'])), rim.call(g.call(0, true, 2, [h0]))), ok)
    c.chk('no active', cmp.call(rep.call([[1, d0]]), rim.call(g.call(0, false, 2, [h0])), rim.call), { 'ok' => false, 'reason' => 'RIMs carry no active golden measurements' })
    c.chk('more than the report', cmp.call(rep.call([[1, d0]]), rim.call(g.call(0, true, 2, [h0]), g.call(1, true, 2, [h0])), rim.call),
          { 'ok' => false, 'reason' => 'RIMs list more active measurements than the report carries' })
    c.chk('as many as the report', cmp.call(rep.call([[1, d0], [2, d0]]), rim.call(g.call(0, true, 2, [h0]), g.call(1, true, 2, [h0])), rim.call), ok)
    mm = ->(k) { { 'ok' => false, 'reason' => "runtime measurements differ from the golden RIM values at #{k} index(es)" } }
    c.chk('digest differs', cmp.call(rep.call([[1, "\x01\x03".b]]), rim.call(g.call(0, true, 2, [h0])), rim.call), mm.call(1))
    c.chk('size differs', cmp.call(rep.call([[1, d0]]), rim.call(g.call(0, true, 3, ['010200'])), rim.call), mm.call(1))
    c.chk('size differs but hash present', cmp.call(rep.call([[1, d0]]), rim.call(g.call(0, true, 3, [h0])), rim.call), mm.call(1))
    c.chk('absent index counts', cmp.call(rep.call([[2, d0]]), rim.call(g.call(0, true, 2, [h0])), rim.call), mm.call(1))
    c.chk('two mismatches', cmp.call(rep.call([[1, d0], [2, d0], [3, d0]]), rim.call(g.call(0, true, 2, ['aaaa']), g.call(1, true, 2, [h0]), g.call(2, true, 2, ['bbbb'])), rim.call), mm.call(2))
    c.chk('alternative', cmp.call(rep.call([[1, d0]]), rim.call(g.call(0, true, 2, ['aaaa', h0])), rim.call), ok)
    # NVDEC0: report block 35 is runtime index 34
    wrong = 'ffff'
    nv = ->(byte, idx) { cmp.call(rep.call([[idx + 1, d0]], byte), rim.call(g.call(idx, true, 2, [wrong])), rim.call) }
    c.chk('nvdec disabled skips block 35', nv.call("\x55".b, 34), ok)
    c.chk('nvdec disabled, other block', nv.call("\x55".b, 33), mm.call(1))
    c.chk('nvdec disabled, other block 2', nv.call("\x55".b, 35), mm.call(1))
    c.chk('nvdec disabled, first block', nv.call("\x55".b, 0), mm.call(1))
    c.chk('nvdec 0x54 is not disabled', nv.call("\x54".b, 34), mm.call(1))
    c.chk('nvdec 0x56 is not disabled', nv.call("\x56".b, 34), mm.call(1))
    c.chk('nvdec 0 is not disabled', nv.call("\x00".b, 34), mm.call(1))
    c.chk('nvdec absent', nv.call(nil, 34), mm.call(1))
    c.chk('nvdec empty', nv.call(''.b, 34), mm.call(1))
    c.chk('nvdec only the first byte', nv.call("\x00\x55".b, 34), mm.call(1))
    c.chk('nvdec first byte then more', nv.call("\x55\x00".b, 34), ok)
    true
  end

  t('nvidia: check_nvidia_chain_revocation verifies CRLs under the chain and refuses revoked links') do
    next true unless c.run?

    n = c.nv
    lc = c.chain3.map { |x| c.lib_cert(x) }
    now = c::NOW
    leaf_s = c.serial(c::LEAF)
    mid_s = c.serial(c::MID)
    root_s = c.serial(c::ROOT)
    chk = ->(crls, req = :omit) { req == :omit ? n.check_nvidia_chain_revocation(lc, crls, now) : n.check_nvidia_chain_revocation(lc, crls, now, req) }
    c.chk('none', chk.call([]), { 'ok' => false, 'reason' => 'no CRLs supplied' })
    c.chk('ok one', chk.call([c.crl(c::MID)]), { 'ok' => true, 'verifiedCrls' => 1 })
    c.chk('ok two', chk.call([c.crl(c::MID), c.crl(c::ROOT)]), { 'ok' => true, 'verifiedCrls' => 2 })
    rv = ->(i) { { 'ok' => false, 'reason' => "chain certificate '#{lc[i].subject.gsub("\n", ', ')}' is revoked" } }
    c.chk('leaf revoked by mid', chk.call([c.crl(c::MID, revoked: [leaf_s])]), rv.call(0))
    c.chk('mid revoked by root', chk.call([c.crl(c::ROOT, revoked: [mid_s])]), rv.call(1))
    c.chk('second crl revokes', chk.call([c.crl(c::MID), c.crl(c::ROOT, revoked: [mid_s])]), rv.call(1))
    c.chk('leaf listed by root is not an issuer link', chk.call([c.crl(c::ROOT, revoked: [leaf_s])]), { 'ok' => true, 'verifiedCrls' => 1 })
    c.chk('mid listed by itself', chk.call([c.crl(c::MID, revoked: [mid_s, root_s])]), { 'ok' => true, 'verifiedCrls' => 1 })
    c.chk('root listed by itself', chk.call([c.crl(c::ROOT, revoked: [root_s])]), { 'ok' => true, 'verifiedCrls' => 1 })
    c.chk('unrelated serial', chk.call([c.crl(c::MID, revoked: [leaf_s + 1000])]), { 'ok' => true, 'verifiedCrls' => 1 })
    c.chk('leaf-signed crl lists nothing relevant', chk.call([c.crl(c::LEAF, revoked: [leaf_s])]), { 'ok' => true, 'verifiedCrls' => 1 })
    c.chk('stranger', chk.call([c.crl(c::MID, signer: 'stranger')]), { 'ok' => false, 'reason' => 'CRL #0 rejected: CRL signature does not verify under the issuer' })
    c.chk('stranger second', chk.call([c.crl(c::MID), c.crl(c::MID, signer: 'stranger')]), { 'ok' => false, 'reason' => 'CRL #1 rejected: CRL signature does not verify under the issuer' })
    stale = { 'ok' => false, 'reason' => 'CRL #0 rejected: CRL is stale (nextUpdate passed)' }
    c.chk('stale by mid', chk.call([c.crl(c::MID, nxt: 1_790_000_000)]), stale)
    c.chk('stale by root', chk.call([c.crl(c::ROOT, nxt: 1_790_000_000)]), stale)
    c.chk('stale by leaf', chk.call([c.crl(c::LEAF, nxt: 1_790_000_000)]), stale)
    c.chk('future by mid', chk.call([c.crl(c::MID, this: 1_810_000_000, nxt: 1_820_000_000)]), { 'ok' => false, 'reason' => 'CRL #0 rejected: CRL thisUpdate is in the future' })
    parse = lc[0].then { |l| c.a::Intel.verify_crl('junk'.b, l.public_key, now)['reason'] }
    c.chk('parse reason text', parse.start_with?('CRL parse failed: '), true)
    c.chk('junk', chk.call(['junk'.b]), { 'ok' => false, 'reason' => "CRL #0 rejected: #{parse}" })
    none = MutationKill::Seam.with(c.a::Intel, { verify_crl: ->(_c, _k, _n) { { 'ok' => true, 'revoked' => nil } } }) { n.check_nvidia_chain_revocation(lc, ['x'], now) }
    c.chk('ok without a revoked set is refused', none, { 'ok' => false, 'reason' => 'CRL #0 rejected: no chain certificate verifies it' })
    ok1 = [c.crl(c::MID)]
    c.chk('required issuer present', chk.call(ok1, ['Mid']), { 'ok' => true, 'verifiedCrls' => 1 })
    c.chk('required nil', chk.call(ok1, nil), { 'ok' => true, 'verifiedCrls' => 1 })
    c.chk('required empty', chk.call(ok1, []), { 'ok' => true, 'verifiedCrls' => 1 })
    c.chk('required issuer absent', chk.call(ok1, ['Root']), { 'ok' => false, 'reason' => "no verified CRL issued by a certificate matching 'Root'" })
    c.chk('required second absent', chk.call(ok1, %w[Mid Nobody]), { 'ok' => false, 'reason' => "no verified CRL issued by a certificate matching 'Nobody'" })
    c.chk('required both', chk.call([c.crl(c::MID), c.crl(c::ROOT)], %w[Mid Root]), { 'ok' => true, 'verifiedCrls' => 2 })
    true
  end

  t('nvidia: parse_version, cmp_version and the firmware policy') do
    next true unless c.run?

    n = c.nv
    pv = n.method(:parse_version)
    rows = [['1.2.3', 10, [1, 2, 3]], ['0', 10, [0]], ['595.71.05', 10, [595, 71, 5]], ['1.', 10, nil], ['', 10, nil], ['1..2', 10, nil], ['.1', 10, nil],
            [nil, 10, nil], [5, 10, nil], ['a', 10, nil], ['1a', 10, nil], ['x1', 10, nil], [' 1', 10, nil], ["1\n", 10, nil], ["1\n2", 10, nil], ['1 2', 10, nil],
            ['ab.0F', 16, [171, 15]], ['abcd', 16, [43_981]], ['abcde', 16, nil], ['g', 16, nil], ['1.', 16, nil], ['', 16, nil], ['96.00.9f.00.04', 16, [0x96, 0, 0x9f, 0, 4]],
            [['1'], 10, nil], ['1.abcde', 16, nil], ['1.2.3', 16, [1, 2, 3]], ['12345678', 10, [12_345_678]], ["a\n", 16, nil], ["\n1", 10, nil]]
    rows.each { |v, r, want| c.chk("parse_version #{v.inspect}/#{r}", pv.call(v, r), want) }
    cv = n.method(:cmp_version)
    [[[1, 2], [1, 2, 0], 0], [[1], [1, 0, 1], -1], [[2], [1, 9, 9], 1], [[], [], 0], [[1, 2, 3], [1, 2], 1], [[1, 2], [1, 2, 3], -1], [[0, 9], [1], -1],
     [[1, 9], [1, 10], -1], [[1, 10], [1, 9], 1], [[5], [5], 0]].each { |x, y, want| c.chk("cmp #{x}/#{y}", cv.call(x, y), want) }

    pol = ->(fw) { n.compile_firmware_policy(fw) }
    ids = ->(d, v) { { 'driverVersion' => d, 'vbiosVersion' => v } }
    [nil, false].each do |fw|
      f = pol.call(fw)
      c.chk("no policy #{fw.inspect}", [f.call(ids.call('x', 'y')), f.call(ids.call('1', '1'))], [nil, nil])
    end
    f = pol.call({})
    c.chk('empty policy parses', [f.call(ids.call('1.2', 'ab.cd')), f.call(ids.call('x', 'ab')), f.call(ids.call('1', 'zz')), f.call(ids.call('x', 'zz'))],
          [nil, "driver version 'x' in the GPU report is not parseable", "VBIOS version 'zz' in the GPU report is not parseable", "driver version 'x' in the GPU report is not parseable"])
    c.chk('nil versions', [f.call(ids.call(nil, '1')), f.call(ids.call('1', nil))], ["driver version '' in the GPU report is not parseable", "VBIOS version '' in the GPU report is not parseable"])
    mn = pol.call({ 'minDriverVersion' => '595.71.05', 'minVbiosVersion' => '96.00.9f.00.04' })
    c.chk('min driver', [mn.call(ids.call('595.71.05', '96.00.9f.00.04')), mn.call(ids.call('595.71.06', '96.00.9f.00.04')), mn.call(ids.call('600', '96.00.9f.00.04')), mn.call(ids.call('595.71.5', '96.00.9f.00.04'))],
          [nil, nil, nil, nil])
    c.chk('below min driver', mn.call(ids.call('595.71.04', '96.00.9f.00.04')), 'driver 595.71.04 is below the minimum 595.71.05')
    c.chk('below min driver shorter', mn.call(ids.call('595.71', '96.00.9f.00.04')), 'driver 595.71 is below the minimum 595.71.05')
    c.chk('below min vbios', mn.call(ids.call('595.71.05', '96.00.9f.00.03')), 'VBIOS 96.00.9f.00.03 is below the minimum 96.00.9f.00.04')
    c.chk('vbios hex compare', mn.call(ids.call('595.71.05', '96.00.a0.00.00')), nil)
    c.chk('driver checked before vbios', mn.call(ids.call('1', '1')), 'driver 1 is below the minimum 595.71.05')
    c.chk('unparseable before min', mn.call(ids.call('x', '1')), "driver version 'x' in the GPU report is not parseable")
    dn = pol.call({ 'denyDriverVersions' => ['595.71.05', '1.0'], 'denyVbiosVersions' => ['96.00.9f.00.04', 'ff'] })
    c.chk('deny driver', dn.call(ids.call('595.71.05', '1')), 'driver 595.71.05 is on the deny list')
    c.chk('deny driver trailing zero', dn.call(ids.call('1.0.0', '1')), 'driver 1.0.0 is on the deny list')
    c.chk('deny driver second entry', dn.call(ids.call('1', '1')), 'driver 1 is on the deny list')
    c.chk('deny vbios', dn.call(ids.call('2', '96.00.9f.00.04')), 'VBIOS 96.00.9f.00.04 is on the deny list')
    c.chk('deny vbios second entry', dn.call(ids.call('2', 'FF')), 'VBIOS FF is on the deny list')
    c.chk('not denied', dn.call(ids.call('2', '3')), nil)
    c.chk('deny driver before vbios', dn.call(ids.call('595.71.05', 'ff')), 'driver 595.71.05 is on the deny list')
    c.chk('min before deny', pol.call({ 'minDriverVersion' => '9', 'denyDriverVersions' => ['1'] }).call(ids.call('1', '1')), 'driver 1 is below the minimum 9')
    c.chk('min vbios before deny driver', pol.call({ 'minVbiosVersion' => 'ff', 'denyDriverVersions' => ['1'] }).call(ids.call('1', '1')), 'VBIOS 1 is below the minimum ff')
    c.chk('empty-string minimums are none', pol.call({ 'minDriverVersion' => '', 'minVbiosVersion' => '' }).call(ids.call('0', '0')), nil)
    c.chk('minimum only vbios', pol.call({ 'minVbiosVersion' => '10' }).call(ids.call('0', '9')), 'VBIOS 9 is below the minimum 10')
    c.chk('minimum only driver', pol.call({ 'minDriverVersion' => '10' }).call(ids.call('9', '0')), 'driver 9 is below the minimum 10')
    c.chk('nil minimums', pol.call({ 'minDriverVersion' => nil, 'minVbiosVersion' => nil, 'denyDriverVersions' => nil, 'denyVbiosVersions' => nil }).call(ids.call('0', '0')), nil)
    ce = ->(fw) { c.err_of { pol.call(fw) } }
    c.chk('malformed min driver', ce.call({ 'minDriverVersion' => 'x' }), ['AtlasPca::Attest::AttestConstructError', "nvidiaCollateralHook: malformed minDriverVersion 'x'"])
    c.chk('malformed min vbios', ce.call({ 'minVbiosVersion' => 'xyz' }), ['AtlasPca::Attest::AttestConstructError', "nvidiaCollateralHook: malformed minVbiosVersion 'xyz'"])
    c.chk('min driver is decimal', ce.call({ 'minDriverVersion' => 'ab' })[1], "nvidiaCollateralHook: malformed minDriverVersion 'ab'")
    c.chk('min vbios is hex', ce.call({ 'minVbiosVersion' => 'ab' }), nil)
    c.chk('malformed deny driver', ce.call({ 'denyDriverVersions' => ['1', 'q'] }), ['AtlasPca::Attest::AttestConstructError', "nvidiaCollateralHook: malformed denyDriverVersions entry 'q'"])
    c.chk('malformed deny vbios', ce.call({ 'denyVbiosVersions' => ['1', 'q'] }), ['AtlasPca::Attest::AttestConstructError', "nvidiaCollateralHook: malformed denyVbiosVersions entry 'q'"])
    c.chk('malformed nil entry', ce.call({ 'denyDriverVersions' => [nil] }), ['AtlasPca::Attest::AttestConstructError', "nvidiaCollateralHook: malformed denyDriverVersions entry 'undefined'"])
    c.chk('malformed float', ce.call({ 'minDriverVersion' => 1.0 }), ['AtlasPca::Attest::AttestConstructError', "nvidiaCollateralHook: malformed minDriverVersion '1'"])
    c.chk('malformed non-string', ce.call({ 'minDriverVersion' => 5 }), ['AtlasPca::Attest::AttestConstructError', "nvidiaCollateralHook: malformed minDriverVersion '5'"])
    true
  end
end

module MutationKill
  c = C13
  hook_leaf = Struct.new(:subject)
  hook_pins = ['pin1'].freeze
  ids0 = { 'chip' => 'GH100', 'driver' => 'D', 'vbios' => 'V', 'driverVersion' => '595.71.05', 'vbiosVersion' => '96.00.9f.00.04' }.freeze
  okd = { 'ok' => true, 'rim' => { 'product' => 'GH100', 'version' => '595.71.05', 'golden' => { d: 1 } } }.freeze
  okv = { 'ok' => true, 'rim' => { 'product' => 'GH100', 'version' => '96.00.9F.00.04', 'golden' => { v: 1 } } }.freeze
  bundle0 = { 'driverRimXml' => 'DX', 'vbiosRimXml' => 'VX' }.freeze
  run_hook = lambda do |opts = {}, ctx: {}, ids: ids0, d: okd, v: okv, cmp: { 'ok' => true }, crl: { 'ok' => true }, ocsp: { 'ok' => true }, bundle: bundle0|
    calls = []
    hopts = { 'rimRootSpkiSha256' => hook_pins, 'resolve' => ->(i, e) { calls << [:resolve, i, e]; bundle } }.merge(opts)
    n = c.nv
    stubs = { nvidia_rim_ids_for_report: ->(r) { calls << [:ids, r]; ids },
              verify_nvidia_rim: ->(x, p, t) { calls << [:rim, x, p, t]; x == 'DX' ? d : v },
              compare_report_to_rims: ->(r, dr, vr) { calls << [:cmp, r, dr, vr]; cmp },
              check_nvidia_chain_revocation: ->(ch, cr, now, req, rf) { calls << [:crl, ch, cr, now, req, rf]; crl } }
    res = Seam.with(n, stubs) do
      Seam.with(c.a::Ocsp, { check_nvidia_chain_ocsp: ->(ch, o, now) { calls << [:ocsp, ch, o, now]; ocsp } }) do
        h = c.a::NvidiaCollateralHook.new(hopts)
        h.call({ 'report' => :rep, 'leaf' => hook_leaf.new('CN=NVIDIA GH100 Device'), 'chain' => :chain, 'nowMs' => C13::NOW, 'evidence' => :ev }.merge(ctx))
      end
    end
    [res, calls]
  end

  t('nvidia: NvidiaCollateralHook construction and report naming') do
    next true unless c.run?

    [nil, [], 'x', {}].each do |p|
      c.chk("pins #{p.inspect}", c.err_of { c.a::NvidiaCollateralHook.new({ 'rimRootSpkiSha256' => p }) },
            ['AtlasPca::Attest::AttestConstructError', 'nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root'])
    end
    c.chk('no opts pins', c.err_of { c.a::NvidiaCollateralHook.new({}) }&.last, 'nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root')
    c.chk('constructs', c.a::NvidiaCollateralHook.new({ 'rimRootSpkiSha256' => ['p'] }).class.name, 'AtlasPca::Attest::NvidiaCollateralHook')
    c.chk('bad firmware at construction', c.err_of { c.a::NvidiaCollateralHook.new({ 'rimRootSpkiSha256' => ['p'], 'firmware' => { 'minDriverVersion' => 'x' } }) },
          ['AtlasPca::Attest::AttestConstructError', "nvidiaCollateralHook: malformed minDriverVersion 'x'"])
    r, calls = run_hook.call(ids: nil)
    c.chk('no ids', [r, calls], ['GPU report does not carry the opaque fields needed to name its RIMs', [[:ids, :rep]]])
    true
  end

  t('nvidia: NvidiaCollateralHook binds the chip family through the leaf subject') do
    next true unless c.run?

    mism = ->(subj, chip = 'GH100') { "device leaf subject '#{subj.gsub("\n", ', ')}' is not a #{chip} device certificate (chip family mismatch)" }
    ['CN=NVIDIA GH100 Device', 'GH100', 'CN=GH100', 'GH100 dev', 'dev GH100', "O=x\nGH100 y\nC=US", "CN=a-GH100-b"].each do |s|
      c.chk("subject #{s.inspect}", run_hook.call(ctx: { 'leaf' => hook_leaf.new(s) })[0], nil)
    end
    ['CN=xGH100', 'CN=GH100x', 'CN=GH1000', 'CN=0GH100', 'CN=GH10', 'CN=gh100', '', "O=a\nCN=x"].each do |s|
      c.chk("mismatch #{s.inspect}", run_hook.call(ctx: { 'leaf' => hook_leaf.new(s) })[0], mism.call(s))
    end
    other = ids0.merge('chip' => 'G.1')
    c.chk('chip dot escaped', run_hook.call(ids: other, ctx: { 'leaf' => hook_leaf.new('CN=GX1') })[0], mism.call('CN=GX1', 'G.1'))
    c.chk('chip dot literal passes the subject check', run_hook.call(ids: other, ctx: { 'leaf' => hook_leaf.new('CN=G.1') })[0].to_s.start_with?('device leaf subject'), false)
    c.chk('chip meta', run_hook.call(ids: ids0.merge('chip' => 'A|B'), ctx: { 'leaf' => hook_leaf.new('CN=A') })[0], mism.call('CN=A', 'A|B'))
    # a mismatch stops before the firmware policy and the resolver
    c.chk('stops early', run_hook.call(ctx: { 'leaf' => hook_leaf.new('x') })[1].map(&:first), [:ids])
    true
  end

  t('nvidia: NvidiaCollateralHook firmware policy, resolver and RIM verification') do
    next true unless c.run?

    r, calls = run_hook.call({ 'firmware' => { 'minDriverVersion' => '600' } })
    c.chk('firmware', [r, calls.map(&:first)], ['firmware policy: driver 595.71.05 is below the minimum 600', [:ids]])
    h = ->(fw_result) { ->(_ids) { fw_result } }
    # an empty reason is no reason
    k = c.a::NvidiaCollateralHook.new({ 'rimRootSpkiSha256' => hook_pins, 'resolve' => ->(*) { nil } })
    k.instance_variable_set(:@firmware, h.call(''))
    c.chk('empty firmware reason continues', Seam.with(c.nv, { nvidia_rim_ids_for_report: ->(_r) { ids0 } }) { k.call({ 'report' => 1, 'leaf' => hook_leaf.new('GH100'), 'chain' => 1, 'nowMs' => 1, 'evidence' => 1 }) },
          'no RIM collateral supplied for this report')
    c.chk('nil firmware reason continues', run_hook.call({ 'firmware' => { 'minDriverVersion' => '595' } })[0], nil)

    r, calls = run_hook.call(bundle: nil)
    c.chk('no bundle', [r, calls], ['no RIM collateral supplied for this report', [[:ids, :rep], [:resolve, ids0, :ev]]])
    r, calls = run_hook.call
    c.chk('rim calls', calls.select { |x| x[0] == :rim }, [[:rim, 'DX', hook_pins, C13::NOW], [:rim, 'VX', hook_pins, C13::NOW]])
    c.chk('rim pins identity', calls.find { |x| x[0] == :rim }[2].equal?(hook_pins), true)
    c.chk('success is nil', r, nil)
    r, calls = run_hook.call(d: { 'ok' => false, 'reason' => 'bad d' })
    c.chk('driver rim fails', [r, calls.count { |x| x[0] == :rim }], ['driver RIM: bad d', 2])
    c.chk('vbios rim fails', run_hook.call(v: { 'ok' => false, 'reason' => 'bad v' })[0], 'VBIOS RIM: bad v')
    c.chk('driver first', run_hook.call(d: { 'ok' => false, 'reason' => 'bad d' }, v: { 'ok' => false, 'reason' => 'bad v' })[0], 'driver RIM: bad d')
    with = ->(rim, key, val) { { 'ok' => true, 'rim' => rim['rim'].merge(key => val) } }
    c.chk('driver product', run_hook.call(d: with.call(okd, 'product', 'GB100'))[0], "driver RIM product 'GB100' does not match the GPU chip 'GH100' (wrong-family manifest)")
    c.chk('vbios product', run_hook.call(v: with.call(okv, 'product', 'GB100'))[0], "VBIOS RIM product 'GB100' does not match the GPU chip 'GH100' (wrong-family manifest)")
    c.chk('driver product first', run_hook.call(d: with.call(okd, 'product', 'X'), v: with.call(okv, 'product', 'Y'))[0], "driver RIM product 'X' does not match the GPU chip 'GH100' (wrong-family manifest)")
    c.chk('driver version', run_hook.call(d: with.call(okd, 'version', '1.0'))[0], "driver RIM version '1.0' does not match the report's driver '595.71.05'")
    c.chk('driver version case', run_hook.call(ids: ids0.merge('driverVersion' => 'a1'), d: with.call(okd, 'version', 'A1'))[0], "driver RIM version 'A1' does not match the report's driver 'a1'")
    c.chk('vbios version', run_hook.call(v: with.call(okv, 'version', '1.2'))[0], "VBIOS RIM version '1.2' does not match the report's VBIOS '96.00.9f.00.04'")
    c.chk('vbios version dots and case', %w[96009f0004 96.00.9F.00.04 96.00.9f.00.04].map { |x| run_hook.call(v: with.call(okv, 'version', x))[0] }, [nil, nil, nil])
    c.chk('product before version', run_hook.call(d: with.call(with.call(okd, 'product', 'X'), 'version', '1'))[0], "driver RIM product 'X' does not match the GPU chip 'GH100' (wrong-family manifest)")
    c.chk('driver version before vbios product', run_hook.call(d: with.call(okd, 'version', '1'), v: with.call(okv, 'product', 'Y'))[0],
          "VBIOS RIM product 'Y' does not match the GPU chip 'GH100' (wrong-family manifest)")
    r, calls = run_hook.call(cmp: { 'ok' => false, 'reason' => 'R' })
    c.chk('compare reason', r, 'R')
    cm = calls.find { |x| x[0] == :cmp }
    c.chk('compare args', [cm[1], cm[2], cm[3]], [:rep, okd['rim'], okv['rim']])
    true
  end

  t('nvidia: NvidiaCollateralHook revocation modes') do
    next true unless c.run?

    rows = [
      [{}, {}, true, false], [{ 'requireCrls' => false }, {}, false, false], [{ 'requireCrls' => false }, { 'crls' => ['c'] }, true, false],
      [{ 'requireCrls' => false }, { 'ocsp' => ['o'] }, false, true], [{ 'requireCrls' => true }, {}, true, false], [{ 'requireCrls' => nil }, {}, true, false],
      [{ 'revocation' => 'ocsp' }, {}, false, true], [{ 'revocation' => 'both' }, {}, true, true], [{ 'revocation' => 'crl', 'requireCrls' => false }, {}, true, false],
      [{ 'revocation' => 'none' }, {}, false, false], [{ 'revocation' => 'none' }, { 'crls' => ['c'] }, true, false], [{ 'revocation' => 'none' }, { 'ocsp' => ['o'] }, false, true],
      [{ 'revocation' => 'ocsp' }, { 'crls' => ['c'] }, true, true], [{ 'revocation' => 'ocsp', 'requireCrls' => false }, {}, false, true],
      [{ 'revocation' => 'crl' }, { 'ocsp' => ['o'] }, true, true], [{ 'revocation' => 'both' }, { 'crls' => [], 'ocsp' => [] }, true, true]
    ]
    rows.each do |opts, extra, want_crl, want_ocsp|
      r, calls = run_hook.call(opts, bundle: bundle0.merge(extra))
      got = [calls.any? { |x| x[0] == :crl }, calls.any? { |x| x[0] == :ocsp }]
      c.chk("modes #{opts} #{extra}", [r, got], [nil, [want_crl, want_ocsp]])
    end
    r, calls = run_hook.call({ 'requireCrlIssuers' => ['X'] }, bundle: bundle0.merge('crls' => ['c1']))
    c.chk('crl args', calls.find { |x| x[0] == :crl }, [:crl, :chain, ['c1'], C13::NOW, ['X'], 'cdp'])
    c.chk('crl args default', run_hook.call[1].find { |x| x[0] == :crl }, [:crl, :chain, [], C13::NOW, nil, 'cdp'])
    c.chk('ocsp args', run_hook.call({ 'revocation' => 'ocsp' }, bundle: bundle0.merge('ocsp' => ['o1']))[1].find { |x| x[0] == :ocsp }, [:ocsp, :chain, ['o1'], C13::NOW])
    c.chk('ocsp args default', run_hook.call({ 'revocation' => 'ocsp' })[1].find { |x| x[0] == :ocsp }, [:ocsp, :chain, [], C13::NOW])
    r, calls = run_hook.call({ 'revocation' => 'both' }, crl: { 'ok' => false, 'reason' => 'bad crl' })
    c.chk('crl refusal', [r, calls.any? { |x| x[0] == :ocsp }], ['revocation: bad crl', false])
    c.chk('ocsp refusal', run_hook.call({ 'revocation' => 'both' }, ocsp: { 'ok' => false, 'reason' => 'bad ocsp' })[0], 'revocation (OCSP): bad ocsp')
    c.chk('compare before revocation', run_hook.call({ 'revocation' => 'both' }, cmp: { 'ok' => false, 'reason' => 'R' }, crl: { 'ok' => false, 'reason' => 'x' })[0], 'R')
    true
  end
end

module MutationKill
  c = C13
  d1 = "\xA1".b * 48
  d2 = "\xB2".b * 32
  vb = [0x00, 0x9f, 0x00, 0x96, 0x04, 0xAA, 0xBB, 0xCC].pack('C*')
  bind = { 'holder_pub' => 'h', 'grant_ref' => 'g', 'epoch' => 1, 'nonce' => 'n' }.freeze
  hex = ->(d) { d.unpack1('H*') }
  evid = lambda do |blocks: [[1, d1], [2, d2]], opaque: { 3 => "595.71.05\0".b, 6 => vb }, rq: 0x11, rs: 0x11, nonce: nil, flip: false, signer: C13::LEAF|
    nonce ||= c.a::Common.attestation_challenge_sha256(bind)
    t0 = c.tx(blocks: blocks.map { |i, d| c.block(i, d) }, opaque: opaque, rq: rq, rs: rs, nonce: nonce)
    signed = t0.byteslice(0, t0.bytesize - 96)
    sig = c.raw_sig(c.key(signer), signed)
    sig = sig.dup.tap { |s| s.setbyte(0, s.getbyte(0) ^ 1) } if flip
    signed + sig
  end
  mk = lambda do |o = {}, evidence: nil, resolve: nil, chain: c.chain3|
    ev = { 'evidence' => evidence || evid.call, 'certChainPem' => c.pem(chain) }
    opts = { 'rootSpkiSha256' => [c.pin(c.chain3[2])], 'policy' => { 'measurements' => { '1' => hex.call(d1) } }, 'resolve_evidence' => resolve || ->(_doc) { ev } }.merge(o)
    [c.a::NvidiaSpdmVerifier.new(opts), ev]
  end
  ver = ->(v, exp = bind) { v.verify('doc', exp, C13::NOW) }
  fail_r = ->(r) { { 'ok' => false, 'reason' => r } }

  t('nvidia: NvidiaSpdmVerifier construction refuses accept-all configurations and bad indices') do
    next true unless c.run?

    ne = ->(o) { c.err_of { c.a::NvidiaSpdmVerifier.new(o) } }
    cls = 'AtlasPca::Attest::AttestConstructError'
    pin_msg = 'createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)'
    [nil, [], 'x', {}].each { |p| c.chk("pins #{p.inspect}", ne.call({ 'rootSpkiSha256' => p, 'policy' => { 'measurements' => { '1' => 'aa' } } }), [cls, pin_msg]) }
    meas_msg = 'createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)'
    [nil, 'x', [], 5, {}, { 'measurements' => {} }, { 'measurements' => [] }, { 'measurements' => 'x' }, { 'measurements' => nil }].each do |pol|
      c.chk("policy #{pol.inspect}", ne.call({ 'rootSpkiSha256' => ['p'], 'policy' => pol }), [cls, meas_msg])
    end
    c.chk('no policy key', ne.call({ 'rootSpkiSha256' => ['p'] }), [cls, meas_msg])
    c.chk('post verify stands in', ne.call({ 'rootSpkiSha256' => ['p'], 'postVerify' => ->(_x) {} }), nil)
    c.chk('post verify with non-hash policy', ne.call({ 'rootSpkiSha256' => ['p'], 'policy' => 'x', 'postVerify' => ->(_x) {} }), nil)
    rng = 'createNvidiaSpdmVerifier: measurement index out of range'
    ['256', '-1', '1.5', 'abc', 256, -1, '1e3', 'Infinity', '300'].each do |k|
      c.chk("index #{k.inspect}", ne.call({ 'rootSpkiSha256' => ['p'], 'policy' => { 'measurements' => { k => 'aa' } } }), [cls, rng])
    end
    c.chk('symbol key is not a JSON index', ne.call({ 'rootSpkiSha256' => ['p'], 'policy' => { 'measurements' => { a: 'aa' } } })&.first, 'NoMethodError')
    c.chk('index range check applies to later entries', ne.call({ 'rootSpkiSha256' => ['p'], 'policy' => { 'measurements' => { '1' => 'aa', '256' => 'bb' } } }), [cls, rng])
    ['0', '255', 0, 255, '0x10', ' 7 ', 3.0].each do |k|
      c.chk("index ok #{k.inspect}", ne.call({ 'rootSpkiSha256' => ['p'], 'policy' => { 'measurements' => { k => 'aa' } } }), nil)
    end
    true
  end

  t('nvidia: NvidiaSpdmVerifier accepts a bound report and returns the exact hostAsserted block') do
    next true unless c.run?

    ch = c.chain3
    subj = c.lib_cert(ch[0]).subject.gsub("\n", ', ')
    meas = { 'ok' => true, 'bound' => true, 'measured' => { 'model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => '', 'operator' => '' } }
    host = { 'attestation_type' => 'nvidia-gpu-cc', 'gpu_measurements_sha384' => Digest::SHA384.hexdigest(d1 + d2), 'leaf_subject' => subj, 'driver_version' => '595.71.05', 'vbios_version' => '96.00.9f.00.04' }
    v, = mk.call
    c.chk('accept', ver.call(v), meas.merge('hostAsserted' => host))
    v, = mk.call({}, evidence: evid.call(blocks: [[2, d2], [1, d1]]))
    c.chk('blocks sorted by index', ver.call(v)['hostAsserted']['gpu_measurements_sha384'], host['gpu_measurements_sha384'])
    v, = mk.call({}, evidence: evid.call(blocks: [[10, d2], [9, d1], [1, d1]]))
    c.chk('numeric index order', ver.call(v)['hostAsserted']['gpu_measurements_sha384'], Digest::SHA384.hexdigest(d1 + d1 + d2))
    v, = mk.call({}, evidence: evid.call(opaque: { 3 => "5\xFF9\0\0".b, 6 => vb }))
    c.chk('driver scrub', ver.call(v)['hostAsserted']['driver_version'], "5�9")
    v, = mk.call({}, evidence: evid.call(opaque: { 17 => 'x'.b }))
    c.chk('no versions', ver.call(v)['hostAsserted'].keys, %w[attestation_type gpu_measurements_sha384 leaf_subject])
    v, = mk.call({}, evidence: evid.call(opaque: { 3 => '1'.b }))
    c.chk('driver only', ver.call(v)['hostAsserted'].keys, %w[attestation_type gpu_measurements_sha384 leaf_subject driver_version])
    v, = mk.call({}, evidence: evid.call(opaque: { 6 => vb }))
    c.chk('vbios only', ver.call(v)['hostAsserted'].keys, %w[attestation_type gpu_measurements_sha384 leaf_subject vbios_version])
    v, = mk.call({ 'policy' => { 'measurements' => { '1' => hex.call(d1).upcase, 2 => hex.call(d2) } } })
    c.chk('upcase pins and integer index', ver.call(v)['ok'], true)
    v, = mk.call({ 'policy' => { 'measurements' => { '1' => hex.call(d1), '0x2' => hex.call(d2) } } })
    c.chk('hex index', ver.call(v)['ok'], true)
    v, = mk.call({ 'rootSpkiSha256' => [c.pin(ch[2]).upcase] })
    c.chk('upcase root pin', ver.call(v)['ok'], true)
    v, = mk.call({ 'policy' => { 'leafSubjectIncludes' => 'GH100', 'measurements' => { '1' => hex.call(d1) } } })
    c.chk('leaf includes', ver.call(v)['ok'], true)
    ['', nil].each do |inc|
      v, = mk.call({ 'policy' => { 'leafSubjectIncludes' => inc, 'measurements' => { '1' => hex.call(d1) } } })
      c.chk("leaf includes #{inc.inspect} is none", ver.call(v)['ok'], true)
    end
    [[], 5].each do |inc|
      c.chk("non-string include #{inc.inspect} refused at construction", c.err_of { mk.call({ 'policy' => { 'leafSubjectIncludes' => inc, 'measurements' => { '1' => hex.call(d1) } } }) },
            ['AtlasPca::Attest::AttestConstructError', 'createNvidiaSpdmVerifier: policy.leafSubjectIncludes must be a string'])
    end
    v, = mk.call({ 'policy' => { 'measurements' => {} }, 'postVerify' => ->(_x) {} })
    c.chk('post verify supplies references', ver.call(v)['ok'], true)
    true
  end

  t('nvidia: NvidiaSpdmVerifier refuses each defect in order with the exact reason') do
    next true unless c.run?

    ch = c.chain3
    nores = 'no NVIDIA GPU evidence for this action'
    v = c.a::NvidiaSpdmVerifier.new({ 'rootSpkiSha256' => ['p'], 'policy' => { 'measurements' => { '1' => 'aa' } } })
    c.chk('no resolver', ver.call(v), fail_r.call('no NVIDIA GPU evidence resolver configured (fail closed)'))
    pem = c.pem(ch)
    [nil, [], 'x', {}, { 'evidence' => 'x' }, { 'certChainPem' => pem }, { 'evidence' => 5, 'certChainPem' => pem }, { 'evidence' => 'x', 'certChainPem' => 5 }, { 'evidence' => nil, 'certChainPem' => pem }].each do |e|
      v, = mk.call({}, resolve: ->(_d) { e })
      c.chk("evidence #{e.inspect}", ver.call(v), fail_r.call(nores))
    end
    seen = []
    v, = mk.call({}, resolve: ->(d) { seen << d; nil })
    ver.call(v)
    c.chk('resolver gets the document', seen, ['doc'])
    v, = mk.call({ 'rootSpkiSha256' => ['0' * 64] })
    c.chk('wrong pin', ver.call(v), fail_r.call('chain root is not a pinned NVIDIA root'))
    v, = mk.call({ 'rootSpkiSha256' => ['0' * 64] }, evidence: 'xx')
    c.chk('chain before parse', ver.call(v), fail_r.call('chain root is not a pinned NVIDIA root'))
    v, = mk.call({ 'policy' => { 'leafSubjectIncludes' => 'ZZZ', 'measurements' => { '1' => 'aa' } } }, evidence: 'xx')
    c.chk('leaf subject', ver.call(v), fail_r.call("device leaf subject does not contain 'ZZZ'"))
    v, = mk.call({}, evidence: 'xx')
    c.chk('parse', ver.call(v), fail_r.call('GPU attestation report parse failed: parseNvidiaSpdmEvidence: transcript too short (2)'))
    v, = mk.call({}, evidence: evid.call(rq: 0x10, rs: 0x10, flip: true))
    c.chk('version before signature', ver.call(v), fail_r.call('SPDM version 0x10/0x10 is not an accepted GET_MEASUREMENTS version'))
    v, = mk.call({}, evidence: evid.call(flip: true))
    c.chk('signature', ver.call(v), fail_r.call('GPU attestation report signature does not verify under the device identity key'))
    c.chk('signature before binding', ver.call(v, nil), fail_r.call('GPU attestation report signature does not verify under the device identity key'))
    v, = mk.call({}, evidence: evid.call(signer: 'some other signer'))
    c.chk('signed by another key', ver.call(v), fail_r.call('GPU attestation report signature does not verify under the device identity key'))
    v, = mk.call
    c.chk('no binding', ver.call(v, nil), fail_r.call('no expected attestation binding supplied'))
    c.chk('bad binding', ver.call(v, bind.merge('holder_pub' => '')), fail_r.call('binding not constructible: binding: holderPub required'))
    c.chk('bad epoch', ver.call(v, bind.merge('epoch' => -1)), fail_r.call('binding not constructible: binding: epoch must be a non-negative safe integer'))
    nonce = 'SPDM request nonce does not bind holder/grant/epoch/nonce (relayed or unbound report)'
    [{ 'holder_pub' => 'other' }, { 'grant_ref' => 'other' }, { 'epoch' => 2 }, { 'nonce' => 'other' }].each { |m| c.chk("relayed #{m}", ver.call(v, bind.merge(m)), fail_r.call(nonce)) }
    v, = mk.call({}, evidence: evid.call(nonce: 'z'.b * 32))
    c.chk('unbound nonce', ver.call(v), fail_r.call(nonce))
    v, = mk.call({ 'policy' => { 'measurements' => { '1' => hex.call(d1), '200' => 'aa' } } })
    c.chk('missing block', ver.call(v), fail_r.call('measurement block 200 missing from report'))
    v, = mk.call({ 'policy' => { 'measurements' => { '1' => hex.call(d2) } } })
    c.chk('digest mismatch', ver.call(v), fail_r.call('measurement block 1 does not match the pinned digest'))
    v, = mk.call({ 'policy' => { 'measurements' => { '1' => hex.call(d1), '2' => 'aa' } } })
    c.chk('second digest mismatch', ver.call(v), fail_r.call('measurement block 2 does not match the pinned digest'))
    v, = mk.call({ 'policy' => { 'measurements' => { '1' => 5 } } })
    c.chk('non-string digest', ver.call(v), fail_r.call('measurement block 1 does not match the pinned digest'))
    true
  end

  t('nvidia: NvidiaSpdmVerifier post-verify hook context, results and fail-closed rescue') do
    next true unless c.run?

    ch = c.chain3
    seen = []
    ev_holder = nil
    hook = ->(ctx) { seen << ctx; nil }
    v, ev_holder = mk.call({ 'postVerify' => hook })
    r = ver.call(v)
    ctx = seen[0]
    c.chk('hook ok', r['ok'], true)
    c.chk('ctx keys', ctx.keys.sort, %w[chain evidence leaf nowMs report])
    c.chk('ctx values', [ctx['nowMs'], ctx['evidence'].equal?(ev_holder), ctx['leaf'].raw, ctx['chain'].map(&:raw), ctx['report']['measurements'].map { |m| m['index'] }],
          [C13::NOW, true, ch[0].to_der, ch.map(&:to_der), [1, 2]])
    c.chk('ctx leaf is chain head', ctx['leaf'].equal?(ctx['chain'][0]), true)
    v, = mk.call({ 'postVerify' => ->(_x) { 'because' } })
    c.chk('hook reason', ver.call(v), fail_r.call('because'))
    ['', nil].each do |w|
      v, = mk.call({ 'postVerify' => ->(_x) { w } })
      c.chk("hook #{w.inspect} continues", ver.call(v)['ok'], true)
    end
    v, = mk.call({ 'postVerify' => ->(_x) { raise 'hook boom' } })
    c.chk('hook raises', ver.call(v), fail_r.call('nvidia-spdm verification error (fail closed): hook boom'))
    v, = mk.call({}, resolve: ->(_d) { raise 'resolver boom' })
    c.chk('resolver raises', ver.call(v), fail_r.call('nvidia-spdm verification error (fail closed): resolver boom'))
    # the hook runs after the pinned digests: a digest mismatch never reaches it
    seen.clear
    v, = mk.call({ 'postVerify' => hook, 'policy' => { 'measurements' => { '1' => hex.call(d2) } } })
    ver.call(v)
    c.chk('hook not reached', seen, [])
    true
  end
end
