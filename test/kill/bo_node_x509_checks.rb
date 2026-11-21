# frozen_string_literal: true
# Verdicts read from Node 26: `checkIssued(up) && verify(up.publicKey)` and the X509Certificate parser on really signed P-384
# certificates built byte for byte like these, and crypto.verify under an rsa-pss key. Rows under `stricter` are ones Node takes
# and this SDK refuses, on purpose.
module MutationKill
  module NodeX509
    module_function

    AK = "\x55\x1d\x23".b
    SK = "\x55\x1d\x0e".b
    RSA = OpenSSL::PKey::RSA.generate(2048) # at load, once: the mutants only re-evaluate the library
    MSG = 'signed input'

    def tlv(tag, *parts) = OcspStrict.tlv(tag, *parts)
    def oid(b) = tlv(0x06, b)
    def b(*bytes) = bytes.pack('C*')
    def name(cn, str = 0x0c) = tlv(0x30, tlv(0x31, tlv(0x30, oid("\x55\x04\x03".b), tlv(str, cn))))
    def ext(id, v) = tlv(0x30, oid(id), tlv(0x04, v))

    def cert(iss, sub, exts, serial, subject_key: StrictChain.key('nx-up'), signer: StrictChain.key('nx-root'))
      alg = tlv(0x30, oid(b(0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 3)))
      val = tlv(0x30, tlv(0x17, '250101000000Z'), tlv(0x17, '350101000000Z'))
      e = exts.empty? ? [] : [tlv(0xa3, tlv(0x30, *exts))]
      tbs = tlv(0x30, tlv(0xa0, tlv(0x02, b(2))), tlv(0x02, serial), alg, iss, val, sub, subject_key.public_to_der, *e)
      tlv(0x30, tbs, alg, tlv(0x03, b(0), signer.sign('SHA384', tbs)))
    end

    def up_name = name('up')
    def root = name('root')
    def other = name('nope')
    def keyid = tlv(0x80, b(7, 7, 7, 7))
    def skid = ext(SK, tlv(0x04, b(7, 7, 7, 7)))
    def ak(*m) = ext(AK, tlv(0x30, *m))
    def dir(n) = tlv(0xa4, n)
    def names(*g) = tlv(0xa1, *g)
    def ser(*x) = tlv(0x82, b(*x))
    def dns = tlv(0x82, 'a.example')

    def issued?(child_exts, up_exts = [skid])
      c = AtlasPca::Attest::Cert
      u = c.new(cert(root, up_name, up_exts, b(0x11)))
      leaf = c.new(cert(up_name, name('leaf'), child_exts, b(0x22), subject_key: StrictChain.key('nx-leaf'), signer: StrictChain.key('nx-up')))
      raise 'not really signed' unless leaf.verify(u.public_key)

      leaf.check_issued(u)
    end

    def oe(oid_bytes, v) = tlv(0x30, oid(oid_bytes), tlv(0x04, v))
    def x(last, v) = oe(b(0x55, 0x1d, last), v)
    def u8(s) = tlv(0x0c, s)
    def uri = tlv(0x86, 'https://a')
    def cn_oid = oid(b(0x55, 4, 3))
    def rdn(*a) = tlv(0x31, *a)
    def atv(*a) = tlv(0x30, *a)
    def nm(*r) = tlv(0x30, *r)
    def val(tag, *bytes) = nm(rdn(atv(cn_oid, tlv(tag, b(*bytes)))))

    # An AKID whose issuer lists these names and a key id; the first directory name must be `root` for the row to link.
    def with_names(*g) = issued?([ak(keyid, tlv(0xa1, *g))])

    # A DirectoryName after a matching one.
    def later(n) = with_names(dir(root), dir(n))

    def rsa = RSA

    def spki(oid_tlv)
      asn = OpenSSL::ASN1.decode(rsa.public_to_der)
      tlv(0x30, tlv(0x30, oid_tlv), asn.value[1].to_der)
    end

    def pss_key = AtlasPca::Attest::Common.load_public_key(spki(OcspStrict.oid('1.2.840.113549.1.1.10')))
    def pkcs1_sig = rsa.sign('SHA256', MSG)
    def pss_sig(salt = 32) = rsa.sign_pss('SHA256', MSG, salt_length: salt, mgf1_hash: 'SHA256')
    def pkcs1_alg = tlv(0x30, OcspStrict.oid('1.2.840.113549.1.1.11'), tlv(0x05))

    def pss_alg(salt = 32)
      h = tlv(0x30, OcspStrict.oid('2.16.840.1.101.3.4.2.1'))
      mgf = tlv(0x30, OcspStrict.oid('1.2.840.113549.1.1.8'), h)
      tlv(0x30, OcspStrict.oid('1.2.840.113549.1.1.10'), tlv(0x30, tlv(0xa0, h), tlv(0xa1, mgf), tlv(0xa2, tlv(0x02, b(salt)))))
    end

    def jws(sig) = { 'header' => { 'alg' => 'RS256' }, 'signature' => sig, 'signingInput' => MSG }
  end

  t('check_issued: the AKID key id, serial and first directory name, as Node reads them') do
    n = NodeX509
    good = [
      [], [n.ak(n.keyid)], [n.ak], [n.ak(n.keyid, n.names(n.dir(n.root)), n.ser(0x11))], [n.ak(n.names(n.dir(n.root)), n.ser(0x11))],
      [n.ak(n.keyid, n.ser(0x11))], [n.ak(n.keyid, n.names(n.dns), n.ser(0x11))], [n.ak(n.keyid, n.names(n.dir(n.root), n.dir(n.other)))],
      [n.ak(n.keyid, n.tlv(0xa1))], [n.ext(NodeX509::AK, n.tlv(0x30, n.keyid) + n.b(5, 0))]
    ]
    bad = [
      [n.ak(n.tlv(0x80, n.b(8, 8, 8, 8)))], [n.ak(n.keyid, n.ser(0x12))], [n.ak(n.keyid, n.ser(0, 0x11))], [n.ak(n.keyid, n.ser)],
      [n.ak(n.keyid, n.ser(0xff, 0x80))], [n.ak(n.keyid, n.names(n.dir(n.other)))], [n.ak(n.keyid, n.names(n.dir(n.other)), n.ser(0x11))],
      [n.ak(n.keyid, n.names(n.dns, n.dir(n.other)))], [n.ak(n.keyid, n.names(n.dir(n.other), n.dir(n.root)))],
      [n.ak(n.keyid, n.b(0xa1, 2, 0x30, 5))], [n.ak(n.keyid, n.names(n.tlv(0x89, n.b(1))))], [n.ak(n.keyid, n.names(n.tlv(0x8f, n.b(1))))],
      [n.ak(n.keyid, n.names(n.tlv(0xa4, n.tlv(0x04, n.b(1)))))], [n.ak(n.keyid, n.names(n.dir(n.root), n.tlv(0xa4, n.tlv(0x04, n.b(1)))))],
      [n.ak(n.keyid, n.names(n.tlv(0xa4, n.tlv(0x30, n.tlv(0x04, n.b(1))))))], [n.ak(n.keyid, n.names(n.tlv(0xa4, n.root, n.root)))],
      [n.ak(n.ser(0x11), n.keyid)], [n.ak(n.names(n.dir(n.root)), n.keyid)], [n.ak(n.ser(0x11), n.names(n.dir(n.root)))], [n.ak(n.keyid, n.keyid)],
      [n.ak(n.tlv(0x04, n.b(1)))], [n.ak(n.tlv(0xa0, n.b(1)))], [n.ext(NodeX509::AK, n.tlv(0x04, n.b(1)))], [n.ak(n.keyid), n.ak(n.keyid)],
      [n.ext(NodeX509::AK, '')], [n.ext(NodeX509::SK, n.tlv(0x30))], [n.skid, n.skid],
      # Node reads these two as the same name (X509_NAME_cmp); bytes stay stricter here
      [n.ak(n.keyid, n.names(n.dir(n.name('root', 0x13))))], [n.ak(n.keyid, n.names(n.dir(n.name('ROOT'))))]
    ]
    good.all? { |c| n.issued?(c) == true } && bad.none? { |c| n.issued?(c) }
  end

  t('check_issued: a later AKID directory name decodes in full or there is no link, as Node reads it') do
    n = NodeX509
    good = [
      n.nm, n.nm(n.rdn), n.name('later'), n.val(0x0c), n.val(0x13, 0xc3, 0xa9), n.val(0x16, 0xe9), n.val(0x14, 0xe9),
      n.nm(n.rdn(n.atv(n.oid(n.b(0x55, 4, 6)), n.u8('b')), n.atv(n.cn_oid, n.u8('a')))), n.nm(n.rdn(n.atv(n.cn_oid, n.u8('a'))), n.rdn(n.atv(n.cn_oid, n.u8('b'))))
    ]
    bad = [
      n.nm(n.tlv(0x30)), n.nm(n.rdn(n.tlv(0x04, n.b(1)))), n.nm(n.rdn(n.atv(n.cn_oid))), n.nm(n.rdn(n.atv)), n.nm(n.rdn(n.atv(n.tlv(0x04, n.b(1)), n.u8('x')))),
      n.nm(n.rdn(n.atv(n.cn_oid, n.u8('x'), n.u8('y')))), n.nm(n.rdn(n.atv(n.tlv(0x06), n.u8('x')))), n.nm(n.rdn(n.atv(n.tlv(0x06, n.b(0x80, 1)), n.u8('x')))),
      n.nm(n.rdn(n.atv(n.tlv(0x06, n.b(0x55, 0x84)), n.u8('x')))), n.nm(n.rdn(n.atv(n.tlv(0x06, n.b(0x55, 0x80, 1)), n.u8('x')))),
      n.val(0x02, 1), n.val(0x05), n.val(0x0c, 0xc3, 0x28), n.val(0x1e, 0, 0x41, 0), n.val(0x1c, 0, 0, 0x41),
      n.nm(n.rdn(n.b(0x30, 0x09, 6, 3, 0x55, 4, 3, 0x0c, 9, 0x61, 0x61))), n.nm(n.rdn(n.atv(n.cn_oid, n.u8('x')), n.tlv(0x04, n.b(1)))),
      # stricter
      n.nm(n.rdn(n.atv(n.cn_oid, n.tlv(0x30)))), n.val(0x1e, 0, 0x41)
    ]
    n.with_names(n.dir(n.root)) == true && n.with_names(n.dir(n.other)) == false &&
      good.all? { |d| n.later(d) == true } && bad.none? { |d| n.later(d) }
  end

  t('check_issued: every AKID GeneralName decodes or there is no link, as Node reads it') do
    n = NodeX509
    other = ->(*a) { n.tlv(0xa0, *a) }
    good = [
      other.call(n.cn_oid, n.tlv(0xa0, n.u8('x'))), n.tlv(0x81, n.b(0xe9)), n.tlv(0x82, n.b(0xe9)), n.tlv(0x82), n.tlv(0x86, n.b(0xe9)), n.tlv(0x87, n.b(1, 2, 3)), n.tlv(0x87)
    ]
    bad = [
      other.call(n.tlv(0x04, n.b(1))), other.call, other.call(n.cn_oid), other.call(n.tlv(0x04, n.b(1)), n.tlv(0xa0, n.u8('x'))),
      n.tlv(0x88), n.tlv(0x88, n.b(0x80, 1)), n.tlv(0xa5), n.tlv(0xa5, n.tlv(0x04, n.b(1))), n.tlv(0xa4), n.tlv(0x83, n.b(1)), n.tlv(0x84, n.b(1)), n.tlv(0x85, n.b(1)), n.tlv(0xa8),
      # stricter
      n.tlv(0x88, n.b(0x55, 4, 3)), n.tlv(0xa3), n.tlv(0xa3, n.tlv(0x02, n.b(1))), n.tlv(0xa5, n.tlv(0xa1, n.u8('x'))), n.tlv(0xa2, n.tlv(0x16, n.b(0x41))), n.tlv(0xa6), n.tlv(0xa7), n.tlv(0xa1)
    ]
    good.all? { |g| n.with_names(g, n.dir(n.root)) == true } && bad.none? { |g| n.with_names(g, n.dir(n.root)) }
  end

  t('check_issued: an extension OpenSSL caches decodes on both certificates or there is no link, as Node reads it') do
    n = NodeX509
    g = n.tlv(0x82, 'a')
    gb = n.tlv(0x82, 'b')
    oth = ->(*a) { n.tlv(0xa0, n.cn_oid, *a) }
    both = {
      # basicConstraints
      [0x13, n.tlv(0x30)] => true, [0x13, n.tlv(0x30, n.tlv(0x01, n.b(255)))] => true, [0x13, n.tlv(0x30, n.tlv(0x01, n.b(0x55)))] => true, [0x13, n.tlv(0x30, n.tlv(0x01, n.b(0)))] => true,
      [0x13, n.tlv(0x30, n.tlv(0x01, n.b(255)), n.tlv(0x02, n.b(1)))] => true, [0x13, n.tlv(0x30, n.tlv(0x02, n.b(1)))] => true, [0x13, n.tlv(0x30) + n.b(5, 0)] => true,
      [0x13, n.tlv(0x30, n.tlv(0x02, n.b(1)), n.tlv(0x01, n.b(255)))] => false, [0x13, n.tlv(0x30, n.tlv(0x01, n.b(255, 255)))] => false, [0x13, n.tlv(0x30, n.tlv(0x01))] => false,
      [0x13, n.tlv(0x30, n.tlv(0x01, n.b(255)), n.tlv(0x02, n.b(0, 1)))] => false, [0x13, n.tlv(0x30, n.tlv(0x01, n.b(255)), n.tlv(0x02))] => false,
      [0x13, n.tlv(0x30, n.tlv(0x01, n.b(255)), n.tlv(0x02, n.b(0xff)))] => false, [0x13, n.tlv(0x30, n.tlv(0x01, n.b(255)), n.tlv(0x02, n.b(1)), n.tlv(0x05))] => false, [0x13, n.tlv(0x04, n.b(1))] => false,
      # keyUsage
      [0x0f, n.tlv(0x03)] => false, [0x0f, n.tlv(0x03, n.b(0))] => false, [0x0f, n.tlv(0x03, n.b(8, 0xa0))] => false, [0x0f, n.tlv(0x04, n.b(0))] => false, [0x0f, n.b(3, 5, 0)] => false, [0x0f, ''] => false,
      # extendedKeyUsage
      [0x25, n.tlv(0x30, n.oid(n.b(0x2b, 6, 1, 5, 5, 7, 3, 1)))] => true, [0x25, n.tlv(0x30)] => true, [0x25, n.tlv(0x30, n.tlv(0x04, n.b(1)))] => false, [0x25, n.tlv(0x30, n.tlv(0x06, n.b(0x80, 1)))] => false, [0x25, n.tlv(0x04, n.b(1))] => false,
      # subjectAltName
      [0x11, n.tlv(0x30, n.uri)] => true, [0x11, n.tlv(0x30)] => true, [0x11, n.tlv(0x30, n.uri) + n.b(5, 0)] => true, [0x11, n.tlv(0x30, oth.call(n.tlv(0xa0, n.u8('x'))))] => true,
      [0x11, n.tlv(0x30, oth.call(n.tlv(0xa0, n.u8('x'), n.u8('y'))))] => false, [0x11, n.tlv(0x30, oth.call(n.tlv(0xa0)))] => false, [0x11, n.tlv(0x30, oth.call(n.tlv(0xa0, n.u8('x')), n.tlv(0x05)))] => false,
      [0x11, n.tlv(0x30, oth.call(n.tlv(0xa1, n.u8('x'))))] => false, [0x11, n.tlv(0x30, n.tlv(0x89, n.b(1)))] => false, [0x11, n.tlv(0x30, n.tlv(0xa4, n.tlv(0x04, n.b(1))))] => false, [0x11, n.tlv(0x04, n.b(1))] => false,
      # nameConstraints
      [0x1e, n.tlv(0x30, n.tlv(0xa0, n.tlv(0x30, g)))] => true, [0x1e, n.tlv(0x30)] => true, [0x1e, n.tlv(0x30, n.tlv(0xa0, n.tlv(0x30, g)), n.tlv(0xa1, n.tlv(0x30, gb)))] => true, [0x1e, n.tlv(0x30, n.tlv(0xa0))] => true,
      [0x1e, n.tlv(0x30, n.tlv(0xa0, n.tlv(0x30, g, n.tlv(0x80, n.b(0)), n.tlv(0x81, n.b(1)))))] => true,
      [0x1e, n.tlv(0x30, n.tlv(0xa1, n.tlv(0x30, gb)), n.tlv(0xa0, n.tlv(0x30, g)))] => false, [0x1e, n.tlv(0x30, n.tlv(0xa0, n.tlv(0x04, n.b(1))))] => false, [0x1e, n.tlv(0x30, n.tlv(0xa0, n.tlv(0x30)))] => false,
      [0x1e, n.tlv(0x30, n.tlv(0xa0, n.tlv(0x30, g, n.tlv(0x81, n.b(1)), n.tlv(0x80, n.b(0)))))] => false, [0x1e, n.tlv(0x30, n.tlv(0xa0, n.tlv(0x30, g, n.tlv(0x80, n.b(0, 1)))))] => false,
      [0x1e, n.tlv(0x30, n.tlv(0x80, n.b(1)))] => false, [0x1e, n.tlv(0x30, n.tlv(0xa0, n.tlv(0x30, g, gb)))] => false, [0x1e, n.tlv(0x30, n.tlv(0xa0, g))] => false,
      [0x1e, n.tlv(0x30, n.tlv(0xa0, n.tlv(0x30, g, n.tlv(0x80, n.b(0xff)))))] => false, # stricter
      # cRLDistributionPoints
      [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa0, n.tlv(0xa0, n.uri))))] => true, [0x1f, n.tlv(0x30)] => true, [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa0, n.tlv(0xa1, n.atv(n.cn_oid, n.u8('x'))))))] => true,
      [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa2, n.uri)))] => true, [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa0, n.tlv(0xa0, n.uri)), n.tlv(0x81, n.b(1, 0x80))))] => true,
      [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa0, n.tlv(0xa0, n.uri)), n.tlv(0x81, n.b(0))))] => true, [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa0, n.tlv(0xa0))))] => true, [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa0, n.tlv(0xa1))))] => true,
      [0x1f, n.tlv(0x30, n.tlv(0x30))] => false, [0x1f, n.tlv(0x30, n.tlv(0x04, n.b(1)))] => false, [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa0, n.tlv(0xa1, n.tlv(0x04, n.b(1))))))] => false,
      [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0x81, n.b(1, 0x80))))] => false, [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa2, n.tlv(0x89, n.b(1)))))] => false, [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa2)))] => false,
      [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa2, n.uri), n.tlv(0xa0, n.tlv(0xa0, n.uri))))] => false, [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa0)))] => false, [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa0, n.tlv(0xa2, n.uri))))] => false,
      [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa0, n.tlv(0xa0, n.uri), n.tlv(0xa0, n.uri))))] => false, [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa0, n.tlv(0xa0, n.tlv(0x89, n.b(1))))))] => false,
      [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa0, n.tlv(0xa0, n.uri)), n.tlv(0x81, n.b(8, 0x80))))] => false, [0x1f, n.tlv(0x30, n.tlv(0x30, n.tlv(0xa0, n.tlv(0xa0, n.uri)), n.tlv(0x81)))] => false
    }
    pci = n.oe(n.b(0x2b, 6, 1, 5, 5, 7, 1, 14), n.tlv(0x30, n.tlv(0x30, n.oid(n.b(0x2b, 6, 1, 5, 5, 7, 21, 1)))))
    both.all? { |(last, v), want| e = n.x(last, v); n.issued?([e]) == want && n.issued?([], [n.skid, e]) == want } &&
      # keyUsage without keyCertSign refuses only on the issuer, with keyCertSign it links on both
      n.issued?([n.x(0x0f, n.tlv(0x03, n.b(5, 0xa0)))]) == true && n.issued?([], [n.skid, n.x(0x0f, n.tlv(0x03, n.b(5, 0xa0)))]) == false &&
      n.issued?([n.x(0x0f, n.tlv(0x03, n.b(7, 0x80)))]) == true && n.issued?([], [n.skid, n.x(0x0f, n.tlv(0x03, n.b(2, 0x04)))]) == true &&
      # stricter: Node links under a proxyCertInfo and a repeated unknown extension
      !n.issued?([pci]) && !n.issued?([], [n.skid, pci]) && !n.issued?([n.x(0x63, n.b(1)), n.x(0x63, n.b(1))])
  end

  t('check_issued: the issuer side decodes too, and a missing SKID or the issuer\'s own AKID values do not matter, as Node reads them') do
    n = NodeX509
    n.issued?([n.ak(n.keyid)], []) == true &&
      n.issued?([n.ak(n.keyid)], [n.ext(NodeX509::SK, n.tlv(0x04, n.b(7, 7, 7, 7)) + n.b(5, 0))]) == true &&
      n.issued?([], [n.skid, n.ak(n.ser(0x77))]) == true &&
      [[n.ext(NodeX509::SK, n.tlv(0x30))], [n.skid, n.skid], [n.skid, n.ext(NodeX509::AK, n.tlv(0x04, n.b(1)))]].none? { |u| n.issued?([], u) } &&
      n.issued?([n.ak(n.keyid)], [n.ext(NodeX509::SK, n.tlv(0x30))]) == false
  end

  t('a certificate serial must be a minimal DER INTEGER, as Node\'s X509Certificate reads it') do
    n = NodeX509
    parse = ->(*s) { AtlasPca::Attest::Cert.new(n.cert(n.root, n.up_name, [], n.b(*s))) }
    [[1], [0x11], [0, 0x80], [0xff, 0x7f], [0x80], [0], [0x11] * 21].all? { |s| parse.call(*s).serial == n.b(*s) } &&
      [[0, 0x11], [0xff, 0x80], [0, 0], []].all? { |s|
        begin
          parse.call(*s)
          false
        rescue AtlasPca::Attest::CertError
          true
        end
      }
  end

  t('an rsa-pss key: PKCS#1 is refused on every path, PSS verifies, RS256 is refused outright') do
    n = NodeX509
    a = AtlasPca::Attest
    c = a::Common
    pk = n.pss_key
    leaf = Struct.new(:public_key).new(pk)
    c.key_type(pk) == 'rsa-pss' && c.key_type(n.rsa.public_key) == 'rsa' &&
      c.rsa_pkcs1_verify(n.rsa.public_key, n.pkcs1_sig, NodeX509::MSG, 'sha256') == true &&
      c.rsa_pkcs1_verify(pk, n.pkcs1_sig, NodeX509::MSG, 'sha256') == false &&
      a::Cert.verify_with_alg(n.pkcs1_alg, NodeX509::MSG, n.pkcs1_sig, n.rsa.public_key) == true &&
      a::Cert.verify_with_alg(n.pkcs1_alg, NodeX509::MSG, n.pkcs1_sig, pk) == false &&
      a::Cert.verify_with_alg(n.pss_alg, NodeX509::MSG, n.pss_sig, pk) == true &&
      a::Cert.verify_with_alg(n.pss_alg, NodeX509::MSG, n.pss_sig, n.rsa.public_key) == true &&
      a::Cert.verify_with_alg(n.pss_alg(20), NodeX509::MSG, n.pss_sig, pk) == false &&
      a::Cert.verify_with_alg(n.pss_alg, NodeX509::MSG, n.pkcs1_sig, pk) == false &&
      a::Cert.verify_with_alg(n.pss_alg, NodeX509::MSG, n.pss_sig, StrictChain.key('leaf')) == false &&
      a::Gcp.verify_jws_signature(n.jws(n.pkcs1_sig), pk) == 'RS256 token but signing key is rsa-pss (not RSA)' &&
      a::Gcp.verify_jws_signature(n.jws(n.pkcs1_sig), n.rsa.public_key).nil? &&
      a::Azure.verify_jws_signature(n.jws(n.pkcs1_sig), leaf) == 'RS256 token but signing key is rsa-pss (not RSA)'
  end

  t('load_public_key takes an SPKI only: not PEM, not a private key') do
    c = AtlasPca::Attest::Common
    r = NodeX509.rsa
    c.key_type(c.load_public_key(r.public_to_der)) == 'rsa' &&
      [r.public_to_pem, r.private_to_der, r.to_der].none? { |x|
        begin
          c.load_public_key(x)
          true
        rescue StandardError
          false
        end
      }
  end

  t('a signed PCActn with an obligations member is refused, a present null included (wire.ts: unknown field)') do
    g = Intent.grant
    AtlasPca.wire_ok?(Intent.pcactn(g)) &&
      [nil, [], 'x'].none? { |v| AtlasPca.wire_ok?(Intent.pcactn(g, 'obligations' => v)) } &&
      Intent.verify(Intent.pcactn(g, 'obligations' => nil), g).checks == { 'wire' => false }
  end
end
