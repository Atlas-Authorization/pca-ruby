# frozen_string_literal: true

# Hardening kill tests (e02): Sigstore RSA key rule + OID caps + RFC 3161 timestamp cap, OCSP DER nesting / node caps, RIM XML nesting cap.
# Every AtlasPca object is resolved at CALL time (the mutation oracle re-evaluates the library per mutant).
require 'openssl'
require 'atlas_pca/attest'

module MutationKill
  module E02
    module_function

    def gate?(*names) = (f = ENV['MUT_FILE']) && !f.empty? && !names.include?(f)

    # rows: [label, got, want]
    def chk(rows)
      bad = rows.reject { |_l, got, want| got == want && got.class == want.class }
      return true if bad.empty?

      raise "e02 mismatch: #{bad.first(4).map { |l, g, w| "#{l}: got #{g.inspect[0, 200]} want #{w.inspect[0, 200]}" }.join(' | ')}"
    end

    def err
      yield
    rescue Exception => e # rubocop:disable Lint/RescueException
      [e.class, e.message]
    end

    RSA2K = OpenSSL::PKey::RSA.generate(2048)
    Duck = Struct.new(:n, :e)

    def bn(bits) = OpenSSL::BN.new((2**(bits - 1)).to_s)

    def oid_of(content)
      s = AtlasPca::SigstoreBundle
      der = MutationKill::C21Sig.tl(6, content)
      s.oid(der, s.tlv(der, 0))
    end

    def tlv(tag, *parts)
      b = parts.join.b
      n = [b.bytesize].pack('N').sub(/\A\0+/, '')
      len = b.bytesize < 128 ? [b.bytesize].pack('C') : [0x80 | n.bytesize].pack('C') + n
      [tag].pack('C') + len + b
    end

    # k SEQUENCEs around a NULL
    def nest(k) = (1..k).reduce("\x05\x00".b) { |acc, _| tlv(0x30, acc) }

    OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1'
    ALG = tlv(0x30, OpenSSL::ASN1::ObjectId.new('1.2.840.10045.4.3.3').to_der)
    DEEP_REASON = 'BasicOCSPResponse is not valid DER'

    def ocsp(tbs_content)
      basic = tlv(0x30, tlv(0x30, tbs_content), ALG, tlv(0x03, "\0", 'sig'))
      resp = tlv(0x30, tlv(0x0A, "\0"), tlv(0xA0, tlv(0x30, OpenSSL::ASN1::ObjectId.new(OCSP_BASIC).to_der, tlv(0x04, basic))))
      AtlasPca::Attest::Ocsp.verify_ocsp_response(resp, nil, nil, nil, 1_800_000_000_000)
    end
  end

  t('e02 sigstore: oid refuses content over 256 bytes and arcs over 64 groups, still decodes real OIDs') do
    next true if E02.gate?('sigstore_bundle.rb')

    big = (0...64).sum { |k| 128**k }
    E02.chk([['2.5.29.19', E02.oid_of("\x55\x1d\x13".b), '2.5.29.19'],
             ['256 bytes ok', E02.oid_of("\x2a".b + ("\x01".b * 255)), "1.2.#{(['1'] * 255).join('.')}"],
             ['257 bytes', E02.err { E02.oid_of("\x2a".b + ("\x01".b * 256)) }, [AtlasPca::SigstoreBundle::Fail, 'extension OID is too long']],
             ['64 groups ok', E02.oid_of("\x2a".b + ("\x81".b * 63) + "\x01".b), "1.2.#{big}"],
             ['65 groups', E02.err { E02.oid_of("\x2a".b + ("\x81".b * 64) + "\x01".b) },
              [AtlasPca::SigstoreBundle::Fail, 'extension OID has an oversized arc']]])
  end

  t('e02 sigstore: rsa_key_ok? bounds (modulus 512..16384, odd e >= 3, e at most 32 bits)') do
    next true if E02.gate?('sigstore_bundle.rb')

    s = AtlasPca::SigstoreBundle
    ok = ->(bits, e) { s.rsa_key_ok?(E02::Duck.new(E02.bn(bits), e)) }
    E02.chk([['2048/65537', ok.call(2048, 65_537), true], ['512/3', ok.call(512, 3), true], ['511/3', ok.call(511, 3), false],
             ['16384', ok.call(16_384, 65_537), true], ['16385', ok.call(16_385, 65_537), false],
             ['e=1', ok.call(2048, 1), false], ['e=2', ok.call(2048, 2), false], ['e=4', ok.call(2048, 4), false],
             ['e=3', ok.call(2048, 3), true], ['e 2^32-1', ok.call(2048, (2**32) - 1), true], ['e 2^32+1', ok.call(2048, (2**32) + 1), false]])
  end

  t('e02 sigstore: verify_sig accepts a normal RSA signature and refuses an e=1 key even when sig == the padded digest') do
    next true if E02.gate?('sigstore_bundle.rb')

    s = AtlasPca::SigstoreBundle
    data = 'e02-data'
    good = E02::RSA2K.sign('SHA256', data)
    # e=1 key over the same modulus: the "signature" is the PKCS#1 v1.5 encoded message itself
    n = E02::RSA2K.n
    spki = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId('rsaEncryption'), OpenSSL::ASN1::Null(nil)]),
                                    OpenSSL::ASN1::BitString(OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(n),
                                                                                       OpenSSL::ASN1::Integer(1)]).to_der)]).to_der
    weak = OpenSSL::PKey.read(spki)
    prefix = ['3031300d060960864801650304020105000420'].pack('H*')
    digest = OpenSSL::Digest::SHA256.digest(data)
    t_len = prefix.bytesize + digest.bytesize
    em = "\x00\x01".b + ("\xff".b * (256 - 3 - t_len)) + "\x00".b + prefix + digest
    E02.chk([['good', s.verify_sig('sha256', data, E02::RSA2K, good), true],
             ['e=1', s.verify_sig('sha256', data, weak, em), false]])
  end

  t('e02 sigstore: more than 8 RFC 3161 timestamps are refused before any is verified') do
    next true if E02.gate?('sigstore_bundle.rb')

    c = MutationKill::C21Sig
    run = lambda do |n|
      b, roots = c.case_of(c::OK_V1)
      b['verificationMaterial']['timestampVerificationData'] = { 'rfc3161Timestamps' => Array.new(n) { { 'signedTimestamp' => 'x' } } }
      c.slim(AtlasPca.verify_sigstore_bundle_core(b, roots))
    end
    E02.chk([['9', run.call(9), { ok: false, code: 'tsa', detail: 'too many RFC 3161 timestamps (9, at most 8)' }],
             ['8', run.call(8), { ok: false, code: 'tsa', detail: 'fail closed: not base64' }]])
  end

  t('e02 ocsp: DER nesting over 100 and more than 10000 nodes are refused with BasicOCSPResponse is not valid DER') do
    next true if E02.gate?('ocsp.rb')

    pass = { 'ok' => false, 'reason' => 'OCSP response rejected: responderID is malformed' }
    deep = { 'ok' => false, 'reason' => E02::DEEP_REASON }
    E02.chk([['99 nested', E02.ocsp(E02.nest(99)), pass], ['100 nested', E02.ocsp(E02.nest(100)), deep],
             ['2000 nested', E02.ocsp(E02.nest(2000)), deep],
             ['9996 nodes', E02.ocsp("\x05\x00".b * 9996), pass], ['9997 nodes', E02.ocsp("\x05\x00".b * 9997), deep]])
  end

  t('e02 xml: element nesting over 64 is refused, 64 parses; surfaced through the RIM verifier') do
    next true if E02.gate?('xml.rb', 'nvidia.rb')

    x = AtlasPca::Attest::Xml
    doc = ->(n) { ('<a>' * n) + ('</a>' * n) }
    rim = AtlasPca::Attest::Nvidia.verify_nvidia_rim(doc.call(65), [''], 0)
    E02.chk([['64', x.parse_xml(doc.call(64)).root.qname, 'a'],
             ['65', E02.err { x.parse_xml(doc.call(65)) }, [AtlasPca::Attest::XmlError, 'XML nesting is too deep']],
             ['5000', E02.err { x.parse_xml(doc.call(5000)) }, [AtlasPca::Attest::XmlError, 'XML nesting is too deep']],
             ['rim', rim, { 'ok' => false, 'reason' => 'RIM: verification error (fail closed): XML nesting is too deep' }]])
  end
end
