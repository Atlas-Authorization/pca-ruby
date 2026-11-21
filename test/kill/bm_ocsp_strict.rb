# frozen_string_literal: true
# The SingleResponse shape the reference's schema enforces (attest-nvidia-ocsp.ts): exact certStatus tags; after thisUpdate only
# nextUpdate then singleExtensions; one GeneralizedTime in nextUpdate. Every response here is genuinely signed by the issuer.
module MutationKill
  module OcspStrict
    module_function

    NOW = 1_800_000_000_000
    def s = StrictChain
    def tlv(tag, *parts)
      b = parts.join.b
      n = [b.bytesize].pack('N').sub(/\A\0+/, '')
      len = b.bytesize < 128 ? [b.bytesize].pack('C') : [0x80 | n.bytesize].pack('C') + n
      [tag].pack('C') + len + b
    end

    def gt(ms) = tlv(0x18, Time.at(ms / 1000).utc.strftime('%Y%m%d%H%M%SZ'))
    def oid(o) = OpenSSL::ASN1::ObjectId.new(o).to_der
    def certs = (@certs ||= s.chain)
    def cert = AtlasPca::Attest::Cert.new(certs[0].to_der)
    def issuer = AtlasPca::Attest::Cert.new(certs[1].to_der)

    def single(status, *after, serial: certs[0].serial)
      name, key = AtlasPca::Attest::Ocsp.cert_id_hashes(issuer, 'sha1')
      id = tlv(0x30, tlv(0x30, oid('1.3.14.3.2.26')), tlv(0x04, name), tlv(0x04, key), OpenSSL::ASN1::Integer.new(serial).to_der)
      tlv(0x30, id, status, gt(NOW - 1000), *after)
    end

    def verify(*singles)
      tbs = tlv(0x30, tlv(0xA1, certs[1].subject.to_der), gt(NOW - 1000), tlv(0x30, *singles))
      sig = s.key('inter').sign(OpenSSL::Digest.new('SHA384'), tbs)
      basic = tlv(0x30, tbs, tlv(0x30, oid('1.2.840.10045.4.3.3')), tlv(0x03, "\0", sig))
      top = tlv(0x30, tlv(0x0A, "\0"), tlv(0xA0, tlv(0x30, oid('1.3.6.1.5.5.7.48.1.1'), tlv(0x04, basic))))
      AtlasPca::Attest::Ocsp.verify_ocsp_response(top, cert, issuer, certs.map { |c| AtlasPca::Attest::Cert.new(c.to_der) }, NOW)
    end

    def good = tlv(0x80)
    def ok(status = 'good') = { 'ok' => true, 'status' => status, 'responder' => 'issuer' }
    def no(reason) = { 'ok' => false, 'reason' => reason }
    def bad_single = no('OCSP response rejected: SingleResponse is malformed')
    def bad_next = no('OCSP response rejected: nextUpdate is malformed')
  end

  t('OCSP certStatus: exact tags, on a genuinely signed response') do
    o = OcspStrict
    st = ->(b) { o.verify(o.single(b)) }
    st.(o.tlv(0x80)) == o.ok && st.(o.tlv(0x82)) == o.ok('unknown') && st.(o.tlv(0xA1, o.gt(o::NOW - 5000))) == o.ok('revoked') &&
      [0xA0, 0xA2, 0x81, 0x05, 0xC0].all? { |t| st.(o.tlv(t)) == o.no('malformed certStatus') } &&
      [0x83, 0xA3, 0x84].all? { |t| st.(o.tlv(t)) == o.no('unrecognised certStatus') } &&
      st.(o.tlv(0xA1)) == o.no('malformed revoked certStatus')
  end

  t('OCSP SingleResponse: after thisUpdate only nextUpdate then singleExtensions, in every SingleResponse') do
    o = OcspStrict
    fut = o.tlv(0xA0, o.gt(o::NOW + 5000))
    past = o.tlv(0xA0, o.gt(o::NOW - 500))
    ext = o.tlv(0xA1)
    v = ->(*after) { o.verify(o.single(o.good, *after)) }
    v.() == o.ok && v.(fut) == o.ok && v.(ext) == o.ok && v.(fut, ext) == o.ok &&
      v.(past) == o.no('response is stale (past nextUpdate)') &&
      v.(o.tlv(0xA2, o.gt(o::NOW - 500))) == o.bad_single && v.(ext, fut) == o.bad_single && v.(fut, fut) == o.bad_single &&
      v.(fut, ext, ext) == o.bad_single && v.(ext, ext) == o.bad_single &&
      o.verify(o.single(o.good, o.tlv(0xA2), serial: 7), o.single(o.good)) == o.bad_single
  end

  t('OCSP nextUpdate: exactly one GeneralizedTime') do
    o = OcspStrict
    v = ->(*kids) { o.verify(o.single(o.good, o.tlv(0xA0, *kids))) }
    v.(o.gt(o::NOW + 5000)) == o.ok && v.() == o.bad_next && v.(o.gt(o::NOW + 5000), o.gt(o::NOW + 6000)) == o.bad_next &&
      v.(o.tlv(0x17, '330101000000Z')) == o.bad_next
  end
end
