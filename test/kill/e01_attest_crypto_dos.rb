# frozen_string_literal: true

# PCA 0.5 hardening e01: RSA public-key rule (H1), OID content / arc caps (H2), JSON depth (H4) and JSON size (H7).
# Reference rule: Swift ACrypto.rsaKeyOK, AttestDER.swift:9-10, AttestCommon.swift:186. Every AtlasPca reference is resolved at CALL time.
# (c07_attest_common.rb is loaded before this file: alphabetical order, so MutationKill::C07::RSAK exists)
require 'base64'
require 'digest'
require 'openssl'

module MutationKill
  module E01
    module_function

    def run? = (f = ENV['MUT_FILE']).nil? || f.empty? || %w[common.rb cert.rb gcp.rb der.rb].include?(f)

    def chk(label, got, want)
      raise "#{label}: got #{got.inspect}, want #{want.inspect}" unless got == want

      true
    end

    def err
      yield
      nil
    rescue StandardError => e
      [e.class, e.message]
    end

    def b64u(s) = Base64.urlsafe_encode64(s, padding: false)
    def com = AtlasPca::Attest::Common
    def rsa_pub(n, e) = OpenSSL::PKey::RSA.new(OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(n), OpenSSL::ASN1::Integer(e)]).to_der)
    def k = MutationKill::C07::RSAK

    SHA256_PREFIX = ['3031300d060960864801650304020105000420'].pack('H*').freeze

    # The PKCS#1 v1.5 encoded message of sha256(data) for a 2048-bit modulus: the signature a key with e = 1 would accept.
    def pkcs1_em(data)
      t = SHA256_PREFIX + Digest::SHA256.digest(data)
      "\x00\x01".b + ("\xff".b * (256 - 3 - t.bytesize)) + "\x00".b + t
    end

    def mgf1(seed, len)
      out = ''.b
      i = 0
      while out.bytesize < len
        out << Digest::SHA256.digest(seed + [i].pack('N'))
        i += 1
      end
      out.byteslice(0, len)
    end

    # RSASSA-PSS (sha256, MGF1-sha256, salt length 0) encoded message for a 2048-bit modulus: the signature a key with e = 1 would accept.
    def pss_em(data)
      h = Digest::SHA256.digest(("\x00".b * 8) + Digest::SHA256.digest(data))
      db = ("\x00".b * 222) + "\x01".b
      masked = db.bytes.zip(mgf1(h, 223).bytes).map { |a, b| a ^ b }
      masked[0] &= 0x7F
      masked.pack('C*') + h + "\xbc".b
    end

    def oid(s) = OpenSSL::ASN1::ObjectId(s)
    def pkcs1_alg = OpenSSL::ASN1::Sequence([oid('1.2.840.113549.1.1.11'), OpenSSL::ASN1::Null.new(nil)]).to_der
    def tagged(n, v) = OpenSSL::ASN1::ASN1Data.new([v], n, :CONTEXT_SPECIFIC)

    def hash_id = OpenSSL::ASN1::Sequence([oid('2.16.840.1.101.3.4.2.1'), OpenSSL::ASN1::Null.new(nil)])

    # id-RSASSA-PSS with sha256, MGF1-sha256, salt length 0
    def pss_alg
      params = OpenSSL::ASN1::Sequence([tagged(0, hash_id),
                                        tagged(1, OpenSSL::ASN1::Sequence([oid('1.2.840.113549.1.1.8'), hash_id])),
                                        tagged(2, OpenSSL::ASN1::Integer(0))])
      OpenSSL::ASN1::Sequence([oid('1.2.840.113549.1.1.10'), params]).to_der
    end

    def depth_of(v)
      d = 0
      while v.is_a?(Array) && !v.empty?
        d += 1
        v = v[0]
      end
      d + 1
    end

    def oid_of(bytes) = AtlasPca::Attest::Der.oid_to_dotted(bytes, AtlasPca::Attest::Der::Tlv.new(0x06, 0, bytes.bytesize))
    def der_err = AtlasPca::Attest::DerError
  end

  e = E01

  t('e01 rsa: the key rule is modulus 512..16384 bits, odd e >= 3, at most 32 bits') do
    next true unless e.run?

    c = e.com
    [
      ['512 bit n', c.rsa_ne_ok?(1 << 511, 65_537), true],
      ['511 bit n', c.rsa_ne_ok?(1 << 510, 65_537), false],
      ['256 bit n', c.rsa_ne_ok?(1 << 255, 65_537), false],
      ['16384 bit n', c.rsa_ne_ok?(1 << 16_383, 65_537), true],
      ['16385 bit n', c.rsa_ne_ok?(1 << 16_384, 65_537), false],
      ['17000 bit n', c.rsa_ne_ok?(1 << 16_999, 65_537), false],
      ['e = 1', c.rsa_ne_ok?(1 << 2047, 1), false],
      ['e = 2', c.rsa_ne_ok?(1 << 2047, 2), false],
      ['e = 3', c.rsa_ne_ok?(1 << 2047, 3), true],
      ['e = 4', c.rsa_ne_ok?(1 << 2047, 4), false],
      ['e = 65537', c.rsa_ne_ok?(1 << 2047, 65_537), true],
      ['e 32 bit odd', c.rsa_ne_ok?(1 << 2047, (2**32) - 1), true],
      ['e 32 bit even', c.rsa_ne_ok?(1 << 2047, (2**32) - 2), false],
      ['e 33 bit odd', c.rsa_ne_ok?(1 << 2047, (2**32) + 1), false],
      ['e 2^33 + 1', c.rsa_ne_ok?(1 << 2047, (2**33) + 1), false]
    ].each { |label, got, want| e.chk(label, got, want) }
    true
  end

  t('e01 rsa: a real key passes and a key with e = 1 or an oversized e verifies nothing (PKCS#1, JWK)') do
    next true unless e.run?

    c = e.com
    k = e.k
    data = 'e01 rsa data'.b
    n = k.n.to_i
    pub = OpenSSL::PKey.read(k.public_to_der)
    e.chk('real key ok', c.rsa_key_ok?(pub), true)
    e.chk('real signature verifies', c.rsa_pkcs1_verify(pub, k.sign(OpenSSL::Digest.new('SHA256'), data), data, 'sha256'), true)
    # e = 1: s^1 = EM, so the encoded message itself "verifies" unless the key is refused
    one = e.rsa_pub(n, 1)
    e.chk('e=1 key refused', c.rsa_key_ok?(one), false)
    e.chk('e=1 forged signature', c.rsa_pkcs1_verify(one, e.pkcs1_em(data), data, 'sha256'), false)
    # e = 2^32 + 15 (33 bits, prime): a genuine signature under it, made with the private key, is still refused
    big_e = (2**32) + 15
    phi = (k.p.to_i - 1) * (k.q.to_i - 1)
    d = big_e.to_bn.mod_inverse(phi.to_bn).to_i
    s = e.pkcs1_em(data).unpack1('H*').to_i(16).pow(d, n)
    sig = [s.to_s(16).rjust(512, '0')].pack('H*')
    big = e.rsa_pub(n, big_e)
    e.chk('33-bit e key refused', c.rsa_key_ok?(big), false)
    e.chk('33-bit e signature', c.rsa_pkcs1_verify(big, sig, data, 'sha256'), false)
    # the JWK path refuses the same keys with the decoder wording
    g = AtlasPca::Attest::Gcp
    jwk = ->(ee) { { 'kty' => 'RSA', 'n' => e.b64u(k.n.to_s(2)), 'e' => e.b64u(ee) } }
    unusable = { 'reason' => 'JWKS key is not a usable public key: error:1E08010C:DECODER routines::unsupported' }
    e.chk('jwk e=1', g.key_from_jwk(jwk.call("\x01".b)), unusable)
    e.chk('jwk e=4', g.key_from_jwk(jwk.call("\x04".b)), unusable)
    e.chk('jwk e=2^32+15', g.key_from_jwk(jwk.call([big_e.to_s(16).rjust(10, '0')].pack('H*'))), unusable)
    e.chk('jwk real e', g.key_from_jwk(jwk.call("\x01\x00\x01".b))['key'].public_to_der, k.public_to_der)
    true
  end

  t('e01 rsa: a certificate signature under an e = 1 key is refused, PKCS#1 and PSS, a real one verifies') do
    next true unless e.run?

    cert = AtlasPca::Attest::Cert
    k = e.k
    data = 'e01 cert data'.b
    one = e.rsa_pub(k.n.to_i, 1)
    real = OpenSSL::PKey.read(k.public_to_der)
    e.chk('pkcs1 real', cert.verify_with_alg(e.pkcs1_alg, data, k.sign(OpenSSL::Digest.new('SHA256'), data), real), true)
    e.chk('pkcs1 e=1', cert.verify_with_alg(e.pkcs1_alg, data, e.pkcs1_em(data), one), false)
    pss = k.sign_pss('SHA256', data, salt_length: 0, mgf1_hash: 'SHA256')
    e.chk('pss real', cert.verify_with_alg(e.pss_alg, data, pss, real), true)
    e.chk('pss e=1', cert.verify_with_alg(e.pss_alg, data, e.pss_em(data), one), false)
    true
  end

  t('e01 der: an OID of more than 256 content bytes or an arc of more than 64 groups is refused before any big-integer work') do
    next true unless e.run?

    d = e.der_err
    e.chk('2.5.29.19', e.oid_of("\x55\x1d\x13".b), '2.5.29.19')
    e.chk('256 bytes ok', e.oid_of("\x2a".b + ("\x01".b * 255)), '1.2' + ('.1' * 255))
    e.chk('257 bytes', e.err { e.oid_of("\x2a".b + ("\x01".b * 256)) }, [d, 'extension OID is too long'])
    e.chk('300 bytes', e.err { e.oid_of(("\x81".b * 299) + "\x01".b) }, [d, 'extension OID is too long'])
    v = 0
    64.times { v = (v << 7) | 1 }
    e.chk('64 groups ok', e.oid_of(("\x81".b * 63) + "\x01".b), "2.#{v - 80}")
    e.chk('65 groups', e.err { e.oid_of(("\x81".b * 64) + "\x01".b) }, [d, 'extension OID has an oversized arc'])
    e.chk('65 groups, unterminated', e.err { e.oid_of("\x81".b * 65) }, [d, 'extension OID has an oversized arc'])
    # the group count restarts with every arc
    v40 = 0
    40.times { v40 = (v40 << 7) | 1 }
    e.chk('two 40-group arcs', e.oid_of(("\x2a".b + ("\x81".b * 39) + "\x01".b) * 2), "1.2.#{v40}.42.#{v40}")
    # 2.25.<UUID>: a 128-bit arc is 19 groups
    arc = (2**127) + 12_345
    groups = []
    x = arc
    while x.positive?
      groups.unshift(x & 0x7F)
      x >>= 7
    end
    bytes = groups.each_with_index.map { |g, i| i == groups.length - 1 ? g : g | 0x80 }
    e.chk('uuid arc groups', groups.length, 19)
    e.chk('2.25.uuid', e.oid_of(([0x69] + bytes).pack('C*')), "2.25.#{arc}")
    # 100 KB in one arc: refused at once
    big = ("\x81".b * 100_000) + "\x01".b
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    e.chk('100 KB arc', e.err { e.oid_of(big) }, [d, 'extension OID is too long'])
    e.chk('100 KB arc is fast', Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0 < 0.5, true)
    true
  end

  t('e01 json: containers nest at most 512 deep, deeper is a JsError and never a stack overflow') do
    next true unless e.run?

    c = e.com
    js = AtlasPca::Attest::JsError
    stack = [js, 'Maximum call stack size exceeded']
    e.chk('511 deep', e.depth_of(c.js_json_loads(('[' * 511) + (']' * 511))), 511)
    e.chk('512 deep', e.depth_of(c.js_json_loads(('[' * 512) + (']' * 512))), 512)
    e.chk('513 deep', e.err { c.js_json_loads(('[' * 513) + (']' * 513)) }, stack)
    e.chk('513 deep objects', e.err { c.js_json_loads(('{"a":' * 513) + '1' + ('}' * 513)) }, stack)
    e.chk('512 deep objects', c.js_json_loads(('{"a":' * 512) + '1' + ('}' * 512)).class, Hash)
    e.chk('200000 open brackets', e.err { c.js_json_loads('[' * 200_000) }, stack)
    # as a JWS header: refused with the verifier's wording, nothing raised out of the reader
    token = "#{e.b64u('[' * 200_000)}.e30.AA"
    e.chk('jws header', e.err { c.parse_jws(token, 'verifyX') }, [AtlasPca::Attest::JsTypeError, 'verifyX: malformed JSON segment: Maximum call stack size exceeded'])
    true
  end

  t('e01 json: a segment of more than 16 MiB is refused before parsing') do
    next true unless e.run?

    c = e.com
    js = AtlasPca::Attest::JsError
    lim = 16 * 1024 * 1024
    e.chk('16 MiB + 1', e.err { c.js_json_loads('a' * (lim + 1)) }, [js, 'input too large'])
    # exactly 16 MiB is parsed (and fails for its own reason, quickly: the second quote ends the string)
    e.chk('16 MiB', e.err { c.js_json_loads('"' * lim) }, [js, 'Unexpected non-whitespace character after JSON at position 2'])
    # multi-byte text counts in bytes
    e.chk('bytes not chars', e.err { c.js_json_loads("é" * ((lim / 2) + 1)) }, [js, 'input too large'])
    true
  end
end
