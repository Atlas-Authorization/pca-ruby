# frozen_string_literal: true

require 'openssl'
require 'json'
require_relative 'js_compat'
require_relative 'jose'
require_relative 'attest/common'
require_relative 'attest/der'
require_relative 'attest/cert'

# Bridge PCA agent identity with SPIFFE / SPIRE workload identity, matching the TypeScript reference: SPIFFE ID parsing,
# JWT-SVID and X.509-SVID verification, the SVID -> PCA holder binding, trust-bundle and revocation caches that fail closed,
# and SPIFFE evidence for blueprint admission. Every failure refuses.
#
# Options are snake_case String-keyed Hashes. The reference's asynchronous calls (bundle / revocation fetch, revocation
# checks) are plain synchronous callables here. Time: X.509 verification takes `now_ms` (epoch milliseconds) or `now`
# (a Time or epoch seconds); JWT verification takes `current_date` (a Time or epoch seconds); the caches take a `now`
# callable returning epoch milliseconds. Records keep the reference's member names: a SPIFFE ID is
# {'id','trustDomain','path'}, a holder {'holder','spiffeId','trustDomain','path'}.
module AtlasPca
  module Spiffe
    # A validation / parse / verification failure with a stable `code` (the reference's SpiffeErrorCode).
    class SpiffeError < StandardError
      attr_reader :code

      def initialize(code, message)
        super(message)
        @code = code
      end
    end

    # A JOSE-level refusal carrying the library's stable code (ERR_JWS_INVALID, ERR_JWT_EXPIRED ...).
    class JoseError < StandardError
      attr_reader :code

      def initialize(code, message)
        super(message)
        @code = code
      end
    end

    # A structural DER problem (the reference's RangeError).
    class DerRangeError < StandardError; end

    SPIFFE_SCHEME = 'spiffe://'
    MAX_SPIFFE_ID_LENGTH = 2048
    MAX_TRUST_DOMAIN_LENGTH = 255
    JWT_SVID_ALGORITHMS = %w[RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512].freeze

    JwtSvid = Struct.new(:spiffe_id, :claims, :audience, :expires_at)
    X509Svid = Struct.new(:spiffe_id, :certificate, :public_key_der) # public_key_der: base64url SPKI DER

    # SVIDs the verify functions returned: svid_to_holder accepts only these (identity-keyed)
    VERIFIED = ObjectSpace::WeakMap.new

    module_function

    def err(code, msg) = SpiffeError.new(code, msg)
    def b64u(bin) = AtlasPca.b64e(bin)

    def b64d_strict(s, len = nil)
      AtlasPca.b64d(s, len)
    rescue ArgumentError
      nil
    end

    def binary?(s) = s.is_a?(String) && s.encoding == Encoding::BINARY

    # ---- SPIFFE ID -------------------------------------------------------------------------------------------------------

    # Validate and parse `spiffe://<trust-domain>/<path>`; raises SpiffeError on anything malformed.
    def parse_spiffe_id(s)
      raise err('malformed_spiffe_id', 'SPIFFE ID must be a non-empty string') unless s.is_a?(String) && !s.empty?
      raise err('id_too_long', "SPIFFE ID exceeds #{MAX_SPIFFE_ID_LENGTH} bytes") if Js.len16(s) > MAX_SPIFFE_ID_LENGTH

      b = s.b # byte-wise: a lone surrogate never matches the ASCII grammar
      raise err('malformed_spiffe_id', "SPIFFE ID must begin with \"#{SPIFFE_SCHEME}\"") unless b.start_with?(SPIFFE_SCHEME)

      rest = b.byteslice(SPIFFE_SCHEME.bytesize..)
      slash = rest.index('/')
      td = slash.nil? ? rest : rest.byteslice(0, slash)
      path = slash.nil? ? ''.b : rest.byteslice(slash..)
      raise err('empty_trust_domain', 'SPIFFE ID has an empty trust domain') if td.empty?

      td_s = td.dup.force_encoding(s.encoding)
      raise err('trust_domain_too_long', "trust domain exceeds #{MAX_TRUST_DOMAIN_LENGTH} bytes") if Js.len16(td_s) > MAX_TRUST_DOMAIN_LENGTH
      unless td.match?(/\A[a-z0-9._-]+\z/n)
        raise err('invalid_trust_domain', "trust domain \"#{td_s.scrub}\" must be lowercase and contain only [a-z0-9._-]")
      end

      unless path.empty?
        raise err('invalid_path', 'SPIFFE ID path must not end with a trailing slash') if path.end_with?('/')

        path.split('/', -1)[1..].each do |seg|
          raise err('invalid_path', 'SPIFFE ID path must not contain an empty segment') if seg.empty?
          raise err('invalid_path', 'SPIFFE ID path must not contain a "." or ".." segment') if ['.', '..'].include?(seg)
          unless seg.match?(/\A[a-zA-Z0-9._-]+\z/n)
            raise err('invalid_path', "SPIFFE ID path segment \"#{seg.dup.force_encoding('UTF-8').scrub}\" contains an invalid character")
          end
        end
      end
      td = td.force_encoding('UTF-8')
      path = path.force_encoding('UTF-8')
      { 'id' => SPIFFE_SCHEME + td + path, 'trustDomain' => td, 'path' => path }.freeze
    end

    # ---- minimal DER reader for the X.509 extensions the SVID rules depend on ----------------------------------------------

    Tlv = Struct.new(:tag, :start, :end_)

    def read_tlv(buf, off, limit)
      raise DerRangeError, 'der: truncated header' if off + 2 > limit

      tag = buf.getbyte(off)
      raise DerRangeError, 'der: high-tag-number form is not supported' if (tag & 0x1F) == 0x1F

      ln = buf.getbyte(off + 1)
      p = off + 2
      if ln & 0x80 != 0
        n = ln & 0x7F
        raise DerRangeError, 'der: unsupported length form' if n.zero? || n > 4
        raise DerRangeError, 'der: truncated length' if p + n > limit

        ln = 0
        n.times { |i| ln = (ln * 256) + buf.getbyte(p + i) }
        p += n
      end
      raise DerRangeError, 'der: content exceeds container' if p + ln > limit

      Tlv.new(tag, p, p + ln)
    end

    def children(buf, parent)
      out = []
      off = parent.start
      while off < parent.end_
        t = read_tlv(buf, off, parent.end_)
        out << t
        off = t.end_
      end
      out
    end

    OID_KEY_USAGE = '551d0f'
    OID_SAN = '551d11'
    OID_BASIC_CONSTRAINTS = '551d13'
    # extension OIDs understood well enough to ignore when marked critical
    KNOWN_CRITICAL = [OID_KEY_USAGE, OID_SAN, OID_BASIC_CONSTRAINTS, '551d25', '551d0e', '551d23'].freeze

    # The X.509 facts the SVID rules need. bad_boolean: a BOOLEAN that is not one byte long (the reference's parser refuses it).
    CertFacts = Struct.new(:basic_constraints_present, :is_ca, :path_len, :key_usage_present, :digital_signature, :key_cert_sign,
                           :crl_sign, :uri_sans, :unknown_critical, :bad_boolean)

    # Read the facts from a DER certificate. Raises DerRangeError on malformed DER.
    def read_cert_facts(der)
      der = der.b
      cert = read_tlv(der, 0, der.bytesize)
      raise DerRangeError, 'der: certificate is not a single SEQUENCE' if cert.tag != 0x30 || cert.end_ != der.bytesize

      tbs = children(der, cert)[0]
      raise DerRangeError, 'der: missing tbsCertificate' if tbs.nil? || tbs.tag != 0x30

      ext_wrap = children(der, tbs).find { |f| f.tag == 0xA3 }
      facts = CertFacts.new(false, false, nil, false, false, false, false, [], [], false)
      return facts if ext_wrap.nil?

      ext_seq = children(der, ext_wrap)[0]
      raise DerRangeError, 'der: malformed extensions' if ext_seq.nil? || ext_seq.tag != 0x30

      seen = {}
      children(der, ext_seq).each do |ext|
        parts = children(der, ext)
        oid_t = parts[0]
        raise DerRangeError, 'der: malformed extension' if oid_t.nil? || oid_t.tag != 0x06

        oid = der.byteslice(oid_t.start, oid_t.end_ - oid_t.start).unpack1('H*')
        raise DerRangeError, 'der: duplicate extension' if seen[oid]

        seen[oid] = true
        facts.bad_boolean = true if parts.length == 3 && parts[1].tag == 0x01 && parts[1].end_ - parts[1].start != 1
        critical = parts.length == 3 && parts[1].tag == 0x01 && der.getbyte(parts[1].start) == 0xFF
        value_t = parts[-1]
        raise DerRangeError, 'der: malformed extension value' if value_t.tag != 0x04

        facts.unknown_critical << oid if critical && !KNOWN_CRITICAL.include?(oid)
        inner = read_tlv(der, value_t.start, value_t.end_)
        case oid
        when OID_BASIC_CONSTRAINTS
          facts.basic_constraints_present = true
          children(der, inner).each do |c|
            if c.tag == 0x01
              facts.bad_boolean = true if c.end_ - c.start != 1
              facts.is_ca = der.getbyte(c.start) == 0xFF
            elsif c.tag == 0x02
              n = 0
              (c.start...c.end_).each { |i| n = (n * 256) + der.getbyte(i) }
              facts.path_len = n
            end
          end
        when OID_KEY_USAGE
          raise DerRangeError, 'der: malformed keyUsage' if inner.tag != 0x03 || inner.end_ - inner.start < 2

          b0 = der.getbyte(inner.start + 1)
          facts.key_usage_present = true
          facts.digital_signature = (b0 & 0x80) != 0
          facts.key_cert_sign = (b0 & 0x04) != 0
          facts.crl_sign = (b0 & 0x02) != 0
        when OID_SAN
          children(der, inner).each do |gn|
            next unless gn.tag == 0x86

            facts.uri_sans << der.byteslice(gn.start, gn.end_ - gn.start).force_encoding('ISO-8859-1').encode('UTF-8')
          end
        end
      end
      facts
    end

    # ---- JWT-SVID --------------------------------------------------------------------------------------------------------

    EC_ALG = { 'ES256' => ['P-256', 'prime256v1', 32], 'ES384' => ['P-384', 'secp384r1', 48], 'ES512' => ['P-521', 'secp521r1', 66] }.freeze

    def b64u_bn(v)
      raw = v.is_a?(String) ? b64d_strict(v) : nil
      raise TypeError, 'invalid JWK member' if raw.nil?

      OpenSSL::BN.new(raw, 2)
    end

    def ec_public_key(curve, size, x, y)
      xs = x.to_s(2).rjust(size, "\x00")
      ys = y.to_s(2).rjust(size, "\x00")
      raise TypeError, 'EC coordinate is too long' if xs.bytesize > size || ys.bytesize > size

      group = OpenSSL::PKey::EC::Group.new(curve)
      pt = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new("\x04".b + xs + ys, 2))
      raise TypeError, 'point is not on the curve' unless pt.on_curve?

      alg = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId('id-ecPublicKey'), OpenSSL::ASN1::ObjectId(curve)])
      OpenSSL::PKey.read(OpenSSL::ASN1::Sequence([alg, OpenSSL::ASN1::BitString(pt.to_octet_string(:uncompressed))]).to_der)
    rescue OpenSSL::OpenSSLError => e
      raise TypeError, e.message
    end

    # verify(data, signature) for a public JWK under a JWT-SVID `alg` (RS / PS / ES, 256 / 384 / 512).
    def svid_verifier(jwk, alg)
      raise TypeError, 'JWT-SVID key must be a JWK object' unless jwk.is_a?(Hash)

      bits = alg.is_a?(String) ? alg[2..] : nil
      raise TypeError, "unsupported algorithm #{alg}" unless %w[256 384 512].include?(bits) && %w[RS PS ES].include?(alg[0, 2])

      h = "SHA#{bits}"
      if alg.start_with?('ES')
        crv, curve, size = EC_ALG[alg]
        raise TypeError, "key does not match #{alg}" if jwk['kty'] != 'EC' || jwk['crv'] != crv

        pub = ec_public_key(curve, size, b64u_bn(jwk['x']), b64u_bn(jwk['y']))
        ver = lambda do |data, sig|
          next false unless sig.bytesize == 2 * size

          r = OpenSSL::BN.new(sig.byteslice(0, size), 2)
          s = OpenSSL::BN.new(sig.byteslice(size, size), 2)
          pub.verify(h, OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der, data)
        rescue OpenSSL::OpenSSLError
          false
        end
        return ver
      end
      raise TypeError, "key does not match #{alg}" if jwk['kty'] != 'RSA'

      n = b64u_bn(jwk['n'])
      e = b64u_bn(jwk['e']).to_i
      if n.num_bits < 2048 || n.num_bits > 16_384 || e.even? || e < 3 || e.bit_length > 32
        raise TypeError, "#{alg} requires an RSA key of 2048 bits or larger with a valid exponent"
      end

      alg_id = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId('rsaEncryption'), OpenSSL::ASN1::Null.new(nil)])
      body = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(n), OpenSSL::ASN1::Integer(OpenSSL::BN.new(e))]).to_der
      pub = begin
        OpenSSL::PKey.read(OpenSSL::ASN1::Sequence([alg_id, OpenSSL::ASN1::BitString(body)]).to_der)
      rescue OpenSSL::OpenSSLError => ex
        raise TypeError, ex.message
      end
      pss = alg.start_with?('PS')
      lambda do |data, sig|
        pss ? pub.verify_pss(h, sig, data, salt_length: :digest, mgf1_hash: h) : pub.verify(h, sig, data)
      rescue OpenSSL::OpenSSLError
        false
      end
    end

    # The key resolver over a JWKS: kid / kty / alg / use / key_ops / crv filtering; exactly one key must match (a one-element list).
    def create_local_jwk_set(jwks)
      unless jwks.is_a?(Hash) && jwks['keys'].is_a?(Array) && jwks['keys'].all? { |k| k.is_a?(Hash) }
        raise JoseError.new('ERR_JWKS_INVALID', 'JSON Web Key Set malformed')
      end

      keys = jwks['keys']
      lambda do |header, _token = nil|
        alg = header['alg']
        kid = header['kid']
        unless alg.is_a?(String) && %w[RS PS ES Ed].include?(alg[0, 2])
          raise JoseError.new('ERR_JOSE_NOT_SUPPORTED', 'Unsupported "alg" value for a JSON Web Key Set')
        end

        kty = { 'RS' => 'RSA', 'PS' => 'RSA', 'ES' => 'EC' }.fetch(alg[0, 2], 'OKP')
        out = keys.select do |k|
          ok = k['kty'] == kty
          ok &&= k['kid'] == kid if kid.is_a?(String)
          ok &&= k['alg'] == alg if k['alg'].is_a?(String)
          ok &&= k['use'] == 'sig' if k['use'].is_a?(String)
          ok &&= k['key_ops'].include?('verify') if k['key_ops'].is_a?(Array)
          ok &&= %w[Ed25519 Ed448].include?(k['crv']) if alg == 'EdDSA'
          ok &&= k['crv'] == EC_ALG[alg][0] if EC_ALG.key?(alg)
          ok
        end
        raise JoseError.new('ERR_JWKS_NO_MATCHING_KEY', 'no applicable key found in the JSON Web Key Set') if out.empty?
        # the reference's verifier does not iterate the candidates: ambiguity refuses
        raise JoseError.new('ERR_JWKS_MULTIPLE_MATCHING_KEYS', 'multiple matching keys found in the JSON Web Key Set') if out.length != 1
        raise JoseError.new('ERR_JWKS_INVALID', 'JSON Web Key Set members must be public keys') if out[0].key?('d')

        begin
          svid_verifier(out[0], alg) unless alg == 'EdDSA' # the key must import under this alg
        rescue TypeError, ArgumentError
          raise JoseError.new('ERR_JWKS_INVALID', 'JSON Web Key Set member cannot be imported')
        end
        out
      end
    end

    # A clock tolerance: seconds, or a period string like "30s" / "2 minutes" / "1 hour ago" (the library's grammar).
    def tolerance(v)
      v = Jose.secs(v) if v.is_a?(String)
      return 0 if v.nil?
      raise TypeError, 'Invalid clockTolerance option type' unless Js.num?(v)

      v
    end

    def now_sec(now)
      return Time.now.to_i if now.nil?
      return now.to_i if now.is_a?(Time)
      raise err('malformed_token', 'verifyJwtSvid: currentDate must be a valid Date') if Js.num?(now) && !now.to_f.finite?
      raise TypeError, 'current_date must be a Time or epoch seconds' unless Js.num?(now)

      now.floor
    end

    def jose_crit!(header)
      return unless header.key?('crit')

      crit = header['crit']
      unless crit.is_a?(Array) && !crit.empty? && crit.all? { |c| c.is_a?(String) && !c.empty? }
        raise JoseError.new('ERR_JWS_INVALID', '"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present')
      end

      crit.each do |p|
        raise JoseError.new('ERR_JOSE_NOT_SUPPORTED', "Extension Header Parameter \"#{p}\" is not recognized") if p != 'b64'
        raise JoseError.new('ERR_JWS_INVALID', 'Extension Header Parameter "b64" is missing') unless header.key?('b64')
        unless [true, false].include?(header['b64'])
          raise JoseError.new('ERR_JWS_INVALID', 'The "b64" (base64url-encode payload) Header Parameter must be a boolean')
        end
        raise JoseError.new('ERR_JWT_INVALID', 'JWTs MUST NOT use unencoded payload') if header['b64'] == false
      end
    end

    def claim_failed(m) = JoseError.new('ERR_JWT_CLAIM_VALIDATION_FAILED', m)

    # The library's jwtVerify claims stage for a JWT-SVID: aud presence and match, iat / nbf / exp.
    def jwt_claims_check(payload, audience, tol, epoch)
      raise claim_failed('missing required "aud" claim') unless payload.key?('aud')

      opts = audience.is_a?(String) ? [audience] : audience
      aud = payload['aud']
      ok = if aud.is_a?(String) then opts.include?(aud)
           elsif aud.is_a?(Array) then opts.any? { |o| aud.include?(o) }
           else false
           end
      raise claim_failed('unexpected "aud" claim value') unless ok
      raise claim_failed('"iat" claim must be a number') if payload.key?('iat') && !Js.num?(payload['iat'])

      if payload.key?('nbf')
        raise claim_failed('"nbf" claim must be a number') unless Js.num?(payload['nbf'])
        raise claim_failed('"nbf" claim timestamp check failed') if payload['nbf'] > epoch + tol
      end
      return unless payload.key?('exp')
      raise claim_failed('"exp" claim must be a number') unless Js.num?(payload['exp'])
      raise JoseError.new('ERR_JWT_EXPIRED', '"exp" claim timestamp check failed') if payload['exp'] <= epoch - tol
    end

    # Verify a JWT-SVID: signature against `key`, mandatory `aud`, `exp` / `nbf`, SPIFFE `sub` pinned to `trust_domain`.
    # Options: audience (String | Array), key (JWK Hash, or a callable(header, token) returning a JWK Hash or an Array of
    # JWKs), trust_domain, current_date, algorithms, clock_tolerance, revocation (callable(subject Hash) -> exactly false to
    # admit; present but not callable refuses).
    def verify_jwt_svid(token, opts)
      rev = opts['revocation']
      raise err('revocation_unavailable', 'revocation must be a function') if opts.key?('revocation') && !rev.respond_to?(:call)

      td = opts['trust_domain']
      unless td.is_a?(String) && !td.empty?
        raise err('missing_trust_domain', 'verify_jwt_svid requires `trust_domain` (an unpinned JWT-SVID would accept any trust domain the key signs for)')
      end

      audience = opts['audience']
      aud_list = audience.is_a?(String) ? [audience] : audience
      raise TypeError, 'audience must be a string or a list' unless aud_list.is_a?(Array)
      if aud_list.empty? || aud_list.any? { |a| !a.is_a?(String) || a.empty? }
        raise err('missing_audience', 'verify_jwt_svid requires a non-empty audience (JWT-SVID aud is mandatory)')
      end

      algorithms = opts['algorithms'].nil? ? JWT_SVID_ALGORITHMS : opts['algorithms']
      raise TypeError, 'algorithms must be a list' unless algorithms.is_a?(Array)

      bad = algorithms.find { |a| !a.is_a?(String) || a == 'none' || a.upcase.start_with?('HS') }
      if !bad.nil? || algorithms.empty?
        raise err('forbidden_algorithm', "JWT-SVIDs must not use #{bad.nil? ? 'an empty algorithm list' : bad}")
      end
      # an invalid clock or a non-finite tolerance makes every exp/nbf comparison pass
      cd = opts['current_date']
      raise err('malformed_token', 'verifyJwtSvid: currentDate must be a valid Date') if Js.num?(cd) && !cd.to_f.finite?

      ct = opts['clock_tolerance']
      raise err('malformed_token', 'verifyJwtSvid: clockTolerance must be a finite number >= 0') if Js.num?(ct) && !(ct.to_f.finite? && ct >= 0)

      parsed = begin
        Jose.assert_canonical_compact_jws(token) # canonical-spelling gate BEFORE the signature check
      rescue StandardError => e
        raise err('malformed_token', e.message)
      end
      header = parsed['header']
      payload = parsed['payload']
      jose_crit!(header)
      alg = header['alg']
      raise JoseError.new('ERR_JWS_INVALID', 'JWS "alg" (Algorithm) Header Parameter missing or invalid') unless alg.is_a?(String) && !alg.empty?
      raise JoseError.new('ERR_JOSE_ALG_NOT_ALLOWED', '"alg" (Algorithm) Header Parameter value not allowed') unless algorithms.include?(alg)

      key = opts['key']
      resolver = key.respond_to?(:call)
      k = resolver ? key.call(header, token) : key
      cands = resolver && k.is_a?(Array) ? k : [k]
      raise JoseError.new('ERR_JWKS_NO_MATCHING_KEY', 'no applicable key found in the JSON Web Key Set') if cands.empty?

      verifiers = cands.map { |x| svid_verifier(x, alg) }
      p, pl, sg = parsed['segments']
      sig = b64d_strict(sg)
      raise JoseError.new('ERR_JWS_INVALID', 'Failed to base64url decode the signature') if sig.nil?

      data = "#{p}.#{pl}".b
      unless verifiers.any? { |v| v.call(data, sig) }
        raise JoseError.new('ERR_JWS_SIGNATURE_VERIFICATION_FAILED', 'signature verification failed')
      end

      jwt_claims_check(payload, audience, tolerance(opts['clock_tolerance']), now_sec(opts['current_date']))
      # JWT-SVID section 3: `typ`, when present, must be JWT or JOSE
      if header.key?('typ') && !%w[JWT JOSE].include?(header['typ'])
        raise err('invalid_typ', "JWT-SVID header typ must be JWT or JOSE, got '#{header['typ']}'")
      end

      exp = payload['exp']
      raise err('missing_exp', 'JWT-SVID is missing the required "exp" claim') unless Js.num?(exp)

      sub = payload['sub']
      raise err('invalid_subject', 'JWT-SVID "sub" must be a string SPIFFE ID') unless sub.is_a?(String)

      id = begin
        parse_spiffe_id(sub)
      rescue SpiffeError => e
        raise err('invalid_subject', "JWT-SVID \"sub\" is not a valid SPIFFE ID: #{e.message}")
      end
      if id['trustDomain'] != td
        raise err('trust_domain_mismatch', "JWT-SVID trust domain \"#{id['trustDomain']}\" does not match expected \"#{td}\"")
      end

      aud = payload['aud']
      out = JwtSvid.new(id, payload, aud.is_a?(String) ? [aud] : aud, exp).freeze
      if opts.key?('revocation')
        subject = { 'spiffe_id' => id['id'] }
        subject['jti'] = payload['jti'] if payload['jti'].is_a?(String)
        subject['expires_at'] = exp
        subject['token_hash'] = b64u(OpenSSL::Digest::SHA256.digest(token.b))
        verdict = begin
          rev.call(subject)
        rescue StandardError => e
          raise err('revocation_unavailable', "revocation check failed: #{e.message}")
        end
        raise err('svid_revoked', "JWT-SVID for #{id['id']} is revoked") if verdict.equal?(true)
        raise err('revocation_unavailable', 'revocation check did not return a boolean') unless verdict.equal?(false)
      end
      VERIFIED[out] = true
      out
    end

    # ---- X.509-SVID ------------------------------------------------------------------------------------------------------

    PEM_CERT_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/

    # A certificate from PEM text (the first CERTIFICATE block) or DER bytes (a binary String; a PEM held in one is read as PEM).
    def to_certificate(x)
      if x.is_a?(String) && !binary?(x)
        m = PEM_CERT_RE.match(x.scrub)
        raise ArgumentError, 'no PEM certificate found' if m.nil?

        Attest::Cert.from_pem(m[0])
      elsif binary?(x)
        return to_certificate(x.dup.force_encoding('ISO-8859-1').encode('UTF-8')) if x.lstrip.start_with?('-----BEGIN'.b)

        Attest::Cert.new(x)
      else
        raise TypeError, 'certificate must be PEM text or DER bytes'
      end
    rescue StandardError => e
      raise err('malformed_certificate', "cannot parse certificate: #{e.message}")
    end

    def facts_of(cert)
      facts = begin
        read_cert_facts(cert.raw)
      rescue StandardError => e
        raise err('malformed_certificate', "cannot read certificate extensions: #{e.message}")
      end
      raise err('malformed_certificate', 'cannot parse certificate: malformed BOOLEAN') if facts.bad_boolean

      facts
    end

    # The X509-SVID leaf rules (SPIFFE X509-SVID section 4.3).
    def validate_leaf(cert)
      f = facts_of(cert)
      unless f.unknown_critical.empty?
        raise err('unsupported_critical_extension', "certificate has an unsupported critical extension (#{f.unknown_critical.join(', ')})")
      end
      raise err('no_uri_san', 'X.509-SVID certificate has no URI SAN') if f.uri_sans.empty?
      if f.uri_sans.length > 1
        raise err('multiple_uri_san', "X.509-SVID certificate must have exactly one URI SAN, found #{f.uri_sans.length}")
      end

      id = parse_spiffe_id(f.uri_sans[0])
      raise err('leaf_root_path', 'X.509-SVID leaf SPIFFE ID must have a non-root path') if id['path'].empty?
      raise err('leaf_is_ca', 'leaf certificate must not have the CA flag set to true') if f.is_ca
      raise err('leaf_no_digital_signature', "leaf certificate must have 'digitalSignature' set as key usage") unless f.digital_signature
      raise err('leaf_cert_sign', "leaf certificate must not have 'keyCertSign' set as key usage") if f.key_cert_sign
      raise err('leaf_crl_sign', "leaf certificate must not have 'cRLSign' set as key usage") if f.crl_sign

      id
    end

    # Parse an X.509-SVID (PEM text or DER bytes) and apply the leaf rules. Does NOT check chain, validity or revocation.
    def parse_x509_svid(cert)
      c = to_certificate(cert)
      X509Svid.new(validate_leaf(c), c, b64u(c.spki_der)).freeze
    end

    def certs_of(x)
      if x.is_a?(String) && !binary?(x)
        blocks = x.scrub.scan(PEM_CERT_RE)
        raise err('malformed_certificate', 'no PEM certificate found') if blocks.empty?

        return blocks.map { |b| to_certificate(b) }
      end
      [to_certificate(x)]
    end

    def validate_signer(cert, label)
      f = facts_of(cert)
      unless f.unknown_critical.empty?
        raise err('unsupported_critical_extension', "#{label} has an unsupported critical extension (#{f.unknown_critical.join(', ')})")
      end
      raise err('chain_not_ca', "#{label} must have the CA flag set to true") unless f.is_ca
      raise err('chain_no_key_cert_sign', "#{label} must have 'keyCertSign' set as key usage") unless f.key_usage_present && f.key_cert_sign

      f
    end

    ED25519_SPKI_PREFIX = ['302a300506032b6570032100'].pack('H*').freeze
    ED25519_ALG = ['300506032b6570'].pack('H*').freeze

    def ed25519_raw(cert)
      spki = cert.spki_der
      spki.bytesize == 44 && spki.start_with?(ED25519_SPKI_PREFIX) ? spki.byteslice(12, 32) : nil
    end

    def ed25519_verify(raw, msg, sig)
      OpenSSL::PKey.new_raw_public_key('ED25519', raw).verify(nil, sig, msg)
    rescue OpenSSL::OpenSSLError
      false
    end

    def signed_by(cert, issuer)
      if cert.sig_alg_der == ED25519_ALG && cert.inner_sig_alg_der == ED25519_ALG # Ed25519 certificate signatures (X509_verify rules)
        raw = ed25519_raw(issuer)
        return cert.sig_unused.zero? && cert.check_issued(issuer) && !raw.nil? && ed25519_verify(raw, cert.tbs_der, cert.signature)
      end
      cert.check_issued(issuer) && cert.verify(issuer.public_key)
    rescue StandardError # an unusable issuer key never verifies
      false
    end

    # The serial in the form OpenSSL prints: uppercase hex, no leading zeros, even length.
    def serial_hex(cert)
      h = cert.serial.unpack1('H*').upcase.sub(/\A0+/, '')
      h = '0' if h.empty?
      h.length.odd? ? "0#{h}" : h
    end

    def fingerprint256(cert) = OpenSSL::Digest::SHA256.hexdigest(cert.raw).upcase.scan(/../).join(':')

    def now_ms(opts)
      return opts['now_ms'].to_f if Js.num?(opts['now_ms'])

      now = opts['now']
      return Time.now.to_f * 1000 if now.nil?
      return now.to_f * 1000 if now.is_a?(Time)
      raise TypeError, 'now must be a Time or epoch seconds' unless Js.num?(now)

      now.to_f * 1000
    end

    # Verify an X.509-SVID against a trust bundle (SPIFFE X509-SVID section 4): leaf rules, trust domain, validity of every
    # certificate, signatures, CA / keyCertSign / pathLenConstraint of every signer, and an anchor in `roots`. `chain` is PEM
    # text or an Array of PEM / DER items, leaf first. Options: trust_domain, roots, now_ms / now, max_chain_length (8),
    # revocation (callable(subject Hash) -> exactly false to admit, run LAST for every certificate; present but not callable
    # refuses).
    def verify_x509_svid(chain, opts)
      rev = opts['revocation']
      raise err('revocation_unavailable', 'revocation must be a function') if opts.key?('revocation') && !rev.respond_to?(:call)

      at = now_ms(opts)
      items = if chain.is_a?(String) && !binary?(chain) then certs_of(chain)
              elsif chain.is_a?(Array) then chain.flat_map { |x| certs_of(x) }
              else raise TypeError, 'chain must be PEM text or a list'
              end
      raise err('chain_empty', 'certificate chain is empty') if items.empty?

      max_len = opts['max_chain_length'].nil? ? 8 : opts['max_chain_length']
      raise TypeError, 'max_chain_length must be a number' unless Js.num?(max_len)
      raise err('chain_too_long', 'certificate chain is too long') unless items.length <= max_len

      leaf = items[0]
      id = validate_leaf(leaf)
      td = opts['trust_domain']
      raise err('chain_trust_domain_mismatch', "SPIFFE ID trust domain '#{id['trustDomain']}' is not '#{td}'") if id['trustDomain'] != td

      raise TypeError, 'roots must be a list' unless opts['roots'].is_a?(Array)

      roots = opts['roots'].flat_map { |r| certs_of(r) }
      raise err('chain_untrusted_root', 'trust bundle has no X.509 authorities') if roots.empty?

      items.each do |c|
        raise err('chain_expired', 'a certificate in the chain is not within its validity period') unless Attest::Der.x509_valid_at?(c.raw, at)
      end
      # structure first: every signer is a CA with keyCertSign and a satisfied pathLenConstraint
      (1...items.length).each do |i|
        f = validate_signer(items[i], "signing certificate ##{i}")
        raise err('chain_path_len', "signing certificate ##{i} pathLenConstraint exceeded") if !f.path_len.nil? && i - 1 > f.path_len
      end
      below = items.length - 1
      (0...(items.length - 1)).each do |i|
        raise err('chain_signature', "certificate ##{i} is not signed by certificate ##{i + 1}") unless signed_by(items[i], items[i + 1])
      end
      top = items[-1]
      if items.length == 1 && roots.any? { |r| r.raw == leaf.raw }
        raise err('chain_untrusted_root', 'a leaf certificate cannot be its own trust anchor')
      end

      top_is_anchor = items.length > 1 && roots.any? { |r| r.raw == top.raw }
      unless top_is_anchor
        signer = roots.find { |r| signed_by(top, r) }
        raise err('chain_untrusted_root', 'the chain does not lead to an authority in the trust bundle') if signer.nil?
        raise err('chain_expired', 'the trust bundle authority is not within its validity period') unless Attest::Der.x509_valid_at?(signer.raw, at)

        f = validate_signer(signer, 'trust bundle authority')
        raise err('chain_path_len', 'trust bundle authority pathLenConstraint exceeded') if !f.path_len.nil? && below > f.path_len
      end
      if opts.key?('revocation')
        items.each_with_index do |c, i|
          verdict = begin
            rev.call({ 'spiffe_id' => id['id'], 'serial_number' => serial_hex(c), 'fingerprint256' => fingerprint256(c),
                       'position' => i, 'is_leaf' => i.zero? })
          rescue StandardError => e
            raise err('revocation_unavailable', "revocation check failed: #{e.message}")
          end
          if verdict.equal?(true)
            raise err('svid_revoked', "X.509-SVID for #{id['id']} is revoked") if i.zero?

            raise err('chain_revoked', "signing certificate ##{i} of the chain is revoked")
          end
          raise err('revocation_unavailable', 'revocation check did not return a boolean') unless verdict.equal?(false)
        end
      end
      out = X509Svid.new(id, leaf, b64u(leaf.spki_der)).freeze
      VERIFIED[out] = true
      out
    end

    # ---- SPIFFE ID <-> PCA agent-holder identity ---------------------------------------------------------------------------

    def normalize_holder_key(k)
      if binary?(k)
        raise err('invalid_holder_key', 'holder key must be a 32-byte Ed25519 public key') unless k.bytesize == 32

        return b64u(k)
      end
      raw = b64d_strict(k, 32)
      raise err('invalid_holder_key', 'holder key must be a 32-byte Ed25519 public key encoded as base64url') if raw.nil?

      b64u(raw)
    end

    # Domain-separated message a workload signs with its SVID key to bind a PCA holder key to its SPIFFE ID (binary String).
    def holder_binding_message(spiffe_id, holder) = Js.utf8("pca-spiffe-holder-binding-v1\n#{spiffe_id}\n#{holder}")

    def proof_verifies(cert, msg, sig)
      raw = ed25519_raw(cert)
      return ed25519_verify(raw, msg, sig) unless raw.nil?

      key = cert.public_key
      case Attest::Common.key_type(key)
      when 'ec' then Attest::Common.ecdsa_verify_raw(key, sig, msg, key.group.curve_name == 'secp384r1' ? 'sha384' : 'sha256')
      when 'rsa' then Attest::Common.rsa_pkcs1_verify(key, sig, msg, 'sha256')
      else false
      end
    end

    # Bind a VERIFIED SVID (what verify_jwt_svid / verify_x509_svid returned; anything else is `unverified_svid`) to a PCA
    # holder. X.509 Ed25519: the holder IS the SVID key. Another key, or a different holder: opts['proof'], a base64url
    # signature by the SVID key over holder_binding_message (ECDSA is IEEE P1363). JWT-SVID: the token's cnf.jwk must equal the
    # holder unless opts['accept_unbound_jwt_holder'] is true.
    def svid_to_holder(svid, holder_key = nil, opts = nil)
      opts ||= {}
      unless (svid.is_a?(JwtSvid) || svid.is_a?(X509Svid)) && VERIFIED.key?(svid)
        raise err('unverified_svid', 'svid_to_holder needs the result of verify_jwt_svid / verify_x509_svid (a string, a parsed-only SVID or a hand-built object is not accepted)')
      end

      id = svid.spiffe_id
      if svid.is_a?(X509Svid)
        cert_raw = ed25519_raw(svid.certificate)
        cert_ed = cert_raw.nil? ? nil : b64u(cert_raw)
        if holder_key.nil?
          if cert_ed.nil?
            raise err('invalid_holder_key', 'the X.509-SVID key is not Ed25519, so the holder cannot be derived from it: pass holder_key and opts["proof"]')
          end

          holder = cert_ed
        else
          holder = normalize_holder_key(holder_key)
          if cert_ed.nil? || cert_ed != holder
            proof = opts['proof']
            unless proof.is_a?(String)
              raise err('holder_binding_failed', 'the holder key is not the SVID key: opts["proof"] (a signature by the SVID key over holder_binding_message) is required')
            end

            sig = b64d_strict(proof)
            ok = begin
              !sig.nil? && proof_verifies(svid.certificate, holder_binding_message(id['id'], holder), sig) == true
            rescue StandardError
              false
            end
            raise err('holder_binding_failed', 'opts["proof"] does not verify under the X.509-SVID key') unless ok
          end
        end
      else
        raise err('invalid_holder_key', 'a JWT-SVID has no key of its own: pass holder_key') if holder_key.nil?

        holder = normalize_holder_key(holder_key)
        cnf = svid.claims['cnf']
        jwk = cnf.is_a?(Hash) ? cnf['jwk'] : nil
        bound = jwk.is_a?(Hash) && jwk['kty'] == 'OKP' && jwk['crv'] == 'Ed25519' && jwk['x'].is_a?(String) && jwk['x'] == holder
        unless bound || opts['accept_unbound_jwt_holder'] == true
          raise err('holder_binding_failed', 'the JWT-SVID carries no cnf.jwk equal to the holder key (set accept_unbound_jwt_holder only if the key is authenticated by other means)')
        end
      end
      { 'holder' => holder, 'spiffeId' => id['id'], 'trustDomain' => id['trustDomain'], 'path' => id['path'] }
    end

    # The validated, canonical SPIFFE ID a holder record ({'spiffeId' => ...}) was bridged from.
    def holder_to_spiffe_id(holder) = parse_spiffe_id(holder.is_a?(Hash) ? holder['spiffeId'] : nil)['id']

    # The SPIFFE ID of a VERIFIED SVID bound to `leaf_holder` (the key that signed the PCActn); refuses otherwise.
    def spiffe_id_for_holder(svid, leaf_holder, opts = nil)
      h = svid_to_holder(svid, leaf_holder, opts)
      raise err('holder_binding_failed', 'the SVID is not bound to the PCActn leaf holder') if h['holder'] != leaf_holder

      h['spiffeId']
    end

    # A discharge-issuer pin for a workload: its own Ed25519 SVID key and SPIFFE ID, class `workload`.
    def workload_discharge_pin(label, svid)
      h = svid_to_holder(svid)
      { 'label' => label, 'class' => 'workload', 'pk' => h['holder'], 'spiffe_id' => h['spiffeId'] }
    end

    # ---- trust-bundle cache (fails closed) ---------------------------------------------------------------------------------

    def check_windows!(refresh_ms, max_stale_ms, code)
      ok = Js.num?(refresh_ms) && refresh_ms.to_f.finite? && refresh_ms.positive? &&
           Js.num?(max_stale_ms) && max_stale_ms.to_f.finite? && max_stale_ms >= refresh_ms
      raise err(code, 'refresh_ms must be > 0 and max_stale_ms >= refresh_ms (both finite)') unless ok
    end

    def clock_ms = (Time.now.to_f * 1000)

    # A trust-bundle cache that fails closed: before the first successful fetch, or past max_stale_ms after the last one,
    # every call raises `trust_bundle_unavailable` (fetch failed) or `trust_bundle_invalid` (empty / malformed). A refresh
    # REPLACES the bundle (never merged). A bundle is {'jwks' => {'keys' => [...]}, 'x509_authorities' => [PEM or DER, ...]}.
    class TrustBundleSource
      def initialize(opts)
        fetch = opts.is_a?(Hash) ? opts['fetch'] : nil
        raise Spiffe.err('trust_bundle_unavailable', 'create_trust_bundle_source requires `fetch`') unless fetch.respond_to?(:call)

        Spiffe.check_windows!(opts['refresh_ms'], opts['max_stale_ms'], 'trust_bundle_unavailable')
        @fetch = fetch
        @refresh_ms = opts['refresh_ms']
        @max_stale_ms = opts['max_stale_ms']
        @now = opts['now'] || -> { Spiffe.clock_ms }
        @good = nil
        @last_failure = nil
        @lock = Mutex.new
      end

      # Key resolver for verify_jwt_svid's `key` option (pass `source.method(:jwt_key)`).
      def jwt_key(header, token = nil)
        jwks = current['jwks']
        unless jwks.is_a?(Hash) && jwks['keys'].is_a?(Array) && !jwks['keys'].empty?
          raise Spiffe.err('trust_bundle_invalid', 'trust bundle has no JWT authorities')
        end

        Spiffe.create_local_jwk_set(jwks).call(header, token)
      end

      # Authorities for verify_x509_svid's `roots` option.
      def x509_roots
        roots = current['x509_authorities']
        raise Spiffe.err('trust_bundle_invalid', 'trust bundle has no X.509 authorities') unless roots.is_a?(Array) && !roots.empty?

        roots.dup
      end

      private

      def usable?(b)
        return false unless b.is_a?(Hash)

        j = b['jwks']
        raise TypeError, 'jwks is null' if b.key?('jwks') && j.nil? # the reference reads `.keys` of it: a failed fetch
        x = b['x509_authorities']
        (j.is_a?(Hash) && j['keys'].is_a?(Array) && !j['keys'].empty?) || (x.is_a?(Array) && !x.empty?)
      end

      def refresh
        b = @fetch.call
        raise Spiffe.err('trust_bundle_invalid', 'fetched trust bundle has no authorities') unless usable?(b)

        @good = [b, @now.call]
        @last_failure = nil
      rescue StandardError => e
        @last_failure = e.is_a?(SpiffeError) ? e : Spiffe.err('trust_bundle_unavailable', "trust bundle fetch failed: #{e.message}")
      end

      def current
        @lock.synchronize do
          refresh if @good.nil? || !(@now.call - @good[1] < @refresh_ms)
          if @good.nil? || !((age = @now.call - @good[1]).to_f.finite? && age <= @max_stale_ms)
            raise @last_failure || Spiffe.err('trust_bundle_unavailable', 'no trust bundle available')
          end

          @good[0]
        end
      end
    end

    def create_trust_bundle_source(opts) = TrustBundleSource.new(opts)

    # ---- revocation source (fails closed) ----------------------------------------------------------------------------------

    def norm_hex(s) = s.delete(':').upcase
    def norm_serial(s) = norm_hex(s).sub(/\A0+(?=.)/m, '')

    # A revocation snapshot cache that fails closed, in the shape of TrustBundleSource. The fetched list is a Hash of optional
    # String lists: fingerprints, serials, spiffe_ids, jtis, token_hashes. `x509` uses the cached snapshot (call
    # `ensure_fresh` first); `jwt` refreshes when due.
    class RevocationSource
      Snapshot = Struct.new(:fingerprints, :serials, :spiffe_ids, :jtis, :token_hashes)

      def initialize(opts)
        fetch = opts.is_a?(Hash) ? opts['fetch'] : nil
        raise Spiffe.err('revocation_unavailable', 'create_revocation_source requires `fetch`') unless fetch.respond_to?(:call)

        Spiffe.check_windows!(opts['refresh_ms'], opts['max_stale_ms'], 'revocation_unavailable')
        @fetch = fetch
        @refresh_ms = opts['refresh_ms']
        @max_stale_ms = opts['max_stale_ms']
        @now = opts['now'] || -> { Spiffe.clock_ms }
        @good = nil
        @last_failure = nil
        @lock = Mutex.new
      end

      # Fetch now; raises `revocation_unavailable` when the fetch fails or returns a malformed snapshot.
      def refresh
        @lock.synchronize do
          run
          raise @last_failure unless @last_failure.nil?
        end
      end

      # Fetch when older than refresh_ms; raises when no snapshot younger than max_stale_ms exists afterwards.
      def ensure_fresh
        @lock.synchronize do
          run if @good.nil? || !(@now.call - @good[1] < @refresh_ms)
          usable
        end
        nil
      end

      def x509(s)
        snap = usable
        snap.fingerprints.include?(Spiffe.norm_hex(s['fingerprint256'])) || snap.serials.include?(Spiffe.norm_serial(s['serial_number'])) ||
          snap.spiffe_ids.include?(s['spiffe_id'])
      end

      def jwt(s)
        ensure_fresh
        snap = usable
        snap.spiffe_ids.include?(s['spiffe_id']) || (!s['jti'].nil? && snap.jtis.include?(s['jti'])) || snap.token_hashes.include?(s['token_hash'])
      end

      private

      def list_of(raw, key)
        return [] unless raw.key?(key)

        v = raw[key]
        unless v.is_a?(Array) && v.all? { |x| x.is_a?(String) }
          raise Spiffe.err('revocation_unavailable', "revocation list field \"#{key}\" must be an array of strings")
        end

        v
      end

      def snapshot(lst)
        raise Spiffe.err('revocation_unavailable', 'revocation list must be an object') unless lst.is_a?(Hash)

        Snapshot.new(list_of(lst, 'fingerprints').map { |x| Spiffe.norm_hex(x) }, list_of(lst, 'serials').map { |x| Spiffe.norm_serial(x) },
                     list_of(lst, 'spiffe_ids'), list_of(lst, 'jtis'), list_of(lst, 'token_hashes'))
      end

      def run
        @good = [snapshot(@fetch.call), @now.call]
        @last_failure = nil
      rescue StandardError => e
        @last_failure = e.is_a?(SpiffeError) ? e : Spiffe.err('revocation_unavailable', "revocation fetch failed: #{e.message}")
      end

      def usable
        if @good.nil? || !((age = @now.call - @good[1]).to_f.finite? && age <= @max_stale_ms)
          raise @last_failure || Spiffe.err('revocation_unavailable', 'no revocation snapshot available')
        end

        @good[0]
      end
    end

    def create_revocation_source(opts) = RevocationSource.new(opts)

    # ---- evidence for blueprint admission ----------------------------------------------------------------------------------

    # A workload admitted under its verified SPIFFE ID: the SVID is verified ({'kind' => 'x509', 'chain', 'verify', 'bind'?}
    # or {'kind' => 'jwt', 'token', 'verify', 'bind'?}) then bound to the INSTANCE KEY. Anything unverifiable, unbound or for
    # another key is {'ok' => false, 'bound' => false, 'reason' => code}.
    def spiffe_admission_evidence(e, instance_key)
      svid = e['kind'] == 'x509' ? verify_x509_svid(e['chain'], e['verify']) : verify_jwt_svid(e['token'], e['verify'])
      h = svid_to_holder(svid, instance_key, e['bind'] || {})
      return { 'ok' => false, 'bound' => false, 'reason' => 'SVID is bound to a different key' } if h['holder'] != instance_key

      { 'ok' => true, 'bound' => true, 'identity' => { 'spiffe_id' => h['spiffeId'] } }
    rescue StandardError => ex
      code = ex.respond_to?(:code) ? ex.code : nil
      { 'ok' => false, 'bound' => false, 'reason' => code.is_a?(String) ? code : ex.class.name.split('::').last }
    end
  end
end
