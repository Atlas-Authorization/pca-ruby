# frozen_string_literal: true

require 'openssl'
require_relative 'js_compat'

# The JOSE layer the protocol bridges share: the canonical compact-JWS gate (one accepted spelling per token, run BEFORE any
# signature check) and a JWS / JWT sign + verify with the reference JOSE library's semantics (check order and messages):
# crit, alg allow-list, signature, typ, required claims, iss / sub / aud, iat / nbf / exp with clock tolerance. Keys: a raw
# 32-byte Ed25519 public key (binary String), a JWK Hash (OKP Ed25519, EC P-256/384/521, RSA >= 2048 bits) or an
# OpenSSL::PKey. Crypto is OpenSSL only.
module AtlasPca
  module Jose
    # A refusal of the JOSE layer (bad header, algorithm not allowed, bad key, signature or claim failure).
    # #code is the reference library's stable code for the same failure (ERR_JWS_INVALID, ERR_JWT_EXPIRED ...), by the failure's text.
    class Error < StandardError
      CODES = [
        [/\A"exp" claim timestamp check failed\z/, 'ERR_JWT_EXPIRED'],
        [/\AJWTs MUST NOT use unencoded payload|\AJWT Claims Set must be/, 'ERR_JWT_INVALID'],
        [/ claim (must be a number|timestamp check failed)|\Amissing required ".*" claim\z|\Aunexpected ".*" (claim|JWT header) value\z/, 'ERR_JWT_CLAIM_VALIDATION_FAILED'],
        [/\Asignature verification failed\z/, 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED'],
        [/\A"alg" \(Algorithm\) Header Parameter value not allowed\z/, 'ERR_JOSE_ALG_NOT_ALLOWED'],
        [/\AJWS |\A"crit" \(Critical\) Header Parameter MUST|\AThe "b64" /, 'ERR_JWS_INVALID'],
        [/is not recognized\z|is not supported either by JOSE|"kty" \(Key Type\) Parameter missing or unsupported/, 'ERR_JOSE_NOT_SUPPORTED'],
        [/\Ano applicable key found in the JSON Web Key Set/, 'ERR_JWKS_NO_MATCHING_KEY'],
        [/\Amultiple matching keys found/, 'ERR_JWKS_MULTIPLE_MATCHING_KEYS'],
        [/\AJSON Web Key Set/, 'ERR_JWKS_INVALID'],
        [/Parameter missing or invalid\z/, 'ERR_JWK_INVALID']
      ].freeze

      def code = CODES.find { |re, _| re.match?(message) }&.last
    end

    class CanonicalJwsError < StandardError
      attr_reader :reason

      def initialize(reason, detail = nil)
        @reason = reason
        super("non-canonical compact JWS: #{reason}#{detail ? " (#{detail})" : ''}")
      end
    end

    DEFAULT_MAX_JWS_BYTES = 64 * 1024
    ALGS = {
      'EdDSA' => nil,
      'ES256' => ['prime256v1', 'SHA256', 32], 'ES384' => ['secp384r1', 'SHA384', 48], 'ES512' => ['secp521r1', 'SHA512', 66],
      'RS256' => ['rsa', 'SHA256'], 'RS384' => ['rsa', 'SHA384'], 'RS512' => ['rsa', 'SHA512'],
      'PS256' => ['pss', 'SHA256'], 'PS384' => ['pss', 'SHA384'], 'PS512' => ['pss', 'SHA512']
    }.freeze
    CURVES = { 'P-256' => 'prime256v1', 'P-384' => 'secp384r1', 'P-521' => 'secp521r1' }.freeze
    UNSET = Object.new.freeze

    module_function

    def b64u(bin) = AtlasPca.b64e(bin)

    # Lenient base64url (the JOSE library's decoder: padding / whitespace ignored, the standard alphabet tolerated).
    def lenient_b64d(s)
      t = s.to_s.tr('+/', '-_').delete("= \t\n\r")
      Base64.urlsafe_decode64(t + ('=' * (-t.length % 4)))
    rescue ArgumentError
      raise Error, 'Failed to base64url decode'
    end

    # ---- canonical gate ----

    def decode_canonical_base64url(seg)
      raise CanonicalJwsError, 'bad-character' unless seg.match?(/\A[A-Za-z0-9_-]*\z/)
      raise CanonicalJwsError.new('non-canonical-base64url', 'impossible length') if seg.length % 4 == 1

      bin = begin
        Base64.urlsafe_decode64(seg + ('=' * (-seg.length % 4)))
      rescue ArgumentError # non-zero trailing bits: the strict decoder refuses what a lenient one would re-spell
        raise CanonicalJwsError, 'non-canonical-base64url'
      end
      raise CanonicalJwsError, 'non-canonical-base64url' unless b64u(bin) == seg

      bin
    end

    def parse_json_bytes(bin)
      raise CanonicalJwsError, 'bom' if bin.byteslice(0, 3) == "\xEF\xBB\xBF".b

      text = bin.dup.force_encoding('UTF-8')
      raise CanonicalJwsError, 'bad-utf8' unless text.valid_encoding?

      begin
        AtlasPca.parse_json(text, any_top: true)
      rescue AtlasPca::Malformed => e
        raise CanonicalJwsError.new('bad-json', e.message)
      end
    end

    def decode_canonical_json_segment(seg) = parse_json_bytes(decode_canonical_base64url(seg))

    def as_object(v)
      raise CanonicalJwsError, 'not-an-object' unless v.is_a?(Hash)

      v
    end

    # {'segments', 'header', 'payload'?} of the one canonical spelling of a compact JWS (parts 3) / JWE (parts 5).
    def assert_canonical_compact_jws(token, parts: 3, max_bytes: DEFAULT_MAX_JWS_BYTES, payload: 'json')
      raise CanonicalJwsError, 'not-a-string' unless token.is_a?(String)
      raise CanonicalJwsError, 'too-long' if token.length > max_bytes

      segments = token.split('.', -1)
      raise CanonicalJwsError.new('bad-segment-count', "#{segments.length} != #{parts}") unless segments.length == parts

      bytes = segments.each_with_index.map do |seg, i|
        if seg.empty?
          next ''.b if parts == 5 && i == 1

          raise CanonicalJwsError.new('empty-segment', "segment #{i}")
        end
        decode_canonical_base64url(seg)
      end
      out = { 'segments' => segments, 'header' => as_object(parse_json_bytes(bytes[0])) }
      out['payload'] = as_object(parse_json_bytes(bytes[1])) if parts == 3 && payload == 'json'
      out
    end

    # Whether a key carries its private half. The generic key class has no `private?` in every OpenSSL binding (an Ed25519 / Ed448 key): the raw
    # private key answers then.
    def private_key?(key)
      return key.private? if key.respond_to?(:private?)

      !key.raw_private_key.nil?
    rescue StandardError
      false
    end

    def canonical_compact_jws?(token, **kw)
      assert_canonical_compact_jws(token, **kw)
      true
    rescue CanonicalJwsError
      false
    end

    # The protected header of a flattened / detached JWS (payload out of band), through the same gate.
    def assert_canonical_jws_segments(protected_b64u, signature_b64u, max_bytes: DEFAULT_MAX_JWS_BYTES)
      raise CanonicalJwsError, 'not-a-string' unless protected_b64u.is_a?(String) && signature_b64u.is_a?(String)
      raise CanonicalJwsError, 'too-long' if protected_b64u.length + signature_b64u.length + 1 > max_bytes
      raise CanonicalJwsError.new('empty-segment', 'segment 0') if protected_b64u.empty?
      raise CanonicalJwsError.new('empty-segment', 'segment 2') if signature_b64u.empty?

      decode_canonical_base64url(signature_b64u)
      as_object(parse_json_bytes(decode_canonical_base64url(protected_b64u)))
    end

    # ---- keys ----

    def b64int(s)
      raise Error, 'JWK member must be a string' unless s.is_a?(String)

      OpenSSL::BN.new(lenient_b64d(s), 2)
    end

    def spki(alg_seq, bits) = OpenSSL::ASN1::Sequence([alg_seq, OpenSSL::ASN1::BitString(bits)]).to_der

    # A verification key from a PUBLIC JWK.
    def public_key_from_jwk(jwk)
      raise Error, 'JSON Web Key for this operation be a public JWK' if !jwk.is_a?(Hash) || !jwk['kty'].is_a?(String) || jwk.key?('d')

      case jwk['kty']
      when 'OKP'
        size = { 'Ed25519' => 32, 'Ed448' => 57 }[jwk['crv']]
        raise Error, 'unsupported OKP key' unless size && jwk['x'].is_a?(String)

        x = lenient_b64d(jwk['x'])
        raise Error, "invalid #{jwk['crv']} public key" unless x.bytesize == size

        OpenSSL::PKey.new_raw_public_key(jwk['crv'].upcase, x)
      when 'EC'
        curve = CURVES[jwk['crv']]
        raise Error, 'unsupported EC curve' if curve.nil?

        size = { 'prime256v1' => 32, 'secp384r1' => 48, 'secp521r1' => 66 }[curve]
        x = b64int(jwk['x']).to_s(2).rjust(size, "\x00")
        y = b64int(jwk['y']).to_s(2).rjust(size, "\x00")
        raise Error, 'invalid EC public key' unless x.bytesize == size && y.bytesize == size

        alg = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId('id-ecPublicKey'), OpenSSL::ASN1::ObjectId(curve)])
        begin
          k = OpenSSL::PKey.read(spki(alg, "\x04".b + x + y))
          k.check_key
          k
        rescue OpenSSL::PKey::PKeyError, OpenSSL::PKey::ECError
          raise Error, 'invalid EC public key'
        end
      when 'RSA'
        rsa = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(b64int(jwk['n'])), OpenSSL::ASN1::Integer(b64int(jwk['e']))]).to_der
        alg = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId('rsaEncryption'), OpenSSL::ASN1::Null(nil)])
        begin
          OpenSSL::PKey.read(spki(alg, rsa))
        rescue OpenSSL::PKey::PKeyError
          raise Error, 'invalid RSA public key'
        end
      else raise Error, 'Unsupported "kty" (Key Type) Parameter value'
      end
    end

    def ed25519?(k) = k.is_a?(OpenSSL::PKey::PKey) && !k.is_a?(OpenSSL::PKey::EC) && !k.is_a?(OpenSSL::PKey::RSA) && k.oid == 'ED25519'
    # an EdDSA key (Ed25519 or Ed448)
    def eddsa?(k) = k.is_a?(OpenSSL::PKey::PKey) && !k.is_a?(OpenSSL::PKey::EC) && !k.is_a?(OpenSSL::PKey::RSA) && %w[ED25519 ED448].include?(k.oid)

    # An OpenSSL private key from a PRIVATE JWK (OKP Ed25519 / Ed448, EC, RSA with its CRT members).
    def private_key_from_jwk(jwk)
      raise Error, 'JSON Web Key for this operation be a private JWK' unless jwk.is_a?(Hash) && jwk['d'].is_a?(String)

      case jwk['kty']
      when 'OKP'
        size = { 'Ed25519' => 32, 'Ed448' => 57 }[jwk['crv']]
        d = lenient_b64d(jwk['d'])
        raise Error, 'invalid OKP private key' unless size && d.bytesize == size

        OpenSSL::PKey.new_raw_private_key(jwk['crv'].upcase, d)
      when 'EC'
        pub = public_key_from_jwk(jwk.except('d'))
        curve = CURVES[jwk['crv']]
        der = OpenSSL::ASN1::Sequence([
          OpenSSL::ASN1::Integer(1), OpenSSL::ASN1::OctetString(lenient_b64d(jwk['d'])),
          OpenSSL::ASN1::ObjectId(curve).tap { |o| o.tag = 0; o.tagging = :EXPLICIT; o.tag_class = :CONTEXT_SPECIFIC },
          OpenSSL::ASN1::BitString(pub.public_key.to_bn.to_s(2)).tap { |o| o.tag = 1; o.tagging = :EXPLICIT; o.tag_class = :CONTEXT_SPECIFIC }
        ]).to_der
        OpenSSL::PKey.read(der)
      when 'RSA'
        ints = %w[n e d p q dp dq qi].map { |k| OpenSSL::ASN1::Integer(b64int(jwk[k])) }
        OpenSSL::PKey.read(OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(0), *ints]).to_der)
      else raise Error, 'Unsupported "kty" (Key Type) Parameter value'
      end
    rescue OpenSSL::PKey::PKeyError, OpenSSL::ASN1::ASN1Error
      raise Error, 'invalid private JWK'
    end

    def jwk_matches!(alg, k)
      raise Error, 'Invalid key for this operation, when present its use must be sig' if k.key?('use') && k['use'] != 'sig'
      if k.key?('key_ops') && !(k['key_ops'].is_a?(Array) && k['key_ops'].include?('verify'))
        raise Error, 'Invalid key for this operation, when present its key_ops must include verify'
      end
      raise Error, "Invalid key for this operation, when present its alg must be #{alg}" if k.key?('alg') && k['alg'] != alg
    end

    # The embedded-`jwk` key resolver (jose EmbeddedJWK): the header's `jwk` must be a JSON object holding a public key.
    EMBEDDED_JWK = lambda do |header|
      j = header['jwk']
      raise Error, '"jwk" (JSON Web Key) Header Parameter must be a JSON object' unless j.is_a?(Hash)
      raise Error, '"jwk" (JSON Web Key) Header Parameter must be a public key' if j['kty'] == 'oct' || j.key?('d')

      public_key_from_jwk(j)
    end

    # Normalize a caller key to an OpenSSL public key valid for `alg`.
    def verify_key(alg, key)
      raise Error, 'Unsupported "alg" value for a JSON Web Signature Algorithm' unless ALGS.key?(alg)

      if key.is_a?(String)
        raise Error, 'Invalid key for this operation: raw bytes are only an Ed25519 public key' unless alg == 'EdDSA'
        raise Error, 'invalid Ed25519 public key' unless key.bytesize == 32

        return OpenSSL::PKey.new_raw_public_key('ED25519', key.b)
      end
      if key.is_a?(Hash)
        raise Error, 'Invalid key for this operation: a symmetric key' if key['kty'] == 'oct'

        jwk_matches!(alg, key)
        key = public_key_from_jwk(key)
      end
      raise Error, 'Invalid key for this operation' unless key.is_a?(OpenSSL::PKey::PKey)

      if alg == 'EdDSA'
        raise Error, 'Invalid key for this operation: EdDSA needs an Ed25519 or Ed448 key' unless eddsa?(key)

        return key
      end
      kind = ALGS[alg][0]
      if kind.start_with?('prime', 'secp')
        unless key.is_a?(OpenSSL::PKey::EC) && key.group.curve_name == kind
          raise Error, "Invalid key for this operation: #{alg} needs an EC #{kind} key"
        end
      else
        raise Error, "Invalid key for this operation: #{alg} needs an RSA key" unless key.is_a?(OpenSSL::PKey::RSA)
        raise Error, "#{alg} requires key modulusLength to be 2048 bits or larger" if key.n.num_bits < 2048
      end
      key
    end

    # Signature check only. Raises Error for an unusable key / algorithm; false for a bad signature.
    def jws_verify(alg, key, sig, data)
      k = verify_key(alg, key)
      return k.verify(nil, sig, data) if alg == 'EdDSA'

      kind, h, size = ALGS[alg]
      if size
        return false unless sig.bytesize == 2 * size

        r = OpenSSL::BN.new(sig.byteslice(0, size), 2)
        s = OpenSSL::BN.new(sig.byteslice(size, size), 2)
        return false if r.zero? || s.zero?

        k.verify(h, OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der, data)
      elsif kind == 'rsa'
        k.verify(h, sig, data)
      else
        k.verify_pss(h, sig, data, salt_length: :digest, mgf1_hash: h)
      end
    rescue OpenSSL::PKey::PKeyError
      false
    end

    # Sign `data` with a 32-byte Ed25519 seed (binary String), a private JWK or an OpenSSL private key matching `alg`.
    def jws_sign(alg, key, data)
      raise Error, 'Unsupported "alg" value for a JSON Web Signature Algorithm' unless ALGS.key?(alg)

      key = private_key_from_jwk(key) if key.is_a?(Hash)
      if alg == 'EdDSA'
        pk = if key.is_a?(String) && key.bytesize == 32
               OpenSSL::PKey.new_raw_private_key('ED25519', key.b)
             elsif eddsa?(key) && private_key?(key)
               key
             end
        raise Error, 'Invalid key for this operation: EdDSA needs an Ed25519 or Ed448 private key' if pk.nil?

        return pk.sign(nil, data)
      end
      kind, h, size = ALGS[alg]
      raise Error, 'Invalid key for this operation' unless key.is_a?(OpenSSL::PKey::PKey) && private_key?(key)

      if size
        raise Error, 'Invalid key for this operation' unless key.is_a?(OpenSSL::PKey::EC) && key.group.curve_name == kind

        r, s = OpenSSL::ASN1.decode(key.sign(h, data)).value.map { |x| x.value.to_s(2).rjust(size, "\x00") }
        return r + s
      end
      raise Error, 'Invalid key for this operation' unless key.is_a?(OpenSSL::PKey::RSA)
      raise Error, "#{alg} requires key modulusLength to be 2048 bits or larger" if key.n.num_bits < 2048

      kind == 'rsa' ? key.sign(h, data) : key.sign_pss(h, data, salt_length: :digest, mgf1_hash: h)
    end

    # SignJWT(payload).setProtectedHeader(header).sign(key): JSON in insertion order (JSON.stringify), compact.
    def sign_jwt(payload, header, key)
      alg = header.is_a?(Hash) ? header['alg'] : nil
      raise Error, 'JWS "alg" (Algorithm) Header Parameter missing or invalid' unless alg.is_a?(String) && !alg.empty?

      input = "#{b64u(Js.json(header).b)}.#{b64u(Js.json(payload).b)}"
      "#{input}.#{b64u(jws_sign(alg, key, input.b))}"
    end

    # ---- verify ----

    SECS_RE = /\A([+-])? ?([0-9]+|[0-9]+\.[0-9]+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?\z/i
    UNIT = { 's' => 1, 'm' => 60, 'h' => 3600, 'd' => 86_400, 'w' => 604_800, 'y' => 31_557_600 }.freeze

    def secs(str)
      m = SECS_RE.match(str)
      raise TypeError, 'Invalid time period format' if m.nil? || (m[4] && m[1])

      u = m[3].downcase
      k = %w[y w d h m].find { |c| u.start_with?(c) } || 's'
      n = (m[2].to_f * UNIT[k]) + 0.5
      n = n.floor if n.finite? # an absurdly long digit string is Infinity, as in JS
      m[1] == '-' || m[4] == 'ago' ? -n : n
    end

    # epoch(new Date(ms)): an out-of-range clock is an Invalid Date (NaN: every time comparison is false).
    def epoch_of_ms(ms)
      raise TypeError, 'clock must be a number of milliseconds' unless Js.num?(ms)

      t = ms.to_f
      return Float::NAN if !t.finite? || t.abs > 8.64e15

      (t.truncate / 1000.0).floor
    end

    def normalize_typ(t) = t.downcase.sub(%r{\Aapplication/}, '')

    # jwtVerify(jwt, key, options) -> [payload, protected_header]. Options as the reference: algorithms, typ, required_claims,
    # issuer, subject, audience, clock_tolerance, now_ms (currentDate), max_token_age, crit (extra recognized extensions).
    def jwt_verify(jwt, key, algorithms: nil, typ: nil, required_claims: [], issuer: nil, subject: nil, audience: UNSET,
                   clock_tolerance: UNSET, now_ms: nil, max_token_age: nil, crit: {})
      payload, header = compact_verify(jwt, key, algorithms: algorithms, crit: crit)
      raise Error, 'JWTs MUST NOT use unencoded payload' if header['crit'].is_a?(Array) && header['crit'].include?('b64') && header['b64'] == false

      [claims_check(payload, header, typ: typ, required_claims: required_claims, issuer: issuer, subject: subject,
                                     audience: audience, clock_tolerance: clock_tolerance, now_ms: now_ms, max_token_age: max_token_age), header]
    end

    # compactVerify: [payload bytes, protected header]; raises Error on any refusal.
    def compact_verify(jws, key, algorithms: nil, crit: {})
      raise Error, 'Compact JWS must be a string or Uint8Array' unless jws.is_a?(String)

      prot, pay, sig = parts = jws.split('.', -1)
      raise Error, 'Invalid Compact JWS' unless parts.length == 3

      header = begin
        h = AtlasPca.parse_json_text(lenient_b64d(prot).force_encoding('UTF-8'))
        h.is_a?(Hash) ? h : raise(Error, 'JWS Protected Header must be an object')
      rescue AtlasPca::Malformed, Error
        raise Error, 'JWS Protected Header is invalid'
      end
      b64 = true
      if header.key?('crit')
        c = header['crit']
        unless c.is_a?(Array) && !c.empty? && c.all? { |x| x.is_a?(String) && !x.empty? }
          raise Error, '"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present'
        end

        recognized = { 'b64' => true }.merge(crit)
        c.each do |p|
          raise Error, "Extension Header Parameter \"#{p}\" is not recognized" unless recognized.key?(p)
          raise Error, "Extension Header Parameter \"#{p}\" is missing" unless header.key?(p)
        end
        if c.include?('b64')
          b64 = header['b64']
          raise Error, 'The "b64" (base64url-encode payload) Header Parameter must be a boolean' unless [true, false].include?(b64)
        end
      end
      alg = header['alg']
      raise Error, 'JWS "alg" (Algorithm) Header Parameter missing or invalid' unless alg.is_a?(String) && !alg.empty?
      unless algorithms.nil?
        raise TypeError, '"algorithms" option must be an array of strings' unless Js.str_list?(algorithms)
        raise Error, '"alg" (Algorithm) Header Parameter value not allowed' unless algorithms.include?(alg)
      end
      key = key.call(header) if key.respond_to?(:call) # a key resolver (e.g. the embedded `jwk`) sees the protected header
      raise Error, 'signature verification failed' unless jws_verify(alg, key, lenient_b64d(sig), "#{prot}.#{pay}".b)

      [b64 ? lenient_b64d(pay) : pay.b, header]
    end

    def audience_ok?(value, opt)
      return opt.include?(value) if value.is_a?(String)
      return value.any? { |v| opt.include?(v) } if value.is_a?(Array)

      false
    end

    # The JWT claims-set validation (jwtPayload) over the raw payload bytes; returns the claims Hash.
    def claims_check(bytes, header, typ: nil, required_claims: [], issuer: nil, subject: nil, audience: UNSET,
                     clock_tolerance: UNSET, now_ms: nil, max_token_age: nil)
      payload = begin
        AtlasPca.parse_json_text(bytes.dup.force_encoding('UTF-8'))
      rescue AtlasPca::Malformed
        nil
      end
      raise Error, 'JWT Claims Set must be a top-level JSON object' unless payload.is_a?(Hash)
      if Js.truthy?(typ) && !(header['typ'].is_a?(String) && normalize_typ(header['typ']) == normalize_typ(typ))
        raise Error, 'unexpected "typ" JWT header value'
      end

      presence = required_claims.dup
      presence << 'iat' unless max_token_age.nil?
      presence << 'aud' unless audience.equal?(UNSET)
      presence << 'sub' unless subject.nil?
      presence << 'iss' unless issuer.nil?
      presence.reverse.uniq.each { |c| raise Error, "missing required \"#{c}\" claim" unless payload.key?(c) }
      if Js.truthy?(issuer) && !(issuer.is_a?(Array) ? issuer : [issuer]).include?(payload['iss'])
        raise Error, 'unexpected "iss" claim value'
      end
      raise Error, 'unexpected "sub" claim value' if Js.truthy?(subject) && payload['sub'] != subject
      if !audience.equal?(UNSET) && Js.truthy?(audience) && !audience_ok?(payload['aud'], audience.is_a?(String) ? [audience] : audience)
        raise Error, 'unexpected "aud" claim value'
      end

      tol = if clock_tolerance.equal?(UNSET) then 0
            elsif clock_tolerance.is_a?(String) then secs(clock_tolerance)
            elsif Js.num?(clock_tolerance) then clock_tolerance
            else raise TypeError, 'Invalid clockTolerance option type'
            end
      now = now_ms.nil? ? Time.now.to_i : epoch_of_ms(now_ms)
      if (payload.key?('iat') || Js.truthy?(max_token_age)) && !Js.num?(payload['iat'])
        raise Error, '"iat" claim must be a number'
      end
      if payload.key?('nbf')
        raise Error, '"nbf" claim must be a number' unless Js.num?(payload['nbf'])
        raise Error, '"nbf" claim timestamp check failed' if payload['nbf'] > now + tol
      end
      if payload.key?('exp')
        raise Error, '"exp" claim must be a number' unless Js.num?(payload['exp'])
        raise Error, '"exp" claim timestamp check failed' if payload['exp'] <= now - tol
      end
      if Js.truthy?(max_token_age)
        age = now - payload['iat']
        max = Js.num?(max_token_age) ? max_token_age : secs(max_token_age)
        raise Error, '"iat" claim timestamp check failed (too far in the past)' if age - tol > max
        raise Error, '"iat" claim timestamp check failed (it should not be in the future)' if age < 0 - tol
      end
      payload
    end
  end
end
