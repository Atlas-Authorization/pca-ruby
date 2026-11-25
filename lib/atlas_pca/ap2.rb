# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'set'
require_relative 'js_compat'
require_relative 'jose'
require_relative 'payments'

# AP2 (Agent Payments Protocol) mandates as real SD-JWT credentials, bound to a PCA grant, matching the TypeScript reference
# (@atlasauth/pca-ap2). PCA governs: it decides who may spend, how much, until when, and when a human must co-sign. AP2 is the
# mandate wire other parties verify.
#
# - SD-JWT primitives (RFC 9901): strict compact parsing (duplicate keys, fatal UTF-8, canonical base64url), disclosure
#   processing, the sd_hash / issuer_jwt_hash binding digests and ES256 (P-256) signing and verification (this file).
# - Mandate claim shapes, their validators, ISO 4217 minor units and the open-mandate constraint evaluation (ap2_mandates.rb).
# - Issuance and presentation of delegation chains, chain and purchase verification, the single-use redeem ledger (ap2_chain.rb).
# - The PCA terms bridge, the PCActn binding, settlement payloads (x402, Stripe shared payment tokens) (ap2_pca.rb).
#
# Options are String-keyed snake_case Hashes (resolve_issuer_key, expected_audience, agent_jwk, ...); mandate claims, results and
# keys keep the reference's member names, so a token issued here verifies in the TypeScript verifier and the reverse. A key pair is
# { 'publicJwk', 'privateKey' } (an OpenSSL P-256 key). Time arguments are epoch seconds; where the reference reads the clock the
# default is the wall clock.
module AtlasPca
  module Ap2
    AP2_COMMIT = 'e1ea56db72a6385bce3e5c1112b3a56ce60acb43'
    VCT_CHECKOUT = 'mandate.checkout.1'
    VCT_CHECKOUT_OPEN = 'mandate.checkout.open.1'
    VCT_PAYMENT = 'mandate.payment.1'
    VCT_PAYMENT_OPEN = 'mandate.payment.open.1'
    PCA_CLAIM = 'x_pca'
    FREQUENCIES = %w[ON_DEMAND DAILY WEEKLY BIWEEKLY MONTHLY QUARTERLY ANNUALLY].freeze
    PCA_BINDING_VERSION = 1
    TYP_TERMINAL = %w[kb+sd-jwt kb-sd-jwt].freeze
    TYP_INTERMEDIATE = %w[kb+sd-jwt+kb kb-sd-jwt+kb].freeze
    MAX_HOPS = 8
    ROOT_TYP = 'dc+sd-jwt'
    SD_ALGS = %w[sha-256 sha-384 sha-512].freeze
    MAX_SAFE = (2**53) - 1
    UNDEF = Payments::UNDEF # an absent member (JS undefined), distinct from JSON null

    # Every failure raised while parsing or verifying carries a human-readable reason.
    class Ap2Error < StandardError; end

    # A private JWK that cannot be imported as a P-256 key (the reference's Node ERR_CRYPTO_INVALID_JWK).
    class Ap2KeyError < ArgumentError
      def code = 'ERR_CRYPTO_INVALID_JWK'
    end

    # An unusable hash algorithm name (the reference's Node ERR_INVALID_ARG_TYPE).
    class Ap2ArgError < ArgumentError
      def code = 'ERR_INVALID_ARG_TYPE'
    end

    # The reference's RangeError (a number outside its allowed range).
    class Ap2RangeError < ArgumentError; end

    module_function

    # ---- JS-semantics helpers -------------------------------------------------------------------------------------------

    def undef?(v) = v.equal?(UNDEF)

    # `o[k]`: a member of a JSON object; undefined for any other non-null value; null / undefined throw like the reference.
    def g(o, k)
      return o.key?(k) ? o[k] : UNDEF if o.is_a?(Hash)
      raise TypeError, "Cannot read properties of #{o.nil? ? 'null' : 'undefined'} (reading '#{k}')" if o.nil? || undef?(o)

      UNDEF
    end

    def num?(v) = v.is_a?(Integer) || v.is_a?(Float)
    def finite?(v) = v.is_a?(Integer) || (v.is_a?(Float) && v.finite?)
    def neg0?(v) = v.is_a?(Float) && v.zero? && (1.0 / v).negative?

    # Number.isSafeInteger.
    def safe_int?(v)
      return v.abs <= MAX_SAFE if v.is_a?(Integer)

      v.is_a?(Float) && v.finite? && v == v.truncate && v.abs <= MAX_SAFE
    end

    def int?(v) = safe_int?(v) && !neg0?(v)
    def nonneg_int?(v) = int?(v) && v >= 0
    def str?(v) = v.is_a?(String)
    def nonempty_str?(v) = v.is_a?(String) && !v.empty?

    def truthy?(v)
      return false if v.nil? || undef?(v) || v == false
      return !(v.zero? || (v.is_a?(Float) && v.nan?)) if v.is_a?(Numeric)
      return !v.empty? if v.is_a?(String)

      true
    end

    # `a === b` over JSON values (containers by identity).
    def seq?(a, b)
      return a.equal?(b) if undef?(a) || undef?(b)
      return a.equal?(b) if [true, false].include?(a) || [true, false].include?(b)
      return a == b if num?(a) && num?(b)
      return a == b if a.is_a?(String) && b.is_a?(String)

      a.equal?(b)
    end

    # String(v).
    def str(v) = undef?(v) ? 'undefined' : Js.string(v)

    def stringify(v) = Js.json(v)

    def spread(x)
      return x.dup if x.is_a?(Hash)
      return x.each_with_index.to_h { |v, i| [i.to_s, v] } if x.is_a?(Array)
      return x.chars.each_with_index.to_h { |v, i| [i.to_s, v] } if x.is_a?(String)

      {}
    end

    # A Hash without the members whose value is undefined (what JSON.stringify drops).
    def compact(h) = h.reject { |_, v| undef?(v) }

    def js_round(x)
      return x unless x.finite? # Math.round leaves NaN and the infinities as they are

      f = x.floor
      x - f >= 0.5 ? f + 1 : f
    end

    # JSON.parse(JSON.stringify(v)): throws for undefined.
    def to_json_value(v)
      raise TypeError, 'JSON.parse: undefined is not valid JSON' if undef?(v)

      Js.parse(stringify(v))
    end

    def iter_list(x)
      raise TypeError, 'x is not iterable' unless x.is_a?(Array)

      x
    end

    # ToNumber for the relational comparisons (anything not a plain scalar is NaN).
    def to_number(x)
      return 0.0 if x.nil? || x == false
      return 1.0 if x == true
      return x.to_f if num?(x)
      return Float::NAN unless x.is_a?(String)

      t = Js.trim(x)
      return 0.0 if t.empty?
      return Float::INFINITY if ['Infinity', '+Infinity'].include?(t)
      return -Float::INFINITY if t == '-Infinity'
      return Float::NAN unless t.ascii_only? && t.match?(/\A[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\z/)

      Float(t.sub(/\A([+-]?)\./) { "#{Regexp.last_match(1)}0." }.sub(/\.(?=[eE]|\z)/, '.0'))
    end

    # UTF-16 code unit order of two strings (the JS string comparison).
    def cmp(a, b, &op)
      return op.call(Payments.u16(a) <=> Payments.u16(b), 0) if a.is_a?(String) && b.is_a?(String)

      x = to_number(a)
      y = to_number(b)
      x.nan? || y.nan? ? false : op.call(x <=> y, 0)
    end

    def lt?(a, b) = cmp(a, b) { |c, z| c < z }
    def gt?(a, b) = cmp(a, b) { |c, z| c > z }
    def ge?(a, b) = cmp(a, b) { |c, z| c >= z }
    def le?(a, b) = cmp(a, b) { |c, z| c <= z }
    # Number.isFinite after the numeric coercion the comparisons use.
    def fin_num?(v) = (n = to_number(v)).is_a?(Numeric) && n.finite?

    # ---- base64url + JSON helpers ---------------------------------------------------------------------------------------

    def b64u_encode(data) = AtlasPca.b64e(data.is_a?(String) ? Js.utf8(data) : data.pack('C*'))

    # Buffer.from(s, 'base64url'): both alphabets, invalid characters skipped, stops at '=', lenient trailing bits.
    def node_b64url_decode(s)
      s = s.b
      i = s.index('=')
      s = s[0, i] if i
      t = s.gsub(%r{[^A-Za-z0-9+/\-_]}n, '')
      t = t[0..-2] if (t.length % 4) == 1
      t = t.tr('-_', '+/')
      "#{t}#{'=' * (-t.length % 4)}".unpack1('m')
    end

    # Strict base64url decode: canonical alphabet, no padding, and the encoding must round-trip.
    def b64u_decode(s, what)
      raise Ap2Error, "#{what}: not base64url" unless s.is_a?(String) && s.b.match?(/\A[A-Za-z0-9_-]*\z/n)

      buf = node_b64url_decode(s)
      raise Ap2Error, "#{what}: non-canonical base64url" if AtlasPca.b64e(buf) != s

      buf
    end

    def object?(v) = v.is_a?(Hash)

    # Reject an object that repeats a key (JSON.parse keeps the last): run on text that already parsed.
    def assert_no_duplicate_keys(text, what)
      stack = []
      expect_key = false
      b = text.b
      i = 0
      n = b.bytesize
      while i < n
        c = b.getbyte(i)
        if c == 0x22
          j = i + 1
          j += b.getbyte(j) == 0x5c ? 2 : 1 while b.getbyte(j) != 0x22
          top = stack.last
          if expect_key && !top.nil?
            key = AtlasPca.parse_json_text(b[i..j].force_encoding('UTF-8'))
            raise Ap2Error, "#{what}: duplicate key #{Js.json(key)}" if top.include?(key)

            top.add(key)
            expect_key = false
          end
          i = j
        elsif c == 0x7b
          stack.push(Set.new)
          expect_key = true
        elsif c == 0x5b
          stack.push(nil)
          expect_key = false
        elsif c == 0x7d || c == 0x5d
          stack.pop unless stack.empty?
          expect_key = false
        elsif c == 0x2c
          expect_key = !stack.empty? && !stack.last.nil?
        end
        i += 1
      end
    end

    # JSON.parse that rejects duplicate keys. Numbers are parsed as written (`1000.0` is accepted).
    def parse_json(text, what)
      begin
        v = AtlasPca.parse_json_text(text)
      rescue AtlasPca::Malformed, ArgumentError, TypeError, SystemStackError => e
        raise Ap2Error, "#{what}: invalid JSON (#{e.message})"
      end
      assert_no_duplicate_keys(text, what)
      v
    end

    # Fatal on any invalid sequence; a BOM is kept so JSON parsing refuses it.
    def utf8_text(bytes, what)
      t = bytes.dup.force_encoding('UTF-8')
      raise Ap2Error, "#{what}: not valid UTF-8" unless t.valid_encoding?

      t
    end

    def decode_json_segment(segment, what)
      v = parse_json(utf8_text(b64u_decode(segment, what), what), what)
      raise Ap2Error, "#{what}: must be a JSON object" unless v.is_a?(Hash)

      v
    end

    # ---- hashing --------------------------------------------------------------------------------------------------------

    def sd_alg?(v) = v.is_a?(String) && SD_ALGS.include?(v)

    # base64url(hash(ascii(value))): the digest used for disclosures, sd_hash and checkout_hash.
    def sd_digest(value, alg = 'sha-256')
      raise Ap2Error, 'digest input must be ASCII' unless value.is_a?(String) && value.b.match?(/\A[\x20-\x7e]*\z/n)
      raise Ap2ArgError, 'unsupported hash algorithm' unless sd_alg?(alg)

      AtlasPca.b64e(OpenSSL::Digest.new(alg.delete('-').upcase).digest(value))
    end

    # ---- ES256 keys (P-256) ---------------------------------------------------------------------------------------------

    # Validate a public JWK against `types/jwk.json` and prove the point is on the curve. Returns the JWK itself.
    def assert_p256_jwk(jwk, what)
      raise Ap2Error, "#{what}: JWK must be an object" unless jwk.is_a?(Hash)
      kty = jwk.key?('kty') ? jwk['kty'] : UNDEF
      crv = jwk.key?('crv') ? jwk['crv'] : UNDEF
      raise Ap2Error, "#{what}: JWK must be EC P-256" if !seq?(kty, 'EC') || !seq?(crv, 'P-256')

      %w[x y].each do |c|
        v = jwk.key?(c) ? jwk[c] : UNDEF
        raise Ap2Error, "#{what}: bad JWK #{c}" unless v.is_a?(String) && v.b.match?(/\A[A-Za-z0-9_-]{43}\z/n)
      end
      raise Ap2Error, "#{what}: JWK carries private material" if jwk.key?('d')
      raise Ap2Error, "#{what}: JWK alg must be ES256" if jwk.key?('alg') && !seq?(jwk['alg'], 'ES256')

      begin
        Jose.public_key_from_jwk(jwk)
      rescue Jose::Error
        raise Ap2Error, "#{what}: JWK is not a valid P-256 point"
      end
      jwk
    end

    def public_jwk(pub_point, kid = UNDEF)
      b = pub_point.to_bn(:uncompressed).to_s(2)
      out = { 'kty' => 'EC', 'crv' => 'P-256', 'x' => AtlasPca.b64e(b.byteslice(1, 32)), 'y' => AtlasPca.b64e(b.byteslice(33, 32)) }
      out['kid'] = kid unless undef?(kid)
      out
    end

    P256_ORDER = OpenSSL::PKey::EC::Group.new('prime256v1').order

    # An OpenSSL P-256 private key for the scalar d (an unsigned big-endian integer).
    def p256_private(d)
      group = OpenSSL::PKey::EC::Group.new('prime256v1')
      raise ArgumentError, 'invalid scalar' if d.zero? || d >= P256_ORDER

      point = group.generator.mul(d)
      der = OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::Integer(1), OpenSSL::ASN1::OctetString(d.to_s(2).rjust(32, "\x00")),
        OpenSSL::ASN1::ObjectId('prime256v1').tap { |o| o.tag = 0; o.tagging = :EXPLICIT; o.tag_class = :CONTEXT_SPECIFIC },
        OpenSSL::ASN1::BitString(point.to_bn(:uncompressed).to_s(2)).tap { |o| o.tag = 1; o.tagging = :EXPLICIT; o.tag_class = :CONTEXT_SPECIFIC }
      ]).to_der
      [OpenSSL::PKey.read(der), point]
    end

    # A fresh P-256 key pair: { 'publicJwk' (never contains `d`), 'privateKey' }.
    def generate_ap2_key_pair(kid = nil)
      key = OpenSSL::PKey::EC.generate('prime256v1')
      { 'publicJwk' => public_jwk(key.public_key, kid.nil? ? UNDEF : kid), 'privateKey' => key }
    end

    # Rebuild a key pair from a private JWK (`d` present), e.g. for fixtures. A JWK whose x / y do not match `d` is refused.
    def ap2_key_pair_from_private_jwk(jwk)
      unless jwk.is_a?(Hash) && jwk['kty'] == 'EC' && jwk['crv'] == 'P-256' && %w[d x y].all? { |k| jwk[k].is_a?(String) }
        raise Ap2KeyError, 'Invalid JWK EC key'
      end

      begin
        key, point = p256_private(OpenSSL::BN.new(node_b64url_decode(jwk['d']), 2))
      rescue ArgumentError, OpenSSL::PKey::PKeyError, OpenSSL::BNError
        raise Ap2KeyError, 'Invalid JWK EC key'
      end
      pub = public_jwk(point)
      raise Ap2KeyError, 'Invalid JWK EC key' if node_b64url_decode(jwk['x']) != AtlasPca.b64d(pub['x']) || node_b64url_decode(jwk['y']) != AtlasPca.b64d(pub['y'])

      kid = jwk['kid']
      { 'privateKey' => key, 'publicJwk' => public_jwk(point, kid.is_a?(String) ? kid : UNDEF) }
    end

    # RFC 7638 JWK thumbprint (SHA-256) of an EC P-256 key.
    def jwk_thumbprint(jwk)
      canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"#{str(g(jwk, 'x'))}\",\"y\":\"#{str(g(jwk, 'y'))}\"}"
      AtlasPca.b64e(OpenSSL::Digest::SHA256.digest(Js.utf8(canonical)))
    end

    def es256_sign(private_key, signing_input) = AtlasPca.b64e(Jose.jws_sign('ES256', private_key, signing_input.b))

    def es256_verify(jwk, signing_input, signature)
      return false unless signature.bytesize == 64

      Jose.jws_verify('ES256', Jose.public_key_from_jwk(jwk), signature, signing_input.b)
    rescue Jose::Error
      false
    end

    # ---- compact JWT / SD-JWT parsing -----------------------------------------------------------------------------------

    # The hop's `~`-joined serialisation: what sd_hash is computed over.
    def hop_sd_jwt(hop) = "#{hop['jwt']}~#{hop['disclosures'].map { |d| "#{d}~" }.join}"

    # Parse one SD-JWT (`jwt~d1~...~dn~`; it must end with `~`). Returns { raw, jwt, header, payload, disclosures, sdAlg,
    # signingInput, signature }.
    def parse_sd_jwt_hop(token)
      raise Ap2Error, 'SD-JWT: empty' if !token.is_a?(String) || token.empty?
      raise Ap2Error, 'SD-JWT: empty issuer JWT' if token.start_with?('~')
      raise Ap2Error, 'SD-JWT: must end with "~" (a trailing KB-JWT is not an AP2 form)' unless token.end_with?('~')

      parts = token[0..-2].split('~', -1)
      jwt = parts[0]
      disclosures = parts[1..]
      raise Ap2Error, 'SD-JWT: empty disclosure segment' if disclosures.any?(&:empty?)

      seg = jwt.split('.', -1)
      raise Ap2Error, 'SD-JWT: issuer JWT must be header.payload.signature' if seg.length != 3 || seg.any?(&:empty?)

      h, p, s = seg
      header = decode_json_segment(h, 'JWT header')
      payload = decode_json_segment(p, 'JWT payload')
      signature = b64u_decode(s, 'JWT signature')
      raw_alg = payload.key?('_sd_alg') ? payload['_sd_alg'] : UNDEF
      raise Ap2Error, "SD-JWT: unsupported _sd_alg #{Js.json(raw_alg)}" if !undef?(raw_alg) && !sd_alg?(raw_alg)

      { 'raw' => token, 'jwt' => jwt, 'header' => header, 'payload' => payload, 'disclosures' => disclosures,
        'sdAlg' => sd_alg?(raw_alg) ? raw_alg : 'sha-256', 'signingInput' => "#{h}.#{p}", 'signature' => signature }
    end

    # sd_hash of a hop: the digest of `<jwt>~<d1>~...~` (the on-wire form of the preceding hop).
    def sd_hash_of(hop, alg = nil) = sd_digest(hop_sd_jwt(hop), alg.nil? ? hop['sdAlg'] : alg)

    # issuer_jwt_hash of a hop: the digest of the issuer-signed JWT alone.
    def issuer_jwt_hash_of(hop, alg = nil) = sd_digest(hop['jwt'], alg.nil? ? hop['sdAlg'] : alg)

    # Verify the issuer JWT's ES256 signature. Anything other than `alg: ES256` is rejected.
    def verify_hop_signature(hop, key)
      return false unless seq?(hop['header'].key?('alg') ? hop['header']['alg'] : UNDEF, 'ES256')

      es256_verify(assert_p256_jwk(key, 'verification key'), hop['signingInput'], hop['signature'])
    end

    # Parse a compact JWT: { header, payload, signingInput, signature }.
    def parse_jwt(jwt, what)
      raise TypeError, 'expected a string' unless jwt.is_a?(String)

      seg = jwt.split('.', -1)
      raise Ap2Error, "#{what}: must be header.payload.signature" if seg.length != 3 || seg.any?(&:empty?)

      h, p, s = seg
      { 'header' => decode_json_segment(h, "#{what} header"), 'payload' => decode_json_segment(p, "#{what} payload"),
        'signingInput' => "#{h}.#{p}", 'signature' => b64u_decode(s, "#{what} signature") }
    end

    def verify_jwt_es256(parsed, key)
      return false unless seq?(parsed['header'].key?('alg') ? parsed['header']['alg'] : UNDEF, 'ES256')

      es256_verify(assert_p256_jwk(key, 'verification key'), parsed['signingInput'], parsed['signature'])
    end

    # ---- disclosure processing (RFC 9901 section 7) ---------------------------------------------------------------------

    def decode_disclosure(raw)
      arr = parse_json(utf8_text(b64u_decode(raw, 'disclosure'), 'disclosure'), 'disclosure')
      raise Ap2Error, 'disclosure: must be a JSON array' unless arr.is_a?(Array)
      raise Ap2Error, 'disclosure: salt must be a non-empty string' if arr.empty? || !arr[0].is_a?(String) || arr[0].empty?

      if arr.length == 3
        name = arr[1]
        raise Ap2Error, 'disclosure: claim name must be a string' unless name.is_a?(String)
        raise Ap2Error, "disclosure: claim name #{name} is reserved" if name == '_sd' || name == '...'

        return { 'kind' => 'property', 'name' => name, 'value' => arr[2], 'raw' => raw }
      end
      return { 'kind' => 'element', 'value' => arr[1], 'raw' => raw } if arr.length == 2

      raise Ap2Error, 'disclosure: array must have 2 or 3 elements'
    end

    # Resolve every selectively-disclosable claim in `payload` using `disclosures`; `_sd`, `...` markers and `_sd_alg` are removed.
    # Raises if a disclosure is duplicated, not referenced from the payload, collides with an existing claim, or is in the wrong
    # position.
    def process_disclosures(payload, disclosures, alg)
      by_digest = {}
      disclosures.each do |raw|
        d = decode_disclosure(raw)
        digest = sd_digest(raw, alg)
        raise Ap2Error, 'SD-JWT: duplicate disclosure' if by_digest.key?(digest)

        by_digest[digest] = d
      end
      used = Set.new
      take = lambda do |digest, want|
        d = digest.is_a?(String) ? by_digest[digest] : nil
        next nil if d.nil? # decoy digest, or a disclosure the holder chose not to reveal

        raise Ap2Error, 'SD-JWT: a digest is referenced more than once' if used.include?(digest)
        raise Ap2Error, "SD-JWT: a #{d['kind']} disclosure is referenced from a #{want} position" if d['kind'] != want

        used.add(digest)
        d
      end
      walk = nil
      walk = lambda do |node, depth|
        raise Ap2Error, 'SD-JWT: nesting too deep' if depth > 32

        case node
        when Array
          out = []
          node.each do |el|
            if el.is_a?(Hash) && el.key?('...')
              raise Ap2Error, 'SD-JWT: malformed array digest placeholder' if el.length != 1 || !el['...'].is_a?(String)

              d = take.call(el['...'], 'element')
              out << walk.call(d['value'], depth + 1) unless d.nil?
            else
              out << walk.call(el, depth + 1)
            end
          end
          out
        when Hash
          res = {}
          node.each do |k, v|
            next if k == '_sd' || k == '_sd_alg'
            raise Ap2Error, 'SD-JWT: "..." is only valid as the sole key of an array element' if k == '...'

            res[k] = walk.call(v, depth + 1)
          end
          if node.key?('_sd')
            sd = node['_sd']
            raise Ap2Error, 'SD-JWT: _sd must be an array of strings' if !sd.is_a?(Array) || sd.any? { |x| !x.is_a?(String) }

            sd.each do |digest|
              d = take.call(digest, 'property')
              next if d.nil? || d['kind'] != 'property'
              raise Ap2Error, "SD-JWT: disclosed claim #{d['name']} collides with an existing claim" if res.key?(d['name'])

              res[d['name']] = walk.call(d['value'], depth + 1)
            end
          end
          res
        else node
        end
      end
      result = walk.call(payload, 0)
      raise Ap2Error, 'SD-JWT: a disclosure is not referenced by the signed payload' if used.length != by_digest.length

      result
    end

    # ---- issuing --------------------------------------------------------------------------------------------------------

    def new_salt = AtlasPca.b64e(SecureRandom.random_bytes(16))

    class DisclosureBuilder
      attr_reader :disclosures

      def initialize(alg, salt)
        @alg = alg
        @salt = salt
        @disclosures = []
      end

      # Array-element disclosure for `value`; returns the `{"...": digest}` placeholder.
      def element(value)
        raw = Ap2.b64u_encode(Ap2.stringify([@salt.call, value]))
        @disclosures << raw
        { '...' => Ap2.sd_digest(raw, @alg) }
      end

      # Property disclosure; returns the digest to put into the parent's `_sd`.
      def property(name, value)
        raw = Ap2.b64u_encode(Ap2.stringify([@salt.call, name, value]))
        @disclosures << raw
        Ap2.sd_digest(raw, @alg)
      end
    end

    def disclosure_builder(alg = nil, salt = nil) = DisclosureBuilder.new(alg.nil? ? 'sha-256' : alg, salt.nil? ? -> { new_salt } : salt)

    # Sign `payload` as an ES256 JWT and append `disclosures`: `<jwt>~<d1>~...~<dn>~`. args: header, payload, disclosures, private_key.
    def sign_sd_jwt(args)
      header = b64u_encode(stringify({ 'alg' => 'ES256' }.merge(spread(args['header']))))
      payload = b64u_encode(stringify(args['payload']))
      jwt = "#{header}.#{payload}.#{es256_sign(args['private_key'], "#{header}.#{payload}")}"
      "#{jwt}~#{args['disclosures'].map { |d| "#{d}~" }.join}"
    end

    # Sign an arbitrary compact JWT (used for merchant-signed `checkout_jwt`). args: header, payload, private_key.
    def sign_jwt_es256(args)
      header = b64u_encode(stringify({ 'alg' => 'ES256', 'typ' => 'JWT' }.merge(spread(args['header']))))
      payload = b64u_encode(stringify(args['payload']))
      "#{header}.#{payload}.#{es256_sign(args['private_key'], "#{header}.#{payload}")}"
    end
  end
end

require_relative 'ap2_mandates'
require_relative 'ap2_chain'
require_relative 'ap2_pca'
