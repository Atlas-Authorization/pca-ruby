# frozen_string_literal: true

# Shared plumbing of the native hardware-attestation verifiers: the report_data binding, JavaScript-faithful JSON / base64
# helpers (the conformance vectors pin the reference's exact reason strings) and the OpenSSL glue. Everything but `openssl`
# (already required by the SDK) is the standard library.
require 'digest'
require 'base64'
require 'json'
require 'openssl'

module AtlasPca
  module Attest
    # The analogue of a JavaScript TypeError / RangeError the reference throws and embeds in a reason string.
    class JsTypeError < StandardError; end

    # A JavaScript exception whose message the reference embeds in a reason string.
    class JsError < StandardError; end

    # A verifier configuration the factory refuses (accept-all, a missing pin or allowlist, an unknown mode).
    class AttestConstructError < JsTypeError; end

    # A structural DER problem (the message is part of the conformance contract).
    class DerError < StandardError; end

    # An X.509 parse failure (the wording mirrors the kind of message OpenSSL raises and is not portable).
    class CertError < StandardError; end

    class CanonicalJwsError < StandardError
      def initialize(reason, detail = nil)
        super("non-canonical compact JWS: #{reason}#{detail ? " (#{detail})" : ''}")
      end
    end

    module Common
      ATTEST_BIND_DOMAIN = "atlas-pca/attest-bind/v1\x00".b.freeze
      MAX_SAFE = 9_007_199_254_740_991

      module_function

      def lp(s)
        b = s.dup.force_encoding(Encoding::UTF_8).scrub("�").b
        [b.bytesize].pack('N') + b
      end

      def expected_parts(exp)
        return [nil, nil, nil, nil] unless exp.is_a?(Hash)

        [exp.fetch('holder_pub') { exp['holderPub'] }, exp.fetch('grant_ref') { exp['grantRef'] }, exp['epoch'], exp['nonce']]
      end

      def safe_nonneg_int(v)
        return nil if v == true || v == false
        return (v >= 0 && v <= MAX_SAFE ? v : nil) if v.is_a?(Integer)
        return v.to_i if v.is_a?(Float) && v.finite? && v == v.floor && v >= 0 && v <= MAX_SAFE

        nil
      end

      # SHA-512(domain || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce)): the report_data / quote-bound value.
      # Raises JsTypeError with the reference's message on a malformed expected binding.
      def attestation_binding(exp)
        holder, grant, epoch, nonce = expected_parts(exp)
        raise JsTypeError, 'binding: holderPub required' if !exp.is_a?(Hash) || !holder.is_a?(String) || holder.empty?
        raise JsTypeError, 'binding: grantRef required' if !grant.is_a?(String) || grant.empty?
        raise JsTypeError, 'binding: nonce required' if !nonce.is_a?(String) || nonce.empty?

        ep = safe_nonneg_int(epoch)
        raise JsTypeError, 'binding: epoch must be a non-negative safe integer' if ep.nil?

        Digest::SHA512.digest(ATTEST_BIND_DOMAIN + lp(holder) + lp(grant) + [ep].pack('Q>') + lp(nonce))
      end

      # The 32-byte SPDM challenge that carries the PCA binding: SHA-256(attestationBinding(expected)).
      def attestation_challenge_sha256(exp)
        Digest::SHA256.digest(attestation_binding(exp))
      end

      # ---- JS-faithful helpers

      def to_hex(b) = b.unpack1('H*')

      def num?(v)
        return false if v == true || v == false

        v.is_a?(Integer) || (v.is_a?(Float) && v.finite?)
      end

      def int?(v) = num?(v) && (v.is_a?(Integer) || v == v.floor)

      # String(v) for the values that reach a reason text.
      def js_str(v)
        return 'undefined' if v.nil?
        return 'true' if v == true
        return 'false' if v == false
        return v.to_i.to_s if v.is_a?(Float) && v.finite? && v == v.floor && v.abs < 1e21

        v.to_s
      end

      def js_num_str(v) = js_str(v)

      # Node's lenient Buffer.from(s, 'base64' | 'base64url'): both alphabets, illegal characters skipped, stops at '='.
      def node_b64decode(s)
        out = +''
        s.each_char do |ch|
          break if ch == '='

          ch = '+' if ch == '-'
          ch = '/' if ch == '_'
          out << ch if ch.match?(/\A[A-Za-z0-9+\/]\z/)
        end
        out = out[0...-1] if (out.length % 4) == 1
        out << ('=' * ((4 - (out.length % 4)) % 4))
        Base64.strict_decode64(out)
      rescue ArgumentError
        ''.b
      end

      JS_WS = " \t\n\r\v\f                 　﻿"

      def js_trim(s)
        s = s.dup.force_encoding(Encoding::UTF_8)
        i = 0
        i += 1 while i < s.length && JS_WS.include?(s[i])
        j = s.length
        j -= 1 while j > i && JS_WS.include?(s[j - 1])
        s[i...j]
      end

      # Number(string) for the values the reference converts (a measurement index).
      def js_number(s)
        t = js_trim(s)
        return 0.0 if t.empty?
        return t.to_i(16).to_f if t.match?(/\A0[xX][0-9a-fA-F]+\z/)
        return t[2..].to_i(8).to_f if t.match?(/\A0[oO][0-7]+\z/)
        return t[2..].to_i(2).to_f if t.match?(/\A0[bB][01]+\z/)
        return (t.start_with?('-') ? -Float::INFINITY : Float::INFINITY) if t.match?(/\A[+-]?Infinity\z/)
        return Float(t) if t.match?(/\A[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?\z/)

        Float::NAN
      rescue ArgumentError, FloatDomainError
        Float::NAN
      end

      # BigInt(v) for a decimal string or an integer (JavaScript's SyntaxError text on anything else).
      def big_int(v)
        raise JsError, 'Cannot convert null to a BigInt' if v.nil?
        return (v ? 1 : 0) if v == true || v == false
        return v if v.is_a?(Integer)
        return v.to_i if v.is_a?(Float) && v.finite? && v == v.floor

        if v.is_a?(String)
          t = js_trim(v)
          return 0 if t.empty?
          return t.to_i if t.match?(/\A[+-]?\d+\z/)
          return t.to_i(16) if t.match?(/\A0[xX][0-9a-fA-F]+\z/)
          return t[2..].to_i(8) if t.match?(/\A0[oO][0-7]+\z/)
          return t[2..].to_i(2) if t.match?(/\A0[bB][01]+\z/)

          raise JsError, "Cannot convert #{v} to a BigInt"
        end
        raise JsError, "Cannot convert #{js_str(v)} to a BigInt"
      end

      # ---- JSON.parse with V8-style messages (the common cases: end of input, unexpected token)

      SPECIAL_JSON = ['NaN', 'Infinity', 'undefined', '[object Object]'].freeze

      # The position of the first syntax error of `text` as JSON (a strict recursive descent), or nil when valid.
      class JsonProbe
        attr_reader :pos, :extra

        def initialize(text)
          @s = text
          @i = 0
          @pos = nil
          @extra = false
        end

        def check
          ws
          return fail_at(@i) unless value
          ws
          return true if @i >= @s.length

          @extra = true
          fail_at(@i)
        end

        private

        def fail_at(i)
          @pos ||= i
          false
        end

        def ws = (@i += 1 while @i < @s.length && " \t\n\r".include?(@s[@i]))

        def value
          return fail_at(@i) if @i >= @s.length

          case @s[@i]
          when '{' then object
          when '[' then array
          when '"' then string
          when 't' then lit('true')
          when 'f' then lit('false')
          when 'n' then lit('null')
          else number
          end
        end

        def lit(w)
          w.each_char do |c|
            return fail_at(@i) unless @s[@i] == c

            @i += 1
          end
          true
        end

        def number
          m = @s[@i..].match(/\A-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/)
          return fail_at(@i + (@s[@i] == '-' ? 1 : 0)) if m.nil?

          @i += m[0].length
          true
        end

        def string
          @i += 1
          while @i < @s.length
            c = @s[@i]
            if c == '"'
              @i += 1
              return true
            elsif c == '\\'
              n = @s[@i + 1]
              if n == 'u'
                return fail_at(@i) unless @s[@i + 2, 4].to_s.match?(/\A\h{4}\z/)

                @i += 6
              elsif n && '"\\/bfnrt'.include?(n)
                @i += 2
              else
                return fail_at(@i + 1)
              end
            elsif c.ord < 0x20
              return fail_at(@i)
            else
              @i += 1
            end
          end
          fail_at(@i)
        end

        def array
          @i += 1
          ws
          if @s[@i] == ']'
            @i += 1
            return true
          end
          loop do
            ws
            return false unless value

            ws
            if @s[@i] == ','
              @i += 1
            elsif @s[@i] == ']'
              @i += 1
              return true
            else
              return fail_at(@i)
            end
          end
        end

        def object
          @i += 1
          ws
          if @s[@i] == '}'
            @i += 1
            return true
          end
          loop do
            ws
            return fail_at(@i) unless @s[@i] == '"'
            return false unless string

            ws
            return fail_at(@i) unless @s[@i] == ':'

            @i += 1
            ws
            return false unless value

            ws
            if @s[@i] == ','
              @i += 1
            elsif @s[@i] == '}'
              @i += 1
              return true
            else
              return fail_at(@i)
            end
          end
        end
      end

      def v8_json_message(text, pos)
        n = text.length
        return 'Unexpected end of JSON input' if pos >= n
        return "\"#{text}\" is not valid JSON" if SPECIAL_JSON.include?(text)

        ch = text[pos]
        return "Unexpected string in JSON at position #{pos}" if ch == '"'
        return "Unexpected number in JSON at position #{pos}" if ch.match?(/\A[0-9-]\z/)

        ctx = 10
        return "Unexpected token '#{ch}', \"#{text}\" is not valid JSON" if n < (2 * ctx) + 1
        return "Unexpected token '#{ch}', \"#{text[0, pos + ctx]}\"... is not valid JSON" if pos < ctx
        return "Unexpected token '#{ch}', ...\"#{text[pos - ctx, 2 * ctx]}\"... is not valid JSON" if pos < n - ctx

        "Unexpected token '#{ch}', ...\"#{text[(pos - ctx)..]}\" is not valid JSON"
      end

      LITERALS = %w[null true false].freeze

      # JSON.parse. Raises JsError carrying a V8-style message.
      def js_json_loads(text)
        probe = JsonProbe.new(text)
        unless probe.check
          stripped = text.sub(/\A[ \t\n\r]+/, '')
          raise JsError, 'Unexpected end of JSON input' if stripped.empty?

          lead = text.length - stripped.length
          LITERALS.each do |lit|
            next unless lit[0] == stripped[0]

            k = 0
            k += 1 while k < lit.length && lead + k < text.length && text[lead + k] == lit[k]
            raise JsError, v8_json_message(text, lead + k) if k < lit.length
          end
          raise JsError, "Unexpected non-whitespace character after JSON at position #{probe.pos}" if probe.extra

          raise JsError, v8_json_message(text, probe.pos)
        end
        JSON.parse(text, allow_nan: false, max_nesting: false)
      rescue JSON::ParserError, JSON::NestingError => e
        raise JsError, e.message
      end

      # ---- strict JWS segments

      def decode_canonical_b64url(seg)
        raise CanonicalJwsError, 'bad-character' unless seg.match?(/\A[A-Za-z0-9_-]*\z/)
        raise CanonicalJwsError.new('non-canonical-base64url', 'impossible length') if (seg.length % 4) == 1

        raw = seg.tr('-_', '+/').unpack1('m')
        raise CanonicalJwsError, 'non-canonical-base64url' unless Base64.urlsafe_encode64(raw, padding: false) == seg

        raw
      end

      # ---- PEM / lenient decode

      PEM_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/
      PEM_BODY = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/

      def pem_blocks(pem) = pem.scan(PEM_BLOCK)

      def pem_to_der(pem)
        m = pem.match(PEM_BODY)
        raise ArgumentError, 'pemToDer: no certificate found' if m.nil? || m[1].empty?

        node_b64decode(m[1].gsub(/\s+/, ''))
      end

      def hex?(s) = !s.empty? && s.length.even? && s.match?(/\A[0-9a-fA-F]+\z/)

      # A byte-carrying claim: hex (optionally 0x-prefixed), else base64url, else base64; nil when it decodes to nothing.
      def decode_claim_bytes(value)
        trimmed = js_trim(value)
        hx = trimmed.start_with?('0x', '0X') ? trimmed[2..] : trimmed
        return [hx].pack('H*') if hex?(hx)

        out = node_b64decode(trimmed)
        out.empty? ? nil : out
      end

      # ---- the OpenSSL glue

      def hash_alg(name)
        OpenSSL::Digest.new({ 'sha1' => 'SHA1', 'sha224' => 'SHA224', 'sha256' => 'SHA256', 'sha384' => 'SHA384',
                              'sha512' => 'SHA512' }.fetch(name))
      end

      # The public key of an SPKI. An id-RSASSA-PSS key (the AMD / vendor chains) is an RSA key: its BIT STRING is the same
      # RSAPublicKey, so it is loaded as rsaEncryption (the PSS parameters are applied by the signature check, not the key).
      def load_public_key(spki_der)
        asn = OpenSSL::ASN1.decode(spki_der.b)
        if asn.value[0].value[0].oid == '1.2.840.113549.1.1.10'
          alg = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId('rsaEncryption'), OpenSSL::ASN1::Null(nil)])
          return OpenSSL::PKey.read(OpenSSL::ASN1::Sequence([alg, asn.value[1]]).to_der)
        end
        OpenSSL::PKey.read(spki_der.b)
      end

      # Node's asymmetricKeyType: 'ec', 'rsa' or another lowercase name.
      def key_type(key)
        return 'ec' if key.is_a?(OpenSSL::PKey::EC)
        return 'rsa' if key.is_a?(OpenSSL::PKey::RSA)

        key.class.name.split('::').last.downcase
      end

      JWK_CURVE = { 'prime256v1' => 'P-256', 'secp384r1' => 'P-384', 'secp521r1' => 'P-521' }.freeze

      # OpenSSL's name of an EC key's curve (prime256v1, secp384r1, ...), nil for a non-EC key.
      def node_curve(key) = key_type(key) == 'ec' ? key.group.curve_name : nil

      def jwk_curve(key)
        return nil unless key_type(key) == 'ec'

        n = key.group.curve_name
        JWK_CURVE.fetch(n, n)
      end

      def spki_of(key) = key.public_to_der

      def spki_sha(key, algo) = OpenSSL::Digest.new(algo.upcase).hexdigest(spki_of(key))

      # The uncompressed SEC1 point of an EC key; raises JsTypeError unless it is an EC key on exactly `curve`.
      def ec_point(key, curve)
        t = key_type(key)
        raise JsTypeError, "public key is not EC (got #{t})" if t != 'ec'
        raise JsTypeError, "public key is not on #{curve} (got #{jwk_curve(key)})" if jwk_curve(key) != curve

        key.public_key.to_octet_string(:uncompressed)
      end

      EC_OID = '1.2.840.10045.2.1'
      CURVE_OID = { 'P-256' => 'prime256v1', 'P-384' => 'secp384r1' }.freeze

      # Validate and load an uncompressed (or compressed) SEC1 point; raises ArgumentError off the curve.
      def ec_key_from_point(curve, point)
        group = OpenSSL::PKey::EC::Group.new(CURVE_OID.fetch(curve))
        pt = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(point.b, 2))
        raise ArgumentError, 'point is not on the curve' unless pt.on_curve?

        spki = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId(EC_OID), OpenSSL::ASN1::ObjectId(CURVE_OID.fetch(curve))]),
                                        OpenSSL::ASN1::BitString(pt.to_octet_string(:uncompressed))])
        OpenSSL::PKey.read(spki.to_der)
      rescue OpenSSL::PKey::PKeyError, OpenSSL::PKey::EC::Point::Error => e
        raise ArgumentError, e.message
      end

      def ecdsa_verify_der(key, sig_der, data, hash_name)
        return false unless key_type(key) == 'ec'

        key.verify(hash_alg(hash_name), sig_der.b, data.b)
      rescue OpenSSL::OpenSSLError, ArgumentError, TypeError
        false
      end

      # ECDSA over an IEEE P1363 signature (r || s, equal halves).
      def ecdsa_verify_raw(key, sig, data, hash_name)
        return false unless key_type(key) == 'ec'

        half = (key.group.degree + 7) / 8
        return false if sig.bytesize != 2 * half

        r = OpenSSL::BN.new(sig.byteslice(0, half), 2)
        s = OpenSSL::BN.new(sig.byteslice(half, half), 2)
        return false if r.zero? || s.zero?

        der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
        ecdsa_verify_der(key, der, data, hash_name)
      end

      def rsa_pkcs1_verify(key, sig, data, hash_name)
        return false unless key_type(key) == 'rsa'

        key.verify(hash_alg(hash_name), sig.b, data.b)
      rescue OpenSSL::OpenSSLError, ArgumentError, TypeError
        false
      end

      def result(ok, **kw) = { 'ok' => ok }.merge(kw.transform_keys(&:to_s))

      # ---- compact JWS (MAA / GCP)

      def as_str(v) = v.is_a?(String) ? v : nil

      def as_str_list(v)
        return nil unless v.is_a?(Array) && v.all?(String)

        v
      end

      # The first present, non-empty string claim across candidate keys.
      def first_string(rec, keys)
        keys.each do |k|
          v = as_str(rec[k])
          return v if !v.nil? && !v.empty?
        end
        nil
      end

      # A compact JWS into {header, payload, signingInput, signature}. Raises JsTypeError (the reference's messages).
      def parse_jws(token, fn)
        raise JsTypeError, "#{fn}: empty token" if !token.is_a?(String) || token.empty?

        parts = token.split('.', -1)
        raise JsTypeError, "#{fn}: a compact JWS has exactly three dot-separated parts" if parts.length != 3

        h, p, s = parts
        raise JsTypeError, "#{fn}: empty JWS segment" if h.empty? || p.empty? || s.empty?

        begin
          header_obj = js_json_loads(decode_canonical_b64url(h).force_encoding('UTF-8').scrub("�"))
          payload_obj = js_json_loads(decode_canonical_b64url(p).force_encoding('UTF-8').scrub("�"))
        rescue JsError, CanonicalJwsError => e
          raise JsTypeError, "#{fn}: malformed JSON segment: #{e.message}"
        end
        raise JsTypeError, "#{fn}: header is not a JSON object" unless header_obj.is_a?(Hash)
        raise JsTypeError, "#{fn}: payload is not a JSON object" unless payload_obj.is_a?(Hash)

        alg = as_str(header_obj['alg'])
        raise JsTypeError, "#{fn}: header has no alg" if alg.nil? || alg.empty?

        header = { 'alg' => alg }
        %w[kid jku typ].each { |k| header[k] = header_obj[k] unless as_str(header_obj[k]).nil? }
        x5c = as_str_list(header_obj['x5c'])
        header['x5c'] = x5c unless x5c.nil?
        begin
          signature = decode_canonical_b64url(s)
        rescue CanonicalJwsError => e
          raise JsTypeError, "#{fn}: malformed signature segment: #{e.message}"
        end
        raise JsTypeError, "#{fn}: empty signature" if signature.empty?

        { 'header' => header, 'payload' => payload_obj, 'signingInput' => "#{h}.#{p}".b, 'signature' => signature }
      end

      def transform_binding(binding, mode)
        return Digest::SHA256.digest(binding) if mode == 'sha256'
        return Digest::SHA512.digest(binding) if mode == 'sha512'

        binding
      end
    end
  end
end
