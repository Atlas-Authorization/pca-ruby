# frozen_string_literal: true

require_relative 'js_compat'
require_relative 'jose'
require_relative 'oidc'

# The A2A 1.0 Agent Card layer the agent-card and ACP bridges share (TypeScript reference @atlasauth/pca-a2a card helpers):
# RFC 8785 canonical bytes, the AgentCard schema check, signed-card issuing and the flattened-JWS verification of a card
# signature. Cards are String-keyed Hashes. A member that is present but `undefined` in the reference is UNDEFINED here (it
# stays distinct from nil = null); JavaScript object semantics (spread, property reads) follow the reference.
module AtlasPca
  module AgentcardCard
    PCA_PASSPORT_HEADER = 'pca_passport'
    MAX_DEPTH = 64
    EC_CURVES = %w[P-256 P-384 P-521].freeze

    # JavaScript `undefined`, where it must stay distinct from null.
    UNDEFINED = Object.new.tap { |o| o.define_singleton_method(:inspect) { 'undefined' } }.freeze
    # A key that imports but cannot verify (symmetric, or a curve this verifier does not support).
    BAD_KEY = Object.new.freeze

    module_function

    def undefined?(v) = v.equal?(UNDEFINED)
    def b64u(bin) = AtlasPca.b64e(bin)

    # o.k with JS semantics: a TypeError for null / undefined, undefined for a missing member or a non-object.
    def get(o, k)
      if o.nil? || o.equal?(UNDEFINED)
        raise TypeError, "Cannot read properties of #{o.nil? ? 'null' : 'undefined'} (reading '#{k}')"
      end

      o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEFINED
    end

    # The member of a Hash, or UNDEFINED when absent (a non-Hash has no members).
    def member(o, k) = o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEFINED

    def nullish(v, default) = v.nil? || v.equal?(UNDEFINED) ? default : v

    # One UTF-16 code unit as a String (a surrogate becomes its WTF-8 form).
    def unit_char(u)
      return [u].pack('U') unless u.between?(0xD800, 0xDFFF)

      [0xE0 | (u >> 12), 0x80 | ((u >> 6) & 0x3f), 0x80 | (u & 0x3f)].pack('C*').force_encoding('UTF-8')
    end

    # The own enumerable members JavaScript object spread {...v} copies: a Hash as is, an Array or String by index.
    def spread(v)
      case v
      when Hash then v.dup
      when Array then v.each_with_index.to_h { |x, i| [i.to_s, x] }
      when String then u16key(v).unpack('n*').each_with_index.to_h { |u, i| [i.to_s, unit_char(u)] }
      else {}
      end
    end

    # UTF-16 code-unit order key (a lone surrogate, WTF-8, sorts by its code unit).
    def u16key(s)
      return s.encode('UTF-16BE').b if s.valid_encoding?

      out = String.new(encoding: Encoding::BINARY)
      s.b.split(/(\xED[\xA0-\xBF][\x80-\xBF])/n).each do |part|
        next if part.empty?

        if part.match?(/\A\xED[\xA0-\xBF][\x80-\xBF]\z/n)
          b = part.bytes
          out << [((b[0] & 0x0f) << 12) | ((b[1] & 0x3f) << 6) | (b[2] & 0x3f)].pack('n')
        else
          out << part.dup.force_encoding('UTF-8').scrub("�").encode('UTF-16BE').b
        end
      end
      out
    end

    # String#toLowerCase: a lone surrogate (WTF-8) is kept as is.
    def lower(s)
      return s.downcase if s.valid_encoding?

      s.b.split(/(\xED[\xA0-\xBF][\x80-\xBF])/n).map do |part|
        part.match?(/\A\xED[\xA0-\xBF][\x80-\xBF]\z/n) ? part : part.dup.force_encoding('UTF-8').scrub('?').downcase.b
      end.join.force_encoding('UTF-8')
    end

    # ---- RFC 8785 ----

    def jcs(v, depth)
      case v
      when nil then 'null'
      when true then 'true'
      when false then 'false'
      when Integer, Float
        raise TypeError, 'jcs: non-finite number' if v.is_a?(Float) && !v.finite?

        Predicates.js_number_string(v)
      when String
        raise TypeError, 'jcs: lone surrogate in string' unless v.valid_encoding?

        AtlasPca.js_string(v)
      when Array, Hash
        raise TypeError, 'jcs: nesting too deep' if depth > MAX_DEPTH

        if v.is_a?(Array)
          "[#{v.map { |x| jcs(x, depth + 1) }.join(',')}]"
        else
          "{#{v.keys.sort_by { |k| u16key(k) }.map do |k|
            raise TypeError, 'jcs: lone surrogate in key' unless k.valid_encoding?

            "#{AtlasPca.js_string(k)}:#{jcs(v[k], depth + 1)}"
          end.join(',')}}"
        end
      else raise TypeError, "jcs: unsupported type #{v.equal?(UNDEFINED) ? 'undefined' : v.class}"
      end
    end

    # RFC 8785 canonical UTF-8 bytes of a JSON value. Raises TypeError for a value with no JSON form.
    def jcs_bytes(value) = jcs(value, 1).b

    # ---- A2A 1.0 AgentCard message ----

    def validate_agent_card1(card)
      return ['$: the agent card must be an object'] unless card.is_a?(Hash)

      pr = []
      req_str = lambda do |o, k, at|
        pr << "#{at}.#{k}: required non-empty string" if !o[k].is_a?(String) || o[k] == ''
      end
      opt_str = ->(o, k, at) { pr << "#{at}.#{k}: must be a string" if o.key?(k) && !o[k].is_a?(String) }
      opt_bool = ->(o, k, at) { pr << "#{at}.#{k}: must be a boolean" if o.key?(k) && ![true, false].include?(o[k]) }
      str_array = lambda do |v, at, non_empty|
        if !v.is_a?(Array) || !v.all?(String)
          pr << "#{at}: must be an array of strings"
        elsif non_empty && v.empty?
          pr << "#{at}: must not be empty"
        end
      end
      obj_array = lambda do |o, k, at, required, non_empty, each|
        unless o.key?(k)
          pr << "#{at}.#{k}: required array" if required
          next
        end
        v = o[k]
        unless v.is_a?(Array)
          pr << "#{at}.#{k}: must be an array"
          next
        end
        pr << "#{at}.#{k}: must not be empty" if non_empty && v.empty?
        v.each_with_index do |e, i|
          if e.is_a?(Hash)
            each.call(e, "#{at}.#{k}[#{i}]")
          else
            pr << "#{at}.#{k}[#{i}]: must be an object"
          end
        end
      end

      req_str.call(card, 'name', '$')
      req_str.call(card, 'description', '$')
      req_str.call(card, 'version', '$')
      opt_str.call(card, 'documentationUrl', '$')
      opt_str.call(card, 'iconUrl', '$')

      iface = lambda do |e, at|
        req_str.call(e, 'url', at)
        req_str.call(e, 'protocolBinding', at)
        req_str.call(e, 'protocolVersion', at)
        opt_str.call(e, 'tenant', at)
      end
      obj_array.call(card, 'supportedInterfaces', '$', true, true, iface)
      if card.key?('provider')
        if card['provider'].is_a?(Hash)
          req_str.call(card['provider'], 'url', '$.provider')
          req_str.call(card['provider'], 'organization', '$.provider')
        else
          pr << '$.provider: must be an object'
        end
      end
      if card['capabilities'].is_a?(Hash)
        c = card['capabilities']
        opt_bool.call(c, 'streaming', '$.capabilities')
        opt_bool.call(c, 'pushNotifications', '$.capabilities')
        opt_bool.call(c, 'extendedAgentCard', '$.capabilities')
        ext = lambda do |e, at|
          opt_str.call(e, 'uri', at)
          opt_str.call(e, 'description', at)
          opt_bool.call(e, 'required', at)
          pr << "#{at}.params: must be an object" if e.key?('params') && !e['params'].is_a?(Hash)
        end
        obj_array.call(c, 'extensions', '$.capabilities', false, false, ext)
      else
        pr << '$.capabilities: required object'
      end
      pr << '$.securitySchemes: must be an object' if card.key?('securitySchemes') && !card['securitySchemes'].is_a?(Hash)
      pr << '$.securityRequirements: must be an array' if card.key?('securityRequirements') && !card['securityRequirements'].is_a?(Array)
      %w[defaultInputModes defaultOutputModes].each do |k|
        if card.key?(k)
          str_array.call(card[k], "$.#{k}", true)
        else
          pr << "$.#{k}: required array of strings"
        end
      end
      skill = lambda do |e, at|
        req_str.call(e, 'id', at)
        req_str.call(e, 'name', at)
        req_str.call(e, 'description', at)
        if e.key?('tags')
          str_array.call(e['tags'], "#{at}.tags", false)
        else
          pr << "#{at}.tags: required array of strings"
        end
        %w[examples inputModes outputModes].each { |k| str_array.call(e[k], "#{at}.#{k}", false) if e.key?(k) }
        pr << "#{at}.securityRequirements: must be an array" if e.key?('securityRequirements') && !e['securityRequirements'].is_a?(Array)
      end
      obj_array.call(card, 'skills', '$', true, false, skill)
      sig = lambda do |e, at|
        req_str.call(e, 'protected', at)
        req_str.call(e, 'signature', at)
        pr << "#{at}.header: must be an object" if e.key?('header') && !e['header'].is_a?(Hash)
      end
      obj_array.call(card, 'signatures', '$', false, false, sig)
      pr
    end

    # ---- signed cards ----

    def jwk?(k) = k.is_a?(Hash) && k.key?('kty')

    # RFC 8785 of the card minus its signatures (A2A 1.0 section 8.4).
    def card_bytes(card) = jcs_bytes(card.reject { |k, _| k == 'signatures' })

    # The runtime's refusal of a private JWK it cannot import (Node: ERR_CRYPTO_INVALID_JWK).
    class InvalidJwkError < Jose::Error
      def code = 'ERR_CRYPTO_INVALID_JWK'
    end

    # importJWK for a signing key: only Ed25519 / EC private JWKs sign (Jose.jws_sign reads the JWK itself).
    def signing_key(key, _alg)
      return key unless jwk?(key)

      if key['kty'] == 'EC' && key['d'].is_a?(String)
        raise Jose::Error, 'unsupported EC curve' unless EC_CURVES.include?(key['crv'])

        return key
      end
      if key['kty'] == 'OKP' && key['crv'] == 'Ed25519'
        d = key['d']
        raise InvalidJwkError, 'Invalid JWK OKP key' unless d.is_a?(String) && (Jose.lenient_b64d(d).bytesize == 32 rescue false)

        return key
      end

      raise Jose::Error, 'Invalid key for this operation: unsupported private JWK'
    end

    # importJWK for a verification key: raises Jose::Error where the import itself fails; a private JWK yields its public half.
    def import_verify_key(key, _alg)
      return key unless jwk?(key)

      case key['kty']
      when 'oct'
        raise Jose::Error, 'missing k' if !key['k'].is_a?(String) || key['k'].empty?

        BAD_KEY
      when 'OKP'
        return BAD_KEY unless key['crv'] == 'Ed25519'

        if Js.truthy?(key['d'])
          seed = key['d'].is_a?(String) ? Jose.lenient_b64d(key['d']) : ''.b
          raise Jose::Error, 'invalid Ed25519 private key' unless seed.bytesize == 32

          return OpenSSL::PKey.new_raw_private_key('ED25519', seed)
        end
        Jose.public_key_from_jwk(key)
      when 'EC', 'RSA'
        if Js.truthy?(key['d'])
          return BAD_KEY unless key['kty'] == 'EC'

          signing_key(key, nil)
          return Jose.private_key_from_jwk(key)
        end
        Jose.public_key_from_jwk(key)
      else raise Jose::Error, 'Unsupported "kty" (Key Type) Parameter value'
      end
    end

    # The protected header of a signature as a Hash ({} when it does not parse).
    def payload_header(prot)
      h = Js.parse(Jose.lenient_b64d(prot).force_encoding('UTF-8').scrub("�"))
      h.is_a?(Hash) ? h : {}
    rescue StandardError
      {}
    end

    # jose flattenedVerify for a card signature; payload is the detached raw bytes (raw: true) or the base64url text. Raises on refusal.
    def flattened_verify(prot, payload, signature, key, resolver, raw: false)
      parsed = prot.empty? ? {} : Js.parse(Jose.lenient_b64d(prot).force_encoding('UTF-8').scrub("�"))
      raise Jose::Error, 'JWS Protected Header is invalid' unless parsed.is_a?(Hash)

      b64 = true
      if parsed.key?('crit')
        crit = parsed['crit']
        unless crit.is_a?(Array) && !crit.empty? && crit.all? { |c| c.is_a?(String) && !c.empty? }
          raise Jose::Error, '"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present'
        end

        crit.each { |c| raise Jose::Error, "Extension Header Parameter \"#{c}\" is not recognized" unless c == 'b64' }
        b64 = parsed['b64']
        raise Jose::Error, 'The "b64" (base64url-encode payload) Header Parameter must be a boolean' unless [true, false].include?(b64)
      end
      alg = parsed['alg']
      raise Jose::Error, 'JWS "alg" (Algorithm) Header Parameter missing or invalid' unless alg.is_a?(String) && !alg.empty?
      raise Jose::Error, 'JWS Payload must be a string' if b64 && raw

      if resolver
        jwk = key.call(parsed)
        key = jwk?(jwk) ? import_verify_key(jwk, alg) : jwk
      end
      raise Jose::Error, 'Invalid key for this operation' if key.equal?(BAD_KEY)

      data = prot.b + '.'.b + payload.b
      raise Jose::Error, 'signature verification failed' unless Jose.jws_verify(alg, key, Jose.lenient_b64d(signature), data)

      parsed
    end

    # The card with a signature appended: the passport reference is embedded (and put in the signed protected header) before
    # signing. opts: 'alg' (default EdDSA), 'passport', 'kid', 'profile' ('pca-detached' default, or 'a2a-1.0', which needs a kid)
    # and 'schema' ('a2a-1.0': refuse a card that does not match the schema). Raises on any refusal.
    def issue_signed_agent_card(card, signing_key_in, opts = nil)
      o = opts || {}
      raise TypeError, 'issue_signed_agent_card: the card must be an object' unless card.is_a?(Hash)

      alg = o['alg'].nil? ? 'EdDSA' : o['alg']
      if Js.truthy?(o['passport'])
        pp = o['passport']
        passport = { 'id' => pp.is_a?(Hash) && pp.key?('id') ? pp['id'] : UNDEFINED }
        passport['uri'] = pp['uri'] if pp.is_a?(Hash) && pp.key?('uri') && !pp['uri'].equal?(UNDEFINED)
      else
        passport = card['pcaPassport']
      end
      to_sign = card.dup
      to_sign['pcaPassport'] = passport if Js.truthy?(passport)
      if o['schema'] == 'a2a-1.0'
        problems = validate_agent_card1(to_sign)
        unless problems.empty?
          raise ArgumentError, "issue_signed_agent_card: the card does not match the A2A 1.0 schema: #{problems.join('; ')}"
        end
      end
      payload = card_bytes(to_sign)
      key = signing_key(signing_key_in, alg)
      a2a10 = o['profile'] == 'a2a-1.0'
      if a2a10 && (!o['kid'].is_a?(String) || o['kid'].empty?)
        raise ArgumentError, "issue_signed_agent_card: the 'a2a-1.0' profile requires a kid"
      end

      header = { 'alg' => alg }
      if a2a10
        header['typ'] = 'JOSE'
      else
        header['b64'] = false
        header['crit'] = ['b64']
      end
      header['kid'] = o['kid'] if o.key?('kid')
      if Js.truthy?(passport)
        pid = passport.is_a?(Hash) && passport.key?('id') ? passport['id'] : UNDEFINED
        header[PCA_PASSPORT_HEADER] = pid unless pid.equal?(UNDEFINED)
      end
      prot = b64u(Js.json(header).b)
      body = a2a10 ? b64u(payload) : payload
      sig = b64u(Jose.jws_sign(alg, key, prot.b + '.'.b + body.b))
      existing = to_sign['signatures']
      prior = case existing
              when nil then []
              when Array then existing.dup
              when String then spread(existing).values
              else raise TypeError, 'existing is not iterable'
              end
      to_sign.merge('signatures' => prior + [{ 'protected' => prot, 'signature' => sig }])
    end
  end
end
