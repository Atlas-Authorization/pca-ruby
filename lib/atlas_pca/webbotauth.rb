# frozen_string_literal: true

require 'openssl'
require 'digest'
require_relative 'js_compat'
require_relative 'whatwg_url'

# Web Bot Auth for Proof-Carrying Authority (the TypeScript reference, @atlasauth/pca-webbotauth): RFC 9421 HTTP Message
# Signatures over outbound agent requests in the `web-bot-auth` profile (Ed25519), RFC 9530 `Content-Digest`, signed
# key-directory responses and the PCA proof binding (the `PCA-Action` header is a covered component). Verification FAILS
# CLOSED: any parse error, missing field, stale window, wrong tag, unknown key or bad signature returns
# {"valid" => false, "reason" => ...} and never raises.
#
# Inputs and results are String-keyed Hashes with the reference's member names (`created`, `expiresInSec`, `agentDirectoryUrl`,
# `signatureInput`, ...) so a request signed here verifies in the TypeScript verifier and the reverse. A signing key is an
# AtlasPca::KeyPair, a 32-byte seed String or {"secretKey" => seed}. Raw bytes are binary Strings (a UTF-8 String is text).
# Time arguments are epoch seconds; where the reference reads the clock the default is Time.now.
# Differences from the reference: only special-scheme URLs (http, https, ws, wss, ftp) are signed or verified, and a URL with
# credentials is refused wherever the serialized URL itself is needed; resolvers, caches and fetchers are synchronous callables.
module AtlasPca
  module WebBotAuth
    WEB_BOT_AUTH_TAG = 'web-bot-auth'
    WEB_BOT_AUTH_ALG = 'ed25519'
    WELL_KNOWN_DIRECTORY_PATH = '/.well-known/http-message-signatures-directory'
    DIRECTORY_CONTENT_TYPE = 'application/http-message-signatures-directory+json'
    DEFAULT_SIGNATURE_LABEL = 'sig1'
    DEFAULT_EXPIRES_SEC = 300
    SIGNATURE_AGENT_HEADER = 'Signature-Agent'
    PCA_HEADER = 'PCA-Action'
    PCA_PROOF_COMPONENT = 'pca-action'
    CONTENT_DIGEST_ALGS = %w[sha-256 sha-512].freeze
    CONTENT_DIGEST_HEADER = 'Content-Digest'
    DIRECTORY_SIGNATURE_TAG = 'http-message-signatures-directory'

    DIRECTORY_LIFETIME_SEC = 86_400
    SPECIAL_SCHEMES = %w[http https ws wss ftp].freeze
    UNDEF = Object.new.freeze

    # A malformed or unsupported signature field (the reference's internal parse error).
    class ParseError < StandardError; end

    # An error that carries the reference's error code (ERR_INVALID_URL, ...).
    class CodedError < StandardError
      attr_reader :code

      def initialize(message, code)
        super(message)
        @code = code
      end
    end

    module_function

    # ---- small JS-semantics helpers ---------------------------------------------------------------------------------------

    def trim(s) = Js.trim(s)
    def utf8(s) = Js.utf8(s)
    def num?(v) = v.is_a?(Integer) || v.is_a?(Float)
    def finite?(v) = num?(v) && (!v.is_a?(Float) || v.finite?)
    def truthy?(v) = !v.equal?(UNDEF) && Js.truthy?(v)

    # a JS boolean takes part in arithmetic and comparisons as 0 / 1
    def pn(v)
      return 1 if v == true
      return 0 if v == false

      v
    end

    def need_num(v, what)
      raise TypeError, "#{what} must be a number" unless num?(v)

      v
    end

    def need_str(v, what)
      raise TypeError, "#{what} must be a string" unless v.is_a?(String)

      v
    end

    def hash!(v)
      raise TypeError, 'not an object' unless v.is_a?(Hash)

      v
    end

    def str_eq?(a, b) = a.is_a?(String) && b.is_a?(String) && a == b

    def list_of(x, what)
      raise TypeError, "#{what} must be an array" unless x.is_a?(Array)

      x
    end

    # `{...x}` of a JSON value
    def spread_obj(x)
      case x
      when Hash then x.dup
      when Array then x.each_with_index.to_h { |v, i| [i.to_s, v] }
      when String then x.each_char.with_index.to_h { |c, i| [i.to_s, c] }
      else {}
      end
    end

    # Object.entries(o)
    def entries(o)
      case o
      when Hash then o.to_a
      when Array then o.each_with_index.map { |v, i| [i.to_s, v] }
      when String then o.each_char.with_index.map { |c, i| [i.to_s, c] }
      else []
      end
    end

    # for ... of x: arrays and strings only
    def iter(x)
      return x.dup if x.is_a?(Array)
      return x.chars if x.is_a?(String)

      raise TypeError, 'not iterable'
    end

    def parse_int(s)
      v = Integer(s, 10)
      v.abs <= 2**53 ? v : v.to_f # Number.parseInt returns a double
    end

    # Buffer.from(s, 'base64'): both alphabets, invalid characters skipped, stops at '=', lenient trailing bits.
    def node_b64decode(s)
      s = s.b
      i = s.index('=')
      s = s[0, i] if i
      t = s.gsub(%r{[^A-Za-z0-9+/\-_]}n, '')
      t = t[0..-2] if (t.length % 4) == 1
      t = t.tr('-_', '+/')
      "#{t}#{'=' * (-t.length % 4)}".unpack1('m')
    end

    def now_sec = Time.now.to_i

    def b64u(bytes) = AtlasPca.b64e(bytes)
    def b64(bytes) = [bytes].pack('m0')

    # Python-style str.split(sep): "" gives [""] and empties are kept
    def psplit(s, sep) = s.empty? ? [''] : s.split(sep, -1)

    def ed_key(key)
      key = key['secretKey'] if key.is_a?(Hash)
      return key if key.is_a?(AtlasPca::KeyPair)
      raise TypeError, "the signing key must be a KeyPair, a 32-byte seed or {'secretKey' => seed}" unless key.is_a?(String) && key.bytesize == 32

      AtlasPca::KeyPair.new(key)
    end

    def ed_sign(key, message) = ed_key(key).sign(message)
    def ed_public(key) = AtlasPca.b64d(ed_key(key).public, 32)

    # Ed25519 verify under the base64url `x` of a public key; false for any malformed key or signature.
    def ed_verify_x(x, message, sig)
      return false unless sig.bytesize == 64

      pub = node_b64decode(x)
      return false unless pub.bytesize == 32

      OpenSSL::PKey.new_raw_public_key('ED25519', pub).verify(nil, sig.b, message.b)
    rescue StandardError
      false
    end

    # RFC 7638 JWK thumbprint of an Ed25519 public key (base64url of SHA-256 over the canonical JWK).
    def jwk_thumbprint(public_key)
      raise TypeError, 'the public key must be bytes' unless public_key.is_a?(String)

      thumbprint_of_x(b64u(public_key))
    end

    def thumbprint_of_x(x)
      b64u(Digest::SHA256.digest(%({"crv":"Ed25519","kty":"OKP","x":"#{x}"}).b))
    end

    # ---- structured-field helpers (targeted to the RFC 9421 Signature-Input / Signature grammars) -------------------------

    def sf_string(s)
      need_str(s, 'a structured-field string')
      %("#{s.gsub('\\') { '\\\\' }.gsub('"') { '\\"' }}")
    end

    def split_top_level(s, sep)
      out = []
      depth = 0
      in_str = false
      start = 0
      i = 0
      n = s.length
      while i < n
        c = s[i]
        if in_str
          if c == '\\'
            i += 1
          elsif c == '"'
            in_str = false
          end
          i += 1
          next
        end
        if c == '"'
          in_str = true
        elsif c == '('
          depth += 1
        elsif c == ')'
          depth = [0, depth - 1].max
        elsif c == sep && depth.zero?
          out << s[start...i]
          start = i + 1
        end
        i += 1
      end
      out << s[start..]
      out
    end

    def char_at(s, i) = i >= 0 && i < s.length ? s[i] : ''

    def read_sf_string(s, i)
      raise ParseError, 'expected a quoted string' unless char_at(s, i) == '"'

      out = +''
      j = i + 1
      while j < s.length
        c = s[j]
        if c == '\\'
          nx = char_at(s, j + 1)
          raise ParseError, 'invalid escape in string' if nx != '"' && nx != '\\'

          out << nx
          j += 1
        elsif c == '"'
          return [out, j + 1]
        else
          out << c
        end
        j += 1
      end
      raise ParseError, 'unterminated string'
    end

    INT_RE = /\A-?[0-9]+\z/
    DEC_RE = /\A-?[0-9]+\.[0-9]+\z/

    def parse_param_value(raw)
      s = trim(raw)
      return true if s.empty? # valueless parameter => boolean true

      if s[0] == '"'
        value, nxt = read_sf_string(s, 0)
        raise ParseError, 'trailing characters after string parameter' if nxt != s.length

        return value
      end
      return true if s == '?1'
      return false if s == '?0'
      return parse_int(s) if INT_RE.match?(s)
      return s.to_f if DEC_RE.match?(s)

      s # token
    end

    def index_of_top_level(s, ch)
      depth = 0
      in_str = false
      i = 0
      n = s.length
      while i < n
        c = s[i]
        if in_str
          if c == '\\'
            i += 1
          elsif c == '"'
            in_str = false
          end
          i += 1
          next
        end
        if c == '"'
          in_str = true
        elsif c == '('
          depth += 1
        elsif c == ')'
          depth = [0, depth - 1].max
        elsif c == ch && depth.zero?
          return i
        end
        i += 1
      end
      -1
    end

    def matching_paren(s, open_)
      return -1 unless char_at(s, open_) == '('

      depth = 0
      in_str = false
      i = open_
      n = s.length
      while i < n
        c = s[i]
        if in_str
          if c == '\\'
            i += 1
          elsif c == '"'
            in_str = false
          end
          i += 1
          next
        end
        if c == '"'
          in_str = true
        elsif c == '('
          depth += 1
        elsif c == ')'
          depth -= 1
          return i if depth.zero?
        end
        i += 1
      end
      -1
    end

    def parse_params(param_str)
      params = {}
      trimmed = trim(param_str)
      return params if trimmed.empty?
      raise ParseError, 'expected parameters to start with ";"' if trimmed[0] != ';'

      split_top_level(trimmed[1..], ';').each do |part|
        seg = trim(part)
        next if seg.empty?

        eq = index_of_top_level(seg, '=')
        if eq == -1
          params[seg] = true
        else
          params[trim(seg[0, eq])] = parse_param_value(seg[(eq + 1)..])
        end
      end
      params
    end

    # a JS `.` does not match a line terminator
    KEY_PARAM = /\A;key=("(?:[^"\\]|\\[^\n\r  ])*")\z/
    MEMBER_PARAMS = %r{\A(?:;[a-z*][a-z0-9_.*-]*(?:=(?:"(?:[^"\\]|\\[^\n\r  ])*"|[A-Za-z0-9_.:/*+%-]+))?)*\z}

    def parse_signature_input(value)
      entries = []
      split_top_level(value, ',').each do |member_raw|
        member = trim(member_raw)
        next if member.empty?

        eq = index_of_top_level(member, '=')
        raise ParseError, 'malformed Signature-Input member' if eq == -1

        label = trim(member[0, eq])
        params_raw = trim(member[(eq + 1)..])
        raise ParseError, 'Signature-Input value must be an inner list' if char_at(params_raw, 0) != '('

        close = matching_paren(params_raw, 0)
        raise ParseError, 'unterminated inner list' if close == -1

        inner = params_raw[1...close]
        components = []
        split_top_level(inner, ' ').each do |chunk_raw|
          chunk = trim(chunk_raw)
          next if chunk.empty?

          ident, nxt = read_sf_string(chunk, 0)
          lowered = ident.downcase
          rest = trim(chunk[nxt..])
          if rest.empty?
            components << { 'id' => lowered, 'raw' => %("#{lowered}"), 'key' => nil }
            next
          end
          # the only component parameter supported is `key` (dictionary member), on header components
          m = KEY_PARAM.match(rest)
          raise ParseError, %(unsupported component parameters on "#{ident}") if m.nil? || lowered.start_with?('@')

          key = read_sf_string(m[1], 0)[0]
          components << { 'id' => lowered, 'raw' => %("#{lowered}";key=#{sf_string(key)}), 'key' => key }
        end
        params = parse_params(params_raw[(close + 1)..])
        entries << { 'label' => label, 'components' => components, 'paramsRaw' => params_raw, 'params' => params }
      end
      entries
    end

    def parse_signature(value)
      out = {}
      split_top_level(value, ',').each do |member_raw|
        member = trim(member_raw)
        next if member.empty?

        eq = index_of_top_level(member, '=')
        raise ParseError, 'malformed Signature member' if eq == -1

        label = trim(member[0, eq])
        v = trim(member[(eq + 1)..])
        raise ParseError, 'Signature value must be a byte sequence (:base64:)' if v.length < 2 || v[0] != ':' || v[-1] != ':'

        out[label] = node_b64decode(v[1..-2])
      end
      out
    end

    # ---- signature base (RFC 9421 section 2.5) ----------------------------------------------------------------------------

    def normalize_headers(h)
      m = {}
      return m unless truthy?(h)

      entries(h).each do |k, v|
        name = k.downcase
        value = if v.is_a?(Array)
                  v.map { |x| trim(need_str(x, 'a header value')) }.join(', ')
                else
                  trim(need_str(v, 'a header value'))
                end
        prev = m[name]
        m[name] = prev.nil? ? value : "#{prev}, #{value}"
      end
      m
    end

    # [parsed URL, fragment or nil, whether a `?` starts a query, whether it has credentials] of a special-scheme URL.
    def url_parts(url)
      raise CodedError.new('Invalid URL', 'ERR_INVALID_URL') unless url.is_a?(String)

      s = utf8(url).force_encoding(Encoding::UTF_8)
      u = WhatwgUrl.parse(s)
      raise CodedError.new('Invalid URL', 'ERR_INVALID_URL') if u.nil? || !SPECIAL_SCHEMES.include?(u['scheme'])

      s = s.sub(/\A[\x00-\x20]+/, '').sub(/[\x00-\x20]+\z/, '').delete("\t\n\r")
      hash_at = s.index('#')
      nofrag = hash_at ? s[0, hash_at] : s
      authority = s[(s.index(':') + 1)..].sub(%r{\A[/\\]+}, '').split(%r{[/\\?#]}, 2)[0].to_s
      [u, hash_at ? s[(hash_at + 1)..] : nil, nofrag.include?('?'), authority.include?('@')]
    end

    # `new URL(url).href` for a special-scheme URL without credentials; a URL with credentials is refused.
    def href(url)
      u, frag, has_query, creds = url_parts(url)
      raise ArgumentError, 'a URL with credentials is not supported' if creds

      out = "#{u['scheme']}://#{u['host']}#{u['pathname']}#{u['search']}"
      out += '?' if has_query && u['search'] == ''
      out += "##{WhatwgUrl.pct(frag, '"<>`')}" unless frag.nil?
      out
    end

    def build_context(method, url, headers)
      u = url_parts(url)[0]
      path = u['pathname'] == '' ? '/' : u['pathname']
      {
        'method' => need_str(method, 'the method').upcase,
        'authority' => u['host'].downcase,
        'path' => path,
        'url' => url,
        'scheme' => u['scheme'].downcase,
        'query' => u['search'] == '' ? '?' : u['search'],
        'requestTarget' => path + u['search'],
        'headers' => headers
      }
    end

    # RFC 9421 section 2.1.2: the serialized value of dictionary member `key`; only string members in canonical form.
    def dictionary_member(header, key, header_name)
      split_top_level(header, ',').each do |member_raw|
        member = trim(member_raw)
        eq = index_of_top_level(member, '=')
        next if eq == -1 || trim(member[0, eq]) != key

        value = trim(member[(eq + 1)..])
        _v, nxt = read_sf_string(value, 0)
        # parameters are allowed only in compact canonical form, so the verbatim text IS the serialization
        raise ParseError, %(member "#{key}" of "#{header_name}" is not in canonical form) unless MEMBER_PARAMS.match?(value[nxt..])

        return value
      end
      raise ParseError, %("#{header_name}" has no dictionary member "#{key}")
    end

    def derive_component_value(component, ctx)
      cid = component['id']
      case cid
      when '@method' then return ctx['method']
      when '@authority' then return ctx['authority']
      when '@path' then return ctx['path']
      when '@target-uri' then return href(ctx['url'])
      when '@scheme' then return ctx['scheme']
      when '@query' then return ctx['query']
      when '@request-target' then return ctx['requestTarget']
      end
      raise ParseError, %(unsupported derived component "#{cid}") if cid.start_with?('@')

      v = ctx['headers'][cid]
      raise ParseError, %(covered header "#{cid}" is absent from the request) if v.nil?
      return dictionary_member(v, component['key'], cid) unless component['key'].nil?

      v
    end

    def build_signature_base(components, params_raw, ctx)
      lines = components.map { |c| "#{c['raw']}: #{derive_component_value(c, ctx)}" }
      lines << %("@signature-params": #{params_raw})
      lines.join("\n")
    end

    # ---- sign_request ----------------------------------------------------------------------------------------------------

    # Build the `Signature-Input` / `Signature` header values over the RFC 9421 base (`@authority @method @path`, plus
    # `@query` when the URL has a query string, the `Signature-Agent` component and any `coverHeaders`). `input`: method, url,
    # headers?, key, keyid, created?, expiresInSec?, agentDirectoryUrl?, agentDirectoryKey?, components?, coverHeaders?, nonce?,
    # label?. Returns {"signatureInput", "signature", "signatureAgent"?, "covered", "headers"}.
    def sign_request(input, now = nil)
      hash!(input)
      label = input['label']
      label = DEFAULT_SIGNATURE_LABEL if label.nil?
      created = input['created']
      created = (now.nil? ? Time.now.to_f : now).floor if created.nil?
      need_num(created, 'created')
      ex = input['expiresInSec']
      expires = created.to_f + need_num(ex.nil? ? DEFAULT_EXPIRES_SEC : ex, 'expiresInSec').to_f

      working = normalize_headers(input['headers'])
      emitted = {}

      components = []
      comps = input.fetch('components', UNDEF)
      derived = comps.equal?(UNDEF) || comps.nil? ? %w[@authority @method @path] : list_of(comps, 'components').dup
      # by default a URL with a query string also covers @query (the verifier requires it)
      derived << '@query' if comps.equal?(UNDEF) && need_str(input['url'], 'url').match?(/\?[^#]/)
      raise ArgumentError, 'signRequest: the web-bot-auth profile requires @authority to be covered' unless derived.include?('@authority')

      derived.each do |cid|
        lower = need_str(cid, 'a component').downcase
        raise ArgumentError, %(signRequest: components must be derived components, got "#{cid}" (use coverHeaders for headers)) unless lower.start_with?('@')

        components << { 'id' => lower, 'raw' => %("#{lower}"), 'key' => nil }
      end

      signature_agent = nil
      agent_url = input.fetch('agentDirectoryUrl', UNDEF)
      agent_key = input.fetch('agentDirectoryKey', UNDEF)
      if !agent_url.equal?(UNDEF)
        signature_agent = if agent_key.equal?(UNDEF)
                            sf_string(agent_url)
                          else
                            "#{Js.string(agent_key)}=#{sf_string(agent_url)}"
                          end
        working['signature-agent'] = signature_agent
        emitted[SIGNATURE_AGENT_HEADER] = signature_agent
        if agent_key.equal?(UNDEF)
          components << { 'id' => 'signature-agent', 'raw' => '"signature-agent"', 'key' => nil }
        else
          components << { 'id' => 'signature-agent', 'raw' => %("signature-agent";key=#{sf_string(agent_key)}), 'key' => agent_key }
        end
      elsif !agent_key.equal?(UNDEF)
        raise ArgumentError, 'signRequest: agentDirectoryKey requires agentDirectoryUrl'
      end

      cover = input['coverHeaders']
      (cover.nil? ? [] : list_of(cover, 'coverHeaders')).each do |name|
        lower = need_str(name, 'a covered header').downcase
        raise ArgumentError, %(signRequest: covered header "#{name}" is not present in headers) unless working.key?(lower)

        components << { 'id' => lower, 'raw' => %("#{lower}"), 'key' => nil } unless components.any? { |c| c['id'] == lower }
      end

      ctx = build_context(input['method'], input['url'], working)

      # parameter order follows the Web Bot Auth architecture draft: created, keyid, alg, expires, nonce, tag
      inner_list = components.map { |c| c['raw'] }.join(' ')
      params_raw = "(#{inner_list});created=#{Js.string(created)};keyid=#{sf_string(input['keyid'])};alg=#{sf_string(WEB_BOT_AUTH_ALG)};expires=#{Js.string(expires)}"
      params_raw += ";nonce=#{sf_string(input['nonce'])}" unless input.fetch('nonce', UNDEF).equal?(UNDEF)
      params_raw += ";tag=#{sf_string(WEB_BOT_AUTH_TAG)}"

      base = build_signature_base(components, params_raw, ctx)
      sig = ed_sign(input['key'], utf8(base))

      signature_input = "#{Js.string(label)}=#{params_raw}"
      signature = "#{Js.string(label)}=:#{b64(sig)}:"
      emitted['Signature-Input'] = signature_input
      emitted['Signature'] = signature
      out = { 'signatureInput' => signature_input, 'signature' => signature, 'covered' => components.map { |c| c['id'] }, 'headers' => emitted }
      out['signatureAgent'] = signature_agent unless signature_agent.nil?
      out
    end

    # ---- verify_signed_request --------------------------------------------------------------------------------------------

    def x_from_resolved(k)
      return nil if k.nil?
      return (k.bytesize == 32 ? b64u(k) : nil) if k.is_a?(String) && k.encoding == Encoding::BINARY
      return k['x'] if k.is_a?(Hash) && k['x'].is_a?(String) && k['crv'] == 'Ed25519' && k['kty'] == 'OKP'

      nil
    end

    def resolve_from_jwks(keyid, jwks, now, skew)
      keys = jwks.is_a?(Hash) ? jwks['keys'] : nil
      raise TypeError, 'jwks.keys is not an array' unless keys.is_a?(Array)

      match = nil
      keys.each do |j|
        raise TypeError, 'a directory key must not be null' if j.nil?

        if j.is_a?(Hash) && str_eq?(j['kid'], keyid)
          match = j
          break
        end
      end
      return nil if match.nil?

      # a published validity window is enforced; a bound that is not a finite number cannot be checked, so the key resolves to nothing
      %w[nbf exp].each { |b| return nil if match.key?(b) && !finite?(match[b]) }
      return nil if (match.key?('nbf') || match.key?('exp')) && !(finite?(now) && finite?(skew))
      return nil if match.key?('nbf') && now + skew < match['nbf']
      return nil if match.key?('exp') && now - skew > match['exp']

      x_from_resolved(match)
    end

    # Verify an RFC 9421 signature over `req` = {"method", "url", "headers"}. `opts`: resolveKey (a callable: keyid -> 32 raw
    # bytes, a public JWK Hash or nil) or jwks ({"keys" => [...]}), now?, clockSkewSec?, maxAgeSec?, requireExpires? (default
    # true), requiredTag? (default "web-bot-auth"; nil = not enforced), label?, requiredComponents? (default @authority @method
    # @path, plus @query when the URL has a query string), maxLifetimeSec? (default 300; Float::INFINITY disables),
    # replayCache? (an object with `claim(key, expires_at_sec, now_sec)`; see memory_replay_cache). Never raises.
    def verify_signed_request(req, opts)
      opts = {} unless opts.is_a?(Hash)
      resolve = opts['resolveKey']
      jwks = opts['jwks']
      return { 'valid' => false, 'reason' => 'verifySignedRequest: provide resolveKey or jwks' } if !truthy?(resolve) && !truthy?(jwks)

      headers = normalize_headers(hash!(req)['headers'])
      sig_input_header = headers['signature-input']
      sig_header = headers['signature']
      return { 'valid' => false, 'reason' => 'missing Signature-Input or Signature header' } if sig_input_header.nil? || sig_header.nil?

      inputs = parse_signature_input(sig_input_header)
      sigs = parse_signature(sig_header)
      required_tag = opts.fetch('requiredTag', UNDEF)
      required_tag = WEB_BOT_AUTH_TAG if required_tag.equal?(UNDEF)

      chosen = nil
      if opts.key?('label')
        chosen = inputs.find { |e| str_eq?(e['label'], opts['label']) }
      elsif !required_tag.nil?
        chosen = inputs.find { |e| str_eq?(e['params']['tag'], required_tag) }
        chosen = inputs[0] if chosen.nil? && !inputs.empty?
      else
        chosen = inputs[0]
      end
      return { 'valid' => false, 'reason' => 'no matching signature in Signature-Input' } if chosen.nil?

      sig_bytes = sigs[chosen['label']]
      return { 'valid' => false, 'reason' => %(no Signature entry for label "#{chosen['label']}") } if sig_bytes.nil?

      tag = chosen['params']['tag']
      tag = nil unless tag.is_a?(String)
      if !required_tag.nil? && !str_eq?(tag, required_tag)
        return { 'valid' => false, 'reason' => %(tag "#{tag.nil? ? 'undefined' : tag}" does not match required "#{Js.string(required_tag)}") }
      end

      # @authority is required by the profile; @method and @path too, so a signature cannot be replayed on another method or path
      covered = chosen['components'].map { |c| c['id'] }
      req_components = opts.fetch('requiredComponents', UNDEF)
      required = req_components.equal?(UNDEF) || req_components.nil? ? %w[@authority @method @path] : iter(req_components)
      required.each do |cid|
        return { 'valid' => false, 'reason' => "#{Js.string(cid)} is not a covered component" } unless covered.include?(cid)
      end
      if req_components.equal?(UNDEF)
        url = need_str(req['url'], 'url')
        q = url.index('?')
        return { 'valid' => false, 'reason' => '@query is not a covered component' } if q && url[(q + 1)..].split('#', -1)[0].to_s != '' && !covered.include?('@query')
      end

      alg = chosen['params'].fetch('alg', UNDEF)
      return { 'valid' => false, 'reason' => %(unsupported alg "#{Js.string(alg)}") } if !alg.equal?(UNDEF) && !str_eq?(alg, WEB_BOT_AUTH_ALG)

      now = opts['now']
      now = now_sec if now.nil?
      now = pn(now)
      skew = opts['clockSkewSec']
      skew = 0 if skew.nil?
      skew = pn(skew)
      created = chosen['params']['created']
      created = nil unless num?(created)
      expires = chosen['params']['expires']
      expires = nil unless num?(expires)
      return { 'valid' => false, 'reason' => 'missing expires parameter' } if expires.nil? && opts['requireExpires'] != false
      return { 'valid' => false, 'reason' => 'signature has expired' } if !expires.nil? && !(finite?(now) && finite?(skew) && now <= expires + skew)
      return { 'valid' => false, 'reason' => 'signature created-time is in the future' } if !created.nil? && !(finite?(now) && finite?(skew) && created <= now + skew)

      max_age = opts.fetch('maxAgeSec', UNDEF)
      return { 'valid' => false, 'reason' => 'signature is older than maxAgeSec' } if !max_age.equal?(UNDEF) && !created.nil? && !(finite?(now) && finite?(skew) && now - created <= pn(max_age) + skew)

      max_lifetime = opts['maxLifetimeSec']
      max_lifetime = 300 if max_lifetime.nil?
      if finite?(max_lifetime)
        return { 'valid' => false, 'reason' => 'missing created parameter (needed to bound the signature lifetime)' } if created.nil?
        return { 'valid' => false, 'reason' => 'signature lifetime exceeds maxLifetimeSec' } if !expires.nil? && expires - created > max_lifetime
      end

      keyid = chosen['params']['keyid']
      return { 'valid' => false, 'reason' => 'missing keyid parameter' } unless keyid.is_a?(String)

      x = if truthy?(resolve)
            x_from_resolved(resolve.call(keyid))
          elsif truthy?(jwks)
            resolve_from_jwks(keyid, jwks, now, skew)
          end
      return { 'valid' => false, 'reason' => %(could not resolve key "#{keyid}") } if x.nil?

      ctx = build_context(req['method'], req['url'], headers)
      base = build_signature_base(chosen['components'], chosen['paramsRaw'], ctx)
      return { 'valid' => false, 'reason' => 'signature does not verify under the resolved key' } unless ed_verify_x(x, utf8(base), sig_bytes)

      nonce = chosen['params']['nonce']
      nonce = nil unless nonce.is_a?(String)
      cache = opts['replayCache']
      if truthy?(cache)
        until_ = if !expires.nil?
                   expires
                 elsif !created.nil?
                   created + (finite?(max_lifetime) ? max_lifetime : 3600)
                 else
                   now + 3600
                 end
        key = "#{keyid}|#{nonce.nil? ? b64u(sig_bytes) : nonce}"
        return { 'valid' => false, 'reason' => 'replayed signature' } unless Js.truthy?(cache.claim(key, until_ + skew, now))
      end
      out = { 'valid' => true, 'label' => chosen['label'], 'keyid' => keyid, 'covered' => covered }
      out['created'] = created unless created.nil?
      out['expires'] = expires unless expires.nil?
      out['tag'] = tag unless tag.nil?
      out['nonce'] = nonce unless nonce.nil?
      out
    rescue StandardError => e
      { 'valid' => false, 'reason' => "verification failed (fail closed): #{e.message}" }
    end

    # In-process single-use store for accepted signatures. Fails CLOSED (raises) when `max_entries` unexpired claims are held.
    class MemoryReplayCache
      def initialize(max_entries)
        @max = max_entries
        @seen = {}
      end

      def claim(key, expires_at_sec, now_sec)
        return false unless WebBotAuth.finite?(now_sec) # a non-finite clock admits nothing, whichever side it lands on

        if @seen.length >= @max
          @seen.delete_if { |_k, exp| WebBotAuth.finite?(now_sec) && exp < now_sec } # an infinite clock evicts nothing
          raise 'replay cache full' if @seen.length >= @max
        end
        existing = @seen[key]
        return false if !existing.nil? && !(existing < now_sec)

        @seen[key] = expires_at_sec
        true
      end
    end

    def memory_replay_cache(max_entries = nil) = MemoryReplayCache.new(max_entries.nil? ? 100_000 : max_entries)

    # ---- key directory (JWKS) and handler --------------------------------------------------------------------------------

    # JWKS for the agent's public keys: [{"publicKey" => bytes, "keyid"?, "use"?, "nbf"?, "exp"?}]; `kid` defaults to the thumbprint.
    def build_key_directory(keys)
      out = list_of(keys, 'keys').map do |k|
        hash!(k)
        pk = k.fetch('publicKey')
        raise TypeError, 'the public key must be bytes' unless pk.is_a?(String)

        kid = k['keyid']
        entry = { 'kty' => 'OKP', 'crv' => 'Ed25519', 'x' => b64u(pk), 'kid' => kid.nil? ? jwk_thumbprint(pk) : kid }
        %w[use nbf exp].each { |f| entry[f] = k[f] if k.key?(f) }
        entry
      end
      { 'keys' => out }
    end

    # The directory entry whose `kid` is `keyid`, or nil.
    def resolve_from_directory(directory, keyid)
      list_of(hash!(directory)['keys'], 'directory.keys').each do |j|
        raise TypeError, 'a directory key must not be null' if j.nil?
        return j if j.is_a?(Hash) && str_eq?(j['kid'], keyid)
      end
      nil
    end

    # A framework-agnostic handler: the 200 response when the path is the well-known directory path, else nil.
    def directory_handler(keys)
      body = Js.json(build_key_directory(keys))
      lambda do |pathname|
        path = need_str(pathname, 'the path').partition('?')[0]
        next nil unless path == WELL_KNOWN_DIRECTORY_PATH

        { 'status' => 200, 'headers' => { 'content-type' => DIRECTORY_CONTENT_TYPE, 'cache-control' => 'max-age=86400' }, 'body' => body }
      end
    end

    # ---- PCA proof binding ------------------------------------------------------------------------------------------------

    # The `PCA-Action` header carrying a PCActn (base64url of its canonical wire form).
    def proof_headers(pcactn)
      raise TypeError, 'canonicalize: unsupported type undefined' if pcactn.equal?(UNDEF)

      { PCA_HEADER => b64u(utf8(AtlasPca.canonicalize(pcactn))) }
    end

    # Reverse proof_headers: the `PCA-Action` header value to the PCActn. Raises on a malformed header or PCActn.
    def decode_proof_header(value)
      text = AtlasPca.decode_pca_header(value)
      raise CodedError.new('PCA-Action header is not strict unpadded base64url UTF-8', 'invalid_pca_header') if text.nil?
      raise ArgumentError, AtlasPca::ARTIFACT_SIZE_REASON if text.bytesize > AtlasPca::MAX_ARTIFACT_BYTES

      v = AtlasPca.parse_json(text)
      raise TypeError, 'decodePCActn: not an object' unless v.is_a?(Hash)

      v
    end

    # sign_request plus the PCActn in `PCA-Action` as a covered header. `input` is a sign_request input with `pcactn`.
    def sign_request_with_proof(input, now = nil)
      hash!(input)
      proof = proof_headers(input.fetch('pcactn', UNDEF))
      headers = spread_obj(input['headers'].nil? ? {} : input['headers'])
      headers.update(proof)
      cover = input['coverHeaders']
      cover_headers = iter(cover.nil? ? [] : cover) + [PCA_PROOF_COMPONENT]
      rest = input.reject { |k, _| k == 'pcactn' }
      rest['headers'] = headers
      rest['coverHeaders'] = cover_headers
      result = sign_request(rest, now)
      out = result.dup
      out['headers'] = result['headers'].merge(proof)
      out['proofHeader'] = proof
      out
    end

    def proof_stage(base, req, opts)
      return base unless base['valid']
      return { 'valid' => false, 'reason' => "the #{PCA_HEADER} proof header is not covered by the signature" } unless (base['covered'] || []).include?(PCA_PROOF_COMPONENT)

      header_value = normalize_headers(req['headers'])[PCA_PROOF_COMPONENT]
      return { 'valid' => false, 'reason' => "missing #{PCA_HEADER} header" } if header_value.nil?

      begin
        pcactn = decode_proof_header(header_value)
      rescue StandardError => e
        return { 'valid' => false, 'reason' => "invalid PCActn in #{PCA_HEADER}: #{e.message}" }
      end
      expected = hash!(opts).fetch('expectedPCActn', UNDEF)
      return { 'valid' => false, 'reason' => 'carried PCActn does not match the expected proof' } if !expected.equal?(UNDEF) && AtlasPca.hash_canonical(pcactn) != AtlasPca.hash_canonical(expected)

      base.merge('pcactn' => pcactn)
    end

    # verify_signed_request AND extract the proof: `PCA-Action` must be a covered component; `opts["expectedPCActn"]`, when
    # given, must equal the carried PCActn by canonical digest. The returned `pcactn` is bound to the verified signature.
    def verify_signed_request_with_proof(req, opts)
      proof_stage(verify_signed_request(req, opts), req, opts)
    end

    # ---- Content-Digest (RFC 9530) ----------------------------------------------------------------------------------------

    DIGEST_MEMBER = %r{\A([a-z*][a-z0-9_\-.*]*)=:([A-Za-z0-9+/]*={0,2}):\z}

    def body_bytes(body)
      raise TypeError, 'the body must be a string or bytes' unless body.is_a?(String)

      utf8(body)
    end

    # The raw digest bytes of `body` under `alg` ("sha-256" or "sha-512").
    def content_digest_bytes(body, alg)
      raise CodedError.new('The "algorithm" argument must be of type string. Received undefined', 'ERR_INVALID_ARG_TYPE') unless alg.is_a?(String) && CONTENT_DIGEST_ALGS.include?(alg)

      (alg == 'sha-256' ? Digest::SHA256 : Digest::SHA512).digest(body_bytes(body))
    end

    # The `Content-Digest` field value, e.g. `sha-256=:X48E9q...=:` (members in the given order, duplicates dropped).
    def content_digest_header(body, algs = nil)
      algs = algs.nil? ? ['sha-256'] : list_of(algs, 'algs')
      raise ArgumentError, 'contentDigestHeader: name at least one algorithm' if algs.empty?

      seen = []
      parts = []
      algs.each do |alg|
        raise ArgumentError, "contentDigestHeader: unsupported algorithm #{Js.string(alg)}" unless alg.is_a?(String) && CONTENT_DIGEST_ALGS.include?(alg)
        next if seen.include?(alg)

        seen << alg
        parts << "#{alg}=:#{b64(content_digest_bytes(body, alg))}:"
      end
      parts.join(', ')
    end

    # Parse the dictionary: key -> byte sequence. Raises on anything that is not `key=:base64:` (parameters and repeats refused).
    def parse_content_digest(value)
      out = {}
      psplit(need_str(value, 'the Content-Digest value'), ',').each do |raw|
        member = trim(raw)
        raise ArgumentError, 'empty dictionary member' if member.empty?

        m = DIGEST_MEMBER.match(member)
        raise ArgumentError, %(malformed Content-Digest member "#{member}") if m.nil?

        key = m[1]
        b64s = m[2]
        raise ArgumentError, %(member "#{key}" is not canonical base64) unless (b64s.length % 4).zero?

        data = node_b64decode(b64s)
        raise ArgumentError, %(member "#{key}" is not canonical base64) if b64(data) != b64s
        raise ArgumentError, %(member "#{key}" appears twice) if out.key?(key)

        out[key] = data
      end
      out
    end

    # Check `body` against a `Content-Digest` field value. Every supported member present must match; unsupported members are
    # ignored; at least one supported member must be present; every algorithm in `opts["require"]` must be among the matched.
    def verify_content_digest(header, body, opts = nil)
      return { 'valid' => false, 'reason' => 'missing Content-Digest' } if header.nil? || trim(need_str(header, 'the header')).empty?

      members = parse_content_digest(header)
      matched = []
      CONTENT_DIGEST_ALGS.each do |alg|
        got = members[alg]
        next if got.nil?

        want = content_digest_bytes(body, alg)
        return { 'valid' => false, 'reason' => "#{alg} digest does not match the content" } unless got.bytesize == want.bytesize && OpenSSL.fixed_length_secure_compare(got, want)

        matched << alg
      end
      return { 'valid' => false, 'reason' => 'no supported digest algorithm (sha-256 or sha-512)' } if matched.empty?

      req = opts.is_a?(Hash) ? opts['require'] : nil
      (req.nil? ? [] : iter(req)).each do |alg|
        return { 'valid' => false, 'reason' => "required #{Js.string(alg)} digest is absent" } unless matched.include?(alg)
      end
      { 'valid' => true, 'matched' => matched }
    rescue StandardError => e
      { 'valid' => false, 'reason' => "malformed Content-Digest: #{e.message}" }
    end

    # ---- signed key-directory responses ----------------------------------------------------------------------------------

    X_RE = /\A[A-Za-z0-9_-]{43}\z/
    AUTHORITY_RE = /\A[a-z0-9.\-\[\]:]+\z/
    LABEL_RE = '[a-z][a-z0-9_.*-]*'
    DIR_ENTRY = /\A(#{LABEL_RE})=\("@authority";req\)((?:;[a-z]+=(?:[0-9]+|"[A-Za-z0-9_.\-]*"))*)\z/
    DIR_SIG = %r{\A(#{LABEL_RE})=:([A-Za-z0-9+/]+={0,2}):\z}

    def json_parse(text)
      Js.parse_no_duplicates(need_str(text, 'the document')) # a duplicate member would otherwise keep the last value
    end

    # Strictly parse a directory document: every key must be a well-formed Ed25519 OKP JWK with a string `kid`. Raises otherwise.
    def parse_key_directory(text)
      doc = json_parse(text)
      keys = doc.is_a?(Hash) ? doc['keys'] : nil
      raise ArgumentError, 'directory has no keys' if !keys.is_a?(Array) || keys.empty?

      keys.each do |j|
        raise ArgumentError, 'directory contains a malformed key' if !j.is_a?(Hash) || j['kty'] != 'OKP' || j['crv'] != 'Ed25519' || !j['kid'].is_a?(String) || j['kid'] == ''

        x = j['x']
        raise ArgumentError, 'directory contains a malformed key' if !x.is_a?(String) || !X_RE.match?(x) || node_b64decode(x).bytesize != 32

        %w[nbf exp].each { |f| raise ArgumentError, 'directory contains a malformed key' if j.key?(f) && !finite?(j[f]) }
      end
      doc
    end

    # Sign a directory response (RFC 9421 over `"@authority";req`, one signature per key). `input`: keys (signing keys),
    # directory, authority (lower-case host or host:port), created?, expiresInSec?. Returns the exact `body` and the `headers`.
    def sign_directory_response(input, now = nil)
      hash!(input)
      keys = list_of(input['keys'], 'keys')
      raise ArgumentError, 'signDirectoryResponse: at least one signing key is required' if keys.empty?

      authority = need_str(input['authority'], 'authority')
      raise ArgumentError, 'signDirectoryResponse: authority must be a lower-case host or host:port' unless AUTHORITY_RE.match?(authority)

      created = input['created']
      created = (now.nil? ? Time.now.to_f : now).floor if created.nil?
      need_num(created, 'created')
      ex = input['expiresInSec']
      expires = created.to_f + need_num(ex.nil? ? DIRECTORY_LIFETIME_SEC : ex, 'expiresInSec').to_f
      directory = input['directory']
      body = Js.json(directory)
      inputs = []
      sigs = []
      dir_keys = list_of(directory.is_a?(Hash) ? directory['keys'] : nil, 'directory.keys')
      keys.each_with_index do |k, i|
        x = b64u(ed_public(k))
        raise ArgumentError, 'signDirectoryResponse: a signing key is not in the directory' unless dir_keys.any? { |j| j.is_a?(Hash) && j['x'] == x }

        keyid = thumbprint_of_x(x)
        label = "sig#{i + 1}"
        params = %[("@authority";req);created=#{Js.string(created)};expires=#{Js.string(expires)};keyid="#{keyid}";alg="ed25519";tag="#{DIRECTORY_SIGNATURE_TAG}"]
        base = %("@authority";req: #{authority}\n"@signature-params": #{params})
        inputs << "#{label}=#{params}"
        sigs << "#{label}=:#{b64(ed_sign(k, utf8(base)))}:"
      end
      { 'body' => body, 'headers' => { 'content-type' => DIRECTORY_CONTENT_TYPE, 'signature-input' => inputs.join(', '), 'signature' => sigs.join(', ') } }
    end

    # Verify a signed directory response: `input` = {"authority", "headers" (lower-case `signature-input`, `signature`), "body",
    # "now"?, "clockSkewSec"?, "maxLifetimeSec"?}. Fail closed: {"valid" => false, "reason", "keys" => []} unless at least one
    # signature is valid; when valid, `keys` holds only the directory keys that carry a valid signature.
    def verify_directory_response(input, now = nil)
      fail_ = ->(reason) { { 'valid' => false, 'reason' => reason, 'keys' => [] } }
      begin
        headers = hash!(input).fetch('headers')
        hash!(headers)
        sig_input = headers['signature-input']
        sig_header = headers['signature']
        return fail_.call('missing signature-input or signature header') if !truthy?(sig_input) || !truthy?(sig_header)

        directory = parse_key_directory(input['body'])
        sigs = {}
        psplit(sig_header, ', ').each do |part|
          m = DIR_SIG.match(part)
          return fail_.call('malformed signature header') if m.nil?

          sigs[m[1]] = node_b64decode(m[2])
        end
        t = input['now']
        t = (now.nil? ? Time.now.to_f : now).floor if t.nil?
        t = pn(t)
        skew = input['clockSkewSec']
        skew = pn(skew.nil? ? 0 : skew)
        max_life = input['maxLifetimeSec']
        max_life = pn(max_life.nil? ? DIRECTORY_LIFETIME_SEC : max_life)
        good = {}
        last_reason = 'no signature entry'
        psplit(sig_input, ', ').each do |raw|
          m = DIR_ENTRY.match(raw)
          if m.nil?
            last_reason = 'malformed signature-input entry (must cover exactly "@authority";req)'
            next
          end
          label = m[1]
          params = {}
          dup = false
          m[2].split(';', -1).drop(1).each do |p|
            eq = p.index('=')
            k = p[0, eq]
            dup = true if params.key?(k)
            params[k] = p[(eq + 1)..]
          end
          if dup
            last_reason = 'duplicate signature parameter'
            next
          end
          sv = lambda do |k|
            v = params[k]
            !v.nil? && v.start_with?('"') ? v[1..-2] : nil
          end
          nv = lambda do |k|
            v = params[k]
            !v.nil? && v.match?(/\A[0-9]+\z/) ? parse_int(v) : nil
          end
          if sv.call('tag') != DIRECTORY_SIGNATURE_TAG
            last_reason = 'wrong tag'
            next
          end
          alg = params['alg']
          if !alg.nil? && alg != '"ed25519"'
            last_reason = 'unsupported alg'
            next
          end
          created = nv.call('created')
          expires = nv.call('expires')
          if created.nil? || expires.nil?
            last_reason = 'created and expires are required'
            next
          end
          unless finite?(t) && finite?(skew) && created <= t + skew
            last_reason = 'signature created-time is in the future'
            next
          end
          unless finite?(t) && finite?(skew) && t <= expires + skew
            last_reason = 'signature has expired'
            next
          end
          if expires - created > max_life
            last_reason = 'signature lifetime exceeds maxLifetimeSec'
            next
          end
          keyid = sv.call('keyid')
          if keyid.nil?
            last_reason = 'missing keyid'
            next
          end
          key = directory['keys'].find { |j| thumbprint_of_x(j['x']) == keyid }
          if key.nil?
            last_reason = 'keyid is not the thumbprint of any directory key'
            next
          end
          if (num?(key['nbf']) && t + skew < key['nbf']) || (num?(key['exp']) && t - skew > key['exp'])
            last_reason = 'directory key is outside its validity window'
            next
          end
          sig = sigs[label]
          if sig.nil? || sig.bytesize != 64
            last_reason = 'no valid signature bytes for the label'
            next
          end
          base = %("@authority";req: #{Js.string(input['authority'])}\n"@signature-params": #{raw[(label.length + 1)..]})
          unless ed_verify_x(key['x'], utf8(base), sig)
            last_reason = 'signature does not verify'
            next
          end
          good[key['kid']] = key
        end
        return fail_.call(last_reason) if good.empty?

        { 'valid' => true, 'keys' => good.values }
      rescue StandardError => e
        fail_.call("verification failed (fail closed): #{e.message}")
      end
    end

    # ---- fetch_key_directory ---------------------------------------------------------------------------------------------

    # Response of the built-in fetcher: status, headers.get(name) and text.
    class FetchResponse
      Headers = Struct.new(:map) do
        def get(name) = map[name.downcase]
      end
      attr_reader :status, :headers

      def initialize(status, headers, data)
        @status = status
        @headers = Headers.new(headers.to_h { |k, v| [k.downcase, v] })
        @data = data
      end

      def text = @data.dup.force_encoding(Encoding::UTF_8).scrub
    end

    # No redirects followed; the body is capped at 1 MiB.
    def net_fetch(url, init)
      require 'net/http'
      uri = URI.parse(url)
      timeout = init['timeout']
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', open_timeout: timeout, read_timeout: timeout) do |http|
        http.request(Net::HTTP::Get.new(uri, init['headers'] || {}))
      end
      FetchResponse.new(res.code.to_i, res.each_header.to_h, res.body.to_s.byteslice(0, 1 << 20))
    end

    # Fetch and strictly parse a Web Bot Auth key directory. FAIL-CLOSED: raises on a non-https URL, redirect, non-200 status,
    # wrong content type, oversize body, invalid JSON, or any key that is not a well-formed Ed25519 OKP JWK. Never returns a
    # partial directory. `options`: fetch? (callable `fetch(url, init) -> response`, `init` = {"redirect" => "error", "timeout" =>
    # seconds, "headers" => {...}}; the response has `status`, `headers.get(name)` and `text`), maxBytes? (UTF-16 units,
    # default 65536), timeoutMs? (default 5000), allowInsecureHttp?, requireSignature?, now?.
    def fetch_key_directory(url, options = nil)
      options ||= {}
      u = url_parts(url)[0]
      raise ArgumentError, 'directory URL must be https' if u['scheme'] != 'https' && !(options['allowInsecureHttp'] == true && u['scheme'] == 'http')

      target = href(url)
      do_fetch = options['fetch'] || method(:net_fetch)
      timeout_ms = options['timeoutMs']
      res = do_fetch.call(target, { 'redirect' => 'error', 'timeout' => (timeout_ms.nil? ? 5000 : timeout_ms) / 1000.0,
                                    'headers' => { 'accept' => 'application/http-message-signatures-directory+json' } })
      raise ArgumentError, "directory fetch returned status #{Js.string(res.status)}" if res.status != 200

      ct = trim((res.headers.get('content-type') || '').split(';', -1)[0].to_s).downcase
      raise ArgumentError, 'directory has the wrong content type' if ct != DIRECTORY_CONTENT_TYPE

      text = res.text
      max_bytes = options['maxBytes']
      raise ArgumentError, 'directory response is too large' if Js.len16(text) > (max_bytes.nil? ? 65_536 : max_bytes)

      directory = parse_key_directory(text)
      if options['requireSignature'] == true
        vin = { 'authority' => u['host'].downcase, 'body' => text,
                'headers' => { 'signature-input' => res.headers.get('signature-input') || '', 'signature' => res.headers.get('signature') || '' } }
        vin['now'] = options['now'] unless options['now'].nil?
        v = verify_directory_response(vin)
        raise ArgumentError, "directory signature: #{v['reason']}" unless v['valid']

        return { 'keys' => v['keys'] }
      end
      directory
    end
  end
end
