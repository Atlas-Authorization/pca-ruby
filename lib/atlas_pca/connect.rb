# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require_relative '../atlas_pca'
require_relative 'js_compat'
require_relative 'predicates'
require_relative 'whatwg_url'
require_relative 'siem'
require_relative 'connect_replay'

module AtlasPca
  # An OUTBOUND connection / token vault for PCA agents: it holds an agent's third-party OAuth tokens and refreshes them, releasing a
  # fresh, least-privilege access token only when a verified Proof-Carrying Action proves authority over the provider and scopes.
  # Mirrors the TypeScript reference (@atlasauth/pca-connect): oauth_scope caveats, token refresh, the proxy-mode request extractor,
  # signed release receipts, the envelope-encrypted store and the TokenVault.
  #
  # The reference's async functions are synchronous here. Injected transports are plain callables: fetch.call(url, init) returns an
  # object with ok, status, json and text; proxy_fetch.call(req) returns {'status', 'headers', 'body'}; the replay option is a
  # one-time-use store (ConnectReplay::InMemoryReplayStore or your own: consume_once(key, retain_until_ms, now_ms) -> bool).
  # Connections, caveats and PCActns are String-keyed Hashes with the reference's member names.
  module Connect
    UNDEF = Predicates::UNDEF
    OAUTH_SCOPE_CAVEAT = 'oauth_scope'

    module_function

    # ---- JS-value helpers ---------------------------------------------------------------------------------------------------
    def finite?(x) = ConnectReplay.finite?(x)

    # o[k] where a missing member (or a non-object) is undefined
    def g(o, k) = o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF

    # o["k"] where a missing member raises (a typed field the reference reads unguarded)
    def sub(o, k)
      raise TypeError, "cannot read '#{k}'" unless o.is_a?(Hash)

      o.fetch(k)
    end

    # Object.entries of a JSON value (strings and arrays yield their indices; null and undefined throw)
    def entries(v)
      case v
      when Hash then v.to_a
      when Array then v.each_with_index.map { |x, i| [i.to_s, x] }
      when String then Siem::U16.units(v).each_with_index.map { |u, i| [i.to_s, Siem::U16.from_units([u])] }
      when nil then raise TypeError, 'Cannot convert undefined or null to object'
      else
        raise TypeError, 'Cannot convert undefined or null to object' if v.equal?(UNDEF)

        []
      end
    end

    def u16key(s) = Siem::U16.units(s)

    # ---- the oauth_scope caveat ---------------------------------------------------------------------------------------------
    # An oauth_scope caveat granting scopes on provider; duplicate scopes are collapsed.
    def oauth_scope_caveat(provider, scopes) = { 'type' => OAUTH_SCOPE_CAVEAT, 'provider' => provider, 'scopes' => scopes.to_a.uniq }

    def oauth_scope_caveat?(cv)
      return false unless cv.is_a?(Hash) && cv.key?('type') && cv.key?('provider') && cv.key?('scopes')

      sc = cv['scopes']
      cv['type'] == OAUTH_SCOPE_CAVEAT && cv['provider'].is_a?(String) && sc.is_a?(Array) && sc.all?(String)
    end

    # The INTERSECTION of every oauth_scope caveat naming provider in the chain's leaf, or nil when the chain grants nothing for it
    # (so the vault can tell "not covered" from "covered but too narrow"). Run the chain verifier first.
    def granted_oauth_scopes(chain, provider)
      return nil unless chain.is_a?(Array) && !chain.empty?

      leaf = chain[-1]
      raise TypeError, 'Cannot read properties of null' if leaf.nil?
      return nil unless leaf.is_a?(Hash) && leaf['caveats'].is_a?(Array)

      effective = nil
      leaf['caveats'].each do |cv|
        next if !oauth_scope_caveat?(cv) || cv['provider'] != provider

        here = cv['scopes'].uniq
        effective = effective.nil? ? here : effective.select { |s| here.include?(s) }
      end
      effective
    end

    # ---- errors ---------------------------------------------------------------------------------------------------------------
    # Base class of every typed refusal of the vault; branch on #code.
    class VaultError < StandardError
      attr_reader :code

      def initialize(code, message)
        super(message)
        @code = code
      end
    end

    class NotAuthorizedError < VaultError
      attr_reader :checks

      def initialize(message, checks = nil)
        super('not_authorized', message)
        @checks = checks
      end
    end

    class ScopeExceededError < VaultError
      attr_reader :provider, :requested, :granted, :missing

      def initialize(provider, requested, granted, missing)
        super('scope_exceeded', "requested scopes exceed the capability's grant for '#{provider}': not granted [#{missing.join(', ')}]")
        @provider = provider
        @requested = requested.to_a
        @granted = granted.to_a
        @missing = missing.to_a
      end
    end

    class ExpiredNoRefreshError < VaultError
      attr_reader :provider, :connection_id

      def initialize(provider, connection_id)
        super('expired_no_refresh', "connection '#{provider}/#{connection_id}' token is expired and has no refresh token")
        @provider = provider
        @connection_id = connection_id
      end
    end

    class RefreshFailedError < VaultError
      attr_reader :provider, :status

      def initialize(provider, detail, status = nil)
        super('refresh_failed', "refresh for '#{provider}' failed: #{detail}")
        @provider = provider
        @status = status
      end
    end

    class UnknownConnectionError < VaultError
      attr_reader :agent_id, :provider, :connection_id

      def initialize(agent_id, provider, connection_id)
        super('unknown_connection', "no connection for agent '#{agent_id}' provider '#{provider}' id '#{connection_id}'")
        @agent_id = agent_id
        @provider = provider
        @connection_id = connection_id
      end
    end

    class StoreError < VaultError
      def initialize(message = 'the connection store failed') = super('store_error', message)
    end

    class UnknownActionError < VaultError
      def initialize(verb) = super('unknown_action', "no pinned action definition for verb '#{verb}': refusing to release a credential")
    end

    class UnconfirmedActionError < VaultError
      def initialize(verb) = super('unconfirmed_action', "the definition of '#{verb}' has no valid signed confirmation: refusing to release a credential")
    end

    class RequestMismatchError < VaultError
      def initialize(message) = super('request_mismatch', message)
    end

    class BearerReleaseDisabledError < VaultError
      def initialize
        super('bearer_release_disabled', 'this vault does not release bearer tokens to callers; use proxyCall(), or construct it with ' \
                                         'insecureBearerRelease: true (insecure: the caller can use the token for anything inside its scopes until it expires)')
      end
    end

    class ProxyFailedError < VaultError
      def initialize(message) = super('proxy_failed', message)
    end

    # ---- stored connections -------------------------------------------------------------------------------------------------
    def clone_connection(c)
      a = c.fetch('authority')
      auth = { 'provider' => a.fetch('provider'), 'principal' => a.fetch('principal'), 'scopes' => a.fetch('scopes').dup }
      auth['audience'] = a['audience'] if a.key?('audience')
      out = { 'agentId' => c.fetch('agentId'), 'provider' => c.fetch('provider'), 'connectionId' => c.fetch('connectionId'),
              'accessToken' => c.fetch('accessToken'), 'expiresAt' => c.fetch('expiresAt'), 'scopes' => c.fetch('scopes').dup, 'authority' => auth,
              'createdAt' => c.fetch('createdAt'), 'useCount' => c.fetch('useCount') }
      out['refreshToken'] = c['refreshToken'] if c.key?('refreshToken')
      out['lastUsedAt'] = c['lastUsedAt'] if c.key?('lastUsedAt')
      out
    end

    def key_string(key) = "#{key['agentId']}\u0000#{key['provider']}\u0000#{key['connectionId']}"

    # Process-local connection store; records are cloned in and out so callers cannot mutate vault state.
    class InMemoryConnectionStore
      def initialize = @map = {}

      def get(key)
        found = @map[Connect.key_string(key)]
        found.nil? ? nil : Connect.clone_connection(found)
      end

      def set(connection) = @map[Connect.key_string(connection)] = Connect.clone_connection(connection)
      def delete(key) = @map.delete(Connect.key_string(key))
    end

    # ---- the proxy-mode request extractor -----------------------------------------------------------------------------------
    SPECIAL_PORTS = { 'ftp' => 21, 'http' => 80, 'https' => 443, 'ws' => 80, 'wss' => 443 }.freeze
    PLACEHOLDER = /\{([A-Za-z0-9_]+)\}/
    class UrlError < ArgumentError; end

    # The part of the WHATWG URL parse the extractor reads, for special schemes (http, https, ftp, ws, wss).
    class Url
      attr_reader :scheme, :username, :password, :port, :host, :hash, :search, :pathname, :origin

      def self.pct_encode(s, extra)
        s.b.bytes.map { |b| b < 0x21 || b > 0x7E || extra.include?(b.chr) ? format('%%%02X', b) : b.chr }.join
      end

      def initialize(text)
        raise UrlError, 'Invalid URL' unless text.is_a?(String)

        # a lone surrogate becomes U+FFFD (USVString conversion), then the leading / trailing C0 controls and spaces go
        s = text.b.gsub(/\xED[\xA0-\xBF][\x80-\xBF]/n, "\xEF\xBF\xBD".b)
        s = s.sub(/\A[\x00-\x20]+/n, '').sub(/[\x00-\x20]+\z/n, '').delete("\t\n\r")
        m = s.match(/\A([A-Za-z][A-Za-z0-9+.\-]*):/n)
        raise UrlError, 'Invalid URL' if m.nil? || !SPECIAL_PORTS.key?(m[1].downcase)

        @scheme = m[1].downcase
        rest = m.post_match.sub(%r{\A[/\\]+}n, '')
        cut = rest.index(%r{[/\\?#]}n) || rest.length
        auth = rest[0, cut]
        rest = rest[cut..]
        @username = @password = ''
        if auth.include?('@')
          userinfo, _at, auth = auth.rpartition('@')
          @username, _colon, @password = userinfo.partition(':')
        end
        host = auth
        port = ''
        if auth.start_with?('[')
          i = auth.index(']')
          raise UrlError, 'Invalid URL' if i.nil? || (auth[(i + 1)..] != '' && !auth[(i + 1)..].start_with?(':'))

          host = auth[0..i]
          port = auth[(i + 2)..] || ''
        elsif auth.include?(':')
          host, _colon, port = auth.partition(':')
        end
        @host = self.class.parse_host(host)
        if port != ''
          raise UrlError, 'Invalid URL' unless port.match?(/\A[0-9]+\z/n) && port.to_i <= 65_535

          @port = port.to_i == SPECIAL_PORTS[@scheme] ? '' : port.to_i.to_s
        else
          @port = ''
        end
        frag = nil
        frag = rest.split('#', 2)[1] if rest.include?('#')
        rest = rest.split('#', 2)[0] if rest.include?('#')
        query = nil
        if rest.include?('?')
          rest, query = rest.split('?', 2)
        end
        @hash = frag.nil? || frag.empty? ? '' : "##{self.class.pct_encode(frag, '"<>`')}"
        @query = query.nil? ? '' : self.class.pct_encode(query, "\"#<>'")
        @search = @query.empty? ? '' : "?#{@query}"
        segs = rest.empty? ? [''] : rest[1..].split(%r{[/\\]}n, -1)
        segs = [''] if segs.empty?
        out = []
        segs.each_with_index do |seg, i|
          low = seg.downcase
          last = i == segs.length - 1
          if ['..', '.%2e', '%2e.', '%2e%2e'].include?(low)
            out.pop
            out << '' if last
          elsif ['.', '%2e'].include?(low)
            out << '' if last
          else
            out << self.class.pct_encode(seg, "\"#<>?`{}")
          end
        end
        @pathname = "/#{out.join('/')}".force_encoding(Encoding::UTF_8)
        @origin = "#{@scheme}://#{@host}#{@port.empty? ? '' : ":#{@port}"}"
      end

      # shortcut: UTS 46 is approximated by NFKC + lowercase before Punycode (RFC 3492); upgrade if an exotic IDN mapping must match.
      def self.parse_host(h)
        raise UrlError, 'Invalid URL' if h.empty?

        r = WhatwgUrl.parse_host(h, true)
        r = WhatwgUrl.parse_host(idna_ascii(h), true) if r.nil? && !h.start_with?('[')
        raise UrlError, 'Invalid URL' if r.nil? || r.empty?

        r.dup.force_encoding(Encoding::UTF_8)
      end

      def self.idna_ascii(h)
        d = WhatwgUrl.pct_decode(h).force_encoding(Encoding::UTF_8)
        return h unless d.valid_encoding? && !d.ascii_only?

        d.unicode_normalize(:nfkc).downcase.split('.', -1).map { |l| l.ascii_only? ? l : "xn--#{punycode(l)}" }.join('.')
      end

      def self.punycode(label)
        cps = label.codepoints
        out = cps.select { |c| c < 128 }.pack('U*')
        b = h = out.length
        out += '-' if b.positive?
        n = 128
        delta = 0
        bias = 72
        digit = ->(d) { d < 26 ? (97 + d).chr : (22 + d).chr }
        while h < cps.length
          m = cps.select { |c| c >= n }.min
          delta += (m - n) * (h + 1)
          n = m
          cps.each do |c|
            if c < n
              delta += 1
            elsif c == n
              q = delta
              k = 36
              loop do
                t = k <= bias ? 1 : (k >= bias + 26 ? 26 : k - bias)
                break if q < t

                out += digit.call(t + ((q - t) % (36 - t)))
                q = (q - t) / (36 - t)
                k += 36
              end
              out += digit.call(q)
              dl = h == b ? delta / 700 : delta / 2
              dl += dl / (h + 1)
              kk = 0
              while dl > 455
                dl /= 35
                kk += 36
              end
              bias = kk + ((36 * dl) / (dl + 38))
              delta = 0
              h += 1
            end
          end
          delta += 1
          n += 1
        end
        out
      end

      def search_params = Connect.form_pairs(@query)
    end

    def pct_decode_str(s)
      s.b.gsub(/%([0-9A-Fa-f]{2})/n) { Regexp.last_match(1).to_i(16).chr }.force_encoding(Encoding::UTF_8).scrub("�")
    end

    # application/x-www-form-urlencoded parse (URLSearchParams): '+' is a space, bad percent escapes stay literal.
    def form_pairs(s)
      # USVString: a lone surrogate reads as U+FFFD
      s.to_s.b.gsub(/\xED[\xA0-\xBF][\x80-\xBF]/n, "\xEF\xBF\xBD".b).split('&').reject(&:empty?).map do |seq|
        k, _eq, v = seq.partition('=')
        [pct_decode_str(k.tr('+', ' ')), pct_decode_str(v.tr('+', ' '))]
      end
    end

    # decodeURIComponent; raises on a malformed escape or invalid UTF-8
    def decode_uri_component(s)
      raise ArgumentError, 'URI malformed' if s.b.match?(/%(?![0-9A-Fa-f]{2})/n)

      out = s.b.gsub(/%([0-9A-Fa-f]{2})/n) { Regexp.last_match(1).to_i(16).chr }.force_encoding(Encoding::UTF_8)
      raise ArgumentError, 'URI malformed' unless out.valid_encoding?

      out
    end

    def mismatch(m) = raise(RequestMismatchError, "outbound request refused: #{m}")

    # The extractor of one operation: maps an outbound request back to the action's parameters and refuses anything the pinned spec
    # does not carry (an extra query key, body member, header or redirect target). Raises TypeError on a malformed spec.
    def http_extractor(spec)
      spec_url = spec['url']
      begin
        u = Url.new(spec_url.gsub(PLACEHOLDER, 'x'))
      rescue UrlError
        raise TypeError, 'Invalid URL'
      end
      raise TypeError, 'httpExtractor: url must be https without query, fragment or userinfo' if u.scheme != 'https' || u.search != '' || u.hash != '' || u.username != '' || u.password != ''
      raise TypeError, 'httpExtractor: method must be upper case' if spec['method'] != spec['method'].upcase

      names = []
      origin = u.origin
      template = spec_url[origin.length..] || ''
      pat = []
      template.split(PLACEHOLDER, -1).each_with_index do |part, i|
        if i.odd?
          names << part
          pat << '([A-Za-z0-9._~%-]+)'
        else
          pat << Regexp.escape(part)
        end
      end
      rx = Regexp.new("\\A(?:#{pat.join})\\z")
      allowed_query = spec['query'].then { |q| Js.truthy?(q) ? q : [] }
      body_kind = spec['body']
      ctype = body_kind == 'json' ? 'application/json' : body_kind == 'form' ? 'application/x-www-form-urlencoded' : nil

      lambda do |req|
        mismatch("method #{Predicates.js_string(g(req, 'method'))} is not #{spec['method']}") if g(req, 'method') != spec['method']
        begin
          r = Url.new(g(req, 'url').equal?(UNDEF) ? nil : g(req, 'url'))
        rescue UrlError
          mismatch('the url does not parse')
        end
        mismatch('the url is not on the pinned origin') if r.origin != origin || r.username != '' || r.password != '' || r.hash != ''
        m = rx.match(r.pathname)
        mismatch('the path does not match the pinned template') if m.nil?
        params = {}
        put = lambda do |k, v|
          mismatch("parameter '#{k}' is carried twice") if params.key?(k)
          params[k] = v
        end
        names.each_with_index do |n, i|
          v = begin
            decode_uri_component(m[i + 1])
          rescue ArgumentError
            mismatch('a path segment is not valid percent-encoding')
          end
          put.call(n, v)
        end
        seen = {}
        r.search_params.each do |k, v|
          mismatch("query key '#{k}' is not allowed") unless allowed_query.include?(k)
          mismatch("query key '#{k}' is repeated") if seen.key?(k)
          seen[k] = true
          put.call(k, v)
        end
        hdrs = g(req, 'headers')
        ct = UNDEF
        (hdrs.equal?(UNDEF) || hdrs.nil? ? [] : entries(hdrs)).each do |h, v|
          if Siem::U16.to_pua(h).downcase == 'content-type'
            ct = v
            break
          end
        end
        body = g(req, 'body')
        if body_kind.nil?
          mismatch('this operation carries no body') if !body.equal?(UNDEF) && body != ''
        else
          mismatch('the body is missing') if !body.is_a?(String) || body.empty?
          mismatch("content-type must be #{ctype}") if ct.equal?(UNDEF) || Js.trim(Siem::U16.to_pua(ct).split(';')[0].to_s).downcase != ctype
          fixed = (spec['fixed'].then { |f| Js.truthy?(f) ? f : {} }).dup
          if body_kind == 'json'
            b = begin
              AtlasPca.parse_json(body, any_top: true)
            rescue StandardError
              mismatch('the body is not strict JSON')
            end
            mismatch('the body must be a JSON object') unless b.is_a?(Hash)
            b.each do |k, v|
              if fixed.key?(k)
                mismatch("fixed member '#{k}' has another value") if AtlasPca.hash_canonical(v) != AtlasPca.hash_canonical(fixed[k])
                fixed.delete(k)
              else
                put.call(k, v)
              end
            end
          else
            keys = {}
            form_pairs(body.start_with?('?') ? body[1..] : body).each do |k, v|
              mismatch("form key '#{k}' is repeated") if keys.key?(k)
              keys[k] = true
              if fixed.key?(k)
                mismatch("fixed member '#{k}' has another value") if v != fixed[k]
                fixed.delete(k)
              else
                put.call(k, v)
              end
            end
          end
          mismatch("fixed member(s) #{fixed.keys.join(', ')} missing") unless fixed.empty?
        end
        params
      end
    end

    DEFAULT_PROXY_HEADERS = %w[content-type accept idempotency-key].freeze

    # The request headers the agent may set (the vault sets Authorization itself); anything else is refused.
    def check_proxy_headers(headers, allow)
      out = {}
      (headers.nil? ? [] : entries(headers)).each do |k, v|
        n = Siem::U16.to_pua(k).downcase
        mismatch("header '#{k}' is not allowed") unless allow.include?(n)
        mismatch("header '#{k}' is repeated") if out.key?(n)
        mismatch("header '#{k}' has an invalid value") if !v.is_a?(String) || v.b.match?(/[\r\n\x00]/n)
        out[n] = v
      end
      out
    end

    # ---- release receipts ---------------------------------------------------------------------------------------------------
    RELEASE_RECEIPT_DOMAIN = "atlas-pca/connect-release-receipt/v1\0"

    def outbound_request_digest(method, url, headers, body)
      AtlasPca.hash_canonical({ 'd' => 'atlas-pca/connect-request/v1', 'method' => method, 'url' => url, 'headers' => headers, 'body' => body })
    end

    # The receipt body plus an Ed25519 signature of the vault key (a 32-byte seed) over domain || canonical(body).
    def sign_release_receipt(body, secret_key) = AtlasPca.sign_artifact(RELEASE_RECEIPT_DOMAIN, body, KeyPair.new(secret_key))

    # true iff the receipt is signed by the pinned vault key
    def verify_release_receipt(receipt, vault_pk) = AtlasPca.wb_verify_artifact_sig(RELEASE_RECEIPT_DOMAIN, receipt, vault_pk)

    def receipt_action_digest(pcactn) = AtlasPca.escalation_action_digest(pcactn)

    # ---- token refresh ------------------------------------------------------------------------------------------------------
    def form_encode(params) = params.map { |k, v| "#{Js.encode_uri_component(k)}=#{Js.encode_uri_component(v)}" }.join('&')

    def redact(text, secrets)
      secrets.each { |s| text = text.gsub(s, '[redacted]') if s.is_a?(String) && !s.empty? }
      text
    end

    def parse_token_response(body, provider)
      raise RefreshFailedError.new(provider, 'token endpoint returned a non-object body') unless body.is_a?(Hash)

      at = body['access_token']
      raise RefreshFailedError.new(provider, 'token endpoint response has no access_token') if !at.is_a?(String) || at.empty?

      out = { 'accessToken' => at }
      ex = body['expires_in']
      out['expiresInSecs'] = ex if finite?(ex) && ex > 0
      rt = body['refresh_token']
      out['refreshToken'] = rt if rt.is_a?(String) && !rt.empty?
      scope = body['scope']
      if scope.is_a?(String) && !Js.trim(Siem::U16.to_pua(scope)).empty?
        out['scopes'] = Js.trim(Siem::U16.to_pua(scope)).split(/[#{Js::WS}]+/o).map { |x| Siem::U16.from_pua(x) }
      end
      out
    end

    # Epoch-ms expiry claimed by a JWT access token; nil for an opaque (non-JWT) token.
    def jwt_expiry_ms(token)
      parts = token.split('.', -1)
      return nil unless parts.length == 3

      b64 = parts[1].gsub(/[\t\n\f\r ]/, '').tr('-_', '+/')
      b64 = b64.sub(/={1,2}\z/, '') if (b64.length % 4).zero?
      return nil unless b64.match?(%r{\A[A-Za-z0-9+/]*\z}) && (b64.length % 4) != 1

      claims = Js.parse(Base64.decode64(b64 + ('=' * (-b64.length % 4))).force_encoding(Encoding::UTF_8).scrub("�"))
      exp = claims.is_a?(Hash) ? claims['exp'] : nil
      finite?(exp) ? exp * 1000 : nil
    rescue StandardError
      nil
    end

    # Refresh connection's access token at its provider's token endpoint. Returns the fields to apply to the connection (accessToken,
    # refreshToken, expiresAt, scopes); raises RefreshFailedError on any transport or parse failure. No secret reaches an error.
    def refresh_connection(connection, config, refresh_token, requested, fetch, now, default_token_lifetime_ms)
      provider = connection['provider']
      cfg = config || {}
      secrets = [refresh_token, connection['accessToken'], cfg['clientSecret'], *(cfg['extraParams'] || {}).values]
      raise RefreshFailedError.new(provider, 'no provider token-endpoint config') if config.nil?
      raise RefreshFailedError.new(provider, 'no fetch transport configured') if fetch.nil?

      params = { 'grant_type' => 'refresh_token', 'refresh_token' => refresh_token, 'client_id' => config.fetch('clientId') }
      params['client_secret'] = config['clientSecret'] if config.key?('clientSecret')
      params.update(config['extraParams'] || {})
      narrowing = config['supportsScopeNarrowing'] == true
      params['scope'] = requested.join(' ') if narrowing && !requested.empty?
      res = begin
        fetch.call(config['tokenEndpoint'], { 'method' => 'POST', 'headers' => { 'content-type' => 'application/x-www-form-urlencoded', 'accept' => 'application/json' },
                                              'body' => form_encode(params) })
      rescue StandardError => e
        raise RefreshFailedError.new(provider, "transport error: #{redact(e.message, secrets)}")
      end
      unless res.ok
        detail = begin
          redact(Siem::U16.slice(res.text, 256), secrets)
        rescue StandardError
          '<unreadable body>'
        end
        raise RefreshFailedError.new(provider, "token endpoint #{res.status}: #{detail}", res.status)
      end
      j = begin
        res.json
      rescue StandardError
        raise RefreshFailedError.new(provider, 'unparseable JSON body')
      end
      parsed = parse_token_response(j, provider)
      expires_at = if parsed.key?('expiresInSecs')
                     now + (parsed['expiresInSecs'] * 1000)
                   else
                     jwt_expiry_ms(parsed['accessToken']) || (now + default_token_lifetime_ms)
                   end
      scopes = if parsed.key?('scopes') then parsed['scopes']
               elsif narrowing && !requested.empty? then requested.dup
               else connection['scopes'].dup
               end
      { 'accessToken' => parsed['accessToken'], 'expiresAt' => expires_at, 'scopes' => scopes, 'refreshToken' => parsed.fetch('refreshToken', refresh_token) }
    end

    # ---- envelope encryption of stored tokens -------------------------------------------------------------------------------
    ENVELOPE_PREFIX = 'pca1'

    def seal(key, aad, plain, iv = nil)
      iv ||= SecureRandom.random_bytes(12)
      c = OpenSSL::Cipher.new('aes-256-gcm').encrypt
      c.key = key
      c.iv = iv
      c.auth_data = aad
      ct = (plain.empty? ? '' : c.update(plain)) + c.final
      iv + ct + c.auth_tag(16) # ciphertext || 16-byte tag, as the reference lays it out
    end

    def open_sealed(key, aad, sealed)
      raise ArgumentError, 'short ciphertext' if sealed.bytesize < 12 + 16

      c = OpenSSL::Cipher.new('aes-256-gcm').decrypt
      c.key = key
      c.iv = sealed.byteslice(0, 12)
      c.auth_tag = sealed.byteslice(-16, 16)
      c.auth_data = aad
      ct = sealed.byteslice(12, sealed.bytesize - 28)
      (ct.empty? ? '' : c.update(ct)) + c.final
    end

    def unb64u_strict_chars(s)
      raise ArgumentError, 'bad encoding' unless s.match?(/\A[A-Za-z0-9_-]*\z/)
      raise ArgumentError, 'bad encoding' if (s.length % 4) == 1

      Base64.urlsafe_decode64(s + ('=' * (-s.length % 4)))
    end

    # A key ring held in process memory (production keys belong behind a KMS implementing wrap and unwrap).
    class LocalKeyWrapper
      def initialize(keys, active_id)
        @keys = {}
        keys.each { |i, k| add_key(i, k) }
        raise ArgumentError, 'LocalKeyWrapper: the active key id is not in the key ring' unless @keys.key?(active_id)

        @active = active_id
      end

      def add_key(key_id, key)
        raise ArgumentError, 'LocalKeyWrapper: key id must not be empty' if key_id.empty?
        raise ArgumentError, 'LocalKeyWrapper: keys must be 32 bytes' unless key.is_a?(String) && key.bytesize == 32

        @keys[key_id] = key.b.dup
      end

      def set_active(key_id)
        raise ArgumentError, 'LocalKeyWrapper: the active key id is not in the key ring' unless @keys.key?(key_id)

        @active = key_id
      end

      def remove_key(key_id)
        raise ArgumentError, 'LocalKeyWrapper: cannot remove the active key' if key_id == @active

        @keys.delete(key_id)
      end

      def destroy
        @keys.each_value { |k| k.replace("\0".b * k.bytesize) }
        @keys.clear
      end

      def wrap(dek, aad)
        k = @keys[@active]
        raise ArgumentError, 'no active key' if k.nil?

        { 'keyId' => @active, 'wrapped' => Connect.seal(k, aad, dek) }
      end

      def unwrap(key_id, wrapped, aad)
        k = @keys[key_id]
        raise ArgumentError, 'unknown key id' if k.nil?

        Connect.open_sealed(k, aad, wrapped)
      end
    end

    def aad_for(key, field)
      ['pca-connect/v1', field, key['agentId'], key['provider'], key['connectionId']].map { |p| AtlasPca::Js.utf8("#{AtlasPca::Js.utf8(p).bytesize}:#{p}") }.join('|'.b)
    end

    def encrypt_field(wrapper, key, field, plain)
      aad = aad_for(key, field)
      dek = SecureRandom.random_bytes(32)
      wr = wrapper.wrap(dek, aad)
      sealed = seal(dek, aad, plain.b)
      [ENVELOPE_PREFIX, AtlasPca.b64e(wr['keyId'].b), AtlasPca.b64e(wr['wrapped']), AtlasPca.b64e(sealed)].join('.')
    end

    def decrypt_field(wrapper, key, field, value)
      parts = value.split('.', -1)
      raise ArgumentError, 'not an envelope' if parts.length != 4 || parts[0] != ENVELOPE_PREFIX

      aad = aad_for(key, field)
      key_id = unb64u_strict_chars(parts[1]).force_encoding(Encoding::UTF_8)
      raise ArgumentError, 'bad key id' unless key_id.valid_encoding?

      dek = wrapper.unwrap(key_id, unb64u_strict_chars(parts[2]), aad)
      plain = open_sealed(dek, aad, unb64u_strict_chars(parts[3])).force_encoding(Encoding::UTF_8)
      raise ArgumentError, 'bad plaintext' unless plain.valid_encoding?

      plain
    end

    # Wraps a connection store so accessToken and refreshToken are encrypted before they reach it. Fails closed: a stored token that
    # is not an envelope, fails authentication or was sealed under an unknown key makes #get raise a StoreError (no detail).
    class EncryptedConnectionStore
      def initialize(inner, wrapper)
        @inner = inner
        @wrapper = wrapper
      end

      def encrypted = true

      def get(key)
        raw = @inner.get(key)
        return nil if raw.nil?

        begin
          out = Connect.clone_connection(raw)
          k = { 'agentId' => raw['agentId'], 'provider' => raw['provider'], 'connectionId' => raw['connectionId'] }
          raise ArgumentError, 'record key mismatch' if k['agentId'] != key['agentId'] || k['provider'] != key['provider'] || k['connectionId'] != key['connectionId']

          out['accessToken'] = Connect.decrypt_field(@wrapper, k, 'access', raw['accessToken'])
          out['refreshToken'] = Connect.decrypt_field(@wrapper, k, 'refresh', raw['refreshToken']) if raw.key?('refreshToken')
          out
        rescue StandardError
          raise StoreError.new('a stored token could not be decrypted')
        end
      end

      def set(connection)
        k = { 'agentId' => connection['agentId'], 'provider' => connection['provider'], 'connectionId' => connection['connectionId'] }
        sealed = Connect.clone_connection(connection)
        begin
          sealed['accessToken'] = Connect.encrypt_field(@wrapper, k, 'access', connection['accessToken'])
          sealed['refreshToken'] = Connect.encrypt_field(@wrapper, k, 'refresh', connection['refreshToken']) if connection.key?('refreshToken')
        rescue StandardError
          raise StoreError.new('a token could not be encrypted; nothing was stored')
        end
        @inner.set(sealed)
      end

      def delete(key) = @inner.delete(key)

      # Re-encrypt one record under the wrapper's active key (run after rotating the key ring).
      def reencrypt(key)
        c = get(key)
        return false if c.nil?

        set(c)
        true
      end
    end

    # ---- the vault ----------------------------------------------------------------------------------------------------------
    DEFAULT = Object.new.freeze

    # Holds an agent's third-party OAuth tokens and releases a fresh access token only for a verified PCActn. Options mirror the
    # reference's (snake_case keywords); actions.call(verb) returns a Hash {'verb', 'def_digest', 'confirmed',
    # 'upstream' => {'provider', 'scopes_min'}, 'extract' => callable?} or nil; receipts is {'secret_key' => 32-byte seed,
    # 'sink' => callable?}; replay is the one-time-use store.
    class TokenVault
      def initialize(store: nil, providers: nil, fetch: nil, now: nil, audience: nil, pq_pins: nil, authorized_plan_roots: nil,
                     insecure_skip_plan_root_check: false, expiry_leeway_ms: nil, default_connection_id: nil, require_action_binding: nil,
                     resource_for: nil, use_verb: DEFAULT, default_token_lifetime_ms: nil, replay: nil, is_revoked: nil, strict: nil,
                     actions: nil, insecure_bearer_release: false, proxy_fetch: nil, proxy_headers: nil, max_proxy_response_bytes: nil,
                     receipts: nil)
        if strict != false
          missing = []
          missing << 'an encrypting store' unless store.respond_to?(:encrypted) && store.encrypted == true
          missing << 'replay' if replay.nil?
          missing << 'isRevoked' if is_revoked.nil?
          missing << 'audience' if !audience.is_a?(String) || audience.empty?
          raise ArgumentError, "TokenVault strict mode requires #{missing.join(', ')}" unless missing.empty?
        elsif store.nil?
          raise ArgumentError, 'TokenVault requires a store'
        end
        @actions = actions
        @bearer = insecure_bearer_release == true
        @proxy_fetch = proxy_fetch
        @proxy_headers = (proxy_headers.nil? ? DEFAULT_PROXY_HEADERS : proxy_headers).map(&:downcase)
        @max_proxy = max_proxy_response_bytes.nil? ? 4 * 1024 * 1024 : max_proxy_response_bytes
        @receipts = receipts
        @replay = replay
        @is_revoked = is_revoked
        @store = store
        @providers = providers || {}
        @fetch = fetch
        @now = now || -> { (Time.now.to_f * 1000).to_i }
        @audience = audience
        @pq_pins = pq_pins
        @plan_roots = authorized_plan_roots
        @skip_plan_root = insecure_skip_plan_root_check == true
        @leeway = expiry_leeway_ms.nil? ? 30_000 : expiry_leeway_ms
        @default_cid = default_connection_id.nil? ? 'default' : default_connection_id
        @require_binding = require_action_binding.nil? ? true : require_action_binding
        @resource_for = resource_for || ->(provider, _cid) { "oauth:#{provider}" }
        @use_verb = use_verb.equal?(DEFAULT) ? 'use_connection' : use_verb
        @default_lifetime = default_token_lifetime_ms.nil? ? 300_000 : default_token_lifetime_ms
      end

      # Store (or replace) an agent's connection; the authority descriptor binds which capability may use it.
      def put_connection(agent_id, provider, access_token, expires_at, scopes, authority, connection_id = nil, refresh_token = nil)
        cid = connection_id.nil? ? @default_cid : connection_id
        [['agentId', agent_id], ['provider', provider], ['connectionId', cid], ['accessToken', access_token],
         ['principal', authority.is_a?(Hash) ? authority['principal'] : nil]].each do |k, val|
          raise TypeError, "putConnection: #{k} must be a non-empty string" if !val.is_a?(String) || val.empty?
        end
        raise TypeError, 'putConnection: expiresAt must be a finite number' unless Connect.finite?(expires_at)
        raise TypeError, 'putConnection: refreshToken must be a non-empty string when given' if !refresh_token.nil? && (!refresh_token.is_a?(String) || refresh_token.empty?)
        raise TypeError, 'putConnection: scopes must be a list of strings' unless scopes.is_a?(Array) && scopes.all?(String)

        auth = { 'provider' => provider, 'principal' => authority['principal'], 'scopes' => (authority['scopes'].nil? ? scopes : authority['scopes']).dup }
        auth['audience'] = authority['audience'] unless authority['audience'].nil?
        conn = { 'agentId' => agent_id, 'provider' => provider, 'connectionId' => cid, 'accessToken' => access_token, 'expiresAt' => expires_at,
                 'scopes' => scopes.dup, 'authority' => auth, 'createdAt' => @now.call, 'useCount' => 0 }
        conn['refreshToken'] = refresh_token unless refresh_token.nil?
        store_set(conn)
        conn
      end

      # A FRESH access token iff pcactn verifies against the connection's bound principal and the chain's grant covers the requested
      # provider and scopes. Disabled unless the vault was built with insecure_bearer_release (prefer #proxy_call).
      def get_connection_token(pcactn, provider, connection_id = nil, scopes = nil)
        raise BearerReleaseDisabledError.new unless @bearer

        a = authorize(pcactn, provider, connection_id, scopes, false, nil)
        token, refreshed = fresh_token(a)
        done = record_use(a, token)
        issue_receipt(pcactn, a, 'bearer', nil, nil, 'released', done['scopes'])
        exp = pcactn['exp']
        { 'provider' => a['provider'], 'connectionId' => a['connectionId'], 'accessToken' => done['accessToken'], 'scopes' => done['scopes'].dup,
          'expiresAt' => !a['action'].nil? && Connect.finite?(exp) ? [done['expiresAt'], exp].min : done['expiresAt'], 'refreshed' => refreshed }
      end

      # Proxy mode: the vault makes the outbound call itself (the agent never holds the credential). The request must re-derive
      # exactly the params the PCActn signed; the action is spent first; redirects are not followed; a receipt links release to effect.
      def proxy_call(pcactn, request, provider, connection_id = nil)
        raise TypeError, 'proxyCall requires the vault to be constructed with `actions`' if @actions.nil?
        raise TypeError, 'proxyCall requires the vault to be constructed with `proxyFetch`' if @proxy_fetch.nil?

        rh = Connect.g(request, 'headers')
        send_headers = Connect.check_proxy_headers(rh.equal?(Connect::UNDEF) ? nil : rh, @proxy_headers)
        a = authorize(pcactn, provider, connection_id, nil, true, request)
        token, _refreshed = fresh_token(a)
        done = record_use(a, token)
        headers = send_headers.dup
        headers['authorization'] = "Bearer #{done['accessToken']}"
        body = request['body']
        req_digest = Connect.outbound_request_digest(request['method'], request['url'], send_headers, body)
        call = { 'method' => request['method'], 'url' => request['url'], 'headers' => headers, 'redirect' => 'manual' }
        call['body'] = body if request.key?('body')
        response = begin
          @proxy_fetch.call(call)
        rescue StandardError
          issue_receipt(pcactn, a, 'proxy', req_digest, nil, 'failed', done['scopes'])
          raise ProxyFailedError.new('the outbound call failed before a response')
        end
        rbody = response.is_a?(Hash) ? response['body'] : nil
        size = rbody.is_a?(String) ? rbody.bytesize : Float::INFINITY
        status = response.is_a?(Hash) ? response['status'] : nil
        receipt = issue_receipt(pcactn, a, 'proxy', req_digest, Js.safe_integer?(status) ? status : nil, 'executed', done['scopes'])
        raise ProxyFailedError.new('the response is larger than maxProxyResponseBytes (the call was made and the action is spent)') unless size.to_f.finite? && size <= @max_proxy

        tok = done['accessToken']
        rb = rbody.gsub(tok, '[redacted]')
        out_headers = {}
        hs = response['headers']
        hs = {} unless Js.truthy?(hs) && !(hs.respond_to?(:empty?) && hs.empty?)
        hs.each_pair { |k, v| out_headers[k] = Predicates.js_string(v).gsub(tok, '[redacted]') unless k.downcase == 'set-cookie' }
        out = { 'response' => { 'status' => status, 'headers' => out_headers, 'body' => rb } }
        out['receipt'] = receipt if receipt
        out
      end

      def delete_connection(agent_id, provider, connection_id = nil)
        @store.delete({ 'agentId' => agent_id, 'provider' => provider, 'connectionId' => connection_id.nil? ? @default_cid : connection_id })
      rescue VaultError
        raise
      rescue StandardError # the store's own error text can quote a record
        raise StoreError.new
      end

      private

      def authorize(pcactn, provider, connection_id, scopes, need_action, request)
        raise TypeError, 'not a PCActn' unless pcactn.is_a?(Hash)

        cid = connection_id.nil? ? @default_cid : connection_id
        chain = pcactn['cap_chain']
        raise NotAuthorizedError.new('PCActn has no capability chain') if !chain.is_a?(Array) || chain.empty?

        leaf = chain[-1]
        root = chain[0]
        raise NotAuthorizedError.new('PCActn capability chain is malformed') if leaf.nil? || root.nil?

        agent_id = Connect.sub(leaf, 'holder')
        connection = store_get({ 'agentId' => agent_id, 'provider' => provider, 'connectionId' => cid })
        raise UnknownConnectionError.new(agent_id, provider, cid) if connection.nil?
        raise NotAuthorizedError.new("capability chain is not rooted at the connection's bound principal") if Connect.sub(root, 'issuer') != connection['authority']['principal']

        now = @now.call
        audience = connection['authority'].key?('audience') ? connection['authority']['audience'] : @audience
        # audience nil accepts any audience: the verifier has no opt-out, so it is given the action's own signed aud
        v = AtlasPca.verify_pcactn(pcactn, root, now: now, audience: audience.nil? ? pcactn['aud'] : audience, authorized_plan_roots: @plan_roots,
                                                 insecure_skip_plan_root_check: @skip_plan_root, pq_pins: @pq_pins)
        raise NotAuthorizedError.new("PCActn verification failed: #{v.reason.nil? || v.reason.empty? ? 'rejected' : v.reason}", v.checks) unless v.allow

        unless @is_revoked.nil?
          revoked = begin
            !@is_revoked.call(pcactn).equal?(false)
          rescue StandardError
            raise NotAuthorizedError.new('revocation source unavailable')
          end
          raise NotAuthorizedError.new('the capability chain is revoked') if revoked
        end
        action = nil
        act = pcactn.fetch('action')
        if !@actions.nil?
          verb = Connect.sub(act, 'verb')
          action = @actions.call(verb)
          raise UnknownActionError.new(Predicates.js_string(verb)) if action.nil? || action['verb'] != verb
          raise UnconfirmedActionError.new(verb) unless action['confirmed'] == true
          raise NotAuthorizedError.new("the action '#{verb}' is not for provider '#{provider}'") if action['upstream']['provider'] != provider

          smin = action['upstream']['scopes_min']
          raise NotAuthorizedError.new("the action '#{verb}' declares no upstream scopes (nothing to release)") if !smin.is_a?(Array) || smin.empty?
        elsif need_action
          raise UnknownActionError.new(Predicates.js_string(act['verb']))
        elsif @require_binding
          expected = @resource_for.call(provider, cid)
          raise NotAuthorizedError.new("PCActn action resource '#{Predicates.js_string(Connect.g(act, 'resource'))}' is not for this connection (expected '#{expected}')") if act['resource'] != expected
          if !@use_verb.nil? && act['verb'] != @use_verb
            raise NotAuthorizedError.new("PCActn action verb '#{Predicates.js_string(Connect.g(act, 'verb'))}' is not a connection-use verb (expected '#{@use_verb}')")
          end
        end
        granted = Connect.granted_oauth_scopes(chain, provider)
        raise NotAuthorizedError.new("capability grants no authority for provider '#{provider}'") if granted.nil?

        if !action.nil?
          mn = action['upstream']['scopes_min'].dup
          requested = scopes.nil? ? mn : scopes
          beyond = requested.reject { |s| mn.include?(s) }
          raise ScopeExceededError.new(provider, requested, mn, beyond) unless beyond.empty?

          unheld = mn.reject { |s| connection['scopes'].include?(s) && connection['authority']['scopes'].include?(s) }
          raise ScopeExceededError.new(provider, mn, connection['scopes'], unheld) unless unheld.empty?

          unless need_action
            extra = connection['scopes'].reject { |s| mn.include?(s) }
            raise ScopeExceededError.new(provider, mn, connection['scopes'], extra) unless extra.empty?
          end
          ungranted = mn.reject { |s| granted.include?(s) }
          raise ScopeExceededError.new(provider, mn, granted, ungranted) unless ungranted.empty?
        else
          requested = scopes.nil? ? connection['authority']['scopes'] : scopes
        end
        missing = requested.reject { |s| granted.include?(s) }
        raise ScopeExceededError.new(provider, requested, granted, missing) unless missing.empty?

        if need_action && !action.nil?
          raise RequestMismatchError.new('the action has no request extractor: proxy mode cannot bind the outbound request') if request.nil? || action['extract'].nil?

          params = begin
            action['extract'].call(request)
          rescue StandardError => e
            raise e if e.is_a?(RequestMismatchError)

            raise RequestMismatchError.new('the outbound request could not be mapped to the action parameters')
          end
          d = begin
            AtlasPca.params_digest(params)
          rescue StandardError
            raise RequestMismatchError.new('the outbound request parameters are not canonical')
          end
          raise RequestMismatchError.new('the outbound request does not carry the parameters the PCActn signed') if d != act['params_digest']
        end
        unless @replay.nil?
          verdict = ConnectReplay.guard_pcactn_replay(@replay, pcactn, pcactn['aud'], now)
          raise NotAuthorizedError.new("replay guard refused the action: #{verdict['reason']}") unless verdict['ok']
        end
        { 'agentId' => agent_id, 'provider' => provider, 'connectionId' => cid, 'connection' => connection, 'requested' => requested.dup, 'now' => now, 'action' => action }
      end

      def fresh_token(a)
        conn = a['connection']
        now = a['now']
        token = conn
        refreshed = false
        if !Connect.finite?(conn['expiresAt']) || !Connect.finite?(now) || !Connect.finite?(@leeway) || conn['expiresAt'] - now <= @leeway
          raise ExpiredNoRefreshError.new(a['provider'], a['connectionId']) unless conn.key?('refreshToken')

          updated = Connect.refresh_connection(conn, @providers[a['provider']], conn['refreshToken'], a['requested'], @fetch, now, @default_lifetime)
          token = conn.merge(updated)
          refreshed = true
        end
        [token, refreshed]
      end

      def record_use(a, token)
        t = token.dup
        t['lastUsedAt'] = a['now']
        t['useCount'] = token['useCount'] + 1
        store_set(t)
        t
      end

      def issue_receipt(pcactn, a, mode, request_digest, http_status, outcome, scopes)
        return nil if @receipts.nil?

        receipt = Connect.sign_release_receipt({ 'v' => 1, 'kind' => 'pca-release-receipt', 'action_digest' => Connect.receipt_action_digest(pcactn), 'provider' => a['provider'],
                                                 'connection_id' => a['connectionId'], 'mode' => mode, 'scopes_released' => scopes.sort_by { |s| Connect.u16key(s) },
                                                 'request_digest' => request_digest, 'http_status' => http_status, 'outcome' => outcome, 'ts' => a['now'] },
                                               @receipts['secret_key'])
        sink = @receipts['sink']
        unless sink.nil?
          begin
            sink.call(receipt)
          rescue StandardError
            nil # a failing sink must not turn a made call into an error the caller retries
          end
        end
        receipt
      end

      def store_get(key)
        @store.get(key)
      rescue VaultError
        raise
      rescue StandardError
        raise StoreError.new
      end

      def store_set(c)
        @store.set(c)
      rescue VaultError
        raise
      rescue StandardError
        raise StoreError.new
      end
    end
  end
end
