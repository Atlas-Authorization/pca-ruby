# frozen_string_literal: true

require 'securerandom'
require 'digest'
require 'base64'
require_relative '../atlas_pca'
require_relative 'js_compat'
require_relative 'predicates'
require_relative 'connect'
require_relative 'connectors_providers'

module AtlasPca
  # A declarative catalog of outbound OAuth connectors for the token vault: manifest validation and digests, the provider registry,
  # the authorize URL with PKCE and URL variables, access-token placement, authorization-code exchange and refresh into the vault,
  # and the manifest-to-vault-provider mapping. Mirrors the TypeScript reference (@atlasauth/pca-connectors); the seeded provider
  # manifests are BUILTIN_MANIFESTS.
  #
  # Manifests and option bags are String-keyed Hashes with the reference's member names. Injected transports are callables
  # (fetch.call(url, init) returning an object with ok, status, json and text); the vault is an AtlasPca::Connect::TokenVault.
  module Connectors
    UNDEF = Predicates::UNDEF
    WS = Js::WS
    WS_OR_COMMA = /[#{WS},]/o
    WS_OR_COMMA_RUN = /[#{WS},]+/o

    class ConnectorError < StandardError; end

    class ManifestValidationError < ConnectorError
      attr_reader :issues

      def initialize(issues)
        super("invalid provider manifest: #{issues.join('; ')}")
        @issues = issues.dup
      end
    end

    class UnknownProviderError < ConnectorError
      attr_reader :provider_id

      def initialize(provider_id)
        super("no connector registered for provider '#{provider_id}'")
        @provider_id = provider_id
      end
    end

    RESERVED_AUTHORIZE_PARAMS = %w[response_type client_id redirect_uri scope state code_challenge code_challenge_method].freeze
    RESERVED_TOKEN_PARAMS = %w[grant_type code redirect_uri client_id client_secret code_verifier refresh_token].freeze
    ID_SOURCE = '^[a-z0-9][a-z0-9._-]*$'
    ID_PATTERN = /\A[a-z0-9][a-z0-9._-]*\z/
    TOKEN_PLACEMENTS = %w[bearer header query].freeze
    REFRESH_MODES = %w[refresh_token none].freeze
    CLIENT_AUTHS = %w[post basic].freeze
    HEADER_NAME = /\A[A-Za-z0-9][A-Za-z0-9-]*\z/
    FORBIDDEN_HEADERS = %w[host content-length content-type transfer-encoding connection cookie set-cookie].freeze
    QUERY_NAME = /\A[A-Za-z_][A-Za-z0-9_.-]*\z/
    VAR = /\{(\w+)\}/

    module_function

    def prop(o, k) = o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF
    def record?(v) = v.is_a?(Hash)
    def non_empty?(v) = v.is_a?(String) && !v.empty?
    def str_array?(v) = v.is_a?(Array) && v.all?(String)
    def str_record?(v) = v.is_a?(Hash) && v.values.all?(String)
    def bool?(v) = v == true || v == false
    def one_of(items) = items.join(' | ')

    # regex tests on a string that may hold a lone surrogate (invalid UTF-8 here): stand-ins keep every ASCII class a non-match
    def pua(s) = Siem::U16.to_pua(s)
    def m?(s, re) = pua(s).match?(re)

    # the keys a JS `for (const k in x)` / Object.keys(x) walk: an object's members or an array's elements
    def keys_of(x) = x.is_a?(Hash) ? x.keys : (x.is_a?(Array) ? x : [])

    def https_url?(v)
      return false unless v.is_a?(String) && v.start_with?('https://')

      v = pua(v)

      begin
        u = Connect::Url.new(v.gsub(VAR, 'x'))
      rescue Connect::UrlError
        return false
      end
      return false if u.scheme != 'https' || u.username != '' || u.password != '' || u.hash != ''

      raw_host = v['https://'.length..].split(%r{[/?#]}, 2)[0].to_s
      !raw_host.match?(/\A\{\w+\}(:[0-9]+)?\z/)
    end

    def url_vars(url) = url.scan(VAR).flatten

    # {'ok' => true, 'manifest'} or {'ok' => false, 'issues'}: every problem of a provider manifest, no partial acceptance.
    def validate_manifest(inp)
      issues = []
      return { 'ok' => false, 'issues' => ['manifest must be an object'] } unless record?(inp)

      mid = prop(inp, 'id')
      if !non_empty?(mid) then issues << 'id must be a non-empty string'
      elsif !m?(mid, ID_PATTERN) then issues << "id '#{mid}' must be lowercase and match #{ID_SOURCE}"
      end
      issues << 'displayName must be a non-empty string' unless non_empty?(prop(inp, 'displayName'))
      authorize_url = prop(inp, 'authorizeUrl')
      issues << 'authorizeUrl must be an https:// URL' unless https_url?(authorize_url)
      token_url = prop(inp, 'tokenUrl')
      issues << 'tokenUrl must be an https:// URL' unless https_url?(token_url)
      scopes_available = prop(inp, 'scopesAvailable')
      issues << 'scopesAvailable must be an array of strings' unless str_array?(scopes_available)
      default_scopes = prop(inp, 'defaultScopes')
      issues << 'defaultScopes must be an array of strings' unless str_array?(default_scopes)
      [['scopesAvailable', scopes_available], ['defaultScopes', default_scopes]].each do |name, lst|
        next unless str_array?(lst)

        if lst.any? { |s| s.empty? || m?(s, WS_OR_COMMA) }
          issues << "#{name} entries must be non-empty and contain no whitespace or comma (a separator inside a scope would smuggle in another scope)"
        end
        issues << "#{name} must not contain duplicates" if lst.uniq.length != lst.length
      end
      if str_array?(scopes_available) && str_array?(default_scopes) && !scopes_available.empty?
        missing = default_scopes.reject { |s| scopes_available.include?(s) }
        issues << "defaultScopes must be a subset of scopesAvailable (unknown: #{missing.join(', ')})" unless missing.empty?
      end
      refresh_ = prop(inp, 'refresh')
      if !record?(refresh_)
        issues << 'refresh must be an object'
      else
        mode = prop(refresh_, 'mode')
        issues << "refresh.mode must be one of #{one_of(REFRESH_MODES)}" if !mode.is_a?(String) || !REFRESH_MODES.include?(mode)
        te = prop(refresh_, 'tokenEndpoint')
        issues << 'refresh.tokenEndpoint, when present, must be an https:// URL' if !te.equal?(UNDEF) && !https_url?(te)
        sn = prop(refresh_, 'supportsScopeNarrowing')
        issues << 'refresh.supportsScopeNarrowing must be a boolean' if !sn.equal?(UNDEF) && !bool?(sn)
        ep = prop(refresh_, 'extraParams')
        if !ep.equal?(UNDEF) && !str_record?(ep)
          issues << 'refresh.extraParams must be a string→string map'
        elsif str_record?(ep)
          ep.each_key { |k| issues << "refresh.extraParams may not set '#{k}': the request builder owns it" if RESERVED_TOKEN_PARAMS.include?(k) }
        end
      end
      placement = prop(inp, 'tokenPlacement')
      if !placement.is_a?(String) || !TOKEN_PLACEMENTS.include?(placement)
        issues << "tokenPlacement must be one of #{one_of(TOKEN_PLACEMENTS)}"
      elsif placement == 'header' && !non_empty?(prop(inp, 'headerName'))
        issues << "tokenPlacement 'header' requires a non-empty headerName"
      elsif placement == 'query' && !non_empty?(prop(inp, 'queryParam'))
        issues << "tokenPlacement 'query' requires a non-empty queryParam"
      end
      header_name = prop(inp, 'headerName')
      if header_name.is_a?(String) && (!m?(header_name, HEADER_NAME) || FORBIDDEN_HEADERS.include?(pua(header_name).downcase))
        issues << "headerName '#{header_name}' must be an HTTP token and not a protocol header"
      end
      query_param = prop(inp, 'queryParam')
      issues << "queryParam '#{query_param}' must be a plain parameter name" if query_param.is_a?(String) && !m?(query_param, QUERY_NAME)
      sep_raw = prop(inp, 'scopeSeparator')
      issues << 'scopeSeparator must not be empty' if sep_raw.is_a?(String) && sep_raw.empty?
      pkce = prop(inp, 'pkce')
      issues << 'pkce must be a boolean' if !pkce.equal?(UNDEF) && !bool?(pkce)
      scope_sep = prop(inp, 'scopeSeparator')
      issues << 'scopeSeparator must be a string' if !scope_sep.equal?(UNDEF) && !scope_sep.is_a?(String)
      auth_params = prop(inp, 'authParams')
      if !auth_params.equal?(UNDEF) && !str_record?(auth_params)
        issues << 'authParams must be a string→string map'
      elsif str_record?(auth_params)
        auth_params.each_key { |k| issues << "authParams may not set '#{k}': the request builder owns it" if RESERVED_AUTHORIZE_PARAMS.include?(k) }
      end
      client_auth = prop(inp, 'clientAuth')
      issues << "clientAuth must be one of #{one_of(CLIENT_AUTHS)}" if !client_auth.equal?(UNDEF) && (!client_auth.is_a?(String) || !CLIENT_AUTHS.include?(client_auth))
      required_vars = prop(inp, 'requiredVars')
      issues << 'requiredVars must be an array of strings' if !required_vars.equal?(UNDEF) && !str_array?(required_vars)
      if https_url?(authorize_url) && https_url?(token_url)
        declared = (str_array?(required_vars) ? required_vars : []).uniq
        used = (url_vars(authorize_url) + url_vars(token_url)).uniq
        used.each { |v| issues << "url uses '{#{v}}' but requiredVars does not declare it" unless declared.include?(v) }
        declared.each { |v| issues << "requiredVars declares '#{v}' but no URL uses '{#{v}}'" unless used.include?(v) }
      end
      docs_url = prop(inp, 'docsUrl')
      issues << 'docsUrl must be a string' if !docs_url.equal?(UNDEF) && !docs_url.is_a?(String)
      return { 'ok' => false, 'issues' => issues } unless issues.empty?

      { 'ok' => true, 'manifest' => freeze_manifest(inp) }
    end

    def str_or(v, fallback = '') = v.is_a?(String) ? v : fallback

    def freeze_manifest(inp)
      raw = prop(inp, 'refresh')
      rr = raw.is_a?(Hash) ? raw : {}
      refresh_ = { 'mode' => prop(rr, 'mode') == 'none' ? 'none' : 'refresh_token' }
      te = prop(rr, 'tokenEndpoint')
      refresh_['tokenEndpoint'] = te if te.is_a?(String)
      sn = prop(rr, 'supportsScopeNarrowing')
      refresh_['supportsScopeNarrowing'] = sn if bool?(sn)
      ep = prop(rr, 'extraParams')
      refresh_['extraParams'] = ep.dup if str_record?(ep)
      tp = prop(inp, 'tokenPlacement')
      sa = prop(inp, 'scopesAvailable')
      ds = prop(inp, 'defaultScopes')
      m = {
        'id' => str_or(prop(inp, 'id')), 'displayName' => str_or(prop(inp, 'displayName')), 'authorizeUrl' => str_or(prop(inp, 'authorizeUrl')),
        'tokenUrl' => str_or(prop(inp, 'tokenUrl')), 'scopesAvailable' => str_array?(sa) ? sa.dup : [], 'defaultScopes' => str_array?(ds) ? ds.dup : [],
        'refresh' => refresh_, 'tokenPlacement' => tp == 'header' ? 'header' : tp == 'query' ? 'query' : 'bearer'
      }
      pkce = prop(inp, 'pkce')
      m['pkce'] = pkce if bool?(pkce)
      sep = prop(inp, 'scopeSeparator')
      m['scopeSeparator'] = sep if sep.is_a?(String)
      ap = prop(inp, 'authParams')
      m['authParams'] = ap.dup if str_record?(ap)
      ca = prop(inp, 'clientAuth')
      m['clientAuth'] = ca if %w[post basic].include?(ca)
      hn = prop(inp, 'headerName')
      m['headerName'] = hn if hn.is_a?(String)
      qp = prop(inp, 'queryParam')
      m['queryParam'] = qp if qp.is_a?(String)
      rv = prop(inp, 'requiredVars')
      m['requiredVars'] = rv.dup if str_array?(rv)
      du = prop(inp, 'docsUrl')
      m['docsUrl'] = du if du.is_a?(String)
      m
    end

    def assert_manifest(inp)
      r = validate_manifest(inp)
      raise ManifestValidationError.new(r['issues']) unless r['ok']

      r['manifest']
    end

    # The content address of a validated manifest: a pinned digest detects a swapped endpoint.
    def manifest_digest(manifest) = AtlasPca.hash_canonical(manifest)

    # ---- registry -----------------------------------------------------------------------------------------------------------
    class ProviderRegistry
      def initialize = @by_id = {}

      # Validate and register a manifest; opts 'expectedDigest' pins it, a duplicate id needs 'replace' => true.
      def register(manifest, opts = nil)
        opts ||= {}
        valid = Connectors.assert_manifest(manifest)
        if !opts['expectedDigest'].nil? && Connectors.manifest_digest(valid) != opts['expectedDigest']
          raise ConnectorError, "manifest '#{valid['id']}' does not match the pinned digest"
        end
        if @by_id.key?(valid['id']) && opts['replace'] != true
          raise ConnectorError, "provider '#{valid['id']}' is already registered; pass { replace: true } to replace it deliberately"
        end

        @by_id[valid['id']] = valid
      end

      def get(provider_id) = @by_id[provider_id]

      def require_provider(provider_id)
        m = @by_id[provider_id]
        raise UnknownProviderError.new(provider_id) if m.nil?

        m
      end

      def has?(provider_id) = @by_id.key?(provider_id)
      def list = @by_id.values.sort_by { |m| Siem::U16.units(m['id']) }
      def ids = list.map { |m| m['id'] }
    end

    def create_default_registry
      r = ProviderRegistry.new
      BUILTIN_MANIFESTS.each { |m| r.register(m) }
      r
    end

    # built on first use, so loading the library never validates the catalog
    def default_registry = (@default_registry ||= create_default_registry)
    def register_provider(manifest, opts = nil) = default_registry.register(manifest, opts)

    # One digest over the whole catalog (id and manifest digest, in id order).
    def catalog_digest(registry = nil)
      AtlasPca.hash_canonical((registry || default_registry).list.map { |m| [m['id'], manifest_digest(m)] })
    end

    def get_provider(provider_id) = default_registry.get(provider_id)
    def list_providers = default_registry.list

    # ---- authorize URL, PKCE, URL variables and token placement ---------------------------------------------------------------
    PKCE_VERIFIER = /\A[A-Za-z0-9._~-]{43,128}\z/
    MIN_STATE_CHARS = 16
    LABEL = /\A[A-Za-z0-9][A-Za-z0-9-]{0,62}\z/

    def random_token(n = 32) = AtlasPca.b64e(SecureRandom.random_bytes(n))

    # The PKCE challenge of a verifier: S256 (base64url of its SHA-256), or the verifier itself for "plain".
    def pkce_challenge(verifier, method = 'S256') = method == 'plain' ? verifier : AtlasPca.b64e(Digest::SHA256.digest(verifier.b))

    # Fill {name} placeholders from vars; each value must be a single DNS label so a value can never change the host.
    def substitute_vars(url, vars = UNDEF)
      url.gsub(VAR) do
        name = Regexp.last_match(1)
        raise TypeError, 'Cannot convert undefined or null to object' if vars.nil?

        v = vars.is_a?(Hash) && vars.key?(name) ? vars[name] : UNDEF
        raise ConnectorError, "missing URL variable '{#{name}}'" if v.equal?(UNDEF)
        raise ConnectorError, "URL variable '{#{name}}' must be a single DNS label (letters, digits and hyphens)" if !v.is_a?(String) || !m?(v, LABEL)

        v
      end
    end

    def enc(v)
      s = v.is_a?(String) ? v : Predicates.js_string(v)
      raise ArgumentError, 'URI malformed' unless s.dup.force_encoding(Encoding::UTF_8).valid_encoding?

      Js.encode_uri_component(s)
    end

    def encode_form(params) = params.map { |k, v| "#{enc(k)}=#{enc(v)}" }.join('&')

    def check_redirect_uri(uri)
      text = Predicates.js_string(uri)
      begin
        u = url_info(text)
      rescue Connect::UrlError
        raise ConnectorError, 'buildAuthorizeUrl: redirectUri must be an absolute URL'
      end
      raise ConnectorError, 'buildAuthorizeUrl: redirectUri must not have a fragment (RFC 6749 3.1.2)' if u['hash'] != ''
      raise ConnectorError, 'buildAuthorizeUrl: redirectUri must not carry credentials' if u['username'] != '' || u['password'] != ''

      local = ['localhost', '127.0.0.1', '[::1]'].include?(u['hostname'])
      return if u['protocol'] == 'https:' || (u['protocol'] == 'http:' && local)

      raise ConnectorError, 'buildAuthorizeUrl: redirectUri must be https (http only for localhost)'
    end

    # protocol, username, password, hostname and hash of an absolute URL (WHATWG parse; raises UrlError when it does not parse).
    def url_info(text)
      s = text.b.gsub(/\xED[\xA0-\xBF][\x80-\xBF]/n, "\xEF\xBF\xBD".b).sub(/\A[\x00-\x20]+/n, '').sub(/[\x00-\x20]+\z/n, '').delete("\t\n\r")
      m = s.match(/\A([A-Za-z][A-Za-z0-9+.\-]*):/n)
      raise Connect::UrlError, 'Invalid URL' if m.nil?

      scheme = m[1].downcase
      begin
        u = Connect::Url.new(s)
        return { 'protocol' => "#{scheme}:", 'username' => u.username, 'password' => u.password, 'hostname' => u.host, 'hash' => u.hash }
      rescue Connect::UrlError
        raise if Connect::SPECIAL_PORTS.key?(scheme)
      end
      rest = m.post_match
      frag = rest.include?('#') ? rest.split('#', 2)[1] : ''
      user = pw = host = ''
      if rest.start_with?('//')
        auth = rest[2..].split(%r{[/?#]}n, 2)[0].to_s
        if auth.include?('@')
          ui, _at, auth = auth.rpartition('@')
          user, _colon, pw = ui.partition(':')
        end
        host = auth.split(':', 2)[0].to_s
      end
      { 'protocol' => "#{scheme}:", 'username' => user, 'password' => pw, 'hostname' => host, 'hash' => frag.empty? ? '' : "##{frag}" }
    end

    def check_scopes(manifest, scopes, allow_unlisted)
      raise ConnectorError, 'buildAuthorizeUrl: scopes must be a list' unless scopes.is_a?(Array)

      seen = {}
      sep = manifest.fetch('scopeSeparator', ' ')
      scopes.each do |s|
        if !s.is_a?(String) || s.empty? || m?(s, WS_OR_COMMA) || s.include?(sep)
          raise ConnectorError, 'buildAuthorizeUrl: every scope must be a non-empty string without whitespace, commas or the separator'
        end
        raise ConnectorError, "buildAuthorizeUrl: scope '#{s}' is listed twice" if seen.key?(s)

        seen[s] = true
        if !allow_unlisted && !manifest['scopesAvailable'].empty? && !manifest['scopesAvailable'].include?(s)
          raise ConnectorError, "buildAuthorizeUrl: scope '#{s}' is not offered by provider '#{manifest['id']}'"
        end
      end
    end

    # The authorization URL (RFC 6749 3.1, RFC 7636) for a registered provider: {'url', 'state', 'pkce'?}. options carries clientId,
    # redirectUri, scopes, state, pkce (false, true or {verifier, method}), vars, registry, extraParams, allowUnlistedScopes and
    # allowPlainPkce. A random state / PKCE verifier is generated when none is given.
    def build_authorize_url(provider_id, options)
      registry = Js.truthy?(options['registry']) ? options['registry'] : default_registry
      manifest = registry.require_provider(provider_id)
      scopes = options['scopes']
      scopes = manifest['defaultScopes'] if scopes.nil?
      separator = manifest.fetch('scopeSeparator', ' ')
      state = options['state']
      state = random_token if state.nil?
      client_id = options['clientId']
      raise ConnectorError, 'buildAuthorizeUrl: clientId must be a non-empty string' if !client_id.is_a?(String) || client_id.empty?

      check_redirect_uri(options.key?('redirectUri') ? options['redirectUri'] : UNDEF)
      if !state.is_a?(String) || Js.len16(state) < MIN_STATE_CHARS
        raise ConnectorError, "buildAuthorizeUrl: state must be at least #{MIN_STATE_CHARS} characters (omit it to get a random one)"
      end

      check_scopes(manifest, scopes, options['allowUnlistedScopes'] == true)
      extra = Js.truthy?(options['extraParams']) ? options['extraParams'] : {}
      keys_of(extra).each do |k|
        raise ConnectorError, "buildAuthorizeUrl: extraParams may not set '#{k}'" if RESERVED_AUTHORIZE_PARAMS.include?(k)
      end
      params = [%w[response_type code], ['client_id', client_id], ['redirect_uri', options['redirectUri']]]
      params << ['scope', scopes.join(separator)] unless scopes.empty?
      params << ['state', state]
      pk = options.key?('pkce') ? options['pkce'] : UNDEF
      want = if pk.equal?(false) then false
             elsif !pk.equal?(UNDEF) then true
             else manifest['pkce'] == true
             end
      pkce = nil
      if want
        if pk.is_a?(Hash)
          verifier = pk.key?('verifier') ? pk['verifier'] : UNDEF
          method = pk['method']
          method = 'S256' if method.nil?
        elsif pk.nil?
          raise TypeError, 'Cannot read properties of null'
        else
          verifier = random_token
          method = 'S256'
        end
        raise ConnectorError, 'buildAuthorizeUrl: the PKCE verifier must be 43 to 128 unreserved characters (RFC 7636)' unless m?(Predicates.js_string(verifier), PKCE_VERIFIER)
        unless method == 'S256' || (method == 'plain' && options['allowPlainPkce'] == true)
          raise ConnectorError, "buildAuthorizeUrl: PKCE method must be 'S256' (pass allowPlainPkce to use 'plain')"
        end

        challenge = pkce_challenge(verifier, method)
        params << ['code_challenge', challenge]
        params << ['code_challenge_method', method]
        pkce = { 'verifier' => verifier, 'challenge' => challenge, 'method' => method }
      end
      (manifest['authParams'] || {}).each { |k, v| params << [k, v] }
      (Js.truthy?(options['extraParams']) ? options['extraParams'] : {}).each { |k, v| params << [k, v] }
      base = substitute_vars(manifest['authorizeUrl'], options.key?('vars') ? options['vars'] : UNDEF)
      out = { 'url' => "#{base}#{base.include?('?') ? '&' : '?'}#{encode_form(params)}", 'state' => state }
      out['pkce'] = pkce unless pkce.nil?
      out
    end

    # How to present an access token: {'kind' => 'header' | 'query', 'name', 'value'}. The token must be printable ASCII without spaces.
    def apply_access_token(manifest, access_token)
      if !access_token.is_a?(String) || access_token.empty? || access_token.b.match?(/[^\x21-\x7e]/n)
        raise ConnectorError, 'applyAccessToken: the access token must be a non-empty string of printable ASCII without spaces'
      end
      raise TypeError, 'manifest must be an object' unless manifest.is_a?(Hash)

      case manifest['tokenPlacement']
      when 'bearer' then { 'kind' => 'header', 'name' => 'Authorization', 'value' => "Bearer #{access_token}" }
      when 'header'
        raise ConnectorError, "manifest '#{Predicates.js_string(prop(manifest, 'id'))}' is header-placed but has no headerName" unless manifest.key?('headerName')

        { 'kind' => 'header', 'name' => manifest['headerName'], 'value' => access_token }
      when 'query'
        raise ConnectorError, "manifest '#{Predicates.js_string(prop(manifest, 'id'))}' is query-placed but has no queryParam" unless manifest.key?('queryParam')

        { 'kind' => 'query', 'name' => manifest['queryParam'], 'value' => access_token }
      end
    end

    # ---- code exchange, refresh and the vault bridge ------------------------------------------------------------------------
    DEFAULT_TOKEN_LIFETIME_MS = 3_600_000

    def redact(text, secrets)
      secrets.each { |s| text = text.gsub(s, '[redacted]') if s.is_a?(String) && !s.empty? }
      text
    end

    def check_extra_params(extra, what)
      keys_of(Js.truthy?(extra) ? extra : {}).each { |k| raise ConnectorError, "#{what}: extraParams may not set '#{k}'" if RESERVED_TOKEN_PARAMS.include?(k) }
    end

    def basic_auth_header(client_id, client_secret)
      "Basic #{Base64.strict_encode64(AtlasPca::Js.utf8("#{Predicates.js_string(client_id)}:#{Predicates.js_string(client_secret)}"))}"
    end

    def parse_token_response(body, provider)
      raise ConnectorError, "[#{provider}] token endpoint returned a non-object body" unless body.is_a?(Hash)

      at = body['access_token']
      raise ConnectorError, "[#{provider}] token endpoint response has no access_token" if !at.is_a?(String) || at.empty?

      out = { 'accessToken' => at }
      ex = body['expires_in']
      out['expiresInSecs'] = ex if Connect.finite?(ex) && ex > 0
      rt = body['refresh_token']
      out['refreshToken'] = rt if rt.is_a?(String) && !rt.empty?
      sc = body['scope']
      if sc.is_a?(String) && !Js.trim(pua(sc)).empty?
        out['scopes'] = Js.trim(pua(sc)).split(WS_OR_COMMA_RUN, -1).map { |x| Siem::U16.from_pua(x) }
      end
      out
    end

    def post_token(manifest, token_endpoint, params, client_secret, fetch)
      headers = { 'content-type' => 'application/x-www-form-urlencoded', 'accept' => 'application/json' }
      body = params.dup
      if manifest['clientAuth'] == 'basic'
        raise ConnectorError, "[#{manifest['id']}] clientAuth 'basic' requires a clientSecret" if client_secret.nil?

        client_id = body['client_id']
        raise ConnectorError, "[#{manifest['id']}] missing client_id for basic auth" if client_id.nil? || client_id.equal?(UNDEF)

        headers['authorization'] = basic_auth_header(client_id, client_secret)
        body.delete('client_id')
        body.delete('client_secret')
      end
      secs = [client_secret, params['code'], params['code_verifier'], params['refresh_token'], headers['authorization']]
      res = begin
        raise TypeError, 'fetchImpl is not a function' if fetch.nil?

        fetch.call(token_endpoint, { 'method' => 'POST', 'headers' => headers, 'body' => encode_form(body.to_a) })
      rescue StandardError => e
        raise ConnectorError, "[#{manifest['id']}] token transport error: #{redact(e.message, secs)}"
      end
      unless res.ok
        detail = begin
          redact(Siem::U16.slice(res.text, 512), secs)
        rescue StandardError
          '<unreadable body>'
        end
        raise ConnectorError, "[#{manifest['id']}] token endpoint #{res.status}: #{detail}"
      end
      j = begin
        res.json
      rescue StandardError
        raise ConnectorError, "[#{manifest['id']}] unparseable token JSON"
      end
      parse_token_response(j, manifest['id'])
    end

    def store_connection(manifest, parsed, requested, bind, now, prior_refresh_token = nil)
      expires_at = parsed.key?('expiresInSecs') ? now + (parsed['expiresInSecs'] * 1000) : now + DEFAULT_TOKEN_LIFETIME_MS
      granted = parsed.fetch('scopes', requested)
      refresh_token = parsed.fetch('refreshToken', prior_refresh_token)
      a = bind['authority']
      authority = { 'principal' => a.fetch('principal'), 'scopes' => a.fetch('scopes', requested) }
      authority['audience'] = a['audience'] if a.key?('audience')
      bind['vault'].put_connection(bind['agentId'], manifest['id'], parsed['accessToken'], expires_at, granted, authority, bind['connectionId'], refresh_token)
    end

    def now_of(args) = args['now'].nil? ? (Time.now.to_f * 1000).to_i : args['now']

    # Exchange an authorization code for tokens at the provider's token endpoint and store the connection in the vault. args:
    # providerId, clientId, clientSecret?, code, redirectUri, codeVerifier?, scopes?, fetch, bind {vault, agentId, connectionId?,
    # authority {principal, scopes?, audience?}}, now?, registry?, vars?, extraParams?. Returns the stored connection.
    def exchange_code(args)
      registry = Js.truthy?(args['registry']) ? args['registry'] : default_registry
      manifest = registry.require_provider(args.fetch('providerId'))
      now = now_of(args)
      requested = args['scopes']
      requested = manifest['defaultScopes'] if requested.nil?
      code = args['code']
      raise ConnectorError, "[#{manifest['id']}] an authorization code is required" if !code.is_a?(String) || code.empty?

      check_extra_params(args['extraParams'], "[#{manifest['id']}] exchangeCode")
      if manifest['pkce'] == true && !args.key?('codeVerifier')
        raise ConnectorError, "[#{manifest['id']}] provider uses PKCE; a codeVerifier is required to exchange the code"
      end

      params = { 'grant_type' => 'authorization_code', 'code' => code, 'redirect_uri' => args.fetch('redirectUri', UNDEF), 'client_id' => args.fetch('clientId', UNDEF) }
      params['client_secret'] = args['clientSecret'] if args.key?('clientSecret')
      params['code_verifier'] = args['codeVerifier'] if args.key?('codeVerifier')
      params.update(Js.truthy?(args['extraParams']) ? args['extraParams'] : {})
      endpoint = substitute_vars(manifest['tokenUrl'], args.fetch('vars', UNDEF))
      parsed = post_token(manifest, endpoint, params, args['clientSecret'], args['fetch'])
      store_connection(manifest, parsed, requested, args.fetch('bind'), now)
    end

    # Refresh a connection's tokens at the provider and store the result in the vault (the refresh token is kept unless the provider
    # rotates it). args as for exchange_code, with refreshToken in place of code, redirectUri and codeVerifier.
    def refresh(args)
      registry = Js.truthy?(args['registry']) ? args['registry'] : default_registry
      manifest = registry.require_provider(args.fetch('providerId'))
      raise ConnectorError, "[#{manifest['id']}] provider does not support token refresh" if manifest['refresh']['mode'] == 'none'

      now = now_of(args)
      requested = args['scopes']
      requested = manifest['defaultScopes'] if requested.nil?
      rt = args['refreshToken']
      raise ConnectorError, "[#{manifest['id']}] a refresh token is required" if !rt.is_a?(String) || rt.empty?

      check_extra_params(args['extraParams'], "[#{manifest['id']}] refresh")
      params = { 'grant_type' => 'refresh_token', 'refresh_token' => rt, 'client_id' => args.fetch('clientId', UNDEF) }
      params['client_secret'] = args['clientSecret'] if args.key?('clientSecret')
      params.update(manifest['refresh']['extraParams'] || {})
      params.update(Js.truthy?(args['extraParams']) ? args['extraParams'] : {})
      params['scope'] = requested.join(manifest.fetch('scopeSeparator', ' ')) if manifest['refresh']['supportsScopeNarrowing'] == true && !requested.empty?
      endpoint = substitute_vars(manifest['refresh'].fetch('tokenEndpoint', manifest['tokenUrl']), args.fetch('vars', UNDEF))
      parsed = post_token(manifest, endpoint, params, args['clientSecret'], args['fetch'])
      store_connection(manifest, parsed, requested, args.fetch('bind'), now, rt)
    end

    # The vault's token-endpoint configuration for a refreshable manifest (creds: clientId, clientSecret?, vars?).
    def manifest_to_provider_config(manifest, creds)
      raise ConnectorError, "[#{manifest['id']}] provider does not support token refresh; no ProviderConfig" if manifest['refresh']['mode'] == 'none'

      config = { 'tokenEndpoint' => substitute_vars(manifest['refresh'].fetch('tokenEndpoint', manifest['tokenUrl']), creds.fetch('vars', UNDEF)),
                 'clientId' => creds.fetch('clientId') }
      config['clientSecret'] = creds['clientSecret'] if creds.key?('clientSecret')
      config['supportsScopeNarrowing'] = manifest['refresh']['supportsScopeNarrowing'] if manifest['refresh'].key?('supportsScopeNarrowing')
      config['extraParams'] = manifest['refresh']['extraParams'].dup if manifest['refresh'].key?('extraParams')
      config
    end

    # The providers option of a TokenVault from per-provider credentials; non-refreshable providers are skipped.
    def build_vault_providers(creds_by_id, registry = nil)
      registry ||= default_registry
      out = {}
      creds_by_id.each do |pid, creds|
        manifest = registry.require_provider(pid)
        next if manifest['refresh']['mode'] == 'none'

        out[pid] = manifest_to_provider_config(manifest, creds)
      end
      out
    end
  end
end
