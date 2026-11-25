# frozen_string_literal: true

require_relative 'whatwg_url'
require_relative 'js_compat'

# OAuth 2.1 / MCP-authorization interop bridge: RFC 9728 Protected Resource Metadata, the RFC 6750 / RFC 7235 WWW-Authenticate
# challenge, RFC 8707 resource indicators and token-audience binding, the 401 / discovery glue, the pca_grant token gate and
# scopes derived from the confirmed action. Mirrors the TypeScript reference (@atlasauth/pca-oauth). Options are String-keyed
# Hashes in snake_case ('authorization_servers', 'error_description', 'pca_challenge', ...). Pure, I/O-free.
module AtlasPca
  module OAuth
    WELL_KNOWN_OAUTH_PRM = '/.well-known/oauth-protected-resource'
    WELL_KNOWN_PCA_PATH = '/.well-known/pca-configuration'
    DEFAULT_PCA_HINT = 'send PCA-Action: <base64url PCActn> or JSON body {pcactn}'
    DEFAULT_SUITES = %w[ed25519 ml-dsa-65 hybrid-ed25519-ml-dsa-65].freeze
    DEFAULT_REQUIRED = %w[counter_format replay revocation plan_root_authorized audience validity grant_ref_bound].freeze
    PCA_NEED_MAX_ENCODED = 2048
    SCOPE_TOKEN = /\A[\x21\x23-\x5b\x5d-\x7e]+\z/

    module_function

    # RFC 9728 section 1.2: the reason `resource` is not an https URL without a fragment, or nil when it is valid.
    def resource_identifier_problem(resource)
      return 'resource identifier must be a non-empty string' unless resource.is_a?(String) && !resource.empty?

      u = WhatwgUrl.parse(resource)
      return 'resource identifier is not an absolute URL' if u.nil?
      return 'resource identifier must use the https scheme' unless u['scheme'] == 'https'
      return 'resource identifier must not contain a fragment' if resource.include?('#')

      nil
    end

    # RFC 9728 section 3.1: the suffix goes between host and path/query. Raises ArgumentError on an invalid identifier.
    def prm_path_for_resource(resource)
      problem = resource_identifier_problem(resource)
      raise ArgumentError, "prmPathForResource: #{problem}" if problem

      u = WhatwgUrl.parse(resource)
      WELL_KNOWN_OAUTH_PRM + (u['pathname'] == '/' ? '' : u['pathname']) + u['search']
    end

    def prm_url_for_resource(resource)
      u = WhatwgUrl.parse(resource)
      raise ArgumentError, 'prmUrlForResource: invalid resource identifier' if u.nil? || !u.key?('origin')

      u['origin'] + prm_path_for_resource(resource)
    end

    # The PCA discovery document (buildDiscoveryDocument of the core package). Options: audience, pca_versions,
    # signature_suites, action_header, required_checks, endpoints, trusted_roots, metadata.
    def build_discovery_document(o)
      aud = o['audience']
      raise ArgumentError, 'buildDiscoveryDocument: audience is required' unless aud.is_a?(String) && !aud.empty?

      doc = {
        'audience' => aud,
        'pca_versions' => o['pca_versions'].nil? ? [2] : o['pca_versions'],
        'signature_suites' => o['signature_suites'].nil? ? DEFAULT_SUITES.dup : o['signature_suites'],
        'action_header' => o['action_header'].nil? ? 'PCA-Action' : o['action_header'],
        'required_checks' => o['required_checks'].nil? ? DEFAULT_REQUIRED.dup : o['required_checks']
      }
      %w[endpoints trusted_roots metadata].each { |k| doc[k] = o[k] if Js.truthy?(o[k]) }
      doc
    end

    # RFC 9728 Protected Resource Metadata plus the PCA block (the discovery document embedded). Raises on a bad resource.
    def protected_resource_metadata(o)
      resource = o['resource']
      unless resource.is_a?(String) && !resource.empty?
        raise ArgumentError, 'protectedResourceMetadata: `resource` (the RS id = PCActn audience) is required'
      end

      unless o['strict'] == false
        problem = resource_identifier_problem(resource)
        raise ArgumentError, "protectedResourceMetadata: #{problem}" if problem
      end
      discovery = build_discovery_document({ 'audience' => resource }.merge(
        o.slice('signature_suites', 'pca_versions', 'action_header', 'required_checks', 'endpoints', 'trusted_roots', 'metadata')
      ))
      cfg = o['pca_configuration_endpoint']
      cfg = resource.split('?', -1)[0].sub(%r{/+\z}, '') + WELL_KNOWN_PCA_PATH if cfg.nil?
      doc = {
        'resource' => resource,
        'bearer_methods_supported' => o['bearer_methods_supported'].nil? ? ['header'] : o['bearer_methods_supported'],
        'pca_action_header' => discovery['action_header'],
        'pca_signature_suites' => Js.spread(discovery['signature_suites']),
        'pca_versions' => Js.spread(discovery['pca_versions']),
        'pca_configuration_endpoint' => cfg,
        'pca' => discovery
      }
      doc['authorization_servers'] = Js.spread(o['authorization_servers']) if Js.truthy?(o['authorization_servers'])
      doc['resource_documentation'] = o['resource_documentation'] if Js.truthy?(o['resource_documentation'])
      doc['scopes_supported'] = Js.spread(o['scopes_supported']) if Js.truthy?(o['scopes_supported'])
      doc['resource_name'] = o['resource_name'] if Js.truthy?(o['resource_name'])
      %w[resource_signing_alg_values_supported authorization_details_types_supported].each do |k|
        doc[k] = Js.spread(o[k]) if Js.truthy?(o[k])
      end
      doc
    end

    # Validate and narrow an untrusted PRM document. Options: expected_resource, strict. Raises ArgumentError (fail closed).
    def parse_protected_resource_metadata(v, opts = nil)
      opts ||= {}
      p = 'parseProtectedResourceMetadata: '
      raise ArgumentError, "#{p}not an object" unless v.is_a?(Hash) || v.is_a?(Array)
      raise ArgumentError, "#{p}missing `resource`" unless v.is_a?(Hash) && v['resource'].is_a?(String) && !v['resource'].empty?
      raise ArgumentError, "#{p}bearer_methods_supported must be a string[]" unless Js.str_list?(v['bearer_methods_supported'])
      unless v['pca_action_header'].is_a?(String) && !v['pca_action_header'].empty?
        raise ArgumentError, "#{p}missing pca_action_header"
      end
      raise ArgumentError, "#{p}pca_signature_suites must be a string[]" unless Js.str_list?(v['pca_signature_suites'])
      unless v['pca_versions'].is_a?(Array) && v['pca_versions'].all? { |n| Js.num?(n) }
        raise ArgumentError, "#{p}pca_versions must be a number[]"
      end

      pca = v['pca']
      raise ArgumentError, "#{p}missing embedded `pca` discovery document" unless pca.is_a?(Hash) || pca.is_a?(Array)
      unless pca.is_a?(Hash) && pca['audience'].is_a?(String) && !pca['audience'].empty?
        raise ArgumentError, "#{p}embedded pca.audience is required"
      end

      if opts.key?('expected_resource')
        raise ArgumentError, "#{p}`resource` does not match the expected resource identifier" unless v['resource'] == opts['expected_resource']
        unless pca['audience'] == opts['expected_resource']
          raise ArgumentError, "#{p}embedded pca.audience does not match the expected resource identifier"
        end
      end
      unless opts['strict'] == false
        unless opts.key?('expected_resource')
          raise ArgumentError, "#{p}expectedResource is required (RFC 9728 section 3.3); pass strict: false to skip"
        end

        problem = resource_identifier_problem(v['resource'])
        raise ArgumentError, p + problem if problem
        unless v['bearer_methods_supported'].all? { |m| %w[header body query].include?(m) }
          raise ArgumentError, "#{p}bearer_methods_supported has a value outside header/body/query"
        end
      end
      doc = {
        'resource' => v['resource'], 'bearer_methods_supported' => v['bearer_methods_supported'],
        'pca_action_header' => v['pca_action_header'], 'pca_signature_suites' => v['pca_signature_suites'],
        'pca_versions' => v['pca_versions'], 'pca' => pca
      }
      doc['pca_configuration_endpoint'] = v['pca_configuration_endpoint'] if v['pca_configuration_endpoint'].is_a?(String)
      doc['authorization_servers'] = v['authorization_servers'] if Js.str_list?(v['authorization_servers'])
      doc['resource_documentation'] = v['resource_documentation'] if v['resource_documentation'].is_a?(String)
      doc['scopes_supported'] = v['scopes_supported'] if Js.str_list?(v['scopes_supported'])
      doc['resource_name'] = v['resource_name'] if v['resource_name'].is_a?(String)
      doc['resource_signing_alg_values_supported'] = v['resource_signing_alg_values_supported'] if Js.str_list?(v['resource_signing_alg_values_supported'])
      doc
    end

    # A quoted auth-param value (RFC 7235): a quote, backslash or control character is refused (header injection).
    def quoted_param(value)
      raise TypeError, 'pca-oauth: WWW-Authenticate parameter value must be a string' unless value.is_a?(String)
      if value.match?(/["\\\x00-\x1f\x7f]/)
        raise ArgumentError, 'pca-oauth: WWW-Authenticate parameter value may not contain a quote or newline'
      end

      value
    end

    def encode_pca_need(need)
      code = AtlasPca.a2a_need_error(need)
      raise ArgumentError, "encodePcaNeed: malformed need (#{code})" if code

      enc = AtlasPca.b64e(AtlasPca.canon_bytes(need))
      raise ArgumentError, 'encodePcaNeed: the need is too large for a header' if enc.length > PCA_NEED_MAX_ENCODED

      enc
    end

    # The WWW-Authenticate value of a 401: the MCP `Bearer resource_metadata` challenge plus (by default) the PCA challenge.
    # Options: error, error_description, scope, pca_need, include_pca, pca_challenge, realm, hint.
    def www_authenticate(prm_url, o = nil)
      o ||= {}
      raise ArgumentError, 'wwwAuthenticate: prmUrl is required' unless prm_url.is_a?(String) && !prm_url.empty?

      params = ["resource_metadata=\"#{quoted_param(prm_url)}\""]
      params << "error=\"#{quoted_param(o['error'])}\"" if Js.truthy?(o['error'])
      params << "error_description=\"#{quoted_param(o['error_description'])}\"" if Js.truthy?(o['error_description'])
      params << "scope=\"#{quoted_param(o['scope'])}\"" if Js.truthy?(o['scope'])
      params << "pca_need=\"#{quoted_param(encode_pca_need(o['pca_need']))}\"" if Js.truthy?(o['pca_need'])
      challenges = ["Bearer #{params.join(', ')}"]
      include_pca = o['include_pca'].nil? ? true : o['include_pca']
      if Js.truthy?(o['pca_challenge'])
        pc = o['pca_challenge']
        raise TypeError, 'pca-oauth: pcaChallenge must be a string' unless pc.is_a?(String)
        if pc.match?(/[\x00-\x08\x0a-\x1f\x7f]/)
          raise ArgumentError, 'pca-oauth: pcaChallenge may not contain control characters or newlines'
        end

        challenges << pc
      elsif Js.truthy?(include_pca)
        realm = o['realm'].nil? ? 'pca' : o['realm']
        hint = o['hint'].nil? ? DEFAULT_PCA_HINT : o['hint']
        pca = +"PCA realm=\"#{quoted_param(realm)}\""
        pca << ", hint=\"#{quoted_param(hint)}\"" if Js.truthy?(hint)
        challenges << pca
      end
      challenges.join(', ')
    end

    # RFC 8707: the OAuth-layer echo of the audience (an early reject, never the security boundary; the signed `aud` is).
    def check_resource_indicator(resource_param, expected_audience)
      unless expected_audience.is_a?(String) && !expected_audience.empty?
        raise ArgumentError, 'checkResourceIndicator: expectedAudience is required'
      end
      return { 'ok' => false, 'reason' => 'no resource indicator presented' } if resource_param.nil?

      values = resource_param.is_a?(Array) ? resource_param : [resource_param]
      return { 'ok' => false, 'reason' => 'empty resource indicator' } if values.empty?

      values.each do |r|
        next unless r.is_a?(String) && !r.empty?
        return { 'ok' => true, 'matched' => r } if r == expected_audience
      end
      { 'ok' => false, 'reason' => "resource indicator #{Js.json(values)} does not match audience #{Js.json(expected_audience)}" }
    end

    # The `aud` of a verified token must be, or contain, exactly this resource identifier. No prefix or case tolerance.
    def check_token_audience(aud, expected_resource)
      unless expected_resource.is_a?(String) && !expected_resource.empty?
        raise ArgumentError, 'checkTokenAudience: expectedResource is required'
      end
      return { 'ok' => false, 'reason' => 'token has no audience' } if aud.nil?

      values = aud.is_a?(Array) ? aud : [aud]
      return { 'ok' => false, 'reason' => 'token has an empty audience' } if values.empty?
      return { 'ok' => true, 'matched' => expected_resource } if values.any? { |a| a.is_a?(String) && a == expected_resource }

      { 'ok' => false, 'reason' => "token audience #{Js.json(aud)} does not include resource #{Js.json(expected_resource)}" }
    end

    # The path and body to serve the RFC 9728 document ('rfcPath' is an alias of 'path').
    def oauth_discovery_handler(o)
      body = protected_resource_metadata(o)
      path = resource_identifier_problem(o['resource']).nil? ? prm_path_for_resource(o['resource']) : WELL_KNOWN_OAUTH_PRM
      { 'path' => path, 'body' => body, 'rfcPath' => path }
    end

    # The complete MCP / OAuth 401: status, the WWW-Authenticate header and a JSON body echoing the error and the PRM pointer.
    def mcp_unauthorized(prm_url, o = nil)
      o ||= {}
      body = { 'error' => o['error'].nil? ? 'invalid_request' : o['error'], 'resource_metadata' => prm_url }
      body['error_description'] = o['error_description'] if Js.truthy?(o['error_description'])
      { 'status' => 401, 'headers' => { 'WWW-Authenticate' => www_authenticate(prm_url, o) }, 'body' => body }
    end

    # Upgrade a verifier deny result's 401: its existing PCA challenge ('wwwAuthenticate') is kept verbatim and the Bearer
    # resource_metadata challenge is prepended. Every other member is preserved.
    def upgrade_unauthorized_challenge(result, prm_url, o = nil)
      o ||= {}
      existing = result['wwwAuthenticate']
      header = www_authenticate(prm_url, Js.truthy?(existing) ? o.merge('pca_challenge' => existing) : o)
      result.merge('wwwAuthenticate' => header)
    end

    # ---- pca_grant (RFC 9396) ----

    # A validated `pca_grant` detail. Options: chain_ids (root first), chain_ref, bundle_revision, locations.
    def build_pca_grant_detail(o)
      ids = o['chain_ids']
      raise TypeError, 'buildPcaGrantDetail: chain_ids must be an array' unless ids.is_a?(Array)

      d = { 'type' => PCA_GRANT_TYPE, 'chain_digest' => AtlasPca.pca_grant_chain_digest(ids), 'chain_len' => ids.length }
      d['chain_ref'] = o['chain_ref'] unless o['chain_ref'].nil?
      d['bundle_revision'] = o['bundle_revision'] unless o['bundle_revision'].nil?
      d['locations'] = Js.spread(o['locations']) unless o['locations'].nil?
      code = AtlasPca.validate_pca_grant_detail(d)
      raise ArgumentError, "buildPcaGrantDetail: refused (#{code})" if code

      d
    end

    # The form-encoded value of the `authorization_details` request parameter (RFC 9396 section 3).
    def pca_grant_request_param(details) = Js.encode_uri_component(Js.json(details))

    # Gate an access token carrying pca_grant details. Options: authorization_details, resource, chain_ids, proof_verified.
    # Allow only with well-formed details naming a prefix of the presented chain and this resource AND a verified proof.
    def authorize_pca_grant_token(o)
      details, code = AtlasPca.parse_pca_grant_details(o['authorization_details'])
      return { 'allow' => false, 'status' => 401, 'error' => 'invalid_token', 'code' => code } if code

      idx, code = AtlasPca.check_pca_grant_presentation(details, o['resource'], o['chain_ids'], o['proof_verified'])
      return { 'allow' => true, 'detail' => details[idx] } if code.nil?

      loc = code == 'wrong_location'
      { 'allow' => false, 'status' => loc ? 403 : 401, 'error' => loc ? 'insufficient_scope' : 'invalid_token', 'code' => code }
    end

    # ---- scopes derived from the confirmed action ----

    # deriveActionScopes: upstream.scopes_min of a confirmed action, inside `granted` when given; else a refusal code.
    def derive_action_scopes(action, o = {})
      return { 'ok' => false, 'code' => 'unknown_action' } unless action.is_a?(Hash) || action.is_a?(Array)
      return { 'ok' => false, 'code' => 'unconfirmed' } unless action.is_a?(Hash) && action['confirmed'] == true

      up = action['upstream'].is_a?(Hash) ? action['upstream'] : {}
      return { 'ok' => false, 'code' => 'provider_mismatch' } if o.key?('provider') && !o['provider'].nil? && up['provider'] != o['provider']

      min = up['scopes_min']
      return { 'ok' => false, 'code' => 'no_scopes' } unless min.is_a?(Array) && !min.empty?
      unless min.all? { |s| s.is_a?(String) && s.length <= 256 && s.match?(SCOPE_TOKEN) }
        return { 'ok' => false, 'code' => 'bad_scope' }
      end

      scopes = min.uniq.sort
      if !o['granted'].nil? && !(scopes - o['granted']).empty?
        return { 'ok' => false, 'code' => 'exceeds_grant' }
      end

      { 'ok' => true, 'scopes' => scopes, 'provider' => up['provider'], 'def_digest' => action['def_digest'] }
    end

    # The `scope` (and RFC 8707 `resource`) an OAuth client should request for one action. Options: provider, granted, resource.
    def oauth_scope_for_action(action, o)
      d = derive_action_scopes(action, o.slice('provider', 'granted'))
      return { 'ok' => false, 'code' => d['code'] } unless d['ok']

      r = { 'ok' => true, 'scope' => d['scopes'].join(' '), 'scopes' => d['scopes'] }
      r['resource'] = o['resource'] unless o['resource'].nil?
      r
    end
  end
end
