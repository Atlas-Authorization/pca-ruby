# frozen_string_literal: true

require_relative 'oidc'

# ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant, OAuth Cross-App Access) bridge: verify an ID-JAG (reusing the OIDC
# verifier for every crypto and registered-claim check, then the single-audience, `act` agent, scope and draft-shape rules),
# project it onto a PCA principal and a signed root capability, and build the RFC 8693 token-exchange and RFC 7523
# jwt-bearer requests of the XAA flow. Mirrors @atlasauth/pca-idjag. Options are String-keyed snake_case Hashes; returned
# objects keep the reference's member names.
module AtlasPca
  module IdJag
    MAX_ID_JAG_CHARS = 16_384
    IDJAG_AUTHORITY_CAVEAT = 'idjag_authority'
    IDJAG_PROVENANCE_CAVEAT = 'idjag_provenance'
    GRANT_TYPE_TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
    GRANT_TYPE_JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
    TOKEN_TYPE_ID_JAG = 'urn:ietf:params:oauth:token-type:id-jag'
    TOKEN_TYPE_ID_TOKEN = 'urn:ietf:params:oauth:token-type:id_token'
    TOKEN_TYPE_ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token'
    TOKEN_TYPE_JWT = 'urn:ietf:params:oauth:token-type:jwt'
    CLIENT_ASSERTION_TYPE_JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    ID_JAG_TYP = 'oauth-id-jag+jwt'
    WS_RE = /[#{Js::WS}]+/o

    # Any ID-JAG verification failure; #code is an OIDC code or actor / scope / grant.
    class IdJagVerificationError < StandardError
      attr_reader :code

      def initialize(code, message)
        @code = code
        super(message)
      end
    end

    module_function

    def err(code, msg) = IdJagVerificationError.new(code, msg)
    def str(v) = v.is_a?(String) && !v.empty?

    PASS = %w[nonce clock_tolerance_sec max_token_age_sec algorithms key jwks_uri discover fetch].freeze

    # Verify an ID-JAG; the grant {iss, sub, actor, agent, audience, scopes, iat, exp, jti?, nonce?, cnf?, oidcClaims}.
    # Options: issuer, audience (one resource app) required; nonce, required_scopes, clock_tolerance_sec, max_token_age_sec,
    # algorithms, key | jwks_uri | discover (+ fetch); strict_draft (default true) with client_id and consume_jti
    # (callable(jti, exp) -> true only for a fresh jti) required.
    def verify_id_jag(jwt, o)
      raise err('invalid_token', 'verifyIdJag: jwt must be a non-empty string') unless str(jwt)
      raise err('invalid_token', 'verifyIdJag: jwt exceeds the size limit') if Js.len16(jwt) > MAX_ID_JAG_CHARS
      raise err('config', 'verifyIdJag: opts is required') unless o.is_a?(Hash)
      raise err('config', 'verifyIdJag: opts.issuer is required') unless str(o['issuer'])
      raise err('config', 'verifyIdJag: opts.audience is required (ID-JAG is single-audience)') unless str(o['audience'])

      strict = o['strict_draft'] != false
      raise err('config', 'verifyIdJag: strictDraft requires opts.consumeJti (single-use store)') if strict && !o['consume_jti'].respond_to?(:call)
      if strict && !str(o['client_id'])
        raise err('config', 'verifyIdJag: strictDraft requires opts.clientId (the client authenticated at the token endpoint)')
      end

      base = begin
        Oidc.verify_id_token(jwt, { 'issuer' => o['issuer'], 'audience' => o['audience'] }.merge(o.slice(*PASS)))
      rescue Oidc::OidcVerificationError => e
        raise err(e.code, e.message)
      rescue StandardError
        raise err('invalid_token', 'ID-JAG verification failed')
      end
      aud = base['aud'].is_a?(Array) ? base['aud'] : [base['aud']]
      unless aud.length == 1 && aud[0] == o['audience']
        raise err('audience', 'ID-JAG must carry exactly one audience equal to the resource app (single-audience grant)')
      end

      jws = Jose.assert_canonical_compact_jws(jwt) # authentic: the signature verified above
      raw = jws['payload']
      actor = as_actor(raw['act'])
      raise err('actor', 'ID-JAG is missing a well-formed "act" (agent) claim with a string "sub"') if actor.nil?

      scopes = parse_scopes(raw['scope'], raw['scopes'])
      raise err('scope', 'ID-JAG is missing the "scope" (or "scopes") claim') if scopes.nil?
      if o['required_scopes'].is_a?(Array)
        o['required_scopes'].each { |r| raise err('scope', "ID-JAG does not grant the required scope \"#{Js.string(r)}\"") unless scopes.include?(r) }
      end
      jti = str(raw['jti']) ? raw['jti'] : nil
      if strict
        raise err('grant', "ID-JAG header typ must be \"#{ID_JAG_TYP}\"") unless jws['header']['typ'] == ID_JAG_TYP
        raise err('grant', 'ID-JAG is missing "client_id"') unless str(raw['client_id'])
        raise err('grant', 'ID-JAG client_id does not match the expected client') unless raw['client_id'] == o['client_id']
        raise err('grant', 'ID-JAG is missing "jti"') if jti.nil?

        fresh = begin
          o['consume_jti'].call(jti, base['exp']) == true
        rescue StandardError
          false
        end
        raise err('grant', 'ID-JAG jti was already used or the single-use store failed') unless fresh
      end
      g = { 'iss' => base['iss'], 'sub' => base['sub'], 'actor' => actor, 'agent' => actor['sub'], 'audience' => o['audience'],
            'scopes' => scopes, 'iat' => base['iat'], 'exp' => base['exp'] }
      g['jti'] = jti if jti
      g['nonce'] = base['nonce'] if base.key?('nonce')
      g['cnf'] = base['cnf'] if base.key?('cnf')
      g['oidcClaims'] = base
      g
    end

    def as_actor(v)
      return nil unless v.is_a?(Hash) && str(v['sub'])

      v.merge('sub' => v['sub'])
    end

    def parse_scopes(scope, scopes)
      return scope.split(WS_RE).reject(&:empty?) if scope.is_a?(String)
      return scope.select { |s| str(s) } if scope.is_a?(Array)
      return scopes.select { |s| str(s) } if scopes.is_a?(Array)

      nil
    end

    # The PCA principal of a verified grant (Oidc.oidc_principal over its oidcClaims).
    def id_jag_to_pca_principal(grant, opts = {})
      raise TypeError, 'idJagToPcaPrincipal: grant is required' unless grant.is_a?(Hash) || grant.is_a?(Array)

      Oidc.oidc_principal(Js.get(grant, 'oidcClaims'), opts)
    end

    # A signed PCA root capability from a verified grant: authority = scopes, holder = the agent key, subject = the human,
    # plus a provenance caveat. Options: principal_secret (32-byte Ed25519 seed, binary String), principal_public, holder,
    # suite ({'alg', 'pq' => PqKeyPair} for a post-quantum / hybrid root), extra_caveats.
    def id_jag_to_capability(grant, opts)
      raise TypeError, 'idJagToCapability: grant is required' unless grant.is_a?(Hash) || grant.is_a?(Array)
      raise TypeError, 'idJagToCapability: opts is required' unless opts.is_a?(Hash)

      secret = opts['principal_secret']
      raise TypeError, 'idJagToCapability: opts.principalSecret must be a Uint8Array' unless secret.is_a?(String) && secret.encoding == Encoding::BINARY
      raise TypeError, 'idJagToCapability: opts.principalPublic is required' unless str(opts['principal_public'])
      raise TypeError, 'idJagToCapability: opts.holder (the agent key) is required' unless str(opts['holder'])

      principal = id_jag_to_pca_principal(grant, { 'principal_public' => opts['principal_public'] })
      g = grant.is_a?(Hash) ? grant : {}
      authority = { 'type' => IDJAG_AUTHORITY_CAVEAT, 'scopes' => Js.spread(g['scopes']), 'aud' => g['audience'] }
      provenance = { 'type' => IDJAG_PROVENANCE_CAVEAT, 'iss' => g['iss'], 'sub' => g['sub'], 'agent' => g['agent'], 'aud' => g['audience'],
                     'iat' => g['iat'], 'exp' => g['exp'] }
      provenance['jti'] = g['jti'] if g.key?('jti')
      caveats = [authority, provenance, principal['subjectCaveat'], *Js.spread(opts['extra_caveats'].nil? ? [] : opts['extra_caveats'])]
      suite = opts['suite'] || {}
      cap = AtlasPca.seal_cap(opts['principal_public'], opts['holder'], AtlasPca.clone_json(caveats), nil, nil,
                              AtlasPca::KeyPair.new(secret), suite['alg'], suite['pq'])
      { 'capability' => cap, 'principal' => principal, 'scopes' => Js.spread(g['scopes']) }
    end

    def id_jag_authority_caveat?(cv)
      return false unless cv.is_a?(Hash)

      cv['type'] == IDJAG_AUTHORITY_CAVEAT && cv['scopes'].is_a?(Array) && cv['scopes'].all? { |s| s.is_a?(String) } && str(cv['aud'])
    end

    def id_jag_provenance_caveat?(cv)
      return false unless cv.is_a?(Hash)

      cv['type'] == IDJAG_PROVENANCE_CAVEAT && %w[iss sub agent aud].all? { |k| cv[k].is_a?(String) } && Js.num?(cv['iat']) && Js.num?(cv['exp'])
    end

    # cap?.caveats?.find(c => c?.type === type): a present non-array caveats member throws, as the reference.
    def read_caveat(cap, type)
      cavs = cap.is_a?(Hash) ? cap['caveats'] : nil
      return nil if cavs.nil?
      raise TypeError, 'cap.caveats.find is not a function' unless cavs.is_a?(Array)

      cavs.find { |c| c.is_a?(Hash) && c['type'] == type }
    end

    def read_id_jag_authority(cap) = read_caveat(cap, IDJAG_AUTHORITY_CAVEAT).then { |cv| cv && id_jag_authority_caveat?(cv) ? cv : nil }
    def read_id_jag_provenance(cap) = read_caveat(cap, IDJAG_PROVENANCE_CAVEAT).then { |cv| cv && id_jag_provenance_caveat?(cv) ? cv : nil }

    # ---- XAA request shapes ----

    # application/x-www-form-urlencoded (URLSearchParams): space is '+', only A-Z a-z 0-9 * - . _ stay literal.
    def form_encode(s) = Js.utf8(s).gsub(/[^A-Za-z0-9*\-._ ]/n) { |c| format('%%%02X', c.ord) }.tr(' ', '+').force_encoding('UTF-8')

    def form_request(url, params)
      clean = {}
      Js.js_keys(params).each { |k| clean[k] = params[k] if str(params[k]) }
      { 'url' => url, 'method' => 'POST', 'headers' => { 'content-type' => 'application/x-www-form-urlencoded', 'accept' => 'application/json' },
        'params' => clean, 'body' => Js.js_keys(clean).map { |k| "#{form_encode(k)}=#{form_encode(clean[k])}" }.join('&') }
    end

    # `scope` as the space-delimited OAuth form (nil when empty); a value that is neither a String nor an Array throws.
    def scope_param(scope)
      parts = scope.is_a?(Array) ? scope : (scope.is_a?(String) ? scope.split(WS_RE) : raise(TypeError, 'scope.split is not a function'))
      parts = parts.select { |s| str(s) }
      parts.empty? ? nil : parts.join(' ')
    end

    # The object spread of opts.extra (?? {}): a Hash's members, an Array's or String's indexed elements, nothing else.
    def spread_object(x)
      case x
      when Hash then x
      when Array then x.each_with_index.to_h { |v, i| [i.to_s, v] }
      when String then x.chars.each_with_index.to_h { |v, i| [i.to_s, v] }
      else {}
      end
    end

    # RFC 8693 token exchange that OBTAINS an ID-JAG. Options: token_endpoint, subject_token (required), subject_token_type,
    # actor_token, actor_token_type, audience, resource, scope, requested_token_type, client_id, extra.
    def token_exchange_request(o)
      raise TypeError, 'tokenExchangeRequest: opts is required' unless o.is_a?(Hash) || o.is_a?(Array)

      o = {} if o.is_a?(Array)
      raise TypeError, 'tokenExchangeRequest: opts.tokenEndpoint is required' unless str(o['token_endpoint'])
      raise TypeError, 'tokenExchangeRequest: opts.subjectToken is required' unless str(o['subject_token'])

      p = { 'grant_type' => GRANT_TYPE_TOKEN_EXCHANGE, 'subject_token' => o['subject_token'],
            'subject_token_type' => o['subject_token_type'].nil? ? TOKEN_TYPE_ID_TOKEN : o['subject_token_type'],
            'requested_token_type' => o['requested_token_type'].nil? ? TOKEN_TYPE_ID_JAG : o['requested_token_type'] }
      p['audience'] = o['audience'] if o.key?('audience')
      p['resource'] = o['resource'] if o.key?('resource')
      if o.key?('scope')
        s = scope_param(o['scope'])
        p['scope'] = s unless s.nil?
      end
      if str(o['actor_token'])
        p['actor_token'] = o['actor_token']
        p['actor_token_type'] = o['actor_token_type'].nil? ? TOKEN_TYPE_JWT : o['actor_token_type']
      end
      p['client_id'] = o['client_id'] if o.key?('client_id')
      form_request(o['token_endpoint'], p.merge(spread_object(o['extra'])))
    end

    # RFC 7523 jwt-bearer redemption of an ID-JAG: {grantType, assertion, scope?, request}. Options: token_endpoint, assertion
    # (required), scope, client_id, client_assertion, extra.
    def jwt_bearer_assertion(o)
      raise TypeError, 'jwtBearerAssertion: opts is required' unless o.is_a?(Hash) || o.is_a?(Array)

      o = {} if o.is_a?(Array)
      raise TypeError, 'jwtBearerAssertion: opts.tokenEndpoint is required' unless str(o['token_endpoint'])
      raise TypeError, 'jwtBearerAssertion: opts.assertion is required' unless str(o['assertion'])

      scope = o.key?('scope') ? scope_param(o['scope']) : nil
      p = { 'grant_type' => GRANT_TYPE_JWT_BEARER, 'assertion' => o['assertion'] }
      p['scope'] = scope if scope
      p['client_id'] = o['client_id'] if o.key?('client_id')
      if str(o['client_assertion'])
        p['client_assertion_type'] = CLIENT_ASSERTION_TYPE_JWT_BEARER
        p['client_assertion'] = o['client_assertion']
      end
      out = { 'grantType' => GRANT_TYPE_JWT_BEARER, 'assertion' => o['assertion'] }
      out['scope'] = scope if scope
      out['request'] = form_request(o['token_endpoint'], p.merge(spread_object(o['extra'])))
      out
    end
  end
end
