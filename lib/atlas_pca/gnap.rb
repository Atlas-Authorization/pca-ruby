# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require_relative 'js_compat'
require_relative 'jose'
require_relative 'whatwg_url'

# GNAP (RFC 9635) bridge for Proof-Carrying Authority, byte-identical to the TypeScript reference: access rights <-> PCA
# predicates, a grant request -> an attenuated, key-bound capability chain, action authorization over the chain, bound access
# tokens, the `jwsd` detached-JWS key proof (sign / verify with a replay store), continuation / step-up through threshold
# co-signatures, and the interaction modes (start modes, finish methods, the interaction hash, the AS state machine).
# Options and arguments are String-keyed Hashes in snake_case (wire members of GNAP messages keep their RFC names); a signing
# secret is the 32-byte Ed25519 seed (binary String); `now` is epoch milliseconds, except the interaction server's clock, which
# returns seconds. An absent key is a JavaScript `undefined`, a nil value a JSON null. Every verification fails closed.
module AtlasPca
  module Gnap
    # A malformed request on an issuance path (the verification paths return a refusal value instead). `code` mirrors the
    # platform error code where the reference surfaces one.
    class Error < StandardError
      attr_reader :code

      def initialize(msg = nil, code = nil)
        super(msg)
        @code = code
      end
    end

    # An interaction refusal with a stable `code`: invalid_interaction, unknown_interaction, too_many_attempts, invalid_request,
    # expired, wrong_state or unsupported_hash.
    class InteractionError < Error
      def initialize(code, msg) = super(msg, code)
    end

    UNDEF = Object.new.freeze # a JavaScript `undefined` read
    ABSENT = Object.new.freeze # gnap_content_digest(ABSENT): a request that carries no content

    GNAP_GRANT_CAVEAT = 'gnap_grant'
    GNAP_ACCESS_CAVEAT = 'gnap_access'
    GNAP_RESOURCE_PREFIX = 'gnap'
    MAX_DETACHED_JWS_CHARS = 8192
    JWSD_TYP = 'gnap-binding-jwsd'
    SIGNER_SET_DOMAIN = "atlas-pca/signerset/v1\x00".b.freeze
    ROLES = %w[agent guardian principal].freeze

    module_function

    def sha256(b) = OpenSSL::Digest::SHA256.digest(b)
    def b64u(b) = AtlasPca.b64e(b)

    # `o.k` in JavaScript: a read of null raises, a non-object has no members.
    def prop(o, k)
      raise TypeError, "Cannot read properties of null (reading '#{k}')" if o.nil?

      o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF
    end

    def obj?(x) = x.is_a?(Hash) || x.is_a?(Array)
    def defined(v) = v.equal?(UNDEF) ? nil : v
    def str_arr(u) = u.is_a?(Array) ? u.grep(String) : nil
    def as_ed25519(x) = x.is_a?(String) && !AtlasPca.b64d(x, 32).nil? ? x : nil
    def now_ms = (Time.now.to_f * 1000).floor

    # The PCA resource string for a GNAP (type, location) pair: gnap:<type>:<location>.
    def gnap_action_resource(type, location) = "#{GNAP_RESOURCE_PREFIX}:#{Js.string(type)}:#{Js.string(location)}"

    # ---- access rights ----

    def try_normalize_access_item(item)
      return item.empty? ? nil : { 'type' => item } if item.is_a?(String)
      return nil unless item.is_a?(Hash)

      type = item['type']
      return nil unless type.is_a?(String) && !type.empty?

      out = { 'type' => type }
      %w[actions locations datatypes].each do |k|
        v = str_arr(item[k])
        out[k] = v if v && !v.empty?
      end
      out['identifier'] = item['identifier'] if item['identifier'].is_a?(String)
      pr = str_arr(item['privileges'])
      out['privileges'] = pr if pr && !pr.empty?
      out
    end

    # Normalize an access array for issuance; raises Error on any malformed entry.
    def normalize_access(items)
      raise Error, 'access must be an array' unless items.is_a?(Array)

      items.map { |i| try_normalize_access_item(i) || raise(Error, 'malformed access item (needs a non-empty string `type`)') }
    end

    # A stored access array (signed caveats), read totally: malformed entries are skipped.
    def read_access_array(u) = u.is_a?(Array) ? u.filter_map { |i| try_normalize_access_item(i) } : []

    def nonempty?(v) = !v.nil? && v.respond_to?(:length) && v.length.positive?

    # One PCA predicate per location: `type` namespaces the resource, `actions` are the verbs, `datatypes` / `identifier` are
    # `where` conditions on the action params. Absent `actions` / `locations` mean any (verb `*` / the `*` resource).
    def access_to_predicates(access)
      verb = nonempty?(access['actions']) ? access['actions'].dup : '*'
      locations = nonempty?(access['locations']) ? access['locations'] : ['*']
      where = []
      where << { 'field' => 'action.params.datatype', 'op' => 'in', 'value' => access['datatypes'].dup } if nonempty?(access['datatypes'])
      where << { 'field' => 'action.params.identifier', 'op' => 'eq', 'value' => access['identifier'] } if access['identifier'].is_a?(String)
      locations.map do |loc|
        p = { 'verb' => verb.is_a?(Array) ? verb.dup : verb, 'resource' => gnap_action_resource(access['type'], loc) }
        p['where'] = where.map(&:dup) unless where.empty?
        p
      end
    end

    def access_array_to_predicates(access) = access.flat_map { |a| access_to_predicates(a) }

    def covers_strings?(sup, sub)
      return true if sup.nil? # the issuer allows all
      return false if sub.nil? # the request wants all, the issuer has a concrete set

      sub.all? { |s| sup.include?(s) }
    end

    def covers_locations?(sup, sub)
      return true if sup.nil?
      return sup.include?('*') if sub.nil?

      sub.all? { |s| sup.any? { |g| g == s || g == '*' || (g.end_with?('*') && s.start_with?(g[0...-1])) } }
    end

    # Does the issuer's granted right `g` fully contain the requested right `r`?
    def access_contains(g, r)
      return false unless g['type'] == r['type']
      return false unless covers_strings?(g['actions'], r['actions'])
      return false unless covers_locations?(g['locations'], r['locations'])
      return false unless covers_strings?(g['datatypes'], r['datatypes'])
      return false if !r['identifier'].nil? && !g['identifier'].nil? && g['identifier'] != r['identifier']

      true
    end

    def access_within(granted, r) = granted.any? { |g| access_contains(g, r) }

    # Split a requested access array into the subset within the issuer's authority and the rest.
    def clamp_access(issuer_granted, requested)
      granted, dropped = requested.partition { |r| access_within(issuer_granted, r) }
      { 'granted' => granted, 'dropped' => dropped }
    end

    # ---- provenance caveats ----

    def read_gnap_grant(root)
      env = AtlasPca.read_envelope(root)
      cv = env && env['caveats'].find { |c| c.is_a?(Hash) && c['type'] == GNAP_GRANT_CAVEAT }
      return nil unless cv

      client_id = cv['client_id']
      digest = cv['request_digest']
      return nil unless client_id.is_a?(String) && digest.is_a?(String)

      { 'type' => GNAP_GRANT_CAVEAT, 'client_id' => client_id, 'granted_access' => read_access_array(cv['granted_access']),
        'request_digest' => digest, 'interacted' => cv['interacted'] == true, 'ts' => Js.num?(cv['ts']) ? cv['ts'] : 0 }
    end

    # The effective granted access of a chain: the most recent delegated hop's recorded rights, or the root's.
    def granted_access_of(chain)
      return [] unless chain.is_a?(Array) && !chain.empty?

      caveats = prop(chain[-1], 'caveats')
      caveats = [] unless caveats.is_a?(Array)
      cv = caveats.reverse.find { |c| c.is_a?(Hash) && c['type'] == GNAP_ACCESS_CAVEAT }
      return read_access_array(cv['access']) if cv

      grant = read_gnap_grant(chain[0])
      grant ? grant['granted_access'] : []
    end

    # ---- holder resolution ----

    # The b64u Ed25519 holder key of a request's client key, or an explicit override (nil is an override and is refused). The
    # client key proof method must be `jwsd`: a declared other method is refused even with an override.
    def resolve_holder(req, holder_override = UNDEF)
      client = prop(req, 'client')
      declared = obj?(client) ? prop(client, 'key') : UNDEF
      if obj?(declared)
        proof = prop(declared, 'proof')
        method = if proof.is_a?(String) then proof
                 elsif proof.is_a?(Hash) then proof.fetch('method', UNDEF)
                 else UNDEF
                 end
        unless method == 'jwsd'
          raise Error, "unsupported client key proof method: #{method.is_a?(String) ? method : 'none'} (only jwsd is supported)"
        end
      end
      unless holder_override.equal?(UNDEF)
        return as_ed25519(holder_override) || raise(Error, 'holder override is not a canonical base64url Ed25519 public key')
      end

      key = declared
      if key.is_a?(Hash)
        jwk = key['jwk']
        if jwk.is_a?(Hash) && jwk['kty'] == 'OKP' && jwk['crv'] == 'Ed25519'
          x = as_ed25519(jwk['x'])
          return x if x
        end
      end
      raise Error, 'cannot resolve holder: supply client.key.jwk (OKP/Ed25519) or a holder override'
    end

    # The holder key rendered as a GNAP JWK.
    def holder_jwk(holder) = { 'kty' => 'OKP', 'crv' => 'Ed25519', 'x' => holder, 'use' => 'sig', 'alg' => 'EdDSA' }

    def access_of(req)
      at = prop(req, 'access_token')
      return at['access'] if at.is_a?(Hash) && at['access'].is_a?(Array)

      raise Error, 'grant request must carry access_token.access (single-token request)'
    end

    def request_digest_of(holder, granted, interact)
      AtlasPca.hash_canonical({ 'd' => 'atlas-pca/gnap/request/v1', 'client_id' => holder, 'access' => granted,
                                'interact' => defined(interact) })
    end

    # A root signer whose issuer id is the stated public key (as the reference takes opts.issuerPublic) and whose signature
    # comes from the issuer secret.
    StatedSigner = Struct.new(:public, :key) do
      def sign(msg) = key.sign(msg)
    end

    # Convert a GNAP grant request into a PCA capability bound to the client key and attenuated to never exceed the issuer.
    # With no `parent` this mints a root grant whose envelope predicates ARE the requested rights; with a `parent` it delegates
    # a narrower hop that records the clamped rights as an append-only `gnap_access` caveat. Options: issuer_secret, issuer_public,
    # parent, issuer_chain, clamp_to_issuer (default true), holder, interacted, now, and for a root grant goal, risk_policy,
    # agent_binding, salt. Returns {grant, chain, holder, granted_access, dropped_access, provenance}.
    def grant_request_to_capability(req, opts)
      holder = resolve_holder(req, opts.key?('holder') ? opts['holder'] : UNDEF)
      requested = normalize_access(access_of(req))
      now = opts['now'].nil? ? now_ms : opts['now']
      now = now.floor if now.finite? # a non-finite clock stays as it is (never a FloatDomainError)
      granted = requested
      dropped = []
      parent = opts['parent']
      issuer_chain = nil
      if Js.truthy?(parent)
        issuer_chain = opts['issuer_chain'].nil? ? [parent] : opts['issuer_chain']
        unless opts['clamp_to_issuer'] == false
          split = clamp_access(granted_access_of(issuer_chain), requested)
          granted = split['granted']
          dropped = split['dropped']
        end
      end
      request_digest = request_digest_of(holder, granted, prop(req, 'interact'))
      signer = KeyPair.new(opts['issuer_secret'])
      if Js.truthy?(parent)
        prov = { 'type' => GNAP_ACCESS_CAVEAT, 'access' => granted, 'predicates' => access_array_to_predicates(granted),
                 'request_digest' => request_digest, 'client_id' => holder, 'ts' => now }
        child = AtlasPca.delegate_cap(parent, signer, to_holder: holder, added: [prov])
        return { 'grant' => child, 'chain' => issuer_chain + [child], 'holder' => holder, 'granted_access' => granted,
                 'dropped_access' => dropped, 'provenance' => prov }
      end

      prov = { 'type' => GNAP_GRANT_CAVEAT, 'client_id' => holder, 'granted_access' => granted, 'request_digest' => request_digest,
               'interacted' => opts['interacted'] == true, 'ts' => now }
      principal = opts['issuer_public'].nil? ? signer : StatedSigner.new(opts['issuer_public'], signer)
      envelope = { 'predicates' => access_array_to_predicates(granted), 'caveats' => [prov],
                   'agent_binding' => opts['agent_binding'].nil? ? {} : opts['agent_binding'],
                   'risk_policy' => opts['risk_policy'].nil? ? AtlasPca::DEFAULT_RISK_POLICY : opts['risk_policy'] }
      goal = opts['goal'].nil? ? "gnap:grant:#{holder}" : opts['goal']
      grant = AtlasPca.mint_grant(principal, holder, envelope, goal, salt: opts['salt'])['grant']
      { 'grant' => grant, 'chain' => [grant], 'holder' => holder, 'granted_access' => granted, 'dropped_access' => dropped,
        'provenance' => prov }
    end

    # ---- action authorization ----

    def verify_chain_opts(chain, opts)
      AtlasPca.verify_chain(chain, opts['expected_root_issuer'], opts.key?('expected_root_issuer'), nil, opts['pq_pins'])
    end

    # Is `action` authorized by a GNAP-issued chain? The chain must verify, the root envelope must permit the action, and every
    # delegated hop's recorded rights must permit it too. Options: expected_root_issuer, pq_pins. Returns {allowed, reason?}.
    def authorize_gnap_action(chain, action, opts = {})
      return { 'allowed' => false, 'reason' => 'empty chain' } unless chain.is_a?(Array) && !chain.empty?

      reason, ok = verify_chain_opts(chain, opts || {})
      return { 'allowed' => false, 'reason' => "capability chain invalid: #{reason || 'unknown'}" } unless ok

      env = AtlasPca.read_envelope(chain[0])
      return { 'allowed' => false, 'reason' => 'root grant carries no policy envelope' } unless env

      act = {}
      %w[verb resource params reversibility_class].each do |k|
        v = prop(action, k)
        act[k] = v unless v.equal?(UNDEF)
      end
      ctx = { 'action' => act }
      d = AtlasPca.evaluate_predicates(env['predicates'], ctx)
      return { 'allowed' => false, 'reason' => "root authority denies: #{d['reason'] || 'no predicate matched'}" } unless d['allowed']

      caveats = prop(chain[-1], 'caveats')
      (caveats.is_a?(Array) ? caveats : []).each do |cv|
        next unless cv.is_a?(Hash) && cv['type'] == GNAP_ACCESS_CAVEAT

        hop = AtlasPca.evaluate_predicates(access_array_to_predicates(read_access_array(cv['access'])), ctx)
        return { 'allowed' => false, 'reason' => "delegated hop denies: #{hop['reason'] || 'no predicate matched'}" } unless hop['allowed']
      end
      { 'allowed' => true }
    end

    # ---- bound token ----

    # A capability chain as a GNAP access-token value: base64url(JSON.stringify(chain)).
    def encode_bound_token(chain) = b64u(Js.utf8(Js.json(chain)))

    def capability_shape?(x)
      x.is_a?(Hash) && %w[id issuer holder body_digest sig].all? { |k| x[k].is_a?(String) } && x['caveats'].is_a?(Array) &&
        %w[parent alg pq_pk pq_sig].all? { |k| !x.key?(k) || x[k].is_a?(String) }
    end

    # A bound token back into a chain; nil on any deviation (a leading byte-order mark is dropped, as the platform decoder does).
    def decode_bound_token(value)
      raw = AtlasPca.b64d(value)
      return nil if raw.nil?

      text = raw.force_encoding('UTF-8')
      return nil unless text.valid_encoding?

      text = text[1..] if text.start_with?("﻿")
      parsed = AtlasPca.parse_json(text, any_top: true)
      parsed.is_a?(Array) && parsed.all? { |h| capability_shape?(h) } ? parsed : nil
    rescue StandardError
      nil
    end

    # Render a (verified) chain as a GNAP grant response with a bound access token. Options: expires_in, bearer, instance_id,
    # manage_uri, continue (a continuation handle); a present key counts even when its value is nil, as in the reference.
    def capability_to_grant_response(chain, opts = {})
      opts ||= {}
      raise Error, 'capabilityToGrantResponse: empty chain' unless chain.is_a?(Array) && !chain.empty?

      token = { 'value' => encode_bound_token(chain), 'access' => granted_access_of(chain),
                'key' => opts['bearer'] == true ? false : holder_jwk(defined(prop(chain[-1], 'holder'))) }
      token['expires_in'] = opts['expires_in'] if opts.key?('expires_in')
      token['manage'] = { 'uri' => opts['manage_uri'] } if opts.key?('manage_uri')
      out = { 'access_token' => token }
      out['continue'] = opts['continue'] if opts.key?('continue')
      out['instance_id'] = opts['instance_id'] if opts.key?('instance_id')
      out
    end

    # Verify an incoming bound token back to a PCA principal + capability. Fails closed. Options: expected_root_issuer, pq_pins.
    def verify_gnap_token(value, opts = {})
      opts ||= {}
      return { 'ok' => false, 'reason' => 'token value is empty' } unless value.is_a?(String) && !value.empty?

      chain = decode_bound_token(value)
      return { 'ok' => false, 'reason' => 'token is not a decodable PCA capability chain' } if chain.nil? || chain.empty?

      reason, ok = verify_chain_opts(chain, opts)
      return { 'ok' => false, 'reason' => "capability chain invalid: #{reason || 'unknown'}" } unless ok

      { 'ok' => true, 'principal' => chain[0]['issuer'], 'capability' => chain[-1], 'chain' => chain, 'access' => granted_access_of(chain) }
    end

    # ---- jwsd: key-bound requests ----

    def ath_of(token) = b64u(sha256(Js.utf8(Js.string(token))))

    # The jwsd JWS payload (RFC 9635 7.3.3): SHA-256 of the request CONTENT, or nothing when there is none (ABSENT). A String
    # (text, or binary bytes) is the exact content; any other value is hashed as its strict canonical JSON.
    def gnap_content_digest(body = ABSENT)
      return ''.b if body.equal?(ABSENT)
      return sha256(Js.utf8(body)) if body.is_a?(String)

      sha256(AtlasPca.canon_bytes(Js.parse(Js.json(body))))
    end

    # A GNAP `jwsd` detached-JWS proof over `body`, signed by the client key. Arguments: body (omit for no content), key
    # ({'secret_key' => 32-byte seed, 'public_key' => 32 bytes}), htm, uri, created (epoch SECONDS, default now), kid,
    # access_token_value. Returns {detached_jws, header, holder}.
    def sign_gnap_request(args)
      created = args['created'].nil? ? Time.now.to_i : args['created']
      key = args['key']
      holder = b64u(key['public_key'])
      header = { 'alg' => 'EdDSA', 'typ' => JWSD_TYP, 'htm' => args['htm'].upcase, 'uri' => args['uri'], 'created' => created }
      header['kid'] = args['kid'] if args.key?('kid')
      header['ath'] = ath_of(args['access_token_value']) if args.key?('access_token_value')
      payload = gnap_content_digest(args.key?('body') ? args['body'] : ABSENT)
      protected_b64 = b64u(Js.utf8(Js.json(header)))
      seed = key['secret_key']
      raise Error.new('Invalid JWK OKP key', 'ERR_CRYPTO_INVALID_JWK') unless seed.is_a?(String) && seed.bytesize == 32

      sig = KeyPair.new(seed).sign("#{protected_b64}.#{b64u(payload)}")
      { 'detached_jws' => "#{protected_b64}..#{b64u(sig)}", 'header' => header, 'holder' => holder }
    end

    # The JOSE library's flattened-verify header rules that apply here: `crit` (only b64 is recognised), a boolean b64, an alg.
    def jws_header_ok!(header)
      if header.key?('crit')
        crit = header['crit']
        raise ArgumentError, 'crit' if !crit.is_a?(Array) || crit.empty? || crit.any? { |c| !c.is_a?(String) || c.empty? }
        raise ArgumentError, 'crit' if crit.any? { |p| p != 'b64' || !header.key?('b64') }
        raise ArgumentError, 'b64' unless [true, false].include?(header['b64'])
      end
      raise ArgumentError, 'alg' unless header['alg'].is_a?(String) && !header['alg'].empty?
    end

    def canonical_reason(e) = e.reason == 'empty-segment' ? 'non-canonical compact JWS: empty-segment' : e.message

    # Verify a `jwsd` detached-JWS proof and bind the request to the holder key. Fails closed on a bad signature, a tampered
    # body, a wrong holder, a mismatched htm / uri, a stale or future `created`, an `ath` that does not bind the named token, or
    # a replay. Arguments: detached_jws, body (omit for no content), holder, htm, uri, max_age_sec (300), now (ms),
    # access_token_value, and a replay store `seen_proof` (callable (proof_id, expires_sec) -> true when already seen), REQUIRED
    # unless replay_check == 'unchecked' (without either this raises Error). Returns {ok: true, holder, header} or {ok: false, reason}.
    def verify_gnap_request(args)
      seen_proof = args['seen_proof']
      store = seen_proof.respond_to?(:call)
      if !store && args['replay_check'] != 'unchecked'
        raise Error, "verifyGnapRequest: supply args.seen_proof (a replay store) or set args.replay_check to 'unchecked'"
      end

      fail_with = ->(r) { { 'ok' => false, 'reason' => r } }
      detached = args['detached_jws']
      return fail_with.('detached JWS exceeds the size limit') if detached.is_a?(String) && Js.len16(detached) > MAX_DETACHED_JWS_CHARS

      begin
        parts = detached.split('.', -1)
        return fail_with.('not a compact JWS (expected three dot-separated parts)') unless parts.length == 3

        protected_b64, mid, signature = parts
        holder = as_ed25519(args['holder'])
        return fail_with.('holder is not a canonical base64url Ed25519 public key') if holder.nil?

        payload_b64 = b64u(gnap_content_digest(args.key?('body') ? args['body'] : ABSENT))
        return fail_with.('not a DETACHED compact JWS') unless mid.empty? || mid == payload_b64

        begin
          header = Jose.assert_canonical_jws_segments(protected_b64, signature) # the canonical gate BEFORE the signature check
        rescue Jose::CanonicalJwsError => e
          return fail_with.("non-canonical detached JWS: #{canonical_reason(e)}")
        end
        begin
          jws_header_ok!(header)
          raise ArgumentError, 'alg' unless header['alg'] == 'EdDSA'
          raise ArgumentError, 'signature' unless AtlasPca.verify_b64u(holder, "#{protected_b64}.#{payload_b64}", signature)
        rescue StandardError
          return fail_with.('jwsd signature does not verify under the holder key (or body was tampered)')
        end
        return fail_with.('unexpected typ (not gnap-binding-jwsd)') unless header['typ'] == JWSD_TYP

        htm = header['htm']
        return fail_with.('htm does not match the request method') if !htm.is_a?(String) || htm.upcase != args['htm'].upcase

        uri = header['uri']
        return fail_with.('uri does not match the request target') if !uri.is_a?(String) || uri != args['uri']

        created = header['created']
        return fail_with.('missing or malformed created') unless Js.num?(created) && created.to_f.finite?

        now = args['now'].nil? ? now_ms : args['now']
        now_sec = now.is_a?(Integer) ? now.div(1000) : ((f = now / 1000.0).finite? ? f.floor : f)
        max_age = args['max_age_sec'].nil? ? 300 : args['max_age_sec']
        return fail_with.('created is in the future') unless now_sec.to_f.finite? && created <= now_sec + 60
        return fail_with.('jwsd proof is stale') unless Js.num?(max_age) && max_age.to_f.finite? && now_sec - created <= max_age

        ath = header['ath']
        if args.key?('access_token_value') && (!ath.is_a?(String) || ath != ath_of(args['access_token_value']))
          return fail_with.('ath does not bind the named access token')
        end

        if store
          replayed = begin
            seen_proof.call(ath_of(detached), created + max_age) != false
          rescue StandardError
            true # a store failure refuses
          end
          return fail_with.('jwsd proof replayed (or the replay store failed)') if replayed
        end
        out = { 'alg' => 'EdDSA', 'typ' => JWSD_TYP, 'htm' => htm, 'uri' => uri, 'created' => created }
        out['kid'] = header['kid'] if header['kid'].is_a?(String)
        out['ath'] = ath if ath.is_a?(String)
        { 'ok' => true, 'holder' => holder, 'header' => out }
      rescue StandardError
        fail_with.('malformed jwsd request')
      end
    end

    # ---- threshold shares (the step-up co-signature carrier) ----

    def valid_t?(t) = Js.num?(t) && [1, 2, 3].include?(t)

    # The signer-set hash exactly as the reference computes it, lenient on a malformed set (it hashes what is there).
    def lenient_signer_set_hash(signer_set)
      rows = (signer_set.is_a?(Array) ? signer_set : []).map do |s|
        h = s.is_a?(Hash)
        row = { 'publicKey' => h && s.key?('publicKey') ? Js.string(s['publicKey']) : 'undefined',
                'role' => h && s.key?('role') ? Js.string(s['role']) : 'undefined' }
        row['pq_pk'] = s['pq_pk'] if h && s['pq_pk'].is_a?(String)
        row
      end
      rows.sort_by! { |r| [r['role'].b, r['publicKey'].b] }
      sha256(SIGNER_SET_DOMAIN + AtlasPca.strict_bytes(rows))
    end

    def share_message(role, message, signer_set, t, alg = nil)
      raise ArgumentError, 'shareMessage: t must be 1, 2 or 3' unless valid_t?(t)

      tag = alg.is_a?(String) && alg != 'ed25519' && AtlasPca::REGISTERED_SUITES.include?(alg) ? "\x00atlas-pca/share-suite/v1\x00#{alg}".b : ''.b
      AtlasPca::Js.utf8("atlas-pca/share/#{Js.string(role)}\x00") + sha256(message) + lenient_signer_set_hash(signer_set) + [t.to_i].pack('C') + tag
    end

    def sign_share(role, secret, message, signer_set, t)
      msg = share_message(role, message, signer_set, t)
      raise ArgumentError, 'an Ed25519 secret is a 32-byte seed' unless secret.is_a?(String) && secret.bytesize == 32

      kp = KeyPair.new(secret)
      { 'role' => role, 'publicKey' => kp.public, 'sig' => b64u(kp.sign(msg)) }
    end

    def pq_pk?(v)
      raw = v.is_a?(String) ? AtlasPca.b64d(v) : nil
      !raw.nil? && AtlasPca::PQ_PK_LENGTHS.include?(raw.bytesize)
    end

    def show(v)
      return '<array>' if v.is_a?(Array)
      return '<object>' if v.is_a?(Hash)

      Js.string(v)
    end

    # A t-of-n multi-signature check: the signer set is validated first (known roles, one key per role, one role per key,
    # well-formed keys), then the DISTINCT registered keys with a valid role / signer-set / t-bound share are counted. Returns
    # {ok, count, roles, reason?}. Deterministic and total.
    def verify_threshold(sig, message, signer_set, t)
      bad = ->(r) { { 'ok' => false, 'count' => 0, 'roles' => [], 'reason' => r } }
      return bad.("invalid threshold t=#{show(t)} (must be 1, 2 or 3)") unless valid_t?(t)

      tt = t.to_i
      reg = {}
      pq_of_role = {}
      seen_entry = {}
      (signer_set.is_a?(Array) ? signer_set : []).each do |s|
        h = s.is_a?(Hash)
        role = h && s['role'].is_a?(String) && ROLES.include?(s['role']) ? s['role'] : nil
        key_ok = h && !AtlasPca.b64d(s['publicKey'], 32).nil?
        pq_ok = !Js.truthy?(s) || !h || !s.key?('pq_pk') || pq_pk?(s['pq_pk'])
        if role && key_ok && pq_ok
          ident = [role, s['publicKey']]
          pq = s['pq_pk'].is_a?(String) ? s['pq_pk'] : nil
          if seen_entry.key?(ident) && seen_entry[ident] != pq
            pq_ok = false
          else
            seen_entry[ident] = pq
          end
        end
        return bad.('malformed signer set') if role.nil? || !key_ok
        return bad.('malformed signer set (pq_pk)') unless pq_ok
        return bad.("signer set registers more than one key for role #{show(s['role'])}") if reg.key?(role) && reg[role] != s['publicKey']

        key_role = reg.key(s['publicKey'])
        return bad.('signer set registers one key under two roles') if key_role && key_role != role

        next if reg.key?(role)

        reg[role] = s['publicKey']
        pq_of_role[role] = s['pq_pk'].is_a?(String) ? s['pq_pk'] : nil
      end
      shares = sig.is_a?(Hash) && sig['shares'].is_a?(Array) ? sig['shares'] : []
      keys = []
      roles = []
      reason = nil
      shares.each do |share|
        unless share.is_a?(Hash) && share['role'].is_a?(String) && share['publicKey'].is_a?(String)
          reason ||= 'malformed share'
          next
        end
        next if keys.include?(share['publicKey'])

        role = ROLES.include?(share['role']) ? share['role'] : nil
        reg_key = role && reg[role]
        if reg_key.nil?
          reason ||= "role #{show(share['role'])} is not in the signer set"
          next
        end
        if reg_key != share['publicKey']
          reason ||= "share for role #{show(share['role'])} uses a key not registered for that role"
          next
        end
        alg = share['alg']
        if share.key?('alg') && !(alg.is_a?(String) && AtlasPca::REGISTERED_SUITES.include?(alg))
          reason ||= "share for role #{show(share['role'])} declares an unknown signature alg"
          next
        end
        if share.key?('pq_pk') && !(share['pq_pk'].is_a?(String) && share['pq_pk'] == pq_of_role[role])
          reason ||= "share for role #{show(share['role'])} names a pq_pk that is not the key its role registers"
          next
        end
        good = begin
          signed = share_message(share['role'], message, signer_set, tt, alg)
          registered = pq_of_role[role]
          if alg.nil? || alg == 'ed25519'
            registered.nil? && share['sig'].is_a?(String) && AtlasPca.verify_b64u(share['publicKey'], signed, share['sig'])
          else
            !registered.nil? && AtlasPca.verify_leaf_suite(share.merge('pq_pk' => registered), share['publicKey'], signed)
          end
        rescue StandardError
          false
        end
        unless good
          reason ||= "invalid signature for role #{show(share['role'])}"
          next
        end
        keys << share['publicKey']
        roles << role
      end
      return { 'ok' => true, 'count' => keys.length, 'roles' => roles } if keys.length >= tt

      { 'ok' => false, 'count' => keys.length, 'roles' => roles,
        'reason' => reason || "only #{keys.length} distinct valid key(s), need #{show(t)}" }
    end

    # ---- continuation -> step-up ----

    # Does a grant request need a continuation / step-up: when interaction is requested, a higher tier is asked for, or (given
    # the issuer's chain) it asks for rights BEYOND the issuer's own authority. Options: issuer_chain, tier. Returns
    # {required, reason, beyond, tier}.
    def gnap_request_requires_step_up(req, opts = {})
      opts ||= {}
      beyond = []
      if Js.truthy?(opts['issuer_chain'])
        granted = granted_access_of(opts['issuer_chain'])
        normalize_access(access_of(req)).each { |r| beyond << r unless access_within(granted, r) }
      end
      interact = prop(req, 'interact')
      interact_requested = false
      unless interact.equal?(UNDEF)
        start = prop(interact, 'start')
        interact_requested = start.is_a?(Array) && !start.empty?
      end
      tier_in = opts['tier']
      tier_gt1 = Js.num?(tier_in) && tier_in > 1
      required = interact_requested || !beyond.empty? || tier_gt1
      tier = tier_in.nil? ? (beyond.empty? ? 2 : 3) : tier_in
      reason = if !required then 'no step-up required'
               elsif !beyond.empty? then "requested rights exceed the issuer's authority (#{beyond.length} right(s) beyond)"
               elsif interact_requested then 'GNAP interaction requested'
               else "tier #{Js.string(tier)} step-up required"
               end
      { 'required' => required, 'reason' => reason, 'beyond' => beyond, 'tier' => tier }
    end

    # Begin a GNAP continuation: the `continue` handle (a grant response with no token yet) and the step-up it resolves through.
    # Arguments: signer_set, t, tier, continue_uri, continue_token, wait, reason. Returns {response, step_up}.
    def begin_gnap_continuation(args)
      cont = { 'uri' => args['continue_uri'], 'access_token' => { 'value' => args['continue_token'], 'bound' => true } }
      cont['wait'] = args['wait'] if args.key?('wait')
      reason = args['reason'].nil? ? "tier #{Js.string(args['tier'])} co-signature required to continue" : args['reason']
      { 'response' => { 'continue' => cont },
        'step_up' => { 'tier' => args['tier'], 't' => args['t'], 'signer_set' => args['signer_set'], 'reason' => reason,
                       'continue_token' => args['continue_token'] } }
    end

    # One role's step-up co-signature share over the action's PCActn body (bound to the signer set and `t`).
    def gnap_step_up_share(body, role, secret, signer_set, t) = sign_share(role, secret, AtlasPca.threshold_message(body), signer_set, t)

    # Resolve a continuation: build the action's PCActn (the agent leaf signature), fold the step-up co-signatures into its
    # `threshold`, and verify the threshold `t` is reached. Arguments: grant, chain, plan, node_id, params, counter, aud, now,
    # ttl_ms, agent_leaf_secret (seed), signer_set, t, cosign_secrets ([{role, secret}]). Returns {pcactn, threshold, verdict}.
    def complete_gnap_continuation(args)
      chain = args['chain']
      raise Error, 'completeGnapContinuation: empty chain' unless chain.is_a?(Array) && !chain.empty?

      kw = {}
      kw[:params] = args['params'] if args.key?('params')
      kw[:iat] = args['now'] if args.key?('now')
      kw[:ttl_ms] = args['ttl_ms'] unless args['ttl_ms'].nil?
      pcactn = AtlasPca.build_pcactn(grant: args['grant'], chain: chain, plan: args['plan'], node_id: args['node_id'],
                                     counter: args['counter'], signer: KeyPair.new(args['agent_leaf_secret']), aud: args['aud'], **kw)
      message = AtlasPca.threshold_message(pcactn)
      shares = [sign_share('agent', args['agent_leaf_secret'], message, args['signer_set'], args['t'])] +
               args['cosign_secrets'].map { |cs| sign_share(cs['role'], cs['secret'], message, args['signer_set'], args['t']) }
      threshold = { 'shares' => shares }
      { 'pcactn' => pcactn.merge('threshold' => threshold), 'threshold' => threshold,
        'verdict' => verify_threshold(threshold, message, args['signer_set'], args['t']) }
    end

    # ---- interaction modes (RFC 9635 sections 2.5, 3.3, 4, 5.1) ----

    START_MODES = %w[redirect app user_code user_code_uri].freeze
    FINISH_METHODS = %w[redirect push].freeze
    HASH_METHODS = { 'sha-256' => 'SHA256', 'sha-384' => 'SHA384', 'sha-512' => 'SHA512', 'sha3-256' => 'SHA3-256',
                     'sha3-512' => 'SHA3-512' }.freeze
    # the names a JavaScript `in` test on the reference's method table also finds (it inherits them from Object.prototype)
    OBJECT_PROTO = %w[constructor __defineGetter__ __defineSetter__ hasOwnProperty __lookupGetter__ __lookupSetter__
                      isPrototypeOf propertyIsEnumerable toString valueOf __proto__ toLocaleString].freeze
    USER_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

    def in_hash_methods?(v)
      k = Js.string(v)
      HASH_METHODS.key?(k) || OBJECT_PROTO.include?(k)
    end

    def start_name(e)
      return e if e.is_a?(String)

      e.is_a?(Hash) && e['mode'].is_a?(String) ? e['mode'] : nil
    end

    # RFC 9635 2.5.2: an absolute URI without a fragment; HTTPS, a loopback HTTP host, or an application-specific scheme.
    def callback_uri_ok(uri)
      return false unless uri.is_a?(String) && Js.len16(uri) <= 2048

      u = WhatwgUrl.parse(uri)
      return false if u.nil? || uri.include?('#')
      return true if u['scheme'] == 'https'

      if u['scheme'] == 'http'
        host = u['host']
        hostname = host.start_with?('[') ? host[0..host.index(']')] : host.split(':')[0]
        return %w[localhost 127.0.0.1 [::1]].include?(hostname)
      end
      !%w[javascript data file blob].include?(u['scheme'])
    end

    # Validate an `interact` request; returns the problems (empty = valid). Unknown start modes are tolerated.
    def validate_interact_request(r)
      return ['interact must be an object'] unless r.is_a?(Hash)

      e = []
      start = r['start']
      if !start.is_a?(Array) || start.empty? || start.length > 16
        e << 'start must be a non-empty array of modes'
      else
        start.each { |s| e << 'each start entry is a mode name or an object with a mode' if start_name(s).nil? }
      end
      if r.key?('finish')
        f = r['finish']
        if obj?(f)
          m = ->(k) { f.is_a?(Hash) && f.key?(k) ? f[k] : UNDEF }
          e << 'finish.method must be redirect or push' unless m.('method').is_a?(String) && FINISH_METHODS.include?(m.('method'))
          e << 'finish.uri must be an absolute https, loopback or app-scheme URI without a fragment' unless callback_uri_ok(m.('uri'))
          n = m.('nonce')
          unless n.is_a?(String) && Js.len16(n) >= 8 && Js.len16(n) <= 256 && n.valid_encoding? && n.match?(/\A[\x21-\x7e]+\z/)
            e << 'finish.nonce must be 8..256 printable ASCII characters'
          end
          hm = m.('hash_method')
          e << 'finish.hash_method is not a supported Named Information hash' if !hm.equal?(UNDEF) && !in_hash_methods?(hm)
        else
          e << 'finish must be an object'
        end
      end
      e
    end

    # Node's 'ascii' input encoding: the low byte of each UTF-16 code unit (a lone surrogate in WTF-8 is one unit).
    def ascii_bytes(s)
      s.b.scan(/[\x00-\x7f]|[\xc0-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xf7][\x80-\xbf]{3}|./nm).flat_map do |c|
        b = c.bytes
        cp = case b.length
             when 1 then b[0]
             when 2 then ((b[0] & 0x1f) << 6) | (b[1] & 0x3f)
             when 3 then ((b[0] & 0x0f) << 12) | ((b[1] & 0x3f) << 6) | (b[2] & 0x3f)
             else ((b[0] & 0x07) << 18) | ((b[1] & 0x3f) << 12) | ((b[2] & 0x3f) << 6) | (b[3] & 0x3f)
             end
        cp > 0xffff ? [(0xd800 + ((cp - 0x10000) >> 10)) & 0xff, (0xdc00 + ((cp - 0x10000) & 0x3ff)) & 0xff] : [cp & 0xff]
      end.pack('C*')
    end

    def field(a, k) = a.key?(k) ? Js.string(a[k]) : 'undefined'

    # RFC 9635 4.2.3: base64url (no padding) of HASH(client_nonce \n as_nonce \n interact_ref \n grant_endpoint). Arguments:
    # client_nonce, as_nonce, interact_ref, grant_endpoint, hash_method (default sha-256).
    def interaction_hash(a)
      m = a['hash_method'].nil? ? 'sha-256' : a['hash_method']
      raise InteractionError.new('unsupported_hash', "hash_method #{Js.string(m)} is not supported") unless in_hash_methods?(m)

      key = Js.string(m)
      # an inherited Object.prototype member passes the reference's `in` test, then is no algorithm name
      raise Error.new("hash_method #{key} is not a hash algorithm", 'ERR_INVALID_ARG_TYPE') unless HASH_METHODS.key?(key)

      text = "#{field(a, 'client_nonce')}\n#{field(a, 'as_nonce')}\n#{field(a, 'interact_ref')}\n#{field(a, 'grant_endpoint')}"
      b64u(OpenSSL::Digest.new(HASH_METHODS[key]).digest(ascii_bytes(text)))
    end

    # Client side: does the callback's `hash` match? Constant time; a non-validating hash means the interact_ref MUST NOT be sent.
    def verify_interaction_hash(received, a)
      return false unless received.is_a?(String)

      want = interaction_hash(a).b
      got = Js.utf8(received)
      want.bytesize == got.bytesize && OpenSSL.fixed_length_secure_compare(want, got)
    end

    # 6..12 characters from an alphabet without look-alikes (random; 256 % 32 == 0, so no modulo bias).
    def new_user_code(length = 8)
      raise ArgumentError, 'user code length 6..12' unless Js.num?(length) && length >= 6 && length <= 12

      SecureRandom.random_bytes(length.to_i).bytes.map { |b| USER_CODE_ALPHABET[b % 32] }.join
    end

    def norm_code(c) = c.gsub(/[#{Js::WS}-]/o, '').upcase

    # One interaction's state. #to_h is the wire-style view (camelCase members, only the members that are set).
    class Interaction
      attr_accessor :id, :state, :grant_endpoint, :modes, :finish, :user_code, :interact_ref, :ref_used, :expires_at

      def initialize(id, grant_endpoint, modes, expires_at)
        @id = id
        @state = 'pending'
        @grant_endpoint = grant_endpoint
        @modes = modes
        @finish = nil # {method, uri, client_nonce, as_nonce, hash_method}
        @user_code = nil
        @interact_ref = nil
        @ref_used = false
        @expires_at = expires_at
      end

      def to_h
        d = { 'id' => @id, 'state' => @state, 'grantEndpoint' => @grant_endpoint, 'modes' => @modes.dup }
        if @finish
          f = @finish
          d['finish'] = { 'method' => f['method'], 'uri' => f['uri'], 'clientNonce' => f['client_nonce'], 'asNonce' => f['as_nonce'],
                          'hashMethod' => f['hash_method'] }
        end
        d['userCode'] = @user_code unless @user_code.nil?
        d['interactRef'] = @interact_ref unless @interact_ref.nil?
        d['refUsed'] = @ref_used
        d['expiresAt'] = @expires_at
        d
      end
    end

    FORM_KEEP = /[*\-._0-9A-Za-z]/n
    USERINFO_ENC = "\"#<>?`{}/:;=@[\\]^|"

    def form_decode(s) = WhatwgUrl.pct_decode(s.tr('+', ' ')).force_encoding('UTF-8').scrub("�")

    def form_encode(s)
      Js.utf8(s).bytes.map { |b| c = b.chr; c.match?(FORM_KEEP) ? c : (b == 0x20 ? '+' : format('%%%02X', b)) }.join
    end

    # `u = new URL(uri); u.searchParams.set('hash', ..); u.searchParams.set('interact_ref', ..); u.toString()` for a URI that
    # callback_uri_ok accepted (so no fragment): the URL is re-serialized and its query rebuilt as application/x-www-form-urlencoded.
    def redirect_url(uri, hash, ref)
      d = WhatwgUrl.parse(uri) or raise ArgumentError, 'invalid URL'
      s = uri.sub(/\A[\x00-\x20]+/, '').sub(/[\x00-\x20]+\z/, '').delete("\t\n\r")
      rest = s[s.match(/\A[A-Za-z][A-Za-z0-9+.\-]*:/).end(0)..]
      q = rest.index('?')
      raw_q = q ? rest[(q + 1)..] : nil
      body = q ? rest[0, q] : rest
      scheme = d['scheme']
      special = WhatwgUrl::SPECIAL.key?(scheme)
      authority = nil
      if special
        body = body.sub(%r{\A[/\\]+}, '')
        cut = body.index(%r{[/\\]})
        authority, path = cut ? [body[0, cut], body[cut..]] : [body, '']
      elsif body.start_with?('//')
        inner = body[2..]
        cut = inner.index('/')
        authority, path = cut ? [inner[0, cut], inner[cut..]] : [inner, '']
      else
        path = body
      end
      out = "#{scheme}:"
      unless authority.nil?
        out += '//'
        if authority.include?('@')
          user, _, pw = authority.rpartition('@')[0].partition(':')
          user = WhatwgUrl.pct(user, USERINFO_ENC)
          pw = WhatwgUrl.pct(pw, USERINFO_ENC)
          out += user + (pw.empty? ? '' : ":#{pw}") + '@' unless user.empty? && pw.empty?
        end
        out += d['host']
      end
      out += d['pathname'] unless !authority.nil? && !special && path.empty?
      pairs = (raw_q || '').split('&').reject(&:empty?).map do |seg|
        n, _, v = seg.partition('=')
        [form_decode(n), form_decode(v)]
      end
      [['hash', hash], ['interact_ref', ref]].each do |name, value|
        hit = pairs.find { |p| p[0] == name }
        if hit
          hit[1] = value
          pairs = pairs.reject { |p| !p.equal?(hit) && p[0] == name }
        else
          pairs << [name, value]
        end
      end
      "#{out}?#{pairs.map { |n, v| "#{form_encode(n)}=#{form_encode(v)}" }.join('&')}"
    end

    # The authorization-server side of GNAP interaction. The response never includes a mode the client did not ask for nor one
    # the AS does not support (RFC 9635 3.3), and each interact_ref is single use: a second presentation is `too_many_attempts`
    # and finalizes the grant. Options: grant_endpoint, supports, redirect_uri (callable id -> uri), app_uri (callable)?,
    # user_code_uri?, ttl_sec?, now (callable -> seconds).
    class InteractionServer
      def initialize(opts)
        @o = opts
        @by_id = {}
        @by_code = {}
        @by_ref = {}
      end

      def now = @o['now'].call

      # Fail closed: a non-finite clock or expiry reads as expired.
      def expired?(it)
        t = now
        !(Js.num?(t) && t.to_f.finite? && Js.num?(it.expires_at) && it.expires_at.to_f.finite? && t <= it.expires_at)
      end

      def start(req)
        problems = Gnap.validate_interact_request(req)
        raise InteractionError.new('invalid_request', problems.join('; ')) unless problems.empty?

        asked = req['start'].map { |e| Gnap.start_name(e) }
        modes = @o['supports'].select do |m|
          asked.include?(m) && (m != 'app' || @o['app_uri']) && (m != 'user_code_uri' || @o['user_code_uri'])
        end
        has_finish = Js.truthy?(req['finish'])
        raise InteractionError.new('invalid_interaction', 'no requested interaction mode is supported') if modes.empty? && !has_finish

        id = Gnap.b64u(SecureRandom.random_bytes(16))
        ttl = @o['ttl_sec'].nil? ? 600 : @o['ttl_sec']
        it = Interaction.new(id, @o['grant_endpoint'], modes, now + ttl)
        res = { 'expires_in' => ttl }
        res['redirect'] = @o['redirect_uri'].call(id) if modes.include?('redirect')
        res['app'] = @o['app_uri'].call(id) if modes.include?('app')
        if modes.include?('user_code') || modes.include?('user_code_uri')
          it.user_code = Gnap.new_user_code
          @by_code[it.user_code] = id
          res['user_code'] = it.user_code if modes.include?('user_code')
          res['user_code_uri'] = { 'code' => it.user_code, 'uri' => @o['user_code_uri'] } if modes.include?('user_code_uri')
        end
        if has_finish
          f = req['finish']
          as_nonce = Gnap.b64u(SecureRandom.random_bytes(24))
          hm = f['hash_method']
          it.finish = { 'method' => f['method'], 'uri' => f['uri'], 'client_nonce' => f['nonce'], 'as_nonce' => as_nonce,
                        'hash_method' => hm.nil? ? 'sha-256' : hm }
          res['finish'] = as_nonce
        end
        @by_id[id] = it
        { 'interaction' => it, 'response' => res }
      end

      # The resource owner typed a code (case-insensitive). A 32^8 code space is only safe behind a per-source rate limit on
      # this lookup: the caller MUST apply one.
      def lookup_user_code(code)
        id = @by_code[Gnap.norm_code(code)]
        it = id && @by_id[id]
        return nil if it.nil? || it.state != 'pending' || expired?(it)

        it
      end

      def get(id) = @by_id[id]

      # The resource owner approved. Returns {interact_ref, finish?}: finish is {method: 'redirect', url} or
      # {method: 'push', uri, body: {hash, interact_ref}}, absent without a finish method.
      def approve(id)
        it = live(id)
        raise InteractionError.new('wrong_state', "interaction is #{it.state}") unless it.state == 'pending'

        it.state = 'approved'
        it.interact_ref = Gnap.b64u(SecureRandom.random_bytes(18))
        @by_ref[it.interact_ref] = id
        @by_code.delete(it.user_code) if it.user_code
        return { 'interact_ref' => it.interact_ref } if it.finish.nil?

        f = it.finish
        h = Gnap.interaction_hash({ 'client_nonce' => f['client_nonce'], 'as_nonce' => f['as_nonce'], 'interact_ref' => it.interact_ref,
                                    'grant_endpoint' => it.grant_endpoint, 'hash_method' => f['hash_method'] })
        if f['method'] == 'push'
          return { 'interact_ref' => it.interact_ref,
                   'finish' => { 'method' => 'push', 'uri' => f['uri'], 'body' => { 'hash' => h, 'interact_ref' => it.interact_ref } } }
        end
        { 'interact_ref' => it.interact_ref, 'finish' => { 'method' => 'redirect', 'url' => Gnap.redirect_url(f['uri'], h, it.interact_ref) } }
      end

      # Continuation (RFC 9635 5.1): present the interact_ref once. A replay finalizes the grant and is `too_many_attempts`.
      def consume(interact_ref)
        id = @by_ref[interact_ref]
        it = id && @by_id[id]
        raise InteractionError.new('unknown_interaction', 'no such interaction reference') if it.nil?

        if it.ref_used || it.state == 'finalized'
          it.state = 'finalized'
          raise InteractionError.new('too_many_attempts', 'the interaction reference was already used')
        end
        raise InteractionError.new('expired', 'the interaction expired') if expired?(it)
        raise InteractionError.new('wrong_state', "interaction is #{it.state}") unless it.state == 'approved'

        it.ref_used = true
        it
      end

      def finalize(id)
        it = @by_id[id]
        it.state = 'finalized' if it
        nil
      end

      private

      def live(id)
        it = @by_id[id]
        raise InteractionError.new('unknown_interaction', 'no such interaction') if it.nil?
        raise InteractionError.new('expired', 'the interaction expired') if expired?(it)

        it
      end
    end

    # Client side: validate a finish callback (query for redirect, JSON body for push). Returns the interact_ref to send, or
    # raises unknown_interaction. ctx: client_nonce, as_nonce, grant_endpoint, hash_method?.
    def accept_finish(cb, ctx)
      ref = cb['interact_ref']
      h = cb['hash']
      raise InteractionError.new('unknown_interaction', 'hash and interact_ref are required') unless ref.is_a?(String) && !ref.empty? && h.is_a?(String)
      raise InteractionError.new('unknown_interaction', 'the callback hash does not validate') unless verify_interaction_hash(h, ctx.merge('interact_ref' => ref))

      ref
    end

    def type_text(t) = t.equal?(UNDEF) ? 'undefined' : Js.string(t)
    def js_length(v) = v.is_a?(String) ? Js.len16(v) : (v.is_a?(Array) ? v.length : nil)

    # One need {verb, resource} per (action, location) pair of an access array. An access right with no actions or no locations
    # is a wildcard and is refused: a need must be explicit.
    def access_to_needs(access)
      access.flat_map do |a|
        actions = prop(a, 'actions')
        locations = prop(a, 'locations')
        unless Js.truthy?(js_length(defined(actions))) && Js.truthy?(js_length(defined(locations)))
          raise InteractionError.new('invalid_request', "access \"#{type_text(prop(a, 'type'))}\" needs explicit actions and locations to become a need")
        end
        Js.spread(actions).flat_map do |verb|
          Js.spread(locations).map { |loc| { 'verb' => verb, 'resource' => "gnap:#{type_text(prop(a, 'type'))}:#{Js.string(loc)}" } }
        end
      end
    end

    # ---- the Agent-GNAP profile, as a machine-readable spec object ----

    AGENT_GNAP_PROFILE = {
      "name" => "agent-gnap",
      "version" => "1.0",
      "rfc" => "RFC 9635",
      "summary" => "A GNAP profile for autonomous-agent delegation: each A2A hop is a GNAP grant whose authority is issued as an attenuated, key-bound PCA capability, never wider than the issuing agent.",
      "mapping" => [
        {
          "gnap" => "access[].type",
          "pca" => "predicate resource namespace gnap:<type>:<location>",
          "note" => "the resource family the rights live in"
        },
        {
          "gnap" => "access[].actions",
          "pca" => "predicate.verb (list, or * for any)",
          "note" => "the operations permitted"
        },
        {
          "gnap" => "access[].locations",
          "pca" => "predicate.resource (exact or trailing-* prefix)",
          "note" => "the resource targets"
        },
        {
          "gnap" => "access[].datatypes / identifier",
          "pca" => "predicate.where on action.params.*",
          "note" => "value-level constraints"
        },
        {
          "gnap" => "client.key.jwk (OKP/Ed25519)",
          "pca" => "capability.holder (cnf-bound key)",
          "note" => "the proof-of-possession key"
        },
        {
          "gnap" => "grant request (no prior grant)",
          "pca" => "mintGrant → root capability",
          "note" => "envelope predicates = requested access"
        },
        {
          "gnap" => "grant request (delegated hop)",
          "pca" => "delegate → child capability + gnap_access caveat",
          "note" => "append-only attenuation"
        },
        {
          "gnap" => "access_token (§3.2)",
          "pca" => "a verifiable PCA capability chain (encodeBoundToken)",
          "note" => "bound, self-verifying token"
        },
        {
          "gnap" => "continue (§3.1) + interact (§3.3)",
          "pca" => "PCA step-up: FROST/threshold co-signature folded into a PCActn",
          "note" => "tier-2/3 escalation"
        },
        {
          "gnap" => "jwsd detached JWS (§7.3.4)",
          "pca" => "request proof binding the body to capability.holder",
          "note" => "verified with jose"
        }
      ],
      "proofMethods" => ["jwsd"],
      "multiHop" => "An A2A task is a chain of GNAP grants. Each hop delegates from the issuing agent to the next, recording its (clamped) rights as an append-only gnap_access caveat. Effective authority is the intersection of the root policy envelope and every hop; PCA caveats are conjunctive and append-only, so no hop can widen — \"never wider than the issuer\" holds across any depth.",
      "stepUp" => "A request for authority beyond the issuer (or an explicit interaction) returns a GNAP continue handle instead of a token. The client returns with the action PCActn plus a guardian/principal co-signature, which is folded into the PCActn threshold and verified at tier 2/3 (FROST or multi-signature) before the action is admitted.",
      "security" => [
        "Attenuation is structural and append-only: a delegated hop can only ever narrow authority.",
        "Every grant is key-bound (cnf): the holder key must prove possession via a jwsd detached JWS.",
        "All verification fails closed: bad token, broken chain, bad proof, stale request, or out-of-scope action denies.",
        "Rights beyond the issuer are clamped at issue time and denied at action time (defense in depth).",
        "Elevation beyond the agent requires a human/guardian co-signature, not a self-minted grant."
      ]
    }.freeze
  end
end
