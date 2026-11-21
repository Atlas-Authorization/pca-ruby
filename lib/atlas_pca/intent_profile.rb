# frozen_string_literal: true

require_relative 'intent_omega'
require_relative 'intent_policy'
require_relative 'intent_v2'
require_relative 'predicates'

# Portable, revocable intent profiles: the principal's signed, versioned record of standing rules and prior answers, append-only
# succession, scoped use (deny wins, permit is explicit, negative observations veto) and revocation. Native port of the
# TypeScript reference (@atlasauth/pca-intent); signing is Ed25519 (a suite-agile profile verifies under the verifier's pin).
module AtlasPca
  module IntentProfile
    UNDEF = V2JS::UNDEF
    INTENT_PROFILE_KIND = 'pca-intent-profile'
    INTENT_PROFILE_SIG_DOMAIN = "atlas-pca/intent-profile/v1\0"
    INTENT_PROFILE_REF_DOMAIN = 'atlas-pca/intent-profile-ref/v1'
    MAX_PROFILE_RULES = 256
    MAX_PROFILE_OBSERVATIONS = 2000
    KEYS = %w[v kind profile_id version owner scope standing prior expires_at revocation prev alg pq_pk sig pq_sig].freeze
    ID_RE = /\A[A-Za-z0-9_.-]{1,128}\z/
    BODY_KEYS = %w[v kind profile_id version owner scope standing prior expires_at revocation].freeze

    module_function

    def g(o, k) = o.key?(k) ? o[k] : UNDEF
    def js(v) = V2JS.js_str(v)
    def str_list?(v, mx = 256) = v.is_a?(Array) && v.length <= mx && v.all? { |x| x.is_a?(String) && !x.empty? }

    def pred_ok?(p)
      return false unless p.is_a?(Hash)

      v = g(p, 'verb')
      v.is_a?(String) || (v.is_a?(Array) && v.all? { |x| x.is_a?(String) })
    end

    def sorted_keys(o) = V2JS.js_keys(o).sort_by { |k| IntentOmega.u16key(k) }.join(',')
    def b32?(x) = !AtlasPca.b64d(x, 32).nil?

    # nil when the profile is well-formed (closed, strictly typed); else the first problem.
    def intent_profile_shape_error(p, signed = true)
      return 'profile is not an object' unless p.is_a?(Hash)

      V2JS.js_keys(p).each { |k| return "profile: unknown member '#{k}'" unless KEYS.include?(k) }
      return 'not a pca-intent-profile v1' if !V2JS.strict_eq(g(p, 'v'), 1) || g(p, 'kind') != INTENT_PROFILE_KIND

      pid = g(p, 'profile_id')
      return 'profile_id must match [A-Za-z0-9_.-]{1,128}' if !pid.is_a?(String) || !ID_RE.match?(pid)

      ver = g(p, 'version')
      return 'version must be a safe integer >= 1' unless V2JS.int?(ver) && ver >= 1
      return 'owner must be canonical base64url (32 bytes)' unless b32?(g(p, 'owner'))

      scope = g(p, 'scope')
      return 'scope must be {sites?, verbs?, semantic_types?}' if !scope.is_a?(Hash) || V2JS.js_keys(scope).any? { |k| !%w[sites verbs semantic_types].include?(k) }

      %w[sites verbs semantic_types].each do |k|
        return "scope.#{k} must be a list of strings" if !g(scope, k).equal?(UNDEF) && !str_list?(g(scope, k))
      end
      standing = g(p, 'standing')
      return 'standing must be {deny, permit}' if !standing.is_a?(Hash) || sorted_keys(standing) != 'deny,permit'

      %w[deny permit].each do |k|
        r = standing[k]
        return "standing.#{k} must be at most #{MAX_PROFILE_RULES} predicates" if !r.is_a?(Array) || r.length > MAX_PROFILE_RULES || !r.all? { |x| pred_ok?(x) }
      end
      prior = g(p, 'prior')
      return 'prior must be {observations, maps}' if !prior.is_a?(Hash) || sorted_keys(prior) != 'maps,observations'

      obs = prior['observations']
      return "prior.observations must be at most #{MAX_PROFILE_OBSERVATIONS}" if !obs.is_a?(Array) || obs.length > MAX_PROFILE_OBSERVATIONS

      obs.each do |o|
        if !o.is_a?(Hash) || sorted_keys(o) != 'at,values,verb,y' || !o['verb'].is_a?(String) || !o['values'].is_a?(Hash) ||
           !(V2JS.strict_eq(o['y'], 0) || V2JS.strict_eq(o['y'], 1)) || !(V2JS.int?(o['at']) && o['at'] >= 0)
          return 'prior.observations entries are {verb, values, y, at}'
        end
      end
      maps = prior['maps']
      return 'prior.maps must be 32-byte digests' if !maps.is_a?(Array) || !maps.all? { |m| b32?(m) }

      ea = g(p, 'expires_at')
      return 'expires_at must be a non-negative safe integer' unless V2JS.int?(ea) && ea >= 0

      rev = g(p, 'revocation')
      if !rev.is_a?(Hash) || V2JS.js_keys(rev).any? { |k| !%w[epoch_uri key].include?(k) } || !g(rev, 'epoch_uri').is_a?(String) || rev['epoch_uri'].empty?
        return 'revocation must be {epoch_uri, key?}'
      end
      if !g(rev, 'key').equal?(UNDEF) && !b32?(rev['key'])
        return 'revocation.key (the revocation authority; absent = the owner) must be canonical base64url (32 bytes)'
      end

      prev = g(p, 'prev')
      return 'prev is required exactly when version > 1' if V2JS.strict_eq(ver, 1) != prev.equal?(UNDEF)
      return 'prev must be canonical base64url (32 bytes)' if !prev.equal?(UNDEF) && !b32?(prev)

      if signed
        alg = g(p, 'alg')
        return 'alg must be a string' if !alg.equal?(UNDEF) && !alg.is_a?(String)

        se = IntentV2.suite_known_err(alg)
        return "alg: #{se}" unless se.nil?
        return 'an ed25519 profile must not carry pq_pk / pq_sig' if (alg.equal?(UNDEF) || alg == 'ed25519') && (!g(p, 'pq_pk').equal?(UNDEF) || !g(p, 'pq_sig').equal?(UNDEF))
        return 'sig must be a string' unless g(p, 'sig').is_a?(String)
      end
      AtlasPca.strict_bytes(profile_body(p))
      nil
    rescue StandardError => e
      "malformed profile: #{e.message}"
    end

    def profile_body(p)
      b = BODY_KEYS.select { |k| p.key?(k) }.to_h { |k| [k, p[k]] }
      b['prev'] = p['prev'] if p.key?('prev') && !p['prev'].equal?(UNDEF)
      b
    end

    def message(body) = INTENT_PROFILE_SIG_DOMAIN.b + AtlasPca.strict_bytes(body)

    # Sign a profile version as its owner (the owner identity must be the signer's Ed25519 key).
    def sign_intent_profile(body, owner_secret, suite = nil)
      raise ArgumentError, 'signIntentProfile: only Ed25519 signing is supported natively' if !suite.nil? && ![nil, 'ed25519'].include?(suite['alg'])

      key = KeyPair.new(owner_secret)
      owner = key.public
      raise ArgumentError, 'signIntentProfile: owner does not match the signing key' if body.key?('owner') && body['owner'] != owner

      b = profile_body(body.merge('owner' => owner))
      bad = intent_profile_shape_error(b, false)
      raise ArgumentError, "signIntentProfile: #{bad}" if bad

      b.merge('sig' => AtlasPca.b64e(key.sign(message(b))))
    end

    def pins_of(pin)
      pq = pin.is_a?(Hash) ? pin['pqPins'] : nil
      pq.is_a?(Hash) ? pq : nil
    end

    def verify_intent_profile(p, pin = nil)
      bad = intent_profile_shape_error(p)
      return { 'ok' => false, 'reason' => bad } if bad

      body = IntentV2.bind_suite_fields(profile_body(p), g(p, 'alg'), g(p, 'pq_pk'))
      ok = IntentV2.verify_pinned_suite(g(p, 'alg'), p['owner'], g(p, 'pq_pk'), message(body), p['sig'], g(p, 'pq_sig'), pins_of(pin))
      return { 'ok' => false, 'reason' => 'profile signature invalid' } unless ok

      { 'ok' => true }
    rescue StandardError => e
      { 'ok' => false, 'reason' => "malformed profile: #{e.message}" }
    end

    # The content address of a signed profile version.
    def intent_profile_digest(p) = AtlasPca.hash_canonical({ 'd' => INTENT_PROFILE_REF_DOMAIN, 'p' => p })

    # Append-only succession: same id and owner, version + 1, prev = digest(previous).
    def verify_profile_succession(prev, nxt)
      [[prev, 'previous'], [nxt, 'next']].each do |x, n|
        v = verify_intent_profile(x)
        return { 'ok' => false, 'reason' => "#{n} version: #{v['reason']}" } unless v['ok']
      end
      return { 'ok' => false, 'reason' => 'a profile version cannot change its id or owner' } if nxt['profile_id'] != prev['profile_id'] || nxt['owner'] != prev['owner']
      return { 'ok' => false, 'reason' => 'versions are append-only: next.version must be previous + 1' } if nxt['version'] != prev['version'] + 1
      return { 'ok' => false, 'reason' => 'next.prev is not the digest of the previous version' } if g(nxt, 'prev') != intent_profile_digest(prev)

      { 'ok' => true }
    end

    def lt?(a, b) = IntentOmega.finite_number?(a) && IntentOmega.finite_number?(b) && a < b
    def present_list?(x) = !x.equal?(UNDEF) && !x.nil?

    # Is the profile in scope (and unexpired) for this action?
    def profile_applies(p, u)
      return false unless lt?(u['now'], p['expires_at'])

      scope = p['scope']
      sites = g(scope, 'sites')
      verbs = g(scope, 'verbs')
      sem = g(scope, 'semantic_types')
      return false if present_list?(sites) && sites.none? { |x| V2JS.strict_eq(x, g(u, 'aud')) }
      return false if present_list?(verbs) && verbs.none? { |x| V2JS.strict_eq(x, g(u, 'verb')) }
      if present_list?(sem)
        sems = g(u, 'semantics')
        sems = [] if sems.equal?(UNDEF) || sems.nil?
        sems = sems.chars if sems.is_a?(String)
        raise TypeError, 'semantics is not iterable' unless sems.is_a?(Array)
        return false unless sems.any? { |s| sem.any? { |t| V2JS.strict_eq(t, s) } }
      end
      true
    end

    # G^std membership: an in-scope action is outside the standing layer iff a deny rule matches it (deny wins).
    def standing_admits(p, u, action)
      return true unless profile_applies(p, u)

      p['standing']['deny'].none? { |r| AtlasPca.predicate_matches(r, action) }
    end

    # The explicit standing-permission layer: an in-scope permit rule matches (the only positive import).
    def standing_permits(p, u, action)
      profile_applies(p, u) && p['standing']['permit'].any? { |r| AtlasPca.predicate_matches(r, action) }
    end

    # The cells that the profile's negative observations veto.
    def profile_veto_cells(p, omega)
      out = []
      seen = {}
      p['prior']['observations'].each do |o|
        next if o['y'] != 0

        vs = omega['verbs'].find { |v| v['verb'] == o['verb'] }
        cell = vs ? IntentOmega.cell_of(vs, { 'verb' => o['verb'], 'values' => o['values'] }) : nil
        next if vs.nil? || cell.nil?

        k = "#{o['verb']}|#{cell.join(',')}"
        next if seen.key?(k)

        seen[k] = true
        out << { 'verb' => o['verb'], 'cell' => cell }
      end
      out
    end

    # A ceiling function (for a visit decision) from the profile's standing deny rules over outcomes.
    def profile_ceiling(p, u)
      lambda do |vs, o|
        a = IntentPolicy.outcome_to_action(vs, o)
        ctx = { 'action' => { 'verb' => a['verb'], 'resource' => a['resource'], 'params' => a['params'] } }
        ctx['env'] = a['env'] if a['env'] && !a['env'].empty?
        ctx['subject'] = a['subject'] if a['subject'] && !a['subject'].empty?
        standing_admits(p, u.merge('verb' => o['verb']), ctx)
      end
    end

    # Is this profile version usable now: signed, unexpired, and not revoked per a fresh epoch of its revocation authority.
    def profile_usable(p, c)
      v = verify_intent_profile(p, c['pin'])
      return v unless v['ok']
      return { 'ok' => false, 'reason' => 'the profile has expired' } unless lt?(c['now'], p['expires_at'])

      rev = p['revocation']
      authority = !g(rev, 'key').equal?(UNDEF) && !rev['key'].nil? ? rev['key'] : p['owner']
      r = IntentV2.check_session_revocation(c.key?('revocation') ? c['revocation'] : UNDEF, session: p['profile_id'],
                                            scope: IntentV2.profile_revocation_scope(p['profile_id']), authority: authority,
                                            ids: [IntentV2.profile_revocation_id(p['profile_id'], p['version'])],
                                            now: c.key?('now') ? c['now'] : UNDEF, max_age_ms: c.key?('maxAgeMs') ? c['maxAgeMs'] : UNDEF,
                                            pins: pins_of(c['pin']), last: c.key?('last') ? c['last'] : UNDEF)
      r['ok'] ? { 'ok' => true } : { 'ok' => false, 'reason' => "profile revocation: #{r['reason']}" }
    end
  end
end
