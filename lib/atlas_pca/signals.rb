# frozen_string_literal: true

require 'securerandom'
require_relative 'js_compat'
require_relative 'jose'

module AtlasPca
  # Shared Signals Framework / CAEP: Security Event Tokens (RFC 8417), the subscriber-side revocation state, the fail-closed
  # SET receiver, SSF stream health / verification / poll / push bookkeeping and the SSF management API. Mirrors the
  # TypeScript reference (@atlasauth/pca-signals): asynchronous reference functions are synchronous, store and function
  # options are callables / duck-typed objects, option keys are snake_case. JSON-shaped inputs follow JavaScript semantics
  # (truthiness, missing members, member order), so a hostile input is refused or accepted exactly as the reference does.
  module Signals
    SET_TYP = 'secevent+jwt'
    SET_ALG = 'EdDSA'
    EVENT_TYPES = {
      'sessionRevoked' => 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
      'credentialChange' => 'https://schemas.openid.net/secevent/caep/event-type/credential-change',
      'grantRevoked' => 'https://atlasauth.net/caep/grant-revoked',
      'killSwitch' => 'https://atlasauth.net/caep/kill-switch',
      'intentRevoked' => 'https://atlasauth.net/caep/intent-revoked',
      'verification' => 'https://schemas.openid.net/secevent/ssf/event-type/verification',
      'riskLevelChange' => 'https://schemas.openid.net/secevent/caep/event-type/risk-level-change',
      'assuranceLevelChange' => 'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change'
    }.freeze
    RISC_EVENT_TYPES = {
      'sessionsRevoked' => 'https://schemas.openid.net/secevent/risc/event-type/sessions-revoked',
      'accountDisabled' => 'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
      'accountPurged' => 'https://schemas.openid.net/secevent/risc/event-type/account-purged',
      'credentialCompromise' => 'https://schemas.openid.net/secevent/risc/event-type/credential-compromise'
    }.freeze
    SET_INMEMORY_MAX_ENTRIES = 100_000
    DELIVERY_PUSH = 'urn:ietf:rfc:8935'
    DELIVERY_POLL = 'urn:ietf:rfc:8936'
    STREAM_STATUSES = %w[enabled paused disabled].freeze

    UNDEF = Object.new.freeze # an absent JSON member (distinct from null)
    DEFAULT = Object.new.freeze

    class SignalsError < StandardError
      attr_reader :code

      def initialize(code, message)
        super(message)
        @code = code
      end
    end

    # A JOSE-level refusal; `code` is the JOSE error code (nil for the package's own `SET invalid:` errors).
    class SetVerifyError < StandardError
      attr_reader :code

      def initialize(message, code = nil)
        super(message)
        @code = code
      end
    end

    # Subscriber-side revocation state: each key keeps the max event_timestamp seen.
    class RevocationState
      attr_accessor :revoked_grants, :killed_agents, :revoked_intent_ids

      def initialize
        @revoked_grants = {}
        @killed_agents = {}
        @revoked_intent_ids = nil
      end
    end

    # Bounded single-process replay store: when full, a new jti raises (the receiver then refuses) instead of evicting a live entry.
    class InMemorySetReplayStore
      def initialize(max_entries)
        @max = max_entries
        @seen = {}
      end

      def add_if_absent(jti, expires_at_sec, now_sec)
        return false unless Signals.finite_num?(now_sec) && Signals.finite_num?(expires_at_sec) # a non-finite clock or expiry admits nothing

        held = @seen[jti]
        return false if !held.nil? && !(now_sec >= held)

        if held.nil? && @seen.length >= @max
          @seen.delete_if { |_, exp| now_sec >= exp }
          raise 'replay store is full' if @seen.length >= @max
        end
        @seen[jti] = expires_at_sec
        true
      end
    end

    module_function

    # ---- JS-semantics helpers ----

    def rec?(v) = v.is_a?(Hash)
    def str_ne?(x) = x.is_a?(String) && !x.empty?

    # `o.k`: TypeError for null / undefined, UNDEF for a missing member or a primitive.
    def prop(o, k)
      raise TypeError, "Cannot read properties of #{o.nil? ? 'null' : 'undefined'} (reading '#{k}')" if o.nil? || o.equal?(UNDEF)

      o.is_a?(Hash) ? o.fetch(k, UNDEF) : UNDEF
    end

    def optprop(o, k) = o.nil? || o.equal?(UNDEF) ? UNDEF : prop(o, k)

    # Object.entries(x)
    def entries(x)
      raise TypeError, 'Cannot convert undefined or null to object' if x.nil? || x.equal?(UNDEF)
      return Js.js_keys(x).map { |k| [k, x[k]] } if x.is_a?(Hash)
      return x.each_with_index.map { |v, i| [i.to_s, v] } if x.is_a?(Array)
      return x.each_char.with_index.map { |c, i| [i.to_s, c] } if x.is_a?(String)

      []
    end

    def safe_int?(v)
      return false unless Js.num?(v)
      return false if v.is_a?(Float) && (!v.finite? || v != v.floor)

      v.abs <= (2**53) - 1
    end

    def nonneg_safe_int?(v) = safe_int?(v) && v >= 0 && !Js.neg_zero?(v)
    def finite_num?(v) = Js.num?(v) && (v.is_a?(Integer) || v.finite?)
    def js_num(v) = Predicates.js_number_string(v)

    # ---- SET build / verify ----

    # Build a signed SET. `key` is a 32-byte Ed25519 seed; `subject` nil omits sub / sub_id.
    def build_set(events, issuer, audience, key, subject: nil, now: nil, jti: nil)
      unless (events.is_a?(Hash) || events.is_a?(Array)) && !events.empty?
        raise ArgumentError, 'buildSET: at least one event is required in the `events` map (RFC 8417 §2.2)'
      end

      payload = { 'events' => events }
      payload['sub_id'] = { 'format' => 'opaque', 'id' => subject } unless subject.nil?
      payload['iss'] = issuer
      payload['iat'] = now.nil? ? Time.now.to_i : now
      payload['jti'] = jti.nil? ? SecureRandom.uuid : jti
      payload['aud'] = audience
      payload['sub'] = subject unless subject.nil?
      Jose.sign_jwt(payload, { 'alg' => SET_ALG, 'typ' => SET_TYP }, key)
    end

    def norm_typ(v) = Jose.normalize_typ(v)

    def parse_segment(seg)
      AtlasPca.parse_json_text(Jose.lenient_b64d(seg).force_encoding('UTF-8').scrub)
    rescue AtlasPca::Malformed, ArgumentError
      nil
    end

    # jose jwtVerify with its claim checks and their order, for an already canonical compact JWS.
    def jose_verify(jwt, key, opts, typ)
      prot, pay, sig = jwt.split('.', -1)
      header = prot.empty? ? {} : parse_segment(prot)
      header = {} unless header.is_a?(Hash)
      b64 = true
      if header.key?('crit')
        crit = header['crit']
        unless crit.is_a?(Array) && !crit.empty? && crit.all? { |c| str_ne?(c) }
          raise SetVerifyError.new('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present', 'ERR_JWS_INVALID')
        end

        crit.each do |p|
          raise SetVerifyError.new("Extension Header Parameter \"#{p}\" is not recognized", 'ERR_JOSE_NOT_SUPPORTED') unless p == 'b64'
        end
        b64 = header['b64']
        unless [true, false].include?(b64)
          raise SetVerifyError.new('The "b64" (base64url-encode payload) Header Parameter must be a boolean', 'ERR_JWS_INVALID')
        end
      end
      alg = header['alg']
      raise SetVerifyError.new('JWS "alg" (Algorithm) Header Parameter missing or invalid', 'ERR_JWS_INVALID') unless str_ne?(alg)
      raise SetVerifyError.new('"alg" (Algorithm) Header Parameter value not allowed', 'ERR_JOSE_ALG_NOT_ALLOWED') unless alg == SET_ALG

      ok = begin
        Jose.jws_verify(alg, key, Jose.lenient_b64d(sig), "#{prot}.#{pay}".b)
      rescue Jose::Error => e
        raise SetVerifyError, e.message
      end
      raise SetVerifyError.new('signature verification failed', 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') unless ok
      raise SetVerifyError.new('JWTs MUST NOT use unencoded payload', 'ERR_JWT_INVALID') unless b64

      payload = parse_segment(pay)
      raise SetVerifyError.new('JWT Claims Set must be a top-level JSON object', 'ERR_JWT_INVALID') unless payload.is_a?(Hash)

      claim = 'ERR_JWT_CLAIM_VALIDATION_FAILED'
      if Js.truthy?(typ) && !(header['typ'].is_a?(String) && norm_typ(header['typ']) == norm_typ(typ))
        raise SetVerifyError.new('unexpected "typ" JWT header value', claim)
      end

      issuer = opts['issuer']
      audience = opts['audience']
      required = (opts.key?('issuer') ? ['iss'] : []) + (opts.key?('audience') ? ['aud'] : [])
      required.each { |c| raise SetVerifyError.new("missing required \"#{c}\" claim", claim) unless payload.key?(c) }
      if Js.truthy?(issuer) && !(issuer.is_a?(Array) ? issuer : [issuer]).include?(payload['iss'])
        raise SetVerifyError.new('unexpected "iss" claim value', claim)
      end
      if Js.truthy?(audience)
        aud_opt = audience.is_a?(String) ? [audience] : audience
        raise TypeError, 'audience option must be a string or an array' unless aud_opt.is_a?(Array)

        ap = payload['aud']
        good = if ap.is_a?(String) then aud_opt.include?(ap)
               elsif ap.is_a?(Array) then aud_opt.any? { |a| ap.include?(a) }
               else false
               end
        raise SetVerifyError.new('unexpected "aud" claim value', claim) unless good
      end
      tol = if !opts.key?('clock_tolerance') then 0
            elsif opts['clock_tolerance'].is_a?(String) then Jose.secs(opts['clock_tolerance'])
            elsif Js.num?(opts['clock_tolerance']) then opts['clock_tolerance']
            else raise TypeError, 'Invalid clockTolerance option type'
            end
      now = opts.key?('current_date') ? Jose.epoch_of_ms(opts['current_date']) : Time.now.to_i
      raise SetVerifyError.new('"iat" claim must be a number', claim) if payload.key?('iat') && !Js.num?(payload['iat'])
      if payload.key?('nbf')
        raise SetVerifyError.new('"nbf" claim must be a number', claim) unless Js.num?(payload['nbf'])
        raise SetVerifyError.new('"nbf" claim timestamp check failed', claim) if payload['nbf'] > now + tol
      end
      if payload.key?('exp')
        raise SetVerifyError.new('"exp" claim must be a number', claim) unless Js.num?(payload['exp'])
        raise SetVerifyError.new('"exp" claim timestamp check failed', 'ERR_JWT_EXPIRED') if payload['exp'] <= now - tol
      end
      [payload, header]
    end

    def parse_events(raw)
      raise ArgumentError, 'SET invalid: `events` claim is missing or not a JSON object (RFC 8417 §2.2)' unless rec?(raw)
      raise ArgumentError, 'SET invalid: `events` claim is empty (RFC 8417 §2.2)' if raw.empty?

      Js.js_keys(raw).each do |k|
        raise ArgumentError, "SET invalid: event payload for `#{k}` is not a JSON object (RFC 8417 §2.2)" unless rec?(raw[k])
      end
      raw
    end

    # Verify a SET (EdDSA; `verify_key` is the 32-byte public key) and parse it: {events, iss, jti, sub?, payload}.
    # opts: issuer, audience, clock_tolerance, current_date (epoch ms), typ, require_typ. Raises on any invalid token.
    def verify_set(set, verify_key, opts = DEFAULT)
      opts = {} if opts.equal?(DEFAULT)
      raise TypeError, "Cannot read properties of null (reading 'issuer')" if opts.nil?

      Jose.assert_canonical_compact_jws(set)
      typ = opts['require_typ'] == false ? nil : (opts['typ'].nil? ? SET_TYP : opts['typ'])
      payload, = jose_verify(set, verify_key, opts, typ)
      raise ArgumentError, 'SET invalid: missing or non-string `iss`' unless payload['iss'].is_a?(String)
      raise ArgumentError, 'SET invalid: missing or non-string `jti` (RFC 8417 §2.2 requires it)' unless payload['jti'].is_a?(String)

      events = parse_events(payload['events'])
      out = { 'events' => events, 'iss' => payload['iss'], 'jti' => payload['jti'], 'payload' => payload }
      out['sub'] = payload['sub'] if payload['sub'].is_a?(String)
      out
    end

    # ---- subscriber-side revocation state ----

    def create_revocation_state = RevocationState.new

    def record_max(m, key, ts)
      prev = m[key]
      m[key] = ts if prev.nil? || ts > prev
    end

    def ts_of(ev)
      t = prop(ev, 'event_timestamp')
      Js.num?(t) ? t : 0
    end

    # Fold one verified SET into the state: monotone, each key keeps the max event_timestamp.
    def apply_set(state, parsed)
      entries(prop(parsed, 'events')).each do |typ, ev|
        next if ev.equal?(UNDEF)

        ts = ts_of(ev)
        case typ
        when EVENT_TYPES['grantRevoked']
          ref = prop(ev, 'grant_ref')
          record_max(state.revoked_grants, ref, ts) if str_ne?(ref)
        when EVENT_TYPES['killSwitch']
          agent = prop(ev, 'agent')
          ref = prop(ev, 'grant_ref')
          record_max(state.killed_agents, agent, ts) if str_ne?(agent)
          record_max(state.revoked_grants, ref, ts) if str_ne?(ref)
        when EVENT_TYPES['intentRevoked']
          ids = prop(ev, 'ids')
          if ids.is_a?(Array)
            ids.each do |i|
              next unless i.is_a?(String) && i.start_with?('pca-intent:')

              state.revoked_intent_ids ||= {}
              record_max(state.revoked_intent_ids, i, ts)
            end
          end
        end
      end
      state
    end

    def intent_revoked?(state, id) = !state.revoked_intent_ids.nil? && state.revoked_intent_ids.key?(id)

    def revoked?(state, grant_ref, agent = nil)
      return true if state.revoked_grants.key?(grant_ref)

      !agent.nil? && state.killed_agents.key?(agent)
    end

    def set_timestamp(p)
      m = Float::INFINITY
      entries(prop(p, 'events')).each do |_, ev|
        next if ev.equal?(UNDEF)

        t = prop(ev, 'event_timestamp')
        m = t if Js.num?(t) && t < m
      end
      m.is_a?(Integer) || m.finite? ? m : 0
    end

    # Fold verified SETs in event_timestamp order (stable), so delivery order cannot matter.
    def stream_processor(parsed_sets, state = nil)
      raise TypeError, 'parsedSets is not iterable' unless parsed_sets.is_a?(Array)

      state ||= create_revocation_state
      keyed = parsed_sets.each_with_index.map { |p, i| [set_timestamp(p), i, p] }
      keyed.sort_by { |t, i, _| [t, i] }.each { |_, _, p| apply_set(state, p) }
      state
    end

    # ---- replay store, receiver ----

    def create_in_memory_set_replay_store(opts = DEFAULT)
      opts = {} if opts.equal?(DEFAULT)
      mx = prop(opts, 'max_entries')
      mx = SET_INMEMORY_MAX_ENTRIES if mx.equal?(UNDEF) || mx.nil?
      unless Js.num?(mx) && (mx.is_a?(Integer) || (mx.finite? && mx == mx.floor)) && mx >= 1
        raise SignalsError.new('misconfigured', 'maxEntries must be a positive integer')
      end

      InMemorySetReplayStore.new(mx.to_i)
    end

    def run_set_replay_store_conformance(make)
      failures = []
      check = ->(ok, name) { failures << name unless ok }
      s = make.call
      check.call(s.add_if_absent('a', 200, 100) == true, 'first sight of a jti returns true')
      check.call(s.add_if_absent('a', 200, 101) == false, 'second sight of the same jti returns false')
      check.call(s.add_if_absent('b', 200, 101) == true, 'a different jti is independent')
      check.call(s.add_if_absent('a', 200, 199) == false, 'still seen one second before expiry')
      t = make.call
      t.add_if_absent('c', 200, 100)
      check.call(t.add_if_absent('c', 400, 200) == true, 'an expired entry may be added again (nowSec >= expiresAtSec)')
      u = make.call
      wins = 16.times.count { u.add_if_absent('race', 200, 100) == true }
      check.call(wins == 1, "16 concurrent adds of one jti: exactly one wins (got #{wins})")
      failures
    end

    def fails(code, reason) = { 'ok' => false, 'code' => code, 'reason' => reason }

    # The recommended receive path: size cap, canonical spelling, signature, typ, iss, aud, iat window, atomic jti replay
    # guard, then fold into the state. Every refusal is a value; a replay store that raises denies (the SET is not applied).
    def receive_set(set, verify_key, opts)
      store = opts ? optprop(opts, 'replay_store') : UNDEF
      max_age = opts.is_a?(Hash) ? opts.fetch('max_age_sec', UNDEF) : UNDEF
      if !opts.is_a?(Hash) || !opts.key?('issuer') || !opts.key?('audience') || !store.respond_to?(:add_if_absent) ||
         !Js.truthy?(opts['state']) || !finite_num?(max_age) || max_age <= 0
        return fails('misconfigured', 'issuer, audience, replayStore, state and a positive maxAgeSec are all required')
      end

      mb = opts['max_bytes'].nil? ? 16_384 : opts['max_bytes']
      return fails('oversize', 'SET is not a string or exceeds maxBytes') if !set.is_a?(String) || Js.len16(set) > mb

      begin
        Jose.assert_canonical_compact_jws(set)
      rescue Jose::CanonicalJwsError => e
        return fails('malformed', e.message)
      end
      now = opts['now_sec'].nil? ? Time.now.to_i : opts['now_sec']
      # a Date beyond +-8.64e15 ms is invalid, which the JWT library reads as no clock: refuse it (NaN and +-Infinity fail this test too)
      return fails('verify_failed', 'nowSec is not a representable time') unless finite_num?(now) && (now * 1000).abs <= 8.64e15

      parsed = begin
        verify_set(set, verify_key, { 'issuer' => opts['issuer'], 'audience' => opts['audience'], 'current_date' => now * 1000 })
      rescue StandardError => e # every verification failure is a refusal value
        return fails('verify_failed', e.message)
      end
      iat = parsed['payload']['iat']
      return fails('iat_missing', 'SET has no numeric iat') unless finite_num?(iat)

      skew = opts['clock_skew_sec'].nil? ? 60 : opts['clock_skew_sec']
      return fails('iat_future', 'SET iat is in the future') unless finite_num?(now) && finite_num?(skew) && iat <= now + skew
      return fails('iat_stale', "SET is older than #{js_num(max_age)}s") unless now - iat <= max_age

      plan = nil
      unless opts['standard_revocations'].nil?
        begin
          plan = plan_standard_revocations(parsed, opts['standard_revocations'])
        rescue StandardError => e
          return fails('unmapped_subject', e.message)
        end
      end
      fresh = begin
        store.add_if_absent(parsed['jti'], iat + max_age + skew, now)
      rescue StandardError => e
        return fails('replay_store_error', e.message)
      end
      return fails('replay', "jti '#{parsed['jti']}' has already been received") unless fresh == true

      apply_set(opts['state'], parsed)
      plan&.fetch('agents')&.each { |agent, ts| record_max(opts['state'].killed_agents, agent, ts) }
      { 'ok' => true, 'parsed' => parsed }
    end

    # ---- standard (CAEP / RISC) revocation events ----

    def default_subject_to_agent(subject)
      i = subject['id']
      subject['format'] == 'opaque' && str_ne?(i) ? i : nil
    end

    def revoking_standard_event?(typ, ev)
      return true if typ == EVENT_TYPES['sessionRevoked']
      return prop(ev, 'change_type') != 'create' if typ == EVENT_TYPES['credentialChange'] # unknown or absent counts as a change

      RISC_EVENT_TYPES.value?(typ)
    end

    # Decide, without touching any state, which agents the SET's CAEP / RISC revoking events revoke:
    # {agents: [[agent, ts]], unmapped: [event types]}. opts: subject_to_agent (callable), fail_on_unmapped.
    def plan_standard_revocations(parsed, opts = nil)
      opts = {} if opts.nil?
      to_agent = opts['subject_to_agent'] || method(:default_subject_to_agent)
      plan = { 'agents' => [], 'unmapped' => [] }
      sub_id = prop(prop(parsed, 'payload'), 'sub_id')
      set_subject = rec?(sub_id) ? sub_id : nil
      entries(prop(parsed, 'events')).each do |typ, ev|
        next if ev.equal?(UNDEF) || !revoking_standard_event?(typ, ev)

        ev_subject = prop(ev, 'subject')
        own = rec?(ev_subject) ? ev_subject : set_subject
        agent = nil
        if !own.nil? && own['format'].is_a?(String)
          agent = begin
            to_agent.call(own)
          rescue StandardError # a mapper that raises names no agent
            nil
          end
        end
        unless str_ne?(agent)
          raise SignalsError.new('unmapped_subject', "event '#{typ}' names no mappable agent") if opts['fail_on_unmapped'] == true

          plan['unmapped'] << typ
          next
        end
        plan['agents'] << [agent, ts_of(ev)]
      end
      plan
    end

    def assert_state(state)
      raise SignalsError.new('misconfigured', 'state must come from createRevocationState()') unless state.is_a?(RevocationState)
    end

    def apply_standard_revocations(state, parsed, opts = nil)
      assert_state(state)
      plan = plan_standard_revocations(parsed, opts)
      plan['agents'].each { |agent, ts| record_max(state.killed_agents, agent, ts) }
      plan
    end

    # ---- authorize() adapters ----

    def leaf_holder_agent(ctx)
      chain = prop(prop(ctx, 'pcactn'), 'cap_chain')
      raise TypeError, "Cannot read properties of undefined (reading 'length')" if chain.equal?(UNDEF) || chain.nil?

      last = chain.is_a?(Array) && !chain.empty? ? chain[-1] : nil
      h = rec?(last) ? optprop(last, 'holder') : UNDEF
      h.equal?(UNDEF) ? nil : h
    end

    def revocation_reason(state, pcactn, grant, agent_of)
      ref = prop(pcactn, 'grant_ref')
      return 'grant_ref is missing' unless str_ne?(ref)
      return 'grant revoked by signal' if state.revoked_grants.key?(ref)

      gid = optprop(grant, 'id')
      return 'grant revoked by signal' if gid.is_a?(String) && state.revoked_grants.key?(gid)

      agent = agent_of.call({ 'pcactn' => pcactn, 'grant' => grant })
      return 'agent could not be determined' unless str_ne?(agent)
      return 'agent killed by signal' if state.killed_agents.key?(agent)

      nil
    rescue StandardError
      'revocation check error (fail closed)'
    end

    # A hook for authorize(): reads `state` live, always enforced; a revoked grant, a revoked or undeterminable agent, or any
    # error denies. opts: agent_of (callable over {pcactn, grant}), default the leaf holder of the capability chain.
    def create_revocation_hook(state, opts = nil)
      assert_state(state)
      agent_of = (opts || {})['agent_of'] || method(:leaf_holder_agent)
      lambda do |ctx|
        reason = revocation_reason(state, prop(ctx, 'pcactn'), prop(ctx, 'grant'), agent_of)
        reason.nil? ? { 'enforced' => true, 'ok' => true } : { 'enforced' => true, 'ok' => false, 'reason' => reason }
      end
    end

    def create_is_revoked(state, opts = nil)
      assert_state(state)
      agent_of = (opts || {})['agent_of'] || method(:leaf_holder_agent)
      ->(grant, pcactn) { !revocation_reason(state, pcactn, grant, agent_of).nil? }
    end

    # ---- snapshot / restore ----

    def snapshot_revocation_state(state)
      assert_state(state)
      { 'v' => 1, 'grants' => state.revoked_grants.to_a, 'agents' => state.killed_agents.to_a,
        'intents' => (state.revoked_intent_ids || {}).to_a }
    end

    def pairs(v, what)
      raise SignalsError.new('bad_snapshot', "#{what} is not an array") unless v.is_a?(Array)

      v.map do |p|
        unless p.is_a?(Array) && p.length == 2 && str_ne?(p[0]) && finite_num?(p[1])
          raise SignalsError.new('bad_snapshot', "#{what} holds an entry that is not [string, number]")
        end

        [p[0], p[1]]
      end
    end

    # Merge a snapshot into `into` (a fresh state by default). Strict: any shape error raises `bad_snapshot` and `into` is
    # untouched. Monotone (max timestamp), so restoring never un-revokes.
    def restore_revocation_state(snapshot, into = DEFAULT)
      into = create_revocation_state if into.equal?(DEFAULT)
      assert_state(into)
      unless rec?(snapshot) && snapshot['v'] == 1 && Js.num?(snapshot['v'])
        raise SignalsError.new('bad_snapshot', 'snapshot is not a version 1 object')
      end

      extra = Js.js_keys(snapshot).reject { |k| %w[v grants agents intents].include?(k) }
      raise SignalsError.new('bad_snapshot', "snapshot has unknown member '#{extra[0]}'") unless extra.empty?

      grants = pairs(snapshot['grants'], 'grants')
      agents = pairs(snapshot['agents'], 'agents')
      intents = pairs(snapshot['intents'], 'intents')
      grants.each { |k, t| record_max(into.revoked_grants, k, t) }
      agents.each { |k, t| record_max(into.killed_agents, k, t) }
      intents.each do |k, t|
        into.revoked_intent_ids ||= {}
        record_max(into.revoked_intent_ids, k, t)
      end
      into
    end

    # ---- SSF stream configuration and health ----

    HTTPS_URL = /\Ahttps:\/\/[^#{Js::WS}]+\z/

    def https_url?(v) = v.is_a?(String) && HTTPS_URL.match?(v)

    # SSF 8.1.1 shape checks: the problems found (empty = valid).
    def validate_stream_config(c)
      return ['not an object'] unless c.is_a?(Hash)

      e = []
      strs = ->(x) { x.is_a?(Array) && x.all? { |i| str_ne?(i) } }
      aud = c['aud']
      e << 'stream_id is required' unless str_ne?(c['stream_id'])
      e << 'iss is required' unless str_ne?(c['iss'])
      e << 'aud must be a non-empty string or array' unless str_ne?(aud) || (aud.is_a?(Array) && !aud.empty? && aud.all? { |i| str_ne?(i) })
      delivered = c['events_delivered']
      supported = c['events_supported']
      e << 'events_delivered must be a non-empty array of event type URIs' if !strs.call(delivered) || delivered.empty?
      e << 'events_supported must be an array of URIs' if c.key?('events_supported') && !strs.call(supported)
      if c.key?('events_requested') && (!strs.call(c['events_requested']) || c['events_requested'].empty?)
        e << 'events_requested must be a non-empty array of URIs'
      end
      if strs.call(delivered) && strs.call(supported) && !delivered.all? { |x| supported.include?(x) }
        e << 'events_delivered must be a subset of events_supported'
      end
      d = c['delivery']
      if !Js.truthy?(d) || !d.is_a?(Hash) || ![DELIVERY_PUSH, DELIVERY_POLL].include?(d['method'])
        e << 'delivery.method must be the RFC 8935 or RFC 8936 URI'
      elsif !https_url?(d['endpoint_url'])
        e << 'delivery.endpoint_url must be an https URL'
      end
      if c.key?('min_verification_interval') && !nonneg_safe_int?(c['min_verification_interval'])
        e << 'min_verification_interval must be a non-negative integer (seconds)'
      end
      e
    end

    # Receiver-side health of one stream. All times are epoch seconds passed in; a verification state is single use, expiring,
    # and only valid if this tracker issued it. options: max_pending, verify_timeout_sec, verified_within_sec, fail_after.
    class StreamHealth
      attr_reader :config

      def initialize(config, options = nil)
        @config = config
        @o = options || {}
        @status = 'enabled'
        @last_event = nil
        @last_verified = nil
        @last_requested = nil
        @fails = 0
        @rejected = 0
        @pending = {}
      end

      def opt(k, d) = @o[k].nil? ? d : @o[k]

      def status=(s)
        raise ArgumentError, 'unknown stream status' unless s.is_a?(String) && STREAM_STATUSES.include?(s)

        @status = s
      end

      def record_event(now_sec)
        @last_event = [@last_event || 0, now_sec].max
      end

      def request_verification(now_sec)
        return nil unless @status == 'enabled'
        return nil unless Signals.finite_num?(now_sec)

        mn = @config['min_verification_interval'] || 0
        return nil if !@last_requested.nil? && !(now_sec - @last_requested >= mn)

        expire(now_sec)
        return nil unless @pending.length < opt('max_pending', 16)

        state = SecureRandom.urlsafe_base64(16)
        exp = now_sec + opt('verify_timeout_sec', 60)
        return nil unless Signals.finite_num?(exp) # a NaN or infinite timeout would leave the request pending forever

        @pending[state] = exp
        @last_requested = now_sec
        state
      end

      def ack_verification(state, now_sec)
        unless Signals.finite_num?(now_sec)
          @rejected += 1
          return false
        end

        expire(now_sec)
        exp = state.is_a?(String) ? @pending[state] : nil
        if exp.nil?
          @rejected += 1
          return false
        end
        @pending.delete(state)
        @last_verified = now_sec
        @last_event = [@last_event || 0, now_sec].max
        @fails = 0
        true
      end

      def report(now_sec)
        expire(now_sec)
        reasons = []
        within = opt('verified_within_sec', 300)
        state = if @status == 'disabled'
                  reasons << 'stream is disabled: no events are transmitted or held'
                  'disabled'
                elsif @status == 'paused'
                  reasons << 'stream is paused: events may be delayed'
                  'paused'
                elsif !(@fails < opt('fail_after', 3))
                  reasons << "#{@fails} consecutive verification requests timed out"
                  'failing'
                elsif @last_verified.nil?
                  reasons << 'no verification round trip has completed'
                  'unverified'
                elsif !(Signals.finite_num?(now_sec) && now_sec - @last_verified <= within)
                  reasons << "last verified #{Signals.js_num(now_sec - @last_verified)}s ago, over #{Signals.js_num(within)}s"
                  'degraded'
                else
                  'healthy'
                end
        out = { 'state' => state, 'status' => @status, 'reasons' => reasons, 'pending_verifications' => @pending.length,
                'consecutive_verification_failures' => @fails, 'rejected_verifications' => @rejected }
        out['last_event_at'] = @last_event unless @last_event.nil?
        out['last_verified_at'] = @last_verified unless @last_verified.nil?
        out
      end

      # May the verifier assume no pushed revocation was missed in the last `max_age_sec`? Only if the stream is enabled and a
      # verified round trip completed inside that window; otherwise fall back to the signed epoch pull bound.
      def revocation_fresh_within(max_age_sec, now_sec)
        @status == 'enabled' && !@last_verified.nil? && Signals.finite_num?(now_sec) && now_sec - @last_verified <= max_age_sec
      end

      private

      def expire(now_sec)
        @pending.each_key.select { |k| now_sec > @pending[k] }.each do |k|
          @pending.delete(k)
          @fails += 1
        end
      end
    end

    # SSF 8.1.4.2: 404 unknown stream, 400 malformed, 429 inside min_verification_interval, else 204 plus the signed SET.
    def handle_verification_request(streams, req, now_sec, key)
      sid = req.is_a?(Hash) ? req.fetch('stream_id', UNDEF) : UNDEF
      state = req.is_a?(Hash) ? req.fetch('state', UNDEF) : UNDEF
      if !sid.is_a?(String) || (!state.equal?(UNDEF) && !state.is_a?(String))
        return { 'status' => 400, 'error' => 'stream_id (string) is required; state must be a string' }
      end

      s = streams[sid]
      return { 'status' => 404, 'error' => 'no such stream' } if s.nil?

      mn = s['config']['min_verification_interval'] || 0
      last = s['lastVerification']
      return { 'status' => 429, 'error' => 'verification requested too soon' } if !last.nil? && now_sec - last < mn

      s['lastVerification'] = now_sec
      cfg = s['config']
      ev = state.equal?(UNDEF) ? {} : { 'state' => state }
      { 'status' => 204,
        'set' => build_set({ EVENT_TYPES['verification'] => ev }, cfg['iss'], cfg['aud'], key, subject: cfg['stream_id']) }
    end

    # RFC 8936 transmitter queue: retains a SET until acknowledged, retransmits unacknowledged ones, records receiver errors.
    # A poll request keeps its wire member names (maxEvents, ack, setErrs).
    class PollQueue
      attr_reader :errors

      def initialize
        @q = {}
        @errors = []
      end

      def enqueue(jti, set)
        @q[jti] = set
      end

      def depth = @q.length

      def poll(req)
        mx = Signals.prop(req, 'maxEvents')
        raise RangeError, 'maxEvents must be a non-negative integer' if !mx.equal?(UNDEF) && !Signals.nonneg_safe_int?(mx)

        ack = Signals.prop(req, 'ack')
        unless ack.equal?(UNDEF) || ack.nil?
          list = if ack.is_a?(Array) then ack
                 elsif ack.is_a?(String) then ack.chars
                 else raise TypeError, 'ack is not iterable'
                 end
          list.each { |j| @q.delete(j) if j.is_a?(String) }
        end
        errs = Signals.prop(req, 'setErrs')
        Signals.entries(errs.equal?(UNDEF) || errs.nil? ? {} : errs).each do |jti, e|
          next unless @q.key?(jti)

          @q.delete(jti)
          rec = { 'jti' => jti }
          %w[err description].each do |k|
            v = Signals.prop(e, k)
            rec[k] = v unless v.equal?(UNDEF)
          end
          @errors << rec
        end
        limit = mx.equal?(UNDEF) || mx.nil? ? Float::INFINITY : mx
        sets = {}
        n = 0
        @q.each do |jti, s|
          break if n >= limit

          sets[jti] = s
          n += 1
        end
        out = { 'sets' => sets }
        out['moreAvailable'] = true if @q.length > n
        out
      end
    end

    # RFC 8935 receiver status for a receive_set outcome: 202 on success, 400 + {err, description} otherwise.
    def push_response(r)
      return { 'status' => 202 } if Js.truthy?(prop(r, 'ok')) && !prop(r, 'ok').equal?(UNDEF)

      err = case prop(r, 'code')
            when 'verify_failed' then 'invalid_key'
            when 'misconfigured', 'replay_store_error' then 'access_denied'
            else 'invalid_request'
            end
      body = { 'err' => err }
      reason = prop(r, 'reason')
      body['description'] = reason unless reason.equal?(UNDEF)
      { 'status' => 400, 'body' => body }
    end

    # args: issuer, audience, key (32-byte seed), event.
    def risk_level_change_set(args)
      build_set({ EVENT_TYPES['riskLevelChange'] => args['event'] }, args['issuer'], args['audience'], args['key'])
    end

    def index_in(order, x)
      return order.index(x) || -1 if order.is_a?(Array)
      return order.index(x.is_a?(String) ? x : Js.string(x)) || -1 if order.is_a?(String)

      -1
    end

    # CAEP assurance-level-change; `change_direction` is derived when both levels are in `order`.
    def assurance_level_change_set(args)
      e = args['event'].is_a?(Hash) ? args['event'].dup : {} # an object spread of null is {}
      order = args['order']
      if e.key?('previous_level') && !e.key?('change_direction') && Js.truthy?(order)
        i = index_in(order, e['previous_level'])
        j = index_in(order, e.fetch('current_level', nil))
        e['change_direction'] = j > i ? 'increase' : 'decrease' if i >= 0 && j >= 0 && i != j
      end
      build_set({ EVENT_TYPES['assuranceLevelChange'] => e }, args['issuer'], args['audience'], args['key'])
    end

    # ---- SSF stream management API ----

    class MemoryStreamStore
      def initialize
        @m = {}
      end

      def get(id)
        r = @m[id]
        r.nil? ? nil : Marshal.load(Marshal.dump(r))
      end

      def put(id, r)
        @m[id] = Marshal.load(Marshal.dump(r))
      end

      def delete(id)
        @m.delete(id)
      end

      def list_by_receiver(receiver)
        @m.select { |_, r| r['receiver'] == receiver }.map { |i, r| [i, Marshal.load(Marshal.dump(r))] }
      end
    end

    ENDPOINTS = %w[configuration status add_subject remove_subject verification].freeze
    RECEIVER_SUPPLIED = %w[events_requested delivery description].freeze
    TRANSMITTER_SUPPLIED = %w[stream_id iss aud events_supported events_delivered min_verification_interval].freeze

    def bad(m) = { 'status' => 400, 'body' => { 'error' => 'invalid_request', 'description' => m } }

    def subject_key(s)
      return nil unless rec?(s) && str_ne?(s['format'])

      shaped = s.keys.sort_by { |k| k.encode('UTF-16BE').b }.to_h { |k| [k, s[k]] }
      "{#{Js.js_keys(shaped).map { |k| "#{Js.json_string(k)}:#{Js.json(shaped[k])}" }.join(',')}}"
    rescue StandardError
      nil
    end

    # String.prototype.slice(0, n) over UTF-16 code units.
    # shortcut: a cut inside a surrogate pair drops the pair instead of keeping a lone surrogate; fine for descriptions.
    def slice16(s, n)
      out = +''
      used = 0
      s.each_char do |c|
        w = c.ord > 0xffff ? 2 : 1
        break if used + w > n

        out << c
        used += w
      end
      out
    end

    # SSF 7.1 transmitter configuration metadata (served at /.well-known/ssf-configuration). o: issuer, delivery_methods.
    def transmitter_metadata(o, base, jwks_uri = nil)
      dm = o['delivery_methods']
      out = { 'spec_version' => '1_0' }
      out['issuer'] = o['issuer'] if o.key?('issuer')
      out['jwks_uri'] = jwks_uri if Js.truthy?(jwks_uri)
      out['delivery_methods_supported'] = dm.nil? ? [DELIVERY_PUSH, DELIVERY_POLL] : dm
      b = base.is_a?(String) ? base : Js.string(base)
      [%w[configuration_endpoint configuration], %w[status_endpoint status], %w[add_subject_endpoint add_subject],
       %w[remove_subject_endpoint remove_subject], %w[verification_endpoint verification]].each do |k, p|
        out[k] = "#{b}/ssf/#{p}"
      end
      out['default_subjects'] = 'NONE'
      out
    end

    # Framework-neutral SSF 8.1 stream management: {method, path, query, body} in, {status, body} out. `authenticate` returns
    # the receiver {id, aud} or nil (401). A stream belongs to one receiver; anyone else sees 404, never 403.
    # Options: store, issuer, events_supported, poll_endpoint(stream_id), signing_key (32-byte seed), deliver(stream, set),
    # now(), and optionally delivery_methods, max_streams_per_receiver, max_subjects_per_stream, new_id().
    def ssf_management_handler(o, authenticate)
      Manager.new(o, authenticate).method(:handle)
    end

    class Manager
      NF = { 'status' => 404, 'body' => { 'error' => 'not_found' } }.freeze
      NA = { 'status' => 405, 'body' => { 'error' => 'method_not_allowed' } }.freeze

      def initialize(o, authenticate)
        @o = o
        @auth = authenticate
        @methods = o['delivery_methods'].nil? ? [DELIVERY_PUSH, DELIVERY_POLL] : o['delivery_methods']
        @new_id = o['new_id'] || -> { SecureRandom.urlsafe_base64(12) }
        @max_streams = o['max_streams_per_receiver'].nil? ? 1 : o['max_streams_per_receiver']
        @store = o['store']
        @supported = o['events_supported']
      end

      def handle(req)
        rcv = @auth.call(req)
        return { 'status' => 401, 'body' => { 'error' => 'unauthenticated' } } unless Js.truthy?(rcv)

        route(req, rcv)
      rescue StandardError # a handler never leaks an exception
        { 'status' => 500, 'body' => { 'error' => 'server_error' } }
      end

      private

      def nf = NF.dup
      def na = NA.dup
      def bad(m) = Signals.bad(m)
      def rid(rcv) = rcv.is_a?(Hash) ? rcv['id'] : nil

      def own(rcv, id)
        return nil unless id.is_a?(String)

        r = @store.get(id)
        r && r['receiver'] == rid(rcv) ? r : nil
      end

      def delivered(requested) = requested.nil? ? @supported.dup : @supported.select { |e| requested.include?(e) }
      def requested_ok?(v) = v.is_a?(Array) && !v.empty? && v.all? { |e| Signals.str_ne?(e) }

      def delivery_for(id, d)
        if d.equal?(UNDEF)
          return [false, 'delivery is required: this transmitter does not support poll'] unless @methods.include?(DELIVERY_POLL)

          return [true, { 'method' => DELIVERY_POLL, 'endpoint_url' => @o['poll_endpoint'].call(id) }]
        end
        unless d.is_a?(Hash) && d['method'].is_a?(String) && @methods.include?(d['method'])
          return [false, 'delivery.method is not supported by this transmitter']
        end
        return [true, { 'method' => DELIVERY_POLL, 'endpoint_url' => @o['poll_endpoint'].call(id) }] if d['method'] == DELIVERY_POLL
        return [false, 'push delivery needs an https endpoint_url'] unless Signals.https_url?(d['endpoint_url'])

        [true, { 'method' => DELIVERY_PUSH, 'endpoint_url' => d['endpoint_url'] }]
      end

      def build(id, rcv, requested, delivery, description)
        cfg = { 'stream_id' => id, 'iss' => @o['issuer'], 'aud' => rcv.is_a?(Hash) ? rcv['aud'] : nil,
                'events_supported' => @supported.dup, 'events_delivered' => delivered(requested), 'delivery' => delivery }
        cfg['description'] = Signals.slice16(description, 256) unless description.nil?
        cfg
      end

      def status_body(id, s)
        out = { 'stream_id' => id, 'status' => s['status'] }
        out['reason'] = s['status_reason'] unless s['status_reason'].nil?
        { 'status' => 200, 'body' => out }
      end

      def route(req, rcv)
        path = Signals.prop(req, 'path')
        raise TypeError, 'path.split is not a function' unless path.is_a?(String)

        seg = path.split('/').reject(&:empty?).last || ''
        q = Signals.prop(req, 'query')
        q = {} if q.equal?(UNDEF) || q.nil?
        body = Signals.prop(req, 'body')
        b = body.is_a?(Hash) ? body : nil
        method = Signals.prop(req, 'method')
        raise TypeError, 'toUpperCase is not a function' unless method.is_a?(String)

        m = method.upcase
        return nf unless ENDPOINTS.include?(seg)

        qsid = Signals.prop(q, 'stream_id')
        case seg
        when 'configuration' then configuration(m, b, qsid, rcv)
        when 'status' then status(m, b, qsid, rcv)
        when 'add_subject', 'remove_subject' then subject(seg, m, b, rcv)
        else verification(m, b, rcv)
        end
      end

      def configuration(m, b, qsid, rcv)
        case m
        when 'POST'
          return bad('a JSON object body is required') if b.nil?

          Js.js_keys(b).each { |k| return bad("'#{k}' is not a receiver-supplied member") unless RECEIVER_SUPPLIED.include?(k) }
          er = b.fetch('events_requested', UNDEF)
          return bad('events_requested must be a non-empty array of event type URIs') if !er.equal?(UNDEF) && !requested_ok?(er)
          return bad('description must be a string') if b.key?('description') && !b['description'].is_a?(String)
          if @store.list_by_receiver(rid(rcv)).length >= @max_streams
            return { 'status' => 409,
                     'body' => { 'error' => 'conflict', 'description' => 'this receiver already has the maximum number of streams' } }
          end

          id = @new_id.call
          ok, d = delivery_for(id, b.fetch('delivery', UNDEF))
          return bad(d) unless ok

          req_ev = er.equal?(UNDEF) ? nil : er
          return bad('none of events_requested is supported by this transmitter') if delivered(req_ev).empty?

          config = build(id, rcv, req_ev, d, b['description'])
          problems = Signals.validate_stream_config(config)
          return bad(problems.join('; ')) unless problems.empty?

          rec = { 'receiver' => rid(rcv), 'config' => config }
          rec['events_requested'] = er if !er.equal?(UNDEF) && Js.truthy?(er)
          rec['status'] = 'enabled'
          rec['subjects'] = {}
          @store.put(id, rec)
          { 'status' => 201, 'body' => config }
        when 'GET'
          return { 'status' => 200, 'body' => @store.list_by_receiver(rid(rcv)).map { |_, r| r['config'] } } if qsid.equal?(UNDEF)

          s = own(rcv, qsid)
          s ? { 'status' => 200, 'body' => s['config'] } : nf
        when 'PATCH', 'PUT' then update(m, b, rcv)
        when 'DELETE'
          s = own(rcv, qsid)
          return nf unless s

          @store.delete(qsid)
          { 'status' => 204 }
        else na
        end
      end

      def update(m, b, rcv)
        return bad('a JSON object body is required') if b.nil?

        s = own(rcv, b['stream_id'])
        return bad('stream_id is required') unless b['stream_id'].is_a?(String)
        return nf unless s

        Js.js_keys(b).each do |k|
          return bad("unknown member '#{k}'") unless RECEIVER_SUPPLIED.include?(k) || TRANSMITTER_SUPPLIED.include?(k)
        end
        TRANSMITTER_SUPPLIED.each do |k|
          next unless b.key?(k)

          exp = s['config'].key?(k) ? Js.json(s['config'][k]) : nil
          return bad("'#{k}' is transmitter-supplied and does not match") if Js.json(b[k]) != exp
        end
        er = b.fetch('events_requested', UNDEF)
        return bad('events_requested must be a non-empty array of event type URIs') if !er.equal?(UNDEF) && !requested_ok?(er)
        return bad('description must be a string') if b.key?('description') && !b['description'].is_a?(String)

        delivery = s['config']['delivery']
        if b.key?('delivery') || m == 'PUT'
          ok, d = delivery_for(s['config']['stream_id'], b.fetch('delivery', UNDEF))
          return bad(d) unless ok
          return bad('delivery.method cannot be changed: create a new stream') if d['method'] != s['config']['delivery']['method']

          delivery = d
        end
        if m == 'PUT'
          requested = er.equal?(UNDEF) ? nil : er
          description = b['description']
        else
          requested = er.equal?(UNDEF) ? s['events_requested'] : er
          description = b.key?('description') ? b['description'] : s['config']['description']
        end
        return bad('none of events_requested is supported by this transmitter') if delivered(requested).empty?

        nxt = build(s['config']['stream_id'], rcv, requested, delivery, description)
        nxt['min_verification_interval'] = s['config']['min_verification_interval'] if s['config'].key?('min_verification_interval')
        s['config'] = nxt
        if Js.truthy?(requested)
          s['events_requested'] = requested
        else
          s.delete('events_requested')
        end
        @store.put(nxt['stream_id'], s)
        { 'status' => 200, 'body' => nxt }
      end

      def status(m, b, qsid, rcv)
        case m
        when 'GET'
          s = own(rcv, qsid)
          return qsid.equal?(UNDEF) ? bad('stream_id is required') : nf unless s

          status_body(qsid, s)
        when 'POST'
          return bad('stream_id is required') if b.nil? || !b['stream_id'].is_a?(String)
          return bad("status must be 'enabled', 'paused' or 'disabled'") unless b['status'].is_a?(String) && STREAM_STATUSES.include?(b['status'])
          return bad('reason must be a string') if b.key?('reason') && !b['reason'].is_a?(String)

          s = own(rcv, b['stream_id'])
          return nf unless s

          s['status'] = b['status']
          if b.key?('reason')
            s['status_reason'] = b['reason']
          else
            s.delete('status_reason')
          end
          @store.put(b['stream_id'], s)
          status_body(b['stream_id'], s)
        else na
        end
      end

      def subject(seg, m, b, rcv)
        return na unless m == 'POST'
        return bad('stream_id is required') if b.nil? || !b['stream_id'].is_a?(String)

        key = Signals.subject_key(b['subject'])
        return bad('subject must be a Subject Identifier object with a format') if key.nil?
        return bad('verified must be a boolean') if b.key?('verified') && ![true, false].include?(b['verified'])

        s = own(rcv, b['stream_id'])
        return nf unless s

        if seg == 'add_subject'
          cap = @o['max_subjects_per_stream'].nil? ? 10_000 : @o['max_subjects_per_stream']
          if !s['subjects'].key?(key) && s['subjects'].length >= cap
            return { 'status' => 429, 'body' => { 'error' => 'too_many_requests', 'description' => 'subject limit reached' } }
          end

          s['subjects'][key] = b.key?('verified') ? b['verified'] : true
          @store.put(b['stream_id'], s)
          return { 'status' => 200 }
        end
        s['subjects'].delete(key)
        @store.put(b['stream_id'], s)
        { 'status' => 204 }
      end

      def verification(m, b, rcv)
        return na unless m == 'POST'
        return bad('a JSON object body is required') if b.nil?

        s = own(rcv, b['stream_id'])
        return b['stream_id'].is_a?(String) ? nf : bad('stream_id is required') unless s
        return bad('the stream is disabled') if s['status'] == 'disabled'

        entry = { 'config' => s['config'] }
        entry['lastVerification'] = s['lastVerification'] unless s['lastVerification'].nil?
        vreq = { 'stream_id' => b['stream_id'] }
        vreq['state'] = b['state'] if b.key?('state')
        out = Signals.handle_verification_request({ s['config']['stream_id'] => entry }, vreq, @o['now'].call, @o['signing_key'])
        if out['status'] != 204
          return { 'status' => out['status'],
                   'body' => { 'error' => out['status'] == 429 ? 'too_many_requests' : 'invalid_request', 'description' => out['error'] } }
        end

        s['lastVerification'] = @o['now'].call
        @store.put(s['config']['stream_id'], s)
        @o['deliver'].call(s, out['set'])
        { 'status' => 204 }
      end
    end
  end
end
