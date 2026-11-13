# frozen_string_literal: true

# Negative authority (frontier 3.2): a principal-committed CONSTITUTION of invariants the agent must NEVER violate, enforced
# independently of the permission plan. Port of packages/pca/src/prohibitions.ts (the TypeScript is authoritative).
#
#   permissions GRANT, prohibitions VETO, prohibitions WIN:   allow = permitted AND prohibitions.ok
#
# Pure data and pure functions; nothing raises except the authoring-time sign helpers. Everything malformed, unknown or
# unresolvable FAILS CLOSED, and for a prohibition "closed" is the OPPOSITE of the predicate DSL's direction: a permission
# predicate that cannot be evaluated is not matched (denied), but a prohibition trigger that cannot be evaluated is MATCHED
# (the veto applies). The one exception is a positive precondition (`require_prior.prior`, `never_unless.unless`,
# `require_approval_over.approved`): it must hold AFFIRMATIVELY, so "cannot evaluate" means "not satisfied".
#
# Inputs are JSON values with String keys (Hash / Array / String / Integer / Float / true / false / nil). Results are Hashes
# with the same keys as the TypeScript objects (`decidedBy` stays camelCase: it is the shared vector spelling).
module AtlasPca
  module Prohibitions
    CONSTITUTION_VERSION = 1
    CONSTITUTION_SIG_DOMAIN = "atlas-pca/constitution/v1\0"
    EVIDENCE_VERSION = 1
    SAFETY_EVIDENCE_SIG_DOMAIN = "atlas-pca/safety-evidence/v1\0"
    STATE_DIGEST_DOMAIN = 'atlas-pca/monitor-state/v1'
    STATE_CHAIN_DOMAIN = 'atlas-pca/monitor-state-link/v1'
    MAX_LEDGER = 10_000
    MAX_INVARIANTS = 256
    MAX_STATE_ENTRIES = 100_000
    NO_PIN = Object.new.freeze # default of the optional principal pins: distinguishes "omitted" from an explicit nil
    MAX_STATE_KEYS = 1024
    MAX_ID_LEN = 128
    MAX_DEADLINE = 1_000_000
    MAX_CONDITION_DEPTH = 32
    FORBIDDEN_IDS = %w[__proto__ constructor prototype].freeze
    OPS = %w[eq ne in nin lt lte gt gte prefix exists like matches is_a member_of].freeze
    UNHASHABLE = '<unhashable>'

    module_function

    # JS Number.isFinite on a JSON value (a boolean is not a number here).
    def fin?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite?)

    # JS Number.isInteger.
    def int?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite? && x == x.floor)

    def neg_zero?(x) = x.is_a?(Float) && x.zero? && (1.0 / x).negative?

    def obj?(x) = x.is_a?(Hash)

    # JS string length (UTF-16 code units).
    def jlen(s) = AtlasPca.utf16_key(s).bytesize / 2

    # ECMAScript Number::toString for a finite JSON number (reason texts quote numbers).
    def jsn(x) = x.is_a?(Integer) ? x.to_s : Predicates.js_number_string(x)

    # String(h.k) for a JSON object member: a missing member prints "undefined", an explicit null prints "null".
    def jsm(h, k) = AtlasPca::Predicates.js_string(h.key?(k) ? h[k] : AtlasPca::Predicates::UNDEF)

    def err_safe
      yield
    rescue StandardError, SystemStackError
      UNHASHABLE
    end

    # ---- constitution commitment ----------------------------------------------------------------------------------

    # Genesis monitor state at time `now`: empty ledger, no latches, seq 0, no parent.
    def empty_state(now) = { 'now' => now, 'seq' => 0, 'parent' => nil, 'ledger' => {}, 'latched' => {} }

    def body(c) = c.reject { |k, _| k == 'id' || k == 'sig' }

    def domain_message(domain, id) = domain.b + AtlasPca.sha(id.dup.force_encoding('UTF-8').b)

    # Content address of a constitution body. Raises only on non-canonicalizable input (authoring time).
    def constitution_id(c) = AtlasPca.hash_canonical(body(c))

    # The principal signs the constitution (`key` is an AtlasPca::KeyPair). Refuses a malformed one.
    def sign_constitution(c, key)
      problems = validate_constitution(c)
      raise TypeError, "signConstitution: #{problems.join('; ')}" unless problems.empty?

      id = constitution_id(c)
      body(c).merge('id' => id, 'sig' => AtlasPca.b64e(key.sign(domain_message(CONSTITUTION_SIG_DOMAIN, id))))
    end

    # Well-formed, id matches content, signature by `expected_principal` (or the embedded one). Never raises.
    # An omitted pin means "no pin"; an explicit nil is a pin that never matches (as the reference refuses null).
    def verify_constitution(sc, expected_principal = NO_PIN)
      problems = validate_constitution(sc)
      return { 'ok' => false, 'reason' => problems[0] } unless problems.empty?
      return { 'ok' => false, 'reason' => 'principal mismatch' } if !NO_PIN.equal?(expected_principal) && sc['principal'] != expected_principal
      return { 'ok' => false, 'reason' => 'id does not match content' } unless sc['id'].is_a?(String) && sc['id'] == constitution_id(sc)
      unless sc['sig'].is_a?(String) && AtlasPca.verify_b64u(sc['principal'], domain_message(CONSTITUTION_SIG_DOMAIN, sc['id']), sc['sig'])
        return { 'ok' => false, 'reason' => 'bad signature' }
      end

      { 'ok' => true }
    rescue StandardError, SystemStackError
      { 'ok' => false, 'reason' => 'verification error (fail closed)' }
    end

    # ---- validation (strict; unknown forms are rejected, never ignored) -------------------------------------------

    def validate_condition(c, depth = 0)
      return 'condition not an object' unless obj?(c)
      return 'condition nesting too deep' if depth > MAX_CONDITION_DEPTH

      if c.key?('all_of') || c.key?('any_of') || c.key?('not')
        return validate_condition(c['not'], depth + 1) if c.key?('not')

        key = c.key?('all_of') ? 'all_of' : 'any_of'
        arr = c[key]
        return "condition.#{key} must be a non-empty array" if !arr.is_a?(Array) || arr.empty?

        arr.each do |child|
          e = validate_condition(child, depth + 1)
          return e if e
        end
        return nil
      end
      return 'condition.field missing' if !c['field'].is_a?(String) || c['field'].empty?
      return "unknown condition op #{jsm(c, 'op')}" if !c['op'].is_a?(String) || !OPS.include?(c['op'])
      return 'bad condition.ref' if c.key?('ref') && (!c['ref'].is_a?(String) || c['ref'].empty?)
      if c['op'] == 'member_of' && c.key?('collection') && (!c['collection'].is_a?(String) || c['collection'].empty?)
        return 'bad condition.collection'
      end

      nil
    end

    def validate_conditions(cs, label)
      return "#{label} must be a non-empty array" if !cs.is_a?(Array) || cs.empty?

      cs.each do |c|
        e = validate_condition(c)
        return e if e
      end
      nil
    end

    def validate_when(w, label)
      return "#{label}: not an object" unless obj?(w)

      v = w['verb']
      verb_ok = (v.is_a?(String) && !v.empty?) || (v.is_a?(Array) && !v.empty? && v.all? { |x| x.is_a?(String) && !x.empty? })
      return "#{label}: bad verb" unless verb_ok

      if w.key?('resource')
        return "#{label}: bad resource" unless w['resource'].is_a?(String)

        if w['resource'].start_with?('re:')
          src = w['resource'][3..]
          # an unsafe / over-long / uncompilable regex would make the matcher return false, so the veto would silently NOT apply
          return "#{label}: unsafe regex resource" if jlen(src) > 200 || !AtlasPca.is_safe_regex_source(src)
        end
      end
      if w.key?('where')
        return "#{label}: where not an array" unless w['where'].is_a?(Array)

        w['where'].each do |c|
          e = validate_condition(c)
          return "#{label}: #{e}" if e
        end
      end
      nil
    end

    # Structural problems with an invariant (empty = well-formed).
    def validate_invariant(inv)
      return ['invariant not an object'] unless obj?(inv)

      id = inv['id']
      return ['<no id>: missing id'] if !id.is_a?(String) || id.empty?

      err = ->(m) { ["#{id}: #{m}"] }
      return err.call('id too long') if jlen(id) > MAX_ID_LEN
      return err.call('forbidden id') if FORBIDDEN_IDS.include?(id)

      case inv['kind']
      when 'never'
        e = validate_when(inv['when'], 'when')
        e ? err.call(e) : []
      when 'never_unless'
        e = validate_when(inv['when'], 'when') || validate_conditions(inv['unless'], 'unless')
        e ? err.call(e) : []
      when 'cap'
        e = validate_when(inv['when'], 'when')
        return err.call(e) if e
        return err.call('amount must be an action.* path') if !inv['amount'].is_a?(String) || !inv['amount'].start_with?('action.')
        return err.call('max must be a finite number >= 0') if !fin?(inv['max']) || inv['max'].negative?
        return err.call('bad window_secs') if inv.key?('window_secs') && (!fin?(inv['window_secs']) || inv['window_secs'] <= 0)

        []
      when 'rate'
        e = validate_when(inv['when'], 'when')
        return err.call(e) if e

        m = inv['max']
        return err.call('max must be an integer in [0,10000]') if !int?(m) || m.negative? || neg_zero?(m) || m > MAX_LEDGER
        return err.call('window_secs must be > 0') if !fin?(inv['window_secs']) || inv['window_secs'] <= 0

        []
      when 'never_after'
        e = validate_when(inv['after'], 'after') || validate_when(inv['forbid'], 'forbid')
        e ? err.call(e) : []
      when 'require_prior'
        e = validate_when(inv['when'], 'when') || validate_when(inv['prior'], 'prior')
        e ? err.call(e) : []
      when 'require_approval_over'
        e = validate_when(inv['when'], 'when')
        return err.call(e) if e
        return err.call('amount must be an action.* path') if !inv['amount'].is_a?(String) || !inv['amount'].start_with?('action.')
        return err.call('threshold must be a finite number >= 0') if !fin?(inv['threshold']) || inv['threshold'].negative?

        e = validate_conditions(inv['approved'], 'approved')
        e ? err.call(e) : []
      else
        err.call("unknown invariant kind #{jsm(inv, 'kind')}")
      end
    end

    # Structural problems with a constitution (empty = well-formed).
    def validate_constitution(c)
      return ['constitution not an object'] unless obj?(c)

      out = []
      out << "unsupported version #{jsm(c, 'version')}" unless c['version'] == CONSTITUTION_VERSION
      out << 'principal missing' if !c['principal'].is_a?(String) || c['principal'].empty?
      return out + ['invariants not an array'] unless c['invariants'].is_a?(Array)

      out << 'too many invariants' if c['invariants'].length > MAX_INVARIANTS
      seen = {}
      c['invariants'].each do |inv|
        out.concat(validate_invariant(inv))
        id = obj?(inv) ? inv['id'] : nil
        next unless id.is_a?(String)

        out << "#{id}: duplicate id" if seen.key?(id)
        seen[id] = true
      end
      out
    end

    # ---- canonical monitor state ----------------------------------------------------------------------------------

    # Structural problem with a monitor state (nil = well-formed). Total; never raises.
    def state_problem(state)
      return 'malformed monitor state' if !obj?(state) || !fin?(state['now']) || !obj?(state['ledger']) || !obj?(state['latched'])

      seq = state['seq']
      return 'malformed monitor state: seq' if !int?(seq) || seq.negative? || neg_zero?(seq)
      return 'malformed monitor state: parent' if !state['parent'].nil? && !state['parent'].is_a?(String)
      return 'malformed monitor state: genesis has a parent' if seq.zero? && !state['parent'].nil?
      return 'malformed monitor state: missing chain link' if seq.positive? && state['parent'].nil?

      now = state['now']
      return 'malformed monitor state: too many keys' if state['ledger'].size > MAX_STATE_KEYS || state['latched'].size > MAX_STATE_KEYS

      total = 0
      state['ledger'].each do |k, l|
        return 'malformed monitor state: bad ledger key' if FORBIDDEN_IDS.include?(k) || jlen(k) > MAX_ID_LEN
        return 'malformed monitor state: bad ledger' if !l.is_a?(Array) || l.length > MAX_LEDGER

        total += l.length
        l.each do |e|
          return 'malformed monitor state: bad ledger entry' if !obj?(e) || !fin?(e['t']) || !fin?(e['amount']) || e['amount'].negative?
          # an entry from the "future" would be ignored by the window and so UNDER-count: refuse (clock regression)
          return 'malformed monitor state: ledger entry after now (clock regression)' if e['t'] > now
        end
      end
      return 'malformed monitor state: too many entries' if total > MAX_STATE_ENTRIES

      state['latched'].each do |k, t|
        return 'malformed monitor state: bad latch key' if FORBIDDEN_IDS.include?(k) || jlen(k) > MAX_ID_LEN
        return 'malformed monitor state: bad latch' if !fin?(t) || t > now
      end
      unless state['deadlines'].nil?
        dl = state['deadlines']
        return 'malformed monitor state: deadlines' unless obj?(dl)
        return 'malformed monitor state: too many deadline keys' if dl.size > MAX_STATE_KEYS

        dl.each do |k, d|
          return 'malformed monitor state: bad deadline key' if FORBIDDEN_IDS.include?(k) || jlen(k) > MAX_ID_LEN
          # an open obligation always has a strictly positive, integral remaining budget
          return 'malformed monitor state: bad deadline' if !int?(d) || d < 1 || d > MAX_DEADLINE
        end
      end
      nil
    rescue StandardError, SystemStackError
      'malformed monitor state'
    end

    def entry_key(e) = [e['t'], e['amount']]

    # Canonical, digest-committed projection of a monitor state: unknown fields dropped, ledger entries reduced to
    # {t, amount} and sorted, empty ledger arrays omitted, an empty `deadlines` omitted. Raises TypeError if malformed.
    def canonical_state(state)
      p = state_problem(state)
      raise TypeError, p if p

      ledger = {}
      state['ledger'].each_key do |k|
        l = state['ledger'][k].map { |e| { 't' => e['t'], 'amount' => e['amount'] } }.sort_by { |e| entry_key(e) }
        ledger[k] = l unless l.empty?
      end
      base = { 'd' => STATE_DIGEST_DOMAIN, 'now' => state['now'], 'seq' => state['seq'], 'parent' => state['parent'],
               'ledger' => ledger, 'latched' => state['latched'].dup }
      base['deadlines'] = state['deadlines'].dup if !state['deadlines'].nil? && !state['deadlines'].empty?
      base
    end

    def state_digest(state) = AtlasPca.hash_canonical(canonical_state(state))

    # The same state at a later `now`; refuses regression. Never raises.
    def tick_state(state, now)
      return { 'ok' => false, 'reason' => 'malformed monitor state' } if state_problem(state)
      return { 'ok' => false, 'reason' => 'clock regression' } if !fin?(now) || now < state['now']

      { 'ok' => true, 'state' => state.merge('now' => now) }
    end

    # ---- matching (conservative: unresolvable => MATCHED) ---------------------------------------------------------

    # A prohibition trigger's condition holds unless it is CLEANLY false (anything else, unknown included, vetoes).
    def condition_conservative?(c, ctx) = AtlasPca.evaluate_condition_tri(c, ctx) != 'false'

    # Does a prohibition trigger match? verb+resource exactly as the permission DSL; where-conditions conservatively. FULLY
    # fail-closed: anything that cannot be decided counts as MATCHED. Never raises.
    def when_matches?(w, ctx)
      return true if validate_when(w, 'when')

      a = ctx.is_a?(Hash) ? ctx['action'] : nil
      return true if !a.is_a?(Hash) || !a['verb'].is_a?(String) || !a['resource'].is_a?(String)

      oversized = w['resource'].is_a?(String) && w['resource'].start_with?('re:') && jlen(a['resource']) > AtlasPca::Predicates::MAX_RE_RESOURCE_LEN
      # a regex evaluation REFUSED by the document budget is "could not decide", never "no match": a veto must apply
      refused0 = AtlasPca.regex_refusals
      probe = { 'verb' => w['verb'] }
      probe['resource'] = w['resource'] if !oversized && w.key?('resource')
      return false if !AtlasPca.predicate_matches(probe, ctx) && AtlasPca.regex_refusals == refused0

      (w['where'] || []).each { |c| return false unless condition_conservative?(c, ctx) }
      true
    rescue StandardError, SystemStackError
      true # cannot evaluate => the veto applies
    end

    # AFFIRMATIVE trigger match (plain permission-DSL semantics, unresolvable => not matched).
    def when_affirmative?(w, ctx)
      validate_when(w, 'when').nil? && AtlasPca.predicate_matches(w, ctx)
    rescue StandardError, SystemStackError
      false
    end

    def all_hold?(cs, ctx) = cs.all? { |c| AtlasPca.evaluate_condition(c, ctx) }

    # ---- the monitor ----------------------------------------------------------------------------------------------

    # Window entries (sorted so float sums are order-independent). `state` must already be validated.
    def window_entries(state, id, window_secs)
      l = state['ledger'][id]
      return [] unless l.is_a?(Array)

      lo = window_secs.nil? ? -Float::INFINITY : state['now'] - (window_secs * 1000)
      l.select { |e| e['t'] > lo && e['t'] <= state['now'] }.sort_by { |e| entry_key(e) }
    end

    def eval_one(inv, ctx, state)
      case inv['kind']
      when 'never'
        when_matches?(inv['when'], ctx) ? { 'ok' => false, 'reason' => inv['description'] || 'forbidden action' } : { 'ok' => true }
      when 'never_unless'
        return { 'ok' => true } unless when_matches?(inv['when'], ctx)

        # exceptions must hold AFFIRMATIVELY (unresolvable => false => still forbidden)
        all_hold?(inv['unless'], ctx) ? { 'ok' => true } : { 'ok' => false, 'reason' => inv['description'] || 'forbidden without required condition' }
      when 'cap'
        return { 'ok' => true } unless when_matches?(inv['when'], ctx)

        a = AtlasPca.resolve_path(ctx, inv['amount'])
        return { 'ok' => false, 'reason' => 'amount unresolvable (fail closed)' } if !a['found'] || !fin?(a['value']) || a['value'].negative?

        spent = window_entries(state, inv['id'], inv['window_secs']).sum(0) { |e| e['amount'] }
        if spent + a['value'] <= inv['max']
          { 'ok' => true }
        else
          { 'ok' => false, 'reason' => "cap exceeded: #{jsn(spent)} + #{jsn(a['value'])} > #{jsn(inv['max'])}" }
        end
      when 'rate'
        return { 'ok' => true } unless when_matches?(inv['when'], ctx)

        n = window_entries(state, inv['id'], inv['window_secs']).length
        if n + 1 <= inv['max']
          { 'ok' => true }
        else
          { 'ok' => false, 'reason' => "rate exceeded: #{n + 1} > #{jsn(inv['max'])} per #{jsn(inv['window_secs'])}s" }
        end
      when 'never_after'
        return { 'ok' => true } if !state['latched'].key?(inv['id']) || !when_matches?(inv['forbid'], ctx)

        { 'ok' => false, 'reason' => inv['description'] || 'forbidden after trigger' }
      when 'require_prior'
        return { 'ok' => true } unless when_matches?(inv['when'], ctx)

        state['latched'].key?(inv['id']) ? { 'ok' => true } : { 'ok' => false, 'reason' => inv['description'] || 'required prior action not admitted' }
      when 'require_approval_over'
        return { 'ok' => true } unless when_matches?(inv['when'], ctx)

        a = AtlasPca.resolve_path(ctx, inv['amount'])
        over = !a['found'] || !fin?(a['value']) || a['value'].negative? || a['value'] > inv['threshold'] # unresolvable => over
        return { 'ok' => true } unless over

        all_hold?(inv['approved'], ctx) ? { 'ok' => true } : { 'ok' => false, 'reason' => inv['description'] || "approval required over #{jsn(inv['threshold'])}" }
      end
    end

    # Evaluate EVERY invariant (no short-circuit) against the action and running state. Pure, total, fail-closed.
    def check_prohibitions(action, constitution, state)
      # the WHOLE constitution is one document: every invariant and condition shares one regex budget
      AtlasPca.with_regex_budget { check_prohibitions_inner(action, constitution, state) }
    end

    def structural_fail(id, reason)
      { 'ok' => false, 'violated' => [id], 'reasons' => [reason], 'evaluated' => [{ 'id' => id, 'kind' => 'structural', 'result' => 'violated', 'reason' => reason }] }
    end

    def action_ok?(action)
      a = action.is_a?(Hash) ? action['action'] : nil
      a.is_a?(Hash) && a['verb'].is_a?(String) && a['resource'].is_a?(String)
    end

    def check_prohibitions_inner(action, constitution, state)
      cp = validate_constitution(constitution)
      return structural_fail('<constitution>', cp[0]) unless cp.empty?
      return structural_fail('<action>', 'malformed action') unless action_ok?(action)

      sp = state_problem(state)
      return structural_fail('<state>', sp) if sp

      evaluated = constitution['invariants'].map do |inv|
        r = begin
          eval_one(inv, action, state)
        rescue StandardError, SystemStackError
          { 'ok' => false, 'reason' => 'evaluation error (fail closed)' }
        end
        row = { 'id' => inv['id'], 'kind' => inv['kind'], 'result' => r['ok'] ? 'pass' : 'violated' }
        row['reason'] = r['reason'] if r['reason'] && !r['reason'].empty?
        row
      end
      bad = evaluated.select { |e| e['result'] == 'violated' }
      { 'ok' => bad.empty?, 'violated' => bad.map { |e| e['id'] }, 'reasons' => bad.map { |e| "#{e['id']}: #{e['reason'] || 'violated'}" }, 'evaluated' => evaluated }
    rescue StandardError, SystemStackError
      structural_fail('<monitor>', 'monitor error (fail closed)')
    end

    # Pure, deterministic state transition for an ADMITTED action. Returns {'ok'=>true,'state'=>s} or {'ok'=>false,'reason'=>r};
    # never a silently unchanged state, because a dropped contribution would UNDER-count a cap. Never raises.
    def advance_state_strict(action, constitution, state, now = :unset)
      now = state.is_a?(Hash) ? state['now'] : nil if now == :unset
      AtlasPca.with_regex_budget { advance_state_strict_inner(action, constitution, state, now) }
    end

    def advance_state_strict_inner(action, constitution, state, now)
      cp = validate_constitution(constitution)
      return { 'ok' => false, 'reason' => cp[0] } unless cp.empty?

      sp = state_problem(state)
      return { 'ok' => false, 'reason' => sp } if sp
      return { 'ok' => false, 'reason' => 'clock regression' } if !fin?(now) || now < state['now']
      return { 'ok' => false, 'reason' => 'malformed action' } unless action_ok?(action)

      canon = canonical_state(state)
      prev_digest = AtlasPca.hash_canonical(canon)
      action_digest = AtlasPca.hash_canonical(action)
      ledger = canon['ledger'].transform_values(&:dup)
      latched = canon['latched'].dup
      constitution['invariants'].each do |inv|
        case inv['kind']
        when 'cap', 'rate'
          prev = ledger[inv['id']] || []
          lo = inv['window_secs'].nil? ? -Float::INFINITY : now - (inv['window_secs'] * 1000)
          kept = prev.select { |e| e['t'] > lo }
          if when_matches?(inv['when'], action)
            amount = 1
            if inv['kind'] == 'cap'
              r = AtlasPca.resolve_path(action, inv['amount'])
              return { 'ok' => false, 'reason' => "#{inv['id']}: amount unresolvable" } if !r['found'] || !fin?(r['value']) || r['value'].negative?

              amount = r['value']
            end
            kept << { 't' => now, 'amount' => amount }
          end
          kept = kept.sort_by { |e| entry_key(e) }
          if kept.length > MAX_LEDGER
            return { 'ok' => false, 'reason' => "#{inv['id']}: rate ledger overflow" } if inv['kind'] == 'rate'

            while kept.length > MAX_LEDGER
              x, y = kept.shift(2) # merge the oldest two; keeps the LATER time, so a cap is never under-counted
              kept.unshift({ 't' => y['t'], 'amount' => x['amount'] + y['amount'] })
            end
          end
          if kept.empty? then ledger.delete(inv['id']) else ledger[inv['id']] = kept end
        when 'never_after'
          # conservative match: an ambiguous trigger latches (stricter)
          latched[inv['id']] = now if !latched.key?(inv['id']) && when_matches?(inv['after'], action)
        when 'require_prior'
          # AFFIRMATIVE match: an ambiguous prerequisite must NOT count as satisfied
          latched[inv['id']] = now if !latched.key?(inv['id']) && when_affirmative?(inv['prior'], action)
        end
      end
      nxt = { 'now' => now, 'seq' => state['seq'] + 1,
              'parent' => AtlasPca.hash_canonical({ 'd' => STATE_CHAIN_DOMAIN, 'state' => prev_digest, 'action' => action_digest }),
              'ledger' => ledger, 'latched' => latched }
      return { 'ok' => false, 'reason' => 'resulting state invalid' } if state_problem(nxt)

      { 'ok' => true, 'state' => nxt }
    rescue StandardError, SystemStackError
      { 'ok' => false, 'reason' => 'advance error (fail closed)' }
    end

    # advance_state_strict that returns the INPUT state on failure (prefer the strict form wherever a no-op would be unsafe).
    def advance_state(action, constitution, state, now = :unset)
      r = advance_state_strict(action, constitution, state, now)
      r['ok'] ? r['state'] : state
    end

    # ---- per-action safety evidence -------------------------------------------------------------------------------

    # Build the evidence a verifier re-checks. Never raises. Anything that cannot be digested makes it ok:false.
    def prove_safety(action, constitution, state) = evidence_from(check_prohibitions(action, constitution, state), action, constitution, state)

    def evidence_from(r, action, constitution, state)
      cid = err_safe { constitution_id(constitution) }
      adg = err_safe { AtlasPca.hash_canonical(action) }
      sdg = err_safe { state_digest(state) }
      extra = []
      extra << '<constitution>' if cid == UNHASHABLE
      extra << '<action>' if adg == UNHASHABLE
      extra << '<state>' if sdg == UNHASHABLE
      { 'v' => EVIDENCE_VERSION, 'constitution' => cid, 'action_digest' => adg, 'state_digest' => sdg,
        'now' => state.is_a?(Hash) && fin?(state['now']) ? state['now'] : 0,
        'evaluated' => r['evaluated'].map(&:dup), # the evidence never aliases the decision's result
        'ok' => r['ok'] && extra.empty?,
        'violated' => r['violated'] + extra.reject { |x| r['violated'].include?(x) } }
    end

    # Digest of an evidence record.
    def evidence_digest(e) = AtlasPca.hash_canonical(e)

    # Offline re-check: recompute from (action, constitution, state); the evidence must match EXACTLY. Never raises.
    def verify_safety_evidence(evidence, action, constitution, state)
      return { 'ok' => false, 'reason' => 'unsupported evidence version' } if !obj?(evidence) || evidence['v'] != EVIDENCE_VERSION

      fresh = prove_safety(action, constitution, state)
      return { 'ok' => false, 'reason' => 'constitution mismatch' } if fresh['constitution'] != evidence['constitution']
      return { 'ok' => false, 'reason' => 'action digest mismatch' } if fresh['action_digest'] != evidence['action_digest']
      return { 'ok' => false, 'reason' => 'state digest mismatch' } if fresh['state_digest'] != evidence['state_digest']
      return { 'ok' => false, 'reason' => 'evidence does not reproduce' } if AtlasPca.hash_canonical(fresh) != AtlasPca.hash_canonical(evidence)
      return { 'ok' => false, 'reason' => "prohibition violated: #{fresh['violated'].join(',')}" } unless fresh['ok']

      { 'ok' => true }
    rescue StandardError, SystemStackError
      { 'ok' => false, 'reason' => 'verification error (fail closed)' }
    end

    # ---- signed + bound safety evidence ---------------------------------------------------------------------------

    # Binding id: commits to signer + evidence digest + the three bound digests. Raises on unhashable evidence or a missing digest.
    def safety_binding_id(evidence, signer)
      AtlasPca.hash_canonical({ 'd' => SAFETY_EVIDENCE_SIG_DOMAIN, 'signer' => signer, 'evidence' => AtlasPca.hash_canonical(evidence),
                                'constitution' => evidence.fetch('constitution'), 'action_digest' => evidence.fetch('action_digest'),
                                'state_digest' => evidence.fetch('state_digest') })
    end

    # Sign evidence (Ed25519, domain-separated; `key` is an AtlasPca::KeyPair). Refuses evidence that could not be digested.
    def sign_safety_evidence(evidence, key)
      raise TypeError, 'signSafetyEvidence: unsupported evidence' if !obj?(evidence) || evidence['v'] != EVIDENCE_VERSION

      [evidence['constitution'], evidence['action_digest'], evidence['state_digest']].each do |d|
        raise TypeError, 'signSafetyEvidence: unbound evidence' if !d.is_a?(String) || d.empty? || d == UNHASHABLE
      end
      pub = key.public
      raise TypeError, 'signSafetyEvidence: signer missing' if !pub.is_a?(String) || pub.empty?

      id = safety_binding_id(evidence, pub)
      { 'evidence' => evidence, 'signer' => pub, 'id' => id, 'sig' => AtlasPca.b64e(key.sign(domain_message(SAFETY_EVIDENCE_SIG_DOMAIN, id))) }
    end

    # Verify signed evidence offline against what the verifier already knows (`expected`: signer, action | actionDigest,
    # constitution | constitutionId, principal, state | stateDigest, requireOk). Never raises.
    def verify_signed_safety_evidence(signed, expected)
      no = ->(reason) { { 'ok' => false, 'reason' => reason } }
      return no.call('malformed input') if !obj?(signed) || !obj?(signed['evidence']) || !obj?(expected)

      ev = signed['evidence']
      return no.call('unsupported evidence version') if ev['v'] != EVIDENCE_VERSION

      signers = expected['signer'].is_a?(Array) ? expected['signer'] : [expected['signer']]
      return no.call('no pinned signer') if signers.empty? || signers.any? { |s| !s.is_a?(String) || s.empty? }
      return no.call('signer not trusted') if !signed['signer'].is_a?(String) || !signers.include?(signed['signer'])
      return no.call('unbound: action not specified') if !expected.key?('action') && !expected.key?('actionDigest')
      return no.call('unbound: constitution not specified') if !expected.key?('constitution') && !expected.key?('constitutionId')
      return no.call('unbound: state not specified') if !expected.key?('state') && !expected.key?('stateDigest')
      return no.call('binding id mismatch') if !signed['id'].is_a?(String) || signed['id'] != safety_binding_id(ev, signed['signer'])
      unless signed['sig'].is_a?(String) && AtlasPca.verify_b64u(signed['signer'], domain_message(SAFETY_EVIDENCE_SIG_DOMAIN, signed['id']), signed['sig'])
        return no.call('bad signature')
      end

      want_action = expected.key?('action') ? AtlasPca.hash_canonical(expected['action']) : expected['actionDigest']
      return no.call('expected action and digest disagree') if expected.key?('action') && expected.key?('actionDigest') && expected['actionDigest'] != want_action
      return no.call('action digest mismatch (evidence bound to another action)') if ev['action_digest'] != want_action

      if expected.key?('principal')
        sc = expected['constitution']
        return no.call('principal pin requires a signed constitution') if !obj?(sc) || !sc['sig'].is_a?(String)

        vc = verify_constitution(sc, expected['principal'])
        return no.call("constitution not authentic: #{vc['reason']}") unless vc['ok']
      end
      want_const = expected.key?('constitution') ? constitution_id(expected['constitution']) : expected['constitutionId']
      return no.call('expected constitution and id disagree') if expected.key?('constitution') && expected.key?('constitutionId') && expected['constitutionId'] != want_const
      return no.call('constitution mismatch (evidence bound to another constitution)') if ev['constitution'] != want_const
      # a malformed expected constitution never verifies: an invariant without a string id would otherwise "cover" an id-less row
      if expected.key?('constitution')
        cp = validate_constitution(expected['constitution'])
        return no.call("constitution malformed: #{cp[0]}") unless cp.empty?
      end

      want_state = expected.key?('state') ? state_digest(expected['state']) : expected['stateDigest']
      return no.call('expected state and digest disagree') if expected.key?('state') && expected.key?('stateDigest') && expected['stateDigest'] != want_state
      return no.call('state digest mismatch (evidence bound to another state)') if ev['state_digest'] != want_state

      # internal consistency: the claimed verdict must follow from the claimed rows
      return no.call('malformed evidence') if !ev['evaluated'].is_a?(Array) || !ev['violated'].is_a?(Array)

      return no.call('malformed evidence') if ev['evaluated'].any? { |r| obj?(r) && r.key?('id') && !r['id'].is_a?(String) }

      bad_rows = ev['evaluated'].reject { |r| obj?(r) && r['result'] == 'pass' }
      return no.call('evidence verdict inconsistent with rows') if ev['ok'] != (bad_rows.empty? && ev['violated'].empty?)

      if expected.key?('action') && expected.key?('constitution') && expected.key?('state')
        full = verify_safety_evidence(ev, expected['action'], expected['constitution'], expected['state'])
        return no.call(full['reason'] || 'evidence does not reproduce') if !full['ok'] && ev['ok']
        return no.call(full['reason']) if !full['ok'] && !ev['ok'] && !full['reason'].nil? && !full['reason'].start_with?('prohibition violated')
      elsif ev['ok'] && expected.key?('constitution')
        ids = expected['constitution']['invariants'].map { |i| i['id'] }
        return no.call('evidence does not cover every invariant') if ev['evaluated'].length != ids.length || ev['evaluated'].each_with_index.any? { |r, i| (obj?(r) ? r['id'] : nil) != ids[i] }
      end
      return no.call("prohibition violated: #{ev['violated'].join(',')}") if expected['requireOk'] != false && !ev['ok']

      { 'ok' => true }
    rescue StandardError, SystemStackError
      { 'ok' => false, 'reason' => 'verification error (fail closed)' }
    end

    # ---- composition: permissions grant, prohibitions veto --------------------------------------------------------

    # allow = permitted AND prohibitions.ok. The monitor runs unconditionally so denial reasons are complete.
    def compose_authority(permitted, action, constitution, state) = compose_from(permitted, check_prohibitions(action, constitution, state))

    def compose_from(permitted, prohibition)
      p = permitted == true
      { 'allow' => p && prohibition['ok'], 'decidedBy' => !prohibition['ok'] ? 'prohibition' : (p ? 'none' : 'permission'),
        'permitted' => p, 'prohibition' => prohibition }
    end

    # Pure kernel of the server's critical section: guard the head (CAS), compose authority, build evidence against the
    # pre-state, and on allow compute the next state. Persisting `next` iff allow MUST happen in the same atomic step that
    # read `state`. `opts`: 'expectedSeq', 'expectedStateDigest'. Never raises.
    def check_and_advance(permitted, action, constitution, state, opts = {})
      monitored = check_prohibitions(action, constitution, state)
      evidence = evidence_from(monitored, action, constitution, state)
      decision = compose_from(permitted, monitored)
      refuse = lambda do |decided_by, reason = nil|
        r = { 'allow' => false, 'decidedBy' => decided_by, 'evidence' => evidence, 'prohibition' => decision['prohibition'], 'next' => state }
        r['reason'] = reason if reason && !reason.empty?
        r
      end
      begin
        return refuse.call('state', 'stale state head (seq)') if opts.key?('expectedSeq') && (!obj?(state) || state['seq'] != opts['expectedSeq'])
        if opts.key?('expectedStateDigest') && err_safe { state_digest(state) } != opts['expectedStateDigest']
          return refuse.call('state', 'stale state head (digest)')
        end
        return refuse.call(decision['decidedBy'] == 'none' ? 'permission' : decision['decidedBy']) unless decision['allow']
        return refuse.call('prohibition', 'evidence not attestable') unless evidence['ok']

        adv = advance_state_strict(action, constitution, state)
        return refuse.call('state', "advance failed: #{adv['reason']}") unless adv['ok']

        { 'allow' => true, 'decidedBy' => 'none', 'evidence' => evidence, 'prohibition' => decision['prohibition'], 'next' => adv['state'] }
      rescue StandardError, SystemStackError
        refuse.call('state', 'check-and-advance error (fail closed)')
      end
    end
  end
end
