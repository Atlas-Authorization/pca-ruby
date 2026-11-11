# frozen_string_literal: true

# Bounded safety-LTL behavioural contracts (PCA frontier B2, v1) and their durable enforcer. Port of
# packages/pca/src/contracts.ts and contract-enforcer.ts (the TypeScript is authoritative).
#
# A contract is an optional embedded prohibition constitution PLUS a set of temporal clauses, run against one shared,
# hash-chained monitor state: `always P` (affirmative), `never P` (conservative), `precedes` / `requires_prior`, bounded
# `responds_within N`, and `and`. A contract with no clauses is exactly the prohibition monitor. Pure data and total pure
# functions: everything malformed, unknown or unresolvable FAILS CLOSED as the prohibition monitor does.
#
# Inputs are JSON values with String keys; results are Hashes with the shared vector keys (`decidedBy` stays camelCase).
module AtlasPca
  module Contracts
    CONTRACT_VERSION = 1
    CONTRACT_SIG_DOMAIN = "atlas-pca/contract/v1\0"
    MAX_CLAUSES = 256
    MAX_CLAUSE_DEPTH = 16
    MAX_ID_LEN = 128
    FORBIDDEN_IDS = %w[__proto__ constructor prototype].freeze
    UNHASHABLE = '<unhashable>'
    P = Prohibitions

    module_function

    def obj?(x) = x.is_a?(Hash)

    def safe_str
      yield
    rescue StandardError, SystemStackError
      UNHASHABLE
    end

    # ---- validation -------------------------------------------------------------------------------------------------

    # Structural problems with a clause (empty = well-formed). Collects every id into `seen` (global uniqueness); `depth` bounds nesting.
    def validate_clause(cl, seen, depth)
      return ['clause nesting too deep'] if depth > MAX_CLAUSE_DEPTH
      return ['clause not an object'] unless obj?(cl)

      id = cl['id']
      return ['<no id>: missing clause id'] if !id.is_a?(String) || id.empty?

      err = ->(m) { ["#{id}: #{m}"] }
      return err.call('id too long') if P.jlen(id) > MAX_ID_LEN
      return err.call('forbidden id') if FORBIDDEN_IDS.include?(id)
      return err.call('duplicate id') if seen.key?(id)

      seen[id] = true
      case cl['kind']
      when 'always', 'never'
        e = P.validate_when(cl['p'], 'p')
        e ? err.call(e) : []
      when 'precedes', 'requires_prior'
        e = P.validate_when(cl['p'], 'p') || P.validate_when(cl['q'], 'q')
        e ? err.call(e) : []
      when 'responds_within'
        e = P.validate_when(cl['p'], 'p') || P.validate_when(cl['q'], 'q')
        return err.call(e) if e

        w = cl['within']
        return err.call('within must be an integer in [1, MAX_DEADLINE]') if !P.int?(w) || w < 1 || w > P::MAX_DEADLINE

        []
      when 'and'
        subs = cl['clauses']
        return err.call('and.clauses must be a non-empty array') if !subs.is_a?(Array) || subs.empty?

        subs.flat_map { |sub| validate_clause(sub, seen, depth + 1) }
      else
        err.call("unknown clause kind #{AtlasPca::Predicates.js_string(cl['kind'])}")
      end
    end

    # Count clauses (including nested). An absurdly deep nest is "too many" at once, never a stack overflow.
    def count_clauses(cls, depth = 1)
      return MAX_CLAUSES + 1 if depth > MAX_CLAUSE_DEPTH + 1

      n = 0
      cls.each do |cl|
        n += 1
        n += count_clauses(cl['clauses'], depth + 1) if obj?(cl) && cl['kind'] == 'and' && cl['clauses'].is_a?(Array)
      end
      n
    end

    # Structural problems with a contract (empty = well-formed). Total; never raises.
    def validate_contract(c)
      return ['contract not an object'] unless obj?(c)

      out = []
      out << "unsupported version #{AtlasPca::Predicates.js_string(c['version'])}" unless c['version'] == CONTRACT_VERSION
      out << 'principal missing' if !c['principal'].is_a?(String) || c['principal'].empty?
      ids = {}
      if c.key?('invariants')
        invariants = c['invariants']
        return out + ['invariants not an array'] unless invariants.is_a?(Array)

        out << 'too many invariants' if invariants.length > P::MAX_INVARIANTS
        invariants.each do |inv|
          out.concat(P.validate_invariant(inv))
          id = obj?(inv) ? inv['id'] : nil
          next unless id.is_a?(String)

          out << "#{id}: duplicate id" if ids.key?(id)
          ids[id] = true
        end
      end
      if c.key?('clauses')
        clauses = c['clauses']
        return out + ['clauses not an array'] unless clauses.is_a?(Array)

        out << 'too many clauses' if count_clauses(clauses) > MAX_CLAUSES
        # clause ids must be globally unique AND disjoint from the constitution invariant ids (shared state keys)
        clauses.each { |cl| out.concat(validate_clause(cl, ids, 1)) }
      end
      out
    end

    # ---- contract commitment ----------------------------------------------------------------------------------------

    def body(c) = c.reject { |k, _| k == 'id' || k == 'sig' }

    # Content address of a contract body. Raises only on non-canonicalizable input (authoring time).
    def contract_id(c) = AtlasPca.hash_canonical(body(c))

    # The principal signs the contract (`key` is an AtlasPca::KeyPair). Refuses a malformed one.
    def sign_contract(c, key)
      problems = validate_contract(c)
      raise TypeError, "signContract: #{problems.join('; ')}" unless problems.empty?

      id = contract_id(c)
      body(c).merge('id' => id, 'sig' => AtlasPca.b64e(key.sign(P.domain_message(CONTRACT_SIG_DOMAIN, id))))
    end

    # Well-formed, id matches content, signature by `expected_principal` (or the embedded one). Never raises.
    def verify_contract(sc, expected_principal = nil)
      problems = validate_contract(sc)
      return { 'ok' => false, 'reason' => problems[0] } unless problems.empty?
      return { 'ok' => false, 'reason' => 'principal mismatch' } if !expected_principal.nil? && sc['principal'] != expected_principal
      return { 'ok' => false, 'reason' => 'id does not match content' } unless sc['id'].is_a?(String) && sc['id'] == contract_id(sc)
      unless sc['sig'].is_a?(String) && AtlasPca.verify_b64u(sc['principal'], P.domain_message(CONTRACT_SIG_DOMAIN, sc['id']), sc['sig'])
        return { 'ok' => false, 'reason' => 'bad signature' }
      end

      { 'ok' => true }
    rescue StandardError, SystemStackError
      { 'ok' => false, 'reason' => 'verification error (fail closed)' }
    end

    # The embedded prohibition constitution of a contract (empty when `invariants` is omitted).
    def embedded_constitution(c)
      { 'version' => 1, 'principal' => c['principal'], 'invariants' => c['invariants'].is_a?(Array) ? c['invariants'] : [] }
    end

    # Lift a plain prohibition constitution into the degenerate contract (no temporal clauses).
    def contract_from_constitution(c)
      { 'version' => CONTRACT_VERSION, 'principal' => c['principal'], 'invariants' => c['invariants'], 'clauses' => [] }
    end

    # ---- clause evaluation (per-action transition) ------------------------------------------------------------------

    def row(cl, ok, reason)
      r = { 'id' => cl['id'], 'kind' => cl['kind'], 'result' => ok ? 'pass' : 'violated' }
      r['reason'] = reason if reason && !reason.empty?
      r
    end

    def base_transition(cl, ok, reason = nil)
      { ok: ok, reason: reason, rows: [row(cl, ok, reason)], latch_set: {}, deadline_set: {} }
    end

    # Per-clause transition against ONE action and the pre-state: the verdict plus the intended state updates (`latch_set`:
    # precedence latches to set now; `deadline_set`: new bounded-liveness budget, or nil to clear an open obligation). The
    # updates are applied to the next state ONLY if the whole contract is ok.
    def eval_clause(cl, ctx, state, now)
      latched = state['latched']
      deadlines = state['deadlines'] || {}
      case cl['kind']
      when 'always'
        P.when_affirmative?(cl['p'], ctx) ? base_transition(cl, true) : base_transition(cl, false, cl['description'] || 'always-invariant violated (action does not satisfy p)')
      when 'never'
        P.when_matches?(cl['p'], ctx) ? base_transition(cl, false, cl['description'] || 'never-invariant violated (forbidden action)') : base_transition(cl, true)
      when 'precedes', 'requires_prior'
        is_q = P.when_matches?(cl['q'], ctx) # the guarded action, conservative
        held = !is_q || latched.key?(cl['id'])
        t = base_transition(cl, held, held ? nil : cl['description'] || 'precedence violated (prerequisite p not yet admitted before q)')
        # latch the prerequisite on an AFFIRMATIVE match (an ambiguous prerequisite must not count)
        t[:latch_set][cl['id']] = now if !latched.key?(cl['id']) && P.when_affirmative?(cl['p'], ctx)
        t
      when 'responds_within'
        violated = false
        carried = nil # budget carried from an existing obligation (not yet discharged)
        if deadlines.key?(cl['id'])
          cur = deadlines[cl['id']]
          if P.when_affirmative?(cl['q'], ctx)
            carried = nil # any response discharges all open obligations
          else
            r = cur - 1
            if r <= 0 then violated = true # window exhausted with no response => violation at this action
            else carried = r
            end
          end
        end
        reason = violated ? cl['description'] || "bounded-liveness deadline missed (no q within #{P.jsn(cl['within'])} actions of p)" : nil
        rows = [row(cl, !violated, reason)]
        return { ok: false, reason: reason, rows: rows, latch_set: {}, deadline_set: {} } if violated

        # a (conservative) stimulus opens a fresh obligation of budget `within`; the binding deadline is the MOST URGENT open one
        nxt = carried
        nxt = nxt.nil? ? cl['within'] : [nxt, cl['within']].min if P.when_matches?(cl['p'], ctx)
        { ok: true, reason: nil, rows: rows, latch_set: {}, deadline_set: { cl['id'] => nxt } }
      when 'and'
        rows = []
        latch_set = {}
        deadline_set = {}
        ok = true
        reason = nil
        cl['clauses'].each do |sub|
          r = eval_clause(sub, ctx, state, now)
          rows.concat(r[:rows])
          latch_set.merge!(r[:latch_set])
          deadline_set.merge!(r[:deadline_set])
          if !r[:ok] && ok
            ok = false
            reason = r[:reason]
          end
        end
        # the `and` itself emits no row: its children's rows carry the detail (ok rolls up)
        { ok: ok, reason: reason, rows: rows, latch_set: latch_set, deadline_set: deadline_set }
      else
        base_transition(cl, false, 'unknown clause kind (fail closed)')
      end
    rescue StandardError, SystemStackError
      base_transition(cl, false, 'clause evaluation error (fail closed)')
    end

    # ---- the contract monitor ---------------------------------------------------------------------------------------

    # Evaluate a whole contract (embedded constitution + temporal clauses) against one action and the running state,
    # WITHOUT advancing. Pure, total, fail-closed; every invariant and clause is evaluated (no short-circuit).
    def check_contract(action, contract, state)
      # the whole contract (embedded constitution + every clause) is one document for the regex budget
      AtlasPca.with_regex_budget { check_contract_inner(action, contract, state) }
    end

    def contract_fail(id, reason)
      { 'ok' => false, 'violated' => [id], 'reasons' => ["#{id}: #{reason}"], 'evaluated' => [{ 'id' => id, 'kind' => 'structural', 'result' => 'violated', 'reason' => reason }] }
    end

    def check_contract_inner(action, contract, state)
      cp = validate_contract(contract)
      return contract_fail('<contract>', cp[0]) unless cp.empty?
      return contract_fail('<action>', 'malformed action') unless P.action_ok?(action)

      sp = P.state_problem(state)
      return contract_fail('<state>', sp) if sp

      evaluated = []
      constitution = embedded_constitution(contract)
      evaluated.concat(P.check_prohibitions(action, constitution, state)['evaluated']) unless constitution['invariants'].empty?
      now = state['now']
      (contract['clauses'] || []).each do |cl|
        t = begin
          eval_clause(cl, action, state, now)
        rescue StandardError, SystemStackError
          { rows: [row({ 'id' => cl['id'], 'kind' => cl['kind'] || 'clause' }, false, 'clause evaluation error (fail closed)')] }
        end
        evaluated.concat(t[:rows])
      end
      bad = evaluated.select { |e| e['result'] == 'violated' }
      { 'ok' => bad.empty?, 'violated' => bad.map { |e| e['id'] }, 'reasons' => bad.map { |e| "#{e['id']}: #{e['reason'] || 'violated'}" }, 'evaluated' => evaluated }
    rescue StandardError, SystemStackError
      contract_fail('<monitor>', 'monitor error (fail closed)')
    end

    # Check the whole contract against one action and, iff it holds, advance the hash-chained monitor state exactly like the
    # prohibition monitor, overlaying the clauses' precedence latches and bounded-liveness deadline counters. Fail-closed on
    # anything unresolvable or on a stale chain head; `next` is then the input state, unchanged. `opts`: 'expectedSeq',
    # 'expectedStateDigest', 'now'. Never raises.
    def advance_contract(state, action, contract, opts = {})
      refuse = lambda do |decided_by, r = nil, reason = nil|
        base = r || check_contract(action, contract, state)
        { 'ok' => false,
          'violated' => reason ? base['violated'].reject { |v| v == '<state>' } + ['<state>'] : base['violated'],
          'reasons' => reason ? base['reasons'] + ["<state>: #{reason}"] : base['reasons'],
          'evaluated' => base['evaluated'], 'next' => state, 'decidedBy' => decided_by }
      end
      begin
        now = opts['now'].nil? ? (state.is_a?(Hash) ? state['now'] : nil) : opts['now']
        # CAS on the chain head FIRST: a rolled-back / stale state is refused before anything else
        return refuse.call('state', nil, 'stale state head (seq)') if !opts['expectedSeq'].nil? && (!obj?(state) || state['seq'] != opts['expectedSeq'])
        if !opts['expectedStateDigest'].nil? && safe_str { P.state_digest(state) } != opts['expectedStateDigest']
          return refuse.call('state', nil, 'stale state head (digest)')
        end

        verdict = check_contract(action, contract, state)
        unless verdict['ok']
          structural = verdict['violated'].any? { |v| v.start_with?('<') && v.end_with?('>') }
          return verdict.merge('next' => state, 'decidedBy' => structural ? 'state' : 'contract')
        end

        constitution = embedded_constitution(contract)
        adv = P.advance_state_strict(action, constitution, state, now)
        return refuse.call('state', verdict, "advance failed: #{adv['reason']}") unless adv['ok']

        # overlay the temporal clauses' state, recomputed against the PRE-state (the same transitions the verdict used)
        latched = adv['state']['latched'].dup
        deadlines = (state['deadlines'] || {}).dup
        # a second evaluation pass of the same clauses: its own document budget
        AtlasPca.with_regex_budget do
          (contract['clauses'] || []).each do |cl|
            t = eval_clause(cl, action, state, now)
            t[:latch_set].each { |k, v| latched[k] = v unless latched.key?(k) }
            t[:deadline_set].each { |k, v| v.nil? ? deadlines.delete(k) : deadlines[k] = v }
          end
        end
        nxt = adv['state'].merge('latched' => latched)
        nxt['deadlines'] = deadlines unless deadlines.empty?
        sp = P.state_problem(nxt)
        return refuse.call('state', verdict, "resulting state invalid: #{sp}") if sp

        verdict.merge('next' => nxt, 'decidedBy' => 'none')
      rescue StandardError, SystemStackError
        refuse.call('state', nil, 'advance error (fail closed)')
      end
    end

    # allow = permitted AND contract.ok, and on allow the state advances. The permission verdict is an INPUT that can only be
    # ANDed; the contract monitor runs unconditionally so denial reasons are complete.
    def check_and_advance_contract(permitted, state, action, contract, opts = {})
      adv = advance_contract(state, action, contract, opts)
      p = permitted == true
      return adv.merge('allow' => false, 'permitted' => p) unless adv['ok']

      unless p
        return { 'ok' => false, 'violated' => adv['violated'], 'reasons' => adv['reasons'] + ['<permission>: not permitted'], 'evaluated' => adv['evaluated'],
                 'next' => state, 'decidedBy' => 'contract', 'allow' => false, 'permitted' => p }
      end

      adv.merge('allow' => true, 'permitted' => p)
    end

    # ---- durable enforcement (contract-enforcer.ts) -----------------------------------------------------------------

    CONTRACT_RESET_DOMAIN = "atlas-pca/contract-reset/v1\0"
    DOC_VERSION = 1

    class ContractEnforcerError < StandardError
      def initialize(message)
        super("ContractEnforcer: #{message}")
      end
    end

    def reset_message(id, seq) = CONTRACT_RESET_DOMAIN.b + AtlasPca.sha("#{id}:#{seq}".dup.force_encoding('UTF-8').b)

    # The principal's authorisation to un-latch `contract_id` at sequence `seq` (binds both, so it cannot be replayed later).
    def sign_contract_reset(key, contract_id_value, seq) = AtlasPca.b64e(key.sign(reset_message(contract_id_value, seq)))

    def enforcer_doc?(d, id)
      return false unless d.is_a?(Hash)
      return false if d['v'] != DOC_VERSION || d['contract_id'] != id || !P.state_problem(d['state']).nil?
      return true unless d.key?('latched')

      l = d['latched']
      l.is_a?(Hash) && P.int?(l['seq']) && !P.neg_zero?(l['seq']) && l['violated'].is_a?(Array) && l['violated'].all?(String)
    end

    # JS Math.max over two numbers: NaN wins (a non-finite wall clock then refuses the advance instead of raising).
    def js_max(a, b) = (a.is_a?(Float) && a.nan?) || (b.is_a?(Float) && b.nan?) ? Float::NAN : [a, b].max

    def enforce_result(allow, reason, violated, reasons, seq) = { 'allow' => allow, 'reason' => reason, 'violated' => violated, 'reasons' => reasons, 'seq' => seq }

    # Durable enforcement of a signed contract: the monitor state is one document in a DurableKv (kv.get / kv.update), and the
    # whole read-check-advance runs inside the kv's atomic update, so concurrent callers are serialised and a stale or
    # rolled-back state can never be advanced. Only a contract signed by the PINNED principal is loaded; a real violation
    # LATCHES the enforcer (default) until the principal signs a reset. Every malformed, corrupt or unreadable state denies.
    class ContractEnforcer
      # Raises ContractEnforcerError unless the contract verifies under the pinned principal.
      def self.open(kv, contract, principal:, key: nil, now: nil, latch_on_violation: true)
        raise ContractEnforcerError, 'a pinned principal is required' if !principal.is_a?(String) || principal.empty?

        v = Contracts.verify_contract(contract, principal)
        raise ContractEnforcerError, "contract refused: #{v['reason']}" unless v['ok']

        new(kv, contract, key || "contract/#{Contracts.contract_id(contract)}", now || -> { (Time.now.to_f * 1000).to_i }, latch_on_violation != false)
      end

      def initialize(kv, contract, key, now, latch)
        @kv = kv
        @contract = contract
        @key = key
        @now = now
        @latch = latch
      end

      # Check one action against the permission verdict AND the contract, advancing the durable state iff both allow. Never raises.
      def check(action, permitted = true)
        id = @contract['id']
        out = Contracts.enforce_result(false, 'store-error', [], ['store unavailable'], 0)
        begin
          wall = @now.call
          @kv.update(@key) do |prev|
            if !prev.nil? && !Contracts.enforcer_doc?(prev, id)
              out = Contracts.enforce_result(false, 'state-error', [], ['<state>: stored state is corrupt or belongs to another contract'], 0)
              next nil
            end
            if !prev.nil? && !P.fin?(wall)
              out = Contracts.enforce_result(false, 'state-error', [], ['<state>: clock is not finite'], prev['state']['seq'])
              next nil
            end
            doc = prev || { 'v' => DOC_VERSION, 'contract_id' => id, 'state' => P.empty_state(P.fin?(wall) ? wall : 0) }
            if doc['latched']
              out = Contracts.enforce_result(false, 'latched', doc['latched']['violated'], ["<latched>: contract violated at seq #{doc['latched']['seq']}"], doc['state']['seq'])
              next nil
            end
            r = Contracts.check_and_advance_contract(permitted, doc['state'], action, @contract, { 'now' => Contracts.js_max(wall, doc['state']['now']), 'expectedSeq' => doc['state']['seq'] })
            if r['allow']
              out = Contracts.enforce_result(true, 'ok', [], [], r['next']['seq'])
              next doc.merge('state' => r['next'])
            end
            structural = r['decidedBy'] == 'state'
            real = !structural && !r['violated'].empty?
            out = Contracts.enforce_result(false, structural ? 'state-error' : (real ? 'violated' : 'permission'), real ? r['violated'] : [], r['reasons'], doc['state']['seq'])
            real && @latch ? doc.merge('latched' => { 'seq' => doc['state']['seq'], 'violated' => r['violated'] }) : nil
          end
        rescue StandardError, SystemStackError
          out = Contracts.enforce_result(false, 'store-error', [], ['store error (fail closed)'], 0)
        end
        out
      end

      # Read-only evaluation against the stored state: nothing is advanced or latched. Used to refuse BEFORE a replay counter
      # is spent; `check` then commits once the action is actually admitted. Never raises.
      def peek(action)
        prev = @kv.get(@key)
        return Contracts.enforce_result(false, 'state-error', [], ['<state>: stored state is corrupt or belongs to another contract'], 0) if !prev.nil? && !Contracts.enforcer_doc?(prev, @contract['id'])
        return Contracts.enforce_result(false, 'latched', prev['latched']['violated'], ["<latched>: contract violated at seq #{prev['latched']['seq']}"], prev['state']['seq']) if prev && prev['latched']

        wall = @now.call
        r = Contracts.check_contract(action, @contract, prev ? prev['state'] : P.empty_state(P.fin?(wall) ? wall : 0))
        seq = prev ? prev['state']['seq'] : 0
        return Contracts.enforce_result(true, 'ok', [], [], seq) if r['ok']

        Contracts.enforce_result(false, 'violated', r['violated'], r['reasons'], seq)
      rescue StandardError, SystemStackError
        Contracts.enforce_result(false, 'store-error', [], ['store error (fail closed)'], 0)
      end

      # The current stored state ({'state'=>, 'latched'=>bool}), or nil when nothing was admitted yet. Raises ContractEnforcerError on a corrupt document.
      def state
        d = @kv.get(@key)
        return nil if d.nil?
        raise ContractEnforcerError, 'stored state is corrupt or belongs to another contract' unless Contracts.enforcer_doc?(d, @contract['id'])

        { 'state' => d['state'], 'latched' => d.key?('latched') }
      end

      # Un-latch with the principal's signature (see Contracts.sign_contract_reset) at the latched sequence. Returns whether it cleared.
      def reset(sig)
        cleared = false
        @kv.update(@key) do |prev|
          next nil if !Contracts.enforcer_doc?(prev, @contract['id']) || !prev['latched']
          next nil unless sig.is_a?(String) && AtlasPca.verify_b64u(@contract['principal'], Contracts.reset_message(@contract['id'], prev['latched']['seq']), sig)

          cleared = true
          prev.reject { |k, _| k == 'latched' }
        end
        cleared
      rescue StandardError, SystemStackError
        false
      end
    end
  end
end
