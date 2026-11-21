# frozen_string_literal: true

module AtlasPca
  # The undo-window coordinator (the reference's `server/undo`): admission, the durable ledger, the human surface and the real rollback.
  #
  #   admit      ELIGIBILITY. A window opens only when the policy does not turn windows off, the signed reversibility class is `reversible`,
  #              the engine (the verifier's own CONFIRMED action definitions) returns a plan, and the compensating action is AUTHORIZED under
  #              the original grant (the Policy VM releases it over the original PCActn's verified chain).
  #   open       writes the record DURABLY before the effect may run (a volatile store is refused), signs the `opened` receipt, mints the
  #              one-click undo token and notifies the principal; a failed notification aborts the record and raises an alert.
  #   veto       a valid token (or an operator, a fraud proof, a revocation policy) inside the window moves open -> vetoed exactly once.
  #   compensate re-decides the compensating action under the grant AS IT STOOD AT ADMISSION, then runs it at most once per attempt through
  #              the operations store and the `compensate` executor. Failure: compensation_failed, the reservation kept, an alert raised.
  #   finalize_due closes the windows whose time is up and commits their budget reservations.
  #
  # Synchronous. Options (a Hash, String or Symbol keys): store, engine (#plan(op, {'operationId'})), signer_secret (32 bytes), audience,
  # resolve_grant ->(grant_ref, pcactn), compensate ->(call), operations, notifier (#notify), alert ->(alert), policy ->(op, grant) {mode:
  # off|escalations|always, windowMs?, onRevocation: keep|veto}, window, resolve_target, budget (a KvBudgetLedger or anything with
  # #commit(key, id) and #release(key, id, evidence), or {'ledger', 'evidence'}; a release carries evidence only when 'evidence' is given), pq_pins, effect_timeout_ms, now, relay (#pending), insecure_volatile_store, bonds
  # (#slash_bond(params)). Records are String-keyed Hashes.

  def self.create_undo_coordinator(opts)
    o = opts.to_h { |k, v| [k.to_s, v] }
    missing = missing_undo_components(o)
    raise UndoError.new('config', "undo coordinator: missing required component(s): #{missing.join(', ')}") unless missing.empty?
    if o['store'].durable != true && o['insecure_volatile_store'] != true
      raise UndoError.new('not_durable', 'an undo ledger must be durable: a restart would lose every open window and its compensation')
    end

    UndoCoordinator.new(o)
  end

  class UndoCoordinator
    MAX_CAS = 64
    attr_reader :signer_public

    def initialize(o)
      @o = o
      @policy = o['policy']
      @window = o['window'] || {}
      @resolve_target = o['resolve_target']
      b = o['budget']
      @budget = b.nil? || b == false ? nil : (b.is_a?(Hash) ? b.to_h { |k, v| [k.to_s, v] } : { 'ledger' => b })
      @pq_pins = o['pq_pins']
      @effect_timeout = o['effect_timeout_ms'].nil? ? 5 * 60_000 : o['effect_timeout_ms']
      raise UndoError.new('config', 'undo coordinator: effectTimeoutMs must be a non-negative number') unless @effect_timeout.is_a?(Numeric) && @effect_timeout >= 0
      @relay = o['relay']
      @bonds = o['bonds']
      @clock = o['now'] || -> { (Time.now.to_r * 1000).to_f }
      @store = o['store']
      @key = AtlasPca.undo_key(o['signer_secret'])
      @signer_public = @key.public
    end

    # ---- the API ----

    # ELIGIBILITY: an admission Hash, or {'refused' => reason}. Never raises.
    def admit(pcactn, operation, converted, grant = nil)
      pc = pcactn
      op = operation
      return { 'refused' => 'no operation' } if !pc.is_a?(Hash) || !op.is_a?(Hash) || !op['verb'].is_a?(String) || !op['resource'].is_a?(String)

      g = grant || @o['resolve_grant'].call(pc['grant_ref'], pc)
      return { 'refused' => 'unknown grant' } if g.nil? || g == false

      pol = policy_of(op, g)
      mode = pol['mode'] || 'always'
      return { 'refused' => 'policy: undo windows are off' } if mode == 'off'
      return { 'refused' => 'policy: windows only replace approvals' } if mode == 'escalations' && !converted

      rc = pc['action'].is_a?(Hash) ? pc['action']['reversibility_class'] : nil
      return { 'refused' => "the signed class is #{rc}" } if AtlasPca.class_rank(rc) != 0 # the stricter of the signed class and the definition applies

      id = AtlasPca.hash_canonical(pc)
      plan = @o['engine'].plan(op, { 'operationId' => id })
      return { 'refused' => 'not confirmed reversible, or no confirmed compensating action' } if plan.nil? || plan == false

      pc_plan = plan['compensation']
      comp = { 'verb' => pc_plan['verb'], 'resource' => op['resource'], 'params' => AtlasPca.undo_copy(pc_plan['params']), 'undo_of' => id,
               'def_digest' => pc_plan['def_digest'] }
      comp['target_param'] = pc_plan['target_param'] unless pc_plan['target_param'].nil?
      t = now
      allowed = compensation_allowed(pc, g, { 'verb' => comp['verb'], 'resource' => comp['resource'], 'params' => comp['params'] }, t)
      return { 'refused' => "the compensating action is not authorized under the grant: #{allowed[:reason]}" } unless allowed[:ok]

      window_ms = AtlasPca.resolve_undo_window(AtlasPca.undo_policy(pol, 'windowMs', 'window_ms'), @window)
      { 'id' => id, 'opened_at' => t, 'window_end' => t + window_ms, 'converted' => converted, 'plan' => plan, 'compensation' => comp, 'pcactn' => pc,
        'grant' => g, 'operation' => { 'verb' => op['verb'], 'resource' => op['resource'], 'params' => AtlasPca.undo_copy(op['params'] || {}) } }
    rescue StandardError, SystemStackError => e
      { 'refused' => "undo admission error (fail closed): #{e.message.to_s.empty? ? 'unknown' : e.message}" }
    end

    # Write the record durably, sign the `opened` receipt, mint the one-click token and tell the principal. `bond`: {'ref', 'challengeEndsAt'}.
    def open(adm, bond = nil)
      chain = adm['pcactn']['cap_chain']
      window_end = bond ? [adm['window_end'], bond['challengeEndsAt'].floor].max : adm['window_end']
      cdig = AtlasPca.compensation_digest(adm['compensation'])
      base = { 'v' => 1, 'id' => adm['id'], 'aud' => @o['audience'], 'grant_ref' => adm['pcactn']['grant_ref'], 'holder' => chain[-1]['holder'],
               'principal' => adm['grant']['issuer'],
               'action' => { 'verb' => adm['operation']['verb'], 'resource' => adm['operation']['resource'],
                             'params_digest' => adm['pcactn']['action']['params_digest'], 'def_digest' => adm['plan']['def_digest'] },
               'compensation' => adm['compensation'], 'compensation_digest' => cdig }
      base['render_digest'] = adm['plan']['render_digest'] unless adm['plan']['render_digest'].nil?
      base.merge!('opened_at' => adm['opened_at'], 'window_end' => window_end, 'converted' => adm['converted'], 'state' => 'open', 'ver' => 0,
                  'pcactn' => AtlasPca.canonicalize(adm['pcactn']))
      base['bond_ref'] = bond['ref'] if bond
      base.merge!('attempt' => 0, 'receipts' => [])
      rec = AtlasPca.undo_with_receipt(base, { 'event' => 'opened', 'note' => adm['converted'] ? 'converted' : '' }, adm['opened_at'], @key)
      c = @store.create(rec)
      unless c['created']
        # a retry of the same admission returns the same window; anything else is a different action under the same id
        if c['record']['compensation_digest'] != cdig || c['record']['state'] != 'open'
          raise UndoError.new('invalid', "undo record #{adm['id']} already exists with other terms or state #{c['record']['state']}")
        end

        return info_of(c['record'])
      end
      info = info_of(rec)
      notice = { 'kind' => 'opened', 'record' => strip(rec), 'token' => info['token'] }
      notice['render'] = adm['plan']['render'] if adm['plan']['render']
      n = notify(notice)
      unless n['delivered']
        apply_event(rec['id'], { 'kind' => 'abort', 'reason' => 'notify_failed' })
        alert('level' => 'critical', 'code' => 'notify_failed', 'record' => rec['id'],
              'reason' => "the principal could not be told about the undo window: #{n['reason'] || 'not delivered'}")
        raise UndoError.new('invalid', "notify_failed: the undo window could not be announced (#{n['reason'] || 'not delivered'})")
      end
      info
    end

    def get(id) = @store.get(id)

    # Hold aggregate budget reservations [{'key', 'id'}] until the window closes.
    def hold_budget(id, reservations)
      MAX_CAS.times do
        cur = @store.get(id)
        raise UndoError.new('invalid', "no undo record #{id}") if cur.nil?
        raise UndoError.new('invalid', "a #{cur['state']} record holds no budget") unless %w[open vetoed].include?(cur['state'])

        nxt = cur.merge('budget' => (cur['budget'] || []) + reservations.map { |r| { 'key' => r['key'], 'id' => r['id'] } }, 'ver' => cur['ver'] + 1)
        return nxt if @store.replace(id, cur['ver'], nxt)
      end
      raise UndoError.new('conflict_exhausted', "undo record #{id} kept changing")
    end

    # Report the original effect (its result names the compensation target). A veto that arrived while it ran is acted on now.
    def record_effect(id, result = nil, has_result = false)
      ev = { 'kind' => 'effect' }
      ev['result'] = result if has_result || !result.nil?
      r = must(id, ev)
      r['record']['state'] == 'vetoed' ? run_compensation(r['record']) : r['record']
    end

    def abort(id, reason)
      r = must(id, { 'kind' => 'abort', 'reason' => reason })
      settle_budget(r['record'], 'effect_not_run') if r['applied']
      r['record']
    end

    # Veto with the one-click `token` (the principal; `at` is the relayed veto time), as an authenticated `operator` of this server, or with
    # a prepared `veto` (revocation, fraud proof). {'ok' => true, 'record', 'replayed'} or {'ok' => false, 'code', 'reason'}.
    def veto(id, token: nil, at: nil, operator: nil, veto: nil)
      cur = @store.get(id)
      return { 'ok' => false, 'code' => 'unknown', 'reason' => "no undo record #{id}" } if cur.nil?

      t = now
      check_at = nil
      if !token.nil?
        unless at.nil?
          return { 'ok' => false, 'code' => 'malformed', 'reason' => 'a relayed veto time must lie between the opening of the window and now' } if !at.is_a?(Integer) || at > t || at < cur['opened_at']

          t = check_at = at
        end
        tok = token.is_a?(String) ? AtlasPca.decode_undo_token(token) : token
        chk = AtlasPca.undo_token_check(tok, @signer_public, cur, t)
        return { 'ok' => false, 'code' => chk, 'reason' => "the undo token was refused (#{chk})" } unless chk == 'ok'

        v = { 'at' => t, 'via' => 'token', 'by' => cur['principal'], 'evidence' => AtlasPca.undo_token_digest(tok) }
      elsif !operator.nil?
        return { 'ok' => false, 'code' => 'malformed', 'reason' => 'an operator veto names the operator' } if !operator.is_a?(String) || operator.empty?

        v = { 'at' => t, 'via' => 'operator', 'by' => operator }
      else
        v = (veto || {}).merge('at' => t)
      end
      r = apply_event(id, { 'kind' => 'veto', 'veto' => v }, check_at)
      return { 'ok' => false, 'code' => r['refused'], 'reason' => r['reason'] } if r.key?('refused')

      notify({ 'kind' => 'vetoed', 'record' => strip(r['record']) }) if r['applied']
      done = run_compensation(r['record'])
      { 'ok' => true, 'record' => done, 'replayed' => !r['applied'] }
    rescue StandardError, SystemStackError => e
      { 'ok' => false, 'code' => 'malformed', 'reason' => "veto error (fail closed): #{e.message.to_s.empty? ? 'unknown' : e.message}" }
    end

    # Apply the relay's pending vetoes now (also done by every finalize_due). Raises when the relay cannot be read.
    def sync_relay
      return [] unless @relay

      lst = @relay.pending
      raise UndoError.new('invalid', 'the veto relay returned no list') unless lst.is_a?(Array)

      lst.select { |x| x.is_a?(Hash) && x['id'].is_a?(String) }.map { |x| veto(x['id'], token: x['token'], at: x['at']) }
    end

    def compensate(id)
      cur = @store.get(id)
      raise UndoError.new('invalid', "no undo record #{id}") if cur.nil?

      run_compensation(cur)
    end

    def retry(id) = run_compensation(must(id, { 'kind' => 'retry' })['record'])

    # Close the windows whose time is up (open -> finalized) and commit their budget reservations. Returns the finalized ids.
    def finalize_due
      out = []
      begin
        sync_relay
      rescue StandardError => e
        # a veto may be waiting at the relay: closing any window now could finalize an action the principal undid
        alert('level' => 'critical', 'code' => 'veto_relay_failed', 'record' => '*',
              'reason' => "the veto relay could not be read; no window was finalized: #{e.message.to_s.empty? ? 'error' : e.message}")
        return out
      end
      @store.list({ 'state' => 'open', 'window_ended_by' => now - 1 - (@relay ? UNDO_RELAY_GRACE_MS : 0) }).each do |rec|
        r = apply_event(rec['id'], { 'kind' => 'finalize' })
        next if r.key?('refused') || !r['applied']

        out << rec['id']
        if r['record']['effect'].nil?
          alert('level' => 'warning', 'code' => 'effect_unknown', 'record' => rec['id'],
                'reason' => 'the window closed without an effect report: reconcile the original operation')
        end
        settle_budget(r['record'], 'commit')
        notify({ 'kind' => 'finalized', 'record' => strip(r['record']) })
      end
      out
    end

    # After a restart: resume every vetoed record's compensation, then finalize what is due.
    def recover
      out = []
      @store.list({ 'state' => 'vetoed' }).each { |rec| out << rec['id'] if run_compensation(rec)['state'] != 'vetoed' }
      out + finalize_due
    end

    # A grant was revoked: veto its open windows when the policy says so, else alert and tell the principal.
    def on_revocation(grant_ref)
      out = []
      @store.list({ 'state' => 'open', 'grant_ref' => grant_ref }).each do |rec|
        pc = AtlasPca::Gateway.decode_pcactn(rec['pcactn'])
        grant = @o['resolve_grant'].call(rec['grant_ref'], pc)
        pol = grant ? policy_of({ 'verb' => rec['action']['verb'], 'resource' => rec['action']['resource'] }, grant) : {}
        if (AtlasPca.undo_policy(pol, 'onRevocation', 'on_revocation') || 'keep') == 'veto'
          out << rec['id'] if veto(rec['id'], veto: { 'at' => 0, 'via' => 'revocation', 'by' => grant_ref })['ok']
        else
          alert('level' => 'warning', 'code' => 'revoked_open_window', 'record' => rec['id'],
                'reason' => "grant #{grant_ref} was revoked while this window is open; the principal can still undo it")
          notify({ 'kind' => 'revoked', 'record' => strip(rec) })
        end
      end
      out
    end

    # Slash a bond (the bond ledger re-verifies the fraud proof itself and refuses outside the challenge window), then undo the record.
    def rollback_on_slash(params, bonds = nil)
      bonds ||= @bonds
      raise UndoError.new('config', 'rollback_on_slash needs a bond ledger (pass bonds to the coordinator or to this call)') if bonds.nil?

      claim = params['claimId'] || params['claim_id']
      settlement = bonds.slash_bond(params)
      evidence = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/undo-slash-ref/v1', 'settlement' => settlement })
      recs = @store.list({ 'state' => 'open', 'bond_ref' => claim })
      target = recs.first || @store.get(claim)
      if target.nil?
        return { 'settlement' => settlement, 'veto' => { 'ok' => false, 'code' => 'unknown', 'reason' => "no undo record for bond #{claim}" } }
      end

      v = veto(target['id'], veto: { 'at' => 0, 'via' => 'fraud_proof', 'by' => claim, 'evidence' => evidence })
      unless v['ok']
        alert('level' => 'critical', 'code' => 'slash_after_window', 'record' => target['id'],
              'reason' => "the bond was slashed but the effect could not be rolled back: #{v['reason']}")
      end
      { 'settlement' => settlement, 'veto' => v }
    end

    private

    def now
      t = @clock.call
      raise UndoError.new('invalid', 'the clock returned a non-finite time') unless t.is_a?(Numeric) && (!t.is_a?(Float) || t.finite?)

      t.floor
    end

    def strip(r) = r.reject { |k, _| %w[pcactn receipts].include?(k) }

    def alert(a)
      @o['alert'].call(a)
    rescue StandardError # an alert sink that throws is itself a failure the operator must see
      warn "pca undo alert (#{a['code']}) for #{a['record']}: #{a['reason']}"
    end

    def notify(n)
      r = @o['notifier'].notify(n)
      return { 'delivered' => true } if r.is_a?(Hash) && r['delivered'] == true

      { 'delivered' => false, 'reason' => r.is_a?(Hash) && r['reason'] ? r['reason'] : 'no channel delivered the notice' }
    rescue StandardError => e
      { 'delivered' => false, 'reason' => e.message.to_s.empty? ? 'notifier error' : e.message }
    end

    # {'record', 'applied'} or {'refused' => code, 'reason'}
    def apply_event(id, ev, check_at = nil)
      MAX_CAS.times do
        cur = @store.get(id)
        return { 'refused' => 'unknown', 'reason' => "no undo record #{id}" } if cur.nil?

        t = now
        tr = AtlasPca.undo_transition(cur, ev, check_at.nil? ? t : check_at) # a relayed veto is judged as of when the principal made it
        return { 'refused' => tr['code'], 'reason' => tr['reason'] } if tr['outcome'] == 'refused'
        return { 'record' => tr['record'], 'applied' => false } if tr['outcome'] == 'replayed'

        nxt = AtlasPca.undo_with_receipt(tr['record'], tr['receipt'], t, @key)
        return { 'record' => nxt, 'applied' => true } if @store.replace(id, cur['ver'], nxt)
      end
      raise UndoError.new('conflict_exhausted', "undo record #{id} kept changing")
    end

    def must(id, ev)
      r = apply_event(id, ev)
      raise UndoError.new('invalid', "#{r['refused']}: #{r['reason']}") if r.key?('refused')

      r
    end

    def settle_budget(rec, how)
      b = @budget
      return if b.nil? || !rec['budget']

      rec['budget'].each do |r|
        o = if how == 'commit'
              b['ledger'].commit(r['key'], r['id'])
            else
              # as the reference: release evidence only when the caller supplies an 'evidence' callable ->(reservation, reason) (e.g. BudgetLedger.sign_release)
              ev = b['evidence'].respond_to?(:call) ? b['evidence'].call(r, how) : nil
              b['ledger'].release(r['key'], r['id'], ev)
            end
        outcome = o.is_a?(Hash) ? o['outcome'].to_s : ''
        unless %w[settled replayed].include?(outcome)
          alert('level' => 'warning', 'code' => 'budget_settle_failed', 'record' => rec['id'], 'reason' => "#{how} of #{r['key']}/#{r['id']}: #{outcome}")
        end
      rescue StandardError => e
        alert('level' => 'warning', 'code' => 'budget_settle_failed', 'record' => rec['id'],
              'reason' => "#{how} of #{r['key']}/#{r['id']}: #{e.message.to_s.empty? ? 'error' : e.message}")
      end
    end

    def policy_of(op, grant)
      r = @policy ? @policy.call(op, grant) : nil
      r.is_a?(Hash) ? r.to_h { |k, v| [k.to_s, v] } : {}
    end

    def compensation_allowed(pc, grant, op, at)
      input = { 'grant' => grant, 'trustedRoot' => grant,
                'action' => { 'action' => { 'verb' => op['verb'], 'resource' => op['resource'], 'params' => op['params'] || {} } }, 'risk' => {},
                'budget' => { 'B' => 0, 'tau' => at }, 'now' => at }
      input['chain'] = pc['cap_chain'] unless pc['cap_chain'].nil?
      input['pqPins'] = @pq_pins unless @pq_pins.nil?
      d = AtlasPca.decide(input)
      return { ok: true, reason: '' } if d['releaseGuardianShare']

      { ok: false, reason: d['reasons'].find { |r| !r.start_with?('risk input') } || 'the grant does not authorize the compensating action' }
    end

    def info_of(rec)
      { 'id' => rec['id'], 'window_end' => rec['window_end'], 'converted' => rec['converted'],
        'compensation' => { 'verb' => rec['compensation']['verb'], 'resource' => rec['compensation']['resource'] },
        'token' => AtlasPca.encode_undo_token(AtlasPca.sign_undo_token(rec, @key)),
        'obligation' => { 'kind' => 'undo_window', 'params' => { 'id' => rec['id'], 'window_end' => rec['window_end'] }, 'due' => rec['window_end'] } }
    end

    def finish_compensated(rec)
      if rec['state'] == 'compensated'
        settle_budget(rec, 'rollback')
        notify({ 'kind' => 'compensated', 'record' => strip(rec) })
      end
      rec
    end

    def run_compensation(rec0)
      rec = rec0
      return rec if rec['state'] != 'vetoed'

      t = now
      return rec if rec['effect'].nil? && t - ((rec['veto'] || {})['at'] || t) < @effect_timeout # wait for the effect report (record_effect resumes)

      pc = AtlasPca::Gateway.decode_pcactn(rec['pcactn'])
      grant = @o['resolve_grant'].call(rec['grant_ref'], pc)
      fail_with = lambda do |reason, code = 'compensation_failed'|
        r = apply_event(rec['id'], { 'kind' => 'compensation_failed', 'reason' => reason })
        out = r.key?('refused') ? (@store.get(rec['id']) || rec) : r['record']
        if !r.key?('refused') && r['applied']
          alert('level' => 'critical', 'code' => code, 'record' => rec['id'], 'reason' => reason)
          notify({ 'kind' => 'compensation_failed', 'record' => strip(out) })
        end
        out
      end
      return fail_with.call('the grant is no longer known: the compensation cannot be authorized', 'compensation_denied') if grant.nil? || grant == false

      params = rec['compensation']['params'].dup
      tp = rec['compensation']['target_param']
      unless tp.nil?
        if @resolve_target
          target = @resolve_target.call(rec)
        else
          res = (rec['effect'] || {})['result']
          target = res.is_a?(Hash) && res['id'].is_a?(String) && !res['id'].empty? ? res['id'] : nil
        end
        return fail_with.call("the target '#{tp}' of the compensation is unknown (no effect result names it)") if target.nil?

        params[tp] = target
      end
      op = { 'verb' => rec['compensation']['verb'], 'resource' => rec['compensation']['resource'], 'params' => params }
      dec = compensation_allowed(pc, grant, op, rec['opened_at'])
      return fail_with.call("the compensating action is not authorized under the grant: #{dec[:reason]}", 'compensation_denied') unless dec[:ok]

      ops = @o['operations']
      # at most once per attempt: the operation record is created before the compensator runs
      op_id = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/undo-compensation-op/v1', 'record' => rec['id'], 'attempt' => rec['attempt'] })
      orec = { 'id' => op_id, 'state' => 'pending', 'verb' => op['verb'], 'resource' => op['resource'], 'params_digest' => AtlasPca.hash_canonical(params),
               'reversibility' => 'irreversible', 'startedAt' => t }
      prev = ops.create(orec)
      unless prev.nil?
        case prev['state']
        when 'committed'
          r = apply_event(rec['id'], prev.key?('result') ? { 'kind' => 'compensated', 'result' => prev['result'] } : { 'kind' => 'compensated' })
          rec = r['record'] unless r.key?('refused')
          return finish_compensated(rec)
        when 'failed', 'uncertain'
          return fail_with.call("compensation attempt #{rec['attempt']} #{prev['state']}: #{prev['error'] || ''}")
        when 'aborted'
          r = apply_event(rec['id'], { 'kind' => 'compensation_failed', 'reason' => 'attempt never started' })
          return rec if r.key?('refused')

          again = apply_event(rec['id'], { 'kind' => 'retry' })
          return again.key?('refused') ? r['record'] : run_compensation(again['record'])
        end
        # pending / executing: another worker holds it, or a crash; stale ones are settled here
        if t - (prev['executingAt'].nil? ? prev['startedAt'] : prev['executingAt']) > @effect_timeout
          settled = if prev['state'] == 'pending'
                      prev.merge('state' => 'aborted', 'error' => 'never started', 'finishedAt' => t)
                    else
                      prev.merge('state' => 'uncertain', 'error' => 'no outcome recorded: the compensation may or may not have run', 'finishedAt' => t)
                    end
          ops.transition(prev['id'], prev['state'], settled)
          return run_compensation(@store.get(rec['id']) || rec)
        end
        return rec
      end
      # re-read under the record: a concurrent retry or resolution wins
      cur = @store.get(rec['id'])
      if cur.nil? || cur['state'] != 'vetoed' || cur['attempt'] != rec['attempt']
        ops.transition(op_id, 'pending', orec.merge('state' => 'aborted', 'error' => 'the undo record moved on', 'finishedAt' => now))
        return cur || rec
      end
      running = orec.merge('state' => 'executing', 'executingAt' => now)
      return @store.get(rec['id']) || rec unless ops.transition(op_id, 'pending', running)

      call = { 'operation' => op, 'idempotencyKey' => op_id, 'undoOf' => rec['id'], 'record' => cur.reject { |k, _| k == 'pcactn' } }
      call['originalResult'] = rec['effect']['result'] if !rec['effect'].nil? && !rec['effect']['result'].nil?
      begin
        result = @o['compensate'].call(call)
      rescue StandardError => e
        error = e.message.to_s
        begin
          ops.transition(op_id, 'executing', running.merge('state' => 'failed', 'error' => error, 'finishedAt' => now))
        rescue StandardError
          nil
        end
        return fail_with.call("the compensating action failed: #{error}")
      end
      begin
        ops.transition(op_id, 'executing', running.merge('state' => 'committed', 'result' => result, 'finishedAt' => now))
      rescue StandardError
        nil
      end
      r = apply_event(rec['id'], result.nil? ? { 'kind' => 'compensated' } : { 'kind' => 'compensated', 'result' => result })
      return @store.get(rec['id']) || rec if r.key?('refused')

      finish_compensated(r['record'])
    end
  end
end
