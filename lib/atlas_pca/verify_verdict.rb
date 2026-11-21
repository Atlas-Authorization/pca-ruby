# frozen_string_literal: true

# The resource-server verifier with the FULL verdict (the reference's server `verifyPCActn`): one call answers `allow`, the recomputed risk `r`,
# the `requiredThreshold`, every check with its status ('pass' / 'fail' / 'not-enforced' / 'unsupported'), the reasons in order, the budget after the
# decision (when it allows or escalates) and, when asked, the per-check assurance report. It never raises: an internal error is a fail-closed verdict
# (`malformed: fail`). The core fold (the reference's verifyPCActnCore: wire, version, audience, validity, cap_chain, grant_ref_bound, plan_inclusion,
# leaf_signature, counter_format, intent, the v2 checks, fresh_at, the enforcement gates, the hooks) and the server layer (pq_pin, grant_ref,
# operation, params_digest, plan_root_authorized, freshness epoch, beacon, budget, risk inputs, reversibility, delegated caveats, the Policy VM,
# the threshold rule, assurance, default-deny) are folded here in the reference's order; the primitives are the library's own.
#
# Options (`opts`: String keys, the reference's names; every key optional but `grant`): grant (the verifier's OWN stored grant), now, audience (a
# String; an explicit nil accepts any audience; absent fails closed), insecureSkipPlanRootCheck, context (params, subject, env, plan, planAuthorized,
# reversibilityClass, risk, budget, recentActionTimes, revocationEpoch, beacon), require, allowedSuites, pqPins, operation, intent, intentV2, freshAt,
# requireRiskInputs, assurance, requireAssurance, allowUnsupported, k1, hooks ({'attestation','threshold','revocation','zk' => ->(ctx) { {...} }}
# with ctx = {'pcactn', 'grant', 'nowEpoch'} answering {'enforced', 'ok', 'reason', 't'}), enforce ({'freshness', 'attestation' => {'verifier',
# 'required'}, 'taint' => {'ctx', 'maxTaint'}}). There is NO allowUnboundPq: it is ignored (a PQ key is never read from the artifact).
module AtlasPca
  module VerifyVerdict
    DEFAULT_REQUIRED_CHECKS = %w[counter_format revocation plan_root_authorized audience validity grant_ref_bound].freeze
    STATEFUL_REQUIRED_CHECKS = %w[counter_format replay revocation plan_root_authorized audience validity grant_ref_bound].freeze
    WORST = { 't' => 3, 'proof' => 'strong', 'optimisticAllowed' => false }.freeze
    PCACTN_VERSION = 2
    MAX_SAFE = 9_007_199_254_740_991
    DEFAULT_FRESHNESS_EPOCH_MS = 60_000
    ABSENT = Object.new.freeze # `undefined`: the member is not there

    module_function

    # The verdict of `pcactn` (a parsed Hash or its JSON text) under `opts`.
    def verify(pcactn, opts)
      v = begin
        run(pcactn, opts)
      rescue StandardError, SystemStackError => e
        fail_closed("verifier error (fail closed): #{e.message}")
      end
      if (opt(opts, 'assurance') == true || opts_key?(opts, 'requireAssurance')) && !v.key?('assurance')
        v['assurance'] = AtlasPca.assurance_report(nil, v['checks']) # a verdict that stopped before the checks ran still reports its outcomes
      end
      v
    end

    def fail_closed(reason, checks = {})
      { 'allow' => false, 'r' => 1, 'requiredThreshold' => WORST.dup, 'checks' => checks.merge('malformed' => 'fail'), 'reasons' => [reason] }
    end

    def opts_key?(o, k) = o.is_a?(Hash) && o.key?(k) && !o[k].nil?
    def opt(o, k) = o.is_a?(Hash) ? o[k] : nil
    def has?(o, k) = o.is_a?(Hash) && o.key?(k)
    def obj(v) = v.is_a?(Hash) ? v : {}
    def truthy?(v) = V2JS.truthy?(v)
    def safe_int?(v) = (v.is_a?(Integer) && v.abs <= MAX_SAFE) || (v.is_a?(Float) && v.finite? && v == v.floor && v.abs <= MAX_SAFE && !V2JS.neg_zero?(v))
    def fin?(v) = v.is_a?(Integer) || (v.is_a?(Float) && v.finite?)
    def jstr(v) = V2JS.js_str(v)
    def hash_of(v) = AtlasPca.hash_canonical(v)
    def list?(v) = v.is_a?(Array)

    # a member as the reference reads it (`undefined` when the key is absent)
    def member(o, k) = o.is_a?(Hash) && o.key?(k) ? o[k] : nil

    # ---- hooks: a hook is a callable; null from a hook is the reference's `Cannot read properties of null`, a non-object reads as no members
    def call_hook(hook, ctx)
      res = hook.call(ctx)
      raise TypeError, "Cannot read properties of #{res.nil? ? 'null' : 'undefined'} (reading 'enforced')" if res.nil?

      res.is_a?(Hash) ? res : {}
    end

    # the intent slots of the wire form, as the full verifier loads them (the reference's INTENT_WIRE_EXTENSION)
    def wire_extension = AtlasPca::INTENT_WIRE_EXTENSION

    # ---- the core fold (verifyPCActnCore with the full extensions) -------------------------------------------------------------------
    # Returns {'checks', 'reason', 'allow', 'wire' => message_or_nil}.
    def core(p, grant, now, aud_kind, aud, hooks, enforce, allowed_suites, intent, intent_v2, fresh_at, hook_state)
      checks = {}
      reason = nil
      fail = lambda do |name, why|
        checks[name] = 'fail'
        reason ||= "#{name}: #{why}"
      end
      mark = ->(name, s) { checks[name] = s }
      result = -> { { 'checks' => checks, 'reason' => reason, 'allow' => checks.values.none?('fail') } }

      wire = AtlasPca.validate_wire_v2(p, wire_extension)
      return { 'checks' => { 'wire' => 'fail' }, 'reason' => "wire: #{wire}", 'allow' => false, 'wire' => wire } unless wire.nil?

      mark.call('wire', 'pass')
      begin
        # 0. version
        if p['ver'] == PCACTN_VERSION then mark.call('version', 'pass')
        else fail.call('version', "unsupported ver #{jstr(p['ver'])} (this verifier requires #{PCACTN_VERSION})")
        end

        # 0a. audience and validity window
        has_aud = p['aud'].is_a?(String) && !p['aud'].empty?
        status = case aud_kind
                 when :null then 'not-enforced'
                 when :absent then has_aud ? 'fail' : 'not-enforced'
                 else p['aud'] == aud ? 'pass' : 'fail'
                 end
        if status != 'fail' then mark.call('audience', status)
        elsif aud_kind == :absent then fail.call('audience', 'PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or audience: null to accept any)')
        else fail.call('audience', 'aud does not match this resource server / instance')
        end
        iat = p['iat']
        exp = p['exp']
        if !safe_int?(now) then fail.call('validity', 'the verifier clock is not a safe integer epoch-ms')
        elsif !(exp > iat) then fail.call('validity', 'exp must be greater than iat')
        elsif exp - iat > AtlasPca::MAX_LIFETIME_MS then fail.call('validity', "lifetime exceeds #{AtlasPca::MAX_LIFETIME_MS} ms")
        elsif iat > now + AtlasPca::MAX_SKEW_MS then fail.call('validity', 'iat is in the future (clock skew)')
        elsif now > exp then fail.call('validity', 'the PCActn has expired')
        else mark.call('validity', 'pass')
        end

        # 1. capability chain, rooted at the stored grant
        chain = p['cap_chain']
        if !(chain.is_a?(Array) && !chain.empty?) then fail.call('cap_chain', 'empty chain')
        elsif AtlasPca.cap_hash(chain[0]) != AtlasPca.cap_hash(grant) then fail.call('cap_chain', 'chain root is not the grant')
        else
          why, ok = AtlasPca.verify_chain(chain, grant['issuer'], true, allowed_suites, nil, grant)
          if ok then mark.call('cap_chain', 'pass')
          else fail.call('cap_chain', why.to_s.empty? ? 'invalid' : why)
          end
        end

        # 1a. grant_ref binds the chain's root capability
        chain_root = chain.is_a?(Array) && !chain.empty? ? chain[0] : nil
        root_id = chain_root.is_a?(Hash) ? chain_root['id'] : nil
        if p['grant_ref'].is_a?(String) && !p['grant_ref'].empty? && root_id.is_a?(String) && p['grant_ref'] == root_id then mark.call('grant_ref_bound', 'pass')
        else fail.call('grant_ref_bound', 'grant_ref is not the id of the root capability in cap_chain')
        end

        # 2. plan inclusion; the plan root authorization is decided by the server layer
        plan = p['plan']
        cond = plan.key?('conditions_digest') ? plan['conditions_digest'] : AtlasPca.conditions_digest(nil, nil)
        if AtlasPca.verify_inclusion(plan['root'], plan['inclusion_proof'], AtlasPca.plan_leaf(plan['node_id'], p['action'], cond)) then mark.call('plan_inclusion', 'pass')
        else fail.call('plan_inclusion', 'action is not a node of the committed plan')
        end
        mark.call('plan_root_authorized', 'not-enforced')

        # 3. the leaf holder's signature (dispatched by `alg`)
        leaf_cap = chain.is_a?(Array) ? chain[-1] : nil
        if leaf_cap.nil?
          fail.call('leaf_signature', 'signature does not verify under the leaf holder key / suite')
        else
          err = AtlasPca.suite_policy_error(p['alg'], 'leaf', allowed_suites) || AtlasPca.pq_binding_error(p['alg'], p['pq_pk'], leaf_cap['holder_pq'], 'leaf')
          if !err.nil? then fail.call('leaf_signature', err)
          elsif p['sig'].is_a?(String) &&
                AtlasPca.verify_suite(p, leaf_cap['holder'], AtlasPca.threshold_message(p), AtlasPca.resolve_pq_key(leaf_cap['holder'], p['pq_pk'], holder_pq: leaf_cap['holder_pq']))
            mark.call('leaf_signature', 'pass')
          else fail.call('leaf_signature', 'signature does not verify under the leaf holder key / suite')
          end
        end

        # 4. counter_format
        if safe_int?(p['counter']) && p['counter'] >= 0 then mark.call('counter_format', 'pass')
        else fail.call('counter_format', 'missing or not a non-negative safe integer')
        end

        # the intent checks
        session = p.key?('intent_session') ? p['intent_session']['session'] : nil
        map_form = p.key?('intent_session') ? p['intent_session']['map_form'] : nil
        st, why = AtlasPca.decide_intent_binding(p['intent'], grant, intent, session, map_form)
        if st == :pass then mark.call('intent', 'pass')
        elsif st == :fail then fail.call('intent', why)
        end
        AtlasPca.decide_intent_v2(p, grant, intent_v2, now)['checks'].each do |c|
          if c['ok'] then mark.call(c['name'], 'pass')
          else fail.call(c['name'], c['reason'] || 'rejected')
          end
        end
        fa = AtlasPca.decide_fresh_at(p, fresh_at, now)
        unless fa.nil?
          if fa['ok'] then mark.call('fresh_at', 'pass')
          else fail.call('fresh_at', fa['reason'])
          end
        end

        # the opt-in taint gate
        tg = member(enforce, 'taint')
        if truthy?(tg)
          begin
            g = tg['ctx'].is_a?(Hash) ? tg['ctx'] : {}
            t = AtlasPca::Taint.taint_gate(p['provenance'], g['registry'], g['resourceGraph'], tg['maxTaint'])
            if t['ok'] then mark.call('taint_gate', 'pass')
            else fail.call('taint_gate', t['reason'])
            end
          rescue StandardError => e
            fail.call('taint_gate', "taint gate error (fail closed): #{e.message}")
          end
        else
          mark.call('taint_gate', 'not-enforced')
        end

        # the opt-in freshness gate
        fg = member(enforce, 'freshness')
        if truthy?(fg)
          epoch_ms = fg['epochMs'].nil? ? DEFAULT_FRESHNESS_EPOCH_MS : fg['epochMs']
          fnow = fg['now'].nil? ? now : fg['now']
          skew = fin?(fg['clockSkewMs']) ? [0, fg['clockSkewMs']].max : 0
          fr = p['freshness']
          if !(fin?(epoch_ms) ? epoch_ms > 0 : false) || !fin?(fg['maxAgeMs']) || fg['maxAgeMs'] < 0 || !fin?(fnow)
            fail.call('freshness', 'freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)')
          elsif !(fr.is_a?(Hash) && fr['beacon_ref'].is_a?(String) && !fr['beacon_ref'].empty?) || !safe_int?(fr['epoch']) || fr['epoch'] <= 0
            fail.call('freshness', 'freshness anchor is missing (empty beacon_ref or non-positive epoch stub)')
          else
            anchor = fr['epoch'] * epoch_ms
            if anchor > fnow + skew then fail.call('freshness', 'freshness anchor is in the future')
            elsif fnow - anchor > fg['maxAgeMs'] then fail.call('freshness', "freshness anchor is stale (older than #{Predicates.js_number_string(fg['maxAgeMs'].to_f)} ms)")
            else mark.call('freshness', 'pass')
            end
          end
        end

        # the hooks, in the reference's order: attestation, threshold, revocation, zk
        ctx = { 'pcactn' => p, 'grant' => grant, 'nowEpoch' => now }
        run_hook = lambda do |name, hook|
          res = hook.nil? ? {} : call_hook(hook, ctx)
          enforced = truthy?(res['enforced'])
          hook_state[:t] = res['t'] if name == 'threshold' && enforced
          if !enforced then mark.call(name, 'not-enforced')
          elsif truthy?(res['ok']) then mark.call(name, 'pass')
          else fail.call(name, truthy?(res['reason']) ? jstr(res['reason']) : 'rejected')
          end
        end
        att_gate = member(enforce, 'attestation')
        att_hook = att_gate.is_a?(Hash) && !att_gate['verifier'].nil? ? att_gate['verifier'] : hooks['attestation']
        run_hook.call('attestation', att_hook)
        if truthy?(att_gate) && (att_gate.is_a?(Hash) && att_gate['required'].nil? ? true : (att_gate.is_a?(Hash) ? att_gate['required'] : true)) != false && checks['attestation'] == 'not-enforced'
          fail.call('attestation', 'attestation required but the verifier reported not-enforced / no document (fail closed)')
        end
        run_hook.call('threshold', hooks['threshold'])
        run_hook.call('revocation', hooks['revocation'])
        if p.key?('zk_compliance')
          run_hook.call('zk_compliance', hooks['zk'])
          if checks['zk_compliance'] != 'pass' && checks['zk_compliance'] != 'fail'
            fail.call('zk_compliance', 'zk_compliance: PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof'.sub(/\Azk_compliance: /, ''))
          end
        end
        mark.call('bond', 'not-enforced') if p.key?('bond_ref')
      rescue StandardError, SystemStackError => e
        reason ||= "malformed PCActn: #{e.message}"
        checks['malformed'] = 'fail'
      end
      checks['bond'] = 'unsupported' if p.key?('bond_ref') && checks['bond'] == 'not-enforced'
      result.call
    end

    # ---- the server layer ------------------------------------------------------------------------------------------------------------
    def run(pcactn, opts)
      # ---- decode
      if pcactn.is_a?(String)
        begin
          p = Gateway.decode_pcactn(pcactn)
        rescue AtlasPca::Malformed => e
          return fail_closed("undecodable PCActn: strict JSON: #{e.message}")
        rescue StandardError => e
          return fail_closed("undecodable PCActn: #{e.message}")
        end
      else
        p = pcactn
      end
      return fail_closed('PCActn is not an object') unless p.is_a?(Hash) || p.is_a?(Array)

      grant = opt(opts, 'grant')
      raise TypeError, 'the grant is not a capability' unless grant.is_a?(Hash) && grant['caveats'].is_a?(Array)

      now = has?(opts, 'now') && !opts['now'].nil? ? opts['now'] : (Time.now.to_f * 1000).to_i
      op = opt(opts, 'operation')
      ctx_in = opt(opts, 'context')
      ctx_params = member(ctx_in, 'params')
      ctx = ctx_in.is_a?(Hash) ? ctx_in.dup : {}
      ctx['params'] = op['params'] if op.is_a?(Hash) && op.key?('params')
      hooks = opt(opts, 'hooks').is_a?(Hash) ? opts['hooks'] : {}
      enforce = opt(opts, 'enforce')
      hook_state = { t: nil }
      user_threshold = hooks['threshold']

      # rules 20 and 21 read the stored grant's envelope: when it carries any, the v2 pipeline needs the plaintext params and the host env
      grant_env = AtlasPca.read_envelope(grant)
      needs_model_rules = !grant_env.nil? && (%w[units tighten model_polarity actions].any? { |k| grant_env.key?(k) } ||
                                              !AtlasPca.model_paths_read([grant_env['predicates']]).empty?)
      v2_in = opt(opts, 'intentV2')
      intent_v2 = nil
      if truthy?(v2_in) || needs_model_rules
        intent_v2 = v2_in.is_a?(Hash) ? v2_in.dup : {}
        params = intent_v2['params'].nil? ? ctx['params'] : intent_v2['params']
        env = intent_v2['env'].nil? ? ctx['env'] : intent_v2['env']
        intent_v2['params'] = params unless params.nil?
        intent_v2['env'] = env unless env.nil?
      end
      now_f = fin?(now) ? now : nil
      v2d = p.is_a?(Hash) && (p.key?('intent_session') || needs_model_rules) && now_f ? AtlasPca.decide_intent_v2(p, grant, intent_v2, now) : nil
      v2d = nil if p.is_a?(Hash) && !now_f && (p.key?('intent_session') || needs_model_rules) # decide_intent_v2 needs a number: the core reports the clock

      # ---- the audience: a String; an explicit null accepts any; absent fails closed
      if !has?(opts, 'audience') then aud_kind = :absent
      elsif opts['audience'].nil? then aud_kind = :null
      else aud_kind = :string
      end
      aud = opts['audience']
      allowed = opt(opts, 'allowedSuites')

      c = core(p, grant, now, aud_kind, aud, hooks, enforce, allowed.is_a?(Array) ? allowed : nil, opt(opts, 'intent'), intent_v2, opt(opts, 'freshAt'), hook_state)
      return fail_closed(c['reason'] || 'wire: malformed PCActn', { 'wire' => 'fail' }) if c['checks']['wire'] == 'fail'

      core_checks = c['checks']
      unsupported = core_checks.select { |_n, s| s == 'unsupported' }.keys
      checks = core_checks.dup
      reasons = !c['allow'] && !c['reason'].nil? ? [c['reason']] : []
      reasons.concat(AtlasPca.fold_v2_reasons(reasons, v2d['checks'])[reasons.length..]) if v2d
      fail = lambda do |name, why|
        checks[name] = 'fail'
        reasons << "#{name}: #{why}"
      end
      mark = ->(name, s) { checks[name] = s }

      # ---- the server-side PQ pin
      pq_pins = opt(opts, 'pqPins')
      unless pq_pins.nil?
        alg = grant['alg'].nil? ? 'ed25519' : grant['alg']
        pins = pq_pins.is_a?(Hash) ? pq_pins : {}
        issuer = grant['issuer']
        has_pin = issuer.is_a?(String) && pins.key?(issuer)
        pin = has_pin ? pins[issuer] : nil
        if alg == 'ed25519'
          if has_pin then fail.call('pq_pin', 'the grant issuer is pinned to a post-quantum key; a classical grant is refused')
          else mark.call('pq_pin', 'pass')
          end
        elsif pin.is_a?(String) && grant['pq_pk'].is_a?(String) && pin == grant['pq_pk'] then mark.call('pq_pin', 'pass')
        else fail.call('pq_pin', pin.nil? ? "no server-side PQ pin for the grant issuer (suite #{jstr(alg)})" : 'the grant pq_pk does not match the server-side pin')
        end
      end

      # ---- grant_ref and the operation
      p_h = p.is_a?(Hash) ? p : {}
      if p_h['grant_ref'] == grant['id'] then mark.call('grant_ref', 'pass')
      else fail.call('grant_ref', 'does not reference the supplied grant')
      end
      action = p_h['action'].is_a?(Hash) ? p_h['action'] : {}
      if truthy?(op)
        o = obj(op)
        signed = "#{jstr(action.key?('verb') ? action['verb'] : V2JS::UNDEF)} on #{jstr(action.key?('resource') ? action['resource'] : V2JS::UNDEF)}"
        if !o['verb'].is_a?(String) || !o['resource'].is_a?(String) then fail.call('operation', 'the server operation has no verb / resource (fail closed)')
        elsif action['verb'] != o['verb'] || action['resource'] != o['resource'] then fail.call('operation', "the proof is for #{signed}, but this operation is #{o['verb']} on #{o['resource']}")
        elsif o.key?('params') && hash_of(o['params']) != action['params_digest'] then fail.call('operation', "the proof's params_digest does not match the params of this #{o['verb']} operation")
        elsif o.key?('params') && ctx_in.is_a?(Hash) && ctx_in.key?('params') && hash_of(ctx_params) != hash_of(o['params'])
          fail.call('operation', 'context.params differ from the operation params')
        else mark.call('operation', 'pass')
        end
      end
      if ctx.key?('params')
        if hash_of(ctx['params']) == action['params_digest'] then mark.call('params_digest', 'pass')
        else fail.call('params_digest', 'supplied params do not hash to action.params_digest')
        end
      else
        mark.call('params_digest', 'not-enforced')
      end

      # ---- the server's own copy of the plan
      plan_v = ctx['plan']
      plan_supplied = truthy?(plan_v)
      plan_nodes = nil
      root_matches = false
      if plan_supplied
        raise TypeError, 'ctx.plan.map is not a function' unless plan_v.is_a?(Array)

        plan_nodes = plan_v
        leaves = plan_nodes.map do |n|
          raise TypeError, 'plan node is not an object' unless n.is_a?(Hash)

          AtlasPca.plan_node_leaf(n)
        end
        root_matches = AtlasPca.merkle_root(leaves) == (p_h['plan'].is_a?(Hash) ? p_h['plan']['root'] : nil)
      end
      authorized = ctx['planAuthorized']
      pd = if !plan_supplied then 'not-enforced'
           elsif !root_matches then 'mismatch'
           elsif authorized == true then 'pass'
           elsif authorized == false then 'unauthorized'
           else 'not-enforced'
           end
      case pd
      when 'mismatch' then fail.call('plan_root_authorized', 'known plan does not match plan.root')
      when 'unauthorized' then fail.call('plan_root_authorized', 'the plan root has not been authorized by the principal')
      when 'pass' then mark.call('plan_root_authorized', 'pass')
      else
        if opt(opts, 'insecureSkipPlanRootCheck') == true then mark.call('plan_root_authorized', 'not-enforced')
        else fail.call('plan_root_authorized', 'default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)')
        end
      end

      # ---- the guardian-signed revocation epoch
      re = ctx['revocationEpoch']
      if truthy?(re)
        kw = { pcactn_epoch: (p_h['freshness'].is_a?(Hash) && p_h['freshness'].key?('epoch') ? p_h['freshness']['epoch'] : V2JS::UNDEF) }
        kw[:last_accepted_epoch] = re['lastAcceptedEpoch'] if re.is_a?(Hash) && !re['lastAcceptedEpoch'].nil?
        kw[:max_age_ms] = re['maxAgeMs'] if re.is_a?(Hash) && !re['maxAgeMs'].nil?
        r = AtlasPca.check_revocation_epoch(member(re, 'epoch'), member(re, 'guardianPublic'), now, grant['id'], nil, **kw)
        if r['ok']
          mark.call('freshness', 'pass') unless checks['freshness'] == 'fail'
        else
          fail.call('freshness', r['reason'] || 'revocation epoch rejected')
        end
      elsif !checks.key?('freshness')
        mark.call('freshness', 'not-enforced')
      end

      # ---- the dead-man liveness beacon
      bc = ctx['beacon']
      bc_on = truthy?(bc)
      br = nil
      replayed = false
      ref_binds = false
      if bc_on
        bc_h = obj(bc)
        beacon = bc_h['beacon']
        br = AtlasPca.verify_liveness_beacon(beacon, issuers: bc_h['issuers'], now: now, instance: bc_h['instance'], scope: grant['id'], pq_pins: bc_h['pqPins'])
        last = bc_h['lastAcceptedSeq']
        replayed = br['ok'] == true && !last.nil? && fin?(beacon.is_a?(Hash) ? beacon['seq'] : nil) && beacon['seq'] < last
        fr = p_h['freshness']
        ref_binds = br['ok'] == true && !replayed && fr.is_a?(Hash) && fr['beacon_ref'] == AtlasPca.beacon_ref(beacon)
      end
      if !bc_on then mark.call('beacon', 'not-enforced')
      elsif br['ok'] != true then fail.call('beacon', br['reason'] || 'beacon rejected')
      elsif replayed then fail.call('beacon', "beacon seq #{Predicates.js_number_string(bc['beacon']['seq'].to_f)} is older than the last accepted #{Predicates.js_number_string(bc['lastAcceptedSeq'].to_f)} (replay)")
      elsif !ref_binds then fail.call('beacon', 'PCActn freshness.beacon_ref does not bind the presented beacon')
      else mark.call('beacon', 'pass')
      end

      # ---- require-when-bound: a grant that binds the agent REQUIRES a passing attestation
      if AtlasPca.requires_attestation?(grant_env.is_a?(Hash) ? grant_env['agent_binding'] : nil) && checks['attestation'] != 'pass'
        fail.call('attestation', 'the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED')
      end

      # ---- budget (an absent one fails closed to B = 0) and the risk inputs
      chain = p_h['cap_chain'].is_a?(Array) ? p_h['cap_chain'] : []
      depth = [0, chain.length - 1].max
      has_budget = !ctx['budget'].nil?
      budget_in = has_budget ? ctx['budget'] : { 'B' => 0, 'tau' => now, 'asOf' => now }
      mark.call('budget', has_budget ? 'pass' : 'not-enforced')
      reasons << 'budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge' unless has_budget
      risk = ctx['risk'].is_a?(Hash) ? ctx['risk'].dup : {}
      req_risk = opt(opts, 'requireRiskInputs')
      if list?(req_risk) && !req_risk.empty?
        supplied = ->(k) { fin?(risk[k]) || (k == 'semanticDistance' && !ctx['plan'].nil?) }
        missing = req_risk.reject { |k| supplied.call(k) }
        if missing.empty? then mark.call('risk_inputs', 'pass')
        else fail.call('risk_inputs', "required risk input(s) not supplied by the server: #{missing.map { |k| jstr(k) }.join(', ')}")
        end
      end

      # ---- reversibility: the server's class wins; the agent may only be stricter
      declared = action['reversibility_class']
      reversibility = declared
      if ctx.key?('reversibilityClass')
        sc = ctx['reversibilityClass']
        dr = AtlasPca.class_rank(declared)
        sr = AtlasPca.class_rank(sc)
        if dr < sr then fail.call('reversibility', "declared class '#{jstr(declared)}' is less restrictive than the authoritative '#{jstr(sc)}'")
        else mark.call('reversibility', 'pass')
        end
        reversibility = dr > sr ? declared : sc
      end

      # ---- the Policy VM
      inner = {}
      inner['verb'] = action['verb'] if action.key?('verb')
      inner['resource'] = action['resource'] if action.key?('resource')
      inner['params'] = ctx['params'] unless ctx['params'].nil?
      inner['reversibility_class'] = reversibility unless reversibility.nil?
      action_ctx = { 'action' => inner }
      action_ctx['subject'] = ctx['subject'] unless ctx['subject'].nil?
      pe = p_h.key?('intent_session') ? v2_env(v2d, ctx['env']) : ctx['env']
      action_ctx['env'] = pe unless pe.nil?
      action_ctx['toolBinding'] = p_h['tool_binding'] if p_h['tool_binding'].is_a?(String)
      recent = ctx['recentActionTimes']
      caveat_ctx = { 'delegationDepth' => depth }
      caveat_ctx['recentActionTimes'] = recent unless recent.nil?
      plan_h = p_h['plan'].is_a?(Hash) ? p_h['plan'] : {}
      k1_in = opt(opts, 'k1')
      d_in = { 'grant' => grant, 'trustedRoot' => grant, 'action' => action_ctx, 'risk' => risk,
               'budget' => has_budget ? budget_in : budget_in.merge('B' => 0), 'now' => now, 'caveatContext' => caveat_ctx }
      d_in['pqPins'] = pq_pins.is_a?(Hash) ? pq_pins : {} unless pq_pins.nil?
      d_in['plan'] = plan_nodes if plan_supplied
      d_in['nodeId'] = plan_h['node_id'] unless plan_h['node_id'].nil?
      d_in['k1'] = obj(k1_in).reject { |k, _| k == 'narrow' }.merge('action_digest' => AtlasPca.discharge_action_digest(p_h)) unless k1_in.nil?
      d_in['rFloor'] = p_h['caution'] if fin?(p_h['caution'])
      d = AtlasPca.decide(d_in)

      # caveats added by delegation hops are conjunctive too
      leaf = chain.empty? ? nil : chain[-1]
      k1_bound = nil
      unless leaf.nil?
        raise TypeError, 'leaf.caveats.slice is not a function' unless leaf.is_a?(Hash) && leaf['caveats'].is_a?(Array)

        extra = leaf['caveats'][grant['caveats'].length..] || []
        use_k1 = leaf['caveats'].any? { |cv| AtlasPca.k1_caveat?(cv) } || (k1_in.is_a?(Hash) && k1_in.key?('narrow'))
        k1r = nil
        if use_k1
          k1r = AtlasPca.evaluate_k1(grant, chain, k1_in.nil? ? nil : obj(k1_in).merge('action_digest' => AtlasPca.discharge_action_digest(p_h)), { 'now' => now, 'action' => inner })
          k1_bound = k1r[:bound]
        end
        rc = AtlasPca.resolve_reversibility_class(action_ctx, plan_nodes, plan_h['node_id'])
        cctx = { 'now' => now, 'action' => inner, 'delegation_depth' => depth }
        cctx['blast_radius'] = risk['blastRadius'] unless risk['blastRadius'].nil?
        cctx['reversibility_class'] = rc unless rc.nil?
        cctx['recent_action_times'] = recent unless recent.nil?
        tool_call = { 'tool' => inner['verb'].is_a?(String) ? inner['verb'] : '', 'args' => inner['params'].is_a?(Hash) ? inner['params'] : {} }
        tool_call['tool_signature_digest'] = action_ctx['toolBinding'] if action_ctx['toolBinding'].is_a?(String)
        list = extra.reject { |cv| AtlasPca.k1_caveat?(cv) } + (k1r ? k1r[:plain] : [])
        ok, failed = AtlasPca.evaluate_agent_caveats(list, cctx, action_ctx, tool_call)
        if ok && (k1r.nil? || k1r[:ok])
          mark.call('delegated_caveats', 'pass')
        else
          why = "delegation caveat(s) not satisfied: #{(failed + (k1r ? k1r[:failed] : [])).join(', ')}"
          why += " (#{k1r[:reasons].join('; ')})" if k1r && !k1r[:ok]
          fail.call('delegated_caveats', why)
        end
      end

      # ---- policy and threshold
      release = d['releaseGuardianShare'] == true
      mark.call('policy', release ? 'pass' : 'fail')
      d['reasons'].each { |x| reasons << "policy: #{x}" }
      t_req = d['requiredThreshold']['t']
      th = checks['threshold']
      hook_t = hook_state[:t]
      hook_ti = hook_t_int(hook_t)
      if t_req > 1 && release && th == 'pass' && !(!hook_ti.nil? && hook_ti >= t_req)
        fail.call('threshold', "threshold hook enforced t=#{hook_t.nil? ? 'unreported' : jstr(hook_t)} but the server requires t=#{t_req} (below the server-derived threshold; derive t from server-held data)")
      elsif t_req > 1 && release && th != 'pass'
        fail.call('threshold', th == 'fail' ? "t=#{t_req} required and the threshold proof was rejected" : "t=#{t_req} (#{d['requiredThreshold']['proof']}) required but no threshold verifier is enforced")
      end

      # ---- assurance
      required = opts_key?(opts, 'require') ? opts['require'] : DEFAULT_REQUIRED_CHECKS
      req_a = opt(opts, 'requireAssurance')
      want_assurance = opt(opts, 'assurance') == true || opts_key?(opts, 'requireAssurance')
      att_for_report = member(enforce, 'attestation').is_a?(Hash) && !member(enforce, 'attestation')['verifier'].nil? ? enforce['attestation']['verifier'] : hooks['attestation']
      report_hooks = opt(opts, 'hooks').is_a?(Hash) ? hooks.slice('attestation', 'zk', 'threshold', 'revocation').compact : nil
      degraded = v2d && v2d['legacy_model_polarity'] == true ? { 'tighten' => "model_polarity 'legacy': a grant reads a model-derived value in where (rule 21)" } : nil
      report = ->(cs) { AtlasPca.assurance_report(p_h, cs, degraded, hooks: report_hooks, attestation_hook: att_for_report, threshold_t: hook_t) }
      if truthy?(req_a)
        unmet = unmet(report.call(checks), req_a)
        if unmet.nil? then mark.call('assurance', 'pass')
        else
          checks['assurance'] = 'fail'
          reasons << unmet
        end
      end

      allow = checks.values.none?('fail') && release && c['allow']
      final = checks.dup
      unsupported.each { |n| final[n] = 'unsupported' if final[n] == 'not-enforced' }
      budget_out = ctx['budget'].nil? ? nil : pick_budget(d['budget'])
      raise TypeError, 'required.map is not a function' unless required.is_a?(Array)

      refused = unsupported.reject { |n| allow_list(opt(opts, 'allowUnsupported')).include?(n) }
      unless refused.empty?
        out = { 'allow' => false, 'r' => d['r'], 'requiredThreshold' => d['requiredThreshold'], 'checks' => final,
                'reasons' => reasons + refused.map { |n| "#{n}: unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)" } }
        out = enforce_required(out, required)
        out['assurance'] = AtlasPca.refresh_assurance(report.call(final), out['checks']) if want_assurance
        return out
      end
      out = { 'allow' => allow, 'r' => d['r'], 'requiredThreshold' => d['requiredThreshold'], 'checks' => final, 'reasons' => reasons }
      out['budget'] = budget_out if allow && !budget_out.nil?
      out['k1Bound'] = k1_bound if k1_bound&.any? { |b| b['caveat'].is_a?(Hash) && b['caveat']['type'] == 'max_uses' }
      out = enforce_required(out, required)
      # an escalation keeps the post-decision budget: an answered escalation is admitted with it, never free
      out['budget'] = pick_budget(d['budget']) if !out['allow'] && !ctx['budget'].nil? && AtlasPca.decision_of(out) == 'escalate'
      out['reasons'] = ['denied'] if !out['allow'] && out['reasons'].empty?
      out['assurance'] = AtlasPca.refresh_assurance(report.call(final), out['checks']) if want_assurance
      out
    end

    # the budget of a decision as the verdict reports it: B, tau and asOf (undefined members absent)
    def pick_budget(b) = b.is_a?(Hash) ? b.slice('B', 'tau', 'asOf').compact : b

    # the hook's t as the reference reads it: floored and clamped to the safe range; nil when it is not a number
    def hook_t_int(t)
      return nil unless t.is_a?(Integer) || (t.is_a?(Float) && !t.nan?)
      return MAX_SAFE if t >= MAX_SAFE
      return -MAX_SAFE if t <= -MAX_SAFE

      t.floor
    end

    # the predicate `env`: the host's, with the verifier-computed v2 members (only the verifier computes them)
    def v2_env(v2d, env)
      rest = env.is_a?(Hash) ? env.dup : {}
      %w[acc mon canon world prov class].each { |k| rest.delete(k) }
      ((v2d && v2d['env']) || {}).each { |k, v| rest[k] = v unless v.nil? }
      rest
    end

    def allow_list(v) = v.is_a?(Array) ? v.select { |x| x.is_a?(String) } : []

    # Default-deny: every required check must be `pass`; one that is not turns the verdict to a deny and (unless already `fail`) is recorded as
    # `fail` with its reason. `counter` is the old name of `replay` (with a store) or `counter_format`.
    def enforce_required(v, required)
      checks = v['checks'].dup
      reasons = v['reasons'].dup
      allow = v['allow']
      required.each do |name0|
        name = name0.is_a?(String) ? name0 : jstr(name0)
        name = checks.key?('replay') ? 'replay' : 'counter_format' if name == 'counter' && !checks.key?('counter')
        st = checks[name]
        next if st == 'pass'

        allow = false
        next if st == 'fail'

        reasons << "#{name}: required check is #{st == 'unsupported' ? 'unsupported' : (st || 'absent')} (default-deny: not enforced by this resource server)"
        checks[name] = 'fail'
      end
      v.merge('allow' => allow, 'checks' => checks, 'reasons' => reasons)
    end

    # The one unmet_assurance: an unknown key or value (a `threshold` that is not a list included) is refused there, fail closed.
    def unmet(report, req) = AtlasPca.unmet_assurance(report, req)
  end

  def self.verify_verdict(pcactn, opts) = VerifyVerdict.verify(pcactn, opts)
end
