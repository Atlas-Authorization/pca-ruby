# frozen_string_literal: true

require_relative 'js_compat'

module AtlasPca
  # A replayable debugger over the pure decision core (PolicyVm.decide): explain_risk decomposes the risk score into its six weighted
  # terms, explain_decision explains a decide input, apply_delta / counterfactual re-run the core under edits and report which edits flip
  # the outcome, audit_pcactn re-verifies a proof-carrying action and attaches the explanation. Nothing here decides anything: every number
  # comes from the same decide the verifier runs. Inputs and reports are Hashes with the reference's member names (String keys).
  module PolicyDebug
    TERMS = [%w[semanticDistance alpha], %w[reversibility beta], %w[blastRadius gamma], %w[taint delta], %w[confidence epsilon],
             %w[age zeta]].freeze
    INVERTED = %w[reversibility confidence].freeze
    ZERO_WEIGHTS = { 'alpha' => 0, 'beta' => 0, 'gamma' => 0, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0 }.freeze
    NOT_GIVEN = Object.new.freeze
    NO_AUDIENCE = 'PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or audience: null to accept any)'
    HOOK_CHECKS = %w[taint_gate attestation threshold revocation].freeze

    module_function

    def fin?(v) = Risk.fin?(v)
    def clamp01(x) = Risk.clamp01(x)
    def wt(x) = fin?(x) && x > 0 ? x : 0
    def member(h, k) = h.is_a?(Hash) ? h[k] : nil

    # The risk score as its six terms, in the fixed order semanticDistance, reversibility, blastRadius, taint, confidence, age:
    # {'inputs', 'weights', 'terms' => [{'term', 'weight', 'input', 'effective', 'contribution', 'inverted'}], 'rawSum', 'rScore',
    # 'rFloor', 'r'} with r = max(rScore, rFloor). A missing or non-finite input counts as its worst value, a non-positive weight as 0.
    def explain_risk(inputs, weights, r_floor = 0)
      floor = fin?(r_floor) ? r_floor : 0
      raw = 0
      terms = TERMS.map do |name, wname|
        v = member(inputs, name)
        x = fin?(v) ? clamp01(v) : Risk::WORST[name]
        w = wt(member(weights, wname))
        inverted = INVERTED.include?(name)
        eff = inverted ? 1 - x : x
        raw += w * eff
        { 'term' => name, 'weight' => w, 'input' => x, 'effective' => eff, 'contribution' => w * eff, 'inverted' => inverted }
      end
      score = clamp01(raw)
      { 'inputs' => inputs, 'weights' => weights, 'terms' => terms, 'rawSum' => raw, 'rScore' => score, 'rFloor' => clamp01(floor),
        'r' => [score, clamp01(floor)].max }
    end

    # The risk inputs, floor and leaked budget exactly as decide resolves them.
    def resolve(inp, env)
      leaked = Risk.leak(inp['budget'], inp['now'], env['risk_policy']['lambda'])
      given = inp['risk'].is_a?(Hash) ? inp['risk'] : {}
      inputs = Risk::WORST.dup
      Risk::WORST.each_key { |k| inputs[k] = given[k] if fin?(given[k]) }
      plan = inp['plan']
      if plan.is_a?(Array) && !given.key?('semanticDistance')
        goal = inp['goalNodeId'].nil? ? (plan.last.is_a?(Hash) ? plan.last['id'] : nil) : inp['goalNodeId']
        inputs['semanticDistance'] = inp.key?('nodeId') && !goal.nil? ? Risk.plan_geodesic(plan, inp['nodeId'], goal) : 1
      end
      unless given.key?('age')
        inputs['age'] = inp.key?('ageHorizonMs') ? Risk.age_since_touch(leaked, inp['now'], inp['ageHorizonMs']) : Risk.age_since_touch(leaked, inp['now'])
      end
      floor = inp['rFloor']
      [inputs, fin?(floor) ? [1, [0, floor].max].min : 0, leaked]
    end

    # Explain one decide input: {'decision', 'risk', 'requiredThreshold', 't', 'autoAllow', 'needStepUp', 'releaseGuardianShare',
    # 'budget' => {'before', 'leaked', 'after', 'cost', 'safetyBound'}, 'reasons', 'envelopeValid'}. Without a readable envelope the risk
    # explanation has no terms and carries the (worst) score the decision reports.
    def explain_decision(input)
      inp = PolicyVm.stringify(input)
      decision = PolicyVm.decide(inp)
      env = AtlasPca.read_envelope(inp['grant'])
      pol = env ? env['risk_policy'] : AtlasPca::DEFAULT_RISK_POLICY
      if env
        inputs, floor, leaked = resolve(inp, env)
        risk = explain_risk(inputs, pol['weights'], floor)
      else
        leaked = inp['budget']
        r = decision['r']
        risk = { 'inputs' => Risk::WORST.dup, 'weights' => ZERO_WEIGHTS.dup, 'terms' => [], 'rawSum' => r, 'rScore' => r, 'rFloor' => 0, 'r' => r }
      end
      { 'decision' => decision, 'risk' => risk, 'requiredThreshold' => decision['requiredThreshold'], 't' => decision['requiredThreshold']['t'],
        'autoAllow' => decision['admit'], 'needStepUp' => decision['needStepUp'], 'releaseGuardianShare' => decision['releaseGuardianShare'],
        'budget' => { 'before' => inp['budget'], 'leaked' => leaked, 'after' => decision['budget'], 'cost' => Risk.cost(decision['r'], pol['kappa']),
                      'safetyBound' => Risk.safety_bound(pol) },
        'reasons' => decision['reasons'], 'envelopeValid' => !env.nil? }
    end

    # ---- counterfactuals

    def describe(d)
      return d['label'] if Js.truthy?(d['label'])

      parts = []
      cosign = d['humanCosign']
      parts << (cosign.is_a?(Hash) && Js.truthy?(cosign['full']) ? 'human re-confirms goal (B←Bmax)' : 'human co-signs (B+ρ)') if Js.truthy?(cosign)
      { 'risk' => '', 'budget' => 'budget.' }.each do |m, prefix|
        d[m].each { |k, v| parts << "#{prefix}#{k}=#{Js.string(v)}" } if d[m].is_a?(Hash)
      end
      parts << "caution=#{Js.string(d['rFloor'])}" if d.key?('rFloor')
      parts << "now=#{Js.string(d['now'])}" if d.key?('now')
      d['caveatContext'].each { |k, v| parts << "ctx.#{k}=#{Js.json(v)}" } if d['caveatContext'].is_a?(Hash)
      parts.empty? ? 'no-op' : parts.join(', ')
    end

    # The decide input after a counterfactual edit {'label'?, 'risk'?, 'budget'?, 'rFloor'?, 'now'?, 'caveatContext'?, 'humanCosign'? =>
    # true | {'full'?}}: members of risk / budget / caveatContext override the input's, and a human co-sign recharges the budget (+rho,
    # or to bMax when full) at the edited time. The input is not changed.
    def apply_delta(input, delta)
      inp = PolicyVm.stringify(input)
      d = PolicyVm.stringify(delta)
      now = d['now'].nil? ? inp['now'] : d['now']
      budget = (inp['budget'].is_a?(Hash) ? inp['budget'] : {}).merge(d['budget'].is_a?(Hash) ? d['budget'] : {})
      cosign = d['humanCosign']
      if Js.truthy?(cosign)
        env = AtlasPca.read_envelope(inp['grant'])
        pol = env ? env['risk_policy'] : AtlasPca::DEFAULT_RISK_POLICY
        full = cosign.is_a?(Hash) && cosign['full'] == true
        budget = full ? Risk.recharge_full(budget, pol['bMax'], now) : Risk.recharge(budget, pol['rho'], pol['bMax'], now)
      end
      nxt = inp.dup
      nxt['now'] = now unless now.nil? && !inp.key?('now')
      nxt['budget'] = budget
      nxt['risk'] = (inp['risk'].is_a?(Hash) ? inp['risk'] : {}).merge(d['risk'].is_a?(Hash) ? d['risk'] : {})
      nxt['caveatContext'] = (inp['caveatContext'].is_a?(Hash) ? inp['caveatContext'] : {}).merge(d['caveatContext'].is_a?(Hash) ? d['caveatContext'] : {})
      nxt['rFloor'] = d['rFloor'] if d.key?('rFloor')
      nxt
    end

    # Re-run the decision under each edit: {'baseline', 'outcomes' => [{'label', 'delta', 'explanation', 'flipsAllow', 'allow',
    # 'thresholdDirection' => raised | lowered | same, 'changesThreshold', 't', 'rDelta'}], 'flipping' => [label],
    # 'thresholdChanging' => [label]}.
    def counterfactual(input, deltas)
      inp = PolicyVm.stringify(input)
      baseline = explain_decision(inp)
      outcomes = deltas.map do |d|
        ex = explain_decision(apply_delta(inp, d))
        dir = ex['t'] > baseline['t'] ? 'raised' : (ex['t'] < baseline['t'] ? 'lowered' : 'same')
        { 'label' => describe(d), 'delta' => d, 'explanation' => ex, 'flipsAllow' => ex['autoAllow'] != baseline['autoAllow'],
          'allow' => ex['autoAllow'], 'thresholdDirection' => dir, 'changesThreshold' => dir != 'same', 't' => ex['t'],
          'rDelta' => ex['risk']['r'] - baseline['risk']['r'] }
      end
      { 'baseline' => baseline, 'outcomes' => outcomes, 'flipping' => outcomes.select { |o| o['flipsAllow'] }.map { |o| o['label'] },
        'thresholdChanging' => outcomes.select { |o| o['changesThreshold'] }.map { |o| o['label'] } }
    end

    # ---- audit

    # The reasons of the reference's core for the checks the SDK's verifier words more coarsely, recomputed from the PCActn itself.
    def core_reason(name, reason, pcactn, now)
      return reason unless pcactn.is_a?(Hash)

      case name
      when 'version' then "unsupported ver #{Js.string(pcactn['ver'])} (this verifier requires 2)"
      when 'validity'
        iat = pcactn['iat']
        exp = pcactn['exp']
        if !now.is_a?(Integer) || now.abs > 9_007_199_254_740_991 then 'the verifier clock is not a safe integer epoch-ms'
        elsif !(exp > iat) then 'exp must be greater than iat'
        elsif exp - iat > AtlasPca::MAX_LIFETIME_MS then "lifetime exceeds #{AtlasPca::MAX_LIFETIME_MS} ms"
        elsif iat > now + AtlasPca::MAX_SKEW_MS then 'iat is in the future (clock skew)'
        else 'the PCActn has expired'
        end
      else reason
      end
    rescue StandardError
      reason
    end

    # The reference's wording of a failing capability chain: `empty chain`, `chain root is not the grant`, else the chain verifier's own reason
    # (`invalid` when it gives none). nil when it cannot be recomputed (the SDK's coarse reason then stands).
    def chain_reason(pcactn, grant)
      chain = pcactn['cap_chain']
      return 'empty chain' unless chain.is_a?(Array) && !chain.empty?
      return 'chain root is not the grant' unless AtlasPca.cap_hash(chain[0]) == AtlasPca.cap_hash(grant)

      issuer = grant['issuer']
      reason, ok = AtlasPca.verify_chain(chain, issuer, issuer.is_a?(String), nil, nil, grant)
      ok ? nil : (reason.to_s.empty? ? 'invalid' : reason)
    rescue StandardError
      nil
    end

    # A core verdict in the reference's report form: every check pass / fail / not-enforced under the reference's names.
    def verify_report(verdict, pcactn, audience, now, skipped_plan_root, grant = nil)
      ev = EvidenceVerify
      checks = verdict.checks.to_h { |k, ok| [ev.ts_check_name(k), ok == true ? 'pass' : 'fail'] }
      head, sep, rest = verdict.reason.to_s.partition(': ')
      reason = verdict.reason.nil? || verdict.reason.empty? ? nil : ev.ts_reason(verdict.reason)
      if checks.keys != ['wire']
        if !sep.empty? && %w[version validity].include?(head) && checks[head] == 'fail'
          reason = "#{head}: #{core_reason(head, rest, pcactn, now)}"
        elsif head == 'chain' && checks['cap_chain'] == 'fail' && pcactn.is_a?(Hash) && grant.is_a?(Hash) && (why = chain_reason(pcactn, grant))
          reason = "cap_chain: #{why}"
        end
        checks['plan_root_authorized'] = 'not-enforced' if skipped_plan_root && !checks.key?('plan_root_authorized')
        checks['audience'] = 'not-enforced' if audience.nil? && checks['audience'] == 'pass'
        if checks['audience'] == 'fail' && head == 'audience'
          reason = audience.equal?(NOT_GIVEN) ? "audience: #{NO_AUDIENCE}" : 'audience: aud does not match this resource server / instance'
        end
        HOOK_CHECKS.each { |k| checks[k] = 'not-enforced' unless checks.key?(k) }
        checks['bond'] = 'not-enforced' if pcactn.is_a?(Hash) && pcactn.key?('bond_ref') && !checks.key?('bond')
      elsif pcactn.is_a?(Hash)
        ext = { 'intent' => ->(v) { AtlasPca.validate_intent_wire(v) }, 'intent_session' => ->(v) { AtlasPca.validate_intent_session_wire(v) },
                'fresh_at' => ->(v) { AtlasPca.validate_fresh_at_wire(v) } }
        why = AtlasPca.validate_wire_v2(pcactn, ext)
        reason = "wire: #{why}" unless why.nil?
      end
      out = { 'allow' => verdict.allow == true, 'checks' => checks }
      out['reason'] = reason unless reason.nil?
      out
    end

    # Re-verify a proof-carrying action with the core verifier and attach the explanation of its decide input: {'verify' => {'allow',
    # 'checks', 'reason'?}, 'explanation'}. `audience`: this verifier's id; an explicit nil accepts any audience (reported not-enforced);
    # NOT_GIVEN (the default), a PCActn that carries a signed aud fails the audience check.
    def audit_pcactn(pcactn, input, grant, now_epoch: nil, audience: NOT_GIVEN, insecure_skip_plan_root_check: false,
                     attestation_hook: nil, threshold_hook: nil, zk_hook: nil)
      now = now_epoch.nil? ? AtlasPca.now_ms : now_epoch
      aud = if audience.equal?(NOT_GIVEN) then nil
            elsif audience.nil? then pcactn.is_a?(Hash) ? pcactn['aud'] : nil
            else audience
            end
      verdict = AtlasPca.verify_pcactn(pcactn, grant, now: now, audience: aud, insecure_skip_plan_root_check: insecure_skip_plan_root_check,
                                                      attestation_hook: attestation_hook, threshold_hook: threshold_hook, zk_hook: zk_hook)
      { 'verify' => verify_report(verdict, pcactn, audience, now, insecure_skip_plan_root_check == true, grant), 'explanation' => explain_decision(input) }
    end
  end
end
