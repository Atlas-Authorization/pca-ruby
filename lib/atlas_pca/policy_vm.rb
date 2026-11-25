# frozen_string_literal: true

module AtlasPca
  # `deriveDecideInput` was called without `grant` (the verifier's own stored grant). Never defaulted from the artifact.
  class DecideInputGrantRequired < ArgumentError
    def code = 'grant_required'

    def initialize(msg = 'deriveDecideInput: ctx.grant (the grant from your own store) is required; the presented chain root is never used as the grant')
      super
    end
  end

  # The deterministic Policy VM decision (the reference's `decide` of policy-vm.ts): the release decision for one action from the grant
  # and its delegation chain, the risk inputs and the trust budget. Input (String keys): grant, action ({'action' => {verb, resource,
  # params?, reversibility_class?}, 'subject'?, 'env'?}), chain?, plan?, nodeId?, goalNodeId?, risk, budget, now, caveatContext?
  # (camelCase), ageHorizonMs?, rFloor?, chainVerified?, pqPins?, trustedRoot?, k1?. Result: releaseGuardianShare, requiredThreshold,
  # r, admit, needStepUp, reasons, budget (and k1Bound when the caveat language ran). TOTAL: any error is a fail-closed denial.
  module PolicyVm
    module_function

    CAVEAT_CTX = { 'blastRadius' => 'blast_radius', 'reversibilityClass' => 'reversibility_class',
                   'recentActionTimes' => 'recent_action_times', 'delegationDepth' => 'delegation_depth' }.freeze

    def denied(reason, budget)
      { 'releaseGuardianShare' => false, 'requiredThreshold' => { 't' => 3, 'proof' => 'strong', 'optimisticAllowed' => false }, 'r' => 1,
        'admit' => false, 'needStepUp' => true, 'reasons' => [reason], 'budget' => budget }
    end

    def stringify(h) = h.is_a?(Hash) ? h.to_h { |k, v| [k.to_s, v] } : h

    def no_k1(cs) = cs.is_a?(Array) ? cs.reject { |c| AtlasPca.k1_type?(c) } : cs

    def decide(input)
      inp = input.is_a?(Hash) ? stringify(input) : {}
      b = inp['budget']
      fallback = b.nil? || b == false ? { 'B' => 0, 'tau' => 0 } : b
      AtlasPca.with_regex_budget { inner(inp, fallback) }
    rescue StandardError, SystemStackError => e
      denied("policy evaluation error (fail closed): #{e.message.to_s.empty? ? 'unknown' : e.message}", fallback)
    end

    def inner(inp, fallback)
      grant = inp['grant']
      env = AtlasPca.read_envelope(grant)
      return denied('grant carries no valid envelope', inp['budget']) if env.nil?

      now = inp['now']
      return denied('invalid decision time', inp['budget']) unless Risk.fin?(now)

      chain_in = inp['chain']
      if inp['chainVerified'] != true
        to_verify = chain_in.is_a?(Array) && !chain_in.empty? ? chain_in : [grant]
        issuer = grant['issuer']
        pins = inp['pqPins']
        why, ok = AtlasPca.verify_chain(to_verify, issuer.is_a?(String) ? issuer : nil, issuer.is_a?(String), nil,
                                        pins.is_a?(Hash) ? pins : nil, inp['trustedRoot'].is_a?(Hash) ? inp['trustedRoot'] : nil)
        return denied("capability chain unverified: #{why}", inp['budget']) unless ok
      end

      pol = env['risk_policy']
      reasons = []
      action_ctx = inp['action'].is_a?(Hash) ? stringify(inp['action']) : {}
      inner_action = action_ctx['action'].is_a?(Hash) ? action_ctx['action'] : {}

      # 1. semantic predicates (default deny)
      pr = AtlasPca.evaluate_predicates(env['predicates'], action_ctx)
      pr_ok = pr['allowed'] == true
      reasons << (pr['reason'] || 'action not permitted by envelope predicates') unless pr_ok

      node_id = inp['nodeId']
      plan = inp['plan'].is_a?(Array) ? inp['plan'] : nil
      risk = inp['risk'].is_a?(Hash) ? stringify(inp['risk']) : {}
      rev_class = AtlasPca.resolve_reversibility_class(action_ctx, plan, node_id)

      # 2. envelope caveats
      cctx = { 'now' => now, 'action' => inner_action }
      cctx['blast_radius'] = risk['blastRadius'] unless risk['blastRadius'].nil?
      cctx['reversibility_class'] = rev_class unless rev_class.nil?
      over = inp['caveatContext'].is_a?(Hash) ? stringify(inp['caveatContext']) : {}
      CAVEAT_CTX.each { |camel, snake| cctx[snake] = over[camel] if over.key?(camel) }
      params = inner_action['params']
      tool_call = { 'tool' => inner_action['verb'].is_a?(String) ? inner_action['verb'] : '', 'args' => params.is_a?(Hash) ? params : {} }
      tool_call['tool_signature_digest'] = action_ctx['toolBinding'] if action_ctx['toolBinding'].is_a?(String)

      chain_ok = true
      extra = []
      gcs = grant['caveats'].is_a?(Array) ? grant['caveats'] : []
      if inp.key?('chain')
        if !chain_in.is_a?(Array) || chain_in.empty?
          chain_ok = false
          reasons << 'delegation chain is empty or malformed'
        else
          cctx['delegation_depth'] = chain_in.length - 1
          lcs = chain_in[-1].is_a?(Hash) ? chain_in[-1]['caveats'] : nil
          extra = lcs.is_a?(Array) ? (lcs[gcs.length..] || []) : []
        end
      end
      ecv_ok, ecv_failed = AtlasPca.evaluate_agent_caveats(env['caveats'], cctx, action_ctx, tool_call)
      reasons << "caveat(s) not satisfied: #{ecv_failed.join(', ')}" unless ecv_ok

      # root caveats outside the envelope are signed authority too; the caveat-language (K1) types run over the whole chain
      leaf_hop = chain_in.is_a?(Array) && !chain_in.empty? ? chain_in[-1] : grant
      leaf_cv = leaf_hop.is_a?(Hash) ? leaf_hop['caveats'] : nil
      k1_in = inp['k1']
      use_k1 = (k1_in.is_a?(Hash) && k1_in.key?('narrow')) || (leaf_cv.is_a?(Array) && leaf_cv.any? { |c| AtlasPca.k1_type?(c) })
      k1 = use_k1 ? AtlasPca.evaluate_k1(grant, chain_in, k1_in.is_a?(Hash) ? k1_in : nil, { 'now' => now, 'action' => inner_action }) : nil
      rcv_ok, rcv_failed = AtlasPca.evaluate_agent_caveats(no_k1(AtlasPca.root_caveats(grant)), cctx, action_ctx, tool_call)
      reasons << "root caveat(s) not satisfied: #{rcv_failed.join(', ')}" unless rcv_ok
      cv_ok = ecv_ok && rcv_ok
      dcv_ok, dcv_failed = AtlasPca.evaluate_agent_caveats(no_k1(extra) + (k1 ? k1[:plain] : []), cctx, action_ctx, tool_call)
      reasons << "delegated caveat(s) not satisfied: #{dcv_failed.join(', ')}" unless dcv_ok
      if k1 && !k1[:ok]
        dcv_ok = false
        k1[:reasons].each_with_index { |why, i| reasons << "caveat language: #{k1[:failed][i]}: #{why}" }
      end

      # 3. risk
      bi = stringify(inp['budget'])
      num = ->(x) { x.is_a?(Integer) || x.is_a?(Float) } # a non-finite number is still a number: the reference's leak() degrades it, it does not refuse
      unless bi.is_a?(Hash) && num.(bi['B']) && num.(bi['tau']) && (bi['asOf'].nil? || num.(bi['asOf']))
        raise ArgumentError, 'budget is not a trust budget'
      end

      leaked = Risk.leak(bi, now, pol['lambda'])
      inputs = Risk::WORST.merge(risk.select { |k, v| Risk::INPUT_KEYS.include?(k) && Risk.fin?(v) })
      missing = Risk::INPUT_KEYS.reject { |k| k == 'age' || Risk.fin?(risk[k]) }
      if plan && !risk.key?('semanticDistance')
        goal = inp['goalNodeId'] || (plan.last.is_a?(Hash) ? plan.last['id'] : nil)
        inputs['semanticDistance'] = node_id.is_a?(String) && goal.is_a?(String) ? Risk.plan_geodesic(plan, node_id, goal) : 1
        missing.delete('semanticDistance')
      end
      inputs['age'] = Risk.age_since_touch(leaked, now, inp['ageHorizonMs'].nil? ? 3_600_000 : inp['ageHorizonMs']) unless risk.key?('age')
      reasons << "risk input(s) missing, assumed worst case: #{missing.join(', ')}" unless missing.empty?
      r_floor = Risk.fin?(inp['rFloor']) ? Risk.clamp01(inp['rFloor']) : 0
      r = [Risk.risk_score(inputs, pol['weights']), r_floor].max

      # a class that is not a recognized non-irreversible one is treated as irreversible (never fail-open)
      rc = cctx['reversibility_class']
      irreversible = !(rc.is_a?(String) && AtlasPca::FAST_PATH_CLASSES.include?(rc))
      rt = Risk.required_threshold(r, pol, irreversible: irreversible)

      # 4. budget admission
      adm = Risk.admit_of(Risk.required_threshold(r, pol)['t'], Risk.fin?(leaked['B']) && leaked['B'] >= Risk.cost(r, pol['kappa']))
      if adm['needStepUp']
        reasons << (rt['t'] < 3 && adm['t'] == 3 ? 'trust budget depleted: human recharge required' :
                    "risk #{Risk.to_fixed3(r)} exceeds auto threshold: step-up to t=#{adm['t']}")
      end

      # 5. guardian release: policy AND caveats AND a well-formed chain; the human / step-up path stays available otherwise
      dec = Risk.decide_core(pr_ok, cv_ok, dcv_ok, chain_ok, rt, adm)
      out_budget = dec['debit'] ? Risk.debit(leaked, Risk.cost(r, pol['kappa'])) : leaked
      res = { 'releaseGuardianShare' => dec['release'], 'requiredThreshold' => dec['threshold'], 'r' => r, 'admit' => dec['admit'],
              'needStepUp' => dec['needStepUp'], 'reasons' => reasons, 'budget' => out_budget }
      res['k1Bound'] = k1[:bound].map { |x| { 'caveat' => x['caveat'], 'hop' => x['hop'], 'capHash' => x['cap_hash'] } } if k1
      res
    end

    # Assemble a decide input from a PCActn plus the verifier's own context (Hash, String or Symbol keys: grant, params?, risk, budget,
    # now, chain?, plan?, pqPins?, goalNodeId?, subject?, env?, caveatContext?, ageHorizonMs?), so caller and verifier derive the action,
    # node and chain identically. `grant` is REQUIRED (the grant from the verifier's own store, also the chain's trusted root; never
    # defaulted from the presented chain). `params` must already be checked against the action's params_digest.
    def derive_decide_input(pcactn, ctx)
      grant = AtlasPca.arg_member(ctx, 'grant')
      raise DecideInputGrantRequired unless grant.is_a?(Hash) || grant.is_a?(Array) # `typeof grant === 'object'`: an array passes

      raise TypeError, "Cannot read properties of null (reading 'cap_chain')" if pcactn.nil?

      pc = pcactn.is_a?(Hash) ? pcactn : {} # the members of a value that is not an object read as undefined
      act = pc['action'].is_a?(Hash) ? pc['action'] : {}
      has = ->(k) { ctx.key?(k) || ctx.key?(k.to_sym) }
      params = AtlasPca.arg_member(ctx, 'params')
      # a member that is JSON null stays (null is a value), a member that is absent stays absent (undefined)
      inner = %w[verb resource].select { |k| act.key?(k) }.to_h { |k| [k, act[k]] }
      inner['params'] = params.nil? ? {} : params
      inner['reversibility_class'] = act['reversibility_class'] if act.key?('reversibility_class')
      action = { 'action' => inner }
      %w[subject env].each do |k|
        v = AtlasPca.arg_member(ctx, k)
        action[k] = v unless v.nil? || v == false || v == '' || v == 0
      end
      out = { 'grant' => grant, 'trustedRoot' => grant }
      put = ->(k) { out[k] = AtlasPca.arg_member(ctx, k) if has.call(k) }
      put.call('pqPins')
      chain = AtlasPca.arg_member(ctx, 'chain')
      if !chain.nil? then out['chain'] = chain
      elsif pc.key?('cap_chain') then out['chain'] = pc['cap_chain']
      end
      out['action'] = action
      put.call('plan')
      out['nodeId'] = pc['plan']['node_id'] if pc['plan'].is_a?(Hash) && pc['plan'].key?('node_id')
      put.call('goalNodeId')
      %w[risk budget now caveatContext ageHorizonMs].each { |k| put.call(k) }
      out
    end
  end

  def self.decide(input) = PolicyVm.decide(input)
  def self.derive_decide_input(pcactn, ctx) = PolicyVm.derive_decide_input(pcactn, ctx)
end
