# frozen_string_literal: true

module AtlasPca
  # Policy simulation and linting (the reference's `policy-sim` module): before a principal enables a grant, replay a batch of
  # historical or hypothetical actions against the compiled policy and see which are admitted on their own, which force a step-up
  # and which are denied, plus static lints for the classic authoring mistakes. Pure and offline: it composes compile_policy, the
  # predicate and caveat evaluators and the trust budget algebra; it signs nothing and reaches no network. A planning tool: the
  # resource server's verifier stays the authority at run time.
  # `policy` is what compile_policy returns; an action is {'verb', 'resource', 'params'?, 'at'?}; `catalog` is a Catalog (or an
  # Array of action specs), default the built-in one.
  module PolicySim
    module_function

    def catalog_of(catalog)
      return Catalog::DEFAULT_CATALOG if catalog.nil?

      catalog.is_a?(Array) ? Catalog.new(catalog) : catalog
    end

    def nan?(x) = x.is_a?(Float) && x.nan?

    # the risk of one action: amount / kappa under the dollars model for a money verb, else the catalog's blast radius (0.8 for a
    # verb the catalog does not know), clamped to [0, 1]
    def risk_of(policy, catalog, verb, params)
      spec = catalog.get(verb)
      kappa = policy['riskPolicy']['kappa']
      if policy['budgetModel'] == 'dollars' && spec && spec['amountField'].is_a?(String) && !spec['amountField'].empty?
        amount = AtlasPca.js_to_number(params.nil? ? {} : params, spec['amountField'])
        return AtlasPca.js_clamp01(amount / kappa) if amount.finite? && kappa.positive?
      end
      AtlasPca.js_clamp01(spec ? spec['blastRadius'] : 0.8)
    end

    # Replay `actions` in time order against the policy, threading the trust budget as the server would (the leak between
    # actions, a debit of kappa * r on every admitted action, a step-up when the budget cannot cover a machine-band action).
    # `start` is the start TIME (default 0): an action without 'at' occurs at start + its index; the budget starts at bMax. An
    # action with no finite time is reported as denied, first. Returns {'results' => [{'action', 'outcome' ('auto' | 'step_up' |
    # 'deny'), 't'?, 'r', 'reason'?, 'budgetAfter'}], 'auto', 'stepUp', 'deny', 'endBudget', 'peakRisk', 'autonomousRisk'}.
    def simulate(policy, actions, catalog: nil, start: nil)
      catalog = catalog_of(catalog)
      start = 0 if start.nil?
      rp = policy['riskPolicy']
      timed = actions.each_with_index.map { |a, i| [a, a['at'].nil? ? start + i : a['at'], i] }
      untimed, ordered = timed.partition { |_, at, _| !Risk.fin?(at) }
      ordered = ordered.sort_by { |_, at, i| [at, i] } # a stable sort, as the reference's

      budget = { 'B' => rp['bMax'], 'tau' => start, 'asOf' => start }
      recent = []
      results = []
      peak = 0
      autonomous = 0
      untimed.each do |a, _, _|
        results << { 'action' => a, 'outcome' => 'deny', 'r' => 1, 'reason' => 'action has no finite time', 'budgetAfter' => budget['B'] }
      end

      ordered.each do |a, at, _|
        spec = catalog.get(a['verb'])
        reversibility = spec && !spec['reversibility'].nil? ? spec['reversibility'] : 'irreversible'
        ctx = { 'action' => { 'verb' => a['verb'], 'resource' => a['resource'], 'params' => a['params'].nil? ? {} : a['params'],
                              'reversibility_class' => reversibility } }
        r = risk_of(policy, catalog, a['verb'], a['params'])
        peak = nan?(peak) || nan?(r) ? Float::NAN : [peak, r].max

        pred = AtlasPca.evaluate_predicates(policy['predicates'], ctx)
        cav_ok = false
        failed = []
        if pred['allowed']
          cav_ok, failed = AtlasPca.evaluate_caveats(policy['caveats'], { 'now' => at, 'blast_radius' => spec && !spec['blastRadius'].nil? ? spec['blastRadius'] : 1,
                                                                         'reversibility_class' => reversibility, 'recent_action_times' => recent.dup })
        end
        budget = Risk.leak(budget, at, rp['lambda'])

        unless pred['allowed']
          results << { 'action' => a, 'outcome' => 'deny', 'r' => r, 'reason' => pred['reason'].nil? ? 'no predicate permits this action' : pred['reason'],
                       'budgetAfter' => budget['B'] }
          next
        end
        unless cav_ok
          results << { 'action' => a, 'outcome' => 'deny', 'r' => r, 'reason' => "caveat(s) failed: #{failed.join(', ')}", 'budgetAfter' => budget['B'] }
          next
        end
        adm = Risk.admit(r, budget, rp)
        if adm['t'] == 1 && adm['admit']
          budget = budget.merge('B' => budget['B'] - Risk.cost(r, rp['kappa']))
          autonomous += r
          recent << at
          results << { 'action' => a, 'outcome' => 'auto', 't' => 1, 'r' => r, 'budgetAfter' => budget['B'] }
        else
          # t = 2 (the guardian co-signs) and t = 3 (a human) both show as a step-up in the planning view
          res = { 'action' => a, 'outcome' => 'step_up', 't' => adm['t'], 'r' => r }
          res['reason'] = "requires tier #{adm['t']}" if adm['needStepUp']
          results << res.merge('budgetAfter' => budget['B'])
        end
      end

      count = ->(o) { results.count { |x| x['outcome'] == o } }
      { 'results' => results, 'auto' => count.call('auto'), 'stepUp' => count.call('step_up'), 'deny' => count.call('deny'),
        'endBudget' => budget['B'], 'peakRisk' => peak, 'autonomousRisk' => autonomous }
    end

    def severity(cls) = REVERSIBILITY_ORDER.index(cls) || -1

    # Static lints over a compiled policy: [{'level' ('error' | 'warn' | 'info'), 'code', 'message'}]. error: almost certainly a
    # mistake (a limit that matches no granted action); warn: a real risk worth a second look; info: a notable property. Pure.
    def lint_policy(policy, catalog: nil)
      catalog = catalog_of(catalog)
      lints = []
      granted = policy['actions'].flat_map { |s| [s['verb'], s['action'], *(s['aliases'] || [])] }
      policy['inputLimits'].each_key do |key|
        lints << { 'level' => 'error', 'code' => 'limit-unmatched', 'message' => "limit for '#{key}' matches no granted action" } unless granted.include?(key)
      end

      policy['actions'].each do |spec|
        verb = spec['verb']
        pred = policy['predicates'].find { |p| p['verb'] == verb }
        resource = pred && pred['resource']
        broad = resource.nil? || resource == false || resource == '' || resource == '*'
        if spec['amountField'].is_a?(String) && !spec['amountField'].empty? && !policy['limits'][verb]
          lints << { 'level' => 'warn', 'code' => 'money-unbounded',
                     'message' => "money action '#{verb}' has no per-call limit — spend is bounded only by the trust budget" }
        end
        if broad && severity(spec['reversibility']) >= severity('rate_limited')
          lints << { 'level' => 'warn', 'code' => 'broad-resource', 'message' => "'#{verb}' (#{spec['reversibility']}) matches ANY resource — consider a resource prefix" }
        end
        unless catalog.get(verb)
          lints << { 'level' => 'info', 'code' => 'uncatalogued',
                     'message' => "'#{verb}' is not in the catalog — treated conservatively (irreversible, high blast radius)" }
        end
      end

      # the budget never forces a human: every within-cap action is admitted on its own. Intended for a capped autonomous agent.
      rp = policy['riskPolicy']
      if rp['theta2'] >= 1
        irreversible = policy['actions'].any? { |s| severity(s['reversibility']) >= severity('irreversible') }
        lints << { 'level' => irreversible ? 'warn' : 'info', 'code' => 'no-step-up-band',
                   'message' => "theta2 ≥ 1: no action triggers a human step-up until the budget is exhausted#{irreversible ? ' — including irreversible actions' : ''}" }
      end
      if rp['kappa'].positive? && rp['bMax'] / rp['kappa'].to_f > 100
        bound = Predicates.js_number_string((rp['bMax'] / rp['kappa'].to_f + 0.5).floor)
        lints << { 'level' => 'warn', 'code' => 'large-autonomy', 'message' => "autonomous bound is #{bound}× a max-risk action between human co-signs" }
      end
      lints
    end
  end
end
