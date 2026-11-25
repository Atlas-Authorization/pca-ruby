# frozen_string_literal: true

module AtlasPca
  # Budget forecaster and policy recommender (the reference's `budget-forecast` module): given a planned sequence of actions and
  # a compiled policy, how the trust budget drains, where the first step-up is forced and how many co-signs the whole plan
  # needs; and, inversely, the kappa / bMax that reach a target level of autonomy. Composes the simulator and the budget algebra.
  # Pure.
  module BudgetForecast
    module_function

    # Forecast `plan` ([{'verb', 'resource', 'params'?, 'at'?}]) against `policy` (what compile_policy returns). `start` is the
    # start time (default 0), `catalog` a Catalog (default: the built-in one; a verb it does not know fails closed). Returns
    # {'steps' => [{'verb', 'resource', 'outcome', 'r', 'budgetAfter'}], 'firstStepUpAt'? (index of the first forced step-up),
    # 'autonomousRisk', 'forcesCosign', 'cosignsNeeded', 'endBudget'}.
    def forecast(policy, plan, start: nil, catalog: nil)
      rep = PolicySim.simulate(policy, plan, start: start.nil? ? 0 : start, catalog: catalog)
      steps = rep['results'].map do |r|
        { 'verb' => r['action']['verb'], 'resource' => r['action']['resource'], 'outcome' => r['outcome'], 'r' => r['r'], 'budgetAfter' => r['budgetAfter'] }
      end
      first = steps.index { |s| s['outcome'] == 'step_up' }
      out = { 'steps' => steps }
      out['firstStepUpAt'] = first unless first.nil?
      out.merge('autonomousRisk' => rep['autonomousRisk'], 'forcesCosign' => rep['stepUp'].positive?, 'cosignsNeeded' => rep['stepUp'],
                'endBudget' => rep['endBudget'])
    end

    # x.toFixed(3) of the reference: the exact decimal expansion, a tie rounds away from zero; 1e21 and above print as a number does
    def fixed3(x)
      return Predicates.js_number_string(x) if x.abs >= 1e21

      n = ((x.to_r * 1000) + Rational(1, 2)).floor # x >= 0 here
      format('%d.%03d', n / 1000, n % 1000)
    end

    # The kappa / bMax with which an agent can take `target_actions` autonomous actions of typical risk `per_action_risk` (taken
    # into [0.000001, 1]) between human co-signs: the sum of the risks stays under bMax / kappa, so bMax = target_actions *
    # per_action_risk * kappa (kappa default 1). Returns {'kappa', 'bMax', 'autonomousBound', 'rationale'}. Raises RangeError
    # unless kappa is a positive finite number and both other arguments are finite numbers.
    def recommend_policy(target_actions, per_action_risk, kappa: nil)
      kappa = 1 if kappa.nil?
      raise RangeError, 'recommendPolicy: kappa must be a positive finite number' unless Risk.fin?(kappa) && kappa.positive?
      unless Risk.fin?(target_actions) && Risk.fin?(per_action_risk)
        raise RangeError, 'recommendPolicy: targetActions and perActionRisk must be finite numbers'
      end

      r = [1e-6, [1, per_action_risk].min].max
      n = [0, target_actions].max
      b_max = n.to_f * r * kappa
      bound = b_max / kappa
      { 'kappa' => kappa, 'bMax' => b_max, 'autonomousBound' => bound,
        'rationale' => "Σr ≤ bMax/κ = #{fixed3(bound)} ≥ #{Predicates.js_number_string(n)}×#{fixed3(r.to_f)} actions before a human co-sign" }
    end

    # The proven autonomous bound of a risk policy: bMax / kappa risk units (0 when kappa is not above 0).
    def autonomy_bound_of(p) = SafetyCertificate.safety_certificate_bound(p)
  end
end
