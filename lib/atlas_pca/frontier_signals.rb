# frozen_string_literal: true

module AtlasPca
  # Typing of the intent-frontier results as 'ok' | 'escalate' | 'deny' (a signal can only LOWER a decision; 'ok' is neutral) and the
  # risk-input tightening that lets the objective path only RAISE risk. Total functions: anything that is not a result is 'deny'.
  # Results and inputs are Hashes with the reference's member names (String keys).
  module FrontierSignals
    PROGRESS_ESCALATE = %w[exploration-exhausted budget-exceeded].freeze

    module_function

    def bool?(v) = v == true || v == false

    # 'ok' / 'escalate' for a result whose 'ok' is a real boolean, else 'deny'.
    def semantic_signal(result)
      return 'deny' unless result.is_a?(Hash) && bool?(result['ok'])

      result['ok'] ? 'ok' : 'escalate'
    end

    # 'ok' iff the step verified; running out of exploration budget escalates; every other denial denies.
    def progress_signal(result)
      return 'deny' unless result.is_a?(Hash) && bool?(result['ok'])
      return 'ok' if result['ok']

      result['reason'].is_a?(String) && PROGRESS_ESCALATE.include?(result['reason']) ? 'escalate' : 'deny'
    end

    # Nothing committed ('none') or a reproduced result ('objective') is neutral; a mismatch is neutral only under onMismatch: heuristic.
    def objective_signal(res)
      return 'deny' unless res.is_a?(Hash)

      case res['mode']
      when 'none', 'objective' then 'ok'
      when 'mismatch' then res['onMismatch'] == 'heuristic' ? 'ok' : 'deny'
      else 'deny'
      end
    end

    def fin?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite?)

    # o.k of the reference: a null object throws, a non-object has no such member.
    def read(o, k)
      raise TypeError, "Cannot read properties of null (reading '#{k}')" if o.nil?

      o.is_a?(Hash) ? o[k] : nil
    end

    def neg_zero?(x) = x.is_a?(Float) && x.zero? && (1.0 / x).negative?

    # Math.min / Math.max order signed zeros: min(0, -0) is -0 and max(-0, 0) is 0.
    def ieee_min(a, b) = a.zero? && b.zero? ? (neg_zero?(a) || neg_zero?(b) ? -0.0 : 0) : [a, b].min
    def ieee_max(a, b) = a.zero? && b.zero? ? (neg_zero?(a) && neg_zero?(b) ? -0.0 : 0) : [a, b].max

    # Reversibility is the lower of the two, blast radius the higher, and a non-finite value on either side makes both the worst case
    # (0 and 1); the semantic distance is the objective's when finite, else 1. A null baseline or objective raises.
    def tighten_risk_inputs(baseline, objective)
      br = read(baseline, 'reversibility')
      bb = read(baseline, 'blastRadius')
      orv = read(objective, 'reversibility')
      ob = read(objective, 'blastRadius')
      ok = fin?(br) && fin?(orv) && fin?(bb) && fin?(ob)
      sd = read(objective, 'semanticDistance')
      { 'reversibility' => ok ? ieee_min(br, orv) : 0, 'blastRadius' => ok ? ieee_max(bb, ob) : 1, 'semanticDistance' => fin?(sd) ? sd : 1 }
    end
  end
end
