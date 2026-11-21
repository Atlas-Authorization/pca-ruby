# frozen_string_literal: true

require_relative 'intent_omega'
require_relative 'intent_learner'
require_relative 'intent_policy'
require_relative 'intent_render'
require_relative 'intent_v2'

# Runtime intent conformance: routing an admitted action by the map's posterior and the verb's reversibility, the judge panel input,
# the intent-conformance attestation (IC-Att) and just-in-time consent. Native port of the TypeScript reference
# (@atlasauth/pca-intent). A "learner" is any object with #omega, #harm, #acceptance(o), #admits_outcome(o) and #vetoed?(o); the
# signed-verdict threshold check is injected (the core has no semantic-threshold verifier).
module AtlasPca
  module IntentRuntime
    IC_ATT_DOMAIN = 'atlas-pca/intent-ic-att/v1'
    DEFAULT_BOND_POLICY = { 'floor' => 1, 'k' => 1, 'maxOpenClaims' => 100, 'maxOpenAmount' => Float::INFINITY }.freeze
    MICROS = 1_000_000
    MAX_SAFE_MICROS = 1e15

    module_function

    def quantize_up(x)
      return x if !x.finite? || x <= 0

      scaled = x * MICROS
      return x if scaled > MAX_SAFE_MICROS

      r = (scaled + 0.5).floor
      m = r.to_f / MICROS == x || (scaled - r).abs <= 1e-3 ? r : scaled.ceil
      m.to_f / MICROS
    end

    def curve_component(curve, k, e)
      kind = curve.is_a?(Hash) ? curve['kind'] : nil
      return k * e if !IntentLearner.truthy(curve) || kind == 'linear'

      if kind == 'power'
        gm = curve['gamma']
        raise ArgumentError, 'bondAmount: power curve requires finite gamma >= 1' unless IntentOmega.finite_number?(gm) && gm >= 1

        return k * (e.to_f**gm)
      end
      tiers = curve['tiers']
      raise ArgumentError, 'bondAmount: piecewise curve requires at least one tier' if !tiers.is_a?(Array) || tiers.empty?

      acc = 0.0
      prev_up = 0
      prev_marginal = 0
      tiers.each do |t|
        up = t['upTo']
        mk = t['marginalK']
        raise ArgumentError, 'bondAmount: piecewise tier `upTo` must be strictly increasing' if !(IntentOmega.finite_number?(up) && up > prev_up) && up != Float::INFINITY
        raise ArgumentError, 'bondAmount: piecewise `marginalK` must be a finite number >= 0' unless IntentOmega.finite_number?(mk) && mk >= 0
        raise ArgumentError, 'bondAmount: piecewise marginal rates must be non-decreasing (convex)' if mk < prev_marginal

        width = [e, up].min - prev_up
        acc += width * mk if width.positive?
        prev_up = up
        prev_marginal = mk
        break if e <= up
      end
      acc += (e - prev_up) * prev_marginal if e > prev_up
      k * acc
    end

    # max(floor, curve(k, exposure)) snapped up onto the micro grid; a non-finite or non-positive exposure gives the floor.
    def bond_amount(policy, exposure)
      e = IntentOmega.finite_number?(exposure) && exposure > 0 ? exposure : 0
      quantize_up(IntentOmega.js_max(policy['floor'], curve_component(policy['curve'], policy['k'], e)))
    end

    def vs_of(l, verb) = l.omega['verbs'].find { |v| v['verb'] == verb }

    # deny / allow / optimistic / jit-consent for an action the grant already admits.
    def route_action(l, o, opts = nil)
      opts ||= {}
      vs = vs_of(l, o['verb'])
      if vs.nil? || IntentOmega.cell_of(vs, o).nil?
        return { 'route' => 'deny', 'p' => 0, 'inGrant' => false, 'vetoed' => false, 'reversibility' => vs ? vs['reversibility'] : 'unknown',
                 'harm' => 0, 'risk' => 1, 'judges' => false, 'reason' => "outside the Intent Map's outcome space" }
      end
      p = l.acceptance(o)
      in_grant = l.admits_outcome(o)
      vetoed = l.vetoed?(o)
      harm = IntentOmega.harm_of(vs, o, l.harm)
      h_max = opts['hMax']
      h_max = IntentOmega.harm_max(l.omega, l.harm) if h_max.nil?
      risk = [1, [0, ((1 - p) * harm) / (h_max > 0 ? h_max : 1)].max].min
      theta2 = opts['theta2']
      theta2 = 0.5 if theta2.nil?
      base = { 'p' => p, 'inGrant' => in_grant, 'vetoed' => vetoed, 'reversibility' => vs['reversibility'], 'harm' => harm, 'risk' => risk }
      unless in_grant
        return base.merge('route' => 'deny', 'judges' => false,
                          'reason' => vetoed ? 'the cell was vetoed by a runtime divergence' : 'outside the conservative grant (p_n < τ)')
      end

      judges = vs['reversibility'] == 'irreversible' || p < 1 - 1e-12 || risk >= theta2
      return base.merge('route' => 'jit-consent', 'judges' => judges, 'reason' => 'irreversible: just-in-time consent on the rendered action') if vs['reversibility'] == 'irreversible'

      if judges
        return base.merge('route' => 'optimistic', 'judges' => judges, 'bond' => bond_amount(opts['bondPolicy'] || DEFAULT_BOND_POLICY, harm),
                          'reason' => p < 1 - 1e-12 ? 'unconfirmed region (p_n < 1): bonded claim + judges' : 'risk ≥ θ2: bonded claim + judges')
      end
      base.merge('route' => 'allow', 'judges' => false, 'reason' => 'confirmed region, reversible, low risk')
    end

    # ---- L3: the judge panel input and the IC-Att ------------------------------------------------------------------

    def pcactn_action_of(vs, o)
      a = IntentPolicy.outcome_to_action(vs, o)
      { 'verb' => a['verb'], 'resource' => a['resource'], 'params_digest' => AtlasPca.params_digest(IntentLearner.truthy(a['params']) ? a['params'] : {}),
        'reversibility_class' => vs['reversibility'] }
    end

    def action_digest(action) = AtlasPca.hash_canonical(action)

    def judge_input_of(l, o, ctx)
      vs = vs_of(l, o['verb'])
      raise ArgumentError, "judgeInputOf: no verb #{o['verb']} in Ω" if vs.nil?

      ctx.merge('renderedAction' => IntentRender.render_action(vs, o['values']), 'p' => l.acceptance(o), 'reversibility' => vs['reversibility'],
                'actionDigest' => action_digest(pcactn_action_of(vs, o)))
    end

    def calibration_digest(c)
      AtlasPca.hash_canonical({ 'd' => 'atlas-pca/intent-calibration/v1', 'alpha' => c['alpha'],
                                'samples' => c['samples'].map { |s| { 'score' => s['score'], 'faithful' => s['faithful'] } } })
    end

    def to_ppm(x) = IntentOmega.finite_number?(x) ? ((x * 1_000_000) + 0.5).floor : nil

    # Verify a panel's verdicts for one action with the injected threshold verifier and produce the IC-Att. The verifier takes
    # (verdicts, {judgeKeys, k, goalCommitment, actionDigest, calibration?, attestation?}) and returns
    # {ok, agreeCount, aggregateScore, cutoff?, reason?}.
    def intent_conformance_attestation(input, verdicts, opts, verify, verdict_digest = AtlasPca.method(:hash_canonical))
      vo = { 'judgeKeys' => opts['judgeKeys'], 'k' => opts['k'], 'goalCommitment' => input['goalCommitment'], 'actionDigest' => input['actionDigest'] }
      vo['calibration'] = opts['calibration'] if IntentLearner.truthy(opts['calibration'])
      vo['attestation'] = opts['attestation'] if IntentLearner.truthy(opts['attestation'])
      r = verify.call(verdicts, vo)
      att = { 'v' => 1, 'kind' => 'pca-ic-att', 'intent_ref' => input['intentRef'], 'map_digest' => input['mapDigest'],
              'action_digest' => input['actionDigest'], 'goal_commitment' => input['goalCommitment'],
              'verdict_digests' => verdicts.map { |v| verdict_digest.call(v) }.sort,
              'calibration_digest' => IntentLearner.truthy(opts['calibration']) ? calibration_digest(opts['calibration']) : nil,
              'k' => opts['k'], 'ok' => r['ok'], 'agree_count' => r['agreeCount'],
              'aggregate_score_ppm' => to_ppm(r['aggregateScore']) || 0,
              'cutoff_ppm' => r['cutoff'].nil? ? nil : to_ppm(r['cutoff']) }
      att['reason'] = r['reason'] if IntentLearner.truthy(r['reason'])
      att
    end

    def ic_att_digest(a) = AtlasPca.hash_canonical({ 'd' => IC_ATT_DOMAIN, 'a' => a })

    # Re-verify an IC-Att from the verdicts it names (a relying party never trusts the ok bit).
    def verify_ic_att(att, input, verdicts, opts, verify)
      again = intent_conformance_attestation(input, verdicts, opts, verify)
      problems = []
      problems << 'IC-Att does not match the recomputation from its verdicts' if ic_att_digest(again) != ic_att_digest(att)
      problems << "panel does not pass: #{IntentLearner.truthy(again['reason']) ? again['reason'] : 'unknown'}" unless again['ok']
      { 'ok' => problems.empty?, 'problems' => problems }
    end

    def semantic_risk_contribution(score)
      return 1 unless IntentOmega.finite_number?(score)

      r = 1 - score
      r.negative? ? 0 : (r > 1 ? 1 : r)
    end

    # The monotone risk fold: r := max(r, 1 - aggregateScore). Never lowers r.
    def fold_semantic_risk(r, att)
      ppm = att.key?('aggregate_score_ppm') ? att['aggregate_score_ppm'] : V2JS::UNDEF
      score = IntentOmega.number?(ppm) ? ppm / 1_000_000.0 : Float::NAN
      IntentOmega.js_max(r, semantic_risk_contribution(score))
    end

    # ---- L4: just-in-time consent ----------------------------------------------------------------------------------

    def jit_consent_request(l, o, ctx)
      vs = vs_of(l, o['verb'])
      raise ArgumentError, "jitConsentRequest: no verb #{o['verb']} in Ω" if vs.nil?

      p = l.acceptance(o)
      { 'v' => 1, 'kind' => 'pca-intent-jit', 'intent_ref' => ctx['intentRef'], 'map_digest' => ctx['mapDigest'], 'verb' => o['verb'],
        'values' => o['values'].dup, 'reversibility' => vs['reversibility'], 'p_ppm' => ((p * 1_000_000) + 0.5).floor,
        'text' => "#{IntentRender.render_action(vs, o['values'])} This cannot be undone. Approve?" }
    end

    def jit_consent_digest(r) = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/intent-jit/v1', 'r' => r })

    # Record the principal's JIT decision as a runtime observation: approve -> y = 1 (widens the grant only through the posterior),
    # deny -> y = 0 and the cell is vetoed.
    def record_jit_decision(l, req, decision)
      require_relative 'intent_mapkit'
      IntentMapkit.apply_divergence(l, { 'verb' => req['verb'], 'values' => req['values'] }, decision == 'approve' ? 1 : 0)
    end
  end
end
