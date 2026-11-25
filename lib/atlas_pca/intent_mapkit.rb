# frozen_string_literal: true

require_relative 'intent_learner'
require_relative 'intent_omega'
require_relative 'detmath'
require_relative 'intent_v2'

# The Intent Map: a content-addressed, replayable artifact holding the outcome space, the learner parameters, every answer, the
# learned cells, the conservative grant and the quantified fidelity (all probabilities and metrics are integer ppm so the digest is
# language-portable). Native port of the TypeScript reference (@atlasauth/pca-intent, map.ts). Maps, omegas and learner options are
# plain String-keyed Hashes with the reference's field names. (IntentMap holds the committed-map builder.)
module AtlasPca
  module IntentMapkit
    INTENT_MAP_DOMAIN = 'atlas-pca/intent-map/v1'
    PPM = 1_000_000
    L = IntentLearner

    module_function

    # JS Math.round: the nearest integer, ties toward +infinity.
    def js_round(x)
      return x unless x.finite? # Math.round leaves NaN and the infinities as they are

      f = x.floor
      x - f >= 0.5 ? f + 1 : f
    end

    def ppm(x) = js_round(x * PPM)
    def qz(x) = js_round(x * PPM) / PPM.to_f
    def num?(x) = IntentOmega.number?(x)

    def omega_to_json(o)
      ws = o['verbs'].map { |v| v['weight'] }
      equal = ws.all? { |w| (w - ws[0]).abs < 1e-15 }
      verbs = o['verbs'].map do |v|
        dims = v['dims'].map do |d|
          if d['kind'] == 'num'
            nd = { 'kind' => 'num', 'path' => d['path'], 'lo' => d['lo'], 'hi' => d['hi'], 'cuts' => d['cuts'].dup }
            nd['dist'] = d['dist'] if d.key?('dist')
            nd
          else
            { 'kind' => 'cat', 'path' => d['path'], 'values' => d['values'].map(&:dup) }
          end
        end
        { 'verb' => v['verb'], 'reversibility' => v['reversibility'], 'w' => equal ? 1 : [1, js_round(v['weight'] * PPM)].max, 'dims' => dims }
      end
      { 'verbs' => verbs, 'approximate' => o['approximate'].dup }
    end

    def omega_from_json(j)
      tot = j['verbs'].sum { |v| v['w'] }
      verbs = j['verbs'].map do |v|
        dims = v['dims'].map do |d|
          if d['kind'] == 'num'
            { 'kind' => 'num', 'path' => d['path'], 'lo' => d['lo'], 'hi' => d['hi'], 'cuts' => L.opt(d, 'cuts', []).dup, 'dist' => L.opt(d, 'dist', 'uniform') }
          else
            { 'kind' => 'cat', 'path' => d['path'], 'values' => L.opt(d, 'values', []).map(&:dup) }
          end
        end
        { 'verb' => v['verb'], 'reversibility' => v['reversibility'], 'weight' => v['w'] / tot.to_f, 'dims' => dims }
      end
      { 'v' => 1, 'approximate' => j['approximate'].dup, 'verbs' => verbs }
    end

    def grant_digest(g)
      inner = {}
      inner['predicates'] = g['predicates'] unless g['predicates'].nil?
      inner['caveats'] = g.key?('caveats') ? g['caveats'] : []
      AtlasPca.hash_canonical({ 'd' => 'atlas-pca/intent-grant/v1', 'g' => inner })
    end

    # Content address of an Intent Map (the core definition, so the server and relying parties agree).
    def intent_map_digest(m) = AtlasPca.hash_canonical({ 'd' => INTENT_MAP_DOMAIN, 'm' => m })

    def metrics_of(l)
      m = l.metrics
      rmax = 0.0
      l.cells.each { |c| rmax += c['mass'] * (1 - c['p']) * c['harm'] }
      {
        'residual_risk_ppm' => ppm(m['residualRisk']),
        'burden_ppm' => ppm(m['burden']),
        'uncertainty_ppm' => ppm(m['uncertainty']),
        'disagreement_ppm' => ppm(m['disagreementMass']),
        'mean_harm_ppm' => ppm(m['meanHarm']),
        'fidelity_est_ppm' => ppm(rmax > 0 ? 1 - (m['residualRisk'] / rmax) : 1),
        'entropy_mbits' => js_round(m['entropyBits'] * 1000),
        'log2_vs_mbits' => m['log2VersionSpace'].nil? ? nil : js_round(m['log2VersionSpace'] * 1000),
        'questions' => m['questions'],
        'conflicts' => m['conflicts']
      }
    end

    def safe_integer?(x) = num?(x) && (x.is_a?(Integer) || x.finite?) && x == x.floor && x.abs <= 9_007_199_254_740_991

    # The learner's priorMix function for a data-form population prior (ppm-quantised like every map number).
    def prior_mix_of(pm)
      by_verb = {}
      pm['cells'].each do |c|
        q = qz(c['q'])
        raise ArgumentError, 'pca-intent: priorMix cells need q in [0, 1] and a cell index >= 0' if !(q >= 0 && q <= 1) || !safe_integer?(c['cell']) || c['cell'] < 0

        (by_verb[c['verb']] ||= []) << { 'cell' => c['cell'], 'lq' => AtlasPca::DetMath.det_ln(q), 'lnq' => AtlasPca::DetMath.det_ln(1 - q) }
      end
      weight = lambda do |vs, contains|
        lw = 0.0
        (by_verb[vs['verb']] || []).each { |t| lw += contains.call(t['cell']) ? t['lq'] : t['lnq'] }
        AtlasPca::DetMath.det_exp(lw)
      end
      { 'beta' => qz(pm['beta']), 'weight' => weight }
    end

    def anchor_opt(a)
      { 'policy' => { 'predicates' => a['policy']['predicates'], 'caveats' => L.opt(a['policy'], 'caveats', []) }, 'lambda' => js_round(a['lambda'] * 1000) / 1000.0 }
    end

    def anchor_json(a)
      { 'policy' => { 'predicates' => a['policy']['predicates'], 'caveats' => L.opt(a['policy'], 'caveats', []) }, 'lambda_milli' => js_round(a['lambda'] * 1000) }
    end

    def quantize_class(h)
      return { 'kind' => 'box' } if !L.truthy(h) || h['kind'] == 'box'

      decay = qz(L.opt(h, 'decay', 0.25))
      return { 'kind' => 'union', 'k' => h['k'], 'decay' => decay } if h['kind'] == 'union'

      { 'kind' => 'decision-list', 'maxRules' => h['maxRules'], 'decay' => decay, 'conditions' => L.opt(h, 'conditions', 'box') }
    end

    def null_mass_of(o, verb)
      nm = o['nullMass']
      return nm if num?(nm)

      own = nm.is_a?(Hash) ? nm[verb] : nil # own entries only: a verb named like an Object member is an ordinary key
      return own unless own.nil?

      L.opt(o, 'defaultNullMass', 0.2)
    end

    # Build a learner whose parameters are exactly representable in an Intent Map (ppm-quantised).
    def create_learner(omega, o = nil)
      o = {} if o.nil?
      eta0 = L.opt(o, 'eta', 0)
      opts = {
        'eta' => qz(eta0),
        'tau' => qz(L.opt(o, 'tau', eta0 == 0 ? 1 : 0.95)),
        'strategy' => L.opt(o, 'strategy', 'disagreement'),
        'nullMass' => ->(vs) { qz(null_mass_of(o, vs['verb'])) },
        'hypothesisClass' => quantize_class(o['hypothesisClass'])
      }
      opts['agnosticSlack'] = o['agnosticSlack'] if o.key?('agnosticSlack')
      opts['anchor'] = anchor_opt(o['anchor']) if L.truthy(o['anchor'])
      opts['anchors'] = o['anchors'].map { |a| anchor_opt(a) } if L.truthy(o['anchors'])
      opts['monotone'] = { 'paths' => o['monotone']['paths'].dup, 'offMass' => qz(L.opt(o['monotone'], 'offMass', 0)) } if L.truthy(o['monotone'])
      opts['etaPos'] = qz(o['etaPos']) if o.key?('etaPos')
      opts['etaNeg'] = qz(o['etaNeg']) if o.key?('etaNeg')
      opts['priorMix'] = prior_mix_of(o['priorMix']) if L.truthy(o['priorMix'])
      l = L::IntentLearner.new(omega, opts)
      l.map_params = o
      l
    end

    # The serialisable parameters a learner was built with (create_learner only).
    def learner_options_of(l)
      o = l.map_params
      raise ArgumentError, 'pca-intent: build the learner with createLearner() so its parameters are serialisable' if o.nil?

      o
    end

    def emit_intent_map(l, intent_ref_value = nil)
      o = learner_options_of(l)
      null_mass_ppm = l.omega['verbs'].to_h { |vs| [vs['verb'], ppm(null_mass_of(o, vs['verb']))] }
      grant = l.synthesize
      hc = l.hypothesis_class
      learner = { 'hypothesis_class' => L.hypothesis_class_name(hc) }
      learner['class_params'] = { 'k' => hc['k'], 'decay_ppm' => ppm(L.opt(hc, 'decay', 0.25)) } if hc['kind'] == 'union'
      learner['class_params'] = { 'max_rules' => hc['maxRules'], 'decay_ppm' => ppm(L.opt(hc, 'decay', 0.25)) } if hc['kind'] == 'decision-list'
      learner['agnostic_slack'] = l.agnostic_slack unless l.agnostic_slack.nil?
      learner['eta_ppm'] = ppm(l.eta)
      learner['tau_ppm'] = ppm(l.tau)
      learner['strategy'] = l.strategy
      learner['null_mass_ppm'] = null_mass_ppm
      learner['anchor'] = anchor_json(o['anchor']) if L.truthy(o['anchor'])
      learner['anchors'] = o['anchors'].map { |a| anchor_json(a) } if L.truthy(o['anchors'])
      learner['monotone'] = { 'paths' => o['monotone']['paths'].dup, 'off_ppm' => ppm(L.opt(o['monotone'], 'offMass', 0)) } if L.truthy(o['monotone'])
      learner['noise'] = { 'eta_pos_ppm' => ppm(l.eta_pos), 'eta_neg_ppm' => ppm(l.eta_neg) } if o.key?('etaPos') || o.key?('etaNeg')
      if L.truthy(o['priorMix'])
        pm = o['priorMix']
        learner['prior_mix'] = { 'beta_ppm' => ppm(pm['beta']), 'cells' => pm['cells'].map { |c| { 'verb' => c['verb'], 'cell' => c['cell'], 'q_ppm' => ppm(c['q']) } } }
      end
      observations = l.observations.map do |x|
        ob = { 'verb' => x['verb'], 'values' => x['values'].dup, 'y' => x['y'], 'source' => x['source'] }
        ob['region'] = x['region'] unless x['region'].nil?
        ob
      end
      {
        'v' => 1,
        'kind' => 'pca-intent-map',
        'intent_ref' => intent_ref_value,
        'principals' => L.truthy(intent_ref_value) ? [intent_ref_value] : [],
        'omega' => omega_to_json(l.omega),
        'learner' => learner,
        'observations' => observations,
        'cells' => l.cells.map { |c| { 'verb' => c['verb'], 'cell' => c['cell'], 'p_ppm' => ppm(c['p']), 'in_grant' => c['inGrant'] } },
        'grant' => grant,
        'grant_digest' => grant_digest(grant),
        'metrics' => metrics_of(l)
      }
    end

    # The learner parameters a map records (inverse of what emit_intent_map writes).
    def map_learner_options(m)
      lr = m['learner']
      null_mass = lr['null_mass_ppm'].transform_values { |v| v / PPM.to_f }
      cp = lr['class_params']
      hcn = lr['hypothesis_class']
      hc = case hcn
           when 'per-verb-union/v1'
             { 'kind' => 'union', 'k' => L.opt(cp, 'k', 2), 'decay' => L.opt(cp, 'decay_ppm', 250_000) / PPM.to_f }
           when 'per-verb-decision-list/v1', 'per-verb-decision-list/v2'
             { 'kind' => 'decision-list', 'maxRules' => L.opt(cp, 'max_rules', 2), 'decay' => L.opt(cp, 'decay_ppm', 250_000) / PPM.to_f,
               'conditions' => hcn == 'per-verb-decision-list/v1' ? 'atomic' : 'box' }
           else { 'kind' => 'box' }
           end
      out = { 'eta' => lr['eta_ppm'] / PPM.to_f, 'tau' => lr['tau_ppm'] / PPM.to_f, 'strategy' => lr['strategy'], 'nullMass' => null_mass, 'hypothesisClass' => hc }
      out['agnosticSlack'] = lr['agnostic_slack'] unless lr['agnostic_slack'].nil?
      out['anchor'] = { 'policy' => lr['anchor']['policy'], 'lambda' => lr['anchor']['lambda_milli'] / 1000.0 } if L.truthy(lr['anchor'])
      out['anchors'] = lr['anchors'].map { |a| { 'policy' => a['policy'], 'lambda' => a['lambda_milli'] / 1000.0 } } if L.truthy(lr['anchors'])
      out['monotone'] = { 'paths' => lr['monotone']['paths'].dup, 'offMass' => lr['monotone']['off_ppm'] / PPM.to_f } if L.truthy(lr['monotone'])
      if L.truthy(lr['noise'])
        out['etaPos'] = lr['noise']['eta_pos_ppm'] / PPM.to_f
        out['etaNeg'] = lr['noise']['eta_neg_ppm'] / PPM.to_f
      end
      if L.truthy(lr['prior_mix'])
        pm = lr['prior_mix']
        out['priorMix'] = { 'beta' => pm['beta_ppm'] / PPM.to_f, 'cells' => pm['cells'].map { |c| { 'verb' => c['verb'], 'cell' => c['cell'], 'q' => c['q_ppm'] / PPM.to_f } } }
      end
      out
    end

    # Rebuild the learner a map describes (omega + prior + observations).
    def learner_from_map(m)
      l = create_learner(omega_from_json(m['omega']), map_learner_options(m))
      m['observations'].each { |o| l.observe({ 'verb' => o['verb'], 'values' => o['values'] }, o['y'], o['source'], o['region']) }
      l
    end

    # NOT within 2 ppm, written as the negation of the positive condition: a missing, non-numeric or NaN side is never close.
    def far2?(a, b) = !(num?(a) && num?(b) && (a - b).abs <= 2)

    # Replay a single-principal map and check every number, every cell and the grant.
    def verify_intent_map(m)
      problems = []
      begin
        return { 'ok' => false, 'problems' => ['not an intent map v1'] } unless m.is_a?(Hash) && num?(m['v']) && m['v'] == 1 && m['kind'] == 'pca-intent-map'
        return { 'ok' => false, 'problems' => ['combined map: verify each principal map and recombine with verifyAggregate'] } if m['principals'].length > 1 || !m['aggregation'].nil?

        r = emit_intent_map(learner_from_map(m), m['intent_ref'])
        problems << 'grant does not match the replayed posterior' if r['grant_digest'] != m['grant_digest'] || grant_digest(m['grant']) != m['grant_digest']
        if r['cells'].length != m['cells'].length
          problems << 'cell count differs'
        else
          r['cells'].each_with_index do |c, i|
            x = m['cells'][i]
            problems << "cell #{i} differs" if c['verb'] != x['verb'] || c['in_grant'] != x['in_grant'] || far2?(c['p_ppm'], x['p_ppm'])
          end
        end
        r['metrics'].each do |k, a|
          b = m['metrics'].is_a?(Hash) && m['metrics'].key?(k) ? m['metrics'][k] : V2JS::UNDEF
          bad = a.nil? || b.nil? ? !a.equal?(b) : far2?(a, b)
          problems << "metric #{k} differs (#{V2JS.js_str(b)} claimed, #{V2JS.js_str(a)} replayed)" if bad
        end
      rescue StandardError => e
        problems << "replay failed: #{e.message}"
      end
      { 'ok' => problems.empty?, 'problems' => problems }
    end

    # A runtime divergence is one more labelled observation; a NEGATIVE one also vetoes the outcome's cell for good.
    def apply_divergence(l, outcome, y)
      before = l.cells.count { |c| c['inGrant'] }
      l.observe(outcome, y, 'runtime')
      { 'before' => before, 'after' => l.cells.count { |c| c['inGrant'] }, 'grant' => l.synthesize }
    end
  end
end
