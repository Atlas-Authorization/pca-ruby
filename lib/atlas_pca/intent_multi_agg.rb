# frozen_string_literal: true

require_relative 'intent_learner'
require_relative 'intent_mapkit'
require_relative 'intent_multi'
require_relative 'intent_omega'
require_relative 'intent_region'

# Multi-principal aggregation over Intent Maps: the joint grant under a unanimity / quorum / weighted rule (every number
# recomputable from the inputs), lifting a map onto a common refinement, and cross-organisation aggregation. Native port of the
# TypeScript reference (@atlasauth/pca-intent, multi.ts; the rule and refinement primitives are in IntentMulti).
module AtlasPca
  module IntentMultiAgg
    ORDER = %w[reversible rate_limited irreversible].freeze
    PPM = IntentMapkit::PPM
    K = IntentMapkit

    module_function

    # JSON.stringify of a JSON value (key order kept; an integral double prints as an integer).
    def stringify(x) = Js.json(x)

    # Aggregate single-principal maps over a SHARED omega under a rule; the result has `aggregation` set.
    def aggregate_intent_maps(maps, rule, opts = nil)
      orgs = (opts || {})['orgs']
      raise ArgumentError, 'aggregateIntentMaps: no maps' if maps.empty?

      om = stringify(maps[0]['omega'])
      raise ArgumentError, 'aggregateIntentMaps: maps must share Ω (lift them with crossOrgAggregate)' if maps.any? { |m| stringify(m['omega']) != om }
      if maps.any? { |m| !m['aggregation'].nil? || m['principals'].length != 1 || !m['intent_ref'].is_a?(String) }
        raise ArgumentError, 'aggregateIntentMaps: every input must be a single-principal map with an intent_ref'
      end

      refs = maps.map { |m| m['intent_ref'] }
      raise ArgumentError, 'aggregateIntentMaps: duplicate principal' if refs.uniq.length != refs.length

      n = IntentMulti.normalize_rule(rule, refs)
      omega = K.omega_from_json(maps[0]['omega'])
      stats = []
      omega['verbs'].each do |vs|
        IntentOmega.verb_cell_count(vs).times { |c| stats << IntentOmega.cell_stats(vs, IntentOmega.decode_cell(vs, c), IntentOmega::DEFAULT_HARM) }
      end
      cells = maps[0]['cells'].each_with_index.map do |c, i|
        { 'verb' => c['verb'], 'cell' => c['cell'],
          'p_ppm' => K.ppm(IntentMulti.joint_acceptance(n, maps.map { |m| m['cells'][i]['p_ppm'] / PPM.to_f })),
          'in_grant' => IntentMulti.rule_admits(n, maps.map { |m| m['cells'][i]['in_grant'] }) }
      end
      predicates = []
      worst = -1
      off = 0
      omega['verbs'].each do |vs|
        nc = IntentOmega.verb_cell_count(vs)
        allowed = Array.new(nc, 0)
        any = false
        nc.times do |c|
          if cells[off + c]['in_grant']
            allowed[c] = 1
            any = true
          end
        end
        off += nc
        next unless any

        worst = [worst, ORDER.index(vs['reversibility']) || -1].max
        predicates.concat(IntentLearner.boxes_to_predicates(vs, allowed))
      end
      grant = { 'predicates' => predicates, 'caveats' => worst >= 0 ? [{ 'type' => 'reversibility_max', 'class' => ORDER[worst] }] : [] }
      # each principal's own posterior estimate of the JOINT grant
      per = maps.each_with_index.map do |m, i|
        r = b = rmax = 0.0
        m['cells'].each_with_index do |c, j|
          p = c['p_ppm'] / PPM.to_f
          mass = stats[j]['mass']
          harm = stats[j]['harm']
          rmax += mass * (1 - p) * harm
          if cells[j]['in_grant']
            r += mass * (1 - p) * harm
          else
            b += mass * p
          end
        end
        e = { 'intent_ref' => refs[i] }
        e['org'] = orgs[refs[i]] if orgs.is_a?(Hash) && IntentLearner.truthy(orgs[refs[i]])
        e['R'] = r
        e['B'] = b
        e['F'] = rmax > 0 ? 1 - (r / rmax) : 1
        e
      end
      worst_metric = ->(k, f) { maps.map { |m| m['metrics'][k].nil? ? 0 : m['metrics'][k] }.public_send(f) }
      kind = rule['kind']
      aggregation = { 'rule' => kind }
      aggregation['k'] = rule['k'] if kind == 'quorum'
      if kind == 'weighted'
        aggregation['weights'] = refs.each_with_index.to_h { |r, i| [r, n['weights'][i]] }
        aggregation['threshold'] = rule['threshold']
      end
      aggregation['vetoers'] = refs.each_with_index.select { |_r, i| n['veto'][i] }.map(&:first)
      aggregation['per_principal'] = per.map do |x|
        pp = { 'intent_ref' => x['intent_ref'] }
        pp['org'] = x['org'] if IntentLearner.truthy(x['org'])
        pp['residual_risk_ppm'] = K.ppm(x['R'])
        pp['burden_ppm'] = K.ppm(x['B'])
        pp
      end
      pps = aggregation['per_principal']
      {
        'v' => 1,
        'kind' => 'pca-intent-map',
        'intent_ref' => nil,
        'principals' => refs,
        'omega' => maps[0]['omega'],
        'learner' => maps[0]['learner'],
        'observations' => maps.flat_map { |m| m['observations'] },
        'cells' => cells,
        'grant' => grant,
        'grant_digest' => K.grant_digest(grant),
        'metrics' => {
          # every principal's own posterior estimate of the joint grant; the map reports the worst of them
          'residual_risk_ppm' => pps.map { |x| x['residual_risk_ppm'] }.max,
          'burden_ppm' => pps.map { |x| x['burden_ppm'] }.max,
          'uncertainty_ppm' => worst_metric.call('uncertainty_ppm', :max),
          'disagreement_ppm' => worst_metric.call('disagreement_ppm', :max),
          'mean_harm_ppm' => maps[0]['metrics']['mean_harm_ppm'],
          'fidelity_est_ppm' => K.ppm(per.map { |x| x['F'] }.min),
          'entropy_mbits' => worst_metric.call('entropy_mbits', :sum),
          'log2_vs_mbits' => maps.any? { |m| m['metrics']['log2_vs_mbits'].nil? } ? nil : worst_metric.call('log2_vs_mbits', :sum),
          'questions' => worst_metric.call('questions', :sum),
          'conflicts' => worst_metric.call('conflicts', :sum)
        },
        'aggregation' => aggregation
      }
    end

    # The unanimity rule: the joint grant is the intersection of the principals' conservative grants.
    def combine_intent_maps(maps, opts = nil) = aggregate_intent_maps(maps, { 'kind' => 'unanimity' }, opts)

    # The rule an aggregated map records.
    def rule_of(agg)
      a = agg['aggregation']
      raise ArgumentError, 'ruleOf: not an aggregated map' unless IntentLearner.truthy(a)

      case a['rule']
      when 'unanimity' then { 'kind' => 'unanimity', 'vetoers' => a['vetoers'] }
      when 'quorum' then { 'kind' => 'quorum', 'k' => a['k'], 'vetoers' => a['vetoers'] }
      else { 'kind' => 'weighted', 'weights' => a['weights'], 'threshold' => a['threshold'], 'vetoers' => a['vetoers'] }
      end
    end

    # Replay-verify every input map, then recompute the aggregate and compare digests (inputs share the omega).
    def verify_aggregate(agg, inputs, opts = nil)
      problems = []
      begin
        inputs.each_with_index do |m, i|
          r = K.verify_intent_map(m)
          problems << "input #{i}: #{r['problems'].join('; ')}" unless r['ok']
        end
        return { 'ok' => false, 'problems' => problems } unless problems.empty?

        again = aggregate_intent_maps(inputs, rule_of(agg), opts)
        problems << 'aggregate does not match its recomputation' if K.intent_map_digest(again) != K.intent_map_digest(agg)
      rescue StandardError => e
        problems << "recompute failed: #{e.message}"
      end
      { 'ok' => problems.empty?, 'problems' => problems }
    end

    # Re-express a single-principal map on a refinement of its omega: observations re-applied as value-space regions and prior mass 1
    # on the empty hypothesis for every verb the map did not cover.
    def lift_intent_map(m, target)
      raise ArgumentError, 'liftIntentMap: lift single-principal maps, then aggregate' if !m['aggregation'].nil? || m['principals'].length > 1

      src = K.omega_from_json(m['omega'])
      o = K.map_learner_options(m)
      known = src['verbs'].to_h { |v| [v['verb'], true] }
      src_mass = o['nullMass']
      null_mass = {}
      target['verbs'].each do |vs|
        if known.key?(vs['verb'])
          own = src_mass.is_a?(Hash) ? src_mass[vs['verb']] : nil
          null_mass[vs['verb']] = own.nil? ? 0.2 : own
        else
          null_mass[vs['verb']] = 1
        end
      end
      l = K.create_learner(target, o.merge('nullMass' => null_mass))
      m['observations'].each do |ob|
        svs = src['verbs'].find { |v| v['verb'] == ob['verb'] }
        tvs = target['verbs'].find { |v| v['verb'] == ob['verb'] }
        raise ArgumentError, "liftIntentMap: verb #{ob['verb']} missing from Ω" if svs.nil? || tvs.nil?

        values = ob['values'].dup
        tvs['dims'].each { |d| values[d['path']] = IntentOmega.rep_value(d, 0) unless values.key?(d['path']) }
        own_cell = IntentOmega.cell_of(svs, { 'verb' => ob['verb'], 'values' => ob['values'] })
        raise ArgumentError, "liftIntentMap: an observation of #{ob['verb']} lies outside the map's own Ω" if own_cell.nil?

        region = ob['region']
        region = IntentRegion.region_of_cell(svs, own_cell) if region.nil?
        l.observe({ 'verb' => ob['verb'], 'values' => values }, ob['y'], ob['source'], region)
      end
      K.emit_intent_map(l, m['intent_ref'])
    end

    # Replay-verify every map, lift all of them onto the common refinement of their omegas, then aggregate.
    def cross_org_aggregate(maps, rule, opts = nil)
      maps.each_with_index do |m, i|
        r = K.verify_intent_map(m)
        raise ArgumentError, "crossOrgAggregate: map #{i} does not verify: #{r['problems'].join('; ')}" unless r['ok']
      end
      omega = IntentMulti.common_refinement(maps.map { |m| K.omega_from_json(m['omega']) })
      lifted = maps.map { |m| lift_intent_map(m, omega) }
      { 'aggregate' => aggregate_intent_maps(lifted, rule, opts), 'lifted' => lifted, 'omega' => omega }
    end

    # Verify a cross-org aggregate by recomputing it from the ORIGINAL maps.
    def verify_cross_org_aggregate(agg, maps, opts = nil)
      again = cross_org_aggregate(maps, rule_of(agg), opts)['aggregate']
      return { 'ok' => true, 'problems' => [] } if K.intent_map_digest(again) == K.intent_map_digest(agg)

      { 'ok' => false, 'problems' => ['aggregate does not match its recomputation'] }
    rescue StandardError => e
      { 'ok' => false, 'problems' => [e.message] }
    end

    # The omega of an aggregated or single map as JSON (a comparison key).
    def omega_key(o) = stringify(K.omega_to_json(o))
  end
end
