# frozen_string_literal: true

require_relative 'intent_learner'
require_relative 'intent_mapkit'
require_relative 'intent_omega'
require_relative 'intent_region'

# Cut refinement and partial answers: a "partly" answer inserts the stated cuts / values (or adds a whole dimension) to the outcome
# space, re-enumerates the hypotheses and replays every earlier observation as a value-space region. Native port of the TypeScript
# reference (@atlasauth/pca-intent, refine.ts). Refinements, partial answers and questions are plain Hashes.
module AtlasPca
  module IntentRefine
    module_function

    def u16key(s) = IntentOmega.u16key(s)
    def deep(v) = Marshal.load(Marshal.dump(v))

    def integer?(x) = IntentOmega.number?(x) && (x.is_a?(Integer) || (x.finite? && x == x.floor))

    def sorted_cat(values)
      ex = values.select { |v| v['kind'] == 'exact' }.map { |v| v['value'] }.uniq.sort_by { |s| u16key(s) }
      pre = values.select { |v| v['kind'] == 'prefix' }.map { |v| v['value'] }.uniq.sort_by { |s| u16key(s) }
      ex.map { |v| { 'kind' => 'exact', 'value' => v } } + pre.map { |v| { 'kind' => 'prefix', 'value' => v } } + [{ 'kind' => 'other', 'value' => IntentOmega::OTHER }]
    end

    # Omega with one verb's dimension refined (a deep copy; other verbs and the weights are unchanged).
    def refine_omega(omega, r)
      out = deep(omega)
      vs = out['verbs'].find { |v| v['verb'] == r['verb'] }
      raise ArgumentError, "refineOmega: no verb #{r['verb']} in Ω" if vs.nil?

      i = vs['dims'].index { |d| d['path'] == r['path'] } || -1
      if IntentLearner.truthy(r['newDim'])
        raise ArgumentError, "refineOmega: #{r['path']} is already a dimension of #{r['verb']}" if i >= 0
        raise ArgumentError, 'refineOmega: newDim.path must equal path' if r['newDim']['path'] != r['path']

        d = deep(r['newDim'])
        if d['kind'] == 'cat'
          d['values'] = sorted_cat(d['values'])
        else
          d['cuts'] = d['cuts'].uniq.select { |c| c >= d['lo'] && c <= d['hi'] }.sort
        end
        vs['dims'] << d
        vs['dims'] = vs['dims'].sort_by { |x| u16key(x['path']) }
        return out
      end
      raise ArgumentError, "refineOmega: #{r['verb']} has no dimension #{r['path']} (pass newDim to add it)" if i.negative?

      d = vs['dims'][i]
      if d['kind'] == 'num'
        raise ArgumentError, "refineOmega: #{r['path']} is numeric" if IntentLearner.truthy(r['values']) || IntentLearner.truthy(r['prefixes'])

        cuts = (r['cuts'] || []).select { |c| integer?(c) }
        d['cuts'] = (d['cuts'] + cuts).uniq.select { |c| c >= d['lo'] && c <= d['hi'] }.sort
      else
        raise ArgumentError, "refineOmega: #{r['path']} is categorical" if IntentLearner.truthy(r['cuts'])

        d['values'] = sorted_cat(d['values'] + (r['values'] || []).map { |v| { 'kind' => 'exact', 'value' => v } } +
                                 (r['prefixes'] || []).map { |v| { 'kind' => 'prefix', 'value' => v } })
        raise ArgumentError, "refineOmega: #{r['path']} would have more than 20 values" if d['values'].length > 20
      end
      out
    end

    # The value-space region an observation was about, in the omega it was recorded in.
    def region_of_observation(omega, o)
      return o['region'] if IntentLearner.truthy(o['region'])

      vs = omega['verbs'].find { |v| v['verb'] == o['verb'] }
      raise ArgumentError, "regionOfObservation: no verb #{o['verb']}" if vs.nil?

      IntentRegion.region_of_cell(vs, o['cell'])
    end

    # Rebuild a learner over a refined omega and replay every observation as a region (rescope may rewrite a region).
    def refine_learner(l, r, rescope = nil)
      omega = refine_omega(l.omega, r)
      nxt = IntentMapkit.create_learner(omega, IntentMapkit.learner_options_of(l))
      l.observations.each do |o|
        region = region_of_observation(l.omega, o)
        region = rescope.call(o, region) unless rescope.nil?
        vs = omega['verbs'].find { |v| v['verb'] == o['verb'] }
        values = o['values'].dup
        vs['dims'].each { |d| values[d['path']] = IntentOmega.rep_value(d, 0) unless values.key?(d['path']) }
        nxt.observe({ 'verb' => o['verb'], 'values' => values }, o['y'], o['source'], region)
      end
      nxt
    end

    def part_label(d, j, parts)
      x = IntentOmega.rep_value(d, j)
      parts.each do |p|
        if p.key?('lo')
          next if d['kind'] != 'num'

          c = IntentOmega.num_cells(d)[j]
          return p['y'] if c['lo'] >= p['lo'] && c['hi'] <= p['hi']
        elsif p.key?('values')
          return p['y'] if d['kind'] == 'cat' && d['values'][j]['kind'] == 'exact' && p['values'].include?(V2JS.js_str(x))
        elsif d['kind'] == 'cat' && d['values'][j]['kind'] != 'exact'
          return p['y']
        end
      end
      nil
    end

    # Sub-cells of dimension d (in the refined omega) that lie inside the questioned region's dimension.
    def sub_cells(d, region)
      n = d['kind'] == 'num' ? IntentOmega.num_cells(d).length : d['values'].length
      rd = region['dims'][d['path']]
      out = []
      n.times do |j|
        if !IntentLearner.truthy(rd)
          out << j
        elsif d['kind'] == 'num' && rd['kind'] == 'num'
          c = IntentOmega.num_cells(d)[j]
          out << j if c['lo'] >= rd['lo'] && c['hi'] <= rd['hi']
        elsif d['kind'] == 'cat' && rd['kind'] == 'cat'
          cell = IntentOmega.cat_cell_of({ 'kind' => 'cat', 'path' => d['path'], 'values' => rd['values'] }, IntentOmega.rep_value(d, j))
          out << j if rd['cells'].include?(cell)
        end
      end
      out
    end

    # Apply a partial answer to question q: a NEW learner over the refined omega and the observations the answer added.
    def answer_partial(l, q, a)
      old_vs = l.omega['verbs'].find { |v| v['verb'] == q['verb'] }
      raise ArgumentError, "answerPartial: no verb #{q['verb']}" if old_vs.nil?

      q_region = IntentRegion.region_of_cell(old_vs, q['cell'])
      r = { 'verb' => q['verb'], 'path' => a['path'] }
      %w[cuts values newDim].each { |k| r[k] = a[k] if IntentLearner.truthy(a[k]) }
      refined = refine_omega(l.omega, r)
      nvs = refined['verbs'].find { |v| v['verb'] == q['verb'] }
      d = nvs['dims'].find { |x| x['path'] == a['path'] }
      rescope = nil
      if IntentLearner.truthy(a['newDim'])
        n_d = d['kind'] == 'num' ? IntentOmega.num_cells(d).length : d['values'].length
        yes_cells = (0...n_d).select { |j| part_label(d, j, a['parts']) == 1 }
        rescope = lambda do |o, region|
          next region if o['verb'] != q['verb'] || o['y'] != 1
          next IntentRegion.restrict_region(region, d, { 'cells' => yes_cells }) if d['kind'] == 'cat'
          # numeric: restrict to the contiguous accepted span (the "typical" range the earlier yes was about)
          next IntentRegion.restrict_region(region, d, { 'lo' => d['hi'] + 1, 'hi' => d['hi'] + 1 }) if yes_cells.empty?

          cells = IntentOmega.num_cells(d)
          IntentRegion.restrict_region(region, d, { 'lo' => cells[yes_cells[0]]['lo'], 'hi' => cells[yes_cells[-1]]['hi'] })
        end
      end
      nxt = refine_learner(l, r, rescope)
      added = []
      sub_cells(d, q_region).each do |j|
        y = part_label(d, j, a['parts'])
        next if y.nil?

        region = if d['kind'] == 'num'
                   c = IntentOmega.num_cells(d)[j]
                   IntentRegion.restrict_region(q_region, d, { 'lo' => c['lo'], 'hi' => c['hi'] })
                 else
                   IntentRegion.restrict_region(q_region, d, { 'cells' => [j] })
                 end
        values = q['outcome']['values'].dup
        values[d['path']] = IntentOmega.rep_value(d, j)
        nvs['dims'].each { |x| values[x['path']] = IntentOmega.rep_value(x, 0) unless values.key?(x['path']) }
        ob = nxt.observe({ 'verb' => q['verb'], 'values' => values }, y, 'elicitation', region)
        added << ob if ob
      end
      { 'learner' => nxt, 'added' => added }
    end

    # Elicitation that accepts "yes", "no" and "partly": the stop rule and audit of `elicit`, a partial answer counts as one question
    # and swaps in the refined learner; after maxRefinements partial answers a further one is treated as "no".
    def elicit_adaptive(learner, answer, o)
      l = learner
      asked = []
      refinements = 0
      max_ref = o['maxRefinements']
      max_ref = 8 if max_ref.nil?
      apply = lambda do |q|
        a = answer.call(q, l)
        asked << q
        if a.is_a?(Hash) || a.nil?
          if refinements < max_ref
            l = answer_partial(l, q, a)['learner']
            refinements += 1
          else
            l.observe(q['outcome'], 0, 'elicitation')
          end
        else
          l.observe(q['outcome'], a, 'elicitation')
        end
      end
      seed_questions = 0
      (o['seed'] || []).each do |s|
        break unless asked.length < o['maxQuestions']

        vs = l.omega['verbs'].find { |v| v['verb'] == s['verb'] }
        next if vs.nil? || s['cell'].length != vs['dims'].length

        outcome = { 'verb' => s['verb'], 'values' => vs['dims'].each_with_index.to_h { |d, k| [d['path'], IntentOmega.rep_value(d, s['cell'][k])] } }
        p = l.acceptance(outcome)
        next if p <= 1e-9 || p >= 1 - 1e-9 || l.vetoed?(outcome)

        apply.call({ 'verb' => s['verb'], 'cell' => s['cell'].dup, 'outcome' => outcome, 'p' => p, 'score' => 0 })
        seed_questions += 1
      end
      stop = nil
      while stop.nil?
        m = l.metrics
        if m['residualRisk'] <= o['epsRisk'] && m['burden'] <= o['epsBurden']
          stop = 'converged'
        elsif !(asked.length < o['maxQuestions'])
          stop = 'budget'
        else
          q = l.next_question
          if q.nil?
            stop = 'no-disagreement'
          else
            apply.call(q)
          end
        end
      end
      audit_questions = 0
      if IntentLearner.truthy(o['audit'])
        loop do
          pending = l.unconfirmed_grant_cells
          total = 0.0
          pending.each { |x| total += x['weight'] }
          break if pending.empty? || total <= o['epsRisk']

          if !(asked.length < o['maxQuestions'])
            stop = 'budget'
            break
          end
          top = pending[0]
          vs = l.omega['verbs'].find { |v| v['verb'] == top['verb'] }
          outcome = IntentOmega.cell_rep(vs, top['cell'])
          apply.call({ 'verb' => top['verb'], 'cell' => top['cell'], 'outcome' => outcome, 'p' => l.acceptance(outcome), 'score' => top['weight'] })
          audit_questions += 1
        end
      end
      { 'stop' => stop, 'questions' => asked.length, 'auditQuestions' => audit_questions, 'seedQuestions' => seed_questions, 'asked' => asked,
        'learner' => l, 'refinements' => refinements }
    end
  end
end
