# frozen_string_literal: true

require_relative 'intent_clopper'
require_relative 'intent_omega'

# Classifier error folded into the residual-risk estimate: the confusion calibration (exact Clopper-Pearson upper bounds per entry),
# the risk on explicit arrays, the label-sound bound, the classifier-aware residual risk of a learner and the gamma-max JIT gate.
# Native port of the TypeScript reference (@atlasauth/pca-intent). A "learner" exposes #omega and #cells ->
# [{verb, cell, p, mass, harm, inGrant}].
module AtlasPca
  module IntentClassifier
    module_function

    def utf8(s) = s.b

    # Calibrate a classifier on labelled examples. Labels outside the label set are refused.
    def calibrate_confusion(samples, labels, delta_gamma = 0.05)
      ls = labels.uniq.sort_by { |l| utf8(l) }
      raise ArgumentError, 'calibrateConfusion: empty label set' if ls.empty?
      raise ArgumentError, 'calibrateConfusion: delta must be in (0, 1)' unless delta_gamma > 0 && delta_gamma < 1

      ix = ls.each_with_index.to_h
      counts = ls.map { ls.map { 0 } }
      samples.each do |s|
        t = ix[s['truth']]
        p = ix[s['predicted']]
        raise ArgumentError, "calibrateConfusion: label outside L (#{s['truth']} / #{s['predicted']})" if t.nil? || p.nil?

        counts[t][p] += 1
      end
      alpha = delta_gamma / (ls.length * ls.length)
      gamma = []
      gamma_bar = []
      counts.each do |row|
        n = row.sum
        gamma << row.map { |c| n.positive? ? c.to_f / n : 0 }
        gamma_bar << row.map { |c| IntentClopper.clopper_pearson_upper(c, n, alpha) }
      end
      { 'labels' => ls, 'counts' => counts, 'gamma' => gamma, 'gammaBar' => gamma_bar, 'delta_ppm' => ((delta_gamma * 1_000_000) + 0.5).floor }
    end

    def confusion_digest(c)
      AtlasPca.hash_canonical({ 'd' => 'atlas-pca/intent-classifier-calibration/v1', 'labels' => c['labels'], 'counts' => c['counts'], 'delta_ppm' => c['delta_ppm'] })
    end

    # Max over true labels of the capped upper bound of any other label.
    def published_error_rate(c)
      worst = 0
      c['gammaBar'].each_with_index do |row, t|
        s = 0
        row.each_with_index { |g, p| s += g if p != t }
        e = [1, s].min
        worst = e if e > worst
      end
      worst
    end

    # JS toFixed(1): round half up on the exact value of the double (non-negative here).
    def to_fixed1(x)
      n = ((x.to_f.to_r * 10) + Rational(1, 2)).floor
      "#{n / 10}.#{n % 10}"
    end

    def classifier_card_note(id, c)
      "\"#{id}\" is decided by an attested classifier, not by a person. Published error rate: up to #{to_fixed1(published_error_rate(c) * 100)}%."
    end

    def gamma_of_set(g, a, t)
      s = 0
      a.each { |p| s += g[p][t] }
      [1, s].min
    end

    # R_kappa(G) = sum mu (1 - a) h Gamma(A_G(x) | l), with Gamma(A | l) capped at 1.
    def classifier_risk(m)
      r = 0.0
      m['mu'].each_with_index do |row, x|
        a = m['inG'][x].each_index.select { |p| m['inG'][x][p] }
        row.each_with_index { |mu, t| r += mu * (1 - m['a'][x][t]) * m['h'][x][t] * gamma_of_set(m['g'], a, t) }
      end
      r
    end

    def label_sound(m) = m['inG'].each_with_index.all? { |row, x| row.each_with_index.all? { |b, p| !b || m['a'][x][p] == 1 } }

    def label_sound_bound(m, h_max)
      s = 0.0
      m['mu'].each_with_index do |row, x|
        a = m['inG'][x].each_index.select { |p| m['inG'][x][p] }
        row.each_with_index { |mu, t| s += mu * gamma_of_set(m['g'], a, t) if m['a'][x][t].zero? }
      end
      h_max * s
    end

    def groups_of(l, spec)
      vs = l.omega['verbs'].find { |v| v['verb'] == spec['verb'] }
      raise ArgumentError, "classifier: no verb #{spec['verb']} in Ω" if vs.nil?

      k = vs['dims'].index { |d| d['path'] == spec['path'] } || -1
      dim = k >= 0 ? vs['dims'][k] : nil
      raise ArgumentError, "classifier: #{spec['verb']} has no categorical dimension #{spec['path']}" if k.negative? || dim.nil? || dim['kind'] != 'cat'

      groups = {}
      l.cells.each do |c|
        next if c['verb'] != spec['verb']

        key = c['cell'].each_with_index.reject { |_x, i| i == k }.map(&:first).join(',')
        (groups[key] ||= {})[c['cell'][k]] = { 'cell' => c['cell'], 'p' => c['p'], 'mass' => c['mass'], 'harm' => c['harm'], 'inGrant' => c['inGrant'] }
      end
      [dim, k, groups]
    end

    def gbar(spec, dim, pred, truth)
      pv = dim['values'][pred]
      tv = dim['values'][truth]
      return 0 if pv['kind'] != 'exact'

      labels = spec['cal']['labels']
      pi = labels.index(pv['value']) || -1
      return 0 if pi.negative?

      ti = tv['kind'] == 'exact' ? (labels.index(tv['value']) || -1) : -1
      return 1 if ti.negative?

      spec['cal']['gammaBar'][ti][pi]
    end

    def sum_gbar(spec, dim, a, t)
      s = 0
      a.each { |p| s += gbar(spec, dim, p, t) }
      s
    end

    # R-hat of the learner's grant with classifier error folded in; other verbs contribute the ordinary sum.
    def classifier_aware_residual_risk(l, specs)
      per_verb = {}
      spec_verbs = specs.to_h { |s| [s['verb'], true] }
      l.cells.each do |c|
        next if spec_verbs.key?(c['verb'])

        prev = per_verb.fetch(c['verb'], 0)
        per_verb[c['verb']] = c['inGrant'] ? prev + (c['mass'] * (1 - c['p']) * c['harm']) : prev
      end
      specs.each do |spec|
        dim, _k, groups = groups_of(l, spec)
        r = 0.0
        groups.each_value do |g|
          a = g.select { |_i, m| m['inGrant'] }.keys
          g.each { |t, m| r += m['mass'] * (1 - m['p']) * m['harm'] * [1, sum_gbar(spec, dim, a, t)].min }
        end
        per_verb[spec['verb']] = r
      end
      total = 0
      per_verb.each_value { |x| total += x }
      { 'total' => total, 'perVerb' => per_verb }
    end

    # Cells admitted on a classifier label that go to JIT consent: some true label the grant does not admit at the same x has an
    # upper-bounded mislabel rate above gamma_max.
    def classifier_jit_cells(l, spec, gamma_max)
      dim, _k, groups = groups_of(l, spec)
      vs = l.omega['verbs'].find { |v| v['verb'] == spec['verb'] }
      out = []
      groups.each_value do |g|
        a = g.select { |_i, m| m['inGrant'] }.keys
        next if a.empty?

        bad = g.select { |t, m| !m['inGrant'] && dim['values'][t]['kind'] == 'exact' }.keys
        worst = 0
        bad.each { |t| worst = [worst, [1, sum_gbar(spec, dim, a, t)].min].max }
        next unless worst > gamma_max

        a.each do |p|
          cell = g[p]['cell']
          out << { 'verb' => spec['verb'], 'cell' => cell, 'flat' => IntentOmega.encode_cell(vs, cell) }
        end
      end
      out.each_with_index.sort_by { |c, i| [c['flat'], i] }.map(&:first)
    end
  end
end
