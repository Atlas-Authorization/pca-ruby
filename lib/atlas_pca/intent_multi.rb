# frozen_string_literal: true

require_relative 'intent_omega'
require_relative 'intent_v2'

# Multi-principal intent: aggregation rules (unanimity, quorum, weighted, vetoers), the exact joint-acceptance DP and the common
# refinement of several outcome spaces. Native port of the TypeScript reference (@atlasauth/pca-intent).
module AtlasPca
  module IntentMulti
    UNDEF = V2JS::UNDEF
    PPM = 1_000_000
    SEV = %w[reversible rate_limited irreversible].freeze

    module_function

    def ppm(x) = ((x * PPM) + 0.5).floor

    # o.k with the reference's TypeError on null / undefined (the message is part of the observable behaviour).
    def member(o, k)
      raise TypeError, "Cannot read properties of null (reading '#{k}')" if o.nil?
      raise TypeError, "Cannot read properties of undefined (reading '#{k}')" if o.equal?(UNDEF)

      o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF
    end

    def int?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite? && x == x.floor)

    # A rule in normal form: {weights, threshold, veto}; the reference's error messages.
    def normalize_rule(rule, refs)
      vs = member(rule, 'vetoers')
      vs = [] if vs.nil? || vs.equal?(UNDEF)
      raise TypeError, 'rule.vetoers is not iterable' unless vs.is_a?(Array) || vs.is_a?(String)

      vetoers = vs.is_a?(String) ? vs.chars : vs.dup
      vetoers.each { |v| raise ArgumentError, "aggregateIntentMaps: vetoer #{v} is not one of the maps" unless refs.include?(v) }
      veto = refs.map { |r| vetoers.include?(r) }
      kind = member(rule, 'kind')
      return { 'weights' => refs.map { 1 }, 'threshold' => refs.length, 'veto' => veto } if kind == 'unanimity'

      if kind == 'quorum'
        k = member(rule, 'k')
        raise ArgumentError, "aggregateIntentMaps: quorum k must be an integer in [1, #{refs.length}]" unless int?(k) && k >= 1 && k <= refs.length

        return { 'weights' => refs.map { 1 }, 'threshold' => k, 'veto' => veto }
      end
      wmap = member(rule, 'weights')
      weights = refs.map { |r| member(wmap, r) }
      raise ArgumentError, 'aggregateIntentMaps: every principal needs a non-negative integer weight' if weights.any? { |w| !(int?(w) && w >= 0) }

      total = weights.sum
      th = member(rule, 'threshold')
      raise ArgumentError, "aggregateIntentMaps: threshold must be an integer in [1, #{V2JS.js_str(total)}]" unless int?(th) && th >= 1 && th <= total

      { 'weights' => weights, 'threshold' => th, 'veto' => veto }
    end

    # Principals that bound the joint grant: explicit vetoers plus implicit ones (T > W - w_i).
    def effective_vetoers(rule, refs)
      n = normalize_rule(rule, refs)
      total = n['weights'].sum
      refs.each_with_index.select { |_r, i| n['veto'][i] || n['threshold'] > total - n['weights'][i] }.map(&:first)
    end

    # Vetoers must admit; the admitting weight must reach the threshold.
    def rule_admits(n, ins)
      s = 0
      ins.each_index do |i|
        return false if n['veto'][i] && !ins[i]

        s += n['weights'][i] if ins[i]
      end
      s >= n['threshold']
    end

    # P(rule admits) with independent Bernoulli(p_i) acceptances: DP over the (capped) admitting weight.
    def joint_acceptance(n, ps)
      th = n['threshold']
      dist = Array.new(th + 1, 0.0)
      dist[0] = 1.0
      ps.each_with_index do |p, i|
        nxt = Array.new(th + 1, 0.0)
        w = n['weights'][i]
        (th + 1).times do |s|
          m = dist[s]
          next if m == 0

          t = [th, s + w].min
          nxt[t] = nxt[t] + (m * p)
          nxt[s] = nxt[s] + (m * (1 - p)) unless n['veto'][i]
        end
        dist = nxt
      end
      dist[th]
    end

    # ---- cross-org: common refinement ------------------------------------------------------------------------------

    def sev(r) = SEV.index(r) || -1

    def merge_dim(a, b)
      raise ArgumentError, "commonRefinement: #{a['path']} is numeric in one Ω and categorical in another" if a['kind'] != b['kind']

      if a['kind'] == 'num'
        if a['lo'] != b['lo'] || a['hi'] != b['hi']
          raise ArgumentError, "commonRefinement: #{a['path']} has different domains ([#{a['lo']}, #{a['hi']}] vs [#{b['lo']}, #{b['hi']}])"
        end

        cuts = []
        (a['cuts'] + b['cuts']).each { |c| cuts << c unless cuts.include?(c) }
        return { 'kind' => 'num', 'path' => a['path'], 'lo' => a['lo'], 'hi' => a['hi'], 'dist' => a['dist'], 'cuts' => cuts.sort }
      end
      ex = {}
      pre = {}
      (a['values'] + b['values']).each do |v|
        if v['kind'] == 'exact' then ex[v['value']] = nil
        elsif v['kind'] == 'prefix' then pre[v['value']] = nil
        end
      end
      values = ex.keys.sort_by { |s| IntentOmega.u16key(s) }.map { |v| { 'kind' => 'exact', 'value' => v } }
      values += pre.keys.sort_by { |s| IntentOmega.u16key(s) }.map { |v| { 'kind' => 'prefix', 'value' => v } }
      values << { 'kind' => 'other', 'value' => '⊥' }
      { 'kind' => 'cat', 'path' => a['path'], 'values' => values }
    end

    def deep(v) = Marshal.load(Marshal.dump(v))

    # The union of the verbs; per verb the union of dimensions; per numeric dimension the union of cuts (domains must agree); per
    # categorical dimension the union of the named values.
    def common_refinement(omegas)
      by_verb = {}
      approx = {}
      omegas.each do |o|
        o['approximate'].each { |x| approx[x] = nil }
        o['verbs'].each do |vs|
          cur = by_verb[vs['verb']]
          if cur.nil?
            by_verb[vs['verb']] = { 'verb' => vs['verb'], 'reversibility' => vs['reversibility'], 'weight' => 0, 'dims' => vs['dims'].map { |d| deep(d) } }
            next
          end
          cur['reversibility'] = vs['reversibility'] if sev(vs['reversibility']) > sev(cur['reversibility'])
          vs['dims'].each do |d|
            i = cur['dims'].index { |x| x['path'] == d['path'] } || -1
            if i.negative?
              cur['dims'] << deep(d)
            else
              cur['dims'][i] = merge_dim(cur['dims'][i], d)
            end
          end
        end
      end
      verbs = by_verb.values.sort_by { |v| IntentOmega.u16key(v['verb']) }
      verbs.each do |v|
        v['dims'] = v['dims'].sort_by { |d| IntentOmega.u16key(d['path']) }
        v['weight'] = 1.0 / verbs.length
      end
      { 'v' => 1, 'verbs' => verbs, 'approximate' => approx.keys.sort_by { |s| IntentOmega.u16key(s) } }
    end
  end
end
