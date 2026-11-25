# frozen_string_literal: true

# Quantitative and ternary static queries over a policy (the most that can ever be spent, the actions that need a human, the reach
# of a delegation chain, a first-class diff) and the workflow-DAG exposure. Port of the TypeScript reference (@atlasauth/pca-analyzer).
require_relative 'analyzer_core'

module AtlasPca
  module Analyzer
    HUGE = 9_007_199_254_740_991
    INF = Float::INFINITY
    WIDEN = %w[deny->allow deny->escalate escalate->allow].freeze
    PATH_CAP = 1_000_000
    UNBOUNDED_PEAK = { 'admitted' => true, 'max' => Float::INFINITY, 'attained' => false }.freeze

    module_function

    # {spec, catalogued}: a catalogued verb's spec, else the fail-closed spec (irreversible, maximum blast radius).
    def resolve_action(catalog, verb)
      spec = catalog_get(catalog, verb)
      return { 'spec' => spec, 'catalogued' => true } unless spec.nil?

      connector, _dot, rest = verb.partition('.')
      { 'spec' => { 'connector' => connector, 'action' => rest.empty? ? verb : rest, 'verb' => verb, 'reversibility' => 'irreversible',
                    'blastRadius' => 1, 'description' => "(uncatalogued) #{verb}" }, 'catalogued' => false }
    end

    def catalog_get(catalog, verb)
      catalog = AtlasPca::BUILTIN_ACTIONS if catalog.nil? || undef?(catalog)
      return catalog[verb] if catalog.is_a?(Hash)
      return catalog.get(verb) if !catalog.is_a?(Array) && catalog.respond_to?(:get)

      found = nil
      catalog.each { |a| found = a if a.is_a?(Hash) && a['verb'] == verb } # a later spec with the same verb replaces an earlier one
      found
    end

    def cond_thresholds(c, path, into)
      return unless obj?(c)

      if Predicates.group?(c)
        if c.key?('all_of') && c['all_of'].is_a?(Array)
          c['all_of'].each { |x| cond_thresholds(x, path, into) }
        elsif c.key?('any_of') && c['any_of'].is_a?(Array)
          c['any_of'].each { |x| cond_thresholds(x, path, into) }
        elsif c.key?('not')
          cond_thresholds(c['not'], path, into)
        end
        return
      end
      return if !Predicates.leaf?(c) || c['field'] != path

      v = own(c, 'value')
      if num?(v) && jsnum(v).finite?
        into << v
      elsif v.is_a?(Array)
        v.each { |x| into << x if num?(x) && jsnum(x).finite? }
      end
    end

    # Every numeric literal the policy compares `path` against, ascending and de-duplicated.
    def thresholds_of(model, path)
      out = []
      probe_set(model).each do |p|
        w = nn(jget(p, 'where'), [])
        req_list(w).each { |c| cond_thresholds(c, path, out) }
      end
      model['vetoes'].each do |v|
        over = jget(v, 'over')
        out << jget(over, 'threshold') if truthy?(over) && jget(over, 'path') == path && num?(jget(over, 'threshold'))
      end
      seen = {}
      out.each { |x| seen[jsnum(x)] = x unless seen.key?(jsnum(x)) }
      seen.keys.sort.map { |k| seen[k] }
    end

    def pinned(pr, path, value, resource)
      fields = pr['fields'].reject { |f| f['path'] == path } + [{ 'path' => path, 'values' => [value] }]
      pr.merge('resources' => undef?(resource) ? pr['resources'] : [resource], 'fields' => fields)
    end

    def peak_at(model, o, level)
      field = nn(jget(o, 'amountField'), 'amount')
      fname = js_str(field)
      path = "action.params.#{fname}"
      mx = bound_of(o)
      base = collect_probes({ 'predicateSets' => [probe_set(model)], 'varyReversibility' => model.key?('revCap') })
      base['verbs'] = [jget(o, 'verb')]
      t = thresholds_of(model, path)
      lo = pmax(0, jsnum(nn(jget(o, 'min'), 0)))
      hi = jsnum(nn(jget(o, 'max'), INF))
      raw = []
      t.each_with_index do |x, i|
        raw << (x - 1)
        raw << x
        raw << ((x + t[i + 1]) / 2.0) if i + 1 < t.length
      end
      raw << (t.empty? ? 0 : t[-1] + 1)
      raw << HUGE
      raw << lo
      raw << hi if hi.finite?
      uniq = {}
      raw.each { |c| uniq[jsnum(c)] = c unless uniq.key?(jsnum(c)) }
      cands = uniq.values.select { |c| lo <= c && c <= hi && jsnum(c).finite? }.sort.reverse
      resource = jget(o, 'resource')
      ok = ->(m) { level == 'allow' ? ->(rep) { decide(m, rep) == 'allow' } : ->(rep) { decide(m, rep) != 'deny' } }
      overflow = false
      cands.each do |c|
        out = search(pinned(base, path, c, resource), ok.call(model), mx)
        if out['overflow']
          overflow = true
          break
        end
        next unless out.key?('hit')

        hit = out['hit']
        act = lambda do |v|
          a = rep_to_action(hit)
          a['params'] = (a['params'] || {}).merge(fname => v)
          a
        end
        holds = lambda do |a|
          d = decide_action(model, a)
          level == 'allow' ? d == 'allow' : d != 'deny'
        end
        top = t.empty? ? -INF : t[-1]
        if c > top
          if hi.finite?
            return { 'peak' => { 'admitted' => true, 'max' => hi, 'attained' => holds.call(act.call(hi)), 'witness' => act.call(hi) }, 'overflow' => false }
          end

          return { 'peak' => { 'admitted' => true, 'max' => INF, 'attained' => false, 'witness' => act.call(HUGE) }, 'overflow' => false }
        end
        return { 'peak' => { 'admitted' => true, 'max' => c, 'attained' => true, 'witness' => act.call(c) }, 'overflow' => false } if t.any? { |x| jsnum(x) == c }

        nxt = t.find { |x| x > c }
        if jget(o, 'integer') == true
          m = nxt.ceil - 1
          return { 'peak' => { 'admitted' => true, 'max' => m, 'attained' => true, 'witness' => act.call(m) }, 'overflow' => false } if m >= c && holds.call(act.call(m))
        end
        return { 'peak' => { 'admitted' => true, 'max' => nxt, 'attained' => false, 'witness' => act.call(c) }, 'overflow' => false }
      end
      { 'peak' => { 'admitted' => false, 'max' => 0, 'attained' => false }, 'overflow' => overflow }
    end

    def universal(p, verb)
      pv = jget(p, 'verb')
      verb_ok = strict_eq(pv, '*') || strict_eq(pv, verb) || (pv.is_a?(Array) && (includes?(pv, '*') || includes?(pv, verb)))
      res = jget(p, 'resource')
      where = jget(p, 'where')
      raise TypeError, "cannot read properties of null (reading 'length')" if where.nil?

      verb_ok && (undef?(res) || strict_eq(res, '*')) && (undef?(where) || where.length.zero?) ? true : false
    end

    def ceil_div(a, b)
      q = jsnum(a) / jsnum(b)
      q.finite? ? q.ceil : q
    end

    def window_bound(model, c, o, peak)
      w = jget(o, 'windowSecs')
      path = "action.params.#{js_str(nn(jget(o, 'amountField'), 'amount'))}"
      per = peak['admitted'] ? peak['max'] : 0
      basis = []
      not_applied = []
      st = { 'maxActions' => INF }

      limit_actions = lambda do |n, per_secs, why|
        k = undef?(w) ? INF : n * ceil_div(w, per_secs) # a sliding limit of n per perSecs: at most n per started period
        if k < st['maxActions']
          st['maxActions'] = k
          basis << why
        end
      end

      caveats = model['caveats'].dup
      model['meets'].each { |m| caveats.concat(m['caveats']) }
      invs = c.is_a?(Hash) ? own(c, 'invariants') : UNDEF
      invs = [] unless invs.is_a?(Array)
      caveats.each do |cv|
        mx = jget(cv, 'max')
        ps = jget(cv, 'per_secs')
        limit_actions.call(mx, ps, "rate caveat #{num_str(jsnum(mx))}/#{num_str(jsnum(ps))}s") if jget(cv, 'type') == 'rate' && num?(mx) && num?(ps) && ps > 0
      end
      invs.each do |inv|
        next unless jget(inv, 'kind') == 'rate'

        if universal(jget(inv, 'when'), jget(o, 'verb'))
          limit_actions.call(jget(inv, 'max'), jget(inv, 'window_secs'), "rate invariant #{js_str(jget(inv, 'id'))}")
        else
          not_applied << jget(inv, 'id')
        end
      end
      max_actions = st['maxActions']
      bound = per == 0 ? 0 : (max_actions == INF ? INF : per * max_actions)
      basis.unshift('per-action ceiling') if jsnum(per).finite? && per > 0
      caveats.each do |cv|
        lim = jget(cv, 'limit')
        next if jget(cv, 'type') != 'budget_alloc' || !num?(lim)

        bm = jget(o, 'budgetModel')
        kappa = jget(o, 'kappa')
        if bm == 'dollars'
          if lim < bound
            bound = lim # in the dollar model the allocation is a lifetime cap on the total
            basis << "budget_alloc limit #{num_str(jsnum(lim))}"
          end
        elsif bm == 'risk' && num?(kappa) && kappa > 0
          r = jget(o, 'blastRadius')
          r = resolve_action(nil, jget(o, 'verb'))['spec']['blastRadius'] if undef?(r) || r.nil?
          cost = jsnum(kappa) * pmin(1, pmax(0, jsnum(r)))
          n = cost > 0 ? (jsnum(lim) / cost).floor : INF
          if n < max_actions
            max_actions = n
            st['maxActions'] = n
            bound = n == 0 ? 0 : (jsnum(per).finite? && per > 0 ? per * n : bound)
            basis << "budget_alloc #{num_str(jsnum(lim))} / cost #{num_str(cost)} = #{num_str(jsnum(n))} actions"
          end
        else
          not_applied << "budget_alloc #{num_str(jsnum(lim))} (trust-budget units; pass budgetModel and kappa)"
        end
      end
      invs.each do |inv|
        next unless jget(inv, 'kind') == 'cap'

        if !universal(jget(inv, 'when'), jget(o, 'verb')) || jget(inv, 'amount') != path
          not_applied << jget(inv, 'id')
          next
        end
        ws = jget(inv, 'window_secs')
        next if !undef?(ws) && undef?(w) # a windowed cap says nothing about a lifetime total

        cap = undef?(ws) || undef?(w) ? jget(inv, 'max') : jget(inv, 'max') * ceil_div(w, ws)
        if cap < bound
          bound = cap
          basis << "cap invariant #{js_str(jget(inv, 'id'))}"
        end
      end
      max_actions = st['maxActions']
      out = { 'maxActions' => max_actions, 'bound' => bound, 'basis' => basis, 'notApplied' => not_applied.reject { |x| undef?(x) } }
      out['secs'] = w unless undef?(w)
      wit = peak['witness']
      if peak['admitted'] && !wit.nil? && jsnum(max_actions).finite? && jsnum(peak['max']).finite? && peak['max'] > 0
        out['sequence'] = { 'action' => wit, 'repeat' => max_actions }
      end
      out
    end

    # The most that can ever leave under a policy: the largest single action, the largest autonomous action and the windowed
    # total ({verb, amountField, perAction, autonomousPerAction, window, autonomousWindow, unmodeled, approximate?, reason?}).
    def max_exposure(policy, given)
      o = given.is_a?(Hash) ? given.dup : {}
      if undef?(jget(given, 'budgetModel'))
        bmodel = jget(policy, 'budgetModel')
        o['budgetModel'] = bmodel if %w[dollars risk].include?(bmodel)
      end
      if undef?(jget(given, 'kappa'))
        rp = jget(policy, 'riskPolicy')
        pk = !undef?(rp) && !rp.nil? ? jget(rp, 'kappa') : UNDEF
        o['kappa'] = pk if num?(pk)
      end
      c = jget(o, 'constitution')
      cv = undef?(c) ? nil : vetoes_from_constitution(c)
      base = to_model(policy)
      model = cv.nil? ? base : base.merge('vetoes' => base['vetoes'] + cv['vetoes'])
      admit = peak_at(model, o, 'admit')
      auto = peak_at(model, o, 'allow')
      approximate = admit['overflow'] || auto['overflow'] || !model['undecidable'].empty?
      ap = admit['overflow'] ? UNBOUNDED_PEAK.dup : admit['peak']
      up = auto['overflow'] ? UNBOUNDED_PEAK.dup : auto['peak']
      unmodeled = (cv.nil? ? [] : cv['unmodeled']).reject { |u| %w[cap rate].include?(u['kind']) }
                                                  .map { |u| "#{js_str(own(u, 'id'))}: #{u['reason']}" }
      e = uobj({
                 'verb' => jget(o, 'verb'), 'amountField' => nn(jget(o, 'amountField'), 'amount'),
                 'perAction' => ap, 'autonomousPerAction' => up,
                 'window' => window_bound(model, c, o, ap), 'autonomousWindow' => window_bound(model, c, o, up),
                 'unmodeled' => unmodeled
               })
      if approximate
        e['approximate'] = true
        e['reason'] = admit['overflow'] || auto['overflow'] ? 'representative grid exceeded the bound; exposure reported as unbounded' : "over-approximated (#{model['undecidable'].join('; ')})"
      end
      e
    end

    # The actions that are admitted only with a human: {escalates, witnesses, approximate?, reason?}.
    def escalation_surface(policy, opts = nil)
      opts = {} if opts.nil?
      model = to_model(policy)
      base = collect_probes({ 'predicateSets' => [probe_set(model)], 'varyReversibility' => model.key?('revCap') })
      verb = jget(opts, 'verb')
      base['verbs'] = [verb] unless undef?(verb)
      r = collect(base, ->(rep) { decide(model, rep) == 'escalate' }, bound_of(opts), nn(jget(opts, 'limit'), 8))
      witnesses = r['hits'].map { |h| rep_to_action(h) }.select { |a| decide_action(model, a) == 'escalate' }
      out = { 'escalates' => !witnesses.empty?, 'witnesses' => witnesses }
      if r['overflow'] || !model['undecidable'].empty?
        out['approximate'] = true
        out['reason'] = r['overflow'] ? 'representative grid exceeded the bound' : "over-approximated (#{model['undecidable'].join('; ')})"
      end
      out
    end

    # The join of everything any holder of the leaf could do, with the remaining delegation depth.
    def delegation_envelope(chain, opts = nil)
      chain = req_list(chain)
      leaf = chain.empty? ? UNDEF : chain[-1]
      if obj?(leaf)
        extra = leaf.is_a?(Hash) ? own(leaf, 'meet') : UNDEF
        raise TypeError, 'meet is not iterable' if truthy?(extra) && !extra.is_a?(Array)

        policy = if leaf.is_a?(Hash)
                   leaf.merge('meet' => chain[0...-1] + (truthy?(extra) ? extra : []))
                 else
                   { 'meet' => chain[0...-1] }
                 end
      else
        policy = { 'predicates' => [] }
      end
      model = to_model(policy)
      base = collect_probes({ 'predicateSets' => [probe_set(model)], 'varyReversibility' => model.key?('revCap') })
      verbs = []
      any_verb = false
      overflow = false
      base['verbs'].each do |verb|
        r = collect(base.merge('verbs' => [verb]), ->(rep) { decide(model, rep) != 'deny' }, bound_of(opts), 1)
        if r['overflow']
          overflow = true
          break
        end
        next if r['hits'].empty?

        hit = r['hits'][0]
        w = rep_to_action(hit)
        if verb.start_with?("\u0000")
          any_verb = true
        else
          verbs << { 'verb' => verb, 'witness' => w, 'autonomous' => decide(model, hit) == 'allow' }
        end
      end
      violations = []
      (chain.length - 1).times do |i|
        a = to_model(chain[i])
        b = to_model(chain[i + 1])
        pr = collect_probes({ 'predicateSets' => [probe_set(a), probe_set(b)], 'varyReversibility' => a.key?('revCap') || b.key?('revCap') })
        out = search(pr, ->(rep) { decide(b, rep) != 'deny' && decide(a, rep) == 'deny' }, bound_of(opts))
        violations << (i + 1) if out.key?('hit') || out['overflow']
      end
      depths = []
      chain.each do |p|
        cvs = p.is_a?(Hash) ? own(p, 'caveats') : UNDEF
        (cvs.is_a?(Array) ? cvs : []).each do |c|
          depths << c['max'] if jget(c, 'type') == 'delegation_depth' && num?(jget(c, 'max'))
        end
      end
      used = pmax(0, chain.length - 1)
      depth = { 'used' => used }
      unless depths.empty?
        allowed = depths.min_by { |x| jsnum(x) }
        depth['allowed'] = allowed
        depth['remaining'] = pmax(0, jsnum(allowed) - used)
      end
      out2 = { 'violations' => violations, 'verbs' => verbs, 'anyVerb' => any_verb, 'depth' => depth }
      if overflow || !model['undecidable'].empty?
        out2['approximate'] = true
        out2['reason'] = overflow ? 'representative grid exceeded the bound' : "over-approximated (#{model['undecidable'].join('; ')})"
      end
      out2
    end

    def sub(x, y) = x == y ? 0 : x - y # Infinity - Infinity is no change

    # `diff(A, B)`: which actions move between allow / escalate / deny, with witnesses; optionally how the max exposure moved.
    def diff_policies(a, b, o = nil)
      o = {} if o.nil?
      ma = to_model(a)
      mb = to_model(b)
      pr = collect_probes({ 'predicateSets' => [probe_set(ma), probe_set(mb)], 'varyReversibility' => ma.key?('revCap') || mb.key?('revCap') })
      limit = nn(jget(o, 'limit'), 4)
      shifts = {}
      counts = Hash.new(0)
      visit = lambda do |rep|
        x = decide(ma, rep)
        y = decide(mb, rep)
        next false if x == y

        k = "#{x}->#{y}"
        n = counts[k]
        counts[k] = n + 1
        (shifts[k] ||= []) << rep_to_action(rep) if n < limit
        false # walk the whole grid
      end
      walk = collect(pr, visit, bound_of(o), 1)
      overflow = walk['overflow']
      kinds = shifts.keys
      widens = kinds.any? { |k| WIDEN.include?(k) }
      narrows = kinds.any? { |k| !WIDEN.include?(k) }
      summary = kinds.map do |k|
        s0 = shifts[k][0]
        "#{k}: #{shifts[k].length}+ action(s), e.g. #{js_str(s0['verb'])} #{js_str(s0['resource'])} #{js_json(s0['params'] || {})}"
      end
      d = {
        'equivalent' => kinds.empty? && !overflow && ma['undecidable'].empty? && mb['undecidable'].empty?,
        'shifts' => shifts, 'widens' => widens, 'narrows' => narrows, 'summary' => summary
      }
      ex = jget(o, 'exposure')
      unless undef?(ex)
        before = max_exposure(a, ex)
        after = max_exposure(b, ex)
        e = {
          'before' => before, 'after' => after,
          'perActionDelta' => sub(after['perAction']['max'], before['perAction']['max']),
          'autonomousDelta' => sub(after['autonomousWindow']['bound'], before['autonomousWindow']['bound']),
          'delta' => sub(after['window']['bound'], before['window']['bound'])
        }
        d['exposure'] = e
        worst = [e['delta'], e['perActionDelta'], e['autonomousDelta']].max
        best = [e['delta'], e['perActionDelta']].min
        verb = js_str(jget(ex, 'verb'))
        if worst > 0
          summary << "max exposure of #{verb} rises by #{num_str(jsnum(worst))}"
        elsif best.negative?
          summary << "max exposure of #{verb} falls by #{num_str(jsnum(-best))}"
        end
      end
      if overflow || !ma['undecidable'].empty? || !mb['undecidable'].empty?
        d['approximate'] = true
        seen = {}
        (ma['undecidable'] + mb['undecidable']).each { |r| seen[r] = nil }
        d['reason'] = overflow ? 'representative grid exceeded the bound' : "over-approximated (#{seen.keys.join('; ')})"
      end
      d
    end

    # A CI gate over a diff: fails when the change widens authority beyond what the reviewer allowed.
    def diff_gate(d, allow = nil)
      allow = {} if allow.nil?
      reasons = []
      if jget(d, 'widens') == true && jget(allow, 'widen') != true
        reasons << "widens authority: #{d['summary'].select { |s| WIDEN.any? { |k| s.start_with?(k) } }.join('; ')}"
      end
      ex = jget(d, 'exposure')
      rise = truthy?(ex) ? [ex['delta'], ex['perActionDelta'], ex['autonomousDelta']].max : 0
      lim = nn(jget(allow, 'maxExposureIncrease'), 0)
      reasons << "max exposure rises by #{num_str(jsnum(rise))}" if rise > lim
      reasons << "inconclusive: #{js_str(nn(jget(d, 'reason'), 'approximate'))}" if truthy?(jget(d, 'approximate'))
      { 'ok' => reasons.empty?, 'reasons' => reasons }
    end

    # Check what an optional external solver returned: a witness is re-checked by the real evaluator (never trusted); an unsat
    # claim is returned labelled as solver-claimed. `backend` has a `name` and a `find(query)` callable returning {witness?, unsat?}.
    def find_with_backend(backend, q)
      find = backend.is_a?(Hash) ? backend['find'] : backend.method(:find)
      name = backend.is_a?(Hash) ? backend['name'] : backend.name
      r = find.call(q)
      w = jget(r, 'witness')
      unless undef?(w)
        ma = to_model(jget(q, 'a'))
        qb = jget(q, 'b')
        qv = jget(q, 'verb')
        ok = if jget(q, 'kind') == 'reachable'
               decide_action(ma, w) != 'deny' && (undef?(qv) || strict_eq(jget(w, 'verb'), qv))
             else
               !undef?(qb) && ((decide_action(ma, w) != 'deny') != (decide_action(to_model(qb), w) != 'deny'))
             end
        return ok ? { 'witness' => w } : { 'rejected' => true }
      end
      return { 'claimedUnsat' => { 'by' => name, 'proof' => 'solver-claimed, not machine-checked' } } if jget(r, 'unsat') == true

      {}
    end

    # ---- workflow DAG exposure -----------------------------------------------------------------------------------------------

    # Static exposure of a workflow body (steps, dependency DAG, edges, budget); raises ArgumentError (the reference's RangeError)
    # on a body that is not a DAG.
    def dag_exposure(b)
      steps = req_list(jget(b, 'steps'))
      by_id = {}
      steps.each { |s| by_id[jget(s, 'id')] = s }
      raise ArgumentError, 'dagExposure: duplicate step id' if by_id.length != steps.length

      level = {}
      anc = {}
      visiting = {}
      visit = nil
      visit = lambda do |id|
        next if level.key?(id)
        raise ArgumentError, 'dagExposure: cycle' if visiting.key?(id)

        visiting[id] = true
        raise ArgumentError, "dagExposure: unknown step #{js_str(id)}" unless by_id.key?(id)

        s = by_id[id]
        a = {}
        lv = 0
        req_list(jget(s, 'deps')).each do |d|
          visit.call(d)
          a[d] = true
          a.merge!(anc[d])
          lv = [lv, level[d] + 1].max
        end
        visiting.delete(id)
        anc[id] = a
        level[id] = lv
      end
      steps.each { |s| visit.call(jget(s, 'id')) }
      depth = ([0] + level.values).max + 1
      widths = Hash.new(0)
      level.each_value { |lv| widths[lv] += 1 }
      level_width = widths.empty? ? -INF : widths.values.max

      children = {}
      steps.each { |s| children[jget(s, 'id')] = [] }
      steps.each { |s| jget(s, 'deps').each { |d| children[d] << jget(s, 'id') } }
      memo = {}
      capped = false
      to_leaves = nil
      to_leaves = lambda do |id|
        next memo[id] if memo.key?(id)

        kids = children[id]
        n = kids.empty? ? 1 : 0
        kids.each { |k| n += to_leaves.call(k) }
        if n > PATH_CAP
          n = PATH_CAP
          capped = true
        end
        memo[id] = n
      end
      paths = 0
      steps.each { |s| paths = [PATH_CAP, paths + to_leaves.call(jget(s, 'id'))].min if jget(s, 'deps').length.zero? }

      budget = jget(b, 'budget')
      caps = jget(budget, 'caps')
      raise TypeError, 'Object.entries requires an object' if undef?(caps) || caps.nil? || !caps.is_a?(Hash)

      cost = {}
      key_order(caps).each do |name|
        cap = caps[name]
        total = 0
        steps.each do |s|
          sc = jget(s, 'cost')
          total += (sc.is_a?(Hash) && sc.key?(name) && !sc[name].nil? ? sc[name] : 0)
        end
        cost[name] = { 'cap' => cap, 'total' => total, 'maxSpend' => pmin(cap, total) }
      end
      max_steps = jget(budget, 'max_steps')
      never = []
      steps.each do |s|
        sc = jget(s, 'cost')
        if sc.is_a?(Hash) && sc.any? { |n, c| c > nn(caps[n], 0) }
          never << { 'step' => jget(s, 'id'), 'reason' => 'cost_over_cap' }
        elsif num?(max_steps) && anc[jget(s, 'id')].length + 1 > jsnum(max_steps)
          never << { 'step' => jget(s, 'id'), 'reason' => 'needs_more_steps_than_budget' }
        end
      end

      edges = req_list(jget(b, 'edges'))
      feeds = {}
      steps.each { |s| feeds[jget(s, 'id')] = {} }
      edges.each { |e| feeds[jget(jget(e, 'to'), 'step')][jget(jget(e, 'from'), 'step')] = true }
      lineage_of = nil
      lineage_of = lambda do |id, seen|
        feeds[id].each_key do |f|
          next if seen.key?(f)

          seen[f] = true
          lineage_of.call(f, seen)
        end
        seen
      end
      sinks = []
      steps.each do |s|
        sk = jget(s, 'sink')
        next if sk.nil?

        sid = jget(s, 'id')
        incoming = edges.select { |e| jget(jget(e, 'to'), 'step') == sid }
        lineage = lineage_of.call(sid, {}).keys.sort_by { |x| u16key(x) }
        sinks << uobj({
                        'step' => sid, 'sink' => sk, 'lineage' => lineage,
                        'protected' => jget(s, 'deny_labels').length.positive? || jget(s, 'escalate_labels').length.positive? ||
                                       incoming.any? { |e| jget(e, 'deny_labels').length.positive? }
                      })
      end
      unprotected = sinks.reject { |k| k['protected'] || k['lineage'].empty? }.map { |k| k['step'] }
      ordering_only = steps.select { |s| jget(s, 'deps').length.positive? && edges.none? { |e| jget(jget(e, 'to'), 'step') == jget(s, 'id') } }
                           .map { |s| jget(s, 'id') }
      pipelinable = []
      edges.each_with_index { |e, i| pipelinable << i unless jget(e, 'promise').nil? }
      ms = num?(max_steps) ? jsnum(max_steps) : Float::NAN
      {
        'steps' => steps.length, 'maxSteps' => ms.nan? ? nil : pmin(steps.length, ms), 'depth' => depth, 'levelWidth' => level_width,
        'paths' => paths, 'pathsCapped' => capped, 'cost' => cost, 'neverRunnable' => never, 'sinks' => sinks, 'unprotectedSinks' => unprotected,
        'orderingOnly' => ordering_only, 'pipelinable' => pipelinable
      }
    end
  end
end
