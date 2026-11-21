# frozen_string_literal: true

# Policy coverage (which clauses decided, which never matched, how close traffic came to each threshold, which single-edit mutants the
# traffic cannot tell from the policy) and the minimal-change counterfactual search on a deny or escalate. Port of the TypeScript
# reference (@atlasauth/pca-analyzer).
require_relative 'analyzer_core'

module AtlasPca
  module Analyzer
    FLIP = { 'lt' => 'lte', 'lte' => 'lt', 'gt' => 'gte', 'gte' => 'gt', 'eq' => 'ne', 'ne' => 'eq', 'in' => 'nin', 'nin' => 'in' }.freeze
    RANK = { 'deny' => 0, 'escalate' => 1, 'allow' => 2 }.freeze

    module_function

    def permit_id(i) = "permit[#{i}]"
    def undef_nil(x) = x.equal?(UNDEF) ? nil : x

    # A stable sort by a key (Python's sorted is stable; sort_by is not).
    def stable_sort_by(xs)
      xs.each_with_index.sort_by { |x, i| [yield(x), i] }.map(&:first)
    end

    # `list(x)`: an array is copied, a string splits into characters, anything else is not iterable.
    def listify(x)
      return x.dup if x.is_a?(Array)
      return x.chars if x.is_a?(String)

      raise TypeError, 'not iterable'
    end

    # The decision with the clause that decided it: a forbid beats an approval rule, which beats a permit.
    def witness_of(model, action)
      decision = decide_action(model, action)
      ctx = context_of_action(action)
      permits = model['predicates'].each_with_index.select { |p, _| AtlasPca.predicate_matches(p, ctx) }.map { |_, i| permit_id(i) }
      vetoes = model['vetoes'].select { |v| veto_applies(v, ctx) }
      tighten = model['tighten'].select do |t|
        w = jget(t, 'when')
        AtlasPca.evaluate_condition_tri(w.equal?(UNDEF) ? nil : w, ctx) != 'false'
      end
      others = lambda do |win|
        (permits + vetoes.map { |v| undef_nil(jget(v, 'id')) } + tighten.map { |t| undef_nil(jget(t, 'id')) }).reject { |i| i == win }
      end
      done = lambda do |kind, id|
        { 'decision' => decision, 'winner' => { 'kind' => kind, 'id' => undef_nil(id) }, 'also' => others.call(undef_nil(id)) }
      end

      if !model['caveatSat'] || decision == 'deny'
        return done.call('caveat', 'caveats') unless model['caveatSat']
        return { 'decision' => decision, 'winner' => { 'kind' => 'none', 'id' => nil }, 'also' => others.call(nil) } if permits.empty?

        veto = vetoes.find { |v| jget(v, 'kind') == 'deny' }
        return done.call('veto', jget(veto, 'id')) unless veto.nil?

        t = tighten.find { |x| jget(x, 'signal') == 'deny' }
        return done.call('tighten', jget(t, 'id')) unless t.nil?

        return done.call('caveat', 'caveats') # reversibility cap or an ancestor of the chain
      end
      if decision == 'escalate'
        veto = vetoes.find { |v| jget(v, 'kind') == 'approval' }
        return done.call('veto', jget(veto, 'id')) unless veto.nil?

        return done.call('tighten', tighten.empty? ? nil : jget(tighten[0], 'id'))
      end
      done.call('permit', permits.empty? ? nil : permits[0])
    end

    # ---- mutation operators -------------------------------------------------------------------------------------------------

    def variants_of_cond(c, eps)
      return [] unless c.is_a?(Hash) || c.is_a?(Array)

      if AtlasPca.group_condition?(c)
        out = []
        if c.key?('not')
          variants_of_cond(c['not'], eps).each { |v| out << { 'cond' => { 'not' => v['cond'] }, 'what' => "not(#{v['what']})" } }
          return out
        end
        is_all = c.key?('all_of')
        kids = req_list(is_all ? c['all_of'] : g(c, 'any_of'))
        kids.each_with_index do |k, i|
          variants_of_cond(k, eps).each do |v|
            nxt = kids.each_with_index.map { |x, j| j == i ? v['cond'] : x }
            out << { 'cond' => is_all ? { 'all_of' => nxt } : { 'any_of' => nxt },
                     'what' => "#{is_all ? 'all_of' : 'any_of'}[#{i}] #{v['what']}" }
          end
        end
        return out
      end
      return [] if !AtlasPca.leaf_condition?(c) || c.key?('ref')

      out = []
      name = c['field'].sub(/\Aaction\.params\./, '')
      val = g(c, 'value')
      op = g(c, 'op')
      if num?(val) && jsnum(val).finite? && %w[lt lte gt gte eq].include?(op)
        up = val + eps
        dn = val - eps
        out << { 'cond' => c.merge('value' => up), 'what' => "#{name} #{op} #{num_str(jsnum(val))} -> #{num_str(jsnum(up))}" }
        out << { 'cond' => c.merge('value' => dn), 'what' => "#{name} #{op} #{num_str(jsnum(val))} -> #{num_str(jsnum(dn))}" }
      end
      out << { 'cond' => c.merge('op' => FLIP[op]), 'what' => "#{name} #{op} -> #{FLIP[op]}" } if op.is_a?(String) && FLIP.key?(op)
      out
    end

    def mutants_of(policy, eps)
      out = []
      mk = ->(over) { { 'predicates' => policy['predicates'], 'caveats' => policy['caveats'], 'vetoes' => policy['vetoes'], 'tighten' => policy['tighten'] }.merge(over) }
      preds = policy['predicates']
      preds.each_with_index do |p, i|
        out << { 'id' => "drop-#{permit_id(i)}", 'description' => "drop #{permit_id(i)}",
                 'policy' => mk.call('predicates' => preds.each_with_index.reject { |_, j| j == i }.map(&:first)) }
        where = req_list(nn(jget(p, 'where'), []))
        where.each_with_index do |c, j|
          variants_of_cond(c, eps).each do |v|
            np = spread(p).merge('where' => where.each_with_index.map { |x, k| k == j ? v['cond'] : x })
            out << { 'id' => "#{permit_id(i)}.where[#{j}]:#{v['what']}", 'description' => "#{permit_id(i)}: #{v['what']}",
                     'policy' => mk.call('predicates' => preds.each_with_index.map { |x, k| k == i ? np : x }) }
          end
          rest = where.each_with_index.reject { |_, k| k == j }.map(&:first)
          out << { 'id' => "#{permit_id(i)}.where[#{j}]:drop", 'description' => "#{permit_id(i)}: drop condition #{j}",
                   'policy' => mk.call('predicates' => preds.each_with_index.map { |x, k| k == i ? spread(p).merge('where' => rest) : x }) }
        end
      end
      vetoes = policy['vetoes']
      vetoes.each_with_index do |v, i|
        vid = js_str(jget(v, 'id'))
        out << { 'id' => "drop-veto:#{vid}", 'description' => "drop prohibition #{vid}",
                 'policy' => mk.call('vetoes' => vetoes.each_with_index.reject { |_, j| j == i }.map(&:first)) }
        over = jget(v, 'over')
        next unless truthy?(over)

        nv = vetoes.each_with_index.map do |x, j|
          j == i ? spread(x).merge('over' => spread(over).merge('threshold' => jget(over, 'threshold') + eps)) : x
        end
        out << { 'id' => "veto:#{vid}:threshold+", 'description' => "raise the #{vid} threshold by #{num_str(jsnum(eps))}", 'policy' => mk.call('vetoes' => nv) }
      end
      tighten = policy['tighten']
      tighten.each_with_index do |t, i|
        tid = js_str(jget(t, 'id'))
        out << { 'id' => "drop-tighten:#{tid}", 'description' => "drop tighten rule #{tid}",
                 'policy' => mk.call('tighten' => tighten.each_with_index.reject { |_, j| j == i }.map(&:first)) }
      end
      out
    end

    def reach(model, kind, idx)
      if kind == 'permit'
        r = always_denies({ 'predicates' => [model['predicates'][idx]], 'caveats' => model['caveats'] })
        return r['approximate'] ? 'unknown' : !r['alwaysDenies']
      end
      if kind == 'veto'
        r = always_denies({ 'predicates' => [jget(model['vetoes'][idx], 'when')] })
        return r['approximate'] ? 'unknown' : !r['alwaysDenies']
      end
      'unknown'
    end

    # Python's `int(x)` over a JSON number (or numeric string): truncates toward zero.
    def py_int(x)
      case x
      when Integer then x
      when Float then x.to_i
      when true then 1
      when false then 0
      when String then Integer(x.strip, 10)
      else raise TypeError, 'int() argument must be a string or a number'
      end
    end

    # Coverage of `policy` by `traffic` (actions): clauses, boundaries, mutants and the 0..1 scores.
    def coverage(policy, traffic, o = nil)
      o = {} if o.nil?
      traffic = req_list(traffic)
      model = to_model(policy)
      eps = nn(jget(o, 'epsilon'), 1)
      ids = model['predicates'].each_index.map { |i| { 'id' => permit_id(i), 'kind' => 'permit' } } +
            model['vetoes'].map { |v| { 'id' => undef_nil(jget(v, 'id')), 'kind' => 'veto' } } +
            model['tighten'].map { |t| { 'id' => undef_nil(jget(t, 'id')), 'kind' => 'tighten' } }
      matched = {}
      decisive = {}
      bump = ->(m, k) { m[k] = m.fetch(k, 0) + 1 unless k.nil? }
      traffic.each do |a|
        w = witness_of(model, a)
        bump.call(decisive, w['winner']['id'])
        ([w['winner']['id']] + w['also']).each { |i| bump.call(matched, i) }
      end
      np = model['predicates'].length
      nv = model['vetoes'].length
      clauses = ids.each_with_index.map do |c, n|
        idx = c['kind'] == 'permit' ? n : (c['kind'] == 'veto' ? n - np : n - np - nv)
        { 'id' => c['id'], 'kind' => c['kind'], 'matched' => matched.fetch(c['id'], 0), 'decisive' => decisive.fetch(c['id'], 0),
          'reachable' => reach(model, c['kind'], idx) }
      end
      paths = {}
      walk = nil
      walk = lambda do |c|
        next unless c.is_a?(Hash) || c.is_a?(Array)

        if AtlasPca.group_condition?(c)
          if c.key?('all_of')
            req_list(c['all_of']).each { |x| walk.call(x) }
          elsif c.key?('any_of')
            req_list(c['any_of']).each { |x| walk.call(x) }
          else
            walk.call(c['not'])
          end
        elsif AtlasPca.leaf_condition?(c) && c['field'].start_with?('action.params.') && %w[lt lte gt gte eq in nin].include?(c['op'])
          paths[c['field']] = true
        end
      end
      probe_set(model).each { |p| req_list(nn(jget(p, 'where'), [])).each { |c| walk.call(c) } }
      model['vetoes'].each do |v|
        over = jget(v, 'over')
        paths[jget(over, 'path')] = true if truthy?(over)
      end
      boundaries = []
      paths.keys.sort_by { |s| u16key(s) }.each do |path|
        name = path['action.params.'.length..] || ''
        vals = traffic.map { |a| own(nn(jget(a, 'params'), {}), name) }.select { |x| num?(x) }
        thresholds_of(model, path).each do |t|
          boundaries << {
            'path' => path, 'threshold' => t, 'at' => vals.any? { |v| strict_eq(v, t) },
            'below' => vals.any? { |v| v < t && v >= t - eps }, 'above' => vals.any? { |v| v > t && v <= t + eps }
          }
        end
      end
      survivors = []
      killed = 0
      equiv = 0
      mm = nn(jget(o, 'maxMutants'), 200)
      allm = mm.is_a?(Float) && mm.nan? ? [] : mutants_of(model, eps)[0...py_int(mm)]
      base = traffic.map { |a| decide_action(model, a) }
      allm.each do |m|
        mmod = to_model(m['policy'])
        if traffic.each_with_index.any? { |a, i| decide_action(mmod, a) != base[i] }
          killed += 1
          next
        end
        eq = equivalent(policy, m['policy'])
        if eq['equivalent']
          equiv += 1
          next
        end
        s = { 'id' => m['id'], 'description' => m['description'] }
        s['killer'] = eq['counterexample'] if truthy?(g(eq, 'counterexample'))
        survivors << s
      end
      ratio = ->(n, d) { d.zero? ? 1 : n.to_f / d }
      live = clauses.reject { |c| c['reachable'] == false }
      {
        'traffic' => traffic.length,
        'policyDigest' => policy_digest_of(model),
        'clauses' => clauses,
        'neverMatched' => clauses.select { |c| c['matched'].zero? }.map { |c| c['id'] },
        'neverDecisive' => clauses.select { |c| c['decisive'].zero? }.map { |c| c['id'] },
        'untested' => clauses.select { |c| c['reachable'] != false && c['matched'].zero? }.map { |c| c['id'] },
        'unreachable' => clauses.select { |c| c['reachable'] == false }.map { |c| c['id'] },
        'boundaries' => boundaries,
        'mutants' => { 'total' => allm.length, 'killed' => killed, 'equivalent' => equiv, 'survivors' => survivors },
        'score' => {
          'clauses' => ratio.call(live.count { |c| c['decisive'].positive? }, live.length),
          'boundaries' => ratio.call(boundaries.count { |b| b['at'] && b['below'] && b['above'] }, boundaries.length),
          'mutation' => ratio.call(killed, allm.length - equiv)
        }
      }
    end

    # A CI gate over a coverage report: {ok, reasons}.
    def coverage_gate(r, minimum = nil)
      mn = minimum.nil? ? {} : minimum
      reasons = []
      score = jget(r, 'score')
      [%w[clauses clause\ coverage], %w[boundaries boundary\ coverage], %w[mutation mutation\ score]].each do |key, label|
        lim = jget(mn, key)
        next unless jsnum(score.fetch(key)) < jsnum(nn(lim, 0))

        reasons << "#{label} #{to_fixed(jsnum(score.fetch(key)), 2)} < #{num?(lim) ? num_str(jsnum(lim)) : js_str(lim)}"
      end
      ms = jget(mn, 'maxSurvivors')
      if !ms.equal?(UNDEF) && r['mutants']['survivors'].length > jsnum(ms)
        reasons << "#{r['mutants']['survivors'].length} surviving mutants > #{num?(ms) ? num_str(jsnum(ms)) : js_str(ms)}"
      end
      reasons << "unreachable clauses: #{r['unreachable'].map { |x| js_str(x) }.join(', ')}" unless r['unreachable'].empty?
      { 'ok' => reasons.empty?, 'reasons' => reasons }
    end

    # ---- minimal flip -------------------------------------------------------------------------------------------------------

    # The reference's camelCase CaveatContext as the context Hash `evaluate_caveats` reads.
    def cav_ctx(c)
      return c unless c.is_a?(Hash)

      out = c.dup
      [%w[blastRadius blast_radius], %w[reversibilityClass reversibility_class], %w[delegationDepth delegation_depth],
       %w[recentActionTimes recent_action_times]].each do |camel, snake|
        out[snake] = out.delete(camel) if out.key?(camel)
      end
      out
    end

    def jsmax(a, b) = (a.is_a?(Float) && a.nan?) || (b.is_a?(Float) && b.nan?) ? Float::NAN : [a, b].max

    def wait_time(caveats, ctx)
      at = UNDEF
      now = jget(ctx, 'now')
      caveats.each do |c|
        t = jget(c, 'type')
        cat = jget(c, 'at')
        at = jsmax(at.equal?(UNDEF) ? 0 : at, jsnum(cat)) if t == 'not_before' && num?(cat) && js_gt(cat, now)
        mx = jget(c, 'max')
        ps = jget(c, 'per_secs')
        next unless t == 'rate' && num?(mx) && num?(ps)

        span = jsnum(ps) * 1000
        times = nn(jget(ctx, 'recentActionTimes'), [])
        recent = stable_sort_by(req_list(times).select { |x| js_gt(x, jsnum(now) - span) }) { |x| jsnum(x) }
        next unless recent.length >= jsnum(mx)

        i = recent.length - jsnum(mx)
        v = i == i.to_i && i >= 0 && i < recent.length ? jsnum(recent[i.to_i]) + span : Float::NAN
        at = jsmax(at.equal?(UNDEF) ? 0 : at, v)
      end
      at
    end

    def meters?(m)
      cs = m['caveats'].dup
      m['meets'].each { |x| cs.concat(x['caveats']) }
      cs.any? { |c| %w[rate budget_alloc max_blast_radius].include?(jget(c, 'type')) }
    end

    def set_path(o, path, v)
      return o if path.empty?

      k = path[0]
      rest = path[1..]
      o[k] = rest.empty? ? v : set_path(spread(nn(o[k], {})), rest, v)
      o
    end

    def decl_of(shape, name)
      return UNDEF if shape.equal?(UNDEF)

      jget(jget(shape, 'params'), name)
    end

    def with_param(action, params, name, v)
      a = spread(action)
      p = params.dup
      p[name] = v
      a['params'] = p
      a
    end

    def uniq_vals(xs)
      seen = {}
      xs.each do |x|
        k = if num?(x) then ['n', jsnum(x)]
            elsif x.is_a?(String) then ['s', x]
            else ['o', x.object_id]
            end
        seen[k] = x unless seen.key?(k)
      end
      seen.values
    end

    # The smallest verified change that gets `action` to the wanted decision (default allow), ordered by cost: wait, change one
    # parameter, change two together, another resource, obtain a fact, split (opt-in), ask a human. Only a repair the real decision
    # confirms is returned; shown only to the authenticated holder; critical values are redacted by default.
    def minimal_flip(policy, action, o)
      model = to_model(policy)
      cctx = jget(o, 'caveatContext')
      caveats_ok = cctx.equal?(UNDEF) || AtlasPca.evaluate_caveats(model['caveats'], cav_ctx(cctx))[0]
      current = caveats_ok ? decide_action(model, action) : 'deny'
      want = nn(jget(o, 'desired'), 'allow')
      rank_want = want.is_a?(String) ? RANK.fetch(want, Float::NAN) : Float::NAN
      res = { 'current' => current, 'repairs' => [], 'repairExists' => false }
      return res.merge('refused' => 'counterfactuals are shown only to the authenticated holder') unless truthy?(jget(o, 'holderAuthenticated'))

      probe = jget(o, 'probe')
      if truthy?(probe)
        now = jget(probe, 'now')
        hist = req_list(jget(probe, 'history'))
        # a clock, window or history stamp that is not finite cannot say what is still inside the window: refuse (a +Infinity limit stays an unbounded cap)
        unless [now, jget(probe, 'windowSecs')].all? { |x| num?(x) && jsnum(x).finite? } && hist.all? { |x| num?(x) && jsnum(x).finite? }
          return res.merge('refused' => 'probe budget exhausted', 'probe' => { 'history' => hist })
        end

        recent = req_list(jget(probe, 'history')).select { |t| js_gt(t, jsnum(now) - (jsnum(jget(probe, 'windowSecs')) * 1000)) }
        return res.merge('refused' => 'probe budget exhausted', 'probe' => { 'history' => recent }) unless recent.length < jsnum(jget(probe, 'limit'))

        res['probe'] = { 'history' => recent + [now] }
      end
      digest = policy_digest_of(model)
      return res if RANK[current] >= rank_want

      schema = jget(o, 'schema')
      shape = UNDEF
      shape = req_list(schema).find { |s| strict_eq(jget(s, 'verb'), jget(action, 'verb')) } || UNDEF if !schema.equal?(UNDEF) && !schema.nil?

      reaches = lambda do |a|
        d = decide_action(model, a)
        RANK[d] >= rank_want ? d : nil
      end
      cands = []
      push = lambda do |repair, cost, a|
        d = reaches.call(a)
        cands << { 'repair' => repair, 'cost' => cost, 'decision' => d, 'action' => a } unless d.nil?
      end

      pr = collect_probes({ 'predicateSets' => [probe_set(model)], 'varyReversibility' => model.key?('revCap') })
      params = spread(nn(jget(action, 'params'), {}))
      ch = jget(o, 'changeable')
      names = if !ch.equal?(UNDEF) && !ch.nil? then listify(req_list(ch))
              elsif !shape.equal?(UNDEF) then key_order(jget(shape, 'params'))
              else key_order(params)
              end

      # 1. wait: a time caveat that is not open yet, or a rate window that will reset
      if !caveats_ok && truthy?(cctx)
        at = wait_time(model['caveats'], cctx)
        d = decide_action(model, action)
        unless at.equal?(UNDEF)
          later = spread(cctx).merge('now' => at)
          if AtlasPca.evaluate_caveats(model['caveats'], cav_ctx(later))[0] && RANK[d] >= rank_want
            cands << { 'repair' => { 'kind' => 'wait_until', 'at' => at, 'reason' => 'a time or rate caveat opens then' }, 'cost' => 1, 'decision' => d, 'action' => action }
          end
        end
      end
      finish = !caveats_ok # nothing else helps while a caveat is closed

      # 2. one parameter changed: the nearest verified value, per parameter
      (finish ? [] : names).each do |name|
        path = "action.params.#{name}"
        decl = decl_of(shape, name)
        cur = own(params, name)
        field = pr['fields'].find { |f| f['path'] == path }
        dvals = oget(decl, 'values')
        dmin = oget(decl, 'min')
        dmax = oget(decl, 'max')
        pool = ((field ? field['values'].dup : []) + (dvals.equal?(UNDEF) ? [] : listify(dvals)) + (dmin.equal?(UNDEF) ? [] : [dmin]) +
                (dmax.equal?(UNDEF) ? [] : [dmax])).reject { |v| v.equal?(ABSENT) }
        nums = pool.select { |v| num?(v) && jsnum(v).finite? }
        thr = thresholds_of(model, path)
        integer = oget(decl, 'type') == 'integer' || (num?(cur) && jsnum(cur).finite? && jsnum(cur) == jsnum(cur).floor)
        ints = integer ? thr.flat_map { |t| [t - 1, t + 1] } : []
        curn = num?(cur) ? jsnum(cur) : 0
        numeric = stable_sort_by(uniq_vals(nums + ints).select { |v| (dmin.equal?(UNDEF) || v >= dmin) && (dmax.equal?(UNDEF) || v <= dmax) }) do |v|
          [(jsnum(v) - curn).abs, jsnum(v)]
        end
        strs = uniq_vals(pool.select { |v| v.is_a?(String) && !v.start_with?("\u0000") })
        best = nil
        (numeric + strs).each do |v|
          next if strict_eq(v, cur)

          a = with_param(action, params, name, v)
          d = reaches.call(a)
          next if d.nil?

          extra = num?(v) && num?(cur) ? [1, (jsnum(v) - jsnum(cur)).abs / (jsnum(cur).abs + 1)].min : 0.5
          best = { 'repair' => uobj({ 'kind' => 'set_param', 'param' => name, 'from' => cur, 'to' => v }), 'cost' => 2 + extra, 'decision' => d, 'action' => a }
          break # the pool is ordered nearest first
        end
        cands << best unless best.nil?
      end

      # 2b. when no single edit works, the cheapest PAIR of edits
      if !finish && cands.empty?
        dims = []
        param_dim = lambda do |name|
          field = pr['fields'].find { |f| f['path'] == "action.params.#{name}" }
          decl = decl_of(shape, name)
          dv = oget(decl, 'values')
          vals = (field ? field['values'].dup : []) + (dv.equal?(UNDEF) ? [] : listify(dv))
          vals = vals.select { |v| (v.is_a?(String) && !v.start_with?("\u0000")) || num?(v) }
          vals = vals.reject { |v| strict_eq(v, own(params, name)) }
          {
            'cost' => 2,
            'make' => lambda { |a, v|
              pa = jget(a, 'params')
              with_param(a, pa.is_a?(Hash) ? nn(pa, {}) : {}, name, v)
            },
            'step' => ->(v) { uobj({ 'kind' => 'set_param', 'param' => name, 'from' => own(params, name), 'to' => v }) },
            'values' => uniq_vals(vals)[0, 6]
          }
        end
        names.each { |name| dims << param_dim.call(name) }
        ares0 = jget(action, 'resource')
        dims << {
          'cost' => 3, 'make' => ->(a, v) { spread(a).merge('resource' => v) },
          'step' => ->(v) { uobj({ 'kind' => 'set_resource', 'from' => ares0, 'to' => v }) },
          'values' => pr['resources'].reject { |x| x.start_with?("\u0000") || x == ares0 }[0, 6]
        }
        (0...dims.length).each do |i|
          ((i + 1)...dims.length).each do |j|
            dims[i]['values'].each do |x|
              dims[j]['values'].each do |y|
                a = dims[j]['make'].call(dims[i]['make'].call(action, x), y)
                d = reaches.call(a)
                next if d.nil?

                cands << { 'repair' => { 'kind' => 'combine', 'steps' => [dims[i]['step'].call(x), dims[j]['step'].call(y)] },
                           'cost' => dims[i]['cost'] + dims[j]['cost'], 'decision' => d, 'action' => a }
              end
            end
          end
        end
      end

      # 3. another allowed resource
      ares = jget(action, 'resource')
      (finish ? [] : pr['resources'].reject { |x| x.start_with?("\u0000") || x == ares }).each do |r|
        push.call(uobj({ 'kind' => 'set_resource', 'from' => ares, 'to' => r }), 3, spread(action).merge('resource' => r))
      end

      # 4. a named fact that is missing: a subject or env field the policy reads
      (finish ? [] : pr['fields'].select { |x| x['path'].start_with?('subject.') || x['path'].start_with?('env.') }).each do |f|
        segs = f['path'].split('.', -1)
        root = segs[0]
        rest = segs[1..]
        f['values'].reject { |x| x.equal?(ABSENT) }.each do |v|
          cur_root = jget(action, root)
          a = spread(action)
          a[root] = set_path(spread(nn(cur_root, {})), rest, v)
          before = reaches.call(action)
          d = reaches.call(a)
          next unless !d.nil? && before.nil?

          cands << { 'repair' => { 'kind' => 'obtain_fact', 'path' => f['path'], 'value' => v }, 'cost' => 4, 'decision' => d, 'action' => a }
          break
        end
      end

      # 5. split (opt-in, and only when nothing meters the total)
      if jget(o, 'allowSplit') == true && !meters?(model)
        names.each do |name|
          cur = own(params, name)
          next unless num?(cur)

          flipped = cands.find { |c| c['repair']['kind'] == 'set_param' && c['repair']['param'] == name && num?(g(c['repair'], 'to')) }
          part = !flipped.nil? && flipped['repair']['kind'] == 'set_param' ? flipped['repair']['to'] : UNDEF
          next if part.equal?(UNDEF) || part <= 0 || part >= cur

          n = (jsnum(cur) / jsnum(part)).ceil
          next if n > 8

          parts = (0...n).map { |i| { name => i < n - 1 ? part : cur - (part * (n - 1)) } }
          if parts.all? { |p| !reaches.call(spread(action).merge('params' => params.merge(p))).nil? }
            cands << { 'repair' => { 'kind' => 'split', 'param' => name, 'parts' => parts }, 'cost' => 3 + n, 'decision' => want, 'action' => action }
          end
        end
      end

      cands = stable_sort_by(cands) { |c| c['cost'] }
      mc = nn(jget(o, 'maxCandidates'), 8)
      top = cands[0...py_int(mc)]
      res['repairExists'] = !top.empty?
      redact = nn(jget(o, 'redact'), 'critical')

      hide = lambda do |c|
        return c if redact == 'none' || c['repair']['kind'] != 'set_param'

        sens = oget(decl_of(shape, c['repair']['param']), 'sensitivity')
        return c if redact == 'critical' && sens != 'critical'

        res['redacted'] = true
        c.merge('repair' => { 'kind' => 'set_param', 'param' => c['repair']['param'], 'redacted' => true }, 'action' => spread(action))
      end

      if redact == 'all'
        res['redacted'] = true
      else
        res['repairs'] = top.map { |c| hide.call(c) }
      end
      free = top.find { |c| c['decision'] == 'allow' && c['repair']['kind'] != 'split' }
      res['humanFree'] = hide.call(free) if !free.nil? && current == 'escalate'
      if current == 'escalate' || top.empty?
        res['humanAsk'] = uobj({ 'verb' => jget(action, 'verb'), 'resource' => jget(action, 'resource'), 'params' => params.dup,
                                 'kind' => current == 'escalate' ? 'approval' : 'access-request', 'policyDigest' => digest })
      end
      res
    end
  end
end
