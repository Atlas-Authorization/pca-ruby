# frozen_string_literal: true

require 'set'
require_relative 'goal_js'
require_relative 'goal_digests'
require_relative 'goal_normalize'
require_relative 'goal_refsem'
require_relative 'goal_sign'

module AtlasPca
  # Boundary examples and signed GoalTests over the Goal IR and its reference semantics (the TypeScript reference is
  # @atlasauth/pca-goal `examples`). An action is classified per coordinate (verb, resource, relation bits, each parameter) against
  # the literals of the policy; `cells` enumerates one representative per decision cell. A Case is {'act', 'rels'}: an action plus
  # the relation facts it is decided under. A Space is {'verbs', 'resources', 'rels', 'q', 'd'} with 'q' param -> unit key -> sorted
  # numbers and 'd' param -> sorted discrete literals.
  module GoalExamples
    J = GoalJs
    MAX_CELLS = 40_000
    OTHER = "\u0000other"
    KIND_W = { 'probe' => 0, 'cap_sequence' => 1, 'allow_witness' => 2, 'prohibit_trigger' => 3, 'member' => 4, 'boundary' => 5 }.freeze

    module_function

    def empty_hist = { 'adms' => [], 'last' => -1, 'aggs' => {} }
    def decision_of(d) = d == 2 ? 'allow' : (d == 1 ? 'escalate' : 'deny')
    def rank_of(d) = d == 'allow' ? 0 : (d == 'escalate' ? 1 : 2)

    # An action with the fixed envelope the examples use (one session, one principal, no delegation, time 0).
    def mk_act(verb, res, params = nil, over = nil)
      { 'verb' => verb, 'res' => res, 'params' => params.nil? ? {} : params, 't' => 0, 'sess' => 's', 'prin' => 'p', 'org' => 'o', 'agent' => 'a',
        'depth' => 0 }.merge(over || {})
    end

    # The reference decision of a goal for {act, hist?, rels?}: {decision, witness, prohibited}.
    def decide_case(g, ont, c)
      rels = J.jget(c, 'rels')
      hist = J.jget(c, 'hist')
      ont2 = J.truthy(rels) ? ont.merge('rels' => rels) : ont
      x = GoalRefsem.ref_explain(g, ont2, J.jget(c, 'act'), hist.nil? || J.undef?(hist) ? empty_hist : hist)
      { 'decision' => decision_of(x['d']), 'witness' => x['witness'], 'prohibited' => x['prohibit'] < 2 }
    end

    # The history of the admitted prefix of `acts` (an action the goal refuses is not recorded).
    def replay(g, ont, acts, rels)
      h = empty_hist
      J.req_list(acts).each do |act|
        v = decide_case(g, ont, { 'act' => act, 'hist' => h, 'rels' => rels })
        next unless v['decision'] == 'allow' && !v['witness'].nil?

        h['adms'] << { 'gid' => v['witness'], 'act' => act }
        h['last'] = J.jget(act, 't')
      end
      h
    end

    def qkey(q)
      u = J.jget(q, 'u')
      J.jget(u, 'k') == 'money' ? "money:#{J.js_str(J.jget(u, 'ccy'))}" : J.js_str(J.jget(u, 'k'))
    end

    def unit_of_key(key) = key.start_with?('money:') ? { 'k' => 'money', 'ccy' => key[6..] } : { 'k' => key }
    def dkey(v) = J.jget(v, 'k') == 's' ? "s:#{J.js_str(J.jget(v, 's'))}" : nil

    def walk_cond(c, &f)
      case J.jget(c, 'k')
      when 'cmp'
        l = J.jget(c, 'l')
        r = J.jget(c, 'r')
        p = J.jget(l, 'k') == 'param' ? J.jget(l, 'path') : (J.jget(r, 'k') == 'param' ? J.jget(r, 'path') : nil)
        other = J.jget(l, 'k') == 'param' ? r : l
        return if p.nil? || J.jget(other, 'k') != 'lit'

        v = J.jget(other, 'v')
        if J.jget(v, 'k') == 'set'
          J.req_list(J.jget(v, 'items')).each { |i| f.call(p, i) }
        else
          f.call(p, v)
        end
      when 'and', 'or'
        walk_cond(J.jget(c, 'a'), &f)
        walk_cond(J.jget(c, 'b'), &f)
      when 'not' then walk_cond(J.jget(c, 'c'), &f)
      end
    end

    def parts_of(s)
      k = J.jget(s, 'k')
      k == 'all_of' ? J.req_list(J.jget(s, 'parts')) : (k == 'any' ? [] : [s])
    end

    def build_space(goals, extra_verbs = nil)
      verbs = {}
      (extra_verbs || []).each { |v| verbs[v] = nil }
      resources = {}
      rels = {}
      q = {}
      d = {}
      lit = lambda do |p, v|
        if J.jget(v, 'k') == 'q'
          (q[p] ||= {})[qkey(J.jget(v, 'q'))] ||= Set.new
          q[p][qkey(J.jget(v, 'q'))] << J.jget(J.jget(v, 'q'), 'n')
        elsif (k = dkey(v))
          (d[p] ||= Set.new) << k
        end
      end
      res = lambda do |s|
        parts_of(s).each do |x|
          case J.jget(x, 'k')
          when 'exact' then resources[J.jget(x, 'id')] = nil
          when 'oneof' then J.req_list(J.jget(x, 'ids')).each { |i| resources[i] = nil }
          else rels["#{J.jget(x, 'rel')}\0#{J.jget(x, 'anchor')}"] = { 'rel' => J.jget(x, 'rel'), 'anchor' => J.jget(x, 'anchor') }
          end
        end
      end
      J.req_list(goals).each do |g|
        J.req_list(J.jget(g, 'grants')).each do |gr|
          verbs[J.jget(gr, 'verb')] = nil
          res.call(J.jget(gr, 'res'))
          walk_cond(J.jget(gr, 'cond'), &lit)
        end
        J.req_list(J.jget(g, 'prohibits')).each do |p|
          t = J.jget(p, 'target')
          verbs[J.jget(t, 'verb')] = nil if J.jget(t, 'k') == 'verb'
          res.call(J.jget(p, 'res'))
          walk_cond(J.jget(p, 'cond'), &lit)
        end
        J.req_list(J.jget(g, 'escalateOn')).each { |c| walk_cond(c, &lit) }
        J.req_list(J.jget(g, 'bounds')).each do |b|
          v = J.jget(b, 'value')
          # reps around the cap so witnesses carry the summed param
          lit.call(J.jget(v, 'path'), { 'k' => 'q', 'q' => J.jget(b, 'cap') }) if J.jget(b, 'agg') == 'sum' && J.jget(v, 'k') == 'param'
        end
      end
      { 'verbs' => verbs.keys.sort_by { |k| J.u16key(k) }, 'resources' => resources.keys.sort_by { |k| J.u16key(k) },
        'rels' => J.stable_sort_by(rels.values) { |x| J.u16key(x['rel'] + x['anchor']) },
        'q' => q.transform_values { |m| m.transform_values { |s| s.to_a.sort } },
        'd' => d.transform_values { |s| s.to_a.sort_by { |k| J.u16key(k) } } }
    end

    def classify_lit(sp, p, l)
      return 'missing' if J.undef?(l) || J.jget(l, 'k') == 'set'

      groups = sp['q'][p]
      ds = sp['d'][p]
      if J.jget(l, 'k') == 'q'
        key = qkey(J.jget(l, 'q'))
        g = groups.nil? ? nil : groups[key]
        return (!groups.nil? || !ds.nil? ? 'unit' : 'any') if g.nil?

        v = J.jget(J.jget(l, 'q'), 'n')
        i = g.index { |x| x == v }
        return "#{key}=#{i}" if i

        pos = 0
        pos += 1 while pos < g.length && g[pos] < v
        return "#{key}@#{pos}" # strictly between literal pos-1 and pos
      end
      k = dkey(l)
      return (groups.nil? ? 'any' : 'unit') if ds.nil?

      ds.include?(k) ? k : 'other'
    end

    def rel_bit(c, rel, anchor)
      J.req_list(J.jget(c, 'rels')).each do |x|
        return J.includes(J.jget(x, 'members'), J.jget(J.jget(c, 'act'), 'res')) ? 1 : 0 if J.strict_eq(J.jget(x, 'rel'), rel) && J.strict_eq(J.jget(x, 'anchor'), anchor)
      end
      0
    end

    def params_of(sp) = (sp['q'].keys + sp['d'].keys).uniq.sort_by { |k| J.u16key(k) }

    # The decision cell of a case under a space (canonical string; the unit of precedents).
    def cell_key(sp, c)
      act = J.jget(c, 'act')
      params = J.jget(act, 'params')
      GoalNormalize.stable({
                             'v' => J.includes(sp['verbs'], J.jget(act, 'verb')) ? J.jget(act, 'verb') : '*',
                             'r' => J.includes(sp['resources'], J.jget(act, 'res')) ? J.jget(act, 'res') : '*',
                             'l' => sp['rels'].map { |x| rel_bit(c, x['rel'], x['anchor']) },
                             'p' => params_of(sp).to_h { |p| [p, classify_lit(sp, p, params.is_a?(Hash) && params.key?(p) ? params[p] : J::UNDEF)] }
                           })
    end

    def param_options(sp, p)
      out = [nil] # nil = the parameter is absent
      seen = Set.new
      add = lambda do |v|
        k = GoalNormalize.stable(v)
        next if seen.include?(k)

        seen << k
        out << v
      end
      (sp['q'][p] || {}).each do |key, vals|
        is_instant = key == 'instant'
        vals.each do |v|
          [v - 1, v, v + 1].each do |x|
            add.call({ 'k' => 'q', 'q' => { 'u' => unit_of_key(key), 'n' => x } }) if x >= 0 || is_instant
          end
        end
        add.call({ 'k' => 'q', 'q' => { 'u' => { 'k' => 'money', 'ccy' => 'ZZZ' }, 'n' => 0 } }) if key.start_with?('money:') # unit mismatch -> Unknown
      end
      (sp['d'][p] || []).each { |k| add.call({ 'k' => 's', 's' => k[2..] }) }
      add.call({ 'k' => 's', 's' => OTHER }) if sp['d'].key?(p)
      out
    end

    # One representative per decision cell. 'complete' is false when the grid exceeded MAX_CELLS (then it is a subset).
    def cells(sp, opts = nil)
      opts ||= {}
      vs = opts['verbs']
      verbs = vs.nil? ? sp['verbs'] + ["\u0000other-verb"] : vs
      resources = sp['resources'] + ["\u0000other-resource"]
      params = params_of(sp)
      p_opts = params.map { |p| param_options(sp, p) }
      rel_bits = sp['rels'].length
      total = verbs.length * resources.length * (2**rel_bits)
      p_opts.each { |o| total *= o.length }
      complete = total <= MAX_CELLS
      out = []
      seen = Set.new
      push = lambda do |c|
        k = cell_key(sp, c)
        unless seen.include?(k)
          seen << k
          out << c
        end
      end
      build = lambda do |verb, resource, bits, choice|
        pr = {}
        params.each_with_index { |p, i| pr[p] = choice[i] unless choice[i].nil? }
        { 'act' => mk_act(verb, resource, pr),
          'rels' => sp['rels'].each_with_index.map { |x, i| { 'rel' => x['rel'], 'anchor' => x['anchor'], 'members' => (bits & (1 << i)).zero? ? [] : [resource] } } }
      end
      if complete
        verbs.each do |verb|
          resources.each do |res|
            (2**rel_bits).times do |bits|
              idx = Array.new(params.length, 0)
              loop do
                push.call(build.call(verb, res, bits, idx.each_with_index.map { |j, i| p_opts[i][j] }))
                k = 0
                while k < idx.length
                  idx[k] += 1
                  break if idx[k] != p_opts[k].length

                  idx[k] = 0
                  k += 1
                end
                break if k == idx.length
              end
            end
          end
        end
      else
        base_choice = -> { p_opts.map { |o| o[[2, o.length - 1].min] } }
        verbs.each do |verb|
          push.call(build.call(verb, resources[0], 0, base_choice.call))
          resources.each do |res|
            (2**rel_bits).times { |bits| push.call(build.call(verb, res, bits, base_choice.call)) }
          end
          p_opts.each_with_index do |o, i|
            o.each do |l|
              ch = base_choice.call
              ch[i] = l
              push.call(build.call(verb, resources[0], 0, ch))
            end
          end
        end
      end
      { 'cases' => out, 'complete' => complete }
    end

    def magnitude(a)
      s = 0
      J.jget(a, 'params').each_value { |v| s += J.jget(v, 'k') == 'q' ? J.jget(J.jget(v, 'q'), 'n').abs : 0 }
      s
    end

    # The smallest-magnitude case the grant admits (a minimal Allow witness), or nil if its Allow set is empty.
    def allow_witness(g, gr, ont)
      sp = build_space([g])
      best = nil
      cells(sp, { 'verbs' => [J.jget(gr, 'verb')] })['cases'].each do |c|
        v = decide_case(g, ont, c)
        best = c if v['decision'] == 'allow' && v['witness'] == J.jget(gr, 'gid') && (best.nil? || magnitude(c['act']) < magnitude(best['act']))
      end
      best
    end

    # Math.floor(a / b) with JavaScript division (x / 0 is +-Infinity, 0 / 0 is NaN).
    def fdiv_floor(a, b)
      if b.zero?
        return a.zero? ? Float::NAN : (a.positive? ? Float::INFINITY : -Float::INFINITY)
      end

      q = a.to_f / b
      q.finite? ? q.floor : q # an overflowing quotient is Infinity, as in JS
    end

    # The full example set: decision-cell representatives, cap sequences and unmentioned-dimension probes.
    def boundary_examples(g, opts)
      ont = opts['ont']
      goals = [g] + (opts['extra'] || [])
      sp = build_space(goals, opts['verbs'] || [])
      c = cells(sp)
      out = []
      add = lambda do |kind, why, cs, hist = nil|
        h = hist.nil? ? empty_hist : hist
        out << { 'id' => "#{kind}:#{AtlasPca.hash_canonical({ 'act' => cs['act'], 'hist' => h, 'rels' => cs['rels'] })[0, 12]}", 'kind' => kind, 'why' => why,
                 'act' => cs['act'], 'hist' => h, 'rels' => cs['rels'],
                 'decision' => decide_case(g, ont, { 'act' => cs['act'], 'hist' => h, 'rels' => cs['rels'] })['decision'] }
      end
      c['cases'].each do |cs|
        v = decide_case(g, ont, cs)
        add.call(v['prohibited'] && v['decision'] == 'deny' ? 'prohibit_trigger' : (v['decision'] == 'allow' ? 'member' : 'boundary'), "cell #{v['decision']}", cs)
      end
      J.req_list(J.jget(g, 'grants')).each do |gr|
        w = allow_witness(g, gr, ont)
        add.call('allow_witness', "minimal Allow witness of grant #{J.js_str(J.jget(gr, 'gid'))}", w) if w
      end
      J.req_list(J.jget(g, 'bounds')).each do |b|
        sel = J.jget(b, 'sel')
        gids = J.jget(sel, 'k') == 'gids' ? J.jget(sel, 'gids') : []
        gr = J.req_list(J.jget(g, 'grants')).find { |x| J.includes(gids, J.jget(x, 'gid')) }
        w = gr.nil? ? nil : allow_witness(g, gr, ont)
        next unless w

        cap_n = J.jget(J.jget(b, 'cap'), 'n')
        if J.jget(b, 'agg') == 'count'
          per = 1
        else
          val = J.jget(b, 'value')
          v = J.jget(val, 'k') == 'param' ? (w['act']['params'].key?(J.jget(val, 'path')) ? w['act']['params'][J.jget(val, 'path')] : J::UNDEF) : J::UNDEF
          per = !J.undef?(v) && J.truthy(v) && J.jget(v, 'k') == 'q' ? J.jget(J.jget(v, 'q'), 'n') : 0
        end
        next if J.jget(b, 'agg') == 'sum' && per <= 0

        n = fdiv_floor(cap_n, per)
        next if n > 60 # sequence too long to review; the aggregate theorem (not examples) covers it

        count = n.is_a?(Integer) || (n.is_a?(Float) && n.finite?) ? n.to_i : 0
        add.call('cap_sequence', "reach the #{J.js_str(J.jget(b, 'bid'))} cap with #{J.js_str(n)} action(s), then one more", w,
                 replay(g, ont, [w['act']] * [count, 0].max, w['rels']))
      end
      J.req_list(J.jget(g, 'grants')).each do |gr| # unmentioned-dimension probes: extreme amount, other resource, other relation anchor
        w = allow_witness(g, gr, ont)
        next unless w

        w['act']['params'].each do |p, l|
          next unless J.jget(l, 'k') == 'q' && J.jget(J.jget(J.jget(l, 'q'), 'u'), 'k') == 'money'

          act = w['act'].merge('params' => w['act']['params'].merge(p => { 'k' => 'q', 'q' => l['q'].merge('n' => 1_000_000_000) }))
          add.call('probe', "extreme #{p}", w.merge('act' => act))
        end
        nothing = w['rels'].map { |r| r.merge('members' => []) }
        add.call('probe', 'other resource', { 'act' => w['act'].merge('res' => "\u0000other-resource"), 'rels' => nothing })
        add.call('probe', 'other customer/anchor', { 'act' => w['act'], 'rels' => nothing })
      end
      seen = Set.new
      res = out.select { |e| seen.add?(e['id']) }
      { 'examples' => res, 'complete' => c['complete'] }
    end

    # Cap examples, riskiest-looking first (Allow of the unmentioned, then Allow, then boundary), stable.
    def review_set(examples, cap)
      J.stable_sort_by(examples) { |e| [rank_of(e['decision']), KIND_W[e['kind']], J.u16key(e['id'])] }.first(cap)
    end

    def expected_decision(a) = a == 'allow' ? 'allow' : (a == 'deny' ? 'deny' : 'escalate')

    # Order-independent digest of a test list.
    def tests_digest(tests)
      AtlasPca.hash_canonical({ 'd' => 'atlas-pca/goal-tests/v1', 'tests' => J.stable_sort_by(tests) { |t| J.u16key(t['id']) } })
    end

    def make_goal_tests(g, confirmed)
      tests = confirmed.map { |c| { 'id' => c['example']['id'], 'act' => c['example']['act'], 'hist' => c['example']['hist'], 'rels' => c['example']['rels'], 'answer' => c['answer'] } }
      { 'goal_digest' => GoalDigests.goal_digest(g), 'ontology_digest' => J.jget(g, 'ontDigest'), 'tests' => tests, 'tests_digest' => tests_digest(tests) }
    end

    def sign_goal_tests(s, secret, alg: nil, pq: nil) = GoalSign.sign_payload('goal-tests', s, secret, alg: alg, pq: pq)

    # Recompile check: any recompile must reproduce every confirmed test or the policy is refused.
    def check_goal_tests(s, pins, decide_fn)
      return { 'ok' => false, 'reason' => 'signature', 'failures' => [] } unless GoalSign.verify_payload(s, 'goal-tests', pins)

      pl = s['payload']
      return { 'ok' => false, 'reason' => 'tests_digest', 'failures' => [] } if tests_digest(pl['tests']) != pl['tests_digest']

      failures = []
      pl['tests'].each do |t|
        got = decide_fn.call(t)
        failures << { 'id' => t['id'], 'expected' => expected_decision(t['answer']), 'got' => got } if got != expected_decision(t['answer'])
      end
      failures.empty? ? { 'ok' => true, 'failures' => failures } : { 'ok' => false, 'reason' => 'test_regression', 'failures' => failures }
    end

    # The pin: the policy version cannot silently change under a signed test set.
    def sign_pin(p, secret, alg: nil, pq: nil) = GoalSign.sign_payload('policy-pin', p, secret, alg: alg, pq: pq)

    def check_pin(pin, pins, cur)
      return { 'ok' => false, 'reason' => 'signature' } unless GoalSign.verify_payload(pin, 'policy-pin', pins)

      p = pin['payload']
      goal = J.jget(cur, 'goal')
      tests = J.jget(cur, 'tests')
      return { 'ok' => false, 'reason' => 'goal changed under the pin' } if p['goal_digest'] != GoalDigests.goal_digest(goal)
      return { 'ok' => false, 'reason' => 'policy changed under the pin' } if p['policy_digest'] != J.jget(cur, 'policy_digest')
      if p['tests_digest'] != J.jget(tests, 'tests_digest') || p['tests_digest'] != tests_digest(J.jget(tests, 'tests'))
        return { 'ok' => false, 'reason' => 'tests changed under the pin' }
      end
      return { 'ok' => false, 'reason' => 'ontology changed under the pin' } if p['ontology_digest'] != J.jget(goal, 'ontDigest')

      { 'ok' => true }
    end
  end
end
