# frozen_string_literal: true

require_relative 'goal_js'

module AtlasPca
  # An independent reading of the goal semantics D_G (the TypeScript reference is @atlasauth/pca-goal `refsem`): a second,
  # hand-written implementation used to cross-check a compiled policy. NOT the trusted decision function. Decisions are 0 deny,
  # 1 escalate, 2 allow; condition truth is 0 false, 1 unknown, 2 true.
  module GoalRefsem
    J = GoalJs

    module_function

    def b2t(b) = J.truthy(b) ? 2 : 0

    def same_unit?(a, b)
      return a.equal?(b) if J.undef?(a) || J.undef?(b)

      Js.json(a) == Js.json(b)
    end

    def has?(o, k)
      raise TypeError, 'cannot convert undefined or null to object' if o.nil? || J.undef?(o)

      o.is_a?(Hash) && k.is_a?(String) && o.key?(k)
    end

    def val(t, a, h)
      k = J.jget(t, 'k')
      if k == 'param'
        params = J.jget(a, 'params')
        path = J.jget(t, 'path')
        return has?(params, path) ? params[path] : J::UNDEF
      end
      return J.jget(t, 'v') if k == 'lit'

      aggs = J.jget(h, 'aggs')
      bid = J.jget(t, 'bid')
      has?(aggs, bid) ? { 'k' => 'q', 'q' => aggs[bid] } : J::UNDEF
    end

    def eq(x, y)
      if J.jget(x, 'k') == 'q' && J.jget(y, 'k') == 'q'
        xq = J.jget(x, 'q')
        yq = J.jget(y, 'q')
        return same_unit?(J.jget(xq, 'u'), J.jget(yq, 'u')) ? b2t(J.strict_eq(J.jget(xq, 'n'), J.jget(yq, 'n'))) : 1
      end
      return b2t(J.strict_eq(J.jget(x, 's'), J.jget(y, 's'))) if J.jget(x, 'k') == 's' && J.jget(y, 'k') == 's'

      1
    end

    def lt(x, y)
      if J.jget(x, 'k') == 'q' && J.jget(y, 'k') == 'q' && same_unit?(J.jget(J.jget(x, 'q'), 'u'), J.jget(J.jget(y, 'q'), 'u'))
        return b2t(J.js_lt(J.jget(J.jget(x, 'q'), 'n'), J.jget(J.jget(y, 'q'), 'n')))
      end

      1
    end

    def in_set(x, y)
      return 1 if J.jget(y, 'k') != 'set'

      acc = 0
      J.req_list(J.jget(y, 'items')).each { |it| acc = [acc, eq(x, it)].max }
      acc
    end

    def cmp(op, x, y)
      return 1 if !J.truthy(x) || !J.truthy(y)

      case op
      when 'eq' then eq(x, y)
      when 'ne' then 2 - eq(x, y)
      when 'lt' then lt(x, y)
      when 'gte' then 2 - lt(x, y)
      when 'gt' then lt(y, x)
      when 'lte' then 2 - lt(y, x)
      when 'in' then in_set(x, y)
      else 2 - in_set(x, y)
      end
    end

    def eval_c(c, a, h)
      case J.jget(c, 'k')
      when 'true' then 2
      when 'cmp' then cmp(J.jget(c, 'op'), val(J.jget(c, 'l'), a, h), val(J.jget(c, 'r'), a, h))
      when 'and' then [eval_c(J.jget(c, 'a'), a, h), eval_c(J.jget(c, 'b'), a, h)].min
      when 'or' then [eval_c(J.jget(c, 'a'), a, h), eval_c(J.jget(c, 'b'), a, h)].max
      when 'not' then 2 - eval_c(J.jget(c, 'c'), a, h)
      else raise ArgumentError, 'unknown condition' # the reference yields NaN here; refuse instead
      end
    end

    def res_ok?(s, ont, r)
      case J.jget(s, 'k')
      when 'any' then true
      when 'exact' then J.strict_eq(r, J.jget(s, 'id'))
      when 'oneof' then J.includes(J.jget(s, 'ids'), r)
      when 'related'
        members = []
        J.req_list(J.jget(ont, 'rels')).each do |x|
          next unless J.strict_eq(J.jget(x, 'rel'), J.jget(s, 'rel')) && J.strict_eq(J.jget(x, 'anchor'), J.jget(s, 'anchor'))

          m = J.jget(x, 'members')
          members = m.nil? || J.undef?(m) ? [] : m
          break
        end
        J.includes(members, r)
      when 'all_of' then J.req_list(J.jget(s, 'parts')).all? { |p| res_ok?(p, ont, r) }
      else false
      end
    end

    def verbs_of(ont, cls)
      J.req_list(J.jget(ont, 'verbs')).select { |v| J.strict_eq(J.jget(v, 'cls'), cls) }.map { |v| J.jget(v, 'verb') }
    end

    def in_scope?(sc, a, x)
      case J.jget(sc, 'k')
      when 'session' then J.strict_eq(J.jget(a, 'sess'), J.jget(x, 'sess'))
      when 'principal' then J.strict_eq(J.jget(a, 'prin'), J.jget(x, 'prin'))
      when 'org' then J.strict_eq(J.jget(a, 'org'), J.jget(x, 'org'))
      when 'fleet' then J.includes(J.jget(sc, 'agents'), J.jget(a, 'agent')) && J.includes(J.jget(sc, 'agents'), J.jget(x, 'agent'))
      else false
      end
    end

    def floor(v) = v.finite? ? v.floor : v

    def in_win?(w, a, x)
      case J.jget(w, 'k')
      when 'task', 'lifetime' then true
      when 'sliding'
        at = J.to_number(J.jget(a, 't'))
        xt = J.to_number(J.jget(x, 't'))
        ms = J.to_number(J.jget(w, 'ms'))
        J.js_gt(J.jget(x, 't'), at - ms) && xt <= at
      when 'period'
        ms = J.jget(w, 'ms')
        return false unless J.js_gt(ms, 0)

        m = J.to_number(ms)
        t0 = J.to_number(J.jget(w, 't0'))
        floor((J.to_number(J.jget(a, 't')) - t0) / m) == floor((J.to_number(J.jget(x, 't')) - t0) / m)
      else false
      end
    end

    # JS `+` accumulation from 0: numbers add, anything else concatenates the strings
    def fsum(xs)
      s = 0.0
      xs.each { |x| s = s.is_a?(Float) && Js.num?(x) ? s + Predicates.jsnum(x).to_f : J.js_str(s) + J.js_str(x) }
      s
    end

    def ref_decide(g, ont, a, h) = ref_explain(g, ont, a, h)['d']

    # `{d, witness, prohibit}`: the decision, the first grant (goal order) whose own decision is Allow (null unless d = 2), and the
    # meet over the prohibitions alone (0 one fires, 1 one is unknown, 2 none applies).
    def ref_explain(g, ont, a, h)
      d = 2
      prohibit = 2
      witness = nil
      v = J.jget(g, 'validity')
      t = J.jget(a, 't')
      deleg = J.jget(g, 'deleg')
      last = J.jget(h, 'last')
      depth = J.jget(a, 'depth')
      if J.js_lt(t, J.jget(v, 'notBefore')) || J.js_gt(t, J.jget(v, 'notAfter'))
        d = [d, 0].min
      elsif J.js_gt(J.jget(v, 'maxIdle'), 0) && !J.js_lt(last, 0) && (nl = J.to_number(last)) == nl &&
            J.js_gt(J.to_number(t) - J.to_number(last), J.jget(v, 'maxIdle'))
        d = [d, 0].min
      elsif J.js_lt(depth, 0) || J.js_gt(depth, J.jget(deleg, 'maxDepth'))
        d = [d, 0].min
      end
      J.req_list(J.jget(g, 'prohibits')).each do |p|
        tg = J.jget(p, 'target')
        verbs = J.jget(tg, 'k') == 'verb' ? [J.jget(tg, 'verb')] : verbs_of(ont, J.jget(tg, 'cls'))
        m = [b2t(J.includes(verbs, J.jget(a, 'verb'))), [b2t(res_ok?(J.jget(p, 'res'), ont, J.jget(a, 'res'))), eval_c(J.jget(p, 'cond'), a, h)].min].min
        pd = m == 2 ? 0 : (m == 1 ? 1 : 2)
        d = [d, pd].min
        prohibit = [prohibit, pd].min
      end
      J.req_list(J.jget(g, 'escalateOn')).each { |c| d = [d, eval_c(c, a, h).zero? ? 2 : 1].min }
      best = 0
      J.req_list(J.jget(g, 'grants')).each do |gr|
        verb_ok = J.strict_eq(J.jget(a, 'verb'), J.jget(gr, 'verb')) && (J.strict_eq(depth, 0) || J.includes(J.jget(deleg, 'mayTouch'), J.jget(gr, 'gid')))
        gd = [b2t(verb_ok), [b2t(res_ok?(J.jget(gr, 'res'), ont, J.jget(a, 'res'))), eval_c(J.jget(gr, 'cond'), a, h)].min].min
        J.req_list(J.jget(g, 'bounds')).each do |b|
          gd = [gd, bound_dec(b, gr, g, ont, a, h)].min
        end
        witness = J.jget(gr, 'gid') if gd == 2 && witness.nil?
        best = [best, gd].max
      end
      d = [d, best].min
      { 'd' => d, 'witness' => d == 2 ? witness : nil, 'prohibit' => prohibit }
    end

    # the decision one bound imposes on the candidate under one grant (2 when it does not apply)
    def bound_dec(b, gr, _g, ont, a, h)
      sel = J.jget(b, 'sel')
      gids = J.jget(sel, 'k') == 'gids' ? J.jget(sel, 'gids') : []
      verbs = J.jget(sel, 'k') == 'effect' ? verbs_of(ont, J.jget(sel, 'cls')) : []
      return 2 unless J.includes(gids, J.jget(gr, 'gid')) || J.includes(verbs, J.jget(a, 'verb'))

      items = []
      J.req_list(J.jget(h, 'adms')).each do |x|
        xa = J.jget(x, 'act')
        items << xa if (J.includes(gids, J.jget(x, 'gid')) || J.includes(verbs, J.jget(xa, 'verb'))) && in_scope?(J.jget(b, 'scope'), a, xa) &&
                       in_win?(J.jget(b, 'window'), a, xa)
      end
      items << a
      cap = J.jget(b, 'cap')
      agg = J.jget(b, 'agg')
      ex = if agg == 'count'
             b2t(J.js_gt(items.length, J.jget(cap, 'n')))
           elsif %w[sum max].include?(agg)
             sum_max_ex(b, agg, items, cap, h)
           else
             distinct_ex(b, items, cap)
           end
      ex == 2 ? (J.jget(b, 'onExceed') == 'deny' ? 0 : 1) : (ex == 1 ? 1 : 2)
    end

    def sum_max_ex(b, agg, items, cap, h)
      xs = []
      items.each do |it|
        v = val(J.jget(b, 'value'), it, h)
        return 1 if !J.truthy(v) || J.jget(v, 'k') != 'q' || !same_unit?(J.jget(J.jget(v, 'q'), 'u'), J.jget(cap, 'u'))

        xs << J.jget(J.jget(v, 'q'), 'n')
      end
      return b2t(J.js_gt(fsum(xs), J.jget(cap, 'n'))) if agg == 'sum'
      return 1 if xs.empty?

      ns = xs.map { |x| J.to_number(x) }
      b2t(J.js_gt(ns.any?(&:nan?) ? Float::NAN : ns.max, J.jget(cap, 'n')))
    end

    def distinct_ex(b, items, cap)
      ks = []
      key = J.jget(b, 'key')
      items.each do |it|
        ip = J.jget(it, 'params')
        return 1 unless has?(ip, key)

        ks << Js.json(ip[key])
      end
      b2t(J.js_gt(ks.uniq.length, J.jget(cap, 'n')))
    end
  end
end
