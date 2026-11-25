# frozen_string_literal: true

# Partial evaluation, residual policies, "what may I do?" discovery and data filters (SQL / UCAST). Port of the TypeScript reference
# (@atlasauth/pca-analyzer). Everything here is advisory: the verifier stays authoritative.
require_relative 'analyzer_exposure'

module AtlasPca
  module Analyzer
    UNKNOWN_VERB = "\u0000unknown-verb\u0000"
    UNKNOWN_RESOURCE = "\u0000unknown-resource\u0000"
    COL_RE = /\A[A-Za-z_][A-Za-z0-9_]{0,62}(\.[A-Za-z_][A-Za-z0-9_]{0,62})?\z/
    SQL_OPS = { 'eq' => '=', 'ne' => '<>', 'lt' => '<', 'lte' => '<=', 'gt' => '>', 'gte' => '>=' }.freeze
    INV = { 'eq' => 'ne', 'ne' => 'eq', 'lt' => 'gte', 'lte' => 'gt', 'gt' => 'lte', 'gte' => 'lt' }.freeze

    # An expression the filter cannot express exactly (the caller falls back to per-row authorization).
    class Unsupported < StandardError; end

    module_function

    # A path is symbolic when it is an unknown path, below one, or an ancestor of one.
    def unknown_path?(path, unknown)
      path.is_a?(String) && unknown.any? { |u| path == u || path.start_with?("#{u}.") || u.start_with?("#{path}.") }
    end

    def const_of(v, src) = { 't' => 'const', 'v' => v, 'src' => src }

    def pe(c, ctx, unk)
      return const_of('unknown', c) unless c.is_a?(Hash) || c.is_a?(Array)

      if AtlasPca.group_condition?(c)
        if c.key?('all_of')
          a = c['all_of']
          return const_of('unknown', c) if !a.is_a?(Array) || a.empty?

          rs = a.map { |x| pe(x, ctx, unk) }
          return const_of('false', c) if rs.any? { |r| r['t'] == 'const' && r['v'] == 'false' }

          kept = rs.reject { |r| r['t'] == 'const' && r['v'] == 'true' }
          return const_of('true', c) if kept.empty?
          return const_of('unknown', c) if kept.all? { |r| r['t'] == 'const' }

          cs = kept.map { |r| r['t'] == 'const' ? r['src'] : r['c'] }
          return { 't' => 'cond', 'c' => cs.length == 1 ? cs[0] : { 'all_of' => cs } }
        end
        if c.key?('any_of')
          a = c['any_of']
          return const_of('unknown', c) if !a.is_a?(Array) || a.empty?

          rs = a.map { |x| pe(x, ctx, unk) }
          return const_of('true', c) if rs.any? { |r| r['t'] == 'const' && r['v'] == 'true' }

          kept = rs.reject { |r| r['t'] == 'const' && r['v'] == 'false' }
          return const_of('false', c) if kept.empty?
          return const_of('unknown', c) if kept.all? { |r| r['t'] == 'const' }

          cs = kept.map { |r| r['t'] == 'const' ? r['src'] : r['c'] }
          return { 't' => 'cond', 'c' => cs.length == 1 ? cs[0] : { 'any_of' => cs } }
        end
        r = pe(c['not'], ctx, unk)
        return { 't' => 'cond', 'c' => { 'not' => r['c'] } } if r['t'] == 'cond'

        return const_of(r['v'] == 'true' ? 'false' : (r['v'] == 'false' ? 'true' : 'unknown'), c)
      end
      if AtlasPca.leaf_condition?(c) && (unknown_path?(c['field'], unk) || unknown_path?(c['ref'], unk) || unknown_path?(c['collection'], unk))
        return { 't' => 'cond', 'c' => c }
      end

      const_of(AtlasPca.evaluate_condition_tri(c, ctx), c)
    end

    # AND of a `where` list: ['v', 'true'|'false'|'unknown'] or ['cs', [symbolic conditions]].
    def pe_all(where, ctx, unk)
      return %w[v true] if where.equal?(UNDEF)
      return %w[v unknown] unless where.is_a?(Array)

      rs = where.map { |w| pe(w, ctx, unk) }
      return %w[v false] if rs.any? { |r| r['t'] == 'const' && r['v'] == 'false' }

      kept = rs.reject { |r| r['t'] == 'const' && r['v'] == 'true' }
      return %w[v true] if kept.empty?
      return %w[v unknown] if kept.all? { |r| r['t'] == 'const' }

      ['cs', kept.map { |r| r['t'] == 'const' ? r['src'] : r['c'] }]
    end

    def context_of_known(k)
      verb = jget(k, 'verb')
      resource = jget(k, 'resource')
      params = jget(k, 'params')
      subj = jget(k, 'subject')
      env = jget(k, 'env')
      rc = jget(k, 'reversibilityClass')
      action = {
        'verb' => verb.equal?(UNDEF) || verb.nil? ? UNKNOWN_VERB : verb,
        'resource' => resource.equal?(UNDEF) || resource.nil? ? UNKNOWN_RESOURCE : resource,
        'params' => spread(params.equal?(UNDEF) ? nil : params)
      }
      action['reversibility_class'] = rc unless rc.equal?(UNDEF)
      { 'action' => action, 'subject' => spread(subj.equal?(UNDEF) ? nil : subj), 'env' => spread(env.equal?(UNDEF) ? nil : env) }
    end

    # hashCanonical of the policy a residual was planned against.
    def policy_digest_of(model)
      AtlasPca.hash_canonical({
                                'predicates' => model['predicates'], 'caveats' => model['caveats'], 'vetoes' => model['vetoes'], 'tighten' => model['tighten'],
                                'meet' => model['meets'].map { |m| policy_digest_of(m) }
                              })
    end

    def flatten_model(m)
      out = [m]
      m['meets'].each { |x| out.concat(flatten_model(x)) }
      out
    end

    def pm(pat, ctx) = AtlasPca.predicate_matches(pat, ctx)

    def residual_part(part, ctx, unk, verb_known, res_known)
      predicates = []
      part['predicates'].each do |p|
        next unless p.is_a?(Hash) || p.is_a?(Array)

        pv = jget(p, 'verb')
        pr = jget(p, 'resource')
        next if verb_known && !pm({ 'verb' => pv, 'resource' => '*' }, ctx)
        next if res_known && !pm({ 'verb' => '*', 'resource' => pr }, ctx)

        w = pe_all(jget(p, 'where'), ctx, unk)
        next if w[0] == 'v' && w[1] != 'true' # false and unknown both fail closed for a permit

        item = uobj({ 'verb' => verb_known ? '*' : pv })
        item['resource'] = pr if !res_known && !pr.equal?(UNDEF)
        item['where'] = w[1] if w[0] == 'cs'
        predicates << item
      end
      vetoes = part['vetoes'].map { |v| pe_veto(v, ctx, unk, verb_known, res_known) }.compact
      tighten = []
      part['tighten'].each do |t|
        tw = jget(t, 'when')
        r = pe(tw.equal?(UNDEF) ? nil : tw, ctx, unk)
        next if r['t'] == 'const' && r['v'] == 'false' # a veto-polarity rule that cleanly cannot hold

        nt = spread(t)
        nt['when'] = r['t'] == 'cond' ? r['c'] : tw
        tighten << uobj(nt)
      end
      { 'predicates' => predicates, 'caveats' => part['caveats'], 'vetoes' => vetoes, 'tighten' => tighten }
    end

    def pe_veto(v, ctx, unk, verb_known, res_known)
      whn = jget(v, 'when')
      wv = jget(whn, 'verb')
      return nil if verb_known && !pm({ 'verb' => wv, 'resource' => '*' }, ctx)

      wr = jget(whn, 'resource')
      return nil if res_known && !wr.equal?(UNDEF) && !pm({ 'verb' => '*', 'resource' => wr }, ctx)

      w = pe_all(jget(whn, 'where'), ctx, unk)
      return nil if w[0] == 'v' && w[1] == 'false' # veto polarity: a clean false removes the veto; true and unknown mean it applies

      keep = w[0] == 'cs' ? w[1] : nil
      nw = uobj({ 'verb' => verb_known ? '*' : wv })
      nw['resource'] = wr if !res_known && !wr.equal?(UNDEF)
      nw['where'] = keep unless keep.nil?
      out = uobj({ 'id' => jget(v, 'id'), 'kind' => jget(v, 'kind'), 'when' => nw })
      over = jget(v, 'over')
      if truthy?(over)
        if unknown_path?(jget(over, 'path'), unk)
          out['over'] = over
        else
          r = AtlasPca.resolve_path(ctx, jget(over, 'path'))
          val = r['value']
          is_over = !r['found'] || fin(val).nil? || val.negative? || js_gt(val, jget(over, 'threshold'))
          return nil unless is_over
        end
      end
      unl = jget(v, 'unless')
      if truthy?(unl) && jget(v, 'kind') == 'approval'
        out['unless'] = unl # the evidence of approval: carried, never used to drop the veto
      elsif truthy?(unl)
        u = pe_all(unl, ctx, unk)
        if u[0] == 'cs'
          out['unless'] = u[1]
        elsif u[1] == 'true'
          return nil # the exception certainly holds: the veto never applies
        end
      end
      out
    end

    # Specialise `policy` to `known` ({verb?, resource?, params?, subject?, env?, reversibilityClass?}); everything under
    # `opts.unknown` stays symbolic. Returns {decision: 'never'|'always'|'conditional', reason?, policy, policyDigest}.
    def residual(policy, known, opts = nil)
      opts = {} if opts.nil?
      model = to_model(policy)
      digest = policy_digest_of(model)
      verb_known = !jget(known, 'verb').equal?(UNDEF)
      res_known = !jget(known, 'resource').equal?(UNDEF) && jget(opts, 'resourceUnknown') != true
      unknown = nn(jget(opts, 'unknown'), ['action.params'])
      unk = req_list(unknown).dup + (verb_known ? [] : ['action.verb']) + (res_known ? [] : ['action.resource'])
      ctx = context_of_known(known)
      empty = { 'predicates' => [], 'caveats' => [], 'vetoes' => [], 'tighten' => [] }
      never = ->(reason) { { 'decision' => 'never', 'reason' => reason, 'policy' => empty, 'policyDigest' => digest } }

      return never.call("caveats unsatisfiable: #{model.fetch('caveatReason', 'unknown')}") unless model['caveatSat']

      rc = jget(known, 'reversibilityClass')
      if !rc.equal?(UNDEF) && model.key?('revCap')
        idx = rc.is_a?(String) && AtlasPca::REVERSIBILITY_ORDER.include?(rc) ? AtlasPca::REVERSIBILITY_ORDER.index(rc) : -1
        return never.call('reversibility class exceeds the caveat cap') if idx.negative? || idx > model['revCap']
      end
      parts = flatten_model(model).map { |m| residual_part(m, ctx, unk, verb_known, res_known) }
      own_part = parts[0]
      rest = parts[1..]
      pol = own_part.dup
      pol['meet'] = rest unless rest.empty?
      res = { 'decision' => 'conditional', 'policy' => pol, 'policyDigest' => digest }
      return never.call('no permit survives the known facts') if parts.any? { |p| p['predicates'].empty? }

      parts.each do |p|
        p['vetoes'].each do |v|
          w = v['when']
          if v['kind'] == 'deny' && (!w.key?('resource') || w['resource'] == '*') && (!w.key?('where') || w['where'].empty?) &&
             !v.key?('unless') && !v.key?('over')
            return never.call("veto #{js_str(g(v, 'id'))} applies to every completion")
          end
        end
      end
      if parts.all? { |p| p['predicates'].any? { |x| !x.key?('where') } && p['vetoes'].empty? && p['tighten'].empty? }
        res['decision'] = 'always'
      end
      res
    end

    # The residual as a policy the analyzer and the real evaluator both understand.
    def residual_policy(r)
      pol = jget(r, 'policy')
      own_part = pol.reject { |k, _| k == 'meet' }
      meet = pol['meet']
      own_part['meet'] = meet.map(&:dup) if truthy?(meet)
      own_part
    end

    # Ternary decision of a residual once the unknown fields are bound.
    def evaluate_residual(r, ctx)
      return 'deny' if jget(r, 'decision') == 'never'

      a = jget(ctx, 'action')
      action = uobj({ 'verb' => jget(a, 'verb'), 'resource' => jget(a, 'resource') })
      action['params'] = jget(a, 'params') if truthy?(jget(a, 'params'))
      action['subject'] = jget(ctx, 'subject') if truthy?(jget(ctx, 'subject'))
      action['env'] = jget(ctx, 'env') if truthy?(jget(ctx, 'env'))
      action['reversibilityClass'] = jget(a, 'reversibility_class') if truthy?(jget(a, 'reversibility_class'))
      decide_action(to_model(residual_policy(r)), action)
    end

    # ---- "what may I do?" ---------------------------------------------------------------------------------------------------

    def merge_ranges(rs)
      lo = ->(r) { r.key?('lo') ? jsnum(r['lo']) : -Float::INFINITY }
      cmp = lambda do |a, b|
        d = lo.call(a) == lo.call(b) && lo.call(a).infinite? ? Float::NAN : lo.call(a) - lo.call(b)
        if d.nan? || d.zero? # NaN and 0 are falsy: fall through to the inclusive tie-break
          (truthy?(b['loInclusive']) ? 1 : 0) - (truthy?(a['loInclusive']) ? 1 : 0)
        else
          d
        end
      end
      out = []
      rs.each_with_index.sort { |(a, i), (b, j)| (c = cmp.call(a, b)) == 0 ? i <=> j : (c.positive? ? 1 : -1) }.map(&:first).each do |r|
        last = out[-1]
        rlo = r.key?('lo') ? jsnum(r['lo']) : -Float::INFINITY
        rhi = r.key?('hi') ? jsnum(r['hi']) : Float::INFINITY
        lhi = last.nil? ? nil : (last.key?('hi') ? jsnum(last['hi']) : Float::INFINITY)
        if !last.nil? && lhi >= rlo && !(lhi == rlo && !truthy?(last['hiInclusive']) && !truthy?(r['loInclusive']))
          if rhi > lhi || (rhi == lhi && truthy?(r['hiInclusive']))
            if r.key?('hi')
              last['hi'] = r['hi']
            else
              last.delete('hi')
            end
            if truthy?(r['hiInclusive'])
              last['hiInclusive'] = true
            else
              last.delete('hiInclusive')
            end
          end
        else
          out << r.dup
        end
      end
      out
    end

    def cell_range(value, thr)
      return { 'lo' => value, 'hi' => value, 'loInclusive' => true, 'hiInclusive' => true } if thr.any? { |t| jsnum(t) == jsnum(value) }

      below = thr.reverse.find { |t| t < value } || UNDEF
      above = thr.find { |t| t > value } || UNDEF
      out = {}
      out['lo'] = below unless below.equal?(UNDEF)
      out['hi'] = above unless above.equal?(UNDEF)
      out
    end

    # Per verb shape ({verb, params}): autonomous / approval-only / denied for the known principal, and which parameter values and
    # resources are still allowed. Advisory; sound on the decided fragment, otherwise `approximate`.
    def what_may_i_do(policy, verbs, known = nil, o = nil)
      known = {} if known.nil?
      o = {} if o.nil?
      out = []
      mc = jget(o, 'maxCombinations')
      mx = num?(mc) ? mc : DEFAULT_MAX_COMBINATIONS
      req_list(verbs).each do |shape|
        sverb = jget(shape, 'verb')
        kn = spread(known)
        kn['verb'] = sverb
        res = residual(policy, uobj(kn))
        env = uobj({
                     'verb' => sverb, 'status' => 'denied', 'params' => {}, 'resources' => { 'autonomous' => [], 'withApproval' => [], 'other' => false },
                     'policyDigest' => res['policyDigest'], 'advisory' => true
                   })
        rem = jget(o, 'remaining')
        env['remaining'] = spread(rem) if truthy?(rem)
        md = jget(o, 'missingDischarges')
        env['missingDischarges'] = listify(md) if truthy?(md)
        if res['decision'] == 'never'
          env['reason'] = res['reason'] if res.key?('reason')
          out << env
          next
        end
        rp = to_model(residual_policy(res))
        sparams = jget(shape, 'params')
        raise TypeError, 'Object.entries requires an object' unless sparams.is_a?(Hash)

        names = key_order(sparams)
        extra = []
        names.each do |name|
          d = sparams[name]
          next if jget(d, 'values').equal?(UNDEF)

          extra << { 'path' => "action.params.#{name}", 'cond' => { 'field' => "action.params.#{name}", 'op' => 'in', 'value' => d['values'] } }
        end
        extra_num = []
        names.each do |name|
          d = sparams[name]
          unless jget(d, 'min').equal?(UNDEF)
            extra_num << { 'path' => "action.params.#{name}", 'cond' => { 'field' => "action.params.#{name}", 'op' => 'gte', 'value' => d['min'] } }
          end
          unless jget(d, 'max').equal?(UNDEF)
            extra_num << { 'path' => "action.params.#{name}", 'cond' => { 'field' => "action.params.#{name}", 'op' => 'lte', 'value' => d['max'] } }
          end
        end
        pr = collect_probes({ 'predicateSets' => [probe_set(rp)], 'extraFieldConditions' => extra + extra_num, 'varyReversibility' => rp.key?('revCap') })
        pr['verbs'] = [sverb]
        declared = names
        if product_size(pr) > mx
          env['status'] = 'needs-approval'
          env['approximate'] = true
          env['reason'] = 'representative grid exceeded the bound; no domain is claimed'
          out << env
          next
        end
        kres = jget(known, 'resource')
        pr['resources'] = [kres] unless kres.equal?(UNDEF)
        seen = {}
        res_seen = {}
        any_allow = false
        any_escalate = false
        fresh_res = false
        representatives(pr) do |rep|
          d = decide(rp, rep)
          next if d == 'deny'

          if d == 'allow'
            any_allow = true
          else
            any_escalate = true
          end
          act = rep_to_action(rep)
          params = truthy?(act['params']) ? act['params'] : {}
          declared.each do |name|
            v = params.fetch(name, UNDEF)
            m = (seen[name] ||= {})
            k = v.equal?(UNDEF) ? "\u0000absent" : js_json(v)
            cur = m[k]
            if cur.nil?
              cur = { 'value' => v, 'allow' => false, 'escalate' => false }
              m[k] = cur
            end
            cur[d == 'allow' ? 'allow' : 'escalate'] = true
          end
          rr = (res_seen[act['resource']] ||= { 'allow' => false, 'escalate' => false })
          rr[d == 'allow' ? 'allow' : 'escalate'] = true
          fresh_res = true if act['resource'].start_with?("\u0000")
        end
        env['status'] = any_allow ? 'autonomous' : (any_escalate ? 'needs-approval' : 'denied')
        declared.each do |name|
          decl = sparams[name]
          path = "action.params.#{name}"
          thr = thresholds_of(rp, path)
          vals = (seen[name] || {}).values
          dmin = jget(decl, 'min')
          dmax = jget(decl, 'max')
          nums = vals.select { |x| num?(x['value']) && (dmin.equal?(UNDEF) || x['value'] >= dmin) && (dmax.equal?(UNDEF) || x['value'] <= dmax) }
          strs = vals.select { |x| x['value'].is_a?(String) }
          dvalues = jget(decl, 'values')
          if jget(decl, 'type') == 'integer' || !nums.empty?
            clip = lambda do |r|
              n = r.dup
              if !dmin.equal?(UNDEF) && (!r.key?('lo') || r['lo'] < dmin)
                n['lo'] = dmin
                n['loInclusive'] = true
              end
              if !dmax.equal?(UNDEF) && (!r.key?('hi') || r['hi'] > dmax)
                n['hi'] = dmax
                n['hiInclusive'] = true
              end
              n
            end
            ranges = ->(pick) { merge_ranges(nums.select { |x| pick.call(x) }.map { |x| clip.call(cell_range(x['value'], thr)) }) }
            env['params'][name] = { 'kind' => 'numeric', 'autonomous' => ranges.call(->(x) { x['allow'] }),
                                    'withApproval' => ranges.call(->(x) { x['escalate'] && !x['allow'] }) }
          elsif !dvalues.equal?(UNDEF) || !strs.empty?
            pick_list = ->(f) { strs.select { |x| f.call(x) && !x['value'].start_with?("\u0000") }.map { |x| x['value'] }.sort_by { |s| u16key(s) } }
            fresh = strs.find { |x| x['value'].start_with?("\u0000") }
            env['params'][name] = {
              'kind' => 'enum',
              'autonomous' => pick_list.call(->(x) { x['allow'] }),
              'withApproval' => pick_list.call(->(x) { x['escalate'] && !x['allow'] }),
              'otherAutonomous' => dvalues.equal?(UNDEF) && !fresh.nil? && fresh['allow'] == true,
              'otherWithApproval' => dvalues.equal?(UNDEF) && !fresh.nil? && fresh['escalate'] && !fresh['allow'] ? true : false
            }
          else
            env['params'][name] = { 'kind' => 'unconstrained' }
          end
        end
        rnames = res_seen.reject { |r, _| r.start_with?("\u0000") }
        env['resources'] = {
          'autonomous' => rnames.select { |_, v| v['allow'] }.keys.sort_by { |s| u16key(s) },
          'withApproval' => rnames.select { |_, v| v['escalate'] && !v['allow'] }.keys.sort_by { |s| u16key(s) },
          'other' => fresh_res
        }
        unless rp['undecidable'].empty?
          env['approximate'] = true
          env['reason'] = "over-approximated (#{rp['undecidable'].join('; ')})"
        end
        out << env
      end
      out
    end

    # ---- data filters -------------------------------------------------------------------------------------------------------

    def scalar?(v) = v == true || v == false || v.is_a?(String) || (num?(v) && !fin(v).nil?)

    def col_of(path, cols)
      raise TypeError, 'columns is not an object' unless cols.is_a?(Hash)

      c = path.is_a?(String) && cols.key?(path) ? cols[path] : UNDEF
      raise Unsupported, "field '#{js_str(path)}' has no usable column" if c.equal?(UNDEF) || !c.is_a?(String) || !COL_RE.match?(c)

      c
    end

    def f_and(xs) = xs.empty? ? { 't' => 'true' } : (xs.length == 1 ? xs[0] : { 't' => 'and', 'xs' => xs })
    def f_or(xs) = xs.empty? ? { 't' => 'false' } : (xs.length == 1 ? xs[0] : { 't' => 'or', 'xs' => xs })

    def filter_cond(c, cols)
      raise Unsupported, 'malformed condition' unless c.is_a?(Hash) || c.is_a?(Array)

      if AtlasPca.group_condition?(c)
        return f_and(c['all_of'].map { |x| filter_cond(x, cols) }) if c.key?('all_of') && c['all_of'].is_a?(Array) && !c['all_of'].empty?
        return f_or(c['any_of'].map { |x| filter_cond(x, cols) }) if c.key?('any_of') && c['any_of'].is_a?(Array) && !c['any_of'].empty?
        return { 't' => 'not', 'x' => filter_cond(c['not'], cols) } if c.key?('not')

        raise Unsupported, 'empty condition group'
      end
      raise Unsupported, 'malformed condition' unless AtlasPca.leaf_condition?(c)
      raise Unsupported, 'cross-field ref' if c.key?('ref')

      col = col_of(c['field'], cols)
      v = g(c, 'value')
      op = g(c, 'op')
      if op == 'eq' || op == 'ne'
        raise Unsupported, "#{op} against a non-scalar" unless scalar?(v)

        return { 't' => 'cmp', 'col' => col, 'op' => op, 'v' => v }
      end
      if %w[lt lte gt gte].include?(op)
        raise Unsupported, 'string ordering follows UTF-8 byte order, which SQL collations do not guarantee' if !num?(v) || fin(v).nil?

        return { 't' => 'cmp', 'col' => col, 'op' => op, 'v' => v }
      end
      if op == 'in' || op == 'nin'
        raise Unsupported, "#{op} needs a non-empty list of scalars" if !v.is_a?(Array) || v.empty? || !v.all? { |x| scalar?(x) }

        return { 't' => 'in', 'col' => col, 'vs' => v, 'neg' => op == 'nin' }
      end
      if op == 'prefix'
        raise Unsupported, 'prefix needs a string' unless v.is_a?(String)

        return { 't' => 'prefix', 'col' => col, 'prefix' => v }
      end
      return { 't' => 'null', 'col' => col, 'isNull' => v == false } if op == 'exists'

      raise Unsupported, "operator '#{js_str(op)}' has no exact SQL form"
    end

    def resource_expr(p, cols)
      r = jget(p, 'resource')
      return { 't' => 'true' } if r.equal?(UNDEF) || strict_eq(r, '*')

      col = col_of('action.resource', cols)
      raise TypeError, 'resource.startsWith is not a function' unless r.is_a?(String)
      raise Unsupported, 'regex resource matcher' if r.start_with?('re:')
      return { 't' => 'prefix', 'col' => col, 'prefix' => r[0...-1] } if r.end_with?('*')

      { 't' => 'cmp', 'col' => col, 'op' => 'eq', 'v' => r }
    end

    def veto_expr(v, cols)
      wh = jget(v, 'when')
      xs = []
      xs << { 't' => 'coalesce', 'x' => resource_expr(wh, cols), 'def' => true } unless jget(wh, 'resource').equal?(UNDEF)
      req_list(nn(jget(wh, 'where'), [])).each { |c| xs << { 't' => 'coalesce', 'x' => filter_cond(c, cols), 'def' => true } }
      parts = [f_and(xs)]
      over = jget(v, 'over')
      if truthy?(over)
        col = col_of(jget(over, 'path'), cols)
        parts << f_or([{ 't' => 'null', 'col' => col, 'isNull' => true }, { 't' => 'cmp', 'col' => col, 'op' => 'lt', 'v' => 0 },
                       { 't' => 'cmp', 'col' => col, 'op' => 'gt', 'v' => jget(over, 'threshold') }])
      end
      unl = jget(v, 'unless')
      if jget(v, 'kind') != 'approval' && truthy?(unl) && py_len(unl).positive?
        parts << { 't' => 'not', 'x' => f_and(listify(unl).map { |c| { 't' => 'coalesce', 'x' => filter_cond(c, cols), 'def' => false } }) }
      end
      f_and(parts)
    end

    def part_expr(p, cols, include)
      permits = []
      jget(p, 'predicates').each do |x|
        permits << f_and([resource_expr(x, cols)] + req_list(nn(jget(x, 'where'), [])).map { |c| filter_cond(c, cols) })
      end
      gates = [f_or(permits)]
      jget(p, 'vetoes').each do |v|
        e = veto_expr(v, cols)
        # an approval veto sends the row to a human: it leaves the autonomous set but stays in the admitted set
        gates << { 't' => 'not', 'x' => e } if jget(v, 'kind') == 'deny' || include == 'autonomous'
      end
      if include == 'autonomous'
        jget(p, 'tighten').each { |t| gates << { 't' => 'not', 'x' => { 't' => 'coalesce', 'x' => filter_cond(jget(t, 'when'), cols), 'def' => true } } }
      else
        jget(p, 'tighten').each do |t|
          gates << { 't' => 'not', 'x' => { 't' => 'coalesce', 'x' => filter_cond(jget(t, 'when'), cols), 'def' => true } } if jget(t, 'signal') == 'deny'
        end
      end
      f_and(gates)
    end

    def render_sql(e, dialect, params)
      ph = lambda do |v|
        params << v
        dialect == 'postgres' ? "$#{params.length}" : '?'
      end
      r = nil
      r = lambda do |x|
        case x['t']
        when 'true' then 'TRUE'
        when 'false' then 'FALSE'
        when 'cmp' then "#{x['col']} #{SQL_OPS.fetch(x['op'])} #{ph.call(x['v'])}"
        when 'in' then "#{x['col']} #{x['neg'] ? 'NOT IN' : 'IN'} (#{x['vs'].map { |v| ph.call(v) }.join(', ')})"
        when 'prefix' then "#{x['col']} LIKE #{ph.call("#{x['prefix'].gsub(/[!%_]/) { |m| "!#{m}" }}%")} ESCAPE '!'"
        when 'null' then "#{x['col']} IS #{x['isNull'] ? '' : 'NOT '}NULL"
        when 'and' then "(#{x['xs'].map { |y| r.call(y) }.join(' AND ')})"
        when 'or' then "(#{x['xs'].map { |y| r.call(y) }.join(' OR ')})"
        when 'not' then "NOT (#{r.call(x['x'])})"
        else "COALESCE(#{r.call(x['x'])}, #{x['def'] ? 'TRUE' : 'FALSE'})"
        end
      end
      r.call(e)
    end

    # Compile a residual to a parameterized SQL filter ({ok, expr, sql, params, ucast}), or {ok: false, reason} when it cannot be done
    # exactly (the caller then falls back to per-row authorization).
    def to_filter(res, o)
      if jget(res, 'decision') == 'never'
        return { 'ok' => true, 'expr' => { 't' => 'false' }, 'sql' => 'FALSE', 'params' => [], 'ucast' => to_ucast({ 't' => 'false' }) }
      end

      include = nn(jget(o, 'include'), 'autonomous')
      pol = jget(res, 'policy')
      own_part = pol.reject { |k, _| k == 'meet' }
      meet = pol['meet']
      cols = jget(o, 'columns')
      expr = f_and(([own_part] + nn(meet, []).to_a).map { |p| part_expr(p, cols, include) })
      params = []
      sql = render_sql(expr, nn(jget(o, 'dialect'), 'postgres'), params)
      { 'ok' => true, 'expr' => expr, 'sql' => sql, 'params' => params, 'ucast' => to_ucast(expr) }
    rescue Unsupported => e
      { 'ok' => false, 'reason' => e.message }
    rescue StandardError # any other failure is a compile error, never a looser filter
      { 'ok' => false, 'reason' => 'filter compilation error' }
    end

    def typeof_val(x)
      return 'boolean' if x == true || x == false
      return 'number' if num?(x)
      return 'string' if x.is_a?(String)

      x.equal?(UNDEF) ? 'undefined' : 'object'
    end

    def row_get(row, c) = row.is_a?(Hash) && row.key?(c) ? row[c] : nil

    def kleene(x, row)
      case x['t']
      when 'true' then true
      when 'false' then false
      when 'cmp'
        a = row_get(row, x['col'])
        b = x['v']
        return nil if a.nil? || typeof_val(a) != typeof_val(b)

        op = x['op']
        return strict_eq(a, b) if op == 'eq'
        return !strict_eq(a, b) if op == 'ne'
        return false if typeof_val(a) == 'object'

        a, b = typeof_val(a) == 'number' ? [jsnum(a), jsnum(b)] : [a, b]
        case op
        when 'lt' then a < b
        when 'lte' then a <= b
        when 'gt' then a > b
        else a >= b
        end
      when 'in'
        a = row_get(row, x['col'])
        return nil if a.nil?

        hit = x['vs'].any? { |v| strict_eq(v, a) }
        x['neg'] ? !hit : hit
      when 'prefix'
        a = row_get(row, x['col'])
        a.is_a?(String) ? a.start_with?(x['prefix']) : nil
      when 'null' then row_get(row, x['col']).nil? == x['isNull']
      when 'and'
        unk = false
        x['xs'].each do |y|
          v = kleene(y, row)
          return false if v == false

          unk = true if v.nil?
        end
        unk ? nil : true
      when 'or'
        unk = false
        x['xs'].each do |y|
          v = kleene(y, row)
          return true if v == true

          unk = true if v.nil?
        end
        unk ? nil : false
      when 'not'
        v = kleene(x['x'], row)
        v.nil? ? nil : !v
      else
        v = kleene(x['x'], row)
        v.nil? ? x['def'] : v
      end
    end

    # Evaluate a filter expression over one row with SQL's three-valued (Kleene) logic: true, false or nil (NULL).
    def eval_filter(e, row) = kleene(e, row)

    # ---- UCAST --------------------------------------------------------------------------------------------------------------

    def ucast_empty?(u, op) = u['type'] == 'compound' && u['operator'] == op && u['value'].empty?

    def ucast_join(op, xs)
      other = op == 'and' ? 'or' : 'and'
      flat = []
      xs.each do |x|
        if x['type'] == 'compound' && x['operator'] == op
          flat.concat(x['value'])
        else
          flat << x
        end
      end
      return { 'type' => 'compound', 'operator' => other, 'value' => [] } if flat.any? { |x| ucast_empty?(x, other) }

      kept = flat.reject { |x| ucast_empty?(x, op) }
      return kept[0] if kept.length == 1

      { 'type' => 'compound', 'operator' => op, 'value' => kept }
    end

    def u_and(xs) = ucast_join('and', xs)
    def u_or(xs) = ucast_join('or', xs)
    def u_not(x) = { 'type' => 'compound', 'operator' => 'not', 'value' => [x] }
    def u_field(field, operator, value) = { 'type' => 'field', 'field' => field, 'operator' => operator, 'value' => value }
    def u_not_null(c) = u_field(c, 'ne', nil)

    def ucast_t(x)
      case x['t']
      when 'true' then u_and([])
      when 'false' then u_or([])
      when 'cmp' then x['op'] == 'ne' ? u_and([u_not_null(x['col']), u_field(x['col'], 'ne', x['v'])]) : u_field(x['col'], x['op'], x['v'])
      when 'in' then x['neg'] ? u_and([u_not_null(x['col']), u_field(x['col'], 'nin', x['vs'])]) : u_field(x['col'], 'in', x['vs'])
      when 'prefix' then u_field(x['col'], 'startswith', x['prefix'])
      when 'null' then x['isNull'] ? u_field(x['col'], 'eq', nil) : u_not_null(x['col'])
      when 'and' then u_and(x['xs'].map { |y| ucast_t(y) })
      when 'or' then u_or(x['xs'].map { |y| ucast_t(y) })
      when 'not' then ucast_f(x['x'])
      else x['def'] ? u_not(ucast_f(x['x'])) : ucast_t(x['x'])
      end
    end

    def ucast_f(x)
      case x['t']
      when 'true' then u_or([])
      when 'false' then u_and([])
      when 'cmp' then u_and([u_not_null(x['col']), u_field(x['col'], INV.fetch(x['op']), x['v'])])
      when 'in' then x['neg'] ? u_field(x['col'], 'in', x['vs']) : u_and([u_not_null(x['col']), u_field(x['col'], 'nin', x['vs'])])
      when 'prefix' then u_and([u_not_null(x['col']), u_not(u_field(x['col'], 'startswith', x['prefix']))])
      when 'null' then x['isNull'] ? u_not_null(x['col']) : u_field(x['col'], 'eq', nil)
      when 'and' then u_or(x['xs'].map { |y| ucast_f(y) })
      when 'or' then u_and(x['xs'].map { |y| ucast_f(y) })
      when 'not' then ucast_t(x['x'])
      else x['def'] ? ucast_f(x['x']) : u_not(ucast_t(x['x'])) # coalesce(x, FALSE) is false exactly when x is not definitely true
      end
    end

    # The filter as a UCAST tree whose rows are exactly those the SQL form selects.
    def to_ucast(e) = ucast_t(e)

    # Evaluate a UCAST tree over one row (two-valued; a comparison with NULL is false).
    def eval_ucast(u, row)
      if u['type'] == 'compound'
        return u['value'].all? { |c| eval_ucast(c, row) } if u['operator'] == 'and'
        return u['value'].any? { |c| eval_ucast(c, row) } if u['operator'] == 'or'

        return !eval_ucast(u['value'][0], row)
      end
      a = row_get(row, u['field'])
      v = u['value']
      op = u['operator']
      return a.nil? if op == 'eq' && v.nil?
      return !a.nil? if op == 'ne' && v.nil?
      return false if a.nil?
      return strict_eq(a, v) if op == 'eq'

      if %w[ne lt lte gt gte].include?(op)
        return false if typeof_val(a) != typeof_val(v)
        return !strict_eq(a, v) if op == 'ne'
        return false if typeof_val(a) == 'object'

        x, y = typeof_val(a) == 'number' ? [jsnum(a), jsnum(v)] : [a, v]
        return case op
               when 'lt' then x < y
               when 'lte' then x <= y
               when 'gt' then x > y
               else x >= y
               end
      end
      return v.any? { |e| strict_eq(e, a) } if op == 'in'
      return v.none? { |e| strict_eq(e, a) } if op == 'nin'
      return a.is_a?(String) && a.start_with?(v) if op == 'startswith'

      false
    end
  end
end
