# frozen_string_literal: true

require_relative 'actions'
require_relative 'goal_js'
require_relative 'goal_card'
require_relative 'goal_normalize'
require_relative 'goal_ontologies'
require_relative 'goal_compiler'
require_relative 'actions_builtin'

module AtlasPca
  # Trait selectors and role-addressed parameters for the Goal IR (the TypeScript reference is @atlasauth/pca-goal `selectors`). A
  # selector goal ("SelGoal") names a verb or a trait class in its grants, prohibitions and bounds, and may name a parameter by ROLE;
  # it is lowered against the PINNED catalog to an ordinary goal (one grant per verb). Fail-closed rules: a grant verb with no unique
  # parameter of a named role is dropped from the grant (reported); a prohibition whose role term is unresolved for a verb applies
  # to that verb unconditionally; a bound whose role value cannot be resolved for every selected verb is a type error; an allow
  # selector is positive (no `none_of`, at least one trait); an unconfirmed verb carries `pca.unreviewed`: a class ALLOW never covers
  # it, a class prohibition or bound over a trait selector ALWAYS covers it; an unknown trait id is a type error.
  module GoalSelectors
    J = GoalJs
    UNREVIEWED = 'pca.unreviewed'
    SEL_ID_RE = /\A[0-9A-Za-z_]{1,64}\z/
    ROLE_MARK = "\u0001role:"

    module_function

    # The catalog of a pack of defs (verb ids and parameter paths are the defs' own): {known, verbs}.
    def sel_catalog_of_defs(defs, reg = nil, review = nil)
      reg ||= Actions::CORE_REGISTRY
      verbs = defs.map do |d|
        roles = {}
        d['params'].keys.sort_by { |k| J.u16key(k) }.each do |name|
          r = d['params'][name]['role']
          (roles[r] ||= []) << name unless r.nil?
        end
        { 'verb' => d['verb'], 'traits' => Actions.effective(d, reg, review)['closure'], 'roles' => roles }
      end
      { 'known' => reg.keys.sort_by { |k| J.u16key(k) }, 'verbs' => J.stable_sort_by(verbs) { |v| J.u16key(v['verb']) } }
    end

    # The catalog of one domain (the NL short ids and NL parameter names, with the traits of the defs behind them): the shipped
    # catalog for the core registry with no review, derived from the built-in defs otherwise.
    def sel_catalog_of_domain(domain, reg = nil, review = nil)
      if reg.nil? && review.nil?
        shipped = GoalOntologies.shipped_catalog(domain)
        return shipped unless shipped.nil?
      end
      raise(TypeError, "unknown domain #{domain.inspect}") unless domain.is_a?(String) && ActionsBuiltin::DOMAIN_VERBS.key?(domain)

      reg ||= Actions::CORE_REGISTRY
      roles = ActionsBuiltin.domain_roles(domain)
      verbs = ActionsBuiltin::DOMAIN_VERBS[domain].map do |b|
        d = ActionsBuiltin::CORE_PACK_DEFS.find { |x| x['verb'] == b['verb'] }
        { 'verb' => b['id'], 'traits' => Actions.effective(d, reg, review)['closure'], 'roles' => roles[b['id']] || {} }
      end
      { 'known' => reg.keys.sort_by { |k| J.u16key(k) }, 'verbs' => J.stable_sort_by(verbs) { |v| J.u16key(v['verb']) } }
    end

    # Digest of the catalog (what `SelGoal.catDigest` must equal).
    def sel_catalog_digest(c) = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/goal-sel-catalog/v1', 'catalog' => c })
    def sel_goal_digest(g) = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/goal-ir-sel/v1', 'goal' => g })

    # ---- G-A4: the verbs of a Class selector
    def all?(ts, req) = J.req_list(req).all? { |t| J.includes(ts, t) }
    def none?(ts, ex) = J.req_list(ex).none? { |t| J.includes(ts, t) }

    # The verbs of the catalog, in catalog order, whose trait closure contains every `all_of` trait and none of the `none_of` traits.
    def class_verbs(cat, all_of, none_of)
      J.req_list(J.jget(cat, 'verbs')).select { |v| all?(J.jget(v, 'traits'), all_of) && none?(J.jget(v, 'traits'), none_of) }.map { |v| J.jget(v, 'verb') }
    end

    # The verbs a class ALLOW covers: the class, minus every unconfirmed verb.
    def allow_class_verbs(cat, all_of, none_of) = class_verbs(cat, all_of, J.req_list(none_of) + [UNREVIEWED])

    # The verbs a class PROHIBITION or bound covers: the class, plus every unconfirmed verb whatever the selector says.
    def float_class_verbs(cat, all_of, none_of)
      J.req_list(J.jget(cat, 'verbs')).select do |v|
        J.includes(J.jget(v, 'traits'), UNREVIEWED) || (all?(J.jget(v, 'traits'), all_of) && none?(J.jget(v, 'traits'), none_of))
      end.map { |v| J.jget(v, 'verb') }
    end

    # ---- role resolution
    def decl_of(ont, verb) = J.req_list(J.jget(ont, 'verbs')).find { |v| J.strict_eq(J.jget(v, 'verb'), verb) }
    def info_of(cat, verb) = J.req_list(J.jget(cat, 'verbs')).find { |v| J.strict_eq(J.jget(v, 'verb'), verb) }

    # The one parameter of `verb` carrying `role`, with its declared type; none, several or undeclared: nil.
    def resolve_role(ont, cat, verb, role)
      info = info_of(cat, verb)
      decl = decl_of(ont, verb)
      return nil if info.nil? || decl.nil?

      roles = J.jget(info, 'roles')
      paths = roles.is_a?(Hash) && role.is_a?(String) && roles.key?(role) ? roles[role] : []
      return nil unless paths.length == 1

      p = J.req_list(J.jget(decl, 'params')).find { |x| J.strict_eq(J.jget(x, 'path'), paths[0]) }
      p.nil? ? nil : { 'path' => J.jget(p, 'path'), 'ty' => J.jget(p, 'ty') }
    end

    def resolve_term(ont, cat, verb, t)
      case J.jget(t, 'k')
      when 'param' then { 'k' => 'param', 'path' => J.jget(t, 'path'), 'ty' => J.jget(t, 'ty') }
      when 'lit' then { 'k' => 'lit', 'v' => J.jget(t, 'v') }
      when 'hist' then { 'k' => 'hist', 'bid' => J.jget(t, 'bid'), 'u' => J.jget(t, 'u') }
      when 'role'
        r = resolve_role(ont, cat, verb, J.jget(t, 'role'))
        r ? { 'k' => 'param', 'path' => r['path'], 'ty' => r['ty'] } : nil
      end
    end

    # nil as soon as one role term is unresolved for the verb
    def resolve_cond(ont, cat, verb, c)
      k = J.jget(c, 'k')
      return { 'k' => 'true' } if k == 'true'

      if k == 'cmp'
        l = resolve_term(ont, cat, verb, J.jget(c, 'l'))
        r = resolve_term(ont, cat, verb, J.jget(c, 'r'))
        return l && r ? { 'k' => 'cmp', 'op' => J.jget(c, 'op'), 'l' => l, 'r' => r } : nil
      end
      if %w[and or].include?(k)
        a = resolve_cond(ont, cat, verb, J.jget(c, 'a'))
        b = resolve_cond(ont, cat, verb, J.jget(c, 'b'))
        return a && b ? { 'k' => k, 'a' => a, 'b' => b } : nil
      end
      if k == 'not'
        a = resolve_cond(ont, cat, verb, J.jget(c, 'c'))
        return a ? { 'k' => 'not', 'c' => a } : nil
      end
      nil
    end

    # ---- the expansion
    def grant_verbs(cat, s) = J.jget(s, 'k') == 'verb' ? [J.jget(s, 'verb')] : allow_class_verbs(cat, J.jget(s, 'all_of'), J.jget(s, 'none_of'))

    def expand_grants(ont, cat, gs, report)
      out = []
      J.req_list(gs).each do |gr|
        sel = J.jget(gr, 'sel')
        verbs = grant_verbs(cat, sel)
        dropped = []
        verbs.each do |v|
          c = resolve_cond(ont, cat, v, J.jget(gr, 'cond'))
          if c.nil?
            dropped << { 'verb' => v, 'reason' => 'role_unresolved' }
            next
          end
          out << { 'src' => J.jget(gr, 'gid'),
                   'g' => { 'gid' => J.jget(sel, 'k') == 'class' ? "#{J.js_str(J.jget(gr, 'gid'))}.#{J.js_str(v)}" : J.jget(gr, 'gid'),
                            'verb' => v, 'res' => J.jget(gr, 'res'), 'cond' => c } }
        end
        report['grants'] << { 'gid' => J.jget(gr, 'gid'), 'verbs' => verbs, 'dropped' => dropped }
      end
      out
    end

    def proh_verbs(ont, cat, t)
      case J.jget(t, 'k')
      when 'verb' then [J.jget(t, 'verb')]
      when 'effect'
        J.req_list(J.jget(ont, 'verbs')).select { |v| J.strict_eq(J.jget(v, 'cls'), J.jget(t, 'cls')) }.map { |v| J.jget(v, 'verb') }
      else float_class_verbs(cat, J.jget(t, 'all_of'), J.jget(t, 'none_of'))
      end
    end

    def expand_prohibits(ont, cat, ps, report)
      out = []
      J.req_list(ps).each do |p|
        target = J.jget(p, 'target')
        verbs = proh_verbs(ont, cat, target)
        unconditional = []
        verbs.each do |v|
          c = resolve_cond(ont, cat, v, J.jget(p, 'cond'))
          unconditional << v if c.nil?
          out << { 'pid' => J.jget(target, 'k') == 'verb' ? J.jget(p, 'pid') : "#{J.js_str(J.jget(p, 'pid'))}.#{J.js_str(v)}",
                   'target' => { 'k' => 'verb', 'verb' => v }, 'res' => J.jget(p, 'res'), 'cond' => c.nil? ? { 'k' => 'true' } : c }
        end
        report['prohibits'] << { 'pid' => J.jget(p, 'pid'), 'verbs' => verbs, 'unconditional' => unconditional }
      end
      out
    end

    def ids_of(es, srcs) = es.select { |e| J.includes(srcs, e['src']) }.map { |e| e['g']['gid'] }
    def gids_of_verbs(es, vs) = es.select { |e| J.includes(vs, e['g']['verb']) }.map { |e| e['g']['gid'] }
    def verbs_of_gids(es, gids) = es.select { |e| J.includes(gids, e['g']['gid']) }.map { |e| e['g']['verb'] }

    def bound_role_verbs(ont, cat, es, s)
      case J.jget(s, 'k')
      when 'gids' then verbs_of_gids(es, ids_of(es, J.jget(s, 'gids')))
      when 'effect' then J.req_list(J.jget(ont, 'verbs')).select { |v| J.strict_eq(J.jget(v, 'cls'), J.jget(s, 'cls')) }.map { |v| J.jget(v, 'verb') }
      else verbs_of_gids(es, gids_of_verbs(es, float_class_verbs(cat, J.jget(s, 'all_of'), J.jget(s, 'none_of'))))
      end
    end

    # One value term for the whole bound: the shared path when every verb agrees; the role key `@<role>` when the paths differ but
    # the type is one.
    def bound_value(ont, cat, vs, t)
      case J.jget(t, 'k')
      when 'param' then return { 'term' => { 'k' => 'param', 'path' => J.jget(t, 'path'), 'ty' => J.jget(t, 'ty') }, 'how' => 'literal' }
      when 'lit' then return { 'term' => { 'k' => 'lit', 'v' => J.jget(t, 'v') }, 'how' => 'literal' }
      when 'hist' then return { 'term' => { 'k' => 'hist', 'bid' => J.jget(t, 'bid'), 'u' => J.jget(t, 'u') }, 'how' => 'literal' }
      when 'role'
        rs = []
        vs.each do |v|
          r = resolve_role(ont, cat, v, J.jget(t, 'role'))
          return nil unless r

          rs << r
        end
        return nil if rs.empty?

        same = ->(a, b) { Js.json(a) == Js.json(b) }
        return { 'term' => { 'k' => 'param', 'path' => rs[0]['path'], 'ty' => rs[0]['ty'] }, 'how' => 'shared_path' } if rs.all? { |r| r['path'] == rs[0]['path'] && same.call(r['ty'], rs[0]['ty']) }
        if rs.all? { |r| same.call(r['ty'], rs[0]['ty']) }
          return { 'term' => { 'k' => 'param', 'path' => "@#{J.js_str(J.jget(t, 'role'))}", 'ty' => rs[0]['ty'] }, 'how' => 'role_key' }
        end
      end
      nil
    end

    def expand_bounds(ont, cat, es, bs, report)
      out = []
      J.req_list(bs).each do |b|
        bsel = J.jget(b, 'sel')
        bv = bound_value(ont, cat, bound_role_verbs(ont, cat, es, bsel), J.jget(b, 'value'))
        next if bv.nil? # a type error (sel_reasons), never reached when the goal is well typed

        mk = lambda do |sel|
          { 'bid' => J.jget(b, 'bid'), 'sel' => sel, 'agg' => J.jget(b, 'agg'), 'value' => bv['term'], 'key' => J.jget(b, 'key'), 'window' => J.jget(b, 'window'),
            'scope' => J.jget(b, 'scope'), 'cap' => J.jget(b, 'cap'), 'onExceed' => J.jget(b, 'onExceed') }
        end
        k = J.jget(bsel, 'k')
        gids = nil
        if k == 'gids'
          gids = ids_of(es, J.jget(bsel, 'gids'))
        elsif k == 'trait'
          gids = gids_of_verbs(es, float_class_verbs(cat, J.jget(bsel, 'all_of'), J.jget(bsel, 'none_of')))
        end
        if k == 'effect'
          out << mk.call({ 'k' => 'effect', 'cls' => J.jget(bsel, 'cls') })
          report['bounds'] << { 'bid' => J.jget(b, 'bid'), 'gids' => [], 'dropped' => false, 'value' => bv['how'] }
          next
        end
        if gids.empty?
          report['bounds'] << { 'bid' => J.jget(b, 'bid'), 'gids' => [], 'dropped' => true, 'value' => bv['how'] }
          next
        end
        out << mk.call({ 'k' => 'gids', 'gids' => gids })
        report['bounds'] << { 'bid' => J.jget(b, 'bid'), 'gids' => gids, 'dropped' => false, 'value' => bv['how'] }
      end
      out
    end

    # Lower a selector goal to an ordinary Goal against the PINNED catalog. Pure and total; typing is `sel_reasons` + the core typechecker.
    def expand_sel_goal(sg, ont, cat)
      report = { 'grants' => [], 'prohibits' => [], 'bounds' => [] }
      es = expand_grants(ont, cat, J.jget(sg, 'grants'), report)
      prohibits = expand_prohibits(ont, cat, J.jget(sg, 'prohibits'), report)
      bounds = expand_bounds(ont, cat, es, J.jget(sg, 'bounds'), report)
      deleg = J.jget(sg, 'deleg')
      goal = {
        'v' => 1, 'principal' => J.jget(sg, 'principal'), 'ontDigest' => J.jget(sg, 'ontDigest'), 'nlDigest' => J.jget(sg, 'nlDigest'), 'sources' => J.jget(sg, 'sources'),
        'grants' => es.map { |e| e['g'] }, 'prohibits' => prohibits, 'bounds' => bounds, 'validity' => J.jget(sg, 'validity'),
        'deleg' => deleg.merge('mayTouch' => ids_of(es, J.jget(deleg, 'mayTouch'))), 'escalateOn' => J.jget(sg, 'escalateOn'),
        'wildcardAck' => ids_of(es, J.jget(sg, 'wildcardAck')),
        'holes' => J.req_list(J.jget(sg, 'holes')).map { |h| h.merge('affects' => ids_of(es, J.jget(h, 'affects'))) }
      }
      { 'goal' => goal, 'report' => report }
    end

    # ---- typing of the selector layer
    def all_known?(known, ids) = J.req_list(ids).all? { |i| i.length.positive? && J.includes(known, i) }

    def grant_sel_ok?(cat, g)
      s = J.jget(g, 'sel')
      J.jget(s, 'k') == 'verb' || (J.jget(s, 'all_of').length.positive? && J.jget(s, 'none_of').length.zero? && all_known?(J.jget(cat, 'known'), J.jget(s, 'all_of')))
    end

    def proh_sel_ok?(cat, p)
      t = J.jget(p, 'target')
      J.jget(t, 'k') != 'trait' || (all_known?(J.jget(cat, 'known'), J.jget(t, 'all_of')) && all_known?(J.jget(cat, 'known'), J.jget(t, 'none_of')))
    end

    def bound_sel_ok?(cat, gs, b)
      s = J.jget(b, 'sel')
      case J.jget(s, 'k')
      when 'gids' then J.req_list(J.jget(s, 'gids')).all? { |i| J.req_list(gs).any? { |g| J.strict_eq(J.jget(g, 'gid'), i) } }
      when 'effect' then true
      else all_known?(J.jget(cat, 'known'), J.jget(s, 'all_of')) && all_known?(J.jget(cat, 'known'), J.jget(s, 'none_of'))
      end
    end

    # The type reasons of the selector layer, preceded by the wire checks (`catalog_digest_mismatch`, `bad_id`). [] = well typed at this layer.
    def sel_reasons(sg, ont, cat)
      out = []
      out << 'catalog_digest_mismatch' unless J.strict_eq(J.jget(sg, 'catDigest'), sel_catalog_digest(cat))
      ids = J.req_list(J.jget(sg, 'grants')).map { |g| J.jget(g, 'gid') } + J.req_list(J.jget(sg, 'prohibits')).map { |p| J.jget(p, 'pid') } +
            J.req_list(J.jget(sg, 'bounds')).map { |b| J.jget(b, 'bid') }
      out << 'bad_id' unless ids.all? { |i| SEL_ID_RE.match?(J.js_str(i)) }
      out << 'catalog_mismatch' unless J.req_list(J.jget(cat, 'verbs')).all? { |v| !decl_of(ont, J.jget(v, 'verb')).nil? }
      out << 'bad_grant_selector' unless J.req_list(J.jget(sg, 'grants')).all? { |g| grant_sel_ok?(cat, g) }
      out << 'bad_prohibit_selector' unless J.req_list(J.jget(sg, 'prohibits')).all? { |p| proh_sel_ok?(cat, p) }
      out << 'bad_bound_selector' unless J.req_list(J.jget(sg, 'bounds')).all? { |b| bound_sel_ok?(cat, J.jget(sg, 'grants'), b) }
      es = expand_grants(ont, cat, J.jget(sg, 'grants'), { 'grants' => [], 'prohibits' => [], 'bounds' => [] })
      out << 'unresolved_role_bound' unless J.req_list(J.jget(sg, 'bounds')).all? { |b| !bound_value(ont, cat, bound_role_verbs(ont, cat, es, J.jget(b, 'sel')), J.jget(b, 'value')).nil? }
      out
    end

    # CompileX: selector reasons first (fail closed), then expansion and the core compiler. `compile_goal(goal, ont) ->
    # {ok, policy | reasons}` (default: GoalCompiler.compile_goal).
    def compile_sel_goal(sg, ont, cat, compile_goal = nil)
      rs = sel_reasons(sg, ont, cat)
      return { 'ok' => false, 'reasons' => rs } unless rs.empty?

      x = expand_sel_goal(sg, ont, cat)
      compile_goal ||= GoalCompiler.method(:compile_goal)
      c = compile_goal.call(x['goal'], ont)
      c['ok'] ? { 'ok' => true, 'policy' => c['policy'], 'goal' => x['goal'], 'report' => x['report'] } : { 'ok' => false, 'reasons' => c['reasons'] }
    end

    # ---- acts
    # Add the role keys a role-addressed bound may read: for every role the act's verb carries on exactly one parameter that the act
    # supplies, `@<role>` is that parameter's value. Any `@` key the caller sent is removed first (a caller cannot forge a role value).
    def with_role_params(act, cat)
      params = {}
      J.jget(act, 'params').each { |k, v| params[k] = v unless k.start_with?('@') }
      info = info_of(cat, J.jget(act, 'verb'))
      J.jget(info, 'roles').each { |role, paths| params["@#{role}"] = params[paths[0]] if paths.length == 1 && params.key?(paths[0]) } unless info.nil?
      act.merge('params' => params)
    end

    # ---- the policy card
    def selector_text(all_, none, reg)
      phrase = lambda do |i|
        t = i.is_a?(String) ? reg[i] : nil
        !t.nil? && !t['card_phrase'].nil? ? t['card_phrase'] : J.js_str(i)
      end
      a = all_.length.positive? ? "every action that #{J.req_list(all_).map { |i| phrase.call(i) }.join(' and ')}" : 'every action'
      none.length.positive? ? "#{a}, except those that #{J.req_list(none).map { |i| phrase.call(i) }.join(' or ')}" : a
    end

    # The card of a selector goal: one line per selector clause in the words of the trait phrases (never a model), with the verbs the
    # pinned catalog gives it, then the card of the expansion (the exact clauses that run).
    def render_sel_card(sg, ont, cat, reg = nil)
      reg ||= Actions::CORE_REGISTRY
      x = expand_sel_goal(sg, ont, cat)
      goal = x['goal']
      report = x['report']
      jq = GoalNormalize.method(:jq)
      lines = []
      warnings = []
      J.req_list(J.jget(sg, 'grants')).each_with_index do |g, i|
        r = report['grants'][i]
        s = J.jget(g, 'sel')
        if J.jget(s, 'k') == 'class'
          lines << "ALLOW #{jq.call(J.jget(g, 'gid'))}: #{selector_text(J.jget(s, 'all_of'), [], reg)} [#{r['verbs'].length} verb(s) in the pinned catalog: #{r['verbs'].map { |v| jq.call(v) }.join(', ')}]"
        end
        r['dropped'].each do |d|
          warnings << "grant #{jq.call(J.jget(g, 'gid'))} does not cover #{jq.call(d['verb'])}: it has no unique parameter for a role the condition names"
        end
      end
      J.req_list(J.jget(sg, 'prohibits')).each_with_index do |p, i|
        r = report['prohibits'][i]
        t = J.jget(p, 'target')
        if J.jget(t, 'k') == 'trait'
          lines << "NEVER #{jq.call(J.jget(p, 'pid'))}: #{selector_text(J.jget(t, 'all_of'), J.jget(t, 'none_of'), reg)}, today #{r['verbs'].length} verb(s) " \
                   "[#{r['verbs'].map { |v| jq.call(v) }.join(', ')}]; it also covers every verb added to the catalog later"
        end
        r['unconditional'].each do |v|
          warnings << "prohibition #{jq.call(J.jget(p, 'pid'))} applies to #{jq.call(v)} without its condition: the verb has no unique parameter for a role the condition names"
        end
      end
      J.req_list(J.jget(sg, 'bounds')).each_with_index do |b, i|
        r = i < report['bounds'].length ? report['bounds'][i] : nil
        s = J.jget(b, 'sel')
        if J.jget(s, 'k') == 'trait' && r
          lines << "LIMIT #{jq.call(J.jget(b, 'bid'))}: over #{selector_text(J.jget(s, 'all_of'), J.jget(s, 'none_of'), reg)} (#{r['gids'].length} grant(s))"
        end
        warnings << "limit #{jq.call(J.jget(b, 'bid'))} selects no grant and bounds nothing" if r && r['dropped']
        if r && r['value'] == 'role_key'
          warnings << "limit #{jq.call(J.jget(b, 'bid'))} sums a role the verbs carry on different parameters: the action must supply the role key"
        end
      end
      core = GoalCard.render_card(goal)
      { 'lines' => lines + core['lines'], 'warnings' => warnings + core['warnings'] }
    end

    # The closure of a trait id list under the registry (a selector written with a parent trait covers the children by `implies`).
    def trait_closure(ids, reg = nil) = Actions.closure(reg || Actions::CORE_REGISTRY, ids)

    # ---- the carrier form
    def carry_term(t)
      case J.jget(t, 'k')
      when 'role' then { 'k' => 'param', 'path' => ROLE_MARK + J.jget(t, 'role'), 'ty' => { 'k' => 's' } }
      when 'param' then { 'k' => 'param', 'path' => J.jget(t, 'path'), 'ty' => J.jget(t, 'ty') }
      when 'lit' then { 'k' => 'lit', 'v' => J.jget(t, 'v') }
      else { 'k' => 'hist', 'bid' => J.jget(t, 'bid'), 'u' => J.jget(t, 'u') }
      end
    end

    def carry_cond(c)
      k = J.jget(c, 'k')
      case k
      when 'true' then { 'k' => 'true' }
      when 'cmp' then { 'k' => 'cmp', 'op' => J.jget(c, 'op'), 'l' => carry_term(J.jget(c, 'l')), 'r' => carry_term(J.jget(c, 'r')) }
      when 'and', 'or' then { 'k' => k, 'a' => carry_cond(J.jget(c, 'a')), 'b' => carry_cond(J.jget(c, 'b')) }
      else { 'k' => 'not', 'c' => carry_cond(J.jget(c, 'c')) }
      end
    end

    def sel2(all_, none) = "#{J.req_list(all_).join("\u0002")}\u0001#{J.req_list(none).join("\u0002")}"

    # An ordinary Goal's worth of data carrying a selector goal (selectors ride in strings and role-marked params), so the extracted
    # model decodes it with its existing Goal decoder.
    def sel_carrier(sg)
      grants = J.req_list(J.jget(sg, 'grants')).map do |g|
        s = J.jget(g, 'sel')
        { 'gid' => J.jget(g, 'gid'), 'verb' => J.jget(s, 'k') == 'verb' ? "V\u0001#{J.jget(s, 'verb')}" : "C\u0001#{sel2(J.jget(s, 'all_of'), J.jget(s, 'none_of'))}",
          'res' => J.jget(g, 'res'), 'cond' => carry_cond(J.jget(g, 'cond')) }
      end
      prohibits = J.req_list(J.jget(sg, 'prohibits')).map do |p|
        t = J.jget(p, 'target')
        k = J.jget(t, 'k')
        verb = if k == 'verb' then "V\u0001#{J.jget(t, 'verb')}"
               elsif k == 'effect' then "E\u0001#{J.jget(t, 'cls')}"
               else "T\u0001#{sel2(J.jget(t, 'all_of'), J.jget(t, 'none_of'))}"
               end
        { 'pid' => J.jget(p, 'pid'), 'res' => J.jget(p, 'res'), 'cond' => carry_cond(J.jget(p, 'cond')), 'target' => { 'k' => 'verb', 'verb' => verb } }
      end
      bounds = J.req_list(J.jget(sg, 'bounds')).map do |b|
        s = J.jget(b, 'sel')
        k = J.jget(s, 'k')
        sel = if k == 'gids' then { 'k' => 'gids', 'gids' => J.jget(s, 'gids') }
              elsif k == 'effect' then { 'k' => 'effect', 'cls' => J.jget(s, 'cls') }
              else { 'k' => 'effect', 'cls' => "T\u0001#{sel2(J.jget(s, 'all_of'), J.jget(s, 'none_of'))}" }
              end
        { 'bid' => J.jget(b, 'bid'), 'key' => J.jget(b, 'key'), 'window' => J.jget(b, 'window'), 'scope' => J.jget(b, 'scope'), 'cap' => J.jget(b, 'cap'),
          'onExceed' => J.jget(b, 'onExceed'), 'agg' => J.jget(b, 'agg'), 'value' => carry_term(J.jget(b, 'value')), 'sel' => sel }
      end
      { 'v' => 1, 'principal' => J.jget(sg, 'principal'), 'ontDigest' => J.jget(sg, 'ontDigest'), 'nlDigest' => J.jget(sg, 'nlDigest'), 'sources' => J.jget(sg, 'sources'),
        'grants' => grants, 'prohibits' => prohibits, 'bounds' => bounds, 'validity' => J.jget(sg, 'validity'), 'deleg' => J.jget(sg, 'deleg'),
        'escalateOn' => J.jget(sg, 'escalateOn'), 'wildcardAck' => J.jget(sg, 'wildcardAck'), 'holes' => J.jget(sg, 'holes') }
    end

    # The catalog tape the extracted model reads: known trait ids, then per verb: verb, traits, number of roles, (role, paths)*.
    def encode_sel_catalog(c)
      strs = ->(xs) { [['i', xs.length]] + xs.map { |x| ['s', x] } }
      out = strs.call(J.jget(c, 'known')) + [['i', J.jget(c, 'verbs').length]]
      J.jget(c, 'verbs').each do |v|
        roles = J.jget(v, 'roles').to_a
        out += [['s', J.jget(v, 'verb')]] + strs.call(J.jget(v, 'traits')) + [['i', roles.length]]
        roles.each { |r, ps| out += [['s', r]] + strs.call(ps) }
      end
      out
    end
  end
end
