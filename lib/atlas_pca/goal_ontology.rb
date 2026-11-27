# frozen_string_literal: true

require_relative 'goal_js'
require_relative 'goal_codec'
require_relative 'goal_digests'
require_relative 'goal_examples'
require_relative 'goal_normalize'
require_relative 'goal_sign'

module AtlasPca
  # The intent-fidelity ontology: the signed authoring vocabulary (aliases, templates, units), its projection onto the IR
  # ontology, its well-formedness checker, template instantiation, slot typing and locale-aware amount parsing (the TypeScript
  # reference is @atlasauth/pca-goal `ontology`). Ontologies, goals and slot values are the parsed-JSON trees of the reference.
  module GoalOntology
    J = GoalJs
    UNDEF = GoalJs::UNDEF
    EFFECT_CLASSES = %w[read reversible external_send irreversible].freeze
    INVIS_RE = /[​-‏⁠﻿]/
    FOREVER = 9_007_199_254_740_991
    ID_RE = /\A[A-Za-z0-9_-]+\z/
    NUM_RE = /\A[0-9][0-9.,]*\z/
    WS_CLASS = "\t\n\v\f\r    -     　﻿"

    # A JavaScript Set over JSON values: objects and arrays by identity, everything else by value.
    class JsSet
      def initialize(items = [])
        @s = {}
        items.each { |i| add(i) }
      end

      def add(x) = @s[key(x)] = true
      def include?(x) = @s.key?(key(x))
      def length = @s.length

      private

      def key(x) = x.is_a?(Hash) || x.is_a?(Array) ? [:obj, x.object_id] : (x.is_a?(Float) && x.finite? && x == x.floor && x.abs < 2**53 ? x.to_i : x)
    end

    module_function

    def ontology_digest(o) = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/goal-intent-ontology/v1', 'ontology' => o })
    def sign_ontology(o, secret, alg: nil, pq: nil) = GoalSign.sign_payload('ontology', o, secret, alg: alg, pq: pq)
    def verify_ontology(s, pins) = GoalSign.verify_payload(s, 'ontology', pins)

    def norm(s) = s.unicode_normalize(:nfkc).downcase.gsub(INVIS_RE, '')

    # Object.entries(o): a Hash's members in JavaScript key order; null throws; other primitives have none.
    def entries(o)
      raise TypeError, 'cannot convert undefined or null to object' if o.nil? || J.undef?(o)

      case o
      when Hash then Js.js_keys(o).map { |k| [k, o[k]] }
      when Array then o.each_with_index.map { |x, i| [i.to_s, x] }
      when String then Predicates.units(o).each_with_index.map { |c, i| [i.to_s, [c].pack('U')] }
      else []
      end
    end

    # `for (const e of x)`: an array's elements or a string's code points; anything else throws.
    def iter(x)
      return x.dup if x.is_a?(Array)
      return x.chars if x.is_a?(String)

      raise TypeError, 'not iterable'
    end

    def values(o) = entries(o).map { |_, v| v }

    def find(xs, &pred)
      J.req_list(xs).each { |x| return x if J.truthy(pred.call(x)) }
      UNDEF
    end

    # o[k] for an own member of a plain object, else undefined (the reference reads a null object and throws).
    def own(o, k)
      raise TypeError, 'cannot read properties of null' if o.nil? || J.undef?(o)

      o.is_a?(Hash) && k.is_a?(String) && o.key?(k) ? o[k] : UNDEF
    end

    def len_pos?(x) = (x.is_a?(Array) || x.is_a?(String)) && !x.empty?
    def integer?(x) = Js.num?(x) && (x.is_a?(Integer) || (x.finite? && x == x.floor))

    # The canonical verb id of an id or declared alias; case and homoglyph variants are NOT guessed.
    def resolve_verb(o, word)
      raise TypeError, 'word.trim is not a function' unless word.is_a?(String)

      w = Js.trim(word)
      return w if J.req_list(J.jget(o, 'verbs')).any? { |v| J.strict_eq(J.jget(v, 'id'), w) }

      hit = own(J.jget(o, 'aliases'), w)
      J.undef?(hit) ? nil : hit
    end

    # The currency a goal is written in: the first money quantity in its conditions or bound caps (nil without money).
    def goal_ccy(g)
      found = [UNDEF]
      t = lambda do |x|
        next unless J.jget(x, 'k') == 'lit'

        v = J.jget(x, 'v')
        (J.jget(v, 'k') == 'set' ? J.req_list(J.jget(v, 'items')) : [v]).each do |i|
          found[0] = J.jget(J.jget(J.jget(i, 'q'), 'u'), 'ccy') if J.undef?(found[0]) && J.jget(i, 'k') == 'q' && J.jget(J.jget(J.jget(i, 'q'), 'u'), 'k') == 'money'
        end
      end
      c = lambda do |x|
        case J.jget(x, 'k')
        when 'cmp'
          t.call(J.jget(x, 'l'))
          t.call(J.jget(x, 'r'))
        when 'and', 'or'
          c.call(J.jget(x, 'a'))
          c.call(J.jget(x, 'b'))
        when 'not' then c.call(J.jget(x, 'c'))
        end
      end
      J.req_list(J.jget(g, 'grants')).each { |gr| c.call(J.jget(gr, 'cond')) }
      J.req_list(J.jget(g, 'prohibits')).each { |p| c.call(J.jget(p, 'cond')) }
      J.req_list(J.jget(g, 'escalateOn')).each { |x| c.call(x) }
      J.req_list(J.jget(g, 'bounds')).each do |b|
        cap = J.jget(b, 'cap')
        found[0] = J.jget(J.jget(cap, 'u'), 'ccy') if J.undef?(found[0]) && J.jget(J.jget(cap, 'u'), 'k') == 'money'
      end
      J.undef?(found[0]) ? nil : found[0]
    end

    def param_ty(p, ccy)
      kind = J.jget(p, 'kind')
      return { 'k' => 's' } if %w[id enum text].include?(kind)

      if kind == 'money'
        ccys = J.jget(p, 'ccys')
        c = if !ccy.nil? && !J.undef?(ccy) && !J.undef?(ccys) && J.includes(ccys, ccy)
              ccy
            elsif !J.undef?(ccys) && J.includes(ccys, 'USD')
              'USD'
            else
              J.req_list(ccys).empty? ? UNDEF : J.req_list(ccys)[0]
            end
        return { 'k' => 'q', 'u' => { 'k' => 'money', 'ccy' => c } }
      end
      { 'k' => 'q', 'u' => { 'k' => kind } }
    end

    # T1's `Ontology` (verbs with effect class and typed parameters, relation tables) for an intent ontology. `opts`: {ccy?, rels?}.
    def to_ir_ontology(o, opts = nil)
      opts ||= {}
      verbs = J.req_list(J.jget(o, 'verbs')).map do |v|
        params = J.jget(v, 'params')
        { 'verb' => J.jget(v, 'id'), 'cls' => J.jget(v, 'effect'),
          'params' => entries(params).map(&:first).sort_by { |k| J.u16key(k) }.map { |path| { 'path' => path, 'ty' => param_ty(own(params, path), opts['ccy']) } } }
      end
      rels = opts['rels']
      { 'verbs' => verbs, 'rels' => rels.nil? ? [] : rels }
    end

    # The IR ontology a goal is typed and decided against: money parameters in the goal's own currency.
    def ontology_for_goal(o, g, rels = nil)
      ccy = goal_ccy(g)
      opts = { 'rels' => rels.nil? ? [] : rels }
      opts['ccy'] = ccy unless ccy.nil?
      to_ir_ontology(o, opts)
    end

    # Relation anchors a goal mentions, declared with no members (typing needs them; facts come per case).
    def goal_anchors(g)
      out = {}
      sel = lambda do |s|
        case J.jget(s, 'k')
        when 'related' then out["#{J.jget(s, 'rel')}\0#{J.jget(s, 'anchor')}"] = { 'rel' => J.jget(s, 'rel'), 'anchor' => J.jget(s, 'anchor'), 'members' => [] }
        when 'all_of' then J.req_list(J.jget(s, 'parts')).each { |p| sel.call(p) }
        end
      end
      J.req_list(J.jget(g, 'grants')).each { |gr| sel.call(J.jget(gr, 'res')) }
      J.req_list(J.jget(g, 'prohibits')).each { |p| sel.call(J.jget(p, 'res')) }
      J.stable_sort_by(out.values) { |x| J.u16key("#{x['rel']}\0#{x['anchor']}") }
    end

    def refs_res(s)
      d = ->(x) { x.start_with?('$') ? [x[1..]] : [] }
      case J.jget(s, 'k')
      when 'exact' then d.call(J.jget(s, 'id'))
      when 'oneof' then J.req_list(J.jget(s, 'ids')).flat_map { |i| d.call(i) }
      when 'related' then d.call(J.jget(s, 'anchor'))
      when 'all_of' then J.req_list(J.jget(s, 'parts')).flat_map { |p| refs_res(p) }
      else []
      end
    end

    def refs_term(x) = J.jget(x, 'k') == 'slot' ? [J.jget(x, 'slot')] : []

    def refs_cond(c)
      case J.jget(c, 'k')
      when 'cmp' then refs_term(J.jget(c, 'l')) + refs_term(J.jget(c, 'r'))
      when 'and', 'or' then refs_cond(J.jget(c, 'a')) + refs_cond(J.jget(c, 'b'))
      when 'not' then refs_cond(J.jget(c, 'c'))
      else []
      end
    end

    def refs_grant(g) = refs_res(J.jget(g, 'res')) + refs_cond(J.jget(g, 'cond'))
    def refs_bound(b) = J.truthy(J.jget(b, 'cap_slot')) ? [J.jget(b, 'cap_slot')] : []

    def slot_refs(t)
      J.req_list(J.jget(t, 'grants')).flat_map { |g| refs_grant(g) } + J.req_list(J.jget(t, 'prohibits')).flat_map { |p| refs_grant(p) } +
        J.req_list(J.jget(t, 'bounds')).flat_map { |b| refs_bound(b) }
    end

    # Well-formedness checker: every defect as {code, where, msg}; an empty list means well formed.
    def check_ontology(o)
      issues = []
      bad = lambda do |code, where, msg|
        issues << { 'code' => code, 'where' => where, 'msg' => msg }.reject { |_, v| J.undef?(v) }
      end
      type_ids = JsSet.new
      prefixes = JsSet.new
      iter(J.jget(o, 'types')).each do |t|
        tid = J.jget(t, 'id')
        bad.call('dup_type', tid, 'duplicate type id') if type_ids.include?(tid)
        type_ids.add(tid)
        pre = J.jget(t, 'id_prefix')
        bad.call('dup_prefix', tid, 'id prefix empty or reused') if !J.truthy(pre) || prefixes.include?(pre)
        prefixes.add(pre)
      end
      units = J.jget(o, 'units')
      entries(units).each do |u, d|
        exp = J.jget(d, 'exponent')
        bad.call('unit_exponent', u, 'money unit needs an integer exponent 0..4') if J.jget(d, 'kind') == 'money' && !(integer?(exp) && exp >= 0 && exp <= 4)
        bad.call('unit_exponent', u, 'only money units carry an exponent') if J.jget(d, 'kind') != 'money' && !J.undef?(exp)
      end
      rel_ids = JsSet.new
      iter(J.jget(o, 'relations')).each do |r|
        rid = J.jget(r, 'id')
        bad.call('dup_relation', rid, 'duplicate relation') if rel_ids.include?(rid)
        rel_ids.add(rid)
        bad.call('relation_type', rid, 'relation endpoint type is not declared') if !type_ids.include?(J.jget(r, 'from')) || !type_ids.include?(J.jget(r, 'to'))
      end
      verb_ids = JsSet.new
      verbs = {}
      iter(J.jget(o, 'verbs')).each do |v|
        vid = J.jget(v, 'id')
        bad.call('dup_verb', vid, 'duplicate verb') if verb_ids.include?(vid)
        verb_ids.add(vid)
        verbs[hk(vid)] = v
        bad.call('no_effect_class', vid, 'verb has no valid effect class') unless J.includes(EFFECT_CLASSES, J.jget(v, 'effect'))
        bad.call('verb_resource_type', vid, 'resource type is not declared') unless type_ids.include?(J.jget(v, 'resource_type'))
        entries(J.jget(v, 'params')).each do |p, pt|
          kind = J.jget(pt, 'kind')
          w = "#{J.js_str(vid)}.#{p}"
          if kind == 'money'
            ccys = J.jget(pt, 'ccys')
            bad.call('param_ccy', w, 'money parameter lists no currency') unless len_pos?(ccys)
            (ccys.nil? || J.undef?(ccys) ? [] : iter(ccys)).each do |c|
              bad.call('unit_unknown', w, "currency #{J.js_str(c)} is not a declared money unit") if J.oget(c.is_a?(String) ? own(units, c) : UNDEF, 'kind') != 'money'
            end
          elsif kind == 'enum'
            bad.call('param_enum', w, 'enum parameter has no values') unless len_pos?(J.jget(pt, 'values'))
          elsif kind == 'id'
            of = J.jget(pt, 'of')
            bad.call('param_type', w, 'id parameter type is not declared') if !J.truthy(of) || !type_ids.include?(of)
          elsif kind != 'text'
            bad.call('unit_unknown', w, "no declared unit of kind #{J.js_str(kind)}") unless values(units).any? { |u| J.strict_eq(J.jget(u, 'kind'), kind) }
          end
        end
      end
      seen = {}
      aliases = J.jget(o, 'aliases')
      entries(aliases).each do |k, target|
        bad.call('alias_key', k, 'alias key is not in normalized form') if k != norm(k) || (k.match?(/[^\x20-\x7e]/) && k != k.unicode_normalize(:nfkc))
        bad.call('alias_key', k, 'alias key contains invisible characters') if INVIS_RE.match?(k)
        n = norm(k)
        bad.call('alias_collision', k, "collides with #{seen[n]} after normalization") if seen.key?(n) && seen[n] != k
        seen[n] = k
        bad.call('alias_target', k, 'alias target is not a canonical verb') unless verb_ids.include?(target)
        bad.call('alias_chain', k, 'alias target is itself an alias (chain or cycle)') if target.is_a?(String) && aliases.is_a?(Hash) && aliases.key?(target)
        bad.call('alias_shadow', k, 'alias shadows a canonical verb') if verb_ids.include?(k) && k != target
      end
      tids = JsSet.new
      J.req_list(J.jget(o, 'templates')).each do |t|
        tid = J.jget(t, 'id')
        w = "template:#{J.js_str(tid)}"
        bad.call('dup_template', w, 'duplicate template id') if tids.include?(tid)
        tids.add(tid)
        slots = J.req_list(J.jget(t, 'slots'))
        slot_names = JsSet.new(slots.map { |s| J.jget(s, 'name') })
        bad.call('dup_slot', w, 'duplicate slot') if slot_names.length != slots.length
        slot_refs(t).each { |r| bad.call('slot_undeclared', w, "slot #{J.js_str(r)} is used but not declared") unless slot_names.include?(r) }
        slots.each do |s|
          sw = "#{w}.#{J.js_str(J.jget(s, 'name'))}"
          sk = J.jget(s, 'kind')
          if %w[id id_list].include?(sk)
            of = J.jget(s, 'of')
            bad.call('slot_type', sw, 'id slot type is not declared') if !J.truthy(of) || !type_ids.include?(of)
          end
          if sk == 'money'
            ccy = J.jget(s, 'ccy')
            u = J.undef?(ccy) || ccy.is_a?(String) ? own(units, J.undef?(ccy) ? '' : ccy) : UNDEF
            bad.call('slot_ccy', sw, 'money slot currency is not a declared unit') if J.oget(u, 'kind') != 'money'
          end
          bad.call('slot_enum', sw, 'enum slot has no values') if %w[enum enum_list].include?(sk) && !len_pos?(J.jget(s, 'values'))
          bad.call('slot_default', sw, 'optional slot needs a default (an unfilled slot must be a hole or a default)') if !J.truthy(J.jget(s, 'mandatory')) && J.undef?(J.jget(s, 'default'))
          bad.call('slot_unused', sw, 'declared slot is never used') unless slot_refs(t).include?(J.jget(s, 'name'))
        end
        tgrants = J.req_list(J.jget(t, 'grants'))
        tbounds = J.req_list(J.jget(t, 'bounds'))
        bad.call('empty_allow', w, 'template has no grant (empty Allow set)') if tgrants.empty?
        gids = JsSet.new(tgrants.map { |g| J.jget(g, 'gid') })
        bad.call('dup_gid', w, 'duplicate grant id') if gids.length != tgrants.length
        tgrants.each do |g|
          v = verbs[hk(J.jget(g, 'verb'))]
          gw = "#{w}.#{J.js_str(J.jget(g, 'gid'))}"
          if v.nil?
            bad.call('grant_verb', gw, 'grant verb is not in the ontology')
            next
          end
          check_resource(o, J.jget(g, 'res'), v, gw, bad)
          check_cond(J.jget(g, 'cond'), v, t, gw, bad)
          res = J.jget(g, 'res')
          bad.call('unbounded', gw, 'wildcard resource in a template') if J.jget(res, 'k') == 'any' && !(J.jget(v, 'effect') == 'read' && tbounds.length.positive?)
          bad.call('unbounded', gw, 'non-read grant on a related set needs an aggregate bound') if J.jget(v, 'effect') != 'read' && J.jget(res, 'k') == 'related' && tbounds.empty?
        end
        J.req_list(J.jget(t, 'prohibits')).each do |p|
          tg = J.jget(p, 'target')
          pw = "#{w}.#{J.js_str(J.jget(p, 'pid'))}"
          bad.call('prohibit_verb', pw, 'prohibit verb is not in the ontology') if J.jget(tg, 'k') == 'verb' && !verbs.key?(hk(J.jget(tg, 'verb')))
          bad.call('prohibit_effect', pw, 'unknown effect class') if J.jget(tg, 'k') == 'effect' && !J.includes(EFFECT_CLASSES, J.jget(tg, 'cls'))
        end
        tbounds.each do |b|
          bw = "#{w}.#{J.js_str(J.jget(b, 'bid'))}"
          over = J.jget(b, 'over')
          bad.call('bound_over', bw, 'bound selects an unknown grant') if !J.strict_eq(over, 'all') && J.req_list(over).any? { |x| !gids.include?(x) }
          cs_name = J.jget(b, 'cap_slot')
          bad.call('slot_undeclared', w, "cap slot #{J.js_str(cs_name)} is not declared") if J.truthy(cs_name) && !slot_names.include?(cs_name)
          if J.truthy(cs_name)
            cs = find(slots) { |x| J.strict_eq(J.jget(x, 'name'), cs_name) }
            unless J.undef?(cs)
              csk = J.jget(cs, 'kind')
              agg = J.jget(b, 'agg')
              bad.call('bound_cap', bw, 'cap slot must be money or count') unless %w[money count].include?(csk)
              bad.call('bound_cap', bw, 'count bound needs a count slot') if agg == 'count' && csk != 'count'
              bad.call('bound_cap', bw, 'sum bound over money needs a money slot') if agg == 'sum' && csk != 'money'
            end
          end
          bad.call('bound_value', bw, 'sum bound has no value parameter') if J.jget(b, 'agg') == 'sum' && !J.truthy(J.jget(b, 'param'))
        end
        # non-empty and bounded after instantiation with the declared example
        g = instantiate_template(o, tid, J.jget(t, 'example'), { 'principal' => 'p', 'nl' => '' })
        if g['holes'].length.positive?
          bad.call('example_holes', w, "example leaves holes: #{g['holes'].map { |h| h['hid'] }.join(',')}")
        elsif g['grants'].length != tgrants.length
          bad.call('empty_allow', w, 'example instantiation dropped a grant')
        elsif !allow_witness?(o, g)
          bad.call('empty_allow', w, 'instantiated template has an empty Allow set')
        end
      end
      issues
    end

    # a hashable key with JavaScript Map semantics for the verb table
    def hk(x) = x.is_a?(Hash) || x.is_a?(Array) ? [:obj, x.object_id] : x

    def check_resource(o, s, v, w, bad)
      rt = J.jget(v, 'resource_type')
      ty = find(J.jget(o, 'types')) { |t| J.strict_eq(J.jget(t, 'id'), rt) }
      prefix = J.oget(ty, 'id_prefix')
      id_ok = ->(i, pre) { i.start_with?('$') || (!J.undef?(pre) && i.start_with?(pre)) }
      case J.jget(s, 'k')
      when 'exact'
        bad.call('resource_type', w, 'exact resource id has the wrong type prefix') unless id_ok.call(J.jget(s, 'id'), prefix)
      when 'oneof'
        ids = J.req_list(J.jget(s, 'ids'))
        bad.call('resource_empty', w, 'one_of is empty') if ids.empty?
        ids.each { |i| bad.call('resource_type', w, 'one_of member has the wrong type prefix') unless id_ok.call(i, prefix) }
      when 'related'
        rel = J.jget(s, 'rel')
        r = find(J.jget(o, 'relations')) { |x| J.strict_eq(J.jget(x, 'id'), rel) }
        if J.undef?(r)
          bad.call('relation_unknown', w, "relation #{J.js_str(rel)} is not declared")
        else
          bad.call('relation_type', w, 'relation target type differs from the verb resource type') if J.jget(r, 'to') != rt
          rf = J.jget(r, 'from')
          anchor_pre = J.oget(find(J.jget(o, 'types')) { |t| J.strict_eq(J.jget(t, 'id'), rf) }, 'id_prefix')
          bad.call('resource_type', w, 'relation anchor has the wrong type prefix') unless id_ok.call(J.jget(s, 'anchor'), anchor_pre)
        end
      when 'all_of'
        parts = J.req_list(J.jget(s, 'parts'))
        bad.call('all_of_arity', w, 'all_of needs at least two parts') if parts.length < 2
        parts.each { |x| check_resource(o, x, v, w, bad) }
      end
    end

    def check_cond(c, v, t, w, bad)
      k = J.jget(c, 'k')
      if %w[and or].include?(k)
        check_cond(J.jget(c, 'a'), v, t, w, bad)
        check_cond(J.jget(c, 'b'), v, t, w, bad)
        return
      end
      if k == 'not'
        check_cond(J.jget(c, 'c'), v, t, w, bad)
        return
      end
      return if k != 'cmp'

      l = J.jget(c, 'l')
      p = J.jget(l, 'k') == 'param' ? own(J.jget(v, 'params'), J.jget(l, 'path')) : UNDEF
      if J.jget(l, 'k') != 'param' || !J.truthy(p)
        bad.call('cond_param', w, 'left side of a comparison must be a declared parameter of the verb')
        return
      end
      op = J.jget(c, 'op')
      pk = J.jget(p, 'kind')
      bad.call('cond_order', w, 'ordering on a text/enum/id parameter') if %w[lt lte gt gte].include?(op) && %w[text enum id].include?(pk)
      x = J.jget(c, 'r')
      xk = J.jget(x, 'k')
      if xk == 'slot'
        sn = J.jget(x, 'slot')
        s = find(J.jget(t, 'slots')) { |q| J.strict_eq(J.jget(q, 'name'), sn) }
        return if J.undef?(s)

        sk = J.jget(s, 'kind')
        ok_kind = if pk == 'money'
                    sk == 'money'
                  else
                    pk == sk || (pk == 'enum' && %w[enum enum_list].include?(sk)) || (pk == 'id' && %w[id id_list].include?(sk)) || (pk == 'text' && sk == 'text_list')
                  end
        bad.call('cond_type', w, "slot #{J.js_str(J.jget(s, 'name'))} (#{J.js_str(sk)}) does not type-check against parameter kind #{J.js_str(pk)}") unless ok_kind
        ccys = J.jget(p, 'ccys')
        scc = J.jget(s, 'ccy')
        bad.call('cond_unit', w, 'slot currency is not accepted by the parameter') if pk == 'money' && sk == 'money' && !(!J.undef?(ccys) && J.includes(ccys, J.undef?(scc) ? '' : scc))
        lst = %w[id_list enum_list text_list].include?(sk)
        bad.call('cond_type', w, 'list slots pair with in/nin and scalar slots with the other operators') if lst != %w[in nin].include?(op)
      elsif xk == 'lit'
        lv = J.jget(x, 'v')
        if J.jget(lv, 'k') == 'set'
          items = J.req_list(J.jget(lv, 'items'))
          bad.call('cond_type', w, 'empty literal list') if items.empty?
          items.each { |i| lit_check(i, p, w, bad) }
          bad.call('cond_type', w, 'a literal set pairs with in/nin') unless %w[in nin].include?(op)
        else
          lit_check(lv, p, w, bad)
          bad.call('cond_type', w, 'in/nin needs a list') if %w[in nin].include?(op)
        end
      else
        bad.call('cond_term', w, 'unsupported right-hand term')
      end
    end

    def lit_check(l, p, w, bad)
      pk = J.jget(p, 'kind')
      case J.jget(l, 'k')
      when 'q'
        u = J.jget(J.jget(l, 'q'), 'u')
        bad.call('cond_type', w, 'literal kind differs from the parameter kind') if J.jget(u, 'k') != pk
        ccys = J.jget(p, 'ccys')
        bad.call('cond_unit', w, 'literal currency is not accepted by the parameter') if J.jget(u, 'k') == 'money' && !(!J.undef?(ccys) && J.includes(ccys, J.jget(u, 'ccy')))
      when 's'
        bad.call('cond_type', w, 'literal kind differs from the parameter kind') unless %w[enum id text].include?(pk)
        vals = J.jget(p, 'values')
        bad.call('cond_enum', w, 'enum literal is not a member') if pk == 'enum' && !(!J.undef?(vals) && J.includes(vals, J.jget(l, 's')))
      else
        bad.call('cond_type', w, 'nested literal set')
      end
    end

    # A cheap Allow witness for the checker: build an action from the grant's selector and conditions.
    def allow_witness?(o, g)
      ont = ontology_for_goal(o, g)
      g['grants'].all? { |gr| !GoalExamples.allow_witness(g, gr, ont).nil? }
    end

    def safe_n?(n, signed) = GoalCodec.safe_int?(n) && (signed || n >= 0)

    def quantity_of(s, v)
      return nil if v.is_a?(String) || v.is_a?(Array)
      raise TypeError, "cannot use 'in' operator on a non-object" unless v.is_a?(Hash)

      kind = J.jget(s, 'kind')
      if v.key?('minor') && kind == 'money' && J.strict_eq(v['ccy'], J.jget(s, 'ccy')) && safe_n?(v['minor'], false)
        return { 'u' => { 'k' => 'money', 'ccy' => v['ccy'] }, 'n' => v['minor'] }
      end
      return { 'u' => { 'k' => 'count' }, 'n' => v['n'] } if v.key?('n') && kind == 'count' && safe_n?(v['n'], false)
      return { 'u' => { 'k' => 'duration' }, 'n' => v['ms'] } if v.key?('ms') && kind == 'duration' && safe_n?(v['ms'], false)
      return { 'u' => { 'k' => 'instant' }, 'n' => v['epoch_ms'] } if v.key?('epoch_ms') && kind == 'instant' && safe_n?(v['epoch_ms'], true)

      nil
    end

    def sv(s) = { 'k' => 's', 's' => s }
    def utf16_len(s) = Predicates.units(s).length

    # Typed value(s) of a slot, or a reason string when it is missing / invalid (the slot then becomes a Hole).
    def slot_lits(o, s, v = UNDEF)
      return 'missing' if J.undef?(v)

      kind = J.jget(s, 'kind')
      if %w[money count duration instant].include?(kind)
        q = quantity_of(s, v)
        return 'ill-typed' if q.nil?

        mx = J.jget(s, 'max')
        return 'above the template maximum' if !J.undef?(mx) && J.js_gt(kind == 'instant' ? 0 : q['n'], mx)

        return [{ 'k' => 'q', 'q' => q }]
      end
      if %w[id id_list].include?(kind)
        of = J.jget(s, 'of')
        pre = J.oget(find(J.jget(o, 'types')) { |t| J.strict_eq(J.jget(t, 'id'), of) }, 'id_prefix')
        if kind == 'id'
          return v.is_a?(String) && J.truthy(pre) && v.start_with?(pre) && utf16_len(v) > utf16_len(pre) && ID_RE.match?(v) ? [sv(v)] : 'ill-typed'
        end
        return v.map { |x| sv(x) } if v.is_a?(Array) && !v.empty? && v.all? { |x| J.truthy(pre) && x.start_with?(pre) && ID_RE.match?(x) }

        return 'ill-typed'
      end
      vals = J.jget(s, 'values')
      return v.is_a?(String) && !J.undef?(vals) && J.includes(vals, v) ? [sv(v)] : 'ill-typed' if kind == 'enum'

      if kind == 'enum_list'
        return v.map { |x| sv(x) } if v.is_a?(Array) && !v.empty? && v.all? { |x| !J.undef?(vals) && J.includes(vals, x) }

        return 'ill-typed'
      end
      if kind == 'text_list'
        return v.map { |x| sv(x) } if v.is_a?(Array) && !v.empty? && v.all? { |x| x.is_a?(String) && !x.empty? && x == x.unicode_normalize(:nfkc) && !INVIS_RE.match?(x) }

        return 'ill-typed'
      end
      nil # the reference switch has no default
    end

    def list_slot?(t, name)
      s = find(J.jget(t, 'slots')) { |x| J.strict_eq(J.jget(x, 'name'), name) }
      k = J.undef?(s) || J.undef?(J.jget(s, 'kind')) ? '' : J.jget(s, 'kind')
      k.is_a?(String) && k.end_with?('_list')
    end

    # Template -> Goal (IR, canonical order). Mandatory slots that are missing or ill-typed become Holes; every clause depending on a
    # hole is dropped (the most restrictive completion); a prohibition that depends on a hole widens to every resource. Limits become
    # IR bounds over the surviving grants (admitting grant, lifetime window, session scope).
    def instantiate_template(o, template_id, values, opts)
      t = find(J.jget(o, 'templates')) { |x| J.strict_eq(J.jget(x, 'id'), template_id) }
      raise ArgumentError, "unknown template #{J.js_str(template_id)}" if J.undef?(t)

      bound = {}
      holes = []
      J.req_list(J.jget(t, 'slots')).each do |s|
        name = J.jget(s, 'name')
        v = own(values, name)
        r = slot_lits(o, s, v.nil? || J.undef?(v) ? J.jget(s, 'default') : v)
        if r.is_a?(String)
          ccy = J.jget(s, 'ccy')
          holes << { 'hid' => name, 'q' => "What is the #{J.js_str(name).tr('_', ' ')} (#{J.js_str(J.jget(s, 'kind'))}#{J.truthy(ccy) ? " #{J.js_str(ccy)}" : ''})? (#{r})",
                     'domain' => [], 'affects' => [], 'global' => false }
        else
          bound[name] = r
        end
      end
      deps = ->(refs) { refs.all? { |r| bound.key?(r) } }
      single = ->(name) { bound[name][0] }
      sub = ->(i) { i.start_with?('$') ? single.call(i[1..])['s'] : i }
      sub_part = lambda do |r|
        case J.jget(r, 'k')
        when 'exact' then { 'k' => 'exact', 'id' => sub.call(J.jget(r, 'id')) }
        when 'oneof' then { 'k' => 'oneof', 'ids' => J.req_list(J.jget(r, 'ids')).map { |i| sub.call(i) } }
        else r.merge('anchor' => sub.call(J.jget(r, 'anchor')))
        end
      end
      sub_res = lambda do |r|
        case J.jget(r, 'k')
        when 'any' then r
        when 'all_of' then { 'k' => 'all_of', 'parts' => J.req_list(J.jget(r, 'parts')).map { |p| sub_part.call(p) } }
        else sub_part.call(r)
        end
      end
      verb_of = {}
      J.req_list(J.jget(o, 'verbs')).each { |v| verb_of[hk(J.jget(v, 'id'))] ||= v }
      ty_of = lambda do |verb, path, ccy|
        p = !verb.nil? && verb_of.key?(hk(verb)) ? own(J.jget(verb_of[hk(verb)], 'params'), path) : UNDEF
        if J.undef?(p)
          J.req_list(J.jget(o, 'verbs')).each do |v|
            x = own(J.jget(v, 'params'), path)
            unless J.undef?(x)
              p = x
              break
            end
          end
        end
        raise ArgumentError, "parameter #{J.js_str(path)} is not declared by any verb" if J.undef?(p)

        param_ty(p, ccy)
      end
      lit = lambda do |x|
        case J.jget(x, 'k')
        when 'slot'
          l = bound[J.jget(x, 'slot')]
          { 'k' => 'lit', 'v' => list_slot?(t, J.jget(x, 'slot')) ? { 'k' => 'set', 'items' => l } : l[0] }
        when 'lit' then { 'k' => 'lit', 'v' => J.jget(x, 'v') }
        end
      end
      ccy_of = lambda do |x|
        if !x.nil? && J.jget(x, 'k') == 'lit' && J.jget(J.jget(x, 'v'), 'k') == 'q' && J.jget(J.jget(J.jget(J.jget(x, 'v'), 'q'), 'u'), 'k') == 'money'
          J.jget(J.jget(J.jget(J.jget(x, 'v'), 'q'), 'u'), 'ccy')
        end
      end
      sub_cond = nil
      sub_cond = lambda do |c, verb|
        k = J.jget(c, 'k')
        next c if k == 'true'
        next({ 'k' => k, 'a' => sub_cond.call(J.jget(c, 'a'), verb), 'b' => sub_cond.call(J.jget(c, 'b'), verb) }) if %w[and or].include?(k)
        next({ 'k' => 'not', 'c' => sub_cond.call(J.jget(c, 'c'), verb) }) if k == 'not'

        lv = lit.call(J.jget(c, 'l'))
        rv = lit.call(J.jget(c, 'r'))
        hint = ccy_of.call(lv)
        hint = ccy_of.call(rv) if hint.nil?
        term = lambda do |x, v|
          next v unless v.nil?

          path = J.jget(x, 'path')
          { 'k' => 'param', 'path' => path, 'ty' => ty_of.call(verb, path, hint) }
        end
        { 'k' => 'cmp', 'op' => J.jget(c, 'op'), 'l' => term.call(J.jget(c, 'l'), lv), 'r' => term.call(J.jget(c, 'r'), rv) }
      end
      dropped = JsSet.new
      grants = []
      t_bounds = J.req_list(J.jget(t, 'bounds'))
      t_grants = J.req_list(J.jget(t, 'grants'))
      keep_bound = t_bounds.select { |b| deps.call(refs_bound(b)) }
      t_bounds.each do |b|
        next if keep_bound.any? { |kb| b.equal?(kb) }

        t_grants.each do |g|
          over = J.jget(b, 'over')
          dropped.add(J.jget(g, 'gid')) if J.strict_eq(over, 'all') || J.includes(over, J.jget(g, 'gid'))
        end
      end
      t_grants.each do |g|
        if dropped.include?(J.jget(g, 'gid')) || !deps.call(refs_grant(g))
          dropped.add(J.jget(g, 'gid'))
        else
          grants << { 'gid' => J.jget(g, 'gid'), 'verb' => J.jget(g, 'verb'), 'res' => sub_res.call(J.jget(g, 'res')), 'cond' => sub_cond.call(J.jget(g, 'cond'), J.jget(g, 'verb')) }
        end
      end
      prohibits = []
      J.req_list(J.jget(t, 'prohibits')).each do |p|
        tg = J.jget(p, 'target')
        if J.jget(tg, 'k') == 'verb'
          verb = J.jget(tg, 'verb')
        else
          fv = find(J.jget(o, 'verbs')) { |v| J.strict_eq(J.jget(v, 'effect'), J.jget(tg, 'cls')) }
          verb = J.oget(fv, 'id')
          verb = nil if J.undef?(verb)
        end
        if deps.call(refs_grant(p))
          prohibits << { 'pid' => J.jget(p, 'pid'), 'target' => tg, 'res' => sub_res.call(J.jget(p, 'res')), 'cond' => sub_cond.call(J.jget(p, 'cond'), verb) }
        else
          prohibits << { 'pid' => J.jget(p, 'pid'), 'target' => tg, 'res' => { 'k' => 'any', 'reason' => 'hole' }, 'cond' => { 'k' => 'true' } }
        end
      end
      kept = grants.map { |g| g['gid'] }
      bounds = []
      keep_bound.each do |b|
        over = J.jget(b, 'over')
        gids = J.strict_eq(over, 'all') ? grants.map { |g| g['gid'] } : J.req_list(over).select { |x| kept.include?(x) }
        next if gids.empty?

        cs = J.jget(b, 'cap_slot')
        cap_lit = J.truthy(cs) ? single.call(cs) : nil
        cap = !cap_lit.nil? && J.jget(cap_lit, 'k') == 'q' ? J.jget(cap_lit, 'q') : J.jget(b, 'cap')
        verb = grants.find { |g| g['gid'] == gids[0] }['verb']
        agg = J.jget(b, 'agg')
        capu = J.jget(cap, 'u')
        bounds << {
          'bid' => J.jget(b, 'bid'), 'sel' => { 'k' => 'gids', 'gids' => gids }, 'agg' => agg,
          'value' => if agg == 'sum'
                       { 'k' => 'param', 'path' => J.jget(b, 'param'), 'ty' => ty_of.call(verb, J.jget(b, 'param'), J.jget(capu, 'k') == 'money' ? J.jget(capu, 'ccy') : nil) }
                     else
                       { 'k' => 'lit', 'v' => { 'k' => 'q', 'q' => { 'u' => { 'k' => 'count' }, 'n' => 1 } } }
                     end,
          'key' => '', 'window' => { 'k' => 'lifetime' }, 'scope' => { 'k' => 'session' }, 'cap' => cap, 'onExceed' => J.jget(b, 'onExceed')
        }
      end
      srcs = J.jget(opts, 'sources')
      GoalNormalize.canonicalize_goal({
                                        'v' => 1, 'principal' => J.jget(opts, 'principal'), 'ontDigest' => ontology_digest(o), 'nlDigest' => GoalDigests.nl_digest(J.jget(opts, 'nl')),
                                        'sources' => !J.undef?(srcs) && !srcs.nil? ? J.req_list(srcs).dup : [],
                                        'grants' => grants, 'prohibits' => prohibits, 'bounds' => bounds,
                                        'validity' => { 'notBefore' => 0, 'notAfter' => FOREVER, 'maxIdle' => 0 }, 'deleg' => { 'maxDepth' => 0, 'narrowOnly' => true, 'mayTouch' => [] },
                                        'escalateOn' => [], 'wildcardAck' => [], 'holes' => holes
                                      })
    end

    # ---- locale-aware human number parsing (interpreter front end only; the IR has no locale)

    # "1,000.50", "1.000,50", "$20", "20 dollars". Ambiguous literals ("1,000" with no locale hint, "1.000") are NOT guessed: they
    # yield a failure and become a Hole. `locale` 'en' reads ',' as thousands, 'de' reads '.' as thousands.
    def parse_human_amount(text, exponent, locale = nil)
      raise TypeError, 'text.normalize is not a function' unless text.is_a?(String)

      t = Js.trim(text.unicode_normalize(:nfkc)).gsub(/[^0-9.,]/, '')
      return { 'ok' => false, 'reason' => 'not a number' } if !NUM_RE.match?(t) || t.match?(/[.,]{2}/)

      last_dot = t.rindex('.') || -1
      last_comma = t.rindex(',') || -1
      dec = thou = nil
      if last_dot >= 0 && last_comma >= 0
        dec = last_dot > last_comma ? '.' : ','
        thou = dec == '.' ? ',' : '.'
      elsif last_dot >= 0 || last_comma >= 0
        sep = last_dot >= 0 ? '.' : ','
        parts = t.split(sep, -1)
        group_like = parts.length > 2 || parts[-1].length == 3
        if !group_like
          dec = sep
        elsif parts.length > 2
          thou = sep
        elsif locale && !locale.empty?
          if (locale == 'en') == (sep == ',')
            thou = sep
          else
            dec = sep
          end
        else
          return { 'ok' => false, 'reason' => 'ambiguous separator' }
        end
      end
      int_part = t
      frac = ''
      if dec
        i = t.rindex(dec)
        int_part = t[0...i]
        frac = t[(i + 1)..]
      end
      if thou
        groups = int_part.split(thou, -1)
        return { 'ok' => false, 'reason' => 'malformed grouping' } if groups[1..].any? { |g| g.length != 3 } || groups[0].empty? || groups[0].length > 3

        int_part = groups.join
      end
      return { 'ok' => false, 'reason' => 'more decimals than the currency allows' } if frac.length > exponent

      minor = (int_part + frac.ljust(exponent, '0')).to_i
      minor <= FOREVER ? { 'ok' => true, 'minor' => minor } : { 'ok' => false, 'reason' => 'out of range' }
    end

    # The strict front-end contract over `parse_human_amount`: only digits, '.' and ',' after one optional leading currency symbol; with
    # a locale, a decimal separator that contradicts it is refused; without one, a repeated or ambiguous separator is a Hole, not a guess.
    def parse_money(text, exponent, locale)
      t = Js.trim(J.js_str(text)).sub(/\A[$€£][#{WS_CLASS}]*/, '')
      return { 'error' => 'BAD_NUMBER' } unless NUM_RE.match?(t)

      both = t.include?('.') && t.include?(',')
      return { 'error' => 'BAD_NUMBER' } if !locale.nil? && both && t[[t.rindex('.'), t.rindex(',')].max] != (locale == 'en' ? '.' : ',')
      return { 'hole' => 'AMBIGUOUS_NUMBER' } if locale.nil? && !both && t.scan(/[.,]/).length > 1

      r = parse_human_amount(t, exponent, locale)
      return { 'minor' => r['minor'] } if r['ok']

      r['reason'] == 'ambiguous separator' ? { 'hole' => 'AMBIGUOUS_NUMBER' } : { 'error' => 'BAD_NUMBER' }
    end
  end
end
