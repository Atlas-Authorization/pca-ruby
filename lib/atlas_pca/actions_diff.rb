# frozen_string_literal: true

# Semantic diff of two versions of one ActionDef (native port of diff.ts and defdiff.ts of the TypeScript reference
# @atlasauth/pca-actions). diff_defs is the grant-pin form (equal|narrow|widen|incomparable, never optimistic); diff_defs_authoring
# and diff_packs are the authoring-CLI form.
require_relative 'actions'
require_relative 'actions_effective'
require_relative 'actions_idpattern'
require_relative 'js_compat'

module AtlasPca
  module ActionsDiff
    A = AtlasPca::Actions
    E = AtlasPca::ActionsEffective
    ID = AtlasPca::ActionsIdPattern
    UNDEF = AtlasPca::V2JS::UNDEF
    INF = Float::INFINITY
    DEFAULT_MAX_LEN = 1024
    DEFAULT_MAX_ITEMS = 64
    SCOPE_RANK = { 'one' => 0, 'set' => 1, 'tenant' => 2, 'global' => 3 }.freeze
    IDEM_RANK = { 'none' => 0, 'natural' => 1, 'key_param' => 2 }.freeze

    module_function

    # `o[k] ?? default`: an absent or null member takes the default.
    def g(o, k, default)
      v = o[k]
      v.nil? ? default : v
    end

    # JSON.stringify(o[k]) (key order matters; an absent member is 'undefined').
    # key order is not meaning (a stored def comes back with sorted keys, a fresh one in author order); array order is
    def sort_keys(v)
      case v
      when Hash then v.keys.sort_by { |k| A.u16key(k.to_s) }.to_h { |k| [k, sort_keys(v[k])] }
      when Array then v.map { |x| sort_keys(x) }
      else v
      end
    end

    def same_json(a, b) = AtlasPca::Js.json(sort_keys(a)) == AtlasPca::Js.json(sort_keys(b))

    def sj(o, k) = o.key?(k) ? AtlasPca::Js.json(sort_keys(o[k])) : 'undefined'

    def set_rel(old, new)
      added = new.any? { |x| !old.include?(x) }
      removed = old.any? { |x| !new.include?(x) }
      added && removed ? 'inc' : added ? 'narrow' : removed ? 'widen' : 'eq'
    end

    # More restrictive = larger.
    def rank_rel(o, n) = n == o ? 'eq' : n > o ? 'narrow' : 'widen'

    # Is every value of inner's domain also a value of outer's? Same declared type required. Sound, not complete.
    def domain_contains?(outer, inner)
      t = outer['type']
      return false if t != inner['type']

      case t
      when 'string', 'object_ref'
        return false if g(inner, 'max_len', DEFAULT_MAX_LEN) > g(outer, 'max_len', DEFAULT_MAX_LEN)
        return false if !outer['values'].nil? && (inner['values'].nil? || !inner['values'].all? { |v| outer['values'].include?(v) })

        outer['format'].nil? || inner['format'] == outer['format']
      when 'integer'
        g(inner, 'min', -INF) >= g(outer, 'min', -INF) && g(inner, 'max', INF) <= g(outer, 'max', INF)
      when 'duration'
        [g(inner, 'min', 0), 0].max >= [g(outer, 'min', 0), 0].max && g(inner, 'max', INF) <= g(outer, 'max', INF)
      when 'set'
        ov = outer['values'] || []
        iv = inner['values'] || []
        return false unless iv.all? { |v| ov.include?(v) }

        o_max = [g(outer, 'max_items', ov.length), ov.length].min
        i_max = [g(inner, 'max_items', iv.length), iv.length].min
        g(inner, 'min_items', 0) >= g(outer, 'min_items', 0) && i_max <= o_max
      when 'array'
        return false if g(outer, 'items', 'string') != g(inner, 'items', 'string')
        return false if g(inner, 'min_items', 0) < g(outer, 'min_items', 0) || g(inner, 'max_items', DEFAULT_MAX_ITEMS) > g(outer, 'max_items', DEFAULT_MAX_ITEMS)
        return g(inner, 'min', -INF) >= g(outer, 'min', -INF) && g(inner, 'max', INF) <= g(outer, 'max', INF) if outer['items'] == 'integer'

        g(inner, 'max_len', DEFAULT_MAX_LEN) <= g(outer, 'max_len', DEFAULT_MAX_LEN)
      else true # boolean, date, datetime: no domain members
      end
    end

    # Is every call conforming to `inner` also conforming to `outer`? Closed world, required members, domains.
    def calls_contained?(outer, inner)
      inner.each do |name, ip|
        op = outer[name]
        return false if op.nil? || !domain_contains?(op, ip)
      end
      outer.each do |name, op|
        next unless op['required']

        ip = inner[name]
        return false if ip.nil? || !ip['required']
      end
      true
    end

    def call_set_rel(old_p, new_p)
      sub = calls_contained?(old_p, new_p)
      sup = calls_contained?(new_p, old_p)
      sub && sup ? 'eq' : sub ? 'narrow' : sup ? 'widen' : 'inc'
    end

    def prov_rank(p) = p.nil? ? A::PROVENANCE_LEVELS.length - 1 : (A::PROVENANCE_LEVELS.index(p) || raise(ArgumentError, "#{p.inspect} is not a provenance level"))

    def param_attr_rels(o, n)
      out = []
      out << %w[role inc] if o['role'] != n['role']
      out << ['sensitivity', rank_rel(A::SENSITIVITY_RANK.fetch(o['sensitivity']), A::SENSITIVITY_RANK.fetch(n['sensitivity']))]
      out << ['tags', set_rel(o['tags'] || [], n['tags'] || [])]
      out << ['provenance_min', rank_rel(-prov_rank(o['provenance_min']), -prov_rank(n['provenance_min']))]
      out << %w[unit inc] if sj(o, 'unit') != sj(n, 'unit')
      out << ['accumulates', set_rel(o['accumulates'] || [], n['accumulates'] || [])]
      out << %w[default inc] if sj(o, 'default') != sj(n, 'default') || o.fetch('principal_neutral_default', UNDEF) != n.fetch('principal_neutral_default', UNDEF)
      out
    end

    def text_differs?(o, n) = %w[title description compensates].any? { |k| o.fetch(k, UNDEF) != n.fetch(k, UNDEF) }

    def sort_str(xs) = xs.sort_by { |s| A.u16key(s) }

    def prof_rel(a, b)
      if A.leq(a, b) then A.leq(b, a) ? 'eq' : 'narrow'
      else A.leq(b, a) ? 'widen' : 'inc'
      end
    end

    # The semantic diff of `nxt` against `prev` (two versions of one verb): {class, reasons}. Raises diff_verb for two different verbs.
    def diff_defs(prev, nxt, reg = A::CORE_REGISTRY, verifier = nil)
      raise A::ActionKitError.new('diff_verb', "diff compares two versions of one verb, not '#{prev['verb']}' and '#{nxt['verb']}'") if prev['verb'] != nxt['verb']

      o = A.normalize(prev)
      n = A.normalize(nxt)
      rels = []
      text = text_differs?(o, n)
      rels << ['effects', set_rel(o['effects'], n['effects'])]
      rels << ['params.accepted_calls', call_set_rel(o['params'], n['params'])]
      o['params'].keys.sort_by(&:b).each do |name|
        next unless n['params'].key?(name)

        param_attr_rels(o['params'][name], n['params'][name]).each { |k, r| rels << ["params.#{name}.#{k}", r] }
      end
      eo = E.effective_with(prev, reg, verifier)
      en = E.effective_with(nxt, reg, verifier)
      rels << ['traits', set_rel(A.closure(reg, eo['hint']['traits']), A.closure(reg, en['hint']['traits']))]
      rels << ['profile', prof_rel(eo['hint']['eff'], en['hint']['eff'])]
      rels << ['confirmation', rank_rel(eo['confirmed'] ? 0 : 1, en['confirmed'] ? 0 : 1)]
      rels << ['effective.traits', set_rel(A.closure(reg, eo['traits']), A.closure(reg, en['traits']))]
      rels << ['effective.profile', prof_rel(eo['eff'], en['eff'])]
      rels << ['reversibility', rank_rel(A::REV_RANK.fetch(A.worst_reversibility(o['reversibility'], o['params'])), A::REV_RANK.fetch(A.worst_reversibility(n['reversibility'], n['params'])))]
      rels << ['blast', rank_rel(o['blast']['ppm'], n['blast']['ppm'])]
      oi = o['idempotency']
      ni = n['idempotency']
      idem = oi['mode'] == 'key_param' && ni['mode'] == 'key_param' && oi['param'] != ni['param'] ? 'inc' : rank_rel(IDEM_RANK.fetch(oi['mode']), IDEM_RANK.fetch(ni['mode']))
      rels << ['idempotency', idem]
      rels << ['context', set_rel(o['context'], n['context'])]
      rels << ['side_effects', set_rel(o['side_effects'].map { |s| "#{s['target']}|#{s['kind']}" }, n['side_effects'].map { |s| "#{s['target']}|#{s['kind']}" })]
      orr = o['resource']
      nrr = n['resource']
      res_id = if same_json(orr['id'], nrr['id']) then 'eq'
               elsif ID.id_pattern_contains(orr['id'], nrr['id']) then 'narrow'
               elsif ID.id_pattern_contains(nrr['id'], orr['id']) then 'widen'
               else 'inc'
               end
      rels << ['resource.id', orr['type'] != nrr['type'] ? 'inc' : res_id]
      rels << ['resource.scope', rank_rel(-SCOPE_RANK.fetch(orr['scope']), -SCOPE_RANK.fetch(nrr['scope']))]
      ar = set_rel(o['aliases'], n['aliases']) # new aliases widen what natural language can reach
      rels << ['aliases', ar == 'narrow' ? 'widen' : ar == 'widen' ? 'narrow' : ar]
      rels << ['bindings', same_json(o['bindings'], n['bindings']) ? 'eq' : 'inc']

      diffs = rels.reject { |_, r| r == 'eq' }
      reasons = sort_str(diffs.map { |d, r| "#{d}: #{r == 'inc' ? 'incomparable' : r}" })
      reasons << 'text: title, description or compensates changed' if text
      reasons = sort_str(reasons)
      has = ->(r) { diffs.any? { |_, x| x == r } }
      cls = has.call('inc') || (has.call('narrow') && has.call('widen')) ? 'incomparable' : has.call('widen') ? 'widen' : has.call('narrow') ? 'narrow' : 'equal'
      { 'class' => cls, 'reasons' => reasons }
    end

    # Does a pin follow this change on its own (no principal)?
    def diff_is_free(c) = %w[equal narrow].include?(c)

    # ---- the authoring diff (defdiff.ts) ----------------------------------------------------------------------------

    def num_str(v) = A.js.js_str(v.nil? ? UNDEF : v)

    def num_diff(k, f, lower_is_wider, x, y, wide, narrow)
      o = x[f]
      n = y[f]
      return if o == n

      rank = ->(v) { v.nil? ? (lower_is_wider ? -INF : INF) : v }
      wider_new = lower_is_wider ? rank.call(n) < rank.call(o) : rank.call(n) > rank.call(o)
      (wider_new ? wide : narrow) << "param #{k}: #{f} #{num_str(o)} to #{num_str(n)}"
    end

    def pl(v) = v.nil? ? A::PROVENANCE_LEVELS.length : (A::PROVENANCE_LEVELS.index(v) || -1)

    def role_floor(r) = !r.nil? && A::ROLE_SENSITIVITY_FLOOR.key?(r) ? A::SENSITIVITY_RANK.fetch(A::ROLE_SENSITIVITY_FLOOR[r]) : 0

    def param_diff(k, x, y, wide, narrow, incomp)
      incomp << "param #{k}: type changed" if x['type'] != y['type']
      num_diff(k, 'min', true, x, y, wide, narrow)
      num_diff(k, 'max', false, x, y, wide, narrow)
      num_diff(k, 'max_len', false, x, y, wide, narrow)
      num_diff(k, 'max_items', false, x, y, wide, narrow)
      num_diff(k, 'min_items', true, x, y, wide, narrow)
      incomp << "param #{k}: unit changed" if AtlasPca::Js.json(x['unit']) != AtlasPca::Js.json(y['unit'])
      vo = x['values']
      vn = y['values']
      if !vo.nil? || !vn.nil?
        if vo.nil?
          narrow << "param #{k}: values restricted"
        elsif vn.nil?
          wide << "param #{k}: values unrestricted"
        else
          added = vn.reject { |v| vo.include?(v) }
          removed = vo.reject { |v| vn.include?(v) }
          wide << "param #{k}: values added (#{added.map { |v| A.js.js_str(v) }.join(', ')})" unless added.empty?
          narrow << "param #{k}: values removed (#{removed.map { |v| A.js.js_str(v) }.join(', ')})" unless removed.empty?
        end
      end
      wide << "param #{k}: required to optional" if x['required'] == true && y['required'] == false
      narrow << "param #{k}: optional to required" if x['required'] == false && y['required'] == true
      if pl(y['provenance_min']) > pl(x['provenance_min'])
        wide << "param #{k}: provenance_min loosened"
      elsif pl(y['provenance_min']) < pl(x['provenance_min'])
        narrow << "param #{k}: provenance_min tightened"
      end
      sx = A::SENSITIVITY_RANK.fetch(A.effective_param_sensitivity(x))
      sy = A::SENSITIVITY_RANK.fetch(A.effective_param_sensitivity(y))
      if sy < sx
        wide << "param #{k}: sensitivity lowered"
      elsif sy > sx
        narrow << "param #{k}: sensitivity raised"
      end
      return if x['role'] == y['role']

      if role_floor(y['role']) < role_floor(x['role'])
        wide << "param #{k}: role changed to a lower-floor role"
      elsif role_floor(y['role']) > role_floor(x['role'])
        narrow << "param #{k}: role changed to a higher-floor role"
      else
        incomp << "param #{k}: role changed"
      end
    end

    # {class, breaking, reasons}: anything not shown to be no wider is widening. A renamed verb is a breaking widen.
    def diff_defs_authoring(a, b, reg)
      return { 'class' => 'widen', 'breaking' => true, 'reasons' => ['verb renamed: removed + added (grants on the old verb do not follow)'] } if a['verb'] != b['verb']

      wide = []
      narrow = []
      incomp = []
      breaking = false
      na = A.normalize(a)
      nb = A.normalize(b)
      ea = E.effective_with(a, reg)['hint']
      eb = E.effective_with(b, reg)['hint']
      if !A.leq(ea['eff'], eb['eff'])
        wide << 'the effective profile is not at least the old one'
      elsif !E.profile_eq(ea['eff'], eb['eff'])
        narrow << 'the effective profile rose'
      end
      na['effects'].each { |e| wide << "effect #{e} removed" unless nb['effects'].include?(e) }
      nb['effects'].each { |e| narrow << "effect #{e} added" unless na['effects'].include?(e) }
      na['traits'].each { |t| wide << "declared trait #{t} removed" unless nb['traits'].include?(t) }
      nb['traits'].each { |t| narrow << "declared trait #{t} added" unless na['traits'].include?(t) }
      ra = A.worst_reversibility(na['reversibility'], na['params'])
      rb = A.worst_reversibility(nb['reversibility'], nb['params'])
      if A::REV_RANK.fetch(rb) < A::REV_RANK.fetch(ra)
        wide << "reversibility lowered (#{ra} to #{rb})"
      elsif A::REV_RANK.fetch(rb) > A::REV_RANK.fetch(ra)
        narrow << "reversibility raised (#{ra} to #{rb})"
      end
      if nb['blast']['ppm'] < na['blast']['ppm']
        wide << 'blast lowered'
      elsif nb['blast']['ppm'] > na['blast']['ppm']
        narrow << 'blast raised'
      end
      idem = ->(m) { m == 'none' ? 0 : 1 }
      if idem.call(nb['idempotency']['mode']) < idem.call(na['idempotency']['mode'])
        wide << 'idempotency loosened'
      elsif idem.call(nb['idempotency']['mode']) > idem.call(na['idempotency']['mode'])
        narrow << 'idempotency added'
      end
      incomp << 'resource type changed' if na['resource']['type'] != nb['resource']['type']
      if SCOPE_RANK.fetch(nb['resource']['scope']) > SCOPE_RANK.fetch(na['resource']['scope'])
        wide << 'resource scope widened'
      elsif SCOPE_RANK.fetch(nb['resource']['scope']) < SCOPE_RANK.fetch(na['resource']['scope'])
        narrow << 'resource scope narrowed'
      end
      in_old = ID.id_pattern_contains(na['resource']['id'], nb['resource']['id'])
      in_new = ID.id_pattern_contains(nb['resource']['id'], na['resource']['id'])
      if !in_old
        wide << 'the resource id pattern is not contained in the old one'
      elsif !in_new
        narrow << 'the resource id pattern is narrower'
      end
      na['params'].each do |k, x|
        y = nb['params'][k]
        if y.nil?
          narrow << "param #{k} removed"
          breaking = true
          next
        end
        param_diff(k, x, y, wide, narrow, incomp)
        breaking = true if x['required'] == false && y['required'] == true
      end
      nb['params'].each do |k, p|
        next if na['params'].key?(k)

        if p['required']
          narrow << "required param #{k} added"
          breaking = true
        else
          wide << "optional param #{k} added"
        end
      end
      narrow << 'review state left confirmed' if a['review']['state'] == 'confirmed' && b['review']['state'] != 'confirmed'
      cls = !incomp.empty? || (!wide.empty? && !narrow.empty?) ? 'incomparable' : !wide.empty? ? 'widen' : !narrow.empty? ? 'narrow' : 'equal'
      cmp_eq = cls == 'equal' && A.def_digest(a) != A.def_digest(b)
      reasons = wide.map { |r| "widen: #{r}" } + narrow.map { |r| "narrow: #{r}" } + incomp.map { |r| "incomparable: #{r}" } + (cmp_eq ? ['equal: only title or description changed'] : [])
      { 'class' => cls, 'breaking' => breaking, 'reasons' => reasons }
    end

    # Per-verb diff of two sets of defs. A removed verb is `removed`; a new verb is `added`.
    def diff_packs(olds, news, reg)
      o = olds.to_h { |d| [d['verb'], d] }
      n = news.to_h { |d| [d['verb'], d] }
      (o.keys | n.keys).sort_by(&:b).map do |v|
        x = o[v]
        y = n[v]
        if x.nil? then { 'verb' => v, 'class' => 'added', 'breaking' => false, 'reasons' => [] }
        elsif y.nil? then { 'verb' => v, 'class' => 'removed', 'breaking' => true, 'reasons' => ['verb removed'] }
        else { 'verb' => v }.merge(diff_defs_authoring(x, y, reg))
        end
      end
    end
  end
end
