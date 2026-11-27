# frozen_string_literal: true

# Static analyzability of authority: the bounded decision engine and its relational queries (reachability, vacuity, totality,
# subsumption, disjointness, equivalence, intent conformance). Port of the TypeScript reference (@atlasauth/pca-analyzer).
#
# Policies are plain JSON trees (String-keyed Hashes); a model, a probe set, a representative and every result are plain Hashes.
# The engine enumerates a finite distinguishing grid of representative actions and evaluates the real predicate evaluator at each,
# so a verdict is exact over the decided fragment and fails safe (`approximate`) outside it.
require_relative '../atlas_pca'
require_relative 'analyzer_js'

module AtlasPca
  module Analyzer
    extend AnalyzerJs

    UNDEF = AnalyzerJs::UNDEF
    DEFAULT_MAX_COMBINATIONS = 200_000
    FRESH_STRING = "\u0000atlas-analyzer::fresh-unmatched\u0000"
    FRESH_VERB = "\u0000atlas-analyzer::fresh-verb\u0000"
    FRESH_RESOURCE = "\u0000atlas-analyzer::fresh-resource\u0000"
    ABSENT = Object.new.freeze
    FULL_INTERVAL = { 'lo' => -Float::INFINITY, 'loInclusive' => false, 'hi' => Float::INFINITY, 'hiInclusive' => false }.freeze
    Leaf = Struct.new(:value)

    module_function

    # Python-style max / min of two numbers: the first wins a tie or a NaN.
    def pmax(a, b) = b > a ? b : a
    def pmin(a, b) = b < a ? b : a

    # An own member of an object, UNDEF when absent.
    def g(o, k) = own(o, k)

    # Python `len(x)`.
    def py_len(x)
      raise TypeError, "object of type '#{x.class}' has no len()" unless x.is_a?(Array) || x.is_a?(String) || x.is_a?(Hash)

      x.length
    end

    # `list(x)` over the shapes the reference spreads.
    def py_list(x)
      case x
      when Array then x.dup
      when String then x.each_char.to_a
      when Hash then x.keys
      else raise TypeError, 'not iterable'
      end
    end

    # An insertion-ordered set of JS values (strict equality).
    def set_add(arr, v)
      arr << v unless arr.any? { |e| strict_eq(e, v) }
    end

    # ---- caveats -------------------------------------------------------------------------------------------------------------

    # Static satisfiability of an envelope caveat set: {sat, reason?, revCap?} (revCap indexes REVERSIBILITY_ORDER).
    def analyze_caveats(caveats)
      return { 'sat' => false, 'reason' => 'caveats are not an array' } unless caveats.is_a?(Array)

      not_before_max = -Float::INFINITY
      expires_min = Float::INFINITY
      rev_cap = nil
      caveats.each do |cv|
        return { 'sat' => false, 'reason' => 'malformed caveat (not an object with a string type)' } unless cv.is_a?(Hash) && cv['type'].is_a?(String)

        case cv['type']
        when 'expires'
          at = fin(cv['at'])
          return { 'sat' => false, 'reason' => 'expires.at is not a finite number' } if at.nil?

          expires_min = pmin(expires_min, at)
        when 'not_before'
          at = fin(cv['at'])
          return { 'sat' => false, 'reason' => 'not_before.at is not a finite number' } if at.nil?

          not_before_max = pmax(not_before_max, at)
        when 'rate'
          mx = fin(cv['max'])
          per = fin(cv['per_secs'])
          return { 'sat' => false, 'reason' => 'rate caveat requires finite max and per_secs > 0' } if mx.nil? || per.nil? || per <= 0
          return { 'sat' => false, 'reason' => "rate.max #{num_str(mx)} < 1 forbids every action" } if mx < 1
        when 'max_blast_radius'
          mx = fin(cv['max'])
          return { 'sat' => false, 'reason' => 'max_blast_radius.max is not a finite number' } if mx.nil?
          return { 'sat' => false, 'reason' => 'max_blast_radius.max < 0 forbids every action' } if mx.negative?
        when 'reversibility_max'
          cls = js_str(own(cv, 'class'))
          return { 'sat' => false, 'reason' => "reversibility_max.class '#{cls}' is unknown" } unless AtlasPca::REVERSIBILITY_ORDER.include?(cls)

          idx = AtlasPca::REVERSIBILITY_ORDER.index(cls)
          rev_cap = rev_cap.nil? ? idx : [rev_cap, idx].min
        when 'delegation_depth'
          mx = fin(cv['max'])
          return { 'sat' => false, 'reason' => 'delegation_depth.max is not a finite number' } if mx.nil?
          return { 'sat' => false, 'reason' => 'delegation_depth.max < 0 forbids every action' } if mx.negative?
        when 'budget_alloc'
          lim = fin(cv['limit'])
          return { 'sat' => false, 'reason' => 'budget_alloc.limit must be a finite number >= 0' } if lim.nil? || lim.negative?
        else
          return { 'sat' => false, 'reason' => "unknown caveat type '#{cv['type']}' (fail closed)" }
        end
      end
      if not_before_max != -Float::INFINITY && expires_min != Float::INFINITY && not_before_max >= expires_min
        return { 'sat' => false, 'reason' => "not_before (#{num_str(not_before_max)}) >= expires (#{num_str(expires_min)}): the validity window is empty" }
      end

      out = { 'sat' => true }
      out['revCap'] = rev_cap unless rev_cap.nil?
      out
    end

    # ---- constitution --------------------------------------------------------------------------------------------------------

    # A constitution's stateless invariants as analyzer vetoes; the rest are reported in `unmodeled`.
    def vetoes_from_constitution(c)
      vetoes = []
      unmodeled = []
      invs = c.is_a?(Hash) ? own(c, 'invariants') : UNDEF
      (invs.is_a?(Array) ? invs : []).each do |inv|
        kind = jget(inv, 'kind')
        iid = jget(inv, 'id')
        case kind
        when 'never'
          vetoes << uobj({ 'id' => iid, 'kind' => 'deny', 'when' => jget(inv, 'when') })
        when 'never_unless'
          vetoes << uobj({ 'id' => iid, 'kind' => 'deny', 'when' => jget(inv, 'when'), 'unless' => jget(inv, 'unless') })
        when 'require_approval_over'
          vetoes << uobj({ 'id' => iid, 'kind' => 'approval', 'when' => jget(inv, 'when'),
                           'over' => uobj({ 'path' => jget(inv, 'amount'), 'threshold' => jget(inv, 'threshold') }),
                           'unless' => jget(inv, 'approved') })
        when 'cap', 'rate'
          unmodeled << uobj({ 'id' => iid, 'kind' => kind, 'reason' => 'windowed total: bounded by maxExposure, not by a per-action veto' })
        else
          unmodeled << uobj({ 'id' => iid, 'kind' => kind, 'reason' => 'needs action history' })
        end
      end
      { 'vetoes' => vetoes, 'unmodeled' => unmodeled }
    end

    # ---- single-field interval / finite-set engine ---------------------------------------------------------------------------

    def numeric_cell_reps(thresholds)
      s = thresholds.uniq.select(&:finite?).sort
      return [] if s.empty?

      out = [s[0] - 1]
      s.each_with_index do |ti, i|
        out << ti
        out << ((ti + s[i + 1]) / 2) if i + 1 < s.length
      end
      out << (s[-1] + 1)
      out
    end

    def value_key(x)
      return 's:__fresh__' if x.is_a?(String) && x == FRESH_STRING

      t = if num?(x) then 'number'
          elsif x.is_a?(String) then 'string'
          elsif x == true || x == false then 'boolean'
          elsif undef?(x) then 'undefined'
          else 'object'
          end
      "#{t}:#{undef?(x) ? 'undefined' : js_json(x)}"
    end

    # Representative probe values for one field from the conjunction of `where` conditions on it.
    def field_probes(conditions)
      literals = []
      thresholds = []
      prefixes = []
      req_list(conditions).each do |c|
        next if !Predicates.leaf?(c) || c.key?('ref')

        v = own(c, 'value')
        op = own(c, 'op')
        case op
        when 'eq', 'ne'
          literals << v
          thresholds << jsnum(v) if fin?(v)
        when 'in', 'nin'
          if v.is_a?(Array)
            v.each do |x|
              literals << x
              thresholds << jsnum(x) if fin?(x)
            end
          end
        when 'lt', 'lte', 'gt', 'gte'
          thresholds << jsnum(v) if fin?(v)
        when 'prefix', 'like', 'matches', 'is_a'
          if v.is_a?(String)
            literals << v
            prefixes << v if op == 'prefix'
          end
        when 'member_of'
          if v.is_a?(String)
            literals << v
          elsif v.is_a?(Array)
            v.each { |x| literals << x if x.is_a?(String) }
          end
        end
      end
      out = []
      seen = {}
      add = lambda do |x|
        k = value_key(x)
        unless seen.key?(k)
          seen[k] = true
          out << x
        end
      end
      literals.each { |lit| add.call(lit) }
      numeric_cell_reps(thresholds).each { |n| add.call(n) }
      prefixes.each do |p|
        add.call(p)
        add.call("#{p}x")
      end
      add.call(FRESH_STRING)
      out
    end

    # Tighten an interval {lo, loInclusive, hi, hiInclusive} by one numeric condition (a non-numeric operand returns it as is).
    def tighten_interval(iv, op, value)
      return iv unless fin?(value)

      n = iv.dup
      case op
      when 'eq'
        if value > n['lo'] || (value == n['lo'] && !n['loInclusive'])
          n['lo'] = value
          n['loInclusive'] = true
        end
        if value < n['hi'] || (value == n['hi'] && !n['hiInclusive'])
          n['hi'] = value
          n['hiInclusive'] = true
        end
      when 'gte'
        if value > n['lo']
          n['lo'] = value
          n['loInclusive'] = true
        end
      when 'gt'
        if value > n['lo'] || (value == n['lo'] && n['loInclusive'])
          n['lo'] = value
          n['loInclusive'] = false
        end
      when 'lte'
        if value < n['hi']
          n['hi'] = value
          n['hiInclusive'] = true
        end
      when 'lt'
        if value < n['hi'] || (value == n['hi'] && n['hiInclusive'])
          n['hi'] = value
          n['hiInclusive'] = false
        end
      end
      n
    end

    def interval_empty(iv)
      return true if iv['lo'] > iv['hi']
      return !(iv['loInclusive'] && iv['hiInclusive']) if iv['lo'] == iv['hi']

      false
    end

    # Is the numeric part of a field's `where` conjunction satisfiable (an empty interval is not)?
    def numeric_conjunction_satisfiable(conditions)
      by_field = {}
      req_list(conditions).each do |c|
        next if !Predicates.leaf?(c) || c.key?('ref')

        by_field[c['field']] = tighten_interval(by_field[c['field']] || FULL_INTERVAL, own(c, 'op'), own(c, 'value'))
      end
      by_field.values.none? { |iv| interval_empty(iv) }
    end

    def predicate_numeric_satisfiable(where)
      return true unless where.is_a?(Array)

      numeric_conjunction_satisfiable(where)
    end

    # ---- model ---------------------------------------------------------------------------------------------------------------

    # A value that is not a policy is an empty policy (the verifier admits nothing under it).
    def normalize_policy(p)
      return { 'predicates' => [], 'caveats' => [], 'vetoes' => [], 'tighten' => [] } unless p.is_a?(Hash)

      arr = lambda do |k|
        v = own(p, k)
        v.is_a?(Array) ? v : []
      end
      { 'predicates' => arr.call('predicates'), 'caveats' => arr.call('caveats'), 'vetoes' => arr.call('vetoes'), 'tighten' => arr.call('tighten') }
    end

    # The predicates whose literals shape the grid: the permits plus every veto and tighten trigger.
    def probe_set(m)
      out = m['predicates'].dup
      m['vetoes'].each do |v|
        out << jget(v, 'when')
        unl = jget(v, 'unless')
        out << { 'verb' => '*', 'where' => unl } if unl.is_a?(Array) && !unl.empty?
        over = jget(v, 'over')
        out << { 'verb' => '*', 'where' => [{ 'field' => jget(over, 'path'), 'op' => 'gt', 'value' => jget(over, 'threshold') }] } if truthy?(over)
      end
      m['tighten'].each { |t| out << { 'verb' => '*', 'where' => [jget(t, 'when')] } }
      m['meets'].each { |x| out.concat(probe_set(x)) }
      out
    end

    def condition_undecidable(c, reasons)
      return unless obj?(c)

      if Predicates.group?(c)
        if c.key?('all_of') && c['all_of'].is_a?(Array)
          c['all_of'].each { |x| condition_undecidable(x, reasons) }
        elsif c.key?('any_of') && c['any_of'].is_a?(Array)
          c['any_of'].each { |x| condition_undecidable(x, reasons) }
        elsif c.key?('not')
          condition_undecidable(c['not'], reasons)
        end
        return
      end
      return unless Predicates.leaf?(c)

      reasons['cross-field `ref` condition — the relation between two fields is not resolved'] = nil if c.key?('ref')
      reasons['condition on the whole `action.params` object is not enumerated precisely'] = nil if c['field'] == 'action.params'
      op = own(c, 'op')
      reasons["`#{op}` against a non-numeric operand — string ordering is not enumerated exactly"] = nil if %w[lt lte gt gte].include?(op) && !fin?(own(c, 'value'))
      reasons["`#{op}` condition — matched by over-approximation, not enumerated exactly"] = nil if %w[like matches is_a member_of].include?(op)
    end

    def detect_undecidable(predicates)
      reasons = {}
      predicates.each do |p|
        next unless obj?(p)

        r = own(p, 'resource')
        reasons['re: regex resource matcher — resource dimension cannot be soundly enumerated'] = nil if r.is_a?(String) && r.start_with?('re:')
        w = own(p, 'where')
        w.each { |c| condition_undecidable(c, reasons) } if w.is_a?(Array)
      end
      reasons.keys
    end

    # The analyzable model of a policy: {predicates, caveats, vetoes, tighten, meets, caveatSat, caveatReason?, revCap?, undecidable}.
    def to_model(p)
      n = normalize_policy(p)
      ca = analyze_caveats(n['caveats'])
      meet = p.is_a?(Hash) ? own(p, 'meet') : UNDEF
      meets = meet.is_a?(Array) ? meet.map { |x| to_model(x) } : []
      if ca['sat']
        bad = meets.find { |x| !x['caveatSat'] }
        reason = bad && bad['caveatReason']
      else
        reason = ca['reason']
      end
      caps = ([ca['revCap']] + meets.map { |x| x['revCap'] }).compact
      m = {
        'predicates' => n['predicates'], 'caveats' => n['caveats'], 'vetoes' => n['vetoes'], 'tighten' => n['tighten'], 'meets' => meets,
        'caveatSat' => ca['sat'] && meets.all? { |x| x['caveatSat'] } ? true : false
      }
      m['caveatReason'] = reason unless reason.nil?
      m['revCap'] = caps.min unless caps.empty?
      seen = {}
      detect_undecidable(probe_set(m)).each { |r| seen[r] = nil }
      meets.each { |x| x['undecidable'].each { |r| seen[r] = nil } }
      m['undecidable'] = seen.keys
      m
    end

    # ---- probe collection ----------------------------------------------------------------------------------------------------

    def add_verb_literals(c, into)
      v = own(c, 'value')
      op = own(c, 'op')
      if %w[eq ne prefix like is_a].include?(op)
        set_add(into, v) if v.is_a?(String)
      elsif %w[in nin].include?(op) && v.is_a?(Array)
        v.each { |x| set_add(into, x) if x.is_a?(String) }
      end
    end

    # The grid dimensions {verbs, resources, revClasses, fields:[{path, values}]} of a set of predicate sets
    # ({predicateSets, extraVerbs?, extraResources?, extraFieldConditions?, varyReversibility}); an absent value is ABSENT.
    def collect_probes(inputs)
      verb_literals = []
      nn(inputs['extraVerbs'], []).each { |v| set_add(verb_literals, v) }
      resource_literals = {}
      field_conds = {}

      classify_resource = lambda do |r|
        next if undef?(r) || (r.is_a?(String) && r == '*')
        raise TypeError, 'resource matcher is not a string' unless r.is_a?(String)
        next if r.start_with?('re:')

        if r.end_with?('*')
          body = r[0...-1]
          resource_literals[body] = nil
          resource_literals["#{body}x"] = nil
          next
        end
        resource_literals[r] = nil
      end

      handle_cond = nil
      handle_cond = lambda do |c|
        next unless obj?(c)

        if Predicates.group?(c)
          if c.key?('all_of') && c['all_of'].is_a?(Array)
            c['all_of'].each { |x| handle_cond.call(x) }
          elsif c.key?('any_of') && c['any_of'].is_a?(Array)
            c['any_of'].each { |x| handle_cond.call(x) }
          elsif c.key?('not')
            handle_cond.call(c['not'])
          end
          next
        end
        next unless Predicates.leaf?(c)

        field = c['field']
        if field == 'action.verb'
          add_verb_literals(c, verb_literals)
          next
        end
        if field == 'action.resource'
          v = own(c, 'value')
          if own(c, 'op') == 'prefix' && v.is_a?(String)
            classify_resource.call("#{v}*")
          elsif v.is_a?(String)
            classify_resource.call(v)
          elsif v.is_a?(Array)
            v.each { |x| classify_resource.call(x) if x.is_a?(String) }
          end
          next
        end
        (field_conds[field] ||= []) << c
      end

      req_list(inputs['predicateSets']).each do |lst|
        next unless lst.is_a?(Array)

        lst.each do |p|
          next unless obj?(p)

          verb = own(p, 'verb')
          if verb.is_a?(String)
            set_add(verb_literals, verb) if verb != '*'
          elsif verb.is_a?(Array)
            verb.each { |v| set_add(verb_literals, v) if v.is_a?(String) && v != '*' }
          end
          classify_resource.call(own(p, 'resource'))
          w = own(p, 'where')
          w.each { |c| handle_cond.call(c) } if w.is_a?(Array)
        end
      end
      nn(inputs['extraResources'], []).each { |r| classify_resource.call(r) }
      nn(inputs['extraFieldConditions'], []).each { |ec| handle_cond.call(ec['cond'].merge('field' => ec['path'])) }
      fields = field_conds.map { |path, conds| { 'path' => path, 'values' => field_probes(conds) + [ABSENT] } }
      {
        'verbs' => verb_literals + [FRESH_VERB],
        'resources' => resource_literals.keys + [FRESH_RESOURCE],
        'revClasses' => truthy?(inputs['varyReversibility']) ? AtlasPca::REVERSIBILITY_ORDER.dup : [nil],
        'fields' => fields
      }
    end

    def product_size(pr)
      n = pr['verbs'].length * pr['resources'].length * pr['revClasses'].length
      pr['fields'].each { |f| n *= f['values'].length }
      n
    end

    # ---- representatives -----------------------------------------------------------------------------------------------------

    def each_assignments(fields, i, acc, &blk)
      if i >= fields.length
        blk.call(acc.dup)
        return
      end
      f = fields[i]
      f['values'].each do |v|
        if v.equal?(ABSENT)
          acc.delete(f['path'])
        else
          acc[f['path']] = v
        end
        each_assignments(fields, i + 1, acc, &blk)
      end
    end

    # Every grid point as {verb, resource, revClass (nil = no class), assignments: {path => value}}, in order.
    def each_representative(pr)
      pr['verbs'].each do |verb|
        pr['resources'].each do |resource|
          pr['revClasses'].each do |rev|
            each_assignments(pr['fields'], 0, {}) do |assignments|
              yield({ 'verb' => verb, 'resource' => resource, 'revClass' => rev, 'assignments' => assignments })
            end
          end
        end
      end
    end

    # With a block, every grid point is yielded; without, the list of them.
    def representatives(pr, &blk)
      return each_representative(pr, &blk) if blk

      out = []
      each_representative(pr) { |r| out << r }
      out
    end

    def insert_leaf(root, segs, value)
      node = root
      segs[0...-1].each do |key|
        nxt = node[key]
        if nxt.nil? || nxt.is_a?(Leaf)
          created = {}
          node[key] = created
          node = created
        else
          node = nxt
        end
      end
      node[segs[-1]] = Leaf.new(value)
    end

    def materialize(node)
      node.transform_values { |c| c.is_a?(Leaf) ? c.value : materialize(c) }
    end

    def build_roots(rep)
      roots = { 'action' => {}, 'subject' => {}, 'env' => {} }
      rep['assignments'].each do |path, value|
        segs = path.split('.', -1)
        next if segs.length < 2 || !roots.key?(segs[0])

        insert_leaf(roots[segs[0]], segs[1..], value)
      end
      action = { 'verb' => rep['verb'], 'resource' => rep['resource'], 'params' => {} }
      roots['action'].each do |key, child|
        next if key == 'verb' || key == 'resource'

        if key == 'params'
          action['params'] = materialize(child) unless child.is_a?(Leaf)
        else
          action[key] = child.is_a?(Leaf) ? child.value : materialize(child)
        end
      end
      action['reversibility_class'] = rep['revClass'] unless rep['revClass'].nil?
      { 'action' => action, 'subject' => materialize(roots['subject']), 'env' => materialize(roots['env']) }
    end

    def reversibility_ok(model, rev)
      return true unless model.key?('revCap')
      return false if rev.nil? || undef?(rev) # a reversibility_max caveat denies an action with no class

      rev.is_a?(String) && AtlasPca::REVERSIBILITY_ORDER.include?(rev) && AtlasPca::REVERSIBILITY_ORDER.index(rev) <= model['revCap']
    end

    # Does a veto apply at this context? Veto polarity: whatever cannot be decided counts as applying.
    def veto_applies(v, ctx)
      w = jget(v, 'when')
      return false unless Prohibitions.when_matches?(undef?(w) ? nil : w, ctx)

      over = jget(v, 'over')
      if truthy?(over)
        r = AtlasPca.resolve_path(ctx, jget(over, 'path'))
        val = r['value']
        is_over = !r['found'] || !fin?(val) || val.negative? || js_gt(val, jget(over, 'threshold'))
        return false unless is_over
      end
      unl = jget(v, 'unless')
      if jget(v, 'kind') != 'approval' && truthy?(unl)
        raise TypeError, 'unless.every is not a function' unless unl.is_a?(Array)

        return false if unl.all? { |c| AtlasPca.evaluate_condition(c, ctx) }
      end
      true
    end

    # The ternary decision 'allow' | 'escalate' | 'deny' of the permission layer at a concrete context.
    def decision_at_context(model, ctx)
      return 'deny' unless AtlasPca.evaluate_predicates(model['predicates'], ctx)['allowed']

      escalate = false
      model['vetoes'].each do |v|
        next unless veto_applies(v, ctx)
        return 'deny' if jget(v, 'kind') == 'deny'

        escalate = true
      end
      model['tighten'].each do |t|
        w = jget(t, 'when')
        next if AtlasPca.evaluate_condition_tri(undef?(w) ? nil : w, ctx) == 'false'
        return 'deny' if jget(t, 'signal') == 'deny'

        escalate = true
      end
      own_d = escalate ? 'escalate' : 'allow'
      model['meets'].each do |x|
        d = decision_at_context(x, ctx)
        return 'deny' if d == 'deny'

        own_d = 'escalate' if d == 'escalate'
      end
      own_d
    end

    # Ternary decision of a representative (the static caveat gate first).
    def decide(model, rep)
      return 'deny' unless model['caveatSat']
      return 'deny' unless reversibility_ok(model, rep['revClass'])

      decision_at_context(model, build_roots(rep))
    end

    def admits(model, rep) = decide(model, rep) != 'deny'

    def context_of_action(action)
      act = {}
      verb = jget(action, 'verb')
      resource = jget(action, 'resource')
      act['verb'] = verb unless undef?(verb)
      act['resource'] = resource unless undef?(resource)
      params = jget(action, 'params')
      act['params'] = spread(undef?(params) ? nil : params)
      rc = jget(action, 'reversibilityClass')
      act['reversibility_class'] = rc unless undef?(rc)
      subj = jget(action, 'subject')
      env = jget(action, 'env')
      { 'action' => act, 'subject' => spread(undef?(subj) ? nil : subj), 'env' => spread(undef?(env) ? nil : env) }
    end

    # Ternary decision of a fully-specified action.
    def decide_action(model, action)
      return 'deny' unless model['caveatSat']
      return 'deny' unless reversibility_ok(model, jget(action, 'reversibilityClass'))

      decision_at_context(model, context_of_action(action))
    end

    def admits_action(model, action) = decide_action(model, action) != 'deny'

    def rep_to_action(rep)
      roots = build_roots(rep)
      action = { 'verb' => rep['verb'], 'resource' => rep['resource'], 'params' => roots['action']['params'].dup }
      action['reversibilityClass'] = rep['revClass'] unless rep['revClass'].nil?
      action['subject'] = roots['subject'] unless roots['subject'].empty?
      action['env'] = roots['env'] unless roots['env'].empty?
      action
    end

    # Walk the grid to the first representative the predicate accepts: {hit?, overflow}.
    def search(pr, predicate, mx)
      return { 'overflow' => true } if product_size(pr) > mx

      each_representative(pr) { |rep| return { 'hit' => rep, 'overflow' => false } if predicate.call(rep) }
      { 'overflow' => false }
    end

    # Like `search`, collecting up to `limit` accepted representatives. The predicate is the block, or the first argument.
    def collect(pr, *args, &blk)
      predicate = blk || args.shift
      mx, limit = args
      return { 'hits' => [], 'overflow' => true } if product_size(pr) > mx

      hits = []
      each_representative(pr) do |rep|
        next unless predicate.call(rep)

        hits << rep
        break if hits.length >= limit
      end
      { 'hits' => hits, 'overflow' => false }
    end

    # ---- queries -------------------------------------------------------------------------------------------------------------

    # The grid bound; anything but a non-negative finite number falls back to the default.
    def bound_of(opts)
      m = opts.is_a?(Hash) ? own(opts, 'maxCombinations') : UNDEF
      f = fin(m)
      !f.nil? && f >= 0 ? m : DEFAULT_MAX_COMBINATIONS
    end

    def merge_witness(witness, provided)
      params = (witness['params'] || {}).dup
      pp = jget(provided, 'params')
      params.update(spread(undef?(pp) ? nil : pp))
      out = uobj({ 'verb' => jget(provided, 'verb'), 'resource' => jget(provided, 'resource'), 'params' => params })
      rc = jget(provided, 'reversibilityClass')
      rc = own(witness, 'reversibilityClass') if undef?(rc) || rc.nil?
      out['reversibilityClass'] = rc unless undef?(rc)
      out['subject'] = witness['subject'] if witness.key?('subject')
      out['env'] = witness['env'] if witness.key?('env')
      out
    end

    # Can any input complete `action` into one the policy admits? {reachable, witness?, approximate?, reason?}.
    def reachable(policy, action, opts = nil)
      model = to_model(policy)
      mx = bound_of(opts)
      return { 'reachable' => false, 'reason' => "caveats unsatisfiable: #{model.fetch('caveatReason', 'unknown')}" } unless model['caveatSat']

      rc = jget(action, 'reversibilityClass')
      if !undef?(rc) && model.key?('revCap')
        idx = rc.is_a?(String) && AtlasPca::REVERSIBILITY_ORDER.include?(rc) ? AtlasPca::REVERSIBILITY_ORDER.index(rc) : -1
        return { 'reachable' => false, 'reason' => "reversibility class '#{js_str(rc)}' exceeds the caveat cap" } if idx.negative? || idx > model['revCap']
      end
      return { 'reachable' => true, 'witness' => action } if admits_action(model, action)

      base = collect_probes({ 'predicateSets' => [probe_set(model)], 'varyReversibility' => model.key?('revCap') })
      provided = nn(jget(action, 'params'), {})
      fields = []
      base['fields'].each do |f|
        if f['path'].start_with?('action.params.')
          key = f['path']['action.params.'.length..] || ''
          if provided.is_a?(Hash) && provided.key?(key)
            fields << { 'path' => f['path'], 'values' => [provided[key]] }
            next
          end
        end
        fields << f
      end
      rev_classes = if !undef?(rc) then [rc]
                    elsif model.key?('revCap') then AtlasPca::REVERSIBILITY_ORDER.dup
                    else [nil]
                    end
      pr = { 'verbs' => [jget(action, 'verb')], 'resources' => [jget(action, 'resource')], 'revClasses' => rev_classes, 'fields' => fields }
      outcome = search(pr, ->(rep) { admits(model, rep) }, mx)
      return { 'reachable' => true, 'witness' => merge_witness(rep_to_action(outcome['hit']), action) } if outcome.key?('hit')
      return { 'reachable' => true, 'approximate' => true, 'reason' => 'representative grid exceeded the bound; could not prove unreachable' } if outcome['overflow']

      unless model['undecidable'].empty?
        return {
          'reachable' => true, 'approximate' => true,
          'reason' => "over-approximated (#{model['undecidable'].join('; ')}); could not construct a witness but cannot prove unreachable"
        }
      end
      { 'reachable' => false, 'reason' => 'no predicate admits this action for any input (proven over the decided fragment)' }
    end

    def probes_for(models, verb = nil)
      pr = collect_probes({ 'predicateSets' => models.map { |m| probe_set(m) }, 'varyReversibility' => models.any? { |m| m.key?('revCap') } })
      pr['verbs'] = [verb] unless verb.nil? || undef?(verb)
      pr
    end

    # Does the policy deny everything (optionally restricted to `verb`)? Proven only over the decided fragment.
    def always_denies(policy, verb = nil, opts = nil)
      model = to_model(policy)
      mx = bound_of(opts)
      return { 'alwaysDenies' => true, 'reason' => "caveats unsatisfiable: #{model.fetch('caveatReason', 'unknown')}" } unless model['caveatSat']

      outcome = search(probes_for([model], verb), ->(rep) { admits(model, rep) }, mx)
      return { 'alwaysDenies' => false, 'witness' => rep_to_action(outcome['hit']) } if outcome.key?('hit')
      return { 'alwaysDenies' => false, 'approximate' => true, 'reason' => 'grid exceeded the bound; cannot prove vacuity' } if outcome['overflow']

      unless model['undecidable'].empty?
        return { 'alwaysDenies' => false, 'approximate' => true, 'reason' => "over-approximated (#{model['undecidable'].join('; ')}); cannot prove vacuity" }
      end
      { 'alwaysDenies' => true }
    end

    # Does the policy admit EVERY action of `verb`? Proven only over the decided fragment.
    def always_allows(policy, verb, opts = nil)
      model = to_model(policy)
      mx = bound_of(opts)
      return { 'alwaysAllows' => false, 'reason' => "caveats unsatisfiable: #{model.fetch('caveatReason', 'unknown')}" } unless model['caveatSat']

      outcome = search(probes_for([model], verb), ->(rep) { !admits(model, rep) }, mx)
      return { 'alwaysAllows' => false, 'counterexample' => rep_to_action(outcome['hit']) } if outcome.key?('hit')
      return { 'alwaysAllows' => false, 'approximate' => true, 'reason' => 'grid exceeded the bound; cannot prove totality' } if outcome['overflow']

      unless model['undecidable'].empty?
        return { 'alwaysAllows' => false, 'approximate' => true, 'reason' => "over-approximated (#{model['undecidable'].join('; ')}); cannot prove totality" }
      end
      { 'alwaysAllows' => true }
    end

    def approx_note(models, overflow)
      return 'representative grid exceeded the bound; cannot prove the relation' if overflow

      reasons = {}
      models.each { |m| m['undecidable'].each { |r| reasons[r] = nil } }
      return "over-approximated (#{reasons.keys.join('; ')}); cannot prove the relation" unless reasons.empty?

      nil
    end

    def relation(a, b, opts, pred, key, witness_key)
      ma = to_model(a)
      mb = to_model(b)
      mx = bound_of(opts)
      outcome = search(probes_for([ma, mb]), ->(rep) { pred.call(ma, mb, rep) }, mx)
      return { key => false, witness_key => rep_to_action(outcome['hit']) } if outcome.key?('hit')

      note = approx_note([ma, mb], outcome['overflow'])
      return { key => false, 'approximate' => true, 'reason' => note } unless note.nil?

      { key => true }
    end

    # Does `a` permit everything `b` permits? A counterexample is an action `b` admits that `a` denies.
    def subsumes(a, b, opts = nil)
      relation(a, b, opts, ->(ma, mb, r) { admits(mb, r) && !admits(ma, r) }, 'subsumes', 'counterexample')
    end

    # Is there no action both policies admit? A witness is one both admit.
    def disjoint(a, b, opts = nil)
      relation(a, b, opts, ->(ma, mb, r) { admits(ma, r) && admits(mb, r) }, 'disjoint', 'witness')
    end

    # Do the policies admit exactly the same actions? A counterexample is admitted by exactly one.
    def equivalent(a, b, opts = nil)
      relation(a, b, opts, ->(ma, mb, r) { admits(ma, r) != admits(mb, r) }, 'equivalent', 'counterexample')
    end

    def scope_matches(scope, resource)
      raise TypeError, 'scope.startsWith is not a function' unless scope.is_a?(String)
      return true if scope == '*'

      if scope.start_with?('re:')
        src = scope[3..] || ''
        return false if SafeRegex.utf16_len(src) > 200 || SafeRegex.utf16_len(resource) > Predicates::MAX_RE_RESOURCE_LEN || !AtlasPca.is_safe_regex_source(src)

        return AtlasPca.safe_regex_full_match(src, resource) == true
      end
      return Predicates.starts_with?(resource, scope[0...-1]) if scope.end_with?('*')

      scope == resource
    end

    def intent_violation_kinds(action, intent, amount_field, min_amount)
      kinds = []
      verbs = jget(intent, 'verbs')
      kinds << 'off-verb' unless includes?(verbs, '*') || includes?(verbs, action['verb'])
      scopes = nn(jget(intent, 'resourceScopes'), [])
      req_list(scopes)
      kinds << 'off-scope' if !scopes.empty? && scopes.none? { |s| scope_matches(s, action['resource']) }
      max_amount = jget(intent, 'maxAmount')
      unless undef?(max_amount)
        amt = own(nn(action['params'], {}), amount_field)
        if fin?(amt)
          if js_gt(amt, max_amount)
            kinds << 'over-amount'
          elsif js_lt(amt, min_amount)
            kinds << 'under-amount'
          end
        end
      end
      kinds
    end

    def scope_starts_re(s)
      raise TypeError, 's.startsWith is not a function' unless s.is_a?(String)

      s.start_with?('re:')
    end

    # Does the policy admit ONLY actions inside the declared intent envelope? {conforms, violations, approximate?, reason?}.
    def intent_conformance(policy, intent, opts = nil)
      model = to_model(policy)
      mx = bound_of(opts)
      amount_field = nn(jget(intent, 'amountField'), 'amount')
      min_amount = nn(jget(intent, 'minAmount'), 0)
      return { 'conforms' => true, 'violations' => [] } unless model['caveatSat']

      extra_conds = []
      max_amount = jget(intent, 'maxAmount')
      unless undef?(max_amount)
        path = "action.params.#{js_str(amount_field)}"
        extra_conds << { 'path' => path, 'cond' => { 'field' => path, 'op' => 'lte', 'value' => max_amount } }
        extra_conds << { 'path' => path, 'cond' => { 'field' => path, 'op' => 'gte', 'value' => min_amount } }
      end
      verbs = req_list(jget(intent, 'verbs'))
      pr = collect_probes({
                            'predicateSets' => [probe_set(model)],
                            'extraVerbs' => verbs.reject { |v| v == '*' },
                            'extraResources' => nn(jget(intent, 'resourceScopes'), []),
                            'extraFieldConditions' => extra_conds,
                            'varyReversibility' => model.key?('revCap')
                          })
      fp = 1
      pr['fields'].each { |f| fp *= f['values'].length }
      if pr['verbs'].length * pr['resources'].length * pr['revClasses'].length * fp > mx
        return { 'conforms' => false, 'approximate' => true, 'violations' => [], 'reason' => 'grid exceeded the bound; cannot prove conformance' }
      end

      violations = []
      each_representative(pr) do |rep|
        next unless admits(model, rep)

        action = rep_to_action(rep)
        kinds = intent_violation_kinds(action, intent, amount_field, min_amount)
        next if kinds.empty?

        violations << { 'action' => action, 'kinds' => kinds }
        break if violations.length >= 16
      end
      return { 'conforms' => false, 'violations' => violations } unless violations.empty?

      scopes = nn(jget(intent, 'resourceScopes'), [])
      intent_regex = scopes.any? { |s| scope_starts_re(s) }
      if !model['undecidable'].empty? || intent_regex
        reasons = model['undecidable'].dup
        reasons << 're: intent resource scope not enumerated soundly' if intent_regex
        return { 'conforms' => false, 'approximate' => true, 'violations' => [], 'reason' => "over-approximated (#{reasons.join('; ')}); cannot prove conformance" }
      end
      { 'conforms' => true, 'violations' => [] }
    end

    # Exact admission of a fully-specified action (no existential search).
    def admits_concrete(policy, action) = admits_action(to_model(policy), action)
  end
end
