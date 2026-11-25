# frozen_string_literal: true

# Lint a policy against the action schema / ActionDefs it is written for, and the policy-as-code test runner (boundary-test generation,
# signed test documents). Port of the TypeScript reference (@atlasauth/pca-analyzer).
require_relative 'analyzer_coverage'
require_relative 'analyzer_narrowing'

module AtlasPca
  module Analyzer
    POLICY_TESTS_KIND = 'pca-policy-tests'
    POLICY_TESTS_SIG_DOMAIN = "atlas-pca/policy-tests/v1\0"
    DEF_TYPE = { 'string' => 'string', 'integer' => 'integer', 'boolean' => 'boolean', 'date' => 'date', 'set' => 'set', 'array' => 'array' }.freeze
    NUMERIC_OPS = %w[lt lte gt gte].freeze

    module_function

    def def_shape(p)
      t = jget(p, 'type')
      out = {}
      out['type'] = DEF_TYPE[t] if t.is_a?(String) && DEF_TYPE.key?(t)
      out['semantic'] = jget(p, 'role') if truthy?(jget(p, 'role'))
      out['values'] = jget(p, 'values') if truthy?(jget(p, 'values'))
      out['min'] = jget(p, 'min') unless jget(p, 'min').equal?(UNDEF)
      out['max'] = jget(p, 'max') unless jget(p, 'max').equal?(UNDEF)
      out['sensitivity'] = jget(p, 'sensitivity') if truthy?(jget(p, 'sensitivity'))
      out['required'] = jget(p, 'required') unless jget(p, 'required').equal?(UNDEF)
      out
    end

    def entries_of(o)
      o = nn(o, {})
      raise TypeError, 'Object.entries requires an object' unless o.is_a?(Hash)

      key_order(o).map { |k| [k, o[k]] }
    end

    # Verb shapes from ActionDefs ({verb, params: {name: {type, role?, required?, values?, min?, max?, sensitivity?}}}). Types the
    # policy language cannot compare directly (datetime, duration, object_ref) stay untyped.
    def verb_shapes_from_action_defs(defs)
      req_list(defs).map do |d|
        uobj({ 'verb' => jget(d, 'verb'), 'params' => entries_of(jget(d, 'params')).to_h { |k, p| [k, def_shape(p)] } })
      end
    end

    # The verbs and parameters of a signed action schema ({verbs: [...]}), a list of shapes, or a list of ActionDefs.
    def verb_shapes(src)
      if src.is_a?(Hash) && src.key?('verbs')
        return req_list(src['verbs']).map do |v|
          params = {}
          entries_of(jget(v, 'params')).each do |k, d|
            s = { 'type' => jget(d, 'type') }
            s['values'] = jget(d, 'values') if truthy?(jget(d, 'values'))
            s['min'] = jget(d, 'min') unless jget(d, 'min').equal?(UNDEF)
            s['max'] = jget(d, 'max') unless jget(d, 'max').equal?(UNDEF)
            s['unit'] = jget(d, 'unit') if truthy?(jget(d, 'unit'))
            s['semantic'] = jget(d, 'semantic')
            s['sensitivity'] = jget(d, 'sensitivity')
            s['required'] = jget(d, 'required') unless jget(d, 'required').equal?(UNDEF)
            params[k] = uobj(s)
          end
          uobj({ 'verb' => jget(v, 'verb'), 'params' => params })
        end
      end
      lst = req_list(src)
      shapes = lst.map do |d|
        v = d.is_a?(Hash) && d.key?('verb') ? d['verb'] : false
        v = d.is_a?(Hash) && d.key?('id') ? d['id'] : false unless truthy?(v)
        v = '' unless truthy?(v)
        { 'verb' => v, 'params' => entries_of(jget(d, 'params')).to_h { |k, p| [k, def_shape(p)] } }
      end
      shapes.each_with_index do |v, i|
        orig = nn(jget(lst[i], 'params'), {})
        v['params'].each_key do |k|
          v['params'][k]['semantic'] = orig[k]['semantic'] unless oget(own(orig, k), 'semantic').equal?(UNDEF)
          v['params'][k]['unit'] = orig[k]['unit'] unless oget(own(orig, k), 'unit').equal?(UNDEF)
        end
      end
      shapes
    end

    def leaves_of(c, into)
      return into unless c.is_a?(Hash) || c.is_a?(Array)

      if AtlasPca.group_condition?(c)
        if c.key?('all_of') && c['all_of'].is_a?(Array)
          c['all_of'].each { |x| leaves_of(x, into) }
        elsif c.key?('any_of') && c['any_of'].is_a?(Array)
          c['any_of'].each { |x| leaves_of(x, into) }
        elsif c.key?('not')
          leaves_of(c['not'], into)
        end
      else
        into << c
      end
      into
    end

    def typeof_param(x)
      return 'boolean' if x == true || x == false
      return 'number' if num?(x)
      return 'string' if x.is_a?(String)

      x.equal?(UNDEF) ? 'undefined' : 'object'
    end

    def type_ok?(t, v)
      return true if t.equal?(UNDEF)
      return num?(v) && jsnum(v).finite? if t == 'integer'
      return v == true || v == false if t == 'boolean'
      return v.is_a?(String) if t == 'string' || t == 'date'

      true
    end

    def semantic_money?(d)
      s = nn(jget(d, 'semantic'), '')
      raise TypeError, 'startsWith is not a function' unless s.is_a?(String)

      s.start_with?('money.')
    end

    def grants?(p, verb)
      pv = jget(p, 'verb')
      strict_eq(pv, '*') || strict_eq(pv, verb) || (pv.is_a?(Array) && (includes?(pv, '*') || includes?(pv, verb))) ? true : false
    end

    def numfmt(v) = num_str(jsnum(v))

    def has_verb?(by_verb, v)
      return false if v.is_a?(Array) || v.is_a?(Hash)

      by_verb.key?(v)
    end

    # Lint a policy against the schema it is written for: {ok, findings: [{code, severity, where, message}]}; ok is false when a
    # finding is an error.
    def validate_policy_against_schema(policy, src, o = nil)
      o = {} if o.nil?
      shapes = verb_shapes(src)
      by_verb = {}
      shapes.each { |s| by_verb[g(s, 'verb')] = s }
      schema_units = jget(o, 'schemaUnits')
      schema_units = (src.is_a?(Hash) && src.key?('units') ? g(src, 'units') : UNDEF) if schema_units.equal?(UNDEF) || schema_units.nil?
      model = to_model(policy)
      findings = []
      units = jget(o, 'units')
      list_ungranted = truthy?(jget(o, 'listUngranted'))

      add = ->(code, severity, where, message) { findings << { 'code' => code, 'severity' => severity, 'where' => where, 'message' => message } }

      check = lambda do |p, where, is_veto|
        pv = jget(p, 'verb')
        verbs = if strict_eq(pv, '*') || (pv.is_a?(Array) && includes?(pv, '*')) then shapes.map { |s| g(s, 'verb') }
                elsif pv.is_a?(Array) then pv.dup
                else [pv]
                end
        verbs.each do |v|
          add.call('undeclared-verb', is_veto ? 'warn' : 'error', where, "verb '#{js_str(v)}' is not declared by the schema") unless has_verb?(by_verb, v)
        end
        declared = verbs.select { |v| has_verb?(by_verb, v) }.map { |v| by_verb[v] }
        next if declared.empty?

        pw = nn(jget(p, 'where'), [])
        req_list(pw).each_with_index do |w, wi|
          leaves_of(w, []).each do |c|
            next if !AtlasPca.leaf_condition?(c) || !c['field'].start_with?('action.params.')

            name = c['field']['action.params.'.length..].split('.', -1)[0] || ''
            at = "#{where}.where[#{wi}]"
            having = declared.select { |s| s['params'].key?(name) }
            if having.empty?
              add.call('undeclared-param', 'error', at, "parameter '#{name}' is declared by none of #{declared.map { |s| js_str(g(s, 'verb')) }.join(', ')}")
              next
            end
            if having.length < declared.length
              add.call('undeclared-param', 'warn', at,
                       "parameter '#{name}' is not declared by #{declared.reject { |s| having.any? { |h| s.equal?(h) } }.map { |s| js_str(g(s, 'verb')) }.join(', ')}")
            end
            d = having[0]['params'][name]
            op = g(c, 'op')
            val = g(c, 'value')
            vals = val.is_a?(Array) && (op == 'in' || op == 'nin') ? val : [val]
            dtype = own(d, 'type')
            if !c.key?('ref') && (%w[eq ne in nin] + NUMERIC_OPS).include?(op)
              vals.each do |x|
                add.call('type-mismatch', 'error', at, "'#{name}' is #{js_str(dtype)} but is compared (#{op}) with #{typeof_param(x)}") unless type_ok?(dtype, x)
              end
            end
            if NUMERIC_OPS.include?(op) && !dtype.equal?(UNDEF) && dtype != 'integer'
              if dtype == 'string' || dtype == 'date'
                add.call('ordering-on-string', 'warn', at, "'#{name}' is #{dtype}: ordering follows UTF-8 byte order")
              else
                add.call('type-mismatch', 'error', at, "ordering operator #{op} on #{js_str(dtype)} parameter '#{name}'")
              end
            end
            dvals = own(d, 'values')
            if truthy?(dvals) && (op == 'eq' || op == 'in') && (vals.empty? ? UNDEF : vals[0]).is_a?(String)
              missing = vals.select { |x| x.is_a?(String) && !includes?(dvals, x) }
              if missing.length == vals.length
                add.call('value-not-in-enum', 'error', at, "no value of #{op} #{js_json(vals)} is in the schema's set for '#{name}'")
              elsif !missing.empty?
                add.call('value-not-in-enum', 'warn', at, "#{js_json(missing)} are not in the schema's set for '#{name}'")
              end
            end
            dmin = own(d, 'min')
            dmax = own(d, 'max')
            if dtype == 'integer' && num?(val) && !c.key?('ref')
              v = val
              dead = (op == 'eq' && ((!dmax.equal?(UNDEF) && v > dmax) || (!dmin.equal?(UNDEF) && v < dmin))) ||
                     (op == 'gt' && !dmax.equal?(UNDEF) && v >= dmax) ||
                     (op == 'gte' && !dmax.equal?(UNDEF) && v > dmax) ||
                     (op == 'lt' && !dmin.equal?(UNDEF) && v <= dmin) ||
                     (op == 'lte' && !dmin.equal?(UNDEF) && v < dmin)
              lo = dmin.equal?(UNDEF) || dmin.nil? ? '-inf' : numfmt(dmin)
              hi = dmax.equal?(UNDEF) || dmax.nil? ? 'inf' : numfmt(dmax)
              if dead
                add.call('out-of-range', 'error', at, "'#{name}' #{op} #{numfmt(v)} can never hold: the schema bounds it to [#{lo}, #{hi}]")
              elsif (op == 'lte' && !dmax.equal?(UNDEF) && v >= dmax) || (op == 'gte' && !dmin.equal?(UNDEF) && v <= dmin)
                add.call('redundant-bound', 'info', at, "'#{name}' #{op} #{numfmt(v)} never binds: the schema already bounds it to [#{lo}, #{hi}]")
              end
            end
            dunit = own(d, 'unit')
            next unless truthy?(dunit) && !units.equal?(UNDEF) && (NUMERIC_OPS.include?(op) || op == 'eq') && !is_veto

            tag = own(units, c['field'])
            tag = own(units, "action.params.#{name}") if tag.equal?(UNDEF) || tag.nil?
            sch = schema_units.is_a?(Hash) && dunit.is_a?(String) ? g(schema_units, dunit) : UNDEF
            if tag.equal?(UNDEF) || tag.nil?
              add.call('unit-missing', 'error', at, "'#{name}' carries unit '#{js_str(dunit)}' but the policy has no unit tag for it (rule 20)")
            elsif truthy?(sch) && (!strict_eq(jget(tag, 'kind'), jget(sch, 'kind')) || !strict_eq(jget(tag, 'currency'), jget(sch, 'currency')) ||
                                   !strict_eq(jget(tag, 'exponent'), jget(sch, 'exponent')))
              add.call('unit-mismatch', 'error', at, "'#{name}': policy unit #{js_json(tag)} differs from the schema's #{js_json(sch)} (rule 20)")
            end
          end
        end
      end

      model['predicates'].each_with_index do |p, i|
        next unless p.is_a?(Hash) || p.is_a?(Array)

        check.call(p, "predicates[#{i}]", false)
        r = always_denies({ 'predicates' => [p] })
        add.call('unreachable-predicate', 'warn', "predicates[#{i}]", 'no action can ever match this predicate') if r['alwaysDenies'] && !r['approximate']
      end
      model['vetoes'].each_with_index { |v, i| check.call(jget(v, 'when'), "vetoes[#{i}]", true) }

      # a money verb with no ceiling in any predicate that grants it
      shapes.each do |s|
        sverb = g(s, 'verb')
        money = key_order(s['params']).select { |name| semantic_money?(s['params'][name]) }
        next if money.empty?

        granting = model['predicates'].select { |p| grants?(p, sverb) }
        if granting.empty?
          add.call('verb-not-granted', 'info', js_str(sverb), "the schema declares '#{js_str(sverb)}' but no predicate grants it") if list_ungranted
          next
        end
        money.each do |name|
          path = "action.params.#{name}"
          bounded = lambda do |p|
            req_list(nn(jget(p, 'where'), [])).each do |w|
              src_w = AtlasPca.group_condition?(w) ? { 'all_of' => w.key?('all_of') ? w['all_of'] : [] } : w
              return true if leaves_of(src_w, []).any? { |c| AtlasPca.leaf_condition?(c) && c['field'] == path && %w[lt lte eq in].include?(c['op']) }
            end
            false
          end
          unless granting.all? { |p| bounded.call(p) }
            add.call('unbounded-money', 'warn', js_str(sverb),
                     "'#{js_str(sverb)}' can move '#{name}' with no per-action ceiling in at least one granting predicate")
          end
        end
      end
      if list_ungranted
        shapes.each do |s|
          next if s['params'].values.any? { |d| semantic_money?(d) }

          sverb = g(s, 'verb')
          unless model['predicates'].any? { |p| grants?(p, sverb) }
            add.call('verb-not-granted', 'info', js_str(sverb), "the schema declares '#{js_str(sverb)}' but no predicate grants it")
          end
        end
      end
      { 'ok' => findings.all? { |f| f['severity'] != 'error' }, 'findings' => findings }
    end

    # ---- policy-as-code test runner -----------------------------------------------------------------------------------------

    def policy_tests_doc(policy, cases)
      { 'v' => 1, 'kind' => POLICY_TESTS_KIND, 'policy_digest' => policy_digest_of(to_model(policy)), 'cases' => cases }
    end

    # Run a test document against a policy: {total, passed, failures, digestMatch, ok}. With `requireDigest` a changed policy fails
    # even if every case still passes.
    def run_policy_tests(policy, doc, opts = nil)
      opts = {} if opts.nil?
      model = to_model(policy)
      failures = []
      cases = req_list(jget(doc, 'cases'))
      cases.each do |c|
        w = witness_of(model, jget(c, 'action'))
        decided_by = w['winner']['id']
        exp_by = jget(c, 'decidedBy')
        next unless !strict_eq(w['decision'], jget(c, 'expect')) || (!exp_by.equal?(UNDEF) && !strict_eq(exp_by, decided_by))

        f = uobj({ 'name' => jget(c, 'name'), 'expected' => jget(c, 'expect'), 'got' => w['decision'], 'decidedBy' => decided_by })
        f['expectedDecidedBy'] = exp_by unless exp_by.equal?(UNDEF)
        failures << f
      end
      digest_match = strict_eq(jget(doc, 'policy_digest'), policy_digest_of(model))
      { 'total' => cases.length, 'passed' => cases.length - failures.length, 'failures' => failures, 'digestMatch' => digest_match,
        'ok' => failures.empty? && (jget(opts, 'requireDigest') != true || digest_match) }
    end

    def tests_message(doc)
      POLICY_TESTS_SIG_DOMAIN.b + Digest::SHA256.digest(AtlasPca.hash_canonical(doc).b)
    end

    # The principal signs the confirmed examples. `secret` is the Ed25519 seed.
    def sign_policy_tests(doc, secret, signer_public)
      { 'doc' => doc, 'signer' => signer_public, 'sig' => AtlasPca.b64e(AtlasPca::KeyPair.new(secret).sign(tests_message(doc))) }
    end

    def verify_policy_tests(s, expected_signer)
      return false unless strict_eq(jget(s, 'signer'), expected_signer)

      d = jget(s, 'doc')
      return false if d.equal?(UNDEF) || d.nil? || jget(d, 'kind') != POLICY_TESTS_KIND

      sig = jget(s, 'sig')
      return false unless sig.is_a?(String)

      msg = tests_message(d)
      AtlasPca.verify_b64u(jget(s, 'signer'), msg, sig) ? true : false
    rescue StandardError
      false
    end

    def param_paths(p)
      out = {}
      walk = nil
      walk = lambda do |c|
        next unless c.is_a?(Hash) || c.is_a?(Array)

        o = c.is_a?(Hash) ? c : {}
        f = o['field']
        out[f] = true if f.is_a?(String) && f.start_with?('action.params.')
        %w[all_of any_of].each { |k| o[k].each { |x| walk.call(x) } if o[k].is_a?(Array) }
        walk.call(o['not']) if truthy?(g(o, 'not'))
      end
      w = jget(p, 'where')
      w.each { |c| walk.call(c) } if w.is_a?(Array)
      out.keys
    end

    # Boundary examples for every clause and numeric threshold: one minimal allow per permit, one trigger per prohibition, and the
    # points just below, at and just above each threshold. Expectations are the policy's CURRENT behaviour, to be confirmed.
    def generate_boundary_tests(policy, o = nil)
      o = {} if o.nil?
      eps = nn(jget(o, 'epsilon'), 1)
      model = to_model(policy)
      cases = []
      seen = {}

      add = lambda do |name, action|
        key = js_json(action)
        next if seen.key?(key)

        seen[key] = true
        w = witness_of(model, action)
        c = { 'name' => name, 'action' => action, 'expect' => w['decision'] }
        c['decidedBy'] = w['winner']['id'] unless w['winner']['id'].nil?
        cases << c
      end

      model['predicates'].each_with_index do |p, i|
        r = always_denies({ 'predicates' => [p], 'caveats' => model['caveats'], 'vetoes' => model['vetoes'], 'tighten' => model['tighten'] })
        base = r['witness']
        base = always_denies({ 'predicates' => [p], 'caveats' => model['caveats'] })['witness'] if base.nil?
        next if base.nil? || base.empty?

        add.call("#{permit_id(i)}: minimal admitted action", base)
        param_paths(p).each do |path|
          name = path['action.params.'.length..]
          thresholds_of(to_model({ 'predicates' => [p] }), path).each do |t|
            [['below', t - eps], ['at', t], ['above', t + eps]].each do |tag, v|
              a = base.dup
              a['params'] = (truthy?(base['params']) ? base['params'] : {}).merge(name => v)
              add.call("#{permit_id(i)}: #{name} #{tag} #{numfmt(t)}", a)
            end
          end
        end
        add.call("#{permit_id(i)}: unmentioned resource", base.merge('resource' => "#{base['resource']}/__other__"))
      end
      # a trigger per prohibition: an action some permit would allow and this prohibition stops
      permit_only = model.merge('vetoes' => [], 'tighten' => [])
      pr = collect_probes({ 'predicateSets' => [probe_set(model)], 'varyReversibility' => model.key?('revCap') })
      model['vetoes'].each do |v|
        hits = collect(pr, DEFAULT_MAX_COMBINATIONS, 1) do |rep|
          decide(permit_only, rep) != 'deny' && veto_applies(v, context_of_action(rep_to_action(rep)))
        end['hits']
        add.call("#{js_str(jget(v, 'id'))}: trigger", rep_to_action(hits[0])) unless hits.empty?
      end
      policy_tests_doc(policy, cases)
    end

    # Decision of every case of a test document under `policy`.
    def decide_all(policy, doc)
      model = to_model(policy)
      req_list(jget(doc, 'cases')).map { |c| decide_action(model, jget(c, 'action')) }
    end
  end
end
