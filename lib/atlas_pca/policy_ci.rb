# frozen_string_literal: true

# The policy-safety CI gate. Port of the TypeScript reference (@atlasauth/pca-policy-ci).
#
# It drives the real static analyzer (AtlasPca::Analyzer) over a PCA envelope, grant, compiled policy, bare `{predicates, caveats}`
# or a delegation chain and reports findings: five toggleable rules plus schema mismatch. SOUNDNESS: a hard `error` is emitted only
# from a PROVEN analyzer verdict; any undecidable feature fails safe to a `warn` / `info` that says so. Also the authoring gates
# (`diff_command`, `test_command`, `coverage_command`) and the command line (`run`, `parse_args`). Findings and results are plain
# String-keyed Hashes; options keep the reference's camelCase members.
require_relative '../atlas_pca'
require_relative 'js_compat'
require_relative 'analyzer'

module AtlasPca
  module PolicyCi
    extend AnalyzerJs

    UNDEF = AnalyzerJs::UNDEF
    A = AtlasPca::Analyzer

    DEFAULT_DANGEROUS_VERBS = %w[delete destroy drop remove purge transfer payout wire withdraw admin grant revoke deploy shutdown rotate].freeze
    SEVERITY_RANK = { 'info' => 1, 'warn' => 2, 'error' => 3 }.freeze
    SCOPE_NARROWING_CAVEATS = %w[max_blast_radius rate reversibility_max budget_alloc delegation_depth].freeze
    BUDGET_GATE_CAVEATS = %w[max_blast_radius rate budget_alloc].freeze
    ENVELOPE_CAVEAT_TYPE = AtlasPca::ENVELOPE_CAVEAT

    # JavaScript String.prototype.trim whitespace
    JS_WS = "[\t\n\v\f\r    -     　﻿]"
    TRIM_RE = /\A#{JS_WS}+|#{JS_WS}+\z/o

    ORDERED_CAVEATS = [%w[expires at min], %w[not_before at max], %w[max_blast_radius max min], %w[delegation_depth max min],
                       %w[budget_alloc limit min]].freeze
    NUMERIC_OPS = %w[lt lte gt gte eq].freeze
    SEVERITIES = %w[error warn info].freeze
    GH_LEVEL = { 'error' => 'error', 'warn' => 'warning', 'info' => 'notice' }.freeze
    TEXT_TAG = { 'error' => 'ERROR', 'warn' => 'WARN', 'info' => 'INFO' }.freeze
    ERRNO_TEXT = { 2 => %w[ENOENT no\ such\ file\ or\ directory], 13 => %w[EACCES permission\ denied],
                   21 => %w[EISDIR illegal\ operation\ on\ a\ directory] }.freeze
    VALUED = %w[--verb --amount-field --window-secs --max-exposure-increase --min-clauses --min-boundaries --min-mutation --max-survivors].freeze
    BOOLS = %w[--allow-widen --integer --require-digest].freeze
    JS_NUMBER = /\A[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\z/

    module_function

    def trim(s) = s.gsub(TRIM_RE, '')
    def record?(x) = x.is_a?(Hash)
    # `typeof x === 'object'`: an array, an object or null
    def js_object?(x) = x.nil? || x.is_a?(Hash) || x.is_a?(Array)

    def verbs_of(verb)
      return [verb] if verb.is_a?(String)
      return verb.select { |x| x.is_a?(String) } if verb.is_a?(Array)

      []
    end

    # A finite number, else UNDEF.
    def finite_num(x) = num?(x) && jsnum(x).finite? ? x : UNDEF

    def dangerous_verb?(verb, dangerous)
      raise TypeError, 'dangerous.some is not a function' unless dangerous.is_a?(Array)

      v = verb.downcase
      dangerous.any? do |kw|
        raise TypeError, 'kw.toLowerCase is not a function' unless kw.is_a?(String)

        v.include?(kw.downcase)
      end
    end

    def wildcard_resource?(resource) = resource.equal?(UNDEF) || resource == '*'

    def caveat_of_type?(caveats, types)
      caveats.any? { |c| c.is_a?(Hash) && c['type'].is_a?(String) && types.include?(c['type']) }
    end

    def describe_action(a)
      parts = [js_str(jget(a, 'verb')), js_str(jget(a, 'resource'))]
      params = jget(a, 'params')
      parts << js_json(params) if truthy?(params) && params.is_a?(Hash) && !params.empty?
      rc = jget(a, 'reversibilityClass')
      parts << "[#{js_str(rc)}]" unless rc.equal?(UNDEF)
      parts.join(' ')
    end

    def find(rule, severity, message, where = nil)
      f = { 'rule' => rule, 'severity' => severity, 'message' => message }
      f['where'] = where unless where.nil?
      f
    end

    # ---- normalization ---------------------------------------------------------------------------------------------------

    # A minted grant / delegation hop: the content-addressed, signed shape of a capability.
    def capability?(x)
      record?(x) && x['id'].is_a?(String) && x['issuer'].is_a?(String) && x['holder'].is_a?(String) &&
        x['body_digest'].is_a?(String) && x['sig'].is_a?(String) && x['caveats'].is_a?(Array)
    end

    # A signed policy envelope (the root intent grant payload).
    def envelope?(x)
      record?(x) && x['goal_commit'].is_a?(String) && x['predicates'].is_a?(Array) && x['caveats'].is_a?(Array) &&
        record?(x['agent_binding']) && record?(x['risk_policy'])
    end

    def compiled?(x)
      record?(x) && x['predicates'].is_a?(Array) && x['caveats'].is_a?(Array) && record?(x['riskPolicy']) && x['actions'].is_a?(Array)
    end

    # Drop the envelope-carrying caveat; keep the runtime gate caveats (and any appended attenuation).
    def runtime_caveats(caveats)
      caveats.select { |c| (c.is_a?(Hash) || c.is_a?(Array)) && !(c.is_a?(Hash) && c['type'] == ENVELOPE_CAVEAT_TYPE) }
    end

    def from_grant(grant)
      env = AtlasPca.read_envelope(grant)
      return { 'ok' => false, 'reason' => 'grant has no readable `envelope` caveat (malformed or unsigned payload)' } if env.nil?

      cs = grant['caveats']
      appended = runtime_caveats(cs.is_a?(Array) ? cs : [])
      { 'ok' => true, 'policy' => { 'predicates' => env['predicates'], 'caveats' => env['caveats'].dup + appended,
                                    'riskPolicy' => env['risk_policy'], 'kind' => 'grant' } }
    end

    # Reduce any single-policy input to its effective authority: {ok: true, policy: {predicates, caveats, riskPolicy?, kind}} or
    # {ok: false, reason}.
    def normalize_policy_input(input)
      return from_grant(input) if capability?(input)
      if envelope?(input)
        return { 'ok' => true, 'policy' => { 'predicates' => input['predicates'], 'caveats' => input['caveats'],
                                             'riskPolicy' => input['risk_policy'], 'kind' => 'envelope' } }
      end
      if compiled?(input)
        return { 'ok' => true, 'policy' => { 'predicates' => input['predicates'], 'caveats' => input['caveats'],
                                             'riskPolicy' => input['riskPolicy'], 'kind' => 'compiled' } }
      end
      if record?(input) && input['predicates'].is_a?(Array)
        c = input['caveats']
        return { 'ok' => true, 'policy' => { 'predicates' => input['predicates'], 'caveats' => c.is_a?(Array) ? c : [], 'kind' => 'bare' } }
      end
      { 'ok' => false, 'reason' => 'unrecognized policy shape (expected an envelope, grant, compiled policy, or { predicates, caveats })' }
    end

    # Normalize a delegation chain (root to leaf) to one effective policy per hop: {ok: true, hops} or {ok: false, reason}.
    def normalize_chain(chain)
      req_list(chain)
      return { 'ok' => false, 'reason' => 'empty chain' } if chain.empty?

      if chain.all? { |c| capability?(c) }
        env = AtlasPca.read_envelope(chain[0])
        return { 'ok' => false, 'reason' => 'root grant has no readable `envelope` caveat' } if env.nil?

        hops = chain.map do |cap|
          cs = cap['caveats']
          { 'predicates' => env['predicates'], 'caveats' => env['caveats'].dup + runtime_caveats(cs.is_a?(Array) ? cs : []),
            'riskPolicy' => env['risk_policy'], 'kind' => 'chain-hop' }
        end
        return { 'ok' => true, 'hops' => hops }
      end
      hops = []
      chain.each_with_index do |c, i|
        r = normalize_policy_input(c)
        return { 'ok' => false, 'reason' => "hop #{i}: #{r['reason']}" } unless r['ok']

        hops << r['policy'].merge('kind' => 'chain-hop')
      end
      { 'ok' => true, 'hops' => hops }
    end

    # ---- rules -----------------------------------------------------------------------------------------------------------

    def analyzer_input(p) = { 'predicates' => p['predicates'], 'caveats' => p['caveats'] }

    def declared_verbs(predicates)
      concrete = []
      predicates.each do |p|
        next unless p.is_a?(Hash) || p.is_a?(Array)

        verbs_of(p.is_a?(Hash) ? p['verb'] : nil).each { |v| concrete << v unless v == '*' }
      end
      concrete.uniq
    end

    def gate_description(policy)
      gates = []
      if caveat_of_type?(policy['caveats'], BUDGET_GATE_CAVEATS)
        gates << policy['caveats'].select { |c| includes?(BUDGET_GATE_CAVEATS, jget(c, 'type')) }.map { |c| js_str(jget(c, 'type')) }.join('/')
      end
      rp = policy['riskPolicy']
      unless rp.nil? || rp.equal?(UNDEF)
        t2 = rp.is_a?(Hash) && rp.key?('theta2') ? rp['theta2'] : UNDEF
        gates << 'risk step-up (theta2 < 1)' if num?(t2) && jsnum(t2).finite? && jsnum(t2) < 1
      end
      gates.empty? ? nil : gates.join(', ')
    end

    # A wildcard verb or resource, a dangerous verb with no narrowing, or a proven always-allow.
    def rule_over_broad_grant(policy, dangerous, opts)
      out = []
      inp = analyzer_input(policy)
      scope_narrowing = caveat_of_type?(policy['caveats'], SCOPE_NARROWING_CAVEATS)
      policy['predicates'].each_with_index do |p, i|
        next unless p.is_a?(Hash) || p.is_a?(Array)

        d = p.is_a?(Hash) ? p : {}
        verbs = verbs_of(d['verb'])
        where = "predicates[#{i}]"
        w = d['where']
        has_where = w.is_a?(Array) && !w.empty?
        out << find('over-broad-grant', 'error', "predicate grants a WILDCARD verb '*' — authority over any action", where) if verbs.include?('*')
        if wildcard_resource?(own(d, 'resource'))
          dv = verbs.select { |v| dangerous_verb?(v, dangerous) }
          if !dv.empty?
            out << find('over-broad-grant', 'error', "dangerous verb(s) #{js_json(dv)} granted on a WILDCARD resource ('*')", where)
          elsif !verbs.include?('*')
            out << find('over-broad-grant', 'warn', "predicate matches ANY resource ('*') — consider a resource prefix", where)
          end
        end
        verbs.each do |v|
          next unless v != '*' && dangerous_verb?(v, dangerous) && !has_where && !scope_narrowing

          out << find('over-broad-grant', 'error',
                      "dangerous verb '#{v}' is granted with NO narrowing `where` and no scope-narrowing caveat (#{SCOPE_NARROWING_CAVEATS.join('/')})", where)
        end
      end
      declared_verbs(policy['predicates']).each do |v|
        aa = A.always_allows(inp, v, opts)
        if aa['alwaysAllows'] && aa['approximate'] != true
          out << find('over-broad-grant', 'error', "grants EVERY action of '#{v}' — the authority has no effective constraint (always-allow)")
        end
      end
      out
    end

    # A delegation hop whose effective authority is not a subset of its parent's.
    def rule_privilege_escalation(hops, opts)
      out = []
      (1...hops.length).each do |i|
        s = A.subsumes(analyzer_input(hops[i - 1]), analyzer_input(hops[i]), opts)
        where = "hop[#{i}]"
        next if s['subsumes']

        if s['approximate'] == true
          reason = s['reason']
          out << find('privilege-escalation', 'warn',
                      "could not prove hop #{i} attenuation (undecidable#{truthy?(reason) ? ": #{reason}" : ''}) — attenuation not verified", where)
        else
          ce = s['counterexample']
          ex = ce.nil? ? '' : " — child admits '#{describe_action(ce)}' which its parent denies"
          out << find('privilege-escalation', 'error',
                      "delegation hop #{i} ESCALATES authority: its effective authority is not a subset of its parent (attenuation violated)#{ex}", where)
        end
      end
      out
    end

    def interval_eq(a, b)
      a['lo'] == b['lo'] && a['loInclusive'] == b['loInclusive'] && a['hi'] == b['hi'] && a['hiInclusive'] == b['hiInclusive']
    end

    # A numeric leaf condition that does not tighten its field's interval is redundant (never binds).
    def non_binding_conditions(where, pred_index)
      by_field = {}
      where.each_with_index do |c, i|
        next if !AtlasPca.leaf_condition?(c) || c.key?('ref')
        next unless c['op'].is_a?(String) && NUMERIC_OPS.include?(c['op'])
        next if finite_num(own(c, 'value')).equal?(UNDEF)

        (by_field[c['field']] ||= []) << [c, i]
      end
      out = []
      by_field.each do |field, conds|
        next if conds.length < 2

        full = conds.reduce(A::FULL_INTERVAL) { |iv, e| A.tighten_interval(iv, e[0]['op'], e[0]['value']) }
        next if A.interval_empty(full)

        conds.each do |e|
          without = conds.reject { |x| x.equal?(e) }.reduce(A::FULL_INTERVAL) { |iv, x| A.tighten_interval(iv, x[0]['op'], x[0]['value']) }
          next unless interval_eq(without, full)

          out << find('redundant-caveat', 'info',
                      "condition on '#{field}' (#{e[0]['op']} #{js_str(e[0]['value'])}) does not tighten the authority — redundant with the other bounds on this field",
                      "predicates[#{pred_index}].where[#{e[1]}]")
        end
      end
      out
    end

    # A caveat or condition that can never bite: a duplicate, one subsumed by a stricter one, an unsatisfiable predicate, a
    # non-binding bound.
    def rule_redundant_caveat(policy)
      out = []
      caveats = policy['caveats']
      seen = {}
      caveats.each_with_index do |cv, i|
        next unless cv.is_a?(Hash) || cv.is_a?(Array)

        k = js_json(cv)
        if seen.key?(k)
          out << find('redundant-caveat', 'warn', "caveat #{i} ('#{js_str(jget(cv, 'type'))}') is an exact duplicate of caveat #{seen[k]} — dead policy", "caveats[#{i}]")
        else
          seen[k] = i
        end
      end
      ORDERED_CAVEATS.each do |typ, field, keep|
        vals = []
        caveats.each_with_index do |cv, i|
          next unless cv.is_a?(Hash) && cv['type'] == typ

          v = finite_num(own(cv, field))
          vals << [i, v] unless v.equal?(UNDEF)
        end
        next if vals.length < 2

        nums = vals.map { |_i, v| jsnum(v) }
        binding_v = keep == 'min' ? nums.min : nums.max
        vals.each do |i, v|
          next if jsnum(v) == binding_v

          out << find('redundant-caveat', 'warn',
                      "caveat #{i} ('#{typ}' #{field}=#{num_str(jsnum(v))}) is subsumed by a stricter '#{typ}' (#{field}=#{num_str(binding_v)}) — it can never bite", "caveats[#{i}]")
        end
      end
      policy['predicates'].each_with_index do |p, i|
        next unless p.is_a?(Hash) && p['where'].is_a?(Array)

        w = p['where']
        if !A.predicate_numeric_satisfiable(w)
          out << find('redundant-caveat', 'warn', "predicate #{i} can never match — its numeric `where` constraints are unsatisfiable (dead policy)", "predicates[#{i}]")
        else
          out.concat(non_binding_conditions(w, i))
        end
      end
      out
    end

    # A dangerous (verb, resource) the analyzer PROVES reachable, with no budget / rate / step-up gate (error) or with one (info).
    def rule_dangerous_reachability(policy, dangerous, extra_targets, opts)
      out = []
      inp = analyzer_input(policy)
      derived = declared_verbs(policy['predicates']).select { |v| dangerous_verb?(v, dangerous) }.map { |v| { 'verb' => v } }
      extra = if extra_targets.is_a?(Array) then extra_targets
              elsif extra_targets.is_a?(String) then extra_targets.chars
              else raise TypeError, 'extraTargets is not iterable'
              end
      gate = gate_description(policy)
      (derived + extra).each do |t|
        verb = jget(t, 'verb')
        resource = jget(t, 'resource')
        if !resource.equal?(UNDEF)
          r = A.reachable(inp, { 'verb' => verb, 'resource' => resource }, opts)
          proven = r['reachable'] ? r['approximate'] != true : false
          approximate = r['approximate'] == true
          reason = r['reason']
          witness = "#{js_str(verb)} #{js_str(resource)}"
        else
          ad = A.always_denies(inp, verb, opts)
          proven = ad['alwaysDenies'] == false && ad['approximate'] != true
          approximate = ad['approximate'] == true
          reason = ad['reason']
          witness = ad.key?('witness') ? describe_action(ad['witness']) : js_str(verb)
        end
        if approximate
          out << find('dangerous-reachability', 'warn', "could not decide reachability of dangerous verb '#{js_str(verb)}' (undecidable#{truthy?(reason) ? ": #{reason}" : ''})")
        elsif proven
          out << if gate.nil?
                   find('dangerous-reachability', 'error', "dangerous action '#{witness}' is REACHABLE with no budget / rate / step-up gate")
                 else
                   find('dangerous-reachability', 'info', "dangerous action '#{witness}' is reachable but gated by #{gate}")
                 end
        end
      end
      out
    end

    def non_trivial?(policy, dangerous)
      policy['predicates'].any? do |p|
        next false unless p.is_a?(Hash) || p.is_a?(Array)

        d = p.is_a?(Hash) ? p : {}
        verbs = verbs_of(d['verb'])
        w = d['where']
        has_where = w.is_a?(Array) && !w.empty?
        verbs.include?('*') || verbs.any? { |v| dangerous_verb?(v, dangerous) } || wildcard_resource?(own(d, 'resource')) || !has_where
      end
    end

    # No `expires` caveat, or no blast-radius / rate / budget gate on a non-trivial grant.
    def rule_missing_safety_floor(policy, cfg, dangerous)
      out = []
      return out if policy['predicates'].empty?

      if cfg['requireExpiry'] && !caveat_of_type?(policy['caveats'], ['expires'])
        out << find('missing-safety-floor', 'warn', 'grant has no `expires` caveat — the authority never expires')
      end
      if cfg['requireScopeGate'] && non_trivial?(policy, dangerous) && !caveat_of_type?(policy['caveats'], BUDGET_GATE_CAVEATS)
        out << find('missing-safety-floor', 'warn', "non-trivial grant has no blast-radius / rate / budget gate (#{BUDGET_GATE_CAVEATS.join('/')})")
      end
      out
    end

    # The policy compared with the action schema it is written for.
    def rule_schema_mismatch(policy, schema, options = nil)
      r = A.validate_policy_against_schema({ 'predicates' => policy['predicates'], 'caveats' => policy['caveats'] }, schema, options)
      r['findings'].map do |f|
        out = { 'rule' => 'schema-mismatch', 'severity' => f['severity'], 'message' => "#{f['code']}: #{f['message']}" }
        out['where'] = f['where'] if f.key?('where')
        out
      end
    end

    # ---- lint ------------------------------------------------------------------------------------------------------------

    # A rule that throws is a finding, not a crash and not silence: a gate must not pass a policy it could not finish checking.
    def guarded(rule)
      yield
    rescue StandardError => e
      [{ 'rule' => 'internal-error', 'severity' => 'error', 'message' => "rule #{rule} could not run: #{e.message}" }]
    rescue SystemStackError
      [{ 'rule' => 'internal-error', 'severity' => 'error', 'message' => "rule #{rule} could not run: Maximum call stack size exceeded" }]
    end

    def rule_verbs(o)
      js_object?(o) && truthy?(jget(o, 'dangerousVerbs')) ? jget(o, 'dangerousVerbs') : DEFAULT_DANGEROUS_VERBS
    end

    def resolve_rules(rules)
      r = nn(rules, {})
      ob = jget(r, 'overBroadGrant')
      dr = jget(r, 'dangerousReachability')
      sf = jget(r, 'missingSafetyFloor')
      {
        'overBroadGrant' => { 'enabled' => !false.equal?(ob), 'dangerousVerbs' => rule_verbs(ob) },
        'privilegeEscalation' => !false.equal?(jget(r, 'privilegeEscalation')),
        'redundantCaveat' => !false.equal?(jget(r, 'redundantCaveat')),
        'dangerousReachability' => { 'enabled' => !false.equal?(dr), 'dangerousVerbs' => rule_verbs(dr),
                                     'targets' => js_object?(dr) && truthy?(jget(dr, 'targets')) ? jget(dr, 'targets') : [] },
        'missingSafetyFloor' => { 'enabled' => !false.equal?(sf),
                                  'requireExpiry' => js_object?(sf) ? !false.equal?(jget(sf, 'requireExpiry')) : true,
                                  'requireScopeGate' => js_object?(sf) ? !false.equal?(jget(sf, 'requireScopeGate')) : true }
      }
    end

    def analyzer_opts(opts)
      mc = opts.is_a?(Hash) ? jget(opts, 'maxCombinations') : UNDEF
      mc.equal?(UNDEF) ? {} : { 'maxCombinations' => mc }
    end

    def single_rules(cfg, policy, ao)
      out = []
      if cfg['overBroadGrant']['enabled']
        out.concat(guarded('over-broad-grant') { rule_over_broad_grant(policy, cfg['overBroadGrant']['dangerousVerbs'], ao) })
      end
      out.concat(guarded('redundant-caveat') { rule_redundant_caveat(policy) }) if cfg['redundantCaveat']
      dr = cfg['dangerousReachability']
      if dr['enabled']
        out.concat(guarded('dangerous-reachability') { rule_dangerous_reachability(policy, dr['dangerousVerbs'], dr['targets'], ao) })
      end
      if cfg['missingSafetyFloor']['enabled']
        out.concat(guarded('missing-safety-floor') { rule_missing_safety_floor(policy, cfg['missingSafetyFloor'], cfg['overBroadGrant']['dangerousVerbs']) })
      end
      out
    end

    # Lint a single PCA policy (an envelope, a minted grant, a compiled policy or a bare `{predicates, caveats?}`). All findings
    # (empty = clean). `opts`: {rules?, schema?, schemaOptions?, maxCombinations?}.
    def lint_policy(input, opts = nil)
      opts = {} if opts.nil?
      norm = normalize_policy_input(input)
      return [{ 'rule' => 'malformed-policy', 'severity' => 'error', 'message' => norm['reason'] }] unless norm['ok']

      cfg = resolve_rules(jget(opts, 'rules'))
      ao = analyzer_opts(opts)
      policy = norm['policy']
      out = single_rules(cfg, policy, ao)
      schema = jget(opts, 'schema')
      unless schema.equal?(UNDEF)
        so = jget(opts, 'schemaOptions')
        out.concat(guarded('schema-mismatch') { rule_schema_mismatch(policy, schema, so.equal?(UNDEF) ? nil : so) })
      end
      out
    end

    # Lint a delegation chain (root to leaf): privilege escalation across every consecutive pair, then the single-policy rules on
    # the acting LEAF's effective authority.
    def lint_chain(chain, opts = nil)
      opts = {} if opts.nil?
      norm = normalize_chain(chain)
      return [{ 'rule' => 'malformed-policy', 'severity' => 'error', 'message' => norm['reason'] }] unless norm['ok']

      cfg = resolve_rules(jget(opts, 'rules'))
      ao = analyzer_opts(opts)
      hops = norm['hops']
      out = []
      out.concat(guarded('privilege-escalation') { rule_privilege_escalation(hops, ao) }) if cfg['privilegeEscalation']
      out.concat(single_rules(cfg, hops[-1], ao)) unless hops.empty?
      out
    end

    # An array input is a delegation chain; anything else is a single policy.
    def lint(input, opts = nil) = input.is_a?(Array) ? lint_chain(input, opts) : lint_policy(input, opts)

    # The own severity key a value names (a property key is coerced the way JavaScript coerces it), else nil.
    def rank_key(k)
      s = js_str(k)
      SEVERITY_RANK.key?(s) ? s : nil
    end

    # Roll labeled findings into counts and an exit code (0 ok, 1 a finding reaches the threshold, 2 nothing was linted).
    def summarize(results, opts = nil)
      opts = {} if opts.nil?
      max_severity = nn(jget(opts, 'maxSeverity'), 'error')
      mk = rank_key(max_severity)
      # an unknown threshold would make every comparison false and pass everything
      raise ArgumentError, "summarize: maxSeverity must be one of #{SEVERITY_RANK.keys.join(', ')}" if mk.nil?

      counts = { 'error' => 0, 'warn' => 0, 'info' => 0 }
      if !results.is_a?(Array) || results.empty?
        return { 'results' => [], 'counts' => counts, 'maxSeverity' => max_severity, 'ok' => false, 'exitCode' => 2, 'reason' => 'no policies were linted' }
      end

      failing = 0
      threshold = SEVERITY_RANK[mk]
      results.each do |r|
        req_list(jget(r, 'findings')).each do |f|
          sev = rank_key(jget(f, 'severity')) || 'error' # a severity that is not one of the three counts as an error
          counts[sev] += 1
          failing += 1 if SEVERITY_RANK[sev] >= threshold
        end
      end
      ok = failing.zero?
      { 'results' => results, 'counts' => counts, 'maxSeverity' => max_severity, 'ok' => ok, 'exitCode' => ok ? 0 : 1 }
    end

    # Lint a list of labeled policies (or chains) and roll the findings into a summary.
    def lint_policies(items, opts = nil)
      opts = {} if opts.nil?
      results = req_list(items).each_with_index.map do |item, i|
        label = nn(jget(item, 'label'), "policy[#{i}]")
        { 'label' => label, 'findings' => lint(jget(item, 'policy'), opts) }
      end
      summarize(results, opts)
    end

    # ---- pinned lint rule list -------------------------------------------------------------------------------------------

    LINT_RULES_DIGEST_DOMAIN = 'atlas-pca/action-lint-rules/v1'
    LINT_RULES = [
      ['LD-001', 'error', 'a destroy-like verb whose effects do not delete'],
      ['LD-002', 'error', 'a money parameter without a currency, or a currency without the iso_currency format'],
      ['LD-003', 'error', 'a numeric parameter without min and max'],
      ['LD-004', 'error', 'a money-moving action without idempotency'],
      ['LD-005', 'error', 'personal data can leave without the matching effect'],
      ['LD-006', 'error', 'a declared reversibility or blast below the effective floor'],
      ['LD-007', 'error', 'an unknown trait, role, format, effect or context key, or an invalid custom trait'],
      ['LD-008', 'error', "resource id '*' with scope one"],
      ['LD-009', 'error', 'a duplicate verb or alias collision'],
      ['LD-010', 'error', 'a write marked reversible with no compensating action in the pack'],
      ['LD-011', 'error', 'review state confirmed without a valid attestation for this digest'],
      ['LD-012', 'error', 'a structural param rule that the effective traits require is violated'],
      ['LD-013', 'error', 'a read-only action that can mutate or handles credentials'],
      ['LD-014', 'error', 'one binding in two defs'],
      ['LW-001', 'warning', 'description missing or too long, or title not imperative'],
      ['LW-002', 'warning', 'a string parameter without max_len'],
      ['LW-003', 'warning', 'free text flows into an outbound action without the free_text_outbound tag'],
      ['LW-004', 'warning', 'an unreviewed def in a stable pack'],
      ['LW-005', 'warning', 'a dismissed suggested trait without a reason'],
      ['LW-006', 'warning', 'an array parameter without max_items'],
      ['LW-007', 'warning', 'a critical parameter without provenance_min'],
      ['LW-008', 'warning', 'verb naming inconsistent with its siblings or with the file namespace'],
      ['LW-009', 'warning', 'a money-moving, destructive or privilege-changing action without an example'],
      ['LW-010', 'warning', 'since is missing']
    ].freeze
    DIGEST_RE = /\A[A-Za-z0-9_-]{43}\z/

    # The digest the CI gate pins: the ordered (id, severity, title) list of the action-kit lint rules.
    def lint_rules_digest
      AtlasPca.hash_canonical({ 'd' => LINT_RULES_DIGEST_DOMAIN, 'rules' => LINT_RULES.map { |i, s, t| { 'id' => i, 'severity' => s, 'title' => t } } })
    end

    # Enforce the pinned digest of the lint rule list: `pin_text` is the content of the pin file (one digest, surrounding
    # whitespace ignored). Adding, removing or rewording a rule fails here until the pin is updated in the same change.
    def check_lint_rules_pin(pin_text, actual = nil)
      actual = lint_rules_digest if actual.nil?
      pinned = trim(pin_text)
      return { 'ok' => false, 'message' => 'the lint rules pin is not a digest (expected 43 base64url characters)' } unless DIGEST_RE.match?(pinned)
      return { 'ok' => true, 'message' => "lint rules digest #{actual} matches the pin" } if pinned == actual

      { 'ok' => false, 'message' => "lint rules digest #{actual} differs from the pin #{pinned}: the rule list changed; review it and update the pin" }
    end

    # ---- authoring gates -------------------------------------------------------------------------------------------------

    def bad(line) = { 'ok' => false, 'exitCode' => 2, 'lines' => [line] }

    # A policy document as the analyzer reads it: any shape `lint` accepts, plus optional `vetoes` and `tighten` members.
    def to_analyzer_policy(doc)
      n = normalize_policy_input(doc)
      return n unless n['ok']

      policy = { 'predicates' => n['policy']['predicates'], 'caveats' => n['policy']['caveats'] }
      if record?(doc)
        policy['vetoes'] = doc['vetoes'] if doc['vetoes'].is_a?(Array)
        policy['tighten'] = doc['tighten'] if doc['tighten'].is_a?(Array)
      end
      { 'ok' => true, 'policy' => policy }
    end

    # `diff`: does this change widen authority, or raise the most that can leave? {ok, exitCode (0 ok, 1 gate failed, 2 unusable
    # input), lines}.
    def diff_command(old_doc, new_doc, o = nil)
      o = {} if o.nil?
      a = to_analyzer_policy(old_doc)
      b = to_analyzer_policy(new_doc)
      return bad("old policy: #{a['reason']}") unless a['ok']
      return bad("new policy: #{b['reason']}") unless b['ok']

      verb = jget(o, 'verb')
      opts = {}
      unless verb.equal?(UNDEF)
        ex = { 'verb' => verb }
        ex['amountField'] = jget(o, 'amountField') if truthy?(jget(o, 'amountField'))
        ex['integer'] = true if truthy?(jget(o, 'integer'))
        ex['windowSecs'] = jget(o, 'windowSecs') unless jget(o, 'windowSecs').equal?(UNDEF)
        opts = { 'exposure' => ex }
      end
      d = A.diff_policies(a['policy'], b['policy'], opts)
      allow = { 'widen' => jget(o, 'allowWiden') == true }
      allow['maxExposureIncrease'] = jget(o, 'maxExposureIncrease') unless jget(o, 'maxExposureIncrease').equal?(UNDEF)
      gate = A.diff_gate(d, allow)
      lines = if d['equivalent'] then ['no change in what is admitted']
              elsif !d['summary'].empty? then d['summary'].dup
              else ['no witness found']
              end
      gate['reasons'].each { |r| lines << "FAIL: #{r}" } unless gate['ok']
      lines << (gate['ok'] ? 'PASS' : 'FAIL')
      { 'ok' => gate['ok'], 'exitCode' => gate['ok'] ? 0 : 1, 'lines' => lines }
    end

    # `test`: a policy test document against a policy, pinned by digest with `requireDigest`.
    def test_command(policy_doc, tests_doc, o = nil)
      o = {} if o.nil?
      p = to_analyzer_policy(policy_doc)
      return bad("policy: #{p['reason']}") unless p['ok']
      return bad('tests: not a pca-policy-tests document') if !record?(tests_doc) || tests_doc['kind'] != 'pca-policy-tests' || !tests_doc['cases'].is_a?(Array)

      rd = jget(o, 'requireDigest')
      r = A.run_policy_tests(p['policy'], tests_doc, rd.equal?(UNDEF) ? {} : { 'requireDigest' => rd })
      lines = r['failures'].map do |f|
        eb = f['expectedDecidedBy']
        by = f['decidedBy']
        "FAIL #{js_str(own(f, 'name'))}: expected #{js_str(own(f, 'expected'))}#{truthy?(eb) ? " by #{js_str(eb)}" : ''}, got #{js_str(f['got'])} by #{by.nil? ? 'no clause' : js_str(by)}"
      end
      lines << "#{truthy?(rd) ? 'FAIL' : 'note'}: the policy differs from the one the examples were confirmed against" unless r['digestMatch']
      lines << "#{r['passed']}/#{r['total']} examples #{r['ok'] ? 'PASS' : 'FAIL'}"
      { 'ok' => r['ok'], 'exitCode' => r['ok'] ? 0 : 1, 'lines' => lines }
    end

    # `coverage`: which clauses and thresholds the tests or traffic never exercise, and which mutations they cannot tell apart.
    def coverage_command(policy_doc, traffic_doc, o = nil)
      o = {} if o.nil?
      p = to_analyzer_policy(policy_doc)
      return bad("policy: #{p['reason']}") unless p['ok']

      actions = nil
      if traffic_doc.is_a?(Array)
        actions = traffic_doc
      elsif record?(traffic_doc) && traffic_doc['cases'].is_a?(Array)
        actions = traffic_doc['cases'].map { |c| record?(c) ? own(c, 'action') : c }
      end
      if actions.nil? || actions.any? { |a| !record?(a) || !a['verb'].is_a?(String) || !a['resource'].is_a?(String) }
        return bad('traffic: expected an array of {verb, resource, params?} actions or a pca-policy-tests document')
      end

      r = A.coverage(p['policy'], actions)
      mn = {}
      [%w[minClauses clauses], %w[minBoundaries boundaries], %w[minMutation mutation], %w[maxSurvivors maxSurvivors]].each do |src, dst|
        mn[dst] = jget(o, src) unless jget(o, src).equal?(UNDEF)
      end
      gate = A.coverage_gate(r, mn)
      sc = r['score']
      mu = r['mutants']
      lines = ["clauses decisive #{to_fixed(sc['clauses'] * 100, 0)}%, boundaries covered #{to_fixed(sc['boundaries'] * 100, 0)}%, " \
               "mutants killed #{to_fixed(sc['mutation'] * 100, 0)}% (#{mu['killed']}/#{mu['total'] - mu['equivalent']})"]
      lines += r['untested'].map { |i| "untested: #{i}" }
      lines += mu['survivors'].map { |m| "survives: #{m['description']}#{truthy?(m['killer']) ? " (kill with #{js_json(m['killer'])})" : ''}" }
      lines += gate['reasons'].map { |x| "FAIL: #{x}" }
      lines << (gate['ok'] ? 'PASS' : 'FAIL')
      { 'ok' => gate['ok'], 'exitCode' => gate['ok'] ? 0 : 1, 'lines' => lines }
    end

    # ---- command line ----------------------------------------------------------------------------------------------------

    HELP = <<~TXT.chomp
      pca-policy-ci — statically catch unsafe PCA policies before they ship.

      Usage:
        pca-policy-ci <files...> [options]
        pca-policy-ci diff <old.json> <new.json> [--allow-widen] [--verb V [--integer] [--amount-field F] [--window-secs N] [--max-exposure-increase N]]
        pca-policy-ci test <policy.json> <tests.json> [--require-digest]
        pca-policy-ci coverage <policy.json> <traffic-or-tests.json> [--min-clauses R] [--min-boundaries R] [--min-mutation R] [--max-survivors N]

      Options:
        --max-severity <error|warn|info>  Lowest severity that fails the gate (default: error)
        --format <text|github>            Output format (default: text; 'github' = workflow annotations)
        --schema <file>                   Also check each policy against this signed action schema (JSON)
        --lint-rules-pin <file>           Fail unless the action-kit lint rule list has the digest in <file>
        --quiet, -q                       Only print findings and the summary line
        --help, -h                        Show this help

      Each file is a JSON policy (Envelope / grant / compiled / { predicates, caveats }) or a JSON array
      treated as a delegation chain. Exits non-zero when any finding is at or above --max-severity.
    TXT

    # The command line as {args: {files, maxSeverity, format, quiet, help, schema?, lintRulesPin?}} or {error}.
    def parse_args(argv)
      files = []
      max_severity = 'error'
      fmt = 'text'
      quiet = false
      help = false
      schema = nil
      pin = nil
      argv = argv.to_a
      i = 0
      while i < argv.length
        a = argv[i]
        case a
        when '--help', '-h' then help = true
        when '--quiet', '-q' then quiet = true
        when '--lint-rules-pin'
          i += 1
          v = argv[i]
          return { 'error' => '--lint-rules-pin expects a file' } if v.nil? || v.start_with?('-')

          pin = v
        when '--max-severity'
          i += 1
          v = argv[i]
          return { 'error' => "--max-severity expects one of #{SEVERITIES.join('|')}" } if v.nil? || !SEVERITIES.include?(v)

          max_severity = v
        when /\A--max-severity=/
          v = a['--max-severity='.length..]
          return { 'error' => "--max-severity expects one of #{SEVERITIES.join('|')}" } unless SEVERITIES.include?(v)

          max_severity = v
        when '--schema'
          i += 1
          v = argv[i]
          return { 'error' => '--schema expects a file' } if v.nil?

          schema = v
        when /\A--schema=/ then schema = a['--schema='.length..]
        when '--format'
          i += 1
          v = argv[i]
          return { 'error' => "--format expects 'text' or 'github'" } unless %w[text github].include?(v)

          fmt = v
        when /\A--format=/
          v = a['--format='.length..]
          return { 'error' => "--format expects 'text' or 'github'" } unless %w[text github].include?(v)

          fmt = v
        else
          return { 'error' => "unknown option '#{a}'" } if a.start_with?('-')

          files << a
        end
        i += 1
      end
      args = { 'files' => files, 'maxSeverity' => max_severity, 'format' => fmt, 'quiet' => quiet, 'help' => help }
      args['schema'] = schema unless schema.nil?
      args['lintRulesPin'] = pin unless pin.nil?
      { 'args' => args }
    end

    def read_text(path)
      File.binread(path).force_encoding(Encoding::UTF_8).scrub("�")
    rescue SystemCallError => e
      n = e.errno || 0
      code, text = ERRNO_TEXT.fetch(n) { ["E#{n}", SystemCallError.new(n).message.sub(/ - .*\z/, '').downcase] }
      raise IOError, "#{code}: #{text}, #{n == 21 ? 'read' : 'open'} '#{path}'"
    end

    def lint_file(path, schema = UNDEF)
      text = begin
        read_text(path)
      rescue IOError => e
        return [{ 'rule' => 'malformed-policy', 'severity' => 'error', 'message' => "cannot read file: #{e.message}" }]
      end
      doc = begin
        Js.parse(text)
      rescue StandardError => e
        return [{ 'rule' => 'malformed-policy', 'severity' => 'error', 'message' => "invalid JSON: #{e.message}" }]
      end
      lint(doc, schema.equal?(UNDEF) ? {} : { 'schema' => schema })
    end

    def print_text(results, quiet, write)
      results.each do |r|
        write.call("\n#{r['label']}:") unless quiet
        if r['findings'].empty?
          write.call('  (clean)') unless quiet
          next
        end
        r['findings'].each do |f|
          loc = f.key?('where') ? " [#{f['where']}]" : ''
          write.call("  #{TEXT_TAG[f['severity']].ljust(5)} #{f['rule']}#{loc}: #{f['message']}")
        end
      end
    end

    def escape_gh(s) = s.gsub('%', '%25').gsub("\r", '%0D').gsub("\n", '%0A')

    # Workflow-command PROPERTY values must also escape `:` and `,`, or a file name can add properties or end the command.
    def escape_gh_prop(s) = escape_gh(s).gsub(':', '%3A').gsub(',', '%2C')

    def print_github(results, write)
      results.each do |r|
        r['findings'].each do |f|
          props = "file=#{escape_gh_prop(r['label'])},title=#{escape_gh_prop(f['rule'])}"
          loc = f.key?('where') ? "#{f['where']}: " : ''
          write.call("::#{GH_LEVEL[f['severity']]} #{props}::#{escape_gh("#{loc}#{f['message']}")}")
        end
      end
    end

    def read_json(path)
      { 'ok' => true, 'doc' => Js.parse(read_text(path)) }
    rescue IOError, StandardError => e
      { 'ok' => false, 'reason' => "#{path}: #{e.message}" }
    end

    # `Number(v)` of a flag value when it is a non-blank finite number, else UNDEF.
    def flag_number(flags, k)
      v = flags[k]
      return UNDEF unless v.is_a?(String)

      t = trim(v)
      return UNDEF if t.empty?

      n = if t.match?(/\A0[xX][0-9a-fA-F]+\z/) then t[2..].to_i(16).to_f
          elsif t.match?(/\A0[oO][0-7]+\z/) then t[2..].to_i(8).to_f
          elsif t.match?(/\A0[bB][01]+\z/) then t[2..].to_i(2).to_f
          elsif JS_NUMBER.match?(t) then t.sub(/(\d)\.(?![0-9])/, '\1.0').to_f
          else return UNDEF
          end
      return UNDEF unless n.finite?

      n == n.floor && n.abs < 2**53 ? n.to_i : n
    end

    def run_authoring(cmd, rest, write)
      files = []
      flags = {}
      i = 0
      while i < rest.length
        a = rest[i]
        if VALUED.include?(a)
          i += 1
          if i >= rest.length
            write.call("#{a} expects a value")
            return 2
          end
          flags[a] = rest[i]
        elsif BOOLS.include?(a)
          flags[a] = true
        elsif a.start_with?('-')
          write.call("unknown option '#{a}'")
          return 2
        else
          files << a
        end
        i += 1
      end
      flags.each do |k, v|
        next unless VALUED.include?(k) && k != '--verb' && k != '--amount-field' && flag_number(flags, k).equal?(UNDEF)

        write.call("#{k} expects a number, got '#{v}'")
        return 2
      end
      if files.length != 2
        write.call("error: #{cmd} takes exactly two files")
        write.call(HELP)
        return 2
      end
      docs = files.map { |f| read_json(f) }
      failed = docs.find { |d| !d['ok'] }
      unless failed.nil?
        write.call(failed['reason'])
        return 2
      end
      a_doc = docs[0]['doc']
      b_doc = docs[1]['doc']
      opt = lambda do |flag, key, out|
        n = flag_number(flags, flag)
        out[key] = n unless n.equal?(UNDEF)
      end
      case cmd
      when 'diff'
        o = { 'allowWiden' => flags.key?('--allow-widen') }
        o['verb'] = flags['--verb'] if flags['--verb'].is_a?(String)
        o['amountField'] = flags['--amount-field'] if flags['--amount-field'].is_a?(String)
        o['integer'] = flags.key?('--integer')
        opt.call('--window-secs', 'windowSecs', o)
        opt.call('--max-exposure-increase', 'maxExposureIncrease', o)
        r = diff_command(a_doc, b_doc, o)
      when 'test'
        r = test_command(a_doc, b_doc, { 'requireDigest' => flags.key?('--require-digest') })
      else
        o = {}
        opt.call('--min-clauses', 'minClauses', o)
        opt.call('--min-boundaries', 'minBoundaries', o)
        opt.call('--min-mutation', 'minMutation', o)
        opt.call('--max-survivors', 'maxSurvivors', o)
        r = coverage_command(a_doc, b_doc, o)
      end
      r['lines'].each { |l| write.call(l) }
      r['exitCode']
    end

    # Run the command line (`<files...>`, `diff`, `test`, `coverage`); `write` receives each output line (default: stdout). Returns
    # the exit code: 0 ok, 1 a gate failed, 2 unusable input.
    def run(argv, write = nil)
      write ||= ->(s) { $stdout.write("#{s}\n") }
      argv = argv.to_a
      return run_authoring(argv[0], argv[1..], write) if %w[diff test coverage].include?(argv[0])

      parsed = parse_args(argv)
      if parsed.key?('error')
        write.call(parsed['error'])
        write.call(HELP)
        return 2
      end
      args = parsed['args']
      if args['help']
        write.call(HELP)
        return 0
      end
      pin_failed = false
      if args.key?('lintRulesPin')
        r = begin
          check_lint_rules_pin(read_text(args['lintRulesPin']))
        rescue IOError => e
          { 'ok' => false, 'message' => "cannot read the lint rules pin: #{e.message}" }
        end
        write.call("#{r['ok'] ? 'PASS' : 'FAIL'} — #{r['message']}")
        pin_failed = !r['ok']
        return pin_failed ? 1 : 0 if args['files'].empty?
      end
      if args['files'].empty?
        write.call('error: no policy files given')
        write.call(HELP)
        return 2
      end
      schema = UNDEF
      if args.key?('schema')
        s = read_json(args['schema'])
        unless s['ok']
          write.call(s['reason'])
          return 2
        end
        schema = s['doc']
      end
      results = args['files'].map { |f| { 'label' => f, 'findings' => lint_file(f, schema) } }
      summary = summarize(results, { 'maxSeverity' => args['maxSeverity'] })
      if args['format'] == 'github' then print_github(results, write)
      else print_text(results, args['quiet'], write)
      end
      write.call("error: #{summary['reason']}") if truthy?(summary['reason'])
      c = summary['counts']
      write.call("\n#{summary['ok'] ? 'PASS' : 'FAIL'} — #{c['error']} error(s), #{c['warn']} warning(s), #{c['info']} info across #{results.length} " \
                 "policy/policies (fail threshold: #{summary['maxSeverity']})")
      pin_failed ? [1, summary['exitCode']].max : summary['exitCode']
    end
  end
end
