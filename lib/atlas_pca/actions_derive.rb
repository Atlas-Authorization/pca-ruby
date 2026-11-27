# frozen_string_literal: true

# Everything an ActionDef yields (native port of derive.ts and explain.ts of the TypeScript reference @atlasauth/pca-actions): the signed
# schema verb and document, the operation binding, risk inputs, policy predicates, ontology terms, the policy card, the escalation tier,
# MCP annotations and the plain-language explanation. Rule 22's integrity half lives in actions.rb. `verifier` is the caller's
# confirmation verifier (absent: nothing is confirmed).
require_relative 'actions'
require_relative 'actions_effective'
require_relative 'actions_idpattern'

module AtlasPca
  module ActionsDerive
    A = AtlasPca::Actions
    E = AtlasPca::ActionsEffective
    MAX_PARAM_PATH_DEPTH = 3
    ESC_TIERS = %w[auto confirm cosign stepup].freeze
    RISK_NAMES = %w[low elevated high critical].freeze
    REVERSIBILITY_SCORE = { 'reversible' => 1, 'rate_limited' => 0.4, 'irreversible' => 0 }.freeze
    CORE_NAMESPACE = 'pca.'

    module_function

    def u16(xs) = xs.sort_by { |x| A.u16key(x) }

    # Nested plain objects become dotted keys (up to 3 segments); arrays and scalars are leaves; a deeper object stays a leaf.
    def flatten_params(params)
      out = {}
      walk = lambda do |prefix, depth, v|
        if v.is_a?(Hash) && depth < MAX_PARAM_PATH_DEPTH && !v.empty?
          v.each { |k, x| walk.call(prefix == '' ? k : "#{prefix}.#{k}", depth + 1, x) }
        else
          out[prefix] = v
        end
      end
      params.each { |k, v| walk.call(k, 1, v) }
      out
    end

    # The unique param carrying `role`, or raises no_param / ambiguous_param.
    def param_by_role(d, role)
      hits = u16(d['params'].keys.select { |n| d['params'][n]['role'] == role })
      raise A::ActionKitError.new('no_param', "'#{d['verb']}' has no parameter with role #{role}") if hits.empty?
      raise A::ActionKitError.new('ambiguous_param', "'#{d['verb']}' has several parameters with role #{role}") if hits.length > 1

      hits[0]
    end

    # The one adapter to the Goal IR's 4 classes: read | reversible | external_send | irreversible.
    def effect_class(d)
      n = A.normalize(d)
      return 'read' if A.read_only?(n['effects'])
      return 'irreversible' if A.worst_reversibility(n['reversibility'], n['params']) == 'irreversible'
      return 'external_send' if n['effects'].any? { |e| %w[send publish export].include?(e) }

      'reversible'
    end

    # ---- signed schema (v2) -------------------------------------------------------------------------------------

    def unit_id(p)
      u = p['unit']
      return nil if u.nil?
      return u['kind'] if u['kind'] != 'money'

      u['ccy'].is_a?(String) ? "money.#{u['ccy'].downcase}" : nil
    end

    def unit_decl(p)
      u = p['unit']
      return nil if u.nil?
      return { 'kind' => u['kind'] } if u['kind'] != 'money'
      return nil unless u['ccy'].is_a?(String)

      out = { 'kind' => 'money', 'currency' => u['ccy'] }
      out['exponent'] = u['exp'] if u.key?('exp')
      out
    end

    def to_param_decl(n)
      d = { 'type' => n['type'], 'semantic' => n['role'].nil? ? "generic.#{n['type']}" : n['role'], 'sensitivity' => n['sensitivity'] }
      d['required'] = false unless n['required']
      d['values'] = n['values'].dup if n.key?('values')
      %w[min max max_len items min_items max_items format provenance_min default principal_neutral_default description].each { |k| d[k] = A.deep_copy(n[k]) if n.key?(k) }
      uid = unit_id(n)
      d['unit'] = uid unless uid.nil?
      d['accumulates_into'] = n['accumulates'].dup if n.key?('accumulates')
      d['role'] = n['role'] if n.key?('role')
      d['tags'] = n['tags'].dup if n.key?('tags')
      d
    end

    # {verb, units}: the signed v2 verb declaration of a def (effects, traits, def digest, materialized floors) and the units it needs.
    def to_schema_verb(d, reg, verifier = nil)
      n = A.normalize(d)
      eff = E.effective_with(d, reg, verifier)
      params = {}
      units = {}
      n['params'].each do |name, p|
        params["action.params.#{name}"] = to_param_decl(p)
        uid = unit_id(p)
        units[uid] = unit_decl(p) unless uid.nil?
      end
      v = {
        'verb' => n['verb'], 'kind' => A.read_only?(n['effects']) ? 'read' : 'write', 'params' => params, 'effects' => n['effects'].dup,
        'traits' => eff['traits'], 'def' => A.def_digest(d), 'floors' => eff['eff']
      }
      att = (d['review'] || {})['attestation']
      v['confirmation'] = att if eff['confirmed'] && att.is_a?(Hash) && att.key?('sig')
      r = n['reversibility']
      if r.is_a?(String)
        v['reversibility'] = r
      else
        by = { 'param' => "action.params.#{r['by']}", 'map' => r['map'].dup }
        by['default'] = r['default'] if r.key?('default')
        v['reversibility_by'] = by
      end
      b = n['bindings']
      v['mcp'] = b['mcp'].key?('tool') ? { 'tool' => b['mcp']['tool'] } : {} unless b['mcp'].nil?
      v['openapi'] = b['openapi'].key?('operationId') ? { 'operationId' => b['openapi']['operationId'] } : {} unless b['openapi'].nil?
      v['description'] = n['description'] if n.key?('description')
      { 'verb' => v, 'units' => units }
    end

    # The unsigned v2 schema document of a set of defs (verbs sorted; units merged, a conflicting redefinition refused).
    def to_schema_doc(defs, reg, meta, verifier = nil)
      verbs = []
      units = {}
      seen = {}
      defs.sort_by { |x| A.u16key(x['verb']) }.each do |d|
        raise A::ActionKitError.new('duplicate_verb', "verb '#{d['verb']}' appears twice") if seen.key?(d['verb'])

        seen[d['verb']] = true
        o = to_schema_verb(d, reg, verifier)
        verbs << o['verb']
        o['units'].each do |uid, u|
          prev = units[uid]
          if !prev.nil? && (prev['kind'] != u['kind'] || prev['currency'] != u['currency'] || prev['exponent'] != u['exponent'])
            raise A::ActionKitError.new('unit_conflict', "unit '#{uid}' is declared with two different definitions")
          end

          units[uid] = u
        end
      end
      custom = reg.values.reject { |t| t['id'].start_with?(CORE_NAMESPACE) }.sort_by { |t| A.u16key(t['id']) }
      doc = { 'v' => 2, 'kind' => 'pca-action-schema', 'site' => meta['site'], 'aud' => meta['aud'], 'version' => meta['version'] }
      doc['units'] = units unless units.empty?
      doc['verbs'] = verbs
      doc['traits_digest'] = A.traits_digest(reg)
      doc['trait_defs'] = custom unless custom.empty?
      doc['pack'] = meta['pack'] unless meta['pack'].nil?
      doc
    end

    # ---- operation binding ----------------------------------------------------------------------------------------

    # {ok: true, op: {verb, resource, params}} or {ok: false, reason}: refuses (never guesses) a missing or non-matching id.
    def operation_of(d, call)
      flat = flatten_params(call['params'])
      declared = u16(d['params'].keys)
      params = declared.select { |k| flat.key?(k) }.to_h { |k| [k, flat[k]] }
      rtype = d['resource']['type']
      rid = d['resource']['id']
      scope = d['resource']['scope']
      if rid != '*' && rid.key?('exact')
        resource = "#{rtype}:#{rid['exact']}"
      else
        id_param = declared.find { |n| d['params'][n]['role'] == "id.#{rtype}" }
        val = id_param.nil? ? nil : params[id_param]
        if val.is_a?(String)
          return { 'ok' => false, 'reason' => "the id '#{val}' does not match the resource pattern of #{d['verb']}" } unless ActionsIdPattern.id_matches(rid, val)

          resource = "#{rtype}:#{val}"
        elsif scope != 'one'
          resource = "#{rtype}:*"
        else
          return { 'ok' => false, 'reason' => "#{d['verb']} needs a parameter with role id.#{rtype} to name its resource" }
        end
      end
      { 'ok' => true, 'op' => { 'verb' => d['verb'], 'resource' => resource, 'params' => params } }
    end

    # ---- risk ----------------------------------------------------------------------------------------------------

    def unit01(x) = [1, [0, x].max].min

    def num?(x) = x.is_a?(Integer) || x.is_a?(Float)
    def finite_num?(x) = num?(x) && (x.is_a?(Integer) || x.finite?)

    # Risk inputs for a call: reversibility score and blast from the effective profile; a money.amount param makes the blast
    # amount/kappa from the signed kappa (missing or invalid: 1, the worst case). Reads nothing the agent claims.
    def risk_of(d, eff, params = nil, opts = nil)
      opts ||= {}
      blast = unit01(eff['eff']['blast_ppm'].to_f / 1_000_000)
      money = u16(d['params'].keys.select { |n| d['params'][n]['role'] == 'money.amount' })
      unless money.empty?
        flat = params.nil? || params.empty? ? {} : flatten_params(params)
        amount = flat[money[0]]
        kappa = opts['kappa']
        blast = finite_num?(amount) && amount >= 0 && num?(kappa) && kappa.positive? ? unit01(amount.to_f / kappa) : 1
      end
      out = { 'reversibility' => REVERSIBILITY_SCORE.fetch(eff['eff']['rev']), 'blastRadius' => blast, 'confidence' => 1 }
      t = opts['taint']
      out['taint'] = unit01(t) if finite_num?(t)
      out
    end

    # ---- predicates -----------------------------------------------------------------------------------------------

    # `<type>:<prefix>*`, `<type>:<exact>` or `<type>:*`.
    def resource_matcher(d)
      rtype = d['resource']['type']
      rid = d['resource']['id']
      return "#{rtype}:*" if rid == '*'

      rid.key?('exact') ? "#{rtype}:#{rid['exact']}" : "#{rtype}:#{rid['prefix']}*"
    end

    # The policy predicate scaffold; a money limit on a def with no money.amount parameter raises (never silently unbounded).
    def predicates_of(d, limits = nil)
      limits ||= {}
      out = { 'verb' => d['verb'], 'resource' => resource_matcher(d) }
      if limits.key?('max_amount')
        m = limits['max_amount']
        raise A::ActionKitError.new('bad_limit', 'max_amount must be a non-negative safe integer') if !A.int?(m) || m.negative?

        name = param_by_role(d, 'money.amount')
        out['where'] = [{ 'field' => "action.params.#{name}", 'op' => 'lte', 'value' => m }, { 'field' => "action.params.#{name}", 'op' => 'gte', 'value' => 0 }]
      end
      out
    end

    # ---- Goal IR ontology terms -----------------------------------------------------------------------------------

    def ont_param(d, p)
      u = p['unit']
      unless u.nil?
        if u['kind'] == 'money'
          c = u['ccy']
          return { 'kind' => 'money', 'ccys' => [c] } if c.is_a?(String)

          cp = d['params'][c['from']]
          return { 'kind' => 'money', 'ccys' => !cp.nil? && !cp['values'].nil? ? u16(cp['values']) : [] }
        end
        return { 'kind' => %w[duration bytes ratio].include?(u['kind']) ? u['kind'] : 'count' }
      end
      role = p['role']
      fmt = p['format']
      return { 'kind' => 'id', 'of' => role[3..] } if !role.nil? && role.start_with?('id.')
      return { 'kind' => 'id', 'of' => fmt[3..] } if !fmt.nil? && fmt.start_with?('id:')

      case p['type']
      when 'duration' then { 'kind' => 'duration' }
      when 'datetime', 'date' then { 'kind' => 'instant' }
      when 'integer' then { 'kind' => 'count' }
      when 'boolean' then { 'kind' => 'enum', 'values' => %w[false true] }
      when 'set' then { 'kind' => 'enum', 'values' => u16(p['values'] || []) }
      when 'string' then p['values'].nil? ? { 'kind' => 'text' } : { 'kind' => 'enum', 'values' => u16(p['values']) }
      else { 'kind' => 'text' }
      end
    end

    # Ontology terms for a set of defs; `effect` is derived (effect_class), never overridden.
    def to_ontology(defs, reg, verifier = nil)
      types = {}
      units = {}
      verbs = []
      aliases = {}
      traits = {}
      defs.sort_by { |x| A.u16key(x['verb']) }.each do |d|
        rid = d['resource']['id']
        prefix = rid == '*' || rid.key?('exact') ? '' : rid['prefix']
        types[d['resource']['type']] = prefix unless types.key?(d['resource']['type'])
        params = {}
        u16(d['params'].keys).each do |name|
          params[name] = ont_param(d, d['params'][name])
          u = d['params'][name]['unit']
          if !u.nil? && u['kind'] == 'money' && u['ccy'].is_a?(String)
            units[u['ccy']] = { 'kind' => 'money' }.merge(u.key?('exp') ? { 'exponent' => u['exp'] } : {})
          elsif !u.nil? && u['kind'] != 'money'
            units[u['kind']] = { 'kind' => u['kind'] }
          end
        end
        verbs << { 'id' => d['verb'], 'effect' => effect_class(d), 'resource_type' => d['resource']['type'], 'params' => params }
        (d['aliases'] || []).each do |a|
          raise A::ActionKitError.new('alias_collision', "alias '#{a}' names two verbs") if aliases.key?(a) && aliases[a] != d['verb']

          aliases[a] = d['verb']
        end
        traits[d['verb']] = E.effective_with(d, reg, verifier)['traits']
      end
      { 'types' => types.map { |i, p| { 'id' => i, 'id_prefix' => p } }, 'units' => units, 'verbs' => verbs, 'aliases' => aliases, 'traits' => traits }
    end

    # ---- policy card + escalation + MCP annotations ---------------------------------------------------------------------

    def sentence(s) = !s.empty? && '.!?'.include?(s[-1]) ? s : "#{s}."

    def list(xs)
      return xs[0] || '' if xs.length <= 1

      "#{xs[0...-1].join(', ')} and #{xs[-1]}"
    end

    # The deterministic policy card: the title and the phrases of the trait closure, riskiest first.
    def card_of(d, eff, reg)
      ordered = A.closure(reg, eff['traits']).map { |i| reg[i] }.sort_by { |t| [-t['floor']['risk'], A.u16key(t['id'])] }
      phrases = ordered.map { |t| t['card_phrase'] }.uniq
      e = eff['eff']
      second = if eff['confirmed']
                 phrases.empty? ? 'This action only reads.' : "This action #{list(phrases)}."
               else
                 "This action has not been reviewed by a person, so it is treated as the most dangerous kind of action: it #{list(phrases)}."
               end
      { 'verb' => d['verb'], 'title' => d['title'], 'text' => "#{sentence(d['title'])} #{second}", 'risk' => RISK_NAMES[e['risk']],
        'escalation' => ESC_TIERS[e['esc']], 'reversibility' => e['rev'], 'blast_ppm' => e['blast_ppm'], 'needs' => e['caveats'].dup, 'context' => e['context'].dup }
    end

    # The minimum escalation tier of the effective profile.
    def escalation_of(eff) = { 'tier' => eff['eff']['esc'], 'name' => ESC_TIERS[eff['eff']['esc']] }

    # Advisory MCP tool annotations; an unreviewed def's own claim of safety is never advertised.
    def mcp_annotations_of(d, eff)
      cl = eff['closure']
      idem = ((d['idempotency'] || {})['mode']) || 'none'
      ro = A.read_only?(d['effects'])
      { 'readOnlyHint' => eff['confirmed'] && ro, 'destructiveHint' => cl.include?('pca.destructive'),
        'idempotentHint' => eff['confirmed'] && (idem != 'none' || ro),
        'openWorldHint' => cl.include?('pca.network_egress') || cl.include?('pca.external_communication') }
    end

    # ---- explain.ts -----------------------------------------------------------------------------------------------

    def blast_text(ppm) = (ppm % 1000).zero? ? "#{ppm / 1000}k" : "#{ppm}ppm"

    # The plain-language profile of one def: card, effective profile, what a grant must carry, traits and review state.
    def explain_def(d, reg, verifier = nil)
      eff = E.effective_with(d, reg, verifier)
      card = card_of(d, eff, reg)
      e = eff['eff']
      rev = e['rev'] == 'irreversible' ? 'irreversible' : e['rev'] == 'rate_limited' ? 'rate limited' : 'reversible'
      lines = [card['text'], "effective: risk #{e['risk']}, #{rev}, blast #{blast_text(e['blast_ppm'])}, escalation: #{card['escalation']}",
               "grant must carry: #{card['needs'].empty? ? 'nothing' : card['needs'].join(', ')}"]
      lines << "call must carry: #{card['context'].join(', ')}" unless card['context'].empty?
      lines << "traits: #{eff['closure'].empty? ? 'none' : eff['closure'].join(', ')}"
      lines << "review: #{eff['confirmed'] ? d['review']['state'] : "#{d['review']['state']}, not confirmed by a signed review"}"
      unless eff['confirmed']
        h = eff['hint']
        lines << "until a reviewer signs it this action is treated as the most dangerous kind of action; as written it would be: risk #{h['eff']['risk']}, escalation tier #{h['eff']['esc']}, traits: #{h['closure'].empty? ? 'none' : h['closure'].join(', ')}"
      end
      lines.join("\n")
    end
  end
end
