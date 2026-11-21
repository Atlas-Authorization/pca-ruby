# frozen_string_literal: true

# Run every def's executable examples through the real pipeline in process (native port of test-runner.ts of the TypeScript reference
# @atlasauth/pca-actions): derive the schema, conform the params, expand the floors, decide; plus the generic property checks of the pack:
# monotonicity over trait additions and subsets, one digest across the JSON and YAML forms, and the schema round trip (the example conforms;
# every mutation of it is refused). The example policy (`under`) is a small allow selector evaluated here; it can only pre-authorize.
# The YAML form of the digest property runs over the value form of the same document unless the caller passes `yaml_load`
# (def -> load result, the caller's emit-and-load round trip).
require_relative 'actions'
require_relative 'actions_author'
require_relative 'actions_derive'
require_relative 'actions_effective'
require_relative 'js_compat'

module AtlasPca
  module ActionsTestRunner
    A = AtlasPca::Actions
    E = AtlasPca::ActionsEffective
    AU = AtlasPca::ActionsAuthor
    DR = AtlasPca::ActionsDerive
    UNDEF = AtlasPca::V2JS::UNDEF
    META = { 'site' => 'https://example.invalid', 'aud' => 'example', 'version' => '0' }.freeze
    SEL_KEYS = %w[trait verb where caveats context].freeze

    module_function

    def num?(v) = v.is_a?(Integer) || v.is_a?(Float)

    # Examples and property checks describe the action AS REVIEWED (its hint view): authoring tests, not enforcement.
    def hint_of(d, reg)
      e = E.effective_with(d, reg)
      e.merge(e['hint']).merge('confirmed' => true)
    end

    def core_trait_ids = A::CORE_TRAIT_DEFS.map { |t| t['id'] }

    # the parsed allow selectors, or a String reason
    def parse_under(under)
      return [] if under.equal?(UNDEF)
      return 'under must be {allow: selector | [selector]}' if !under.is_a?(Hash) || under.keys.any? { |k| k != 'allow' }

      allow = under['allow']
      (allow.is_a?(Array) ? allow : [allow]).map do |s|
        return 'an allow selector has trait, verb, where, caveats, context' if !s.is_a?(Hash) || s.keys.any? { |k| !SEL_KEYS.include?(k) }
        return 'an allow selector names exactly one of trait and verb' if s.key?('trait') == s.key?('verb')
        return 'where must be an object' if s.key?('where') && !s['where'].is_a?(Hash)
        return 'caveats must be known caveat kinds' if s.key?('caveats') && (!s['caveats'].is_a?(Array) || !s['caveats'].all? { |c| A::CAVEAT_KINDS.include?(c) })

        s
      end
    end

    def domain_of(v) = v[((v.rindex('@') || -1) + 1)..].downcase

    # The caveats of the grant a matching allow selector stands for, or nil when it does not match this call.
    def grant_of(sel, d, flat, eff)
      return nil if sel.key?('trait') && !eff['closure'].include?(sel['trait'].include?('.') ? sel['trait'] : "pca.#{sel['trait']}")
      return nil if sel.key?('verb') && sel['verb'] != d['verb']

      caveats = (sel['caveats'] || []).dup
      (sel['where'] || {}).each do |key, cond|
        dom = key.end_with?('.domain')
        name = dom ? key[0...-'.domain'.length] : key
        pd = d['params'][name]
        return nil if pd.nil? || !flat.key?(name)

        v = flat[name]
        if cond.is_a?(Array)
          return nil if !v.is_a?(String) || !cond.include?(dom ? domain_of(v) : v)
        elsif cond.is_a?(Hash)
          return nil if !num?(v) || (cond.key?('max') && v > cond['max']) || (cond.key?('min') && v < cond['min'])
        else
          return nil
        end
        role = pd['role'] || ''
        if role.start_with?('contact.') || role == 'party.payee' then caveats << 'recipient_scope'
        elsif role == 'money.amount' then caveats << 'amount_cap'
        elsif role == 'count.limit' then caveats << 'count_cap'
        elsif role.start_with?('id.') then caveats << 'resource_scope'
        end
      end
      caveats.uniq
    end

    # Decide one example: {got, why}.
    def decide_example(d, ex, reg, defs)
      doc = DR.to_schema_doc(defs, reg, META)
      flat = DR.flatten_params(ex['params'])
      c = AtlasPca.conform_action(doc, d['verb'], flat)
      return { 'got' => 'deny', 'why' => "schema_violation #{c['code']}#{c['path'] && c['path'] != '' ? " (#{c['path']})" : ''}" } unless c['ok']

      op = DR.operation_of(d, { 'params' => ex['params'] })
      return { 'got' => 'deny', 'why' => op['reason'] } unless op['ok']

      sels = parse_under(ex.key?('under') ? ex['under'] : UNDEF)
      return { 'got' => 'deny', 'why' => "bad example policy: #{sels}" } if sels.is_a?(String)

      eff = hint_of(d, reg)
      call_ctx = []
      idem = d['idempotency']
      call_ctx << 'idempotency' if idem && idem['mode'] == 'natural'
      call_ctx << 'idempotency' if idem && idem['mode'] == 'key_param' && !idem['param'].nil? && flat.key?(idem['param'])
      grant_caveats = []
      pre = 0
      sels.each do |s|
        g = grant_of(s, d, flat, eff)
        next if g.nil?

        pre = 3
        grant_caveats |= g
        (s['context'] || []).each { |k| call_ctx << k unless call_ctx.include?(k) }
      end
      got = A.floor_decision({ 'caveats' => grant_caveats, 'max_esc' => 3, 'preauth_esc' => pre }, { 'context' => call_ctx.uniq }, eff['eff'])
      if got == 'allow'
        why = 'floor satisfied'
      else
        need = (eff['eff']['caveats'].reject { |k| grant_caveats.include?(k) } + eff['eff']['context'].reject { |k| call_ctx.include?(k) }).join(', ')
        why = "floor needs #{need.empty? ? "escalation tier #{eff['eff']['esc']}" : need}"
      end
      { 'got' => got, 'why' => why }
    end

    def mutations(d, flat)
      out = [{ 'name' => 'extra param', 'params' => flat.merge('zz_undeclared' => 'x') }]
      flat.keys.sort_by { |k| A.u16key(k) }.each do |k|
        pd = d['params'][k]
        next if pd.nil?

        out << { 'name' => "missing #{k}", 'params' => flat.reject { |x, _| x == k } } if pd['required'] != false
        v = flat[k]
        out << { 'name' => "type swap #{k}", 'params' => flat.merge(k => v.is_a?(String) ? 12_345 : (num?(v) || v == true || v == false ? 'x' : {})) }
        if num?(v) && pd['type'] == 'integer'
          out << { 'name' => "above max #{k}", 'params' => flat.merge(k => pd['max'] + 1) } unless pd['max'].nil?
          out << { 'name' => "below min #{k}", 'params' => flat.merge(k => pd['min'] - 1) } unless pd['min'].nil?
        end
        next unless v.is_a?(String) && pd['type'] == 'string'

        out << { 'name' => "outside values #{k}", 'params' => flat.merge(k => 'not_a_listed_value_zz') } if pd['values'] && !pd['values'].empty?
        out << { 'name' => "too long #{k}", 'params' => flat.merge(k => 'x' * (pd['max_len'] + 1)) } unless pd['max_len'].nil?
      end
      out
    end

    # The def through the value form of the document (no YAML emitter here).
    def yaml_form(d) = AU.load_actions_value({ 'ns' => d['verb'].split('.', -1)[0], 'actions' => [d] })

    # Run examples and property checks for a set of defs (one pack). `prop_limit` bounds the trait subsets tried per def.
    def run_def_tests(defs, reg, prop_limit = nil, yaml_load = nil)
      examples = []
      props = []
      limit = prop_limit.nil? ? 256 : prop_limit
      defs.each do |d|
        (d['examples'] || []).each_with_index do |ex, index|
          r = decide_example(d, ex, reg, defs)
          examples << { 'verb' => d['verb'], 'index' => index, 'expect' => ex['expect'], 'got' => r['got'], 'ok' => r['got'] == ex['expect'], 'why' => r['why'] }
        end

        # T2: adding any core trait never lowers the effective profile
        eff = hint_of(d, reg)
        lowered = core_trait_ids.reject { |t| A.leq(eff['eff'], E.eff_with_trait(d, t, reg)) }
        props << { 'verb' => d['verb'], 'name' => 'adding a trait never lowers the profile', 'ok' => lowered.empty?, 'detail' => lowered.join(', ') }

        # T2 over subsets of the def's own traits (bounded): F(S) <= F(T)
        ts = eff['traits']
        bad = 0
        total = [2**[ts.length, 20].min, limit].min
        top = A.floor_of(reg, ts)
        total.times do |mask|
          sub = ts.each_with_index.select { |_, i| ((mask >> (i % 32)) & 1) == 1 }.map(&:first) # 32-bit shift counts, as in the reference
          bad += 1 unless A.leq(A.floor_of(reg, sub), top)
        end
        props << { 'verb' => d['verb'], 'name' => 'floors are monotone over trait subsets', 'ok' => bad.zero?, 'detail' => "#{total} subsets, #{bad} violations" }

        # one digest across the JSON and YAML forms
        want = A.def_digest(d)
        via_json = AU.load_actions_text(AtlasPca::Js.json(d), 'json')
        via_yaml = yaml_load ? yaml_load.call(d) : yaml_form(d)
        ok_j = via_json['errors'].empty? && !via_json['defs'].empty? && A.def_digest(via_json['defs'][0]) == want
        ok_y = via_yaml['errors'].empty? && !via_yaml['defs'].empty? && A.def_digest(via_yaml['defs'][0]) == want
        why = lambda do |ok, via|
          ok ? 'ok' : (via['errors'].empty? ? 'digest differs' : via['errors'][0]['message'])
        end
        props << { 'verb' => d['verb'], 'name' => 'one digest across JSON and YAML forms', 'ok' => ok_j && ok_y,
                   'detail' => ok_j && ok_y ? '' : "json #{why.call(ok_j, via_json)}; yaml #{why.call(ok_y, via_yaml)}" }

        # schema round trip: each example conforms, every mutation is refused
        if (d['examples'] || []).empty?
          props << { 'verb' => d['verb'], 'name' => 'schema round trip', 'ok' => true, 'detail' => 'skipped: no examples' }
          next
        end
        doc = DR.to_schema_doc(defs, reg, META)
        accepted = []
        tried = 0
        d['examples'].each do |ex|
          flat = DR.flatten_params(ex['params'])
          next unless AtlasPca.conform_action(doc, d['verb'], flat)['ok'] # a deliberately non-conforming example is a deny example

          mutations(d, flat).each do |m|
            tried += 1
            accepted << m['name'] if AtlasPca.conform_action(doc, d['verb'], m['params'])['ok']
          end
        end
        props << { 'verb' => d['verb'], 'name' => 'schema round trip', 'ok' => accepted.empty?, 'detail' => accepted.empty? ? "#{tried} mutations refused" : "accepted: #{accepted.uniq.join(', ')}" }
      end
      { 'examples' => examples, 'props' => props, 'ok' => examples.all? { |e| e['ok'] } && props.all? { |q| q['ok'] } }
    end

    def test_text(r)
      lines = []
      r['examples'].each do |e|
        lines << "#{e['ok'] ? 'PASS' : 'FAIL'}  #{e['verb']} example #{e['index'] + 1}: expected #{e['expect']}, got #{e['got']} (#{e['why']})"
      end
      r['props'].each { |q| lines << "#{q['ok'] ? 'PASS' : 'FAIL'}  #{q['verb']} #{q['name']}#{q['detail'] && q['detail'] != '' ? ": #{q['detail']}" : ''}" }
      f = lines.count { |l| l.start_with?('FAIL') }
      lines << "#{lines.length - f} passed, #{f} failed"
      lines.join("\n")
    end
  end
end
