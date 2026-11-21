# frozen_string_literal: true

# The 24 stable lint rules over action definitions, SARIF output and the digest of the rule list (native port of lint.ts of the
# TypeScript reference @atlasauth/pca-actions). Pure: defs in, findings out, deterministic order. A def that fails validate_def is
# reported as LD-000 and not linted further.
require_relative 'actions'
require_relative 'actions_effective'
require_relative 'actions_undo'
require_relative 'js_compat'
require_relative 'siem'

module AtlasPca
  module ActionsLint
    A = AtlasPca::Actions
    E = AtlasPca::ActionsEffective
    U = AtlasPca::ActionsUndo

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
    ].map(&:freeze).freeze
    SEVERITY = LINT_RULES.to_h { |r| [r[0], r[1]] }.freeze
    NOTE_RULE = ['LN-001', 'note', 'an informational note from the loader'].freeze
    STRUCTURE_RULE = ['LD-000', 'error', 'the def is not well formed and cannot be loaded'].freeze
    LINT_RULES_DIGEST_DOMAIN = 'atlas-pca/action-lint-rules/v1'

    DESTROY_RE = /\A(?:delete|destroy|remove|purge|drop|erase|wipe|revoke|terminate|truncate)(?:_|\z)/
    SEND_RE = /\A(?:send|email|notify|sms|message|post_to|broadcast|invite)(?:_|\z)/
    EXPORT_RE = /\A(?:export|download|dump|backup|extract)(?:_|\z)/
    JS_WS = "\t\n\v\f\r    -     　﻿"
    WS_SPLIT = /[#{JS_WS}]+/
    NAME_GROUPS = [%w[create_ new_ add_ make_], %w[delete_ remove_ destroy_]].freeze

    module_function

    # The digest pca-policy-ci pins: the ordered (id, severity, title) list.
    def lint_rules_digest = AtlasPca.hash_canonical({ 'd' => LINT_RULES_DIGEST_DOMAIN, 'rules' => LINT_RULES.map { |r| { 'id' => r[0], 'severity' => r[1], 'title' => r[2] } } })

    # UTF-16 code-unit sort key (a message can carry a lone surrogate, which String#encode refuses)
    def u16k(s) = AtlasPca::Siem::U16.units(s).pack('n*')

    def last_seg(verb) = verb.split('.', -1).last || ''

    def binding_keys(d)
      b = d['bindings'] || {}
      out = []
      truthy = ->(x) { x.is_a?(Hash) && !x.empty? }
      out << "mcp:#{A.js.js_str(b['mcp']['tool'])}" if truthy.call(b['mcp'])
      out << "openapi:#{A.js.js_str(b['openapi']['operationId'])}" if truthy.call(b['openapi'])
      out << "http:#{b['http']['method'].upcase} #{b['http']['path']}" if truthy.call(b['http'])
      out << "graphql:#{b['graphql']['op']}.#{b['graphql']['field']}" if truthy.call(b['graphql'])
      out << "grpc:#{b['grpc']['service']}/#{b['grpc']['method']}" if truthy.call(b['grpc'])
      out << "asyncapi:#{b['asyncapi']['op']} #{b['asyncapi']['channel']}" if truthy.call(b['asyncapi'])
      out
    end

    # Vocabulary problems of a raw def (LD-007). Reads only what a malformed def can still be asked.
    def vocabulary_issues(x, reg)
      return [] unless x.is_a?(Hash)

      js = A.js
      out = []
      x['effects'].each { |e| out << "unknown effect '#{js.js_str(e)}'" unless e.is_a?(String) && A::EFFECTS.include?(e) } if x['effects'].is_a?(Array)
      if x['params'].is_a?(Hash)
        x['params'].each do |n, q|
          next unless q.is_a?(Hash)

          out << "#{n}: unknown role '#{js.js_str(q['role'])}'" if q.key?('role') && !A.role?(q['role'])
          out << "#{n}: unknown format '#{js.js_str(q['format'])}'" if q.key?('format') && !A.format?(q['format'])
        end
      end
      x['context'].each { |c| out << "unknown context key '#{js.js_str(c)}' (known: #{A::CONTEXT_KEYS.join(', ')}, session_taint_max:<level>)" unless A.context_key?(c) } if x['context'].is_a?(Array)
      x['traits'].each { |t| out << "unknown trait '#{t}'" if t.is_a?(String) && !reg.key?(t) } if x['traits'].is_a?(Array)
      out
    end

    # Lint a pack's defs (raw values, so a malformed one is still reported). opts: {custom_traits, stability, ns}. Findings are sorted by
    # verb, rule, param, message. Errors fail CI; warnings fail under strict.
    def lint_defs(raw, opts = nil, verifier = nil)
      opts ||= {}
      js = A.js
      out = []
      add = lambda do |rule, d, message, param = nil|
        f = { 'rule' => rule, 'severity' => rule == STRUCTURE_RULE[0] ? 'error' : SEVERITY.fetch(rule) }
        f['verb'] = d['verb'] if !d.nil? && !d['verb'].nil?
        f['param'] = param unless param.nil?
        f['message'] = message
        out << f
      end

      reg = A::CORE_REGISTRY
      ct = opts['custom_traits']
      if ct && !(ct.respond_to?(:empty?) && ct.empty?)
        begin
          reg = A.extend_registry(A::CORE_REGISTRY, ct)
        rescue StandardError => e
          add.call('LD-007', nil, "invalid custom traits: #{e.message}")
        end
      end

      defs = []
      raw.each do |x|
        verb = x.is_a?(Hash) && x['verb'].is_a?(String) ? x['verb'] : nil
        vocab = vocabulary_issues(x, reg)
        unless vocab.empty?
          vocab.each { |v| add.call('LD-007', { 'verb' => verb }, v) }
          next
        end
        bad = A.validate_def(x)
        if bad
          add.call(STRUCTURE_RULE[0], { 'verb' => verb }, bad)
          next
        end
        defs << x
      end

      # ---- pack-level rules
      by_verb = {}
      names = {}
      defs.each do |d|
        add.call('LD-009', d, "verb '#{d['verb']}' is defined twice") if by_verb.key?(d['verb'])
        by_verb[d['verb']] = d
      end
      defs.each do |d|
        ([d['verb']] + (d['aliases'] || [])).each do |n|
          owner = names[n]
          if !owner.nil? && owner != d['verb']
            add.call('LD-009', d, "'#{n}' is also a name of '#{owner}'")
          elsif !names.key?(n)
            names[n] = d['verb']
          end
        end
      end
      bound = {}
      defs.each do |d|
        binding_keys(d).each do |k|
          owner = bound[k]
          if !owner.nil? && owner != d['verb']
            add.call('LD-014', d, "binding #{k} is also bound by '#{owner}'")
          else
            bound[k] = d['verb']
          end
        end
      end
      NAME_GROUPS.each do |grp|
        used = {}
        defs.each do |d|
          g = grp.find { |p| last_seg(d['verb']).start_with?(p) }
          used[g] = (used[g] || 0) + 1 if g
        end
        next unless used.length > 1

        win = used.sort_by { |name, count| [-count, A.u16key(name)] }[0][0]
        defs.each do |d|
          g = grp.find { |p| last_seg(d['verb']).start_with?(p) }
          add.call('LW-008', d, "uses '#{g}' where its siblings use '#{win}'") if g && g != win
        end
      end
      unless opts['ns'].nil?
        defs.each do |d|
          add.call('LW-008', d, "verb namespace '#{d['verb'].split('.', -1)[0]}' differs from the file namespace '#{opts['ns']}'") if d['verb'].split('.', -1)[0] != opts['ns']
        end
      end

      # ---- per-def rules
      defs.each do |d|
        n = A.normalize(d)
        pnames = n['params'].keys.sort_by { |k| A.u16key(k) }
        eff = E.effective_with(d, reg, verifier)
        tset = eff['hint']['traits']
        cl = eff['hint']['closure']
        effects = d['effects']
        params = ->(&pred) { pnames.select { |k| pred.call(n['params'][k]) } }
        seg = last_seg(d['verb'])

        add.call('LD-001', d, "the verb says '#{seg}' but effects do not include delete") if DESTROY_RE.match?(seg) && !effects.include?('delete')
        params.call { |q| %w[money.amount money.fee].include?(q['role']) }.each do |k|
          u = n['params'][k]['unit']
          if u.nil? || u['kind'] != 'money'
            add.call('LD-002', d, 'a money parameter needs a unit of kind money with a currency', k)
          elsif !u['ccy'].is_a?(String)
            c = n['params'][u['ccy']['from']]
            add.call('LD-002', d, "the currency parameter '#{u['ccy']['from']}' needs role money.currency and format iso_currency", k) if c.nil? || c['role'] != 'money.currency' || c['format'] != 'iso_currency'
          end
        end
        params.call { |q| q['role'] == 'money.currency' }.each do |k|
          add.call('LD-002', d, 'a currency parameter needs the iso_currency format', k) if n['params'][k]['format'] != 'iso_currency'
        end
        params.call { |q| %w[integer duration].include?(q['type']) }.each do |k|
          q = n['params'][k]
          next if !q['role'].nil? && q['role'].start_with?('id.')
          next if q['role'] == 'count.limit' && q.key?('max')

          add.call('LD-003', d, "a numeric parameter needs both min and max (has #{q.key?('min') ? 'min' : 'no min'}, #{q.key?('max') ? 'max' : 'no max'})", k) if !q.key?('min') || !q.key?('max')
        end
        add.call('LD-004', d, 'a money-moving action needs idempotency key_param or natural') if (effects.include?('pay') || tset.include?('pca.money_moving')) && n['idempotency']['mode'] == 'none'
        pii = params.call { |q| (q['tags'] || []).include?('pii') || (!q['role'].nil? && (q['role'].start_with?('contact.') || q['role'].start_with?('person.'))) }
        unless pii.empty?
          expected = []
          (d['side_effects'] || []).each { |s| expected << s['kind'] if %w[send export].include?(s['kind']) }
          expected << 'send' if SEND_RE.match?(seg)
          expected << 'export' if EXPORT_RE.match?(seg)
          expected.uniq.sort_by(&:b).each do |e|
            add.call('LD-005', d, "personal data can #{e == 'send' ? 'be sent' : 'be exported'} (#{pii.join(', ')}) but effects do not include #{e}") unless effects.include?(e)
          end
        end
        eff['clamps'].each do |c|
          add.call('LD-006', d, "declared #{c['field'] == 'rev' ? 'reversibility' : 'blast'} #{js.js_str(c['declared'])} is below the floor #{js.js_str(c['floor'])}")
        end
        add.call('LD-008', d, "resource id '*' with scope one names every resource at once") if n['resource']['id'] == '*' && n['resource']['scope'] == 'one'
        if !A.read_only?(effects) && U.may_be_reversible(d)
          if d['compensates'].nil?
            add.call('LD-010', d, 'a write declared reversible must name its compensating action (compensates)')
          elsif !by_verb.key?(d['compensates'])
            add.call('LD-010', d, "compensates '#{d['compensates']}', which is not in the pack")
          else
            s = U.compensation_shape(d, by_verb[d['compensates']])
            add.call('LD-010', d, "compensates '#{d['compensates']}', which cannot undo it: #{s['reason']}") unless s['ok']
          end
        end
        review = d['review']
        if review['state'] == 'confirmed'
          a = review['attestation']
          if a.nil?
            add.call('LD-011', d, 'confirmed without an attestation')
          elsif a['def_digest'] != A.def_digest(d)
            add.call('LD-011', d, 'the attestation covers a different digest of this def')
          elsif a['traits_digest'] != A.traits_digest(reg)
            add.call('LD-011', d, 'the attestation was made against a different trait registry')
          elsif verifier ? !verifier.call(d) : !a.key?('sig')
            add.call('LD-011', d, 'the attestation is not signed by a pinned reviewer')
          end
        end
        dismissed = review['state'] == 'confirmed' ? (((review['attestation'] || {})['dismissed']) || []) : []
        dismissed_names = dismissed.map { |x| x['trait'] }
        (((review['provenance'] || {})['union']) || []).each do |t|
          add.call('LD-011', d, "the union-added trait #{t} was removed without a signed dismissal") if !cl.include?(t) && !dismissed_names.include?(t)
        end
        own = %w[money_has_currency money_amount_bounded pay_has_idempotency]
        E.prules_violations(d, eff['hint']['eff']['prules']).each do |r|
          add.call('LD-012', d, "structural rule #{r} is required by the action's traits and violated") unless own.include?(r)
        end
        if A.read_only?(effects)
          enforced = (d['context'] || []).include?('sandbox_attested')
          params.call { |q| %w[code.command query.sql].include?(q['role']) }.each do |k|
            add.call('LD-013', d, 'a read-only action takes code or a query it cannot prove read-only (declare context sandbox_attested)', k) unless enforced
          end
          params.call { |q| (q['tags'] || []).include?('credential') }.each { |k| add.call('LD-013', d, 'a read-only action handles a credential', k) }
        end

        # ---- warnings
        if !d.key?('description')
          add.call('LW-001', d, 'description is missing')
        elsif d['description'].bytesize > 400
          add.call('LW-001', d, 'description is longer than 400 bytes')
        end
        first = (d['title'].split(WS_SPLIT, -1)[0] || '').downcase
        add.call('LW-001', d, "title '#{d['title']}' is not imperative") if /(?:ing|ed)\z/.match?(first) || (/[^s]s\z/.match?(first) && !/(?:us|is)\z/.match?(first)) || %w[a an the].include?(first)
        params.call { |q| q['type'] == 'string' && !q.key?('max_len') && !q.key?('values') }.each { |k| add.call('LW-002', d, 'a string parameter without max_len (the default is 1024; say it)', k) }
        if cl.include?('pca.external_communication')
          params.call do |q|
            q['type'] == 'string' && !q.key?('values') && !q.key?('format') && (q['role'].nil? || q['role'].start_with?('text.')) && !(q['tags'] || []).include?('free_text_outbound')
          end.each do |k|
            add.call('LW-003', d, 'free text flows into an outbound action without tags: [free_text_outbound]', k) if k != n['idempotency']['param']
          end
        end
        add.call('LW-004', d, "a #{review['state']} def in a stable pack") if opts['stability'] == 'stable' && %w[unreviewed suggested].include?(review['state'])
        (((review['attestation'] || {})['dismissed']) || []).each do |x|
          add.call('LW-005', d, "dismissed trait #{x['trait']} has no reason") if js.u16len(AtlasPca::Js.trim(x['reason'])) < 5
        end
        params.call { |q| q['type'] == 'array' && q['max_items'].nil? }.each { |k| add.call('LW-006', d, 'an array parameter without max_items', k) }
        params.call { |q| A::SENSITIVITY_RANK[A.effective_param_sensitivity(q)] >= A::SENSITIVITY_RANK['critical'] && !q.key?('provenance_min') }.each do |k|
          add.call('LW-007', d, 'a critical parameter without provenance_min', k)
        end
        add.call('LW-009', d, 'no example for a money-moving, destructive or privilege-changing action') if (tset.include?('pca.money_moving') || tset.include?('pca.destructive') || tset.include?('pca.privilege_change')) && (d['examples'] || []).empty?
        add.call('LW-010', d, 'since is missing') unless d.key?('since')
      end

      out.sort_by { |f| [u16k(f['verb'] || ''), u16k(f['rule']), u16k(f['param'] || ''), u16k(f['message'])] }
    end

    # Does the run fail? Errors always; warnings under `strict`.
    def lint_fails(fs, strict = false) = fs.any? { |f| f['severity'] == 'error' || (strict && f['severity'] == 'warning') }

    # Plain text, one line per finding.
    def lint_text(fs)
      return '0 errors, 0 warnings' if fs.empty?

      js = A.js
      e = fs.count { |f| f['severity'] == 'error' }
      w = fs.count { |f| f['severity'] == 'warning' }
      lines = fs.map do |f|
        loc = ''
        unless f['file'].nil? || f['file'] == ''
          loc = "#{f['file']}#{f['line'].nil? ? '' : ":#{js.js_str(f['line'])}:#{js.js_str(f['column'].nil? ? 1 : f['column'])}"}: "
        end
        v = f['verb']
        p = f['param']
        v = nil if v == ''
        p = nil if p == ''
        "#{f['severity'].ljust(7)} #{f['rule']}  #{loc}#{v || ''}#{p ? " [#{p}]" : ''}#{v || p ? ': ' : ''}#{f['message']}"
      end
      notes = fs.length - e - w
      "#{lines.join("\n")}\n#{e} error#{e == 1 ? '' : 's'}, #{w} warning#{w == 1 ? '' : 's'}#{notes.positive? ? ", #{notes} note#{notes == 1 ? '' : 's'}" : ''}"
    end

    # SARIF 2.1.0, so findings appear as pull request annotations.
    def to_sarif(fs, tool = nil)
      tool ||= {}
      rules = [STRUCTURE_RULE, NOTE_RULE] + LINT_RULES
      level = ->(s) { s == 'error' ? 'error' : s == 'warning' ? 'warning' : 'note' }
      driver = { 'name' => tool['name'].nil? ? 'pca actions lint' : tool['name'] }
      driver['version'] = tool['version'] if tool['version'] && tool['version'] != ''
      driver['rules'] = rules.map { |r| { 'id' => r[0], 'shortDescription' => { 'text' => r[2] }, 'defaultConfiguration' => { 'level' => level.call(r[1]) } } }
      results = fs.map do |f|
        loc = {}
        if f['file'] && f['file'] != ''
          pl = { 'artifactLocation' => { 'uri' => f['file'] } }
          pl['region'] = { 'startLine' => f['line'], 'startColumn' => f['column'].nil? ? 1 : f['column'] } unless f['line'].nil?
          loc['physicalLocation'] = pl
        end
        loc['logicalLocations'] = [{ 'name' => f['verb'], 'kind' => 'member' }] if f['verb'] && f['verb'] != ''
        prefix = f['verb'] && f['verb'] != '' ? "#{f['verb']}#{f['param'] && f['param'] != '' ? " [#{f['param']}]" : ''}: " : ''
        { 'ruleId' => f['rule'], 'level' => level.call(f['severity']), 'message' => { 'text' => prefix + f['message'] }, 'locations' => [loc] }
      end
      { '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json', 'version' => '2.1.0', 'runs' => [{ 'tool' => { 'driver' => driver }, 'results' => results }] }
    end
  end
end
