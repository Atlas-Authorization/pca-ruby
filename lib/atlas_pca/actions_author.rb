# frozen_string_literal: true

# Authoring forms of an ActionDef (native port of author.ts of the TypeScript reference @atlasauth/pca-actions): the param and resource
# shorthands, the entry expansion and the document loader over an already parsed value. One action has one digest whichever way it was
# written; every expanded def is checked by validate_def. The typed builder is the module `P`.
require_relative 'actions'
require_relative 'js_compat'

module AtlasPca
  module ActionsAuthor
    A = AtlasPca::Actions
    MAX_AUTHOR_BYTES = 1 << 20
    IDEMPOTENCY_PARAM = 'idempotency_key'
    AUTO_IDEMPOTENT_EFFECTS = %w[send pay create provision publish].freeze
    DEFAULT_ID_LEN = [8, 32].freeze
    SHORTHAND_RE = /\A([a-z_]+(?::[a-z0-9_]+(?:\.[a-z0-9_]+){0,3})?)(?:\(([^\n\r  ]*)\))?(\?)?\z/
    INT_ARG_RE = /\A-?[0-9]{1,15}\z/
    INT_RANGE_RE = /\A(-?[0-9]{1,15})\.\.(-?[0-9]{1,15})\z/
    AT_RE = /\A.*@([a-z]+)\z/m
    ID_REST_RE = /\A\{([a-z_]+),([0-9]{1,3})\.\.([0-9]{1,3})\}\z/
    NS_RE = /\A[a-z][a-z0-9_]{0,31}\z/
    ENTRY_KEYS = %w[v kind verb aliases title description effects resource params reversibility blast side_effects idempotency context traits audience
                    compensates bindings examples review source since].freeze
    FILE_KEYS = %w[ns since actions].freeze
    NONE = Object.new.freeze

    module_function

    def trim(s) = AtlasPca::Js.trim(s)

    def bad_shorthand(msg) = raise(A::ActionKitError.new('bad_shorthand', msg))
    def bad_action(msg) = raise(A::ActionKitError.new('bad_action', msg))

    def split_args(s)
      pos = []
      named = {}
      s.split(',', -1).each do |raw|
        a = trim(raw)
        next if a == ''

        eq = a.index('=')
        if !eq.nil? && eq.positive?
          named[trim(a[0, eq])] = trim(a[(eq + 1)..])
        else
          pos << a
        end
      end
      [pos, named]
    end

    def int_arg(s, what)
      return nil if s.nil?

      bad_shorthand("#{what} must be an integer, got '#{s}'") unless INT_ARG_RE.match?(s)
      s.to_i
    end

    def only(pos, named, n, names, shorthand)
      bad_shorthand("'#{shorthand}' takes at most #{n} positional argument(s)") if pos.length > n
      named.each_key { |k| bad_shorthand("'#{shorthand}' has no option '#{k}'") unless names.include?(k) }
    end

    def list_arg(s, shorthand)
      xs = s.split('|', -1).map { |x| trim(x) }
      bad_shorthand("'#{shorthand}' needs values separated by |") if xs.empty? || xs.any? { |x| x == '' }
      xs
    end

    # Expand one param shorthand (email phone url uuid ccy country secret bool date datetime duration text(N) string(N) message(N)
    # int(MIN..MAX) count(MAX) money(CCY|@param, max=, min=, exp=, provenance=) id:<type> enum(a|b) set(a|b) array(items, max=, min=));
    # a trailing `?` makes it optional.
    def parse_param_shorthand(src)
      m = SHORTHAND_RE.match(trim(src))
      bad_shorthand("unknown param shorthand '#{src}'") unless m
      name = m[1]
      inner = m[2]
      optional = m[3] == '?'
      pos, named = split_args(inner || '')
      bare = -> { bad_shorthand("'#{name}' takes no arguments") unless inner.nil? }
      p = case name
          when 'email' then bare.call || { 'type' => 'string', 'role' => 'contact.email', 'format' => 'email', 'tags' => ['pii'], 'max_len' => 254 }
          when 'phone' then bare.call || { 'type' => 'string', 'role' => 'contact.phone', 'format' => 'phone_e164', 'tags' => ['pii'], 'max_len' => 16 }
          when 'url' then bare.call || { 'type' => 'string', 'role' => 'url.target', 'format' => 'url', 'max_len' => 2048 }
          when 'uuid' then bare.call || { 'type' => 'string', 'format' => 'uuid', 'max_len' => 36 }
          when 'ccy' then bare.call || { 'type' => 'string', 'role' => 'money.currency', 'format' => 'iso_currency', 'max_len' => 3 }
          when 'country' then bare.call || { 'type' => 'string', 'format' => 'iso_country', 'max_len' => 2 }
          when 'secret' then bare.call || { 'type' => 'string', 'role' => 'credential.secret', 'tags' => ['secret'], 'max_len' => 512 }
          when 'bool' then bare.call || { 'type' => 'boolean' }
          when 'date' then bare.call || { 'type' => 'date' }
          when 'datetime' then bare.call || { 'type' => 'datetime' }
          when 'duration'
            only(pos, named, 1, [], 'duration')
            mx = int_arg(pos[0], 'duration max (ms)')
            { 'type' => 'duration' }.tap { |h| h.merge!('min' => 0, 'max' => mx) unless mx.nil? }
          when 'text', 'string'
            only(pos, named, 1, [], name)
            n = int_arg(pos[0], "#{name} length")
            { 'type' => 'string' }.tap { |h| h['max_len'] = n unless n.nil? }
          when 'message'
            only(pos, named, 1, [], 'message')
            ml = int_arg(pos[0], 'message length')
            { 'type' => 'string', 'role' => 'text.message', 'tags' => ['free_text_outbound'], 'max_len' => ml.nil? ? 1024 : ml }
          when 'int'
            only(pos, named, 1, [], 'int')
            r = pos.empty? ? nil : INT_RANGE_RE.match(pos[0])
            bad_shorthand('int takes MIN..MAX, for example int(0..100)') if !pos.empty? && r.nil?
            { 'type' => 'integer' }.tap { |h| h.merge!('min' => r[1].to_i, 'max' => r[2].to_i) if r }
          when 'count'
            only(pos, named, 1, [], 'count')
            mx = int_arg(pos[0], 'count max')
            { 'type' => 'integer', 'role' => 'count.limit', 'min' => 1 }.tap { |h| h['max'] = mx unless mx.nil? }.tap { |h| h['unit'] = { 'kind' => 'count' } }
          when 'money'
            only(pos, named, 1, %w[max min exp provenance], 'money')
            c = pos[0]
            bad_shorthand('money needs a currency: money(USD) or money(@currency_param)') if c.nil?
            ccy = c.start_with?('@') ? { 'from' => c[1..] } : c
            mx = int_arg(named['max'], 'money max')
            prov = named.fetch('provenance', 'first_party') # an amount defaults to provenance first_party
            bad_shorthand("money provenance must be one of #{A::PROVENANCE_LEVELS.join(', ')}") unless A::PROVENANCE_LEVELS.include?(prov)
            mn = int_arg(named['min'], 'money min')
            ex = int_arg(named['exp'], 'money exp')
            h = { 'type' => 'integer', 'role' => 'money.amount', 'min' => mn.nil? ? 1 : mn }
            h['max'] = mx unless mx.nil?
            h.merge('unit' => { 'kind' => 'money', 'ccy' => ccy, 'exp' => ex.nil? ? 2 : ex }, 'provenance_min' => prov)
          when 'enum', 'set'
            bad_shorthand("#{name} needs values: #{name}(a|b|c)") if inner.nil?
            { 'type' => name == 'enum' ? 'string' : 'set', 'values' => list_arg(inner, name) }
          when 'array'
            only(pos, named, 1, %w[max min], 'array')
            items = pos[0]
            bad_shorthand('array(items): items is string or integer') unless %w[string integer].include?(items)
            mx = int_arg(named['max'], 'array max')
            mn = int_arg(named['min'], 'array min')
            { 'type' => 'array', 'items' => items }.tap { |h| h['min_items'] = mn unless mn.nil? }.tap { |h| h['max_items'] = mx unless mx.nil? }
          else
            if name.start_with?('id:')
              bare.call || { 'type' => 'string', 'role' => "id.#{name[3..]}", 'max_len' => 64 }
            else
              bad_shorthand("unknown param shorthand '#{name}'")
            end
          end
      optional ? p.merge('required' => false) : p
    end

    # `type`, `type:*`, `type:exact`, `type:prefix*` or `type:prefix*{class,min..max}`, with an optional `@one|set|tenant|global`.
    def parse_resource_shorthand(src)
      s = trim(src)
      scope = nil
      at = AT_RE.match(s)
      if at
        name = at[1]
        bad_shorthand("unknown resource scope '@#{name}'") unless A::RESOURCE_SCOPES.include?(name)
        scope = name
        s = s[0, at.begin(1) - 1]
      end
      colon = s.index(':')
      return { 'type' => s, 'id' => '*', 'scope' => scope || 'tenant' } if colon.nil?

      typ = s[0, colon]
      idsrc = s[(colon + 1)..]
      return { 'type' => typ, 'id' => '*', 'scope' => scope || 'set' } if idsrc == '*'

      star = idsrc.index('*')
      return { 'type' => typ, 'id' => { 'exact' => idsrc }, 'scope' => scope || 'one' } if star.nil?

      prefix = idsrc[0, star]
      rest = idsrc[(star + 1)..]
      cls = 'alnum'
      ln = DEFAULT_ID_LEN.dup
      unless rest == ''
        r = ID_REST_RE.match(rest)
        bad_shorthand("resource id '#{idsrc}': expected prefix*{class,min..max}") if r.nil? || !A::ID_CLASSES.include?(r[1])
        cls = r[1]
        ln = [r[2].to_i, r[3].to_i]
      end
      { 'type' => typ, 'id' => { 'prefix' => prefix, 'class' => cls, 'len' => ln }, 'scope' => scope || 'one' }
    end

    # The title an action gets when it names none: "acme.invoice.send" -> "Send invoice".
    def default_title(verb)
      seg = verb.split('.', -1)[1..] || []
      act = seg.empty? ? verb : seg.last
      t = ([act] + (seg[0...-1] || [])).join(' ').tr('_', ' ')
      "#{t[0, 1].upcase}#{t[1..]}"
    end

    def as_list(v) = v.is_a?(String) ? [v] : v

    # Expand one authoring entry (shorthands or full def members) to {def, notes}. Raises bad_action / bad_shorthand for a malformed entry.
    def expand_action(entry, since = nil)
      bad_action('an action must be an object') unless entry.is_a?(Hash)
      entry.each_key { |k| bad_action("unknown member '#{k}'") unless ENTRY_KEYS.include?(k) }
      bad_action('unsupported def version') if entry.key?('v') && entry['v'] != 1
      bad_action("kind must be '#{A::ACTION_DEF_KIND}'") if entry.key?('kind') && entry['kind'] != A::ACTION_DEF_KIND
      verb = entry['verb']
      bad_action('verb is required') unless verb.is_a?(String)
      notes = []
      if entry.key?('kind')
        full = { 'v' => 1 }.merge(entry) # the full form is taken exactly as written: validate_def decides
        je0 = A.json_profile_error(full)
        bad_action("not strict JSON: #{je0}") if je0
        return { 'def' => full, 'notes' => notes }
      end
      out = { 'v' => 1, 'kind' => A::ACTION_DEF_KIND, 'verb' => verb }
      out['aliases'] = as_list(entry['aliases']) if entry.key?('aliases')
      out['title'] = entry['title'].nil? ? default_title(verb) : entry['title']
      out['description'] = entry['description'] if entry.key?('description')
      # an absent effects / resource is JS undefined in the reference: the strict-JSON check below refuses it (NONE is no JSON value)
      out['effects'] = entry.key?('effects') ? as_list(entry['effects']) : NONE
      res = entry.key?('resource') ? entry['resource'] : NONE
      out['resource'] = res.is_a?(String) ? parse_resource_shorthand(res) : res
      params = {}
      if entry.key?('params')
        bad_action('params must be an object') unless entry['params'].is_a?(Hash)
        entry['params'].each { |k, v| params[k] = v.is_a?(String) ? parse_param_shorthand(v) : v }
      end
      out['reversibility'] = entry['reversibility'] if entry.key?('reversibility')
      out['blast'] = entry['blast'].is_a?(String) ? { 'radius' => entry['blast'] } : entry['blast'] if entry.key?('blast')
      bad_action("unknown blast radius '#{entry['blast']}'") if entry['blast'].is_a?(String) && !A::BLAST_RADII.include?(entry['blast'])
      out['side_effects'] = entry['side_effects'] if entry.key?('side_effects')
      effects = out['effects'].is_a?(Array) ? out['effects'] : []
      idem = entry.key?('idempotency') ? entry['idempotency'] : NONE
      idem = idem == 'key_param' ? { 'mode' => 'key_param', 'param' => IDEMPOTENCY_PARAM } : { 'mode' => idem } if idem.is_a?(String)
      if idem.equal?(NONE) && effects.any? { |e| AUTO_IDEMPOTENT_EFFECTS.include?(e) }
        idem = { 'mode' => 'key_param', 'param' => IDEMPOTENCY_PARAM }
        notes << { 'verb' => verb, 'message' => "#{IDEMPOTENCY_PARAM} auto-added" }
      end
      params[IDEMPOTENCY_PARAM] = { 'type' => 'string', 'max_len' => 64 } if idem.is_a?(Hash) && idem['mode'] == 'key_param' && idem['param'] == IDEMPOTENCY_PARAM && !params.key?(IDEMPOTENCY_PARAM)
      out['idempotency'] = idem unless idem.equal?(NONE)
      out['params'] = params
      %w[context traits].each { |k| out[k] = as_list(entry[k]) if entry.key?(k) }
      %w[audience compensates bindings examples source].each { |k| out[k] = entry[k] if entry.key?(k) }
      out['review'] = entry['review'].nil? ? { 'state' => 'authored' } : entry['review']
      sn = entry['since'].nil? ? since : entry['since']
      out['since'] = sn unless sn.nil?
      je = A.json_profile_error(out)
      bad_action("not strict JSON: #{je}") if je
      { 'def' => out, 'notes' => notes }
    end

    def proto_key?(v, depth = 0)
      return depth > 40 unless v.is_a?(Hash) || v.is_a?(Array)
      return depth > 40 || v.any? { |x| proto_key?(x, depth + 1) } if v.is_a?(Array)

      depth > 40 || v.any? { |k, x| k == '__proto__' || proto_key?(x, depth + 1) }
    end

    # Expand an already parsed document ({ns, since?, actions: [...]}, or one raw def) to {defs, notes, errors, locs, rules[, ns]}. Never raises.
    def load_actions_value(doc)
      res = { 'defs' => [], 'notes' => [], 'errors' => [], 'locs' => {}, 'rules' => {} }
      fail_with = ->(msg) { res.merge('errors' => [{ 'message' => msg }]) }
      return fail_with.call("the document contains a '__proto__' member or nests deeper than 40") if proto_key?(doc)
      return fail_with.call('the document must be an object') unless doc.is_a?(Hash)

      since = nil
      if doc['kind'] == A::ACTION_DEF_KIND
        entries = [doc]
      else
        doc.each_key { |k| return fail_with.call("unknown top-level member '#{k}' (expected ns, since, actions)") unless FILE_KEYS.include?(k) }
        return fail_with.call('ns must be a lowercase identifier') unless doc['ns'].is_a?(String) && NS_RE.match?(doc['ns'])

        res['ns'] = doc['ns']
        if doc['since'].is_a?(String)
          since = doc['since']
        elsif doc.key?('since')
          return fail_with.call('since must be a string')
        end
        return fail_with.call('actions must be a list') unless doc['actions'].is_a?(Array)

        entries = doc['actions']
      end
      entries.each_with_index do |e, index|
        verb = e.is_a?(Hash) && e['verb'].is_a?(String) ? e['verb'] : nil
        err = lambda do |message|
          x = { 'index' => index }
          x['verb'] = verb if verb && verb != ''
          x['message'] = message
          res['errors'] << x
        end
        begin
          rules = NONE
          entry = e
          if e.is_a?(Hash) && e.key?('rules')
            rules = e['rules']
            entry = e.reject { |k, _| k == 'rules' }
          end
          ex = expand_action(entry, since)
          d = ex['def']
          bad = A.validate_def(d)
          if bad
            err.call(bad)
            next
          end
          unless rules.equal?(NONE)
            require_relative 'actions_rules'
            re = ActionsRules.business_rules_error(d, rules)
            if re
              err.call(re)
              next
            end
            res['rules'][d['verb']] = rules
          end
          res['defs'] << d
          res['notes'].concat(ex['notes'])
        rescue StandardError => x
          err.call(x.is_a?(A::ActionKitError) ? x.message : "malformed action: #{x.message}")
        end
      end
      res
    end

    # Load an authoring file (YAML 1.2 core or JSON) with source positions. The syntax layer is Psych's parser (events only); see
    # ActionsYamlLoad for what it refuses beyond the reference. Input above MAX_AUTHOR_BYTES is refused. Never raises.
    def load_actions_text(text, fmt = 'yaml')
      require_relative 'actions_yaml_load'
      y = AtlasPca::ActionsYamlLoad
      fail_with = lambda do |message, line = 1, column = 1|
        { 'defs' => [], 'notes' => [], 'errors' => [{ 'message' => message, 'line' => line, 'column' => column }], 'locs' => {}, 'rules' => {} }
      end
      return fail_with.call("the file is larger than #{MAX_AUTHOR_BYTES} bytes") if text.bytesize > MAX_AUTHOR_BYTES

      positions = nil
      if fmt == 'json'
        begin
          value = AtlasPca::Js.parse(text)
        rescue StandardError => e
          return fail_with.call("not JSON: #{e.message}")
        end
        positions = begin # JSON is YAML: only the positions come from the YAML parse, the value from the JSON parse
          y.positions_of(y.parse_document(text.gsub(/\\u[dD][89a-fA-F][0-9a-fA-F]{2}/, '\\u0041'), false)) # libyaml refuses surrogate escapes; same width keeps the columns
        rescue StandardError
          nil
        end
      else
        begin
          root = y.parse_document(text)
          value = y.to_value(root)
          positions = y.positions_of(root)
        rescue y::YamlError => e
          return fail_with.call("not YAML: #{e.message}", e.line, e.column)
        end
      end
      res = load_actions_value(value)
      y.attach_positions(res, positions) unless positions.nil?
      res
    end

    # The typed constructor over the JSON form: the same expansion as the loader (so the same digest); raises bad_action on a malformed spec.
    def action(verb, spec)
      d = expand_action({ 'verb' => verb }.merge(spec))['def']
      bad = A.validate_def(d)
      bad_action("#{verb}: #{bad}") if bad
      d
    end

    # Typed param constructors; each returns the same param the matching shorthand expands to. A trailing `x` adds or overrides members.
    module P
      module_function

      def with_extra(p, x = nil) = x && !x.empty? ? p.merge(x) : p
      def shorthand(s, x = nil) = with_extra(ActionsAuthor.parse_param_shorthand(s), x)

      %w[email phone url uuid ccy country secret date datetime].each { |n| define_method(n) { |x = nil| shorthand(n, x) } }
      def bool_(x = nil) = shorthand('bool', x)
      def duration(max_ms = nil, x = nil) = shorthand(max_ms.nil? ? 'duration' : "duration(#{max_ms})", x)
      def message(max_len = nil, x = nil) = shorthand(max_len.nil? ? 'message' : "message(#{max_len})", x)
      def text(max_len = nil, x = nil) = shorthand(max_len.nil? ? 'text' : "text(#{max_len})", x)
      def int_(min = nil, max = nil, x = nil) = shorthand(min.nil? || max.nil? ? 'int' : "int(#{min}..#{max})", x)
      def count(max = nil, x = nil) = shorthand(max.nil? ? 'count' : "count(#{max})", x)

      # `ccy` is a literal ISO code, or {"from" => "param"} naming the currency param.
      def money(ccy, o = nil, x = nil)
        o ||= {}
        c = ccy.is_a?(String) ? ccy : "@#{ccy['from']}"
        opts = %w[max min exp].select { |k| !o[k].nil? }.map { |k| ", #{k}=#{o[k]}" }.join
        shorthand("money(#{c}#{opts})", x)
      end

      def id_(type, x = nil) = shorthand("id:#{type}", x)
      def enum_(values, x = nil) = shorthand("enum(#{values.join('|')})", x)
      def set_(values, x = nil) = shorthand("set(#{values.join('|')})", x)
      def array(items, max = nil, x = nil) = shorthand(max.nil? ? "array(#{items})" : "array(#{items}, max=#{max})", x)
      def optional(d) = d.merge('required' => false)
    end
  end
end
