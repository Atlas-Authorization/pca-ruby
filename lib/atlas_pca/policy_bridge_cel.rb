# frozen_string_literal: true

require_relative 'policy_bridge'

module AtlasPca
  module PolicyBridge
    # ---- strict CEL
    MAX_EXPR = 4096
    CEL_MAX_DEPTH = 32
    MAX_NODES = 256
    MAX_LIST = 64
    MAX_STR = 256
    CEL_IDENT = PolicyBridge.full('[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*')
    PCA_PATH = PolicyBridge.full('(?:action|subject|env)(?:\\.[A-Za-z_][A-Za-z0-9_]*)+')
    FORBIDDEN = %w[__proto__ constructor prototype].freeze
    PUNCT = ['&&', '||', '==', '!=', '<=', '>=', '<', '>', '!', '(', ')', '[', ']', ',', '.', '-'].freeze
    UNSUPPORTED_CH = {
      '+' => 'arithmetic (+)', '*' => 'arithmetic (*)', '/' => 'arithmetic (/)', '%' => 'arithmetic (%)', '?' => 'the conditional operator',
      ':' => 'the conditional operator / map literal', '{' => 'map or message literal', '}' => 'map or message literal', '@' => '@',
      '&' => 'bitwise &', '|' => 'bitwise |', '^' => '^', '~' => '~', '=' => 'assignment', '`' => 'quoted identifier'
    }.freeze
    RELOPS = %w[== != < <= > >=].freeze
    REJECTED_FUNCS = ('size matches exists all exists_one map filter int uint double string bytes bool duration type dyn min max getHours ' \
                      'getDayOfWeek getMinutes getSeconds getFullYear getMonth getDate getDayOfMonth getDayOfYear getMilliseconds extract ' \
                      'format lowerAscii upperAscii trim split join replace substring indexOf lastIndexOf charAt isIpv4 inIpRange cidr ip ' \
                      'isCIDR containsIp url quantity semver optional').split.freeze
    ESCAPES = { '\\' => '\\', '"' => '"', "'" => "'", 'n' => "\n", 't' => "\t", 'r' => "\r" }.freeze
    TS = PolicyBridge.full('(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(?:\\.(\\d{1,3}))?Z')

    class Reject < StandardError
      attr_reader :code, :at

      def initialize(code, message, at)
        super(message)
        @code = code
        @at = at
      end
    end

    module_function

    def rej(code, message, at) = raise(Reject.new(code, message, at))
    def letter?(c) = !c.nil? && c.match?(/\A[A-Za-z_]\z/)
    def digit?(c) = !c.nil? && c.match?(/\A[0-9]\z/)

    def lex(src)
      out = []
      n = src.length
      i = 0
      while i < n
        c = src[i]
        if " \t\n\r".include?(c)
          i += 1
          next
        end
        rej('unsupported', 'comments', i) if c == '/' && src[i + 1] == '/'
        if letter?(c)
          j = i + 1
          j += 1 while j < n && (letter?(src[j]) || digit?(src[j]))
          w = src[i...j]
          rej('unsupported', "#{w.downcase == 'r' ? 'raw string' : 'bytes'} literal", i) if %w[r b R B].include?(w) && ['"', "'"].include?(src[j])
          out << { 'k' => 'id', 'v' => w, 'at' => i }
          i = j
          next
        end
        if digit?(c)
          j = i
          j += 1 while j < n && digit?(src[j])
          nxt = src[j]
          rej('unsupported', 'double literal', i) if nxt == '.' && digit?(src[j + 1])
          rej('unsupported', 'double literal', i) if %w[e E].include?(nxt)
          rej('unsupported', 'unsigned integer literal', i) if %w[u U].include?(nxt)
          rej('unsupported', 'hexadecimal literal', i) if %w[x X].include?(nxt)
          w = src[i...j]
          rej('unsupported', 'integer literal with a leading zero', i) if w.length > 1 && w[0] == '0'
          out << { 'k' => 'int', 'v' => w, 'at' => i }
          i = j
          next
        end
        if c == '"' || c == "'"
          rej('unsupported', 'triple-quoted string', i) if src[i, 3] == c * 3
          j = i + 1
          parts = []
          loop do
            d = src[j]
            rej('syntax', 'unterminated string', i) if d.nil? || d == "\n" || d == "\r"
            break if d == c

            if d == '\\'
              e = src[j + 1].to_s
              rej('unsupported', "string escape \\#{e}", j) if e.empty? || !ESCAPES.key?(e)
              parts << ESCAPES[e]
              j += 2
              next
            end
            parts << d
            j += 1
          end
          s = parts.join
          rej('too_complex', "string literal longer than #{MAX_STR}", i) if s.length > MAX_STR
          out << { 'k' => 'str', 'v' => s, 'at' => i }
          i = j + 1
          next
        end
        p = PUNCT.find { |x| src[i, x.length] == x }
        rej(UNSUPPORTED_CH.key?(c) ? 'unsupported' : 'syntax', UNSUPPORTED_CH.fetch(c) { "unexpected character '#{c}'" }, i) if p.nil?
        out << { 'k' => 'p', 'v' => p, 'at' => i }
        i += p.length
      end
      out
    end

    def days_from_civil(y, m, d)
      y -= 1 if m <= 2
      era = (y >= 0 ? y : y - 399) / 400
      yoe = y - (era * 400)
      doy = (((153 * (m + (m > 2 ? -3 : 9))) + 2) / 5) + d - 1
      doe = (yoe * 365) + (yoe / 4) - (yoe / 100) + doy
      (era * 146_097) + doe - 719_468
    end

    def parse_timestamp(s, at)
      m = TS.match(s)
      rej('unsupported', 'timestamp() argument must be RFC 3339 UTC (Z) with at most millisecond precision', at) unless m
      date, time = m[1].split('T')
      y, mo, d = date.split('-').map(&:to_i)
      h, mi, sec = time.split(':').map(&:to_i)
      ms = (m[2] || '').ljust(3, '0').to_i
      leap = (y % 4).zero? && (y % 100 != 0 || (y % 400).zero?)
      dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
      rej('unsupported', 'timestamp() is not a real instant', at) unless mo.between?(1, 12) && d >= 1 && d <= dim[mo - 1] && h <= 23 && mi <= 59 && sec <= 59
      (((((days_from_civil(y, mo, d) * 24) + h) * 60 + mi) * 60) + sec) * 1000 + ms
    end

    # recursive-descent parser over the token list
    class CelParser
      def initialize(src)
        @src = src
        @toks = PolicyBridge.lex(src)
        @pos = 0
        @nodes = 0
      end

      def parse
        root = expr(0)
        PolicyBridge.rej('syntax', "unexpected '#{@toks[@pos]['v']}'", @toks[@pos]['at']) if @pos < @toks.length
        root
      end

      private

      def peek = @pos < @toks.length ? @toks[@pos] : nil
      def p?(v) = (t = peek) && t['k'] == 'p' && t['v'] == v

      def eat(v)
        return false unless p?(v)

        @pos += 1
        true
      end

      def need(v)
        return if eat(v)

        t = peek
        PolicyBridge.rej('syntax', "expected '#{v}'", t ? t['at'] : @src.length)
      end

      def tick(at)
        @nodes += 1
        PolicyBridge.rej('too_complex', "more than #{MAX_NODES} nodes", at) if @nodes > MAX_NODES
      end

      def expr(d)
        if d > CEL_MAX_DEPTH
          t = peek
          PolicyBridge.rej('too_complex', "nesting deeper than #{CEL_MAX_DEPTH}", t ? t['at'] : 0)
        end
        or_(d)
      end

      def or_(d)
        left = and_(d)
        while p?('||')
          at = peek['at']
          @pos += 1
          tick(at)
          left = { 't' => 'or', 'l' => left, 'r' => and_(d), 'at' => at }
        end
        left
      end

      def and_(d)
        left = rel(d)
        while p?('&&')
          at = peek['at']
          @pos += 1
          tick(at)
          left = { 't' => 'and', 'l' => left, 'r' => rel(d), 'at' => at }
        end
        left
      end

      def relop?(t) = (t['k'] == 'p' && RELOPS.include?(t['v'])) || (t['k'] == 'id' && t['v'] == 'in')

      def rel(d)
        left = unary(d)
        t = peek
        return left if t.nil? || !relop?(t)

        @pos += 1
        tick(t['at'])
        n = { 't' => 'rel', 'op' => t['v'], 'l' => left, 'r' => unary(d), 'at' => t['at'] }
        u = peek
        PolicyBridge.rej('unsupported', 'chained comparison', u['at']) if !u.nil? && relop?(u)
        n
      end

      def unary(d)
        t = peek
        if !t.nil? && t['k'] == 'p' && t['v'] == '!'
          @pos += 1
          tick(t['at'])
          PolicyBridge.rej('too_complex', "nesting deeper than #{CEL_MAX_DEPTH}", t['at']) if d + 1 > CEL_MAX_DEPTH
          return { 't' => 'not', 'e' => unary(d + 1), 'at' => t['at'] }
        end
        if !t.nil? && t['k'] == 'p' && t['v'] == '-'
          nx = @pos + 1 < @toks.length ? @toks[@pos + 1] : nil
          PolicyBridge.rej('unsupported', 'unary minus on a non-literal', t['at']) if nx.nil? || nx['k'] != 'int'
          @pos += 2
          return int_node("-#{nx['v']}", t['at'])
        end
        member(d)
      end

      def int_node(text, at)
        tick(at)
        v = text.to_i
        PolicyBridge.rej('unsupported', 'integer literal outside the safe-integer range', at) if v.abs > 9_007_199_254_740_991
        { 't' => 'int', 'v' => v, 'at' => at }
      end

      def args(d)
        a = []
        unless p?(')')
          a << expr(d + 1)
          a << expr(d + 1) while eat(',')
        end
        need(')')
        a
      end

      def member(d)
        n = primary(d)
        while p?('.')
          dot = peek
          @pos += 1
          ident = peek
          PolicyBridge.rej('syntax', "expected a name after '.'", dot['at']) if ident.nil? || ident['k'] != 'id'
          @pos += 1
          if p?('(')
            @pos += 1
            a = args(d)
            PolicyBridge.rej('unsupported', "method '#{ident['v']}'", ident['at']) unless %w[startsWith endsWith contains].include?(ident['v'])
            PolicyBridge.rej('syntax', "'#{ident['v']}' takes one argument", ident['at']) if a.length != 1
            tick(ident['at'])
            n = { 't' => 'method', 'target' => n, 'fn' => ident['v'], 'arg' => a[0], 'at' => ident['at'] }
          else
            PolicyBridge.rej('unsupported', 'field selection on something that is not a declared variable', dot['at']) if n['t'] != 'var'
            n = n.merge('name' => "#{n['name']}.#{ident['v']}")
          end
        end
        PolicyBridge.rej('unsupported', 'index operator', peek['at']) if p?('[')
        n
      end

      def primary(d)
        t = peek
        PolicyBridge.rej('syntax', 'unexpected end of expression', @src.length) if t.nil?
        if t['k'] == 'int'
          @pos += 1
          return int_node(t['v'], t['at'])
        end
        if t['k'] == 'str'
          @pos += 1
          tick(t['at'])
          return { 't' => 'str', 'v' => t['v'], 'at' => t['at'] }
        end
        if t['k'] == 'p' && t['v'] == '('
          @pos += 1
          e = expr(d + 1)
          need(')')
          return e
        end
        if t['k'] == 'p' && t['v'] == '['
          @pos += 1
          items = []
          unless p?(']')
            loop do
              PolicyBridge.rej('too_complex', "list longer than #{MAX_LIST}", t['at']) if items.length >= MAX_LIST
              items << expr(d + 1)
              break unless eat(',')
            end
          end
          need(']')
          tick(t['at'])
          return { 't' => 'list', 'items' => items, 'at' => t['at'] }
        end
        if t['k'] == 'id'
          @pos += 1
          if %w[true false].include?(t['v'])
            tick(t['at'])
            return { 't' => 'bool', 'v' => t['v'] == 'true', 'at' => t['at'] }
          end
          PolicyBridge.rej('unsupported', 'null', t['at']) if t['v'] == 'null'
          if p?('(')
            @pos += 1
            a = args(d)
            if t['v'] == 'has'
              PolicyBridge.rej('syntax', 'has() takes one declared variable', t['at']) if a.length != 1 || a[0]['t'] != 'var'
              tick(t['at'])
              return { 't' => 'has', 'e' => a[0], 'at' => t['at'] }
            end
            if t['v'] == 'timestamp'
              PolicyBridge.rej('unsupported', 'timestamp() of a non-literal', t['at']) if a.length != 1 || a[0]['t'] != 'str'
              return { 't' => 'ts', 'v' => PolicyBridge.parse_timestamp(a[0]['v'], t['at']), 'at' => t['at'] }
            end
            PolicyBridge.rej('unsupported', "#{REJECTED_FUNCS.include?(t['v']) ? 'function' : 'unknown function'} '#{t['v']}'", t['at'])
          end
          PolicyBridge.rej('syntax', "unexpected 'in'", t['at']) if t['v'] == 'in'
          tick(t['at'])
          return { 't' => 'var', 'name' => t['v'], 'at' => t['at'] }
        end
        PolicyBridge.rej('syntax', "unexpected '#{t['v']}'", t['at'])
      end
    end

    INTERNAL = { 'ok' => false, 'code' => 'syntax', 'message' => 'internal error', 'at' => 0 }.freeze

    def parse_src(src)
      PolicyBridge.rej('syntax', 'empty expression', 0) if !src.is_a?(String) || src.empty?
      PolicyBridge.rej('too_complex', "expression longer than #{MAX_EXPR} characters", 0) if src.length > MAX_EXPR
      CelParser.new(src).parse
    end

    def cel_error(e) = { 'ok' => false, 'code' => e.code, 'message' => e.message, 'at' => e.at }
    def units_of(expression) = expression.is_a?(String) ? PolicyBridge.to_units(expression) : expression

    # Parse a CEL expression of the supported subset: {ok: true, ast} or {ok: false, code, message, at}.
    def parse_cel(expression)
      PolicyBridge.deep_from_units({ 'ok' => true, 'ast' => parse_src(units_of(expression)) })
    rescue Reject => e
      PolicyBridge.deep_from_units(cel_error(e))
    rescue StandardError, SystemStackError # the reference reports any non-rejection as an internal error
      INTERNAL.dup
    end

    def schema_error(s)
      return 'the schema must be an object' unless s.is_a?(Hash)

      vars = s['vars']
      return 'the schema needs a vars object' unless vars.is_a?(Hash)

      Js.js_keys(vars).each do |name|
        v = vars[name]
        return "bad variable name '#{name}'" if !CEL_IDENT.match?(name) || name.split('.', -1).any? { |x| FORBIDDEN.include?(x) }

        path = v.is_a?(Hash) ? v['path'] : nil
        if !(v.is_a?(Hash) || v.is_a?(Array)) || !path.is_a?(String) || !PCA_PATH.match?(path) || path.split('.', -1).any? { |x| FORBIDDEN.include?(x) }
          return "variable '#{name}' needs a path rooted at action, subject or env"
        end

        t = v['type']
        return "variable '#{name}' has an unsupported type" if !t.is_a?(String) || !%w[string int bool timestamp_ms].include?(t)
        return "variable '#{name}': optional must be a boolean" if v.key?('optional') && v['optional'] != true && v['optional'] != false
      end
      nil
    end

    # the AST -> PCA condition translation, one boolean expression
    class CelTranslator
      PCA_OP = { '==' => 'eq', '!=' => 'ne', '<' => 'lt', '<=' => 'lte', '>' => 'gt', '>=' => 'gte' }.freeze
      FLIP = { 'eq' => 'eq', 'ne' => 'ne', 'lt' => 'gt', 'lte' => 'gte', 'gt' => 'lt', 'gte' => 'lte' }.freeze

      attr_reader :fields

      def initialize(svars)
        @svars = svars
        @fields = {}
      end

      def operand(n)
        case n['t']
        when 'var'
          PolicyBridge.rej('unknown_identifier', "'#{n['name']}' is not declared in the schema", n['at']) unless @svars.key?(n['name'])
          return { 'kind' => 'var', 'v' => @svars[n['name']], 'name' => n['name'] }
        when 'int' then return { 'kind' => 'lit', 'type' => 'int', 'value' => n['v'] }
        when 'str' then return { 'kind' => 'lit', 'type' => 'string', 'value' => n['v'] }
        when 'bool' then return { 'kind' => 'lit', 'type' => 'bool', 'value' => n['v'] }
        when 'ts' then return { 'kind' => 'lit', 'type' => 'timestamp_ms', 'value' => n['v'] }
        end
        PolicyBridge.rej('unsupported', 'a computed value as a comparison operand', n['at'])
      end

      def type_of(o) = o['kind'] == 'var' ? o['v']['type'] : o['type']

      def read(o)
        @fields[o['v']['path']] = nil
        o['v']['path']
      end

      def flat(n, t, out)
        if n['t'] == t
          flat(n['l'], t, out)
          flat(n['r'], t, out)
        else
          out << n
        end
        out
      end

      def tr(n)
        t = n['t']
        return { 'any_of' => flat(n, 'or', []).map { |x| tr(x) } } if t == 'or'
        return { 'all_of' => flat(n, 'and', []).map { |x| tr(x) } } if t == 'and'
        return { 'not' => tr(n['e']) } if t == 'not'

        if t == 'has'
          o = operand(n['e'])
          PolicyBridge.rej('syntax', 'has() takes a declared variable', n['at']) if o['kind'] != 'var'
          if o['v']['optional'] != true
            PolicyBridge.rej('has_requires_optional', "has(#{o['name']}): mark the variable optional in the schema (its container must always be present)", n['at'])
          end
          return { 'field' => read(o), 'op' => 'exists', 'value' => true }
        end
        if t == 'var'
          o = operand(n)
          hint = o['kind'] == 'var' && o['v']['type'] == 'bool' ? " (write #{n['name']} == true)" : ''
          PolicyBridge.rej('unsupported', "a bare variable '#{n['name']}' as a condition#{hint}", n['at'])
        end
        return method_node(n) if t == 'method'
        return rel_node(n) if t == 'rel'

        PolicyBridge.rej('constant_expression', 'a bare constant is not a condition', n['at'])
      end

      def method_node(n)
        tg = operand(n['target'])
        PolicyBridge.rej('type_mismatch', "#{n['fn']} needs a string variable", n['at']) if tg['kind'] != 'var' || tg['v']['type'] != 'string'
        if n['arg']['t'] != 'str' || n['arg']['v'].empty?
          PolicyBridge.rej('unsupported', "#{n['fn']} of anything but a non-empty string literal", n['at'])
        end
        lit = n['arg']['v']
        return { 'field' => read(tg), 'op' => 'prefix', 'value' => lit } if n['fn'] == 'startsWith'

        esc = lit.gsub(/[\\*?]/) { |m| "\\#{m}" }
        glob = n['fn'] == 'endsWith' ? "*#{esc}" : "*#{esc}*"
        PolicyBridge.rej('too_complex', 'literal too long for a glob', n['at']) if glob.length > 512
        { 'field' => read(tg), 'op' => 'like', 'value' => glob }
      end

      def rel_node(n)
        if n['op'] == 'in'
          left = operand(n['l'])
          PolicyBridge.rej('constant_expression', 'the left side of "in" must be a declared variable', n['at']) if left['kind'] != 'var'
          if n['r']['t'] != 'list' || n['r']['items'].empty?
            PolicyBridge.rej('unsupported', '"in" against anything but a non-empty list literal', n['at'])
          end
          items = n['r']['items'].map { |x| operand(x) }
          if items.any? { |i| i['kind'] != 'lit' || i['type'] != left['v']['type'] }
            PolicyBridge.rej('type_mismatch', "list items must be #{left['v']['type']} literals", n['at'])
          end
          return { 'field' => read(left), 'op' => 'in', 'value' => items.map { |i| i['value'] } }
        end
        left = operand(n['l'])
        right = operand(n['r'])
        PolicyBridge.rej('constant_expression', 'a comparison of two literals', n['at']) if left['kind'] == 'lit' && right['kind'] == 'lit'
        PolicyBridge.rej('type_mismatch', "#{type_of(left)} against #{type_of(right)}", n['at']) if type_of(left) != type_of(right)
        ty = type_of(left)
        eq_op = n['op'] == '==' || n['op'] == '!='
        PolicyBridge.rej('type_mismatch', 'ordering of booleans', n['at']) if !eq_op && ty == 'bool'
        pca_op = PCA_OP[n['op']]
        return { 'field' => read(left), 'op' => pca_op, 'ref' => read(right) } if left['kind'] == 'var' && right['kind'] == 'var'
        return { 'field' => read(left), 'op' => pca_op, 'value' => right['value'] } if left['kind'] == 'var'

        { 'field' => read(right), 'op' => FLIP[pca_op], 'value' => left['value'] }
      end
    end

    # ONE boolean CEL expression as a PCA condition, or a rejection naming the construct (there is no best-effort mode):
    # {ok: true, condition, fields} or {ok: false, code, message, at}. `schema` is {vars: {name: {path, type, optional?}}}.
    def cel_to_condition(expression, schema)
      se = schema_error(schema)
      return { 'ok' => false, 'code' => 'bad_schema', 'message' => se, 'at' => 0 } unless se.nil?

      begin
        ast = parse_src(units_of(expression))
      rescue Reject => e
        return PolicyBridge.deep_from_units(cel_error(e))
      rescue StandardError, SystemStackError
        return INTERNAL.dup
      end
      tl = CelTranslator.new(schema['vars'])
      begin
        condition = tl.tr(ast)
        rej('constant_expression', 'the expression reads no variable', 0) if tl.fields.empty?
        PolicyBridge.deep_from_units({ 'ok' => true, 'condition' => condition, 'fields' => tl.fields.keys.sort_by { |f| PolicyBridge.u16key(f) } })
      rescue Reject => e
        PolicyBridge.deep_from_units(cel_error(e))
      rescue StandardError, SystemStackError
        INTERNAL.dup
      end
    end

    # One CEL expression as a permit predicate for `scope.verb` (and optionally `scope.resource`).
    def cel_to_predicate(expression, schema, scope)
      r = cel_to_condition(expression, schema)
      return r unless r['ok']

      p = { 'verb' => scope['verb'] }
      p['resource'] = scope['resource'] if scope.is_a?(Hash) && scope.key?('resource')
      p['where'] = [r['condition']]
      { 'ok' => true, 'predicate' => p, 'fields' => r['fields'] }
    end

    def js_text(x)
      return 'undefined' if x.equal?(MISSING)

      x.nil? ? 'null' : Js.string(x)
    end

    # A batch of named CEL expressions: every one is translated or REPORTED; one rejection makes `report.errors` non-empty, and
    # `decide` then denies everything (an incomplete import never grants).
    def cel_conditions_to_pca(items, schema)
      predicates = []
      translated = []
      errors = []
      items.each do |it|
        scope = { 'verb' => it['verb'] }
        scope['resource'] = it['resource'] if it.key?('resource')
        r = cel_to_predicate(it['expression'], schema, scope)
        name = js_text(it.key?('name') ? it['name'] : MISSING)
        if r['ok']
          predicates << r['predicate']
          translated << "#{name}: translated exactly (reads #{r['fields'].join(', ')})"
        else
          errors << "#{name}: rejected (#{r['code']}) at #{r['at']}: #{r['message']}"
        end
      end
      { 'predicates' => predicates, 'denies' => [], 'caveats' => [], 'report' => { 'source' => 'cel', 'translated' => translated, 'skipped' => [], 'errors' => errors } }
    end
  end
end
