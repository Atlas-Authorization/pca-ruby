# frozen_string_literal: true

require_relative 'js_compat'
require_relative 'siem'
require_relative 'predicates'

module AtlasPca
  # Import external authorization policy into PCA predicates. Mirrors the TypeScript reference (@atlasauth/pca-policy-bridge).
  #
  #   cedar_to_pca(text)            Cedar permit / forbid policies
  #   rego_to_pca(text)             OPA / Rego allow-rule subset
  #   openfga_to_pca(model, tuples) OpenFGA / Zanzibar ReBAC model + relationship tuples
  #   cel_to_condition(...)         strict CEL expressions (one condition, or a rejection naming the construct)
  #   decide(result, ctx)           deny-overrides-permit over a translation, built on the core predicate evaluator
  #
  # Every translator returns {predicates, denies, caveats, report: {source, translated, skipped, errors}}; whatever is not modeled
  # fails closed. Text is read the way JavaScript reads it: the translators work on a UTF-16 code-unit view of the input (one
  # character per unit, a surrogate standing as a private-use stand-in), the JavaScript whitespace set and ASCII word characters,
  # so messages and offsets agree with the reference.
  module PolicyBridge
    UNDEF = Object.new.freeze
    MISSING = Object.new.freeze
    WS = Siem::WS
    S = "[#{WS}]"
    DOT = "[^\\n\\r\\u2028\\u2029]"

    # ---- UTF-16 unit view
    # one character per code unit: an astral code point is split into its surrogate pair, a surrogate is a plane-15 stand-in
    def self.to_units(s)
      Siem::U16.units(s).map { |u| u >= 0xD800 && u <= 0xDFFF ? 0xF0000 + (u - 0xD800) : u }.pack('U*')
    end

    # a unit view back to a string: surrogate pairs combine, a lone surrogate stays
    def self.from_units(s)
      Siem::U16.from_units(s.each_codepoint.map { |c| c >= 0xF0000 && c <= 0xF07FF ? c - 0xF0000 + 0xD800 : c })
    end

    def self.deep_from_units(v)
      case v
      when String then from_units(v)
      when Array then v.map { |x| deep_from_units(x) }
      when Hash then v.to_h { |k, x| [from_units(k), deep_from_units(x)] }
      else v
      end
    end

    # UTF-16 code-unit ordering key of a unit view
    def self.u16key(s) = s.each_codepoint.map { |c| c >= 0xF0000 && c <= 0xF07FF ? c - 0xF0000 + 0xD800 : c }

    def self.rx(src) = Regexp.new("(?a)#{src}")
    def self.full(src) = Regexp.new("(?a)\\A(?:#{src})\\z")
    def self.head(src) = Regexp.new("(?a)\\A(?:#{src})")

    module_function

    def trim(s) = Js.trim(s)

    # JSON.stringify of a unit-view string (a lone surrogate is escaped, a pair stays)
    def jstr(s)
      out = +'"'
      cps = s.codepoints.map { |c| c >= 0xF0000 && c <= 0xF07FF ? c - 0xF0000 + 0xD800 : c }
      i = 0
      while i < cps.length
        o = cps[i]
        c = o >= 0xD800 && o <= 0xDFFF ? [0xF0000 + (o - 0xD800)].pack('U') : [o].pack('U')
        if o == 0x22 then out << '\\"'
        elsif o == 0x5C then out << '\\\\'
        elsif o == 8 then out << '\\b'
        elsif o == 12 then out << '\\f'
        elsif o == 10 then out << '\\n'
        elsif o == 13 then out << '\\r'
        elsif o == 9 then out << '\\t'
        elsif o < 0x20 then out << format('\\u%04x', o)
        elsif o >= 0xD800 && o <= 0xDBFF && i + 1 < cps.length && cps[i + 1] >= 0xDC00 && cps[i + 1] <= 0xDFFF
          out << c << [0xF0000 + (cps[i + 1] - 0xD800)].pack('U')
          i += 1
        elsif o >= 0xD800 && o <= 0xDFFF then out << format('\\u%04x', o)
        else out << c
        end
        i += 1
      end
      out << '"'
    end

    def jverb(v) = v.is_a?(String) ? jstr(v) : "[#{v.map { |x| jstr(x) }.join(',')}]"

    WS_RUN = PolicyBridge.rx("#{S}+")

    def truncate(s)
      one = trim(s.gsub(WS_RUN, ' '))
      one.length > 80 ? "#{one[0, 77]}..." : one
    end

    def number(s)
      return s.to_f if s.include?('.')

      v = s.to_i
      v.abs > 9_007_199_254_740_991 ? v.to_f : v
    end

    def entries(o)
      case o
      when Hash then Js.js_keys(o).map { |k| [k, o[k]] }
      when Array then o.each_with_index.map { |x, i| [i.to_s, x] }
      end
    end

    # ---- bracket and quote aware scanning
    def index_of_top_level(text, token)
      depth = 0
      in_str = false
      text.each_char.with_index do |ch, i|
        if in_str
          in_str = false if ch == '"'
          next
        end
        if ch == '"'
          in_str = true
          next
        end
        if '([{'.include?(ch) then depth += 1
        elsif ')]}'.include?(ch) then depth -= 1
        elsif depth.zero? && text[i, token.length] == token then return i
        end
      end
      -1
    end

    def split_top_level(text, delim)
      out = []
      depth = 0
      in_str = false
      start = 0
      i = 0
      n = text.length
      while i < n
        ch = text[i]
        if in_str
          in_str = false if ch == '"'
          i += 1
          next
        end
        if ch == '"'
          in_str = true
          i += 1
          next
        end
        if '([{'.include?(ch) then depth += 1
        elsif ')]}'.include?(ch) then depth -= 1
        end
        if depth.zero? && text[i, delim.length] == delim
          out << text[start...i]
          i += delim.length - 1
          start = i + 1
        end
        i += 1
      end
      out << text[start..]
      out
    end

    def match_delim(text, open_, o, c)
      depth = 0
      in_str = false
      (open_...text.length).each do |i|
        ch = text[i]
        if in_str
          in_str = false if ch == '"'
          next
        end
        if ch == '"' then in_str = true
        elsif ch == o then depth += 1
        elsif ch == c
          depth -= 1
          return i if depth.zero?
        end
      end
      -1
    end

    def new_report(source) = { 'source' => source, 'translated' => [], 'skipped' => [], 'errors' => [] }
    def result(predicates, denies, report) = { 'predicates' => predicates, 'denies' => denies, 'caveats' => [], 'report' => report }
    def trimmed_non_empty(parts) = parts.map { |p| trim(p) }.reject(&:empty?)

    # ---- Cedar
    ENTITY_PARENTS = 'env.entity_parents'

    # A construct outside the modeled Cedar subset; the message lands in the report.
    class CedarError < StandardError; end

    # Cedar `permit` / `forbid` policies as permit predicates and deny predicates (consume with `decide`).
    def cedar_to_pca(policy_text) = translate_cedar(policy_text, true)

    # error_guards = false omits the trailing "no attribute was missing" guard (bare structure; not exact)
    def translate_cedar(policy_text, error_guards)
      report = new_report('cedar')
      predicates = []
      denies = []
      cleaned = PolicyBridge.to_units(policy_text).gsub(/\/\/[^\n]*/, '')
      trimmed_non_empty(split_top_level(cleaned, ';')).each do |stmt|
        translate_statement(stmt, predicates, denies, report, error_guards)
      rescue SystemStackError
        report['errors'] << "policy \"#{truncate(stmt)}\": Maximum call stack size exceeded"
      rescue CedarError => e
        report['errors'] << "policy \"#{truncate(stmt)}\": #{e.message}"
      end
      PolicyBridge.deep_from_units(result(predicates, denies, report))
    end

    ANNOT = PolicyBridge.head("#{S}*(?:@[A-Za-z_]\\w*#{S}*\\([^)]*\\)#{S}*)+")
    HEAD = PolicyBridge.head("#{S}*(#{Siem.ci_alt('permit', 'forbid')})#{S}*\\(")
    SCOPE = PolicyBridge.full("(principal|action|resource)\\b#{S}*(?:(==|in|is)#{S}*)?([\\s\\S]*)")

    def translate_statement(stmt, permits, denies, report, error_guards)
      body = stmt
      annot = ANNOT.match(body)
      body = body[annot.end(0)..] if annot
      head = HEAD.match(body)
      unless head
        report['skipped'] << "unrecognized statement: \"#{truncate(stmt)}\""
        return
      end
      effect = head[1].downcase == 'forbid' ? 'forbid' : 'permit'
      open_idx = body.index('(', head.begin(0))
      close_idx = match_delim(body, open_idx, '(', ')')
      raise CedarError, 'unterminated scope parentheses' if close_idx.negative?

      scope_text = body[(open_idx + 1)...close_idx]
      rest = body[(close_idx + 1)..]
      scope = parse_scope(scope_text)
      where = scope['scopeConditions'].dup
      guards = []
      parse_condition_blocks(rest).each do |kind, text|
        parsed = parse_expr(text)
        if parsed.nil?
          report['skipped'] << "unmodeled #{kind}-condition \"#{truncate(text)}\" — policy dropped (fail closed)"
          if effect == 'forbid'
            report['errors'] << "forbid could not be fully modeled and was dropped — treat result as fail-closed: \"#{truncate(stmt)}\""
          end
          return
        end
        where << (kind == 'when' ? parsed : { 'not' => parsed })
        g = no_error(parsed)
        guards << g unless g.nil?
      end
      condition_count = where.length
      where << (guards.length == 1 ? guards[0] : { 'all_of' => guards }) if error_guards && !guards.empty?
      predicate = { 'verb' => scope['verb'] }
      predicate['resource'] = scope['resource'] unless scope['resource'].nil?
      predicate['where'] = where unless where.empty?
      on = scope['resource'] && !scope['resource'].empty? ? " on #{scope['resource']}" : ''
      if effect == 'permit'
        permits << predicate
        report['translated'] << "permit → verb #{jverb(scope['verb'])}#{on} (#{condition_count} condition(s))"
      else
        denies << predicate
        report['translated'] << "forbid → deny verb #{jverb(scope['verb'])}#{on} (#{condition_count} condition(s))"
      end
    end

    def parse_scope(scope_text)
      clauses = trimmed_non_empty(split_top_level(scope_text, ','))
      result = { 'verb' => '*', 'scopeConditions' => [] }
      clauses.each do |clause|
        m = SCOPE.match(clause)
        raise CedarError, "unparseable scope clause \"#{truncate(clause)}\"" unless m

        variable = m[1]
        op = m[2]
        operand = trim(m[3] || '')
        next if op.nil? || op.empty?

        if variable == 'action'
          if op == '=='
            eid = entity_id(operand)
            raise CedarError, "action == expects an Action entity, got \"#{truncate(operand)}\"" if eid.nil?

            result['verb'] = eid
          elsif op == 'in' && operand.start_with?('[')
            verbs = []
            trimmed_non_empty(split_top_level(operand[1...-1], ',')).each do |it|
              eid = entity_id(it)
              raise CedarError, "action in [...] expects Action entities, got \"#{truncate(it)}\"" if eid.nil?

              verbs << eid
            end
            result['verb'] = verbs
          else
            raise CedarError, "unsupported action scope operator \"#{op}\""
          end
        else
          field = variable == 'resource' ? 'action.resource' : 'subject.id'
          if op == '=='
            uid = entity_uid(operand)
            if variable == 'resource'
              raise CedarError, "resource == expects an entity, got \"#{truncate(operand)}\"" if uid.nil?

              result['resource'] = uid
            else
              raise CedarError, "principal == expects an entity, got \"#{truncate(operand)}\"" if uid.nil?

              result['scopeConditions'] << { 'field' => field, 'op' => 'eq', 'value' => uid }
            end
          elsif op == 'is'
            t = type_name(operand)
            raise CedarError, "#{variable} is expects a type, got \"#{truncate(operand)}\"" if t.nil?

            result['scopeConditions'] << { 'field' => field, 'op' => 'is_a', 'value' => t }
          else
            mem = member_of_condition(field, operand)
            raise CedarError, "#{variable} in expects an entity (hierarchy), got \"#{truncate(operand)}\"" if mem.nil?

            result['scopeConditions'] << mem
          end
        end
      end
      result
    end

    BLOCK = PolicyBridge.rx("\\b(when|unless)\\b#{S}*\\{")

    def parse_condition_blocks(rest)
      blocks = []
      pos = 0
      loop do
        m = BLOCK.match(rest, pos)
        break if m.nil?

        kind = m[1] == 'unless' ? 'unless' : 'when'
        open_ = rest.index('{', m.begin(0))
        close = match_delim(rest, open_, '{', '}')
        raise CedarError, "unterminated #{kind} block" if close.negative?

        blocks << [kind, rest[(open_ + 1)...close]]
        pos = close + 1
      end
      blocks
    end

    def parse_expr(text)
      t = trim(text)
      return nil if t.empty?

      ors = trimmed_non_empty(split_top_level(t, '||'))
      if ors.length > 1
        subs = ors.map { |s| parse_expr(s) }
        return nil if subs.any?(&:nil?)

        return { 'any_of' => subs }
      end
      ands = trimmed_non_empty(split_top_level(t, '&&'))
      if ands.length > 1
        subs = ands.map { |s| parse_expr(s) }
        return nil if subs.any?(&:nil?)

        return { 'all_of' => subs }
      end
      return parse_expr(t[1...-1]) if t.start_with?('(') && match_delim(t, 0, '(', ')') == t.length - 1

      parse_atom(t)
    end

    CMP_TOKENS = [['==', 'eq'], ['!=', 'ne'], ['<=', 'lte'], ['>=', 'gte'], ['<', 'lt'], ['>', 'gt']].freeze
    WORD_OP = PolicyBridge.full("([\\s\\S]*?[^#{WS}])#{S}+(in|is|like|has)#{S}+([\\s\\S]+)")

    def parse_atom(text)
      t = trim(text)
      CMP_TOKENS.each do |tok, op|
        idx = index_of_top_level(t, tok)
        return build_comparison(trim(t[0, idx]), op, trim(t[(idx + tok.length)..])) if idx >= 0
      end
      wm = WORD_OP.match(t)
      return build_word_op(trim(wm[1]), wm[2], trim(wm[3])) if wm

      nil
    end

    def build_comparison(lhs_raw, op, rhs_raw)
      field = to_field_path(lhs_raw)
      return nil if field.nil?

      if field == 'action.verb'
        return nil if op != 'eq' && op != 'ne'

        eid = entity_id(rhs_raw)
        return eid.nil? ? nil : { 'field' => field, 'op' => op, 'value' => eid }
      end
      if path_expr?(rhs_raw)
        ref = to_field_path(rhs_raw)
        return { 'field' => field, 'op' => op, 'ref' => ref } unless ref.nil?
      end
      ok, value = to_literal(rhs_raw)
      return nil unless ok

      { 'field' => field, 'op' => op, 'value' => value }
    end

    IDENT = PolicyBridge.full('[A-Za-z_]\\w*')

    def build_word_op(lhs_raw, kind, rhs_raw)
      if kind == 'has'
        return nil unless IDENT.match?(rhs_raw)

        field = to_field_path("#{lhs_raw}.#{rhs_raw}")
        return field.nil? ? nil : { 'field' => field, 'op' => 'exists' }
      end
      field = to_field_path(lhs_raw)
      return nil if field.nil?

      if field == 'action.verb'
        return nil if kind != 'in'

        inner = rhs_raw.start_with?('[') && rhs_raw.end_with?(']') ? rhs_raw[1...-1] : rhs_raw
        ids = trimmed_non_empty(split_top_level(inner, ',')).map { |x| entity_id(x) }
        return !ids.empty? && ids.none?(&:nil?) ? { 'field' => field, 'op' => 'in', 'value' => ids } : nil
      end
      if kind == 'is'
        t = type_name(rhs_raw)
        return t.nil? ? nil : { 'field' => field, 'op' => 'is_a', 'value' => t }
      end
      if kind == 'like'
        sm = LIKE_STR.match(rhs_raw)
        return nil unless sm

        return { 'field' => field, 'op' => 'like', 'value' => cedar_like_to_glob(sm[1]) }
      end
      if rhs_raw.start_with?('[')
        inner = rhs_raw.end_with?(']') ? rhs_raw[1...-1] : rhs_raw[1..]
        items = trimmed_non_empty(split_top_level(inner, ','))
        if !items.empty? && items.all? { |it| !entity_uid(it).nil? }
          return { 'field' => field, 'op' => 'member_of', 'value' => items.map { |it| entity_uid(it) }, 'collection' => ENTITY_PARENTS }
        end

        values = []
        items.each do |it|
          ok, v = to_literal(it)
          return nil unless ok

          values << v
        end
        return { 'field' => field, 'op' => 'in', 'value' => values }
      end
      member_of_condition(field, rhs_raw)
    end

    LIKE_STR = PolicyBridge.full('"([\\s\\S]*)"')

    def member_of_condition(field, operand)
      uid = entity_uid(operand)
      return { 'field' => field, 'op' => 'member_of', 'value' => uid, 'collection' => ENTITY_PARENTS } unless uid.nil?

      if path_expr?(operand)
        ref = to_field_path(operand)
        return { 'field' => field, 'op' => 'member_of', 'ref' => ref, 'collection' => ENTITY_PARENTS } unless ref.nil?
      end
      nil
    end

    PATH_HEAD = PolicyBridge.head('(principal|resource|action|context)\\b')
    def path_expr?(expr) = PATH_HEAD.match?(expr)

    P_PRINCIPAL = PolicyBridge.full('principal\\.([A-Za-z_][\\w.]*)')
    P_RESOURCE = PolicyBridge.full('resource\\.([A-Za-z_][\\w.]*)')
    P_CONTEXT = PolicyBridge.full('context\\.([A-Za-z_][\\w.]*)')

    def to_field_path(expr)
      case expr
      when 'principal' then return 'subject.id'
      when 'resource' then return 'action.resource'
      when 'action' then return 'action.verb'
      when 'context' then return 'env'
      end
      m = P_PRINCIPAL.match(expr)
      return "subject.#{m[1]}" if m

      m = P_RESOURCE.match(expr)
      return "env.resource.#{m[1]}" if m

      m = P_CONTEXT.match(expr)
      m ? "env.#{m[1]}" : nil
    end

    TYPE_NAME = PolicyBridge.full('[A-Za-z_]\\w*(?:::[A-Za-z_]\\w*)*')
    ENTITY_ID = PolicyBridge.full("#{DOT}+::\"([^\"]*)\"")
    ENTITY_UID = PolicyBridge.full("(#{DOT}+)::\"([^\"]*)\"")
    STR_LIT = PolicyBridge.full('"([^"]*)"')
    NUM_LIT = PolicyBridge.full('-?\\d+(?:\\.\\d+)?')

    def type_name(expr)
      s = trim(expr)
      TYPE_NAME.match?(s) ? s : nil
    end

    def entity_id(expr) = ENTITY_ID.match(trim(expr))&.[](1)

    def entity_uid(expr)
      m = ENTITY_UID.match(trim(expr))
      m ? "#{m[1]}::#{m[2]}" : nil
    end

    def to_literal(expr)
      s = trim(expr)
      m = STR_LIT.match(s)
      return [true, m[1]] if m
      return [true, true] if s == 'true'
      return [true, false] if s == 'false'
      return [true, number(s)] if NUM_LIT.match?(s)

      uid = entity_uid(s)
      uid.nil? ? [false, nil] : [true, uid]
    end

    def escape_glob_literal(ch) = '*?\\'.include?(ch) ? "\\#{ch}" : ch

    def cedar_like_to_glob(inner)
      out = +''
      i = 0
      n = inner.length
      while i < n
        ch = inner[i]
        if ch == '\\'
          nxt = i + 1 < n ? inner[i + 1] : nil
          if nxt == '*'
            out << '\\*'
            i += 2
            next
          end
          unless nxt.nil?
            out << escape_glob_literal(nxt)
            i += 2
            next
          end
          out << '\\\\'
          i += 1
          next
        end
        out << (ch == '*' ? '*' : escape_glob_literal(ch))
        i += 1
      end
      out
    end

    # --- Cedar evaluation-error semantics: the guard that makes a policy apply only when no absent attribute is read
    TOTAL_FIELDS = ['subject.id', 'action.verb', 'action.resource', 'env'].freeze

    def guarded_paths(field)
      return [] if field.nil? || TOTAL_FIELDS.include?(field) || field.start_with?('env.entity_parents')

      field.start_with?('subject.') || field.start_with?('env.') ? [field] : []
    end

    def exists_cond(field) = { 'field' => field, 'op' => 'exists' }
    def all_of1(xs) = xs.length == 1 ? xs[0] : { 'all_of' => xs }
    def any_of1(xs) = xs.length == 1 ? xs[0] : { 'any_of' => xs }

    # "Evaluating this expression raises no Cedar error", as a condition (nil = it cannot)
    def no_error(c)
      return no_error(c['not']) if c.key?('not')

      if c.key?('all_of') || c.key?('any_of')
        is_and = c.key?('all_of')
        kids = is_and ? c['all_of'] : c['any_of']
        acc = nil
        kids.reverse_each do |kid|
          n = no_error(kid)
          cont = acc.nil? ? nil : any_of1([is_and ? { 'not' => kid } : kid, acc])
          acc = if n.nil? then cont
                elsif cont.nil? then n
                else all_of1([n, cont])
                end
        end
        return acc
      end
      field = c['field']
      if c['op'] == 'exists' && !field.nil?
        base = field.sub(/\.[^.]+\z/, '')
        deep = base.split('.', -1).length >= (base.start_with?('env.resource') ? 3 : 2)
        base_needs = deep ? guarded_paths(base).map { |p| exists_cond(p) } : []
        return base_needs.empty? ? nil : all_of1(base_needs)
      end
      needs = (guarded_paths(field) + guarded_paths(c['ref'])).map { |p| exists_cond(p) }
      needs.empty? ? nil : all_of1(needs)
    end

    # ---- Rego
    PKG = PolicyBridge.rx("\\bpackage#{S}+([A-Za-z_][\\w.]*)")
    DEFAULT = PolicyBridge.rx("\\bdefault#{S}+allow#{S}*(?::?=)#{S}*(true|false)\\b")
    ALLOW = PolicyBridge.rx("\\ballow\\b#{S}*(?:(?::?=#{S}*true\\b|=#{S}*true\\b|\\bif\\b)#{S}*)?\\{")
    NOT = PolicyBridge.full("not#{S}+([\\s\\S]+)")
    UNMODELED_A = PolicyBridge.rx(":=|\\bsome\\b|\\bevery\\b|\\[#{DOT}*\\|#{DOT}*\\]")
    UNMODELED_IDX = PolicyBridge.rx('\\binput\\.[\\w.]*\\[')
    REGO_CMP = PolicyBridge.full("(input\\.[\\w.]+)#{S}*(==|!=|<=|>=|<|>|\\bin\\b)#{S}*([\\s\\S]+)")
    INPUT_PATH = PolicyBridge.full('input\\.[\\w.]+')
    STARTSWITH = PolicyBridge.full("startswith\\(#{S}*(input\\.[\\w.]+)#{S}*,#{S}*\"([^\"]*)\"#{S}*\\)")
    GLOB = PolicyBridge.full("glob\\.match\\(#{S}*\"([^\"]*)\"#{S}*,#{S}*(\\[#{S}*\\]|null)#{S}*,#{S}*(input\\.[\\w.]+)#{S}*\\)")
    REGO_STR = PolicyBridge.full('"([^"]*)"')

    # OPA / Rego `allow` rules (a conjunction of input comparisons per rule) as permit predicates; anything else drops its rule.
    def rego_to_pca(module_text)
      report = new_report('rego')
      predicates = []
      src = PolicyBridge.to_units(module_text).gsub(/#[^\n]*/, '')
      pkg = PKG.match(src)
      report['translated'] << "package #{pkg[1]}" if pkg
      d = DEFAULT.match(src)
      if d && d[1] == 'true'
        report['skipped'] << '`default allow = true` is not modeled (cannot express allow-unless); treated as default-deny'
      elsif !d
        report['skipped'] << 'no `default allow = false` found; assuming default-deny'
      end
      extract_allow_bodies(src, report).each { |body| translate_rule(body, predicates, report) }
      PolicyBridge.deep_from_units(result(predicates, [], report))
    end

    def extract_allow_bodies(src, report)
      bodies = []
      pos = 0
      loop do
        m = ALLOW.match(src, pos)
        break if m.nil?

        open_ = src.index('{', m.begin(0))
        close = match_delim(src, open_, '{', '}')
        if close.negative?
          report['errors'] << 'unterminated `allow { ... }` block'
          break
        end
        bodies << src[(open_ + 1)...close]
        pos = close + 1
      end
      bodies
    end

    def translate_rule(body, predicates, report)
      statements = body.split(/[\n;]/, -1).map { |s| trim(s) }.reject(&:empty?)
      verb = '*'
      resource = nil
      where = []
      statements.each do |stmt|
        parsed = parse_statement(stmt)
        kind = parsed[0]
        if kind == 'unmodeled'
          report['skipped'] << "unmodeled statement \"#{truncate(stmt)}\" — rule dropped (fail closed)"
          return
        end
        if kind == 'verb'
          if verb.is_a?(String) && verb == '*'
            verb = parsed[1]
          else
            have = verb.is_a?(Array) ? verb : [verb]
            nxt = parsed[1].is_a?(Array) ? parsed[1] : [parsed[1]]
            both = have.select { |v| nxt.include?(v) }
            if both.empty?
              report['translated'] << 'rule can never match (contradictory action selectors), nothing emitted'
              return
            end
            verb = both.length == 1 ? both[0] : both
          end
        elsif kind == 'resource'
          if !resource.nil? && resource != parsed[1]
            report['translated'] << 'rule can never match (contradictory resource selectors), nothing emitted'
            return
          end
          resource = parsed[1]
        else
          where << parsed[1]
        end
      end
      predicate = { 'verb' => verb }
      predicate['resource'] = resource unless resource.nil?
      predicate['where'] = where unless where.empty?
      predicates << predicate
      on = resource && !resource.empty? ? " on #{resource}" : ''
      report['translated'] << "allow → verb #{jverb(verb)}#{on} (#{where.length} condition(s))"
    end

    UNMODELED = ['unmodeled', nil].freeze

    def parse_statement(stmt)
      s = trim(stmt)
      nm = NOT.match(s)
      if nm
        inner = parse_statement(trim(nm[1]))
        return UNMODELED if inner[0] != 'condition'

        c = inner[1]
        if c['op'] == 'eq' && c['field'].is_a?(String)
          needs = ([c['field']] + (c['ref'].is_a?(String) ? [c['ref']] : [])).map { |f| { 'field' => f, 'op' => 'exists' } }
          return ['condition', { 'not' => { 'all_of' => needs + [c] } }]
        end
        return ['condition', { 'not' => c }]
      end
      builtin = parse_builtin(s)
      return builtin unless builtin.nil?
      return UNMODELED if UNMODELED_A.match?(s)
      return UNMODELED if s.include?('(')
      return UNMODELED if UNMODELED_IDX.match?(s)

      m = REGO_CMP.match(s)
      return UNMODELED unless m

      path = m[1]
      op_tok = m[2]
      rhs_raw = trim(m[3])
      sub = path['input.'.length..]
      if op_tok == 'in'
        ok, values = parse_set_literal(rhs_raw)
        return UNMODELED unless ok

        if sub == 'action'
          verbs = values.select { |v| v.is_a?(String) }
          return UNMODELED if verbs.length != values.length

          return ['verb', verbs]
        end
        return ['condition', { 'field' => "env.#{sub}", 'op' => 'in', 'value' => values }]
      end
      if (op_tok == '==' || op_tok == '!=') && INPUT_PATH.match?(rhs_raw)
        return ['condition', { 'field' => "env.#{sub}", 'op' => op_tok == '!=' ? 'ne' : 'eq', 'ref' => "env.#{rhs_raw['input.'.length..]}" }]
      end

      ok, value = rego_literal(rhs_raw)
      return UNMODELED unless ok

      if op_tok == '=='
        return ['verb', value] if sub == 'action' && value.is_a?(String)
        return ['resource', value] if sub == 'resource' && value.is_a?(String)

        return ['condition', { 'field' => "env.#{sub}", 'op' => 'eq', 'value' => value }]
      end
      return ['condition', { 'field' => "env.#{sub}", 'op' => 'ne', 'value' => value }] if op_tok == '!='
      return UNMODELED if value == true || value == false || !(value.is_a?(Integer) || value.is_a?(Float))

      cmp = { '<' => 'lt', '<=' => 'lte', '>' => 'gt' }.fetch(op_tok, 'gte')
      ['condition', { 'field' => "env.#{sub}", 'op' => cmp, 'value' => value }]
    end

    def parse_builtin(s)
      sw = STARTSWITH.match(s)
      return ['condition', { 'field' => "env.#{sw[1]['input.'.length..]}", 'op' => 'prefix', 'value' => sw[2] }] if sw

      gm = GLOB.match(s)
      if gm
        pattern = gm[1]
        return UNMODELED if pattern.match?(/[\[\]{}]/)
        return UNMODELED if gm[2].start_with?('[') && pattern.match?(/[*?\\]/)

        return ['condition', { 'field' => "env.#{gm[3]['input.'.length..]}", 'op' => 'like', 'value' => pattern }]
      end
      nil
    end

    def rego_literal(expr)
      s = trim(expr)
      m = REGO_STR.match(s)
      return [true, m[1]] if m
      return [true, true] if s == 'true'
      return [true, false] if s == 'false'
      return [true, number(s)] if NUM_LIT.match?(s)

      [false, nil]
    end

    def parse_set_literal(expr)
      s = trim(expr)
      is_set = s.start_with?('{') && s.end_with?('}')
      is_arr = s.start_with?('[') && s.end_with?(']')
      return [false, []] if !is_set && !is_arr

      values = []
      trimmed_non_empty(split_top_level(s[1...-1], ',')).each do |it|
        ok, v = rego_literal(it)
        return [false, []] unless ok

        values << v
      end
      [true, values]
    end

    # ---- OpenFGA
    MAX_DEPTH = 32

    # An OpenFGA / Zanzibar model plus relationship tuples as one permit per (user, object, relation) triple that holds (`this`,
    # computedUserset, union, intersection, difference, tupleToUserset; bounded and cycle-guarded).
    def openfga_to_pca(model, tuples = MISSING)
      report = new_report('openfga')
      predicates = []
      type_relations = parse_model(model, report)
      tuple_list = parse_tuples(tuples, report)
      return result(predicates, [], report) if type_relations.nil?

      direct = {}
      users_seen = {}
      wildcard_types = {}
      objects_seen = {}
      userset_tuples = 0
      tuple_list.each do |t|
        objects_seen[t['object']] = nil
        (direct["#{t['object']}\u0000#{t['relation']}"] ||= {})[t['user']] = nil
        if t['user'].include?('#')
          userset_tuples += 1
        elsif wildcard?(t['user'])
          wildcard_types[t['user'][0...-2]] = nil
        else
          users_seen[t['user']] = nil
        end
      end
      report['skipped'] << "#{userset_tuples} userset-valued tuple(s) (user contains '#') not expanded to concrete users" if userset_tuples.positive?

      plans = {}
      type_relations.each do |type_, relations|
        relations.each do |relation, node|
          built = build_plan(node)
          unless built['ok'] && built.key?('plan')
            report['skipped'] << "relation #{type_}##{relation}: #{built.fetch('reason', 'unsupported rewrite')} — skipped"
            next
          end
          report['skipped'] << "relation #{type_}##{relation}: some union children unsupported and dropped (under-approximated)" if built['partial']
          plans["#{type_}\u0000#{relation}"] = built['plan']
          report['translated'] << "relation #{type_}##{relation} (#{describe_plan(built['plan'])})"
        end
      end

      type_of = lambda { |obj| (i = obj.index(':')).nil? ? obj : obj[0, i] }
      object_of_userset = lambda { |p| (i = p.index('#')).nil? ? p : p[0, i] }
      holds_rel = nil
      eval_plan = lambda do |user, obj, relation, plan, depth, visited|
        case plan['kind']
        when 'direct'
          s = direct["#{obj}\u0000#{relation}"]
          !s.nil? && (s.key?(user) || s.key?("#{type_of.call(user)}:*"))
        when 'computed' then holds_rel.call(user, obj, plan['relation'], depth + 1, visited)
        when 'union' then plan['children'].any? { |c| eval_plan.call(user, obj, relation, c, depth, visited) }
        when 'intersection' then plan['children'].all? { |c| eval_plan.call(user, obj, relation, c, depth, visited) }
        when 'difference'
          eval_plan.call(user, obj, relation, plan['base'], depth, visited) && !eval_plan.call(user, obj, relation, plan['subtract'], depth, visited)
        else
          related = direct["#{obj}\u0000#{plan['tupleset']}"]
          if related.nil?
            false
          else
            related.each_key.any? { |p| holds_rel.call(user, object_of_userset.call(p), plan['computed'], depth + 1, visited) }
          end
        end
      end
      holds_rel = lambda do |user, obj, relation, depth, visited|
        key = "#{obj}\u0000#{relation}"
        next false if depth > MAX_DEPTH || visited.include?(key)

        plan = plans["#{type_of.call(obj)}\u0000#{relation}"]
        next false if plan.nil?

        eval_plan.call(user, obj, relation, plan, depth, visited + [key])
      end

      by_key = ->(s) { Siem::U16.units(s) }
      sorted_users = users_seen.keys.sort_by(&by_key)
      objects_seen.keys.sort_by(&by_key).each do |obj|
        type_ = type_of.call(obj)
        relations = type_relations[type_]
        if relations.nil?
          report['skipped'] << "object #{obj}: type \"#{type_}\" not defined in model — ignored"
          next
        end
        relations.keys.sort_by(&by_key).each do |relation|
          next unless plans.key?("#{type_}\u0000#{relation}")

          sorted_users.each do |user|
            if holds_rel.call(user, obj, relation, 0, [])
              predicates << { 'verb' => relation, 'resource' => obj, 'where' => [{ 'field' => 'subject.id', 'op' => 'eq', 'value' => user }] }
            end
          end
          # a public tuple (`type:*`) grants every subject of that type, including ones no tuple names
          wildcard_types.keys.sort_by(&by_key).each do |wtype|
            next unless holds_rel.call("#{wtype}:\u0000anyone", obj, relation, 0, [])

            named = sorted_users.select { |u| type_of.call(u) == wtype }
            where = [{ 'field' => 'subject.id', 'op' => 'like', 'value' => "#{escape_glob(wtype)}:*" }]
            where << { 'not' => { 'field' => 'subject.id', 'op' => 'in', 'value' => named } } unless named.empty?
            predicates << { 'verb' => relation, 'resource' => obj, 'where' => where }
          end
        end
      end
      result(predicates, [], report)
    end

    def wildcard?(user) = user.end_with?(':*') && Siem::U16.len(user) > 2 && !user.include?('#')
    def escape_glob(t) = t.gsub(/[*?\\]/) { |m| "\\#{m}" }

    def describe_plan(plan)
      case plan['kind']
      when 'direct' then 'direct'
      when 'computed' then "computed #{plan['relation']}"
      when 'union' then "union[#{plan['children'].map { |c| describe_plan(c) }.join(', ')}]"
      when 'intersection' then "intersection[#{plan['children'].map { |c| describe_plan(c) }.join(', ')}]"
      when 'difference' then "difference(#{describe_plan(plan['base'])} - #{describe_plan(plan['subtract'])})"
      else "#{plan['computed']} from #{plan['tupleset']}"
      end
    end

    def rewrite?(v) = v.is_a?(Hash) || v.is_a?(Array)
    def has_own?(o, k) = o.is_a?(Hash) && o.key?(k)

    def child_nodes(container)
      return nil unless rewrite?(container)

      child = container.is_a?(Hash) ? container['child'] : nil
      child.is_a?(Array) ? child : nil
    end

    def relation_of(v)
      return nil unless rewrite?(v)

      rel = v.is_a?(Hash) ? v['relation'] : nil
      rel.is_a?(String) && !rel.empty? ? rel : nil
    end

    def build_plan(node)
      return { 'ok' => true, 'plan' => { 'kind' => 'direct' }, 'partial' => false } if has_own?(node, 'this')

      if has_own?(node, 'computedUserset')
        cu = node['computedUserset']
        rel = cu.is_a?(Hash) ? cu['relation'] : nil
        return { 'ok' => false, 'partial' => false, 'reason' => 'computedUserset without a relation' } if !rel.is_a?(String) || rel.empty?

        return { 'ok' => true, 'plan' => { 'kind' => 'computed', 'relation' => rel }, 'partial' => false }
      end
      if has_own?(node, 'union')
        children = child_nodes(node['union'])
        return { 'ok' => false, 'partial' => false, 'reason' => 'union without children' } if children.nil?

        subs = []
        partial = false
        children.each do |child|
          unless rewrite?(child)
            partial = true
            next
          end
          sub = build_plan(child)
          unless sub['ok'] && sub.key?('plan')
            partial = true # OR under-approximates safely: drop the unmodeled child
            next
          end
          partial = true if sub['partial']
          subs << sub['plan']
        end
        return { 'ok' => false, 'partial' => partial, 'reason' => 'union with no modeled children' } if subs.empty?

        return { 'ok' => true, 'plan' => { 'kind' => 'union', 'children' => subs }, 'partial' => partial }
      end
      if has_own?(node, 'intersection')
        children = child_nodes(node['intersection'])
        return { 'ok' => false, 'partial' => false, 'reason' => 'intersection without children' } if children.nil?

        subs = []
        children.each do |child|
          return { 'ok' => false, 'partial' => false, 'reason' => 'intersection child is not a rewrite' } unless rewrite?(child)

          sub = build_plan(child)
          unless sub['ok'] && sub.key?('plan')
            return { 'ok' => false, 'partial' => false, 'reason' => "intersection child unmodeled (#{sub.fetch('reason', 'unsupported')})" }
          end
          subs << sub['plan']
        end
        return { 'ok' => false, 'partial' => false, 'reason' => 'intersection with no children' } if subs.empty?

        return { 'ok' => true, 'plan' => { 'kind' => 'intersection', 'children' => subs }, 'partial' => false }
      end
      if has_own?(node, 'difference')
        diff = node['difference']
        return { 'ok' => false, 'partial' => false, 'reason' => 'malformed difference' } unless rewrite?(diff)

        base_node = diff.is_a?(Hash) ? diff['base'] : nil
        sub_node = diff.is_a?(Hash) ? diff['subtract'] : nil
        return { 'ok' => false, 'partial' => false, 'reason' => 'difference needs both base and subtract' } if !rewrite?(base_node) || !rewrite?(sub_node)

        base = build_plan(base_node)
        subtract = build_plan(sub_node)
        return { 'ok' => false, 'partial' => false, 'reason' => "difference base unmodeled (#{base.fetch('reason', '?')})" } unless base['ok'] && base.key?('plan')
        unless subtract['ok'] && subtract.key?('plan')
          return { 'ok' => false, 'partial' => false, 'reason' => "difference subtract unmodeled (#{subtract.fetch('reason', '?')})" }
        end

        return { 'ok' => true, 'plan' => { 'kind' => 'difference', 'base' => base['plan'], 'subtract' => subtract['plan'] },
                 'partial' => base['partial'] || subtract['partial'] }
      end
      if has_own?(node, 'tupleToUserset')
        ttu = node['tupleToUserset']
        return { 'ok' => false, 'partial' => false, 'reason' => 'malformed tupleToUserset' } unless rewrite?(ttu)

        tupleset_rel = relation_of(ttu.is_a?(Hash) ? ttu['tupleset'] : nil)
        computed_rel = relation_of(ttu.is_a?(Hash) ? ttu['computedUserset'] : nil)
        return { 'ok' => false, 'partial' => false, 'reason' => 'tupleToUserset without a tupleset relation' } if tupleset_rel.nil?
        return { 'ok' => false, 'partial' => false, 'reason' => 'tupleToUserset without a computedUserset relation' } if computed_rel.nil?

        return { 'ok' => true, 'plan' => { 'kind' => 'ttu', 'tupleset' => tupleset_rel, 'computed' => computed_rel }, 'partial' => false }
      end
      { 'ok' => false, 'partial' => false, 'reason' => 'unknown rewrite node' }
    end

    def parse_model(model, report)
      unless rewrite?(model)
        report['errors'] << 'model is not an object'
        return nil
      end
      defs = model.is_a?(Hash) ? model['type_definitions'] : nil
      unless defs.is_a?(Array)
        report['errors'] << 'model.type_definitions is missing or not an array'
        return nil
      end
      out = {}
      defs.each do |d|
        next unless rewrite?(d)

        t = d.is_a?(Hash) ? d['type'] : nil
        next if !t.is_a?(String) || t.empty?

        rels = d.is_a?(Hash) ? d['relations'] : nil
        rel_map = {}
        ents = entries(rels)
        ents&.each { |name, node| rel_map[name] = node if rewrite?(node) }
        out[t] = rel_map
      end
      out
    end

    def parse_tuples(tuples, report)
      unless tuples.is_a?(Array)
        report['errors'] << 'tuples is not an array' unless tuples.equal?(MISSING)
        return []
      end
      out = []
      tuples.each do |t|
        next unless t.is_a?(Hash)

        user = t['user']
        relation = t['relation']
        obj = t['object']
        out << { 'user' => user, 'relation' => relation, 'object' => obj } if user.is_a?(String) && relation.is_a?(String) && obj.is_a?(String)
      end
      out
    end

    # ---- decide
    def length_of(x)
      raise TypeError, "cannot read properties of null (reading 'length')" if x.nil?

      x.is_a?(Array) ? x.length : (x.is_a?(String) ? Siem::U16.len(x) : nil)
    end

    # One action under a translation with deny-overrides-permit (Cedar's combining rule), built on the core evaluator. An
    # incomplete translation (`report.errors` non-empty) denies everything.
    def decide(result, ctx)
      report = result.is_a?(Hash) ? result['report'] : nil
      if !report.nil? && Js.truthy?(report)
        n = length_of(report.is_a?(Hash) ? report['errors'] : nil)
        return { 'allowed' => false, 'reason' => 'translation incomplete (fail closed)' } if !n.nil? && n.positive?
      end
      denies = result['denies']
      n = length_of(denies)
      if !n.nil? && n.positive?
        denied = AtlasPca.evaluate_predicates(denies, ctx)
        return { 'allowed' => false, 'matched' => denied['matched'], 'reason' => 'forbidden by deny policy' } if denied['allowed']
      end
      AtlasPca.evaluate_predicates(result['predicates'], ctx)
    end
  end
end
require_relative 'policy_bridge_cel'
