# frozen_string_literal: true

# Deterministic, non-code predicate DSL evaluator (spec s5.1 "semantic action-predicates"). Port of the evaluator part of
# packages/pca/src/predicates.ts (the TypeScript is authoritative; the DEFAULT code path, not the PCA_VERIFIED_CORE opt-in).
#
# Predicates are PURE DATA. Every public function here is total and never raises; anything malformed, unknown or missing
# FAILS CLOSED (condition false, predicate not matched).
#
# JS semantics reproduced (inputs are JSON values with String keys, as the JSON readers yield them):
#  - a JS number is an Integer or a Float, compared as ONE binary64 value (a huge Integer rounds as JSON.parse would;
#    beyond the binary64 range it is +/-Infinity); true / false are never numbers;
#  - `typeof x === 'object'` is a Hash or an Array (`Array.isArray` is Array; a "record" is a Hash);
#  - string `.length`, prefix tests, globs and regexes work over UTF-16 code units (SafeRegex.units);
#  - lt / lte / gt / gte order strings by their UTF-8 bytes (Unicode code point order); a lone surrogate has no order;
#  - eq / ne / in / nin are canonical-JSON equality: same JSON type and value (2 == 2.0, 0 == -0, 2 != "2", true != 1); a
#    non-finite number makes the comparison false (the canonicalizer refuses it).
module AtlasPca
  module Predicates
    # Longest field value a `like` / `matches` leaf is tested against (UTF-16 units).
    MAX_PATTERN_SUBJECT_LEN = 512
    # Longest `like` glob / `matches` regex source accepted (UTF-16 units).
    MAX_LIKE_PATTERN_LEN = 512
    MAX_MATCHES_PATTERN_LEN = 200
    # Upper bound on nodes visited while resolving a `member_of` transitive closure.
    MAX_MEMBER_CLOSURE_NODES = 10_000
    # Longest resource string a `re:` pattern is evaluated against (UTF-16 units).
    MAX_RE_RESOURCE_LEN = 512
    # Longest `re:` pattern source (UTF-16 units).
    MAX_RE_SOURCE_LEN = 200
    MAX_BOUNDED_REPEAT = 64
    # Backtracking-cost budget in bits: `|` and `?` 1 bit each, a variable bounded repeat `{m,n}` ceil(log2(n-m+1)), an
    # unbounded quantifier 8; the SUM is capped.
    MAX_REGEX_COST_BITS = 22
    UNBOUNDED_QUANTIFIER_BITS = 8

    ROOTS = %w[action subject env].freeze
    FORBIDDEN = %w[__proto__ constructor prototype].freeze
    UNDEF = Object.new.freeze
    INDEX_RE = /\A(?:0|[1-9][0-9]*)\z/n
    MAX_EQ_DEPTH = 10_000

    class NotCanonical < StandardError; end

    module_function

    # ---- JS type helpers -----------------------------------------------------------------------------------------------

    def num?(x)
      x.is_a?(Integer) || x.is_a?(Float)
    end

    # `x !== null && typeof x === 'object'` (arrays included).
    def obj?(x)
      x.is_a?(Hash) || x.is_a?(Array)
    end

    # The binary64 value JS holds for this JSON number (a huge Integer rounds; beyond the range it is +/-Infinity).
    def jsnum(x)
      x.is_a?(Integer) ? x.to_f : x
    end

    # Own-property read `o[k]` (UNDEF when absent). Only plain objects (Hashes) carry named properties.
    def get(o, k)
      o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF
    end

    def units(s)
      SafeRegex.units(s)
    end

    def ulen(s)
      SafeRegex.units(s).length
    end

    # JS `a === b` for two strings (same UTF-16 code units).
    def str_eq?(a, b)
      if plain_utf8?(a) && plain_utf8?(b)
        a.bytesize == b.bytesize && a.b == b.b
      else
        units(a) == units(b)
      end
    end

    def plain_utf8?(s)
      (s.encoding == Encoding::UTF_8 || s.encoding == Encoding::US_ASCII) && s.valid_encoding?
    end

    # JS `s.startsWith(prefix)` over UTF-16 code units.
    def starts_with?(s, prefix)
      su = units(s)
      pu = units(prefix)
      su.length >= pu.length && su[0, pu.length] == pu
    end

    def params_unavailable?(ctx)
      p = get(get(ctx, 'action'), 'params')
      p.equal?(UNDEF) || p.nil? || !obj?(p)
    end

    def params_rooted?(path)
      path == 'action.params' || path.start_with?('action.params.')
    end

    # ECMAScript Number::toString(v).
    def js_number_string(v)
      return 'NaN' if v.nan?
      return (v.positive? ? 'Infinity' : '-Infinity') if v.infinite?
      return '0' if v.zero?

      sign = v.negative? ? '-' : ''
      mant, exp = v.abs.to_s.split('e')
      e = exp.nil? ? 0 : exp.to_i
      ip, fp = mant.split('.')
      fp = '' if fp.nil? || fp == '0'
      all = ip + fp
      stripped = all.sub(/\A0+/, '')
      lead = all.length - stripped.length
      n = ip.length + e - lead # value = 0.digits x 10^n
      digits = stripped.sub(/0+\z/, '')
      k = digits.length
      s = if k <= n && n <= 21
            digits + ('0' * (n - k))
          elsif n.positive? && n <= 21
            "#{digits[0, n]}.#{digits[n..]}"
          elsif n > -6 && n <= 0
            "0.#{'0' * -n}#{digits}"
          else
            ex = n - 1
            es = (ex >= 0 ? '+' : '-') + ex.abs.to_s
            k == 1 ? "#{digits}e#{es}" : "#{digits[0]}.#{digits[1..]}e#{es}"
          end
      sign + s
    end

    # ECMAScript String(v) for a JSON value (UNDEF is undefined).
    def js_string(v, depth = 0)
      return 'undefined' if v.equal?(UNDEF)
      return 'null' if v.nil?
      return 'true' if v == true
      return 'false' if v == false
      return v.dup.force_encoding(Encoding::UTF_8) if v.is_a?(String)
      return js_number_string(jsnum(v).to_f) if num?(v)

      if v.is_a?(Array)
        raise NotCanonical, 'String(): nesting too deep' if depth > 64

        return v.map { |x| x.nil? ? '' : js_string(x, depth + 1) }.join(',')
      end
      '[object Object]'
    end

    # ---- resolvePath ---------------------------------------------------------------------------------------------------

    # [found, value]. Raises only on a path that is not a JS string (callers guard).
    def resolve(ctx, path)
      return [false, nil] unless path.is_a?(String) && !path.empty?

      enc = path.encoding
      segs = path.b.split('.'.b, -1).map { |s| s.force_encoding(enc) }
      return [false, nil] unless ROOTS.include?(segs[0])

      cur = get(ctx, segs[0])
      return [false, nil] if cur.equal?(UNDEF)

      segs[1..].each do |s|
        return [false, nil] if FORBIDDEN.include?(s) || cur.nil? || !obj?(cur)

        if cur.is_a?(Array)
          return [false, nil] unless s.b.match?(INDEX_RE)

          idx = s.to_i
          return [false, nil] if idx >= cur.length

          cur = cur[idx]
        else
          return [false, nil] unless cur.key?(s)

          cur = cur[s]
        end
      end
      [true, cur]
    end

    # ---- deepEq / ordering ---------------------------------------------------------------------------------------------

    # canonicalize(a) === canonicalize(b), structurally: raises NotCanonical where the lenient canonicalizer would throw.
    def jeq(a, b, depth)
      raise NotCanonical if depth > MAX_EQ_DEPTH
      raise NotCanonical if num?(a) && !jsnum(a).to_f.finite?
      raise NotCanonical if num?(b) && !jsnum(b).to_f.finite?
      return a.nil? && b.nil? if a.nil? || b.nil?
      if a == true || a == false || b == true || b == false
        return (a == true || a == false) && (b == true || b == false) && a == b
      end
      return num?(a) && num?(b) && jsnum(a).to_f == jsnum(b).to_f if num?(a) || num?(b)
      return a.is_a?(String) && b.is_a?(String) && units(a) == units(b) if a.is_a?(String) || b.is_a?(String)

      if a.is_a?(Array) && b.is_a?(Array)
        return false unless a.length == b.length

        return a.each_index.all? { |i| jeq(a[i], b[i], depth + 1) }
      end
      if a.is_a?(Hash) && b.is_a?(Hash)
        (a.keys + b.keys).each { |k| raise NotCanonical unless k.is_a?(String) }
        ka = a.keys.to_h { |k| [units(k), k] }
        kb = b.keys.to_h { |k| [units(k), k] }
        return false if ka.length != a.length || kb.length != b.length || ka.keys.sort != kb.keys.sort

        return ka.all? { |u, k| jeq(a[k], b[kb[u]], depth + 1) }
      end
      return false if obj?(a) && obj?(b) # array vs object

      raise NotCanonical # unsupported type
    end

    def deep_eq?(a, b)
      jeq(a, b, 0)
    rescue StandardError, SystemStackError
      false
    end

    # Code points of a unit view that holds no lone surrogate.
    def code_points(u)
      out = []
      i = 0
      while i < u.length
        c = u[i]
        if c >= 0xd800 && c <= 0xdbff
          out << (0x10000 + ((c - 0xd800) << 10) + (u[i + 1] - 0xdc00))
          i += 2
        else
          out << c
          i += 1
        end
      end
      out
    end

    # NORMATIVE string order: UTF-8 byte order (== code point order); a lone surrogate has no order (nil).
    def order_utf8(a, b)
      ua = units(a)
      ub = units(b)
      return nil if SafeRegex.units_have_lone_surrogate?(ua) || SafeRegex.units_have_lone_surrogate?(ub)

      code_points(ua) <=> code_points(ub)
    end

    def ordered(a, b)
      if num?(a) && num?(b)
        x = jsnum(a).to_f
        y = jsnum(b).to_f
        return x < y ? -1 : (x > y ? 1 : 0) if x.finite? && y.finite?
      end
      return order_utf8(a, b) if a.is_a?(String) && b.is_a?(String)

      nil
    end

    # ---- glob / type tags / member closure -----------------------------------------------------------------------------

    # Tokens over UTF-16 units: [:lit, unit] | [:one] | [:star]. nil on a dangling trailing backslash. Consecutive `*`
    # collapse to one.
    def parse_glob(u)
      out = []
      i = 0
      n = u.length
      while i < n
        ch = u[i]
        if ch == 0x5c
          return nil if i + 1 >= n

          out << [:lit, u[i + 1]]
          i += 1
        elsif ch == 0x2a
          out << [:star] unless !out.empty? && out[-1][0] == :star
        elsif ch == 0x3f
          out << [:one]
        else
          out << [:lit, ch]
        end
        i += 1
      end
      out
    end

    # Anchored glob match in O(|glob| x |s|) worst case with NO regex engine; nil on a malformed glob.
    def glob_match(glob, s)
      toks = parse_glob(units(glob))
      return nil if toks.nil?

      su = units(s)
      ti = 0
      si = 0
      star_ti = -1 # token index just after the most recent star
      star_si = 0  # subject index that star is currently extended to
      nt = toks.length
      while si < su.length
        t = ti < nt ? toks[ti] : nil
        if !t.nil? && t[0] == :star
          ti += 1
          star_ti = ti
          star_si = si
        elsif !t.nil? && (t[0] == :one || su[si] == t[1])
          ti += 1
          si += 1
        elsif star_ti >= 0
          ti = star_ti
          star_si += 1
          si = star_si
        else
          return false
        end
      end
      ti += 1 while ti < nt && toks[ti][0] == :star
      ti == nt
    end

    # `is_a` type/tag test. nil when the value carries no decidable type/tag.
    def type_tag_match(v, t)
      return str_eq?(v, t) || starts_with?(v, "#{t}::") if v.is_a?(String)
      return nil unless v.is_a?(Hash)

      decidable = false
      matched = false
      if v.key?('type')
        ty = v['type']
        if ty.is_a?(String)
          decidable = true
          matched = true if str_eq?(ty, t) || starts_with?(ty, "#{t}::")
        end
      end
      if v.key?('tags')
        tags = v['tags']
        if tags.is_a?(Array)
          decidable = true
          matched = true if tags.any? { |x| x.is_a?(String) && str_eq?(x, t) }
        end
      end
      decidable ? matched : nil
    end

    # Direct neighbours of `node` in an adjacency map (own String | String[] values only; proto-safe).
    def neighbours_of(adj, node)
      return [] if FORBIDDEN.include?(node) || !adj.key?(node)

      raw = adj[node]
      return [raw] if raw.is_a?(String)
      return raw.select { |x| x.is_a?(String) } if raw.is_a?(Array)

      []
    end

    # Reflexive, bounded, cycle-guarded transitive closure of `start` over an adjacency map.
    def member_closure(start, adj)
      seen = { start => true }
      queue = [start]
      qi = 0
      visited = 0
      while qi < queue.length && visited < MAX_MEMBER_CLOSURE_NODES
        visited += 1
        node = queue[qi]
        qi += 1
        neighbours_of(adj, node).each do |n|
          next if seen.key?(n)

          seen[n] = true
          queue << n
        end
      end
      seen
    end

    # ---- conditions ----------------------------------------------------------------------------------------------------

    def group?(c)
      c.is_a?(Hash) && (c.key?('all_of') || c.key?('any_of') || c.key?('not'))
    end

    def leaf?(c)
      c.is_a?(Hash) && !group?(c) && c['field'].is_a?(String)
    end

    def tri_leaf(c, ctx)
      field = get(c, 'field')
      return 'unknown' unless field.is_a?(String) && !field.empty?

      op = get(c, 'op')
      return 'unknown' unless op.is_a?(String)
      # "params unavailable" (never supplied / not verified) is NOT "field absent": a params-rooted condition fails closed,
      # otherwise `exists:false` / `nin` style checks pass vacuously.
      return 'unknown' if params_rooted?(field) && params_unavailable?(ctx)

      ref = get(c, 'ref')
      return 'unknown' if ref.is_a?(String) && params_rooted?(ref) && params_unavailable?(ctx)

      f_found, v = resolve(ctx, field)
      if op == 'exists'
        must_be_absent = get(c, 'value') == false
        holds = must_be_absent ? !f_found : f_found
        return holds ? 'true' : 'false'
      end
      return 'unknown' unless f_found

      # member_of resolves a target group (value/ref) AND an adjacency collection.
      if op == 'member_of'
        return 'unknown' unless v.is_a?(String)

        coll_path = get(c, 'collection')
        return 'unknown' unless coll_path.is_a?(String) && !coll_path.empty?

        c_found, coll = resolve(ctx, coll_path)
        return 'unknown' unless c_found && coll.is_a?(Hash)

        if ref.equal?(UNDEF)
          target = get(c, 'value')
          return 'unknown' if target.equal?(UNDEF)
        else
          r_found, target = resolve(ctx, ref)
          return 'unknown' unless r_found
        end
        targets = if target.is_a?(Array) then target.select { |x| x.is_a?(String) }
                  elsif target.is_a?(String) then [target]
                  else []
                  end
        return 'unknown' if targets.empty?

        reach = member_closure(v, coll)
        return targets.any? { |t| reach.key?(t) } ? 'true' : 'false'
      end

      if ref.equal?(UNDEF)
        operand = get(c, 'value')
        return 'unknown' if operand.equal?(UNDEF)
      else
        r_found, operand = resolve(ctx, ref)
        return 'unknown' unless r_found
      end

      case op
      when 'eq' then deep_eq?(v, operand) ? 'true' : 'false'
      when 'ne' then deep_eq?(v, operand) ? 'false' : 'true'
      when 'in'
        return 'unknown' unless operand.is_a?(Array)

        operand.any? { |x| deep_eq?(v, x) } ? 'true' : 'false'
      when 'nin'
        return 'unknown' unless operand.is_a?(Array)

        operand.any? { |x| deep_eq?(v, x) } ? 'false' : 'true'
      when 'lt', 'lte', 'gt', 'gte'
        o = ordered(v, operand)
        return 'unknown' if o.nil?

        ok = case op
             when 'lt' then o.negative?
             when 'lte' then o <= 0
             when 'gt' then o.positive?
             else o >= 0
             end
        ok ? 'true' : 'false'
      when 'prefix'
        return 'unknown' unless v.is_a?(String) && operand.is_a?(String)

        starts_with?(v, operand) ? 'true' : 'false'
      when 'like'
        return 'unknown' unless v.is_a?(String) && operand.is_a?(String)
        return 'unknown' if ulen(operand) > MAX_LIKE_PATTERN_LEN || ulen(v) > MAX_PATTERN_SUBJECT_LEN

        m = glob_match(operand, v)
        return 'unknown' if m.nil?

        m ? 'true' : 'false'
      when 'matches'
        return 'unknown' unless v.is_a?(String) && operand.is_a?(String)

        vlen = ulen(v)
        return 'unknown' if ulen(operand) > MAX_MATCHES_PATTERN_LEN || vlen > MAX_PATTERN_SUBJECT_LEN
        return 'unknown' unless AtlasPca.is_safe_regex_source(operand)
        return 'unknown' unless AtlasPca.charge_regex(operand, vlen) # R4-05: per-document regex work budget (fail closed)

        r = AtlasPca.safe_regex_full_match(operand, v) # R3-02: linear-time engine, never a backtracking Regexp
        r.nil? ? 'unknown' : (r ? 'true' : 'false')
      when 'is_a'
        return 'unknown' unless operand.is_a?(String) && !operand.empty?

        t = type_tag_match(v, operand)
        t.nil? ? 'unknown' : (t ? 'true' : 'false')
      else
        'unknown'
      end
    end

    def tri_inner(c, ctx)
      return 'unknown' unless obj?(c)

      if group?(c)
        if c.key?('all_of')
          xs = c['all_of']
          return 'unknown' unless xs.is_a?(Array) && !xs.empty?

          saw_unknown = false
          xs.each do |x|
            t = AtlasPca.evaluate_condition_tri(x, ctx)
            return 'false' if t == 'false'

            saw_unknown = true if t == 'unknown'
          end
          return saw_unknown ? 'unknown' : 'true'
        end
        if c.key?('any_of')
          xs = c['any_of']
          return 'unknown' unless xs.is_a?(Array) && !xs.empty?

          saw_unknown = false
          xs.each do |x|
            t = AtlasPca.evaluate_condition_tri(x, ctx)
            return 'true' if t == 'true'

            saw_unknown = true if t == 'unknown'
          end
          return saw_unknown ? 'unknown' : 'false'
        end
        # 'not'
        inner = AtlasPca.evaluate_condition_tri(c['not'], ctx)
        return inner == 'true' ? 'false' : (inner == 'false' ? 'true' : 'unknown')
      end
      return 'unknown' unless c.is_a?(Hash) # an array: `c.field` is undefined

      tri_leaf(c, ctx)
    rescue StandardError, SystemStackError
      'unknown'
    end

    # ---- the linear-time-safe regex subset guard -----------------------------------------------------------------------

    # `{` at i: /^\{(\d+)(?:(,)(\d*))?\}/ over the rest of the source. [length, lo, hi] (hi INF for `{n,}`) or nil.
    def guard_brace(s, i)
      n = s.length
      j = i + 1
      d0 = j
      j += 1 while j < n && SafeRegex.digit_unit?(s[j])
      return nil if j == d0

      lo = s[d0...j].pack('U*').to_i
      if j < n && s[j] == 0x2c
        k = j + 1
        k0 = k
        k += 1 while k < n && SafeRegex.digit_unit?(s[k])
        if k < n && s[k] == 0x7d
          hi = k == k0 ? SafeRegex::INF : s[k0...k].pack('U*').to_i
          return [k + 1 - i, lo, hi]
        end
        return nil
      end
      return nil unless j < n && s[j] == 0x7d

      [j + 1 - i, lo, lo]
    end

    def safe_source?(s, orig)
      stack = [[false, false]] # frames: [has_quant, has_alt]
      prev = :none # :none | :atom | frame
      bits = 0
      i = 0
      n = s.length
      while i < n
        ch = s[i]
        if ch == 0x5c # backslash
          return false if i + 1 >= n

          nx = s[i + 1]
          return false if (nx >= 0x31 && nx <= 0x39) || nx == 0x6b # backreference

          i += 2
          prev = :atom
          next
        end
        if ch == 0x5b # [
          # JavaScript class semantics: the class ends at the FIRST unescaped `]` after `[` and an optional `^`.
          j = i + 1
          j += 1 if j < n && s[j] == 0x5e
          while j < n && s[j] != 0x5d
            j += 1 if s[j] == 0x5c
            j += 1
          end
          return false if j >= n

          i = j + 1
          prev = :atom
          next
        end
        if ch == 0x28 # (
          if i + 1 < n && s[i + 1] == 0x3f
            return false unless i + 2 < n && s[i + 2] == 0x3a # lookahead/lookbehind/named group

            i += 3
          else
            i += 1
          end
          stack << [false, false]
          prev = :none
          next
        end
        if ch == 0x29 # )
          return false if stack.length < 2

          f = stack.pop
          parent = stack[-1]
          parent[0] ||= f[0]
          parent[1] ||= f[1]
          prev = f
          i += 1
          next
        end
        if ch == 0x7c # |
          bits += 1
          return false if bits > MAX_REGEX_COST_BITS

          stack[-1][1] = true
          prev = :none
          i += 1
          next
        end
        q = nil # [len, unbounded, max, options]
        if [0x2a, 0x2b].include?(ch)
          q = [1, true, SafeRegex::INF, SafeRegex::INF]
        elsif ch == 0x3f
          q = [1, false, 1, 2]
        elsif ch == 0x7b
          m = guard_brace(s, i)
          return false if m.nil?

          len, lo, hi = m
          return false if hi < lo

          q = [len, hi == SafeRegex::INF, hi, hi == SafeRegex::INF ? SafeRegex::INF : hi - lo + 1]
        end
        if q
          return false if prev == :none # nothing to repeat
          return false if prev.is_a?(Array) && (prev[0] || prev[1]) # nested quantifier

          qlen, unbounded, qmax, options = q
          return false if !unbounded && qmax != SafeRegex::INF && qmax > MAX_BOUNDED_REPEAT

          if unbounded
            bits += UNBOUNDED_QUANTIFIER_BITS
          elsif options > 1
            bits += (options - 1).bit_length # == ceil(log2(options)) for an integer options >= 2
          end
          return false if bits > MAX_REGEX_COST_BITS

          stack[-1][0] = true
          i += qlen
          i += 1 if i < n && s[i] == 0x3f # lazy modifier
          prev = :none # a quantifier cannot be quantified again
          next
        end
        i += 1
        prev = :atom
      end
      # R3-02: the source must ALSO compile in the linear-time engine that actually runs it (one parser decides what runs).
      stack.length == 1 && !SafeRegex.compile_cached(orig).nil?
    end

    # ---- predicates ----------------------------------------------------------------------------------------------------

    def verb_matches(p, verb)
      return p == '*' || str_eq?(p, verb) if p.is_a?(String)
      return p.any? { |x| x.is_a?(String) && (x == '*' || str_eq?(x, verb)) } if p.is_a?(Array)

      false
    end

    def resource_matches(pattern, resource)
      return true if pattern.equal?(UNDEF)
      return false unless pattern.is_a?(String)
      return true if pattern == '*'

      pb = pattern.b
      if pb.start_with?('re:'.b)
        src = pb.byteslice(3, pb.bytesize - 3).force_encoding(pattern.encoding)
        return false if ulen(src) > MAX_RE_SOURCE_LEN

        # ReDoS defence (no dependency): only a linear-time-safe subset is evaluated, and the subject is capped.
        rlen = ulen(resource)
        return false if rlen > MAX_RE_RESOURCE_LEN
        return false unless AtlasPca.is_safe_regex_source(src)
        return false unless AtlasPca.charge_regex(src, rlen) # R4-05: per-document regex work budget (fail closed)

        # R3-02: the linear-time budgeted engine. nil => unsupported / over budget => no match.
        return AtlasPca.safe_regex_full_match(src, resource) == true
      end
      if pb.end_with?('*'.b)
        prefix = pb.byteslice(0, pb.bytesize - 1).force_encoding(pattern.encoding)
        return starts_with?(resource, prefix)
      end
      str_eq?(pattern, resource)
    end

    def predicate_matches_inner(p, ctx)
      return false unless p.is_a?(Hash) # an array has no `verb`

      a = get(ctx, 'action')
      return false unless a.is_a?(Hash)

      verb = get(a, 'verb')
      resource = get(a, 'resource')
      return false unless verb.is_a?(String) && resource.is_a?(String)
      return false unless verb_matches(get(p, 'verb'), verb)
      return false unless resource_matches(get(p, 'resource'), resource)

      where = get(p, 'where')
      unless where.equal?(UNDEF)
        return false unless where.is_a?(Array)

        where.each { |c| return false unless AtlasPca.evaluate_condition(c, ctx) }
      end
      true
    rescue StandardError, SystemStackError
      false
    end

    OP_TEXT = { 'eq' => '==', 'ne' => '!=', 'lt' => '<', 'lte' => '<=', 'gt' => '>', 'gte' => '>=', 'in' => 'in',
                'nin' => 'not in', 'prefix' => 'starts with', 'like' => 'like', 'matches' => 'matches', 'is_a' => 'is a',
                'member_of' => 'member of' }.freeze
    MAX_SHOWN_STRING = 64
    MAX_SHOWN_ITEMS = 8

    # A scalar operand in a denial reason (TypeScript showValue): only safe integers, booleans, null and plain short
    # strings are spelled out.
    def show_value(v, depth = 0)
      return 'null' if v.nil?
      return v.to_s if v == true || v == false
      if num?(v)
        f = jsnum(v).to_f
        return f.finite? && f == f.floor && f.abs <= MAX_SAFE ? f.to_i.to_s : '<number>'
      end
      if v.is_a?(String)
        u = units(v)
        plain = u.length <= MAX_SHOWN_STRING && u.none? { |c| c < 0x20 || c == 0x22 || c == 0x5c || (c >= 0xd800 && c <= 0xdfff) }
        return plain ? "\"#{v}\"" : '"..."'
      end
      if v.is_a?(Array) && depth.zero?
        return v.length <= MAX_SHOWN_ITEMS ? "[#{v.map { |x| show_value(x, 1) }.join(', ')}]" : '[...]'
      end
      '<value>'
    end

    # The condition as the limit a reader recognises: `amount <= 500`, `currency in ["usd", "eur"]`.
    def describe_condition(c, depth = 0)
      return '<condition>' unless c.is_a?(Hash) || c.is_a?(Array)

      if group?(c)
        return '(...)' if depth >= 2

        if c['all_of'].is_a?(Array)
          return "all of (#{c['all_of'].first(MAX_SHOWN_ITEMS).map { |x| describe_condition(x, depth + 1) }.join('; ')})"
        end
        if c['any_of'].is_a?(Array)
          return "any of (#{c['any_of'].first(MAX_SHOWN_ITEMS).map { |x| describe_condition(x, depth + 1) }.join('; ')})"
        end
        return "not (#{describe_condition(c['not'], depth + 1)})" if c.key?('not')

        return '<condition>'
      end
      f = c.is_a?(Hash) && c['field'].is_a?(String) ? c['field'] : '<field>'
      name = f.start_with?('action.params.') ? f[('action.params.'.length)..] : f
      op = c.is_a?(Hash) ? c['op'] : nil
      return c['value'] == false ? "#{name} absent" : "#{name} present" if op == 'exists'

      text = op.is_a?(String) ? OP_TEXT[op] : nil
      return "#{name} <condition>" if text.nil?

      operand = c.key?('ref') ? (c['ref'].is_a?(String) ? c['ref'] : '<ref>') : (c.key?('value') ? show_value(c['value']) : '<value>')
      "#{name} #{text} #{operand}"
    end

    # Inside an unmet top-level condition, the narrowest part that failed (an all_of points at its first unmet child).
    def narrowest_unmet(c, ctx, depth = 0)
      if depth < 4 && group?(c) && c.key?('all_of') && c['all_of'].is_a?(Array)
        c['all_of'].each { |x| return narrowest_unmet(x, ctx, depth + 1) unless AtlasPca.evaluate_condition(x, ctx) }
      end
      c
    end

    # 0.5: when the verb and resource are in scope but a `where` limit is not met, name that limit; nil when no predicate
    # is in scope (the plain "no predicate permits" wording stays for that case).
    def first_unmet_limit(predicates, ctx)
      a = get(ctx, 'action')
      return nil unless a.is_a?(Hash) && get(a, 'verb').is_a?(String) && get(a, 'resource').is_a?(String)

      predicates.each do |p|
        next unless p.is_a?(Hash) && verb_matches(get(p, 'verb'), a['verb']) && resource_matches(get(p, 'resource'), a['resource'])

        where = get(p, 'where')
        next unless where.is_a?(Array)

        where.each { |c| return describe_condition(narrowest_unmet(c, ctx)) unless AtlasPca.evaluate_condition(c, ctx) }
      end
      nil
    end

    def evaluate_predicates_inner(predicates, ctx)
      return { 'allowed' => false, 'reason' => 'envelope grants no predicates' } unless predicates.is_a?(Array) && !predicates.empty?

      predicates.each do |p|
        return { 'allowed' => true, 'matched' => p } if AtlasPca.predicate_matches(p, ctx)
      end
      a = get(ctx, 'action')
      limit = first_unmet_limit(predicates, ctx)
      unless limit.nil?
        return { 'allowed' => false,
                 'reason' => "#{limit} not satisfied for #{js_string(get(a, 'verb'))} on #{js_string(get(a, 'resource'))}" }
      end
      { 'allowed' => false, 'reason' => "no predicate permits #{js_string(get(a, 'verb'))} on #{js_string(get(a, 'resource'))}" }
    rescue StandardError, SystemStackError
      { 'allowed' => false, 'reason' => 'predicate evaluation error (fail closed)' }
    end
  end

  module_function

  # Resolve a dotted path (rooted at action / subject / env) into the context: {"found"=>true, "value"=>v} or
  # {"found"=>false}. Own properties only; unknown root => not found. Never raises.
  def resolve_path(ctx, path)
    found, value = Predicates.resolve(ctx, path)
    found ? { 'found' => true, 'value' => value } : { 'found' => false }
  rescue StandardError
    { 'found' => false }
  end

  # Is this condition a boolean grouping (`all_of` / `any_of` / `not`) rather than a leaf comparison?
  def group_condition?(c)
    Predicates.group?(c)
  end

  # Is this condition a leaf comparison (a Hash with a String `field`, not a grouping)?
  def leaf_condition?(c)
    Predicates.leaf?(c)
  end

  # Tri-valued evaluation ('true' | 'false' | 'unknown') of any condition (leaf or boolean grouping). Never raises.
  def evaluate_condition_tri(c, ctx)
    with_regex_budget { Predicates.tri_inner(c, ctx) }
  rescue StandardError, SystemStackError
    'unknown'
  end

  # Evaluate one condition: true iff it is cleanly decided true (groupings fail closed).
  def evaluate_condition(c, ctx)
    evaluate_condition_tri(c, ctx) == 'true'
  end

  # Is `src` in the linear-time-safe subset (no quantified group holding a quantifier or alternation, no backreferences /
  # lookaround, bounded repeats <= 64, a 22-bit backtracking-cost budget) AND does it compile in the linear-time engine?
  # Never raises.
  def is_safe_regex_source(src) # rubocop:disable Naming/PredicateName
    return false unless src.is_a?(String)

    Predicates.safe_source?(SafeRegex.units(src), src)
  rescue StandardError
    false
  end

  # Does a single predicate permit the action (verb AND resource AND every `where`)? Never raises.
  def predicate_matches(p, ctx)
    with_regex_budget { Predicates.predicate_matches_inner(p, ctx) }
  rescue StandardError, SystemStackError
    false
  end

  # An action is allowed iff it matches AT LEAST ONE predicate (default-deny: an empty list allows nothing).
  # {"allowed"=>true, "matched"=>p} or {"allowed"=>false, "reason"=>s}. Never raises.
  def evaluate_predicates(predicates, ctx)
    with_regex_budget { Predicates.evaluate_predicates_inner(predicates, ctx) }
  rescue StandardError, SystemStackError
    { 'allowed' => false, 'reason' => 'predicate evaluation error (fail closed)' }
  end
end
