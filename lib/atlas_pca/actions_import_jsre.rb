# frozen_string_literal: true

# A translator from the JavaScript regular expression dialect (ECMAScript, no flags, Annex B leniency) used by `path_re` of the suggestion
# rules to a Ruby Regexp with the same meaning on UTF-16 code units. It exists so a rule set is accepted or refused exactly as the
# reference's `new RegExp(...)` does and matches the same locations. Syntax the reference rejects raises JsReError. Supported: literals,
# `.`, anchors, `\b \B`, classes with ranges and class escapes, groups `(...)` and `(?:...)`, alternation, greedy and lazy quantifiers.
# Lookaround, named groups and back-references are refused (the rule validator refuses them before a pattern is compiled).
# A lone surrogate code unit rides through the Regexp as a private-use stand-in (plane 15, as Siem::U16 does), so every class is
# built from code-unit intervals and the subject is the matching unit-for-codepoint string.
require_relative 'siem'

module AtlasPca
  module ActionsImportJsre
    class JsReError < ArgumentError; end

    U16 = AtlasPca::Siem::U16
    WS = [[9, 13], [32, 32], [0xA0, 0xA0], [0x1680, 0x1680], [0x2000, 0x200A], [0x2028, 0x2029], [0x202F, 0x202F], [0x205F, 0x205F], [0x3000, 0x3000], [0xFEFF, 0xFEFF]].freeze
    DIGIT = [[48, 57]].freeze
    WORD = [[48, 57], [65, 90], [95, 95], [97, 122]].freeze
    MAX = 0xFFFF
    CLASS_ESC = { 'd'.ord => DIGIT, 'w'.ord => WORD, 's'.ord => WS }.freeze
    CTRL = { 'f'.ord => 12, 'n'.ord => 10, 'r'.ord => 13, 't'.ord => 9, 'v'.ord => 11 }.freeze
    W = '[A-Za-z0-9_]'
    WORD_B = "(?:(?<=#{W})(?!#{W})|(?<!#{W})(?=#{W}))"
    WORD_NB = "(?:(?<!#{W})(?!#{W})|(?<=#{W})(?=#{W}))"

    module_function

    def norm(iv)
      out = []
      iv.sort.each do |lo, hi|
        if !out.empty? && lo <= out[-1][1] + 1
          out[-1] = [out[-1][0], [out[-1][1], hi].max]
        else
          out << [lo, hi]
        end
      end
      out
    end

    def neg(iv)
      out = []
      cur = 0
      norm(iv).each do |lo, hi|
        out << [cur, lo - 1] if lo > cur
        cur = hi + 1
      end
      out << [cur, MAX] if cur <= MAX
      out
    end

    # a code unit as the code point the Regexp sees (a surrogate becomes its plane-15 stand-in)
    def ucode(u) = u >= 0xD800 && u <= 0xDFFF ? 0xF0000 + (u - 0xD800) : u
    def hexcp(u) = format('\\u{%x}', u)

    def cls(iv)
      iv = norm(iv)
      return '(?!)' if iv.empty?

      parts = []
      iv.each do |lo, hi|
        segs = []
        segs << [lo, [hi, 0xD7FF].min] if lo <= 0xD7FF
        segs << [[lo, 0xD800].max, [hi, 0xDFFF].min] if hi >= 0xD800 && lo <= 0xDFFF
        segs << [[lo, 0xE000].max, hi] if hi >= 0xE000
        segs.each do |a, b|
          a = ucode(a)
          b = ucode(b)
          parts << (a == b ? hexcp(a) : "#{hexcp(a)}-#{hexcp(b)}")
        end
      end
      "[#{parts.join}]"
    end

    def lit(u) = u > 0x20 && u < 0x7F ? Regexp.escape(u.chr) : hexcp(ucode(u))

    class Parser
      def initialize(src)
        @s = U16.units(src)
        @i = 0
      end

      attr_reader :i

      def done? = @i >= @s.length
      def peek(k = 0) = (j = @i + k) < @s.length ? @s[j] : nil
      def at?(k, ch) = peek(k) == ch.ord
      def err(msg) = raise(JsReError, "Invalid regular expression: #{msg}")

      def disjunction(depth)
        alts = [alternative(depth)]
        while at?(0, '|')
          @i += 1
          alts << alternative(depth)
        end
        alts.join('|')
      end

      def alternative(depth)
        out = []
        out << term(depth) while @i < @s.length && !at?(0, '|') && !at?(0, ')')
        out.join
      end

      # {n}, {n,} or {n,m} at the cursor: [min, max or nil, length], or nil when the brace is not a quantifier.
      def braced
        j = @i
        return nil unless at?(0, '{')

        j += 1
        d0 = j
        j += 1 while j < @s.length && @s[j] >= 48 && @s[j] <= 57
        return nil if j == d0

        lo = @s[d0...j].pack('U*').to_i
        hi = lo
        if j < @s.length && @s[j] == 44
          j += 1
          d1 = j
          j += 1 while j < @s.length && @s[j] >= 48 && @s[j] <= 57
          hi = j == d1 ? nil : @s[d1...j].pack('U*').to_i
        end
        return nil unless j < @s.length && @s[j] == 125

        err('numbers out of order in {} quantifier') if !hi.nil? && hi < lo
        [lo, hi, j + 1 - @i]
      end

      def quantifier(atom)
        if at?(0, '*') || at?(0, '+') || at?(0, '?')
          q = peek.chr
          @i += 1
        else
          b = at?(0, '{') ? braced : nil
          return atom if b.nil?

          @i += b[2]
          q = "{#{b[0]},#{b[1]}}"
        end
        if at?(0, '?')
          @i += 1
          q += '?'
        end
        atom + q
      end

      def term(depth)
        if at?(0, '^')
          @i += 1
          return '\\A'
        end
        if at?(0, '$')
          @i += 1
          return '\\z'
        end
        if at?(0, '\\') && (at?(1, 'b') || at?(1, 'B'))
          @i += 2
          return at?(-1, 'b') ? WORD_B : WORD_NB
        end
        err('nothing to repeat') if at?(0, '*') || at?(0, '+') || at?(0, '?')
        err('nothing to repeat') if at?(0, '{') && !braced.nil?
        quantifier(atom(depth))
      end

      def atom(depth)
        err('too deeply nested') if depth > 200
        if at?(0, '(')
          @i += 1
          if at?(0, '?')
            err('invalid group') unless at?(1, ':')
            @i += 2
            head = '(?:'
          else
            head = '('
          end
          body = disjunction(depth + 1)
          err('unterminated group') unless at?(0, ')')
          @i += 1
          return "#{head}#{body})"
        end
        if at?(0, '.')
          @i += 1
          return '[^\\n\\r\\u2028\\u2029]'
        end
        return char_class if at?(0, '[')
        return atom_escape if at?(0, '\\')

        u = peek
        @i += 1
        AtlasPca::ActionsImportJsre.lit(u)
      end

      def hex(n)
        h = @s[@i, n]
        if h.length == n && h.all? { |x| (x >= 48 && x <= 57) || (x >= 65 && x <= 70) || (x >= 97 && x <= 102) }
          @i += n
          return h.pack('U*').to_i(16)
        end
        nil
      end

      def octal?(u) = !u.nil? && u >= 48 && u <= 55
      def alpha?(u) = !u.nil? && ((u >= 65 && u <= 90) || (u >= 97 && u <= 122))
      def digit_us?(u) = !u.nil? && ((u >= 48 && u <= 57) || u == 95)

      # The code unit a character escape at `\` denotes (cursor past the escape).
      def escape_char(in_class)
        @i += 1 # the backslash
        err('\\ at end of pattern') if @i >= @s.length
        c = @s[@i]
        if CTRL.key?(c)
          @i += 1
          return CTRL[c]
        end
        if c == 99 # c
          nxt = peek(1)
          if alpha?(nxt)
            @i += 2
            return nxt % 32
          end
          if in_class && digit_us?(nxt)
            @i += 2
            return nxt % 32
          end
          return 92 # a lone backslash; the `c` is read next
        end
        if c == 48 # 0
          @i += 1
          if octal?(peek)
            v = 0
            n = 0
            while n < 3 && octal?(peek) && (v * 8) + (peek - 48) <= 0o377
              v = (v * 8) + (peek - 48)
              @i += 1
              n += 1
            end
            return v
          end
          return 0
        end
        if c == 120 # x
          @i += 1
          v = hex(2)
          return v.nil? ? 120 : v
        end
        if c == 117 # u
          @i += 1
          v = hex(4)
          return v.nil? ? 117 : v
        end
        if c == 98 && in_class
          @i += 1
          return 8
        end
        err('back-references are not supported') if c >= 49 && c <= 57
        if c == 107 # k
          @i += 1
          return 107
        end
        @i += 1
        c
      end

      def class_esc?(n) = !n.nil? && (CLASS_ESC.key?(n) || [68, 87, 83].include?(n))

      def atom_escape
        c = peek(1)
        if class_esc?(c)
          @i += 2
          iv = CLASS_ESC[c | 0x20]
          return AtlasPca::ActionsImportJsre.cls(c >= 97 ? iv : AtlasPca::ActionsImportJsre.neg(iv))
        end
        AtlasPca::ActionsImportJsre.lit(escape_char(false))
      end

      # [code unit or nil, interval set or nil]
      def class_atom
        c = peek
        if c == 92
          n = peek(1)
          if class_esc?(n)
            @i += 2
            iv = CLASS_ESC[n | 0x20]
            return [nil, n >= 97 ? iv : AtlasPca::ActionsImportJsre.neg(iv)]
          end
          return [escape_char(true), nil]
        end
        @i += 1
        [c, nil]
      end

      def char_class
        @i += 1
        negate = false
        if at?(0, '^')
          negate = true
          @i += 1
        end
        iv = []
        loop do
          err('unterminated character class') if @i >= @s.length
          if at?(0, ']')
            @i += 1
            break
          end
          a, aset = class_atom
          if at?(0, '-') && !peek(1).nil? && !at?(1, ']')
            @i += 1
            b, bset = class_atom
            if !aset.nil? || !bset.nil? # Annex B: a class escape on either side makes the dash a literal
              iv += (aset.nil? ? [[a, a]] : aset) + [[45, 45]] + (bset.nil? ? [[b, b]] : bset)
              next
            end
            err('range out of order in character class') if a > b
            iv << [a, b]
            next
          end
          iv += aset.nil? ? [[a, a]] : aset
        end
        AtlasPca::ActionsImportJsre.cls(negate ? AtlasPca::ActionsImportJsre.neg(iv) : iv)
      end
    end

    # The Ruby pattern text for a JavaScript pattern, or JsReError.
    def translate(pattern)
      p = Parser.new(pattern)
      out = p.disjunction(0)
      p.err("unmatched ')'") unless p.done?
      out
    end

    def compile_js(pattern)
      Regexp.new(translate(pattern))
    rescue RegexpError => e
      raise JsReError, "Invalid regular expression: #{e.message}"
    end

    # RegExp.prototype.test: a match anywhere in the string (as UTF-16 code units).
    def js_test(rx, s) = rx.match?(U16.units(s).map { |u| [ucode(u)].pack('U') }.join)
  end
end
