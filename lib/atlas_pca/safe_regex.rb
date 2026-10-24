# frozen_string_literal: true

# A linear-time, budgeted regular-expression matcher for untrusted `re:` / `matches` patterns, plus the per-document regex
# work budget. Port of packages/pca/src/safe-regex.ts and packages/pca/src/regex-budget.ts (the TypeScript is
# authoritative; the DEFAULT code path, not the PCA_VERIFIED_CORE opt-in).
#
# The pattern is parsed ONCE, by this parser, into a Thompson NFA and run by a Pike-style simulation whose cost is
# O(|subject| x |NFA|) by construction. Ruby's Regexp is never run on an untrusted pattern.
#
# SUBSET (anything else is REFUSED at compile time, fail closed): literals; `.` (not a line terminator); classes `[...]` /
# `[^...]` incl. `[]` (matches nothing) and `[^]` (any char), ranges and `\d \D \w \W \s \S` inside them; escapes
# `\d \D \w \W \s \S \t \n \v \f \r \0 \xHH \uHHHH \cX` and escaped punctuation; groups `( )` and `(?: )`; alternation `|`
# (empty branches allowed); quantifiers `* + ? {n} {n,} {n,m}` with an optional lazy `?`; anchors `^` `$`.
#
# JS SEMANTICS: patterns and subjects are processed as sequences of UTF-16 CODE UNITS, exactly like a flagless JS RegExp
# (an astral character is two units; `.` matches one unit). Every Ruby string is first expanded with
# SafeRegex.units (UTF-8, or the WTF-8 bytes the loose JSON reader gives a lone surrogate; anything else raises, and every
# public entry point fails closed on it).
module AtlasPca
  module SafeRegex
    # Largest NFA (instruction count) a pattern may compile to. Bounds memory and the per-character cost.
    MAX_NFA_INSTRUCTIONS = 4096
    # Largest `{n,m}` bound.
    MAX_REPEAT = 64
    # Hard cap on (NFA size x (subject length + 1)): the matcher refuses rather than run longer.
    MAX_MATCH_STEPS = 2_000_000

    OP_SET = 0   # consume one code unit that is in `set`
    OP_SPLIT = 1 # epsilon to x and y
    OP_JMP = 2   # epsilon to x
    OP_BOL = 3   # assert position 0
    OP_EOL = 4   # assert position n
    OP_MATCH = 5

    INF = Float::INFINITY

    DIGIT = [[0x30, 0x39]].freeze
    WORD = [[0x30, 0x39], [0x41, 0x5a], [0x5f, 0x5f], [0x61, 0x7a]].freeze
    SPACE = [[0x09, 0x0d], [0x20, 0x20], [0xa0, 0xa0], [0x1680, 0x1680], [0x2000, 0x200a], [0x2028, 0x2029],
             [0x202f, 0x202f], [0x205f, 0x205f], [0x3000, 0x3000], [0xfeff, 0xfeff]].freeze
    LINE_TERMINATORS = [[0x0a, 0x0a], [0x0d, 0x0d], [0x2028, 0x2029]].freeze

    # A set of UTF-16 code units: sorted, merged ranges, optionally negated (negation is applied at test time).
    class CharSet
      attr_reader :ranges, :negated

      def initialize(ranges, negated)
        @ranges = ranges
        @negated = negated
      end

      def has?(c)
        lo = 0
        hi = @ranges.length - 1
        inside = false
        while lo <= hi
          mid = (lo + hi) >> 1
          r = @ranges[mid]
          if c < r[0]
            hi = mid - 1
          elsif c > r[1]
            lo = mid + 1
          else
            inside = true
            break
          end
        end
        inside != @negated
      end
    end

    class Refuse < StandardError; end

    # A compiled NFA program: an Array of [op, x, y, set] instructions.
    class CompiledRegex
      attr_reader :program

      def initialize(program)
        @program = program
      end
    end

    module_function

    # ---- UTF-16 helpers (shared with predicates.rb) ------------------------------------------------------------------

    # The UTF-16 code-unit view of `s` (an Array of Integers): astral code points split into their surrogate pair; a lone
    # surrogate (WTF-8 bytes) is its own unit. Raises ArgumentError on bytes that are not (generalized) UTF-8.
    def units(s)
      cps = s.unpack('U*')
      return cps if cps.all? { |c| c <= 0xffff }

      out = []
      cps.each do |c|
        if c > 0xffff
          raise ArgumentError, 'code point beyond U+10FFFF' if c > 0x10ffff

          c -= 0x10000
          out << (0xd800 + (c >> 10)) << (0xdc00 + (c & 0x3ff))
        else
          out << c
        end
      end
      out
    end

    # JS `s.length` (UTF-16 code units).
    def utf16_len(s)
      units(s).length
    end

    # `hasLoneSurrogate` over a unit view: a high surrogate not followed by a low one, or a low not preceded by a high.
    def units_have_lone_surrogate?(u)
      n = u.length
      i = 0
      while i < n
        o = u[i]
        if o >= 0xd800 && o <= 0xdbff
          if i + 1 < n && u[i + 1] >= 0xdc00 && u[i + 1] <= 0xdfff
            i += 2
            next
          end
          return true
        end
        return true if o >= 0xdc00 && o <= 0xdfff

        i += 1
      end
      false
    end

    def digit_unit?(c)
      !c.nil? && c >= 0x30 && c <= 0x39
    end

    def hex_unit?(c)
      !c.nil? && ((c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66))
    end

    def alpha_unit?(c)
      !c.nil? && ((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a))
    end

    def normalize(ranges)
      s = ranges.map { |r| [r[0], r[1]] }.sort_by.with_index { |r, i| [r[0], i] }
      out = []
      s.each do |r|
        last = out[-1]
        if last && r[0] <= last[1] + 1
          last[1] = [last[1], r[1]].max
        else
          out << [r[0], r[1]]
        end
      end
      out
    end

    def complement(r)
      out = []
      nxt = 0
      normalize(r).each do |a, b|
        out << [nxt, a - 1] if a > nxt
        nxt = b + 1
      end
      out << [nxt, 0xffff] if nxt <= 0xffff
      out
    end

    def refuse(m)
      raise Refuse, m
    end

    # ---- parser (AST nodes: [:set, CharSet] | [:bol] | [:eol] | [:cat, items] | [:alt, items] | [:rep, node, min, max])

    class Parser
      def initialize(s)
        @s = s # unit view (Array of Integers)
        @i = 0
      end

      def at(i)
        i >= 0 && i < @s.length ? @s[i] : nil
      end

      def parse
        n = alt
        SafeRegex.refuse('unbalanced )') if @i < @s.length
        n
      end

      def alt
        items = [cat]
        while at(@i) == 0x7c # |
          @i += 1
          items << cat
        end
        items.length == 1 ? items[0] : [:alt, items]
      end

      def cat
        items = []
        items << quantified while @i < @s.length && @s[@i] != 0x7c && @s[@i] != 0x29
        [:cat, items]
      end

      # `{` at @i: /^\{(\d{1,4})(?:(,)(\d{0,4}))?\}/ over the next 16 units. [length, min, max] or nil.
      def brace
        j = @i + 1
        d0 = j
        j += 1 while j - d0 < 4 && SafeRegex.digit_unit?(at(j))
        return nil if j == d0

        lo = @s[d0...j].pack('U*').to_i
        if at(j) == 0x2c # ,
          k = j + 1
          k0 = k
          k += 1 while k - k0 < 4 && SafeRegex.digit_unit?(at(k))
          return nil unless at(k) == 0x7d

          hi = k == k0 ? INF : @s[k0...k].pack('U*').to_i
          return [k + 1 - @i, lo, hi]
        end
        return nil unless at(j) == 0x7d

        [j + 1 - @i, lo, lo]
      end

      def quantified
        atom = self.atom
        c = at(@i)
        case c
        when 0x2a # *
          min = 0
          max = INF
          @i += 1
        when 0x2b # +
          min = 1
          max = INF
          @i += 1
        when 0x3f # ?
          min = 0
          max = 1
          @i += 1
        when 0x7b # {
          m = brace
          SafeRegex.refuse('{ is not a well-formed quantifier') if m.nil?
          len, min, max = m
          SafeRegex.refuse('quantifier range out of order') if max < min
          @i += len
        else
          return atom
        end
        SafeRegex.refuse('nothing to repeat (assertion)') if atom[0] == :bol || atom[0] == :eol
        SafeRegex.refuse('repeat bound too large') if (max != INF && max > MAX_REPEAT) || min > MAX_REPEAT
        @i += 1 if at(@i) == 0x3f # lazy: no effect on a full-match boolean
        [:rep, atom, min, max]
      end

      def atom
        c = @s[@i]
        case c
        when 0x28 # (
          @i += 1
          if at(@i) == 0x3f
            SafeRegex.refuse('lookaround / named groups are not supported') unless at(@i + 1) == 0x3a
            @i += 2
          end
          n = alt
          SafeRegex.refuse('unterminated group') unless at(@i) == 0x29
          @i += 1
          n
        when 0x5b then cls # [
        when 0x2e # .
          @i += 1
          [:set, CharSet.new(LINE_TERMINATORS, true)]
        when 0x5e # ^
          @i += 1
          [:bol]
        when 0x24 # $
          @i += 1
          [:eol]
        when 0x5c then [:set, escape_inner(false)[0]] # backslash
        when 0x2a, 0x2b, 0x3f then SafeRegex.refuse('nothing to repeat')
        when 0x7b then SafeRegex.refuse('{ is not a well-formed quantifier')
        else
          @i += 1
          [:set, CharSet.new([[c, c]], false)]
        end
      end

      # After `\`: [set, is_class_escape, ch or nil] (a class escape cannot be a range endpoint).
      def escape_inner(in_class)
        @i += 1 # backslash
        c = at(@i)
        SafeRegex.refuse('trailing backslash') if c.nil?
        @i += 1
        single = ->(code) { [CharSet.new([[code, code]], false), false, code] }
        case c
        when 0x64 then [CharSet.new(DIGIT, false), true, nil] # d
        when 0x44 then [CharSet.new(DIGIT, true), true, nil]  # D
        when 0x77 then [CharSet.new(WORD, false), true, nil]  # w
        when 0x57 then [CharSet.new(WORD, true), true, nil]   # W
        when 0x73 then [CharSet.new(SPACE, false), true, nil] # s
        when 0x53 then [CharSet.new(SPACE, true), true, nil]  # S
        when 0x74 then single.call(9)  # t
        when 0x6e then single.call(10) # n
        when 0x76 then single.call(11) # v
        when 0x66 then single.call(12) # f
        when 0x72 then single.call(13) # r
        when 0x30 # 0
          SafeRegex.refuse('octal escape') if SafeRegex.digit_unit?(at(@i))
          single.call(0)
        when 0x78 # x
          h = @s[@i, 2] || []
          SafeRegex.refuse('bad \\x escape') unless h.length == 2 && h.all? { |u| SafeRegex.hex_unit?(u) }
          @i += 2
          single.call(h.pack('U*').to_i(16))
        when 0x75 # u
          h = @s[@i, 4] || []
          SafeRegex.refuse('bad \\u escape') unless h.length == 4 && h.all? { |u| SafeRegex.hex_unit?(u) }
          @i += 4
          single.call(h.pack('U*').to_i(16))
        when 0x63 # c
          l = at(@i)
          SafeRegex.refuse('bad \\c escape') unless SafeRegex.alpha_unit?(l)
          @i += 1
          single.call(l % 32)
        when 0x62 # b
          return single.call(8) if in_class # [\b] is backspace

          SafeRegex.refuse('word-boundary assertions are not supported')
        else
          # Back-references, \B, \k, \p, and any other letter/digit escape: not in the subset. Escaped punctuation (and the
          # other non-alphanumeric characters) is the character itself.
          SafeRegex.refuse('escape is not supported') if SafeRegex.alpha_unit?(c) || SafeRegex.digit_unit?(c) || c == 0x5f
          single.call(c)
        end
      end

      def read_class_atom
        c = @s[@i] # both call sites have just checked @s[@i] is defined
        if c == 0x5c
          set, is_cls, ch = escape_inner(true)
          # a negated class escape (\D \W \S) contributes the complement as ranges
          rs = set.negated ? SafeRegex.complement(set.ranges) : set.ranges
          return [rs, ch, is_cls]
        end
        @i += 1
        [[[c, c]], c, false]
      end

      def cls
        @i += 1 # [
        negated = false
        if at(@i) == 0x5e
          negated = true
          @i += 1
        end
        ranges = []
        loop do
          c = at(@i)
          SafeRegex.refuse('unterminated class') if c.nil?
          if c == 0x5d
            @i += 1
            break
          end
          a = read_class_atom
          nx = at(@i + 1)
          if at(@i) == 0x2d && !nx.nil? && nx != 0x5d
            # possible range
            @i += 1
            b = read_class_atom
            if a[2] || b[2]
              # Annex B: a class escape as a range endpoint makes the '-' a literal
              a[0].each { |r| ranges << [r[0], r[1]] }
              ranges << [0x2d, 0x2d]
              b[0].each { |r| ranges << [r[0], r[1]] }
            else
              SafeRegex.refuse('class range out of order') if a[1] > b[1]
              ranges << [a[1], b[1]]
            end
          else
            a[0].each { |r| ranges << [r[0], r[1]] }
          end
        end
        [:set, CharSet.new(SafeRegex.normalize(ranges), negated)]
      end
    end

    # ---- compile -------------------------------------------------------------------------------------------------------

    def emit(node, prog)
      refuse('pattern too large') if prog.length > MAX_NFA_INSTRUCTIONS
      case node[0]
      when :set then prog << [OP_SET, 0, 0, node[1]]
      when :bol then prog << [OP_BOL, 0, 0, nil]
      when :eol then prog << [OP_EOL, 0, 0, nil]
      when :cat then node[1].each { |it| emit(it, prog) }
      when :alt
        # split L1, L2 ; L1: a ; jmp end ; L2: split ... ; last
        items = node[1]
        jmps = []
        items.each_with_index do |it, i|
          if i < items.length - 1
            split = prog.length
            prog << [OP_SPLIT, split + 1, -1, nil]
            emit(it, prog)
            jmps << prog.length
            prog << [OP_JMP, -1, 0, nil]
            prog[split][2] = prog.length
          else
            emit(it, prog)
          end
        end
        jmps.each { |j| prog[j][1] = prog.length }
      else # :rep
        _, body, min, max = node
        min.times { emit(body, prog) }
        if max == INF
          # L: split body, end ; body ; jmp L
          split = prog.length
          prog << [OP_SPLIT, split + 1, -1, nil]
          emit(body, prog)
          prog << [OP_JMP, split, 0, nil]
          prog[split][2] = prog.length
        else
          # (max-min) nested optionals: split body, end ; body ; split body, end ; ...
          splits = []
          (min...max).each do
            splits << prog.length
            prog << [OP_SPLIT, prog.length + 1, -1, nil]
            emit(body, prog)
          end
          splits.each { |sp| prog[sp][2] = prog.length }
        end
        refuse('pattern too large') if prog.length > MAX_NFA_INSTRUCTIONS
      end
    end

    # Compile `src` into an NFA, or nil when it is outside the supported subset or too large. Never raises.
    def compile(src)
      return nil unless src.is_a?(String)

      ast = Parser.new(units(src)).parse
      prog = []
      emit(ast, prog)
      prog << [OP_MATCH, 0, 0, nil]
      return nil if prog.length > MAX_NFA_INSTRUCTIONS

      CompiledRegex.new(prog)
    rescue StandardError, SystemStackError # Refuse, stack depth on absurd nesting, malformed bytes: refuse
      nil
    end

    # Full-match `subject` against a compiled program: true / false, or nil when the work budget would be exceeded.
    # O(|subject| x |program|), no backtracking.
    def run(re, subject)
      prog = re.program
      u = units(subject)
      n = u.length
      plen = prog.length
      return nil if plen * (n + 1) > MAX_MATCH_STEPS

      mark = Array.new(plen, -1)
      gen = 0
      matched = false
      stack = []
      add = lambda do |list, pc0, pos|
        stack.clear
        stack << pc0
        until stack.empty?
          pc = stack.pop
          next if mark[pc] == gen

          mark[pc] = gen
          ins = prog[pc]
          case ins[0]
          when OP_JMP then stack << ins[1]
          when OP_SPLIT
            stack << ins[2] # push y first so x is explored first (order is irrelevant for a boolean)
            stack << ins[1]
          when OP_BOL then stack << (pc + 1) if pos.zero?
          when OP_EOL then stack << (pc + 1) if pos == n
          when OP_MATCH then matched = true if pos == n
          else list << pc # OP_SET
          end
        end
      end

      gen += 1
      clist = []
      add.call(clist, 0, 0)
      pos = 0
      while pos < n
        c = u[pos]
        gen += 1
        nlist = []
        clist.each { |pc| add.call(nlist, pc + 1, pos + 1) if prog[pc][3].has?(c) }
        clist = nlist
        return false if clist.empty? && !matched

        pos += 1
      end
      matched
    end

    # ---- the bounded compiled-program cache (regex-cache.ts: an LRU evicting one entry at a time; the verdict never
    # depends on it). Refusals are cached too.
    CACHE_MAX_ENTRIES = 512
    CACHE = {} # rubocop:disable Style/MutableConstant
    CACHE_LOCK = Mutex.new

    def compile_cached(src)
      return nil unless src.is_a?(String)

      key = src.b.freeze
      CACHE_LOCK.synchronize do
        if CACHE.key?(key)
          v = CACHE.delete(key)
          CACHE[key] = v
          return v
        end
      end
      re = compile(src)
      CACHE_LOCK.synchronize do
        CACHE.delete(key)
        CACHE[key] = re
        CACHE.shift while CACHE.length > CACHE_MAX_ENTRIES
      end
      re
    end
  end

  # ---- per-document regex work budget (regex-budget.ts, R4-05 / R5-API-01) ------------------------------------------
  #
  # A DOCUMENT budget is opened by every library entry point (evaluate_predicates, predicate_matches,
  # evaluate_condition_tri); it sums, across every `re:` resource pattern and `matches` condition evaluated inside it, the
  # number of evaluations, the pattern source size (UTF-16 units) and the worst-case NFA steps (instructions x (subject
  # length + 1)). Charging happens BEFORE matching; once any cap is exceeded the budget is poisoned and every further
  # regex evaluation in the scope is refused (fail closed). An optional REQUEST budget (RegexBudget.request) is charged as
  # well by every document budget opened inside it. The open scope is FIBER-LOCAL (Thread#[]), never a process global.
  class RegexBudget
    MAX_REGEX_EVALUATIONS_PER_DOCUMENT = 64
    MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT = 8192
    MAX_REGEX_STEPS_PER_DOCUMENT = 5_000_000
    # A request-level budget allows this many documents' worth of regex work in total.
    REGEX_REQUEST_SCALE = 4
    SCOPE_KEY = :atlas_pca_regex_budget

    attr_accessor :evaluations, :chars, :steps, :refusals
    attr_reader :source

    class << self
      # An AMBIENT request-budget provider (a callable returning a RegexBudget or nil); every document budget opened with
      # no enclosing scope chains to it. nil uninstalls.
      attr_accessor :provider

      def request(source = nil)
        new(REGEX_REQUEST_SCALE, nil, false, source)
      end

      def current
        Thread.current[SCOPE_KEY]
      end

      def ambient
        cur = current
        return cur unless cur.nil?

        p = provider
        p.nil? ? nil : p.call
      rescue StandardError
        nil
      end
    end

    def initialize(scale = 1, parent = nil, is_document = true, source = nil)
      @scale = scale
      @parent = parent
      @is_document = is_document
      @source = source
      @evaluations = 0
      @chars = 0
      @steps = 0
      @refusals = 0
    end

    def document?
      @is_document
    end

    # The enclosing budget this one also charges (nil for a top-level budget).
    def parent_budget
      @parent
    end

    # Charge one evaluation of `src` against a subject of `subject_len` UTF-16 units; false = refused (do NOT match).
    def charge(src, subject_len)
      c = SafeRegex.compile_cached(src)
      if c.nil?
        @refusals += 1
        return false
      end
      ev = @evaluations + 1
      chars = @chars + SafeRegex.utf16_len(src)
      steps = @steps + (c.program.length * (subject_len + 1))
      k = @scale
      if ev > MAX_REGEX_EVALUATIONS_PER_DOCUMENT * k ||
         chars > MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT * k ||
         steps > MAX_REGEX_STEPS_PER_DOCUMENT * k ||
         (!@parent.nil? && !@parent.charge(src, subject_len))
        # Poison the budget so a later, cheaper pattern cannot sneak in after an over-budget one.
        @evaluations = (MAX_REGEX_EVALUATIONS_PER_DOCUMENT * k) + 1
        @refusals += 1
        return false
      end
      @evaluations = ev
      @chars = chars
      @steps = steps
      true
    end

    # Make this the open scope for the block (restores the previous scope afterwards).
    def run
      prev = Thread.current[SCOPE_KEY]
      Thread.current[SCOPE_KEY] = self
      begin
        yield
      ensure
        Thread.current[SCOPE_KEY] = prev
      end
    end
  end

  module_function

  # Install (or, with nil, uninstall) the ambient request-budget provider.
  def set_regex_budget_provider(fn)
    RegexBudget.provider = fn
  end

  # Run the block as ONE document: inside `budget` if given; else join an open document scope; else open a fresh document
  # budget chained to the enclosing request budget, if any.
  def with_regex_budget(budget = nil, &fn)
    return budget.run(&fn) unless budget.nil?

    cur = RegexBudget.current
    return fn.call if !cur.nil? && cur.document?

    RegexBudget.new(1, RegexBudget.ambient, true).run(&fn)
  end

  # The open scope's refusal count (0 outside a scope).
  def regex_refusals
    cur = RegexBudget.current
    cur.nil? ? 0 : cur.refusals
  end

  # Charge one regex evaluation to the open scope; false = over budget (the caller must NOT match). Outside any scope the
  # evaluation is charged to a fresh single-use budget.
  def charge_regex(src, subject_len)
    (RegexBudget.current || RegexBudget.new(1, RegexBudget.ambient, true)).charge(src, subject_len)
  end

  # Compile `src` into the linear-time engine's NFA (a SafeRegex::CompiledRegex), or nil when it is outside the supported
  # subset or too large. Never raises.
  def compile_safe_regex(src)
    SafeRegex.compile(src)
  end

  # `new RegExp('^(?:' + src + ')$').test(subject)` over the supported subset, in linear time: true / false, or nil when
  # `src` is outside the subset (or too large), `subject` is not a string, or the work budget is exceeded (the caller
  # fails closed). Never raises.
  def safe_regex_full_match(src, subject)
    return nil unless subject.is_a?(String)

    re = SafeRegex.compile_cached(src)
    return nil if re.nil?

    SafeRegex.run(re, subject)
  rescue StandardError
    nil
  end
end
