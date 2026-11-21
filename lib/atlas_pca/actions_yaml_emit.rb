# frozen_string_literal: true

# The YAML text the reference writes for an action pack (defsToYaml): a line-for-line port of the default stringifier of the `yaml`
# package (v2, core schema, 80 columns): plain, quoted and block scalars, folding, escapes, anchors and aliases for repeated containers.
#
# Strings are processed as UTF-16 code units because the reference measures and folds in code units: an astral character becomes
# two stand-in characters and a lone surrogate one (U+F0000 + (unit - 0xD800), as Siem::U16 does), and the result is recombined
# (a lone surrogate comes back as its WTF-8 bytes). Comments, tags, flow collections and custom schemas are not produced by the
# reference for plain data and are not ported.
require_relative 'siem'
require_relative 'predicates'

module AtlasPca
  module ActionsYamlEmit
    LINE_WIDTH = 80
    MIN_CONTENT_WIDTH = 20
    DQ_MIN_MULTILINE = 40
    INDENT_STEP = '  '
    END_NL = /(\A|(?<!\n))\n+(?!\n|\z)/
    PLAIN_BAD = /\A[\n\t ,\[\]{}#&*!|>'"%@`]|\A[?-]\z|\A[?-][ \t]|[\n:][ \t]|[ \t]\n|[\n\t ]#|[\n\t :]\z/
    CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/
    DOC_MARKER = /(?:\A|(?<=[\n\r  ]))(%|---|\.\.\.)/
    TAG_TESTS = [/\A(?:~|[Nn]ull|NULL)?\z/, /\A(?:[Tt]rue|TRUE|[Ff]alse|FALSE)\z/, /\A0o[0-7]+\z/, /\A[-+]?[0-9]+\z/, /\A0x[0-9a-fA-F]+\z/,
                 /\A(?:[-+]?\.(?:inf|Inf|INF)|\.nan|\.NaN|\.NAN)\z/, /\A[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)[eE][-+]?[0-9]+\z/,
                 /\A[-+]?(?:\.[0-9]+|[0-9]+\.[0-9]*)\z/].freeze
    ESC_MAP = { '0000' => '\\0', '0007' => '\\a', '000b' => '\\v', '001b' => '\\e', '0085' => '\\N', '00a0' => '\\_', '2028' => '\\L', '2029' => '\\P' }.freeze
    PUA = 0xF0000

    Ctx = Struct.new(:indent, :indent_at_start, :implicit_key, :actual_string, :force_block_indent, :anchors)
    Scalar = Struct.new(:value, :anchor)
    Seq = Struct.new(:items, :anchor)
    Map = Struct.new(:pairs, :anchor)
    Alias = Struct.new(:source)

    module_function

    # ---- UTF-16 code unit domain
    def surrogate_pua?(c) = c >= PUA && c <= PUA + 0x7FF
    def hi?(ch) = !ch.empty? && surrogate_pua?(ch.ord) && ch.ord - PUA < 0x400
    def lo?(ch) = !ch.empty? && surrogate_pua?(ch.ord) && ch.ord - PUA >= 0x400
    def unit_char(u) = [u >= 0xD800 && u <= 0xDFFF ? PUA + (u - 0xD800) : u].pack('U')

    def to_units(raw)
      Siem::U16.to_pua(raw).each_codepoint.map do |c|
        if c > 0xFFFF && !surrogate_pua?(c)
          v = c - 0x10000
          unit_char(0xD800 + (v >> 10)) + unit_char(0xDC00 + (v & 0x3FF))
        else
          [c].pack('U')
        end
      end.join
    end

    def from_units(s)
      out = ''.b
      cps = s.codepoints
      i = 0
      while i < cps.length
        c = cps[i]
        if surrogate_pua?(c)
          u = 0xD800 + (c - PUA)
          if u <= 0xDBFF && i + 1 < cps.length && surrogate_pua?(cps[i + 1]) && cps[i + 1] - PUA >= 0x400
            out << [0x10000 + ((u - 0xD800) << 10) + (cps[i + 1] - PUA - 0x400)].pack('U').b
            i += 2
            next
          end
          out << [0xE0 | (u >> 12), 0x80 | ((u >> 6) & 0x3f), 0x80 | (u & 0x3f)].pack('C*')
        else
          out << [c].pack('U').b
        end
        i += 1
      end
      out.force_encoding(Encoding::UTF_8)
    end

    # JSON.stringify of a string in the code unit domain (well-formed: lone surrogates are escaped)
    def json_string(s)
      chars = s.chars
      out = +'"'
      chars.each_with_index do |c, i|
        o = c.ord
        out << if c == '"' then '\\"'
               elsif c == '\\' then '\\\\'
               elsif c == "\b" then '\\b'
               elsif c == "\f" then '\\f'
               elsif c == "\n" then '\\n'
               elsif c == "\r" then '\\r'
               elsif c == "\t" then '\\t'
               elsif o < 0x20 then format('\\u%04x', o)
               elsif hi?(c) && i + 1 < chars.length && lo?(chars[i + 1]) then c
               elsif lo?(c) && i.positive? && hi?(chars[i - 1]) then c
               elsif surrogate_pua?(o) then format('\\u%04x', 0xD800 + (o - PUA))
               else c
               end
      end
      "#{out}\""
    end

    def at(s, i) = i >= 0 && i < s.length ? s[i] : ''
    def sl(s, a, b) = s[a...b] || ''

    # ---- folding
    def consume_more_indented(text, i, indent)
      end_ = i
      start = i + 1
      ch = at(text, start)
      while ch == ' ' || ch == "\t"
        if i < start + indent
          i += 1
          ch = at(text, i)
        else
          loop do
            i += 1
            ch = at(text, i)
            break if ch.empty? || ch == "\n"
          end
          end_ = i
          start = i + 1
          ch = at(text, start)
        end
      end
      end_
    end

    def fold(text, indent, mode, indent_at_start, on_overflow = nil)
      line_width = LINE_WIDTH
      min_content = MIN_CONTENT_WIDTH
      min_content = 0 if min_content > line_width
      end_step = [1 + min_content, 1 + line_width - indent.length].max
      return text if text.length <= end_step

      folds = []
      escaped = {}
      end_ = line_width - indent.length
      unless indent_at_start.nil?
        if indent_at_start > line_width - [2, min_content].max
          folds << 0
        else
          end_ = line_width - indent_at_start
        end
      end
      split = nil
      prev = ''
      overflow = false
      i = -1
      esc_start = esc_end = -1
      if mode == 'block'
        i = consume_more_indented(text, i, indent.length)
        end_ = i + end_step if i != -1
      end
      loop do
        i += 1
        ch = at(text, i)
        break if ch.empty?

        if mode == 'quoted' && ch == '\\'
          esc_start = i
          nxt = at(text, i + 1)
          i += nxt == 'x' ? 3 : nxt == 'u' ? 5 : nxt == 'U' ? 9 : 1
          esc_end = i
        end
        if ch == "\n"
          i = consume_more_indented(text, i, indent.length) if mode == 'block'
          end_ = i + indent.length + end_step
          split = nil
        else
          if ch == ' ' && !prev.empty? && !" \n\t".include?(prev)
            nxt = at(text, i + 1)
            split = i if !nxt.empty? && !" \n\t".include?(nxt)
          end
          if i >= end_
            if !split.nil?
              folds << split
              end_ = split + end_step
              split = nil
            elsif mode == 'quoted'
              while prev == ' ' || prev == "\t"
                prev = ch
                i += 1
                ch = at(text, i)
                overflow = true
              end
              j = i > esc_end + 1 ? i - 2 : esc_start - 1
              return text if escaped[j]

              folds << j
              escaped[j] = true
              end_ = j + end_step
              split = nil
            else
              overflow = true
            end
          end
        end
        prev = ch
      end
      on_overflow&.call if overflow
      return text if folds.empty?

      res = sl(text, 0, folds[0])
      folds.each_with_index do |fold_at, k|
        nxt_fold = k + 1 < folds.length ? folds[k + 1] : 0
        stop = nxt_fold.zero? ? text.length : nxt_fold
        if fold_at.zero?
          res = "\n#{indent}#{sl(text, 0, stop)}"
        else
          res += "#{fold_at >= 0 && fold_at < text.length ? text[fold_at] : ''}\\" if mode == 'quoted' && escaped[fold_at]
          res += "\n#{indent}#{sl(text, fold_at + 1, stop)}"
        end
      end
      res
    end

    # ---- context
    def doc_marker?(s) = DOC_MARKER.match?(s)
    def fold_opts(ctx, is_block) = is_block ? ctx.indent.length : ctx.indent_at_start

    def line_len_over?(s, line_width, indent_len)
      return false if line_width.nil? || line_width.zero? || line_width.negative?

      limit = line_width - indent_len
      n = s.length
      return false if n <= limit

      start = 0
      n.times do |i|
        next unless s[i] == "\n"
        return true if i - start > limit

        start = i + 1
        return false if n - start <= limit
      end
      true
    end

    # ---- strings
    def double_quoted(value, ctx)
      js = json_string(value)
      implicit = ctx.implicit_key
      indent = ctx.indent.empty? ? (doc_marker?(value) ? '  ' : '') : ctx.indent
      out = +''
      start = 0
      i = 0
      n = js.length
      while i < n
        ch = js[i]
        if ch == ' ' && at(js, i + 1) == '\\' && at(js, i + 2) == 'n'
          out << sl(js, start, i) << '\\ '
          i += 1
          start = i
          ch = '\\'
        end
        if ch == '\\'
          nx = at(js, i + 1)
          if nx == 'u'
            out << sl(js, start, i)
            code = sl(js, i + 2, i + 6)
            if ESC_MAP.key?(code) then out << ESC_MAP[code]
            elsif code[0, 2] == '00' then out << "\\x#{code[2..]}"
            else out << sl(js, i, i + 6)
            end
            i += 5
            start = i + 1
          elsif nx == 'n'
            if implicit || at(js, i + 2) == '"' || js.length < DQ_MIN_MULTILINE
              i += 1
            else
              out << sl(js, start, i) << "\n\n"
              while at(js, i + 2) == '\\' && at(js, i + 3) == 'n' && at(js, i + 4) != '"'
                out << "\n"
                i += 2
              end
              out << indent
              out << '\\' if at(js, i + 2) == ' '
              i += 1
              start = i + 1
            end
          else
            i += 1
          end
        end
        i += 1
      end
      out = start.zero? ? js : out + (js[start..] || '')
      implicit ? out : fold(out, indent, 'quoted', fold_opts(ctx, false))
    end

    def single_quoted(value, ctx)
      return double_quoted(value, ctx) if (ctx.implicit_key && value.include?("\n")) || value.match?(/[ \t]\n|\n[ \t]/)

      indent = ctx.indent.empty? ? (doc_marker?(value) ? '  ' : '') : ctx.indent
      res = "'#{value.gsub("'", "''").gsub(/\n+/) { "#{Regexp.last_match(0)}\n#{indent}" }}'"
      ctx.implicit_key ? res : fold(res, indent, 'flow', fold_opts(ctx, false))
    end

    def quoted(value, ctx)
      has_d = value.include?('"')
      has_s = value.include?("'")
      return single_quoted(value, ctx) if has_d && !has_s

      double_quoted(value, ctx) # a lone single quote, both or neither: double (the default)
    end

    def block_string(value, ctx)
      return quoted(value, ctx) if value.match?(/\n[\t ]+\z/)

      indent = ctx.indent.empty? ? (ctx.force_block_indent || doc_marker?(value) ? '  ' : '') : ctx.indent
      literal = !line_len_over?(value, LINE_WIDTH, indent.length)
      return literal ? "|\n" : ">\n" if value.empty?

      end_start = value.length
      end_start -= 1 while end_start.positive? && "\n\t ".include?(value[end_start - 1])
      end_ = value[end_start..]
      nl = end_.index("\n")
      chomp = if nl.nil? then '-'
              elsif value == end_ || nl != end_.length - 1 then '+'
              else ''
              end
      unless end_.empty?
        value = value[0...-end_.length]
        end_ = end_[0...-1] if end_[-1] == "\n"
        end_ = end_.gsub(END_NL) { "#{Regexp.last_match(0)}#{indent}" }
      end
      start_with_space = false
      start_end = 0
      start_nl = -1
      while start_end < value.length
        ch = value[start_end]
        if ch == ' ' then start_with_space = true
        elsif ch == "\n" then start_nl = start_end
        else break
        end
        start_end += 1
      end
      start = sl(value, 0, start_nl < start_end ? start_nl + 1 : start_end)
      unless start.empty?
        value = value[start.length..] || ''
        start = start.gsub(/\n+/) { "#{Regexp.last_match(0)}#{indent}" }
      end
      header = start_with_space ? (indent.empty? ? '1' : '2') : ''
      header += chomp
      unless literal
        folded = value.gsub(/\n+/) { "\n#{Regexp.last_match(0)}" }
        folded = folded.gsub(/(?:\A|\n)([\t ][^\n\r  ]*)(?:([\n\t ]*)\n(?![\n\t ]))?/) { "#{Regexp.last_match(1)}#{Regexp.last_match(2)}" }
        folded = folded.gsub(/\n+/) { "#{Regexp.last_match(0)}#{indent}" }
        fell = false
        body = fold(start + folded + end_, indent, 'block', ctx.indent.length, -> { fell = true })
        return ">#{header}\n#{indent}#{body}" unless fell
      end
      value = value.gsub(/\n+/) { "#{Regexp.last_match(0)}#{indent}" }
      "|#{header}\n#{indent}#{start}#{value}#{end_}"
    end

    def plain(value, ctx)
      return quoted(value, ctx) if ctx.implicit_key && value.include?("\n")
      return (ctx.implicit_key || !value.include?("\n") ? quoted(value, ctx) : block_string(value, ctx)) if PLAIN_BAD.match?(value)
      return block_string(value, ctx) if !ctx.implicit_key && value.include?("\n")

      if doc_marker?(value)
        if ctx.indent.empty?
          ctx.force_block_indent = true
          return block_string(value, ctx)
        end
        return quoted(value, ctx) if ctx.implicit_key && ctx.indent == INDENT_STEP
      end
      s = value.gsub(/\n+/) { "#{Regexp.last_match(0)}\n#{ctx.indent}" }
      return quoted(value, ctx) if ctx.actual_string && TAG_TESTS.any? { |t| t.match?(s) }

      ctx.implicit_key ? s : fold(s, ctx.indent, 'flow', fold_opts(ctx, false))
    end

    def string(raw, ctx)
      lone = Siem::U16.to_pua(raw).each_codepoint.any? { |c| surrogate_pua?(c) } # a surrogate in the input is never half of a pair
      value = to_units(raw)
      return double_quoted(value, ctx) if lone || CONTROL.match?(value)

      plain(value, ctx)
    end

    def number(v)
      f = v.to_f
      return f.nan? ? '.nan' : f.negative? ? '-.inf' : '.inf' unless f.finite?
      return '-0' if f.zero? && (1.0 / f).negative?

      AtlasPca::Predicates.js_number_string(f)
    end

    # ---- nodes
    # createNode with aliasDuplicateObjects: a container met twice becomes an anchor (named a1, a2, ... in the order the repeats are
    # met) on its first occurrence and an alias on every later one; cycles are allowed.
    class Builder
      def initialize
        @seen = {}
        @keep = []
        @n = 0
        @alias_sources = []
      end

      def node(v)
        if v.is_a?(Hash) || v.is_a?(Array)
          ref = @seen[v.object_id]
          unless ref.nil?
            if ref[0].nil?
              @n += 1
              ref[0] = "a#{@n}"
            end
            return Alias.new(ref[0])
          end
          ref = [nil, nil]
          @seen[v.object_id] = ref
          @keep << v
          if v.is_a?(Hash)
            m = Map.new([], nil)
            ref[1] = m
            v.each do |k, x|
              raise TypeError, 'a mapping key must be a string' unless k.is_a?(String)

              m.pairs << [Scalar.new(k, nil), node(x)]
            end
            @alias_sources << ref
            return m
          end
          s = Seq.new([], nil)
          ref[1] = s
          v.each { |x| s.items << node(x) }
          @alias_sources << ref
          return s
        end
        return Scalar.new(v, nil) if v.nil? || v == true || v == false || v.is_a?(String) || v.is_a?(Integer) || v.is_a?(Float)

        raise TypeError, "cannot write a #{v.class} as YAML"
      end

      def finish
        @alias_sources.each { |ref| ref[1].anchor = ref[0] unless ref[0].nil? }
      end
    end

    def coll?(n) = n.is_a?(Seq) || n.is_a?(Map)

    def stringify_node(item, ctx)
      if item.is_a?(Alias)
        raise ArgumentError, "Unresolved alias (the anchor must be set before the alias): #{item.source}" unless ctx.anchors.include?(item.source)

        return ctx.implicit_key ? "*#{item.source} " : "*#{item.source}"
      end
      props = ''
      if item.anchor
        ctx.anchors << item.anchor
        props = "&#{item.anchor}"
        ctx.indent_at_start = (ctx.indent_at_start || 0) + props.length + 1
      end
      s = if item.is_a?(Scalar)
            v = item.value
            if v.is_a?(String)
              c = ctx.dup
              c.actual_string = true
              string(v, c)
            elsif v.nil? then 'null'
            elsif v == true then 'true'
            elsif v == false then 'false'
            else number(v)
            end
          elsif item.is_a?(Seq)
            ictx = item_ctx(ctx, "#{ctx.indent}  ") # one context for every item, as the reference shares it
            block(ctx, item.items.map { |x| "- #{stringify_node(x, ictx)}" }, '[', ']')
          else
            ictx = item_ctx(ctx, ctx.indent)
            block(ctx, item.pairs.map { |k, v| pair(k, v, ictx) }, '{', '}')
          end
      return s if props.empty?

      item.is_a?(Scalar) || '{['.include?(s[0]) ? "#{props} #{s}" : "#{props}\n#{ctx.indent}#{s}"
    end

    def item_ctx(ctx, indent)
      c = ctx.dup
      c.indent = indent
      c
    end

    def block(ctx, lines, start, end_)
      return start + end_ if lines.empty?

      out = +lines[0]
      lines[1..].each { |line| out << (line.empty? ? "\n" : "\n#{ctx.indent}#{line}") }
      out
    end

    def pair(key, value, ctx)
      indent = ctx.indent
      ctx = ctx.dup
      ctx.implicit_key = true
      ctx.indent = indent + INDENT_STEP
      s = stringify_node(key, ctx)
      explicit = s.length > 1024
      s = explicit ? "? #{s}\n#{indent}:" : "#{s}:"
      ctx.implicit_key = false
      ctx.indent_at_start = s.length + 1 if !explicit && value.is_a?(Scalar)
      vs = stringify_node(value, ctx)
      ws = ' '
      if !explicit && coll?(value)
        nl0 = vs.index("\n")
        has_nl = !nl0.nil?
        flow = (value.is_a?(Seq) ? value.items.length : value.pairs.length).zero?
        if has_nl || !flow
          props_line = false
          if has_nl && '&!'.include?(vs[0])
            sp0 = vs.index(' ')
            if vs[0] == '&' && !sp0.nil? && sp0 < nl0 && at(vs, sp0 + 1) == '!'
              sp0 = vs.index(' ', sp0 + 1)
            end
            props_line = true if sp0.nil? || nl0 < sp0
          end
          ws = "\n#{ctx.indent}" unless props_line
        end
      elsif vs.empty? || vs[0] == "\n"
        ws = ''
      end
      s + ws + vs
    end

    # The YAML text of plain data (Hash / Array / String / true / false / Integer / Float / nil); repeated containers become anchors
    # and aliases.
    def stringify(value)
      b = Builder.new
      root = b.node(value)
      b.finish
      ctx = Ctx.new('', nil, false, false, false, Set.new)
      "#{from_units(stringify_node(root, ctx))}\n"
    end

    # `ns: <ns>` and `actions: [...]` as YAML; a def whose verb has an own entry in `rules` gets it re-attached as its `rules` member.
    def defs_to_yaml(ns, defs, rules = nil)
      rules ||= {}
      stringify({ 'ns' => ns, 'actions' => defs.map { |d| rules.key?(d['verb']) ? d.merge('rules' => rules[d['verb']]) : d } })
    end
  end
end
