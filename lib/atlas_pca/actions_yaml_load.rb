# frozen_string_literal: true

# YAML text for the authoring-file loader (loadActionsText). The syntax layer is Psych's libyaml scanner and parser; only its EVENT
# stream is used (Psych resolves scalars as YAML 1.1, so none of its own resolution, merge-key or alias handling is used). Everything
# the reference decides about meaning is done here: the tree is built from events, plain scalars are resolved with the YAML 1.2 core
# schema (null, bool, int, 0o / 0x, float, .inf, .nan; everything else a string), mapping keys are stringified the way JavaScript
# does, aliases are refused, `<<` is an ordinary key, and positions are the 1-based start of each action and each param key.
#
# Where this differs from the reference it is STRICTER (it refuses): an explicit tag other than !!str / !!map / !!seq, a complex
# (non-scalar) mapping key, two keys that are equal once stringified (the reference keeps the last of 1 and "1"), a bare carriage
# return used as a line break, more than one document. Syntax error wording and line/column of a syntax error are the parser's own.
require 'psych'
require_relative 'predicates'

module AtlasPca
  module ActionsYamlLoad
    STR = 'tag:yaml.org,2002:str'
    OK_TAGS = [STR, 'tag:yaml.org,2002:map', 'tag:yaml.org,2002:seq'].freeze
    INT_RE = /\A[-+]?[0-9]+\z/
    OCT_RE = /\A0o[0-7]+\z/
    HEX_RE = /\A0x[0-9a-fA-F]+\z/
    FLOAT_RE = /\A[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?\z/
    INF_RE = /\A[-+]?\.(?:inf|Inf|INF)\z/
    NAN_RE = /\A\.(?:nan|NaN|NAN)\z/
    SAFE = 2**53

    class YamlError < StandardError
      attr_reader :line, :column

      def initialize(message, line = 1, column = 1)
        super(message)
        @line = line
        @column = column
      end
    end

    # A parsed node: kind :scalar | :map | :seq, its resolved value, children and 1-based start position.
    Node = Struct.new(:kind, :line, :col, :value, :items)
    Ev = Struct.new(:kind, :tag, :value, :style, :line, :col)

    # records the libyaml events with their start marks
    class Recorder < Psych::Handler
      attr_reader :events

      def initialize
        super
        @events = []
        @loc = [1, 1]
      end

      def event_location(start_line, start_column, _end_line, _end_column) = @loc = [start_line + 1, start_column + 1]
      def start_document(*) = add(:doc_start)
      def end_document(*) = add(:doc_end)
      def alias(_anchor) = add(:alias)
      def scalar(value, _anchor, tag, _plain, _quoted, style) = add(:scalar, tag, value, style)
      def start_sequence(_anchor, tag, _implicit, _style) = add(:seq_start, tag)
      def end_sequence = add(:seq_end)
      def start_mapping(_anchor, tag, _implicit, _style) = add(:map_start, tag)
      def end_mapping = add(:map_end)

      private

      def add(kind, tag = nil, value = nil, style = nil) = @events << Ev.new(kind, tag, value, style, @loc[0], @loc[1])
    end

    module_function

    def js_int(text, radix = 10)
      neg = text.start_with?('-')
      n = radix == 10 ? text.sub(/\A[+-]/, '').to_i(10) : text.to_i(radix)
      return -0.0 if neg && n.zero?

      n = -n if neg
      n.abs <= SAFE ? n : n.to_f
    end

    # The YAML 1.2 core schema value of a plain scalar, as a JavaScript number / boolean / null / string.
    def resolve_core_plain(text)
      return nil if ['', '~', 'null', 'Null', 'NULL'].include?(text)
      return true if %w[true True TRUE].include?(text)
      return false if %w[false False FALSE].include?(text)
      return js_int(text) if INT_RE.match?(text)
      return js_int(text[2..], 8) if OCT_RE.match?(text)
      return js_int(text[2..], 16) if HEX_RE.match?(text)
      return text[0] == '-' ? -Float::INFINITY : Float::INFINITY if INF_RE.match?(text)
      return Float::NAN if NAN_RE.match?(text)

      if FLOAT_RE.match?(text)
        f = text.to_f
        return f.to_i if f.finite? && f == f.floor && f.abs <= SAFE && !(f.zero? && text.sub(/\A\++/, '').start_with?('-'))

        return f
      end
      text
    end

    def js_key(v)
      return 'null' if v.nil?
      return v.to_s if v == true || v == false
      return AtlasPca::Predicates.js_number_string(v.to_f) if v.is_a?(Numeric)

      v
    end

    # The one document of `text` as a node tree (nil for an empty stream). `strict` (YAML files) refuses duplicate keys; JSON text is
    # parsed leniently because only its positions are used.
    def parse_document(text, strict = true)
      raise YamlError, 'bare carriage return is not accepted as a line break' if text.match?(/\r(?!\n)/)

      text = text.delete_prefix("\uFEFF") # a byte order mark is not content
      rec = Recorder.new
      begin
        Psych::Parser.new(rec).parse(text)
      rescue Psych::SyntaxError => e
        raise YamlError.new(e.problem || e.message.lines.first.to_s.strip, e.line || 1, e.column || 1)
      end
      events = rec.events
      pos = 0
      docs = 0
      node = nil
      node = lambda do
        ev = events[pos]
        pos += 1
        raise YamlError.new('Alias resolution is disabled', ev.line, ev.col) if ev.kind == :alias

        tag = ev.tag
        if !tag.nil? && !OK_TAGS.include?(tag)
          raise YamlError.new("Unresolved or unsupported tag: #{tag}", ev.line, ev.col)
        end
        case ev.kind
        when :scalar
          n = Node.new(:scalar, ev.line, ev.col, nil, [])
          plain = ev.style == Psych::Nodes::Scalar::PLAIN && tag.nil?
          n.value = plain ? resolve_core_plain(ev.value) : ev.value
          n
        when :seq_start
          n = Node.new(:seq, ev.line, ev.col, nil, [])
          until events[pos].kind == :seq_end
            n.items << node.call
          end
          pos += 1
          n
        when :map_start
          n = Node.new(:map, ev.line, ev.col, nil, [])
          seen = {}
          until events[pos].kind == :map_end
            key = node.call
            val = node.call
            if strict
              raise YamlError.new('complex mapping keys are not accepted', key.line, key.col) unless key.kind == :scalar

              s = js_key(key.value)
              raise YamlError.new('Map keys must be unique', key.line, key.col) if seen.key?(s)

              seen[s] = true
            end
            n.items << [key, val]
          end
          pos += 1
          n
        else
          raise YamlError.new("unexpected parser event #{ev.kind}", ev.line, ev.col)
        end
      end
      root = nil
      while pos < events.length
        if events[pos].kind == :doc_start
          docs += 1
          raise YamlError, 'Source contains multiple documents; please use YAML.parseAllDocuments()' if docs > 1

          pos += 1
          root = node.call unless events[pos].kind == :doc_end
        else
          pos += 1
        end
      end
      root
    end

    def to_value(n)
      return nil if n.nil?
      return n.value if n.kind == :scalar
      return n.items.map { |x| to_value(x) } if n.kind == :seq

      n.items.each_with_object({}) do |(k, v), out|
        raise YamlError.new('complex mapping keys are not accepted', k.line, k.col) unless k.kind == :scalar

        out[js_key(k.value)] = to_value(v)
      end
    end

    # Per-entry positions of an authoring document (`actions` items and their `params` keys), by entry index; nil when not a mapping.
    def positions_of(root)
      return nil if root.nil? || root.kind != :map

      actions = nil
      root.items.each { |k, v| actions = v if k.kind == :scalar && k.value == 'actions' }
      items = !actions.nil? && actions.kind == :seq ? actions.items : [root]
      items.map do |it|
        params = {}
        if it.kind == :map
          pm = nil
          it.items.each { |k, v| pm = v if k.kind == :scalar && k.value == 'params' }
          if !pm.nil? && pm.kind == :map
            pm.items.each { |k, _| params[k.value.nil? ? '' : js_key(k.value)] = { 'line' => k.line, 'column' => k.col } if k.kind == :scalar }
          end
        end
        { 'item' => { 'line' => it.line, 'column' => it.col }, 'params' => params }
      end
    end

    def attach_positions(res, pos)
      failed = res['errors'].filter_map { |e| e['index'] }.to_set
      order = (0...pos.length).reject { |i| failed.include?(i) }
      res['defs'].each_with_index do |d, k|
        p = k < order.length ? pos[order[k]] : nil
        res['locs'][d['verb']] = p['item'].merge('params' => p['params']) if p
      end
      res['errors'].each do |e|
        idx = e['index']
        p = !idx.nil? && idx >= 0 && idx < pos.length ? pos[idx] : nil
        if p
          e['line'] = p['item']['line']
          e['column'] = p['item']['column']
        elsif idx.nil?
          e['line'] = 1
          e['column'] = 1
        end
      end
    end
  end
end
