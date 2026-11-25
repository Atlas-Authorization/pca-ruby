# frozen_string_literal: true

require_relative 'js_compat'
require_relative 'predicates'

module AtlasPca
  # JavaScript value semantics the goal package reproduces over JSON trees (Hash, Array, String, Integer / Float, true / false,
  # nil = null, UNDEF = undefined): property reads, truthiness, ===, Number(x), relational comparison, UTF-16 key order.
  module GoalJs
    UNDEF = Predicates::UNDEF
    WS = "\t\n\v\f\r    -     　﻿"
    NUMLIT = /\A(?:[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|[+-]?Infinity)\z/

    module_function

    def undef?(v) = v.equal?(UNDEF)

    # `o[k]`: undefined for an absent member or a non-object; a member of null / undefined throws, as in JavaScript.
    def jget(o, k)
      raise TypeError, "cannot read properties of #{o.nil? ? 'null' : 'undefined'} (reading '#{k}')" if o.nil? || undef?(o)

      Predicates.get(o, k)
    end

    # `o?.k`
    def oget(o, k) = o.nil? || undef?(o) ? UNDEF : jget(o, k)

    def truthy(v) = !undef?(v) && Js.truthy?(v)
    def js_str(v) = Predicates.js_string(v)

    def req_list(x)
      raise TypeError, 'not an array' unless x.is_a?(Array)

      x
    end

    # Sort key giving JavaScript's default string order (UTF-16 code units).
    def u16key(s) = Predicates.units(s).pack('n*')

    def strict_eq(a, b)
      return a.equal?(b) if undef?(a) || undef?(b) || a.nil? || b.nil?
      return [true, false].include?(a) && [true, false].include?(b) && a == b if [true, false].include?(a) || [true, false].include?(b)
      return Js.num?(a) && Js.num?(b) && Predicates.jsnum(a).to_f == Predicates.jsnum(b).to_f if Js.num?(a) || Js.num?(b)
      return a == b if a.is_a?(String) && b.is_a?(String)

      a.equal?(b)
    end

    def includes(xs, x) = req_list(xs).any? { |e| strict_eq(e, x) }

    # `Number(v)` for a JSON value.
    def to_number(v)
      return 0.0 if v.nil?
      return Float::NAN if undef?(v)
      return (v ? 1.0 : 0.0) if [true, false].include?(v)
      return Predicates.jsnum(v).to_f if Js.num?(v)

      if v.is_a?(String)
        t = v.gsub(/\A[#{WS}]+|[#{WS}]+\z/o, '')
        return 0.0 if t.empty?

        return Float::NAN unless NUMLIT.match?(t)
        return t.start_with?('-') ? -Float::INFINITY : Float::INFINITY if t.end_with?('Infinity')

        return Float(t.sub(/\.(?=[eE]|\z)/, ''))
      end
      return v.empty? ? 0.0 : (v.length == 1 ? to_number(v[0]) : Float::NAN) if v.is_a?(Array)

      Float::NAN
    end

    def js_gt(a, b)
      return (Predicates.units(a) <=> Predicates.units(b)) > 0 if a.is_a?(String) && b.is_a?(String)

      to_number(a) > to_number(b)
    end

    def js_lt(a, b)
      return (Predicates.units(a) <=> Predicates.units(b)) < 0 if a.is_a?(String) && b.is_a?(String)

      to_number(a) < to_number(b)
    end

    # Object.keys(o): a Hash's keys, an Array's / String's indices, nothing for other primitives; null / undefined throws.
    def okeys(o)
      raise TypeError, 'cannot convert undefined or null to object' if o.nil? || undef?(o)

      case o
      when Hash then o.keys
      when Array then o.each_index.map(&:to_s)
      when String then Predicates.units(o).each_index.map(&:to_s)
      else []
      end
    end

    # `o[k]` for a key of Object.keys(o).
    def kget(o, k)
      case o
      when Hash then o.key?(k) ? o[k] : UNDEF
      when Array then o[Integer(k, 10)]
      when String then [Predicates.units(o)[Integer(k, 10)]].pack('U')
      else UNDEF
      end
    end

    # The String of a UTF-16 unit list (a lone surrogate becomes its WTF-8 3-byte form).
    def from_units(u)
      out = String.new(encoding: Encoding::BINARY)
      i = 0
      while i < u.length
        c = u[i]
        if c.between?(0xD800, 0xDBFF) && i + 1 < u.length && u[i + 1].between?(0xDC00, 0xDFFF)
          out << [0x10000 + ((c - 0xD800) << 10) + (u[i + 1] - 0xDC00)].pack('U').b
          i += 2
        elsif c.between?(0xD800, 0xDFFF)
          out << [0xE0 | (c >> 12), 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F)].pack('C*')
          i += 1
        else
          out << [c].pack('U').b
          i += 1
        end
      end
      out.force_encoding(Encoding::UTF_8)
    end

    # The text as one BMP character per UTF-16 unit (a surrogate unit is shifted into the private use area), so character indices
    # and regexes act as JavaScript's do on UTF-16 strings; `from_u16s` undoes it.
    def u16s(s) = Predicates.units(s).map { |u| [u.between?(0xD800, 0xDFFF) ? u + 0x800 : u].pack('U') }.join

    def from_u16s(m) = from_units(m.codepoints.map { |c| c.between?(0xE000, 0xE7FF) ? c - 0x800 : c })

    # String#toLowerCase (a lone surrogate is unchanged).
    def lower(s)
      return s.downcase if s.valid_encoding?

      s.b.split(/(\xED[\xA0-\xBF][\x80-\xBF])/n).map { |part| part.match?(/\A\xED[\xA0-\xBF][\x80-\xBF]\z/n) ? part : part.dup.force_encoding('UTF-8').downcase.b }.join.force_encoding('UTF-8')
    end

    # `x.toFixed(digits)`: exact decimal expansion of the double, ties away from zero.
    def to_fixed(x, digits = 2)
      return 'NaN' if x.is_a?(Float) && x.nan?
      return (x.positive? ? 'Infinity' : '-Infinity') if x.is_a?(Float) && x.infinite?

      scaled = Rational(x) * (10**digits)
      n = (scaled.abs + Rational(1, 2)).floor
      neg = scaled.negative? || (x.is_a?(Float) && x.zero? && (1.0 / x).negative?)
      s = n.to_s.rjust(digits + 1, '0')
      body = digits.zero? ? s : "#{s[0...-digits]}.#{s[-digits..]}"
      neg ? "-#{body}" : body
    end

    # a stable sort (Ruby's sort_by is not)
    def stable_sort(xs)
      xs.each_with_index.sort { |(a, i), (b, j)| (c = yield(a, b)).zero? ? i <=> j : c }.map(&:first)
    end

    def stable_sort_by(xs) = xs.each_with_index.sort_by { |x, i| [yield(x), i] }.map(&:first)
  end
end
