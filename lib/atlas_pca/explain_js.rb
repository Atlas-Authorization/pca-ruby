# frozen_string_literal: true

require_relative 'js_compat'
require_relative 'predicates'

# JavaScript value semantics over JSON values (Hash, Array, String, Integer/Float, true/false, nil, Predicates::UNDEF) shared by the
# explainer, the evidence bundle and the policy analyzer: property reads on any value, Number(x), relational comparison over
# UTF-16 code units, truthiness, Object.keys order. A hostile shape then yields the same text or the same refusal as the reference.
module AtlasPca
  module ExplainJs
    UNDEF = Predicates::UNDEF
    NAN = Float::NAN
    IDX = /\A(?:0|[1-9][0-9]*)\z/
    # JS \s: WhiteSpace + LineTerminator code points
    WS_UNITS = [0x9, 0xa, 0xb, 0xc, 0xd, 0x20, 0xa0, 0x1680, *(0x2000..0x200a), 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff].freeze
    WS_CLASS = "\\t\\n\\v\\f\\r    -     　﻿"

    module_function

    # ---- UTF-16 views --------------------------------------------------------------------------------------------------

    def units(s) = Predicates.units(s)
    def len16(s) = units(s).length

    # the String of a UTF-16 unit list (a lone surrogate becomes its WTF-8 3-byte form)
    def from_units(u)
      out = String.new(encoding: Encoding::BINARY)
      i = 0
      while i < u.length
        c = u[i]
        if c >= 0xd800 && c <= 0xdbff && i + 1 < u.length && u[i + 1] >= 0xdc00 && u[i + 1] <= 0xdfff
          out << [0x10000 + ((c - 0xd800) << 10) + (u[i + 1] - 0xdc00)].pack('U').b
          i += 2
        elsif c >= 0xd800 && c <= 0xdfff
          out << [0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)].pack('C*')
          i += 1
        else
          out << [c].pack('U').b
          i += 1
        end
      end
      out.force_encoding(Encoding::UTF_8)
    end

    def slice16(s, a, b = nil)
      u = units(s)
      from_units(u[a...(b.nil? ? u.length : b)] || [])
    end

    def u16key(s) = units(s).pack('n*')

    def trim(s)
      return Js.trim(s) if s.valid_encoding?

      u = units(s)
      u = u.drop_while { |c| WS_UNITS.include?(c) }
      u.pop while !u.empty? && WS_UNITS.include?(u.last)
      from_units(u)
    end

    # ---- types ---------------------------------------------------------------------------------------------------------

    def num?(v) = v.is_a?(Integer) || v.is_a?(Float)
    def fin?(v) = num?(v) && (v.is_a?(Integer) || v.finite?)
    def obj?(v) = v.is_a?(Hash) || v.is_a?(Array)
    def numstr(x) = Predicates.js_number_string(x.to_f)
    def jstr(v) = v.equal?(UNDEF) ? 'undefined' : Js.json(v)
    def js_string(v) = Predicates.js_string(v)

    def truthy?(v)
      return false if v.equal?(UNDEF) || v.nil? || v == false
      return true if v == true
      return !(v.zero? || (v.is_a?(Float) && v.nan?)) if num?(v)
      return !v.empty? if v.is_a?(String)

      true
    end

    # a ?? b
    def nn(a, b) = a.nil? || a.equal?(UNDEF) ? b : a

    # ---- property reads ------------------------------------------------------------------------------------------------

    # o[k] without throwing: UNDEF for an absent member or a value without members
    def get(o, k)
      case o
      when Hash then o.key?(k) ? o[k] : UNDEF
      when Array
        return o.length if k == 'length'

        k.match?(IDX) && k.to_i < o.length ? o[k.to_i] : UNDEF
      when String
        return len16(o) if k == 'length'

        k.match?(IDX) && k.to_i < len16(o) ? slice16(o, k.to_i, k.to_i + 1) : UNDEF
      else UNDEF
      end
    end

    def opt(o, k) = o.nil? || o.equal?(UNDEF) ? UNDEF : get(o, k)

    # o[k] where o must not be null or undefined
    def rd(o, k)
      raise TypeError, "cannot read '#{k}' of #{o.nil? ? 'null' : 'undefined'}" if o.nil? || o.equal?(UNDEF)

      get(o, k)
    end

    # Object.keys
    def keys(o)
      case o
      when Hash then Js.js_keys(o)
      when Array then (0...o.length).map(&:to_s)
      when String then (0...len16(o)).map(&:to_s)
      else []
      end
    end

    def put(h, k, v)
      h[k] = v unless v.equal?(UNDEF)
    end

    # a Hash member or UNDEF
    def hget(h, k) = h.key?(k) ? h[k] : UNDEF

    # ---- coercions and comparison --------------------------------------------------------------------------------------

    def str_to_num(s)
      t = trim(s)
      return 0.0 if t.empty?
      return Float::INFINITY if ['Infinity', '+Infinity'].include?(t)
      return -Float::INFINITY if t == '-Infinity'

      if t.match?(/\A0([xX][0-9a-fA-F]+|[bB][01]+|[oO][0-7]+)\z/)
        return t[2..].to_i({ 'x' => 16, 'b' => 2, 'o' => 8 }[t[1].downcase]).to_f
      end
      return NAN unless t.match?(/\A[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\z/)

      Float(t.sub(/\A([+-]?)\./) { "#{Regexp.last_match(1)}0." }.sub(/\.(?=[eE]|\z)/, '.0'))
    end

    # Number(v) for a JSON value (an object is NaN, an array goes through its string form)
    def to_num(v)
      return NAN if v.equal?(UNDEF)
      return 0.0 if v.nil?
      return (v ? 1.0 : 0.0) if v == true || v == false
      return v.to_f if num?(v)
      return str_to_num(v) if v.is_a?(String)
      return str_to_num(js_string(v)) if v.is_a?(Array)

      NAN
    end

    def prim(v)
      return js_string(v) if v.is_a?(Array)
      return '[object Object]' if v.is_a?(Hash)

      v
    end

    def lt(a, b)
      a = prim(a)
      b = prim(b)
      return (u16key(a) <=> u16key(b)) == -1 if a.is_a?(String) && b.is_a?(String)

      to_num(a) < to_num(b)
    end

    def le(a, b)
      a = prim(a)
      b = prim(b)
      return !((u16key(b) <=> u16key(a)) == -1) if a.is_a?(String) && b.is_a?(String)

      to_num(a) <= to_num(b)
    end

    def gt(a, b) = lt(b, a)

    # JS `a + n` for a number n: a string or array on the left makes it a concatenation
    def add(a, n)
      a = prim(a)
      a.is_a?(String) ? a + n.to_s : to_num(a) + n
    end

    # the values `for (const x of v)` visits: an array's items or a string's code points; anything else throws
    def iter(v)
      return v if v.is_a?(Array)
      return v.valid_encoding? ? v.chars : units(v).map { |c| from_units([c]) } if v.is_a?(String)

      raise TypeError, 'not iterable'
    end

    def slice_from(v, n)
      return v[n..] || [] if v.is_a?(Array)
      return slice16(v, n) if v.is_a?(String)

      raise TypeError, 'slice is not a function'
    end

    def pad_end(s, n) = s + (' ' * [0, n - len16(s)].max)
  end
end
