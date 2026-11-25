# frozen_string_literal: true

# JavaScript-semantics helpers for the policy analyzer (the TypeScript reference is @atlasauth/pca-analyzer).
#
# Inputs are JSON trees as the JSON readers yield them. A missing member is UNDEF (JavaScript `undefined`), nil is `null`; UNDEF never
# appears in a result (`uobj` drops it).
require_relative '../atlas_pca'

module AtlasPca
  module AnalyzerJs
    UNDEF = Predicates::UNDEF
    NUMLIT = /\A(?:[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|[+-]?Infinity)\z/
    TRIM_CHARS = " \t\n\r\f\v   ﻿"

    module_function

    def arr?(x) = x.is_a?(Array)
    def obj?(x) = x.is_a?(Hash) || x.is_a?(Array)
    def num?(x) = x.is_a?(Integer) || x.is_a?(Float)
    def jsnum(x) = x.is_a?(Integer) ? x.to_f : x
    def js_str(x) = Predicates.js_string(x)
    def num_str(x) = Predicates.js_number_string(x)
    def undef?(x) = x.equal?(UNDEF)

    # `o[k]`: undefined for an absent member or a non-object; reading a member of null / undefined throws, as in JavaScript.
    def jget(o, k)
      raise TypeError, "cannot read properties of #{o.nil? ? 'null' : 'undefined'} (reading '#{k}')" if o.nil? || o.equal?(UNDEF)

      o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF
    end

    # `o?.k`
    def oget(o, k) = o.nil? || o.equal?(UNDEF) ? UNDEF : jget(o, k)

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

    # Sort key giving JavaScript's default string order (UTF-16 code units).
    def u16key(s)
      s = s.dup.force_encoding(Encoding::UTF_8)
      return s.encode(Encoding::UTF_16BE).b if s.valid_encoding?

      # lone surrogates (WTF-8): decode by hand
      s.b.scan(/[\x00-\x7f]|[\xc0-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xf7][\x80-\xbf]{3}|./n).flat_map do |ch|
        b = ch.bytes
        c = case b.length
            when 1 then b[0] >= 0x80 ? 0xfffd : b[0]
            when 2 then ((b[0] & 0x1f) << 6) | (b[1] & 0x3f)
            when 3 then ((b[0] & 0x0f) << 12) | ((b[1] & 0x3f) << 6) | (b[2] & 0x3f)
            else ((b[0] & 0x07) << 18) | ((b[1] & 0x3f) << 12) | ((b[2] & 0x3f) << 6) | (b[3] & 0x3f)
            end
        c > 0xffff ? [0xd800 + ((c - 0x10000) >> 10), 0xdc00 + ((c - 0x10000) & 0x3ff)] : [c]
      end.pack('n*')
    end

    def has?(o, k) = o.is_a?(Hash) && o.key?(k)

    # An own member of a plain object, else `default` (never throws).
    def own(o, k, default = UNDEF) = o.is_a?(Hash) && o.key?(k) ? o[k] : default

    # `v ?? default`
    def nn(v, default) = v.nil? || v.equal?(UNDEF) ? default : v

    # `typeof v === 'number' && Number.isFinite(v)`: the binary64 value, else nil.
    def fin(v)
      return nil unless num?(v)

      f = jsnum(v)
      f.finite? ? f : nil
    end

    def fin?(v) = !fin(v).nil?

    def truthy?(v)
      return false if v.nil? || v.equal?(UNDEF) || v == false
      return true if v == true
      return !v.empty? if v.is_a?(String)
      return jsnum(v) != 0 && !jsnum(v).nan? if num?(v)

      true
    end

    # `a === b` over JSON values (objects by identity).
    def strict_eq(a, b)
      return a.equal?(b) if a.equal?(UNDEF) || b.equal?(UNDEF)
      return a.nil? && b.nil? if a.nil? || b.nil?
      return (a == true || a == false) && (b == true || b == false) && a == b if a == true || a == false || b == true || b == false
      return num?(a) && num?(b) && jsnum(a) == jsnum(b) if num?(a) || num?(b)
      return a == b if a.is_a?(String) && b.is_a?(String)

      a.equal?(b)
    end

    # `xs.includes(x)`; a non-array has no `includes` and throws.
    def includes?(xs, x)
      req_list(xs)
      xs.any? { |e| strict_eq(e, x) }
    end

    def req_list(x)
      raise TypeError, 'not an array' unless x.is_a?(Array)

      x
    end

    # `Number(v)` for a JSON value.
    def to_number(v)
      return 0.0 if v.nil?
      return Float::NAN if v.equal?(UNDEF)
      return (v ? 1.0 : 0.0) if v == true || v == false
      return jsnum(v) if num?(v)

      if v.is_a?(String)
        t = v.gsub(/\A[#{TRIM_CHARS}]+|[#{TRIM_CHARS}]+\z/, '')
        return 0.0 if t.empty?
        return Float::NAN unless t.match?(NUMLIT)

        return t.include?('Infinity') ? (t.start_with?('-') ? -Float::INFINITY : Float::INFINITY) : t.to_f
      end
      return v.empty? ? 0.0 : (v.length == 1 ? to_number(v[0]) : Float::NAN) if v.is_a?(Array)

      Float::NAN
    end

    def js_gt(a, b)
      return (a <=> b) == 1 if a.is_a?(String) && b.is_a?(String)

      to_number(a) > to_number(b)
    end

    def js_le(a, b)
      return (a <=> b) <= 0 if a.is_a?(String) && b.is_a?(String)

      to_number(a) <= to_number(b)
    end

    def js_lt(a, b)
      return (a <=> b) == -1 if a.is_a?(String) && b.is_a?(String)

      to_number(a) < to_number(b)
    end

    # JavaScript own-key order: array-index keys ascending, then insertion order.
    def key_order(m) = Js.js_keys(m)

    # `JSON.stringify(v)` of a JSON tree (undefined members dropped, -0 as 0, own-key order).
    def js_json(v)
      case v
      when nil then 'null'
      when true then 'true'
      when false then 'false'
      when String then Js.json_string(v)
      when Integer, Float
        f = jsnum(v)
        f.finite? ? Predicates.js_number_string(f) : 'null'
      when Array then "[#{v.map { |x| x.equal?(UNDEF) ? 'null' : js_json(x) }.join(',')}]"
      when Hash then "{#{key_order(v).reject { |k| v[k].equal?(UNDEF) }.map { |k| "#{Js.json_string(k)}:#{js_json(v[k])}" }.join(',')}}"
      else 'null'
      end
    end

    # An object literal: members whose value is undefined are absent.
    def uobj(d) = d.reject { |_, v| v.equal?(UNDEF) }

    # `{...o}` (nullish spreads nothing; a string or array spreads its indices).
    def spread(o)
      case o
      when Hash then o.dup
      when Array then o.each_with_index.to_h { |x, i| [i.to_s, x] }
      when String
        # one member per UTF-16 code unit (an astral character is two lone surrogates)
        s = o.dup.force_encoding(Encoding::UTF_8)
        s = s.scrub('?') unless s.valid_encoding?
        s.codepoints.flat_map { |c| c > 0xffff ? [0xd800 + ((c - 0x10000) >> 10), 0xdc00 + ((c - 0x10000) & 0x3ff)] : [c] }
         .each_with_index.to_h { |u, i| [i.to_s, [u].pack('U').force_encoding(Encoding::UTF_8)] }
      else {}
      end
    end
  end
end
