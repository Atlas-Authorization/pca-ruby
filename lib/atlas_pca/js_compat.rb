# frozen_string_literal: true

# JavaScript semantics the protocol bridges reproduce byte-for-byte: truthiness and JSON.stringify.
module AtlasPca
  module Js
    module_function

    # JS truthiness: nil / false / 0 / NaN / "" are falsy; an empty Array or Hash is truthy.
    def truthy?(v)
      return false if v.nil? || v == false
      return !(v.zero? || (v.is_a?(Float) && v.nan?)) if v.is_a?(Numeric)
      return !v.empty? if v.is_a?(String)

      true
    end

    def num?(x) = (x.is_a?(Integer) || x.is_a?(Float))
    def str_list?(x) = x.is_a?(Array) && x.all? { |s| s.is_a?(String) }

    # JSON.stringify (compact, the JS number form, the JS property order: integer-index keys ascending first, then
    # insertion order; nil members of a Hash are kept as null; a lone surrogate (WTF-8) is escaped as \udxxx).
    def json(v)
      case v
      when nil then 'null'
      when true then 'true'
      when false then 'false'
      when Integer, Float
        v.is_a?(Float) && (v.nan? || v.infinite?) ? 'null' : Predicates.js_number_string(v)
      when String, Symbol then json_string(v.to_s)
      when Array then "[#{v.map { |x| json(x) }.join(',')}]"
      when Hash then "{#{js_keys(v).map { |k| "#{json_string(k.to_s)}:#{json(v[k])}" }.join(',')}}"
      else raise TypeError, "JSON: unsupported #{v.class}"
      end
    end

    INDEX_KEY = /\A(?:0|[1-9][0-9]*)\z/

    # Own-property order of a JS object: array-index keys (< 2^32 - 1) ascending, then the rest in insertion order.
    def js_keys(h)
      idx, rest = h.keys.partition { |k| k.is_a?(String) && k.match?(INDEX_KEY) && k.to_i < 4_294_967_295 }
      idx.sort_by(&:to_i) + rest
    end

    def json_string(s)
      return AtlasPca.js_string(s) if s.valid_encoding?

      # WTF-8: each lone surrogate is the 3-byte form ED A0..BF xx
      s.b.split(/(\xED[\xA0-\xBF][\x80-\xBF])/n).map do |part|
        if part.match?(/\A\xED[\xA0-\xBF][\x80-\xBF]\z/n)
          b = part.bytes
          format('\\u%04x', ((b[0] & 0x0f) << 12) | ((b[1] & 0x3f) << 6) | (b[2] & 0x3f))
        else
          AtlasPca.js_string(part.force_encoding('UTF-8').scrub("�"))[1..-2]
        end
      end.join.then { |x| "\"#{x}\"" }
    end

    # TextEncoder#encode: UTF-8 bytes, every lone surrogate (WTF-8) replaced by U+FFFD. A binary String is returned as is.
    def utf8(s)
      return s if s.encoding == Encoding::BINARY

      s.valid_encoding? ? s.b : s.b.gsub(/\xED[\xA0-\xBF][\x80-\xBF]/n, "\xEF\xBF\xBD".b)
    end

    # String length in UTF-16 code units.
    def len16(s) = s.valid_encoding? ? s.each_char.sum { |c| c.ord > 0xffff ? 2 : 1 } : s.b.length - (s.b.scan(/\xED[\xA0-\xBF][\x80-\xBF]/n).length * 2)

    # JSON.parse with JS numbers: an integral Float in the safe range is an Integer (JS has one number type; -0 stays -0.0).
    # Raises AtlasPca::Malformed on invalid JSON.
    def parse(text) = ints(AtlasPca.parse_json_text(text))

    # The first duplicate object member of a JSON text at any depth (keys compared after unescaping, so "a" and "\u0061" collide), or nil.
    # Numbers and everything else stay as the sender wrote them. A text that is not valid JSON is not scanned meaningfully: parse it first.
    def duplicate_key(text)
      stack = []
      expect_key = false
      i = 0
      n = text.length
      while i < n
        c = text[i]
        case c
        when '"'
          j = i + 1
          j += text[j] == '\\' ? 2 : 1 while j < n && text[j] != '"'
          top = stack.last
          if expect_key && top.is_a?(Hash)
            key = AtlasPca.parse_json_text(text[i..j])
            return key if top.key?(key)

            top[key] = true
            expect_key = false
          end
          i = j
        when '{'
          stack.push({})
          expect_key = true
        when '['
          stack.push(nil)
          expect_key = false
        when '}', ']'
          stack.pop
          expect_key = false
        when ','
          expect_key = stack.last.is_a?(Hash)
        end
        i += 1
      end
      nil
    end

    # parse_json_text (numbers as written, a bare -0 stays negative zero) that refuses a duplicate member at any depth
    def parse_text_no_duplicates(text)
      v = AtlasPca.parse_json_text(text)
      k = duplicate_key(text)
      raise AtlasPca::Malformed, "duplicate key #{json(k)}" unless k.nil?

      v
    end

    # JSON.parse that refuses a duplicate member (message `duplicate key "k"`): for third-party JSON that was signed or digested as written.
    def parse_no_duplicates(text)
      v = parse(text)
      k = duplicate_key(text)
      raise AtlasPca::Malformed, "duplicate key #{json(k)}" unless k.nil?

      v
    end

    def ints(v)
      case v
      when Hash then v.transform_values { |x| ints(x) }
      when Array then v.map { |x| ints(x) }
      when Float then v.finite? && v == v.floor && v.abs <= MAX_SAFE && !(v.zero? && (1.0 / v).negative?) ? v.to_i : v
      else v
      end
    end
  end
end

module AtlasPca
  module Js
    module_function

    # encodeURIComponent (UTF-8 percent-encoding of everything outside A-Z a-z 0-9 - _ . ! ~ * ' ( )).
    def encode_uri_component(s)
      s = s.to_s
      raise ArgumentError, 'URI malformed' unless s.dup.force_encoding(Encoding::UTF_8).valid_encoding? # a lone surrogate (WTF-8) is the URIError

      s.encode('UTF-8').b.gsub(/[^A-Za-z0-9\-_.!~*'()]/n) { |c| format('%%%02X', c.ord) }.force_encoding('UTF-8')
    end

    # Array spread ([...x]): an Array is copied, a String splits into characters, anything else is not iterable.
    def spread(x)
      return x.dup if x.is_a?(Array)
      return x.chars if x.is_a?(String)

      raise TypeError, 'value is not iterable'
    end
  end
end

module AtlasPca
  module Js
    WS = "\t\n\v\f\r    -     　﻿"

    module_function

    # String(x) of a JSON value: null -> "null", an Array joins its elements' strings with "," (null -> ""), a Hash is
    # "[object Object]".
    def string(x)
      case x
      when nil then 'null'
      when String then x
      when Symbol then x.to_s
      when true, false then x.to_s
      when Integer, Float then Predicates.js_number_string(x)
      when Array then x.map { |e| e.nil? ? '' : string(e) }.join(',')
      else '[object Object]'
      end
    end

    # x.toLowerCase(): only a String has it (anything else throws, as a property call on a non-string does).
    def lower(x)
      raise TypeError, 'toLowerCase is not a function' unless x.is_a?(String)

      x.downcase
    end

    # BigInt(x): an integral Number, a boolean, or a String (JS-whitespace trimmed; "" is 0; decimal with an optional sign,
    # or 0x / 0o / 0b without one); anything else raises.
    def bigint(x)
      case x
      when Integer then x
      when Float
        raise RangeError, 'not an integer' unless x.finite? && x == x.floor

        x.to_i
      when true then 1
      when false then 0
      when String, Array
        t = string(x).gsub(/\A[#{WS}]+|[#{WS}]+\z/o, '')
        return 0 if t.empty?
        return t.to_i if t.match?(/\A[+-]?[0-9]+\z/)
        return t[2..].to_i(16) if t.match?(/\A0[xX][0-9a-fA-F]+\z/)
        return t[2..].to_i(8) if t.match?(/\A0[oO][0-7]+\z/)
        return t[2..].to_i(2) if t.match?(/\A0[bB][01]+\z/)

        raise ArgumentError, "Cannot convert #{t} to a BigInt"
      else raise TypeError, 'Cannot convert to a BigInt'
      end
    end

    def safe_integer?(x)
      (x.is_a?(Integer) && x.abs <= MAX_SAFE) || (x.is_a?(Float) && x.finite? && x == x.floor && x.abs <= MAX_SAFE)
    end

    def neg_zero?(x) = x.is_a?(Float) && x.zero? && (1.0 / x).negative?

    # o[k] with JS property-read semantics on a JSON value: nil (null / undefined) throws; a non-object has no members.
    def get(o, k)
      raise TypeError, "Cannot read properties of null (reading '#{k}')" if o.nil?

      o.is_a?(Hash) ? o[k] : nil
    end
  end
end

module AtlasPca
  module Js
    module_function

    # String#trim (JS WhiteSpace + LineTerminator; U+0085 and U+200B are not whitespace).
    def trim(s) = s.gsub(/\A[#{WS}]+|[#{WS}]+\z/o, '')

    # replayKey(namespace, ...parts): "<namespace>:" + b64u(sha256(u32be(len) || utf8 bytes, per part)).
    def replay_key(namespace, *parts)
      buf = [namespace, *parts].map do |p|
        raise TypeError, 'replayKey: every part must be a well-formed string (no lone surrogates)' unless p.is_a?(String) && p.valid_encoding?

        b = p.b
        [b.bytesize].pack('N') + b
      end.join
      "#{namespace}:#{AtlasPca.b64e(OpenSSL::Digest::SHA256.digest(buf))}"
    end
  end
end
