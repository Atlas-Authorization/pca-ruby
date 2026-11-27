# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require_relative 'js_compat'
require_relative 'attest'

# Shared helpers of the EAT attestation modules: JavaScript-faithful property access, string coercion, the constant-time
# compare and the clock, so the port refuses and words its reasons as the TypeScript reference (@atlasauth/pca-attest-eat)
# does on hostile JSON input. JSON null is nil; JavaScript `undefined` is the sentinel U.
module AtlasPca
  module AttestEat
    # JavaScript `undefined`, kept apart from JSON null (nil).
    U = Object.new.tap do |u|
      def u.inspect = 'undefined'
      def u.to_s = 'undefined'
    end.freeze

    module_function

    # `o.k`: the member, U when absent or when `o` has no members; a TypeError on null / undefined (as JS).
    def g(o, k)
      raise TypeError, "Cannot read properties of #{o.nil? ? 'null' : 'undefined'} (reading '#{k}')" if o.nil? || o.equal?(U)

      o.is_a?(Hash) ? o.fetch(k, U) : U
    end

    # `o.k !== undefined` (an explicit null counts as defined).
    def has?(o, k) = !g(o, k).equal?(U)

    def number?(v) = v.is_a?(Integer) || v.is_a?(Float)
    def finite?(v) = number?(v) && !(v.is_a?(Float) && (v.nan? || v.infinite?))
    def record?(v) = v.is_a?(Hash)

    # JS truthiness over a JSON value (U is falsy).
    def truthy?(v) = !v.equal?(U) && Js.truthy?(v)

    # String(v).
    def js_string(v) = v.equal?(U) ? 'undefined' : Js.string(v)

    # Length-checked constant-time equality over UTF-8 (a non-string throws, as Buffer.from(undefined) does).
    def ct_eq(a, b)
      raise TypeError, 'the first argument must be of type string' unless a.is_a?(String) && b.is_a?(String)

      x = Js.utf8(a)
      y = Js.utf8(b)
      x.bytesize == y.bytesize && OpenSSL.fixed_length_secure_compare(x, y)
    end

    def now_ms = (Time.now.to_f * 1000).floor

    # a === b for JSON values (no boolean / number mixing; containers by identity).
    def strict_eq?(a, b)
      return a == b if a.is_a?(String) && b.is_a?(String)
      return a == b if number?(a) && number?(b)

      a.equal?(b)
    end

    # Array.prototype.includes (SameValueZero) over a list.
    def includes?(seq, v) = seq.any? { |x| strict_eq?(x, v) }

    def msg_of(e) = e.message.empty? ? 'unknown' : e.message

    # A byte buffer (a Uint8Array), as opposed to a text String.
    def bytes?(v) = v.is_a?(String) && v.encoding == Encoding::BINARY

    def u8(s) = Js.utf8(s)
  end
end
