# frozen_string_literal: true

require 'digest'
require_relative 'js_compat'

# Prime-order group layer of the homomorphic risk accumulator, matching the TypeScript reference (@atlasauth/pca-ratchet):
# ristretto255 (RFC 9496) on libsodium (constant time, vetted), the Pedersen generators G and H, scalar helpers and the
# Fiat-Shamir transcript hash. A point is its canonical 32-byte ristretto255 encoding (a binary String, so two equal group
# elements are two equal Strings); a scalar is an Integer in [0, L). libsodium is bound lazily and the module
# fails closed (LoadError) when it is missing: install libsodium (apt: libsodium-dev, brew: libsodium).
module AtlasPca
  module RatchetGroup
    # libsodium is bound on first use, so loading the gem never needs it; a missing library fails closed (LoadError) at that point.
    module Sodium
      # the libsodium bundled in the platform gem first, then the system's
      LIBS = (Dir.glob(File.join(__dir__, 'native', 'libsodium.{so,dylib,dll}')) + %w[sodium libsodium.so.26 libsodium.so.23 libsodium.dylib libsodium-26.dll libsodium.dll]).freeze
      FUNCS = {
        crypto_core_ristretto255_from_hash: [%i[buffer_out buffer_in], :int],
        crypto_core_ristretto255_is_valid_point: [[:buffer_in], :int],
        crypto_core_ristretto255_add: [%i[buffer_out buffer_in buffer_in], :int],
        crypto_core_ristretto255_sub: [%i[buffer_out buffer_in buffer_in], :int],
        crypto_core_ristretto255_scalar_random: [[:buffer_out], :void],
        crypto_core_ristretto255_scalar_reduce: [%i[buffer_out buffer_in], :void],
        crypto_core_ristretto255_scalar_add: [%i[buffer_out buffer_in buffer_in], :void],
        crypto_core_ristretto255_scalar_sub: [%i[buffer_out buffer_in buffer_in], :void],
        crypto_core_ristretto255_scalar_mul: [%i[buffer_out buffer_in buffer_in], :void],
        crypto_core_ristretto255_scalar_invert: [%i[buffer_out buffer_in], :int],
        crypto_core_ristretto255_scalar_negate: [%i[buffer_out buffer_in], :void],
        crypto_scalarmult_ristretto255: [%i[buffer_out buffer_in buffer_in], :int],
        crypto_scalarmult_ristretto255_base: [%i[buffer_out buffer_in], :int]
      }.freeze
      LOCK = Mutex.new
      @bound = false

      def self.bind!
        return if @bound

        LOCK.synchronize do
          return if @bound

          begin
            require 'ffi'
          rescue LoadError => e
            raise LoadError, "ristretto255 needs the ffi gem and libsodium (#{e.message})"
          end
          lib = Module.new
          lib.extend(FFI::Library)
          begin
            lib.ffi_lib(LIBS)
          rescue LoadError => e
            raise LoadError, "ristretto255 needs libsodium (apt: libsodium-dev, brew: libsodium): #{e.message}"
          end
          lib.attach_function(:sodium_init, [], :int)
          raise LoadError, 'libsodium could not be initialised' if lib.sodium_init.negative?

          FUNCS.each { |name, (args, ret)| lib.attach_function(name, args, ret) }
          @lib = lib
          @bound = true
        end
      end

      def self.method_missing(name, *args)
        return super unless FUNCS.key?(name)

        bind!
        @lib.public_send(name, *args)
      end

      def self.respond_to_missing?(name, priv = false) = FUNCS.key?(name) || super
    end

    L = (1 << 252) + 27_742_317_777_372_353_535_851_937_790_883_648_493
    ZERO = ("\0".b * 32).freeze

    module_function

    def le(bytes) = bytes.b.reverse.unpack1('H*').to_i(16)

    def le_bytes(n, len)
      raise ArgumentError, 'number_to_bytes_le: negative' if n.negative?
      raise RangeError, 'number_to_bytes_le: does not fit' if n.bit_length > len * 8

      [n.to_s(16).rjust(len * 2, '0')].pack('H*').reverse
    end

    def buf(len = 32) = "\0".b * len

    def sc(k) = le_bytes(k % L, 32)

    # A fixed Pedersen generator pair: G is the ristretto255 base point, H a nothing-up-my-sleeve point (RFC 9496 one-way map).
    def hash_to_curve(b)
      raise ArgumentError, 'hash_to_curve: need 64 bytes' unless b.bytesize == 64

      out = buf
      Sodium.crypto_core_ristretto255_from_hash(out, b.b)
      out.freeze
    end

    # G (the ristretto255 base point) and H (a nothing-up-my-sleeve point, RFC 9496 one-way map) are built on first use.
    def self.const_missing(name)
      case name
      when :G
        out = buf
        raise 'ristretto255 base point unavailable' unless Sodium.crypto_scalarmult_ristretto255_base(out, sc(1)).zero?

        const_set(:G, out.freeze)
      when :H then const_set(:H, hash_to_curve(Digest::SHA512.digest('atlas-pca-ratchet/pedersen-generator-H/v1')))
      else super
      end
    end

    # RFC 9496: bit 255 must be clear; libsodium 1.0.18 (the Ubuntu package) ignores it, so it is checked here
    def valid?(pt) = pt.is_a?(String) && pt.bytesize == 32 && pt.getbyte(31) < 0x80 && Sodium.crypto_core_ristretto255_is_valid_point(pt.b) == 1

    def check(pt)
      raise ArgumentError, 'ristretto255: invalid encoding' unless valid?(pt)

      pt.b
    end

    def mod(x) = x % L
    def scalar_add(a, b) = scalar_op(:crypto_core_ristretto255_scalar_add, a, b)
    def scalar_sub(a, b) = scalar_op(:crypto_core_ristretto255_scalar_sub, a, b)
    def scalar_mul(a, b) = scalar_op(:crypto_core_ristretto255_scalar_mul, a, b)

    def scalar_op(fn, a, b)
      out = buf
      Sodium.public_send(fn, out, sc(a), sc(b))
      le(out)
    end

    def scalar_negate(a)
      out = buf
      Sodium.crypto_core_ristretto255_scalar_negate(out, sc(a))
      le(out)
    end

    def scalar_invert(a)
      out = buf
      raise ArgumentError, 'scalar_invert: zero' unless Sodium.crypto_core_ristretto255_scalar_invert(out, sc(a)).zero?

      le(out)
    end

    def mul(pt, k)
      p = check(pt)
      s = k % L
      return ZERO if s.zero? || p == ZERO

      out = buf
      raise ArgumentError, 'ristretto255: scalar multiplication failed' unless Sodium.crypto_scalarmult_ristretto255(out, sc(s), p).zero?

      out
    end

    def add(a, b)
      out = buf
      raise ArgumentError, 'ristretto255: invalid point' unless Sodium.crypto_core_ristretto255_add(out, check(a), check(b)).zero?

      out
    end

    def sub(a, b)
      out = buf
      raise ArgumentError, 'ristretto255: invalid point' unless Sodium.crypto_core_ristretto255_sub(out, check(a), check(b)).zero?

      out
    end

    # Encodings are canonical, so equality is byte equality.
    def equals(a, b) = check(a) == check(b)

    def rand_scalar
      loop do
        out = buf
        Sodium.crypto_core_ristretto255_scalar_random(out)
        s = le(out)
        return s unless s.zero?
      end
    end

    def to_raw_bytes(pt) = check(pt)
    def encode_point(pt) = AtlasPca.b64e(check(pt))

    def decode_point(s)
      raw = s.is_a?(String) ? AtlasPca.b64d(s, 32) : nil
      raise ArgumentError, 'decode_point: not a canonical 32-byte base64url string' if raw.nil?

      check(raw)
    end

    def encode_scalar(k) = AtlasPca.b64e(le_bytes(k % L, 32))

    # Strict: canonical base64url, exactly 32 bytes, value < L (a reduced scalar would make every proof malleable).
    def decode_scalar(s)
      raw = s.is_a?(String) ? AtlasPca.b64d(s, 32) : nil
      raise ArgumentError, 'decode_scalar: not a canonical 32-byte base64url string' if raw.nil?

      v = le(raw)
      raise ArgumentError, 'decode_scalar: non-canonical scalar (>= L)' if v >= L

      v
    end

    # Length-prefixed (4-byte big-endian) transcript, SHA-512, reduced mod L.
    def hash_to_scalar(parts)
      buffer = parts.map { |p| [p.bytesize].pack('N') + p.b }.join.b
      out = buf
      Sodium.crypto_core_ristretto255_scalar_reduce(out, Digest::SHA512.digest(buffer))
      le(out)
    end

    def utf8(s) = s.b
  end
end
