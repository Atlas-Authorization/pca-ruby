# frozen_string_literal: true

require 'digest'
require_relative 'mpc'
require_relative 'frost'

module AtlasPca
  module Mpc
    # A small prime-order group for the base oblivious transfer: Ed25519 (twisted Edwards, q = 2^255 - 19) in its prime-order
    # subgroup (order L). The group law (add, subtract, scalar multiplication, subgroup test) is libsodium's Ed25519 core, called
    # through the ffi loader of Frost::Sodium on the compressed encoding; nothing of it is written out here. What remains in Integer
    # is only the public coordinate codec (affine normalisation, RFC 8032 x-recovery) and the on-curve predicate, which touch no
    # secret. Every point received across the OT trust boundary is validated (on curve, non-identity, [L]P = O).
    module Ec
      Q = (1 << 255) - 19
      L = (1 << 252) + 27_742_317_777_372_353_535_851_937_790_883_648_493

      # a curve point in extended coordinates (X:Y:Z:T): x = X/Z, y = Y/Z, T = XY/Z
      Point = Struct.new(:x, :y, :z, :t)

      # raised when a received point fails on-curve / subgroup / identity validation
      class PointValidationError < StandardError; end

      module_function

      def mod_q(v) = v % Q
      def inv_q(a) = mod_q(a).pow(Q - 2, Q)
      def pow_q(b, e) = mod_q(b).pow(e, Q)

      D = (-121_665 * (121_666.pow(Q - 2, Q))) % Q
      SQRT_M1 = 2.pow((Q - 1) >> 2, Q)

      def from_affine(x, y)
        x = mod_q(x)
        y = mod_q(y)
        Point.new(x, y, 1, mod_q(x * y))
      end

      IDENTITY = Point.new(0, 1, 1, 0).freeze
      BASE = from_affine(15_112_221_349_535_400_772_501_151_409_588_531_511_454_012_693_041_857_206_046_113_283_949_847_762_202,
                         46_316_835_694_926_478_169_428_394_003_475_163_141_307_993_866_256_225_615_783_033_603_165_251_855_960).freeze

      def le32(s) = Array.new(32) { |i| (s >> (8 * i)) & 0xFF }.pack('C*')

      def binary(sub, p1, p2)
        r = "\0".b * 32
        a = compress_point(p1)
        b = compress_point(p2)
        rc = if sub then Frost::Sodium.crypto_core_ed25519_sub(r, a, b) else Frost::Sodium.crypto_core_ed25519_add(r, a, b) end
        raise PointValidationError, 'point is not on the curve' unless rc.zero?

        decompress_point(r)
      end

      # public group addition P + Q (complete on the subgroup)
      def add_points(p1, p2) = binary(false, p1, p2)
      def sub(p1, p2) = binary(true, p1, p2)
      def dbl(p) = add_points(p, p)
      def neg(p) = sub(IDENTITY, p)

      # [k]P with k reduced mod L (k = 0 or P = identity is the identity). P must lie in the prime-order subgroup (libsodium refuses torsion).
      def mul(k, p)
        s = k % L
        return IDENTITY if s.zero? || identity?(p)

        r = "\0".b * 32
        raise PointValidationError, 'scalar multiplication refused: point not in the prime-order subgroup' unless Frost::Sodium.crypto_scalarmult_ed25519_noclamp(r, le32(s), compress_point(p)).zero?

        decompress_point(r)
      end

      def mul_base(k)
        s = k % L
        return IDENTITY if s.zero?

        r = "\0".b * 32
        raise 'ed25519 base multiplication failed' unless Frost::Sodium.crypto_scalarmult_ed25519_base_noclamp(r, le32(s)).zero?

        decompress_point(r)
      end

      # affine [x, y] of a point (identity is [0, 1])
      def to_affine(p)
        zinv = inv_q(p.z)
        [mod_q(p.x * zinv), mod_q(p.y * zinv)]
      end

      def equal(a, b) = mod_q(a.x * b.z) == mod_q(b.x * a.z) && mod_q(a.y * b.z) == mod_q(b.y * a.z)

      def fe_bytes(a) = le32(mod_q(a))

      # canonical 64-byte affine encoding x || y (little-endian field elements), the OT key-derivation input
      def encode_point(p)
        x, y = to_affine(p)
        fe_bytes(x) + fe_bytes(y)
      end

      # canonical 32-byte compressed encoding (little-endian y, sign of x in bit 255)
      def compress_point(p)
        x, y = to_affine(p)
        out = fe_bytes(y)
        out.setbyte(31, out.getbyte(31) | ((x & 1) << 7))
        out
      end

      # decodes a canonical compressed encoding (RFC 8032 5.1.3 x-recovery)
      def decompress_point(bytes)
        raise PointValidationError, 'decompressPoint: expected 32 bytes' unless bytes.is_a?(String) && bytes.bytesize == 32

        sign = (bytes.getbyte(31) >> 7) & 1
        y = bytes.b.unpack('C*').each_with_index.sum { |v, i| v << (8 * i) } & ((1 << 255) - 1)
        raise PointValidationError, 'decompressPoint: non-canonical y (>= q)' if y >= Q

        y2 = mod_q(y * y)
        u = mod_q(y2 - 1)
        v = mod_q(D * y2 + 1)
        v3 = mod_q(v * v * v)
        v7 = mod_q(v3 * v3 * v)
        x = mod_q(u * v3 * pow_q(u * v7, (Q - 5) >> 3))
        vx2 = mod_q(v * x * x)
        if vx2 == mod_q(u)
          nil # x is correct as-is
        elsif vx2 == mod_q(-u)
          x = mod_q(x * SQRT_M1)
        else
          raise PointValidationError, 'decompressPoint: not on curve'
        end
        raise PointValidationError, 'decompressPoint: non-canonical sign' if x.zero? && sign == 1

        x = mod_q(Q - x) if (x & 1) != sign
        from_affine(x, y)
      end

      # whether the extended coordinates lie on the curve (projectively, no inversion)
      def on_curve?(p)
        return false if mod_q(p.z).zero?
        return false unless mod_q(p.t * p.z) == mod_q(p.x * p.y)

        x2 = mod_q(p.x * p.x)
        y2 = mod_q(p.y * p.y)
        z2 = mod_q(p.z * p.z)
        mod_q((y2 - x2) * z2) == mod_q(z2 * z2 + mod_q(D * x2) * y2)
      end

      def identity?(p) = equal(p, IDENTITY)

      # the cofactor check [L]P = O (true for the identity too)
      def prime_order?(p)
        return false unless on_curve?(p)

        return true if identity?(p)

        b = compress_point(p)
        # the group law decides: libsodium 1.0.20 and older accept a mixed-order point through is_valid_point
        Frost.safe_point?(b) && Frost::Sodium.crypto_core_ed25519_is_valid_point(b) == 1
      end

      # a valid non-identity point of the prime-order subgroup
      def in_subgroup?(p) = on_curve?(p) && !identity?(p) && prime_order?(p)

      def assert_in_subgroup(p, label = 'point')
        raise PointValidationError, "#{label}: not on curve" unless on_curve?(p)
        raise PointValidationError, "#{label}: identity element (forbidden here)" if identity?(p)
        raise PointValidationError, "#{label}: not in the prime-order subgroup (small-order/cofactor)" unless prime_order?(p)

        true
      end

      # Fiat-Shamir Schnorr proof of knowledge of y with S = y*B: commitment U = r*B and z = r + e*y
      SchnorrProof = Struct.new(:u, :z)
      TAG_SCHNORR = 'atlas-pca-mpc/schnorr-dlog'.b.freeze

      def schnorr_challenge(s, u, ctx)
        h = Digest::SHA512.digest(TAG_SCHNORR + [ctx.bytesize].pack('N') + ctx.b + encode_point(BASE) + encode_point(s) + encode_point(u))
        h.unpack1('H*').to_i(16) % L
      end

      # rnd is a callable returning a scalar
      def schnorr_prove(y, s, rnd, ctx)
        raise ArgumentError, 'schnorrProve: a non-empty session binding is required' if ctx.nil? || ctx.empty?

        r = rnd.call % L
        raise 'schnorrProve: nonce source returned 0 (RNG failure); refusing to produce a proof' if r.zero?

        u = mul_base(r)
        e = schnorr_challenge(s, u, ctx)
        SchnorrProof.new(u, (r + e * (y % L)) % L)
      end

      def schnorr_verify(s, proof, ctx)
        return false if ctx.nil? || ctx.empty?
        return false if proof.z.negative? || proof.z >= L
        return false unless in_subgroup?(proof.u)

        e = schnorr_challenge(s, proof.u, ctx)
        equal(mul_base(proof.z), add_points(proof.u, mul(e, s)))
      rescue PointValidationError
        false
      end
    end
  end
end
