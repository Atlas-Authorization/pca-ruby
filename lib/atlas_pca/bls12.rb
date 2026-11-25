# frozen_string_literal: true

require 'digest'

module AtlasPca
  # Thin helpers over supranational blst (through ffi) shared by the pairing packages (bbs, abe): points as G1 / G2 objects,
  # scalar arithmetic mod r on Integer, RFC 9380 expand_message_xmd (SHA-256), strict canonical decoders and the GT group (a small
  # shim over blst's public API, native/pca_gt.c). No pairing, field or curve arithmetic is implemented here.
  #
  # The library is bound lazily; a missing one raises LoadError (never a "bad input" result). Point it at the shared library with
  # PCA_BLST_LIB (blst built together with the shim: see the pairing workflow), or put libblst on the loader path.
  #
  # shortcut: scalar-field add/mul/inverse is Integer arithmetic, which is not constant time. Point multiplication (the expensive,
  # key-dependent part) is blst's constant-time implementation; upgrade to blst's scalar functions if a deployment needs the scalar
  # steps constant time as well.
  module Bls12
    R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

    # name => [argument types, return type]
    FUNCS = {
      blst_scalar_from_bendian: [%i[pointer buffer_in], :void],
      blst_p1_mult: [%i[pointer pointer pointer size_t], :void],
      blst_p1_add_or_double: [%i[pointer pointer pointer], :void],
      blst_p1_cneg: [%i[pointer bool], :void],
      blst_p1_compress: [%i[pointer pointer], :void],
      blst_p1_uncompress: [%i[pointer buffer_in], :int],
      blst_p1_from_affine: [%i[pointer pointer], :void],
      blst_p1_to_affine: [%i[pointer pointer], :void],
      blst_p1_is_inf: [[:pointer], :bool],
      blst_p1_affine_in_g1: [[:pointer], :bool],
      blst_p1_affine_on_curve: [[:pointer], :bool],
      blst_hash_to_g1: [%i[pointer buffer_in size_t buffer_in size_t pointer size_t], :void],
      blst_p1_generator: [[], :pointer],
      blst_p2_mult: [%i[pointer pointer pointer size_t], :void],
      blst_p2_add_or_double: [%i[pointer pointer pointer], :void],
      blst_p2_cneg: [%i[pointer bool], :void],
      blst_p2_compress: [%i[pointer pointer], :void],
      blst_p2_uncompress: [%i[pointer buffer_in], :int],
      blst_p2_from_affine: [%i[pointer pointer], :void],
      blst_p2_to_affine: [%i[pointer pointer], :void],
      blst_p2_is_inf: [[:pointer], :bool],
      blst_p2_affine_in_g2: [[:pointer], :bool],
      blst_p2_affine_on_curve: [[:pointer], :bool],
      blst_p2_generator: [[], :pointer],
      blst_miller_loop: [%i[pointer pointer pointer], :void],
      blst_fp12_finalverify: [%i[pointer pointer], :bool]
    }.freeze
    # the GT shim (native/pca_gt.c), present only in a library built with it
    GT_FUNCS = {
      pca_gt_mul: [%i[pointer buffer_in buffer_in], :int],
      pca_gt_pow: [%i[pointer buffer_in buffer_in], :int],
      pca_gt_is_element: [[:buffer_in], :int],
      pca_gt_pairing: [%i[pointer buffer_in buffer_in size_t], :int]
    }.freeze
    LIBS = [*ENV['PCA_BLST_LIB'], *Dir.glob(File.join(__dir__, 'native', '{libblst.so,libblst.dylib,blst.dll}')), *%w[blst libblst.so libblst.dylib blst.dll]].freeze
    LOCK = Mutex.new
    @lib = nil

    module_function

    def lib
      return @lib if @lib

      LOCK.synchronize do
        @lib ||= begin
          begin
            require 'ffi'
          rescue LoadError => e
            raise LoadError, "BLS12-381 needs the ffi gem and libblst (#{e.message})"
          end
          m = Module.new
          m.extend(FFI::Library)
          begin
            m.ffi_lib(LIBS)
          rescue LoadError => e
            raise LoadError, "BLS12-381 needs a built libblst (supranational/blst; abe also needs the GT shim, set PCA_BLST_LIB): #{e.message}"
          end
          FUNCS.each { |name, (args, ret)| m.attach_function(name, args, ret) }
          m
        end
      end
    end

    def gt_lib
      l = lib
      LOCK.synchronize do
        unless @gt_bound
          begin
            GT_FUNCS.each { |name, (args, ret)| l.attach_function(name, args, ret) }
          rescue FFI::NotFoundError => e
            raise LoadError, "abe needs the GT shim (native/pca_gt.c) built into the library: #{e.message}"
          end
          @gt_bound = true
        end
      end
      l
    end

    def mem(n) = (lib && FFI::MemoryPointer.new(:uint8, n))

    def mod(x) = x % R
    def add(a, b) = (a + b) % R
    def sub(a, b) = (a - b) % R
    def mul(a, b) = (a * b) % R

    # Fermat inverse x^(r-2) mod r (fixed public exponent); raises on zero
    def inv(x)
      v = x % R
      raise ZeroDivisionError, 'inverse of zero' if v.zero?

      v.pow(R - 2, R)
    end

    # I2OSP: non-negative integer to fixed-length big-endian octets; raises when it does not fit
    def i2osp(n, len)
      raise ArgumentError, "integer does not fit #{len} octets" if n.negative? || n.bit_length > 8 * len

      [format("%0#{2 * len}x", n)].pack('H*')
    end

    def os2ip(bytes) = bytes.unpack1('H*').to_i(16)

    # expand_message_xmd with SHA-256 (RFC 9380 5.3.1); the DST must be at most 255 octets
    def expand_message_xmd(msg, dst, len)
      msg = msg.b
      dst = dst.b
      ell = (len + 31) / 32
      raise ArgumentError, 'expand_message_xmd: invalid length or DST' if ell > 255 || len > 65_535 || dst.bytesize > 255 || len.negative?

      dst_prime = dst + [dst.bytesize].pack('C')
      b0 = Digest::SHA256.digest(("\0".b * 64) + msg + [len].pack('n') + "\0".b + dst_prime)
      bi = Digest::SHA256.digest(b0 + "\x01".b + dst_prime)
      out = bi.dup
      (2..ell).each do |i|
        x = b0.bytes.zip(bi.bytes).map { |a, b| a ^ b }.pack('C*')
        bi = Digest::SHA256.digest(x + [i].pack('C') + dst_prime)
        out << bi
      end
      out.byteslice(0, len)
    end

    # blst_scalar (32 bytes) for a value in [0, r)
    def scalar(s)
      p = mem(32)
      lib.blst_scalar_from_bendian(p, i2osp(s % R, 32))
      p
    end

    # A point in G1 or G2 (a blst Jacobian point). Immutable: every operation returns a new point.
    class Point
      attr_reader :ptr

      def initialize(ptr = nil) = @ptr = ptr || Bls12.mem(self.class::SIZE)

      def self.call(name, *args) = Bls12.lib.public_send(:"blst_#{self::TAG}_#{name}", *args)

      def +(other)
        out = self.class.new
        self.class.call(:add_or_double, out.ptr, ptr, other.ptr)
        out
      end

      def -@
        out = dup_point
        self.class.call(:cneg, out.ptr, true)
        out
      end

      def -(other) = self + -other

      # k * P, the identity when k is zero mod r
      def *(k)
        v = k % R
        return self.class.new if v.zero?

        out = self.class.new
        self.class.call(:mult, out.ptr, ptr, Bls12.scalar(v), 255)
        out
      end

      def dup_point
        out = self.class.new
        out.ptr.put_bytes(0, ptr.read_bytes(self.class::SIZE))
        out
      end

      def inf? = self.class.call(:is_inf, ptr)

      def compress
        out = Bls12.mem(self.class::COMPRESSED)
        self.class.call(:compress, out, ptr)
        out.read_bytes(self.class::COMPRESSED)
      end

      def affine
        a = Bls12.mem(self.class::AFFINE)
        self.class.call(:to_affine, a, ptr)
        a
      end

      def ==(other) = other.is_a?(self.class) && compress == other.compress

      # Strict compressed decoding: compression flag set, canonical, on curve, in the prime-order subgroup. The identity is allowed
      # (check it separately). Raises ArgumentError otherwise.
      def self.decode(bytes)
        unless bytes.is_a?(String) && bytes.bytesize == self::COMPRESSED && (bytes.getbyte(0) & 0x80) != 0
          raise ArgumentError, "not a #{self::COMPRESSED}-byte compressed #{self::NAME} point"
        end

        aff = Bls12.mem(self::AFFINE)
        raise ArgumentError, "invalid #{self::NAME} encoding" unless call(:uncompress, aff, bytes.b).zero?
        raise ArgumentError, "invalid #{self::NAME} encoding" unless call(:affine_on_curve, aff) && call(:"affine_in_g#{self::GROUP}", aff)

        pt = new
        call(:from_affine, pt.ptr, aff)
        raise ArgumentError, "non-canonical #{self::NAME} encoding" unless pt.compress == bytes.b

        pt
      end
    end

    class G1 < Point
      TAG = 'p1'
      NAME = 'G1'
      GROUP = 1
      SIZE = 144
      AFFINE = 96
      COMPRESSED = 48

      def self.generator
        g = new
        g.ptr.put_bytes(0, Bls12.lib.blst_p1_generator.read_bytes(SIZE))
        g
      end

      # RFC 9380 hash_to_curve (SSWU_RO) into G1
      def self.hash_to(msg, dst)
        out = new
        m = msg.b
        d = dst.b
        Bls12.lib.blst_hash_to_g1(out.ptr, m, m.bytesize, d, d.bytesize, nil, 0)
        out
      end
    end

    class G2 < Point
      TAG = 'p2'
      NAME = 'G2'
      GROUP = 2
      SIZE = 288
      AFFINE = 192
      COMPRESSED = 96

      def self.generator
        g = new
        g.ptr.put_bytes(0, Bls12.lib.blst_p2_generator.read_bytes(SIZE))
        g
      end
    end

    # e(a, x) == e(b, y), by blst's pairing
    def pairing_eq(a, x, b, y)
      l = mem(576)
      r = mem(576)
      lib.blst_miller_loop(l, x.affine, a.affine)
      lib.blst_miller_loop(r, y.affine, b.affine)
      lib.blst_fp12_finalverify(l, r)
    end

    # The pairing target group GT as 576-byte strings (12 Fp coordinates, 48-byte big-endian each), through the shim.
    module Gt
      BYTES = 576

      module_function

      def mul(a, b)
        out = Bls12.mem(BYTES)
        Bls12.gt_lib.pca_gt_mul(out, a.b, b.b).zero? ? raise(ArgumentError, 'not a canonical GT encoding') : out.read_bytes(BYTES)
      end

      # a^(k mod r)
      def pow(a, k)
        out = Bls12.mem(BYTES)
        Bls12.gt_lib.pca_gt_pow(out, a.b, Bls12.i2osp(k % R, 32)).zero? ? raise(ArgumentError, 'not a canonical GT encoding') : out.read_bytes(BYTES)
      end

      # canonical encoding of an element of the order-r subgroup other than the identity
      def element?(a) = a.is_a?(String) && a.bytesize == BYTES && Bls12.gt_lib.pca_gt_is_element(a.b) == 1

      def pairing(p, q) = pairing_product([p], [q])

      # prod e(g1[i], g2[i]) with one shared final exponentiation; raises on an identity point
      def pairing_product(g1, g2)
        n = g1.length
        raise ArgumentError, 'pairing product needs equal, non-empty point lists' if n.zero? || n != g2.length
        raise ArgumentError, 'pairing is not defined for the identity' if g1.any?(&:inf?) || g2.any?(&:inf?)

        out = Bls12.mem(BYTES)
        ok = Bls12.gt_lib.pca_gt_pairing(out, g1.map(&:compress).join.b, g2.map(&:compress).join.b, n)
        raise ArgumentError, 'invalid pairing input' if ok.zero?

        out.read_bytes(BYTES)
      end
    end
  end
end
