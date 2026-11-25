# frozen_string_literal: true

require 'digest'
require 'openssl'
require_relative 'mpc'

module AtlasPca
  module Mpc
    # Word-array kernels for the OT-extension hot path: AES-128-CTR column PRG, 32x32 bit transposes, GF(2^128) on four little-endian
    # u32 words (an Array of unsigned Integers), and the batched tweakable correlation-robust hash H(x, t) = pi(pi(x) ^ t) ^ pi(x)
    # with a fixed-key AES-128 truncated to 64 bits. AES comes from OpenSSL through the openssl gem.
    module Otx
      COLS = 128 # bit columns of the IKNP matrix (kappa)
      M32 = 0xFFFFFFFF
      TAG_PRG_KEY = 'atlas-pca-mpc/ot-prg-aes'.b.freeze
      TAG_CRH_KEY = 'atlas-pca-mpc/ot-crh-aes-fixed-key'.b.freeze
      TAG_TWEAK_DOMAIN = 'atlas-pca-mpc/ot-crh-tweak-domain/v2'.b.freeze
      # tweak of a hash call: channel-global row offset plus the 2-word session domain
      OtTweak = Struct.new(:offset, :domain)

      module_function

      # little-endian bytes of a bigint, exactly len bytes (the low bytes; a negative value reads as two's complement)
      def big_to_bytes(v, len) = Array.new(len) { |i| (v >> (8 * i)) & 0xFF }.pack('C*')

      # the bigint with the given little-endian bytes
      def bytes_to_big(b) = b.b.reverse.unpack1('H*').to_i(16)

      def le_words(b, off, n) = b.byteslice(off, 4 * n).unpack('V*')
      def le_bytes(w, n) = w.first(n).pack('V*')
      def words_from_le_bytes(b, nwords) = le_words(b, 0, nwords)

      def prg_key(seed) = Digest::SHA256.digest(TAG_PRG_KEY + seed.b).byteslice(0, 16)

      # nwords u32 words of the PRG stream of seed from AES block start_block (high tail bits unmasked)
      def prg_column(seed, start_block, nwords)
        iv = [0, start_block & ((1 << 64) - 1)].pack('Q>Q>')
        c = OpenSSL::Cipher.new('aes-128-ctr')
        c.encrypt
        c.key = prg_key(seed)
        c.iv = iv
        le_words(c.update("\0".b * (nwords * 4)) + c.final, 0, nwords)
      end

      # clears the bits at positions >= nbits in a little-endian word column (in place)
      def mask_tail(col, nbits)
        full = nbits >> 5
        rem = nbits & 31
        col[full] &= (1 << rem) - 1 if rem != 0
        (rem != 0 ? full + 1 : full).upto(col.length - 1) { |i| col[i] = 0 }
        col
      end

      # in-place transpose of a 32x32 bit matrix held as 32 u32 words from off
      def transpose32(a, off = 0)
        m = 0x0000ffff
        j = 16
        while j != 0
          k = 0
          while k < 32
            t = (((a[off + k] >> j) ^ a[off + k + j]) & m) & M32
            a[off + k] = (a[off + k] ^ ((t << j) & M32)) & M32
            a[off + k + j] = (a[off + k + j] ^ t) & M32
            k = (k + j + 1) & ~j
          end
          j >>= 1
          m = (m ^ (m << j)) & M32
        end
        a
      end

      # transposes COLS bit-columns (each W words, concatenated) into rows rows of four words
      def transpose_cols(cols, w, rows)
        out = Array.new(rows * 4, 0)
        blocks = (rows + 31) >> 5
        blocks.times do |rb|
          4.times do |cb|
            tmp = Array.new(32) { |c| cols[((cb * 32) + c) * w + rb] }
            transpose32(tmp, 0)
            lim = [32, rows - (rb * 32)].min
            lim.times { |r| out[((rb * 32) + r) * 4 + cb] = tmp[r] }
          end
        end
        out
      end

      # acc ^= the four-word element at v[vo..]
      def gf_xor_into(acc, v, vo = 0)
        4.times { |i| acc[i] ^= v[vo + i] }
        acc
      end

      # acc *= x in GF(2^128) (x^128 = x^7 + x^2 + x + 1)
      def gf_mul_x(acc)
        carry = acc[3] >> 31
        acc[3] = ((acc[3] << 1) | (acc[2] >> 31)) & M32
        acc[2] = ((acc[2] << 1) | (acc[1] >> 31)) & M32
        acc[1] = ((acc[1] << 1) | (acc[0] >> 31)) & M32
        acc[0] = ((acc[0] << 1) ^ (carry != 0 ? 0x87 : 0)) & M32
        acc
      end

      # XORs into acc chi[j] (four words) for every set bit j of the word column col[off, len]
      def accum_column(col, off, len, chi, acc)
        len.times do |w|
          x = col[off + w]
          base = w << 5
          while x != 0
            low = x & -x
            o = (base + low.bit_length - 1) << 2
            acc[0] ^= chi[o]
            acc[1] ^= chi[o + 1]
            acc[2] ^= chi[o + 2]
            acc[3] ^= chi[o + 3]
            x ^= low
          end
        end
        acc
      end

      # sum_i x^i * (sum_{j in col_i} chi_j) by Horner over the columns: the KOS combination of both roles
      def kos_combine(cols, w, chi)
        acc = [0, 0, 0, 0]
        (COLS - 1).downto(0) do |i|
          gf_mul_x(acc)
          part = [0, 0, 0, 0]
          accum_column(cols, i * w, w, chi, part)
          gf_xor_into(acc, part, 0)
        end
        acc
      end

      def gf_from_big(v) = Array.new(4) { |i| (v >> (32 * i)) & M32 }
      def gf_to_big(w, off = 0) = (3.downto(0)).reduce(0) { |v, i| (v << 32) | w[off + i] }

      def crh_key = Digest::SHA256.digest(TAG_CRH_KEY).byteslice(0, 16)

      def aes_ecb(buf)
        c = OpenSSL::Cipher.new('aes-128-ecb')
        c.encrypt
        c.padding = 0
        c.key = crh_key
        c.update(buf) + c.final
      end

      # the 64-bit session domain of a channel: SHA-256(tag, binding)[0..8] as two little-endian words
      def ot_tweak_domain(binding) = le_words(Digest::SHA256.digest(TAG_TWEAK_DOMAIN + binding.b), 0, 2)

      # H(tweak, row_j) for n rows of four words: two u32 words per row (the low 64 bits of the TMMO hash)
      def tmmo_crh(rows, n, tweak = nil)
        offset = tweak.nil? ? 0 : tweak.offset
        dom = tweak.nil? ? [0, 0] : tweak.domain
        raise ArgumentError, 'tmmoCrh: tweak offset must be a non-negative safe integer' if !offset.is_a?(Integer) || offset.negative? || offset > (1 << 53) - 1
        raise ArgumentError, 'tmmoCrh: tweak domain must be 2 words' unless dom.length == 2

        aw = le_words(aes_ecb(le_bytes(rows, n * 4)), 0, n * 4)
        b = Array.new(n * 4)
        n.times do |j|
          o = j * 4
          v = offset + j
          b[o] = aw[o] ^ (v & M32)
          b[o + 1] = aw[o + 1] ^ ((v >> 32) & M32)
          b[o + 2] = aw[o + 2] ^ dom[0]
          b[o + 3] = aw[o + 3] ^ dom[1]
        end
        cw = le_words(aes_ecb(le_bytes(b, n * 4)), 0, n * 4)
        out = Array.new(n * 2)
        n.times do |j|
          out[2 * j] = cw[4 * j] ^ aw[4 * j]
          out[2 * j + 1] = cw[4 * j + 1] ^ aw[4 * j + 1]
        end
        out
      end

      # the 64-bit value of the two words at index j of a tmmo_crh output
      def word64(h, j) = (h[(2 * j) + 1] << 32) | h[2 * j]
    end
  end
end
