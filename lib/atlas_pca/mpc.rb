# frozen_string_literal: true

require 'digest'
require 'securerandom'

module AtlasPca
  # Secure multi-party composition of stakeholder decisions (the TypeScript reference, @atlasauth/pca-mpc), deterministic layer and
  # the SPDZ malicious-with-abort online phase: additive sharing over F_p (p = 2^61 - 1), Beaver multiplication, thermometer
  # encoding, the cleartext and simulated-MPC compositions, authenticated shares with a batched MAC-check, and the sacrifice check of
  # dealer triples. Pure Integer arithmetic (not constant time); every random draw comes from an explicit FieldRng seed (tests) or the
  # CSPRNG-backed SecureFieldRng (the default for protocol randomness). The OT-based offline phase is in MpcOt.
  module Mpc
    # ---- field F_p ----
    module Field
      PRIME = (1 << 61) - 1
      MASK64 = (1 << 64) - 1
      LIMIT = (1 << 64) - 8 # the largest multiple of p that fits in 64 bits; anything at or above it is rejected so `% p` is uniform

      module_function

      def mod(x) = x % PRIME
      def fadd(a, b) = (a + b) % PRIME
      def fsub(a, b) = (a - b) % PRIME
      def fmul(a, b) = (a * b) % PRIME
      def fneg(a) = (-a) % PRIME

      # deterministic SplitMix64 drawing unbiased field elements by rejection sampling
      class FieldRng
        def initialize(seed = 0x243f6a8885a308d3) = @s = seed & MASK64

        def next_u64
          @s = (@s + 0x9e3779b97f4a7c15) & MASK64
          z = @s
          z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & MASK64
          z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & MASK64
          z ^ (z >> 31)
        end

        def next
          loop do
            u = next_u64
            return u % PRIME if u < LIMIT
          end
        end
      end

      # CSPRNG-backed field source: fresh random bytes, rejection sampled
      class SecureFieldRng < FieldRng
        def initialize = super(0)

        def next_u64 = SecureRandom.random_bytes(8).unpack1('Q>')
      end

      # CSPRNG by default, a reproducible seeded FieldRng only when test_seed is non-nil
      def field_random(test_seed = nil) = test_seed.nil? ? SecureFieldRng.new : FieldRng.new(test_seed)
    end

    # ---- additive sharing ----
    module Sharing
      MAX_PARTIES = 1024 # bounds allocation

      module_function

      def check_n(n, who)
        raise ArgumentError, "#{who}: n must be an integer in [1, #{MAX_PARTIES}]" unless n.is_a?(Integer) && n >= 1 && n <= MAX_PARTIES
      end

      def share(secret, n, rng)
        check_n(n, 'share')
        out = Array.new(n - 1) { rng.next }
        acc = out.reduce(0) { |a, s| Field.fadd(a, s) }
        out << Field.fadd(Field.mod(secret), Field.fneg(acc))
      end

      def reconstruct(shares)
        raise ArgumentError, 'reconstruct: no shares (fail closed)' if shares.empty?

        shares.reduce(0) do |acc, s|
          raise ArgumentError, 'reconstruct: missing share (fail closed)' if s.nil?

          Field.fadd(acc, s)
        end
      end

      def share_constant(c, n)
        check_n(n, 'shareConstant')
        out = Array.new(n, 0)
        out[0] = Field.mod(c)
        out
      end

      def same!(x, y)
        raise ArgumentError, 'shared values must have the same party count' unless x.length == y.length
      end

      def add_sv(x, y)
        same!(x, y)
        x.zip(y).map { |a, b| Field.fadd(a, b) }
      end

      def sub_sv(x, y)
        same!(x, y)
        x.zip(y).map { |a, b| Field.fadd(a, Field.fneg(b)) }
      end

      def neg_sv(x) = x.map { |a| Field.fneg(a) }
      def scale_sv(x, c) = x.map { |a| Field.fmul(a, c) }

      def add_public_sv(x, c)
        o = x.dup
        o[0] = Field.fadd(o[0], Field.mod(c))
        o
      end

      def not_bit_sv(b) = add_public_sv(neg_sv(b), 1)
    end

    # GF(2^128) with the reduction polynomial x^128 + x^7 + x^2 + x + 1: the field of the KOS correlation check. Elements are
    # 128-bit non-negative Integers (bit i = coefficient of x^i); addition is XOR. Not constant time.
    module Gf128
      MASK = (1 << 128) - 1
      RED = 0x87

      module_function

      def add(a, b) = (a ^ b) & MASK

      def mul_x(v)
        r = (v << 1) & MASK
        v[127] == 1 ? r ^ RED : r
      end

      def mul_by_xi(v, i)
        r = v & MASK
        i.times { r = mul_x(r) }
        r
      end

      def mul(a, b)
        res = 0
        v = a & MASK
        128.times do |i|
          res ^= v if b[i] == 1
          v = mul_x(v)
        end
        res & MASK
      end
    end

    # privacy-amplified OT choice-bit encoding (the selective-failure remedy): the receiver chooses with m = 61 + 3s uniform bits b and
    # takes x = sum g_k b_k (mod p) for a public gadget vector g. s = 0 is the legacy plain binary encoding.
    module Enc
      FIELD_BITS = 61
      STAT_SEC = 64
      MIN_STAT_SEC = 40
      EncShare = Struct.new(:value, :bits)

      module_function

      def enc_bits(s) = FIELD_BITS + (3 * s)

      def make_gadget(s, rng, unsafe = false)
        raise ArgumentError, 'statSec must be an integer in [0, 64]' unless s.is_a?(Integer) && s >= 0 && s <= 64
        if s < MIN_STAT_SEC && !unsafe
          raise ArgumentError, "statSec #{s} is below #{MIN_STAT_SEC}: refused (tests may pass the explicit unsafe flag)"
        end

        Array.new(enc_bits(s)) { |k| s.zero? ? Field.mod(1 << k) : rng.next }
      end

      def enc_value(g, bits)
        raise ArgumentError, 'encValue: gadget / bits length mismatch' unless g.length == bits.length

        Field.mod(g.each_index.sum { |k| bits[k] == 1 ? g[k] : 0 })
      end

      def plain_share(x)
        v = Field.mod(x)
        EncShare.new(v, Array.new(FIELD_BITS) { |k| v[k] })
      end

      def plain_gadget = Array.new(FIELD_BITS) { |k| Field.mod(1 << k) }

      # m uniform bits from a field source (the 60 low bits of each draw are uniform)
      def random_bits(m, rng)
        out = []
        while out.length < m
          w = rng.next
          60.times { |i| out << w[i] if out.length < m }
        end
        out
      end

      def sample_enc(g, rng)
        bits = random_bits(g.length, rng)
        EncShare.new(enc_value(g, bits), bits)
      end
    end

    # secure multiplication of two additively-shared values with Beaver triples (a trusted dealer supplies the triples)
    module Beaver
      Triple = Struct.new(:a, :b, :c)
      OpenedMsg = Struct.new(:label, :value, :shares) # label is "d" or "e"

      module_function

      def gen_triples(count, n, rng) = Array.new(count) { gen_triple(n, rng) }

      def gen_triple(n, rng)
        a = rng.next
        b = rng.next
        c = Field.fmul(a, b)
        Triple.new(Sharing.share(a, n, rng), Sharing.share(b, n, rng), Sharing.share(c, n, rng))
      end

      # x*y consuming triple; every opened value is appended to transcript when non-nil
      def beaver_mul(x, y, triple, transcript = nil)
        raise ArgumentError, 'beaverMul: operand party counts differ' unless x.length == y.length

        [triple.a, triple.b, triple.c].each do |part|
          raise ArgumentError, 'beaverMul: triple party count differs from the operands' if part.nil? || part.length != x.length
        end
        d_shares = Sharing.sub_sv(x, triple.a)
        e_shares = Sharing.sub_sv(y, triple.b)
        d = Sharing.reconstruct(d_shares)
        e = Sharing.reconstruct(e_shares)
        transcript&.push(OpenedMsg.new('d', d, d_shares), OpenedMsg.new('e', e, e_shares))
        de = Field.fmul(d, e)
        Array.new(x.length) do |i|
          zi = Field.fadd(triple.c[i], Field.fadd(Field.fmul(d, triple.b[i]), Field.fmul(e, triple.a[i])))
          i.zero? ? Field.fadd(zi, de) : zi
        end
      end
    end

    # thermometer (unary) encoding of a bounded integer: ge[k] = [v >= k] for k = 1..M, so MAX is a position-wise OR
    module Thermometer
      module_function

      # encodes v in {0..M}; v is clamped into range (fail safe). v is a JS number: NaN encodes all zero, infinities clamp.
      def thermometer_encode(v, m)
        raise ArgumentError, 'thermometerEncode: M must be a non-negative integer' unless m.is_a?(Integer) && m >= 0
        return Array.new(m, 0) if v.respond_to?(:nan?) && v.nan?

        tr = v.respond_to?(:infinite?) && v.infinite? ? v : v.truncate
        clamped = [0, [m, tr].min].max
        Array.new(m) { |k| clamped >= k + 1 ? 1 : 0 }
      end

      # number of 1s (robust to non-monotone input)
      def thermometer_decode(bits) = bits.count { |b| b == 1 }
    end

    # per-stakeholder decision vector: allow in {0,1}, t in {1,2,3}, r_quant in {0..Q}
    DecisionVector = Struct.new(:allow, :t, :r_quant)
    ComposedDecision = Struct.new(:allow, :t, :r_quant)

    module Party
      DEFAULT_Q = 100

      module_function

      # quantizes r in [0,1] to {0..Q}; non-finite is the worst case (Q)
      def quantize_r(r, q = DEFAULT_Q)
        return q if r.respond_to?(:nan?) && (r.nan? || r.infinite?)

        v = [0, [1, r].min].max * q
        [0, [q, (v + 0.5).floor].min].max # JS Math.round: floor(x + 0.5)
      end

      # Evaluate a party's own policy ({'decideInput' => decide input}) to its decision vector through the Policy VM (AtlasPca.decide).
      # Pure and total; the vector is the party's PRIVATE input to the composition.
      def evaluate_party(policy, q = DEFAULT_Q)
        d = AtlasPca.decide(policy.is_a?(Hash) ? (policy['decideInput'] || policy[:decideInput]) : nil)
        DecisionVector.new(d['releaseGuardianShare'] ? 1 : 0, d['requiredThreshold']['t'], quantize_r(d['r'], q))
      end
    end

    # composition semantics (the "meet" of stakeholder authorities): allow = AND, t = MAX, r_quant = MAX. Composition can only
    # tighten, never loosen.
    module Compose
      module_function

      # rejects a malformed decision vector (allow in {0,1}, t in {1,2,3}, integer r_quant in [0,Q])
      def assert_decision_vectors(vectors, q)
        raise ArgumentError, 'decision vectors must be an array' unless vectors.is_a?(Array)

        vectors.each_with_index do |v, i|
          raise ArgumentError, "party #{i}: decision vector must be an object" if v.nil?
          raise ArgumentError, "party #{i}: allow must be 0 or 1" unless [0, 1].include?(v.allow)
          raise ArgumentError, "party #{i}: t must be 1, 2 or 3" unless [1, 2, 3].include?(v.t)
          raise ArgumentError, "party #{i}: rQuant must be an integer in [0, #{q}]" unless v.r_quant.is_a?(Integer) && v.r_quant >= 0 && v.r_quant <= q
        end
      end

      def compose_clear(vectors, q = Party::DEFAULT_Q)
        raise ArgumentError, 'composeClear: no parties (fail closed)' if vectors.empty?

        assert_decision_vectors(vectors, q)
        ComposedDecision.new(vectors.any? { |v| v.allow.zero? } ? 0 : 1, [1, *vectors.map(&:t)].max, [0, *vectors.map(&:r_quant)].max)
      end
    end

    # the simulated multi-party runner: all N parties in one process, exchanging shares and Beaver openings through inspectable
    # structures. compose_secure computes exactly Compose.compose_clear under MPC.
    module Runner
      T_M = 3
      SharingRecord = Struct.new(:label, :party, :secret, :shares) # the full additive sharing of one party's secret bit (test inspection)
      PartyView = Struct.new(:party, :held_shares, :opened, :output)
      MpcResult = Struct.new(:composed, :parties, :q, :opened, :sharings, :views, :multiplications)

      module_function

      # composes under MPC. seed nil means CSPRNG sharing randomness; a seed is for reproducible tests only.
      def compose_secure(vectors, q_opt = nil, seed = nil)
        n = vectors.length
        raise ArgumentError, 'composeSecure: no parties (fail closed)' if n.zero?

        q = q_opt.nil? ? Party::DEFAULT_Q : q_opt
        Compose.assert_decision_vectors(vectors, q)
        rng = seed.nil? ? Field::SecureFieldRng.new : Field::FieldRng.new(seed)
        opened = []
        sharings = []
        mults = 0
        share_bit = lambda do |bit, label, party|
          s = Sharing.share(bit, n, rng)
          sharings << SharingRecord.new(label, party, bit, s.dup)
          s
        end
        and_all = lambda do |bits|
          next Sharing.share_constant(1, n) if bits.empty?

          bits[1..].reduce(bits[0]) do |acc, b|
            mults += 1
            Beaver.beaver_mul(acc, b, Beaver.gen_triple(n, rng), opened)
          end
        end
        or_all = lambda do |bits|
          next Sharing.share_constant(0, n) if bits.empty?

          prod = bits[1..].reduce(Sharing.not_bit_sv(bits[0])) do |acc, b|
            mults += 1
            Beaver.beaver_mul(acc, Sharing.not_bit_sv(b), Beaver.gen_triple(n, rng), opened)
          end
          Sharing.not_bit_sv(prod)
        end
        allow = Sharing.reconstruct(and_all.call((0...n).map { |p| share_bit.call(vectors[p].allow, "p#{p}.allow", p) })) == 1 ? 1 : 0
        t_therm = vectors.map { |v| Thermometer.thermometer_encode(v.t, T_M) }
        t_ge = (0...T_M).map do |k|
          Sharing.reconstruct(or_all.call((0...n).map { |p| share_bit.call(t_therm[p][k], "p#{p}.t.ge#{k + 1}", p) })) == 1 ? 1 : 0
        end
        t = [3, [1, Thermometer.thermometer_decode(t_ge)].max].min
        r_therm = vectors.map { |v| Thermometer.thermometer_encode(v.r_quant, q) }
        r_ge = (0...q).map do |k|
          Sharing.reconstruct(or_all.call((0...n).map { |p| share_bit.call(r_therm[p][k], "p#{p}.r.ge#{k + 1}", p) })) == 1 ? 1 : 0
        end
        composed = ComposedDecision.new(allow, t, Thermometer.thermometer_decode(r_ge))
        views = (0...n).map { |p| PartyView.new(p, sharings.map { |s| s.shares[p] }, opened, composed) }
        MpcResult.new(composed, n, q, opened, sharings, views, mults)
      end
    end
  end
end
