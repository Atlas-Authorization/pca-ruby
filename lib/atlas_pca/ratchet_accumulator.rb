# frozen_string_literal: true

require_relative 'ratchet_group'

# Homomorphic risk accumulator with a zero-knowledge spend ceiling (Pedersen commitments on ristretto255 plus a
# bit-decomposition range proof), matching the TypeScript reference (@atlasauth/pca-ratchet), wire format included: proofs
# are String-keyed Hashes with the reference's camelCase member names and a blinding is a plain Integer. The group runs on
# libsodium (see ratchet_group.rb).
module AtlasPca
  module RatchetAccumulator
    G = RatchetGroup
    N_BITS = 32
    MAX_PROVABLE_CEILING = (1 << N_BITS) - 1

    # code: invalid_value | length_mismatch | invalid_proof_shape
    class AccumulatorError < StandardError
      attr_reader :code

      def initialize(code, message)
        super(message)
        @code = code
      end
    end

    CTX_DOMAIN = 'atlas-pca-ratchet/budget/ctx/v1'
    RISK_CTX_DOMAIN = 'atlas-pca-ratchet/risk-range/ctx/v1'
    OR_DOMAIN = 'atlas-pca-ratchet/budget/bit-or/v1'
    AGG_DOMAIN = 'atlas-pca-ratchet/budget/agg/v1'

    module_function

    def as_units(x)
      case x
      when Integer
        raise AccumulatorError.new('invalid_value', 'risk/budget must be >= 0') if x.negative?

        x
      when Float
        raise AccumulatorError.new('invalid_value', 'risk/budget must be a non-negative integer') unless x.finite? && x == x.floor && x >= 0

        x.to_i
      else raise AccumulatorError.new('invalid_value', 'risk/budget must be a non-negative integer')
      end
    end

    # Commit to a non-negative integer risk in units, with a given or fresh random blinding.
    def commit_risk(risk, blinding = nil)
      v = as_units(risk)
      b = blinding.nil? ? G.rand_scalar : G.mod(blinding)
      c = G.add(G.mul(G::G, v), G.mul(G::H, b))
      { 'commitment' => G.encode_point(c), 'blinding' => b }
    end

    # Homomorphic sum; an empty input commits to (0, 0), the identity.
    def add_commitments(commitments)
      acc = G::ZERO
      commitments.each { |c| acc = G.add(acc, G.decode_point(c)) }
      G.encode_point(acc)
    end

    # Never raises; malformed input is false.
    def open_commitment(commitment, risk, blinding)
      return false unless blinding.is_a?(Integer)

      v = as_units(risk)
      expected = G.add(G.mul(G::G, v), G.mul(G::H, G.mod(blinding)))
      G.equals(G.decode_point(commitment), expected)
    rescue StandardError
      false
    end

    # a ceiling above the range is clamped: "sum <= 2^N-1" is strictly stronger, so a verifier is never weakened
    def effective_ceiling(b_max) = b_max > MAX_PROVABLE_CEILING ? MAX_PROVABLE_CEILING : b_max

    def context_hash(n, b_max, commitment_sum, bits)
      parts = [CTX_DOMAIN, [n & 0xFF].pack('C'), G.le_bytes(G.mod(b_max), 32), G.to_raw_bytes(commitment_sum)]
      parts.concat(bits.map { |b| G.to_raw_bytes(b) })
      G.le_bytes(G.hash_to_scalar(parts), 32)
    end

    def risk_context_hash(n, commitment, bits)
      parts = [RISK_CTX_DOMAIN, [n & 0xFF].pack('C'), G.to_raw_bytes(commitment)]
      parts.concat(bits.map { |b| G.to_raw_bytes(b) })
      G.le_bytes(G.hash_to_scalar(parts), 32)
    end

    def bit_challenge(ctx, index, a0, a1)
      G.hash_to_scalar([OR_DOMAIN, ctx, [index & 0xFF].pack('C'), G.to_raw_bytes(a0), G.to_raw_bytes(a1)])
    end

    def prove_bit(ctx, index, b_pt, bit, s)
      p0 = b_pt
      p1 = G.sub(b_pt, G::G)
      real = bit == 1 ? 1 : 0
      e_fake = G.rand_scalar
      z_fake = G.rand_scalar
      p_fake = real == 1 ? p0 : p1
      a_fake = G.sub(G.mul(G::H, z_fake), G.mul(p_fake, e_fake))
      k = G.rand_scalar
      a_real = G.mul(G::H, k)
      a0 = real.zero? ? a_real : a_fake
      a1 = real == 1 ? a_real : a_fake
      e = bit_challenge(ctx, index, a0, a1)
      e_real = G.scalar_sub(e, e_fake)
      z_real = G.scalar_add(k, G.scalar_mul(e_real, s))
      e0, e1 = real.zero? ? [e_real, e_fake] : [e_fake, e_real]
      z0, z1 = real.zero? ? [z_real, z_fake] : [z_fake, z_real]
      { 'e0' => G.encode_scalar(e0), 'e1' => G.encode_scalar(e1), 'z0' => G.encode_scalar(z0), 'z1' => G.encode_scalar(z1) }
    end

    def verify_bit(ctx, index, b_pt, proof)
      raise TypeError, 'bit proof must be an object' unless proof.is_a?(Hash)

      e0 = G.decode_scalar(proof['e0'])
      e1 = G.decode_scalar(proof['e1'])
      z0 = G.decode_scalar(proof['z0'])
      z1 = G.decode_scalar(proof['z1'])
      a0 = G.sub(G.mul(G::H, z0), G.mul(b_pt, e0))
      a1 = G.sub(G.mul(G::H, z1), G.mul(G.sub(b_pt, G::G), e1))
      G.scalar_add(e0, e1) == bit_challenge(ctx, index, a0, a1)
    end

    def schnorr_challenge(ctx, d, a) = G.hash_to_scalar([AGG_DOMAIN, ctx, G.to_raw_bytes(d), G.to_raw_bytes(a)])

    def prove_schnorr(ctx, d, w)
      k = G.rand_scalar
      a = G.mul(G::H, k)
      e = schnorr_challenge(ctx, d, a)
      { 'a' => G.encode_point(a), 'z' => G.encode_scalar(G.scalar_add(k, G.scalar_mul(e, w))) }
    end

    def verify_schnorr(ctx, d, proof)
      raise TypeError, 'agg proof must be an object' unless proof.is_a?(Hash)

      a = G.decode_point(proof['a'])
      z = G.decode_scalar(proof['z'])
      e = schnorr_challenge(ctx, d, a)
      G.equals(G.mul(G::H, z), G.add(a, G.mul(d, e)))
    end

    def range_prove(make_ctx, v_pt, value, gamma)
      v_masked = value & ((1 << N_BITS) - 1) # low N_BITS bits, two's complement for a negative slack
      bit_commitments = []
      bit_blindings = []
      bits = []
      N_BITS.times do |i|
        bit = (v_masked >> i) & 1
        s = G.rand_scalar
        bits << bit
        bit_blindings << s
        bit_commitments << G.add(G.mul(G::G, bit), G.mul(G::H, s))
      end
      ctx = make_ctx.call(bit_commitments)
      orp = Array.new(N_BITS) { |i| prove_bit(ctx, i, bit_commitments[i], bits[i], bit_blindings[i]) }
      s_star = 0
      agg_point = G::ZERO
      N_BITS.times do |i|
        w = 1 << i
        s_star = G.scalar_add(s_star, G.scalar_mul(w, bit_blindings[i]))
        agg_point = G.add(agg_point, G.mul(bit_commitments[i], w))
      end
      d = G.sub(agg_point, v_pt)
      { 'bitCommitments' => bit_commitments, 'or' => orp, 'agg' => prove_schnorr(ctx, d, G.scalar_sub(s_star, gamma)) }
    end

    def range_verify(make_ctx, v_pt, proof)
      return false unless proof.is_a?(Hash)

      n = proof['n']
      bit_commitments = proof['bitCommitments']
      orp = proof['or']
      agg = proof['agg']
      return false unless (n.is_a?(Integer) || n.is_a?(Float)) && n == N_BITS
      return false unless bit_commitments.is_a?(Array) && orp.is_a?(Array)
      return false unless bit_commitments.length == N_BITS && orp.length == N_BITS
      return false unless agg.is_a?(Hash)

      b = bit_commitments.map { |x| G.decode_point(x) }
      ctx = make_ctx.call(b)
      return false unless N_BITS.times.all? { |i| verify_bit(ctx, i, b[i], orp[i]) }

      agg_point = G::ZERO
      N_BITS.times { |i| agg_point = G.add(agg_point, G.mul(b[i], 1 << i)) }
      verify_schnorr(ctx, G.sub(agg_point, v_pt), agg)
    end

    def wire(r)
      { 'n' => N_BITS, 'bitCommitments' => r['bitCommitments'].map { |p| G.encode_point(p) }, 'or' => r['or'], 'agg' => r['agg'] }
    end

    # Prove sum(risk) <= b_max over the committed values. An over-budget input yields a well-formed proof the verifier rejects.
    def prove_budget(risks, blindings, b_max)
      raise AccumulatorError.new('length_mismatch', 'risks and blindings must have equal length') unless risks.length == blindings.length

      ceiling = effective_ceiling(as_units(b_max))
      sum_risk = 0
      sum_blind = 0
      risks.each_index do |i|
        sum_risk += as_units(risks[i])
        sum_blind = G.scalar_add(sum_blind, blindings[i])
      end
      c_sum = G.add(G.mul(G::G, G.mod(sum_risk)), G.mul(G::H, sum_blind))
      v_pt = G.sub(G.mul(G::G, G.mod(ceiling)), c_sum)
      ctx = ->(bits) { context_hash(N_BITS, ceiling, c_sum, bits) }
      wire(range_prove(ctx, v_pt, ceiling - sum_risk, G.mod(-sum_blind)))
    end

    # Never raises; malformed input is false. Ceilings above 2^N_BITS - 1 are clamped.
    def verify_budget(commitment_sum, b_max, proof)
      ceiling = effective_ceiling(as_units(b_max))
      c_sum = G.decode_point(commitment_sum)
      v_pt = G.sub(G.mul(G::G, G.mod(ceiling)), c_sum)
      range_verify(->(bits) { context_hash(N_BITS, ceiling, c_sum, bits) }, v_pt, proof)
    rescue StandardError
      false
    end

    # Prove that commit_risk(risk, blinding) holds a value in [0, 2^N_BITS).
    def prove_risk_range(risk, blinding)
      v = as_units(risk)
      b = G.mod(blinding)
      c = G.add(G.mul(G::G, G.mod(v)), G.mul(G::H, b))
      wire(range_prove(->(bits) { risk_context_hash(N_BITS, c, bits) }, c, v, b))
    end

    def verify_risk_range(commitment, proof)
      c = G.decode_point(commitment)
      range_verify(->(bits) { risk_context_hash(N_BITS, c, bits) }, c, proof)
    rescue StandardError
      false
    end

    # Every commitment carries a valid range proof and the budget proof verifies for their sum. Never raises.
    def verify_bounded_budget(commitments, range_proofs, b_max, budget_proof)
      return false unless commitments.is_a?(Array) && range_proofs.is_a?(Array) && commitments.length == range_proofs.length
      return false unless commitments.each_index.all? { |i| verify_risk_range(commitments[i], range_proofs[i]) }

      verify_budget(add_commitments(commitments), b_max, budget_proof)
    rescue StandardError
      false
    end
  end
end
