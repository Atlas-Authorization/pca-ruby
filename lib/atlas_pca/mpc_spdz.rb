# frozen_string_literal: true

require_relative 'mpc'

module AtlasPca
  module Mpc
    # SPDZ-style authenticated secret sharing over F_p: the malicious-with-abort (dishonest-majority) layer. A global MAC key alpha is
    # additively shared; every authenticated value carries MAC shares summing to alpha*x under MAC_KEYS independent keys; the batched
    # commit-then-open MAC-check aborts on any deviation, so the result is correct or an abort. The authenticated triples come from a
    # trusted dealer (the explicit trust assumption) or the OT-based no-dealer offline phase; the online phase is the real thing.
    module Spdz
      # one global MAC key, additively shared (alpha is for dealer preprocessing and tests only)
      MacKey = Struct.new(:alpha_shares, :alpha)
      # key 0 is alpha_shares/alpha; extra_keys are further independent keys
      MacContext = Struct.new(:n, :alpha_shares, :alpha, :extra_keys)
      # value shares sum to x, mac shares to alpha*x (key 0), extra_mac[l-1] to extra_keys[l-1].alpha*x
      AuthSV = Struct.new(:value, :mac, :extra_mac)
      AuthTriple = Struct.new(:a, :b, :c)
      TripleWithPartners = Struct.new(:keep, :partners) # a triple to deliver plus its sacrifice partners (every partner shares keep.b)
      # TEST-ONLY lying-dealer fault: the dealer authenticates a wrong product. nil entries mean no delta.
      DealerFault = Struct.new(:keep_c_delta, :partner_c_delta)
      # a party's broadcast deviation in the online phase (models an active cheater); nil deltas mean none; mac_key defaults to 0
      Deviation = Struct.new(:open_index, :party, :value_delta, :mac_delta, :mac_key)
      # one partial opening as it reaches the MAC-check: the public value and mac_shares[key][party]
      OpenedValue = Struct.new(:value, :mac_shares, :label)

      MAC_KEYS = 2
      MIN_MAC_SOUNDNESS_BITS = 100
      SACRIFICE_PARTNERS = 2
      PRIME = Field::PRIME

      # raised when the MAC-check detects an inconsistent opening/MAC: the protocol ABORTS, no output
      class MacCheckAbort < StandardError; end

      module_function

      def mac_keys(ctx) = [MacKey.new(ctx.alpha_shares, ctx.alpha), *ctx.extra_keys]

      # keys * (log2 p - 1): the soundness in bits of the batched MAC-check
      def mac_soundness_bits(keys, p = PRIME)
        d = p.to_f
        l = Math.log(d) / Math.log(2)
        r = l.round
        l = r if (l - r).abs < 1e-9 && 2.0**r == d
        keys * (l - 1)
      end

      def setup_mac(n, rng, keys = MAC_KEYS)
        raise ArgumentError, 'setupMac: n must be a positive integer' unless n.is_a?(Integer) && n >= 1
        raise ArgumentError, 'setupMac: keys must be an integer in [1, 16]' unless keys.is_a?(Integer) && keys >= 1 && keys <= 16

        first = mk(n, rng)
        extra = Array.new(keys - 1) { mk(n, rng) }
        MacContext.new(n, first.alpha_shares, first.alpha, extra)
      end

      def mk(n, rng)
        alpha = rng.next
        MacKey.new(Sharing.share(alpha, n, rng), alpha)
      end

      def auth_share(secret, ctx, rng)
        v = Field.mod(secret)
        value = Sharing.share(v, ctx.n, rng)
        mac = Sharing.share(Field.fmul(ctx.alpha, v), ctx.n, rng)
        extra = ctx.extra_keys.map { |k| Sharing.share(Field.fmul(k.alpha, v), ctx.n, rng) }
        AuthSV.new(value, mac, extra)
      end

      def auth_constant(c, ctx)
        v = Field.mod(c)
        value = Array.new(ctx.n, 0)
        value[0] = v
        AuthSV.new(value, Sharing.scale_sv(ctx.alpha_shares, v), ctx.extra_keys.map { |k| Sharing.scale_sv(k.alpha_shares, v) })
      end

      def zip_with(x, y, op) = x.zip(y).map { |a, b| Field.public_send(op, a, b) }

      def add_auth(x, y)
        require_same(x, y)
        AuthSV.new(zip_with(x.value, y.value, :fadd), zip_with(x.mac, y.mac, :fadd), x.extra_mac.zip(y.extra_mac).map { |a, b| zip_with(a, b, :fadd) })
      end

      def sub_auth(x, y)
        require_same(x, y)
        AuthSV.new(zip_with(x.value, y.value, :fsub), zip_with(x.mac, y.mac, :fsub), x.extra_mac.zip(y.extra_mac).map { |a, b| zip_with(a, b, :fsub) })
      end

      def neg_auth(x) = AuthSV.new(Sharing.neg_sv(x.value), Sharing.neg_sv(x.mac), x.extra_mac.map { |r| Sharing.neg_sv(r) })

      def scale_auth(x, c)
        k = Field.mod(c)
        AuthSV.new(Sharing.scale_sv(x.value, k), Sharing.scale_sv(x.mac, k), x.extra_mac.map { |r| Sharing.scale_sv(r, k) })
      end

      # x + c for a PUBLIC constant c: c to one party's value share, alpha_i*c to every party's MAC share under every key
      def add_public_auth(x, c, ctx)
        n = ctx.n
        if x.value.length != n || x.mac.length != n || ctx.alpha_shares.length != n
          raise ArgumentError, 'addPublicAuth: shared value and MAC context disagree on the party count'
        end
        raise ArgumentError, 'addPublicAuth: shared value and MAC context disagree on the key count' if x.extra_mac.length != ctx.extra_keys.length

        k = Field.mod(c)
        value = x.value.dup
        value[0] = Field.fadd(value[0], k)
        mac = Array.new(n) { |i| Field.fadd(x.mac[i], Field.fmul(ctx.alpha_shares[i], k)) }
        extra = x.extra_mac.each_with_index.map do |row, l|
          key = ctx.extra_keys[l]
          raise ArgumentError, 'addPublicAuth: extra MAC party count mismatch' if row.length != n || key.alpha_shares.length != n

          Array.new(n) { |i| Field.fadd(row[i], Field.fmul(key.alpha_shares[i], k)) }
        end
        AuthSV.new(value, mac, extra)
      end

      def not_bit_auth(b, ctx) = add_public_auth(neg_auth(b), 1, ctx)

      def gen_auth_triple(ctx, rng)
        a = rng.next
        b = rng.next
        as = auth_share(a, ctx, rng)
        bs = auth_share(b, ctx, rng)
        AuthTriple.new(as, bs, auth_share(Field.fmul(a, b), ctx, rng))
      end

      def gen_triple_with_partners(ctx, rng, partners = SACRIFICE_PARTNERS, fault = nil)
        raise ArgumentError, 'genTripleWithPartners: partners must be in [1, 8]' unless partners.is_a?(Integer) && partners >= 1 && partners <= 8

        a = rng.next
        b = rng.next
        b_sv = auth_share(b, ctx, rng)
        kd = fault&.keep_c_delta || 0
        keep_a = auth_share(a, ctx, rng)
        keep_c = auth_share(Field.fadd(Field.fmul(a, b), kd), ctx, rng)
        keep = AuthTriple.new(keep_a, b_sv, keep_c)
        ps = Array.new(partners) do |r|
          ah = rng.next
          pd = fault&.partner_c_delta && r < fault.partner_c_delta.length && fault.partner_c_delta[r] ? fault.partner_c_delta[r] : 0
          pa = auth_share(ah, ctx, rng)
          pc = auth_share(Field.fadd(Field.fmul(ah, b), pd), ctx, rng)
          AuthTriple.new(pa, b_sv, pc)
        end
        TripleWithPartners.new(keep, ps)
      end

      # sacrifice check: certifies the kept triples or raises MacCheckAbort, emitting nothing
      def sacrifice_verify(batch, ctx, rng, deviations = [])
        engine = SpdzEngine.new(ctx, deviations)
        taus = []
        batch.each do |t|
          keep = t.keep
          raise MacCheckAbort, 'sacrifice: a triple without partners cannot be certified' if t.partners.empty?

          t.partners.each do |sac|
            raise MacCheckAbort, 'sacrifice: partner does not share b with the triple' unless sac.b.value == keep.b.value

            e = rng.next
            e = 1 if e.zero?
            rho = engine.open(sub_auth(scale_auth(keep.a, e), sac.a), 'sacrifice:rho')
            tau = sub_auth(scale_auth(keep.c, e), sac.c)
            tau = sub_auth(tau, scale_auth(keep.b, rho))
            taus << engine.open(tau, 'sacrifice:tau')
          end
        end
        engine.mac_check(rng)
        taus.each do |t|
          next if t.zero?

          raise MacCheckAbort, "Beaver-triple sacrifice FAILED: residual tau=#{t} != 0 - a malformed triple (c != a*b) was delivered; aborting with no triple emitted"
        end
        batch.map(&:keep)
      end

      # arithmetic core of the batched MAC-check over an arbitrary modulus p; returns sigma[key][party]
      def mac_residuals(p, alpha_shares, opened, challenges)
        alpha_shares.each_with_index.map do |alphas, l|
          r = challenges[l]
          a = opened.each_index.reduce(0) { |acc, j| (acc + (r[j] * opened[j].value)) % p }
          alphas.each_with_index.map do |alpha, i|
            gamma = opened.each_index.reduce(0) { |acc, j| (acc + (r[j] * opened[j].mac_shares[l][i])) % p }
            (gamma - (alpha * a)) % p
          end
        end
      end

      # SHA-256 binding commitment to a field element under a nonce
      def commit(value, nonce) = Digest::SHA256.hexdigest("#{value.to_s(16)}:#{nonce.to_s(16)}")

      # the SPDZ online engine: partial openings and the batched MAC-check
      class SpdzEngine
        def initialize(ctx, deviations = nil)
          bits = Spdz.mac_soundness_bits(1 + ctx.extra_keys.length)
          if bits < MIN_MAC_SOUNDNESS_BITS
            raise ArgumentError, "SpdzEngine: MAC context gives only #{bits.round} bits of statistical soundness (< #{MIN_MAC_SOUNDNESS_BITS}); " \
                                 "use setupMac(n, rng) with the default #{MAC_KEYS} keys"
          end
          @ctx = ctx
          @deviations = deviations || []
          @opened = []
          @counter = 0
        end

        def open_count = @counter

        def open(x, label = '')
          idx = @counter
          @counter += 1
          raise ArgumentError, 'open: value and MAC context disagree on the key count' if x.extra_mac.length != @ctx.extra_keys.length

          value_shares = x.value.dup
          mac_shares = [x.mac.dup, *x.extra_mac.map(&:dup)]
          @deviations.each do |d|
            next unless d.open_index == idx
            raise ArgumentError, 'Deviation.party out of range' if d.party < 0 || d.party >= @ctx.n

            value_shares[d.party] = Field.fadd(value_shares[d.party], d.value_delta) if d.value_delta
            next unless d.mac_delta

            key = d.mac_key || 0
            raise ArgumentError, 'Deviation.macKey out of range' if key < 0 || key >= mac_shares.length

            mac_shares[key][d.party] = Field.fadd(mac_shares[key][d.party], d.mac_delta)
          end
          value = value_shares.reduce(0) { |a, s| Field.fadd(a, s) }
          @opened << OpenedValue.new(value, mac_shares, label)
          value
        end

        # batched MAC-check over every partial open so far; raises MacCheckAbort on any inconsistency
        def mac_check(rng)
          return if @opened.empty?

          keys = Spdz.mac_keys(@ctx)
          challenges = keys.map { Array.new(@opened.length) { rng.next } }
          sigma = Spdz.mac_residuals(PRIME, keys.map(&:alpha_shares), @opened, challenges)
          sigma.each do |row|
            nonces = row.map { rng.next }
            commitments = row.each_index.map { |i| Spdz.commit(row[i], nonces[i]) }
            commitments.each_index do |i|
              raise MacCheckAbort, "MAC-check: commitment from party #{i} did not open consistently" unless Spdz.commit(row[i], nonces[i]) == commitments[i]
            end
          end
          sigma.each_with_index do |row, l|
            residual = row.reduce(0) { |a, s| Field.fadd(a, s) }
            next if residual.zero?

            raise MacCheckAbort, "MAC-check FAILED (key #{l}): residual #{residual} != 0 — an actively-malicious party was detected; aborting with no output"
          end
        end
      end

      # authenticated Beaver multiplication consuming triple; the d and e openings are recorded for the MAC-check
      def beaver_mul_auth(x, y, triple, ctx, engine, label)
        [triple.a, triple.b, triple.c, y].each { |o| require_same(x, o) }
        d = engine.open(sub_auth(x, triple.a), "#{label}:d")
        e = engine.open(sub_auth(y, triple.b), "#{label}:e")
        z = add_auth(triple.c, add_auth(scale_auth(triple.b, d), scale_auth(triple.a, e)))
        add_public_auth(z, Field.fmul(d, e), ctx)
      end

      def auth_value(x) = x.value.reduce(0) { |a, s| Field.fadd(a, s) }

      def require_same(x, y)
        raise ArgumentError, 'authenticated shared values must have the same party count' if x.value.length != y.value.length || x.mac.length != y.mac.length
        raise ArgumentError, 'authenticated shared values must carry the same number of MAC keys' if x.extra_mac.length != y.extra_mac.length

        x.extra_mac.each_index do |l|
          raise ArgumentError, 'authenticated shared values must have the same party count' if x.extra_mac[l].length != y.extra_mac[l].length
        end
      end
    end

    # The no-dealer (OT-based, MASCOT) offline provider of n parties (see mpc_mascot.rb); a non-nil seed makes every draw reproducible
    # (tests only). It never falls back to a trusted dealer.
    def self.make_no_dealer_offline(n, seed = nil) = Mascot.make_no_dealer_offline(n, seed)

    # the malicious-secure (SPDZ) runner: the same composition as Runner.compose_secure, but every shared value carries a MAC and
    # nothing is accepted as output until the batched MAC-check passes (correct result or MacCheckAbort). Offline phase: a no-dealer
    # provider (the default, OT-based), or an explicit trusted dealer with sacrifice-certified triples.
    module SpdzRunner
      # trusted-dealer options (honoured only with insecure_trusted_dealer); nil verify_triples means true
      DealerOptions = Struct.new(:verify_triples, :partners, :fault)
      MaliciousMpcResult = Struct.new(:composed, :parties, :q, :opens, :multiplications, :offline_mode, :triples_verified, :mac_checked)
      T_M = 3

      module_function

      # offline: an object with n, mac_context, gen_auth_triple and auth_input(value, owner); nil selects the no-dealer OT phase
      def compose_secure_malicious(vectors, q: nil, seed: nil, deviations: nil, offline: nil, insecure_trusted_dealer: false, dealer: nil)
        n = vectors.length
        raise ArgumentError, 'composeSecureMalicious: no parties (fail closed)' if n.zero?

        q ||= Party::DEFAULT_Q
        Compose.assert_decision_vectors(vectors, q)
        rng = seed.nil? ? Field::SecureFieldRng.new : Field::FieldRng.new(seed)
        raise 'composeSecureMalicious: offline and insecureTrustedDealer are mutually exclusive (fail closed)' if offline && insecure_trusted_dealer
        if dealer && !insecure_trusted_dealer && offline.nil?
          raise 'composeSecureMalicious: dealer options require insecureTrustedDealer: true (fail closed)'
        end

        offline ||= Mpc.make_no_dealer_offline(n, seed) unless insecure_trusted_dealer
        raise 'composeSecureMalicious: offline provider party count != number of vectors' if offline && offline.n != n

        ctx = offline ? offline.mac_context : Spdz.setup_mac(n, rng)
        engine = Spdz::SpdzEngine.new(ctx, deviations || [])
        mults = 0
        verify = dealer.nil? || dealer.verify_triples.nil? || dealer.verify_triples
        next_triple = lambda do
          next offline.gen_auth_triple if offline

          unless verify
            next dealer&.fault ? Spdz.gen_triple_with_partners(ctx, rng, 1, dealer.fault).keep : Spdz.gen_auth_triple(ctx, rng)
          end
          partners = dealer&.partners || Spdz::SACRIFICE_PARTNERS
          dealt = Spdz.gen_triple_with_partners(ctx, rng, partners, dealer&.fault)
          Spdz.sacrifice_verify([dealt], ctx, rng, [])[0]
        end
        share_bit = lambda do |bit, owner|
          offline ? offline.auth_input(bit, owner) : Spdz.auth_share(bit, ctx, rng)
        end
        and_all = lambda do |bits|
          next Spdz.auth_constant(1, ctx) if bits.empty?

          i = 0
          bits[1..].reduce(bits[0]) do |acc, b|
            i += 1
            mults += 1
            Spdz.beaver_mul_auth(acc, b, next_triple.call, ctx, engine, "and#{i}")
          end
        end
        or_all = lambda do |bits|
          next Spdz.auth_constant(0, ctx) if bits.empty?

          i = 0
          prod = bits[1..].reduce(Spdz.not_bit_auth(bits[0], ctx)) do |acc, b|
            i += 1
            mults += 1
            Spdz.beaver_mul_auth(acc, Spdz.not_bit_auth(b, ctx), next_triple.call, ctx, engine, "or#{i}")
          end
          Spdz.not_bit_auth(prod, ctx)
        end
        allow_sv = and_all.call((0...n).map { |p| share_bit.call(vectors[p].allow, p) })
        t_therm = vectors.map { |v| Thermometer.thermometer_encode(v.t, T_M) }
        t_ge = (0...T_M).map { |k| or_all.call((0...n).map { |p| share_bit.call(t_therm[p][k], p) }) }
        r_therm = vectors.map { |v| Thermometer.thermometer_encode(v.r_quant, q) }
        r_ge = (0...q).map { |k| or_all.call((0...n).map { |p| share_bit.call(r_therm[p][k], p) }) }
        allow_open = engine.open(allow_sv, 'out:allow')
        t_open = t_ge.each_with_index.map { |sv, k| engine.open(sv, "out:t.ge#{k + 1}") == 1 ? 1 : 0 }
        r_open = r_ge.each_with_index.map { |sv, k| engine.open(sv, "out:r.ge#{k + 1}") == 1 ? 1 : 0 }
        engine.mac_check(rng)
        composed = ComposedDecision.new(allow_open == 1 ? 1 : 0, [3, [1, Thermometer.thermometer_decode(t_open)].max].min, Thermometer.thermometer_decode(r_open))
        MaliciousMpcResult.new(composed, n, q, engine.open_count, mults, offline ? 'no-dealer' : 'trusted-dealer', !offline.nil? || verify, true)
      end
    end
  end
end

require_relative 'mpc_mascot'
