# frozen_string_literal: true

require_relative 'mpc_spdz'
require_relative 'mpc_ot'

module AtlasPca
  module Mpc
    # The no-dealer SPDZ offline phase (MASCOT-style): every product of two additively shared values is built from real oblivious
    # transfers (Gilboa multiplication over OT extension), the MAC key is distributed and never reconstructed, and every produced
    # triple is certified by the sacrifice check. When a check fails the OT transcripts are searched to blame the cheating party.
    module Mascot
      # a MAC-check abort raised by the offline phase, naming the party the OT transcripts convict (when one can be named)
      class OfflineCheatingAbort < Spdz::MacCheckAbort
        attr_reader :blamed

        def initialize(message, blamed)
          super(blamed.empty? ? message : "#{message}; offline OT transcript names party #{blamed.join(', ')}")
          @blamed = blamed
        end
      end

      OtRecord = Struct.new(:receiver, :sender, :msg0, :msg1, :received)
      ProductClaim = Struct.new(:claimed, :implied)
      # TEST-ONLY: the product_mul-th product's claimed share is shifted by delta (a cheating party lying about a product)
      OfflineDeviation = Struct.new(:product_mul, :delta)
      # options (nil fields mean the defaults)
      NoDealerOptions = Struct.new(:sacrifice, :sacrifice_partners, :mac_keys, :deviation, :stat_sec, :unsafe_stat_sec)
      # one operand of a multiplication request: x is a list of plain values or encoded (value, choice bits) shares
      Req = Struct.new(:x, :y)
      Part = Struct.new(:bits, :gad)
      Piece = Struct.new(:value, :parts)
      Seg = Struct.new(:q, :start, :len, :sender_sum)

      # the no-dealer offline provider of n parties; a non-nil seed makes every draw reproducible (tests only)
      def self.make_no_dealer_offline(n, seed = nil, opts = nil) = NoDealerOffline.new(n, seed, opts)

      class NoDealerOffline
        attr_reader :n, :alpha_shares, :stat_sec

        def initialize(n, seed = nil, opts = nil)
          opts ||= NoDealerOptions.new
          raise ArgumentError, 'NoDealerOffline: n must be a positive integer' unless n.is_a?(Integer) && n >= 1

          @n = n
          @deterministic = !seed.nil?
          @seed = seed.nil? ? 0xabcdef12345 : seed
          @rng = @deterministic ? Field::FieldRng.new(@seed) : Field::SecureFieldRng.new
          @sacrifice_on = opts.sacrifice.nil? || opts.sacrifice
          @deviation = opts.deviation
          keys = opts.mac_keys.nil? ? Spdz::MAC_KEYS : opts.mac_keys
          raise ArgumentError, 'NoDealerOffline: macKeys must be an integer in [1, 16]' unless keys.is_a?(Integer) && keys >= 1 && keys <= 16

          @stat_sec = opts.stat_sec.nil? ? Enc::STAT_SEC : opts.stat_sec
          @gadget = Enc.make_gadget(@stat_sec, @rng, opts.unsafe_stat_sec == true)
          @key_enc = Array.new(keys) { Array.new(n) { Enc.sample_enc(@gadget, @rng) } }
          @key_shares = @key_enc.map { |row| row.map(&:value) }
          @alpha_shares = @key_shares[0]
          @sacrifice_partners = opts.sacrifice_partners.nil? ? Spdz::SACRIFICE_PARTNERS : opts.sacrifice_partners
          raise ArgumentError, 'NoDealerOffline: sacrificePartners must be an integer in [1, 8]' unless @sacrifice_partners.is_a?(Integer) && @sacrifice_partners >= 1 && @sacrifice_partners <= 8

          @channels = {}
          @product_mul_count = 0
          @log = nil
          @claims = []
        end

        # the MAC context: the shares of each key and (for tests and the check only) their sums
        def mac_context
          keys = @key_shares.map { |shares| Spdz::MacKey.new(shares.dup, shares.reduce(0) { |a, s| Field.fadd(a, s) }) }
          Spdz::MacContext.new(@n, keys[0].alpha_shares, keys[0].alpha, keys[1..])
        end

        # additive shares of x*y where party i holds x_i and y_i (all cross terms via OT)
        def ot_share_multiply(x, y) = mul_batch([Req.new(x, y)])[0]

        # one authenticated triple, certified by the sacrifice check (or raw when sacrifice is switched off)
        def gen_auth_triple
          return raw_triple_with_partners(0).keep unless @sacrifice_on

          @log = []
          @claims = []
          begin
            t = raw_triple_with_partners(@sacrifice_partners)
            Spdz.sacrifice_verify([t], mac_context, @rng, [])[0]
          rescue Spdz::MacCheckAbort => e
            raise attribute(e)
          ensure
            @log = nil
            @claims = []
          end
        end

        def gen_auth_triples(count) = Array.new(count) { gen_auth_triple }

        # an authenticated sharing of a value contributed by owner, MACed by OT under the distributed key
        def auth_input(value, owner)
          raise ArgumentError, 'authInput: owner out of range' unless owner.is_a?(Integer) && owner >= 0 && owner < @n

          authenticate(Sharing.share(Field.mod(value), @n, @rng))
        end

        # verifies that every supplied input's MAC matches its value via a random combination (aborts otherwise)
        def check_input_consistency(inputs)
          return if inputs.empty?

          inputs.each do |inp|
            raise ArgumentError, 'checkInputConsistency: input party count mismatch' if inp.value.length != @n || inp.mac.length != @n
          end
          engine = Spdz::SpdzEngine.new(mac_context, [])
          w = authenticate(Array.new(@n) { @rng.next })
          inputs.each do |inp|
            e = @rng.next
            e = 1 if e.zero?
            w = Spdz.add_auth(w, Spdz.scale_auth(inp, e))
          end
          engine.open(w, 'input-check:w')
          engine.mac_check(@rng)
        end

        private

        def channel(i, j)
          @channels["#{i}->#{j}"] ||= begin
            ot_rng = if @deterministic
                       Ot.ot_random(Ot.split_mix64(@seed ^ ((i + 1) * 0x100000001b3) ^ ((j + 1) * 0x1000000000)))
                     else
                       Ot.secure_ot_random
                     end
            Ot::OtChannel.new(ot_rng)
          end
        end

        def sample_share = Enc.sample_enc(@gadget, @rng)

        # batched Gilboa multiplication: one OT-extension call per ordered party pair for every request
        def mul_batch(reqs)
          reqs.each { |r| raise ArgumentError, 'otShareMultiply: wrong length' if r.x.length != @n || r.y.length != @n }
          pieces = reqs.map do |r|
            r.x.map do |xi|
              if xi.is_a?(Enc::EncShare)
                Piece.new(xi.value, [Part.new(xi.bits, @gadget)])
              else
                v = Field.mod(xi)
                e = Enc.sample_enc(@gadget, @rng)
                d = Enc.plain_share(Field.fsub(v, e.value))
                Piece.new(v, [Part.new(e.bits, @gadget), Part.new(d.bits, Enc.plain_gadget)])
              end
            end
          end
          z = Array.new(reqs.length) { |q| Array.new(@n) { |i| Field.fmul(pieces[q][i].value, reqs[q].y[i]) } }
          @n.times do |i|
            @n.times do |j|
              next if i == j

              bits = []
              msg0 = []
              msg1 = []
              segs = []
              reqs.each_with_index do |req, q|
                y = Field.mod(req.y[j])
                pieces[q][i].parts.each do |part|
                  at = bits.length
                  sender_sum = 0
                  part.bits.each_with_index do |bit, k|
                    rho = @rng.next
                    sender_sum = Field.fadd(sender_sum, rho)
                    bits << bit
                    msg0 << rho
                    msg1 << Field.fadd(rho, Field.fmul(part.gad[k], y))
                  end
                  segs << Seg.new(q, at, part.bits.length, sender_sum)
                end
              end
              received = channel(i, j).extend_ot(bits, msg0, msg1).received
              @log << OtRecord.new(i, j, msg0, msg1, received) if @log
              segs.each do |sg|
                receiver_sum = 0
                sg.len.times { |k| receiver_sum = Field.fadd(receiver_sum, Field.mod(received[sg.start + k])) }
                z[sg.q][i] = Field.fadd(z[sg.q][i], receiver_sum)
                z[sg.q][j] = Field.fadd(z[sg.q][j], Field.fneg(sg.sender_sum))
              end
            end
          end
          z
        end

        def key_req(l) = @key_enc[l].dup

        def authenticate(value_shares)
          to_auth(value_shares, mul_batch(Array.new(@key_enc.length) { |l| Req.new(key_req(l), value_shares) }))
        end

        def to_auth(value, macs) = Spdz::AuthSV.new(value, macs[0], macs[1..])

        def claim_product(implied)
          z = implied.dup
          idx = @product_mul_count
          @product_mul_count += 1
          z[0] = Field.fadd(z[0], @deviation.delta) if @deviation && @deviation.product_mul == idx
          @claims << ProductClaim.new(z, implied)
          z
        end

        def raw_triple_with_partners(partners)
          k = @key_enc.length
          a_enc = Array.new(@n) { sample_share }
          b_shares = Array.new(@n) { @rng.next }
          ah_enc = Array.new(partners) { Array.new(@n) { sample_share } }
          a_val = a_enc.map(&:value)
          ah_val = ah_enc.map { |row| row.map(&:value) }
          reqs = [Req.new(a_enc.dup, b_shares)]
          partners.times { |r| reqs << Req.new(ah_enc[r].dup, b_shares) }
          mac_start = reqs.length
          k.times do |l|
            reqs << Req.new(key_req(l), a_val)
            reqs << Req.new(key_req(l), b_shares)
            partners.times { |r| reqs << Req.new(key_req(l), ah_val[r]) }
          end
          z1 = mul_batch(reqs)
          c_shares = claim_product(z1[0])
          ch_shares = Array.new(partners) { |r| claim_product(z1[1 + r]) }
          per = 2 + partners
          reqs2 = []
          k.times do |l|
            reqs2 << Req.new(key_req(l), c_shares)
            partners.times { |r| reqs2 << Req.new(key_req(l), ch_shares[r]) }
          end
          z2 = mul_batch(reqs2)
          per2 = 1 + partners
          b = to_auth(b_shares, mac_of(z1, mac_start, per, 1, k))
          keep = Spdz::AuthTriple.new(to_auth(a_val, mac_of(z1, mac_start, per, 0, k)), b, to_auth(c_shares, mac_of(z2, 0, per2, 0, k)))
          parts = Array.new(partners) do |r|
            Spdz::AuthTriple.new(to_auth(ah_val[r], mac_of(z1, mac_start, per, 2 + r, k)), b, to_auth(ch_shares[r], mac_of(z2, 0, per2, 1 + r, k)))
          end
          Spdz::TripleWithPartners.new(keep, parts)
        end

        def mac_of(z, start, per, off, k) = Array.new(k) { |l| z[start + (l * per) + off] }

        def attribute(abort)
          blamed = []
          @log&.each do |r|
            r.received.each_with_index do |v, k|
              got = Field.mod(v)
              next if got == r.msg0[k] || got == r.msg1[k]

              blamed << r.sender
              break
            end
          end
          @claims.each { |c| c.claimed.each_index { |i| blamed << i if c.claimed[i] != c.implied[i] } }
          OfflineCheatingAbort.new(abort.message, blamed.uniq.sort)
        end
      end
    end
  end
end
