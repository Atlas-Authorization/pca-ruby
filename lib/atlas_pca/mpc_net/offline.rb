# frozen_string_literal: true

require 'digest'
require 'set'
require_relative '../mpc_net'
require_relative '../mpc_mascot'
require_relative 'protocol'
require_relative 'gadget'

module AtlasPca
  module Mpc
    module Net
      # The NO-DEALER offline phase over the mutual-TLS mesh (research prototype). Each party is its own process holding only its own
      # shares. Nobody is trusted to know the MAC keys, the triples or the inputs: every party samples its own key shares and triple
      # shares, and the products needed for the triples and the MACs are computed by Gilboa OT multiplication between every ordered
      # pair of parties (Mascot is the in-process model of exactly this computation):
      #
      #   ob-S / ob-R / ob-C    all-to-all: the kappa = 128 base OTs of every ordered pair (malicious-secure, session-bound)
      #   gd-c / gd-o / gd-e    all-to-all: the signed commit / reveal / echo of the jointly contributed choice-bit gadget seeds
      #   in-share              all-to-all: each owner splits every input bit into additive shares, one per peer
      #   ox<layer>.<chunk>.u   all-to-all: OT-extension receiver messages (u matrix + KOS pair) -> the sender's KOS correlation check
      #   ox<layer>.<chunk>.y   all-to-all: OT-extension sender ciphertexts
      #
      # Layer 1 = the triple products c = a*b and c-hat = a-hat*b plus the MACs of every value known before them; layer 2 = the MACs of
      # the products; layer 3 = the pairwise tags (identifiable abort). The triple SACRIFICE and the input-consistency opening run in
      # the online phase (protocol.rb), so a party that feeds wrong OT inputs yields a wrong triple the sacrifice catches.
      #
      # SELECTIVE FAILURE: receivers do not choose with the bits of their share but with the gadget encoding (Enc), so whether a run
      # aborts is statistically independent of the share. What is NOT here: any security proof, and attribution of a wrong OT operand
      # in the offline triple products (named only for n = 2, or by the forensic audit of the discarded triple's OT transcript).
      module Offline
        ROWS_PER_ROUND = 128 * Enc::FIELD_BITS
        T_M = 3
        HEX128 = /\A(?:0|[1-9a-f][0-9a-f]{0,31})\z/
        MASK61 = (1 << 61) - 1

        # exchange: proc(rd, mine, parse) one un-echoed all-to-all round (errors while parsing a peer's message abort naming that
        # peer); bad: proc(peer, what) raising; arr: proc(peer, raw, len) -> canonical field elements
        Args = Struct.new(:mesh, :id, :n, :c, :keys, :partners, :session_id, :input, :q, :behavior, :exchange, :bad, :arr, keyword_init: true)
        # one OT multiplication item: my choice bits (weights gad, public) against my sender operand y
        Item = Struct.new(:bits, :gad, :y)
        # per-row transcript of selected items (for post-abort attribution), keyed peer => item => rows
        Kept = Struct.new(:recv, :rho)

        # the field-element stream of the public gadget: SHA-256(seed || counter) reduced by rejection
        class GadgetStream
          def initialize(seed)
            @seed = seed
            @ctr = 0
          end

          def next
            loop do
              h = Digest::SHA256.digest(@seed + [@ctr].pack('Q<'))
              @ctr += 1
              v = h.byteslice(0, 8).unpack1('Q<') & MASK61
              return v if v < Field::PRIME
            end
          end
        end

        module_function

        # the public gadget of the privacy-amplified choice-bit encoding from the parties' contributed seeds: H(all seeds in party
        # order || session) expanded by a hash chain. Every party commits to a fresh seed before any is revealed.
        def gadget_from_seeds(session_id, seeds)
          h0 = Digest::SHA256.new
          h0.update('atlas-pca-mpc/enc-gadget')
          h0.update(AtlasPca::Js.utf8(session_id))
          seeds.each { |sd| h0.update(sd.b) }
          Enc.make_gadget(Enc::STAT_SEC, GadgetStream.new(h0.digest))
        end

        def encode_u(msg, m_ext)
          cb = (m_ext + 7) / 8
          { 'u' => NetCodec.b64(msg.u.map { |c| Otx.big_to_bytes(c, cb) }.join), 'x' => msg.x.to_s(16), 't' => msg.t_comb.to_s(16) }
        end

        def hex128(s)
          raise ArgumentError, 'bad 128-bit value' unless s.is_a?(String) && HEX128.match?(s)

          s.to_i(16)
        end

        def decode_u(raw, m_ext)
          raise ArgumentError, 'bad extension message' unless raw.is_a?(Hash)

          cb = (m_ext + 7) / 8
          bytes = NetCodec.unb64(raw['u'], Ot::KAPPA * cb)
          u = Array.new(Ot::KAPPA) { |i| Otx.bytes_to_big(bytes.byteslice(i * cb, cb)) }
          Ot::ExtRoundMsg.new(u, hex128(raw['x']), hex128(raw['t']))
        end

        def encode_y(y0, y1) = { 'y0' => NetCodec.b64(y0.pack('Q<*')), 'y1' => NetCodec.b64(y1.pack('Q<*')) }

        def decode_y(raw, m)
          raise ArgumentError, 'bad ciphertext message' unless raw.is_a?(Hash)

          { y0: NetCodec.unb64(raw['y0'], m * 8).unpack('Q<*'), y1: NetCodec.unb64(raw['y1'], m * 8).unpack('Q<*') }
        end

        def pairs_b64(ps) = ps.map { |a, b| [NetCodec.b64(a), NetCodec.b64(b)] }

        def parse_pairs(raw, count, len)
          raise ArgumentError, 'bad pair array' unless raw.is_a?(Array) && raw.length == count

          raw.map do |p|
            raise ArgumentError, 'bad pair' unless p.is_a?(Array) && p.length == 2

            [NetCodec.unb64(p[0], len), NetCodec.unb64(p[1], len)]
          end
        end

        # runs the no-dealer offline phase for one party and returns its Protocol::Prep
        def run(args) = Run.new(args).run

        # one party's offline phase
        class Run
          def initialize(a)
            @a = a
            @mesh = a.mesh
            @id = a.id
            @n = a.n
            @k = a.keys
            @pp = a.partners
            @c = a.c
            @ex = a.exchange
            @beh = a.behavior
            @others = (0...@n).reject { |i| i == @id }
            @rng = Ot.secure_ot_random
            @frng = Field::SecureFieldRng.new
            # my pairwise verification key delta (non-zero, secret): the key that verifies every share the peers open to me
            @delta = @frng.next
            @delta = @frng.next while @delta.zero?
            @gadget = []
            @sid = Digest::SHA256.digest('atlas-pca-mpc/net-session/v2'.b + AtlasPca::Js.utf8(@mesh.session_id))
          end

          def fadd(a, b) = Field.fadd(a, b)
          def fsub(a, b) = Field.fsub(a, b)
          def fmul(a, b) = Field.fmul(a, b)

          # binding of the channel whose EXTENSION RECEIVER (= base-OT sender) is recv and extension sender is send
          def chan(recv, send, round) = Ot::BaseOtBinding.new(@sid, recv, send, round)

          # runs a check that may raise an OT error, turning it into an abort that names peer
          def ot_guard(peer, what)
            yield
          rescue NetWire::NetAbort
            raise
          rescue StandardError => e
            kind = e.is_a?(Ot::BaseOtAbort) || e.is_a?(Ot::MalOtAbort) || e.is_a?(Ec::PointValidationError) ? 'ot-check' : 'malformed'
            ne = NetWire::NetAbort.new(kind, peer, @id, "#{what}: #{e.message}")
            @mesh.fail(ne)
            raise ne
          end

          def run
            base_ots
            @gadget = Offline.gadget_from_seeds(
              @mesh.session_id,
              Gadget.agree_gadget_seeds(@mesh, @n, Gadget::Io.new(@ex, @a.bad))
            )
            my_bits = [@a.input.allow, *Thermometer.thermometer_encode(@a.input.t, T_M), *Thermometer.thermometer_encode(@a.input.r_quant, @a.q)]
            raise NetWire::NetAbort.new('local', nil, @id, 'input chain count mismatch') if my_bits.length != @c

            @alpha_enc = Array.new(@k) { Enc.sample_enc(@gadget, @frng) }
            input_value = share_inputs(my_bits)
            mask_share = @frng.next
            nt = (@n - 1) * @c
            a_enc = []
            b_s = []
            ah_enc = []
            nt.times do
              a_enc << Enc.sample_enc(@gadget, @frng)
              b_s << @frng.next
              ah_enc << Array.new(@pp) { Enc.sample_enc(@gadget, @frng) }
            end
            a_s = a_enc.map(&:value)
            ah_s = ah_enc.map { |row| row.map(&:value) }

            # ---- layer 1: products and the MACs of known values
            xs1 = []
            ys1 = []
            push1 = lambda do |x, y|
              xs1 << x
              ys1 << y
              xs1.length - 1
            end
            i_c = []
            i_ch = []
            i_ma = []
            i_mb = []
            i_mah = []
            nt.times do |t|
              i_c << push1.call(a_enc[t], b_s[t])
              i_ch << Array.new(@pp) { |r| push1.call(ah_enc[t][r], b_s[t]) }
              i_ma << @alpha_enc.map { |al| push1.call(al, a_s[t]) }
              i_mb << @alpha_enc.map { |al| push1.call(al, b_s[t]) }
              i_mah << Array.new(@pp) { |r| @alpha_enc.map { |al| push1.call(al, ah_s[t][r]) } }
            end
            i_in = input_value.map { |val| @alpha_enc.map { |al| push1.call(al, val) } }
            i_mask = @alpha_enc.map { |al| push1.call(al, mask_share) }
            keep_items = Set.new(i_c + i_ch.flatten)
            z1, kept1 = mul_layer('1', xs1, ys1, @beh&.kind == 'offline-lie' && !i_c.empty? ? i_c[0] : -1, keep_items)

            # ---- layer 2: the MACs of the products
            c_s = i_c.map { |i| z1[i] }
            ch_s = i_ch.map { |row| row.map { |i| z1[i] } }
            xs2 = []
            ys2 = []
            push2 = lambda do |x, y|
              xs2 << x
              ys2 << y
              xs2.length - 1
            end
            i_mc = []
            i_mch = []
            nt.times do |t|
              i_mc << @alpha_enc.map { |al| push2.call(al, c_s[t]) }
              i_mch << ch_s[t].map { |chv| @alpha_enc.map { |al| push2.call(al, chv) } }
            end
            z2, = mul_layer('2', xs2, ys2)

            # ---- assemble, then pairwise-tag every share
            pa = ->(x) { NetPa::PA.new(x, Array.new(@n, 0), Array.new(@n, 0)) }
            aw = ->(value, mac_idx, z) { NetPa::AW.new(pa.call(value), mac_idx.map { |i| pa.call(z[i]) }) }
            triples = Array.new(nt) do |t|
              sh = [aw.call(a_s[t], i_ma[t], z1), aw.call(b_s[t], i_mb[t], z1), aw.call(c_s[t], i_mc[t], z2)]
              @pp.times do |r|
                sh << aw.call(ah_s[t][r], i_mah[t][r], z1)
                sh << aw.call(ch_s[t][r], i_mch[t][r], z2)
              end
              raise NetWire::NetAbort.new('local', nil, @id, 'triple assembly mismatch') if sh.length != NetCodec.sharings_per_triple(@pp)

              sh
            end
            inputs = input_value.each_with_index.map { |val, q| aw.call(val, i_in[q], z1) }
            check_mask = aw.call(mask_share, i_mask, z1)
            alpha = @alpha_enc.map { |e| pa.call(e.value) }
            all_pa = alpha.dup
            [*triples.flatten, *inputs, check_mask].each do |w|
              all_pa << w.v
              all_pa.concat(w.m)
            end
            tags, keys = tag_layer(all_pa.map(&:x))
            all_pa.each_with_index do |x, u|
              @others.each do |p|
                x.tag[p] = tags[p][u]
                x.key[p] = keys[p][u]
              end
            end
            disclose = lambda do |t|
              slot = lambda do |item, x, z|
                NetForensics::SlotDisclosure.new(x.bits.dup, b_s[t], z, @others.to_h { |p| [p, kept1.recv[p][item]] },
                                                 @others.to_h { |p| [p, kept1.rho[p][item]] })
              end
              [slot.call(i_c[t], a_enc[t], c_s[t]), *i_ch[t].each_with_index.map { |item, r| slot.call(item, ah_enc[t][r], ch_s[t][r]) }]
            end
            Protocol::Prep.new('no-dealer', true, @delta, alpha, triples, inputs, my_bits.dup, check_mask,
                               Protocol::Forensics.new(@gadget, @gadget.length, 1 + @pp, disclose))
          end

          # the kappa base OTs of every ordered pair, both roles; ends with every extension sender holding its seeds
          def base_ots
            @recv_ch = {}
            @send_ch = {}
            seeds = {}
            my_setup = {}
            @selector = {}
            @others.each do |p|
              r = Ot::OtExtReceiver.new(@rng, Ot.binding_bytes(chan(@id, p, 'iknp-kos')))
              seeds[p] = r.make_seeds
              @recv_ch[p] = r
              my_setup[p] = Ot.mal_base_ot_sender_setup(@rng, chan(@id, p, 'offline-kappa'))
              s = Ot::OtExtSender.new(@rng, Ot.binding_bytes(chan(p, @id, 'iknp-kos')))
              @selector[p] = s.make_selector
              @send_ch[p] = s
            end
            their_s = @ex.call(
              'ob-S',
              lambda do |peer|
                st = my_setup[peer]
                z = @beh&.kind == 'ot-proof-lie' ? st.proof.z + 1 : st.proof.z
                { 'S' => NetCodec.pt_j(st.s), 'U' => NetCodec.pt_j(st.proof.u), 'z' => NetWire.hx(z) }
              end,
              lambda do |p, raw|
                @a.bad.call(p, 'bad S message') unless raw.is_a?(Hash)
                proof = Ec::SchnorrProof.new(NetCodec.j_pt(raw['U']), NetCodec.hex_big(raw['z']))
                { s: NetCodec.j_pt(raw['S']), proof: proof }
              end
            )
            respond = {}
            @others.each do |p|
              st = their_s[p]
              respond[p] = ot_guard(p, 'base OT (receiver)') do
                Ot.mal_base_ot_receiver_respond(st[:s], st[:proof], @selector[p], @rng, chan(p, @id, 'offline-kappa'))
              end
            end
            their_r = @ex.call(
              'ob-R', ->(peer) { respond[peer].r.map { |pt| NetCodec.pt_j(pt) } },
              lambda do |p, raw|
                return @a.bad.call(p, 'bad R array') unless raw.is_a?(Array) && raw.length == Ot::KAPPA

                raw.map { |pt| NetCodec.j_pt(pt) }
              end
            )
            enc = {}
            @others.each do |p|
              st = my_setup[p]
              enc[p] = ot_guard(p, 'base OT (sender)') do
                pads = Ot.mal_base_ot_sender_derive(st.y, st.t, their_r[p], st.s, chan(@id, p, 'offline-kappa'))
                Ot.base_ot_sender_encrypt(seeds[p], pads)
              end
            end
            their_ct = @ex.call(
              'ob-C', ->(peer) { { 'ct' => Offline.pairs_b64(enc[peer][0]), 'com' => Offline.pairs_b64(enc[peer][1]) } },
              lambda do |p, raw|
                return @a.bad.call(p, 'bad ciphertext message') unless raw.is_a?(Hash)

                { ct: Offline.parse_pairs(raw['ct'], Ot::KAPPA, 16), com: Offline.parse_pairs(raw['com'], Ot::KAPPA, 32) }
              end
            )
            @others.each do |p|
              m = their_ct[p]
              got = ot_guard(p, 'base OT (receiver)') { Ot.base_ot_receiver_decrypt(@selector[p], respond[p].recv_pads, m[:ct], m[:com]) }
              @send_ch[p].set_seeds(got)
            end
          end

          # split each of my bits into additive shares (a random share for every peer, the rest is mine), exchange them, and return
          # my value share of every (owner, chain)
          def share_inputs(my_bits)
            out_shares = {}
            @others.each { |p| out_shares[p] = Array.new(@c) { @frng.next } }
            my_own = my_bits.each_with_index.map do |b, ci|
              s = b
              @others.each { |p| s = fsub(s, out_shares[p][ci]) }
              s
            end
            got = @ex.call('in-share', ->(peer) { out_shares[peer].map { |x| NetWire.hx(x) } }, ->(p, raw) { @a.arr.call(p, raw, @c) })
            out = []
            @n.times { |o| @c.times { |ci| out << (o == @id ? my_own[ci] : got[o][ci]) } }
            out
          end

          # The Gilboa OT core. For every peer p: as the OT RECEIVER towards p I choose with the bits of my xs[t] and get
          # recv[p][t] = x_t*y^p_t + sum rho^p_t; as the OT SENDER towards p I offer (rho_k, rho_k + gad_k*y) with fresh masks and keep
          # send_sum[p][t] = sum rho. So recv[p][t] - send_sum^p[t] over the pair is an additive sharing of x_t*y_t.
          def ot_rows(layer, items, keep = nil)
            t_n = items.length
            recv = {}
            send_sum = {}
            kept = Kept.new({}, {})
            @others.each do |p|
              recv[p] = Array.new(t_n, 0)
              send_sum[p] = Array.new(t_n, 0)
              kept.recv[p] = {}
              kept.rho[p] = {}
            end
            return [recv, send_sum, kept] if t_n.zero? || @others.empty?

            rows = items.sum { |it| it.bits.length }
            row_item = Array.new(rows)
            choice = Array.new(rows)
            m0 = {}
            m1 = {}
            @others.each do |p|
              m0[p] = Array.new(rows)
              m1[p] = Array.new(rows)
            end
            off = 0
            item_off = Array.new(t_n)
            t_n.times do |t|
              it = items[t]
              len = it.bits.length
              item_off[t] = off
              @others.each { |p| kept.recv[p][t] = Array.new(len, 0) } if keep&.include?(t)
              len.times do |k|
                choice[off + k] = it.bits[k]
                row_item[off + k] = t
              end
              @others.each do |p|
                a0 = m0[p]
                a1 = m1[p]
                sum_rho = 0
                len.times do |k|
                  rho = @frng.next
                  sum_rho = fadd(sum_rho, rho)
                  a0[off + k] = rho
                  a1[off + k] = fadd(rho, fmul(it.gad[k], it.y))
                end
                send_sum[p][t] = sum_rho
                kept.rho[p][t] = a0[off, len] if keep&.include?(t)
              end
              off += len
            end
            chunk = 0
            start = 0
            while start < rows
              m = [rows, start + ROWS_PER_ROUND].min - start
              m_ext = m + Ot::KAPPA + Ot::SSEC
              tag = "ox#{layer}.#{chunk}"
              if @beh&.kind == 'ot-u-lie'
                # an inconsistent matrix: flip the first row in 64 of the 128 columns only (not a different choice vector)
                @others.each { |p| @recv_ch[p].tamper_u = ->(u, _round) { 64.times { |i| u[i] ^= 1 } } }
              end
              begun = {}
              @others.each { |p| begun[p] = @recv_ch[p].begin_round(choice[start, m]) }
              us = @ex.call("#{tag}.u", ->(peer) { Offline.encode_u(begun[peer].msg, m_ext) }, ->(_p, raw) { Offline.decode_u(raw, m_ext) })
              resp = {}
              @others.each do |p|
                resp[p] = ot_guard(p, "OT extension (#{tag})") { @send_ch[p].respond(us[p], m0[p][start, m], m1[p][start, m]) }
              end
              cts = @ex.call("#{tag}.y", ->(peer) { Offline.encode_y(resp[peer].y0, resp[peer].y1) }, ->(_p, raw) { Offline.decode_y(raw, m) })
              @others.each do |p|
                got = ot_guard(p, "OT extension (#{tag})") { @recv_ch[p].finish(begun[p].pending, cts[p][:y0], cts[p][:y1]) }
                rv = recv[p]
                m.times do |j|
                  t = row_item[start + j]
                  v = Field.mod(got[j])
                  rv[t] = fadd(rv[t], v)
                  kept.recv[p][t][start + j - item_off[t]] = v if keep&.include?(t)
                end
              end
              start += ROWS_PER_ROUND
              chunk += 1
            end
            [recv, send_sum, kept]
          end

          # Given my shares xs[t] of X_t and ys[t] of Y_t, my additive share of X_t*Y_t = (sum x)(sum y): the diagonal x_i*y_i locally
          # plus, for every ordered pair, the Gilboa OT product of one party's x with the other's y.
          def mul_layer(layer, xs, ys, lie_at = -1, keep = nil)
            z = xs.each_with_index.map { |x, t| fmul(x.value, ys[t]) }
            items = xs.each_with_index.map { |x, t| Item.new(x.bits, @gadget, t == lie_at ? fadd(ys[t], 1) : ys[t]) }
            recv, send_sum, kept = ot_rows(layer, items, keep)
            @others.each do |p|
              rv = recv[p]
              ss = send_sum[p]
              z.each_index { |t| z[t] = fsub(fadd(z[t], rv[t]), ss[t]) }
            end
            [z, kept]
          end

          # Pairwise tags for my shares xs: for every peer j, a tag T_ij (mine) and a key K_ji (for verifying j's share of the same
          # item) with T_ij = K_ij + delta_j * x_i. A tag operand is an arbitrary derived value with no uniform choice-bit encoding of
          # its own, so each x is split as x = e + d with a fresh encoded e and d = x - e; both halves are multiplied with delta.
          def tag_layer(xs)
            items = []
            xs.each do |x|
              e = Enc.sample_enc(@gadget, @frng)
              d = Enc.plain_share(fsub(x, e.value))
              items << Item.new(e.bits, @gadget, @delta)
              items << Item.new(d.bits, Enc.plain_gadget, @delta)
            end
            recv, send_sum, = ot_rows('3', items)
            tag = {}
            key = {}
            @others.each do |p|
              r = recv[p]
              k = send_sum[p]
              tag[p] = xs.each_index.map { |u| fadd(r[2 * u], r[(2 * u) + 1]) }
              key[p] = xs.each_index.map { |u| fadd(k[2 * u], k[(2 * u) + 1]) }
            end
            [tag, key]
          end
        end
      end
    end
  end
end
