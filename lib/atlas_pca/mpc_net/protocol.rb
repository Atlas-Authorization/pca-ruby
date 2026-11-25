# frozen_string_literal: true

require 'digest'
require 'securerandom'
require_relative '../mpc_net'
require_relative '../mpc_spdz'
require_relative 'mesh'
require_relative 'forensics'

module AtlasPca
  module Mpc
    module Net
      # The DISTRIBUTED malicious-with-abort (SPDZ-style) composition protocol (research prototype). Same circuit and semantics as
      # Spdz composition in one process (allow = AND, t = MAX, r = MAX via thermometers; authenticated Beaver multiplication; batched
      # MAC-check before any output), but each party is its OWN process holding ONLY its own shares, and every opening is a real
      # message over the TLS mesh. Rounds (n parties, C = 1 + 3 + Q independent chains, k = MAC_KEYS global keys):
      #
      #   prep      dealer -> party: [TRUSTED-DEALER mode] key shares, sacrificed-triple material, input masks, pairwise tags
      #             (or, in NO-DEALER mode, the OT-based offline phase of offline.rb runs here instead)
      #   coin1-*   all-to-all: commit/open of a random seed -> public challenges for the triple sacrifice
      #   sac-rho   all-to-all: value shares of rho = e*a - a-hat for every triple and sacrifice partner
      #   sac-tau   all-to-all: value shares of tau = e*c - c-hat - rho*b; every tau must be 0
      #   inputs    all-to-all: [dealer mode] owner broadcasts x - r
      #   in-check  all-to-all: [no-dealer mode] opening of a masked random combination of the inputs
      #   mul0..    all-to-all: value shares of d = x-a, e = y-b for all C chains at once (n-1 rounds)
      #   out       all-to-all: value shares of the C output bits
      #   <rd>.t    all-to-all: after every opening, the pairwise tags: each receiver verifies the sender's opened shares at once
      #   coin-c/o  all-to-all: commit/open of a random seed -> public MAC-check challenges
      #   sig-c/o   all-to-all: commit/open of each party's MAC residual shares (one per key); sums must be 0
      #   digest    all-to-all: hash of the whole broadcast transcript; any disagreement aborts
      #   blame     all-to-all: [only after a MAC-check failure] MAC shares with their pairwise tags; names the inconsistent party
      #
      # No output is decoded until the MAC-check and the transcript echo pass. HONEST LIMITS: there is no security proof for this
      # implementation; the echo-broadcast is a hash exchange, not a Byzantine agreement; the trusted dealer is trusted for privacy.
      module Protocol
        T_M = 3
        DEFAULT_Q = 100
        PREP_CHUNK = 30_000 # hex numbers per prep frame (keeps every frame far below the frame cap)
        MASK61 = (1 << 61) - 1
        HEX64 = /\A[0-9a-f]{64}\z/
        W = NetWire

        # thrown by the test-only silent behaviour; the host process then idles with its sockets open
        class SilentParty < StandardError
          def initialize = super('silent')
        end

        # Test-only protocol-level misbehaviour for a (malicious) party. Never set in production. kind is one of
        # open-lie, mac-lie, bad-tag, sigma-lie, offline-lie, ot-u-lie, ot-proof-lie, equivocate, bad-coin-open, bad-sigma-open,
        # short-array, noncanonical, crash, silent; round names the round it acts in (where it applies).
        Behavior = Struct.new(:kind, :round, keyword_init: true)
        BEHAVIOR_KINDS = %w[open-lie mac-lie bad-tag sigma-lie offline-lie ot-u-lie ot-proof-lie equivocate bad-coin-open bad-sigma-open
                            short-array noncanonical crash silent].freeze

        RoundStat = Struct.new(:rd, :ms, :bytes_out, :bytes_in)
        PartyResult = Struct.new(:id, :n, :q, :composed, :rounds, :transcript_digest, :wall_ms, :multiplications, :opens, :offline_mode,
                                 :mac_keys, :sacrificed_triples, :sacrifice_partners, :identifiable_abort)
        # kind trusted-dealer | no-dealer; forensics (no-dealer only) is Forensics
        Prep = Struct.new(:mode, :tagged, :delta, :alpha, :triples, :inputs, :my_plain, :check_mask, :forensics)
        # gadget: the public choice-bit gadget; rows: choice bits per product item; slots: product slots per triple;
        # disclose: proc(t) -> my disclosure of triple t
        Forensics = Struct.new(:gadget, :rows, :slots, :disclose)
        Opened = Struct.new(:val, :mac)

        # insecure_trusted_dealer: required true (the dealer sees every share and MAC key); seed: deterministic stream for
        # reproducible tests; fault / mac_fault_at_input: TEST ONLY lying dealer
        DealerConfig = Struct.new(:insecure_trusted_dealer, :n, :q, :mesh, :seed, :fault, :mac_fault_at_input, keyword_init: true)
        # dealer_id default n; offline default 'no-dealer'; behavior TEST ONLY and refused unless unsafe_test_hooks is true;
        # forensic_deadline_ms default 30 s
        PartyConfig = Struct.new(:id, :n, :q, :input, :mesh, :dealer_id, :offline, :insecure_trusted_dealer, :behavior, :unsafe_test_hooks,
                                 :session_id, :forensic_deadline_ms, keyword_init: true)

        module_function

        # number of independent circuit chains (= output bits = input bits per owner)
        def chain_count(q) = 1 + T_M + q

        def prep_layout(n, c, keys, partners, tagged)
          aw = NetPa.aw_width(n, keys, tagged)
          triples = (n - 1) * c
          inputs = n * c
          { nums: (tagged ? 1 : 0) + (keys * NetPa.pa_width(n, tagged)) + (triples * NetCodec.sharings_per_triple(partners) * aw) + (inputs * aw) + c,
            triples: triples, inputs: inputs }
        end

        # ---------------------------------------------------------------------------------- dealer

        # The TRUSTED DEALER role: samples the MAC keys, the verification keys, sacrifice-certified authenticated triples and
        # authenticated input masks, and ships each party only its own slice. It never sees any party's input bit, but it knows every
        # key and share, so it can break privacy/integrity if it colludes with parties. A dealer that deals a wrong triple is caught
        # by the parties' sacrifice check.
        def run_dealer(cfg)
          n = cfg.n
          mesh = cfg.mesh
          unless cfg.insecure_trusted_dealer == true
            raise ArgumentError, 'run_dealer requires insecure_trusted_dealer: true (a dealer sees every share and MAC key; the default offline phase has no dealer)'
          end

          q = cfg.q || DEFAULT_Q
          rng = cfg.seed.nil? ? Field::SecureFieldRng.new : Field::FieldRng.new(cfg.seed)
          c = chain_count(q)
          ctx = Spdz.setup_mac(n, rng, Spdz::MAC_KEYS)
          keys = Spdz.mac_keys(ctx)
          deltas = Array.new(n) do
            d = rng.next
            d = rng.next while d.zero?
            d
          end

          # deal the pairwise tags/keys for one sharing x_0..x_{n-1}: T_ij = K_ij + delta_j * x_i
          deal_pa = lambda do |x|
            k = x.each_index.map { |i| x.each_index.map { |j| i == j ? 0 : rng.next } }
            x.each_with_index.map do |xi, p|
              NetPa::PA.new(xi, x.each_index.map { |j| j == p ? 0 : Field.fadd(k[p][j], Field.fmul(deltas[j], xi)) },
                            x.each_index.map { |j| j == p ? 0 : k[j][p] })
            end
          end
          deal_aw = lambda do |sv|
            comps = [sv.value, sv.mac, *sv.extra_mac].map { |comp| deal_pa.call(comp) }
            Array.new(n) { |p| NetPa::AW.new(comps[0][p], comps[1..].map { |comp| comp[p] }) }
          end

          per_party = Array.new(n) { |p| [deltas[p]] }
          alpha_pa = keys.map { |k| deal_pa.call(k.alpha_shares) }
          n.times { |p| alpha_pa.each { |a| per_party[p].concat(NetPa.pa_flat(a[p], p, n, true)) } }

          (((n - 1) * c)).times do
            tr = Spdz.gen_triple_with_partners(ctx, rng, Spdz::SACRIFICE_PARTNERS, cfg.fault)
            sharings = [tr.keep.a, tr.keep.b, tr.keep.c, *tr.partners.flat_map { |pt| [pt.a, pt.c] }]
            sharings.each do |sv|
              aws = deal_aw.call(sv)
              n.times { |p| per_party[p].concat(NetPa.aw_flat(aws[p], p, n, true)) }
            end
          end
          masks_by_owner = Array.new(n) { [] }
          (n * c).times do |qi|
            owner = qi / c
            r = rng.next
            masks_by_owner[owner] << r
            sv = Spdz.auth_share(r, ctx, rng)
            sv.mac[0] = Field.fadd(sv.mac[0], 1) if cfg.mac_fault_at_input == qi
            aws = deal_aw.call(sv)
            n.times { |p| per_party[p].concat(NetPa.aw_flat(aws[p], p, n, true)) }
          end
          n.times { |p| per_party[p].concat(masks_by_owner[p]) }

          n.times do |p|
            nums = per_party[p].map { |v| W.hx(v) }
            chunks = [1, (nums.length.to_f / PREP_CHUNK).ceil].max
            mesh.send_to(p, 'prep', { 'total' => nums.length, 'chunks' => chunks, 'nums' => nums[0, PREP_CHUNK] })
            (1...chunks).each { |ci| mesh.send_to(p, "prep.#{ci}", nums[ci * PREP_CHUNK, PREP_CHUNK] || []) }
          end
          mesh.finish
        end

        # ---------------------------------------------------------------------------------- party

        # runs one party to completion and returns its PartyResult, or raises the attributable NetAbort
        def run_party(cfg) = PartyRun.new(cfg).run

        def sha(*parts)
          d = Digest::SHA256.new
          parts.each do |p|
            d.update(p.is_a?(String) ? p.b : p.to_s.b)
            d.update("\0")
          end
          d.digest
        end

        # uniform non-zero field element j of the public challenge stream label derived from seed (rejection on p)
        def challenge(seed, label, j)
          ctr = 0
          loop do
            x = sha('chal', seed, "#{label}:#{j}:#{ctr}").byteslice(0, 8).unpack1('Q>') & MASK61
            return x if x < Field::PRIME && !x.zero?

            ctr += 1
          end
        end

        # one party's run (state lives in instance variables; the phases are methods)
        class PartyRun
          def initialize(cfg)
            @cfg = cfg
            @id = cfg.id
            @n = cfg.n
            @mesh = cfg.mesh
            @sid = cfg.session_id
            @q = cfg.q || DEFAULT_Q
            @dealer_id = cfg.dealer_id || @n
            @offline_mode = cfg.offline || 'no-dealer'
            @c = Protocol.chain_count(@q)
            @k = Spdz::MAC_KEYS
            @pp = Spdz::SACRIFICE_PARTNERS
            @beh = cfg.behavior
            unless %w[trusted-dealer no-dealer].include?(@offline_mode)
              raise W::NetAbort.new('local', nil, @id, "unknown offline mode #{@offline_mode.inspect}")
            end
            if @offline_mode == 'trusted-dealer' && cfg.insecure_trusted_dealer != true
              raise W::NetAbort.new('local', nil, @id, "offline 'trusted-dealer' requires insecure_trusted_dealer: true (the dealer sees every share and key); the default is 'no-dealer'")
            end
            raise W::NetAbort.new('local', nil, @id, 'the behavior test hook requires unsafe_test_hooks: true (test-only)') if @beh && cfg.unsafe_test_hooks != true
            if @beh && !BEHAVIOR_KINDS.include?(@beh.kind)
              raise W::NetAbort.new('local', nil, @id, "unknown behavior #{@beh.kind.inspect}")
            end
            raise W::NetAbort.new('local', nil, @id, 'n must be >= 1') unless @n.is_a?(Integer) && @n >= 1

            v = cfg.input
            unless v && [0, 1].include?(v.allow) && [1, 2, 3].include?(v.t) && v.r_quant.is_a?(Integer) && v.r_quant >= 0 && v.r_quant <= @q
              raise W::NetAbort.new('local', nil, @id, 'invalid decision vector')
            end

            @input = v
            @others = (0...@n).reject { |i| i == @id }
            @rounds = []
            @transcript = Digest::SHA256.new
            @opened = []
          end

          def now_ms = Process.clock_gettime(Process::CLOCK_MONOTONIC) * 1000

          def totals
            o = i = 0
            @mesh.stats.each do |s|
              o += s.app_bytes_out
              i += s.app_bytes_in
            end
            [o, i]
          end

          def crash_if(rd)
            exit!(7) if @beh&.kind == 'crash' && @beh.round == rd
            raise SilentParty if @beh&.kind == 'silent' && @beh.round == rd
          end

          # one all-to-all round among the parties: send mine(peer) to each peer, collect and validate theirs. hashed = false keeps
          # a round (the peer-specific pairwise tags) out of the echoed transcript.
          def exchange(rd, mine, parse, common, hashed = true, timeout_ms = nil)
            crash_if(rd)
            a = totals
            s = now_ms
            @others.each { |p| @mesh.send_to(p, rd, mine.call(p)) }
            raw = @mesh.collect(rd, @others, timeout_ms)
            parsed = {}
            @others.each do |p|
              parsed[p] = parse.call(p, raw[p])
            rescue W::NetAbort => e
              @mesh.fail(e)
              raise
            rescue StandardError => e
              ne = W::NetAbort.new('malformed', p, @id, "round '#{rd}': #{e.message}")
              @mesh.fail(ne)
              raise ne
            end
            if hashed
              # transcript: party order, canonical JSON of what each party broadcast in this round
              @transcript.update(rd)
              @n.times do |p|
                @transcript.update("|#{p}:")
                @transcript.update(Js.json(p == @id ? common : raw[p]))
              end
            end
            b = totals
            @rounds << RoundStat.new(rd, now_ms - s, b[0] - a[0], b[1] - a[1])
            parsed
          end

          def bad(p, what) = raise(W::NetAbort.new('malformed', p, @id, what))
          def arr(p, raw, len) = W.unhx_array(raw, len) || bad(p, "expected #{len} canonical field elements")

          def abort_with(e)
            @mesh.fail(e)
            raise e
          end

          def hx(x) = W.hx(x)
          def fadd(a, b) = Field.fadd(a, b)
          def fsub(a, b) = Field.fsub(a, b)
          def fmul(a, b) = Field.fmul(a, b)

          def run
            t0 = now_ms
            crash_if('prep')
            prep_start = now_ms
            before = totals
            if @offline_mode == 'trusted-dealer'
              @prep = receive_dealer_prep
            else
              require_relative 'offline'
              @prep = Offline.run(
                Offline::Args.new(
                  mesh: @mesh, id: @id, n: @n, c: @c, keys: @k, partners: @pp, session_id: @sid, input: @input, q: @q, behavior: @beh,
                  exchange: ->(rd, mine, parse) { exchange(rd, mine, parse, nil, false) },
                  bad: ->(p, what) { bad(p, what) }, arr: ->(p, raw, len) { arr(p, raw, len) }
                )
              )
            end
            after = totals
            @rounds << RoundStat.new('prep', now_ms - prep_start, after[0] - before[0], after[1] - before[1])

            @env = NetPa::PaEnv.new(@id, @n, @prep.delta, @prep.tagged)
            sacrifice
            bit_share = input_shares
            outs, mults = online(bit_share)
            joint = coin('coin', true)
            digest, aw_state = mac_check(joint)
            finish_blame(aw_state) if aw_state[:failed]
            decode_and_finish(outs, mults, digest, t0)
          end

          def add_pub(x, c) = NetPa.w_add_public(@env, x, c, @prep.alpha)
          def not_(x) = add_pub(NetPa.w_neg(x), 1)

          # ---- offline phase from the trusted dealer ----
          def receive_dealer_prep
            lay = Protocol.prep_layout(@n, @c, @k, @pp, true)
            first = @mesh.recv(@dealer_id, 'prep')
            nums = []
            begin
              first = {} unless first.is_a?(Hash)
              bad(@dealer_id, 'bad prep size') unless first['total'].is_a?(Integer) && first['total'] == lay[:nums]
              want_chunks = [1, (lay[:nums].to_f / PREP_CHUNK).ceil].max
              bad(@dealer_id, 'bad prep chunk count') unless first['chunks'].is_a?(Integer) && first['chunks'] == want_chunks
              take = ->(raw, len) { W.unhx_array(raw, len) || bad(@dealer_id, 'bad prep numbers') }
              nums = take.call(first['nums'], [PREP_CHUNK, lay[:nums]].min)
              (1...first['chunks']).each do |ci|
                part = @mesh.recv(@dealer_id, "prep.#{ci}")
                nums += take.call(part, [PREP_CHUNK, lay[:nums] - (ci * PREP_CHUNK)].min)
              end
            rescue W::NetAbort => e
              abort_with(e)
            rescue StandardError => e
              abort_with(W::NetAbort.new('malformed', @dealer_id, @id, e.message))
            end
            o = 0
            delta = nums[o]
            o += 1
            abort_with(W::NetAbort.new('dealer', @dealer_id, @id, 'the dealer gave me a zero verification key')) if delta.zero?
            w = NetPa.pa_width(@n, true)
            alpha = Array.new(@k) do
              pa = NetPa.pa_parse(nums, o, @id, @n, true)
              o += w
              pa
            end
            aw = NetPa.aw_width(@n, @k, true)
            triples = Array.new(lay[:triples]) do
              Array.new(NetCodec.sharings_per_triple(@pp)) do
                x = NetPa.aw_parse(nums, o, @id, @n, @k, true)
                o += aw
                x
              end
            end
            inputs = Array.new(lay[:inputs]) do
              x = NetPa.aw_parse(nums, o, @id, @n, @k, true)
              o += aw
              x
            end
            Prep.new('trusted-dealer', true, delta, alpha, triples, inputs, nums[o, @c])
          end

          # open authenticated values: broadcast value shares, verify pairwise tags, record for the MAC-check
          def open_many(rd, ws)
            send_vals = ws.map { |x| x.v.x }
            macs = ws.map(&:m)
            if @beh && @beh.round == rd
              send_vals = send_vals.each_with_index.map { |x, i| i.zero? ? fadd(x, 1) : x } if @beh.kind == 'open-lie'
              if @beh.kind == 'mac-lie'
                macs[0] = macs[0].each_with_index.map { |pa, l| l.zero? ? NetPa::PA.new(fadd(pa.x, 1), pa.tag, pa.key) : pa }
              end
            end
            common = send_vals.map { |x| hx(x) }
            mine_fn = lambda do |peer|
              if @beh&.kind == 'equivocate' && @beh.round == rd && peer == @others[0]
                common.each_with_index.map { |s, i| i.zero? ? hx(fadd(s.to_i(16), 1)) : s }
              elsif @beh&.kind == 'short-array' && @beh.round == rd
                common[1..]
              elsif @beh&.kind == 'noncanonical' && @beh.round == rd
                common.each_with_index.map { |s, i| i.zero? ? hx(Field::PRIME) : s }
              else
                common
              end
            end
            got = exchange(rd, mine_fn, ->(p, raw) { arr(p, raw, ws.length) }, common)
            if @prep.tagged
              # pairwise tags: peer-specific, so a separate un-echoed round; each receiver verifies at once
              tag_msg = lambda do |peer|
                ws.each_with_index.map do |x, i|
                  hx(@beh&.kind == 'bad-tag' && @beh.round == rd && i.zero? ? fadd(x.v.tag[peer], 1) : x.v.tag[peer])
                end
              end
              tags = exchange("#{rd}.t", tag_msg, ->(p, raw) { arr(p, raw, ws.length) }, nil, false)
              @others.each do |p|
                ws.each_index do |i|
                  next if NetPa.pa_verify(@env, ws[i].v, p, got[p][i], tags[p][i])

                  abort_with(W::NetAbort.new('mac-check', p, @id,
                                             "pairwise MAC on party #{p}'s opened share failed in round '#{rd}' (index #{i}): the share or its tag is not what the dealer issued"))
                end
              end
            end
            Array.new(ws.length) do |i|
              sum = send_vals[i]
              @others.each { |p| sum = fadd(sum, got[p][i]) }
              @opened << Opened.new(sum, macs[i])
              sum
            end
          end

          # coin flip (commit / open of a random seed) -> a joint public seed
          def coin(label, tamper_open)
            my_seed = SecureRandom.random_bytes(32)
            seed_commit = Protocol.sha('seed', @sid, label, @id.to_s, my_seed).unpack1('H*')
            seed_commits = exchange(
              "#{label}-c", ->(_p) { seed_commit },
              ->(p, raw) { raw.is_a?(String) && HEX64.match?(raw) ? raw : bad(p, 'bad commitment') },
              seed_commit
            )
            open_msg = ->(_p) { tamper_open && @beh&.kind == 'bad-coin-open' ? SecureRandom.hex(32) : my_seed.unpack1('H*') }
            seeds = exchange(
              "#{label}-o", open_msg,
              lambda do |p, raw|
                return bad(p, 'bad seed') unless raw.is_a?(String) && HEX64.match?(raw)

                sd = [raw].pack('H*')
                if Protocol.sha('seed', @sid, label, p.to_s, sd).unpack1('H*') != seed_commits[p]
                  raise W::NetAbort.new('commitment', p, @id, "party #{p} opened a coin seed that does not match its commitment")
                end

                sd
              end,
              my_seed.unpack1('H*')
            )
            Protocol.sha('joint', @sid, label, *Array.new(@n) { |p| p == @id ? my_seed : seeds[p] })
          end

          # sacrifice: certify every triple against its partners before it is used
          def sacrifice
            nt = @prep.triples.length
            return if nt.zero?

            joint1 = coin('coin1', false)
            # a peer that detects the failed sacrifice sends its tau share and disclosures and then its abort claim back to back; the claim is read in link order, after every frame that peer sent before it, so this party finishes its OWN verified detection instead of reporting the peer's unverified accusation
            @mesh.set_defer_aborts(true)
            idx = ->(t, r) { (t * @pp) + r }
            rho_w = []
            nt.times do |t|
              a, _b, _c, *parts = @prep.triples[t]
              @pp.times do |r|
                e = Protocol.challenge(joint1, 'sac', idx.call(t, r))
                rho_w << NetPa.w_sub(NetPa.w_scale(a, e), parts[2 * r])
              end
            end
            rho = open_many('sac-rho', rho_w)
            tau_w = []
            nt.times do |t|
              _a, b, c, *parts = @prep.triples[t]
              @pp.times do |r|
                e = Protocol.challenge(joint1, 'sac', idx.call(t, r))
                tau_w << NetPa.w_sub(NetPa.w_sub(NetPa.w_scale(c, e), parts[(2 * r) + 1]), NetPa.w_scale(b, rho[idx.call(t, r)]))
              end
            end
            tau = open_many('sac-tau', tau_w)
            bad_at = tau.index { |x| x != 0 }
            if bad_at.nil?
              @mesh.set_defer_aborts(false)
              return
            end

            # dealer-free mode: the triple is discarded, so its OT transcript can be disclosed and audited to name a party that fed a
            # wrong operand into a triple product. Every honest party reaches this point together.
            attributed = nil
            note = ''
            fx = @prep.mode == 'no-dealer' ? @prep.forensics : nil
            if fx
              bt = bad_at / @pp
              mine = fx.disclose.call(bt)
              got = Forensic.exchange_disclosures(
                Forensic::ExchangeArgs.new(
                  session_id: @sid, id: @id, n: @n, triple_index: bt, mine: mine, slots: fx.slots, rows: fx.rows,
                  deadline_ms: @cfg.forensic_deadline_ms || NetForensics::DEFAULT_FORENSIC_DEADLINE_MS,
                  exchange: ->(rd, m, parse, t) { exchange(rd, m, parse, nil, false, t) }, bad: ->(p, what) { bad(p, what) }
                )
              )
              all = { @id => mine }.merge(got)
              res = NetForensics.audit_disclosures(all, fx.gadget)
              attributed = NetForensics.blame_from(@id, res)
              note = if attributed.nil?
                       " (OT transcript audit: #{res.pair_bad.length} inconsistent pair(s), no party can be named from this view: a pair failure between two other parties is not evidence against either of them to me)"
                     else
                       " (OT transcript audit names party #{attributed})"
                     end
            end
            dealer = @prep.mode == 'trusted-dealer'
            abort_with(
              W::NetAbort.new(
                dealer ? 'dealer' : 'mac-check', dealer ? @dealer_id : (attributed || (@n == 2 ? 1 - @id : nil)), @id,
                "triple sacrifice FAILED at triple #{bad_at / @pp} (partner #{bad_at % @pp}): c != a*b in the offline material; aborting with no output#{note}",
                nil, nil,
                "the triple sacrifice failed in dealer-free mode and the OT transcript audit of this party's own view names no one (a failing pair that does not involve me is not evidence I can use, and an accusation is never accepted against a third party)"
              )
            )
          end

          # inputs: bit k of owner o is the C-vector [allow, t-therm(3), r-therm(Q)]; returns proc(owner, k) -> AW
          def input_shares
            my_bits = [@input.allow, *Thermometer.thermometer_encode(@input.t, T_M), *Thermometer.thermometer_encode(@input.r_quant, @q)]
            if @prep.mode == 'trusted-dealer'
              masked = my_bits.each_with_index.map { |b, k| fsub(b, @prep.my_plain[k]) }
              masked_msg = masked.map { |x| hx(x) }
              got_masked = exchange('inputs', ->(_p) { masked_msg }, ->(p, raw) { arr(p, raw, @c) }, masked_msg)
              lambda do |owner, k|
                pub = owner == @id ? masked[k] : got_masked[owner][k]
                add_pub(@prep.inputs[(owner * @c) + k], pub)
              end
            else
              # no-dealer: the inputs are already authenticated sharings of the bits. Run the input-consistency check: open a random
              # masked combination (the opening joins the batched MAC-check below).
              joint_in = coin('coin-in', false)
              w = @prep.check_mask
              (@n * @c).times { |qi| w = NetPa.w_add(w, NetPa.w_scale(@prep.inputs[qi], Protocol.challenge(joint_in, 'in', qi))) }
              open_many('in-check', [w])
              ->(owner, k) { @prep.inputs[(owner * @c) + k] }
            end
          end

          # chains: acc_c over owners; allow uses AND, others OR (= NOT AND NOT); returns [opened output values, multiplications]
          def online(bit_share)
            is_or = ->(ci) { ci != 0 }
            acc = Array.new(@c) do |ci|
              b0 = bit_share.call(0, ci)
              is_or.call(ci) ? not_(b0) : b0
            end
            mults = 0
            (1...@n).each do |s|
              trs = Array.new(@c) { |ci| @prep.triples[((s - 1) * @c) + ci] }
              ys = Array.new(@c) do |ci|
                b = bit_share.call(s, ci)
                is_or.call(ci) ? not_(b) : b
              end
              ds = acc.each_with_index.map { |x, ci| NetPa.w_sub(x, trs[ci][0]) }
              es = ys.each_with_index.map { |y, ci| NetPa.w_sub(y, trs[ci][1]) }
              pub = open_many("mul#{s - 1}", ds + es)
              acc = Array.new(@c) do |ci|
                d = pub[ci]
                e = pub[@c + ci]
                ta, tb, tc = trs[ci][0], trs[ci][1], trs[ci][2]
                z = NetPa.w_add(tc, NetPa.w_add(NetPa.w_scale(tb, d), NetPa.w_scale(ta, e)))
                add_pub(z, fmul(d, e))
              end
              mults += @c
            end
            # outputs: allow as-is; or-chains are NOT of the product
            out_shares = acc.each_with_index.map { |x, ci| is_or.call(ci) ? not_(x) : x }
            [open_many('out', out_shares), mults]
          end

          def chal(joint, l, j) = Protocol.challenge(joint, "mac#{l}", j)

          # the batched MAC-check: coin-flip for the challenges, one independent challenge vector per key, commit/open of the
          # residuals, then the transcript echo. Returns [digest, state].
          def mac_check(joint)
            @joint = joint
            a_pub = Array.new(@k) do |l|
              a = 0
              @opened.each_with_index { |o, j| a = fadd(a, fmul(chal(joint, l, j), o.val)) }
              a
            end
            @a_pub = a_pub
            @gamma = Array.new(@k) do |l|
              g = 0
              @opened.each_with_index { |o, j| g = fadd(g, fmul(chal(joint, l, j), o.mac[l].x)) }
              g
            end
            sigma = @gamma.each_with_index.map { |g, l| fsub(g, fmul(@prep.alpha[l].x, a_pub[l])) }
            sig_nonce = SecureRandom.random_bytes(32)
            sig_commit = ->(p, s, nonce) { Protocol.sha('sigma', @sid, p.to_s, s.map { |x| hx(x) }.join(','), nonce).unpack1('H*') }
            sigma_sent = @beh&.kind == 'sigma-lie' ? sigma.each_with_index.map { |s, l| l.zero? ? fadd(s, 1) : s } : sigma
            my_sig_commit = sig_commit.call(@id, sigma_sent, sig_nonce)
            sig_commits = exchange(
              'sig-c', ->(_p) { my_sig_commit },
              ->(p, raw) { raw.is_a?(String) && HEX64.match?(raw) ? raw : bad(p, 'bad commitment') },
              my_sig_commit
            )
            my_sig_open = { 's' => sigma_sent.map { |x| hx(x) }, 'nonce' => sig_nonce.unpack1('H*') }
            open_msg = lambda do |_p|
              next my_sig_open unless @beh&.kind == 'bad-sigma-open'

              { 's' => sigma_sent.each_with_index.map { |s, l| hx(l.zero? ? fadd(s, 1) : s) }, 'nonce' => my_sig_open['nonce'] }
            end
            @sig_opens = exchange(
              'sig-o', open_msg,
              lambda do |p, raw|
                o = raw.is_a?(Hash) ? raw : {}
                sv = W.unhx_array(o['s'], @k)
                return bad(p, 'bad sigma opening') if sv.nil? || !o['nonce'].is_a?(String) || !HEX64.match?(o['nonce'])

                if sig_commit.call(p, sv, [o['nonce']].pack('H*')) != sig_commits[p]
                  raise W::NetAbort.new('commitment', p, @id, "party #{p} opened a MAC residual that does not match its commitment")
                end

                sv
              end,
              my_sig_open
            )
            residual = Array.new(@k) do |l|
              r = sigma_sent[l]
              @others.each { |p| r = fadd(r, @sig_opens[p][l]) }
              r
            end
            mac_failed = residual.any? { |r| r != 0 }

            # transcript echo: everyone must have seen the same broadcasts (also fixes the sigma data for the blame)
            digest = @transcript.dup.hexdigest
            digests = exchange(
              'digest', ->(_p) { digest },
              ->(p, raw) { raw.is_a?(String) && HEX64.match?(raw) ? raw : bad(p, 'bad digest') },
              digest
            )
            @others.each do |p|
              next if digests[p] == digest

              abort_with(W::NetAbort.new('equivocation', p, @id, "transcript digest of party #{p} differs from mine (a broadcast was inconsistent)"))
            end
            [digest, { failed: mac_failed }]
          end

          def combo(l, joint = @joint)
            g = 0
            @opened.each_with_index { |o, j| g = fadd(g, fmul(chal(joint, l, j), yield(o))) }
            g
          end

          # the blame round after a MAC-check failure: every party opens its combined MAC shares with their pairwise tags; each
          # verifier checks them. Always raises.
          def finish_blame(_state)
            msg = 'MAC-check FAILED: an opened value or MAC share was inconsistent; aborting with no output'
            unless @prep.tagged
              abort_with(W::NetAbort.new('mac-check', @n == 2 ? 1 - @id : nil, @id, msg, nil, nil,
                                         'this mode carries no pairwise tags, so a MAC-check failure cannot name a party (only possible with two parties)'))
            end
            blame_msg = lambda do |peer|
              {
                'g' => @gamma.map { |x| hx(x) },
                'gt' => Array.new(@k) { |l| hx(combo(l) { |o| o.mac[l].tag[peer] }) },
                'a' => @prep.alpha.map { |a| hx(a.x) },
                'at' => @prep.alpha.map { |a| hx(a.tag[peer]) }
              }
            end
            # abort claims arriving during this round are read in link order (see Mesh#set_defer_aborts): the cheater's own abort
            # must not pre-empt an honest party that has not yet received every peer's blame data
            @mesh.set_defer_aborts(true)
            blames = begin
              exchange(
                'blame', blame_msg,
                lambda do |p, raw|
                  o = raw.is_a?(Hash) ? raw : {}
                  { g: arr(p, o['g'], @k), gt: arr(p, o['gt'], @k), a: arr(p, o['a'], @k), at: arr(p, o['at'], @k) }
                end,
                nil, false
              )
            ensure
              @mesh.set_defer_aborts(false)
            end
            @others.each do |p|
              b = blames[p]
              @k.times do |l|
                key_combo = combo(l) { |o| o.mac[l].key[p] }
                if fadd(key_combo, fmul(@env.delta, b[:g][l])) != b[:gt][l]
                  abort_with(W::NetAbort.new('mac-check', p, @id, "#{msg} - party #{p}'s MAC share (key #{l}) does not match its pairwise tag"))
                end
                if fadd(@prep.alpha[l].key[p], fmul(@env.delta, b[:a][l])) != b[:at][l]
                  abort_with(W::NetAbort.new('mac-check', p, @id, "#{msg} - party #{p}'s key share (key #{l}) does not match its pairwise tag"))
                end
                next if fsub(b[:g][l], fmul(b[:a][l], @a_pub[l])) == @sig_opens[p][l]

                abort_with(W::NetAbort.new('mac-check', p, @id, "#{msg} - party #{p}'s opened MAC residual (key #{l}) is not what its authenticated shares give"))
              end
            end
            # every other party's data is consistent with its pairwise tags; so is mine: the offline material disagrees
            if @prep.mode == 'trusted-dealer'
              abort_with(W::NetAbort.new('dealer', @dealer_id, @id, "#{msg} - every party's shares verify, so the trusted dealer's MACs are inconsistent with its values"))
            end
            abort_with(
              W::NetAbort.new('mac-check', @n == 2 ? 1 - @id : nil, @id,
                              "#{msg} - every party's shares verify under its pairwise tags, so the offline material is inconsistent (a wrong OT operand): not attributable",
                              nil, nil,
                              "every party's shares verify under its pairwise tags, so the failure is in the offline OT material and no party can be named")
            )
          end

          # only now decode
          def decode_and_finish(out_vals, mults, digest, t0)
            bit = ->(x) { x == 1 ? 1 : 0 }
            allow = bit.call(out_vals[0])
            t_bits = out_vals[1, T_M].map { |x| bit.call(x) }
            r_bits = out_vals[1 + T_M..].map { |x| bit.call(x) }
            composed = ComposedDecision.new(allow, [3, [1, Thermometer.thermometer_decode(t_bits)].max].min, Thermometer.thermometer_decode(r_bits))
            @mesh.finish
            PartyResult.new(@id, @n, @q, composed, @rounds, digest, now_ms - t0, mults, @opened.length, @prep.mode, @k,
                            @prep.triples.length, @pp, @prep.tagged)
          end
        end
      end
    end
  end
end
