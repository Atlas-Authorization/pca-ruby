# frozen_string_literal: true

require 'digest'
require 'securerandom'
require 'openssl'
require_relative 'mpc_ec'
require_relative 'mpc_otx'
require_relative 'mpc_libcrypto'

module AtlasPca
  module Mpc
    # Oblivious transfer, the root of the no-dealer offline phase. (1) A maliciously secure Chou-Orlandi base OT over the Ed25519
    # subgroup: the sender proves knowledge of its discrete log with a Schnorr NIZK, every received point is validated, and the core
    # runs as a random OT so there is no selective-failure surface. (2) IKNP OT extension with the KOS consistency check (a deviating
    # receiver is caught and the protocol aborts). Both roles run in one process; the functions take both parties' inputs and return
    # the receiver's outputs plus an inspectable transcript.
    module Ot
      KAPPA = 128 # IKNP security parameter (number of base OTs / width of the selector s)
      SSEC = 128  # KOS statistical parameter: extra random check rows that mask the revealed combination
      SEED_BYTES = KAPPA / 8
      MASK64 = (1 << 64) - 1

      # the KOS correlation check failed: a cheating OT-extension receiver is detected
      class MalOtAbort < StandardError; end

      # a base OT aborted: a cheating sender (bad proof / inconsistent ciphertext) is detected
      class BaseOtAbort < StandardError; end

      # a source of scalars (uniform in [1, L)) and byte strings for OT needs
      class OtRandom
        def initialize(scalar_fn, bytes_fn)
          @scalar_fn = scalar_fn
          @bytes_fn = bytes_fn
        end

        def scalar = @scalar_fn.call
        def bytes(n) = @bytes_fn.call(n)
      end

      module_function

      # the CSPRNG-backed default: scalars by rejection over 32 random bytes
      def secure_ot_random
        bound = (1 << 256) - ((1 << 256) % Ec::L)
        scalar = lambda do
          loop do
            acc = SecureRandom.random_bytes(32).unpack1('H*').to_i(16)
            next if acc >= bound

            s = acc % Ec::L
            return s unless s.zero?
          end
        end
        OtRandom.new(scalar, ->(n) { SecureRandom.random_bytes(n) })
      end

      # a raw SplitMix64 stream (deterministic; reproducible tests only): a callable returning unsigned 64-bit Integers
      def split_mix64(seed)
        s = seed & MASK64
        lambda do
          s = (s + 0x9e3779b97f4a7c15) & MASK64
          z = s
          z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & MASK64
          z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & MASK64
          z ^ (z >> 31)
        end
      end

      # an OtRandom from a 64-bit stream
      def ot_random(next64)
        scalar = lambda do
          8.times do
            acc = 0
            4.times { acc = (acc << 64) | next64.call }
            s = acc % Ec::L
            return s unless s.zero?
          end
          raise 'otRandom: entropy stream returned zero scalars repeatedly (RNG failure)'
        end
        bytes = lambda do |n|
          out = ''.b
          out << [next64.call].pack('Q<') while out.bytesize < n
          out.byteslice(0, n)
        end
        OtRandom.new(scalar, bytes)
      end

      def sha256(*chunks) = Digest::SHA256.digest(chunks.join.b)
      def u32(x) = [x & 0xFFFFFFFF].pack('N')

      def xor_bytes(a, b) = a.bytes.zip(b.bytes).map { |x, y| x ^ y }.pack('C*')

      def ct_eq(a, b) = a.bytesize == b.bytesize && OpenSSL.fixed_length_secure_compare(a, b)

      # session binding of one base OT: who runs it, in which session and round (indices are uint32)
      BaseOtBinding = Struct.new(:session_id, :sender_index, :receiver_index, :round)

      TAG_BINDING = 'atlas-pca-mpc/base-ot-binding'.b.freeze
      TAG_TRANSCRIPT = 'atlas-pca-mpc/base-ot-transcript'.b.freeze
      TAG_KDF = 'atlas-pca-mpc/ot-kdf'.b.freeze
      TAG_KOS = 'atlas-pca-mpc/ot-kos'.b.freeze
      TAG_COMMIT = 'atlas-pca-mpc/ot-msg-commit'.b.freeze

      def uint32?(v) = v.is_a?(Integer) && v >= 0 && v <= 0xFFFFFFFF

      # canonical, length-prefixed encoding of a binding (the Schnorr context and part of every KDF input)
      def binding_bytes(b)
        sid = b.session_id
        raise ArgumentError, 'base-OT binding: sessionId must be 8..64 bytes' if !sid.is_a?(String) || sid.bytesize < 8 || sid.bytesize > 64
        raise ArgumentError, 'base-OT binding: senderIndex must be a uint32' unless uint32?(b.sender_index)
        raise ArgumentError, 'base-OT binding: receiverIndex must be a uint32' unless uint32?(b.receiver_index)
        raise ArgumentError, 'base-OT binding: sender and receiver must be different parties' if b.sender_index == b.receiver_index

        round = b.round.to_s.b
        raise ArgumentError, 'base-OT binding: round label must be 1..64 bytes' if round.empty? || round.bytesize > 64

        TAG_BINDING + u32(sid.bytesize) + sid.b + u32(b.sender_index) + u32(b.receiver_index) + u32(round.bytesize) + round
      end

      # a fresh binding for an in-process OT: a random 16-byte session id from rng
      def random_binding(rng, round, sender_index = 0, receiver_index = 1) = BaseOtBinding.new(rng.bytes(16), sender_index, receiver_index, round)

      # hash of the whole base-OT transcript: binding, S and every receiver point, in order
      def base_ot_transcript_hash(binding, s, r)
        sha256(TAG_TRANSCRIPT, binding_bytes(binding), Ec.encode_point(s), u32(r.length), *r.map { |p| Ec.encode_point(p) })
      end

      # H("ot-kdf" || H(transcript) || index || R_i || P), SEED_BYTES bytes
      def base_ot_kdf(transcript_hash, index, ri, p)
        sha256(TAG_KDF, transcript_hash, u32(index), Ec.encode_point(ri), Ec.encode_point(p)).byteslice(0, SEED_BYTES)
      end

      # the KOS row-weights as little-endian u32 words (4 per row): SHAKE256 over the binding, round and every column of u
      def kos_chi_words(binding, round, u, m_ext, col_bytes_list = nil)
        col_bytes = (m_ext + 7) / 8
        cols = col_bytes_list || u.map { |c| Otx.big_to_bytes(c, col_bytes) }
        input = TAG_KOS + u32(binding.bytesize) + binding.b + u32(round) + u32(m_ext) + u32(u.length) + cols.join.b
        Otx.words_from_le_bytes(Libcrypto.shake256(input, m_ext * 16), m_ext * 4)
      end

      def kos_challenges(binding, round, u, m_ext)
        w = kos_chi_words(binding, round, u, m_ext)
        Array.new(m_ext) { |j| Otx.gf_to_big(w, 4 * j) }
      end

      # ---- base OT ----

      # TEST-ONLY injection points modelling a malicious sender or receiver in the base OT (nil = honest); each is a callable
      BaseOtTamper = Struct.new(:tamper_s, :tamper_proof, :tamper_r, :tamper_ciphertext)
      # ct and com hold [i][0/1] byte strings
      BaseOtTranscript = Struct.new(:s, :proof, :r, :ct, :com)
      BaseOtResult = Struct.new(:received, :transcript)
      # output of the malicious-secure random base OT: validated points and the two RO pads per index
      MalRandomOtResult = Struct.new(:s, :proof, :r, :sender_pads, :recv_pads)
      SenderSetup = Struct.new(:y, :t, :s, :proof)
      ReceiverResponse = Struct.new(:r, :recv_pads)

      def ot_commit(i, b, msg, pad) = sha256(TAG_COMMIT, u32(i), [b & 1].pack('C'), msg, pad)

      def mal_base_random_ot(choices, rng = nil, tamper = nil, binding = nil)
        rng ||= secure_ot_random
        binding ||= random_binding(rng, 'base-ot')
        setup = mal_base_ot_sender_setup(rng, binding)
        s = tamper&.tamper_s ? tamper.tamper_s.call(setup.s) : setup.s
        proof = tamper&.tamper_proof ? tamper.tamper_proof.call(setup.proof) : setup.proof
        rr = mal_base_ot_receiver_respond(s, proof, choices, rng, binding)
        tamper.tamper_r.call(rr.r) if tamper&.tamper_r
        sender_pads = mal_base_ot_sender_derive(setup.y, setup.t, rr.r, s, binding)
        MalRandomOtResult.new(s, proof, rr.r, sender_pads, rr.recv_pads)
      end

      def mal_base_ot_sender_setup(rng, binding)
        ctx = binding_bytes(binding)
        y = rng.scalar
        s = Ec.mul_base(y)
        t = Ec.mul(y, s)
        proof = Ec.schnorr_prove(y, s, -> { rng.scalar }, ctx)
        SenderSetup.new(y, t, s, proof)
      end

      def mal_base_ot_receiver_respond(s, proof, choices, rng, binding)
        ctx = binding_bytes(binding)
        Ec.assert_in_subgroup(s, 'base-OT S (received by receiver)')
        raise BaseOtAbort, 'base OT: sender Schnorr proof-of-knowledge of S=y*B failed; aborting' unless Ec.schnorr_verify(s, proof, ctx)

        xs = []
        r = choices.map do |c|
          x = rng.scalar
          xs << x
          (c & 1) == 1 ? Ec.add_points(Ec.mul_base(x), s) : Ec.mul_base(x)
        end
        th = base_ot_transcript_hash(binding, s, r)
        ReceiverResponse.new(r, Array.new(choices.length) { |i| base_ot_kdf(th, i, r[i], Ec.mul(xs[i], s)) })
      end

      def mal_base_ot_sender_derive(y, t, r, s, binding)
        r.each_with_index { |p, i| Ec.assert_in_subgroup(p, "base-OT R_#{i} (received by sender)") }
        th = base_ot_transcript_hash(binding, s, r)
        r.each_with_index.map do |ri, i|
          yr = Ec.mul(y, ri)
          [base_ot_kdf(th, i, ri, yr), base_ot_kdf(th, i, ri, Ec.sub(yr, t))]
        end
      end

      # one-time-pads the messages under the sender pads and commits to each (message, pad). Returns [ct, com].
      def base_ot_sender_encrypt(messages, sender_pads)
        raise ArgumentError, 'baseOT: messages/pads length mismatch' if messages.length != sender_pads.length

        messages.each_with_index do |(m0, m1), i|
          if m0.bytesize > SEED_BYTES || m1.bytesize > SEED_BYTES || m0.bytesize != m1.bytesize
            raise ArgumentError, "baseOT: message pair #{i} must be equal length and at most #{SEED_BYTES} bytes (pad width)"
          end
        end
        ct = messages.each_with_index.map { |m, i| [xor_bytes(m[0], sender_pads[i][0]), xor_bytes(m[1], sender_pads[i][1])] }
        com = messages.each_with_index.map { |m, i| [ot_commit(i, 0, m[0], sender_pads[i][0]), ot_commit(i, 1, m[1], sender_pads[i][1])] }
        [ct, com]
      end

      def base_ot_receiver_decrypt(choices, recv_pads, ct, com)
        if ct.length != choices.length || com.length != choices.length || recv_pads.length != choices.length
          raise BaseOtAbort, 'base OT: ciphertext/commitment count does not match the number of choices; aborting'
        end

        choices.each_with_index.map do |c, i|
          ci = c & 1
          c0, c1 = ct[i]
          raise BaseOtAbort, "base OT (index #{i}): malformed ciphertext shape; aborting" if c0.bytesize != c1.bytesize || c0.bytesize > SEED_BYTES

          m = xor_bytes(ct[i][ci], recv_pads[i])
          unless ct_eq(ot_commit(i, ci, m, recv_pads[i]), com[i][ci])
            raise BaseOtAbort, "base OT (index #{i}): sender ciphertext inconsistent with its commitment; aborting"
          end

          m
        end
      end

      # chosen-message 1-of-2 OT for choices.length transfers, built over the random base OT
      def base_ot(messages, choices, rng = nil, tamper = nil, binding = nil)
        rng ||= secure_ot_random
        binding ||= random_binding(rng, 'base-ot')
        raise ArgumentError, 'baseOT: messages/choices length mismatch' if messages.length != choices.length

        ro = mal_base_random_ot(choices, rng, tamper, binding)
        ct, com = base_ot_sender_encrypt(messages, ro.sender_pads)
        tamper.tamper_ciphertext.call(ct) if tamper&.tamper_ciphertext
        received = base_ot_receiver_decrypt(choices, ro.recv_pads, ct, com)
        BaseOtResult.new(received, BaseOtTranscript.new(ro.s, ro.proof, ro.r, ct, com))
      end

      # ---- OT extension (IKNP + KOS) ----

      # the receiver's extension-round message: the u columns and the KOS values (x, t)
      ExtRoundMsg = Struct.new(:u, :x, :t_comb)
      # the receiver's per-round state between begin and finish
      ExtPending = Struct.new(:m, :choice_bits, :t, :w, :row_offset)

      def check_ext_inputs(choice_bits, msg0, msg1)
        m = choice_bits.length
        limit = 1 << 64
        choice_bits.each_with_index do |b, j|
          raise ArgumentError, "OtChannel.extend: choice bit #{j} must be 0 or 1" unless b == 0 || b == 1
        end
        return unless msg0 && msg1

        m.times do |j|
          a = msg0[j]
          b = msg1[j]
          if a.nil? || b.nil? || a.negative? || b.negative? || a >= limit || b >= limit
            raise ArgumentError, "OtChannel.extend: message #{j} must be a bigint in [0, 2^64) (the pad is 64 bits wide)"
          end
        end
      end

      # the extension receiver (base-OT sender): makes the seed pairs, then per round the u matrix and KOS values
      class OtExtReceiver
        Begin = Struct.new(:msg, :pending)
        attr_accessor :tamper_u
        attr_reader :ready

        def initialize(rng, kos_binding)
          @rng = rng
          @kos_binding = kos_binding
          @seed0 = []
          @seed1 = []
          @blk0 = Array.new(KAPPA, 0)
          @blk1 = Array.new(KAPPA, 0)
          @round = 0
          @rows_done = 0
          @tweak_domain = Otx.ot_tweak_domain(kos_binding)
          @ready = false
          @tamper_u = nil
        end

        # the kappa seed pairs, to be transferred by the base OT with the sender's selector as choices
        def make_seeds
          messages = Array.new(KAPPA) do
            k0 = @rng.bytes(SEED_BYTES)
            k1 = @rng.bytes(SEED_BYTES)
            @seed0 << k0
            @seed1 << k1
            [k0, k1]
          end
          @ready = true
          messages
        end

        def begin_round(choice_bits)
          raise 'OtExtReceiver: base OT not done' unless @ready

          Ot.check_ext_inputs(choice_bits, nil, nil)
          m = choice_bits.length
          round_idx = @round
          @round += 1
          row_offset = @rows_done
          @rows_done += m
          pad = KAPPA + SSEC
          m_ext = m + pad
          w = (m_ext + 31) >> 5
          col_bytes = (m_ext + 7) / 8
          bvec = Array.new(w, 0)
          m.times { |j| bvec[j >> 5] |= 1 << (j & 31) if (choice_bits[j] & 1) != 0 }
          pad_bytes = @rng.bytes(pad)
          pad.times do |p|
            j = m + p
            bvec[j >> 5] |= 1 << (j & 31) if (pad_bytes.getbyte(p) & 1) != 0
          end
          blocks = (w + 3) / 4
          t = Array.new(Otx::COLS * w, 0)
          u = Array.new(Otx::COLS)
          ubytes = Array.new(Otx::COLS)
          KAPPA.times do |i|
            ti = Otx.prg_column(@seed0[i], @blk0[i], w)
            gi = Otx.prg_column(@seed1[i], @blk1[i], w)
            @blk0[i] += blocks
            @blk1[i] += blocks
            Otx.mask_tail(ti, m_ext)
            Otx.mask_tail(gi, m_ext)
            t[i * w, w] = ti
            uw = Array.new(w) { |k| gi[k] ^ ti[k] ^ bvec[k] }
            ubytes[i] = Otx.le_bytes(uw, w).byteslice(0, col_bytes)
            u[i] = Otx.bytes_to_big(ubytes[i])
          end
          @tamper_u&.call(u, round_idx)
          pending = ExtPending.new(m, choice_bits.dup, t, w, row_offset)
          limit = 1 << m_ext
          if u.any? { |c| c.nil? || c.negative? || c >= limit }
            return Begin.new(ExtRoundMsg.new(u, 0, 0), pending)
          end

          chi = Ot.kos_chi_words(@kos_binding, round_idx, u, m_ext, @tamper_u ? nil : ubytes)
          x = [0, 0, 0, 0]
          Otx.accum_column(bvec, 0, w, chi, x)
          t_comb = Otx.kos_combine(t, w, chi)
          Begin.new(ExtRoundMsg.new(u, Otx.gf_to_big(x), Otx.gf_to_big(t_comb)), pending)
        end

        # the receiver's outputs: m_{c_j} for every row j, from the sender's ciphertexts
        def finish(pending, y0, y1)
          m = pending.m
          raise MalOtAbort, 'OT extension: ciphertext count does not match the number of rows; aborting' if y0.length != m || y1.length != m

          rows = Otx.transpose_cols(pending.t, pending.w, m)
          h = Otx.tmmo_crh(rows, m, Otx::OtTweak.new(pending.row_offset, @tweak_domain))
          Array.new(m) { |j| (pending.choice_bits[j] == 1 ? y1[j] : y0[j]) ^ Otx.word64(h, j) }
        end
      end

      # the extension sender (base-OT receiver): holds the secret selector s and answers each round after the KOS check
      class OtExtSender
        Response = Struct.new(:y0, :y1)
        attr_reader :ready

        def initialize(rng, kos_binding)
          @rng = rng
          @kos_binding = kos_binding
          @s = []
          @s_bits = 0
          @seeds = []
          @blk = []
          @round = 0
          @rows_done = 0
          @tweak_domain = Otx.ot_tweak_domain(kos_binding)
          @ready = false
        end

        def make_selector
          @s = Array.new(KAPPA) { @rng.bytes(1).getbyte(0) & 1 }
          @s.dup
        end

        def set_seeds(seeds)
          raise 'OtExtSender: wrong base-OT output size' if seeds.length != KAPPA || @s.length != KAPPA

          @seeds = seeds
          @blk = Array.new(KAPPA, 0)
          @s_bits = (0...KAPPA).reduce(0) { |acc, i| @s[i] == 1 ? acc | (1 << i) : acc }
          @ready = true
        end

        def selector = @s_bits

        def respond(msg, msg0, msg1)
          raise 'OtExtSender: base OT not done' unless @ready

          m = msg0.length
          raise ArgumentError, 'OtChannel.extend: length mismatch' if msg1.length != m

          Ot.check_ext_inputs(Array.new(m, 0), msg0, msg1)
          round_idx = @round
          @round += 1
          row_offset = @rows_done
          @rows_done += m
          m_ext = m + KAPPA + SSEC
          u = msg.u
          raise MalOtAbort, "KOS check (round #{round_idx}): wrong number of u columns; a cheating OT-extension receiver was detected; aborting" if u.nil? || u.length != KAPPA

          col_limit = 1 << m_ext
          u.each_with_index do |ui, i|
            if ui.nil? || ui.negative? || ui >= col_limit
              raise MalOtAbort, "KOS check (round #{round_idx}): malformed u column #{i}; a cheating OT-extension receiver was detected; aborting"
            end
          end
          lim128 = 1 << 128
          x = msg.x
          tc = msg.t_comb
          if x.nil? || tc.nil? || x.negative? || x >= lim128 || tc.negative? || tc >= lim128
            raise MalOtAbort, "KOS check (round #{round_idx}): malformed (x, t); a cheating OT-extension receiver was detected; aborting"
          end

          w = (m_ext + 31) >> 5
          col_bytes = (m_ext + 7) / 8
          blocks = (w + 3) / 4
          q = Array.new(Otx::COLS * w, 0)
          ubytes = Array.new(Otx::COLS)
          KAPPA.times do |i|
            ubytes[i] = Otx.big_to_bytes(u[i], col_bytes)
            ks = Otx.prg_column(@seeds[i], @blk[i], w)
            @blk[i] += blocks
            Otx.mask_tail(ks, m_ext)
            if @s[i] == 1
              uw = Otx.words_from_le_bytes(ubytes[i] + ("\0".b * ((4 * w) - ubytes[i].bytesize)), w)
              w.times { |k| ks[k] ^= uw[k] }
            end
            q[i * w, w] = ks
          end
          chi = Ot.kos_chi_words(@kos_binding, round_idx, u, m_ext, ubytes)
          q_comb = Otx.gf_to_big(Otx.kos_combine(q, w, chi))
          expected = tc ^ Gf128.mul(x, @s_bits)
          raise MalOtAbort, "KOS correlation check FAILED (round #{round_idx}): a cheating OT-extension receiver was detected; aborting" if q_comb != expected

          rows = Otx.transpose_cols(q, w, m)
          tweak = Otx::OtTweak.new(row_offset, @tweak_domain)
          h0 = Otx.tmmo_crh(rows, m, tweak)
          sw = Otx.gf_from_big(@s_bits)
          m.times do |j|
            row = rows[4 * j, 4]
            Otx.gf_xor_into(row, sw, 0)
            rows[4 * j, 4] = row
          end
          h1 = Otx.tmmo_crh(rows, m, tweak)
          Response.new(Array.new(m) { |j| msg0[j] ^ Otx.word64(h0, j) }, Array.new(m) { |j| msg1[j] ^ Otx.word64(h1, j) })
        end
      end

      # an in-process OT-extension channel: one base-OT setup (kappa transfers) is amortised over every later extend. The base OT is
      # the EC base OT unless base_ot_fn (callable (messages, choices, rng) -> received) supplies another (a post-quantum one).
      class OtChannel
        Extended = Struct.new(:received, :u_matrix)
        attr_reader :base_transcript
        attr_accessor :tamper_u

        # binding: only session_id, sender_index and receiver_index are used (its round is ignored); may be nil
        def initialize(rng = nil, base_ot_fn = nil, binding = nil)
          @rng = rng || Ot.secure_ot_random
          @base_ot_fn = base_ot_fn
          @binding_opt = binding
          @ready = false
          @base_transcript = nil
          @tamper_u = nil
        end

        def selector
          setup unless @ready
          @send.selector
        end

        def extend_ot(choice_bits, msg0, msg1)
          setup unless @ready
          m = choice_bits.length
          raise ArgumentError, 'OtChannel.extend: length mismatch' if msg0.length != m || msg1.length != m
          return Extended.new([], []) if m.zero?

          Ot.check_ext_inputs(choice_bits, msg0, msg1)
          @recv.tamper_u = @tamper_u
          b = @recv.begin_round(choice_bits)
          r = @send.respond(b.msg, msg0, msg1)
          Extended.new(@recv.finish(b.pending, r.y0, r.y1), b.msg.u)
        end

        private

        def setup
          base = @binding_opt || Ot.random_binding(@rng, 'x')
          kos = Ot.binding_bytes(Ot::BaseOtBinding.new(base.session_id, base.sender_index, base.receiver_index, 'iknp-kos'))
          r = OtExtReceiver.new(@rng, kos)
          sd = OtExtSender.new(@rng, kos)
          messages = r.make_seeds
          sel = sd.make_selector
          if @base_ot_fn
            sd.set_seeds(@base_ot_fn.call(messages, sel, @rng))
          else
            res = Ot.base_ot(messages, sel, @rng, nil, Ot::BaseOtBinding.new(base.session_id, base.sender_index, base.receiver_index, 'iknp-kappa-setup'))
            sd.set_seeds(res.received)
            @base_transcript = res.transcript
          end
          @recv = r
          @send = sd
          @ready = true
        end
      end
    end
  end
end
