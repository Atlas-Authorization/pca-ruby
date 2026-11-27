# frozen_string_literal: true

require_relative 'mpc_ot'

module AtlasPca
  module Mpc
    # Post-quantum base OT from ML-KEM-768 (FIPS 203, OpenSSL >= 3.5 through Libcrypto::MlKem768): the receiver publishes a public-key
    # pair with a known secret key for only its chosen slot, the sender encapsulates to both and pads each message with the shared
    # secret. Variants: the semi-honest transfer (kem_base_ot), the commit-then-open malicious-secure transfer with a session id
    # (kem_base_ot_mal), and the random-OT form that outputs fixed-width secrets for the hybrid base OT (kem_base_ot_mal_random).
    module KemOt
      TAG_KEMOT = 'atlas-pca-mpc/kem-ot-pad'.b.freeze
      TAG_KEMOT_COMMIT = 'atlas-pca-mpc/kem-ot-commit'.b.freeze
      TAG_KEMOT_SID = 'atlas-pca-mpc/kem-ot-sid'.b.freeze
      TAG_KEMOT_MALPAD = 'atlas-pca-mpc/kem-ot-mal-pad'.b.freeze
      TAG_KEMOT_MALSECRET = 'atlas-pca-mpc/kem-ot-mal-secret'.b.freeze
      NONCE_BYTES = 32
      KEM_OT_SECRET_BYTES = 32
      MlKem = Libcrypto::MlKem768

      # a KEM base OT aborted: the opened keys do not match the receiver's commitment
      class KemBaseOtAbort < StandardError; end

      # TEST-ONLY injection points for a malicious sender or receiver (nil = honest); each is a callable
      KemMalTamper = Struct.new(:tamper_opened_keys, :tamper_receiver_sid)
      KemOtReceiverState = Struct.new(:choices, :secret_keys)
      KemOtReceiverMessage = Struct.new(:public_keys)
      KemOtSenderMessage = Struct.new(:ciphertexts, :encrypted)
      KemBaseOtTranscript = Struct.new(:public_keys, :ciphertexts, :encrypted)
      KemBaseOtResult = Struct.new(:received, :transcript)
      ReceiverStep = Struct.new(:message, :state)
      KemMalCommitMessage = Struct.new(:rn, :commitments)
      KemMalOpenMessage = Struct.new(:public_keys)
      KemMalSenderNonce = Struct.new(:sn)
      KemMalSenderMessage = Struct.new(:ciphertexts, :encrypted)
      KemMalReceiverState = Struct.new(:choices, :secret_keys, :public_keys, :rn)
      KemMalTranscript = Struct.new(:rn, :commitments, :sn, :public_keys, :ciphertexts, :encrypted)
      KemBaseOtMalResult = Struct.new(:received, :transcript)
      CommitStep = Struct.new(:message, :state)
      KemMalRandomSenderMessage = Struct.new(:ciphertexts, :sender_secrets)
      KemMalRandomTranscript = Struct.new(:rn, :commitments, :sn, :public_keys, :ciphertexts)
      KemBaseOtMalRandomResult = Struct.new(:sender_secrets, :recv_secrets, :sid, :transcript)

      module_function

      def sha256(*chunks) = Ot.sha256(*chunks)
      def u32(x) = Ot.u32(x)

      def xor(a, b)
        raise ArgumentError, 'kem-ot: XOR length mismatch' if a.bytesize != b.bytesize

        Ot.xor_bytes(a, b)
      end

      def expand(tag, prefix, index, slot, shared_secret, len)
        out = ''.b
        ctr = 0
        while out.bytesize < len
          out << sha256(tag, *prefix, u32(index), [slot & 1].pack('C'), u32(ctr), shared_secret)
          ctr += 1
        end
        out.byteslice(0, len)
      end

      # pad of len bytes (at most 1 MiB) from the shared secret: SHA-256 in counter mode
      def kem_ot_pad(index, slot, shared_secret, len)
        raise ArgumentError, 'kemOtPad: length must be an integer in [0, 1 MiB]' unless len.is_a?(Integer) && len >= 0 && len <= 1 << 20

        expand(TAG_KEMOT, [], index, slot, shared_secret, len)
      end

      def keypair_for(rng, choice)
        chosen = MlKem.keygen(rng.bytes(MlKem::SEED_BYTES))
        other = MlKem.keygen(rng.bytes(MlKem::SEED_BYTES))
        [choice.zero? ? [chosen.public_key, other.public_key] : [other.public_key, chosen.public_key], chosen.secret_key]
      end

      def kem_base_ot_receive(choices, rng = nil)
        rng ||= Ot.secure_ot_random
        public_keys = []
        secret_keys = []
        retained = []
        choices.each do |ch|
          c = ch & 1
          pks, sk = keypair_for(rng, c)
          public_keys << pks
          secret_keys << sk
          retained << c
        end
        ReceiverStep.new(KemOtReceiverMessage.new(public_keys), KemOtReceiverState.new(retained, secret_keys))
      end

      def kem_base_ot_send(messages, receiver_message, rng = nil)
        rng ||= Ot.secure_ot_random
        public_keys = receiver_message.public_keys
        raise ArgumentError, 'kemBaseOtSend: messages/publicKeys length mismatch' if messages.length != public_keys.length

        cts = []
        encrypted = []
        messages.each_with_index do |(m0, m1), i|
          raise ArgumentError, "kemBaseOtSend (index #{i}): the two messages must be equal length" if m0.bytesize != m1.bytesize

          e0 = MlKem.encapsulate(public_keys[i][0], rng.bytes(MlKem::MSG_BYTES))
          e1 = MlKem.encapsulate(public_keys[i][1], rng.bytes(MlKem::MSG_BYTES))
          cts << [e0.cipher_text, e1.cipher_text]
          encrypted << [xor(m0, kem_ot_pad(i, 0, e0.shared_secret, m0.bytesize)), xor(m1, kem_ot_pad(i, 1, e1.shared_secret, m1.bytesize))]
        end
        KemOtSenderMessage.new(cts, encrypted)
      end

      def kem_base_ot_open(state, sender_message)
        n = state.choices.length
        if sender_message.ciphertexts.length != n || sender_message.encrypted.length != n
          raise ArgumentError, 'kemBaseOtOpen: transcript/state length mismatch'
        end

        Array.new(n) do |i|
          c = state.choices[i] & 1
          ss = MlKem.decapsulate(sender_message.ciphertexts[i][c], state.secret_keys[i])
          e = sender_message.encrypted[i][c]
          xor(e, kem_ot_pad(i, c, ss, e.bytesize))
        end
      end

      def kem_base_ot(messages, choices, rng = nil)
        rng ||= Ot.secure_ot_random
        raise ArgumentError, 'kemBaseOT: messages/choices length mismatch' if messages.length != choices.length

        r = kem_base_ot_receive(choices, rng)
        s = kem_base_ot_send(messages, r.message, rng)
        received = kem_base_ot_open(r.state, s)
        KemBaseOtResult.new(received, KemBaseOtTranscript.new(r.message.public_keys, s.ciphertexts, s.encrypted))
      end

      # the semi-honest KEM OT as a pluggable base OT for Ot::OtChannel
      def with_kem_base_ot = ->(m, c, r) { kem_base_ot(m, c, r).received }

      # ---- malicious-secure (commit-then-open, session id) ----

      def kem_mal_commit(rn, index, pk0, pk1) = sha256(TAG_KEMOT_COMMIT, rn, u32(index), pk0, pk1)
      def kem_mal_sid(rn, sn) = sha256(TAG_KEMOT_SID, rn, sn)
      def kem_ot_mal_pad(sid, com, index, slot, ss, len) = expand(TAG_KEMOT_MALPAD, [sid, com], index, slot, ss, len)

      def kem_ot_mal_secret(sid, com, index, slot, ss)
        sha256(TAG_KEMOT_MALSECRET, sid, com, u32(index), [slot & 1].pack('C'), ss).byteslice(0, KEM_OT_SECRET_BYTES)
      end

      def kem_base_ot_mal_commit(choices, rng = nil)
        rng ||= Ot.secure_ot_random
        rn = rng.bytes(NONCE_BYTES)
        public_keys = []
        secret_keys = []
        retained = []
        commitments = []
        choices.each_with_index do |ch, i|
          c = ch & 1
          pks, sk = keypair_for(rng, c)
          public_keys << pks
          secret_keys << sk
          retained << c
          commitments << kem_mal_commit(rn, i, pks[0], pks[1])
        end
        CommitStep.new(KemMalCommitMessage.new(rn, commitments), KemMalReceiverState.new(retained, secret_keys, public_keys, rn))
      end

      def kem_base_ot_mal_sender_nonce(rng = nil) = KemMalSenderNonce.new((rng || Ot.secure_ot_random).bytes(NONCE_BYTES))

      # the receiver's opening: a copy of its public-key pairs
      def kem_base_ot_mal_open(state) = KemMalOpenMessage.new(state.public_keys.map(&:dup))

      def check_opening!(commit, public_keys, i)
        com = kem_mal_commit(commit.rn, i, public_keys[i][0], public_keys[i][1])
        unless Ot.ct_eq(com, commit.commitments[i])
          raise KemBaseOtAbort, "kem base OT (index #{i}): opened public keys do not match the receiver's commitment; aborting"
        end

        com
      end

      def kem_base_ot_mal_send(messages, commit, sender_nonce, opening, rng = nil)
        rng ||= Ot.secure_ot_random
        public_keys = opening.public_keys
        if messages.length != public_keys.length || commit.commitments.length != public_keys.length
          raise ArgumentError, 'kemBaseOtMalSend: messages/commitments/publicKeys length mismatch'
        end

        sid = kem_mal_sid(commit.rn, sender_nonce.sn)
        cts = []
        encrypted = []
        messages.each_with_index do |(m0, m1), i|
          raise ArgumentError, "kemBaseOtMalSend (index #{i}): the two messages must be equal length" if m0.bytesize != m1.bytesize

          com = check_opening!(commit, public_keys, i)
          e0 = MlKem.encapsulate(public_keys[i][0], rng.bytes(MlKem::MSG_BYTES))
          e1 = MlKem.encapsulate(public_keys[i][1], rng.bytes(MlKem::MSG_BYTES))
          cts << [e0.cipher_text, e1.cipher_text]
          encrypted << [xor(m0, kem_ot_mal_pad(sid, com, i, 0, e0.shared_secret, m0.bytesize)),
                        xor(m1, kem_ot_mal_pad(sid, com, i, 1, e1.shared_secret, m1.bytesize))]
        end
        KemMalSenderMessage.new(cts, encrypted)
      end

      def receiver_sid(state, sender_nonce, tamper)
        sid = kem_mal_sid(state.rn, sender_nonce.sn)
        tamper&.tamper_receiver_sid ? tamper.tamper_receiver_sid.call(sid) : sid
      end

      def kem_base_ot_mal_recover(state, sender_nonce, sender_message, tamper = nil)
        n = state.choices.length
        if sender_message.ciphertexts.length != n || sender_message.encrypted.length != n
          raise ArgumentError, 'kemBaseOtMalRecover: transcript/state length mismatch'
        end

        sid = receiver_sid(state, sender_nonce, tamper)
        Array.new(n) do |i|
          c = state.choices[i] & 1
          com = kem_mal_commit(state.rn, i, state.public_keys[i][0], state.public_keys[i][1])
          ss = MlKem.decapsulate(sender_message.ciphertexts[i][c], state.secret_keys[i])
          e = sender_message.encrypted[i][c]
          xor(e, kem_ot_mal_pad(sid, com, i, c, ss, e.bytesize))
        end
      end

      def kem_base_ot_mal(messages, choices, rng = nil, tamper = nil)
        rng ||= Ot.secure_ot_random
        raise ArgumentError, 'kemBaseOtMal: messages/choices length mismatch' if messages.length != choices.length

        cs = kem_base_ot_mal_commit(choices, rng)
        nonce = kem_base_ot_mal_sender_nonce(rng)
        opening = kem_base_ot_mal_open(cs.state)
        tamper.tamper_opened_keys.call(opening.public_keys) if tamper&.tamper_opened_keys
        sm = kem_base_ot_mal_send(messages, cs.message, nonce, opening, rng)
        received = kem_base_ot_mal_recover(cs.state, nonce, sm, tamper)
        KemBaseOtMalResult.new(received, KemMalTranscript.new(cs.message.rn, cs.message.commitments, nonce.sn, opening.public_keys, sm.ciphertexts, sm.encrypted))
      end

      # the malicious-secure KEM OT as a pluggable base OT for Ot::OtChannel
      def with_kem_base_ot_mal = ->(m, c, r) { kem_base_ot_mal(m, c, r, nil).received }

      # ---- random-OT form (fixed-width secrets, for the hybrid base OT) ----

      def kem_base_ot_mal_random_send(commit, sender_nonce, opening, rng = nil)
        rng ||= Ot.secure_ot_random
        public_keys = opening.public_keys
        raise ArgumentError, 'kemBaseOtMalRandomSend: commitments/publicKeys length mismatch' if commit.commitments.length != public_keys.length

        sid = kem_mal_sid(commit.rn, sender_nonce.sn)
        cts = []
        secrets = []
        public_keys.each_index do |i|
          com = check_opening!(commit, public_keys, i)
          e0 = MlKem.encapsulate(public_keys[i][0], rng.bytes(MlKem::MSG_BYTES))
          e1 = MlKem.encapsulate(public_keys[i][1], rng.bytes(MlKem::MSG_BYTES))
          cts << [e0.cipher_text, e1.cipher_text]
          secrets << [kem_ot_mal_secret(sid, com, i, 0, e0.shared_secret), kem_ot_mal_secret(sid, com, i, 1, e1.shared_secret)]
        end
        KemMalRandomSenderMessage.new(cts, secrets)
      end

      def kem_base_ot_mal_random_recover(state, sender_nonce, sender_message, tamper = nil)
        n = state.choices.length
        raise ArgumentError, 'kemBaseOtMalRandomRecover: transcript/state length mismatch' if sender_message.ciphertexts.length != n

        sid = receiver_sid(state, sender_nonce, tamper)
        Array.new(n) do |i|
          c = state.choices[i] & 1
          com = kem_mal_commit(state.rn, i, state.public_keys[i][0], state.public_keys[i][1])
          kem_ot_mal_secret(sid, com, i, c, MlKem.decapsulate(sender_message.ciphertexts[i][c], state.secret_keys[i]))
        end
      end

      def kem_base_ot_mal_random(choices, rng = nil, tamper = nil)
        rng ||= Ot.secure_ot_random
        cs = kem_base_ot_mal_commit(choices, rng)
        nonce = kem_base_ot_mal_sender_nonce(rng)
        opening = kem_base_ot_mal_open(cs.state)
        tamper.tamper_opened_keys.call(opening.public_keys) if tamper&.tamper_opened_keys
        sm = kem_base_ot_mal_random_send(cs.message, nonce, opening, rng)
        recv = kem_base_ot_mal_random_recover(cs.state, nonce, sm, tamper)
        KemBaseOtMalRandomResult.new(sm.sender_secrets, recv, kem_mal_sid(cs.message.rn, nonce.sn),
                                     KemMalRandomTranscript.new(cs.message.rn, cs.message.commitments, nonce.sn, opening.public_keys, sm.ciphertexts))
      end
    end

    # Hybrid base OT: the elliptic-curve random OT and the ML-KEM random OT run side by side and BOTH secrets are folded into every
    # transfer key, so the transfer is secure if either the classical or the post-quantum assumption holds. The keys encrypt the
    # messages and a per-message commitment catches an inconsistent sender.
    module HybridOt
      TAG_HYBRID_SID = 'atlas-pca-mpc/hybrid-ot-sid'.b.freeze
      TAG_HYBRID_KEY = 'atlas-pca-mpc/hybrid-ot-transfer-key'.b.freeze
      TAG_HYBRID_COMMIT = 'atlas-pca-mpc/hybrid-ot-msg-commit'.b.freeze

      # a hybrid base OT aborted: the sender's ciphertext is inconsistent with its commitment
      class HybridOtAbort < StandardError; end

      HybridSenderMessage = Struct.new(:encrypted, :commitments)
      # TEST-ONLY injection points (nil = honest)
      HybridBaseOtTamper = Struct.new(:ec, :kem, :tamper_encrypted)
      HybridBaseOtTranscript = Struct.new(:sid, :ec_s, :kem_sid, :encrypted, :commitments)
      HybridBaseOtResult = Struct.new(:received, :transcript)

      module_function

      def hybrid_session_id(kem_sid, ec_s) = Ot.sha256(TAG_HYBRID_SID, kem_sid, Ec.encode_point(ec_s))

      def hybrid_transfer_key(sid, index, slot, ss_ec, ss_kem, len)
        raise ArgumentError, 'hybridTransferKey: length must be an integer in [0, 1 MiB]' unless len.is_a?(Integer) && len >= 0 && len <= 1 << 20

        out = ''.b
        ctr = 0
        while out.bytesize < len
          out << Ot.sha256(TAG_HYBRID_KEY, sid, Ot.u32(index), [slot & 1].pack('C'), Ot.u32(ctr), ss_ec, ss_kem)
          ctr += 1
        end
        out.byteslice(0, len)
      end

      def hybrid_commit(sid, index, slot, msg, key) = Ot.sha256(TAG_HYBRID_COMMIT, sid, Ot.u32(index), [slot & 1].pack('C'), msg, key)

      def xor(a, b)
        raise ArgumentError, 'hybrid-ot: XOR length mismatch' if a.bytesize != b.bytesize

        Ot.xor_bytes(a, b)
      end

      def hybrid_sender_encrypt(sid, messages, ec_secrets, kem_secrets)
        if messages.length != ec_secrets.length || messages.length != kem_secrets.length
          raise ArgumentError, 'hybridSenderEncrypt: messages/ecSecrets/kemSecrets length mismatch'
        end

        encrypted = []
        commitments = []
        messages.each_with_index do |(m0, m1), i|
          raise ArgumentError, "hybridSenderEncrypt (index #{i}): the two messages must be equal length" if m0.bytesize != m1.bytesize

          k0 = hybrid_transfer_key(sid, i, 0, ec_secrets[i][0], kem_secrets[i][0], m0.bytesize)
          k1 = hybrid_transfer_key(sid, i, 1, ec_secrets[i][1], kem_secrets[i][1], m1.bytesize)
          encrypted << [xor(m0, k0), xor(m1, k1)]
          commitments << [hybrid_commit(sid, i, 0, m0, k0), hybrid_commit(sid, i, 1, m1, k1)]
        end
        HybridSenderMessage.new(encrypted, commitments)
      end

      def hybrid_receiver_recover(sid, choices, sender, ec_recv, kem_recv)
        n = choices.length
        if sender.encrypted.length != n || sender.commitments.length != n || ec_recv.length != n || kem_recv.length != n
          raise ArgumentError, 'hybridReceiverRecover: length mismatch'
        end

        Array.new(n) do |i|
          c = choices[i] & 1
          e = sender.encrypted[i][c]
          key = hybrid_transfer_key(sid, i, c, ec_recv[i], kem_recv[i], e.bytesize)
          m = xor(e, key)
          unless Ot.ct_eq(hybrid_commit(sid, i, c, m, key), sender.commitments[i][c])
            raise HybridOtAbort, "hybrid base OT (index #{i}): sender ciphertext inconsistent with its commitment; aborting"
          end

          m
        end
      end

      def hybrid_base_ot(messages, choices, rng = nil, tamper = nil)
        rng ||= Ot.secure_ot_random
        raise ArgumentError, 'hybridBaseOT: messages/choices length mismatch' if messages.length != choices.length

        ec = Ot.mal_base_random_ot(choices, rng, tamper&.ec, nil)
        kem = KemOt.kem_base_ot_mal_random(choices, rng, tamper&.kem)
        sid = hybrid_session_id(kem.sid, ec.s)
        sender = hybrid_sender_encrypt(sid, messages, ec.sender_pads, kem.sender_secrets)
        tamper.tamper_encrypted.call(sender.encrypted) if tamper&.tamper_encrypted
        received = hybrid_receiver_recover(sid, choices, sender, ec.recv_pads, kem.recv_secrets)
        HybridBaseOtResult.new(received, HybridBaseOtTranscript.new(sid, ec.s, kem.sid, sender.encrypted, sender.commitments))
      end

      # the hybrid base OT as a pluggable base OT for Ot::OtChannel
      def with_hybrid_base_ot = ->(m, c, r) { hybrid_base_ot(m, c, r, nil).received }
    end
  end
end
