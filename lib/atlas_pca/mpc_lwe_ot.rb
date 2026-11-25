# frozen_string_literal: true

require 'digest'
require 'openssl'
require 'securerandom'

module AtlasPca
  # The post-quantum, maliciously-secure endemic base OT (Masny-Rindal over Module-LWE, Kyber-768 K-PKE) for the MPC package, wire-compatible with
  # the TypeScript package's recommended base OT. The receiver places a real key's offset-by-oracle point at its choice slot and a uniform ring
  # vector at the other, so the sender's effective key for the other slot is uniform and its ciphertext is unrecoverable; the chosen-message form
  # pads and commits each message and aborts on any inconsistency.
  #
  # Nothing lattice-related is implemented here: every K-PKE and ring operation is the small C library liblweot (pca_lwe_ot.h, built from the
  # flagship's crate with cargo build --features capi) over ffi, bound lazily (a missing library raises LoadError, never a "bad input" result).
  # Point ATLAS_PCA_LIBLWEOT at it, or put liblweot on the loader path. The receiver's real key pair is the FIPS 203
  # K-PKE.KeyGen(d), the derivation the reference uses, so every receiver message matches it byte for byte.
  module MpcLweOt
    PK_BYTES = 1184
    SK_BYTES = 1152
    CT_BYTES = 1088
    TVEC_BYTES = 1152
    SYM_BYTES = 32
    HASHIN_CAP = 4096
    ENDEMIC_SECRET_BYTES = SYM_BYTES

    TAG_SID = 'atlas-pca-mpc/endemic-lwe-ot-sid'.b.freeze
    TAG_HPK = 'atlas-pca-mpc/endemic-lwe-ot-hpk'.b.freeze
    TAG_N = 'atlas-pca-mpc/endemic-lwe-ot-N'.b.freeze
    TAG_PAD = 'atlas-pca-mpc/endemic-lwe-ot-pad'.b.freeze
    TAG_COMMIT = 'atlas-pca-mpc/endemic-lwe-ot-commit'.b.freeze

    # The endemic base OT aborted: malformed input, or a sender ciphertext failing its commitment.
    class EndemicAbort < StandardError; end

    # A lattice call refused (wrong size, or the library refused).
    class LatticeError < ArgumentError; end

    FUNCS = {
      lweot_len_pk: [[], :size_t], lweot_len_sk: [[], :size_t], lweot_len_ct: [[], :size_t], lweot_len_tvec: [[], :size_t],
      lweot_len_sym: [[], :size_t], lweot_hashin_cap: [[], :size_t],
      lweot_kpke_keygen_fips203: [%i[buffer_in size_t buffer_out size_t buffer_out size_t], :int32],
      lweot_kpke_keygen: [%i[buffer_in size_t buffer_out size_t buffer_out size_t], :int32],
      lweot_kpke_enc: [%i[buffer_in size_t buffer_in size_t buffer_in size_t buffer_out size_t], :int32],
      lweot_kpke_dec: [%i[buffer_in size_t buffer_in size_t buffer_out size_t], :int32],
      lweot_ring_add: [%i[buffer_in size_t buffer_in size_t buffer_out size_t], :int32],
      lweot_ring_sub: [%i[buffer_in size_t buffer_in size_t buffer_out size_t], :int32],
      lweot_hash_to_ring: [%i[buffer_in size_t buffer_out size_t], :int32]
    }.freeze
    LIBS = [*ENV['ATLAS_PCA_LIBLWEOT'], *Dir.glob(File.join(__dir__, 'native', '{liblweot.so,liblweot.dylib,lweot.dll}')), *%w[lweot liblweot.so liblweot.dylib lweot.dll]].freeze
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
            raise LoadError, "the endemic LWE OT needs the ffi gem and liblweot (#{e.message})"
          end
          m = Module.new
          m.extend(FFI::Library)
          begin
            m.ffi_lib(LIBS)
            FUNCS.each { |name, (args, ret)| m.attach_function(name, args, ret) }
          rescue LoadError, FFI::NotFoundError => e
            raise LoadError, "the endemic LWE OT needs liblweot built from the flagship's crate (cargo build --features capi; set ATLAS_PCA_LIBLWEOT): #{e.message}"
          end
          # the sizes this module hard-codes must be the ones the library was built with, or nothing is safe
          got = %i[lweot_len_pk lweot_len_sk lweot_len_ct lweot_len_tvec lweot_len_sym lweot_hashin_cap].map { |f| m.public_send(f) }
          raise LoadError, "liblweot reports different Kyber-768 sizes: #{got.inspect}" unless got == [PK_BYTES, SK_BYTES, CT_BYTES, TVEC_BYTES, SYM_BYTES, HASHIN_CAP]

          m
        end
      end
    end

    # True when liblweot can be loaded.
    def available?
      lib
      true
    rescue LoadError
      false
    end

    def need(str, len, what)
      raise LatticeError, "lattice: #{what} must be exactly #{len} bytes" unless str.is_a?(String) && str.bytesize == len

      str.b
    end

    def out(len) = FFI::MemoryPointer.new(:uint8, len)

    def ok!(rc, op)
      raise LatticeError, "lattice: #{op} refused (#{rc})" unless rc.zero?
    end

    # [public key, secret key] of Kyber-768 K-PKE, deterministic in the 32-byte seed.
    def kpke_keygen(seed)
      s = need(seed, SYM_BYTES, 'seed')
      pk = out(PK_BYTES)
      sk = out(SK_BYTES)
      ok!(lib.lweot_kpke_keygen(s, SYM_BYTES, pk, PK_BYTES, sk, SK_BYTES), 'keygen')
      [pk.read_bytes(PK_BYTES), sk.read_bytes(SK_BYTES)]
    end

    # [public key, secret key] exactly as FIPS 203 Algorithm 13 derives K-PKE.KeyGen(d): the derivation the endemic receiver uses.
    def kpke_keygen_fips203(seed)
      s = need(seed, SYM_BYTES, 'seed')
      pk = out(PK_BYTES)
      sk = out(SK_BYTES)
      ok!(lib.lweot_kpke_keygen_fips203(s, SYM_BYTES, pk, PK_BYTES, sk, SK_BYTES), 'keygen (FIPS 203)')
      [pk.read_bytes(PK_BYTES), sk.read_bytes(SK_BYTES)]
    end

    def kpke_enc(public_key, message, coins)
      p = need(public_key, PK_BYTES, 'public key')
      m = need(message, SYM_BYTES, 'message')
      c = need(coins, SYM_BYTES, 'coins')
      ct = out(CT_BYTES)
      ok!(lib.lweot_kpke_enc(p, PK_BYTES, m, SYM_BYTES, c, SYM_BYTES, ct, CT_BYTES), 'enc')
      ct.read_bytes(CT_BYTES)
    end

    def kpke_dec(secret_key, ciphertext)
      s = need(secret_key, SK_BYTES, 'secret key')
      c = need(ciphertext, CT_BYTES, 'ciphertext')
      msg = out(SYM_BYTES)
      ok!(lib.lweot_kpke_dec(s, SK_BYTES, c, CT_BYTES, msg, SYM_BYTES), 'dec')
      msg.read_bytes(SYM_BYTES)
    end

    def ring_add(a, b) = ring(:lweot_ring_add, a, b, 'ring add')
    def ring_sub(a, b) = ring(:lweot_ring_sub, a, b, 'ring sub')

    def ring(fn, a, b, op)
      x = need(a, TVEC_BYTES, 'a')
      y = need(b, TVEC_BYTES, 'b')
      o = out(TVEC_BYTES)
      ok!(lib.public_send(fn, x, TVEC_BYTES, y, TVEC_BYTES, o, TVEC_BYTES), op)
      o.read_bytes(TVEC_BYTES)
    end

    # SHAKE128 then the FIPS 203 SampleNTT sampler: a uniform ring vector. At most 4096 input bytes.
    def hash_to_ring(input)
      raise LatticeError, "lattice: hash input must be at most #{HASHIN_CAP} bytes" unless input.is_a?(String) && input.bytesize <= HASHIN_CAP

      o = out(TVEC_BYTES)
      ok!(lib.lweot_hash_to_ring(input.b, input.bytesize, o, TVEC_BYTES), 'hash to ring')
      o.read_bytes(TVEC_BYTES)
    end

    # The CSPRNG-backed default; #bytes(n) returns n random bytes.
    class OtRandom
      def bytes(n) = SecureRandom.random_bytes(n)
    end

    # A deterministic SplitMix64 stream (reproducible tests only).
    class SplitMix64 < OtRandom
      MASK = 0xFFFFFFFFFFFFFFFF

      def initialize(seed) = (@s = seed & MASK)

      def next64
        @s = (@s + 0x9E3779B97F4A7C15) & MASK
        z = @s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
        z ^ (z >> 31)
      end

      def bytes(n)
        out = [].tap do |a|
          while a.length < n
            v = next64
            8.times do
              a << (v & 0xFF)
              v >>= 8
            end
          end
        end
        out.first(n).pack('C*')
      end
    end

    ReceiverMessage = Struct.new(:rn, :points, :rhos)
    ReceiverState = Struct.new(:choices, :secret_keys, :rhos, :rn, :sid)
    SenderMessage = Struct.new(:ciphertexts, :sender_pads)
    Transcript = Struct.new(:rn, :points, :rhos, :ciphertexts, :encrypted, :commitments)

    def u32(x) = [x & 0xFFFFFFFF].pack('N')
    def sha(*chunks) = Digest::SHA256.digest(chunks.map(&:b).join)

    def xor(a, b)
      raise ArgumentError, 'endemic-ot: XOR length mismatch' unless a.bytesize == b.bytesize

      a.bytes.zip(b.bytes).map { |x, y| x ^ y }.pack('C*')
    end

    # sid = H(TAG || rn): binds every oracle query to this receiver nonce.
    def session_id(rn) = sha(TAG_SID, rn)

    def hpk(sid, i, other) = hash_to_ring(TAG_HPK + sid + u32(i) + other)

    # The pad for a slot: SHA-256 in counter mode over TAG || sid || i || slot || ctr || payload.
    def pad(sid, index, slot, payload, length)
      o = ''.b
      ctr = 0
      while o.bytesize < length
        o << sha(TAG_PAD, sid, u32(index), [slot & 1].pack('C'), u32(ctr), payload)
        ctr += 1
      end
      o.byteslice(0, length)
    end

    def commit(sid, i, slot, msg, pad_) = sha(TAG_COMMIT, sid, u32(i), [slot & 1].pack('C'), msg, pad_)

    # Receiver round: a real key pair per choice, a uniform vector for the other slot, C = t_real - Hpk(sid, i, N) at the choice slot.
    # Returns [ReceiverMessage, ReceiverState].
    def receive(choices, rng = OtRandom.new)
      rn = rng.bytes(SYM_BYTES)
      sid = session_id(rn)
      points = []
      rhos = []
      sks = []
      kept = []
      choices.each_with_index do |ch, i|
        c = ch & 1
        pk, sk = kpke_keygen_fips203(rng.bytes(SYM_BYTES))
        n_slot = hash_to_ring(TAG_N + sid + u32(i) + rng.bytes(SYM_BYTES))
        c_point = ring_sub(pk.byteslice(0, TVEC_BYTES), hpk(sid, i, n_slot))
        points << (c.zero? ? [c_point, n_slot] : [n_slot, c_point])
        rhos << pk.byteslice(TVEC_BYTES, PK_BYTES - TVEC_BYTES)
        sks << sk
        kept << c
      end
      [ReceiverMessage.new(rn, points, rhos), ReceiverState.new(kept, sks, rhos, rn, sid)]
    end

    def validate!(m)
      bin = ->(x, n) { x.is_a?(String) && x.bytesize == n }
      raise EndemicAbort, 'endemic LWE OT: malformed session nonce' unless bin.call(m&.rn, SYM_BYTES)
      raise EndemicAbort, 'endemic LWE OT: points/rhos length mismatch' unless m.points.is_a?(Array) && m.rhos.is_a?(Array) && m.points.length == m.rhos.length

      m.points.each_with_index do |pt, i|
        raise EndemicAbort, "endemic LWE OT: malformed point pair at index #{i}" unless pt.is_a?(Array) && pt.length == 2 && bin.call(pt[0], TVEC_BYTES) && bin.call(pt[1], TVEC_BYTES)
        raise EndemicAbort, "endemic LWE OT: malformed rho at index #{i}" unless bin.call(m.rhos[i], PK_BYTES - TVEC_BYTES)
      end
    end

    # pk_b = (P_b + Hpk(sid, i, P_{1-b}) || rho)
    def effective_key(sid, i, own, other, rho) = ring_add(own, hpk(sid, i, other)) + rho

    # Sender round (random-OT form): encrypt a fresh payload under each slot's effective key and output both pads. tamper (test-only) corrupts the
    # ciphertexts on the wire.
    def send_random(message, rng = OtRandom.new, tamper = nil)
      validate!(message)
      sid = session_id(message.rn)
      cts = []
      pads = []
      message.points.each_with_index do |(p0, p1), i|
        rho = message.rhos[i]
        pk0 = effective_key(sid, i, p0, p1, rho)
        pk1 = effective_key(sid, i, p1, p0, rho)
        r0 = rng.bytes(SYM_BYTES)
        r1 = rng.bytes(SYM_BYTES)
        ct0 = kpke_enc(pk0, r0, rng.bytes(SYM_BYTES))
        ct1 = kpke_enc(pk1, r1, rng.bytes(SYM_BYTES))
        cts << [ct0, ct1]
        pads << [pad(sid, i, 0, r0, ENDEMIC_SECRET_BYTES), pad(sid, i, 1, r1, ENDEMIC_SECRET_BYTES)]
      end
      tamper&.call(cts)
      SenderMessage.new(cts, pads)
    end

    # Receiver recovery (random-OT form): decrypt only the chosen ciphertext.
    def recover_random(state, sm)
      cts = sm&.ciphertexts
      raise EndemicAbort, 'endemic LWE OT: ciphertext count does not match the transfer count' unless cts.is_a?(Array) && cts.length == state.choices.length

      cts.each_with_index do |ct, i|
        ok = ct.is_a?(Array) && ct.length == 2 && ct.all? { |x| x.is_a?(String) && x.bytesize == CT_BYTES }
        raise EndemicAbort, "endemic LWE OT: malformed ciphertext pair at index #{i}" unless ok
      end
      state.choices.each_with_index.map do |c, i|
        pad(state.sid, i, c & 1, kpke_dec(state.secret_keys[i], cts[i][c & 1]), ENDEMIC_SECRET_BYTES)
      end
    end

    # In-process chosen-message endemic base OT: messages[i] = [m0, m1] of equal length, choices[i] in {0,1}. The sender pads and commits each
    # message; the receiver recovers m_{choices[i]} and checks the commitment, aborting on any inconsistency. receiver_rng and sender_rng are the
    # two parties' entropy; tamper_encrypted (test-only) corrupts the padded messages on the wire. Returns [received, Transcript].
    def base_ot(messages, choices, receiver_rng = OtRandom.new, sender_rng = receiver_rng, tamper_encrypted = nil)
      raise ArgumentError, 'endemicBaseOT: messages/choices length mismatch' unless messages.length == choices.length

      msg, st = receive(choices, receiver_rng)
      sid = st.sid
      cts = []
      enc = []
      com = []
      messages.each_with_index do |(m0, m1), i|
        raise ArgumentError, "endemicBaseOT (index #{i}): the two messages must be equal length" unless m0.bytesize == m1.bytesize

        (p0, p1) = msg.points[i]
        rho = msg.rhos[i]
        r0 = sender_rng.bytes(SYM_BYTES)
        r1 = sender_rng.bytes(SYM_BYTES)
        ct0 = kpke_enc(effective_key(sid, i, p0, p1, rho), r0, sender_rng.bytes(SYM_BYTES))
        ct1 = kpke_enc(effective_key(sid, i, p1, p0, rho), r1, sender_rng.bytes(SYM_BYTES))
        cts << [ct0, ct1]
        pad0 = pad(sid, i, 0, r0, m0.bytesize)
        pad1 = pad(sid, i, 1, r1, m1.bytesize)
        enc << [xor(m0, pad0), xor(m1, pad1)]
        com << [commit(sid, i, 0, m0, pad0), commit(sid, i, 1, m1, pad1)]
      end
      tamper_encrypted&.call(enc)
      received = choices.each_with_index.map do |ch, i|
        c = ch & 1
        e = enc[i][c]
        pd = pad(sid, i, c, kpke_dec(st.secret_keys[i], cts[i][c]), e.bytesize)
        m = xor(e, pd)
        unless OpenSSL.fixed_length_secure_compare(commit(sid, i, c, m, pd), com[i][c])
          raise EndemicAbort, "endemic base OT (index #{i}): sender ciphertext inconsistent with its commitment; aborting"
        end

        m
      end
      [received, Transcript.new(msg.rn, msg.points, msg.rhos, cts, enc, com)]
    end

    # The chosen-message endemic base OT as a base_ot_fn (only `received` is part of the contract): callable (messages, choices, rng) -> received.
    def base_ot_fn = ->(messages, choices, rng) { base_ot(messages, choices, rng)[0] }

    # Wire the endemic ML-KEM base OT into the KOS OT extension (the post-quantum, maliciously-secure base): the base_ot_fn to pass as the second
    # argument of an OtChannel (`OtChannel.new(rng, MpcLweOt.with_endemic_base_ot)`). Everything above the base OT is unchanged.
    def with_endemic_base_ot = base_ot_fn
  end
end
