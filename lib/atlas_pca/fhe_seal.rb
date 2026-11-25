# frozen_string_literal: true

require 'base64'

module AtlasPca
  # Homomorphic risk gate (BFV on Microsoft SEAL), wire-compatible with the TypeScript package (node-seal 5.1.x bundles SEAL 4.1.x).
  #
  # BFV is never reimplemented here: this binds SEAL's own C export API (native/src/seal/c, the one SEAL.NET binds) through the ffi gem, so
  # the optional native library libsealc (built from the pinned SEAL tag) is the only extra requirement. Point ATLAS_PCA_LIBSEALC at it, or
  # install it where the loader finds libsealc. Every SEAL object crosses the API as the base64 of its SEAL native stream.
  module FheSeal
    POLY_MODULUS_DEGREE = 8192
    PLAIN_MODULUS_BITS = 30
    PLAIN_MODULUS = 1_073_692_673
    SIGNED_BOUND = PLAIN_MODULUS / 2
    RISK_DIM = 6
    MIN_NOISE_BUDGET_BITS = 16
    BFV = 1
    TC128 = 128
    COMPR_NONE = 0
    COMPR_ZSTD = 2

    # The public gate policy: fixed-point weights, kappa-weighted weights and the budget bound (scale S, budget at S^2).
    Policy = Data.define(:scale, :dim, :weights_scaled, :kappa_weights_scaled, :budget_scaled, :kappa) do
      def initialize(scale:, dim:, weights_scaled:, kappa_weights_scaled:, budget_scaled:, kappa: 1.0) = super
    end
    Keyset = Data.define(:secret_key, :public_key, :relin_keys, :galois_keys)
    EncryptedGate = Data.define(:enc_risk_raw, :enc_slack)
    # r_scaled is r at scale S^2 clamped to [0, S^2]; admit is slack >= 0.
    Verdict = Data.define(:r_scaled, :slack, :admit)

    P = :pointer
    # The slice of SEAL's C export API the gate uses (SEAL 4.1.x prototypes; HRESULT is long off Windows).
    PROTOS = {
      EncParams_Create1: [[:uint8, P]], EncParams_Destroy: [[P]], EncParams_SetPolyModulusDegree: [[P, :uint64]],
      EncParams_SetCoeffModulus: [[P, :uint64, P]], EncParams_SetPlainModulus1: [[P, P]],
      CoeffModulus_BFVDefault: [[:uint64, :int, P, P]], CoeffModulus_Create1: [[:uint64, :uint64, P, P]],
      Modulus_Destroy: [[P]], Modulus_Value: [[P, P]],
      SEALContext_Create: [[P, :bool, :int, P]], SEALContext_Destroy: [[P]], SEALContext_ParametersSet: [[P, P]],
      BatchEncoder_Create: [[P, P]], BatchEncoder_Destroy: [[P]], BatchEncoder_Encode2: [[P, :uint64, P, P]],
      BatchEncoder_Decode2: [[P, P, P, P, P]], BatchEncoder_GetSlotCount: [[P, P]],
      KeyGenerator_Create1: [[P, P]], KeyGenerator_Destroy: [[P]], KeyGenerator_SecretKey: [[P, P]],
      KeyGenerator_CreatePublicKey: [[P, :bool, P]], KeyGenerator_CreateRelinKeys: [[P, :bool, P]],
      KeyGenerator_CreateGaloisKeysAll: [[P, :bool, P]],
      PublicKey_Create1: [[P]], PublicKey_Destroy: [[P]], PublicKey_SaveSize: [[P, :uint8, P]],
      PublicKey_Save: [[P, P, :uint64, :uint8, P]], PublicKey_Load: [[P, P, P, :uint64, P]],
      SecretKey_Create1: [[P]], SecretKey_Destroy: [[P]], SecretKey_SaveSize: [[P, :uint8, P]],
      SecretKey_Save: [[P, P, :uint64, :uint8, P]], SecretKey_Load: [[P, P, P, :uint64, P]],
      KSwitchKeys_Create1: [[P]], KSwitchKeys_Destroy: [[P]], KSwitchKeys_SaveSize: [[P, :uint8, P]],
      KSwitchKeys_Save: [[P, P, :uint64, :uint8, P]], KSwitchKeys_Load: [[P, P, P, :uint64, P]],
      Ciphertext_Create1: [[P, P]], Ciphertext_Create2: [[P, P]], Ciphertext_Destroy: [[P]],
      Ciphertext_SaveSize: [[P, :uint8, P]], Ciphertext_Save: [[P, P, :uint64, :uint8, P]], Ciphertext_Load: [[P, P, P, :uint64, P]],
      Plaintext_Create1: [[P, P]], Plaintext_Destroy: [[P]],
      Encryptor_Create: [[P, P, P, P]], Encryptor_Encrypt: [[P, P, P, P]], Encryptor_Destroy: [[P]],
      Decryptor_Create: [[P, P, P]], Decryptor_Destroy: [[P]], Decryptor_Decrypt: [[P, P, P]], Decryptor_InvariantNoiseBudget: [[P, P, P]],
      Evaluator_Create: [[P, P]], Evaluator_Destroy: [[P]], Evaluator_Negate: [[P, P, P]], Evaluator_Add: [[P, P, P, P]],
      Evaluator_AddPlain: [[P, P, P, P]], Evaluator_MultiplyPlain: [[P, P, P, P, P]],
      Evaluator_RotateRows: [[P, P, :int, P, P, P]], Evaluator_RotateColumns: [[P, P, P, P, P]]
    }.freeze
    KINDS = { public: 'PublicKey', secret: 'SecretKey', keys: 'KSwitchKeys', cipher: 'Ciphertext' }.freeze
    B64 = %r{\A[A-Za-z0-9+/]*={0,2}\z}
    LOCK = Mutex.new
    @lib = nil

    module_function

    # True when the ffi gem and libsealc are usable.
    def available?
      lib
      true
    rescue LoadError
      false
    end

    def lib
      return @lib if @lib

      LOCK.synchronize do
        @lib ||= begin
          begin
            require 'ffi'
          rescue LoadError => e
            raise LoadError, "FheSeal needs the ffi gem and libsealc (#{e.message})"
          end
          m = Module.new
          m.extend(FFI::Library)
          begin
            m.ffi_lib([*ENV['ATLAS_PCA_LIBSEALC'], *Dir.glob(File.join(__dir__, 'native', '{libsealc.so,libsealc.dylib,sealc.dll}')), 'sealc', 'libsealc.so', 'libsealc.dylib'])
          rescue LoadError => e
            raise LoadError, "libsealc not found: build it from the pinned SEAL tag and set ATLAS_PCA_LIBSEALC (#{e.message})"
          end
          PROTOS.each { |name, (args)| m.attach_function(name, args, :long) }
          m
        end
      end
    end

    def call(name, *args)
      hr = lib.public_send(name, *args)
      # SEAL's HRESULT convention: negative is failure, S_FALSE (1) is success
      raise "seal #{name} failed: 0x#{format('%08x', hr & 0xFFFFFFFF)}" if hr.negative?
    end

    # Creates a handle with its create function and queues its destroy; handles are released in reverse order by +release+.
    def make(scope, create, destroy, *args)
      out = FFI::MemoryPointer.new(:pointer)
      call(create, *args, out)
      h = out.read_pointer
      scope << [destroy, h]
      h
    end

    def release(scope)
      scope.reverse_each { |destroy, h| lib.public_send(destroy, h) if destroy }
      scope.clear
    end

    def with_scope
      scope = []
      yield scope
    ensure
      release(scope)
    end

    # Rejects anything that is not a well-formed SEAL stream envelope (magic, header size, compression mode, declared size == length).
    def assert_seal_blob(blob, what)
      raise ArgumentError, "#{what}: not a serialized SEAL object (bad encoding)" unless blob.is_a?(String) && blob.length >= 24 && (blob.length % 4).zero? && B64.match?(blob)

      b = Base64.strict_decode64(blob).b
      raise ArgumentError, "#{what}: not a serialized SEAL object (bad header)" if b.bytesize < 16 || b.getbyte(0) != 0x5E || b.getbyte(1) != 0xA1 ||
                                                                                       b.getbyte(2) != 16 || b.getbyte(5) > 2 || b.getbyte(6) != 0 || b.getbyte(7) != 0

      size = b.byteslice(8, 8).unpack1('Q<')
      raise ArgumentError, "#{what}: truncated or padded SEAL object (declared #{size} bytes, got #{b.bytesize})" if size != b.bytesize

      b
    end

    # The policy crosses a trust boundary: validate every coefficient exactly as the policy builder would have produced it.
    def require_policy(p)
      raise ArgumentError, 'policy must be a FheSeal::Policy' unless p.is_a?(Policy)

      ints = [p.scale, p.dim, p.budget_scaled, *p.weights_scaled, *p.kappa_weights_scaled]
      raise ArgumentError, 'policy coefficients must be integers' unless ints.all?(Integer)
      raise ArgumentError, 'policy.scale must be a positive integer' unless p.scale.positive?
      raise ArgumentError, 'policy coefficients must be integers with |value| < SIGNED_BOUND' if [p.budget_scaled, *p.weights_scaled, *p.kappa_weights_scaled].any? { |v| v.abs >= SIGNED_BOUND }
      raise ArgumentError, "policy.dim must be #{RISK_DIM}" unless p.dim == RISK_DIM
      raise ArgumentError, "policy weight vectors must have length #{RISK_DIM}" unless p.weights_scaled.length == RISK_DIM && p.kappa_weights_scaled.length == RISK_DIM
    end

    def u64(ptr) = ptr.read_uint64

    def context(s)
      parms = make(s, :EncParams_Create1, :EncParams_Destroy, BFV)
      call(:EncParams_SetPolyModulusDegree, parms, POLY_MODULUS_DEGREE)
      n = FFI::MemoryPointer.new(:uint64)
      call(:CoeffModulus_BFVDefault, POLY_MODULUS_DEGREE, TC128, n, nil)
      count = u64(n)
      coeffs = FFI::MemoryPointer.new(:pointer, count)
      call(:CoeffModulus_BFVDefault, POLY_MODULUS_DEGREE, TC128, n, coeffs)
      coeffs.read_array_of_pointer(count).each { |m| s << [:Modulus_Destroy, m] }
      call(:EncParams_SetCoeffModulus, parms, count, coeffs)
      bits = FFI::MemoryPointer.new(:int)
      bits.write_int(PLAIN_MODULUS_BITS)
      out = FFI::MemoryPointer.new(:pointer)
      call(:CoeffModulus_Create1, POLY_MODULUS_DEGREE, 1, bits, out)
      plain = out.read_pointer
      s << [:Modulus_Destroy, plain]
      live = FFI::MemoryPointer.new(:uint64)
      call(:Modulus_Value, plain, live)
      raise "plain modulus drift: live #{u64(live)} != documented #{PLAIN_MODULUS}" if u64(live) != PLAIN_MODULUS

      call(:EncParams_SetPlainModulus1, parms, plain)
      ctx = make(s, :SEALContext_Create, :SEALContext_Destroy, parms, true, TC128)
      ok = FFI::MemoryPointer.new(:uint8)
      call(:SEALContext_ParametersSet, ctx, ok)
      raise 'SEAL rejected the BFV parameters' if ok.read_uint8.zero?

      enc = make(s, :BatchEncoder_Create, :BatchEncoder_Destroy, ctx)
      sc = FFI::MemoryPointer.new(:uint64)
      call(:BatchEncoder_GetSlotCount, enc, sc)
      { context: ctx, encoder: enc, slots: u64(sc) }
    end

    def new_obj(s, kind)
      t = KINDS.fetch(kind)
      kind == :cipher ? make(s, :Ciphertext_Create1, :Ciphertext_Destroy, nil) : make(s, :"#{t}_Create1", :"#{t}_Destroy")
    end

    def load_obj(ctx, s, kind, blob, what)
      raw = assert_seal_blob(blob, what)
      buf = FFI::MemoryPointer.new(:uint8, raw.bytesize)
      buf.put_bytes(0, raw)
      p = new_obj(s, kind)
      call(:"#{KINDS.fetch(kind)}_Load", p, ctx[:context], buf, raw.bytesize, FFI::MemoryPointer.new(:int64))
      p
    end

    def save_obj(kind, p, compr = COMPR_ZSTD)
      t = KINDS.fetch(kind)
      size = FFI::MemoryPointer.new(:int64)
      call(:"#{t}_SaveSize", p, compr, size)
      n = size.read_int64
      buf = FFI::MemoryPointer.new(:uint8, n)
      out = FFI::MemoryPointer.new(:int64)
      call(:"#{t}_Save", p, buf, n, compr, out)
      Base64.strict_encode64(buf.get_bytes(0, out.read_int64))
    end

    def encode(ctx, s, values)
      slots = FFI::MemoryPointer.new(:int64, ctx[:slots])
      slots.write_array_of_int64(values.to_a)
      pt = make(s, :Plaintext_Create1, :Plaintext_Destroy, nil)
      call(:BatchEncoder_Encode2, ctx[:encoder], ctx[:slots], slots, pt)
      pt
    end

    # Generates the key material (the secret key stays with the policy owner).
    def keygen
      with_scope do |s|
        ctx = context(s)
        gen = make(s, :KeyGenerator_Create1, :KeyGenerator_Destroy, ctx[:context])
        sk = make(s, :KeyGenerator_SecretKey, nil, gen) # a view of the generator's own key (SEAL.NET: owned false): destroying it too is a double free
        pk = make(s, :KeyGenerator_CreatePublicKey, :PublicKey_Destroy, gen, false)
        rk = make(s, :KeyGenerator_CreateRelinKeys, :KSwitchKeys_Destroy, gen, false)
        gk = make(s, :KeyGenerator_CreateGaloisKeysAll, :KSwitchKeys_Destroy, gen, false)
        Keyset.new(save_obj(:secret, sk), save_obj(:public, pk), save_obj(:keys, rk), save_obj(:keys, gk))
      end
    end

    # BFV-encrypts the quantized risk-input vector (length 6, each a non-negative integer below the signed bound).
    def encrypt_risk_inputs(public_key, inputs_scaled)
      raise ArgumentError, "inputs_scaled must have length #{RISK_DIM}" unless inputs_scaled.length == RISK_DIM
      raise ArgumentError, 'each scaled input must be a non-negative integer below the signed bound' unless inputs_scaled.all? { |v| v.is_a?(Integer) && v >= 0 && v < SIGNED_BOUND }

      with_scope do |s|
        ctx = context(s)
        pk = load_obj(ctx, s, :public, public_key, 'publicKey')
        enc = make(s, :Encryptor_Create, :Encryptor_Destroy, ctx[:context], pk, nil)
        pt = encode(ctx, s, inputs_scaled)
        ct = new_obj(s, :cipher)
        call(:Encryptor_Encrypt, enc, pt, ct, nil)
        save_obj(:cipher, ct)
      end
    end

    # Evaluates the gate blind with the reference's operation order (multiplyPlain, sumElements, negate, addPlain). Never builds a decryptor.
    def eval_risk_gate(public_key, galois_keys, enc_inputs, policy)
      require_policy(policy)
      with_scope do |s|
        ctx = context(s)
        gk = load_obj(ctx, s, :keys, galois_keys, 'galoisKeys')
        pk = load_obj(ctx, s, :public, public_key, 'publicKey')
        ev = make(s, :Evaluator_Create, :Evaluator_Destroy, ctx[:context])
        enc = make(s, :Encryptor_Create, :Encryptor_Destroy, ctx[:context], pk, nil)
        x = load_obj(ctx, s, :cipher, enc_inputs, 'encInputs')

        total = lambda do |prod|
          temp = make(s, :Ciphertext_Create2, :Ciphertext_Destroy, prod)
          dest = new_obj(s, :cipher)
          call(:Evaluator_RotateColumns, ev, temp, gk, dest, nil)
          call(:Evaluator_Add, ev, temp, dest, temp)
          steps = POLY_MODULUS_DEGREE / 4
          while steps >= 1
            call(:Evaluator_RotateRows, ev, temp, steps, gk, dest, nil)
            call(:Evaluator_RotateColumns, ev, dest, gk, dest, nil)
            call(:Evaluator_Add, ev, temp, dest, temp)
            steps /= 2
          end
          temp
        end
        dot = lambda do |coeffs|
          # SEAL refuses multiplyPlain by an all-zero plaintext (transparent result): the dot product is then a fresh encryption of zero.
          if coeffs.all?(&:zero?)
            ct = new_obj(s, :cipher)
            call(:Encryptor_Encrypt, enc, encode(ctx, s, []), ct, nil)
            next ct
          end
          prod = new_obj(s, :cipher)
          call(:Evaluator_MultiplyPlain, ev, x, encode(ctx, s, coeffs), prod, nil)
          total.call(prod)
        end

        risk_raw = dot.call(policy.weights_scaled)
        kappa_risk = dot.call(policy.kappa_weights_scaled)
        neg = new_obj(s, :cipher)
        slack = new_obj(s, :cipher)
        call(:Evaluator_Negate, ev, kappa_risk, neg)
        call(:Evaluator_AddPlain, ev, neg, encode(ctx, s, [policy.budget_scaled]), slack)
        EncryptedGate.new(save_obj(:cipher, risk_raw), save_obj(:cipher, slack))
      end
    end

    # Decrypts the gate outputs and reads the verdict; fails closed when the noise budget is exhausted (wrong key, corrupt or foreign ciphertext).
    def decrypt_verdict(secret_key, enc_risk_raw, enc_slack, policy)
      require_policy(policy)
      with_scope do |s|
        ctx = context(s)
        sk = load_obj(ctx, s, :secret, secret_key, 'secretKey')
        dec = make(s, :Decryptor_Create, :Decryptor_Destroy, ctx[:context], sk)
        cts = [load_obj(ctx, s, :cipher, enc_risk_raw, 'encRiskRaw'), load_obj(ctx, s, :cipher, enc_slack, 'encSlack')]
        cts.each do |ct|
          nb = FFI::MemoryPointer.new(:int)
          call(:Decryptor_InvariantNoiseBudget, dec, ct, nb)
          raise ArgumentError, 'decrypt_verdict: ciphertext has no noise budget left (wrong key, corrupted, or not produced by the gate)' if nb.read_int < MIN_NOISE_BUDGET_BITS
        end
        first = lambda do |ct|
          pt = make(s, :Plaintext_Create1, :Plaintext_Destroy, nil)
          call(:Decryptor_Decrypt, dec, ct, pt)
          n = FFI::MemoryPointer.new(:uint64) # the C export rejects a null destination: size the buffer from the slot count and check the count after
          n.write_uint64(ctx[:slots])
          out = FFI::MemoryPointer.new(:int64, ctx[:slots])
          call(:BatchEncoder_Decode2, ctx[:encoder], pt, n, out, nil)
          raise 'seal BatchEncoder_Decode2 returned an unexpected slot count' if u64(n) != ctx[:slots]

          out.read_array_of_int64(1).first
        end
        raw = first.call(cts[0])
        slack = first.call(cts[1])
        Verdict.new(raw.clamp(0, policy.scale * policy.scale), slack, slack >= 0)
      end
    end

    # The deterministic BFV context (the reference's createFheContext): #slot_count is the batching slot count, #dispose releases
    # every native object the context owns (idempotent). The caller disposes it.
    class Context
      attr_reader :slot_count

      def initialize(scope, ctx)
        @scope = scope
        @ctx = ctx
        @slot_count = ctx[:slots]
      end

      def dispose
        FheSeal.release(@scope)
        nil
      end
    end

    def create_fhe_context
      scope = []
      begin
        Context.new(scope, context(scope))
      rescue StandardError, LoadError
        release(scope)
        raise
      end
    end

    # Re-saves a base64 SEAL ciphertext uncompressed, for byte comparison independent of the zstd build.
    def canonical_cipher(blob)
      with_scope do |s|
        ctx = context(s)
        save_obj(:cipher, load_obj(ctx, s, :cipher, blob, 'ciphertext'), COMPR_NONE)
      end
    end
  end
end
