# frozen_string_literal: true

require 'json'

module AtlasPca
  # Groth16 over BN254 and BLS12-381 through ffi over libpcazk (pca_zk.h): the pairing check of a snarkjs proof and the prover.
  #
  # Every curve operation is the small C library libpcazk, built from the flagship's zk crate with cargo build --features capi
  # (arkworks). Opt-in: nothing else in the library loads it. The platform gem carries libpcazk in lib/atlas_pca/native;
  # ATLAS_PCA_LIBPCAZK names another build, else the loader path is searched. A missing or mismatched library raises
  # ZkNative::BackendMissing: it never answers "invalid" and never verifies.
  #
  # The library decides the pairing question only. The checks in front of it (envelope shape, circuit and system tags, the
  # public-signal count and pins) are the caller's.
  #
  #   require 'atlas_pca/zk_native'
  #   AtlasPca::ZkNative.verify('bn254', verification_key, proof, public_signals) # => { 'valid' => true, 'reason' => 'ok' }
  module ZkNative
    # libpcazk (or the ffi gem) is not available, or is not the library this module was written for.
    class BackendMissing < StandardError; end

    # The prover refused: #code is 'prove' (the witness does not satisfy the circuit, or a zkey the prover cannot read),
    # 'witness' (the witness program failed or the input does not fit the circuit), 'zkey' (malformed, or for another curve),
    # 'input' (not a JSON object) or 'internal'.
    class ProveError < StandardError
      attr_reader :code

      def initialize(code, message)
        super(message)
        @code = code
      end
    end

    CURVES = { 'bn254' => 0, 'bls12-381' => 1 }.freeze
    # the library reads the curve from the key's own name, as snarkjs does (letters and digits, any case; BN128 | BN254 | ALTBN128 | BLS12381); only with the
    # compat flag (never strict, never prove): a name it does not know is invalid with the reason bad_curve
    CURVE_FROM_KEY = 2
    FROM_KEY = :from_key
    FLAG_SNARKJS_COMPAT = 1
    VALID = 1
    INVALID = 0
    ERR_ARG = -1
    # why a proof was refused, by the library's reason number
    REASONS = %w[ok bad_json bad_protocol bad_curve bad_encoding not_in_subgroup not_affine bad_shape signal_count ic_short pairing_failed].freeze
    PROVE_ERRORS = { -2 => 'internal', -3 => 'prove', -4 => 'witness', -5 => 'zkey', -6 => 'input' }.freeze
    SEED_BYTES = 32

    FUNCS = {
      pca_zk_version: [[], :string],
      pca_zk_reason_text: [[:int32], :string],
      pca_zk_verify: [%i[int32 uint32 buffer_in size_t buffer_in size_t buffer_in size_t pointer], :int32],
      pca_zk_prove: [%i[int32 buffer_in size_t buffer_in size_t buffer_in size_t pointer size_t pointer pointer], :int32],
      pca_zk_free: [%i[pointer size_t], :void]
    }.freeze
    LIBS = [*ENV['ATLAS_PCA_LIBPCAZK'], *Dir.glob(File.join(__dir__, 'native', '{libpcazk.so,libpcazk.dylib,pcazk.dll}')),
            *%w[pcazk libpcazk.so libpcazk.dylib pcazk.dll]].freeze
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
            raise BackendMissing, "the zk backend needs the ffi gem and libpcazk (#{e.message})"
          end
          m = Module.new
          m.extend(FFI::Library)
          begin
            m.ffi_lib(LIBS)
            FUNCS.each { |name, (args, ret)| m.attach_function(name, args, ret) }
          rescue LoadError, FFI::NotFoundError => e
            raise BackendMissing, "libpcazk could not be loaded (cargo build --features capi in the flagship's zk crate; set ATLAS_PCA_LIBPCAZK): #{e.message}"
          end
          # the reason table this module names must be as long as the library's, or a refusal would be reported under another name
          unless m.pca_zk_reason_text(0) == 'ok' && m.pca_zk_reason_text(REASONS.length - 1) != 'unknown' && m.pca_zk_reason_text(REASONS.length) == 'unknown'
            raise BackendMissing, 'libpcazk reports a different set of refusal reasons'
          end
          m
        end
      end
    end

    # True when libpcazk can be loaded.
    def available?
      lib
      true
    rescue BackendMissing
      false
    end

    # The library's version text.
    def version = lib.pca_zk_version

    def curve_id(curve) = CURVES.fetch(curve) { raise ArgumentError, "zk: unknown curve #{curve.inspect} (bn254 | bls12-381)" }

    # the library's curve code: an explicit curve, or FROM_KEY (the key names it; not with `strict`)
    def verify_curve_id(curve, strict)
      return curve_id(curve) unless curve == FROM_KEY
      raise ArgumentError, 'zk: the curve cannot be read from the key in strict mode' if strict

      CURVE_FROM_KEY
    end

    # a snarkjs JSON document: a String is sent as it is, anything else is serialised
    def json_bytes(doc, what)
      (doc.is_a?(String) ? doc : JSON.generate(doc)).b
    rescue JSON::GeneratorError, Encoding::UndefinedConversionError, Encoding::InvalidByteSequenceError => e
      raise ArgumentError, "zk: #{what} is not JSON (#{e.message})"
    end

    # The Groth16 pairing check of `proof` (snarkjs proof.json) for `public_signals` (decimal strings) under
    # `verification_key` (snarkjs verification_key.json) on `curve` ('bn254' | 'bls12-381', or FROM_KEY: the curve the key names). Each document is a Hash / Array or its
    # JSON text. Answers {'valid' => true, 'reason' => 'ok'} or {'valid' => false, 'reason' => one of REASONS}.
    # By default the verdict is the one snarkjs gives (the key's protocol and nPublic members and surplus IC entries are not
    # checked); `strict: true` refuses a key with any of those. A proof point outside the prime-order subgroup, a non-canonical
    # field element and a public signal at or above the group order are refused in both modes.
    # Raises BackendMissing without the library and ArgumentError for a call the library rejects as such: never "invalid".
    def verify(curve, verification_key, proof, public_signals, strict: false)
      id = verify_curve_id(curve, strict)
      vk = json_bytes(verification_key, 'the verification key')
      pr = json_bytes(proof, 'the proof')
      sg = json_bytes(public_signals, 'the public signals')
      l = lib
      reason = FFI::MemoryPointer.new(:int32)
      reason.write_int32(-1)
      rc = l.pca_zk_verify(id, strict ? 0 : FLAG_SNARKJS_COMPAT, vk, vk.bytesize, pr, pr.bytesize, sg, sg.bytesize, reason)
      code = reason.read_int32
      return { 'valid' => true, 'reason' => 'ok' } if rc == VALID && code.zero?
      # an answer of "invalid" always names a reason this module knows; anything else is not a verdict
      return { 'valid' => false, 'reason' => REASONS[code] } if rc == INVALID && code.between?(1, REASONS.length - 1)
      raise ArgumentError, 'zk: libpcazk rejected the call (argument error)' if rc == ERR_ARG

      raise BackendMissing, "libpcazk answered #{rc} (reason #{code}), which is not a verdict"
    end

    # A Groth16 proof of the circuit whose witness program is `wasm` (the bytes of circom's <circuit>.wasm) under the proving key
    # `zkey` (the bytes of the snarkjs .zkey, held in memory whole) for `input` (the circuit's input object, or its JSON text):
    # {'proof' => {...}, 'publicSignals' => ['...', ...]} as snarkjs writes them. `seed` (32 bytes) makes the blinding
    # deterministic and is for known-answer tests only: leave it out and the library draws from the operating system.
    # Raises ProveError when the prover refuses.
    def prove(curve, wasm, zkey, input, seed: nil)
      id = curve_id(curve)
      raise ArgumentError, 'zk: wasm and zkey must be byte strings' unless wasm.is_a?(String) && zkey.is_a?(String)
      raise ArgumentError, "zk: seed must be #{SEED_BYTES} bytes" unless seed.nil? || (seed.is_a?(String) && seed.bytesize == SEED_BYTES)

      inp = json_bytes(input, 'the input')
      l = lib
      seed_ptr = nil
      unless seed.nil?
        seed_ptr = FFI::MemoryPointer.new(:uint8, SEED_BYTES)
        seed_ptr.put_bytes(0, seed.b)
      end
      out = FFI::MemoryPointer.new(:pointer)
      out_len = FFI::MemoryPointer.new(:size_t)
      out.write_pointer(nil)
      out_len.write(:size_t, 0)
      rc = l.pca_zk_prove(id, wasm.b, wasm.bytesize, zkey.b, zkey.bytesize, inp, inp.bytesize, seed_ptr, seed.nil? ? 0 : SEED_BYTES, out, out_len)
      ptr = out.read_pointer
      len = out_len.read(:size_t)
      text = ''
      unless ptr.null?
        begin
          text = ptr.read_bytes(len).force_encoding('UTF-8')
        ensure
          l.pca_zk_free(ptr, len) # the buffer is the library's: copied above, released exactly once
        end
      end
      raise ArgumentError, 'zk: libpcazk rejected the call (argument error)' if rc == ERR_ARG
      raise ProveError.new(PROVE_ERRORS.fetch(rc, 'internal'), text.scrub) unless rc.zero?

      JSON.parse(text)
    end
  end
end
