# frozen_string_literal: true

require 'securerandom'
require_relative 'fndsa'

module AtlasPca
  # Real FN-DSA (Falcon) backend for AtlasPca::Fndsa through ffi over libfndsa.
  #
  # Every lattice operation is the small C library libfndsa (pca_fndsa.h), built from the flagship's crate with cargo build --features capi
  # (Thomas Pornin's fn-dsa 0.4.0). FIPS 206 is not final: this is a draft best guess pinned in lockstep with the TypeScript reference, so keys
  # and signatures interoperate with it and with nothing that implements the earlier round-3 Falcon. Point ATLAS_PCA_LIBFNDSA at the library,
  # or put libfndsa on the loader path. A missing or mismatched library raises Fndsa::BackendMissing; it never verifies.
  #
  #   AtlasPca::Fndsa.set_falcon_backend(AtlasPca::FndsaNative.native_backend)
  module FndsaNative
    SEED_BYTES = 32
    MESSAGE_CAP = 8192
    TAGS = { 'fn-dsa-512' => 512, 'fn-dsa-1024' => 1024 }.freeze
    SK_BYTES = { 'fn-dsa-512' => 1345, 'fn-dsa-1024' => 2369 }.freeze
    PK_BYTES = Fndsa::VARIANT_PK_BYTES
    SIG_BYTES = Fndsa::VARIANT_SIG_BYTES
    BY_SK = SK_BYTES.invert.freeze
    BY_PK = PK_BYTES.invert.freeze

    FUNCS = {
      fndsa_len_vk: [[:int32], :ssize_t], fndsa_len_sk: [[:int32], :ssize_t], fndsa_len_sig: [[:int32], :ssize_t],
      fndsa_len_seed: [[], :size_t], fndsa_cap_msg: [[], :size_t],
      fndsa_c_keygen: [%i[int32 buffer_in size_t buffer_out size_t buffer_out size_t], :int32],
      fndsa_c_sign: [%i[int32 buffer_in size_t buffer_in size_t buffer_in size_t buffer_out size_t], :int32],
      fndsa_c_verify: [%i[int32 buffer_in size_t buffer_in size_t buffer_in size_t], :int32]
    }.freeze
    LIBS = [*ENV['ATLAS_PCA_LIBFNDSA'], *Dir.glob(File.join(__dir__, 'native', '{libfndsa.so,libfndsa.dylib,fndsa.dll}')), *%w[fndsa libfndsa.so libfndsa.dylib fndsa.dll]].freeze
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
            raise Fndsa::BackendMissing, "FN-DSA needs the ffi gem and libfndsa (#{e.message})"
          end
          m = Module.new
          m.extend(FFI::Library)
          begin
            m.ffi_lib(LIBS)
            FUNCS.each { |name, (args, ret)| m.attach_function(name, args, ret) }
          rescue LoadError, FFI::NotFoundError => e
            raise Fndsa::BackendMissing, "libfndsa could not be loaded (cargo build --features capi in the flagship's crate; set ATLAS_PCA_LIBFNDSA): #{e.message}"
          end
          # the sizes this module hard-codes must be the ones the library was built with, or nothing is safe
          TAGS.each do |variant, tag|
            got = [m.fndsa_len_vk(tag), m.fndsa_len_sk(tag), m.fndsa_len_sig(tag)]
            raise Fndsa::BackendMissing, "libfndsa reports different sizes for #{variant}" unless got == [PK_BYTES[variant], SK_BYTES[variant], SIG_BYTES[variant]]
          end
          raise Fndsa::BackendMissing, 'libfndsa reports a different seed length or message cap' unless m.fndsa_len_seed == SEED_BYTES && m.fndsa_cap_msg == MESSAGE_CAP

          m
        end
      end
    end

    # True when libfndsa can be loaded.
    def available?
      lib
      true
    rescue Fndsa::BackendMissing
      false
    end

    def tag(variant)
      raise ArgumentError, "fndsa_native: unknown FN-DSA variant #{variant.inspect}" unless variant.is_a?(String) && TAGS.key?(variant)

      TAGS[variant]
    end

    def bytes(name, v)
      raise TypeError, "fndsa_native: #{name} must be bytes" unless Fndsa.bytes?(v)

      v
    end

    def out(len) = FFI::MemoryPointer.new(:uint8, len)

    # Deterministic [sk, vk] from a 32-byte seed.
    def keygen(variant, seed)
      t = tag(variant)
      s = bytes('seed', seed)
      raise ArgumentError, "fndsa_native: seed must be #{SEED_BYTES} bytes" unless s.bytesize == SEED_BYTES

      l = lib
      sk = out(SK_BYTES[variant])
      vk = out(PK_BYTES[variant])
      rc = l.fndsa_c_keygen(t, s, s.bytesize, sk, SK_BYTES[variant], vk, PK_BYTES[variant])
      raise "fndsa_native: keygen refused (#{rc})" unless rc.zero?

      [sk.read_bytes(SK_BYTES[variant]), vk.read_bytes(PK_BYTES[variant])]
    end

    # Signature over a raw message. seed is for known-answer tests only; by default 32 fresh bytes come from the system CSPRNG.
    def sign(variant, sk, msg, seed = nil)
      t = tag(variant)
      k = bytes('sk', sk)
      m = bytes('msg', msg)
      raise ArgumentError, "fndsa_native: secret key must be #{SK_BYTES[variant]} bytes for #{variant}" unless k.bytesize == SK_BYTES[variant]
      raise ArgumentError, "fndsa_native: message over #{MESSAGE_CAP} bytes" if m.bytesize > MESSAGE_CAP

      s = seed.nil? ? SecureRandom.random_bytes(SEED_BYTES) : bytes('seed', seed)
      raise ArgumentError, "fndsa_native: seed must be #{SEED_BYTES} bytes" unless s.bytesize == SEED_BYTES

      l = lib
      sig = out(SIG_BYTES[variant])
      rc = l.fndsa_c_sign(t, k, k.bytesize, m, m.bytesize, s, s.bytesize, sig, SIG_BYTES[variant])
      raise "fndsa_native: sign failed (#{rc})" unless rc.zero?

      sig.read_bytes(SIG_BYTES[variant])
    end

    # True only when the library returns 0; any bad length, oversize message or nonzero return is false.
    def verify(variant, pk, msg, sig)
      t = tag(variant)
      p = bytes('pk', pk)
      m = bytes('msg', msg)
      s = bytes('sig', sig)
      return false if p.bytesize != PK_BYTES[variant] || s.bytesize != SIG_BYTES[variant] || m.bytesize > MESSAGE_CAP

      lib.fndsa_c_verify(t, p, p.bytesize, s, s.bytesize, m, m.bytesize).zero?
    end

    # A FalconBackend over libfndsa (raises Fndsa::BackendMissing now if the library is absent). The variant follows the key length;
    # keygen draws a fresh fn-dsa-512 pair from the system CSPRNG (use keygen(variant, seed) for 1024).
    def native_backend
      lib
      Fndsa::FalconBackend.new(
        lambda { |pk, msg, sig|
          variant = BY_PK[pk.bytesize]
          !variant.nil? && verify(variant, pk, msg, sig)
        },
        lambda { |sk, msg, seed = nil|
          variant = BY_SK[sk.bytesize]
          raise ArgumentError, 'fndsa_native: unrecognised FN-DSA secret-key length' if variant.nil?

          sign(variant, sk, msg, seed)
        },
        lambda {
          sk, vk = keygen('fn-dsa-512', SecureRandom.random_bytes(SEED_BYTES))
          { 'pk' => vk, 'sk' => sk }
        },
        lambda { |variant, seed|
          sk, vk = keygen(variant, seed)
          { 'pk' => vk, 'sk' => sk }
        }
      )
    end
  end
end
