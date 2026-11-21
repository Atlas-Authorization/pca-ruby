# frozen_string_literal: true

require_relative 'mpc'

module AtlasPca
  module Mpc
    # The few OpenSSL libcrypto entry points the OT stack needs that the openssl gem does not expose: the SHAKE256 extendable-output
    # function with a caller-chosen length, and ML-KEM-768 (OpenSSL >= 3.5) with caller-supplied key-generation seed and encapsulation
    # message, so the OT transcripts are reproducible from a seeded stream (the gem's PKey#encapsulate draws its own randomness).
    # Everything is the vetted OpenSSL implementation; nothing is written out here. Bound lazily through ffi to the vetted OpenSSL 3.x library (PCA_LIBCRYPTO overrides the
    # library name); the module fails closed with LoadError when ffi or libcrypto is missing.
    module Libcrypto
      # macOS: the bare names resolve to the system stub (LibreSSL), whose loader aborts the whole process ("loading libcrypto in an unsafe way"), so
      # only the Homebrew OpenSSL 3 paths are tried there
      BREW = [ENV['HOMEBREW_PREFIX'], '/opt/homebrew', '/usr/local'].compact.map { |h| "#{h}/opt/openssl@3/lib/libcrypto.3.dylib" }.freeze
      LIBS = if RUBY_PLATFORM.include?('darwin')
               [ENV.fetch('PCA_LIBCRYPTO', nil), *BREW].compact.freeze
             else
               [ENV.fetch('PCA_LIBCRYPTO', nil), 'libcrypto.so.3', 'libcrypto.3.dylib', 'libcrypto.dylib', 'libcrypto-3-x64.dll', 'libcrypto-3.dll',
                'crypto'].compact.freeze
             end
      LOCK = Mutex.new
      @bound = false

      module_function

      def lib
        return @lib if @bound

        LOCK.synchronize do
          return @lib if @bound

          begin
            require 'ffi'
          rescue LoadError => e
            raise LoadError, "the OT stack needs the ffi gem and OpenSSL libcrypto 3.x (#{e.message})"
          end
          m = Module.new
          m.extend(FFI::Library)
          begin
            m.ffi_lib(LIBS)
          rescue LoadError => e
            raise LoadError, "the OT stack needs OpenSSL libcrypto 3.x: #{e.message}"
          end
          m.attach_function(:EVP_shake256, [], :pointer)
          m.attach_function(:EVP_MD_CTX_new, [], :pointer)
          m.attach_function(:EVP_MD_CTX_free, [:pointer], :void)
          m.attach_function(:EVP_DigestInit_ex, %i[pointer pointer pointer], :int)
          m.attach_function(:EVP_DigestUpdate, %i[pointer buffer_in size_t], :int)
          m.attach_function(:EVP_DigestFinalXOF, %i[pointer buffer_out size_t], :int)
          attach_kem(m)
          @lib = m
          @bound = true
          @lib
        end
      end

      def attach_kem(m)
        m.attach_function(:OPENSSL_version_major, [], :uint)
        m.attach_function(:OPENSSL_version_minor, [], :uint)
        m.attach_function(:EVP_PKEY_CTX_new_from_name, %i[pointer string pointer], :pointer)
        m.attach_function(:EVP_PKEY_CTX_new_from_pkey, %i[pointer pointer pointer], :pointer)
        m.attach_function(:EVP_PKEY_CTX_free, [:pointer], :void)
        m.attach_function(:EVP_PKEY_CTX_set_params, %i[pointer pointer], :int)
        m.attach_function(:EVP_PKEY_keygen_init, [:pointer], :int)
        m.attach_function(:EVP_PKEY_keygen, %i[pointer pointer], :int)
        m.attach_function(:EVP_PKEY_free, [:pointer], :void)
        m.attach_function(:EVP_PKEY_get_raw_public_key, %i[pointer pointer pointer], :int)
        m.attach_function(:EVP_PKEY_new_raw_public_key_ex, %i[pointer string pointer pointer size_t], :pointer)
        m.attach_function(:EVP_PKEY_encapsulate_init, %i[pointer pointer], :int)
        m.attach_function(:EVP_PKEY_encapsulate, %i[pointer pointer pointer pointer pointer], :int)
        m.attach_function(:EVP_PKEY_decapsulate_init, %i[pointer pointer], :int)
        m.attach_function(:EVP_PKEY_decapsulate, %i[pointer pointer pointer pointer size_t], :int)
        m.attach_function(:ERR_get_error, [], :ulong)
        m.attach_function(:ERR_error_string_n, %i[ulong pointer size_t], :void)
      end

      # whether the loaded libcrypto is OpenSSL >= 3.5 (ML-KEM in the default provider)
      def mlkem_available?
        l = lib
        major = l.OPENSSL_version_major
        major > 3 || (major == 3 && l.OPENSSL_version_minor >= 5)
      rescue LoadError
        false
      end

      # SHAKE256(data) squeezed to outlen bytes
      def shake256(data, outlen)
        raise ArgumentError, 'shake256: negative output length' if outlen.negative?

        l = lib
        ctx = l.EVP_MD_CTX_new
        raise 'shake256: EVP_MD_CTX_new failed' if ctx.null?

        begin
          raise 'shake256: init failed' unless l.EVP_DigestInit_ex(ctx, l.EVP_shake256, nil) == 1

          d = data.b
          raise 'shake256: update failed' unless l.EVP_DigestUpdate(ctx, d, d.bytesize) == 1

          out = "\0".b * [outlen, 1].max
          raise 'shake256: squeeze failed' unless l.EVP_DigestFinalXOF(ctx, out, outlen) == 1

          out.byteslice(0, outlen)
        ensure
          l.EVP_MD_CTX_free(ctx)
        end
      end

      # ML-KEM-768 (FIPS 203): key generation from a 64-byte seed (d || z) and encapsulation from a 32-byte message m
      module MlKem768
        PK_BYTES = 1184
        CT_BYTES = 1088
        SS_BYTES = 32
        SEED_BYTES = 64
        MSG_BYTES = 32
        OCTET_STRING = 5 # OSSL_PARAM_OCTET_STRING
        UNMODIFIED = (1 << 64) - 1

        # a decapsulation key: owns its EVP_PKEY and frees it with the object
        class SecretKey
          attr_reader :pkey

          def initialize(pkey)
            @pkey = FFI::AutoPointer.new(pkey, Libcrypto.lib.method(:EVP_PKEY_free))
          end
        end

        KeyPair = Struct.new(:public_key, :secret_key)
        Encapsulation = Struct.new(:cipher_text, :shared_secret)

        module_function

        def err(what)
          out = []
          while (e = Libcrypto.lib.ERR_get_error) != 0
            buf = FFI::MemoryPointer.new(:char, 256)
            Libcrypto.lib.ERR_error_string_n(e, buf, 256)
            out << buf.read_string
          end
          "ML-KEM: #{what} failed#{out.empty? ? '' : " (#{out.join('; ')})"}"
        end

        def param_class
          @param_class ||= Class.new(FFI::Struct) do
            layout :key, :pointer, :data_type, :uint, :data, :pointer, :data_size, :size_t, :return_size, :size_t
          end
        end

        # a one-entry OSSL_PARAM array holding an octet string, plus the objects that must stay alive during the call
        def octet_param(name, data)
          data = data.b
          key = FFI::MemoryPointer.from_string(name)
          buf = FFI::MemoryPointer.new(:uint8, data.bytesize)
          buf.put_bytes(0, data)
          arr = FFI::MemoryPointer.new(param_class, 2)
          p0 = param_class.new(arr)
          p0[:key] = key
          p0[:data_type] = OCTET_STRING
          p0[:data] = buf
          p0[:data_size] = data.bytesize
          p0[:return_size] = UNMODIFIED
          [arr, [key, buf]]
        end

        def check_available!
          raise LoadError, 'ML-KEM-768 needs OpenSSL >= 3.5' unless Libcrypto.mlkem_available?
        end

        def keygen(seed64)
          check_available!
          raise ArgumentError, 'ml-kem keygen: seed must be exactly 64 bytes' unless seed64.is_a?(String) && seed64.bytesize == SEED_BYTES

          l = Libcrypto.lib
          ctx = l.EVP_PKEY_CTX_new_from_name(nil, 'ML-KEM-768', nil)
          raise err('EVP_PKEY_CTX_new_from_name') if ctx.null?

          begin
            raise err('EVP_PKEY_keygen_init') unless l.EVP_PKEY_keygen_init(ctx) == 1

            params, keep = octet_param('seed', seed64)
            raise err('EVP_PKEY_CTX_set_params(seed)') unless l.EVP_PKEY_CTX_set_params(ctx, params) == 1

            out = FFI::MemoryPointer.new(:pointer)
            raise err('EVP_PKEY_keygen') unless l.EVP_PKEY_keygen(ctx, out) == 1

            keep.clear
            pkey = out.read_pointer
            sk = SecretKey.new(pkey)
            KeyPair.new(raw_public_key(sk.pkey), sk)
          ensure
            l.EVP_PKEY_CTX_free(ctx)
          end
        end

        def raw_public_key(pkey)
          l = Libcrypto.lib
          len = FFI::MemoryPointer.new(:size_t)
          len.write(:size_t, PK_BYTES)
          buf = FFI::MemoryPointer.new(:uint8, PK_BYTES)
          raise err('EVP_PKEY_get_raw_public_key') unless l.EVP_PKEY_get_raw_public_key(pkey, buf, len) == 1
          raise 'ML-KEM: unexpected public key length' unless len.read(:size_t) == PK_BYTES

          buf.read_bytes(PK_BYTES)
        end

        def encapsulate(public_key, msg32)
          check_available!
          raise ArgumentError, 'ml-kem encapsulate: message must be exactly 32 bytes' unless msg32.is_a?(String) && msg32.bytesize == MSG_BYTES
          raise ArgumentError, 'ml-kem encapsulate: bad public key length' unless public_key.is_a?(String) && public_key.bytesize == PK_BYTES

          l = Libcrypto.lib
          pk_buf = FFI::MemoryPointer.new(:uint8, PK_BYTES)
          pk_buf.put_bytes(0, public_key.b)
          pkey = l.EVP_PKEY_new_raw_public_key_ex(nil, 'ML-KEM-768', nil, pk_buf, PK_BYTES)
          raise err('EVP_PKEY_new_raw_public_key_ex') if pkey.null?

          ctx = l.EVP_PKEY_CTX_new_from_pkey(nil, pkey, nil)
          if ctx.null?
            l.EVP_PKEY_free(pkey)
            raise err('EVP_PKEY_CTX_new_from_pkey')
          end
          begin
            params, keep = octet_param('ikme', msg32)
            raise err('EVP_PKEY_encapsulate_init') unless l.EVP_PKEY_encapsulate_init(ctx, params) == 1

            ct = FFI::MemoryPointer.new(:uint8, CT_BYTES)
            ss = FFI::MemoryPointer.new(:uint8, SS_BYTES)
            ctlen = FFI::MemoryPointer.new(:size_t)
            sslen = FFI::MemoryPointer.new(:size_t)
            ctlen.write(:size_t, CT_BYTES)
            sslen.write(:size_t, SS_BYTES)
            raise err('EVP_PKEY_encapsulate') unless l.EVP_PKEY_encapsulate(ctx, ct, ctlen, ss, sslen) == 1
            raise 'ML-KEM: unexpected ciphertext or secret length' unless ctlen.read(:size_t) == CT_BYTES && sslen.read(:size_t) == SS_BYTES

            keep.clear
            Encapsulation.new(ct.read_bytes(CT_BYTES), ss.read_bytes(SS_BYTES))
          ensure
            l.EVP_PKEY_CTX_free(ctx)
            l.EVP_PKEY_free(pkey)
          end
        end

        # ML-KEM decapsulation never fails on a well-sized ciphertext (a wrong one yields the implicit-rejection secret)
        def decapsulate(cipher_text, secret_key)
          check_available!
          raise ArgumentError, 'ml-kem decapsulate: bad ciphertext length' unless cipher_text.is_a?(String) && cipher_text.bytesize == CT_BYTES

          l = Libcrypto.lib
          ctx = l.EVP_PKEY_CTX_new_from_pkey(nil, secret_key.pkey, nil)
          raise err('EVP_PKEY_CTX_new_from_pkey') if ctx.null?

          begin
            raise err('EVP_PKEY_decapsulate_init') unless l.EVP_PKEY_decapsulate_init(ctx, nil) == 1

            ct = FFI::MemoryPointer.new(:uint8, CT_BYTES)
            ct.put_bytes(0, cipher_text.b)
            ss = FFI::MemoryPointer.new(:uint8, SS_BYTES)
            sslen = FFI::MemoryPointer.new(:size_t)
            sslen.write(:size_t, SS_BYTES)
            raise err('EVP_PKEY_decapsulate') unless l.EVP_PKEY_decapsulate(ctx, ss, sslen, ct, CT_BYTES) == 1

            ss.read_bytes(SS_BYTES)
          ensure
            l.EVP_PKEY_CTX_free(ctx)
          end
        end
      end

      # ML-KEM-768 and ML-KEM-1024 (FIPS 203) on byte strings, for the hybrid KEMs: key generation from the 64-byte seed d || z
      # returning the encapsulation key and the EXPANDED decapsulation key, encapsulation from a caller-supplied 32-byte message,
      # and decapsulation from an expanded decapsulation key. Needs OpenSSL >= 3.5 (LoadError otherwise).
      module MlKem
        # level => [algorithm name, encapsulation key bytes, ciphertext bytes, expanded decapsulation key bytes]
        LEVELS = { 768 => ['ML-KEM-768', 1184, 1088, 2400], 1024 => ['ML-KEM-1024', 1568, 1568, 3168] }.freeze
        SS_BYTES = 32
        KEYPAIR = 0x87 # EVP_PKEY_KEYPAIR
        LOCK = Mutex.new

        module_function

        def spec(level) = LEVELS.fetch(level) { raise ArgumentError, "ml-kem: unknown level #{level.inspect}" }
        def err(what) = MlKem768.err(what)

        # libcrypto with the extra entry points of this module, bound on first use (an older OpenSSL still serves the OT stack)
        def lib
          return @lib if @lib

          MlKem768.check_available!
          l = Libcrypto.lib
          LOCK.synchronize do
            unless @lib
              l.attach_function(:EVP_PKEY_get_octet_string_param, %i[pointer string pointer size_t pointer], :int)
              l.attach_function(:EVP_PKEY_fromdata_init, [:pointer], :int)
              l.attach_function(:EVP_PKEY_fromdata, %i[pointer pointer int pointer], :int)
              l.attach_function(:OSSL_LIB_CTX_new, [], :pointer)
              l.attach_function(:OSSL_PROVIDER_load, %i[pointer string], :pointer)
              l.attach_function(:OSSL_PROVIDER_add_conf_parameter, %i[pointer string string], :int)
              @lib = l
            end
          end
          @lib
        end

        # A library context of its own whose default provider imports an explicit decapsulation key without the pairwise
        # consistency test (provider parameter ml-kem.import_pct_type = none). FIPS 203 decapsulation is defined for every
        # well-sized key: a key whose decryption half is damaged must yield the implicit-rejection secret, as the reference does,
        # and the test would refuse to import it. The process-wide default context keeps its own setting.
        def import_ctx
          return @import_ctx if @import_ctx

          l = lib
          LOCK.synchronize do
            unless @import_ctx
              ctx = l.OSSL_LIB_CTX_new
              raise err('OSSL_LIB_CTX_new') if ctx.null?

              prov = l.OSSL_PROVIDER_load(ctx, 'default')
              raise err('OSSL_PROVIDER_load') if prov.null?
              raise err('OSSL_PROVIDER_add_conf_parameter') unless l.OSSL_PROVIDER_add_conf_parameter(prov, 'ml-kem.import_pct_type', 'none') == 1

              @import_ctx = ctx
            end
          end
          @import_ctx
        end

        def bytes!(v, len, what)
          raise ArgumentError, "ml-kem: #{what} must be exactly #{len} bytes" unless v.is_a?(String) && v.bytesize == len

          v.b
        end

        # [encapsulation key, expanded decapsulation key] from the seed d || z
        def keygen(level, seed64)
          name, pk_len, _ct_len, dk_len = spec(level)
          seed = bytes!(seed64, 64, 'keygen seed')
          l = lib
          ctx = l.EVP_PKEY_CTX_new_from_name(nil, name, nil)
          raise err('EVP_PKEY_CTX_new_from_name') if ctx.null?

          begin
            raise err('EVP_PKEY_keygen_init') unless l.EVP_PKEY_keygen_init(ctx) == 1

            params, keep = MlKem768.octet_param('seed', seed)
            raise err('EVP_PKEY_CTX_set_params(seed)') unless l.EVP_PKEY_CTX_set_params(ctx, params) == 1

            out = FFI::MemoryPointer.new(:pointer)
            raise err('EVP_PKEY_keygen') unless l.EVP_PKEY_keygen(ctx, out) == 1

            keep.clear
            pkey = out.read_pointer
            begin
              [octets(pkey, 'pub', pk_len), octets(pkey, 'priv', dk_len)]
            ensure
              l.EVP_PKEY_free(pkey)
            end
          ensure
            l.EVP_PKEY_CTX_free(ctx)
          end
        end

        # the octet-string parameter `name` of a key, which must be exactly `len` bytes
        def octets(pkey, name, len)
          buf = FFI::MemoryPointer.new(:uint8, len)
          got = FFI::MemoryPointer.new(:size_t)
          raise err("EVP_PKEY_get_octet_string_param(#{name})") unless lib.EVP_PKEY_get_octet_string_param(pkey, name, buf, len, got) == 1
          raise "ML-KEM: unexpected #{name} length" unless got.read(:size_t) == len

          buf.read_bytes(len)
        end

        # [ciphertext, shared secret] for the encapsulation key `ek` from the message m (derandomised)
        def encapsulate(level, ek, msg32)
          name, pk_len, ct_len, = spec(level)
          ek = bytes!(ek, pk_len, 'encapsulation key')
          msg = bytes!(msg32, 32, 'encapsulation message')
          l = lib
          pk_buf = FFI::MemoryPointer.new(:uint8, pk_len)
          pk_buf.put_bytes(0, ek)
          pkey = l.EVP_PKEY_new_raw_public_key_ex(nil, name, nil, pk_buf, pk_len)
          raise err('EVP_PKEY_new_raw_public_key_ex') if pkey.null?

          ctx = l.EVP_PKEY_CTX_new_from_pkey(nil, pkey, nil)
          if ctx.null?
            l.EVP_PKEY_free(pkey)
            raise err('EVP_PKEY_CTX_new_from_pkey')
          end
          begin
            params, keep = MlKem768.octet_param('ikme', msg)
            raise err('EVP_PKEY_encapsulate_init') unless l.EVP_PKEY_encapsulate_init(ctx, params) == 1

            ct = FFI::MemoryPointer.new(:uint8, ct_len)
            ss = FFI::MemoryPointer.new(:uint8, SS_BYTES)
            ctlen = FFI::MemoryPointer.new(:size_t)
            sslen = FFI::MemoryPointer.new(:size_t)
            ctlen.write(:size_t, ct_len)
            sslen.write(:size_t, SS_BYTES)
            raise err('EVP_PKEY_encapsulate') unless l.EVP_PKEY_encapsulate(ctx, ct, ctlen, ss, sslen) == 1
            raise 'ML-KEM: unexpected ciphertext or secret length' unless ctlen.read(:size_t) == ct_len && sslen.read(:size_t) == SS_BYTES

            keep.clear
            [ct.read_bytes(ct_len), ss.read_bytes(SS_BYTES)]
          ensure
            l.EVP_PKEY_CTX_free(ctx)
            l.EVP_PKEY_free(pkey)
          end
        end

        # FIPS 203 decodes the decryption half of a decapsulation key with ByteDecode12 (each 12-bit coefficient mod q); OpenSSL refuses a
        # coefficient >= q at import. Reduce them so a key damaged there still decapsulates (to the implicit-rejection secret), as the reference does.
        def reduce_decryption_half(dk, level)
          n = 384 * (level == 768 ? 3 : 4)
          q = 3329
          head = dk.byteslice(0, n).unpack('C*').each_slice(3).flat_map do |a, b, c|
            x = (a | ((b & 0xf) << 8)) % q
            y = ((b >> 4) | (c << 4)) % q
            [x & 0xff, ((x >> 8) & 0xf) | ((y & 0xf) << 4), y >> 4]
          end
          head.pack('C*') + dk.byteslice(n..)
        end

        # The shared secret of `cipher_text` under the expanded decapsulation key `dk`. Never fails on well-sized inputs: a wrong
        # ciphertext or a damaged decryption half yields the implicit-rejection secret (FIPS 203). A key whose embedded
        # encapsulation-key hash does not match is refused.
        def decapsulate(level, cipher_text, dk)
          name, _pk_len, ct_len, dk_len = spec(level)
          ct_bytes = bytes!(cipher_text, ct_len, 'ciphertext')
          dk = reduce_decryption_half(bytes!(dk, dk_len, 'decapsulation key'), level)
          l = lib
          libctx = import_ctx
          kctx = l.EVP_PKEY_CTX_new_from_name(libctx, name, nil)
          raise err('EVP_PKEY_CTX_new_from_name') if kctx.null?

          pkey = nil
          dctx = nil
          begin
            raise err('EVP_PKEY_fromdata_init') unless l.EVP_PKEY_fromdata_init(kctx) == 1

            params, keep = MlKem768.octet_param('priv', dk)
            out = FFI::MemoryPointer.new(:pointer)
            raise err('EVP_PKEY_fromdata') unless l.EVP_PKEY_fromdata(kctx, out, KEYPAIR, params) == 1

            keep.clear
            pkey = out.read_pointer
            dctx = l.EVP_PKEY_CTX_new_from_pkey(libctx, pkey, nil)
            raise err('EVP_PKEY_CTX_new_from_pkey') if dctx.null?
            raise err('EVP_PKEY_decapsulate_init') unless l.EVP_PKEY_decapsulate_init(dctx, nil) == 1

            ct = FFI::MemoryPointer.new(:uint8, ct_len)
            ct.put_bytes(0, ct_bytes)
            ss = FFI::MemoryPointer.new(:uint8, SS_BYTES)
            sslen = FFI::MemoryPointer.new(:size_t)
            sslen.write(:size_t, SS_BYTES)
            raise err('EVP_PKEY_decapsulate') unless l.EVP_PKEY_decapsulate(dctx, ss, sslen, ct, ct_len) == 1

            ss.read_bytes(SS_BYTES)
          ensure
            l.EVP_PKEY_CTX_free(dctx) if dctx && !dctx.null?
            l.EVP_PKEY_free(pkey) if pkey && !pkey.null?
            l.EVP_PKEY_CTX_free(kctx)
          end
        end
      end
    end
  end
end
