# frozen_string_literal: true

# LESS (less-252-45, the `less-cat1` / `hybrid-ed25519-less-cat1` suites; a NIST additional-signature round-2 candidate, not a
# standard) through Fiddle to `libatlas_less`: the patched LESS reference C of the repository's sdks/pca-less-c built as a
# shared library (`sdks/pca-less-c/build.sh`). Found at ATLAS_PCA_LIBLESS (one path, or several separated by File::PATH_SEPARATOR),
# else in the repository's sdks/pca-less-c/build/. It counts only if it reports the less-252-45 sizes; without one (or without
# Fiddle) the LESS suites are left out of AtlasPca.supported_suites and fail closed with `unsupported_suite`. The detached
# signature is variable-length (1,153..1,329 bytes in steps of 16). Never raises.
module AtlasPca
  module LessFfi
    KEY_TYPE = 'LESS-cat1'
    PUBLIC_KEY_BYTES = 97_484
    SIGNATURE_MIN_BYTES = 1153
    SIGNATURE_MAX_BYTES = 1329
    SIGNATURE_STEP_BYTES = 16
    SECRET_KEY_BYTES = 32
    SEED_BYTES = 32

    module_function

    # @api private
    def candidates
      env = ENV.fetch('ATLAS_PCA_LIBLESS', '')
      paths = env.split(File::PATH_SEPARATOR).reject(&:empty?)
      build = File.expand_path('../../../pca-less-c/build', __dir__)
      paths + Dir.glob(File.join(__dir__, 'native', '{libatlas_less.so,libatlas_less.dylib,atlas_less.dll}')) + %w[libatlas_less.so libatlas_less.dylib atlas_less.dll].map { |n| File.join(build, n) }
    end

    def binding
      return @binding if defined?(@binding)

      @binding = load_binding
    end

    # The signing entry points {keygen:, sign:, secret_key_bytes:} of the same library, or nil (a verify-only build).
    def signer
      binding # loads the library
      @signer
    end

    def signer_available? = !signer.nil?

    def load_binding
      require 'fiddle'
      sz = Fiddle::TYPE_SIZE_T
      candidates.each do |path|
        next unless File.file?(path)

        begin
          lib = Fiddle.dlopen(path)
          size = ->(name) { Fiddle::Function.new(lib[name], [], sz).call }
          next unless size.call('atlas_less_cat1_public_key_bytes') == PUBLIC_KEY_BYTES &&
                      size.call('atlas_less_cat1_signature_min_bytes') == SIGNATURE_MIN_BYTES &&
                      size.call('atlas_less_cat1_signature_max_bytes') == SIGNATURE_MAX_BYTES

          vp = Fiddle::TYPE_VOIDP
          @signer = load_signer(lib, vp, sz)
          return Fiddle::Function.new(lib['atlas_less_cat1_verify'], [vp, sz, vp, sz, vp, sz], Fiddle::TYPE_INT)
        rescue StandardError
          next
        end
      end
      nil
    rescue LoadError
      nil
    end

    def load_signer(lib, vp, sz)
      sk_bytes = Fiddle::Function.new(lib['atlas_less_cat1_secret_key_bytes'], [], sz).call
      return nil unless sk_bytes == SECRET_KEY_BYTES

      { keygen: Fiddle::Function.new(lib['atlas_less_cat1_keygen'], [vp, sz, vp, sz, vp, sz], Fiddle::TYPE_INT),
        sign: Fiddle::Function.new(lib['atlas_less_cat1_sign'], [vp, sz, vp, sz, vp, sz, vp, sz, vp], Fiddle::TYPE_INT) }
    rescue StandardError
      nil # a verify-only build: the symbols are absent
    end

    def available? = !binding.nil?

    # [public_key, secret_key] from a 32-byte seed (the same seed gives the same key). Raises when the library cannot sign.
    def keygen(seed)
      sg = signer or raise ArgumentError, 'LESS signing needs libatlas_less with the signing entry points'
      raise ArgumentError, "a LESS seed is #{SEED_BYTES} bytes" unless seed.is_a?(String) && seed.bytesize == SEED_BYTES

      pk = ("\x00".b * PUBLIC_KEY_BYTES)
      sk = ("\x00".b * SECRET_KEY_BYTES)
      s = seed.b
      raise ArgumentError, 'LESS keygen failed' unless sg[:keygen].call(pk, pk.bytesize, sk, sk.bytesize, s, s.bytesize) == 1

      [pk, sk]
    end

    # The detached signature of `msg` under the secret key with a 32-byte RNG seed (never reuse a seed across signatures).
    def sign(sk, msg, seed)
      sg = signer or raise ArgumentError, 'LESS signing needs libatlas_less with the signing entry points'
      raise ArgumentError, "a LESS secret key is #{SECRET_KEY_BYTES} bytes, a seed #{SEED_BYTES}" unless sk.bytesize == SECRET_KEY_BYTES && seed.bytesize == SEED_BYTES

      m = msg.b
      out = "\x00".b * SIGNATURE_MAX_BYTES
      len = Fiddle::Pointer.malloc(Fiddle::SIZEOF_SIZE_T, Fiddle::RUBY_FREE)
      ok = sg[:sign].call(sk.b, sk.bytesize, m.empty? ? "\x00".b : m, m.bytesize, seed.b, seed.bytesize, out, out.bytesize, len)
      n = len[0, Fiddle::SIZEOF_SIZE_T].unpack1('J')
      raise ArgumentError, 'LESS sign failed' unless ok == 1 && sig_len_ok?(n)

      out.byteslice(0, n)
    end

    def sig_len_ok?(n)
      n.between?(SIGNATURE_MIN_BYTES, SIGNATURE_MAX_BYTES) && ((SIGNATURE_MAX_BYTES - n) % SIGNATURE_STEP_BYTES).zero?
    end

    # The detached signature opens under `pk` and yields exactly `msg`.
    def verify(pk, msg, sig)
      return false unless pk.bytesize == PUBLIC_KEY_BYTES && sig_len_ok?(sig.bytesize)

      f = binding
      return false if f.nil?

      m = msg.b
      f.call(pk.b, pk.bytesize, m.empty? ? "\x00".b : m, m.bytesize, sig.b, sig.bytesize) == 1
    rescue StandardError
      false
    end
  end
end
