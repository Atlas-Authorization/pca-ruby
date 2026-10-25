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

    module_function

    # @api private
    def candidates
      env = ENV.fetch('ATLAS_PCA_LIBLESS', '')
      paths = env.split(File::PATH_SEPARATOR).reject(&:empty?)
      build = File.expand_path('../../../pca-less-c/build', __dir__)
      paths + %w[libatlas_less.so libatlas_less.dylib atlas_less.dll].map { |n| File.join(build, n) }
    end

    def binding
      return @binding if defined?(@binding)

      @binding = load_binding
    end

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
          return Fiddle::Function.new(lib['atlas_less_cat1_verify'], [vp, sz, vp, sz, vp, sz], Fiddle::TYPE_INT)
        rescue StandardError
          next
        end
      end
      nil
    rescue LoadError
      nil
    end

    def available? = !binding.nil?

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
