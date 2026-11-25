# frozen_string_literal: true

module AtlasPca
  # IDNA for byte parity with Node's WHATWG URL host parser: Ada's C API (ada_c.h, the parser Node uses; Apache-2.0) through the ffi gem.
  # The platform gems carry libada (lib/atlas_pca/native, built from the pinned amalgamated ada.cpp), so `available?` is true on them; ATLAS_PCA_LIBADA
  # (one path, or several) overrides the bundled copy. The pure gem loads without either: Ciba.domain_to_ascii and the URL host parser then keep their
  # approximation / refusal of a non-ASCII host. Nothing here is on the verification path: it only maps a host name to its ASCII form.
  module AdaIdna
    @lock = Mutex.new
    @lib = nil
    @tried = false

    module_function

    # Candidate library paths: ATLAS_PCA_LIBADA (one path, or several separated by File::PATH_SEPARATOR) when set, else the copy bundled in the platform gem.
    def candidates
      env = ENV.fetch('ATLAS_PCA_LIBADA', '')
      return env.split(File::PATH_SEPARATOR).reject(&:empty?) unless env.empty?

      Dir.glob(File.join(__dir__, 'native', '{libada.so,libada.dylib,ada.dll}'))
    end

    def load_lib
      require 'ffi'
      mod = Module.new do
        extend FFI::Library
        const_set(:Str, Class.new(FFI::Struct) { layout :data, :pointer, :length, :size_t })
      end
      candidates.each do |path|
        mod.ffi_lib(path)
        mod.attach_function :ada_parse, %i[pointer size_t], :pointer
        mod.attach_function :ada_free, [:pointer], :void
        mod.attach_function :ada_is_valid, [:pointer], :bool
        mod.attach_function :ada_set_hostname, %i[pointer pointer size_t], :bool
        mod.attach_function :ada_get_hostname, [:pointer], mod::Str.by_value
        return mod
      rescue LoadError, FFI::NotFoundError
        next
      end
      nil
    rescue LoadError
      nil
    end

    # True iff ffi and a libada exposing the C API are loadable.
    def available?
      @lock.synchronize do
        unless @tried
          @tried = true
          @lib = load_lib
        end
      end
      !@lib.nil?
    end

    # url.domainToASCII(word) as Node computes it: the hostname setter of the URL `ws://x` given the word (so a path, port or userinfo in the
    # word is refused, not cut off), '' when Ada refuses it. Raises when Ada is not available.
    def domain_to_ascii(word)
      raise LoadError, 'AdaIdna: set ATLAS_PCA_LIBADA to a libada build' unless available?

      base = 'ws://x'
      url = @lib.ada_parse(base, base.bytesize)
      src = word.b
      buf = FFI::MemoryPointer.new(:char, src.bytesize + 1)
      buf.put_bytes(0, src)
      begin
        return '' if url.null? || !@lib.ada_is_valid(url) || !@lib.ada_set_hostname(url, buf, src.bytesize)

        h = @lib.ada_get_hostname(url)
        h[:length].zero? ? '' : h[:data].read_bytes(h[:length]).force_encoding('UTF-8')
      ensure
        @lib.ada_free(url) unless url.null?
      end
    end
  end
end
