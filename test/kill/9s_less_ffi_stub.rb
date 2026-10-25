# frozen_string_literal: true
require 'tmpdir'
require 'fileutils'
# less_ffi.rb (the Fiddle loader of libatlas_less) against STUB libraries compiled at registry load by the unmutated parent: one
# with the less-252-45 sizes whose verify always answers 1, three with one wrong size each, one without the verify symbol. That
# pins the candidate list, the size handshake (all three sizes), the fall-through to the next candidate, the memo, and the
# pre-checks of verify (a stub that says "valid" must still be refused for a wrong key / signature length). Needs a C compiler
# (the LESS build already does); without one the test skips itself.
module MutationKill
  module LessStub
    module_function
    SIZES = { 'atlas_less_cat1_public_key_bytes' => 97_484, 'atlas_less_cat1_signature_min_bytes' => 1153, 'atlas_less_cat1_signature_max_bytes' => 1329 }.freeze

    def src(sizes = {}, verify: true)
      s = SIZES.merge(sizes).map { |n, v| "unsigned long #{n}(void){return #{v}UL;}\n" }.join
      s += "int atlas_less_cat1_verify(const void*a,unsigned long b,const void*c,unsigned long d,const void*e,unsigned long f){return 1;}\n" if verify
      s
    end

    DIR = Dir.mktmpdir('lessstub')
    at_exit { FileUtils.rm_rf(DIR) }

    def build(name, text)
      c = File.join(DIR, "#{name}.c")
      so = File.join(DIR, "#{name}.so")
      File.write(c, text)
      system('cc', '-shared', '-fPIC', '-o', so, c, out: File::NULL, err: File::NULL) ? so : nil
    end

    STUBS = {
      ok: build('ok', src({})),
      pk: build('badpk', src({ 'atlas_less_cat1_public_key_bytes' => 97_485 })),
      min: build('badmin', src({ 'atlas_less_cat1_signature_min_bytes' => 1154 })),
      max: build('badmax', src({ 'atlas_less_cat1_signature_max_bytes' => 1330 })),
      nov: build('nov', src({}, verify: false))
    }.freeze
    REAL = ENV['ATLAS_PCA_LIBLESS'].to_s
    ENABLED = STUBS.values.all?

    def ffi = AtlasPca::LessFfi

    def with_env(val)
      old = ENV['ATLAS_PCA_LIBLESS']
      saved = ffi.instance_variable_defined?(:@binding) ? [ffi.instance_variable_get(:@binding)] : nil
      ffi.send(:remove_instance_variable, :@binding) if saved
      val.nil? ? ENV.delete('ATLAS_PCA_LIBLESS') : ENV['ATLAS_PCA_LIBLESS'] = val
      yield
    ensure
      old.nil? ? ENV.delete('ATLAS_PCA_LIBLESS') : ENV['ATLAS_PCA_LIBLESS'] = old
      ffi.send(:remove_instance_variable, :@binding) if ffi.instance_variable_defined?(:@binding)
      ffi.instance_variable_set(:@binding, saved[0]) if saved
    end

    def build_libs? = ffi.candidates.last(3).any? { |p| File.file?(p) }

    def check
      s = STUBS
      sep = File::PATH_SEPARATOR
      with_env("a#{sep}#{sep}b#{sep}") do
        c = ffi.candidates
        base = File.expand_path('../../../pca-less-c/build', File.dirname(ffi.method(:candidates).source_location[0]))
        want = %w[a b] + %w[libatlas_less.so libatlas_less.dylib atlas_less.dll].map { |n| File.join(base, n) }
        return "candidates #{c.inspect}" unless c == want
      end
      with_env(nil) { return "candidates (no env) #{ffi.candidates.size}" unless ffi.candidates.size == 3 && ffi.candidates.all? { |p| File.absolute_path?(p) } }
      with_env([s[:ok]].join(sep)) do
        f = ffi.binding
        return 'good stub not loaded' if f.nil?
        return 'binding not memoised' unless ffi.binding.equal?(f)
        ENV['ATLAS_PCA_LIBLESS'] = s[:pk]
        return 'binding re-read after first load' unless ffi.binding.equal?(f)
        return 'available? false for a loaded library' unless ffi.available? == true
      end
      unless build_libs?
        # each handshake size is checked, a failing candidate falls through to the next, a missing path is skipped
        %i[pk min max nov].each do |k|
          with_env(s[k]) do
            return "stub #{k} accepted" unless ffi.binding.nil?
            return "available? true for stub #{k}" unless ffi.available? == false
          end
        end
        with_env(File.join(DIR, 'missing.so')) { return 'missing path gave a binding' unless ffi.load_binding.nil? }
        with_env('/etc/hostname') { return 'a non-library file gave a binding' unless ffi.load_binding.nil? }
      end
      [%i[pk min max nov], %i[nov pk min max]].each do |order|
        with_env((order.map { |k| s[k] } + [File.join(DIR, 'missing.so'), s[:ok]]).join(sep)) do
          f = ffi.load_binding
          return "fall-through to the good stub failed (#{order})" if f.nil?
        end
      end
      # verify: a stub that always says valid must still be refused for a wrong key / signature length, and answers exactly
      # true / false
      with_env(s[:ok]) do
        pk = 'k'.b * 97_484
        sg = 's'.b * 1329
        return 'verify true' unless ffi.verify(pk, 'm', sg) == true
        return 'verify empty msg' unless ffi.verify(pk, '', sg) == true
        return 'verify short key' unless ffi.verify(pk[0, 97_483], 'm', sg).equal?(false)
        return 'verify long key' unless ffi.verify(pk + 'x', 'm', sg).equal?(false)
        return 'verify short sig' unless ffi.verify(pk, 'm', sg[0, 1328]).equal?(false)
        return 'verify min sig' unless ffi.verify(pk, 'm', 's'.b * 1153) == true
        return 'verify off-step sig' unless ffi.verify(pk, 'm', 's'.b * 1154).equal?(false)
        return 'verify long sig' unless ffi.verify(pk, 'm', sg + 'x').equal?(false)
        ffi.instance_variable_set(:@binding, nil)
        return 'verify without a library' unless ffi.verify(pk, 'm', sg).equal?(false)
      end
      nil
    end
  end

  t('less_ffi against stub libraries') do
    next true unless LessStub::ENABLED
    next true if DiffUtil.skip?('less_ffi.rb', 'atlas_pca.rb')

    bad = LessStub.check
    warn bad if bad && !ENV['MUT_FILE']
    bad.nil?
  end
end
