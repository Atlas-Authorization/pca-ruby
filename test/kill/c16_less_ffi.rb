# frozen_string_literal: true
require 'tmpdir'
# less_ffi.rb: load_binding skips a candidate that is not a regular file WITHOUT opening it. dlopen of a bare name searches the
# loader path, so opening a non-file candidate is observable (a seam over Fiddle.dlopen records every open).
module MutationKill
  t('less_ffi: a candidate that is not a regular file is never opened (seam over Fiddle.dlopen)') do
    begin
      require 'fiddle'
    rescue LoadError
      next true
    end
    opened = []
    stub = ->(p, *_) { opened << p; raise Fiddle::DLError, 'seam' }
    Seam.with(AtlasPca::LessFfi, { candidates: -> { ['/nonexistent/atlas-less-seam.so', Dir.tmpdir] } }) do
      Seam.with(Fiddle, { dlopen: stub }) { AtlasPca::LessFfi.load_binding.nil? && opened.empty? }
    end
  end
end
