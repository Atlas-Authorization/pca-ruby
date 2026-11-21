# frozen_string_literal: true

module AtlasPca
  # The reference's locale-aware string compare (`a.localeCompare(b)`: ICU root collation at tertiary strength, punctuation not ignored) through the
  # OPTIONAL gem `ffi-icu` over the system libicu. Without the gem (or the library) `compare` answers nil and the caller keeps its Latin-text
  # approximation; nothing here is loaded until the first comparison, and a missing gem is never an error.
  module Collation
    @collator = nil
    @tried = false
    @lock = Mutex.new

    module_function

    # the ICU root collator, or nil when ffi-icu / libicu cannot be loaded
    def collator
      @lock.synchronize do
        unless @tried
          @tried = true
          @collator = begin
            require 'ffi-icu'
            ICU::Collation::Collator.new('root')
          rescue LoadError, StandardError, NotImplementedError
            nil
          end
        end
        @collator
      end
    end

    def available? = !collator.nil?

    # -1, 0 or 1 by ICU root collation of two valid UTF-8 strings; nil when ICU is not available or a string is not valid UTF-8
    def compare(a, b)
      c = collator
      return nil if c.nil? || !a.is_a?(String) || !b.is_a?(String)

      x = a.dup.force_encoding('UTF-8')
      y = b.dup.force_encoding('UTF-8')
      return nil unless x.valid_encoding? && y.valid_encoding?

      c.compare(x, y) <=> 0
    rescue StandardError
      nil
    end
  end
end
