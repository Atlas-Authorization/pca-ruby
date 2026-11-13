# frozen_string_literal: true

# Shared helpers for the zc_* kill tests (exact comparisons: Integer 1 and Float 1.0 are different results here).
module MutationKill
  module ZC
    module_function

    def gate?(*files) = (f = ENV['MUT_FILE']).nil? || f.empty? || files.include?(f)

    # eql? (type-exact for numbers, deep for Hash / Array); true or raises with a label
    def eq(label, got, want)
      got.eql?(want) || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    end

    def same(label, got, want)
      got.equal?(want) || raise("#{label}: not the same object (got #{got.inspect}, want #{want.inspect})")
    end

    def near(label, got, want)
      (got.is_a?(Float) && (got - want).abs < 1e-12) || raise("#{label}: got #{got.inspect}, want about #{want.inspect}")
    end

    # the block must raise a StandardError (of `klass`)
    def raises(label, klass = StandardError)
      yield
    rescue klass
      true
    else
      raise "#{label}: did not raise"
    end

    # swap singleton methods for the block (stubs: name => callable), restore afterwards
    def seam(mod, stubs)
      orig = stubs.keys.to_h { |n| [n, mod.method(n)] }
      stubs.each { |n, impl| mod.define_singleton_method(n, &impl) }
      yield
    ensure
      orig&.each { |n, m| mod.define_singleton_method(n, m) }
    end

    # a StandardError whose #message differs from its #to_s
    class LoudError < StandardError
      def message = 'loud-message'
    end
  end
end
