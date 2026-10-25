# frozen_string_literal: true
# Every mutable-type constant the unmutated library freezes must still be frozen: `X = [...].freeze` -> `X = [...]` (the
# `call->recv-freeze` mutants) is otherwise invisible to a behavioural test. The expected set is taken ONCE, from the unmutated
# library at registry load (the parent); each test lambda resolves the same constant paths in the (possibly mutated) library.
# Immediate / intrinsically frozen values (numbers, symbols, classes, ranges, regexps, literal strings under the
# frozen_string_literal magic comment) are not recorded: removing `.freeze` there changes nothing.
module MutationKill
  module FrozenConstants
    module_function

    def collect(mod, path, seen, out)
      return if seen.key?(mod.object_id)

      seen[mod.object_id] = true
      mod.constants(false).sort.each do |name|
        full = "#{path}::#{name}"
        v = begin
          mod.const_get(name, false)
        rescue StandardError, LoadError
          next
        end
        if v.is_a?(Module) then collect(v, full, seen, out)
        elsif v.frozen? && (v.is_a?(Array) || v.is_a?(Hash) || (v.instance_of?(Object))) then out << full
        end
      end
    end

    def expected
      @expected ||= begin
        out = []
        collect(AtlasPca, 'AtlasPca', {}, out)
        out
      end
    end

    # a few buckets so a mutant that unfreezes one constant is found by the first bucket that holds it
    BUCKETS = 4
    def check(k)
      expected.each_with_index do |path, i|
        next unless i % BUCKETS == k

        v = Object.const_get(path)
        return "#{path} is not frozen" unless v.frozen?
      rescue NameError
        return "#{path} is gone"
      end
      nil
    end

    expected # computed by the unmutated parent
  end

  FrozenConstants::BUCKETS.times do |k|
    t("constants stay frozen: bucket #{k + 1}") do
      bad = FrozenConstants.check(k)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
