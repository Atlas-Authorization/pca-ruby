# frozen_string_literal: true

# The unit tests of the modules track mN added (revocation staleness, operation records, plan lifecycle, assurance labels,
# goal v3, step-up client, store conformance helper, authorize, Rack options) as mutation-kill tests: each Minitest class is
# one registry entry that passes when every one of its test methods passes. The files are loaded WITHOUT their autorun (the
# oracle forks per mutant and must not run the suite at exit), and a mutant that makes a test method raise is a kill.
require 'minitest'

module MutationKill
  module MnModules
    FILES = %w[revocation_staleness operations plan_lifecycle assurance_vectors stepup store_conformance goal_commit_v3
               middleware_options authorize].freeze

    def self.passes?(klass)
      klass.runnable_methods.all? do |m|
        r = klass.new(m).run
        r.passed? || r.skipped?
      rescue StandardError, SystemStackError
        false
      end
    end

    def self.load_all
      Minitest.seed ||= Random.new_seed % 0xFFFF # runnable_methods does `srand Minitest.seed`; the standalone runner never parses minitest args
      orig = Minitest.method(:autorun)
      Minitest.define_singleton_method(:autorun) { |*| nil }
      FILES.each do |f|
        before = Minitest::Runnable.runnables.dup
        load File.expand_path("../test_#{f}.rb", __dir__)
        (Minitest::Runnable.runnables - before).each do |k|
          t(f, k) if k.runnable_methods.any?
        end
      end
    ensure
      Minitest.define_singleton_method(:autorun, orig) if orig
    end

    def self.t(file, klass)
      MutationKill.t("mn:#{file}:#{klass.name}") { passes?(klass) }
    end
  end
end

MutationKill::MnModules.load_all
