# frozen_string_literal: true

# Every Minitest file of test/ (the CI's own suites: shared vector replays and end-to-end module tests) as mutation-kill tests:
# one registry entry per file, passing when every test method of every class it defines passes (a skip is a pass; a raise is a
# kill). Left out: attestation_vectors (a3_attest.rb replays the same rows) and agent_producer (be_agent_producer.rb, with its
# keys built per call). The four plain scripts (intent, middleware, less, r041) have their own kill ports.
#
# A file is LOADED when its entry first runs, i.e. inside the mutant's process after the oracle replaced AtlasPca, so every
# constant it captures (vector documents, KeyPairs, `A = AtlasPca::Actions`) binds the MUTATED library. (Until run 41710479412
# only ten files were registered, loaded once in the parent: their captured KeyPairs / modules were the unmutated originals.)
# Autorun is disabled for good: the files `require 'minitest/autorun'`, and the oracle must never run a suite at exit.
require 'minitest'
# opt-in lib files (not required by atlas_pca.rb) a suite exercises are required here, in the parent, so the oracle re-evaluates
# them per mutant (oracle.rb @opt_in): a first require inside the mutant's process would load the unmutated file from disk
require 'atlas_pca/sigstore_bundle'

module MutationKill
  module MnModules
    FILES = %w[a2a actions_vectors approval arg_provenance_vectors assurance_vectors authorize authorize_workflow blueprint
               break_glass caveat_lang decision ext_vectors forbid_certificate fresh_at fresh_at_authorize goal_commit_v3
               goal_vectors intent_state k3_vectors k4 k5 k5_vault lease mesh middleware_options middleware_workflow
               missing_context model_rules nvidia_spdm_version obligations operations passport pca_grant plan_lifecycle
               policy_classes policy_link protect provenance provenance_flow revocation_staleness runtime_claim
               sigstore_bundle stepup store_conformance undo_vectors].freeze
    LOADED = {} # rubocop:disable Style/MutableConstant

    def self.classes(f)
      LOADED[f] ||= begin
        before = Minitest::Runnable.runnables.dup
        load File.expand_path("../test_#{f}.rb", __dir__)
        Minitest::Runnable.runnables - before
      end
    end

    def self.passes?(f)
      classes(f).all? do |k|
        k.runnable_methods.all? do |m|
          r = k.new(m).run
          warn "  #{k}##{m}: #{r.failures.first&.message.to_s[0, 800]}" if $mn_verbose && !(r.passed? || r.skipped?)
          r.passed? || r.skipped?
        rescue StandardError, SystemStackError
          false
        end
      end
    end
  end

  Minitest.seed ||= Random.new_seed % 0xFFFF # runnable_methods does `srand Minitest.seed`; nothing here parses minitest args
  Minitest.define_singleton_method(:autorun) { |*| nil }
  require 'minitest/autorun'
  MnModules::FILES.each do |f|
    raise "test/test_#{f}.rb is missing" unless File.file?(File.expand_path("../test_#{f}.rb", __dir__))

    t("mn:#{f}") { MnModules.passes?(f) }
  end
end
