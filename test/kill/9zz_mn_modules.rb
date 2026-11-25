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
require 'atlas_pca/kem'
require 'atlas_pca/zk_native'

module MutationKill
  module MnModules
    FILES = %w[a2a actions_vectors agent_side approval arg_provenance_vectors assurance_vectors authorize authorize_workflow blueprint
               break_glass caveat_lang decision ext_vectors forbid_certificate fresh_at fresh_at_authorize goal_commit_v3
               goal_vectors ref_goal_bench ref_goal_selectors assurance_hooks pq_surface approval_channels hash_suite small_surface server_guard chain_compact policy_templates ref_decide undo_coordinator ref_core_mesh ref_actions_pack pq_threshold_experimental ref_durable_state ref_core_stores bond_settlement discovery reference_names durable_state undo_stores wire_checks approvals reference_helpers ref_agent_native ref_sibling_ports ref_kem ref_entropy ref_zk_ceremony ref_zk verifier_hooks ref_decide_derive intent_state k3_vectors k4 k5 k5_vault lease mesh middleware_options middleware_workflow
               missing_context model_rules nvidia_spdm_version obligations operations passport pca_grant plan_lifecycle
               policy_classes policy_link protect provenance provenance_flow revocation_staleness runtime_claim
               sigstore_bundle stepup store_conformance undo_vectors ref_prohibitions_contracts ref_mesh_issue ref_pq_quorum ref_safety_certificate ref_catalog ref_core_research ref_budget_forecast ref_reputation ref_policy_debug ref_ha ref_taint ref_frontier_signals ref_objective_risk ref_progress ref_attestation_soft ref_sevsnp_helpers ref_connectors_providers ref_attest_pq_software ref_attest_puf ref_attest_allowlist ref_attest_maa ref_attest_nvidia ref_semantic_threshold ref_passport ref_beacons ref_action_schema ref_intent_misc2 ref_nl_approval ref_frost_net ref_frost_dkg ref_attest_vendors ref_control_blue base_intenthistory].freeze
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
