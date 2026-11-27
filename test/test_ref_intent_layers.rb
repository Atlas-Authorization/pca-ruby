# frozen_string_literal: true

# Replays the TS-reference oracle of the multi-principal rules, common refinement, wallet-side layer lattice, quorum approvals and
# grant measurement (test-data/ref-intent-layers.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/intent_layers_wallet'
require_relative '../lib/atlas_pca/intent_metrics'
require_relative '../lib/atlas_pca/intent_multi'
require 'minitest/autorun'

class TestRefIntentLayers < Minitest::Test
  L = AtlasPca::IntentLayersWallet
  M = AtlasPca::IntentMetrics
  U = AtlasPca::IntentMulti
  P = AtlasPca::IntentPolicy
  BY_FN = Ref.load('intent-layers')

  MAP = {
    'normalizeRule' => U.method(:normalize_rule),
    'effectiveVetoers' => U.method(:effective_vetoers),
    'ruleAdmits' => U.method(:rule_admits),
    'jointAcceptance' => U.method(:joint_acceptance),
    'commonRefinement' => U.method(:common_refinement),
    'ceilingOf' => ->(layers, vs, o) { L.ceiling_of(L.ceiling_admitters(layers), vs, o) },
    'assertAskable' => lambda { |view, c|
      L.assert_askable(view, c)
      nil
    },
    'layerCells' => ->(om, pol) { L.layer_cells(om, P.admitter(pol)) },
    'ownerRisk' => ->(om, cells, pol) { L.owner_risk(om, cells, M.acceptability_of(pol)) },
    'cellKeyOf' => L.method(:cell_key_of),
    'signLayerApproval' => ->(st, seed) { L.sign_layer_approval(st, AtlasPca.b64d(seed, 32)) },
    'verifyQuorumApprovals' => L.method(:verify_quorum_approvals),
    'measureGrantExact' => ->(om, g, t) { M.measure_grant_exact(om, g, M.acceptability_of(t)) },
    'measureGrant' => ->(om, g, t, opts) { M.measure_grant(om, g, M.acceptability_of(t), opts) }
  }.freeze

  def test_corpus_is_fully_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 419, BY_FN.values.sum(&:length), 'intent-layers'
  end

end
