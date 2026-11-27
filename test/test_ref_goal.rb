# frozen_string_literal: true

# Replays the TS-reference oracle of the goal package (test-data/ref-goal.json.gz): token-tape codec, digests, canonical order,
# formatting, policy card, reference semantics, policy digest, decision-to-effect binding and the signing envelope.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/goal_codec'
require_relative '../lib/atlas_pca/goal_digests'
require_relative '../lib/atlas_pca/goal_normalize'
require_relative '../lib/atlas_pca/goal_fmt'
require_relative '../lib/atlas_pca/goal_card'
require_relative '../lib/atlas_pca/goal_refsem'
require_relative '../lib/atlas_pca/goal_compiler'
require_relative '../lib/atlas_pca/goal_binding'
require_relative '../lib/atlas_pca/goal_sign'
require 'minitest/autorun'

class TestRefGoal < Minitest::Test
  C = AtlasPca::GoalCodec
  D = AtlasPca::GoalDigests
  N = AtlasPca::GoalNormalize
  F = AtlasPca::GoalFmt
  CD = AtlasPca::GoalCard
  R = AtlasPca::GoalRefsem
  CP = AtlasPca::GoalCompiler
  B = AtlasPca::GoalBinding
  S = AtlasPca::GoalSign
  BY_FN = Ref.load('goal')
  KP = ->(seed) { AtlasPca::KeyPair.from_seed_b64u(seed) }

  FNS = {
    'encodeGoal' => C.method(:encode_goal), 'decodeGoal' => C.method(:decode_goal), 'encodeOntology' => C.method(:encode_ontology),
    'encodeAct' => C.method(:encode_act), 'encodeHist' => C.method(:encode_hist), 'decodePolicy' => C.method(:decode_policy),
    'goalDigest' => D.method(:goal_digest), 'nlDigest' => D.method(:nl_digest), 'modelSetDigest' => D.method(:model_set_digest),
    'approvalDigest' => D.method(:approval_digest), 'canonicalizeGoal' => N.method(:canonicalize_goal), 'stable' => N.method(:stable),
    'fmtMoney' => F.method(:fmt_money), 'fmtQuantity' => F.method(:fmt_quantity), 'fmtValue' => F.method(:fmt_value),
    'fmtAct' => F.method(:fmt_act), 'renderCard' => CD.method(:render_card), 'renderCond' => CD.method(:cond),
    'refExplain' => R.method(:ref_explain), 'refDecide' => R.method(:ref_decide), 'canonicalPolicy' => CP.method(:canonical_policy),
    'policyDigest' => CP.method(:policy_digest), 'actionDigest' => B.method(:action_digest), 'bindDecision' => B.method(:bind_decision),
    'guardExecute' => B.method(:guard_execute), 'claimGate' => ->(base, mn, rep) { B.claim_gate(base, mn, 0, rep) },
    'goalCommit' => B.method(:goal_commit), 'openCommit' => B.method(:open_commit),
    'signPayloadSeed' => ->(kind, payload, seed) { S.sign_payload(kind, payload, KP.call(seed)) },
    'signGoalArtifactSeed' => ->(kind, body, seed) { S.sign_goal_artifact(kind, body, KP.call(seed)) },
    'signerId' => ->(seed) { S.signer_id(KP.call(seed)) }, 'goalDomain' => S.method(:goal_domain),
    'verifyPayload' => S.method(:verify_payload), 'verifyGoalArtifact' => S.method(:verify_goal_artifact)
  }.freeze

  def test_every_function_is_covered
    assert_equal FNS.keys.sort, BY_FN.keys.sort
  end

  FNS.each do |fn, call|
    define_method("test_matches_reference_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 2213, BY_FN.values.sum(&:length), 'goal'
  end

end
