# frozen_string_literal: true

# Goal binding v3 (approved_goal): replays packages/pca/conformance/goal-commit-vectors.json (`commit`, `invalid`,
# `binding`); a missing file fails.
#   ruby -Ilib test/test_goal_commit_v3.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestGoalCommitV3 < Minitest::Test
  FILE = File.expand_path('../conformance/goal-commit-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)
  G = 'B5JcJLcCoUyZ2P4kdlU8dI9ukFkzuspDbELVR295azw'
  P = '9U7dBfYHPTNYZ84mWFHOiddEAPc7IEQ1AMEVp13dqSo'

  def grant(commit)
    { 'caveats' => commit.is_a?(String) ? [{ 'type' => 'envelope', 'goal_commit' => commit }] : [] }
  end

  def test_corpus_sizes
    assert_equal [7, 4, 16], [DOC['commit'].length, DOC['invalid'].length, DOC['binding'].length]
  end

  def test_commit_vectors
    DOC['commit'].each do |v|
      ref = { 'goal_digest' => v['goal_digest'], 'policy_digest' => v['policy_digest'] }
      assert_equal v['goal'], AtlasPca.intent_goal_v3(ref), v['name']
      assert_equal v['commit'], AtlasPca.intent_goal_commit_v3(ref, v['salt']), v['name']
    end
  end

  def test_invalid_digests_are_refused
    DOC['invalid'].each do |v|
      ref = { 'goal_digest' => v['goal_digest'], 'policy_digest' => v['policy_digest'] }
      refute AtlasPca.approved_goal_ref?(ref), v['name']
      assert_raises(ArgumentError, v['name']) { AtlasPca.intent_goal_v3(ref) }
      assert_raises(ArgumentError, v['name']) { AtlasPca.intent_goal_commit_v3(ref, 's') }
    end
  end

  def test_binding_vectors
    DOC['binding'].each do |v|
      status, why = AtlasPca.decide_intent_binding(v['intent'], grant(v['grant_commit']), v['policy'], v['session'], v['map_form'])
      assert_equal v['expect'], status == :pass ? 'pass' : 'fail', "#{v['name']}: #{status} #{why}"
    end
  end

  def test_unit_exact_outcomes
    ref = { 'goal_digest' => G, 'policy_digest' => P }
    intent = { 'ref' => G, 'map_digest' => P, 'goal_salt' => 's', 'fidelity_ppm' => 1, 'residual_risk_ppm' => 0 }
    v3 = AtlasPca.intent_goal_commit_v3(ref, 's')
    v1 = AtlasPca.intent_goal_commit(G, P, 's')
    pol = { 'approved_goal' => ref }
    assert AtlasPca.intent_policy_active?(pol)
    assert_equal [:pass, nil], AtlasPca.decide_intent_binding(intent, grant(v3), pol)
    assert_equal :fail, AtlasPca.decide_intent_binding(intent, grant(v1), pol)[0]
    assert_equal :fail, AtlasPca.decide_intent_binding(intent, grant(v3), { 'require' => true })[0]
    assert_equal :fail, AtlasPca.decide_intent_binding(nil, grant(v3), pol)[0]
    assert_equal :fail, AtlasPca.decide_intent_binding(intent, grant(nil), pol)[0]
    [{ 'goal_digest' => G }, { 'goal_digest' => G, 'policy_digest' => P, 'x' => 1 },
     { 'goal_digest' => G, 'policy_digest' => '' }, nil].each do |bad|
      status, why = AtlasPca.decide_intent_binding(intent, grant(v3), { 'approved_goal' => bad })
      assert_equal :fail, status
      assert_includes why, 'misconfigured'
    end
    assert_equal :fail, AtlasPca.decide_intent_binding(intent, grant(v3), pol.merge('min_fidelity_ppm' => 2))[0]
  end
end
