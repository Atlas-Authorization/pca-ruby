# frozen_string_literal: true

# Replays the pca-goal vectors (goal corpus and selector corpus): goal digest, lowered policy digest, decision + witness for every
# probe, the helper vectors, and the native expansion of trait selectors. The semantics are the shared runner
# (packages/pca-conformance/runners/goal/ruby/run.rb; test/goal_runner.rb is its generated copy), so every language replays one
# reference. A missing corpus FAILS (set PCA_GOAL_VECTORS to override the search).
#   ruby test/test_goal_vectors.rb
require 'minitest/autorun'
require_relative 'goal_runner'

class TestGoalVectors < Minitest::Test
  CANDIDATES = [ENV['PCA_GOAL_VECTORS'],
                File.expand_path('../../../packages/pca-conformance/vectors/goal', __dir__),
                File.expand_path('../packages/pca-conformance/vectors/goal', __dir__),
                File.expand_path('../conformance/goal', __dir__)].compact

  def dir
    d = CANDIDATES.find { |c| File.directory?(c) }
    flunk "goal vectors not found (looked in #{CANDIDATES.join(', ')})" if d.nil?
    d
  end

  def test_goal_vectors
    n, probes, bad = G.replay(dir)
    assert_operator n, :>=, 240
    assert_operator probes, :>, 6000
    assert_equal [], bad.first(20)
  end

  def test_selector_vectors
    sel = File.join(File.dirname(dir), 'goal-select')
    flunk "selector vectors not found at #{sel}" unless File.directory?(sel)
    n, probes, bad = G.replay(sel)
    assert_operator n, :>=, 48
    assert_operator probes, :>, 1000
    assert_equal [], bad.first(20)
  end

  def test_the_reference_is_sensitive
    refute_equal G.goal_digest({ 'a' => 1 }), G.goal_digest({ 'a' => 2 })
    assert_equal 'deny', G.meet('deny', 'ok')
    assert_equal 'escalate', G.meet('allow', 'escalate')
  end
end
