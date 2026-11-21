# frozen_string_literal: true

# Replays the TS-reference oracle of the verifier-filled outcome-space dimensions (test-data/ref-intent-world.json.gz): world, provenance and classifier-label dimensions.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/intent_world'
require 'minitest/autorun'

class TestRefIntentWorld < Minitest::Test
  W = AtlasPca::IntentWorld
  BY_FN = Ref.load('intent-world')

  MAP = {
    'worldDim' => W.method(:world_dim),
    'excessDim' => W.method(:excess_dim),
    'optimalityCondition' => W.method(:optimality_condition),
    'provenanceDim' => W.method(:provenance_dim),
    'classifierDim' => W.method(:classifier_dim),
    'withDims' => W.method(:with_dims),
    'liftOutcome' => W.method(:lift_outcome)
  }.freeze

  def test_corpus_is_fully_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 52, BY_FN.values.sum(&:length), 'intent-world'
  end

end
