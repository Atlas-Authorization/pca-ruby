# frozen_string_literal: true

# The Policy VM decision (AtlasPca.decide) against the TS reference: test-data/ref-decide-java.json.gz (reasons compared in order).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/mpc' # the party evaluator is an opt-in module
require 'minitest/autorun'

class TestRefDecide < Minitest::Test
  BY_FN = Ref.load('decide-java')

  def test_matches_reference_decide
    Ref.run(self, BY_FN['decide'], ->(input) { AtlasPca.decide(input) })
  end

  def test_every_function_is_covered
    assert_equal ['decide'], BY_FN.keys
  end

  def test_evaluate_party_without_a_grant_is_the_worst_vector
    v = AtlasPca::Mpc::Party.evaluate_party({ 'decideInput' => nil })
    assert_equal [0, 3, 100], [v.allow, v.t, v.r_quant]
  end

  def test_derive_decide_input_requires_the_stored_grant
    err = assert_raises(AtlasPca::DecideInputGrantRequired) { AtlasPca.derive_decide_input({ 'action' => {} }, { 'risk' => {} }) }
    assert_equal 'grant_required', err.code
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 226, BY_FN.values.sum(&:length), 'decide-java'
  end

end
