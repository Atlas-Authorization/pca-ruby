# frozen_string_literal: true

# Replays the TS-reference oracle of the PCA explainer (test-data/ref-explain.json.gz): cleanText, the verification / decision /
# chain explanations and their text renderers. Explanations compare as canonical JSON (an absent member is a JS undefined).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/explain'
require 'minitest/autorun'

class TestRefExplain < Minitest::Test
  T = AtlasPca::Explain
  BY_FN = Ref.load('explain')

  MAP = {
    'cleanText' => ->(*a) { T.clean_text(*a) },
    'explainVerification' => ->(*a) { T.explain_verification(*a) },
    'explainVerificationText' => ->(*a) { T.verification_to_text(T.explain_verification(*a)) },
    'explainDecision' => ->(*a) { T.explain_decision(*a) },
    'explainDecisionText' => ->(*a) { T.decision_to_text(T.explain_decision(*a)) },
    'explainChain' => ->(*a) { T.explain_chain(*a) },
    'explainChainText' => ->(*a) { T.chain_to_text(T.explain_chain(*a)) },
    'consts' => -> { { 'VERIFY_CHECK_ORDER' => T::VERIFY_CHECK_ORDER, 'MAX_TEXT' => T::MAX_TEXT } }
  }.freeze

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 2107, BY_FN.values.sum(&:length), 'explain'
  end

end
