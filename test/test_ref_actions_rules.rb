# frozen_string_literal: true

# Replays the reference oracle of business rules (validation, compile, evaluate, explain, lint, diff, signed review;
# test-data/ref-actions-rules-py.json.gz). Time zones need the tzinfo gem. The reviewer secrets are seed labels in the corpus.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_rules'
require 'minitest/autorun'

class TestRefActionsRules < Minitest::Test
  R = AtlasPca::ActionsRules
  BY_FN = Ref.load('actions-rules-py')

  MAP = {
    'resolveParamRef' => R.method(:resolve_param_ref),
    'moneyOf' => R.method(:money_of),
    'minorUnits' => R.method(:minor_units),
    'knownTimeZone' => R.method(:known_time_zone),
    'businessRulesError' => R.method(:business_rules_error),
    'businessRulesDigest' => R.method(:business_rules_digest),
    'compileBusinessRules' => R.method(:compile_business_rules),
    'clockAt' => R.method(:clock_at),
    'evaluateBusinessRules' => R.method(:evaluate_business_rules),
    'runRuleExamples' => R.method(:run_rule_examples),
    'formatMoney' => R.method(:format_money),
    'explainBusinessRules' => R.method(:explain_business_rules),
    'lintBusinessRules' => R.method(:lint_business_rules),
    'diffBusinessRules' => R.method(:diff_business_rules),
    'rulesReviewMessage' => ->(b) { { '$bytes' => Ref.b64e(R.rules_review_message(b)) } },
    'signRulesReview' => ->(b, secret) { R.sign_rules_review(b, secret.is_a?(String) && secret.encoding != Encoding::BINARY ? Ref.b64d(secret) : secret) },
    'rulesReviewError' => R.method(:rules_review_error)
  }.freeze

  def test_every_function_is_covered = assert_equal MAP.keys.sort, BY_FN.keys.sort

  MAP.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 2766, BY_FN.values.sum(&:length), 'actions-rules-py'
  end

end
