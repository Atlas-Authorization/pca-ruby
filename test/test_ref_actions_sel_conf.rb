# frozen_string_literal: true

# Replays the reference oracle of trait selectors, the policy decision and signed confirmation (test-data/ref-actions-sel-conf.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_selector'
require_relative '../lib/atlas_pca/actions_confirmation'
require 'minitest/autorun'

class TestRefActionsSelConf < Minitest::Test
  A = AtlasPca::Actions
  S = AtlasPca::ActionsSelector
  C = AtlasPca::ActionsConfirmation
  BY_FN = Ref.load('actions-sel-conf')

  def self.reg(defs) = defs.nil? ? A::CORE_REGISTRY : A.extend_registry(A::CORE_REGISTRY, defs)

  MAP = {
    'selectorMatches' => ->(s, c) { S.selector_matches(s, c) ? true : false },
    'selectorMatchesFor' => ->(s, m, c, z) { S.selector_matches_for(s, m, c, z) ? true : false },
    'selectorHasNot' => S.method(:selector_has_not),
    'allowSelectorError' => S.method(:allow_selector_error),
    'policyDecision' => S.method(:policy_decision),
    'blankReason' => C.method(:blank_reason),
    'reviewMessage' => C.method(:review_message),
    'signReview' => C.method(:sign_review),
    'verbConfirmationError' => ->(v, rd, pins) { C.verb_confirmation_error(v, reg(rd), pins) }
  }.freeze

  # lone surrogates ride through JS-order JSON; a byte result is compared as bytes
  CMP = lambda do |got, out, _c|
    next got.b == Ref.b64d(out['$bytes']) if out.is_a?(Hash) && out.key?('$bytes')

    js = ->(v) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(v))) }
    js.call(got) == js.call(out)
  end

  # nil pins is "none pinned" natively (JS undefined); the reference reads a JSON null as malformed pins: both refuse
  SKIP = ->(c) { c['fn'] == 'verbConfirmationError' && c['args'][2].nil? }

  def test_every_function_is_covered = assert_equal [], BY_FN.keys - MAP.keys

  MAP.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call, compare: CMP, skip: SKIP) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1266, BY_FN.values.sum(&:length), 'actions-sel-conf'
  end

end
