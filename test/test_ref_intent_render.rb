# frozen_string_literal: true

# Replays the TS-reference oracle of the intent renderer, back-translation diff and boundary witnesses (test-data/ref-intent-render.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/intent_render'
require_relative '../lib/atlas_pca/intent_witnesses'
require 'minitest/autorun'

class TestRefIntentRender < Minitest::Test
  R = AtlasPca::IntentRender
  W = AtlasPca::IntentWitnesses
  BY_FN = Ref.load('intent-render')

  def self.oracle(mode)
    case mode
    when 'agree' then ->(w) { w['grantAllows'] }
    when 'flip' then ->(w) { !w['grantAllows'] }
    when 'flip-boundary' then ->(w) { w['kind'] == 'boundary' ? !w['grantAllows'] : w['grantAllows'] }
    else ->(w) { w['side'] == 'inside' && w['kind'] != 'unconstrained' }
    end
  end

  MAP = {
    'labelOf' => R.method(:label_of),
    'renderCondition' => R.method(:render_condition),
    'renderCaveat' => R.method(:render_caveat),
    'renderGrant' => R.method(:render_grant),
    'renderQuestion' => R.method(:render_question),
    'renderAction' => R.method(:render_action),
    'claimsOf' => R.method(:claims_of),
    'backTranslationDiff' => R.method(:back_translation_diff),
    'claimDiff' => R.method(:claim_diff),
    'boundaryWitnesses' => W.method(:boundary_witnesses),
    'checkWitnesses' => ->(ws, mode) { W.check_witnesses(ws, oracle(mode)) }
  }.freeze

  def test_corpus_is_fully_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 269, BY_FN.values.sum(&:length), 'intent-render'
  end

end
