# frozen_string_literal: true

# Replays the TS-reference oracle of lift_legacy (test-data/ref-goal-legacy.json.gz): the facade's {permissions, limits} lifted to a
# Goal and IR ontology.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/goal_legacy'
require 'minitest/autorun'

class TestRefGoalLegacy < Minitest::Test
  BY_FN = Ref.load('goal-legacy')

  LIFT = lambda do |permissions, limits, principal, not_after, not_before, nl|
    o = { 'permissions' => permissions, 'principal' => principal }
    o['limits'] = limits if AtlasPca::GoalJs.truthy(limits)
    o['notAfter'] = not_after unless not_after.nil?
    o['notBefore'] = not_before unless not_before.nil?
    o['nlDigest'] = nl unless nl.nil?
    AtlasPca::GoalLegacy.lift_legacy(o)
  end

  def test_every_function_is_covered
    assert_equal ['liftLegacy'], BY_FN.keys
  end

  def test_matches_reference
    Ref.run(self, BY_FN['liftLegacy'], LIFT)
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 125, BY_FN.values.sum(&:length), 'goal-legacy'
  end

end
