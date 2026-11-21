# frozen_string_literal: true

# Replays the TS-reference oracle of goal roundtrip (test-data/ref-goal-roundtrip.json.gz): the card tape round trip, widening
# mutations and the explainer + comparator detector (injected explainers and comparators are chosen by mode name).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/goal_roundtrip'
require 'minitest/autorun'

class TestRefGoalRoundtrip < Minitest::Test
  R = AtlasPca::GoalRoundtrip
  BY_FN = Ref.load('goal-roundtrip')

  class Explainer
    def initialize(mode) = @mode = mode

    def explain(lines)
      raise 'boom' if @mode == 'throw'

      lines.join("\n")
    end
  end

  class Comparator
    def initialize(mode) = @mode = mode

    def equivalent(_text, explanation)
      raise 'boom' if @mode == 'throw'
      return { 'equivalent' => true } if @mode == 'ok'
      return { 'equivalent' => false, 'reason' => 'x' } if @mode == 'no'

      { 'equivalent' => explanation.include?(@mode[9..]) }
    end
  end

  FNS = {
    'cardRoundTrips' => R.method(:card_round_trips?),
    'mutateGoal' => ->(g, k, ont) { R.mutate_goal(g, k, ont) },
    'roundTrip' => ->(g, text, ex, cm) { R.round_trip(g, text, Explainer.new(ex), Comparator.new(cm)) },
    'measureDetection' => ->(cases, ont, ex, cm) { R.measure_detection(cases, ont, Explainer.new(ex), Comparator.new(cm)) }
  }.freeze

  def test_every_function_is_covered
    assert_equal FNS.keys.sort, BY_FN.keys.sort
  end

  FNS.each do |fn, call|
    define_method("test_matches_reference_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 78, BY_FN.values.sum(&:length), 'goal-roundtrip'
  end

end
