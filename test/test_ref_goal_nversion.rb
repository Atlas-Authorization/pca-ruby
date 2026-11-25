# frozen_string_literal: true

# Replays the TS-reference oracle of nversion and disambiguate (test-data/ref-goal-nversion.json.gz): the semantic meet of readings,
# the panel check, N-version interpretation, witness questions and version-space halving.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/goal_disambiguate'
require_relative '../lib/atlas_pca/goal_nversion'
require 'minitest/autorun'

class TestRefGoalNVersion < Minitest::Test
  D = AtlasPca::GoalDisambiguate
  N = AtlasPca::GoalNVersion
  BY_FN = Ref.load('goal-nversion')

  DISAMBIGUATE = lambda do |readings, ont, mode, budget|
    ask = lambda do |q|
      next mode if %w[allow deny].include?(mode)

      D.allows_witness(readings[mode[6..].to_i]['goal'], ont, q) ? 'allow' : 'deny'
    end
    opts = { 'ont' => ont }
    opts['budget'] = budget unless budget.nil?
    D.disambiguate(readings, ask, opts)
  end

  FNS = {
    'meet' => N.method(:meet), 'meetGrants' => N.method(:meet_grants), 'checkPanel' => N.method(:check_panel),
    'nVersion' => ->(r, ont, th) { N.n_version(r, { 'ont' => ont }.merge(th.nil? ? {} : { 'massThreshold' => th })) },
    'questions' => ->(r, ont) { D.questions(r, { 'ont' => ont }) },
    'disagreementMass' => D.method(:disagreement_mass), 'allowsWitness' => D.method(:allows_witness), 'disambiguate' => DISAMBIGUATE
  }.freeze

  def test_every_function_is_covered
    assert_equal FNS.keys.sort, BY_FN.keys.sort
  end

  FNS.each do |fn, call|
    define_method("test_matches_reference_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 93, BY_FN.values.sum(&:length), 'goal-nversion'
  end

end
