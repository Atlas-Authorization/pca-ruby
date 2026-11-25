# frozen_string_literal: true

# Replays the TS-reference oracle of goal examples (test-data/ref-goal-examples.json.gz): decision cells, boundary examples, goal
# tests and the policy pin.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/goal_examples'
require 'minitest/autorun'

class TestRefGoalExamples < Minitest::Test
  E = AtlasPca::GoalExamples
  BY_FN = Ref.load('goal-examples')
  KP = ->(seed) { AtlasPca::KeyPair.from_seed_b64u(seed) }

  CHECK_TESTS = lambda do |signed, pins, mode, g, ont|
    fn = if mode == 'ref'
           ->(t) { E.decide_case(g, ont, t)['decision'] }
         else
           ->(_t) { { 'allow' => 'allow', 'deny' => 'deny' }.fetch(mode, 'escalate') }
         end
    E.check_goal_tests(signed, pins, fn)
  end

  FNS = {
    'buildSpace' => E.method(:build_space),
    'cellKey' => ->(goals, extra, c) { E.cell_key(E.build_space(goals, extra), c) },
    'cells' => ->(goals, extra, verbs) { E.cells(E.build_space(goals, extra), verbs.nil? ? {} : { 'verbs' => verbs }) },
    'decideCase' => E.method(:decide_case), 'replay' => E.method(:replay),
    'allowWitness' => ->(g, i, ont) { E.allow_witness(g, g['grants'][i], ont) },
    'boundaryExamples' => lambda do |g, ont, extra, verbs|
      opts = { 'ont' => ont }
      opts['extra'] = extra if extra && !extra.empty?
      opts['verbs'] = verbs if verbs && !verbs.empty?
      E.boundary_examples(g, opts)
    end,
    'reviewSet' => E.method(:review_set), 'testsDigest' => E.method(:tests_digest), 'makeGoalTests' => E.method(:make_goal_tests),
    'signGoalTestsSeed' => ->(s, seed) { E.sign_goal_tests(s, KP.call(seed)) }, 'checkGoalTests' => CHECK_TESTS,
    'signPinSeed' => ->(p, seed) { E.sign_pin(p, KP.call(seed)) }, 'checkPin' => E.method(:check_pin)
  }.freeze

  def test_every_function_is_covered
    assert_equal FNS.keys.sort, BY_FN.keys.sort
  end

  FNS.each do |fn, call|
    define_method("test_matches_reference_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 132, BY_FN.values.sum(&:length), 'goal-examples'
  end

end
