# frozen_string_literal: true

# Replays the TS-reference oracle of the goal benchmark (test-data/ref-goal-bench.json.gz): the seeded generator, labelled cases with
# hostile variants, simulated-model fixtures, the four-level evaluation, the calibrated report and the case-set digest.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/goal_bench'
require 'minitest/autorun'

class TestRefGoalBench < Minitest::Test
  B = AtlasPca::GoalBench
  BY_FN = Ref.load('goal-bench')

  def self.items(cases)
    cases.map { |c| g = B.truth_goal(c); { 'goal' => g, 'ont' => B.truth_ont(c, g) } }
  end

  FNS = {
    'rngSeq' => ->(seed, n) { r = B.rng(seed); Array.new(n) { r.call } },
    'generateCases' => lambda { |dom, n, seed, every, only|
      o = {}
      o['hostileEvery'] = every unless every.nil?
      o['hostileOnly'] = true if only == true
      B.generate_cases(dom, n, seed, o)
    },
    'truthGoalOf' => ->(c) { B.truth_goal(c) },
    'simulateOutputOf' => ->(c, id) { B.simulate_output(c, B::SIM_SPECS.find { |s| s['id'] == id }) },
    'recordFixturesOf' => ->(cs) { B.record_fixtures(cs) },
    'caseSetDigest' => ->(cs) { B.case_set_digest(cs) },
    'evalCaseOf' => ->(c) { B.eval_case(c, B.completions_from(B.record_fixtures([c]))) },
    'compileWideningOf' => ->(cs) { B.compile_widening_count(TestRefGoalBench.items(cs)) },
    'summarizeOf' => ->(dom, outs, ms, cw = nil) { B.summarize(dom, outs, ms, cw) },
    'runDomainOf' => ->(dom, cs) { B.run_domain(dom, cs, B.record_fixtures(cs)) }
  }.freeze

  def test_every_function_is_covered
    assert_equal FNS.keys.sort, BY_FN.keys.sort
  end

  FNS.each do |fn, call|
    define_method("test_matches_reference_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 461, BY_FN.values.sum(&:length), 'goal-bench'
  end

end
