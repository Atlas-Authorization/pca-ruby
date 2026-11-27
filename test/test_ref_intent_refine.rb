# frozen_string_literal: true

# Replays the TS-reference oracle of cut refinement, partial answers and adaptive elicitation (test-data/ref-intent-refine.json.gz).
# Doubles from transcendental functions compare to 1e-12 relative; counts, strings and structure exactly.
require_relative 'support/ref_intent'
require_relative '../lib/atlas_pca/intent_refine'
require 'minitest/autorun'

class TestRefIntentRefine < Minitest::Test
  M = AtlasPca::IntentMapkit
  O = AtlasPca::IntentOmega
  P = AtlasPca::IntentPolicy
  R = AtlasPca::IntentRefine
  BY_FN = Ref.load('intent-refine')

  def self.mk(omega, mo, obs)
    l = M.create_learner(omega, mo)
    obs.each { |x| l.observe({ 'verb' => x['verb'], 'values' => x['values'] }, x['y'], x['source'], x['region']) }
    l
  end

  def self.cells_of(l) = l.cells.map { |c| { 'verb' => c['verb'], 'cell' => c['cell'], 'p' => c['p'] } }

  def self.regions_of(omega, mo, obs, empty)
    l = mk(omega, mo, obs)
    l.observations.map { |x| R.region_of_observation(empty ? omega.merge('verbs' => []) : l.omega, x) }
  end

  def self.refine_scenario(omega, mo, obs, rr)
    nl = R.refine_learner(mk(omega, mo, obs), rr)
    { 'omega' => nl.omega, 'observations' => nl.observations, 'metrics' => nl.metrics, 'cells' => cells_of(nl) }
  end

  def self.partial_scenario(omega, mo, obs, q, pa)
    l = mk(omega, mo, obs)
    svs = omega['verbs'].find { |v| v['verb'] == q['verb'] }
    if svs.nil?
      oc = { 'verb' => q['verb'], 'values' => {} }
      p = 0.5
    else
      oc = O.cell_rep(svs, q['cell'])
      p = l.acceptance(oc)
    end
    r = R.answer_partial(l, { 'verb' => q['verb'], 'cell' => q['cell'], 'outcome' => oc, 'p' => p, 'score' => 0 }, pa)
    { 'omega' => r['learner'].omega, 'added' => r['added'], 'observations' => r['learner'].observations, 'metrics' => r['learner'].metrics,
      'synth' => r['learner'].synthesize }
  end

  def self.adaptive_scenario(omega, mo, policy, ps, ev, oo)
    k = 0
    pi = 0
    adm = P.admitter(policy)
    ans = lambda do |q, l|
      k += 1
      if (k % ev).zero? && pi < ps.length && q['verb'] == 'stripe.refund'
        x = ps[pi]
        pi += 1
        return x
      end
      vs = l.omega['verbs'].find { |v| v['verb'] == q['verb'] }
      adm.admits(vs, q['outcome']) ? 1 : 0
    end
    r = R.elicit_adaptive(M.create_learner(omega, mo), ans, { 'epsRisk' => 0.001, 'epsBurden' => 0.01, 'maxQuestions' => 25 }.merge(oo))
    { 'stop' => r['stop'], 'questions' => r['questions'], 'auditQuestions' => r['auditQuestions'], 'seedQuestions' => r['seedQuestions'],
      'refinements' => r['refinements'], 'asked' => r['asked'].map { |q| q.slice('verb', 'cell', 'outcome', 'p', 'score') },
      'omega' => r['learner'].omega, 'metrics' => r['learner'].metrics, 'observations' => r['learner'].observations }
  end

  MAP = {
    'refineOmega' => R.method(:refine_omega),
    'regionsOf' => method(:regions_of),
    'refineScenario' => method(:refine_scenario),
    'partialScenario' => method(:partial_scenario),
    'adaptiveScenario' => method(:adaptive_scenario)
  }.freeze

  def test_corpus_is_fully_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn], compare: RefIntent.cmp) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 179, BY_FN.values.sum(&:length), 'intent-refine'
  end

end
