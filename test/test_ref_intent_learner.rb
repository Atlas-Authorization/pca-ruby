# frozen_string_literal: true

# Replays the TS-reference oracle of the intent learner (test-data/ref-intent-learner.json.gz): the posterior over box / union /
# decision-list classes, questions, the audit round and the synthesis into predicates. Doubles compare exactly (the entropies, prior mix and Occam weights use the deterministic math).
require_relative 'support/ref_intent'
require_relative '../lib/atlas_pca/intent_learner'
require 'minitest/autorun'

class TestRefIntentLearner < Minitest::Test
  L = AtlasPca::IntentLearner
  P = AtlasPca::IntentPolicy
  BY_FN = Ref.load('intent-learner')

  def self.mk_opts(opts)
    x = opts.dup
    if x['nullMassFn'] == 'byRev'
      x['nullMass'] = ->(vs) { vs['reversibility'] == 'reversible' ? 0.1 : 0.3 }
      x.delete('nullMassFn')
    end
    if L.truthy(x['priorMix'])
      kind = x['priorMix']['weight']
      wt = case kind
           when 'size' then ->(_vs, has) { 1 + (0...64).count { |c| has.call(c) } }
           when 'neg' then ->(_vs, _has) { -1 }
           else ->(_vs, _has) { 0 }
           end
      x['priorMix'] = { 'beta' => x['priorMix']['beta'], 'weight' => wt }
    end
    x
  end

  def self.jq(q) = q.nil? ? nil : q.slice('verb', 'cell', 'outcome', 'p', 'score')

  def self.scenario(omega, opts, ops)
    lopts = mk_opts(opts)
    l = L::IntentLearner.new(omega, lopts)
    ops.map do |op|
      case op['op']
      when 'observe' then l.observe({ 'verb' => op['verb'], 'values' => op['values'] }, op['y'], L.truthy(op['source']) ? op['source'] : 'elicitation', op['region'])
      when 'probe'
        oc = { 'verb' => op['verb'], 'values' => op['values'] }
        [l.acceptance(oc), l.admits_outcome(oc), l.vetoed?(oc)]
      when 'next' then jq(l.next_question)
      when 'metrics' then l.metrics
      when 'cells' then l.cells
      when 'unconfirmed' then l.unconfirmed_grant_cells
      when 'synth' then l.synthesize
      when 'vetoed' then l.vetoed_cells
      when 'observations' then l.observations
      when 'replay' then L::IntentLearner.replay(omega, lopts, l.observations).metrics
      when 'elicit'
        adm = P.admitter(op['policy'])
        count = [0]
        ans = lambda do |q|
          vs = omega['verbs'].find { |v| v['verb'] == q['verb'] }
          y = adm.admits(vs, q['outcome']) ? 1 : 0
          count[0] += 1
          L.truthy(op['flipEvery']) && (count[0] % op['flipEvery']).zero? ? 1 - y : y
        end
        r = L.elicit(l, ans, { 'epsRisk' => op['epsRisk'], 'epsBurden' => op['epsBurden'], 'maxQuestions' => op['maxQuestions'], 'audit' => op['audit'], 'seed' => op['seed'] })
        { 'stop' => r['stop'], 'questions' => r['questions'], 'auditQuestions' => r['auditQuestions'], 'seedQuestions' => r['seedQuestions'],
          'asked' => r['asked'].map { |q| jq(q) }, 'metrics' => l.metrics }
      else raise ArgumentError, 'bad op'
      end
    end
  end

  def self.hypothesis_cell_sets(vs, hc, caps = nil, *_rest)
    r = L.hypothesis_cell_sets(vs, hc, caps)
    return r['sets'].length if !caps.nil? || hc.nil?

    { 'sets' => r['sets'].map(&:dup), 'complexity' => r['complexity'] }
  end

  MAP = {
    'scenario' => method(:scenario),
    'hypothesisCellSets' => method(:hypothesis_cell_sets),
    'hypothesisClassName' => L.method(:hypothesis_class_name),
    'boxesToPredicates' => ->(vs, allowed) { L.boxes_to_predicates(vs, allowed) }
  }.freeze

  def test_corpus_is_fully_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn], compare: RefIntent.cmp) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 443, BY_FN.values.sum(&:length), 'intent-learner'
  end

end
