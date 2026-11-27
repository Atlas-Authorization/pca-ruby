# frozen_string_literal: true

# Replays the TS-reference oracle of goal precedent (test-data/ref-goal-precedent.json.gz): the hash-chained precedent log over
# principal-signed escalation answers. The log is stateful, so it is driven through a step script exactly as the reference's
# generator drives it.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/goal_precedent'
require 'minitest/autorun'

class TestRefGoalPrecedent < Minitest::Test
  E = AtlasPca::GoalExamples
  P = AtlasPca::GoalPrecedent
  BY_FN = Ref.load('goal-precedent')

  FLOW = lambda do |goal, ont, grant, principals, steps|
    log = P::Log.new(principals)
    space = E.build_space([goal])
    out = []
    steps.each do |s|
      case s['op']
      when 'append'
        r = log.append(s['answer'], s['answered'], grant, space, s['now'])
        out << (r['ok'] ? { 'ok' => true, 'digest' => r['entry']['digest'], 'cell' => r['entry']['cell'], 'seq' => r['entry']['seq'] } : r)
      when 'revoke'
        r = log.revoke(s['rev'])
        out << (r['ok'] ? { 'ok' => true, 'digest' => r['entry']['digest'], 'seq' => r['entry']['seq'] } : r)
      when 'verifyChain' then out << log.verify_chain(space)
      when 'lookup'
        h = log.lookup(s['policyDigest'], space, s['case'], s['now'])
        out << (h ? { 'decision' => h['decision'], 'digest' => h['entry']['digest'] } : nil)
      when 'authorize'
        a = P.authorize_with_precedents(goal, ont, s['policyDigest'], log, s['case'], s['now'])
        out << { 'decision' => a['decision'], 'via' => a['via'] }.merge(a['precedent'] ? { 'digest' => a['precedent']['digest'] } : {})
      when 'tamper'
        if s['del']
          log.entries[s['index']].delete(s['key'])
        else
          log.entries[s['index']][s['key']] = s['value']
        end
        out << true
      else out << log.head
      end
    end
    out
  end

  FNS = {
    'flow' => FLOW, 'ceilingsOf' => P.method(:ceilings_of), 'answerBodyFor' => P.method(:answer_body_for),
    'signRevocationSeed' => ->(p, seed) { P.sign_revocation(p, AtlasPca::KeyPair.from_seed_b64u(seed)) }
  }.freeze

  def test_every_function_is_covered
    assert_equal FNS.keys.sort, BY_FN.keys.sort
  end

  FNS.each do |fn, call|
    define_method("test_matches_reference_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 34, BY_FN.values.sum(&:length), 'goal-precedent'
  end

end
