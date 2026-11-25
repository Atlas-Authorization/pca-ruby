# frozen_string_literal: true

# Replays the TS-reference oracle of the policy debugger (test-data/ref-policy-debug.json.gz, 553 cases): explainRisk, explainDecision over
# Policy VM decide inputs, applyDelta, counterfactual and auditPCActn (the core verifier's report with the explanation). Every fn has a
# handler and the total is asserted. Results are compared by JSON value with null members counted as absent (the reference leaves an
# option it was not given undefined; this port carries nil); in an optional position null is "not given", except the audit's audience,
# where an explicit null is the opt-out and an absent member is "not given".
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefPolicyDebug < Minitest::Test
  A = AtlasPca
  D = AtlasPca::PolicyDebug
  BY_FN = Ref.load('policy-debug')
  TOTALS = { 'explainRisk' => 315, 'explainDecision' => 140, 'applyDelta' => 63, 'counterfactual' => 26, 'auditPCActn' => 9 }.freeze
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  def self.present(v)
    case v
    when Hash then v.reject { |_, x| x.nil? }.transform_values { |x| present(x) }
    when Array then v.map { |x| present(x) }
    else v
    end
  end

  def self.audit(p, inp, opts)
    kw = { now_epoch: opts['nowEpoch'], insecure_skip_plan_root_check: opts['insecureSkipPlanRootCheck'] == true }
    kw[:audience] = opts['audience'] if opts.key?('audience')
    D.audit_pcactn(p, inp, opts['grant'], **kw)
  end

  HANDLERS = {
    'explainRisk' => ->(inputs, weights, floor) { floor.nil? ? D.explain_risk(inputs, weights) : D.explain_risk(inputs, weights, floor) },
    'explainDecision' => ->(inp) { D.explain_decision(inp) },
    'applyDelta' => ->(inp, d) { D.apply_delta(inp, d) },
    'counterfactual' => ->(inp, deltas) { D.counterfactual(inp, deltas) },
    'auditPCActn' => ->(p, inp, opts) { audit(p, inp, opts) }
  }.freeze

  def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 553, BY_FN.values.sum(&:length)
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      same = ->(got, out, _c) { Ref.canon(self.class.present(got)) == Ref.canon(self.class.present(out)) }
      ran = Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| self.class.dnum(a) }) }, compare: same)
      assert_equal TOTALS.fetch(fn), ran
    end
  end

  # a failing capability chain is worded as the reference words it (`cap_chain: <why>`), not by the SDK's coarse text
  def test_a_failing_chain_is_worded_as_the_reference_words_it
    grant = { 'id' => 'g', 'issuer' => 'a', 'holder' => 'b', 'body_digest' => 'd', 'sig' => 's', 'caveats' => [] }
    assert_equal 'empty chain', D.chain_reason({ 'cap_chain' => [] }, grant)
    assert_equal 'empty chain', D.chain_reason({}, grant)
    assert_equal 'chain root is not the grant', D.chain_reason({ 'cap_chain' => [grant.merge('id' => 'other')] }, grant)
    why = D.chain_reason({ 'cap_chain' => [grant] }, grant)
    assert_equal A.verify_chain([grant], 'a', true, nil, nil, grant)[0], why
    assert_kind_of String, why
    refute_empty why
  end

end
