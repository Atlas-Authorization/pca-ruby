# frozen_string_literal: true

# Policy templates and the fluent builder compile through compile_policy: what is authored is what the verifier enforces.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestPolicyTemplates < Minitest::Test
  A = AtlasPca
  PRINCIPAL = A::KeyPair.new("\x09".b * 32)

  def test_the_four_role_templates
    assert_equal %w[read-only support-agent finance-bot dev-assistant], A.list_templates.map { |t| t['name'] }
    assert_equal({ 'refund' => '$500/day' }, A::POLICY_TEMPLATES['finance-bot']['limits'])
  end

  def test_from_template_mints_an_agent_and_refuses_an_unknown_name
    ag = A.from_template('finance-bot', principal: PRINCIPAL, goal: 'refund duplicates', aud: 'rs', now: 1_000_000)
    assert_kind_of A::AgentHandle, ag
    e = assert_raises(ArgumentError) { A.from_template('nope', principal: PRINCIPAL, goal: 'g') }
    assert_match(/unknown template 'nope' \(have: read-only, support-agent, finance-bot, dev-assistant\)/, e.message)
    assert_raises(ArgumentError) { A.from_template(nil, principal: PRINCIPAL, goal: 'g') }
  end

  def test_builder_merges_actions_and_builds_a_copy
    b = A.policy.allow('stripe', ['refund']).allow('stripe', %w[refund charge]).limit('refund', '$500/day').risk({ 'a' => 1 }).risk({ 'b' => 2 })
    built = b.build
    assert_equal({ 'stripe' => %w[refund charge] }, built['permissions'])
    assert_equal({ 'refund' => '$500/day' }, built['limits'])
    assert_equal({ 'a' => 1, 'b' => 2 }, built['riskPolicy'])
    built['permissions']['stripe'] << 'x'
    assert_equal %w[refund charge], b.build['permissions']['stripe']
    assert_raises(ArgumentError) { A.policy.build }
  end

  def test_builder_from_a_template_and_straight_to_an_agent
    t = A::PolicyBuilder.from('dev-assistant').build
    assert_equal %w[read create_pr comment], t['permissions']['github']
    assert_equal({ 'create_pr' => '20/day' }, t['limits'])
    assert_raises(ArgumentError) { A::PolicyBuilder.from('nope') }
    ag = A::PolicyBuilder.from('read-only').agent(principal: PRINCIPAL, goal: 'read', now: 1_000_000)
    assert_kind_of A::AgentHandle, ag
  end
end
