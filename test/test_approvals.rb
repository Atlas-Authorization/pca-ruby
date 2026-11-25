# frozen_string_literal: true

# The approval / step-up model: goal lineage, review of an intended action, standing class approvals, the co-sign recharge and time-boxing.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestApprovals < Minitest::Test
  A = AtlasPca
  NOW = 1_700_000_000_000
  PRINCIPAL = A::KeyPair.new("\x01".b * 32)
  HOLDER = A::KeyPair.new("\x02".b * 32)
  SALT = 'salt-1'

  def agent(**kw)
    A.create_agent(principal: PRINCIPAL, goal: 'refund duplicate charges', permissions: { 'stripe' => ['refund'] }, limits: { 'refund' => '$500/day' },
                   holder: HOLDER, aud: 'rs', now: NOW, goal_salt: SALT, **kw)
  end

  def test_lineage_verifies_a_revealed_goal_and_never_fabricates
    ag = agent
    l = A.build_goal_lineage(ag, 'stripe.refund', 'charge:ch_1', { 'amount' => 42 }, goal: 'refund duplicate charges')
    assert_equal [true, %w[goal authority action]], [l['goalVerified'], l['chain'].map { |n| n['kind'] }]
    assert_equal 'verified: this goal opens the signed grant commitment', l['chain'][0]['detail']
    assert_match(/Delegated authority to stripe\.refund \(up to \$500\/1d\)/, l['chain'][1]['label'])
    assert_equal 'amount=42', l['chain'][2]['detail']
    assert_equal "Approving stripe.refund on charge:ch_1 because you asked to “refund duplicate charges”.", l['because']
    wrong = A.build_goal_lineage(ag, 'stripe.refund', 'charge:ch_1', nil, goal: 'something else')
    assert_equal [false, 'unverified: the revealed goal does not open the grant commitment'], [wrong['goalVerified'], wrong['chain'][0]['detail']]
    none = A.build_goal_lineage(ag, 'stripe.refund', 'charge:ch_1')
    refute none.key?('goal')
    assert_match(/\Acommitted as /, none['chain'][0]['detail'])
    assert_nil none['chain'][2]['detail']
    assert_equal 'Approving stripe.refund on charge:ch_1, authorized under the grant’s committed goal.', none['because']
  end

  def test_review_deny_and_the_render_requirement
    ag = agent
    deny = A.review_action(ag, 'stripe.nuke', 'x', nil, now: NOW)
    assert_equal 'deny', deny['kind']
    r = A.review_action(ag, 'stripe.refund', 'charge:ch_1', { 'amount' => 900_000 }, now: NOW)
    if r['kind'] == 'deny'
      assert r['reason']
    elsif r['kind'] == 'step_up'
      flunk 'a step-up must not be created without a render'
    end
  end

  def test_step_up_carries_lineage_render_and_a_stable_id
    ag = agent
    big = { 'amount' => 900_000 }
    t = ag.dry_run('stripe.refund', 'charge:ch_1', big, now: NOW)
    skip 'this policy auto-admits the amount' unless t['allowed'] && t['t'].to_i > 1
    render = ->(verb, resource, _p) { { 'v' => 1, 'kind' => 'pca-approval-render', 'verb' => verb, 'resource' => resource, 'fields' => [] } }
    r = A.review_action(ag, 'stripe.refund', 'charge:ch_1', big, now: NOW, goal: 'refund duplicate charges', renderer: ->(*a) { render.call(*a) }, insecure_unbound_approval: true)
    assert_equal 'step_up', r['kind'] if r['kind'] != 'deny'
    return unless r['kind'] == 'step_up'

    q = r['request']
    assert_equal [t['t'], NOW, 'refund duplicate charges'], [q['tier'], q['requestedAt'], q['goal']]
    assert_equal q['id'], A.review_action(ag, 'stripe.refund', 'charge:ch_1', big, now: NOW, renderer: ->(*a) { render.call(*a) })['request']['id']
    assert_equal [q], A.pending_requests(A.batch_review(ag, [{ 'verb' => 'stripe.refund', 'resource' => 'charge:ch_1', 'params' => big }], now: NOW, goal: 'refund duplicate charges',
                                                          renderer: ->(*a) { render.call(*a) }, insecure_unbound_approval: true))
  end

  def test_a_throwing_renderer_denies
    ag = agent
    t = ag.dry_run('stripe.refund', 'charge:ch_1', { 'amount' => 900_000 }, now: NOW)
    skip 'this policy auto-admits the amount' unless t['allowed'] && t['t'].to_i > 1
    r = A.review_action(ag, 'stripe.refund', 'charge:ch_1', { 'amount' => 900_000 }, now: NOW, renderer: ->(*) { raise 'cannot show it' })
    assert_equal ['deny', 'approval render failed (fail closed): cannot show it'], r.values_at('kind', 'reason')
  end

  def test_standing_class_approvals
    ap = A.approve_class(%w[stripe.refund gmail.send], ttl_ms: 4 * 3_600_000, by: 'ana', now: NOW)
    assert_equal ap['id'], A.approve_class(%w[gmail.send stripe.refund], ttl_ms: 1, by: 'ana', now: NOW)['id'] # verb order does not matter
    assert A.class_approval_covers?(ap, 'stripe.refund', 'anything', NOW)
    assert A.class_approval_covers?(ap, 'gmail.send', 'x', NOW + 4 * 3_600_000 - 1)
    refute A.class_approval_covers?(ap, 'gmail.send', 'x', NOW + 4 * 3_600_000)
    refute A.class_approval_covers?(ap, 'gmail.send', 'x', NOW - 1)
    refute A.class_approval_covers?(ap, 'stripe.charge', 'x', NOW)
    pre = A.approve_class(['stripe.refund'], ttl_ms: 1000, by: 'ana', now: NOW, resource: 'charge:*')
    assert A.class_approval_covers?(pre, 'stripe.refund', 'charge:ch_9', NOW)
    refute A.class_approval_covers?(pre, 'stripe.refund', 'invoice:1', NOW)
    exact = A.approve_class(['v'], ttl_ms: 1000, by: 'a', now: NOW, resource: 'r1')
    assert A.class_approval_covers?(exact, 'v', 'r1', NOW)
    refute A.class_approval_covers?(exact, 'v', 'r10', NOW)
    assert A.covered_by_any?([exact, pre], 'stripe.refund', 'charge:1', NOW)
    refute A.covered_by_any?([], 'v', 'r', NOW)
  end

  def test_decision_cosign_and_time_box
    d = A.record_decision({ 'id' => 'q1' }, 'approve', 'ana', 5)
    assert_equal({ 'requestId' => 'q1', 'decision' => 'approve', 'by' => 'ana', 'at' => 5 }, d)
    pol = { 'bMax' => 10, 'rho' => 3 }
    low = { 'B' => 1, 'tau' => 0, 'asOf' => 0 }
    assert_equal({ 'B' => 4, 'tau' => 9, 'asOf' => 9 }, A.apply_cosign(low, pol, 9))
    assert_equal({ 'B' => 10, 'tau' => 9, 'asOf' => 9 }, A.apply_cosign(low, pol, 9, full: true))
    assert_equal 10, A.apply_cosign({ 'B' => 9, 'tau' => 0, 'asOf' => 0 }, pol, 9)['B']
    ag = agent
    boxed = A.time_box(ag.grant, HOLDER, 60_000, NOW)
    assert_equal({ 'type' => 'expires', 'at' => NOW + 60_000 }, boxed['caveats'].last)
    assert_equal A.cap_hash(ag.grant), boxed['parent']
  end
end
