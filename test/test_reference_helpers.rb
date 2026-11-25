# frozen_string_literal: true

# Receipt chain, assurance refresh, caveat predicates, the suite verify seam and the policy-VM / revocation helpers.
require_relative '../lib/atlas_pca'
require_relative '../lib/atlas_pca/fhe'
require 'minitest/autorun'

class TestReferenceHelpers < Minitest::Test
  A = AtlasPca

  def pc(n) = { 'iat' => 10 + n, 'action' => { 'verb' => 'v', 'resource' => "r#{n}" } }

  def test_receipt_chain_links_detects_tampering_and_has_a_head
    log = []
    3.times { |i| log = A.append_receipt(log, pc(i), { 'allow' => i != 1, 'checks' => { 'audience' => 'pass' } }) }
    assert_equal [0, 1, 2], log.map { |r| r['seq'] }
    assert_equal %w[allow deny allow], log.map { |r| r['outcome'] }
    assert_equal [10, ''], [log[0]['at'], log[0]['prev']]
    assert_equal log[0]['hash'], log[1]['prev']
    assert_equal log[2]['hash'], A.receipt_head(log)
    assert_equal '', A.receipt_head([])
    assert_equal({ 'ok' => true }, A.verify_receipt_chain(log))
    assert_equal 99, A.append_receipt([], pc(0), { 'allow' => true }, 99)[0]['at']
    t = Marshal.load(Marshal.dump(log))
    t[1]['outcome'] = 'allow'
    assert_equal [false, 1], A.verify_receipt_chain(t).values_at('ok', 'brokenAt')
    assert_match(/tampered body/, A.verify_receipt_chain(t)['reason'])
    assert_match(/out of order/, A.verify_receipt_chain([log[1]])['reason'])
    assert_match(/prev link mismatch/, A.verify_receipt_chain([log[0], log[2].merge('seq' => 1)])['reason'])
  end

  def test_refresh_assurance
    r = { 'a' => { 'outcome' => 'pass', 'level' => 'x' }, 'b' => { 'outcome' => 'unsupported' }, 'c' => { 'outcome' => 'fail' } }
    A.refresh_assurance(r, { 'a' => 'fail', 'b' => 'pass', 'c' => 'pass', 'd' => 'pass', 'e' => 'not-enforced' })
    assert_equal({ 'a' => { 'outcome' => 'fail' }, 'b' => { 'outcome' => 'unsupported' }, 'c' => { 'outcome' => 'pass' }, 'd' => { 'outcome' => 'pass' }, 'e' => { 'outcome' => 'not-enforced' } }, r)
    keep = { 'a' => { 'outcome' => 'pass', 'level' => 'x' } }
    assert_equal 'x', A.refresh_assurance(keep, { 'a' => 'pass' })['a']['level']
  end

  def test_caveat_predicates
    assert A.budget_alloc_caveat?({ 'type' => 'budget_alloc', 'limit' => 0 })
    refute A.budget_alloc_caveat?({ 'type' => 'budget_alloc', 'limit' => -1 })
    refute A.budget_alloc_caveat?({ 'type' => 'budget_alloc', 'limit' => Float::INFINITY })
    refute A.budget_alloc_caveat?({ 'type' => 'budget_alloc', 'limit' => '1' })
    refute A.budget_alloc_caveat?(nil)
    assert A.k1_caveat?({ 'type' => 'sealed' })
    refute A.k1_caveat?({ 'type' => 'expires' })
    refute A.k1_caveat?('sealed')
  end

  def test_verify_with_suite_is_fail_closed
    ed = A::KeyPair.new("\x04".b * 32)
    msg = 'm'
    sig = A.b64e(ed.sign(msg))
    assert A.verify_with_suite(nil, { 'ed_pub' => ed.public }, msg, { 'sig' => sig })
    assert A.verify_with_suite('ed25519', { 'ed_pub' => ed.public }, msg, { 'sig' => sig })
    refute A.verify_with_suite('ed25519', { 'ed_pub' => ed.public }, 'x', { 'sig' => sig })
    refute A.verify_with_suite('rsa', { 'ed_pub' => ed.public }, msg, { 'sig' => sig })
    refute A.verify_with_suite('ed25519', { 'ed_pub' => ed.public, 'pq' => 'forged' }, msg, { 'sig' => sig })
    refute A.verify_with_suite('ed25519', nil, msg, nil)
  end

  def test_policy_vm_helpers
    assert_equal ['a', 'b: bad'], A.fold_v2_reasons(['a'], [{ 'name' => 'b', 'ok' => false, 'reason' => 'bad' }, { 'name' => 'c', 'ok' => false }, { 'name' => 'd', 'ok' => true, 'reason' => 'x' }])
    assert_equal ['a'], A.fold_v2_reasons(['a'], [{ 'name' => 'a', 'ok' => false, 'reason' => 'x' }]).first(1)
    assert_equal ['b: bad'], A.fold_v2_reasons([], [{ 'name' => 'b', 'ok' => false, 'reason' => 'bad' }, { 'name' => 'b', 'ok' => false, 'reason' => 'bad' }])
    act = { 'action' => { 'verb' => 'pay', 'params' => { 'n' => 1 } }, 'toolBinding' => 'tb' }
    ctx = A.agent_caveat_context({ 'now' => 1, 'action' => 'forged' }, act)
    assert_equal [act, { 'tool' => 'pay', 'args' => { 'n' => 1 }, 'toolSignatureDigest' => 'tb' }, 1], [ctx['action'], ctx['toolCall'], ctx['now']]
    assert_equal({ 'tool' => '', 'args' => {} }, A.agent_caveat_context({}, nil)['toolCall'])
    assert_equal 'costly', A.resolve_reversibility_class({ 'action' => { 'reversibility_class' => 'costly' } }, [], 'n')
    plan = [{ 'id' => 'n1', 'reversibility_class' => 'reversible' }]
    assert_equal 'reversible', A.resolve_reversibility_class({ 'action' => {} }, plan, 'n1')
    assert_nil A.resolve_reversibility_class({ 'action' => {} }, plan, nil)
    assert_nil A.resolve_reversibility_class(nil, plan, 'zz')
  end

  def test_amount_risk_and_staleness_and_link_digest
    grant = { 'caveats' => [{ 'type' => 'envelope', 'goal_commit' => 'g', 'predicates' => [], 'caveats' => [], 'agent_binding' => {}, 'risk_policy' => A::DEFAULT_RISK_POLICY.merge('kappa' => 200) }] } # a valid policy: read_envelope refuses an incomplete one
    assert_equal({ 'blastRadius' => 0.25 }, A.amount_risk(grant, { 'amount' => 50 }))
    assert_equal({ 'blastRadius' => 1 }, A.amount_risk(grant, { 'amount' => 5000 }))
    assert_equal({ 'blastRadius' => 0 }, A.amount_risk(grant, { 'sum' => -4 }, amount_field: 'sum'))
    assert_nil A.amount_risk(grant, { 'amount' => 'x' })
    assert_nil A.amount_risk({ 'caveats' => [] }, { 'amount' => 5 })
    refute A.staleness_policy_on?({})
    assert A.staleness_policy_on?({ 'max_revocation_age_ms' => 5 })
    assert A.staleness_policy_on?(A::RevocationStaleness.new(staleness: { 'irreversible' => 5 }))
    assert_raises(ArgumentError) { A.validate_revocation_staleness({ max_revocation_age_ms: -1 }) }
    assert_equal A.hash_canonical({ 'a' => 1 }), A.link_digest({ 'a' => 1 })
  end

  def test_satellite_helpers
    e = A::PcaAgentError.new('network', 'down', 502)
    assert_equal ['network', 502, 'down'], [e.code, e.http_status, e.message]
    assert_nil A::PcaAgentError.new('no_plan', 'x').http_status
    assert_equal 'b', A.first_failed_check({ 'a' => 'pass', 'b' => 'fail', 'c' => 'fail' })
    assert_nil A.first_failed_check({ 'a' => 'pass' })
    assert A.plain_object?({})
    refute A.plain_object?([])
    st = A::MemoryChargeBudgetStore.new
    assert_nil st.get('k')
    refute st.compare_and_set('k', 1, { 'B' => 1 })
    assert st.compare_and_set('k', nil, { 'B' => 1, 'tau' => 0, 'asOf' => 0 })
    assert_equal 1, st.get('k')['version']
    refute st.compare_and_set('k', nil, { 'B' => 2 })
    assert st.compare_and_set('k', 1, { 'B' => 2, 'tau' => 0, 'asOf' => 0 })
    assert_equal [2, 2], [st.get('k')['version'], st.get('k')['budget']['B']]
  end

  def test_shard_defs_split_by_resource_family
    d = ->(t) { { 'resource' => { 'type' => t } } }
    defs = [d.call('b.x'), d.call('a.y'), d.call('a.z'), d.call('a.w')]
    out = A.shard_defs(defs, 2)
    assert_equal %w[a-1 a-2 b], out.map { |s| s['name'] }
    assert_equal [2, 1, 1], out.map { |s| s['defs'].length }
    assert_equal %w[a b], A.shard_defs(defs).map { |s| s['name'] }
    assert_equal 512, A::DEFAULT_SHARD_DEFS
    assert_raises(A::Actions::ActionKitError) { A.shard_defs(defs, 0) }
  end

  def test_builtin_release_ctx_follows_the_pins
    ctx = A::ActionsBuiltin.builtin_release_ctx
    pinned = !A::ActionsBuiltin.builtin_reviewer_pins.nil?
    assert_equal pinned, !ctx.nil?
    assert_equal pinned, A::ActionsBuiltin.builtin_review_opts.key?('attestation_verified')
  end

  def test_eval_signed_risk_claim_refuses_before_touching_seal
    o = A::Fhe::Origin
    exp = o::ClaimExpectations.new([], 'ctx', {}, {}, o.memory_nonce_guard)
    r = o.eval_signed_risk_claim({ 'public_key' => 'x', 'galois_keys' => 'y' }, 'not-a-claim', exp)
    assert_equal({ 'ok' => false, 'reason' => 'claim is not signed: malformed envelope' }, r)
  end

  def test_parse_intent_goal
    assert_equal({ 'intentRef' => 'r1' }, A.parse_intent_goal(A.intent_goal('r1')))
    assert_equal({ 'intentRef' => 'r1', 'mapDigest' => 'm' }, A.parse_intent_goal(A.intent_goal('r1', 'm')))
    assert_nil A.parse_intent_goal('other:r1')
    assert_nil A.parse_intent_goal('pca-intent:v1:')
    assert_nil A.parse_intent_goal('pca-intent:v1:a:b:c')
    assert_nil A.parse_intent_goal(5)
  end

  def test_check_intent_conformance_asks_the_panel_then_attests
    panel = Object.new
    panel.define_singleton_method(:verdicts) { |input| [{ 'judge' => input['actionDigest'] }] }
    seen = nil
    verify = lambda do |verdicts, vo|
      seen = [verdicts, vo['k']]
      { 'ok' => true, 'agreeCount' => 1, 'aggregateScore' => 1 }
    end
    input = { 'intentRef' => 'r', 'mapDigest' => 'm', 'goalCommitment' => 'g', 'actionDigest' => 'a' }
    r = A.check_intent_conformance(panel, input, { 'judgeKeys' => [], 'k' => 1 }, verify)
    assert_equal [[{ 'judge' => 'a' }], 1], seen
    assert_equal [{ 'judge' => 'a' }], r['verdicts']
    assert_equal 'pca-ic-att', r['att']['kind']
  end
end
