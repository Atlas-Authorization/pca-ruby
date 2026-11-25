# frozen_string_literal: true

# Small public functions of the reference: goal commitment opening, cheap pre-signature claim checks, discharge requests and the
# detector-receipt policy / tighten-only fold.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestSmallSurface < Minitest::Test
  A = AtlasPca
  D = AtlasPca::Dataflow

  def test_verify_goal_commit
    c = A.goal_commit_of('pay suppliers', 'salt')
    assert A.verify_goal_commit(c, 'pay suppliers', 'salt')
    refute A.verify_goal_commit(c, 'pay suppliers', 'salt2')
    refute A.verify_goal_commit(c, 'pay', 'salt')
  end

  def test_pcactn_cheap_claims
    ok = { 'aud' => 'rs', 'iat' => 1000, 'exp' => 2000 }
    assert_nil A.pcactn_cheap_claims(ok, audience: 'rs', now: 1500)
    assert_equal 'audience', A.pcactn_cheap_claims(ok.merge('aud' => 'x'), audience: 'rs', now: 1500)['check']
    assert_equal 'audience', A.pcactn_cheap_claims(ok.merge('aud' => ''), audience: '', now: 1500)['check']
    assert_equal 'iat and exp must be safe-integer epoch ms', A.pcactn_cheap_claims(ok.merge('iat' => 1.5), audience: 'rs', now: 1500)['reason']
    assert_equal 'exp must be greater than iat', A.pcactn_cheap_claims(ok.merge('exp' => 1000), audience: 'rs', now: 1500)['reason']
    assert_match(/lifetime exceeds/, A.pcactn_cheap_claims(ok.merge('exp' => 1000 + 3_600_001), audience: 'rs', now: 1500)['reason'])
    assert_match(/in the future/, A.pcactn_cheap_claims(ok, audience: 'rs', now: 1000 - 60_001)['reason'])
    assert_nil A.pcactn_cheap_claims(ok, audience: 'rs', now: 1000 - 60_000)
    assert_match(/expired/, A.pcactn_cheap_claims(ok, audience: 'rs', now: 2001)['reason'])
    assert_nil A.pcactn_cheap_claims(ok, audience: 'rs', now: 2000)
    assert_match(/clock/, A.pcactn_cheap_claims(ok, audience: 'rs', now: 1.5)['reason'])
    assert_equal 'audience', A.pcactn_cheap_claims(nil, audience: 'rs', now: 1)['check']
  end

  def test_discharge_requests
    cav = { 'type' => 'needs_discharge', 'id' => 'ok1', 'issuer' => 'idp', 'issuer_class' => 'human', 'bind' => 'action', 'ttl_ms' => 60_000,
            'require' => [{ 'claim' => 'mfa', 'op' => 'eq', 'value' => true }] }
    grant = { 'id' => 'g', 'issuer' => 'a', 'holder' => 'b', 'caveats' => [cav, { 'type' => 'needs_discharge' }, { 'type' => 'sealed' }], 'body_digest' => 'x', 'sig' => 'y' }
    rs = A.discharge_requests(grant, nil, 'AD')
    assert_equal 1, rs.length
    assert_equal %w[v kind caveat_id issuer cap_hash bind action_digest require ttl_ms], rs[0].keys
    assert_equal ['pca-discharge-request', 'ok1', 'AD'], rs[0].values_at('kind', 'caveat_id', 'action_digest')
    refute A.discharge_requests(grant)[0].key?('action_digest')
    refute A.discharge_requests({ 'caveats' => [cav.merge('bind' => 'chain_hop')] }, nil, 'AD')[0].key?('action_digest')
    assert_empty A.discharge_requests({ 'nope' => 1 })
  end

  PIN_SEED = "\x05".b * 32

  def policy(extra = {})
    k = A::KeyPair.new(PIN_SEED)
    { 'detectors' => [{ 'id' => 'lakera', 'keys' => [{ 'pk' => k.public }], 'on_suspicious' => 'deny', 'max_age_ms' => 60_000 }.merge(extra)] }
  end

  def receipt(verdict, cats, over = {})
    body = { 'v' => 1, 'kind' => 'pca-detector-receipt', 'detector' => 'lakera', 'version' => '1', 'input_digest' => D.detector_input_digest('x'),
             'verdict' => verdict, 'categories' => cats, 'iat' => 1000 }.merge(over)
    D.sign_detector_receipt(body, A::KeyPair.new(PIN_SEED))
  end

  def run_signal(receipts, pol = policy, extra = {})
    D.detector_signal({ 'receipts' => receipts, 'policy' => pol, 'input_digests' => [D.detector_input_digest('x')], 'now' => 1500 }.merge(extra))
  end

  def test_policy_errors
    assert_nil D.detector_policy_error(policy)
    assert_equal 'policy must be {detectors}', D.detector_policy_error(nil)
    assert_match(/malformed/, D.detector_policy_error({ 'detectors' => [1] }))
    assert_match(/other than "invalid"/, D.detector_policy_error(policy('id' => 'invalid')))
    assert_match(/on_suspicious/, D.detector_policy_error(policy('on_suspicious' => 'ok')))
    assert_match(/max_age_ms/, D.detector_policy_error(policy('max_age_ms' => 0)))
    assert_match(/categories/, D.detector_policy_error(policy('categories' => [])))
    assert_match(/keys must hold/, D.detector_policy_error(policy('keys' => [])))
    assert_match(/at most 16/, D.detector_policy_error({ 'detectors' => Array.new(17, {}) }))
    two = policy
    two['detectors'] << two['detectors'][0]
    assert_match(/distinct/, D.detector_policy_error(two))
  end

  def test_signal_folds_tighten_only
    none = run_signal([])
    assert_equal ['ok', [], { 'lakera' => false, 'invalid' => 0 }], [none['signal'], none['flagged'], none['env']['detect']]
    assert_equal 'ok', run_signal([receipt('no_finding', [])])['signal']
    s = run_signal([receipt('suspicious', ['injection'])])
    assert_equal ['deny', ['lakera'], true], [s['signal'], s['flagged'], s['env']['detect']['lakera']]
    assert_equal 'ok', run_signal([receipt('suspicious', ['other'])], policy('categories' => ['injection']))['signal']
    assert_equal 'deny', run_signal([receipt('suspicious', [])], policy('categories' => ['injection']))['signal']
  end

  def test_signal_refuses_what_it_cannot_trust
    bad = ->(r, kw = {}) { run_signal([r], policy, kw) }
    assert_match(/about other content/, bad.call(receipt('no_finding', []), { 'input_digests' => ['x'] })['rejected'][0]['reason'])
    assert_match(/from the future/, bad.call(receipt('no_finding', [], 'iat' => 1501))['rejected'][0]['reason'])
    assert_match(/stale/, bad.call(receipt('no_finding', [], 'iat' => 1), { 'now' => 70_000 })['rejected'][0]['reason'])
    assert_match(/another session/, bad.call(receipt('no_finding', [], 'session' => A.b64e("\x01".b * 32)))['rejected'][0]['reason'])
    assert_match(/undeclared/, bad.call(receipt('no_finding', [], 'detector' => 'other'))['rejected'][0]['reason'])
    forged = receipt('no_finding', []).merge('verdict' => 'suspicious', 'categories' => [])
    assert_match(/no pinned key/, bad.call(forged)['rejected'][0]['reason'])
    assert_match(/malformed/, bad.call({ 'x' => 1 })['rejected'][0]['reason'])
    r = bad.call({ 'x' => 1 })
    assert_equal ['escalate', 1], [r['signal'], r['env']['detect']['invalid']]
    assert_equal 'deny', run_signal([], { 'detectors' => 'x' })['signal']
    assert_equal 'escalate', run_signal(Array.new(33, 1))['signal']
    assert_equal 'escalate', run_signal([], policy, { 'now' => 1.5 })['signal']
  end

  def test_collect_obligations_adds_duties_when_a_rule_cannot_be_decided
    log = { 'kind' => 'log', 'params' => {} }
    rules = [{ 'id' => 'r1', 'when' => { 'field' => 'action.verb', 'op' => 'eq', 'value' => 'pay' }, 'obligations' => [log] }]
    hit = A.collect_obligations(rules, { 'action' => { 'verb' => 'pay' } })
    assert_equal [true, [log]], [hit['ok'], hit['obligations']]
    assert_equal [], A.collect_obligations(rules, { 'action' => { 'verb' => 'read' } })['obligations']
    assert_equal [log], A.collect_obligations(rules, {})['obligations'] # undecidable: the duties apply
    assert_equal({ 'ok' => true, 'obligations' => [] }, A.collect_obligations(nil, {}))
    assert_equal 'obligation rules must be an array', A.collect_obligations({}, {})['reason']
    assert_match(/rule 0 is malformed/, A.collect_obligations([1], {})['reason'])
    assert_match(/duplicate/, A.collect_obligations([rules[0], rules[0]], {})['reason'])
    assert_match(/must not be empty/, A.collect_obligations([rules[0].merge('obligations' => [])], {})['reason'])
  end

  def test_workflow_commitment_error_codes
    assert_equal 'bad_workflow', A.workflow_commitment_error(nil, 'x', 1)
    assert_equal 'bad_workflow', A.workflow_commitment_error({ 'body' => {}, 'sig' => 's' }, 'x', 1)
  end
end
