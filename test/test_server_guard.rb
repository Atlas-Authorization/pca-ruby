# frozen_string_literal: true

# The server stack: the atomic KV state store, request extractors, undo admission check, default-deny helper and the authorizer factory.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestServerGuard < Minitest::Test
  A = AtlasPca

  def test_kv_store_claims_pins_budget_and_consume_once
    s = A.durable_pca_state_store(A::MemoryDurableKv.new)
    assert A.atomic_pca_state_store?(s)
    assert_equal :shared, s.scope
    assert s.claim('k', 5).ok
    r = s.claim('k', 5)
    assert_equal [false, 5], [r.ok, r.last_counter]
    assert s.claim('k', 6).ok
    assert_equal 6, s.last('k')
    assert_nil s.pin('k')
    assert_equal 3, s.raise_pin('k', 3)
    assert_equal 3, s.raise_pin('k', 2)
    assert_equal 9, s.raise_beacon_pin('k', 9)
    b = { 'B' => 1, 'tau' => 2, 'asOf' => 3 }
    assert s.budget_cas('k', nil, b)
    refute s.budget_cas('k', nil, b)
    assert_equal b, s.budget('k')
    assert s.consume_once('u', 10, 1)
    refute s.consume_once('u', 10, 2)
    assert s.consume_once('u', 20, 11)
    assert_equal 6, s.last('k') # the pins and the budget did not disturb the counter
  end

  def test_memory_stores_are_process_scoped
    assert_equal :process, A.memory_pca_store.scope
    assert A.atomic_pca_state_store?(A.atomic_memory_pca_store)
    refute A.atomic_pca_state_store?(nil)
  end

  def test_decision_of_result
    assert_equal 'allow', A.decision_of_result({ 'ok' => true })
    assert_equal 'escalate', A.decision_of_result({ 'ok' => false, 'decision' => 'escalate' })
    assert_equal 'deny', A.decision_of_result({ 'ok' => false })
    assert_equal 'deny', A.decision_of_result(A::AuthorizeResult.new(allow: false))
  end

  def test_default_extract_header_body_and_escalation_answer
    pc = { 'ver' => 2, 'aud' => 'rs' }
    hdr = A.b64e(A.canon_bytes(pc))
    assert_equal A.canon_bytes(pc).force_encoding('UTF-8'), A.default_extract({ 'headers' => { 'PCA-Action' => hdr } })
    assert_equal pc, A.default_extract({ 'headers' => {}, 'body' => JSON.generate('pcactn' => pc) })
    assert_nil A.default_extract({ 'headers' => {}, 'body' => '{"pcactn":' })
    assert_nil A.default_extract({ 'headers' => {} })
    assert_raises(ArgumentError) { A.default_extract({ 'headers' => { 'pca-action' => 'AB==' } }) }
    assert_nil A.request_header({ 'headers' => { 'X' => 'a', 'x' => 'b' } }, 'x')
    ans = { 'v' => 1 }
    assert_equal ans, A.default_escalation_answer({ 'headers' => { 'pca-escalation-answer' => A.b64e(A.canon_bytes(ans)) } })
    assert_equal ans, A.default_escalation_answer({ 'headers' => {}, 'body' => { 'escalation_answer' => ans } })
  end

  def test_undo_admission_error
    ok = { 'id' => 'u1', 'window_end' => 10, 'compensation' => { 'verb' => 'refund_undo' } }
    assert_nil A.undo_admission_error(ok)
    assert_match(/object/, A.undo_admission_error(nil))
    assert_match(/id/, A.undo_admission_error(ok.merge('id' => '')))
    assert_match(/id/, A.undo_admission_error(ok.merge('id' => 'x' * 129)))
    assert_match(/window_end/, A.undo_admission_error(ok.merge('window_end' => -1)))
    assert_match(/window_end/, A.undo_admission_error(ok.merge('window_end' => 1.5)))
    assert_match(/compensation/, A.undo_admission_error(ok.merge('compensation' => {})))
  end

  def test_missing_execution_components
    full = { 'audience' => 'rs', 'grant' => {}, 'state' => A.memory_pca_store, 'is_revoked' => ->(*) { false } }
    assert_empty A.missing_execution_components(full)
    assert_equal ['audience', 'grant or resolve_grant', 'state', 'is_revoked'], A.missing_execution_components(nil)
  end

  def test_enforce_required_default_deny
    v = { 'allow' => true, 'checks' => { 'replay' => 'pass', 'revocation' => 'not-enforced', 'bond' => 'unsupported' }, 'reasons' => [] }
    A.enforce_required(v, %w[counter revocation bond audience])
    assert_equal false, v['allow']
    assert_equal({ 'replay' => 'pass', 'revocation' => 'fail', 'bond' => 'unsupported', 'audience' => 'fail' }, v['checks'])
    assert_equal 'bond: required check is unsupported (default-deny: not enforced by this resource server)', v['reasons'][1]
    assert_equal 'audience: required check is absent (default-deny: not enforced by this resource server)', v['reasons'][2]
  end

  def test_create_authorizer_refuses_an_incomplete_configuration
    r = A.create_authorizer(audience: 'rs').call({}, operation: { 'verb' => 'v', 'resource' => 'r', 'params' => {} })
    assert_equal [false, 403, 'deny'], [r.allow, r.status, r.decision]
    assert_includes r.missing, 'resolve_grant'
  end

  def test_require_authorized_denies_without_a_pcactn
    guard = A.require_authorized(operation: ->(_req) { { 'verb' => 'v', 'resource' => 'r', 'params' => {} } }, audience: 'rs', resolve_grant: ->(_) {},
                                 state_store: A.memory_pca_store, is_revoked: ->(*) { false })
    r = guard.call({ 'headers' => {} })
    assert_equal [false, 'deny'], [r['ok'], r['decision']]
    assert_kind_of Integer, r['status']
  end
end
