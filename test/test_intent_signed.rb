# frozen_string_literal: true

# The signed intent-map attestation, the signed runtime observation and the anchoring receipt (round trips, every shape refusal, tampering, pins).
require_relative '../lib/atlas_pca'
require 'minitest/autorun'
require 'digest'

class TestIntentSigned < Minitest::Test
  A = AtlasPca
  S = AtlasPca::IntentSigned
  UNDEF = AtlasPca::IntentV2::UNDEF

  def d32(l) = A.b64e(Digest::SHA256.digest(l))
  def seed(l) = Digest::SHA256.digest("intent-signed/#{l}")

  def map = { 'v' => 1, 'kind' => 'pca-intent-map', 'intent_ref' => d32('ref'), 'metrics' => { 'fidelity_est_ppm' => 900_000, 'residual_risk_ppm' => 100 }, 'cells' => [] }

  def test_a_map_attestation_round_trips_and_binds_the_map
    att = S.sign_intent_map_attestation(map, seed('s'), 5)
    assert_equal %w[intent_ref map_digest sig signed_at signer v], att.keys.sort
    assert_equal({ 'ok' => true }, S.verify_intent_map_attestation(att))
    assert_equal({ 'ok' => true }, S.verify_intent_map_attestation(att, map))
    assert_equal({ 'ok' => true }, S.verify_intent_map_attestation(att, map, { 'expectedSigner' => att['signer'] }))
    assert_equal 'map digest mismatch', S.verify_intent_map_attestation(att, map.merge('cells' => [1]))['reason']
    assert_equal 'intent_ref mismatch', S.verify_intent_map_attestation(att.merge('intent_ref' => d32('zz')), map)['reason']
    assert_equal 'signer mismatch', S.verify_intent_map_attestation(att, UNDEF, { 'expectedSigner' => d32('other') })['reason']
  end

  def test_a_map_attestation_refuses_every_malformed_form
    att = S.sign_intent_map_attestation(map, seed('s'), 5)
    {
      nil => 'not an intent map attestation v1', att.merge('v' => 2) => 'not an intent map attestation v1',
      att.merge('map_digest' => 'x') => 'map_digest is not canonical base64url (32 bytes)',
      att.merge('intent_ref' => 'x') => 'intent_ref must be null or canonical base64url (32 bytes)',
      att.merge('signer' => 'x') => 'signer is not canonical base64url (32 bytes)',
      att.merge('signed_at' => -1) => 'signed_at must be a non-negative safe integer',
      att.merge('alg' => 'bogus') => 'unknown signature suite',
      att.merge('pq_pk' => 'x') => 'an ed25519 artifact must not carry pq_pk / pq_sig',
      att.merge('signed_at' => 6) => 'bad signature', att.merge('sig' => A.b64e("\0".b * 64)) => 'bad signature'
    }.each { |a, why| assert_equal why, S.verify_intent_map_attestation(a)['reason'], a.inspect[0, 60] }
    assert_equal 'not an intent map v1', S.verify_intent_map_attestation(att, 5)['reason']
  end

  def test_signing_a_malformed_map_or_clock_raises
    assert_raises(ArgumentError) { S.sign_intent_map_attestation(map.merge('kind' => 'x'), seed('s'), 5) }
    assert_raises(ArgumentError) { S.sign_intent_map_attestation(map, seed('s'), -1) }
    assert_raises(ArgumentError) { S.sign_intent_map_attestation(map, seed('s'), 5, { 'alg' => 'ml-dsa-65' }) }
  end

  def test_the_map_shape
    assert_nil S.intent_map_shape_error(map)
    assert_nil S.intent_map_shape_error(map.merge('intent_ref' => nil))
    assert_equal 'intent_ref must be null or canonical base64url (32 bytes)', S.intent_map_shape_error(map.merge('intent_ref' => 'x'))
    assert_equal 'metrics must be an object', S.intent_map_shape_error(map.merge('metrics' => 5))
    assert_equal 'metrics.fidelity_est_ppm must be an integer in [0, 1e6]', S.intent_map_shape_error(map.merge('metrics' => { 'fidelity_est_ppm' => 1_000_001, 'residual_risk_ppm' => 0 }))
    assert_equal 'metrics.residual_risk_ppm must be a non-negative integer', S.intent_map_shape_error(map.merge('metrics' => { 'fidelity_est_ppm' => 1, 'residual_risk_ppm' => -1 }))
  end

  def obs = { 'map_digest' => d32('map'), 'verb' => 'pay', 'values' => { 'action.params.amount' => 5, 'action.params.to' => 'x' }, 'y' => 0, 'source' => 'runtime', 'observed_at' => 9 }

  def test_an_observation_round_trips_and_every_field_is_bound
    o = S.sign_intent_observation(obs, seed('o'))
    assert_equal({ 'ok' => true }, S.verify_intent_observation(o))
    assert_equal({ 'ok' => true }, S.verify_intent_observation(S.sign_intent_observation(obs.merge('pcactn_digest' => d32('p')), seed('o'))))
    %w[verb y observed_at source].zip(['x', 1, 10, 'witness']).each { |k, v| assert_equal 'bad signature', S.verify_intent_observation(o.merge(k => v))['reason'], k }
    assert_equal 'bad signature', S.verify_intent_observation(o.merge('values' => { 'a' => 1 }))['reason']
    assert_equal 'signer mismatch', S.verify_intent_observation(o, { 'expectedSigner' => d32('z') })['reason']
  end

  def test_an_observation_refuses_every_malformed_form
    o = S.sign_intent_observation(obs, seed('o'))
    {
      nil => 'not an intent observation v1', o.merge('map_digest' => 'x') => 'map_digest is not canonical base64url (32 bytes)',
      o.merge('verb' => '') => 'verb must be a non-empty string', o.merge('values' => []) => 'values must map paths to numbers or strings',
      o.merge('values' => { 'a' => nil }) => 'values must map paths to numbers or strings', o.merge('y' => 2) => 'y must be 0 or 1',
      o.merge('source' => 'x') => 'unknown observation source', o.merge('observed_at' => -1) => 'observed_at must be a non-negative safe integer',
      o.merge('pcactn_digest' => 'x') => 'pcactn_digest is not canonical base64url (32 bytes)', o.merge('signer' => 'x') => 'signer is not canonical base64url (32 bytes)'
    }.each { |v, why| assert_equal why, S.verify_intent_observation(v)['reason'], why }
    assert_raises(ArgumentError) { S.sign_intent_observation(obs.merge('y' => 3), seed('o')) }
  end

  def test_an_anchor_receipt_verifies_only_under_the_guardian_and_the_log
    g = A::KeyPair.new(seed('guardian'))
    leaf = A::Evidence.anchor_commit('map', d32('m'))
    ledger = A::TransparencyLedger.new(S::INTENT_ANCHOR_LOG)
    ledger.append_commitment(A::Evidence.anchor_commit('statement', d32('s')))
    ledger.append_commitment(leaf)
    head = ledger.head
    sth = A.sign_tree_head(g, head.merge('instance_id' => 'ins_1', 'principal' => S::INTENT_ANCHOR_LOG, 'timestamp' => 1, 'prev_root' => d32('prev')))
    rec = { 'kind' => 'map', 'digest' => d32('m'), 'index' => 1, 'proof' => ledger.inclusion_proof(1), 'signed_tree_head' => sth }
    assert_equal({ 'ok' => true }, S.verify_intent_anchor(rec, g.public, 'ins_1'))
    assert_equal 'tree head signature invalid', S.verify_intent_anchor(rec, A::KeyPair.new(seed('x')).public, 'ins_1')['reason']
    assert_equal 'not a head of this instance intent log', S.verify_intent_anchor(rec, g.public, 'ins_2')['reason']
    assert_equal 'unknown anchor kind', S.verify_intent_anchor(rec.merge('kind' => 'nope'), g.public, 'ins_1')['reason']
    assert_equal 'digest is not canonical base64url (32 bytes)', S.verify_intent_anchor(rec.merge('digest' => 'x'), g.public, 'ins_1')['reason']
    assert_equal 'proof does not match the head', S.verify_intent_anchor(rec.merge('index' => 0), g.public, 'ins_1')['reason']
    assert_equal 'artifact is not included under the signed head', S.verify_intent_anchor(rec.merge('digest' => d32('other')), g.public, 'ins_1')['reason']
    assert_match(/\Amalformed anchor receipt: /, S.verify_intent_anchor(rec.merge('signed_tree_head' => nil), g.public, 'ins_1')['reason'])
  end
end
