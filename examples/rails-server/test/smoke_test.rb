# frozen_string_literal: true

require 'minitest/autorun'
require 'rack/test'
require 'json'
require_relative '../refund_app'

class SmokeTest < Minitest::Test
  include Rack::Test::Methods

  PROOF = JSON.parse(File.read(File.join(__dir__, '..', 'fixtures', 'refund_proof.json')))
  GRANTS = JSON.parse(File.read(File.join(__dir__, '..', 'grants.json')))
  DOC = 'https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md'

  # The agent harness that records provenance (its key stays out of the model's reach); the server pins its key.
  HARNESS = AtlasPca::KeyPair.new("\x01".b * 32)
  PIN = { 'mediator' => 'refund-harness', 'kid' => 'k1', 'pk' => HARNESS.public }.freeze

  def setup
    # a fresh app (and replay store) per test; `now` is pinned to the moment the fixture proof was signed for
    @app, @protected = RefundApp.build(grants: GRANTS, audience: PROOF['audience'], now: PROOF['now'],
                                       provenance: { 'mediators' => [PIN] })
  end

  def app = @app

  def proof_header = AtlasPca.b64e(AtlasPca.canon_bytes(PROOF['pcactn']))

  # The refund comes straight from the user (no model in between): a principal-direct provenance bundle.
  def provenance_header(amount)
    rec = AtlasPca::ProvenanceRecorder.new(mediator: PIN['mediator'], kid: PIN['kid'], key: HARNESS)
    op = { verb: 'payments.send', resource: 'payments/acme', params: { amount: amount, currency: 'usd' } }
    AtlasPca.b64e(AtlasPca.canon_bytes(AtlasPca.principal_direct_provenance(rec, op)))
  end

  def refund(amount: 50, provenance: true)
    header 'PCA-Action', proof_header
    header 'PCA-Provenance', provenance_header(amount) if provenance
    post '/refunds', JSON.generate(account: 'acme', amount: amount, currency: 'usd'), 'CONTENT_TYPE' => 'application/json'
  end

  def test_a_valid_proof_for_this_operation_runs_the_handler
    refund
    assert_equal 200, last_response.status
    assert_equal 'payments.send', JSON.parse(last_response.body)['verb']
  end

  def test_the_same_proof_twice_is_refused_with_a_doc
    refund
    refund
    assert_equal 403, last_response.status
    body = JSON.parse(last_response.body)
    assert_equal 'access_denied', body['error']
    assert_equal "#{DOC}#replay", body['doc']
  end

  def test_a_proof_signed_for_50_cannot_refund_400
    refund(amount: 400)
    assert_equal 403, last_response.status
    assert_equal "#{DOC}#operation", JSON.parse(last_response.body)['doc']
  end

  def test_no_proof_is_a_401_with_a_doc
    post '/refunds', '{}', 'CONTENT_TYPE' => 'application/json'
    assert_equal 401, last_response.status
    assert_equal DOC, JSON.parse(last_response.body)['doc']
  end

  def test_without_provenance_the_refund_is_escalated
    refund(provenance: false)
    assert_equal 403, last_response.status
    body = JSON.parse(last_response.body)
    assert_equal 'escalate', body['decision']
    assert_equal ['provenance_flow'], body['failed_checks']
  end

  def test_a_revoked_grant_is_refused
    @protected.revoke(GRANTS.first['id'])
    refund
    assert_equal 403, last_response.status
    assert_equal "#{DOC}#revocation", JSON.parse(last_response.body)['doc']
  end
end
