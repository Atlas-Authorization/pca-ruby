# frozen_string_literal: true

# The A2A card entry point delegates to the implementations the reference replay (test_ref_a2a_binding.rb) covers in depth:
# a signed card verifies, a tampered one does not, the schema check names its paths.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/a2a_card'
require 'digest'
require 'minitest/autorun'

class TestRefA2aCard < Minitest::Test
  C = AtlasPca::A2aCard

  CARD = {
    'name' => 'Agent', 'description' => 'd', 'version' => '1',
    'supportedInterfaces' => [{ 'url' => 'https://a.example/a2a', 'protocolBinding' => 'JSONRPC', 'protocolVersion' => '1.0' }],
    'capabilities' => {}, 'defaultInputModes' => ['text/plain'], 'defaultOutputModes' => ['text/plain'],
    'skills' => [{ 'id' => 's', 'name' => 'S', 'description' => 'd', 'tags' => ['pca-verb:stripe.refund'] }]
  }.freeze

  def test_canonical_bytes_are_sorted_and_compact
    assert_equal '{"a":2,"b":1}', C.jcs_bytes({ 'b' => 1, 'a' => 2 })
  end

  def test_schema_check_names_paths
    assert_equal [], C.validate_agent_card1(CARD)
    assert_includes C.validate_agent_card1(CARD.reject { |k, _| k == 'name' }), '$.name: required non-empty string'
  end

  def test_signed_card_verifies_and_tampering_is_refused
    seed = Digest::SHA256.digest('atlas-pca-conformance/a2a-card-smoke')
    priv = OpenSSL::PKey.new_raw_private_key('ED25519', seed)
    jwk = { 'kty' => 'OKP', 'crv' => 'Ed25519', 'x' => AtlasPca.b64e(priv.raw_public_key) }
    signed = C.issue_signed_agent_card(CARD, { 'kty' => 'OKP', 'crv' => 'Ed25519', 'x' => jwk['x'], 'd' => AtlasPca.b64e(seed) })
    assert C.verify_agent_card(signed, { 'key' => jwk })['ok']
    refute C.verify_agent_card(signed.merge('name' => 'Other'), { 'key' => jwk })['ok']
  end
end
