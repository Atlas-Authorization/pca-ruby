# frozen_string_literal: true

# Resource-server discovery: the document builder, the strict parser, the intent block and the fetcher over an injected transport.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestDiscovery < Minitest::Test
  A = AtlasPca
  INTENT = { 'versions' => [1, 2], 'actions_uri' => 'https://x/a', 'question_relay' => true, 'tiers' => { 'pay' => 3 },
             'schema_keys' => [{ 'kid' => 'k', 'alg' => 'ed25519', 'pk' => 'p' }] }.freeze

  def test_build_defaults_and_optional_members
    d = A.build_discovery_document({ 'audience' => 'rs' })
    assert_equal [2], d['pca_versions']
    assert_equal 'PCA-Action', d['action_header']
    assert_equal A::STATEFUL_REQUIRED_CHECKS, d['required_checks']
    refute d.key?('intent')
    full = A.build_discovery_document({ 'audience' => 'rs', 'intent' => INTENT, 'obligations_supported' => ['log'], 'trusted_roots' => ['r'] })
    assert_equal [INTENT, ['log'], ['r']], full.values_at('intent', 'obligations_supported', 'trusted_roots')
    assert_raises(ArgumentError) { A.build_discovery_document({ 'audience' => '' }) }
  end

  def test_parse_accepts_a_built_document_and_refuses_malformed_ones
    d = A.build_discovery_document({ 'audience' => 'rs', 'intent' => INTENT })
    assert_equal d, A.parse_discovery_document(d)
    [d.merge('audience' => ''), d.merge('pca_versions' => ['2']), d.merge('signature_suites' => [1]), d.merge('action_header' => ''), 'x',
     d.merge('obligations_supported' => [1])].each { |bad| assert_raises(ArgumentError) { A.parse_discovery_document(bad) } }
  end

  def test_intent_block_rules
    assert_equal INTENT, A.parse_discovery_intent(INTENT)
    [nil, { 'versions' => [] }, { 'versions' => [3] }, INTENT.merge('z' => 1), INTENT.merge('actions_uri' => ''), INTENT.merge('question_relay' => 1),
     INTENT.merge('tiers' => { 'a' => 5 }), INTENT.merge('tiers' => { 'a' => 1.5 }), INTENT.merge('schema_keys' => [{ 'kid' => 'k' }]),
     INTENT.merge('schema_keys' => 'x')].each { |bad| assert_raises(ArgumentError, bad.inspect) { A.parse_discovery_intent(bad) } }
  end

  def test_fetch_discovery_builds_the_url_and_parses_the_body
    seen = nil
    doc = A.build_discovery_document({ 'audience' => 'rs' })
    got = A.fetch_discovery('https://api.acme.com//', lambda { |url, h|
      seen = [url, h]
      { 'ok' => true, 'status' => 200, 'body' => JSON.generate(doc) }
    })
    assert_equal ['https://api.acme.com/.well-known/pca-configuration', { 'accept' => 'application/json' }], seen
    assert_equal doc, got
    e = assert_raises(ArgumentError) { A.fetch_discovery('https://x', ->(*) { { 'ok' => false, 'status' => 503 } }) }
    assert_match(/returned 503/, e.message)
    assert_raises(ArgumentError) { A.fetch_discovery('https://x', ->(*) { { 'ok' => true, 'status' => 200, 'body' => '{}' } }) }
  end

  def test_accepts_suite
    d = A.build_discovery_document({ 'audience' => 'rs' })
    assert A.accepts_suite?(d, 'ml-dsa-65')
    refute A.accepts_suite?(d, 'fn-dsa-512')
  end
end
