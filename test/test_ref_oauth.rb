# frozen_string_literal: true

# Replays the TS-reference oracle of the OAuth / MCP-authorization bridge (test-data/ref-oauth.json.gz).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefOAuth < Minitest::Test
  O = AtlasPca::OAuth
  S = Ref.method(:snake)
  CASES = Ref.load('oauth')
  FNS = {
    'resourceIdentifierProblem' => ->(u) { O.resource_identifier_problem(u) },
    'prmPathForResource' => ->(u) { O.prm_path_for_resource(u) },
    'prmUrlForResource' => ->(u) { O.prm_url_for_resource(u) },
    'protectedResourceMetadata' => ->(o) { O.protected_resource_metadata(S.(o)) },
    'oauthDiscoveryHandler' => ->(o) { O.oauth_discovery_handler(S.(o)) },
    'parseProtectedResourceMetadata' => ->(d, p = nil) { O.parse_protected_resource_metadata(d, p && S.(p)) },
    'wwwAuthenticate' => ->(u, w = nil) { O.www_authenticate(u, w && S.(w)) },
    'mcpUnauthorized' => ->(u, w = nil) { O.mcp_unauthorized(u, w && S.(w)) },
    'upgradeUnauthorizedChallenge' => ->(r, u, w = nil) { O.upgrade_unauthorized_challenge(r, u, w && S.(w)) },
    'checkResourceIndicator' => ->(r, a) { O.check_resource_indicator(r, a) },
    'checkTokenAudience' => ->(r, a) { O.check_token_audience(r, a) },
    'buildPcaGrantDetail' => ->(o) { O.build_pca_grant_detail(S.(o)) },
    'pcaGrantRequestParam' => ->(d) { O.pca_grant_request_param(d) },
    'authorizePcaGrantToken' => ->(o) { O.authorize_pca_grant_token(S.(o)) },
    'oauthScopeForAction' => ->(a, o) { O.oauth_scope_for_action(a, S.(o)) }
  }.freeze

  def test_every_fn_is_mapped
    assert_empty CASES.keys - FNS.keys
  end

  FNS.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, CASES[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 840, CASES.values.sum(&:length), 'oauth'
  end

end
