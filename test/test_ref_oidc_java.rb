# frozen_string_literal: true

# Replays the second (deterministic-key) TS-reference oracle of the OIDC bridge (test-data/ref-oidc-java.json.gz): ID-token
# verification over a local JWK Set (opts.jwks), discovery with an injected reply, the principal mapping and JWKS-resolver
# scenarios driven by a clock and a reply queue.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefOidcJava < Minitest::Test
  O = AtlasPca::Oidc
  CASES = Ref.load('oidc-java')

  VERIFY = lambda do |token, opts|
    return O.verify_id_token(token, nil) if opts.nil?

    o = Ref.snake(opts)
    jwks = o.delete('jwks')
    o['key'] = O.create_local_jwk_set(jwks) if opts.key?('jwks')
    O.verify_id_token(token, o)
  end

  DISCOVER = lambda do |issuer, opts, resp|
    fetch = lambda do |*_|
      raise 'net' if resp['throws']

      { 'status' => resp['status'], 'body' => resp['text'], 'headers' => resp['contentLength'].nil? ? {} : { 'content-length' => resp['contentLength'] } }
    end
    O.discover_oidc(issuer, Ref.snake(opts).merge('fetch' => fetch))
  end

  SCENARIO = lambda do |opts, steps|
    cur = 0
    fetches = 0
    queue = nil
    fetch = lambda do |*_|
      fetches += 1
      raise 'net' if queue.nil? || queue == 'throw'

      { 'status' => queue['status'], 'body' => queue['text'], 'headers' => {} }
    end
    r = O.create_oidc_jwks({ 'jwks_uri' => 'https://idp.example.com/jwks' }.merge(Ref.snake(opts)).merge('fetch' => fetch, 'now' => -> { cur }))
    steps.map do |s|
      cur = s['t']
      queue = s['resp']
      begin
        r.call(s['header'])
        { 'fetches' => fetches, 'ok' => true }
      rescue StandardError => e
        { 'fetches' => fetches, 'ok' => false, 'code' => e.is_a?(O::OidcVerificationError) ? e.code : 'other' }
      end
    end
  end

  FNS = {
    'verifyIdToken' => VERIFY,
    'discoveryUrl' => ->(u) { O.discovery_url(u) },
    'discoverOidc' => DISCOVER,
    'oidcPrincipal' => ->(c, *p) { p.empty? ? O.oidc_principal(c) : O.oidc_principal(c, Ref.snake(p[0])) },
    'isOidcSubjectCaveat' => ->(c) { O.oidc_subject_caveat?(c) },
    'jwksScenario' => SCENARIO
  }.freeze

  def test_every_fn_is_mapped
    assert_empty CASES.keys - FNS.keys
  end

  FNS.each { |fn, call| define_method("test_#{fn}") { Ref.run(self, CASES[fn], call) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 943, CASES.values.sum(&:length), 'oidc-java'
  end

end
