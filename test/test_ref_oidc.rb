# frozen_string_literal: true

# Replays the TS-reference oracle of the OIDC bridge (test-data/ref-oidc.json.gz): discovery, ID-token verification across
# algorithms and key forms, the caching JWKS resolver and the principal mapping. Function-valued options travel as JSON
# specs: key {jwks: <set>} is a local JWK-Set resolver, key {resolver: {...}} a create_oidc_jwks, fetch {responses: [...]}
# a reply sequence (the last repeats); a {"$bytes"} key is an HMAC secret.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefOidc < Minitest::Test
  O = AtlasPca::Oidc
  CASES = Ref.load('oidc')

  def self.mk_fetch(spec, calls = nil)
    i = 0
    lambda do |url, *_|
      calls&.push(url)
      r = spec['responses'][[i, spec['responses'].length - 1].min]
      i += 1
      raise 'boom' if r['throws']

      { 'status' => r['status'], 'body' => r['body'], 'headers' => (r['headers'] || {}).transform_keys(&:downcase) }
    end
  end

  def self.resolver(spec) = O.create_oidc_jwks(Ref.snake(spec).merge('fetch' => mk_fetch(spec['fetch'])))

  def self.adapt(opts)
    return opts unless opts.is_a?(Hash)

    a = Ref.snake(opts)
    k = a['key']
    if k.is_a?(Hash)
      a['key'] = O.create_local_jwk_set(k['jwks']) if k.key?('jwks')
      a['key'] = resolver(k['resolver']) if k.key?('resolver')
    end
    a['fetch'] = mk_fetch(a['fetch']) if a['fetch'].is_a?(Hash)
    a
  end

  def self.pick(j) = %w[kty crv x y n e].select { |k| j.key?(k) }.to_h { |k| [k, j[k]] }
  def self.err_of(e) = e.is_a?(O::OidcVerificationError) && e.code == 'keys' ? 'keys' : 'other'

  SEQ = lambda do |s|
    clock = 0
    fetches = 0
    f = mk_fetch(s['fetch'])
    o = { 'jwks_uri' => s['jwksUri'] }.merge(Ref.snake(s['opts'] || {}))
    r = O.create_oidc_jwks(o.merge('fetch' => ->(u, *_) { fetches += 1; f.call(u) }, 'now' => -> { clock }))
    steps = s['steps'].map do |st|
      clock = st['atMs']
      { 'ok' => pick(r.call(st['header'])) }
    rescue StandardError => e
      { 'err' => err_of(e) }
    end
    { 'steps' => steps, 'fetches' => fetches }
  end

  FROM_ISSUER = lambda do |s|
    urls = []
    r = O.create_oidc_jwks_from_issuer(s['issuer'], Ref.snake(s['opts'] || {}).merge('fetch' => mk_fetch(s['fetch'], urls)))
    out = begin
      { 'ok' => pick(r.call(s['header'])) }
    rescue StandardError => e
      { 'err' => err_of(e) }
    end
    { 'out' => out, 'urls' => urls }
  end

  CALLS = lambda do |issuer, op|
    urls = []
    outcome = 'ok'
    begin
      O.discover_oidc(issuer, Ref.snake(op).merge('fetch' => mk_fetch(op['fetch'], urls)))
    rescue StandardError
      outcome = 'error'
    end
    { 'urls' => urls, 'outcome' => outcome }
  end

  FNS = {
    'constants' => lambda {
      { 'DEFAULT_ID_TOKEN_ALGS' => O::DEFAULT_ID_TOKEN_ALGS, 'DEFAULT_MAX_DISCOVERY_BYTES' => O::DEFAULT_MAX_DISCOVERY_BYTES,
        'DEFAULT_JWKS_TIMEOUT_MS' => O::DEFAULT_JWKS_TIMEOUT_MS, 'OIDC_SUBJECT_CAVEAT' => O::OIDC_SUBJECT_CAVEAT }
    },
    'verifyIdToken' => ->(t, o) { O.verify_id_token(t, adapt(o)) },
    'discoveryUrl' => ->(u) { O.discovery_url(u) },
    'discoverOidc' => ->(i, o) { O.discover_oidc(i, adapt(o)) },
    'discoverOidcCalls' => CALLS,
    'createOidcJwks' => SEQ,
    'createOidcJwksFromIssuer' => FROM_ISSUER,
    'oidcPrincipal' => ->(c, *p) { p.empty? ? O.oidc_principal(c) : O.oidc_principal(c, Ref.snake(p[0])) },
    'isOidcSubjectCaveat' => ->(c) { O.oidc_subject_caveat?(c) }
  }.freeze

  def test_every_fn_is_mapped
    assert_empty CASES.keys - FNS.keys
  end

  FNS.each { |fn, call| define_method("test_#{fn}") { Ref.run(self, CASES[fn], call) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 662, CASES.values.sum(&:length), 'oidc'
  end

end
