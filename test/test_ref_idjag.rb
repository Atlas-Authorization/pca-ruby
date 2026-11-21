# frozen_string_literal: true

# Replays the TS-reference oracles of the ID-JAG bridge: test-data/ref-idjag.json.gz (verification, principal / capability
# projection, caveat guards, the XAA request shapes) and test-data/ref-idjag-suite-java.json.gz (a post-quantum / hybrid
# root hop). Function-valued options travel as JSON specs: consumeJti {mode: fresh|seen|throw|truthy}, key {jwks: <set>},
# fetch {responses: [...]}.
require_relative 'support/ref_oracle'
require 'minitest/autorun'
require 'digest'

class TestRefIdJag < Minitest::Test
  J = AtlasPca::IdJag
  CASES = Ref.load('idjag')
  SUITE = Ref.load('idjag-suite-java')

  def self.mk_fetch(spec)
    i = 0
    lambda do |*_|
      r = spec['responses'][[i, spec['responses'].length - 1].min]
      i += 1
      raise 'boom' if r['throws']

      { 'status' => r['status'], 'body' => r['body'], 'headers' => (r['headers'] || {}).transform_keys(&:downcase) }
    end
  end

  def self.adapt(opts)
    return opts unless opts.is_a?(Hash)

    a = Ref.snake(opts)
    cj = a['consume_jti']
    if cj.is_a?(Hash) && cj.key?('mode')
      a['consume_jti'] = lambda do |*_|
        raise 'store down' if cj['mode'] == 'throw'

        { 'fresh' => true, 'truthy' => 1 }.fetch(cj['mode'], false)
      end
    end
    a['key'] = AtlasPca::Oidc.create_local_jwk_set(a['key']['jwks']) if a['key'].is_a?(Hash) && a['key'].key?('jwks')
    a['fetch'] = mk_fetch(a['fetch']) if a['fetch'].is_a?(Hash)
    a
  end

  def self.seed(label) = Digest::SHA256.digest("atlas-pca-conformance/#{label}")
  def self.blen(v) = v.is_a?(String) ? Ref.b64d(v).bytesize : nil

  SUITE_FN = lambda do |grant, label, alg, pq, pub = nil|
    sk = seed(label)
    principal_public = pub || AtlasPca::KeyPair.new(sk).public
    suite = { 'alg' => alg }
    suite['pq'] = AtlasPca::PqKeyPair.from_seed(alg.end_with?('ml-dsa-87') ? 'ML-DSA-87' : 'ML-DSA-65', Ref.b64d(pq)) unless alg == 'ed25519'
    r = J.id_jag_to_capability(grant, { 'principal_secret' => sk, 'principal_public' => principal_public,
                                        'holder' => AtlasPca::KeyPair.new(seed('idjag/holder')).public, 'suite' => suite })
    cap = r['capability']
    pins = cap.key?('pq_pk') ? { principal_public => cap['pq_pk'] } : nil
    _reason, ok = AtlasPca.verify_chain([cap], principal_public, true, nil, pins)
    { 'capability' => cap.except('sig', 'pq_sig'), 'sig_len' => blen(cap['sig']), 'pq_sig_len' => blen(cap['pq_sig']),
      'principal' => r['principal'], 'scopes' => r['scopes'], 'ok' => ok == true }
  end

  FNS = {
    'verifyIdJag' => ->(t, o) { J.verify_id_jag(t, adapt(o)) },
    'idJagToPcaPrincipal' => ->(g, *o) { o.empty? ? J.id_jag_to_pca_principal(g) : J.id_jag_to_pca_principal(g, Ref.snake(o[0])) },
    'idJagToCapability' => ->(g, o) { J.id_jag_to_capability(g, Ref.snake(o)) },
    'isIdJagAuthorityCaveat' => ->(c = nil) { J.id_jag_authority_caveat?(c) },
    'isIdJagProvenanceCaveat' => ->(c = nil) { J.id_jag_provenance_caveat?(c) },
    'readIdJagAuthority' => ->(c) { J.read_id_jag_authority(c) },
    'readIdJagProvenance' => ->(c) { J.read_id_jag_provenance(c) },
    'tokenExchangeRequest' => ->(o) { J.token_exchange_request(Ref.snake(o)) },
    'jwtBearerAssertion' => ->(o) { J.jwt_bearer_assertion(Ref.snake(o)) }
  }.freeze

  JS_EQ = ->(g, o, _c) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(g))) == AtlasPca::Js.json(Ref.sort_keys(Ref.norm(o))) }

  def test_every_fn_is_mapped
    assert_empty CASES.keys - FNS.keys
    assert_equal ['idJagToCapabilitySuite'], SUITE.keys
  end

  FNS.each { |fn, call| define_method("test_#{fn}") { Ref.run(self, CASES[fn], call, compare: JS_EQ) } }

  def test_idJagToCapabilitySuite
    Ref.run(self, SUITE['idJagToCapabilitySuite'], SUITE_FN)
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 444, CASES.values.sum(&:length), 'idjag'
    assert_equal 13, SUITE.values.sum(&:length), 'idjag-suite-java'
  end

end
