# frozen_string_literal: true

# Replays the TS-reference oracle of DPoP proofs, mTLS confirmation, the PCActn binding, replay stores and server nonces
# (test-data/ref-dpop.json.gz). Verify options arrive as JSON: seenJti is a list (a Set here), replayStore names a kind
# (memory with maxEntries / preload, or a store that always returns true / false / throws), nonceIssuer carries a base64url
# secret. Results compare as JS JSON (claims may hold a lone surrogate).
require_relative 'support/ref_oracle'
require 'minitest/autorun'
require 'set'

class TestRefDpop < Minitest::Test
  D = AtlasPca::Dpop
  CASES = Ref.load('dpop')

  Fixed = Struct.new(:result) do
    def add_if_absent(*) = result == :throws ? raise('boom') : result
  end

  class NoExpiry
    def initialize = @seen = Set.new
    def add_if_absent(k, *) = !!@seen.add?(k)
  end

  def self.store(s)
    case s['kind']
    when 'memory'
      st = s.key?('maxEntries') ? D::InMemoryReplayStore.new(max_entries: s['maxEntries']) : D::InMemoryReplayStore.new
      (s['preload'] || []).each { |k, e, n| st.add_if_absent(k, e, n) }
      st
    when 'true' then Fixed.new(true)
    when 'false' then Fixed.new(false)
    else Fixed.new(:throws)
    end
  end

  def self.issuer(n) = D::NonceIssuer.new(secret: Ref.b64d(n['secret']), ttl_sec: n['ttl'])

  # -> [options, seen Set or nil]
  def self.adapt(opts)
    o = Ref.snake(opts)
    seen = o.key?('seen_jti') ? (o['seen_jti'] = Set.new(o['seen_jti'])) : nil
    o['replay_store'] = store(o['replay_store']) if o.key?('replay_store')
    o['nonce_issuer'] = issuer(o['nonce_issuer']) if o.key?('nonce_issuer')
    [o, seen]
  end

  def self.with_seen(r, seen) = seen ? r.merge('seen' => seen.to_a) : r

  NONCE_OPS = lambda do |secret, ttl, ops|
    iss = D::NonceIssuer.new(secret: secret.nil? ? nil : Ref.b64d(secret), ttl_sec: ttl)
    issued = []
    ops.map do |op|
      if op['op'] == 'issue'
        (op.key?('now') ? iss.issue(op['now']) : iss.issue).tap { |n| issued << n }
      else
        n = op['nonce'].is_a?(Hash) && op['nonce'].key?('$issued') ? issued[op['nonce']['$issued']] : op['nonce']
        op.key?('now') ? iss.check(n, op['now']) : iss.check(n)
      end
    end
  end

  STORE_OPS = lambda do |max, ops|
    st = max.nil? ? D::InMemoryReplayStore.new : D::InMemoryReplayStore.new(max_entries: max)
    ops.map do |op|
      st.add_if_absent(op['key'], op['exp'], op['now'])
    rescue StandardError
      'throws'
    end
  end

  CONFORMANCE = lambda do |kind|
    D.run_replay_store_conformance(lambda {
      case kind
      when 'memory' then D::InMemoryReplayStore.new
      when 'alwaysTrue' then Fixed.new(true)
      when 'alwaysFalse' then Fixed.new(false)
      else NoExpiry.new
      end
    })
  end

  VERIFY = lambda do |proof, opts|
    o, seen = adapt(opts)
    with_seen(D.verify_dpop_proof(proof, o), seen)
  end

  CREATE_VERIFY = lambda do |input, vo|
    proof = D.create_dpop_proof(Ref.snake(input))
    base = { 'method' => input['method'], 'url' => input['url'], 'maxAgeSec' => 300, 'nowSec' => (input['iat'] || 1_800_000_000) + 1, 'seenJti' => [] }
    o, seen = adapt(base.merge(vo))
    with_seen(D.verify_dpop_proof(proof, o), seen)
  end

  ASSERT = lambda do |p, proof, opts|
    o, seen = adapt(opts)
    with_seen(D.assert_pca_dpop(p, proof, o), seen)
  end

  FNS = {
    'constants' => lambda {
      { 'allowedAlgs' => D::ALLOWED_ALGS, 'typ' => D::JWT_TYP, 'defaultMaxAgeSec' => D::DEFAULT_MAX_AGE_SEC, 'clockSkewSec' => D::CLOCK_SKEW_SEC,
        'maxProofBytes' => D::MAX_PROOF_BYTES, 'inMemoryMaxEntries' => D::INMEMORY_MAX_ENTRIES }
    },
    'jwkThumbprint' => ->(j, d = 'sha256') { D.jwk_thumbprint(j, d) },
    'dpopAlgForJwk' => ->(j) { D.alg_for_jwk(j) },
    'dpopAlgMatchesJwk' => ->(a, j) { D.alg_matches_jwk?(a, j) },
    'normalizeHtu' => ->(u) { D.normalize_htu(u) },
    'athFor' => ->(t) { D.ath_for(t) },
    'nonceIssuer' => NONCE_OPS,
    'replayStore' => STORE_OPS,
    'replayConformance' => CONFORMANCE,
    'createDpopProof' => ->(i) { D.create_dpop_proof(Ref.snake(i)) },
    'createThenVerify' => CREATE_VERIFY,
    'verifyDpopProof' => VERIFY,
    'mtlsCnf' => ->(c) { D.mtls_cnf(c) },
    'mtlsThumbprint' => ->(c) { D.mtls_thumbprint(c) },
    'assertMtlsBound' => ->(c, cnf) { D.assert_mtls_bound(c, cnf) },
    'leafHolderJwk' => ->(p) { D.leaf_holder_jwk(p) },
    'bindPcaToDpop' => ->(p) { D.bind_pca_to_dpop(p) },
    'assertPcaDpop' => ASSERT
  }.freeze

  JS_EQ = ->(g, o, _c) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(g))) == AtlasPca::Js.json(Ref.sort_keys(Ref.norm(o))) }

  # An absent max_age_sec means 300 s; a non-finite or non-number bound would disable the stale check, a non-finite clock the window.
  def test_absent_max_age_is_the_default_and_non_finite_bounds_are_refused
    seed = OpenSSL::Digest::SHA256.digest('dpop-non-finite')
    x = [OpenSSL::PKey.new_raw_private_key('ED25519', seed).raw_public_key].pack('m0').tr('+/', '-_').delete('=')
    url = 'https://rs.example/r'
    proof = D.create_dpop_proof('method' => 'GET', 'url' => url, 'iat' => 1_800_000_000, 'private_key' => seed,
                                'public_jwk' => { 'kty' => 'OKP', 'crv' => 'Ed25519', 'x' => x })
    code = lambda do |o|
      D.verify_dpop_proof(proof, { 'method' => 'GET', 'url' => url, 'require_replay_store' => false }.merge(o))
      'ok'
    rescue D::DpopVerificationError => e
      e.code
    end
    assert_equal 'ok', code.call('now_sec' => 1_800_000_001)
    assert_equal 'iat_stale', code.call('now_sec' => 1_800_000_301)
    [Float::INFINITY, -Float::INFINITY, Float::NAN, '300', true].each do |v|
      assert_equal 'max_age', code.call('now_sec' => 1_800_000_001, 'max_age_sec' => v), v.inspect
      assert_equal 'now', code.call('now_sec' => v), v.inspect
    end
  end

  def test_every_fn_is_mapped
    assert_empty CASES.keys - FNS.keys
  end

  FNS.each { |fn, call| define_method("test_#{fn}") { Ref.run(self, CASES[fn], call, compare: JS_EQ) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1040, CASES.values.sum(&:length), 'dpop'
  end
end

# The RSA DPoP cases: ref-dpop-rsa.json.gz, generated by CI (never committed), same case format and function table.
class TestRefDpopRsa < Minitest::Test
  RSA_PATH = ENV['PCA_DPOP_RSA_CORPUS'] || File.join(Ref::DATA, 'ref-dpop-rsa.json.gz')
  RSA_CASES = File.exist?(RSA_PATH) ? Ref.load('dpop-rsa', path: RSA_PATH) : nil

  def test_rsa_corpus
    unless RSA_CASES
      msg = "ref-dpop-rsa.json.gz not found at #{RSA_PATH} (generate with .github/scripts/dpop-rsa-corpus.sh or set PCA_DPOP_RSA_CORPUS)"
      flunk msg if %w[true 1].include?(ENV['CI'])
      skip msg
    end
    assert_empty RSA_CASES.keys - TestRefDpop::FNS.keys
    RSA_CASES.each { |fn, cases| Ref.run(self, cases, TestRefDpop::FNS[fn], compare: TestRefDpop::JS_EQ) }
  end
end
