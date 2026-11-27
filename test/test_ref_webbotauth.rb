# frozen_string_literal: true

# Replays the TS-reference oracle of Web Bot Auth (RFC 9421 message signatures, signed key directory, Content-Digest, PCA proof
# binding; test-data/ref-webbotauth.json.gz). Signing keys derive from the corpus seed labels.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/webbotauth'
require 'minitest/autorun'

class TestRefWebbotauth < Minitest::Test
  W = AtlasPca::WebBotAuth
  CASES = Ref.load('webbotauth')
  # the RFC 9421 appendix B.1.4 published test key
  RFC_SEED = 'n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU'

  def self.key(k)
    s = k['secretKey']
    AtlasPca::KeyPair.new(Ref.b64d(s.is_a?(Hash) ? RFC_SEED : s))
  end

  def self.with_key(x) = x.is_a?(Hash) && x['key'].is_a?(Hash) ? x.merge('key' => key(x['key'])) : x

  # a resolver whose answer is the spec's value for the key id; {"$throw"} makes it raise
  def self.resolver(spec)
    lambda do |kid|
      v = spec[kid]
      raise 'resolver down' if v.is_a?(Hash) && v['$throw']

      v
    end
  end

  class Fixed
    def initialize(result) = @r = result

    def claim(_key, _expires, _now)
      raise 'cache down' if @r == 'throw'

      @r
    end
  end

  def self.cache(spec)
    case spec
    when 'always' then Fixed.new(true)
    when 'never' then Fixed.new(false)
    when 'throw' then Fixed.new('throw')
    when 'memory' then W.memory_replay_cache
    when /\Amemory:(.*)\z/ then W.memory_replay_cache(Regexp.last_match(1).to_i)
    else spec
    end
  end

  def self.opts(op)
    o = op.dup
    o['resolveKey'] = resolver(o['resolveKey']) if o['resolveKey'].is_a?(Hash)
    o['maxLifetimeSec'] = Float::INFINITY if o['maxLifetimeSec'] == 'Infinity'
    o['replayCache'] = cache(o['replayCache']) if o.key?('replayCache')
    o
  end

  def self.norm_reason(r)
    r = r.dup
    r['reason'] = r['reason'].sub(/\A(invalid PCActn in PCA-Action): .*\z/m, '\1') if r['reason'].is_a?(String)
    r
  end

  def self.verify(req, op, times = 1)
    vo = opts(op)
    rs = Array.new(times) { norm_reason(W.verify_signed_request(req, vo)) }
    times == 1 ? rs[0] : rs
  end

  def self.constants
    { 'tag' => W::WEB_BOT_AUTH_TAG, 'alg' => W::WEB_BOT_AUTH_ALG, 'path' => W::WELL_KNOWN_DIRECTORY_PATH, 'ct' => W::DIRECTORY_CONTENT_TYPE,
      'label' => W::DEFAULT_SIGNATURE_LABEL, 'exp' => W::DEFAULT_EXPIRES_SEC, 'agent' => W::SIGNATURE_AGENT_HEADER, 'pca' => W::PCA_HEADER,
      'comp' => W::PCA_PROOF_COMPONENT, 'cd' => W::CONTENT_DIGEST_HEADER, 'algs' => W::CONTENT_DIGEST_ALGS, 'dtag' => W::DIRECTORY_SIGNATURE_TAG }
  end

  def self.cache_run(mx, ops)
    c = W.memory_replay_cache(mx)
    ops.map do |k, e, n|
      c.claim(k, e, n)
    rescue StandardError
      'throw' # the reference records a throwing claim as "throw"
    end
  end

  Res = Struct.new(:status, :headers, :body) do
    def text = body
  end

  class Hdrs
    def initialize(h) = @h = h
    def get(name) = @h[name.downcase]
  end

  def self.fetch_run(url, spec)
    called = []
    res = spec['response']
    fetch = lambda do |u, init|
      called << { 'url' => u, 'headers' => init['headers'], 'redirect' => init['redirect'] }
      raise 'network down' if res == 'throw'

      Res.new(res['status'], Hdrs.new(res['headers'] || {}), res['body'])
    end
    d = W.fetch_key_directory(url, (spec['options'] || {}).merge('fetch' => fetch))
    { 'directory' => d, 'called' => called[0] }
  rescue StandardError => e
    msg = e.message
    msg = msg.start_with?('directory ', 'Invalid URL') ? msg.sub(/\A(directory signature): .*\z/m, '\1') : 'other'
    { 'error' => true, 'message' => msg, 'called' => called[0] }
  end

  def self.sd_input(i) = i.merge('keys' => i['keys'].map { |k| key(k) })

  MAP = {
    'constants' => -> { constants },
    'jwkThumbprint' => ->(k) { W.jwk_thumbprint(k) },
    'signRequest' => ->(i) { W.sign_request(with_key(i)) },
    'verifySignedRequest' => ->(req, op, times = 1) { verify(req, op, times) },
    'buildKeyDirectory' => ->(k) { W.build_key_directory(k) },
    'resolveFromDirectory' => ->(d, k) { W.resolve_from_directory(d, k) },
    'directoryHandler' => ->(keys, paths) { h = W.directory_handler(keys); paths.map { |p| h.call(p) } },
    'memoryReplayCache' => ->(mx, ops) { cache_run(mx, ops) },
    'proofHeaders' => ->(p) { W.proof_headers(p) },
    'decodeProofHeader' => ->(v) { W.decode_proof_header(v) },
    'signRequestWithProof' => ->(i) { W.sign_request_with_proof(with_key(i)) },
    'verifySignedRequestWithProof' => ->(req, op) { norm_reason(W.verify_signed_request_with_proof(req, opts(op))) },
    'contentDigestBytes' => ->(b, a) { W.content_digest_bytes(b, a) },
    'contentDigestHeader' => ->(*a) { W.content_digest_header(*a) },
    'verifyContentDigest' => ->(*a) { W.verify_content_digest(*a) },
    'parseContentDigest' => ->(v) { W.parse_content_digest(v) },
    'parseKeyDirectory' => ->(t) { W.parse_key_directory(t) },
    'signDirectoryResponse' => ->(i) { W.sign_directory_response(sd_input(i)) },
    'verifyDirectoryResponse' => ->(i) { W.verify_directory_response(i) },
    'fetchKeyDirectory' => ->(url, spec) { fetch_run(url, spec) }
  }.freeze

  # the language's own error text after the marker is not comparable
  def self.fail_closed(v)
    case v
    when String then (i = v.index('(fail closed): ')) ? v[0, i + 15] : v
    when Hash then v.transform_values { |x| fail_closed(x) }
    when Array then v.map { |x| fail_closed(x) }
    else v
    end
  end

  # raw bytes are binary Strings; the harness would read a short ASCII one as text
  def self.bin(v)
    case v
    when Hash then v.transform_values { |x| bin(x) }
    when Array then v.map { |x| bin(x) }
    when String then v.encoding == Encoding::BINARY ? { '$bytes' => Ref.b64e(v) } : v
    else v
    end
  end

  CMP = ->(got, out, _c) { Ref.canon(fail_closed(Ref.norm(bin(got)))) == Ref.canon(fail_closed(out)) }

  def test_corpus_is_the_full_oracle
    assert_equal [], CASES.keys - MAP.keys
    assert_equal [], MAP.keys - CASES.keys
  end

  MAP.each do |fn, call|
    define_method("test_matches_the_reference_#{fn}") do
      Ref.run(self, CASES[fn], call, compare: CMP)
    end
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1253, CASES.values.sum(&:length), 'webbotauth'
  end

end
