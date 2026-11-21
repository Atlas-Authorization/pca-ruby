# frozen_string_literal: true

# Differential oracle: AtlasPca::Fetch (with_pca / create_pca_fetch_guard) against the vectors generated from the TypeScript
# reference (@atlasauth/pca-fetch): the construction guards and the pre-verification refusals. Compared by shape: the core
# verifier's reason text and challenge string are its own.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/fetch'
require 'minitest/autorun'

class TestRefFetch < Minitest::Test
  F = AtlasPca::Fetch
  BY_FN = Ref.load('fetch')
  AUD = 'rs_fetch'

  OK_HANDLER = ->(_req, _ctx) { { 'status' => 200, 'headers' => {}, 'body' => 'ok' } }
  NIL_RESOLVE = ->(_ref) {}

  def self.construct(kind)
    case kind
    when 'ok' then F.with_pca(OK_HANDLER, audience: AUD, resolve_grant: NIL_RESOLVE, insecure_allow_unbound_operation: true)
    when 'noaudience' then F.with_pca(OK_HANDLER, audience: '', resolve_grant: NIL_RESOLVE, insecure_allow_unbound_operation: true)
    when 'nooperation' then F.with_pca(OK_HANDLER, audience: AUD, resolve_grant: NIL_RESOLVE)
    else raise ArgumentError, 'unknown kind'
    end
    { 'built' => true }
  end

  def self.request(spec)
    ran = []
    resolve = lambda do |_ref|
      raise 'store down' if spec['resolve'] == 'throws'

      nil
    end
    handler = lambda do |_req, _ctx|
      ran << true
      { 'status' => 200, 'headers' => {}, 'body' => '{"ok":true}' }
    end
    guarded = F.with_pca(handler, audience: AUD, resolve_grant: resolve, insecure_allow_unbound_operation: true)
    res = guarded.call({ 'method' => 'POST', 'url' => 'http://localhost/refunds', 'headers' => spec['headers'] || {}, 'body' => spec['body'] })
    body = begin
      JSON.parse(res['body'])
    rescue JSON::ParserError
      nil
    end
    www = res['headers']['WWW-Authenticate']
    { 'status' => res['status'], 'handlerRan' => !ran.empty?, 'decision' => body.is_a?(Hash) ? body['decision'] : nil,
      'challenge' => res['status'] == 401 ? (!www.nil? && www.start_with?('PCA realm="')) : nil,
      'contentType' => res['headers']['content-type'], 'bodyKeys' => body.is_a?(Hash) ? body.keys.sort : nil,
      'errorIsString' => body.is_a?(Hash) && body['error'].is_a?(String) }
  end

  MAP = { 'constructScenario' => ->(k) { construct(k) }, 'requestScenario' => ->(s) { request(s) } }.freeze

  def test_corpus_is_the_full_oracle
    assert_equal 59, BY_FN.values.sum(&:length)
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each do |fn, call|
    define_method("test_matches_the_reference_#{fn}") { assert_equal BY_FN[fn].length, Ref.run(self, BY_FN[fn], call) }
  end
end
