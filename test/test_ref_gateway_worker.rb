# frozen_string_literal: true

# Replays the TS-reference oracle of the gateway's Cloudflare Worker adapter (test-data/ref-gateway-worker.json.gz): decision, the
# strip of inbound x-pca-* headers before the upstream, the deny JSON and the forged-header 400, over injected next / respond.
require_relative 'support/ref_oracle'
require_relative 'test_ref_gateway'
require 'minitest/autorun'

class TestRefGatewayWorker < Minitest::Test
  G = AtlasPca::Gateway
  BY_FN = Ref.load('gateway-worker')

  def self.view(r)
    { 'method' => r['method'], 'url' => r['url'], 'headers' => r['headers'].to_h { |k, v| [k.downcase, v] }.sort.to_h }
  end

  def self.worker(spec)
    ev = spec['events'][0]
    rewrite = case ev['rewrite']
              when 'null' then nil
              when 'custom'
                lambda { |r, drop|
                  r.merge('headers' => r['headers'].reject { |k, _| drop.include?(k.downcase) }.merge('x-rewritten' => drop.join(',')))
                }
              else :default
              end
    w = G.cloudflare_worker(TestRefGateway.build(spec), nxt: ->(r) { { 'forwarded' => view(r) } }, rewrite_request: rewrite,
                                                          respond: ->(body, init) { { 'status' => init['status'], 'headers' => init['headers'], 'body' => JSON.parse(body) } })
    TestRefGateway.mask(w.call({ 'method' => ev['method'], 'url' => ev['url'], 'headers' => ev['headers'] }))
  rescue TypeError, ArgumentError => e
    { 'create' => e.message }
  end

  def test_worker_scenario
    ran = Ref.run(self, BY_FN['workerScenario'], ->(s) { worker(s) }, compare: TestRefGateway::CMP)
    assert_equal BY_FN['workerScenario'].length, ran
  end

  # the corpus is pinned: its fn set and every fn's case count (a fn the replay skips, or a changed corpus, fails here)
  def test_the_corpus_is_pinned_in_full
    assert_equal({ 'workerScenario' => 22 }, BY_FN.transform_values(&:length))
  end

end
