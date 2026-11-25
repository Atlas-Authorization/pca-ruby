# frozen_string_literal: true

# Replays the TS-reference oracle of step-up events and signed webhooks (test-data/ref-events.json.gz). A byte secret
# arrives as {"$bytes"} (a binary String here); a text secret is a UTF-8 String.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefEvents < Minitest::Test
  E = AtlasPca::Events
  CASES = Ref.load('events')
  SECRET = 'whsec_0123456789abcdef0123456789'

  class Throws
    def consume_once(*) = raise('down')
  end

  class Refuses
    def consume_once(*) = false
  end

  # The generator's reason mapping: engine-specific JSON syntax texts and canonicalize texts are compared by class only.
  def self.reason(v)
    return v unless v.is_a?(Hash) && v['ok'] == false && v['reason'].is_a?(String)
    return v.merge('reason' => '<canonicalize>') if v['reason'].start_with?('canonicalize:')
    return v if v['reason'].match?(/\A(a replay store|bad signature|replayed|replay store|parseEvent: )/)

    v.merge('reason' => '<json>')
  end

  SCENARIO = lambda do |spec|
    store = case spec['store']
            when 'throws' then Throws.new
            when 'refuses' then Refuses.new
            else AtlasPca::MemoryStateStore.new
            end
    spec['deliveries'].map do |d|
      opts = spec['noOpts'] ? nil : (spec['noReplay'] ? {} : { 'replay' => store }).merge(Ref.snake(d['opts']))
      secret = d.key?('secret') ? d['secret'] : SECRET
      reason(E.verify_delivery(secret, d['payload'], d['header'], opts))
    end
  end

  FNS = {
    'buildStepUpEvent' => ->(t, d) { E.build_step_up_event(t, d) },
    'serializeEvent' => ->(e) { E.serialize_event(e) },
    'parseEvent' => ->(s) { E.parse_event(s) },
    'signWebhook' => ->(s, p, o) { E.sign_webhook(s, p, o) },
    'verifyWebhook' => ->(s, p, h, o = nil) { E.verify_webhook(s, p, h, Ref.snake(o)) },
    'webhookHeaders' => ->(s, p, o) { E.webhook_headers(s, p, o) },
    'deliveryScenario' => SCENARIO,
    'minSecretBytes' => -> { E::MIN_SECRET_BYTES }
  }.freeze

  def test_every_fn_is_mapped
    assert_empty CASES.keys - FNS.keys
  end

  FNS.each { |fn, call| define_method("test_#{fn}") { Ref.run(self, CASES[fn], call) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1071, CASES.values.sum(&:length), 'events'
  end

end
