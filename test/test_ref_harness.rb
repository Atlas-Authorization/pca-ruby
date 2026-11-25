# frozen_string_literal: true

# Replays the TS-reference oracle of the attested orchestration harness (test-data/ref-harness.json.gz): plan inclusion, taint
# fold, trust budget, signing, the mediator measurement and the allowlisting verifier.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/harness'
require 'minitest/autorun'
require 'digest'

class TestRefHarness < Minitest::Test
  H = AtlasPca::Harness
  BY_FN = Ref.load('harness')

  def self.scenario(spec)
    op = spec['opts']
    t = 1_800_000_000_000
    k = 0
    nonce = lambda do
      n = "n#{k}"
      k += 1
      n
    end
    begin
      h = H::Instance.new(grant: op['grant'], chain: op['chain'], agent_secret: Digest::SHA256.digest("atlas-pca-conformance/#{op['label']}"),
                          plan: op['plan'], audience: op['audience'], budget: op['budget'], policy: op['policy'], base_risk: op['baseRisk'],
                          now: -> { t }, ttl_ms: op['ttlMs'], measurement_manifest: op['manifest'], nonce: nonce, attestation: op['attestation'])
    rescue StandardError # a refused construction is the reference's {$err}
      return { '$err' => true }
    end
    outs = spec['steps'].map do |st|
      if st['op'] == 'now'
        t = st['t']
        next nil
      end
      orc = st['oracle']
      h.step(lambda do
        raise orc['msg'] if orc['kind'] == 'throw'

        orc['kind'] == 'bad' ? orc['v'] : orc['c']
      end)
    end
    { 'steps' => outs, 'budget' => h.budget, 'counter' => h.counter, 'planRoot' => h.plan_root, 'measurement' => h.harness_measurement }
  end

  MAP = {
    'consts' => -> { { 'HARNESS_VERSION' => H::HARNESS_VERSION, 'HARNESS_MODEL_ID' => H::HARNESS_MODEL_ID, 'ENFORCED_CHECKS' => H::ENFORCED_CHECKS } },
    'computeHarnessMeasurement' => ->(v, e, p) { H.compute_harness_measurement(v, e, p) },
    'harnessAttest' => ->(cfg, ctx) { H.create_harness_attestation_verifier(cfg).call(ctx) },
    'harness' => ->(s) { scenario(s) }
  }.freeze

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  # JSON cannot carry an undefined argument: that case reaches Ruby as null, which the reference never saw
  MAP.each_key do |fn|
    define_method("test_#{fn}") do
      Ref.run(self, BY_FN[fn], MAP[fn], skip: ->(c) { c['name'].start_with?('undefined-checks') })
    end
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 824, BY_FN.values.sum(&:length), 'harness'
  end

end
