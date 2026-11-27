# frozen_string_literal: true

# Replays the TS-reference oracle of the step-up fold, the core threshold hook and the full hybrid step-up verification
# (test-data/ref-pq-threshold-java-extra.json.gz). Needs OpenSSL with ML-DSA-65. hybridSign (random FROST nonces) is not replayed.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/pq_threshold'
require 'minitest/autorun'

class TestRefPqThresholdExtra < Minitest::Test
  T = AtlasPca::PqThreshold
  CASES = Ref.load('pq-threshold-java-extra')

  def test_fold_matches_the_reference
    Ref.run(self, CASES['fold'], ->(a, b) { T.fold_hybrid_step_up(a, b) })
  end

  def test_hook_matches_the_reference
    Ref.run(self, CASES['hook'], ->(opts, pcactn) { T.create_hybrid_threshold_verifier(opts).call({ 'pcactn' => pcactn, 'grant' => {}, 'nowEpoch' => 1_800_000_000_000 }) })
  end

  def test_step_up_matches_the_reference
    call = lambda do |su, opts|
      r = T.verify_hybrid_step_up(su, opts)
      { 'allow' => r['allow'], 'pq' => r['pq'] }
    end
    cmp = ->(got, out, _c) { Ref.canon(got) == Ref.canon({ 'allow' => out['allow'], 'pq' => out['pq'] }) }
    Ref.run(self, CASES['stepUp'], call, compare: cmp)
  end

  # the corpus is pinned: its fn set and every fn's case count (a fn the replay skips, or a changed corpus, fails here)
  def test_the_corpus_is_pinned_in_full
    assert_equal({ 'fold' => 15, 'hook' => 40, 'stepUp' => 28, 'hybridSign' => 17 }, CASES.transform_values(&:length))
  end

end
