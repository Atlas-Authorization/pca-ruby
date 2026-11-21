# frozen_string_literal: true

# Replays the TS-reference oracle of the dispute evidence replay (test-data/ref-evidence-bundle-py.json.gz): findings, summary and the
# report digest over the chargeback walkthrough and its tampered / re-trusted variants. `trust.verifiers` members are constant verdicts
# the native ports return.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/evidence_verify'
require 'minitest/autorun'

class TestRefEvidenceBundle < Minitest::Test
  BY_FN = Ref.load('evidence-bundle-py')

  def self.verify(bundle, trust = nil)
    if trust.is_a?(Hash) && !trust['verifiers'].nil?
      trust = trust.merge('verifiers' => trust['verifiers'].to_h { |k, v| [k, ->(_a, _b) { v }] })
    end
    AtlasPca::EvidenceVerify.verify_evidence_bundle(bundle, trust)
  end

  def test_every_function_is_covered
    assert_equal ['verifyEvidenceBundle'], BY_FN.keys
  end

  def test_evidence_bundle_matches_reference
    ran = Ref.run(self, BY_FN.fetch('verifyEvidenceBundle'), ->(bundle, trust = nil) { self.class.verify(bundle, trust) })
    assert_equal 204, ran
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 204, BY_FN.values.sum(&:length), 'evidence-bundle-py'
  end

end
