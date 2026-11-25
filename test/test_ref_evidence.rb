# frozen_string_literal: true

# Replays the TS-reference oracle of the dispute evidence bundle (test-data/ref-evidence.json.gz): shape validation, normal form,
# commitments-only form, digest, reference and anchor leaf, the accumulator cap reader and the trust-input validators. The full
# replay (verifyEvidenceBundle) is not ported, so its corpus is not replayed.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/evidence'
require 'minitest/autorun'

class TestRefEvidence < Minitest::Test
  T = AtlasPca::Evidence
  BY_FN = Ref.load('evidence')

  MAP = {
    'bundleShapeError' => ->(*a) { T.bundle_shape_error(*a) },
    'normalizeBundle' => ->(*a) { T.normalize_bundle(*a) },
    'buildEvidenceBundle' => ->(*a) { T.build_evidence_bundle(*a) },
    'commitmentForm' => ->(*a) { T.commitment_form(*a) },
    'evidenceDigest' => ->(*a) { T.evidence_digest(*a) },
    'evidenceRef' => ->(*a) { T.evidence_ref(*a) },
    'evidenceAnchorCommit' => ->(*a) { T.evidence_anchor_commit(*a) },
    'anchorCommit' => ->(*a) { T.anchor_commit(*a) },
    'capOf' => ->(*a) { T.cap_of(*a) },
    'principalsTrustError' => ->(*a) { T.principals_trust_error(*a) },
    'accTrustError' => ->(*a) { T.acc_trust_error(*a) },
    'consts' => lambda {
      { 'EVIDENCE_DOMAIN' => T::EVIDENCE_DOMAIN, 'EVIDENCE_REPORT_DOMAIN' => T::EVIDENCE_REPORT_DOMAIN,
        'EVIDENCE_CONTENT_TYPE' => T::EVIDENCE_CONTENT_TYPE }
    }
  }.freeze

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1772, BY_FN.values.sum(&:length), 'evidence'
  end

end
