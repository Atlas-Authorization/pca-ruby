# frozen_string_literal: true

# Replays the TS-reference oracle of the evidence signed statement (test-data/ref-evidence-statement.json.gz): the COSE Sign1 over the
# bundle reference, Ed25519, byte for byte. The signing key is sha256("atlas-pca-conformance/" + label).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/evidence'
require 'minitest/autorun'

class TestRefEvidenceStatement < Minitest::Test
  BY_FN = Ref.load('evidence-statement')

  def self.statement(bundle, spec)
    key = Digest::SHA256.digest("atlas-pca-conformance/#{spec['label']}")
    bytes = AtlasPca::Evidence.evidence_signed_statement(bundle, spec['alg'], key, spec['issuer'], spec['subject'])
    { '$bytes' => Ref.b64e(bytes) }
  end

  def test_signed_statement
    Ref.run(self, BY_FN['evidenceSignedStatement'], ->(b, spec) { self.class.statement(b, spec) })
  end

  # the corpus is pinned: its fn set and every fn's case count (a fn the replay skips, or a changed corpus, fails here)
  def test_the_corpus_is_pinned_in_full
    assert_equal({ 'evidenceSignedStatement' => 16 }, BY_FN.transform_values(&:length))
  end

end
