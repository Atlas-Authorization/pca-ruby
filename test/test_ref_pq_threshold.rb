# frozen_string_literal: true

# Replays the TS-reference oracle of the PQ threshold step-up verifier (signed FROST group descriptor, ML-DSA-65 quorum, hybrid
# verdict; test-data/ref-pq-threshold.json.gz). Needs OpenSSL with ML-DSA-65. The corpus carries seed labels, not secret keys.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/pq_threshold'
require 'minitest/autorun'

class TestRefPqThreshold < Minitest::Test
  T = AtlasPca::PqThreshold
  CASES = Ref.load('pq-threshold')

  def self.wire(v)
    case v
    when Hash then v.to_h { |k, x| [k, wire(x)] }
    when Array then v.map { |x| wire(x) }
    when Set then wire(v.to_a.sort)
    when String then v.encoding == Encoding::BINARY ? { '$bytes' => Ref.b64e(v) } : v
    else v
    end
  end

  MAP = {
    'signerSetCommitment' => ->(p) { T.signer_set_commitment(p) },
    'issueGroupDescriptor' => ->(a) { T.issue_group_descriptor(a['authoritySeed'], a['groupPublicKey'], a['t'], a['participants']) },
    'verifyGroupDescriptor' => ->(s, exp) { T.verify_group_descriptor(s, exp) },
    'normalizePqQuorumPool' => ->(pks) { T.normalize_pq_quorum_pool(pks).to_a.sort },
    'pqQuorumRepresentative' => ->(m) { T.pq_quorum_representative(m) },
    'verifyPqQuorum' => ->(block, msg, pool, pq_t) { T.verify_pq_quorum(block, msg, T.normalize_pq_quorum_pool(pool), pq_t) },
    'verifyHybridThreshold' => ->(action, art, opts) { T.verify_hybrid_threshold(action, art, opts) }
  }.freeze

  def test_corpus_is_covered
    assert_equal MAP.keys.sort, CASES.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}_matches_the_reference") { Ref.run(self, CASES[fn], ->(*a) { self.class.wire(MAP[fn].call(*a)) }) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 212, CASES.values.sum(&:length), 'pq-threshold'
  end

end
