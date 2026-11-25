# frozen_string_literal: true

# Replays the TS-reference oracle of the retrieval filter core (test-data/ref-rag.json.gz): aclsFromMetadata, compilePolicy,
# principalFromPCActn and filterDocuments (OpenFGA closures, deny-overrides-permit, fail-closed drops, the decision digest).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/rag'
require 'minitest/autorun'

class TestRefRag < Minitest::Test
  R = AtlasPca::Rag
  BY_FN = Ref.load('rag')

  MAP = {
    'aclsFromMetadata' => ->(acl = nil, tags = nil) { R.acls_from_metadata(acl, tags) },
    'compilePolicy' => ->(p = nil) { R.compile_policy(p) },
    'principalFromPCActn' => ->(p = nil, o = nil) { R.principal_from_pcactn(p, o) },
    'filterDocuments' => ->(pr = nil, docs = nil, pol = nil) { R.filter_documents(pr, docs, pol) }
  }.freeze

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) } }

  Retr = Struct.new(:docs) do
    def retrieve(_query, _k = nil) = docs
  end

  def test_with_pca_filter_fails_closed_without_a_usable_policy_and_keeps_the_decision
    f = R.with_pca_filter(Retr.new([{ 'id' => 'a' }, { 'id' => 'b' }]), { 'id' => 'u' }, nil)
    assert_nil f.last_decision
    assert_equal [], f.retrieve('q', 5)
    d = f.last_decision
    assert_equal [2, true, ['a', 'b']], [d['considered'], d['policyIncomplete'], d['droppedIds']]
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 397, BY_FN.values.sum(&:length), 'rag'
  end

end
