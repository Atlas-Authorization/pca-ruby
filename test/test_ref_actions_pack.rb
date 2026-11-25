# frozen_string_literal: true

# Replays the reference oracle of pack building, sharding, upgrade verification and the pack statement payload
# (test-data/ref-actions-pack.json.gz), plus the rule 22 engine object.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_pack'
require 'minitest/autorun'

class TestRefActionsPack < Minitest::Test
  P = AtlasPca::ActionsPack
  BY_FN = Ref.load('actions-pack')
  NO_ATTEST = ->(_d) { false }

  MAP = {
    'buildPack' => lambda { |a, secret|
      P.build_pack(a['ns'], a['version'], a['stability'], a['defs'], a['source'], a['kid'], secret, prev: a['prev'], shard: a['shard'],
                                                                                                    attestation_verified: NO_ATTEST)
    },
    'shardDefs' => ->(defs, max = nil) { max.nil? ? P.shard_defs(defs) : P.shard_defs(defs, max) },
    'verifyUpgrade' => ->(prev, nxt, keys, ps, s) { P.verify_upgrade(prev, nxt, keys, ps, s, attestation_verified: NO_ATTEST) },
    'packStatementPayload' => ->(p) { AtlasPca::ActionsTransparency.pack_statement_payload(p) }
  }.freeze

  def test_every_function_is_covered = assert_equal [], BY_FN.keys - MAP.keys

  MAP.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  def test_rule22_engine_object_and_the_pack_verifier_alias
    e = AtlasPca::ActionsRegistry::RULE22_ENGINE
    assert_equal 'deny', e.decide({ 'verbs' => [] }, 'a.b', { 'caveats' => [], 'max_esc' => 0, 'preauth_esc' => 0 }, [])
    assert_kind_of String, e.schema_error(nil) # a document with no verbs is refused, never raised
    assert_equal AtlasPca::ActionsRegistry.verify_pack({}, [])['ok'], AtlasPca::ActionsRegistry.verify_action_pack({}, [])['ok']
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 86, BY_FN.values.sum(&:length), 'actions-pack'
  end

end
