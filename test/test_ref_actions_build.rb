# frozen_string_literal: true

# Replays the reference oracle of pack build, signing and verification, source sync and the domain bindings
# (test-data/ref-actions-build-py.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_build'
require_relative '../lib/atlas_pca/actions_builtin'
require_relative '../lib/atlas_pca/actions_sync'
require 'minitest/autorun'

class TestRefActionsBuild < Minitest::Test
  A = AtlasPca::Actions
  B = AtlasPca::ActionsBuild
  BI = AtlasPca::ActionsBuiltin
  S = AtlasPca::ActionsSync
  BY_FN = Ref.load('actions-build-py')
  CORE = A::CORE_REGISTRY

  def self.opt(c) = ->(_d) { c }
  def self.sync(a, c) = S.sync_source(a['current'], a['imported'], a['specDigest'], a['now'], a['lock'], CORE, opt(c))

  MAP = {
    'buildArtifacts' => ->(ds, cfg, c) { B.build_artifacts(ds, cfg, CORE, opt(c)) },
    'toolActionMapOf' => ->(ds, t, a) { B.tool_action_map_of(ds).call(t, a) },
    'generateTypes' => B.method(:generate_types),
    'packConsistencyError' => ->(p) { B.pack_consistency_error(p, CORE) },
    'signPack' => ->(p, k, s) { B.sign_pack(p, k, s, CORE) },
    'verifyPack' => ->(p, k) { B.verify_signed_pack(p, k, CORE) },
    'packKeyOf' => B.method(:pack_key_of),
    'syncSource' => ->(a, c) { sync(a, c) },
    'syncText' => ->(a, c) { S.sync_text(sync(a, c)) },
    'domainVerbs' => BI.method(:domain_verbs),
    'domainRoles' => BI.method(:domain_roles)
  }.freeze

  def test_every_function_is_covered = assert_equal [], BY_FN.keys - MAP.keys

  MAP.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 183, BY_FN.values.sum(&:length), 'actions-build'
  end

end
