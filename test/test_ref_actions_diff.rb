# frozen_string_literal: true

# Replays the reference oracle of id patterns, effective profiles, structural param rules and semantic diffs (test-data/ref-actions-diff.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_diff'
require 'minitest/autorun'

class TestRefActionsDiff < Minitest::Test
  A = AtlasPca::Actions
  E = AtlasPca::ActionsEffective
  ID = AtlasPca::ActionsIdPattern
  D = AtlasPca::ActionsDiff
  BY_FN = Ref.load('actions-diff')
  CORE = A::CORE_REGISTRY

  MAP = {
    'idMatches' => ID.method(:id_matches),
    'idPatternContains' => ID.method(:id_pattern_contains),
    'join' => A.method(:join),
    'leq' => A.method(:leq),
    'profileEq' => E.method(:profile_eq),
    'effective' => ->(d, c) { E.effective_with(d, CORE, ->(_d) { c }) },
    'hintTraits' => A.method(:hint_traits),
    'prulesViolations' => E.method(:prules_violations),
    'effWithTrait' => ->(d, t) { E.eff_with_trait(d, t, CORE) },
    'requiredPrulesViolated' => E.method(:required_prules_violated),
    'diffDefs' => ->(a, b, c = nil) { D.diff_defs(a, b, CORE, ->(_d) { c }) },
    'diffDefsAuthoring' => ->(a, b) { D.diff_defs_authoring(a, b, CORE) },
    'diffIsFree' => D.method(:diff_is_free),
    'diffPacks' => ->(a, b) { D.diff_packs(a, b, CORE) }
  }.freeze

  def test_every_function_is_covered = assert_equal [], BY_FN.keys - MAP.keys

  MAP.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1302, BY_FN.values.sum(&:length), 'actions-diff'
  end

end

# the version diff does not read key order as a change (a stored definition comes back with sorted keys); array order still counts
class TestActionsDiffKeyOrder < Minitest::Test
  D = AtlasPca::ActionsDiff

  def test_same_json_ignores_key_order_at_every_depth
    assert D.same_json({ 'a' => 1, 'b' => { 'x' => [1, 2], 'y' => 3 } }, { 'b' => { 'y' => 3, 'x' => [1, 2] }, 'a' => 1 })
  end

  def test_same_json_keeps_array_order_and_values
    refute D.same_json({ 'a' => [1, 2] }, { 'a' => [2, 1] })
    refute D.same_json({ 'a' => 1 }, { 'a' => 2 })
  end

  def test_sj_of_reversed_keys_is_equal
    assert_equal D.sj({ 'unit' => { 'k' => 1, 'z' => 2 } }, 'unit'), D.sj({ 'unit' => { 'z' => 2, 'k' => 1 } }, 'unit')
  end
end
