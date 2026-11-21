# frozen_string_literal: true

# Replays the reference oracle of the action vocabulary migration shims (test-data/ref-actions-compat.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_compat'
require 'minitest/autorun'

class TestRefActionsCompat < Minitest::Test
  C = AtlasPca::ActionsCompat
  BY_FN = Ref.load('actions-compat')

  MAP = {
    'normalizeReversibility' => C.method(:normalize_reversibility),
    'legacyOperationsClass' => C.method(:legacy_operations_class),
    'maxRevOf' => C.method(:max_rev_of),
    'unitTagOf' => C.method(:unit_tag_of),
    'blastOfFloat' => C.method(:blast_of_float),
    'blastExactOfFloat' => C.method(:blast_exact_of_float),
    'fromCatalogSpec' => C.method(:from_catalog_spec),
    'fromCatalog' => C.method(:from_catalog)
  }.freeze

  def test_every_function_is_covered = assert_equal [], BY_FN.keys - MAP.keys

  MAP.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 133, BY_FN.values.sum(&:length), 'actions-compat'
  end

end
