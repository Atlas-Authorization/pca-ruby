# frozen_string_literal: true

# Replays the reference oracle of pack evolution records, registry signing and the whole-change check (test-data/ref-actions-evolve.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_evolve'
require 'minitest/autorun'

class TestRefActionsEvolve < Minitest::Test
  EV = AtlasPca::ActionsEvolve
  CORE = AtlasPca::Actions::CORE_REGISTRY
  BY_FN = Ref.load('actions-evolve')

  MAP = {
    'evolutionRecords' => ->(ns, p, n, c) { EV.evolution_records(ns, p, n, CORE, ->(_d) { c }) },
    'signEvolution' => EV.method(:sign_evolution),
    'evolutionError' => ->(ns, p, n, r, k, c) { EV.evolution_error(ns, p, n, r, k, CORE, ->(_d) { c }) }
  }.freeze

  def test_every_function_is_covered = assert_equal [], BY_FN.keys - MAP.keys

  MAP.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 154, BY_FN.values.sum(&:length), 'actions-evolve'
  end

end
