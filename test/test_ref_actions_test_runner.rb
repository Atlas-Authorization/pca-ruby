# frozen_string_literal: true

# Replays the reference oracle of the example and property runner of the action packs (test-data/ref-actions-test-runner.json.gz).
# The YAML form of the digest property runs over the value form of the document (no YAML emitter in this module).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_test_runner'
require 'minitest/autorun'

class TestRefActionsTestRunner < Minitest::Test
  TR = AtlasPca::ActionsTestRunner
  BY_FN = Ref.load('actions-test-runner')
  CORE = AtlasPca::Actions::CORE_REGISTRY

  MAP = {
    'decideExample' => ->(d, ex, defs) { TR.decide_example(d, ex, CORE, defs) },
    'runDefTests' => ->(defs, limit = nil) { TR.run_def_tests(defs, CORE, limit) },
    'testText' => TR.method(:test_text)
  }.freeze

  def test_every_function_is_covered = assert_equal [], BY_FN.keys - MAP.keys

  MAP.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 47, BY_FN.values.sum(&:length), 'actions-test-runner'
  end

end
