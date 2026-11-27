# frozen_string_literal: true

# Replays the reference oracle of the starter templates (test-data/ref-actions-templates.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_templates'
require 'minitest/autorun'

class TestRefActionsTemplates < Minitest::Test
  T = AtlasPca::ActionsTemplates
  BY_FN = Ref.load('actions-templates')

  def self.meta(t) = t.nil? ? nil : { 'id' => t.id, 'title' => t.title, 'description' => t.description, 'ns' => t.ns }

  MAP = {
    'templateList' => -> { T::STARTER_TEMPLATES.map { |t| meta(t) } },
    'starterTemplate' => ->(i) { meta(T.starter_template(i)) },
    'templateTraits' => ->(i, n) { T.starter_template(i).traits(n) },
    'templateYaml' => ->(i, n) { T.starter_template(i).yaml(n) }
  }.freeze

  def test_every_function_is_covered = assert_equal [], BY_FN.keys - MAP.keys

  MAP.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 169, BY_FN.values.sum(&:length), 'actions-templates'
  end

end
