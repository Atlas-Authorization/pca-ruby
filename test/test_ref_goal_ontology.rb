# frozen_string_literal: true

# Replays the TS-reference oracle of the goal ontology (test-data/ref-goal-ontology.json.gz): verb resolution, IR projection, the
# well-formedness checker, template instantiation, slot typing, locale-aware amount parsing and the shipped ontology data.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/goal_ontologies'
require_relative '../lib/atlas_pca/goal_ontology'
require 'minitest/autorun'

class TestRefGoalOntology < Minitest::Test
  OS = AtlasPca::GoalOntologies
  O = AtlasPca::GoalOntology
  UNDEF = AtlasPca::GoalJs::UNDEF
  BY_FN = Ref.load('goal-ontology')

  # a shipped ontology travels by name; a hand-written one inline
  def self.ont(x) = x.is_a?(String) && OS.shipped_ontology(x) ? OS.shipped_ontology(x) : x

  FNS = {
    'shippedOntology' => OS.method(:shipped_ontology), 'shippedCatalog' => OS.method(:shipped_catalog),
    'ontologyDigest' => ->(o) { O.ontology_digest(TestRefGoalOntology.ont(o)) },
    'resolveVerb' => ->(o, w) { O.resolve_verb(TestRefGoalOntology.ont(o), w) },
    'goalCcy' => O.method(:goal_ccy), 'goalAnchors' => O.method(:goal_anchors),
    'toIrOntology' => ->(o, op) { O.to_ir_ontology(TestRefGoalOntology.ont(o), op) },
    'ontologyForGoal' => ->(o, g, rels = nil) { O.ontology_for_goal(TestRefGoalOntology.ont(o), g, rels) },
    'checkOntology' => ->(o) { O.check_ontology(TestRefGoalOntology.ont(o)) },
    'instantiateTemplate' => ->(o, tid, vals, opts) { O.instantiate_template(TestRefGoalOntology.ont(o), tid, vals, opts) },
    'slotLits' => ->(o, s, v) { O.slot_lits(TestRefGoalOntology.ont(o), s, v.nil? ? UNDEF : v) },
    'parseHumanAmount' => O.method(:parse_human_amount), 'parseMoney' => O.method(:parse_money)
  }.freeze

  def test_every_function_is_covered
    assert_equal FNS.keys.sort, BY_FN.keys.sort
  end

  FNS.each do |fn, call|
    define_method("test_matches_reference_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 2579, BY_FN.values.sum(&:length), 'goal-ontology'
  end

end
