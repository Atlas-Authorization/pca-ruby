# frozen_string_literal: true

# Replays the reference oracle of everything an ActionDef yields: schema verb/document, operation binding, risk, predicates, ontology,
# policy card, escalation, MCP annotations and the explanation (test-data/ref-actions-derive.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_derive'
require 'minitest/autorun'

class TestRefActionsDerive < Minitest::Test
  A = AtlasPca::Actions
  E = AtlasPca::ActionsEffective
  DR = AtlasPca::ActionsDerive
  BY_FN = Ref.load('actions-derive')
  CORE = A::CORE_REGISTRY

  def self.reg(defs) = defs.nil? ? CORE : A.extend_registry(CORE, defs)
  def self.opt(c) = ->(_d) { c }

  MAP = {
    'flattenParams' => DR.method(:flatten_params),
    'paramByRole' => DR.method(:param_by_role),
    'effectClass' => DR.method(:effect_class),
    'toSchemaVerb' => ->(d, c) { DR.to_schema_verb(d, CORE, opt(c)) },
    'toSchemaDoc' => ->(ds, m, c, rd) { DR.to_schema_doc(ds, reg(rd), m, opt(c)) },
    'operationOf' => ->(d, p) { DR.operation_of(d, { 'params' => p }) },
    'riskOf' => ->(d, c, p, o) { DR.risk_of(d, E.effective_with(d, CORE, opt(c)), p, o) },
    'resourceMatcher' => DR.method(:resource_matcher),
    'predicatesOf' => DR.method(:predicates_of),
    'toOntology' => ->(ds, c) { DR.to_ontology(ds, CORE, opt(c)) },
    'cardOf' => ->(d, c) { DR.card_of(d, E.effective_with(d, CORE, opt(c)), CORE) },
    'escalationOf' => ->(d, c) { DR.escalation_of(E.effective_with(d, CORE, opt(c))) },
    'mcpAnnotationsOf' => ->(d, c) { DR.mcp_annotations_of(d, E.effective_with(d, CORE, opt(c))) },
    'explainDef' => ->(d, c) { DR.explain_def(d, CORE, opt(c)) },
    'REVERSIBILITY_SCORE' => -> { DR::REVERSIBILITY_SCORE }
  }.freeze

  def test_every_function_is_covered = assert_equal [], BY_FN.keys - MAP.keys

  MAP.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1829, BY_FN.values.sum(&:length), 'actions-derive'
  end

end
