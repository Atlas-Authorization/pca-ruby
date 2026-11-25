# frozen_string_literal: true

# Replays the TS-reference oracles of the goal selectors: the verbs of a class selector, role resolution, expansion of a selector goal
# against the pinned catalog, selector typing, role keys, the policy card and the carrier form. A shipped domain's catalog and
# ontology travel by name and are resolved from the shipped data. The second corpus is a hand-written catalog with confirmed verbs,
# the selector typing refusals and the catalog of a pack of defs.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/goal_ontologies'
require_relative '../lib/atlas_pca/goal_ontology'
require_relative '../lib/atlas_pca/goal_selectors'
require_relative '../lib/atlas_pca/goal_compiler'
require 'minitest/autorun'

class TestRefGoalSelectors < Minitest::Test
  OS = AtlasPca::GoalOntologies
  O = AtlasPca::GoalOntology
  S = AtlasPca::GoalSelectors
  BY_FN = Ref.load('goal-selectors-py')
  BY_FN_REF = Ref.load('goal-selectors-java')

  def self.dom(d) = O.to_ir_ontology(OS.shipped_ontology(d))
  def self.ref_ont(x) = x.is_a?(String) && OS.shipped_ontology(x) ? O.to_ir_ontology(OS.shipped_ontology(x)) : x
  def self.ref_cat(x) = x.is_a?(String) && OS.shipped_catalog(x) ? OS.shipped_catalog(x) : x

  FNS = {
    'selCatalogOfDomain' => S.method(:sel_catalog_of_domain), 'selCatalogDigest' => S.method(:sel_catalog_digest),
    'selGoalDigest' => S.method(:sel_goal_digest), 'classVerbs' => S.method(:class_verbs), 'allowClassVerbs' => S.method(:allow_class_verbs),
    'floatClassVerbs' => S.method(:float_class_verbs),
    'resolveRole' => ->(dom, cat, verb, role) { S.resolve_role(TestRefGoalSelectors.dom(dom), cat, verb, role) },
    'expandSelGoal' => ->(sg, dom, cat) { S.expand_sel_goal(sg, TestRefGoalSelectors.dom(dom), cat) },
    'selReasons' => ->(sg, dom, cat) { S.sel_reasons(sg, TestRefGoalSelectors.dom(dom), cat) },
    'withRoleParams' => S.method(:with_role_params), 'selCarrier' => S.method(:sel_carrier), 'encodeSelCatalog' => S.method(:encode_sel_catalog),
    'renderSelCard' => ->(sg, dom, cat) { S.render_sel_card(sg, TestRefGoalSelectors.dom(dom), cat) }, 'traitClosure' => S.method(:trait_closure)
  }.freeze

  REF_FNS = {
    'selCatalogDigest' => ->(c) { S.sel_catalog_digest(TestRefGoalSelectors.ref_cat(c)) }, 'selGoalDigest' => S.method(:sel_goal_digest),
    'classVerbs' => ->(c, a, n) { S.class_verbs(TestRefGoalSelectors.ref_cat(c), a, n) },
    'allowClassVerbs' => ->(c, a, n) { S.allow_class_verbs(TestRefGoalSelectors.ref_cat(c), a, n) },
    'floatClassVerbs' => ->(c, a, n) { S.float_class_verbs(TestRefGoalSelectors.ref_cat(c), a, n) },
    'resolveRole' => ->(o, c, v, r) { S.resolve_role(TestRefGoalSelectors.ref_ont(o), TestRefGoalSelectors.ref_cat(c), v, r) },
    'expandSelGoal' => ->(sg, o, c) { S.expand_sel_goal(sg, TestRefGoalSelectors.ref_ont(o), TestRefGoalSelectors.ref_cat(c)) },
    'selReasons' => ->(sg, o, c) { S.sel_reasons(sg, TestRefGoalSelectors.ref_ont(o), TestRefGoalSelectors.ref_cat(c)) },
    'compileSelGoal' => lambda { |sg, o, c|
      S.compile_sel_goal(sg, TestRefGoalSelectors.ref_ont(o), TestRefGoalSelectors.ref_cat(c), AtlasPca::GoalCompiler.method(:compile_goal))
    },
    'withRoleParams' => ->(a, c) { S.with_role_params(a, TestRefGoalSelectors.ref_cat(c)) },
    'renderSelCard' => ->(sg, o, c) { S.render_sel_card(sg, TestRefGoalSelectors.ref_ont(o), TestRefGoalSelectors.ref_cat(c)) },
    'selCarrier' => S.method(:sel_carrier), 'encodeSelCatalog' => ->(c) { S.encode_sel_catalog(TestRefGoalSelectors.ref_cat(c)) },
    'traitClosure' => S.method(:trait_closure), 'catalogOfDomain' => S.method(:sel_catalog_of_domain),
    'catalogOfDefs' => ->(defs) { S.sel_catalog_of_defs(defs) }
  }.freeze

  def test_every_function_is_covered
    assert_equal FNS.keys.sort, BY_FN.keys.sort
  end

  FNS.each do |fn, call|
    define_method("test_matches_reference_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  def test_reference_corpus_every_function_is_covered
    assert_equal REF_FNS.keys.sort, BY_FN_REF.keys.sort
  end

  REF_FNS.each do |fn, call|
    define_method("test_matches_reference_corpus_#{fn}") { Ref.run(self, BY_FN_REF[fn], call) }
  end

  # the catalog derived from the built-in defs is the shipped one
  def test_derived_catalog_equals_shipped
    OS::NAMES.each { |d| assert_equal OS.shipped_catalog(d), S.sel_catalog_of_domain(d, AtlasPca::Actions::CORE_REGISTRY), d }
    assert_raises(TypeError) { S.sel_catalog_of_domain('nope', AtlasPca::Actions::CORE_REGISTRY) }
  end

  # without an injected compiler the core compiler is used
  def test_compile_sel_goal_defaults_to_the_core_compiler
    c = BY_FN_REF['compileSelGoal'].first
    args = Ref.dec(c['args'])
    got = S.compile_sel_goal(args[0], TestRefGoalSelectors.ref_ont(args[1]), TestRefGoalSelectors.ref_cat(args[2]))
    assert_equal Ref.canon(c['out']), Ref.canon(got)
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1034, BY_FN.values.sum(&:length), 'goal-selectors-py'
    assert_equal 363, BY_FN_REF.values.sum(&:length), 'goal-selectors-java'
  end

end
