# frozen_string_literal: true

# Replays the TS-reference oracle of the policy bridge (test-data/ref-policy-bridge.json.gz): Cedar / Rego / OpenFGA / strict-CEL
# translation of engine-checked corpora, hand-written constructs and refusals, seeded mutations of both (hostile text), and
# deny-overrides-permit `decide`.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/policy_bridge'
require 'minitest/autorun'

class TestRefPolicyBridge < Minitest::Test
  B = AtlasPca::PolicyBridge
  BY_FN = Ref.load('policy-bridge')

  MAP = {
    'cedarToPca' => ->(t) { B.cedar_to_pca(t) },
    'translateCedar' => ->(t, g) { B.translate_cedar(t, g) },
    'regoToPca' => ->(t) { B.rego_to_pca(t) },
    'openfgaToPca' => ->(*a) { B.openfga_to_pca(*a) },
    'decide' => ->(r, c) { B.decide(r, c) },
    'celToCondition' => ->(e, s) { B.cel_to_condition(e, s) },
    'celToPredicate' => ->(e, s, sc) { B.cel_to_predicate(e, s, sc) },
    'celConditionsToPca' => ->(i, s) { B.cel_conditions_to_pca(i, s) },
    'parseCel' => ->(e) { B.parse_cel(e) }
  }.freeze

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 4361, BY_FN.values.sum(&:length), 'policy-bridge'
  end

end
