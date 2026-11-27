# frozen_string_literal: true

# Replays the reference oracle of the action lint rules, text and SARIF output and the definition-level undo structure
# (test-data/ref-actions-lint.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_lint'
require 'minitest/autorun'

class TestRefActionsLint < Minitest::Test
  L = AtlasPca::ActionsLint
  U = AtlasPca::ActionsUndo
  BY_FN = Ref.load('actions-lint')

  # the reference option names are camelCase; `att` stands for the confirmation verdict of the injected verifier
  def self.lint(raw, opts = nil)
    o = Ref.snake(opts || {})
    has = o.key?('att')
    att = o.delete('att')
    L.lint_defs(raw, o, has ? ->(_d) { att } : nil)
  end

  MAP = {
    'lintDefs' => ->(raw, opts = nil) { lint(raw, opts) },
    'lintRulesDigest' => L.method(:lint_rules_digest),
    'LINT_RULES' => -> { L::LINT_RULES.map(&:dup) },
    'lintText' => L.method(:lint_text),
    'toSarif' => L.method(:to_sarif),
    'lintFails' => L.method(:lint_fails),
    'mayBeReversible' => U.method(:may_be_reversible),
    'reversibilityFor' => U.method(:reversibility_for),
    'compensationShape' => U.method(:compensation_shape)
  }.freeze

  # findings can carry lone surrogates: compare as JS-order JSON
  CMP = lambda do |got, out, _c|
    js = ->(v) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(v))) }
    js.call(got) == js.call(out)
  end

  def test_every_function_is_covered = assert_equal [], BY_FN.keys - MAP.keys

  MAP.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call, compare: CMP) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 2231, BY_FN.values.sum(&:length), 'actions-lint'
  end

end
