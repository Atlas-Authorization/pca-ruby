# frozen_string_literal: true

# Replays the TS-reference oracle of the policy-safety CI gate (test-data/ref-policy-ci.json.gz): normalization of every accepted
# input shape, the lint rules over the analyzer, summary and exit codes, the pinned lint-rule digest, the authoring gates and the
# command line (run against small files in a temporary directory).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/policy_ci'
require 'minitest/autorun'
require 'tmpdir'

class TestRefPolicyCi < Minitest::Test
  P = AtlasPca::PolicyCi
  BY_FN = Ref.load('policy-ci')

  # Write each member of `files` (name -> text) into a fresh directory, run the command line there, return {code, lines}.
  def self.run_cli(spec)
    Dir.mktmpdir do |d|
      spec['files'].each { |name, text| File.binwrite(File.join(d, name), text) }
      lines = []
      code = Dir.chdir(d) { P.run(spec['argv'], ->(l) { lines << l }) }
      { 'code' => code, 'lines' => lines }
    end
  end

  MAP = {
    'normalizePolicyInput' => P.method(:normalize_policy_input),
    'normalizeChain' => P.method(:normalize_chain),
    'isCapability' => P.method(:capability?),
    'isEnvelope' => P.method(:envelope?),
    'lintPolicy' => ->(i, o = nil) { P.lint_policy(i, o) },
    'lintChain' => ->(c, o = nil) { P.lint_chain(c, o) },
    'lint' => ->(i, o = nil) { P.lint(i, o) },
    'lintPolicies' => ->(items, o = nil) { P.lint_policies(items, o) },
    'summarize' => ->(r, o = nil) { P.summarize(r, o) },
    'checkLintRulesPin' => ->(t, a = nil) { P.check_lint_rules_pin(t, a) },
    'toAnalyzerPolicy' => P.method(:to_analyzer_policy),
    'diffCommand' => ->(a, b, o = nil) { P.diff_command(a, b, o) },
    'testCommand' => ->(a, b, o = nil) { P.test_command(a, b, o) },
    'coverageCommand' => ->(a, b, o = nil) { P.coverage_command(a, b, o) },
    'parseArgs' => P.method(:parse_args),
    'run' => nil
  }.freeze

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}") do
      # the command-line cases carry the spec itself, not an argument list
      cases = BY_FN[fn].map { |c| c['args'].is_a?(Hash) ? c.merge('args' => [c['args']]) : c }
      Ref.run(self, cases, ->(*a) { fn == 'run' ? self.class.run_cli(*a) : MAP[fn].call(*a) })
    end
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 2060, BY_FN.values.sum(&:length), 'policy-ci'
  end

end
