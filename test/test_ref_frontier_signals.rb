# frozen_string_literal: true

# Replays the TS-reference oracle of the frontier signals (test-data/ref-frontier-signals.json.gz, 690 cases): the three signal typings and the
# risk-input tightening, signed zeros included. Every fn has a handler and the totals are asserted; a reference refusal (a null baseline or
# objective) needs a native exception.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefFrontierSignals < Minitest::Test
  F = AtlasPca::FrontierSignals
  BY_FN = Ref.load('frontier-signals')
  TOTALS = { 'semanticSignal' => 39, 'progressSignal' => 129, 'objectiveSignal' => 182, 'tightenRiskInputs' => 340 }.freeze
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  HANDLERS = {
    'semanticSignal' => ->(r) { F.semantic_signal(r) },
    'progressSignal' => ->(r) { F.progress_signal(r) },
    'objectiveSignal' => ->(r) { F.objective_signal(r) },
    'tightenRiskInputs' => ->(b, o) { F.tighten_risk_inputs(b, o) }
  }.freeze

  # Equal by value, with the sign of a zero compared explicitly (min(0, -0) is -0, max(-0, 0) is 0).
  def self.same?(got, out)
    return got.keys.sort == out.keys.sort && out.all? { |k, v| same?(got[k], v) } if got.is_a?(Hash) && out.is_a?(Hash)

    zero_sign = ->(x) { x.is_a?(Numeric) && x.zero? ? (x.is_a?(Float) && (1.0 / x).negative? ? -1 : 1) : nil }
    got == out && zero_sign.call(got) == zero_sign.call(out)
  end

  def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 690, BY_FN.values.sum(&:length)
    assert_equal 2, BY_FN.values.flatten.count { |c| Ref.throws?(c['out']) }
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      ran = Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| self.class.dnum(a) }) },
                    compare: ->(got, out, _c) { self.class.same?(got, out) })
      assert_equal TOTALS.fetch(fn), ran
    end
  end
end
