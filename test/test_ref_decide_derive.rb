# frozen_string_literal: true

# Replays the TS-reference oracle of the decide-input derivation (test-data/ref-decide-derive.json.gz, 240 cases): derive_decide_input
# (a PCActn plus the verifier's own context -> the Policy VM input; the stored grant is required) and the derivation followed by the
# decision ({input, decision}). Every fn of the corpus has a handler; a reference throw must be a native raise.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefDecideDerive < Minitest::Test
  BY_FN = Ref.load('decide-derive')

  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze

  # a non-finite number is {"$num": ...} in the arguments
  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  HANDLERS = {
    'deriveDecideInput' => ->(pcactn, ctx) { AtlasPca.derive_decide_input(dnum(pcactn), dnum(ctx)) },
    'deriveThenDecide' => lambda do |pcactn, ctx|
      pcactn = dnum(pcactn)
      ctx = dnum(ctx)
      input = AtlasPca.derive_decide_input(pcactn, ctx)
      { 'input' => input, 'decision' => AtlasPca.decide(input) }
    end
  }.freeze

  def test_every_fn_of_the_corpus_has_a_handler
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal 240, BY_FN.values.sum(&:length)
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") { Ref.run(self, BY_FN.fetch(fn), handler) }
  end
end
