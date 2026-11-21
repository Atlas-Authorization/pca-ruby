# frozen_string_literal: true

# Replays the TS-reference oracle of the reputation input validator and the fail-closed edges of the score
# (test-data/ref-reputation.json.gz, 85 cases; the scoring, the pricing and the signed quote are replayed from the sweep corpus,
# the disputes of settlement records from the research corpus). Every fn has a handler and the total is asserted. The record cap
# is not in the corpus (it would be megabytes): it is checked here with a generated list.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefReputation < Minitest::Test
  A = AtlasPca
  BY_FN = Ref.load('reputation')
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  HANDLERS = {
    'validateReputationInput' => ->(input) { A.validate_reputation_input(input) },
    'reputation' => ->(input) { A.reputation(input) },
    'constants' => -> { { 'MAX_REPUTATION_RECORDS' => A::MAX_REPUTATION_RECORDS, 'COVERAGE_QUOTE_DOMAIN' => A::COVERAGE_QUOTE_DOMAIN } }
  }.freeze

  def test_every_fn_of_the_corpus_has_a_handler
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal 85, BY_FN.values.sum(&:length)
  end

  def test_the_record_cap
    event = { 'outcome' => 'auto' }
    assert_nil A.validate_reputation_input({ 'subject' => 's', 'events' => [event] * A::MAX_REPUTATION_RECORDS })
    over = { 'subject' => 's', 'events' => [event] * (A::MAX_REPUTATION_RECORDS + 1) }
    assert_equal 'too many records', A.validate_reputation_input(over)
    assert_equal({ 'subject' => 's', 'actions' => 0, 'autos' => 0, 'stepUps' => 0, 'denies' => 0, 'slashes' => 0, 'disputes' => 0, 'score' => 0,
                   'factors' => ['invalid input: too many records'] }, A.reputation(over))
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| self.class.dnum(a) }) })
    end
  end
end
