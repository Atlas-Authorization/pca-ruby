# frozen_string_literal: true

# Session histories (windows, accumulator keys, pre-states, post values, monitor folds) against the TS reference over hostile inputs: the base corpus
# test-data/base-intenthistory.json.gz (29,179 cases): every window kind and malformed ones around their edges, histories with junk entries (null, strings,
# arrays, non-object params, non-string verbs), counted events with unreadable times, sums at the safe-integer edge, a candidate without its key parameter
# for every aggregate, and the responds_within counter over hostile `pending:` tails. Where the reference throws the native raises; where it answers
# undefined (a window or a monitor of an unknown kind) the native answers false / nil. Totals are asserted, nothing is skipped.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestBaseIntentHistory < Minitest::Test
  BY_FN = Ref.load('intenthistory', path: File.join(Ref::DATA, 'base-intenthistory.json.gz'))
  UNDEF = AtlasPca::V2JS::UNDEF
  TOTALS = { 'inWindow' => 1848, 'accKeyOf' => 104, 'accPreState' => 11340, 'accPost' => 14784, 'monitorStep' => 1003, 'monitorState' => 100 }.freeze

  HANDLERS = {
    'inWindow' => ->(w, ti, t) { AtlasPca.in_window(w, ti, t) },
    'accKeyOf' => ->(a, params) { AtlasPca.acc_key_of(a, params) },
    'accPreState' => ->(a, h, cand, schema = nil) { AtlasPca.acc_pre_state(a, h, cand, schema.nil? ? UNDEF : schema) },
    'accPost' => ->(a, h, cand, schema = nil) { AtlasPca.acc_post(a, h, cand, schema.nil? ? UNDEF : schema) },
    'monitorStep' => ->(m, q, e) { AtlasPca.monitor_step(m, q, e) },
    'monitorState' => ->(m, h) { AtlasPca.monitor_state(m, h) }
  }.freeze

  def test_the_corpus_is_pinned_in_full
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 29_179, BY_FN.values.sum(&:length)
    throws = BY_FN.values.flatten.count { |c| Ref.throws?(c['out']) }
    assert_equal 16_284, throws, 'the rest are values: a replay that only refuses cannot pass'
  end

  TOTALS.each_key do |fn|
    define_method("test_replay_#{fn}") do
      # the reference answers undefined (null) for a window of an unknown kind: false here
      compare = fn == 'inWindow' ? ->(got, out, _c) { got == (out.nil? ? false : out) } : nil
      ran = Ref.run(self, BY_FN.fetch(fn), ->(*args) { HANDLERS[fn].call(*args) }, compare: compare)
      assert_equal TOTALS[fn], ran
    end
  end
end
