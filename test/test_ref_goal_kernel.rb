# frozen_string_literal: true

# Replays the TS-reference goal kernel corpus (test-data/ref-goal-kernel.json.gz): for every goal, the typecheck / compile /
# render tapes and, per probe, the reference-semantics and compiled-policy tapes (decision, witness, witness check).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/goal_kernel'
require 'minitest/autorun'

class TestRefGoalKernel < Minitest::Test
  K = AtlasPca::GoalKernel
  BY_FN = Ref.load('goal-kernel')

  def test_every_function_is_covered
    assert_equal ['kernel'], BY_FN.keys
    assert_operator BY_FN['kernel'].length, :>, 150
  end

  def test_tape_text_round_trip
    BY_FN['kernel'].each do |c|
      [c['args'][0], c['args'][1], c['out']['compile']].each { |x| assert_equal x, K.tape_to_text(K.tape_from_text(x)) }
    end
    assert_equal [['k', 5], ['i', -3], ['s', ''], ['s', "h\u{1f600}"]], K.tape_from_text('k5 i-3 s s68.1f600')
  end

  def test_kernel_tapes
    bad = []
    BY_FN['kernel'].each do |c|
      g = K.tape_from_text(c['args'][0])
      o = K.tape_from_text(c['args'][1])
      probes = c['args'][2]
      want = c['out']
      %w[typecheck compile render].each do |op|
        got = K.tape_to_text(K.kernel_call(op, g, o))
        bad << "#{c['name']} #{op}: #{got[0, 120]} != #{want[op][0, 120]}" unless got == want[op]
      end
      assert_equal probes.length, want['probes'].length
      probes.each_with_index do |(a, h), i|
        at = K.tape_from_text(a)
        ht = K.tape_from_text(h)
        %w[decideg decidep].zip(want['probes'][i]).each do |op, w|
          got = K.tape_to_text(K.kernel_call(op, g, o, at, ht))
          bad << "#{c['name']}##{i} #{op}: #{got} != #{w}" unless got == w
        end
      end
    end
    assert bad.empty?, "#{bad.length} divergent tape(s):\n#{bad.first(25).join("\n")}"
  end

  def test_malformed_input_is_refused
    assert_equal [['i', 9]], K.kernel_call('typecheck', [['i', 7]], [])
    assert_equal [['i', 9]], K.kernel_call('render', [])
    assert_raises(AtlasPca::Goal::IrError) { K.kernel_call('typecheck', [['k', 1.5]], []) }
    assert_raises(AtlasPca::Goal::IrError) { K.kernel_call('typecheck', [['i', 2**60]], []) }
    assert_raises(ArgumentError) { K.kernel_call('nope', [], []) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 203, BY_FN.values.sum(&:length), 'goal-kernel'
  end

end
