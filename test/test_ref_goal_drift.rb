# frozen_string_literal: true

# Replays the TS-reference oracle of goal drift and crc (test-data/ref-goal-drift.json.gz): the tighten-only drift monitor (driven
# through a step script, as the monitor is stateful), conformal risk control numerics and the fidelity report.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/goal_crc'
require_relative '../lib/atlas_pca/goal_drift'
require 'minitest/autorun'

class TestRefGoalDrift < Minitest::Test
  C = AtlasPca::GoalCrc
  D = AtlasPca::GoalDrift
  BY_FN = Ref.load('goal-drift')

  def self.deep(v) = Marshal.load(Marshal.dump(v))

  FLOW = lambda do |goal, opts, steps|
    mon = D::Monitor.new(goal, opts || {})
    last = nil
    out = []
    steps.each do |s|
      case s['op']
      when 'observe' then out << mon.observe(s['act'], s['t'])
      when 'state' then out << TestRefGoalDrift.deep(mon.state)
      when 'seal'
        last = TestRefGoalDrift.deep(mon.seal(Ref.b64d(s['key'])))
        out << last
      when 'restoreLast'
        sealed = TestRefGoalDrift.deep(last)
        sealed['state']['strikes'] = 0 if s['mode'] == 'state'
        sealed['mac'] = (sealed['mac'][0] == '0' ? '1' : '0') + sealed['mac'][1..] if s['mode'] == 'mac'
        sealed['mac'] = 'zz' if s['mode'] == 'badmac'
        mon = D::Monitor.restore(goal, sealed, Ref.b64d(s['key']), opts || {})
        out << TestRefGoalDrift.deep(mon.state)
      when 'guarded'
        r = D.guarded_decide(goal, s['ont'], mon, s['case'], s['t'])
        out << { 'decision' => r['decision'], 'signal' => r['signal'] }
      end
    end
    out
  end

  CALIBRATE = lambda do |losses, alpha, gate|
    g = gate == 'none' ? nil : ->(k, n) { C.cp_upper95(k, n) <= gate[2..].to_f / 1e5 }
    C.calibrate(losses, alpha, g)
  end

  FNS = {
    'flow' => FLOW, 'applyDrift' => D.method(:apply_drift), 'alphaOf' => C.method(:alpha_of), 'calibrate' => CALIBRATE,
    'assertMonotone' => C.method(:assert_monotone), 'cpUpper95' => C.method(:cp_upper95), 'renderReportMarkdown' => C.method(:render_report_markdown)
  }.freeze

  def test_every_function_is_covered
    assert_equal FNS.keys.sort, BY_FN.keys.sort
  end

  FNS.each do |fn, call|
    define_method("test_matches_reference_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 152, BY_FN.values.sum(&:length), 'goal-drift'
  end

end
