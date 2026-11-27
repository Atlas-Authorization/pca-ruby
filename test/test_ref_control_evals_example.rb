# frozen_string_literal: true

# The example blue control protocol (ControlEvals.example_blue: replay, review, Dlp, the budget under the Immune-adapted policy)
# against the reference's own recorded runs: every runEpisode / controlEval case of the control-evals oracle is run through the native
# protocol and must equal the reference's transcript and report (outcome, control, risk, threat, reason, budget).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefControlEvalsExample < Minitest::Test
  CE = AtlasPca::ControlEvals
  BY_FN = Ref.load('control-evals')
  AGENT = CE.build_example_agent

  REDS = {
    'over-cap' => CE::OVER_CAP_RED, 'off-verb' => CE::OFF_VERB_RED, 'slow-burn' => CE::SLOW_BURN_RED, 'taint-exfil' => CE::TAINT_EXFIL_RED,
    'replay' => CE::REPLAY_RED, 'immune-probe' => CE::IMMUNE_PROBE_BURST_RED, 'benign' => CE::BENIGN_BASELINE_RED,
    'gap-exploit' => CE.gap_exploit_red
  }.freeze

  def self.env(name)
    return CE::EXAMPLE_ENV if name == 'example'

    name == 'gap-aware' ? CE.gap_aware_env : CE.gap_aware_env(name[('gap-aware:'.length)..])
  end

  def test_run_episode
    Ref.run(self, BY_FN['runEpisode'], lambda { |s|
      CE.run_episode(REDS[s['red']], CE.example_blue(AGENT), self.class.env(s['env']), s['seed'])
    })
  end

  def test_control_eval
    Ref.run(self, BY_FN['controlEval'], lambda { |s|
      reds = s['reds'].is_a?(Array) ? s['reds'].map { |k| REDS[k] } : s['reds']
      CE.control_eval(reds, CE.example_blue(AGENT), self.class.env(s['env']), s['episodes'], s['seed'])
    })
  end

  def test_example_control_eval
    r = CE.example_control_eval
    assert_equal 8 * CE::EXAMPLE_RED_POLICIES.length, r['episodes']
    assert_equal 1, r['seed']
    pol = CE.build_example_agent.policy['riskPolicy']
    assert_in_delta pol['bMax'].to_f / pol['kappa'], r['analyticBound'], 1e-12
    assert_equal CE::EXAMPLE_RED_POLICIES.map(&:strategy).uniq.length, r['byStrategy'].length
    assert_equal Ref.canon(r), Ref.canon(CE.example_control_eval)
    assert_raises(ArgumentError) { CE.example_control_eval(episodes: 0) }
  end

  # the corpus is pinned: its fn set and every fn's case count (a fn the replay skips, or a changed corpus, fails here)
  def test_the_corpus_is_pinned_in_full
    assert_equal({ 'mulberry32' => 65, 'mixSeed' => 560, 'wilsonLowerBound' => 1170, 'assertControlGate' => 361, 'redGen' => 8, 'gapExploitCustom' => 1, 'redLists' => 1, 'exampleDlpPolicy' => 1, 'envJudge' => 1440, 'runEpisode' => 80, 'controlEval' => 15 }, BY_FN.transform_values(&:length))
  end

end
