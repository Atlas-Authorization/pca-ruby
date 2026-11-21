# frozen_string_literal: true

# Replays the TS-reference oracle of the empirical control-evaluation harness (test-data/ref-control-evals.json.gz): seeded PRNG,
# Wilson bound, CI gate, red policies, modeled environments, episode runner and aggregation. The blue control decisions are
# replayed from the decisions the reference recorded.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/control_evals'
require 'minitest/autorun'

class TestRefControlEvals < Minitest::Test
  CE = AtlasPca::ControlEvals
  BY_FN = Ref.load('control-evals')

  REDS = {
    'over-cap' => CE::OVER_CAP_RED, 'off-verb' => CE::OFF_VERB_RED, 'slow-burn' => CE::SLOW_BURN_RED, 'taint-exfil' => CE::TAINT_EXFIL_RED,
    'replay' => CE::REPLAY_RED, 'immune-probe' => CE::IMMUNE_PROBE_BURST_RED, 'benign' => CE::BENIGN_BASELINE_RED,
    'gap-exploit' => CE.gap_exploit_red
  }.freeze

  def self.env(name)
    return CE::EXAMPLE_ENV if name == 'example'

    name == 'gap-aware' ? CE.gap_aware_env : CE.gap_aware_env(name[('gap-aware:'.length)..])
  end

  class Episode
    def initialize(rec)
      @rec = rec
      @i = -1
    end

    def decide(_action, _at)
      @i += 1
      @rec['steps'][@i].reject { |k, _| k == 'money' }
    end

    def money_amount(_action) = @rec['steps'][@i]['money']
    def end_budget = @rec['endBudget']
  end

  class Stub < CE::Blue
    attr_reader :start_ms, :step_ms, :analytic_bound

    def initialize(spec, recs)
      super()
      @start_ms = spec['startMs']
      @step_ms = spec['stepMs']
      @analytic_bound = spec['analyticBound']
      @recs = recs.dup
    end

    def new_episode = Episode.new(@recs.shift)
  end

  def self.episode(spec) = CE.run_episode(REDS[spec['red']], Stub.new(spec, [spec['recorded']]), env(spec['env']), spec['seed'])

  def self.eval_spec(spec)
    reds = spec['reds'].is_a?(Array) ? spec['reds'].map { |k| REDS[k] } : spec['reds']
    recs = spec['recorded'].flatten(1)
    CE.control_eval(reds, Stub.new(spec, recs), env(spec['env']), spec['episodes'], spec['seed'])
  end

  def self.red_gen(name)
    r = REDS[name]
    { 'name' => r.name, 'strategy' => r.strategy, 'actions' => r.gen.call({ 'env' => CE::EXAMPLE_ENV, 'rng' => CE.mulberry32(1), 'now' => 0 }) }
  end

  def self.gap_custom
    r = CE.gap_exploit_red('file:x')
    { 'name' => r.name, 'actions' => r.gen.call({}) }
  end

  MAP = {
    'mulberry32' => ->(seed, k) { g = CE.mulberry32(seed); Array.new(k) { g.call } },
    'mixSeed' => ->(s, a, b) { CE.mix_seed(s, a, b) },
    'wilsonLowerBound' => ->(*a) { CE.wilson_lower_bound(*a) },
    'assertControlGate' => ->(r, g) { CE.assert_control_gate(r, g) },
    'redGen' => ->(n) { red_gen(n) },
    'gapExploitCustom' => -> { gap_custom },
    'redLists' => -> { { 'builtin' => CE::BUILTIN_RED_POLICIES.map(&:strategy), 'example' => CE::EXAMPLE_RED_POLICIES.map(&:strategy) } },
    'exampleDlpPolicy' => -> { CE.example_dlp_policy },
    'envJudge' => ->(env, action, ctx) { env(env).unacceptable_if_allowed(action, ctx) },
    'runEpisode' => ->(s) { episode(s) },
    'controlEval' => ->(s) { eval_spec(s) }
  }.freeze

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 3702, BY_FN.values.sum(&:length), 'control-evals'
  end

end
