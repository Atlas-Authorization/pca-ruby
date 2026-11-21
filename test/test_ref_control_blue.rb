# frozen_string_literal: true

# Replays the blue control protocol of the control evaluation (test-data/ref-control-blue.json.gz, 362 cases) against the real native blue stack
# (ref-control-evals replays only the aggregation, from a stub blue): the example agent with its review battery, the example blue protocol (the
# agent's base policy at theta 1 / 1, the data-flow policy, the immune-adapted metered budget), every episode (replay, predicates and caveats through the
# agent's review, data-flow governance, the budget) and the example evaluation. Totals are asserted; numbers compare to a relative 1e-12 (the leak decays
# exponentially). A reference refusal (params outside the strict canonical profile) must be a refusal here.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefControlBlue < Minitest::Test
  CE = AtlasPca::ControlEvals
  BY_FN = Ref.load('control-blue')
  TOTALS = { 'buildExampleAgent' => 1, 'exampleBlue' => 3, 'blueEpisode' => 352, 'exampleEval' => 6 }.freeze
  PERMISSIONS = { 'stripe' => ['refund'], 'gmail' => %w[send draft], 'files' => %w[read write], 'github' => ['read'] }.freeze
  REDS = {
    'over-cap' => CE::OVER_CAP_RED, 'off-verb' => CE::OFF_VERB_RED, 'slow-burn' => CE::SLOW_BURN_RED, 'taint-exfil' => CE::TAINT_EXFIL_RED,
    'replay' => CE::REPLAY_RED, 'immune-probe' => CE::IMMUNE_PROBE_BURST_RED, 'benign' => CE::BENIGN_BASELINE_RED, 'gap-exploit' => CE.gap_exploit_red
  }.freeze

  def self.agent_of(name)
    return CE.build_example_agent if name == 'example'

    kw = name == 'cap50' ? { limits: { 'refund' => '$50/day' } } : {}
    AtlasPca.create_agent(principal: AtlasPca::KeyPair.generate, goal: 'handle refunds and customer email for October', permissions: PERMISSIONS,
                          aud: 'ins_example', now: 0, **kw)
  end

  def self.blue_of(b)
    blue = CE.example_blue(agent_of(b['agent']))
    blue.dlp = nil if b['dlp'] == false
    blue.use_agent_risk_policy if b['theta'] == 'agent'
    blue.step = b['stepMs'] if b.key?('stepMs')
    blue.start = b['startMs'] if b.key?('startMs')
    blue.immune_cfg = b['immune'] if b['immune']
    blue.adapt_cfg = b['adapt'] if b['adapt']
    blue
  end

  def self.review_view(entries)
    a = CE.build_example_agent
    p = a.policy
    actions = p['actions'].map { |s| s.slice('connector', 'action', 'verb', 'reversibility', 'blastRadius', 'amountField', 'resource') }
    reviews = entries.map do |e|
      r = AtlasPca.review_action(a, e['verb'], e['resource'], e['params'], now: e['now'], insecure_unbound_approval: true)
      e.merge('review' => r.slice('kind', 'reason'))
    end
    { 'policy' => p.slice('predicates', 'caveats', 'riskPolicy', 'budgetModel', 'approximations', 'inputLimits').merge('actions' => actions), 'reviews' => reviews }
  end

  def self.episode(spec, actions)
    red = actions ? AtlasPca::ControlEvals::RedPolicy.new('custom', 'custom', ->(_ctx) { actions }) : REDS.fetch(spec['red'])
    env = spec['env'] == 'example' ? CE::EXAMPLE_ENV : CE.gap_aware_env
    CE.run_episode(red, blue_of(spec['blue']), env, spec['seed'])
  end

  # numbers by a relative 1e-12, everything else by value
  def self.same?(want, got)
    case want
    when Hash then got.is_a?(Hash) && want.keys.sort == got.keys.sort && want.all? { |k, v| same?(v, got[k]) }
    when Array then got.is_a?(Array) && want.length == got.length && want.each_index.all? { |i| same?(want[i], got[i]) }
    when Integer, Float then (got.is_a?(Integer) || got.is_a?(Float)) && (want == got || (want - got).abs <= 1e-12 * [want.abs, 1.0].max)
    else want == got
    end
  end

  HANDLERS = {
    'buildExampleAgent' => ->(*) { review_view(BY_FN['buildExampleAgent'][0]['out']['reviews']) },
    'exampleBlue' => lambda { |name|
      b = CE.example_blue(agent_of(name))
      { 'name' => b.name, 'basePolicy' => b.base, 'dlp' => b.dlp, 'startMs' => b.start_ms, 'stepMs' => b.step_ms }
    },
    'blueEpisode' => ->(spec, actions = nil) { episode(spec, actions) },
    'exampleEval' => ->(s) { CE.example_control_eval(episodes: s['episodes'], seed: s['seed']) }
  }.freeze

  def test_every_fn_is_pinned_in_full
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 362, BY_FN.values.sum(&:length)
    assert_equal 5, BY_FN.values.flatten.count { |c| Ref.throws?(c['out']) }, 'the five reference refusals (params that are not canonical JSON)'
  end

  TOTALS.each_key do |fn|
    define_method("test_replay_#{fn}") do
      # the review battery is the reference's own entries (verb, resource, params, now) re-reviewed natively
      Ref.run(self, BY_FN.fetch(fn), ->(*args) { HANDLERS[fn].call(*args) }, compare: ->(got, out, _c) { self.class.same?(Ref.norm(out), Ref.norm(got)) })
    end
  end
end
