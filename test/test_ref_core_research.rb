# frozen_string_literal: true

# Replays the TS-reference oracle of the research-tier modules (test-data/ref-core-research-java.json.gz, 6188 cases): the DLP
# evaluator and its preset, the immune read side (baseline, assess, observe, the state validator), the policy simulator with
# its lints over a policy compiled from {permissions, limits?, budgetModel?, riskPolicy?, now}, and the disputes of settlement records. Every fn of the corpus has a
# handler here or is named in PENDING (its module is not replayed yet); a fn that is in neither fails. The total is asserted.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefCoreResearch < Minitest::Test
  A = AtlasPca
  BY_FN = Ref.load('core-research-java')
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  def self.compile(sp)
    A.compile_policy(sp['permissions'], sp['limits'], budget_model: sp['budgetModel'], risk_policy: sp['riskPolicy'], now: sp['now'])
  end

  def self.kp(label) = A::KeyPair.new(Digest::SHA256.digest("atlas-pca-conformance/research/#{label}"))

  # A session script: ["agent", name, spec], ["start", name, agent], ["mk", name, [agents], goal|null], ["add", name, parent, holder|null,
  # caveats|null], and the reads agents / depth / shares / goal / console. Each op answers a value; an op the reference refuses is
  # {"$err": "Error"} and must raise here.
  def self.session_script(ops)
    ags = {}
    sess = {}
    ops.map do |op, name, *rest|
      case op
      when 'agent'
        spec = rest[0]
        ags[name] = A.create_agent(principal: kp(spec['principal']), goal: spec['goal'], permissions: spec['permissions'], holder: kp(spec['holder']),
                                   goal_salt: spec['goalSalt'], now: spec['now'])
        ags[name].holder.public
      when 'start' then (sess[name] = A.start_session(ags.fetch(rest[0])))['goalCommit']
      when 'mk'
        members = rest[0].map { |n| ags.fetch(n) }
        goal = rest[1]
        sess[name] = { 'root' => members.first, 'members' => members,
                       'goalCommit' => goal.nil? ? (members.empty? ? '' : A.session_goal_commit(members.first)) : goal }
        sess[name]['goalCommit']
      when 'add'
        kw = {}
        kw[:holder] = kp(rest[1]) unless rest[1].nil?
        kw[:added_caveats] = rest[2] unless rest[2].nil?
        r = A.add_member(sess.fetch(rest[0]), **kw)
        sess[name] = r['session']
        r['member'].holder.public
      when 'agents' then A.session_agents(sess.fetch(name))
      when 'depth' then A.session_depth(sess.fetch(name))
      when 'shares' then A.shares_goal?(sess.fetch(name))
      when 'goal' then sess.fetch(name)['goalCommit']
      when 'console' then A.session_console(sess.fetch(name), rest[0])
      else raise "unknown session op #{op}"
      end
    rescue StandardError
      { '$err' => 'Error' }
    end
  end

  GUARDIAN = A::KeyPair.new(Digest::SHA256.digest('atlas-pca-conformance/research/guardian'))

  HANDLERS = {
    'evaluateDlp' => ->(policy, ctx) { A::Dlp.evaluate_dlp(policy, ctx) },
    'defaultDlpPolicy' => ->(opts) { A::Dlp.default_dlp_policy(opts) },
    'updateBaseline' => ->(b, r) { A::Immune.update_baseline(b, r) },
    'baselineStd' => ->(b) { A::Immune.baseline_std(b) },
    'assess' => ->(state) { A::Immune.assess(state) },
    'validateImmuneState' => ->(s) { A::Immune.validate_immune_state(s) },
    'observe' => ->(state, obs) { A::Immune.observe(state, obs) },
    'buildConsole' => ->(events) { A.build_console(events) },
    'anomalies' => ->(events) { A.anomalies(A.build_console(events)) },
    'eventFromPCActn' => ->(p, outcome, at) { A.event_from_pcactn(p, outcome, at) },
    'freezeAgent' => ->(set, agent) { A.freeze_agent(set, agent) },
    'unfreezeAgent' => ->(set, agent) { A.unfreeze_agent(set, agent) },
    'isFrozen' => ->(set, agent) { A.frozen?(set, agent) },
    'session' => ->(ops) { session_script(ops) },
    'simulate' => ->(spec, actions, start) { A::PolicySim.simulate(compile(spec), actions, start: start) },
    'lintPolicy' => ->(spec) { A::PolicySim.lint_policy(compile(spec)) },
    # the guardian "@g" is the corpus key; the subjects are an own-key lookup in the map; pin null = not given
    'disputesFromSettlements' => ->(records, g, subjects, pin) { A.disputes_from_settlements(records, g == '@g' ? GUARDIAN.public : g, subjects, pin) }
  }.freeze

  # fns of the corpus this file does not replay yet; an entry leaves this list when its replay lands
  PENDING = [].freeze

  def test_every_fn_of_the_corpus_is_replayed_or_listed_as_pending
    assert_empty BY_FN.keys - HANDLERS.keys - PENDING, 'fns without a handler'
    assert_empty PENDING - BY_FN.keys, 'pending fns the corpus does not have'
    assert_empty PENDING & HANDLERS.keys, 'fns both replayed and pending'
    assert_equal 6188, BY_FN.values.sum(&:length)
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| self.class.dnum(a) }) })
    end
  end
end
