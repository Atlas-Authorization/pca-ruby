# frozen_string_literal: true

# za_b: mutation-kill tests for the helpers of lib/atlas_pca/authorize.rb: the in-memory and SQL budget stores, the construction-time
# store checks, the numeric risk step (budget source and shape, risk inputs, plan distance, age, caution floor, reversibility class,
# step-up wording, debit), merged_risk, the threshold hook result and the defaults of authorize / authorize_unchecked.
# Reference: packages/pca/src/{risk.ts,policy-vm.ts,server/authorize.ts,server/verify.ts}. AtlasPca is resolved at call time.

module MutationKill
  module ZB
    module_function

    def gate? = (f = ENV['MUT_FILE']).nil? || f.empty? || f == 'authorize.rb'

    def ck(label, got, want)
      got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    end

    NOW = 1_800_000_000_000
    BEST = { 'semanticDistance' => 0, 'reversibility' => 1, 'blastRadius' => 0, 'taint' => 0, 'confidence' => 1, 'age' => 0 }.freeze
    OP = { 'verb' => 'orders.quote', 'resource' => 'orders/42', 'params' => {} }.freeze
    GRANT = { 'id' => 'g1' }.freeze
    ZERO_W = { 'alpha' => 0.0, 'beta' => 0.0, 'gamma' => 0.0, 'delta' => 0.0, 'epsilon' => 0.0, 'zeta' => 0.0 }.freeze
    NO_BUDGET = "budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge"

    # a store offering the budget pair
    class Bs
      attr_reader :asked

      def initialize(stored)
        @stored = stored
        @asked = []
      end

      def budget(key)
        @asked << key
        @stored
      end

      def budget_cas(*)
        true
      end
    end

    class OnlyBudget
      def budget(_key) = nil
    end

    class OnlyCas
      def budget_cas(*) = true
    end

    def pol(weights = {}, over = {})
      { 'weights' => ZERO_W.merge(weights), 'theta1' => 0.25, 'theta2' => 0.6, 'kappa' => 10, 'lambda' => 0, 'rho' => 5, 'bMax' => 100 }.merge(over)
    end

    def bud(b = 100, tau = NOW, as_of = NOW)
      { 'B' => b, 'tau' => tau, 'asOf' => as_of }
    end

    def sd_only = pol({ 'alpha' => 1.0 })

    # a ctx always carries a valid budget unless the test says otherwise
    def step(pl = sd_only, ctx: {}, pcactn: {}, plan_nodes: nil, node_id: nil, rev: 'reversible', risk: BEST, store: nil, release: false, seed: nil)
      AtlasPca.policy_risk_step(pl, pcactn, GRANT, { 'budget' => bud }.merge(ctx), plan_nodes, node_id, rev, NOW, risk, OP, store, 'bk', release, seed)
    end

    def no_sd = BEST.reject { |k, _| k == 'semanticDistance' }

    def hook(res)
      checks = {}
      reasons = []
      out = AtlasPca.threshold_hook_result(->(_p, _g) { res }, {}, {}, checks, reasons)
      [out, checks['threshold'], reasons]
    end
  end

  t('za_b MemoryStateStore budget: copies in and out, compare-and-set is exact') do
    next true unless ZB.gate?

    s = AtlasPca::MemoryStateStore.new
    h = { 'B' => 1 }
    ZB.ck('insert', s.budget_cas('k', nil, h), true)
    h['B'] = 99
    ZB.ck('stored a copy', s.budget('k'), { 'B' => 1 })
    got = s.budget('k')
    got['B'] = 7
    ZB.ck('read a copy', s.budget('k'), { 'B' => 1 })
    ZB.ck('absent', s.budget('none'), nil)
    ZB.ck('wrong old', s.budget_cas('k', { 'B' => 2 }, { 'B' => 3 }), false)
    ZB.ck('unchanged', s.budget('k'), { 'B' => 1 })
    ZB.ck('exists, old nil', s.budget_cas('k', nil, { 'B' => 3 }), false)
    ZB.ck('unchanged 2', s.budget('k'), { 'B' => 1 })
    ZB.ck('right old', s.budget_cas('k', { 'B' => 1 }, { 'B' => 5 }), true)
    ZB.ck('replaced', s.budget('k'), { 'B' => 5 })
    ZB.ck('absent, old given', s.budget_cas('other', { 'B' => 1 }, { 'B' => 5 }), false)
    ZB.ck('still absent', s.budget('other'), nil)
  end

  t('za_b SqlStateStore budget and pins: exact statements, placeholders and row counts') do
    next true unless ZB.gate?

    st, log = C06.sql_store(table: 'tb', sel: '{"B":3}')
    ZB.ck('read', st.budget('k'), { 'B' => 3 })
    ZB.ck('read sql', log, [['SELECT value FROM tb_budget WHERE key = ?', ['k']]])
    st, log = C06.sql_store(placeholders: :dollar, sel: '{"B":3}')
    ZB.ck('read dollar', [st.budget('k'), log], [{ 'B' => 3 }, [['SELECT value FROM pca_replay_budget WHERE key = $1', ['k']]]])
    ZB.ck('no row', C06.sql_store(sel: nil)[0].budget('k'), nil)
    ZB.ck('not text', C06.sql_store(sel: 5)[0].budget('k'), nil)

    ins_q = 'INSERT INTO tb_budget (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING'
    ins_d = 'INSERT INTO pca_replay_budget (key, value) VALUES ($1, $2) ON CONFLICT(key) DO NOTHING'
    upd_q = 'UPDATE tb_budget SET value = ? WHERE key = ? AND value = ?'
    upd_d = 'UPDATE pca_replay_budget SET value = $1 WHERE key = $2 AND value = $3'
    [[1, true], [0, false], [2, false]].each do |rows, want|
      st, log = C06.sql_store(table: 'tb', rets: [rows])
      ZB.ck("insert #{rows}", [st.budget_cas('k', nil, { 'B' => 2 }), log], [want, [[ins_q, ['k', '{"B":2}']]]])
      st, log = C06.sql_store(placeholders: :dollar, rets: [rows])
      ZB.ck("insert dollar #{rows}", [st.budget_cas('k', nil, { 'B' => 2 }), log], [want, [[ins_d, ['k', '{"B":2}']]]])
      st, log = C06.sql_store(table: 'tb', rets: [rows])
      ZB.ck("update #{rows}", [st.budget_cas('k', { 'B' => 1 }, { 'B' => 2 }), log], [want, [[upd_q, ['{"B":2}', 'k', '{"B":1}']]]])
      st, log = C06.sql_store(placeholders: :dollar, rets: [rows])
      ZB.ck("update dollar #{rows}", [st.budget_cas('k', { 'B' => 1 }, { 'B' => 2 }), log], [want, [[upd_d, ['{"B":2}', 'k', '{"B":1}']]]])
    end

    st, log = C06.sql_store
    ZB.ck('raise_pin', [st.raise_pin('k', 5), log], [5, [[st.claim_sql, ["\u001fpin:k", 5]]]])
    msg = 'raise_pin: value must be an Integer'
    ZB.ck('symbol key', C06.raises(ArgumentError, msg) { st.raise_pin(:k, 5) }, true)
    ZB.ck('nil key', C06.raises(ArgumentError, msg) { st.raise_pin(nil, 5) }, true)
    ZB.ck('string value', C06.raises(ArgumentError, msg) { st.raise_pin('k', '5') }, true)
    ZB.ck('float value', C06.raises(ArgumentError, msg) { st.raise_pin('k', 5.0) }, true)
  end

  t('za_b store_shared? and the construction-time store problems') do
    next true unless ZB.gate?

    with = lambda do |meths, scope = nil|
      c = Class.new
      meths.each { |m| c.define_method(m) { |*| nil } }
      o = c.new
      o.define_singleton_method(:scope) { scope } unless scope.nil?
      o
    end
    ZB.ck('process', AtlasPca.store_shared?(with.call([], :process)), false)
    ZB.ck('process text', AtlasPca.store_shared?(with.call([], 'process')), false)
    ZB.ck('shared scope', AtlasPca.store_shared?(with.call([], :shared)), true)
    ZB.ck('no scope', AtlasPca.store_shared?(Object.new), true)
    ZB.ck('nil', AtlasPca.store_shared?(nil), true)

    multi = 'multiInstance requires a shared state store (a process-scoped store lets one PCActn replay once per instance)'
    stale = 'revocation staleness needs a state store that implements pins (rollback protection)'
    prob = ->(*a) { AtlasPca.state_store_config_problems(*a) }
    full = with.call(%i[pin raise_pin])
    proc_full = with.call(%i[pin raise_pin], :process)
    ZB.ck('nothing', prob.call(nil, nil, true), [])
    ZB.ck('no store, staleness', prob.call(nil, :rs, true), [])
    ZB.ck('no store, no multi', prob.call(nil, :rs, nil), [])
    ZB.ck('full store', prob.call(full, :rs, nil), [])
    ZB.ck('full store, multi', prob.call(full, :rs, true), [])
    ZB.ck('only pin', prob.call(with.call([:pin]), :rs, nil), [stale])
    ZB.ck('only raise_pin', prob.call(with.call([:raise_pin]), :rs, nil), [stale])
    ZB.ck('neither', prob.call(Object.new, :rs, nil), [stale])
    ZB.ck('no staleness', prob.call(with.call([]), nil, nil), [])
    ZB.ck('process, multi', prob.call(proc_full, nil, true), [multi])
    ZB.ck('process, not true', [prob.call(proc_full, nil, false), prob.call(proc_full, nil, nil), prob.call(proc_full, nil, 'true')], [[], [], []])
    ZB.ck('both', prob.call(with.call([], :process), :rs, true), [multi, stale])
  end

  t('za_b policy_risk_step: the budget source, its shape and the fail-closed default') do
    next true unless ZB.gate?

    guard = ZB::Bs.new(nil)
    r = ZB.step(store: guard)
    ZB.ck('supplied', [r['stored'], r['persist'], r['budget_present'], r['reasons'], r['after'], guard.asked], [nil, false, true, [], ZB.bud, []])
    r = ZB.step(ctx: { 'budget' => { 'B' => 100, 'tau' => ZB::NOW, 'asOf' => ZB::NOW }.transform_keys(&:to_sym) })
    ZB.ck('symbol keys', [r['budget_present'], r['reasons']], [true, []])

    [{ 'tau' => ZB::NOW }, { 'B' => 100 }, { 'B' => 'x', 'tau' => ZB::NOW }, { 'B' => 100, 'tau' => 'x' }, { 'B' => Float::NAN, 'tau' => ZB::NOW },
     { 'B' => 100, 'tau' => Float::INFINITY }, [['B', 100], ['tau', ZB::NOW]], 'str', nil, 5].each_with_index do |b, i|
      r = ZB.step(ctx: { 'budget' => b })
      ZB.ck("malformed #{i}", [r['budget_present'], r['persist'], r['reasons'], r['after']], [false, false, [ZB::NO_BUDGET], ZB.bud(0)])
    end

    r = ZB.step(ctx: { 'budget' => nil }, store: store = ZB::Bs.new(nil))
    ZB.ck('seeded from bMax', [r['persist'], r['stored'], r['budget_present'], r['after'], store.asked], [true, nil, true, ZB.bud(100), ['bk']])
    [ZB::OnlyBudget.new, ZB::OnlyCas.new, Object.new].each_with_index do |s, i|
      r = ZB.step(ctx: { 'budget' => nil }, store: s)
      ZB.ck("no store pair #{i}", [r['persist'], r['stored'], r['budget_present'], r['reasons']], [false, nil, false, [ZB::NO_BUDGET]])
    end

    seen = []
    seed = ->(g, n) { seen << [g, n]; ZB.bud(40, ZB::NOW - 7000) }
    r = ZB.step(ctx: { 'budget' => nil }, store: ZB::Bs.new(nil), seed: seed)
    ZB.ck('seed hook', [r['persist'], r['stored'], r['after'], seen], [true, nil, ZB.bud(40, ZB::NOW - 7000), [[ZB::GRANT, ZB::NOW]]])
    r = ZB.step(ctx: { 'budget' => nil }, store: ZB::Bs.new(nil), seed: ->(_g, _n) { { B: 40, tau: ZB::NOW, asOf: ZB::NOW } })
    ZB.ck('seed with symbol keys', [r['budget_present'], r['persist'], r['after']], [true, true, ZB.bud(40)])
    r = ZB.step(ctx: { 'budget' => nil }, store: ZB::Bs.new(nil), seed: ->(_g, _n) {})
    ZB.ck('seed hook with none', [r['budget_present'], r['persist'], r['reasons']], [false, false, [ZB::NO_BUDGET]])
    r = ZB.step(ctx: { 'budget' => nil }, store: ZB::Bs.new(ZB.bud(7)), seed: ->(_g, _n) { ZB.bud(40) })
    ZB.ck('stored wins', [r['stored'], r['persist'], r['after']], [ZB.bud(7), true, ZB.bud(7)])
    r = ZB.step(ctx: { 'budget' => nil }, store: ZB::Bs.new({ 'B' => 'x' }))
    ZB.ck('stored malformed', [r['stored'], r['persist'], r['budget_present'], r['reasons']], [{ 'B' => 'x' }, false, false, [ZB::NO_BUDGET]])

    r = ZB.step(ZB.pol({ 'alpha' => 1.0 }, 'lambda' => 1), ctx: { 'budget' => ZB.bud(100, ZB::NOW - 10_000, ZB::NOW - 10_000) })
    ZB.ck('the budget leaks per second', r['after'], ZB.bud(90.0, ZB::NOW - 10_000, ZB::NOW))
  end

  t('za_b policy_risk_step: risk inputs, the plan distance, age and the caution floor') do
    next true unless ZB.gate?

    ab = %w[a b c].map { |i| { 'id' => i } }
    r = ZB.step(ctx: { 'goal_node_id' => 'b' }, plan_nodes: ab, node_id: 'a', risk: ZB.no_sd)
    ZB.ck('goal from ctx', [r['r'], r['reasons']], [0.5, ['risk 0.500 exceeds auto threshold: step-up to t=2']])
    r = ZB.step(plan_nodes: ab, node_id: 'b', risk: ZB.no_sd)
    ZB.ck('goal is the last node', [r['r'], r['reasons']], [0.5, ['risk 0.500 exceeds auto threshold: step-up to t=2']])
    r = ZB.step(ctx: { 'goal_node_id' => 'b' }, plan_nodes: ab, node_id: nil, risk: ZB.no_sd)
    ZB.ck('no node id', r['r'], 1)
    ZB.ck('no node id (id-less node)', ZB.step(ctx: { 'goal_node_id' => 'g' }, plan_nodes: [{}, { 'id' => 'g' }, { 'id' => 'z' }], node_id: nil, risk: ZB.no_sd)['r'], 1)
    ZB.ck('no goal', ZB.step(plan_nodes: ['x', { 'id' => 'n' }, 'z', 'w'], node_id: 'n', risk: ZB.no_sd)['r'], 1)
    ZB.ck('no goal, false id', ZB.step(plan_nodes: [{ 'id' => 'n' }, { 'id' => false }, 'w'], node_id: 'n', risk: ZB.no_sd)['r'], 1)
    ZB.ck('no goal, odd last node', ZB.step(plan_nodes: [{ 'id' => 'n' }, 7], node_id: 'n', risk: ZB.no_sd)['r'], 1)
    r = ZB.step(plan_nodes: nil, risk: ZB.no_sd)
    ZB.ck('no plan', [r['r'], r['reasons']], [1, ['risk input(s) missing, assumed worst case: semanticDistance', "risk 1.000 exceeds auto threshold: step-up to t=3"]])
    ZB.ck('supplied distance wins', ZB.step(ctx: { 'goal_node_id' => 'b' }, plan_nodes: ab, node_id: 'a', risk: ZB::BEST.merge('semanticDistance' => 0.3))['r'], 0.3)
    r = ZB.step(ctx: { 'goal_node_id' => 'b' }, plan_nodes: ab, node_id: 'a', risk: ZB::BEST.merge('semanticDistance' => 'x'))
    ZB.ck('a bad distance is replaced', [r['r'], r['reasons']], [0.5, ['risk 0.500 exceeds auto threshold: step-up to t=2']])

    ZB.ck('a bad input is missing', ZB.step(risk: ZB::BEST.merge('taint' => 'x'))['reasons'], ['risk input(s) missing, assumed worst case: taint'])
    ZB.ck('nothing supplied', ZB.step(risk: {})['reasons'],
          ['risk input(s) missing, assumed worst case: semanticDistance, reversibility, blastRadius, taint, confidence',
           'risk 1.000 exceeds auto threshold: step-up to t=3'])

    age = ZB.pol({ 'zeta' => 1.0 })
    old = { 'budget' => ZB.bud(100, ZB::NOW - 1_800_000) }
    no_age = ZB::BEST.reject { |k, _| k == 'age' }
    ZB.ck('default horizon', ZB.step(age, ctx: old, risk: no_age)['r'], 0.5)
    ZB.ck('ctx horizon', ZB.step(age, ctx: old.merge('age_horizon_ms' => 7_200_000), risk: no_age)['r'], 0.25)
    ZB.ck('bad age is replaced', ZB.step(age, ctx: old, risk: ZB::BEST.merge('age' => 'x'))['r'], 0.5)
    ZB.ck('supplied age wins', ZB.step(age, ctx: old, risk: ZB::BEST.merge('age' => 0.9))['r'], 0.9)

    zero = ZB.pol
    [[0.7, 0.7], [5, 1], [1, 1], [-3, 0], [0, 0], [nil, 0], ['x', 0], [true, 0]].each do |caution, want|
      ZB.ck("caution #{caution.inspect}", ZB.step(zero, pcactn: { 'caution' => caution })['r'], want)
    end
  end

  t('za_b policy_risk_step: reversibility class, step-up wording, admission and debit') do
    next true unless ZB.gate?

    weird = Object.new
    def weird.to_str
      'reversible'
    end

    def weird.==(_other)
      true
    end

    [['reversible', true], ['rate_limited', true], ['costly', true], ['irreversible', false], ['REVERSIBLE', false], ['', false], [nil, false],
     [:reversible, false], [weird, false]].each do |cls, want|
      r = ZB.step(rev: cls)
      ZB.ck("class #{cls.inspect}", [r['threshold'], r['adm']], [{ 't' => 1, 'proof' => 'claim', 'optimisticAllowed' => want },
                                                                 { 'admit' => true, 'needStepUp' => false, 't' => 1, 'metered' => true }])
    end

    lo = ZB::BEST.merge('semanticDistance' => 0.1)
    r = ZB.step(ctx: { 'budget' => ZB.bud(100) }, risk: lo, release: true)
    ZB.ck('debit', [r['r'], r['reasons'], r['after']], [0.1, [], ZB.bud(99.0)])
    ZB.ck('no release, no debit', ZB.step(risk: lo, release: false)['after'], ZB.bud(100))

    r = ZB.step(ctx: { 'budget' => ZB.bud(0.5) }, risk: lo, release: true)
    ZB.ck('depleted', [r['reasons'], r['adm'], r['threshold'], r['after']],
          [['trust budget depleted: human recharge required'], { 'admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => false },
           { 't' => 3, 'proof' => 'strong', 'optimisticAllowed' => false }, ZB.bud(0.5)])

    mid = ZB::BEST.merge('semanticDistance' => 0.4)
    r = ZB.step(risk: mid, release: true)
    ZB.ck('band two', [r['reasons'], r['adm'], r['threshold'], r['after']],
          [['risk 0.400 exceeds auto threshold: step-up to t=2'], { 'admit' => false, 'needStepUp' => true, 't' => 2, 'metered' => true },
           { 't' => 2, 'proof' => 'standard', 'optimisticAllowed' => false }, ZB.bud(96.0)])
    r = ZB.step(ctx: { 'budget' => ZB.bud(1) }, risk: mid, release: true)
    ZB.ck('band two depleted', [r['reasons'], r['adm']['t'], r['threshold']['t']], [['trust budget depleted: human recharge required'], 3, 3])

    r = ZB.step(risk: ZB::BEST.merge('semanticDistance' => 0.9), release: true)
    ZB.ck('band three', [r['reasons'], r['adm'], r['threshold'], r['after']],
          [['risk 0.900 exceeds auto threshold: step-up to t=3'], { 'admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => false },
           { 't' => 3, 'proof' => 'strong', 'optimisticAllowed' => false }, ZB.bud(100)])
  end

  t('za_b merged_risk: the riskier of the context and the option, string keys, only Hashes count') do
    next true unless ZB.gate?

    m = ->(ctx, risk) { AtlasPca.merged_risk(ctx, risk, ZB::OP, ZB::GRANT, :pc) }
    ZB.ck('ctx symbols', m.call({ 'risk' => { taint: 0.2 } }, nil), { 'taint' => 0.2 })
    ZB.ck('option symbols', m.call({}, { taint: 0.7 }), { 'taint' => 0.7 })
    seen = []
    fn = ->(op, g, pc) { seen << [op, g, pc]; { taint: 0.5, confidence: 0.3 } }
    ZB.ck('callable', [m.call({ 'risk' => { 'taint' => 0.2, 'confidence' => 0.9 } }, fn), seen],
          [{ 'taint' => 0.5, 'confidence' => 0.3 }, [[ZB::OP, ZB::GRANT, :pc]]])
    ZB.ck('ctx pairs are not a Hash', m.call({ 'risk' => [['taint', 0.5]] }, nil), {})
    ZB.ck('ctx text', m.call({ 'risk' => 'abc' }, nil), {})
    ZB.ck('option pairs are not a Hash', m.call({}, [['taint', 1]]), {})
    ZB.ck('option text', m.call({}, 'x'), {})
    ZB.ck('option text keeps ctx', m.call({ 'risk' => { 'taint' => 0.2 } }, 'x'), { 'taint' => 0.2 })
    ZB.ck('callable answering pairs', m.call({ 'risk' => { 'taint' => 0.2 } }, ->(*) { [['taint', 1]] }), { 'taint' => 0.2 })
  end

  t('za_b threshold_hook_result: statuses, reported t text, clamp and reasons') do
    next true unless ZB.gate?

    checks = {}
    reasons = []
    ZB.ck('no hook', [AtlasPca.threshold_hook_result(nil, {}, {}, checks, reasons), checks, reasons], [['not-enforced', nil, nil], { 'threshold' => 'not-enforced' }, []])
    ne = ['not-enforced', nil, nil]
    ZB.ck('not enforced', ZB.hook({ enforced: false, ok: true, t: 3 }), [ne, 'not-enforced', []])
    [true, 5, 'x', [1], [['enforced', true], ['ok', true]], { 'enforced' => 'yes' }].each_with_index do |res, i|
      ZB.ck("not a verdict #{i}", ZB.hook(res), [ne, 'not-enforced', []])
    end
    ZB.ck('symbol keys', ZB.hook({ enforced: true, ok: true, t: 2.5 }), [['pass', 2, '2.5'], 'pass', []])
    ZB.ck('string keys', ZB.hook({ 'enforced' => true, 'ok' => true, 't' => 3 }), [['pass', 3, '3'], 'pass', []])

    { 2.0 => '2', 1e21 => '1e+21', 1.9 => '1.9', 0.1 => '0.1', Rational(5, 2) => '2.5', Float::NAN => 'NaN', Float::INFINITY => 'Infinity',
      'x' => 'x', :abc => 'abc', true => 'true', nil => nil }.each do |t, shown|
      want_t = t.is_a?(Float) && t.finite? ? [[t.floor, (2**53) - 1].min, -((2**53) - 1)].max : nil
      ZB.ck("shown #{t.inspect}", ZB.hook({ enforced: true, ok: true, t: t })[0], ['pass', want_t, shown])
    end

    top = (2**53) - 1
    [[1.9, 1], [-1.5, -2], [0, 0], [3, 3], [top, top], [2**53, top], [2**54, top], [2**60, top], [-top, -top], [-(2**53), -top], [-(2**54), -top],
     [-(2**60), -top], [1e300, top], [-1e300, -top]].each do |tv, want|
      ZB.ck("clamp #{tv}", ZB.hook({ enforced: true, ok: true, t: tv })[0][1], want)
    end

    ZB.ck('rejected', ZB.hook({ enforced: true, ok: false, t: 1.9, reason: 'no' }), [['fail', nil, '1.9'], 'fail', ['threshold: no']])
    ZB.ck('rejected, no reason', ZB.hook({ enforced: true, ok: false })[2], ['threshold: rejected'])
    ZB.ck('rejected, odd reason', ZB.hook({ enforced: true, ok: false, reason: 5 })[2], ['threshold: rejected'])
    ZB.ck('ok must be true', ZB.hook({ enforced: true, ok: 'yes', t: 3 }), [['fail', nil, '3'], 'fail', ['threshold: rejected']])
    checks = {}
    reasons = []
    out = AtlasPca.threshold_hook_result(->(*) { raise 'boom' }, {}, {}, checks, reasons)
    ZB.ck('raising', [out, checks, reasons], [['fail', nil, nil], { 'threshold' => 'fail' }, ['threshold: threshold hook error (fail closed)']])
  end

  t('za_b authorize_unchecked and authorize: every defaulted argument behaves as its explicit default') do
    next true unless ZB.gate?

    c = C06.base
    s = c['steps'][0]
    full = Array.new(9) + [false] + Array.new(12) + [false] + Array.new(11)
    mk = lambda do
      [s['pcactn'], s['operation'], C06.aud, ->(_r) { c['grant'] }, AtlasPca::MemoryStateStore.new, ->(_p, _g) { false }, C06::NOW, 'single-step',
       nil, nil, nil, nil, nil]
    end
    shape = ->(r) { [r.allow, r.status, r.decision, r.checks, r.reasons] }
    plain = shape.call(AtlasPca.authorize_unchecked(*mk.call))
    ZB.ck('unchecked', shape.call(AtlasPca.authorize_unchecked(*mk.call, *full)), plain)

    base = shape.call(C06.go(:base, drop: [:risk]))
    expl = shape.call(C06.go(:base, provenance_bundle: nil, undo: nil, allow_unsupported: nil, multi_instance: nil, risk: nil, threshold_hook: nil,
                                    pq_pins: nil, require_risk_inputs: nil, resolve_principal: nil, require_verified_principal: false, require_passport: nil,
                                    passport: nil, enforce_freshness: nil, adaptive: nil, seed_budget: nil, enforce_taint: nil, beacon: nil,
                                    require_linked_template: nil, forbid: nil, forbid_certificate: nil, contracts: nil))
    ZB.ck('authorize', expl, base)
  end

  t('za_b authorize: forbid keys may be symbols; contracts need peek and check') do
    next true unless ZB.gate?

    r = C06.go(forbid: { clauses: ->(_op, _grant) { [] } })
    ZB.ck('symbol clauses', [r.checks['forbid'], r.reasons.include?('forbid: deny by none'), r.reason.to_s.include?('authorize_config')], ['fail', true, false])

    peek_only = Class.new { def peek(*) = nil }.new
    check_only = Class.new { def check(*) = nil }.new
    both = Class.new do
      def peek(*) = nil
      def check(*) = nil
    end.new
    needle = 'contracts (must respond to #peek and #check)'
    ZB.ck('peek only', C06.go(contracts: peek_only).reason.to_s.include?(needle), true)
    ZB.ck('check only', C06.go(contracts: check_only).reason.to_s.include?(needle), true)
    ZB.ck('both', C06.go(contracts: both).reason.to_s.include?(needle), false)
  end
end
