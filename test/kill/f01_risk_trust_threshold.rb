# frozen_string_literal: true

# f01: PCA 0.5 hardening F2, the full risk score / trust budget / threshold step-up / caution floor port. Reference:
# packages/pca/src/risk.ts, policy-vm.ts (decide steps 3-5), server/verify.ts (the threshold rule), formal/dafny/PolicyVm.dfy
# (ReqThr, Escalate, AdmitOf, DecideCore). Every expected number is hand-computed from the reference; AtlasPca is resolved at call time.

module MutationKill
  module F01
    module_function

    def gate?(*files) = (f = ENV['MUT_FILE']).nil? || f.empty? || files.include?(f)

    def ck(label, got, want)
      got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    end

    def near(label, got, want) = ((got - want).abs < 1e-12) || raise("#{label}: got #{got.inspect}, want about #{want.inspect}")

    def r = AtlasPca::Risk
    W = { 'alpha' => 0.25, 'beta' => 0.2, 'gamma' => 0.2, 'delta' => 0.2, 'epsilon' => 0.1, 'zeta' => 0.05 }.freeze
    P = { 'weights' => W, 'theta1' => 0.25, 'theta2' => 0.6, 'kappa' => 1, 'lambda' => 0.0005, 'rho' => 0.5, 'bMax' => 1 }.freeze
    AUD = 'f01-rs'
    NOW = 1_800_000_000_000
    OP = { 'verb' => 'orders.quote', 'resource' => 'orders/42', 'params' => { 'order' => 'o42' } }.freeze

    # A real minted grant that carries the DEFAULT risk policy (non-zero weights) and a signed PCActn for OP: the corpus fixtures all carry
    # an all-zero-weight policy, under which every risk score is 0.
    def fixture
      @fixture ||= begin
        principal = AtlasPca::KeyPair.new("\x31".b * 32)
        agent = AtlasPca::KeyPair.new("\x32".b * 32)
        env = { 'predicates' => [{ 'verb' => '*', 'resource' => '*', 'where' => [] }], 'caveats' => [], 'risk_policy' => P, 'provenance' => { 'mode' => 'insecure_off' } }
        grant = AtlasPca.mint_grant(principal, agent.public, env, 'f01 goal')['grant']
        pc = AtlasPca::Agent.new(agent, grant, AUD, clock: -> { NOW }).act(OP['verb'], OP['resource'], OP['params']).pcactn
        { grant: grant, pcactn: pc, holder: agent.public }
      end
    end

    def go(**kw)
      f = fixture
      opts = { operation: OP, audience: AUD, resolve_grant: ->(_ref) { f[:grant] }, state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false },
               now: NOW, plan: 'single-step', risk: ProvHarness::RISK }.merge(kw)
      AtlasPca.authorize(f[:pcactn], **opts)
    end

    BEST = { 'semanticDistance' => 0, 'reversibility' => 1, 'blastRadius' => 0, 'taint' => 0, 'confidence' => 1, 'age' => 0 }.freeze
  end

  t('f01 risk: the score is the weighted sum, clamped, with every bad input at its worst case') do
    next true unless F01.gate?('risk.rb')

    r = F01.r
    F01.ck('best', r.risk_score(F01::BEST, F01::W), 0) &&
      F01.ck('distance', r.risk_score(F01::BEST.merge('semanticDistance' => 1), F01::W), 0.25) &&
      F01.ck('irreversible', r.risk_score(F01::BEST.merge('reversibility' => 0), F01::W), 0.2) &&
      F01.ck('nil reversibility is the worst', r.risk_score(F01::BEST.merge('reversibility' => nil), F01::W), 0.2) &&
      F01.ck('NaN distance is the worst', r.risk_score(F01::BEST.merge('semanticDistance' => Float::NAN), F01::W), 0.25) &&
      F01.ck('infinite taint is the worst', r.risk_score(F01::BEST.merge('taint' => Float::INFINITY), F01::W), 0.2) &&
      F01.ck('a string is the worst', r.risk_score(F01::BEST.merge('blastRadius' => '1'), F01::W), 0.2) &&
      F01.ck('a boolean is the worst', r.risk_score(F01::BEST.merge('confidence' => true), F01::W), 0.1) &&
      F01.ck('above one is one', r.risk_score(F01::BEST.merge('semanticDistance' => 7), F01::W), 0.25) &&
      F01.ck('below zero is zero', r.risk_score(F01::BEST.merge('semanticDistance' => -3), F01::W), 0) &&
      F01.ck('weights above one clamp the score', r.risk_score(F01::BEST.merge('semanticDistance' => 1), F01::W.merge('alpha' => 5)), 1) &&
      F01.ck('a negative weight counts as zero', r.risk_score(F01::BEST.merge('semanticDistance' => 1), F01::W.merge('alpha' => -1)), 0) &&
      F01.ck('a missing weight counts as zero', r.risk_score(F01::BEST.merge('semanticDistance' => 1), F01::W.reject { |k, _| k == 'alpha' }), 0) &&
      F01.ck('every input at its worst', r.risk_score({}, F01::W), 1)
  end

  t('f01 risk: the threshold map, its escalation and the budget admission') do
    next true unless F01.gate?('risk.rb')

    r = F01.r
    rt = ->(x, irr = false) { r.required_threshold(x, F01::P, irreversible: irr) }
    t1 = { 't' => 1, 'proof' => 'claim', 'optimisticAllowed' => true }
    t2 = { 't' => 2, 'proof' => 'standard', 'optimisticAllowed' => false }
    t3 = { 't' => 3, 'proof' => 'strong', 'optimisticAllowed' => false }
    F01.ck('theta1 inclusive', rt.call(0.25), t1) && F01.ck('zero', rt.call(0), t1) &&
      F01.ck('irreversible is never optimistic', rt.call(0.25, true), t1.merge('optimisticAllowed' => false)) &&
      F01.ck('above theta1', rt.call(0.26), t2) && F01.ck('theta2 inclusive', rt.call(0.6), t2) && F01.ck('above theta2', rt.call(0.61), t3) &&
      F01.ck('NaN is the worst', rt.call(Float::NAN), t3) && F01.ck('nil is the worst', rt.call(nil), t3) &&
      F01.ck('escalate up', r.escalate_threshold(t1, 2), t2) && F01.ck('escalate to three', r.escalate_threshold(t1, 3), t3) &&
      F01.ck('escalate never lowers', r.escalate_threshold(t3, 1), t3) && F01.ck('escalate keeps t', r.escalate_threshold(t2, 2), t2) &&
      F01.ck('escalate keeps a stronger proof', r.escalate_threshold({ 't' => 2, 'proof' => 'strong', 'optimisticAllowed' => false }, 2),
             { 't' => 2, 'proof' => 'strong', 'optimisticAllowed' => false }) &&
      F01.ck('escalate to one keeps optimism', r.escalate_threshold(t1, 1), t1) &&
      F01.ck('admit_of 1 covered', r.admit_of(1, true), { 'admit' => true, 'needStepUp' => false, 't' => 1, 'metered' => true }) &&
      F01.ck('admit_of 1 uncovered', r.admit_of(1, false), { 'admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => false }) &&
      F01.ck('admit_of 2 covered', r.admit_of(2, true), { 'admit' => false, 'needStepUp' => true, 't' => 2, 'metered' => true }) &&
      F01.ck('admit_of 2 uncovered', r.admit_of(2, false), { 'admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => false }) &&
      F01.ck('admit_of 3', r.admit_of(3, true), { 'admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => false }) &&
      F01.ck('admit covered', r.admit(0.1, { 'B' => 1 }, F01::P), { 'admit' => true, 'needStepUp' => false, 't' => 1, 'metered' => true }) &&
      F01.ck('admit depleted', r.admit(0.1, { 'B' => 0.05 }, F01::P), { 'admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => false }) &&
      F01.ck('admit NaN budget', r.admit(0.1, { 'B' => Float::NAN }, F01::P), { 'admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => false }) &&
      F01.ck('decide released and admitted', r.decide_core(true, true, true, true, t1, r.admit_of(1, true)),
             { 'release' => true, 'admit' => true, 'needStepUp' => false, 'threshold' => t1, 'debit' => true }) &&
      F01.ck('decide not released', r.decide_core(false, true, true, true, t1, r.admit_of(1, true)),
             { 'release' => false, 'admit' => false, 'needStepUp' => true, 'threshold' => t1, 'debit' => false }) &&
      [[false, true, true, true], [true, false, true, true], [true, true, false, true], [true, true, true, false]].all? do |a, b, c, d|
        F01.ck("one operand false #{[a, b, c, d]}", r.decide_core(a, b, c, d, t1, r.admit_of(1, true))['release'], false)
      end &&
      F01.ck('decide steps up to the admission t', r.decide_core(true, true, true, true, t1, r.admit_of(1, false)),
             { 'release' => true, 'admit' => false, 'needStepUp' => true, 'threshold' => t3, 'debit' => false })
  end

  t('f01 risk: the trust budget leaks, debits, recharges and ages') do
    next true unless F01.gate?('risk.rb')

    r = F01.r
    b = { 'B' => 1, 'tau' => 0 }
    l = r.leak(b, 2000, 0.0005)
    F01.near('leak', l['B'], 0.999)
    F01.ck('leak keeps tau and sets asOf', [l['tau'], l['asOf']], [0, 2000]) &&
      F01.ck('leak is idempotent at one instant', r.leak(l, 2000, 0.0005), l) &&
      F01.ck('leak never goes below zero', r.leak({ 'B' => 0.001, 'tau' => 0 }, 1_000_000, 0.0005)['B'], 0) &&
      F01.ck('leak never runs backwards', r.leak({ 'B' => 1, 'tau' => 5000, 'asOf' => 9000 }, 1000, 0.0005), { 'B' => 1.0, 'tau' => 5000, 'asOf' => 9000 }) &&
      F01.ck('leak at a non-finite time', r.leak(b, Float::NAN, 0.0005), { 'B' => 1.0, 'tau' => 0, 'asOf' => 0 }) &&
      F01.ck('leak with a bad lambda', r.leak(b, 5000, -1)['B'], 1) &&
      F01.ck('debit', r.debit({ 'B' => 0.5, 'tau' => 1, 'asOf' => 2 }, 0.25), { 'B' => 0.25, 'tau' => 1, 'asOf' => 2 }) &&
      F01.ck('debit floors at zero', r.debit({ 'B' => 0.5, 'tau' => 1 }, 2)['B'], 0) &&
      F01.ck('debit ignores a bad cost', r.debit({ 'B' => 0.5, 'tau' => 1 }, Float::NAN)['B'], 0.5) &&
      F01.ck('cost', [r.cost(0.5, 2), r.cost(Float::NAN, 2), r.cost(7, 2), r.cost(0.5, -1)], [1.0, 2, 2, 0]) &&
      F01.ck('recharge caps at bMax', r.recharge({ 'B' => 0.9, 'tau' => 0, 'asOf' => 0 }, 0.5, 1, 7), { 'B' => 1, 'tau' => 7, 'asOf' => 7 }) &&
      F01.ck('recharge adds rho', r.recharge({ 'B' => 0.25, 'tau' => 0 }, 0.5, 1, 7), { 'B' => 0.75, 'tau' => 7, 'asOf' => 7 }) &&
      F01.ck('recharge_full', r.recharge_full({ 'B' => 0, 'tau' => 0 }, 3, 9), { 'B' => 3, 'tau' => 9, 'asOf' => 9 }) &&
      F01.ck('age', [r.age_since_touch(b, 1_800_000), r.age_since_touch(b, 7_200_000), r.age_since_touch(b, 1_800_000, 1_800_000)], [0.5, 1, 1]) &&
      F01.ck('age at the worst', [r.age_since_touch(b, nil), r.age_since_touch(b, 5, 0), r.age_since_touch({ 'tau' => nil }, 5), r.age_since_touch(b, -5)], [1, 1, 1, 0]) &&
      F01.ck('safety bound', [r.safety_bound({ 'bMax' => 1, 'kappa' => 2 }), r.safety_bound({ 'bMax' => 1, 'kappa' => 0 }), r.safety_bound({ 'bMax' => -1, 'kappa' => 1 })],
             [0.5, 0, 0])
  end

  t('f01 risk: the multi-agent budget algebra, the plan geodesic and toFixed(3)') do
    next true unless F01.gate?('risk.rb')

    r = F01.r
    par = { 'B' => 0.5, 'tau' => 3 }
    F01.ck('sub budget', r.sub_budget(par, 0.25), { 'ok' => true, 'sub' => { 'B' => 0.25, 'tau' => 3, 'asOf' => 3 } }) &&
      F01.ck('sub budget keeps the parent asOf', r.sub_budget(par.merge('asOf' => 8), 0.25)['sub']['asOf'], 8) &&
      F01.ck('negative allocation', r.sub_budget(par, -1), { 'ok' => false, 'reason' => 'allocation must be finite and >= 0' }) &&
      F01.ck('NaN allocation', r.sub_budget(par, Float::NAN), { 'ok' => false, 'reason' => 'allocation must be finite and >= 0' }) &&
      F01.ck('over allocation', r.sub_budget(par, 0.6), { 'ok' => false, 'reason' => 'allocation exceeds parent remaining budget' }) &&
      F01.ck('whole allocation', r.sub_budget(par, 0.5)['ok'], true) &&
      F01.ck('consolidated', r.debit_consolidated({ 'B' => 1, 'tau' => 0 }, { 'B' => 0.5, 'tau' => 0 }, 0.25),
             { 'ok' => true, 'parent' => { 'B' => 0.75, 'tau' => 0 }, 'sub' => { 'B' => 0.25, 'tau' => 0 } }) &&
      F01.ck('sub short', r.debit_consolidated({ 'B' => 1 }, { 'B' => 0.1 }, 0.25), { 'ok' => false, 'reason' => 'sub-agent budget insufficient' }) &&
      F01.ck('parent short', r.debit_consolidated({ 'B' => 0.2 }, { 'B' => 1 }, 0.25), { 'ok' => false, 'reason' => 'parent budget insufficient' }) &&
      F01.ck('path', r.debit_consolidated_path([{ 'B' => 1 }, { 'B' => 0.5 }], 0.25), { 'ok' => true, 'nodes' => [{ 'B' => 0.75 }, { 'B' => 0.25 }] }) &&
      F01.ck('path offender', r.debit_consolidated_path([{ 'B' => 1 }, { 'B' => 0.5 }, { 'B' => 0.125 }], 0.25),
             { 'ok' => false, 'reason' => 'budget node at depth 2 insufficient (need 0.25, have 0.125)' }) &&
      F01.ck('path integer numbers', r.debit_consolidated_path([{ 'B' => 1 }, { 'B' => 2 }], 4),
             { 'ok' => false, 'reason' => 'budget node at depth 0 insufficient (need 4, have 1)' }) &&
      F01.ck('toFixed ties go up', [r.to_fixed3(0.0625), r.to_fixed3(0.1875), r.to_fixed3(0.5625)], %w[0.063 0.188 0.563]) &&
      F01.ck('toFixed', [r.to_fixed3(0), r.to_fixed3(1), r.to_fixed3(0.1), r.to_fixed3(0.0004), r.to_fixed3(0.7000000000000001), r.to_fixed3(0.9995)],
             %w[0.000 1.000 0.100 0.000 0.700 1.000]) &&
      begin
        pl = %w[a b c d].map { |i| { 'id' => i } }
        g = ->(plan, a, b) { r.plan_geodesic(plan, a, b) }
        edged = [{ 'id' => 'a' }, { 'id' => 'b', 'pre' => 'a' }, { 'id' => 'c', 'pre' => ['b'] }, { 'id' => 'd' }]
        posted = [{ 'id' => 'a', 'post' => { 'then' => 'b' } }, { 'id' => 'b', 'post' => ['c'] }, { 'id' => 'c' }, { 'id' => 'd' }]
        keyed = [{ 'id' => 'a' }, { 'id' => 'b', 'pre' => { 'depends_on' => 'a' } }, { 'id' => 'c', 'pre' => { 'after' => ['b'], 'nodes' => 'nobody' } }, { 'id' => 'd' }]
        F01.ck('same node', g.call(pl, 'b', 'b'), 0) && F01.ck('index distance without edges', [g.call(pl, 'a', 'c'), g.call(pl, 'a', 'b'), g.call(pl, 'd', 'a')], [2 / 3.0, 1 / 3.0, 1]) &&
          F01.ck('unknown ids', [g.call(pl, 'a', 'zz'), g.call(pl, 'zz', 'a'), g.call(nil, 'a', 'b'), g.call('x', 'a', 'b')], [1, 1, 1, 1]) &&
          F01.ck('pre edges', [g.call(edged, 'a', 'b'), g.call(edged, 'a', 'c'), g.call(edged, 'c', 'a'), g.call(edged, 'a', 'd')], [1 / 3.0, 2 / 3.0, 2 / 3.0, 1]) &&
          F01.ck('post edges', [g.call(posted, 'a', 'c'), g.call(posted, 'c', 'a'), g.call(posted, 'a', 'd')], [2 / 3.0, 2 / 3.0, 1]) &&
          F01.ck('keyed pre edges', [g.call(keyed, 'a', 'c'), g.call(keyed, 'a', 'b')], [2 / 3.0, 1 / 3.0])
      end
  end

  t('f01 authorize: the allowed fixture has a budget, risk zero, t=1, and the threshold is not enforced') do
    next true unless F01.gate?('authorize.rb', 'risk.rb')

    res = F01.go
    g = F01.fixture[:grant]
    ok = F01.ck('allow', [res.allow, res.checks['budget'], res.checks['threshold'], res.risk], [true, 'pass', 'not-enforced', 0]) &&
         F01.ck('threshold', [res.required_threshold['t'], res.required_threshold['proof']], [1, 'claim']) &&
         F01.ck('budget after', res.budget, { 'B' => 1, 'tau' => F01::NOW, 'asOf' => F01::NOW })
    ok && begin
      store = AtlasPca::MemoryStateStore.new
      r2 = F01.go(state_store: store, risk: ProvHarness::RISK.merge('reversibility' => 0.5))
      stored = store.budget(AtlasPca.state_key(g['id'], F01.fixture[:holder]))
      F01.ck('spent', r2.allow, true) && F01.near('debited', r2.budget['B'], 0.9) && F01.ck('persisted', stored, r2.budget)
    end
  end

  t('f01 authorize: a missing risk input is the worst case and a step-up needs an enforced threshold hook') do
    next true unless F01.gate?('authorize.rb', 'risk.rb')

    worst = F01.go(risk: {})
    miss = 'policy: risk input(s) missing, assumed worst case: reversibility, blastRadius, taint, confidence'
    step = 'policy: risk 0.700 exceeds auto threshold: step-up to t=3'
    none = 'threshold: t=3 (strong) required but no threshold verifier is enforced'
    hook = ->(res) { ->(_p, _g) { res } }
    F01.ck('worst case denies', [worst.allow, worst.status, worst.checks['policy'], worst.checks['threshold']], [false, 403, 'pass', 'fail']) &&
      F01.ck('reasons', [worst.reasons.include?(miss), worst.reasons.include?(step), worst.reasons.include?(none)], [true, true, true]) &&
      F01.ck('required', [worst.required_threshold['t'], worst.required_threshold['proof'], worst.risk.round(3)], [3, 'strong', 0.7]) &&
      F01.ck('enforced t=3 passes', [F01.go(risk: {}, threshold_hook: hook.call({ enforced: true, ok: true, t: 3 })).allow,
                                      F01.go(risk: {}, threshold_hook: hook.call({ 'enforced' => true, 'ok' => true, 't' => 4.9 })).allow], [true, true]) &&
      begin
        below = F01.go(risk: {}, threshold_hook: hook.call({ enforced: true, ok: true, t: 2 }))
        unrep = F01.go(risk: {}, threshold_hook: hook.call({ enforced: true, ok: true }))
        lead = 'threshold: threshold hook enforced t='
        tail = ' but the server requires t=3 (below the server-derived threshold; derive t from server-held data)'
        F01.ck('below', [below.allow, below.checks['threshold'], below.reasons.include?("#{lead}2#{tail}")], [false, 'fail', true]) &&
          # the value the hook reported prints as TypeScript String() does: unfloored (1.9), NaN stays NaN
          F01.ck('unfloored', F01.go(risk: {}, threshold_hook: hook.call({ enforced: true, ok: true, t: 1.9 })).reasons.include?("#{lead}1.9#{tail}"), true) &&
          F01.ck('NaN', F01.go(risk: {}, threshold_hook: hook.call({ enforced: true, ok: true, t: Float::NAN })).reasons.include?("#{lead}NaN#{tail}"), true) &&
          F01.ck('a rejecting hook without a reason says rejected', F01.go(risk: {}, threshold_hook: hook.call({ enforced: true, ok: false })).reasons.include?('threshold: rejected'), true) &&
          F01.ck('unreported', [unrep.allow, unrep.reasons.include?("#{lead}unreported#{tail}")], [false, true])
      end &&
      begin
        off = F01.go(risk: {}, threshold_hook: hook.call({ enforced: false }))
        rej = F01.go(risk: {}, threshold_hook: hook.call({ enforced: true, ok: false, reason: 'nope' }))
        boom = F01.go(risk: {}, threshold_hook: ->(_p, _g) { raise NotImplementedError, 'x' })
        F01.ck('not enforced', [off.allow, off.checks['threshold'], off.reasons.include?(none)], [false, 'fail', true]) &&
          F01.ck('rejected', [rej.allow, rej.reasons.include?('threshold: nope'), rej.reasons.include?('threshold: t=3 required and the threshold proof was rejected')], [false, true, true]) &&
          F01.ck('a raising hook', [boom.allow, boom.reasons.include?('threshold: threshold hook error (fail closed)')], [false, true])
      end &&
      F01.ck('a hook below t=1 is not consulted for the rule', F01.go(threshold_hook: hook.call({ enforced: true, ok: false, reason: 'no' })).checks['threshold'], 'fail')
  end

  t('f01 authorize: the budget decides admission, an absent budget is deny-metered, the caution floor only raises') do
    next true unless F01.gate?('authorize.rb', 'risk.rb')

    one = ProvHarness::RISK.merge('reversibility' => 0.5) # r = 0.1: t=1, cost 0.1
    ctx = ->(b) { ->(_p) { { 'budget' => b } } }
    covered = F01.go(risk: one, context: ctx.call({ 'B' => 1, 'tau' => F01::NOW, 'asOf' => F01::NOW }))
    empty = F01.go(risk: one, context: ctx.call({ 'B' => 0, 'tau' => F01::NOW, 'asOf' => F01::NOW }))
    bare = Class.new(AtlasPca::StateStore) { def claim(_k, _c) = AtlasPca::ClaimResult.new(true) }.new
    nobudget_free = F01.go(state_store: bare)
    nobudget_paid = F01.go(state_store: bare, risk: one)
    gone = 'budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge'
    F01.ck('covered', [covered.allow, covered.checks['budget']], [true, 'pass']) && F01.near('covered debit', covered.budget['B'], 0.9) &&
      F01.ck('depleted', [empty.allow, empty.reasons.include?('policy: trust budget depleted: human recharge required'), empty.required_threshold['t']], [false, true, 3]) &&
      F01.ck('depleted is not debited', empty.budget, nil) &&
      F01.ck('a free action needs no budget', [nobudget_free.allow, nobudget_free.checks['budget'], nobudget_free.reasons.include?(gone)], [true, 'not-enforced', true]) &&
      F01.ck('a paid action is deny-metered', [nobudget_paid.allow, nobudget_paid.reasons.include?(gone), nobudget_paid.required_threshold['t']], [false, true, 3]) &&
      F01.ck('a malformed budget is absent', F01.go(risk: one, context: ctx.call({ 'B' => 'x', 'tau' => 1 })).allow, false)
  end
end
