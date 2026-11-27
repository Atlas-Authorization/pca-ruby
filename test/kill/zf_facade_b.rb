# frozen_string_literal: true

# zf: compile_policy and the dollar risk claim of the facade (helpers in zf_facade_a.rb). Reference: packages/pca/src/facade.ts
# compilePolicy, riskFor (Number(params[field]) is ECMAScript ToNumber).

module MutationKill
  t('zf facade compile: a $0 cap on a reversible verb of the caller catalog') do
    next true unless ZF.gate?

    lim = { 'send' => '$0' }
    pol = AtlasPca.compile_policy({ 'pay' => ['send'] }, lim, catalog: ZF.cat, now: 1)
    where = [{ 'field' => 'action.params.amount', 'op' => 'lte', 'value' => 0 }, { 'field' => 'action.params.amount', 'op' => 'gte', 'value' => 0 }]
    ZF.eq('actions', pol['actions'].map { |a| a['verb'] }, ['pay.send']) &&
      ZF.eq('predicates', pol['predicates'], [{ 'verb' => 'pay.send', 'resource' => 'acct:*', 'where' => where }]) &&
      ZF.eq('caveats', pol['caveats'], [{ 'type' => 'reversibility_max', 'class' => 'reversible' }]) &&
      ZF.eq('risk policy', pol['riskPolicy'], { 'weights' => ZF.dollar_weights, 'theta1' => 1, 'theta2' => 1, 'kappa' => 1, 'lambda' => 0,
                                                'rho' => 0.5, 'bMax' => 1 }) &&
      ZF.eq('model', pol['budgetModel'], 'dollars') &&
      ZF.eq('limits', pol['limits'], { 'pay.send' => { 'amount' => 0, 'unit' => 'usd' } }) &&
      ZF.eq('input limits', pol['inputLimits'], lim) && (!pol['inputLimits'].equal?(lim) || raise('inputLimits must be a copy')) &&
      ZF.eq('approximations', pol['approximations'], [])
  end

  t('zf facade compile: a cap below 1, an irreversible grant beside it, an alias key') do
    next true unless ZF.gate?

    half = AtlasPca.compile_policy({ 'pay' => ['send'] }, { 'pay.send' => '$0.5' }, catalog: ZF.cat, now: 1)['riskPolicy']
    pol = AtlasPca.compile_policy({ 'pay' => %w[send cancel] }, { 'send' => '$4', 'void' => '$6' }, catalog: ZF.cat, now: 1)
    ZF.eq('$0.5', [half['kappa'], half['bMax'], half['theta1'], half['theta2']], [0.5, 0.5, 1, 1]) &&
      ZF.eq('irreversible', pol['riskPolicy'], { 'weights' => ZF.dollar_weights, 'theta1' => 0.25, 'theta2' => 0.6, 'kappa' => 6,
                                                 'lambda' => 0, 'rho' => 0.5, 'bMax' => 10 }) &&
      ZF.eq('class', pol['caveats'], [{ 'type' => 'reversibility_max', 'class' => 'irreversible' }]) &&
      ZF.eq('limits', pol['limits'].keys, %w[pay.send pay.cancel]) &&
      # the built-in catalog: no own resource is '*'
      ZF.eq('builtin resource', AtlasPca.compile_policy({ 'files' => ['read'] }, nil, now: 1)['predicates'],
            [{ 'verb' => 'files.read', 'resource' => '*' }])
  end

  t('zf facade compile: budget_model dollars / risk override the automatic choice') do
    next true unless ZF.gate?

    d = AtlasPca.compile_policy({ 'files' => ['read'] }, nil, budget_model: 'dollars', now: 1)
    r = AtlasPca.compile_policy({ 'stripe' => ['refund'] }, { 'refund' => '$50' }, budget_model: 'risk', now: 1)
    a = AtlasPca.compile_policy({ 'files' => ['read'] }, nil, now: 1)
    ZF.eq('dollars without a $ limit', [d['budgetModel'], d['riskPolicy']], ['dollars', AtlasPca::DEFAULT_RISK_POLICY]) &&
      ZF.eq('risk with a $ limit', [r['budgetModel'], r['riskPolicy']], ['risk', AtlasPca::DEFAULT_RISK_POLICY]) &&
      ZF.eq('auto', a['budgetModel'], 'risk') &&
      # the default policy is a copy, weights included (a caller editing it must not change the default)
      [d, r, a].all? { |p|
        !p['riskPolicy'].equal?(AtlasPca::DEFAULT_RISK_POLICY) && !p['riskPolicy']['weights'].equal?(AtlasPca::DEFAULT_RISK_POLICY['weights']) &&
          !p['riskPolicy'].frozen? || raise('the derived risk policy shares the default')
      }
  end

  t('zf facade compile: a risk_policy override merges over the derived one, weights member by member') do
    next true unless ZF.gate?

    rp = AtlasPca.compile_policy({ 'files' => ['read'] }, nil, risk_policy: { 'theta1' => 0.1, 'weights' => { 'alpha' => 0.5 } }, now: 1)['riskPolicy']
    want = AtlasPca::DEFAULT_RISK_POLICY.merge('theta1' => 0.1, 'weights' => AtlasPca::DEFAULT_RISK_POLICY['weights'].merge('alpha' => 0.5))
    ZF.eq('merged', rp, want) &&
      ZF.eq('no weights', AtlasPca.compile_policy({ 'files' => ['read'] }, nil, risk_policy: { 'rho' => 0.25 }, now: 1)['riskPolicy'],
            AtlasPca::DEFAULT_RISK_POLICY.merge('rho' => 0.25))
  end

  t('zf facade compile: periods become the grant lifetime and count limits rate caveats') do
    next true unless ZF.gate?

    rev = { 'type' => 'reversibility_max', 'class' => 'reversible' }
    c = ->(l) { AtlasPca.compile_policy({ 'files' => ['read'] }, l, now: 1) }
    sec = c.call({ 'read' => '1/s' })
    hour = c.call({ 'read' => '10/hour' })
    plain = c.call({ 'read' => '3' })
    ZF.eq('1/s', sec['caveats'], [rev, { 'type' => 'expires', 'at' => 1001 }, { 'type' => 'rate', 'max' => 1, 'per_secs' => 1 }]) &&
      ZF.eq('10/hour', hour['caveats'], [rev, { 'type' => 'expires', 'at' => 3_600_001 }, { 'type' => 'rate', 'max' => 10, 'per_secs' => 3600 }]) &&
      ZF.eq('a count without a period is no rate', plain['caveats'], [rev]) &&
      ZF.eq('limits', plain['limits'], { 'files.read' => { 'amount' => 3, 'unit' => 'count' } }) &&
      # a period under a second still gives a window of at least one second (Math.max(1, Math.round(ms / 1000)))
      ZF.seam(parse_limit: ->(_s) { { 'amount' => 5, 'unit' => 'count', 'periodMs' => 1 } }) {
        ZF.eq('1 ms', c.call({ 'read' => 'x' })['caveats'], [rev, { 'type' => 'expires', 'at' => 2 }, { 'type' => 'rate', 'max' => 5, 'per_secs' => 1 }])
      } &&
      ZF.seam(parse_limit: ->(_s) { { 'amount' => 5, 'unit' => 'count', 'periodMs' => 2500 } }) {
        ZF.eq('2.5 s rounds up', c.call({ 'read' => 'x' })['caveats'][2], { 'type' => 'rate', 'max' => 5, 'per_secs' => 3 })
      }
  end

  t('zf facade compile: no now is the wall clock') do
    next true unless ZF.gate?

    t0 = (Time.now.to_f * 1000).to_i
    pol = AtlasPca.compile_policy({ 'files' => ['read'] }, { 'read' => '1/day' })
    t1 = (Time.now.to_f * 1000).to_i
    at = pol['caveats'][1]['at']
    at.is_a?(Integer) && at >= t0 + ZF::DAY && at <= t1 + ZF::DAY || raise("expires at #{at.inspect}, want #{t0 + ZF::DAY}..#{t1 + ZF::DAY}")
  end

  t('zf facade compile: no limits, or a limits value that is not an object, is no limit') do
    next true unless ZF.gate?

    [nil, 5, true].all? do |l|
      pol = AtlasPca.compile_policy({ 'files' => ['read'] }, l, now: 1)
      ZF.eq("limits #{l.inspect}", [pol['limits'], pol['inputLimits'], pol['caveats'].length], [{}, {}, 1])
    end
  end

  t('zf facade compile: only String keys name a limit; a granted action name is its JS string') do
    next true unless ZF.gate?

    pol = AtlasPca.compile_policy({ 'sym' => ['a'] }, { sym: '3' }, catalog: ZF.cat, now: 1)
    ZF.eq('non-String alias', pol['limits'], {}) &&
      ZF.eq('null action', AtlasPca.compile_policy({ 'files' => [nil] }, nil, now: 1)['actions'][0]['verb'], 'files.null') &&
      ZF.eq('unknown class', AtlasPca.compile_policy({ 'odd' => ['x'] }, nil, catalog: ZF.cat, now: 1)['caveats'],
            [{ 'type' => 'reversibility_max', 'class' => 'reversible' }])
  end

  t('zf facade compile: a dollar limit with a period is listed as an approximation, amount as a JS number') do
    next true unless ZF.gate?

    pol = AtlasPca.compile_policy({ 'stripe' => ['refund'] }, { 'refund' => '$1000000000000000000000/day' }, now: 1)
    ZF.eq('approximations', pol['approximations'],
          ['stripe.refund: $1e+21/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap'])
  end

  # ---- ECMAScript Number(params[field]) and the risk claim --------------------------------------------------------------

  t('zf facade js_to_number: ToNumber of each JSON value') do
    next true unless ZF.gate?

    n = ->(v) { AtlasPca.js_to_number({ 'a' => v }, 'a') }
    cases = { nil => 0.0, true => 1.0, false => 0.0, 5 => 5.0, 2.5 => 2.5, '12' => 12.0, " 12\n" => 12.0, '' => 0.0, '  ' => 0.0,
              '0x1f' => 31.0, '0X1F' => 31.0, '0o17' => 15.0, '0O17' => 15.0, '0b101' => 5.0, '0B11' => 3.0,
              'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY, '+Infinity' => Float::INFINITY,
              '5.' => 5.0, '5.e2' => 500.0, '-5.E1' => -50.0, '.5' => 0.5, '-.5' => -0.5, '+.5' => 0.5, '+5' => 5.0, '1e3' => 1000.0,
              '00.10' => 0.1, ['7'] => 7.0, [] => 0.0, [' 8 '] => 8.0 }
    cases.all? { |v, want| ZF.eq("Number(#{v.inspect})", n.call(v), want) } &&
      ['abc', '0x', '-0x1f', '1_000', 'Infinityx', ['1', '2'], {}, '0b2'].all? { |v| ZF.nan("Number(#{v.inspect})", n.call(v)) } &&
      ZF.nan('absent', AtlasPca.js_to_number({}, 'a')) && ZF.nan('nil params', AtlasPca.js_to_number(nil, 'a')) &&
      ZF.nan('array params', AtlasPca.js_to_number([1], 'a'))
  end

  t('zf facade js_clamp01: Math.max(0, Math.min(1, x)) keeps NaN') do
    next true unless ZF.gate?

    ZF.nan('NaN', AtlasPca.js_clamp01(Float::NAN)) &&
      ZF.eq('values', [1.5, -0.5, 0.25, 2, -3, 0].map { |x| AtlasPca.js_clamp01(x) }.map(&:to_f), [1.0, 0.0, 0.25, 1.0, 0.0, 0.0])
  end

  t('zf facade risk claim: dollars model reads the amount against kappa, else the blast radius; an override wins') do
    next true unless ZF.gate?

    spec = { 'verb' => 'pay.send', 'blastRadius' => 0.3, 'amountField' => 'amount' }
    plain = { 'verb' => 'pay.note', 'blastRadius' => 0.2 }
    pol = ->(model, kappa) { { 'budgetModel' => model, 'riskPolicy' => { 'kappa' => kappa } } }
    r = ->(p, params, over = nil, s = spec) { AtlasPca.facade_risk_for(p, s, params, over).to_f }
    d = pol.call('dollars', 500)
    [[pol.call('risk', 1), { 'amount' => 100 }, nil, 0.3], [d, { 'amount' => 125 }, nil, 0.25], [d, {}, nil, 0.3],
     [d, { 'amount' => 'abc' }, nil, 0.3], [d, { 'amount' => 'Infinity' }, nil, 0.3], [d, { 'amount' => nil }, nil, 0.0],
     [d, { 'amount' => -5 }, nil, 0.0], [pol.call('dollars', 0.5), { 'amount' => 0.25 }, nil, 0.5],
     [pol.call('dollars', 0), { 'amount' => 5 }, nil, 0.3], [pol.call('dollars', -1), { 'amount' => 5 }, nil, 0.3],
     [d, { 'amount' => 5 }, 1.5, 1.0], [d, { 'amount' => 5 }, 0.5, 0.5], [d, { 'amount' => 5 }, 2, 1.0], [d, { 'amount' => 5 }, 0, 0.0],
     [d, { 'amount' => 5 }, -1, 0.0], [d, { 'amount' => 5 }, '0.9', 0.01], [d, { 'amount' => 5 }, true, 0.01]].each_with_index.all? { |(p, params, over, want), i|
      ZF.eq("case #{i}", r.call(p, params, over), want)
    } && ZF.eq('no amount field', r.call(d, { nil => 0, 'amount' => 0 }, nil, plain), 0.2) &&
      ZF.nan('override NaN', AtlasPca.facade_risk_for(d, spec, {}, Float::NAN))
  end
end
