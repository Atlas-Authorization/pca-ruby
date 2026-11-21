# frozen_string_literal: true

# zc risk: exact results of the risk / trust-budget kernels (AtlasPca::Risk), resolved at call time.
module MutationKill
  module ZCRisk
    module_function

    def r = AtlasPca::Risk
    W = { 'alpha' => 0.25, 'beta' => 0.2, 'gamma' => 0.2, 'delta' => 0.2, 'epsilon' => 0.1, 'zeta' => 0.05 }.freeze
    BEST = { 'semanticDistance' => 0, 'reversibility' => 1, 'blastRadius' => 0, 'taint' => 0, 'confidence' => 1, 'age' => 0 }.freeze
    P = { 'theta1' => 0.25, 'theta2' => 0.6, 'kappa' => 1 }.freeze

    def plan(*nodes) = nodes
    def node(id, pre = nil, post = nil)
      h = { 'id' => id }
      h['pre'] = pre unless pre.nil?
      h['post'] = post unless post.nil?
      h
    end
  end

  t('zc risk: constants') do
    next true unless ZC.gate?('risk.rb')

    r = ZCRisk.r
    ZC.eq('weights', r::WEIGHT_KEYS, %w[alpha beta gamma delta epsilon zeta]) &&
      ZC.eq('inputs', r::INPUT_KEYS, %w[semanticDistance reversibility blastRadius taint confidence age]) &&
      ZC.eq('worst', r::WORST, { 'semanticDistance' => 1, 'reversibility' => 0, 'blastRadius' => 1, 'taint' => 1, 'confidence' => 0, 'age' => 1 }) &&
      ZC.eq('worst frozen', r::WORST.frozen?, true) &&
      ZC.eq('proof for t', r::PROOF_FOR_T, { 1 => 'claim', 2 => 'standard', 3 => 'strong' }) &&
      ZC.eq('proof rank', r::PROOF_RANK, { 'claim' => 0, 'standard' => 1, 'strong' => 2 }) &&
      ZC.eq('pre keys', r::PRE_KEYS, %w[after depends_on requires nodes]) &&
      ZC.eq('post keys', r::POST_KEYS, %w[before enables then next])
  end

  t('zc risk: clamp01, wt and nz keep the exact numeric type and refuse non-finite values') do
    next true unless ZC.gate?('risk.rb')

    r = ZCRisk.r
    ZC.eq('clamp 0.0', r.clamp01(0.0), 0.0) && ZC.eq('clamp 1.0', r.clamp01(1.0), 1.0) && ZC.eq('clamp 0', r.clamp01(0), 0) &&
      ZC.eq('clamp 1', r.clamp01(1), 1) && ZC.eq('clamp neg', r.clamp01(-0.1), 0) && ZC.eq('clamp high', r.clamp01(1.1), 1) &&
      ZC.eq('clamp mid', r.clamp01(0.5), 0.5) &&
      ZC.eq('wt 0.0', r.wt(0.0), 0) && ZC.eq('wt 0', r.wt(0), 0) && ZC.eq('wt pos', r.wt(0.5), 0.5) && ZC.eq('wt int', r.wt(3), 3) &&
      ZC.eq('wt neg', r.wt(-1), 0) && ZC.eq('wt nil', r.wt(nil), 0) && ZC.eq('wt inf', r.wt(Float::INFINITY), 0) &&
      ZC.eq('wt nan', r.wt(Float::NAN), 0) && ZC.eq('wt str', r.wt('1'), 0) && ZC.eq('wt true', r.wt(true), 0) &&
      ZC.eq('nz 0.0', r.nz(0.0), 0) && ZC.eq('nz 0', r.nz(0), 0) && ZC.eq('nz pos', r.nz(0.5), 0.5) && ZC.eq('nz int', r.nz(3), 3) &&
      ZC.eq('nz neg', r.nz(-1), 0) && ZC.eq('nz nil', r.nz(nil), 0) && ZC.eq('nz inf', r.nz(Float::INFINITY), 0) &&
      ZC.eq('nz nan', r.nz(Float::NAN), 0) && ZC.eq('nz str', r.nz('x'), 0) && ZC.eq('nz true', r.nz(true), 0)
  end

  t('zc risk: a missing age is the worst case 1 in the score') do
    next true unless ZC.gate?('risk.rb')

    r = ZCRisk.r
    ZC.near('age missing', r.risk_score(ZCRisk::BEST.merge('age' => nil), ZCRisk::W), 0.05) &&
      ZC.near('age nan', r.risk_score(ZCRisk::BEST.merge('age' => Float::NAN), ZCRisk::W), 0.05) &&
      ZC.near('age 1', r.risk_score(ZCRisk::BEST.merge('age' => 1), ZCRisk::W), 0.05)
  end

  t('zc risk: required_threshold defaults, boundaries and the non-finite worst case') do
    next true unless ZC.gate?('risk.rb')

    r = ZCRisk.r
    p = ZCRisk::P
    ZC.eq('default optimistic', r.required_threshold(0.1, p), { 't' => 1, 'proof' => 'claim', 'optimisticAllowed' => true }) &&
      ZC.eq('irreversible', r.required_threshold(0.1, p, irreversible: true), { 't' => 1, 'proof' => 'claim', 'optimisticAllowed' => false }) &&
      ZC.eq('theta1 boundary', r.required_threshold(0.25, p), { 't' => 1, 'proof' => 'claim', 'optimisticAllowed' => true }) &&
      ZC.eq('theta2 boundary', r.required_threshold(0.6, p), { 't' => 2, 'proof' => 'standard', 'optimisticAllowed' => false }) &&
      ZC.eq('above', r.required_threshold(0.61, p), { 't' => 3, 'proof' => 'strong', 'optimisticAllowed' => false }) &&
      ZC.eq('nan under a wide theta1', r.required_threshold(Float::NAN, { 'theta1' => 1.5, 'theta2' => 2.5 })['t'], 1) &&
      ZC.eq('nil under a wide theta1', r.required_threshold(nil, { 'theta1' => 1.0, 'theta2' => 2.5 })['t'], 1) &&
      ZC.eq('nan is r = 1', r.required_threshold(Float::NAN, { 'theta1' => 0.5, 'theta2' => 1.5 })['t'], 2) &&
      ZC.eq('nan above theta2', r.required_threshold(Float::NAN, { 'theta1' => 0.5, 'theta2' => 0.9 })['t'], 3)
  end

  t('zc risk: escalate_threshold never lowers, keeps the stronger proof object and the exact t') do
    next true unless ZC.gate?('risk.rb')

    r = ZCRisk.r
    std = { 't' => 2, 'proof' => +'standard', 'optimisticAllowed' => false }
    out = r.escalate_threshold(std, 2.0)
    low = { 't' => 1, 'proof' => +'standard', 'optimisticAllowed' => true }
    out2 = r.escalate_threshold(low, 2)
    ZC.eq('equal min_t as a float keeps the integer t', out, { 't' => 2, 'proof' => 'standard', 'optimisticAllowed' => false }) &&
      ZC.same('equal rank keeps the carried proof', out['proof'], std['proof']) &&
      ZC.eq('raised', out2, { 't' => 2, 'proof' => 'standard', 'optimisticAllowed' => false }) &&
      ZC.same('raised keeps the carried proof of equal rank', out2['proof'], low['proof']) &&
      ZC.eq('raised to strong', r.escalate_threshold({ 't' => 1, 'proof' => 'claim', 'optimisticAllowed' => true }, 3),
            { 't' => 3, 'proof' => 'strong', 'optimisticAllowed' => false }) &&
      ZC.eq('never lowers', r.escalate_threshold({ 't' => 3, 'proof' => 'strong', 'optimisticAllowed' => false }, 1),
            { 't' => 3, 'proof' => 'strong', 'optimisticAllowed' => false }) &&
      ZC.eq('a stronger carried proof stays', r.escalate_threshold({ 't' => 1, 'proof' => 'strong', 'optimisticAllowed' => true }, 1),
            { 't' => 1, 'proof' => 'strong', 'optimisticAllowed' => true })
  end

  t('zc risk: leak with a non-finite origin does not drain, age_since_touch edge cases') do
    next true unless ZC.gate?('risk.rb')

    r = ZCRisk.r
    ZC.eq('leak from -inf', r.leak({ 'B' => 1, 'tau' => -Float::INFINITY, 'asOf' => nil }, 5000, 1),
          { 'B' => 1.0, 'tau' => -Float::INFINITY, 'asOf' => 5000 }) &&
      ZC.eq('age half', r.age_since_touch({ 'tau' => 0 }, 1_800_000), 0.5) &&
      ZC.eq('age past the horizon', r.age_since_touch({ 'tau' => 0 }, 7_200_000), 1) &&
      ZC.eq('age now nil', r.age_since_touch({ 'tau' => 0 }, nil), 1) &&
      ZC.eq('age now nan', r.age_since_touch({ 'tau' => 0 }, Float::NAN), 1) &&
      ZC.eq('age tau nil', r.age_since_touch({ 'tau' => nil }, 5), 1) &&
      ZC.eq('age horizon nil', r.age_since_touch({ 'tau' => 0 }, 5, nil), 1) &&
      ZC.eq('age horizon inf', r.age_since_touch({ 'tau' => 0 }, 5, Float::INFINITY), 1) &&
      ZC.eq('age horizon zero, same instant', r.age_since_touch({ 'tau' => 5 }, 5, 0), 1) &&
      ZC.eq('age horizon negative, same instant', r.age_since_touch({ 'tau' => 5 }, 5, -1), 1) &&
      ZC.eq('age horizon negative', r.age_since_touch({ 'tau' => 0 }, 5, -10), 1) &&
      ZC.eq('age horizon one', r.age_since_touch({ 'tau' => 0 }, 0, 1), 0.0) &&
      ZC.eq('age horizon one, half', r.age_since_touch({ 'tau' => 0 }, 1, 2), 0.5)
  end

  t('zc risk: admit_of, admit and the safety bound') do
    next true unless ZC.gate?('risk.rb')

    r = ZCRisk.r
    t3 = { 'admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => false }
    ZC.eq('t1 covered', r.admit_of(1, true), { 'admit' => true, 'needStepUp' => false, 't' => 1, 'metered' => true }) &&
      ZC.eq('t1 uncovered', r.admit_of(1, false), t3) &&
      ZC.eq('t2 covered', r.admit_of(2, true), { 'admit' => false, 'needStepUp' => true, 't' => 2, 'metered' => true }) &&
      ZC.eq('t2 uncovered', r.admit_of(2, false), t3) &&
      ZC.eq('t3 covered', r.admit_of(3, true), t3) && ZC.eq('t3 uncovered', r.admit_of(3, false), t3) &&
      ZC.raises('a non-numeric t is not coerced') { r.admit_of(nil, false) } &&
      ZC.eq('budget equal to the cost admits', r.admit(0.25, { 'B' => 0.25 }, ZCRisk::P), { 'admit' => true, 'needStepUp' => false, 't' => 1, 'metered' => true }) &&
      ZC.eq('budget below the cost steps up', r.admit(0.25, { 'B' => 0.2 }, ZCRisk::P), t3) &&
      ZC.eq('no kappa', r.safety_bound({ 'kappa' => 0, 'bMax' => 5 }), 0) &&
      ZC.eq('negative kappa', r.safety_bound({ 'kappa' => -1, 'bMax' => 5 }), 0) &&
      ZC.eq('bound', r.safety_bound({ 'kappa' => 2, 'bMax' => 1 }), 0.5) &&
      ZC.eq('negative bMax', r.safety_bound({ 'kappa' => 2, 'bMax' => -3 }), 0.0)
  end

  t('zc risk: sub budgets and consolidated debits at their exact boundaries') do
    next true unless ZC.gate?('risk.rb')

    r = ZCRisk.r
    par = { 'B' => 2, 'tau' => 1, 'asOf' => nil }
    ZC.eq('zero allocation', r.sub_budget(par, 0), { 'ok' => true, 'sub' => { 'B' => 0, 'tau' => 1, 'asOf' => 1 } }) &&
      ZC.eq('all of it', r.sub_budget(par, 2), { 'ok' => true, 'sub' => { 'B' => 2, 'tau' => 1, 'asOf' => 1 } }) &&
      ZC.eq('asOf is kept', r.sub_budget({ 'B' => 2, 'tau' => 1, 'asOf' => 7 }, 1), { 'ok' => true, 'sub' => { 'B' => 1, 'tau' => 1, 'asOf' => 7 } }) &&
      ZC.eq('negative', r.sub_budget(par, -1), { 'ok' => false, 'reason' => 'allocation must be finite and >= 0' }) &&
      ZC.eq('nan', r.sub_budget(par, Float::NAN), { 'ok' => false, 'reason' => 'allocation must be finite and >= 0' }) &&
      ZC.eq('too much', r.sub_budget(par, 3), { 'ok' => false, 'reason' => 'allocation exceeds parent remaining budget' }) &&
      begin
        sub = { 'B' => 1, 'tau' => 1, 'asOf' => 1 }
        pa = { 'B' => 2, 'tau' => 1, 'asOf' => 1 }
        ZC.eq('sub exactly covers', r.debit_consolidated(pa, sub, 1),
              { 'ok' => true, 'parent' => { 'B' => 1, 'tau' => 1, 'asOf' => 1 }, 'sub' => { 'B' => 0, 'tau' => 1, 'asOf' => 1 } }) &&
          ZC.eq('parent exactly covers', r.debit_consolidated({ 'B' => 1, 'tau' => 1, 'asOf' => 1 }, { 'B' => 2, 'tau' => 1, 'asOf' => 1 }, 1),
                { 'ok' => true, 'parent' => { 'B' => 0, 'tau' => 1, 'asOf' => 1 }, 'sub' => { 'B' => 1, 'tau' => 1, 'asOf' => 1 } }) &&
          ZC.eq('sub short', r.debit_consolidated(pa, { 'B' => 0.5 }, 1), { 'ok' => false, 'reason' => 'sub-agent budget insufficient' }) &&
          ZC.eq('parent short', r.debit_consolidated({ 'B' => 0.5 }, sub, 1), { 'ok' => false, 'reason' => 'parent budget insufficient' })
      end &&
      ZC.eq('path exactly covers', r.debit_consolidated_path([{ 'B' => 1 }], 1), { 'ok' => true, 'nodes' => [{ 'B' => 0 }] }) &&
      ZC.eq('path short', r.debit_consolidated_path([{ 'B' => 5 }, { 'B' => 0.5 }], 1),
            { 'ok' => false, 'reason' => 'budget node at depth 1 insufficient (need 1, have 0.5)' }) &&
      ZC.eq('path short, JS number printing', r.debit_consolidated_path([{ 'B' => 1e-7 }], 1e21),
            { 'ok' => false, 'reason' => 'budget node at depth 0 insufficient (need 1e+21, have 1e-7)' })
  end

  t('zc risk: js_num prints like JavaScript String(n)') do
    next true unless ZC.gate?('risk.rb')

    r = ZCRisk.r
    [[1.0, '1'], [5, '5'], [2.5, '2.5'], [-0.0, '0'], [0, '0'], [1e21, '1e+21'], [1e20, '100000000000000000000'], [1e-7, '1e-7'],
     [0.000015, '0.000015'], [10**21, '1e+21'], [10**20, '100000000000000000000'], [-3.0, '-3'], [Float::NAN, 'NaN'], [Float::INFINITY, 'Infinity'], [-Float::INFINITY, '-Infinity'],
     [123_456_789.123, '123456789.123'], ['abc', 'abc'], [nil, '']].each { |x, want| ZC.eq("js_num #{x.inspect}", r.js_num(x), want) }
    true
  end

  t('zc risk: to_fixed3 rounds half up on the exact value') do
    next true unless ZC.gate?('risk.rb')

    r = ZCRisk.r
    ZC.eq('tie', r.to_fixed3(0.0625), '0.063') && ZC.eq('zero', r.to_fixed3(0), '0.000') && ZC.eq('one', r.to_fixed3(1), '1.000') &&
      ZC.eq('half', r.to_fixed3(0.5), '0.500') && ZC.eq('eighth', r.to_fixed3(0.125), '0.125') &&
      ZC.eq('exact rational input', r.to_fixed3('0.0625'), '0.063') &&
      ZC.eq('thousandths', r.to_fixed3(0.999), '0.999') && ZC.eq('integer floor, out of the unit range', r.to_fixed3(-0.001), '-1.999')
  end

  t('zc risk: riskier merges per key, never replaces with a non-finite value and never aliases its input') do
    next true unless ZC.gate?('risk.rb')

    r = ZCRisk.r
    a = { 'taint' => 0.3, 'reversibility' => 0.8, 'confidence' => 0.2, 'semanticDistance' => 0.1 }
    a0 = Marshal.load(Marshal.dump(a))
    b = { 'taint' => 0.1, 'reversibility' => 0.3, 'confidence' => 0.9, 'semanticDistance' => 0.4, 'age' => 0.6, 'blastRadius' => Float::NAN }
    out = r.riskier(a, b)
    ZC.eq('merge', out, { 'taint' => 0.3, 'reversibility' => 0.3, 'confidence' => 0.2, 'semanticDistance' => 0.4, 'age' => 0.6 }) &&
      ZC.eq('input untouched', a, a0) && (!out.equal?(a) || raise('riskier returned its input')) &&
      ZC.eq('higher second', r.riskier({ 'blastRadius' => 0.2 }, { 'blastRadius' => 0.9 }), { 'blastRadius' => 0.9 }) &&
      ZC.eq('higher second reversibility is not taken', r.riskier({ 'reversibility' => 0.2 }, { 'reversibility' => 0.9 }), { 'reversibility' => 0.2 }) &&
      ZC.eq('lower second confidence', r.riskier({ 'confidence' => 0.9 }, { 'confidence' => 0.2 }), { 'confidence' => 0.2 }) &&
      ZC.eq('non-finite first is replaced', r.riskier({ 'reversibility' => nil }, { 'reversibility' => 0.4 }), { 'reversibility' => 0.4 }) &&
      ZC.eq('non-finite first is replaced (taint)', r.riskier({ 'taint' => Float::NAN }, { 'taint' => 0.4 })['taint'], 0.4) &&
      ZC.eq('non-finite second is ignored', r.riskier({ 'taint' => nil }, { 'taint' => 'x' }), { 'taint' => nil }) &&
      ZC.eq('a missing key of the first', r.riskier({}, { 'taint' => 0.2 }), { 'taint' => 0.2 }) &&
      ZC.eq('a non-finite new key is not added', r.riskier({ 'taint' => 1 }, { 'age' => Float::INFINITY }), { 'taint' => 1 }) &&
      ZC.eq('unknown keys take the max', r.riskier({ 'zzz' => 1 }, { 'zzz' => 2 }), { 'zzz' => 2 }) &&
      ZC.eq('both nil', r.riskier(nil, nil), nil) &&
      ZC.same('only the second', r.riskier(nil, b), b) && ZC.same('only the first', r.riskier(a, nil), a)
  end

  t('zc risk: refs_of collects only strings from the named keys') do
    next true unless ZC.gate?('risk.rb')

    r = ZCRisk.r
    keys = r::PRE_KEYS
    ZC.eq('string', r.refs_of('x', keys), ['x']) &&
      ZC.eq('array', r.refs_of(['a', 5, nil, 'b', :c], keys), %w[a b]) &&
      ZC.eq('hash', r.refs_of({ 'after' => 'a', 'depends_on' => ['b', 7, 'c'], 'requires' => 5, 'nodes' => nil, 'other' => 'z' }, keys), %w[a b c]) &&
      ZC.eq('hash value', r.refs_of({ 'after' => { 'x' => 1 } }, keys), []) &&
      ZC.eq('nil', r.refs_of(nil, keys), []) && ZC.eq('integer', r.refs_of(5, keys), []) &&
      ZC.eq('post keys', r.refs_of({ 'before' => 'a', 'enables' => ['b'], 'then' => 'c', 'next' => ['d'], 'after' => 'no' }, r::POST_KEYS), %w[a b c d])
  end

  t('zc risk: plan_geodesic builds undirected hop edges from pre / post references') do
    next true unless ZC.gate?('risk.rb')

    r = ZCRisk.r
    nd = ZCRisk.method(:node)
    ids = %w[a b c d]
    plain = ids.map { |i| nd.call(i) }
    ZC.eq('not an array', r.plan_geodesic(nil, 'a', 'b'), 1) &&
      ZC.eq('unknown node', r.plan_geodesic(plain, 'a', 'zzz'), 1) && ZC.eq('unknown from', r.plan_geodesic(plain, 'zzz', 'a'), 1) &&
      ZC.eq('same node', r.plan_geodesic(plain, 'b', 'b'), 0) &&
      ZC.eq('no edges: index distance', r.plan_geodesic(plain, 'a', 'c'), 2 / 3.0) &&
      ZC.eq('no edges: ends', r.plan_geodesic(plain, 'a', 'd'), 1.0) &&
      ZC.eq('no edges: adjacent', r.plan_geodesic(plain, 'c', 'b'), 1 / 3.0) &&
      ZC.eq('a self reference is no edge (pre)', r.plan_geodesic([nd.call('a', ['a']), nd.call('b'), nd.call('c'), nd.call('d')], 'a', 'c'), 2 / 3.0) &&
      ZC.eq('a self reference is no edge (post)', r.plan_geodesic([nd.call('a', nil, ['a']), nd.call('b'), nd.call('c'), nd.call('d')], 'a', 'c'), 2 / 3.0) &&
      begin
        pre_only = [nd.call('a'), nd.call('b'), nd.call('c'), nd.call('d', { 'depends_on' => 'a' })]
        ZC.eq('pre edge', r.plan_geodesic(pre_only, 'a', 'd'), 1 / 3.0) && ZC.eq('pre edge, reversed', r.plan_geodesic(pre_only, 'd', 'a'), 1 / 3.0) &&
          ZC.eq('pre edge: unreachable', r.plan_geodesic(pre_only, 'a', 'b'), 1) && ZC.eq('pre edge: both unreachable', r.plan_geodesic(pre_only, 'b', 'c'), 1)
      end &&
      begin
        post_only = [nd.call('a', nil, { 'then' => ['d'] }), nd.call('b'), nd.call('c'), nd.call('d')]
        ZC.eq('post edge', r.plan_geodesic(post_only, 'a', 'd'), 1 / 3.0) && ZC.eq('post edge, reversed', r.plan_geodesic(post_only, 'd', 'a'), 1 / 3.0) &&
          ZC.eq('post edge: unreachable', r.plan_geodesic(post_only, 'b', 'c'), 1)
      end &&
      ZC.eq('unknown references are skipped',
            r.plan_geodesic([nd.call('a', nil, %w[zzz d]), nd.call('b', ['nope']), nd.call('c'), nd.call('d')], 'a', 'd'), 1 / 3.0) &&
      begin
        five = [nd.call('a', nil, ['c']), nd.call('b'), nd.call('c', nil, ['e']), nd.call('d'), nd.call('e', ['c'])]
        ZC.eq('two hops, duplicated edge', r.plan_geodesic(five, 'a', 'e'), 0.5) && ZC.eq('one hop', r.plan_geodesic(five, 'a', 'c'), 1 / 4.0) &&
          ZC.eq('two hops, reversed', r.plan_geodesic(five, 'e', 'a'), 0.5) && ZC.eq('isolated', r.plan_geodesic(five, 'a', 'd'), 1)
      end
  end
end
