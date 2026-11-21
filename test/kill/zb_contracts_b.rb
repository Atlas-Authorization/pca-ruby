# frozen_string_literal: true

# zb_contracts_b: clause transitions, the contract monitor and the check-and-advance kernel. Builds on the helpers of
# zb_contracts_a.rb.

module MutationKill
  module ZbK
    module_function

    UNK = { 'field' => 'action.params.zz', 'op' => 'eq', 'value' => true }.freeze

    def rpass(cl) = { 'id' => cl['id'], 'kind' => cl['kind'], 'result' => 'pass' }
    def rbad(cl, reason = nil)
      r = { 'id' => cl['id'], 'kind' => cl['kind'], 'result' => 'violated' }
      r['reason'] = reason if reason
      r
    end

    def tr(ok, reason, rows, latch = {}, deadline = {}) = { ok: ok, reason: reason, rows: rows, latch_set: latch, deadline_set: deadline }
    def ev(cl, ctx, state = st, now = NOW) = C.eval_clause(cl, ctx, state, now)
    def flaky(h, plan)
      f = Flaky.new
      h.each { |kk, v| f.store(kk, v) }
      f.plan = plan
      f
    end
  end

  t('zb contracts: eval_clause always, never and precedes') do
    next true unless ZbK.gate?

    k = ZbK
    al = k.always('al', 'ok')
    k.ck('always holds', k.ev(al, k.act('ok')), k.tr(true, nil, [k.rpass(al)]))
    always_msg = 'always-invariant violated (action does not satisfy p)'
    k.ck('always violated', k.ev(al, k.act('no')), k.tr(false, always_msg, [k.rbad(al, always_msg)]))
    ald = al.merge('description' => 'must be ok')
    k.ck('always description', k.ev(ald, k.act('no')), k.tr(false, 'must be ok', [k.rbad(ald, 'must be ok')]))
    k.ck('always description unused when it holds', k.ev(ald, k.act('ok')), k.tr(true, nil, [k.rpass(ald)]))
    alu = al.merge('p' => { 'verb' => 'ok', 'where' => [k::UNK] })
    k.ck('always needs an affirmative match', k.ev(alu, k.act('ok')), k.tr(false, always_msg, [k.rbad(alu, always_msg)]))

    nv = k.never('nv', 'del')
    never_msg = 'never-invariant violated (forbidden action)'
    k.ck('never hits', k.ev(nv, k.act('del')), k.tr(false, never_msg, [k.rbad(nv, never_msg)]))
    k.ck('never misses', k.ev(nv, k.act('x')), k.tr(true, nil, [k.rpass(nv)]))
    nvd = nv.merge('description' => 'no deleting')
    k.ck('never description', k.ev(nvd, k.act('del')), k.tr(false, 'no deleting', [k.rbad(nvd, 'no deleting')]))
    k.ck('never description unused on a miss', k.ev(nvd, k.act('x')), k.tr(true, nil, [k.rpass(nvd)]))
    nvu = nv.merge('p' => { 'verb' => 'del', 'where' => [k::UNK] })
    k.ck('never matches conservatively', k.ev(nvu, k.act('del')), k.tr(false, never_msg, [k.rbad(nvu, never_msg)]))

    pc = k.prec('pc', 'review', 'deploy')
    prec_msg = 'precedence violated (prerequisite p not yet admitted before q)'
    latched = k.st('latched' => { 'pc' => 5 })
    %w[precedes requires_prior].each do |kind|
      c = pc.merge('kind' => kind)
      k.ck("#{kind}: neither", k.ev(c, k.act('read')), k.tr(true, nil, [k.rpass(c)]))
      k.ck("#{kind}: the prerequisite latches", k.ev(c, k.act('review')), k.tr(true, nil, [k.rpass(c)], { 'pc' => k::NOW }))
      k.ck("#{kind}: the prerequisite latches at the given clock", k.ev(c, k.act('review'), k.st, 77), k.tr(true, nil, [k.rpass(c)], { 'pc' => 77 }))
      k.ck("#{kind}: guarded action before the prerequisite", k.ev(c, k.act('deploy')), k.tr(false, prec_msg, [k.rbad(c, prec_msg)]))
      k.ck("#{kind}: guarded action after the prerequisite", k.ev(c, k.act('deploy'), latched), k.tr(true, nil, [k.rpass(c)]))
      k.ck("#{kind}: the prerequisite again keeps the first latch", k.ev(c, k.act('review'), latched), k.tr(true, nil, [k.rpass(c)]))
      k.ck("#{kind}: a latch under another id does not count", k.ev(c, k.act('deploy'), k.st('latched' => { 'zz' => 5 })), k.tr(false, prec_msg, [k.rbad(c, prec_msg)]))
    end
    cd = pc.merge('description' => 'review first')
    k.ck('precedes description', k.ev(cd, k.act('deploy')), k.tr(false, 'review first', [k.rbad(cd, 'review first')]))
    k.ck('precedes description unused when held', k.ev(cd, k.act('deploy'), latched), k.tr(true, nil, [k.rpass(cd)]))
    same = k.prec('same', 'go', 'go')
    k.ck('a violation still reports the latch it would set', k.ev(same, k.act('go')), k.tr(false, prec_msg, [k.rbad(same, prec_msg)], { 'same' => k::NOW }))
    amb_p = pc.merge('p' => { 'verb' => 'review', 'where' => [k::UNK] })
    k.ck('an ambiguous prerequisite does not latch', k.ev(amb_p, k.act('review')), k.tr(true, nil, [k.rpass(amb_p)]))
    amb_q = pc.merge('q' => { 'verb' => 'deploy', 'where' => [k::UNK] })
    k.ck('an ambiguous guarded action is guarded', k.ev(amb_q, k.act('deploy')), k.tr(false, prec_msg, [k.rbad(amb_q, prec_msg)]))
    k.ck('an ambiguous guarded action after the prerequisite', k.ev(amb_q, k.act('deploy'), latched), k.tr(true, nil, [k.rpass(amb_q)]))

    # unknown kinds and a failing clause fail closed
    zz = { 'id' => 'z', 'kind' => 'zz' }
    k.ck('unknown kind', k.ev(zz, k.act('x')), k.tr(false, 'unknown clause kind (fail closed)', [k.rbad(zz, 'unknown clause kind (fail closed)')]))
    boom = k.st('latched' => k::BoomLatched.new)
    k.ck('error', k.ev(pc, k.act('review'), boom), k.tr(false, 'clause evaluation error (fail closed)', [k.rbad(pc, 'clause evaluation error (fail closed)')]))
    k.ck('error on the guarded action too', k.ev(pc, k.act('deploy'), boom), k.tr(false, 'clause evaluation error (fail closed)', [k.rbad(pc, 'clause evaluation error (fail closed)')]))
    true
  end

  t('zb contracts: eval_clause responds_within') do
    next true unless ZbK.gate?

    k = ZbK
    rw = k.rw('rw', 'req', 'resp', 3)
    miss = 'bounded-liveness deadline missed (no q within 3 actions of p)'
    open = ->(n) { k.st('deadlines' => { 'rw' => n }) }
    k.ck('no obligation, unrelated', k.ev(rw, k.act('x')), k.tr(true, nil, [k.rpass(rw)], {}, { 'rw' => nil }))
    k.ck('no obligation, the stimulus opens one', k.ev(rw, k.act('req')), k.tr(true, nil, [k.rpass(rw)], {}, { 'rw' => 3 }))
    k.ck('no obligation, a response alone', k.ev(rw, k.act('resp')), k.tr(true, nil, [k.rpass(rw)], {}, { 'rw' => nil }))
    k.ck('an obligation counts down', k.ev(rw, k.act('x'), open.call(2)), k.tr(true, nil, [k.rpass(rw)], {}, { 'rw' => 1 }))
    k.ck('a longer obligation counts down', k.ev(rw, k.act('x'), open.call(9)), k.tr(true, nil, [k.rpass(rw)], {}, { 'rw' => 8 }))
    k.ck('an exhausted obligation is a violation', k.ev(rw, k.act('x'), open.call(1)), k.tr(false, miss, [k.rbad(rw, miss)]))
    k.ck('the stimulus does not rescue an exhausted obligation', k.ev(rw, k.act('req'), open.call(1)), k.tr(false, miss, [k.rbad(rw, miss)]))
    rwd = rw.merge('description' => 'answer in time')
    k.ck('description', k.ev(rwd, k.act('x'), open.call(1)), k.tr(false, 'answer in time', [k.rbad(rwd, 'answer in time')]))
    k.ck('description unused while on time', k.ev(rwd, k.act('x'), open.call(2)), k.tr(true, nil, [k.rpass(rwd)], {}, { 'rw' => 1 }))
    rwf = k.rw('rw', 'req', 'resp', 3.0)
    k.ck('the window prints like JS', k.ev(rwf, k.act('x'), open.call(1)), k.tr(false, miss, [k.rbad(rwf, miss)]))
    rw10 = k.rw('rw', 'req', 'resp', 10)
    k.ck('the window prints in full', k.ev(rw10, k.act('x'), open.call(1)).fetch(:reason), 'bounded-liveness deadline missed (no q within 10 actions of p)')
    k.ck('a response discharges', k.ev(rw, k.act('resp'), open.call(5)), k.tr(true, nil, [k.rpass(rw)], {}, { 'rw' => nil }))
    k.ck('a response discharges an exhausted obligation', k.ev(rw, k.act('resp'), open.call(1)), k.tr(true, nil, [k.rpass(rw)], {}, { 'rw' => nil }))
    both = k.rw('rw', 'go', 'go', 3)
    k.ck('a response that is also a stimulus opens a fresh obligation', k.ev(both, k.act('go'), open.call(5)), k.tr(true, nil, [k.rpass(both)], {}, { 'rw' => 3 }))
    k.ck('a stimulus keeps the most urgent obligation (carried is smaller)', k.ev(rw, k.act('req'), open.call(2)), k.tr(true, nil, [k.rpass(rw)], {}, { 'rw' => 1 }))
    k.ck('a stimulus keeps the most urgent obligation (carried is one less)', k.ev(rw, k.act('req'), open.call(3)), k.tr(true, nil, [k.rpass(rw)], {}, { 'rw' => 2 }))
    k.ck('a stimulus keeps the most urgent obligation (the window is smaller)', k.ev(rw, k.act('req'), open.call(10)), k.tr(true, nil, [k.rpass(rw)], {}, { 'rw' => 3 }))
    k.ck('a stimulus with a long window', k.ev(rw10, k.act('req'), open.call(2)), k.tr(true, nil, [k.rpass(rw10)], {}, { 'rw' => 1 }))
    k.ck('a stimulus with a long window and no obligation', k.ev(rw10, k.act('req')), k.tr(true, nil, [k.rpass(rw10)], {}, { 'rw' => 10 }))
    amb_q = rw.merge('q' => { 'verb' => 'resp', 'where' => [k::UNK] })
    k.ck('an ambiguous response does not discharge', k.ev(amb_q, k.act('resp'), open.call(5)), k.tr(true, nil, [k.rpass(amb_q)], {}, { 'rw' => 4 }))
    k.ck('an ambiguous response does not rescue an exhausted obligation', k.ev(amb_q, k.act('resp'), open.call(1)), k.tr(false, miss, [k.rbad(amb_q, miss)]))
    amb_p = rw.merge('p' => { 'verb' => 'req', 'where' => [k::UNK] })
    k.ck('an ambiguous stimulus opens an obligation', k.ev(amb_p, k.act('req')), k.tr(true, nil, [k.rpass(amb_p)], {}, { 'rw' => 3 }))
    k.ck('a stimulus under another id leaves the obligation alone', k.ev(rw, k.act('x'), k.st('deadlines' => { 'zz' => 1 })), k.tr(true, nil, [k.rpass(rw)], {}, { 'rw' => nil }))
    true
  end

  t('zb contracts: eval_clause and') do
    next true unless ZbK.gate?

    k = ZbK
    n1 = k.never('n1', 'del')
    a1 = k.always('a1', 'ok')
    never_msg = 'never-invariant violated (forbidden action)'
    always_msg = 'always-invariant violated (action does not satisfy p)'
    both = k.andc('all', [n1, a1])
    k.ck('and: all pass', k.ev(both, k.act('ok')), k.tr(true, nil, [k.rpass(n1), k.rpass(a1)]))
    k.ck('and: the second fails', k.ev(both, k.act('x')), k.tr(false, always_msg, [k.rpass(n1), k.rbad(a1, always_msg)]))
    k.ck('and: the first fails', k.ev(k.andc('all', [n1, k.always('a2', 'del')]), k.act('del')), k.tr(false, never_msg, [k.rbad(n1, never_msg), k.rpass(k.always('a2', 'del'))]))
    k.ck('and: both fail, the first reason wins', k.ev(both, k.act('del')), k.tr(false, never_msg, [k.rbad(n1, never_msg), k.rbad(a1, always_msg)]))
    swapped = k.andc('all', [a1, n1])
    k.ck('and: both fail, order decides', k.ev(swapped, k.act('del')), k.tr(false, always_msg, [k.rbad(a1, always_msg), k.rbad(n1, never_msg)]))
    k.ck('and: a passing first child does not set the reason', k.ev(swapped, k.act('ok')), k.tr(true, nil, [k.rpass(a1), k.rpass(n1)]))
    third = k.andc('all', [k.never('n2', 'zz'), k.never('n3', 'del'), a1])
    k.ck('and: the first failing of three', k.ev(third, k.act('del')).fetch(:reason), never_msg)
    k.ck('and: three rows', k.ev(third, k.act('del')).fetch(:rows).map { |r| r['id'] }, %w[n2 n3 a1])

    pc = k.prec('pc', 'review', 'deploy')
    rw = k.rw('rw', 'req', 'resp', 3)
    mix = k.andc('mix', [pc, rw])
    k.ck('and merges the latches and the deadlines', k.ev(mix, k.act('review')), k.tr(true, nil, [k.rpass(pc), k.rpass(rw)], { 'pc' => k::NOW }, { 'rw' => nil }))
    k.ck('and merges a new obligation', k.ev(mix, k.act('req')), k.tr(true, nil, [k.rpass(pc), k.rpass(rw)], {}, { 'rw' => 3 }))
    rw2 = k.rw('rw2', 'req', 'resp', 5)
    k.ck('and merges several deadlines', k.ev(k.andc('mix', [rw, rw2]), k.act('req')), k.tr(true, nil, [k.rpass(rw), k.rpass(rw2)], {}, { 'rw' => 3, 'rw2' => 5 }))
    nested = k.andc('outer', [k.andc('inner', [n1, pc]), a1])
    k.ck('and nests and flattens the rows', k.ev(nested, k.act('review')), k.tr(false, always_msg, [k.rpass(n1), k.rpass(pc), k.rbad(a1, always_msg)], { 'pc' => k::NOW }))
    k.ck('the and itself has no row', k.ev(nested, k.act('ok')).fetch(:rows).map { |r| r['id'] }, %w[n1 pc a1])
    true
  end

  t('zb contracts: check_contract exact results') do
    next true unless ZbK.gate?

    k = ZbK
    c = k::C
    never_msg = 'never-invariant violated (forbidden action)'
    inv = k.inv('i', 'del')
    cn = k.contract([k.never('n', 'del')], [inv])
    r = c.check_contract(k.act('del'), cn, k.st)
    k.ck('violations in order', r, { 'ok' => false, 'violated' => %w[i n], 'reasons' => ['i: forbidden action', "n: #{never_msg}"],
                                     'evaluated' => [{ 'id' => 'i', 'kind' => 'never', 'result' => 'violated', 'reason' => 'forbidden action' }, k.rbad(k.never('n', 'del'), never_msg)] })
    r = c.check_contract(k.act('x'), cn, k.st)
    k.ck('all clear', r, { 'ok' => true, 'violated' => [], 'reasons' => [], 'evaluated' => [{ 'id' => 'i', 'kind' => 'never', 'result' => 'pass' }, k.rpass(k.never('n', 'del'))] })
    only_inv = k.contract(nil, [inv])
    k.ck('no clauses key', c.check_contract(k.act('x'), only_inv, k.st), { 'ok' => true, 'violated' => [], 'reasons' => [], 'evaluated' => [{ 'id' => 'i', 'kind' => 'never', 'result' => 'pass' }] })
    k.ck('no clauses key, violated', c.check_contract(k.act('del'), only_inv, k.st)['violated'], ['i'])
    only_cl = k.contract([k.never('n', 'del')])
    k.ck('no invariants key', c.check_contract(k.act('x'), only_cl, k.st)['evaluated'], [k.rpass(k.never('n', 'del'))])
    k.ck('empty invariants', c.check_contract(k.act('x'), k.contract([k.never('n', 'del')], []), k.st)['evaluated'], [k.rpass(k.never('n', 'del'))])
    nothing = k.contract
    k.ck('an empty contract', c.check_contract(k.act('x'), nothing, k.st), { 'ok' => true, 'violated' => [], 'reasons' => [], 'evaluated' => [] })

    quiet = k.never('q', 'del').merge('description' => '')
    r = c.check_contract(k.act('del'), k.contract([quiet]), k.st)
    k.ck('an empty description has no reason in the row', r['evaluated'], [{ 'id' => 'q', 'kind' => 'never', 'result' => 'violated' }])
    k.ck('an empty description is summarised as violated', [r['violated'], r['reasons']], [['q'], ['q: violated']])

    # structural failures
    k.ck('invalid contract', c.check_contract(k.act('x'), { 'version' => 2 }, k.st), c.contract_fail('<contract>', 'unsupported version 2'))
    k.ck('invalid contract text', c.check_contract(k.act('x'), { 'version' => 2 }, k.st)['reasons'], ['<contract>: unsupported version 2'])
    k.ck('invalid action', c.check_contract({ 'action' => { 'verb' => 'x' } }, nothing, k.st), c.contract_fail('<action>', 'malformed action'))
    k.ck('invalid action nil', c.check_contract(nil, nothing, k.st)['violated'], ['<action>'])
    k.ck('invalid state', c.check_contract(k.act('x'), nothing, k.st('seq' => -1)), c.contract_fail('<state>', 'malformed monitor state: seq'))
    k.ck('invalid state nil', c.check_contract(k.act('x'), nothing, nil)['reasons'], ['<state>: malformed monitor state'])
    boom_action = Class.new(Hash) { def [](_key) = raise('boom') }.new
    k.ck('monitor error', c.check_contract(boom_action, nothing, k.st), c.contract_fail('<monitor>', 'monitor error (fail closed)'))
    k.ck('monitor error text', c.check_contract(boom_action, nothing, k.st)['reasons'], ['<monitor>: monitor error (fail closed)'])
    # a clause that fails in evaluation is reported, never raised
    boom_state = k.st('latched' => k::BoomLatched.new)
    pc = k.prec('pc', 'review', 'deploy')
    r = c.check_contract(k.act('review'), k.contract([pc]), boom_state)
    k.ck('clause error', [r['ok'], r['violated'], r['reasons']], [false, ['pc'], ['pc: clause evaluation error (fail closed)']])
    # a clause whose evaluation itself raises still yields a row
    fl = ->(plan) { k.contract([k.flaky(k.never('fk', 'del'), plan)]) }
    r = c.check_contract(k.act('x'), fl.call({ 3 => :raise, 4 => :raise }), k.st)
    row = { 'id' => 'fk', 'kind' => 'never', 'result' => 'violated', 'reason' => 'clause evaluation error (fail closed)' }
    k.ck('clause that cannot even be reported', r, { 'ok' => false, 'violated' => ['fk'], 'reasons' => ['fk: clause evaluation error (fail closed)'], 'evaluated' => [row] })
    r = c.check_contract(k.act('x'), fl.call({ 3 => :raise, 4 => :raise, 5 => :nil }), k.st)
    k.ck('clause without a readable kind', r['evaluated'], [row.merge('kind' => 'clause')])
    true
  end

  t('zb contracts: advance_contract inputs, guards and results') do
    next true unless ZbK.gate?

    k = ZbK
    c = k::C
    p = k::P
    now = k::NOW
    never_msg = 'never-invariant violated (forbidden action)'
    pc = k.prec('pc', 'review', 'deploy')
    rw = k.rw('rw', 'req', 'resp', 3)
    nv = k.never('n', 'del')
    ct = k.contract([nv, pc, rw])
    s0 = k.st
    link = lambda do |state, action|
      AtlasPca.hash_canonical({ 'd' => 'atlas-pca/monitor-state-link/v1', 'state' => p.state_digest(state), 'action' => AtlasPca.hash_canonical(action) })
    end

    # success
    a = k.act('review')
    r = c.advance_contract(s0, a, ct)
    verdict = c.check_contract(a, ct, s0)
    nxt = { 'now' => now, 'seq' => 1, 'parent' => link.call(s0, a), 'ledger' => {}, 'latched' => { 'pc' => now } }
    k.ck('success', r, verdict.merge('next' => nxt, 'decidedBy' => 'none'))
    k.ck('success is ok', [r['ok'], r['decidedBy'], r['violated'], r['reasons']], [true, 'none', [], []])
    k.ck('no deadlines key when none are open', r['next'].key?('deadlines'), false)
    r2 = c.advance_contract(r['next'], k.act('deploy'), ct)
    k.ck('the latch persists', [r2['ok'], r2['next']['latched'], r2['next']['seq']], [true, { 'pc' => now }, 2])
    k.ck('the input state is untouched', s0, k.st)
    r = c.advance_contract(s0, k.act('req'), ct)
    k.ck('an obligation is opened', [r['ok'], r['next']['deadlines'], r['next']['latched']], [true, { 'rw' => 3 }, {}])
    r2 = c.advance_contract(r['next'], k.act('x'), ct)
    k.ck('the obligation counts down', r2['next']['deadlines'], { 'rw' => 2 })
    r3 = c.advance_contract(r2['next'], k.act('resp'), ct)
    k.ck('the response discharges it and the key disappears', [r3['ok'], r3['next'].key?('deadlines')], [true, false])
    r4 = c.advance_contract(r['next'], k.act('x'), ct)
    r4 = c.advance_contract(r4['next'], k.act('x'), ct)
    k.ck('the obligation is exhausted', r4['ok'], true)
    r5 = c.advance_contract(r4['next'], k.act('x'), ct)
    k.ck('a missed deadline is a contract violation', [r5['ok'], r5['violated'], r5['decidedBy'], r5['next'].equal?(r4['next'])], [false, ['rw'], 'contract', true])
    k.ck('the missed deadline text', r5['reasons'], ['rw: bounded-liveness deadline missed (no q within 3 actions of p)'])
    orphan = k.st('deadlines' => { 'orphan' => 5 })
    r = c.advance_contract(orphan, k.act('x'), ct)
    k.ck('deadlines of other ids are kept', r['next']['deadlines'], { 'orphan' => 5 })
    r = c.advance_contract(orphan, k.act('req'), ct)
    k.ck('deadlines of other ids are kept beside a new one', r['next']['deadlines'], { 'orphan' => 5, 'rw' => 3 })

    # the clock
    k.ck('default clock', c.advance_contract(s0, k.act('x'), ct)['next']['now'], now)
    k.ck('explicit clock', c.advance_contract(s0, k.act('x'), ct, { 'now' => now + 9 })['next']['now'], now + 9)
    k.ck('nil clock option uses the state clock', c.advance_contract(s0, k.act('x'), ct, { 'now' => nil })['next']['now'], now)
    r = c.advance_contract(s0, k.act('x'), ct, { 'now' => now - 1 })
    verdict_rows = c.check_contract(k.act('x'), ct, s0)['evaluated']
    k.ck('clock regression', r, { 'ok' => false, 'violated' => ['<state>'], 'reasons' => ['<state>: advance failed: clock regression'], 'evaluated' => verdict_rows, 'next' => s0, 'decidedBy' => 'state' })
    k.ck('clock regression keeps the evidence', r['evaluated'].length, 3)

    # head guards
    guard = lambda do |opts, state = s0|
      c.advance_contract(state, k.act('del'), ct, opts)
    end
    base = c.check_contract(k.act('del'), ct, s0)
    stale = { 'ok' => false, 'violated' => ['n', '<state>'], 'reasons' => base['reasons'] + ['<state>: stale state head (seq)'], 'evaluated' => base['evaluated'], 'next' => s0, 'decidedBy' => 'state' }
    k.ck('stale seq', guard.call({ 'expectedSeq' => 1 }), stale)
    k.ck('stale seq: nil head', guard.call({ 'expectedSeq' => nil }), stale)
    k.ck('stale seq: a string', guard.call({ 'expectedSeq' => '0' }), stale)
    k.ck('stale digest', guard.call({ 'expectedStateDigest' => 'x' }), stale.merge('reasons' => base['reasons'] + ['<state>: stale state head (digest)']))
    k.ck('stale digest: nil head', guard.call({ 'expectedStateDigest' => nil })['reasons'].last, '<state>: stale state head (digest)')
    k.ck('a current head passes the guards, the violation then decides', guard.call({ 'expectedSeq' => 0, 'expectedStateDigest' => p.state_digest(s0) }),
         base.merge('next' => s0, 'decidedBy' => 'contract'))
    k.ck('seq is checked before the digest', guard.call({ 'expectedSeq' => 1, 'expectedStateDigest' => 'x' })['reasons'].last, '<state>: stale state head (seq)')
    r = c.advance_contract(nil, k.act('del'), ct, { 'expectedSeq' => 0 })
    k.ck('stale seq on a malformed state, named once', [r['violated'], r['reasons'], r['decidedBy'], r['next']], [['<state>'], ['<state>: malformed monitor state', '<state>: stale state head (seq)'], 'state', nil])
    r = c.advance_contract(5, k.act('del'), ct, { 'expectedSeq' => 0 })
    k.ck('stale seq on a non object state', r['reasons'].last, '<state>: stale state head (seq)')
    r = c.advance_contract(nil, k.act('del'), ct, { 'expectedStateDigest' => 'x' })
    k.ck('stale digest on a malformed state, named once', [r['violated'], r['reasons']], [['<state>'], ['<state>: malformed monitor state', '<state>: stale state head (digest)']])
    r = c.advance_contract(nil, k.act('del'), ct, { 'expectedStateDigest' => '' })
    k.ck('an empty digest never matches an unhashable state', r['reasons'].last, '<state>: stale state head (digest)')
    r = c.advance_contract(nil, k.act('del'), ct, { 'expectedStateDigest' => nil })
    k.ck('a nil digest never matches an unhashable state', r['reasons'].last, '<state>: stale state head (digest)')
    k.ck('a malformed state with no opts', c.advance_contract(nil, k.act('x'), ct), c.check_contract(k.act('x'), ct, nil).merge('next' => nil, 'decidedBy' => 'state'))

    # who decides
    ids = ->(id) { c.advance_contract(s0, k.act('del'), k.contract([k.never(id, 'del')])) }
    k.ck('an ordinary id is the contract', ids.call('n')['decidedBy'], 'contract')
    k.ck('an id that only opens with <', ids.call('<open')['decidedBy'], 'contract')
    k.ck('an id that only closes with >', ids.call('close>')['decidedBy'], 'contract')
    k.ck('an id with the brackets reversed', ids.call('>x<')['decidedBy'], 'contract')
    k.ck('an id inside brackets is structural', ids.call('<x>')['decidedBy'], 'state')
    k.ck('a violation keeps the state', ids.call('n')['next'].equal?(s0), true)
    k.ck('a state problem is structural', c.advance_contract(k.st('seq' => -1), k.act('x'), ct)['decidedBy'], 'state')
    k.ck('an action problem is structural', c.advance_contract(s0, { 'action' => {} }, ct)['violated'], ['<action>'])

    # resulting state invalid
    full = k.st('latched' => (0...1024).to_h { |i| ["k#{i}", now] })
    only_pc = k.contract([k.prec('pc', 'a', 'b')])
    r = c.advance_contract(full, k.act('a'), only_pc)
    k.ck('resulting state invalid', r, { 'ok' => false, 'violated' => ['<state>'], 'reasons' => ['<state>: resulting state invalid: malformed monitor state: too many keys'],
                                         'evaluated' => c.check_contract(k.act('a'), only_pc, full)['evaluated'], 'next' => full, 'decidedBy' => 'state' })
    k.ck('the same latches fit when nothing new is latched', c.advance_contract(full, k.act('x'), only_pc)['ok'], true)

    # failures
    r = c.advance_contract(s0, k.act('x'), ct, nil)
    k.ck('options that are not a hash', r, { 'ok' => false, 'violated' => ['<state>'], 'reasons' => ['<state>: advance error (fail closed)'], 'evaluated' => c.check_contract(k.act('x'), ct, s0)['evaluated'], 'next' => s0, 'decidedBy' => 'state' })
    r = c.advance_contract(s0, k.act('del'), ct, nil)
    k.ck('options that are not a hash, with a violation', [r['violated'], r['reasons'].last], [['n', '<state>'], '<state>: advance error (fail closed)'])
    r = c.advance_contract(s0, k.act('x'), ct, [])
    k.ck('options that are an array', r['reasons'], ['<state>: advance error (fail closed)'])

    # a contract with only invariants (no clauses key) advances
    only_inv = k.contract(nil, [k.inv('i', 'del')])
    r = c.advance_contract(s0, k.act('x'), only_inv)
    k.ck('invariants only', [r['ok'], r['next']['seq'], r['decidedBy']], [true, 1, 'none'])
    k.ck('invariants only, violated', c.advance_contract(s0, k.act('del'), only_inv)['violated'], ['i'])
    cap = { 'id' => 'cap', 'kind' => 'cap', 'when' => { 'verb' => 'pay' }, 'amount' => 'action.params.n', 'max' => 10 }
    r = c.advance_contract(s0, k.act('pay', '/r', { 'n' => 4 }), k.contract(nil, [cap]))
    k.ck('the embedded constitution advances the ledger', r['next']['ledger'], { 'cap' => [{ 't' => now, 'amount' => 4 }] })
    r = c.advance_contract(r['next'], k.act('pay', '/r', { 'n' => 7 }), k.contract(nil, [cap]))
    k.ck('the embedded constitution vetoes', [r['ok'], r['violated'], r['decidedBy']], [false, ['cap'], 'contract'])
    true
  end

  t('zb contracts: a recomputed verdict would differ under an ambient regex budget') do
    next true unless ZbK.gate?

    k = ZbK
    c = k::C
    rx = { 'id' => 'rx', 'kind' => 'never', 'p' => { 'verb' => 'del', 'resource' => 're:/zzz' } }
    ct = k.contract([rx])
    s0 = k.st
    req = AtlasPca::RegexBudget.new(0.02, nil, false)
    AtlasPca.set_regex_budget_provider(-> { req })
    begin
      r = c.advance_contract(s0, k.act('del', '/y'), ct, { 'now' => k::NOW - 1 })
    ensure
      AtlasPca.set_regex_budget_provider(nil)
    end
    # the verdict computed once is reused: the second evaluation of the regex would have been refused (and vetoed)
    k.ck('verdict reused', [r['violated'], r['reasons'], r['decidedBy']], [['<state>'], ['<state>: advance failed: clock regression'], 'state'])
    k.ck('verdict rows reused', r['evaluated'], [{ 'id' => 'rx', 'kind' => 'never', 'result' => 'pass' }])
    true
  end

  t('zb contracts: check_and_advance_contract') do
    next true unless ZbK.gate?

    k = ZbK
    c = k::C
    nv = k.never('n', 'del')
    ct = k.contract([nv])
    s0 = k.st
    ok_adv = c.advance_contract(s0, k.act('x'), ct)
    r = c.check_and_advance_contract(true, s0, k.act('x'), ct)
    k.ck('allowed', r, ok_adv.merge('allow' => true, 'permitted' => true))
    k.ck('allowed advances', r['next']['seq'], 1)
    r = c.check_and_advance_contract(false, s0, k.act('x'), ct)
    k.ck('not permitted', r, { 'ok' => false, 'violated' => [], 'reasons' => ['<permission>: not permitted'], 'evaluated' => ok_adv['evaluated'], 'next' => s0,
                               'decidedBy' => 'contract', 'allow' => false, 'permitted' => false })
    ['yes', 1, nil, 'true', [true]].each do |v|
      r = c.check_and_advance_contract(v, s0, k.act('x'), ct)
      k.ck("permitted #{v.inspect} is not true", [r['allow'], r['permitted'], r['reasons']], [false, false, ['<permission>: not permitted']])
    end
    bad = c.advance_contract(s0, k.act('del'), ct)
    r = c.check_and_advance_contract(true, s0, k.act('del'), ct)
    k.ck('violation', r, bad.merge('allow' => false, 'permitted' => true))
    r = c.check_and_advance_contract(false, s0, k.act('del'), ct)
    k.ck('violation and not permitted: no permission reason is added', r, bad.merge('allow' => false, 'permitted' => false))
    r = c.check_and_advance_contract(true, s0, k.act('x'), ct, { 'expectedSeq' => 5 })
    k.ck('stale head', [r['allow'], r['decidedBy'], r['reasons'].last, r['permitted']], [false, 'state', '<state>: stale state head (seq)', true])
    r = c.check_and_advance_contract(false, s0, k.act('x'), ct, { 'expectedSeq' => 5 })
    k.ck('stale head, not permitted', [r['allow'], r['decidedBy'], r['permitted']], [false, 'state', false])
    true
  end
end
