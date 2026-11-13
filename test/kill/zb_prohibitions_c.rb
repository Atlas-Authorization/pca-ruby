# frozen_string_literal: true

# zb_prohibitions_c: per-kind evaluation, the monitor result, the state transition, safety evidence (plain and signed) and
# the check-and-advance kernel of the prohibition engine. Builds on the helpers of zb_prohibitions_b.rb.

module MutationKill
  module ZbQ
    module_function

    CAP = { 'id' => 'c', 'kind' => 'cap', 'when' => { 'verb' => 'pay' }, 'amount' => 'action.params.n', 'max' => 100 }.freeze
    RATE = { 'id' => 'r', 'kind' => 'rate', 'when' => { 'verb' => 'send' }, 'max' => 2, 'window_secs' => 60 }.freeze
    NA = { 'id' => 'na', 'kind' => 'never_after', 'after' => { 'verb' => 'open' }, 'forbid' => { 'verb' => 'close' } }.freeze
    RP = { 'id' => 'rp', 'kind' => 'require_prior', 'when' => { 'verb' => 'deploy' }, 'prior' => { 'verb' => 'review' } }.freeze
    RA = { 'id' => 'ra', 'kind' => 'require_approval_over', 'when' => { 'verb' => 'pay' }, 'amount' => 'action.params.n', 'threshold' => 10,
           'approved' => [{ 'field' => 'env.ok', 'op' => 'eq', 'value' => true }] }.freeze
    NU = { 'id' => 'nu', 'kind' => 'never_unless', 'when' => { 'verb' => 'del' }, 'unless' => [{ 'field' => 'env.human', 'op' => 'eq', 'value' => true }] }.freeze
    NV = { 'id' => 'nv', 'kind' => 'never', 'when' => { 'verb' => 'boom' } }.freeze

    def pay(n, env = nil) = act('pay', '/r', n.nil? ? {} : { 'n' => n }, env)
  end

  t('zb prohibitions: eval_one never, never_unless and cap rows') do
    next true unless ZbQ.gate?

    q = ZbQ
    q.ck('never hits', q.row(q::NV, q.act('boom')), q.bad_row(q::NV, 'forbidden action'))
    q.ck('never misses', q.row(q::NV, q.act('other')), q.pass_row(q::NV))
    d = q::NV.merge('description' => 'custom words')
    q.ck('never description', q.row(d, q.act('boom')), q.bad_row(d, 'custom words'))
    q.ck('never description unused when it passes', q.row(d, q.act('other')), q.pass_row(d))
    q.ck('never result text', q.chk(q::NV, q.act('boom')), { 'ok' => false, 'violated' => ['nv'], 'reasons' => ['nv: forbidden action'], 'evaluated' => [q.bad_row(q::NV, 'forbidden action')] })
    q.ck('never ok result', q.chk(q::NV, q.act('other')), { 'ok' => true, 'violated' => [], 'reasons' => [], 'evaluated' => [q.pass_row(q::NV)] })

    q.ck('never_unless miss', q.row(q::NU, q.act('read')), q.pass_row(q::NU))
    q.ck('never_unless held', q.row(q::NU, q.act('del', '/r', nil, { 'human' => true })), q.pass_row(q::NU))
    q.ck('never_unless not held', q.row(q::NU, q.act('del', '/r', nil, { 'human' => false })), q.bad_row(q::NU, 'forbidden without required condition'))
    q.ck('never_unless unresolvable', q.row(q::NU, q.act('del')), q.bad_row(q::NU, 'forbidden without required condition'))
    nd = q::NU.merge('description' => 'ask a human')
    q.ck('never_unless description', q.row(nd, q.act('del')), q.bad_row(nd, 'ask a human'))
    q.ck('never_unless description unused when held', q.row(nd, q.act('del', '/r', nil, { 'human' => true })), q.pass_row(nd))
    two = q::NU.merge('unless' => [{ 'field' => 'env.human', 'op' => 'eq', 'value' => true }, { 'field' => 'env.b', 'op' => 'eq', 'value' => true }])
    q.ck('never_unless needs every exception', q.row(two, q.act('del', '/r', nil, { 'human' => true, 'b' => false })), q.bad_row(two, 'forbidden without required condition'))
    q.ck('never_unless every exception holds', q.row(two, q.act('del', '/r', nil, { 'human' => true, 'b' => true })), q.pass_row(two))

    led = ->(entries) { q.st('ledger' => { 'c' => entries }) }
    q.ck('cap exactly the max', q.row(q::CAP, q.pay(50), led.call([q.entry(q::NOW - 1, 50)])), q.pass_row(q::CAP))
    q.ck('cap one over', q.row(q::CAP, q.pay(51), led.call([q.entry(q::NOW - 1, 50)])), q.bad_row(q::CAP, 'cap exceeded: 50 + 51 > 100'))
    q.ck('cap fractions print like JS', q.row(q::CAP.merge('max' => 1), q.pay(1.5), led.call([q.entry(q::NOW - 1, 0.5)])), q.bad_row(q::CAP.merge('max' => 1), 'cap exceeded: 0.5 + 1.5 > 1'))
    q.ck('cap max fraction prints', q.row(q::CAP.merge('max' => 2.5), q.pay(3)), q.bad_row(q::CAP.merge('max' => 2.5), 'cap exceeded: 0 + 3 > 2.5'))
    q.ck('cap sums every entry', q.row(q::CAP, q.pay(1), led.call([q.entry(q::NOW - 3, 40), q.entry(q::NOW - 2, 40), q.entry(q::NOW - 1, 20)])), q.bad_row(q::CAP, 'cap exceeded: 100 + 1 > 100'))
    q.ck('cap miss', q.row(q::CAP, q.act('read', '/r', { 'n' => 1000 })), q.pass_row(q::CAP))
    q.ck('cap miss does not read the amount', q.row(q::CAP, q.act('read')), q.pass_row(q::CAP))
    w = q::CAP.merge('window_secs' => 10)
    q.ck('cap window ignores old entries', q.row(w, q.pay(100), led.call([q.entry(q::NOW - 10_000, 99)])), q.pass_row(w))
    q.ck('cap window counts recent entries', q.row(w, q.pay(100), led.call([q.entry(q::NOW - 9995, 1)])), q.bad_row(w, 'cap exceeded: 1 + 100 > 100'))
    q.ck('cap without a window counts everything', q.row(q::CAP, q.pay(100), led.call([q.entry(1, 1)])), q.bad_row(q::CAP, 'cap exceeded: 1 + 100 > 100'))
    unres = q.bad_row(q::CAP, 'amount unresolvable (fail closed)')
    [nil, 'x', -1, -0.5, true, [1], Float::NAN].each { |v| q.ck("cap amount #{v.inspect}", q.row(q::CAP, q.act('pay', '/r', { 'n' => v })), unres) }
    q.ck('cap amount missing', q.row(q::CAP, q.pay(nil)), unres)
    q.ck('cap no params', q.row(q::CAP, q.act('pay')), unres)
    q.ck('cap amount zero', q.row(q::CAP, q.pay(0)), q.pass_row(q::CAP))
    q.ck('cap unresolvable text', q.chk(q::CAP, q.pay(nil))['reasons'], ['c: amount unresolvable (fail closed)'])
    true
  end

  t('zb prohibitions: eval_one rate, never_after, require_prior and require_approval_over rows') do
    next true unless ZbQ.gate?

    q = ZbQ
    rl = ->(n) { q.st('ledger' => { 'r' => q.prior(n) }) }
    q.ck('rate within', q.row(q::RATE, q.act('send'), rl.call(1)), q.pass_row(q::RATE))
    q.ck('rate first', q.row(q::RATE, q.act('send'), rl.call(0)), q.pass_row(q::RATE))
    q.ck('rate over', q.row(q::RATE, q.act('send'), rl.call(2)), q.bad_row(q::RATE, 'rate exceeded: 3 > 2 per 60s'))
    q.ck('rate far over', q.row(q::RATE, q.act('send'), rl.call(5)), q.bad_row(q::RATE, 'rate exceeded: 6 > 2 per 60s'))
    z = q::RATE.merge('max' => 0)
    q.ck('rate max zero hit', q.row(z, q.act('send')), q.bad_row(z, 'rate exceeded: 1 > 0 per 60s'))
    q.ck('rate max zero miss', q.row(z, q.act('read')), q.pass_row(z))
    q.ck('rate miss ignores the ledger', q.row(q::RATE, q.act('read'), rl.call(9)), q.pass_row(q::RATE))
    f = q::RATE.merge('max' => 0, 'window_secs' => 0.5)
    q.ck('rate window prints like JS', q.row(f, q.act('send')), q.bad_row(f, 'rate exceeded: 1 > 0 per 0.5s'))
    old = q.st('ledger' => { 'r' => [q.entry(q::NOW - 61_000), q.entry(q::NOW - 60_000), q.entry(q::NOW - 59_999)] })
    q.ck('rate window edges', q.row(q::RATE.merge('max' => 2), q.act('send'), old), q.pass_row(q::RATE))
    q.ck('rate window edges, one fewer allowed', q.row(q::RATE.merge('max' => 1), q.act('send'), old), q.bad_row(q::RATE.merge('max' => 1), 'rate exceeded: 2 > 1 per 60s'))

    lat = q.st('latched' => { 'na' => q::NOW - 1 })
    q.ck('never_after latched and forbidden', q.row(q::NA, q.act('close'), lat), q.bad_row(q::NA, 'forbidden after trigger'))
    q.ck('never_after latched, other action', q.row(q::NA, q.act('read'), lat), q.pass_row(q::NA))
    q.ck('never_after not latched, forbidden action', q.row(q::NA, q.act('close')), q.pass_row(q::NA))
    q.ck('never_after not latched, other action', q.row(q::NA, q.act('read')), q.pass_row(q::NA))
    q.ck('never_after latched by another id', q.row(q::NA, q.act('close'), q.st('latched' => { 'zz' => 1 })), q.pass_row(q::NA))
    nad = q::NA.merge('description' => 'locked')
    q.ck('never_after description', q.row(nad, q.act('close'), lat), q.bad_row(nad, 'locked'))
    q.ck('never_after description unused when it passes', q.row(nad, q.act('read'), lat), q.pass_row(nad))
    q.ck('never_after reasons text', q.chk(q::NA, q.act('close'), lat)['reasons'], ['na: forbidden after trigger'])

    rlat = q.st('latched' => { 'rp' => 5 })
    q.ck('require_prior missing', q.row(q::RP, q.act('deploy')), q.bad_row(q::RP, 'required prior action not admitted'))
    q.ck('require_prior admitted', q.row(q::RP, q.act('deploy'), rlat), q.pass_row(q::RP))
    q.ck('require_prior other action unlatched', q.row(q::RP, q.act('read')), q.pass_row(q::RP))
    q.ck('require_prior latched by another id', q.row(q::RP, q.act('deploy'), q.st('latched' => { 'zz' => 1 })), q.bad_row(q::RP, 'required prior action not admitted'))
    rpd = q::RP.merge('description' => 'review first')
    q.ck('require_prior description', q.row(rpd, q.act('deploy')), q.bad_row(rpd, 'review first'))
    q.ck('require_prior description unused when admitted', q.row(rpd, q.act('deploy'), rlat), q.pass_row(rpd))

    app = ->(n, ok) { q.pay(n, ok.nil? ? nil : { 'ok' => ok }) }
    over = q.bad_row(q::RA, 'approval required over 10')
    q.ck('approval at the threshold', q.row(q::RA, app.call(10, nil)), q.pass_row(q::RA))
    q.ck('approval below the threshold', q.row(q::RA, app.call(0, nil)), q.pass_row(q::RA))
    q.ck('approval over and approved', q.row(q::RA, app.call(11, true)), q.pass_row(q::RA))
    q.ck('approval over and denied', q.row(q::RA, app.call(11, false)), over)
    q.ck('approval over and unresolvable approval', q.row(q::RA, app.call(11, nil)), over)
    q.ck('approval amount missing is over', q.row(q::RA, app.call(nil, nil)), over)
    q.ck('approval amount missing but approved', q.row(q::RA, app.call(nil, true)), q.pass_row(q::RA))
    q.ck('approval amount not a number is over', q.row(q::RA, app.call('x', false)), over)
    q.ck('approval amount not a number but approved', q.row(q::RA, app.call('x', true)), q.pass_row(q::RA))
    q.ck('approval negative amount is over', q.row(q::RA, app.call(-1, false)), over)
    q.ck('approval negative amount approved', q.row(q::RA, app.call(-1, true)), q.pass_row(q::RA))
    q.ck('approval fractional amount over', q.row(q::RA.merge('threshold' => 10.5), app.call(10.75, false)), q.bad_row(q::RA.merge('threshold' => 10.5), 'approval required over 10.5'))
    q.ck('approval fractional amount at threshold', q.row(q::RA.merge('threshold' => 10.5), app.call(10.5, false)), q.pass_row(q::RA))
    q.ck('approval miss', q.row(q::RA, q.act('read', '/r', { 'n' => 1000 })), q.pass_row(q::RA))
    q.ck('approval miss without amount', q.row(q::RA, q.act('read')), q.pass_row(q::RA))
    rad = q::RA.merge('description' => 'sign off')
    q.ck('approval description', q.row(rad, app.call(11, false)), q.bad_row(rad, 'sign off'))
    q.ck('approval description unused when approved', q.row(rad, app.call(11, true)), q.pass_row(rad))
    two = q::RA.merge('approved' => q::RA['approved'] + [{ 'field' => 'env.b', 'op' => 'eq', 'value' => true }])
    q.ck('approval needs every approval', q.row(two, q.pay(11, { 'ok' => true, 'b' => false })), q.bad_row(two, 'approval required over 10'))
    true
  end

  t('zb prohibitions: check_prohibitions result shape and fail-closed rows') do
    next true unless ZbQ.gate?

    q = ZbQ
    p = q::P
    empty = q.act('boom')
    # an empty description is a reason of zero length: the row has no reason and the summary says "violated"
    nd = q::NV.merge('description' => '')
    r = q.chk(nd, empty)
    q.ck('empty description row', r['evaluated'], [{ 'id' => 'nv', 'kind' => 'never', 'result' => 'violated' }])
    q.ck('empty description summary', [r['ok'], r['violated'], r['reasons']], [false, ['nv'], ['nv: violated']])
    # every invariant is evaluated and reported in order
    many = [q::NV, q::NU, q::CAP.merge('id' => 'c2')]
    r = p.check_prohibitions(q.act('boom'), q.con(many), q.st)
    q.ck('all rows in order', r['evaluated'].map { |e| [e['id'], e['result']] }, [%w[nv violated], %w[nu pass], %w[c2 pass]])
    r = p.check_prohibitions(q.act('del'), q.con([q::NV, q::NU, q::NU.merge('id' => 'nu2')]), q.st)
    q.ck('two violations', [r['ok'], r['violated'], r['reasons']], [false, %w[nu nu2], ['nu: forbidden without required condition', 'nu2: forbidden without required condition']])
    # structural failures
    q.ck('bad constitution', p.check_prohibitions(empty, { 'version' => 2 }, q.st), { 'ok' => false, 'violated' => ['<constitution>'], 'reasons' => ['unsupported version 2'],
                                                                                'evaluated' => [{ 'id' => '<constitution>', 'kind' => 'structural', 'result' => 'violated', 'reason' => 'unsupported version 2' }] })
    q.ck('bad action', p.check_prohibitions({ 'action' => { 'verb' => 'x' } }, q.con([q::NV]), q.st)['violated'], ['<action>'])
    q.ck('bad action text', p.check_prohibitions(nil, q.con([q::NV]), q.st)['reasons'], ['malformed action'])
    q.ck('bad action: not a hash', p.check_prohibitions(5, q.con([q::NV]), q.st)['violated'], ['<action>'])
    q.ck('bad action: action not a hash', p.check_prohibitions({ 'action' => 5 }, q.con([q::NV]), q.st)['violated'], ['<action>'])
    q.ck('bad action: duck action', p.check_prohibitions({ 'action' => q::Duck.new('verb' => 'boom', 'resource' => '/r') }, q.con([q::NV]), q.st)['violated'], ['<action>'])
    q.ck('bad action: resource missing', p.check_prohibitions({ 'action' => { 'verb' => 'boom' } }, q.con([q::NV]), q.st)['violated'], ['<action>'])
    q.ck('bad action: resource not a string', p.check_prohibitions({ 'action' => { 'verb' => 'boom', 'resource' => 5 } }, q.con([q::NV]), q.st)['violated'], ['<action>'])
    q.ck('bad action: duck wrapper is not an action', p.check_prohibitions(q::Duck.new('action' => { 'verb' => 'boom', 'resource' => '/r' }), q.con([q::NV]), q.st)['violated'], ['<action>'])
    q.ck('bad state', p.check_prohibitions(empty, q.con([q::NV]), q.st('seq' => -1))['reasons'], ['malformed monitor state: seq'])
    q.ck('bad state row', p.check_prohibitions(empty, q.con([q::NV]), nil)['evaluated'], [{ 'id' => '<state>', 'kind' => 'structural', 'result' => 'violated', 'reason' => 'malformed monitor state' }])
    # an exception outside any single row is a monitor failure
    boom_action = Class.new(Hash) { def [](_k) = raise('boom') }.new
    q.ck('monitor error', p.check_prohibitions(boom_action, q.con([q::NV]), q.st), { 'ok' => false, 'violated' => ['<monitor>'], 'reasons' => ['monitor error (fail closed)'],
                                                                                     'evaluated' => [{ 'id' => '<monitor>', 'kind' => 'structural', 'result' => 'violated', 'reason' => 'monitor error (fail closed)' }] })
    # an exception inside one row fails that row closed
    bl = q::BoomLatched.new
    s = q.st('latched' => bl)
    r = p.check_prohibitions(q.act('close'), q.con([q::NA, q::NV]), s)
    q.ck('row error', r['evaluated'], [q.bad_row(q::NA, 'evaluation error (fail closed)'), q.pass_row(q::NV)])
    q.ck('row error summary', [r['ok'], r['violated'], r['reasons']], [false, ['na'], ['na: evaluation error (fail closed)']])
    r = p.check_prohibitions(q.act('deploy'), q.con([q::RP]), s)
    q.ck('require_prior row error', r['evaluated'], [q.bad_row(q::RP, 'evaluation error (fail closed)')])
    q.ck('structural_fail shape', p.structural_fail('i', 'why'), { 'ok' => false, 'violated' => ['i'], 'reasons' => ['why'], 'evaluated' => [{ 'id' => 'i', 'kind' => 'structural', 'result' => 'violated', 'reason' => 'why' }] })
    [[{ 'action' => { 'verb' => 'a', 'resource' => 'b' } }, true], [{ 'action' => { 'verb' => 'a' } }, false], [{ 'action' => { 'resource' => 'b' } }, false], [{}, false],
     [nil, false], [[], false], [{ 'action' => [] }, false], [{ 'action' => { 'verb' => 1, 'resource' => 'b' } }, false], [{ 'action' => { 'verb' => 'a', 'resource' => 1 } }, false]].each do |a, want|
      q.ck("action_ok? #{a.inspect}", p.action_ok?(a), want)
    end
    true
  end

  t('zb prohibitions: advance_state_strict inputs, pruning, ordering, latches and failures') do
    next true unless ZbQ.gate?

    q = ZbQ
    p = q::P
    now = q::NOW
    adv = ->(a, invs, s, *rest) { p.advance_state_strict(a, q.con(invs), s, *rest) }
    ok_rate = q::RATE.merge('max' => 5)
    # input refusals, in order
    q.ck('bad constitution', p.advance_state_strict(q.act('send'), { 'version' => 3 }, q.st), { 'ok' => false, 'reason' => 'unsupported version 3' })
    q.ck('bad state', adv.call(q.act('send'), [ok_rate], q.st('seq' => 1.5)), { 'ok' => false, 'reason' => 'malformed monitor state: seq' })
    q.ck('nil state', adv.call(q.act('send'), [ok_rate], nil), { 'ok' => false, 'reason' => 'malformed monitor state' })
    q.ck('number state', adv.call(q.act('send'), [ok_rate], 5), { 'ok' => false, 'reason' => 'malformed monitor state' })
    q.ck('clock regression', adv.call(q.act('send'), [ok_rate], q.st, now - 1), { 'ok' => false, 'reason' => 'clock regression' })
    q.ck('clock nil', adv.call(q.act('send'), [ok_rate], q.st, nil), { 'ok' => false, 'reason' => 'clock regression' })
    q.ck('clock nan', adv.call(q.act('send'), [ok_rate], q.st, Float::NAN), { 'ok' => false, 'reason' => 'clock regression' })
    q.ck('clock string', adv.call(q.act('send'), [ok_rate], q.st, 'x'), { 'ok' => false, 'reason' => 'clock regression' })
    q.ck('malformed action', adv.call({ 'action' => { 'verb' => 'x' } }, [ok_rate], q.st), { 'ok' => false, 'reason' => 'malformed action' })
    q.ck('malformed action nil', adv.call(nil, [ok_rate], q.st), { 'ok' => false, 'reason' => 'malformed action' })
    q.ck('state problem beats the clock', adv.call(q.act('send'), [ok_rate], q.st('seq' => -1), now - 1)['reason'], 'malformed monitor state: seq')
    q.ck('constitution problem beats the state', p.advance_state_strict(q.act('send'), {}, nil)['reason'], 'unsupported version undefined')

    # the chain link and the shape of the next state
    s0 = q.st
    r = adv.call(q.act('send'), [ok_rate], s0)
    prev_digest = p.state_digest(s0)
    link = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/monitor-state-link/v1', 'state' => prev_digest, 'action' => AtlasPca.hash_canonical(q.act('send')) })
    q.ck('advanced', r, { 'ok' => true, 'state' => { 'now' => now, 'seq' => 1, 'parent' => link, 'ledger' => { 'r' => [q.entry(now, 1)] }, 'latched' => {} } })
    r2 = adv.call(q.act('send'), [ok_rate], r['state'], now + 5)
    q.ck('second advance', [r2['state']['seq'], r2['state']['now'], r2['state']['ledger']], [2, now + 5, { 'r' => [q.entry(now, 1), q.entry(now + 5, 1)] }])
    q.ck('default clock is the state clock', adv.call(q.act('send'), [ok_rate], q.st)['state']['now'], now)
    q.ck('explicit clock', adv.call(q.act('send'), [ok_rate], q.st, now + 7)['state']['now'], now + 7)
    q.ck('a non matching action leaves the ledger empty', adv.call(q.act('read'), [ok_rate], q.st)['state']['ledger'], {})
    q.ck('advance_state returns the state', p.advance_state(q.act('send'), q.con([ok_rate]), q.st)['seq'], 1)
    q.ck('advance_state returns the input on refusal', p.advance_state(q.act('send'), q.con([ok_rate]), q.st, now - 1), q.st)

    # the input state is never aliased or mutated
    na = q::NA
    s = q.st('latched' => {}, 'ledger' => { 'r' => [q.entry(now - 1)] })
    before = Marshal.load(Marshal.dump(s))
    r = adv.call(q.act('open'), [na, ok_rate], s)
    q.ck('latched in the next state', r['state']['latched'], { 'na' => now })
    q.ck('input latched untouched', s, before)
    q.ck('next latched is not the input map', r['state']['latched'].equal?(s['latched']), false)

    # pruning at the window edge
    w = ok_rate.merge('window_secs' => 10)
    sw = q.st('ledger' => { 'r' => [q.entry(now - 10_000, 1), q.entry(now - 9995, 2), q.entry(now - 1, 3)] })
    r = adv.call(q.act('read'), [w], sw)
    q.ck('window edge pruned', r['state']['ledger'], { 'r' => [q.entry(now - 9995, 2), q.entry(now - 1, 3)] })
    r = adv.call(q.act('send'), [w], sw)
    q.ck('window edge pruned and appended', r['state']['ledger'], { 'r' => [q.entry(now - 9995, 2), q.entry(now - 1, 3), q.entry(now, 1)] })
    gone = q.st('ledger' => { 'r' => [q.entry(now - 20_000)] })
    q.ck('an emptied ledger key is removed', adv.call(q.act('read'), [w], gone)['state']['ledger'], {})
    q.ck('an emptied ledger key is removed when the id is shared', adv.call(q.act('read'), [w, ok_rate.merge('id' => 'z')], gone)['state']['ledger'], {})
    later = adv.call(q.act('read'), [w], q.st('ledger' => { 'r' => [q.entry(now - 9995)] }), now + 10_000)
    q.ck('pruned by the new clock', later['state']['ledger'], {})
    swc = q.st('ledger' => { 'c' => [q.entry(now - 10_000, 1), q.entry(now - 9995, 2), q.entry(now - 1, 3)] })
    q.ck('no window keeps everything', adv.call(q.act('read'), [q::CAP], swc)['state']['ledger']['c'].length, 3)

    # cap amounts and sorted ledgers
    cap = q::CAP
    r = adv.call(q.pay(1), [cap], q.st('ledger' => { 'c' => [q.entry(now, 5)] }))
    q.ck('cap appends the amount, sorted', r['state']['ledger'], { 'c' => [q.entry(now, 1), q.entry(now, 5)] })
    r = adv.call(q.pay(2.5), [cap], q.st)
    q.ck('cap float amount', r['state']['ledger'], { 'c' => [q.entry(now, 2.5)] })
    [nil, 'x', -1, true].each do |v|
      q.ck("cap amount #{v.inspect} refuses", adv.call(q.act('pay', '/r', { 'n' => v }), [cap], q.st), { 'ok' => false, 'reason' => 'c: amount unresolvable' })
    end
    # a NaN cannot be digested, so the action is refused before the amount is read
    q.ck('cap amount NaN refuses', adv.call(q.act('pay', '/r', { 'n' => Float::NAN }), [cap], q.st), { 'ok' => false, 'reason' => 'advance error (fail closed)' })
    q.ck('cap amount zero is recorded', adv.call(q.pay(0), [cap], q.st)['state']['ledger'], { 'c' => [q.entry(now, 0)] })
    q.ck('cap miss does not need an amount', adv.call(q.act('read'), [cap], q.st)['ok'], true)
    q.ck('rate amount is one', adv.call(q.act('send'), [ok_rate], q.st)['state']['ledger']['r'][0]['amount'], 1)

    # ledger bounds
    fill = ->(n) { q.st('ledger' => { 'c' => (0...n).map { |i| q.entry(now - n + i, 1) } }) }
    r = adv.call(q.pay(1), [cap], fill.call(9999))
    q.ck('10000 entries are kept', r['state']['ledger']['c'].length, 10_000)
    q.ck('10000 entries keep the oldest', r['state']['ledger']['c'].first, q.entry(now - 9999, 1))
    r = adv.call(q.pay(1), [cap], fill.call(10_000))
    merged = r['state']['ledger']['c']
    q.ck('10001 entries merge the oldest two', [merged.length, merged.first, merged.last], [10_000, q.entry(now - 9999, 2), q.entry(now, 1)])
    q.ck('merged total preserved', merged.sum { |e| e['amount'] }, 10_001)
    q.ck('rate overflow refuses', adv.call(q.act('send'), [ok_rate.merge('max' => 10_000, 'window_secs' => 100_000)],
                                            q.st('ledger' => { 'r' => (0...10_000).map { |i| q.entry(now - 10_000 + i, 1) } })), { 'ok' => false, 'reason' => 'r: rate ledger overflow' })
    # too many keys in the resulting state
    keys = q.st('ledger' => (0...1024).to_h { |i| ["k#{i}", [q.entry(now)]] })
    q.ck('resulting state invalid', adv.call(q.pay(1), [cap], keys), { 'ok' => false, 'reason' => 'resulting state invalid' })
    # latches keep the earliest time and only latch on a match
    rp = q::RP
    r = adv.call(q.act('review'), [rp], q.st)
    q.ck('require_prior latches on the prior', r['state']['latched'], { 'rp' => now })
    q.ck('require_prior unlatched on other actions', adv.call(q.act('read'), [rp], q.st)['state']['latched'], {})
    q.ck('require_prior keeps the first latch', adv.call(q.act('review'), [rp], q.st('latched' => { 'rp' => 5 }), now + 3)['state']['latched'], { 'rp' => 5 })
    q.ck('never_after keeps the first latch', adv.call(q.act('open'), [na], q.st('latched' => { 'na' => 5 }), now + 3)['state']['latched'], { 'na' => 5 })
    q.ck('never_after latches at the new clock', adv.call(q.act('open'), [na], q.st, now + 3)['state']['latched'], { 'na' => now + 3 })
    q.ck('never_after unlatched on other actions', adv.call(q.act('read'), [na], q.st)['state']['latched'], {})
    unknown = q.act('review', '/r', { 'k' => 1 })
    amb = rp.merge('prior' => { 'verb' => 'review', 'where' => [{ 'field' => 'action.params.zz', 'op' => 'eq', 'value' => true }] })
    q.ck('an ambiguous prerequisite is not latched', adv.call(unknown, [amb], q.st)['state']['latched'], {})
    amb_na = na.merge('after' => { 'verb' => 'open', 'where' => [{ 'field' => 'action.params.zz', 'op' => 'eq', 'value' => true }] })
    q.ck('an ambiguous trigger latches', adv.call(q.act('open'), [amb_na], q.st)['state']['latched'], { 'na' => now })

    # a failing row is an advance error, not a raise
    q.ck('advance error', adv.call(q.act('open'), [na], q.st('latched' => q::BoomLatched.new)), { 'ok' => false, 'reason' => 'advance error (fail closed)' })
    true
  end
end
