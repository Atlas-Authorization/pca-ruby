# frozen_string_literal: true

# zb_contracts_c: the durable ContractEnforcer (open, check, peek, state, reset) and its stored-document guard. Builds on
# the helpers of zb_contracts_a.rb.

module MutationKill
  module ZbK
    module_function

    CLOCK = -> { 1_700_000_000_000 }

    def signed = C.sign_contract(contract([never('no-delete', 'delete'), prec('review-first', 'review', 'deploy')]), key)
    def kv = AtlasPca::MemoryAtomicKv.new
    def doc_key = "contract/#{signed['id']}"

    def open_enforcer(store = kv, **extra) = C::ContractEnforcer.open(store, signed, principal: key.public, now: CLOCK, **extra)
    def refusal(msg)
      yield
      raise "no error: #{msg}"
    rescue C::ContractEnforcerError => e
      raise "wrong message #{e.message}" unless e.message == "ContractEnforcer: #{msg}"

      true
    end

    def res(allow, reason, violated, reasons, seq) = { 'allow' => allow, 'reason' => reason, 'violated' => violated, 'reasons' => reasons, 'seq' => seq }
  end

  t('zb contracts: ContractEnforcer.open guards and defaults') do
    next true unless ZbK.gate?

    k = ZbK
    k.refusal('a pinned principal is required') { k::C::ContractEnforcer.open(k.kv, k.signed, principal: nil) }
    k.refusal('a pinned principal is required') { k::C::ContractEnforcer.open(k.kv, k.signed, principal: '') }
    k.refusal('a pinned principal is required') { k::C::ContractEnforcer.open(k.kv, k.signed, principal: 5) }
    k.refusal('a pinned principal is required') { k::C::ContractEnforcer.open(k.kv, k.signed, principal: ['x']) }
    k.refusal('contract refused: principal mismatch') { k::C::ContractEnforcer.open(k.kv, k.signed, principal: k.other.public) }
    k.refusal('contract refused: bad signature') { k::C::ContractEnforcer.open(k.kv, k.signed.merge('sig' => 'AAAA'), principal: k.key.public) }
    k.refusal('contract refused: unsupported version 2') { k::C::ContractEnforcer.open(k.kv, { 'version' => 2 }, principal: k.key.public) }

    # a custom key is used verbatim, the default key is derived from the contract id
    store = k.kv
    e = k::C::ContractEnforcer.open(store, k.signed, principal: k.key.public, key: 'custom/key', now: k::CLOCK)
    k.ck('custom key admits', e.check(k.act('review'))['allow'], true)
    k.ck('custom key is used', [store.get('custom/key').nil?, store.get(k.doc_key).nil?], [false, true])
    store = k.kv
    e = k.open_enforcer(store)
    e.check(k.act('review'))
    k.ck('default key', [store.get(k.doc_key).nil?, store.get('custom/key').nil?], [false, true])
    k.ck('default key content', store.get(k.doc_key)['contract_id'], k.signed['id'])
    k.ck('latching is on by default', k::C::ContractEnforcer.open(k.kv, k.signed, principal: k.key.public, now: k::CLOCK).instance_variable_get(:@latch), true)
    k.ck('latching can be turned off', k.open_enforcer(k.kv, latch_on_violation: false).instance_variable_get(:@latch), false)
    k.ck('anything but false keeps latching', k.open_enforcer(k.kv, latch_on_violation: nil).instance_variable_get(:@latch), true)

    # the default clock is wall-clock milliseconds, an integer
    store = k.kv
    lo = (Time.now.to_f * 1000).to_i - 3_600_000
    e = k::C::ContractEnforcer.open(store, k.signed, principal: k.key.public)
    k.ck('default clock admits', e.check(k.act('review'))['allow'], true)
    wall = store.get(k.doc_key)['state']['now']
    hi = (Time.now.to_f * 1000).to_i + 3_600_000
    k.ck('default clock is an integer', wall.is_a?(Integer), true)
    k.ck('default clock is milliseconds since the epoch', wall.between?(lo, hi), true)
    store = k.kv
    k.open_enforcer(store).check(k.act('review'))
    k.ck('an explicit clock is used', store.get(k.doc_key)['state']['now'], 1_700_000_000_000)
    true
  end

  t('zb contracts: ContractEnforcer.check results and latching') do
    next true unless ZbK.gate?

    k = ZbK
    prec_msg = 'review-first: precedence violated (prerequisite p not yet admitted before q)'
    store = k.kv
    e = k.open_enforcer(store)
    k.ck('admit', e.check(k.act('review')), k.res(true, 'ok', [], [], 1))
    k.ck('admit again', e.check(k.act('deploy')), k.res(true, 'ok', [], [], 2))
    k.ck('the stored state advanced', store.get(k.doc_key)['state']['seq'], 2)

    # permission denial: nothing is stored or latched
    store = k.kv
    e = k.open_enforcer(store)
    k.ck('not permitted', e.check(k.act('review'), false), k.res(false, 'permission', [], ['<permission>: not permitted'], 0))
    k.ck('not permitted stores nothing', store.get(k.doc_key), nil)
    k.ck('not permitted, a non boolean', e.check(k.act('review'), 'yes')['reason'], 'permission')
    k.ck('still admits afterwards', e.check(k.act('review')), k.res(true, 'ok', [], [], 1))
    k.ck('not permitted after an admission reports the stored seq', e.check(k.act('deploy'), false), k.res(false, 'permission', [], ['<permission>: not permitted'], 1))

    # a violation latches
    store = k.kv
    e = k.open_enforcer(store)
    r = e.check(k.act('deploy'))
    k.ck('violation', r, k.res(false, 'violated', ['review-first'], [prec_msg], 0))
    k.ck('violation is latched in the store', store.get(k.doc_key)['latched'], { 'seq' => 0, 'violated' => ['review-first'] })
    k.ck('violation keeps the state', store.get(k.doc_key)['state'], k::P.empty_state(1_700_000_000_000))
    k.ck('latched', e.check(k.act('review')), k.res(false, 'latched', ['review-first'], ['<latched>: contract violated at seq 0'], 0))
    k.ck('latched stays', e.check(k.act('review'))['reason'], 'latched')
    k.ck('state reports the latch', e.state, { 'state' => k::P.empty_state(1_700_000_000_000), 'latched' => true })

    store = k.kv
    e = k.open_enforcer(store)
    e.check(k.act('review'))
    r = e.check(k.act('delete'))
    k.ck('violation after an admission', r, k.res(false, 'violated', ['no-delete'], ['no-delete: never-invariant violated (forbidden action)'], 1))
    k.ck('latched at the stored seq', store.get(k.doc_key)['latched'], { 'seq' => 1, 'violated' => ['no-delete'] })
    k.ck('latched result carries the seq', e.check(k.act('review')), k.res(false, 'latched', ['no-delete'], ['<latched>: contract violated at seq 1'], 1))

    # without latching a violation only denies
    store = k.kv
    e = k.open_enforcer(store, latch_on_violation: false)
    k.ck('violation without latching', e.check(k.act('delete')), k.res(false, 'violated', ['no-delete'], ['no-delete: never-invariant violated (forbidden action)'], 0))
    k.ck('nothing stored', store.get(k.doc_key), nil)
    k.ck('the next action is admitted', e.check(k.act('review'))['allow'], true)

    # a clock that is not finite refuses the advance without storing anything
    nan = k::C::ContractEnforcer.open(store = k.kv, k.signed, principal: k.key.public, now: -> { Float::NAN })
    r = nan.check(k.act('review'))
    k.ck('nan clock on a fresh store', r, k.res(false, 'state-error', [], ['<state>: advance failed: clock regression'], 0))
    k.ck('nan clock stores nothing', store.get(k.doc_key), nil)
    inf = k::C::ContractEnforcer.open(store = k.kv, k.signed, principal: k.key.public, now: -> { Float::INFINITY })
    k.ck('infinite clock on a fresh store', inf.check(k.act('review')), k.res(false, 'state-error', [], ['<state>: advance failed: clock regression'], 0))
    store = k.kv
    clock = [1_700_000_000_000]
    steady = k::C::ContractEnforcer.open(store, k.signed, principal: k.key.public, now: -> { clock.empty? ? Float::NAN : clock.shift })
    k.ck('admit with a finite clock', steady.check(k.act('review'))['allow'], true)
    before = store.get(k.doc_key)
    r = steady.check(k.act('review'))
    k.ck('stored state with an unreadable clock', r, k.res(false, 'state-error', [], ['<state>: clock is not finite'], 1))
    k.ck('the stored document is left exactly as it was', store.get(k.doc_key), before)

    # corrupt documents
    corrupt = k.res(false, 'state-error', [], ['<state>: stored state is corrupt or belongs to another contract'], 0)
    store = k.kv
    e = k.open_enforcer(store)
    store.set(k.doc_key, { 'v' => 1, 'contract_id' => 'other', 'state' => k::P.empty_state(k::NOW) })
    k.ck('another contract', e.check(k.act('review')), corrupt)
    store.set(k.doc_key, { 'v' => 2, 'contract_id' => k.signed['id'], 'state' => k::P.empty_state(k::NOW) })
    k.ck('another version', e.check(k.act('review')), corrupt)
    store.set(k.doc_key, { 'v' => 1, 'contract_id' => k.signed['id'], 'state' => { 'now' => 'x' } })
    k.ck('malformed state', e.check(k.act('review')), corrupt)
    store.set(k.doc_key, 5)
    k.ck('not a document', e.check(k.act('review')), corrupt)
    store.set(k.doc_key, { 'v' => 1, 'contract_id' => k.signed['id'], 'state' => k::P.empty_state(k::NOW) })
    k.ck('a document written by hand is accepted', e.check(k.act('review')), k.res(true, 'ok', [], [], 1))

    # failures of the store or the clock
    idle = Object.new
    def idle.update(_key) = nil
    k.ck('a store that never runs the update', k.open_enforcer(idle).check(k.act('review')), k.res(false, 'store-error', [], ['store unavailable'], 0))
    down = Object.new
    def down.update(_key) = raise('down')
    def down.get(_key) = raise('down')
    failed = k.res(false, 'store-error', [], ['store error (fail closed)'], 0)
    k.ck('store error', k.open_enforcer(down).check(k.act('review')), failed)
    k.ck('clock error', k.open_enforcer(k.kv).tap { |en| en.instance_variable_set(:@now, -> { raise 'clock' }) }.check(k.act('review')), failed)
    k.ck('store error is not an exception', k.open_enforcer(down).check(k.act('review')).keys, %w[allow reason violated reasons seq])
    true
  end

  t('zb contracts: ContractEnforcer.peek, state and reset') do
    next true unless ZbK.gate?

    k = ZbK
    prec_msg = 'review-first: precedence violated (prerequisite p not yet admitted before q)'
    store = k.kv
    e = k.open_enforcer(store)
    k.ck('peek ok', e.peek(k.act('review')), k.res(true, 'ok', [], [], 0))
    k.ck('peek violation', e.peek(k.act('deploy')), k.res(false, 'violated', ['review-first'], [prec_msg], 0))
    k.ck('peek stores nothing', store.get(k.doc_key), nil)
    k.ck('state of nothing', e.state, nil)
    e.check(k.act('review'))
    before = store.get(k.doc_key)
    k.ck('peek uses the stored state', e.peek(k.act('deploy')), k.res(true, 'ok', [], [], 1))
    k.ck('peek reports the stored seq on a violation', e.peek(k.act('delete')), k.res(false, 'violated', ['no-delete'], ['no-delete: never-invariant violated (forbidden action)'], 1))
    k.ck('peek leaves the store alone', store.get(k.doc_key), before)
    k.ck('state', e.state, { 'state' => before['state'], 'latched' => false })
    e.check(k.act('delete'))
    k.ck('peek latched', e.peek(k.act('review')), k.res(false, 'latched', ['no-delete'], ['<latched>: contract violated at seq 1'], 1))
    k.ck('state after the latch', e.state['latched'], true)

    # an unreadable clock does not stop a read-only evaluation of a fresh store
    nan = k::C::ContractEnforcer.open(k.kv, k.signed, principal: k.key.public, now: -> { Float::NAN })
    k.ck('peek with a nan clock', nan.peek(k.act('review')), k.res(true, 'ok', [], [], 0))
    k.ck('peek with a nan clock and a violation', nan.peek(k.act('deploy')), k.res(false, 'violated', ['review-first'], [prec_msg], 0))
    inf = k::C::ContractEnforcer.open(k.kv, k.signed, principal: k.key.public, now: -> { Float::INFINITY })
    k.ck('peek with an infinite clock', inf.peek(k.act('review')), k.res(true, 'ok', [], [], 0))

    # corrupt and failing stores
    store = k.kv
    e = k.open_enforcer(store)
    store.set(k.doc_key, { 'v' => 1, 'contract_id' => 'other', 'state' => k::P.empty_state(k::NOW) })
    k.ck('peek corrupt', e.peek(k.act('review')), k.res(false, 'state-error', [], ['<state>: stored state is corrupt or belongs to another contract'], 0))
    down = Object.new
    def down.get(_key) = raise('down')
    k.ck('peek store error', k.open_enforcer(down).peek(k.act('review')), k.res(false, 'store-error', [], ['store error (fail closed)'], 0))
    store = k.kv
    broken_clock = k.open_enforcer(store)
    broken_clock.instance_variable_set(:@now, -> { raise 'clock' })
    k.ck('peek clock error', broken_clock.peek(k.act('review')), k.res(false, 'store-error', [], ['store error (fail closed)'], 0))

    # state() on a corrupt document raises
    store = k.kv
    e = k.open_enforcer(store)
    store.set(k.doc_key, { 'v' => 1, 'contract_id' => 'other', 'state' => k::P.empty_state(k::NOW) })
    err = k.err_of { e.state }
    k.ck('state refuses a foreign document', [err.class, err.message], [k::C::ContractEnforcerError, 'ContractEnforcer: stored state is corrupt or belongs to another contract'])
    store.set(k.doc_key, { 'v' => 1, 'contract_id' => k.signed['id'], 'state' => k::P.empty_state(k::NOW) })
    k.ck('state accepts a document written by hand', e.state, { 'state' => k::P.empty_state(k::NOW), 'latched' => false })
    store.set(k.doc_key, { 'v' => 1, 'contract_id' => k.signed['id'], 'state' => k::P.empty_state(k::NOW), 'latched' => { 'seq' => 0, 'violated' => [] } })
    k.ck('state with a latch', e.state['latched'], true)

    # reset
    reset_sig = ->(seq) { k::C.sign_contract_reset(k.key, k.signed['id'], seq) }
    store = k.kv
    e = k.open_enforcer(store)
    k.ck('reset of nothing', e.reset(reset_sig.call(0)), false)
    e.check(k.act('review'))
    k.ck('reset of an unlatched document', e.reset(reset_sig.call(1)), false)
    e.check(k.act('delete'))
    latched_doc = store.get(k.doc_key)
    k.ck('reset with the wrong sequence', e.reset(reset_sig.call(0)), false)
    k.ck('reset by another key', e.reset(k::C.sign_contract_reset(k.other, k.signed['id'], 1)), false)
    k.ck('reset for another contract', e.reset(k::C.sign_contract_reset(k.key, 'other', 1)), false)
    [nil, 5, '', 'AAAA', ['x']].each { |sg| k.ck("reset with #{sg.inspect}", e.reset(sg), false) }
    k.ck('still latched', store.get(k.doc_key), latched_doc)
    k.ck('reset', e.reset(reset_sig.call(1)), true)
    k.ck('reset removes only the latch', store.get(k.doc_key), latched_doc.reject { |kk, _| kk == 'latched' })
    k.ck('reset twice', e.reset(reset_sig.call(1)), false)
    k.ck('admitted after a reset', e.check(k.act('deploy'))['allow'], true)

    # a latched document of another contract is not cleared even with a good signature
    store = k.kv
    e = k.open_enforcer(store)
    foreign = { 'v' => 1, 'contract_id' => 'other', 'state' => k::P.empty_state(k::NOW), 'latched' => { 'seq' => 0, 'violated' => [] } }
    store.set(k.doc_key, foreign)
    k.ck('reset refuses a foreign document', e.reset(reset_sig.call(0)), false)
    k.ck('the foreign document is untouched', store.get(k.doc_key), foreign)
    down = Object.new
    def down.update(_key) = raise('down')
    k.ck('reset on a failing store', k.open_enforcer(down).reset('x'), false)
    true
  end

  t('zb contracts: enforcer_doc? guard') do
    next true unless ZbK.gate?

    k = ZbK
    ed = ->(d) { k::C.enforcer_doc?(d, 'cid') }
    good = { 'v' => 1, 'contract_id' => 'cid', 'state' => k::P.empty_state(k::NOW) }
    k.ck('good', ed.call(good), true)
    [nil, 5, 'x', [], true].each { |d| k.ck("not a hash #{d.inspect}", ed.call(d), false) }
    [2, nil, '1', 0].each { |v| k.ck("version #{v.inspect}", ed.call(good.merge('v' => v)), false) }
    k.ck('version missing', ed.call(good.reject { |kk, _| kk == 'v' }), false)
    ['other', nil, 5].each { |v| k.ck("contract id #{v.inspect}", ed.call(good.merge('contract_id' => v)), false) }
    k.ck('contract id missing', ed.call(good.reject { |kk, _| kk == 'contract_id' }), false)
    [nil, 5, { 'now' => 'x' }, k::P.empty_state(k::NOW).merge('seq' => -1)].each { |s| k.ck("state #{s.inspect[0, 30]}", ed.call(good.merge('state' => s)), false) }
    k.ck('state missing', ed.call(good.reject { |kk, _| kk == 'state' }), false)
    ok_latch = { 'seq' => 0, 'violated' => [] }
    k.ck('latch ok', ed.call(good.merge('latched' => ok_latch)), true)
    k.ck('latch with ids', ed.call(good.merge('latched' => { 'seq' => 3, 'violated' => %w[a b] })), true)
    k.ck('latch with a whole float seq', ed.call(good.merge('latched' => { 'seq' => 2.0, 'violated' => [] })), true)
    [nil, 'x', 5, [], true].each { |l| k.ck("latch #{l.inspect}", ed.call(good.merge('latched' => l)), false) }
    [nil, 1.5, 'x', -0.0, true, [1], Float::NAN].each { |s| k.ck("latch seq #{s.inspect}", ed.call(good.merge('latched' => ok_latch.merge('seq' => s))), false) }
    k.ck('latch seq missing', ed.call(good.merge('latched' => { 'violated' => [] })), false)
    [nil, 'x', 5, {}, [1], ['a', 2], [nil]].each { |v| k.ck("latch violated #{v.inspect}", ed.call(good.merge('latched' => ok_latch.merge('violated' => v))), false) }
    k.ck('latch violated missing', ed.call(good.merge('latched' => { 'seq' => 0 })), false)
    k.ck('a document may carry a latch key set to nothing only if well formed', ed.call(good.merge('latched' => nil)), false)
    true
  end
end
