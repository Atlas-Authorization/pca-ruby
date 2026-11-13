# frozen_string_literal: true

# zb_prohibitions_b: exact-value checks of the monitor state, trigger matching, per-kind evaluation and the state
# transition of the prohibition engine (packages/pca/src/prohibitions.ts is authoritative). AtlasPca is resolved at call time.

module MutationKill
  module ZbQ
    module_function

    def live(name)
      Module.new do
        define_singleton_method(:method_missing) { |m, *a, **k, &b| AtlasPca.const_get(name).public_send(m, *a, **k, &b) }
        define_singleton_method(:respond_to_missing?) { |m, priv = false| AtlasPca.const_get(name).respond_to?(m, priv) }
        define_singleton_method(:const_missing) { |c| AtlasPca.const_get(name).const_get(c) }
      end
    end

    P = live(:Prohibitions)
    NOW = 1_700_000_000_000
    M = 'malformed monitor state'

    # A non-Hash that answers [] like a Hash: code that tests is_a?(Hash) must not treat it as an object.
    class Duck
      def initialize(h) = (@h = h)
      def [](k) = @h[k]
    end

    # A Hash whose latched map raises on key?: drives the evaluation / advance fail-closed paths.
    class BoomLatched < Hash
      def key?(_k) = raise('boom')
    end

    def gate? = (f = ENV['MUT_FILE']).nil? || f.empty? || f == 'prohibitions.rb'
    def ck(label, got, want) = got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    def err_of
      yield
      nil
    rescue StandardError, SystemStackError => e
      e
    end

    def st(over = {}) = P.empty_state(NOW).merge(over)
    def act(verb, resource = '/r', params = nil, env = nil)
      a = { 'verb' => verb, 'resource' => resource }
      a['params'] = params if params
      c = { 'action' => a }
      c['env'] = env if env
      c
    end

    def key = (@key ||= AtlasPca::KeyPair.generate)
    def con(invs) = { 'version' => 1, 'principal' => key.public, 'invariants' => invs }
    def chk(inv, ctx, state = st) = P.check_prohibitions(ctx, con([inv]), state)
    def row(inv, ctx, state = st) = chk(inv, ctx, state)['evaluated'][0]
    def pass_row(inv) = { 'id' => inv['id'], 'kind' => inv['kind'], 'result' => 'pass' }
    def bad_row(inv, reason) = { 'id' => inv['id'], 'kind' => inv['kind'], 'result' => 'violated', 'reason' => reason }
    def entry(t, amount = 1) = { 't' => t, 'amount' => amount }
    def prior(n) = Array.new(n) { |i| entry(NOW - n + i) }
  end

  t('zb prohibitions: state_problem exact problems') do
    next true unless ZbQ.gate?

    p = ZbQ::P
    m = ZbQ::M
    sp = ->(s) { p.state_problem(s) }
    st = ZbQ.method(:st)
    ZbQ.ck('genesis', sp.call(st.call), nil)
    [nil, 5, 'x', [], true, ZbQ::Duck.new(st.call)].each { |s| ZbQ.ck("not an object #{s.inspect[0, 20]}", sp.call(s), m) }
    [nil, 'x', Float::NAN, Float::INFINITY, true, [1]].each { |v| ZbQ.ck("now #{v.inspect}", sp.call(st.call('now' => v)), m) }
    ZbQ.ck('now float ok', sp.call(st.call('now' => 1.5, 'ledger' => {})), nil)
    [nil, [], 'x', 5].each { |v| ZbQ.ck("ledger #{v.inspect}", sp.call(st.call('ledger' => v)), m) }
    [nil, [], 'x', 5].each { |v| ZbQ.ck("latched #{v.inspect}", sp.call(st.call('latched' => v)), m) }
    ZbQ.ck('ledger missing', sp.call(st.call.reject { |k, _| k == 'ledger' }), m)
    ZbQ.ck('latched missing', sp.call(st.call.reject { |k, _| k == 'latched' }), m)
    [1.5, -1, -0.0, 'x', nil, true, Float::NAN, Float::INFINITY].each { |v| ZbQ.ck("seq #{v.inspect}", sp.call(st.call('seq' => v, 'parent' => 'p')), "#{m}: seq") }
    ZbQ.ck('seq missing', sp.call(st.call.reject { |k, _| k == 'seq' }), "#{m}: seq")
    ZbQ.ck('seq whole float', sp.call(st.call('seq' => 2.0, 'parent' => 'p')), nil)
    ZbQ.ck('seq 0.0 genesis', sp.call(st.call('seq' => 0.0)), nil)
    ZbQ.ck('parent number at seq 1', sp.call(st.call('seq' => 1, 'parent' => 5)), "#{m}: parent")
    ZbQ.ck('parent number at genesis', sp.call(st.call('seq' => 0, 'parent' => 5)), "#{m}: parent")
    ZbQ.ck('parent array', sp.call(st.call('seq' => 3, 'parent' => ['p'])), "#{m}: parent")
    ZbQ.ck('genesis with a parent', sp.call(st.call('seq' => 0, 'parent' => 'p')), "#{m}: genesis has a parent")
    ZbQ.ck('missing chain link', sp.call(st.call('seq' => 1, 'parent' => nil)), "#{m}: missing chain link")
    ZbQ.ck('chained', sp.call(st.call('seq' => 1, 'parent' => 'p')), nil)

    # key and entry bounds
    ZbQ.ck('1024 ledger keys', sp.call(st.call('ledger' => (0...1024).to_h { |i| ["k#{i}", [ZbQ.entry(ZbQ::NOW)]] })), nil)
    ZbQ.ck('1025 ledger keys', sp.call(st.call('ledger' => (0...1025).to_h { |i| ["k#{i}", [ZbQ.entry(ZbQ::NOW)]] })), "#{m}: too many keys")
    ZbQ.ck('1024 latch keys', sp.call(st.call('latched' => (0...1024).to_h { |i| ["k#{i}", ZbQ::NOW] })), nil)
    ZbQ.ck('1025 latch keys', sp.call(st.call('latched' => (0...1025).to_h { |i| ["k#{i}", ZbQ::NOW] })), "#{m}: too many keys")
    %w[__proto__ constructor prototype].each do |k|
      ZbQ.ck("ledger key #{k}", sp.call(st.call('ledger' => { k => [] })), "#{m}: bad ledger key")
      ZbQ.ck("latch key #{k}", sp.call(st.call('latched' => { k => ZbQ::NOW })), "#{m}: bad latch key")
    end
    ZbQ.ck('ledger key 128', sp.call(st.call('ledger' => { 'k' * 128 => [] })), nil)
    ZbQ.ck('ledger key 129', sp.call(st.call('ledger' => { 'k' * 129 => [] })), "#{m}: bad ledger key")
    ZbQ.ck('latch key 128', sp.call(st.call('latched' => { 'k' * 128 => ZbQ::NOW })), nil)
    ZbQ.ck('latch key 129', sp.call(st.call('latched' => { 'k' * 129 => ZbQ::NOW })), "#{m}: bad latch key")
    ZbQ.ck('ledger value not an array', sp.call(st.call('ledger' => { 'a' => 5 })), "#{m}: bad ledger")
    ZbQ.ck('ledger value nil', sp.call(st.call('ledger' => { 'a' => nil })), "#{m}: bad ledger")
    ZbQ.ck('ledger value hash', sp.call(st.call('ledger' => { 'a' => {} })), "#{m}: bad ledger")
    ZbQ.ck('ledger 10000 entries', sp.call(st.call('ledger' => { 'a' => Array.new(10_000, ZbQ.entry(ZbQ::NOW)) })), nil)
    ZbQ.ck('ledger 10001 entries', sp.call(st.call('ledger' => { 'a' => Array.new(10_001, ZbQ.entry(ZbQ::NOW)) })), "#{m}: bad ledger")
    full = ->(extra) { { 'a' => Array.new(10_000, ZbQ.entry(ZbQ::NOW)) }.merge((1..9).to_h { |i| ["b#{i}", Array.new(10_000, ZbQ.entry(ZbQ::NOW))] }).merge(extra) }
    ZbQ.ck('100000 entries in total', sp.call(st.call('ledger' => full.call({}))), nil)
    ZbQ.ck('100001 entries in total', sp.call(st.call('ledger' => full.call('z' => [ZbQ.entry(ZbQ::NOW)]))), "#{m}: too many entries")
    boom_state = Class.new(Hash) { def [](_k) = raise('boom') }.new
    ZbQ.ck('a state that raises while being read is malformed', sp.call(boom_state), m)

    bad_entries = [5, nil, 'x', [], { 't' => ZbQ::NOW }, { 'amount' => 1 }, { 't' => 'x', 'amount' => 1 }, { 't' => ZbQ::NOW, 'amount' => 'x' },
                   { 't' => nil, 'amount' => 1 }, { 't' => ZbQ::NOW, 'amount' => nil }, { 't' => Float::NAN, 'amount' => 1 }, { 't' => ZbQ::NOW, 'amount' => Float::INFINITY },
                   { 't' => ZbQ::NOW, 'amount' => -1 }, { 't' => ZbQ::NOW, 'amount' => -0.5 }, { 't' => true, 'amount' => 1 }]
    bad_entries.each { |e| ZbQ.ck("entry #{e.inspect}", sp.call(st.call('ledger' => { 'a' => [e] })), "#{m}: bad ledger entry") }
    ZbQ.ck('entry amount 0 ok', sp.call(st.call('ledger' => { 'a' => [ZbQ.entry(ZbQ::NOW, 0)] })), nil)
    ZbQ.ck('entry float ok', sp.call(st.call('ledger' => { 'a' => [{ 't' => 1.5, 'amount' => 2.5 }] })), nil)
    ZbQ.ck('entry at now', sp.call(st.call('ledger' => { 'a' => [ZbQ.entry(ZbQ::NOW)] })), nil)
    ZbQ.ck('entry after now', sp.call(st.call('ledger' => { 'a' => [ZbQ.entry(ZbQ::NOW + 1)] })), "#{m}: ledger entry after now (clock regression)")
    ZbQ.ck('second entry after now', sp.call(st.call('ledger' => { 'a' => [ZbQ.entry(ZbQ::NOW), ZbQ.entry(ZbQ::NOW + 1)] })), "#{m}: ledger entry after now (clock regression)")
    ZbQ.ck('entry bad beats a later bad ledger', sp.call(st.call('ledger' => { 'a' => [5], 'b' => 5 })), "#{m}: bad ledger entry")

    [nil.to_s, 'x', Float::NAN, nil, [1], true, ZbQ::NOW + 1].each do |v|
      ZbQ.ck("latch value #{v.inspect}", sp.call(st.call('latched' => { 'a' => v })), "#{m}: bad latch")
    end
    ZbQ.ck('latch at now', sp.call(st.call('latched' => { 'a' => ZbQ::NOW })), nil)
    ZbQ.ck('latch in the past', sp.call(st.call('latched' => { 'a' => 5 })), nil)

    ZbQ.ck('deadlines nil ok', sp.call(st.call('deadlines' => nil)), nil)
    ZbQ.ck('deadlines empty ok', sp.call(st.call('deadlines' => {})), nil)
    ['x', 5, [], true].each { |v| ZbQ.ck("deadlines #{v.inspect}", sp.call(st.call('deadlines' => v)), "#{m}: deadlines") }
    ZbQ.ck('1024 deadline keys', sp.call(st.call('deadlines' => (0...1024).to_h { |i| ["k#{i}", 1] })), nil)
    ZbQ.ck('1025 deadline keys', sp.call(st.call('deadlines' => (0...1025).to_h { |i| ["k#{i}", 1] })), "#{m}: too many deadline keys")
    %w[__proto__ constructor prototype].each { |k| ZbQ.ck("deadline key #{k}", sp.call(st.call('deadlines' => { k => 1 })), "#{m}: bad deadline key") }
    ZbQ.ck('deadline key 128', sp.call(st.call('deadlines' => { 'k' * 128 => 1 })), nil)
    ZbQ.ck('deadline key 129', sp.call(st.call('deadlines' => { 'k' * 129 => 1 })), "#{m}: bad deadline key")
    [0, -1, 1.5, 'x', nil, 1_000_001, Float::NAN, Float::INFINITY, true].each do |d|
      ZbQ.ck("deadline #{d.inspect}", sp.call(st.call('deadlines' => { 'a' => d })), "#{m}: bad deadline")
    end
    ZbQ.ck('deadline 1', sp.call(st.call('deadlines' => { 'a' => 1 })), nil)
    ZbQ.ck('deadline max', sp.call(st.call('deadlines' => { 'a' => 1_000_000 })), nil)
    ZbQ.ck('deadline whole float', sp.call(st.call('deadlines' => { 'a' => 3.0 })), nil)
    true
  end

  t('zb prohibitions: canonical_state, state_digest, tick_state') do
    next true unless ZbQ.gate?

    p = ZbQ::P
    s = ZbQ.st('seq' => 2, 'parent' => 'p', 'latched' => { 'l' => 3 }, 'deadlines' => { 'd' => 4 },
               'ledger' => { 'a' => [{ 't' => 5, 'amount' => 2, 'extra' => 1 }, ZbQ.entry(3, 9), ZbQ.entry(3, 1), ZbQ.entry(3, 5)], 'b' => [] })
    want = { 'd' => 'atlas-pca/monitor-state/v1', 'now' => ZbQ::NOW, 'seq' => 2, 'parent' => 'p', 'latched' => { 'l' => 3 }, 'deadlines' => { 'd' => 4 },
             'ledger' => { 'a' => [ZbQ.entry(3, 1), ZbQ.entry(3, 5), ZbQ.entry(3, 9), ZbQ.entry(5, 2)] } }
    canon = p.canonical_state(s)
    ZbQ.ck('canonical', canon, want)
    ZbQ.ck('canonical entry order', canon['ledger']['a'].map { |e| [e['t'], e['amount']] }, [[3, 1], [3, 5], [3, 9], [5, 2]])
    ZbQ.ck('latched is a copy', canon['latched'].equal?(s['latched']), false)
    ZbQ.ck('deadlines is a copy', canon['deadlines'].equal?(s['deadlines']), false)
    ZbQ.ck('input untouched', s['ledger']['a'][0], { 't' => 5, 'amount' => 2, 'extra' => 1 })
    plain = p.canonical_state(ZbQ.st)
    ZbQ.ck('no deadlines key when absent', plain.key?('deadlines'), false)
    ZbQ.ck('no deadlines key when empty', p.canonical_state(ZbQ.st('deadlines' => {})).key?('deadlines'), false)
    ZbQ.ck('empty state', plain, { 'd' => 'atlas-pca/monitor-state/v1', 'now' => ZbQ::NOW, 'seq' => 0, 'parent' => nil, 'ledger' => {}, 'latched' => {} })
    e = ZbQ.err_of { p.canonical_state(ZbQ.st('seq' => -1)) }
    ZbQ.ck('canonical refuses a malformed state', [e.class, e.message], [TypeError, 'malformed monitor state: seq'])
    e = ZbQ.err_of { p.canonical_state(nil) }
    ZbQ.ck('canonical refuses nil', [e.class, e.message], [TypeError, 'malformed monitor state'])
    ZbQ.ck('digest', p.state_digest(s), AtlasPca.hash_canonical(want))
    ZbQ.ck('digest ignores unknown fields', p.state_digest(s.merge('zzz' => 1)), p.state_digest(s))
    ZbQ.ck('digest sees the deadlines', p.state_digest(s.merge('deadlines' => { 'd' => 5 })) == p.state_digest(s), false)

    ZbQ.ck('tick', p.tick_state(ZbQ.st, ZbQ::NOW + 5), { 'ok' => true, 'state' => ZbQ.st('now' => ZbQ::NOW + 5) })
    ZbQ.ck('tick same', p.tick_state(ZbQ.st, ZbQ::NOW), { 'ok' => true, 'state' => ZbQ.st })
    ZbQ.ck('tick regression', p.tick_state(ZbQ.st, ZbQ::NOW - 1), { 'ok' => false, 'reason' => 'clock regression' })
    ZbQ.ck('tick nan', p.tick_state(ZbQ.st, Float::NAN), { 'ok' => false, 'reason' => 'clock regression' })
    ZbQ.ck('tick nil', p.tick_state(ZbQ.st, nil), { 'ok' => false, 'reason' => 'clock regression' })
    ZbQ.ck('tick malformed', p.tick_state(nil, ZbQ::NOW), { 'ok' => false, 'reason' => 'malformed monitor state' })
    true
  end

  t('zb prohibitions: window_entries bounds and order') do
    next true unless ZbQ.gate?

    p = ZbQ::P
    now = ZbQ::NOW
    s = ZbQ.st('ledger' => { 'c' => [ZbQ.entry(now - 10_000, 1), ZbQ.entry(now - 9995, 2), ZbQ.entry(now, 3), ZbQ.entry(now + 1, 4)], 'd' => 5, 'e' => [ZbQ.entry(now - 5, 9), ZbQ.entry(now - 5, 1), ZbQ.entry(now - 5, 5), ZbQ.entry(now - 6, 7)] })
    ZbQ.ck('window of 10 seconds', p.window_entries(s, 'c', 10), [ZbQ.entry(now - 9995, 2), ZbQ.entry(now, 3)])
    ZbQ.ck('window of 9 seconds', p.window_entries(s, 'c', 9), [ZbQ.entry(now, 3)])
    ZbQ.ck('window of 11 seconds', p.window_entries(s, 'c', 11), [ZbQ.entry(now - 10_000, 1), ZbQ.entry(now - 9995, 2), ZbQ.entry(now, 3)])
    ZbQ.ck('no window', p.window_entries(s, 'c', nil), [ZbQ.entry(now - 10_000, 1), ZbQ.entry(now - 9995, 2), ZbQ.entry(now, 3)])
    ZbQ.ck('fractional window', p.window_entries(s, 'c', 0.5), [ZbQ.entry(now, 3)])
    ZbQ.ck('sorted by time then amount', p.window_entries(s, 'e', nil), [ZbQ.entry(now - 6, 7), ZbQ.entry(now - 5, 1), ZbQ.entry(now - 5, 5), ZbQ.entry(now - 5, 9)])
    ZbQ.ck('unknown id', p.window_entries(s, 'zz', 10), [])
    ZbQ.ck('not an array', p.window_entries(s, 'd', 10), [])
    true
  end

  t('zb prohibitions: when_matches? and when_affirmative?') do
    next true unless ZbQ.gate?

    p = ZbQ::P
    wm = ->(w, ctx) { p.when_matches?(w, ctx) }
    ctx = ZbQ.act('x', '/a')
    ZbQ.ck('invalid trigger matches', wm.call({ 'verb' => '' }, ctx), true)
    ZbQ.ck('non object trigger matches', wm.call(nil, ctx), true)
    [nil, 5, 'action', [], {}, { 'action' => nil }, { 'action' => 5 }, { 'action' => 'x' }, { 'action' => [] }, { 'action' => { 'resource' => '/a' } },
     { 'action' => { 'verb' => 'x' } }, { 'action' => { 'verb' => 5, 'resource' => '/a' } }, { 'action' => { 'verb' => 'x', 'resource' => 5 } },
     { 'action' => { 'verb' => nil, 'resource' => '/a' } }, { 'action' => { 'verb' => 'x', 'resource' => nil } }].each do |c|
      ZbQ.ck("undecidable context #{c.inspect}", wm.call({ 'verb' => 'x', 'resource' => '/a' }, c), true)
    end
    # not a Hash: undecidable even when the duck answers like one (verbs differ so a decision would be "no match")
    ZbQ.ck('duck context', wm.call({ 'verb' => 'x' }, ZbQ::Duck.new('action' => { 'verb' => 'zzz', 'resource' => '/a' })), true)
    ZbQ.ck('duck action', wm.call({ 'verb' => 'x' }, { 'action' => ZbQ::Duck.new('verb' => 'zzz', 'resource' => '/a') }), true)
    ZbQ.ck('resource missing', wm.call({ 'verb' => 'x', 'resource' => '/a' }, { 'action' => { 'verb' => 'x' } }), true)
    ZbQ.ck('resource missing, trigger without resource', wm.call({ 'verb' => 'x' }, { 'action' => { 'verb' => 'x' } }), true)
    ZbQ.ck('verb missing, wrong verb would not match', wm.call({ 'verb' => 'q' }, { 'action' => { 'resource' => '/a' } }), true)

    ZbQ.ck('verb match', wm.call({ 'verb' => 'x' }, ctx), true)
    ZbQ.ck('verb mismatch', wm.call({ 'verb' => 'y' }, ctx), false)
    ZbQ.ck('verb list match', wm.call({ 'verb' => %w[y x] }, ctx), true)
    ZbQ.ck('verb list mismatch', wm.call({ 'verb' => %w[y z] }, ctx), false)
    ZbQ.ck('resource match', wm.call({ 'verb' => 'x', 'resource' => '/a' }, ctx), true)
    ZbQ.ck('resource mismatch', wm.call({ 'verb' => 'x', 'resource' => '/b' }, ctx), false)
    ZbQ.ck('verb mismatch, no resource trigger, short-circuits where', wm.call({ 'verb' => 'y', 'where' => [{ 'field' => 'action.params.k', 'op' => 'eq', 'value' => 1 }] }, ctx), false)
    leaf = { 'field' => 'action.params.k', 'op' => 'eq', 'value' => true }
    with_k = ->(v) { ZbQ.act('x', '/a', { 'k' => v }) }
    ZbQ.ck('where clean true', wm.call({ 'verb' => 'x', 'where' => [leaf] }, with_k.call(true)), true)
    ZbQ.ck('where clean false', wm.call({ 'verb' => 'x', 'where' => [leaf] }, with_k.call(false)), false)
    ZbQ.ck('where unknown matches', wm.call({ 'verb' => 'x', 'where' => [leaf] }, ctx), true)
    ZbQ.ck('where second clean false', wm.call({ 'verb' => 'x', 'where' => [leaf, { 'field' => 'action.params.k', 'op' => 'eq', 'value' => 9 }] }, with_k.call(true)), false)
    ZbQ.ck('where all clean true', wm.call({ 'verb' => 'x', 'where' => [leaf, { 'field' => 'action.params.k', 'op' => 'ne', 'value' => 9 }] }, with_k.call(true)), true)
    ZbQ.ck('empty where', wm.call({ 'verb' => 'x', 'where' => [] }, ctx), true)

    # an over-long subject is not matched against a regex resource (the veto applies on the verb alone)
    long = ->(n) { ZbQ.act('x', "/#{'b' * (n - 1)}") }
    rx = { 'verb' => 'x', 'resource' => 're:/zzz' }
    ZbQ.ck('regex short subject no match', wm.call(rx, ZbQ.act('x', '/b')), false)
    ZbQ.ck('regex 512 units is evaluated', wm.call(rx, long.call(512)), false)
    ZbQ.ck('regex 513 units is oversized', wm.call(rx, long.call(513)), true)
    ZbQ.ck('regex oversized, wrong verb', wm.call(rx.merge('verb' => 'other'), long.call(600)), false)
    ZbQ.ck('regex oversized, where clean false', wm.call(rx.merge('where' => [leaf]), long.call(600).merge('action' => long.call(600)['action'].merge('params' => { 'k' => false }))), false)
    ZbQ.ck('plain resource is compared however long', wm.call({ 'verb' => 'x', 'resource' => '/zzz' }, long.call(600)), false)
    ZbQ.ck('no resource trigger, wrong verb', wm.call({ 'verb' => 'y' }, long.call(600)), false)
    ZbQ.ck('no resource trigger, long subject', wm.call({ 'verb' => 'x' }, long.call(600)), true)
    ZbQ.ck('unsafe regex matches', wm.call({ 'verb' => 'x', 'resource' => 're:(a+)+$' }, ctx), true)

    # a regex evaluation refused by the document budget is "could not decide": the veto applies
    outs = AtlasPca.with_regex_budget { Array.new(70) { wm.call({ 'verb' => 'x', 'resource' => 're:/zzz' }, ZbQ.act('x', '/b')) } }
    ZbQ.ck('first evaluations are clean misses', outs.first, false)
    ZbQ.ck('a refused evaluation vetoes', outs.last, true)
    ZbQ.ck('refusals begin after the budget', outs.index(true).between?(1, 69), true)

    wa = ->(w, c) { p.when_affirmative?(w, c) }
    ZbQ.ck('affirmative match', wa.call({ 'verb' => 'x' }, ctx), true)
    ZbQ.ck('affirmative mismatch', wa.call({ 'verb' => 'y' }, ctx), false)
    ZbQ.ck('affirmative resource', wa.call({ 'verb' => 'x', 'resource' => '/a' }, ctx), true)
    ZbQ.ck('affirmative resource mismatch', wa.call({ 'verb' => 'x', 'resource' => '/b' }, ctx), false)
    ZbQ.ck('affirmative unknown where is not a match', wa.call({ 'verb' => 'x', 'where' => [leaf] }, ctx), false)
    ZbQ.ck('affirmative clean where', wa.call({ 'verb' => 'x', 'where' => [leaf] }, with_k.call(true)), true)
    ZbQ.ck('affirmative invalid trigger', wa.call({ 'verb' => ['x', ''] }, ctx), false)
    ZbQ.ck('affirmative non object', wa.call(nil, ctx), false)
    boom = Class.new(Hash) { def [](_k) = raise('boom') }.new
    ZbQ.ck('affirmative raising trigger fails closed', wa.call(boom, ctx), false)
    ZbQ.ck('conservative raising trigger vetoes', wm.call(boom, ctx), true)
    true
  end
end
