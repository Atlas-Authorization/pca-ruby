# frozen_string_literal: true

# zb_prohibitions_a: exact-value checks of the prohibition engine's helpers, validators and constitution commitment
# (packages/pca/src/prohibitions.ts is authoritative). AtlasPca is resolved at call time.

module MutationKill
  module ZbP
    module_function

    # A mutation run re-evaluates the library under a new AtlasPca; resolve the module on every use.
    def live(name)
      Module.new do
        define_singleton_method(:method_missing) { |m, *a, **k, &b| AtlasPca.const_get(name).public_send(m, *a, **k, &b) }
        define_singleton_method(:respond_to_missing?) { |m, priv = false| AtlasPca.const_get(name).respond_to?(m, priv) }
        define_singleton_method(:const_missing) { |c| AtlasPca.const_get(name).const_get(c) }
      end
    end

    P = live(:Prohibitions)
    NOW = 1_700_000_000_000

    def gate? = (f = ENV['MUT_FILE']).nil? || f.empty? || f == 'prohibitions.rb'
    def ck(label, got, want) = got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    def key = (@key ||= AtlasPca::KeyPair.generate)
    def other = (@other ||= AtlasPca::KeyPair.generate)

    # The exception a block raises (nil when it returns).
    def err
      yield
      nil
    rescue StandardError, SystemStackError => e
      e
    end

    def w(verb = 'x') = { 'verb' => verb }
    def never(id = 'n') = { 'id' => id, 'kind' => 'never', 'when' => w }
    def leaf = { 'field' => 'action.verb', 'op' => 'eq', 'value' => 'x' }
    def con(invs = [never]) = { 'version' => 1, 'principal' => key.public, 'invariants' => invs }
    def nest_all(n)
      c = leaf
      n.times { c = { 'all_of' => [c] } }
      c
    end

    def nest_not(n)
      c = leaf
      n.times { c = { 'not' => c } }
      c
    end
  end

  t('zb prohibitions: fin? int? neg_zero? jsn empty_state domain_message') do
    next true unless ZbP.gate?

    p = ZbP::P
    [[1, true], [0, true], [-3, true], [1.5, true], [-0.0, true], [Float::INFINITY, false], [-Float::INFINITY, false], [Float::NAN, false],
     ['1', false], [true, false], [nil, false], [[1], false]].each { |v, want| ZbP.ck("fin? #{v.inspect}", p.fin?(v), want) }
    [[3, true], [0, true], [-2, true], [3.0, true], [-0.0, true], [3.5, false], [Float::INFINITY, false], [Float::NAN, false], ['3', false], [nil, false],
     [true, false], [[3], false], [-1.0, true]].each { |v, want| ZbP.ck("int? #{v.inspect}", p.int?(v), want) }
    [[-0.0, true], [0.0, false], [0, false], [-1.0, false], [1.0, false], [-0.5, false], ['x', false], [nil, false], [true, false]].each do |v, want|
      ZbP.ck("neg_zero? #{v.inspect}", p.neg_zero?(v), want)
    end
    ZbP.ck('jsn int', p.jsn(5), '5')
    ZbP.ck('jsn neg int', p.jsn(-7), '-7')
    ZbP.ck('jsn big int stays an integer string', p.jsn(2**70), (2**70).to_s)
    ZbP.ck('jsn float', p.jsn(1.5), '1.5')
    ZbP.ck('jsn whole float', p.jsn(100.0), '100')
    ZbP.ck('jsn 1e21', p.jsn(1e21), '1e+21')
    ZbP.ck('jsn neg zero', p.jsn(-0.0), '0')
    ZbP.ck('jsn small', p.jsn(0.000001), '0.000001')
    ZbP.ck('jsn tiny', p.jsn(1e-7), '1e-7')
    ZbP.ck('empty_state', p.empty_state(42), { 'now' => 42, 'seq' => 0, 'parent' => nil, 'ledger' => {}, 'latched' => {} })
    ZbP.ck('empty_state keys', p.empty_state(1).keys, %w[now seq parent ledger latched])
    sha = AtlasPca.sha('id'.b)
    ZbP.ck('domain_message', p.domain_message("d\0", 'id'), "d\0".b + sha)
    ZbP.ck('domain_message non-ascii domain is bytes', p.domain_message("dé", 'id'), "dé".b + sha)
    ZbP.ck('domain_message frozen id', p.domain_message('d', 'id'.freeze), 'd'.b + sha)
    ZbP.ck('domain_message encodes id as utf-8 bytes', p.domain_message('d', "é"), 'd'.b + AtlasPca.sha("é".b))
    true
  end

  t('zb prohibitions: sign_constitution refusal text and verify_constitution results') do
    next true unless ZbP.gate?

    p = ZbP::P
    e = ZbP.err { p.sign_constitution({ 'version' => 2, 'invariants' => [] }, ZbP.key) }
    ZbP.ck('sign refusal class', e.class, TypeError)
    ZbP.ck('sign refusal text', e.message, 'signConstitution: unsupported version 2; principal missing')
    e = ZbP.err { p.sign_constitution({}, ZbP.key) }
    ZbP.ck('sign refusal text 2', e.message, 'signConstitution: unsupported version undefined; principal missing; invariants not an array')

    sc = p.sign_constitution(ZbP.con, ZbP.key)
    ZbP.ck('signed keys', sc.keys.sort, %w[id invariants principal sig version])
    ZbP.ck('body drops id and sig', p.body(sc), ZbP.con)
    ZbP.ck('id is the content address', sc['id'], p.constitution_id(ZbP.con))
    ZbP.ck('verify', p.verify_constitution(sc), { 'ok' => true })
    ZbP.ck('verify pinned', p.verify_constitution(sc, ZbP.key.public), { 'ok' => true })
    ZbP.ck('verify wrong pin', p.verify_constitution(sc, ZbP.other.public), { 'ok' => false, 'reason' => 'principal mismatch' })
    ZbP.ck('verify nil pin', p.verify_constitution(sc, nil), { 'ok' => false, 'reason' => 'principal mismatch' })
    ZbP.ck('verify malformed', p.verify_constitution({ 'version' => 2 }), { 'ok' => false, 'reason' => 'unsupported version 2' })
    ZbP.ck('verify malformed first problem only', p.verify_constitution({}), { 'ok' => false, 'reason' => 'unsupported version undefined' })
    ZbP.ck('verify not an object', p.verify_constitution(nil), { 'ok' => false, 'reason' => 'constitution not an object' })
    ZbP.ck('id tampered', p.verify_constitution(sc.merge('id' => 'x')), { 'ok' => false, 'reason' => 'id does not match content' })
    ZbP.ck('id missing', p.verify_constitution(sc.reject { |k, _| k == 'id' }), { 'ok' => false, 'reason' => 'id does not match content' })
    ZbP.ck('id non string', p.verify_constitution(sc.merge('id' => 5)), { 'ok' => false, 'reason' => 'id does not match content' })
    ZbP.ck('content tampered', p.verify_constitution(sc.merge('invariants' => [ZbP.never('m')])), { 'ok' => false, 'reason' => 'id does not match content' })
    ZbP.ck('sig missing', p.verify_constitution(sc.reject { |k, _| k == 'sig' }), { 'ok' => false, 'reason' => 'bad signature' })
    ZbP.ck('sig non string', p.verify_constitution(sc.merge('sig' => 7)), { 'ok' => false, 'reason' => 'bad signature' })
    ZbP.ck('sig nil', p.verify_constitution(sc.merge('sig' => nil)), { 'ok' => false, 'reason' => 'bad signature' })
    forged = p.sign_constitution(ZbP.con, ZbP.other)
    ZbP.ck('sig by another key', p.verify_constitution(sc.merge('sig' => forged['sig'])), { 'ok' => false, 'reason' => 'bad signature' })
    ZbP.ck('principal swapped to the signer of another doc', p.verify_constitution(forged), { 'ok' => false, 'reason' => 'bad signature' })
    # an unrelated member that cannot be canonicalised raises inside the verifier: it must fail closed
    odd = sc.merge('x' => Object.new)
    ZbP.ck('fail closed', p.verify_constitution(odd), { 'ok' => false, 'reason' => 'verification error (fail closed)' })
    true
  end

  t('zb prohibitions: validate_condition exact problems') do
    next true unless ZbP.gate?

    p = ZbP::P
    vc = ->(c, d = 0) { p.validate_condition(c, d) }
    [5, nil, 'x', [], true].each { |v| ZbP.ck("not an object #{v.inspect}", vc.call(v), 'condition not an object') }
    ZbP.ck('leaf ok', vc.call(ZbP.leaf), nil)
    ZbP.ck('depth 32 ok', vc.call(ZbP.leaf, 32), nil)
    ZbP.ck('depth 33 too deep', vc.call(ZbP.leaf, 33), 'condition nesting too deep')
    ZbP.ck('all_of nested 32 ok', vc.call(ZbP.nest_all(32)), nil)
    ZbP.ck('all_of nested 33 too deep', vc.call(ZbP.nest_all(33)), 'condition nesting too deep')
    ZbP.ck('any_of nested 32 ok', vc.call({ 'any_of' => [ZbP.nest_all(31)] }), nil)
    ZbP.ck('not nested 32 ok', vc.call(ZbP.nest_not(32)), nil)
    ZbP.ck('not nested 33 too deep', vc.call(ZbP.nest_not(33)), 'condition nesting too deep')
    ZbP.ck('not of a bad leaf', vc.call({ 'not' => { 'field' => '' , 'op' => 'eq' } }), 'condition.field missing')
    ZbP.ck('not of a non object', vc.call({ 'not' => 5 }), 'condition not an object')
    ZbP.ck('all_of empty', vc.call({ 'all_of' => [] }), 'condition.all_of must be a non-empty array')
    ZbP.ck('all_of non array', vc.call({ 'all_of' => 'x' }), 'condition.all_of must be a non-empty array')
    ZbP.ck('all_of nil', vc.call({ 'all_of' => nil }), 'condition.all_of must be a non-empty array')
    ZbP.ck('any_of empty', vc.call({ 'any_of' => [] }), 'condition.any_of must be a non-empty array')
    ZbP.ck('any_of non array', vc.call({ 'any_of' => {} }), 'condition.any_of must be a non-empty array')
    ZbP.ck('all_of first child bad', vc.call({ 'all_of' => [{ 'field' => 'a', 'op' => 'zz' }, ZbP.leaf] }), 'unknown condition op zz')
    ZbP.ck('all_of second child bad', vc.call({ 'all_of' => [ZbP.leaf, { 'field' => '', 'op' => 'eq' }] }), 'condition.field missing')
    ZbP.ck('any_of children ok', vc.call({ 'any_of' => [ZbP.leaf, ZbP.leaf] }), nil)
    ZbP.ck('all_of wins over any_of key', vc.call({ 'all_of' => [], 'any_of' => [ZbP.leaf] }), 'condition.all_of must be a non-empty array')
    ZbP.ck('not wins', vc.call({ 'not' => ZbP.leaf, 'all_of' => [] }), nil)
    [nil, '', 5, ['a']].each { |f| ZbP.ck("field #{f.inspect}", vc.call({ 'field' => f, 'op' => 'eq' }), 'condition.field missing') }
    ZbP.ck('field missing', vc.call({ 'op' => 'eq' }), 'condition.field missing')
    ZbP.ck('op missing', vc.call({ 'field' => 'a' }), 'unknown condition op undefined')
    ZbP.ck('op nil', vc.call({ 'field' => 'a', 'op' => nil }), 'unknown condition op null')
    ZbP.ck('op number', vc.call({ 'field' => 'a', 'op' => 5 }), 'unknown condition op 5')
    ZbP.ck('op true', vc.call({ 'field' => 'a', 'op' => true }), 'unknown condition op true')
    ZbP.ck('op array', vc.call({ 'field' => 'a', 'op' => %w[a b] }), 'unknown condition op a,b')
    ZbP.ck('op unknown', vc.call({ 'field' => 'a', 'op' => 'bogus' }), 'unknown condition op bogus')
    ZbP.ck('op case', vc.call({ 'field' => 'a', 'op' => 'EQ' }), 'unknown condition op EQ')
    ZbP::P::OPS.each { |o| ZbP.ck("op #{o}", vc.call({ 'field' => 'a', 'op' => o }), nil) }
    ZbP.ck('ref ok', vc.call({ 'field' => 'a', 'op' => 'eq', 'ref' => 'action.x' }), nil)
    ['', 5, nil, ['a'], true].each { |r| ZbP.ck("ref #{r.inspect}", vc.call({ 'field' => 'a', 'op' => 'eq', 'ref' => r }), 'bad condition.ref') }
    ZbP.ck('collection ok', vc.call({ 'field' => 'a', 'op' => 'member_of', 'collection' => 'c' }), nil)
    ZbP.ck('member_of without collection', vc.call({ 'field' => 'a', 'op' => 'member_of' }), nil)
    ['', 5, nil, ['a']].each do |c|
      ZbP.ck("collection #{c.inspect}", vc.call({ 'field' => 'a', 'op' => 'member_of', 'collection' => c }), 'bad condition.collection')
    end
    ZbP.ck('collection on another op is not checked', vc.call({ 'field' => 'a', 'op' => 'eq', 'collection' => '' }), nil)
    ZbP.ck('collection on in', vc.call({ 'field' => 'a', 'op' => 'in', 'collection' => 5 }), nil)
    true
  end

  t('zb prohibitions: validate_conditions and validate_when exact problems') do
    next true unless ZbP.gate?

    p = ZbP::P
    [nil, [], 'x', 5, {}].each { |v| ZbP.ck("conditions #{v.inspect}", p.validate_conditions(v, 'lbl'), 'lbl must be a non-empty array') }
    ZbP.ck('conditions ok', p.validate_conditions([ZbP.leaf], 'lbl'), nil)
    ZbP.ck('conditions two ok', p.validate_conditions([ZbP.leaf, ZbP.leaf], 'lbl'), nil)
    ZbP.ck('conditions bad second', p.validate_conditions([ZbP.leaf, { 'field' => 'a', 'op' => 'q' }], 'lbl'), 'unknown condition op q')
    ZbP.ck('conditions bad first', p.validate_conditions([5, ZbP.leaf], 'lbl'), 'condition not an object')

    vw = ->(x) { p.validate_when(x, 'L') }
    [nil, 5, 'x', []].each { |v| ZbP.ck("when #{v.inspect}", vw.call(v), 'L: not an object') }
    ZbP.ck('when ok', vw.call(ZbP.w), nil)
    ZbP.ck('when verb list ok', vw.call({ 'verb' => %w[a b] }), nil)
    [nil, '', 5, [], [''], ['a', ''], ['a', 5], ['a', nil], {}, true].each { |v| ZbP.ck("verb #{v.inspect}", vw.call({ 'verb' => v }), 'L: bad verb') }
    ZbP.ck('verb missing', vw.call({}), 'L: bad verb')
    ZbP.ck('resource ok', vw.call({ 'verb' => 'x', 'resource' => '/a/*' }), nil)
    ZbP.ck('resource empty string ok', vw.call({ 'verb' => 'x', 'resource' => '' }), nil)
    [5, nil, ['a']].each { |v| ZbP.ck("resource #{v.inspect}", vw.call({ 'verb' => 'x', 'resource' => v }), 'L: bad resource') }
    ZbP.ck('safe regex resource', vw.call({ 'verb' => 'x', 'resource' => 're:/a/[^/]+' }), nil)
    ZbP.ck('unsafe regex resource', vw.call({ 'verb' => 'x', 'resource' => 're:(a+)+$' }), 'L: unsafe regex resource')
    ZbP.ck('regex 200 chars', vw.call({ 'verb' => 'x', 'resource' => "re:#{'a' * 200}" }), nil)
    ZbP.ck('regex 201 chars', vw.call({ 'verb' => 'x', 'resource' => "re:#{'a' * 201}" }), 'L: unsafe regex resource')
    ZbP.ck('where ok', vw.call({ 'verb' => 'x', 'where' => [ZbP.leaf] }), nil)
    ZbP.ck('where empty ok', vw.call({ 'verb' => 'x', 'where' => [] }), nil)
    ['x', nil, {}, 5].each { |v| ZbP.ck("where #{v.inspect}", vw.call({ 'verb' => 'x', 'where' => v }), 'L: where not an array') }
    ZbP.ck('where bad condition', vw.call({ 'verb' => 'x', 'where' => [ZbP.leaf, 5] }), 'L: condition not an object')
    ZbP.ck('where bad op', vw.call({ 'verb' => 'x', 'where' => [{ 'field' => 'a', 'op' => 'zz' }] }), 'L: unknown condition op zz')
    ZbP.ck('verb checked before resource', vw.call({ 'verb' => '', 'resource' => 5 }), 'L: bad verb')
    true
  end

  t('zb prohibitions: validate_invariant exact problems per kind') do
    next true unless ZbP.gate?

    p = ZbP::P
    vi = ->(i) { p.validate_invariant(i) }
    bad_when = { 'verb' => '' }
    ZbP.ck('not an object', vi.call(5), ['invariant not an object'])
    ZbP.ck('nil', vi.call(nil), ['invariant not an object'])
    [nil, '', 5, ['a']].each { |id| ZbP.ck("id #{id.inspect}", vi.call({ 'id' => id, 'kind' => 'never' }), ['<no id>: missing id']) }
    ZbP.ck('id missing', vi.call({ 'kind' => 'never' }), ['<no id>: missing id'])
    ZbP.ck('id 128 ok', vi.call(ZbP.never('a' * 128)), [])
    ZbP.ck('id 129 too long', vi.call(ZbP.never('a' * 129)), ["#{'a' * 129}: id too long"])
    ZbP.ck('id 128 utf-16 units ok', vi.call(ZbP.never("é" * 128)), [])
    ZbP.ck('id 129 utf-16 units too long', vi.call(ZbP.never("é" * 129)), ["#{"é" * 129}: id too long"])
    %w[__proto__ constructor prototype].each { |id| ZbP.ck("forbidden #{id}", vi.call(ZbP.never(id)), ["#{id}: forbidden id"]) }
    ZbP.ck('never ok', vi.call(ZbP.never), [])
    ZbP.ck('never bad when', vi.call({ 'id' => 'x', 'kind' => 'never', 'when' => bad_when }), ['x: when: bad verb'])
    ZbP.ck('never no when', vi.call({ 'id' => 'x', 'kind' => 'never' }), ['x: when: not an object'])

    nu = { 'id' => 'x', 'kind' => 'never_unless', 'when' => ZbP.w, 'unless' => [ZbP.leaf] }
    ZbP.ck('never_unless ok', vi.call(nu), [])
    ZbP.ck('never_unless bad when', vi.call(nu.merge('when' => bad_when)), ['x: when: bad verb'])
    ZbP.ck('never_unless bad when and bad unless: when first', vi.call(nu.merge('when' => bad_when, 'unless' => [])), ['x: when: bad verb'])
    ZbP.ck('never_unless empty unless', vi.call(nu.merge('unless' => [])), ['x: unless must be a non-empty array'])
    ZbP.ck('never_unless missing unless', vi.call(nu.reject { |k, _| k == 'unless' }), ['x: unless must be a non-empty array'])
    ZbP.ck('never_unless bad unless leaf', vi.call(nu.merge('unless' => [{ 'field' => 'a', 'op' => 'zz' }])), ['x: unknown condition op zz'])

    cap = { 'id' => 'x', 'kind' => 'cap', 'when' => ZbP.w, 'amount' => 'action.params.n', 'max' => 5 }
    ZbP.ck('cap ok', vi.call(cap), [])
    ZbP.ck('cap max 0 ok', vi.call(cap.merge('max' => 0)), [])
    ZbP.ck('cap max float ok', vi.call(cap.merge('max' => 0.5)), [])
    ZbP.ck('cap window ok', vi.call(cap.merge('window_secs' => 1)), [])
    ZbP.ck('cap window fraction ok', vi.call(cap.merge('window_secs' => 0.5)), [])
    ZbP.ck('cap bad when', vi.call(cap.merge('when' => bad_when)), ['x: when: bad verb'])
    ZbP.ck('cap bad when beats bad amount', vi.call(cap.merge('when' => bad_when, 'amount' => 'q')), ['x: when: bad verb'])
    ['params.n', 'action', 'actions.n', 5, nil, ''].each do |a|
      ZbP.ck("cap amount #{a.inspect}", vi.call(cap.merge('amount' => a)), ['x: amount must be an action.* path'])
    end
    ZbP.ck('cap amount missing', vi.call(cap.reject { |k, _| k == 'amount' }), ['x: amount must be an action.* path'])
    ZbP.ck('cap amount action. only', vi.call(cap.merge('amount' => 'action.')), [])
    [-1, -0.5, nil, 'x', Float::INFINITY, Float::NAN, true].each do |m|
      ZbP.ck("cap max #{m.inspect}", vi.call(cap.merge('max' => m)), ['x: max must be a finite number >= 0'])
    end
    [0, -1, -0.5, nil, 'x', Float::INFINITY, true].each do |s|
      ZbP.ck("cap window_secs #{s.inspect}", vi.call(cap.merge('window_secs' => s)), ['x: bad window_secs'])
    end

    rate = { 'id' => 'x', 'kind' => 'rate', 'when' => ZbP.w, 'max' => 3, 'window_secs' => 60 }
    ZbP.ck('rate ok', vi.call(rate), [])
    ZbP.ck('rate max 0 ok', vi.call(rate.merge('max' => 0)), [])
    ZbP.ck('rate max 10000 ok', vi.call(rate.merge('max' => 10_000)), [])
    ZbP.ck('rate max whole float ok', vi.call(rate.merge('max' => 3.0)), [])
    ZbP.ck('rate window fraction ok', vi.call(rate.merge('window_secs' => 0.5)), [])
    ZbP.ck('rate window 1 ok', vi.call(rate.merge('window_secs' => 1)), [])
    ZbP.ck('rate bad when', vi.call(rate.merge('when' => bad_when)), ['x: when: bad verb'])
    [10_001, -1, 1.5, -0.0, nil, 'x', true, Float::INFINITY, Float::NAN].each do |m|
      ZbP.ck("rate max #{m.inspect}", vi.call(rate.merge('max' => m)), ['x: max must be an integer in [0,10000]'])
    end
    [0, -1, nil, 'x', Float::INFINITY, true, -0.5].each do |s|
      ZbP.ck("rate window_secs #{s.inspect}", vi.call(rate.merge('window_secs' => s)), ['x: window_secs must be > 0'])
    end
    ZbP.ck('rate window missing', vi.call(rate.reject { |k, _| k == 'window_secs' }), ['x: window_secs must be > 0'])

    na = { 'id' => 'x', 'kind' => 'never_after', 'after' => ZbP.w, 'forbid' => ZbP.w('y') }
    ZbP.ck('never_after ok', vi.call(na), [])
    ZbP.ck('never_after bad after', vi.call(na.merge('after' => bad_when)), ['x: after: bad verb'])
    ZbP.ck('never_after bad forbid', vi.call(na.merge('forbid' => bad_when)), ['x: forbid: bad verb'])
    ZbP.ck('never_after after first', vi.call(na.merge('after' => bad_when, 'forbid' => bad_when)), ['x: after: bad verb'])
    ZbP.ck('never_after missing after', vi.call(na.reject { |k, _| k == 'after' }), ['x: after: not an object'])
    ZbP.ck('never_after missing forbid', vi.call(na.reject { |k, _| k == 'forbid' }), ['x: forbid: not an object'])

    rp = { 'id' => 'x', 'kind' => 'require_prior', 'when' => ZbP.w, 'prior' => ZbP.w('y') }
    ZbP.ck('require_prior ok', vi.call(rp), [])
    ZbP.ck('require_prior bad when', vi.call(rp.merge('when' => bad_when)), ['x: when: bad verb'])
    ZbP.ck('require_prior bad prior', vi.call(rp.merge('prior' => bad_when)), ['x: prior: bad verb'])
    ZbP.ck('require_prior when first', vi.call(rp.merge('when' => bad_when, 'prior' => bad_when)), ['x: when: bad verb'])
    ZbP.ck('require_prior missing prior', vi.call(rp.reject { |k, _| k == 'prior' }), ['x: prior: not an object'])

    ra = { 'id' => 'x', 'kind' => 'require_approval_over', 'when' => ZbP.w, 'amount' => 'action.params.n', 'threshold' => 10, 'approved' => [ZbP.leaf] }
    ZbP.ck('approval ok', vi.call(ra), [])
    ZbP.ck('approval threshold 0 ok', vi.call(ra.merge('threshold' => 0)), [])
    ZbP.ck('approval bad when', vi.call(ra.merge('when' => bad_when)), ['x: when: bad verb'])
    ZbP.ck('approval bad when beats amount', vi.call(ra.merge('when' => bad_when, 'amount' => 'q')), ['x: when: bad verb'])
    ['q', 5, nil, 'actions.x'].each { |a| ZbP.ck("approval amount #{a.inspect}", vi.call(ra.merge('amount' => a)), ['x: amount must be an action.* path']) }
    [-1, nil, 'x', Float::INFINITY, Float::NAN].each do |t|
      ZbP.ck("approval threshold #{t.inspect}", vi.call(ra.merge('threshold' => t)), ['x: threshold must be a finite number >= 0'])
    end
    ZbP.ck('approval empty approved', vi.call(ra.merge('approved' => [])), ['x: approved must be a non-empty array'])
    ZbP.ck('approval missing approved', vi.call(ra.reject { |k, _| k == 'approved' }), ['x: approved must be a non-empty array'])
    ZbP.ck('approval bad approved leaf', vi.call(ra.merge('approved' => [{ 'field' => 'a', 'op' => 'zz' }])), ['x: unknown condition op zz'])

    ZbP.ck('unknown kind', vi.call({ 'id' => 'x', 'kind' => 'eventually' }), ['x: unknown invariant kind eventually'])
    ZbP.ck('kind missing', vi.call({ 'id' => 'x' }), ['x: unknown invariant kind undefined'])
    ZbP.ck('kind nil', vi.call({ 'id' => 'x', 'kind' => nil }), ['x: unknown invariant kind null'])
    ZbP.ck('kind number', vi.call({ 'id' => 'x', 'kind' => 7 }), ['x: unknown invariant kind 7'])
    ZbP.ck('kind float', vi.call({ 'id' => 'x', 'kind' => 1.5 }), ['x: unknown invariant kind 1.5'])
    ZbP.ck('kind bool', vi.call({ 'id' => 'x', 'kind' => false }), ['x: unknown invariant kind false'])
    ZbP.ck('kind object', vi.call({ 'id' => 'x', 'kind' => {} }), ['x: unknown invariant kind [object Object]'])
    true
  end

  t('zb prohibitions: validate_constitution exact problems') do
    next true unless ZbP.gate?

    p = ZbP::P
    vc = ->(c) { p.validate_constitution(c) }
    ZbP.ck('not an object', vc.call(nil), ['constitution not an object'])
    ZbP.ck('array', vc.call([]), ['constitution not an object'])
    ZbP.ck('empty', vc.call({}), ['unsupported version undefined', 'principal missing', 'invariants not an array'])
    ZbP.ck('ok', vc.call(ZbP.con), [])
    ZbP.ck('no invariants ok', vc.call(ZbP.con([])), [])
    ZbP.ck('version 2', vc.call(ZbP.con.merge('version' => 2)), ['unsupported version 2'])
    ZbP.ck('version string', vc.call(ZbP.con.merge('version' => '1')), ['unsupported version 1'])
    ZbP.ck('version nil', vc.call(ZbP.con.merge('version' => nil)), ['unsupported version null'])
    ZbP.ck('version float', vc.call(ZbP.con.merge('version' => 1.5)), ['unsupported version 1.5'])
    ZbP.ck('version true', vc.call(ZbP.con.merge('version' => true)), ['unsupported version true'])
    [nil, '', 5, ['a']].each { |v| ZbP.ck("principal #{v.inspect}", vc.call(ZbP.con.merge('principal' => v)), ['principal missing']) }
    ZbP.ck('principal missing', vc.call(ZbP.con.reject { |k, _| k == 'principal' }), ['principal missing'])
    ZbP.ck('invariants non array', vc.call(ZbP.con.merge('invariants' => {})), ['invariants not an array'])
    ZbP.ck('invariants nil', vc.call(ZbP.con.merge('invariants' => nil)), ['invariants not an array'])
    ZbP.ck('problems accumulate with the array check', vc.call({ 'version' => 2, 'principal' => 'x', 'invariants' => 'q' }), ['unsupported version 2', 'invariants not an array'])
    ZbP.ck('two non objects', vc.call(ZbP.con([5, 6])), ['invariant not an object', 'invariant not an object'])
    ZbP.ck('non object then valid', vc.call(ZbP.con([nil, ZbP.never])), ['invariant not an object'])
    ZbP.ck('id-less problems do not collide', vc.call(ZbP.con([{ 'kind' => 'never' }, { 'kind' => 'never' }])), ['<no id>: missing id', '<no id>: missing id'])
    ZbP.ck('non string ids do not collide', vc.call(ZbP.con([{ 'id' => 5, 'kind' => 'never' }, { 'id' => 5, 'kind' => 'never' }])), ['<no id>: missing id', '<no id>: missing id'])
    ZbP.ck('duplicate id', vc.call(ZbP.con([ZbP.never('a'), ZbP.never('a')])), ['a: duplicate id'])
    ZbP.ck('three of one id', vc.call(ZbP.con([ZbP.never('a'), ZbP.never('a'), ZbP.never('a')])), ['a: duplicate id', 'a: duplicate id'])
    ZbP.ck('duplicate after a problem', vc.call(ZbP.con([{ 'id' => 'a', 'kind' => 'zz' }, ZbP.never('a')])), ['a: unknown invariant kind zz', 'a: duplicate id'])
    ZbP.ck('distinct ids', vc.call(ZbP.con([ZbP.never('a'), ZbP.never('b')])), [])
    many = ->(n) { Array.new(n) { |i| ZbP.never("i#{i}") } }
    ZbP.ck('256 invariants ok', vc.call(ZbP.con(many.call(256))), [])
    ZbP.ck('257 invariants', vc.call(ZbP.con(many.call(257))), ['too many invariants'])
    true
  end
end
