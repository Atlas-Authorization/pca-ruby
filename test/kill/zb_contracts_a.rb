# frozen_string_literal: true

# zb_contracts_a: exact-value checks of contract validation and commitment (packages/pca/src/contracts.ts is
# authoritative). AtlasPca is resolved at call time.

module MutationKill
  module ZbK
    module_function

    def live(name)
      Module.new do
        define_singleton_method(:method_missing) { |m, *a, **k, &b| AtlasPca.const_get(name).public_send(m, *a, **k, &b) }
        define_singleton_method(:respond_to_missing?) { |m, priv = false| AtlasPca.const_get(name).respond_to?(m, priv) }
        define_singleton_method(:const_missing) { |c| AtlasPca.const_get(name).const_get(c) }
      end
    end

    C = live(:Contracts)
    P = live(:Prohibitions)
    NOW = 1_700_000_000_000

    # A Hash whose reads of "kind" follow a plan {read number => :raise | :nil}: drives the clause fail-closed paths.
    class Flaky < Hash
      attr_accessor :plan

      def [](key)
        if key == 'kind' && @plan
          @reads = (@reads || 0) + 1
          act = @plan[@reads]
          raise 'boom' if act == :raise
          return nil if act == :nil
        end
        super
      end
    end

    # A Hash whose latched map raises on key?.
    class BoomLatched < Hash
      def key?(_key) = raise('boom')
    end

    def gate? = (f = ENV['MUT_FILE']).nil? || f.empty? || f == 'contracts.rb'
    def ck(label, got, want) = got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    def key = (@key ||= AtlasPca::KeyPair.generate)
    def other = (@other ||= AtlasPca::KeyPair.generate)

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

    def w(verb) = { 'verb' => verb }
    def never(id, verb = 'del') = { 'id' => id, 'kind' => 'never', 'p' => w(verb) }
    def always(id, verb = 'ok') = { 'id' => id, 'kind' => 'always', 'p' => w(verb) }
    def prec(id, p = 'review', q = 'deploy', kind = 'precedes') = { 'id' => id, 'kind' => kind, 'p' => w(p), 'q' => w(q) }
    def rw(id, p = 'req', q = 'resp', within = 3) = { 'id' => id, 'kind' => 'responds_within', 'p' => w(p), 'q' => w(q), 'within' => within }
    def andc(id, subs) = { 'id' => id, 'kind' => 'and', 'clauses' => subs }
    def inv(id, verb = 'x') = { 'id' => id, 'kind' => 'never', 'when' => w(verb) }
    def contract(clauses = nil, invs = nil)
      c = { 'version' => 1, 'principal' => key.public }
      c['clauses'] = clauses unless clauses.nil?
      c['invariants'] = invs unless invs.nil?
      c
    end

    def nest(levels)
      c = never('leaf')
      levels.times { |i| c = andc("and#{i}", [c]) }
      c
    end
  end

  t('zb contracts: validate_clause exact problems') do
    next true unless ZbK.gate?

    k = ZbK
    vc = ->(cl, seen = {}, depth = 1) { k::C.validate_clause(cl, seen, depth) }
    k.ck('never ok', vc.call(k.never('a')), [])
    k.ck('always ok', vc.call(k.always('a')), [])
    k.ck('depth 16 ok', vc.call(k.never('a'), {}, 16), [])
    k.ck('depth 17 too deep', vc.call(k.never('a'), {}, 17), ['clause nesting too deep'])
    k.ck('too deep before the shape', vc.call(5, {}, 17), ['clause nesting too deep'])
    [5, nil, 'x', [], true].each { |v| k.ck("not an object #{v.inspect}", vc.call(v), ['clause not an object']) }
    [nil, '', 5, ['a'], true].each { |id| k.ck("id #{id.inspect}", vc.call(k.never('a').merge('id' => id)), ['<no id>: missing clause id']) }
    k.ck('id missing', vc.call(k.never('a').reject { |kk, _| kk == 'id' }), ['<no id>: missing clause id'])
    k.ck('id 128 ok', vc.call(k.never('a' * 128)), [])
    k.ck('id 129 too long', vc.call(k.never('a' * 129)), ["#{'a' * 129}: id too long"])
    k.ck('id 128 utf-16 units ok', vc.call(k.never("é" * 128)), [])
    k.ck('id 129 utf-16 units too long', vc.call(k.never("é" * 129)), ["#{"é" * 129}: id too long"])
    %w[__proto__ constructor prototype].each { |id| k.ck("forbidden #{id}", vc.call(k.never(id)), ["#{id}: forbidden id"]) }
    seen = {}
    k.ck('first use of an id', vc.call(k.never('a'), seen), [])
    k.ck('the id is recorded', seen, { 'a' => true })
    k.ck('duplicate id', vc.call(k.never('a'), seen), ['a: duplicate id'])
    k.ck('a seen id from the constitution', vc.call(k.never('inv1'), { 'inv1' => true }), ['inv1: duplicate id'])
    k.ck('too long beats forbidden', vc.call(k.never('a' * 129), { 'a' * 129 => true }), ["#{'a' * 129}: id too long"])

    bad = { 'verb' => '' }
    k.ck('never bad p', vc.call(k.never('a').merge('p' => bad)), ['a: p: bad verb'])
    k.ck('never missing p', vc.call(k.never('a').reject { |kk, _| kk == 'p' }), ['a: p: not an object'])
    k.ck('always bad p', vc.call(k.always('a').merge('p' => bad)), ['a: p: bad verb'])
    %w[precedes requires_prior].each do |kind|
      c = k.prec('a', 'x', 'y', kind)
      k.ck("#{kind} ok", vc.call(c), [])
      k.ck("#{kind} bad p", vc.call(c.merge('p' => bad)), ['a: p: bad verb'])
      k.ck("#{kind} bad q", vc.call(c.merge('q' => bad)), ['a: q: bad verb'])
      k.ck("#{kind} p first", vc.call(c.merge('p' => bad, 'q' => bad)), ['a: p: bad verb'])
      k.ck("#{kind} missing q", vc.call(c.reject { |kk, _| kk == 'q' }), ['a: q: not an object'])
    end
    r = k.rw('a')
    k.ck('responds_within ok', vc.call(r), [])
    k.ck('responds_within bad p', vc.call(r.merge('p' => bad)), ['a: p: bad verb'])
    k.ck('responds_within bad q', vc.call(r.merge('q' => bad)), ['a: q: bad verb'])
    k.ck('responds_within p first', vc.call(r.merge('p' => bad, 'q' => bad)), ['a: p: bad verb'])
    k.ck('responds_within bad p beats bad within', vc.call(r.merge('p' => bad, 'within' => 0)), ['a: p: bad verb'])
    within = 'a: within must be an integer in [1, MAX_DEADLINE]'
    [1, 2, 1_000_000, 3.0].each { |v| k.ck("within #{v.inspect} ok", vc.call(r.merge('within' => v)), []) }
    [0, -1, 1_000_001, 1.5, 'x', nil, true, Float::NAN, Float::INFINITY, 0.5].each { |v| k.ck("within #{v.inspect}", vc.call(r.merge('within' => v)), [within]) }
    k.ck('within missing', vc.call(r.reject { |kk, _| kk == 'within' }), [within])

    a = k.andc('a', [k.never('b'), k.always('c')])
    k.ck('and ok', vc.call(a), [])
    [nil, [], 'x', 5, {}].each { |v| k.ck("and.clauses #{v.inspect}", vc.call(a.merge('clauses' => v)), ['a: and.clauses must be a non-empty array']) }
    k.ck('and.clauses missing', vc.call(a.reject { |kk, _| kk == 'clauses' }), ['a: and.clauses must be a non-empty array'])
    k.ck('and collects every child problem', vc.call(k.andc('a', [k.never('b').merge('p' => bad), 5, k.always('c').merge('p' => bad)])), ['b: p: bad verb', 'clause not an object', 'c: p: bad verb'])
    k.ck('and children share the seen ids', vc.call(k.andc('a', [k.never('b'), k.never('b')])), ['b: duplicate id'])
    k.ck('and child with the parent id', vc.call(k.andc('a', [k.never('a')])), ['a: duplicate id'])
    k.ck('nest 15 ok', vc.call(k.nest(15)), [])
    k.ck('nest 16 too deep', vc.call(k.nest(16)), ['clause nesting too deep'])
    k.ck('nested depth counts from the given depth', vc.call(k.nest(14), {}, 2), [])
    k.ck('nested depth counts from the given depth, too deep', vc.call(k.nest(15), {}, 2), ['clause nesting too deep'])

    k.ck('unknown kind', vc.call({ 'id' => 'a', 'kind' => 'eventually' }), ['a: unknown clause kind eventually'])
    k.ck('kind missing', vc.call({ 'id' => 'a' }), ['a: unknown clause kind undefined'])
    k.ck('kind nil', vc.call({ 'id' => 'a', 'kind' => nil }), ['a: unknown clause kind null'])
    k.ck('kind number', vc.call({ 'id' => 'a', 'kind' => 7 }), ['a: unknown clause kind 7'])
    k.ck('kind object', vc.call({ 'id' => 'a', 'kind' => {} }), ['a: unknown clause kind [object Object]'])
    k.ck('kind list', vc.call({ 'id' => 'a', 'kind' => %w[a b] }), ['a: unknown clause kind a,b'])
    true
  end

  t('zb contracts: count_clauses') do
    next true unless ZbK.gate?

    k = ZbK
    cc = ->(cls, d = 1) { k::C.count_clauses(cls, d) }
    k.ck('empty', cc.call([]), 0)
    k.ck('flat', cc.call([k.never('a'), k.always('b')]), 2)
    k.ck('and counts itself and its children', cc.call([k.andc('a', [k.never('b'), k.always('c')])]), 3)
    k.ck('nested and', cc.call([k.andc('a', [k.andc('b', [k.never('c')])])]), 3)
    k.ck('non objects count one each', cc.call([5, nil, 'x', [], k.never('a')]), 5)
    k.ck('and with non array clauses counts one', cc.call([{ 'kind' => 'and', 'clauses' => 'x' }]), 1)
    k.ck('and with nil clauses counts one', cc.call([{ 'kind' => 'and', 'clauses' => nil }]), 1)
    k.ck('and with hash clauses counts one', cc.call([{ 'kind' => 'and', 'clauses' => {} }]), 1)
    k.ck('only and nests', cc.call([{ 'kind' => 'never', 'clauses' => [k.never('x')] }]), 1)
    k.ck('and without a kind string', cc.call([{ 'clauses' => [k.never('x')] }]), 1)
    k.ck('depth 17 still counts', cc.call([k.never('a')], 17), 1)
    k.ck('depth 18 is too many at once', cc.call([k.never('a')], 18), 257)
    k.ck('16 nested ands', cc.call([k.nest(16)]), 17)
    k.ck('17 nested ands', cc.call([k.nest(17)]), 17 + 257)
    true
  end

  t('zb contracts: validate_contract exact problems') do
    next true unless ZbK.gate?

    k = ZbK
    vc = ->(c) { k::C.validate_contract(c) }
    [nil, 5, 'x', [], true].each { |v| k.ck("not an object #{v.inspect}", vc.call(v), ['contract not an object']) }
    k.ck('empty', vc.call({}), ['unsupported version undefined', 'principal missing'])
    k.ck('minimal ok', vc.call(k.contract), [])
    k.ck('clauses ok', vc.call(k.contract([k.never('a')])), [])
    k.ck('both ok', vc.call(k.contract([k.never('a')], [k.inv('i')])), [])
    k.ck('version 2', vc.call(k.contract.merge('version' => 2)), ['unsupported version 2'])
    k.ck('version nil', vc.call(k.contract.merge('version' => nil)), ['unsupported version null'])
    k.ck('version string', vc.call(k.contract.merge('version' => '1')), ['unsupported version 1'])
    k.ck('version float', vc.call(k.contract.merge('version' => 1.5)), ['unsupported version 1.5'])
    [nil, '', 5, ['a'], true].each { |v| k.ck("principal #{v.inspect}", vc.call(k.contract.merge('principal' => v)), ['principal missing']) }
    k.ck('invariants not an array', vc.call(k.contract.merge('invariants' => 'x')), ['invariants not an array'])
    k.ck('invariants nil', vc.call(k.contract.merge('invariants' => nil)), ['invariants not an array'])
    k.ck('invariants hash', vc.call(k.contract.merge('invariants' => {})), ['invariants not an array'])
    k.ck('invariants stop the check', vc.call({ 'version' => 2, 'principal' => 'p', 'invariants' => 'x', 'clauses' => 'y' }), ['unsupported version 2', 'invariants not an array'])
    k.ck('clauses not an array', vc.call(k.contract.merge('clauses' => 'x')), ['clauses not an array'])
    k.ck('clauses nil', vc.call(k.contract.merge('clauses' => nil)), ['clauses not an array'])
    k.ck('clauses hash', vc.call(k.contract.merge('clauses' => {})), ['clauses not an array'])
    k.ck('invalid invariant', vc.call(k.contract(nil, [{ 'id' => 'a', 'kind' => 'zz' }])), ['a: unknown invariant kind zz'])
    k.ck('invalid invariant text', vc.call(k.contract(nil, [k.inv('a').merge('when' => { 'verb' => '' })])), ['a: when: bad verb'])
    k.ck('invariant not an object', vc.call(k.contract(nil, [5])), ['invariant not an object'])
    k.ck('invariants not objects do not collide', vc.call(k.contract(nil, [5, nil])), ['invariant not an object', 'invariant not an object'])
    k.ck('invariants without ids do not collide', vc.call(k.contract(nil, [{ 'kind' => 'never' }, { 'kind' => 'never' }])), ['<no id>: missing id', '<no id>: missing id'])
    k.ck('invariants with non string ids do not collide', vc.call(k.contract(nil, [{ 'id' => 5, 'kind' => 'never' }, { 'id' => 5, 'kind' => 'never' }])), ['<no id>: missing id', '<no id>: missing id'])
    k.ck('duplicate invariant', vc.call(k.contract(nil, [k.inv('a'), k.inv('a')])), ['a: duplicate id'])
    k.ck('duplicate invariant, problem first', vc.call(k.contract(nil, [{ 'id' => 'a', 'kind' => 'zz' }, k.inv('a')])), ['a: unknown invariant kind zz', 'a: duplicate id'])
    k.ck('a clause id equal to an invariant id', vc.call(k.contract([k.never('a')], [k.inv('a')])), ['a: duplicate id'])
    k.ck('duplicate clause', vc.call(k.contract([k.never('a'), k.always('a')])), ['a: duplicate id'])
    k.ck('invalid clause', vc.call(k.contract([k.never('a').merge('p' => { 'verb' => '' })])), ['a: p: bad verb'])
    k.ck('clause problems in order', vc.call(k.contract([k.never('a').merge('p' => { 'verb' => '' }), 5, k.never('b').merge('p' => { 'verb' => '' })])), ['a: p: bad verb', 'clause not an object', 'b: p: bad verb'])
    many_inv = ->(n) { Array.new(n) { |i| k.inv("i#{i}") } }
    many_cl = ->(n) { Array.new(n) { |i| k.never("c#{i}") } }
    k.ck('256 invariants ok', vc.call(k.contract(nil, many_inv.call(256))), [])
    k.ck('257 invariants', vc.call(k.contract(nil, many_inv.call(257))), ['too many invariants'])
    k.ck('256 clauses ok', vc.call(k.contract(many_cl.call(256))), [])
    k.ck('257 clauses', vc.call(k.contract(many_cl.call(257))), ['too many clauses'])
    k.ck('nested clauses count', vc.call(k.contract([k.andc('a', many_cl.call(255))])), [])
    k.ck('nested clauses count over', vc.call(k.contract([k.andc('a', many_cl.call(256))])), ['too many clauses'])
    k.ck('and with a non array does not break the count', vc.call(k.contract([{ 'id' => 'a', 'kind' => 'and', 'clauses' => 'x' }])), ['a: and.clauses must be a non-empty array'])
    k.ck('deep nesting is refused, not a crash', vc.call(k.contract([k.nest(40)])).first(2), ['too many clauses', 'clause nesting too deep'])
    true
  end

  t('zb contracts: sign_contract, verify_contract and the embedded constitution') do
    next true unless ZbK.gate?

    k = ZbK
    c = k::C
    e = ZbK.err_of { c.sign_contract({ 'version' => 2, 'clauses' => [] }, k.key) }
    k.ck('sign refusal', [e.class, e.message], [TypeError, 'signContract: unsupported version 2; principal missing'])
    e = ZbK.err_of { c.sign_contract({}, k.key) }
    k.ck('sign refusal, two problems joined', e.message, 'signContract: unsupported version undefined; principal missing')
    e = ZbK.err_of { c.sign_contract({ 'version' => 2, 'invariants' => 5 }, k.key) }
    k.ck('sign refusal, three', e.message, 'signContract: unsupported version 2; principal missing; invariants not an array')

    body = k.contract([k.never('a')], [k.inv('i')])
    sc = c.sign_contract(body, k.key)
    k.ck('signed keys', sc.keys.sort, %w[clauses id invariants principal sig version])
    k.ck('body drops id and sig', c.body(sc), body)
    k.ck('id is the content address', sc['id'], c.contract_id(body))
    k.ck('id is hash of the body', sc['id'], AtlasPca.hash_canonical(body))
    k.ck('verify', c.verify_contract(sc), { 'ok' => true })
    k.ck('verify pinned', c.verify_contract(sc, k.key.public), { 'ok' => true })
    k.ck('verify wrong pin', c.verify_contract(sc, k.other.public), { 'ok' => false, 'reason' => 'principal mismatch' })
    k.ck('verify nil pin', c.verify_contract(sc, nil), { 'ok' => false, 'reason' => 'principal mismatch' })
    k.ck('verify malformed', c.verify_contract({ 'version' => 2 }), { 'ok' => false, 'reason' => 'unsupported version 2' })
    k.ck('verify not an object', c.verify_contract(nil), { 'ok' => false, 'reason' => 'contract not an object' })
    k.ck('id tampered', c.verify_contract(sc.merge('id' => 'x')), { 'ok' => false, 'reason' => 'id does not match content' })
    k.ck('id missing', c.verify_contract(sc.reject { |kk, _| kk == 'id' }), { 'ok' => false, 'reason' => 'id does not match content' })
    k.ck('id non string', c.verify_contract(sc.merge('id' => 5)), { 'ok' => false, 'reason' => 'id does not match content' })
    k.ck('content tampered', c.verify_contract(sc.merge('clauses' => [k.never('b')])), { 'ok' => false, 'reason' => 'id does not match content' })
    k.ck('sig missing', c.verify_contract(sc.reject { |kk, _| kk == 'sig' }), { 'ok' => false, 'reason' => 'bad signature' })
    k.ck('sig non string', c.verify_contract(sc.merge('sig' => 7)), { 'ok' => false, 'reason' => 'bad signature' })
    k.ck('sig nil', c.verify_contract(sc.merge('sig' => nil)), { 'ok' => false, 'reason' => 'bad signature' })
    forged = c.sign_contract(body, k.other)
    k.ck('sig by another key', c.verify_contract(sc.merge('sig' => forged['sig'])), { 'ok' => false, 'reason' => 'bad signature' })
    k.ck('fail closed', c.verify_contract(sc.merge('x' => Object.new)), { 'ok' => false, 'reason' => 'verification error (fail closed)' })
    k.ck('the signature domain separates constitutions', AtlasPca.verify_b64u(k.key.public, k::P.domain_message("atlas-pca/constitution/v1\0", sc['id']), sc['sig']), false)
    k.ck('the signature is over the contract domain', AtlasPca.verify_b64u(k.key.public, k::P.domain_message("atlas-pca/contract/v1\0", sc['id']), sc['sig']), true)

    k.ck('embedded with invariants', c.embedded_constitution(body), { 'version' => 1, 'principal' => k.key.public, 'invariants' => [k.inv('i')] })
    k.ck('embedded without invariants', c.embedded_constitution(k.contract([k.never('a')])), { 'version' => 1, 'principal' => k.key.public, 'invariants' => [] })
    k.ck('embedded ignores a non array', c.embedded_constitution({ 'principal' => 'p', 'invariants' => 'x' })['invariants'], [])
    k.ck('embedded ignores a hash', c.embedded_constitution({ 'principal' => 'p', 'invariants' => { 'a' => 1 } })['invariants'], [])
    k.ck('embedded ignores nil', c.embedded_constitution({ 'principal' => 'p', 'invariants' => nil })['invariants'], [])
    k.ck('contract from a constitution', c.contract_from_constitution({ 'principal' => 'p', 'invariants' => [k.inv('i')] }), { 'version' => 1, 'principal' => 'p', 'invariants' => [k.inv('i')], 'clauses' => [] })

    # rows
    cl = k.never('a')
    k.ck('row pass', c.row(cl, true, nil), { 'id' => 'a', 'kind' => 'never', 'result' => 'pass' })
    k.ck('row violated', c.row(cl, false, nil), { 'id' => 'a', 'kind' => 'never', 'result' => 'violated' })
    k.ck('row with a reason', c.row(cl, false, 'why'), { 'id' => 'a', 'kind' => 'never', 'result' => 'violated', 'reason' => 'why' })
    k.ck('row with an empty reason has none', c.row(cl, false, ''), { 'id' => 'a', 'kind' => 'never', 'result' => 'violated' })
    k.ck('row with a reason on a pass', c.row(cl, true, 'note'), { 'id' => 'a', 'kind' => 'never', 'result' => 'pass', 'reason' => 'note' })
    k.ck('base transition', c.base_transition(cl, true), { ok: true, reason: nil, rows: [c.row(cl, true, nil)], latch_set: {}, deadline_set: {} })
    k.ck('base transition reason is nil, not false', c.base_transition(cl, true)[:reason].nil?, true)
    k.ck('base transition violated', c.base_transition(cl, false, 'why'), { ok: false, reason: 'why', rows: [c.row(cl, false, 'why')], latch_set: {}, deadline_set: {} })
    k.ck('contract_fail', c.contract_fail('i', 'why'), { 'ok' => false, 'violated' => ['i'], 'reasons' => ['i: why'], 'evaluated' => [{ 'id' => 'i', 'kind' => 'structural', 'result' => 'violated', 'reason' => 'why' }] })
    k.ck('enforce_result', c.enforce_result(true, 'ok', ['v'], ['r'], 3), { 'allow' => true, 'reason' => 'ok', 'violated' => ['v'], 'reasons' => ['r'], 'seq' => 3 })
    k.ck('unhashable marker', c::UNHASHABLE, '<unhashable>')
    k.ck('safe_str passes a value through', c.safe_str { 'v' }, 'v')
    k.ck('safe_str marks a failure', c.safe_str { raise 'boom' }, '<unhashable>')
    k.ck('constants', [c::MAX_ID_LEN, c::MAX_CLAUSES, c::MAX_CLAUSE_DEPTH, c::CONTRACT_VERSION, c::DOC_VERSION], [128, 256, 16, 1, 1])
    k.ck('js_max numbers', [c.js_max(1, 2), c.js_max(3, 2), c.js_max(2, 2), c.js_max(1.5, 2), c.js_max(2.5, 1), c.js_max(-1, -2), c.js_max(Float::INFINITY, 1)], [2, 3, 2, 2, 2.5, -1, Float::INFINITY])
    k.ck('js_max NaN first', c.js_max(Float::NAN, 5).nan?, true)
    k.ck('js_max NaN second', c.js_max(5, Float::NAN).nan?, true)
    k.ck('js_max NaN both', c.js_max(Float::NAN, Float::NAN).nan?, true)
    k.ck('js_max float second', c.js_max(1, 2.5), 2.5)
    k.ck('reset message', c.reset_message('i', 3), "atlas-pca/contract-reset/v1\0".b + AtlasPca.sha('i:3'))
    k.ck('reset message with a non ascii id', c.reset_message("é", 3), "atlas-pca/contract-reset/v1\0".b + AtlasPca.sha("é:3".b))
    k.ck('reset signature', AtlasPca.verify_b64u(k.key.public, c.reset_message('i', 3), c.sign_contract_reset(k.key, 'i', 3)), true)
    k.ck('reset signature binds the sequence', AtlasPca.verify_b64u(k.key.public, c.reset_message('i', 4), c.sign_contract_reset(k.key, 'i', 3)), false)
    true
  end
end
