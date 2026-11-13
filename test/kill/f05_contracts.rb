# frozen_string_literal: true

# f05: bounded safety-LTL behavioural contracts and the durable ContractEnforcer. Replays the shared vectors
# (packages/pca/conformance/contracts-vectors.json) and translates the reference's own tests (contracts.test.ts,
# contracts-fail-closed-table.test.ts, contracts-enforcer.test.ts). AtlasPca is resolved at call time.

module MutationKill
  module F05
    module_function

    # A mutation run re-evaluates the library under a new AtlasPca; a constant bound at load would keep testing the
    # original module and every mutant would survive. This stand-in resolves the module on each use.
    def live(name)
      Module.new do
        define_singleton_method(:method_missing) { |m, *a, **k, &b| AtlasPca.const_get(name).public_send(m, *a, **k, &b) }
        define_singleton_method(:respond_to_missing?) { |m, priv = false| AtlasPca.const_get(name).respond_to?(m, priv) }
        define_singleton_method(:const_missing) { |c| AtlasPca.const_get(name).const_get(c) }
      end
    end

    C = live(:Contracts)
    P = live(:Prohibitions)
    CONF = File.expand_path('../../conformance', __dir__)
    NOW = 1_700_000_000_000

    def vec = (@vec ||= AtlasPca.parse_json(File.read(File.join(CONF, 'contracts-vectors.json'), encoding: 'UTF-8'), loose: true))
    def gate?(*files) = (f = ENV['MUT_FILE']).nil? || f.empty? || files.include?(f)
    def ck(label, got, want) = got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    def key = (@key ||= AtlasPca::KeyPair.generate)

    def act(verb, resource = '/r', params = nil, env = nil)
      a = { 'verb' => verb, 'resource' => resource }
      a['params'] = params if params
      c = { 'action' => a }
      c['env'] = env if env
      c
    end

    def contract(clauses, invariants = []) = { 'version' => 1, 'principal' => key.public, 'invariants' => invariants, 'clauses' => clauses }

    # Fold a contract over a trace from genesis; advances only on ok.
    def run(c, actions)
      state = P.empty_state(NOW)
      results = actions.map do |a|
        r = C.advance_contract(state, a, c, { 'now' => state['now'] })
        state = r['next']
        r
      end
      { state: state, results: results, rejected: results.any? { |r| !r['ok'] }, first_reject: results.index { |r| !r['ok'] } || -1 }
    end

    def seeded(seed)
      a = seed & 0xffffffff
      lambda do
        a = (a + 0x6d2b79f5) & 0xffffffff
        t = ((a ^ (a >> 15)) * (1 | a)) & 0xffffffff
        t = ((t + (((t ^ (t >> 7)) * (61 | t)) & 0xffffffff)) & 0xffffffff) ^ t
        (((t ^ (t >> 14)) & 0xffffffff).to_f / 4_294_967_296)
      end
    end

    def nest(n)
      c = { 'id' => 'leaf', 'kind' => 'never', 'p' => { 'verb' => 'x' } }
      n.times { |i| c = { 'id' => "and#{i}", 'kind' => 'and', 'clauses' => [c] } }
      c
    end
  end

  # ---- shared vectors -----------------------------------------------------------------------------------------------

  t('f05 vectors: validate, check, verify rows replay exactly') do
    next true unless F05.gate?('contracts.rb')

    d = F05.vec
    raise 'rows' unless d['validate'].length > 4 && d['check'].length > 4 && d['verify'].length > 4
    d['validate'].each { |v| F05.ck(v['name'], F05::C.validate_contract(v['contract']), v['expect']['problems']) }
    d['check'].each { |v| F05.ck(v['name'], F05::C.check_contract(v['action'], v['contract'], v['state']), v['expect']) }
    d['verify'].each { |v| F05.ck(v['name'], (v.key?('principal') ? F05::C.verify_contract(v['contract'], v['principal']) : F05::C.verify_contract(v['contract'])), v['expect']) }
    true
  end

  t('f05 vectors: advance step sequences replay exactly (digests included)') do
    next true unless F05.gate?('contracts.rb')

    rows = F05.vec['advance']
    raise 'rows' unless rows.length > 4
    rows.each do |v|
      st = F05::P.empty_state(v['genesis_now'])
      v['steps'].each_with_index do |step, i|
        opts = step['options'] || {}
        o = {}
        o['now'] = opts['now'] unless opts['now'].nil?
        o['expectedSeq'] = opts['expectedSeq'] unless opts['expectedSeq'].nil?
        o['expectedStateDigest'] = F05::P.state_digest(F05::P.empty_state(v['genesis_now'])) if opts['stale_digest_of_genesis']
        r = F05::C.advance_contract(st, step['action'], v['contract'], o)
        st = r['next'] if r['ok']
        got = { 'ok' => r['ok'], 'decidedBy' => r['decidedBy'], 'violated' => r['violated'], 'reasons' => r['reasons'], 'seq' => r['next']['seq'],
                'deadlines' => r['next']['deadlines'] || {}, 'latched' => r['next']['latched'].keys.sort, 'state_digest' => F05::P.state_digest(r['next']) }
        F05.ck("#{v['name']} #{i}", got, step['expect'])
      end
    end
    true
  end

  t('f05 vectors: enforcer scenarios replay exactly') do
    next true unless F05.gate?('contracts.rb')

    head, *scen = F05.vec['enforcer']
    raise 'rows' unless scen.length > 4
    scen.each do |v|
      kv = AtlasPca::MemoryAtomicKv.new
      wall = head['clock']
      opts = { principal: head['principal'], now: -> { wall } }
      opts[:latch_on_violation] = v['options']['latchOnViolation'] if v['options']
      e = F05::C::ContractEnforcer.open(kv, head['contract'], **opts)
      kv.set("contract/#{head['contract']['id']}", v['stored_document']) unless v['stored_document'].nil?
      v['steps'].each_with_index do |st, i|
        n = "#{v['name']} #{i}"
        case st['op']
        when 'check'
          wall = st['wall'] || head['clock']
          F05.ck(n, e.check(st['action'], st.key?('permitted') ? st['permitted'] : true), st['expect'])
        when 'peek' then F05.ck(n, e.peek(st['action']), st['expect'])
        when 'state'
          r = begin
            e.state
          rescue F05::C::ContractEnforcerError
            :corrupt
          end
          got = r.nil? ? nil : { 'seq' => r['state']['seq'], 'now' => r['state']['now'], 'latched' => r['latched'], 'state_digest' => F05::P.state_digest(r['state']) } unless r == :corrupt
          F05.ck(n, got, st['expect']) unless r == :corrupt
        else F05.ck(n, { 'cleared' => e.reset(st['sig']) }, st['expect'])
        end
      end
    end
    other = AtlasPca::KeyPair.generate
    kv = AtlasPca::MemoryAtomicKv.new
    e = F05::C::ContractEnforcer.open(kv, head['contract'], principal: head['principal'], now: -> { head['clock'] })
    e.check(F05.act('delete'))
    F05.ck('a reset for another key does not clear', e.reset(F05::C.sign_contract_reset(other, head['contract']['id'], 0)), false)
    true
  end

  # ---- operators ----------------------------------------------------------------------------------------------------

  t('f05 operators: always, never, precedes / requires_prior, responds_within, and') do
    next true unless F05.gate?('contracts.rb')

    run = F05.method(:run)
    act = F05.method(:act)
    c = F05.contract([{ 'id' => 'only-safe', 'kind' => 'always', 'p' => { 'verb' => '*', 'resource' => '/safe/*' } }])
    F05.ck('always ok', run.call(c, [act.call('read', '/safe/a'), act.call('write', '/safe/b')])[:rejected], false)
    r = run.call(c, [act.call('read', '/safe/a'), act.call('read', '/prod/x')])
    F05.ck('always rejects', [r[:rejected], r[:first_reject], r[:results][1]['violated']], [true, 1, ['only-safe']])
    F05.ck('always reason', r[:results][1]['reasons'], ['only-safe: always-invariant violated (action does not satisfy p)'])
    cc = F05.contract([{ 'id' => 'need-param', 'kind' => 'always', 'p' => { 'verb' => '*', 'where' => [{ 'field' => 'action.params.ok', 'op' => 'eq', 'value' => true }] } }])
    F05.ck('always unresolvable is a violation', run.call(cc, [act.call('read', '/r')])[:rejected], true)
    F05.ck('always resolvable', run.call(cc, [act.call('read', '/r', { 'ok' => true })])[:rejected], false)

    nv = F05.contract([{ 'id' => 'no-delete', 'kind' => 'never', 'p' => { 'verb' => 'delete', 'resource' => '*' } }])
    F05.ck('never ok', run.call(nv, [act.call('read'), act.call('write')])[:rejected], false)
    r = run.call(nv, [act.call('read'), act.call('delete', '/x')])
    F05.ck('never rejects', [r[:rejected], r[:results][1]['violated'], r[:results][1]['reasons']], [true, ['no-delete'], ['no-delete: never-invariant violated (forbidden action)']])
    bad = F05.contract([{ 'id' => 'bad-re', 'kind' => 'never', 'p' => { 'verb' => 'x', 'resource' => 're:(a+)+' } }])
    raise 'unsafe regex accepted' if F05::C.validate_contract(bad).empty?
    F05.ck('invalid contract rejects', run.call(bad, [act.call('x', '/anything')])[:rejected], true)
    d = F05.contract([{ 'id' => 'd', 'kind' => 'never', 'p' => { 'verb' => 'x' }, 'description' => 'custom' }])
    F05.ck('description is the reason', run.call(d, [act.call('x')])[:results][0]['reasons'], ['d: custom'])

    %w[precedes requires_prior].each do |kind|
      pc = F05.contract([{ 'id' => 'review-before-deploy', 'kind' => kind, 'q' => { 'verb' => 'deploy' }, 'p' => { 'verb' => 'review' } }])
      F05.ck("#{kind} ok", run.call(pc, [act.call('review'), act.call('deploy')])[:rejected], false)
      r = run.call(pc, [act.call('deploy')])
      F05.ck("#{kind} rejects", [r[:rejected], r[:results][0]['violated']], [true, ['review-before-deploy']])
      F05.ck("#{kind} reason", r[:results][0]['reasons'], ['review-before-deploy: precedence violated (prerequisite p not yet admitted before q)'])
      F05.ck("#{kind} out of order", run.call(pc, [act.call('deploy'), act.call('review'), act.call('deploy')])[:results].map { |x| x['ok'] }, [false, true, true])
    end
    self_c = F05.contract([{ 'id' => 'x', 'kind' => 'precedes', 'p' => { 'verb' => 'open' }, 'q' => { 'verb' => 'open' } }])
    F05.ck('no self-satisfaction', run.call(self_c, [act.call('open'), act.call('open')])[:results].map { |x| x['ok'] }, [false, false])
    c2 = F05.contract([{ 'id' => 'y', 'kind' => 'precedes', 'p' => { 'verb' => 'prep' }, 'q' => { 'verb' => 'open' } }])
    F05.ck('prior latched then q', run.call(c2, [act.call('prep'), act.call('open')])[:rejected], false)
    amb = F05.contract([{ 'id' => 'z', 'kind' => 'precedes', 'p' => { 'verb' => 'review', 'where' => [{ 'field' => 'action.params.passed', 'op' => 'eq', 'value' => true }] }, 'q' => { 'verb' => 'deploy' } }])
    F05.ck('ambiguous prerequisite does not latch', run.call(amb, [act.call('review'), act.call('deploy')])[:results].map { |x| x['ok'] }, [true, false])

    ack = ->(within) { F05.contract([{ 'id' => 'ack', 'kind' => 'responds_within', 'p' => { 'verb' => 'request' }, 'q' => { 'verb' => 'ack' }, 'within' => within }]) }
    c = ack.call(2)
    F05.ck('within 1', run.call(c, [act.call('request'), act.call('ack')])[:rejected], false)
    F05.ck('within 2 boundary', run.call(c, [act.call('request'), act.call('noise'), act.call('ack')])[:rejected], false)
    r = run.call(c, [act.call('request'), act.call('noise'), act.call('noise'), act.call('ack')])
    F05.ck('missed deadline', [r[:rejected], r[:first_reject], r[:results][2]['violated']], [true, 2, ['ack']])
    F05.ck('missed reason', r[:results][2]['reasons'], ['ack: bounded-liveness deadline missed (no q within 2 actions of p)'])
    F05.ck('pending at end is fine', run.call(c, [act.call('request')])[:rejected], false)
    F05.ck('still budget', run.call(c, [act.call('request'), act.call('noise')])[:rejected], false)
    F05.ck('one response discharges all', run.call(c, [act.call('request'), act.call('request'), act.call('ack')])[:rejected], false)
    F05.ck('within 1 ok', run.call(ack.call(1), [act.call('request'), act.call('ack')])[:rejected], false)
    F05.ck('within 1 demands next', run.call(ack.call(1), [act.call('request'), act.call('noise')])[:rejected], true)
    F05.ck('ack before request does not pre-satisfy', run.call(c, [act.call('ack'), act.call('request'), act.call('noise'), act.call('noise')])[:rejected], true)
    F05.ck('overlapping stimuli keep the most urgent deadline', run.call(c, [act.call('request'), act.call('noise'), act.call('request'), act.call('noise')])[:rejected], true)
    st = run.call(c, [act.call('request')])[:state]
    F05.ck('open obligation is carried in the state', st['deadlines'], { 'ack' => 2 })
    F05.ck('discharged obligation clears', run.call(c, [act.call('request'), act.call('ack')])[:state]['deadlines'], nil)

    both = F05.contract([{ 'id' => 'both', 'kind' => 'and', 'clauses' => [{ 'id' => 'no-delete', 'kind' => 'never', 'p' => { 'verb' => 'delete' } },
                                                                          { 'id' => 'review-first', 'kind' => 'precedes', 'p' => { 'verb' => 'review' }, 'q' => { 'verb' => 'deploy' } }] }])
    F05.ck('and ok', run.call(both, [act.call('review'), act.call('deploy')])[:rejected], false)
    F05.ck('and child 1', run.call(both, [act.call('delete')])[:results][0]['violated'], ['no-delete'])
    F05.ck('and child 2', run.call(both, [act.call('deploy')])[:results][0]['violated'], ['review-first'])
    F05.ck('and emits no row of its own', F05::C.check_contract(act.call('read'), both, F05::P.empty_state(F05::NOW))['evaluated'].map { |e| e['id'] }, %w[no-delete review-first])
    true
  end

  # ---- composition with the constitution ----------------------------------------------------------------------------

  t('f05 composition: a plain constitution is the degenerate contract; both can veto') do
    next true unless F05.gate?('contracts.rb')

    spend = { 'id' => 'spend', 'kind' => 'cap', 'when' => { 'verb' => 'pay' }, 'amount' => 'action.params.usd', 'max' => 100, 'window_secs' => 86_400 }
    lock = { 'id' => 'lock', 'kind' => 'never_after', 'after' => { 'verb' => 'read', 'resource' => '/s/*' }, 'forbid' => { 'verb' => 'send' } }
    invs = [spend, lock]
    cons = { 'version' => 1, 'principal' => F05.key.public, 'invariants' => invs }
    degenerate = F05::C.contract_from_constitution(cons)
    F05.ck('embedded round trip', F05::C.embedded_constitution(degenerate)['invariants'], invs)
    F05.ck('embedded without invariants', F05::C.embedded_constitution({ 'principal' => 'p' }), { 'version' => 1, 'principal' => 'p', 'invariants' => [] })
    F05.ck('degenerate shape', [degenerate['version'], degenerate['clauses']], [1, []])
    trace = [F05.act('pay', '/v', { 'usd' => 40 }), F05.act('read', '/s/x'), F05.act('send', '/y'), F05.act('pay', '/v', { 'usd' => 80 })]
    cs = F05::P.empty_state(F05::NOW)
    ps = F05::P.empty_state(F05::NOW)
    trace.each do |a|
      pr = F05::P.check_prohibitions(a, cons, ps)
      cr = F05::C.advance_contract(cs, a, degenerate, { 'now' => cs['now'] })
      F05.ck('ok', cr['ok'], pr['ok'])
      F05.ck('violated', cr['violated'], pr['violated'])
      adv = F05::P.advance_state_strict(a, cons, ps)
      if pr['ok']
        F05.ck('plain advance', adv['ok'], true)
        F05.ck('digest identical', F05::P.state_digest(cr['next']), F05::P.state_digest(adv['state']))
        F05.ck('state identical', cr['next'], adv['state'])
        ps = adv['state']
        cs = cr['next']
      else
        F05.ck('refused leaves the state', cr['next'], cs)
        ps = F05::P.advance_state(a, cons, ps)
      end
    end
    cr = F05::C.advance_contract(F05::P.empty_state(F05::NOW), F05.act('pay', '/v', { 'usd' => 10 }), degenerate, { 'now' => F05::NOW })
    F05.ck('no deadlines key', cr['next'].key?('deadlines'), false)
    c = F05.contract([{ 'id' => 'ack', 'kind' => 'responds_within', 'p' => { 'verb' => 'open' }, 'q' => { 'verb' => 'close' }, 'within' => 2 }], invs)
    over = F05.run(c, [F05.act('pay', '/v', { 'usd' => 200 })])
    F05.ck('prohibition veto', [over[:rejected], over[:results][0]['violated']], [true, ['spend']])
    live = F05.run(c, [F05.act('open'), F05.act('x'), F05.act('y')])
    F05.ck('temporal veto', [live[:rejected], live[:results][2]['violated']], [true, ['ack']])
    F05.ck('evaluated covers both', F05::C.check_contract(F05.act('read', '/z'), c, F05::P.empty_state(F05::NOW))['evaluated'].map { |e| e['id'] }, %w[spend lock ack])
    true
  end

  # ---- commitment ---------------------------------------------------------------------------------------------------

  t('f05 commitment: sign, verify, tamper, malformed refusal, global id uniqueness') do
    next true unless F05.gate?('contracts.rb')

    c = F05.contract([{ 'id' => 'a', 'kind' => 'never', 'p' => { 'verb' => 'delete' } }])
    sc = F05::C.sign_contract(c, F05.key)
    F05.ck('id binds content', sc['id'], F05::C.contract_id(c))
    F05.ck('verify', F05::C.verify_contract(sc), { 'ok' => true })
    F05.ck('verify pinned', F05::C.verify_contract(sc, F05.key.public), { 'ok' => true })
    F05.ck('tampered', F05::C.verify_contract(sc.merge('clauses' => [{ 'id' => 'a', 'kind' => 'never', 'p' => { 'verb' => 'write' } }])), { 'ok' => false, 'reason' => 'id does not match content' })
    F05.ck('other principal embedded', F05::C.verify_contract(sc.merge('principal' => AtlasPca::KeyPair.generate.public))['ok'], false)
    F05.ck('wrong pin', F05::C.verify_contract(sc, AtlasPca::KeyPair.generate.public), { 'ok' => false, 'reason' => 'principal mismatch' })
    other = F05::C.sign_contract(c, AtlasPca::KeyPair.generate)
    F05.ck('foreign sig', F05::C.verify_contract(sc.merge('sig' => other['sig'])), { 'ok' => false, 'reason' => 'bad signature' })
    F05.ck('missing sig', F05::C.verify_contract(sc.reject { |k, _| k == 'sig' }), { 'ok' => false, 'reason' => 'bad signature' })
    F05.ck('non-string id', F05::C.verify_contract(sc.merge('id' => 5))['reason'], 'id does not match content')
    F05.ck('null', F05::C.verify_contract(nil)['ok'], false)
    F05.ck('domain', F05::C::CONTRACT_SIG_DOMAIN, "atlas-pca/contract/v1\0")
    raise 'signed a malformed contract' unless (begin; F05::C.sign_contract({ 'version' => 1, 'principal' => F05.key.public, 'clauses' => [{ 'id' => 'x' }] }, F05.key); false; rescue TypeError; true; end)
    dup = F05.contract([{ 'id' => 'dup', 'kind' => 'never', 'p' => { 'verb' => 'a' } }], [{ 'id' => 'dup', 'kind' => 'never', 'when' => { 'verb' => 'b' } }])
    raise 'duplicate across clauses and invariants' unless F05::C.validate_contract(dup).any? { |p| p.include?('duplicate') }
    true
  end

  t('f05 validation: exact problems, bounds, no stack overflow') do
    next true unless F05.gate?('contracts.rb')

    prin = F05.key.public
    base = ->(clauses) { { 'version' => 1, 'principal' => prin, 'clauses' => clauses } }
    never = { 'id' => 'a', 'kind' => 'never', 'p' => { 'verb' => 'x' } }
    [['not an object', nil, 'contract not an object'], ['wrong version', { 'version' => 2, 'principal' => prin }, 'unsupported version 2'],
     ['no principal', { 'version' => 1 }, 'principal missing'], ['clauses not an array', { 'version' => 1, 'principal' => prin, 'clauses' => {} }, 'clauses not an array'],
     ['invariants not an array', { 'version' => 1, 'principal' => prin, 'invariants' => 5 }, 'invariants not an array'],
     ['clause not an object', base.call([5]), 'clause not an object'], ['clause without id', base.call([{ 'kind' => 'never', 'p' => { 'verb' => 'x' } }]), '<no id>: missing clause id'],
     ['unknown kind', base.call([{ 'id' => 'u', 'kind' => 'eventually', 'p' => { 'verb' => 'x' } }]), 'u: unknown clause kind eventually'],
     ['forbidden id', base.call([never.merge('id' => '__proto__')]), '__proto__: forbidden id'], ['id too long', base.call([never.merge('id' => 'a' * 129)]), "#{'a' * 129}: id too long"],
     ['duplicate ids', base.call([never, never]), 'a: duplicate id'],
     ['within 0', base.call([{ 'id' => 'r', 'kind' => 'responds_within', 'p' => { 'verb' => 'x' }, 'q' => { 'verb' => 'y' }, 'within' => 0 }]), 'r: within must be an integer in [1, MAX_DEADLINE]'],
     ['within fractional', base.call([{ 'id' => 'r', 'kind' => 'responds_within', 'p' => { 'verb' => 'x' }, 'q' => { 'verb' => 'y' }, 'within' => 1.5 }]), 'r: within must be an integer in [1, MAX_DEADLINE]'],
     ['within too big', base.call([{ 'id' => 'r', 'kind' => 'responds_within', 'p' => { 'verb' => 'x' }, 'q' => { 'verb' => 'y' }, 'within' => 1_000_001 }]), 'r: within must be an integer in [1, MAX_DEADLINE]'],
     ['bad q', base.call([{ 'id' => 'r', 'kind' => 'responds_within', 'p' => { 'verb' => 'x' }, 'q' => { 'verb' => '' }, 'within' => 1 }]), 'r: q: bad verb'],
     ['bad p', base.call([{ 'id' => 'r', 'kind' => 'precedes', 'p' => 5, 'q' => { 'verb' => 'y' } }]), 'r: p: not an object'],
     ['empty and', base.call([{ 'id' => 'n', 'kind' => 'and', 'clauses' => [] }]), 'n: and.clauses must be a non-empty array']].each do |name, c, problem|
      raise "#{name}: #{F05::C.validate_contract(c).inspect}" unless F05::C.validate_contract(c).include?(problem)
    end
    many = Array.new(257) { |i| { 'id' => "c#{i}", 'kind' => 'never', 'p' => { 'verb' => 'x' } } }
    raise 'too many' unless F05::C.validate_contract(base.call(many)).include?('too many clauses')
    F05.ck('256 fine', F05::C.validate_contract(base.call(many.first(256))), [])
    F05.ck('depth bound ok', F05::C.validate_contract(base.call([F05.nest(14)])), [])
    raise 'deep nest accepted' unless F05::C.validate_contract(base.call([F05.nest(18)])).any? { |p| p.include?('too deep') }
    raise 'huge nest accepted' if F05::C.validate_contract(base.call([F05.nest(20_000)])).empty?
    F05.ck('count nested', F05::C.count_clauses([F05.nest(3)]), 4)
    F05.ck('count absurd', F05::C.count_clauses([F05.nest(30)]), 274)
    F05.ck('js_max', [F05::C.js_max(1, 2), F05::C.js_max(Float::NAN, 2).nan?, F05::C.js_max(2, Float::NAN).nan?], [2, true, true])
    many_inv = Array.new(257) { |i| { 'id' => "i#{i}", 'kind' => 'never', 'when' => { 'verb' => 'x' } } }
    raise 'too many invariants' unless F05::C.validate_contract({ 'version' => 1, 'principal' => prin, 'invariants' => many_inv }).include?('too many invariants')
    true
  end

  # ---- advance: CAS, forged state, clocks ---------------------------------------------------------------------------

  t('f05 advance: stale, forged and replayed state; totality') do
    next true unless F05.gate?('contracts.rb')

    c = F05.contract([{ 'id' => 'order', 'kind' => 'precedes', 'p' => { 'verb' => 'review' }, 'q' => { 'verb' => 'deploy' } }])
    s0 = F05::P.empty_state(F05::NOW)
    s1 = F05::C.advance_contract(s0, F05.act('review'), c)
    F05.ck('first admit', [s1['ok'], s1['next']['seq'], s1['next']['parent'].nil?], [true, 1, false])
    r = F05::C.advance_contract(s0, F05.act('review'), c, { 'expectedSeq' => 1 })
    F05.ck('stale seq', [r['ok'], r['decidedBy'], r['violated'], r['next'].equal?(s0), r['reasons'].last], [false, 'state', ['<state>'], true, '<state>: stale state head (seq)'])
    r = F05::C.advance_contract(s1['next'], F05.act('deploy'), c, { 'expectedStateDigest' => F05::P.state_digest(s0) })
    F05.ck('stale digest', [r['ok'], r['decidedBy'], r['reasons'].last], [false, 'state', '<state>: stale state head (digest)'])
    ok = F05::C.advance_contract(s1['next'], F05.act('deploy'), c, { 'expectedSeq' => s1['next']['seq'], 'expectedStateDigest' => F05::P.state_digest(s1['next']) })
    F05.ck('correct head', [ok['ok'], ok['next']['seq']], [true, 2])
    [{ 'seq' => -1 }, { 'seq' => 3, 'parent' => nil }, { 'seq' => 0, 'parent' => 'x' }, { 'now' => Float::INFINITY }, { 'ledger' => 5 }].each_with_index do |patch, i|
      forged = s0.merge(patch)
      r = F05::C.advance_contract(forged, F05.act('review'), c)
      F05.ck("forged #{i}", [r['ok'], r['next'].equal?(forged)], [false, true])
    end
    r = F05::C.advance_contract(s0, F05.act('deploy'), c)
    F05.ck('contract violation', [r['ok'], r['decidedBy'], r['violated']], [false, 'contract', ['order']])
    F05.ck('clock backwards', F05::C.advance_contract(s1['next'], F05.act('deploy'), c, { 'now' => F05::NOW - 1 }), F05::C.advance_contract(s1['next'], F05.act('deploy'), c, { 'now' => F05::NOW - 1 }))
    back = F05::C.advance_contract(s1['next'], F05.act('deploy'), c, { 'now' => F05::NOW - 1 })
    F05.ck('clock backwards refused', [back['ok'], back['decidedBy'], back['violated'].include?('<state>')], [false, 'state', true])
    smuggled = F05.contract([{ 'id' => 'u', 'kind' => 'eventually', 'p' => { 'verb' => 'x' } }])
    F05.ck('smuggled kind', F05::C.check_contract(F05.act('read'), smuggled, s0)['ok'], false)
    F05.ck('smuggled advance', F05::C.advance_contract(s0, F05.act('read'), smuggled)['ok'], false)
    never = F05.contract([{ 'id' => 'a', 'kind' => 'never', 'p' => { 'verb' => 'delete' } }])
    F05.ck('malformed action', F05::C.advance_contract(s0, { 'action' => { 'verb' => 1 } }, never)['ok'], false)
    F05.ck('malformed state', F05::C.advance_contract({ 'now' => Float::NAN }, F05.act('read'), never)['ok'], false)
    F05.ck('wrong version', F05::C.advance_contract(s0, F05.act('read'), { 'version' => 2, 'principal' => F05.key.public, 'clauses' => [] })['ok'], false)
    F05.ck('null contract', F05::C.check_contract(F05.act('read'), nil, s0)['ok'], false)
    bad = F05::C.advance_contract(s0, { 'action' => {} }, never)
    F05.ck('malformed input leaves state', [bad['next'], bad['decidedBy'], bad['violated']], [s0, 'state', ['<action>']])
    F05.ck('structural reason', F05::C.check_contract(F05.act('read'), nil, s0)['reasons'], ['<contract>: contract not an object'])
    v = F05::C.check_contract({ 'action' => { 'verb' => 1 } }, never, s0)
    F05.ck('structural row', v['evaluated'], [{ 'id' => '<action>', 'kind' => 'structural', 'result' => 'violated', 'reason' => 'malformed action' }])
    true
  end

  t('f05 check_and_advance_contract: permission AND contract; the monitor runs unconditionally') do
    next true unless F05.gate?('contracts.rb')

    c = F05.contract([{ 'id' => 'no-del', 'kind' => 'never', 'p' => { 'verb' => 'delete' } }])
    s0 = F05::P.empty_state(F05::NOW)
    a = F05::C.check_and_advance_contract(true, s0, F05.act('read'), c, { 'now' => F05::NOW })
    F05.ck('allowed', [a['allow'], a['permitted'], a['next']['seq'], a['decidedBy']], [true, true, 1, 'none'])
    n = F05::C.check_and_advance_contract(false, s0, F05.act('read'), c, { 'now' => F05::NOW })
    F05.ck('not permitted', [n['allow'], n['ok'], n['next'], n['reasons'], n['decidedBy']], [false, false, s0, ['<permission>: not permitted'], 'contract'])
    v = F05::C.check_and_advance_contract(true, s0, F05.act('delete'), c, { 'now' => F05::NOW })
    F05.ck('vetoed', [v['allow'], v['violated']], [false, ['no-del']])
    both = F05::C.check_and_advance_contract(false, s0, F05.act('delete'), c, { 'now' => F05::NOW })
    F05.ck('both fail keeps the contract verdict', [both['allow'], both['permitted'], both['violated']], [false, false, ['no-del']])
    F05.ck('only literal true permits', F05::C.check_and_advance_contract(1, s0, F05.act('read'), c)['allow'], false)
    true
  end

  # ---- property tests (deterministic generators) --------------------------------------------------------------------

  t('f05 properties: determinism, monotone hash-chaining, never and responds_within against independent oracles') do
    next true unless F05.gate?('contracts.rb')

    verbs = %w[read write pay deploy delete review ack request send open close]
    resources = %w[/a /b /prod/x /safe/y /s/z]
    pick = ->(r, xs) { xs[(r.call * xs.length).floor % xs.length] }
    rand_action = ->(r) { F05.act(pick.call(r, verbs), pick.call(r, resources), r.call < 0.3 ? { 'usd' => (r.call * 300).floor } : nil) }
    rand_clause = lambda do |r, id|
      kind = pick.call(r, %w[always never precedes requires_prior responds_within])
      p = { 'verb' => pick.call(r, verbs) }
      q = { 'verb' => pick.call(r, verbs) }
      case kind
      when 'always', 'never' then { 'id' => id, 'kind' => kind, 'p' => p }
      when 'responds_within' then { 'id' => id, 'kind' => kind, 'p' => p, 'q' => q, 'within' => 1 + (r.call * 4).floor }
      else { 'id' => id, 'kind' => kind, 'p' => p, 'q' => q }
      end
    end
    rand_contract = ->(r) { F05.contract(Array.new(1 + (r.call * 3).floor) { |i| rand_clause.call(r, "c#{i}") }) }
    (1..40).each do |seed|
      r = F05.seeded(seed)
      c = rand_contract.call(r)
      trace = Array.new(8) { rand_action.call(r) }
      a = F05.run(c, trace)
      b = F05.run(c, trace)
      F05.ck("determinism #{seed}", a[:results].map { |x| [x['ok'], x['violated']] }, b[:results].map { |x| [x['ok'], x['violated']] })
      F05.ck("digest #{seed}", F05::P.state_digest(a[:state]), F05::P.state_digest(b[:state]))
    end
    (1..40).each do |seed|
      r = F05.seeded(seed + 10_000)
      c = rand_contract.call(r)
      prev = F05::P.empty_state(F05::NOW)
      digests = { F05::P.state_digest(prev) => true }
      Array.new(8) { rand_action.call(r) }.each do |action|
        res = F05::C.advance_contract(prev, action, c, { 'now' => prev['now'] })
        if res['ok']
          F05.ck('seq', res['next']['seq'], prev['seq'] + 1)
          F05.ck('parent', res['next']['parent'], AtlasPca.hash_canonical({ 'd' => 'atlas-pca/monitor-state-link/v1', 'state' => F05::P.state_digest(prev), 'action' => AtlasPca.hash_canonical(action) }))
          d = F05::P.state_digest(res['next'])
          raise 'digest reused' if digests.key?(d)

          digests[d] = true
          prev = res['next']
        else
          F05.ck('refusal does not advance', res['next'], prev)
        end
      end
    end
    (1..60).each do |seed|
      r = F05.seeded(seed + 20_000)
      v = pick.call(r, verbs)
      c = F05.contract([{ 'id' => 'n', 'kind' => 'never', 'p' => { 'verb' => v } }])
      trace = Array.new(7) { rand_action.call(r) }
      F05.ck("never oracle #{seed}", F05.run(c, trace)[:rejected], trace.any? { |a| a['action']['verb'] == v })
    end
    oracle = lambda do |trace, vp, vq, n|
      trace.each_with_index.any? do |a, i|
        next false if a['action']['verb'] != vp || i + n > trace.length - 1

        (i + 1..i + n).none? { |j| trace[j]['action']['verb'] == vq }
      end
    end
    (1..80).each do |seed|
      r = F05.seeded(seed + 30_000)
      n = 1 + (r.call * 3).floor
      c = F05.contract([{ 'id' => 'ack', 'kind' => 'responds_within', 'p' => { 'verb' => 'request' }, 'q' => { 'verb' => 'ack' }, 'within' => n }])
      alpha = %w[request ack noise noise]
      trace = Array.new(2 + (r.call * 7).floor) { F05.act(pick.call(r, alpha)) }
      F05.ck("liveness oracle #{seed}", F05.run(c, trace)[:rejected], oracle.call(trace, 'request', 'ack', n))
    end
    true
  end

  # ---- the durable enforcer -----------------------------------------------------------------------------------------

  t('f05 enforcer: open pins the principal; check, latch, reset, peek, fail closed') do
    next true unless F05.gate?('contracts.rb')

    cl = [{ 'id' => 'no-delete', 'kind' => 'never', 'p' => { 'verb' => 'delete' } }, { 'id' => 'review-first', 'kind' => 'precedes', 'p' => { 'verb' => 'review' }, 'q' => { 'verb' => 'deploy' } }]
    sc = F05::C.sign_contract({ 'version' => 1, 'principal' => F05.key.public, 'clauses' => cl }, F05.key)
    kvs = -> { AtlasPca::MemoryAtomicKv.new }
    open = ->(kv, **extra) { F05::C::ContractEnforcer.open(kv, sc, principal: F05.key.public, now: -> { 1_700_000_000_000 }, **extra) }
    raises = lambda do |msg, &blk|
      blk.call
      raise "no error: #{msg}"
    rescue F05::C::ContractEnforcerError => e
      raise "wrong message #{e.message}" unless e.message == "ContractEnforcer: #{msg}"
    end
    raises.call('contract refused: principal mismatch') { F05::C::ContractEnforcer.open(kvs.call, sc, principal: AtlasPca::KeyPair.generate.public) }
    raises.call('contract refused: id does not match content') { F05::C::ContractEnforcer.open(kvs.call, sc.merge('clauses' => []), principal: F05.key.public) }
    raises.call('a pinned principal is required') { F05::C::ContractEnforcer.open(kvs.call, sc, principal: '') }
    raises.call('a pinned principal is required') { F05::C::ContractEnforcer.open(kvs.call, sc, principal: nil) }

    e = open.call(kvs.call)
    F05.ck('admit', e.check(F05.act('review')), { 'allow' => true, 'reason' => 'ok', 'violated' => [], 'reasons' => [], 'seq' => 1 })
    F05.ck('second', e.check(F05.act('deploy')).values_at('allow', 'seq'), [true, 2])
    e = open.call(kvs.call)
    r = e.check(F05.act('review'), false)
    F05.ck('permission', r.values_at('allow', 'reason', 'violated', 'seq'), [false, 'permission', [], 0])
    F05.ck('no latch after permission denial', e.check(F05.act('review')).values_at('allow', 'seq'), [true, 1])
    e = open.call(kvs.call)
    r = e.check(F05.act('deploy'))
    F05.ck('violation', r.values_at('allow', 'reason', 'violated'), [false, 'violated', ['review-first']])
    r = e.check(F05.act('review'))
    F05.ck('latched', [r['allow'], r['reason'], r['violated'], r['reasons']], [false, 'latched', ['review-first'], ['<latched>: contract violated at seq 0']])
    F05.ck('state latched', e.state['latched'], true)
    e = open.call(kvs.call, latch_on_violation: false)
    F05.ck('violation only denied', e.check(F05.act('delete'))['reason'], 'violated')
    F05.ck('next admitted', e.check(F05.act('review'))['allow'], true)

    kv = kvs.call
    e = open.call(kv)
    e.check(F05.act('review'))
    e.check(F05.act('delete'))
    F05.ck('reset by another key', e.reset(F05::C.sign_contract_reset(AtlasPca::KeyPair.generate, sc['id'], 1)), false)
    F05.ck('reset at the wrong seq', e.reset(F05::C.sign_contract_reset(F05.key, sc['id'], 0)), false)
    F05.ck('still latched', e.check(F05.act('review'))['reason'], 'latched')
    F05.ck('reset non-string', e.reset(5), false)
    F05.ck('reset', e.reset(F05::C.sign_contract_reset(F05.key, sc['id'], 1)), true)
    F05.ck('reset twice', e.reset(F05::C.sign_contract_reset(F05.key, sc['id'], 1)), false)
    F05.ck('admitted after reset', e.check(F05.act('deploy'))['allow'], true)
    F05.ck('reset message domain', F05::C.reset_message('i', 3), "atlas-pca/contract-reset/v1\0".b + AtlasPca.sha('i:3'))

    kv = kvs.call
    e = open.call(kv)
    e.check(F05.act('review'))
    kv.set("contract/#{sc['id']}", { 'v' => 1, 'contract_id' => sc['id'], 'state' => { 'now' => 'x' } })
    r = e.check(F05.act('review'))
    F05.ck('corrupt doc', r.values_at('allow', 'reason', 'seq', 'reasons'), [false, 'state-error', 0, ['<state>: stored state is corrupt or belongs to another contract']])
    raises.call('stored state is corrupt or belongs to another contract') { e.state }
    F05.ck('corrupt doc peek', e.peek(F05.act('review'))['reason'], 'state-error')
    kv = kvs.call
    e = open.call(kv)
    e.check(F05.act('review'))
    e.check(F05.act('delete'))
    doc = kv.get("contract/#{sc['id']}")
    kv.set("contract/#{sc['id']}", doc.merge('latched' => doc['latched'].merge('seq' => 0)))
    F05.ck('latched seq 0 fine', e.state['latched'], true)
    kv.set("contract/#{sc['id']}", doc.merge('latched' => doc['latched'].merge('seq' => -0.0)))
    raises.call('stored state is corrupt or belongs to another contract') { e.state }
    kv.set("contract/#{sc['id']}", doc.merge('latched' => doc['latched'].merge('violated' => [1])))
    raises.call('stored state is corrupt or belongs to another contract') { e.state }
    kv.set("contract/#{sc['id']}", doc.merge('latched' => 'x'))
    raises.call('stored state is corrupt or belongs to another contract') { e.state }
    kv = kvs.call
    e = open.call(kv)
    e.check(F05.act('review'))
    kv.set("contract/#{sc['id']}", kv.get("contract/#{sc['id']}").merge('contract_id' => 'other'))
    F05.ck('another contract state', e.check(F05.act('review'))['reason'], 'state-error')
    F05.ck('foreign version', F05::C.enforcer_doc?(kv.get("contract/#{sc['id']}").merge('contract_id' => sc['id'], 'v' => 2), sc['id']), false)
    down = Object.new
    def down.update(_k) = raise('down')
    def down.get(_k) = raise('down')
    F05.ck('store error check', open.call(down).check(F05.act('review')).values_at('allow', 'reason'), [false, 'store-error'])
    F05.ck('store error peek', open.call(down).peek(F05.act('review')).values_at('allow', 'reason'), [false, 'store-error'])
    F05.ck('store error reset', open.call(down).reset('x'), false)
    nan = F05::C::ContractEnforcer.open(kvs.call, sc, principal: F05.key.public, now: -> { Float::NAN })
    F05.ck('a non-finite clock refuses the advance (state-error)', nan.check(F05.act('review')).values_at('allow', 'reason'), [false, 'state-error'])
    nan_wall = [1_700_000_000_000, Float::NAN]
    clock = -> { nan_wall.shift || Float::NAN }
    e2 = F05::C::ContractEnforcer.open(kvs.call, sc, principal: F05.key.public, now: clock)
    F05.ck('admit with a finite clock', e2.check(F05.act('review'))['allow'], true)
    F05.ck('then the clock is not finite', e2.check(F05.act('review')).values_at('allow', 'reason', 'reasons', 'seq'), [false, 'state-error', ['<state>: clock is not finite'], 1])

    e = open.call(kvs.call)
    r = e.peek(F05.act('delete'))
    F05.ck('peek violation', r.values_at('allow', 'reason', 'violated'), [false, 'violated', ['no-delete']])
    F05.ck('peek advanced nothing', e.state, nil)
    F05.ck('peek ok', e.peek(F05.act('review')), { 'allow' => true, 'reason' => 'ok', 'violated' => [], 'reasons' => [], 'seq' => 0 })
    F05.ck('still nothing', e.state, nil)
    e.check(F05.act('delete'))
    F05.ck('peek latched', e.peek(F05.act('review')).values_at('allow', 'reason'), [false, 'latched'])
    e = open.call(kvs.call)
    e.check(F05.act('review'))
    F05.ck('peek reports the stored seq', e.peek(F05.act('deploy'))['seq'], 1)
    F05.ck('state doc', e.state.keys.sort, %w[latched state])
    true
  end

  t('f05 enforcer: concurrent enforcers on one kv admit each sequence exactly once') do
    next true unless F05.gate?('contracts.rb')

    cl = [{ 'id' => 'no-delete', 'kind' => 'never', 'p' => { 'verb' => 'delete' } }]
    sc = F05::C.sign_contract({ 'version' => 1, 'principal' => F05.key.public, 'clauses' => cl }, F05.key)
    kv = AtlasPca::MemoryAtomicKv.new
    es = Array.new(2) { F05::C::ContractEnforcer.open(kv, sc, principal: F05.key.public, now: -> { 1_700_000_000_000 }) }
    rs = Array.new(4) { |i| Thread.new { es[i % 2].check(F05.act('review')) } }.map(&:value)
    F05.ck('all admitted', rs.all? { |r| r['allow'] }, true)
    F05.ck('distinct seqs', rs.map { |r| r['seq'] }.sort, [1, 2, 3, 4])
    true
  end

  # ---- explicit-key semantics: a present key with a nil value is a specified pin / head guard ------------------------

  t('f05 pins: an omitted principal pin passes, an explicit nil pin never matches') do
    next true unless F05.gate?('contracts.rb')

    sc = F05::C.sign_contract(F05.contract([{ 'id' => 'no-del', 'kind' => 'never', 'p' => { 'verb' => 'delete' } }]), F05.key)
    F05.ck('omitted', F05::C.verify_contract(sc), { 'ok' => true })
    F05.ck('explicit nil', F05::C.verify_contract(sc, nil), { 'ok' => false, 'reason' => 'principal mismatch' })
    F05.ck('right key', F05::C.verify_contract(sc, F05.key.public), { 'ok' => true })
    F05.ck('wrong key', F05::C.verify_contract(sc, AtlasPca::KeyPair.generate.public), { 'ok' => false, 'reason' => 'principal mismatch' })
    true
  end

  t('f05 advance: the head guards fire on a present key even when its value is nil') do
    next true unless F05.gate?('contracts.rb')

    c = F05.contract([{ 'id' => 'no-del', 'kind' => 'never', 'p' => { 'verb' => 'delete' } }])
    s0 = F05::P.empty_state(F05::NOW)
    fresh = -> { Marshal.load(Marshal.dump(s0)) }
    [
      ->(o) { F05::C.advance_contract(fresh.call, F05.act('read'), c, o) },
      ->(o) { F05::C.check_and_advance_contract(true, fresh.call, F05.act('read'), c, o) }
    ].each_with_index do |run, i|
      r = run.call({ 'expectedSeq' => nil })
      F05.ck("seq nil #{i}", [r['ok'], r['decidedBy'], r['reasons'].last], [false, 'state', '<state>: stale state head (seq)'])
      r = run.call({ 'expectedStateDigest' => nil })
      F05.ck("digest nil #{i}", [r['ok'], r['decidedBy'], r['reasons'].last], [false, 'state', '<state>: stale state head (digest)'])
      r = run.call({ 'expectedSeq' => 1 })
      F05.ck("seq wrong #{i}", [r['ok'], r['reasons'].last], [false, '<state>: stale state head (seq)'])
      r = run.call({ 'expectedStateDigest' => 'x' })
      F05.ck("digest wrong #{i}", [r['ok'], r['reasons'].last], [false, '<state>: stale state head (digest)'])
      F05.ck("no opts #{i}", run.call({})['ok'], true)
      F05.ck("seq matches #{i}", run.call({ 'expectedSeq' => 0 })['ok'], true)
      F05.ck("digest matches #{i}", run.call({ 'expectedStateDigest' => F05::P.state_digest(s0) })['ok'], true)
    end
    true
  end
end
