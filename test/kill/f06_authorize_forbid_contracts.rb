# frozen_string_literal: true

# f06: the forbid-wins clause policy and the durable behavioural contract are checks of the authorize pipeline (TypeScript
# server/authorize.ts, `forbid` and `contracts`): refused BEFORE the replay counter is spent, committed after the claim.

module MutationKill
  module F06
    module_function

    def gate?(*files) = (f = ENV['MUT_FILE']).nil? || f.empty? || files.include?(f)
    def ck(label, got, want) = got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")

    PAY = { 'verb' => 'payments.send' }.freeze
    KEY = AtlasPca::KeyPair.new("\x09".b * 32)

    def clause(id, kind, w = PAY, signer = nil)
      h = { 'id' => id, 'kind' => kind, 'when' => w }
      h['signer'] = signer unless signer.nil?
      h
    end

    def forbid(clauses, **extra) = { 'clauses' => ->(_op, _grant) { clauses } }.merge(extra.transform_keys(&:to_s))

    def ctx(c = nil)
      op = C06.base['steps'][0]['operation']
      { 'action' => { 'verb' => op['verb'], 'resource' => op['resource'], 'params' => op['params'] } }.merge(c || {})
    end

    def enforcer(clauses, **opts)
      sc = AtlasPca::Contracts.sign_contract({ 'version' => 1, 'principal' => KEY.public, 'clauses' => clauses }, KEY)
      kv = AtlasPca::MemoryAtomicKv.new
      [AtlasPca::Contracts::ContractEnforcer.open(kv, sc, principal: KEY.public, now: -> { C06::NOW }, **opts), sc, kv]
    end
  end

  t('f06 authorize forbid: the clause decision is a check that refuses before the counter is spent') do
    next true unless F06.gate?('authorize.rb')

    off = C06.go
    F06.ck('off', [off.allow, off.checks.key?('forbid'), off.forbid], [true, false, nil])
    permit = F06.clause('p', 'permit')
    ok = C06.go(forbid: F06.forbid([permit]))
    F06.ck('permit allows', [ok.allow, ok.checks['forbid'], ok.forbid['decision'], ok.forbid['winner']], [true, 'pass', 'allow', { 'kind' => 'permit', 'id' => 'p' }])
    F06.ck('the certificate is recomputable', AtlasPca.check_forbid_certificate(ok.forbid, [permit], F06.ctx, {}), { 'ok' => true })
    store = AtlasPca::MemoryStateStore.new
    deny = C06.go(forbid: F06.forbid([permit, F06.clause('f', 'forbid')]), state_store: store)
    F06.ck('forbid refuses', [deny.allow, deny.checks['forbid'], deny.reasons.include?('forbid: deny by forbid f')], [false, 'fail', true])
    F06.ck('a refusal does not spend the counter', C06.go(state_store: store).allow, true)
    F06.ck('default deny names none', C06.go(forbid: F06.forbid([])).reasons.include?('forbid: deny by none'), true)
    esc = C06.go(forbid: F06.forbid([permit, F06.clause('e', 'escalate')]))
    F06.ck('escalate refuses', [esc.allow, esc.reasons.include?('forbid: escalate by escalate e')], [false, true])
    unres = F06.clause('f', 'forbid', { 'verb' => 'payments.send', 'where' => [{ 'field' => 'action.params.nope', 'op' => 'eq', 'value' => 1 }] })
    F06.ck('an unresolvable forbid vetoes', C06.go(forbid: F06.forbid([permit, unres])).reasons.include?('forbid: deny by forbid f'), true)
    F06.ck('malformed clauses deny', C06.go(forbid: F06.forbid('x')).reasons.include?('forbid: deny by malformed'), true)
    ctxt = F06.clause('f', 'forbid', { 'verb' => 'payments.send', 'where' => [{ 'field' => 'env.tenant', 'op' => 'eq', 'value' => 'blocked' }] })
    seen = []
    ctx_hook = ->(op) { seen << op['verb']; { 'env' => { 'tenant' => 'blocked' } } }
    blocked = C06.go(forbid: F06.forbid([permit, ctxt], 'context' => ctx_hook))
    F06.ck('context hook feeds the evaluators', [blocked.allow, seen], [false, ['payments.send']])
    F06.ck('permitSigners', C06.go(forbid: F06.forbid([F06.clause('p', 'permit', F06::PAY, 'org')], 'permitSigners' => ['user'])).reasons.include?('forbid: deny by none'), true)
    F06.ck('permit_signers spelling', C06.go(forbid: F06.forbid([F06.clause('p', 'permit', F06::PAY, 'user')], 'permit_signers' => ['user'])).allow, true)
    F06.ck('precedence', C06.go(forbid: F06.forbid([F06.clause('fb', 'forbid', F06::PAY, 'user'), F06.clause('fa', 'forbid', F06::PAY, 'org')], 'precedence' => %w[org user])).reasons.include?('forbid: deny by forbid fa'), true)
    boom = C06.go(forbid: { 'clauses' => ->(_o, _g) { raise 'down' } })
    F06.ck('a failing clause source denies', [boom.allow, boom.reasons.include?('forbid: the clause source failed (fail closed)')], [false, true])
    cfg = C06.go(forbid: { 'clauses' => 'x' })
    F06.ck('forbid.clauses is required', [cfg.allow, cfg.status, cfg.missing], [false, 403, ['forbid.clauses']])
    F06.ck('forbid must be a hash', C06.go(forbid: 5).missing, ['forbid.clauses'])
    true
  end

  t('f06 authorize forbid: require_certificate recomputes the certificate, never trusts it') do
    next true unless F06.gate?('authorize.rb')

    permit = F06.clause('p', 'permit')
    cert = AtlasPca.certify_clauses([permit], F06.ctx, {})
    need = F06.forbid([permit], 'requireCertificate' => true)
    none = C06.go(forbid: need)
    F06.ck('no certificate', [none.allow, none.reasons.include?('forbid: the call carries no certificate (fail closed)')], [false, true])
    F06.ck('a matching certificate', C06.go(forbid: need, forbid_certificate: cert).allow, true)
    F06.ck('snake spelling', C06.go(forbid: F06.forbid([permit], 'require_certificate' => true), forbid_certificate: cert).allow, true)
    other = AtlasPca.certify_clauses([permit], { 'action' => { 'verb' => 'x', 'resource' => 'y' } }, {})
    bad = C06.go(forbid: need, forbid_certificate: other)
    F06.ck('a certificate for another action', [bad.allow, bad.reasons.include?('forbid: certificate refused (certificate does not match the recomputed decision)')], [false, true])
    junk = C06.go(forbid: need, forbid_certificate: 5)
    F06.ck('junk', junk.reasons.include?('forbid: certificate refused (certificate table does not entail its decision)'), true)
    F06.ck('certificate ignored without the requirement', C06.go(forbid: F06.forbid([permit]), forbid_certificate: other).allow, true)
    true
  end

  t('f06 authorize contracts: peek before the counter, commit after the claim, latch on a violation') do
    next true unless F06.gate?('authorize.rb')

    clauses = [{ 'id' => 'no-pay', 'kind' => 'never', 'p' => { 'verb' => 'payments.send', 'resource' => 'forbidden/*' } }]
    e, = F06.enforcer(clauses)
    ok = C06.go(contracts: e)
    F06.ck('admitted', [ok.allow, ok.checks['contract']], [true, 'pass'])
    F06.ck('committed after the claim', e.state['state']['seq'], 1)
    F06.ck('off', C06.go.checks.key?('contract'), false)

    e2, = F06.enforcer([{ 'id' => 'no-pay', 'kind' => 'never', 'p' => { 'verb' => 'payments.send' } }])
    store = AtlasPca::MemoryStateStore.new
    r = C06.go(contracts: e2, state_store: store)
    F06.ck('violation refused', [r.allow, r.checks['contract'], r.reasons.include?('contract: violated (no-pay)')], [false, 'fail', true])
    F06.ck('peek advanced nothing', e2.state, nil)
    F06.ck('and spent no counter', C06.go(state_store: store).allow, true)

    e3, = F06.enforcer([{ 'id' => 'no-pay', 'kind' => 'never', 'p' => { 'verb' => 'payments.send' } }])
    e3.check({ 'action' => { 'verb' => 'payments.send', 'resource' => 'r' } })
    latched = C06.go(contracts: e3)
    F06.ck('latched', [latched.allow, latched.reasons.include?('contract: latched (no-pay)')], [false, true])

    # a violation that only the commit sees (the peek passed, then the state was latched under it): refused after the claim
    e4, = F06.enforcer(clauses)
    race = Object.new
    race.define_singleton_method(:peek) { |a| e4.peek(a) }
    race.define_singleton_method(:check) { |_a, _p = true| { 'allow' => false, 'reason' => 'latched', 'violated' => ['x'], 'reasons' => [], 'seq' => 0 } }
    late = C06.go(contracts: race)
    F06.ck('a refused commit denies', [late.allow, late.reasons.include?('contract: latched (x)')], [false, true])

    cfg = C06.go(contracts: Object.new)
    F06.ck('contracts must be an enforcer', [cfg.allow, cfg.missing], [false, ['contracts (must respond to #peek and #check)']])
    true
  end
end
