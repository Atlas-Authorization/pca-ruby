# frozen_string_literal: true

# za_a2: kill tests for AtlasPca.authorize (authorize.rb): the forbid clause gate, the durable contracts, requireLinkedTemplate,
# resolvePrincipal and requirePassport. Reference: packages/pca/src/server/{authorize,require-pca}.ts. Reuses the C06 helpers and
# ZaA (za_a1). AtlasPca is resolved at call time.

module MutationKill
  op_of = -> { C06.base['steps'][0]['operation'] }
  act_of = -> { o = op_of.call; { 'verb' => o['verb'], 'resource' => o['resource'], 'params' => o['params'] } }

  t('za authorize forbid: the clause context, the options and the certificate requirement') do
    next true unless ZaA.gate?

    act = act_of.call
    clauses = ->(_o, _g) { ['C1'] }
    run = lambda do |forbid, **kw|
      cap = []
      stubs = { decide_clauses: ->(cl, ctx, co) { cap << [cl, ctx, co]; { 'decision' => 'allow' } }, certify_clauses: ->(*) { { 'cert' => 1 } } }
      r = Seam.with(AtlasPca, stubs) { ZaA.go(forbid: forbid, **kw) }
      [r, cap]
    end
    seen = []
    full, cap = run.call({ clauses: clauses, context: ->(o) { seen << o; { tenant: 'x' } }, precedence: ['a'], permit_signers: ['u'] })
    ZaA.ck('symbol keys, extra context, precedence and permit_signers',
           [full.allow, full.checks['forbid'], full.forbid, cap, seen],
           [true, 'pass', { 'cert' => 1 }, [[['C1'], { 'action' => act, 'tenant' => 'x' }, { 'precedence' => ['a'], 'permitSigners' => ['u'] }]], [act]]) &&
      ZaA.ck('no options', run.call({ 'clauses' => clauses })[1], [[['C1'], { 'action' => act }, {}]]) &&
      ZaA.ck('a context that is not callable is ignored', run.call({ 'clauses' => clauses, 'context' => { 'x' => 1 } }).then { |r, c| [r.checks['forbid'], c] },
             ['pass', [[['C1'], { 'action' => act }, {}]]]) &&
      ZaA.ck('a context answer that is not a Hash is ignored', run.call({ 'clauses' => clauses, 'context' => ->(_o) { 5 } })[1], [[['C1'], { 'action' => act }, {}]]) &&
      ZaA.ck('the context may replace the action', run.call({ 'clauses' => clauses, 'context' => ->(_o) { { 'action' => 'over' } } })[1][0][1], { 'action' => 'over' }) &&
      ZaA.ck('permitSigners wins over permit_signers', run.call({ 'clauses' => clauses, 'permitSigners' => ['p'], 'permit_signers' => ['z'] })[1][0][2], { 'permitSigners' => ['p'] }) &&
      ZaA.ck('a nil permitSigners is the spelling in use', run.call({ 'clauses' => clauses, 'permitSigners' => nil, 'permit_signers' => ['z'] })[1][0][2], {}) &&
      ZaA.ck('permit_signers alone', run.call({ 'clauses' => clauses, 'permit_signers' => ['z'] })[1][0][2], { 'permitSigners' => ['z'] }) &&
      ZaA.ck('a nil precedence is none', run.call({ 'clauses' => clauses, 'precedence' => nil })[1][0][2], {})
  end

  t('za authorize forbid: require_certificate in both spellings, and the certificate refusal text') do
    next true unless ZaA.gate?

    clauses = ->(_o, _g) { [] }
    run = lambda do |forbid, cert, chk|
      stubs = { decide_clauses: ->(*) { { 'decision' => 'allow' } }, certify_clauses: ->(*) { { 'cert' => 1 } }, check_forbid_certificate: ->(*) { chk } }
      r = Seam.with(AtlasPca, stubs) { ZaA.go(forbid: forbid, forbid_certificate: cert) }
      [r.allow, r.checks['forbid'], ZaA.why(r, 'forbid')]
    end
    none = [false, 'fail', ['the call carries no certificate (fail closed)']]
    ok = [true, 'pass', []]
    ZaA.ck('camel spelling', run.call({ 'clauses' => clauses, 'requireCertificate' => true }, nil, { 'ok' => true }), none) &&
      ZaA.ck('snake spelling', run.call({ 'clauses' => clauses, 'require_certificate' => true }, nil, { 'ok' => true }), none) &&
      ZaA.ck('a refusal with no reason', run.call({ 'clauses' => clauses, 'requireCertificate' => true }, 'c', { 'ok' => false }), [false, 'fail', ['certificate refused (mismatch)']]) &&
      ZaA.ck('a refusal with a reason', run.call({ 'clauses' => clauses, 'requireCertificate' => true }, 'c', { 'ok' => false, 'reason' => 'r1' }), [false, 'fail', ['certificate refused (r1)']]) &&
      ZaA.ck('an accepted certificate', run.call({ 'clauses' => clauses, 'require_certificate' => true }, 'c', { 'ok' => true }), ok) &&
      ZaA.ck('false is not a requirement', run.call({ 'clauses' => clauses, 'requireCertificate' => false, 'require_certificate' => false }, nil, { 'ok' => true }), ok) &&
      ZaA.ck('a truthy non-true is not a requirement', [run.call({ 'clauses' => clauses, 'requireCertificate' => 1 }, nil, { 'ok' => true }),
                                                       run.call({ 'clauses' => clauses, 'require_certificate' => 'yes' }, nil, { 'ok' => true })], [ok, ok])
  end

  t('za authorize contracts: the peeked and committed action, and the violation text') do
    next true unless ZaA.gate?

    act = act_of.call
    fake = lambda do |peek, check|
      Class.new do
        attr_reader :peeked, :checked

        define_method(:initialize) { @peeked = []; @checked = [] }
        define_method(:peek) { |a| @peeked << a; peek }
        define_method(:check) { |a, commit = false| @checked << [a, commit]; check }
      end.new
    end
    deny = ->(violated) { { 'allow' => false, 'reason' => 'R', 'violated' => violated } }
    yes = { 'allow' => true, 'reason' => nil, 'violated' => [] }
    out = ->(r) { [r.allow, r.checks['contract'], ZaA.why(r, 'contract')] }
    a = fake.call(deny.call(%w[a b]), yes)
    b = fake.call(deny.call([]), yes)
    c = fake.call(yes, deny.call(%w[x y]))
    d = fake.call(yes, deny.call([]))
    e = fake.call(yes, yes)
    ZaA.ck('peek refusal with violations', [out.call(ZaA.go(contracts: a)), a.peeked, a.checked], [[false, 'fail', ['R (a,b)']], [{ 'action' => act }], []]) &&
      ZaA.ck('peek refusal without violations', out.call(ZaA.go(contracts: b)), [false, 'fail', ['R']]) &&
      ZaA.ck('commit refusal with violations', [out.call(ZaA.go(contracts: c)), c.peeked, c.checked], [[false, 'fail', ['R (x,y)']], [{ 'action' => act }], [[{ 'action' => act }, true]]]) &&
      ZaA.ck('commit refusal without violations', out.call(ZaA.go(contracts: d)), [false, 'fail', ['R']]) &&
      ZaA.ck('admitted', [out.call(ZaA.go(contracts: e)), e.checked], [[true, 'pass', []], [[{ 'action' => act }, true]]])
  end

  t('za authorize require_linked_template: the registry source, the envelope reads and the verifier answer') do
    next true unless ZaA.gate?

    g = C06.base['grant']
    env = g['caveats'].find { |c| c['type'] == 'envelope' }
    gt = g.merge('caveats' => [env.merge('template_ref' => 'tpl-1')])
    reg = { 'templates' => {}, 'trusted' => [] }
    run = lambda do |grant, opt, ret = { 'ok' => true }|
      cap = []
      r = Seam.with(AtlasPca, { verify_linked_policy: ->(e, rg) { cap << [e, rg]; ret } }) { ZaA.go(grant: grant, require_linked_template: opt) }
      [[r.checks['template'], ZaA.why(r, 'template')], cap]
    end
    pass = ['pass', []]
    noreg = ['fail', ['no template registry (fail closed)']]
    ZaA.ck('no template_ref', run.call(g, { 'registry' => reg }), [['fail', ['the grant carries no template_ref']], []]) &&
      ZaA.ck('no readable envelope', run.call(g.merge('caveats' => []), { 'registry' => reg }), [['fail', ['the grant has no readable envelope']], []]) &&
      begin
        res, cap = run.call(gt, { 'registry' => reg })
        ZaA.ck('a Hash registry', [res, cap.length, cap[0][1].equal?(reg), cap[0][0]['template_ref'], cap[0][0].key?('type')], [pass, 1, true, 'tpl-1', false])
      end &&
      begin
        res, cap = run.call(gt, { registry: reg })
        ZaA.ck('symbol keys', [res, cap.length, cap[0][1].equal?(reg)], [pass, 1, true])
      end &&
      begin
        res, cap = run.call(gt, { 'registry' => -> { reg } })
        ZaA.ck('a callable registry', [res, cap.length, cap[0][1].equal?(reg)], [pass, 1, true])
      end &&
      ZaA.ck('a raising registry source', run.call(gt, { 'registry' => -> { raise 'down' } }), [noreg, []]) &&
      ZaA.ck('an option that is not a Hash', [run.call(gt, true), run.call(gt, 5)], [[noreg, []]] * 2) &&
      ZaA.ck('a registry that is not a Hash', [run.call(gt, { 'registry' => 5 }), run.call(gt, {})], [[noreg, []]] * 2) &&
      ZaA.ck('a refusal with no reason', run.call(gt, { 'registry' => reg }, { 'ok' => false })[0], ['fail', ['refused']]) &&
      ZaA.ck('a refusal with a reason', run.call(gt, { 'registry' => reg }, { 'ok' => false, 'reason' => 'why' })[0], ['fail', ['why']])
  end

  t('za authorize resolve_principal: an answer that is not a Hash is unverified') do
    next true unless ZaA.gate?

    pr = lambda do |ret, req|
      r = ZaA.go(resolve_principal: ->(*) { ret }, require_verified_principal: req)
      [r.checks['principal'], ZaA.why(r, 'principal'), r.checks.key?('authorize')]
    end
    refused = ['fail', ['the grant issuer is not an enrolled, verified principal'], false]
    ZaA.ck('not enforced', [true, 'x', [], 5].map { |v| pr.call(v, false) }, [['not-enforced', [], false]] * 4) &&
      ZaA.ck('refused when required', [true, 'x', [], 5].map { |v| pr.call(v, true) }, [refused] * 4) &&
      ZaA.ck('string keys', pr.call({ 'verified' => true }, true), ['pass', [], false]) &&
      ZaA.ck('symbol keys', pr.call({ verified: true }, true), ['pass', [], false]) &&
      ZaA.ck('"true" is not verified', pr.call({ 'verified' => 'true' }, false), ['not-enforced', [], false])
  end

  t('za authorize require_passport: the leaf subject, the verifier arguments, the answer and the hardware rule') do
    next true unless ZaA.gate?

    leaf = ZaA.holder
    pp = { 'passport' => {} }
    run = lambda do |rp, ret: nil, pc: :base, passport: pp|
      cap = []
      r = Seam.with(AtlasPca, { verify_passport: ->(sp, ti, now, **k) { cap << [sp, ti, now, k]; ret } }) { ZaA.go(pc, require_passport: rp, passport: passport) }
      [[r.checks['passport'], ZaA.why(r, 'passport')], cap]
    end
    rv = ->(*) { false }
    at = ->(*) { true }
    dv = ->(*) { nil }
    kw = { clock_skew_ms: 5, max_evidence_age_ms: 6, subject: leaf, revoked: rv, pq_pins: { 'a' => 'b' }, attest: at, default_verifier: dv }
    sym = { trusted_issuers: ['i'], clock_skew_ms: 5, max_evidence_age_ms: 6, revoked: rv, pq_pins: { 'a' => 'b' }, attest: at, default_verifier: dv }
    str = sym.transform_keys(&:to_s)
    bare = { clock_skew_ms: nil, max_evidence_age_ms: nil, subject: leaf, revoked: nil, pq_pins: nil, attest: nil, default_verifier: nil }
    ZaA.ck('symbol keys', run.call(sym), [['pass', []], [[pp, ['i'], C06::NOW, kw]]]) &&
      ZaA.ck('string keys', run.call(str), [['pass', []], [[pp, ['i'], C06::NOW, kw]]]) &&
      ZaA.ck('an option that is not a Hash', run.call(true), [['pass', []], [[pp, nil, C06::NOW, bare]]]) &&
      ZaA.ck('a verifier refusal', run.call(str, ret: 'revoked')[0], ['fail', ['revoked']]) &&
      ZaA.ck('no leaf holder', [
        C06.fixture_pcactn.merge('cap_chain' => 'x'), C06.fixture_pcactn.merge('cap_chain' => []), C06.fixture_pcactn.merge('cap_chain' => [5]),
        C06.fixture_pcactn.merge('cap_chain' => [{ 'holder' => 5 }])
      ].map { |pc| run.call(str, pc: pc) }, [[['fail', ['subject_mismatch']], []]] * 4) &&
      begin
        rooted = { 'passport' => { 'hardware_rooted' => true } }
        missing = ['fail', ['hardware_evidence_missing']]
        hw = { 'hardware' => true }
        ZaA.ck('hardware evidence present', run.call(hw, passport: rooted)[0], ['pass', []]) &&
          ZaA.ck('hardware evidence absent or not true', [{ 'passport' => { 'hardware_rooted' => false } }, { 'passport' => { 'hardware_rooted' => 'true' } },
                                                         { 'passport' => { 'hardware_rooted' => 1 } }, { 'passport' => {} }, { 'passport' => [] }, { 'passport' => 'x' }]
                                    .map { |sp| run.call(hw, passport: sp)[0] }, [missing] * 6) &&
          ZaA.ck('hardware not required', [{ 'hardware' => false }, { 'hardware' => 'yes' }, {}].map { |o| run.call(o, passport: pp)[0] }, [['pass', []]] * 3)
      end
  end
end
