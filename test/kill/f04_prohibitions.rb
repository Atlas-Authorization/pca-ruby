# frozen_string_literal: true

# f04: negative authority (the veto-polarity prohibitions engine) and the forbid-wins clause certificate. Replays the shared
# vectors (packages/pca/conformance/prohibition-vectors.json) and translates the reference's own test cases
# (prohibitions.test.ts, forbid-certificate.test.ts). AtlasPca is resolved at call time.

module MutationKill
  module F04
    module_function

    P = AtlasPca::Prohibitions
    CONF = File.expand_path('../../conformance', __dir__)
    NOW = 1_700_000_000_000
    DAY = 86_400

    def vec = (@vec ||= AtlasPca.parse_json(File.read(File.join(CONF, 'prohibition-vectors.json'), encoding: 'UTF-8'), loose: true))
    def gate?(*files) = (f = ENV['MUT_FILE']).nil? || f.empty? || files.include?(f)
    def ck(label, got, want) = got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")

    def act(verb, resource, params = nil, env = nil)
      a = { 'verb' => verb, 'resource' => resource }
      a['params'] = params if params
      c = { 'action' => a }
      c['env'] = env if env
      c
    end

    def key = (@key ||= AtlasPca::KeyPair.generate)
    def signer = (@signer ||= AtlasPca::KeyPair.generate)

    def constitution(invs) = { 'version' => 1, 'principal' => key.public, 'invariants' => invs }

    SPEND = { 'id' => 'spend-day', 'kind' => 'cap', 'when' => { 'verb' => 'pay', 'resource' => '*' }, 'amount' => 'action.params.usd', 'max' => 100, 'window_secs' => DAY }.freeze
    NO_PROD_DELETE = { 'id' => 'no-prod-delete-without-human', 'kind' => 'never_unless', 'when' => { 'verb' => 'delete', 'resource' => '/prod/*' },
                       'unless' => [{ 'field' => 'env.human_approved', 'op' => 'eq', 'value' => true }] }.freeze
    NO_EXFIL = { 'id' => 'no-pii-exfil', 'kind' => 'never',
                 'when' => { 'verb' => %w[export send], 'resource' => '*', 'where' => [{ 'field' => 'action.params.contains_pii', 'op' => 'eq', 'value' => true }] } }.freeze

    def chk(a, c, s = P.empty_state(NOW)) = P.check_prohibitions(a, c, s)
    def ok?(a, c, s = P.empty_state(NOW)) = chk(a, c, s)['ok']
    def violated(a, c, s = P.empty_state(NOW)) = chk(a, c, s)['violated']
    def adv(a, c, s, now = :unset) = P.advance_state(a, c, s, now)
  end

  # ---- shared vectors -----------------------------------------------------------------------------------------------

  t('f04 vectors: clauses and forbid-certificate rows replay exactly') do
    next true unless F04.gate?('forbid_certificate.rb')

    d = F04.vec
    raise 'rows' unless d['clauses'].length > 4 && d['check'].length > 4
    d['clauses'].each do |v|
      F04.ck("#{v['name']} err", AtlasPca.clauses_error(v['clauses']), v['expect']['error'])
      r = AtlasPca.decide_clauses(v['clauses'], v['action'], v['options'])
      got = { 'decision' => r['decision'], 'winner' => r['witness']['winner'], 'shadowed' => r['witness']['shadowed'], 'values' => r['values'] }
      F04.ck(v['name'], got, v['expect'].slice('decision', 'winner', 'shadowed', 'values'))
      F04.ck("#{v['name']} malformed", r['witness']['winner'], { 'kind' => 'malformed', 'id' => nil }) unless v['expect']['error'].nil?
    end
    d['check'].each do |v|
      F04.ck(v['name'], AtlasPca.check_forbid_certificate(v['certificate'], v['clauses'], v['action'], v['options']), v['expect'])
      F04.ck("#{v['name']} cert", AtlasPca.certify_clauses(v['clauses'], v['action'], v['options']), v['certificate']) if v['expect']['ok']
    end
    true
  end

  t('f04 vectors: constitution rows (validate + check from the given state) replay exactly') do
    next true unless F04.gate?('prohibitions.rb')

    rows = F04.vec['constitution']
    raise 'rows' unless rows.length >= 30
    rows.each do |v|
      F04.ck("#{v['name']} problems", F04::P.validate_constitution(v['constitution']), v['expect']['problems'])
      F04.ck(v['name'], F04::P.check_prohibitions(v['action'], v['constitution'], v['state']), v['expect']['result'])
    end
    true
  end

  t('f04 vectors: monitor step sequences (tick then check_and_advance) replay exactly') do
    next true unless F04.gate?('prohibitions.rb')

    rows = F04.vec['monitor']
    raise 'rows' unless rows.length >= 5
    rows.each do |v|
      st = F04::P.empty_state(v['genesis_now'])
      v['steps'].each_with_index do |step, i|
        cur = st
        unless step['now'].nil?
          tk = F04::P.tick_state(st, step['now'])
          unless tk['ok']
            F04.ck("#{v['name']} #{i}", { 'allow' => false, 'decidedBy' => 'clock', 'reason' => tk['reason'] }, step['expect'])
            next
          end
          cur = tk['state']
        end
        r = F04::P.check_and_advance(true, step['action'], v['constitution'], cur)
        st = r['allow'] ? r['next'] : cur
        F04.ck("#{v['name']} #{i}", { 'allow' => r['allow'], 'decidedBy' => r['decidedBy'], 'violated' => r['prohibition']['violated'], 'seq' => r['next']['seq'] }, step['expect'])
      end
    end
    true
  end

  t('f04 vectors: signed safety evidence rows replay exactly (ok and the reason text)') do
    next true unless F04.gate?('prohibitions.rb')

    rows = F04.vec['evidence']
    raise 'rows' unless rows.length >= 13
    rows.each { |v| F04.ck(v['name'], F04::P.verify_signed_safety_evidence(v['signed'], v['expected']), v['expect']) }
    true
  end

  # ---- veto over permission -----------------------------------------------------------------------------------------

  t('f04 compose: an in-plan permitted action is refused by a prohibition; permission never overrides a veto') do
    next true unless F04.gate?('prohibitions.rb')

    c = F04.constitution([F04::NO_PROD_DELETE, F04::NO_EXFIL])
    a = F04.act('delete', '/prod/db1', {}, { 'human_approved' => false })
    d = F04::P.compose_authority(true, a, c, F04::P.empty_state(F04::NOW))
    F04.ck('veto', [d['allow'], d['decidedBy'], d['prohibition']['violated']], [false, 'prohibition', ['no-prod-delete-without-human']])
    ok = F04.act('delete', '/prod/db1', {}, { 'human_approved' => true })
    F04.ck('approved', F04::P.compose_authority(true, ok, c, F04::P.empty_state(F04::NOW))['allow'], true)
    pii = F04.act('send', '/mail/x', { 'contains_pii' => true })
    F04.ck('monitor runs even when not permitted', F04::P.compose_authority(false, pii, c, F04::P.empty_state(F04::NOW))['prohibition']['violated'], ['no-pii-exfil'])
    benign = F04.act('send', '/mail/x', { 'contains_pii' => false })
    F04.ck('permission denial alone', F04::P.compose_authority(false, benign, c, F04::P.empty_state(F04::NOW))['decidedBy'], 'permission')
    [true, false, 1, 'yes', nil].each do |p|
      F04.ck("permitted #{p.inspect} never overrides", F04::P.compose_authority(p, a, c, F04::P.empty_state(F04::NOW))['allow'], false)
    end
    F04.ck('only literal true grants', F04::P.compose_authority(1, F04.act('delete', '/staging/x'), c, F04::P.empty_state(F04::NOW))['decidedBy'], 'permission')
    F04.ck('permitted flag', F04::P.compose_authority(1, F04.act('delete', '/staging/x'), c, F04::P.empty_state(F04::NOW))['permitted'], false)
    true
  end

  # ---- stateful invariants ------------------------------------------------------------------------------------------

  t('f04 cap: spend accumulates, the window rolls, exactly the maximum is allowed') do
    next true unless F04.gate?('prohibitions.rb')

    c = F04.constitution([F04::SPEND])
    s = F04::P.empty_state(F04::NOW)
    pay = ->(usd) { F04.act('pay', '/vendor/acme', { 'usd' => usd }) }
    [40, 40].each_with_index do |usd, i|
      t0 = F04::NOW + (i * 1000)
      s = s.merge('now' => t0)
      F04.ck("admit #{usd}", F04.ok?(pay.call(usd), c, s), true)
      s = F04.adv(pay.call(usd), c, s, t0)
    end
    s = s.merge('now' => F04::NOW + 3000)
    r = F04.chk(pay.call(30), c, s)
    F04.ck('80 + 30 > 100', [r['ok'], r['violated'], r['reasons']], [false, ['spend-day'], ['spend-day: cap exceeded: 80 + 30 > 100']])
    F04.ck('exactly 100', F04.ok?(pay.call(20), c, s), true)
    F04.ck('rolled', F04.ok?(pay.call(30), c, s.merge('now' => F04::NOW + ((F04::DAY + 10) * 1000))), true)
    [nil, {}, { 'usd' => -5 }, { 'usd' => '5' }].each do |params|
      F04.ck("amount #{params.inspect}", F04.ok?(F04.act('pay', '/v', params), c), false)
    end
    F04.ck('non-matching verb', F04.ok?(F04.act('refund', '/v'), c), true)
    F04.ck('unresolvable reason', F04.chk(F04.act('pay', '/v'), c)['reasons'], ['spend-day: amount unresolvable (fail closed)'])
    true
  end

  t('f04 rate, never_after, require_prior latch behaviour') do
    next true unless F04.gate?('prohibitions.rb')

    c = F04.constitution([
                           { 'id' => 'rate', 'kind' => 'rate', 'when' => { 'verb' => 'send', 'resource' => '*' }, 'max' => 2, 'window_secs' => 60 },
                           { 'id' => 'lockdown', 'kind' => 'never_after', 'after' => { 'verb' => 'read', 'resource' => '/secrets/*' }, 'forbid' => { 'verb' => 'send', 'resource' => '/net/*' } }
                         ])
    s = F04::P.empty_state(F04::NOW)
    send = F04.act('send', '/net/out')
    2.times do
      F04.ck('admit', F04.ok?(send, c, s), true)
      s = F04.adv(send, c, s)
    end
    r = F04.chk(send, c, s)
    F04.ck('rate', [r['violated'], r['reasons']], [['rate'], ['rate: rate exceeded: 3 > 2 per 60s']])
    s = F04.adv(F04.act('read', '/secrets/key'), c, F04::P.empty_state(F04::NOW))
    F04.ck('lockdown', F04.violated(send, c, s), ['lockdown'])
    F04.ck('other read', F04.ok?(F04.act('read', '/pub/x'), c, s), true)

    rp = F04.constitution([{ 'id' => 'review-first', 'kind' => 'require_prior', 'when' => { 'verb' => 'deploy' },
                             'prior' => { 'verb' => 'review', 'where' => [{ 'field' => 'action.params.passed', 'op' => 'eq', 'value' => true }] } }])
    deploy = F04.act('deploy', '/prod')
    s = F04::P.empty_state(F04::NOW)
    F04.ck('forbidden first', F04.violated(deploy, rp, s), ['review-first'])
    s = F04.adv(F04.act('review', '/pr/1', { 'passed' => false }), rp, s)
    F04.ck('failed review', s['latched'], {})
    s = F04.adv(F04.act('review', '/pr/1'), rp, s) # ambiguous prerequisite does not count
    F04.ck('ambiguous review', s['latched'], {})
    F04.ck('still forbidden', F04.ok?(deploy, rp, s), false)
    s = F04.adv(F04.act('review', '/pr/1', { 'passed' => true }), rp, s)
    F04.ck('latched at now', s['latched'], { 'review-first' => F04::NOW })
    F04.ck('allowed after', F04.ok?(deploy, rp, s), true)
    true
  end

  t('f04 advance: pure, chained, strict, prunes, merges, latches the earliest time') do
    next true unless F04.gate?('prohibitions.rb')

    lock = { 'id' => 'lock', 'kind' => 'never_after', 'after' => { 'verb' => 'read', 'resource' => '/s/*' }, 'forbid' => { 'verb' => 'send' } }
    c = F04.constitution([F04::SPEND, lock])
    pay = ->(usd) { F04.act('pay', '/v', { 'usd' => usd }) }
    s0 = F04::P.empty_state(F04::NOW)
    before = Marshal.dump(s0)
    s1 = F04.adv(pay.call(5), c, s0)
    F04.ck('pure', Marshal.dump(s0), before)
    F04.ck('ledger', s1['ledger']['spend-day'], [{ 't' => F04::NOW, 'amount' => 5 }])
    a = F04::P.advance_state_strict(pay.call(5), c, s0)
    F04.ck('deterministic', a, F04::P.advance_state_strict(pay.call(5), c, s0))
    F04.ck('seq', a['state']['seq'], 1)
    link = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/monitor-state-link/v1', 'state' => F04::P.state_digest(s0), 'action' => AtlasPca.hash_canonical(pay.call(5)) })
    F04.ck('parent link', a['state']['parent'], link)
    a2 = F04::P.advance_state_strict(pay.call(6), c, a['state'])
    F04.ck('seq 2', [a2['ok'], a2['state']['seq'], a2['state']['parent'] != a['state']['parent']], [true, 2, true])

    x = F04.adv(pay.call(2), c, F04.adv(pay.call(1), c, s0, F04::NOW + 10), F04::NOW + 20)
    y = F04.adv(pay.call(1), c, F04.adv(pay.call(2), c, s0, F04::NOW + 10), F04::NOW + 20)
    F04.ck('order-independent ledger', F04::P.canonical_state(x)['ledger']['spend-day'].map { |e| e['amount'] }.sort, [1, 2])
    F04.ck('order-dependent chain', x['parent'] == y['parent'], false)

    F04.ck('unresolvable amount', F04::P.advance_state_strict(F04.act('pay', '/v'), c, s0), { 'ok' => false, 'reason' => 'spend-day: amount unresolvable' })
    F04.ck('clock regression', F04::P.advance_state_strict(pay.call(1), c, s0, F04::NOW - 1), { 'ok' => false, 'reason' => 'clock regression' })
    F04.ck('malformed state', F04::P.advance_state_strict(pay.call(1), c, { 'now' => Float::NAN })['ok'], false)
    F04.ck('malformed action', F04::P.advance_state_strict({ 'action' => { 'verb' => 1 } }, c, s0), { 'ok' => false, 'reason' => 'malformed action' })
    F04.ck('malformed constitution', F04::P.advance_state_strict(pay.call(1), F04.constitution([{ 'kind' => 'x' }]), s0)['ok'], false)
    F04.ck('wrapper returns the input', F04.adv(F04.act('pay', '/v'), c, s0).equal?(s0), true)

    e0 = F04.adv(pay.call(50), c, s0)
    e1 = F04.adv(pay.call(1), c, e0, F04::NOW + ((F04::DAY + 1) * 1000))
    F04.ck('prunes expired', e1['ledger']['spend-day'], [{ 't' => F04::NOW + ((F04::DAY + 1) * 1000), 'amount' => 1 }])
    life = F04.constitution([F04::SPEND.merge('max' => 1_000_000_000).tap { |h| h.delete('window_secs') }])
    big = s0.merge('ledger' => { 'spend-day' => Array.new(10_000) { |i| { 't' => F04::NOW - 10_000 + i, 'amount' => 1 } } })
    grown = F04::P.advance_state_strict(pay.call(1), life, big)
    F04.ck('merged length', grown['state']['ledger']['spend-day'].length, 10_000)
    F04.ck('merged sum (never under-counts)', grown['state']['ledger']['spend-day'].sum { |e| e['amount'] }, 10_001)
    l1 = F04.adv(F04.act('read', '/s/k'), c, s0)
    l2 = F04.adv(F04.act('read', '/s/k'), c, l1, F04::NOW + 5)
    F04.ck('earliest latch', l2['latched']['lock'], F04::NOW)
    rc = F04.constitution([{ 'id' => 'r', 'kind' => 'rate', 'when' => { 'verb' => 'x' }, 'max' => 10_000, 'window_secs' => 1_000_000_000 }])
    rs = s0.merge('ledger' => { 'r' => Array.new(10_000) { { 't' => F04::NOW, 'amount' => 1 } } })
    F04.ck('rate overflow', F04::P.advance_state_strict(F04.act('x', '/a'), rc, rs), { 'ok' => false, 'reason' => 'r: rate ledger overflow' })
    true
  end

  # ---- canonical state digest ---------------------------------------------------------------------------------------

  t('f04 state: canonical form, digest sensitivity, problems, tick') do
    next true unless F04.gate?('prohibitions.rb')

    a = { 'now' => F04::NOW, 'seq' => 0, 'parent' => nil, 'ledger' => { 'x' => [{ 't' => 1, 'amount' => 2 }, { 't' => 0, 'amount' => 5 }], 'y' => [] }, 'latched' => { 'b' => 1, 'a' => 2 } }
    b = { 'latched' => { 'a' => 2, 'b' => 1 }, 'ledger' => { 'x' => [{ 'amount' => 5, 't' => 0, 'junk' => 1 }, { 'amount' => 2, 't' => 1 }] }, 'parent' => nil, 'seq' => 0, 'now' => F04::NOW, 'extra' => 'ignored' }
    F04.ck('digest ignores order / unknown / empty', F04::P.state_digest(a), F04::P.state_digest(b))
    F04.ck('sorted entries', F04::P.canonical_state(a)['ledger']['x'], [{ 't' => 0, 'amount' => 5 }, { 't' => 1, 'amount' => 2 }])
    F04.ck('empty array omitted', F04::P.canonical_state(a)['ledger'].keys, ['x'])
    F04.ck('domain', F04::P.canonical_state(a)['d'], 'atlas-pca/monitor-state/v1')
    c = F04.constitution([F04::SPEND])
    s = F04.adv(F04.act('pay', '/v', { 'usd' => 10 }), c, F04::P.empty_state(F04::NOW))
    base = F04::P.state_digest(s)
    [s.merge('now' => s['now'] + 1), s.merge('seq' => s['seq'] + 1), s.merge('parent' => 'other'),
     s.merge('ledger' => { 'spend-day' => [{ 't' => F04::NOW, 'amount' => 9 }] }), s.merge('ledger' => {}), s.merge('latched' => { 'z' => F04::NOW })].each_with_index do |v, i|
      F04.ck("variant #{i}", F04::P.state_digest(v) == base, false)
    end
    ok = F04::P.empty_state(F04::NOW)
    with_dl = ok.merge('deadlines' => { 'k' => 2 })
    F04.ck('deadlines bind the digest', F04::P.state_digest(with_dl) == F04::P.state_digest(ok), false)
    F04.ck('empty deadlines are the plain digest', F04::P.state_digest(ok.merge('deadlines' => {})), F04::P.state_digest(ok))
    [nil, ok.merge('now' => Float::NAN), ok.merge('seq' => -1), ok.merge('seq' => 1.5), ok.merge('parent' => 5), ok.merge('parent' => 'p'), ok.merge('seq' => 2),
     ok.merge('ledger' => { 'a' => 'x' }), ok.merge('ledger' => { 'a' => [{ 't' => 1, 'amount' => -1 }] }), ok.merge('ledger' => { 'a' => [{ 't' => F04::NOW + 1, 'amount' => 1 }] }),
     ok.merge('latched' => { 'a' => F04::NOW + 1 }), ok.merge('latched' => { 'a' => 'x' }), ok.merge('ledger' => { '__proto__' => [] }),
     ok.merge('ledger' => { 'a' => Array.new(10_001) { { 't' => 1, 'amount' => 1 } } }), ok.merge('ledger' => { ('k' * 129) => [] }),
     ok.merge('latched' => { ('k' * 129) => 1 }), ok.merge('ledger' => (0..1024).to_h { |i| ["k#{i}", []] }),
     ok.merge('deadlines' => 'x'), ok.merge('deadlines' => { 'k' => 0 }), ok.merge('deadlines' => { 'k' => 1_000_001 }), ok.merge('deadlines' => { 'k' => 1.5 }),
     ok.merge('deadlines' => { '__proto__' => 1 })].each_with_index do |bad, i|
      raise "state #{i} accepted" if F04::P.state_problem(bad).nil?
      raise "digest #{i} did not raise" unless (begin; F04::P.state_digest(bad); false; rescue TypeError; true; end)
    end
    F04.ck('ok state', F04::P.state_problem(ok), nil)
    F04.ck('deadline at max', F04::P.state_problem(ok.merge('deadlines' => { 'k' => 1_000_000 })), nil)
    F04.ck('deadline at 1', F04::P.state_problem(ok.merge('deadlines' => { 'k' => 1 })), nil)
    tk = F04::P.tick_state(ok, F04::NOW + 5)
    F04.ck('tick', [tk['ok'], tk['state']['now']], [true, F04::NOW + 5])
    F04.ck('tick same instant', F04::P.tick_state(ok, F04::NOW)['ok'], true)
    F04.ck('regression', F04::P.tick_state(ok, F04::NOW - 1), { 'ok' => false, 'reason' => 'clock regression' })
    F04.ck('NaN now', F04::P.tick_state(ok, Float::NAN)['ok'], false)
    F04.ck('malformed state', F04::P.tick_state({ 'now' => Float::NAN }, F04::NOW), { 'ok' => false, 'reason' => 'malformed monitor state' })
    true
  end

  # ---- constitution commitment + validation -------------------------------------------------------------------------

  t('f04 constitution: sign, verify, tamper, principal pin') do
    next true unless F04.gate?('prohibitions.rb')

    sc = F04::P.sign_constitution(F04.constitution([F04::SPEND, F04::NO_EXFIL]), F04.key)
    F04.ck('verifies', F04::P.verify_constitution(sc, F04.key.public), { 'ok' => true })
    F04.ck('verifies without pin', F04::P.verify_constitution(sc)['ok'], true)
    F04.ck('wrong pin', F04::P.verify_constitution(sc, AtlasPca::KeyPair.generate.public), { 'ok' => false, 'reason' => 'principal mismatch' })
    F04.ck('weakened', F04::P.verify_constitution(sc.merge('invariants' => [F04::SPEND.merge('max' => 1_000_000_000), F04::NO_EXFIL])), { 'ok' => false, 'reason' => 'id does not match content' })
    F04.ck('dropped', F04::P.verify_constitution(sc.merge('invariants' => [F04::SPEND]))['ok'], false)
    other = AtlasPca::KeyPair.generate
    forged = F04::P.sign_constitution(F04.constitution([]).merge('principal' => other.public), other)
    F04.ck('re-signed by another principal', F04::P.verify_constitution(forged, F04.key.public)['ok'], false)
    F04.ck('bad signature', F04::P.verify_constitution(sc.merge('sig' => forged['sig'])), { 'ok' => false, 'reason' => 'bad signature' })
    F04.ck('non-string sig', F04::P.verify_constitution(sc.merge('sig' => 5))['reason'], 'bad signature')
    F04.ck('non-string id', F04::P.verify_constitution(sc.merge('id' => 5))['reason'], 'id does not match content')
    F04.ck('malformed first problem', F04::P.verify_constitution({ 'version' => 2 })['reason'], 'unsupported version 2')
    F04.ck('id strips id and sig', F04::P.constitution_id(sc), sc['id'])
    F04.ck('message domain', F04::P.domain_message(F04::P::CONSTITUTION_SIG_DOMAIN, sc['id']), "atlas-pca/constitution/v1\0".b + AtlasPca.sha(sc['id'].b))
    raise 'sign accepted a malformed constitution' unless (begin; F04::P.sign_constitution(F04.constitution([{ 'kind' => 'x' }]), F04.key); false; rescue TypeError; true; end)
    true
  end

  t('f04 validation: malformed invariants deny everything; forms and id hygiene') do
    next true unless F04.gate?('prohibitions.rb')

    inf = Float::INFINITY
    bad = [
      { 'id' => 'u', 'kind' => 'eventually_always', 'when' => { 'verb' => 'x' } }, { 'id' => 'u', 'kind' => 'never', 'when' => { 'verb' => '' } },
      { 'id' => 'u', 'kind' => 'never', 'when' => { 'verb' => 'x', 'where' => [{ 'field' => 'action.verb', 'op' => 'regex', 'value' => '.' }] } },
      { 'id' => 'u', 'kind' => 'never', 'when' => { 'verb' => 'x', 'resource' => 're:(a+)+' } },
      { 'id' => 'u', 'kind' => 'cap', 'when' => { 'verb' => 'x' }, 'amount' => 'env.x', 'max' => 1 },
      { 'id' => 'u', 'kind' => 'cap', 'when' => { 'verb' => 'x' }, 'amount' => 'action.params.u', 'max' => inf },
      { 'id' => 'u', 'kind' => 'cap', 'when' => { 'verb' => 'x' }, 'amount' => 'action.params.u', 'max' => -1 },
      { 'id' => 'u', 'kind' => 'cap', 'when' => { 'verb' => 'x' }, 'amount' => 'action.params.u', 'max' => 1, 'window_secs' => 0 },
      { 'id' => 'u', 'kind' => 'rate', 'when' => { 'verb' => 'x' }, 'max' => 1.5, 'window_secs' => 1 },
      { 'id' => 'u', 'kind' => 'rate', 'when' => { 'verb' => 'x' }, 'max' => 10_001, 'window_secs' => 1 },
      { 'id' => 'u', 'kind' => 'rate', 'when' => { 'verb' => 'x' }, 'max' => -1, 'window_secs' => 1 },
      { 'id' => 'u', 'kind' => 'rate', 'when' => { 'verb' => 'x' }, 'max' => -0.0, 'window_secs' => 1 },
      { 'id' => 'u', 'kind' => 'rate', 'when' => { 'verb' => 'x' }, 'max' => 1, 'window_secs' => 0 },
      { 'id' => 'u', 'kind' => 'never_unless', 'when' => { 'verb' => 'x' }, 'unless' => [] }, { 'kind' => 'never', 'when' => { 'verb' => 'x' } }, nil,
      { 'id' => 'a', 'kind' => 'require_prior', 'when' => { 'verb' => 'x' } }, { 'id' => 'a', 'kind' => 'require_prior', 'when' => { 'verb' => 'x' }, 'prior' => { 'verb' => '' } },
      { 'id' => 'a', 'kind' => 'require_approval_over', 'when' => { 'verb' => 'x' }, 'amount' => 'env.x', 'threshold' => 1, 'approved' => [{ 'field' => 'env.a', 'op' => 'eq', 'value' => 1 }] },
      { 'id' => 'a', 'kind' => 'require_approval_over', 'when' => { 'verb' => 'x' }, 'amount' => 'action.x', 'threshold' => -1, 'approved' => [{ 'field' => 'env.a', 'op' => 'eq', 'value' => 1 }] },
      { 'id' => 'a', 'kind' => 'require_approval_over', 'when' => { 'verb' => 'x' }, 'amount' => 'action.x', 'threshold' => 1, 'approved' => [] },
      { 'id' => 'a', 'kind' => 'require_approval_over', 'when' => { 'verb' => 'x' }, 'amount' => 'action.x', 'threshold' => inf, 'approved' => [{ 'field' => 'env.a', 'op' => 'eq', 'value' => 1 }] },
      { 'id' => '__proto__', 'kind' => 'never', 'when' => { 'verb' => 'x' } }, { 'id' => 'constructor', 'kind' => 'never', 'when' => { 'verb' => 'x' } },
      { 'id' => 'prototype', 'kind' => 'never', 'when' => { 'verb' => 'x' } }, { 'id' => 'x' * 129, 'kind' => 'never', 'when' => { 'verb' => 'x' } },
      { 'id' => 'a', 'kind' => 'never_unless', 'when' => { 'verb' => 'x' }, 'unless' => [{ 'field' => 'env.a', 'op' => 'eq', 'ref' => '' }] },
      { 'id' => 'a', 'kind' => 'never_after', 'after' => { 'verb' => 'x' } }, { 'id' => 'a', 'kind' => 'never' },
      { 'id' => 'a', 'kind' => 'never', 'when' => { 'verb' => 'x', 'resource' => 5 } }, { 'id' => 'a', 'kind' => 'never', 'when' => { 'verb' => ['x', ''] } },
      { 'id' => 'a', 'kind' => 'never', 'when' => { 'verb' => [] } }, { 'id' => 'a', 'kind' => 'never', 'when' => { 'verb' => 'x', 'where' => 'x' } },
      { 'id' => 'a', 'kind' => 'never', 'when' => { 'verb' => 'x', 'resource' => "re:#{'a' * 201}" } }
    ]
    bad.each_with_index do |inv, i|
      c = F04.constitution([inv])
      raise "bad invariant #{i} accepted" if F04::P.validate_constitution(c).empty?

      r = F04.chk(F04.act('anything', '/ok'), c)
      F04.ck("bad #{i} denies", [r['ok'], r['violated']], [false, ['<constitution>']])
      raise "bad #{i} signed" unless (begin; F04::P.sign_constitution(c, F04.key); false; rescue TypeError; true; end)
    end
    ok = ->(h) { F04::P.validate_invariant(h) }
    F04.ck('id at 128', ok.call({ 'id' => 'x' * 128, 'kind' => 'never', 'when' => { 'verb' => 'x' } }), [])
    F04.ck('rate max 10000', ok.call({ 'id' => 'r', 'kind' => 'rate', 'when' => { 'verb' => 'x' }, 'max' => 10_000, 'window_secs' => 1 }), [])
    F04.ck('rate max 0', ok.call({ 'id' => 'r', 'kind' => 'rate', 'when' => { 'verb' => 'x' }, 'max' => 0, 'window_secs' => 1 }), [])
    F04.ck('cap max 0', ok.call({ 'id' => 'c', 'kind' => 'cap', 'when' => { 'verb' => 'x' }, 'amount' => 'action.a', 'max' => 0 }), [])
    F04.ck('regex at 200', ok.call({ 'id' => 'g', 'kind' => 'never', 'when' => { 'verb' => 'x', 'resource' => "re:#{'a' * 200}" } }), [])
    F04.ck('no id', F04::P.validate_invariant({ 'kind' => 'never' }), ['<no id>: missing id'])
    F04.ck('unknown kind text', F04::P.validate_invariant({ 'id' => 'z', 'kind' => 'q' }), ['z: unknown invariant kind q'])
    F04.ck('wrapped message', F04::P.validate_invariant({ 'id' => 'z', 'kind' => 'never', 'when' => { 'verb' => '' } }), ['z: when: bad verb'])

    c = F04.constitution([F04::NO_EXFIL])
    F04.ck('version', F04::P.validate_constitution(c.merge('version' => 2)), ['unsupported version 2'])
    F04.ck('duplicate id', F04::P.validate_constitution(F04.constitution([F04::NO_EXFIL, F04::NO_EXFIL])), ['no-pii-exfil: duplicate id'])
    F04.ck('principal', F04::P.validate_constitution(c.merge('principal' => '')), ['principal missing'])
    F04.ck('invariants not an array', F04::P.validate_constitution(c.merge('invariants' => 5)), ['invariants not an array'])
    F04.ck('not an object', F04::P.validate_constitution(nil), ['constitution not an object'])
    many = F04.constitution(Array.new(257) { |i| { 'id' => "n#{i}", 'kind' => 'never', 'when' => { 'verb' => 'x' } } })
    F04.ck('too many', F04::P.validate_constitution(many), ['too many invariants'])
    F04.ck('256 fine', F04::P.validate_constitution(F04.constitution(Array.new(256) { |i| { 'id' => "n#{i}", 'kind' => 'never', 'when' => { 'verb' => 'x' } } })), [])
    deep = ->(n) { n.zero? ? { 'field' => 'env.a', 'op' => 'eq', 'value' => 1 } : { 'not' => deep.call(n - 1) } }
    F04.ck('depth 32 ok', F04::P.validate_condition(deep.call(32)), nil)
    F04.ck('depth 33 refused', F04::P.validate_condition(deep.call(33)), 'condition nesting too deep')
    F04.ck('empty all_of', F04::P.validate_condition({ 'all_of' => [] }), 'condition.all_of must be a non-empty array')
    F04.ck('empty any_of', F04::P.validate_condition({ 'any_of' => 5 }), 'condition.any_of must be a non-empty array')
    F04.ck('bad op', F04::P.validate_condition({ 'field' => 'a', 'op' => 'explode' }), 'unknown condition op explode')
    F04.ck('bad member_of collection', F04::P.validate_condition({ 'field' => 'a', 'op' => 'member_of', 'collection' => '' }), 'bad condition.collection')
    F04.ck('field missing', F04::P.validate_condition({ 'op' => 'eq' }), 'condition.field missing')
    true
  end

  # ---- conservative matching ----------------------------------------------------------------------------------------

  t('f04 matching: unresolvable trigger conditions MATCH (the veto applies); clean conditions evaluate normally') do
    next true unless F04.gate?('prohibitions.rb')

    ctx = F04.act('export', '/r', { 'n' => 5, 's' => 'abc', 'arr' => [1, 2], 'flag' => true }, { 'tenant' => 'a' })
    m = ->(c, a = ctx) { F04::P.when_matches?({ 'verb' => 'export', 'where' => [c] }, a) }
    [{ 'field' => 'action.params.missing', 'op' => 'eq', 'value' => 1 }, { 'field' => 'action.params.n', 'op' => 'eq' },
     { 'field' => 'action.params.n', 'op' => 'eq', 'ref' => 'action.params.nope' }, { 'field' => 'env.nope', 'op' => 'ne', 'value' => 1 },
     { 'field' => 'subject.x', 'op' => 'eq', 'value' => 1 }, { 'field' => 'bogus.root', 'op' => 'eq', 'value' => 1 },
     { 'field' => 'action.params.n', 'op' => 'in', 'value' => 'notarray' }, { 'field' => 'action.params.n', 'op' => 'nin', 'value' => 5 },
     { 'field' => 'action.params.n', 'op' => 'lt', 'value' => 'str' }, { 'field' => 'action.params.s', 'op' => 'gt', 'value' => 3 },
     { 'field' => 'action.params.flag', 'op' => 'gte', 'value' => true }, { 'field' => 'action.params.n', 'op' => 'prefix', 'value' => 'a' },
     { 'field' => 'action.params.s', 'op' => 'prefix', 'value' => 1 }, { 'field' => 'action.params.n', 'op' => 'explode', 'value' => 1 },
     { 'field' => '', 'op' => 'eq', 'value' => 1 }, { 'op' => 'eq', 'value' => 1 }, nil, 'str'].each_with_index do |c, i|
      raise "case #{i} not matched" unless m.call(c)
      raise "case #{i} not violated" if F04.ok?(ctx, F04.constitution([{ 'id' => 'v', 'kind' => 'never', 'when' => { 'verb' => 'export', 'where' => [c] } }]))
    end
    np = F04.act('export', '/r')
    F04.ck('no params eq', m.call({ 'field' => 'action.params.n', 'op' => 'eq', 'value' => 5 }, np), true)
    F04.ck('no params exists', m.call({ 'field' => 'action.params.n', 'op' => 'exists' }, np), true)
    F04.ck('no params exists false', m.call({ 'field' => 'action.params.n', 'op' => 'exists', 'value' => false }, np), true)
    F04.ck('malformed action', F04::P.when_matches?({ 'verb' => 'export' }, { 'action' => { 'verb' => 1 } }), true)
    F04.ck('empty verb', F04::P.when_matches?({ 'verb' => '' }, ctx), true)
    F04.ck('nil trigger', F04::P.when_matches?(nil, ctx), true)
    F04.ck('unsafe regex', F04::P.when_matches?({ 'verb' => 'export', 'resource' => 're:(a+)+' }, ctx), true)
    F04.ck('uncompilable regex', F04::P.when_matches?({ 'verb' => 'export', 'resource' => 're:(' }, ctx), true)
    F04.ck('where not array', F04::P.when_matches?({ 'verb' => 'export', 'where' => 'x' }, ctx), true)
    F04.ck('oversized subject', F04::P.when_matches?({ 'verb' => 'export', 'resource' => 're:/a/[^/]+' }, F04.act('export', "/a/#{'b' * 600}")), true)
    F04.ck('oversized subject, wrong verb', F04::P.when_matches?({ 'verb' => 'other', 'resource' => 're:/a/[^/]+' }, F04.act('export', "/a/#{'b' * 600}")), false)
    F04.ck('eq hit', m.call({ 'field' => 'action.params.n', 'op' => 'eq', 'value' => 5 }), true)
    F04.ck('eq miss', m.call({ 'field' => 'action.params.n', 'op' => 'eq', 'value' => 6 }), false)
    F04.ck('ne', m.call({ 'field' => 'action.params.n', 'op' => 'ne', 'value' => 6 }), true)
    F04.ck('in', m.call({ 'field' => 'action.params.n', 'op' => 'in', 'value' => [1, 5] }), true)
    F04.ck('nin', m.call({ 'field' => 'action.params.n', 'op' => 'nin', 'value' => [1, 5] }), false)
    F04.ck('lt', m.call({ 'field' => 'action.params.n', 'op' => 'lt', 'value' => 6 }), true)
    F04.ck('gt', m.call({ 'field' => 'action.params.n', 'op' => 'gt', 'value' => 6 }), false)
    F04.ck('prefix', m.call({ 'field' => 'action.params.s', 'op' => 'prefix', 'value' => 'ab' }), true)
    F04.ck('prefix miss', m.call({ 'field' => 'action.params.s', 'op' => 'prefix', 'value' => 'zz' }), false)
    F04.ck('exists', m.call({ 'field' => 'action.params.n', 'op' => 'exists' }), true)
    F04.ck('exists miss', m.call({ 'field' => 'action.params.zz', 'op' => 'exists' }), false)
    F04.ck('exists false', m.call({ 'field' => 'action.params.zz', 'op' => 'exists', 'value' => false }), true)
    F04.ck('ref', m.call({ 'field' => 'action.params.n', 'op' => 'eq', 'ref' => 'action.params.n' }), true)
    F04.ck('verb miss', F04::P.when_matches?({ 'verb' => 'import' }, ctx), false)
    F04.ck('resource miss', F04::P.when_matches?({ 'verb' => 'export', 'resource' => '/zzz' }, ctx), false)
    F04.ck('affirmative: unresolvable is NOT matched', F04::P.when_affirmative?({ 'verb' => 'export', 'where' => [{ 'field' => 'action.params.missing', 'op' => 'eq', 'value' => 1 }] }, ctx), false)
    F04.ck('affirmative: clean match', F04::P.when_affirmative?({ 'verb' => 'export', 'where' => [{ 'field' => 'action.params.n', 'op' => 'eq', 'value' => 5 }] }, ctx), true)
    F04.ck('affirmative: malformed', F04::P.when_affirmative?({ 'verb' => '' }, ctx), false)
    true
  end

  t('f04 never / never_unless / oversized regex subject / redos shapes / ambiguous stateful actions') do
    next true unless F04.gate?('prohibitions.rb')

    c = F04.constitution([F04::NO_EXFIL])
    F04.ck('pii', F04.ok?(F04.act('export', '/r', { 'contains_pii' => true }), c), false)
    F04.ck('no pii', F04.ok?(F04.act('export', '/r', { 'contains_pii' => false }), c), true)
    F04.ck('other verb', F04.ok?(F04.act('read', '/r', { 'contains_pii' => true }), c), true)
    F04.ck('params absent', F04.ok?(F04.act('export', '/r'), c), false)
    F04.ck('field absent', F04.ok?(F04.act('export', '/r', {}), c), false)
    F04.ck('resolvable != true', F04.ok?(F04.act('export', '/r', { 'contains_pii' => 'yes' }), c), true)
    F04.ck('reason', F04.chk(F04.act('export', '/r'), c)['reasons'], ['no-pii-exfil: forbidden action'])
    F04.ck('description reason', F04.chk(F04.act('x', '/r'), F04.constitution([{ 'id' => 'd', 'kind' => 'never', 'when' => { 'verb' => 'x' }, 'description' => 'no way' }]))['reasons'], ['d: no way'])
    u = F04.constitution([F04::NO_PROD_DELETE])
    F04.ck('unless unresolvable', F04.ok?(F04.act('delete', '/prod/x'), u), false)
    F04.ck('unless staging', F04.ok?(F04.act('delete', '/staging/x'), u), true)
    F04.ck('unless reason', F04.chk(F04.act('delete', '/prod/x'), u)['reasons'], ['no-prod-delete-without-human: forbidden without required condition'])
    rx = F04.constitution([{ 'id' => 'r', 'kind' => 'never', 'when' => { 'verb' => 'x', 'resource' => 're:/a/[^/]+' } }])
    F04.ck('oversized subject vetoes', F04.ok?(F04.act('x', "/a/#{'b' * 600}"), rx), false)
    ['re:(a+)+$', 're:(a|aa)+', 're:(.*a){10}', 're:(?=a)', 're:(a)\\1'].each do |re|
      rc = F04.constitution([{ 'id' => 'r', 'kind' => 'never', 'when' => { 'verb' => 'x', 'resource' => re } }])
      raise "#{re} accepted" if F04::P.validate_constitution(rc).empty?
      F04.ck("#{re} vetoes", F04.ok?(F04.act('x', "/#{'a' * 40}!"), rc), false)
    end
    sc = F04.constitution([F04::SPEND])
    F04.ck('nil amount', F04.ok?(F04.act('pay', '/v', { 'usd' => nil }), sc), false)
    rc = F04.constitution([{ 'id' => 'r', 'kind' => 'rate', 'when' => { 'verb' => 'send', 'where' => [{ 'field' => 'action.params.ext', 'op' => 'eq', 'value' => true }] }, 'max' => 1, 'window_secs' => 60 }])
    s = F04.adv(F04.act('send', '/x'), rc, F04::P.empty_state(F04::NOW)) # ambiguous => counted
    F04.ck('ambiguous counted', s['ledger']['r'].length, 1)
    F04.ck('rate violated', F04.violated(F04.act('send', '/x'), rc, s), ['r'])
    F04.ck('clean miss', F04.ok?(F04.act('send', '/x', { 'ext' => false }), rc), true)
    ok = F04::P.empty_state(F04::NOW)
    F04.ck('future entry', F04.violated(F04.act('pay', '/v', { 'usd' => 1 }), sc, ok.merge('ledger' => { 'spend-day' => [{ 't' => F04::NOW + 1, 'amount' => 99 }] })), ['<state>'])
    F04.ck('negative entry', F04.violated(F04.act('pay', '/v', { 'usd' => 1 }), sc, ok.merge('ledger' => { 'spend-day' => [{ 't' => F04::NOW, 'amount' => -50 }] })), ['<state>'])
    F04.ck('malformed action', F04.violated({ 'action' => { 'verb' => 1 } }, c), ['<action>'])
    F04.ck('malformed state', F04.violated(F04.act('a', '/b'), c, { 'now' => Float::NAN }), ['<state>'])
    F04.ck('structural reason', F04.chk(F04.act('a', '/b'), c, { 'now' => Float::NAN })['evaluated'], [{ 'id' => '<state>', 'kind' => 'structural', 'result' => 'violated', 'reason' => 'malformed monitor state' }])
    F04.ck('nothing at all', F04::P.check_prohibitions(nil, nil, nil)['ok'], false)
    F04.ck('duplicate id', F04.violated(F04.act('a', '/b'), F04.constitution([F04::NO_EXFIL, F04::NO_EXFIL])), ['<constitution>'])
    F04.ck('approval over', F04.ok?(F04.act('a', '/b'), F04.constitution([{ 'id' => 'q', 'kind' => 'require_approval_over', 'when' => { 'verb' => 'a' }, 'amount' => 'action.params.usd', 'threshold' => 5, 'approved' => [{ 'field' => 'env.ok', 'op' => 'eq', 'value' => true }] }])), false)
    true
  end

  t('f04 require_approval_over: threshold, approval, unresolvable amount') do
    next true unless F04.gate?('prohibitions.rb')

    inv = { 'id' => 'big-pay', 'kind' => 'require_approval_over', 'when' => { 'verb' => 'pay' }, 'amount' => 'action.params.usd', 'threshold' => 100,
            'approved' => [{ 'field' => 'env.cfo_approved', 'op' => 'eq', 'value' => true }] }
    c = F04.constitution([inv])
    F04.ck('at threshold', F04.ok?(F04.act('pay', '/v', { 'usd' => 100 }), c), true)
    F04.ck('over', F04.violated(F04.act('pay', '/v', { 'usd' => 101 }), c), ['big-pay'])
    F04.ck('over reason', F04.chk(F04.act('pay', '/v', { 'usd' => 101 }), c)['reasons'], ['big-pay: approval required over 100'])
    F04.ck('approved', F04.ok?(F04.act('pay', '/v', { 'usd' => 101 }, { 'cfo_approved' => true }), c), true)
    F04.ck('approval must be literal true', F04.ok?(F04.act('pay', '/v', { 'usd' => 101 }, { 'cfo_approved' => 'true' }), c), false)
    [nil, {}, { 'usd' => '5' }, { 'usd' => -1 }].each { |params| F04.ck("amount #{params.inspect}", F04.ok?(F04.act('pay', '/v', params), c), false) }
    F04.ck('unresolvable but approved', F04.ok?(F04.act('pay', '/v', nil, { 'cfo_approved' => true }), c), true)
    F04.ck('other verb', F04.ok?(F04.act('refund', '/v', { 'usd' => 1_000_000_000 }), c), true)
    true
  end

  # ---- evidence -----------------------------------------------------------------------------------------------------

  t('f04 evidence: deterministic, offline re-check, tamper and forgery rejected') do
    next true unless F04.gate?('prohibitions.rb')

    c = F04.constitution([F04::SPEND, F04::NO_PROD_DELETE, F04::NO_EXFIL])
    s = F04.adv(F04.act('pay', '/v', { 'usd' => 60 }), c, F04::P.empty_state(F04::NOW))
    a = F04.act('pay', '/vendor/acme', { 'usd' => 30 })
    e1 = F04::P.prove_safety(a, c, s)
    e2 = F04::P.prove_safety(Marshal.load(Marshal.dump(a)), Marshal.load(Marshal.dump(c)), Marshal.load(Marshal.dump(s)))
    F04.ck('deterministic', e1, e2)
    F04.ck('ok', e1['ok'], true)
    F04.ck('every invariant covered', e1['evaluated'].map { |x| x['id'] }, %w[spend-day no-prod-delete-without-human no-pii-exfil])
    F04.ck('shape', [e1['v'], e1['now'], e1['violated']], [1, F04::NOW, []])
    F04.ck('verifies', F04::P.verify_safety_evidence(e1, a, c, s), { 'ok' => true })
    F04.ck('digest', F04::P.evidence_digest(e1), AtlasPca.hash_canonical(e1))
    F04.ck('state digest', e1['state_digest'], F04::P.state_digest(s))
    F04.ck('bad state digest', F04::P.verify_safety_evidence(e1.merge('state_digest' => 'x'), a, c, s), { 'ok' => false, 'reason' => 'state digest mismatch' })
    F04.ck('dropped invariant', F04::P.verify_safety_evidence(e1.merge('evaluated' => e1['evaluated'][1..]), a, c, s), { 'ok' => false, 'reason' => 'evidence does not reproduce' })
    F04.ck('other action', F04::P.verify_safety_evidence(e1, F04.act('pay', '/vendor/acme', { 'usd' => 31 }), c, s), { 'ok' => false, 'reason' => 'action digest mismatch' })
    F04.ck('other constitution', F04::P.verify_safety_evidence(e1, a, F04.constitution([F04::SPEND]), s), { 'ok' => false, 'reason' => 'constitution mismatch' })
    s2 = F04.adv(F04.act('pay', '/v', { 'usd' => 1 }), c, s)
    F04.ck('other state', F04::P.verify_safety_evidence(e1, a, c, s2)['ok'], false)
    F04.ck('version', F04::P.verify_safety_evidence(e1.merge('v' => 9), a, c, s), { 'ok' => false, 'reason' => 'unsupported evidence version' })
    F04.ck('not a hash', F04::P.verify_safety_evidence(nil, a, c, s)['reason'], 'unsupported evidence version')
    bad = F04.act('pay', '/vendor/acme', { 'usd' => 99 })
    real = F04::P.prove_safety(bad, c, s)
    F04.ck('real violation', real['ok'], false)
    F04.ck('honest violation is not an admit', F04::P.verify_safety_evidence(real, bad, c, s), { 'ok' => false, 'reason' => 'prohibition violated: spend-day' })
    forged = real.merge('ok' => true, 'violated' => [], 'evaluated' => real['evaluated'].map { |x| x.merge('result' => 'pass').tap { |h| h.delete('reason') } })
    F04.ck('forged all-clear', F04::P.verify_safety_evidence(forged, bad, c, s)['ok'], false)
    F04.ck('result is not aliased', real['evaluated'][0].equal?(F04.chk(bad, c, s)['evaluated'][0]), false)
    unh = F04::P.prove_safety({ 'action' => { 'verb' => 'pay', 'resource' => '/v', 'params' => { 'usd' => 1.5e300 * 1e10 } } }, c, s)
    F04.ck('unhashable action', [unh['ok'], unh['action_digest'], unh['violated'].include?('<action>')], [false, '<unhashable>', true])
    bs = F04::P.prove_safety(a, c, { 'now' => Float::NAN })
    F04.ck('bad state', [bs['ok'], bs['violated'].include?('<state>'), bs['now']], [false, true, 0])
    true
  end

  t('f04 signed evidence: sign, verify, binding, lifting refused, forged all-clear never admits') do
    next true unless F04.gate?('prohibitions.rb')

    pub = F04.signer.public
    c = F04.constitution([F04::SPEND, F04::NO_PROD_DELETE, F04::NO_EXFIL])
    sc = F04::P.sign_constitution(c, F04.key)
    s = F04.adv(F04.act('pay', '/v', { 'usd' => 60 }), c, F04::P.empty_state(F04::NOW))
    a = F04.act('pay', '/vendor/acme', { 'usd' => 30 })
    sign = ->(act, con, st) { F04::P.sign_safety_evidence(F04::P.prove_safety(act, con, st), F04.signer) }
    full = ->(over = {}) { { 'signer' => pub, 'action' => a, 'constitution' => c, 'state' => s }.merge(over) }
    v = ->(se, exp) { F04::P.verify_signed_safety_evidence(se, exp) }
    se = sign.call(a, c, s)
    F04.ck('verifies', v.call(se, full.call), { 'ok' => true })
    F04.ck('binding id', se['id'], F04::P.safety_binding_id(se['evidence'], pub))
    F04.ck('deterministic', sign.call(a, c, s)['id'], se['id'])
    F04.ck('signer', se['signer'], pub)
    F04.ck('flipped sig', v.call(se.merge('sig' => (se['sig'][0] == 'A' ? 'B' : 'A') + se['sig'][1..]), full.call)['ok'], false)
    F04.ck('non-string sig', v.call(se.merge('sig' => 5), full.call), { 'ok' => false, 'reason' => 'bad signature' })
    F04.ck('digests only', v.call(se, { 'signer' => [pub], 'actionDigest' => se['evidence']['action_digest'], 'constitutionId' => se['evidence']['constitution'], 'stateDigest' => F04::P.state_digest(s) }), { 'ok' => true })
    F04.ck('pinned signed constitution', v.call(sign.call(a, sc, s), { 'signer' => pub, 'action' => a, 'constitution' => sc, 'state' => s, 'principal' => F04.key.public })['ok'], true)
    other = F04.act('pay', '/vendor/acme', { 'usd' => 31 })
    r = v.call(se, full.call('action' => other))
    F04.ck('lifted action', [r['ok'], r['reason']], [false, 'action digest mismatch (evidence bound to another action)'])
    F04.ck('action undefined + digest x', v.call(se, full.call('action' => nil, 'actionDigest' => 'x'))['ok'], false)
    F04.ck('lifted constitution', v.call(se, full.call('constitution' => F04.constitution([F04::SPEND])))['reason'], 'constitution mismatch (evidence bound to another constitution)')
    F04.ck('constitution id nope', v.call(se, full.call('constitution' => nil, 'constitutionId' => 'nope'))['ok'], false)
    weak = F04.constitution([F04::SPEND.merge('max' => 1_000_000_000), F04::NO_PROD_DELETE, F04::NO_EXFIL])
    F04.ck('weakened constitution', v.call(se, full.call('constitution' => weak))['ok'], false)
    F04.ck('constitution + disagreeing id', v.call(se, full.call('constitutionId' => 'zz'))['reason'], 'expected constitution and id disagree')
    F04.ck('lifted state', v.call(se, full.call('state' => F04.adv(F04.act('pay', '/v', { 'usd' => 1 }), c, s)))['reason'], 'state digest mismatch (evidence bound to another state)')
    F04.ck('ticked state', v.call(se, full.call('state' => s.merge('now' => s['now'] + 1)))['ok'], false)
    F04.ck('empty-ledger dodge', v.call(se, full.call('state' => F04::P.empty_state(F04::NOW)))['ok'], false)
    F04.ck('state + disagreeing digest', v.call(se, full.call('stateDigest' => 'zz'))['reason'], 'expected state and digest disagree')
    F04.ck('action + disagreeing digest', v.call(se, full.call('actionDigest' => 'mismatch'))['reason'], 'expected action and digest disagree')
    F04.ck('wrong signer', v.call(se, full.call('signer' => AtlasPca::KeyPair.generate.public))['reason'], 'signer not trusted')
    F04.ck('no signers', v.call(se, full.call('signer' => []))['reason'], 'no pinned signer')
    F04.ck('empty signer', v.call(se, full.call('signer' => ['']))['reason'], 'no pinned signer')
    o = AtlasPca::KeyPair.generate
    F04.ck('re-attributed', v.call(se.merge('signer' => o.public), full.call('signer' => o.public))['ok'], false)
    F04.ck('tampered evidence', v.call(se.merge('evidence' => se['evidence'].merge('now' => se['evidence']['now'] + 1)), full.call)['reason'], 'binding id mismatch')
    F04.ck('tampered digest', v.call(se.merge('evidence' => se['evidence'].merge('action_digest' => 'x')), full.call)['ok'], false)
    { 'action' => 'unbound: action not specified', 'constitution' => 'unbound: constitution not specified', 'state' => 'unbound: state not specified' }.each do |k, want|
      F04.ck("unbound #{k}", v.call(se, full.call(k => nil))['reason'], want)
    end
    F04.ck('null signed', v.call(nil, full.call), { 'ok' => false, 'reason' => 'malformed input' })
    F04.ck('null expected', v.call(se, nil), { 'ok' => false, 'reason' => 'malformed input' })
    F04.ck('version', v.call(se.merge('evidence' => se['evidence'].merge('v' => 2)), full.call)['reason'], 'unsupported evidence version')
    F04.ck('unpinned principal on an unsigned constitution', v.call(se, full.call('principal' => F04.key.public))['reason'], 'principal pin requires a signed constitution')
    fsc = sc.merge('sig' => F04::P.sign_constitution(c.merge('principal' => pub), F04.signer)['sig'])
    F04.ck('forged constitution sig', v.call(sign.call(a, fsc, s), { 'signer' => pub, 'action' => a, 'constitution' => fsc, 'state' => s, 'principal' => F04.key.public })['reason'], 'constitution not authentic: bad signature')
    bad = F04.act('pay', '/vendor/acme', { 'usd' => 99 })
    real = F04::P.prove_safety(bad, c, s)
    honest = F04::P.sign_safety_evidence(real, F04.signer)
    base = { 'signer' => pub, 'action' => bad, 'constitution' => c, 'state' => s }
    F04.ck('honest violation is not an admit', v.call(honest, base), { 'ok' => false, 'reason' => 'prohibition violated: spend-day' })
    F04.ck('requireOk false', v.call(honest, base.merge('requireOk' => false)), { 'ok' => true })
    lie = real.merge('ok' => true, 'violated' => [], 'evaluated' => real['evaluated'].map { |x| x.merge('result' => 'pass') })
    F04.ck('signed lie caught by recompute', v.call(F04::P.sign_safety_evidence(lie, F04.signer), base)['ok'], false)
    inconsistent = F04::P.sign_safety_evidence(real.merge('ok' => true), F04.signer)
    F04.ck('inconsistent verdict', v.call(inconsistent, { 'signer' => pub, 'actionDigest' => real['action_digest'], 'constitutionId' => real['constitution'], 'stateDigest' => real['state_digest'] })['reason'], 'evidence verdict inconsistent with rows')
    realok = F04::P.prove_safety(a, c, s)
    dropped = F04::P.sign_safety_evidence(realok.merge('evaluated' => realok['evaluated'][1..]), F04.signer)
    F04.ck('digest-only coverage', v.call(dropped, { 'signer' => pub, 'actionDigest' => realok['action_digest'], 'constitution' => c, 'stateDigest' => realok['state_digest'] })['ok'], false)
    F04.ck('malformed evidence rows', v.call(F04::P.sign_safety_evidence(realok.merge('evaluated' => 5), F04.signer), full.call)['reason'], 'malformed evidence')
    # unbound / unsupported evidence is never signed
    unb = F04::P.prove_safety({ 'action' => { 'verb' => 'pay', 'resource' => '/v', 'params' => { 'usd' => 1.5e300 * 1e10 } } }, c, s)
    [unb, realok.merge('v' => 9), nil].each_with_index do |bad_ev, i|
      raise "signed #{i}" unless (begin; F04::P.sign_safety_evidence(bad_ev, F04.signer); false; rescue TypeError; true; end)
    end
    nokey = Struct.new(:public) { def sign(_m) = 'x' }
    raise 'signed with no signer' unless (begin; F04::P.sign_safety_evidence(realok, nokey.new('')); false; rescue TypeError; true; end)
    true
  end

  # ---- check_and_advance --------------------------------------------------------------------------------------------

  t('f04 check_and_advance: allow advances; veto, permission denial and stale heads do not') do
    next true unless F04.gate?('prohibitions.rb')

    c = F04.constitution([F04::NO_PROD_DELETE, F04::SPEND])
    s = F04::P.empty_state(F04::NOW)
    pay = F04.act('pay', '/vendor/acme', { 'usd' => 40 })
    r = F04::P.check_and_advance(true, pay, c, s, { 'expectedSeq' => 0, 'expectedStateDigest' => F04::P.state_digest(s) })
    F04.ck('allow', [r['allow'], r['decidedBy'], r['next']['seq'], r['evidence']['state_digest']], [true, 'none', 1, F04::P.state_digest(s)])
    F04.ck('evidence verifies', F04::P.verify_safety_evidence(r['evidence'], pay, c, s)['ok'], true)
    np = F04::P.check_and_advance(false, pay, c, s)
    F04.ck('permission denial', [np['allow'], np['decidedBy'], np['next'].equal?(s)], [false, 'permission', true])
    veto = F04::P.check_and_advance(true, F04.act('pay', '/v', { 'usd' => 500 }), c, s)
    F04.ck('veto', [veto['allow'], veto['decidedBy'], veto['next'].equal?(s)], [false, 'prohibition', true])
    stale = F04::P.check_and_advance(true, pay, c, s, { 'expectedSeq' => r['next']['seq'] })
    F04.ck('stale seq', [stale['allow'], stale['decidedBy'], stale['reason']], [false, 'state', 'stale state head (seq)'])
    F04.ck('stale digest', F04::P.check_and_advance(true, pay, c, s, { 'expectedStateDigest' => 'old' })['reason'], 'stale state head (digest)')
    F04.ck('unresolvable amount', F04::P.check_and_advance(true, F04.act('pay', '/v'), c, s)['allow'], false)
    F04.ck('malformed state', F04::P.check_and_advance(true, pay, c, { 'now' => Float::NAN })['allow'], false)
    F04.ck('stale seq against a malformed state', F04::P.check_and_advance(true, pay, c, nil, { 'expectedSeq' => 0 })['reason'], 'stale state head (seq)')
    F04.ck('no reason key when none', F04::P.check_and_advance(false, pay, c, s).key?('reason'), false)
    true
  end

  t('f04 long session: every stateful form, admits signed, replayable and chained') do
    next true unless F04.gate?('prohibitions.rb')

    c = F04.constitution([
                           F04::SPEND,
                           { 'id' => 'rate', 'kind' => 'rate', 'when' => { 'verb' => 'send' }, 'max' => 3, 'window_secs' => 60 },
                           { 'id' => 'lock', 'kind' => 'never_after', 'after' => { 'verb' => 'read', 'resource' => '/secrets/*' }, 'forbid' => { 'verb' => 'send', 'resource' => '/net/*' } },
                           { 'id' => 'review', 'kind' => 'require_prior', 'when' => { 'verb' => 'deploy' }, 'prior' => { 'verb' => 'review' } },
                           { 'id' => 'big', 'kind' => 'require_approval_over', 'when' => { 'verb' => 'pay' }, 'amount' => 'action.params.usd', 'threshold' => 60,
                             'approved' => [{ 'field' => 'env.ok', 'op' => 'eq', 'value' => true }] }
                         ])
    sc = F04::P.sign_constitution(c, F04.key)
    s = F04::P.empty_state(F04::NOW)
    tnow = F04::NOW
    log = []
    step = lambda do |a, expect_allow, dt = 1000, violated = nil|
      tnow += dt
      tk = F04::P.tick_state(s, tnow)
      raise 'tick' unless tk['ok']

      pre = tk['state']
      r = F04::P.check_and_advance(true, a, sc, pre, { 'expectedSeq' => pre['seq'] })
      F04.ck("#{a['action']['verb']} #{a['action']['resource']}", r['allow'], expect_allow)
      F04.ck('violated', r['prohibition']['violated'], violated) if violated
      if r['allow']
        se = F04::P.sign_safety_evidence(r['evidence'], F04.signer)
        F04.ck('admit verifies', F04::P.verify_signed_safety_evidence(se, { 'signer' => F04.signer.public, 'action' => a, 'constitution' => sc, 'state' => pre, 'principal' => F04.key.public }), { 'ok' => true })
        log << [a, pre, se]
        F04.ck('seq', r['next']['seq'], pre['seq'] + 1)
        s = r['next']
      else
        F04.ck('unchanged', r['next'].equal?(pre), true)
        s = pre
      end
    end
    day = F04::DAY
    step.call(F04.act('deploy', '/prod'), false, 1000, ['review'])
    step.call(F04.act('review', '/pr/1'), true)
    step.call(F04.act('deploy', '/prod'), true)
    step.call(F04.act('pay', '/v', { 'usd' => 50 }), true)
    step.call(F04.act('pay', '/v', { 'usd' => 70 }), false, 1000, %w[spend-day big])
    step.call(F04.act('pay', '/v', { 'usd' => 40 }), true)
    step.call(F04.act('pay', '/v', { 'usd' => 20 }), false, 1000, ['spend-day'])
    3.times { step.call(F04.act('send', '/net/a'), true) }
    step.call(F04.act('send', '/net/a'), false, 1000, ['rate'])
    step.call(F04.act('send', '/net/a'), true, 61_000)
    step.call(F04.act('read', '/secrets/k'), true)
    step.call(F04.act('send', '/net/a'), false, 1000, ['lock'])
    step.call(F04.act('send', '/mail/a'), true)
    step.call(F04.act('pay', '/v', { 'usd' => 20 }), false, 1000, ['spend-day'])
    step.call(F04.act('pay', '/v', { 'usd' => 5 }), true, day * 1000)
    step.call(F04.act('pay', '/v', { 'usd' => 500 }), false, 1000, %w[spend-day big])
    raise 'latches' if s['latched']['lock'].nil? || s['latched']['review'].nil?

    replay = F04::P.empty_state(F04::NOW)
    log.each do |a, pre, se|
      tk = F04::P.tick_state(replay, pre['now'])
      F04.ck('pre-state pinned', F04::P.state_digest(tk['state']), F04::P.state_digest(pre))
      F04.ck('evidence pinned', se['evidence']['state_digest'], F04::P.state_digest(pre))
      ad = F04::P.advance_state_strict(a, c, tk['state'])
      raise 'adv' unless ad['ok']

      replay = ad['state']
    end
    F04.ck('replay length', replay['seq'], log.length)
    F04.ck('distinct pre-states', log.map { |_, pre, _| F04::P.state_digest(pre) }.uniq.length, log.length)
    first = log.first
    last = log.last
    F04.ck('first evidence on the last state', F04::P.verify_signed_safety_evidence(first[2], { 'signer' => F04.signer.public, 'action' => first[0], 'constitution' => sc, 'state' => last[1] })['ok'], false)
    F04.ck('last evidence on a wiped state', F04::P.verify_signed_safety_evidence(last[2], { 'signer' => F04.signer.public, 'action' => last[0], 'constitution' => sc, 'state' => last[1].merge('ledger' => {}, 'latched' => {}) })['ok'], false)
    true
  end

  # ---- forbid-wins clauses (forbid-certificate.test.ts) -------------------------------------------------------------

  t('f04 clauses: veto polarity per kind, precedence, permitSigners, certificate round trip') do
    next true unless F04.gate?('forbid_certificate.rb')

    cl = lambda do |id, kind, w, signer = nil|
      h = { 'id' => id, 'kind' => kind, 'when' => w }
      h['signer'] = signer unless signer.nil?
      h
    end
    ctx = F04.act('pay', '/v', { 'usd' => 5 })
    pm = { 'verb' => 'pay' }
    unresolvable = { 'verb' => 'pay', 'where' => [{ 'field' => 'action.params.missing', 'op' => 'eq', 'value' => 1 }] }
    d = ->(cs, opts = nil) { AtlasPca.decide_clauses(cs, ctx, opts) }
    F04.ck('permit only', d.call([cl.call('p', 'permit', pm)]).slice('decision', 'witness'), { 'decision' => 'allow', 'witness' => { 'winner' => { 'kind' => 'permit', 'id' => 'p' }, 'shadowed' => [] } })
    F04.ck('permit unresolvable is not matched', d.call([cl.call('p', 'permit', unresolvable)])['decision'], 'deny')
    F04.ck('forbid unresolvable is matched', d.call([cl.call('p', 'permit', pm), cl.call('f', 'forbid', unresolvable)])['witness']['winner'], { 'kind' => 'forbid', 'id' => 'f' })
    F04.ck('value unknown', d.call([cl.call('f', 'forbid', unresolvable)])['values'], [{ 'id' => 'f', 'kind' => 'forbid', 'value' => 'unknown' }])
    F04.ck('escalate caps', d.call([cl.call('p', 'permit', pm), cl.call('e', 'escalate', pm)]).slice('decision', 'witness'), { 'decision' => 'escalate', 'witness' => { 'winner' => { 'kind' => 'escalate', 'id' => 'e' }, 'shadowed' => ['p'] } })
    F04.ck('forbid beats all', d.call([cl.call('p', 'permit', pm), cl.call('e', 'escalate', pm), cl.call('f', 'forbid', pm)])['witness'], { 'winner' => { 'kind' => 'forbid', 'id' => 'f' }, 'shadowed' => %w[p e] })
    F04.ck('no permit denies and names none', d.call([cl.call('e', 'escalate', pm)]).slice('decision', 'witness'), { 'decision' => 'deny', 'witness' => { 'winner' => { 'kind' => 'none', 'id' => nil }, 'shadowed' => ['e'] } })
    two = [cl.call('fb', 'forbid', pm, 'user'), cl.call('fa', 'forbid', pm, 'org'), cl.call('fc', 'forbid', pm)]
    F04.ck('precedence', d.call(two, { 'precedence' => %w[org user] })['witness']['winner']['id'], 'fa')
    F04.ck('precedence flipped', d.call(two, { 'precedence' => %w[user org] })['witness']['winner']['id'], 'fb')
    F04.ck('unlisted signer ranks last, ties by id', d.call(two)['witness']['winner']['id'], 'fa')
    F04.ck('ids sort by UTF-16', d.call([cl.call('b', 'forbid', pm), cl.call('B', 'forbid', pm)])['witness']['winner']['id'], 'B')
    ps = [cl.call('p1', 'permit', pm, 'user'), cl.call('p2', 'permit', pm, 'other'), cl.call('p3', 'permit', pm)]
    F04.ck('permitSigners drops others', d.call(ps, { 'permitSigners' => ['user'] })['values'].map { |v| v['value'] }, %w[true false false])
    F04.ck('permitSigners empty denies', d.call(ps, { 'permitSigners' => [] })['decision'], 'deny')
    F04.ck('permitSigners does not drop forbids', d.call([cl.call('f', 'forbid', pm), cl.call('p', 'permit', pm, 'user')], { 'permitSigners' => ['user'] })['witness']['winner']['id'], 'f')
    cs = [cl.call('p', 'permit', pm, 'user'), cl.call('f', 'forbid', { 'verb' => 'zzz' }, 'org'), cl.call('e', 'escalate', unresolvable, 'org')]
    cert = AtlasPca.certify_clauses(cs, ctx, { 'precedence' => %w[org user] })
    F04.ck('certificate', [cert['v'], cert['kind'], cert['decision'], cert['policy'], cert['action']], [1, 'forbid-wins', 'escalate', AtlasPca.hash_canonical(cs), AtlasPca.hash_canonical(ctx)])
    F04.ck('rows keep the signer', cert['clauses'].map { |r| r['signer'] }, %w[user org org])
    F04.ck('round trip', AtlasPca.check_forbid_certificate(cert, cs, ctx, { 'precedence' => %w[org user] }), { 'ok' => true })
    F04.ck('rows without a signer omit the key', AtlasPca.certify_clauses([cl.call('p', 'permit', pm)], ctx)['clauses'], [{ 'id' => 'p', 'kind' => 'permit', 'value' => 'true' }])
    F04.ck('other action', AtlasPca.check_forbid_certificate(cert, cs, F04.act('pay', '/other'), { 'precedence' => %w[org user] })['ok'], false)
    F04.ck('malformed clauses', AtlasPca.check_forbid_certificate(cert, 'x', ctx), { 'ok' => false, 'reason' => 'malformed clauses' })
    F04.ck('malformed action', AtlasPca.decide_clauses(cs, { 'action' => { 'verb' => 1 } }), AtlasPca.malformed_clause_decision)
    F04.ck('nil action', AtlasPca.decide_clauses(cs, nil), AtlasPca.malformed_clause_decision)
    F04.ck('error: not an array', AtlasPca.clauses_error('x'), 'clauses must be an array')
    F04.ck('error: too many', AtlasPca.clauses_error(Array.new(513) { |i| cl.call("c#{i}", 'permit', pm) }), 'more than 512 clauses')
    F04.ck('512 fine', AtlasPca.clauses_error(Array.new(512) { |i| cl.call("c#{i}", 'permit', pm) }), nil)
    F04.ck('error: signer', AtlasPca.clauses_error([cl.call('a', 'permit', pm, 5)]), 'clauses[0].signer must be a string of at most 256 characters')
    F04.ck('error: when', AtlasPca.clauses_error([{ 'id' => 'a', 'kind' => 'permit', 'when' => [] }]), 'clauses[0].when must be a predicate object')
    F04.ck('error: duplicate', AtlasPca.clauses_error([cl.call('a', 'permit', pm), cl.call('a', 'forbid', pm)]), "clauses[1].id 'a' is a duplicate")
    true
  end
end
