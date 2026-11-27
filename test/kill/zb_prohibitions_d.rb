# frozen_string_literal: true

# zb_prohibitions_d: safety evidence (plain and signed), the composition of permission and prohibition, and the
# check-and-advance kernel. Builds on the helpers of zb_prohibitions_b.rb and zb_prohibitions_c.rb.

module MutationKill
  module ZbQ
    module_function

    NV2 = NV.merge('id' => 'nv2').freeze

    def signer = (@signer ||= AtlasPca::KeyPair.generate)
    def stranger = (@stranger ||= AtlasPca::KeyPair.generate)

    # Evidence, its signed form and the full / digest-only expectations for an action, constitution and state.
    def kit(invs = [NV], action = act('other'), state = st) = kit_for(con(invs), action, state)

    def kit_for(c, action = act('other'), state = st)
      ev = P.prove_safety(action, c, state)
      signed = P.sign_safety_evidence(ev, signer)
      { c: c, a: action, s: state, ev: ev, signed: signed,
        full: { 'signer' => signer.public, 'action' => action, 'constitution' => c, 'state' => state },
        digests: { 'signer' => signer.public, 'actionDigest' => ev['action_digest'], 'constitutionId' => ev['constitution'], 'stateDigest' => ev['state_digest'] } }
    end

    def resign(ev) = P.sign_safety_evidence(ev, signer)
    def vs(signed, expected) = P.verify_signed_safety_evidence(signed, expected)
    def no(reason) = { 'ok' => false, 'reason' => reason }
  end

  t('zb prohibitions: prove_safety and evidence_from') do
    next true unless ZbQ.gate?

    q = ZbQ
    p = q::P
    c = q.con([q::NV])
    a = q.act('other')
    ev = p.prove_safety(a, c, q.st)
    q.ck('evidence', ev, { 'v' => 1, 'constitution' => p.constitution_id(c), 'action_digest' => AtlasPca.hash_canonical(a), 'state_digest' => p.state_digest(q.st), 'now' => q::NOW,
                           'evaluated' => [q.pass_row(q::NV)], 'ok' => true, 'violated' => [] })
    q.ck('digest of evidence', p.evidence_digest(ev), AtlasPca.hash_canonical(ev))
    bad = p.prove_safety(q.act('boom'), c, q.st)
    q.ck('violated evidence', [bad['ok'], bad['violated'], bad['evaluated'].map { |e| e['result'] }], [false, ['nv'], ['violated']])

    # an unhashable input makes the evidence not ok, named in `violated`, exactly once
    odd = c.merge('x' => Object.new)
    ev = p.prove_safety(a, odd, q.st)
    q.ck('unhashable constitution', [ev['constitution'], ev['ok'], ev['violated'], ev['action_digest'], ev['state_digest'] == p.state_digest(q.st)], ['<unhashable>', false, ['<constitution>'], AtlasPca.hash_canonical(a), true])
    ev = p.prove_safety(q.act('other', '/r', { 'k' => Object.new }), c, q.st)
    q.ck('unhashable action', [ev['action_digest'], ev['ok'], ev['violated']], ['<unhashable>', false, ['<action>']])
    ev = p.prove_safety(a, c, q.st('now' => 2**53))
    q.ck('unhashable state', [ev['state_digest'], ev['ok'], ev['violated'], ev['now']], ['<unhashable>', false, ['<state>'], 2**53])
    ev = p.prove_safety(a, c, nil)
    q.ck('malformed state is named once', [ev['state_digest'], ev['ok'], ev['violated'], ev['now']], ['<unhashable>', false, ['<state>'], 0])
    ev = p.prove_safety(a, { 'version' => 2 }, q.st)
    q.ck('malformed constitution is named once', [ev['ok'], ev['violated'], ev['constitution'] == p.constitution_id({ 'version' => 2 })], [false, ['<constitution>'], true])
    ev = p.prove_safety(nil, c, q.st)
    q.ck('malformed action is named once', [ev['action_digest'], ev['ok'], ev['violated']], [AtlasPca.hash_canonical(nil), false, ['<action>']])
    ev = p.prove_safety(q.act('boom'), odd, q.st)
    q.ck('a violation and an unhashable input are both named', [ev['ok'], ev['violated']], [false, %w[nv <constitution>]])
    q.ck('clock of a non object state', p.prove_safety(a, c, 5)['now'], 0)
    q.ck('clock of a state without a finite clock', p.prove_safety(a, c, { 'now' => nil })['now'], 0)
    q.ck('clock of a float state', p.prove_safety(a, c, q.st('now' => 1.5))['now'], 1.5)

    r = p.check_prohibitions(a, c, q.st)
    ev = p.evidence_from(r, a, c, q.st)
    q.ck('rows are copies', ev['evaluated'][0].equal?(r['evaluated'][0]), false)
    ev['evaluated'][0]['result'] = 'tampered'
    q.ck('tampering with the evidence leaves the decision alone', r['evaluated'][0]['result'], 'pass')
    true
  end

  t('zb prohibitions: verify_safety_evidence reasons') do
    next true unless ZbQ.gate?

    q = ZbQ
    p = q::P
    c = q.con([q::NV, q::NV2])
    a = q.act('other')
    ev = p.prove_safety(a, c, q.st)
    v = ->(e, ac = a, co = c, s = q.st) { p.verify_safety_evidence(e, ac, co, s) }
    q.ck('honest', v.call(ev), { 'ok' => true })
    q.ck('not an object', v.call(nil), q.no('unsupported evidence version'))
    q.ck('string', v.call('x'), q.no('unsupported evidence version'))
    q.ck('version 2', v.call(ev.merge('v' => 2)), q.no('unsupported evidence version'))
    q.ck('version missing', v.call(ev.reject { |k, _| k == 'v' }), q.no('unsupported evidence version'))
    q.ck('version string', v.call(ev.merge('v' => '1')), q.no('unsupported evidence version'))
    q.ck('constitution mismatch', v.call(ev, a, q.con([q::NV])), q.no('constitution mismatch'))
    q.ck('action mismatch', v.call(ev, q.act('another')), q.no('action digest mismatch'))
    q.ck('state mismatch', v.call(ev, a, c, q.st('seq' => 1, 'parent' => 'p')), q.no('state digest mismatch'))
    q.ck('does not reproduce', v.call(ev.merge('now' => 1)), q.no('evidence does not reproduce'))
    q.ck('does not reproduce: extra field', v.call(ev.merge('extra' => 1)), q.no('evidence does not reproduce'))
    q.ck('does not reproduce: forged all clear', v.call(p.prove_safety(q.act('boom'), c, q.st).merge('ok' => true, 'violated' => []), q.act('boom')), q.no('evidence does not reproduce'))
    bad = p.prove_safety(q.act('boom'), c, q.st)
    q.ck('violated lists every id', v.call(bad, q.act('boom')), q.no('prohibition violated: nv,nv2'))
    q.ck('violated with one id', v.call(p.prove_safety(q.act('boom'), q.con([q::NV]), q.st), q.act('boom'), q.con([q::NV])), q.no('prohibition violated: nv'))
    q.ck('fail closed', v.call(ev.merge('x' => Object.new)), q.no('verification error (fail closed)'))
    q.ck('fail closed on an unhashable evidence member', p.verify_safety_evidence(ev.merge('x' => Float::NAN), a, c, q.st), q.no('verification error (fail closed)'))
    true
  end

  t('zb prohibitions: sign_safety_evidence refusals and shape') do
    next true unless ZbQ.gate?

    q = ZbQ
    p = q::P
    ev = q.kit[:ev]
    refusal = lambda do |evidence, key = q.signer|
      p.sign_safety_evidence(evidence, key)
      raise 'no refusal'
    rescue TypeError => e
      e.message
    end
    [nil, 5, 'x', [], ev.merge('v' => 2), ev.merge('v' => '1'), ev.reject { |k, _| k == 'v' }].each do |e|
      q.ck("unsupported #{e.inspect[0, 24]}", refusal.call(e), 'signSafetyEvidence: unsupported evidence')
    end
    %w[constitution action_digest state_digest].each do |f|
      [nil, '', 5, '<unhashable>', ['x'], true].each do |v|
        q.ck("unbound #{f} #{v.inspect}", refusal.call(ev.merge(f => v)), 'signSafetyEvidence: unbound evidence')
      end
      q.ck("unbound #{f} missing", refusal.call(ev.reject { |k, _| k == f }), 'signSafetyEvidence: unbound evidence')
    end
    keyed = Struct.new(:public) { def sign(_m) = 'sig'.b }
    [nil, '', 5, ['x']].each { |pub| q.ck("signer #{pub.inspect}", refusal.call(ev, keyed.new(pub)), 'signSafetyEvidence: signer missing') }

    signed = p.sign_safety_evidence(ev, q.signer)
    q.ck('keys', signed.keys.sort, %w[evidence id sig signer])
    q.ck('evidence kept', signed['evidence'], ev)
    q.ck('signer', signed['signer'], q.signer.public)
    q.ck('binding id', signed['id'], p.safety_binding_id(ev, q.signer.public))
    want = AtlasPca.hash_canonical({ 'd' => "atlas-pca/safety-evidence/v1\0", 'signer' => q.signer.public, 'evidence' => AtlasPca.hash_canonical(ev),
                                     'constitution' => ev['constitution'], 'action_digest' => ev['action_digest'], 'state_digest' => ev['state_digest'] })
    q.ck('binding id content', signed['id'], want)
    q.ck('signature verifies', AtlasPca.verify_b64u(q.signer.public, p.domain_message("atlas-pca/safety-evidence/v1\0", signed['id']), signed['sig']), true)
    q.ck('signature binds the id', AtlasPca.verify_b64u(q.signer.public, p.domain_message("atlas-pca/safety-evidence/v1\0", 'other'), signed['sig']), false)
    q.ck('binding id commits to the signer', p.safety_binding_id(ev, q.stranger.public) == signed['id'], false)
    q.ck('binding id commits to the evidence', p.safety_binding_id(ev.merge('now' => 1), q.signer.public) == signed['id'], false)
    %w[constitution action_digest state_digest].each do |f|
      e = ZbQ.err_of { p.safety_binding_id(ev.reject { |k, _| k == f }, q.signer.public) }
      q.ck("binding id needs #{f}", [e.class, e.message.include?(f)], [KeyError, true])
    end
    true
  end

  t('zb prohibitions: verify_signed_safety_evidence input, signer and binding reasons') do
    next true unless ZbQ.gate?

    q = ZbQ
    k = q.kit
    signed = k[:signed]
    full = k[:full]
    q.ck('honest, full', q.vs(signed, full), { 'ok' => true })
    q.ck('honest, digests', q.vs(signed, k[:digests]), { 'ok' => true })
    q.ck('signer list', q.vs(signed, full.merge('signer' => [q.stranger.public, q.signer.public])), { 'ok' => true })
    [[nil, full], [5, full], ['x', full], [[], full], [{}, full], [{ 'evidence' => 5 }, full], [{ 'evidence' => nil }, full], [{ 'evidence' => [] }, full],
     [signed, nil], [signed, 5], [signed, 'x'], [signed, []]].each { |s, e| q.ck("malformed input #{s.inspect[0, 20]} #{e.inspect[0, 20]}", q.vs(s, e), q.no('malformed input')) }
    q.ck('version 2', q.vs(signed.merge('evidence' => k[:ev].merge('v' => 2)), full), q.no('unsupported evidence version'))
    q.ck('version missing', q.vs(signed.merge('evidence' => k[:ev].reject { |kk, _| kk == 'v' }), full), q.no('unsupported evidence version'))
    [nil, [], [''], [5], [nil], [q.signer.public, ''], [q.signer.public, 5], '', 5, true].each do |sg|
      q.ck("no pinned signer #{sg.inspect}", q.vs(signed, full.merge('signer' => sg)), q.no('no pinned signer'))
    end
    q.ck('signer missing', q.vs(signed, full.reject { |kk, _| kk == 'signer' }), q.no('no pinned signer'))
    q.ck('signer not trusted', q.vs(signed, full.merge('signer' => q.stranger.public)), q.no('signer not trusted'))
    q.ck('signer not trusted: list', q.vs(signed, full.merge('signer' => [q.stranger.public])), q.no('signer not trusted'))
    q.ck('signed signer not a string', q.vs(signed.merge('signer' => 5), full), q.no('signer not trusted'))
    q.ck('signed signer missing', q.vs(signed.reject { |kk, _| kk == 'signer' }, full), q.no('signer not trusted'))
    q.ck('signed signer another key', q.vs(signed.merge('signer' => q.stranger.public), full.merge('signer' => q.stranger.public)), q.no('binding id mismatch'))

    q.ck('unbound action', q.vs(signed, full.reject { |kk, _| kk == 'action' }), q.no('unbound: action not specified'))
    q.ck('unbound constitution', q.vs(signed, full.reject { |kk, _| kk == 'constitution' }), q.no('unbound: constitution not specified'))
    q.ck('unbound state', q.vs(signed, full.reject { |kk, _| kk == 'state' }), q.no('unbound: state not specified'))
    q.ck('unbound everything reports the action first', q.vs(signed, { 'signer' => q.signer.public }), q.no('unbound: action not specified'))
    q.ck('unbound constitution before state', q.vs(signed, { 'signer' => q.signer.public, 'actionDigest' => k[:ev]['action_digest'] }), q.no('unbound: constitution not specified'))
    q.ck('digest alone binds the action', q.vs(signed, full.reject { |kk, _| kk == 'action' }.merge('actionDigest' => k[:ev]['action_digest'])), { 'ok' => true })
    q.ck('id alone binds the constitution', q.vs(signed, full.reject { |kk, _| kk == 'constitution' }.merge('constitutionId' => k[:ev]['constitution'])), { 'ok' => true })
    q.ck('digest alone binds the state', q.vs(signed, full.reject { |kk, _| kk == 'state' }.merge('stateDigest' => k[:ev]['state_digest'])), { 'ok' => true })

    [nil, 'x', 5, [], ''].each { |i| q.ck("binding id #{i.inspect}", q.vs(signed.merge('id' => i), full), q.no('binding id mismatch')) }
    q.ck('binding id missing', q.vs(signed.reject { |kk, _| kk == 'id' }, full), q.no('binding id mismatch'))
    q.ck('evidence changed after signing', q.vs(signed.merge('evidence' => k[:ev].merge('now' => 1)), full), q.no('binding id mismatch'))
    [nil, 'AAAA', 5, [], ''].each { |sg| q.ck("signature #{sg.inspect}", q.vs(signed.merge('sig' => sg), full), q.no('bad signature')) }
    q.ck('signature missing', q.vs(signed.reject { |kk, _| kk == 'sig' }, full), q.no('bad signature'))
    forged = q.stranger.sign(q::P.domain_message("atlas-pca/safety-evidence/v1\0", signed['id']))
    q.ck('signature by another key', q.vs(signed.merge('sig' => AtlasPca.b64e(forged)), full), q.no('bad signature'))
    true
  end

  t('zb prohibitions: verify_signed_safety_evidence binding reasons') do
    next true unless ZbQ.gate?

    q = ZbQ
    p = q::P
    k = q.kit
    signed = k[:signed]
    full = k[:full]
    ev = k[:ev]
    # action
    q.ck('action digest wrong', q.vs(signed, full.reject { |kk, _| kk == 'action' }.merge('actionDigest' => 'x')), q.no('action digest mismatch (evidence bound to another action)'))
    q.ck('action wrong', q.vs(signed, full.merge('action' => q.act('another'))), q.no('action digest mismatch (evidence bound to another action)'))
    q.ck('action and digest agree', q.vs(signed, full.merge('actionDigest' => ev['action_digest'])), { 'ok' => true })
    q.ck('action and digest disagree', q.vs(signed, full.merge('actionDigest' => 'x')), q.no('expected action and digest disagree'))
    q.ck('action and digest disagree, action also wrong', q.vs(signed, full.merge('action' => q.act('another'), 'actionDigest' => ev['action_digest'])), q.no('expected action and digest disagree'))
    q.ck('action and nil digest disagree', q.vs(signed, full.merge('actionDigest' => nil)), q.no('expected action and digest disagree'))
    # constitution
    q.ck('constitution id wrong', q.vs(signed, full.reject { |kk, _| kk == 'constitution' }.merge('constitutionId' => 'x')), q.no('constitution mismatch (evidence bound to another constitution)'))
    q.ck('constitution wrong', q.vs(signed, full.merge('constitution' => q.con([q::NV2]))), q.no('constitution mismatch (evidence bound to another constitution)'))
    q.ck('constitution and id agree', q.vs(signed, full.merge('constitutionId' => ev['constitution'])), { 'ok' => true })
    q.ck('constitution and id disagree', q.vs(signed, full.merge('constitutionId' => 'x')), q.no('expected constitution and id disagree'))
    q.ck('constitution and nil id disagree', q.vs(signed, full.merge('constitutionId' => nil)), q.no('expected constitution and id disagree'))
    # principal pin
    sc = p.sign_constitution(k[:c], q.key)
    sk = q.kit([q::NV], q.act('other'), q.st)
    sev = p.sign_safety_evidence(p.prove_safety(sk[:a], sc, sk[:s]), q.signer)
    sfull = sk[:full].merge('constitution' => sc)
    q.ck('pinned principal', q.vs(sev, sfull.merge('principal' => q.key.public)), { 'ok' => true })
    q.ck('no pin', q.vs(sev, sfull), { 'ok' => true })
    q.ck('wrong principal', q.vs(sev, sfull.merge('principal' => q.stranger.public)), q.no('constitution not authentic: principal mismatch'))
    q.ck('nil principal', q.vs(sev, sfull.merge('principal' => nil)), q.no('constitution not authentic: principal mismatch'))
    q.ck('unsigned constitution', q.vs(signed, full.merge('principal' => q.key.public)), q.no('principal pin requires a signed constitution'))
    q.ck('constitution id only', q.vs(signed, full.reject { |kk, _| kk == 'constitution' }.merge('constitutionId' => ev['constitution'], 'principal' => q.key.public)), q.no('principal pin requires a signed constitution'))
    q.ck('signature not a string', q.vs(sev, sfull.merge('principal' => q.key.public, 'constitution' => sc.merge('sig' => 5))), q.no('principal pin requires a signed constitution'))
    q.ck('signature nil', q.vs(sev, sfull.merge('principal' => q.key.public, 'constitution' => sc.merge('sig' => nil))), q.no('principal pin requires a signed constitution'))
    q.ck('constitution not an object', q.vs(signed, full.merge('principal' => q.key.public, 'constitution' => 'x')), q.no('principal pin requires a signed constitution'))
    q.ck('bad signature reason is passed on', q.vs(sev, sfull.merge('principal' => q.key.public, 'constitution' => sc.merge('sig' => 'AAAA'))), q.no('constitution not authentic: bad signature'))
    # a malformed expected constitution never verifies
    badc = q.con([{ 'id' => 'a', 'kind' => 'zz' }])
    bk = q.kit_for(badc)
    q.ck('malformed constitution', q.vs(bk[:signed], bk[:full]), q.no('constitution malformed: a: unknown invariant kind zz'))
    # state
    q.ck('state digest wrong', q.vs(signed, full.reject { |kk, _| kk == 'state' }.merge('stateDigest' => 'x')), q.no('state digest mismatch (evidence bound to another state)'))
    q.ck('state wrong', q.vs(signed, full.merge('state' => q.st('seq' => 1, 'parent' => 'p'))), q.no('state digest mismatch (evidence bound to another state)'))
    q.ck('state and digest agree', q.vs(signed, full.merge('stateDigest' => ev['state_digest'])), { 'ok' => true })
    q.ck('state and digest disagree', q.vs(signed, full.merge('stateDigest' => 'x')), q.no('expected state and digest disagree'))
    q.ck('state and nil digest disagree', q.vs(signed, full.merge('stateDigest' => nil)), q.no('expected state and digest disagree'))
    q.ck('malformed expected state fails closed', q.vs(signed, full.merge('state' => { 'now' => nil })), q.no('verification error (fail closed)'))
    true
  end

  t('zb prohibitions: verify_signed_safety_evidence consistency, reproduction and verdict') do
    next true unless ZbQ.gate?

    q = ZbQ
    p = q::P
    k = q.kit([q::NV, q::NV2])
    ev = k[:ev]
    dg = k[:digests]
    full = k[:full]
    # arrays
    q.ck('evaluated not an array', q.vs(q.resign(ev.merge('evaluated' => 'x')), dg), q.no('malformed evidence'))
    q.ck('evaluated nil', q.vs(q.resign(ev.merge('evaluated' => nil)), dg), q.no('malformed evidence'))
    q.ck('violated not an array', q.vs(q.resign(ev.merge('violated' => 'x')), dg), q.no('malformed evidence'))
    q.ck('violated nil', q.vs(q.resign(ev.merge('violated' => nil)), dg), q.no('malformed evidence'))
    q.ck('violated a hash', q.vs(q.resign(ev.merge('violated' => {})), dg), q.no('malformed evidence'))
    q.ck('row id not a string', q.vs(q.resign(ev.merge('evaluated' => [{ 'id' => 5, 'result' => 'pass' }])), dg), q.no('malformed evidence'))
    q.ck('row id nil', q.vs(q.resign(ev.merge('evaluated' => [{ 'id' => nil, 'result' => 'pass' }])), dg), q.no('malformed evidence'))
    # verdict follows from rows
    q.ck('ok flipped', q.vs(q.resign(ev.merge('ok' => false)), dg), q.no('evidence verdict inconsistent with rows'))
    q.ck('violated row but ok', q.vs(q.resign(ev.merge('evaluated' => [{ 'id' => 'nv', 'result' => 'violated' }])), dg), q.no('evidence verdict inconsistent with rows'))
    q.ck('unknown result row but ok', q.vs(q.resign(ev.merge('evaluated' => [{ 'id' => 'nv', 'result' => 'maybe' }])), dg), q.no('evidence verdict inconsistent with rows'))
    q.ck('row without result but ok', q.vs(q.resign(ev.merge('evaluated' => [{ 'id' => 'nv' }])), dg), q.no('evidence verdict inconsistent with rows'))
    q.ck('non object row but ok', q.vs(q.resign(ev.merge('evaluated' => [5])), dg), q.no('evidence verdict inconsistent with rows'))
    q.ck('violated list but ok', q.vs(q.resign(ev.merge('violated' => ['nv'])), dg), q.no('evidence verdict inconsistent with rows'))
    q.ck('violated row but ok false is consistent, refused as a violation', q.vs(q.resign(ev.merge('ok' => false, 'evaluated' => [{ 'id' => 'nv', 'result' => 'violated' }], 'violated' => ['nv'])), dg), q.no('prohibition violated: nv'))
    q.ck('passing rows, violated list, ok false is consistent', q.vs(q.resign(ev.merge('ok' => false, 'violated' => ['x'])), dg), q.no('prohibition violated: x'))
    q.ck('violated row, empty list, ok false is consistent', q.vs(q.resign(ev.merge('ok' => false, 'evaluated' => [{ 'id' => 'nv', 'result' => 'violated' }])), dg), q.no('prohibition violated: '))
    q.ck('ok true with all rows passing', q.vs(q.resign(ev), dg), { 'ok' => true })

    # full reproduction needs all three of action, constitution, state
    forged = q.resign(ev.merge('now' => 1))
    q.ck('full: does not reproduce', q.vs(forged, full), q.no('evidence does not reproduce'))
    q.ck('without the action: the digest binds, no reproduction', q.vs(forged, full.reject { |kk, _| kk == 'action' }.merge('actionDigest' => ev['action_digest'])), { 'ok' => true })
    q.ck('without the constitution', q.vs(forged, full.reject { |kk, _| kk == 'constitution' }.merge('constitutionId' => ev['constitution'])), { 'ok' => true })
    q.ck('without the state', q.vs(forged, full.reject { |kk, _| kk == 'state' }.merge('stateDigest' => ev['state_digest'])), { 'ok' => true })
    q.ck('with the digests only', q.vs(forged, dg), { 'ok' => true })
    q.ck('with every digest beside the objects it still reproduces', q.vs(forged, full.merge('actionDigest' => ev['action_digest'], 'constitutionId' => ev['constitution'], 'stateDigest' => ev['state_digest'])), q.no('evidence does not reproduce'))
    # an honest violation
    bad = q.kit([q::NV, q::NV2], q.act('boom'))
    q.ck('honest violation, full', q.vs(bad[:signed], bad[:full]), q.no('prohibition violated: nv,nv2'))
    q.ck('honest violation, digests', q.vs(bad[:signed], bad[:digests]), q.no('prohibition violated: nv,nv2'))
    q.ck('honest violation accepted when not required', q.vs(bad[:signed], bad[:full].merge('requireOk' => false)), { 'ok' => true })
    q.ck('honest violation, digests, not required', q.vs(bad[:signed], bad[:digests].merge('requireOk' => false)), { 'ok' => true })
    [nil, 0, 'no', true, 1].each { |r| q.ck("requireOk #{r.inspect}", q.vs(bad[:signed], bad[:full].merge('requireOk' => r)), q.no('prohibition violated: nv,nv2')) }
    q.ck('requireOk false with a clean record', q.vs(k[:signed], full.merge('requireOk' => false)), { 'ok' => true })
    tampered = q.resign(bad[:ev].merge('now' => 1))
    q.ck('tampered violation, full', q.vs(tampered, bad[:full]), q.no('evidence does not reproduce'))
    q.ck('tampered violation is refused even when not required', q.vs(tampered, bad[:full].merge('requireOk' => false)), q.no('evidence does not reproduce'))
    wrong_verdict = q.resign(bad[:ev].merge('violated' => ['nv']))
    q.ck('understated violation, full', q.vs(wrong_verdict, bad[:full].merge('requireOk' => false)), q.no('evidence does not reproduce'))
    # a forged all clear never admits
    allclear = p.prove_safety(q.act('boom'), q.con([q::NV, q::NV2]), q.st).merge('ok' => true, 'violated' => [], 'evaluated' => [q.pass_row(q::NV), q.pass_row(q::NV2)])
    sac = q.resign(allclear)
    q.ck('forged all clear, full', q.vs(sac, bad[:full]), q.no('evidence does not reproduce'))

    # coverage when the constitution is known but the action or state is only a digest
    cov = q.kit([q::NV, q::NV2])
    nodoc = cov[:full].reject { |kk, _| kk == 'action' }.merge('actionDigest' => cov[:ev]['action_digest'])
    q.ck('covers every invariant', q.vs(cov[:signed], nodoc), { 'ok' => true })
    q.ck('fewer rows', q.vs(q.resign(cov[:ev].merge('evaluated' => [q.pass_row(q::NV)])), nodoc), q.no('evidence does not cover every invariant'))
    q.ck('no rows', q.vs(q.resign(cov[:ev].merge('evaluated' => [])), nodoc), q.no('evidence does not cover every invariant'))
    q.ck('more rows', q.vs(q.resign(cov[:ev].merge('evaluated' => cov[:ev]['evaluated'] + [q.pass_row(q::NV)])), nodoc), q.no('evidence does not cover every invariant'))
    q.ck('rows in another order', q.vs(q.resign(cov[:ev].merge('evaluated' => cov[:ev]['evaluated'].reverse)), nodoc), q.no('evidence does not cover every invariant'))
    q.ck('a row with another id', q.vs(q.resign(cov[:ev].merge('evaluated' => [q.pass_row(q::NV), q.pass_row(q::NV2.merge('id' => 'other'))])), nodoc), q.no('evidence does not cover every invariant'))
    q.ck('a row without an id', q.vs(q.resign(cov[:ev].merge('evaluated' => [q.pass_row(q::NV), { 'kind' => 'never', 'result' => 'pass' }])), nodoc), q.no('evidence does not cover every invariant'))
    nostate = cov[:full].reject { |kk, _| kk == 'state' }.merge('stateDigest' => cov[:ev]['state_digest'])
    q.ck('coverage with a state digest', q.vs(q.resign(cov[:ev].merge('evaluated' => [])), nostate), q.no('evidence does not cover every invariant'))
    q.ck('coverage is only for an ok record', q.vs(q.resign(cov[:ev].merge('ok' => false, 'evaluated' => [{ 'id' => 'nv', 'result' => 'violated' }], 'violated' => ['nv'])), nodoc.merge('requireOk' => false)), { 'ok' => true })
    true
  end

  t('zb prohibitions: compose_from and compose_authority') do
    next true unless ZbQ.gate?

    q = ZbQ
    p = q::P
    okp = { 'ok' => true }
    nop = { 'ok' => false }
    q.ck('permitted and clean', p.compose_from(true, okp), { 'allow' => true, 'decidedBy' => 'none', 'permitted' => true, 'prohibition' => okp })
    q.ck('not permitted', p.compose_from(false, okp), { 'allow' => false, 'decidedBy' => 'permission', 'permitted' => false, 'prohibition' => okp })
    q.ck('vetoed', p.compose_from(true, nop), { 'allow' => false, 'decidedBy' => 'prohibition', 'permitted' => true, 'prohibition' => nop })
    q.ck('vetoed and not permitted', p.compose_from(false, nop), { 'allow' => false, 'decidedBy' => 'prohibition', 'permitted' => false, 'prohibition' => nop })
    ['yes', 1, nil, 'true', [true]].each { |v| q.ck("permitted #{v.inspect} is not true", p.compose_from(v, okp), { 'allow' => false, 'decidedBy' => 'permission', 'permitted' => false, 'prohibition' => okp }) }
    c = q.con([q::NV])
    r = p.compose_authority(true, q.act('boom'), c, q.st)
    q.ck('authority veto', [r['allow'], r['decidedBy'], r['permitted'], r['prohibition']['violated']], [false, 'prohibition', true, ['nv']])
    r = p.compose_authority(true, q.act('other'), c, q.st)
    q.ck('authority allow', [r['allow'], r['decidedBy'], r['prohibition']], [true, 'none', p.check_prohibitions(q.act('other'), c, q.st)])
    true
  end

  t('zb prohibitions: check_and_advance results') do
    next true unless ZbQ.gate?

    q = ZbQ
    p = q::P
    c = q.con([q::NV])
    a = q.act('other')
    s = q.st
    mon = p.check_prohibitions(a, c, s)
    ev = p.prove_safety(a, c, s)
    ca = ->(perm, ac = a, co = c, st = s, o = {}) { p.check_and_advance(perm, ac, co, st, o) }
    r = ca.call(true)
    q.ck('allow', r, { 'allow' => true, 'decidedBy' => 'none', 'evidence' => ev, 'prohibition' => mon, 'next' => p.advance_state(a, c, s) })
    q.ck('allow advances', r['next']['seq'], 1)
    q.ck('allow with the right head', ca.call(true, a, c, s, { 'expectedSeq' => 0, 'expectedStateDigest' => p.state_digest(s) })['allow'], true)
    q.ck('not permitted', ca.call(false), { 'allow' => false, 'decidedBy' => 'permission', 'evidence' => ev, 'prohibition' => mon, 'next' => s })
    q.ck('not permitted, a non boolean', ca.call('yes')['decidedBy'], 'permission')
    bad_a = q.act('boom')
    bmon = p.check_prohibitions(bad_a, c, s)
    bev = p.prove_safety(bad_a, c, s)
    q.ck('vetoed', ca.call(true, bad_a), { 'allow' => false, 'decidedBy' => 'prohibition', 'evidence' => bev, 'prohibition' => bmon, 'next' => s })
    q.ck('vetoed and not permitted', ca.call(false, bad_a)['decidedBy'], 'prohibition')
    q.ck('vetoed carries no reason', ca.call(true, bad_a).key?('reason'), false)

    stale = { 'allow' => false, 'decidedBy' => 'state', 'evidence' => ev, 'prohibition' => mon, 'next' => s, 'reason' => 'stale state head (seq)' }
    q.ck('stale seq', ca.call(true, a, c, s, { 'expectedSeq' => 1 }), stale)
    q.ck('stale seq, nil head', ca.call(true, a, c, s, { 'expectedSeq' => nil }), stale)
    q.ck('stale seq, a string', ca.call(true, a, c, s, { 'expectedSeq' => '0' }), stale)
    q.ck('stale seq, a malformed state', ca.call(true, a, c, nil, { 'expectedSeq' => 0 })['reason'], 'stale state head (seq)')
    q.ck('stale seq beats a veto', ca.call(true, bad_a, c, s, { 'expectedSeq' => 1 })['decidedBy'], 'state')
    q.ck('stale seq beats a missing permission', ca.call(false, a, c, s, { 'expectedSeq' => 1 })['decidedBy'], 'state')
    q.ck('stale digest', ca.call(true, a, c, s, { 'expectedStateDigest' => 'x' }), stale.merge('reason' => 'stale state head (digest)'))
    q.ck('stale digest, nil head', ca.call(true, a, c, s, { 'expectedStateDigest' => nil })['reason'], 'stale state head (digest)')
    q.ck('stale digest, a malformed state', ca.call(true, a, c, nil, { 'expectedStateDigest' => p.state_digest(s) })['reason'], 'stale state head (digest)')
    q.ck('seq is checked before the digest', ca.call(true, a, c, s, { 'expectedSeq' => 1, 'expectedStateDigest' => 'x' })['reason'], 'stale state head (seq)')

    odd = c.merge('x' => Object.new)
    oev = p.prove_safety(a, odd, s)
    q.ck('evidence not attestable', ca.call(true, a, odd, s), { 'allow' => false, 'decidedBy' => 'prohibition', 'evidence' => oev, 'prohibition' => p.check_prohibitions(a, odd, s), 'next' => s, 'reason' => 'evidence not attestable' })

    keys = q.st('ledger' => (0...1024).to_h { |i| ["k#{i}", [q.entry(q::NOW)]] })
    cc = q.con([q::CAP])
    pa = q.pay(1)
    r = ca.call(true, pa, cc, keys)
    q.ck('advance failed', [r['allow'], r['decidedBy'], r['reason'], r['next'].equal?(keys)], [false, 'state', 'advance failed: resulting state invalid', true])
    q.ck('advance failed carries the evidence', r['evidence'], p.prove_safety(pa, cc, keys))

    q.ck('options that are not a hash fail closed', ca.call(true, a, c, s, nil), { 'allow' => false, 'decidedBy' => 'state', 'evidence' => ev, 'prohibition' => mon, 'next' => s, 'reason' => 'check-and-advance error (fail closed)' })
    q.ck('options that are not a hash fail closed: array', ca.call(true, a, c, s, [])['reason'], 'check-and-advance error (fail closed)')
    true
  end
end
