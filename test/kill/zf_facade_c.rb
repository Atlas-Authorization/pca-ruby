# frozen_string_literal: true

# zf: the facade's AgentHandle and create_agent (helpers in zf_facade_a.rb). Reference: packages/pca/src/facade.ts makeAgent
# (dryRun, act, subAgent) and agent().

module MutationKill
  t('zf facade dry_run: the action context holds the params ({} when none) and the reversibility class') do
    next true unless ZF.gate?

    h = ZF.handle({ 'predicates' => [{ 'verb' => 'files.read', 'resource' => '*', 'where' => [{ 'field' => 'action.params', 'op' => 'eq', 'value' => {} }] },
                                     { 'verb' => 'files.delete', 'resource' => '*',
                                       'where' => [{ 'field' => 'action.reversibility_class', 'op' => 'eq', 'value' => 'irreversible' }] }] })
    ok = { 'allowed' => true, 't' => 1 }
    ZF.eq('no params, no now', h.dry_run('files.read', 'f'), ok) &&
      ZF.eq('nil params', h.dry_run('files.read', 'f', nil, now: 5), ok) &&
      ZF.eq('class', h.dry_run('files.delete', 'f', nil, now: 5), { 'allowed' => true, 't' => 3 }) &&
      ZF.eq('refused', h.dry_run('gmail.send', 'x', nil, now: 5), { 'allowed' => false, 'reason' => 'no predicate permits gmail.send on x' }) &&
      ZF.eq('no predicates', ZF.handle({ 'predicates' => [] }).dry_run('files.read', 'f', nil, now: 5),
            { 'allowed' => false, 'reason' => 'envelope grants no predicates' })
  end

  t('zf facade dry_run: caveats see now, the blast radius, the delegation depth and an empty action history') do
    next true unless ZF.gate?

    preds = [{ 'verb' => 'files.read', 'resource' => '*' }, { 'verb' => 'files.delete', 'resource' => '*' }]
    ok = { 'allowed' => true, 't' => 1 }
    two = ZF.handle({ 'predicates' => preds, 'caveats' => [{ 'type' => 'expires', 'at' => 0 }, { 'type' => 'not_before', 'at' => 10**15 }] })
    br = ZF.handle({ 'predicates' => preds, 'caveats' => [{ 'type' => 'max_blast_radius', 'max' => 0.5 }] })
    depth = { 'predicates' => preds, 'caveats' => [{ 'type' => 'delegation_depth', 'max' => 0 }] }
    rate = ZF.handle({ 'predicates' => preds, 'caveats' => [{ 'type' => 'rate', 'max' => 1, 'per_secs' => 60 }] })
    ZF.eq('two failed', two.dry_run('files.read', 'f', nil, now: 5), { 'allowed' => false, 'reason' => 'caveat(s) failed: expires, not_before' }) &&
      ZF.eq('blast ok', br.dry_run('files.read', 'f', nil, now: 5), ok) &&
      ZF.eq('blast over', br.dry_run('files.delete', 'f', nil, now: 5), { 'allowed' => false, 'reason' => 'caveat(s) failed: max_blast_radius' }) &&
      ZF.eq('root depth', ZF.handle(depth).dry_run('files.read', 'f', nil, now: 5), ok) &&
      ZF.eq('one hop', ZF.handle(depth, chain: [{}, {}]).dry_run('files.read', 'f', nil, now: 5),
            { 'allowed' => false, 'reason' => 'caveat(s) failed: delegation_depth' }) &&
      ZF.eq('rate, no history', rate.dry_run('files.read', 'f', nil, now: 5), ok)
  end

  t('zf facade dry_run: an explicit now is used, none is the wall clock') do
    next true unless ZF.gate?

    pol = AtlasPca.compile_policy({ 'files' => ['read'] }, { 'read' => '5/day' }, now: 0) # expires at one day after the epoch
    h = ZF.handle(pol)
    ZF.eq('inside the day', h.dry_run('files.read', 'f', nil, now: 1000), { 'allowed' => true, 't' => 1 }) &&
      ZF.eq('wall clock', h.dry_run('files.read', 'f'), { 'allowed' => false, 'reason' => 'caveat(s) failed: expires' })
  end

  t('zf facade create_agent: goal salt, agent binding, budget, autonomy bound, inspect, sub-agent and the tier') do
    next true unless ZF.gate?

    pk, ak = ZF.keys
    salt = 'c2FsdC1mb3ItdGVzdHM'
    h = AtlasPca.create_agent(principal: pk, goal: 'g', permissions: { 'stripe' => %w[refund charge] }, limits: { 'refund' => '$200', 'charge' => '$200' },
                              holder: ak, aud: 'rs', now: ZF::NOW, goal_salt: salt, agent_binding: { 'model' => 'm1' })
    env = h.grant['caveats'][0]
    sub = h.sub_agent
    bare = AtlasPca.create_agent(principal: pk, goal: 'g', permissions: { 'files' => ['read'] }, holder: ak, now: ZF::NOW)
    dr = ->(amount) { h.dry_run('stripe.refund', 'c', { 'amount' => amount }, now: ZF::NOW) }
    ZF.eq('salt', [h.goal_salt, sub.goal_salt], [salt, salt]) &&
      ZF.eq('commit', env['goal_commit'], AtlasPca.goal_commit_of('g', salt)) &&
      ZF.eq('binding', env['agent_binding'], { 'model' => 'm1' }) &&
      ZF.eq('no binding', bare.grant['caveats'][0]['agent_binding'], {}) &&
      (bare.goal_salt.is_a?(String) && !bare.goal_salt.empty? || raise('a generated goal salt is returned')) &&
      ZF.eq('budget', [h.budget, sub.budget], [{ 'B' => 400, 'tau' => ZF::NOW, 'asOf' => ZF::NOW }] * 2) &&
      ZF.eq('autonomy bound', h.autonomy_bound, 400.0) &&
      ZF.eq('inspect', h.inspect, "#<AtlasPca::AgentHandle holder=#{ak.public}>") &&
      ZF.eq('sub', [sub.chain.length, sub.principal_public, sub.policy.equal?(h.policy)], [2, pk.public, true]) &&
      # irreversible grant: theta1 0.25, theta2 0.6; r = amount / kappa (200)
      ZF.eq('tiers', [dr.call(42), dr.call(100), dr.call(190)], [{ 'allowed' => true, 't' => 1 }, { 'allowed' => true, 't' => 2 }, { 'allowed' => true, 't' => 3 }])
  end

  t('zf facade create_agent: no now is the wall clock, no holder a fresh key, no aud refused at act') do
    next true unless ZF.gate?

    pk, = ZF.keys
    t0 = (Time.now.to_f * 1000).to_i
    h = AtlasPca.create_agent(principal: pk, goal: 'g', permissions: { 'files' => ['read'] }, limits: { 'read' => '5/day' })
    t1 = (Time.now.to_f * 1000).to_i
    tau = h.budget['tau']
    at = h.policy['caveats'][1]['at']
    (tau.is_a?(Integer) && tau >= t0 && tau <= t1 || raise("budget tau #{tau.inspect} not in #{t0}..#{t1}")) &&
      ZF.eq('expires', at, tau + ZF::DAY) &&
      (h.holder.is_a?(AtlasPca::KeyPair) && h.holder.public != pk.public || raise('a fresh holder key is generated')) &&
      ZF.eq('grant holder', h.grant['holder'], h.holder.public) &&
      ZF.refuses('no aud', 'act: aud (resource-server / instance id) is required (pass aud: here or to create_agent)') { h.act('files.read', 'f') }
  end

  t('zf facade act: per-call aud, ttl, nonce and caution; the defaults; an empty aud is refused') do
    next true unless ZF.gate?

    pk, ak = ZF.keys
    h = AtlasPca.create_agent(principal: pk, goal: 'g', permissions: { 'stripe' => ['refund'] }, holder: ak, aud: 'rs', now: ZF::NOW)
    pc = h.act('stripe.refund', 'c', { 'amount' => 1 }, now: ZF::NOW, aud: 'other', ttl_ms: 5000, caution: 0.25, nonce: 'n1')['pcactn']
    out = h.act('stripe.refund', 'c', { 'amount' => 1 })
    dflt = out['pcactn']
    ZF.eq('options', [pc['aud'], pc['iat'], pc['exp'], pc['caution'], pc['nonce'], pc['counter']], ['other', ZF::NOW, ZF::NOW + 5000, 0.25, 'n1', 1]) &&
      ZF.eq('defaults', [dflt['aud'], dflt['exp'] - dflt['iat'], dflt.key?('nonce'), dflt.key?('caution'), dflt['counter']],
            ['rs', AtlasPca::DEFAULT_TTL_MS, false, false, 2]) &&
      (dflt['iat'].is_a?(Integer) && (dflt['iat'] - AtlasPca.now_ms).abs < 600_000 || raise("iat #{dflt['iat'].inspect} is not the wall clock")) &&
      ZF.eq('dry run on the wall clock', out['dry_run'], { 'allowed' => true, 't' => 3 }) &&
      # no params: the action and its plan node commit the digest of {}
      ZF.eq('no params', h.act('stripe.refund', 'c', now: ZF::NOW)['pcactn']['action']['params_digest'], AtlasPca.params_digest(nil)) &&
      ZF.refuses('empty aud', 'act: aud (resource-server / instance id) is required (pass aud: here or to create_agent)') {
        h.act('stripe.refund', 'c', nil, aud: '')
      }
  end

  t('zf facade act: a handle without a provenance recorder sends no provenance') do
    next true unless ZF.gate?

    pk, ak = ZF.keys
    h = AtlasPca.create_agent(principal: pk, goal: 'g', permissions: { 'stripe' => ['refund'] }, holder: ak, aud: 'rs', now: ZF::NOW)
    bare = AtlasPca::AgentHandle.new(grant: h.grant, chain: h.chain, goal_salt: h.goal_salt, policy: h.policy, holder: ak, principal_public: pk.public,
                                     catalog: AtlasPca.facade_catalog(nil), aud: 'rs', start_now: ZF::NOW, provenance: nil)
    out = bare.act('stripe.refund', 'c', { 'amount' => 1 }, now: ZF::NOW)
    with = h.act('stripe.refund', 'c', { 'amount' => 1 }, now: ZF::NOW)
    ZF.eq('none', [out['provenance'], out['headers'].key?(AtlasPca::PROV_HEADER), out['headers'].key?('PCA-Action')], [nil, false, true]) &&
      ZF.eq('with recorder', [with['provenance'].is_a?(Hash), with['headers'].key?(AtlasPca::PROV_HEADER)], [true, true])
  end
end
