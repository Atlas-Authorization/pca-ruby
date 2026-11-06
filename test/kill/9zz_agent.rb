# frozen_string_literal: true

# Exact-outcome kill tests for lib/atlas_pca/agent.rb (the agent / issuer side): refusal paths and their messages, seeds, suites,
# counters, nonces, header encoding. Every AtlasPca constant is resolved at CALL time (the oracle replaces the module per mutant).
module MutationKill
  module AgentKill
    module_function

    ENV_OK = lambda do
      { 'predicates' => [{ 'verb' => 'v', 'resource' => 'r' }], 'caveats' => [], 'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
    end

    def raises?(klass, msg)
      yield
      false
    rescue klass => e
      e.message == msg
    end

    def kp = AtlasPca::KeyPair.generate
    def rp(over) = AtlasPca::DEFAULT_RISK_POLICY.merge(over)
  end

  t('agent: seeds') do
    a = AgentKill
    seed = ("\x01" * 32).b
    k = AtlasPca::KeyPair.new(seed)
    [0, 31, 33].all? { |n| a.raises?(ArgumentError, 'an Ed25519 seed is 32 bytes') { AtlasPca::KeyPair.new(('x' * n).b) } } &&
      a.raises?(ArgumentError, 'an Ed25519 seed is 32 bytes') { AtlasPca::KeyPair.new(nil) } &&
      AtlasPca::KeyPair.from_seed_b64u(AtlasPca.b64e(seed)).public == k.public &&
      a.raises?(ArgumentError, 'an Ed25519 seed is 32 canonical base64url bytes') { AtlasPca::KeyPair.from_seed_b64u('AAAA') } &&
      k.sign('m').bytesize == 64 && !k.inspect.include?(AtlasPca.b64e(seed)) && AtlasPca.b64d(k.public, 32)
  end

  t('agent: suites') do
    a = AgentKill
    k = a.kp
    r = %w[fn-dsa-512 fn-dsa-1024 less-cat1 hybrid-ed25519-less-cat1].all? do |alg|
      a.raises?(AtlasPca::UnsupportedSigner, "unsupported_suite: #{alg}") { AtlasPca.sign_with_suite(alg, k, nil, 'm') }
    end
    r && a.raises?(ArgumentError, 'unknown signature alg "rot13"') { AtlasPca.sign_with_suite('rot13', k, nil, 'm') } &&
      a.raises?(ArgumentError, 'ed25519 needs an Ed25519 key') { AtlasPca.sign_with_suite(nil, nil, nil, 'm') } &&
      a.raises?(ArgumentError, 'ml-dsa-65 needs a ML-DSA-65 key pair') { AtlasPca.sign_with_suite('ml-dsa-65', k, nil, 'm') } &&
      a.raises?(ArgumentError, 'ml-dsa-65 needs a post-quantum key pair') { AtlasPca.sign_artifact('d', { 'v' => 1 }, k, alg: 'ml-dsa-65') } &&
      AtlasPca.sign_artifact('d', { 'v' => 1 }, k, alg: 'ed25519').keys.sort == %w[sig v]
  end

  t('agent: mint_grant refusals') do
    a = AgentKill
    p = a.kp
    h = a.kp.public
    mg = ->(env, goal = 'g', **kw) { AtlasPca.mint_grant(p, h, env, goal, **kw) }
    e = AgentKill::ENV_OK.call
    r = a.raises?(ArgumentError, 'mint_grant: goal required') { mg.call(e, '') } &&
        a.raises?(ArgumentError, 'mint_grant: goal required') { mg.call(e, nil) } &&
        a.raises?(ArgumentError, 'mint_grant: envelope.predicates and envelope.caveats required') { mg.call({ 'risk_policy' => e['risk_policy'] }) } &&
        a.raises?(ArgumentError, 'mint_grant: risk_policy.weights missing') { mg.call(e.merge('risk_policy' => {})) } &&
        a.raises?(ArgumentError, 'mint_grant: risk_policy.weights.alpha must be finite and >= 0') do
          mg.call(e.merge('risk_policy' => a.rp('weights' => AtlasPca::DEFAULT_RISK_POLICY['weights'].merge('alpha' => -1))))
        end &&
        a.raises?(ArgumentError, 'mint_grant: risk_policy.theta1 must be finite') { mg.call(e.merge('risk_policy' => a.rp('theta1' => nil))) } &&
        a.raises?(ArgumentError, 'mint_grant: risk_policy requires 0 <= theta1 <= theta2') { mg.call(e.merge('risk_policy' => a.rp('theta1' => 0.7))) } &&
        a.raises?(ArgumentError, 'mint_grant: risk_policy requires 0 <= theta1 <= theta2') { mg.call(e.merge('risk_policy' => a.rp('theta1' => -0.1))) } &&
        a.raises?(ArgumentError, 'mint_grant: risk_policy.kappa must be > 0') { mg.call(e.merge('risk_policy' => a.rp('kappa' => 0))) } &&
        a.raises?(ArgumentError, 'mint_grant: risk_policy lambda/rho/bMax must be >= 0') { mg.call(e.merge('risk_policy' => a.rp('rho' => -1))) } &&
        a.raises?(ArgumentError, "mint_grant: model_polarity must be 'legacy' when present") { mg.call(e.merge('model_polarity' => 'strict')) }
    g = mg.call(e, salt: 'abc')
    r && g['goal_salt'] == 'abc' && g['goal_commit'] == AtlasPca.goal_commit_of('g', 'abc') &&
      AtlasPca.b64d(mg.call(e)['goal_salt'], 16) && mg.call(e.merge('model_polarity' => 'legacy'))['grant']['caveats'][0]['model_polarity'] == 'legacy' &&
      g['grant']['caveats'][0]['agent_binding'] == {} && g['grant']['caveats'][0]['type'] == 'envelope'
  end

  t('agent: delegation appends only and keeps holder_pq') do
    a = AgentKill
    p = a.kp
    k = a.kp
    grant = AtlasPca.mint_grant(p, k.public, AgentKill::ENV_OK.call, 'g')['grant']
    add = { 'type' => 'budget_alloc', 'limit' => 5 }
    child = AtlasPca.delegate_cap(grant, k, added: [add])
    pq = AtlasPca.mint_grant(p, k.public, AgentKill::ENV_OK.call, 'g', holder_pq: 'PQKEY')['grant']
    child.fetch('caveats') == grant['caveats'] + [add] && child['holder'] == k.public && child['issuer'] == k.public &&
      child['parent'] == AtlasPca.hash_canonical(grant) && !child.key?('holder_pq') &&
      pq['holder_pq'] == AtlasPca.holder_pq_commitment('PQKEY') && AtlasPca.delegate_cap(pq, k)['holder_pq'] == pq['holder_pq'] &&
      !AtlasPca.delegate_cap(pq, k, to_holder: a.kp.public).key?('holder_pq') &&
      AtlasPca.delegate_cap(pq, k, to_holder: a.kp.public, holder_pq: 'OTHER')['holder_pq'] == AtlasPca.holder_pq_commitment('OTHER')
  end

  t('agent: plan, params and freshness refusals') do
    a = AgentKill
    k = a.kp
    grant = AtlasPca.mint_grant(a.kp, k.public, AgentKill::ENV_OK.call, 'g')['grant']
    node = { 'id' => 'a', 'verb' => 'v', 'resource' => 'r' }
    base = { grant: grant, chain: [grant], plan: [node], node_id: 'a', counter: 1, signer: k, aud: 'x' }
    bp = ->(over = {}) { AtlasPca.build_pcactn(**base, **over) }
    p = bp.call(iat: 1000)
    a.raises?(ArgumentError, 'build_pcactn: aud (audience) is required') { bp.call(aud: '') } &&
      a.raises?(ArgumentError, 'build_pcactn: unknown plan node zz') { bp.call(node_id: 'zz') } &&
      a.raises?(ArgumentError, "build_pcactn: params do not match plan node a's params_digest") do
        bp.call(plan: [node.merge('params_digest' => AtlasPca.params_digest({ 'x' => 1 }))], params: { 'x' => 2 })
      end &&
      a.raises?(ArgumentError, 'commit_plan: duplicate node id a') { AtlasPca.commit_plan([node, node]) } &&
      a.raises?(ArgumentError, 'commit_plan: empty plan') { AtlasPca.commit_plan([]) } &&
      [p['iat'], p['exp'], p['ver'], p['counter']] == [1000, 1000 + (20 * 60_000), 2, 1] &&
      p['action']['reversibility_class'] == 'reversible' && bp.call(iat: 1000, exp: 5000)['exp'] == 5000 &&
      bp.call(iat: 1000, ttl_ms: 7)['exp'] == 1007 && bp.call(iat: 1000, extra: { 'nonce' => 'n', 'caution' => nil }).then { |x| x['nonce'] == 'n' && !x.key?('caution') }
  end

  t('agent: counter, nonce, hook and plan misuse') do
    a = AgentKill
    k = a.kp
    grant = AtlasPca.mint_grant(a.kp, k.public, AgentKill::ENV_OK.call, 'g')['grant']
    seen = []
    agent = AtlasPca::Agent.new(k, grant, 'rs', counter: 41, on_counter: ->(n) { seen << n }, clock: -> { 5000 })
    acts = Array.new(3) { agent.act('v', 'r') }
    sub = agent.delegate(a.kp)
    acts.map { |x| x.pcactn['counter'] } == [42, 43, 44] && seen == [42, 43, 44] &&
      acts.map { |x| x.pcactn['nonce'] }.uniq.length == 3 && acts.all? { |x| AtlasPca.b64d(x.pcactn['nonce'], 16) } &&
      acts.all? { |x| [x.pcactn['iat'], x.pcactn['exp'], x.pcactn['aud'], x.node_id] == [5000, 5000 + (20 * 60_000), 'rs', 'n1'] } &&
      sub.act('v', 'r').pcactn['counter'] == 1 && sub.chain.length == 2 && agent.chain.length == 1 &&
      AtlasPca::Agent.new(k, grant, 'rs').act('v', 'r', nil, extra: { 'nonce' => 'fixed' }).pcactn['nonce'] == 'fixed' &&
      a.raises?(ArgumentError, 'act: no node of the committed plan matches v nope') do
        AtlasPca::Agent.new(k, grant, 'rs').use_plan([{ 'id' => 'a', 'verb' => 'v', 'resource' => 'r' }]).act('v', 'nope')
      end
  end

  t('agent: header encoding') do
    a = AgentKill
    k = a.kp
    grant = AtlasPca.mint_grant(a.kp, k.public, AgentKill::ENV_OK.call, 'g')['grant']
    act = AtlasPca::Agent.new(k, grant, 'rs').act('v', 'r')
    h = act.headers['PCA-Action']
    full = AtlasPca.pca_headers(act.pcactn, discharges: [{ 'd' => 1 }], narrow: { 'n' => 2 }, escalation_answer: { 'a' => 3 })
    dec = ->(v) { AtlasPca.b64d(v).dup.force_encoding('UTF-8') }
    act.headers.keys == ['PCA-Action'] && !h.include?('=') && dec.call(h) == AtlasPca.canonicalize(act.pcactn) &&
      AtlasPca.decode_pca_header(h) == AtlasPca.canonicalize(act.pcactn) &&
      full.keys.sort == %w[PCA-Action PCA-Discharges PCA-Escalation-Answer PCA-Narrow] && dec.call(full['PCA-Discharges']) == '[{"d":1}]' &&
      dec.call(full['PCA-Narrow']) == '{"n":2}' && dec.call(full['PCA-Escalation-Answer']) == '{"a":3}' &&
      AtlasPca.pca_headers(act.pcactn, discharges: []).keys == ['PCA-Action']
  end

  t('agent: signer, answer and passport refusals') do
    a = AgentKill
    k = a.kp
    o = a.kp
    r = [[:sign_workflow, 'sign_workflow'], [:sign_read_grant, 'sign_read_grant'], [:sign_aggregate_grant, 'sign_aggregate_grant']].all? do |fn, w|
      a.raises?(ArgumentError, "#{w}: principal is not the signer") { AtlasPca.send(fn, o, { 'principal' => k.public }) }
    end
    pp = AtlasPca.issue_passport({ 'model_id' => 'm', 'operator' => 'o', 'hardware_rooted' => false, 'issued_at' => 10 })
    hw = AtlasPca.issue_passport({ 'model_id' => 'm', 'operator' => 'o', 'hardware_rooted' => true, 'issued_at' => 10 })
    sp = AtlasPca.sign_passport(pp, o, k.public, 99)
    r && a.raises?(ArgumentError, "decision must be 'allow' or 'deny'") do
      AtlasPca.sign_escalation_answer(o, { 'policy_digest' => 'a', 'action_digest' => 'b', 'history_head' => 'c' }, 'maybe', 1, 2)
    end &&
      a.raises?(ArgumentError, 'sign_passport: exp must be after nbf') { AtlasPca.sign_passport(pp, o, k.public, 10) } &&
      a.raises?(ArgumentError, 'sign_passport: passport.id is not the fingerprint of its identity (use issue_passport)') do
        AtlasPca.sign_passport(pp.merge('model_id' => 'other'), o, k.public, 99)
      end &&
      a.raises?(ArgumentError, 'sign_passport: hardware_rooted requires attestation evidence (fail closed)') { AtlasPca.sign_passport(hw, o, k.public, 99) } &&
      [sp['iat'], sp['nbf'], sp['exp']] == [10, 10, 99] && AtlasPca.sign_passport(pp, o, k.public, 99, iat: 20, nbf: 30)['nbf'] == 30
  end
end
