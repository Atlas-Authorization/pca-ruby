# frozen_string_literal: true
# The agent / issuer side against packages/pca/conformance/producer-vectors.json, byte for byte (fixed keys, nonces and timestamps;
# Ed25519 is deterministic), plus the round trips of test/test_agent_producer.rb: every artifact the agent produces must verify.
# Only test_agent_producer.rb replayed these, outside the mutation oracle (agent.rb: ~440 survivors of 900 in run 41710479412).
# Every AtlasPca constant and key is resolved at CALL time (the oracle replaces the module per mutant).
module MutationKill
  module AgentProducer
    module_function

    CONF = File.expand_path('../../conformance', __dir__)
    def doc = (@doc ||= AtlasPca.parse_json(File.read(File.join(CONF, 'producer-vectors.json'), encoding: 'UTF-8'), loose: true))
    def norm(x) = JSON.parse(JSON.generate(x))

    def run_op(op, a, keys)
      k = ->(n) { keys.fetch(n) }
      case op
      when 'ed25519_sign'
        kp = AtlasPca::KeyPair.from_seed_b64u(a['seed'])
        { 'public' => kp.public, 'sig' => AtlasPca.b64e(kp.sign(a['message_utf8'].b)) }
      when 'goal_commit' then { 'commit' => AtlasPca.goal_commit_of(a['goal'], a['salt']) }
      when 'params_digest' then { 'digest' => AtlasPca.params_digest(a['params']) }
      when 'plan_commit' then AtlasPca.commit_plan(a['nodes'])
      when 'mint_grant' then AtlasPca.mint_grant(k.(a['principal']), k.(a['holder']).public, a['envelope'], a['goal'], salt: a['salt'])
      when 'delegate'
        AtlasPca.delegate_cap(a['parent'], k.(a['signer']), to_holder: a['to_holder'] && k.(a['to_holder']).public, added: a['added_caveats'])
      when 'act'
        extra = %w[nonce caution rationale_commitment tool_binding fresh_at].to_h { |n| [n, a[n]] }
        p = AtlasPca.build_pcactn(grant: a['grant'], chain: a['chain'], plan: a['plan'], node_id: a['node_id'], counter: a['counter'],
                                  signer: k.(a['signer']), aud: a['aud'], params: a['params'], iat: a['iat'], exp: a['exp'], extra: extra)
        { 'pcactn' => p, 'header' => AtlasPca.pca_headers(p)['PCA-Action'] }
      when 'fresh_at' then AtlasPca.sign_fresh_at(k.(a['signer']), a['scope'], a['state'], a['issued_at'])
      when 'escalation_digests'
        { 'policy_digest' => AtlasPca.escalation_policy_digest(a['grant']), 'action_digest' => AtlasPca.escalation_action_digest(a['pcactn']),
          'history_head' => AtlasPca.escalation_history_head(a['last_counter']) }
      when 'sign_escalation_answer'
        b = a['body']
        AtlasPca.sign_escalation_answer(k.(a['signer']), b, b['decision'], b['iat'], b['expires_at'], nonce: b['nonce'])
      when 'sign_discharge'
        b = a['body']
        AtlasPca.sign_discharge(k.(a['signer']), b['caveat_id'], b['issuer'], b['cap_hash'], b['claims'], b['iat'], b['not_after'],
                                bind: b['bind'], action_digest: b['action_digest'], nonce: b['nonce'])
      when 'discharge_digest' then { 'digest' => AtlasPca.discharge_digest(a['discharge']) }
      when 'sign_narrow'
        b = a['body']
        AtlasPca.sign_narrow(k.(a['signer']), b['cap_hash'], b['caveats'], b['iat'], b['not_after'], action_digest: b['action_digest'], nonce: b['nonce'])
      when 'sign_passport'
        pp = AtlasPca.issue_passport(a['identity'])
        { 'passport' => pp, 'signed' => AtlasPca.sign_passport(pp, k.(a['issuer']), k.(a['subject']).public, a['exp']) }
      when 'sign_workflow' then AtlasPca.sign_workflow(k.(a['signer']), a['body'])
      when 'sign_step_receipt'
        AtlasPca.sign_step_receipt(k.(a['signer']), a['workflow'], a['step'], a['outcome'], a['params_digest'], a['outputs'], a['issued_at'], prev: a['prev'])
      when 'sign_read_grant' then AtlasPca.sign_read_grant(k.(a['signer']), a['body'])
      when 'sign_aggregate_grant' then AtlasPca.sign_aggregate_grant(k.(a['signer']), a['body'])
      else raise "unknown producer op #{op}"
      end
    end

    def new_grant(principal, agent, holder_pq: nil)
      env = { 'predicates' => [{ 'verb' => 'refund', 'resource' => 'orders/*' }], 'caveats' => [], 'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
      AtlasPca.mint_grant(principal, agent.public, env, 'refund an order', holder_pq: holder_pq)['grant']
    end

    def core_ok?(pcactn, grant) = AtlasPca.verify_pcactn(pcactn, grant, now: pcactn['iat'], audience: 'rs-test').allow == true

    def raises?(klass)
      yield
      false
    rescue klass
      true
    end
  end

  t('agent producer vectors: every case byte for byte (producer-vectors.json)') do
    a = AgentProducer
    keys = a.doc['keys'].transform_values { |k| AtlasPca::KeyPair.from_seed_b64u(k['seed']) }
    a.doc['cases'].length >= 34 && a.doc['cases'].all? do |c|
      want = c['expect'].dup
      want.delete('threshold_message') if c['op'] == 'act'
      a.norm(a.run_op(c['op'], c['args'], keys)) == a.norm(want)
    end
  end

  t('agent producer: act counters, nonces, header round trip, delegation and plan nodes verify') do
    a = AgentProducer
    principal = AtlasPca::KeyPair.generate
    key = AtlasPca::KeyPair.generate
    grant = a.new_grant(principal, key)
    agent = AtlasPca::Agent.new(key, grant, 'rs-test')
    a1 = agent.act('refund', 'orders/1', { 'amount_cents' => 500 })
    a2 = agent.act('refund', 'orders/1', { 'amount_cents' => 500 })
    sub = AtlasPca::KeyPair.generate
    child = agent.delegate(sub, [AtlasPca.sealed_caveat])
    why, ok = AtlasPca.verify_chain(child.chain, principal.public, true) # [reason, ok]: ['', true] when valid
    planned = AtlasPca::Agent.new(key, grant, 'rs-test').use_plan([{ 'id' => 'a', 'verb' => 'read', 'resource' => 'x' },
                                                                    { 'id' => 'b', 'verb' => 'refund', 'resource' => 'orders/1' }])
    [a1.pcactn['counter'], a2.pcactn['counter']] == [1, 2] && a1.pcactn['nonce'] != a2.pcactn['nonce'] &&
      a.core_ok?(a1.pcactn, grant) && a.core_ok?(a2.pcactn, grant) &&
      a.core_ok?(AtlasPca.parse_json(AtlasPca.decode_pca_header(a1.headers['PCA-Action'])), grant) &&
      !a.core_ok?(a1.pcactn.merge('counter' => 9), grant) &&
      ok == true && why == '' && a.core_ok?(child.act('refund', 'orders/2', { 'amount_cents' => 1 }).pcactn, grant) &&
      a.core_ok?(planned.act('refund', 'orders/1').pcactn, grant) &&
      a.raises?(ArgumentError) { planned.act('delete', 'everything') }
  end

  t('agent producer: escalation answer and passport round trips') do
    a = AgentProducer
    principal = AtlasPca::KeyPair.generate
    key = AtlasPca::KeyPair.generate
    grant = a.new_grant(principal, key)
    act = AtlasPca::Agent.new(key, grant, 'rs-test').act('refund', 'orders/1').pcactn
    now = act['iat']
    req = { 'policy_digest' => AtlasPca.escalation_policy_digest(grant), 'action_digest' => AtlasPca.escalation_action_digest(act),
            'history_head' => AtlasPca.escalation_history_head(0) }
    ans = AtlasPca.sign_escalation_answer(principal, req, 'allow', now, now + 60_000)
    issuer = AtlasPca::KeyPair.generate
    pp = AtlasPca.issue_passport({ 'model_id' => 'm', 'operator' => 'acme', 'hardware_rooted' => false, 'issued_at' => 1_800_000_000_000 })
    sp = AtlasPca.sign_passport(pp, issuer, key.public, 1_800_003_600_000)
    hw = AtlasPca.issue_passport({ 'model_id' => 'm', 'operator' => 'acme', 'hardware_rooted' => true, 'issued_at' => 1 })
    AtlasPca.verify_escalation_answer(ans, [principal.public], req, now)[:ok] == true &&
      !AtlasPca.verify_escalation_answer(ans.merge('decision' => 'deny'), [principal.public], req, now)[:ok] &&
      AtlasPca.verify_passport(sp, [issuer.public], 1_800_000_000_500, revoked: ->(_id, _iss, _sub) { false }).nil? &&
      a.raises?(ArgumentError) { AtlasPca.sign_passport(hw, issuer, key.public, 99) }
  end

  # the oracle host has every suite (MUT_REQUIRE_PQ); run_kill.rb skips this on an OpenSSL without ML-DSA
  t('agent producer: post-quantum hybrids sign verifiable actions and an uncommitted PQ key is refused', needs: 'hybrid-ed25519-slh-dsa-sha2-128f') do
    a = AgentProducer
    [['hybrid-ed25519-ml-dsa-65', 'ML-DSA-65'], ['hybrid-nested-ed25519-ml-dsa-65', 'ML-DSA-65'], ['ml-dsa-87', 'ML-DSA-87'],
     ['hybrid-ed25519-slh-dsa-sha2-128f', 'SLH-DSA-SHA2-128f']].all? do |alg, prim|
      pq = AtlasPca::PqKeyPair.generate(prim)
      principal = AtlasPca::KeyPair.generate
      key = AtlasPca::KeyPair.generate
      grant = a.new_grant(principal, key, holder_pq: pq.public)
      s = AtlasPca::Agent.new(key, grant, 'rs-test', alg: alg, pq: pq).act('refund', 'orders/1').pcactn
      f = AtlasPca::Agent.new(key, grant, 'rs-test', alg: alg, pq: AtlasPca::PqKeyPair.generate(prim)).act('refund', 'orders/1').pcactn
      s['alg'] == alg && a.core_ok?(s, grant) && !a.core_ok?(f, grant)
    end
  end
end
