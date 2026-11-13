# frozen_string_literal: true
# The agent / issuer side against packages/pca/conformance/producer-vectors.json, byte for byte (fixed keys, nonces and timestamps;
# Ed25519 is deterministic), plus the round trips of test/test_agent_producer.rb: every artifact the agent produces must verify.
# Only test_agent_producer.rb replayed these, outside the mutation oracle (agent.rb: ~440 survivors of 900 in run 41710479412).
# Every AtlasPca constant and key is resolved at CALL time (the oracle replaces the module per mutant).
require 'json'
require_relative '../support/producer_ops'
module MutationKill
  module AgentProducer
    module_function

    CONF = File.expand_path('../../conformance', __dir__)
    def doc = (@doc ||= AtlasPca.parse_json(File.read(File.join(CONF, 'producer-vectors.json'), encoding: 'UTF-8'), loose: true))
    def norm(x) = JSON.parse(JSON.generate(x))

    def pq_doc = (@pq_doc ||= AtlasPca.parse_json(File.read(File.join(CONF, 'producer-pq-vectors.json'), encoding: 'UTF-8'), loose: true))

    def new_grant(principal, agent, holder_pq: nil)
      env = { 'predicates' => [{ 'verb' => 'refund', 'resource' => 'orders/*' }], 'caveats' => [], 'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
      AtlasPca.mint_grant(principal, agent.public, env, 'refund an order', holder_pq: holder_pq)['grant']
    end

    def core_ok?(pcactn, grant) = AtlasPca.verify_pcactn(pcactn, grant, now: pcactn['iat'], audience: 'rs-test', insecure_skip_plan_root_check: true).allow == true

    def raises?(klass)
      yield
      false
    rescue klass
      true
    end
  end

  t('agent producer vectors: every case byte for byte, refusals with the exact text (producer-vectors.json)') do
    a = AgentProducer
    a.doc['cases'].length >= 89 && ProducerOps.v1_problems(a.doc, ProducerOps.keys_of(a.doc['keys'])).empty?
  end

  # the oracle host has every suite (MUT_REQUIRE_PQ); run_kill.rb skips these on an OpenSSL without them
  t('agent producer: post-quantum vectors byte for byte, FN-DSA refused (producer-pq-vectors.json)', needs: 'slh-dsa-sha2-256s') do
    r = ProducerOps.pq_replay(AgentProducer.pq_doc, true)
    r['problems'].empty? && r['ran'] == AgentProducer.pq_doc['cases'].count { |c| c['exact'].include?('ruby') }
  end

  t('agent producer: native artifacts of every kind and suite verify, a tampered one does not', needs: 'slh-dsa-sha2-256s') do
    a = AgentProducer
    ProducerOps.native_problems(ProducerOps.native_cases(a.doc, ProducerOps.keys_of(a.doc['keys'])), true).empty?
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
