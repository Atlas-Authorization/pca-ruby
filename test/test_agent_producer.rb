# frozen_string_literal: true

# The agent / issuer side (lib/atlas_pca/agent.rb): replays packages/pca/conformance/producer-vectors.json byte for byte (fixed keys,
# nonces and timestamps; Ed25519 is deterministic) and round-trips everything it produces through this gem's verifiers,
# post-quantum suites included when OpenSSL >= 3.5 is present.
#   ruby -Ilib test/test_agent_producer.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestAgentProducer < Minitest::Test
  FILE = File.expand_path('../conformance/producer-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)
  KEYS = DOC['keys'].transform_values { |k| AtlasPca::KeyPair.from_seed_b64u(k['seed']) }

  def run_op(op, a)
    k = ->(n) { KEYS.fetch(n) }
    case op
    when 'ed25519_sign'
      kp = AtlasPca::KeyPair.from_seed_b64u(a['seed'])
      { 'public' => kp.public, 'sig' => AtlasPca.b64e(kp.sign(a['message_utf8'].b)) }
    when 'goal_commit' then { 'commit' => AtlasPca.goal_commit_of(a['goal'], a['salt']) }
    when 'params_digest' then { 'digest' => AtlasPca.params_digest(a['params']) }
    when 'plan_commit' then AtlasPca.commit_plan(a['nodes'])
    when 'mint_grant'
      AtlasPca.mint_grant(k.(a['principal']), k.(a['holder']).public, a['envelope'], a['goal'], salt: a['salt'])
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
    else flunk("unknown op #{op}")
    end
  end

  def test_vectors
    assert_operator DOC['cases'].length, :>=, 34
    bad = DOC['cases'].reject do |c|
      want = c['expect'].dup
      want.delete('threshold_message') if c['op'] == 'act'
      JSON.parse(JSON.generate(run_op(c['op'], c['args']))) == JSON.parse(JSON.generate(want))
    end.map { |c| c['name'] }
    assert_empty bad
  end

  def new_grant(principal, agent, holder_pq: nil)
    env = { 'predicates' => [{ 'verb' => 'refund', 'resource' => 'orders/*' }], 'caveats' => [], 'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
    AtlasPca.mint_grant(principal, agent.public, env, 'refund an order', holder_pq: holder_pq)['grant']
  end

  def core_ok(pcactn, grant, label)
    v = AtlasPca.verify_pcactn(pcactn, grant, now: pcactn['iat'], audience: 'rs-test')
    assert v.allow, "#{label}: #{v.reason}"
  end

  def test_agent_round_trip_delegate_plan
    principal = AtlasPca::KeyPair.generate
    key = AtlasPca::KeyPair.generate
    grant = new_grant(principal, key)
    agent = AtlasPca::Agent.new(key, grant, 'rs-test')
    a1 = agent.act('refund', 'orders/1', { 'amount_cents' => 500 })
    a2 = agent.act('refund', 'orders/1', { 'amount_cents' => 500 })
    assert_equal [1, 2], [a1.pcactn['counter'], a2.pcactn['counter']]
    refute_equal a1.pcactn['nonce'], a2.pcactn['nonce']
    core_ok(AtlasPca.parse_json(AtlasPca.decode_pca_header(a1.headers['PCA-Action'])), grant, 'header round trip')
    refute AtlasPca.verify_pcactn(a1.pcactn.merge('counter' => 9), grant, now: a1.pcactn['iat'], audience: 'rs-test').allow

    sub = AtlasPca::KeyPair.generate
    child = agent.delegate(sub, [AtlasPca.sealed_caveat])
    ok, why = AtlasPca.verify_chain(child.chain, principal.public, true)
    assert ok, why
    core_ok(child.act('refund', 'orders/2', { 'amount_cents' => 1 }).pcactn, grant, 'sub-agent')

    planned = AtlasPca::Agent.new(key, grant, 'rs-test').use_plan([{ 'id' => 'a', 'verb' => 'read', 'resource' => 'x' },
                                                                    { 'id' => 'b', 'verb' => 'refund', 'resource' => 'orders/1' }])
    core_ok(planned.act('refund', 'orders/1').pcactn, grant, 'plan node')
    assert_raises(ArgumentError) { planned.act('delete', 'everything') }
  end

  def test_escalation_answer_and_passport
    principal = AtlasPca::KeyPair.generate
    key = AtlasPca::KeyPair.generate
    grant = new_grant(principal, key)
    act = AtlasPca::Agent.new(key, grant, 'rs-test').act('refund', 'orders/1').pcactn
    now = act['iat']
    req = { 'policy_digest' => AtlasPca.escalation_policy_digest(grant), 'action_digest' => AtlasPca.escalation_action_digest(act),
            'history_head' => AtlasPca.escalation_history_head(0) }
    ans = AtlasPca.sign_escalation_answer(principal, req, 'allow', now, now + 60_000)
    assert AtlasPca.verify_escalation_answer(ans, [principal.public], req, now)[:ok]
    refute AtlasPca.verify_escalation_answer(ans.merge('decision' => 'deny'), [principal.public], req, now)[:ok]

    issuer = AtlasPca::KeyPair.generate
    pp = AtlasPca.issue_passport({ 'model_id' => 'm', 'operator' => 'acme', 'hardware_rooted' => false, 'issued_at' => 1_800_000_000_000 })
    sp = AtlasPca.sign_passport(pp, issuer, key.public, 1_800_003_600_000)
    assert_nil AtlasPca.verify_passport(sp, [issuer.public], 1_800_000_000_500, revoked: ->(_id, _iss, _sub) { false })
    hw = AtlasPca.issue_passport({ 'model_id' => 'm', 'operator' => 'acme', 'hardware_rooted' => true, 'issued_at' => 1 })
    assert_raises(ArgumentError) { AtlasPca.sign_passport(hw, issuer, key.public, 99) }
  end

  def test_refuses_bad_input
    principal = AtlasPca::KeyPair.generate
    key = AtlasPca::KeyPair.generate
    env = { 'predicates' => [], 'caveats' => [], 'risk_policy' => {} }
    assert_raises(ArgumentError) { AtlasPca.mint_grant(principal, key.public, env, 'g') }
    assert_raises(ArgumentError) { AtlasPca.mint_grant(principal, key.public, env.merge('risk_policy' => AtlasPca::DEFAULT_RISK_POLICY), '') }
    assert_raises(AtlasPca::UnsupportedSigner) { AtlasPca.sign_with_suite('fn-dsa-512', key, nil, 'm') }
  end

  def test_post_quantum_hybrids
    suites = [['hybrid-ed25519-ml-dsa-65', 'ML-DSA-65'], ['hybrid-nested-ed25519-ml-dsa-65', 'ML-DSA-65'], ['ml-dsa-87', 'ML-DSA-87'],
              ['hybrid-ed25519-slh-dsa-sha2-128f', 'SLH-DSA-SHA2-128f']]
    suites.each do |alg, prim|
      unless AtlasPca.supported_suites.include?(alg)
        # CI on OpenSSL >= 3.5 sets PCA_REQUIRE_PQ=1: a missing backend there is a failure, not a skip
        flunk "#{alg}: OpenSSL >= 3.5 is required in CI" if ENV['PCA_REQUIRE_PQ'] == '1'
        assert_raises(AtlasPca::UnsupportedSigner) { AtlasPca::PqKeyPair.generate(prim) }
        next
      end
      pq = AtlasPca::PqKeyPair.generate(prim)
      principal = AtlasPca::KeyPair.generate
      key = AtlasPca::KeyPair.generate
      grant = new_grant(principal, key, holder_pq: pq.public)
      a = AtlasPca::Agent.new(key, grant, 'rs-test', alg: alg, pq: pq).act('refund', 'orders/1')
      assert_equal alg, a.pcactn['alg']
      core_ok(a.pcactn, grant, alg)
      other = AtlasPca::PqKeyPair.generate(prim)
      f = AtlasPca::Agent.new(key, grant, 'rs-test', alg: alg, pq: other).act('refund', 'orders/1')
      refute AtlasPca.verify_pcactn(f.pcactn, grant, now: f.pcactn['iat'], audience: 'rs-test').allow, "#{alg}: uncommitted PQ key verified"
    end
  end
end
