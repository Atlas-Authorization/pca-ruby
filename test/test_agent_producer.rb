# frozen_string_literal: true

# The agent / issuer side (lib/atlas_pca/agent.rb, signers_more.rb, facade.rb): replays packages/pca/conformance/producer-vectors.json
# byte for byte (fixed keys, nonces and timestamps; Ed25519 is deterministic) and producer-pq-vectors.json (seeded keys,
# deterministic ML-DSA / SLH-DSA), round-trips everything it produces through this gem's verifiers, and builds this gem's own
# signed artifacts for the reference verifier (written to $PCA_PRODUCER_OUT when it is set).
#   ruby -Ilib test/test_agent_producer.rb
require_relative '../lib/atlas_pca'
require_relative 'support/producer_ops'
require 'json'
require 'minitest/autorun'

class TestAgentProducer < Minitest::Test
  DIR = File.expand_path('../conformance', __dir__)
  DOC = AtlasPca.parse_json(File.read(File.join(DIR, 'producer-vectors.json'), encoding: 'UTF-8'), loose: true)
  KEYS = ProducerOps.keys_of(DOC['keys'])
  PQ_DOC = AtlasPca.parse_json(File.read(File.join(DIR, 'producer-pq-vectors.json'), encoding: 'UTF-8'), loose: true)

  # Every case, refusals included: a refusal must carry the reference's exact text.
  def test_vectors
    assert_operator DOC['cases'].length, :>=, 89
    assert_empty ProducerOps.v1_problems(DOC, KEYS)
  end

  def test_every_vector_op_is_produced
    ops = (DOC['cases'] + PQ_DOC['cases']).map { |c| c['op'] }.uniq
    missing = ops.select do |op|
      ProducerOps.run({ 'op' => op, 'args' => {} }, {})
      false
    rescue ProducerOps::NotProduced
      true
    rescue StandardError
      false
    end
    assert_empty missing
    assert_raises(ProducerOps::NotProduced) { ProducerOps.run({ 'op' => 'no_such_op', 'args' => {} }, {}) }
  end

  # Every case that lists this gem in `exact` is reproduced byte for byte; a suite this gem does not sign (FN-DSA) is refused
  # with unsupported_suite, never signed differently. CI sets PCA_REQUIRE_PQ=1 on OpenSSL >= 3.5: a missing backend FAILS there.
  def test_post_quantum_vectors
    required = ENV['PCA_REQUIRE_PQ'] == '1'
    r = ProducerOps.pq_replay(PQ_DOC, required)
    assert_empty r['problems']
    assert_operator r['ran'], :>, 0
    assert_operator r['ran'], :>=, PQ_DOC['cases'].count { |c| c['exact'].include?('ruby') } if required
  end

  def new_grant(principal, agent, holder_pq: nil)
    env = { 'predicates' => [{ 'verb' => 'refund', 'resource' => 'orders/*' }], 'caveats' => [], 'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
    AtlasPca.mint_grant(principal, agent.public, env, 'refund an order', holder_pq: holder_pq)['grant']
  end

  def core_ok(pcactn, grant, label)
    v = AtlasPca.verify_pcactn(pcactn, grant, now: pcactn['iat'], audience: 'rs-test', insecure_skip_plan_root_check: true)
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
    refute AtlasPca.verify_pcactn(a1.pcactn.merge('counter' => 9), grant, now: a1.pcactn['iat'], audience: 'rs-test', insecure_skip_plan_root_check: true).allow

    sub = AtlasPca::KeyPair.generate
    child = agent.delegate(sub, [AtlasPca.sealed_caveat])
    why, ok = AtlasPca.verify_chain(child.chain, principal.public, true) # [reason, ok]
    assert_equal [true, ''], [ok, why]
    refute child.chain[-1].key?('holder_pq')
    assert_nil child.pq
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
      agent = AtlasPca::Agent.new(key, grant, 'rs-test', alg: alg, pq: pq)
      a = agent.act('refund', 'orders/1')
      assert_equal alg, a.pcactn['alg']
      core_ok(a.pcactn, grant, alg)
      other = AtlasPca::PqKeyPair.generate(prim)
      f = AtlasPca::Agent.new(key, grant, 'rs-test', alg: alg, pq: other).act('refund', 'orders/1')
      refute AtlasPca.verify_pcactn(f.pcactn, grant, now: f.pcactn['iat'], audience: 'rs-test', insecure_skip_plan_root_check: true).allow, "#{alg}: uncommitted PQ key verified"

      # a PQ sub-agent signs with its OWN PQ key, committed in its hop (never the parent's key)
      child = agent.delegate(AtlasPca::KeyPair.generate, [{ 'type' => 'budget_alloc', 'limit' => 1 }])
      refute_equal pq.public, child.pq.public
      assert_equal prim, child.pq.prim
      assert_equal AtlasPca.holder_pq_commitment(child.pq.public), child.chain[-1]['holder_pq']
      core_ok(child.act('refund', 'orders/2').pcactn, grant, "#{alg} sub-agent")
      given = AtlasPca::PqKeyPair.generate(prim)
      assert_equal given.public, agent.delegate(AtlasPca::KeyPair.generate, to_pq: given).act('refund', 'orders/3').pcactn['pq_pk']
    end
  end

  def test_pq_seeds_are_deterministic
    seeds = { 'ML-DSA-65' => 32, 'ML-DSA-87' => 32, 'SLH-DSA-SHA2-128f' => 48, 'SLH-DSA-SHA2-256s' => 96 }
    assert_equal seeds, AtlasPca::PQ_SEED_BYTES
    seeds.each do |prim, n|
      e = assert_raises(ArgumentError) { AtlasPca::PqKeyPair.from_seed(prim, "\x01".b * (n - 1)) }
      assert_equal "a #{prim} seed is #{n} bytes", e.message
    end
    %w[FN-DSA-512 FN-DSA-1024 LESS-cat1].each do |prim|
      e = assert_raises(AtlasPca::UnsupportedSigner) { AtlasPca::PqKeyPair.from_seed(prim, "\x01".b * 32) }
      assert_equal "unsupported_suite: #{prim}", e.message
    end
    return unless AtlasPca.pq_prim_available?('ML-DSA-65')

    a = AtlasPca::PqKeyPair.from_seed('ML-DSA-65', "\x07".b * 32)
    b = AtlasPca::PqKeyPair.from_seed('ML-DSA-65', "\x07".b * 32)
    assert_equal a.public, b.public
    assert_equal a.sign('m'), b.sign('m')
    refute_equal a.public, AtlasPca::PqKeyPair.from_seed('ML-DSA-65', "\x08".b * 32).public
  end

  # ---- natives -> reference: this gem's signed artifacts for the reference verifier ------------------------------------------

  def test_native_producer_file
    doc = ProducerOps.native_cases(DOC, KEYS)
    assert_empty ProducerOps.native_problems(doc, ENV['PCA_REQUIRE_PQ'] == '1')
    out = ENV.fetch('PCA_PRODUCER_OUT', '')
    File.write(out, JSON.generate(doc)) unless out.empty?
  end
end

require_relative 'test_agent_side'
