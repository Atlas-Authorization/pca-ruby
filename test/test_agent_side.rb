# frozen_string_literal: true

# The agent side beyond the shared vectors: the facade (create_agent / AgentHandle), the newer signers, and the refusal texts
# of every pre- and post-sign check (each pinned exactly, as the reference words it).
#   ruby -Ilib test/test_agent_side.rb   (also loaded by test/test_agent_producer.rb)
require_relative '../lib/atlas_pca'
require 'json'
require 'minitest/autorun'

class TestAgentSide < Minitest::Test
  NOW = 1_800_000_000_000
  D = 'A' * 43 # canonical base64url of 32 zero bytes

  def refusal(text, klass = ArgumentError, &blk)
    e = assert_raises(klass, &blk)
    assert_equal text, e.message
  end

  def keys = @keys ||= { p: AtlasPca::KeyPair.generate, a: AtlasPca::KeyPair.generate }

  def env(extra = {})
    { 'predicates' => [{ 'verb' => 'refund', 'resource' => 'orders/*' }], 'caveats' => [],
      'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }.merge(extra)
  end

  # ---- facade --------------------------------------------------------------------------------------------------------------

  def test_parse_limit
    assert_equal({ 'amount' => 500, 'unit' => 'usd', 'periodMs' => 86_400_000 }, AtlasPca.parse_limit('$500/day'))
    assert_equal({ 'amount' => 10, 'unit' => 'count' }, AtlasPca.parse_limit('10'))
    assert_equal({ 'amount' => 1.5, 'unit' => 'usd', 'periodMs' => 3_600_000 }, AtlasPca.parse_limit(" $1.5 / H "))
    refusal('parseLimit: empty limit') { AtlasPca.parse_limit(nil) }
    refusal('parseLimit: empty limit') { AtlasPca.parse_limit(" 　") }
    refusal("parseLimit: cannot parse limit '-5'") { AtlasPca.parse_limit('-5') }
    refusal("parseLimit: cannot parse limit '5/'") { AtlasPca.parse_limit('5/') }
    refusal("parseLimit: unknown period 'yr' in '5/yr'") { AtlasPca.parse_limit('5/yr') }
    assert_equal({ 'amount' => 10, 'unit' => 'count' }, AtlasPca.parse_limit("#{' ' * 62}10")) # 64 UTF-16 units is accepted
    refusal('parseLimit: limit is longer than 64 characters') { AtlasPca.parse_limit("#{"\u{1F4B0}" * 32}1") }
  end

  def test_compile_policy_refusals
    refusal('compilePolicy: permissions must be an object') { AtlasPca.compile_policy([]) }
    refusal('compilePolicy: permissions must be an object') { AtlasPca.compile_policy(nil) }
    refusal('compilePolicy: permissions.stripe must be an array') { AtlasPca.compile_policy({ 'stripe' => 'refund' }) }
    refusal('compilePolicy: no permissions granted') { AtlasPca.compile_policy({ 'stripe' => [] }) }
    refusal('compilePolicy: derived risk policy invalid: risk_policy.kappa must be > 0') do
      AtlasPca.compile_policy({ 'stripe' => ['refund'] }, nil, risk_policy: { 'kappa' => 0 })
    end
  end

  def test_compile_policy_dollars
    p = AtlasPca.compile_policy({ 'stripe' => %w[refund charge] }, { 'refund' => '$500/day', 'charge' => '$200' }, now: NOW)
    rp = p['riskPolicy']
    assert_equal [1, 500, 700], [rp['weights']['gamma'], rp['kappa'], rp['bMax']]
    assert_equal 'dollars', p['budgetModel']
    assert_equal %w[stripe.charge stripe.refund], p['predicates'].map { |x| x['verb'] }.sort
  end

  def handle(**kw)
    AtlasPca.create_agent(principal: keys[:p], goal: 'refund order 1', permissions: { 'stripe' => ['refund'] },
                          limits: { 'refund' => '$500/day' }, holder: keys[:a], aud: 'rs-side', now: NOW, **kw)
  end

  def test_facade_act_verifies
    h = handle
    assert_equal keys[:p].public, h.principal_public
    out = h.act('stripe.refund', 'charge:ch_1', { 'amount' => 42 }, now: NOW)
    pc = out['pcactn']
    v = AtlasPca.verify_pcactn(pc, h.grant, now: NOW, audience: 'rs-side', insecure_skip_plan_root_check: true)
    assert v.allow, v.reason
    assert_equal ['n0', 1, 'rs-side'], [pc['plan']['node_id'], pc['counter'], pc['aud']]
    refute pc.key?('nonce') # no default nonce, as the reference
    assert_equal AtlasPca.canonicalize(pc), out['encoded']
    assert_equal({ 'allowed' => true, 't' => out['dry_run']['t'] }, out['dry_run'])
    assert out['headers'].key?('PCA-Provenance')
    assert_equal 2, h.act('stripe.refund', 'charge:ch_2', nil, now: NOW)['pcactn']['counter']
    assert_equal 9, h.act('stripe.refund', 'charge:ch_3', nil, now: NOW, counter: 9)['pcactn']['counter']
    assert_equal 10, h.act('stripe.refund', 'charge:ch_4', nil, now: NOW)['pcactn']['counter']
    assert_equal AtlasPca.canonicalize(h.grant), h.encode_grant
    assert_equal({ 'B' => 500, 'tau' => NOW, 'asOf' => NOW }, h.budget)
  end

  def test_facade_refusals_and_dry_run
    refusal('act: aud (resource-server / instance id) is required (pass aud: here or to create_agent)') do
      AtlasPca.create_agent(principal: keys[:p], goal: 'g', permissions: { 'stripe' => ['refund'] }, holder: keys[:a], now: NOW)
              .act('stripe.refund', 'charge:ch_1')
    end
    h = handle
    denied = h.dry_run('stripe.charge', 'charge:ch_1', nil, now: NOW)
    refute denied['allowed']
    assert_kind_of String, denied['reason']
    sub = h.sub_agent(added_caveats: [{ 'type' => 'budget_alloc', 'limit' => 5 }])
    assert_equal 2, sub.chain.length
    refute_equal h.holder.public, sub.holder.public
    pc = sub.act('stripe.refund', 'charge:ch_9', { 'amount' => 1 }, now: NOW)['pcactn']
    v = AtlasPca.verify_pcactn(pc, sub.grant, now: NOW, audience: 'rs-side', insecure_skip_plan_root_check: true)
    assert v.allow, v.reason
  end

  def test_builtin_catalog_matches_reference
    assert_equal 21, AtlasPca::BUILTIN_ACTIONS.length
    src = File.expand_path('../../../packages/pca/src/catalog-builtin.generated.ts', __dir__)
    skip 'reference sources not present' unless File.exist?(src)

    keys = 'connector|action|verb|reversibility|blastRadius|amountField|description|aliases|traits'
    ref = File.readlines(src, encoding: 'UTF-8').select { |l| l.start_with?('  { connector:') }.map do |l|
      JSON.parse(l.strip.chomp(',').gsub(/(\{ |, )(#{keys}): /o, '\1"\2": '))
    end
    assert_equal ref, AtlasPca::BUILTIN_ACTIONS
  end

  # ---- grant minting and the low-level signers ---------------------------------------------------------------------------

  def test_mint_grant_member_validation
    m = ->(extra) { AtlasPca.mint_grant(keys[:p], keys[:a].public, env(extra), 'g') }
    refusal('mint_grant: units must be an object') { m.({ 'units' => [] }) }
    refusal('mint_grant: tighten must be an array') { m.({ 'tighten' => {} }) }
    refusal('mint_grant: template_ref must be an object') { m.({ 'template_ref' => nil }) } # a present null is present
    refusal('mint_grant: actions must be an object') { m.({ 'actions' => 1 }) }
    refusal('mint_grant: provenance must be an object') { m.({ 'provenance' => 'x' }) }
    refusal("mint_grant: model_polarity must be 'legacy' when present") { m.({ 'model_polarity' => 'new' }) }
    # validator order: risk_policy first, then the members in the reference's order
    refusal('mint_grant: units must be an object') { m.({ 'units' => 1, 'tighten' => 1 }) }
    g = m.({ 'model_polarity' => 'legacy', 'extra' => 1 })['grant']
    assert_equal 'legacy', g['caveats'][0]['model_polarity']
    refute g['caveats'][0].key?('extra')
    assert_equal({}, g['caveats'][0]['agent_binding'])
  end

  def test_body_checks_on_workflow_read_aggregate
    refusal('sign_workflow: malformed workflow') { AtlasPca.sign_workflow(keys[:p], { 'principal' => keys[:p].public }) }
    refusal('sign_read_grant: malformed grant') { AtlasPca.sign_read_grant(keys[:p], { 'principal' => keys[:p].public }) }
    refusal('sign_aggregate_grant: malformed grant') { AtlasPca.sign_aggregate_grant(keys[:p], nil) }
  end

  def test_post_sign_shape_checks
    req = { 'policy_digest' => D, 'action_digest' => D, 'history_head' => 'short' }
    refusal('sign_escalation_answer: history_head must be canonical base64url (32 bytes)') do
      AtlasPca.sign_escalation_answer(keys[:p], req, 'allow', NOW, NOW + 1)
    end
    refusal("decision must be 'allow' or 'deny'") { AtlasPca.sign_escalation_answer(keys[:p], req, 'maybe', NOW, NOW + 1) }
  end

  def test_provenance_header_size_limit
    pc = { 'v' => 1 }
    assert_equal AtlasPca.b64e(AtlasPca.strict_bytes({ 'x' => 'y' })), AtlasPca.pca_headers(pc, provenance: { 'x' => 'y' })['PCA-Provenance']
    big = { 'x' => 'y' * 7000 } # base64url over 8192 characters: sent as a body member, not a header
    refute AtlasPca.pca_headers(pc, provenance: big).key?('PCA-Provenance')
    refute AtlasPca.pca_headers(pc).key?('PCA-Provenance')
  end

  def test_new_signer_refusals
    k = keys[:a]
    refusal('signCaution: holder required') { AtlasPca.sign_caution({ 'action_digest' => D, 'caution' => 0.5 }, k) }
    refusal('signCaution: invalid reason') do
      AtlasPca.sign_caution({ 'action_digest' => D, 'caution' => 0.5, 'holder' => k.public, 'reason' => 'has space' }, k)
    end
    refusal('signCaution: not an object') { AtlasPca.sign_caution(nil, k) }
    refusal('signHeartbeat: body must be an object') { AtlasPca.sign_heartbeat([], k) }
    refusal('signHeartbeat: seq is required') { AtlasPca.sign_heartbeat({ 'cap_id' => 'c' }, k) }
    refusal('signProgressStep: step must be an object') { AtlasPca.sign_progress_step(nil, k) }
    refusal('signProgressStep: step.action_digest is required') { AtlasPca.sign_progress_step({ 'goal_commitment' => D }, k) }
    refusal('signMeshAction: empty chain') { AtlasPca.sign_mesh_action([], {}, k) }
    refusal('shareMessage: t must be 1, 2 or 3') { AtlasPca.share_message('r', 'm', [k.public], 4, nil) }
    refusal('shareMessage: t must be 1, 2 or 3') { AtlasPca.share_message('r', 'm', [k.public], 2.0, nil) }
    refusal("signPreparedShare: unknown signature alg 'rsa'") { AtlasPca.sign_prepared_share('r', k, 'm', alg: 'rsa') }
    refusal('signIntentRequired: not an object') { AtlasPca.sign_intent_required(nil, 'k1', k) }
    refusal("signIntentRequired: unknown member 'x'") { AtlasPca.sign_intent_required({ 'x' => 1 }, 'k1', k) }
    refusal('signRevocationEpoch: instance_id is required') { AtlasPca.sign_revocation_epoch(k, {}) }
  end

  def test_caution_and_pq_binding_round_trip
    k = keys[:a]
    c = AtlasPca.sign_caution({ 'action_digest' => D, 'caution' => 1, 'holder' => k.public, 'reason' => 'ambiguous_instruction', 'x' => 1 }, k)
    refute c.key?('x')
    assert AtlasPca.verify_b64u(k.public, AtlasPca.domain_body_bytes(AtlasPca::CAUTION_DOMAIN, c.reject { |n, _| n == 'sig' }), c['sig'])
    pq_pk = AtlasPca.b64e("\x01".b * 1952) # an ML-DSA-65 public key length
    b = AtlasPca.sign_pq_binding(k, pq_pk, 2, 'rs-side')
    assert_equal({ k.public => pq_pk }, AtlasPca.pq_pin_for(b, 'rs-side'))
    assert_nil AtlasPca.pq_pin_for(b, 'rs-other')
    assert_nil AtlasPca.pq_pin_for(b.merge('epoch' => 3), 'rs-side')
    assert_nil AtlasPca.pq_pin_for(b.merge('pq' => AtlasPca.b64e("\x01".b * 7)), 'rs-side')
  end

  # ---- PQ keys -------------------------------------------------------------------------------------------------------------

  def test_pq_sub_agent_never_reuses_the_parent_key
    skip 'ML-DSA-65 needs OpenSSL >= 3.5' unless AtlasPca.pq_prim_available?('ML-DSA-65') || ENV['PCA_REQUIRE_PQ'] == '1'

    pq = AtlasPca::PqKeyPair.from_seed('ML-DSA-65', "\x05".b * 32)
    grant = AtlasPca.mint_grant(keys[:p], keys[:a].public, env, 'g', holder_pq: pq.public)['grant']
    parent = AtlasPca::Agent.new(keys[:a], grant, 'rs-side', alg: 'ml-dsa-65', pq: pq)
    child = parent.delegate(AtlasPca::KeyPair.generate, [{ 'type' => 'budget_alloc', 'limit' => 2 }])
    grandchild = child.delegate(AtlasPca::KeyPair.generate, [{ 'type' => 'budget_alloc', 'limit' => 1 }])
    pks = [pq, child.pq, grandchild.pq].map(&:public)
    assert_equal pks.uniq, pks
    [child, grandchild].each do |ag|
      assert_equal AtlasPca.holder_pq_commitment(ag.pq.public), ag.chain[-1]['holder_pq']
      pc = ag.act('refund', 'orders/1').pcactn
      assert_equal ag.pq.public, pc['pq_pk']
      v = AtlasPca.verify_pcactn(pc, grant, now: pc['iat'], audience: 'rs-side', insecure_skip_plan_root_check: true)
      assert v.allow, v.reason
    end
  end
end
