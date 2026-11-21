# frozen_string_literal: true

# The attestation and zk verifier hooks of the core verifier and of authorize (the reference's hooks.attestation / hooks.zk):
# a carried zk_compliance proof is verified by the zk hook and refused when no hook enforced it; an attestation hook reports
# the `attestation` check; a grant that binds the agent passes only with an enforced, passing attestation. Without hooks
# nothing changes: no proof, no check; a proof, a refusal.
#   ruby -Ilib -Itest test/test_verifier_hooks.rb
require_relative '../lib/atlas_pca/rack_middleware'
require_relative 'support/prov_harness'
require 'minitest/autorun'
require 'json'
require 'stringio'

class TestVerifierHooks < Minitest::Test
  A = AtlasPca
  Z = AtlasPca::Zk
  AUD = 'rs-hooks'
  OP = { verb: 'refund', resource: 'orders/1', params: {} }.freeze
  NO_VERIFIER = 'zk_compliance: PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof'
  BOUND = 'attestation: the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED'
  PASS = ->(_ctx) { { 'enforced' => true, 'ok' => true } }
  IDLE = ->(_ctx) { { 'enforced' => false } }

  # [agent, grant] under a fresh principal; `binding` is the grant's agent_binding
  def party(binding = nil)
    principal = A::KeyPair.generate
    key = A::KeyPair.generate
    env = { 'predicates' => [{ 'verb' => 'refund', 'resource' => 'orders/*' }], 'caveats' => [], 'risk_policy' => A::DEFAULT_RISK_POLICY }
    env['agent_binding'] = binding unless binding.nil?
    grant = A.mint_grant(principal, key.public, env, 'g')['grant']
    [A::Agent.new(key, grant, AUD), grant]
  end

  # an attested-VM statement for the action `pcactn` takes, signed by `prover`
  def statement(prover, pcactn, grant)
    body = { 'v' => 1, 'mode' => 'attested-vm', 'action_commit' => Z.action_commitment(pcactn), 'policy_commit' => Z.policy_commitment(grant),
             'plan_commit' => Z.plan_commit(pcactn), 'released' => true, 'r' => 0, 'issued_at' => pcactn['iat'] - 1000,
             'expires_at' => pcactn['iat'] + 60_000, 'prover' => prover.public }
    body.merge('sig' => A.b64e(prover.sign(Z.statement_message(body))))
  end

  # [PCActn carrying a signed statement (inside the leaf signature), grant, prover key]
  def proven
    @proven ||= begin
      agent, grant = party
      prover = A::KeyPair.generate
      plain = agent.act('refund', 'orders/1').pcactn
      [agent.act('refund', 'orders/1', extra: { 'zk_compliance' => statement(prover, plain, grant) }).pcactn, grant, prover, plain]
    end
  end

  def core(pcactn, grant, **hooks)
    A.verify_pcactn(pcactn, grant, now: pcactn['iat'], audience: AUD, insecure_skip_plan_root_check: true, **hooks)
  end

  def zk_hook(pcactn, trusted) = Z.create_zk_verifier(trusted_prover_keys: trusted, now: -> { pcactn['iat'] })

  def authorize(pcactn, grant, **hooks)
    A.authorize(pcactn, operation: OP, audience: AUD, resolve_grant: ->(_) { grant }, state_store: A::MemoryStateStore.new,
                        is_revoked: ->(_p, _g) { false }, now: pcactn['iat'], plan: 'single-step', provenance: ProvHarness::OPTION,
                        risk: ProvHarness::RISK, **hooks)
  end

  def failed(r) = r.checks.select { |_, s| s == 'fail' }.keys.sort

  # ---- the core verifier ----

  def test_core_refuses_a_carried_proof_without_a_zk_hook
    pc, grant, _prover, plain = proven
    assert core(plain, grant).allow, 'the same action without a proof passes'
    v = core(pc, grant)
    refute v.allow
    assert_equal false, v.checks['zk_compliance']
    assert_equal NO_VERIFIER, v.reason
    assert_equal v.checks.reject { |k, _| k == 'zk_compliance' }, core(plain, grant).checks, 'every other check is as without the proof'
  end

  def test_core_verifies_a_carried_proof_with_the_zk_hook
    pc, grant, prover = proven
    seen = []
    hook = zk_hook(pc, [prover.public])
    v = core(pc, grant, zk_hook: lambda { |ctx|
      seen << ctx
      hook.call(ctx)
    })
    assert v.allow, v.reason
    assert_equal true, v.checks['zk_compliance']
    assert_equal [{ 'pcactn' => pc, 'grant' => grant, 'nowEpoch' => pc['iat'] }], seen
  end

  def test_core_denies_with_the_reason_of_the_zk_hook
    pc, grant, = proven
    v = core(pc, grant, zk_hook: zk_hook(pc, [A::KeyPair.generate.public]))
    refute v.allow
    assert_equal false, v.checks['zk_compliance']
    assert_equal 'zk_compliance: prover key is not trusted', v.reason
    v = core(pc, grant, zk_hook: ->(_ctx) { { 'enforced' => true, 'ok' => false } })
    assert_equal 'zk_compliance: rejected', v.reason
  end

  def test_core_refuses_a_proof_the_zk_hook_did_not_enforce
    pc, grant, = proven
    [IDLE, ->(_ctx) {}, ->(_ctx) { { 'ok' => true } }].each do |hook|
      v = core(pc, grant, zk_hook: hook)
      refute v.allow
      assert_equal [false, NO_VERIFIER], [v.checks['zk_compliance'], v.reason]
    end
  end

  def test_core_does_not_run_the_zk_hook_without_a_proof
    _pc, grant, _prover, plain = proven
    v = core(plain, grant, zk_hook: ->(_ctx) { flunk 'no proof is carried' })
    assert v.allow, v.reason
    refute v.checks.key?('zk_compliance')
  end

  def test_core_attestation_hook_is_tri_state
    _pc, grant, _prover, plain = proven
    refute core(plain, grant).checks.key?('attestation')
    v = core(plain, grant, attestation_hook: PASS)
    assert v.allow, v.reason
    assert_equal true, v.checks['attestation']
    v = core(plain, grant, attestation_hook: ->(_ctx) { { 'enforced' => true, 'ok' => false, 'reason' => 'quote is stale' } })
    refute v.allow
    assert_equal [false, 'attestation: quote is stale'], [v.checks['attestation'], v.reason]
    v = core(plain, grant, attestation_hook: IDLE)
    assert v.allow, v.reason
    refute v.checks.key?('attestation')
  end

  def test_core_hooks_run_together_and_the_first_refusal_is_the_reason
    pc, grant, prover = proven
    v = core(pc, grant, attestation_hook: PASS, threshold_hook: PASS, zk_hook: zk_hook(pc, [prover.public]))
    assert v.allow, v.reason
    assert_equal [true, true, true], v.checks.values_at('attestation', 'threshold', 'zk_compliance')
    v = core(pc, grant, attestation_hook: ->(_ctx) { { 'enforced' => true, 'ok' => false, 'reason' => 'a' } }, zk_hook: zk_hook(pc, []))
    assert_equal [false, false, 'attestation: a'], [v.checks['attestation'], v.checks['zk_compliance'], v.reason]
  end

  # ---- authorize ----

  def test_authorize_decides_a_carried_proof_by_the_zk_hook
    pc, grant, prover, plain = proven
    base = authorize(plain, grant)
    refute_includes failed(base), 'zk_compliance'
    none = authorize(pc, grant)
    refute none.allow
    assert_equal 'fail', none.checks['zk_compliance']
    assert_includes none.reasons, NO_VERIFIER
    assert_includes failed(none), 'zk_compliance'

    hook = zk_hook(pc, [prover.public])
    ok = authorize(pc, grant, zk: hook)
    assert_equal 'pass', ok.checks['zk_compliance']
    assert_equal [base.allow, failed(base)], [ok.allow, failed(ok)], 'the verified proof changes nothing else'
    assert_equal %w[pass attested_vm], ok.assurance['zk_compliance'].values_at('outcome', 'level')

    bad = authorize(pc, grant, zk: zk_hook(pc, []))
    refute bad.allow
    assert_equal 'fail', bad.checks['zk_compliance']
    assert_includes bad.reasons, 'zk_compliance: prover key is not trusted'
    idle = authorize(pc, grant, zk: IDLE)
    assert_equal [false, 'fail'], [idle.allow, idle.checks['zk_compliance']]
    assert_includes idle.reasons, NO_VERIFIER
  end

  def test_authorize_requires_an_enforced_attestation_for_a_grant_that_binds_the_agent
    agent, grant = party({ 'operator' => 'acme' })
    free_agent, free_grant = party
    base = authorize(free_agent.act('refund', 'orders/1').pcactn, free_grant)
    assert_equal 'not-enforced', base.checks['attestation']
    act = -> { agent.act('refund', 'orders/1').pcactn }

    none = authorize(act.call, grant)
    refute none.allow
    assert_equal 'fail', none.checks['attestation']
    assert_includes none.reasons, "#{BOUND} (no attestation verifier in this SDK: fail closed)"

    ok = authorize(act.call, grant, attestation: PASS)
    assert_equal 'pass', ok.checks['attestation']
    assert_equal [base.allow, failed(base)], [ok.allow, failed(ok)], 'a passing attestation leaves the bound grant as an unbound one'

    idle = authorize(act.call, grant, attestation: IDLE)
    assert_equal [false, 'fail'], [idle.allow, idle.checks['attestation']]
    assert_includes idle.reasons, BOUND

    bad = authorize(act.call, grant, attestation: ->(_ctx) { { 'enforced' => true, 'ok' => false, 'reason' => 'unbound quote' } })
    assert_equal [false, 'fail'], [bad.allow, bad.checks['attestation']]
    assert_equal ['attestation: unbound quote', BOUND], bad.reasons.select { |r| r.start_with?('attestation:') }
  end

  def test_authorize_reports_an_attestation_for_an_unbound_grant_too
    agent, grant = party
    ok = authorize(agent.act('refund', 'orders/1').pcactn, grant, attestation: PASS)
    assert_equal 'pass', ok.checks['attestation']
    bad = authorize(agent.act('refund', 'orders/1').pcactn, grant, attestation: ->(_ctx) { { 'enforced' => true, 'ok' => false } })
    assert_equal [false, 'fail'], [bad.allow, bad.checks['attestation']]
    assert_includes bad.reasons, 'attestation: rejected'
  end

  # ---- the entry points forward the hooks ----

  def test_the_guard_options_carry_the_hooks
    assert_includes A::AuthorizeOptions.members, :attestation
    assert_includes A::AuthorizeOptions.members, :zk
    assert_includes A::RackMiddleware::AUTHORIZE_KEYS, :attestation
    assert_includes A::RackMiddleware::AUTHORIZE_KEYS, :zk
    hook = zk_hook({ 'iat' => 0 }, [])
    assert_equal({ 'threshold' => 1, 'attestation' => PASS, 'zk' => hook }, A.assurance_hooks_of(nil, 1, PASS, hook))
    assert_equal({ 'zk' => :labelled }, A.assurance_hooks_of({ zk: :labelled }, nil, nil, hook), 'an explicit report hook wins')
  end

  def test_the_rack_middleware_forwards_the_zk_hook
    pc, grant, prover = proven
    failed_checks = lambda do |options|
      app = A::RackMiddleware.new(->(_env) { [200, {}, ['ok']] }, audience: AUD, resolve_grant: ->(_) { grant }, now: pc['iat'],
                                                                 authorize: { state_store: A::MemoryStateStore.new, is_revoked: ->(_p, _g) { false },
                                                                              operation: ->(_env) { OP }, plan: 'single-step',
                                                                              provenance: ProvHarness::OPTION, risk: ProvHarness::RISK }.merge(options))
      status, _headers, body = app.call({ 'HTTP_PCA_ACTION' => A.b64e(A.canon_bytes(pc)), 'rack.input' => StringIO.new('') })
      status == 200 ? [] : JSON.parse(body.join)['failed_checks']
    end
    assert_includes failed_checks.call({}), 'zk_compliance'
    refute_includes failed_checks.call({ zk: zk_hook(pc, [prover.public]) }), 'zk_compliance'
    assert_includes failed_checks.call({ zk: zk_hook(pc, []) }), 'zk_compliance'
  end

  def test_the_signature_only_guards_forward_the_hooks
    pc, grant, prover = proven
    status = lambda do |hooks|
      app = A::RackMiddleware.new(->(_env) { [200, {}, ['ok']] }, audience: AUD, resolve_grant: ->(_) { grant }, now: pc['iat'],
                                                                 signature_only: true, hooks: hooks)
      app.call({ 'HTTP_PCA_ACTION' => A.b64e(A.canon_bytes(pc)), 'rack.input' => StringIO.new('') })[0]
    end
    assert_equal 403, status.call(nil)
    assert_equal 200, status.call({ zk: zk_hook(pc, [prover.public]) })
    assert_equal 403, status.call({ 'zk' => zk_hook(pc, []) })
    assert_equal 403, status.call({ 'zk' => zk_hook(pc, [prover.public]), 'attestation' => ->(_ctx) { { 'enforced' => true, 'ok' => false } } })
    assert_raises(ArgumentError) { A::RackMiddleware.new(->(_env) {}, audience: AUD, resolve_grant: ->(_) { grant }, hooks: {}) }
    assert_raises(ArgumentError) { A::RackMiddleware.new(->(_env) {}, audience: AUD, resolve_grant: ->(_) { grant }, signature_only: true, hooks: 5) }
    assert_raises(ArgumentError) { A::Fetch.require_pca(audience: AUD, resolve_grant: ->(_) { grant }, hooks: {}) }
  end
end
