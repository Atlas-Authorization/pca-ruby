# frozen_string_literal: true

# A non-finite clock, spend, charge or timeout (NaN, +Infinity, -Infinity) never admits: every refusal reads as the negation of its
# positive condition and an infinite value that would land on the admitting side is refused explicitly. Each test names the old
# behaviour it kills.
#   ruby -Ilib test/test_nonfinite_clock.rb
require_relative '../lib/atlas_pca'
require 'json'
require 'minitest/autorun'

class TestNonfiniteClock < Minitest::Test
  A = AtlasPca
  BAD = [Float::NAN, Float::INFINITY, -Float::INFINITY].freeze
  SU = { 'id' => 'su1', 'verb' => 'stripe.payout', 'resource' => 'acct:1', 'params' => { 'amount' => 80, 'currency' => 'USD', 'payee' => 'bob' },
         'tier' => 3, 'reason' => 'r', 'goalCommit' => 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq', 'goal' => 'pay suppliers',
         'lineage' => {}, 'r' => 0.5, 'requestedAt' => 1 }.freeze

  def test_ciba_broker_reads_a_non_finite_clock_as_expired
    t = [1_800_000_000_000]
    broker = A::Ciba.create_ciba_broker('now' => -> { t[0] })
    id = broker.start(SU)['auth_req_id']
    assert_equal 'pending', broker.poll(id)['status']
    BAD.each do |v|
      t[0] = v # old: `now >= expiresAt` is false for NaN and -Infinity, so the session stayed pending
      assert_equal 'expired', broker.poll(id)['status'], v.to_s
    end
  end

  def test_signals_replay_store_refuses_a_non_finite_clock_or_expiry
    BAD.each do |v|
      refute A::Signals::InMemorySetReplayStore.new(10).add_if_absent('j', 200, v), "clock #{v}" # old: a fresh jti was admitted
      refute A::Signals::InMemorySetReplayStore.new(10).add_if_absent('j', v, 100), "expiry #{v}"
    end
  end

  def test_signals_replay_store_infinite_clock_does_not_free_a_held_jti
    s = A::Signals::InMemorySetReplayStore.new(10)
    assert s.add_if_absent('j', 200, 100)
    BAD.each { |v| refute s.add_if_absent('j', 300, v) } # old: +Infinity read the held entry as expired and re-admitted the jti
  end

  def test_dpop_replay_store_refuses_a_non_finite_clock
    BAD.each { |v| refute A::Dpop::InMemoryReplayStore.new.add_if_absent('k', 200, v), v.to_s } # old: admitted on a fresh key
    s = A::Dpop::InMemoryReplayStore.new
    assert s.add_if_absent('k', 200, 100)
    BAD.each { |v| refute s.add_if_absent('k', 300, v), v.to_s }
  end

  def test_stream_health_refuses_a_non_finite_clock
    BAD.each do |v|
      h = A::Signals::StreamHealth.new({ 'min_verification_interval' => 0 })
      assert_nil h.request_verification(v), v.to_s # old: NaN / -Infinity opened a pending verification that never expired
      refute h.ack_verification('x', v)
    end
    h = A::Signals::StreamHealth.new({ 'min_verification_interval' => 0 }, 'verify_timeout_sec' => Float::INFINITY)
    assert_nil h.request_verification(100) # an infinite timeout would leave the request pending forever
  end

  def test_sliding_window_counter_ignores_a_non_finite_clock
    c = A::Wallet::SlidingWindowCounter.new(1000)
    assert c.try_add(10, 5)
    BAD.each do |v|
      refute c.try_add(v, 5), v.to_s
      assert_equal 1, c.count(v), v.to_s # old: +Infinity pruned every recorded event
    end
  end

  def test_risk_budget_nodes_must_be_finite
    BAD.each do |v|
      node = { 'B' => v, 'tau' => 0 }
      refute A::Risk.sub_budget(node, 5)['ok'], v.to_s # old: `5 > Infinity` is false, so the allocation passed
      refute A::Risk.debit_consolidated(node, { 'B' => 10, 'tau' => 0 }, 3)['ok'], v.to_s
      refute A::Risk.debit_consolidated({ 'B' => 10, 'tau' => 0 }, node, 3)['ok'], v.to_s
      refute A::Risk.debit_consolidated_path([{ 'B' => 10 }, node], 3)['ok'], v.to_s
    end
  end

  def test_mesh_capability_expiry_needs_a_finite_clock
    e = { 'prefixes' => [''], 'expires_at' => 1000 }
    act = { 'type' => 'x', 'resource' => 'r', 'service_domain' => 'd' }
    assert_nil A.mesh_admits(e, act, 500, 1)
    BAD.each { |v| assert_equal 'capability expired', A.mesh_admits(e, act, v, 1), v.to_s } # old: NaN and -Infinity never exceeded the expiry
  end

  def test_mesh_amount_ceiling_needs_a_finite_amount
    e = { 'prefixes' => [''], 'max_amount' => 100 }
    BAD.each do |v|
      act = { 'type' => 'x', 'resource' => 'r', 'service_domain' => 'd', 'amount' => v }
      assert_match(/amount exceeds ceiling/, A.mesh_admits(e, act, 1, 1), v.to_s) # old: NaN and -Infinity never exceeded the ceiling
    end
  end

  def test_standing_class_approval_needs_a_finite_clock
    a = { 'grantedAt' => 0, 'ttlMs' => 1000, 'verbs' => ['v'], 'resource' => '*' }
    assert A.class_approval_covers?(a, 'v', 'r', 500)
    BAD.each { |v| refute A.class_approval_covers?(a, 'v', 'r', v), v.to_s } # old: NaN compared false both ways and covered
  end

  def test_dlp_an_unreadable_taint_beats_even_an_unbounded_ceiling
    pol = { 'classes' => [], 'defaultMaxTaintForAuto' => Float::INFINITY }
    BAD.each do |v|
      out = A::Dlp.evaluate_dlp(pol, { 'verb' => 'v', 'resource' => 'r', 'taint' => v })
      assert_equal 'step_up', out['outcome'], v.to_s # old: taint read as Infinity and `Infinity > Infinity` is false
    end
  end

  def test_window_read_accumulator_refuses_a_non_finite_charge_or_clock
    BAD.each do |v|
      refute A::GrantsList::WindowReadAccumulator.new(5, 100).charge('k', v, 0), "charge #{v}" # old: -Infinity + n <= cap admitted
      acc = A::GrantsList::WindowReadAccumulator.new(5, 100)
      assert acc.charge('k', 5, 0)
      refute acc.charge('k', 1, v), "clock #{v}" # old: a -Infinity clock opened a fresh window and reset the spend
    end
  end

  def test_payment_authority_with_a_nan_cap_refuses
    auth = { 'maxAmount' => Float::NAN }
    refute A::Acp.check_payment_authority(auth, { 'amount' => 1, 'currency' => 'USD', 'merchant' => 'm' })['ok'] # old: `1 > NaN` is false
  end

  def test_web_bot_auth_replay_cache_refuses_a_non_finite_clock
    cache = A::WebBotAuth.memory_replay_cache(10)
    assert cache.claim('k', 200, 100)
    BAD.each { |v| refute cache.claim('k', 300, v), v.to_s } # old: +Infinity read the held claim as expired
    BAD.each { |v| refute A::WebBotAuth.memory_replay_cache(10).claim('fresh', 200, v), v.to_s }
  end

  def test_sd_jwt_refuses_a_non_finite_clock_tolerance_or_window
    BAD.each do |v|
      %w[now clock_tolerance_sec kb_max_age_sec].each do |k|
        out = A::SdJwt.verify_pca_sd_jwt('x', { k => v })
        refute out['ok'], "#{k} #{v}" # old: the date checks ran against the non-finite value (or the parse raised first)
        assert_equal 'now, clockToleranceSec and kbMaxAgeSec must be finite', out['reason']
      end
    end
  end

  def test_oidc_refuses_a_non_finite_clock_tolerance
    BAD.each do |v|
      e = assert_raises(A::Oidc::OidcVerificationError) do
        A::Oidc.verify_id_token('a.b.c', { 'issuer' => 'https://i', 'audience' => 'a', 'clock_tolerance_sec' => v })
      end
      assert_equal 'config', e.code, v.to_s # old: the tolerance reached the exp / nbf comparisons
    end
  end

  # a present spend cap that is not a non-negative safe integer refuses; an absent one is unbounded (old: only NaN refused)
  def test_payment_authority_refuses_a_cap_that_is_not_a_non_negative_integer
    req = { "amount" => 1, "currency" => "USD", "merchant" => "m" }
    [Float::NAN, Float::INFINITY, -Float::INFINITY, -1, -0.0, 1.5].each do |cap|
      assert_equal({ "ok" => false, "reason" => "authorized spend cap is not a non-negative integer (fail closed)" },
                   A::Acp.check_payment_authority({ "maxAmount" => cap }, req), cap.to_s)
    end
    assert A::Acp.check_payment_authority({ "merchants" => nil, "categories" => nil }, req)["ok"]
  end

  # old: an infinite period end was emitted as expires_at: nil (no expiry) and NaN was compared away
  def test_shared_payment_token_limits_refuse_a_non_finite_period_end
    BAD.each do |v|
      m = { "terms" => { "autoApproveThreshold" => 100, "currency" => "USD", "periodEnd" => v }, "budget" => { "B" => 1000 } }
      e = assert_raises(TypeError, v.to_s) { A::Payments.shared_payment_token_limits(m, 5) }
      assert_equal "sharedPaymentTokenLimits: periodEnd must be an epoch-ms time", e.message
    end
  end

  # old: an unknown frequency was a violation only when a last-used date existed
  def test_ap2_unknown_recurrence_frequency_is_always_a_violation
    c = { "type" => "payment.agent_recurrence", "frequency" => "FORTNIGHTLY" }
    assert_equal ["unknown recurrence frequency"], A::Ap2.evaluate_payment(c, {}, { "now" => 1 })
  end

  # old: a non-finite bond clock must never read as a finished challenge window (finalized opens settlement)
  def test_bond_challenge_status_refuses_a_non_finite_clock
    BAD.each do |v|
      b = A::StoreBondLedger.new(A::KvBondStore.new(A::MemoryAtomicKv.new), A::KeyPair.new("\x04".b * 32), clock: -> { v })
      assert_equal "clock_invalid", assert_raises(A::BondStoreError, v.to_s) { b.challenge_status("c") }.code
    end
  end

  # old: Float#floor raised FloatDomainError on a clock of +-Infinity
  def test_rounding_helpers_leave_a_non_finite_value_as_it_is
    [Float::INFINITY, -Float::INFINITY].each do |v|
      assert_equal v, A::Ap2.js_round(v)
      assert_equal v, A::Harness.js_round(v)
      assert_equal v, A::GoalExamples.fdiv_floor(v, 1)
      assert_equal(v.positive? ? "Infinity" : "-Infinity", A::Risk.to_fixed3(v))
    end
    assert_equal "NaN", A::Risk.to_fixed3(Float::NAN)
  end

  # old: `!(now < expiresAt)` kept an expiring approval executable under a -Infinity clock
  def test_plan_status_refuses_a_non_finite_clock
    steps = JSON.parse(File.read(File.expand_path('../conformance/plan-vectors.json', __dir__)))['scenarios'][0]['steps']
    reg = A::PlanRegistry.new(now: -> { 1_800_000_000_002 }, validator: ->(_r) { { 'ok' => true } })
    root = steps[1]['root']
    reg.draft('g1', steps[0]['nodes'])
    reg.validate('g1', root)
    reg.commit('g1', root)
    assert reg.authorize('g1', root, { 'by' => 'principal-key', 'expiresAt' => 1_800_000_100_000 })['ok']
    assert reg.status('g1', root, 1_800_000_000_003)['executable']
    BAD.each { |v| refute reg.status('g1', root, v)['executable'], v.to_s }
  end

  # old: `now - startedAt > timeout` was true for a +Infinity clock (a live claim aborted and re-runnable) and for a -Infinity timeout
  def test_recover_operation_never_settles_on_a_non_finite_clock_or_timeout
    BAD.each do |v|
      store = A::MemoryOperationStore.new
      store.create('id' => 'a', 'state' => 'pending', 'startedAt' => 1)
      assert_equal 'pending', A.recover_operation(store, 'a', older_than_ms: 10, now: -> { v })['state'], "clock #{v}"
    end
    [Float::NAN, -Float::INFINITY, -1].each do |v|
      store = A::MemoryOperationStore.new
      store.create('id' => 'a', 'state' => 'pending', 'startedAt' => 1)
      assert_equal 'pending', A.recover_operation(store, 'a', older_than_ms: v, now: -> { 100 })['state'], "timeout #{v}"
    end
  end

  # old: a NaN or negative effect timeout meant compensation never waited for the effect report
  def test_undo_coordinator_refuses_a_non_finite_effect_timeout
    base = { 'engine' => Object.new, 'signer_secret' => "\x09".b * 32, 'audience' => 'rs',
             'resolve_grant' => ->(_r, _p) { {} }, 'compensate' => ->(_c) { {} }, 'operations' => A::MemoryOperationStore.new,
             'notifier' => Object.new, 'alert' => ->(_a) {}, 'now' => -> { 0 }, 'insecure_volatile_store' => true }
    [Float::NAN, -Float::INFINITY, -1].each do |v|
      err = assert_raises(A::UndoError, v.to_s) { A.create_undo_coordinator(base.merge('effect_timeout_ms' => v, 'store' => A::MemoryUndoStore.new)) }
      assert_equal 'config', err.code
    end
  end

  # old: amount / Infinity was 0, pricing any amount as no risk
  def test_amount_risk_refuses_an_infinite_kappa_or_amount
    mk = ->(k) { { 'caveats' => [{ 'type' => 'envelope', 'goal_commit' => 'g', 'predicates' => [], 'caveats' => [], 'agent_binding' => {}, 'risk_policy' => A::DEFAULT_RISK_POLICY.merge('kappa' => k) }] } }
    assert_nil A.amount_risk(mk.call(Float::INFINITY), { 'amount' => 2 })
    BAD.each { |v| assert_nil A.amount_risk(mk.call(4), { 'amount' => v }), v.to_s }
  end

  def test_claim_status_refuses_a_non_finite_clock_or_window
    c = { "issued_at" => 1000, "challenge_window_ms" => 500 }
    BAD.each { |v| assert_raises(RangeError, v.to_s) { A.claim_status(c, v) } } # old: read as finalized, which opens settlement
    assert_raises(RangeError) { A.claim_status(c.merge("challenge_window_ms" => Float::NAN), 1200) }
    assert_equal "open", A.claim_status(c, 1500)
    assert_equal "finalized", A.claim_status(c, 1501)
  end

  # old: `now < expiresAt` kept a handle and an egress admission live under a -Infinity clock
  def test_sandbox_handles_and_egress_spend_on_a_non_finite_clock
    op = { 'verb' => 'fs.read', 'resource' => 'r', 'params' => {} }
    res = { 'allow' => true, 'operation' => { 'verb' => 'fs.read', 'resource' => 'r', 'params_digest' => A.hash_canonical({}), 'id' => 'op' } }
    t = 0
    table = A::Sandbox::HandleTable.new('egress_default_deny', A::Sandbox::ReceiptLog.new(now: -> { t }), { 'fs.read' => ->(_o) { 'x'.b } }, -> { t })
    BAD.each do |v|
      h = table.mint(res, op, { 'uses' => 2, 'expires_at' => 100 })
      assert table.use(h)['ok']
      t = v
      assert_equal 'spent', table.use(h)['reason'], v.to_s
      t = 0
    end
  end

  # old: a NaN or infinite clock reading gave NaN steps (or one step from an infinite elapsed time)
  def test_vdf_calibrate_steps_refuses_a_non_finite_clock
    BAD.each do |v|
      [[v, 0], [0, v]].each do |a, b|
        reads = [a, b]
        assert_raises(RangeError, v.to_s) { A::Vdf.calibrate_steps(101, 1, 10, 10, -> { reads.shift }) }
      end
    end
  end

  # old: `attempts >= max` was false for NaN and -Infinity, so the step-up retried forever
  def test_mcp_step_up_gives_up_on_a_non_finite_attempt_count
    www = 'Bearer error="insufficient_scope", scope="a"'
    BAD.each do |v|
      assert_equal 'retry_limit', A::Mcp.plan_step_up(403, www, { 'requested' => [], 'attempts' => v })['reason'], v.to_s
    end
  end

  # old: a NaN timeout never timed a receive out
  def test_mesh_refuses_a_non_finite_timeout
    BAD.each do |v|
      %i[recv_timeout_ms connect_timeout_ms].each do |k|
        assert_raises(RangeError, "#{k} #{v}") do
          A::Mpc::Net::Mesh.new(self_id: 0, nodes: [], key_pem: '', cert_pem: '', session_id: 's', k => v)
        end
      end
    end
  end

  # old: `cost <= Infinity` admitted anything under an infinite budget
  def test_fhe_plaintext_verdict_admits_nothing_under_an_infinite_budget
    refute A::Fhe.plaintext_verdict({}, A::DEFAULT_RISK_POLICY, Float::INFINITY)['admit']
    refute A::Fhe.plaintext_verdict({}, A::DEFAULT_RISK_POLICY, Float::NAN)['admit']
  end

  # old: a NaN or infinite tolerance or current date made every exp and nbf comparison pass
  def test_spiffe_refuses_a_non_finite_clock_tolerance_or_current_date
    BAD.each do |v|
      %w[clock_tolerance current_date].each do |k|
        e = assert_raises(A::Spiffe::SpiffeError, "#{k} #{v}") do
          A::Spiffe.verify_jwt_svid('a.b.c', { 'audience' => 'a', 'trust_domain' => 'example.org', 'key' => {}, k => v })
        end
        assert_equal 'malformed_token', e.code
      end
    end
  end

  # old: a non-finite at was hashed into the id (JSON null) and serialized
  def test_events_refuse_a_non_finite_at
    BAD.each do |v|
      assert_raises(TypeError, v.to_s) { A::Events.build_step_up_event('step_up.created', { 'grant_ref' => 'g', 'action' => { 'verb' => 'v', 'resource' => 'r' }, 'tier' => 2, 'at' => v }) }
      assert_raises(TypeError, v.to_s) { A::Events.serialize_event({ 'at' => v }) }
    end
  end

  EVD = { 'grant_ref' => 'g', 'action' => { 'verb' => 'v', 'resource' => 'r' }, 'tier' => 2, 'at' => 5 }.freeze
  LONE = "a\xED\xA0\x80".b.force_encoding('UTF-8').freeze # a lone surrogate: not well-formed

  def build_refused(msg, type = 'step_up.created', **over)
    e = assert_raises(TypeError) { A::Events.build_step_up_event(type, EVD.merge(over.transform_keys(&:to_s))) }
    assert_equal "buildStepUpEvent: #{msg}", e.message
  end

  def test_events_build_refuses_an_unknown_type
    build_refused('unknown event type or tier', 'step_up.bogus')
    build_refused('unknown event type or tier', nil)
  end

  def test_events_build_refuses_a_tier_outside_two_and_three
    [1, 4, 2.5, '2', nil].each { |t| build_refused('unknown event type or tier', tier: t) }
  end

  def test_events_build_refuses_a_non_string_or_ill_formed_field
    [nil, 7, LONE].each do |v|
      build_refused('grant_ref must be a well-formed string', grant_ref: v)
      build_refused('action must carry well-formed verb and resource strings', action: { 'verb' => v, 'resource' => 'r' })
      build_refused('action must carry well-formed verb and resource strings', action: { 'verb' => 'v', 'resource' => v })
      build_refused('actor must be a well-formed string', actor: v)
    end
    build_refused('action must carry well-formed verb and resource strings', action: ['v', 'r'])
  end

  def test_events_serialize_refuses_hostile_events
    ev = A::Events.build_step_up_event('step_up.created', EVD)
    [[{ 'tier' => 4 }, 'unknown event type or tier'], [{ 'type' => 'x' }, 'unknown event type or tier'],
     [{ 'id' => 7 }, 'id must be a well-formed string'], [{ 'id' => LONE }, 'id must be a well-formed string'],
     [{ 'grant_ref' => 7 }, 'grant_ref must be a well-formed string'], [{ 'actor' => 7 }, 'actor must be a well-formed string'],
     [{ 'at' => nil }, 'at must be a finite number'], [{ 'at' => '5' }, 'at must be a finite number']].each do |over, msg|
      e = assert_raises(TypeError, msg) { A::Events.serialize_event(ev.merge(over)) }
      assert_equal "serializeEvent: #{msg}", e.message
    end
    e = assert_raises(TypeError) { A::Events.serialize_event('nope') }
    assert_equal 'serializeEvent: not an object', e.message
  end

  def test_events_sign_webhook_refuses_a_non_string_payload
    [nil, 7, { 'a' => 1 }, :sym].each do |p|
      e = assert_raises(TypeError) { A::Events.sign_webhook('s' * 32, p) }
      assert_equal 'signWebhook: the payload must be a string', e.message
    end
  end

  def test_events_a_valid_event_still_builds_serializes_and_signs
    ev = A::Events.build_step_up_event('step_up.approved', EVD.merge('actor' => 'u'))
    assert_equal ev, A::Events.parse_event(A::Events.serialize_event(ev))
    assert_match(/\At=7,v1=[0-9a-f]{64}\z/, A::Events.sign_webhook('s' * 32, '{}', 'timestamp' => 7))
  end
end
