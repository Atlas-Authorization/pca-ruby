# frozen_string_literal: true

# RackMiddleware with the 0.5 native-parity options: intent_policy approved_goal (goal binding v3), and the authorize members
# revocation_staleness, require_assurance and plans, plus executor: (operation records). Exact-outcome tests.
#   ruby -Ilib -Itest test/test_middleware_options.rb
require_relative '../lib/atlas_pca/rack_middleware'
require_relative 'support/prov_harness'
require 'minitest/autorun'
require 'json'

class TestMiddlewareOptions < Minitest::Test
  FIX = AtlasPca.parse_json(File.read(File.expand_path('../test-data/authorize-fixtures.json', __dir__), encoding: 'UTF-8'),
                            loose: true)
  G = 'B5JcJLcCoUyZ2P4kdlU8dI9ukFkzuspDbELVR295azw'
  P = '9U7dBfYHPTNYZ84mWFHOiddEAPc7IEQ1AMEVp13dqSo'

  def kase
    c = FIX['cases'].find { |x| x['name'] == 'envelope-max-spend-within' }
    [c, c['steps'][0]]
  end

  def env_for(pcactn)
    { 'HTTP_PCA_ACTION' => AtlasPca.b64e(AtlasPca.canon_bytes(pcactn)) }
  end

  def build(authorize_extra = {}, app: nil, **kw)
    c, s = kase
    app ||= ->(_env) { [200, { 'content-type' => 'text/plain' }, ['ok']] }
    auth = { state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false }, operation: ->(_env) { s['operation'] },
             provenance: ProvHarness::OPTION }
    AtlasPca::RackMiddleware.new(app, audience: FIX['audience'], resolve_grant: ->(_r) { c['grant'] }, now: FIX['now'],
                                      authorize: auth.merge(authorize_extra), **kw)
  end

  def body_of(resp) = JSON.parse(resp[2].join)
  def fresh(p) = Marshal.load(Marshal.dump(p))

  def test_approved_goal_flows_to_the_intent_check
    _, s = kase
    st, _h, = build({}, intent_policy: { 'approved_goal' => { 'goal_digest' => G, 'policy_digest' => P } }).call(env_for(fresh(s['pcactn'])))
    assert_equal 403, st
    r = build({}, intent_policy: { 'approved_goal' => { 'goal_digest' => G, 'policy_digest' => P } }).call(env_for(fresh(s['pcactn'])))
    assert_includes body_of(r)['error_description'], 'requires an intent binding'
    assert_includes body_of(r)['failed_checks'], 'intent'
  end

  def test_malformed_approved_goal_is_a_fail_closed_misconfiguration
    _, s = kase
    [{ 'goal_digest' => G }, { 'goal_digest' => G, 'policy_digest' => P, 'x' => 1 }, { 'goal_digest' => G, 'policy_digest' => 'AAAA' }].each do |bad|
      r = build({}, intent_policy: { 'approved_goal' => bad }).call(env_for(fresh(s['pcactn'])))
      assert_equal 403, r[0]
      assert_includes body_of(r)['error_description'], 'misconfigured'
    end
  end

  def test_revocation_staleness_fails_the_freshness_check
    _, s = kase
    now = FIX['now']
    pol = AtlasPca::RevocationStaleness.new(allow_unsigned_root_for_irreversible: true, staleness: { 'irreversible' => 10_000 },
                                          ids: ->(_p) { [] })
    ctx = ->(_p) { { 'revocation_state' => { 'kind' => 'root', 'root' => 'r', 'issued_at' => now - 10_001 } } }
    r = build({ revocation_staleness: pol, context: ctx }).call(env_for(fresh(s['pcactn'])))
    assert_equal 403, r[0]
    assert_includes body_of(r)['failed_checks'], 'freshness'
    ctx = ->(_p) { { 'revocation_state' => { 'kind' => 'root', 'root' => 'r', 'issued_at' => now - 10_000 } } }
    assert_equal 200, build({ revocation_staleness: pol, context: ctx }).call(env_for(fresh(s['pcactn'])))[0]
  end

  def test_require_assurance_gates_the_request
    _, s = kase
    r = build({ require_assurance: { 'signature' => 'pq' } }).call(env_for(fresh(s['pcactn'])))
    assert_equal 403, r[0]
    assert_equal ['assurance'], body_of(r)['failed_checks']
    assert_includes body_of(r)['error_description'], 'post-quantum signatures required but leaf_signature is ed25519'
    assert_equal 200, build({ require_assurance: {} }).call(env_for(fresh(s['pcactn'])))[0]
  end

  def test_an_unregistered_plan_is_refused_with_plan_state
    _, s = kase
    r = build({ plans: AtlasPca::PlanRegistry.new, plan: nil }).call(env_for(fresh(s['pcactn'])))
    assert_equal 403, r[0]
    assert_includes body_of(r)['failed_checks'], 'plan_state'
  end

  def test_executor_runs_the_app_once_and_answers_a_retry_from_the_record
    _, s = kase
    calls = 0
    app = ->(env) { calls += 1; [201, { 'content-type' => 'text/plain', 'x-key' => env['pca']['idempotency_key'] }, ['created']] }
    mw = build({}, app: app, executor: { operations: AtlasPca::MemoryOperationStore.new })
    first = mw.call(env_for(fresh(s['pcactn'])))
    assert_equal [201, ['created']], [first[0], first[2]]
    assert_equal AtlasPca.hash_canonical(s['pcactn']), first[1]['x-key']
    refute first[1].key?('pca-replayed')
    again = mw.call(env_for(fresh(s['pcactn'])))
    assert_equal [201, ['created'], 'true'], [again[0], again[2], again[1]['pca-replayed']]
    assert_equal 1, calls
  end

  def test_executor_records_an_app_failure_and_never_reruns_it
    _, s = kase
    calls = 0
    mw = build({}, app: ->(_e) { calls += 1; raise 'downstream down' }, executor: { operations: AtlasPca::MemoryOperationStore.new })
    2.times do
      r = mw.call(env_for(fresh(s['pcactn'])))
      assert_equal 500, r[0]
      assert_equal 'operation_failed', body_of(r)['error']
      refute_includes r[2].join, 'downstream down'
    end
    assert_equal 1, calls
  end

  def test_executor_recheck_refusal_aborts_before_the_app_runs
    _, s = kase
    calls = 0
    n = 0
    revoked = ->(_p, _g) { (n += 1) > 1 }
    mw = build({ is_revoked: revoked }, app: ->(_e) { calls += 1; [200, {}, ['x']] }, executor: { operations: AtlasPca::MemoryOperationStore.new })
    r = mw.call(env_for(fresh(s['pcactn'])))
    assert_equal 403, r[0]
    assert_equal 'operation_aborted', body_of(r)['error']
    assert_equal 'recheck: the grant has been revoked', body_of(r)['error_description']
    assert_equal 0, calls
  end

  def test_executor_denials_keep_the_guard_semantics
    _, s = kase
    mw = build({ is_revoked: ->(_p, _g) { true } }, executor: { operations: AtlasPca::MemoryOperationStore.new })
    r = mw.call(env_for(fresh(s['pcactn'])))
    assert_equal 403, r[0]
    assert_equal 'access_denied', body_of(r)['error']
    assert_includes body_of(r)['failed_checks'], 'revocation'
  end

  def test_executor_configuration_errors_raise
    c, = kase
    mk = ->(**kw) { AtlasPca::RackMiddleware.new(->(_e) { [200, {}, []] }, audience: 'a', resolve_grant: ->(_r) { c['grant'] }, **kw) }
    assert_raises(ArgumentError) { mk.call(signature_only: true, executor: { operations: AtlasPca::MemoryOperationStore.new }) }
    assert_raises(ArgumentError) { mk.call(executor: { operations: nil }) }
    assert_raises(ArgumentError) { mk.call(executor: { operations: AtlasPca::MemoryOperationStore.new, bogus: 1 }) }
    assert_raises(ArgumentError) { mk.call(executor: 5) }
  end
end
