# frozen_string_literal: true

# AtlasPca.authorize: the full pipeline (0.5). minitest:
#   ruby -Ilib test/test_authorize.rb
#
# The signed fixtures (test-data/authorize-fixtures.json, `pca-authorize-fixtures/1`) come from the TypeScript reference,
# which also recorded the TypeScript authorize() outcome of every step (`ts`): each case asserts the exact outcome (allow,
# status, sorted failing checks) and that it equals the TypeScript decision, with one fresh store per case, once with
# the memory store and once with the SQLite store. The SQLite tests need the sqlite3 gem (skipped without it).
# The provenance gate is always on: like the TypeScript harness, every replay presents a principal-direct bundle under the
# pinned harness mediator (test/support/prov_harness.rb).
require_relative '../lib/atlas_pca/rack_middleware'
require_relative 'support/prov_harness'
require 'minitest/autorun'
require 'json'
require 'stringio'
require 'tmpdir'
require 'fileutils'
require 'set'

module AuthorizeFixtures
  HERE = __dir__
  FIX = AtlasPca.parse_json(File.read(File.expand_path('../test-data/authorize-fixtures.json', HERE), encoding: 'UTF-8'),
                            loose: true)
  CASES = FIX['cases']
  NOW = FIX['now']
  AUD = FIX['audience']
  VECTORS = File.expand_path('../conformance/vectors.json', HERE)
  LIMIT_CASES = AtlasPca.parse_json(File.read(File.expand_path('../test-data/limit-reasons.json', HERE), encoding: 'UTF-8'),
                                    loose: true)['cases']
  CAVEAT_EVAL = AtlasPca.parse_json(File.read(VECTORS, encoding: 'UTF-8'), loose: true)['primitives']['caveat_eval']

  SQLITE = begin
    require 'sqlite3'
    true
  rescue LoadError
    false
  end

  module_function

  def kase(name)
    CASES.find { |c| c['name'] == name } or raise "no fixture case #{name}"
  end

  def settle(r)
    { 'allow' => r.allow, 'status' => r.status, 'failed' => r.checks.select { |_, s| s == 'fail' }.keys.sort }
  end

  def run_case(c, store)
    revoked = false
    g = c['grant']
    c['steps'].map do |s|
      revoked = s['revoked']
      r = AtlasPca.authorize(s['pcactn'], operation: s['operation'], audience: AUD,
                                             resolve_grant: ->(ref) { ref == g['id'] ? g : nil }, state_store: store,
                                             is_revoked: ->(_p, _g) { revoked }, now: NOW, plan: 'single-step',
                                             provenance: ProvHarness::OPTION)
      got = settle(r)
      # a step that records `expect.reason` pins a substring of the decisive reason
      got['reason'] = s['expect']['reason'] if s['expect'].key?('reason') && r.reason.to_s.include?(s['expect']['reason'])
      got
    end
  end

  def hdr(p)
    AtlasPca.b64e(AtlasPca.canon_bytes(p))
  end
end

class AuthorizeTestBase < Minitest::Test
  include AuthorizeFixtures

  def tmpdir
    @tmpdir ||= Dir.mktmpdir('pca-authorize')
  end

  def teardown
    FileUtils.rm_rf(@tmpdir) if @tmpdir
  end

  def need_sqlite
    skip 'sqlite3 gem not installed' unless SQLITE
  end

  def sqlite_store(name = 'replay.db')
    AtlasPca::SqliteStateStore.new(File.join(tmpdir, name))
  end

  # authorize step `step` of case `c` with the defaults, overridden by `kw`
  def az(c, step = 0, **kw)
    s = c['steps'][step]
    opts = { operation: s['operation'], audience: AUD, resolve_grant: ->(_ref) { c['grant'] },
             state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false }, now: NOW, plan: 'single-step',
             provenance: ProvHarness::OPTION }
    AtlasPca.authorize(s['pcactn'], **opts.merge(kw))
  end

  def within = kase('envelope-max-spend-within')
end

# ---- the shared fixtures: exact outcome, and parity with the TypeScript authorize() ------------------------------------
class TestAuthorizeFixtures < AuthorizeTestBase
  def test_fixture_shape
    assert_equal 'pca-authorize-fixtures/1', FIX['format']
    assert_equal 31, CASES.length
    assert_equal 35, CASES.sum { |c| c['steps'].length }
    assert(CASES.all? { |c| c['steps'].all? { |s| s.key?('ts') } })
  end

  def test_fixture_bytes_identical_to_the_shared_copy
    shared = File.expand_path('../../python-pca/testdata/authorize-fixtures.json', HERE)
    skip 'shared copy not in this checkout' unless File.exist?(shared)
    assert_equal File.binread(shared), File.binread(File.expand_path('../test-data/authorize-fixtures.json', HERE))
  end

  def test_fixtures_memory_store
    CASES.each do |c|
      got = run_case(c, AtlasPca::MemoryStateStore.new)
      assert_equal(c['steps'].map { |s| s['expect'] }, got, c['name'])
      assert_equal(c['steps'].map { |s| s['ts'] }, got.map { |g| { 'allow' => g['allow'], 'status' => g['status'] } }, c['name'])
    end
  end

  def test_fixtures_sqlite_store
    need_sqlite
    CASES.each_with_index do |c, i|
      got = run_case(c, sqlite_store("case-#{i}.db"))
      assert_equal(c['steps'].map { |s| s['expect'] }, got, c['name'])
      assert_equal(c['steps'].map { |s| s['ts'] }, got.map { |g| { 'allow' => g['allow'], 'status' => g['status'] } }, c['name'])
    end
  end
end

# ---- the reviewer acceptance, spelled out ------------------------------------------------------------------------------
class TestAuthorizeAcceptance < AuthorizeTestBase
  def test_400_under_100_refused_with_reason
    r = az(kase('envelope-max-spend-400-refused'))
    assert_equal({ 'allow' => false, 'status' => 403, 'failed' => ['policy'] }, settle(r))
    assert_equal 'policy: caveat(s) not satisfied: max_spend', r.reason
    assert_equal 'policy: root caveat(s) not satisfied: max_spend', az(kase('root-max-spend-400-refused')).reason
    assert_equal 'delegated_caveats: delegation caveat(s) not satisfied: max_spend', az(kase('delegated-max-spend-400-refused')).reason
    assert_equal 'policy: amount <= 100 not satisfied for payments.send on payments/acme', az(kase('envelope-predicate-400-refused')).reason
  end

  def test_unknown_and_agent_caveat_reasons
    assert_match(/\Apolicy: root caveat\(s\) not satisfied: /, az(kase('root-unknown-caveat')).reason)
    assert_match(/\Adelegated_caveats: delegation caveat\(s\) not satisfied: /, az(kase('delegated-unknown-caveat')).reason)
    assert_equal 'delegated_caveats: delegation caveat(s) not satisfied: predicates', az(kase('delegated-predicates-outside')).reason
    assert_equal 'delegated_caveats: delegation caveat(s) not satisfied: tool_schema', az(kase('delegated-tool-schema-400')).reason
    assert_equal 'policy: grant carries no valid envelope', az(kase('no-envelope')).reason
    assert_match(/\Aattestation: the grant binds the agent/, az(kase('attestation-bound')).reason)
  end

  def test_signed_50_executed_400_reports_the_binding_first
    r = az(kase('envelope-max-spend-signed-50-executes-400'))
    assert_equal "operation: the proof's params_digest does not match the params of this payments.send operation", r.reason
  end

  def test_operation_x_for_y_reason
    assert_equal 'operation: the proof is for payments.send on payments/acme, but this operation is payments.refund on payments/acme',
                 az(kase('operation-other-verb')).reason
  end

  def test_allow_binds_the_operation
    c = within
    s = c['steps'][0]
    r = az(c)
    assert_equal [true, 200, nil], [r.allow, r.status, r.reason]
    assert_equal %w[payments.send payments/acme], [r.operation.verb, r.operation.resource]
    assert_equal s['pcactn']['action']['params_digest'], r.operation.params_digest
    assert_equal AtlasPca.hash_canonical(s['pcactn']), r.operation.id
    assert_equal 'pass', r.checks['replay']
    assert AtlasPca.is_authorized_for(r, s['operation'])
    assert AtlasPca.is_authorized_for(r, { verb: 'payments.send', resource: 'payments/acme', params: { amount: 50, currency: 'usd' } })
    refute AtlasPca.is_authorized_for(r, s['operation'].merge('params' => { 'amount' => 400, 'currency' => 'usd' }))
    refute AtlasPca.is_authorized_for(r, s['operation'].merge('verb' => 'payments.refund'))
    refute AtlasPca.is_authorized_for(r, s['operation'].merge('resource' => 'payments/other'))
    refute AtlasPca.is_authorized_for(r, nil)
    denied_case = kase('envelope-max-spend-400-refused')
    refute AtlasPca.is_authorized_for(az(denied_case), denied_case['steps'][0]['operation'])
  end

  def test_symbol_keys_and_integral_floats_in_the_operation
    r = az(within, operation: { verb: 'payments.send', resource: 'payments/acme', params: { amount: 50.0, currency: 'usd' } })
    assert r.allow, r.reason
  end

  def test_operation_params_are_copied_before_verification
    params = within['steps'][0]['operation']['params'].dup
    calls = []
    revoked = lambda do |_p, _g| # runs after the copy: mutating the caller's Hash must not change what was verified
      calls << 1
      params['amount'] = 400
      false
    end
    r = az(within, operation: within['steps'][0]['operation'].merge('params' => params), is_revoked: revoked)
    assert_equal [1], calls
    assert r.allow
  end

  def test_json_text_proof_accepted
    assert az(within).allow
    s = within['steps'][0]
    r = AtlasPca.authorize(AtlasPca.canonicalize(s['pcactn']), operation: s['operation'], audience: AUD,
                                                               resolve_grant: ->(_r) { within['grant'] },
                                                               state_store: AtlasPca::MemoryStateStore.new,
                                                               is_revoked: ->(_p, _g) { false }, now: NOW, plan: 'single-step',
                                                               provenance_bundle: ProvHarness.bundle(s['operation']),
                                                               provenance: { mediators: [ProvHarness::PIN] })
    assert r.allow
  end
end

# ---- fail closed: configuration, operation, callbacks, store -----------------------------------------------------------
class TestAuthorizeFailClosed < AuthorizeTestBase
  def test_missing_component_refused_before_verification
    [['audience', { audience: '' }], ['audience', { audience: nil }], ['audience', { audience: 5 }],
     ['resolve_grant', { resolve_grant: nil }], ['state_store', { state_store: nil }],
     ['state_store', { state_store: Object.new }], ['is_revoked', { is_revoked: nil }],
     ['is_revoked', { is_revoked: true }]].each do |missing, kw|
      seen = []
      base = { resolve_grant: ->(ref) { seen << ref; within['grant'] } }
      r = az(within, **base.merge(kw))
      assert_equal({ 'allow' => false, 'status' => 403, 'failed' => ['authorize_config'] }, settle(r), missing)
      assert_equal [missing], r.missing
      assert_empty seen
      assert_equal "authorize_config: missing required component(s): #{missing} (fail closed)", r.reason
    end
  end

  def test_all_missing_listed
    r = AtlasPca.authorize({})
    assert_equal %w[audience resolve_grant state_store is_revoked], r.missing
    assert_equal 403, r.status
  end

  def test_unknown_plan_mode_refused
    assert_equal ["plan (only 'single-step' or nil)"], az(within, plan: 'multi').missing
  end

  def test_operation_required
    [nil, {}, 5, { 'verb' => 'payments.send', 'resource' => 'payments/acme' },
     { 'verb' => 'payments.send', 'resource' => 'payments/acme', 'params' => [1] },
     { 'verb' => '', 'resource' => 'payments/acme', 'params' => {} },
     { 'verb' => 'payments.send', 'resource' => '', 'params' => {} },
     { 'verb' => :x, 'resource' => 'payments/acme', 'params' => {} }].each do |op|
      seen = []
      r = az(within, operation: op, resolve_grant: ->(ref) { seen << ref; within['grant'] })
      assert_equal({ 'allow' => false, 'status' => 403, 'failed' => ['operation'] }, settle(r), op.inspect)
      assert_equal 'operation: authorize needs the operation to execute (verb, resource, params) (fail closed)', r.reason
      assert_empty seen
    end
  end

  def test_no_plan_source_denies
    r = az(within, plan: nil)
    assert_equal({ 'allow' => false, 'status' => 403, 'failed' => ['plan_root_authorized'] }, settle(r))
    assert_equal 'plan_root_authorized: default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecure_skip_plan_root_check)', r.reason
    assert_equal 'fail', r.checks['plan_root_authorized']
    refute_equal 'not-enforced', r.checks['plan_root_authorized']
    assert_equal 'pass', az(within).checks['plan_root_authorized'] # a configured authorized plan passes
  end

  def test_context_plan_must_be_authorized
    s = within['steps'][0]
    node = { 'id' => 'n1', 'verb' => 'payments.send', 'resource' => 'payments/acme',
             'params_digest' => s['pcactn']['action']['params_digest'], 'reversibility_class' => 'irreversible' }
    assert az(within, plan: nil, context: ->(_p) { { 'plan' => [node], 'plan_authorized' => true } }).allow
    assert az(within, plan: nil, context: ->(_p) { { plan: [node], plan_authorized: true } }).allow # Symbol keys
    no = az(within, plan: nil, context: ->(_p) { { 'plan' => [node] } })
    assert_equal ['plan_root_authorized'], settle(no)['failed']
    assert_equal 'plan_root_authorized: the plan root has not been authorized by the principal', no.reason
    other = az(within, plan: nil, context: ->(_p) { { 'plan' => [node.merge('verb' => 'x')], 'plan_authorized' => true } })
    assert_equal 'plan_root_authorized: known plan does not match plan.root', other.reason
    junk = az(within, plan: nil, context: ->(_p) { { 'plan' => 'x', 'plan_authorized' => true } })
    assert_equal 'plan_root_authorized: known plan does not match plan.root', junk.reason
    # single-step with a context plan: the context plan wins
    assert_equal ['plan_root_authorized'], settle(az(within, context: ->(_p) { { 'plan' => [node.merge('verb' => 'x')] } }))['failed']
  end

  def test_revocation_must_be_exactly_false
    [nil, 0, 'no', [], 'false', :raise].each do |ret|
      chk = ->(_p, _g) { ret == :raise ? raise('down') : ret }
      r = az(within, is_revoked: chk)
      assert_equal({ 'allow' => false, 'status' => 403, 'failed' => ['revocation'] }, settle(r), ret.inspect)
      assert_equal 'revocation: the revocation check failed (fail closed)', r.reason
    end
    assert_equal 'revocation: the grant is revoked', az(within, is_revoked: ->(_p, _g) { true }).reason
    seen = []
    az(within, is_revoked: ->(p, g) { seen << [p['grant_ref'], g['id']]; false })
    assert_equal [[within['grant']['id'], within['grant']['id']]], seen
  end

  def test_store_failure_denies
    broken = Object.new
    def broken.claim(_k, _c) = raise(IOError, 'locked')
    garbage = Object.new
    def garbage.claim(_k, _c) = 'yes'
    null = Object.new
    def null.claim(_k, _c) = nil
    truthy = Object.new
    def truthy.claim(_k, _c) = [1]
    [[broken, 'replay: the replay store failed (fail closed)'], [null, 'replay: the replay store failed (fail closed)'],
     [garbage, 'replay: 1 was already claimed (replay)'], [truthy, 'replay: 1 was already claimed (replay)']].each do |st, why|
      r = az(within, state_store: st)
      assert_equal({ 'allow' => false, 'status' => 403, 'failed' => ['replay'] }, settle(r))
      assert_equal why, r.reason
    end
    last = Object.new
    def last.claim(_k, _c) = AtlasPca::ClaimResult.new(false, 7)
    assert_equal 'replay: 1 is not greater than last seen 7 (replay)', az(within, state_store: last).reason
  end

  def test_store_bool_array_and_key
    seen = []
    rec = Object.new
    rec.define_singleton_method(:claim) { |k, c| seen << [k, c]; true }
    assert az(within, state_store: rec).allow
    leaf = within['steps'][0]['pcactn']['cap_chain'][-1]['holder']
    assert_equal [["#{within['grant']['id']}:#{leaf}", 1]], seen
    assert_equal "#{within['grant']['id']}:#{leaf}", AtlasPca.state_key(within['grant']['id'], leaf)
    arr = Object.new
    def arr.claim(_k, _c) = [true]
    assert az(within, state_store: arr).allow
    no = Object.new
    def no.claim(_k, _c) = false
    assert_equal 'replay: 1 was already claimed (replay)', az(within, state_store: no).reason
  end

  def test_denied_request_never_reaches_the_store
    seen = []
    rec = Object.new
    rec.define_singleton_method(:claim) { |k, _c| seen << k; AtlasPca::ClaimResult.new(true) }
    CASES.each do |c|
      c['steps'].each_with_index do |s, i|
        next if s['expect']['allow'] || s['expect']['failed'] == ['replay']

        r = az(c, i, state_store: rec, is_revoked: ->(_p, _g) { s['revoked'] },
                     resolve_grant: ->(ref) { ref == c['grant']['id'] ? c['grant'] : nil })
        refute r.allow, c['name']
      end
    end
    assert_empty seen
  end

  def test_callbacks_fail_closed
    boom = ->(*_a) { raise 'x' }
    assert_equal ['resolve_grant'], settle(az(within, resolve_grant: boom))['failed']
    assert_equal ['context'], settle(az(within, context: boom))['failed']
    assert_equal ['context'], settle(az(within, context: ->(_p) { [1] }))['failed']
    assert_equal ['intent_v2'], settle(az(within, intent_v2: boom))['failed']
    assert_equal({ 'allow' => false, 'status' => 401, 'failed' => ['grant_ref'] }, settle(az(within, resolve_grant: ->(_r) {})))
    assert_equal({ 'allow' => false, 'status' => 401, 'failed' => ['grant_ref'] }, settle(az(within, resolve_grant: ->(_r) { [1] })))
  end

  def test_grant_ref_not_a_string
    s = within['steps'][0]
    seen = []
    r = AtlasPca.authorize(s['pcactn'].merge('grant_ref' => 5), operation: s['operation'], audience: AUD,
                                                                resolve_grant: ->(ref) { seen << ref },
                                                                state_store: AtlasPca::MemoryStateStore.new,
                                                                is_revoked: ->(_p, _g) { false }, now: NOW, plan: 'single-step')
    assert_equal({ 'allow' => false, 'status' => 401, 'failed' => ['malformed'] }, settle(r))
    assert_empty seen
  end

  def test_undecodable_and_absent_proofs
    s = within['steps'][0]
    kw = { operation: s['operation'], audience: AUD, resolve_grant: ->(_r) { within['grant'] },
           state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false }, now: NOW, plan: 'single-step' }
    assert_equal({ 'allow' => false, 'status' => 401, 'failed' => ['wire'] }, settle(AtlasPca.authorize(nil, **kw)))
    assert_equal 'wire: no PCActn presented', AtlasPca.authorize(nil, **kw).reason
    assert_equal({ 'allow' => false, 'status' => 401, 'failed' => ['pcactn'] }, settle(AtlasPca.authorize('{not json', **kw)))
    assert_equal({ 'allow' => false, 'status' => 401, 'failed' => ['pcactn'] }, settle(AtlasPca.authorize(12, **kw)))
    assert_equal({ 'allow' => false, 'status' => 401, 'failed' => ['pcactn'] }, settle(AtlasPca.authorize('[1]', **kw)))
    assert_equal({ 'allow' => false, 'status' => 401, 'failed' => ['pcactn'] }, settle(AtlasPca.authorize('x' * 600_000, **kw)))
    bad = s['pcactn'].merge('extra_member' => 1) # a wire failure is terminal
    assert_equal({ 'allow' => false, 'status' => 401, 'failed' => %w[malformed wire] }, settle(AtlasPca.authorize(bad, **kw)))
  end

  def test_zk_compliance_fails_closed
    r = az(within, operation: within['steps'][0]['operation'])
    assert r.allow
    s = within['steps'][0]
    p = s['pcactn'].merge('zk_compliance' => { 'x' => 1 })
    r = AtlasPca.authorize(p, operation: s['operation'], audience: AUD, resolve_grant: ->(_r) { within['grant'] },
                              state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false }, now: NOW,
                              plan: 'single-step')
    refute r.allow
    assert_equal 'fail', r.checks['zk_compliance']
  end

  def test_require_adds_checks
    r = az(within, require: ['freshness'])
    assert_equal({ 'allow' => false, 'status' => 403, 'failed' => ['freshness'] }, settle(r))
    assert_equal 'freshness: required check is absent (default-deny: not enforced by this resource server)', r.reason
    assert_equal ['freshness'], settle(az(within, require: [:freshness]))['failed']
    assert_equal ['freshness'], settle(az(within, require: 'freshness'))['failed']
    assert az(within, require: ['policy', 5]).allow
  end

  def test_reversibility_authoritative_class
    c = within # the agent declared "irreversible"
    assert_equal 'pass', az(c, context: ->(_p) { { 'reversibility_class' => 'reversible' } }).checks['reversibility']
    assert_equal 'pass', az(c, context: ->(_p) { { 'reversibility_class' => 'nuclear' } }).checks['reversibility']
    assert_nil az(c).checks['reversibility']
  end

  def test_internal_error_denies
    sc = AtlasPca.singleton_class
    orig = AtlasPca.method(:verify_pcactn)
    sc.send(:define_method, :verify_pcactn) { |*_a, **_k| 1 / 0 }
    begin
      r = az(within)
      assert_equal({ 'allow' => false, 'status' => 403, 'failed' => ['authorize'] }, settle(r))
      assert_equal 'authorize: error (fail closed): ZeroDivisionError', r.reason
    ensure
      sc.send(:define_method, :verify_pcactn, orig)
    end
    assert az(within).allow
  end
end

# ---- the replay stores -------------------------------------------------------------------------------------------------
class TestAuthorizeStores < AuthorizeTestBase
  def monotone(st)
    assert_equal AtlasPca::ClaimResult.new(true), st.claim('k', 5)
    assert_equal AtlasPca::ClaimResult.new(false, 5), st.claim('k', 5)
    assert_equal AtlasPca::ClaimResult.new(false, 5), st.claim('k', 4)
    assert_equal AtlasPca::ClaimResult.new(true), st.claim('k', 6)
    assert_equal AtlasPca::ClaimResult.new(false, 6), st.claim('k', 6)
    assert_equal AtlasPca::ClaimResult.new(true), st.claim('other', 0)
    assert_equal AtlasPca::ClaimResult.new(false, 0), st.claim('other', 0)
  end

  def test_memory_monotone
    monotone(AtlasPca::MemoryStateStore.new)
  end

  def test_sqlite_monotone
    need_sqlite
    monotone(sqlite_store)
  end

  def test_sqlite_survives_reopen
    need_sqlite
    path = File.join(tmpdir, 'r.db')
    assert AtlasPca::SqliteStateStore.new(path).claim('k', 1).ok
    assert_equal AtlasPca::ClaimResult.new(false, 1), AtlasPca::SqliteStateStore.new(path).claim('k', 1)
  end

  def test_sqlite_rejects_non_int_counter
    need_sqlite
    st = sqlite_store
    assert_equal AtlasPca::ClaimResult.new(false), st.claim('k', true)
    assert_equal AtlasPca::ClaimResult.new(false), st.claim('k', '1')
    assert_equal AtlasPca::ClaimResult.new(false), st.claim(:k, 1)
    assert st.claim('k', 1).ok
  end

  # The SQL store decides on the changed-row count of its ONE upsert statement (no read-then-write).
  def test_sql_store_is_one_statement
    log = []
    changes = 1
    stored = nil
    st = AtlasPca::SqlStateStore.new(execute: ->(sql, b) { log << [:execute, sql, b]; changes },
                                     select: ->(sql, b) { log << [:select, sql, b]; stored })
    want = 'INSERT INTO pca_replay (key, last_counter) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET ' \
           'last_counter = excluded.last_counter WHERE excluded.last_counter > pca_replay.last_counter'
    assert_equal want, st.claim_sql
    assert_equal AtlasPca::ClaimResult.new(true), st.claim('k', 5)
    assert_equal [[:execute, want, ['k', 5]]], log
    log.clear
    changes = 0
    assert_equal AtlasPca::ClaimResult.new(false), st.claim('k', 6) # nothing stored, but the statement changed nothing
    stored = 6
    assert_equal AtlasPca::ClaimResult.new(false, 6), st.claim('k', 6)
    assert_equal [:execute, :select, :execute, :select], log.map(&:first)
    assert_equal ['SELECT last_counter FROM pca_replay WHERE key = ?', ['k']], log[1][1..]
    pg = AtlasPca::SqlStateStore.new(execute: ->(_s, _b) { 1 }, select: ->(_s, _b) {}, placeholders: :dollar, table: 'replay2')
    assert_equal 'INSERT INTO replay2 (key, last_counter) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET ' \
                 'last_counter = excluded.last_counter WHERE excluded.last_counter > replay2.last_counter', pg.claim_sql
    assert_raises(ArgumentError) { AtlasPca::SqlStateStore.new(execute: ->(*) {}, select: ->(*) {}, table: 'x; drop') }
    assert_raises(ArgumentError) { AtlasPca::SqlStateStore.new(execute: ->(*) {}, select: ->(*) {}, placeholders: :colon) }
  end

  def concurrent_claims(st, n = 16)
    gate = Queue.new
    wins = Queue.new
    ts = Array.new(n) do
      Thread.new do
        gate.pop
        wins << 1 if st.claim('k', 7).ok
      end
    end
    n.times { gate << 1 }
    ts.each(&:join)
    wins.size
  end

  def test_concurrent_claims_threads_memory
    assert_equal 1, concurrent_claims(AtlasPca::MemoryStateStore.new)
  end

  def test_concurrent_claims_threads_sqlite
    need_sqlite
    assert_equal 1, concurrent_claims(sqlite_store)
  end

  def test_concurrent_claims_processes_sqlite
    need_sqlite
    skip 'fork not available' unless Process.respond_to?(:fork)
    path = File.join(tmpdir, 'procs.db')
    AtlasPca::SqliteStateStore.new(path) # create the table first
    gate_r, gate_w = IO.pipe
    pids = Array.new(16) do
      fork do
        gate_w.close
        st = AtlasPca::SqliteStateStore.new(path)
        gate_r.read # released when the parent closes the write end
        exit!(st.claim('k', 9).ok ? 0 : 1)
      rescue StandardError
        exit!(2)
      end
    end
    gate_r.close
    gate_w.close
    codes = pids.map { |pid| Process.wait2(pid)[1].exitstatus }
    assert_equal [0] + [1] * 15, codes.sort
  end

  def concurrent_authorize(st)
    gate = Queue.new
    res = Queue.new
    ts = Array.new(8) do
      Thread.new do
        gate.pop
        res << az(within, state_store: st).allow
      end
    end
    8.times { gate << 1 }
    ts.each(&:join)
    Array.new(res.size) { res.pop }.sort_by { |x| x ? 1 : 0 }
  end

  def test_concurrent_authorize_same_proof_one_wins_memory
    assert_equal [false] * 7 + [true], concurrent_authorize(AtlasPca::MemoryStateStore.new)
  end

  def test_concurrent_authorize_same_proof_one_wins_sqlite
    need_sqlite
    assert_equal [false] * 7 + [true], concurrent_authorize(sqlite_store)
  end
end

# ---- caveat semantics: conformance parity and the agent-native types ---------------------------------------------------
class TestAuthorizeCaveats < AuthorizeTestBase
  def test_caveat_eval_vectors_agent_evaluator
    assert_equal 41, CAVEAT_EVAL.length
    CAVEAT_EVAL.each do |v|
      ctx = v['context']
      got = AtlasPca.evaluate_agent_caveats(AtlasPca.policy_caveats(v['grant'], v['chain']), ctx,
                                            { 'action' => ctx.is_a?(Hash) ? ctx['action'] : nil })
      assert_equal [v['expect']['allow'], v['expect']['failed']], got, v['name']
      assert_equal AtlasPca.evaluate_caveats(AtlasPca.policy_caveats(v['grant'], v['chain']), ctx), got, v['name']
    end
  end

  def test_agent_caveats_predicates_and_unknown
    ctx = { 'now' => 1, 'action' => { 'verb' => 'pay', 'resource' => 'inv:1', 'params' => { 'amount' => 5 } } }
    actx = { 'action' => ctx['action'] }
    allow = { 'type' => 'predicates', 'allow' => [{ 'verb' => 'pay', 'resource' => 'inv:*' }] }
    deny = { 'type' => 'predicates', 'allow' => [{ 'verb' => 'pay', 'resource' => 'inv:2' }] }
    assert_equal [true, []], AtlasPca.evaluate_agent_caveats([allow], ctx, actx)
    assert_equal [false, ['predicates']], AtlasPca.evaluate_agent_caveats([deny], ctx, actx)
    assert_equal [false, ['predicates']], AtlasPca.evaluate_agent_caveats([{ 'type' => 'predicates', 'allow' => 'x' }], ctx, actx)
    assert_equal [false, ['predicates']], AtlasPca.evaluate_agent_caveats([allow], ctx, nil)
    assert_equal [false, %w[geo <malformed>]], AtlasPca.evaluate_agent_caveats([{ 'type' => 'geo' }, 5], ctx, actx)
    assert_equal [false, ['<malformed caveats>']], AtlasPca.evaluate_agent_caveats('x', ctx, actx)
    assert_equal [true, []], AtlasPca.evaluate_agent_caveats([], ctx, actx)
    assert_equal [false, ['<evaluation error>']], AtlasPca.evaluate_agent_caveats([allow], nil, actx)
    assert_equal [true, []], AtlasPca.evaluate_agent_caveats([{ 'type' => 'max_spend', 'usd' => 5 }], ctx, actx)
    assert_equal [false, ['max_spend']], AtlasPca.evaluate_agent_caveats([{ 'type' => 'max_spend', 'usd' => 4 }], ctx, actx)
  end

  def tool_caveat(schema, tool: 'pay', sig: 'sigdigest')
    { 'type' => 'tool_schema', 'tool' => tool, 'signature_digest' => sig, 'schema' => schema,
      'schema_digest' => AtlasPca.hash_canonical(schema),
      'binding_digest' => AtlasPca.hash_canonical({ 'tool' => tool, 'signature_digest' => sig, 'schema' => schema }) }
  end

  def test_tool_schema_rules
    cv = tool_caveat({ 'props' => { 'n' => { 'type' => 'integer', 'min' => 0, 'max' => 10 },
                                    'flag' => { 'type' => 'boolean', 'const' => true },
                                    's' => { 'type' => 'string', 'prefix' => 'ab', 'maxLength' => 3 },
                                    'e' => { 'type' => 'number', 'enum' => [1, 2.5] },
                                    'o' => { 'type' => 'object', 'props' => { 'x' => { 'type' => 'string' } }, 'required' => ['x'] },
                                    'a' => { 'type' => 'array', 'items' => { 'type' => 'integer' }, 'maxItems' => 2 } },
                       'required' => ['n'] })
    ev = ->(args, **c) { AtlasPca.evaluate_tool_schema(cv, { 'tool' => 'pay', 'args' => args }.merge(c.transform_keys(&:to_s))) }
    assert_equal [true, nil], ev.call({ 'n' => 3 })
    assert_equal [true, nil], ev.call({ 'n' => 3.0 }) # JS: 3.0 is an integer
    assert_equal [false, 'args.n: wrong type (expected integer)'], ev.call({ 'n' => 3.5 })
    assert_equal [false, 'args.n: wrong type (expected integer)'], ev.call({ 'n' => true }) # a bool is never a number
    assert_equal [false, 'args.n: above max'], ev.call({ 'n' => 11 })
    assert_equal [false, 'args.n: below min'], ev.call({ 'n' => -1 })
    assert_equal [false, "args: missing required argument 'n'"], ev.call({})
    assert_equal [false, 'args: unexpected argument "zz"'], ev.call({ 'n' => 1, 'zz' => 1 })
    assert_equal [false, 'args.flag: wrong type (expected boolean)'], ev.call({ 'n' => 1, 'flag' => 1 })
    assert_equal [false, 'args.flag: violates const'], ev.call({ 'n' => 1, 'flag' => false })
    assert_equal [true, nil], ev.call({ 'n' => 1, 'flag' => true })
    assert_equal [true, nil], ev.call({ 'n' => 1, 's' => 'abc' })
    assert_equal [false, 'args.s: violates prefix'], ev.call({ 'n' => 1, 's' => "a\u{1F600}" })
    assert_equal [false, 'args.s: exceeds maxLength'], ev.call({ 'n' => 1, 's' => "ab\u{1F600}" }) # UTF-16 length 4
    assert_equal [false, 'args.s: wrong type (expected string)'], ev.call({ 'n' => 1, 's' => 5 })
    assert_equal [true, nil], ev.call({ 'n' => 1, 'e' => 2.5 })
    assert_equal [true, nil], ev.call({ 'n' => 1, 'e' => 1.0 })
    assert_equal [false, 'args.e: violates enum'], ev.call({ 'n' => 1, 'e' => 3 })
    assert_equal [false, 'args.e: wrong type (expected number)'], ev.call({ 'n' => 1, 'e' => true })
    assert_equal [false, "args.o: missing required argument 'x'"], ev.call({ 'n' => 1, 'o' => {} })
    assert_equal [false, 'args.o: expected object'], ev.call({ 'n' => 1, 'o' => [] })
    assert_equal [false, 'args.a: exceeds maxItems'], ev.call({ 'n' => 1, 'a' => [1, 2, 3] })
    assert_equal [false, 'args.a: expected array'], ev.call({ 'n' => 1, 'a' => {} })
    assert_equal [false, 'args.a[1]: wrong type (expected integer)'], ev.call({ 'n' => 1, 'a' => [1, '2'] })
    assert_equal [false, 'tool "refund" not authorized'], ev.call({ 'n' => 1 }, tool: 'refund')
    assert_equal [false, 'signed tool_binding differs from the authorized tool signature'],
                 ev.call({ 'n' => 1 }, tool_signature_digest: 'other')
    assert_equal [true, nil], ev.call({ 'n' => 1 }, tool_signature_digest: 'sigdigest')
  end

  def test_tool_schema_caveat_integrity
    schema = { 'props' => { 'n' => { 'type' => 'number' } } }
    good = tool_caveat(schema)
    call = { 'tool' => 'pay', 'args' => { 'n' => 1 } }
    assert_equal [true, nil], AtlasPca.evaluate_tool_schema(good, call)
    assert_equal [false, 'schema digest mismatch'], AtlasPca.evaluate_tool_schema(good.merge('schema_digest' => 'x'), call)
    assert_equal [false, 'binding digest mismatch'], AtlasPca.evaluate_tool_schema(good.merge('binding_digest' => 'x'), call)
    assert_equal [false, 'malformed tool_schema caveat'], AtlasPca.evaluate_tool_schema(good.merge('tool' => ''), call)
    assert_equal [false, 'malformed tool_schema caveat'], AtlasPca.evaluate_tool_schema(good.merge('type' => 'x'), call)
    bad = tool_caveat({ 'props' => { 'n' => { 'type' => 'number', 'pattern' => 'x' } } })
    assert_equal [false, 'malformed tool_schema caveat: n: unknown spec key'], AtlasPca.evaluate_tool_schema(bad, call)
    assert_equal [false, 'malformed call'], AtlasPca.evaluate_tool_schema(good, { 'tool' => 'pay', 'args' => [1] })
    assert_equal [false, 'malformed call'], AtlasPca.evaluate_tool_schema(good, nil)
    # no signature_digest: the binding digest is computed over the string "undefined"
    nosig = { 'type' => 'tool_schema', 'tool' => 'pay', 'schema' => schema, 'schema_digest' => AtlasPca.hash_canonical(schema),
              'binding_digest' => AtlasPca.hash_canonical({ 'tool' => 'pay', 'signature_digest' => 'undefined', 'schema' => schema }) }
    assert_equal [true, nil], AtlasPca.evaluate_tool_schema(nosig, call)
  end

  def test_validate_arg_schema
    assert_nil AtlasPca.validate_arg_schema({ 'props' => {} })
    assert_equal 'schema must be an object', AtlasPca.validate_arg_schema([])
    assert_equal 'unknown schema key', AtlasPca.validate_arg_schema({ 'props' => {}, 'x' => 1 })
    assert_equal 'props must be an object', AtlasPca.validate_arg_schema({ 'props' => [] })
    assert_equal "invalid property name 'a-b'", AtlasPca.validate_arg_schema({ 'props' => { 'a-b' => { 'type' => 'string' } } })
    assert_equal 'required names an undeclared property', AtlasPca.validate_arg_schema({ 'props' => {}, 'required' => ['x'] })
    assert_equal 'x: unknown type', AtlasPca.validate_arg_schema({ 'props' => { 'x' => { 'type' => 'date' } } })
    assert_equal 'x: bad enum', AtlasPca.validate_arg_schema({ 'props' => { 'x' => { 'type' => 'integer', 'enum' => [1.5] } } })
    assert_equal 'x: min > max', AtlasPca.validate_arg_schema({ 'props' => { 'x' => { 'type' => 'number', 'min' => 2, 'max' => 1 } } })
    assert_equal 'x: minLength > maxLength',
                 AtlasPca.validate_arg_schema({ 'props' => { 'x' => { 'type' => 'string', 'minLength' => 2, 'maxLength' => 1 } } })
    assert_equal 'x: minItems > maxItems',
                 AtlasPca.validate_arg_schema({ 'props' => { 'x' => { 'type' => 'array', 'items' => { 'type' => 'string' }, 'minItems' => 2, 'maxItems' => 1 } } })
    assert_equal 'too many props', AtlasPca.validate_arg_schema({ 'props' => (0..64).to_h { |i| ["p#{i}", { 'type' => 'string' }] } })
    deep = { 'type' => 'string' }
    8.times { deep = { 'type' => 'object', 'props' => { 'x' => deep } } }
    assert_equal 'x: x: x: x: x: x: x: x: schema too deep', AtlasPca.validate_arg_schema({ 'props' => { 'x' => deep } })
  end
end

# ---- the Rack middleware with `authorize:`: the acceptance before the app runs -----------------------------------------
class TestAuthorizeRack < AuthorizeTestBase
  OVER = 'envelope-max-spend-400-refused'

  def grants
    [within, kase(OVER), kase('wrong-audience')].to_h { |c| [c['grant']['id'], c['grant']] }
  end

  # A tiny resource server: the app records what it executed.
  def server(verb: 'payments.send', revoked: -> { false }, store: AtlasPca::MemoryStateStore.new, **auth)
    @executed = []
    app = lambda do |env|
      @executed << env['pca']['operation']
      [200, { 'content-type' => 'text/plain' }, ['ok']]
    end
    mapping = lambda do |env|
      body = env['rack.input'].read
      env['rack.input'].rewind
      { verb: verb, resource: 'payments/acme', params: JSON.parse(body) }
    end
    opts = { state_store: store, is_revoked: ->(_p, _g) { revoked.call }, operation: mapping, provenance: ProvHarness::OPTION }.merge(auth)
    AtlasPca::RackMiddleware.new(app, audience: AUD, resolve_grant: ->(ref) { grants[ref] }, now: NOW, authorize: opts)
  end

  def post(mw, c, params)
    status, headers, body = mw.call({ 'REQUEST_METHOD' => 'POST', 'PATH_INFO' => '/pay',
                                      'HTTP_PCA_ACTION' => hdr(c['steps'][0]['pcactn']),
                                      'rack.input' => StringIO.new(JSON.generate(params)) })
    [status, headers, status == 200 ? body.join : JSON.parse(body.join)]
  end

  P50 = { 'amount' => 50, 'currency' => 'usd' }.freeze
  P400 = { 'amount' => 400, 'currency' => 'usd' }.freeze

  def test_400_under_100_limit
    mw = server
    status, headers, body = post(mw, kase(OVER), P400)
    assert_equal 403, status
    assert_equal 'policy: caveat(s) not satisfied: max_spend', body['error_description']
    assert_equal 'access_denied', body['error']
    assert_equal ['policy'], body['failed_checks']
    assert_equal 'PCA realm="pca", error="access_denied"', headers['WWW-Authenticate']
    assert_empty @executed
  end

  def test_50_proof_with_a_400_body
    mw = server
    status, _h, body = post(mw, within, P400)
    assert_equal 403, status
    assert_equal "operation: the proof's params_digest does not match the params of this payments.send operation",
                 body['error_description']
    assert_equal %w[operation params_digest plan_root_authorized policy], body['failed_checks']
    assert_empty @executed
  end

  def test_proof_for_x_on_a_route_executing_y
    mw = server(verb: 'payments.refund')
    status, _h, body = post(mw, within, P50)
    assert_equal 403, status
    assert_equal 'operation: the proof is for payments.send on payments/acme, but this operation is payments.refund on payments/acme',
                 body['error_description']
    assert_empty @executed
  end

  def test_allow_then_replay
    mw = server
    status, = post(mw, within, P50)
    assert_equal 200, status
    assert_equal 1, @executed.length
    op = @executed[0]
    assert_equal ['payments.send', 'payments/acme', within['steps'][0]['pcactn']['action']['params_digest']],
                 [op.verb, op.resource, op.params_digest]
    status, _h, body = post(mw, within, P50)
    assert_equal 403, status
    assert_equal 'replay: 1 is not greater than last seen 1 (replay)', body['error_description']
    assert_equal 1, @executed.length
  end

  def test_env_carries_the_authorization
    seen = nil
    app = ->(env) { seen = env['pca']; [200, {}, ['ok']] }
    mw = AtlasPca::RackMiddleware.new(app, audience: AUD, resolve_grant: ->(ref) { grants[ref] }, now: NOW,
                                           authorize: AtlasPca::AuthorizeOptions.new(
                                             state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false },
                                             operation: ->(_env) { within['steps'][0]['operation'] },
                                             provenance: ProvHarness::OPTION
                                           ))
    status, = mw.call({ 'HTTP_PCA_ACTION' => hdr(within['steps'][0]['pcactn']), 'rack.input' => StringIO.new('') })
    assert_equal 200, status
    assert seen['verdict'].allow
    assert_equal within['steps'][0]['pcactn'], seen['pcactn']
    assert seen['authorization'].allow
    assert_same seen['authorization'].operation, seen['operation']
    assert AtlasPca.is_authorized_for(seen['authorization'], within['steps'][0]['operation'])
  end

  def test_revoked
    mw = server(revoked: -> { true })
    status, _h, body = post(mw, within, P50)
    assert_equal [403, 'revocation: the grant is revoked'], [status, body['error_description']]
    assert_empty @executed
  end

  def test_missing_or_failing_operation_mapping
    [[{ operation: ->(_env) {} }, 'operation: authorize needs the operation to execute (verb, resource, params) (fail closed)'],
     [{ operation: nil }, 'operation: authorize needs the operation to execute (verb, resource, params) (fail closed)'],
     [{ operation: ->(_env) { raise 'boom' } }, 'operation: the operation mapping failed (fail closed)']].each do |auth, why|
      mw = server(**auth)
      status, _h, body = post(mw, within, P50)
      assert_equal [403, why, ['operation']], [status, body['error_description'], body['failed_checks']]
      assert_empty @executed
    end
    no_mapping = AtlasPca::RackMiddleware.new(->(_e) { raise 'app ran' }, audience: AUD, resolve_grant: ->(r) { grants[r] },
                                                                          now: NOW, authorize: { state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false } })
    status, = no_mapping.call({ 'HTTP_PCA_ACTION' => hdr(within['steps'][0]['pcactn']), 'rack.input' => StringIO.new('') })
    assert_equal 403, status
  end

  def test_missing_component
    mw = server(store: nil, is_revoked: nil)
    status, _h, body = post(mw, within, P50)
    assert_equal 403, status
    assert_equal %w[state_store is_revoked], body['missing']
    assert_empty @executed
  end

  def test_wrong_audience_and_no_proof_are_401
    mw = server
    status, headers, body = post(mw, kase('wrong-audience'), kase('wrong-audience')['steps'][0]['operation']['params'])
    assert_equal [401, 'invalid_pcactn'], [status, body['error']]
    assert_equal 'PCA realm="pca", error="invalid_pcactn"', headers['WWW-Authenticate']
    status, = mw.call({ 'rack.input' => StringIO.new('') })
    assert_equal 401, status
    assert_empty @executed
  end

  def test_bad_options_raise
    app = ->(_e) { [200, {}, []] }
    assert_raises(ArgumentError) { AtlasPca::RackMiddleware.new(app, audience: AUD, resolve_grant: ->(_r) {}, authorize: 5) }
    assert_raises(ArgumentError) do
      AtlasPca::RackMiddleware.new(app, audience: AUD, resolve_grant: ->(_r) {}, authorize: { state_stor: 1 })
    end
  end

  def mw_with(**o)
    app = ->(env) { @ran << env['pca'].keys; [200, {}, ['ok']] }
    AtlasPca::RackMiddleware.new(app, audience: AUD, resolve_grant: ->(ref) { grants[ref] }, now: NOW, **o)
  end

  def over_env
    { 'HTTP_PCA_ACTION' => hdr(kase(OVER)['steps'][0]['pcactn']), 'rack.input' => StringIO.new(JSON.generate(P400)) }
  end

  def test_signature_only_is_the_explicit_opt_in
    @ran = []
    mw = mw_with(signature_only: true)
    # the core verifier only: a $400 body under a $100 proof reaches the app, twice (no replay store)
    assert_equal 200, mw.call(over_env)[0]
    assert_equal 200, mw.call(over_env)[0]
    assert_equal [%w[verdict pcactn]] * 2, @ran
  end

  def test_default_without_options_refuses_with_authorize_config
    @ran = []
    status, headers, body = mw_with.call(over_env)
    parsed = JSON.parse(body.join)
    assert_equal 403, status
    assert_equal 'access_denied', parsed['error']
    assert_equal 'authorize_config: missing required component(s): state_store, is_revoked (fail closed)', parsed['error_description']
    assert_equal %w[state_store is_revoked], parsed['missing']
    assert_equal 'PCA realm="pca", error="access_denied"', headers['WWW-Authenticate']
    assert_empty @ran
  end

  def test_default_options_given_as_empty_hash_refuses_too
    @ran = []
    assert_equal 403, mw_with(authorize: {}).call(over_env)[0]
    assert_empty @ran
  end

  def test_signature_only_with_authorize_raises
    err = assert_raises(ArgumentError) { mw_with(signature_only: true, authorize: {}) }
    assert_match(/mutually exclusive/, err.message)
  end
end

# ---- B6: check names and limit-naming reasons ---------------------------------------------------------------------------
class TestCheckNamesAndReasons < AuthorizeTestBase
  def test_core_verifier_reports_counter_format_only
    c = within
    s = c['steps'][0]
    v = AtlasPca.verify_pcactn(s['pcactn'], c['grant'], now: NOW, audience: AUD)
    assert_equal %w[wire version audience validity chain grant_ref_bound plan_inclusion leaf_signature counter_format], v.checks.keys
    assert_equal %w[wire version audience validity chain grant_ref_bound plan_inclusion leaf_signature counter_format], AtlasPca::CHECK_ORDER
    bad = AtlasPca.verify_pcactn(s['pcactn'].merge('counter' => -1), c['grant'], now: NOW, audience: AUD)
    refute bad.allow
    assert_equal false, bad.checks['counter_format']
    refute bad.checks.key?('counter')
  end

  def test_authorize_reports_replay_not_counter
    r = az(within)
    assert_equal 'pass', r.checks['replay']
    assert_equal 'pass', r.checks['counter_format']
    refute r.checks.key?('counter')
    assert_equal %w[counter_format replay revocation plan_root_authorized audience validity grant_ref_bound operation params_digest policy],
                 AtlasPca::DEFAULT_REQUIRED_CHECKS
  end

  def test_replay_reason_prefix_and_flip
    store = AtlasPca::MemoryStateStore.new
    assert az(within, state_store: store).allow
    r = az(within, state_store: store)
    assert_equal 'replay: 1 is not greater than last seen 1 (replay)', r.reason
    assert_equal 'fail', r.checks['replay']
    refute r.checks.key?('counter')
  end

  def test_require_counter_is_an_alias_of_replay
    r = az(within, require: ['counter'])
    assert r.allow, r.reason
    assert_equal 'pass', r.checks['replay']
    refute r.checks.key?('counter')
    store = AtlasPca::MemoryStateStore.new
    az(within, state_store: store, require: [:counter])
    assert_equal 'replay: 1 is not greater than last seen 1 (replay)', az(within, state_store: store, require: ['counter']).reason
  end

  LIMITS = AuthorizeFixtures::LIMIT_CASES

  def test_limit_reason_table_matches_typescript
    refute_empty LIMITS
    LIMITS.each do |c|
      r = AtlasPca.evaluate_predicates(c['predicates'], { 'action' => c['action'] })
      assert_equal c['allowed'], r['allowed'], c['name']
      assert_equal c['reason'], r['reason'], c['name'] unless c['allowed']
    end
  end

  def test_limit_is_named_in_the_authorize_policy_reason
    r = az(kase('envelope-predicate-400-refused'))
    assert_equal 'policy: amount <= 100 not satisfied for payments.send on payments/acme', r.reason
  end
end

# ---- the README samples run as written ---------------------------------------------------------------------------------
class TestAuthorizeReadme < AuthorizeTestBase
  README = [File.expand_path('../README.md', AuthorizeFixtures::HERE),
            File.expand_path('../../../scripts/pca-mirror-assets/pca-ruby/README.md', AuthorizeFixtures::HERE)]
           .find { |f| File.exist?(f) && File.read(f).include?('## Authorize an operation') }

  # Evaluates a README block with the names it expects in scope.
  class Host
    attr_reader :sent, :used

    def initialize = (@sent = [])
    def send_payment(body) = @sent << body
    def use(klass, **opts) = (@used = [klass, opts])

    # rubocop:disable Lint/UnusedMethodArgument
    def run(code, pcactn, body, grants, revoked_grant_ids, store = nil, bundle: nil, mediator_pins: [ProvHarness::PIN])
      eval(code, binding, 'README.md') # rubocop:disable Security/Eval
    end
    # rubocop:enable Lint/UnusedMethodArgument
  end

  def blocks
    skip 'README not found' if README.nil?
    text = File.read(README, encoding: 'UTF-8')
    section = text[text.index('## Authorize an operation')...text.index('## Caveats (policy layer)')]
    section.split("```ruby\n")[1..].map { |b| b.split('```', 2)[0] }
  end

  def with_clock(ms)
    sc = Time.singleton_class
    orig = Time.method(:now)
    sc.send(:define_method, :now) { Time.at(ms / 1000r) }
    yield
  ensure
    sc.send(:define_method, :now, orig)
  end

  def test_readme_samples_run
    need_sqlite
    authorize_block, rack_block = blocks
    s = within['steps'][0]
    grants = { within['grant']['id'] => within['grant'] }
    body = { 'amount' => 50, 'currency' => 'usd' }
    op = { 'verb' => 'payments.send', 'resource' => 'payments/acme', 'params' => body }
    Dir.chdir(tmpdir) do
      with_clock(NOW) do
        host = Host.new
        result = host.run("#{authorize_block}\nresult", s['pcactn'], body, grants, Set.new, bundle: ProvHarness.bundle(op))
        assert result.allow
        assert_equal [body], host.sent
        err = assert_raises(SecurityError) { Host.new.run(authorize_block, s['pcactn'], body, grants, Set.new, bundle: ProvHarness.bundle(op)) }
        assert_match(/replay/, err.message) # the same proof again: the SQLite store refuses it
        revoked = assert_raises(SecurityError) do
          Host.new.run(authorize_block, s['pcactn'], body, grants, Set[within['grant']['id']], bundle: ProvHarness.bundle(op))
        end
        assert_equal 'revocation: the grant is revoked', revoked.message

        host = Host.new
        host.run(rack_block, nil, nil, grants, Set.new, AtlasPca::MemoryStateStore.new)
        klass, opts = host.used
        executed = []
        mw = klass.new(->(env) { executed << env['pca']['operation'].verb; [200, {}, ['ok']] }, **opts)
        req = lambda do |path, params|
          mw.call({ 'REQUEST_METHOD' => 'POST', 'PATH_INFO' => path, 'HTTP_PCA_ACTION' => hdr(s['pcactn']),
                    'HTTP_PCA_PROVENANCE' => ProvHarness.header(op.merge('params' => params)),
                    'rack.input' => StringIO.new(JSON.generate(params)) })[0]
        end
        assert_equal 403, req.call('/payments', { 'amount' => 400, 'currency' => 'usd' })
        assert_equal 403, req.call('/other', body)
        assert_equal 200, req.call('/payments', body)
        assert_equal 403, req.call('/payments', body) # replay
        assert_equal ['payments.send'], executed
      end
    end
  end
end
