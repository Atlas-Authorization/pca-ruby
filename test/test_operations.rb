# frozen_string_literal: true

# Operation records (T3): replays packages/pca/conformance/operation-vectors.json scenario by scenario (a fresh in-memory
# store, a fixed clock per step), plus concurrency on the in-memory and the durable store, the executor and recovery. A
# missing vector file fails. The SQLite tests need the sqlite3 gem (skipped without it).
#   ruby -Ilib test/test_operations.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'
require 'tmpdir'

class TestOperations < Minitest::Test
  FILE = File.expand_path('../conformance/operation-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)
  FIX = AtlasPca.parse_json(File.read(File.expand_path('../test-data/authorize-fixtures.json', __dir__), encoding: 'UTF-8'),
                            loose: true)
  EMPTY = AtlasPca.params_digest(nil)
  Allowed = Struct.new(:allow, :pcactn, :operation)
  SQLITE = begin
    require 'sqlite3'
    true
  rescue LoadError
    false
  end

  def authorization(s)
    return AtlasPca::AuthorizeResult.new(allow: false, status: 403) if s['not_allowed']

    pc = {}
    pc['exp'] = s['exp'] if s.key?('exp')
    pc['action'] = s.key?('signed_class') ? { 'reversibility_class' => s['signed_class'] } : {}
    Allowed.new(true, pc, AtlasPca::AuthorizedOperation.new(verb: s.fetch('verb', 'payments.refund'), resource: s.fetch('resource', '/orders/1'),
                                                            params_digest: s.fetch('params_digest', EMPTY), id: s['id']))
  end

  def recheck_for(spec)
    return nil if spec.nil?
    return ->(_h) { { 'ok' => true } } if spec == 'ok'
    return ->(_h) { { 'ok' => false, 'reason' => spec['refuse'] } } if spec.key?('refuse')

    ->(_h) { raise spec['throw'] }
  end

  def run_scenario(steps)
    store = AtlasPca::MemoryOperationStore.new
    steps.map do |s|
      at = ->() { s['at'] }
      case s['op']
      when 'seed' then store.create(s['record'].dup) && nil
      when 'get' then store.get(s['id'])
      when 'recover'
        kw = s.key?('older_than_ms') ? { older_than_ms: s['older_than_ms'] } : {}
        AtlasPca.recover_operations(store, now: at, **kw).map { |x| { 'id' => x['id'], 'state' => x['state'] } }.sort_by { |x| x['id'] }
      when 'recover_one'
        kw = s.key?('older_than_ms') ? { older_than_ms: s['older_than_ms'] } : {}
        AtlasPca.recover_operation(store, s['id'], now: at, **kw)
      when 'resolve' then AtlasPca.resolve_operation(store, s['id'], s['outcome'], now: at)
      else run_execute(store, s, at)
      end
    end
  end

  def run_execute(store, s, at)
    calls = 0
    az = authorization(s)
    opts = { store: s['no_store'] ? nil : store, now: at }
    opts[:recheck] = recheck_for(s['recheck']) unless s['recheck'].nil?
    opts[:recheck_for] = s['recheck_for'] if s['recheck_for']
    opts[:reversibility_class] = s['server_class'] if s.key?('server_class')
    opts[:pending_timeout_ms] = s['timeout_ms'] if s.key?('timeout_ms')
    outcome = AtlasPca.execute_authorized(az, **opts) do |h|
      calls += 1
      case s['fn']['kind']
      when 'throw' then raise s['fn']['message']
      when 'reenter' then AtlasPca.execute_authorized(az, **opts) { raise 'inner must not run' }.status
      else s['fn']['result'].nil? ? h.idempotency_key : s['fn']['result']
      end
    end
    { 'outcome' => outcome.to_h, 'fn_calls' => calls,
      'record' => s['no_store'] || s['not_allowed'] ? nil : store.get(s['id']) }
  end

  def test_corpus_is_complete
    assert_equal({ 'pending_timeout_ms' => 300_000 }, DOC['constants'])
    assert_equal 19, DOC['scenarios'].length
  end

  def test_scenarios
    DOC['scenarios'].each do |scn|
      assert_equal scn['expect'], run_scenario(scn['steps']), scn['name']
    end
  end

  # ---- concurrency -----------------------------------------------------------------------------------------------------

  def stores(dir)
    list = [AtlasPca::MemoryOperationStore.new]
    list << AtlasPca.sqlite_operation_store(File.join(dir, 'ops.db')) if SQLITE
    list
  end

  def test_parallel_executions_of_one_id_run_fn_exactly_once
    Dir.mktmpdir do |dir|
      stores(dir).each do |store|
        az = authorization('id' => 'op-par', 'signed_class' => 'reversible')
        calls = Queue.new
        gate = Queue.new
        outcomes = Queue.new
        threads = Array.new(16) do
          Thread.new do
            gate.pop
            outcomes << AtlasPca.execute_authorized(az, store: store) { calls << 1; 'done' }
          end
        end
        16.times { gate << true }
        threads.each(&:join)
        assert_equal 1, calls.size
        list = Array.new(outcomes.size) { outcomes.pop }
        assert_equal 1, list.count { |o| o.status == 'committed' && !o.replayed }
        assert(list.all? { |o| %w[committed pending].include?(o.status) })
      ensure
        store.close if store.respond_to?(:close) # an open sqlite handle blocks removing the tmpdir on Windows
      end
    end
  end

  def test_a_replayed_commit_returns_the_recorded_result
    store = AtlasPca::MemoryOperationStore.new
    az = authorization('id' => 'op-r', 'signed_class' => 'reversible')
    first = AtlasPca.execute_authorized(az, store: store) { { 'n' => 1 } }
    again = AtlasPca.execute_authorized(az, store: store) { { 'n' => 2 } }
    assert_equal [{ 'n' => 1 }, { 'n' => 1 }, true], [first.result, again.result, again.replayed]
  end

  def test_an_unfinished_durable_record_is_never_rerun
    skip 'sqlite3 gem not installed' unless SQLITE
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'ops.db')
      seed = AtlasPca.sqlite_operation_store(path)
      seed.create('id' => 'op-x', 'state' => 'executing', 'verb' => 'v', 'resource' => '/r',
                  'params_digest' => EMPTY, 'reversibility' => 'reversible', 'startedAt' => 0, 'executingAt' => 0)
      store = AtlasPca.sqlite_operation_store(path)
      calls = 0
      begin
        o = AtlasPca.execute_authorized(authorization('id' => 'op-x', 'signed_class' => 'reversible'),
                                        store: store, now: -> { 10 * 60_000 }) { calls += 1 }
        assert_equal 'uncertain', o.status
        assert_equal 0, calls
      ensure
        seed.close
        store.close # an open sqlite handle blocks removing the tmpdir on Windows
      end
    end
  end

  def test_recover_operations_needs_list_open
    assert_raises(TypeError) { AtlasPca.recover_operations(AtlasPca::KvOperationStore.new(AtlasPca::MemoryAtomicKv.new)) }
  end

  def test_kv_store_semantics
    store = AtlasPca::KvOperationStore.new(AtlasPca::MemoryAtomicKv.new)
    rec = { 'id' => 'k1', 'state' => 'pending', 'startedAt' => 1 }
    assert_nil store.create(rec)
    assert_equal rec, store.create(rec.merge('state' => 'executing'))
    refute store.transition('k1', 'executing', rec.merge('state' => 'committed'))
    assert store.transition('k1', 'pending', rec.merge('state' => 'executing'))
    assert_equal 'executing', store.get('k1')['state']
  end

  # ---- the executor ----------------------------------------------------------------------------------------------------

  def kase
    c = FIX['cases'].find { |x| x['name'] == 'envelope-max-spend-within' }
    [c, c['steps'][0]]
  end

  def executor(c, store, revoked: nil, plans: nil, plan: 'single-step', **kw)
    revoked ||= { v: false }
    opts = AtlasPca::AuthorizeOptions.new(state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(p, g) { revoked[:v].respond_to?(:call) ? revoked[:v].call(p, g) : revoked[:v] },
                                          plan: plan, plans: plans)
    [AtlasPca.create_executor(operations: store, options: opts, audience: FIX['audience'], resolve_grant: ->(_r) { c['grant'] },
                              now: -> { FIX['now'] }, **kw), revoked]
  end

  def fresh(pcactn) = Marshal.load(Marshal.dump(pcactn))

  def test_executor_commits_and_replays_from_the_record
    c, s = kase
    ex, = executor(c, AtlasPca::MemoryOperationStore.new)
    calls = []
    first = ex.call(fresh(s['pcactn']), s['operation']) { |h| calls << h.idempotency_key; 'paid' }
    assert_equal ['committed', 'paid', false], [first.status, first.result, first.replayed]
    assert_equal [AtlasPca.hash_canonical(s['pcactn'])], calls
    retry_ = ex.call(fresh(s['pcactn']), s['operation']) { calls << 'again'; 'paid-twice' }
    assert_equal ['committed', 'paid', true], [retry_.status, retry_.result, retry_.replayed]
    assert_equal 1, calls.length
  end

  def test_executor_revoked_between_authorize_and_run_aborts
    c, s = kase
    n = 0
    ex, = executor(c, AtlasPca::MemoryOperationStore.new, revoked: { v: ->(_p, _g) { (n += 1) > 1 } })
    ran = []
    o = ex.call(fresh(s['pcactn']), s['operation']) { ran << 1 }
    assert_equal 'aborted', o.status
    assert_equal 'recheck: the grant has been revoked', o.reason
    assert_empty ran
  end

  def test_executor_denial_without_a_record_stands
    c, s = kase
    ex, revoked = executor(c, AtlasPca::MemoryOperationStore.new)
    revoked[:v] = true
    o = ex.call(fresh(s['pcactn']), s['operation']) { 1 }
    assert_equal 'denied', o.status
    refute o.authorization.allow
  end

  def test_executor_without_a_store_refuses
    c, s = kase
    ex, = executor(c, nil)
    assert_equal 'refused', ex.call(fresh(s['pcactn']), s['operation']) { 1 }.status
  end

  def test_executor_rechecks_that_a_registered_plan_is_still_executable
    c, s = kase
    p = s['pcactn']
    gid = c['grant']['id']
    node = { 'id' => p['plan']['node_id'], 'verb' => p['action']['verb'], 'resource' => p['action']['resource'],
             'params_digest' => p['action']['params_digest'], 'reversibility_class' => p['action']['reversibility_class'] }
    reg = AtlasPca::PlanRegistry.new(now: -> { FIX['now'] })
    root = reg.draft(gid, [node])['record']['root']
    assert reg.validate(gid, root)['ok'] && reg.commit(gid, root)['ok'] && reg.authorize(gid, root, { 'by' => 'principal' })['ok']
    n = 0
    revoked = lambda do |_pc, _g|
      n += 1
      reg.revoke(gid, root, 'principal withdrew approval') if n == 2
      false
    end
    ex, = executor(c, AtlasPca::MemoryOperationStore.new, revoked: { v: revoked }, plans: reg, plan: nil)
    ran = []
    o = ex.call(fresh(p), s['operation']) { ran << 1 }
    assert_equal 'aborted', o.status
    assert_empty ran
    assert_equal "recheck: plan #{root} is revoked (principal withdrew approval)", o.reason
  end
end
