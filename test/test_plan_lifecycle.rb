# frozen_string_literal: true

# Plan lifecycle (T10): replays packages/pca/conformance/plan-vectors.json scenario by scenario (one fresh registry per
# scenario, the clock set per step), plus concurrency, the durable store and the authorize(plans:) wiring. A missing vector
# file fails. The SQLite tests need the sqlite3 gem (skipped without it).
#   ruby -Ilib test/test_plan_lifecycle.rb
require_relative '../lib/atlas_pca'
require_relative 'support/prov_harness'
require 'minitest/autorun'
require 'tmpdir'

class TestPlanLifecycle < Minitest::Test
  FILE = File.expand_path('../conformance/plan-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)
  FIX = AtlasPca.parse_json(File.read(File.expand_path('../test-data/authorize-fixtures.json', __dir__), encoding: 'UTF-8'),
                            loose: true)
  SQLITE = begin
    require 'sqlite3'
    true
  rescue LoadError
    false
  end

  VALIDATORS = {
    'accept' => ->(_r) { { 'ok' => true } },
    'refuse' => ->(_r) { { 'ok' => false, 'reason' => 'node outside the grant' } },
    'throw' => ->(_r) { raise 'policy down' }
  }.freeze

  def run_steps(reg, clock, steps)
    steps.map do |s|
      clock[:now] = s['at']
      case s['op']
      when 'draft' then reg.draft(s['grant'], s['nodes'])
      when 'validate' then reg.validate(s['grant'], s['root'])
      when 'commit' then reg.commit(s['grant'], s['root'])
      when 'authorize' then reg.authorize(s['grant'], s['root'], s['approval'])
      when 'revoke' then reg.revoke(s['grant'], s['root'], s['reason'])
      when 'status' then reg.status(s['grant'], s['root'], s['at'])
      when 'check' then reg.check(s['grant'], s['root'], now: s['at'], node_id: s['node_id'], operation: s['operation'])
      when 'is_plan_authorized' then reg.plan_authorized?(s['grant'], s['root'])
      when 'context' then reg.context(s['grant'], s['root'], s['at'])
      else flunk("unknown step #{s['op']}")
      end
    end
  end

  def registry(scn, kv = nil)
    clock = { now: 0 }
    [AtlasPca::PlanRegistry.new(kv: kv, now: -> { clock[:now] }, validator: VALIDATORS[scn['validator']]), clock]
  end

  def test_corpus_is_complete
    assert_equal 12, DOC['scenarios'].length
    assert_equal DOC['scenarios'].sum { |s| s['steps'].length }, DOC['scenarios'].sum { |s| s['expect'].length }
  end

  def test_scenarios
    DOC['scenarios'].each do |scn|
      reg, clock = registry(scn)
      assert_equal scn['expect'], run_steps(reg, clock, scn['steps']), scn['name']
    end
  end

  def test_scenarios_on_a_durable_store
    skip 'sqlite3 gem not installed' unless SQLITE
    Dir.mktmpdir do |dir|
      DOC['scenarios'].each_with_index do |scn, i|
        kv = AtlasPca::SqliteAtomicKv.new(File.join(dir, "plans#{i}.db"))
        begin
          reg, clock = registry(scn, kv)
          assert_equal scn['expect'], run_steps(reg, clock, scn['steps']), scn['name']
        ensure
          kv.close # Windows cannot delete an open database file
        end
      end
    end
  end

  def test_the_root_is_the_typescript_root
    nodes = DOC['scenarios'][0]['steps'][0]['nodes']
    assert_equal DOC['scenarios'][0]['steps'][1]['root'], AtlasPca.plan_root(nodes)
  end

  def test_parallel_claims_of_one_transition_have_one_winner
    reg = AtlasPca::PlanRegistry.new(now: -> { 1 })
    root = reg.draft('g1', [{ 'id' => 'n1', 'verb' => 'v', 'resource' => '/r' }])['record']['root']
    assert reg.validate('g1', root)['ok']
    gate = Queue.new
    results = Queue.new
    threads = Array.new(16) { Thread.new { gate.pop; results << reg.commit('g1', root) } }
    16.times { gate << true }
    threads.each(&:join)
    list = Array.new(results.size) { results.pop }
    assert_equal 1, list.count { |r| r['ok'] }
    assert(list.reject { |r| r['ok'] }.all? { |r| r['state'] == 'committed' })
  end

  def test_parallel_claims_on_a_shared_file_have_one_winner
    skip 'sqlite3 gem not installed' unless SQLITE
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'plans.db')
      kvs = Queue.new
      mk = -> { AtlasPca::SqliteAtomicKv.new(path).tap { |k| kvs << k } }
      first = AtlasPca::PlanRegistry.new(kv: mk.call, now: -> { 1 })
      root = first.draft('g1', [{ 'id' => 'n1', 'verb' => 'v', 'resource' => '/r' }])['record']['root']
      first.validate('g1', root)
      gate = Queue.new
      results = Queue.new
      threads = Array.new(8) do
        Thread.new do
          reg = AtlasPca::PlanRegistry.new(kv: mk.call, now: -> { 1 })
          gate.pop
          results << reg.commit('g1', root)
        end
      end
      8.times { gate << true }
      threads.each(&:join)
      assert_equal 1, Array.new(results.size) { results.pop }.count { |r| r['ok'] }
      Array.new(kvs.size) { kvs.pop }.each(&:close) # Windows cannot delete an open database file
    end
  end

  # ---- authorize(plans:) -----------------------------------------------------------------------------------------------

  def fixture
    c = FIX['cases'].find { |x| x['name'] == 'envelope-max-spend-within' }
    [c, c['steps'][0]]
  end

  def run_authorize(c, s, plans, plan: nil)
    AtlasPca.authorize(Marshal.load(Marshal.dump(s['pcactn'])), operation: s['operation'], audience: FIX['audience'],
                                                                 resolve_grant: ->(_r) { c['grant'] }, state_store: AtlasPca::MemoryStateStore.new,
                                                                 is_revoked: ->(_p, _g) { false }, now: FIX['now'], plan: plan, plans: plans,
                                                                 provenance: ProvHarness::OPTION)
  end

  def test_an_unregistered_plan_is_refused_by_name
    c, s = fixture
    r = run_authorize(c, s, AtlasPca::PlanRegistry.new)
    refute r.allow
    assert_equal 'fail', r.checks['plan_state']
    assert_equal 'fail', r.checks['plan_root_authorized']
    assert_includes r.reasons, "plan_state: plan #{s['pcactn']['plan']['root']} is unknown to the plan registry"
  end

  def test_a_registered_plan_is_executable_only_once_authorized
    c, s = fixture
    p = s['pcactn']
    node = { 'id' => p['plan']['node_id'], 'verb' => p['action']['verb'], 'resource' => p['action']['resource'],
             'params_digest' => p['action']['params_digest'], 'reversibility_class' => p['action']['reversibility_class'] }
    reg = AtlasPca::PlanRegistry.new(now: -> { FIX['now'] })
    assert_equal p['plan']['root'], AtlasPca.plan_root([node]), 'the fixture plan is a single-step plan'
    gid = c['grant']['id']
    root = reg.draft(gid, [node])['record']['root']
    [reg.method(:validate), reg.method(:commit)].each { |step| assert step.call(gid, root)['ok'] }
    committed = run_authorize(c, s, reg)
    refute committed.allow
    assert_equal 'fail', committed.checks['plan_state']
    assert_includes committed.reasons.join(' '), 'committed but not authorized by the principal'
    assert reg.authorize(gid, root, { 'by' => 'principal' })['ok']
    ok = run_authorize(c, s, reg)
    assert ok.allow
    assert_equal %w[pass pass], [ok.checks['plan_state'], ok.checks['plan_root_authorized']]
    assert reg.revoke(gid, root, 'changed my mind')['ok']
    again = run_authorize(c, s, reg)
    refute again.allow
    assert_equal 'fail', again.checks['plan_state']
  end
end
