# frozen_string_literal: true

# Differential replay of the TypeScript reference (@atlasauth/pca-store-conformance): the register model, the budgeted linearizability
# search and per-key checker, the history parser, the workload PRNG, report folding and the check inventories of the profiles; plus
# native runs of the kit against good and bad reference stores (a checker that passes everything is worthless).
#
# In the vectors a non-finite number is the object {"$num": "Infinity" | "-Infinity"} (an operation with an unknown outcome has ret
# Infinity); a report's JSON text is compared as text.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/store_conformance_model'
require_relative '../lib/atlas_pca/store_conformance_runner'
require_relative '../lib/atlas_pca/store_conformance_profiles'
require 'minitest/autorun'

class TestRefStoreConformance < Minitest::Test
  M = AtlasPca::StoreConformanceModel
  P = AtlasPca::StoreConformanceProfiles
  R = AtlasPca::StoreConformanceRunner
  BY_FN = Ref.load('store-conformance')

  # {"$num": ...} -> the non-finite number, recursively.
  def self.num(v)
    case v
    when Array then v.map { |x| num(x) }
    when Hash
      if v.length == 1 && v['$num'].is_a?(String)
        { 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.fetch(v['$num'], Float::NAN)
      else
        v.transform_values { |x| num(x) }
      end
    else v
    end
  end

  def self.with_ops(fn) = ->(ops, *rest) { fn.call(num(ops), *rest) }

  def self.inventory(profile)
    keep = ->(cs) { cs.map { |c| { 'name' => c.name, 'claim' => c.claim, 'needs' => c.needs } } }
    case profile
    when 'lease' then keep.call(P::GUARDIAN_LEASE_CHECKS)
    when 'ledger' then keep.call(P::LEDGER_CHECKS)
    when 'budget' then keep.call(P::BUDGET_CHECKS)
    when 'bond' then keep.call(P::BOND_CHECKS)
    else
      kw = {}
      kw[:reopen] = ->(s) { s } if profile.include?('+reopen')
      kw[:damage] = ->(_s) {} if profile.include?('+damage')
      P.mesh_witness_store_cases(P::MeshWitnessStoreAdapter.new(name: 'x', make: -> {}, **kw)).map(&:name)
    end
  end

  # every case of the reference, in the reference's order (the witness-driven ones run a real MeshWitness)
  INVENTORY_EQUAL = lambda do |got, out, _c|
    if out.is_a?(Array) && out.first.is_a?(String)
      got == out
    else
      Ref.canon(got) == Ref.canon(out)
    end
  end

  MAP = {
    'step' => ->(s, op) { M.step(num(s), num(op)) },
    'overlappingTrues' => with_ops(M.method(:overlapping_trues)),
    'prune' => with_ops(M.method(:prune)),
    'fastCheck' => with_ops(M.method(:fast_check)),
    'search' => with_ops(M.method(:search_linearizable)),
    'decideKey' => with_ops(M.method(:decide_key)),
    'minimize' => with_ops(M.method(:minimize)),
    'formatOps' => with_ops(M.method(:format_ops)),
    'checkKey' => ->(ops, opts = nil) { M.check_key(num(ops), Ref.snake(opts)) },
    'checkHistory' => ->(ops, opts = nil) { M.check_history(num(ops), Ref.snake(opts)) },
    'deletion' => ->(ops, i) { num(ops).then { |d| M.deletion(d, d[i]) } },
    'parseHistory' => ->(text) { M.parse_history(text) },
    'prng' => ->(seed, ns) { M.prng(seed).then { |r| ns.map { |n| r.call(n) } } },
    'overall' => lambda { |x|
      x = num(x)
      M.overall(x.is_a?(Hash) ? x['tests'] : x.map { |s| { 'status' => s } })
    },
    'formatReport' => ->(r, k) { M.format_report(num(r), k) },
    'reportJson' => ->(r) { M.report_json(num(r)) },
    'inventory' => ->(profile) { inventory(profile) }
  }.freeze

  def test_every_function_is_covered
    assert_equal [], BY_FN.keys - MAP.keys, 'corpus functions without a replay'
    assert_equal [], MAP.keys - BY_FN.keys
    assert_operator BY_FN.values.sum(&:length), :>, 2000
  end

  MAP.each_key do |fn|
    define_method("test_replay_#{fn}") do
      cmp = fn == 'inventory' ? INVENTORY_EQUAL : nil
      Ref.run(self, BY_FN[fn], MAP[fn], compare: cmp)
    end
  end

  # ---- native runs of the kit ----------------------------------------------------------------------------------------

  SMALL = { 'clients' => 4, 'duration_ms' => 150, 'rounds' => 6, 'revisit_keys' => 24, 'op_timeout_ms' => 2000 }.freeze

  def statuses(report) = report['tests'].to_h { |t| [[t['test'], t['kind']], t['status']] }

  def test_good_stores_pass
    [R.in_memory_adapter, R.durable_file_adapter].each do |a|
      r = R.run_conformance(a, SMALL)
      assert_equal 'pass', r['status'], R.format_report(r)
    end
    assert_equal 'skip', statuses(R.run_conformance(R.in_memory_adapter, SMALL))[%w[durability consume]]
  rescue LoadError
    skip 'sqlite3 gem not installed'
  end

  def test_a_non_strict_counter_is_flagged
    r = R.run_conformance(R.non_strict_counter_adapter, SMALL.merge('tests' => ['burst'], 'values' => 1))
    assert_equal 'fail', r['status'], R.format_report(r)
  end

  def test_a_volatile_store_is_flagged_by_durability
    r = R.run_conformance(R.volatile_adapter, SMALL.merge('tests' => ['durability']))
    assert_equal 'fail', r['status'], R.format_report(r)
  end

  def test_an_evicting_store_is_flagged_by_retention
    r = R.run_conformance(R.evicting_adapter(4), SMALL.merge('tests' => ['retention'], 'revisit_keys' => 40))
    assert_equal 'fail', r['status'], R.format_report(r)
  end

  def test_a_read_then_write_store_is_flagged
    r = R.run_conformance(R.read_then_write_adapter, SMALL.merge('tests' => ['burst'], 'clients' => 8, 'rounds' => 30))
    assert_equal 'fail', r['status'], R.format_report(r)
  end

  def test_the_crash_test_is_reported_as_skipped
    assert_equal 'skip', statuses(R.run_conformance(R.in_memory_adapter, SMALL.merge('tests' => ['crash'])))[%w[crash advance]]
  end

  class MemLease
    def initialize(shared) = (@shared = shared)

    def read = @shared[:lock].synchronize { @shared[:rec]&.dup }
    def now = (Time.now.to_f * 1000).to_i

    def cas(expected, nxt)
      @shared[:lock].synchronize do
        cur = @shared[:rec]
        same = (cur.nil? && expected.nil?) || (!cur.nil? && !expected.nil? && %w[holder epoch expiresAt].all? { |k| cur[k] == expected[k] })
        return false if !same || nxt['epoch'] < (cur ? cur['epoch'] : 0)

        @shared[:rec] = nxt.dup
        true
      end
    end
  end

  def lease_adapter(durable: true)
    create = lambda do
      shared = { rec: nil, lock: Mutex.new }
      P::StoreHandle.new(MemLease.new(shared), -> { MemLease.new(shared) }, -> { MemLease.new(shared) })
    end
    P::ProfileAdapter.new('in-memory lease store', create, durable)
  end

  def test_a_correct_lease_store_passes_the_lease_profile
    r = P.run_guardian_lease_store_conformance(lease_adapter)
    assert_equal 'pass', r['status'], P.format_lease_report(r)
    assert_empty(r['checks'].select { |c| c['status'] == 'skip' })
    assert_equal %w[pass skip], P.run_guardian_lease_store_conformance(lease_adapter(durable: false))['checks'].map { |c| c['status'] }.uniq.sort
  end

  def test_a_lease_store_without_compare_and_swap_is_flagged
    no_cas = Class.new(MemLease) do
      def cas(_expected, nxt)
        @shared[:lock].synchronize { @shared[:rec] = nxt.dup }
        true
      end
    end
    create = lambda do
      shared = { rec: nil, lock: Mutex.new }
      P::StoreHandle.new(no_cas.new(shared), -> { no_cas.new(shared) })
    end
    r = P.run_guardian_lease_store_conformance(P::ProfileAdapter.new('BAD no cas', create, true),
                                               %w[wrong-expected-record-never-writes racing-acquirers-have-one-winner])
    assert_equal 'fail', r['status'], P.format_lease_report(r)
  end

  class MemMesh
    attr_reader :backing

    def initialize(backing) = (@backing = backing)

    def load
      raise 'damaged storage' if @backing[:damaged]

      Marshal.load(Marshal.dump(@backing[:state]))
    end

    def save(state) = (@backing[:state] = Marshal.load(Marshal.dump(state)))
  end

  def test_mesh_witness_store_cases
    ok = P::MeshWitnessStoreAdapter.new(name: 'memory', make: -> { MemMesh.new({}) }, reopen: ->(s) { MemMesh.new(s.backing) },
                                        damage: ->(s) { s.backing[:damaged] = true })
    r = P.run_mesh_witness_store_conformance(ok)
    assert_equal 'pass', r['status'], r.inspect
    assert_equal 10, r['checks'].length

    aliasing = Class.new(MemMesh) { def load = @backing[:state] }
    bad = P::MeshWitnessStoreAdapter.new(name: 'aliasing', make: -> { aliasing.new({}) })
    assert_equal 'fail', P.run_mesh_witness_store_conformance(bad)['status']
  end
end
