# frozen_string_literal: true

# The store-conformance helper: it passes the stores this package ships and FAILS stores that are broken (a guard that has
# never failed proves nothing). The SQLite checks need the sqlite3 gem (skipped without it).
#   ruby -Ilib test/test_store_conformance.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'
require 'tmpdir'

class TestStoreConformance < Minitest::Test
  SQLITE = begin
    require 'sqlite3'
    true
  rescue LoadError
    false
  end

  def statuses(report) = report.results.to_h { |r| [r.test, r.status] }

  # claim = read, wait, write: two callers both read the old value and both win.
  class RacyStateStore
    def initialize(data) = (@d = data)

    def claim(key, counter)
      last = @d[key]
      sleep 0.002
      return AtlasPca::ClaimResult.new(false, last) if !last.nil? && counter <= last

      @d[key] = counter
      AtlasPca::ClaimResult.new(true)
    end
  end

  class AliasingStore < AtlasPca::MemoryOperationStore
    def get(id) = @m[id] # hands out the stored record itself
  end

  class NonAtomicStore < AtlasPca::MemoryOperationStore
    def create(record)
      cur = @m[record['id']]
      sleep 0.002
      return cur.dup unless cur.nil?

      @m[record['id']] = record.dup
      nil
    end
  end

  class LooseCasStore < AtlasPca::MemoryOperationStore
    def transition(id, _from_state, next_record)
      return false if @m[id].nil?

      sleep 0.002
      @m[id] = next_record.merge('id' => id) # ignores the compare
      true
    end
  end

  def test_memory_store_passes_as_process_local
    shared = AtlasPca::MemoryStateStore.new
    r = AtlasPca.run_state_store_conformance(-> { shared }, durable: false, shared: false)
    assert r.ok?, r.render
    assert_equal({ 'claim-sequence' => 'pass', 'claim-burst' => 'pass', 'claim-concurrent' => 'skip', 'claim-durability' => 'skip',
                   'crash-after-claim' => 'skip' }, statuses(r))
  end

  def test_sqlite_store_passes_every_test
    skip 'sqlite3 gem not installed' unless SQLITE
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'replay.db')
      stores = []
      begin
        r = AtlasPca.run_state_store_conformance(-> { AtlasPca::SqliteStateStore.new(path).tap { |s| stores << s } })
        assert r.ok?, r.render
        assert_equal ['pass'], statuses(r).values.uniq
      ensure
        stores.each(&:close) # Windows cannot unlink an open sqlite file
      end
    end
  end

  def test_a_racy_store_fails_the_burst
    data = {}
    r = AtlasPca.run_state_store_conformance(-> { RacyStateStore.new(data) }, durable: false, shared: false)
    refute r.ok?
    assert_equal 'fail', statuses(r)['claim-burst']
    assert_includes r.results.find { |x| x.test == 'claim-burst' }.note, 'want exactly 1'
  end

  def test_a_store_that_forgets_claims_across_handles_fails_durability_and_crash
    r = AtlasPca.run_state_store_conformance(-> { AtlasPca::MemoryStateStore.new }) # a fresh store per handle, declared durable and shared
    s = statuses(r)
    refute r.ok?
    assert_equal %w[fail fail fail], [s['claim-concurrent'], s['claim-durability'], s['crash-after-claim']]
  end

  def test_a_store_without_claim_is_reported
    r = AtlasPca.run_state_store_conformance(-> { Object.new })
    refute r.ok?
    assert(r.results.select { |x| %w[claim-sequence claim-burst].include?(x.test) }.all? { |x| x.status == 'fail' })
  end

  def test_operation_stores_pass
    shared = AtlasPca::MemoryOperationStore.new
    r = AtlasPca.run_operation_store_conformance(-> { shared }, durable: false, shared: false)
    assert r.ok?, r.render
    assert_equal %w[skip skip], [statuses(r)['cross-handle'], statuses(r)['durability']]
    skip 'sqlite3 gem not installed' unless SQLITE
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'ops.db')
      r = AtlasPca.run_operation_store_conformance(-> { AtlasPca.sqlite_operation_store(path) })
      assert r.ok?, r.render
      assert_equal ['pass'], statuses(r).values.uniq
    end
  end

  def test_broken_operation_stores_fail
    [[AliasingStore, 'copies'], [NonAtomicStore, 'create-race'], [LooseCasStore, 'semantics']].each do |cls, test|
      s = cls.new
      r = AtlasPca.run_operation_store_conformance(-> { s }, durable: false, shared: false)
      refute r.ok?, cls.name
      assert_equal 'fail', statuses(r)[test], "#{cls.name}: #{r.render}"
    end
  end
end
