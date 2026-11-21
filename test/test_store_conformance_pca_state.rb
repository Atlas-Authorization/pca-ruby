# frozen_string_literal: true

# The pca-state profile: the good reference stores pass through the real guard and the planted-bug stores are caught.
require_relative '../lib/atlas_pca'
require_relative '../lib/atlas_pca/store_conformance_pca_state'
require_relative '../lib/atlas_pca/store_conformance_cli'
require 'minitest/autorun'
require 'tmpdir'

class TestStoreConformancePcaState < Minitest::Test
  P = AtlasPca::StoreConformancePcaState

  SQLITE = begin
    require 'sqlite3'
    true
  rescue LoadError
    false
  end

  def status_of(report, test) = report['tests'].find { |t| t['test'] == test }['status']

  def test_fixture_proofs_are_real_signed_pcactns
    fx = P.fixture(3)
    assert_equal [1, 2, 3], fx['proofs'].map { |p| p['counter'] }
    g = P.guard(fx, AtlasPca::MemoryStateStore.new)
    assert_equal %w[admitted replay admitted], [g.call(1), g.call(1), g.call(2)]
  end

  def test_the_in_memory_store_passes_what_it_can_and_skips_the_rest
    r = P.run(P.builtin('in-memory', {}), rounds: 3, copies: 8)
    assert_equal 'pass', r['status'], P.format_report(r)
    assert_equal 'skip', status_of(r, 'instances')
    assert_equal 'skip', status_of(r, 'processes')
    assert_equal 'pass', status_of(r, 'one-instance')
    assert_equal 'pass', status_of(r, 'retry-after-timeout')
  end

  def test_a_claim_that_reads_then_writes_admits_two
    r = P.run(P.builtin('bad-read-then-write-claim', {}), tests: %w[one-instance], rounds: 3, copies: 8)
    assert_equal 'fail', r['status'], P.format_report(r)
  end

  def test_a_store_that_forgets_on_restart_fails_the_crash_test
    r = P.run(P.builtin('bad-volatile', {}), tests: %w[crash-after-claim])
    assert_equal 'fail', r['status'], P.format_report(r)
  end

  def test_the_durable_file_store_passes_in_processes_too
    skip 'sqlite3 gem not installed' unless SQLITE
    Dir.mktmpdir('pcasc-test-') do |dir|
      opts = { 'dir' => dir }
      r = P.run(P.builtin('durable-file', opts), spec: 'builtin:durable-file', options: opts, rounds: 3, copies: 4, processes: 2)
      assert_equal 'pass', r['status'], P.format_report(r)
    end
  end

  def test_the_cli_runs_the_profile
    out = []
    code = AtlasPca::StoreConformanceCli.main(%w[--adapter builtin:in-memory --profile pca-state --tests one-instance --rounds 2 --clients 4], ->(s) { out << s }, ->(s) { out << s })
    assert_equal 0, code, out.join("\n")
    assert_includes out.join, 'one-instance'
  end
end
