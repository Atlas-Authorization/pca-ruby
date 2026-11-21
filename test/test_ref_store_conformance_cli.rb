# frozen_string_literal: true

# Differential replay of the store conformance kit's command line (argument parsing, usage text, usage-path exit codes) against the
# TypeScript reference (@atlasauth/pca-store-conformance), plus native runs of the adapter loader and the multi-process crash harness.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/store_conformance_cli'
require_relative '../lib/atlas_pca/store_conformance_crash'
require 'minitest/autorun'
require 'tmpdir'

class TestRefStoreConformanceCli < Minitest::Test
  C = AtlasPca::StoreConformanceCli
  L = AtlasPca::StoreConformanceLoad
  R = AtlasPca::StoreConformanceRunner
  BY_FN = Ref.load('store-conformance-java')

  def test_every_function_is_covered
    assert_equal %w[consts main parseCli], BY_FN.keys.sort
  end

  def test_consts
    Ref.run(self, BY_FN['consts'], -> { { 'DEFAULT_SEARCH_BUDGET' => 200_000, 'ALL_TESTS' => R::ALL_TESTS, 'USAGE' => C::USAGE } })
  end

  def test_parse_cli
    # the reference's own failures are thrown Errors: a refusal here is an ArgumentError
    Ref.run(self, BY_FN['parseCli'], ->(argv) { C.parse_cli(argv) })
  end

  def test_main_usage_paths
    run = lambda do |argv|
      out = []
      err = []
      code = C.main(argv, out.method(:<<), err.method(:<<))
      { 'code' => code, 'out' => out, 'err' => err }
    end
    Ref.run(self, BY_FN['main'], run)
  end

  # ---- native: loader and crash harness ------------------------------------------------------------------------------

  def test_builtin_adapters_load_and_unknown_is_refused
    assert L.load_adapter('builtin:in-memory').name.start_with?('in-memory')
    assert_raises(ArgumentError) { L.load_adapter('builtin:nope') }
  end

  def test_a_file_adapter_loads_by_constant
    Dir.mktmpdir do |d|
      good = File.join(d, 'ad.rb')
      File.write(good, "PcaStoreAdapter = ->(_options) { AtlasPca::StoreConformanceRunner.in_memory_adapter }\n")
      assert L.load_adapter(good).name.start_with?('in-memory')
      bad = File.join(d, 'bad.rb')
      File.write(bad, "PcaStoreAdapter = ->(_options) { Object.new }\n")
      assert_raises(TypeError) { L.load_adapter(bad) }
    end
  end

  def test_cli_flags_a_bad_store
    out = []
    code = C.main(%w[--adapter builtin:bad-non-strict-counter --clients 8 --rounds 20 --values 1 --tests burst], out.method(:<<), out.method(:<<))
    assert_equal 1, code, out.join("\n")
  end

  def test_crash_harness_kills_workers_and_the_history_checks_out
    require 'sqlite3'
    Dir.mktmpdir do |d|
      w = AtlasPca::StoreConformanceCrash.run_crash(
        'advance', 'module' => 'builtin:durable-file', 'options' => { 'dir' => d }, 'processes' => 2, 'clients' => 2, 'duration_ms' => 1500,
        'kill_every_ms' => 300, 'op_timeout_ms' => 2000, 'seed' => 5, 'dir' => Dir.mktmpdir(nil, d)
      )
      assert_operator w['kills'], :>=, 1
      assert_operator w['processes'], :>=, 3
      refute_empty w['ops']
      assert_includes %w[pass unresolved], R.judge('crash', 'advance', w, {})['status']
    end
  rescue LoadError
    skip 'sqlite3 gem not installed'
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 49, BY_FN.values.sum(&:length), 'store-conformance-java'
  end

end
