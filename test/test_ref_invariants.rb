# frozen_string_literal: true

# Replays the TS-reference oracle of the invariant harness (test-data/ref-invariants.json.gz): key pairs from seeds, the legal-chain
# builder, the risk `worsen` helper and the registry constants; plus a small run of the property-based checks themselves.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/invariants'
require 'minitest/autorun'

class TestRefInvariants < Minitest::Test
  I = AtlasPca::Invariants
  BY_FN = Ref.load('invariants')

  # bytes are compared as {"$bytes"} whatever their UTF-8 validity
  def self.bytes(s) = { '$bytes' => Ref.b64e(s) }

  MAP = {
    'keyPairFromSeed' => lambda do |seed|
      p = I.key_pair_from_seed(seed)
      { 'secretKey' => bytes(p['secret_key']), 'publicKey' => bytes(p['public_key']), 'pub' => p['pub'] }
    end,
    'buildChain' => lambda do |m|
      c = I.build_chain({ 'principal_seed' => m['principalSeed'], 'holder0_seed' => m['holder0Seed'], 'root_specs' => m['rootSpecs'],
                          'hops' => m['hops'].map { |h| { 'holder_seed' => h['holderSeed'], 'added_specs' => h['addedSpecs'] } },
                          'predicates' => m['predicates'] })
      { 'caps' => c['caps'], 'predicates' => c['predicates'], 'rootIssuer' => c['root_issuer'], 'holders' => c['holders'] }
    end,
    'worsen' => ->(base, d) { I.worsen(base, d) },
    'consts' => lambda do
      { 'DEFAULT_SEED' => I::DEFAULT_SEED, 'DEFAULT_NUM_RUNS' => I::DEFAULT_NUM_RUNS, 'INVARIANT_NAMES' => I::INVARIANTS.map(&:name) }
    end
  }.freeze

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) } }

  def test_every_invariant_holds_on_the_core
    results = I.check_invariants({ 'num_runs' => 8, 'seed' => 20_260_108 })
    assert_equal I::INVARIANTS.map(&:name), results.map { |r| r['name'] }
    assert_equal [], results.reject { |r| r['ok'] }
    assert(results.all? { |r| r['numRuns'] == 8 && r['seed'] == 20_260_108 })
  end

  def test_bail_stops_at_the_first_failure
    ok = AtlasPca::Invariants::Invariant.new('a', -> { ->(_rng) { true } })
    boom = AtlasPca::Invariants::Invariant.new('b', -> { ->(_rng) { false } })
    reg = [ok, boom, AtlasPca::Invariants::Invariant.new('c', -> { ->(_rng) { true } })]
    assert_equal [true, false, true], I.check_invariants({ 'num_runs' => 2, 'seed' => 1, 'invariants' => reg }).map { |r| r['ok'] }
    res = I.check_invariants({ 'num_runs' => 2, 'seed' => 1, 'bail' => true, 'invariants' => reg })
    assert_equal %w[a b], res.map { |r| r['name'] }
    assert_includes res[1]['error'], 'seed 1'
  end

  def test_refuses_a_vacuous_or_malformed_run
    [{ 'num_runs' => 0 }, { 'num_runs' => -1 }, { 'num_runs' => 1.5 }, { 'num_runs' => '5' }, { 'num_runs' => true },
     { 'num_runs' => 2, 'seed' => 1.5 }, { 'num_runs' => 2, 'seed' => '1' }].each do |o|
      assert_raises(ArgumentError) { I.check_invariants(o) }
    end
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 312, BY_FN.values.sum(&:length), 'invariants'
  end

end
