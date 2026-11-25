# frozen_string_literal: true

# The experimental lattice-threshold toy (NOT PRODUCTION): the reference's vectors (opt-in gate, banner, additive n-of-n sharing, exact reasons).
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestPqThresholdExperimental < Minitest::Test
  X = AtlasPca::PqThreshold::Experimental
  OPT_IN = { 'iUnderstandThisIsNotProduction' => true }.freeze
  Q = X::TOY_DEFAULT_PARAMS['q']
  ZERO = ->(_q) { 0 }

  # the reference's deterministic seeded sampler (a 64-bit LCG)
  def seeded
    state = 0x12345678
    lambda do |q|
      state = (state * 6_364_136_223_846_793_005 + 1_442_695_040_888_963_407) & ((1 << 64) - 1)
      state % q
    end
  end

  def test_banner_and_frozen_design
    assert_match(/NOT PRODUCTION/, X::EXPERIMENTAL_BANNER)
    d = X::RACCOON_DESIGN
    assert_equal [false, 'research-prototype'], [d['productionReady'], d['status']]
    assert_match(/NOT PRODUCTION/, d['banner'])
    refute_empty d['construction']
    assert_match(/HYBRID/, d['shippableAlternative'])
    assert_predicate d, :frozen?
    assert_equal [8_380_417, 4], [Q, X::TOY_DEFAULT_PARAMS['dim']]
  end

  def test_nothing_runs_without_the_opt_in
    key = [1, 2, 3, 4]
    no = { 'iUnderstandThisIsNotProduction' => false }
    assert_raises(ArgumentError) { X.additive_share_lattice_key(key, 3, no) }
    assert_raises(ArgumentError) { X.additive_share_lattice_key(key, 3, nil) }
    shares = X.additive_share_lattice_key(key, 3, OPT_IN, X::TOY_DEFAULT_PARAMS, seeded)
    err = assert_raises(ArgumentError) { X.reconstruct_lattice_key(shares, no) }
    assert_match(/NOT PRODUCTION/, err.message)
  end

  def test_reconstruct_sums_all_shares_and_a_missing_share_does_not
    key = [123, 8_380_416, 0, 42]
    shares = X.additive_share_lattice_key(key, 4, OPT_IN, X::TOY_DEFAULT_PARAMS, seeded)
    assert_equal 4, shares.length
    shares.each { |s| assert_equal 4, s['coeffs'].length }
    assert_equal key.map { |c| c % Q }, X.reconstruct_lattice_key(shares, OPT_IN)
    seven = X.additive_share_lattice_key([7, 7, 7, 7], 3, OPT_IN, X::TOY_DEFAULT_PARAMS, seeded)
    refute_equal [7, 7, 7, 7], X.reconstruct_lattice_key(seven[0, 2], OPT_IN)
  end

  def test_bounds_indices_and_exact_reasons
    key = [1, 2, 3, 4]
    assert_equal 1, X.additive_share_lattice_key(key, 1, OPT_IN, X::TOY_DEFAULT_PARAMS, ZERO).length
    assert_equal 1024, X.additive_share_lattice_key(key, 1024, OPT_IN, X::TOY_DEFAULT_PARAMS, ZERO).length
    [0, 1025, -1, 1.5, Float::NAN].each do |n|
      e = assert_raises(RangeError) { X.additive_share_lattice_key(key, n, OPT_IN, X::TOY_DEFAULT_PARAMS, ZERO) }
      assert_equal 'additiveShareLatticeKey: n must be an integer in [1, 1024]', e.message
    end
    assert_equal 'additiveShareLatticeKey: key must have 4 coefficients', assert_raises(RangeError) { X.additive_share_lattice_key([1], 2, OPT_IN) }.message
    assert_equal 'additiveShareLatticeKey: key must have 3 coefficients',
                 assert_raises(RangeError) { X.additive_share_lattice_key([1, 2], 2, OPT_IN, { 'q' => 97, 'dim' => 3 }) }.message
    assert_equal [1, 2, 3], X.additive_share_lattice_key([0, 0, 0, 0], 3, OPT_IN, X::TOY_DEFAULT_PARAMS, ZERO).map { |s| s['index'] }
  end

  def test_negative_coefficients_reduce_into_range_and_wild_samplers_are_reduced
    s, = X.additive_share_lattice_key([-1, -Q, -Q - 1, 0], 1, OPT_IN, X::TOY_DEFAULT_PARAMS, ZERO)
    assert_equal [Q - 1, 0, Q - 1, 0], s['coeffs']
    assert_equal [Q - 1, 0, Q - 1, 0], X.reconstruct_lattice_key([s], OPT_IN)
    wild = (i = -1
            -> (_q) { (i += 1).even? ? -5 : (3 * Q) + 7 })
    key = [10, 20, 30, 40]
    shares = X.additive_share_lattice_key(key, 4, OPT_IN, X::TOY_DEFAULT_PARAMS, wild)
    assert_equal key, X.reconstruct_lattice_key(shares, OPT_IN)
    shares.each { |sh| sh['coeffs'].each { |c| assert_operator c, :>=, 0; assert_operator c, :<, Q } }
  end

  def test_reconstruct_refusals_and_modular_sum
    assert_equal 'reconstructLatticeKey: need at least one share', assert_raises(RangeError) { X.reconstruct_lattice_key([], OPT_IN) }.message
    s = { 'index' => 1, 'coeffs' => [1, 2, 3, 4] }
    assert_equal 'reconstructLatticeKey: duplicate share index', assert_raises(RangeError) { X.reconstruct_lattice_key([s, s], OPT_IN) }.message
    [[1, 2], [1, 2, 3, 4, 5]].each do |c|
      assert_equal 'reconstructLatticeKey: a share has the wrong dimension',
                   assert_raises(RangeError) { X.reconstruct_lattice_key([{ 'index' => 1, 'coeffs' => c }], OPT_IN) }.message
    end
    a = { 'index' => 1, 'coeffs' => [Q - 1, 1, 0, 5] }
    b = { 'index' => 2, 'coeffs' => [2, Q - 1, 0, 6] }
    assert_equal [1, 0, 0, 11], X.reconstruct_lattice_key([a, b], OPT_IN)
  end
end
