# frozen_string_literal: true

# The deterministic math of the reference contract: integer arithmetic only, one final round-to-nearest-even conversion.
require_relative '../lib/atlas_pca/detmath'
require_relative '../lib/atlas_pca/wallet'
require 'minitest/autorun'

class TestDetMath < Minitest::Test
  D = AtlasPca::DetMath

  def ulps_ok?(got, want, scale = want.abs) = (got - want).abs <= 4 * Float::EPSILON * scale

  def test_ln_exact_and_special_values
    assert_equal 0.0, D.det_ln(1)
    [0, 0.0, -0.0].each { |x| assert_equal(-Float::INFINITY, D.det_ln(x), x.to_s) }
    [-1, -0.5, Float::NAN].each { |x| assert_predicate D.det_ln(x), :nan?, x.to_s }
    assert_equal Float::INFINITY, D.det_ln(Float::INFINITY)
    assert_equal 4.605170185988092, D.det_ln(100)
    assert_equal(-0.6931471805599453, D.det_ln(0.5))
  end

  def test_ln_agrees_with_libm_to_a_few_ulps
    [2.0, 0.5, 100.0, 1e-5, 0.9, 1.1, 3.0, 1e10, 1e-300, 1e300, 5e-324, Float::MAX].each do |x|
      assert ulps_ok?(D.det_ln(x), Math.log(x)), x.to_s
    end
  end

  def test_log2_of_a_power_of_two_is_its_exponent
    [-1074, -1022, -10, -1, 0, 1, 3, 52, 1023].each { |e| assert_equal e.to_f, D.det_log2(Math.ldexp(1.0, e)), e.to_s }
    assert_predicate D.det_log2(-1), :nan?
    [0, 0.0, -0.0].each { |x| assert_equal(-Float::INFINITY, D.det_log2(x), x.to_s) }
    assert_equal Float::INFINITY, D.det_log2(Float::INFINITY)
    [0.3, 0.5, 0.9, 1.5, 3.0, 100.0, 1e-9].each { |x| assert ulps_ok?(D.det_log2(x), Math.log2(x), [1, Math.log2(x).abs].max), x.to_s }
  end

  def test_exp
    assert_equal 1.0, D.det_exp(0)
    assert_equal Float::INFINITY, D.det_exp(710)
    assert_equal 0.0, D.det_exp(-746)
    assert_equal 0.0, D.det_exp(-Float::INFINITY)
    assert_equal Float::INFINITY, D.det_exp(Float::INFINITY)
    # a prior-mix cell with q = 0 or 1 weighs 0, not NaN: exp(0 * ln 0 + ...) with the log at -Infinity
    assert_equal 0.0, D.det_exp(D.det_ln(0))
    assert_predicate D.det_exp(Float::NAN), :nan?
    assert_equal 2.718281828459045, D.det_exp(1)
    [1, -1, 0.5, -0.5, 10, -10, 100, -100, 700, -700, 1e-10, -1e-10].each { |x| assert ulps_ok?(D.det_exp(x), Math.exp(x)), x.to_s }
  end

  def test_pow_int_multiplies_in_sequence
    assert_equal 1024.0, D.det_pow_int(2, 10)
    assert_equal 0.125, D.det_pow_int(0.5, 3)
    assert_equal 1.0, D.det_pow_int(7, 0)
  end

  def test_division_truncates_toward_zero
    assert_equal(-3, D.tdiv(-7, 2))
    assert_equal(-3, D.tdiv(7, -2))
    assert_equal 3, D.tdiv(7, 2)
  end

  def test_the_double_conversion_rounds_to_nearest_even
    assert_equal 2.0**53, D.to_double((1 << 53) + 1) # a tie goes to the even neighbour
    assert_equal (2.0**53) + 4, D.to_double((1 << 53) + 3)
    assert_equal(-(2.0**53), D.to_double(-((1 << 53) + 1)))
  end

  def test_beta_upper_exact_is_the_clopper_pearson_inversion
    w = AtlasPca::Wallet
    [[0.05, 3, 4], [0.01, 1, 1], [0.1, 10, 25]].each do |d, a, b|
      assert_equal w.clopper_pearson_upper(a - 1, a + b - 1, d), w.beta_upper_exact(d, a, b), "#{d} #{a} #{b}"
    end
    [[0, 1], [1, 0], [1.5, 2], [2, -1]].each { |a, b| assert_raises(RangeError, "#{a} #{b}") { w.beta_upper_exact(0.05, a, b) } }
  end
end
