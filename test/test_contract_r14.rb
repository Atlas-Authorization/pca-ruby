# frozen_string_literal: true

# Reference contract update: platform-deterministic immune decay (no pow), the no-widen number-type check, an unrepresentable clock
# refused in the SD-JWT verifier, and the freshness windows written as the negation of the positive condition.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestContractR14 < Minitest::Test
  I = AtlasPca::Immune
  STEP = 0.9993233275026507

  # the contract, written out independently: whole 1/1024ths of a half-life, 0.5 steps then STEP steps, one multiplication at a time
  def reference(count, dt, hl)
    u = (dt.to_f * 1024 / hl).floor
    f = 1.0
    (u / 1024).times { f *= 0.5 }
    (u % 1024).times { f *= STEP }
    count * f
  end

  def test_decay_is_the_repeated_multiplication
    hl = 3_600_000
    [[1.0, hl], [7.0, hl * 2], [3.0, (hl * 1.5).to_i], [5.0, 1], [5.0, 3500], [2.0, (hl * 37.3).to_i], [1.0, hl * 0.001]].each do |c, dt|
      assert_equal reference(c, dt, hl), I.decay(c, dt, hl), "count=#{c} dt=#{dt}"
    end
    assert_equal 0.5, I.decay(1.0, hl, hl)
    assert_equal 0.25, I.decay(1.0, 2 * hl, hl)
  end

  def test_decay_edges
    assert_equal 4.0, I.decay(4.0, 0, 1000)
    assert_equal 4.0, I.decay(4.0, -5, 1000)
    assert_equal 0.0, I.decay(1.0, 2000 * 3_600_000, 3_600_000)
    assert_predicate I.decay(1.0, 1000, Float::NAN), :nan?
  end

  def test_no_widen_refuses_a_value_that_is_not_a_number
    base = { 'kappa' => 1, 'theta1' => 0.3, 'theta2' => 0.6, 'lambda' => 0, 'rho' => 0, 'bMax' => 1, 'weights' => {} }
    assert_nil I.no_widen_violation(base, base.merge('kappa' => 2))
    [nil, true, false, '2'].each do |bad|
      %w[kappa theta1 theta2].each do |k|
        assert_equal 'kappa and theta must be numbers', I.no_widen_violation(base, base.merge(k => bad)), "#{k}=#{bad.inspect}"
      end
    end
  end

  def test_sdjwt_refuses_an_unrepresentable_now
    [8.65e15, -8.65e15, 1e300].each do |now|
      r = AtlasPca::SdJwt.verify_pca_sd_jwt('x', { 'now' => now })
      assert_equal 'now is not a representable time', r['reason'], now.to_s
    end
    assert_equal 'now, clockToleranceSec and kbMaxAgeSec must be finite', AtlasPca::SdJwt.verify_pca_sd_jwt('x', { 'now' => Float::INFINITY })['reason']
  end

  def test_freshness_windows_refuse_a_nan_operand
    a = AtlasPca::Attestation
    nan = Float::NAN
    assert_equal 'nonce issued in the future', a.nonce_age_reason(1, nan, 0, 10)
    assert_equal 'attestation nonce expired (stale quote)', a.nonce_age_reason(1, 5, 0, nan)
    assert_nil a.nonce_age_reason(1, 5, 0, 10)
    assert_equal :notyet, a.window_decision(nan, 0, 1, 10)
    assert_equal :expired, a.window_decision(5, nan, 1, 10)
    assert_equal :valid, a.window_decision(5, 0, 1, 10)
  end
end

class TestBondPowerCurve < Minitest::Test
  B = AtlasPca::BondSettlement

  def test_pow_eighths_uses_only_multiplication_and_sqrt
    assert_equal 8.0, B.pow_eighths(2, 3)
    assert_equal 2.0**0.5, B.pow_eighths(2.0, 1.0 / 8 * 4)
    assert_equal Math.sqrt(Math.sqrt(3.0)) * 3.0, B.pow_eighths(3.0, 1.25)
    assert_equal 1.0, B.pow_eighths(1.0, 64)
  end

  def test_a_gamma_that_is_not_an_eighth_or_above_64_is_refused
    [1.3, 1.01, 64.125, 65, 100].each do |g|
      e = assert_raises(ArgumentError) { B.pow_eighths(2.0, g) }
      assert_equal 'bondAmount: power curve gamma must be a multiple of 1/8 and at most 64', e.message, g.to_s
    end
  end
end
