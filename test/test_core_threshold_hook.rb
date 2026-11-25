# frozen_string_literal: true

# The optional core threshold hook is tri-state (enforced+ok, enforced+refused, not enforced) and invisible when absent.
#   ruby -Ilib test/test_core_threshold_hook.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestCoreThresholdHook < Minitest::Test
  NOW = 1_800_000_000_000

  def signed
    @signed ||= begin
      principal = AtlasPca::KeyPair.generate
      key = AtlasPca::KeyPair.generate
      env = { 'predicates' => [{ 'verb' => 'refund', 'resource' => 'orders/*' }], 'caveats' => [], 'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
      grant = AtlasPca.mint_grant(principal, key.public, env, 'g')['grant']
      [AtlasPca::Agent.new(key, grant, 'rs-hook').act('refund', 'orders/1').pcactn, grant]
    end
  end

  def core(hook)
    pc, grant = signed
    AtlasPca.verify_pcactn(pc, grant, now: pc['iat'], audience: 'rs-hook', insecure_skip_plan_root_check: true, threshold_hook: hook)
  end

  def test_no_hook_reports_no_threshold_check
    v = core(nil)
    assert v.allow
    refute v.checks.key?('threshold')
  end

  def test_enforced_ok_passes
    v = core(->(_ctx) { { 'enforced' => true, 'ok' => true } })
    assert v.allow
    assert_equal true, v.checks['threshold']
  end

  def test_enforced_refusal_denies_with_the_reason
    v = core(->(_ctx) { { 'enforced' => true, 'ok' => false, 'reason' => 'quorum short' } })
    refute v.allow
    assert_equal false, v.checks['threshold']
    assert_equal 'threshold: quorum short', v.reason
  end

  def test_not_enforced_reports_nothing
    v = core(->(_ctx) { { 'enforced' => false } })
    assert v.allow
    refute v.checks.key?('threshold')
  end
end
