# frozen_string_literal: true

# A clock reading that is not a finite number prunes no lease revocation (NaN made every `revoked_at + ceiling >= now` false, so every
# revocation was dropped and the lease it covered read as live again).
#   ruby -Ilib test/test_lease_nonfinite_prune.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestLeaseNonFinitePrune < Minitest::Test
  FILE = File.expand_path('../conformance/lease-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)
  REV = DOC['revocations'][0] # target "lease", value "L1"

  def held(clock)
    reg = AtlasPca::LeaseRegistry.new({ 'authorities' => [DOC['authority']], 'maxTtlCeiling' => 100 }, AtlasPca::MemoryLeaseKv.new, clock: -> { clock })
    assert_equal true, reg.revoke(REV)['ok']
    (0...reg.shards).flat_map { |i| reg.shard_revocations(i) }.select { |r| r['sig'] == REV['sig'] }
  end

  def test_a_finite_clock_past_the_ceiling_prunes_the_revocation
    assert_empty held(REV['revoked_at'] + 1000)
  end

  def test_a_finite_clock_inside_the_ceiling_keeps_it
    assert_equal 1, held(REV['revoked_at'] + 50).length
  end

  def test_a_non_finite_clock_keeps_the_revocation
    [Float::NAN, Float::INFINITY, -Float::INFINITY].each { |bad| assert_equal 1, held(bad).length, bad.to_s }
  end

  def test_a_plan_with_an_approval_expiry_is_not_executable_on_a_non_finite_clock
    [Float::NAN, Float::INFINITY, -Float::INFINITY].each do |bad|
      t = 1000
      reg = AtlasPca::PlanRegistry.new(now: -> { t })
      root = reg.draft('g', [{ 'id' => 'n1', 'verb' => 'orders.read', 'resource' => '/orders/1' }])['record']['root']
      assert reg.validate('g', root)['ok']
      assert reg.commit('g', root)['ok']
      assert reg.authorize('g', root, { 'by' => 'p', 'expiresAt' => 5000 })['ok']
      assert_equal true, reg.status('g', root)['executable']
      t = bad
      assert_equal false, reg.status('g', root)['executable'], bad.to_s
    end
  end
end
