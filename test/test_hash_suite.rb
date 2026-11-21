# frozen_string_literal: true

# Hash-suite agility helpers and the constants exported next to them.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestHashSuite < Minitest::Test
  A = AtlasPca

  def test_suite_guard_and_dispatch
    assert A.hash_suite?('sha256')
    assert A.hash_suite?('sha384')
    refute A.hash_suite?('sha512')
    refute A.hash_suite?(nil)
    assert_equal 'sha256', A::DEFAULT_HASH_SUITE
    assert_equal [32, 48], [A.hash_with_suite('x').bytesize, A.hash_with_suite('x', 'sha384').bytesize]
    assert_equal Digest::SHA256.digest('x'), A.hash_with_suite('x')
    assert_equal A::HASH_LEN['sha384'], A.hash_with_suite('x', 'sha384').bytesize
  end

  def test_canonical_digest_under_a_suite
    assert_equal A.hash_canonical({ 'a' => 1 }), A.hash_canonical({ 'a' => 1 }, 'sha256')
    refute_equal A.hash_canonical({ 'a' => 1 }), A.hash_canonical({ 'a' => 1 }, 'sha384')
    assert_equal A.b64u_len(48), A.hash_canonical({ 'a' => 1 }, 'sha384').length
    assert_equal 43, A.hash_canonical({ 'a' => 1 }).length
  end

  def test_base64url_helpers
    assert_equal [0, 2, 3, 4, 43, 64], [0, 1, 2, 3, 32, 48].map { |n| A.b64u_len(n) }
    assert A.canonical_b64u?(A.b64e('abc'))
    assert A.canonical_b64u?(A.b64e("\x00".b * 32), 32)
    refute A.canonical_b64u?(A.b64e("\x00".b * 32), 31)
    refute A.canonical_b64u?('AB==')
    refute A.canonical_b64u?('AB')
    refute A.canonical_b64u?(5)
  end

  def test_constants
    assert_equal 1_200_000, A::PCACTN_DEFAULT_TTL_MS
    assert_equal 3_720_000, A::REPLAY_MIN_RETENTION_MS
    assert_equal({ 'reversible' => 1, 'rate_limited' => 0.4, 'costly' => 0.4, 'irreversible' => 0 }, A::CATALOG_REVERSIBILITY_SCORE)
    assert_equal 9, A::EXECUTION_REQUIRED_CHECKS.length
    assert_equal 7, A::STATEFUL_REQUIRED_CHECKS.length
  end
end
