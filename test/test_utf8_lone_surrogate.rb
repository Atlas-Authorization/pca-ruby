# frozen_string_literal: true

# A lone surrogate (WTF-8 ED A0 80 in a Ruby string) is hashed as U+FFFD (EF BF BD), as the reference TextEncoder writes it.
#   ruby -Ilib test/test_utf8_lone_surrogate.rb
require_relative '../lib/atlas_pca'
require 'digest'
require 'minitest/autorun'

class TestUtf8LoneSurrogate < Minitest::Test
  LONE = "\xED\xA0\x80".dup.force_encoding('UTF-8')
  FFFD = "\xEF\xBF\xBD".dup.force_encoding('UTF-8')

  def test_utf8_writes_fffd_for_a_lone_surrogate_only
    assert_equal "a\xEF\xBF\xBDb".b, AtlasPca::Js.utf8("a#{LONE}b")
    assert_equal "a\xF0\x9F\x98\x80".b, AtlasPca::Js.utf8("a\u{1F600}")
  end

  def test_goal_commit_hashes_the_fffd_bytes
    assert_equal AtlasPca::GoalBinding.goal_commit("g#{FFFD}", 'p', 's'), AtlasPca::GoalBinding.goal_commit("g#{LONE}", 'p', 's')
  end

  def test_domain_message_and_shard_use_the_fffd_bytes
    assert_equal AtlasPca::Prohibitions.domain_message('d', "x#{FFFD}"), AtlasPca::Prohibitions.domain_message('d', "x#{LONE}")
    assert_equal AtlasPca.kv_shard_of("x#{FFFD}", 16), AtlasPca.kv_shard_of("x#{LONE}", 16)
  end

  def test_encode_uri_component_refuses_a_lone_surrogate
    assert_raises(ArgumentError) { AtlasPca::Js.encode_uri_component("a#{LONE}") }
    assert_equal 'a%F0%9F%98%80', AtlasPca::Js.encode_uri_component("a\u{1F600}")
  end
end
