# frozen_string_literal: true

# The bind-first port line a node prints, read in any key order and refused when malformed (parsed in-process so mutation tools see it).
require_relative 'support/mpc_net_support'
require 'minitest/autorun'

class TestMpcNetLaunchPort < Minitest::Test
  L = AtlasPca::Mpc::Net::LaunchLocal

  def test_accepts_either_key_order
    assert_equal 4321, L.parse_listening(%({"id":0,"listening":4321}\n), 0)
    assert_equal 4321, L.parse_listening(%({"listening":4321,"id":0}\n), 0)
    assert_equal 1, L.parse_listening(%({"listening":1}\n), 3)
    assert_equal 65_535, L.parse_listening(%({"listening":65535}\n), 3)
  end

  def test_refuses_bad_values
    ['"5"', '0', '65536', '-1', '5.5', '5.0', 'true', 'null', '[5]'].each do |v|
      assert_nil L.parse_listening(%({"listening":#{v}}\n), 0), v
    end
    assert_nil L.parse_listening("not json\n5\n[]\n", 0)
  end

  def test_an_id_mismatch_is_ignored_and_a_later_line_still_counts
    assert_nil L.parse_listening(%({"id":1,"listening":4321}\n), 0)
    assert_nil L.parse_listening(%({"id":"0","listening":4321}\n), 0)
    assert_equal 7, L.parse_listening(%({"id":1,"listening":4321}\nbanner\n{"id":0,"listening":7}\n), 0)
  end

  def test_a_partial_last_line_is_not_yet_a_port
    assert_nil L.parse_listening(%({"id":0,"listening":4321}), 0)
    assert_nil L.parse_listening('', 0)
    assert_equal 4321, L.parse_listening(%({"id":0,"listening":4321}\n{"ok":tr), 0)
  end
end
