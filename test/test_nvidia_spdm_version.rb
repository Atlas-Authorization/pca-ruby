# frozen_string_literal: true

# NVIDIA SPDM version rule: GET_MEASUREMENTS request version >= 0x11 and the response echoes it.
#   ruby -Ilib test/test_nvidia_spdm_version.rb
require_relative '../lib/atlas_pca'
require_relative '../lib/atlas_pca/attest'
require 'minitest/autorun'

class TestNvidiaSpdmVersion < Minitest::Test
  N = AtlasPca::Attest::Nvidia

  def reason(req, resp)
    t = [req, 0xE0, 0, 0].pack('C*') + ("\x07".b * 32) + "\0".b + [resp, 0x60, 0, 0, 0, 0, 0, 0].pack('C*') + ("\x09".b * 32) + "\0\0".b + ("\xEE".b * 96)
    N.spdm_version_reason(N.parse_nvidia_spdm_evidence(t))
  end

  def test_version_rule
    assert_nil reason(0x11, 0x11)
    assert_nil reason(0x12, 0x12)
    { [0x10, 0x10] => '0x10/0x10', [0x12, 0x11] => '0x12/0x11', [0x11, 0x12] => '0x11/0x12' }.each do |(rq, rs), txt|
      assert_equal "SPDM version #{txt} is not an accepted GET_MEASUREMENTS version", reason(rq, rs)
    end
  end
end
