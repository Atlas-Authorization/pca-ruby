# frozen_string_literal: true

# Point validation is fail-closed whatever libsodium build answers its validity query: B + T (T of order 2) is mixed-order
# and must be refused (libsodium 1.0.20 and older accept it).
require_relative '../lib/atlas_pca/frost'
require 'minitest/autorun'

class TestEd25519MixedOrder < Minitest::Test
  F = AtlasPca::Frost
  BASE = ["58#{'66' * 31}"].pack('H*')
  NEG_BASE = ["58#{'66' * 30}e6"].pack('H*')
  T2 = ["ec#{'ff' * 30}7f"].pack('H*') # (0, -1), order 2
  IDENT = ["01#{'00' * 31}"].pack('H*')
  NON_CANONICAL = ["ee#{'ff' * 30}7f"].pack('H*') # y = p + 1

  def test_decode_safe_point_refuses_torsion
    mixed = F.raw_add(BASE, T2)
    assert_equal BASE, F.decode_safe_point(BASE)
    assert_equal NEG_BASE, F.decode_safe_point(NEG_BASE)
    [mixed, T2, IDENT, "\0".b * 32, NON_CANONICAL].each do |bad|
      refute F.safe_point?(bad)
      assert_raises(ArgumentError) { F.decode_safe_point(bad) }
    end
  end
end

# RFC 9496: the ristretto255 generator with bit 255 set is a non-canonical alias and must be refused.
class TestRistrettoBit255 < Minitest::Test
  GEN = ['e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76'].pack('H*')

  def test_high_bit_alias_is_refused
    require_relative '../lib/atlas_pca/ratchet_group'
    gr = AtlasPca::RatchetGroup
    alias_enc = GEN.dup
    alias_enc.setbyte(31, alias_enc.getbyte(31) | 0x80)
    assert gr.valid?(GEN)
    refute gr.valid?(alias_enc)
  end
end
