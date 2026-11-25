# frozen_string_literal: true

# AdaIdna (opt-in IDNA through Ada's C API): needs ATLAS_PCA_LIBADA. Without it the test skips; PCA_ADA_REQUIRED=1 (the CI workflow) fails instead.
require_relative '../lib/atlas_pca'
require_relative '../lib/atlas_pca/ada_idna'
require_relative '../lib/atlas_pca/whatwg_url'
require 'minitest/autorun'

class TestAdaIdna < Minitest::Test
  A = AtlasPca::AdaIdna

  def setup
    return if A.available?

    flunk 'ATLAS_PCA_LIBADA is not usable' if ENV['PCA_ADA_REQUIRED'] == '1'
    skip 'no libada (set ATLAS_PCA_LIBADA)'
  end

  def test_domain_to_ascii_matches_the_node_parser
    assert_equal 'xn--mnchen-3ya.de', A.domain_to_ascii('münchen.de')
    assert_equal 'xn--fa-hia.de', A.domain_to_ascii('faß.de') # non-transitional: the sharp s is kept
    assert_equal 'example.com', A.domain_to_ascii('EXAMPLE.com')
    assert_equal 'xn--maana-pta.com', A.domain_to_ascii('mañana.com')
    assert_equal '', A.domain_to_ascii('a b.com') # a forbidden host code point
  end

  def test_url_host_parser_maps_an_idn_host_and_still_refuses_forbidden_ones
    r = AtlasPca::WhatwgUrl.parse('https://münchen.de/x')
    refute_nil r
    assert_equal 'xn--mnchen-3ya.de', r[:host] || r['host']
    assert_nil AtlasPca::WhatwgUrl.parse('https://mün%2Fchen.de/x')
  end
end
