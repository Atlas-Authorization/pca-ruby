# frozen_string_literal: true

require 'minitest/autorun'
require 'atlas_pca'
require 'atlas_pca/fndsa_native'
require 'atlas_pca/mpc_lwe_ot'
require 'atlas_pca/less_ffi'

# An explicit environment override is searched before the copy packaged in the gem, which comes before the bare system names.
class TestNativeLoaderOrder < Minitest::Test
  def test_env_first_then_system_names
    assert_equal '/x/fndsa', AtlasPca::FndsaNative::LIBS.first if ENV['ATLAS_PCA_LIBFNDSA'] == '/x/fndsa'
    assert_equal 'fndsa', AtlasPca::FndsaNative::LIBS.reject { |l| l.include?('/native/') || l.start_with?('/x/') }.first
  end

  def test_less_candidates_env_before_packaged
    old = ENV.fetch('ATLAS_PCA_LIBLESS', nil)
    ENV['ATLAS_PCA_LIBLESS'] = '/x/less'
    assert_equal '/x/less', AtlasPca::LessFfi.candidates.first
  ensure
    ENV['ATLAS_PCA_LIBLESS'] = old
  end
end
