# frozen_string_literal: true

# fn-dsa-512 / fn-dsa-1024 in the CORE suite dispatch (AtlasPca.verify_suite / validate_signature_wire): unsupported without a backend,
# real through libfndsa once FndsaNative is registered. ATLAS_PCA_LIBFNDSA_REQUIRED=1 fails instead of skipping the backend cases.
require_relative '../lib/atlas_pca/fndsa_native'
require 'json'
require 'minitest/autorun'

class TestFndsaCore < Minitest::Test
  F = AtlasPca::Fndsa
  N = AtlasPca::FndsaNative
  KAT = JSON.parse(File.read(File.join(__dir__, '../test-data/ref-fndsa-kat.json')))

  def setup = F.reset_falcon_backend
  def teardown = F.reset_falcon_backend

  def h(s) = [s].pack('H*')
  def flip(b, i = 0) = b.dup.tap { |x| x.setbyte(i, x.getbyte(i) ^ 1) }

  def native!
    unless N.available?
      raise 'libfndsa must load (ATLAS_PCA_LIBFNDSA)' if ENV['ATLAS_PCA_LIBFNDSA_REQUIRED'] == '1'

      skip 'libfndsa not available'
    end
    F.set_falcon_backend(N.native_backend)
  end

  def leaf_for(c, sig: h(c['sig']), vk: h(c['vk']))
    { 'alg' => c['variant'], 'sig' => AtlasPca.b64e(sig), 'pq_pk' => AtlasPca.b64e(vk) }
  end

  def test_no_backend_denies_and_is_unsupported
    KAT['c_signed'].each do |c|
      leaf = leaf_for(c)
      assert_equal "unsupported_suite: #{c['variant']}", AtlasPca.validate_signature_wire(leaf)
      refute_includes AtlasPca.supported_suites, c['variant']
      refute AtlasPca.verify_leaf_suite(leaf, 'x', h(c['msg']))
      refute AtlasPca.pq_verify(c['variant'].upcase, h(c['vk']), h(c['msg']), h(c['sig']))
    end
  end

  def test_backend_verifies_through_core_dispatch
    native!
    KAT['c_signed'].each do |c|
      leaf = leaf_for(c)
      msg = h(c['msg'])
      assert_includes AtlasPca.supported_suites, c['variant']
      assert_nil AtlasPca.validate_signature_wire(leaf)
      assert AtlasPca.verify_leaf_suite(leaf, 'x', msg)
      refute AtlasPca.verify_leaf_suite(leaf_for(c, sig: flip(h(c['sig']), 10)), 'x', msg)
      refute AtlasPca.verify_leaf_suite(leaf, 'x', msg.empty? ? 'x'.b : flip(msg))
      refute AtlasPca.verify_leaf_suite(leaf_for(c, vk: flip(h(c['vk']), 5)), 'x', msg)
      short = leaf_for(c, vk: h(c['vk'])[0...-1])
      refute_nil AtlasPca.validate_signature_wire(short)
      refute AtlasPca.verify_leaf_suite(short, 'x', msg)
    end
  end

  def test_reset_returns_to_unsupported
    native!
    F.reset_falcon_backend
    refute_includes AtlasPca.supported_suites, 'fn-dsa-512'
  end
end
