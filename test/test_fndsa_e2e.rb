# frozen_string_literal: true

# FN-DSA end to end through the PUBLIC producer and verifier: the shared PCActn fixture (ref-fndsa-pcactn.json, signed by the reference).
# With libfndsa registered: keys derive from the fixture labels, AtlasPca.sign_pcactn reproduces the `valid` case byte for byte, and
# AtlasPca.verify_pcactn gives allow == expect_allow on every case. With no backend every case denies (the valid one with unsupported_suite).
# ATLAS_PCA_LIBFNDSA_REQUIRED=1 fails instead of skipping when the library is missing.
require_relative '../lib/atlas_pca/fndsa_native'
require 'digest'
require 'minitest/autorun'

class TestFndsaE2e < Minitest::Test
  F = AtlasPca::Fndsa
  N = AtlasPca::FndsaNative
  DOC = AtlasPca.parse_json(File.read(File.join(__dir__, '../test-data/ref-fndsa-pcactn.json'), encoding: 'UTF-8'), loose: true)
  VARIANTS = %w[fn-dsa-512 fn-dsa-1024].freeze

  def setup = F.reset_falcon_backend
  def teardown = F.reset_falcon_backend

  def native!
    unless N.available?
      flunk 'libfndsa must load (ATLAS_PCA_LIBFNDSA)' if ENV['ATLAS_PCA_LIBFNDSA_REQUIRED'] == '1'

      skip 'libfndsa not available'
    end
    F.set_falcon_backend(N.native_backend)
  end

  def seed(label) = Digest::SHA256.digest("atlas-pca-conformance/#{label}")

  def verify(c)
    AtlasPca.verify_pcactn(c['pcactn'], c['grant'], now: c['now_epoch'], audience: c['audience'], insecure_skip_plan_root_check: true)
  end

  def cases_of(alg) = DOC['cases'].select { |c| c['alg'] == alg }

  def test_fixture_shape
    assert_equal 12, DOC['cases'].length
    VARIANTS.each { |alg| assert_equal 6, cases_of(alg).length }
  end

  def test_sign_reproduces_the_reference
    native!
    VARIANTS.each do |alg|
      c = cases_of(alg).find { |x| x['name'].end_with?('/valid') }
      l = c['key_labels']
      leaf = AtlasPca::KeyPair.new(seed(l['agent_ed25519']))
      pq = AtlasPca::FndsaKeyPair.from_seed(alg.upcase, seed(l['fndsa_keygen']), sign_seed: seed(l['fndsa_sign_seed']))
      assert_equal c['pq_pk'], pq.public, "#{alg} keygen"
      assert_equal c['pcactn'], AtlasPca.sign_pcactn(c['body'], leaf, alg: alg, pq: pq), "#{alg} sign_pcactn"
    end
  end

  def test_every_case_verifies_as_expected
    native!
    DOC['cases'].each do |c|
      v = verify(c)
      assert_equal c['expect_allow'], v.allow, "#{c['name']}: #{v.reason}"
    end
  end

  def test_no_backend_denies_everything
    DOC['cases'].each do |c|
      v = verify(c)
      refute v.allow, c['name']
      assert_includes v.reason, 'unsupported_suite', c['name'] if c['name'].end_with?('/valid')
    end
  end

  def test_signing_refused_without_backend
    VARIANTS.each do |alg|
      assert_raises(AtlasPca::UnsupportedSigner) { AtlasPca::FndsaKeyPair.from_seed(alg.upcase, seed('x')) }
      assert_raises(AtlasPca::UnsupportedSigner) { AtlasPca.sign_with_suite(alg, nil, nil, 'm') }
    end
  end
end
