# frozen_string_literal: true

# Real-primitive FN-DSA through libfndsa (AtlasPca::FndsaNative): byte-for-byte replay of the cross-implementation known-answer file, plus
# refusals and the hybrid framing. Needs libfndsa (ATLAS_PCA_LIBFNDSA) through ffi; with ATLAS_PCA_LIBFNDSA_REQUIRED=1 its absence fails
# instead of skipping.
require_relative '../lib/atlas_pca/fndsa_native'
require_relative '../lib/atlas_pca/mpc_libcrypto'
require 'json'
require 'openssl'
require 'minitest/autorun'

class TestFndsaNative < Minitest::Test
  F = AtlasPca::Fndsa
  N = AtlasPca::FndsaNative
  KAT = JSON.parse(File.read(File.join(__dir__, '../test-data/ref-fndsa-kat.json')))
  VARIANTS = %w[fn-dsa-512 fn-dsa-1024].freeze

  def setup
    unless N.available?
      raise 'libfndsa must load (ATLAS_PCA_LIBFNDSA)' if ENV['ATLAS_PCA_LIBFNDSA_REQUIRED'] == '1'

      skip 'libfndsa not available'
    end
    F.set_falcon_backend(N.native_backend)
  end

  def teardown = F.reset_falcon_backend

  def h(s) = [s].pack('H*')
  def shake_seed(label) = AtlasPca::Mpc::Libcrypto.shake256(label, 32) # the digest class of the openssl gem has no XOF length
  def flip(b, i = 0) = b.dup.tap { |x| x.setbyte(i, x.getbyte(i) ^ 1) }
  def z(n) = ("\x00" * n).b

  def test_kat_has_cases
    refute_empty KAT['wasm_signed']
    refute_empty KAT['c_signed']
  end

  def test_wasm_signed_byte_exact
    KAT['wasm_signed'].each_with_index do |c, i|
      v = c['variant']
      vk = h(c['vk'])
      msg = h(c['msg'])
      sig = h(c['sig'])
      sk, got_vk = N.keygen(v, shake_seed(c['keygen_seed_label']))
      assert_equal vk, got_vk, "wasm_signed[#{i}] keygen"
      assert_equal sig, N.sign(v, sk, msg, shake_seed(c['sign_seed_label'])), "wasm_signed[#{i}] sign"
      assert N.verify(v, vk, msg, sig), "wasm_signed[#{i}] verify"
      assert F.fndsa_verify(v, vk, msg, sig), "wasm_signed[#{i}] framing verify"
    end
  end

  def test_c_signed_verifies
    KAT['c_signed'].each_with_index { |c, i| assert N.verify(c['variant'], h(c['vk']), h(c['msg']), h(c['sig'])), "c_signed[#{i}]" }
  end

  def test_tampering_is_refused
    c = KAT['c_signed'].find { |x| !x['msg'].empty? } # an empty message would make the last check a valid one
    v = c['variant']
    vk = h(c['vk'])
    msg = h(c['msg'])
    sig = h(c['sig'])
    refute N.verify(v, vk, msg, flip(sig, 10))
    refute N.verify(v, vk, msg + 'x'.b, sig)
    refute N.verify(v, flip(vk, 5), msg, sig)
    refute N.verify(v, vk, msg, sig.byteslice(0, sig.bytesize - 1))
    refute N.verify(v, vk.byteslice(0, vk.bytesize - 1), msg, sig)
    refute N.verify(v, vk, z(N::MESSAGE_CAP + 1), sig)
    refute N.verify(v, vk, ''.b, sig)
  end

  def test_refusals_before_the_library
    assert_raises(ArgumentError) { N.keygen('fn-dsa-768', z(32)) }
    assert_raises(ArgumentError) { N.keygen('fn-dsa-512', z(31)) }
    assert_raises(TypeError) { N.keygen('fn-dsa-512', nil) }
    assert_raises(TypeError) { N.keygen('fn-dsa-512', 'a' * 32) } # text is not bytes
    sk, vk = N.keygen('fn-dsa-512', z(32))
    assert_raises(ArgumentError) { N.sign('fn-dsa-512', sk.byteslice(0, sk.bytesize - 1), 'm'.b) }
    assert_raises(ArgumentError) { N.sign('fn-dsa-512', sk, z(N::MESSAGE_CAP + 1)) }
    assert_raises(ArgumentError) { N.sign('fn-dsa-768', sk, 'm'.b) }
    assert_raises(TypeError) { N.sign('fn-dsa-512', sk, nil) }
    assert_raises(ArgumentError) { N.sign('fn-dsa-512', sk, 'm'.b, z(5)) }
    assert_raises(ArgumentError) { N.verify('fn-dsa-768', vk, 'm'.b, z(666)) }
    refute N.verify('fn-dsa-512', vk, 'm'.b, z(666))
    assert_raises(TypeError) { N.verify('fn-dsa-512', nil, 'm'.b, z(666)) }
  end

  def test_random_sign_round_trip
    VARIANTS.each do |v|
      sk, vk = N.keygen(v, (0..31).to_a.pack('C*'))
      s1 = N.sign(v, sk, 'hello'.b)
      s2 = N.sign(v, sk, 'hello'.b)
      refute_equal s1, s2 # fresh randomness per signature
      assert N.verify(v, vk, 'hello'.b, s1)
      assert N.verify(v, vk, 'hello'.b, s2)
      assert N.verify(v, vk, ''.b, N.sign(v, sk, ''.b))
      refute N.verify(v, vk, 'hellp'.b, s1)
      big = ('m' * N::MESSAGE_CAP).b
      assert N.verify(v, vk, big, N.sign(v, sk, big))
    end
  end

  def test_backend_seam
    be = F.falcon_backend
    kp = be.keygen.call
    sig = be.sign.call(kp['sk'], 'x'.b)
    assert_equal true, be.verify.call(kp['pk'], 'x'.b, sig)
    assert_equal false, be.verify.call(kp['pk'].byteslice(0, kp['pk'].bytesize - 1), 'x'.b, sig)
    assert_raises(ArgumentError) { be.sign.call(z(10), 'x'.b) }
  end

  def test_framing_round_trip
    F::FN_DSA_SUITES.each do |alg, suite|
      sk, vk = N.keygen(suite.variant, ([7] * 32).pack('C*'))
      leaf = { 'agent' => 'a', 'n' => 1 }
      ed_seed = ([9] * 32).pack('C*')
      signed = F.sign_pca_with_fndsa(alg, leaf, { 'pk' => vk, 'sk' => sk }, suite.has_ed25519 ? ed_seed : nil)
      holder = suite.has_ed25519 ? AtlasPca.b64e(OpenSSL::PKey.new_raw_private_key('ED25519', ed_seed).raw_public_key) : nil
      assert F.verify_pca_fndsa(alg, leaf, holder, signed['pq_pk'], signed['sig'], signed['pq_sig']), alg
      refute F.verify_pca_fndsa(alg, { 'agent' => 'b', 'n' => 1 }, holder, signed['pq_pk'], signed['sig'], signed['pq_sig']), alg
    end
  end
end
