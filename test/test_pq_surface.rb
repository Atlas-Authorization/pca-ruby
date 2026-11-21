# frozen_string_literal: true

# The PQ suite surface: size constants, per-suite wrappers, predicates, suite artifact signing and the LAMPS composite format.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestPqSurface < Minitest::Test
  P = AtlasPca::Pq

  def pq_available?(prim) = AtlasPca.pq_prim_available?(prim)

  def test_constants_agree_with_the_registry
    { 'ML-DSA-65' => [P::ML_DSA_65_PUBLIC_KEY_BYTES, P::ML_DSA_65_SIGNATURE_BYTES], 'ML-DSA-87' => [P::ML_DSA_87_PUBLIC_KEY_BYTES, P::ML_DSA_87_SIGNATURE_BYTES],
      'SLH-DSA-SHA2-128f' => [P::SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES, P::SLH_DSA_SHA2_128F_SIGNATURE_BYTES],
      'SLH-DSA-SHA2-256s' => [P::SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES, P::SLH_DSA_SHA2_256S_SIGNATURE_BYTES],
      'FN-DSA-512' => [P::FN_DSA_512_PUBLIC_KEY_BYTES, P::FN_DSA_512_SIGNATURE_BYTES], 'FN-DSA-1024' => [P::FN_DSA_1024_PUBLIC_KEY_BYTES, P::FN_DSA_1024_SIGNATURE_BYTES],
      'LESS-cat1' => [P::LESS_CAT1_PUBLIC_KEY_BYTES, P::LESS_CAT1_SIGNATURE_MAX_BYTES] }.each { |prim, v| assert_equal v, AtlasPca::PQ_PRIMS[prim], prim }
    assert_equal 3373, P::COMPOSITE_SIGNATURE_BYTES
  end

  def test_predicates
    assert P.known_sig_alg?('hybrid-ed25519-ml-dsa-65')
    refute P.known_sig_alg?('ml-dsa-1')
    refute P.known_sig_alg?(nil)
    assert P.pinned_pq_key?(AtlasPca::PinnedPq.mint('k', 'pin'))
    refute P.pinned_pq_key?('k')
    assert P.well_formed_pq_public_key?(AtlasPca.b64e('a'.b * 1952))
    refute P.well_formed_pq_public_key?(AtlasPca.b64e('a'.b * 1951))
    refute P.well_formed_pq_public_key?(7)
    assert_equal({ 'available' => false }.keys, P.less_backend_status.keys - ['reason']) unless P.less_backend_active?
  end

  def test_composite_representative_and_ctx_limit
    m = P.composite_representative('hi', 'ctx')
    assert_equal P::COMPOSITE_PREFIX.b + P::COMPOSITE_LABEL.b + "\x03ctx".b + Digest::SHA512.digest('hi'), m
    assert_raises(RangeError) { P.composite_representative('hi', 'x' * 256) }
  end

  def test_composite_round_trip_and_fail_closed
    skip 'ML-DSA needs OpenSSL >= 3.5' unless pq_available?('ML-DSA-65')
    ed = AtlasPca::KeyPair.from_seed_b64u(AtlasPca.b64e("\x07".b * 32))
    ml = P.ml_dsa65_keygen("\x09".b * 32)
    sig = P.composite_sign(ed25519: ed, ml_dsa: ml, message: 'm', ctx: 'c')
    assert_equal P::COMPOSITE_SIGNATURE_BYTES, sig.bytesize
    args = { ed25519_pub: AtlasPca.b64d(ed.public), ml_dsa_pub: AtlasPca.b64d(ml.public), message: 'm', signature: sig, ctx: 'c' }
    assert P.composite_verify(**args)
    refute P.composite_verify(**args, ctx: 'd')
    refute P.composite_verify(**args, message: 'n')
    refute P.composite_verify(**args, signature: sig.byteslice(0, 3372))
    flipped = sig.dup.b
    flipped.setbyte(3000, flipped.getbyte(3000) ^ 1)
    refute P.composite_verify(**args, signature: flipped)
    tail = sig.dup.b
    tail.setbyte(3372, tail.getbyte(3372) ^ 1)
    refute P.composite_verify(**args, signature: tail)
    refute P.composite_verify(**args, ctx: 'x' * 256)
  end

  def test_suite_wrappers_and_artifact_signing
    skip 'ML-DSA needs OpenSSL >= 3.5' unless pq_available?('ML-DSA-65')
    ed = AtlasPca::KeyPair.from_seed_b64u(AtlasPca.b64e("\x01".b * 32))
    ml = P.ml_dsa65_keygen("\x02".b * 32)
    sig = P.ml_dsa65_sign(ml, 'x')
    assert P.ml_dsa65_verify(AtlasPca.b64d(ml.public), 'x', sig)
    assert P.ml_dsa65_verify_b64u(ml.public, 'x', AtlasPca.b64e(sig))
    refute P.ml_dsa65_verify(AtlasPca.b64d(ml.public), 'y', sig)
    assert_raises(ArgumentError) { P.ml_dsa87_sign(ml, 'x') }
    keys = P.suite_keys_of(ed, { 'alg' => 'hybrid-ed25519-ml-dsa-65', 'ml_dsa' => ml })
    assert_equal ml.public, P.suite_pq_public_key('hybrid-ed25519-ml-dsa-65', keys)
    assert_nil P.suite_pq_public_key('ed25519', keys)
    assert_equal %w[sig], P.sign_suite_artifact(nil, keys, 'm').keys
    f = P.sign_suite_artifact('hybrid-ed25519-ml-dsa-65', keys, 'm')
    assert_equal %w[alg pq_pk pq_sig sig], f.keys.sort
    assert_equal ml.public, f['pq_pk']
  end

  # LESS signs through the shared C library (skipped where libatlas_less is absent or verify-only)
  def test_less_sign_round_trip
    skip 'libatlas_less with signing not available' unless AtlasPca::LessFfi.signer_available?
    k = P.less_cat1_keygen("\x03".b * 32)
    assert_equal k.public, P.less_cat1_keygen("\x03".b * 32).public
    sig = P.less_cat1_sign(k, 'm')
    assert AtlasPca::LessFfi.sig_len_ok?(sig.bytesize)
    assert P.less_cat1_verify_b64u(k.public, 'm', AtlasPca.b64e(sig))
    refute P.less_cat1_verify_b64u(k.public, 'n', AtlasPca.b64e(sig))
    ed = AtlasPca::KeyPair.from_seed_b64u(AtlasPca.b64e("\x01".b * 32))
    f = P.sign_suite_artifact('hybrid-ed25519-less-cat1', P.suite_keys_of(ed, { 'less_cat1' => k }), 'm')
    assert_equal k.public, f['pq_pk']
  end
end
