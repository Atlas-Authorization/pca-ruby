# frozen_string_literal: true

# Replays the TS-reference oracle of the KEM module (test-data/ref-kem.json.gz, 464 cases): the hybrid X25519 + ML-KEM-768 / -1024
# KEMs, X-Wing (with the three draft-09 Appendix C vectors), the FIPS 203 key checks and the base64url wrappers. Every fn of the
# corpus has a handler. The corpus carries no key material:
#   {"$bytes": {"$seed": label}}  the 32 bytes sha256("atlas-pca-conformance/" + label)
#   rng                           the pinned random stream, one byte string or the parts to concatenate
#   {"$hybridSk": {level, x, d, z, trim?, pad?, set?}}   x || expandedDk(d || z), then the last `trim` bytes dropped, `pad` zero
#                                                        bytes appended, the [[offset, byte], ...] of `set` written
#   {"$mlkemDk": {level, d, z, set?, rehash?}}           the expanded decapsulation key, bytes patched, and with `rehash` the
#                                                        embedded H(ek) rewritten to SHA3-256 of the patched embedded key
# A key generation answers {publicKey, secretKeySha256, secretKeyLen}: the secret key is compared by its SHA-256. A reference
# throw must be a native refusal. ML-KEM needs OpenSSL >= 3.5: without it the tests skip (they fail when PCA_REQUIRE_PQ is 1).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/kem'
require 'minitest/autorun'

class TestRefKem < Minitest::Test
  K = AtlasPca::Kem
  ML = AtlasPca::Mpc::Libcrypto::MlKem
  BY_FN = Ref.load('kem')
  CONSTANTS = %w[HYBRID_PUBLIC_KEY_LEN HYBRID_CIPHERTEXT_LEN HYBRID_SHARED_SECRET_LEN HYBRID_KEM_SUITE XWING_SUITE XWING_SEED_LEN
                 XWING_SECRET_KEY_LEN XWING_PUBLIC_KEY_LEN XWING_CIPHERTEXT_LEN XWING_SHARED_SECRET_LEN XWING_ESEED_LEN XWING_LABEL
                 HYBRID1024_PUBLIC_KEY_LEN HYBRID1024_CIPHERTEXT_LEN HYBRID1024_SHARED_SECRET_LEN HYBRID1024_KEM_SUITE].freeze

  def self.bx(bytes) = { '$bytes' => Ref.b64e(bytes) }
  def self.join(rng) = rng.is_a?(Array) ? rng.map(&:b).join : rng
  def self.rank(level) = level.to_i == 768 ? 3 : 4

  def self.patch(bytes, spec)
    out = bytes.b
    (spec['set'] || []).each { |offset, byte| out.setbyte(offset, byte) }
    out
  end

  # the corpus forms of a secret key -> bytes (anything else is returned as it is)
  def self.mat(v)
    return v unless v.is_a?(Hash)

    if (h = v['$hybridSk'])
      sk = h['x'] + ML.keygen(h['level'].to_i, h['d'] + h['z'])[1]
      sk = sk.byteslice(0, sk.bytesize - h['trim']) if h['trim']
      sk += "\0".b * h['pad'] if h['pad']
      patch(sk, h)
    elsif (h = v['$mlkemDk'])
      k = rank(h['level'])
      dk = patch(ML.keygen(h['level'].to_i, h['d'] + h['z'])[1], h)
      dk[(768 * k) + 32, 32] = K.sha3_256(dk.byteslice(384 * k, (384 * k) + 32)) if h['rehash']
      dk
    else
      v
    end
  end

  def self.pair(kp) = { 'publicKey' => bx(kp.public_key), 'secretKeySha256' => Digest::SHA256.hexdigest(kp.secret_key), 'secretKeyLen' => kp.secret_key.bytesize }
  def self.encap(e) = { 'ciphertext' => bx(e.ciphertext), 'sharedSecret' => bx(e.shared_secret) }

  HANDLERS = {
    'constants' => -> { CONSTANTS.to_h { |n| [n, n == 'XWING_LABEL' ? bx(K::XWING_LABEL) : K.const_get(n)] } },
    'hybridKemKeygen' => ->(rng) { pair(K.hybrid_kem_keygen(rng: join(rng))) },
    'hybridEncapsulate' => ->(pk, rng) { encap(K.hybrid_encapsulate(pk, rng: join(rng))) },
    'hybridDecapsulate' => ->(ct, sk) { bx(K.hybrid_decapsulate(ct, mat(sk))) },
    'hybridKem1024Keygen' => ->(rng) { pair(K.hybrid_kem1024_keygen(rng: join(rng))) },
    'hybridEncapsulate1024' => ->(pk, rng) { encap(K.hybrid_encapsulate1024(pk, rng: join(rng))) },
    'hybridDecapsulate1024' => ->(ct, sk) { bx(K.hybrid_decapsulate1024(ct, mat(sk))) },
    'xwingKeygen' => ->(seed) { pair(K.xwing_keygen(seed)) },
    'xwingEncapsulateDerand' => ->(pk, eseed) { encap(K.xwing_encapsulate_derand(pk, join(eseed))) }, # a list is the pieces m || x
    'xwingEncapsulate' => ->(pk, rng) { encap(K.xwing_encapsulate_derand(pk, join(rng))) }, # the pinned stream is the eseed
    'xwingDecapsulate' => ->(ct, seed) { bx(K.xwing_decapsulate(ct, seed)) },
    'mlKemEncapsulationKeyCheck' => ->(level, ek) { K.ml_kem_encapsulation_key_check(level, ek) },
    'mlKemDecapsulationKeyCheck' => ->(level, dk) { K.ml_kem_decapsulation_key_check(level, mat(dk)) },
    'encodeHybridPublicKey' => ->(b) { K.encode_hybrid_public_key(b) },
    'encodeHybridCiphertext' => ->(b) { K.encode_hybrid_ciphertext(b) },
    'encodeXWingPublicKey' => ->(b) { K.encode_xwing_public_key(b) },
    'encodeXWingCiphertext' => ->(b) { K.encode_xwing_ciphertext(b) },
    'decodeHybridPublicKey' => ->(s) { bx(K.decode_hybrid_public_key(s)) },
    'decodeHybridCiphertext' => ->(s) { bx(K.decode_hybrid_ciphertext(s)) },
    'decodeXWingPublicKey' => ->(s) { bx(K.decode_xwing_public_key(s)) },
    'decodeXWingCiphertext' => ->(s) { bx(K.decode_xwing_ciphertext(s)) }
  }.freeze

  # fns that never reach ML-KEM: they run on every OpenSSL
  PLAIN = %w[constants encodeHybridPublicKey encodeHybridCiphertext encodeXWingPublicKey encodeXWingCiphertext decodeHybridPublicKey
             decodeHybridCiphertext decodeXWingPublicKey decodeXWingCiphertext].freeze

  def need_mlkem
    return if AtlasPca::Mpc::Libcrypto.mlkem_available?

    flunk 'ML-KEM needs OpenSSL >= 3.5 (PCA_REQUIRE_PQ is set)' if ENV['PCA_REQUIRE_PQ'] == '1'
    skip 'ML-KEM needs OpenSSL >= 3.5'
  end

  def test_every_fn_of_the_corpus_has_a_handler
    assert_empty BY_FN.keys - HANDLERS.keys
    assert_empty HANDLERS.keys - BY_FN.keys
    assert_equal 464, BY_FN.values.sum(&:length)
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      need_mlkem unless PLAIN.include?(fn)
      Ref.run(self, BY_FN.fetch(fn), handler)
    end
  end

  # ---- the randomised entry points (the corpus pins every stream) ---------------------------------------------------

  def test_hybrid_round_trip_with_fresh_randomness
    need_mlkem
    [[768, :hybrid_kem_keygen, :hybrid_encapsulate, :hybrid_decapsulate, 1216, 2432, 1120],
     [1024, :hybrid_kem1024_keygen, :hybrid_encapsulate1024, :hybrid_decapsulate1024, 1600, 3200, 1600]].each do |level, gen, enc, dec, pk, sk, ct|
      kp = K.public_send(gen)
      assert_equal [pk, sk], [kp.public_key.bytesize, kp.secret_key.bytesize]
      refute_equal kp.public_key, K.public_send(gen).public_key
      assert K.ml_kem_encapsulation_key_check(level, kp.public_key.byteslice(32, pk - 32))
      assert K.ml_kem_decapsulation_key_check(level, kp.secret_key.byteslice(32, sk - 32))
      e = K.public_send(enc, kp.public_key)
      assert_equal [ct, 32], [e.ciphertext.bytesize, e.shared_secret.bytesize]
      assert_equal e.shared_secret, K.public_send(dec, e.ciphertext, kp.secret_key)
      again = K.public_send(enc, kp.public_key)
      refute_equal e.ciphertext, again.ciphertext
      refute_equal e.shared_secret, again.shared_secret
      tampered = e.ciphertext.b
      tampered.setbyte(ct - 1, tampered.getbyte(ct - 1) ^ 1)
      refute_equal e.shared_secret, K.public_send(dec, tampered, kp.secret_key) # implicit rejection: a different secret, no error
    end
  end

  def test_the_two_levels_never_share_a_transcript
    need_mlkem
    kp = K.hybrid_kem_keygen
    assert_raises(ArgumentError) { K.hybrid_encapsulate1024(kp.public_key) }
    e = K.hybrid_encapsulate(kp.public_key)
    assert_raises(ArgumentError) { K.hybrid_decapsulate1024(e.ciphertext, kp.secret_key) }
    assert_raises(ArgumentError) { K.hybrid_kem_keygen(rng: 'short') }
    assert_raises(ArgumentError) { K.hybrid_encapsulate(kp.public_key, rng: "\0".b * 63) }
  end

  def test_xwing_round_trip_with_fresh_randomness
    need_mlkem
    kp = K.xwing_keygen
    assert_equal [1216, 32], [kp.public_key.bytesize, kp.secret_key.bytesize]
    refute_equal kp.secret_key, K.xwing_keygen.secret_key
    assert_equal kp.public_key, K.xwing_keygen(kp.secret_key).public_key
    e = K.xwing_encapsulate(kp.public_key)
    assert_equal [1120, 32], [e.ciphertext.bytesize, e.shared_secret.bytesize]
    assert_equal e.shared_secret, K.xwing_decapsulate(e.ciphertext, kp.secret_key)
    refute_equal e.ciphertext, K.xwing_encapsulate(kp.public_key).ciphertext
  end
end
