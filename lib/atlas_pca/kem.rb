# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require_relative 'mpc_libcrypto'

module AtlasPca
  # Key encapsulation: three KEMs that each establish a 32-byte shared secret (no cipher is shipped).
  #   hybrid X25519 + ML-KEM-768   suite 'x25519-ml-kem-768'   HKDF-SHA256 combiner, the secret holds while EITHER half is unbroken
  #   hybrid X25519 + ML-KEM-1024  suite 'x25519-ml-kem-1024'  the same construction under its own domain separator
  #   X-Wing (draft-connolly-cfrg-xwing-kem-09)  suite 'xwing'  SHA3-256 combiner, byte-compatible with other X-Wing implementations
  # plus the FIPS 203 section 7.2 / 7.3 checks of an imported ML-KEM key and the base64url wrappers.
  # Layouts: hybrid public key = X25519 public (32) || ML-KEM encapsulation key; ciphertext = ephemeral X25519 public (32) || ML-KEM
  # ciphertext; secret key = X25519 secret (32) || expanded ML-KEM decapsulation key. X-Wing is the other way round (ML-KEM part
  # first) and its secret key is the 32-byte seed.
  # Every primitive is the vetted OpenSSL one: X25519, HKDF and SHA3 through the openssl extension, SHAKE256 and ML-KEM (OpenSSL >=
  # 3.5) through libcrypto. Byte strings in and out; every refusal is an ArgumentError (LoadError when ML-KEM is not available).
  # Decapsulation never fails on well-sized inputs: a tampered ciphertext or the wrong key gives a different secret (ML-KEM implicit
  # rejection), so confirm the secret in the protocol that uses it. An all-zero X25519 result (a low-order peer point) is refused.
  module Kem
    X25519_LEN = 32
    SS_LEN = 32

    HYBRID_PUBLIC_KEY_LEN = 1216
    HYBRID_CIPHERTEXT_LEN = 1120
    HYBRID_SHARED_SECRET_LEN = 32
    HYBRID_KEM_SUITE = 'x25519-ml-kem-768'
    HYBRID1024_PUBLIC_KEY_LEN = 1600
    HYBRID1024_CIPHERTEXT_LEN = 1600
    HYBRID1024_SHARED_SECRET_LEN = 32
    HYBRID1024_KEM_SUITE = 'x25519-ml-kem-1024'

    XWING_SUITE = 'xwing'
    XWING_SEED_LEN = 32
    XWING_SECRET_KEY_LEN = 32
    XWING_PUBLIC_KEY_LEN = 1216
    XWING_CIPHERTEXT_LEN = 1120
    XWING_SHARED_SECRET_LEN = 32
    XWING_ESEED_LEN = 64
    XWING_LABEL = "\\.//^\\".b.freeze # 5c 2e 2f 2f 5e 5c

    # level => module rank k, ML-KEM encapsulation key / ciphertext bytes, the combiner's domain separator, the reference fn names
    HYBRID = {
      768 => { k: 3, pk: 1184, ct: 1088, domain: "atlas-pca/kem/x25519-ml-kem-768/v1\0".b.freeze,
               encapsulate: 'hybridEncapsulate', decapsulate: 'hybridDecapsulate' }.freeze,
      1024 => { k: 4, pk: 1568, ct: 1568, domain: "atlas-pca/kem/x25519-ml-kem-1024/v1\0".b.freeze,
                encapsulate: 'hybridEncapsulate1024', decapsulate: 'hybridDecapsulate1024' }.freeze
    }.freeze

    KeyPair = Struct.new(:public_key, :secret_key)
    Encapsulation = Struct.new(:ciphertext, :shared_secret)

    module_function

    def ml = Mpc::Libcrypto::MlKem

    def bytes!(v, who, what)
      raise ArgumentError, "#{who}: #{what} must be a byte string" unless v.is_a?(String)

      v.b
    end

    def sized!(v, len, who, what)
      b = bytes!(v, who, what)
      raise ArgumentError, "#{who}: #{what} must be #{len} bytes (got #{b.bytesize})" unless b.bytesize == len

      b
    end

    def x_public(secret) = OpenSSL::PKey.new_raw_private_key('X25519', secret).raw_public_key

    # X25519(secret, peer); a low-order peer point (all-zero result) is refused
    def x_shared(secret, peer)
      ss = OpenSSL::PKey.new_raw_private_key('X25519', secret).derive(OpenSSL::PKey.new_raw_public_key('X25519', peer))
      raise ArgumentError, 'x25519: invalid private or public key received' if ss.bytesize != X25519_LEN || ss.each_byte.all?(&:zero?)

      ss
    rescue OpenSSL::OpenSSLError => e
      raise ArgumentError, "x25519: invalid private or public key received (#{e.message})"
    end

    def sha3_256(data) = OpenSSL::Digest.new('SHA3-256').digest(data)

    # FIPS 203 section 7.2 modulus check: every 12-bit coefficient of the first 384k bytes is below q = 3329
    def coefficients_reduced?(ek, k)
      b = ek.unpack('C*')
      (0...(384 * k)).step(3).all? { |i| (b[i] | ((b[i + 1] & 0x0f) << 8)) < 3329 && ((b[i + 1] >> 4) | (b[i + 2] << 4)) < 3329 }
    end

    def require_reduced_ek(ek, k, who)
      raise ArgumentError, "#{who}: ML-KEM encapsulation key fails the FIPS 203 modulus check" unless coefficients_reduced?(ek, k)
    end

    # HKDF-SHA256 over ssMlkem || ssX25519 || ephemeral public || recipient X25519 public, no salt, the suite's domain as info
    def combine(level, ss_mlkem, ss_x, eph_pub, recip_x)
      OpenSSL::KDF.hkdf(ss_mlkem + ss_x + eph_pub + recip_x, salt: "\0".b * 32, info: HYBRID.fetch(level)[:domain], length: SS_LEN, hash: 'SHA256')
    end

    def level_keygen(level, rng)
      r = rng.nil? ? SecureRandom.random_bytes(96) : sized!(rng, 96, 'hybridKemKeygen', 'rng')
      x_priv = r.byteslice(0, 32)
      ek, dk = ml.keygen(level, r.byteslice(32, 64))
      KeyPair.new(x_public(x_priv) + ek, x_priv + dk)
    end

    def level_encapsulate(level, recipient_public_key, rng)
      spec = HYBRID.fetch(level)
      who = spec[:encapsulate]
      pk = sized!(recipient_public_key, X25519_LEN + spec[:pk], who, 'public key')
      r = rng.nil? ? SecureRandom.random_bytes(64) : sized!(rng, 64, who, 'rng')
      recip_x = pk.byteslice(0, X25519_LEN)
      recip_mlkem = pk.byteslice(X25519_LEN, spec[:pk])
      eph_priv = r.byteslice(0, 32)
      eph_pub = x_public(eph_priv)
      ss_x = x_shared(eph_priv, recip_x)
      require_reduced_ek(recip_mlkem, spec[:k], who)
      ct, ss_mlkem = ml.encapsulate(level, recip_mlkem, r.byteslice(32, 32))
      Encapsulation.new(eph_pub + ct, combine(level, ss_mlkem, ss_x, eph_pub, recip_x))
    end

    def level_decapsulate(level, ciphertext, secret_key)
      spec = HYBRID.fetch(level)
      who = spec[:decapsulate]
      ct = sized!(ciphertext, X25519_LEN + spec[:ct], who, 'ciphertext')
      sk = bytes!(secret_key, who, 'secret key')
      raise ArgumentError, "#{who}: malformed secret key" unless sk.bytesize == X25519_LEN + (768 * spec[:k]) + 96

      eph_pub = ct.byteslice(0, X25519_LEN)
      x_priv = sk.byteslice(0, X25519_LEN)
      ss_x = x_shared(x_priv, eph_pub)
      ss_mlkem = ml.decapsulate(level, ct.byteslice(X25519_LEN, spec[:ct]), sk.byteslice(X25519_LEN, sk.bytesize - X25519_LEN))
      combine(level, ss_mlkem, ss_x, eph_pub, x_public(x_priv))
    end

    # ---- hybrid X25519 + ML-KEM-768 ------------------------------------------------------------------------------

    # A recipient key pair (KeyPair: public_key 1216 bytes, secret_key 2432 bytes). `rng` (known-answer use only) pins the
    # randomness: X25519 secret (32) || ML-KEM seed d || z (64).
    def hybrid_kem_keygen(rng: nil) = level_keygen(768, rng)

    # Encapsulates to a recipient public key: Encapsulation (ciphertext 1120 bytes to send, shared_secret 32 bytes to keep). `rng`
    # (known-answer use only): ephemeral X25519 secret (32) || ML-KEM message (32).
    def hybrid_encapsulate(recipient_public_key, rng: nil) = level_encapsulate(768, recipient_public_key, rng)

    # Recovers the 32-byte shared secret from a ciphertext with the recipient secret key.
    def hybrid_decapsulate(ciphertext, secret_key) = level_decapsulate(768, ciphertext, secret_key)

    # ---- hybrid X25519 + ML-KEM-1024 (public key 1600, secret key 3200, ciphertext 1600 bytes) -------------------------

    def hybrid_kem1024_keygen(rng: nil) = level_keygen(1024, rng)
    def hybrid_encapsulate1024(recipient_public_key, rng: nil) = level_encapsulate(1024, recipient_public_key, rng)
    def hybrid_decapsulate1024(ciphertext, secret_key) = level_decapsulate(1024, ciphertext, secret_key)

    # ---- X-Wing --------------------------------------------------------------------------------------------------

    # seed -> [ML-KEM decapsulation key, ML-KEM encapsulation key, X25519 secret, X25519 public] (SHAKE256(seed, 96) = d || z || skX)
    def expand_xwing_key(seed)
      seed = sized!(seed, XWING_SEED_LEN, 'expandXWingKey', 'seed')
      expanded = Mpc::Libcrypto.shake256(seed, 96)
      x_secret = expanded.byteslice(64, 32)
      ek, dk = ml.keygen(768, expanded.byteslice(0, 64))
      [dk, ek, x_secret, x_public(x_secret)]
    end

    # SHA3-256(ssM || ssX || ctX || pkX || label): the ML-KEM ciphertext is deliberately not hashed in (draft section 5.3)
    def xwing_combiner(ss_m, ss_x, ct_x, pk_x) = sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL)

    # An X-Wing key pair: secret_key is the 32-byte seed (drawn from the CSPRNG when none is given), public_key 1216 bytes.
    def xwing_keygen(seed = nil)
      sk = seed.nil? ? SecureRandom.random_bytes(XWING_SEED_LEN) : bytes!(seed, 'xwingKeygen', 'seed').dup
      _dk, ek, _x_secret, x_pub = expand_xwing_key(sk)
      KeyPair.new(ek + x_pub, sk)
    end

    # Deterministic encapsulation from a 64-byte eseed = ML-KEM message (32) || ephemeral X25519 secret (32).
    def xwing_encapsulate_derand(recipient_public_key, eseed)
      who = 'xwingEncapsulateDerand'
      pk = sized!(recipient_public_key, XWING_PUBLIC_KEY_LEN, who, 'public key')
      es = sized!(eseed, XWING_ESEED_LEN, who, 'eseed')
      pk_m = pk.byteslice(0, 1184)
      pk_x = pk.byteslice(1184, 32)
      ek_x = es.byteslice(32, 32)
      require_reduced_ek(pk_m, 3, who)
      ct_m, ss_m = ml.encapsulate(768, pk_m, es.byteslice(0, 32))
      ct_x = x_public(ek_x)
      ss_x = x_shared(ek_x, pk_x)
      Encapsulation.new(ct_m + ct_x, xwing_combiner(ss_m, ss_x, ct_x, pk_x))
    end

    # Randomised encapsulation (a fresh eseed from the CSPRNG).
    def xwing_encapsulate(recipient_public_key) = xwing_encapsulate_derand(recipient_public_key, SecureRandom.random_bytes(XWING_ESEED_LEN))

    # Recovers the shared secret from an X-Wing ciphertext with the 32-byte secret seed.
    def xwing_decapsulate(ciphertext, secret_key)
      ct = sized!(ciphertext, XWING_CIPHERTEXT_LEN, 'xwingDecapsulate', 'ciphertext')
      dk, _ek, x_secret, x_pub = expand_xwing_key(secret_key)
      ct_x = ct.byteslice(1088, 32)
      ss_m = ml.decapsulate(768, ct.byteslice(0, 1088), dk)
      xwing_combiner(ss_m, x_shared(x_secret, ct_x), ct_x, x_pub)
    end

    # ---- FIPS 203 key checks -------------------------------------------------------------------------------------

    def rank(level)
      spec = HYBRID[level.is_a?(String) && %w[768 1024].include?(level) ? level.to_i : level]
      raise ArgumentError, "ml-kem: unknown level #{level.inspect}" if spec.nil?

      spec[:k]
    end

    # FIPS 203 section 7.2 check of an encapsulation key (level 768 or 1024): the exact length and every coefficient reduced.
    # Never raises for a valid level; an unknown level raises.
    def ml_kem_encapsulation_key_check(level, ek)
      k = rank(level)
      ek.is_a?(String) && ek.bytesize == (384 * k) + 32 && coefficients_reduced?(ek.b, k)
    end

    # FIPS 203 section 7.3 check of an expanded decapsulation key: the exact length, the embedded H(ek) equal to SHA3-256 of the
    # embedded encapsulation key, and that key's modulus check. The decryption half and z are not checked.
    def ml_kem_decapsulation_key_check(level, dk)
      k = rank(level)
      return false unless dk.is_a?(String) && dk.bytesize == (768 * k) + 96

      ek = dk.b.byteslice(384 * k, (384 * k) + 32)
      OpenSSL.fixed_length_secure_compare(sha3_256(ek), dk.b.byteslice((768 * k) + 32, 32)) && ml_kem_encapsulation_key_check(level, ek)
    end

    # ---- base64url (unpadded) wrappers; decoding is strict (no padding, canonical trailing bits) and checks no length ------

    def encode(bytes, who) = AtlasPca.b64e(bytes!(bytes, who, 'value'))
    def decode(str, who) = AtlasPca.b64d(str) || raise(ArgumentError, "#{who}: not canonical unpadded base64url")

    def encode_hybrid_public_key(key) = encode(key, 'encodeHybridPublicKey')
    def decode_hybrid_public_key(str) = decode(str, 'decodeHybridPublicKey')
    def encode_hybrid_ciphertext(ciphertext) = encode(ciphertext, 'encodeHybridCiphertext')
    def decode_hybrid_ciphertext(str) = decode(str, 'decodeHybridCiphertext')
    def encode_xwing_public_key(key) = encode(key, 'encodeXWingPublicKey')
    def decode_xwing_public_key(str) = decode(str, 'decodeXWingPublicKey')
    def encode_xwing_ciphertext(ciphertext) = encode(ciphertext, 'encodeXWingCiphertext')
    def decode_xwing_ciphertext(str) = decode(str, 'decodeXWingCiphertext')
  end
end
