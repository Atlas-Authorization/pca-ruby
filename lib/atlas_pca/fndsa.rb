# frozen_string_literal: true

require 'openssl'
require_relative '../atlas_pca'

module AtlasPca
  # FN-DSA (Falcon) suite registry, wire framing and the Ed25519+FN-DSA hybrid leaf composition (the TypeScript reference, @atlasauth/pca-fndsa).
  #
  # Like the reference this module carries NO Falcon arithmetic: the primitive is a pluggable backend (set_falcon_backend), so the framing,
  # lengths and hybrid fail-closed rules are testable without one, and verification refuses until a backend is installed. Real primitive:
  # AtlasPca::FndsaNative.native_backend (fndsa_native.rb) is an ffi backend over libfndsa (Thomas Pornin's fn-dsa 0.4.0 through a small C
  # library; set ATLAS_PCA_LIBFNDSA). FIPS 206 is not final, so this is a draft best guess pinned in lockstep with the TypeScript reference and
  # interoperates with it byte for byte. It does NOT interoperate with liboqs, BouncyCastle or circl Falcon, which are the earlier round-3
  # scheme (same signature lengths, different keys and hashing).
  #
  # Byte strings are Strings in the ASCII-8BIT (binary) encoding; a UTF-8 String is text and is refused where bytes are required.
  module Fndsa
    FN_DSA_512_PUBLIC_KEY_BYTES = 897
    FN_DSA_512_SIGNATURE_BYTES = 666
    FN_DSA_1024_PUBLIC_KEY_BYTES = 1793
    FN_DSA_1024_SIGNATURE_BYTES = 1280

    VARIANT_PK_BYTES = { 'fn-dsa-512' => FN_DSA_512_PUBLIC_KEY_BYTES, 'fn-dsa-1024' => FN_DSA_1024_PUBLIC_KEY_BYTES }.freeze
    VARIANT_SIG_BYTES = { 'fn-dsa-512' => FN_DSA_512_SIGNATURE_BYTES, 'fn-dsa-1024' => FN_DSA_1024_SIGNATURE_BYTES }.freeze

    Suite = Struct.new(:alg, :variant, :has_ed25519, :sig_bytes, :needs_pq_pk, :pq_pk_bytes, :needs_pq_sig, :pq_sig_bytes, :fn_sig_bytes)

    def self.build_suite(alg, variant, hybrid)
      pk = VARIANT_PK_BYTES[variant]
      sig = VARIANT_SIG_BYTES[variant]
      Suite.new(alg, variant, hybrid, hybrid ? AtlasPca::ED25519_SIGNATURE_BYTES : sig, true, pk, hybrid, hybrid ? sig : 0, sig).freeze
    end

    FN_DSA_SUITES = {
      'fn-dsa-512' => build_suite('fn-dsa-512', 'fn-dsa-512', false),
      'fn-dsa-1024' => build_suite('fn-dsa-1024', 'fn-dsa-1024', false),
      'hybrid-ed25519-fn-dsa-512' => build_suite('hybrid-ed25519-fn-dsa-512', 'fn-dsa-512', true),
      'hybrid-ed25519-fn-dsa-1024' => build_suite('hybrid-ed25519-fn-dsa-1024', 'fn-dsa-1024', true)
    }.freeze

    # No FN-DSA backend is installed (or the library behind the native one is absent).
    class BackendMissing < RuntimeError; end

    NO_BACKEND_MESSAGE = 'no FN-DSA backend registered: supply one via set_falcon_backend (for example FndsaNative.native_backend)'

    # verify.call(pk, msg, sig) -> true/false is required; sign.call(sk, msg) -> bytes and keygen.call -> {'pk'=>, 'sk'=>} are optional (nil).
    # A sign lambda that takes a third (optional) argument also receives the 32-byte signing seed; keygen_seed.call(variant, seed32)
    # -> {'pk'=>, 'sk'=>} derives keys from a seed (both feed AtlasPca::FndsaKeyPair).
    FalconBackend = Struct.new(:verify, :sign, :keygen, :keygen_seed)

    NO_BACKEND = FalconBackend.new(->(*) { raise BackendMissing, NO_BACKEND_MESSAGE }, ->(*) { raise BackendMissing, NO_BACKEND_MESSAGE },
                                   ->(*) { raise BackendMissing, NO_BACKEND_MESSAGE }).freeze
    @backend = NO_BACKEND

    module_function

    def known_fndsa_alg?(x) = x.is_a?(String) && FN_DSA_SUITES.key?(x)
    def resolve_fndsa_alg(alg) = known_fndsa_alg?(alg) ? FN_DSA_SUITES[alg] : nil
    def fndsa_variant?(v) = v.is_a?(String) && VARIANT_PK_BYTES.key?(v)
    def bytes?(v) = v.is_a?(String) && v.encoding == Encoding::BINARY

    # Installing a backend also makes the core verifier's fn-dsa-512 / fn-dsa-1024 suites verify through it.
    def set_falcon_backend(backend)
      @backend = backend
      AtlasPca.register_fndsa_verifier(
        backend.equal?(NO_BACKEND) ? nil : ->(variant, pk, msg, sig) { fndsa_verify(variant, pk.b, msg.b, sig.b) }
      )
      AtlasPca.register_fndsa_signer(backend.equal?(NO_BACKEND) || !backend.sign.respond_to?(:call) ? nil : signer_for(backend))
    end

    def falcon_backend = @backend

    # The core signing seam over a backend. A 2-argument sign lambda never sees the seed.
    def signer_for(backend)
      {
        'sign' => lambda { |_variant, sk, msg, seed|
          s = backend.sign
          s.arity == 2 ? s.call(sk, msg) : s.call(sk, msg, seed)
        },
        'keygen' => lambda { |variant, seed|
          kg = backend.keygen_seed
          raise BackendMissing, 'FN-DSA backend cannot derive keys from a seed' unless kg.respond_to?(:call)

          kg.call(variant, seed)
        }
      }
    end

    def reset_falcon_backend = set_falcon_backend(NO_BACKEND)

    def fndsa_sign(variant, sk, msg)
      raise ArgumentError, "fndsaSign: unknown FN-DSA variant #{variant.inspect}" unless fndsa_variant?(variant)
      raise TypeError, 'fndsaSign: secret key must be a non-empty byte string' unless bytes?(sk) && !sk.empty?
      raise TypeError, 'fndsaSign: message must be bytes' unless bytes?(msg)

      signer = @backend.sign
      raise 'fndsaSign: FN-DSA backend is verify-only (no sign())' unless signer.respond_to?(:call)

      sig = signer.call(sk.b, msg.b)
      expected = VARIANT_SIG_BYTES[variant]
      unless bytes?(sig) && sig.bytesize == expected
        raise "fndsaSign: FN-DSA backend returned a bad signature; expected padded #{expected} bytes for '#{variant}'"
      end

      sig.b
    end

    # False for any length / type violation (before the backend is consulted); a backend that raises propagates.
    def fndsa_verify(variant, pk, msg, sig)
      return false unless fndsa_variant?(variant)
      return false unless bytes?(pk) && pk.bytesize == VARIANT_PK_BYTES[variant]
      return false unless bytes?(sig) && sig.bytesize == VARIANT_SIG_BYTES[variant]
      return false unless bytes?(msg)

      @backend.verify.call(pk.b, msg.b, sig.b) == true
    end

    # ---- hybrid leaf composition

    FN_DSA_LEAF_DOMAIN = "atlas-pca/fn-dsa/leaf/v1\x00".b.freeze

    def utf8_bytes(s) = s.dup.force_encoding(Encoding::UTF_8).scrub("�").b

    # threshold_message(leaf) || domain || alg || 0x00 || the base64url FN-DSA public key text (alg and key are bound).
    def fndsa_leaf_message(leaf, alg, pq_pk_b64u)
      raise TypeError, 'fndsaLeafMessage: alg and pq_pk must be strings' unless alg.is_a?(String) && pq_pk_b64u.is_a?(String)

      AtlasPca.threshold_message(leaf).b + FN_DSA_LEAF_DOMAIN + utf8_bytes(alg) + "\x00".b + utf8_bytes(pq_pk_b64u)
    end

    # {'sig', 'alg', 'pq_pk'[, 'pq_sig']}. fn_dsa is {'pk' => bytes, 'sk' => bytes}; hybrid suites also need the Ed25519 seed.
    def sign_pca_with_fndsa(alg, leaf, fn_dsa, ed_secret = nil)
      suite = resolve_fndsa_alg(alg)
      raise ArgumentError, "signPcaWithFndsa: unknown FN-DSA alg #{alg.inspect}" if suite.nil?

      pk = fn_dsa.is_a?(Hash) ? fn_dsa['pk'] : nil
      sk = fn_dsa.is_a?(Hash) ? fn_dsa['sk'] : nil
      raise TypeError, "signPcaWithFndsa: '#{suite.alg}' requires a #{suite.pq_pk_bytes}-byte FN-DSA public key" unless bytes?(pk) && pk.bytesize == suite.pq_pk_bytes
      raise TypeError, "signPcaWithFndsa: '#{suite.alg}' requires FN-DSA secret-key material" unless bytes?(sk) && !sk.empty?

      pq_pk = AtlasPca.b64e(pk)
      msg = fndsa_leaf_message(leaf, suite.alg, pq_pk)
      fn_sig = fndsa_sign(suite.variant, sk, msg)
      return { 'sig' => AtlasPca.b64e(fn_sig), 'alg' => suite.alg, 'pq_pk' => pq_pk } unless suite.has_ed25519
      raise TypeError, "signPcaWithFndsa: '#{suite.alg}' requires edSecret (Ed25519 leaf-holder secret key)" unless bytes?(ed_secret)

      ed_sig = OpenSSL::PKey.new_raw_private_key('ED25519', ed_secret).sign(nil, msg)
      { 'sig' => AtlasPca.b64e(ed_sig), 'alg' => suite.alg, 'pq_pk' => pq_pk, 'pq_sig' => AtlasPca.b64e(fn_sig) }
    end

    # Fail closed. A hybrid needs BOTH the Ed25519 half and the FN-DSA half; every length/encoding check runs before the backend.
    def verify_pca_fndsa(alg, leaf, holder = nil, pq_pk = nil, sig = nil, pq_sig = nil)
      suite = resolve_fndsa_alg(alg)
      return false if suite.nil?
      return false unless pq_pk.is_a?(String)

      pk = AtlasPca.b64d(pq_pk, suite.pq_pk_bytes)
      return false if pk.nil?

      msg = fndsa_leaf_message(leaf, suite.alg, pq_pk)
      unless suite.has_ed25519
        return false unless sig.is_a?(String)

        fn_sig = AtlasPca.b64d(sig, suite.sig_bytes)
        return false if fn_sig.nil?

        return fndsa_verify(suite.variant, pk, msg, fn_sig)
      end
      return false unless holder.is_a?(String) && sig.is_a?(String)
      return false if AtlasPca.b64d(sig, suite.sig_bytes).nil?

      ed_ok = AtlasPca.verify_b64u(holder, msg, sig)
      return false unless pq_sig.is_a?(String)

      fn_sig = AtlasPca.b64d(pq_sig, suite.pq_sig_bytes)
      return false if fn_sig.nil?

      pq_ok = fndsa_verify(suite.variant, pk, msg, fn_sig)
      ed_ok && pq_ok
    end

    # ---- deterministic mock backend: TEST ONLY (anyone can forge its signatures; never register it in production)

    MOCK_SK_TAG = "atlas-pca/fn-dsa/mock-sk/v1\x00".b.freeze
    MOCK_SIG_TAG = "fn-dsa/mock-sig/v1\x00".b.freeze

    def hash_kat(seed, out_len)
      raise ArgumentError, "Invalid typed array length: #{out_len}" if out_len.negative?

      seed = seed.b
      out = +''.b
      counter = 0
      while out.bytesize < out_len
        out << OpenSSL::Digest::SHA256.digest(seed + [counter].pack('N'))
        counter += 1
      end
      out.byteslice(0, out_len)
    end

    def sig_len_for_pk(n)
      case n
      when FN_DSA_512_PUBLIC_KEY_BYTES then FN_DSA_512_SIGNATURE_BYTES
      when FN_DSA_1024_PUBLIC_KEY_BYTES then FN_DSA_1024_SIGNATURE_BYTES
      end
    end

    def derive_mock_sig(pk, msg)
      n = sig_len_for_pk(pk.bytesize)
      n.nil? ? nil : hash_kat(MOCK_SIG_TAG + pk + msg, n)
    end

    def same_bytes?(a, b) = a.bytesize == b.bytesize && OpenSSL.fixed_length_secure_compare(a, b)

    # seed: a text String ("variant/seed" in UTF-8) or a byte String (variant + "/" + bytes).
    def mock_keypair(variant, seed = 'default')
      raise ArgumentError, "mockKeypair: unknown FN-DSA variant #{variant.inspect}" unless fndsa_variant?(variant)

      seed_bytes = bytes?(seed) ? "#{variant}/".b + seed : utf8_bytes("#{variant}/#{seed}")
      pk = hash_kat(seed_bytes, VARIANT_PK_BYTES[variant])
      { 'pk' => pk, 'sk' => MOCK_SK_TAG + pk }
    end

    # TEST ONLY: installs a hash-derived backend (optionally with explicit known-answer vectors, [{'pk','msg','sig'}], that take precedence).
    def register_test_backend(vectors = nil)
      table = {}
      (vectors || []).each { |v| table["#{AtlasPca.b64e(v['pk'])}|#{AtlasPca.b64e(v['msg'])}"] = v['sig'].b }

      verify = lambda do |pk, msg, sig|
        expected = table["#{AtlasPca.b64e(pk)}|#{AtlasPca.b64e(msg)}"] || derive_mock_sig(pk, msg)
        !expected.nil? && same_bytes?(sig, expected)
      end
      sign = lambda do |sk, msg|
        tag = MOCK_SK_TAG.bytesize
        raise ArgumentError, 'mock FN-DSA backend: secret key was not minted by mock_keypair()' unless sk.bytesize > tag && same_bytes?(sk.byteslice(0, tag), MOCK_SK_TAG)

        pk = sk.byteslice(tag, sk.bytesize - tag)
        known = table["#{AtlasPca.b64e(pk)}|#{AtlasPca.b64e(msg)}"]
        next known unless known.nil?

        derive_mock_sig(pk, msg) || raise(ArgumentError, 'mock FN-DSA backend: public key length matches no FN-DSA variant')
      end
      backend = FalconBackend.new(verify, sign, -> { mock_keypair('fn-dsa-512') })
      set_falcon_backend(backend)
      backend
    end
  end
end
