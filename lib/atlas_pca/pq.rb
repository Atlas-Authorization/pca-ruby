# frozen_string_literal: true

require 'digest'
require 'openssl'

module AtlasPca
  # The post-quantum suite surface of the TypeScript reference (`pq`): the size constants of every registered PQ suite, per-suite
  # keygen / sign / verify wrappers, the public key encoders, the suite predicates and the LAMPS composite-ML-DSA wire format
  # (draft-ietf-lamps-pq-composite-sigs). Keys are the SDK's key objects (`PqKeyPair`, `FndsaKeyPair`, `KeyPair`): OpenSSL does not
  # hand out a raw ML-DSA / SLH-DSA secret key, so signing takes the key pair and verifying takes raw (or base64url) public bytes.
  module Pq
    ML_DSA_65_PUBLIC_KEY_BYTES = 1952
    ML_DSA_65_SIGNATURE_BYTES = 3309
    ML_DSA_65_SEED_BYTES = 32
    ML_DSA_87_PUBLIC_KEY_BYTES = 2592
    ML_DSA_87_SIGNATURE_BYTES = 4627
    ML_DSA_87_SEED_BYTES = 32
    SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES = 32
    SLH_DSA_SHA2_128F_SECRET_KEY_BYTES = 64
    SLH_DSA_SHA2_128F_SIGNATURE_BYTES = 17_088
    SLH_DSA_SHA2_128F_SEED_BYTES = 48
    SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES = 64
    SLH_DSA_SHA2_256S_SECRET_KEY_BYTES = 128
    SLH_DSA_SHA2_256S_SIGNATURE_BYTES = 29_792
    SLH_DSA_SHA2_256S_SEED_BYTES = 96
    FN_DSA_512_PUBLIC_KEY_BYTES = 897
    FN_DSA_512_SECRET_KEY_BYTES = 1345
    FN_DSA_512_SIGNATURE_BYTES = 666
    FN_DSA_1024_PUBLIC_KEY_BYTES = 1793
    FN_DSA_1024_SECRET_KEY_BYTES = 2369
    FN_DSA_1024_SIGNATURE_BYTES = 1280
    FN_DSA_SEED_BYTES = 32
    LESS_CAT1_PUBLIC_KEY_BYTES = 97_484
    LESS_CAT1_SECRET_KEY_BYTES = 32
    LESS_CAT1_SIGNATURE_MAX_BYTES = 1329
    LESS_CAT1_SIGNATURE_MIN_BYTES = 1153
    LESS_CAT1_SIGNATURE_STEP_BYTES = 16
    LESS_SEED_BYTES = 32
    ED25519_SIGNATURE_BYTES = 64

    # The composite-signature Prefix, the registered Label of id-MLDSA65-Ed25519-SHA512 and the composite signature length.
    COMPOSITE_PREFIX = 'CompositeAlgorithmSignatures2025'
    COMPOSITE_LABEL = 'COMPSIG-MLDSA65-Ed25519-SHA512'
    COMPOSITE_SIGNATURE_BYTES = ML_DSA_65_SIGNATURE_BYTES + ED25519_SIGNATURE_BYTES

    # name => OpenSSL / registry primitive of every per-suite wrapper (`<name>_keygen`, `_sign`, `_verify`, `_verify_b64u`).
    SUITES = { 'ml_dsa65' => 'ML-DSA-65', 'ml_dsa87' => 'ML-DSA-87', 'slh_dsa128f' => 'SLH-DSA-SHA2-128f', 'slh_dsa256s' => 'SLH-DSA-SHA2-256s',
               'fn_dsa512' => 'FN-DSA-512', 'fn_dsa1024' => 'FN-DSA-1024' }.freeze

    extend self

    SUITES.each do |name, prim|
      # Deterministic keygen from the suite's seed (nil: a fresh random key); raises when this runtime cannot make the key.
      define_method(:"#{name}_keygen") { |seed = nil| seed.nil? ? PqKeyPair.generate(prim) : PqKeyPair.from_seed(prim, seed) }
      # Sign with a key pair of this suite (a PqKeyPair; FN-DSA: FndsaKeyPair). ML-DSA / SLH-DSA are the deterministic variants.
      define_method(:"#{name}_sign") do |key, msg|
        raise ArgumentError, "#{name}_sign needs a #{prim} key pair" unless key.respond_to?(:prim) && key.prim == prim

        key.sign(msg)
      end
      define_method(:"#{name}_verify") { |pk, msg, sig| AtlasPca.pq_verify(prim, pk, msg, sig) }
      define_method(:"#{name}_verify_b64u") { |pk, msg, sig| AtlasPca.pq_verify_b64u(prim, pk, msg, sig) }
    end

    # LESS-cat1 keygen / sign over the shared C library (the key pair is a LessKeyPair; signatures are randomized).
    def less_cat1_keygen(seed = nil) = seed.nil? ? PqKeyPair.generate(LessFfi::KEY_TYPE) : PqKeyPair.from_seed(LessFfi::KEY_TYPE, seed)

    def less_cat1_sign(key, msg)
      raise ArgumentError, 'less_cat1_sign needs a LESS-cat1 key pair' unless key.respond_to?(:prim) && key.prim == LessFfi::KEY_TYPE

      key.sign(msg)
    end

    # LESS-cat1 verification over base64url key and signature (this SDK verifies LESS through the optional native binding only).
    def less_cat1_verify_b64u(pk, msg, sig) = AtlasPca.pq_verify_b64u(LessFfi::KEY_TYPE, pk, msg, sig)

    # Whether the optional LESS backend is loadable (else every LESS suite verify fails closed), and the status record.
    def less_backend_active? = LessFfi.available?
    def less_backend_status = LessFfi.available? ? { 'available' => true } : { 'available' => false, 'reason' => 'the LESS native binding is not installed' }

    # The base64url `pq_pk` of a public key (raw bytes), for every suite (the same encoding in each slot).
    def encode_public_key(public_key) = AtlasPca.b64e(public_key)
    %w[ml_dsa ml_dsa87 slh_dsa slh_dsa256s fn_dsa less].each { |n| alias_method :"encode_#{n}_public_key", :encode_public_key }

    # True when `x` is a registered signature suite name.
    def known_sig_alg?(x) = x.is_a?(String) && SIG_SUITES.key?(x)

    # True for a key minted by the PQ verify-key choke point (`resolve_pq_key`).
    def pinned_pq_key?(x) = x.is_a?(PinnedPq)

    # True when `pq` is canonical base64url of a byte string with the public-key length of a registered PQ suite.
    def well_formed_pq_public_key?(pq)
      return false unless pq.is_a?(String)

      b = AtlasPca.b64d(pq)
      !b.nil? && PQ_PRIMS.values.map(&:first).include?(b.bytesize)
    end

    SUITE_KEY_SLOTS = { 'ML-DSA-65' => 'ml_dsa', 'ML-DSA-87' => 'ml_dsa87', 'SLH-DSA-SHA2-128f' => 'slh_dsa', 'SLH-DSA-SHA2-256s' => 'slh_dsa256s',
                        'FN-DSA-512' => 'fn_dsa512', 'FN-DSA-1024' => 'fn_dsa1024', 'LESS-cat1' => 'less_cat1' }.freeze

    # The base64url `pq_pk` that `alg` selects from `keys` ({'ml_dsa' => PqKeyPair, ...}), or nil for ed25519 / an unknown alg / when
    # the key material for the suite was not supplied (signing then raises, fail closed).
    def suite_pq_public_key(alg, keys)
      spec = SIG_SUITES[alg.nil? ? 'ed25519' : alg]
      return nil if spec.nil? || !spec[1] || !keys.is_a?(Hash)

      pair = keys.transform_keys(&:to_s)[SUITE_KEY_SLOTS[spec[3]]]
      pair.respond_to?(:public) ? pair.public : nil
    end

    # The key material a surface signs with: the identity's Ed25519 key plus the PQ key pairs of the caller's suite options.
    def suite_keys_of(ed_key, suite = nil)
      (suite.is_a?(Hash) ? suite.transform_keys(&:to_s).reject { |k, _| k == 'alg' } : {}).merge('ed' => ed_key)
    end

    # Sign `msg` and return every wire field an artifact carries for its suite: only {'sig'} for the default suite, else also 'alg',
    # the signer's 'pq_pk' and (hybrid) 'pq_sig'. `keys` is {suite_keys_of}.
    def sign_suite_artifact(alg, keys, msg)
      alg = nil if alg == 'ed25519'
      keys = keys.transform_keys(&:to_s)
      spec = SIG_SUITES[alg || 'ed25519']
      pair = spec && spec[1] ? keys[SUITE_KEY_SLOTS[spec[3]]] : nil
      sig, pq_sig = AtlasPca.sign_with_suite(alg, keys['ed'], pair, msg)
      return { 'sig' => sig } if alg.nil?

      out = { 'sig' => sig, 'alg' => alg }
      pk = suite_pq_public_key(alg, keys)
      out['pq_pk'] = pk unless pk.nil?
      out['pq_sig'] = pq_sig unless pq_sig.nil?
      out
    end

    # M' = Prefix || Label || len(ctx) || ctx || SHA-512(message). A context over 255 bytes raises RangeError.
    def composite_representative(message, ctx = nil)
      c = ctx.nil? ? ''.b : ctx.to_s.b
      raise RangeError, 'composite_representative: ctx exceeds 255 bytes' if c.bytesize > 255

      COMPOSITE_PREFIX.b + COMPOSITE_LABEL.b + [c.bytesize].pack('C') + c + Digest::SHA512.digest(message.b)
    end

    # A LAMPS composite signature over `message`: `mldsa_sig || trad_sig`, both over M'. `ed25519` is a KeyPair, `ml_dsa` a PqKeyPair
    # of ML-DSA-65. Returns the 3373-byte blob; raises on missing key material or a context over 255 bytes.
    def composite_sign(ed25519:, ml_dsa:, message:, ctx: nil)
      raise ArgumentError, 'composite_sign: ed25519 key required' unless ed25519.respond_to?(:sign)
      raise ArgumentError, 'composite_sign: ml_dsa key pair (ML-DSA-65) required' unless ml_dsa.respond_to?(:prim) && ml_dsa.prim == 'ML-DSA-65'

      m = composite_representative(message, ctx)
      ml_dsa.sign(m) + ed25519.sign(m)
    end

    # Verify a composite signature (fail closed): the total length, both components over the same M', and a context that matches the
    # signer's. `ed25519_pub` and `ml_dsa_pub` are raw public keys. Never raises.
    def composite_verify(ed25519_pub:, ml_dsa_pub:, message:, signature:, ctx: nil)
      return false unless signature.is_a?(String) && signature.bytesize == COMPOSITE_SIGNATURE_BYTES

      sig = signature.b
      m = composite_representative(message, ctx)
      ml_ok = AtlasPca.pq_verify('ML-DSA-65', ml_dsa_pub.to_s.b, m, sig.byteslice(0, ML_DSA_65_SIGNATURE_BYTES))
      ed_ok = begin
        OpenSSL::PKey.new_raw_public_key('ED25519', ed25519_pub.to_s.b).verify(nil, sig.byteslice(ML_DSA_65_SIGNATURE_BYTES, 64), m)
      rescue StandardError
        false
      end
      ml_ok && ed_ok
    rescue StandardError
      false
    end
  end
end
