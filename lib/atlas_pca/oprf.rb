# frozen_string_literal: true

# RFC 9497 OPRF / VOPRF / POPRF on ristretto255-SHA512 plus the PCA private-revocation and private-rate-limit layer (the TypeScript
# reference, @atlasauth/pca-oprf). Group arithmetic is libsodium's ristretto255 through RatchetGroup (lazy ffi; fails closed with
# LoadError when libsodium is missing). Byte inputs are binary Strings (String#b); a UTF-8 text String is refused as "not bytes".
# Scalars cross the API as Integers, which are not constant time.
#
# Native-stricter: the reference silently routes any mode other than 'oprf' through the verifiable path in blind_evaluate and skips
# proof verification in finalize for anything but 'voprf'; here an unknown mode (or 'poprf' on the non-POPRF entry points) is refused.
require 'digest'
require 'set'
require 'openssl'
require_relative 'ratchet_group'

module AtlasPca
  module Oprf
    G = RatchetGroup
    ORDER = G::L
    ELEMENT_BYTES = 32
    SCALAR_BYTES = 32
    OUTPUT_BYTES = 64
    SUITE_ID = 'ristretto255-SHA512'
    MODE = { 'oprf' => 0x00, 'voprf' => 0x01, 'poprf' => 0x02 }.freeze
    MAX_FRAMED = 0xFFFF

    module_function

    # ---- plumbing

    def bytes!(v, what, max_len = nil)
      raise TypeError, "#{what}: expected bytes" unless v.is_a?(String) && v.encoding == Encoding::BINARY
      if !max_len.nil? && v.bytesize > max_len
        raise ArgumentError, "#{what}: #{v.bytesize} bytes exceeds the #{max_len}-byte limit (RFC 9497 2-byte length framing)"
      end

      v
    end

    def i2osp(n, len)
      raise RangeError, 'i2osp: does not fit' if n.negative? || n.bit_length > len * 8

      [n.to_s(16).rjust(len * 2, '0')].pack('H*')
    end

    def context(mode)
      raise ArgumentError, "unknown OPRF mode #{mode.inspect}" unless MODE.key?(mode)

      "OPRFV1-".b + i2osp(MODE[mode], 1) + '-'.b + SUITE_ID.b
    end

    def server_mode!(mode)
      raise ArgumentError, "mode must be 'oprf' or 'voprf', got #{mode.inspect}" unless %w[oprf voprf].include?(mode)

      mode
    end

    # the reference's multiply() rejects 0 and anything >= the group order
    def mul(pt, k)
      raise ArgumentError, "expected valid scalar: 1 <= n < #{ORDER}, got #{k}" unless k >= 1 && k < ORDER

      G.mul(pt, k)
    end

    def mul_unsafe(pt, k)
      raise ArgumentError, "expected valid scalar: 0 <= n < #{ORDER}, got #{k}" unless k >= 0 && k < ORDER

      G.mul(pt, k)
    end

    def identity?(p) = G.equals(p, G::ZERO)
    def base_mult(k) = mul(G::G, k % ORDER)

    # RFC 9380 expand_message_xmd with SHA-512 for the 64-byte output every suite step needs (a single block).
    def expand_message_xmd(msg, dst)
      dst = Digest::SHA512.digest("H2C-OVERSIZE-DST-".b + dst) if dst.bytesize > 255
      dst_prime = dst + [dst.bytesize].pack('C')
      b0 = Digest::SHA512.digest(("\0".b * 128) + msg + [64].pack('n') + "\0".b + dst_prime)
      Digest::SHA512.digest(b0 + "\x01".b + dst_prime)
    end

    def hash_to_scalar_dst(data, dst) = G.le(expand_message_xmd(data, dst)) % ORDER
    def hash_to_scalar(data, mode) = hash_to_scalar_dst(data, "HashToScalar-".b + context(mode))

    def scalar_invert(s)
      v = s % ORDER
      raise ArgumentError, 'scalarInvert: inverse of zero' if v.zero?

      v.pow(ORDER - 2, ORDER)
    end

    # ---- (de)serialisation

    def serialize_element(p) = G.to_raw_bytes(p)

    def deserialize_element(b)
      p = G.check(bytes!(b, 'DeserializeElement'))
      raise ArgumentError, 'DeserializeElement: identity element is not a valid input' if identity?(p)

      p
    end

    def serialize_scalar(s) = G.le_bytes(s % ORDER, SCALAR_BYTES)

    def deserialize_scalar(b)
      raw = bytes!(b, 'DeserializeScalar')
      raise ArgumentError, "DeserializeScalar: expected #{SCALAR_BYTES} bytes, got #{raw.bytesize}" unless raw.bytesize == SCALAR_BYTES

      n = G.le(raw)
      raise ArgumentError, 'DeserializeScalar: non-canonical scalar (value >= group order)' if n >= ORDER

      n
    end

    def hash_to_group(data, mode) = G.hash_to_curve(expand_message_xmd(bytes!(data, 'HashToGroup'), 'HashToGroup-'.b + context(mode)))

    def random_scalar
      8.times do
        s = G.rand_scalar
        return s unless s.zero?
      end
      raise 'randomScalar: entropy source returned zero repeatedly (RNG failure); refusing to continue'
    end

    # ---- keys

    def derive_key_pair(seed, info, mode)
      raise ArgumentError, "DeriveKeyPair: seed must be exactly #{SCALAR_BYTES} bytes" unless seed.is_a?(String) && seed.encoding == Encoding::BINARY && seed.bytesize == SCALAR_BYTES

      info = bytes!(info, 'DeriveKeyPair(info)')
      dst = 'DeriveKeyPair'.b + context(mode)
      derive_input = seed + i2osp(info.bytesize, 2) + info
      256.times do |counter|
        sk = hash_to_scalar_dst(derive_input + [counter].pack('C'), dst)
        return { 'secret_key' => serialize_scalar(sk), 'public_key' => serialize_element(base_mult(sk)) } unless sk.zero?
      end
      raise 'DeriveKeyPair: failed to derive a non-zero key after 256 attempts'
    end

    def random_key_pair
      sk = random_scalar
      { 'secret_key' => serialize_scalar(sk), 'public_key' => serialize_element(base_mult(sk)) }
    end

    def public_key_for(secret_key) = serialize_element(base_mult(deserialize_scalar(secret_key)))

    # ---- DLEQ proofs (RFC 9497 section 2.2.1)

    def composites_seed(b_ser, mode)
      seed_dst = 'Seed-'.b + context(mode)
      Digest::SHA512.digest(i2osp(b_ser.bytesize, 2) + b_ser + i2osp(seed_dst.bytesize, 2) + seed_dst)
    end

    def composite_coefficient(seed, index, c_ser, d_ser, mode)
      transcript = i2osp(seed.bytesize, 2) + seed + i2osp(index, 2) + i2osp(c_ser.bytesize, 2) + c_ser +
                   i2osp(d_ser.bytesize, 2) + d_ser + 'Composite'.b
      hash_to_scalar(transcript, mode)
    end

    def composites(b, c, d, mode)
      seed = composites_seed(serialize_element(b), mode)
      coeff = composite_coefficient(seed, 0, serialize_element(c), serialize_element(d), mode)
      [mul_unsafe(c, coeff), mul_unsafe(d, coeff)]
    end

    def challenge(b, m, z, t2, t3, mode)
      parts = [b, m, z, t2, t3].map { |p| s = serialize_element(p); i2osp(s.bytesize, 2) + s }.join.b
      hash_to_scalar(parts + 'Challenge'.b, mode)
    end

    def generate_proof(k, a, b, c, d, mode, fixed_randomness = nil)
      m, = composites(b, c, d, mode)
      z = mul(m, k % ORDER)
      r = fixed_randomness.nil? ? random_scalar : deserialize_scalar(fixed_randomness)
      t2 = mul(a, r)
      t3 = mul(m, r)
      cc = challenge(b, m, z, t2, t3, mode)
      s = (r - (cc * k)) % ORDER
      serialize_scalar(cc) + serialize_scalar(s)
    end

    def verify_proof(a, b, c, d, proof, mode)
      proof = bytes!(proof, 'proof')
      return false unless proof.bytesize == 2 * SCALAR_BYTES

      cc = deserialize_scalar(proof.byteslice(0, SCALAR_BYTES))
      s = deserialize_scalar(proof.byteslice(SCALAR_BYTES, SCALAR_BYTES))
      m, z = composites(b, c, d, mode)
      t2 = G.add(mul_unsafe(a, s), mul_unsafe(b, cc))
      t3 = G.add(mul_unsafe(m, s), mul_unsafe(z, cc))
      ((challenge(b, m, z, t2, t3, mode) - cc) % ORDER).zero?
    end

    def finalize_hash(data, issued)
      Digest::SHA512.digest(i2osp(data.bytesize, 2) + data + i2osp(issued.bytesize, 2) + issued + 'Finalize'.b)
    end

    def finalize_hash_poprf(data, info, issued)
      Digest::SHA512.digest(i2osp(data.bytesize, 2) + data + i2osp(info.bytesize, 2) + info + i2osp(issued.bytesize, 2) + issued + 'Finalize'.b)
    end

    # ---- OPRF / VOPRF

    # Client step 1. The blind is the client's secret.
    def blind(data, mode = 'oprf', fixed_blind = nil)
      data = bytes!(data, 'Blind(input)', MAX_FRAMED)
      r = fixed_blind.nil? ? random_scalar : deserialize_scalar(fixed_blind)
      element = hash_to_group(data, mode)
      raise ArgumentError, 'Blind: input maps to identity' if identity?(element)

      { 'blind' => serialize_scalar(r), 'blinded_element' => serialize_element(mul(element, r)) }
    end

    def blind_evaluate(secret_key, blinded_element, mode = 'oprf', public_key = nil, fixed_proof_randomness = nil)
      server_mode!(mode)
      sk = deserialize_scalar(secret_key)
      r = deserialize_element(blinded_element)
      evaluated = mul(r, sk)
      return { 'evaluated_element' => serialize_element(evaluated) } if mode == 'oprf'

      pk = public_key.nil? ? base_mult(sk) : deserialize_element(public_key)
      { 'evaluated_element' => serialize_element(evaluated), 'proof' => generate_proof(sk, G::G, pk, r, evaluated, 'voprf', fixed_proof_randomness) }
    end

    def finalize(data, blind_scalar, evaluated_element, mode = 'oprf', proof = nil, public_key = nil, blinded_element = nil)
      data = bytes!(data, 'Finalize(input)', MAX_FRAMED)
      server_mode!(mode)
      r = deserialize_scalar(blind_scalar)
      evaluated = deserialize_element(evaluated_element)
      if mode == 'voprf'
        raise ArgumentError, 'Finalize(voprf): proof, publicKey and blindedElement are required' if proof.nil? || public_key.nil? || blinded_element.nil?

        pk = deserialize_element(public_key)
        blinded = deserialize_element(blinded_element)
        raise ArgumentError, 'Finalize(voprf): DLEQ proof verification failed' unless verify_proof(G::G, pk, blinded, evaluated, proof, 'voprf')
      end
      finalize_hash(data, serialize_element(mul(evaluated, scalar_invert(r))))
    end

    def evaluate(secret_key, data, mode = 'oprf')
      data = bytes!(data, 'Evaluate(input)', MAX_FRAMED)
      server_mode!(mode)
      sk = deserialize_scalar(secret_key)
      element = hash_to_group(data, mode)
      raise ArgumentError, 'Evaluate: input maps to identity' if identity?(element)

      finalize_hash(data, serialize_element(mul(element, sk)))
    end

    # ---- POPRF (the public input `info` is bound into the evaluation)

    def poprf_info_scalar(info)
      info = bytes!(info, 'info', MAX_FRAMED)
      hash_to_scalar('Info'.b + i2osp(info.bytesize, 2) + info, 'poprf')
    end

    def blind_poprf(data, info, public_key, fixed_blind = nil)
      data = bytes!(data, 'Blind(input)', MAX_FRAMED)
      m = poprf_info_scalar(info)
      tweaked = G.add(base_mult(m), deserialize_element(public_key))
      raise ArgumentError, 'Blind(poprf): tweaked key is identity' if identity?(tweaked)

      blind(data, 'poprf', fixed_blind).merge('tweaked_key' => serialize_element(tweaked))
    end

    def blind_evaluate_poprf(secret_key, blinded_element, info, fixed_proof_randomness = nil)
      sk = deserialize_scalar(secret_key)
      t = (sk + poprf_info_scalar(info)) % ORDER
      raise ArgumentError, 'BlindEvaluate(poprf): inverse of zero (bad info/key)' if t.zero?

      blinded = deserialize_element(blinded_element)
      evaluated = mul(blinded, scalar_invert(t))
      proof = generate_proof(t, G::G, base_mult(t), evaluated, blinded, 'poprf', fixed_proof_randomness)
      { 'evaluated_element' => serialize_element(evaluated), 'proof' => proof }
    end

    def finalize_poprf(data, blind_scalar, evaluated_element, info, proof, blinded_element, tweaked_key)
      data = bytes!(data, 'Finalize(input)', MAX_FRAMED)
      info = bytes!(info, 'info', MAX_FRAMED)
      r = deserialize_scalar(blind_scalar)
      evaluated = deserialize_element(evaluated_element)
      blinded = deserialize_element(blinded_element)
      tweaked = deserialize_element(tweaked_key)
      raise ArgumentError, 'Finalize(poprf): DLEQ proof verification failed' unless verify_proof(G::G, tweaked, evaluated, blinded, proof, 'poprf')

      finalize_hash_poprf(data, info, serialize_element(mul(evaluated, scalar_invert(r))))
    end

    def evaluate_poprf(secret_key, data, info)
      data = bytes!(data, 'Evaluate(input)', MAX_FRAMED)
      sk = deserialize_scalar(secret_key)
      t = (sk + poprf_info_scalar(info)) % ORDER
      raise ArgumentError, 'Evaluate(poprf): inverse of zero (bad info/key)' if t.zero?

      element = hash_to_group(data, 'poprf')
      raise ArgumentError, 'Evaluate(poprf): input maps to identity' if identity?(element)

      finalize_hash_poprf(data, bytes!(info, 'info'), serialize_element(mul(element, scalar_invert(t))))
    end

    def to_hex(b) = bytes!(b, 'toHex').unpack1('H*')

    def bytes_equal(a, b)
      a = bytes!(a, 'bytesEqual')
      b = bytes!(b, 'bytesEqual')
      a.bytesize == b.bytesize && OpenSSL.fixed_length_secure_compare(a, b)
    end

    # ---- PCA layer: private revocation (does my capability id appear in the revoked set, without telling the service which id?)

    def encode_strict(s, what)
      raise TypeError, "#{what} must be a string" unless s.is_a?(String)

      u = s.dup.force_encoding(Encoding::UTF_8)
      raise ArgumentError, "#{what} contains an unpaired surrogate (ill-formed UTF-16)" unless u.valid_encoding?

      u.b
    end

    # { 'outputs' => Set of hex PRF outputs, 'mode', 'public_key' (voprf only) }
    def build_revocation_set(secret_key, revoked_cap_ids, mode = 'oprf')
      server_mode!(mode)
      outputs = Set.new
      revoked_cap_ids.each { |cap_id| outputs << to_hex(evaluate(secret_key, encode_strict(cap_id, 'capability id'), mode)) }
      out = { 'outputs' => outputs, 'mode' => mode }
      out['public_key'] = public_key_for(secret_key) if mode == 'voprf'
      out
    end

    def make_revocation_evaluator(secret_key, mode = 'oprf')
      server_mode!(mode)
      public_key = mode == 'voprf' ? public_key_for(secret_key) : nil
      ->(blinded) { blind_evaluate(secret_key, blinded, mode, public_key) }
    end

    def revoked_private?(cap_id, blind_eval, revoked_set)
      data = encode_strict(cap_id, 'capability id')
      mode = revoked_set['mode']
      b = blind(data, mode)
      res = blind_eval.call(b['blinded_element'])
      out =
        if mode == 'voprf'
          pk = revoked_set['public_key']
          raise ArgumentError, 'isRevokedPrivate(voprf): missing DLEQ proof or service public key' if res['proof'].nil? || pk.nil?

          finalize(data, b['blind'], res['evaluated_element'], 'voprf', res['proof'], pk, b['blinded_element'])
        else
          finalize(data, b['blind'], res['evaluated_element'], 'oprf')
        end
      revoked_set['outputs'].include?(to_hex(out))
    end

    # ---- PCA layer: private rate limiting (a per-window POPRF token the service cannot link to the identifier)

    def rate_token(secret_key, identifier, window) = evaluate_poprf(secret_key, encode_strict(identifier, 'identifier'), encode_strict(window, 'window'))
    def rate_token_hex(secret_key, identifier, window) = to_hex(rate_token(secret_key, identifier, window))

    def make_rate_evaluator(secret_key)
      ->(blinded, window) { blind_evaluate_poprf(secret_key, blinded, encode_strict(window, 'window')) }
    end

    def private_rate_token(identifier, window, blind_eval, public_key)
      data = encode_strict(identifier, 'identifier')
      info = encode_strict(window, 'window')
      b = blind_poprf(data, info, public_key)
      res = blind_eval.call(b['blinded_element'], window)
      raise ArgumentError, 'privateRateToken: POPRF blind-evaluation did not return a DLEQ proof' if res['proof'].nil?

      finalize_poprf(data, b['blind'], res['evaluated_element'], info, res['proof'], b['blinded_element'], b['tweaked_key'])
    end

    class RateWindowCounter
      def initialize(limit)
        ok = limit.is_a?(Integer) || (limit.is_a?(Float) && limit.finite? && limit == limit.floor)
        raise TypeError, 'RateWindowCounter: limit must be a positive integer' if !ok || limit < 1

        @limit = limit
        @counts = {}
      end

      def hit(token)
        key = Oprf.to_hex(token)
        count = @counts.fetch(key, 0) + 1
        @counts[key] = count
        { 'count' => count, 'allowed' => count <= @limit }
      end

      def count(token) = @counts.fetch(Oprf.to_hex(token), 0)
      def reset = @counts.clear
    end
  end
end
