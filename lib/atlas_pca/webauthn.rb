# frozen_string_literal: true

require 'openssl'
require_relative 'js_compat'
require_relative 'jose'

# Phishing-resistant human co-sign for PCA step-up via WebAuthn / FIDO2, byte-identical to the TypeScript reference. A passkey
# assertion IS the human approval proof when its challenge equals the PCA step-up challenge (the action digest,
# sha256(threshold_message(pcactn))): the signature covers authenticatorData || sha256(clientDataJSON), so a phished origin fails
# the origin + rpIdHash binding and a replayed assertion fails the challenge binding. Server-side verify only. ES256 (P-256)
# and EdDSA (Ed25519), with a minimal, bounded COSE_Key / CBOR reader. Every public entry point fails CLOSED.
# Bytes are binary Strings (Encoding::BINARY); a text String is never taken as bytes. Hashes are String-keyed snake_case; an
# absent key and a nil value differ exactly as `undefined` and `null` do in the reference.
module AtlasPca
  module WebAuthn
    # A refusal from this package (the message is the reference's).
    class Error < StandardError; end

    MAX_AUTHENTICATOR_DATA_BYTES = 4096
    MAX_CLIENT_DATA_BYTES = 8192
    MAX_SIGNATURE_BYTES = 1024
    COSE_KTY = 1
    COSE_CRV = -1
    COSE_X = -2
    COSE_Y = -3
    P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    UNDEF = Object.new.freeze

    module_function

    def bytes?(v) = v.is_a?(String) && v.encoding == Encoding::BINARY
    def sha256(b) = OpenSSL::Digest::SHA256.digest(b)
    def b64u(b) = AtlasPca.b64e(b)
    def same?(a, b) = SdJwt.js_same(a, b)

    def bytes_equal?(a, b) = a.bytesize == b.bytesize && OpenSSL.fixed_length_secure_compare(a, b)

    # Tolerant base64url: the URL alphabet with or without `=` padding (`+` and `/` accepted); nil for anything else.
    def tolerant_b64d(s)
      return nil unless s.is_a?(String)

      AtlasPca.b64d(s.sub(/=+\z/, '').tr('+/', '-_'))
    end

    # ---- minimal COSE_Key / CBOR reader ----
    # Unsigned ints (major 0), negative ints (1), byte strings (2) and maps (5), with 1/2/4-byte arguments. Indefinite length
    # and 8-byte arguments are rejected; map keys must be integers; trailing bytes after the first item are ignored.

    def read_cbor_item(b, offset)
      n = b.bytesize
      raise Error, 'cose: read past the end' if offset >= n

      initial = b.getbyte(offset)
      major = initial >> 5
      ai = initial & 0x1f
      p = offset + 1
      width = { 24 => 1, 25 => 2, 26 => 4 }[ai]
      if ai < 24
        arg = ai
      elsif width
        raise Error, 'cose: read past the end' if p + width > n

        arg = b.byteslice(p, width).bytes.reduce(0) { |acc, x| (acc << 8) | x }
        p += width
      else
        raise Error, 'cose: unsupported CBOR argument encoding (8-byte or indefinite length)'
      end
      case major
      when 0 then [arg, p]
      when 1 then [-1 - arg, p]
      when 2
        raise Error, 'cose: byte string length out of range' if p + arg > n

        [b.byteslice(p, arg), p + arg]
      when 5
        out = {}
        q = p
        arg.times do
          key, nxt = read_cbor_item(b, q)
          raise Error, 'cose: non-integer map key' unless key.is_a?(Integer)

          out[key], q = read_cbor_item(b, nxt)
        end
        [out, q]
      else raise Error, "cose: unsupported CBOR major type #{major}"
      end
    end

    # Decode a raw COSE_Key (attestedCredentialData.credentialPublicKey) into an ES256 (EC2 / P-256) or EdDSA (OKP / Ed25519)
    # JWK. Raises on malformed input or an unsupported key type.
    def cose_key_to_jwk(data)
      raise TypeError, 'coseKeyToJwk: expected bytes' unless bytes?(data)

      value, = read_cbor_item(data, 0)
      raise Error, 'coseKeyToJwk: COSE_Key is not a CBOR map' unless value.is_a?(Hash)

      kty = value[COSE_KTY]
      x = value[COSE_X]
      case kty
      when 2
        y = value[COSE_Y]
        raise Error, 'coseKeyToJwk: EC2 key is not P-256 (crv != 1)' unless value[COSE_CRV] == 1
        raise Error, 'coseKeyToJwk: EC2 key missing an x/y coordinate' unless bytes?(x) && bytes?(y)
        raise Error, 'coseKeyToJwk: EC2 coordinate is not 32 bytes' unless x.bytesize == 32 && y.bytesize == 32

        { 'kty' => 'EC', 'crv' => 'P-256', 'x' => b64u(x), 'y' => b64u(y), 'alg' => 'ES256' }
      when 1
        raise Error, 'coseKeyToJwk: OKP key is not Ed25519 (crv != 6)' unless value[COSE_CRV] == 6
        raise Error, 'coseKeyToJwk: OKP key missing its public key' unless bytes?(x)
        raise Error, 'coseKeyToJwk: Ed25519 public key is not 32 bytes' unless x.bytesize == 32

        { 'kty' => 'OKP', 'crv' => 'Ed25519', 'x' => b64u(x), 'alg' => 'EdDSA' }
      else
        raise Error, "coseKeyToJwk: unsupported COSE key type (kty=#{kty.nil? ? 'undefined' : Js.string(kty.is_a?(String) ? kty.dup.force_encoding('UTF-8') : kty)})"
      end
    end

    # The signature algorithm and the raw key it verifies with (65-byte SEC1 point for ES256, 32 bytes for EdDSA).
    def resolve_key(pub)
      jwk = bytes?(pub) ? cose_key_to_jwk(pub) : pub
      raise TypeError, "Cannot read properties of #{jwk.nil? ? 'undefined' : 'a non-object'} (reading 'kty')" unless jwk.is_a?(Hash)

      case jwk['kty']
      when 'EC'
        raise Error, 'resolveKey: EC JWK is not P-256' unless jwk['crv'] == 'P-256'

        x = tolerant_b64d(jwk['x'])
        y = tolerant_b64d(jwk['y'])
        raise Error, 'resolveKey: invalid EC JWK coordinates' if x.nil? || y.nil? || x.bytesize != 32 || y.bytesize != 32

        ['ES256', "\x04".b + x + y]
      when 'OKP'
        raise Error, 'resolveKey: OKP JWK is not Ed25519' unless jwk['crv'] == 'Ed25519'

        x = tolerant_b64d(jwk['x'])
        raise Error, 'resolveKey: invalid OKP JWK public key' if x.nil? || x.bytesize != 32

        ['EdDSA', x]
      else raise Error, 'resolveKey: unsupported public key'
      end
    end

    # ---- authenticatorData ----

    # The fixed 37-byte header (rpIdHash[32] || flags[1] || signCount[4]), or nil when the value is not bytes or too short.
    def parse_authenticator_data(auth_data)
      return nil unless bytes?(auth_data) && auth_data.bytesize >= 37

      f = auth_data.getbyte(32)
      { 'rpIdHash' => auth_data.byteslice(0, 32),
        'flags' => { 'up' => f & 0x01 != 0, 'uv' => f & 0x04 != 0, 'be' => f & 0x08 != 0, 'bs' => f & 0x10 != 0, 'at' => f & 0x40 != 0,
                     'ed' => f & 0x80 != 0 },
        'signCount' => auth_data.byteslice(33, 4).unpack1('N') }
    end

    # ---- step-up challenge binding ----

    # The WebAuthn challenge for a PCA step-up: sha256(threshold_message(pcactn)). Accepts a PCActn (or body), the base64url
    # digest string, or raw 32-byte digest bytes.
    def build_step_up_challenge(x)
      if bytes?(x)
        raise Error, 'buildStepUpChallenge: digest bytes must be 32 bytes' unless x.bytesize == 32

        return x.dup
      end
      if x.is_a?(String)
        return AtlasPca.b64d(x, 32) || raise(Error, 'buildStepUpChallenge: digest is not a canonical base64url 32-byte value')
      end

      sha256(AtlasPca.threshold_message(object_rest(x)))
    end

    # `const { sig, threshold, pq_sig, ...rest } = x` of a non-object: an array spreads its indices, a primitive spreads nothing.
    def object_rest(x)
      raise TypeError, "Cannot destructure '#{Js.string(x)}' as it is null." if x.nil?
      return x if x.is_a?(Hash)
      return x.each_with_index.to_h { |v, i| [i.to_s, v] } if x.is_a?(Array)

      {}
    end

    # What you see is what you sign: SHA-256(domain || action_digest || H(R)) over the canonical render.
    def build_approval_challenge(x, render_digest)
      AtlasPca.b64d(AtlasPca.approval_challenge(b64u(build_step_up_challenge(x)), render_digest))
    end

    def approval_challenge_for_actn(x, render_digest) = b64u(build_approval_challenge(x, render_digest))
    def step_up_challenge_b64u(x) = b64u(build_step_up_challenge(x))

    # ---- assertion verification ----

    def get(h, k) = h.is_a?(Hash) && h.key?(k) ? h[k] : UNDEF

    # nil if the signed payment data equals the expectation (Secure Payment Confirmation / PSD2 dynamic linking), else why not.
    def spc_payment_error(payment, e, rp_id)
      return 'clientData.payment is missing' unless payment.is_a?(Hash)
      unless e.key?('payeeName') || e.key?('payeeOrigin')
        return 'the expectation names no payee (refused: a payment approval must bind the payee)'
      end
      return 'clientData.payment.rpId is not the verifier rpId' unless same?(get(payment, 'rpId'), rp_id)
      return 'clientData.payment.topOrigin is not the verifier approval origin' unless same?(get(payment, 'topOrigin'), get(e, 'topOrigin'))

      total = payment['total']
      unless total.is_a?(Hash) && same?(get(total, 'currency'), get(etotal(e), 'currency')) && same?(get(total, 'value'), get(etotal(e), 'value'))
        return 'clientData.payment.total does not equal the canonical render'
      end

      %w[payeeName payeeOrigin].each do |k|
        return "clientData.payment.#{k} does not equal the canonical render" if e.key?(k) && !same?(get(payment, k), e[k])
      end
      nil
    end

    def etotal(e) = e['total'].nil? ? raise(TypeError, "Cannot read properties of #{Js.string(e['total'])} (reading 'currency')") : e['total']

    def uint32?(v)
      return false unless Js.num?(v)
      return false if v.is_a?(Float) && (!v.finite? || v != v.floor || Js.neg_zero?(v))

      v >= 0 && v <= 0xFFFFFFFF
    end

    def fail_with(reason) = { 'ok' => false, 'reason' => reason }

    def der_int(data)
      raise ArgumentError, 'negative' if !data.empty? && data.getbyte(0) & 0x80 != 0
      raise ArgumentError, 'leading zero' if !data.empty? && data.getbyte(0).zero? && !(data.bytesize > 1 && data.getbyte(1) & 0x80 != 0)

      data.unpack1('H*').then { |h| h.empty? ? 0 : h.to_i(16) }
    end

    def der_tlv(tag, data)
      raise ArgumentError, 'wrong tlv' if data.bytesize < 2 || data.getbyte(0) != tag

      first = data.getbyte(1)
      pos = 2
      if first & 0x80 == 0
        length = first
      else
        ll = first & 0x7f
        raise ArgumentError, 'bad length of length' if ll.zero? || ll > 4

        lb = data.byteslice(pos, ll) || ''.b
        raise ArgumentError, 'bad length bytes' if lb.bytesize != ll || lb.getbyte(0).zero?
        raise ArgumentError, 'length overflows 32 bits' if ll == 4 && lb.getbyte(0) & 0x80 != 0

        length = lb.bytes.reduce(0) { |a, x| (a << 8) | x }
        pos += ll
        raise ArgumentError, 'not minimal encoding' if length < 128
      end
      v = data.byteslice(pos, length) || ''.b
      raise ArgumentError, 'wrong value length' if v.bytesize != length

      [v, data.byteslice(pos + length..) || ''.b]
    end

    # ES256 over `signed`: a strictly-parsed DER or fixed 64-byte r||s signature, r and s in [1, n-1], optionally low-S.
    def ecdsa_p256_verify(point, signed, sig, der, low_s)
      begin
        if der
          seq, left = der_tlv(0x30, sig)
          return false unless left.empty?

          rb, rest = der_tlv(0x02, seq)
          sb, left = der_tlv(0x02, rest)
          return false unless left.empty?

          r = der_int(rb)
          s = der_int(sb)
        else
          return false unless sig.bytesize == 64

          r = sig.byteslice(0, 32).unpack1('H*').to_i(16)
          s = sig.byteslice(32, 32).unpack1('H*').to_i(16)
        end
      rescue ArgumentError
        return false
      end
      return false unless r >= 1 && r < P256_N && s >= 1 && s < P256_N
      return false if low_s && s > (P256_N >> 1)

      key = Jose.public_key_from_jwk({ 'kty' => 'EC', 'crv' => 'P-256', 'x' => b64u(point.byteslice(1, 32)), 'y' => b64u(point.byteslice(33, 32)) })
      key.verify('SHA256', OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der, signed)
    rescue OpenSSL::PKey::PKeyError, Jose::Error
      false
    end

    # Verify a WebAuthn / FIDO2 assertion as a human step-up co-sign; FAIL CLOSED, never raises on hostile input.
    # assertion: authenticator_data, client_data_json, signature (bytes) and public_key (a JWK Hash or a raw COSE_Key).
    # expect: expected_challenge (bytes or base64url), rp_id, origins, require_uv, stored_sign_count (REQUIRED: 0 for a
    # credential never used), optional require_low_s, reject_cross_origin (default true), payment (the SPC expectation, wire
    # names: topOrigin, total, payeeName / payeeOrigin) and on_sign_count_regression (called once with {storedSignCount,
    # reportedSignCount} when the counter rule refuses a verified signature). Returns {ok: true, alg, signCount, flags} or
    # {ok: false, reason}.
    def verify_assertion(assertion, expect)
      auth_data = assertion['authenticator_data']
      client_json = assertion['client_data_json']
      signature = assertion['signature']
      return fail_with('authenticatorData is not bytes') unless bytes?(auth_data)
      return fail_with('clientDataJSON is not bytes') unless bytes?(client_json)
      return fail_with('signature is not bytes') unless bytes?(signature)
      return fail_with('authenticatorData is too large') if auth_data.bytesize > MAX_AUTHENTICATOR_DATA_BYTES
      return fail_with('clientDataJSON is too large') if client_json.bytesize > MAX_CLIENT_DATA_BYTES
      return fail_with('signature is too large') if signature.bytesize > MAX_SIGNATURE_BYTES

      rp_id = expect['rp_id']
      return fail_with('rpId is required') unless rp_id.is_a?(String) && !rp_id.empty?

      origins = expect['origins']
      return fail_with('origins allowlist is empty') unless origins.is_a?(Array) && !origins.empty?
      return fail_with('storedSignCount is required (use 0 for a credential never used)') unless expect.key?('stored_sign_count')

      text = client_json.dup.force_encoding('UTF-8')
      return fail_with('clientDataJSON is not valid UTF-8') unless text.valid_encoding?

      text = text[1..] if text.start_with?("﻿") # a leading BOM is consumed, as TextDecoder does
      client = begin
        Js.parse_no_duplicates(text) # a duplicate member would otherwise keep the last value
      rescue AtlasPca::Malformed, SystemStackError
        return fail_with('clientDataJSON is not valid JSON')
      end
      return fail_with('clientDataJSON is not a JSON object') unless client.is_a?(Hash)

      payment = get(expect, 'payment')
      want = payment.equal?(UNDEF) ? 'webauthn.get' : 'payment.get'
      unless client['type'] == want
        return fail_with("clientData.type is not \"#{want}\" (#{client.key?('type') ? Js.string(client['type']) : 'undefined'})")
      end

      unless payment.equal?(UNDEF)
        pe = spc_payment_error(client['payment'], payment, rp_id)
        return fail_with(pe) if pe
      end

      got_challenge = AtlasPca.b64d(client['challenge']) # canonical base64url only
      return fail_with('clientData.challenge is missing or not canonical base64url') if got_challenge.nil?

      exp_in = expect['expected_challenge']
      exp_challenge = bytes?(exp_in) ? exp_in : AtlasPca.b64d(exp_in)
      return fail_with('expectedChallenge is not decodable') if exp_challenge.nil?
      return fail_with('clientData.challenge does not match the step-up challenge') unless bytes_equal?(got_challenge, exp_challenge)

      origin = client['origin']
      if expect['reject_cross_origin'] != false && client.key?('crossOrigin')
        return fail_with('clientData.crossOrigin is true') if client['crossOrigin'] == true
        return fail_with('clientData.crossOrigin is not a boolean') unless client['crossOrigin'] == false
      end
      return fail_with('clientData.origin is missing') unless origin.is_a?(String)
      return fail_with("clientData.origin \"#{origin}\" is not in the allowlist") unless origins.any? { |o| o.is_a?(String) && o == origin }

      parsed = parse_authenticator_data(auth_data)
      return fail_with('authenticatorData is too short (< 37 bytes)') if parsed.nil?
      return fail_with('rpIdHash does not match sha256(rpId)') unless bytes_equal?(parsed['rpIdHash'], sha256(Js.utf8(rp_id)))
      return fail_with('User Present (UP) flag is not set') unless parsed['flags']['up']
      if Js.truthy?(expect['require_uv']) && !parsed['flags']['uv']
        return fail_with('User Verified (UV) flag is required but not set')
      end

      signed = auth_data + sha256(client_json)
      begin
        alg, raw = resolve_key(assertion['public_key'])
      rescue StandardError => e
        return fail_with("public key could not be resolved: #{e.message}")
      end
      valid = if alg == 'ES256'
                der = !signature.empty? && signature.getbyte(0) == 0x30 && signature.bytesize != 64
                ecdsa_p256_verify(raw, signed, signature, der, expect['require_low_s'] == true)
              else
                # strict RFC 8032: canonical encodings, S < L, no small-order or mixed-order key or R
                AtlasPca::Ed25519Strict.verify(raw, signed, signature)
              end
      return fail_with('assertion signature did not verify') unless valid

      # the signature counter (clone detection), only after the signature verified so forged input cannot trigger the hook
      stored = expect['stored_sign_count']
      return fail_with('storedSignCount is not a uint32') unless uint32?(stored)

      if (parsed['signCount'] != 0 || stored != 0) && parsed['signCount'] <= stored
        hook = expect['on_sign_count_regression']
        hook.call({ 'storedSignCount' => stored, 'reportedSignCount' => parsed['signCount'] }) if hook.respond_to?(:call)
        return fail_with('signCount did not increase (possible cloned authenticator)')
      end

      { 'ok' => true, 'alg' => alg, 'signCount' => parsed['signCount'], 'flags' => parsed['flags'] }
    rescue StandardError => e
      fail_with("verification error (fail closed): #{e.message}")
    end
  end
end
