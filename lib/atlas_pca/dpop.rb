# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'set'
require_relative 'jose'
require_relative 'whatwg_url'

# RFC 9449 DPoP proofs (create / verify with replay detection and server nonces), RFC 7638 JWK thumbprints, RFC 8705 mTLS
# certificate confirmation and the PCActn <-> DPoP binding (the proof key must be the leaf holder key). Mirrors
# @atlasauth/pca-dpop. Keys are JWK Hashes; a certificate is DER (binary String) or PEM text. Every refusal of a proof is a
# DpopVerificationError with a stable #code.
module AtlasPca
  module Dpop
    ALLOWED_ALGS = %w[EdDSA ES256 ES384 ES512 PS256 RS256].freeze
    JWT_TYP = 'dpop+jwt'
    DEFAULT_MAX_AGE_SEC = 300
    CLOCK_SKEW_SEC = 5
    INMEMORY_MAX_ENTRIES = 100_000
    MAX_PROOF_BYTES = 8192
    PRIVATE_MEMBERS = %w[d p q dp dq qi k].freeze

    class DpopVerificationError < StandardError
      attr_reader :code

      def initialize(code, message)
        @code = code
        super(message)
      end
    end

    # A reference-library refusal outside the DPoP checks, with its stable code (ERR_INVALID_URL, ERR_JWK_INVALID,
    # ERR_JOSE_NOT_SUPPORTED).
    class CodedError < StandardError
      attr_reader :code

      def initialize(code, message)
        @code = code
        super(message)
      end
    end

    # In-memory replay store: add_if_absent(key, expires_at_sec, now_sec) -> true on first sight (or after expiry). When full,
    # expired entries are evicted; a store still full refuses (raises) rather than forgetting a live entry.
    class InMemoryReplayStore
      def initialize(max_entries: INMEMORY_MAX_ENTRIES)
        unless max_entries.is_a?(Integer) || (max_entries.is_a?(Float) && max_entries.finite? && max_entries == max_entries.floor)
          raise DpopVerificationError.new('misconfigured', 'maxEntries must be a positive integer')
        end
        raise DpopVerificationError.new('misconfigured', 'maxEntries must be a positive integer') if max_entries < 1

        @max = max_entries
        @seen = {}
        @lock = Mutex.new
      end

      def add_if_absent(key, expires_at_sec, now_sec)
        return false unless Js.num?(now_sec) && now_sec.to_f.finite? # a non-finite clock admits nothing

        @lock.synchronize do
          held = @seen[key]
          return false if !held.nil? && !(now_sec >= held)

          if held.nil? && @seen.size >= @max
            @seen.delete_if { |_k, exp| now_sec >= exp }
            raise 'replay store is full' if @seen.size >= @max
          end
          @seen[key] = expires_at_sec
          true
        end
      end
    end

    # Server nonces: 8-byte big-endian issue time + the first 16 bytes of HMAC-SHA256(secret, "dpop-nonce\0" || ts), base64url.
    class NonceIssuer
      def initialize(secret:, ttl_sec: nil)
        unless secret.is_a?(String) && secret.bytesize >= 32
          raise DpopVerificationError.new('misconfigured', 'nonce secret must be at least 32 bytes')
        end

        ttl = ttl_sec.nil? ? 300 : ttl_sec
        raise DpopVerificationError.new('misconfigured', 'nonce ttlSec must be positive') unless Js.num?(ttl) && ttl.to_f.finite? && ttl.positive?

        @secret = secret.b
        @ttl = ttl
      end

      def mac(ts) = OpenSSL::HMAC.digest('SHA256', @secret, "dpop-nonce\x00".b + ts).byteslice(0, 16)

      def issue(now_sec = Time.now.to_i)
        now_sec = now_sec.to_i if now_sec.is_a?(Float) && now_sec.finite? && now_sec == now_sec.floor
        raise RangeError, 'nonce time must be an integer' unless now_sec.is_a?(Integer) && now_sec >= 0 && now_sec < 2**64

        ts = [now_sec].pack('Q>')
        AtlasPca.b64e(ts + mac(ts))
      end

      def check(nonce, now_sec = Time.now.to_i)
        return false unless nonce.is_a?(String)

        raw = AtlasPca.b64d(nonce)
        return false if raw.nil? || raw.bytesize != 24

        ts = raw.byteslice(0, 8)
        return false unless OpenSSL.fixed_length_secure_compare(raw.byteslice(8, 16), mac(ts))

        issued = ts.unpack1('Q>')
        issued <= now_sec + CLOCK_SKEW_SEC && now_sec - issued <= @ttl
      end
    end

    module_function

    def err(code, msg) = DpopVerificationError.new(code, msg)

    # runDpopReplayStoreConformance: the names of the failed checks of a store factory (empty when the store conforms).
    def run_replay_store_conformance(make)
      failures = []
      check = ->(ok, name) { failures << name unless ok }
      s = make.call
      check.call(s.add_if_absent('a', 200, 100) == true, 'first sight of a key returns true')
      check.call(s.add_if_absent('a', 200, 101) == false, 'second sight of the same key returns false')
      check.call(s.add_if_absent('b', 200, 101) == true, 'a different key is independent')
      check.call(s.add_if_absent('a', 200, 199) == false, 'still seen one second before expiry')
      t = make.call
      t.add_if_absent('c', 200, 100)
      check.call(t.add_if_absent('c', 400, 200) == true, 'an expired entry may be added again (nowSec >= expiresAtSec)')
      u = make.call
      wins = Array.new(16) { Thread.new { u.add_if_absent('race', 200, 100) } }.map(&:value).count { |w| w }
      check.call(wins == 1, "16 concurrent adds of one key: exactly one wins (got #{wins})")
      failures
    end

    # RFC 7638 thumbprint (base64url of the digest of the required members in lexicographic order).
    def jwk_thumbprint(jwk, digest = 'sha256')
      raise TypeError, 'JWK must be an object' unless jwk.is_a?(Hash)
      unless %w[sha256 sha384 sha512].include?(digest)
        raise TypeError, 'digestAlgorithm must one of "sha256", "sha384", or "sha512"'
      end

      req = ->(k, d) { jwk[k].is_a?(String) && !jwk[k].empty? ? jwk[k] : raise(CodedError.new('ERR_JWK_INVALID', "#{d} missing or invalid")) }
      c = case jwk['kty']
          when 'EC' then { 'crv' => req.('crv', '"crv" (Curve) Parameter'), 'kty' => 'EC', 'x' => req.('x', '"x" (X Coordinate) Parameter'), 'y' => req.('y', '"y" (Y Coordinate) Parameter') }
          when 'OKP' then { 'crv' => req.('crv', '"crv" (Subtype of Key Pair) Parameter'), 'kty' => 'OKP', 'x' => req.('x', '"x" (Public Key) Parameter') }
          when 'RSA' then { 'e' => req.('e', '"e" (Exponent) Parameter'), 'kty' => 'RSA', 'n' => req.('n', '"n" (Modulus) Parameter') }
          when 'oct' then { 'k' => req.('k', '"k" (Key Value) Parameter'), 'kty' => 'oct' }
          else raise CodedError.new('ERR_JOSE_NOT_SUPPORTED', '"kty" (Key Type) Parameter missing or unsupported')
          end
      AtlasPca.b64e(OpenSSL::Digest.digest(digest.upcase, Js.utf8(Js.json(c))))
    end

    def alg_for_jwk(jwk)
      kty = Js.get(jwk, 'kty')
      crv = Js.get(jwk, 'crv')
      case kty
      when 'OKP'
        return 'EdDSA' if %w[Ed25519 Ed448].include?(crv)

        raise err('unsupported_key', "unsupported OKP curve '#{Js.string(crv)}' for DPoP")
      when 'EC'
        a = { 'P-256' => 'ES256', 'P-384' => 'ES384', 'P-521' => 'ES512' }[crv]
        return a if a

        raise err('unsupported_key', "unsupported EC curve '#{Js.string(crv)}' for DPoP")
      when 'RSA' then 'PS256'
      else raise err('unsupported_key', "unsupported key type '#{Js.string(kty)}' for DPoP")
      end
    end

    # An unknown alg is false without reading the key (a null key throws only for a known alg, as the reference).
    def alg_matches_jwk?(alg, jwk)
      case alg
      when 'EdDSA' then Js.get(jwk, 'kty') == 'OKP' && %w[Ed25519 Ed448].include?(Js.get(jwk, 'crv'))
      when 'ES256' then Js.get(jwk, 'kty') == 'EC' && Js.get(jwk, 'crv') == 'P-256'
      when 'ES384' then Js.get(jwk, 'kty') == 'EC' && Js.get(jwk, 'crv') == 'P-384'
      when 'ES512' then Js.get(jwk, 'kty') == 'EC' && Js.get(jwk, 'crv') == 'P-521'
      when 'PS256', 'RS256' then Js.get(jwk, 'kty') == 'RSA'
      else false
      end
    end

    def to_public_jwk(jwk)
      pub = { 'kty' => Js.get(jwk, 'kty') }
      %w[crv x y n e].each { |k| pub[k] = jwk[k] if jwk.is_a?(Hash) && jwk.key?(k) }
      pub
    end

    # `${protocol}//${host}${pathname}` of the WHATWG parse (query and fragment dropped). Raises on an invalid URL.
    def normalize_htu(url)
      u = WhatwgUrl.parse(Js.string(url))
      raise CodedError.new('ERR_INVALID_URL', 'Invalid URL') if u.nil?

      u['htu']
    end

    def ath_for(access_token) = AtlasPca.b64e(OpenSSL::Digest::SHA256.digest(Js.utf8(Js.string(access_token))))

    # A signed DPoP proof. Input: method, url, private_key (private JWK or OpenSSL key), public_jwk, nonce, ath, iat, jti.
    def create_dpop_proof(input)
      pub = to_public_jwk(input['public_jwk'])
      alg = alg_for_jwk(pub)
      claims = { 'htm' => input['method'].upcase, 'htu' => normalize_htu(input['url']),
                 'iat' => input['iat'].nil? ? Time.now.to_i : input['iat'], 'jti' => input['jti'].nil? ? SecureRandom.uuid : input['jti'] }
      claims['nonce'] = input['nonce'] if input.key?('nonce')
      claims['ath'] = input['ath'] if input.key?('ath')
      Jose.sign_jwt(claims, { 'typ' => JWT_TYP, 'alg' => alg, 'jwk' => pub }, input['private_key'])
    end

    # Verify a DPoP proof; {'claims', 'jwk', 'jkt'}. Options: method, url, max_age_sec, expected_jkt, seen_jti (a Set),
    # replay_store (#add_if_absent), require_replay_store, nonce_issuer, now_sec, expected_nonce, access_token.
    # A replay store (or seen_jti) is required unless require_replay_store is false.
    def verify_dpop_proof(proof, o)
      # An absent max age means the default, never "no limit"; a non-number or non-finite one would disable the stale check.
      max_age = o['max_age_sec'].nil? ? DEFAULT_MAX_AGE_SEC : o['max_age_sec']
      raise err('max_age', 'max_age_sec must be a finite, non-negative number of seconds') unless Js.num?(max_age) && max_age.to_f.finite?

      if o['require_replay_store'] != false && o['replay_store'].nil? && o['seen_jti'].nil?
        raise err('replay_store_required', 'no replay store configured; replay cannot be detected')
      end
      unless proof.is_a?(String) && Js.len16(proof) <= MAX_PROOF_BYTES
        raise err('oversize', "proof is not a string or exceeds #{MAX_PROOF_BYTES} bytes")
      end

      header = begin
        Jose.assert_canonical_compact_jws(proof)['header']
      rescue StandardError => e
        raise err('malformed', "not a JWS: #{e.message}")
      end
      raise err('typ', "header typ must be '#{JWT_TYP}', got '#{Js.string(header['typ'])}'") unless header['typ'] == JWT_TYP
      raise err('no_jwk', 'proof header has no embedded jwk') unless header.key?('jwk')

      hj = header['jwk']
      raise err('private_jwk', 'proof header jwk contains private key material') if hj.is_a?(Hash) && PRIVATE_MEMBERS.any? { |m| hj.key?(m) }
      if header['alg'].is_a?(String) && ALLOWED_ALGS.include?(header['alg']) && !alg_matches_jwk?(header['alg'], hj)
        raise err('alg_jwk_mismatch', "alg '#{header['alg']}' does not match the embedded jwk key type")
      end

      begin
        payload, ph = Jose.jwt_verify(proof, Jose::EMBEDDED_JWK, algorithms: ALLOWED_ALGS, typ: JWT_TYP)
        raise err('no_jwk', 'verified header has no embedded jwk') unless ph.key?('jwk')

        jwk = ph['jwk']
      rescue DpopVerificationError
        raise
      rescue StandardError => e
        raise err('signature', "DPoP signature did not verify: #{e.message}")
      end
      htm, htu, iat, jti = payload.values_at('htm', 'htu', 'iat', 'jti')
      raise err('htm', 'htm is missing or not a string') unless htm.is_a?(String)
      raise err('htu', 'htu is missing or not a string') unless htu.is_a?(String)
      raise err('iat', 'iat is missing or not a number') unless Js.num?(iat) && iat.to_f.finite?
      raise err('jti', 'jti is missing or empty') unless jti.is_a?(String) && !jti.empty?
      raise err('htm', "htm '#{htm}' does not match request method") unless htm == o['method'].upcase
      raise err('htu', "htu '#{htu}' does not match request URL") unless htu == normalize_htu(o['url'])

      now = o['now_sec'].nil? ? Time.now.to_i : o['now_sec']
      raise err('now', 'now_sec must be a finite number') unless Js.num?(now) && now.to_f.finite?
      raise err('iat_future', 'iat is in the future') if iat > now + CLOCK_SKEW_SEC
      raise err('iat_stale', "proof is older than #{Js.string(max_age)}s") unless now - iat <= max_age

      jkt = jwk_thumbprint(jwk)
      raise err('jkt', 'embedded key thumbprint does not match expected jkt') if o.key?('expected_jkt') && jkt != o['expected_jkt']
      if o.key?('expected_nonce') && payload['nonce'] != o['expected_nonce']
        raise err('nonce', 'proof nonce is missing or does not match the expected nonce')
      end
      if o['nonce_issuer'] && !o['nonce_issuer'].check(payload['nonce'], now)
        raise err('nonce', 'proof nonce is missing, forged or expired')
      end
      if o.key?('access_token') && payload['ath'] != ath_for(o['access_token'])
        raise err('ath', 'proof ath is missing or does not match the access token')
      end
      if o['seen_jti']
        raise err('jti_replay', "jti '#{jti}' has already been seen") if o['seen_jti'].include?(jti)

        o['seen_jti'].add(jti)
      end
      if o['replay_store']
        fresh = begin
          o['replay_store'].add_if_absent("#{jkt}.#{jti}", iat + max_age + CLOCK_SKEW_SEC, now)
        rescue StandardError => e
          raise err('replay_store_error', "replay store failed: #{e.message}")
        end
        raise err('jti_replay', "jti '#{jti}' has already been seen") unless fresh == true
      end
      { 'claims' => payload, 'jwk' => jwk, 'jkt' => jkt }
    end

    # Node's lenient base64: characters outside the alphabet are skipped and decoding stops at the first '='.
    def pem_to_der(pem)
      m = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/)
      body = (m ? m[1] : pem).gsub(%r{[^A-Za-z0-9+/=]}, '')
      body.split('=', 2)[0].to_s.unpack1('m')
    end

    def mtls_cnf(cert) = { 'x5t#S256' => AtlasPca.b64e(OpenSSL::Digest::SHA256.digest(cert.encoding == Encoding::BINARY ? cert : pem_to_der(cert))) }

    # x5t#S256 of a parsed X.509 certificate (DER as a binary String, or PEM text).
    def mtls_thumbprint(cert)
      raw = begin
        OpenSSL::X509::Certificate.new(cert).to_der
      rescue StandardError => e
        raise err('cert', "not an X.509 certificate: #{e.message}")
      end
      AtlasPca.b64e(OpenSSL::Digest::SHA256.digest(raw))
    end

    # The client certificate must match the token's cnf x5t#S256 (constant-time compare).
    def assert_mtls_bound(cert, cnf)
      want = cnf.is_a?(Hash) ? cnf['x5t#S256'] : nil
      raise err('x5t_missing', "cnf has no 'x5t#S256' thumbprint") unless want.is_a?(String) && !want.empty?

      got = mtls_thumbprint(cert)
      unless got.bytesize == want.bytesize && OpenSSL.fixed_length_secure_compare(got, want.b)
        raise err('x5t', 'client certificate thumbprint does not match cnf x5t#S256')
      end

      { 'x5t#S256' => got }
    end

    NONE = Object.new.freeze

    # The leaf holder key of a PCActn's chain (cap_chain[length - 1]) as an Ed25519 JWK; JS property-read semantics on a
    # malformed chain (an absent holder leaves x out, a null hop throws).
    def leaf_holder_jwk(p)
      chain = Js.get(p, 'cap_chain')
      raise TypeError, "Cannot read properties of null (reading 'length')" if chain.nil?

      leaf = case chain
             when Array, String then chain.empty? ? NONE : chain[-1]
             when Hash
               n = chain['length']
               k = Js.num?(n) ? Js.string(n - 1) : 'NaN'
               chain.key?(k) ? chain[k] : NONE
             else NONE
             end
      raise err('no_leaf', 'PCActn capability chain is empty; no bound holder key') if leaf.equal?(NONE)
      raise TypeError, "Cannot read properties of null (reading 'holder')" if leaf.nil?

      jwk = { 'kty' => 'OKP', 'crv' => 'Ed25519' }
      jwk['x'] = leaf['holder'] if leaf.is_a?(Hash) && leaf.key?('holder')
      jwk
    end

    def bind_pca_to_dpop(p) = { 'jkt' => jwk_thumbprint(leaf_holder_jwk(p)) }

    # Verify a DPoP proof whose key must be the PCActn's leaf holder key (max_age_sec defaults to 300).
    def assert_pca_dpop(p, proof, o)
      jkt = bind_pca_to_dpop(p)['jkt']
      v = o.slice('method', 'url', 'seen_jti', 'replay_store', 'require_replay_store', 'nonce_issuer', 'now_sec', 'expected_nonce', 'access_token')
      verify_dpop_proof(proof, v.merge('max_age_sec' => o['max_age_sec'].nil? ? DEFAULT_MAX_AGE_SEC : o['max_age_sec'], 'expected_jkt' => jkt))
    end
  end
end
