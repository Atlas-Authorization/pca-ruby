# frozen_string_literal: true

require 'openssl'
require 'uri'
require 'net/http'
require 'set'
require_relative 'jose'
require_relative 'whatwg_url'

# Root a PCA grant in an OpenID Connect-authenticated human: discovery, ID-token verification (signature + iss / aud / exp /
# iat / nonce / azp / at_hash / c_hash), a fail-closed caching JWKS resolver and the claims -> principal mapping. Mirrors
# @atlasauth/pca-oidc (check order and error codes of the reference and its JOSE library).
#
# Options are String-keyed snake_case Hashes. A `fetch` is a callable (url, headers, timeout_ms) -> {'status', 'body',
# 'headers'} that raises on a network failure; the default uses Net::HTTP. Keys: a public JWK Hash, an HMAC secret (binary
# String, HS* only), or a resolver (callable header -> JWK) such as create_local_jwk_set / create_oidc_jwks.
module AtlasPca
  module Oidc
    OIDC_SUBJECT_CAVEAT = 'oidc_subject'
    DEFAULT_MAX_DISCOVERY_BYTES = 1024 * 1024
    DEFAULT_JWKS_TIMEOUT_MS = 5000
    DEFAULT_ID_TOKEN_ALGS = %w[RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512 EdDSA].freeze
    WELL_KNOWN = '/.well-known/openid-configuration'

    # Any ID-token verification failure; #code is one of config, invalid_token, signature, issuer, audience, expired,
    # issued_at, not_before, nonce, azp, at_hash, c_hash, keys, claims.
    class OidcVerificationError < StandardError
      attr_reader :code

      def initialize(code, message)
        @code = code
        super(message)
      end
    end

    # Any discovery failure (network, non-2xx, bad JSON, issuer mismatch).
    class OidcDiscoveryError < StandardError; end

    # A refusal that carries the reference runtime's code (ERR_JWKS_INVALID, ERR_INVALID_ARG_TYPE).
    class CodedError < StandardError
      attr_reader :code

      def initialize(code, message)
        @code = code
        super(message)
      end
    end

    # jose's claim-set failures: the claim decides the mapped code (JWTExpired vs JWTClaimValidationFailed).
    class ClaimFailed < Jose::Error
      attr_reader :claim

      def initialize(claim, message)
        @claim = claim
        super(message)
      end
    end

    class Expired < ClaimFailed; end
    class SignatureFailed < Jose::Error; end

    module_function

    def str(v) = v.is_a?(String) && !v.empty? ? v : nil
    def finite(v) = Js.num?(v) && v.to_f.finite? ? v : nil

    # ToNumber of a JSON value (relational comparisons coerce their operands).
    def to_num(v)
      case v
      when Integer, Float then v
      when true then 1
      when false then 0
      when String then AtlasPca.js_string_to_number(v)
      when Array then AtlasPca.js_string_to_number(Js.string(v))
      else Float::NAN
      end
    end

    def https?(u)
      p = u.is_a?(String) ? WhatwgUrl.parse(u) : nil
      !p.nil? && p['scheme'] == 'https'
    end

    def default_fetch(url, headers, timeout_ms)
      uri = URI(url)
      t = timeout_ms.nil? ? nil : timeout_ms / 1000.0
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', open_timeout: t, read_timeout: t) do |http|
        http.request(Net::HTTP::Get.new(uri, headers))
      end
      { 'status' => res.code.to_i, 'body' => res.body.to_s.dup.force_encoding('UTF-8'), 'headers' => res.each_header.to_h }
    end

    def body_text(res)
      b = res['body'].to_s
      b.encoding == Encoding::BINARY ? b.dup.force_encoding('UTF-8').scrub("�") : b
    end

    def ok?(res) = res.is_a?(Hash) && res['status'].is_a?(Integer) && res['status'] >= 200 && res['status'] <= 299

    # ---- discovery ----

    # The issuer + "/.well-known/openid-configuration" (one trailing slash of the issuer is not doubled).
    def discovery_url(issuer)
      raise TypeError, "Cannot read properties of #{Js.string(issuer)} (reading 'endsWith')" unless issuer.is_a?(String)

      "#{issuer.end_with?('/') ? issuer[0...-1] : issuer}#{WELL_KNOWN}"
    end

    # Fetch and parse the issuer's discovery document. Options: fetch, max_bytes, require_https (default true).
    def discover_oidc(issuer, opts = {})
      raise OidcDiscoveryError, 'discoverOidc: issuer must be a non-empty string' unless issuer.is_a?(String) && !issuer.empty?
      raise TypeError, "Cannot read properties of null (reading 'requireHttps')" if opts.nil?

      require_https = opts['require_https'] != false
      raise OidcDiscoveryError, "discoverOidc: issuer '#{issuer}' is not an https URL" if require_https && !https?(issuer)

      do_fetch = opts['fetch'] || method(:default_fetch)
      url = discovery_url(issuer)
      res = begin
        do_fetch.call(url, { 'accept' => 'application/json' }, nil)
      rescue StandardError
        raise OidcDiscoveryError, "discoverOidc: fetch of #{url} failed"
      end
      raise OidcDiscoveryError, "discoverOidc: #{url} returned HTTP #{Js.string(res.is_a?(Hash) ? res['status'] : nil)}" unless ok?(res)

      max_bytes = opts['max_bytes'].nil? ? DEFAULT_MAX_DISCOVERY_BYTES : opts['max_bytes']
      cap = to_num(max_bytes)
      cl = (res['headers'] || {}).find { |k, _| k.to_s.downcase == 'content-length' }&.last
      declared = cl.nil? ? 0 : AtlasPca.js_string_to_number(cl.to_s)
      too_big = "discoverOidc: #{url} response exceeds #{Js.string(max_bytes)} bytes"
      raise OidcDiscoveryError, too_big if declared.to_f.finite? && declared > cap

      text = body_text(res)
      raise OidcDiscoveryError, too_big if Js.utf8(text).bytesize > cap

      body = begin
        AtlasPca.parse_json_text(text)
      rescue StandardError
        raise OidcDiscoveryError, "discoverOidc: #{url} did not return valid JSON"
      end
      meta = as_metadata(body)
      if meta['issuer'] != issuer
        raise OidcDiscoveryError, "discoverOidc: metadata issuer '#{meta['issuer']}' does not match requested '#{issuer}'"
      end
      raise OidcDiscoveryError, "discoverOidc: jwks_uri '#{meta['jwks_uri']}' is not an https URL" if require_https && !https?(meta['jwks_uri'])

      meta
    end

    def as_metadata(body)
      raise OidcDiscoveryError, 'discoverOidc: metadata is not a JSON object' unless body.is_a?(Hash)
      raise OidcDiscoveryError, 'discoverOidc: metadata is missing a string "issuer"' unless str(body['issuer'])
      raise OidcDiscoveryError, 'discoverOidc: metadata is missing a string "jwks_uri"' unless str(body['jwks_uri'])

      { 'issuer' => body['issuer'], 'jwks_uri' => body['jwks_uri'] }.merge(body.except('issuer', 'jwks_uri'))
    end

    # ---- JWK sets ----

    def kty_from_alg(alg)
      case alg.is_a?(String) ? alg[0, 2] : nil
      when 'RS', 'PS' then 'RSA'
      when 'ES' then 'EC'
      when 'Ed' then 'OKP'
      else raise Jose::Error, 'Unsupported "alg" value for a JSON Web Key Set'
      end
    end

    CRV_FOR_ALG = { 'ES256' => ['P-256'], 'ES256K' => ['secp256k1'], 'ES384' => ['P-384'], 'ES512' => ['P-521'],
                    'Ed25519' => ['Ed25519'], 'EdDSA' => %w[Ed25519 Ed448] }.freeze

    # jose createLocalJWKSet: a resolver (header -> the one matching public JWK) over a fixed set. Raises a CodedError
    # ERR_JWKS_INVALID for a malformed set; resolution failures are Jose::Error.
    def create_local_jwk_set(jwks)
      unless jwks.is_a?(Hash) && jwks['keys'].is_a?(Array) && jwks['keys'].all? { |k| k.is_a?(Hash) }
        raise CodedError.new('ERR_JWKS_INVALID', 'JSON Web Key Set malformed')
      end

      keys = Marshal.load(Marshal.dump(jwks['keys']))
      lambda do |header, *_|
        alg = header['alg']
        kid = header['kid']
        kty = kty_from_alg(alg)
        found = keys.select do |j|
          ok = kty == j['kty']
          ok &&= kid == j['kid'] if kid.is_a?(String)
          ok &&= alg == j['alg'] if j['alg'].is_a?(String)
          ok &&= j['use'] == 'sig' if j['use'].is_a?(String)
          ok &&= j['key_ops'].include?('verify') if j['key_ops'].is_a?(Array)
          ok &&= CRV_FOR_ALG[alg].include?(j['crv']) if ok && CRV_FOR_ALG.key?(alg)
          ok
        end
        raise Jose::Error, 'no applicable key found in the JSON Web Key Set' if found.empty?
        raise Jose::Error, 'multiple matching keys found in the JSON Web Key Set' if found.length != 1

        jwk = found[0]
        raise Jose::Error, 'JSON Web Key Set members must be public keys' if jwk.key?('d')
        raise Jose::Error, 'invalid JWK in the JSON Web Key Set' unless loadable?(jwk, alg)

        jwk
      end
    end

    # The fail-closed caching JWKS resolver. Options: jwks_uri (required), fetch, cache_max_age_sec (600), cooldown_sec (30),
    # max_bytes (1 MiB), require_https (true), timeout_ms (5000), now (callable -> epoch ms). A stale set is refetched and
    # never served when the refetch fails (code 'keys'); an unknown kid refetches at most once per cooldown.
    def create_oidc_jwks(opts)
      uri = opts['jwks_uri']
      raise TypeError, 'createOidcJwks: jwksUri is required' unless uri.is_a?(String) && !uri.empty?
      if Js.truthy?(opts['require_https'].nil? ? true : opts['require_https']) && !uri.match?(%r{\Ahttps://}i)
        raise TypeError, 'createOidcJwks: jwksUri must be https (pass requireHttps: false only for local tests)'
      end

      now = opts['now'] || -> { Process.clock_gettime(Process::CLOCK_REALTIME, :millisecond) }
      { 'cache_max_age_sec' => 'cacheMaxAgeSec', 'cooldown_sec' => 'cooldownSec', 'max_bytes' => 'maxBytes', 'timeout_ms' => 'timeoutMs' }.each do |k, name|
        next unless opts.key?(k)

        v = opts[k]
        raise TypeError, "createOidcJwks: #{name} must be a finite number >= 0" unless Js.num?(v) && v.to_f.finite? && v >= 0
      end
      max_age_ms = (opts['cache_max_age_sec'].nil? ? 600 : opts['cache_max_age_sec']) * 1000
      cooldown_ms = (opts['cooldown_sec'].nil? ? 30 : opts['cooldown_sec']) * 1000
      max_bytes = opts['max_bytes'].nil? ? 1024 * 1024 : opts['max_bytes']
      timeout_ms = opts['timeout_ms'].nil? ? DEFAULT_JWKS_TIMEOUT_MS : opts['timeout_ms']
      do_fetch = opts['fetch'] || method(:default_fetch)
      state = { cache: nil, last_fetch: -Float::INFINITY }
      lock = Mutex.new

      refetch = lambda do
        state[:last_fetch] = now.call
        begin
          res = do_fetch.call(uri, { 'accept' => 'application/json' }, timeout_ms)
          raise "HTTP #{res.is_a?(Hash) ? res['status'] : nil}" unless ok?(res)

          text = body_text(res)
          raise "response exceeds #{max_bytes} bytes" if Js.utf8(text).bytesize > max_bytes

          jwks = AtlasPca.parse_json_text(text)
          raise 'not a JWK Set' unless jwks.is_a?(Hash) && jwks['keys'].is_a?(Array)

          resolve = create_local_jwk_set(jwks)
        rescue StandardError
          raise OidcVerificationError.new('keys', "could not fetch the issuer signing keys from #{uri}")
        end
        at = now.call
        raise OidcVerificationError.new('keys', 'the clock returned a non-finite time') unless Js.num?(at) && at.to_f.finite?

        state[:cache] = { at: at, resolve: resolve, kids: jwks['keys'].map { |k| k['kid'] }.grep(String).to_set }
      end

      lambda do |header, *_|
        t = now.call
        raise OidcVerificationError.new('keys', 'the clock returned a non-finite time') unless Js.num?(t) && t.to_f.finite?

        lock.synchronize do
          c = state[:cache]
          if c.nil? || t - c[:at] >= max_age_ms
            state[:cache] = nil # never serve a stale set, even if the refetch below fails
            refetch.call
          elsif header['kid'].is_a?(String) && !c[:kids].include?(header['kid']) && t - state[:last_fetch] >= cooldown_ms
            refetch.call
          end
        end
        state[:cache][:resolve].call(header)
      end
    end

    # Discover the issuer's jwks_uri, then build create_oidc_jwks over it (the same options).
    def create_oidc_jwks_from_issuer(issuer, opts = {})
      meta = discover_oidc(issuer, { 'require_https' => opts['require_https'], 'fetch' => opts['fetch'] })
      create_oidc_jwks(opts.merge('jwks_uri' => meta['jwks_uri']))
    end

    # ---- verification ----

    def invalid(msg) = OidcVerificationError.new('invalid_token', msg)

    def b64(jwk, name)
      v = jwk[name]
      raise Jose::Error, "JWK member #{name} is missing" unless v.is_a?(String)

      Jose.lenient_b64d(v)
    end

    # The key family of a JWK for an algorithm check (an OKP key must be Ed25519 / Ed448).
    def jwk_type(jwk)
      case jwk['kty']
      when 'RSA' then 'rsa'
      when 'EC' then 'ec'
      when 'OKP'
        return 'ed25519' if jwk['crv'] == 'Ed25519'
        return 'ed448' if jwk['crv'] == 'Ed448'

        raise invalid('Invalid key for this operation, its crv must be Ed25519 or Ed448')
      else raise invalid('Invalid key for this operation, its kty must be RSA, OKP, or EC')
      end
    end

    EC_SIZE = { 'P-256' => 32, 'P-384' => 48, 'P-521' => 66 }.freeze

    # Whether the JWK's key material imports (exact coordinate sizes; an EC point must be on its curve).
    def loadable?(jwk, _alg = nil)
      case jwk_type(jwk)
      when 'ed25519' then b64(jwk, 'x').bytesize == 32
      when 'ed448' then b64(jwk, 'x').bytesize == 57
      when 'ec'
        size = EC_SIZE[jwk['crv']]
        return false unless size && b64(jwk, 'x').bytesize == size && b64(jwk, 'y').bytesize == size

        Jose.public_key_from_jwk(jwk)
        true
      else
        return false if b64(jwk, 'n').empty? || b64(jwk, 'e').empty?

        Jose.public_key_from_jwk(jwk)
        true
      end
    rescue StandardError
      false
    end

    def jwk?(k) = k.is_a?(Hash) && k['kty'].is_a?(String)

    # jose's key-type check for verification: the key suits the algorithm family and, as a JWK, is public and usable for sig.
    def check_key_type(alg, key)
      matches_op = lambda do |k|
        raise invalid('Invalid key for this operation, when present its use must be sig') if k.key?('use') && k['use'] != 'sig'
        if k.key?('key_ops') && !(k['key_ops'].is_a?(Array) && k['key_ops'].include?('verify'))
          raise invalid('Invalid key for this operation, when present its key_ops must include verify')
        end
        raise invalid("Invalid key for this operation, when present its alg must be #{alg}") if k.key?('alg') && k['alg'] != alg
      end
      if alg.start_with?('HS')
        return if key.is_a?(String) && key.encoding == Encoding::BINARY
        return matches_op.call(key) if jwk?(key) && key['kty'] == 'oct' && key['k'].is_a?(String)

        raise invalid('Invalid key for a symmetric algorithm')
      end
      return matches_op.call(key) if jwk?(key) && key['kty'] != 'oct' && !key.key?('d')

      raise invalid('Invalid key for this operation: a public JWK is required')
    end

    HS = { 'HS256' => 'SHA256', 'HS384' => 'SHA384', 'HS512' => 'SHA512' }.freeze
    CURVE_ALG = { 'ES256' => 'P-256', 'ES384' => 'P-384', 'ES512' => 'P-521' }.freeze

    # jose's runtime verify: a key unfit for the alg raises invalid_token; bad key material or a bad signature is false.
    def verify_sig(alg, key, sig, data)
      if alg.start_with?('HS')
        raise invalid("alg #{alg} is not supported") unless HS.key?(alg)

        secret = key.is_a?(String) ? key : (Jose.lenient_b64d(key['k']) rescue nil)
        return false if secret.nil?

        mac = OpenSSL::HMAC.digest(HS[alg], secret, data)
        return mac.bytesize == sig.bytesize && OpenSSL.fixed_length_secure_compare(mac, sig)
      end
      t = jwk_type(key)
      if alg == 'EdDSA'
        raise invalid('Invalid key for this operation, its asymmetricKeyType must be ed25519 or ed448') unless %w[ed25519 ed448].include?(t)
      elsif %w[RS PS].include?(alg[0, 2]) && %w[256 384 512].include?(alg[2..])
        raise invalid('Invalid key for this operation, its asymmetricKeyType must be rsa') unless t == 'rsa'

        bits = begin
          b64(key, 'n').bytesize * 8
        rescue Jose::Error, ArgumentError
          0
        end
        raise invalid("#{alg} requires key modulusLength to be 2048 bits or larger") if bits < 2048
      elsif CURVE_ALG.key?(alg)
        raise invalid('Invalid key for this operation, its asymmetricKeyType must be ec') unless t == 'ec'
        raise invalid('Invalid key curve for the algorithm') unless key['crv'] == CURVE_ALG[alg]
      else
        raise invalid("alg #{alg} is not supported either by JOSE or your javascript runtime")
      end
      return false unless loadable?(key)

      Jose.jws_verify(alg, Jose.public_key_from_jwk(key), sig, data)
    rescue Jose::Error, ArgumentError, OpenSSL::PKey::PKeyError
      false
    end

    # jwtVerify in the reference's order: crit, alg, allow-list, key, signature, unencoded payload, then the claim set.
    def jwt_verify(header, payload, segments, key, algs, o)
      if header.key?('crit')
        crit = header['crit']
        unless crit.is_a?(Array) && !crit.empty? && crit.all? { |c| c.is_a?(String) && !c.empty? }
          raise Jose::Error, '"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present'
        end

        crit.each do |p|
          raise Jose::Error, "Extension Header Parameter \"#{p}\" is not recognized" unless p == 'b64'
          raise Jose::Error, 'Extension Header Parameter "b64" is missing' unless header.key?('b64')
        end
        raise Jose::Error, 'The "b64" (base64url-encode payload) Header Parameter must be a boolean' unless [true, false].include?(header['b64'])
      end
      alg = header['alg']
      raise Jose::Error, 'JWS "alg" (Algorithm) Header Parameter missing or invalid' unless alg.is_a?(String) && !alg.empty?
      raise TypeError, '"algorithms" option must be an array of strings' unless Js.str_list?(algs)
      raise Jose::Error, '"alg" (Algorithm) Header Parameter value not allowed' unless algs.include?(alg)

      resolved = key.respond_to?(:call)
      key = key.call(header) if resolved
      check_key_type(alg, key)
      sig = Jose.decode_canonical_base64url(segments[2])
      raise invalid('invalid JWK') if resolved && jwk?(key) && !alg.start_with?('HS') && !loadable?(key)
      raise SignatureFailed, 'signature verification failed' unless verify_sig(alg, key, sig, "#{segments[0]}.#{segments[1]}".b)
      raise Jose::Error, 'JWTs MUST NOT use unencoded payload' if header['crit'].is_a?(Array) && header['crit'].include?('b64') && header['b64'] == false

      claims_check(payload, o)
    end

    def claims_check(payload, o)
      audience = o['audience']
      max_age = o['max_token_age_sec']
      presence = []
      presence << 'iat' if o.key?('max_token_age_sec')
      presence << 'aud' << 'iss'
      presence.reverse.each { |c| raise ClaimFailed.new(c, "missing required \"#{c}\" claim") unless payload.key?(c) }
      raise ClaimFailed.new('iss', 'unexpected "iss" claim value') unless payload['iss'] == o['issuer']
      if Js.truthy?(audience)
        want = audience.is_a?(String) ? [audience] : audience
        aud = payload['aud']
        present = aud.is_a?(String) ? want.include?(aud) : aud.is_a?(Array) && aud.any? { |a| want.include?(a) }
        raise ClaimFailed.new('aud', 'unexpected "aud" claim value') unless present
      end
      tol = if !o.key?('clock_tolerance_sec') then 0
            elsif o['clock_tolerance_sec'].is_a?(String) then Jose.secs(o['clock_tolerance_sec'])
            elsif Js.num?(o['clock_tolerance_sec']) then o['clock_tolerance_sec']
            else raise TypeError, 'Invalid clockTolerance option type'
            end
      now = Time.now.to_i
      if (payload.key?('iat') || Js.truthy?(max_age)) && !Js.num?(payload['iat'])
        raise ClaimFailed.new('iat', '"iat" claim must be a number')
      end
      if payload.key?('nbf')
        raise ClaimFailed.new('nbf', '"nbf" claim must be a number') unless Js.num?(payload['nbf'])
        raise ClaimFailed.new('nbf', '"nbf" claim timestamp check failed') if payload['nbf'] > now + tol
      end
      if payload.key?('exp')
        raise ClaimFailed.new('exp', '"exp" claim must be a number') unless Js.num?(payload['exp'])
        raise Expired.new('exp', '"exp" claim timestamp check failed') if payload['exp'] <= now - tol
      end
      return unless Js.truthy?(max_age)

      age = now - payload['iat']
      max = Js.num?(max_age) ? max_age : Jose.secs(Js.string(max_age))
      raise Expired.new('iat', '"iat" claim timestamp check failed (too far in the past)') if age - tol > max
      raise ClaimFailed.new('iat', '"iat" claim timestamp check failed (it should be in the past)') if age < 0 - tol
    end

    CLAIM_CODE = { 'iss' => 'issuer', 'aud' => 'audience', 'iat' => 'issued_at', 'nbf' => 'not_before' }.freeze

    def map_error(e)
      case e
      when OidcVerificationError then e
      when Expired
        e.claim == 'iat' ? OidcVerificationError.new('issued_at', 'id token is older than the maximum accepted age') : OidcVerificationError.new('expired', 'id token has expired')
      when ClaimFailed then OidcVerificationError.new(CLAIM_CODE[e.claim] || 'claims', e.message)
      when SignatureFailed then OidcVerificationError.new('signature', 'id token signature verification failed')
      when Jose::Error then invalid(e.message)
      else invalid('id token verification failed')
      end
    end

    def resolve_key(o)
      return o['key'] if o.key?('key')

      rh = o['require_https']
      uri = o['jwks_uri']
      uri = discover_oidc(o['issuer'], { 'require_https' => rh, 'fetch' => o['fetch'] })['jwks_uri'] if !o.key?('jwks_uri') && o['discover'] == true
      if uri.nil? && !o.key?('jwks_uri')
        raise OidcVerificationError.new('config', 'verifyIdToken: no key source (pass opts.key, opts.jwksUri, or opts.discover)')
      end

      begin
        create_oidc_jwks({ 'jwks_uri' => uri, 'require_https' => rh })
      rescue TypeError, ArgumentError => e
        raise OidcVerificationError.new('config', "verifyIdToken: #{e.message}")
      end
    end

    def project_claims(payload, o)
      iss = str(payload['iss'])
      raise OidcVerificationError.new('issuer', 'id token is missing the "iss" claim') if iss.nil?

      sub = str(payload['sub'])
      raise OidcVerificationError.new('claims', 'id token is missing the "sub" claim') if sub.nil?
      raise OidcVerificationError.new('audience', 'id token is missing the "aud" claim') unless payload.key?('aud')

      aud = payload['aud']
      iat = finite(payload['iat'])
      raise OidcVerificationError.new('issued_at', 'id token is missing a numeric "iat" claim') if iat.nil?

      exp = finite(payload['exp'])
      raise OidcVerificationError.new('expired', 'id token is missing a numeric "exp" claim') if exp.nil?

      nonce = str(payload['nonce'])
      azp = str(payload['azp'])
      if o.key?('nonce') && nonce != o['nonce']
        raise OidcVerificationError.new('nonce', nonce.nil? ? 'id token is missing the expected nonce' : 'id token nonce does not match the expected value')
      end

      aud_list = aud.is_a?(Array) ? aud : [aud]
      expected_azp = o['authorized_party'].nil? ? (o['audience'].is_a?(String) ? o['audience'] : nil) : o['authorized_party']
      raise OidcVerificationError.new('azp', 'id token has multiple audiences but no azp (authorized party)') if aud_list.length > 1 && azp.nil?
      raise OidcVerificationError.new('azp', 'id token azp does not match the authorized party') if azp && !expected_azp.nil? && azp != expected_azp

      out = { 'iss' => iss, 'sub' => sub, 'aud' => aud, 'iat' => iat, 'exp' => exp }
      out['nonce'] = nonce if nonce
      out['azp'] = azp if azp
      %w[at_hash c_hash].each { |k| out[k] = payload[k] if str(payload[k]) }
      out['auth_time'] = payload['auth_time'] if finite(payload['auth_time'])
      out['email'] = payload['email'] if str(payload['email'])
      out['email_verified'] = payload['email_verified'] if [true, false].include?(payload['email_verified'])
      %w[name preferred_username given_name family_name picture].each { |k| out[k] = payload[k] if str(payload[k]) }
      out['cnf'] = payload['cnf'].dup if payload['cnf'].is_a?(Hash)
      out
    end

    # Node's 'ascii' string encoding: the low byte of each UTF-16 code unit (a WTF-8 lone surrogate is one unit).
    def ascii_bytes(s)
      lone = /\A\xED[\xA0-\xBF][\x80-\xBF]\z/n
      parts = s.valid_encoding? ? [s] : s.b.split(/(\xED[\xA0-\xBF][\x80-\xBF])/n)
      parts.flat_map do |p|
        if !s.valid_encoding? && p.match?(lone)
          [p.getbyte(2) & 0x3f | ((p.getbyte(1) & 0x03) << 6)]
        else
          p.dup.force_encoding('UTF-8').scrub("�").each_char.flat_map do |c|
            o = c.ord
            o > 0xffff ? [(0xD800 + ((o - 0x10000) >> 10)) & 0xff, (0xDC00 + (o & 0x3ff)) & 0xff] : [o & 0xff]
          end
        end
      end.pack('C*')
    end

    # OIDC Core 3.1.3.6: base64url(left half of H(value)), H chosen by the ID token's alg (EdDSA = SHA-512).
    def check_half_hash(name, actual, value, alg)
      raise OidcVerificationError.new(name, "id token is missing the expected #{name}") if actual.nil?

      bits = alg == 'EdDSA' ? '512' : (alg.is_a?(String) ? alg[/(256|384|512)\z/, 1] : nil)
      raise OidcVerificationError.new(name, "cannot compute #{name} for alg #{Js.string(alg)}") if bits.nil?
      unless value.is_a?(String)
        raise CodedError.new('ERR_INVALID_ARG_TYPE', 'The "data" argument must be of type string or an instance of Buffer, TypedArray, or DataView')
      end

      d = OpenSSL::Digest.digest("SHA#{bits}", ascii_bytes(value))
      raise OidcVerificationError.new(name, "id token #{name} does not match the supplied value") unless actual == AtlasPca.b64e(d.byteslice(0, d.bytesize / 2))
    end

    # Verify an ID token; its verified claims. Options: issuer, audience (String | Array) required; nonce,
    # authorized_party, access_token, code, clock_tolerance_sec, max_token_age_sec, algorithms, and a key source: key |
    # jwks_uri | discover (+ fetch), require_https. Raises OidcVerificationError (#code) on any refusal.
    def verify_id_token(id_token, o)
      raise invalid('verifyIdToken: idToken must be a non-empty string') unless id_token.is_a?(String) && !id_token.empty?
      raise OidcVerificationError.new('config', 'verifyIdToken: opts is required') unless o.is_a?(Hash)
      raise OidcVerificationError.new('config', 'verifyIdToken: opts.issuer is required') unless str(o['issuer'])
      raise OidcVerificationError.new('config', 'verifyIdToken: opts.audience is required') unless o['audience'].is_a?(String) || o['audience'].is_a?(Array)
      # a non-finite skew tolerance would make every expiry comparison pass; a NaN age limit would disable the age check
      ct = o['clock_tolerance_sec']
      unless ct.nil? || (Js.num?(ct) && ct.to_f.finite? && ct >= 0)
        raise OidcVerificationError.new('config', 'verifyIdToken: clockToleranceSec must be a finite number >= 0')
      end
      ma = o['max_token_age_sec']
      unless ma.nil? || (Js.num?(ma) ? ma >= 0 : (ma.is_a?(String) && AtlasPca.js_string_to_number(ma) >= 0))
        raise OidcVerificationError.new('config', 'verifyIdToken: maxTokenAgeSec must be a number >= 0')
      end

      jws = begin
        Jose.assert_canonical_compact_jws(id_token)
      rescue Jose::CanonicalJwsError => e
        raise invalid(e.message)
      end
      key = resolve_key(o)
      algs = Js.spread(o['algorithms'].nil? ? DEFAULT_ID_TOKEN_ALGS : o['algorithms'])
      begin
        jwt_verify(jws['header'], jws['payload'], jws['segments'], key, algs, o)
      rescue StandardError => e
        raise map_error(e)
      end
      claims = project_claims(jws['payload'], o)
      alg = jws['header']['alg']
      check_half_hash('at_hash', claims['at_hash'], o['access_token'], alg) if o.key?('access_token')
      check_half_hash('c_hash', claims['c_hash'], o['code'], alg) if o.key?('code')
      claims
    end

    # ---- principal ----

    def canonical_ed25519_b64u(s) = s.is_a?(String) && !s.empty? && AtlasPca.b64d(s, 32) ? s : nil

    def ed25519_public_from_cnf(claims)
      return nil unless claims.key?('cnf')

      cnf = claims['cnf']
      raise TypeError, "Cannot read properties of null (reading 'jwk')" if cnf.nil?

      jwk = cnf.is_a?(Hash) ? cnf['jwk'] : nil
      return nil unless jwk.is_a?(Hash) && jwk['kty'] == 'OKP' && jwk['crv'] == 'Ed25519' && jwk['x'].is_a?(String)

      canonical_ed25519_b64u(jwk['x'])
    end

    # Verified claims -> {iss, sub, principalId ("<iss>#<sub>"), subjectCaveat, claims, principalPublic?, email?,
    # emailVerified?, name?, preferredUsername?, authTime?}. principalPublic is the cnf-bound Ed25519 key or
    # opts['principal_public'] (they must agree). Raises TypeError on a missing iss / sub or a bad key, ArgumentError on a
    # cnf mismatch.
    def oidc_principal(claims, opts = {})
      raise TypeError, "Cannot read properties of null (reading 'iss')" if claims.nil?
      raise TypeError, "Cannot read properties of null (reading 'principalPublic')" if opts.nil?

      c = claims.is_a?(Hash) ? claims : {}
      iss = c['iss']
      sub = c['sub']
      raise TypeError, 'oidcPrincipal: claims.iss is required' unless str(iss)
      raise TypeError, 'oidcPrincipal: claims.sub is required' unless str(sub)

      from_token = ed25519_public_from_cnf(c)
      pp = from_token
      if opts.key?('principal_public')
        provided = canonical_ed25519_b64u(opts['principal_public'])
        raise TypeError, 'oidcPrincipal: opts.principalPublic is not a canonical base64url Ed25519 public key' if provided.nil?
        raise ArgumentError, 'oidcPrincipal: opts.principalPublic does not match the cnf-bound key in the ID token' if from_token && from_token != provided

        pp = provided
      end
      out = { 'iss' => iss, 'sub' => sub, 'principalId' => "#{iss}##{sub}",
              'subjectCaveat' => { 'type' => OIDC_SUBJECT_CAVEAT, 'iss' => iss, 'sub' => sub }, 'claims' => claims }
      out['principalPublic'] = pp if pp
      { 'email' => 'email', 'email_verified' => 'emailVerified', 'name' => 'name', 'preferred_username' => 'preferredUsername',
        'auth_time' => 'authTime' }.each { |src, dst| out[dst] = c[src] if c.key?(src) }
      out
    end

    def oidc_subject_caveat?(cv)
      cv.is_a?(Hash) && cv['type'] == OIDC_SUBJECT_CAVEAT && !str(cv['iss']).nil? && !str(cv['sub']).nil?
    end
  end
end
