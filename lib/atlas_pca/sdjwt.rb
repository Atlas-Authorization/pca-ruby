# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'digest'
require_relative 'jose'
require_relative 'oidc'

# SD-JWT serialization of a PCActn (IETF SD-JWT, RFC 9901): standard claims in the clear, capability claims selectively
# disclosable, an optional holder key-binding JWT. The PCActn's own canonical signature stays the source of truth:
# verify_recovered rebuilds the PCActn from the recovered claims and re-verifies it with PCA Core. Every function fails
# closed. Options are Hashes with the reference option names in snake_case (issuer_key, expected_audience, ...); an absent
# key and a nil value are told apart as undefined and null are in the reference. Result Hashes keep the reference member
# names (protectedHeader, keyBinding).
module AtlasPca
  module SdJwt
    # A refusal of this package (the message is the reference's).
    class Error < StandardError; end
    class ProcessingError < StandardError; end

    SD_ALG = 'sha-256'
    PCA_SD_JWT_TYP = 'pca+sd-jwt'
    KB_JWT_TYP = 'kb+jwt'
    DEFAULT_SIGNING_ALG = 'EdDSA'
    PCA_CAPABILITY_CLAIMS = %w[action grant_ref cap_chain plan attestation provenance freshness counter risk_claim nonce caution
                               rationale_commitment progress_step prohibition_evidence tool_binding alg pq_pk sig pq_sig threshold
                               zk_compliance bond_ref].freeze
    STANDARD_MAPPED = %w[aud iat exp].freeze
    CLEAR_DISCRIMINATOR = 'ver'
    # RFC 9901 s9.7: security-critical claims are never accepted behind a Disclosure.
    CRITICAL_CLAIMS = %w[iss aud exp nbf cnf status].freeze
    RESERVED_CLAIMS = %w[iss sub aud iat exp _sd _sd_alg cnf].freeze
    PUBLIC_JWK_MEMBERS = %w[kty crv x y n e].freeze
    UNSET = Jose::UNSET
    Js = AtlasPca::Js

    module_function

    def b64u(bin) = Jose.b64u(bin)
    def bytes?(v) = v.is_a?(String) && v.encoding == Encoding::BINARY
    def jwk?(v) = v.is_a?(Hash) && v['kty'].is_a?(String)

    # sha256 over the Node 'ascii' encoding of a JS string (the low byte of each UTF-16 code unit), base64url.
    def sha256_ascii_b64u(s)
      bin = s.ascii_only? ? s.b : s.encode('UTF-16LE').unpack('v*').map { |u| u & 0xFF }.pack('C*')
      b64u(Digest::SHA256.digest(bin))
    rescue EncodingError
      b64u(Digest::SHA256.digest(s.b))
    end

    # ---- Ed25519 raw-key bridge ----

    def ed25519_public_jwk(raw)
      raise Error, 'pca-sdjwt: Ed25519 public key must be 32 bytes' unless raw.is_a?(String) && raw.bytesize == 32

      { 'kty' => 'OKP', 'crv' => 'Ed25519', 'x' => b64u(raw.b) }
    end

    def import_ed25519_private_key(raw_seed)
      raise Error, 'pca-sdjwt: Ed25519 private seed must be 32 bytes' unless raw_seed.is_a?(String) && raw_seed.bytesize == 32

      OpenSSL::PKey.new_raw_private_key('ED25519', raw_seed.b)
    end

    def import_ed25519_public_key(raw)
      raise Error, 'pca-sdjwt: Ed25519 public key must be 32 bytes' unless raw.is_a?(String) && raw.bytesize == 32

      OpenSSL::PKey.new_raw_public_key('ED25519', raw.b)
    end

    # ---- issuance ----

    def leaf_holder_jwk(pc_actn)
      chain = pc_actn['cap_chain']
      leaf = chain.is_a?(Array) && !chain.empty? ? chain[-1] : nil
      holder = leaf.is_a?(Hash) ? leaf['holder'] : nil
      raise Error, 'pca-sdjwt: cannot derive holder key — cap_chain leaf holder is missing' unless holder.is_a?(String) && !holder.empty?

      ed25519_public_jwk(Jose.lenient_b64d(holder))
    end

    def resolve_cnf_jwk(pc_actn, kb)
      return leaf_holder_jwk(pc_actn) unless kb.is_a?(Hash) && kb.key?('holder_public_key')

      hp = kb['holder_public_key']
      return ed25519_public_jwk(hp) if bytes?(hp)
      return hp if jwk?(hp)

      raise Error, 'pca-sdjwt: keyBinding.holderPublicKey must be a JWK or a raw Ed25519 public key'
    end

    # Epoch ms -> NumericDate in JS float arithmetic (a Float result, as the reference's one number type).
    def to_numeric_date(ms, label, dir)
      raise Error, "pca-sdjwt: PCActn.#{label} must be a finite number (epoch ms)" unless Js.num?(ms) && ms.to_f.finite?

      q = ms.to_f / 1000
      (dir == :floor ? q.floor : q.ceil).to_f
    end

    def make_disclosure(name, value)
      encoded = b64u(Js.json([b64u(SecureRandom.random_bytes(16)), name, value]).b)
      { 'name' => name, 'encoded' => encoded, 'digest' => sha256_ascii_b64u(encoded) }
    end

    # Serialize a signed PCActn as <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~ (no KB-JWT at issuance).
    # Options: issuer_key (required: an Ed25519 private key / 32-byte seed, a private JWK), disclosable, key_binding
    # ({holder_public_key?}), iss, sub, typ, signing_alg.
    def issue_pca_sd_jwt(pc_actn, options)
      raise Error, 'pca-sdjwt: pcActn must be an object' unless pc_actn.is_a?(Hash)

      chain = pc_actn['cap_chain']
      raise Error, 'pca-sdjwt: pcActn.cap_chain must be a non-empty array' unless chain.is_a?(Array) && !chain.empty?

      root = chain[0]
      leaf = chain[-1]
      raise Error, 'pca-sdjwt: cap_chain root issuer is missing' unless root.is_a?(Hash) && root['issuer'].is_a?(String)
      raise Error, 'pca-sdjwt: cap_chain leaf holder is missing' unless leaf.is_a?(Hash) && leaf['holder'].is_a?(String)

      aud = pc_actn['aud']
      raise Error, 'pca-sdjwt: pcActn.aud is required' unless aud.is_a?(String) && !aud.empty?

      iss = options['iss'].nil? ? root['issuer'] : options['iss']
      sub = options['sub'].nil? ? leaf['holder'] : options['sub']
      iat = to_numeric_date(pc_actn['iat'], 'iat', :floor)
      exp = to_numeric_date(pc_actn['exp'], 'exp', :ceil)
      exp = iat + 1 if exp <= iat # keep exp strictly after iat even for sub-second lifetimes

      disclosable = options['disclosable'].nil? ? PCA_CAPABILITY_CLAIMS : options['disclosable']
      disclosable = disclosable.chars if disclosable.is_a?(String)
      raise TypeError, 'disclosable is not iterable' unless disclosable.is_a?(Array)

      # iat_ms / exp_ms carry the exact signed epoch-ms values so verify_recovered can rebuild the byte-identical PCActn
      payload = { 'iss' => iss, 'sub' => sub, 'aud' => aud, 'iat' => iat, 'exp' => exp }
      payload[CLEAR_DISCRIMINATOR] = pc_actn[CLEAR_DISCRIMINATOR] if pc_actn.key?(CLEAR_DISCRIMINATOR)
      payload['iat_ms'] = pc_actn['iat']
      payload['exp_ms'] = pc_actn['exp']
      payload['_sd_alg'] = SD_ALG
      disclosures = []
      sd = []
      Js.js_keys(pc_actn).each do |key|
        next if STANDARD_MAPPED.include?(key) || key == CLEAR_DISCRIMINATOR

        value = pc_actn[key]
        if disclosable.include?(key)
          d = make_disclosure(key, value)
          disclosures << d
          sd << d['digest']
        else
          payload[key] = value # the caller chose to keep this capability claim in the clear
        end
      end
      payload['_sd'] = sd unless sd.empty?
      kb = options['key_binding']
      payload['cnf'] = { 'jwk' => resolve_cnf_jwk(pc_actn, kb) } if Js.truthy?(kb)

      header = { 'alg' => options['signing_alg'].nil? ? DEFAULT_SIGNING_ALG : options['signing_alg'],
                 'typ' => options['typ'].nil? ? PCA_SD_JWT_TYP : options['typ'] }
      jwt = Jose.sign_jwt(payload, header, options['issuer_key'])
      ([jwt] + disclosures.map { |d| d['encoded'] }).map { |p| "#{p}~" }.join
    end

    # ---- parsing ----

    Parsed = Struct.new(:jwt, :disclosures, :kb_jwt, :presentation_head)

    def parse_sd_jwt(sdjwt)
      raise Error, 'pca-sdjwt: empty SD-JWT' unless sdjwt.is_a?(String) && !sdjwt.empty?

      segments = sdjwt.split('~', -1)
      raise Error, 'pca-sdjwt: malformed SD-JWT (missing ~ separator)' if segments.length < 2

      jwt = segments[0]
      raise Error, 'pca-sdjwt: empty issuer JWT' if jwt.empty?

      last = segments[-1]
      disclosures = segments[1...-1]
      # `a~~b` is an aliasing vector: refuse, never drop
      raise Error, 'pca-sdjwt: empty disclosure segment' if disclosures.any?(&:empty?)

      Jose.assert_canonical_compact_jws(jwt)
      return Parsed.new(jwt, disclosures, nil, sdjwt) if last.empty?

      Jose.assert_canonical_compact_jws(last)
      Parsed.new(jwt, disclosures, last, sdjwt[0, sdjwt.length - last.length])
    end

    def decode_disclosure_parts(encoded)
      parsed = begin
        Jose.decode_canonical_json_segment(encoded)
      rescue StandardError, SystemStackError
        raise Error, 'pca-sdjwt: disclosure is not canonical base64url strict JSON'
      end
      unless parsed.is_a?(Array) && [2, 3].include?(parsed.length)
        raise Error, 'pca-sdjwt: disclosure must be a [salt, name, value] triple or a [salt, value] pair'
      end
      raise Error, 'pca-sdjwt: disclosure salt must be a string' unless parsed[0].is_a?(String)

      parsed
    end

    # ---- holder presentation ----

    # Every digest referenced by `_sd` arrays or {"...": digest} entries anywhere inside `node`.
    def collect_digests(node, out = [])
      if node.is_a?(Array)
        node.each { |x| collect_digests(x, out) }
      elsif node.is_a?(Hash)
        Js.js_keys(node).each do |k|
          v = node[k]
          if k == '_sd' && v.is_a?(Array) then out.concat(v.grep(String))
          elsif k == '...' && v.is_a?(String) then out << v
          else collect_digests(v, out)
          end
        end
      end
      out
    end

    # new Set(iterable): null / undefined is empty, a String iterates its characters, a non-iterable throws.
    def js_set(v)
      return [] if v.nil?
      return v.chars if v.is_a?(String)
      raise TypeError, "#{Js.string(v)} is not iterable" unless v.is_a?(Array)

      v
    end

    # Holder presentation disclosing ONLY select_claims (by claim name), dropping every other Disclosure; an existing KB-JWT
    # is stripped, and with options['key_binding'] ({holder_key, audience, nonce?, iat?, alg?}) a fresh one is signed over
    # the new presentation.
    def present(sdjwt, select_claims, options = nil)
      parsed = parse_sd_jwt(sdjwt)
      keep = js_set(select_claims)
      by_digest = {}
      parsed.disclosures.each { |e| by_digest[sha256_ascii_b64u(e)] = e }

      kept = {}
      incl = lambda do |digest|
        encoded = by_digest[digest]
        next if encoded.nil? || kept.key?(digest)

        kept[digest] = true
        parts = decode_disclosure_parts(encoded)
        collect_digests(parts[-1]).each { |d| incl.call(d) }
      end
      payload = begin
        AtlasPca::Js.parse_text_no_duplicates(Jose.lenient_b64d(parsed.jwt.split('.', -1)[1] || '').force_encoding('UTF-8')) # a duplicate member is refused, not last-wins
      rescue StandardError
        raise Error, 'pca-sdjwt: issuer JWT payload is not valid base64url JSON'
      end
      if payload.is_a?(Hash)
        (payload['_sd'].is_a?(Array) ? payload['_sd'] : []).each do |digest|
          next unless digest.is_a?(String)

          encoded = by_digest[digest]
          next if encoded.nil?

          parts = decode_disclosure_parts(encoded)
          incl.call(digest) if parts[1].is_a?(String) && parts.length == 3 && keep.include?(parts[1])
        end
        Js.js_keys(payload).each do |key|
          collect_digests(payload[key]).each { |d| incl.call(d) } if key != '_sd' && keep.include?(key)
        end
      end
      head = "#{([parsed.jwt] + parsed.disclosures.select { |e| kept.key?(sha256_ascii_b64u(e)) }).join('~')}~"
      kb = options.is_a?(Hash) ? options['key_binding'] : nil
      return head unless Js.truthy?(kb)

      kb_payload = { 'iat' => kb['iat'].nil? ? Time.now.to_i : kb['iat'] }
      kb_payload['aud'] = kb['audience'] if kb.key?('audience')
      kb_payload['sd_hash'] = sha256_ascii_b64u(head)
      kb_payload['nonce'] = kb['nonce'] if kb.key?('nonce')
      header = { 'alg' => kb['alg'].nil? ? DEFAULT_SIGNING_ALG : kb['alg'], 'typ' => KB_JWT_TYP }
      head + Jose.sign_jwt(kb_payload, header, kb['holder_key'])
    end

    # ---- verification ----

    Decoded = Struct.new(:encoded, :parts, :used)

    # RFC 9901 s7.1 payload processing: resolve `_sd` digests and {"...": digest} array entries recursively, refusing
    # reserved / colliding names, reused digests and unreferenced Disclosures. Returns [processed, disclosed_top].
    def process_disclosures(payload, by_digest)
      seen = {}
      disclosed_top = {}
      claim_digest = lambda do |d|
        raise ProcessingError, 'a digest appears more than once in the payload' if seen.key?(d)

        seen[d] = true
        by_digest[d]
      end
      walk = lambda do |node, top|
        if node.is_a?(Array)
          out = []
          node.each do |el|
            if el.is_a?(Hash) && el.keys == ['...']
              digest = el['...']
              raise ProcessingError, "an array '...' entry must reference a string digest" unless digest.is_a?(String)

              d = claim_digest.call(digest)
              next if d.nil? # undisclosed element or decoy: removed
              raise ProcessingError, 'an array-element disclosure must be [salt, value]' unless d.parts.length == 2

              d.used = true
              out << walk.call(d.parts[1], false)
            else
              out << walk.call(el, false)
            end
          end
          next out
        end
        next node unless node.is_a?(Hash)

        out = {}
        Js.js_keys(node).each { |k| out[k] = walk.call(node[k], false) unless k == '_sd' }
        if node.key?('_sd')
          sd = node['_sd']
          raise ProcessingError, '_sd must be an array of strings' unless Js.str_list?(sd)

          sd.each do |digest|
            d = claim_digest.call(digest)
            next if d.nil? # decoy or undisclosed claim
            raise ProcessingError, 'an object-property disclosure must be [salt, name, value]' unless d.parts.length == 3

            name = d.parts[1]
            raise ProcessingError, 'disclosure claim name must be a string' unless name.is_a?(String)
            raise ProcessingError, "disclosure claim name '#{name}' is reserved" if ['_sd', '...'].include?(name)
            raise ProcessingError, "disclosure claim '#{name}' collides with an existing claim" if out.key?(name)
            if top && CRITICAL_CLAIMS.include?(name)
              raise ProcessingError, "'#{name}' is security-critical and must not be selectively disclosable"
            end

            d.used = true
            value = walk.call(d.parts[2], false)
            out[name] = value
            disclosed_top[name] = value if top
          end
        end
        out
      end
      processed = walk.call(payload, true)
      raise ProcessingError, 'payload is not an object' unless processed.is_a?(Hash)

      processed.delete('_sd_alg')
      by_digest.each_value do |d|
        raise ProcessingError, 'a presented disclosure is not referenced by any digest in the payload' unless d.used
      end
      [processed, disclosed_top]
    end

    # JS `===` over JSON values (an object or array is never equal to a different one).
    def js_same(a, b)
      return a.equal?(b) if a.is_a?(Hash) || a.is_a?(Array) || b.is_a?(Hash) || b.is_a?(Array)
      return a == b if Js.num?(a) && Js.num?(b)

      a.instance_of?(b.class) && a == b
    end

    # ToNumber of a JSON value (null is 0, a non-numeric string NaN).
    def to_num(v) = v.nil? ? 0 : Oidc.to_num(v)

    # The `x` of a key: raw Ed25519 bytes, a JWK, or an OpenSSL public key.
    def key_x(k)
      return b64u(k) if bytes?(k)
      return k['x'].is_a?(String) ? k['x'] : nil if jwk?(k)
      raise TypeError, 'key must be a KeyObject, a JWK or raw Ed25519 bytes' unless k.is_a?(OpenSSL::PKey::PKey)
      return b64u(k.raw_public_key) if Jose.eddsa?(k)
      return nil unless k.is_a?(OpenSSL::PKey::EC)

      pt = k.public_key.to_octet_string(:uncompressed)
      b64u(pt.byteslice(1, (pt.bytesize - 1) / 2))
    end

    # importJWK of the cnf key (the reference builds a key object from the JWK members it needs, so a stray private member or
    # alg hint plays no part). Returns [key, deferred]: an OKP key that cannot be built, or an unknown kty, is refused here; a
    # symmetric or unusable EC / RSA key is refused by the KB-JWT verification (`deferred`).
    def import_cnf_jwk(jwk)
      pub = jwk.slice(*PUBLIC_JWK_MEMBERS)
      case jwk['kty']
      when 'OKP'
        begin
          [Jose.public_key_from_jwk(pub), nil]
        rescue Jose::Error, OpenSSL::PKey::PKeyError, ArgumentError
          raise Error, 'Invalid JWK OKP key'
        end
      when 'EC', 'RSA'
        begin
          [Jose.public_key_from_jwk(pub), nil]
        rescue Jose::Error, OpenSSL::PKey::PKeyError, ArgumentError => e
          [nil, e.message]
        end
      when 'oct'
        raise Error, 'missing "k" (Key Value) Parameter value' unless jwk['k'].is_a?(String) && !jwk['k'].empty?

        [nil, 'Invalid key for this operation: a symmetric key']
      else raise Error, 'Unsupported "kty" (Key Type) Parameter value'
      end
    end

    def refuse(reason) = { 'ok' => false, 'reason' => reason }

    def opt(o, k) = o.key?(k) ? o[k] : UNSET

    # Verify a PCA SD-JWT, FAIL CLOSED: any bad signature, unknown `_sd_alg`, unmatched / forged Disclosure, audience /
    # expiry violation or key-binding failure returns {'ok' => false, 'reason'}. Options: issuer_key (required),
    # required_disclosures, expected_audience, key_binding_key, expected_kb_audience, expected_nonce, require_key_binding,
    # algorithms, kb_algorithms, now (epoch ms), kb_max_age_sec, clock_tolerance_sec.
    def verify_pca_sd_jwt(sdjwt, options)
      # a non-finite clock, tolerance or window would slip past the date checks (NaN compares false, -Infinity is before every expiry)
      unless %w[now clock_tolerance_sec kb_max_age_sec].all? { |k| (v = options[k]).nil? || (Js.num?(v) && (v.is_a?(Integer) || v.finite?)) }
        return refuse('now, clockToleranceSec and kbMaxAgeSec must be finite')
      end
      # a Date beyond +-8.64e15 ms is invalid, which the JWT library reads as no clock at all: refused like a non-finite one
      return refuse('now is not a representable time') if options.key?('now') && !options['now'].nil? && !(options['now'].abs <= 8.64e15)

      parsed = parse_sd_jwt(sdjwt)
      algorithms = options['algorithms'].nil? ? [DEFAULT_SIGNING_ALG] : options['algorithms']
      now_ms = options.key?('now') ? (options['now'].nil? ? 0 : options['now']) : nil
      tol = opt(options, 'clock_tolerance_sec')
      payload, protected_header = Jose.jwt_verify(parsed.jwt, options['issuer_key'], algorithms: algorithms,
                                                                                    audience: opt(options, 'expected_audience'),
                                                                                    now_ms: now_ms, clock_tolerance: tol)
      return refuse(%(unsupported _sd_alg (require "#{SD_ALG}"))) if payload.key?('_sd_alg') && payload['_sd_alg'] != SD_ALG

      by_digest = {}
      parsed.disclosures.each do |encoded|
        digest = sha256_ascii_b64u(encoded)
        return refuse('duplicate disclosure') if by_digest.key?(digest)

        by_digest[digest] = Decoded.new(encoded, decode_disclosure_parts(encoded), false)
      end
      begin
        processed, disclosed = process_disclosures(payload, by_digest)
      rescue ProcessingError => e
        return refuse(e.message.include?('not referenced') ? 'a presented disclosure does not match any _sd digest (tampered)' : e.message)
      end

      js_set(options['required_disclosures']).each do |required|
        r = Js.string(required)
        return refuse("required disclosure '#{r}' was not presented") unless disclosed.key?(r)
      end

      cnf = payload['cnf']
      cnf_jwk = cnf.is_a?(Hash) && jwk?(cnf['jwk']) ? cnf['jwk'] : nil
      key_binding = { 'presented' => !parsed.kb_jwt.nil?, 'verified' => false }

      if parsed.kb_jwt
        return refuse('KB-JWT presented but issuer JWT has no cnf key') if cnf_jwk.nil?

        if options.key?('key_binding_key')
          want = key_x(options['key_binding_key'])
          have = key_x(cnf_jwk)
          return refuse('cnf key does not match the expected keyBindingKey') if want.nil? || have.nil? || want != have
        end
        kb_algorithms = options['kb_algorithms'].nil? ? [DEFAULT_SIGNING_ALG] : options['kb_algorithms']
        kb_key, deferred = import_cnf_jwk(cnf_jwk)
        kb_audience = options['expected_kb_audience'].nil? ? opt(options, 'expected_audience') : options['expected_kb_audience']
        begin
          raise Jose::Error, deferred if deferred

          kb_payload, kb_header = Jose.jwt_verify(parsed.kb_jwt, kb_key, algorithms: kb_algorithms, audience: kb_audience,
                                                                          now_ms: now_ms, clock_tolerance: tol)
        rescue StandardError => e
          return refuse("KB-JWT signature/claims invalid: #{e.message}")
        end
        return refuse(%(KB-JWT typ must be "#{KB_JWT_TYP}")) unless kb_header['typ'] == KB_JWT_TYP

        kb_iat = kb_payload['iat']
        return refuse('KB-JWT iat is required') unless Js.num?(kb_iat)

        if options.key?('kb_max_age_sec')
          now_sec = ((now_ms.nil? ? Time.now.to_f * 1000 : now_ms.to_f) / 1000).floor
          max_age = to_num(options['kb_max_age_sec'])
          return refuse('KB-JWT iat is not a finite number') unless kb_iat.to_f.finite?
          return refuse('KB-JWT is older than the accepted window') unless now_sec - kb_iat <= max_age

          ct = options['clock_tolerance_sec']
          return refuse('KB-JWT iat is in the future') if kb_iat - now_sec > (ct.nil? ? 0 : to_num(ct))
        end
        kb_aud = kb_payload['aud']
        return refuse('KB-JWT aud is required') unless kb_aud.is_a?(String) || kb_aud.is_a?(Array)
        return refuse('KB-JWT sd_hash does not cover this presentation') unless kb_payload['sd_hash'] == sha256_ascii_b64u(parsed.presentation_head)
        if options.key?('expected_nonce') && !(kb_payload.key?('nonce') && js_same(kb_payload['nonce'], options['expected_nonce']))
          return refuse('KB-JWT nonce does not match')
        end

        key_binding['verified'] = true
        key_binding['aud'] = kb_aud if kb_aud.is_a?(String)
        key_binding['nonce'] = kb_payload['nonce'] if kb_payload['nonce'].is_a?(String)
      elsif options.key?('key_binding_key') || Js.truthy?(options['require_key_binding'])
        return refuse('key binding required but no KB-JWT was presented')
      end

      claims = processed.reject { |k, _| RESERVED_CLAIMS.include?(k) }
      { 'ok' => true, 'payload' => payload, 'processed' => processed, 'protectedHeader' => protected_header,
        'disclosed' => disclosed, 'claims' => claims, 'keyBinding' => key_binding }
    rescue StandardError, SystemStackError => e
      refuse(e.message) # fail closed: every error is a refusal carrying its message
    end

    CORE_OPTS = %w[allowed_suites intent_policy intent_v2 fresh_at authorized_plan_roots insecure_skip_plan_root_check pq_pins].freeze

    # Re-verify a verified SD-JWT with PCA Core: rebuild the PCActn from the recovered claims and run AtlasPca.verify_pcactn
    # (core_opts: grant, now (epoch ms), audience, and its other keywords by name). FAIL CLOSED: a withheld required claim,
    # missing or inconsistent iat_ms / exp_ms, or an iss / sub that disagrees with the chain denies.
    def verify_recovered(res, core_opts)
      deny = ->(reason) { Verdict.new(false, {}, reason) }
      rest = res['claims'].dup
      p = res['processed']
      iat_ms = rest.delete('iat_ms')
      exp_ms = rest.delete('exp_ms')
      return deny.call('pca-sdjwt: iat_ms/exp_ms missing; cannot rebuild the PCActn') unless Js.num?(iat_ms) && Js.num?(exp_ms)
      return deny.call('pca-sdjwt: iat_ms disagrees with iat') unless js_same((iat_ms.to_f / 1000).floor, p['iat'])
      unless js_same([(exp_ms.to_f / 1000).ceil, (iat_ms.to_f / 1000).floor + 1].max, p['exp'])
        return deny.call('pca-sdjwt: exp_ms disagrees with exp')
      end

      %w[action cap_chain plan sig grant_ref counter].each do |k|
        return deny.call("pca-sdjwt: required claim '#{k}' was not disclosed") unless rest.key?(k)
      end
      return deny.call('pca-sdjwt: aud must be a string') unless p['aud'].is_a?(String)

      chain = rest['cap_chain']
      return deny.call('pca-sdjwt: cap_chain is empty') unless chain.is_a?(Array) && !chain.empty?

      member = ->(o, k) { o.is_a?(Hash) && o.key?(k) ? o[k] : UNSET }
      return deny.call('pca-sdjwt: iss does not match the chain root issuer') unless js_same(member.call(p, 'iss'), member.call(chain[0], 'issuer'))
      return deny.call('pca-sdjwt: sub does not match the chain leaf holder') unless js_same(member.call(p, 'sub'), member.call(chain[-1], 'holder'))

      pc_actn = rest.dup
      pc_actn['ver'] = p['ver'] if p.key?('ver')
      pc_actn.merge!('aud' => p['aud'], 'iat' => iat_ms, 'exp' => exp_ms)
      kw = CORE_OPTS.select { |k| core_opts.key?(k) }.to_h { |k| [k.to_sym, core_opts[k]] }
      now = core_opts['now'].nil? ? (Time.now.to_f * 1000).floor : core_opts['now']
      begin
        AtlasPca.verify_pcactn(pc_actn, core_opts['grant'], now: now, audience: core_opts['audience'], **kw)
      rescue StandardError => e
        deny.call("pca-sdjwt: core verification threw: #{e.message}")
      end
    end
  end
end
