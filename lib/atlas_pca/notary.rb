# frozen_string_literal: true

require 'securerandom'
require_relative 'js_compat'
require_relative 'scitt'
require_relative 'grants'
require_relative 'intent_v2'

# External-fact attestation for proof-carrying actions: a notary witnesses one HTTP request/response and signs a canonical
# record of it; the response body is committed as a salted Merkle tree so one field can be disclosed while the rest stay hidden,
# and the disclosure is bound to a PCActn. Mirrors the TypeScript reference (@atlasauth/pca-notary).
#
# Trust boundary: this relies on a trusted or semi-trusted notary (it is NOT trustless zkTLS). Everything fails closed.
# A notary key is a public-key String (b64u text), raw public-key bytes (BINARY String) or a Hash {'publicKey', 'secretKey'}
# (BINARY Strings; the secret key is the 32-byte Ed25519 seed). Options are String-keyed Hashes in snake_case.
module AtlasPca
  module Notary
    BODY_COMMIT_ALG = 'salted-merkle-sha256-v1'
    NOTARY_DOMAIN = "atlas-pca/notary/v1\x00".b.freeze
    ATTESTED_FACT_CAVEAT = 'attested_fact'
    UNSET = Object.new.freeze

    module_function

    # ---- helpers ----

    def safe_integer?(v) = !Scitt.safe_int(v).nil?
    def finite?(v) = v.is_a?(Integer) || (v.is_a?(Float) && v.finite?)
    def bytes?(v) = Scitt.bytes?(v)

    # JavaScript ToNumber for the comparison operands a keyring window may carry (anything else is NaN, so the window fails closed).
    def to_number(v)
      case v
      when nil then 0.0
      when true then 1.0
      when false then 0.0
      when Integer, Float then v.to_f
      when String
        t = Js.trim(v)
        return 0.0 if t.empty?
        return t.start_with?('-') ? -Float::INFINITY : Float::INFINITY if t.match?(/\A[+-]?Infinity\z/)
        return t.to_i(0).to_f if t.match?(/\A0[xX][0-9a-fA-F]+\z|\A0[oO][0-7]+\z|\A0[bB][01]+\z/)

        t.match?(/\A[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?\z/) ? Float(t) : Float::NAN
      else Float::NAN
      end
    end

    def canonical_equal?(a, b)
      AtlasPca.hash_canonical(a) == AtlasPca.hash_canonical(b)
    rescue StandardError
      false
    end

    def normalize_path(path)
      return [path] if path.is_a?(String)
      return path.dup if path.is_a?(Array)

      raise TypeError, 'path must be a string or an array'
    end

    def flatten_value(value, prefix)
      if value.is_a?(Array)
        return [{ 'path' => prefix, 'value' => [] }] if value.empty?

        return value.each_with_index.flat_map { |x, i| flatten_value(x, prefix + [i]) }
      end
      if value.is_a?(Hash)
        return [{ 'path' => prefix, 'value' => {} }] if value.empty?

        return value.keys.sort { |a, b| AtlasPca::V2JS.compare_utf8(a, b) }.flat_map { |k| flatten_value(value[k], prefix + [k]) }
      end
      [{ 'path' => prefix, 'value' => value }]
    end

    def chunk_string(s, size)
      chars = s.chars # by code point
      return [{ 'path' => ['#chunk', 0], 'value' => '' }] if chars.empty?

      step = [size == Float::INFINITY ? chars.length : size.to_i, chars.length].min
      chars.each_slice(step).with_index.map { |sl, idx| { 'path' => ['#chunk', idx], 'value' => sl.join } }
    end

    def leaf_object(leaf) = { 'p' => leaf['path'], 'v' => leaf['value'], 's' => leaf['salt'] }

    def request_headers_digest(headers)
      norm = {}
      unless headers.nil?
        raise TypeError, 'headers must be an object' unless headers.is_a?(Hash)

        headers.each { |k, val| norm[k.downcase] = val }
      end
      AtlasPca.hash_canonical(norm)
    end

    # A public key as b64u: a b64u String, raw bytes (BINARY), or a key pair Hash {'publicKey' => bytes, 'secretKey' => bytes}.
    def to_pub_b64u(key)
      return AtlasPca.b64e(key) if bytes?(key)
      return key if key.is_a?(String)
      raise TypeError, 'not a public key' unless key.is_a?(Hash) && bytes?(key['publicKey'])

      AtlasPca.b64e(key['publicKey'])
    end

    # ---- attestation ----

    # The bytes the notary signs: NOTARY_DOMAIN || sha256(canonical(session)).
    def notary_message(session) = NOTARY_DOMAIN + AtlasPca.sha(AtlasPca.canon_bytes(session))

    # Witness a request/response: the signed attestation plus the prover's private witness (the per-leaf openings).
    # opts: 'observed_at', 'text_chunk_size', 'random_bytes' (callable n -> n bytes; default the OS CSPRNG).
    def notarize_response(request, response, notary_key, opts = {})
      raise TypeError, 'notarizeResponse: request.method is required' unless request.is_a?(Hash) && request['method'].is_a?(String) && !request['method'].empty?
      raise TypeError, 'notarizeResponse: request.url is required' unless request['url'].is_a?(String) && !request['url'].empty?
      raise TypeError, 'notarizeResponse: response.status must be an integer' unless response.is_a?(Hash) && safe_integer?(response['status'])

      body = response['body']
      size = opts['text_chunk_size']
      bare = if body.is_a?(String) && AtlasPca::Js.num?(size) && size >= 1
               chunk_string(body, size == Float::INFINITY ? size : size.floor)
             else
               flatten_value(body, [])
             end
      rb = opts['random_bytes'] || ->(n) { SecureRandom.random_bytes(n) }
      leaves = bare.map { |l| { 'path' => l['path'], 'value' => l['value'], 'salt' => AtlasPca.b64e(rb.call(16)) } }
      root = AtlasPca.merkle_root(leaves.map { |l| leaf_object(l) })
      status = response['status']
      session = {
        'v' => 1,
        'method' => request['method'].upcase,
        'url' => request['url'],
        'requestHeadersDigest' => request_headers_digest(request['headers']),
        'responseStatus' => status.is_a?(Float) && !Scitt.neg_zero?(status) ? status.to_i : status,
        'responseBodyCommit' => { 'alg' => BODY_COMMIT_ALG, 'root' => root, 'size' => leaves.length },
        'observedAt' => opts['observed_at'].nil? ? (Time.now.to_f * 1000).to_i : opts['observed_at']
      }
      attestation = {
        'session' => session,
        'notary' => AtlasPca.b64e(notary_key.fetch('publicKey')),
        'sig' => AtlasPca.b64e(AtlasPca::KeyPair.new(notary_key.fetch('secretKey')).sign(notary_message(session)))
      }
      { 'attestation' => attestation, 'witness' => { 'session' => session, 'leaves' => leaves } }
    end

    # Reveal ONE response field (by path) with its Merkle inclusion proof. Raises if the path names no committed leaf.
    def disclose_field(_attestation, witness, path)
      want = normalize_path(path)
      idx = witness['leaves'].index { |l| canonical_equal?(l['path'], want) }
      raise ArgumentError, "discloseField: no committed field at path #{AtlasPca::Js.json(want)}" if idx.nil?

      leaf = witness['leaves'][idx]
      proof = AtlasPca::Grants.merkle_proof(witness['leaves'].map { |l| leaf_object(l) }, idx)
      { 'path' => leaf['path'], 'value' => leaf['value'], 'salt' => leaf['salt'], 'proof' => proof }
    end

    # ---- verification (fail closed) ----

    def valid_commit?(c)
      c.is_a?(Hash) && c['alg'] == BODY_COMMIT_ALG && c['root'].is_a?(String) && !AtlasPca.b64d(c['root'], 32).nil? &&
        safe_integer?(c['size']) && c['size'] >= 1
    end

    def valid_session?(s)
      s.is_a?(Hash) && s['v'] == 1 && s['method'].is_a?(String) && s['url'].is_a?(String) && s['requestHeadersDigest'].is_a?(String) &&
        safe_integer?(s['responseStatus']) && !Scitt.neg_zero?(s['responseStatus']) &&
        safe_integer?(s['observedAt']) && !Scitt.neg_zero?(s['observedAt']) && valid_commit?(s['responseBodyCommit'])
    end

    # The attestation is structurally valid, signed by the TRUSTED notary key, and the signature verifies.
    def verify_notary_attestation(attestation, notary_key)
      return false unless attestation.is_a?(Hash) && valid_session?(attestation['session'])
      return false unless attestation['notary'].is_a?(String) && attestation['sig'].is_a?(String)
      return false if attestation['notary'] != to_pub_b64u(notary_key)

      AtlasPca.verify_b64u(attestation['notary'], notary_message(attestation['session']), attestation['sig'])
    rescue StandardError
      false
    end

    # The core inclusion check, with the integer index / size and the hash suite refused or normalised as the reference does.
    def inclusion_ok?(root, proof, leaf)
      return false if proof.key?('hash_suite') && proof['hash_suite'] != 'sha256'

      i = Scitt.safe_int(proof['index'])
      n = Scitt.safe_int(proof['size'])
      return false if i.nil? || n.nil? || Scitt.neg_zero?(proof['index']) || Scitt.neg_zero?(proof['size'])

      AtlasPca.verify_inclusion(root, proof.merge('index' => i, 'size' => n), leaf)
    end

    # The attestation is authentic AND the disclosed leaf is included under the attested body root.
    def verify_disclosed_field(attestation, disclosure, notary_key)
      return false unless verify_notary_attestation(attestation, notary_key)
      return false unless disclosure.is_a?(Hash) && disclosure['path'].is_a?(Array) && disclosure['salt'].is_a?(String)

      proof = disclosure['proof']
      return false unless proof.is_a?(Hash) && proof['path'].is_a?(Array)

      commit = attestation['session']['responseBodyCommit']
      return false if [true, false].include?(proof['size']) || proof['size'] != commit['size']

      leaf = leaf_object({ 'path' => disclosure['path'], 'value' => disclosure.fetch('value'), 'salt' => disclosure['salt'] })
      inclusion_ok?(commit['root'], proof, leaf)
    rescue StandardError
      false
    end

    # ---- PCA binding ----

    # A stable digest of the attested fact (independent of any PCActn binding).
    def fact_ref(attestation)
      AtlasPca.hash_canonical({ 'fact' => 'atlas-pca-notary/v1', 'session' => attestation.fetch('session'),
                                'notary' => attestation.fetch('notary'), 'sig' => attestation.fetch('sig') })
    end

    # A new attestation stamped with the digest of the PCActn the fact is FOR.
    def bind_fact_to_pc_actn(attestation, pc_actn)
      raise TypeError, 'attestation must be an object' unless attestation.nil? || attestation.is_a?(Hash)

      (attestation || {}).merge('fact_binding' => { 'pcactn_digest' => AtlasPca.hash_canonical(pc_actn) })
    end

    # Bound in BOTH directions: the fact names the action AND the action's provenance.trusted_refs commits to the fact.
    def fact_matches_pc_actn(attestation, pc_actn)
      binding = attestation['fact_binding']
      return false unless binding.is_a?(Hash) && binding['pcactn_digest'].is_a?(String)
      return false if binding['pcactn_digest'] != AtlasPca.hash_canonical(pc_actn)

      prov = pc_actn['provenance']
      refs = prov.is_a?(Hash) ? prov['trusted_refs'] : nil
      return false unless refs.is_a?(Array)

      refs.include?(fact_ref(attestation))
    rescue StandardError
      false
    end

    # ---- policy caveat ----

    # opts: 'url', 'bind_to_pc_actn' (present adds the member, whatever its value)
    def require_attested_fact(notary, path, equals, opts = {})
      path = path.chars if path.is_a?(String)
      raise TypeError, 'path must be iterable' unless path.is_a?(Array)

      cv = { 'type' => ATTESTED_FACT_CAVEAT, 'notary' => to_pub_b64u(notary), 'path' => path.dup, 'equals' => equals }
      cv['url'] = opts['url'] if opts.key?('url')
      cv['bindToPcActn'] = opts['bind_to_pc_actn'] if opts.key?('bind_to_pc_actn')
      cv
    end

    # `key` is listed in `ring`, not revoked, and `observed_at` lies in its [notBefore, notAfter) window.
    def notary_key_usable(ring, key, observed_at)
      return false unless ring.is_a?(Array) && safe_integer?(observed_at)

      entries = ring.select { |e| e.is_a?(Hash) && e['key'] == key }
      return false if entries.empty?

      obs = observed_at.to_f
      in_window = ->(e) { (!e.key?('notBefore') || obs >= to_number(e['notBefore'])) && (!e.key?('notAfter') || obs < to_number(e['notAfter'])) }
      entries.all? { |e| e['revoked'] != true } && entries.any? { |e| in_window.call(e) }
    end

    # Admit an action only when the notarized field verifies and satisfies the caveat; every step fails closed.
    def evaluate_attested_fact_caveat(caveat, evidence, policy = UNSET, now = nil)
      return { 'ok' => false, 'reason' => 'not an attested_fact caveat' } unless caveat.is_a?(Hash) && caveat['type'] == ATTESTED_FACT_CAVEAT
      unless caveat['notary'].is_a?(String) && caveat['path'].is_a?(Array)
        return { 'ok' => false, 'reason' => 'caveat is malformed (notary/path)' }
      end
      raise TypeError, 'evidence is required' if evidence.nil?

      ev = evidence.is_a?(Hash) ? evidence : {}
      attestation = ev['attestation']
      disclosure = ev['disclosure']
      pc_actn = ev['pcActn']
      pol = policy.equal?(UNSET) ? {} : policy
      raise TypeError, 'policy is null' if pol.nil?

      pol = {} unless pol.is_a?(Hash)
      unless verify_notary_attestation(attestation, caveat['notary'])
        return { 'ok' => false, 'reason' => 'notary attestation does not verify (fail closed)' }
      end
      if pol.key?('keyring') && !notary_key_usable(pol['keyring'], attestation['notary'], attestation['session']['observedAt'])
        return { 'ok' => false, 'reason' => 'notary key is not trusted for this observation time (unlisted, revoked or out of window)' }
      end
      if pol.key?('maxAgeMs')
        clock = pol['now']
        clock = now.nil? ? (Time.now.to_f * 1000).to_i : now if clock.nil?
        stale = { 'ok' => false, 'reason' => 'attestation is stale or from the future' }
        return stale if !finite?(pol['maxAgeMs']) || !finite?(clock)

        age = clock - attestation['session']['observedAt']
        return stale if age.negative? || age > pol['maxAgeMs']
      end
      if caveat.key?('url') && attestation['session']['url'] != caveat['url']
        return { 'ok' => false, 'reason' => 'attested session URL does not match the caveat' }
      end
      unless verify_disclosed_field(attestation, disclosure, caveat['notary'])
        return { 'ok' => false, 'reason' => 'disclosed field does not verify under the attested root' }
      end
      unless canonical_equal?(disclosure['path'], caveat['path'])
        return { 'ok' => false, 'reason' => 'disclosed field is not the path the caveat requires' }
      end
      if !caveat.key?('equals') || !canonical_equal?(disclosure['value'], caveat['equals'])
        return { 'ok' => false, 'reason' => 'disclosed field value does not satisfy the caveat' }
      end
      if AtlasPca::Js.truthy?(caveat['bindToPcActn'])
        return { 'ok' => false, 'reason' => 'caveat requires PCActn binding but no PCActn was supplied' } unless AtlasPca::Js.truthy?(pc_actn)
        return { 'ok' => false, 'reason' => 'fact is not bound to this PCActn' } unless fact_matches_pc_actn(attestation, pc_actn)
      end
      { 'ok' => true, 'trust' => 'notary-trusted' }
    rescue StandardError => e
      { 'ok' => false, 'reason' => "attested_fact evaluation error (fail closed): #{e.message.to_s.empty? ? 'unknown' : e.message}" }
    end

    def attested_fact_caveat?(cv)
      cv.is_a?(Hash) && cv['type'] == ATTESTED_FACT_CAVEAT && cv['notary'].is_a?(String) && cv['path'].is_a?(Array)
    end
  end
end
