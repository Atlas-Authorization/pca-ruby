# frozen_string_literal: true

require 'digest'
require_relative 'attest_eat_common'
require_relative 'agent'
require_relative 'caveat_lang'
require_relative 'provenance_gate'
require_relative 'sigstore_bundle'

# EAT evidence for blueprint admission and the artifact attestation verifier, matching the TypeScript reference
# (@atlasauth/pca-attest-eat), the admission and provenance modules.
#
# eat_admission_evidence turns an EAT into admission evidence for one instance key: signature, issuer, freshness and RATS
# appraisal must all pass and cnf.jkt must be the RFC 7638 thumbprint of THE INSTANCE KEY, so evidence for one instance cannot
# admit another. issue_artifact_discharge joins Sigstore build provenance to the running image digest from an accepted EAT and
# signs the discharge a K1 caveat asks for; any failure returns no discharge, so provenance can only remove authority.
module AtlasPca
  module AttestEat
    TIER_RANK = { 'rejected' => 0, 'contraindicated' => 0, 'warning' => 1, 'affirming' => 2, 'affirming-hw-rooted' => 3 }.freeze

    module_function

    # RFC 7638 thumbprint (base64url SHA-256) of an Ed25519 public key given as unpadded base64url.
    def ed25519_jkt(holder_pub_b64u)
      canonical = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"#{js_string(holder_pub_b64u)}\"}"
      AtlasPca.b64e(Digest::SHA256.digest(u8(canonical)))
    end

    # Admission evidence for o['instanceKey'] (unpadded base64url Ed25519 public key) from an EAT. `o` carries the options of
    # verify_fresh_attested_eat (verifyKey, nonce, policy, now ...) plus minTier (affirming by default, so degraded warning
    # evidence does not admit). Anything unverifiable is ok: false. The identity returned is the measured identity the verifier
    # established. A minTier other than affirming / affirming-hw-rooted is refused before verification.
    def eat_admission_evidence(eat, o)
      min_tier = o.key?('minTier') ? o['minTier'] : U
      if !min_tier.equal?(U) && !%w[affirming affirming-hw-rooted].include?(min_tier)
        return { 'ok' => false, 'bound' => false, 'reason' => 'invalid minTier' }
      end

      min_tier = 'affirming' if min_tier.equal?(U)
      rest = o.reject { |k, _| %w[instanceKey minTier].include?(k) }
      rest['channelBinding'] = { 'jkt' => ed25519_jkt(o.key?('instanceKey') ? o['instanceKey'] : U) }
      v = verify_fresh_attested_eat(eat, rest)
      if v['ok'] != true || v['tier'].nil?
        return { 'ok' => false, 'bound' => false, 'reason' => v['reasons'].empty? ? 'EAT rejected' : v['reasons'].last }
      end
      return { 'ok' => false, 'bound' => true, 'reason' => "appraisal tier #{v['tier']} is below the minimum" } unless TIER_RANK.fetch(v['tier'], -1) >= TIER_RANK[min_tier]

      m = v['claims'].nil? ? U : g(v['claims'], 'measured')
      # a pass checked cnf.jkt against the instance key, so it is bound
      return { 'ok' => true, 'bound' => true } if m.equal?(U) || m.nil?

      { 'ok' => true, 'bound' => true,
        'identity' => { 'runtime_measurement' => m['runtime_measurement'], 'model_id' => m['model_id'], 'weights_digest' => m['weights_digest'],
                        'operator' => m['operator'] } }
    rescue StandardError => e
      { 'ok' => false, 'bound' => false, 'reason' => e.is_a?(TypeError) ? 'TypeError' : 'Error' }
    end

    # The running image's digest from an ACCEPTED EAT: exactly one measurements entry labelled `slot` (default image), lowercase
    # hex of the algorithm's length (sha256: 64, else 128). nil when the verdict is not ok, the slot is missing or repeated, or
    # the value is malformed (no case folding).
    def runtime_digest_from_eat(verdict, o = nil)
      o = {} if o.nil?
      return nil unless verdict.is_a?(Hash) && verdict['ok'] == true && truthy?(verdict['claims'])

      slot = g(o, 'slot')
      alg = g(o, 'alg')
      slot = 'image' if slot.equal?(U) || slot.nil?
      alg = 'sha256' if alg.equal?(U) || alg.nil?
      ms = g(verdict['claims'], 'measurements')
      ms = [] if ms.equal?(U) || ms.nil?
      raise TypeError, '(verdict.claims.measurements ?? []).filter is not a function' unless ms.is_a?(Array)

      hits = ms.select { |m| strict_eq?(g(m, 'type'), slot) }
      return nil unless hits.length == 1

      v = g(hits[0], 'value')
      pat = alg == 'sha256' ? /\A[0-9a-f]{64}\z/ : /\A[0-9a-f]{128}\z/
      v.is_a?(String) && v.match?(pat) ? { 'alg' => alg, 'digest' => v } : nil
    end

    # The unsigned discharge body (request's binding + the gate's claims); raises unless the gate passed and the ttl fits the request.
    def discharge_body(request, gate, iat, ttl_ms, nonce)
      raise ArgumentError, "provenanceDischargeBody: the provenance gate refused (#{gate[:code]})" unless gate[:ok]

      req_ttl = g(request, 'ttl_ms')
      raise ArgumentError, 'provenanceDischargeBody: ttl_ms and iat must be numbers' unless finite?(ttl_ms) && finite?(iat)
      if !req_ttl.equal?(U) && (!finite?(req_ttl) || ttl_ms > req_ttl)
        raise ArgumentError, 'provenanceDischargeBody: ttl_ms exceeds what the caveat accepts'
      end

      body = { 'v' => 1, 'kind' => 'pca-discharge' }
      %w[caveat_id issuer cap_hash bind action_digest].each do |k|
        val = g(request, k)
        body[k] = val unless val.equal?(U) # an undefined member is absent from the signed JSON
      end
      body['claims'] = gate[:claims]
      body['iat'] = iat
      body['not_after'] = iat + ttl_ms
      body['nonce'] = nonce
      body
    end

    def seconds(now)
      return Float::NAN unless finite?(now)

      now.is_a?(Integer) ? now.div(1000) : (now / 1000).floor
    end

    # Run, for one discharge request: (1) the Sigstore bundle against the pinned roots, (2) the join with the running image digest
    # ('runtime' from runtime_digest_from_eat; an EAT that yielded no digest, nil, is a failed join), (3) the provenance gate (the
    # verifier's own pins), (4) sign the discharge with the gate's claims. Returns {'ok' => true, 'discharge', 'facts', 'level'} or
    # {'ok' => false, 'stage' => 'sigstore' | 'gate', 'code', ...}; raises on a malformed signing input.
    #
    # `i`: bundle, roots (a parse_trusted_root result), policy, runtime (optional), request, now (epoch ms), issuerSecret (the 32-byte
    # Ed25519 seed of the artifact-class key), ttl_ms (optional), nonce (optional, default random 16 bytes).
    def issue_artifact_discharge(i)
      v = AtlasPca.verify_sigstore_bundle(g(i, 'bundle'), g(i, 'roots'))
      return { 'ok' => false, 'stage' => 'sigstore', 'code' => v[:code], 'detail' => v[:detail] } unless v[:ok]
      # an EAT that yielded no digest is not "no runtime": it is a failed join
      return { 'ok' => false, 'stage' => 'gate', 'code' => 'no_runtime' } if i.key?('runtime') && i['runtime'].nil?

      now = g(i, 'now')
      inp = { 'facts' => v[:facts], 'policy' => g(i, 'policy'), 'now' => seconds(now) }
      inp['runtime'] = i['runtime'] if i.key?('runtime')
      gate = AtlasPca.provenance_gate(inp)
      return { 'ok' => false, 'stage' => 'gate', 'code' => gate[:code] } unless gate[:ok]

      request = g(i, 'request')
      ttl = g(i, 'ttl_ms')
      ttl = g(request, 'ttl_ms') if ttl.equal?(U) || ttl.nil?
      nonce = g(i, 'nonce')
      nonce = AtlasPca.b64e(SecureRandom.random_bytes(16)) if nonce.equal?(U) || nonce.nil?
      body = discharge_body(request, gate, now, ttl, nonce)
      discharge = AtlasPca.sign_artifact(AtlasPca::DISCHARGE_DOMAIN, body, AtlasPca::KeyPair.new(g(i, 'issuerSecret')))
      e = AtlasPca.discharge_shape_error(discharge) # signDischarge throws on a malformed body (fail closed)
      raise ArgumentError, "signDischarge: #{e}" if e

      { 'ok' => true, 'discharge' => discharge, 'facts' => v[:facts], 'level' => gate[:level] }
    end
  end
end
