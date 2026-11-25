# frozen_string_literal: true

require_relative 'attest_eat_common'
require_relative 'agent'

# Post-quantum co-signature of a verified attestation verdict, matching the TypeScript reference (@atlasauth/pca-attest-eat).
#
# After the classical AMD SEV-SNP hardware root has been verified, the verdict's security-relevant fields (tier, trustworthy bit,
# measured identity, nonce and iat freshness anchor, issuer, co-sign time) are bound under an ML-DSA-65 signature by default (or a
# hybrid / nested-hybrid / category-5 suite). This does NOT make AMD's root post-quantum: it makes the recorded verdict
# forward-secure against a later break of the classical root. A classical-only suite is refused.
#
# The signed bytes are utf8(JSON(obj)) over a fixed field order with a domain-separating typ and every optional field emitted
# explicitly (its value or null). Secret keys are a Hash with the reference's slots: 'edSecret' (32-byte Ed25519 seed) and one of
# 'mlDsa' / 'mlDsa87' / 'slhDsa' / 'slhDsa256s' (an AtlasPca::PqKeyPair for that family).
module AtlasPca
  module AttestEat
    PQCOSIGN_DOMAIN = 'atlas-pca/attest-cosign/v1'
    DEFAULT_PQ_COSIGN_SUITE = 'ml-dsa-65'
    PQ_COSIGN_SUITES = %w[ml-dsa-65 ml-dsa-87 slh-dsa-sha2-128f slh-dsa-sha2-256s hybrid-ed25519-ml-dsa-65
                          hybrid-nested-ed25519-ml-dsa-65 hybrid-ed25519-ml-dsa-87 hybrid-ed25519-slh-dsa-sha2-128f
                          hybrid-ed25519-slh-dsa-sha2-256s].freeze

    module_function

    # One of the accepted post-quantum suites (rejects ed25519, unknown names and non-strings).
    def pq_co_sign_suite?(x) = x.is_a?(String) && PQ_COSIGN_SUITES.include?(x)

    # a JavaScript undefined member is absent from JSON.stringify
    def put(out, k, v)
      out[k] = v unless v.equal?(U)
    end

    def canonical_measured(m)
      return nil if m.equal?(U)

      out = {}
      put(out, 'model_id', g(m, 'model_id'))
      put(out, 'weights_digest', g(m, 'weights_digest'))
      wm = g(m, 'weights_measured')
      out['weights_measured'] = [true, false].include?(wm) ? wm : nil
      put(out, 'runtime_measurement', g(m, 'runtime_measurement'))
      put(out, 'operator', g(m, 'operator'))
      sp = g(m, 'system_prompt_digest')
      tm = g(m, 'tool_manifest_digest')
      out['system_prompt_digest'] = sp.is_a?(String) ? sp : nil
      out['tool_manifest_digest'] = tm.is_a?(String) ? tm : nil
      out
    end

    # The CANONICAL, DETERMINISTIC bytes the co-signature is computed over (fixed field order, null for every absent optional).
    def canonical_verdict_bytes(verdict, cosigned_at)
      c = { 'typ' => PQCOSIGN_DOMAIN }
      put(c, 'tier', g(verdict, 'tier'))
      c['trustworthy'] = g(verdict, 'trustworthy') == true
      measurement = g(verdict, 'measurement')
      nonce = g(verdict, 'nonce')
      iat = g(verdict, 'iat')
      issuer = g(verdict, 'issuer')
      c['measurement'] = measurement.is_a?(String) ? measurement : nil
      c['measured'] = canonical_measured(g(verdict, 'measured'))
      c['nonce'] = nonce.is_a?(String) ? nonce : nil
      c['iat'] = finite?(iat) ? iat : nil
      c['issuer'] = issuer.is_a?(String) ? issuer : nil
      c['cosignedAt'] = cosigned_at
      u8(Js.json(c))
    end

    # An attestation verdict from an appraise result plus the EAT claims (tier, trustworthy, measured identity / launch
    # measurement, nonce, iat, issuer).
    def verdict_from_appraisal(result, claims)
      verdict = {}
      put(verdict, 'tier', g(result, 'tier'))
      put(verdict, 'trustworthy', g(result, 'trustworthy'))
      measured = g(claims, 'measured')
      verdict['measured'] = measured unless measured.equal?(U)
      rm = measured.nil? || measured.equal?(U) ? U : g(measured, 'runtime_measurement')
      if (rm.is_a?(String) || rm.is_a?(Array)) && !rm.empty?
        measurement = rm
      else
        sevsnp = g(claims, 'sevsnp')
        measurement = sevsnp.nil? || sevsnp.equal?(U) ? U : g(sevsnp, 'measurement')
      end
      verdict['measurement'] = measurement if measurement.is_a?(String) && !measurement.empty?
      nonce = g(claims, 'eat_nonce')
      iat = g(claims, 'iat')
      iss = g(claims, 'iss')
      verdict['nonce'] = nonce if nonce.is_a?(String)
      verdict['iat'] = iat if finite?(iat)
      verdict['issuer'] = iss if iss.is_a?(String)
      verdict
    end

    def pq_slot(suite)
      return 'mlDsa87' if suite.include?('ml-dsa-87')
      return 'mlDsa' if suite.include?('ml-dsa-65')
      return 'slhDsa' if suite.include?('slh-dsa-sha2-128f')

      'slhDsa256s'
    end

    # Co-sign a verified verdict under a post-quantum suite (default ml-dsa-65). Call this AFTER the classical hardware check
    # passed. FAIL CLOSED on misconfiguration: a classical-only or unknown suite, or missing key material for the suite, raises.
    def co_sign_attestation(verdict, opts)
      suite = g(opts, 'suite')
      suite = DEFAULT_PQ_COSIGN_SUITE if suite.equal?(U) || suite.nil?
      raise ArgumentError, "coSignAttestation: '#{js_string(suite)}' is not an accepted post-quantum co-sign suite" unless pq_co_sign_suite?(suite)

      keys = g(opts, 'secretKey')
      raise TypeError, 'coSignAttestation: secretKey material is required' unless record?(keys)

      now = g(opts, 'now')
      cosigned_at = finite?(now) ? now : now_ms
      msg = canonical_verdict_bytes(verdict, cosigned_at)

      slot = pq_slot(suite)
      pq_key = keys[slot]
      raise TypeError, "coSignAttestation: suite '#{suite}' requires #{slot} key material" unless pq_key.is_a?(AtlasPca::PqKeyPair)

      signer_pub = { 'pq' => pq_key.public }
      ed = nil
      if suite.start_with?('hybrid')
        seed = keys['edSecret']
        raise TypeError, "coSignAttestation: hybrid suite '#{suite}' requires edSecret" unless bytes?(seed)

        ed = AtlasPca::KeyPair.new(seed)
        signer_pub['ed'] = ed.public
      end
      raise TypeError, "coSignAttestation: suite '#{suite}' requires #{slot} key material" if pq_key.prim != AtlasPca::SIG_SUITES[suite][3]

      sig, pq_sig = AtlasPca.sign_with_suite(suite, ed, pq_key, msg)
      cosig = { 'cosignedAt' => cosigned_at, 'sig' => sig }
      cosig['pq_sig'] = pq_sig unless pq_sig.nil?
      { 'verdict' => verdict, 'cosig' => cosig, 'suite' => suite, 'signer_pub' => signer_pub }
    end

    def parse_signer_pub(v)
      return nil unless record?(v) && v['pq'].is_a?(String) && !v['pq'].empty?

      out = { 'pq' => v['pq'] }
      out['ed'] = v['ed'] if v['ed'].is_a?(String) && !v['ed'].empty?
      out
    end

    def signer_matches?(expected, got)
      exp_pq = expected.is_a?(String) ? expected : g(expected, 'pq')
      return false unless exp_pq.is_a?(String) && ct_eq(exp_pq, got['pq'])

      unless expected.is_a?(String)
        exp_ed = g(expected, 'ed')
        return false if exp_ed.is_a?(String) && (!got['ed'].is_a?(String) || !ct_eq(exp_ed, got['ed']))
      end
      true
    end

    # Verify a co-signed attestation: recompute the canonical bytes from the artifact's OWN verdict and co-sign time and check the
    # post-quantum signature under the embedded signer key. FAIL CLOSED (a result with a reason, never a raise) on a malformed
    # artifact, a classical-only / unknown suite, a tampered verdict field, a wrong key, an expectedSigner mismatch, a
    # co-signature older than maxAgeMs, or a suite this runtime cannot verify. Without expectedSigner it proves only that the
    # signature matches the key EMBEDDED in the artifact.
    def verify_co_signed_attestation(cosigned, opts = nil)
      opts = {} if opts.nil?
      return { 'ok' => false, 'reason' => 'co-signed attestation is not an object' } unless record?(cosigned)

      verdict = cosigned['verdict']
      unless record?(verdict) && verdict['tier'].is_a?(String) && [true, false].include?(verdict['trustworthy'])
        return { 'ok' => false, 'reason' => 'verdict is missing or has a non-string tier / non-boolean trustworthy' }
      end

      cosig = cosigned['cosig']
      unless record?(cosig) && finite?(cosig['cosignedAt']) && cosig['sig'].is_a?(String)
        return { 'ok' => false, 'reason' => 'cosig is missing or has a non-numeric cosignedAt / non-string sig' }
      end

      suite = cosigned['suite']
      unless pq_co_sign_suite?(suite)
        return { 'ok' => false, 'reason' => "suite '#{js_string(cosigned.key?('suite') ? suite : U)}' is not an accepted post-quantum co-sign suite" }
      end

      signer_pub = parse_signer_pub(cosigned['signer_pub'])
      return { 'ok' => false, 'reason' => 'signer_pub is missing or has no post-quantum public key' } if signer_pub.nil?

      now = g(opts, 'now')
      now = finite?(now) ? now : now_ms
      age_ms = now - cosig['cosignedAt']
      partial = { 'ok' => false, 'suite' => suite, 'verdict' => verdict, 'signer_pub' => signer_pub, 'cosignedAt' => cosig['cosignedAt'],
                  'ageMs' => age_ms }

      if has?(opts, 'expectedSigner') && !signer_matches?(opts['expectedSigner'], signer_pub)
        return partial.merge('reason' => 'co-signer public key does not match the expected signer')
      end

      if has?(opts, 'maxAgeMs')
        max_age = opts['maxAgeMs']
        return partial.merge('reason' => 'invalid maxAgeMs') if !finite?(max_age) || max_age <= 0
        return partial.merge('reason' => 'co-sign timestamp is in the future') unless cosig['cosignedAt'] <= now
        return partial.merge('reason' => 'co-signature is stale (older than maxAgeMs)') unless age_ms <= max_age
      end

      msg = canonical_verdict_bytes(verdict, cosig['cosignedAt'])
      return partial.merge('reason' => "unsupported_suite: #{suite}") unless suite_available?(suite)

      p = { 'alg' => suite, 'sig' => cosig['sig'], 'pq_pk' => signer_pub['pq'] }
      p['pq_sig'] = cosig['pq_sig'] if cosig.key?('pq_sig')
      needs_ed = AtlasPca::SIG_SUITES[suite][2] # hybrid: the Ed25519 half verifies under signer_pub.ed
      unless AtlasPca.verify_leaf_suite(p, needs_ed ? signer_pub['ed'] : nil, msg)
        return partial.merge('reason' => 'post-quantum co-signature does not verify (tampered verdict, wrong key, or bad signature)')
      end

      partial.merge('ok' => true)
    rescue StandardError => e # fail closed
      { 'ok' => false, 'reason' => "co-signature verification error (fail closed): #{msg_of(e)}" }
    end

    # This runtime can verify the suite's post-quantum primitive.
    def suite_available?(suite)
      spec = AtlasPca::SIG_SUITES[suite]
      !spec.nil? && (spec[3].nil? || AtlasPca.pq_prim_available?(spec[3]))
    end
  end
end
