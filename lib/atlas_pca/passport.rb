# frozen_string_literal: true

# Signed agent passport verification (wire level): the native counterpart of `verifyPassport` in @atlasauth/pca. Same
# reason codes and check order (the reason text is not part of the contract). Every signature suite this verifier can verify
# for PCActns in this runtime (AtlasPca.supported_suites) is accepted, a post-quantum one only under a PQ key pinned for the
# issuer (`pq_pins`); a suite it cannot verify is refused with `unsupported_suite`.
#
# Hardware evidence seam: the age rule, the binding handed to the verifier and the identity comparison are enforced here.
# The vendor attestation verification comes from `attest` (a callable (document, expected) -> {ok, bound, measured}, the
# integrator's own verifier; it wins when given) or from `default_verifier` (an object answering verify(document, expected,
# now_ms)). With neither, a hardware_rooted passport that passes every other check is refused with
# `hardware_verifier_missing` (fail closed, never a software pass).
module AtlasPca
  PASSPORT_SIG_DOMAIN = "atlas-pca/passport-sig/v1\x00"
  PASSPORT_DEFAULT_EVIDENCE_AGE_MS = 24 * 3_600_000
  PASSPORT_MAX_SKEW_MS = 60_000

  module_function

  def passport_int(v)
    decision_safe_int?(v) ? v.to_i : nil
  end

  def passport_str(v)
    v.is_a?(String) && !v.empty? ? v : nil
  end

  # nil when the passport verifies, else the reason code. `revoked` nil, or raising, is `revocation_unavailable`:
  # ->(passport_id, issuer, subject) { true | false } (only an exact true revokes).
  def verify_passport(sp, trusted_issuers, now_ms, clock_skew_ms: nil, max_evidence_age_ms: nil, subject: nil, revoked: nil,
                      pq_pins: nil, attest: nil, default_verifier: nil)
    verify_passport_unchecked(sp, trusted_issuers, now_ms, clock_skew_ms, max_evidence_age_ms, subject, revoked, pq_pins,
                              attest, default_verifier)
  rescue StandardError, SystemStackError
    'malformed' # total: a value no check anticipated is a refusal
  end

  def verify_passport_unchecked(sp, trusted_issuers, now_ms, clock_skew_ms, max_evidence_age_ms, subject, revoked, pq_pins,
                                attest, default_verifier)
    return 'malformed' unless sp.is_a?(Hash)

    p = sp['passport']
    return 'malformed' unless sp['typ'] == 'atlas-pca/passport' && p.is_a?(Hash)
    return 'unsupported_version' unless passport_int(sp['ver']) == 1
    return 'unsupported_suite' if resolve_suite(sp)[0].nil?

    iss = passport_str(sp['iss'])
    sub = passport_str(sp['sub'])
    sig = passport_str(sp['sig'])
    pid = passport_str(p['id'])
    hw = p['hardware_rooted']
    unless iss && sub && sig && pid && passport_str(p['model_id']) && passport_str(p['operator']) && [true, false].include?(hw)
      return 'malformed'
    end

    nbf = passport_int(sp['nbf'])
    exp = passport_int(sp['exp'])
    iat = passport_int(sp['iat'])
    return 'malformed' if nbf.nil? || exp.nil? || iat.nil? || exp <= nbf || !decision_safe_int?(now_ms)
    return 'unknown_issuer' unless trusted_issuers.is_a?(Array) && trusted_issuers.include?(iss)

    canon = begin
      canon_bytes(sp.reject { |k, _| %w[sig pq_sig].include?(k) })
    rescue Malformed, StandardError, SystemStackError
      return 'malformed'
    end
    pq = resolve_pq_key(iss, sp['pq_pk'], pq_pins: pq_pins)
    return 'bad_signature' unless verify_suite(sp, iss, PASSPORT_SIG_DOMAIN.b + canon, pq)

    fp = { 'd' => 'atlas-pca/passport/v1', 'hardware_rooted' => hw, 'operator' => p['operator'] }
    %w[model_id weights_digest system_prompt_digest tool_manifest_digest runtime_measurement].each { |k| fp[k] = p[k] }
    id_ok = begin
      hash_canonical(fp) == pid
    rescue Malformed, StandardError
      false
    end
    return 'id_mismatch' unless id_ok

    skew = clock_skew_ms.nil? ? 0 : [[clock_skew_ms, 0].max, PASSPORT_MAX_SKEW_MS].min
    return 'not_yet_valid' if now_ms + skew < nbf
    return 'expired' if now_ms - skew >= exp
    return 'subject_mismatch' if !subject.nil? && subject != sub
    return 'revocation_unavailable' if revoked.nil?

    is_revoked = begin
      revoked.call(pid, iss, sub)
    rescue StandardError
      return 'revocation_unavailable'
    end
    return 'revoked' if is_revoked == true

    hw ? passport_hardware_error(sp, p, pid, sub, now_ms, skew, max_evidence_age_ms, attest, default_verifier) : nil
  end

  def passport_hardware_error(sp, p, pid, sub, now_ms, skew, max_evidence_age_ms, attest, default_verifier)
    ev = sp['evidence']
    doc = ev.is_a?(Hash) ? ev['document'] : nil
    at = ev.is_a?(Hash) ? passport_int(ev['at']) : nil
    return 'hardware_evidence_missing' if !doc.is_a?(Hash) || passport_str(doc['nonce']).nil? || at.nil?

    max_age = max_evidence_age_ms.nil? ? PASSPORT_DEFAULT_EVIDENCE_AGE_MS : max_evidence_age_ms
    return 'hardware_evidence_stale' if max_age.negative? || now_ms - at > max_age || at - now_ms > skew

    attest ||= ->(d, expected) { default_verifier.verify(d, expected, now_ms) } unless default_verifier.nil?
    return 'hardware_verifier_missing' if attest.nil?

    r = begin
      attest.call(doc, { 'holder_pub' => sub, 'grant_ref' => "passport:#{pid}", 'epoch' => 0, 'nonce' => doc['nonce'] })
    rescue StandardError
      return 'hardware_attestation_failed'
    end
    r = r.transform_keys(&:to_s) if r.is_a?(Hash)
    return 'hardware_attestation_failed' unless r.is_a?(Hash) && r['ok'] == true && r['bound'] == true
    return 'hardware_identity_mismatch' unless passport_identity_matches?(p, r['measured'])

    nil
  end

  # The hardware-measured identity equals the claims (model and operator always; the optional digests and the runtime
  # measurement when the passport states them; measured weights when it claims them).
  def passport_identity_matches?(p, m)
    return false unless m.is_a?(Hash)

    m = m.transform_keys(&:to_s)
    eq = ->(k) { p[k].is_a?(String) && p[k] == m[k] }
    return false unless eq.call('model_id') && eq.call('operator')
    return false if %w[weights_digest runtime_measurement system_prompt_digest tool_manifest_digest].any? { |k| p.key?(k) && !eq.call(k) }

    !(p['weights_measured'] == true && m['weights_measured'] != true)
  end
end
