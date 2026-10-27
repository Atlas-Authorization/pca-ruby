# frozen_string_literal: true

# Escalation on the wire: a port of packages/pca/src/escalation.ts (security contract C-51). A verifier decision of
# `escalate` is admitted only with a principal-signed answer bound to (policy digest, action digest, history head), spent
# by the replay counter, never upgrading a deny. The answer's signature is verified under EVERY suite this SDK verifies
# (Ed25519 by default; a PQ / hybrid suite only under a PQ key pinned for the principal). Total: never raises.
module AtlasPca
  ESCALATION_ANSWER_DOMAIN = "atlas-pca/escalation-answer/v1\x00"
  ESCALATION_MAX_LIFETIME_MS = 86_400_000
  ESCALATION_REQUIRED = %w[v kind principal policy_digest action_digest history_head decision iat expires_at nonce sig].freeze
  ESCALATION_OPTIONAL = %w[alg pq_pk pq_sig].freeze

  module_function

  def escalation_policy_digest(grant)
    hash_canonical({ 'd' => 'atlas-pca/escalation-policy/v1', 'grant' => grant })
  end

  def escalation_action_digest(pcactn)
    hash_canonical({ 'd' => 'atlas-pca/escalation-action/v1', 'pcactn' => pcactn })
  end

  # last_counter nil is the empty history (JSON null).
  def escalation_history_head(last_counter)
    hash_canonical({ 'd' => 'atlas-pca/escalation-history/v1', 'last_counter' => last_counter })
  end

  # The question put to the principal for an escalate decision.
  def build_escalation_request(aud:, grant:, pcactn:, last_counter:, reasons:, now:, ttl_ms: 3_600_000)
    action = pcactn.is_a?(Hash) && pcactn['action'].is_a?(Hash) ? pcactn['action'] : {}
    {
      'v' => 1, 'kind' => 'pca-escalation-request', 'aud' => aud.is_a?(String) ? aud : '',
      'policy_digest' => escalation_policy_digest(grant), 'action_digest' => escalation_action_digest(pcactn),
      'history_head' => escalation_history_head(last_counter),
      'verb' => Predicates.js_string(action.key?('verb') ? action['verb'] : Predicates::UNDEF),
      'resource' => Predicates.js_string(action.key?('resource') ? action['resource'] : Predicates::UNDEF),
      'reasons' => reasons.first(16).map { |r| utf16_slice(r.to_s, 512) }, 'expires_at' => now + ttl_ms
    }
  end

  # nil when well-formed (closed members, canonical digests, safe-integer times, sane lifetime), else the reason.
  def escalation_answer_shape_error(a)
    return 'not an object' unless a.is_a?(Hash)

    a.each_key { |k| return "unknown member 'answer.#{k}'" unless ESCALATION_REQUIRED.include?(k) || ESCALATION_OPTIONAL.include?(k) }
    ESCALATION_REQUIRED.each { |k| return "missing member 'answer.#{k}'" unless a.key?(k) }
    return 'not a pca-escalation-answer v1' unless a['v'] == 1 && a['kind'] == 'pca-escalation-answer'
    return 'principal must be canonical base64url (32 bytes)' unless a['principal'].is_a?(String) && !b64d(a['principal'], 32).nil?

    %w[policy_digest action_digest history_head].each do |k|
      return "#{k} must be canonical base64url (32 bytes)" unless a[k].is_a?(String) && !b64d(a[k], 32).nil?
    end
    return "decision must be 'allow' or 'deny'" unless %w[allow deny].include?(a['decision'])

    iat = a['iat']
    exp = a['expires_at']
    unless decision_safe_int?(iat) && iat >= 0 && decision_safe_int?(exp) && exp >= 0
      return 'iat and expires_at must be non-negative safe integers'
    end
    return 'expires_at must be greater than iat' unless exp > iat
    return "an answer lives at most #{ESCALATION_MAX_LIFETIME_MS} ms" if exp - iat > ESCALATION_MAX_LIFETIME_MS

    nb = a['nonce'].is_a?(String) ? b64d(a['nonce']) : nil
    return 'nonce must be canonical base64url of at least 16 bytes' if nb.nil? || nb.bytesize < 16
    return 'sig must be a string' unless a['sig'].is_a?(String)

    %w[pq_pk pq_sig].each { |k| return "#{k} must be a string" if a.key?(k) && !a[k].is_a?(String) }
    return 'alg must be a string' if a.key?('alg') && !a['alg'].is_a?(String)

    suite, err = resolve_suite(a)
    return (err.start_with?('unknown signature alg') ? "#{UNSUPPORTED_SUITE}: #{err}" : err) if suite.nil?
    return 'an ed25519 artifact must not carry pq_pk / pq_sig' if suite == 'ed25519' && (a.key?('pq_pk') || a.key?('pq_sig'))

    nil
  end

  # The principal's signed bytes: utf8(domain) || strictCanonical(answer without sig / pq_sig).
  def escalation_answer_message(answer)
    # v / iat / expires_at spelled 1.0 or 1e3 are the integers they are (the canonical form has no floats)
    body = answer.reject { |k, _| %w[sig pq_sig].include?(k) }
                 .to_h { |k, x| [k, %w[v iat expires_at].include?(k) && x.is_a?(Float) && decision_safe_int?(x) ? x.to_i : x] }
    ESCALATION_ANSWER_DOMAIN.b + canon_bytes(body)
  end

  # Verify `answer` against the verifier's pinned principals (b64u strings, or {'pk' =>, 'pq_pk' =>}) and the binding of THIS
  # decision {policy_digest, action_digest, history_head}. {ok: true, principal:, decision: 'allow'|'deny'} or
  # {ok: false, reason:}. `decision: 'deny'` is a valid answer that refuses the action: the caller must not admit it.
  def verify_escalation_answer(answer, principals, bind, now)
    no = ->(r) { { ok: false, reason: r } }
    return no.call('the verifier clock is not a safe integer (fail closed)') unless decision_safe_int?(now)

    e = escalation_answer_shape_error(answer)
    return no.call("malformed escalation answer: #{e}") if e
    return no.call('no principal is pinned for escalation answers') unless principals.is_a?(Array) && !principals.empty?

    pin = principals.map { |p| p.is_a?(String) ? { 'pk' => p } : p }
                    .find { |p| p.is_a?(Hash) && p['pk'] == answer['principal'] }
    return no.call('the answering principal is not pinned by this verifier') if pin.nil?

    pins = pin['pq_pk'].is_a?(String) ? { pin['pk'] => pin['pq_pk'] } : {}
    unless IntentV2.verify_pinned_suite(answer.fetch('alg', V2JS::UNDEF), pin['pk'], answer.fetch('pq_pk', V2JS::UNDEF),
                                    escalation_answer_message(answer), answer['sig'], answer.fetch('pq_sig', V2JS::UNDEF), pins)
      return no.call('escalation answer signature invalid')
    end
    return no.call('the answer is bound to another policy') unless answer['policy_digest'] == bind['policy_digest']
    return no.call('the answer is bound to another action') unless answer['action_digest'] == bind['action_digest']
    return no.call('the answer is bound to another state of the history') unless answer['history_head'] == bind['history_head']
    return no.call('the answer is from the future') if now < answer['iat']
    return no.call('the answer has expired') if now > answer['expires_at']

    { ok: true, principal: answer['principal'], decision: answer['decision'] }
  rescue StandardError, SystemStackError => e
    { ok: false, reason: "escalation answer error (fail closed): #{e.class}" }
  end
end
