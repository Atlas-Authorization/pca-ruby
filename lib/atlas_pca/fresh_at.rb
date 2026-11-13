# frozen_string_literal: true

# Consistency tokens (`fresh_at`): a signed high-water mark of verifier-side state (revocation epoch, ledger size, budget
# version, policy revision). The verifier refuses to DECIDE against state older than the token it was handed (`stale_state`
# is an escalate-class failure, never an allow). The token travels as the SIGNED `fresh_at` PCActn member. Every function is
# total: malformed input returns the failure value, never raises. Verdicts match packages/pca/conformance/{k3,fresh-at}-vectors.json.
# Hashes use String keys.
module AtlasPca
  FRESH_AT_DOMAIN = "atlas-pca/fresh-at/v1\x00".b.freeze
  FRESH_AT_REF_DOMAIN = 'atlas-pca/fresh-at-ref/v1'
  FRESH_AT_NUMERIC = %w[revocation_epoch ledger_tree_size budget_version policy_revision].freeze
  FRESH_AT_KEYS = (%w[v scope policy_digest issued_at signer sig] + FRESH_AT_NUMERIC).freeze
  FRESH_AT_SKEW_MS = 60_000
  FRESH_AT_ABSENT = Object.new.freeze # "no token" (an explicit nil token is a token, and a bad one)

  module_function

  # JS Number.isSafeInteger(n) && n >= 0 over a JSON value.
  def k3_int?(n)
    n.is_a?(Integer) && n >= 0 && n <= MAX_SAFE
  end

  # Non-empty string of at most `max` UTF-16 code units.
  def k3_str?(x, max = 512)
    x.is_a?(String) && !x.empty? && utf16_len(x) <= max
  end

  # Ed25519 over DOMAIN-PREFIX bytes || strict canonical JSON(body). Never raises.
  def k3_verify_body(domain, body, signer, sig)
    return false unless sig.is_a?(String) && !b64d(sig, 64).nil?

    verify_b64u(signer, domain.b + canon_bytes(body), sig)
  rescue StandardError
    false
  end

  def fresh_at_body(t)
    FRESH_AT_KEYS.reject { |k| k == 'sig' }.to_h { |k| [k, t[k]] }
  end

  # Well formed and signed by `signer` over exactly its content.
  def verify_fresh_at(t, signer)
    return false unless t.is_a?(Hash) && t['v'] == 1 && t['signer'] == signer && k3_str?(t['scope'], 256) &&
                        k3_str?(t['policy_digest'], 128) && k3_int?(t['issued_at'])
    return false unless FRESH_AT_NUMERIC.all? { |k| k3_int?(t[k]) }

    k3_verify_body(FRESH_AT_DOMAIN, fresh_at_body(t), signer, t['sig'])
  rescue StandardError
    false
  end

  # The content address a PCActn or request signs to bind the token it carried.
  def fresh_at_digest(t)
    hash_canonical({ 'd' => FRESH_AT_REF_DOMAIN, 't' => t })
  rescue StandardError
    nil
  end

  # May the verifier decide against `local` for `token`? signature/shape -> scope -> future (> 60 s skew) -> token age ->
  # policy fork -> a counter behind the token => escalate stale_state. Returns {'decision' => ok|escalate|deny, 'code'?, 'behind'?}.
  def check_fresh_at(token, local, signer:, scope:, now:, max_token_age_ms: nil)
    return { 'decision' => 'deny', 'code' => 'bad_token' } unless verify_fresh_at(token, signer)
    return { 'decision' => 'deny', 'code' => 'wrong_scope' } if token['scope'] != scope
    return { 'decision' => 'deny', 'code' => 'token_from_the_future' } unless token['issued_at'] <= now + FRESH_AT_SKEW_MS
    return { 'decision' => 'deny', 'code' => 'token_too_old' } if !max_token_age_ms.nil? && !(now - token['issued_at'] <= max_token_age_ms)

    loc = local.is_a?(Hash) ? local : {}
    if token['policy_revision'] == loc['policy_revision'] && token['policy_digest'] != loc['policy_digest']
      return { 'decision' => 'deny', 'code' => 'policy_fork' }
    end

    behind = FRESH_AT_NUMERIC.reject { |k| loc[k].is_a?(Numeric) && loc[k] >= token[k] }
    behind.empty? ? { 'decision' => 'ok' } : { 'decision' => 'escalate', 'code' => 'stale_state', 'behind' => behind }
  rescue StandardError
    { 'decision' => 'deny', 'code' => 'bad_token' }
  end

  # Wire shape of the member (closed key set). Returns the problem text or nil. Does NOT check the signature.
  def validate_fresh_at_wire(v)
    return "'fresh_at' must be an object" unless v.is_a?(Hash)

    v.each_key { |k| return "'fresh_at' has an unknown field '#{k}'" unless FRESH_AT_KEYS.include?(k) }
    return "'fresh_at.v' must be 1" unless v['v'] == 1
    return "'fresh_at' scope and policy_digest must be non-empty strings" unless k3_str?(v['scope'], 256) && k3_str?(v['policy_digest'], 128)

    (FRESH_AT_NUMERIC + ['issued_at']).each do |k|
      return "'fresh_at.#{k}' must be a non-negative safe integer" unless k3_int?(v[k])
    end
    return "'fresh_at.signer' is not canonical base64url (32 bytes)" if b64d(v['signer'], 32).nil?
    return "'fresh_at.sig' is not canonical base64url (64 bytes)" if b64d(v['sig'], 64).nil?

    nil
  end

  # The verifier's `fresh_at` check as a v2-style check hash {'name','ok','reason'?}, or nil when it is not reported (no member,
  # no side-carried token, no `require`). `policy` (String keys): signer, scope, local {revocation_epoch, ledger_tree_size,
  # budget_version, policy_revision, policy_digest}, max_token_age_ms?, require?, side_carried? (key present, even nil, = a token
  # travelled beside the PCActn; read only when the PCActn has no member).
  def decide_fresh_at(pcactn, policy, now)
    has_member = pcactn.is_a?(Hash) && pcactn.key?('fresh_at')
    fail_with = ->(why) { { 'name' => 'fresh_at', 'ok' => false, 'reason' => why } }
    if policy.nil?
      return has_member ? fail_with.call('the PCActn carries fresh_at but this verifier has no fresh_at policy (fail closed)') : nil
    end
    return fail_with.call('fresh_at policy is malformed (fail closed)') unless policy.is_a?(Hash)

    token = if has_member then pcactn['fresh_at']
            elsif policy.key?('side_carried') then policy['side_carried']
            else FRESH_AT_ABSENT
            end
    if token.equal?(FRESH_AT_ABSENT)
      return policy['require'] == true ? fail_with.call('escalate: a consistency token is required (refresh and retry with the token of your latest write)') : nil
    end

    v = check_fresh_at(token, policy['local'], signer: policy['signer'], scope: policy['scope'], now: now,
                                               max_token_age_ms: policy['max_token_age_ms'])
    case v['decision']
    when 'ok' then { 'name' => 'fresh_at', 'ok' => true }
    when 'escalate' then fail_with.call("escalate: stale_state (verifier state is behind the token on #{v['behind'].join(', ')})")
    else fail_with.call(v['code'])
    end
  rescue StandardError
    { 'name' => 'fresh_at', 'ok' => false, 'reason' => 'fresh_at check error (fail closed)' }
  end
end
