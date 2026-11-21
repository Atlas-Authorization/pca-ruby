# frozen_string_literal: true

# Optimistic-path wire verification: bonded claims, the challenge window, fraud proofs (wire level) and settlement records.
# Matches the shared extension-layer vectors (packages/pca/conformance/optimistic-vectors.json). A fraud proof passing
# fraud_proof_wire_check is well-formed and self-consistent only; recomputing the policy decision it asserts is the
# settlement layer's job.
module AtlasPca
  DEFAULT_WINDOW_POLICY = { 'minWindowMs' => 1000, 'maxWindowMs' => 86_400_000, 'defaultWindowMs' => 300_000,
                            'maxSkewMs' => 5000 }.freeze
  IRREVERSIBLE_CLASS = 'irreversible'
  OPTIMISTIC_CLAIM_DOMAIN = "atlas-pca/optimistic/v1\x00"
  OPTIMISTIC_SETTLEMENT_DOMAIN = "atlas-pca/bond-settlement/v1\x00"
  FRAUD_KINDS = %w[policy-denied risk-understated optimistic-not-allowed irreversible].freeze
  DEFAULT_R_MARGIN = 1e-9
  OPT_MISSING = Object.new.freeze

  module_function

  # A finite JSON number (JS Number.isFinite on a value that is not coerced).
  def opt_num?(x)
    (x.is_a?(Integer) || (x.is_a?(Float) && x.finite?))
  end

  # JS strict equality for JSON values.
  def opt_same?(a, b)
    a_bool = [true, false].include?(a)
    b_bool = [true, false].include?(b)
    return a_bool && b_bool && a == b if a_bool || b_bool
    return a == b if opt_num?(a) && opt_num?(b)

    a.class == b.class && a == b
  end

  def opt_get(h, k)
    h.key?(k) ? h[k] : OPT_MISSING
  end

  def opt_validate_window(issued_at, window_ms, server_now, policy)
    return 'server time is not finite' unless opt_num?(server_now)
    return 'malformed challenge window' unless opt_num?(issued_at) && opt_num?(window_ms)
    return 'issued_at is outside the allowed skew of server time' unless (issued_at - server_now).abs <= policy['maxSkewMs']
    return 'challenge window is below the minimum' unless window_ms >= policy['minWindowMs']
    return 'challenge window exceeds the maximum' unless window_ms <= policy['maxWindowMs']

    nil
  end

  # First failing check of a bonded claim: malformed, irreversible, digest, claimed_r, window, signature; else 'ok'.
  def claim_check(claim, expected_pcactn_digest, signer_public, server_now, window_policy = nil)
    return 'digest' if claim.is_a?(Array) # an array is an object with no members: it covers no PCActn
    return 'malformed' unless claim.is_a?(Hash)
    return 'irreversible' if claim['reversibility_class'] == IRREVERSIBLE_CLASS
    return 'digest' unless opt_same?(opt_get(claim, 'pcactn_digest'), expected_pcactn_digest)
    return 'claimed_r' unless opt_num?(claim['claimed_r'])

    unless opt_validate_window(claim['issued_at'], claim['challenge_window_ms'], server_now,
                               window_policy || DEFAULT_WINDOW_POLICY).nil?
      return 'window'
    end

    sig = claim['sig']
    body = claim.reject { |k, _| k == 'sig' }
    return 'signature' unless sig.is_a?(String) && verify_b64u(signer_public, OPTIMISTIC_CLAIM_DOMAIN.b + canonical_bytes_lenient(body), sig)

    'ok'
  rescue StandardError, SystemStackError
    'malformed'
  end

  # {'ok' => true} or {'ok' => false, 'reason'}: claim_check with the human reason of the first failing check (the reference's verifyClaim).
  def verify_claim(claim, pcactn, signer_public, server_now = nil, window_policy = nil)
    now = opt_num?(server_now) ? server_now : (Time.now.to_f * 1000)
    policy = window_policy || DEFAULT_WINDOW_POLICY
    check = claim_check(claim, hash_canonical(pcactn), signer_public, now, policy)
    reason = case check
             when 'ok' then return { 'ok' => true }
             when 'malformed' then 'malformed claim'
             when 'irreversible' then 'irreversible action is ineligible for the optimistic path'
             when 'digest' then 'claim does not cover this PCActn'
             when 'claimed_r' then 'claimed_r is not finite'
             when 'window' then opt_validate_window(claim['issued_at'], claim['challenge_window_ms'], now, policy)
             else 'claim signature does not verify'
             end
    { 'ok' => false, 'reason' => reason }
  end

  # Last instant (epoch ms) a challenge is accepted: issued_at + challenge_window_ms.
  def challenge_window_end(claim)
    claim['issued_at'] + claim['challenge_window_ms']
  end

  # True while challenges are accepted (inclusive end).
  def within_challenge_window(claim, now)
    opt_num?(now) && now <= challenge_window_end(claim)
  end

  # 'open' while challenges are accepted, else 'finalized'.
  def claim_status(claim, now)
    # 'finalized' opens settlement: a clock or window that is not a finite time is refused, never read as closed
    raise RangeError, 'claimStatus: the clock and the challenge window must be finite times' unless opt_num?(now) && opt_num?(challenge_window_end(claim))

    within_challenge_window(claim, now) ? 'open' : 'finalized'
  end

  # First failing wire check of a fraud proof: malformed, digest, bond, claimed_r, kind, consistency; else 'ok'.
  def fraud_proof_wire_check(claim, proof)
    return 'malformed' unless proof.is_a?(Hash) && claim.is_a?(Hash)

    d = proof['decision']
    unless d.is_a?(Hash) && [true, false].include?(d['releaseGuardianShare']) && [true, false].include?(d['optimisticAllowed']) &&
           opt_num?(d['r'])
      return 'malformed'
    end
    return 'malformed' unless %w[pcactn_digest bond_ref reason].all? { |k| proof[k].is_a?(String) }
    return 'digest' unless opt_same?(proof['pcactn_digest'], opt_get(claim, 'pcactn_digest'))
    return 'bond' unless opt_same?(proof['bond_ref'], opt_get(claim, 'bond_ref'))
    return 'claimed_r' unless opt_same?(opt_get(proof, 'claimed_r'), opt_get(claim, 'claimed_r'))

    kind = proof['kind']
    return 'kind' unless kind.is_a?(String) && FRAUD_KINDS.include?(kind)

    m = proof['r_margin']
    margin = opt_num?(m) ? [0, m].max : DEFAULT_R_MARGIN
    ev = proof['evidence']
    ev = ev.is_a?(Hash) ? ev['action'] : nil
    ev = ev.is_a?(Hash) ? ev['action'] : nil
    ev_class = ev.is_a?(Hash) ? ev['reversibility_class'] : nil
    rel = d['releaseGuardianShare']
    allowed = d['optimisticAllowed']
    holds = case kind
            when 'irreversible' then claim['reversibility_class'] == IRREVERSIBLE_CLASS || ev_class == IRREVERSIBLE_CLASS
            when 'policy-denied' then !rel
            when 'optimistic-not-allowed' then rel && !allowed
            else rel && allowed && d['r'] > claim['claimed_r'] + margin
            end
    holds ? 'ok' : 'consistency'
  rescue StandardError, SystemStackError
    'malformed'
  end

  def opt_nonempty?(x)
    x.is_a?(String) && !x.empty?
  end

  def opt_nonneg?(x)
    opt_num?(x) && x >= 0
  end

  # First failing check of a settlement record: malformed, suite, shape, split, signature; else 'ok'.
  # A PQ half verifies only under `pins[guardian_public]`; a suite this runtime lacks answers `suite` (never accepted).
  def settlement_wire_check(record, guardian_public, pins = nil)
    return 'malformed' unless record.is_a?(Hash)
    return 'suite' if record.key?('alg') && !IntentV2.implemented_suite?(record['alg'])

    r = record
    slash = r['action'] == 'slash'
    ev = r['evidenceDigest']
    bad_shape =
      !opt_nonempty?(r['claimId']) || !%w[open release slash].include?(r['action']) ||
      !opt_num?(r['amount']) || r['amount'] <= 0 ||
      !opt_nonempty?(r['from']) || !opt_nonempty?(r['to']) || !opt_num?(r['at']) ||
      !ev.is_a?(String) || (slash ? ev.empty? : ev != '') ||
      (slash ? !r['split'].is_a?(Hash) : r.key?('split')) ||
      !r['sig'].is_a?(String) ||
      (r.key?('guardian_epoch') && !(safe_int?(r['guardian_epoch']) && r['guardian_epoch'] >= 0))
    return 'shape' if bad_shape

    if slash
      sp = r['split']
      ca = opt_get(sp, 'challengerAccount')
      c = sp['challengerReward']
      v = sp['victimCompensation']
      t = sp['treasuryRemainder']
      ok = opt_same?(sp['amount'], r['amount']) && opt_nonneg?(c) && opt_nonneg?(v) && opt_nonneg?(t) &&
           (c + v) + t == r['amount'] && opt_nonempty?(sp['victimAccount']) && opt_same?(sp['treasuryAccount'], r['to']) &&
           (ca.nil? ? (c.zero? && v.zero? && t == r['amount']) : opt_nonempty?(ca))
      return 'split' unless ok
    end
    body = r.reject { |k, _| %w[sig pq_sig].include?(k) }
    msg = OPTIMISTIC_SETTLEMENT_DOMAIN.b + canonical_bytes_lenient(body)
    IntentV2.verify_pinned_suite(ledger_m(r, 'alg'), guardian_public, ledger_m(r, 'pq_pk'), msg, r['sig'], ledger_m(r, 'pq_sig'), pins) ? 'ok' : 'signature'
  rescue StandardError, SystemStackError
    'malformed'
  end
end
