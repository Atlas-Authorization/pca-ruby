# frozen_string_literal: true

# The producer side of the optimistic fast-path: opening a signed bonded claim and filing a fraud proof against one. The wire
# verifiers (claim_check, fraud_proof_wire_check) and the adjudication (verify_fraud_proof) are in optimistic.rb and
# optimistic_adjudication.rb; a claim opened here passes claim_check under the signer's key, and a proof filed here passes
# fraud_proof_wire_check against the claim.
module AtlasPca
  module_function

  # Opens an optimistic claim for `pcactn`, signed by the agent-leaf `signer` (an AtlasPca::KeyPair). REFUSES (ArgumentError) when
  # the action is irreversible (those take the full threshold path) or the window is outside the policy. `challenge_window_ms`
  # defaults to the policy default (an explicit nil is refused), `issued_at` and `server_now` to the wall clock.
  def open_optimistic(pcactn, signer, bond_ref:, claimed_r:, challenge_window_ms: OPT_MISSING, issued_at: nil, server_now: nil, window_policy: nil)
    action = pcactn.is_a?(Hash) ? pcactn['action'] : nil
    rc = action.is_a?(Hash) ? action['reversibility_class'] : nil
    raise ArgumentError, 'openOptimistic: irreversible actions cannot use the optimistic fast-path (§9A)' if rc == IRREVERSIBLE_CLASS
    raise ArgumentError, 'openOptimistic: claimedR must be finite' unless opt_num?(claimed_r)

    policy = window_policy || DEFAULT_WINDOW_POLICY
    now = opt_num?(server_now) ? server_now : (Time.now.to_f * 1000).floor
    at = opt_num?(issued_at) ? issued_at : now
    window = challenge_window_ms.equal?(OPT_MISSING) ? policy['defaultWindowMs'] : challenge_window_ms
    bad = opt_validate_window(at, window, now, policy)
    raise ArgumentError, "openOptimistic: #{bad}" if bad

    body = { 'pcactn_digest' => pcactn_digest(pcactn), 'bond_ref' => bond_ref, 'claimed_r' => claimed_r,
             'reversibility_class' => rc.is_a?(String) ? rc : 'unknown', 'issued_at' => at, 'challenge_window_ms' => window }
    body.merge('sig' => b64e(signer.sign(OPTIMISTIC_CLAIM_DOMAIN.b + canonical_bytes_lenient(body))))
  end

  # Files a fraud proof against `claim` for `pcactn`: the policy VM is re-run on the frozen open-time snapshot `open_snapshot` under
  # `grant` (a caller-supplied decision is never trusted). nil for a compliant claim, a claim for another action or a missing
  # snapshot. The proof's kind is the first of irreversible, policy-denied, optimistic-not-allowed, risk-understated that holds.
  def file_fraud_proof(claim, pcactn, grant, open_snapshot, r_margin: nil)
    return nil unless open_snapshot.is_a?(Hash)

    o = OptimisticAdjudication
    actual = decide(open_snapshot.merge('grant' => grant))
    return nil if claim['pcactn_digest'] != pcactn_digest(pcactn)

    margin = opt_num?(r_margin) ? [0, r_margin].max : DEFAULT_R_MARGIN
    optimistic = actual['requiredThreshold']['optimisticAllowed']
    action = pcactn.is_a?(Hash) ? pcactn['action'] : nil
    action_class = action.is_a?(Hash) ? action['reversibility_class'] : nil
    claimed = claim['claimed_r']
    if claim['reversibility_class'] == IRREVERSIBLE_CLASS || action_class == IRREVERSIBLE_CLASS
      kind = 'irreversible'
      reason = 'irreversible action took the optimistic path'
    elsif !actual['releaseGuardianShare']
      kind = 'policy-denied'
      why = actual['reasons'].join('; ')
      reason = "Policy VM denied the action: #{why.empty? ? 'not compliant' : why}"
    elsif !optimistic
      kind = 'optimistic-not-allowed'
      reason = "optimistic path not allowed at real r=#{o.fixed3(actual['r'])} (t=#{o.num_s(actual['requiredThreshold']['t'])})"
    elsif actual['r'] > claimed + margin
      kind = 'risk-understated'
      reason = "claimed r=#{o.num_s(claimed)} but real r=#{o.fixed3(actual['r'])}"
    else
      return nil
    end
    { 'pcactn_digest' => claim['pcactn_digest'], 'bond_ref' => claim['bond_ref'], 'claimed_r' => claimed,
      'decision' => { 'releaseGuardianShare' => actual['releaseGuardianShare'], 'r' => actual['r'], 'optimisticAllowed' => optimistic },
      'evidence' => open_snapshot.reject { |k, _| k == 'grant' }, 'r_margin' => margin, 'kind' => kind, 'reason' => reason }
  end
end
