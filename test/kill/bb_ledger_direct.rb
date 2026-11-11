# frozen_string_literal: true
# Fail-closed checks that the public entry points pre-empt (decide_intent_v2 refuses the context first): each is pinned by a
# direct call here instead of a ledger entry, so a regression in the helper itself is caught even if the caller's check moves.
module MutationKill
  t('intent_v2 context helpers refuse a non-object session / accumulator context, exactly') do
    v = AtlasPca::IntentV2
    [5, 'x', [], nil].all? do |bad|
      v.session_ctx_error({ 'session' => bad }) == 'the session context must be an object' &&
        v.acc_ctx_error({ 'acc' => bad }) == 'the accumulator context must be an object'
    end && v.session_ctx_error({ 'session' => {} }).nil? && v.acc_ctx_error({ 'acc' => {} }).nil?
  end

  t('intent_v2 session_step refuses a misconfigured max_revocation_age_s before anything else') do
    v = AtlasPca::IntentV2
    want = { 'ok' => false, 'reason' => 'session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)' }
    [-1, 1.5, '5', nil, 2**53].all? do |age|
      v.session_step({}, {}, { 'policy' => { 'session' => { 'max_revocation_age_s' => age } } }, 0) == want
    end && v.session_step({}, {}, { 'policy' => { 'session' => { 'max_revocation_age_s' => 0 } } }, 0) != want
  end
end
