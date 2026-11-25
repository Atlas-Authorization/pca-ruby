# frozen_string_literal: true
# Exact-outcome kill tests for the verify_pcactn tail: the `fresh_at` consistency token against every shared fresh-at vector
# (wire shape, status, decision, reason), the v3 approved-goal binding and the `degraded` slot of an ordinary verdict.
module MutationKill
  module FreshAt
    module_function
    CONF = File.expand_path('../../conformance', __dir__)
    def doc = (@doc ||= AtlasPca.parse_json(File.read(File.join(CONF, 'fresh-at-vectors.json'), encoding: 'UTF-8'), loose: true))
  end

  t('verify_pcactn fresh_at: every shared vector (allow, core checks, fresh_at status, decision, reason), never degraded') do
    vs = FreshAt.doc['vectors']
    vs.length == 28 && vs.all? do |c|
      ctx = c['context']
      e = c['expect']
      v = AtlasPca.verify_pcactn(c['pcactn'], c['grant'], now: ctx['now'], audience: ctx['aud'], insecure_skip_plan_root_check: true, fresh_at: ctx['fresh_at'])
      status = v.checks.key?('fresh_at') ? (v.checks['fresh_at'] ? 'pass' : 'fail') : 'absent'
      decision = AtlasPca.decision_of({ 'allow' => v.allow, 'reasons' => v.reasons,
                                        'checks' => v.checks.transform_values { |ok| ok ? 'pass' : 'fail' } })
      got = { 'allow' => v.allow, 'checks' => v.checks.reject { |k, _| k == 'fresh_at' }, 'fresh_at' => status, 'decision' => decision }
      got == e.reject { |k, _| k == 'reason' } && v.degraded.nil? &&
        (!e['reason']&.start_with?('fresh_at:') || v.reason == e['reason'])
    end && vs.any? { |c| c['expect']['fresh_at'] == 'pass' } && vs.any? { |c| c['expect']['fresh_at'] == 'absent' }
  end

  t('verify_pcactn intent v3: an approved goal (String or Symbol keys) the root commitment does not open is refused, exactly') do
    i = Intent
    g = i.grant
    d = 'SyLciqqBtMB1cwXrNPGKnRkWRX8_IEuVGmd_htWGh2U'
    bound = i.pcactn(g, 'intent' => i.intent)
    want = "intent: the root grant's goal commitment does not open to the approved goal and compiled policy (v3)"
    [{ 'goal_digest' => d, 'policy_digest' => d }, { goal_digest: d, policy_digest: d }].all? do |ag|
      v = i.verify(bound, g, { 'approved_goal' => ag })
      v.allow == false && v.reason == want
    end && AtlasPca.approved_goal_ref?({ goal_digest: d, policy_digest: d }) && AtlasPca.approved_goal_ref?(5) == false &&
      AtlasPca.approved_goal_ref?({ 'goal_digest' => d }) == false &&
      (begin
        AtlasPca.intent_goal_v3({ 'goal_digest' => d })
        false
      rescue ArgumentError => e
        e.message == 'intent_goal_v3: goal_digest and policy_digest must be canonical base64url (32 bytes)'
      end) &&
      !AtlasPca.approved_goal_ref?({ goal_digest: d, 'goal_digest' => d }) && !AtlasPca.approved_goal_ref?({ 'goal_digest' => d, 'policy_digest' => 'x' })
  end
end
