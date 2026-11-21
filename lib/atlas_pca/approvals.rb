# frozen_string_literal: true

module AtlasPca
  # The approval / step-up model (the reference's `approvals`): the HEADLESS core an approval inbox renders. Given an intended action it
  # decides whether the action auto-admits, is a hard deny, or needs a human, and for a step-up produces a request carrying the goal
  # lineage, the risk tier and a stable id; plus batching, standing "approve this class for N hours" approvals that downgrade a matching
  # step-up to auto, the human co-sign that recharges the trust budget, and time-boxing a grant. Pure and offline: it composes the agent
  # handle's non-authoritative `dry_run` with the budget algebra and signs nothing except `time_box`. Requests, lineages and reviews are
  # String-keyed Hashes with the reference's member names (goalCommit, renderDigest, requestedAt, ...).
  module_function

  def approval_format_limit(limit)
    base = limit['unit'] == 'usd' ? "$#{GoalJs.js_str(limit['amount'])}" : GoalJs.js_str(limit['amount'])
    return base if limit['periodMs'].nil?

    hours = limit['periodMs'] / 3_600_000.0
    period = if (hours % 24).zero? && hours >= 24 then "#{GoalJs.js_str(hours / 24)}d"
             elsif hours >= 1 then "#{GoalJs.js_str(hours)}h"
             else "#{(limit['periodMs'] / 60_000.0 + 0.5).floor}m"
             end
    "#{base}/#{period}"
  end

  def approval_summarize_params(params, amount_field)
    return nil if params.nil?
    return "#{amount_field}=#{GoalJs.js_str(params[amount_field])}" if !amount_field.nil? && !params[amount_field].nil?
    return nil if params.empty?

    params.first(4).map { |k, v| "#{k}=#{v.is_a?(Hash) || v.is_a?(Array) || v.nil? ? Js.json(v) : GoalJs.js_str(v)}" }.join(', ')
  end

  # The goal lineage of one intended action ("you approved X because you asked to Y"): the grant's committed goal, the delegated authority
  # that admits this verb and its limit, and the action; `goal_verified` says whether a revealed plaintext goal opens the commitment, so the
  # inbox can show "unverified" rather than lie. `agent` is an AgentHandle. Pure.
  def build_goal_lineage(agent, verb, resource, params = nil, goal: nil)
    goal_commit = read_envelope(agent.grant)&.dig('goal_commit') || ''
    salt = agent.goal_salt
    verified = !goal.nil? && goal_commit != '' && salt.is_a?(String) && !salt.empty? ? verify_goal_commit(goal_commit, goal, salt) : false
    spec = agent.policy['actions'].find { |s| s['verb'] == verb }
    limit = agent.policy['limits'][verb]
    goal_label = goal.nil? ? 'Pursue the grant’s committed goal' : "Pursue the goal: “#{goal}”"
    goal_detail = if !goal.nil?
                    verified ? 'verified: this goal opens the signed grant commitment' : 'unverified: the revealed goal does not open the grant commitment'
                  elsif goal_commit != ''
                    "committed as #{goal_commit}"
                  end
    authority = "Delegated authority to #{verb}#{limit ? " (up to #{approval_format_limit(limit)})" : ''}"
    action_detail = approval_summarize_params(params, spec && spec['amountField'])
    g = { 'kind' => 'goal', 'label' => goal_label }
    g['detail'] = goal_detail unless goal_detail.nil?
    a = { 'kind' => 'authority', 'label' => authority }
    a['detail'] = spec['description'] if spec && Js.truthy?(spec['description'])
    act = { 'kind' => 'action', 'label' => "#{verb} #{resource}" }
    act['detail'] = action_detail unless action_detail.nil?
    because = goal.nil? ? "Approving #{verb} on #{resource}, authorized under the grant’s committed goal." : "Approving #{verb} on #{resource} because you asked to “#{goal}”."
    out = {}
    out['goal'] = goal unless goal.nil?
    out.merge('goalCommit' => goal_commit, 'goalVerified' => verified, 'chain' => [g, a, act], 'because' => because)
  end

  def approval_risk_for_review(agent, verb, params)
    spec = agent.policy['actions'].find { |s| s['verb'] == verb }
    if agent.policy['budgetModel'] == 'dollars' && spec && spec['amountField']
      amt = GoalJs.to_number((params || {})[spec['amountField']])
      kappa = agent.policy['riskPolicy']['kappa']
      return [0, [1, amt / kappa].min].max if amt.finite? && kappa.positive?
    end
    [0, [1, spec ? spec['blastRadius'] : 0.8].min].max
  end

  # Review an intended action against the agent's grant: {'kind' => 'auto'} (no human needed), {'kind' => 'deny', 'reason'} (the grant's
  # predicates / caveats forbid it) or {'kind' => 'step_up', 'request'} (admissible but needs a tier 2 / 3 co-sign, unless a standing class
  # approval covers it). Options: now, goal, standing (ClassApprovals), renderer (->(verb, resource, params) { render }: with it every step-up
  # carries `render` + `renderDigest`; one that raises makes the review a deny) and insecure_unbound_approval (documented insecure opt-out of
  # the render requirement).
  def review_action(agent, verb, resource, params = nil, now: nil, goal: nil, standing: nil, renderer: nil, insecure_unbound_approval: false)
    now ||= now_ms
    dr = agent.dry_run(verb, resource, params, now: now)
    return { 'kind' => 'deny', 'reason' => dr['reason'] || 'denied by policy' } unless dr['allowed']
    return { 'kind' => 'auto' } if dr['t'] == 1 || dr['t'].nil?
    return { 'kind' => 'auto' } if standing && covered_by_any?(standing, verb, resource, now)

    tier = dr['t']
    if renderer.nil? && insecure_unbound_approval != true
      return { 'kind' => 'deny', 'reason' => 'approval render required: pass a renderer (renderers_from_defs from the pinned action definitions), or insecure_unbound_approval: true' }
    end
    render = render_digest = nil
    unless renderer.nil?
      begin
        render = renderer.call(verb, resource, params)
        render_digest = approval_render_digest(render)
      rescue StandardError => e
        return { 'kind' => 'deny', 'reason' => "approval render failed (fail closed): #{e.message}" }
      end
    end
    goal_commit = read_envelope(agent.grant)&.dig('goal_commit') || ''
    request = { 'id' => hash_canonical({ 'd' => 'atlas-pca/stepup/v1', 'verb' => verb, 'resource' => resource, 'params' => params, 'at' => now }),
                'verb' => verb, 'resource' => resource }
    request['params'] = params unless params.nil?
    request.merge!('tier' => tier, 'reason' => dr['reason'] || "requires tier #{tier} co-sign", 'goalCommit' => goal_commit)
    request['goal'] = goal unless goal.nil?
    request.merge!('lineage' => build_goal_lineage(agent, verb, resource, params, goal: goal), 'r' => approval_risk_for_review(agent, verb, params), 'requestedAt' => now)
    request.merge!('render' => render, 'renderDigest' => render_digest) unless render.nil? || render_digest.nil?
    { 'kind' => 'step_up', 'request' => request }
  end

  # Review a batch of intended actions ([{'verb', 'resource', 'params'?}], the inbox's "N actions waiting").
  def batch_review(agent, calls, **opts) = calls.map { |c| review_action(agent, c['verb'], c['resource'], c['params'], **opts) }

  # Just the step-up requests of a batch of reviews (what the approver actually sees).
  def pending_requests(reviews) = reviews.select { |r| r['kind'] == 'step_up' }.map { |r| r['request'] }

  # Mint a standing class approval ("approve stripe.refund + gmail.send for the next 4 hours").
  def approve_class(verbs, ttl_ms:, by:, now: nil, resource: nil)
    granted_at = now || now_ms
    out = { 'id' => hash_canonical({ 'd' => 'atlas-pca/class-approval/v1', 'verbs' => verbs.sort { |a, b| V2JS.compare_utf8(a, b) }, 'resource' => resource, 'grantedAt' => granted_at, 'by' => by }),
            'verbs' => verbs.dup }
    out['resource'] = resource unless resource.nil?
    out.merge('grantedAt' => granted_at, 'ttlMs' => ttl_ms, 'by' => by)
  end

  def approval_resource_matches?(pattern, resource)
    return true if pattern.nil? || pattern == '*'
    return resource.start_with?(pattern[0...-1]) if pattern.end_with?('*')

    pattern == resource
  end

  # Does this standing approval still cover (verb, resource) at `now`?
  def class_approval_covers?(a, verb, resource, now)
    return false unless [now, a['grantedAt'], a['ttlMs']].all? { |v| Js.num?(v) && v.to_f.finite? }
    return false if !(now >= a['grantedAt']) || !(now < a['grantedAt'] + a['ttlMs'])
    return false unless a['verbs'].include?(verb)

    approval_resource_matches?(a['resource'], resource)
  end

  # Is (verb, resource) covered by ANY active standing approval?
  def covered_by_any?(approvals, verb, resource, now) = approvals.any? { |a| class_approval_covers?(a, verb, resource, now) }

  # A human's decision on a request (pure data for the audit trail).
  def record_decision(request, decision, by, at = nil) = { 'requestId' => request['id'], 'decision' => decision, 'by' => by, 'at' => at || now_ms }

  # Apply a human co-sign to the trust budget: a partial recharge (rho per co-sign) by default, or a full recharge to bMax. This is the ONLY
  # thing that raises the budget, so the safety bound holds between two co-signs.
  def apply_cosign(budget, policy, now, full: false)
    full ? Risk.recharge_full(budget, policy['bMax'], now) : Risk.recharge(budget, policy['rho'], policy['bMax'], now)
  end

  # Narrow a capability to expire `ttl_ms` from `now` by appending an `expires` caveat signed by the holder (a KeyPair): caveats are
  # conjunctive and append-only, so this can only ever RESTRICT.
  def time_box(parent, holder_signer, ttl_ms, now = nil) = attenuate_cap(parent, [{ 'type' => 'expires', 'at' => (now || now_ms) + ttl_ms }], holder_signer)
end
