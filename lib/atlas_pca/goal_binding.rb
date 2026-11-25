# frozen_string_literal: true

require 'digest'
require 'openssl'
require_relative 'decision'

module AtlasPca
  # Decision-to-effect binding and the claimed-fidelity gate (the TypeScript reference is @atlasauth/pca-goal `binding`).
  module GoalBinding
    module_function

    # Digest of exactly the action that was decided: verb, resource and every parameter.
    def action_digest(a) = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/goal-action/v1', 'act' => a })

    def bind_decision(a, decision) = { 'decision' => decision, 'action_digest' => action_digest(a) }

    def ct_eq(x, y) = x.bytesize == y.bytesize && OpenSSL.fixed_length_secure_compare(x.b, y.b)

    # True only for an `allow` bound to exactly this action (swapped params or verb, escalate, deny all refuse). Total.
    def guard_execute(b, executed)
      return false unless b['decision'] == 'allow'

      x = b['action_digest']
      return false unless x.is_a?(String)

      ct_eq(x, action_digest(executed))
    rescue StandardError
      false
    end

    # An agent-claimed fidelity never moves the outcome; only a replayed fidelity below the minimum can, only downward
    # (escalate); a NaN or non-numeric replay is unconfirmed and tightens. A nil replay is the reference's undefined.
    def claim_gate(base, min_ppm, _claimed_ppm = nil, replayed_ppm = nil)
      return base if replayed_ppm.nil?

      ok = replayed_ppm.is_a?(Numeric) && min_ppm.is_a?(Numeric) && replayed_ppm >= min_ppm
      ok ? base : AtlasPca.tighten(base, 'escalate')
    end

    # Hiding goal commitment (goal binding v3): sha256("pca-goal:v3:commit:<goal>:<policy>:<salt>"), base64url.
    def goal_commit(goal_digest, policy_digest, salt)
      AtlasPca.b64e(Digest::SHA256.digest(AtlasPca::Js.utf8("pca-goal:v3:commit:#{goal_digest}:#{policy_digest}:#{salt}")))
    end

    # Constant-time check that `commit` opens to (goal, policy, salt).
    def open_commit(commit, goal_digest, policy_digest, salt)
      raise TypeError, 'commit must be a string' unless commit.is_a?(String)

      ct_eq(commit, goal_commit(goal_digest, policy_digest, salt))
    end
  end
end
