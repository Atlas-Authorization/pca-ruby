# frozen_string_literal: true

require_relative 'agent'
require_relative 'intent_wb'

module AtlasPca
  # The one signer of the goal-to-decision flow (the TypeScript reference is @atlasauth/pca-goal `sign`): artifacts (approvals,
  # test sets, policy pins, precedents) signed with the suite-agile signer under a per-kind domain over STRICT canonical bytes.
  module GoalSign
    module_function

    # Domain separation: an artifact of one kind never verifies as another kind.
    def goal_domain(kind) = "atlas-pca/goal/#{kind}/v1\0"

    def kp(secret) = secret.is_a?(KeyPair) ? secret : KeyPair.new(secret)

    # The pinned public identity (b64u Ed25519) of a signer secret (a 32-byte seed or a KeyPair).
    def signer_id(secret) = kp(secret).public

    # Sign a flat artifact body (it must already carry its signer identity member). Raises on a non-canonical body.
    def sign_goal_artifact(kind, body, secret, alg: nil, pq: nil)
      AtlasPca.sign_artifact(goal_domain(kind), body, kp(secret), alg: alg, pq: pq)
    end

    # Verify against the caller's PINNED signers: the pin whose `pk` equals the artifact's own signer member must verify. Total.
    def verify_goal_artifact(kind, artifact, signer_field, pins)
      return false unless artifact.is_a?(Hash)
      return false unless AtlasPca.wb_artifact_suite_error(artifact).nil?

      who = artifact[signer_field]
      return false unless who.is_a?(String)

      pin = nil
      pins.each do |p|
        return false if p.nil? # a null pin makes the reference throw: refuse

        pk = p.is_a?(String) ? p : (p.is_a?(Hash) ? p['pk'] : nil)
        if pk == who
          pin = p
          break
        end
      end
      !pin.nil? && AtlasPca.wb_verify_artifact_sig(goal_domain(kind), artifact, pin) == true
    rescue StandardError
      false
    end

    # A payload wrapped with its kind and signer: the envelope used by tests, pins and precedents.
    def sign_payload(kind, payload, secret, alg: nil, pq: nil)
      sign_goal_artifact(kind, { 'v' => 1, 'kind' => kind, 'signer' => signer_id(secret), 'payload' => payload }, secret, alg: alg, pq: pq)
    end

    def verify_payload(s, kind, pins)
      return false unless s.is_a?(Hash)

      v = s['v']
      v.is_a?(Numeric) && v == 1 && s['kind'] == kind && verify_goal_artifact(kind, s, 'signer', pins)
    end
  end
end
