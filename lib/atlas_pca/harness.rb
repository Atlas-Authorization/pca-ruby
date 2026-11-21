# frozen_string_literal: true

require 'monitor'
require 'securerandom'
require_relative 'js_compat'
require_relative 'risk'

module AtlasPca
  # Attest the mediator, not the weights. The trusted computing base is this small orchestration harness, not an opaque model:
  # the model is an UNTRUSTED ORACLE that proposes a candidate action, and the harness enforces plan inclusion, the taint fold and
  # the trust budget before any candidate becomes a signed PCActn. The oracle holds no signing key. Mirrors the TypeScript
  # reference (@atlasauth/pca-harness), including the resource-server hook that admits an allowlisted harness measurement.
  module Harness
    # The ordered manifest of checks the harness enforces before signing; folded into the measurement.
    ENFORCED_CHECKS = %w[plan_inclusion_before_signing taint_provenance_fold trust_budget_debit pcactn_sign].freeze
    # Semantic version of the harness's policy-relevant surface. A bump changes the measurement.
    HARNESS_VERSION = '0.1.0'
    # The model id stamped into an emitted PCActn's attestation.model_id when attestation is enabled (the mediator, not an LLM).
    HARNESS_MODEL_ID = '@atlasauth/pca-harness'
    DEFAULT_BASE_RISK = { 'semanticDistance' => 0.1, 'reversibility' => 1, 'blastRadius' => 0.1, 'taint' => 0, 'confidence' => 1, 'age' => 0 }.freeze
    UNDEF = Object.new.freeze

    module_function

    # Pure self-measurement: base64url SHA-256 over the harness version, the enforced-checks manifest and the risk-policy identity
    # (weights, theta1, theta2, kappa). A policy missing one of those raises, as the reference's strict canonical form refuses an
    # undefined member.
    def compute_harness_measurement(version, enforced_checks, policy)
      raise TypeError, 'computeHarnessMeasurement: policy is not an object' unless policy.is_a?(Hash)

      rp = {}
      %w[weights theta1 theta2 kappa].each do |k|
        raise ArgumentError, 'canonicalize: unsupported type undefined' unless policy.key?(k)

        rp[k] = policy[k]
      end
      AtlasPca.hash_canonical({ 'harness' => HARNESS_MODEL_ID, 'version' => version, 'enforces' => enforced_checks, 'risk_policy' => rp })
    end

    def member(v, key) = v.is_a?(Hash) ? v.fetch(key, UNDEF) : UNDEF

    # The resource-server hook: ctx -> {'enforced', 'ok'?, 'reason'?} over ctx['pcactn']['attestation']. Fail closed: an empty
    # allowlist accepts nothing; an absent measurement fails unless `required` is false (then not enforced); a pinned
    # `expectedModelId` must match; a present measurement outside the allowlist ALWAYS fails. config: 'measurements' (allowlisted
    # measurement strings), 'required' (default true), 'expectedModelId' (true for the harness id, or a string).
    def create_harness_attestation_verifier(config)
      ms = config['measurements']
      allow = ms.is_a?(Array) ? ms.select { |m| m.is_a?(String) && !m.empty? } : []
      required = config['required'] != false
      em = config['expectedModelId']
      expected = em == true ? HARNESS_MODEL_ID : (em.is_a?(String) && !em.empty? ? em : nil)

      lambda do |ctx|
        if allow.empty?
          next({ 'enforced' => true, 'ok' => false, 'reason' => 'harness attestation configured with an empty measurement allowlist (fail closed)' })
        end

        att = member(member(ctx, 'pcactn'), 'attestation')
        m = member(att, 'measurement')
        measurement = m.is_a?(String) ? m : ''
        if measurement.empty?
          next({ 'enforced' => true, 'ok' => false, 'reason' => 'harness attestation required but the PCActn carries no harness measurement (fail closed)' }) if required

          next({ 'enforced' => false })
        end
        unless expected.nil?
          mid = member(att, 'model_id')
          if mid != expected
            shown = mid.equal?(UNDEF) ? 'undefined' : Js.string(mid)
            next({ 'enforced' => true, 'ok' => false, 'reason' => "attestation.model_id '#{shown}' is not the required harness identity '#{expected}'" })
          end
        end
        next({ 'enforced' => true, 'ok' => false, 'reason' => 'harness measurement is not in the allowlisted set (unattested or unknown mediator)' }) unless allow.include?(measurement)

        { 'enforced' => true, 'ok' => true }
      end
    end

    def fin?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite?)

    # Math.round: nearest integer, ties toward +Infinity
    def js_round(x)
      return x unless x.finite? # Math.round leaves NaN and the infinities as they are

      f = x.floor
      x - f >= 0.5 ? f + 1 : f
    end

    # Number.prototype.toFixed for the non-negative finite values the harness reports (exact decimal, ties round up)
    def to_fixed(x, digits)
      return Predicates.js_number_string(x) if !fin?(x) || x.abs >= 1e21

      n = ((x.to_r * (10**digits)) + Rational(1, 2)).floor
      s = n.to_s.rjust(digits + 1, '0')
      digits.zero? ? s : "#{s[0...-digits]}.#{s[-digits..]}"
    end

    def refuse(reason, detail) = { 'ok' => false, 'reason' => reason, 'detail' => detail }

    # The attested mediator: holds the principal's grant, the committed plan, the signing key and the trust budget, and wraps an
    # untrusted model oracle. #step is the ONLY path from an oracle proposal to a signed PCActn; it enforces plan inclusion, then
    # the taint fold, then the budget, then signs.
    #
    # grant: the principal-signed root capability; chain: the chain ending at the leaf (default [grant]); agent_secret: the 32-byte
    # Ed25519 seed of the leaf holder; plan: the committed plan nodes (non-empty); audience: the resource-server id; budget:
    # {'B', 'tau', 'asOf'}; policy: a risk policy (default DEFAULT_RISK_POLICY); base_risk: overrides of the base risk inputs;
    # now: a clock returning epoch ms; ttl_ms; measurement_manifest; nonce: a nonce supplier (default 16 random bytes as hex);
    # attestation: {'operator', 'epoch'?} to stamp this harness's self-measurement into every emitted PCActn.
    class Instance
      attr_reader :budget, :counter

      def initialize(grant:, agent_secret:, plan:, audience:, budget:, chain: nil, policy: nil, base_risk: nil, now: nil, ttl_ms: nil,
                     measurement_manifest: nil, nonce: nil, attestation: nil)
        raise ArgumentError, 'Harness: `audience` is required (the resource-server / instance id PCActns are for)' unless audience.is_a?(String) && !audience.empty?
        raise ArgumentError, 'Harness: `agent_secret` must be a 32-byte Ed25519 secret key' unless agent_secret.is_a?(String) && agent_secret.bytesize == 32
        raise ArgumentError, 'Harness: `plan` must be a non-empty array (an empty plan authorises nothing)' unless plan.is_a?(Array) && !plan.empty?
        raise ArgumentError, 'Harness: plan node ids must be unique' unless plan.map { |n| n['id'] }.uniq.length == plan.length

        unless budget.is_a?(Hash) && Harness.fin?(budget['B']) && budget['B'] >= 0 && Harness.fin?(budget['tau']) && Harness.fin?(budget['asOf'])
          raise ArgumentError, 'Harness: `budget` must have finite B >= 0, tau and asOf'
        end

        @grant = grant
        @chain = chain.nil? ? [grant] : chain
        @signer = KeyPair.new(agent_secret)
        @plan = plan
        @plan_index = plan.to_h { |n| [n['id'], n] }
        # commit the principal-authorised plan ONCE; every emitted action carries an inclusion proof under this root
        @committed = AtlasPca.commit_plan(plan)
        @audience = audience
        @policy = policy.nil? ? DEFAULT_RISK_POLICY : policy
        @base_risk = DEFAULT_BASE_RISK.merge(base_risk || {})
        @now = now || -> { (Time.now.to_f * 1000).to_i }
        @ttl_ms = ttl_ms
        @manifest = measurement_manifest.nil? ? ENFORCED_CHECKS : measurement_manifest
        @nonce = nonce || -> { SecureRandom.hex(16) }
        @attest = attestation
        @budget = budget
        @counter = 0
        @lock = Monitor.new
      end

      # The committed plan root the principal authorised.
      def plan_root = @committed['root']

      # What a remote attestation of the MEDIATOR would cover, in place of the unmeasurable model weights.
      def harness_measurement = Harness.compute_harness_measurement(HARNESS_VERSION, @manifest, @policy)

      # Ask the untrusted oracle (a callable) for a candidate {verb, resource, params?, nodeId, inputs?} and, only if it survives
      # the gate, emit a signed PCActn: {'ok' => true, 'pcactn', 'inclusionProof', 'risk', 'budget'}, or a refusal {'ok' => false,
      # 'reason' => 'out_of_plan' | 'over_budget' | 'bad_candidate', 'detail', 'requiredT'?, 'budget'?}. An oracle that raises, or
      # returns a malformed candidate, is a refusal, never an exception.
      def step(propose_action) = @lock.synchronize { do_step(propose_action) }

      private

      def do_step(propose_action)
        begin
          candidate = propose_action.call
        rescue StandardError => e # the oracle is a model call: any failure is a refusal
          return Harness.refuse('bad_candidate', "oracle failed: #{e.message}")
        end

        # (0) the oracle is untrusted: validate the shape before use
        unless candidate.is_a?(Hash) && candidate['nodeId'].is_a?(String) && candidate['verb'].is_a?(String) && candidate['resource'].is_a?(String)
          return Harness.refuse('bad_candidate', 'oracle returned a malformed candidate')
        end

        # (1) PLAN INCLUSION: reject out-of-plan BEFORE signing
        node = @plan_index[candidate['nodeId']]
        return Harness.refuse('out_of_plan', "node '#{candidate['nodeId']}' is not in the committed plan") if node.nil?

        if node['verb'] != candidate['verb'] || node['resource'] != candidate['resource']
          return Harness.refuse('out_of_plan', "action #{candidate['verb']} #{candidate['resource']} does not match committed node " \
                                               "'#{node['id']}' (#{js_s(node, 'verb')} #{js_s(node, 'resource')})")
        end
        inclusion_proof = @committed['proofs'][node['id']]

        # (2) TAINT FOLD: only a well-formed 'trusted' input is trusted; anything else counts as untrusted lineage
        return Harness.refuse('bad_candidate', 'candidate.inputs is not an array') if candidate.key?('inputs') && !candidate['inputs'].is_a?(Array)

        inputs = (candidate['inputs'] || []).map do |i|
          if i.is_a?(Hash) && i['provenance'] == 'trusted' && i['ref'].is_a?(String)
            { 'ref' => i['ref'], 'provenance' => 'trusted' }
          else
            ref = i.is_a?(Hash) ? i['ref'] : nil
            { 'ref' => ref.is_a?(String) ? ref : '', 'provenance' => 'untrusted' }
          end
        end
        taint = inputs.any? { |i| i['provenance'] == 'untrusted' } ? 1 : 0
        trusted_refs = inputs.select { |i| i['provenance'] == 'trusted' }.map { |i| i['ref'] }
        risk_inputs = @base_risk.merge('taint' => taint)
        # rounded to 6 d.p. so the reported r, the signed risk_claim.r and the budget cost agree and stay canonical
        r = Harness.js_round(Risk.risk_score(risk_inputs, @policy['weights']) * 1e6) / 1e6
        rt = Risk.required_threshold(r, @policy, irreversible: node['reversibility_class'] == 'irreversible')

        # (3) TRUST BUDGET: meter machine-only actions, leaking to now first
        now_ms = @now.call
        leaked = Risk.leak(@budget, now_ms, @policy['lambda'])
        c = Risk.cost(r, @policy['kappa'])
        if rt['t'] < 3 && !(Harness.fin?(leaked['B']) && leaked['B'] >= c)
          # the budget cannot cover even a low-risk in-plan action: escalate to a human, debit nothing, produce no PCActn
          @budget = leaked
          out = Harness.refuse('over_budget', "budget #{Harness.to_fixed(leaked['B'], 4)} < cost #{Harness.to_fixed(c, 4)}; step up to a human co-sign")
          out['requiredT'] = 3
          out['budget'] = leaked
          return out
        end

        # (4) SIGN
        provenance = { 'causal_hash' => AtlasPca.hash_canonical(inputs), 'taint_level' => taint, 'trusted_refs' => trusted_refs }
        extra = { 'nonce' => @nonce.call, 'provenance' => provenance, 'risk_claim' => { 'r' => r, 'inputs' => risk_inputs.dup } }
        unless @attest.nil?
          ep = @attest['epoch']
          extra['attestation'] = { 'quote_digest' => '', 'epoch' => ep.nil? ? 0 : ep, 'model_id' => HARNESS_MODEL_ID,
                                   'measurement' => harness_measurement, 'operator' => @attest['operator'] }
        end
        kw = {}
        kw[:ttl_ms] = @ttl_ms unless @ttl_ms.nil?
        begin
          pcactn = AtlasPca.build_pcactn(grant: @grant, chain: @chain, plan: @plan, node_id: node['id'], counter: @counter + 1, signer: @signer,
                                         aud: @audience, params: candidate['params'], iat: now_ms, extra: extra, **kw)
        rescue ArgumentError, TypeError, KeyError => e
          # e.g. params do not match the node's committed params_digest: still never emits an out-of-plan action
          msg = e.message.sub(/\Abuild_pcactn:/, 'buildPCActn:')
          return Harness.refuse('bad_candidate', "could not build PCActn: #{msg}")
        end

        # debit only a metered (machine-only, t < 3) action; commit the counter
        @budget = rt['t'] < 3 ? Risk.debit(leaked, c) : leaked
        @counter += 1
        { 'ok' => true, 'pcactn' => pcactn, 'inclusionProof' => inclusion_proof,
          'risk' => { 'r' => r, 'inputs' => risk_inputs, 'taint' => taint, 't' => rt['t'] }, 'budget' => @budget }
      end

      def js_s(node, key) = node.key?(key) ? Js.string(node[key]) : 'undefined'
    end
  end
end
