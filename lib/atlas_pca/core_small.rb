# frozen_string_literal: true

# Small public helpers and constants of the reference core that the other modules do not carry: the params digest of "no params",
# the policy template version, the trait lattice bounds, the risk-policy validator, the catalog-derived risk inputs, the revocation
# exposure bound, the replay-state key of a holder's counter stream, the `intent` wire validator, the v2 session goal parser, the
# provenance discharge body, the attestation-backed runtime trust and the site's signed `intent_required`. Shapes are the SDK's own:
# String-keyed Hashes, JSON numbers as Integer / Float.
require 'digest'

module AtlasPca
  # hash_canonical({}): what a plan node or PCActn that omits `params_digest` commits to.
  EMPTY_PARAMS_DIGEST = AtlasPca.params_digest.freeze
  # The version member every policy template and overlay carries.
  TEMPLATE_VERSION = 1

  module Actions
    # The upper bounds of the trait profile lattice: risk tier and escalation tier are integers in 0..3.
    RISK_MAX = 3
    ESC_MAX = 3
  end

  module_function

  # nil when the risk policy is well-formed, else the reason.
  def validate_risk_policy(pol)
    return 'risk_policy must be an object' unless pol.is_a?(Hash) || pol.is_a?(Array)

    pol = {} if pol.is_a?(Array) # an array is an object in the reference: every member reads as undefined
    w = pol['weights']
    return 'risk_policy.weights missing' unless w.is_a?(Hash) || w.is_a?(Array)

    w = {} if w.is_a?(Array)
    Risk::WEIGHT_KEYS.each do |k|
      return "risk_policy.weights.#{k} must be finite and >= 0" unless Risk.fin?(w[k]) && w[k] >= 0
    end
    %w[theta1 theta2 kappa lambda rho bMax].each { |k| return "risk_policy.#{k} must be finite" unless Risk.fin?(pol[k]) }
    return 'risk_policy requires 0 <= theta1 <= theta2' if pol['theta1'].negative? || pol['theta2'] < pol['theta1']
    return 'risk_policy.kappa must be > 0' unless pol['kappa'].positive?
    return 'risk_policy lambda/rho/bMax must be >= 0' if pol['lambda'].negative? || pol['rho'].negative? || pol['bMax'].negative?

    nil
  end

  # Server-side risk inputs from the connector action catalog: the verb's reversibility score and blast radius, and for a
  # money-moving verb the blast radius amount / kappa from the operation's amount and the grant's signed risk policy. Never reads
  # anything the agent claims. An unknown verb answers {} (every input is then priced at the worst case). A money verb whose amount
  # is not a finite number >= 0, or whose grant has no positive kappa, gets blast radius 1. `catalog` is an Array of action specs
  # (default: BUILTIN_ACTIONS); `taint` a server-observed taint in [0, 1].
  def catalog_risk(verb, params, grant, taint: nil, catalog: nil)
    spec = (catalog || BUILTIN_ACTIONS).find { |s| s['verb'] == verb }
    return {} if spec.nil?

    unit = ->(x) { [1, [0, x].max].min }
    reversibility = CATALOG_REVERSIBILITY_SCORE.fetch(spec['reversibility'], 0)
    blast = unit.call(spec['blastRadius'])
    if spec.key?('amountField')
      amount = params.is_a?(Hash) && params.key?(spec['amountField']) ? params[spec['amountField']] : nil
      env = read_envelope(grant)
      pol = env.is_a?(Hash) ? env['risk_policy'] : nil
      kappa = pol.is_a?(Hash) ? pol['kappa'] : nil
      blast = Risk.fin?(amount) && amount >= 0 && Risk.fin?(kappa) && kappa.positive? ? unit.call(amount.to_f / kappa) : 1
    end
    out = { 'reversibility' => reversibility, 'blastRadius' => blast, 'confidence' => 1 }
    out['taint'] = unit.call(taint) if Risk.fin?(taint)
    out
  end

  # The last instant an action verified at `now` can still rely on a revocation epoch that predates a revocation at `t_revoked`:
  # t_revoked + max_age_ms + skew_ms.
  def revocation_exposure_end(t_revoked, max_age_ms, skew_ms = 60_000) = t_revoked + max_age_ms + skew_ms

  # The store key of a holder's counter stream. `scope` 'grant-holder' | 'audience-grant-holder' (default: audience-scoped whenever
  # an audience is given).
  def pca_state_key(grant_id, leaf_holder, scope = nil, audience = nil)
    scope ||= audience.nil? ? 'grant-holder' : 'audience-grant-holder'
    return "#{grant_id}:#{leaf_holder}" unless scope == 'audience-grant-holder'

    "aud:#{Js.encode_uri_component(audience.nil? ? '' : audience)}:#{grant_id}:#{leaf_holder}"
  end

  # Wire validation of the `intent` slot: nil when well-formed, else the reason. A -0 is never a wire integer.
  def validate_intent_wire(v)
    if v.is_a?(Hash)
      v = v.dup
      %w[fidelity_ppm residual_risk_ppm].each { |k| v[k] = -1 if v[k].is_a?(Float) && v[k].zero? && (1.0 / v[k]).negative? }
    end
    intent_wire_error(v)
  end

  # {'session', 'mapDigest'} of a `pca-intent:v2:<session>:<map_digest>` goal (both canonical 32-byte base64url), else nil.
  def parse_intent_goal_v2(goal)
    return nil unless goal.is_a?(String) && goal.start_with?(INTENT_GOAL_V2_PREFIX)

    parts = goal[INTENT_GOAL_V2_PREFIX.length..].split(':', -1)
    return nil unless parts.length == 2 && b32?(parts[0]) && b32?(parts[1])

    { 'session' => parts[0], 'mapDigest' => parts[1] }
  end

  # The unsigned discharge body an `artifact` verifier signs after a passing provenance_gate: the request's binding and the gate's
  # claims. Raises when the gate refused (no discharge without a verified provenance) or ttl_ms exceeds what the caveat accepts.
  # `t` = {'iat', 'ttl_ms', 'nonce'}.
  def provenance_discharge_body(request, gate, t)
    ok = gate.key?(:ok) ? gate[:ok] : gate['ok']
    raise ArgumentError, "provenanceDischargeBody: the provenance gate refused (#{gate.key?(:code) ? gate[:code] : gate['code']})" unless ok
    raise ArgumentError, 'provenanceDischargeBody: ttl_ms exceeds what the caveat accepts' if t['ttl_ms'] > request['ttl_ms']

    body = { 'v' => 1, 'kind' => 'pca-discharge', 'caveat_id' => request['caveat_id'], 'issuer' => request['issuer'],
             'cap_hash' => request['cap_hash'], 'bind' => request['bind'] }
    body['action_digest'] = request['action_digest'] unless request['action_digest'].nil?
    body.merge('claims' => gate.key?(:claims) ? gate[:claims] : gate['claims'], 'iat' => t['iat'], 'not_after' => t['iat'] + t['ttl_ms'], 'nonce' => t['nonce'])
  end

  # The site's signed `pca-intent-required` for a visited uncertain cell: intent_required_body(i) signed with sign_intent_required.
  def signed_intent_required(input, kid, site, alg: nil, pq: nil)
    sign_intent_required(IntentJit.intent_required_body(input), kid, site, alg: alg, pq: pq)
  end

  module Sandbox
    module_function

    # Runs an attestation verifier over the evidence; only when it answers ok AND bound is the evidence digest admitted into the
    # trust. Anything else (a raise, a malformed answer, not bound) leaves the list empty, so every claim is 'none'. `o`:
    # {'document', 'verifier' (#verify(document, expected, now_ms) -> {ok, bound}), 'expected', 'now_ms', 'pinned_attestors',
    # 'passport_digest'}. The result is the trust verified_runtime_class takes.
    def trust_from_attestation(o)
      ok = begin
        h = o['verifier'].verify(o['document'], o['expected'], o['now_ms'])
        h = h.transform_keys(&:to_s) if h.is_a?(Hash)
        h.is_a?(Hash) && h['ok'] == true && h['bound'] == true
      rescue StandardError, ScriptError, SecurityError, SystemStackError
        false
      end
      { 'pinnedAttestors' => o['pinned_attestors'], 'passportDigest' => o['passport_digest'],
        'verifiedEvidenceDigests' => ok ? [evidence_digest(o['document'])] : [], 'now' => o['now_ms'] }
    end
  end
end
