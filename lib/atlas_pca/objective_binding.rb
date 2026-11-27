# frozen_string_literal: true

# Binding of the objective-risk functional to the live decision path, without touching the signed PCActn. The facts live in the
# grant's signed envelope as an optional `objective_risk` member (covered by the root signature: tampering breaks the chain). A grant
# that commits nothing is unaffected (the caller falls back to the heuristic). The registry / resource graph / calibration set are
# instance-held config; their digests must equal the committed ones, or the result is a mismatch (deny unless the grant asks for
# the heuristic AND the instance opts in with allow_heuristic_fallback).
module AtlasPca
  module_function

  def ob_obj?(v) = v.is_a?(Hash)
  def ob_str?(v) = v.is_a?(String) && !v.empty?

  # Reads the committed `objective_risk` off a grant's envelope. {} = not committed, {'commitment' => ...} when well-formed,
  # {'malformed' => reason} otherwise. Pure and total.
  def read_objective_commitment(grant)
    env = read_envelope(grant)
    return {} unless env.is_a?(Hash) && env.key?('objective_risk')

    raw = env['objective_risk']
    return { 'malformed' => 'objective_risk: unsupported shape/version' } unless ob_obj?(raw) && raw['v'].is_a?(Numeric) && raw['v'] == 1

    emb = raw['embedder']
    unless ob_obj?(emb) && emb['scheme'] == 'native' && ob_str?(emb['model_id']) && ob_obj?(emb['config'])
      return { 'malformed' => 'objective_risk.embedder must be { scheme: "native", model_id, config }' }
    end
    return { 'malformed' => 'objective_risk.goal must be a goal commitment' } unless ob_obj?(raw['goal']) && ob_str?(raw['goal']['commit'])
    return { 'malformed' => 'objective_risk needs registry_digest and graph_digest' } unless ob_str?(raw['registry_digest']) && ob_str?(raw['graph_digest'])
    return { 'malformed' => 'objective_risk.calibration_digest must be a string' } if raw.key?('calibration_digest') && !ob_str?(raw['calibration_digest'])

    kinds = raw['authorized_kinds']
    return { 'malformed' => 'objective_risk.authorized_kinds must be string[]' } unless kinds.is_a?(Array) && kinds.all? { |k| k.is_a?(String) }
    return { 'malformed' => 'objective_risk.denominations must be an array' } if raw.key?('denominations') && !raw['denominations'].is_a?(Array)
    if raw.key?('on_mismatch') && !%w[deny heuristic].include?(raw['on_mismatch'])
      return { 'malformed' => 'objective_risk.on_mismatch must be "deny" or "heuristic"' }
    end

    { 'commitment' => raw }
  end

  # Resolves the objective risk inputs for `action` under `grant`. Total (never raises).
  #   nothing committed                        => {'mode' => 'none'} (heuristic, unchanged)
  #   committed and reproduced                 => {'mode' => 'objective', 'inputs', 'r', 'evidenceDigest'}
  #   committed but not reproducible / invalid => {'mode' => 'mismatch', 'reasons', 'onMismatch'} (default 'deny')
  # `instance` is the instance-held config {registry, graph, calibration, allow_heuristic_fallback}: the registry and graph in the
  # reference's config form ({'trusted_verifiers', 'entries'} and {'nodes', 'edges'}) or as ObjectiveRisk objects. `engine` is the
  # objective-risk functional; the default is ObjectiveRisk::Engine (atlas_pca/objective_risk.rb). A replacement is an object with
  #   embedder_model_id(config)           -> the model id of the native embedder built from the committed config
  #   calibration_digest(calibration)     -> the digest of a calibration set
  #   evaluate(action, opts)              -> {'valid', 'reasons'?, 'inputs'?, 'r'?, 'evidenceDigest'?}; opts carries the committed facts
  #                                          (authorized_kinds, scope, embedder, goal, commitments, denominations), the instance's raw
  #                                          registry / graph config, the grant's risk weights, taint, age and the calibration set
  def resolve_objective_risk(grant:, action:, instance:, engine: nil, taint: nil, age: nil)
    r = read_objective_commitment(grant)
    return { 'mode' => 'mismatch', 'reasons' => [r['malformed']], 'onMismatch' => 'deny' } if r['malformed']

    commitment = r['commitment']
    return { 'mode' => 'none' } if commitment.nil?

    engine ||= ObjectiveRisk::Engine
    inst = instance.is_a?(Hash) ? instance : nil
    # a GRANT cannot downgrade the verifier's objective risk to the heuristic on its own say-so
    on_mismatch = commitment['on_mismatch'] == 'heuristic' && inst && inst['allow_heuristic_fallback'] == true ? 'heuristic' : 'deny'
    miss = ->(*reasons) { { 'mode' => 'mismatch', 'reasons' => reasons, 'onMismatch' => on_mismatch } }
    begin
      env = read_envelope(grant)
      return miss.call('grant carries no valid envelope') if env.nil?
      return miss.call('the grant commits objective-risk facts but the instance holds no objective-risk config') if inst.nil?

      return miss.call('embedder model_id does not match the committed one') if engine.embedder_model_id(commitment['embedder']['config']) != commitment['embedder']['model_id']

      calibration = inst['calibration']
      if commitment.key?('calibration_digest') && (calibration.nil? || engine.calibration_digest(calibration) != commitment['calibration_digest'])
        return miss.call('calibration set does not match the committed digest')
      end

      commitments = { 'registryDigest' => commitment['registry_digest'], 'graphDigest' => commitment['graph_digest'] }
      commitments['calibrationDigest'] = commitment['calibration_digest'] if commitment.key?('calibration_digest')
      opts = { 'registry' => inst['registry'], 'graph' => inst['graph'], 'authorizedKinds' => commitment['authorized_kinds'], 'scope' => commitment['scope'],
               'embedder' => commitment['embedder'], 'goal' => commitment['goal'], 'commitments' => commitments,
               'denominations' => commitment['denominations'] || [], 'weights' => env['risk_policy']['weights'], 'taint' => taint.nil? ? 1 : taint,
               'age' => age.nil? ? 1 : age }
      opts['calibration'] = calibration if commitment.key?('calibration_digest') && calibration
      res = engine.evaluate(action, opts)
      return miss.call(*res['reasons']) unless res['valid']

      i = res['inputs']
      { 'mode' => 'objective', 'inputs' => { 'reversibility' => i['reversibility'], 'blastRadius' => i['blastRadius'], 'semanticDistance' => i['semanticDistance'] },
        'r' => res['r'], 'evidenceDigest' => res['evidenceDigest'] }
    rescue StandardError, ScriptError, SecurityError, SystemStackError => e
      miss.call("objective risk evaluation error (fail closed): #{e.message}")
    end
  end
end
