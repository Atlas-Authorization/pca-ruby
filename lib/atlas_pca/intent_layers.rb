# frozen_string_literal: true

# LAYERED INTENT, the verifier side (Intent Layer v2 s2.4, s3.5, s5 check `layers`; milestone V5; T18). Port of
# packages/pca/src/intent-layers.ts (the TypeScript is authoritative).
#
# Layers are predicate sets: G^org (org / operator ceiling), G^site (the site's own policy), G^std (the principal's
# standing profile rules) and G^task (G^task_0 and the principal-signed deltas D_1 ... D_k). DENY ANYWHERE WINS: an action
# outside a ceiling is denied with reason `ceiling` and is NEVER a question. Every layer is evaluated by the ONE predicate
# evaluator (evaluate_predicates) with the same action context as the admitting root's predicates. An ABSENT layer is no
# constraint; a layer PRESENT with JSON null or any value that is not {predicates: [...]} is MALFORMED and fails closed
# (README "absent vs null"): never read as "no constraint".
module AtlasPca
  LAYER_CEILINGS = %w[org site std].freeze

  module IntentLayers
    module_function

    GRANT_MEMBERS = %w[org site std task denied].freeze

    # Every own key of `o` is in `allowed` (closed member set).
    def closed_to?(o, allowed)
      o.keys.all? { |k| allowed.include?(k) }
    end

    # A well-formed layer: a plain object (Hash) with exactly one member, `predicates`, an array (closed member set).
    def layer_policy?(l)
      l.is_a?(Hash) && closed_to?(l, ['predicates']) && l.key?('predicates') && l['predicates'].is_a?(Array)
    end

    def ceilings_of(layers, ctx)
      unless layers.is_a?(Hash)
        return { 'status' => 'fail', 'layer' => 'org', 'reason' => 'layers: the layers member is malformed (not an object)' }
      end

      LAYER_CEILINGS.each do |k|
        next unless layers.key?(k) # absent: no constraint

        layer = layers[k]
        unless layer_policy?(layer)
          return { 'status' => 'fail', 'layer' => k,
                   'reason' => "layers: the #{k} ceiling is malformed (null or not {predicates: [...]})" }
        end
        next if layer_admits?(layer, ctx)

        return { 'status' => 'fail', 'layer' => k,
                 'reason' => "layers: the action is outside the #{k} ceiling (a ceiling is never a question)" }
      end
      { 'status' => 'pass' }
    rescue StandardError, SystemStackError => e
      { 'status' => 'fail', 'layer' => 'org', 'reason' => "layers: evaluation error (fail closed): #{e.message}" }
    end

    def layer_admits?(layer, ctx)
      AtlasPca.evaluate_predicates(layer['predicates'], ctx)['allowed'] == true
    end
  end

  module_function

  # The `layers` check of the v2 verification order: the action must be inside G^org, then G^site, then G^std (absent =
  # no constraint). The first ceiling that denies is named. `layers` must be a plain object with no member other than org,
  # site, std (an unknown member fails, reported as org); a layer is exactly {predicates: [...]}; a ceiling present with
  # null or any other value is malformed and fails (named), as does an empty predicate list (it admits nothing). Returns {"status"=>"pass"} or {"status"=>"fail", "layer"=>k, "reason"=>s}. Never raises.
  def is_layer_policy(l) # rubocop:disable Naming/PredicateName
    IntentLayers.layer_policy?(l)
  end

  def decide_layer_ceilings(layers, ctx)
    if layers.is_a?(Hash) && !IntentLayers.closed_to?(layers, LAYER_CEILINGS)
      return { 'status' => 'fail', 'layer' => 'org', 'reason' => 'layers: unknown member (the layers object is {org?, site?, std?})' }
    end

    IntentLayers.ceilings_of(layers, ctx)
  end

  # The full layer decision for one action, in order:
  #   1. outside G^org, then G^site, then G^std (or a malformed ceiling / layers value) -> {"decision"=>"ceiling", "layer"=>k};
  #   2. inside a denied region (veto, p = 0) -> {"decision"=>"intent_denied"};
  #   3. inside G^task_0 or some delta -> {"decision"=>"admit", "by"=>i} (0 for G^task_0, k for D_k);
  #   4. otherwise -> {"decision"=>"intent_required"}.
  # A grant member other than org / site / std / task / denied is malformed: intent_denied (checked first). A `denied`
  # member that is present but not an array, a `task` member that is not an array (it is required), or any of
  # their entries that is not {predicates: [...]}, is malformed and yields intent_denied. Absent `denied` = []. Never raises.
  def decide_layers(g, ctx)
    return { 'decision' => 'intent_denied' } if g.is_a?(Hash) && !IntentLayers.closed_to?(g, IntentLayers::GRANT_MEMBERS)

    c = IntentLayers.ceilings_of(g, ctx)
    return { 'decision' => 'ceiling', 'layer' => c['layer'] } if c['status'] == 'fail'

    denied = g.key?('denied') ? g['denied'] : []
    task = g.key?('task') ? g['task'] : nil
    unless denied.is_a?(Array) && denied.all? { |d| IntentLayers.layer_policy?(d) } &&
           task.is_a?(Array) && task.all? { |t| IntentLayers.layer_policy?(t) }
      return { 'decision' => 'intent_denied' }
    end

    denied.each { |d| return { 'decision' => 'intent_denied' } if IntentLayers.layer_admits?(d, ctx) }
    task.each_with_index { |t, i| return { 'decision' => 'admit', 'by' => i } if IntentLayers.layer_admits?(t, ctx) }
    { 'decision' => 'intent_required' }
  rescue StandardError, SystemStackError
    { 'decision' => 'intent_denied' }
  end
end
