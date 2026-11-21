# frozen_string_literal: true

# Replays the TS-reference oracle of the intent statement, compiler pipeline, schema outcome space, provenance, classifier risk,
# trajectory lift, frame constraints and just-in-time elicitation pure parts (test-data/ref-intent-misc.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/intent_classifier'
require_relative '../lib/atlas_pca/intent_compilers'
require_relative '../lib/atlas_pca/intent_frames'
require_relative '../lib/atlas_pca/intent_jit'
require_relative '../lib/atlas_pca/intent_provenance'
require_relative '../lib/atlas_pca/intent_schema'
require_relative '../lib/atlas_pca/intent_statement'
require_relative '../lib/atlas_pca/intent_trajectory'
require 'minitest/autorun'

class TestRefIntentMisc < Minitest::Test
  CL = AtlasPca::IntentClassifier
  CO = AtlasPca::IntentCompilers
  FR = AtlasPca::IntentFrames
  JI = AtlasPca::IntentJit
  PV = AtlasPca::IntentProvenance
  SC = AtlasPca::IntentSchema
  ST = AtlasPca::IntentStatement
  TR = AtlasPca::IntentTrajectory
  BY_FN = Ref.load('intent-misc')

  def self.compiler(spec)
    case spec['kind']
    when 'captured' then CO.captured_slots_compiler(spec['id'])
    when 'throws' then CO::IntentCompiler.new(spec['id'], spec['family'], ->(_inp) { raise 'boom' })
    else CO.fixed_compiler(spec['id'], spec['family'], ->(_inp) { spec['policy'] })
    end
  end

  def self.regret(cases, scale = nil)
    cs = cases.map { |c| c.merge('admits' => ->(x) { x['values']['ok'] == 1 }, 'utility' => ->(x) { x['values']['u'] }) }
    scale.nil? ? PV.regret_report(cs) : PV.regret_report(cs, scale)
  end

  def self.step(om, psi, hist, cand, allow)
    in_grant = lambda do |_verb, cell|
      next true if allow == 'all'
      next false if allow == 'none'

      allow.any? { |x| x.join(',') == cell.join(',') }
    end
    TR.step_trajectory(om, psi, hist, cand.merge('id' => 'new'), in_grant)
  end

  MAP = {
    'signIntent' => ->(s, seed) { ST.sign_intent(s, AtlasPca.b64d(seed, 32)) },
    'intentRef' => ST.method(:intent_ref),
    'verifyIntent' => ST.method(:verify_intent),
    'parseSlotsJSON' => CO.method(:parse_slots_json),
    'slotsPrompt' => CO.method(:slots_prompt),
    'runCompilers' => ->(inp, specs) { CO.run_compilers(inp, specs.map { |s| compiler(s) }) },
    'analyzeDisagreement' => CO.method(:analyze_disagreement),
    'panelFlags' => CO.method(:panel_flags),
    'committeeAnchors' => CO.method(:committee_anchors),
    'deriveOmegaFromSchema' => SC.method(:derive_omega_from_schema),
    'canonValue' => SC.method(:canon_value),
    'provenanceBanner' => PV.method(:provenance_banner),
    'provenanceFriction' => PV.method(:provenance_friction),
    'regretReport' => method(:regret),
    'calibrateConfusion' => CL.method(:calibrate_confusion),
    'confusionDigest' => CL.method(:confusion_digest),
    'publishedErrorRate' => CL.method(:published_error_rate),
    'classifierCardNote' => CL.method(:classifier_card_note),
    'classifierRisk' => CL.method(:classifier_risk),
    'labelSound' => CL.method(:label_sound),
    'labelSoundBound' => CL.method(:label_sound_bound),
    'dimKindOf' => TR.method(:dim_kind_of),
    'describeAccCell' => TR.method(:describe_acc_cell),
    'trajectoryHarmRange' => TR.method(:trajectory_harm_range),
    'defaultAccumulators' => TR.method(:default_accumulators),
    'augmentOmega' => TR.method(:augment_omega),
    'liftAction' => TR.method(:lift_action),
    'stepTrajectory' => method(:step),
    'stateDigest' => FR.method(:state_digest),
    'snapshotState' => FR.method(:snapshot_state),
    'writeSetOf' => FR.method(:write_set_of),
    'checkFrame' => ->(spec, action, pre, post, opts = nil) { FR.check_frame(spec, action, pre, post, opts) },
    'cellCoords' => JI.method(:cell_coords),
    'cellFromCoords' => JI.method(:cell_from_coords),
    'intentRequiredBody' => JI.method(:intent_required_body)
  }.freeze

  def test_corpus_is_fully_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 795, BY_FN.values.sum(&:length), 'intent-misc'
  end

end
