# frozen_string_literal: true

# Replays the TS-reference oracle of the intent runtime digests, effect postconditions, trust-ramp drift detector and question cards (test-data/ref-intent-runtime.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/intent_effects'
require_relative '../lib/atlas_pca/intent_ramp'
require_relative '../lib/atlas_pca/intent_runtime'
require_relative '../lib/atlas_pca/intent_ux'
require 'minitest/autorun'

class TestRefIntentRuntime < Minitest::Test
  E = AtlasPca::IntentEffects
  RA = AtlasPca::IntentRamp
  RT = AtlasPca::IntentRuntime
  UX = AtlasPca::IntentUx
  BY_FN = Ref.load('intent-runtime')

  # a learner stand-in: the omega and a fixed acceptance probability
  Stub = Struct.new(:omega, :p) do
    def acceptance(_o) = p
  end

  def self.drift(opts, seq)
    d = RA::DriftDetector.new(opts)
    out = seq.map { |x| d.update(x) }
    out << d.state
    d.reset
    out << d.state
    out
  end

  MAP = {
    'pcactnActionOf' => RT.method(:pcactn_action_of),
    'judgeInputOf' => ->(om, o, p, ctx) { RT.judge_input_of(Stub.new(om, p), o, ctx) },
    'jitConsentRequest' => ->(om, o, p, ctx) { RT.jit_consent_request(Stub.new(om, p), o, ctx) },
    'jitConsentDigest' => RT.method(:jit_consent_digest),
    'calibrationDigest' => RT.method(:calibration_digest),
    'icAttDigest' => RT.method(:ic_att_digest),
    'foldSemanticRisk' => RT.method(:fold_semantic_risk),
    'defaultPostconditions' => -> { E::DEFAULT_POSTCONDITIONS },
    'checkPostconditions' => E.method(:check_postconditions),
    'effectContext' => E.method(:effect_context),
    'signalLabel' => RA.method(:signal_label),
    'narrowStart' => RA.method(:narrow_start),
    'driftRun' => method(:drift),
    'questionCard' => UX.method(:question_card),
    'parseCardAnswer' => UX.method(:parse_card_answer)
  }.freeze

  def test_corpus_is_fully_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 585, BY_FN.values.sum(&:length), 'intent-runtime'
  end

end
