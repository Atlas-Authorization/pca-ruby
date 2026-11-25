# frozen_string_literal: true

# Replays the TS-reference oracle of the portable intent profiles (test-data/ref-intent-profile.json.gz): shape, signing, verification, succession, scope, standing rules, veto cells and usability.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/intent_profile'
require 'minitest/autorun'

class TestRefIntentProfile < Minitest::Test
  P = AtlasPca::IntentProfile
  BY_FN = Ref.load('intent-profile')

  MAP = {
    'signIntentProfile' => ->(body, seed) { P.sign_intent_profile(body, AtlasPca.b64d(seed, 32)) },
    'intentProfileShapeError' => ->(p, opts = nil) { P.intent_profile_shape_error(p, !(opts.is_a?(Hash) && opts['signed'] == false)) },
    'verifyIntentProfile' => P.method(:verify_intent_profile),
    'intentProfileDigest' => P.method(:intent_profile_digest),
    'verifyProfileSuccession' => P.method(:verify_profile_succession),
    'profileApplies' => P.method(:profile_applies),
    'standingAdmits' => P.method(:standing_admits),
    'standingPermits' => P.method(:standing_permits),
    'profileVetoCells' => P.method(:profile_veto_cells),
    'profileCeiling' => ->(p, u, vs, o) { P.profile_ceiling(p, u).call(vs, o) },
    'profileUsable' => P.method(:profile_usable)
  }.freeze

  def test_corpus_is_fully_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1996, BY_FN.values.sum(&:length), 'intent-profile'
  end

end
