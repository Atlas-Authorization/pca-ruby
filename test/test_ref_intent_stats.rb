# frozen_string_literal: true

# Replays the TS-reference oracle of the intent numerics (test-data/ref-intent-stats.json.gz): exact Clopper-Pearson, the binomial CDF, Hoeffding and Wilson.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/intent_clopper'
require_relative '../lib/atlas_pca/intent_metrics'
require 'minitest/autorun'

class TestRefIntentStats < Minitest::Test
  C = AtlasPca::IntentClopper
  M = AtlasPca::IntentMetrics
  BY_FN = Ref.load('intent-stats')

  def self.unbig(x) = x.is_a?(Hash) && x.key?('$bigint') ? x['$bigint'].to_i : x
  def self.big(x) = { '$bigint' => x.to_s }

  MAP = {
    'clopperPearsonUpper' => C.method(:clopper_pearson_upper),
    'clopperPearsonCertified' => lambda { |k, n, a|
      c = C.clopper_pearson_certified(k, n, a)
      { 'upper' => c['upper'], 'upperUnits' => big(c['upperUnits']), 'lowerUnits' => big(c['lowerUnits']) }
    },
    'binomialCdf' => C.method(:binomial_cdf),
    'doubleToDyadic' => lambda { |x|
      d = C.double_to_dyadic(x)
      { 'num' => big(d['num']), 'exp' => d['exp'] }
    },
    'cdfRecNumerator' => ->(n, k, a) { big(C.cdf_rec_numerator(n, k, unbig(a))) },
    'cdfExceeds' => ->(n, k, a, al) { C.cdf_exceeds(n, k, unbig(a), { 'num' => unbig(al['num']), 'exp' => al['exp'] }) },
    'hoeffdingHalfWidth' => M.method(:hoeffding_half_width),
    'wilsonInterval' => M.method(:wilson_interval)
  }.freeze

  def test_corpus_is_fully_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 995, BY_FN.values.sum(&:length), 'intent-stats'
  end

end
