# frozen_string_literal: true

# Differential replay of the wallet over an intent learner (the grant view of a learner with an optional ceiling, and the mass a
# released population prior admits beyond the base prior) against vectors generated from the TypeScript reference
# (@atlasauth/pca-wallet). Doubles from transcendental functions are compared to 1e-12 relative; integers, strings and structure exactly.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/wallet_channel'
require_relative '../lib/atlas_pca/wallet_population'
require_relative '../lib/atlas_pca/intent_mapkit'
require 'minitest/autorun'

class TestRefWalletLearner < Minitest::Test
  CH = AtlasPca::WalletChannel
  PO = AtlasPca::WalletPopulation
  O = AtlasPca::IntentOmega
  BY_FN = Ref.load('wallet-learner-py')

  def self.close?(a, b)
    return a.keys == b.keys && a.all? { |k, v| close?(v, b[k]) } if a.is_a?(Hash) && b.is_a?(Hash)
    return a.length == b.length && a.zip(b).all? { |x, y| close?(x, y) } if a.is_a?(Array) && b.is_a?(Array)
    return a.equal?(b) if [true, false].include?(a) || [true, false].include?(b)
    if a.is_a?(Numeric) && b.is_a?(Numeric)
      return a == b if a.is_a?(Integer) && b.is_a?(Integer)

      return (a - b).abs <= [1e-12 * [a.abs, b.abs].max, 1e-15].max
    end
    Ref.canon(a) == Ref.canon(b)
  end

  CMP = ->(got, out, _c) { close?(Ref.norm(got), out) }

  def self.mk(omega, mo, obs)
    l = AtlasPca::IntentMapkit.create_learner(omega, mo)
    obs.each { |x| l.observe({ 'verb' => x['verb'], 'values' => x['values'] }, x['y'], x['source']) }
    l
  end

  CEILINGS = { 'all' => ->(_v, _idx) { true }, 'idx0' => ->(_v, idx) { idx[0] == 0 }, 'never' => ->(_v, _idx) { false } }.freeze

  def self.view_scenario(omega, mo, obs, ceiling, probes)
    view = CH.learner_view(mk(omega, mo, obs), ceiling == 'none' ? {} : { 'insideCeiling' => CEILINGS[ceiling] })
    { 'probes' => probes.map { |p| [view['p'].call(p['verb'], p['idx']), view['vetoed'].call(p['verb'], p['idx']), view['outsideCeiling'].call(p['verb'], p['idx'])] },
      'confirmed' => view['confirmed'].call }
  end

  def self.prior_scenario(omega, base, obs, beta, schema, q_of, hi = false)
    cells = {}
    omega['verbs'].each do |vs|
      O.verb_cell_count(vs).times do |c|
        q = hi ? 0.98 - (0.04 * (c % q_of)) : 0.05 + (0.04 * (c % q_of))
        cells[PO.population_cell_key(schema, vs, O.decode_cell(vs, c))] = { 'q' => [0.98, [0.02, q].max].min, 'n' => 50 }
      end
    end
    rel = { 'v' => 1, 'kind' => 'pca-intent-population-prior', 'schema' => schema, 'period' => 1, 'epsilon' => 0.9, 'delta' => 1e-5, 'sigma' => 1, 'sensitivity' => 8, 'cells' => cells }
    PO.prior_admitted_ppm(omega, base, obs, PO.population_prior(rel, beta))
  end

  MAP = {
    'viewScenario' => method(:view_scenario),
    'viewUnknownVerb' => ->(omega, verb, idx) { CH.learner_view(mk(omega, {}, []))['p'].call(verb, idx) },
    'priorScenario' => method(:prior_scenario)
  }.freeze

  def test_corpus_is_fully_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each { |fn, call| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call, compare: CMP) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 239, BY_FN.values.sum(&:length), 'wallet-learner-py'
  end

end
