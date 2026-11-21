# frozen_string_literal: true

# Replays the TS-reference oracle of the intent outcome space (test-data/ref-intent-omega.json.gz): omega derivation, cells,
# workload and harm measures, the seeded generator, policy plumbing, slots and regions.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/intent_omega'
require_relative '../lib/atlas_pca/intent_policy'
require_relative '../lib/atlas_pca/intent_region'
require_relative '../lib/atlas_pca/intent_slots'
require 'minitest/autorun'

class TestRefIntentOmega < Minitest::Test
  O = AtlasPca::IntentOmega
  P = AtlasPca::IntentPolicy
  R = AtlasPca::IntentRegion
  S = AtlasPca::IntentSlots
  BY_FN = Ref.load('intent-omega')

  def self.stats(s) = { 'mass' => s['mass'], 'harm' => s['harm'] }

  MAP = {
    'deriveOmega' => O.method(:derive_omega),
    'harmMax' => O.method(:harm_max),
    'verbSpace' => O.method(:verb_space),
    'verbCellCount' => O.method(:verb_cell_count),
    'decodeCell' => O.method(:decode_cell),
    'encodeCell' => O.method(:encode_cell),
    'cellRep' => O.method(:cell_rep),
    'seeded' => O.method(:cell_rep),
    'cellStats' => ->(vs, idx) { stats(O.cell_stats(vs, idx)) },
    'cellOf' => O.method(:cell_of),
    'harmOf' => O.method(:harm_of),
    'cellCount' => O.method(:cell_count),
    'numCells' => O.method(:num_cells),
    'numRep' => O.method(:num_rep),
    'repValue' => O.method(:rep_value),
    'catRep' => O.method(:cat_rep),
    'catCellOf' => O.method(:cat_cell_of),
    'cellOfValue' => O.method(:cell_of_value),
    'dimCellStats' => ->(d, i) { stats(O.dim_cell_stats(d, i)) },
    'intervalWeight' => O.method(:interval_weight),
    'rngSeq' => lambda { |seed, n|
      r = O.rng(seed)
      Array.new(n) { r.call }
    },
    'sampleOutcomes' => lambda { |omega, seed, n|
      r = O.rng(seed)
      Array.new(n) { O.sample_outcome(omega, r)[1] }
    },
    'normalizePolicy' => P.method(:normalize_policy),
    'slotsToPolicy' => S.method(:slots_to_policy),
    'outcomeToAction' => P.method(:outcome_to_action),
    'admits' => ->(pol, vs, o) { P.admitter(pol).admits(vs, o) },
    'regionOfCell' => R.method(:region_of_cell),
    'regionCells' => R.method(:region_cells),
    'dimCellsIn' => R.method(:dim_cells_in),
    'restrictRegion' => ->(d, part) { R.restrict_region({ 'verb' => 'v', 'dims' => {} }, d, part) },
    'valueInRegionDim' => R.method(:value_in_region_dim)
  }.freeze

  def test_corpus_is_fully_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 5377, BY_FN.values.sum(&:length), 'intent-omega'
  end

end
