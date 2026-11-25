# frozen_string_literal: true

# Replays the TS-reference oracle of multi-principal aggregation over Intent Maps (test-data/ref-intent-multi-agg.json.gz): rules,
# joint grant, recompute verification, lifting onto a common refinement and cross-organisation aggregation. Doubles compare to
# 1e-12 relative; a verification problem's language-specific text ("replay failed: ...", a recompute error that is not a reference
# message) is compared by its prefix.
require_relative 'support/ref_intent'
require_relative '../lib/atlas_pca/intent_mapkit'
require_relative '../lib/atlas_pca/intent_multi_agg'
require 'minitest/autorun'

class TestRefIntentMultiAgg < Minitest::Test
  M = AtlasPca::IntentMapkit
  A = AtlasPca::IntentMultiAgg
  BY_FN = Ref.load('intent-multi-agg')
  REF_PREFIX = /\A(aggregateIntentMaps|ruleOf|liftIntentMap|crossOrgAggregate|commonRefinement|pca-intent|refineOmega)/

  def self.norm_problem(p)
    q = p.gsub(/replay failed: [^;]*/, 'replay failed')
    m = q.match(/\Arecompute failed: (.*)\z/m)
    return 'recompute failed: error' if m && !REF_PREFIX.match?(m[1])
    return (REF_PREFIX.match?(q) ? q : 'error') if !m && !q.match?(/\A(input |aggregate does not|recompute failed)/) && !q.start_with?('replay failed')

    q
  end

  def self.nrm(r) = { 'ok' => r['ok'], 'problems' => r['problems'].map { |p| norm_problem(p) } }

  def self.build_map(omega, map_opts, observations, ref)
    l = M.create_learner(omega, map_opts)
    observations.each { |x| l.observe({ 'verb' => x['verb'], 'values' => x['values'] }, x['y'], x['source'], x['region']) }
    M.emit_intent_map(l, ref)
  end

  def self.deep(m) = Marshal.load(Marshal.dump(m))

  MUTS = [
    ->(m) { m },
    ->(m) { m['metrics']['residual_risk_ppm'] += 7; m },
    ->(m) { m['cells'][0]['in_grant'] = !m['cells'][0]['in_grant']; m },
    ->(m) { m['aggregation'] = nil; m },
    ->(m) { m['aggregation'].merge!('rule' => 'quorum', 'k' => 1); m },
    ->(m) { m['aggregation']['vetoers'] = []; m }
  ].freeze

  def self.aggregate_scenario(omega, principals, rule, orgs, map_opts)
    # the reference passes the orgs object as the options argument, so no org label is ever applied
    opts = orgs.nil? ? {} : orgs
    maps = principals.map { |p| build_map(omega, map_opts, p['observations'], p['ref']) }
    agg = A.aggregate_intent_maps(maps, rule, opts)
    tampered = MUTS.map { |f| nrm(A.verify_aggregate(f.call(deep(agg)), maps, opts)) }
    { 'aggregate' => agg, 'digest' => M.intent_map_digest(agg), 'rule' => A.rule_of(agg), 'verify' => nrm(A.verify_aggregate(agg, maps, opts)),
      'tampered' => tampered, 'wrongInputs' => nrm(A.verify_aggregate(agg, maps[0...-1], opts)),
      'combined' => rule['kind'] == 'unanimity' && !rule.key?('vetoers') ? A.combine_intent_maps(maps, opts) : nil }
  end

  def self.aggregate_two_omegas(o1, o2, ps, rule)
    A.aggregate_intent_maps([build_map(o1, {}, ps[0]['observations'], ps[0]['ref']), build_map(o2, {}, [], ps[1]['ref'])], rule)
  end

  def self.aggregate_of_aggregate(omega, ps, rule)
    maps = ps.map { |p| build_map(omega, {}, p['observations'], p['ref']) }
    agg = A.aggregate_intent_maps(maps, rule)
    A.aggregate_intent_maps([agg, maps[0]], rule)
  end

  def self.lift_of_aggregate(omega, ps, rule)
    maps = ps.map { |p| build_map(omega, {}, p['observations'], p['ref']) }
    A.lift_intent_map(A.aggregate_intent_maps(maps[0, 1], rule), omega)
  end

  NONE = Object.new.freeze

  def self.cross_scenario(specs, rule, orgs = NONE)
    if orgs.equal?(NONE) # the variant that corrupts the first map's metrics, which crossOrgAggregate must refuse
      maps = specs.map { |s| build_map(s['omega'], {}, s['observations'], s['ref']) }
      maps[0]['metrics']['residual_risk_ppm'] += 9
      return A.cross_org_aggregate(maps, rule)
    end
    opts = orgs.nil? ? {} : orgs
    maps = specs.map { |s| build_map(s['omega'], s['mapOpts'] || {}, s['observations'], s['ref']) }
    r = A.cross_org_aggregate(maps, rule, opts)
    tampered = MUTS.map { |f| nrm(A.verify_cross_org_aggregate(f.call(deep(r['aggregate'])), maps, opts)) }
    { 'aggregate' => r['aggregate'], 'lifted' => r['lifted'], 'omega' => r['omega'], 'digest' => M.intent_map_digest(r['aggregate']),
      'verify' => nrm(A.verify_cross_org_aggregate(r['aggregate'], maps, opts)), 'tampered' => tampered,
      'wrong' => nrm(A.verify_cross_org_aggregate(r['aggregate'], maps[1..], opts)) }
  end

  def self.lift_scenario(omega, mo, obs, ref, target) = A.lift_intent_map(build_map(omega, mo, obs, ref), target)

  MAP = {
    'aggregateScenario' => method(:aggregate_scenario),
    'aggregateTwoOmegas' => method(:aggregate_two_omegas),
    'aggregateOfAggregate' => method(:aggregate_of_aggregate),
    'liftOfAggregate' => method(:lift_of_aggregate),
    'crossScenario' => method(:cross_scenario),
    'liftScenario' => method(:lift_scenario),
    'omegaKey' => A.method(:omega_key)
  }.freeze

  def test_corpus_is_fully_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn], compare: RefIntent.cmp) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 76, BY_FN.values.sum(&:length), 'intent-multi-agg'
  end

end
