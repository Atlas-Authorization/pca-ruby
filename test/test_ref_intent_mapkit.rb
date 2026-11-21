# frozen_string_literal: true

# Replays the TS-reference oracle of the Intent Map (test-data/ref-intent-map.json.gz): emit, digest, replay verification, tamper
# detection, learner options, the committed form and runtime divergence. Doubles compare to 1e-12 relative; a "replay failed:
# <text>" problem compares as "replay failed" (the text is the language's own).
require_relative 'support/ref_intent'
require_relative '../lib/atlas_pca/intent_mapkit'
require_relative '../lib/atlas_pca/intent_map_commit'
require 'minitest/autorun'

class TestRefIntentMapkit < Minitest::Test
  M = AtlasPca::IntentMapkit
  MC = AtlasPca::IntentMapCommit
  O = AtlasPca::IntentOmega
  BY_FN = Ref.load('intent-map')

  def self.sec(seed) = Array.new(32) { |i| (seed + (7 * i)) & 255 }.pack('C*')

  def self.norm_problems(r) = { 'ok' => r['ok'], 'problems' => r['problems'].map { |p| p.start_with?('replay failed') ? 'replay failed' : p } }

  def self.deep(m) = Marshal.load(Marshal.dump(m))

  MUTS = [
    ->(m) { m },
    ->(m) { m['metrics']['residual_risk_ppm'] += 5; m },
    ->(m) { m['cells'][0]['p_ppm'] += 3; m },
    ->(m) { m['cells'][0]['in_grant'] = !m['cells'][0]['in_grant']; m },
    ->(m) { m['grant_digest'] = 'AAAA'; m },
    ->(m) { m['observations'].pop; m },
    ->(m) { m['kind'] = 'x'; m },
    ->(m) { m['principals'] = %w[a b]; m },
    ->(m) { m['aggregation'] = { 'rule' => 'unanimity' }; m },
    ->(m) { m['metrics'].delete('log2_vs_mbits'); m },
    ->(m) { m['learner']['eta_ppm'] += 100_000; m },
    ->(m) { m['metrics']['questions'] += 1; m },
    ->(m) { m['cells'].pop; m },
    ->(m) { m['omega']['verbs'][0]['w'] = 5; m },
    ->(m) { m['metrics']['log2_vs_mbits'] = nil; m },
    ->(m) { m['cells'][0]['p_ppm'] += 2; m },
    ->(m) { m['cells'][0]['p_ppm'] += 1; m }
  ].freeze

  def self.disclosures(omega, cm)
    omega['verbs'].flat_map do |vs|
      t = O.verb_cell_count(vs)
      [0, t / 2, t - 1].map do |f|
        oc = O.cell_rep(vs, O.decode_cell(vs, f))
        params = {}
        resource = nil
        oc['values'].each do |k, v|
          if k == 'action.resource' then resource = v
          else params[k['action.params.'.length..]] = v
          end
        end
        cm['disclose'].call(vs['verb'], resource, params)
      end
    end
  end

  def self.map_scenario(omega, map_opts, observations, intent_ref, secret_seed)
    l = M.create_learner(omega, map_opts)
    observations.each { |x| l.observe({ 'verb' => x['verb'], 'values' => x['values'] }, x['y'], x['source'], x['region']) }
    m = M.emit_intent_map(l, intent_ref)
    tampered = MUTS.map { |f| norm_problems(M.verify_intent_map(f.call(deep(m)))) }
    tampered << norm_problems(M.verify_intent_map(nil))
    tampered << norm_problems(M.verify_intent_map({ 'v' => 2 }))
    commit = begin
      cm = MC.commit_intent_map(m, sec(secret_seed))
      { 'map_commit' => cm['map_commit'], 'size' => cm['size'], 'leaves' => cm['leaves'], 'disclosures' => disclosures(omega, cm) }
    rescue StandardError
      { 'error' => true }
    end
    { 'map' => m, 'digest' => M.intent_map_digest(m), 'grantDigest' => M.grant_digest(m['grant']), 'verify' => norm_problems(M.verify_intent_map(m)),
      'tampered' => tampered, 'options' => M.map_learner_options(m), 'omegaRoundtrip' => M.omega_to_json(M.omega_from_json(m['omega'])), 'commit' => commit }
  end

  def self.commit_intent_map(m)
    cm = MC.commit_intent_map(m, sec(3))
    { 'map_commit' => cm['map_commit'], 'size' => cm['size'], 'leaves' => cm['leaves'] }
  end

  def self.divergence(omega, mo, obs, ds)
    l = M.create_learner(omega, mo)
    obs.each { |x| l.observe({ 'verb' => x['verb'], 'values' => x['values'] }, x['y'], x['source']) }
    ds.map { |d| M.apply_divergence(l, d['outcome'], d['y']) }
  end

  MAP = {
    'mapScenario' => method(:map_scenario),
    'commitIntentMap' => method(:commit_intent_map),
    'grantDigest' => M.method(:grant_digest),
    'intentMapDigest' => M.method(:intent_map_digest),
    'omegaToJSON' => M.method(:omega_to_json),
    'omegaFromJSON' => M.method(:omega_from_json),
    'divergence' => method(:divergence)
  }.freeze

  def test_corpus_is_fully_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn], compare: RefIntent.cmp) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 183, BY_FN.values.sum(&:length), 'intent-map'
  end

end
