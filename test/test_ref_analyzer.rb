# frozen_string_literal: true

# Replays the TS-reference oracle of the policy analyzer (test-data/ref-analyzer.json.gz): caveat / interval / probe engines, the
# bounded decision engine, reachability and relations, exposure, residuals and filters, narrowing, coverage, minimal-flip
# counterfactuals, schema validation and the policy test runner. Keys are labels: the Ed25519 seed of a label is
# sha256("atlas-pca-conformance/" + label), and "$key:LABEL" stands for its public key.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/analyzer'
require 'minitest/autorun'

class TestRefAnalyzer < Minitest::Test
  A = AtlasPca::Analyzer
  BY_FN = Ref.load('analyzer')
  FULL = A::FULL_INTERVAL

  def self.seed(label) = Digest::SHA256.digest("atlas-pca-conformance/#{label}")
  def self.pub(label) = AtlasPca::KeyPair.new(seed(label)).public
  def self.keyed(v) = v.is_a?(String) && v.start_with?('$key:') ? pub(v[5..]) : v

  # {"$num": "Infinity"} back to the number
  def self.revive(v)
    case v
    when Array then v.map { |x| revive(x) }
    when Hash
      if v.size == 1 && v['$num'].is_a?(String)
        { 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY, 'NaN' => Float::NAN }.fetch(v['$num'])
      else
        v.transform_values { |x| revive(x) }
      end
    else v
    end
  end

  def self.probes_json(inp)
    p = A.collect_probes(inp)
    p.merge('fields' => p['fields'].map { |f| { 'path' => f['path'], 'values' => f['values'].map { |x| x.equal?(A::ABSENT) ? { '$absent' => true } : x } } })
  end

  def self.reps(inp)
    p = A.collect_probes(inp)
    raise ArgumentError, 'grid too large for the corpus' if A.product_size(p) > 400

    out = []
    A.representatives(p) do |r|
      o = { 'verb' => r['verb'], 'resource' => r['resource'], 'assignments' => r['assignments'].dup, 'action' => A.rep_to_action(r) }
      o['revClass'] = r['revClass'] unless r['revClass'].nil?
      out << o
    end
    out
  end

  def self.veto_applies(veto, x)
    a = x.dup
    a['params'] = {} if x['params'].nil?
    A.veto_applies(veto, { 'action' => a, 'subject' => x['subject'].nil? ? {} : x['subject'], 'env' => x['env'].nil? ? {} : x['env'] })
  end

  MAP = {
    'analyzeCaveats' => A.method(:analyze_caveats),
    'numericConjunctionSatisfiable' => A.method(:numeric_conjunction_satisfiable),
    'predicateNumericSatisfiable' => A.method(:predicate_numeric_satisfiable),
    'tightenInterval' => ->(iv, op, v) { A.tighten_interval(iv.nil? ? FULL : iv, op, v) },
    'intervalEmpty' => ->(iv) { A.interval_empty(iv.nil? ? FULL : iv) },
    'fieldProbes' => A.method(:field_probes),
    'vetoesFromConstitution' => A.method(:vetoes_from_constitution),
    'toModel' => A.method(:to_model),
    'collectProbes' => ->(inp) { probes_json(inp) },
    'representatives' => ->(inp) { reps(inp) },
    'decideAction' => ->(p, a) { A.decide_action(A.to_model(p), a) },
    'witnessOf' => ->(p, a) { A.witness_of(A.to_model(p), a) },
    'admitsConcrete' => A.method(:admits_concrete),
    'vetoApplies' => ->(veto, x) { veto_applies(veto, x) },
    'reachable' => ->(p, a, o = nil) { A.reachable(p, a, o) },
    'alwaysDenies' => ->(p, v = nil, o = nil) { A.always_denies(p, v, o) },
    'alwaysAllows' => ->(p, v, o = nil) { A.always_allows(p, v, o) },
    'subsumes' => ->(a, b, o = nil) { A.subsumes(a, b, o) },
    'disjoint' => ->(a, b, o = nil) { A.disjoint(a, b, o) },
    'equivalent' => ->(a, b, o = nil) { A.equivalent(a, b, o) },
    'intentConformance' => ->(p, i, o = nil) { A.intent_conformance(p, i, o) },
    'thresholdsOf' => ->(p, path) { A.thresholds_of(A.to_model(p), path) },
    'maxExposure' => A.method(:max_exposure),
    'escalationSurface' => ->(p, o = nil) { A.escalation_surface(p, o) },
    'delegationEnvelope' => ->(c, o = nil) { A.delegation_envelope(c, o) },
    'diffPolicies' => ->(a, b, o = nil) { A.diff_policies(a, b, o) },
    'diffGate' => ->(d, al = nil) { A.diff_gate(revive(d), al) },
    'findWithBackend' => ->(q, spec) { A.find_with_backend({ 'name' => spec['name'], 'find' => ->(_q) { spec['result'] } }, q) },
    'dagExposure' => A.method(:dag_exposure),
    'residual' => ->(p, k, o = nil) { A.residual(p, k, o) },
    'residualPolicy' => A.method(:residual_policy),
    'evaluateResidual' => A.method(:evaluate_residual),
    'whatMayIDo' => ->(p, v, k = nil, o = nil) { A.what_may_i_do(p, v, k, o) },
    'toFilter' => ->(p, k, ro, f) { A.to_filter(A.residual(p, k, ro), f) },
    'toUcast' => A.method(:to_ucast),
    'evalFilter' => A.method(:eval_filter),
    'evalUcast' => A.method(:eval_ucast),
    'suggestNarrowing' => ->(p, ob, o = nil) { A.suggest_narrowing(p, ob, o) },
    'signAccessRequest' => ->(r, label) { A.sign_access_request(r, seed(label), pub(label)) },
    'verifyAccessRequest' => ->(x, e = nil) { A.verify_access_request(x, e.nil? ? nil : keyed(e)) },
    'coverage' => ->(p, t, o = nil) { A.coverage(p, t, o) },
    'coverageGate' => ->(r, m = nil) { A.coverage_gate(r, m) },
    'minimalFlip' => A.method(:minimal_flip),
    'verbShapes' => A.method(:verb_shapes),
    'verbShapesFromActionDefs' => A.method(:verb_shapes_from_action_defs),
    'validatePolicyAgainstSchema' => ->(p, s, o = nil) { A.validate_policy_against_schema(p, s, o) },
    'policyTestsDoc' => A.method(:policy_tests_doc),
    'runPolicyTests' => ->(p, d, o = nil) { A.run_policy_tests(p, d, o) },
    'generateBoundaryTests' => ->(p, o = nil) { A.generate_boundary_tests(p, o) },
    'decideAll' => A.method(:decide_all),
    'signPolicyTests' => ->(d, label) { A.sign_policy_tests(d, seed(label), pub(label)) },
    'verifyPolicyTests' => ->(s, e) { A.verify_policy_tests(s, keyed(e)) }
  }.freeze

  def self.seed_of(label) = seed(label)

  def test_corpus_is_the_full_oracle
    assert_equal MAP.keys.sort, BY_FN.keys.sort
    assert_equal 6309, BY_FN.values.sum(&:length)
  end

  (MAP.keys - ['vetoApplies']).each do |fn|
    define_method("test_#{fn}_matches_the_reference") { Ref.run(self, BY_FN.fetch(fn), MAP.fetch(fn)) }
  end

  def test_veto_applies_matches_the_reference
    cases = BY_FN.fetch('vetoApplies')
    Ref.run(self, cases.reject { |c| c['name'] == 'unless-object' }, MAP.fetch('vetoApplies'))
    # the one case that hands the action over as is: `unless` is not an array, so the reference throws
    Ref.run(self, cases.select { |c| c['name'] == 'unless-object' }, ->(veto, x) { A.veto_applies(veto, { 'action' => x, 'subject' => {}, 'env' => {} }) })
  end
end
