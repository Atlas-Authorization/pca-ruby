# frozen_string_literal: true

# Replays the TS-reference oracle of the objective risk functional (test-data/ref-objective-risk.json.gz, 4052 cases): the canonical action, the
# inverse registry and reversibility, the resource graph and blast radius, the native and BYO embedders, the goal commitment and distance, the
# split-conformal calibration, the harm currency, objectiveRisk and the dispute-game oracle. Every fn has a handler and the totals are asserted;
# a reference refusal needs a native exception. A non-finite number is {"$num": ...} in the arguments and in the results.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefObjectiveRisk < Minitest::Test
  O = AtlasPca::ObjectiveRisk
  BY_FN = Ref.load('objective-risk')
  TOTALS = { 'graphReachable' => 1190, 'blastRadius' => 1190, 'reversibility' => 224, 'objectiveRisk' => 178, 'vectorDistance' => 168, 'calibrate' => 154,
             'conformalThreshold' => 121, 'harmReport' => 108, 'objectiveRiskOracle' => 104, 'graphNode' => 102, 'nativeEmbed' => 98,
             'verifyGoalCommitment' => 88, 'committedDistanceChecked' => 40, 'committedDistance' => 40, 'canonicalAction' => 39, 'byoEmbed' => 39,
             'commitGoal' => 36, 'canonicalActionJson' => 23, 'canonicalActionDigest' => 23, 'byoModelId' => 18, 'graphBuild' => 17,
             'validateVector' => 17, 'calibrationDigest' => 13, 'conformanceCheck' => 10, 'registryDigest' => 8, 'registryOps' => 3, 'constants' => 1 }.freeze
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  # ---- the host objects the specs describe

  def self.registry(s)
    r = O::InMemoryInverseRegistry.new(s['trusted'] || [])
    (s['entries'] || []).each { |verb, entry| r.register(verb, entry) }
    r
  end

  def self.graph(s)
    g = O::ResourceGraph.new
    (s['nodes'] || []).each { |n| g.add_node(n) }
    (s['edges'] || []).each { |e| g.add_edge(e) }
    g
  end

  def self.infer_of(i)
    lambda do |json|
      raise 'infer boom' if i['throws']
      return 'x' if i['notArray']
      return Array.new(i['dims'] || 4) { |k| AtlasPca::Js.len16(json) + k } if i['byLen']

      i['vector']
    end
  end

  def self.byo(descriptor, claimed, infer)
    O.byo_embedder(descriptor, infer_of(infer['byLen'] ? infer.merge('dims' => descriptor['dims']) : infer), claimed)
  end

  def self.embedder(s)
    case s['scheme']
    when 'native' then O.native_hash_embedder(s['config'])
    when 'fixed' then O::Embedder.new(model_id: s['modelId'], config: s['config'], dims: s['dims']) { |_a| s['vector'] }
    else byo(s['descriptor'], s['claimedModelId'], s['infer'])
    end
  end

  def self.ctx(c)
    out = { 'registry' => registry(c['registry']), 'authorizedKinds' => c['authorizedKinds'], 'graph' => graph(c['graph']), 'embedder' => embedder(c['embedder']),
            'goal' => c['goal'], 'commitments' => c['commitments'], 'denominations' => c['denominations'], 'weights' => c['weights'], 'taint' => c['taint'],
            'age' => c['age'] }
    out['scope'] = c['scope'] if c['scope']
    out['attestedUncertainty'] = c['attestedUncertainty'] unless c['attestedUncertainty'].nil?
    out['calibration'] = c['calibration'] if c['calibration']
    out
  end

  def self.registry_ops(trusted, ops)
    r = O::InMemoryInverseRegistry.new(trusted)
    ops.map do |op, *a|
      case op
      when 'register' then r.register(a[0], a[1]) && nil
      when 'lookup' then r.lookup(a[0])
      when 'trustedVerifiers' then r.trusted_verifiers
      else r.digest
      end
    end
  end

  HANDLERS = {
    'constants' => -> { { 'METRIC' => O::METRIC, 'DEFAULT_EPSILON' => O::DEFAULT_EPSILON, 'NATIVE_SCHEME' => O::NATIVE_SCHEME,
                          'DEFAULT_MAX_PARAM_LEAVES' => O::DEFAULT_MAX_PARAM_LEAVES, 'DEFAULT_NATIVE_CONFIG' => O::DEFAULT_NATIVE_CONFIG } },
    'canonicalAction' => ->(a) { O.canonical_action(a) },
    'canonicalActionJson' => ->(c) { O.canonical_action_json(c) },
    'canonicalActionDigest' => ->(c) { O.canonical_action_digest(c) },
    'registryOps' => ->(trusted, ops) { registry_ops(trusted, ops) },
    'registryDigest' => ->(s) { registry(s).digest },
    'reversibility' => ->(a, s, kinds) { O.reversibility(a, registry(s), kinds) },
    'graphBuild' => ->(s) { g = graph(s); { 'size' => g.size, 'digest' => g.digest } },
    'graphReachable' => ->(s, start, scope) { graph(s).reachable(start, scope) },
    'graphNode' => ->(s, id) { graph(s).node(id) },
    'blastRadius' => ->(a, s, scope) { O.blast_radius(a, graph(s), scope) },
    'nativeEmbed' => ->(cfg, a) { e = O.native_hash_embedder(cfg); { 'modelId' => e.model_id, 'dims' => e.dims, 'config' => e.config, 'vector' => e.embed(a) } },
    'byoModelId' => ->(d) { O.byo_model_id(d) },
    'byoEmbed' => ->(d, claimed, infer, a) { e = byo(d, claimed, infer); { 'modelId' => e.model_id, 'dims' => e.dims, 'vector' => e.embed(a) } },
    'validateVector' => ->(v, dims) { O.validate_vector(v, dims) },
    'conformanceCheck' => ->(es, cases) { O.conformance_check(embedder(es), cases) },
    'commitGoal' => ->(es, a, eps) { eps.nil? ? O.commit_goal(embedder(es), a) : O.commit_goal(embedder(es), a, eps) },
    'verifyGoalCommitment' => ->(g, es) { O.verify_goal_commitment(g, embedder(es)) },
    'vectorDistance' => ->(a, b, eps) { eps.nil? ? O.vector_distance(a, b) : O.vector_distance(a, b, eps) },
    'committedDistanceChecked' => ->(c, g, es) { O.committed_distance_checked(c, g, embedder(es)) },
    'committedDistance' => ->(a, g, es) { O.committed_distance(a, g, embedder(es)) },
    'calibrate' => ->(raw, scores) { O.calibrate(raw, scores) },
    'conformalThreshold' => ->(scores, alpha) { O.conformal_threshold(scores, alpha) },
    'calibrationDigest' => ->(scores) { O.calibration_digest(scores) },
    'harmReport' => ->(u, d) { O.harm_report(u, d) },
    'objectiveRisk' => ->(a, c) { O.objective_risk(a, ctx(c)) },
    'objectiveRiskOracle' => ->(c, input, snap) { O.objective_risk_oracle(ctx(c)).resolve(input, snap) }
  }.freeze

  # A reason that starts with the engine's own property-read message is compared only as present (the text is the JS engine's).
  def self.same?(got, out)
    return got.is_a?(String) if out.is_a?(String) && out.start_with?('Cannot read properties')

    Ref.canon(got) == Ref.canon(out)
  end

  def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 4052, BY_FN.values.sum(&:length)
    assert_equal 407, BY_FN.values.flatten.count { |c| Ref.throws?(c['out']) }
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      ran = Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| self.class.dnum(a) }) },
                    compare: ->(got, out, _c) { self.class.same?(got, out) })
      assert_equal TOTALS.fetch(fn), ran
    end
  end

  # resolve_objective_risk with the built-in engine: a grant that commits real objective facts is reproduced, a changed registry is not.
  def test_resolve_objective_risk_with_the_built_in_engine
    a = AtlasPca
    key = ->(label) { a::KeyPair.new(Digest::SHA256.digest("atlas-pca-conformance/objective-risk/#{label}")) }
    agent = a.create_agent(principal: key.call('principal'), goal: 'refund', permissions: { 'stripe' => ['refund'] }, holder: key.call('holder'),
                           goal_salt: 'AAECAwQFBgcICQoLDA0ODw', now: 0)
    entry = { 'inverseKind' => 'stripe.charge', 'fidelity' => 'exact', 'verification' => { 'verifierId' => 'v1', 'evidenceDigest' => 'e' } }
    reg = O::InMemoryInverseRegistry.new(['v1']).register('stripe.refund', entry)
    graph = O::ResourceGraph.new.add_node({ 'id' => 'acct:1', 'harm' => { 'usd' => 10 } })
    emb = O.native_hash_embedder
    action = { 'verb' => 'stripe.refund', 'resource' => 'acct:1', 'params' => { 'amount' => 5 } }
    goal = O.commit_goal(emb, action)
    commit = { 'v' => 1, 'embedder' => { 'scheme' => 'native', 'model_id' => emb.model_id, 'config' => O::DEFAULT_NATIVE_CONFIG }, 'goal' => goal,
               'registry_digest' => reg.digest, 'graph_digest' => graph.digest, 'authorized_kinds' => ['stripe.charge'],
               'denominations' => [{ 'id' => 'usd', 'ceiling' => 100, 'weight' => 1 }] }
    grant = agent.grant.merge('caveats' => agent.grant['caveats'].map { |c| c['type'] == 'envelope' ? c.merge('objective_risk' => commit) : c })
    instance = { 'registry' => { 'trusted_verifiers' => ['v1'], 'entries' => [{ 'verb' => 'stripe.refund', 'inverse_kind' => 'stripe.charge', 'fidelity' => 'exact',
                                                                               'verification' => { 'verifier_id' => 'v1', 'evidence_digest' => 'e' } }] },
                 'graph' => { 'nodes' => [{ 'id' => 'acct:1', 'harm' => { 'usd' => 10 } }], 'edges' => [] } }
    got = a.resolve_objective_risk(grant: grant, action: action, instance: instance)
    want = O.objective_risk(action, { 'registry' => reg, 'authorizedKinds' => ['stripe.charge'], 'graph' => graph, 'embedder' => emb, 'goal' => goal,
                                      'commitments' => { 'registryDigest' => reg.digest, 'graphDigest' => graph.digest },
                                      'denominations' => commit['denominations'], 'weights' => a.read_envelope(grant)['risk_policy']['weights'], 'taint' => 1, 'age' => 1 })
    assert want['valid'], want['reasons'].inspect
    assert_equal 'objective', got['mode'], got.inspect
    assert_equal [want['r'], want['evidenceDigest']], [got['r'], got['evidenceDigest']]
    assert_equal 1, got['inputs']['reversibility']
    other = instance.merge('registry' => { 'trusted_verifiers' => [], 'entries' => [] })
    assert_equal({ 'mode' => 'mismatch', 'reasons' => ['registry digest does not match the committed digest'], 'onMismatch' => 'deny' },
                 a.resolve_objective_risk(grant: grant, action: action, instance: other))
  end
end
