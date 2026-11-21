# frozen_string_literal: true

# Replays the TS-reference oracle of proof of progress (test-data/ref-progress.json.gz, 723 cases): the potentials and their registry, the goal
# commitment, the state, step and trajectory digests, the trajectory anchor in the transparency ledger, signed state attestations and the
# attested state source, the progress tracker (op scripts), the step and trajectory verification and the signed steps. Every fn has a handler and
# the totals are asserted; a reference refusal needs a native exception and an {"$err"} inside a result list needs that single op to raise. The
# host objects (potentials, registries, guards, hooks, sources) are built from the specs the generator describes. The state attestations that
# the reference accepts only through its legacy unbound post-quantum option are asserted REFUSED here (this SDK has no such option).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefProgress < Minitest::Test
  P = AtlasPca::Progress
  BY_FN = Ref.load('progress')
  TOTALS = { 'verifyProgressStep' => 147, 'verifyTrajectory' => 130, 'verifyStateAttestation' => 55, 'verifyGoalCommitment' => 53, 'tracker' => 40,
             'progressStepDigest' => 37, 'goalDigest' => 31, 'commitGoal' => 31, 'verifySignedProgressStep' => 26, 'dagWeightedPotential' => 24,
             'dagRemainingPotential' => 21, 'l1FeaturePotential' => 20, 'verifyTrajectoryAnchor' => 17, 'attestedStateVerifier' => 15,
             'verifySignedTrajectory' => 15, 'stateDigest' => 14, 'anchorTrajectoryHead' => 10, 'trajectoryAnchorCommit' => 8, 'attestedSource' => 8,
             'registryOps' => 7, 'signProgressStep' => 7, 'trajectoryHead' => 6, 'constants' => 1 }.freeze
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze
  UNBOUND = []
  PQ = AtlasPca.supported_suites.include?('ml-dsa-65') # OpenSSL >= 3.5; without it the ML-DSA vectors are skipped (CI sets PCA_REQUIRE_PQ=1 where it must run)

  def self.skip_pq?(c)
    !PQ && c['fn'] == 'verifyStateAttestation' && c['args'][0].is_a?(Hash) && c['args'][0]['alg'].to_s.include?('ml-dsa')
  end

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  # ---- host objects from their specs

  def self.kind_fn(k)
    case k
    when 'l1-feature-v1' then P::L1_FEATURE
    when 'dag-remaining-v1' then P::DAG_REMAINING
    when 'dag-weighted-v1' then P::DAG_WEIGHTED
    when /\Aconst:/ then ->(_o, _s) { Float(k[6..]).then { |n| n == n.floor ? n.to_i : n } }
    when 'v' then ->(_o, s) { s.is_a?(Hash) ? s['v'] : nil }
    when 'throws' then ->(_o, _s) { raise 'potential boom' }
    when 'negative' then ->(_o, _s) { -1 }
    when 'frac' then ->(_o, _s) { 0.5 }
    when 'nan' then ->(_o, _s) { Float::NAN }
    when 'big' then ->(_o, _s) { 2**53 }
    else raise "bad potential kind #{k}"
    end
  end

  def self.registry(s)
    return nil if s.nil?

    if s['mode'] == 'record'
      return s['potentials'].to_h { |id, k, *emb| [id, emb.empty? ? kind_fn(k) : { 'fn' => kind_fn(k), 'embedder' => emb[0] }] }
    end

    r = P::PotentialRegistry.new
    s['potentials'].each { |id, k, *emb| emb.empty? ? r.register(id, kind_fn(k)) : r.register(id, kind_fn(k), emb[0]) }
    r
  end

  def self.guard(g)
    return nil if g.nil?

    case g
    when 'allow' then ->(_t) { true }
    when 'deny' then ->(_t) { false }
    when 'throws' then ->(_t) { raise 'guard boom' }
    when 'truthy' then ->(_t) { 'yes' }
    when /\Aaction:/ then ->(t) { t['action_digest'] != g[7..] }
    when /\Aseq:/ then ->(t) { t['seq'] != g[4..].to_i }
    when /\Aafter-v:/ then ->(t) { (t['after'].is_a?(Hash) ? t['after']['v'] : nil) != g[8..].to_i }
    else raise "bad guard #{g}"
    end
  end

  def self.attestation(a)
    return nil if a.nil?

    case a
    when 'allow' then ->(_s) { true }
    when 'deny' then ->(_s) { false }
    when 'throws' then ->(_s) { raise 'att boom' }
    when 'truthy' then ->(_s) { 'yes' }
    else P.attested_state_verifier(a['attested'])
    end
  end

  def self.opts(o)
    out = (o || {}).dup
    out['registry'] = registry(out['registry']) if out.key?('registry')
    out['guard'] = guard(out['guard']) if out.key?('guard')
    out['attestation'] = attestation(out['attestation']) if out.key?('attestation')
    out
  end

  # A source whose observation is altered (a lying digest or source id) or refused.
  class Wrapped
    attr_reader :id

    def initialize(spec, mem)
      @id = spec['id']
      @kind = spec['kind']
      @mem = mem
    end

    def set(nxt) = @mem.apply(nxt)

    def observe(req)
      raise 'source boom' if @kind == 'throws'
      return nil if @kind == 'null'

      ob = @mem.observe(req)
      return ob.merge('state_digest' => 'x' * 43) if @kind == 'liar-digest'
      return ob.merge('source' => 'someone-else') if @kind == 'liar-source'

      ob
    end
  end

  # An attested source over a mutable world.
  class World
    attr_accessor :v

    def initialize(v) = @v = v
  end

  class AttestedWorld < AtlasPca::Progress::AttestedStateSource
    def initialize(spec, world)
      @world = world
      super(id: spec['id'], signer: AtlasPca::KeyPair.new(Ref.b64d(spec['signerSecret'])), alg: spec['alg']) { |_req| world.v }
    end

    def set(nxt) = @world.v = JSON.parse(JSON.generate(nxt))
  end

  def self.source(s)
    initial = s['initial']
    case s['kind']
    when 'attested' then AttestedWorld.new(s, World.new(JSON.parse(JSON.generate(initial))))
    when 'memory' then P::InMemoryStateSource.new(initial, s['id']).tap { |m| m.define_singleton_method(:set) { |n| apply(n) } }
    else Wrapped.new(s, P::InMemoryStateSource.new(initial, s['id']))
    end
  end

  def self.refused = { '$err' => true }

  def self.registry_ops(ops)
    r = nil
    ops.map do |op, *a|
      case op
      when 'new' then r = P::PotentialRegistry.new
      when 'defaults' then r = P::PotentialRegistry.defaults
      when 'default-frozen' then r = P::DEFAULT_POTENTIALS
      when 'from'
        r = P::PotentialRegistry.from(a[0].to_h { |id, v| [id, v.is_a?(String) ? kind_fn(v) : { 'fn' => kind_fn(v['fn']), 'embedder' => v['embedder'] }] })
      when 'register'
        a.length > 2 ? r.register(a[0], kind_fn(a[1]), a[2]) : r.register(a[0], kind_fn(a[1]))
      when 'get' then next((s = r.get(a[0])) ? { 'embedder' => s['embedder'] } : nil)
      when 'has' then next r.has?(a[0])
      when 'ids' then next r.ids
      when 'freeze' then r.freeze!
      else raise 'bad op'
      end
      nil
    rescue StandardError
      refused
    end
  end

  def self.tracker(goal, commitment, initial, prs, gd, sources, ops)
    srcs = sources.map { |s| source(s) }
    t = P::ProgressTracker.new(goal, commitment.nil? ? P.goal_digest(goal) : commitment, initial, registry(prs), guard: guard(gd))
    ops.map do |op, *a|
      case op
      when 'step' then t.step(a[0], a[1])
      when 'stepObserved' then t.step_observed(srcs[a[0]], a[1])
      when 'apply'
        srcs[a[0]].set(a[1])
        nil
      when 'steps' then t.steps
      when 'currentStateDigest' then t.current_state_digest
      when 'reached' then t.reached?
      when 'state' then t.state
      when 'spent' then t.spent
      when 'remaining' then t.remaining
      else raise "bad op #{op}"
      end
    rescue StandardError
      refused
    end
  end

  def self.attested_source(spec, reqs)
    s = source(spec)
    obs = reqs.map do |r|
      s.observe(r)
    rescue StandardError
      refused
    end
    { 'observations' => obs, 'attestations' => s.respond_to?(:attestations) ? s.attestations : nil }
  end

  def self.anchor(steps, salt, prior)
    l = AtlasPca::TransparencyLedger.new('p')
    prior.each { |c| l.append_commitment(c) }
    P.anchor_trajectory_head(l, steps, salt: salt)
  end

  HANDLERS = {
    'constants' => -> { { 'PROGRESS_VERSION' => P::PROGRESS_VERSION, 'PROGRESS_SIG_DOMAIN' => P::PROGRESS_SIG_DOMAIN,
                          'TRAJECTORY_ANCHOR_DOMAIN' => P::TRAJECTORY_ANCHOR_DOMAIN, 'STATE_ATTESTATION_DOMAIN' => P::STATE_ATTESTATION_DOMAIN } },
    'l1FeaturePotential' => ->(o, s) { P.l1_feature_potential(o, s) },
    'dagRemainingPotential' => ->(o, s) { P.dag_remaining_potential(o, s) },
    'dagWeightedPotential' => ->(o, s) { P.dag_weighted_potential(o, s) },
    'registryOps' => ->(ops) { registry_ops(ops) },
    'goalDigest' => ->(g) { P.goal_digest(g) },
    'commitGoal' => ->(g) { P.commit_goal(g) },
    'verifyGoalCommitment' => ->(g, c) { P.verify_goal_commitment(g, c) },
    'stateDigest' => ->(s) { P.state_digest(s) },
    'trajectoryHead' => ->(steps) { P.trajectory_head(steps) },
    'progressStepDigest' => ->(s) { P.progress_step_digest(s) },
    'trajectoryAnchorCommit' => ->(salt, head) { P.trajectory_anchor_commit(salt, head) },
    'verifyTrajectoryAnchor' => ->(c, salt, head) { P.verify_trajectory_anchor(c, salt, head) },
    'anchorTrajectoryHead' => ->(steps, salt, prior) { anchor(steps, salt, prior) },
    'verifyStateAttestation' => ->(att, key, pin) { P.verify_state_attestation(att, key, pin) },
    'attestedStateVerifier' => ->(o, step) { P.attested_state_verifier(o).call(step) },
    'attestedSource' => ->(src, reqs) { attested_source(src, reqs) },
    'tracker' => ->(*a) { tracker(*a) },
    'verifyProgressStep' => ->(g, c, s, o) { P.verify_progress_step(g, c, s, opts(o)) },
    'verifyTrajectory' => ->(g, c, st, o) { P.verify_trajectory(g, c, st, opts(o)) },
    'verifySignedProgressStep' => ->(g, c, s, o) { P.verify_signed_progress_step(g, c, s, opts(o)) },
    'verifySignedTrajectory' => ->(g, c, st, o) { P.verify_signed_trajectory(g, c, st, opts(o)) },
    'signProgressStep' => ->(step, secret, holder) { P.sign_progress_step(step, AtlasPca::KeyPair.new(secret), holder) }
  }.freeze

  def self.norm_err(v)
    case v
    when Hash then v.key?('$err') ? { '$err' => true } : v.transform_values { |x| norm_err(x) }
    when Array then v.map { |x| norm_err(x) }
    else v
    end
  end

  # post-quantum attestations the reference accepts only through its unbound opt-out are refused here (the lead's ruling)
  def self.unbound_pq?(c)
    c['fn'] == 'verifyStateAttestation' && c['args'][2].is_a?(Hash) && c['args'][2]['allowUnboundPq'] == true && c['args'][0].key?('alg')
  end

  def self.same?(got, out, c)
    if unbound_pq?(c)
      UNBOUND << c['name']
      return out == true && got == false
    end
    Ref.canon(norm_err(got)) == Ref.canon(norm_err(out))
  end

  def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 723, BY_FN.values.sum(&:length)
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      ran = Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| self.class.dnum(a) }) },
                    skip: ->(c) { self.class.skip_pq?(c) }, compare: ->(got, out, c) { self.class.same?(got, out, c) })
      assert_equal TOTALS.fetch(fn) - BY_FN.fetch(fn).count { |c| self.class.skip_pq?(c) }, ran
    end
  end

  def test_the_unbound_post_quantum_cases_are_refused_and_counted
    assert PQ, 'this runtime must have ML-DSA-65' if ENV['PCA_REQUIRE_PQ'] == '1'
    skip 'no ML-DSA-65 in this OpenSSL' unless PQ
    test_replay_verifyStateAttestation
    assert_equal 2, UNBOUND.uniq.length, UNBOUND.uniq.inspect
  end
end
