# frozen_string_literal: true

require 'json'
require 'securerandom'
require_relative 'js_compat'
require_relative 'actions_import_common'

module AtlasPca
  # Proof of progress toward a committed intent. The goal (objective, potential id, embedder id, metric, epsilon, exploration budget) is
  # hashed into a commitment; each action then carries a step proof that either makes progress (potential(after) <= potential(before) -
  # epsilon) or is charged to a bounded exploration budget. A verifier recomputes the potentials from the committed id and the carried
  # states: nothing the prover says about them is trusted. Every step commits, inside one hash-chained body, to the goal, the action
  # digest, the before and after STATE digests, the sequence number and the previous step; a step can be Ed25519-signed by the acting
  # holder. All quantities are safe integers. Potentials are pure functions resolved from a verifier-held registry; an unknown id fails
  # closed. Goals, steps, results and options are Hashes with the reference's member names (String keys); a potential is a callable
  # (objective, state) -> integer; a guard is a callable taking {'seq', 'before', 'after', 'action_digest'}; hooks answer true to allow.
  module Progress
    PROGRESS_VERSION = 2
    PROGRESS_SIG_DOMAIN = 'atlas-pca/progress-step/v2'
    TRAJECTORY_ANCHOR_DOMAIN = 'atlas-pca/trajectory-anchor/v1'
    STATE_ATTESTATION_DOMAIN = "atlas-pca/progress-state-attestation/v1\0"
    GENESIS = 'genesis'
    MAX_SAFE = 9_007_199_254_740_991
    UNDEF = V2JS::UNDEF

    # A refusal with a step-denial code.
    class ProgressError < StandardError
      attr_reader :code

      def initialize(code, msg)
        @code = code
        super(msg)
      end
    end

    module_function

    # ---- helpers

    def safe_int?(n) = (n.is_a?(Integer) || (n.is_a?(Float) && n.finite? && n == n.floor)) && n.abs <= MAX_SAFE

    def assert_int(n, what)
      raise TypeError, "#{what}: safe integer required" unless safe_int?(n)

      n.is_a?(Float) ? n.to_i : n
    end

    def str?(x) = x.is_a?(String)
    def obj?(x) = x.is_a?(Hash)
    def lenient(v) = ActionsImportCommon.lenient(v)
    def hash_of(v) = AtlasPca.hash_canonical(v)

    # A deep, canonical, detached copy of a state or objective, so later caller mutation cannot desync a proof.
    def snapshot(v) = JSON.parse(lenient(v), allow_nan: false, create_additions: false) # a bare scalar round-trips too

    # A member of the reference object (a null object throws, a non-object has no members, an absent member is UNDEF).
    def member(o, k)
      raise TypeError, "Cannot read properties of null (reading '#{k}')" if o.nil?

      o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF
    end

    def skey(x) = x.is_a?(Float) && x.finite? && x == x.floor ? x.to_i : x

    # ---- potentials

    # L1 distance in a committed feature space. objective {'target' => int[]}, state {'x' => int[]}.
    L1_FEATURE = lambda do |objective, state|
      t = member(objective, 'target')
      x = member(state, 'x')
      raise TypeError, 'l1-feature-v1: bad shape' if !t.is_a?(Array) || !x.is_a?(Array) || t.length != x.length

      d = 0
      t.each_index do |i|
        ti = assert_int(t[i], 'target')
        xi = assert_int(x[i], 'x')
        d += (ti - xi).abs
        assert_int(d, 'distance')
      end
      d
    end

    # Task-set remaining work. objective {'tasks' => [{'id', 'cost'}]}, state {'done' => string[]}.
    DAG_REMAINING = lambda do |objective, state|
      tasks = member(objective, 'tasks')
      done = member(state, 'done')
      raise TypeError, 'dag-remaining-v1: bad shape' if !tasks.is_a?(Array) || !done.is_a?(Array)

      ids = tasks.map { |t| skey(member(t, 'id')) }
      raise TypeError, 'dag-remaining-v1: duplicate task id' if ids.uniq.length != tasks.length

      done_set = done.map { |d| skey(d) }.uniq
      done_set.each { |d| raise TypeError, "dag-remaining-v1: unknown task #{Js.string(d)}" unless ids.include?(d) }
      rem = 0
      tasks.each do |t|
        cost = assert_int(member(t, 'cost'), 'cost')
        raise TypeError, 'negative cost' if cost.negative?

        rem += cost unless done_set.include?(skey(t['id']))
        assert_int(rem, 'remaining')
      end
      rem
    end

    # Weighted-DAG remaining cost with dependency integrity: tasks {'id', 'cost' >= 0, 'deps'?}, ids unique, deps known, graph acyclic;
    # the done set is unique and DEPENDENCY-CLOSED.
    DAG_WEIGHTED = lambda do |objective, state|
      tasks = member(objective, 'tasks')
      done = member(state, 'done')
      raise TypeError, 'dag-weighted-v1: bad shape' if !tasks.is_a?(Array) || !done.is_a?(Array)

      by_id = {}
      tasks.each do |t|
        raise TypeError, 'dag-weighted-v1: bad task' if !obj?(t) || !str?(t['id']) || t['id'].empty?
        raise TypeError, 'dag-weighted-v1: duplicate task id' if by_id.key?(t['id'])

        cost = assert_int(member(t, 'cost'), 'cost')
        raise TypeError, 'negative cost' if cost.negative?

        deps = t['deps'].nil? ? [] : t['deps']
        raise TypeError, 'dag-weighted-v1: bad deps' if !deps.is_a?(Array) || !deps.all? { |d| str?(d) }

        by_id[t['id']] = { 'cost' => cost, 'deps' => deps }
      end
      indeg = {}
      rev = {}
      by_id.each do |id, t|
        indeg[id] = t['deps'].uniq.length
        t['deps'].uniq.each do |d|
          raise TypeError, "dag-weighted-v1: bad dependency #{d}" if d == id || !by_id.key?(d)

          rev[d] = (rev[d] || []) + [id]
        end
      end
      q = indeg.select { |_, n| n.zero? }.keys
      seen = 0
      until q.empty?
        id = q.pop
        seen += 1
        (rev[id] || []).each do |n|
          indeg[n] -= 1
          q << n if indeg[n].zero?
        end
      end
      raise TypeError, 'dag-weighted-v1: cycle' if seen != by_id.length

      done_set = {}
      done.each do |d|
        raise TypeError, "dag-weighted-v1: unknown task #{Js.string(d)}" if !str?(d) || !by_id.key?(d)
        raise TypeError, 'dag-weighted-v1: duplicate done' if done_set.key?(d)

        done_set[d] = true
      end
      done_set.each_key do |d|
        by_id[d]['deps'].each { |dep| raise TypeError, "dag-weighted-v1: #{d} done before dependency #{dep}" unless done_set.key?(dep) }
      end
      rem = 0
      by_id.each do |id, t|
        rem += t['cost'] unless done_set.key?(id)
        assert_int(rem, 'remaining')
      end
      rem
    end

    # Verifier-held registry of version-pinned potentials. Lookups are by OWN key only, ids cannot be shadowed once registered, and the
    # registry can be frozen. An id that is not registered fails closed.
    class PotentialRegistry
      def initialize
        @m = {}
        @frozen = false
      end

      # Register `fn` under `id`; a duplicate is refused (ids are immutable).
      def register(id, fn, embedder = '')
        raise 'registry is frozen' if @frozen
        raise TypeError, 'potential id: 1..128 chars' if !id.is_a?(String) || id.empty? || Js.len16(id) > 128
        raise TypeError, 'potential must be a function' unless fn.respond_to?(:call)
        raise TypeError, 'embedder must be a string' unless embedder.is_a?(String)
        raise "potential #{id} already registered" if @m.key?(id)

        @m[id] = { 'fn' => fn, 'embedder' => embedder }
        self
      end

      def get(id) = @m[id]
      def has?(id) = @m.key?(id)
      def ids = @m.keys.sort_by { |s| s.encode('UTF-16BE').unpack('n*') }

      def freeze!
        @frozen = true
        self
      end

      # Build from a plain record {id => callable | {'fn' => callable, 'embedder'?}} (own keys only).
      def self.from(rec)
        r = new
        rec.each { |k, v| v.respond_to?(:call) ? r.register(k, v) : r.register(k, v['fn'], v['embedder'].nil? ? '' : v['embedder']) }
        r
      end

      # A fresh, mutable registry holding the three built-in potentials.
      def self.defaults
        new.register('l1-feature-v1', L1_FEATURE).register('dag-remaining-v1', DAG_REMAINING).register('dag-weighted-v1', DAG_WEIGHTED)
      end
    end

    # The frozen registry of the built-in potentials (used when none is supplied).
    DEFAULT_POTENTIALS = PotentialRegistry.defaults.freeze!

    def to_registry(r)
      return DEFAULT_POTENTIALS if r.nil?

      r.is_a?(PotentialRegistry) ? r : PotentialRegistry.from(r)
    end

    def l1_feature_potential(objective, state) = L1_FEATURE.call(objective, state)
    def dag_remaining_potential(objective, state) = DAG_REMAINING.call(objective, state)
    def dag_weighted_potential(objective, state) = DAG_WEIGHTED.call(objective, state)

    # ---- goal commitment

    def validate_goal(goal)
      raise TypeError, 'goal must be an object' unless obj?(goal)

      eps = assert_int(member(goal, 'epsilon').equal?(UNDEF) ? nil : goal['epsilon'], 'epsilon')
      budget = assert_int(member(goal, 'explorationBudget').equal?(UNDEF) ? nil : goal['explorationBudget'], 'explorationBudget')
      raise RangeError, 'epsilon must be >= 1' if eps < 1
      raise RangeError, 'explorationBudget must be >= 0' if budget.negative?
      raise TypeError, 'potential id required' if !str?(goal['potential']) || goal['potential'].empty?
      raise TypeError, 'metric must be a string' unless str?(goal['metric'])
      raise TypeError, 'embedder must be a string' if goal.key?('embedder') && !str?(goal['embedder'])
    end

    # The commitment hash of a goal: binds objective, potential id, embedder, metric, epsilon and budget.
    def goal_digest(goal)
      validate_goal(goal)
      raise TypeError, 'canonicalize: undefined is not serializable' unless goal.key?('objective')

      hash_of({ 't' => 'pca-goal', 'v' => PROGRESS_VERSION, 'objective' => goal['objective'], 'potential' => goal['potential'],
                'embedder' => goal['embedder'].nil? ? '' : goal['embedder'], 'metric' => goal['metric'], 'epsilon' => goal['epsilon'],
                'explorationBudget' => goal['explorationBudget'] })
    end

    # Commit a goal: {'goal' => a detached canonical snapshot, 'commitment'}.
    def commit_goal(goal)
      c = goal_digest(goal)
      { 'goal' => snapshot(goal), 'commitment' => c }
    end

    # A goal is bound iff it hashes to the commitment the grant carries. Never raises.
    def verify_goal_commitment(goal, commitment)
      goal_digest(goal) == commitment
    rescue StandardError
      false
    end

    # ---- steps

    def step_body_digest(body) = hash_of({ 't' => 'pca-progress-step', 'v' => PROGRESS_VERSION }.merge(body))

    # Digest committing to a state (canonicalizable JSON).
    def state_digest(state) = hash_of({ 't' => 'pca-state', 'state' => state })

    # The trajectory head to publish or anchor: the digest of the last step ('genesis' if empty).
    def trajectory_head(steps) = steps.empty? ? GENESIS : steps.last['digest']
    # `step.digest`: a null step throws, a value that is not an object has no such member
    def progress_step_digest(step)
      raise TypeError, "Cannot read properties of null (reading 'digest')" if step.nil?

      step.is_a?(Hash) ? step['digest'] : nil
    end

    # ---- anchoring the trajectory head into the transparency ledger (external rollback detection)

    # The salted commitment of a trajectory head: the opaque leaf appended to the transparency ledger.
    def trajectory_anchor_commit(salt, head)
      raise TypeError, 'trajectoryAnchorCommit: salt and head must be non-empty strings' if !str?(salt) || salt.empty? || !str?(head) || head.empty?

      hash_of({ 't' => TRAJECTORY_ANCHOR_DOMAIN, 'salt' => salt, 'head' => head })
    end

    # True iff salt + head reproduce the anchored commit. Never raises.
    def verify_trajectory_anchor(commit, salt, head)
      trajectory_anchor_commit(salt, head) == commit
    rescue StandardError
      false
    end

    # Anchor the current trajectory head into `ledger` (a TransparencyLedger) as a salted commitment. The salt defaults to 16 random bytes.
    # Returns {'head', 'salt', 'commit', 'index', 'ledgerHead' => {'size', 'root'}}.
    def anchor_trajectory_head(ledger, steps, salt: nil)
      head = trajectory_head(steps)
      salt = AtlasPca.b64e(SecureRandom.random_bytes(16)) if salt.nil?
      commit = trajectory_anchor_commit(salt, head)
      idx = ledger.append_commitment(commit)['index']
      { 'head' => head, 'salt' => salt, 'commit' => commit, 'index' => idx, 'ledgerHead' => ledger.head }
    end

    # ---- potential evaluation, mode and charge

    def resolve(goal, reg)
      spec = reg.get(goal['potential'])
      raise ProgressError.new('unknown-potential', "unknown potential #{goal['potential']}") if spec.nil?
      raise ProgressError.new('embedder-mismatch', 'embedder mismatch') if (spec['embedder'].nil? ? '' : spec['embedder']) != (goal['embedder'].nil? ? '' : goal['embedder'])

      spec
    end

    def potential_of(goal, reg, state)
      spec = resolve(goal, reg)
      begin
        p = assert_int(spec['fn'].call(goal['objective'], state), 'potential')
      rescue StandardError => e
        raise ProgressError.new('bad-potential', e.message)
      end
      raise ProgressError.new('bad-potential', 'potential must be >= 0') if p.negative?

      p
    end

    def denial_of(e) = e.is_a?(ProgressError) ? e.code : 'bad-potential'

    # The single source of truth for mode and charge: progress when after <= before - epsilon, or when the goal is reached (after == 0)
    # from a state closer than epsilon; otherwise exploration, charged the integer shortfall (>= 1).
    def classify(pb, pa, epsilon)
      required = pb - epsilon
      return { 'mode' => 'progress', 'charge' => 0 } if pa <= required || (pa.zero? && pb.positive?)

      charge = pa - required
      begin
        assert_int(charge, 'charge')
      rescue StandardError => e
        raise ProgressError.new('bad-potential', e.message)
      end
      { 'mode' => 'exploration', 'charge' => charge }
    end

    def run_guard(guard, transition)
      guard.call(transition) == true
    rescue StandardError
      false
    end

    # ---- trusted state

    # In-memory state source for tests and demos: the "world" is a value changed through #apply.
    class InMemoryStateSource
      attr_reader :id, :requests

      def initialize(initial, id = 'in-memory')
        @cur = Progress.snapshot(initial)
        @id = id
        @n = 0
        @requests = []
      end

      def apply(nxt) = @cur = Progress.snapshot(nxt)

      def observe(req)
        @requests << req
        state = Progress.snapshot(@cur)
        n = @n
        @n += 1
        { 'state' => state, 'state_digest' => Progress.state_digest(state), 'source' => @id,
          'evidence' => { 'kind' => 'in-memory', 'n' => n, 'prior' => req['prior_digest'], 'action' => req['action_digest'] } }
      end
    end

    # The message of a state attestation: domain || strictCanonical(suite-bound statement).
    def state_attestation_message(a, alg, pq_pk)
      body = { 'source' => a['source'], 'goal_commitment' => a['goal_commitment'], 'action_digest' => a['action_digest'],
               'prior_digest' => a['prior_digest'], 'state_digest' => a['state_digest'] }
      STATE_ATTESTATION_DOMAIN.b + AtlasPca.canon_bytes(IntentV2.bind_suite_fields(body, alg, pq_pk))
    end

    # Verify a state attestation's signature under a TRUSTED source public key, bound to its exact statement. Never raises.
    # `pin` is {'pqPins'?}; a post-quantum attestation verifies only under a pinned PQ key (no unbound opt-out in this SDK).
    def verify_state_attestation(att, trusted_public_key, pin = nil)
      return false if !att.is_a?(Hash) || !str?(att['sig']) || !str?(att['source'])
      return false if !str?(trusted_public_key) || trusted_public_key.empty?

      alg = att.key?('alg') ? att['alg'] : UNDEF
      return false if IntentV2.suite_of(alg).nil?

      pq_pk = att.key?('pq_pk') ? att['pq_pk'] : UNDEF
      pins = pin.is_a?(Hash) && pin['pqPins'].is_a?(Hash) ? pin['pqPins'] : nil
      IntentV2.verify_pinned_suite(alg, trusted_public_key, pq_pk, state_attestation_message(att, alg, pq_pk), att['sig'],
                                   att.key?('pq_sig') ? att['pq_sig'] : UNDEF, pins)
    rescue StandardError
      false
    end

    # A state source whose observations carry a VERIFIABLE SIGNED attestation: it wraps a real-world observer (a block returning the
    # post-action state for a request) and signs {source, goal, action, prior -> state} with the suite machinery.
    class AttestedStateSource
      attr_reader :id, :public_key

      def initialize(id:, signer:, alg: nil, pq: nil, &observe_state)
        raise ArgumentError, 'AttestedStateSource: id is required' if !id.is_a?(String) || id.empty?
        raise ArgumentError, 'AttestedStateSource: observeState must be a function' if observe_state.nil?
        raise ArgumentError, "AttestedStateSource: unknown signature alg '#{alg}'" unless alg.nil? || AtlasPca::SIG_SUITES.key?(alg)

        @id = id
        @signer = signer
        @public_key = signer.public
        @observe_state = observe_state
        @alg = alg
        @pq = pq
        @attestations = []
      end

      # The signed attestations emitted so far (hand these to attested_state_verifier).
      def attestations = @attestations.dup

      def observe(req)
        state = Progress.snapshot(@observe_state.call(req))
        digest = Progress.state_digest(state)
        stmt = { 'source' => @id, 'goal_commitment' => req['goal_commitment'], 'action_digest' => req['action_digest'],
                 'prior_digest' => req['prior_digest'], 'state_digest' => digest }
        pq_pk = @alg.nil? || @alg == 'ed25519' ? UNDEF : (@pq&.public || UNDEF)
        sig, pq_sig = AtlasPca.sign_with_suite(@alg, @signer, @pq, Progress.state_attestation_message(stmt, @alg.nil? ? UNDEF : @alg, pq_pk))
        att = stmt.merge('sig' => sig)
        att = att.merge('alg' => @alg, 'pq_pk' => pq_pk) unless @alg.nil? || @alg == 'ed25519'
        att = att.merge('pq_sig' => pq_sig) unless pq_sig.nil?
        @attestations << att
        { 'state' => state, 'state_digest' => digest, 'source' => @id, 'evidence' => att }
      end
    end

    # The hook for verify_progress_step / verify_trajectory: per step it finds the trusted key of `state_source`, the attestation of the
    # step's {action, before -> after} digests, requires the step's evidence digest to reproduce that attestation exactly, and verifies the
    # signature. opts: {'trustedKeys' => {source => public key}, 'pqPins'?, 'attestations' => [...]}.
    def attested_state_verifier(opts)
      by_key = {}
      (opts['attestations'] || []).each do |att|
        next unless att.is_a?(Hash) && str?(att['action_digest']) && str?(att['prior_digest']) && str?(att['state_digest'])

        by_key["#{att['action_digest']}\0#{att['prior_digest']}\0#{att['state_digest']}"] = att
      end
      lambda do |step|
        keys = opts['trustedKeys']
        pub = keys.is_a?(Hash) && keys.key?(step['state_source']) ? keys[step['state_source']] : nil
        next false if !str?(pub) || pub.empty?

        att = by_key["#{step['action_digest']}\0#{step['before_digest']}\0#{step['after_digest']}"]
        next false if att.nil? || att['source'] != step['state_source']
        next false if hash_of({ 't' => 'pca-evidence', 'e' => att }) != step['evidence_digest']

        verify_state_attestation(att, pub, opts)
      rescue StandardError
        false
      end
    end

    # ---- prover side

    # Stateful tracker of one trajectory: holds the last state, chain head and exploration spent. A step that would push spent over
    # budget is REFUSED (no proof is produced, the state does not advance): the "forces step-up or denial" mechanism.
    class ProgressTracker
      attr_reader :goal, :commitment, :spent, :state

      # `guard` is the negative-authority callable applied to every transition.
      def initialize(goal, commitment, initial, registry = nil, guard: nil)
        raise 'goal does not match commitment' unless Progress.verify_goal_commitment(goal, commitment)

        @goal = Progress.snapshot(goal)
        @commitment = commitment
        @guard = guard
        @reg = Progress.to_registry(registry)
        @seq = 0
        @head = GENESIS
        @spent = 0
        @log = []
        @state = Progress.snapshot(initial)
        @cur_digest = Progress.state_digest(@state)
        Progress.potential_of(@goal, @reg, @state) # fail fast: unknown id / embedder / bad initial state
      end

      def remaining = @goal['explorationBudget'] - @spent
      def current_state_digest = @cur_digest
      def reached? = Progress.potential_of(@goal, @reg, @state).zero?
      def steps = @log.dup

      # Attempt a step to a self-reported `after`. Does not advance on denial.
      def step(after, action_digest) = advance(after, action_digest, '', '')

      # Observe the post-action state from a trusted source and step to it; the source id and evidence digest are committed in the step.
      def step_observed(source, action_digest)
        obs = source.observe({ 'action_digest' => action_digest, 'goal_commitment' => @commitment, 'prior_digest' => @cur_digest })
        if !obs.is_a?(Hash) || obs['source'] != source.id || obs['state_digest'] != Progress.state_digest(obs['state'])
          return { 'ok' => false, 'reason' => 'state-source-mismatch', 'stepUp' => false }
        end

        advance(obs['state'], action_digest, source.id, Progress.hash_of({ 't' => 'pca-evidence', 'e' => obs['evidence'] }))
      rescue StandardError
        { 'ok' => false, 'reason' => 'state-source-mismatch', 'stepUp' => false }
      end

      private

      def advance(after_in, action_digest, state_source, evidence_digest)
        return { 'ok' => false, 'reason' => 'malformed', 'stepUp' => false } if !action_digest.is_a?(String) || action_digest.empty?

        begin
          after = Progress.snapshot(after_in)
          after_digest = Progress.state_digest(after)
          pb = Progress.potential_of(@goal, @reg, @state)
          pa = Progress.potential_of(@goal, @reg, after)
          cls = Progress.classify(pb, pa, @goal['epsilon'])
        rescue StandardError => e
          return { 'ok' => false, 'reason' => Progress.denial_of(e), 'stepUp' => false }
        end
        if @guard && !Progress.run_guard(@guard, { 'seq' => @seq, 'before' => @state, 'after' => after, 'action_digest' => action_digest })
          return { 'ok' => false, 'reason' => 'prohibited', 'stepUp' => false }
        end

        next_spent = @spent + cls['charge']
        return { 'ok' => false, 'reason' => 'exploration-exhausted', 'stepUp' => true } if !Progress.safe_int?(next_spent) || next_spent > @goal['explorationBudget']

        body = { 'goal_commitment' => @commitment, 'seq' => @seq, 'before' => @state, 'after' => after, 'before_digest' => @cur_digest,
                 'after_digest' => after_digest, 'action_digest' => action_digest, 'mode' => cls['mode'], 'potential_before' => pb,
                 'potential_after' => pa, 'charge' => cls['charge'], 'state_source' => state_source, 'evidence_digest' => evidence_digest,
                 'prev' => @head }
        step = body.merge('digest' => Progress.step_body_digest(body))
        @log << step
        @seq += 1
        @head = step['digest']
        @spent = next_spent
        @state = after
        @cur_digest = after_digest
        { 'ok' => true, 'step' => step, 'spent' => @spent, 'remaining' => remaining }
      end
    end

    # ---- verifier side

    STEP_INTS = %w[seq potential_before potential_after charge].freeze
    STEP_STRS = %w[goal_commitment before_digest after_digest action_digest state_source evidence_digest prev digest].freeze

    def step?(s)
      obj?(s) && STEP_STRS.all? { |k| str?(s[k]) } && STEP_INTS.all? { |k| safe_int?(s[k]) } && s['seq'] >= 0 &&
        %w[progress exploration].include?(s['mode']) && s.key?('before') && s.key?('after')
    end

    def fail_step(reason) = { 'ok' => false, 'reason' => reason }
    def given?(opts, k) = opts.key?(k)

    # Stateless re-check of one step against the committed goal: the state digests, both potentials, the mode and the charge are all
    # recomputed. Never raises. opts (the reference's names): expectedSeq, expectedPrev, expectedActionDigest, expectedBeforeDigest,
    # expectedAfterDigest, registry, guard, trustedStateSources, requireAttestedState, attestation.
    def verify_progress_step(goal, commitment, step, opts = {})
      return fail_step('goal-mismatch') unless verify_goal_commitment(goal, commitment)
      return fail_step('malformed') unless step?(step)
      return fail_step('goal-mismatch') if step['goal_commitment'] != commitment
      return fail_step('seq-mismatch') if given?(opts, 'expectedSeq') && step['seq'] != opts['expectedSeq']
      return fail_step('chain-break') if given?(opts, 'expectedPrev') && step['prev'] != opts['expectedPrev']
      return fail_step('action-mismatch') if given?(opts, 'expectedActionDigest') && step['action_digest'] != opts['expectedActionDigest']
      return fail_step('state-mismatch') if given?(opts, 'expectedBeforeDigest') && step['before_digest'] != opts['expectedBeforeDigest']
      return fail_step('state-mismatch') if given?(opts, 'expectedAfterDigest') && step['after_digest'] != opts['expectedAfterDigest']
      return fail_step('digest-mismatch') if step_body_digest(step.reject { |k, _| k == 'digest' }) != step['digest']
      return fail_step('state-digest-mismatch') if state_digest(step['before']) != step['before_digest'] || state_digest(step['after']) != step['after_digest']

      reg = to_registry(opts['registry'])
      begin
        pb = potential_of(goal, reg, step['before'])
        pa = potential_of(goal, reg, step['after'])
        cls = classify(pb, pa, goal['epsilon'])
      rescue StandardError => e
        return fail_step(denial_of(e))
      end
      return fail_step('potential-mismatch') if pb != step['potential_before'] || pa != step['potential_after']
      return fail_step('mode-mismatch') if step['mode'] != cls['mode']
      return fail_step('charge-mismatch') if step['charge'] != cls['charge']

      trusted = opts['trustedStateSources']
      return fail_step('untrusted-state-source') if Js.truthy?(trusted) && !trusted.include?(step['state_source'])
      return fail_step('untrusted-state-source') if opts['requireAttestedState'] != false && step['state_source'].empty?

      guard = opts['guard']
      if Js.truthy?(guard) && !run_guard(guard, { 'seq' => step['seq'], 'before' => step['before'], 'after' => step['after'], 'action_digest' => step['action_digest'] })
        return fail_step('prohibited')
      end
      if Js.truthy?(opts['attestation'])
        ok = begin
          opts['attestation'].call(step) == true
        rescue StandardError
          false
        end
        return fail_step('attestation-failed') unless ok
      end
      { 'ok' => true, 'charge' => cls['charge'] }
    rescue StandardError
      fail_step('malformed')
    end

    # Verify a whole trajectory: the goal binding, every step re-checked, hash-chained, states contiguous, starting from `initial` or
    # `initialDigest` if given, per-step action binding by `expectedActionDigests`, and the strict invariant sum(charge) <= budget.
    def verify_trajectory(goal, commitment, steps, opts = {})
      return { 'ok' => false, 'reason' => 'goal-mismatch', 'at' => -1 } unless verify_goal_commitment(goal, commitment)
      return { 'ok' => false, 'reason' => 'malformed', 'at' => -1 } unless steps.is_a?(Array)

      digests = opts['expectedActionDigests']
      if Js.truthy?(digests) && digests.length != steps.length
        return { 'ok' => false, 'reason' => 'action-mismatch', 'at' => [digests.length, steps.length].min }
      end
      begin
        anchor = if !opts['initialDigest'].nil? then opts['initialDigest']
                 else opts.key?('initial') ? state_digest(opts['initial']) : nil
                 end
      rescue StandardError
        return { 'ok' => false, 'reason' => 'malformed', 'at' => -1 }
      end
      prev = GENESIS
      spent = 0
      final = -1
      if steps.empty? && opts.key?('initial')
        begin
          final = potential_of(goal, to_registry(opts['registry']), opts['initial'])
        rescue StandardError => e
          return { 'ok' => false, 'reason' => denial_of(e), 'at' => -1 }
        end
      end
      steps.each_with_index do |s, i|
        step_opts = opts.merge('expectedSeq' => i, 'expectedPrev' => prev)
        step_opts['expectedActionDigest'] = digests[i] if Js.truthy?(digests)
        r = verify_progress_step(goal, commitment, s, step_opts)
        return { 'ok' => false, 'reason' => r['reason'], 'at' => i } unless r['ok']
        return { 'ok' => false, 'reason' => 'discontinuous-state', 'at' => i } if !anchor.nil? && s['before_digest'] != anchor

        spent += r['charge']
        return { 'ok' => false, 'reason' => 'budget-exceeded', 'at' => i } if !safe_int?(spent) || spent > goal['explorationBudget']

        anchor = s['after_digest']
        prev = s['digest']
        final = s['potential_after']
      end
      { 'ok' => true, 'spent' => spent, 'remaining' => goal['explorationBudget'] - spent, 'reached' => final.zero?, 'finalPotential' => final,
        'steps' => steps.length, 'head' => prev }
    end

    # ---- signed proofs (Ed25519, domain-separated)

    def sig_message(step, holder)
      # a step missing a bound member has no canonical form (the reference cannot encode an undefined member)
      %w[goal_commitment action_digest before_digest after_digest seq prev digest].each do |k|
        raise TypeError, 'canonicalize: undefined is not serializable' unless step.is_a?(Hash) && step.key?(k)
      end
      AtlasPca.canon_bytes({ 'd' => PROGRESS_SIG_DOMAIN,
                             'b' => { 'holder' => holder, 'goal_commitment' => step['goal_commitment'], 'action_digest' => step['action_digest'],
                                      'before_digest' => step['before_digest'], 'after_digest' => step['after_digest'], 'seq' => step['seq'],
                                      'prev' => step['prev'], 'step_digest' => step['digest'] } })
    end

    # Sign a step: {'step', 'holder', 'sig'}. `holder_public_key` is the base64url public key committed in the message (it is not checked
    # against the key; verification then fails).
    def sign_progress_step(step, key, holder_public_key)
      { 'step' => step, 'holder' => holder_public_key, 'sig' => AtlasPca.b64e(key.sign(sig_message(step, holder_public_key))) }
    end

    # Verify a signed step offline: the signature (strict Ed25519, domain-separated) by the expected holder over the binding fields, THEN
    # the full step re-check. opts as verify_progress_step plus the REQUIRED expectedActionDigest and expectedHolder.
    def verify_signed_progress_step(goal, commitment, signed, opts)
      return fail_step('malformed') if !obj?(signed) || !str?(signed['holder']) || !str?(signed['sig']) || !step?(signed['step'])
      return fail_step('holder-mismatch') if signed['holder'] != opts['expectedHolder']
      return fail_step('action-mismatch') if signed['step']['action_digest'] != opts['expectedActionDigest']
      return fail_step('goal-mismatch') if signed['step']['goal_commitment'] != commitment
      return fail_step('bad-signature') unless AtlasPca.verify_b64u(signed['holder'], sig_message(signed['step'], signed['holder']), signed['sig'])

      verify_progress_step(goal, commitment, signed['step'], opts)
    rescue StandardError
      fail_step('malformed')
    end

    # Verify the signatures on every step and then the whole trajectory. opts as verify_trajectory plus the REQUIRED expectedHolder.
    def verify_signed_trajectory(goal, commitment, signed, opts)
      return { 'ok' => false, 'reason' => 'malformed', 'at' => -1 } unless signed.is_a?(Array)

      digests = opts['expectedActionDigests']
      return { 'ok' => false, 'reason' => 'action-mismatch', 'at' => [digests.length, signed.length].min } if digests.length != signed.length

      signed.each_with_index do |sp, i|
        begin
          return { 'ok' => false, 'reason' => 'malformed', 'at' => i } if !obj?(sp) || !str?(sp['holder']) || !str?(sp['sig']) || !step?(sp['step'])
          return { 'ok' => false, 'reason' => 'holder-mismatch', 'at' => i } if sp['holder'] != opts['expectedHolder']
          return { 'ok' => false, 'reason' => 'action-mismatch', 'at' => i } if sp['step']['action_digest'] != digests[i]
          return { 'ok' => false, 'reason' => 'bad-signature', 'at' => i } unless AtlasPca.verify_b64u(sp['holder'], sig_message(sp['step'], sp['holder']), sp['sig'])
        rescue StandardError
          return { 'ok' => false, 'reason' => 'malformed', 'at' => i }
        end
      end
      verify_trajectory(goal, commitment, signed.map { |s| s['step'] }, opts.reject { |k, _| k == 'expectedHolder' })
    end
  end
end
