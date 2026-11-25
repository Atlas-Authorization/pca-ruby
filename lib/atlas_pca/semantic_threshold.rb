# frozen_string_literal: true

module AtlasPca
  # k-of-n signed semantic judge verdicts with a conformal threshold (the reference's `semantic-threshold`): a judge (a model, or a panel member)
  # scores whether an action is faithful to the signed goal and SIGNS the verdict; the verifier counts the distinct trusted judges that agree the
  # action is faithful, needs k of them, optionally requires a hardware attestation of each judge (its enclave measurement equals the signed
  # `judgeMeasurement` and satisfies an approved agent binding) and optionally requires the aggregate score to exceed a CALIBRATED cutoff (the
  # conformal quantile of the scores of known-unfaithful samples, so the false-allow rate is bounded by alpha).
  #
  # The score is quantised to integer parts per million BEFORE it is signed (`score_ppm`): a float never reaches the signature, so the signed
  # message is the strict canonical JSON. A post-quantum verdict verifies only under a PQ key pinned for its judge (this SDK has no unbound opt-out).
  # Records are String-keyed Hashes with the reference's member names.
  module SemanticThreshold
    UNDEF = IntentV2::UNDEF
    SEMANTIC_JUDGE_DOMAIN = "atlas-pca/semantic-judge/v1\0"
    SCORE_SCALE = 1_000_000

    module_function

    def member(h, k) = h.is_a?(Hash) && h.key?(k) ? h[k] : UNDEF

    # The score in integer parts per million, clamped to 0..1_000_000 (anything that is not a finite number is 0).
    def quantize_score(score)
      return 0 unless Attestation.finite?(score)

      q = (score * SCORE_SCALE).round
      q.negative? ? 0 : (q > SCORE_SCALE ? SCORE_SCALE : q)
    end

    # What a judge signs: the verdict's binding, `faithful` (true only for the boolean true), the quantised score and the measurement; a
    # non-default suite is bound in (`alg`, `pq_pk`; an absent pq_pk is an undefined member that the canonical form refuses).
    def statement_of(v)
      raise TypeError, "Cannot read properties of #{v.nil? ? 'null' : 'undefined'} (reading 'actionDigest')" unless v.is_a?(Hash) || v.is_a?(Array)

      jm = member(v, 'judgeMeasurement')
      base = { 'v' => 1, 'actionDigest' => member(v, 'actionDigest'), 'goalCommitment' => member(v, 'goalCommitment'), 'faithful' => member(v, 'faithful') == true,
               'score_ppm' => quantize_score(member(v, 'score')), 'judgeMeasurement' => jm.nil? || UNDEF.equal?(jm) ? '' : Attestation.jstr(jm) }
      suite = IntentV2.suite_of(member(v, 'alg'))
      return base if suite.nil? || suite == 'ed25519'

      base.merge('alg' => suite, 'pq_pk' => member(v, 'pq_pk'))
    end

    # The bytes signed: the domain, then the strict canonical JSON of the statement. Raises on a non-integer / negative-zero / non-finite member.
    def semantic_judge_message(statement) = SEMANTIC_JUDGE_DOMAIN.b + AtlasPca.canon_bytes(statement)

    def action_digest(action) = AtlasPca.hash_canonical(action)

    # A content address of a whole verdict (signatures included).
    def verdict_digest(v) = AtlasPca.hash_canonical(v)

    # Sign a verdict: `secret` is the judge's Ed25519 secret (32 bytes or a KeyPair), `v` {actionDigest, goalCommitment, faithful, score,
    # judgeMeasurement?}; `alg` (default ed25519) with `pq` (the ML-DSA-65 key pair of the ml-dsa-65 and hybrid suites). Raises on an unknown suite.
    def sign_judge_verdict(secret, v, alg: nil, pq: nil)
      jm = member(v, 'judgeMeasurement')
      jm = jm.nil? || UNDEF.equal?(jm) ? '' : Attestation.jstr(jm)
      suite = alg.nil? ? 'ed25519' : IntentV2.suite_of(alg)
      raise "signJudgeVerdict: unknown signature alg '#{Attestation.jstr(alg)}'" if suite.nil?

      signer = secret.is_a?(AtlasPca::KeyPair) ? secret : AtlasPca::KeyPair.new(secret)
      pq_pk = pq.respond_to?(:public) ? pq.public : UNDEF
      statement = statement_of(v.merge('judgeMeasurement' => jm, 'alg' => suite == 'ed25519' ? UNDEF : suite, 'pq_pk' => pq_pk))
      sig, pq_sig = AtlasPca.sign_with_suite(alg, signer, pq, semantic_judge_message(statement))
      out = { 'judge' => signer.public, 'actionDigest' => member(v, 'actionDigest'), 'goalCommitment' => member(v, 'goalCommitment'),
              'faithful' => member(v, 'faithful') == true, 'score' => member(v, 'score'), 'judgeMeasurement' => jm, 'sig' => sig }
      out = out.merge('alg' => alg, 'pq_pk' => pq.public) unless alg.nil? || alg == 'ed25519'
      out['pq_sig'] = pq_sig unless pq_sig.nil?
      out.reject { |_k, x| UNDEF.equal?(x) }
    end

    # True iff `v` is a well-formed verdict of a 32-byte judge key for exactly this action and goal, its score is in [0, 1], and its signature
    # verifies over the statement under its suite (a PQ verdict only under a key pinned in `pin['pqPins']`). Never raises.
    def verify_judge_verdict(v, expected, pin = nil)
      return false unless v.is_a?(Hash)

      judge = v['judge']
      return false unless judge.is_a?(String) && !AtlasPca.b64d(judge, 32).nil?
      return false unless v['actionDigest'].is_a?(String) && v['goalCommitment'].is_a?(String)
      return false if v['actionDigest'] != member(expected, 'actionDigest') || v['goalCommitment'] != member(expected, 'goalCommitment')
      return false unless v['faithful'] == true || v['faithful'] == false
      return false unless Attestation.finite?(v['score']) && v['score'] >= 0 && v['score'] <= 1
      return false unless v['judgeMeasurement'].is_a?(String) && v['sig'].is_a?(String)

      alg = v.key?('alg') ? v['alg'] : UNDEF
      return false if IntentV2.suite_of(alg).nil?

      msg = semantic_judge_message(statement_of(v))
      pins = pin.is_a?(Hash) && pin['pqPins'].is_a?(Hash) ? pin['pqPins'] : nil
      IntentV2.verify_pinned_suite(alg, judge, v.key?('pq_pk') ? v['pq_pk'] : UNDEF, msg, v['sig'], v.key?('pq_sig') ? v['pq_sig'] : UNDEF, pins)
    rescue StandardError
      false
    end

    # The attestation check of a classifier verdict (the reference's verifyClassifierAttestation): a verdict that is not an object is refused, an
    # error while checking fails closed; the verdict's `measurement` is the judge measurement.
    def verify_classifier_attestation(verdict, attestation, approved = nil)
      return { 'ok' => false, 'reason' => 'verdict must be an object' } unless verdict.is_a?(Hash)

      verify_judge_attestation(verdict['measurement'], attestation, approved)
    rescue StandardError => e
      { 'ok' => false, 'reason' => "attestation check error (fail closed): #{e.message}" }
    end

    # The hardware attestation gate of one judge: the verified attestation must be ok AND bound (a TEE report whose report_data binding the
    # verifier confirmed) with a measured identity whose runtime measurement equals the SIGNED `judge_measurement`, and (when `approved`, an
    # agent_binding) satisfy it. Returns {'ok' => true, 'measured'} or {'ok' => false, 'reason'}.
    def verify_judge_attestation(judge_measurement, attestation, approved = nil)
      unless attestation.is_a?(Hash) && attestation['ok'] == true
        reason = attestation.is_a?(Hash) ? attestation['reason'] : nil
        return { 'ok' => false, 'reason' => reason.nil? ? 'no verified attestation for this judge (fail-closed)' : reason }
      end
      return { 'ok' => false, 'reason' => 'judge attestation not bound to a TEE report (report_data binding unconfirmed)' } unless attestation['bound'] == true

      measured = attestation['measured']
      return { 'ok' => false, 'reason' => 'judge attestation carries no measured identity' } unless measured.is_a?(Hash)

      unless judge_measurement.is_a?(String) && !judge_measurement.empty?
        return { 'ok' => false, 'reason' => 'verdict carries no judgeMeasurement to bind to the attested identity' }
      end
      if member(measured, 'runtime_measurement') != judge_measurement
        return { 'ok' => false, 'reason' => 'attested enclave measurement does not match the signed judgeMeasurement' }
      end

      appraisal = Attestation.match_agent_binding(measured, approved)
      return { 'ok' => false, 'reason' => appraisal } if appraisal

      { 'ok' => true, 'measured' => measured }
    end

    def clamp_alpha(alpha)
      return 1 unless Attestation.finite?(alpha)
      return 5e-324 if alpha <= 0 # (0, 1]: alpha 0 is unsatisfiable, the smallest positive stands in

      alpha > 1 ? 1 : alpha
    end

    def labelled_unfaithful(samples)
      (samples.is_a?(Array) ? samples : []).select { |s| s.is_a?(Hash) && s['faithful'] == false && Attestation.finite?(s['score']) }.map { |s| s['score'] }
    end

    # The conformal cutoff of `calibration` {samples: [{score, faithful}], alpha}: the ceil((m + 1)(1 - alpha))-th smallest score of the m
    # known-unfaithful samples, Infinity when there are none or too few to certify alpha (so nothing passes). An alpha outside (0, 1] is clamped.
    def conformal_threshold(calibration)
      cal = calibration.is_a?(Hash) ? calibration : {}
      alpha = clamp_alpha(cal['alpha'])
      unfaithful = labelled_unfaithful(cal['samples'])
      m = unfaithful.length
      return Float::INFINITY if m.zero?

      rank = ((m + 1) * (1 - alpha)).ceil
      return Float::INFINITY if rank > m

      unfaithful.sort[[rank, 1].max - 1]
    end

    # The fraction of the unfaithful samples whose score is above `cutoff` (the empirical false-allow rate); 0 without unfaithful samples.
    def empirical_false_allow_rate(samples, cutoff)
      un = labelled_unfaithful(samples)
      un.empty? ? 0 : un.count { |s| s > cutoff }.fdiv(un.length)
    end

    # Count the distinct trusted judges that agree. `opts`: {'judgeKeys' (the trusted 32-byte judge keys), 'k' (an integer >= 1), 'goalCommitment',
    # 'actionDigest' (strings the verdicts must be for), 'calibration'?, 'pqPins'?, 'attestation'? => {'resolve' (a callable: verdict ->
    # verified attestation or nil), 'approved'?, 'require' (true to gate)}}. A verdict that does not verify, is from an untrusted judge, or (with
    # `require`) from a judge without an approved attestation does not count; a judge that gives conflicting verdicts (a different faithful or a
    # different quantised score) does not count at all. The aggregate is the mean of the agreeing judges' quantised scores, with a calibration it
    # must EXCEED the cutoff. Returns {'ok', 'agreeCount', 'aggregateScore', 'cutoff'?, 'reason'?}.
    def verify_semantic_threshold(verdicts, opts)
      o = opts.is_a?(Hash) ? opts : {}
      k = member(o, 'k')
      allow = (o['judgeKeys'].is_a?(Array) ? o['judgeKeys'] : []).select { |key| key.is_a?(String) && !AtlasPca.b64d(key, 32).nil? }
      unless o['actionDigest'].is_a?(String) && o['goalCommitment'].is_a?(String)
        return { 'ok' => false, 'agreeCount' => 0, 'aggregateScore' => 0, 'reason' => 'missing action/goal binding' }
      end
      unless Attestation.integer_number?(k) && k >= 1
        return { 'ok' => false, 'agreeCount' => 0, 'aggregateScore' => 0, 'reason' => "invalid quorum k=#{Attestation.jstr(k)}" }
      end

      att = o['attestation'].is_a?(Hash) ? o['attestation'] : nil
      by_judge = {}
      (verdicts.is_a?(Array) ? verdicts : []).each do |v|
        next unless v.is_a?(Hash) && v['judge'].is_a?(String) && allow.include?(v['judge'])
        next unless verify_judge_verdict(v, { 'actionDigest' => o['actionDigest'], 'goalCommitment' => o['goalCommitment'] }, o)
        next if att && att['require'] == true && !verify_judge_attestation(v['judgeMeasurement'], att['resolve'].call(v), att['approved'])['ok']

        g = (by_judge[v['judge']] ||= { faithful: [], score_q: [] })
        g[:faithful] << (v['faithful'] == true)
        g[:score_q] << quantize_score(v['score'])
      end
      agreeing = by_judge.select { |_j, g| g[:faithful].uniq == [true] && g[:score_q].uniq.length == 1 }.map { |j, g| [j, g[:score_q][0]] }
      agreeing.sort_by! { |j, _q| j.b }
      count = agreeing.length
      aggregate = count.zero? ? 0 : agreeing.reduce(0.0) { |acc, (_j, q)| acc + (q / SCORE_SCALE.to_f) } / count
      if count < k
        return { 'ok' => false, 'agreeCount' => count, 'aggregateScore' => aggregate, 'reason' => "only #{count} distinct trusted judge(s) agree, need #{k}" }
      end

      if o['calibration']
        cutoff = conformal_threshold(o['calibration'])
        unless aggregate > cutoff
          return { 'ok' => false, 'agreeCount' => count, 'aggregateScore' => aggregate, 'cutoff' => cutoff,
                   'reason' => "aggregateScore #{Attestation.jstr(aggregate)} does not exceed calibrated cutoff #{Attestation.jstr(cutoff)}" }
        end
        return { 'ok' => true, 'agreeCount' => count, 'aggregateScore' => aggregate, 'cutoff' => cutoff }
      end
      { 'ok' => true, 'agreeCount' => count, 'aggregateScore' => aggregate }
    end

    # The semantic hook (hooks.semantic): a lambda from the context to {'enforced', 'ok'?, 'reason'?}. `verdicts` and `goal_commitment` are
    # callables taking the context (the ensemble for this action, and the signed goal commitment); `action_digest` (default: the canonical hash of
    # ctx['pcactn']['action']) and `attestation` (-> the per-action attestation options) likewise. Without an ensemble or a goal commitment the hook
    # fails closed, unless `optional_when_absent` (then it is not enforced).
    def create_semantic_verifier(judge_keys:, k:, verdicts:, goal_commitment:, calibration: nil, action_digest: nil, optional_when_absent: false, attestation: nil)
      digest_of = action_digest || ->(ctx) { AtlasPca.hash_canonical(Attestation.dg(ctx, 'pcactn', 'action')) }
      lambda do |ctx|
        goal = goal_commitment.call(ctx)
        vs = verdicts.call(ctx)
        if !goal.is_a?(String) || vs.nil?
          next { 'enforced' => false } if optional_when_absent

          next { 'enforced' => true, 'ok' => false, 'reason' => 'no semantic ensemble available for this action (fail-closed)' }
        end
        att = attestation&.call(ctx)
        opts = { 'judgeKeys' => judge_keys, 'k' => k, 'goalCommitment' => goal, 'actionDigest' => digest_of.call(ctx), 'calibration' => calibration }
        opts['attestation'] = att if att
        res = verify_semantic_threshold(vs, opts)
        res['ok'] ? { 'enforced' => true, 'ok' => true } : { 'enforced' => true, 'ok' => false, 'reason' => res['reason'] || 'semantic threshold not met' }
      end
    end

    # The risk contribution of an aggregate score: 1 - score clamped to [0, 1]; 1 when the score is not a finite number.
    def semantic_risk_contribution(aggregate_score) = IntentRuntime.semantic_risk_contribution(aggregate_score)
  end
end
