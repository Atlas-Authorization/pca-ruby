# frozen_string_literal: true

# Replays the TS-reference oracle of the semantic judge threshold (test-data/ref-semantic-threshold.json.gz, 186 cases): quantising a score, the signed
# statement and message, verdict digests, signing a verdict under the Ed25519, ML-DSA-65 and hybrid suites (byte for byte: signing is deterministic),
# verifying a verdict, the judge attestation gate, the k-of-n threshold with a calibration, the attestation gate and PQ pins, the hook over several
# contexts and the risk contribution. Every fn has a handler and the totals are asserted. Encodings: {"$num": ...} a non-finite number;
# {"$bytes": {"$seed": label}} the 32-byte Ed25519 secret sha256("atlas-pca-conformance/" + label); a suite is {alg, pqSeed?} (the ML-DSA-65 key generation
# seed). The two cases the reference accepts only through its `allowUnboundPq` switch (a PQ verdict whose key is not pinned) are asserted REFUSED:
# this SDK has no such switch (the count is asserted). Cases that sign or verify with ML-DSA need a runtime that has it (OpenSSL >= 3.5).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefSemanticThreshold < Minitest::Test
  A = AtlasPca
  S = AtlasPca::SemanticThreshold
  BY_FN = Ref.load('semantic-threshold')
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze
  PQ = A.supported_suites.include?('ml-dsa-65')

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  def self.attestation(a)
    return nil unless a.is_a?(Hash)

    by = a['byJudge'] || {}
    { 'resolve' => ->(v) { by[v['judge']] }, 'approved' => a['approved'], 'require' => a['require'] }
  end

  def self.threshold(verdicts, opts)
    o = opts.dup
    o['attestation'] = attestation(o['attestation']) if o.key?('attestation')
    S.verify_semantic_threshold(verdicts, o)
  end

  def self.hook(opts, ctxs)
    digest = opts['actionDigestMode'].to_s.start_with?('fixed:') ? ->(_c) { opts['actionDigestMode'].delete_prefix('fixed:') } : nil
    h = S.create_semantic_verifier(judge_keys: opts['judgeKeys'], k: opts['k'], calibration: opts['calibration'], verdicts: ->(c) { c['verdicts'] },
                                   goal_commitment: ->(c) { c['goal'] }, action_digest: digest, optional_when_absent: opts['optionalWhenAbsent'] == true,
                                   attestation: ->(c) { attestation(c['attestation']) })
    ctxs.map { |c| h.call(c) }
  end

  def self.sign(secret, v, suite)
    kw = {}
    if suite.is_a?(Hash)
      kw[:alg] = suite['alg']
      kw[:pq] = A::PqKeyPair.from_seed('ML-DSA-65', suite['pqSeed']) if suite['pqSeed']
    end
    S.sign_judge_verdict(secret, v, **kw)
  end

  HANDLERS = {
    'constants' => -> { { 'SEMANTIC_JUDGE_DOMAIN' => S::SEMANTIC_JUDGE_DOMAIN, 'SCORE_SCALE' => S::SCORE_SCALE } },
    'quantizeScore' => ->(x) { S.quantize_score(x) },
    'statementOf' => ->(v) { S.statement_of(v).reject { |_k, x| A::IntentV2::UNDEF.equal?(x) } },
    'semanticJudgeMessage' => ->(st) { { '$bytes' => Ref.b64e(S.semantic_judge_message(st)) } },
    'verdictDigest' => ->(v) { S.verdict_digest(v) },
    'signJudgeVerdict' => ->(secret, v, suite) { sign(secret, v, suite) },
    'verifyJudgeVerdict' => ->(v, expected, pin) { S.verify_judge_verdict(v, expected, pin) },
    'verifyJudgeAttestation' => ->(m, att, approved) { S.verify_judge_attestation(m, att, approved) },
    'verifySemanticThreshold' => ->(verdicts, opts) { threshold(verdicts, opts) },
    'semanticVerifier' => ->(opts, ctxs) { hook(opts, ctxs) },
    'semanticRiskContribution' => ->(x) { S.semantic_risk_contribution(x) }
  }.freeze

  TOTALS = { 'constants' => 1, 'quantizeScore' => 26, 'statementOf' => 21, 'semanticJudgeMessage' => 11, 'verdictDigest' => 4, 'signJudgeVerdict' => 13,
             'verifyJudgeVerdict' => 27, 'verifyJudgeAttestation' => 18, 'verifySemanticThreshold' => 39, 'semanticVerifier' => 12,
             'semanticRiskContribution' => 14 }.freeze

  def self.pq_case?(c) = Ref.canon(c['args']).match?(/ml-dsa/)

  # the cases the reference accepts only through allowUnboundPq
  def self.unbound?(c)
    s = Ref.canon(c['args'])
    s.include?('"allowUnboundPq":true') && (c['out'] == true || (c['out'].is_a?(Hash) && c['out']['ok'] == true))
  end

  def self.same?(got, out, c)
    if unbound?(c)
      return got == false if out == true

      return got.is_a?(Hash) && got['ok'] == false && got['agreeCount'] == 0
    end
    Ref.canon(got) == Ref.canon(out)
  end

  def test_every_fn_of_the_corpus_has_a_handler_and_the_totals_are_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 186, BY_FN.values.sum(&:length)
    assert_equal 2, BY_FN.values.flatten.count { |c| self.class.unbound?(c) }, 'the cases the reference accepts only under allowUnboundPq'
  end

  def test_the_post_quantum_cases_run_where_required
    assert PQ, 'this runtime must have ML-DSA-65' if ENV['PCA_REQUIRE_PQ'] == '1'
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      k = self.class
      Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| k.dnum(a) }) }, skip: ->(c) { !PQ && k.pq_case?(c) },
              compare: ->(got, out, c) { k.same?(got, out, c) })
    end
  end
end
