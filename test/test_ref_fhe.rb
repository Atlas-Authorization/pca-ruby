# frozen_string_literal: true

# Replays the TS-reference oracle of the pure parts of pca-fhe (test-data/ref-fhe.json.gz): quantization, gate policy, claim
# binding, plaintext verdict, and the signed-claim / verdict-attestation layer. Signing seeds travel as {"$seed": label} and are
# derived by the harness; the BFV evaluation is not part of the corpus.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/fhe'
require 'minitest/autorun'

class TestRefFhe < Minitest::Test
  F = AtlasPca::Fhe
  O = F::Origin

  def self.claim_json(r) = r.ok ? { 'ok' => true, 'claim' => r.claim, 'digest' => r.digest } : { 'ok' => false, 'reason' => r.reason }

  def self.verify_claim(signed, e)
    used = e['used'].to_h { |k| [k, true] }
    max = e['max'].to_i
    guard = Object.new
    guard.define_singleton_method(:claim) do |k|
      return false if used.key?(k) || used.size >= max

      used[k] = true
    end
    claim_json(O.verify_signed_risk_claim(signed, O::ClaimExpectations.new(e['trustedSigners'], e['context'], e['binding'], e['policy'], guard)))
  end

  def self.verify_attest(a, holders_exp)
    r = O.verify_verdict_attestation(a, holders_exp['trustedHolders'], holders_exp['claimDigest'], holders_exp['gate'])
    r.ok ? { 'ok' => true, 'admit' => r.admit } : { 'ok' => false, 'reason' => r.reason }
  end

  CASES = Ref.load('fhe')

  MAP = {
    'transformedInputs' => ->(i) { F.transformed_inputs(i) },
    'quantizeRiskInputs' => ->(*a) { F.quantize_risk_inputs(*a) },
    'weightVector' => ->(w) { F.weight_vector(w) },
    'fheRiskPolicy' => ->(*a) { F.fhe_risk_policy(*a) },
    'plaintextVerdict' => ->(i, c, b) { F.plaintext_verdict(i, c, b) },
    'fromActn' => ->(a) { F.transformed_inputs(F.risk_inputs_from_pcactn(a)) },
    'binding' => ->(a) { F.binding_from_pcactn(a) },
    'sign' => ->(claim, seed, context, nonce) { O.sign_risk_claim(claim, Ref.b64d(seed), context, nonce) },
    'claimDigest' => ->(s) { O.signed_claim_digest(s) },
    'verifyClaim' => ->(s, e) { verify_claim(s, e) },
    'nonceGuard' => ->(max, keys) { g = O.memory_nonce_guard(max.to_i); keys.map { |k| g.claim(k) } },
    'attest' => ->(seed, signed, gate, admit) { O.attest_verdict(Ref.b64d(seed), signed, gate, admit == true) },
    'verifyAttest' => ->(a, e) { verify_attest(a, e) }
  }.freeze

  def test_corpus_is_covered
    assert_equal CASES.keys.sort, MAP.keys.sort, 'unmapped corpus functions'
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}_matches_the_reference") { Ref.run(self, CASES[fn], MAP[fn]) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1569, CASES.values.sum(&:length), 'fhe'
  end

end
