# frozen_string_literal: true

# Replays the TS-reference oracle of the post-quantum software attestation root (test-data/ref-attest-pq-software.json.gz, 137 cases): minting
# statements under the ML-DSA and hybrid suites (byte for byte: signing is deterministic), the attestor's construction refusals and the
# verifier (suite and PQ requirement, trusted keys, the signature, the binding, the policy; verify-only statements under SLH-DSA). Every fn has
# a handler and the totals are asserted. Encodings: a key spec is {alg, edSecret?, seed?}, the secrets {"$seed": label} (32 bytes of
# sha256("atlas-pca/..." + label)); the ML-DSA key generation seed is that of the suite's family. The case `wrong-key-family` puts an ML-DSA-65 key
# where the ML-DSA-87 suite wants its own (the spec only names the seed), so it is built as the reference built it. Cases that need ML-DSA or
# SLH-DSA need a runtime that has them (OpenSSL >= 3.5).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefAttestPqSoftware < Minitest::Test
  A = AtlasPca
  P = AtlasPca::AttestPqSoftware
  BY_FN = Ref.load('attest-pq-software')
  PQ = A.supported_suites.include?('ml-dsa-65')
  CURRENT = [nil]

  def self.prim(alg) = alg.to_s.include?('ml-dsa-87') ? 'ML-DSA-87' : 'ML-DSA-65'

  def self.keys(spec)
    prim = CURRENT[0] == 'buildAttestor/wrong-key-family' ? 'ML-DSA-65' : prim(spec['alg'])
    { alg: spec['alg'], pq: spec['seed'] ? A::PqKeyPair.from_seed(prim, Ref.b64d(spec['seed'])) : nil,
      ed: spec['edSecret'] ? A::KeyPair.new(Ref.b64d(spec['edSecret'])) : nil }
  end

  def self.attestor_out(t) = { 'pqPublicKey' => t.pq_public_key }.merge(t.ed25519_public_key ? { 'ed25519PublicKey' => t.ed25519_public_key } : {})

  def self.verifier(c, evidence, seam: true)
    kw = { trusted_pq_public_keys: c['trustedPqPublicKeys'], trusted_ed25519_public_keys: c['trustedEd25519PublicKeys'], policy: c['policy'],
           allowed_suites: c['allowedSuites'], require_pq: c['requirePq'], require_hybrid: c['requireHybrid'] }
    kw[:resolve_evidence] = ->(_doc) { evidence } if seam && !c['noEvidenceSeam']
    P.create_pq_software_verifier(**kw)
  end

  HANDLERS = {
    'constants' => -> { { 'PQ_ATTEST_DOMAIN' => P::PQ_ATTEST_DOMAIN } },
    'attest' => lambda { |spec, claims|
      t = P.create_pq_software_attestor(**keys(spec))
      attestor_out(t).merge('statement' => t.attest(claims))
    },
    'buildAttestor' => ->(spec) { attestor_out(P.create_pq_software_attestor(**keys(spec))) },
    'verifyPq' => ->(sc) { verifier(sc['config'], sc['evidence']).verify({}, sc['input']['expected'], sc['input']['nowMs']) },
    'buildVerifier' => lambda { |c|
      verifier(c, nil)
      { 'built' => true }
    }
  }.freeze

  TOTALS = { 'constants' => 1, 'attest' => 29, 'buildAttestor' => 9, 'verifyPq' => 90, 'buildVerifier' => 8 }.freeze

  def self.pq_case?(c) = Ref.canon(c['args']).match?(/ml-dsa|slh-dsa/)

  def test_every_fn_of_the_corpus_has_a_handler_and_the_totals_are_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 137, BY_FN.values.sum(&:length)
  end

  def test_the_post_quantum_cases_run_where_required
    assert PQ, 'this runtime must have ML-DSA-65' if ENV['PCA_REQUIRE_PQ'] == '1'
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      k = self.class
      Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args) },
              skip: lambda { |c|
                CURRENT[0] = c['name']
                !PQ && k.pq_case?(c)
              })
    end
  end
end
