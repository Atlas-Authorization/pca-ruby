# frozen_string_literal: true

# Replays the TS-reference oracle of the safety certificate (test-data/ref-safety-certificate.json.gz, 262 cases): the bound and
# its statement, the check rows, the signed message, issuing under the Ed25519, ML-DSA-65 and hybrid suites, verifying (reason
# strings compare exactly), encode / decode and the compliance row. Every fn has a handler and the total is asserted.
# Encodings: {"$num": ...} is a non-finite number; {"$bytes": {"$seed": label}} the 32-byte secret sha256("atlas-pca-conformance/"
# + label); a suite is {alg, pqSeed?} (the ML-DSA-65 key generation seed; signing is deterministic, so signatures compare byte for
# byte). Two verify cases pass in the reference only under its `allowUnboundPq` switch: this SDK has no such switch (a
# certificate's own PQ key is never enough), so they are replayed with the refusal this SDK must give. The evidence URL with a
# non-ASCII host needs the Ada URL library; without it that case is skipped (it fails instead when PCA_ADA_REQUIRED is 1).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefSafetyCertificate < Minitest::Test
  A = AtlasPca
  S = AtlasPca::SafetyCertificate
  BY_FN = Ref.load('safety-certificate')
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze
  PQ = A.supported_suites.include?('ml-dsa-65')
  ADA = A::AdaIdna.available?
  UNBOUND_REFUSAL = 'guardian signature does not verify'

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  def self.issue(a)
    kw = { policy: a['policy'], guardian: A::KeyPair.new(a['guardianSecret']), issued_at: a['issuedAt'] }
    kw[:grant_ref] = a['grantRef'] if a.key?('grantRef')
    kw[:instance] = a['instance'] if a.key?('instance')
    kw[:checks] = a['checks'] if a.key?('checks')
    if a['suite'].is_a?(Hash)
      kw[:alg] = a['suite']['alg']
      kw[:pq] = A::PqKeyPair.from_seed('ML-DSA-65', a['suite']['pqSeed']) if a['suite'].key?('pqSeed')
    end
    S.issue_safety_certificate(**kw)
  end

  HANDLERS = {
    'constants' => lambda {
      { 'MAX_SAFETY_CHECKS' => A::MAX_SAFETY_CHECKS, 'SAFETY_CERT_DOMAIN' => A::SAFETY_CERT_DOMAIN, 'SAFETY_CERT_SCOPE' => A::SAFETY_CERT_SCOPE,
        'SAFETY_CERT_VERSION' => A::SAFETY_CERT_VERSION }
    },
    'safetyCertificateBound' => ->(p) { S.safety_certificate_bound(p) },
    'safetyCertificateStatement' => ->(bound) { S.safety_certificate_statement(bound) },
    'validateSafetyChecks' => ->(checks) { S.validate_safety_checks(checks) },
    'safetyCertificateMessage' => ->(c) { { '$bytes' => Ref.b64e(S.safety_certificate_message(c)) } },
    'issueSafetyCertificate' => ->(a) { issue(a) },
    'verifySafetyCertificate' => ->(cert, opts) { S.verify_safety_certificate(cert, opts) },
    'encodeSafetyCertificate' => ->(cert) { S.encode_safety_certificate(cert) },
    'decodeSafetyCertificate' => ->(text) { S.decode_safety_certificate(text) },
    'safetyCertificateForCompliance' => ->(cert, opts) { S.safety_certificate_for_compliance(cert, opts) }
  }.freeze

  def self.unbound?(c) = c['args'][1].is_a?(Hash) && c['args'][1]['allowUnboundPq'] == true
  def self.idn_url?(c) = Ref.canon(c['args']).match?(%r{https://[^"/]*[^\x00-\x7F]})

  # a case that signs or verifies with ML-DSA needs a runtime that has it (OpenSSL >= 3.5)
  def self.pq_case?(c)
    a = c['args'][0]
    a.is_a?(Hash) && ((a['suite'].is_a?(Hash) && a['suite'].key?('pqSeed')) || (a['alg'].is_a?(String) && a['alg'].include?('ml-dsa')))
  end

  def test_every_fn_of_the_corpus_has_a_handler
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal 262, BY_FN.values.sum(&:length)
    assert_equal 2, BY_FN.values.flatten.count { |c| self.class.unbound?(c) }, 'the cases the reference passes under allowUnboundPq'
    assert_equal 1, BY_FN.values.flatten.count { |c| self.class.idn_url?(c) }, 'the cases with a non-ASCII host'
  end

  def test_the_post_quantum_and_url_cases_run_where_required
    assert PQ, 'this runtime must have ML-DSA-65' if ENV['PCA_REQUIRE_PQ'] == '1'
    assert ADA, 'the Ada URL library is required here (PCA_ADA_REQUIRED) and is not available' if ENV['PCA_ADA_REQUIRED'] == '1'
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      k = self.class
      compare = lambda do |got, out, c|
        if k.unbound?(c)
          assert_equal true, out['ok'], 'the reference accepts the certificate under allowUnboundPq'
          next Ref.canon(got) == Ref.canon({ 'ok' => false, 'reason' => UNBOUND_REFUSAL, 'recomputedBound' => out['recomputedBound'] })
        end
        Ref.canon(got) == Ref.canon(out)
      end
      Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| k.dnum(a) }) }, compare: compare,
              skip: ->(c) { (!PQ && k.pq_case?(c)) || (!ADA && k.idn_url?(c)) })
    end
  end
end
