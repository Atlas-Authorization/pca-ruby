# frozen_string_literal: true

# Replays the TS-reference oracle of the agent passport (test-data/ref-passport.json.gz, 516 cases): fingerprint and issue, the binding match
# (reasons and their order compared exactly, a throw for a null passport / binding), the registry, the trust score, the evidence binding, signing a
# passport under the Ed25519, ML-DSA-65 and hybrid suites (byte for byte), the verdict of verification (time, revocation, hardware evidence, PQ
# pins), the assurance label and the constants. Every fn has a handler and the totals are asserted. Encodings: {"$num": ...} a non-finite number;
# {"$bytes": {"$seed": label}} the 32-byte Ed25519 secret; a suite is {alg, pqSeed?}. The one case the reference accepts only through its
# `allowUnboundPq` switch (a PQ passport whose issuer key is not pinned) is asserted REFUSED: this SDK has no such switch. Cases that sign or verify
# with ML-DSA need a runtime that has it (OpenSSL >= 3.5).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefPassport < Minitest::Test
  A = AtlasPca
  P = AtlasPca::PassportApi
  BY_FN = Ref.load('passport')
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze
  PQ = A.supported_suites.include?('ml-dsa-65')

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  def self.sign(passport, opts)
    o = opts.dup
    if o['suite'].is_a?(Hash)
      s = o['suite'].dup
      s['pq'] = A::PqKeyPair.from_seed('ML-DSA-65', s['pqSeed']) if s['pqSeed']
      o['suite'] = s
    end
    P.sign_passport(passport, o)
  end

  def self.revocation(spec)
    case spec
    when 'throws' then ->(_h) { raise 'revocation backend down' }
    when Hash
      if spec.key?('revokedIds') then ->(h) { spec['revokedIds'].include?(h['id']) }
      else ->(_h) { spec['revoked'] }
      end
    end
  end

  def self.hardware(spec)
    return nil unless spec.is_a?(Hash)
    return ->(_doc, _expected) { raise spec['throws'] } if spec.key?('throws')

    ->(_doc, _expected) { spec['result'] }
  end

  def self.verify(signed, opts)
    o = opts.dup
    o['revocation'] = revocation(o['revocation'])
    o['attestationVerifier'] = hardware(o.delete('hardware'))
    P.verify_passport(signed, o)
  end

  def self.registry(passports, ops)
    reg = P.build_registry(passports)
    ops.map do |op, id|
      case op
      when 'get' then reg.get(id)
      when 'has' then reg.has?(id)
      else reg.all
      end
    end
  end

  def self.assurance(verdict, label)
    verifier = label == 'no-verifier' ? nil : Object.new
    A.set_assurance_label(verifier, label['level'], vendor: label['vendor']) if label.is_a?(Hash)
    P.passport_assurance(verdict, verifier)
  end

  HANDLERS = {
    'constants' => -> { { 'PASSPORT_SIG_DOMAIN' => P::PASSPORT_SIG_DOMAIN, 'PASSPORT_VERSION' => P::PASSPORT_VERSION, 'DEFAULT_PASSPORT_EVIDENCE_AGE_MS' => P::DEFAULT_PASSPORT_EVIDENCE_AGE_MS } },
    'passportFingerprint' => ->(id) { A.passport_fingerprint(id) },
    'issuePassport' => ->(id) { A.issue_passport(id) },
    'matchesBinding' => ->(p, b) { P.matches_binding(p, b) },
    'registry' => ->(ps, ops) { registry(ps, ops) },
    'trustScore' => ->(p, o) { P.trust_score(p, o) },
    'passportEvidenceBinding' => ->(id, sub, nonce) { P.passport_evidence_binding(id, sub, nonce) },
    'signPassport' => ->(p, o) { sign(p, o) },
    'verifyPassport' => ->(s, o) { verify(s, o) },
    'passportAssurance' => ->(v, l) { assurance(v, l) }
  }.freeze

  TOTALS = { 'constants' => 1, 'passportFingerprint' => 13, 'issuePassport' => 12, 'matchesBinding' => 267, 'registry' => 4, 'trustScore' => 67,
             'passportEvidenceBinding' => 5, 'signPassport' => 30, 'verifyPassport' => 109, 'passportAssurance' => 8 }.freeze

  def self.pq_case?(c) = Ref.canon(c['args']).match?(/ml-dsa/)

  # the case the reference accepts only through allowUnboundPq
  def self.unbound?(c) = c['fn'] == 'verifyPassport' && c['args'][1]['allowUnboundPq'] == true && c['out'].is_a?(Hash) && c['out']['ok'] == true

  def self.same?(got, out, c)
    return got.is_a?(Hash) && got['ok'] == false && got['reason'] == 'bad_signature' if unbound?(c)

    Ref.canon(got) == Ref.canon(out)
  end

  def test_every_fn_of_the_corpus_has_a_handler_and_the_totals_are_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 516, BY_FN.values.sum(&:length)
    assert_equal 1, BY_FN.values.flatten.count { |c| self.class.unbound?(c) }, 'the cases the reference accepts only under allowUnboundPq'
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
