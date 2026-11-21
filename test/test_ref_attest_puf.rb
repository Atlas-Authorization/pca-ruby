# frozen_string_literal: true

# Replays the TS-reference oracle of the PUF attestation root (test-data/ref-attest-puf.json.gz, 278 cases): the repetition-code fuzzy extractor
# (the key is compared by the SHA-256 of its hex, it is the device's signing seed), the simulated PUF, the TPM EK provider over an injected
# command runner (the exact commands it issues and its refusal texts), enrollment under Ed25519 and ML-DSA, the device attestor, the
# enrollment registry (op scripts) and the verifier (a constant evidence seam; the enrollments are looked up last-wins). Every fn has a handler
# and the totals are asserted. Encodings: {"$bytes": b64url}; a bit vector is a byte array with one 0 / 1 value per bit; a PUF spec is
# {id, seed, length, flip?} with the seed {"$seed": label}; the random callback of an enrollment is [r1, r2] (its first call, for the message
# bits, returns r1; the second, for the salt, r2). A result the reference wraps in {ok: true, value} compares by its value. Cases that sign or
# verify with ML-DSA need a runtime that has it (OpenSSL >= 3.5).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefAttestPuf < Minitest::Test
  A = AtlasPca
  P = AtlasPca::AttestPuf
  BY_FN = Ref.load('attest-puf')
  PQ = A.supported_suites.include?('ml-dsa-65')
  # the oracle's default challenge: sha256("attest-puf-oracle-randomness/challenge")
  CH = Digest::SHA256.digest('attest-puf-oracle-randomness/challenge').b

  def self.by(v) = { '$bytes' => Ref.b64e(v) }
  def self.sha_hex(b) = Digest::SHA256.hexdigest(b)

  def self.puf(spec)
    P.create_simulated_puf(id: spec['id'], seed: Ref.b64d(spec['seed']), length: spec['length'], flip: spec['flip'])
  end

  def self.rnd(pair)
    i = -1
    ->(n) { pair[(i += 1) == 0 ? 0 : 1].byteslice(0, n) }
  end

  def self.tpm(c)
    calls = []
    spec = c['run']
    runner = lambda do |cmd, args|
      calls << [cmd, args.dup]
      next nil if spec == 'undefined'
      raise spec['$throws'] if spec.is_a?(Hash) && spec.key?('$throws')

      spec
    end
    begin
      p = P::TpmEkPufProvider.new(c['opts'].nil? ? nil : c['opts'].merge('run' => runner))
      v = c['op'] == 'readEkPublic' ? p.read_ek_public : p.response(c.key?('challenge') ? c['challenge'] : CH)
      { 'ok' => true, 'value' => by(v), 'calls' => calls }
    rescue StandardError => e
      { 'ok' => false, 'error' => e.message, 'calls' => calls }
    end
  end

  def self.registry(sc)
    r = P.create_puf_enrollment_registry(sc['enrollments'])
    sc['ops'].map do |op|
      k, v = op.first
      case k
      when 'register' then r.register(v)
      when 'lookup' then r.lookup(v)
      when 'revoke' then r.revoke(v)
      else r.revoked?(v)
      end
    end
  end

  def self.verifier(sc, seam: true)
    pol = { 'measurements' => sc['config']['policy']['measurements'] }
    pol['weightsMeasurements'] = sc['config']['policy']['weightsMeasurements'] if sc['config']['policy']['weightsMeasurements']
    if sc['config']['policy']['identity'] == 'custom'
      pol['deriveIdentity'] = lambda do |st, enr|
        { 'model_id' => 'm-custom', 'weights_digest' => st['weights_digest'].nil? ? '' : st['weights_digest'], 'weights_measured' => true,
          'runtime_measurement' => st['measurement'], 'operator' => enr['providerId'] }
      end
    end
    by_id = {}
    (sc['enrollments'] || []).each { |e| by_id[e['providerId']] = e }
    kw = { policy: pol, require_pq: sc['config']['requirePq'] }
    kw[:resolve_enrollment] = ->(id) { by_id[id] } unless sc['config']['noResolveEnrollment']
    kw[:resolve_evidence] = ->(_d) { sc['evidence'] } if seam && !sc['config']['noEvidenceSeam']
    kw[:revoked] = ->(id) { sc['revoked'].include?(id) } if sc['revoked']
    P.create_puf_verifier(**kw)
  end

  HANDLERS = {
    'constants' => lambda {
      { 'PUF_EXTRACT_INFO' => P::PUF_EXTRACT_INFO, 'PUF_ATTEST_DOMAIN' => P::PUF_ATTEST_DOMAIN, 'PUF_KEY_BYTES' => P::PUF_KEY_BYTES,
        'TPM_EK_PUF_DOMAIN' => P::TPM_EK_PUF_DOMAIN }
    },
    'repetitionCorrectionBound' => ->(rep) { P.repetition_correction_bound(rep) },
    'simulatedPufResponse' => ->(spec, ch) { by(puf(spec).response(ch)) },
    'fuzzyEnroll' => lambda { |bits, params, pair|
      r = P.fuzzy_enroll(bits, params, rnd(pair))
      { 'keySha256' => sha_hex(r['key']), 'helper' => r['helper'] }
    },
    'fuzzyReproduce' => ->(bits, helper) { { 'keySha256' => sha_hex(P.fuzzy_reproduce(bits, helper)) } },
    'tpmEk' => ->(c) { tpm(c) },
    'enrollPuf' => ->(spec, ch, opts, pair) { P.enroll_puf(puf(spec), ch, opts.merge('randomBytes' => rnd(pair))) },
    'pufAttest' => ->(spec, enr, claims) { P.create_puf_attestor(puf(spec), enr).attest(claims) },
    'registry' => ->(sc) { registry(sc) },
    'verifyPuf' => ->(sc) { verifier(sc).verify({}, sc['input']['expected'], sc['input']['nowMs']) },
    'buildVerifier' => lambda { |c|
      verifier({ 'config' => { 'policy' => c['policy'] || {}, 'noResolveEnrollment' => c['noResolveEnrollment'] }, 'evidence' => nil, 'enrollments' => [] })
      { 'built' => true }
    }
  }.freeze

  TOTALS = { 'constants' => 1, 'repetitionCorrectionBound' => 12, 'simulatedPufResponse' => 30, 'fuzzyEnroll' => 23, 'fuzzyReproduce' => 80,
             'tpmEk' => 30, 'enrollPuf' => 13, 'pufAttest' => 22, 'registry' => 10, 'verifyPuf' => 52, 'buildVerifier' => 5 }.freeze

  def self.pq_case?(c)
    Ref.canon(c['args']).include?('ml-dsa') || (c['fn'] == 'enrollPuf' && c['args'][2]['alg'].nil?)
  end

  # a result the reference wraps in {ok: true, value} compares by its value
  def self.unwrap(out) = out.is_a?(Hash) && out.keys.sort == %w[ok value] && out['ok'] == true ? out['value'] : out

  def test_every_fn_of_the_corpus_has_a_handler_and_the_totals_are_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 278, BY_FN.values.sum(&:length)
  end

  def test_the_post_quantum_cases_run_where_required
    assert PQ, 'this runtime must have ML-DSA-65' if ENV['PCA_REQUIRE_PQ'] == '1'
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      k = self.class
      Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args) }, skip: ->(c) { !PQ && k.pq_case?(c) },
              compare: ->(got, out, _c) { Ref.canon(got) == Ref.canon(k.unwrap(out)) })
    end
  end
end
