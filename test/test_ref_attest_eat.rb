# frozen_string_literal: true

# Differential oracle for AtlasPca::AttestEat (EAT build / verify, freshness, channel binding, RATS appraisal, tolerant SEV-SNP
# parse, AMD delegation, post-quantum co-signature, admission evidence, artifact discharge) against the TypeScript reference
# (@atlasauth/pca-attest-eat) vectors in test-data/ref-attest-eat.json.gz.
#
# Where the port is deliberately stricter than the reference the case is asserted as a refusal instead (see STRICTER); the cases
# that read the real clock are skipped (their expected output depends on the day the vectors were made).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/attest_eat'
require 'minitest/autorun'

class TestRefAttestEat < Minitest::Test
  E = AtlasPca::AttestEat
  MAIN = Ref.load('attest-eat')
  GEN = Ref.load_gen('attest-eat')
  BY_FN = Ref.merge_cases(MAIN, GEN)

  # the reference's counter-hash nonce, first draw
  DISCHARGE_NONCE = Ref.b64e(Digest::SHA256.digest('eat-oracle-nonce/0')[0, 16])
  DBGSTAT = %w[enabled disabled disabled-since-boot disabled-permanently disabled-fully-and-permanently].freeze
  PQ_SLOT = { 'ml-dsa-65' => %w[mlDsa ML-DSA-65], 'ml-dsa-87' => %w[mlDsa87 ML-DSA-87], 'slh-dsa-sha2-128f' => %w[slhDsa SLH-DSA-SHA2-128f],
              'slh-dsa-sha2-256s' => %w[slhDsa256s SLH-DSA-SHA2-256s] }.freeze

  # The SLH-DSA seeds are concatenated digests of several labels; the corpus carries only the "$derived" marker.
  def self.derived_seed(prim)
    d = ->(l) { Digest::SHA256.digest("atlas-pca-conformance/#{l}") }
    if prim == 'slh-dsa-sha2-128f' then (d.call('eat/pq/slh128/a') + d.call('eat/pq/slh128/b'))[0, 48]
    else (d.call('eat/pq/slh256/a') + d.call('eat/pq/slh256/b') + d.call('eat/pq/slh256/c'))[0, 96]
    end
  end

  def self.verify_key(spec)
    return Ref.b64d(spec['pub']) if spec['alg'] == 'EdDSA'

    E.verify_key_from_jwk({ 'kty' => 'EC', 'crv' => 'P-256', 'x' => spec['x'], 'y' => spec['y'] })
  end

  def self.with_verify_key(opts)
    return opts unless opts.is_a?(Hash) && opts['verifyKey'].is_a?(Hash) && opts['verifyKey']['alg']

    opts.merge('verifyKey' => verify_key(opts['verifyKey']))
  end

  def self.build(args)
    k = args['key']
    args = args.merge('key' => Ref.b64d(k['seed'])) if k.is_a?(Hash) && k['alg']
    E.build_eat(args)
  end

  def self.tolerant(b)
    r = E.parse_report_tolerant(b)
    out = { 'ok' => r['ok'], 'version' => r['version'], 'known' => r['known'], 'degraded' => r['degraded'], 'notes' => r['notes'],
            'hasReport' => r.key?('report') }
    out['evidence'] = r['evidence'] if r.key?('evidence')
    out['measured'] = E.measured_from_report(r['report']) if r.key?('report')
    out
  end

  def self.amd(b, opts)
    r = E.verify_amd_attestation(b, opts)
    %w[ok hardwareRoot reason evidence measured].select { |k| r.key?(k) }.to_h { |k| [k, r[k]] }
  end

  def self.pq_keys(spec)
    keys = {}
    keys['edSecret'] = Ref.b64d(spec['ed']) if spec.key?('ed')
    if spec.key?('pq')
      slot, prim = PQ_SLOT.fetch(spec['pq']['prim'])
      seed = spec['pq']['seed'] == '$derived' ? derived_seed(spec['pq']['prim']) : Ref.b64d(spec['pq']['seed'])
      keys[slot] = AtlasPca::PqKeyPair.from_seed(prim, seed)
    end
    keys
  end

  def self.cosign(verdict, op)
    o = { 'secretKey' => pq_keys(op['key']) }
    o['suite'] = op['suite'] if op.key?('suite')
    o['now'] = op['now'] if op.key?('now')
    E.co_sign_attestation(verdict, o)
  end

  def self.discharge(i)
    E.issue_artifact_discharge(i.merge('roots' => AtlasPca.parse_trusted_root(i['roots']), 'issuerSecret' => Ref.b64d(i['issuerKey']['seed']),
                                       'nonce' => DISCHARGE_NONCE))
  end

  def self.consts
    { 'EAT_TYP' => E::EAT_TYP, 'DEFAULT_EAT_ALG' => E::DEFAULT_EAT_ALG, 'DEFAULT_MAX_AGE_MS' => E::DEFAULT_MAX_AGE_MS,
      'CHANNEL_BINDING_DOMAIN' => E::CHANNEL_BINDING_DOMAIN, 'AMD_SEV_SNP_SIGNED_REGION_END' => E::AMD_SEV_SNP_SIGNED_REGION_END,
      'AMD_SEV_SNP_HARDWARE_ROOT_LABEL' => E::AMD_SEV_SNP_HARDWARE_ROOT_LABEL, 'KNOWN_REPORT_VERSIONS' => E::KNOWN_REPORT_VERSIONS,
      'KNOWN_AMD_ARK_SPKI_SHA384' => E::KNOWN_AMD_ARK_SPKI_SHA384, 'AMD_MILAN_ARK_SPKI_SHA384' => E::AMD_MILAN_ARK_SPKI_SHA384,
      'PQCOSIGN_DOMAIN' => E::PQCOSIGN_DOMAIN, 'DEFAULT_PQ_COSIGN_SUITE' => E::DEFAULT_PQ_COSIGN_SUITE,
      'PQ_COSIGN_SUITES' => E::PQ_COSIGN_SUITES }
  end

  # Stricter than the reference vectors: a dbgstat outside RFC 9711 is unknown (a debug requirement fails closed), and a minTcb /
  # evidence TCB that is null, a boolean or an array is not comparable.
  def self.odd_tcb?(v) = v.nil? || v == true || v == false || v.is_a?(Array)

  def self.stricter_appraise?(got, c)
    return false unless got.is_a?(Hash) && got['tier'] == 'rejected'

    cl = c['args'][0]
    rv = c['args'][1]
    ok_dbg = cl.is_a?(Hash) && cl.key?('dbgstat') && !DBGSTAT.include?(cl['dbgstat']) && rv.is_a?(Hash) && rv['requireDebugDisabled'] == true &&
             got['reasons'].last == "debug status unknown — failing closed"
    ok_tcb = (rv.is_a?(Hash) && rv.key?('minTcb') && odd_tcb?(rv['minTcb'])) ||
             (cl.is_a?(Hash) && cl['sevsnp'].is_a?(Hash) && cl['sevsnp'].key?('reported_tcb') && odd_tcb?(cl['sevsnp']['reported_tcb']))
    ok_dbg || ok_tcb
  end

  APPRAISE_COMPARE = ->(got, out, c) { Ref.canon(got) == Ref.canon(out) || stricter_appraise?(got, c) }

  # cases where the port is stricter than these vectors (a present clock skew that is not a finite number; a minimum tier other than
  # affirming / affirming-hw-rooted): the current reference refuses them too, the vectors predate that fix
  STRICTER = ['verifyFreshness/skew junk string', 'verifyFreshness/skew junk stale', 'verifyFreshness/skew string number',
              'verifyFreshness/skew null', 'verifyFreshness/skew true', 'verifyFreshAttestedEAT/amd skew junk',
              'eatAdmissionEvidence/min tier unknown', 'eatAdmissionEvidence/min tier null'].freeze
  # cases whose reference output depends on the real clock of the day the vectors were generated
  CLOCK = ['verifyFreshness/now missing uses clock', 'verifyFreshness/now string uses clock',
           'verifyCoSignedAttestation/now string uses clock'].freeze

  STRICT_CMP = lambda do |got, out, c|
    STRICTER.include?(c['name']) ? got['ok'] == false : Ref.canon(got) == Ref.canon(out)
  end

  CLOCK_SKIP = ->(c) { 'reads the real clock' if CLOCK.include?(c['name']) }

  SUITE_SKIP = lambda do |c|
    next 'reads the real clock' if CLOCK.include?(c['name'])

    a = c['args']
    need = []
    if c['fn'] == 'coSignAttestation'
      op = a[1]
      need << (op['suite'] || 'ml-dsa-65')
      need << op['key']['pq']['prim'] if op['key'].is_a?(Hash) && op['key'].key?('pq')
    elsif c['fn'] == 'verifyCoSignedAttestation' && a[0].is_a?(Hash) && a[0]['suite'].is_a?(String)
      need << a[0]['suite']
    end
    'no backend in this runtime' if need.any? { |s| AtlasPca::SIG_SUITES.key?(s) && !E.suite_available?(s) }
  end

  REFUSED_TIER = ->(got, _c) { got.is_a?(Hash) && got['tier'] == 'rejected' }

  MAP = {
    'constants' => [-> { consts }, {}],
    'deriveChannelCnf' => [->(*a) { E.derive_channel_cnf(*a) }, {}],
    'bindChannel' => [->(*a) { E.bind_channel(*a) }, {}],
    'buildEAT' => [->(a) { build(a) }, {}],
    'verifyEAT' => [->(eat, pub, opts = nil) { E.verify_eat(eat, verify_key(pub), opts.nil? ? {} : opts) }, {}],
    'verifyFreshness' => [->(*a) { E.verify_freshness(*a) }, { compare: STRICT_CMP, skip: CLOCK_SKIP }],
    'verifyChannelBinding' => [->(*a) { E.verify_channel_binding(*a) }, {}],
    'appraise' => [->(*a) { E.appraise(*a) }, { compare: APPRAISE_COMPARE, refused: REFUSED_TIER }],
    'parseReportTolerant' => [->(b) { tolerant(b) }, {}],
    'verifyAmdAttestation' => [->(b, o) { amd(b, o) }, {}],
    'verifyFreshAttestedEAT' => [->(eat, opts) { E.verify_fresh_attested_eat(eat, with_verify_key(opts)) }, { compare: STRICT_CMP }],
    'canonicalVerdictBytes' => [->(*a) { E.canonical_verdict_bytes(*a) }, {}],
    'verdictFromAppraisal' => [->(*a) { E.verdict_from_appraisal(*a) }, {}],
    'isPqCoSignSuite' => [->(x) { E.pq_co_sign_suite?(x) }, {}],
    'coSignAttestation' => [->(v, op) { cosign(v, op) }, { skip: SUITE_SKIP }],
    'verifyCoSignedAttestation' => [->(c, op = nil) { E.verify_co_signed_attestation(c, op) }, { skip: SUITE_SKIP }],
    'ed25519Jkt' => [->(x) { E.ed25519_jkt(x) }, {}],
    'eatAdmissionEvidence' => [->(eat, op) { E.eat_admission_evidence(eat, with_verify_key(op)) }, { compare: STRICT_CMP }],
    'runtimeDigestFromEat' => [->(v, op = nil) { E.runtime_digest_from_eat(v, op) }, {}],
    'issueArtifactDischarge' => [->(i) { discharge(i) }, {}]
  }.freeze

  def test_corpus_is_the_full_oracle
    assert_equal 1448, MAIN.values.sum(&:length) # the committed corpus; the private-key cases are in the generated -gen corpus
    Ref.check_covered(self, BY_FN, GEN, MAP.keys)
  end

  def test_secret_corpus_present
    Ref.need_gen(self, 'attest-eat') if GEN.nil?
  end

  MAP.each do |fn, (call, kw)|
    define_method("test_matches_the_reference_#{fn}") { Ref.run(self, BY_FN[fn], call, **kw) }
  end

  def test_stricter_cases_are_present
    assert_empty STRICTER - BY_FN.values.flatten.map { |c| c['name'] }
  end

  def test_issue_nonce_shape
    n = E.issue_nonce({ 'now' => 1_800_000_000_000, 'bytes' => 20 })
    rand, _, ts = n['value'].partition('.')
    assert_equal 1_800_000_000_000, n['issuedAt']
    assert_equal 1_800_000_000_000, ts.to_i(36)
    assert_equal 20, Ref.b64d(rand).bytesize
    assert_equal 16, Ref.b64d(E.issue_nonce({ 'bytes' => 3 })['value'].split('.')[0]).bytesize
  end

  def test_non_finite_clock_skew_and_unknown_min_tier_are_refused
    base = { 'expectedNonce' => 'n1', 'now' => 1_800_000_000_000, 'maxAgeMs' => 60_000 }
    eat = { 'eat_nonce' => 'n1', 'iat' => 1_000_000_000 } # decades stale: only an unbounded skew would admit it
    [Float::INFINITY, -Float::INFINITY, Float::NAN, '5', nil, true].each do |skew|
      assert_equal({ 'ok' => false, 'reason' => 'invalid clockSkewMs (must be a finite number)' }, E.verify_freshness(eat, base.merge('clockSkewMs' => skew)))
    end
    refute E.verify_freshness(eat, base.merge('clockSkewMs' => 5000))['ok']
    ['warning', 'rejected', 'bogus', nil, 2].each do |tier|
      assert_equal({ 'ok' => false, 'bound' => false, 'reason' => 'invalid minTier' }, E.eat_admission_evidence('x', { 'instanceKey' => 'k', 'minTier' => tier }))
    end
  end

  def test_an_uncomparable_tcb_is_refused
    ev = { 'iss' => 'i', 'sevsnp' => { 'version' => 3, 'measurement' => 'aa', 'reported_tcb' => 5 } }
    [nil, true, false, []].each do |tcb|
      r = E.appraise(ev, { 'minTcb' => tcb })
      assert_equal 'rejected', r['tier']
      assert_equal 'reference minTcb is not a comparable TCB version', r['reasons'].last
    end
  end
end
