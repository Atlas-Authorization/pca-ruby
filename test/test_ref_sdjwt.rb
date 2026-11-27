# frozen_string_literal: true

# Replays the TS-reference oracle of the SD-JWT serialization (test-data/ref-sdjwt.json.gz): issue / present / verify /
# verifyRecovered. Keys travel as seeds / raw public bytes; options are snake_case. Issuance salts are random, so an issue
# case compares a normalized form (header, clear payload, [name, value] disclosures, digest agreement, verify verdict). A
# verify refusal compares its reason when the reason is this package's own (or the canonical gate's); a JOSE-library
# wording only has to be a refusal.
require_relative 'support/ref_oracle'
require 'minitest/autorun'
require 'openssl'

class TestRefSdJwt < Minitest::Test
  S = AtlasPca::SdJwt
  CASES = Ref.load('sdjwt')
  JS_EQ = ->(g, o, _c) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(g))) == AtlasPca::Js.json(Ref.sort_keys(Ref.norm(o))) }

  OWN = ['pca-sdjwt:', 'non-canonical compact JWS', 'required disclosure', 'KB-JWT ', 'cnf key does not', 'key binding required',
         'duplicate disclosure', 'unsupported _sd_alg', 'a presented disclosure', 'a digest appears', 'an array', 'an object-property',
         'disclosure claim', '_sd must be', "'"].freeze
  CAMEL = %w[required_disclosures expected_audience expected_kb_audience expected_nonce require_key_binding algorithms kb_algorithms
             now kb_max_age_sec clock_tolerance_sec key_binding_key].freeze

  def self.clip(r) = r.start_with?('non-canonical compact JWS: bad-json') ? r.split(' (')[0] : r
  def self.dec_seg(x) = AtlasPca.parse_json_text(AtlasPca::Jose.lenient_b64d(x).force_encoding('UTF-8'))
  def self.pub_of(seed) = OpenSSL::PKey.new_raw_private_key('ED25519', seed).raw_public_key

  CMP_VERIFY = lambda do |g, o, c|
    next JS_EQ.call(g, o, c) unless o['ok'] == false
    next false unless g['ok'] == false

    r = o['reason']
    next g['reason'].start_with?('KB-JWT signature/claims invalid') if r.start_with?('KB-JWT signature/claims invalid')
    next clip(g['reason']) == clip(r) if r.start_with?(*OWN)

    true
  end

  ISSUE = lambda do |pc, o|
    m = { 'issuer_key' => S.import_ed25519_private_key(o['issuer_seed']) }
    %w[disclosable iss sub typ signing_alg].each { |k| m[k] = o[k] if o.key?(k) }
    if o.key?('key_binding')
      kb = o['key_binding']
      m['key_binding'] = kb.is_a?(Hash) && kb.key?('holder_public_key') ? { 'holder_public_key' => kb['holder_public_key'] } : kb
    end
    sd = S.issue_pca_sd_jwt(pc, m)
    parts = sd.split('~', -1)
    ds = parts[1...-1]
    h, p = parts[0].split('.')[0, 2].map { |x| dec_seg(x) }
    ver = S.verify_pca_sd_jwt(sd, { 'issuer_key' => S.import_ed25519_public_key(pub_of(o['issuer_seed'])), 'now' => p['iat'] * 1000 })
    { 'end' => parts[-1], 'header' => h, 'payload' => p.except('_sd'), 'n' => ds.length,
      'digestsOk' => ds.map { |d| S.sha256_ascii_b64u(d) }.sort == (p['_sd'] || []).sort,
      'disclosures' => ds.map { |d| dec_seg(d).then { |x| [x[1], x[2]] } }.sort_by(&:first), 'verified' => ver['ok'] }
  end

  PRESENT = lambda do |sd, sel, *o|
    m = {}
    if o[0].is_a?(Hash) && o[0].key?('key_binding')
      kb = o[0]['key_binding']
      k = { 'holder_key' => S.import_ed25519_private_key(kb['holder_seed']) }
      %w[audience nonce iat alg].each { |a| k[a] = kb[a] if kb.key?(a) }
      m['key_binding'] = k
    end
    S.present(sd, sel, m)
  end

  VERIFY = lambda do |sd, o|
    ik = o['issuer_key']
    # the reference imports a JWK into a key object first (private members and alg hints play no part)
    m = { 'issuer_key' => ik.is_a?(Hash) ? ik.slice(*S::PUBLIC_JWK_MEMBERS) : S.import_ed25519_public_key(ik) }
    CAMEL.each { |k| m[k] = o[k] if o.key?(k) }
    S.verify_pca_sd_jwt(sd, m)
  end

  RECOVERED = lambda do |res, o|
    core = { 'grant' => o['grant'] }
    %w[audience now insecure_skip_plan_root_check].each { |k| core[k] = o[k] if o.key?(k) }
    v = S.verify_recovered(res, core)
    { 'allow' => v.allow, 'reason' => v.reason }
  end

  CMP_RECOVERED = lambda do |g, o, _c|
    next false unless g['allow'] == o['allow']

    r = o['reason']
    !(r.is_a?(String) && r.start_with?('pca-sdjwt:')) || g['reason'] == r
  end

  FNS = {
    'constants' => [lambda {
      { 'SD_ALG' => S::SD_ALG, 'PCA_SD_JWT_TYP' => S::PCA_SD_JWT_TYP, 'KB_JWT_TYP' => S::KB_JWT_TYP,
        'DEFAULT_SIGNING_ALG' => S::DEFAULT_SIGNING_ALG, 'PCA_CAPABILITY_CLAIMS' => S::PCA_CAPABILITY_CLAIMS }
    }, {}],
    'ed25519PublicJwk' => [->(r) { S.ed25519_public_jwk(r) }, {}],
    'importEd25519PrivateKey' => [->(r) { S.import_ed25519_private_key(r) && 'ok' }, {}],
    'importEd25519PublicKey' => [->(r) { S.import_ed25519_public_key(r) && 'ok' }, {}],
    'issuePcaSdJwt' => [ISSUE, { compare: JS_EQ }],
    'present' => [PRESENT, { compare: JS_EQ }],
    'verifyPcaSdJwt' => [VERIFY, { compare: CMP_VERIFY }],
    # the Ruby core has no audience opt-out: audience nil is a mismatch, not "accept any"
    'verifyRecovered' => [RECOVERED, { compare: CMP_RECOVERED, skip: ->(c) { c['name'].end_with?('audience null') } }]
  }.freeze

  def test_every_fn_is_mapped
    assert_empty CASES.keys - FNS.keys
  end

  FNS.each { |fn, (call, kw)| define_method("test_#{fn}") { Ref.run(self, CASES[fn], call, **kw) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 353, CASES.values.sum(&:length), 'sdjwt'
  end

end
