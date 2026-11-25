# frozen_string_literal: true

# Replays the TS-reference oracle of the VC bridges (test-data/ref-vc.json.gz): base58btc / did:key, the AgentPassport SD-JWT
# VC (issued tokens compare a normalized form: salts are random), RFC 9421 / Web Bot Auth request signatures. Keys travel as
# seeds / raw public bytes; the vectors were produced with the clock pinned to NOW.
require_relative 'support/ref_oracle'
require 'minitest/autorun'
require 'openssl'

class TestRefVc < Minitest::Test
  V = AtlasPca::Vc
  CASES = Ref.load('vc')
  NOW = 1_700_000_100_000
  JS_EQ = ->(g, o, _c) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(g))) == AtlasPca::Js.json(Ref.sort_keys(Ref.norm(o))) }

  # the reference's createPrivateKey throws ASN1 not-enough-data for a seed that is not 32 bytes
  def self.priv(seed) = seed.is_a?(String) && seed.bytesize != 32 ? AtlasPca::Vc.signing_key(seed) : OpenSSL::PKey.new_raw_private_key('ED25519', seed)
  def self.pub(raw) = OpenSSL::PKey.new_raw_public_key('ED25519', raw)
  def self.bytes(b) = { '$bytes' => Ref.b64e(b) }
  def self.dec_seg(x) = AtlasPca.parse_json_text(AtlasPca::Jose.lenient_b64d(x).force_encoding('UTF-8'))
  P1 = priv("\x01".b * 32).raw_public_key

  PASSPORT_TO_VC = lambda do |passport, a|
    m = { 'issuer_key' => priv(a['issuer_seed']), 'now' => NOW }
    %w[issuer_did subject_did ttl_sec].each { |k| m[k] = a[k] if a.key?(k) }
    sd = V.passport_to_vc(passport, m)
    parts = sd.split('~', -1)
    ds = parts[1...-1]
    h, p = parts[0].split('.')[0, 2].map { |x| dec_seg(x) }
    cs = p['vc'].is_a?(Hash) ? p['vc']['credentialSubject'] : nil
    sdl = (cs.is_a?(Hash) ? cs.delete('_sd') || [] : []).sort
    verified = begin
      V.verify_passport_vc(sd, pub(P1), { 'now' => NOW })
      true
    rescue StandardError
      false
    end
    { 'end' => parts[-1], 'header' => h, 'payload' => p, 'n' => ds.length,
      'digestsOk' => ds.map { |d| V.sha256_ascii_b64u(d) }.sort == sdl,
      'disclosures' => ds.map { |d| dec_seg(d).then { |x| [x[1], x[2]] } }.sort_by(&:first), 'verified' => verified }
  end

  VERIFY_VC = lambda do |vc, key, *opt|
    o = { 'now' => NOW }
    o['expected_issuer_did'] = opt[0]['expectedIssuerDid'] if opt[0].is_a?(Hash) && opt[0].key?('expectedIssuerDid')
    V.verify_passport_vc(vc, pub(key), o)
  end

  FNS = {
    'base58btcEncode' => [->(b) { V.base58btc_encode(b) }, {}],
    'base58btcDecode' => [->(s) { bytes(V.base58btc_decode(s)) }, {}],
    'didKeyFromEd25519' => [->(b) { V.did_key_from_ed25519(b) }, {}],
    'ed25519FromDidKey' => [->(d) { bytes(V.ed25519_from_did_key(d)) }, {}],
    'constants' => [lambda {
      { 'VC_CONTEXT' => V::VC_CONTEXT, 'AGENT_PASSPORT_CONTEXT' => V::AGENT_PASSPORT_CONTEXT, 'AGENT_PASSPORT_VC_TYPE' => V::AGENT_PASSPORT_VC_TYPE,
        'AGENT_PASSPORT_CONTEXT_DIGEST' => V::AGENT_PASSPORT_CONTEXT_DIGEST, 'AGENT_PASSPORT_CONTEXT_DOC' => V::AGENT_PASSPORT_CONTEXT_DOC }
    }, {}],
    'resolveAgentPassportContext' => [->(i) { V.resolve_agent_passport_context(i) }, {}],
    'passportToVC' => [PASSPORT_TO_VC, { compare: JS_EQ }],
    'verifyPassportVC' => [VERIFY_VC, { compare: JS_EQ }],
    # the URL parser refuses a non-ASCII (IDN) host unless ATLAS_PCA_LIBADA names an Ada build (the CI ada-idna workflow sets it)
    'signRequestMessage' => [->(a) { V.sign_request_message(a.merge('key' => priv(a['key']), 'now' => NOW)) },
                             { compare: JS_EQ, skip: ->(c) { c['name'] == 'url idn' && !AtlasPca::AdaIdna.available? } }],
    'verifyRequestSignature' => [->(a, key) { V.verify_request_signature(a, pub(key)) }, {}]
  }.freeze

  def test_every_fn_is_mapped
    assert_empty CASES.keys - FNS.keys
  end

  FNS.each { |fn, (call, kw)| define_method("test_#{fn}") { Ref.run(self, CASES[fn], call, **kw) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 338, CASES.values.sum(&:length), 'vc'
  end

end
