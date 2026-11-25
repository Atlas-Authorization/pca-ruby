# frozen_string_literal: true

# Third-party JSON that was signed or digested as written is read with a duplicate-member check (a lenient parse keeps the LAST duplicate
# while a different parser sees the first): the WebAuthn clientDataJSON, the SD-JWT issuer payload, the VC disclosures, the Stripe webhook
# body and the Sigstore entry body and statement. Numbers are NOT held to the strict profile at these sites. Every signature is made
# in-test with a throwaway generated key.
require_relative '../lib/atlas_pca'
require_relative '../lib/atlas_pca/sigstore_bundle'
require_relative '../lib/atlas_pca/payments_rails'
require_relative '../lib/atlas_pca/vc'
require_relative '../lib/atlas_pca/sdjwt'
require_relative '../lib/atlas_pca/webauthn'
require 'minitest/autorun'
require 'openssl'
require 'digest'
require 'base64'

class TestDuplicateMemberSites < Minitest::Test
  def b64u(s) = Base64.urlsafe_encode64(s.b, padding: false)

  # ---- WebAuthn clientDataJSON ------------------------------------------------------------------------------------------------
  RP_ID = 'login.example.com'
  ORIGIN = 'https://login.example.com'
  CHALLENGE = (1..32).to_a.pack('C*')
  EC_KEY = OpenSSL::PKey::EC.generate('prime256v1')

  def jwk
    pt = EC_KEY.public_key.to_octet_string(:uncompressed)
    { 'kty' => 'EC', 'crv' => 'P-256', 'x' => b64u(pt.byteslice(1, 32)), 'y' => b64u(pt.byteslice(33, 32)) }
  end

  def auth_data = Digest::SHA256.digest(RP_ID) + [0x05].pack('C') + [1].pack('N')

  # the clientDataJSON is built from raw text so a duplicate member survives; it is signed correctly so only the parse decides
  def assertion(client_text)
    cd = client_text.b
    sig = EC_KEY.sign('SHA256', auth_data + Digest::SHA256.digest(cd))
    { 'authenticator_data' => auth_data, 'client_data_json' => cd, 'signature' => sig, 'public_key' => jwk }
  end

  def expectations = { 'expected_challenge' => CHALLENGE, 'rp_id' => RP_ID, 'origins' => [ORIGIN], 'require_uv' => true, 'stored_sign_count' => 0 }

  def base = %("type":"webauthn.get","challenge":"#{b64u(CHALLENGE)}","origin":"#{ORIGIN}","crossOrigin":false)

  def test_webauthn_client_data_with_a_duplicate_member_is_refused
    r = AtlasPca::WebAuthn.verify_assertion(assertion(%({#{base},"origin":"https://evil.example"})), expectations)
    assert_equal({ 'ok' => false, 'reason' => 'clientDataJSON is not valid JSON' }, r.slice('ok', 'reason'))
  end

  def test_webauthn_client_data_without_a_duplicate_verifies_and_keeps_non_canonical_numbers
    assert AtlasPca::WebAuthn.verify_assertion(assertion(%({#{base}})), expectations)['ok']
    assert AtlasPca::WebAuthn.verify_assertion(assertion(%({#{base},"x":8.0,"y":1e3})), expectations)['ok']
  end

  # ---- SD-JWT issuer payload --------------------------------------------------------------------------------------------------
  def sdjwt(payload) = "#{b64u('{"alg":"EdDSA"}')}.#{b64u(payload)}.#{b64u("\x01".b * 64)}~"

  def test_sdjwt_issuer_payload_with_a_duplicate_member_is_refused
    assert_raises(StandardError) { AtlasPca::SdJwt.present(sdjwt('{"_sd":[],"_sd":["x"]}'), []) }
    assert_equal sdjwt('{"a":1,"_sd":[]}'), AtlasPca::SdJwt.present(sdjwt('{"a":1,"_sd":[]}'), [])
  end

  # ---- VC disclosures ---------------------------------------------------------------------------------------------------------
  VC_KEY = OpenSSL::PKey.generate_key('ED25519')

  def vc_with(disclosure_text)
    disclosure = b64u(disclosure_text)
    digest = b64u(Digest::SHA256.digest(disclosure))
    payload = { 'vc' => { '@context' => [AtlasPca::Vc::VC_CONTEXT, AtlasPca::Vc::AGENT_PASSPORT_CONTEXT],
                          'type' => ['VerifiableCredential', AtlasPca::Vc::AGENT_PASSPORT_VC_TYPE],
                          'credentialSubject' => { 'id' => 'did:example:s', 'passport_id' => 'p', 'model_id' => 'm', 'operator' => 'o',
                                                   'hardware_rooted' => true, 'issued_at' => 1, '_sd' => [digest] } },
                '_sd_alg' => 'sha-256', 'iss' => 'did:example:i', 'sub' => 'did:example:s', 'iat' => 1_700_000_000 }
    jwt = AtlasPca::Jose.sign_jwt(payload, { 'alg' => 'EdDSA', 'typ' => 'vc+sd-jwt' }, VC_KEY)
    "#{jwt}~#{disclosure}~"
  end

  def vc_pub = OpenSSL::PKey.new_raw_public_key('ED25519', VC_KEY.raw_public_key)

  def test_a_vc_disclosure_with_a_duplicate_member_is_refused
    e = assert_raises(AtlasPca::Vc::Error) { AtlasPca::Vc.verify_passport_vc(vc_with('["s","weights_digest",{"a":1,"a":2}]'), vc_pub, { 'now' => 1_700_000_000_000 }) }
    assert_equal 'pca-vc: malformed disclosure', e.message
    r = AtlasPca::Vc.verify_passport_vc(vc_with('["s","weights_digest","dd"]'), vc_pub, { 'now' => 1_700_000_000_000 })
    assert_equal 'dd', r['passport']['weights_digest']
  end

  # ---- Stripe webhook body ----------------------------------------------------------------------------------------------------
  SECRET = 'whsec_0123456789abcdef0123456789'

  def stripe_reply(body)
    h = AtlasPca::Payments.create_stripe_issuing_webhook({ 'secret' => SECRET, 'now_sec' => -> { 1_700_000_100 }, 'authorize' => ->(_a) { { 'approved' => true } } })
    h.call({ 'rawBody' => body, 'signature' => AtlasPca::Payments.sign_stripe_payload(body, SECRET, 1_700_000_100) })
  end

  def test_a_stripe_webhook_body_with_a_duplicate_member_is_refused
    r = stripe_reply('{"type":"x","type":"issuing_authorization.request"}')
    assert_equal 400, r['status']
    assert_equal '{"error":"bad_json"}', r['body']
    assert_equal 200, stripe_reply('{"type":"other","x":8.0,"y":1e3}')['status']
  end

  # ---- Sigstore entry body and statement --------------------------------------------------------------------------------------
  def test_the_sigstore_body_and_statement_parser_refuses_a_duplicate_member_and_leaves_numbers_alone
    sb = AtlasPca::SigstoreBundle
    e = assert_raises(sb::Fail) { sb.send(:json_parse, '{"kind":"x","kind":"y"}') }
    assert_equal 'duplicate key "kind"', e.message
    e = assert_raises(sb::Fail) { sb.send(:json_parse, '{"_type":"a","subject":[{"digest":{"sha256":"1","sha256":"2"}}]}') }
    assert_equal 'duplicate key "sha256"', e.message
    assert_equal({ 'a' => 8.0, 'b' => 1000.0 }, sb.send(:json_parse, '{"a":8.0,"b":1e3}'))
  end
end
