# frozen_string_literal: true

# The small public helpers of the attestation verifiers: the JWT parsers, the JWKS fetchers (over an injected fetch), the issuer-chain header decoder
# and the P-256 point decoder.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'
require 'openssl'

class TestAttestHelpers < Minitest::Test
  A = AtlasPca::Attest

  def jwt(h, p) = "#{AtlasPca.b64e(JSON.generate(h))}.#{AtlasPca.b64e(JSON.generate(p))}.#{AtlasPca.b64e('sig')}"

  def test_the_jwt_parsers_name_their_function_in_a_refusal
    t = jwt({ 'alg' => 'ES256', 'kid' => 'k' }, { 'iss' => 'x' })
    assert_equal 'ES256', A::Azure.parse_maa_jwt(t)['header']['alg']
    assert_equal({ 'iss' => 'x' }, A::Gcp.parse_gcp_cs_jwt(t)['payload'])
    assert_match(/\AparseMaaJwt: empty token/, assert_raises(StandardError) { A::Azure.parse_maa_jwt('') }.message)
    assert_match(/\AparseGcpCsJwt: a compact JWS has exactly three/, assert_raises(StandardError) { A::Gcp.parse_gcp_cs_jwt('a.b') }.message)
  end

  def ok(body) = ->(_u) { { 'ok' => true, 'status' => 200, 'body' => body } }

  def test_the_maa_jwks_fetch_keeps_the_known_members_of_the_object_keys
    got = A::Azure.fetch_maa_jwks('https://m.example//', fetch: ok('{"keys":[{"kid":"k","kty":"RSA","alg":"RS256","x5c":["a"],"extra":1},5,{"kid":7}]}'))
    assert_equal({ 'keys' => [{ 'kid' => 'k', 'kty' => 'RSA', 'alg' => 'RS256', 'x5c' => ['a'] }, {}] }, got)
    seen = []
    A::Azure.fetch_maa_jwks('https://m.example/', certs_path: '/c2', fetch: ->(u) { seen << u; { 'ok' => true, 'status' => 200, 'body' => '{"keys":[]}' } })
    assert_equal ['https://m.example/c2'], seen
    assert_match(/HTTP 500 for https:\/\/m.example\/certs/, assert_raises(RuntimeError) { A::Azure.fetch_maa_jwks('https://m.example', fetch: ->(_u) { { 'ok' => false, 'status' => 500, 'body' => '' } }) }.message)
    assert_equal 'MAA JWKS fetch: response has no keys array', assert_raises(RuntimeError) { A::Azure.fetch_maa_jwks('https://m.example', fetch: ok('{}')) }.message
  end

  def test_the_gcp_jwks_fetch_follows_the_openid_configuration
    seen = []
    f = lambda do |u|
      seen << u
      body = u.end_with?('/.well-known/openid-configuration') ? '{"jwks_uri":"https://g.example/keys"}' : '{"keys":[{"kid":"a","kty":"RSA","n":"n","e":"AQAB","x5c":["c"]},"x"]}'
      { 'ok' => true, 'status' => 200, 'body' => body }
    end
    got = A::Gcp.fetch_gcp_confidential_space_jwks('https://g.example/', fetch: f)
    assert_equal({ 'keys' => [{ 'kid' => 'a', 'kty' => 'RSA', 'n' => 'n', 'e' => 'AQAB', 'x5c' => ['c'] }] }, got)
    assert_equal ['https://g.example/.well-known/openid-configuration', 'https://g.example/keys'], seen
    assert_equal ['https://pinned.example/k'], (seen.clear; A::Gcp.fetch_gcp_confidential_space_jwks('https://g.example', jwks_uri: 'https://pinned.example/k', fetch: ->(u) { seen << u; { 'ok' => true, 'status' => 200, 'body' => '{"keys":[]}' } }); seen)
    assert_equal 'Confidential Space OpenID config carries no jwks_uri', assert_raises(RuntimeError) { A::Gcp.fetch_gcp_confidential_space_jwks('https://g.example', fetch: ok('{}')) }.message
    assert_equal 'Confidential Space JWKS fetch: response has no keys array', assert_raises(RuntimeError) { A::Gcp.fetch_gcp_confidential_space_jwks('https://g.example', jwks_uri: 'https://g.example/k', fetch: ok('[]')) }.message
  end

  def test_the_issuer_chain_header_is_percent_decoded_like_decodeuricomponent
    i = A::Intel
    assert_equal 'a b+c/d', i.decode_issuer_chain_header('a%20b+c%2Fd')
    assert_equal 'é', i.decode_issuer_chain_header('%C3%A9')
    ['%', '%G0', '%E0%A4%A', '%FF'].each { |bad| assert_raises(ArgumentError, bad) { i.decode_issuer_chain_header(bad) } }
  end

  def test_the_p256_point_decoder_normalizes_and_refuses_off_curve_points
    k = OpenSSL::PKey::EC.generate('prime256v1')
    full = k.public_key.to_octet_string(:uncompressed)
    assert_equal full, A::Intel.ecdsa_p256_public_key(full)['point']
    assert_equal full, A::Intel.ecdsa_p256_public_key(k.public_key.to_octet_string(:compressed))['point']
    assert_raises(StandardError) { A::Intel.ecdsa_p256_public_key("\x04".b + ("\x01".b * 64)) }
    assert_raises(StandardError) { A::Intel.ecdsa_p256_public_key('short') }
  end
end
