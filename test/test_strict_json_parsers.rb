# frozen_string_literal: true

# Signed or digested JSON received from outside is read with the reference's profile: step-up events with the strict canonical profile (a
# duplicate member, an exponent or trailing-zero number, a lone surrogate and a byte-order mark are refused), the vendor attestation JSON and
# the third-party documents (WebAuthn clientDataJSON, a key directory) with a duplicate-member check only. A lenient parse keeps the LAST duplicate.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'
require 'base64'

class TestStrictJsonParsers < Minitest::Test
  E = AtlasPca::Events
  J = AtlasPca::Js
  C = AtlasPca::Attest::Common

  def event_json
    e = E.build_step_up_event('step_up.approved', { 'at' => 1_700_000_000_000, 'grant_ref' => 'g1', 'tier' => 2, 'action' => { 'verb' => 'stripe.refund', 'resource' => 'r1' } })
    E.serialize_event(e)
  end

  def test_a_canonical_event_parses
    s = event_json
    assert_equal 'g1', E.parse_event(s)['grant_ref']
  end

  # each variant keeps the event's value (so the id still matches): only the strict profile refuses it
  def test_an_event_in_a_non_canonical_form_is_refused
    s = event_json
    variants = {
      'duplicate member' => s.sub(/\}\z/, ',"grant_ref":"g1"}'),
      'exponent' => s.sub('"at":1700000000000', '"at":17e11'),
      'trailing fractional zero' => s.sub('"at":1700000000000', '"at":1700000000000.0'),
      'byte-order mark' => "﻿#{s}",
      'lone surrogate' => s.sub('"grant_ref":"g1"', '"grant_ref":"\\ud800"')
    }
    variants.each do |name, v|
      refute_equal s, v, name
      assert_raises(AtlasPca::Malformed, name) { E.parse_event(v) }
    end
  end

  def test_a_refused_delivery_reports_a_json_reason_not_a_parse_event_reason
    s = event_json.sub('"at":1700000000000', '"at":17e11')
    secret = 'whsec_0123456789abcdef0123456789'
    header = E.sign_webhook(secret, s, { 'timestamp' => 1_700_000_100 })
    store = AtlasPca::MemoryStateStore.new
    r = E.verify_delivery(secret, s, header, { 'replay' => store, 'now' => 1_700_000_100 })
    assert_equal false, r['ok']
    refute r['reason'].start_with?('parseEvent: '), r['reason']
  end

  def test_duplicate_key_finds_a_repeat_at_any_depth_after_unescaping
    assert_nil J.duplicate_key('{"a":1,"b":{"a":2},"c":[{"a":3},{"a":4}]}')
    assert_equal 'a', J.duplicate_key('{"a":1,"a":2}')
    assert_equal 'a', J.duplicate_key('{"a":1,"\\u0061":2}')
    assert_equal 'x', J.duplicate_key('{"o":{"x":1,"y":2,"x":3}}')
    assert_nil J.duplicate_key('{"s":"a\\",\\"a\\":1"}') # text inside a string is not a key
    e = assert_raises(AtlasPca::Malformed) { J.parse_no_duplicates('{"keys":[],"keys":[1]}') }
    assert_equal 'duplicate key "keys"', e.message
    assert_equal({ 'a' => 1.5 }, J.parse_no_duplicates('{"a":1.5}'))
    assert_equal({ 'a' => 1 }, J.parse_no_duplicates('{"a":1.0}')) # numbers stay lenient: only a duplicate is refused
  end

  def test_a_key_directory_with_a_repeated_keys_member_is_refused
    k = '{"kty":"OKP","crv":"Ed25519","x":"nyhMxDazvaOFgheJPwoXUUeByeYzQY0CCEXGg1KRPZg","kid":"ka"}'
    assert_equal 'ka', AtlasPca::WebBotAuth.parse_key_directory(%({"keys":[#{k}]}))['keys'][0]['kid']
    assert_raises(AtlasPca::Malformed) { AtlasPca::WebBotAuth.parse_key_directory(%({"keys":[#{k}],"keys":[#{k}]})) }
  end

  def b64u(s) = Base64.urlsafe_encode64(s, padding: false)

  def jws(header, payload) = "#{b64u(header)}.#{b64u(payload)}.#{b64u('sig')}"

  # vendor attestation JSON is read as written: only a duplicate member (and what is not JSON) is refused, with one fixed message
  def test_dup_only_json_loads_refuses_a_duplicate_and_non_json_with_one_message
    ['{"a":1,"a":2}', '{"a":{"b":1,"b":1}}', '[{"k":1,"k":2}]', "\uFEFF{}", '{', 'not json', ''].each do |t|
      e = assert_raises(AtlasPca::Attest::JsError, t) { C.dup_only_json_loads(t) }
      assert_equal 'invalid JSON', e.message, t
    end
    assert_equal({ 'a' => [1, 2.5, 'x', nil, true] }, C.dup_only_json_loads('{"a":[1,2.5,"x",null,true]}'))
  end

  def test_dup_only_json_loads_accepts_non_canonical_numbers_and_keeps_the_size_bound
    assert_equal 8.0, C.dup_only_json_loads('{"a":8.0}')['a']
    assert_equal 1000.0, C.dup_only_json_loads('{"a":1e3}')['a']
    assert_equal 0, C.dup_only_json_loads('{"a":-0}')['a'].to_i
    big = %({"a":"#{'x' * (2 * 1024 * 1024)}"}) # beyond the 1 MiB strict cap, within the 16 MiB bound
    assert_equal 2 * 1024 * 1024, C.dup_only_json_loads(big)['a'].length
    e = assert_raises(AtlasPca::Attest::JsError) { C.dup_only_json_loads('a' * ((16 * 1024 * 1024) + 1)) }
    assert_equal 'input too large', e.message
  end

  def test_the_vendor_jws_parsers_refuse_a_duplicate_member_and_unify_the_json_message
    header = '{"alg":"ES256","kid":"k1"}'
    { 'parseMaaJwt' => AtlasPca::AttestVendors.method(:parse_maa_jwt), 'parseGcpCsJwt' => AtlasPca::AttestVendors.method(:parse_gcp_cs_jwt) }.each do |fn, parse|
      assert_equal({ 'a' => 1 }, parse.call(jws(header, '{"a":1}'))['payload'])
      assert_equal({ 'a' => 8.0, 'b' => 1000.0 }, parse.call(jws(header, '{"a":8.0,"b":1e3}'))['payload'])
      ['{"a":1,"a":2}', 'not json', '{"a":'].each do |bad|
        e = assert_raises(AtlasPca::Attest::JsTypeError, "#{fn} #{bad}") { parse.call(jws(header, bad)) }
        assert_equal "#{fn}: malformed JSON segment: invalid JSON", e.message
      end
      e = assert_raises(AtlasPca::Attest::JsTypeError) { parse.call(jws('{"alg":"ES256","alg":"ES384"}', '{"a":1}')) }
      assert_equal "#{fn}: malformed JSON segment: invalid JSON", e.message
    end
  end
end
