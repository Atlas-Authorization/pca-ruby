# frozen_string_literal: true

# Replays the TS-reference oracle of the WebAuthn / FIDO2 step-up co-sign (test-data/ref-webauthn.json.gz): the COSE_Key reader,
# the authenticatorData header, step-up / approval challenges, Secure Payment Confirmation and verifyAssertion. Bytes travel as
# {"$bytes"}; the reference's member names map to snake_case here.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefWebAuthn < Minitest::Test
  W = AtlasPca::WebAuthn
  CASES = Ref.load('webauthn')
  BYTES = ->(b) { { '$bytes' => Ref.b64e(b) } }
  JS_EQ = ->(g, o, _c) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(g))) == AtlasPca::Js.json(Ref.sort_keys(Ref.norm(o))) }
  ASSERTION = { 'authenticatorData' => 'authenticator_data', 'clientDataJSON' => 'client_data_json', 'signature' => 'signature',
                'publicKey' => 'public_key' }.freeze
  EXPECT = { 'expectedChallenge' => 'expected_challenge', 'rpId' => 'rp_id', 'origins' => 'origins', 'requireUV' => 'require_uv',
             'storedSignCount' => 'stored_sign_count', 'requireLowS' => 'require_low_s', 'rejectCrossOrigin' => 'reject_cross_origin',
             'payment' => 'payment' }.freeze

  def self.rename(h, names) = h.is_a?(Hash) ? h.filter_map { |k, v| [names[k], v] if names.key?(k) }.to_h : h

  # a reason ending in the runtime's own error message is cut at the colon, as the generator does
  VERIFY = lambda do |a, e|
    calls = []
    ex = rename(e, EXPECT)
    ex['on_sign_count_regression'] = ->(i) { calls << i } if e['hook']
    r = W.verify_assertion(rename(a, ASSERTION), ex)
    r = r.merge('reason' => r['reason'].sub(/\A(public key could not be resolved|verification error \(fail closed\)):.*\z/m, '\1')) if r['reason'].is_a?(String) && r['reason'].valid_encoding?
    { 'result' => r, 'hook' => calls }
  end

  def self.auth_data(x)
    r = W.parse_authenticator_data(x)
    r && r.merge('rpIdHash' => BYTES.(r['rpIdHash']))
  end

  FNS = {
    'constants' => lambda {
      { 'MAX_AUTHENTICATOR_DATA_BYTES' => W::MAX_AUTHENTICATOR_DATA_BYTES, 'MAX_CLIENT_DATA_BYTES' => W::MAX_CLIENT_DATA_BYTES,
        'MAX_SIGNATURE_BYTES' => W::MAX_SIGNATURE_BYTES }
    },
    'coseKeyToJwk' => ->(b) { W.cose_key_to_jwk(b) },
    'parseAuthenticatorData' => ->(b) { auth_data(b) },
    'buildStepUpChallenge' => ->(x) { BYTES.(W.build_step_up_challenge(x)) },
    'stepUpChallengeB64u' => ->(x) { W.step_up_challenge_b64u(x) },
    'buildApprovalChallenge' => ->(x, r) { BYTES.(W.build_approval_challenge(x, r)) },
    'approvalChallengeForActn' => ->(x, r) { W.approval_challenge_for_actn(x, r) },
    'spcPaymentError' => ->(p, e, rp) { W.spc_payment_error(p, e, rp) },
    'verifyAssertion' => [VERIFY, { compare: JS_EQ }] # a reason may carry a lone surrogate
  }.freeze

  def test_every_fn_is_mapped
    assert_empty CASES.keys - FNS.keys
  end

  FNS.each { |fn, (call, kw)| define_method("test_#{fn}") { Ref.run(self, CASES[fn], call, **(kw || {})) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1001, CASES.values.sum(&:length), 'webauthn'
  end

end
