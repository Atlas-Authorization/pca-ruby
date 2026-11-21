# frozen_string_literal: true

# Replays the TS-reference oracle of ACP delegated payment tokens, x402 v1 and v2 (and its HTTP transport) and Stripe Shared
# Payment Granted Tokens (test-data/ref-acp.json.gz). Stores, verifiers and settle steps are built from the specs the corpus
# names; a token that reaches the full proof verifier carries no valid grant in the corpus.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/acp'
require 'minitest/autorun'

class TestRefAcp < Minitest::Test
  A = AtlasPca::Acp
  BY_FN = Ref.load('acp')
  # the reference quotes its JOSE library after the colon; only the prefix is compared
  REASON = /\A(token signature did not verify|bound proof failed to verify): .*\z/m

  # JS JSON of the normalized values: a lone surrogate (WTF-8) in a string must not break the comparison
  JS_EQ = ->(got, out, _c) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(got))) == AtlasPca::Js.json(Ref.sort_keys(Ref.norm(out))) }

  Store = Struct.new(:fn) do
    def claim(jti, exp) = fn.call(jti, exp)
  end

  # The single-use store a spec names; any other value is passed through as is (and is not a store).
  def self.store(spec)
    case spec
    when 'once'
      seen = {}
      Store.new(lambda do |jti, _exp|
        next false if seen.key?(jti)

        seen[jti] = true
      end)
    when 'always' then Store.new(->(*) { true })
    when 'never' then Store.new(->(*) { false })
    when 'throw' then Store.new(->(*) { raise 'store down' })
    when 'truthy' then Store.new(->(*) { 1 })
    else spec
    end
  end

  def self.norm(r)
    out = r.dup
    out['reason'] = out['reason'].sub(REASON, '\\1') if out['reason'].is_a?(String) && out['reason'].valid_encoding?
    out['pcaResult'] = { 'allow' => out['pcaResult']['allow'] } if AtlasPca::Js.truthy?(out['pcaResult'])
    out
  end

  def self.with_store(op)
    o = Ref.snake(op)
    o.key?('single_use') ? o.merge('single_use' => store(o['single_use'])) : o
  end

  VERIFY_TOKEN = lambda do |token, op, times = 1|
    o2 = with_store(op)
    rs = Array.new(times) { norm(A.verify_delegated_payment_token(token, o2)) }
    times == 1 ? rs[0] : rs
  end

  X402_VERIFIER = lambda do |payload, op, times = 1|
    fn = A.acp_x402_verifier(with_store(op))
    rs = Array.new(times) { norm(fn.call(payload)) }
    times == 1 ? rs[0] : rs
  end

  SETTLE = lambda do |payload, vspec, sspec = nil|
    verify = lambda do |_p|
      raise 'verify down' if vspec == 'throw'
      raise TypeError, 'verify spec is not an object' unless vspec.is_a?(Hash)

      vspec.dup
    end
    o = { 'verify' => verify }
    case sspec
    when 'echo' then o['settle'] = ->(p, c) { { 'jti' => c['jti'], 'token' => p['token'] } }
    when 'value' then o['settle'] = ->(*) { 'receipt-1' }
    when 'throw' then o['settle'] = ->(*) { raise 'settle down' }
    when 'undef' then o['settle'] = ->(*) {}
    end
    A.x402_settle(payload, o)
  end

  MAP = {
    'constants' => lambda {
      { 'v' => A::ACP_DELEGATED_TOKEN_VERSION, 't' => A::ACP_DELEGATED_TOKEN_TYPE, 's' => A::SPEND_CAP_CAVEAT, 'm' => A::MERCHANT_ALLOW_CAVEAT,
        'c' => A::MERCHANT_CATEGORY_CAVEAT, 'h' => A::HUMAN_PRESENT_CAVEAT, 'x1' => A::X402_VERSION_1, 'x2' => A::X402_VERSION_2,
        'sup' => A::X402_SUPPORTED_VERSIONS.dup, 'pr' => A::X402_V2_PAYMENT_REQUIRED_HEADER, 'ps' => A::X402_PAYMENT_SIGNATURE_HEADER,
        'pe' => A::X402_PAYMENT_RESPONSE_HEADER, 'st' => A::X402_HTTP_STATUS, 'spt' => A::STRIPE_SPT_OBJECT }
    },
    'spendCapCaveat' => ->(*a) { A.spend_cap_caveat(*a) },
    'merchantAllowCaveat' => ->(m) { A.merchant_allow_caveat(m) },
    'merchantCategoryCaveat' => ->(c) { A.merchant_category_caveat(c) },
    'humanPresentCaveat' => ->(*a) { A.human_present_caveat(*a) },
    'extractPaymentAuthority' => ->(c) { A.extract_payment_authority(c) },
    'checkPaymentAuthority' => ->(a, r) { A.check_payment_authority(a, r) },
    'mintDelegatedPaymentToken' => ->(pca, op) { A.mint_delegated_payment_token(pca, Ref.snake(op)) },
    'verifyDelegatedPaymentToken' => VERIFY_TOKEN,
    'x402Challenge' => ->(res, op) { A.x402_challenge(res, Ref.snake(op)) },
    'x402ChallengeV2' => ->(res, op) { A.x402_challenge_v2(res, Ref.snake(op)) },
    'x402Settle' => SETTLE,
    'acpX402Verifier' => X402_VERIFIER,
    'toAcpAllowance' => ->(c) { A.to_acp_allowance(c) },
    'resourceInfoProblems' => ->(r) { A.resource_info_problems(r) },
    'requirementV2Problems' => ->(q) { A.requirement_v2_problems(q) },
    'paymentRequiredV2Problems' => ->(pr) { A.payment_required_v2_problems(pr) },
    'paymentPayloadV2Problems' => ->(p) { A.payment_payload_v2_problems(p) },
    'settlementResponseProblems' => ->(r) { A.settlement_response_problems(r) },
    'stripeSptProblems' => ->(t) { A.stripe_spt_problems(t) },
    'encodePaymentRequiredHeader' => ->(pr) { A.encode_payment_required_header(pr) },
    'decodePaymentRequiredHeader' => ->(v) { A.decode_payment_required_header(v) },
    'encodePaymentSignatureHeader' => ->(p) { A.encode_payment_signature_header(p) },
    'decodePaymentSignatureHeader' => ->(v) { A.decode_payment_signature_header(v) },
    'encodePaymentResponseHeader' => ->(r) { A.encode_payment_response_header(r) },
    'decodePaymentResponseHeader' => ->(v) { A.decode_payment_response_header(v) },
    'x402Negotiate' => ->(*a) { A.x402_negotiate(*a) },
    'x402AcceptedMatches' => ->(o, a) { A.x402_accepted_matches(o, a) },
    'normalizeX402Payload' => ->(raw) { A.normalize_x402_payload(raw) },
    'readPaymentSignature' => ->(h) { A.read_payment_signature(h) },
    'x402SettlementResponse' => ->(o, n) { A.x402_settlement_response(o, n) },
    'x402PaymentSignatureHeaders' => ->(p) { A.x402_payment_signature_headers(p) },
    'parseStripeSpt' => ->(t) { A.parse_stripe_spt(t) },
    'stripeSptUsable' => ->(t, u) { A.stripe_spt_usable(t, u) },
    'stripeUsageLimitsFor' => ->(a) { A.stripe_usage_limits_for(a) },
    'stripeSptWithinClaims' => ->(t, c) { A.stripe_spt_within_claims(t, c) }
  }.freeze

  def test_every_function_in_the_corpus_is_replayed
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn], compare: JS_EQ) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 6391, BY_FN.values.sum(&:length), 'acp'
  end

end
