# frozen_string_literal: true

# Differential oracle: AP2 mandates as SD-JWT credentials (strict parsing, disclosure processing, ES256, mandate validators and
# minor units, open-mandate constraint evaluation, delegation chains, purchases and the redeem ledger, PCA terms bridge, settlement
# payloads; AtlasPca::Ap2) against the vectors generated from the TypeScript reference (@atlasauth/pca-ap2).
#
# Keys are derived from labels (d = sha256("atlas-pca-conformance/ap2/<label>")); ECDSA signatures are randomized, so every signing
# function is compared with each signature segment replaced by "SIG".
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/ap2'
require 'minitest/autorun'

class TestRefAp2 < Minitest::Test
  A = AtlasPca::Ap2
  BY_FN = Ref.load('ap2')
  T0 = 1_800_000_000

  # JSON text of the canonical form: a lone surrogate (WTF-8) in a string must not break the comparison
  CANON = ->(v) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(v))) }
  CMP = ->(got, out, _c) { CANON.call(got) == CANON.call(out) }

  KEYS = {}

  def self.priv_of(label)
    d = OpenSSL::Digest::SHA256.digest("atlas-pca-conformance/ap2/#{label}")
    _key, point = A.p256_private(OpenSSL::BN.new(d, 2))
    pub = A.public_jwk(point)
    { 'kty' => 'EC', 'crv' => 'P-256', 'd' => A.b64u_encode(d), 'x' => pub['x'], 'y' => pub['y'], 'kid' => label }
  end

  def self.key_for(label) = (KEYS[label] ||= A.ap2_key_pair_from_private_jwk(priv_of(label)))

  def self.counter_salt
    n = [0]
    lambda do
      n[0] += 1
      A.b64u_encode(format('salt-%012d', n[0]))
    end
  end

  def self.strip_sig(t)
    t.split('~', -1).map { |s| s.match?(/\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z/) ? s.sub(/\.[A-Za-z0-9_-]+\z/, '.SIG') : s }.join('~')
  end

  def self.mask_reason(s) = s.is_a?(String) ? s.sub(/invalid JSON \(.*\)\z/m, 'invalid JSON (*)') : s

  def self.resolver(m)
    ->(h) { m.is_a?(Hash) && h['kid'].is_a?(String) && m.key?(h['kid']) ? m[h['kid']] : nil }
  end

  def self.base_opts(c)
    o = { 'resolve_issuer_key' => resolver(c['issuerKeys']), 'resolve_merchant_key' => resolver(c['merchantKeys']),
          'expected_audience' => c['expectedAudience'], 'expected_nonce' => c['expectedNonce'] }
    o['now'] = c['now'] unless c['now'].nil?
    o['clock_skew_seconds'] = c['clockSkewSeconds'] unless c['clockSkewSeconds'].nil?
    o
  end

  def self.hop_out(h) = { 'index' => h['index'], 'kind' => h['kind'], 'claims' => h['claims'], 'mandate' => h['mandate'] }

  def self.proj_chain(r)
    unless r['ok']
      out = { 'ok' => false, 'reason' => mask_reason(r['reason']) }
      out['violations'] = r['violations'] if r['violations'] && !r['violations'].empty?
      return out
    end
    out = { 'ok' => true, 'hops' => r['hops'].map { |h| hop_out(h) } }
    out.update('open' => r['open'], 'closed' => r['closed']) if r['open']
    out.update('checkoutJwt' => r['checkoutJwt'], 'checkout' => r['checkout']) if r['checkoutJwt']
    out['openHash'] = r['openHash'] if r['openHash']
    out
  end

  def self.proj_purchase(r)
    return { 'ok' => true, 'checkout' => proj_chain(r['checkout']), 'payment' => proj_chain(r['payment']) } if r['ok']

    { 'ok' => false, 'reason' => mask_reason(r['reason']) }
  end

  def self.purch_opts_of(c)
    o = { 'resolve_issuer_key' => resolver(c['issuerKeys']), 'resolve_merchant_key' => resolver(c['merchantKeys']),
          'checkout' => Ref.snake(c['checkout']), 'payment' => Ref.snake(c['payment']) }
    %w[context now].each { |k| o[k] = c[k] unless c[k].nil? }
    o['clock_skew_seconds'] = c['clockSkewSeconds'] unless c['clockSkewSeconds'].nil?
    o
  end

  def self.parse(t) = A.parse_sd_jwt_hop(t)

  def self.sig_bytes(h) = h.merge('signature' => { '$bytes' => Ref.b64e(h['signature']) })

  def self.verify_kb(h, prev, pm, op, label)
    v = A.verify_kb_hop(parse(h), { 'hop' => parse(prev), 'mandate' => pm }, Ref.snake(op), label)
    { 'index' => v['index'], 'kind' => v['kind'], 'claims' => v['claims'], 'mandate' => v['mandate'] }
  end

  def self.verify_payment(t, c)
    o = base_opts(c)
    o['open_checkout_hash'] = c['openCheckoutHash']
    o['context'] = c['context'] unless c['context'].nil?
    o['expected_transaction_id'] = c['expectedTransactionId'] unless c['expectedTransactionId'].nil?
    proj_chain(A.verify_payment_chain(t, o))
  end

  class Ledger
    attr_reader :calls

    def initialize(spec)
      @spec = spec
      @calls = []
    end

    def reserve(h, t, amt)
      @calls << ['reserve', h, t, amt]
      raise 'down' if @spec['mode'] == 'throw'
      return 'replayed' if @spec['mode'] == 'replayed'
      return nil if @spec['mode'] == 'undefined'

      @spec['ctx'].nil? ? { 'totalAmount' => 0, 'totalUses' => 0 } : @spec['ctx']
    end

    def release(h, t)
      @calls << ['release', h, t]
      raise 'release failed' if @spec['releaseThrows']
    end
  end

  def self.redeem(a, b, c, spec)
    ledger = spec == 'none' ? nil : Ledger.new(spec)
    r = A.redeem_purchase(a, b, purch_opts_of(c), ledger)
    { 'result' => r['ok'] ? proj_purchase(r) : { 'ok' => false, 'reason' => mask_reason(r['reason']) }, 'calls' => ledger ? ledger.calls : [] }
  end

  def self.mk_open_input(a)
    issuer = { 'private_key' => key_for(a['issuerKey'] || 'issuer')['privateKey'] }
    issuer['kid'] = a['kid'] unless a['kid'].nil?
    issuer['x5c'] = a['x5c'] unless a['x5c'].nil?
    jwk = a['agentJwk'].nil? ? key_for(a['agentKey'] || 'agent')['publicJwk'].reject { |k, _| k == 'kid' } : a['agentJwk']
    i = { 'issuer' => issuer, 'agent_jwk' => jwk, 'iat' => a['iat'], 'exp' => a['exp'], 'salt' => counter_salt }
    { 'pca' => 'pca', 'sdAlg' => 'sd_alg', 'typ' => 'typ' }.each { |k, v| i[v] = a[k] unless a[k].nil? }
    i
  end

  def self.open_pay(a)
    i = mk_open_input(a).merge('constraints' => a['constraints'])
    { 'payee' => 'payee', 'paymentAmount' => 'payment_amount', 'paymentInstrument' => 'payment_instrument', 'pisp' => 'pisp' }.each { |k, v| i[v] = a[k] unless a[k].nil? }
    i['execution_date'] = a['executionDate'] unless a['executionDate'].nil?
    strip_sig(A.issue_open_payment_mandate(i))
  end

  def self.present_hop_in(a)
    i = { 'open' => a['open'], 'agent_key' => key_for(a['agentKey'] || 'agent'), 'aud' => a['aud'], 'nonce' => a['nonce'], 'iat' => a['iat'],
          'salt' => counter_salt }
    { 'exp' => 'exp', 'pca' => 'pca', 'hashMode' => 'hash_mode' }.each { |k, v| i[v] = a[k] unless a[k].nil? }
    i
  end

  def self.present_pay(a)
    i = present_hop_in(a).merge('transaction_id' => a['transactionId'], 'payee' => a['payee'], 'payment_amount' => a['paymentAmount'],
                                'payment_instrument' => a['paymentInstrument'])
    { 'pisp' => 'pisp', 'executionDate' => 'execution_date', 'riskData' => 'risk_data' }.each { |k, v| i[v] = a[k] unless a[k].nil? }
    strip_sig(A.present_closed_payment(i.reject { |_, v| v.nil? }))
  end

  MERCH = { 'id' => 'merchant_1', 'name' => 'Demo Merchant', 'website' => 'https://demo-merchant.example' }.freeze
  MERCH2 = { 'id' => 'merchant_2', 'name' => 'Other Merchant' }.freeze

  def self.from_in(a)
    o = { 'issuer' => { 'private_key' => key_for('issuer')['privateKey'], 'kid' => 'issuer-1' },
          'agent_jwk' => key_for('agent')['publicJwk'].reject { |k, _| k == 'kid' },
          'merchants' => a['merchants'].nil? ? [MERCH, MERCH2] : a['merchants'], 'iat' => a['iat'].nil? ? T0 : a['iat'], 'salt' => counter_salt }
    o['exp'] = a['exp'] unless a['exp'].nil?
    o
  end

  def self.bind(a)
    i = { 'mandate' => a['mandate'], 'open' => a['open'], 'agent_jwk' => key_for('agent')['publicJwk'].reject { |k, _| k == 'kid' },
          'agent_secret' => OpenSSL::Digest::SHA256.digest("atlas-pca-conformance/#{a['agentSeed']}"), 'audience' => a['audience'],
          'counter' => a['counter'], 'transaction_id' => a['transactionId'], 'payee' => a['payee'], 'amount' => a['amount'],
          'instrument_id' => a['instrumentId'], 'now' => a['now'] }
    i['category'] = a['category'] unless a['category'].nil?
    i['cosign'] = ->(_built) { a['cosign'] } unless a['cosign'].nil?
    A.build_pca_payment_binding(i)
  end

  def self.builder(alg, ops)
    b = A.disclosure_builder(alg, counter_salt)
    results = ops.map { |op| op['kind'] == 'element' ? b.element(op['value']) : b.property(op['name'], op['value']) }
    { 'results' => results, 'disclosures' => b.disclosures }
  end

  def self.process(a, b = nil, c = nil)
    if a.is_a?(String)
      x = parse(a)
      return A.process_disclosures(x['payload'], x['disclosures'], x['sdAlg'])
    end
    A.process_disclosures(a, b, c)
  end

  PROBLEMS = { 'openPaymentMandateProblems' => A.method(:open_payment_mandate_problems), 'paymentMandateProblems' => A.method(:payment_mandate_problems),
               'openCheckoutMandateProblems' => A.method(:open_checkout_mandate_problems), 'checkoutMandateProblems' => A.method(:checkout_mandate_problems) }.freeze

  def self.settle(backend) = ->(p, c = nil) { backend.settle(p, Ref.snake(c)) }

  MAP = {
    'b64uEncode' => ->(x) { A.b64u_encode(x) },
    'b64uDecode' => ->(s, w) { { '$bytes' => Ref.b64e(A.b64u_decode(s, w)) } },
    'parseJson' => ->(t, w) { A.parse_json(t, w) },
    'isSdAlg' => ->(v) { A.sd_alg?(v) },
    'sdDigest' => ->(v, a = nil) { a.nil? ? A.sd_digest(v) : A.sd_digest(v, a) },
    'assertP256Jwk' => ->(j, w) { A.assert_p256_jwk(j, w) },
    'jwkThumbprint' => ->(j) { A.jwk_thumbprint(j) },
    'ap2KeyPairFromPrivateJwk' => ->(label, m) { A.ap2_key_pair_from_private_jwk(priv_of(label).merge(m))['publicJwk'] },
    'parseSdJwtHop' => ->(t) { sig_bytes(parse(t)) },
    'hopSdJwt' => ->(t) { A.hop_sd_jwt(parse(t)) },
    'sdHashOf' => ->(t, a = nil) { A.sd_hash_of(parse(t), a) },
    'issuerJwtHashOf' => ->(t, a = nil) { A.issuer_jwt_hash_of(parse(t), a) },
    'processDisclosures' => ->(a, b = nil, c = nil) { process(a, b, c) },
    'splitChain' => ->(t) { A.split_chain(t) },
    'disclosureBuilder' => ->(alg, ops) { builder(alg, ops) },
    'parseJwt' => ->(x, w) { sig_bytes(A.parse_jwt(x, w)) },
    'verifyJwtEs256' => ->(x, j) { A.verify_jwt_es256(A.parse_jwt(x, 'jwt'), j) },
    'verifyHopSignature' => ->(t, j) { A.verify_hop_signature(parse(t), j) },
    'signSdJwt' => lambda { |a|
      strip_sig(A.sign_sd_jwt({ 'header' => a['header'], 'payload' => a['payload'], 'disclosures' => a['disclosures'], 'private_key' => key_for(a['key'])['privateKey'] }))
    },
    'signJwtEs256' => lambda { |a|
      strip_sig(A.sign_jwt_es256({ 'header' => a['header'], 'payload' => a['payload'], 'private_key' => key_for(a['key'])['privateKey'] }))
    },
    'currencyExponent' => ->(c) { A.currency_exponent(c) },
    'toMinorUnits' => ->(m, c) { A.to_minor_units(m, c) },
    'fromMinorUnits' => ->(m, c) { A.from_minor_units(m, c) },
    'openPaymentMandateProblems' => ->(v) { A.open_payment_mandate_problems(v) },
    'paymentMandateProblems' => ->(v) { A.payment_mandate_problems(v) },
    'openCheckoutMandateProblems' => ->(v) { A.open_checkout_mandate_problems(v) },
    'checkoutMandateProblems' => ->(v) { A.checkout_mandate_problems(v) },
    'assertValid' => ->(k, v, w) { A.assert_valid(v, PROBLEMS[k], w) },
    'constants' => lambda {
      { 'VCT_CHECKOUT' => A::VCT_CHECKOUT, 'VCT_CHECKOUT_OPEN' => A::VCT_CHECKOUT_OPEN, 'VCT_PAYMENT' => A::VCT_PAYMENT,
        'VCT_PAYMENT_OPEN' => A::VCT_PAYMENT_OPEN, 'PCA_CLAIM' => A::PCA_CLAIM, 'FREQUENCIES' => A::FREQUENCIES, 'AP2_COMMIT' => A::AP2_COMMIT,
        'PCA_BINDING_VERSION' => A::PCA_BINDING_VERSION, 'TYP_TERMINAL' => A::TYP_TERMINAL, 'TYP_INTERMEDIATE' => A::TYP_INTERMEDIATE }
    },
    'merchantMatches' => ->(c, t) { A.merchant_matches(c, t) },
    'checkPaymentConstraints' => ->(o, c, x) { A.check_payment_constraints(o, c, Ref.snake(x)) },
    'projectCheckout' => ->(p) { A.project_checkout(p) },
    'checkoutTotal' => ->(c) { A.checkout_total(c) },
    'checkCheckoutConstraints' => ->(o, c) { A.check_checkout_constraints(o, c) },
    'verifyDelegationChain' => ->(t, c) { proj_chain(A.verify_delegation_chain(t, base_opts(c))) },
    'verifyKbHop' => ->(h, prev, pm, op, label) { verify_kb(h, prev, pm, op, label) },
    'verifyCheckoutChain' => ->(t, c) { proj_chain(A.verify_checkout_chain(t, base_opts(c))) },
    'verifyPaymentChain' => ->(t, c) { verify_payment(t, c) },
    'verifyPurchase' => ->(a, b, c) { proj_purchase(A.verify_purchase(a, b, purch_opts_of(c))) },
    'redeemPurchase' => ->(a, b, c, spec) { redeem(a, b, c, spec) },
    'issueOpenPaymentMandate' => ->(a) { open_pay(a) },
    'issueOpenCheckoutMandate' => ->(a) { strip_sig(A.issue_open_checkout_mandate(mk_open_input(a).merge('constraints' => a['constraints']))) },
    'presentClosedPayment' => ->(a) { present_pay(a) },
    'presentClosedCheckout' => ->(a) { strip_sig(A.present_closed_checkout(present_hop_in(a).merge('checkout_jwt' => a['checkoutJwt']))) },
    'ap2BudgetMax' => ->(c, cur) { A.ap2_budget_max(c, cur) },
    'ap2BudgetReads' => ->(m, cur) { A.ap2_budget_reads(m, cur) },
    'riskRatio' => ->(a, c) { A.risk_ratio(a, c) },
    'pcaBindingNonce' => ->(f) { A.pca_binding_nonce(f) },
    'paymentConstraintsFromTerms' => ->(t, m, r) { A.payment_constraints_from_terms(t, m, r) },
    'pcaOpenClaim' => ->(m) { A.pca_open_claim(m) },
    'openPaymentMandateFromPca' => lambda { |x|
      ref = x['checkoutReference'].nil? ? 'REF' : x['checkoutReference']
      strip_sig(A.open_payment_mandate_from_pca(x['mandate'], from_in(x).merge('checkout_reference' => ref)))
    },
    'openCheckoutMandateFromPca' => lambda { |x|
      items = x['lineItems'].nil? ? [{ 'id' => 'line_1', 'acceptable_items' => [{ 'id' => 'sku-1', 'title' => 'Widget' }], 'quantity' => 2 }] : x['lineItems']
      strip_sig(A.open_checkout_mandate_from_pca(x['mandate'], from_in(x).merge('line_items' => items)))
    },
    'toAtomicUnits' => ->(a, d) { A.to_atomic_units(a, d) },
    'x402Settlement' => settle(A.x402_settlement),
    'stripeSptSettlement' => settle(A.stripe_spt_settlement),
    'buildPcaPaymentBinding' => ->(a) { bind(a) }
  }.freeze

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}") do
      ran = Ref.run(self, BY_FN[fn], MAP[fn], compare: CMP)
      assert_equal BY_FN[fn].length, ran
    end
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 3621, BY_FN.values.sum(&:length), 'ap2'
  end

end
