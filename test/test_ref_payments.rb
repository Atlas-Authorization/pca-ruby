# frozen_string_literal: true

# Differential replay of the payments port (AtlasPca::Payments) against the TypeScript reference (@atlasauth/pca-payments)
# oracle (test-data/ref-payments.json.gz): mandate build, charge decision (the reference's recorded policy decision is fed back
# through the injected decider), charge PCActn, Shared Payment Token limits, spend rails, Stripe Issuing adapter and agent
# network tokens. Plus the optimistic bonded claim over a charge (test-data/ref-payments-java-extra.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/payments'
require 'minitest/autorun'

class TestRefPayments < Minitest::Test
  T = AtlasPca::Payments
  BY_FN = Ref.load('payments')
  BOND = Ref.load('payments-java-extra')

  # JSON text of the canonical form: a lone surrogate (WTF-8) in a string must not break the comparison
  CANON = ->(v) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(v))) }
  CMP = ->(got, out, _c) { CANON.call(got) == CANON.call(out) }

  def self.bytes(b) = { '$bytes' => Ref.b64e(b) }

  MAP = {
    'buildPaymentMandate' => ->(p) { T.build_payment_mandate(Ref.snake(p)) },
    'mandatePredicates' => ->(t) { T.mandate_predicates(t) },
    'mandateCaveats' => ->(t) { T.mandate_caveats(t) },
    'mandateRiskPolicy' => ->(t, r) { T.mandate_risk_policy(t, r) },
    'autoSpendBound' => ->(m) { T.auto_spend_bound(m) },
    'isMinorUnits' => ->(x) { T.minor_units?(x) },
    'isPlainId' => ->(x) { T.plain_id?(x) },
    'chargeActionContext' => ->(m, c) { T.charge_action_context(m, c) },
    'chargeParams' => ->(m, c) { T.charge_params(m, c) },
    'chargePlanNode' => ->(m, c, id) { T.charge_plan_node(m, c, id) },
    'chargeDecideInput' => ->(m, c, now, g) { T.charge_decide_input(m, c, now, g) },
    'authorizeCharge' => ->(m, c, g, rec) { T.authorize_charge(m, c, g, ->(_input) { rec }) },
    'chargeToPCActn' => ->(m, c, o) { T.charge_to_pcactn(m, c, Ref.snake(o)) },
    'settleCharge' => ->(m, d) { T.settle_charge(m, d) },
    'applyHumanCosign' => ->(m, now, o) { T.apply_human_cosign(m, now, Ref.snake(o)) },
    'sharedPaymentTokenLimits' => ->(m, now) { T.shared_payment_token_limits(m, now) },
    'railLimits' => ->(m, now, o) { T.rail_limits(m, now, Ref.snake(o)) },
    'categoriesFromTraits' => ->(t) { T.categories_from_traits(t) },
    'reconcileSettlement' => ->(a, s) { T.reconcile_settlement(a, s) },
    'verifyStripeSignature' => lambda { |rb, hd, sc, ns, tl = nil|
      tl.nil? ? T.verify_stripe_signature(rb, hd, sc, ns) : T.verify_stripe_signature(rb, hd, sc, ns, tl)
    },
    'signStripePayload' => ->(raw, secret, t) { T.sign_stripe_payload(raw, secret, t) },
    'stripeCardParams' => lambda { |limits, names, cardholder, metadata|
      opts = { 'category_names' => names, 'cardholder' => cardholder }
      opts['metadata'] = metadata unless metadata.nil?
      T.stripe_card_params(limits, opts)
    },
    'stripeAuthorizationFromEvent' => ->(e) { T.stripe_authorization_from_event(e) },
    'stripeIssuingWebhook' => lambda { |raw, sig, secret, now_sec, approved|
      handler = T.create_stripe_issuing_webhook({ 'secret' => secret, 'now_sec' => -> { now_sec },
                                                  'authorize' => ->(_a) { { 'approved' => approved, 'reasons' => [] } } })
      handler.call({ 'rawBody' => raw, 'signature' => sig })
    },
    'stripeSettlementFromTransaction' => ->(t) { T.stripe_settlement_from_transaction(t) },
    'tokenRefError' => ->(r) { T.token_ref_error(r) },
    'looksLikePan' => ->(s) { T.looks_like_pan?(s) },
    'bindNetworkToken' => ->(o) { T.bind_network_token(Ref.snake(o)) },
    'verifyNetworkTokenBinding' => ->(b, e) { T.verify_network_token_binding(b, Ref.snake(e)) },
    'bindingMessage' => ->(b) { bytes(T.binding_message(b)) },
    'controlsFromLimits' => ->(l, g) { T.controls_from_limits(l, g) },
    'settlementMetadata' => ->(b, d) { T.settlement_metadata(b, d) },
    'reconcileNetworkSettlement' => ->(e, r) { T.reconcile_network_settlement(Ref.snake(e), r) },
    'chargeWithNetworkToken' => ->(b, m, c, o) { T.charge_with_network_token(b, m, c, Ref.snake(o)) }
  }.freeze

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn], compare: CMP) } }

  def test_open_charge_bond_matches_reference
    assert_equal %w[authorizeChargeCore openChargeBond], BOND.keys.sort # authorizeChargeCore needs the reference's built-in policy engine
    cases = BOND['openChargeBond']
    ran = Ref.run(self, cases, ->(p, opts, seed) { T.open_charge_bond(p, Ref.snake(opts), Ref.b64d(seed)) }, compare: CMP)
    assert_equal cases.length, ran
  end

  def test_rail_authorizer_declines_everything_but_an_auto_decision
    authorize = T.create_rail_authorizer({ 'instruments' => ->(_i) {}, 'store' => Object.new, 'decide' => ->(_x) { {} } })
    assert_equal ['instrument_unknown'], authorize.call({ 'id' => 'a1', 'instrumentId' => 'c', 'amount' => 5, 'currency' => 'USD', 'merchantId' => 'm' })['reasons']
    assert_equal ['malformed_authorization'], authorize.call(nil)['reasons']
    assert_equal ['amount_not_positive_minor_units'],
                 authorize.call({ 'id' => 'a1', 'instrumentId' => 'c', 'amount' => 0, 'currency' => 'USD', 'merchantId' => 'm' })['reasons']
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 3123, BY_FN.values.sum(&:length), 'payments'
    assert_equal 137, BOND.values.sum(&:length), 'payments-java-extra'
  end

end
