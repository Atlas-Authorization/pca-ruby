# frozen_string_literal: true

# Replays the TS-reference oracle of the A2A binding (test-data/ref-a2a.json.gz): tasks, signed and extended cards, RFC 8785, the
# A2A 1.0 schema, AUTH_REQUIRED, delegation, push tokens, payment-mandate envelopes and signed receipts. Cases that would reach the
# full verifier are not in the corpus.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/a2a_binding'
require 'digest'
require 'minitest/autorun'

class TestRefA2aBinding < Minitest::Test
  A = AtlasPca
  B = AtlasPca::A2aBinding
  C = AtlasPca::AgentcardCard
  BY_FN = Ref.load('a2a')

  COLON = /\A(signature \d+ did not verify|could not resolve verification key|malformed payment mandate or PCActn): /

  # the reasons that quote the JOSE library or a runtime error are compared up to the first colon
  def self.norm_reason(r)
    return r unless r.is_a?(Hash) && r['reason'].is_a?(String)

    m = COLON.match(r['reason'])
    m ? r.merge('reason' => m[1]) : r
  end

  def self.eq(got, out, _c) = Ref.canon(norm_reason(got)) == Ref.canon(norm_reason(out))

  def self.seed(label) = Digest::SHA256.digest("atlas-pca-conformance/#{label}")

  def self.with_context(x) = x.key?('context') ? x.merge('context' => ->(_p) { x['context'] }) : x

  MAP = {
    'constants' => lambda {
      { 'PCA_A2A_EXTENSION_URI' => B::PCA_A2A_EXTENSION_URI, 'TASK_STATE_AUTH_REQUIRED' => B::TASK_STATE_AUTH_REQUIRED,
        'TASK_STATE_INPUT_REQUIRED' => B::TASK_STATE_INPUT_REQUIRED, 'A2A_AP2_CONTEXT' => B::A2A_AP2_CONTEXT.dup,
        'A2A_RECEIPT_DOMAIN' => B::A2A_RECEIPT_DOMAIN.dup.force_encoding('UTF-8'), 'RECEIPT_KEY' => B::RECEIPT_KEY }
    },
    'jcsBytes' => ->(v) { { '$bytes' => Ref.b64e(C.jcs_bytes(v)) } },
    'validateAgentCard1' => ->(card) { C.validate_agent_card1(card) },
    'attachPcaToA2ATask' => B.method(:attach_pca_to_a2a_task),
    'attachPcaToA2AMessage' => B.method(:attach_pca_to_a2a_message),
    'extractPca' => B.method(:extract_pca),
    'extractPcaFromMessage' => B.method(:extract_pca_from_message),
    'issueSignedAgentCard' => ->(card, k, x = nil) { C.issue_signed_agent_card(card, k, x) },
    'verifyAgentCard' => B.method(:verify_agent_card),
    'verifyA2ATask' => B.method(:verify_a2a_task),
    'middleware' => ->(t, o) { B.pca_a2a_middleware(o).call(t) },
    'resumeAuthRequired' => B.method(:resume_auth_required),
    'verifyA2ADelegation' => B.method(:verify_a2a_delegation),
    'a2aPaymentMandateFromPca' => B.method(:a2a_payment_mandate_from_pca),
    'pcaBindingFromA2APaymentMandate' => B.method(:pca_binding_from_a2a_payment_mandate),
    'verifyA2APaymentMandate' => ->(m, p, x) { B.verify_a2a_payment_mandate(m, p, with_context(x)) },
    'pcaExtensionDeclaration' => B.method(:pca_extension_declaration),
    'readPcaExtension' => B.method(:read_pca_extension),
    'clientOptsIntoPca' => B.method(:client_opts_into_pca),
    'isAuthRequired' => B.method(:auth_required?),
    'authRequiredStatus' => B.method(:auth_required_status),
    'readAuthRequiredNeed' => B.method(:read_auth_required_need),
    'answerMessage' => B.method(:answer_message),
    'resumeGate' => B.method(:resume_gate_obj),
    'chainExtends' => B.method(:chain_extends),
    'checkChainExtension' => B.method(:check_chain_extension),
    'pcaPushToken' => B.method(:pca_push_token),
    'checkPushNotification' => B.method(:check_push_notification),
    'uniformTaskNotFound' => B.method(:uniform_task_not_found),
    'signTaskReceipt' => ->(label, o) { B.sign_task_receipt(seed(label), o) },
    'verifyTaskReceipt' => ->(r, signer) { A.verify_a2a_receipt(r, signer) },
    'receiptDigest' => ->(r) { A.a2a_receipt_digest(r) },
    'checkReceiptChain' => ->(r, o) { B.check_receipt_chain_result(r, o['signer'], o['taskId'], o['chainIds']) },
    'mayTriggerNext' => ->(r, o) { A.a2a_may_trigger_next?(r, o['signer'], o['taskId'], o['chainIds']) },
    'attachReceipt' => B.method(:attach_receipt),
    'receiptOfPayload' => B.method(:receipt_of_payload),
    'extendedAgentCard' => B.method(:extended_agent_card)
  }.freeze

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn], compare: method(:compare_eq)) } }

  def compare_eq(got, out, c) = self.class.eq(got, out, c)

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 6337, BY_FN.values.sum(&:length), 'a2a'
  end

end
