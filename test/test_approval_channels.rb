# frozen_string_literal: true

# Approval channels: formatting (summary, lineage, canonical render, match code, links), the config gate, delivery outcomes over an
# injected transport and the dispatcher.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestApprovalChannels < Minitest::Test
  C = AtlasPca::ApprovalChannels
  DIGEST = AtlasPca.b64e("\x00".b * 32)

  def request(extra = {})
    { 'id' => 'su1', 'verb' => 'pay', 'resource' => 'acct/1', 'tier' => 3, 'reason' => 'over limit', 'r' => 0.456, 'goalCommit' => 'g',
      'lineage' => { 'because' => 'you asked to pay suppliers', 'chain' => [{ 'label' => 'goal', 'detail' => 'pay suppliers' }, { 'label' => 'action' }] },
      'requestedAt' => 1 }.merge(extra)
  end

  def test_summary_and_lineage
    assert_equal 'pay on acct/1 (tier 3, risk 0.46)', C.action_summary(request)
    assert_equal ['you asked to pay suppliers', "goal — pay suppliers", 'action'], C.lineage_lines(request)
  end

  def test_render_lines_show_every_field_the_banner_and_the_match_code
    r = { 'unreviewed' => true, 'fields' => [{ 'id' => 'amt', 'class' => 'money', 'value' => 5, 'unit' => { 'kind' => 'money', 'ccy' => 'USD', 'exp' => 2 } },
                                              { 'id' => 'memo', 'class' => 'free', 'value' => "a\u0085b" }] }
    lines = C.render_lines(request('render' => r, 'renderDigest' => DIGEST))
    assert lines[0].start_with?('UNREVIEWED ACTION')
    assert_equal 'amt [money]: 5 USD (minor units, exponent 2)', lines[1]
    assert_equal 'memo [free]: "a\\u{85}b"', lines[2]
    assert_equal "Match code: #{AtlasPca.binding_words(DIGEST)}", lines[3]
    assert_empty C.render_lines(request)
  end

  def test_links_keep_the_fragment_last
    assert_equal 'https://x/i?a=1&stepup=s%201#tok', C.append_query('https://x/i?a=1#tok', { 'stepup' => 's 1' })
  end

  def test_slack_message_with_and_without_an_inbox
    m = C.build_slack_message(request, { 'inboxUrl' => 'https://x/inbox' })
    assert_equal 'Approval needed: pay on acct/1 (tier 3, risk 0.46)', m['text']
    btn = m['blocks'].last['elements']
    assert_equal %w[pca_approve pca_deny], btn.map { |b| b['action_id'] }
    assert_equal 'https://x/inbox?stepup=su1&decision=approve', btn[0]['url']
    assert_equal 'context', C.build_slack_message(request)['blocks'].last['type']
  end

  def test_webhook_and_text_bodies
    b = C.build_webhook_body(request, { 'inboxUrl' => 'https://x/i' })
    assert_equal %w[type stepup summary lineage inbox_url], b.keys
    refute C.build_webhook_body(request).key?('inbox_url')
    t = C.build_text_body(request, { 'inboxUrl' => 'https://x/i' })
    assert_equal 'Approval needed: pay on acct/1', t['subject']
    assert t['text'].end_with?('Approve or deny: https://x/i?stepup=su1')
  end

  def test_disabled_channels_never_send
    sent = []
    fetch = ->(*a) { sent << a; { 'ok' => true, 'status' => 200 } }
    d = C.slack_approval_channel('fetch' => fetch).notify(request)
    assert_equal [false, 'slack channel not configured', 'slack'], [d['delivered'], d['reason'], d['kind']]
    assert_equal 'webhook channel not configured', C.webhook_approval_channel('fetch' => fetch).notify(request)['reason']
    assert_equal 'sms channel not configured', C.text_approval_channel('sms').notify(request)['reason']
    assert_empty sent
  end

  def test_delivery_outcomes
    ok = C.webhook_approval_channel('url' => 'https://h', 'headers' => { 'x-sig' => 's' }, 'fetch' => lambda { |url, init|
      assert_equal ['https://h', 'POST', 's'], [url, init['method'], init['headers']['x-sig']]
      { 'ok' => true, 'status' => 202 }
    }).notify(request)
    assert_equal [true, 202], [ok['delivered'], ok['status']]
    bad = C.slack_approval_channel('webhookUrl' => 'https://h', 'fetch' => ->(*) { { 'ok' => false, 'status' => 500 } }).notify(request)
    assert_equal [false, 500, 'slack webhook returned 500'], [bad['delivered'], bad['status'], bad['reason']]
    boom = C.webhook_approval_channel('url' => 'https://h', 'fetch' => ->(*) { raise 'down' }).notify(request)
    assert_equal [false, 'down'], [boom['delivered'], boom['reason']]
    txt = C.text_approval_channel('email', 'send' => ->(b) { { 'id' => b['subject'] } }).notify(request)
    assert_equal [true, 'email'], [txt['delivered'], txt['kind']]
    assert_equal [false, 'smtp down'], C.text_approval_channel('push', 'send' => ->(_) { raise 'smtp down' }).notify(request).values_at('delivered', 'reason')
  end

  def test_dispatcher_skips_disabled_channels
    ch = [C.slack_approval_channel, C.text_approval_channel('email', 'send' => ->(_) { {} }), C.webhook_approval_channel('url' => 'https://h', 'fetch' => ->(*) { { 'ok' => true, 'status' => 200 } })]
    assert_equal %w[email webhook], C.create_approval_dispatcher(ch).notify_all(request).map { |d| d['kind'] }
  end

  def test_render_kind
    assert_equal 'pca-approval-render', AtlasPca::APPROVAL_RENDER_KIND
  end
end
