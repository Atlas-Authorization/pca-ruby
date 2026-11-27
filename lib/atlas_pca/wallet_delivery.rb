# frozen_string_literal: true

require_relative 'wallet'
require_relative 'wallet_card'
require_relative 'intent_required'

# Question delivery over the existing approval-channel transports (a webhook with an injected fetch, and email / sms / push through an
# injected sender). A delivery only tells the principal's device that a question is waiting and hands it the SIGNED question: never a
# rendered card, agent text, the map or p. Text surfaces use one fixed template. Native port of the TypeScript reference
# (@atlasauth/pca-wallet, delivery). The transports are injected sync callables: fetch.call(url, init) -> {'ok', 'status'} and
# send.call({'subject', 'text'}); with no fetch configured a webhook delivery reports "no fetch available" instead of touching the
# network.
module AtlasPca
  module WalletDelivery
    module_function

    # A notice for a site-signed question. Raises when the signature or expiry does not verify (nothing unsigned leaves).
    def site_question_notice(ir, ctx)
      v = IntentRequired.verify_intent_required(ir, ctx['keys'], ctx['now'])
      raise ArgumentError, "siteQuestionNotice: #{v['reason']}" unless v['ok']

      out = { 'type' => 'pca.intent.question', 'session' => ir['session'], 'question_id' => ir['question_id'], 'site' => ctx['site'],
              'friction' => ir['friction'], 'expires_at' => ir['expires_at'], 'intent_required' => ir }
      out['inbox_url'] = ctx['inboxUrl'] if Wallet.truthy?(ctx['inboxUrl'])
      out
    end

    # A notice for a wallet-originated question (clarification): ids only.
    def clarification_notice(session, question_id, inbox_url = nil)
      out = { 'type' => 'pca.intent.clarification', 'session' => session, 'question_id' => question_id }
      out['inbox_url'] = inbox_url if Wallet.truthy?(inbox_url)
      out
    end

    # The fixed text of a text-surface notice.
    def question_text(notice, site_name)
      q = notice['type'] == 'pca.intent.question'
      who = q ? (WalletCard.clean_text(site_name, 64).then { |n| n.empty? ? 'A site' : n }) : 'Your agent'
      subject = q ? "#{who} has a question about your request" : "#{who} needs a decision about your request"
      inbox = notice['inbox_url']
      link = Wallet.truthy?(inbox) ? "#{inbox}#{inbox.include?('?') ? '&' : '?'}question=#{Js.encode_uri_component(notice['question_id'])}" : nil
      { 'subject' => subject, 'text' => [subject, '', link ? "Open your wallet to answer: #{link}" : 'Open your wallet to answer.'].join("\n") }
    end

    # One delivery channel: kind, enabled and notify(notice) -> delivery.
    class QuestionChannel
      attr_reader :kind, :enabled

      def initialize(kind, enabled, notify)
        @kind = kind
        @enabled = enabled
        @notify = notify
      end

      def notify(notice) = @notify.call(notice)
    end

    NO_FETCH = ->(_url, _init) { raise 'no fetch available: pass a FetchLike transport' }

    # Webhook delivery (the principal's own wallet push endpoint): the JSON notice, signed question included.
    def question_webhook_channel(config = nil)
      config = {} if config.nil?
      url = config['url']
      enabled = url.is_a?(String) && !url.empty?
      transport = config['fetch'] || NO_FETCH
      headers = { 'content-type' => 'application/json' }.merge(config['headers'] || {})
      notify = lambda do |notice|
        base = { 'kind' => 'webhook', 'questionId' => notice['question_id'], 'payload' => notice }
        next base.merge('delivered' => false, 'reason' => 'webhook channel not configured') if !enabled || url.nil?

        begin
          res = transport.call(url, { 'method' => 'POST', 'headers' => headers, 'body' => Js.json(notice) })
          if res['ok']
            base.merge('delivered' => true, 'status' => res['status'])
          else
            base.merge('delivered' => false, 'status' => res['status'], 'reason' => "webhook returned #{Wallet.js_str(res['status'])}")
          end
        rescue StandardError => e # a transport failure is a failed delivery, not an exception
          base.merge('delivered' => false, 'reason' => e.message.empty? ? 'webhook transport error' : e.message)
        end
      end
      QuestionChannel.new('webhook', enabled, notify)
    end

    # Email / SMS / push delivery through the per-instance sender port (fixed text only).
    def question_text_channel(kind, config)
      send = config['send']
      enabled = send.respond_to?(:call)
      notify = lambda do |notice|
        body = question_text(notice, config['siteName'])
        base = { 'kind' => kind, 'questionId' => notice['question_id'], 'payload' => body }
        next base.merge('delivered' => false, 'reason' => "#{kind} channel not configured") unless enabled

        begin
          send.call(body)
          base.merge('delivered' => true)
        rescue StandardError => e
          base.merge('delivered' => false, 'reason' => e.message.empty? ? "#{kind} send error" : e.message)
        end
      end
      QuestionChannel.new(kind, enabled, notify)
    end

    class QuestionDispatcher
      attr_reader :channels

      def initialize(channels) = @channels = channels

      # Fan a notice out to every enabled channel (disabled channels are skipped).
      def notify_all(notice) = @channels.select(&:enabled).map { |c| c.notify(notice) }
    end

    def create_question_dispatcher(channels) = QuestionDispatcher.new(channels)
  end
end
