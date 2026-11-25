# frozen_string_literal: true

require 'net/http'
require 'uri'
require_relative 'goal_js'
require_relative 'js_compat'
require_relative 'approval'

module AtlasPca
  # Approval-notification channels for PCA step-ups (the TypeScript reference is `approval-channels`). Given a pending step-up
  # request (a Hash with the reference's member names: id, verb, resource, tier, reason, r, lineage, render, renderDigest), each
  # channel FORMATS a human-readable notification (action summary, the "because you asked to ..." goal lineage, the canonical render
  # and an approve / deny affordance or a link to the inbox) and DISPATCHES it over an injected transport. A channel is gated by
  # its config (unconfigured: `enabled` false and nothing is sent), is offline-testable (the transport is injected) and its output
  # never carries the webhook URL, a token or a signing secret. A channel only REPORTS a step-up the verifier already produced.
  module ApprovalChannels
    J = GoalJs
    NO_CONTROL = /[\p{Cc}\p{Cf}  ]/

    module_function

    # The default transport: ->(url, init) { 'ok' => bool, 'status' => int } over Net::HTTP (init: method, headers, body).
    def default_fetch
      lambda do |url, init|
        uri = URI.parse(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.open_timeout = http.read_timeout = 10
        req = Net::HTTP::Post.new(uri.request_uri, init['headers'])
        req.body = init['body']
        res = http.request(req)
        { 'ok' => res.code.to_i.between?(200, 299), 'status' => res.code.to_i }
      end
    end

    # One-line action summary: `verb on resource (tier N, risk R)`.
    def action_summary(request)
      "#{J.js_str(J.jget(request, 'verb'))} on #{J.js_str(J.jget(request, 'resource'))} (tier #{J.js_str(J.jget(request, 'tier'))}, " \
        "risk #{J.to_fixed(J.to_number(J.jget(request, 'r')), 2)})"
    end

    # The lineage as plain text lines: `label - detail`.
    def describe_goal_lineage(lineage)
      J.req_list(J.jget(lineage, 'chain')).map { |n| J.truthy(J.jget(n, 'detail')) ? "#{J.jget(n, 'label')} — #{J.jget(n, 'detail')}" : J.jget(n, 'label') }
    end

    # The lines a human reads to understand WHY: the "because you asked to ..." sentence, the goal / authority / action chain, then the render.
    def lineage_lines(request)
      [J.jget(J.jget(request, 'lineage'), 'because')] + describe_goal_lineage(J.jget(request, 'lineage')) + render_lines(request)
    end

    # The canonical render, one line per field (nothing omitted), the banner for an unreviewed action and the speakable binding words
    # of H(R). Empty when the request carries no render.
    def render_lines(request)
      r = J.jget(request, 'render')
      rd = J.jget(request, 'renderDigest')
      return [] if J.undef?(r) || J.undef?(rd)

      out = []
      out << 'UNREVIEWED ACTION: its definition has not been confirmed, so every value is shown raw and one-tap approval is disabled.' if J.truthy(J.jget(r, 'unreviewed'))
      J.req_list(J.jget(r, 'fields')).each do |f|
        unit = J.jget(f, 'unit')
        u = !J.undef?(unit) && !unit.nil? && J.jget(unit, 'kind') == 'money' ? " #{J.jget(unit, 'ccy')} (minor units, exponent #{J.js_str(J.jget(unit, 'exp'))})" : ''
        v = Js.json(J.jget(f, 'value')).gsub(NO_CONTROL) { |ch| "\\u{#{ch.ord.to_s(16)}}" }
        out << "#{J.jget(f, 'id')} [#{J.jget(f, 'class')}]: #{v}#{u}"
      end
      out << "Match code: #{AtlasPca.binding_words(rd)}"
      out
    end

    # `encodeURIComponent`
    def uri_component(s) = s.to_s.b.gsub(/[^A-Za-z0-9\-_.!~*'()]/) { |c| format('%%%02X', c.ord) }.force_encoding('UTF-8')

    # Add query parameters before any `#fragment` (an approval link may carry its token in the fragment, which stays last).
    def append_query(url, params)
      query = params.map { |k, v| "#{uri_component(k)}=#{uri_component(v)}" }.join('&')
      hash = url.index('#')
      base = hash.nil? ? url : url[0, hash]
      fragment = hash.nil? ? '' : url[hash..]
      "#{base}#{base.include?('?') ? '&' : '?'}#{query}#{fragment}"
    end

    def inbox_url(ctx)
      u = ctx.is_a?(Hash) ? ctx['inboxUrl'] : nil
      u.is_a?(String) && !u.empty? ? u : nil
    end

    # The Block Kit message for a step-up: action summary, goal lineage, approve / deny affordance.
    def build_slack_message(request, ctx = {})
      id = J.jget(request, 'id')
      blocks = [
        { 'type' => 'header', 'text' => { 'type' => 'plain_text', 'text' => "Approval needed · tier #{J.js_str(J.jget(request, 'tier'))}", 'emoji' => true } },
        { 'type' => 'section', 'text' => { 'type' => 'mrkdwn', 'text' => "*#{J.jget(request, 'verb')}* on `#{J.jget(request, 'resource')}`\n_#{J.jget(request, 'reason')}_" } },
        { 'type' => 'section', 'text' => { 'type' => 'mrkdwn', 'text' => "*Why this is requested*\n#{lineage_lines(request).map { |l| "• #{l}" }.join("\n")}" } }
      ]
      if (u = inbox_url(ctx))
        blocks << { 'type' => 'actions', 'elements' => [
          { 'type' => 'button', 'text' => { 'type' => 'plain_text', 'text' => 'Approve', 'emoji' => true }, 'url' => append_query(u, { 'stepup' => id, 'decision' => 'approve' }),
            'style' => 'primary', 'action_id' => 'pca_approve' },
          { 'type' => 'button', 'text' => { 'type' => 'plain_text', 'text' => 'Deny', 'emoji' => true }, 'url' => append_query(u, { 'stepup' => id, 'decision' => 'deny' }),
            'style' => 'danger', 'action_id' => 'pca_deny' }
        ] }
      else
        blocks << { 'type' => 'context', 'elements' => [{ 'type' => 'mrkdwn', 'text' => "Approve or deny step-up `#{id}` in your Atlas inbox." }] }
      end
      { 'text' => "Approval needed: #{action_summary(request)}", 'blocks' => blocks }
    end

    # The webhook JSON body: the step-up plus its pre-formatted human summary and lineage.
    def build_webhook_body(request, ctx = {})
      body = { 'type' => 'pca.step_up.created', 'stepup' => request, 'summary' => action_summary(request), 'lineage' => lineage_lines(request) }
      u = inbox_url(ctx)
      body['inbox_url'] = u unless u.nil?
      body
    end

    # The plain-text body (subject + text) shared by email / sms / push surfaces.
    def build_text_body(request, ctx = {})
      lines = [action_summary(request), ''] + lineage_lines(request)
      u = inbox_url(ctx)
      lines.push('', "Approve or deny: #{append_query(u, { 'stepup' => J.jget(request, 'id') })}") unless u.nil?
      { 'subject' => "Approval needed: #{J.jget(request, 'verb')} on #{J.jget(request, 'resource')}", 'text' => lines.join("\n") }
    end

    # One approval channel: `kind`, `enabled` (the config gate) and `notify(request, ctx)` returning the delivery Hash (never raises):
    # kind, requestId, delivered, payload (formatted, secret-free), status?, reason?.
    class Channel
      attr_reader :kind, :enabled

      def initialize(kind, enabled, &deliver)
        @kind = kind
        @enabled = enabled
        @deliver = deliver
      end

      def notify(request, ctx = nil)
        @deliver.call(request, ctx || {})
      end
    end

    def http_channel(kind, label, url, fetch, headers, build)
      enabled = url.is_a?(String) && !url.empty?
      transport = fetch || default_fetch
      Channel.new(kind, enabled) do |request, ctx|
        payload = build.call(request, ctx)
        base = { 'kind' => kind, 'requestId' => J.jget(request, 'id'), 'payload' => payload }
        next base.merge('delivered' => false, 'reason' => "#{label} not configured") unless enabled

        begin
          res = transport.call(url, { 'method' => 'POST', 'headers' => headers, 'body' => Js.json(payload) })
          if J.truthy(J.jget(res, 'ok'))
            base.merge('delivered' => true, 'status' => J.jget(res, 'status'))
          else
            base.merge('delivered' => false, 'status' => J.jget(res, 'status'), 'reason' => "#{label == 'slack channel' ? 'slack webhook' : 'webhook'} returned #{J.js_str(J.jget(res, 'status'))}")
          end
        rescue StandardError => e
          base.merge('delivered' => false, 'reason' => e.message.to_s.empty? ? "#{kind} transport error" : e.message)
        end
      end
    end

    # Slack approval channel (Block Kit over an incoming webhook). `config`: {'webhookUrl', 'fetch'}. Disabled without a webhook URL.
    def slack_approval_channel(config = {})
      http_channel('slack', 'slack channel', config['webhookUrl'], config['fetch'], { 'content-type' => 'application/json' }, method(:build_slack_message))
    end

    # Generic webhook approval channel. `config`: {'url', 'fetch', 'headers'}. Disabled without a URL.
    def webhook_approval_channel(config = {})
      http_channel('webhook', 'webhook channel', config['url'], config['fetch'], { 'content-type' => 'application/json' }.merge(config['headers'] || {}), method(:build_webhook_body))
    end

    # A text-formatter channel (email / sms / push) over an injected sender `->(body) { {'id' => ...} }`. Disabled without a sender.
    def text_approval_channel(kind, config = {})
      send_fn = config['send']
      enabled = send_fn.respond_to?(:call)
      Channel.new(kind, enabled) do |request, ctx|
        body = build_text_body(request, ctx)
        base = { 'kind' => kind, 'requestId' => J.jget(request, 'id'), 'payload' => body }
        next base.merge('delivered' => false, 'reason' => "#{kind} channel not configured") unless enabled

        begin
          send_fn.call(body)
          base.merge('delivered' => true)
        rescue StandardError => e
          base.merge('delivered' => false, 'reason' => e.message.to_s.empty? ? "#{kind} send error" : e.message)
        end
      end
    end

    # Several channels behind one dispatcher: `notify_all` fans a step-up out to every ENABLED channel (one delivery each, in order).
    class Dispatcher
      attr_reader :channels

      def initialize(channels) = @channels = channels
      def notify_all(request, ctx = nil) = @channels.select(&:enabled).map { |c| c.notify(request, ctx) }
    end

    def create_approval_dispatcher(channels) = Dispatcher.new(channels)
  end
end
