# frozen_string_literal: true

require_relative 'wallet'

# Framework-neutral handlers for the two wallet endpoints named in the session root (3.3 item 3, 3.14): the question endpoint (a site
# delivers, or an agent relays unchanged, a site-signed intent_required plus the raw action) and the clarification endpoint. The HTTP
# routes live with the session store of the host; these functions are what such a route calls, so the wire behaviour is fixed here.
# Neither response carries p or any map content. Native port of the TypeScript reference (@atlasauth/pca-wallet, handlers).
module AtlasPca
  module WalletHandlers
    STATUS_OF_REFUSAL = {
      'bad_site_signature' => 401, 'wrong_session' => 409, 'stale_map' => 409, 'action_mismatch' => 422, 'cell_mismatch' => 422, 'not_uncertain' => 409,
      'already_asked' => 409, 'frozen' => 429, 'cap_session' => 429, 'cap_hour' => 429, 'cell_too_large' => 422, 'bad_request' => 400, 'render_failed' => 422
    }.freeze
    ACTION_KEYS = %w[verb resource params reversibility_class].freeze

    module_function

    def action_of(v)
      return nil if !Wallet.obj?(v) || !v['verb'].is_a?(String) || !v['resource'].is_a?(String) || !v['reversibility_class'].is_a?(String) || !Wallet.obj?(v['params'])
      return nil unless v.each_key.all? { |k| ACTION_KEYS.include?(k) }

      { 'verb' => v['verb'], 'resource' => v['resource'], 'params' => v['params'], 'reversibility_class' => v['reversibility_class'] }
    end

    # The question endpoint: resolve.call(session_id) -> a TrustedChannel or nil.
    def question_handler(resolve)
      lambda do |session_id, body|
        ch = resolve.call(session_id)
        next { 'status' => 404, 'body' => { 'error' => 'unknown_session' } } unless ch
        next { 'status' => 400, 'body' => { 'error' => 'bad_request' } } unless Wallet.obj?(body)

        body.each_key do |k|
          return { 'status' => 400, 'body' => { 'error' => 'bad_request', 'detail' => "unknown member \"#{k}\"" } } if k != 'intent_required' && k != 'action'
        end
        action = action_of(body['action'])
        next { 'status' => 400, 'body' => { 'error' => 'bad_request' } } if action.nil? || !Wallet.obj?(body['intent_required'])

        r = ch.receive(body['intent_required'], { 'action' => action })
        next { 'status' => 202, 'body' => { 'question_id' => r['questionId'], 'friction' => r['friction'] } } if r['ok']

        { 'status' => STATUS_OF_REFUSAL.fetch(r['code'], 400), 'body' => { 'error' => r['code'] } }
      end
    end

    # The clarification endpoint (3.14).
    def clarify_handler(resolve)
      lambda do |session_id, body|
        ch = resolve.call(session_id)
        next { 'status' => 404, 'body' => { 'error' => 'unknown_session' } } unless ch

        r = ch.clarify(body)
        next { 'status' => 400, 'body' => { 'error' => 'bad_request', 'detail' => r['error'] } } unless r['error'].nil?

        out = { 'verdicts' => r['verdicts'] }
        out['question_id'] = r['questionId'] unless r['questionId'].nil?
        out['refused'] = r['refused'] unless r['refused'].nil?
        { 'status' => r['status'], 'body' => out }
      end
    end
  end
end
