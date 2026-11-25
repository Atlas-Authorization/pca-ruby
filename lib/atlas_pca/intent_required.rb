# frozen_string_literal: true

require_relative 'intent_v2'
require_relative 'signers_more'

# Lazy elicitation on the wire: the verifier side of the site-signed `pca-intent-required` v1 body (shape check, the signature against
# the site's discovery keys, the expiry). Native port of the TypeScript reference (@atlasauth/pca, intent-required.ts); the signer is
# AtlasPca.sign_intent_required.
module AtlasPca
  module IntentRequired
    UNDEF = V2JS::UNDEF
    SIG_MEMBERS = %w[alg kid value pq_value].freeze
    PROBLEM_BASE = 'https://atlasauth.net/pca/problems/'
    INTENT_PROBLEM_KINDS = %w[intent-required intent-denied schema-violation ceiling].freeze
    PROBLEM_TITLES = { 'intent-required' => 'Principal confirmation required for this action', 'intent-denied' => 'The principal does not intend this action',
                       'schema-violation' => 'The action does not conform to the site action schema',
                       'ceiling' => 'The action is outside a ceiling the principal cannot widen' }.freeze
    PROBLEM_ERRORS = { 'intent-required' => 'intent_required', 'intent-denied' => 'intent_denied', 'schema-violation' => 'schema_violation',
                       'ceiling' => 'ceiling' }.freeze

    module_function

    # Shape of a `pca-intent-required` v1 body (signed unless `signed` is false): nil when well formed.
    def intent_required_shape_error(b, signed = true)
      return 'not an object' unless b.is_a?(Hash)

      unsigned = AtlasPca.intent_required_shape_error(b.reject { |k, _| k == 'sig' })
      return unsigned if unsigned
      return 'an unsigned body must not carry sig' if !signed && b.key?('sig')

      if signed
        s = b.key?('sig') ? b['sig'] : UNDEF
        if s.is_a?(Hash)
          se = IntentV2.suite_err(s.key?('alg') ? s['alg'] : UNDEF)
          return "sig.alg: #{se}" if se
          return 'sig.pq_value must be a string' if s.key?('pq_value') && !s['pq_value'].is_a?(String)
        end
        if !s.is_a?(Hash) || s.keys.any? { |k| !SIG_MEMBERS.include?(k) } || IntentV2.suite_of(s.key?('alg') ? s['alg'] : UNDEF).nil? ||
           !s['kid'].is_a?(String) || !s['value'].is_a?(String)
          return 'sig must be {alg, kid, value, pq_value?}'
        end
      end
      nil
    end

    def message(b) = INTENT_REQUIRED_DOMAIN.b + AtlasPca.strict_bytes(b.reject { |k, _| k == 'sig' })

    # Verify a site-signed body against the site's discovery keys (the action schema's key list). The clock is REQUIRED: a `now`
    # that is not a safe integer is refused, never coerced, so expiry can never be skipped.
    def verify_intent_required(b, keys, now)
      return { 'ok' => false, 'reason' => 'the verifier clock is not a safe integer (fail closed)' } unless V2JS.int?(now)

      e = intent_required_shape_error(b)
      return { 'ok' => false, 'reason' => e } if e
      return { 'ok' => false, 'reason' => 'the site keys must be an array' } unless keys.is_a?(Array)

      kid = b['sig']['kid']
      key = keys.find { |k| k.is_a?(Hash) && V2JS.strict_eq(k.key?('kid') ? k['kid'] : UNDEF, kid) }
      return { 'ok' => false, 'reason' => "no site key with kid '#{kid}'" } if key.nil?

      kalg = key.key?('alg') ? key['alg'] : UNDEF
      kse = IntentV2.suite_err(kalg)
      return { 'ok' => false, 'reason' => "site key: #{kse}" } if kse

      ka = IntentV2.suite_of(kalg)
      return { 'ok' => false, 'reason' => 'sig.alg does not match the pinned key suite' } if ka.nil? || ka != IntentV2.suite_of(b['sig'].key?('alg') ? b['sig']['alg'] : UNDEF)

      pins = key.key?('pq_pk') && key.key?('pk') ? { key['pk'] => key['pq_pk'] } : nil
      ok = IntentV2.verify_pinned_suite(ka, key['pk'], key.key?('pq_pk') ? key['pq_pk'] : UNDEF, message(b), b['sig']['value'],
                                        b['sig'].key?('pq_value') ? b['sig']['pq_value'] : UNDEF, pins)
      return { 'ok' => false, 'reason' => 'site signature invalid' } unless ok
      return { 'ok' => false, 'reason' => 'the question has expired' } unless now <= b['expires_at']

      { 'ok' => true }
    rescue StandardError => e
      { 'ok' => false, 'reason' => "malformed intent_required: #{e.message}" }
    end

    # Same as verify_intent_required: the clock is checked first (a clock that is not a safe integer is refused), then the body.
    def verify_intent_required_at(b, keys, now)
      return { 'ok' => false, 'reason' => 'the verifier clock is not a safe integer (fail closed)' } unless V2JS.int?(now)

      verify_intent_required(b, keys, now)
    end

    # The RFC 9457 problem of a refusal: {status: 403, headers, body}. An unknown kind has no title and names no error (`error="undefined"`);
    # `intent-required` needs the signed body (raises without it) and names its session and question.
    def intent_problem(kind, opts = nil)
      o = opts.nil? ? {} : opts
      err = PROBLEM_ERRORS.key?(kind) ? PROBLEM_ERRORS[kind] : UNDEF
      params = ["error=\"#{V2JS.js_str(err)}\""]
      body = o.is_a?(Hash) && o.key?('body') ? o['body'] : UNDEF
      if kind == 'intent-required'
        raise 'intentProblem: intent-required needs the signed body' unless V2JS.truthy?(body)

        params << "session=\"#{V2JS.js_str(V2JS.prop(body, 'session'))}\"" << "question=\"#{V2JS.js_str(V2JS.prop(body, 'question_id'))}\""
      end
      out = { 'type' => PROBLEM_BASE + V2JS.js_str(kind) }
      out['title'] = PROBLEM_TITLES[kind] if PROBLEM_TITLES.key?(kind)
      out['status'] = 403
      out['detail'] = o['detail'] if o.is_a?(Hash) && o.key?('detail')
      out['pca'] = body if V2JS.truthy?(body)
      { 'status' => 403, 'headers' => { 'WWW-Authenticate' => "PCA #{params.join(', ')}", 'Content-Type' => 'application/problem+json' }, 'body' => out }
    end
  end
end
