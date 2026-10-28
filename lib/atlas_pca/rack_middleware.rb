# frozen_string_literal: true

# Rack middleware for Proof-Carrying Authority, built ON TOP of the AtlasPca verifier.
#
# Caveats are NOT evaluated here (nor by the core verifier): a resource server that enforces the grant's caveats calls
# AtlasPca.evaluate_caveats(AtlasPca.policy_caveats(grant, pcactn['cap_chain']), ctx) with its own action params (the root
# grant's caveats outside the envelope included: the 0.4.1 policy-layer security fix).
#
# It does NO crypto of its own: it decodes a PCActn off the request, resolves the grant it
# names, and defers every decision to AtlasPca.verify_pcactn (all 8 offline checks, audience
# vs the signed `aud`, chain rooted at the resolved grant). On success the verdict and the
# parsed PCActn are stashed in env['pca'] and the app runs; on failure a Rack response is
# returned without ever calling the app.
#
# Rack is a SOFT dependency: this file does not `require 'rack'`; it only implements the
# `call(env)` contract and returns the [status, headers, body] triple Rack expects, so the
# base gem stays framework-free. `require 'atlas_pca/rack_middleware'` pulls in the verifier
# (stdlib only) but never Rack or Rails.
require_relative '../atlas_pca'

module AtlasPca
  # Rack middleware that gates a request on a valid PCActn.
  #
  #   use AtlasPca::RackMiddleware,
  #       audience: 'rs-billing',
  #       resolve_grant: ->(grant_ref) { GRANTS[grant_ref] }
  #
  # Options:
  #   audience:       (required) the resource-server identifier this app answers to; compared
  #                   against the PCActn's signed `aud` by the verifier.
  #   resolve_grant:  (required) a callable grant_ref -> grant Hash | nil. nil means "unknown
  #                   grant" and yields 401. The grant is the root capability the chain must
  #                   be rooted at. It is only called with a String grant_ref (anything else is a
  #                   401 'malformed PCActn'); if it raises, the request fails closed with a 403.
  #   now:            (optional) current time in epoch milliseconds, or a callable returning it.
  #                   Defaults to wall-clock. Used for the validity-window check.
  #   header:         (optional) the Rack env key carrying the base64url PCActn. Defaults to
  #                   'HTTP_PCA_ACTION' (the `PCA-Action` request header).
  #   intent_policy:  (optional) Intent Layer M2 policy Hash { require:, min_fidelity_ppm:, max_residual_risk_ppm:,
  #                   approved_goal: } forwarded to AtlasPca.verify_pcactn (an active policy denies a PCActn without a bound
  #                   intent). `approved_goal: { goal_digest:, policy_digest: }` (canonical base64url, 32 bytes each) selects goal
  #                   binding v3: only a grant committed to exactly that goal and compiled policy opens; a malformed
  #                   approved_goal is a fail-closed misconfiguration (every request is denied).
  #   intent_v2:      (optional) Intent Layer v2 verifier state + policy (String keys: policy, params, schema, session,
  #                   layers, acc, wb; see AtlasPca.decide_intent_v2): a Hash, or a callable (pcactn) -> Hash | nil
  #                   evaluated per request (the host's store lookup: session root, held grants, accumulator pre-state
  #                   under its row lock, receipts, plaintext params). A callable that raises fails closed: 403
  #                   `intent_v2_context_error`, and the verifier is not run.
  #   fresh_at:       (optional) consistency-token policy Hash (String keys, see AtlasPca.verify_pcactn), forwarded on both paths;
  #                   the side-carried PCA-Fresh-At header (HTTP_PCA_FRESH_AT) is read only when the PCActn has no member.
  #   signature_only: (optional, default false) opt in to verifying the signature and chain only (the core verifier): no
  #                   caveats, replay, revocation or operation binding. Giving it together with `authorize:` raises.
  #   authorize:      (0.5 default path) the full AtlasPca.authorize pipeline: an
  #                   AtlasPca::AuthorizeOptions, or a Hash (Symbol or String keys) of its members:
  #                     state_store: replay store with an atomic claim(key, counter) (required)
  #                     is_revoked:  ->(pcactn, grant) { true | false } (required; only false passes)
  #                     operation:   ->(env) { {verb:, resource:, params:} | nil }, the operation this route executes,
  #                                  from the request (method, path, parsed body), never from the PCActn. nil (or no
  #                                  mapping, or a mapping that raises) denies with a 403.
  #                     plan:        'single-step' (default) or nil (then `context` must supply the authorized plan)
  #                     context:     ->(pcactn) { Hash | nil } (see AtlasPca.authorize)
  #                     require:     extra check names that must pass
  #                     k1:          (optional) the caveat language v2 input (see AtlasPca.authorize): a Hash or ->(pcactn) { Hash }.
#                                  Configured, the discharges / narrow block presented in the PCA-Discharges / PCA-Narrow
#                                  headers are merged under it (your members win); unreadable headers are no discharges.
#                                  Not configured: every K1 caveat in the chain is refused.
#                     uses_store:  (optional) replay store that spends max_uses slots (consume_once, else claim)
#                     escalation_principals: pinned principal keys whose EscalationAnswers count (header
  #                                  PCA-Escalation-Answer: strict base64url JSON, else the JSON body member
  #                                  `escalation_answer`); none pinned: every escalate is refused. The store must offer last(key).
  #                     revocation_staleness: an AtlasPca::RevocationStaleness (T9); the revocation state comes from the
  #                                  `context` member 'revocation_state' (see AtlasPca.authorize); a stale or unverifiable
  #                                  state fails the `freshness` check.
  #                     require_assurance: a high-assurance policy Hash, e.g. { 'signature' => 'pq' }: unmet evidence fails the
  #                                  `assurance` check before any replay state is written.
  #                     plans:       an AtlasPca::PlanRegistry (T10): the registered plan and its executability feed
  #                                  `plan_root_authorized`; the `plan_state` check names the state on a denial.
  #                   A denial is a 401 (`invalid_pcactn`) or 403 (`access_denied`) before the app runs; on success
  #                   env['pca'] also holds 'authorization' (the AtlasPca::AuthorizeResult) and 'operation' (the bound
  #                   AtlasPca::AuthorizedOperation). Without `authorize:` (and without `signature_only: true`) the options are empty: every
  #                   request is refused with a 403 `authorize_config` that names the missing components.
  #   workflow:       (optional, authorize path) K5 workflow admission {principal:, rs_signer:, required: false} forwarded to
  #                   AtlasPca.authorize. The request's workflow step {commitment, receipts, step, units, goal_digest} comes from
  #                   `workflow_step:` (->(env) { Hash | nil }; a raise is no step), else from the
  #                   JSON request body member `workflow`, else none. Required and no step: 403 before the PCActn is read; an
  #                   undecodable PCActn is the pipeline's own 401. Refusals: 403 `access_denied`, failed_checks ['workflow'].
  #   executor:       (optional, needs the authorize path) run the app at most once per authorization with a durable operation
  #                   record (T3): a Hash of AtlasPca::Executor options: operations: (an OperationStore, required), recheck:,
  #                   recheck_for:, reversibility_class_of:, pending_timeout_ms:. The app runs inside
  #                   AtlasPca.execute_authorized: an irreversible operation needs `recheck` (fail closed), a retry of the same
  #                   PCActn is answered from the record (header `PCA-Replayed: true`) without running the app again, a raise
  #                   from the app is recorded `failed` (500 `operation_failed`), a record still in flight is 409
  #                   `operation_in_progress`, an unknown outcome 409 `operation_uncertain`, a refused re-check 403
  #                   `operation_aborted`. The app's Rack response (status, headers, body) is the recorded result.
  #                   env['pca'] also holds 'idempotency_key' (hand it to the downstream call).
  class RackMiddleware
    REALM = 'pca'
    DEFAULT_HEADER = 'HTTP_PCA_ACTION'

    class DecodeError < StandardError; end

    AUTHORIZE_KEYS = %i[state_store is_revoked plan context require operation escalation_principals revocation_staleness
                        require_assurance plans k1 uses_store].freeze
    EXECUTOR_KEYS = %i[operations recheck recheck_for reversibility_class_of pending_timeout_ms].freeze
    FRESH_AT_HEADER = 'HTTP_PCA_FRESH_AT'
    DISCHARGES_HEADER = 'HTTP_PCA_DISCHARGES'
    NARROW_HEADER = 'HTTP_PCA_NARROW'
    ESCALATION_HEADER = 'HTTP_PCA_ESCALATION_ANSWER'

    def initialize(app, audience:, resolve_grant:, now: nil, header: DEFAULT_HEADER, intent_policy: nil, intent_v2: nil,
                   authorize: nil, signature_only: false, executor: nil, fresh_at: nil, workflow: nil, workflow_step: nil)
      raise ArgumentError, 'audience: is required' if audience.nil? || audience.to_s.empty?
      raise ArgumentError, 'resolve_grant: must respond to #call' unless resolve_grant.respond_to?(:call)
      unless intent_v2.nil? || intent_v2.is_a?(Hash) || intent_v2.respond_to?(:call)
        raise ArgumentError, 'intent_v2: must be a Hash or respond to #call'
      end

      if signature_only && !authorize.nil?
        raise ArgumentError, 'signature_only: and authorize: are mutually exclusive (signature_only skips the checks authorize enforces)'
      end

      raise ArgumentError, 'workflow: must be a Hash' unless workflow.nil? || workflow.is_a?(Hash)
      raise ArgumentError, 'workflow: needs the authorize path (not signature_only)' if !workflow.nil? && signature_only
      raise ArgumentError, 'workflow_step: must respond to #call' unless workflow_step.nil? || workflow_step.respond_to?(:call)

      @workflow = workflow
      @workflow_step = workflow_step
      @authorize = signature_only ? nil : authorize_options(authorize || {})
      raise ArgumentError, 'executor: needs the authorize path (not signature_only)' if !executor.nil? && @authorize.nil?

      @app = app
      @audience = audience
      @resolve_grant = resolve_grant
      @now = now
      @header = header
      @intent_policy = intent_policy
      @intent_v2 = intent_v2
      @executor = executor.nil? ? nil : build_executor(executor)
      @fresh_at = fresh_at
    end

    def call(env)
      step = @workflow.nil? ? nil : workflow_call_of(env)
      if !@workflow.nil? && step.nil? && AtlasPca.arg_member(@workflow, 'required') == true
        # TS order: required and no step is refused before the PCActn is read
        return json_response(403, 'access_denied', 'workflow: this call carries no workflow step (fail closed)',
                             'failed_checks' => ['workflow'], 'decision' => 'deny')
      end
      pcactn =
        begin
          extract(env)
        rescue DecodeError => e
          return unauthorized(e.message)
        end
      return unauthorized('no PCActn presented') if pcactn.nil?
      return call_authorize(env, pcactn, step) unless @authorize.nil?

      # Mirrors TS requirePCA: a grant_ref that is not a String (absent, nil, Array, Hash, Integer) is a malformed PCActn
      # (401 invalid_pcactn) and never reaches the host's resolver.
      grant_ref = pcactn['grant_ref']
      return unauthorized('malformed PCActn') unless grant_ref.is_a?(String)

      grant =
        begin
          @resolve_grant.call(grant_ref)
        rescue StandardError
          # the host's resolver failed: fail closed (TS: 403 guard error), never a 500
          return json_response(403, 'access_denied', 'grant resolution failed (fail closed)')
        end
      return unauthorized('unknown grant') if grant.nil?

      v2 = @intent_v2
      if !v2.is_a?(Hash) && v2.respond_to?(:call)
        begin
          v2 = v2.call(pcactn)
        rescue StandardError
          # the host's state lookup failed: fail closed, never verify without it
          return json_response(403, 'intent_v2_context_error', 'intent v2 verifier state unavailable (fail closed)')
        end
      end
      verdict = AtlasPca.verify_pcactn(pcactn, grant, now: current_now, audience: @audience,
                                                           intent_policy: @intent_policy, intent_v2: v2,
                                                           fresh_at: fresh_at_policy(env, pcactn))
      return forbidden(verdict) unless verdict.allow

      env['pca'] = { 'verdict' => verdict, 'pcactn' => pcactn }
      @app.call(env)
    end

    private

    # The fresh_at policy, plus the side-carried `pca-fresh-at` header (strict base64url JSON) when the PCActn has no member.
    # An unparseable header is a nil side-carried token (bad_token), never an absent one.
    def fresh_at_policy(env, pcactn)
      return @fresh_at unless @fresh_at.is_a?(Hash) && !pcactn.key?('fresh_at')

      raw = env[FRESH_AT_HEADER]
      return @fresh_at if raw.nil? || raw.empty?

      text = AtlasPca.decode_pca_header(raw)
      token = begin
        text && AtlasPca.parse_json(text)
      rescue AtlasPca::Malformed
        nil
      end
      @fresh_at.merge('side_carried' => token)
    end

    def authorize_options(opt)
      return nil if opt.nil?
      return opt if opt.is_a?(AtlasPca::AuthorizeOptions)
      raise ArgumentError, 'authorize: must be an AtlasPca::AuthorizeOptions or a Hash' unless opt.is_a?(Hash)

      h = opt.to_h { |k, v| [k.to_sym, v] }
      unknown = h.keys - AUTHORIZE_KEYS
      raise ArgumentError, "authorize: unknown option(s) #{unknown.join(', ')}" unless unknown.empty?

      AtlasPca::AuthorizeOptions.new(**h)
    end

    def build_executor(opt)
      raise ArgumentError, 'executor: must be a Hash of executor options' unless opt.is_a?(Hash)

      h = opt.to_h { |k, v| [k.to_sym, v] }
      unknown = h.keys - EXECUTOR_KEYS
      raise ArgumentError, "executor: unknown option(s) #{unknown.join(', ')}" unless unknown.empty?
      raise ArgumentError, 'executor: operations: (an OperationStore) is required' unless AtlasPca.op_store_ok?(h[:operations])

      AtlasPca::Executor.new(options: @authorize, audience: @audience, resolve_grant: @resolve_grant,
                             now: -> { current_now }, **h)
    end

    # The authorize path: the route's operation, then the full pipeline; the app runs only on an allow.
    def call_authorize(env, pcactn, step = nil)
      opts = @authorize
      mapping = opts.operation
      operation =
        begin
          # no mapping: authorize reports a missing store / revocation check first (authorize_config), then the operation
          mapping.respond_to?(:call) ? mapping.call(env) : nil
        rescue StandardError
          return json_response(403, 'access_denied', 'operation: the operation mapping failed (fail closed)',
                               'failed_checks' => ['operation'])
        end
      return call_executor(env, pcactn, operation, step) unless @executor.nil?

      result = AtlasPca.authorize(pcactn, operation: operation, audience: @audience, resolve_grant: @resolve_grant,
                                          state_store: opts.state_store, is_revoked: opts.is_revoked, now: current_now,
                                          plan: opts.plan, context: opts.context, intent_policy: @intent_policy,
                                          intent_v2: @intent_v2, require: opts.require,
                                          escalation_principals: opts.escalation_principals,
                                          escalation_answer: escalation_answer(env, opts),
                                          revocation_staleness: opts.revocation_staleness, plans: opts.plans,
                                          require_assurance: opts.require_assurance,
                                          fresh_at: fresh_at_policy(env, pcactn),
                                          k1: k1_option(env, opts.k1), uses_store: opts.uses_store,
                                          escalation_render: opts.escalation_render, insecure_unbound_approval: opts.insecure_unbound_approval == true,
                                          workflow: @workflow, workflow_call: step)
      return denied(result) unless result.allow

      env['pca'] = { 'verdict' => result.verdict, 'pcactn' => result.pcactn, 'authorization' => result,
                     'operation' => result.operation }
      @app.call(env)
    end

    # The refusal of a denying AuthorizeResult: 401 for an authentication failure, 403 otherwise.
    def denied(result)
      extra = { 'failed_checks' => result.failed_checks, 'decision' => result.decision }
      extra['escalation'] = result.escalation unless result.escalation.nil?
      extra['missing'] = result.missing unless result.missing.nil?
      reason = result.reason || 'denied'
      return json_response(401, 'invalid_pcactn', reason, extra) if result.status == 401

      json_response(403, 'access_denied', reason, extra)
    end

    # The executor path: authorize, then the app runs inside execute_authorized (see `executor:`).
    def call_executor(env, pcactn, operation, step = nil)
      out = @executor.call(pcactn, operation, intent_policy: @intent_policy, intent_v2: @intent_v2,
                                              escalation_answer: escalation_answer(env, @authorize),
                                              k1: k1_option(env, @authorize&.k1), fresh_at: fresh_at_policy(env, pcactn),
                                              workflow: @workflow, workflow_call: step) do |h|
        az = h.authorization
        env['pca'] = { 'verdict' => az.verdict, 'pcactn' => az.pcactn, 'authorization' => az, 'operation' => az.operation,
                       'idempotency_key' => h.idempotency_key }
        status, headers, body = @app.call(env)
        parts = +''.b
        body.each { |c| parts << c.to_s.b }
        body.close if body.respond_to?(:close)
        { 'status' => status, 'headers' => headers.to_h { |k, v| [k.to_s, v.to_s] }, 'body' => Base64.strict_encode64(parts) }
      end
      case out.status
      when 'committed' then recorded_response(out)
      when 'denied' then denied(out.authorization)
      when 'failed' then json_response(500, 'operation_failed', 'the operation failed')
      when 'aborted' then json_response(403, 'operation_aborted', out.reason.to_s)
      when 'pending' then json_response(409, 'operation_in_progress', 'another execution of this operation is in flight')
      when 'uncertain' then json_response(409, 'operation_uncertain', out.reason.to_s)
      else json_response(403, 'access_denied', out.reason.to_s)
      end
    end

    # The app's recorded Rack response, rebuilt from the operation record.
    def recorded_response(out)
      r = out.result
      unless r.is_a?(Hash) && r['status'].is_a?(Integer) && r['headers'].is_a?(Hash) && r['body'].is_a?(String)
        return json_response(409, 'operation_uncertain', 'the recorded result is unreadable')
      end

      headers = r['headers'].dup
      headers['pca-replayed'] = 'true' if out.replayed
      [r['status'], headers, [Base64.strict_decode64(r['body'])]]
    rescue ArgumentError
      json_response(409, 'operation_uncertain', 'the recorded result is unreadable')
    end

    # TS k1Of: {...presented, ...own}, only when k1 is configured; unreadable headers are no discharges.
    def k1_option(env, k1)
      return nil if k1.nil?

      presented = AtlasPca.presented_k1('pca-discharges' => env[DISCHARGES_HEADER], 'pca-narrow' => env[NARROW_HEADER])
      presented = presented[:ok] ? presented[:value] : {}
      ->(pcactn) do
        own = k1.respond_to?(:call) && !k1.is_a?(Hash) ? k1.call(pcactn) : k1
        raise TypeError, 'k1 is not a Hash' unless own.is_a?(Hash)

        presented.merge(own.to_h { |k, v| [k.is_a?(Symbol) ? k.to_s : k, v] })
      end
    end

    # The request's workflow step: the `workflow_step:` callback if configured (a raise is no step), else the JSON body member
    # `workflow`; nil when none. A non-Hash member is passed on so authorize refuses it (fail closed).
    def workflow_call_of(env)
      return (@workflow_step.call(env) rescue nil) unless @workflow_step.nil?

      input = env['rack.input']
      body = input.nil? ? nil : read_rewind(input)
      return nil if body.nil? || body.empty?

      obj = AtlasPca.parse_json(body.dup.force_encoding('UTF-8'))
      obj.is_a?(Hash) ? obj['workflow'] : nil
    rescue StandardError
      nil
    end

    # The principal's EscalationAnswer: header PCA-Escalation-Answer (strict unpadded base64url of the JSON), else the body
    # member `escalation_answer`. nil when none is pinned, absent or unreadable (an unreadable answer is no answer).
    def escalation_answer(env, opts)
      return nil if opts.escalation_principals.nil? || opts.escalation_principals.empty?

      raw = env[ESCALATION_HEADER]
      return strict_object(AtlasPca.decode_pca_header(raw) || '') unless raw.nil? || raw.empty?

      input = env['rack.input']
      body = input.nil? ? nil : read_rewind(input)
      return nil if body.nil? || body.empty?

      env_obj = AtlasPca.parse_json(body.dup.force_encoding('UTF-8'))
      env_obj.is_a?(Hash) ? env_obj['escalation_answer'] : nil
    rescue StandardError
      nil
    end

    # Returns the parsed PCActn Hash, nil if none presented, or raises DecodeError if what was
    # presented cannot be decoded. Header wins over body.
    def extract(env)
      raw = env[@header]
      return from_header(raw) unless raw.nil? || raw.empty?

      from_body(env)
    end

    # Header path: strict unpadded base64url of strict UTF-8 (AtlasPca.decode_pca_header, 0.4.1) -> JSON text -> the
    # SDK's strict JSON profile. Padding, the standard alphabet, whitespace or bytes that are not UTF-8 are a 401 here.
    def from_header(raw)
      text = AtlasPca.decode_pca_header(raw)
      raise DecodeError, 'PCActn header is not canonical base64url' if text.nil?

      strict_object(text)
    end

    # Body path: a JSON object { "pcactn": <PCActn object> }. The body is rewound so the
    # downstream app can still read it.
    def from_body(env)
      input = env['rack.input']
      return nil if input.nil?

      body = read_rewind(input)
      return nil if body.nil? || body.empty?

      envelope =
        begin
          AtlasPca.parse_json(body.dup.force_encoding('UTF-8'))
        rescue AtlasPca::Malformed => e
          raise DecodeError, "request body is not valid JSON: #{e.message}"
        end
      pcactn = envelope['pcactn']
      return nil if pcactn.nil?
      raise DecodeError, 'body "pcactn" is not an object' unless pcactn.is_a?(Hash)

      pcactn
    end

    def strict_object(text)
      obj = AtlasPca.parse_json(text)
      raise DecodeError, 'PCActn is not an object' unless obj.is_a?(Hash)

      obj
    rescue AtlasPca::Malformed => e
      raise DecodeError, "PCActn failed the strict JSON profile: #{e.message}"
    end

    def read_rewind(input)
      body = input.read
      body
    ensure
      input.rewind if input.respond_to?(:rewind)
    end

    def current_now
      n = @now.respond_to?(:call) ? @now.call : @now
      return n unless n.nil?

      (Time.now.to_f * 1000).to_i
    end

    # ----- responses -----

    def unauthorized(description)
      json_response(401, 'invalid_pcactn', description)
    end

    def forbidden(verdict)
      reason = verdict.reason.nil? || verdict.reason.empty? ? 'policy denied the action' : verdict.reason
      failed = verdict.checks.reject { |_, ok| ok }.keys
      json_response(403, 'access_denied', reason, 'failed_checks' => failed)
    end

    def json_response(status, error, description, extra = {})
      payload = { 'error' => error, 'error_description' => description }.merge(extra)
      headers = { 'content-type' => 'application/json' }
      headers['WWW-Authenticate'] = www_authenticate(error) if status == 401 || status == 403
      [status, headers, [to_json(payload)]]
    end

    # Only the realm and the static error code. The description is NOT emitted: it can carry request-derived text (the
    # verdict reason, a JSON parse error) with CR/LF (header injection); TS requirePCA puts no reason in its challenge
    # either. The description stays in the JSON body.
    def www_authenticate(error)
      %(PCA realm="#{REALM}", error="#{error}")
    end

    # Small, dependency-free JSON emitter for the flat error payloads above
    # (values are strings or arrays of strings only).
    def to_json(payload)
      parts = payload.map do |k, v|
        rendered =
          if v.is_a?(Array)
            "[#{v.map { |s| jstr(s) }.join(',')}]"
          elsif v.is_a?(Hash)
            AtlasPca.canonicalize(v)
          else
            jstr(v)
          end
        "#{jstr(k)}:#{rendered}"
      end
      "{#{parts.join(',')}}"
    end

    def jstr(s)
      out = +'"'
      s.to_s.each_char do |c|
        out << case c
               when '"' then '\\"'
               when '\\' then '\\\\'
               when "\b" then '\\b'
               when "\f" then '\\f'
               when "\n" then '\\n'
               when "\r" then '\\r'
               when "\t" then '\\t'
               else c.ord < 0x20 ? format('\\u%04x', c.ord) : c
               end
      end
      out << '"'
    end
  end
end

# Convenience alias for apps that reach for the Rack namespace (only if Rack is loaded;
# defining it never pulls Rack in).
if defined?(Rack)
  module Rack
    PCA = AtlasPca::RackMiddleware
  end
end
