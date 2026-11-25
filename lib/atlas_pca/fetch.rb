# frozen_string_literal: true

require 'stringio'
require_relative '../atlas_pca'
require_relative 'authorize'
require_relative 'rack_middleware'
require_relative 'arg_provenance'
require_relative 'caveat_lang'
require_relative 'js_compat'

# Runtime-neutral request guard for Proof-Carrying Authority, shaped like the Web Fetch guard of the TypeScript reference
# (@atlasauth/pca-fetch): wrap a handler so the inbound PCActn is verified first; on success the handler runs with the verdict
# and PCActn, otherwise a 401 / 403 response Hash with a WWW-Authenticate challenge is returned. It adds no verification of its
# own: it joins the core verifier (AtlasPca.verify_pcactn, signature_only) or the full AtlasPca.authorize pipeline (the default)
# to a request-like Hash {'method', 'url'?, 'headers', 'body'?} and a response Hash {'status', 'headers', 'body'}.
#
# Options are keyword arguments: audience:, resolve_grant:, operation: (->(headers, body) { {verb:, resource:, params:} | nil }),
# authorize: (an AtlasPca::AuthorizeOptions or a Hash of its members), signature_only:, now:, intent_policy:, intent_v2:,
# fresh_at:, allowed_suites:, workflow:, workflow_step:, insecure_allow_unbound_operation:, hooks: (with signature_only: the verifier
# hooks {'attestation', 'zk', 'threshold'} of AtlasPca.verify_pcactn).
#
# The agent-side signed fetch is AtlasPca::Agent#fetch.
module AtlasPca
  module Fetch
    PCA_HEADER = 'PCA-Action'
    REALM = 'pca'
    FRESH_AT_HEADER = 'pca-fresh-at'

    # Outcome of the guard. `ok` is the one thing a caller must branch on; `decision` is 'allow' (exactly when ok), 'escalate'
    # (refused: `escalation` is the request to put to the principal) or 'deny'.
    PcaResult = Struct.new(:ok, :status, :verdict, :pcactn, :error, :www_authenticate, :authorization, :decision, :escalation,
                           keyword_init: true) do
      def initialize(**kw)
        super
        self.decision ||= 'deny'
      end
    end

    module_function

    # An auth-param quoted-string: escape backslash and double-quote (RFC 7235).
    def quote(v) = "\"#{v.to_s.gsub('\\') { '\\\\' }.gsub('"') { '\\"' }}\""

    # A WWW-Authenticate challenge value: PCA realm="pca", ... built only from fixed tokens and the operator's own audience.
    def challenge(audience, error = nil, description = nil)
      parts = ["realm=#{quote(REALM)}"]
      parts << "audience=#{quote(audience)}" unless audience.nil?
      parts << "error=#{quote(error)}" unless error.nil?
      parts << "error_description=#{quote(description)}" unless description.nil?
      "PCA #{parts.join(', ')}"
    end

    # Case-insensitive header lookup over a Hash: every spelling is read; case-variants with DIFFERENT values make the credential
    # ambiguous -> absent (the caller then denies), never a silent pick. A list value reads as its first element.
    def get_header(headers, name)
      return nil unless headers.is_a?(Hash)

      low = name.downcase
      found = nil
      headers.each do |k, raw|
        next unless k.is_a?(String) && k.downcase == low

        v = raw.is_a?(Array) ? raw.first : raw
        next unless v.is_a?(String)
        return nil if !found.nil? && found != v

        found = v
      end
      found
    end

    def to_text(body)
      return nil unless body.is_a?(String) && !body.empty?

      t = body.dup.force_encoding(Encoding::UTF_8)
      t.valid_encoding? ? t : nil
    end

    # [pcactn, nil] on success, else [nil, 'absent' | 'undecodable'].
    def extract_pcactn(headers, body)
      raw = get_header(headers, PCA_HEADER)
      unless raw.nil? || raw.empty? # an empty header is no header: the body is read
        text = AtlasPca.decode_pca_header(raw)
        return [nil, 'undecodable'] if text.nil?

        obj = begin
          AtlasPca.parse_json(text)
        rescue AtlasPca::Malformed
          return [nil, 'undecodable']
        end
        return obj.is_a?(Hash) ? [obj, nil] : [nil, 'undecodable']
      end

      text = to_text(body)
      return [nil, 'absent'] if text.nil?

      envelope = begin
        AtlasPca.parse_json(text)
      rescue AtlasPca::Malformed
        return [nil, 'undecodable']
      end
      return [nil, 'absent'] unless envelope.is_a?(Hash) && envelope.key?('pcactn')

      envelope['pcactn'].is_a?(Hash) ? [envelope['pcactn'], nil] : [nil, 'undecodable']
    end

    def authorize_options(opt)
      return nil if opt.nil?
      return opt if opt.is_a?(AtlasPca::AuthorizeOptions)
      raise TypeError, 'authorize must be an AuthorizeOptions, a Hash of its members, or nil' unless opt.is_a?(Hash)

      h = opt.to_h { |k, v| [k.to_sym, v] }
      unknown = h.keys - RackMiddleware::AUTHORIZE_KEYS
      raise ArgumentError, "authorize: unknown option(s) #{unknown.join(', ')}" unless unknown.empty?

      AtlasPca::AuthorizeOptions.new(**h)
    end

    # The principal's EscalationAnswer: header PCA-Escalation-Answer (strict base64url JSON), else the body member
    # `escalation_answer`; nil when absent or unreadable (an unreadable answer is no answer).
    def escalation_answer(headers, body)
      raw = get_header(headers, 'PCA-Escalation-Answer')
      unless raw.nil? || raw.empty? # an empty header is no header: the body is read
        text = AtlasPca.decode_pca_header(raw)
        return text.nil? ? nil : AtlasPca.parse_json(text)
      end
      text = to_text(body)
      env = text.nil? ? nil : AtlasPca.parse_json(text)
      env.is_a?(Hash) ? env['escalation_answer'] : nil
    rescue StandardError
      nil
    end

    # The call's workflow step: the configured per-request callback when there is one (a callback that raises yields {}, which
    # admission refuses: fail closed), else the JSON body member `workflow`; nil when absent or the body is unreadable.
    def workflow_step_of(headers, body, callback)
      unless callback.nil?
        begin
          return callback.call(headers, body)
        rescue StandardError
          return {}
        end
      end
      text = to_text(body)
      env = text.nil? ? nil : AtlasPca.parse_json(text)
      env.is_a?(Hash) ? env['workflow'] : nil
    rescue StandardError
      nil
    end

    # Discharges and a narrow block as presented with a request ({} when unreadable: the K1 caveat stays unsatisfied).
    def presented_k1(headers)
      r = AtlasPca.presented_k1('pca-discharges' => get_header(headers, 'PCA-Discharges'), 'pca-narrow' => get_header(headers, 'PCA-Narrow'))
      r[:ok] ? r[:value] : {}
    end

    def k1_option(headers, k1)
      return nil if k1.nil?

      presented = presented_k1(headers)
      lambda do |pcactn|
        own = k1.respond_to?(:call) && !k1.is_a?(Hash) ? k1.call(pcactn) : k1
        raise TypeError, 'k1 is not a Hash' unless own.is_a?(Hash)

        presented.merge(own.to_h { |k, v| [k.is_a?(Symbol) ? k.to_s : k, v] })
      end
    end

    def provenance_option(headers, body, prov)
      return prov unless prov.nil? || prov.is_a?(Hash)

      own = (prov || {}).to_h { |k, v| [k.to_s, v] }
      return own if own['bundle'].respond_to?(:call)

      env = { 'rack.input' => StringIO.new(to_text(body) || '') }
      env[AtlasPca::PROV_RACK_HEADER] = get_header(headers, 'PCA-Provenance')
      own.merge('bundle' => ->(_pcactn, _operation) { AtlasPca.default_provenance_bundle(env) })
    end

    def wall_clock = (Time.now.to_f * 1000).to_i

    # AtlasPca.authorize with the members of an AuthorizeOptions; `over` carries the per-request inputs (operation, audience, now,
    # k1, provenance ...) and wins over the options.
    def authorize_with(az, pcactn, **over)
      kw = { state_store: az.state_store, is_revoked: az.is_revoked, plan: az.plan, context: az.context, require: az.require,
             escalation_principals: az.escalation_principals, revocation_staleness: az.revocation_staleness, plans: az.plans,
             require_assurance: az.require_assurance, uses_store: az.uses_store, escalation_render: az.escalation_render,
             insecure_unbound_approval: az.insecure_unbound_approval == true, undo: az.undo, risk: az.risk,
             threshold_hook: az.threshold_hook, assurance_hooks: az.assurance_hooks, attestation: az.attestation, zk: az.zk, pq_pins: az.pq_pins, require_risk_inputs: az.require_risk_inputs,
             resolve_principal: az.resolve_principal, require_verified_principal: az.require_verified_principal,
             require_passport: az.require_passport, passport: az.passport, enforce_freshness: az.enforce_freshness,
             adaptive: az.adaptive, seed_budget: az.seed_budget, enforce_taint: az.enforce_taint, beacon: az.beacon,
             require_linked_template: az.require_linked_template, forbid: az.forbid, contracts: az.contracts,
             multi_instance: az.multi_instance }
      AtlasPca.authorize(pcactn, **kw.merge(over))
    end

    # The framework-agnostic guard: ->(headers, body = nil, operation: nil) -> PcaResult. Default-deny.
    def require_pca(audience:, resolve_grant:, now: nil, intent_policy: nil, intent_v2: nil, authorize: nil, operation: nil, signature_only: false,
                    fresh_at: nil, allowed_suites: nil, workflow: nil, workflow_step: nil, hooks: nil)
      raise ArgumentError, 'require_pca: signature_only and authorize are mutually exclusive' if signature_only && !authorize.nil?
      # the verifier hooks of the signature-only path; the authorize path takes them in its options (attestation:, zk:, threshold_hook:)
      raise ArgumentError, 'require_pca: hooks must be a Hash' unless hooks.nil? || hooks.is_a?(Hash)
      raise ArgumentError, 'require_pca: hooks is for signature_only; give attestation / zk / threshold_hook in authorize' if !hooks.nil? && !signature_only

      hooks = (hooks || {}).transform_keys(&:to_s).freeze
      raise ArgumentError, 'workflow: needs the authorize path (not signature_only)' if !workflow.nil? && signature_only

      az = signature_only ? nil : (authorize_options(authorize) || AtlasPca::AuthorizeOptions.new)
      suites = allowed_suites&.dup&.freeze # a snapshot: mutating the caller's list later must not widen it
      clock = -> { n = now.respond_to?(:call) ? now.call : now; n.nil? ? wall_clock : n }

      authorized = lambda do |pcactn, headers, body, op, fa, step|
        if op.nil?
          mapper = operation || az.operation
          if mapper.respond_to?(:call)
            op = begin
              operation.nil? ? mapper.call({ 'rack.input' => StringIO.new(to_text(body) || '') }) : mapper.call(headers, body)
            rescue StandardError # the host's mapping failed: no operation, which denies below
              nil
            end
          end
        end
        r = authorize_with(az, pcactn, operation: op, audience: audience, resolve_grant: resolve_grant, now: clock.call,
                                       intent_policy: intent_policy, intent_v2: intent_v2, allowed_suites: suites,
                                       escalation_answer: az.escalation_principals.nil? || az.escalation_principals.empty? ? nil : escalation_answer(headers, body),
                                       fresh_at: fa, k1: k1_option(headers, az.k1), workflow: workflow, workflow_call: step,
                                       provenance: provenance_option(headers, body, az.provenance))
        return PcaResult.new(ok: true, status: 200, verdict: r.verdict, pcactn: pcactn, authorization: r, decision: 'allow', escalation: r.escalation) if r.allow

        code = r.status == 401 ? 'invalid_pcactn' : 'insufficient_authority'
        # the reason stays on `error` / `authorization` (never in the header: it can carry request-derived text)
        PcaResult.new(ok: false, status: r.status, verdict: r.verdict, pcactn: pcactn, error: r.reason,
                      www_authenticate: challenge(audience, code), authorization: r, decision: r.decision, escalation: r.escalation)
      end

      lambda do |headers, body = nil, operation: nil|
        step = az.nil? || workflow.nil? ? nil : workflow_step_of(headers, body, workflow_step)
        # the workflow refusal needs no PCActn: it comes before the PCActn is read, exactly as in authorize
        if !az.nil? && !workflow.nil? && (!workflow.is_a?(Hash) || (AtlasPca.arg_member(workflow, 'required') == true && step.nil?))
          return authorized.call(nil, headers, body, operation, nil, step)
        end

        pcactn, err = extract_pcactn(headers, body)
        if pcactn.nil?
          desc = err == 'absent' ? 'no PCActn presented' : 'PCActn could not be decoded'
          return PcaResult.new(ok: false, status: 401, error: err,
                               www_authenticate: challenge(audience, err == 'absent' ? 'missing_pcactn' : 'invalid_pcactn', desc))
        end

        fa = fresh_at
        if fresh_at.respond_to?(:call)
          begin
            fa = fresh_at.call(pcactn)
          rescue StandardError # the host's state lookup failed: fail closed
            return PcaResult.new(ok: false, status: 403, pcactn: pcactn, error: 'fresh_at_context_error',
                                 www_authenticate: challenge(audience, 'insufficient_authority', 'fresh_at verifier state unavailable (fail closed)'))
          end
        end
        if fa.is_a?(Hash) && !pcactn.key?('fresh_at') && !fa.key?('side_carried')
          side = get_header(headers, FRESH_AT_HEADER)
          unless side.nil?
            tok = begin
              AtlasPca.parse_json(side, any_top: true)
            rescue StandardError # an unparseable token is a bad token (deny), never a missing one
              nil
            end
            fa = fa.merge('side_carried' => tok)
          end
        end
        return authorized.call(pcactn, headers, body, operation, fa, step) unless az.nil?

        grant_ref = pcactn['grant_ref']
        # a grant_ref that is not a string (absent, null, list, object, number) is a malformed PCActn (401) and never reaches the
        # host's resolver
        unless grant_ref.is_a?(String)
          return PcaResult.new(ok: false, status: 401, pcactn: pcactn, error: 'malformed',
                               www_authenticate: challenge(audience, 'invalid_pcactn', 'malformed PCActn'))
        end

        grant = begin
          resolve_grant.call(grant_ref)
        rescue StandardError # the host's resolver failed: fail closed (never a 500)
          return PcaResult.new(ok: false, status: 403, pcactn: pcactn, error: 'resolve_grant_error',
                               www_authenticate: challenge(audience, 'insufficient_authority', 'grant resolution failed (fail closed)'))
        end
        unless grant.is_a?(Hash)
          return PcaResult.new(ok: false, status: 401, pcactn: pcactn, error: 'unknown_grant',
                               www_authenticate: challenge(audience, 'unknown_grant', 'grant_ref does not resolve to a known grant'))
        end

        v2 = intent_v2
        if !intent_v2.is_a?(Hash) && intent_v2.respond_to?(:call)
          begin
            v2 = intent_v2.call(pcactn)
          rescue StandardError # the host's state lookup failed: fail closed, never verify without it
            return PcaResult.new(ok: false, status: 403, pcactn: pcactn, error: 'intent_v2_context_error',
                                 www_authenticate: challenge(audience, 'insufficient_authority', 'intent v2 verifier state unavailable (fail closed)'))
          end
        end
        verdict = AtlasPca.verify_pcactn(pcactn, grant, now: clock.call, audience: audience, intent_policy: intent_policy, intent_v2: v2,
                                                        fresh_at: fa, allowed_suites: suites,
                                                        insecure_skip_plan_root_check: true, # signatures only: `authorize` checks the plan
                                                        attestation_hook: hooks['attestation'], zk_hook: hooks['zk'], threshold_hook: hooks['threshold'])
        if verdict.allow && pcactn.key?('bond_ref') # the core never verifies a bond; a guard never lets one through
          return PcaResult.new(ok: false, status: 403, verdict: verdict, pcactn: pcactn, error: AtlasPca::BOND_UNSUPPORTED,
                               www_authenticate: challenge(audience, 'insufficient_authority'))
        end
        return PcaResult.new(ok: true, status: 200, verdict: verdict, pcactn: pcactn, decision: 'allow') if verdict.allow

        # never echo the reason into the header: it can carry attacker-controlled text (CR/LF -> header injection)
        PcaResult.new(ok: false, status: 403, verdict: verdict, pcactn: pcactn,
                      error: verdict.reason.nil? || verdict.reason.empty? ? 'insufficient_authority' : verdict.reason,
                      www_authenticate: challenge(audience, 'insufficient_authority'))
      end
    end

    def build_guard(options)
      options = options.dup
      raise TypeError, 'pca-fetch: `audience` (this resource server\'s id) is required' if options[:audience].nil? || options[:audience].to_s.empty?

      # a proof must be bound to the operation the request will execute (or use `authorize`); the unbound form is an explicit opt-in
      unbound = options.delete(:insecure_allow_unbound_operation) == true
      if options[:operation].nil? && options[:authorize].nil? && !unbound && options[:signature_only] != true
        raise TypeError, 'pca-fetch: `operation` is required: map each request to the operation it will execute so the proof is bound ' \
                         'to it, or use `authorize`; set insecure_allow_unbound_operation only to migrate'
      end
      options[:signature_only] = true if unbound && options[:operation].nil? && !options.key?(:signature_only)
      guard = require_pca(**options)
      ->(req) { guard.call(req['headers'] || {}, req['body']) }
    end

    # A verifier over a request-like Hash returning the full guard result, so you can compose it yourself. Raises TypeError when
    # the configuration is unsafe (no audience, no operation mapping).
    def create_pca_fetch_guard(**options) = build_guard(options)

    # The 401 / 403 response for a refusal: JSON body {error, verdict, decision, escalation?} (or deny_body.call(result)),
    # content-type: application/json and the WWW-Authenticate challenge.
    def deny_response(result, deny_body = nil)
      if deny_body
        body = deny_body.call(result)
      else
        az = result.authorization
        v = result.verdict
        verdict =
          if !az.nil?
            { 'allow' => false, 'checks' => (az.checks || {}).dup, 'reasons' => (az.reasons || []).dup }
          elsif !v.nil?
            reasons = v.reasons.nil? || v.reasons.empty? ? (v.reason.nil? || v.reason.empty? ? [] : [v.reason]) : v.reasons.dup
            { 'allow' => v.allow ? true : false, 'checks' => v.checks.dup, 'reasons' => reasons }
          else
            { 'allow' => false, 'checks' => {}, 'reasons' => result.error.nil? || result.error.empty? ? [] : [result.error] }
          end
        body = { 'error' => verdict['reasons'].empty? ? 'forbidden' : verdict['reasons'][0], 'verdict' => verdict, 'decision' => result.decision || 'deny' }
        body['escalation'] = result.escalation if result.escalation
      end
      headers = { 'content-type' => 'application/json' }
      headers['WWW-Authenticate'] = result.www_authenticate if result.www_authenticate && !result.www_authenticate.empty?
      { 'status' => result.status, 'headers' => headers, 'body' => Js.json(body) }
    end

    # Wrap handler.call(request, {'pca' => {'verdict', 'pcactn', 'operation'?}}) so the inbound PCActn is verified first.
    def with_pca(handler, deny_body: nil, **options)
      guard = build_guard(options)
      lambda do |req|
        result = guard.call(req)
        if result.ok
          pca = { 'verdict' => result.verdict, 'pcactn' => result.pcactn }
          pca['operation'] = result.authorization.operation if !result.authorization.nil? && !result.authorization.operation.nil?
          next handler.call(req, { 'pca' => pca })
        end
        deny_response(result, deny_body)
      end
    end
  end
end
