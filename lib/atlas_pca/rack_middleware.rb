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
  #   intent_policy:  (optional) Intent Layer M2 policy Hash { require:, min_fidelity_ppm:, max_residual_risk_ppm: }
  #                   forwarded to AtlasPca.verify_pcactn (an active policy denies a PCActn without a bound intent).
  #   intent_v2:      (optional) Intent Layer v2 verifier state + policy (String keys: policy, params, schema, session,
  #                   layers, acc, wb; see AtlasPca.decide_intent_v2): a Hash, or a callable (pcactn) -> Hash | nil
  #                   evaluated per request (the host's store lookup: session root, held grants, accumulator pre-state
  #                   under its row lock, receipts, plaintext params). A callable that raises fails closed: 403
  #                   `intent_v2_context_error`, and the verifier is not run.
  class RackMiddleware
    REALM = 'pca'
    DEFAULT_HEADER = 'HTTP_PCA_ACTION'

    class DecodeError < StandardError; end

    def initialize(app, audience:, resolve_grant:, now: nil, header: DEFAULT_HEADER, intent_policy: nil, intent_v2: nil)
      raise ArgumentError, 'audience: is required' if audience.nil? || audience.to_s.empty?
      raise ArgumentError, 'resolve_grant: must respond to #call' unless resolve_grant.respond_to?(:call)
      unless intent_v2.nil? || intent_v2.is_a?(Hash) || intent_v2.respond_to?(:call)
        raise ArgumentError, 'intent_v2: must be a Hash or respond to #call'
      end

      @app = app
      @audience = audience
      @resolve_grant = resolve_grant
      @now = now
      @header = header
      @intent_policy = intent_policy
      @intent_v2 = intent_v2
    end

    def call(env)
      pcactn =
        begin
          extract(env)
        rescue DecodeError => e
          return unauthorized(e.message)
        end
      return unauthorized('no PCActn presented') if pcactn.nil?

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
                                                           intent_policy: @intent_policy, intent_v2: v2)
      return forbidden(verdict) unless verdict.allow

      env['pca'] = { 'verdict' => verdict, 'pcactn' => pcactn }
      @app.call(env)
    end

    private

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
      headers = {
        'WWW-Authenticate' => www_authenticate(error),
        'content-type' => 'application/json'
      }
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
