# frozen_string_literal: true

# Rack middleware for Proof-Carrying Authority, built ON TOP of the AtlasPca verifier.
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
  #                   be rooted at.
  #   now:            (optional) current time in epoch milliseconds, or a callable returning it.
  #                   Defaults to wall-clock. Used for the validity-window check.
  #   header:         (optional) the Rack env key carrying the base64url PCActn. Defaults to
  #                   'HTTP_PCA_ACTION' (the `PCA-Action` request header).
  class RackMiddleware
    REALM = 'pca'
    DEFAULT_HEADER = 'HTTP_PCA_ACTION'

    class DecodeError < StandardError; end

    def initialize(app, audience:, resolve_grant:, now: nil, header: DEFAULT_HEADER)
      raise ArgumentError, 'audience: is required' if audience.nil? || audience.to_s.empty?
      raise ArgumentError, 'resolve_grant: must respond to #call' unless resolve_grant.respond_to?(:call)

      @app = app
      @audience = audience
      @resolve_grant = resolve_grant
      @now = now
      @header = header
    end

    def call(env)
      pcactn =
        begin
          extract(env)
        rescue DecodeError => e
          return unauthorized(e.message)
        end
      return unauthorized('no PCActn presented') if pcactn.nil?

      grant = @resolve_grant.call(pcactn['grant_ref'])
      return unauthorized('unknown grant') if grant.nil?

      verdict = AtlasPca.verify_pcactn(pcactn, grant, now: current_now, audience: @audience)
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

    # Header path: base64url -> JSON text -> the SDK's strict JSON profile.
    def from_header(raw)
      bin = AtlasPca.b64d(raw)
      raise DecodeError, 'PCActn header is not canonical base64url' if bin.nil?

      strict_object(bin.dup.force_encoding('UTF-8'))
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
        'WWW-Authenticate' => www_authenticate(error, description),
        'content-type' => 'application/json'
      }
      [status, headers, [to_json(payload)]]
    end

    def www_authenticate(error, description)
      # Keep the challenge RFC 7235-clean: strip quotes/backslashes from the free-text bits.
      safe = description.to_s.tr('"\\', ' ')
      %(PCA realm="#{REALM}", error="#{error}", error_description="#{safe}")
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
