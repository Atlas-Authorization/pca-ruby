# frozen_string_literal: true

require_relative 'siem'

module AtlasPca
  # OpenTelemetry instrumentation for PCA: wrap a verification guard so every decision emits a span and two metrics, mirroring the
  # TypeScript reference (@atlasauth/pca-otel). Nothing from opentelemetry is required: pass any tracer-like object
  # (start_span(name) -> span with set_attribute / set_status / record_exception / end) and meter-like object
  # (create_counter(name).add(n, attrs), create_histogram(name).record(n, attrs)). set_status receives a plain
  # { 'code' => int, 'message' => str } Hash (UNSET 0, OK 1, ERROR 2). This observes, it never decides: a tracer, meter or
  # redactor that raises never changes what the guard returned.
  module Otel
    STATUS_OK = 1
    STATUS_ERROR = 2
    MAX_TEXT = 256

    WS = Siem::WS
    CI = Siem.method(:ci)
    # case folding is ASCII-only in a non-unicode JS regex: spell letters out rather than use the i flag
    REDACT = [
      [Regexp.new('(?a)\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*'), '[redacted]'],
      [Regexp.new("(?a)\\b(#{CI.call('authorization')}[\"']?[#{WS}]*[:=][#{WS}]*)[^\\n\"']*"), '\1[redacted]'],
      [Regexp.new("(?a)\\b(#{Siem.ci_alt('Bearer', 'Basic', 'Token')})[#{WS}]+[\\w.~+/=-]{6,}"), '\1 [redacted]'],
      [Regexp.new("(?a)([A-Za-z][A-Za-z0-9+.-]*://)[^#{WS}/@]*:[^#{WS}/@]*@"), '\1[redacted]@']
    ].freeze
    KV_NAMES = Siem.ci_alt('token', 'secret', 'password', 'passwd', 'pwd', 'key', 'signature', 'sig', 'credential', 'auth').sub(
      '(?:', "(?:#{CI.call('api')}[_-]?#{CI.call('key')}|"
    )
    KV = Regexp.new("(?a)\\b(#{KV_NAMES}[\"']?[#{WS}]*[:=][#{WS}]*)(\"[^\"]*\"|'[^']*'|[^#{WS}\"'&,;]+)")
    LONG = /[A-Za-z0-9_-]{32,}/

    module_function

    # Remove what looks like a credential from text bound for telemetry (JWTs, Bearer / Basic credentials, URL userinfo,
    # name=value pairs for secret-like names, 32+ character base64url / hex runs) and cut the result to 256 UTF-16 units.
    def redact_secrets(text)
      t = text.is_a?(String) ? text : Js.string(text)
      t = Siem::U16.safe(t) do |u|
        REDACT.each { |rx, rep| u = u.gsub(rx, rep) }
        u = u.gsub(KV) do
          m = Regexp.last_match
          q = %w[" '].include?(m[2][0]) ? m[2][0] : ''
          "#{m[1]}#{q}[redacted]#{q}"
        end
        u.gsub(LONG, '[redacted]')
      end
      Siem::U16.len(t) > MAX_TEXT ? "#{Siem::U16.slice(t, MAX_TEXT)}..." : t
    end

    def g(o, k) = o.is_a?(Hash) ? o[k] : nil
    def finite_num?(v) = v.is_a?(Integer) || (v.is_a?(Float) && v.finite?)

    # result?.verdict?.reasons?.[0], including JavaScript indexing into a string or an object keyed "0"
    def first_reason(result)
      rs = g(g(result, 'verdict'), 'reasons')
      return rs.first if rs.is_a?(Array)
      return(rs.empty? ? nil : Siem::U16.slice(rs, 1)) if rs.is_a?(String)

      g(rs, '0')
    end

    # Span attributes for a guard result; absent fields are omitted and pca.reason is added on deny only. Anything but an
    # explicit ok is reported as a deny.
    def pca_span_attributes(result, redact = nil)
      red = redact || method(:redact_secrets)
      ok = g(result, 'ok') == true
      attrs = { 'pca.decision' => ok ? 'allow' : 'deny' }
      status = g(result, 'status')
      attrs['pca.status'] = status if finite_num?(status)
      verdict = g(result, 'verdict')
      tier = g(g(verdict, 'requiredThreshold'), 't')
      attrs['pca.tier'] = tier if finite_num?(tier)
      risk = g(verdict, 'r')
      attrs['pca.risk'] = risk if finite_num?(risk)
      action = g(g(result, 'pcactn'), 'action')
      verb = g(action, 'verb')
      attrs['pca.verb'] = red.call(verb) if verb.is_a?(String)
      resource = g(action, 'resource')
      attrs['pca.resource'] = red.call(resource) if resource.is_a?(String)
      unless ok
        reason = first_reason(result)
        attrs['pca.reason'] = red.call(reason) if reason.is_a?(String)
      end
      attrs
    end

    # The scrubbed copy of a guard failure recorded on a span: fresh message, no backtrace, a sanitised class name.
    class TelemetryError < StandardError
      attr_reader :name

      def initialize(message, name = 'Error')
        super(message)
        @name = name
      end
    end

    def safe
      yield
    rescue StandardError # the decision is the guard's, not the exporter's
      nil
    end

    # Wrap a guard so each decision emits a span (default name pca.verify) and metrics (a pca.verifications counter and a
    # pca.verify.risk histogram, created once). The wrapper returns the guard's result unchanged and re-raises its exceptions
    # after recording a scrubbed copy on the span. With no tracer and no meter it is a transparent pass-through.
    def instrument_guard(guard, tracer: nil, meter: nil, span_name: nil, redact: nil)
      name = span_name.nil? ? 'pca.verify' : span_name
      counter = meter&.create_counter('pca.verifications')
      histogram = meter&.create_histogram('pca.verify.risk')
      red = redact || method(:redact_secrets)

      lambda do |*args, **kwargs|
        span = nil
        safe { span = tracer&.start_span(name) }
        begin
          result = guard.call(*args, **kwargs)
          if span
            safe do
              pca_span_attributes(result, red).each { |k, v| span.set_attribute(k, v) }
              reason = g(result, 'ok') == true ? nil : first_reason(result)
              if g(result, 'ok') == true then span.set_status({ 'code' => STATUS_OK })
              elsif reason.is_a?(String) then span.set_status({ 'code' => STATUS_ERROR, 'message' => red.call(reason) })
              else span.set_status({ 'code' => STATUS_ERROR })
              end
            end
          end
          decision = g(result, 'ok') == true ? 'allow' : 'deny'
          safe { counter.add(1, { 'decision' => decision }) } unless counter.nil?
          risk = g(g(result, 'verdict'), 'r')
          safe { histogram.record(risk, { 'decision' => decision }) } if !histogram.nil? && finite_num?(risk)
          result
        rescue StandardError => e
          if span
            safe do
              # a fresh error: the original may carry credentials in its message, cause or backtrace
              nm = e.class.name.to_s.split('::').last.to_s
              clean = TelemetryError.new(red.call(e.message), nm.match?(/\A[A-Za-z0-9_]{1,64}\z/) ? nm : 'Error')
              span.record_exception(clean)
              span.set_status({ 'code' => STATUS_ERROR, 'message' => clean.message })
            end
          end
          raise
        ensure
          safe { span.end } if span
        end
      end
    end
  end
end
