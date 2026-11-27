# frozen_string_literal: true

require 'json'
require_relative '../atlas_pca'
require_relative 'js_compat'
require_relative 'predicates'
require_relative 'siem'
require_relative 'taint'
require_relative 'connect'

module AtlasPca
  # Proof-Carrying Authority gateway: the decision logic of a deny-by-default enforcement point, as pure functions over request
  # Hashes. Mirrors the TypeScript reference (@atlasauth/pca-gateway).
  #
  # A request is {'method', 'path', 'query'?, 'authority'?, 'bodySha256'?, 'body'?, 'headers'}. The proof travels as the PCA-Action
  # header; the gateway's own audience and a route -> capability map are configured once. Every step denies by default. The Envoy
  # HTTP and gRPC ext_authz shapes and the AWS Lambda authorizers are plain functions over event Hashes; gateway_proxy joins a
  # gateway to an injected upstream callable. cloudflare_worker is the runtime-free core of the Worker adapter (the request, next and
  # respond are injected; no Workers runtime is involved).
  #
  # Nothing here authorizes on its own: it extracts the proof, verifies it with the fail-closed offline core, checks the capability
  # the route maps to, and maps that onto the gateway's contract. Hooks other than 'revocation' and the attestation enforcement gate
  # are not supported by this port's core verifier and are refused at construction.
  module Gateway
    PCA_HEADER = 'PCA-Action'
    PCA_INJECTED_HEADERS = %w[x-pca-verdict x-pca-verb x-pca-grant].freeze
    DEFAULT_REQUIRE_CHECKS = %w[revocation].freeze
    UNDEF = Predicates::UNDEF

    # what presented_provenance returns when the request presents none (JSON null is a presented, malformed bundle)
    ABSENT = Object.new.tap { |o| o.define_singleton_method(:inspect) { 'ABSENT' } }.freeze

    class HeaderError < StandardError; end

    # Gateway configuration (see the TypeScript reference for each member). routes: first matching rule wins, {'method'?, 'path',
    # 'capability' => {'verb', 'resource'?}}. resolve_grant: ->(grant_ref, pcactn) { grant | nil }. replay_guard: an object with
    # claim(key, expires_at_ms, now_ms) (see memory_replay_guard). bind_request: nil (bind method, path, query and, when supplied,
    # the body hash), false (off) or {'authority'?, 'body'?}. hooks: {'revocation' => ->(ctx) { {'enforced', 'ok'?, 'reason'?} }}
    # with ctx {'pcactn', 'grant', 'nowEpoch'}. enforce: {'freshness'?, 'taint'?} for the core verification. check_proof:
    # ->(ctx) { true | false | {'allow', 'reason'?} } with ctx {'pcactn', 'grant', 'verdict', 'request', 'required'?}. policy: REQUIRED,
    # {'mode' => 'signature-only'} or {'mode' => 'full', 'params' => 'body' | ->(req) { Hash }, 'state_store', 'is_revoked', ...}; the
    # other keys are keywords of AtlasPca.authorize, plus 'k1' and 'provenance_log' ('provenance_observed' joins the provenance gate's
    # observed callback).
    GatewayOptions = Struct.new(:audience, :routes, :resolve_grant, :authorized_plan_roots, :insecure_skip_plan_root_check, :unmatched_route,
                                :replay_guard, :bind_request, :hooks, :enforce, :require_checks, :check_proof, :path_policy, :now, :realm, :policy,
                                keyword_init: true) do
      def initialize(audience: '', routes: [], insecure_skip_plan_root_check: false, **rest)
        super(audience: audience, routes: routes, insecure_skip_plan_root_check: insecure_skip_plan_root_check, **rest)
      end

      # the provenance log a full-policy gateway keeps when the policy names none
      def default_log = (@default_log ||= MemoryProvenanceLog.new)
    end

    module_function

    # ---- JS helpers ---------------------------------------------------------------------------------------------------------
    def g(o, k) = o.is_a?(Hash) ? o[k] : nil
    def jt(v) = Js.truthy?(v)
    def u16key(s) = Siem::U16.units(s)

    # the first argument that is not nil
    def first(*vs) = vs.find { |v| !v.nil? }

    def js_s(v) = Predicates.js_string(v)

    def deep_dup(v)
      case v
      when Hash then v.to_h { |k, x| [k, deep_dup(x)] }
      when Array then v.map { |x| deep_dup(x) }
      else v
      end
    end

    # ---- canonical query / binding ------------------------------------------------------------------------------------------
    # JavaScript decodeURIComponent: a '%' without two hex digits, or bytes that are not UTF-8, raise ArgumentError. Characters
    # outside the percent runs pass through unchanged.
    def decode_uri_component(s)
      b = s.b
      raise ArgumentError, 'URI malformed' if b.match?(/%(?![0-9a-fA-F]{2})/n)

      out = b.gsub(/(?:%[0-9a-fA-F]{2})+/n) do |run|
        bytes = run.scan(/%([0-9a-fA-F]{2})/n).flatten.map { |h| h.to_i(16) }.pack('C*').force_encoding(Encoding::UTF_8)
        raise ArgumentError, 'URI malformed' unless bytes.valid_encoding?

        bytes.b
      end
      out.force_encoding(Encoding::UTF_8)
    end

    # Strip a leading '?', drop empty pairs, sort the raw pairs (UTF-16 code unit order) and join with '&'. Raises ArgumentError on a
    # query that is ambiguous across upstream parsers: a repeated parameter name (percent-decoded, '+' as space, case-insensitive),
    # a ';' separator, or a malformed percent escape in a name (the gateway turns it into a request-mismatch deny).
    def canonical_query(query)
      return '' if query.nil?

      q = query.start_with?('?') ? query[1..] : query
      raise ArgumentError, "query contains ';' (parsers disagree on it as a separator)" if q.b.include?(';')

      pairs = q.split('&', -1).reject(&:empty?)
      seen = {}
      pairs.each do |pair|
        eq = pair.b.index('=')
        raw_key = eq.nil? ? pair : pair.b[0, eq].force_encoding(Encoding::UTF_8)
        key = begin
          Siem::U16.from_pua(Siem::U16.to_pua(decode_uri_component(raw_key.b.gsub('+'.b, ' '.b))).downcase)
        rescue ArgumentError
          raise ArgumentError, 'query parameter name has a malformed percent escape'
        end
        raise ArgumentError, "duplicate query parameter '#{key}'" if seen.key?(key)

        seen[key] = true
      end
      pairs.sort_by { |x| u16key(x) }.join('&')
    end

    # The canonical binding of a request an agent signs as its action params: upper-cased method, path, canonical query and
    # optionally the authority and body hash.
    def request_binding(req, opts = nil)
      opts ||= {}
      sha = g(req, 'bodySha256')
      sha = g(req, 'body_sha256') if sha.nil?
      b = { 'v' => 2, 'method' => req.fetch('method').upcase, 'path' => req.fetch('path'), 'query' => canonical_query(g(req, 'query')) }
      b['authority'] = (jt(g(req, 'authority')) ? g(req, 'authority') : '').downcase if jt(opts['authority'])
      body = opts.key?('body') ? opts['body'] : UNDEF
      b['body_sha256'] = (sha.nil? ? '' : sha).downcase if body == true || (body.equal?(UNDEF) && !sha.nil?)
      b
    end

    # The params an agent signs for a full-policy gateway: the params plus the request binding as a 'binding' member.
    def bind_params(params, binding = nil)
      return params if binding.nil?
      raise ArgumentError, "params already have a 'binding' member" if params.key?('binding')

      params.merge('binding' => binding)
    end

    # Why path is ambiguous for route matching (the upstream may route a different path), or nil when canonical.
    def ambiguous_path_reason(path)
      pb = path.b
      return 'control character or backslash in path' if pb.match?(/[\x00-\x1f\x7f\\]/n)
      return 'repeated slash in path' if pb.include?('//')
      return 'path parameter (;) in path' if pb.include?(';')
      return 'dot segment in path' if pb.split('/', -1).any? { |seg| seg == '.' || seg == '..' }

      pb.scan(/%([0-9a-fA-F]{2})/n).flatten.each do |h|
        code = h.to_i(16)
        return 'percent-encoded control character in path' if code < 0x20 || code == 0x7F
        return 'percent-encoded slash in path' if [0x2F, 0x5C].include?(code)
        return 'percent-encoded path parameter delimiter in path' if code == 0x3B
        return 'non-canonical percent-encoding in path' if code.chr.match?(/\A[A-Za-z0-9\-._~]\z/n)
      end
      return 'malformed percent-encoding in path' if pb.match?(/%(?![0-9a-fA-F]{2})/n)

      nil
    end

    # ---- replay guard / provenance log --------------------------------------------------------------------------------------
    # In-process single-use store. State is per process: use a shared store for more than one instance. A claim stays live through
    # its expiry inclusive. Fails closed (raises) when max_entries unexpired claims are held.
    class MemoryReplayGuard
      def initialize(max_entries = 100_000, now = nil)
        @seen = {}
        @max = max_entries
        @now = now || -> { (Time.now.to_f * 1000).to_i }
      end

      def claim(key, expires_at_ms, now_ms = nil)
        t = now_ms.nil? ? @now.call : now_ms
        if @seen.length >= @max
          @seen.delete_if { |_k, exp| exp < t }
          raise 'replay guard full' if @seen.length >= @max
        end
        existing = @seen[key]
        return false if !existing.nil? && existing >= t

        @seen[key] = expires_at_ms
        true
      end
    end

    def memory_replay_guard(max_entries = 100_000, now = nil) = MemoryReplayGuard.new(max_entries, now)

    # JavaScript === over JSON values (objects by identity, no bool / number mixing)
    def same?(a, b)
      return a.equal?(b) if a.equal?(UNDEF) || b.equal?(UNDEF)
      return a.equal?(b) if a.is_a?(Hash) || a.is_a?(Array) || b.is_a?(Hash) || b.is_a?(Array)
      return a == b if [true, false].include?(a) || [true, false].include?(b)
      return a == b if Js.num?(a) && Js.num?(b)

      a.class == b.class && a == b
    end

    # The gateway's per-session record of untrusted content it relayed: at most max_sessions sessions (oldest dropped first), 256
    # observations each.
    class MemoryProvenanceLog
      def initialize(max_sessions = 10_000)
        @m = {}
        @max = max_sessions
      end

      def seen(session) = (@m[session] || []).map(&:dup)

      def add(session, o)
        cur = @m.delete(session) || []
        origin = o.key?('origin') ? o['origin'] : UNDEF
        source = o.key?('source') ? o['source'] : UNDEF
        dup = cur.any? { |x| Gateway.same?(x.fetch('origin', UNDEF), origin) && Gateway.same?(x.fetch('source', UNDEF), source) }
        if !dup && cur.length < 256
          entry = {}
          entry['origin'] = origin unless origin.equal?(UNDEF)
          entry['source'] = source unless source.equal?(UNDEF)
          cur << entry
        end
        @m[session] = cur
        @m.delete(@m.keys.first) while @m.length > @max
      end
    end

    def memory_provenance_log(max_sessions = 10_000) = MemoryProvenanceLog.new(max_sessions)

    # ---- headers / extraction -----------------------------------------------------------------------------------------------
    # Case-insensitive single-value lookup over a header map: the first key that matches; an Array reads as its first element.
    def get_header(headers, name)
      return nil unless headers.is_a?(Hash)

      lower = name.downcase
      headers.each do |key, v|
        next unless key.is_a?(String) && Siem::U16.to_pua(key).downcase == lower

        return v.is_a?(Array) ? v.first : v
      end
      nil
    end

    # PCA-Action header value -> the PCActn JSON text. STRICT: non-empty, unpadded RFC 4648 s5 alphabet only, no whitespace
    # anywhere, length mod 4 != 1, zero unused trailing bits, then strict UTF-8.
    def decode_header(value)
      raise HeaderError, 'PCA-Action header is empty' unless value.is_a?(String) && !value.empty?

      raw = AtlasPca.b64d(value)
      raise HeaderError, 'PCA-Action header is not strict unpadded base64url' if raw.nil?

      text = raw.dup.force_encoding(Encoding::UTF_8)
      raise HeaderError, 'PCA-Action header does not decode to UTF-8 text' unless text.valid_encoding?

      text
    end

    def decode_pcactn(text)
      raise ArgumentError, AtlasPca::ARTIFACT_SIZE_REASON if text.bytesize > AtlasPca::MAX_ARTIFACT_BYTES # FIRST: before any parsing

      v = AtlasPca.parse_json(text, any_top: true)
      raise TypeError, 'decodePCActn: not an object' unless v.is_a?(Hash)

      v
    end

    def extract_pcactn(headers)
      raw = get_header(headers, PCA_HEADER)
      return { 'code' => 'no-proof', 'reason' => "no #{PCA_HEADER} header" } if raw.nil? || raw == ''

      begin
        { 'pcactn' => decode_pcactn(decode_header(raw)) }
      rescue StandardError => e # undecodable is a deny
        { 'code' => 'invalid-proof', 'reason' => "undecodable #{PCA_HEADER} header: #{e.message}" }
      end
    end

    def body_object(req)
      body = g(req, 'body')
      return nil unless body.is_a?(String) && !body.empty?

      b = begin
        AtlasPca.parse_json(body, any_top: true)
      rescue StandardError # not JSON: no body form
        return nil
      end
      b.is_a?(Hash) ? b : nil
    end

    def params_is_fn?(policy) = g(policy, 'params').respond_to?(:call)

    # The provenance bundle a request presents: header PCA-Provenance (strict base64url JSON), else body member 'pca_provenance'
    # when the body is not the signed params. ABSENT when none; nil when presented but unreadable.
    def presented_provenance(req, policy)
      begin
        h = get_header(g(req, 'headers'), 'pca-provenance')
        return AtlasPca.parse_json(decode_header(h), any_top: true) if !h.nil? && h != ''
      rescue StandardError # presented but malformed: the gate denies it
        return nil
      end
      if params_is_fn?(policy)
        b = body_object(req)
        return b['pca_provenance'] if !b.nil? && b.key?('pca_provenance')
      end
      ABSENT
    end

    # The discharges and narrow block a request presents (headers, then body members when the body is not the signed params).
    def presented_artifacts(req, policy)
      out = {}
      headers = g(req, 'headers')
      begin
        d = get_header(headers, 'pca-discharges')
        if !d.nil? && d != ''
          arr = AtlasPca.parse_json(decode_header(d), any_top: true)
          out['discharges'] = arr if arr.is_a?(Array)
        end
      rescue StandardError # unreadable: no discharges
        nil
      end
      begin
        n = get_header(headers, 'pca-narrow')
        out['narrow'] = AtlasPca.parse_json(decode_header(n), any_top: true) if !n.nil? && n != ''
      rescue StandardError # unreadable: no narrow block
        nil
      end
      if params_is_fn?(policy)
        b = body_object(req)
        unless b.nil?
          out['discharges'] = b['pca_discharges'] if !out.key?('discharges') && b['pca_discharges'].is_a?(Array)
          out['narrow'] = b['pca_narrow'] if !out.key?('narrow') && b.key?('pca_narrow')
        end
      end
      out
    end

    # ---- routes / decisions -------------------------------------------------------------------------------------------------
    def match_method?(rule, method)
      m = rule['method']
      m.nil? || m == '*' || m.upcase == 'ANY' || m.upcase == method.upcase
    end

    def match_path?(pattern, path)
      return true if ['*', '/*'].include?(pattern)

      if pattern.end_with?('/*')
        prefix = pattern[0...-2]
        path == prefix || path.start_with?("#{prefix}/")
      elsif pattern.end_with?('*')
        path.start_with?(pattern[0...-1])
      else
        path == pattern
      end
    end

    def match_route(routes, method, path) = routes.find { |r| match_method?(r, method) && match_path?(r.fetch('path'), path) }

    ERROR_TOKEN = {
      'no-proof' => 'missing_proof', 'invalid-proof' => 'invalid_proof', 'unknown-grant' => 'invalid_proof',
      'verify-failed' => 'invalid_proof', 'wrong-audience' => 'invalid_resource', 'insufficient-capability' => 'insufficient_capability',
      'unmapped-route' => 'access_denied', 'invalid-path' => 'invalid_request', 'replayed-proof' => 'replayed_proof',
      'replay-guard-unavailable' => 'temporarily_unavailable', 'request-mismatch' => 'proof_not_bound_to_request',
      'proof-rejected' => 'access_denied'
    }.freeze

    def deny(code, status, reason, realm, **extra)
      { 'allow' => false, 'status' => status, 'code' => code, 'reason' => reason,
        'headers' => { 'www-authenticate' => "PCA realm=\"#{realm}\", error=\"#{ERROR_TOKEN.fetch(code)}\"" } }
        .merge(extra.reject { |_k, v| v.nil? }.transform_keys(&:to_s))
    end

    def allow(reason, **extra)
      extra = extra.reject { |_k, v| v.nil? }.transform_keys(&:to_s)
      headers = {}
      headers['x-pca-verdict'] = Js.json(extra['verdict']) if jt(extra['verdict'])
      if jt(extra['pcactn'])
        headers['x-pca-verb'] = extra['pcactn']['action']['verb']
        headers['x-pca-grant'] = extra['pcactn']['grant_ref']
      end
      { 'allow' => true, 'status' => 200, 'code' => 'allow', 'reason' => reason, 'headers' => headers }.merge(extra)
    end

    def policy_mode(opts) = g(opts.policy, 'mode')

    def missing_text(opts, missing)
      mode = policy_mode(opts)
      "#{mode.nil? || mode == 'signature-only' ? 'the gateway' : 'full policy mode'} is missing #{missing.join(', ')}"
    end

    def missing_policy(opts)
      p = opts.policy
      return ["policy ({ mode: 'full', params, state, isRevoked } or an explicit { mode: 'signature-only' })"] if p.nil?

      mode = g(p, 'mode')
      if mode == 'signature-only'
        m = []
        m << 'replayGuard (signature-only mode needs a single-use guard)' if opts.replay_guard.nil?
        rc = opts.require_checks.nil? ? DEFAULT_REQUIRE_CHECKS : opts.require_checks
        if rc.include?('revocation') && !g(opts.hooks, 'revocation').respond_to?(:call)
          m << "hooks.revocation (required by the default requireChecks ['revocation']; pass requireChecks: [] to waive)"
        end
        return m
      end
      return ["a known policy mode (got '#{js_s(mode)}')"] if mode != 'full'

      missing = []
      missing << 'audience' if !opts.audience.is_a?(String) || opts.audience.empty?
      missing << 'resolveGrant' unless opts.resolve_grant.respond_to?(:call)
      store = p['state_store']
      missing << 'state' if store.nil? || !store.respond_to?(:claim)
      missing << 'isRevoked' unless p['is_revoked'].respond_to?(:call)
      if !store.nil? && store.respond_to?(:claim) && !(store.respond_to?(:budget) && store.respond_to?(:budget_cas))
        missing << 'state.claim_budget (the trust budget is decided and debited with the replay claim)'
      end
      missing << "params ('body' or a function)" if p['params'] != 'body' && !p['params'].respond_to?(:call)
      missing
    end

    # Full-policy mode: the params the agent must have signed for this request ({'params'} or {'error'}).
    def signed_params(req, policy, bind)
      if policy['params'] == 'body'
        body = g(req, 'body')
        return { 'error' => 'full policy mode reads the params from the body, and the request carries none' } unless body.is_a?(String)

        params = begin
          AtlasPca.parse_json(body, any_top: true)
        rescue StandardError => e
          return { 'error' => "the body is not strict JSON: #{e.message}" }
        end
      else
        params = policy['params'].call(req)
      end
      return { 'error' => 'the request params are not a JSON object' } unless params.is_a?(Hash)
      return { 'params' => params } if bind.equal?(false)

      b = bind || {}
      return { 'error' => "the request params carry a 'binding' member (reserved for the request binding)" } if params.key?('binding')
      if (jt(b['authority']) && !jt(g(req, 'authority'))) || (b['body'] == true && !jt(g(req, 'bodySha256')))
        return { 'error' => 'request lacks an attribute the proof must bind (authority / body hash)' }
      end

      begin
        # the params carry the body, so its hash is bound only when asked for explicitly (bind_request body: true)
        o = {}
        o['authority'] = true if jt(b['authority'])
        o['body'] = b['body'] == true
        { 'params' => params.merge('binding' => request_binding(req, o)) }
      rescue StandardError => e
        { 'error' => "the request cannot be bound: #{e.message}" }
      end
    end

    # ---- core verification --------------------------------------------------------------------------------------------------
    # enforce.freshness / enforce.taint: the two extra core gates, in the core verifier's check names. -> [[name, ok, reason]]
    def enforce_gates(pcactn, enf, now)
      out = []
      if enf.key?('taint')
        t = enf['taint']
        tg = begin
          Taint.taint_gate(pcactn['provenance'], g(t, 'registry'), g(t, 'resource_graph'), g(t, 'max_taint'))
        rescue StandardError => e
          { 'ok' => false, 'reason' => "taint gate error (fail closed): #{e.message}" }
        end
        out << ['taint_gate', tg['ok'] ? true : false, tg['reason']]
      end
      if enf.key?('freshness')
        f = enf['freshness']
        epoch_ms = g(f, 'epoch_ms').nil? ? 60_000 : g(f, 'epoch_ms')
        fnow = g(f, 'now').nil? ? now : g(f, 'now')
        skew = Connect.finite?(g(f, 'clock_skew_ms')) ? [0, g(f, 'clock_skew_ms')].max : 0
        fr = pcactn['freshness']
        fr = {} unless fr.is_a?(Hash)
        max_age = g(f, 'max_age_ms')
        if !(Connect.finite?(epoch_ms) && epoch_ms > 0) || !Connect.finite?(max_age) || max_age < 0 || !Connect.finite?(fnow)
          out << ['freshness_anchor', false, 'freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)']
        elsif !fr['beacon_ref'].is_a?(String) || fr['beacon_ref'].empty? || !fr['epoch'].is_a?(Integer) || fr['epoch'] <= 0 || fr['epoch'] > MAX_SAFE
          out << ['freshness_anchor', false, 'freshness anchor is missing (empty beacon_ref or non-positive epoch stub)']
        else
          anchor = fr['epoch'] * epoch_ms
          if anchor > fnow + skew then out << ['freshness_anchor', false, 'freshness anchor is in the future']
          elsif fnow - anchor > max_age then out << ['freshness_anchor', false, "freshness anchor is stale (older than #{Predicates.js_number_string(max_age)} ms)"]
          else out << ['freshness_anchor', true, nil]
          end
        end
      end
      out
    end

    # The core verdict's checks in the reference vocabulary: pass / fail / not-enforced.
    def statuses(checks, plan_root_skipped, revocation)
      st = {}
      checks.each { |k, ok| st[k == 'chain' ? 'cap_chain' : k] = ok ? 'pass' : 'fail' }
      st['plan_root_authorized'] = 'not-enforced' if plan_root_skipped
      st['attestation'] = 'not-enforced'
      st['threshold'] = 'not-enforced'
      st['revocation'] = revocation
      st['taint_gate'] = 'not-enforced' unless st.key?('taint_gate')
      st
    end

    def verify(pcactn, grant, opts, now)
      v = AtlasPca.verify_pcactn(pcactn, grant, now: now, audience: opts.audience, authorized_plan_roots: opts.authorized_plan_roots&.dup,
                                                insecure_skip_plan_root_check: opts.insecure_skip_plan_root_check == true)
      checks = v.checks.dup
      allow = v.allow ? true : false
      reason = v.reason.nil? || v.reason.empty? ? nil : v.reason
      if checks['wire']
        enforce_gates(pcactn, opts.enforce || {}, now).each do |name, ok, why|
          checks[name] = ok
          next if ok

          allow = false
          reason ||= "#{name}: #{why}"
        end
      end
      revocation = 'not-enforced'
      hook = g(opts.hooks, 'revocation')
      if !hook.nil? && v.checks['wire']
        begin
          res = hook.call({ 'pcactn' => pcactn, 'grant' => grant, 'nowEpoch' => now })
          enforced = jt(g(res, 'enforced'))
          ok = jt(g(res, 'ok'))
          if !enforced
            revocation = 'not-enforced'
          elsif ok
            revocation = 'pass'
          else
            revocation = 'fail'
            if allow || reason.nil?
              rr = g(res, 'reason')
              reason = "revocation: #{rr.nil? ? 'rejected' : js_s(rr)}"
            end
            allow = false
          end
        rescue StandardError => e # a hook that raises refuses the proof
          revocation = 'fail'
          reason = "malformed PCActn: #{e.message}" if allow || reason.nil?
          allow = false
        end
      end
      skipped = opts.authorized_plan_roots.nil? && opts.insecure_skip_plan_root_check == true && !checks.key?('plan_root_authorized')
      verdict = { 'allow' => allow, 'checks' => statuses(checks, skipped, revocation) }
      verdict['reason'] = reason unless reason.nil?
      [verdict, checks['wire'] ? true : false, checks['audience'] ? true : false]
    end

    # The framework-agnostic core: extract the PCActn, map the request to the capability its route requires, verify (fail closed),
    # enforce audience, capability, request binding, required checks, the proof hook, the policy and single use. Returns a Decision
    # Hash {'allow', 'status', 'code', 'reason', 'headers', 'verdict'?, 'pcactn'?, 'matched'?, 'policyVerdict'?}.
    def authorize(req, opts)
      realm = opts.realm.nil? ? opts.audience : opts.realm
      unmatched = jt(opts.unmatched_route) ? opts.unmatched_route : 'deny'
      path = req.fetch('path')
      method = req.fetch('method')

      # 0. an ambiguous request target is never matched against the route map
      if (jt(opts.path_policy) ? opts.path_policy : 'strict') == 'strict'
        bad = ambiguous_path_reason(path)
        return deny('invalid-path', 400, bad, realm) unless bad.nil?
      end

      # 1. route -> required capability; an unmapped route follows unmatched_route (default deny)
      rule = match_route(opts.routes, method, path)
      if rule.nil?
        return allow("route #{method} #{path} is unmapped (unmatchedRoute=allow)") if unmatched == 'allow'
        return deny('unmapped-route', 403, "no capability mapping for #{method} #{path} (deny-by-default)", realm) if unmatched == 'deny'
      end
      required = rule.nil? ? nil : rule['capability']

      # 2. the proof (fail closed)
      extracted = extract_pcactn(g(req, 'headers'))
      return deny(extracted['code'], 401, extracted['reason'], realm) unless extracted.key?('pcactn')

      pcactn = extracted['pcactn']

      # 3. the grant the chain must root in
      grant_ref = pcactn['grant_ref']
      grant = opts.resolve_grant.call(grant_ref, pcactn)
      unless jt(grant)
        return deny('unknown-grant', 401, "unknown grant_ref #{pcactn.key?('grant_ref') ? js_s(grant_ref) : 'undefined'}", realm, pcactn: pcactn)
      end

      # 3b. a configuration with a missing component denies every request (fail closed)
      missing_cfg = missing_policy(opts)
      return deny('proof-rejected', 403, "#{missing_text(opts, missing_cfg)} (fail closed)", realm, pcactn: pcactn) unless missing_cfg.empty?

      # 4. offline verification, the audience bound to THIS gateway
      now = opts.now.nil? ? (Time.now.to_f * 1000).to_i : opts.now.call
      verdict, wire_ok, aud_ok = verify(pcactn, grant, opts, now)
      unless verdict['allow']
        audience_failed = wire_ok && !aud_ok
        return deny(audience_failed ? 'wrong-audience' : 'verify-failed', audience_failed ? 403 : 401,
                    jt(verdict['reason']) ? verdict['reason'] : 'PCActn verification failed', realm, verdict: verdict, pcactn: pcactn)
      end

      # 5. capability enforcement: the verified proof carries the verb (+ resource) the route requires
      action = pcactn['action']
      unless required.nil?
        if action['verb'] != required['verb']
          return deny('insufficient-capability', 403, "route requires capability '#{required['verb']}' but the proof authorizes '#{js_s(action['verb'])}'",
                      realm, verdict: verdict, pcactn: pcactn, matched: required)
        end
        if !required['resource'].nil? && action['resource'] != required['resource']
          return deny('insufficient-capability', 403, "route is bound to resource '#{required['resource']}' but the proof targets '#{js_s(action['resource'])}'",
                      realm, verdict: verdict, pcactn: pcactn, matched: required)
        end
      end

      policy = policy_mode(opts) == 'full' ? opts.policy : nil
      bind = opts.bind_request
      full_params = nil
      if !policy.nil?
        # 5b (full). the agent signed the real params plus the request binding: rebuild them from THIS request
        sp = signed_params(req, policy, bind.nil? ? {} : bind)
        return deny('request-mismatch', 403, sp['error'], realm, verdict: verdict, pcactn: pcactn) if sp.key?('error')

        if action['params_digest'] != AtlasPca.params_digest(sp['params'])
          return deny('request-mismatch', 403, 'the proof is not bound to this request (params/method/path/query/authority)', realm, verdict: verdict, pcactn: pcactn)
        end

        full_params = sp['params']
      elsif !bind.equal?(false)
        # 5b. request binding: the signed params digest must be the digest of THIS request
        b = bind || {}
        if (jt(b['authority']) && !jt(g(req, 'authority'))) || (b['body'] == true && !jt(g(req, 'bodySha256')))
          return deny('request-mismatch', 403, 'request lacks an attribute the proof must bind (authority / body hash)', realm, verdict: verdict, pcactn: pcactn)
        end

        bound = begin
          AtlasPca.params_digest(request_binding(req, b))
        rescue StandardError => e
          return deny('request-mismatch', 403, "the request cannot be bound: #{e.message}", realm, verdict: verdict, pcactn: pcactn)
        end
        if action['params_digest'] != bound
          return deny('request-mismatch', 403, 'the proof is not bound to this request (method/path/query/authority/body)', realm, verdict: verdict, pcactn: pcactn)
        end
      end

      # 5c. required checks must have PASSED (not merely "not-enforced"); full mode takes revocation from is_revoked
      (opts.require_checks.nil? ? (policy.nil? ? DEFAULT_REQUIRE_CHECKS : []) : opts.require_checks).each do |c|
        next if verdict['checks'][c] == 'pass'

        return deny('proof-rejected', 403, "required check '#{c}' is #{verdict['checks'].fetch(c, 'absent')}", realm, verdict: verdict, pcactn: pcactn)
      end

      # 5d. per-proof policy hook (limits, budgets, revocation lists); a raise denies
      unless opts.check_proof.nil?
        begin
          ctx = { 'pcactn' => pcactn, 'grant' => grant, 'verdict' => verdict, 'request' => req }
          ctx['required'] = required unless required.nil?
          r = opts.check_proof.call(ctx)
          ok = [true, false].include?(r) ? r : jt(g(r, 'allow'))
          unless ok
            why = r.is_a?(Hash) && jt(g(r, 'reason')) ? g(r, 'reason') : 'rejected by checkProof'
            return deny('proof-rejected', 403, why, realm, verdict: verdict, pcactn: pcactn)
          end
        rescue StandardError => e
          return deny('proof-rejected', 403, "checkProof failed: #{e.message}", realm, verdict: verdict, pcactn: pcactn)
        end
      end

      # 5e. full-policy mode: the grant's limits and caveats, revocation, the replay counter and the trust budget
      policy_verdict = nil
      if !policy.nil? && !full_params.nil?
        full = full_policy(req, opts, policy, pcactn, grant, required, full_params, verdict, realm, now)
        return full['decision'] if full.key?('decision')

        policy_verdict = full['policy_verdict']
      end

      # 6. single use, only for a proof that would otherwise be allowed (a denied attempt never burns it)
      unless opts.replay_guard.nil?
        first_use = begin
          opts.replay_guard.claim("#{pcactn['grant_ref']}:#{pcactn['sig']}", pcactn['exp'], now)
        rescue StandardError => e
          return deny('replay-guard-unavailable', 503, "replay guard unavailable: #{e.message}", realm, verdict: verdict, pcactn: pcactn)
        end
        return deny('replayed-proof', 403, 'this proof has already been used', realm, verdict: verdict, pcactn: pcactn) unless first_use
      end

      allow(jt(policy_verdict) ? 'proof-carrying action authorized (full policy)' : 'proof-carrying action verified',
            verdict: verdict, pcactn: pcactn, matched: required, policyVerdict: policy_verdict)
    end

    # Full-policy mode: delegate to the core authorize pipeline with the gateway's own audience, grant and clock.
    def full_policy(req, opts, policy, pcactn, grant, required, full_params, verdict, realm, now)
      k1 = nil
      k1_opt = policy['k1']
      unless k1_opt.nil?
        begin
          own = k1_opt.respond_to?(:call) ? k1_opt.call(req, pcactn) : k1_opt
          k1 = presented_artifacts(req, policy).merge(own)
        rescue StandardError => e
          return { 'decision' => deny('proof-rejected', 403, "k1 input failed: #{e.message} (fail closed)", realm, verdict: verdict, pcactn: pcactn) }
        end
      end
      bundle = presented_provenance(req, policy)
      log_opt = policy.fetch('provenance_log', UNDEF)
      log = if log_opt.equal?(false) then nil
            elsif log_opt.equal?(UNDEF) || log_opt.nil? then opts.default_log
            else log_opt
            end
      chain = pcactn['cap_chain']
      leaf = chain.is_a?(Array) && !chain.empty? && chain[-1].is_a?(Hash) ? chain[-1].fetch('holder', UNDEF) : UNDEF
      receipts = bundle.equal?(ABSENT) ? nil : g(bundle, 'receipts')
      session = receipts.is_a?(Array) && !receipts.empty? ? g(receipts[0], 'session') : nil
      log_key = "#{js_s(pcactn['grant_ref'])}\n#{leaf.equal?(UNDEF) ? 'undefined' : js_s(leaf)}\n#{session.is_a?(String) ? session : '-'}"
      begin
        fields = policy.reject { |k, _| %w[mode params k1 provenance_log provenance_observed].include?(k) }.transform_keys(&:to_sym)
        user_observed = policy['provenance_observed']
        if !user_observed.nil? || !log.nil?
          observed = lambda do |p, op, sess|
            [*(user_observed.nil? ? [] : user_observed.call(p, op, sess)), *(log.nil? ? [] : log.seen(log_key))]
          end
          prov = (fields[:provenance] || {}).transform_keys(&:to_s)
          fields[:provenance] = prov.merge('observed' => observed)
        end
        action = pcactn['action']
        operation = { 'verb' => required ? required['verb'] : action['verb'],
                      'resource' => required && !required['resource'].nil? ? required['resource'] : action['resource'], 'params' => full_params }
        d = AtlasPca.authorize(pcactn, operation: operation, audience: opts.audience, resolve_grant: ->(*_a) { grant }, now: now, k1: k1,
                                       provenance_bundle: bundle.equal?(ABSENT) ? nil : bundle, **fields)
      rescue StandardError => e
        return { 'decision' => deny('proof-rejected', 403, "full policy failed: #{e.message} (fail closed)", realm, verdict: verdict, pcactn: pcactn) }
      end
      # what this call returns flows back into the agent's context: the session has now seen untrusted content
      log.add(log_key, { 'origin' => 'tool', 'source' => action['verb'] }) if d.allow && log
      unless d.allow
        checks = d.checks || {}
        code = if checks['replay'] == 'fail' then 'replayed-proof'
               elsif checks['operation'] == 'fail' then 'insufficient-capability'
               elsif d.status == 401 then 'verify-failed'
               else 'proof-rejected'
               end
        pv = { 'allow' => false, 'checks' => checks, 'reason' => d.reason }
        return { 'decision' => deny(code, d.status, jt(d.reason) ? d.reason : 'rejected', realm, verdict: verdict, pcactn: pcactn, policyVerdict: pv) }
      end
      { 'policy_verdict' => { 'allow' => true, 'checks' => d.checks || {} } }
    end

    # A reusable authorizer bound to one frozen configuration. Raises TypeError when a component is missing, and ArgumentError for a
    # hook or gate this port cannot run (it would otherwise be silently ignored).
    def create_gateway(opts)
      missing = missing_policy(opts)
      raise TypeError, "pca-gateway: #{missing_text(opts, missing)}" unless missing.empty?

      extra_hooks = (opts.hooks.is_a?(Hash) ? opts.hooks.keys : []).reject { |k| k == 'revocation' }
      if !extra_hooks.empty? || (opts.enforce.is_a?(Hash) && opts.enforce.key?('attestation'))
        raise ArgumentError, "pca-gateway: hooks #{(extra_hooks.empty? ? ['attestation'] : extra_hooks).join(', ')} / the attestation gate are not supported by this port's core verifier"
      end

      frozen = opts.dup
      frozen.routes = deep_dup(opts.routes)
      frozen.authorized_plan_roots = opts.authorized_plan_roots.dup unless opts.authorized_plan_roots.nil?
      ->(req) { authorize(req, frozen) }
    end

    # Join a gateway to an injected upstream callable: on allow, upstream.call(request, decision) is called with every
    # client-supplied x-pca-* header removed and the decision's headers set; on deny the 401 / 403 response Hash is returned and the
    # upstream is never called.
    def gateway_proxy(opts, upstream)
      gw = create_gateway(opts)
      lambda do |req|
        d = gw.call(req)
        if d['allow']
          hdrs = (g(req, 'headers') || {}).reject { |k, _| k.is_a?(String) && PCA_INJECTED_HEADERS.include?(Siem::U16.to_pua(k).downcase) }
          hdrs.update(d['headers'])
          upstream.call(req.merge('headers' => hdrs), d)
        else
          deny_response(d)
        end
      end
    end

    def deny_response(d)
      { 'status' => d['status'], 'headers' => { 'content-type' => 'application/json' }.merge(d['headers']),
        'body' => Js.json({ 'error' => d['code'], 'reason' => d['reason'] }) }
    end

    # ---- Cloudflare Worker (fetch-style middleware) --------------------------------------------------------------------------
    # The path, authority and query of a request URL string, without a URL parser.
    def worker_path(url)
      rest = url
      authority = ''
      scheme = rest.index('://')
      unless scheme.nil?
        rest = rest[(scheme + 3)..]
        slash = rest.index('/')
        if slash.nil?
          authority = rest
          rest = '/'
        else
          authority = rest[0, slash]
          rest = rest[slash..]
        end
      end
      mark = rest.index(/[?#]/)
      path = mark.nil? ? rest : rest[0, mark]
      { 'path' => path.empty? ? '/' : path, 'authority' => authority, 'query' => query_of_target(rest) }
    end

    # Lower-case names of the inbound x-pca-* headers a client sent.
    def worker_inbound_pca_headers(request)
      found = []
      hdrs = g(request, 'headers')
      (hdrs.is_a?(Hash) ? hdrs.keys : []).each do |k|
        n = k.is_a?(String) ? Siem::U16.to_pua(k).downcase : nil
        found << n if n&.start_with?('x-pca-') && !found.include?(n)
      end
      found.sort_by!(&:b) # a Fetch Headers iterates in sorted order
      PCA_INJECTED_HEADERS.each { |n| found << n if !get_header(hdrs, n).nil? && !found.include?(n) }
      found
    end

    # The request without the named (lower-case) headers.
    def worker_default_rewrite(request, drop)
      kept = (g(request, 'headers') || {}).reject { |k, _| k.is_a?(String) && drop.include?(Siem::U16.to_pua(k).downcase) }
      request.merge('headers' => kept)
    end

    # Cloudflare Worker middleware core: a callable over a request Hash {'method', 'url', 'headers', 'body'?} that verifies the inbound
    # PCActn. On allow it calls nxt.call(request) with every inbound x-pca-* header removed (rewrite_request: :default drops them from
    # the Hash; a callable ->(request, names) { request } replaces that; nil opts out, and a request carrying one is then refused 400);
    # on deny it returns respond.call(json_body, {'status', 'headers'}) with the WWW-Authenticate challenge and a JSON error body, and
    # the upstream is never reached. A full-policy gateway with params 'body' reads request['body'].
    def cloudflare_worker(opts, nxt:, respond:, rewrite_request: :default)
      gw = create_gateway(opts)
      lambda do |request|
        loc = worker_path(g(request, 'url'))
        headers = {}
        hdrs = g(request, 'headers')
        pca = get_header(hdrs, PCA_HEADER)
        headers[PCA_HEADER.downcase] = pca unless pca.nil?
        %w[pca-discharges pca-narrow].each do |h|
          v = get_header(hdrs, h)
          headers[h] = v unless v.nil?
        end
        req = { 'method' => g(request, 'method'), 'path' => loc['path'], 'query' => loc['query'], 'authority' => loc['authority'], 'headers' => headers }
        req['body'] = request['body'] if policy_mode(opts) == 'full' && g(opts.policy, 'params') == 'body' && request.key?('body')
        d = gw.call(req)
        if d['allow']
          forged = worker_inbound_pca_headers(request)
          return nxt.call(request) if forged.empty?

          clean = rewrite_request == :default ? worker_default_rewrite(request, forged) : rewrite_request&.call(request, forged)
          return nxt.call(clean) unless clean.nil?

          return respond.call(Js.json({ 'error' => 'forged-pca-header', 'reason' => 'inbound x-pca-* header cannot be removed' }),
                              { 'status' => 400, 'headers' => { 'content-type' => 'application/json' } })
        end
        respond.call(Js.json({ 'error' => d['code'], 'reason' => d['reason'] }),
                     { 'status' => d['status'], 'headers' => { 'content-type' => 'application/json' }.merge(d['headers']) })
      end
    end

    # ---- Envoy HTTP ext_authz -----------------------------------------------------------------------------------------------
    def query_of_target(target)
      t = target.b
      q = t.index('?')
      return '' if q.nil?

      rest = t[(q + 1)..]
      h = rest.index('#')
      (h.nil? ? rest : rest[0, h]).force_encoding(Encoding::UTF_8)
    end

    def envoy_request(check)
      headers = first(g(check, 'headers'), {})
      method = first(g(check, 'method'), g(headers, ':method'), '*')
      target = first(g(check, 'path'), g(headers, ':path'), '/')
      raise TypeError, 'path is not a string' unless target.is_a?(String)

      m = target.b.index(/[?#]/n)
      raw_path = (m.nil? ? target.b : target.b[0, m]).force_encoding(Encoding::UTF_8)
      path = raw_path.empty? ? '/' : raw_path
      authority = first(g(check, 'authority'), g(headers, ':authority'))
      req = { 'method' => method, 'path' => path, 'query' => query_of_target(target), 'headers' => headers }
      req['authority'] = authority unless authority.nil?
      req['body'] = check['body'] unless g(check, 'body').nil?
      req
    end

    # Envoy HTTP ext_authz handler: 200 plus the verified verdict headers on allow (every injected header is overwritten, the unset
    # ones blank), the guard's 401 / 403 with a WWW-Authenticate challenge and a JSON body on deny.
    def envoy_ext_authz(opts)
      gw = create_gateway(opts)
      lambda do |c|
        d = gw.call(envoy_request(c))
        next deny_response(d) unless d['allow']

        { 'status' => 200, 'headers' => PCA_INJECTED_HEADERS.to_h { |h| [h, ''] }.merge(d['headers']), 'body' => '' }
      end
    end

    # ---- Envoy gRPC ext_authz -----------------------------------------------------------------------------------------------
    GRPC_OK = 0
    GRPC_UNAUTHENTICATED = 16
    GRPC_PERMISSION_DENIED = 7
    GRPC_UNAVAILABLE = 14
    OVERWRITE_IF_EXISTS_OR_ADD = 2

    def header_options(h) = h.map { |k, v| { 'header' => { 'key' => k, 'value' => v }, 'appendAction' => OVERWRITE_IF_EXISTS_OR_ADD } }

    # Envoy gRPC ext_authz Check handler over a decoded CheckRequest Hash (camelCase). On allow it also lists every x-pca-* header it
    # did not set in headersToRemove, so a client cannot smuggle a forged verdict through an unmapped-route allow.
    def envoy_grpc_ext_authz(opts)
      gw = create_gateway(opts)
      lambda do |c|
        http = g(g(g(c, 'attributes'), 'request'), 'http')
        unless jt(http)
          next({ 'status' => { 'code' => GRPC_PERMISSION_DENIED, 'message' => 'no http request attributes' },
                 'deniedResponse' => { 'status' => { 'code' => 403 }, 'headers' => [],
                                       'body' => Js.json({ 'error' => 'invalid-request', 'reason' => 'CheckRequest carried no HTTP attributes' }) } })
        end

        headers = first(g(http, 'headers'), {})
        req = { 'headers' => headers }
        method = first(g(http, 'method'), g(headers, ':method'))
        req['method'] = method unless method.nil?
        path = first(g(http, 'path'), g(headers, ':path'))
        req['path'] = path unless path.nil?
        authority = first(g(http, 'host'), g(headers, ':authority'))
        req['authority'] = authority unless authority.nil?
        req['body'] = http['body'] unless g(http, 'body').nil?
        d = gw.call(envoy_request(req))
        if d['allow']
          next({ 'status' => { 'code' => GRPC_OK, 'message' => '' },
                 'okResponse' => { 'headers' => header_options(d['headers']),
                                   'headersToRemove' => PCA_INJECTED_HEADERS.reject { |h| d['headers'].key?(h) } } })
        end

        code = d['status'] == 401 ? GRPC_UNAUTHENTICATED : d['status'] == 503 ? GRPC_UNAVAILABLE : GRPC_PERMISSION_DENIED
        { 'status' => { 'code' => code, 'message' => d['reason'] },
          'deniedResponse' => { 'status' => { 'code' => d['status'] },
                                'headers' => header_options({ 'content-type' => 'application/json' }.merge(d['headers'])),
                                'body' => Js.json({ 'error' => d['code'], 'reason' => d['reason'] }) } }
      end
    end

    # ---- AWS Lambda authorizers ---------------------------------------------------------------------------------------------
    def encode_uri_component(s)
      t = js_s(s)
      raise ArgumentError, 'URI malformed' unless t.dup.force_encoding(Encoding::UTF_8).valid_encoding?

      Js.encode_uri_component(t)
    end

    def lambda_resource(event) = first(g(event, 'methodArn'), g(event, 'routeArn'), '*')

    def lambda_method_path(event)
      http = g(g(event, 'requestContext'), 'http')
      method = first(g(http, 'method'), g(event, 'httpMethod'))
      path = first(g(event, 'rawPath'), g(event, 'path'), g(http, 'path'))
      return { 'method' => method, 'path' => path } if !method.nil? && !path.nil?

      arn = first(g(event, 'methodArn'), g(event, 'routeArn'))
      unless arn.nil?
        parts = (arn.split(':', -1)[5..] || []).join(':').split('/', -1)
        arn_method = parts.length > 2 ? parts[2].split(/ /, -1)[0] : nil
        return { 'method' => first(method, arn_method, '*'), 'path' => first(path, "/#{(parts[3..] || []).join('/')}") }
      end
      { 'method' => first(method, '*'), 'path' => first(path, '/') }
    end

    def lambda_query(event)
      raw = g(event, 'rawQueryString')
      return raw if raw.is_a?(String)

      multi = g(event, 'multiValueQueryStringParameters')
      single = g(event, 'queryStringParameters')
      pairs = []
      if jt(multi) && multi.is_a?(Hash)
        multi.each do |k, vs|
          (vs.nil? ? [] : Js.spread(vs)).each { |v| pairs << "#{encode_uri_component(k)}=#{encode_uri_component(v)}" }
        end
      elsif jt(single) && single.is_a?(Hash)
        single.each { |k, v| pairs << "#{encode_uri_component(k)}=#{encode_uri_component(v)}" }
      end
      pairs.join('&')
    end

    def lambda_request(event)
      mp = lambda_method_path(event)
      { 'method' => mp['method'], 'path' => mp['path'], 'query' => lambda_query(event), 'headers' => first(g(event, 'headers'), {}) }
    end

    def lambda_context(d)
      return(jt(d['verdict']) ? { 'pcaVerdict' => Js.json(d['verdict']) } : {}) if d['allow']

      { 'pcaDenied' => 'true', 'pcaCode' => d['code'], 'pcaReason' => d['reason'], 'pcaStatus' => d['status'].to_s }
    end

    # AWS API Gateway REQUEST authorizer: an Allow IAM policy (verdict on context.pcaVerdict) on a valid proof, else a Deny policy.
    # REST (methodArn) and HTTP-API (routeArn) payloads.
    def lambda_authorizer(opts)
      gw = create_gateway(opts)
      lambda do |event|
        d = gw.call(lambda_request(event))
        { 'principalId' => first(g(d['pcactn'], 'grant_ref'), 'anonymous'),
          'policyDocument' => { 'Version' => '2012-10-17', 'Statement' => [{ 'Action' => 'execute-api:Invoke', 'Effect' => d['allow'] ? 'Allow' : 'Deny',
                                                                             'Resource' => lambda_resource(event) }] },
          'context' => lambda_context(d) }
      end
    end

    # HTTP-API simple-response variant: {'isAuthorized', 'context'} instead of an IAM policy.
    def lambda_simple_authorizer(opts)
      gw = create_gateway(opts)
      lambda do |event|
        d = gw.call(lambda_request(event))
        { 'isAuthorized' => d['allow'], 'context' => lambda_context(d) }
      end
    end
  end
end
