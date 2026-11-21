# frozen_string_literal: true

require 'date'
require 'json'
require 'net/http'
require 'open3'
require 'uri'
require_relative 'js_compat'
require_relative 'payments'
require_relative 'harness'
require_relative 'siem'
require_relative 'store_conformance_load'

module AtlasPca
  # Checks a live PCA deployment's assumptions: clock skew, the replay store, trusted-proxy settings, the signature-suite policy,
  # root-caveat enforcement and the verifier's required checks. Every check returns a result Hash {'id', 'status', 'detail',
  # 'remediation'?, 'observed'?} (status pass / warn / fail / skip); run_doctor merges them, verdict_of reduces them, format_results
  # prints them, and nothing printed carries a credential (scrub_text). Configuration is a plain String-keyed Hash with the
  # reference's sections and member names ('url', 'clock', 'store', 'proxy', 'verifier'). Checks that cannot be observed from here
  # say so instead of passing. Mirrors the TypeScript reference (@atlasauth/pca-doctor): same check ids, messages and order.
  #
  # Network access is injected: fetch.call(url, method:, headers:, timeout_ms:) returns an object with #headers (#[] by lowercase
  # name) and optionally #read (default: Net::HTTP, redirects not followed). The deployed library is probed through load_pca
  # (default: this process's atlas_pca, or the copy found under verifier.pcaDir). The replay-store checks run the store
  # conformance kit over the adapter (StoreConformanceRunner).
  module Doctor
    UNDEF = Object.new.freeze # JS `undefined`
    CHECK_GROUPS = %w[clock store proxy suites caveats].freeze
    DEFAULT_REFERENCE_URL = 'https://www.google.com/generate_204'
    ROOT_CAVEAT_MIN_VERSION = '0.4.1'
    DEFAULT_REQUIRED = %w[counter_format replay revocation plan_root_authorized audience validity grant_ref_bound].freeze
    PROXY_HEADERS = %w[x-forwarded-for forwarded x-real-ip].freeze

    CLOCK_REMEDIATION = 'Synchronise every verifier, issuer and replay-store host with NTP (chrony or systemd-timesyncd) and alert on drift. ' \
                        'PCA tolerates at most 60 s between any two clocks (PCACTN_MAX_SKEW_MS); replay retention is exp + skew, so a clock ' \
                        'outside that bound can free a nonce early or reject fresh actions.'
    PROXY_REMEDIATION = 'Set TRUSTED_PROXY_COUNT to exactly the number of reverse proxies in front of the API that APPEND to the trusted ' \
                        'header (1 behind one load balancer / ingress; 0 when clients connect directly), and TRUSTED_PROXY_HEADER to the ' \
                        'header they write. Too high lets a client pick its own rate-limit bucket with extra X-Forwarded-For entries; too ' \
                        "low merges every client into the proxy's bucket."
    SUITES_REMEDIATION = "Set the verifier's allowedSuites to exactly the suites your issuers sign with (names from SIG_SUITES), e.g. " \
                         "['ed25519'] or ['hybrid-ed25519-ml-dsa-65']."
    PQ_REMEDIATION = 'Never set allowUnboundPq. For pure-PQ or hybrid roots, configure pqPins (issuer Ed25519 identity -> PQ public key, ' \
                     'from pqPinFor) or verify against your stored root grant (trustedRoot; requirePCA / verifyPCActnCore do this).'
    ATOMICITY_REMEDIATION = 'Make consumeOnce / advance one atomic operation on the shared store, e.g. Postgres INSERT .. ON CONFLICT (key) ' \
                            'DO UPDATE .. WHERE until < $now RETURNING and UPDATE .. WHERE counter < $n RETURNING, Redis SET key NX PX or a ' \
                            'Lua compare-and-set; never read, then write. Then run the full kit: pca-store-conformance --adapter <your adapter>.'
    DURABILITY_REMEDIATION = 'Keep consumed keys and counters in a store with synchronous, persistent commits (Postgres synchronous_commit=on; ' \
                             'Redis appendfsync always and maxmemory-policy noeviction), shared by every verifier instance. An in-memory store ' \
                             'is only correct for a single process whose lifetime covers the action lifetime.'
    CAVEAT_REMEDIATION = 'Upgrade @atlasauth/pca to >= 0.4.1 in the deployed application (root caveats outside the envelope are enforced ' \
                         'from 0.4.1), redeploy, and re-run pca-doctor with --pca-dir pointing at the application.'

    USAGE = <<~TXT.chomp
      pca-doctor [--url <deployment>] [options]

        --url URL              the live deployment (base URL of the API that verifies PCActns)
        --config FILE          JSON or JS config (see the pca-doctor guide); env and flags override it
        --store MODULE         replay-store adapter module (store conformance kit interface) for the atomicity / durability checks
        --store-option k=v     passed to the adapter factory (repeatable)
        --reference URL|local  clock reference (default https://www.google.com/generate_204)
        --max-skew-ms N        clock fail threshold (default 60000)
        --trusted-proxy-count N, --proxy-header H, --proxy-hops N   the deployment's proxy settings and the real hop count
        --pca-dir DIR          the deployed application's directory (its installed @atlasauth/pca is probed)
        --only a,b | --skip a,b   check groups: #{CHECK_GROUPS.join(', ')}
        --no-probe             do not send forged forwarding headers to the deployment
        --strict               warnings fail too
        --json                 machine-readable output

      Env: PCA_DOCTOR_URL, PCA_DOCTOR_REFERENCE_URL, PCA_DOCTOR_STORE, TRUSTED_PROXY_COUNT, TRUSTED_PROXY_HEADER, PCA_TRUSTED_PROXY_HOPS,
           PCA_ALLOWED_SUITES (comma list), PCA_PQ_PINS (JSON), PCA_ALLOW_UNBOUND_PQ.
    TXT

    module_function

    # ---- JavaScript value semantics over decoded JSON
    # o?.k: UNDEF for a non-object or an absent member.
    def g(o, k) = o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF
    # v ?? default
    def nn(v, default) = v.equal?(UNDEF) || v.nil? ? default : v
    def num?(v) = v.is_a?(Numeric)
    def truthy?(v) = !v.equal?(UNDEF) && Js.truthy?(v)
    def finite?(x) = num?(x) && (x.is_a?(Integer) || x.finite?)
    def integer?(v) = finite?(v) && v.to_f == v.to_f.floor
    def js_string(v) = v.equal?(UNDEF) ? 'undefined' : Js.string(v)
    def u16len(s) = Siem::U16.len(s)
    def pad_end(s, n) = s + (' ' * [0, n - u16len(s)].max)
    def num_str(v) = num?(v) ? Predicates.js_number_string(v.to_f) : js_string(v)

    # ECMAScript Number(v) of a JSON value.
    def number(v)
      return Float::NAN if v.equal?(UNDEF)

      Payments.to_number(v)
    end

    def res(id, status, detail, remediation = nil, observed = nil)
      r = { 'id' => id, 'status' => status, 'detail' => detail }
      r['remediation'] = remediation unless remediation.nil?
      r['observed'] = observed unless observed.nil?
      r
    end

    # ---- scrub
    # ECMAScript \s as a class body
    WS_CLASS = '\t\n\v\f\r    -     　﻿'
    BEFORE_WORD = '(?<![A-Za-z0-9_])' # \b before a word character, ASCII only
    SCRUB_JWT = /#{BEFORE_WORD}eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/
    SCRUB_AUTH = /#{BEFORE_WORD}([Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]["']?[#{WS_CLASS}]*[:=][#{WS_CLASS}]*)[^\n"']*/
    SCRUB_BEARER = /#{BEFORE_WORD}([Bb][Ee][Aa][Rr][Ee][Rr]|[Bb][Aa][Ss][Ii][Cc]|[Tt][Oo][Kk][Ee][Nn])[#{WS_CLASS}]+[A-Za-z0-9_.~+\/=-]{6,}/
    SCRUB_URL = %r{([a-zA-Z][a-zA-Z0-9+.-]*://)[^#{WS_CLASS}/@]*:[^#{WS_CLASS}/@]*@}
    PAIR_WORDS = %w[token secret password passwd pwd key signature sig credential auth sslpassword].freeze
    ci = ->(w) { w.each_char.map { |c| "[#{c.downcase}#{c.upcase}]" }.join }
    PAIR_ALT = "#{(PAIR_WORDS.map { |w| ci.call(w) } + ["#{ci.call('api')}[_-]?#{ci.call('key')}"]).join('|')}".freeze
    SCRUB_PAIR = /#{BEFORE_WORD}((?:#{PAIR_ALT})["']?[#{WS_CLASS}]*[:=][#{WS_CLASS}]*)("[^"]*"|'[^']*'|[^#{WS_CLASS}"'&,;]+)/
    SCRUB_LONG = /[A-Za-z0-9_-]{40,}/

    # Remove credentials from text the doctor prints: URL userinfo, token= / password= pairs, bearer credentials, JWTs and long
    # token runs; cut to 600 UTF-16 units.
    def scrub_text(text)
      t = text.is_a?(String) ? text : js_string(text)
      Siem::U16.safe(t) do |s|
        s = s.gsub(SCRUB_JWT, '[redacted]')
        s = s.gsub(SCRUB_AUTH) { "#{Regexp.last_match(1)}[redacted]" }
        s = s.gsub(SCRUB_BEARER) { "#{Regexp.last_match(1)} [redacted]" }
        s = s.gsub(SCRUB_URL) { "#{Regexp.last_match(1)}[redacted]@" }
        s = s.gsub(SCRUB_PAIR) { "#{Regexp.last_match(1)}[redacted]" }
        s.gsub(SCRUB_LONG, '[redacted]')
      end.then { |r| u16len(r) > 600 ? "#{Siem::U16.slice(r, 600)}..." : r }
    end

    # Scrub every string inside a JSON-like value (nesting deeper than 8 is left as it is).
    def scrub_deep(v, depth = 0)
      return scrub_text(v) if v.is_a?(String)
      return v if depth > 8 || !(v.is_a?(Hash) || v.is_a?(Array))
      return v.map { |x| scrub_deep(x, depth + 1) } if v.is_a?(Array)

      v.transform_values { |x| scrub_deep(x, depth + 1) }
    end

    # ---- fetch and clock
    Response = Struct.new(:status, :headers) do
      def read = ''
    end

    # The default client (Net::HTTP): redirects are not followed and an HTTP error status is a response, not an exception.
    def default_fetch(url, method: 'GET', headers: nil, timeout_ms: 10_000)
      u = URI.parse(url)
      http = Net::HTTP.new(u.host, u.port)
      http.use_ssl = u.scheme == 'https'
      http.open_timeout = http.read_timeout = timeout_ms.to_f / 1000
      req = Net::HTTPGenericRequest.new(method, false, method != 'HEAD', u.request_uri, (headers || {}).to_h)
      r = http.request(req)
      Response.new(r.code.to_i, r.each_header.to_h { |k, v| [k.downcase, v] })
    end

    MONTHS = %w[jan feb mar apr may jun jul aug sep oct nov dec].freeze
    GMT_ZONE = '[Gg][Mm][Tt]|[Uu][Tt][Cc]|[Uu][Tt]|[Zz]|[+-][0-9]{4}'
    RFC_DATE = /\A(?:[A-Za-z]+,?\s+)?([0-9]{1,2})\s+([A-Za-z]{3})[A-Za-z]*\s+([0-9]{4})\s+([0-9]{1,2}):([0-9]{2})(?::([0-9]{2}))?\s*(#{GMT_ZONE})\z/
    ISO_DATE = /\A([0-9]{4})-([0-9]{2})-([0-9]{2})(?:T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]{1,9}))?)?(Z|[+-][0-9]{2}:[0-9]{2}))?\z/
    EPOCH_JD = 2_440_588

    def epoch(y, mo, d, h, mi, s, ms, off_min)
      days = Date.new(y, mo, 1).jd - EPOCH_JD + d - 1
      (((((days * 24) + h) * 60) + mi) * 60_000 + (s * 1000) + ms - (off_min * 60_000)).to_f
    end

    # Date.parse: NaN when unparseable. Covers the HTTP date (RFC 1123 with a zone; a weekday word is ignored, as the reference
    # engine does) and ISO 8601 with a zone or date only (UTC). shortcut: a date without a zone is local time in the reference engine
    # (host-dependent) and is NaN here; other legacy spellings are NaN.
    def parse_date(s)
      t = Js.trim(s)
      if (m = RFC_DATE.match(t))
        mn = m[2].downcase
        return Float::NAN unless MONTHS.include?(mn)

        h = m[4].to_i
        mi = m[5].to_i
        sec = (m[6] || 0).to_i
        return Float::NAN if h > 24 || mi > 59 || sec > 59 || (h == 24 && (mi != 0 || sec != 0))

        z = m[7].upcase
        off = z.match?(/\A[+-][0-9]{4}\z/) ? (z[0] == '-' ? -1 : 1) * ((z[1, 2].to_i * 60) + z[3, 2].to_i) : 0
        day = m[1].to_i
        return Float::NAN if day < 1 || day > 31

        return epoch(m[3].to_i, MONTHS.index(mn) + 1, day, h, mi, sec, 0, off)
      end
      if (m = ISO_DATE.match(t))
        y = m[1].to_i
        mo = m[2].to_i
        d = m[3].to_i
        return Float::NAN if mo < 1 || mo > 12 || d < 1 || d > Date.new(y, mo, -1).day

        h = (m[4] || 0).to_i
        mi = (m[5] || 0).to_i
        sec = (m[6] || 0).to_i
        return Float::NAN if h > 24 || mi > 59 || sec > 59 || (h == 24 && (mi != 0 || sec != 0 || !m[7].nil?))

        ms = m[7] ? "#{m[7]}00"[0, 3].to_i : 0
        z = m[8]
        off = z && z != 'Z' ? (z[0] == '-' ? -1 : 1) * ((z[1, 2].to_i * 60) + z[4, 2].to_i) : 0
        return epoch(y, mo, d, h, mi, sec, ms, off)
      end
      Float::NAN
    rescue Date::Error, RangeError
      Float::NAN
    end

    # A response header by lowercase name: headers is a Hash-like (#[]) or a reader with #get.
    def header(r, name) = r.headers.respond_to?(:get) ? r.headers.get(name) : r.headers[name]

    def wall_ms = Process.clock_gettime(Process::CLOCK_REALTIME) * 1000

    # One reading of a server's clock from its Date header (one-second resolution: +-0.5 s plus half the round trip):
    # {'offsetMs', 'uncertaintyMs'} (remote minus local) or {'error'}.
    def read_date(url, fetch, now, timeout_ms)
      t0 = now.call
      begin
        r = fetch.call(url, method: 'HEAD', timeout_ms: timeout_ms)
      rescue StandardError => e # any transport failure is an unobservable clock
        return { 'error' => "request failed: #{e.message}" }
      end
      t1 = now.call
      date = header(r, 'date')
      d = date.nil? ? Float::NAN : parse_date(date)
      return { 'error' => date.nil? ? 'no Date header' : "unparseable Date header '#{date}'" } unless d.finite?

      { 'offsetMs' => d + 500 - ((t0 + t1) / 2.0), 'uncertaintyMs' => 500 + ((t1 - t0) / 2.0) }
    end

    def signed_s(ms) = "#{ms >= 0 ? '+' : '-'}#{Harness.to_fixed(ms.abs / 1000.0, 1)} s"

    # Clock skew of the deployment against a reference (the Date headers of both, or this machine's clock). FAIL only when the skew is
    # beyond the limit even at the favourable end of the uncertainty interval; WARN when it is above the warning fraction or could be
    # beyond the limit.
    def check_clock(cfg, fetch, now = nil)
      clock = now || -> { wall_ms }
      url = g(cfg, 'url')
      return res('clock', 'skip', 'no deployment URL given (--url)') unless truthy?(url)

      cc = g(cfg, 'clock')
      max_skew = number(nn(g(cc, 'maxSkewMs'), 60_000))
      warn_at = max_skew * number(nn(g(cc, 'warnFraction'), 0.25))
      timeout = number(nn(g(cc, 'timeoutMs'), 10_000))
      dep = read_date(js_string(url), fetch, clock, timeout)
      if dep.key?('error')
        return res('clock', 'warn', "cannot observe the deployment's clock at #{js_string(url)}: #{dep['error']}",
                   "Make the deployment answer with a Date header (RFC 9110 requires one from an origin with a clock), or check its clock on the host. #{CLOCK_REMEDIATION}")
      end

      ref_url = js_string(nn(g(cc, 'referenceUrl'), DEFAULT_REFERENCE_URL))
      ref = { 'offsetMs' => 0.0, 'uncertaintyMs' => 0.0 }
      ref_name = "this machine's clock"
      ref_note = ''
      if ref_url != 'local'
        r = read_date(ref_url, fetch, clock, timeout)
        if r.key?('error')
          ref_note = " (reference #{ref_url} unusable: #{r['error']}; compared with this machine's clock instead)"
        else
          ref = r
          ref_name = ref_url
        end
      end
      skew = dep['offsetMs'] - ref['offsetMs']
      unc = dep['uncertaintyMs'] + ref['uncertaintyMs']
      lower = skew.abs - unc
      upper = skew.abs + unc
      status = lower > max_skew ? 'fail' : (skew.abs > warn_at || upper > max_skew ? 'warn' : 'pass')
      detail = "deployment clock #{signed_s(skew)} relative to #{ref_name}#{ref_note} (+-#{Harness.to_fixed(unc / 1000.0, 1)} s: Date has 1 s " \
               "resolution, plus round trips); fail beyond #{Predicates.js_number_string(max_skew / 1000)} s, warn above " \
               "#{Predicates.js_number_string(warn_at / 1000)} s. The Date header is written by whatever answers the request (a CDN or proxy may set it)."
      res('clock', status, detail, status == 'pass' ? nil : CLOCK_REMEDIATION,
          { 'skewMs' => skew, 'uncertaintyMs' => unc, 'maxSkewMs' => max_skew, 'warnAtMs' => warn_at, 'reference' => ref_name })
    end

    # ---- proxy
    # The stated TRUSTED_PROXY_COUNT / TRUSTED_PROXY_HEADER against the stated number of appending proxies.
    def check_proxy_config(cfg)
      p = g(cfg, 'proxy')
      n = g(p, 'trustedProxyCount')
      return res('proxy.config', 'skip', 'TRUSTED_PROXY_COUNT not given (config proxy.trustedProxyCount or env TRUSTED_PROXY_COUNT)') if n.equal?(UNDEF)

      header = nn(g(p, 'header'), 'x-forwarded-for')
      hs = js_string(header)
      ns = js_string(n)
      fail_with = ->(detail) { res('proxy.config', 'fail', detail, PROXY_REMEDIATION) }
      return fail_with.call("TRUSTED_PROXY_COUNT=#{ns} is not an integer in 0..16") if !integer?(n) || n < 0 || Js.neg_zero?(n) || n > 16
      if header == 'x-real-ip' && n.zero?
        return fail_with.call('TRUSTED_PROXY_HEADER=x-real-ip needs TRUSTED_PROXY_COUNT >= 1 (with 0 every forwarding header is ignored)')
      end

      hops = g(p, 'hops')
      if hops.equal?(UNDEF)
        return res('proxy.config', n.zero? ? 'pass' : 'warn',
                   "TRUSTED_PROXY_COUNT=#{ns} (#{hs}); the real number of appending proxies was not stated (proxy.hops / PCA_TRUSTED_PROXY_HOPS), so it cannot be compared",
                   n.zero? ? nil : PROXY_REMEDIATION)
      end
      hp = js_string(hops)
      h = number(hops)
      if n > h
        return fail_with.call("TRUSTED_PROXY_COUNT=#{ns} is larger than the #{hp} proxies in front of the API: a client chooses its own address " \
                              "(and rate-limit bucket) with extra #{hs} entries")
      end
      if n < h
        return res('proxy.config', 'warn', "TRUSTED_PROXY_COUNT=#{ns} is smaller than the #{hp} proxies in front of the API: clients are keyed " \
                                            "by a proxy's address and share its bucket", PROXY_REMEDIATION)
      end
      res('proxy.config', 'pass', "TRUSTED_PROXY_COUNT=#{ns} (#{hs}) matches the stated #{hp} appending proxies")
    end

    # A random documentation address (RFC 5737 TEST-NET-2 / -3): never a real client.
    def test_net_ip(rand = nil)
      r = rand || -> { Kernel.rand }
      net = r.call < 0.5 ? '198.51.100' : '203.0.113'
      "#{net}.#{1 + (r.call * 254).floor}"
    end

    # Forged values for all three forwarding headers at once (the server trusts at most one of them).
    def forged_headers(rand = nil)
      r = rand || -> { Kernel.rand }
      chain = Array.new(17) { test_net_ip(r) }
      { 'x-forwarded-for' => chain.join(', '), 'forwarded' => chain.map { |ip| "for=#{ip}" }.join(', '), 'x-real-ip' => test_net_ip(r) }
    end

    def remaining(fetch, url, headers, timeout_ms)
      r = fetch.call(url, method: 'GET', headers: headers, timeout_ms: timeout_ms)
      begin
        r.read if r.respond_to?(:read)
      rescue StandardError
        nil # the body is irrelevant
      end
      v = header(r, 'ratelimit-remaining')
      n = v.nil? ? Float::NAN : Payments.string_to_number(v)
      n.finite? ? n : nil
    end

    # new URL(path, base).href for the shapes a probe path takes (absolute URL, rooted path, relative path).
    def href(path, base)
      b = URI.parse(base)
      raise ArgumentError, 'Invalid URL' if b.scheme.nil? || b.host.nil?

      URI.join(b.path.empty? ? "#{base}/" : base, path).to_s
    rescue URI::Error
      raise ArgumentError, 'Invalid URL'
    end

    # Forged forwarding headers sent to a public rate-limited path, watching RateLimit-Remaining: a forged request that lands in a
    # FRESH bucket while plain requests keep draining one bucket means client-written entries are trusted. A count that is too LOW is
    # not observable from one vantage point.
    def check_proxy_probe(cfg, fetch, rand = nil)
      id = 'proxy.probe'
      url = g(cfg, 'url')
      return res(id, 'skip', 'no deployment URL given (--url)') unless truthy?(url)

      proxy = g(cfg, 'proxy')
      return res(id, 'skip', 'disabled (--no-probe)') if g(proxy, 'probe') == false

      target = href(js_string(nn(g(proxy, 'probePath'), '/v1/pca/suites')), js_string(url))
      t = number(nn(g(g(cfg, 'clock'), 'timeoutMs'), 10_000))
      begin
        a = remaining(fetch, target, {}, t)
        b = remaining(fetch, target, {}, t)
        f = remaining(fetch, target, forged_headers(rand), t)
        c = remaining(fetch, target, {}, t)
      rescue StandardError => e
        return res(id, 'warn', "probe request to #{target} failed: #{e.message}",
                   'Set proxy.probePath to a public, rate-limited path of the deployment, or run with --no-probe.')
      end
      observed = { 'url' => target, 'remaining' => [a, b, f, c] }
      if a.nil? || b.nil? || f.nil? || c.nil?
        return res(id, 'skip', "not observable remotely: #{target} does not return a RateLimit-Remaining header on every response", nil, observed)
      end

      sa = num_str(a)
      sb = num_str(b)
      sf = num_str(f)
      sc = num_str(c)
      unless b < a && c < b
        return res(id, 'warn', "inconclusive: the plain requests' bucket did not drain monotonically (#{sa}, #{sb}, then #{sc}): a window " \
                               'rollover, a shared bucket or concurrent traffic. Re-run.', nil, observed)
      end
      if f > b
        return res(id, 'fail', "a request with FORGED forwarding headers got a fresh rate-limit bucket (remaining #{sf}, while the plain " \
                               "requests' bucket was at #{sb}): the deployment trusts client-written forwarding entries", PROXY_REMEDIATION, observed)
      end
      res(id, 'pass', "forged X-Forwarded-For / Forwarded / X-Real-IP did not move the client to another bucket (remaining #{sa}, #{sb}, " \
                      "forged #{sf}, #{sc}). A count that is too LOW is not observable from one client.", nil, observed)
    end

    # ---- suites
    B64U = /\A[A-Za-z0-9_-]+\z/
    ED25519_ID = /\A[A-Za-z0-9_-]{43}\z/

    def pq_suite?(alg) = alg.is_a?(String) && alg != 'ed25519' && REGISTERED_SUITES.include?(alg)

    # allowedSuites against the closed suite registry (the library's registered suite names, in registry order).
    def check_allowed_suites(cfg, registry = REGISTERED_SUITES)
      id = 'suites.allowed'
      v = g(cfg, 'verifier')
      return res(id, 'skip', 'no verifier configuration given (config verifier.*)') unless truthy?(v)

      lst = g(v, 'allowedSuites')
      known = registry.join(', ')
      if lst.equal?(UNDEF)
        return res(id, 'warn', "allowedSuites is unset: every registered suite is accepted (#{registry.length}: #{known})", SUITES_REMEDIATION)
      end
      return res(id, 'fail', 'allowedSuites is empty or not a list: no PCActn can verify', SUITES_REMEDIATION) if !lst.is_a?(Array) || lst.empty?

      unknown = lst.reject { |s| s.is_a?(String) && registry.include?(s) }
      unless unknown.empty?
        return res(id, 'fail', "allowedSuites names suite(s) outside the registry: #{unknown.map { |s| js_string(s) }.join(', ')} (known: #{known})", SUITES_REMEDIATION)
      end

      res(id, 'pass', "allowedSuites = #{lst.join(', ')}")
    end

    # allowUnboundPq / pqPins / trustedRoot sanity.
    def check_pq_binding(cfg)
      id = 'suites.pq-binding'
      v = g(cfg, 'verifier')
      return res(id, 'skip', 'no verifier configuration given (config verifier.*)') unless truthy?(v)

      fail_with = ->(detail) { res(id, 'fail', detail, PQ_REMEDIATION) }
      if g(v, 'allowUnboundPq') == true
        return fail_with.call('allowUnboundPq is set: PQ keys are read from the artifact, so a hybrid gives no protection against an Ed25519 ' \
                              'forger and a pure-PQ hop can be signed by any key')
      end

      pins = g(v, 'pqPins')
      unless pins.equal?(UNDEF)
        return fail_with.call('pqPins is not an object of { ed25519 identity: pq public key }') unless pins.is_a?(Hash)

        bad = pins.select { |k, val| !ED25519_ID.match?(k) || !val.is_a?(String) || !B64U.match?(val) }.keys
        unless bad.empty?
          return fail_with.call("pqPins has malformed entries (key must be a 43-char base64url Ed25519 identity, value a base64url PQ key): #{bad.join(', ')}")
        end
      end
      allowed = nn(g(v, 'allowedSuites'), REGISTERED_SUITES.dup)
      raise TypeError, 'allowedSuites.filter is not a function' unless allowed.is_a?(Array)

      pq = allowed.select { |s| pq_suite?(s) }
      return res(id, 'pass', 'no post-quantum suite is accepted (Ed25519 only: no PQ binding needed, and no PQ protection)') if pq.empty?

      pinned = !pins.equal?(UNDEF) && !pins.empty?
      if !pinned && g(v, 'trustedRoot') != true
        return res(id, 'warn', "post-quantum suite(s) accepted (#{pq.join(', ')}) with neither pqPins nor a stored trustedRoot: a non-Ed25519 root is " \
                               'refused (fail closed) or its PQ key is not pinned', PQ_REMEDIATION)
      end
      res(id, 'pass', "PQ suites (#{pq.join(', ')}) are bound: #{pinned ? "#{pins.length} pin(s)" : 'stored trustedRoot'}; allowUnboundPq off")
    end

    # ---- root caveats and enforcement
    # The library under test: its version, where it was found (path) and how to probe it: probe.call(root_caveat, amount) ->
    # {'allowed' => bool, 'reasons' => [str]} decides a payment of `amount` USD under a root grant that carries `root_caveat`.
    LoadedPca = Struct.new(:version, :path, :probe)

    # -1 / 0 / 1 for a < b / = / > over major.minor.patch (pre-release tags ignored); NaN parts compare as -1.
    def compare_version(a, b)
      pa = a.split(/[.+-]/, -1).first(3).map { |x| Payments.string_to_number(x) }
      pb = b.split(/[.+-]/, -1).first(3).map { |x| Payments.string_to_number(x) }
      3.times do |i|
        x = i < pa.length && pa[i].finite? ? pa[i] : -1
        y = i < pb.length && pb[i].finite? ? pb[i] : -1
        return x < y ? -1 : 1 if x != y
      end
      0
    end

    # A payment of `amount` USD under a root caveat, through the installed library's caveat evaluation.
    def probe_in_process(root_caveat, amount)
      ok, failed = AtlasPca.evaluate_caveats([root_caveat], { 'now' => wall_ms.to_i, 'action' => { 'verb' => 'pay', 'resource' => 'invoice:42',
                                                                                                    'reversibility_class' => 'reversible',
                                                                                                    'params' => { 'amount' => amount, 'currency' => 'usd' } } })
      { 'allowed' => ok == true, 'reasons' => failed.map(&:to_s) }
    end

    PROBE_CODE = <<~RUBY
      require 'json'
      require 'atlas_pca'
      cv, amount = JSON.parse(ARGV[0])
      ok, failed = AtlasPca.evaluate_caveats([cv], { 'now' => (Time.now.to_f * 1000).to_i, 'action' => { 'verb' => 'pay', 'resource' => 'invoice:42',
        'reversibility_class' => 'reversible', 'params' => { 'amount' => amount, 'currency' => 'usd' } } })
      puts JSON.generate({ 'allowed' => ok == true, 'reasons' => failed.map(&:to_s) })
    RUBY

    # Load the library to probe: this process's atlas_pca, or (with `directory`) the copy under that directory (a gem checkout or a
    # bundle path), probed in a child interpreter so the two never mix. Raises when none is found there.
    def load_pca(directory = nil)
      if directory.nil? || directory.empty?
        spec = Gem.loaded_specs['atlas-pca']
        return LoadedPca.new(spec ? spec.version.to_s : 'unknown', File.dirname(File.expand_path('../atlas_pca.rb', __FILE__)), method(:probe_in_process))
      end
      root = File.expand_path(directory)
      entry = ([File.join(root, 'lib', 'atlas_pca.rb')] + Dir.glob(File.join(root, '**', 'lib', 'atlas_pca.rb')).sort).find { |f| File.file?(f) }
      raise "atlas_pca is not installed in #{directory} or any lib/ below it" if entry.nil?

      lib = File.dirname(entry)
      gem_dir = File.dirname(lib)
      version = (File.basename(gem_dir)[/\Aatlas-pca-(.+)\z/, 1] || File.read(Dir.glob(File.join(gem_dir, '*.gemspec')).first.to_s)[/version\s*=\s*'([^']+)'/, 1] rescue nil) || 'unknown'
      probe = lambda do |cv, amount|
        out, err, st = Open3.capture3(RbConfig.ruby, '-I', lib, '-e', PROBE_CODE, JSON.generate([cv, amount]))
        raise((err.strip.lines.last || 'probe failed').strip) unless st.success?

        JSON.parse(out)
      end
      LoadedPca.new(version, entry, probe)
    end

    def decision(raw)
      reasons = raw.is_a?(Hash) ? raw['reasons'] : nil
      { 'allowed' => raw.is_a?(Hash) && raw['allowed'] == true, 'reasons' => reasons.is_a?(Array) ? reasons.map { |r| js_string(r) } : [] }
    end

    # Root-caveat enforcement (0.4.1 security fix): the deployed library must be >= 0.4.1, and a functional probe through THAT library
    # must show a root max_spend of 100 denying 150 and allowing 50, and an unknown root caveat type denying (fail closed).
    def check_root_caveats(cfg, load = nil)
      id = 'caveats.root'
      d = g(g(cfg, 'verifier'), 'pcaDir')
      pca_dir = truthy?(d) ? d : nil
      begin
        pca = (load || method(:load_pca)).call(pca_dir.nil? ? nil : js_string(pca_dir))
      rescue StandardError => e
        return res(id, 'fail', "cannot load @atlasauth/pca#{pca_dir.nil? ? '' : " from #{js_string(pca_dir)}"}: #{e.message}", CAVEAT_REMEDIATION)
      end
      where = "@atlasauth/pca #{pca.version} at #{pca.path}"
      if compare_version(pca.version, ROOT_CAVEAT_MIN_VERSION).negative?
        return res(id, 'fail', "#{where}: root caveats outside the envelope are NOT enforced before #{ROOT_CAVEAT_MIN_VERSION} (legacy behaviour)", CAVEAT_REMEDIATION)
      end

      begin
        over = decision(pca.probe.call({ 'type' => 'max_spend', 'usd' => 100 }, 150))
        under = decision(pca.probe.call({ 'type' => 'max_spend', 'usd' => 100 }, 50))
        unknown = decision(pca.probe.call({ 'type' => 'pca-doctor-unknown-caveat' }, 50))
      rescue StandardError => e
        return res(id, 'fail', "#{where}: the enforcement probe could not run: #{e.message}", CAVEAT_REMEDIATION)
      end
      observed = { 'version' => pca.version, 'over' => over, 'under' => under, 'unknown' => unknown }
      if over['allowed'] || unknown['allowed']
        return res(id, 'fail', "#{where}: a root caveat was NOT enforced (#{over['allowed'] ? 'max_spend 100 allowed a 150 payment' : 'an unknown root caveat type was allowed'})",
                   CAVEAT_REMEDIATION, observed)
      end
      unless under['allowed']
        return res(id, 'warn', "#{where}: inconclusive: the control payment within the root max_spend was denied too (#{under['reasons'].join('; ')})", nil, observed)
      end

      res(id, 'pass', "#{where}: root caveats enforced (max_spend 100 denies 150, allows 50; an unknown root caveat type denies)", nil, observed)
    end

    # requirePCA must not run with insecureAllowUnenforced, and a custom `require` list should keep the defaults.
    def check_enforcement(cfg)
      id = 'verifier.enforcement'
      v = g(cfg, 'verifier')
      return res(id, 'skip', 'no verifier configuration given (config verifier.*)') unless truthy?(v)

      if g(v, 'insecureAllowUnenforced') == true
        return res(id, 'fail', 'requirePCA runs with insecureAllowUnenforced: required checks that are not enforced do not deny',
                   'Remove insecureAllowUnenforced and supply the stores the required checks need (counter / revocation / budget).')
      end

      req = g(v, 'require')
      unless req.equal?(UNDEF)
        missing = case req
                  when Array then DEFAULT_REQUIRED.reject { |c| req.include?(c) }
                  when String then DEFAULT_REQUIRED.reject { |c| req.include?(c) } # String.prototype.includes: a substring test
                  else raise TypeError, 'require.includes is not a function'
                  end
        unless missing.empty?
          return res(id, 'warn', "the require list drops default check(s): #{missing.join(', ')}",
                     "Keep every default required check (#{DEFAULT_REQUIRED.join(', ')}) and add to it.")
        end
      end
      if truthy?(req)
        raise TypeError, 'require.join is not a function' unless req.is_a?(Array)

        return res(id, 'pass', "require = #{req.map { |x| x.nil? ? '' : js_string(x) }.join(', ')}")
      end
      res(id, 'pass', 'default required checks; insecureAllowUnenforced off')
    end

    # ---- the replay store
    # A store adapter: 'builtin:<name>' (the kit's reference adapters) or 'path/to/file.rb[:Constant]' (the constant defaults to
    # PcaStoreAdapter). The export is an adapter (#name String, #open_store callable returning a client with consume_once(key,
    # retain_until_ms, now_ms) and / or advance(key, counter); optional #capabilities, #restart, #crash, #teardown) or a factory
    # (a callable taking the options Hash and returning one): the store conformance kit's adapter interface.
    def load_adapter(spec, options = nil) = StoreConformanceLoad.load_adapter(spec, (options || {}).dup)

    OP_NAME = { 'consume' => 'consumeOnce', 'advance' => 'advance' }.freeze

    def first_counterexample(h)
      return '' if h['violations'].empty?

      v = h['violations'][0]
      " First violating key #{v['key']}: #{StoreConformanceModel.format_ops(v['counterexample'] || []).join(' | ')}"
    end

    # Replay / counter store checks through the conformance kit's adapter interface: a REAL concurrent conflicting write (many clients
    # consume one fresh key at once: exactly one may win; counters race on one stream) and durability (write, close, restart when the
    # adapter can, read back). Short by design; the full kit goes further.
    def check_store(cfg, loader = nil)
      store = g(cfg, 'store')
      spec = g(store, 'adapter')
      unless truthy?(spec)
        detail = 'no store adapter given (--store ./adapter.rb); the replay store cannot be exercised remotely'
        return [res('store.atomicity', 'skip', detail), res('store.durability', 'skip', detail)]
      end
      opts = g(store, 'options')
      begin
        adapter = (loader || method(:load_adapter)).call(js_string(spec), opts.is_a?(Hash) ? opts : {})
      rescue StandardError, ScriptError => e
        return [res('store.atomicity', 'fail', "cannot load the store adapter #{js_string(spec)}: #{e.message}",
                    'Point --store at a Ruby file exporting a store adapter (see the store conformance kit guide).')]
      end
      begin
        kinds = StoreConformanceRunner.detect_kinds(adapter)
        [store_atomicity(adapter, kinds, store), store_durability(adapter, kinds)]
      rescue StandardError => e
        [res('store.atomicity', 'fail', "the store adapter failed: #{e.message}", ATOMICITY_REMEDIATION)]
      ensure
        adapter.teardown&.call if adapter.respond_to?(:teardown)
      end
    end

    def store_atomicity(adapter, kinds, store)
      kit = StoreConformanceRunner
      clients = nn(g(store, 'concurrency'), 32)
      rounds = nn(g(store, 'rounds'), 10)
      parts = []
      observed = {}
      status = 'pass'
      cx = ''
      kinds.each do |kind|
        w = kit.run_burst(adapter, kind, { 'clients' => clients, 'rounds' => rounds, 'values' => 8 })
        h = StoreConformanceModel.check_history(w['ops'])
        winners = w['ops'].select { |o| o['res'] == 'true' }.map { |o| o['key'] }.uniq.length
        observed[kind] = { 'ops' => h['ops'], 'keys' => h['keys'], 'outcomes' => h['outcomes'], 'violations' => h['violations'].length,
                           'unresolved' => h['unresolved'].length }
        definite = h['outcomes']['true'] + h['outcomes']['false']
        if !h['violations'].empty?
          status = 'fail'
          cx = first_counterexample(h) if cx.empty?
          parts << "#{OP_NAME[kind]}: #{h['violations'].length} of #{js_string(rounds)} same-key rounds NOT linearizable (#{js_string(clients)} concurrent clients)"
        elsif definite.zero? || !h['unresolved'].empty?
          status = 'warn' if status == 'pass'
          parts << "#{OP_NAME[kind]}: inconclusive (#{w['errors']} of #{h['ops']} calls failed or timed out" \
                   "#{h['unresolved'].empty? ? '' : ", #{h['unresolved'].length} key(s) undecided"})"
        else
          parts << "#{OP_NAME[kind]}: #{js_string(rounds)} rounds of #{js_string(clients)} concurrent conflicting calls linearizable" \
                   "#{kind == 'consume' ? " (#{winners} of #{js_string(rounds)} rounds had exactly one TRUE)" : ''}" \
                   "#{w['errors'].zero? ? '' : ", #{w['errors']} calls failed closed"}"
        end
      end
      res('store.atomicity', status, "#{adapter.name}: #{parts.join('; ')}.#{cx}", status == 'pass' ? nil : ATOMICITY_REMEDIATION, observed)
    end

    def store_durability(adapter, kinds)
      caps = adapter.respond_to?(:capabilities) ? (adapter.capabilities || {}) : {}
      if caps['durable'] == false
        return res('store.durability', 'warn', "#{adapter.name} declares itself non-durable: a restart forgets consumed nonces", DURABILITY_REMEDIATION)
      end

      parts = []
      status = 'pass'
      cx = ''
      kinds.each do |kind|
        w = StoreConformanceRunner.run_durability(adapter, kind)
        h = StoreConformanceModel.check_history(w['ops'])
        if !h['violations'].empty?
          status = 'fail'
          cx = first_counterexample(h) if cx.empty?
          parts << "#{OP_NAME[kind]}: state LOST across close/restart"
        elsif h['outcomes']['true'] + h['outcomes']['false'] < w['ops'].length
          status = 'warn' if status == 'pass'
          parts << "#{OP_NAME[kind]}: inconclusive (#{w['errors']} calls failed)"
        else
          parts << "#{OP_NAME[kind]}: survived"
        end
      end
      how = adapter.respond_to?(:restart) && adapter.restart ? 'write, close, restart the backend, read back' : 'write, close, re-open (no restart hook: the backend itself was not restarted)'
      res('store.durability', status, "#{adapter.name} (#{how}): #{parts.join('; ')}.#{cx}", status == 'pass' ? nil : DURABILITY_REMEDIATION)
    end

    # ---- configuration
    # The scheme of `u` when it parses as an absolute URL, else nil (the reference's `new URL` throws).
    def valid_url_scheme(u)
      return nil unless u.is_a?(String)

      s = Js.trim(u).delete("\t\r\n")
      m = s.match(/\A([A-Za-z][A-Za-z0-9+.\-]*):/)
      return nil if m.nil?

      rest = m.post_match
      host = ''
      if rest.start_with?('//')
        netloc = rest[2..].split(%r{[/?#]}, 2).first.to_s
        return nil if (netloc.include?('[') && !netloc.include?(']')) || (netloc.include?(']') && !netloc.include?('['))

        info = netloc.rpartition('@')[2]
        if info.include?('[')
          host = info[/\A\[([^\]]*)\]/, 1].to_s
          tail = info[/\].*\z/].to_s[1..].to_s
          port = tail.start_with?(':') ? tail[1..] : (tail.empty? ? nil : :bad)
        else
          host, sep, p = info.partition(':')
          port = sep.empty? ? nil : p
        end
        return nil if port == :bad || (!port.nil? && (!port.match?(/\A[0-9]+\z/) || port.to_i > 65_535))
      end
      scheme = m[1].downcase
      return nil if %w[http https ftp ws wss].include?(scheme) && host.empty?

      scheme
    end

    # Numeric settings that would make a check meaningless (NaN, negative, zero where a duration is needed) are configuration errors.
    def config_problems(cfg)
      out = []
      pos = lambda do |name, v, integer = false|
        next if v.equal?(UNDEF)

        out << "#{name} must be a positive #{integer ? 'integer' : 'number'}" if !num?(v) || !finite?(v) || v <= 0 || (integer && !integer?(v))
      end
      nonneg = lambda do |name, v|
        next if v.equal?(UNDEF)

        out << "#{name} must be a non-negative integer" if !num?(v) || !integer?(v) || v < 0 || Js.neg_zero?(v)
      end
      clock = g(cfg, 'clock')
      store = g(cfg, 'store')
      proxy = g(cfg, 'proxy')
      pos.call('clock.maxSkewMs', g(clock, 'maxSkewMs'))
      pos.call('clock.timeoutMs', g(clock, 'timeoutMs'))
      wf = g(clock, 'warnFraction')
      out << 'clock.warnFraction must be a number in (0, 1]' if !wf.equal?(UNDEF) && !(num?(wf) && wf > 0 && wf <= 1)
      pos.call('store.concurrency', g(store, 'concurrency'), true)
      pos.call('store.rounds', g(store, 'rounds'), true)
      nonneg.call('proxy.trustedProxyCount', g(proxy, 'trustedProxyCount'))
      nonneg.call('proxy.hops', g(proxy, 'hops'))
      url = g(cfg, 'url')
      unless url.equal?(UNDEF)
        scheme = valid_url_scheme(url)
        if scheme.nil?
          out << 'url is not a valid URL'
        elsif !%w[http https].include?(scheme)
          out << 'url must be an http(s) URL'
        end
      end
      out
    end

    # Run the selected check groups (all by default) and scrub everything they report. An invalid configuration is reported as `config`
    # failures and nothing else runs. A group that raises is a failed check, not a crashed run and not a skipped one.
    def run_doctor(cfg, only = nil, fetch: nil, now: nil, load: nil, loader: nil)
      sel = only.nil? ? CHECK_GROUPS.dup : only
      problems = config_problems(cfg)
      unless problems.empty?
        return problems.map { |p| res('config', 'fail', scrub_text("invalid configuration: #{p}"), 'Correct the setting; no check was run.') }
      end

      f = fetch || method(:default_fetch)
      out = []
      guarded = lambda do |id, &run|
        r = run.call
        out.concat(r.is_a?(Array) ? r : [r])
      rescue StandardError => e
        out << res(id, 'fail', "#{id} could not run: #{scrub_text(e.message)}", 'Fix the configuration or the dependency named above and run the doctor again.')
      end
      guarded.call('clock') { check_clock(cfg, f, now) } if sel.include?('clock')
      guarded.call('store') { check_store(cfg, loader) } if sel.include?('store')
      if sel.include?('proxy')
        guarded.call('proxy.config') { check_proxy_config(cfg) }
        guarded.call('proxy.probe') { check_proxy_probe(cfg, f) }
      end
      if sel.include?('suites')
        guarded.call('suites.allowed') { check_allowed_suites(cfg) }
        guarded.call('suites.pq') { check_pq_binding(cfg) }
      end
      if sel.include?('caveats')
        guarded.call('caveats.root') { check_root_caveats(cfg, load) }
        guarded.call('caveats.enforcement') { check_enforcement(cfg) }
      end
      # nothing the doctor prints may carry a credential from the deployment URL, an adapter option or an error message
      out.map { |r| scrub_deep(r) }
    end

    # fail if any check failed; warn if any warned (fail under strict); else pass. A run in which nothing was checked (no results, or
    # every result skipped) is a fail: a doctor that looked at nothing must not report a healthy deployment.
    def verdict_of(results, strict = false)
      return 'fail' unless results.any? { |r| r['status'] != 'skip' }
      return 'fail' if results.any? { |r| r['status'] == 'fail' }
      return strict ? 'fail' : 'warn' if results.any? { |r| r['status'] == 'warn' }

      'pass'
    end

    def format_results(results, target = nil, strict = false)
      lines = ["pca-doctor#{truthy?(target) ? ": #{target}" : ''}"]
      results.each do |r|
        lines << "  #{pad_end(r['status'].to_s.upcase, 4)}  #{pad_end(r['id'].to_s, 20)} #{r['detail']}"
        lines << "  #{' ' * 4}  #{' ' * 20} fix: #{r['remediation']}" if truthy?(r.fetch('remediation', UNDEF))
      end
      n = ->(s) { results.count { |r| r['status'] == s } }
      lines << '  FAIL  nothing checked        no check produced a result: nothing about this deployment was verified' unless results.any? { |r| r['status'] != 'skip' }
      lines << "Summary: #{n.call('pass')} pass, #{n.call('warn')} warn, #{n.call('fail')} fail, #{n.call('skip')} skip -> #{verdict_of(results, strict).upcase}"
      lines.join("\n")
    end

    TRUTHY_ENV = /\A(?:1|[Tt][Rr][Uu][Ee]|[Yy][Ee][Ss]|[Oo][Nn])\z/

    def env_int(name, v)
      return UNDEF if v.nil? || v == ''

      n = Payments.string_to_number(v)
      raise ArgumentError, "#{name} must be a non-negative integer" if !integer?(n) || n.negative? || Js.neg_zero?(n)

      n.to_i
    end

    # The deployment's own environment variable names (as the API and the guides use them).
    def config_from_env(env)
      c = {}
      e = ->(k) { env[k] }
      c['url'] = e.call('PCA_DOCTOR_URL') if truthy?(e.call('PCA_DOCTOR_URL'))
      c['clock'] = { 'referenceUrl' => e.call('PCA_DOCTOR_REFERENCE_URL') } if truthy?(e.call('PCA_DOCTOR_REFERENCE_URL'))
      c['store'] = { 'adapter' => e.call('PCA_DOCTOR_STORE') } if truthy?(e.call('PCA_DOCTOR_STORE'))
      proxy = {}
      touched = false
      unless e.call('TRUSTED_PROXY_COUNT').nil?
        touched = true
        v = env_int('TRUSTED_PROXY_COUNT', e.call('TRUSTED_PROXY_COUNT'))
        proxy['trustedProxyCount'] = v unless v.equal?(UNDEF)
      end
      if truthy?(e.call('TRUSTED_PROXY_HEADER'))
        touched = true
        h = e.call('TRUSTED_PROXY_HEADER').downcase
        raise ArgumentError, "TRUSTED_PROXY_HEADER must be one of #{PROXY_HEADERS.join(', ')}" unless PROXY_HEADERS.include?(h)

        proxy['header'] = h
      end
      unless e.call('PCA_TRUSTED_PROXY_HOPS').nil?
        touched = true
        v = env_int('PCA_TRUSTED_PROXY_HOPS', e.call('PCA_TRUSTED_PROXY_HOPS'))
        proxy['hops'] = v unless v.equal?(UNDEF)
      end
      c['proxy'] = proxy if touched
      verifier = {}
      verifier['allowedSuites'] = e.call('PCA_ALLOWED_SUITES').split(',', -1).map { |s| Js.trim(s) }.reject(&:empty?) unless e.call('PCA_ALLOWED_SUITES').nil?
      if truthy?(e.call('PCA_PQ_PINS'))
        pins = begin
          Js.parse(e.call('PCA_PQ_PINS'))
        rescue StandardError
          raise ArgumentError, 'PCA_PQ_PINS is not valid JSON' # never echo the value
        end
        raise ArgumentError, 'PCA_PQ_PINS must be a JSON object of issuer -> public key strings' unless pins.is_a?(Hash) && pins.values.all?(String)

        verifier['pqPins'] = pins
      end
      verifier['allowUnboundPq'] = TRUTHY_ENV.match?(e.call('PCA_ALLOW_UNBOUND_PQ')) unless e.call('PCA_ALLOW_UNBOUND_PQ').nil?
      c['verifier'] = verifier unless verifier.empty?
      c
    end

    # {...v} of a decoded JSON value: an object's members, an array's or a string's indices.
    def spread(v)
      return v.dup if v.is_a?(Hash)
      return v.each_with_index.to_h { |x, i| [i.to_s, x] } if v.is_a?(Array)
      return Siem::U16.units(v).each_with_index.to_h { |u, i| [i.to_s, Siem::U16.from_units([u])] } if v.is_a?(String)

      {}
    end

    # Two-level merge: later sources win per field inside each section.
    def merge_config(*cs)
      out = {}
      cs.each do |c|
        c.each do |k, val|
          raise ArgumentError, "config key \"#{k}\" is not allowed" if %w[__proto__ constructor prototype].include?(k)

          if val.is_a?(Hash)
            merged = spread(nn(out.fetch(k, UNDEF), {}))
            merged.update(val)
            out[k] = merged
          else
            out[k] = val
          end
        end
      end
      out
    end

    # A JSON file, or a Ruby file whose last expression is the config Hash.
    def load_config_file(path)
      return Js.parse(File.read(path, encoding: 'UTF-8')) if path.end_with?('.json')
      raise ArgumentError, "only a .json or .rb config file can be loaded: #{path}" unless path.end_with?('.rb')

      cfg = eval(File.read(path), TOPLEVEL_BINDING, File.expand_path(path), 1) # rubocop:disable Security/Eval -- the operator's own config file
      raise ArgumentError, "#{path}: defines no config Hash" unless cfg.is_a?(Hash)

      cfg
    end

    # ---- CLI
    def groups(flag, v)
      gs = (v || '').split(',', -1).reject(&:empty?)
      bad = gs.reject { |x| CHECK_GROUPS.include?(x) }
      raise ArgumentError, "#{flag}: unknown check group(s) #{bad.empty? ? '(none given)' : bad.join(', ')}" if !bad.empty? || gs.empty?

      gs
    end

    def num_arg(flag, v)
      n = v.nil? || v == '' ? Float::NAN : Payments.string_to_number(v)
      raise ArgumentError, "#{flag} needs a number" unless n.finite?

      n == n.floor && n.abs < 2**53 ? n.to_i : n
    end

    # d.key = v where an undefined value leaves the member absent.
    def set(d, key, v)
      v.nil? ? d.delete(key) : d[key] = v
    end

    # The parsed command line: {'flags' (a config), 'only', 'json', 'strict', 'help', 'config'?}.
    def parse_doctor_args(argv)
      a = { 'flags' => {}, 'only' => CHECK_GROUPS.dup, 'json' => false, 'strict' => false, 'help' => false }
      f = a['flags']
      i = 0
      sub = lambda do |name|
        d = (f[name] || {}).dup
        f[name] = d
        d
      end
      nxt = lambda do
        i += 1
        i < argv.length ? argv[i] : nil
      end
      while i < argv.length
        k = argv[i]
        case k
        when '--url' then set(f, 'url', nxt.call)
        when '--config'
          v = nxt.call
          v.nil? ? a.delete('config') : a['config'] = v
        when '--store' then set(sub.call('store'), 'adapter', nxt.call)
        when '--store-option'
          kv = nxt.call || ''
          eq = kv.index('=')
          raise ArgumentError, '--store-option needs k=v' if eq.nil? || eq < 1

          st = sub.call('store')
          opts = (st['options'] || {}).dup
          opts[kv[0, eq]] = kv[(eq + 1)..]
          st['options'] = opts
        when '--reference' then set(sub.call('clock'), 'referenceUrl', nxt.call)
        when '--max-skew-ms' then sub.call('clock')['maxSkewMs'] = num_arg(k, nxt.call)
        when '--trusted-proxy-count' then sub.call('proxy')['trustedProxyCount'] = num_arg(k, nxt.call)
        when '--proxy-header'
          h = (nxt.call || '').downcase
          raise ArgumentError, '--proxy-header must be x-forwarded-for, forwarded or x-real-ip' unless PROXY_HEADERS.include?(h)

          sub.call('proxy')['header'] = h
        when '--proxy-hops' then sub.call('proxy')['hops'] = num_arg(k, nxt.call)
        when '--no-probe' then sub.call('proxy')['probe'] = false
        when '--pca-dir' then set(sub.call('verifier'), 'pcaDir', nxt.call)
        when '--only' then a['only'] = groups(k, nxt.call)
        when '--skip'
          s = groups(k, nxt.call)
          a['only'] = a['only'].reject { |x| s.include?(x) }
        when '--strict' then a['strict'] = true
        when '--json' then a['json'] = true
        when '-h', '--help' then a['help'] = true
        else raise ArgumentError, "unknown argument #{k}"
        end
        i += 1
      end
      a
    end

    # JSON.stringify(v, null, 2).
    def stringify(v, ind = '')
      case v
      when nil then 'null'
      when true then 'true'
      when false then 'false'
      when String then Js.json_string(v)
      when Numeric then v.is_a?(Float) && !v.finite? ? 'null' : Predicates.js_number_string(v.to_f)
      when Array
        return '[]' if v.empty?

        inner = "#{ind}  "
        "[\n#{v.map { |x| "#{inner}#{stringify(x, inner)}" }.join(",\n")}\n#{ind}]"
      else
        return '{}' if v.empty?

        inner = "#{ind}  "
        "{\n#{v.map { |k, x| "#{inner}#{Js.json_string(k.to_s)}: #{stringify(x, inner)}" }.join(",\n")}\n#{ind}}"
      end
    end

    # Run the CLI: exit code 1 on any fail (and on warn with --strict), 2 on usage errors, else 0. deps are run_doctor's fetch: /
    # now: / load: / loader:.
    def main(argv, env = nil, print_out = ->(s) { puts s }, print_err = ->(s) { warn s }, **deps)
      begin
        a = parse_doctor_args(argv)
        if a['help']
          print_out.call(USAGE)
          return 0
        end
        cfg = merge_config(a['config'] ? load_config_file(a['config']) : {}, config_from_env(env.nil? ? ENV.to_h : env), a['flags'])
      rescue StandardError => e
        print_err.call("#{scrub_text(e.message)}\n\n#{USAGE}")
        return 2
      end
      results = run_doctor(cfg, a['only'], **deps)
      verdict = verdict_of(results, a['strict'])
      url = cfg['url']
      if a['json']
        print_out.call(stringify({ 'target' => url, 'verdict' => verdict, 'results' => results }))
      else
        print_out.call(format_results(results, truthy?(url) ? js_string(url) : nil, a['strict']))
      end
      verdict == 'fail' ? 1 : 0
    end

    # ---- what only makes sense for a Ruby install
    # Which registered suites this Ruby runtime can verify. When verifier.allowedSuites names a suite that is registered but not
    # verifiable here, it fails closed at verification time: that is a warning here.
    def check_runtime(cfg = nil)
      avail = AtlasPca.supported_suites
      missing = REGISTERED_SUITES - avail
      observed = { 'available' => avail, 'unavailable' => missing }
      allowed = g(g(cfg, 'verifier'), 'allowedSuites')
      want = allowed.is_a?(Array) ? allowed.select { |s| s.is_a?(String) } : []
      dead = want.select { |s| missing.include?(s) }
      unless dead.empty?
        return res('suites.runtime', 'warn', "allowedSuites names suite(s) this Ruby runtime cannot verify (they are refused, fail closed): #{dead.join(', ')}. " \
                                              "Verifiable here: #{avail.join(', ')}",
                   'Use OpenSSL >= 3.5 (post-quantum suites) or drop the suite from allowedSuites.', observed)
      end

      res('suites.runtime', 'pass', "verifiable in this runtime (#{avail.length} of #{REGISTERED_SUITES.length} registered suites): #{avail.join(', ')}", nil, observed)
    end
  end
end
