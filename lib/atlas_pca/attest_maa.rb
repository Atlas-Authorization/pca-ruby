# frozen_string_literal: true

require 'set'
require 'timeout'
require_relative 'attest/common'
require_relative 'attest/cert'
require_relative 'attest_maa_pins_data'

module AtlasPca
  # Trust in the token-signing keys of Azure Attestation (MAA), the reference's `attest-maa-keys` and `attest-maa-pins`: a MAA token is signed
  # by a key published at `<issuer>/certs`, so a verifier must decide WHICH keys to trust, and keep deciding as Microsoft rotates them.
  # fetch_maa_certs reads the key set over an injected transport (https only, no redirect, size limits); evaluate_maa_jwks decides which
  # keys of a set are acceptable (a self-signed key whose subject is the issuer URL, or a chain to a pinned Microsoft root, optionally through a
  # pinned intermediate; strict certificate profile, validity window, key strength); MaaKeyTrust keeps the accepted set per issuer in a state
  # store with a TTL, accepts a rotation only when it overlaps the previous set (or a release-signed re-pin approves it) and bounds how many new
  # keys one fetch may introduce, falls back to a stale cache within a limit, and refuses trust-on-first-use unless allowed;
  # corroborate_maa_key_sets requires k independent vantages to observe the same key set; load_builtin_maa_pins verifies the signed pin manifest
  # the SDK ships (and the one an operator supplies). Records are String-keyed Hashes with the reference's member names; a refusal is a result
  # ({'ok' => false, 'code', 'reason'}), construction errors raise.
  module AttestMaa
    HOUR = 3_600_000
    DAY = 24 * HOUR
    ISSUER_URL = %r{\Ahttps://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?\z}
    HEX64 = /\A[0-9a-f]{64}\z/
    MAX_JWKS_KEYS = 32
    MAX_X5C = 8
    MAX_X5C_B64 = 131_072
    EC_CURVES = %w[prime256v1 secp384r1 secp521r1].freeze
    MAX_LIFETIME_MS = 400 * 24 * 3_600_000
    MIN_VANTAGES = 3
    BUILTIN_CHAIN_LEAF_CN = ['Microsoft Azure Attestation 2020'].freeze
    BUILTIN_MAA_PINS_ISSUER_ID = AttestMaaPinsData::BUILTIN_PINS_ISSUER_ID
    BUILTIN_MAA_PINS_ISSUER_KEYS = { BUILTIN_MAA_PINS_ISSUER_ID => AttestMaaPinsData::BUILTIN_PINS_ISSUER_KEY }.freeze

    module_function

    def nn(v, default) = v.nil? ? default : v

    # Buffer.from(x, 'base64') of an x5c entry: lenient base64 text; anything else is the platform's type error.
    def decode_x5c(v)
      return Attest::Common.node_b64decode(v) if v.is_a?(String)

      what = v.nil? ? 'null' : (v == true || v == false ? "type boolean (#{v})" : (v.is_a?(Numeric) ? "type number (#{Attest::Common.js_str(v)})" : 'an instance of Object'))
      raise Attest::JsTypeError, 'The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. ' \
                                 "Received #{what}"
    end
    def member(h, k) = h.is_a?(Hash) ? h[k] : nil

    # ---- the fetch (an injected transport) ----

    # The key set of `<issuer>/certs`. `fetch` is a callable taking (url, options) and answering {'ok' => bool, 'status' => Integer, 'url' =>
    # the final URL?, 'headers' => {'content-length' => text}?, 'body' => the bytes}; it is called with {'redirect' => 'error', 'headers' =>
    # {'accept' => 'application/json'}} and must not follow redirects. Raises on a non-2xx answer, a response from another URL, a declared or
    # actual size over `max_bytes` (default 1 MiB), a body that is not UTF-8 JSON, or a set that is not well formed (at most 32 keys, each with 1..8
    # non-empty x5c entries); a key set is {'keys' => [{'kid'?, 'kty'?, 'alg'?, 'x5c'}]}.
    def fetch_maa_certs(issuer, fetch:, timeout_ms: nil, max_bytes: nil)
      raise TypeError, 'fetchMaaCerts: a fetch implementation must be injected' unless fetch.respond_to?(:call)
      raise TypeError, 'fetchMaaCerts: issuer must be an https origin URL (no path, no trailing slash)' unless issuer.is_a?(String) && issuer.match?(ISSUER_URL)

      timeout_ms = 10_000 if timeout_ms.nil?
      max_bytes = 1_048_576 if max_bytes.nil?
      url = "#{issuer}/certs"
      Timeout.timeout(timeout_ms / 1000.0, Timeout::Error, "MAA certs fetch timed out after #{timeout_ms} ms") do
        res = fetch.call(url, { 'redirect' => 'error', 'headers' => { 'accept' => 'application/json' } })
        raise "MAA certs fetch failed: HTTP #{res['status']}" unless res['ok']
        raise 'MAA certs fetch: response URL differs from the request (redirect)' if Attestation.truthy?(res['url']) && res['url'] != url

        raw = member(res['headers'], 'content-length')
        declared = raw.nil? ? 0 : Attest::Common.js_number(raw.to_s)
        raise 'MAA certs response exceeds the size limit' if Attestation.finite?(declared) && declared > max_bytes

        bytes = res['body'].to_s.b
        raise 'MAA certs response exceeds the size limit' if bytes.bytesize > max_bytes

        text = bytes.dup.force_encoding(Encoding::UTF_8)
        raise 'MAA certs response is not valid UTF-8 JSON' unless text.valid_encoding?

        text = text.delete_prefix("﻿") # the decoder drops a leading byte order mark
        begin
          parsed = Attest::Common.js_json_loads(text)
        rescue Attest::JsError
          raise 'MAA certs response is not valid UTF-8 JSON'
        end
        parse_jwks(parsed)
      end
    end

    def parse_jwks(x)
      raise 'MAA certs: response has no keys array' unless x.is_a?(Hash) && x['keys'].is_a?(Array)

      raw = x['keys']
      raise 'MAA certs: too many keys' if raw.length > MAX_JWKS_KEYS

      keys = raw.map do |k|
        raise 'MAA certs: malformed key entry' unless k.is_a?(Hash) || k.is_a?(Array)

        r = k.is_a?(Hash) ? k : {}
        x5c = r['x5c']
        unless x5c.is_a?(Array) && !x5c.empty? && x5c.length <= MAX_X5C && x5c.none? { |c| !c.is_a?(String) || c.empty? || SafeRegex.utf16_len(c) > MAX_X5C_B64 }
          raise 'MAA certs: key without a well-formed x5c'
        end

        key = {}
        %w[kid kty alg].each { |f| key[f] = r[f] if r[f].is_a?(String) }
        key.merge('x5c' => x5c)
      end
      { 'keys' => keys }
    end

    # ---- evaluating a key set ----

    def sole_cn(subject)
      lines = subject.split("\n").reject(&:empty?)
      return nil unless lines.length == 1

      m = /\ACN=(.*)\z/.match(lines[0])
      m && m[1]
    end

    def leaf_cn(subject)
      subject.split("\n").each { |l| return l[3..] if l.start_with?('CN=') }
      nil
    end

    def rsa_ok?(key)
      t = Attest::Common.key_type(key)
      t == 'rsa' || t == 'rsa-pss' ? Attest::Common.rsa_key_ok?(key) : true
    end

    def key_strength_error(cert)
      pk = cert.public_key
      t = Attest::Common.key_type(pk)
      if t == 'rsa'
        bits = pk.n.num_bits
        return "RSA key size #{bits} outside 2048..8192" unless bits.between?(2048, 8192)

        return rsa_ok?(pk) ? nil : 'RSA public exponent must be odd, at least 3 and at most 32 bits'
      end
      if t == 'ec'
        curve = Attest::Common.node_curve(pk).to_s
        return EC_CURVES.include?(curve) ? nil : "EC curve '#{curve}' not allowed"
      end
      "key type '#{t}' not allowed"
    end

    def safe_verify(cert, key)
      rsa_ok?(key) && cert.verify(key)
    rescue StandardError
      false
    end

    def validity(cert)
      Attest::Der.der_validity_ms(cert.raw)
    end

    # Which keys of a set to trust at `now_ms`: {'accepted' => [{'spki', 'kind', 'notBeforeMs', 'notAfterMs'}], 'rejected' => [{'kid', 'reason'}]}.
    # `policy`: {'clockSkewMs'? (60 s), 'maxKeyAgeMs'? (400 days), 'chainRootSpkiSha256'?, 'chainIntermediateSpkiSha256'?, 'chainLeafCn'?}.
    def evaluate_maa_jwks(jwks, issuer, policy, now_ms)
      raise TypeError, "Cannot read properties of #{policy.nil? ? 'undefined' : 'a non-object'} (reading 'clockSkewMs')" unless policy.is_a?(Hash)

      skew = nn(policy['clockSkewMs'], 60_000)
      max_age = nn(policy['maxKeyAgeMs'], 400 * DAY)
      roots = Set.new(nn(policy['chainRootSpkiSha256'], []).map(&:downcase))
      inters = Set.new(nn(policy['chainIntermediateSpkiSha256'], []).map(&:downcase))
      accepted = {}
      rejected = []
      keys = jwks.is_a?(Hash) ? nn(jwks['keys'], []) : []
      raise TypeError, 'jwks.keys.entries is not a function' unless keys.is_a?(Array)

      keys.each_with_index do |key, i|
        raise TypeError, "Cannot read properties of #{key.nil? ? 'null' : 'undefined'} (reading 'kid')" if key.nil?

        kid = nn(member(key, 'kid'), "##{i}")
        begin
          raise 'clock and skew must be finite' unless Attestation.finite?(now_ms) && Attestation.finite?(skew)
          x5c = member(key, 'x5c')
          if !x5c.is_a?(Array) || x5c.empty?
            rejected << { 'kid' => kid, 'reason' => 'no x5c' }
            next
          end
          certs = x5c.map { |b64| Attest::Cert.new(decode_x5c(b64)) }
          leaf = certs[0]
          certs.each_with_index do |c, j|
            lo, hi = validity(c)
            raise "cert #{j}: unparsable validity" if lo.nil? || hi.nil?
            raise "cert #{j}: not yet valid" if now_ms + skew < lo
            raise "cert #{j}: expired" if now_ms - skew > hi
          end
          lv = validity(leaf)
          strength = key_strength_error(leaf)
          raise strength if strength

          if certs.length == 1
            raise 'key older than maxKeyAgeMs' unless now_ms - lv[0] <= max_age

            cn = sole_cn(leaf.subject)
            raise 'subject is not a single CN' if cn.nil?
            raise 'wildcard CN rejected' if cn.include?('*')
            raise 'subject CN does not equal the issuer URL' if cn != issuer
            raise 'not a genuine self-signed cert' if leaf.issuer != leaf.subject || !safe_verify(leaf, leaf.public_key)

            spki = leaf.spki_sha256
            accepted[spki] = { 'spki' => spki, 'kind' => 'self-signed', 'notBeforeMs' => lv[0], 'notAfterMs' => lv[1] }
            next
          end
          raise 'chained key ignored (no chainRootSpkiSha256 configured)' if roots.empty?

          (certs.length - 1).times do |j|
            raise "chain link #{j} is not signed by the next cert" unless safe_verify(certs[j], certs[j + 1].public_key)
          end
          profile = Attest::Der.strict_chain_error(certs.map(&:raw))
          raise "chain profile: #{profile}" if profile

          top = certs[-1]
          raise 'chain does not end in a self-signed root' if top.issuer != top.subject || !safe_verify(top, top.public_key)

          root_spki = top.spki_sha256
          raise 'chain root is not pinned' unless roots.include?(root_spki)

          cns = policy['chainLeafCn']
          raise 'chained leaf CN not allowed' if cns && !cns.include?(leaf_cn(leaf.subject) || "\u0000")

          top2 = validity(top)
          anchor_spki = root_spki
          anchor_kind = 'chained-root'
          anchor_from, anchor_to = top2
          unless inters.empty?
            mid = certs[1...-1].find { |c| inters.include?(c.spki_sha256) }
            raise 'chain does not pass through a pinned intermediate' if mid.nil?

            mv = validity(mid)
            anchor_spki = mid.spki_sha256
            anchor_kind = 'chained-intermediate'
            anchor_from, anchor_to = mv
          end
          prev = accepted[anchor_spki]
          accepted[anchor_spki] = { 'spki' => anchor_spki, 'kind' => anchor_kind,
                                    'notBeforeMs' => prev ? [prev['notBeforeMs'], anchor_from].min : anchor_from,
                                    'notAfterMs' => [anchor_to, [prev ? prev['notAfterMs'] : 0, lv[1]].max].min }
        rescue StandardError => e
          rejected << { 'kid' => kid, 'reason' => e.message }
        end
      end
      { 'accepted' => accepted.values, 'rejected' => rejected }
    end

    # ---- the trust state ----

    # A state store in memory (get(issuer) -> state or nil, set(issuer, state)); values are copied in and out.
    class MemoryStateStore
      def initialize = @m = {}
      def get(issuer) = @m[issuer]
      def set(issuer, state) = @m[issuer] = JSON.parse(JSON.generate(state))
      def snapshot = @m.dup
    end

    def create_memory_maa_key_state_store = MemoryStateStore.new

    # `parse_state`: the strictly validated state of an issuer, nil when it is anything else.
    def parse_state(x, issuer)
      return nil unless x.is_a?(Hash)
      return nil if x['v'] != 1 || x['issuer'] != issuer || !Attestation.safe_int?(x['fetchedAtMs']) || neg_zero?(x['fetchedAtMs']) || !x['anchors'].is_a?(Array)

      anchors = x['anchors'].map do |a|
        return nil unless a.is_a?(Hash)
        return nil unless a['spki'].is_a?(String) && a['spki'].match?(HEX64)
        return nil unless %w[self-signed chained-root chained-intermediate].include?(a['kind'])
        return nil unless [a['notBeforeMs'], a['notAfterMs'], a['firstSeenMs']].all? { |n| Attestation.safe_int?(n) && !neg_zero?(n) }

        { 'spki' => a['spki'], 'kind' => a['kind'], 'notBeforeMs' => a['notBeforeMs'], 'notAfterMs' => a['notAfterMs'], 'firstSeenMs' => a['firstSeenMs'] }
      end
      { 'v' => 1, 'issuer' => issuer, 'fetchedAtMs' => x['fetchedAtMs'], 'anchors' => anchors }
    end

    def neg_zero?(n) = n.is_a?(Float) && n.zero? && (1.0 / n).negative?

    # A state store over a durable key-value store (the DurableState contract: get, update): the state of an issuer lives at `maa-keys/<issuer>`
    # and is only ever replaced by one that is not older (a corrupt record is overwritten).
    class DurableStateStore
      def initialize(kv) = @kv = kv
      def key(issuer) = "maa-keys/#{issuer}"
      def get(issuer) = @kv.get(key(issuer))

      def set(issuer, state)
        @kv.update(key(issuer)) do |prev|
          p = prev.nil? ? nil : AttestMaa.parse_state(prev, issuer)
          p && p['fetchedAtMs'] > state['fetchedAtMs'] ? nil : state
        end
        nil
      end
    end

    def durable_maa_key_state_store(kv) = DurableStateStore.new(kv)

    # The trust decision for an issuer. `policy`: {'trustedIssuers' (a non-empty list of https origins), 'ttlMs'? (1 h), 'maxStaleMs'? (1 d),
    # 'maxNewKeysPerFetch'? (2), 'maxInitialKeys'? (8), 'maxKeyAgeMs'?, 'requireOverlap'? (true), 'allowTrustOnFirstUse'?, 'initialPins'? ({issuer =>
    # [spki]}), 'chainRootSpkiSha256'?, 'chainIntermediateSpkiSha256'?, 'builtinPins'? (false | true | a pin source; default true: the shipped
    # release-signed pins), 'chainLeafCn'?, 'clockSkewMs'?, 'fetchTimeoutMs'?, 'maxBodyBytes'?}. Raises TypeError on a policy without trusted issuers
    # or a missing transport.
    class KeyTrust
      def initialize(policy:, store:, fetch:)
        raise TypeError, 'createMaaKeyTrust: fetch must be injected' unless fetch.respond_to?(:call)

        pol = policy.is_a?(Hash) ? Marshal.load(Marshal.dump(policy)) : {} # the configuration is frozen at construction
        ti = pol['trustedIssuers']
        if !ti.is_a?(Array) || ti.empty? || ti.any? { |i| !i.is_a?(String) || !i.match?(ISSUER_URL) }
          raise TypeError, 'createMaaKeyTrust: policy.trustedIssuers must be a non-empty list of https origin URLs'
        end

        @policy = pol
        @store = store
        @fetch = fetch
        @trusted = ti.to_set
      end

      def fail_with(code, reason) = { 'ok' => false, 'code' => code, 'reason' => reason }

      # {'ok' => true, 'trustAnchors' => {'rootSpkiSha256' => [...]}, 'source' (cache | fetched | stale-cache), 'anchors', 'newKeys', 'removedKeys',
      # 'rejected'} or a refusal (untrusted-issuer, corrupt-state, clock-regression, fetch-failed, stale-exceeded, no-valid-keys, no-baseline,
      # too-many-new-keys, no-overlap, repin-invalid, builtin-pins-invalid). `repin`: {'manifest', 'verify' => {allowlist verify options}}: a signed
      # allowlist manifest that approves (or revokes) signing keys of this issuer.
      def get_trust_anchors(issuer, now_ms:, repin: nil)
        return fail_with('untrusted-issuer', 'issuer is not in policy.trustedIssuers') unless @trusted.include?(issuer)
        return fail_with('clock-regression', 'nowMs must be an integer') unless Attestation.safe_int?(now_ms)

        pol = @policy
        skew = AttestMaa.nn(pol['clockSkewMs'], 60_000)
        ttl = AttestMaa.nn(pol['ttlMs'], HOUR)
        max_stale = AttestMaa.nn(pol['maxStaleMs'], DAY)
        max_new = AttestMaa.nn(pol['maxNewKeysPerFetch'], 2)
        max_initial = AttestMaa.nn(pol['maxInitialKeys'], 8)
        require_overlap = AttestMaa.nn(pol['requireOverlap'], true)
        live = ->(a) { a.select { |r| now_ms - skew <= r['notAfterMs'] && now_ms + skew >= r['notBeforeMs'] } }
        build = lambda do |source, anchors, new_keys, removed_keys, rejected|
          spkis = anchors.map { |a| a['spki'] }.uniq.sort
          next fail_with('no-valid-keys', 'no unexpired, un-revoked signing keys remain') if spkis.empty?

          { 'ok' => true, 'trustAnchors' => { 'rootSpkiSha256' => spkis }, 'source' => source, 'anchors' => anchors, 'newKeys' => new_keys,
            'removedKeys' => removed_keys, 'rejected' => rejected }
        end
        approved = Set.new
        denied = Set.new
        if repin
          v = AttestAllowlist.verify_allowlist_manifest(repin['manifest'], (repin['verify'] || {}).merge('nowMs' => now_ms))
          return fail_with('repin-invalid', "#{v['code']}: #{v['reason']}") unless v['ok']

          pr = AttestAllowlist.project_allowlist(v, now_ms: now_ms)
          approved = Set.new(pr['maaSigningSpkis'][issuer] || [])
          denied = Set.new(pr['revoked'].select { |r| r['kind'] == 'maa-signing-spki' && r['label'] == issuer }.map { |r| r['value'] })
        end
        eff = pol
        builtin_baseline = []
        builtin_reason = nil
        if pol['builtinPins'] != false
          b = AttestMaa.load_builtin_maa_pins({ 'nowMs' => now_ms }.merge(pol['builtinPins'].is_a?(Hash) ? { 'source' => pol['builtinPins'] } : {}))
          if b['ok']
            builtin_baseline = b['maaSigningSpkis'][issuer] || []
            (b['revokedSigningSpkis'][issuer] || []).each { |r| denied << r }
            eff = pol.merge('chainRootSpkiSha256' => AttestMaa.nn(pol['chainRootSpkiSha256'], b['maaChainRootSpkis']),
                            'chainIntermediateSpkiSha256' => AttestMaa.nn(pol['chainIntermediateSpkiSha256'], b['maaChainIntermediateSpkis']),
                            'chainLeafCn' => AttestMaa.nn(pol['chainLeafCn'], BUILTIN_CHAIN_LEAF_CN.dup))
            builtin_baseline += b['maaChainIntermediateSpkis'] unless builtin_baseline.empty?
          else
            builtin_reason = b['reason']
          end
        end
        allow = ->(a) { a.reject { |r| denied.include?(r['spki']) } }
        raw_state = @store.get(issuer)
        state = nil
        unless raw_state.nil?
          state = AttestMaa.parse_state(raw_state, issuer)
          return fail_with('corrupt-state', 'persisted MAA key state failed validation') if state.nil?
          return fail_with('clock-regression', 'clock is behind the last persisted fetch time') unless now_ms >= state['fetchedAtMs'] - skew
        end
        if state && now_ms - state['fetchedAtMs'] < ttl && now_ms >= state['fetchedAtMs']
          a = allow.call(live.call(state['anchors']))
          return build.call('cache', a, [], [], []) unless a.empty?
        end
        begin
          jwks = AttestMaa.fetch_maa_certs(issuer, fetch: @fetch, timeout_ms: pol['fetchTimeoutMs'], max_bytes: pol['maxBodyBytes'])
        rescue StandardError, Timeout::Error => e
          why = e.message
          return fail_with('fetch-failed', "#{why}; no cached key set") if state.nil?
          return fail_with('stale-exceeded', "#{why}; cached set is older than maxStaleMs") if now_ms - state['fetchedAtMs'] > max_stale

          a = allow.call(live.call(state['anchors']))
          return fail_with('stale-exceeded', "#{why}; every cached key has expired or been revoked") if a.empty?

          return build.call('stale-cache', a, [], [], [])
        end
        ev = AttestMaa.evaluate_maa_jwks(jwks, issuer, eff, now_ms)
        accepted = ev['accepted'].reject { |r| denied.include?(r['spki']) }
        if accepted.empty?
          detail = ev['rejected'].map { |r| "#{r['kid']}: #{r['reason']}" }.join('; ')
          return fail_with('no-valid-keys', "no JWKS key passed validation (#{detail.empty? ? 'empty JWKS' : detail})")
        end

        prev_anchors = state ? live.call(state['anchors']) : []
        baseline = Set.new(prev_anchors.map { |a| a['spki'] })
        if state.nil?
          ((pol['initialPins'] || {})[issuer] || []).each { |p| baseline << p.downcase }
          builtin_baseline.each { |p| baseline << p }
        end
        builtin_baseline.each { |p| approved << p }
        accepted_set = Set.new(accepted.map { |a| a['spki'] })
        approved_here = accepted_set.select { |s| approved.include?(s) }
        unapproved_new = accepted_set.reject { |s| baseline.include?(s) || approved.include?(s) }
        if baseline.empty?
          if approved_here.empty? && !pol['allowTrustOnFirstUse']
            unless builtin_reason.nil?
              return fail_with('builtin-pins-invalid',
                               "built-in pins unusable (#{builtin_reason}); no persisted state, no initialPins, no signed re-pin; refusing trust-on-first-use")
            end

            return fail_with('no-baseline', 'no persisted state, no built-in pin for this issuer, no initialPins and no signed re-pin: refusing trust-on-first-use')
          end
          if accepted_set.size > max_initial && approved_here.length < accepted_set.size
            return fail_with('too-many-new-keys', "initial set of #{accepted_set.size} keys exceeds maxInitialKeys")
          end
        else
          if unapproved_new.length > max_new
            return fail_with('too-many-new-keys', "#{unapproved_new.length} new keys exceed maxNewKeysPerFetch=#{Attestation.jstr(max_new)}")
          end

          overlap = accepted_set.any? { |s| baseline.include?(s) } || !approved_here.empty?
          if require_overlap && !overlap
            return fail_with('no-overlap', 'the new key set shares no key with the previous set and is not covered by a signed re-pin')
          end
        end
        first_seen = (state ? state['anchors'] : []).to_h { |a| [a['spki'], a['firstSeenMs']] }
        records = accepted.map { |a| a.merge('firstSeenMs' => first_seen.fetch(a['spki'], now_ms)) }
        fetched_at = state ? [state['fetchedAtMs'], now_ms].max : now_ms
        @store.set(issuer, { 'v' => 1, 'issuer' => issuer, 'fetchedAtMs' => fetched_at, 'anchors' => records })
        new_keys = records.reject { |r| baseline.include?(r['spki']) }.map { |r| r['spki'] }
        removed_keys = baseline.reject { |s| accepted_set.include?(s) }
        build.call('fetched', records, new_keys, removed_keys, ev['rejected'])
      rescue StandardError => e
        fail_with('fetch-failed', e.message)
      end
    end

    def create_maa_key_trust(policy:, store:, fetch:) = KeyTrust.new(policy: policy, store: store, fetch: fetch)

    # ---- multi-vantage corroboration ----

    # Require `k` (>= 2) distinct vantages to observe the same set of acceptable keys of `opts['issuer']` at `opts['nowMs']`. `sets`: [{'vantage',
    # 'issuer', 'jwks'}]; `opts`: {'issuer', 'nowMs', 'policy'?} (the evaluation policy). The same vantage twice counts once and must not
    # contradict itself. Returns {'ok' => true, 'issuer', 'spkis', 'vantages', 'k'} or {'ok' => false, 'code' (malformed, insufficient-vantages,
    # vantage-disagreement, no-valid-keys), 'reason'}.
    def corroborate_maa_key_sets(sets, k, opts)
      bad = ->(code, reason) { { 'ok' => false, 'code' => code, 'reason' => reason } }
      begin
        return bad.call('malformed', 'k must be an integer >= 2') unless Attestation.safe_int?(k) && k >= 2

        o = opts.is_a?(Hash) ? opts : {}
        return bad.call('malformed', 'issuer/nowMs invalid') unless o['issuer'].is_a?(String) && o['issuer'].match?(ISSUER_URL) && Attestation.safe_int?(o['nowMs'])
        return bad.call('malformed', 'sets must be an array') unless sets.is_a?(Array)

        policy = { 'trustedIssuers' => [o['issuer']] }.merge(o['policy'].is_a?(Hash) ? o['policy'] : {})
        by_vantage = {}
        sets.each do |ob|
          v = member(ob, 'vantage')
          return bad.call('malformed', 'vantage label must be a non-empty string') unless v.is_a?(String) && !v.empty? && SafeRegex.utf16_len(v) <= 100
          return bad.call('malformed', "observation from '#{v}' is for a different issuer") if ob['issuer'] != o['issuer']

          ev = evaluate_maa_jwks(ob['jwks'], o['issuer'], policy, o['nowMs'])
          if ev['accepted'].empty?
            why = ev['rejected'].map { |r| r['reason'] }.join('; ')
            return bad.call('no-valid-keys', "vantage '#{v}' observed no valid key (#{why.empty? ? 'empty' : why})")
          end

          fp = ev['accepted'].map { |a| a['spki'] }.sort.join(',')
          prior = by_vantage[v]
          return bad.call('vantage-disagreement', "vantage '#{v}' supplied two different key sets") if !prior.nil? && prior != fp

          by_vantage[v] = fp
        end
        return bad.call('insufficient-vantages', "#{by_vantage.size} distinct vantage(s) < k=#{k}") if by_vantage.size < k

        distinct = by_vantage.values.uniq
        if distinct.length != 1
          shown = by_vantage.map { |v, f| "#{v}=#{f.split(',').map { |x| x[0, 8] }.join('+')}" }.join(' | ')
          return bad.call('vantage-disagreement', "vantages disagree: #{shown}")
        end
        { 'ok' => true, 'issuer' => o['issuer'], 'spkis' => distinct[0].split(','), 'vantages' => by_vantage.keys.sort, 'k' => k }
      rescue StandardError => e
        bad.call('malformed', e.message)
      end
    end

    # ---- the release-signed pins ----

    # The pins of a verified pin manifest (the manifest shipped with the SDK unless `source` = {'manifest', 'issuerKeys', 'minVersion'?} is given):
    # the signature is verified under the release issuer keys, the lifetime is at most 400 days, and the manifest must carry exactly one
    # corroboration entry recording at least 3 vantages, signing keys, and the Microsoft chain root and intermediate pins. `opts`: {'nowMs',
    # 'source'?}. Returns {'ok' => true, 'version', 'digest', 'expiresAt', 'maaSigningSpkis' => {issuer => [spki]}, 'revokedSigningSpkis',
    # 'maaChainRootSpkis', 'maaChainIntermediateSpkis', 'vantages', 'method'} or {'ok' => false, 'reason'}.
    def load_builtin_maa_pins(opts)
      return { 'ok' => false, 'reason' => 'nowMs must be an integer' } unless Attestation.safe_int?(member(opts, 'nowMs'))

      now = opts['nowMs']
      src = opts['source'] || { 'manifest' => AttestMaaPinsData::BUILTIN_PINS_MANIFEST, 'issuerKeys' => BUILTIN_MAA_PINS_ISSUER_KEYS,
                                'minVersion' => AttestMaaPinsData::BUILTIN_PINS_MIN_VERSION }
      r = evaluate_pins(src, now)
      return r unless r['ok']
      return { 'ok' => false, 'reason' => 'built-in pins are not yet valid (clock behind the release)' } unless now >= r['notBefore']
      return { 'ok' => false, 'reason' => 'built-in pins expired; update the package or pass explicit initialPins' } unless now <= r['expiresAt']

      r['value']
    rescue StandardError => e
      { 'ok' => false, 'reason' => e.message }
    end

    def evaluate_pins(src, now_ms)
      body = member(src['manifest'], 'body')
      v0 = AttestAllowlist.verify_allowlist_manifest(src['manifest'], { 'issuerKeys' => src['issuerKeys'], 'nowMs' => nn(member(body, 'notBefore'), now_ms),
                                                                         'minVersion' => nn(src['minVersion'], 1), 'maxLifetimeMs' => MAX_LIFETIME_MS })
      return { 'ok' => false, 'reason' => "#{v0['code']}: #{v0['reason']}" } unless v0['ok']

      p = AttestAllowlist.project_allowlist(v0, now_ms: v0['body']['notBefore'])
      corr = p['corroboration']
      return { 'ok' => false, 'reason' => 'manifest must carry exactly one attest-corroboration entry' } if corr.length != 1

      m = /\Avantages=([0-9]+);method=(.*)\z/.match(corr[0]['label'])
      vantages = m ? m[1].to_i : 0
      return { 'ok' => false, 'reason' => "corroboration records #{vantages} vantages < required #{MIN_VANTAGES}" } if m.nil? || vantages < MIN_VANTAGES
      return { 'ok' => false, 'reason' => 'manifest pins no MAA signing key' } if p['maaSigningSpkis'].empty?
      if p['maaChainRootSpkis'].empty? || p['maaChainIntermediateSpkis'].empty?
        return { 'ok' => false, 'reason' => 'manifest lacks the Microsoft chain root / intermediate pins' }
      end

      revoked = {}
      p['revoked'].each { |r| (revoked[r['label']] ||= []) << r['value'] if r['kind'] == 'maa-signing-spki' }
      { 'ok' => true, 'notBefore' => v0['body']['notBefore'], 'expiresAt' => v0['body']['expiresAt'],
        'value' => { 'ok' => true, 'version' => v0['version'], 'digest' => v0['digest'], 'expiresAt' => v0['body']['expiresAt'],
                     'maaSigningSpkis' => p['maaSigningSpkis'], 'revokedSigningSpkis' => revoked, 'maaChainRootSpkis' => p['maaChainRootSpkis'],
                     'maaChainIntermediateSpkis' => p['maaChainIntermediateSpkis'], 'vantages' => vantages, 'method' => m[2] } }
    end
  end
end
