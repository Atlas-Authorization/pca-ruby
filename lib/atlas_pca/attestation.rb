# frozen_string_literal: true

require_relative 'attest/common'

module AtlasPca
  # The software attestation layer of an agent (the reference's `attestation` module): the report_data binding hash, the dev attestor and
  # its signed documents, the document registry (resolver), the bounded single-use nonce store and the nonce entropy gate, the agent-binding
  # match, `verify_attestation` and its hook (`create_attestation_verifier`), the multi-root (N of M independent roots) verifier and the
  # anchoring of a verified attestation in the transparency ledger.
  #
  # A software document is SELF-ASSERTED by the key that signs it (it proves "a key the server trusts vouched for these measurements", not
  # "this silicon runs these weights"); a hardware verifier (see atlas_pca/attest) roots the identity in the vendor's chain instead. Records
  # are String-keyed Hashes with the reference's wire members. Verification never raises and fails closed. A post-quantum document verifies
  # only under a PQ key pinned for its attestor (`pq_pins`); this SDK has no unbound opt-out.
  module Attestation
    UNDEF = IntentV2::UNDEF
    DOC_DOMAIN = "atlas-pca/attest/v1\0"
    # Domain separator of the report_data binding hash.
    ATTEST_BIND_DOMAIN = "atlas-pca/attest-bind/v1\0"
    # Domain separator of the anchored attestation-evidence digest.
    ATTEST_ANCHOR_DOMAIN = "atlas-pca/attest-anchor/v1\0"
    # Hard ceiling (ms) on the age of a server-issued attestation nonce at verification time.
    MAX_ATTESTATION_AGE_MS = 5 * 60_000
    # How long (ms) a consumed nonce is remembered by default: 12x the quote-age ceiling.
    DEFAULT_NONCE_RETENTION_MS = 60 * 60 * 1000
    # Minimum entropy of a server-issued nonce: 128 bits.
    MIN_ATTESTATION_NONCE_BYTES = 16
    DEFAULT_NONCE_STORE_MAX = 100_000
    SVN_TEXT = /\A(?:0|[1-9][0-9]*)\z/

    # An anchoring refusal (the reference throws): no ledger, a missing guardian secret when required, a failed tree-head signature.
    class AnchoringError < StandardError; end

    module_function

    # ---- the JavaScript view of a value (the reference reads members and compares with ===)

    def num?(x) = x.is_a?(Integer) || x.is_a?(Float) # typeof x === 'number'
    def finite?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite?) # Number.isFinite

    def safe_int?(x)
      return x.abs <= Attest::Common::MAX_SAFE if x.is_a?(Integer)

      x.is_a?(Float) && x.finite? && x == x.floor && x.abs <= Attest::Common::MAX_SAFE
    end

    def integer_number?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite? && x == x.floor) # Number.isInteger

    def truthy?(x)
      return false if x.nil? || x == false || UNDEF.equal?(x)
      return x != 0 && !(x.is_a?(Float) && x.nan?) if x.is_a?(Numeric)
      return !x.empty? if x.is_a?(String)

      true
    end

    # a === b for the JSON values a wire member can hold (objects are never identical to another)
    def js_eq(a, b)
      return a == b if (a.is_a?(String) && b.is_a?(String)) || (num?(a) && num?(b))
      return a.nil? && b.nil? if a.nil? || b.nil?

      (a == true || a == false) && a == b
    end

    # SameValueZero (Array#includes): NaN equals NaN, no coercion
    def same_value_zero?(a, b)
      return a.nan? && b.nan? if a.is_a?(Float) && b.is_a?(Float) && (a.nan? || b.nan?)

      js_eq(a, b)
    end

    # String(v) in a template literal
    def jstr(v)
      return 'undefined' if UNDEF.equal?(v)
      return 'null' if v.nil?
      return v.map { |x| x.nil? || UNDEF.equal?(x) ? '' : jstr(x) }.join(',') if v.is_a?(Array)

      Attest::Common.js_str(v)
    end

    def dg(v, *keys) # v?.a?.b: nil for anything that is not an object on the way
      keys.each do |k|
        return nil unless v.is_a?(Hash)

        v = v[k]
      end
      v
    end

    # `id.k` of the reference: a null identity throws, a value that is not an object has no such member, an absent member is undefined
    def idv(h, k)
      raise TypeError, "Cannot read properties of null (reading '#{k}')" if h.nil?

      h.is_a?(Hash) && h.key?(k) ? h[k] : UNDEF
    end

    # Number(v) for the values a numeric option can hold
    def to_number(v)
      return v if v.is_a?(Numeric)
      return 1 if v == true
      return 0 if v == false || v.nil?
      return Float::NAN unless v.is_a?(String)

      s = v.strip
      return 0 if s.empty?
      return Float(s) if s.match?(/\A[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\z/)
      return Float::INFINITY if s.match?(/\A\+?Infinity\z/)
      return -Float::INFINITY if s == '-Infinity'

      Float::NAN
    end

    # ---- the report_data binding

    # SHA-512(domain || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce)): the 64-byte value a quote must carry. `exp` is
    # {holderPub, grantRef, epoch, nonce}. Raises (Attest::JsTypeError) with the reference's message on a malformed expected binding.
    def attestation_binding(exp) = Attest::Common.attestation_binding(exp)

    # The base64url form of attestation_binding (what a software document carries in `binding`).
    def attestation_binding_b64u(exp) = AtlasPca.b64e(attestation_binding(exp))

    # base64url(sha256(canonical(document))): a content address of the full signed quote.
    def attestation_digest(doc) = AtlasPca.hash_canonical(doc)

    # ---- the dev attestor

    # A SOFTWARE-mode attestor for dev and CI: signs documents with `secret` (32 bytes or a KeyPair). `alg` is the signature suite
    # (default ed25519); `pq` the ML-DSA-65 key pair of ml-dsa-65 and hybrid suites. The server trusts it by listing `public_key` in
    # `trusted_attestor_keys`. This is not a hardware root of trust.
    class DevAttestor
      attr_reader :public_key

      def initialize(secret, alg: nil, pq: nil)
        raise ArgumentError, "createDevAttestor: unknown signature alg '#{Attestation.jstr(alg)}'" if !alg.nil? && IntentV2.suite_of(alg).nil?

        @signer = secret.is_a?(AtlasPca::KeyPair) ? secret : AtlasPca::KeyPair.new(secret)
        @public_key = @signer.public
        @alg = alg
        @pq = pq
        @pq_pk = pq.respond_to?(:public) ? pq.public : UNDEF
      end

      # Sign a software document over `claims` {model_id, weights_digest, runtime_measurement, operator, nonce, issued_at, expires_at,
      # system_prompt_digest?, tool_manifest_digest?, holder_pub?, grant_ref?, epoch?}: the document is bound to holder / grant / epoch
      # and the nonce when all three of those are given. A missing claim or a non-finite number raises, like the reference.
      def attest(claims)
        c = claims.is_a?(Hash) ? claims : {}
        g = ->(k) { c.key?(k) ? c[k] : UNDEF }
        body = { 'model_id' => g.call('model_id'), 'weights_digest' => g.call('weights_digest'),
                 'runtime_measurement' => g.call('runtime_measurement'), 'operator' => g.call('operator'), 'nonce' => g.call('nonce'),
                 'issued_at' => g.call('issued_at'), 'expires_at' => g.call('expires_at'), 'attestor' => @public_key, 'mode' => 'software' }
        %w[system_prompt_digest tool_manifest_digest].each { |k| body[k] = c[k] if c.key?(k) }
        if %w[holder_pub grant_ref epoch].all? { |k| c.key?(k) }
          body['binding'] = Attestation.attestation_binding_b64u({ 'holderPub' => c['holder_pub'], 'grantRef' => c['grant_ref'],
                                                                  'epoch' => c['epoch'], 'nonce' => c['nonce'] })
        end
        signed = IntentV2.bind_suite_fields(body, @alg.nil? ? UNDEF : @alg, @pq_pk)
        sig, pq_sig = AtlasPca.sign_with_suite(@alg, @signer, @pq, DOC_DOMAIN.b + AtlasPca.canon_bytes(signed))
        out = signed.merge('sig' => sig)
        out['pq_sig'] = pq_sig unless pq_sig.nil?
        out
      end
    end

    def create_dev_attestor(secret, alg: nil, pq: nil) = DevAttestor.new(secret, alg: alg, pq: pq)

    # ---- the document registry

    # A resolver over known documents: a lambda from a context to the document whose `nonce` equals the PCActn's
    # attestation.quote_digest (nil when none). A later document for a nonce replaces an earlier one.
    def attestation_registry(docs)
      by_nonce = {}
      (docs.is_a?(Array) ? docs : []).each { |d| by_nonce[d['nonce']] = d if d.is_a?(Hash) && d['nonce'].is_a?(String) }
      lambda do |ctx|
        key = dg(ctx, 'pcactn', 'attestation', 'quote_digest')
        key.is_a?(String) ? by_nonce[key] : nil
      end
    end

    # ---- the nonce store

    # In-memory single-process store of consumed nonces: #consume is true for the first call with a nonce and false for every later one
    # while the nonce is inside the retention window. Bounded by `max`: a store full of retained nonces REFUSES a new one (it never evicts
    # a live nonce, which would re-open replay). `now` is a clock returning integer epoch milliseconds; anything else refuses the nonce.
    class MemoryNonceStore
      def initialize(max = nil, retention_ms: nil, now: nil)
        max = DEFAULT_NONCE_STORE_MAX if max.nil?
        raise TypeError, 'memoryNonceStore: max must be a positive integer (a store that retains nothing gives no replay protection)' unless Attestation.safe_int?(max) && max >= 1

        retention = retention_ms.nil? ? DEFAULT_NONCE_RETENTION_MS : retention_ms
        raise TypeError, 'memoryNonceStore: retentionMs must be a positive integer (ms)' unless Attestation.safe_int?(retention) && retention.positive?

        @max = max.to_i
        @retention = retention.to_i
        @clock = now || -> { (Time.now.to_f * 1000).floor }
        @seen = {} # nonce -> time consumed (insertion order is time order)
        @lock = Mutex.new
      end

      def consume(nonce)
        return false unless nonce.is_a?(String)

        @lock.synchronize do
          t = @clock.call
          return false unless Attestation.safe_int?(t)

          t = t.to_i
          if @seen.key?(nonce)
            return false if t - @seen[nonce] < @retention

            @seen.delete(nonce) # aged out of retention: the freshness check refuses such a quote anyway
          end
          if @seen.size >= @max
            stale = []
            @seen.each do |k, at|
              break if t - at < @retention

              stale << k
            end
            stale.each { |k| @seen.delete(k) }
            return false if @seen.size >= @max # full of live nonces: fail closed
          end
          @seen[nonce] = t
          true
        end
      end
    end

    def memory_nonce_store(max = nil, retention_ms: nil, now: nil) = MemoryNonceStore.new(max, retention_ms: retention_ms, now: now)

    # Whether `nonce` plausibly carries at least `min_bytes` (floor 16) bytes of entropy: hex (2 digits a byte) or base64url (3 bytes per 4
    # characters) with at least 8 distinct characters. A syntactic floor only: the server must still draw nonces from a CSPRNG.
    def nonce_entropy_ok?(nonce, min_bytes = nil)
      return false unless nonce.is_a?(String)

      m = to_number(min_bytes.nil? ? MIN_ATTESTATION_NONCE_BYTES : min_bytes)
      need = m.is_a?(Float) && m.nan? ? m : [m, MIN_ATTESTATION_NONCE_BYTES].max
      hex = nonce.match?(/\A[0-9a-fA-F]+\z/)
      return false unless hex || nonce.match?(/\A[A-Za-z0-9_-]+\z/)

      bytes = hex ? nonce.length / 2.0 : (nonce.length * 3) / 4
      return false if !(need.is_a?(Float) && need.nan?) && bytes < need

      nonce.chars.uniq.length >= 8
    end

    # ---- the agent binding

    # True iff the grant's agent_binding pins anything (an attestation is then required).
    def requires_attestation?(binding) = AtlasPca.requires_attestation?(binding)

    # True iff the document's nonce is the one the PCActn declares in attestation.quote_digest.
    def nonce_binds?(doc, ctx)
      doc.is_a?(Hash) && doc['nonce'].is_a?(String) && doc['nonce'] == dg(ctx, 'pcactn', 'attestation', 'quote_digest')
    end

    def svn_bound?(x)
      return x >= 0 && x <= Attest::Common::MAX_SAFE if x.is_a?(Integer)

      x.is_a?(Float) && x.finite? && x == x.floor && x >= 0 && x <= Attest::Common::MAX_SAFE && !(x.zero? && (1.0 / x).negative?)
    end

    # The minimum-measurement SVN of a runtime measurement: the safe integer of a canonical decimal text, else nil.
    def measured_svn(runtime)
      return nil unless runtime.is_a?(String) && runtime.match?(SVN_TEXT)

      n = runtime.to_i
      n <= Attest::Common::MAX_SAFE ? n : nil
    end

    # Match a measured identity against the grant's agent_binding: nil when every pinned constraint holds, else the reason of the first
    # failure (model, min_measurement, operator, measured weights, weights, system prompt, tool manifest, in that order). A malformed
    # min_measurement is itself a failure (fail closed); a pinned digest the identity does not carry fails.
    def match_agent_binding(id, binding)
      b = binding.is_a?(Hash) ? binding : {}
      list = ->(x) { x.is_a?(Array) ? x : [] }
      incl = ->(arr, v) { arr.any? { |e| same_value_zero?(e, v) } }
      unless list.call(b['model_allowlist']).empty?
        model = idv(id, 'model_id')
        return "model_id #{jstr(model)} not in model_allowlist" unless incl.call(b['model_allowlist'], model)
      end

      mm = b.key?('min_measurement') ? b['min_measurement'] : UNDEF
      runtime = idv(id, 'runtime_measurement')
      unless UNDEF.equal?(mm) || mm == ''
        if mm.is_a?(String)
          return 'runtime_measurement does not match required min_measurement' unless runtime.is_a?(String) && runtime == mm
        elsif mm.is_a?(Hash) && mm.size == 1 && mm.key?('svn') && svn_bound?(mm['svn'])
          got = measured_svn(runtime)
          return "runtime_measurement #{jstr(runtime)} is not an integer SVN (required min svn #{jstr(mm['svn'])})" if got.nil?
          return "runtime_measurement svn #{got} is below required min svn #{jstr(mm['svn'])}" if got < mm['svn']
        else
          return 'min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)'
        end
      end
      pinned = b['operator'].is_a?(String) && !b['operator'].empty?
      return "operator #{jstr(idv(id, 'operator'))} is not the bound operator" if pinned && !js_eq(idv(id, 'operator'), b['operator'])
      if b['require_measured_weights'] == true && !(id.is_a?(Hash) && id['weights_measured'] == true)
        return 'weights_digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)'
      end
      if !list.call(b['weights_allowlist']).empty? && !incl.call(b['weights_allowlist'], idv(id, 'weights_digest'))
        return 'weights_digest not in weights_allowlist (model swap / fine-tune?)'
      end
      sys = idv(id, 'system_prompt_digest')
      if !list.call(b['system_prompt_allowlist']).empty? && !(sys.is_a?(String) && incl.call(b['system_prompt_allowlist'], sys))
        return 'system_prompt_digest not in system_prompt_allowlist (instructions changed / prompt injection?)'
      end
      tool = idv(id, 'tool_manifest_digest')
      if !list.call(b['tool_manifest_allowlist']).empty? && !(tool.is_a?(String) && incl.call(b['tool_manifest_allowlist'], tool))
        return 'tool_manifest_digest not in tool_manifest_allowlist (tools changed?)'
      end

      nil
    end

    # ---- verification

    def nonce_age_reason(issued, now_ms, skew, max_age)
      return 'server nonce issue time unknown (cannot establish freshness)' unless finite?(issued)
      return 'nonce issued in the future' unless now_ms + skew >= issued
      return 'attestation nonce expired (stale quote)' unless now_ms - issued <= max_age + skew

      nil
    end

    def window_decision(now_ms, skew, iat, exp)
      return :malformed unless finite?(iat) && finite?(exp)
      return :malformed if exp < iat
      return :notyet unless now_ms + skew >= iat
      return :expired unless now_ms - skew <= exp

      :valid
    end

    # The attestors a verifier trusts (a JavaScript Set over the iterable it is given).
    def trusted_list(keys)
      return [] if keys.nil?
      return keys if keys.is_a?(Array)
      return keys.chars if keys.is_a?(String)
      return keys.to_a if !keys.is_a?(Hash) && keys.respond_to?(:to_a)

      raise TypeError, "#{jstr(keys)} is not iterable"
    end

    def software_identity(d)
      id = {}
      %w[model_id weights_digest runtime_measurement operator].each { |k| id[k] = d[k] if d.key?(k) }
      %w[system_prompt_digest tool_manifest_digest].each { |k| id[k] = d[k] if d[k].is_a?(String) }
      id
    end

    def software_signature_ok?(d, alg, pq_pins)
      return false unless d['sig'].is_a?(String)

      body = d.reject { |k, _| %w[sig pq_sig].include?(k) }
      msg = DOC_DOMAIN.b + AtlasPca.canon_bytes(body)
      IntentV2.verify_pinned_suite(alg, d['attestor'], d.key?('pq_pk') ? d['pq_pk'] : UNDEF, msg, d['sig'],
                                   d.key?('pq_sig') ? d['pq_sig'] : UNDEF, pq_pins.is_a?(Hash) ? pq_pins : nil)
    end

    # Verify an attestation for an action. In order, the first failure wins: a document is present; the expected binding is well formed;
    # the PCActn's grant_ref, attestation.epoch and quote_digest agree with `expected`; the document's nonce is the server-issued one;
    # agent_binding.require_hardware has a hardware verifier and a hardware document; then
    #   hardware (`hardware_verifier` given): the nonce age is within [-skew, max age] (required), the verifier accepts, confirms that its
    #     quote carries attestation_binding(expected) and returns the measured identity (the document's own fields and dates are ignored);
    #   software: mode, a trusted attestor, a known suite, the signature (a PQ suite only under a pinned key), the binding hash, the
    #     validity window and, when `expected` carries nonceIssuedAt, the nonce age;
    # and last the agent_binding match on the established identity.
    # `hardware_verifier` answers verify(document, expected, now_ms) with {'ok', 'bound', 'measured', 'reason'}.
    # Returns {'ok', 'present', 'bound', 'reason'?, 'identity'?}; never raises.
    def verify_attestation(document: nil, ctx: nil, expected: nil, now_ms: nil, trusted_attestor_keys: nil, pq_pins: nil,
                           hardware_verifier: nil, max_nonce_age_ms: nil, clock_skew_ms: nil)
      present = document.is_a?(Hash) || document.is_a?(Array)
      refuse = ->(reason) { { 'ok' => false, 'present' => present, 'bound' => false, 'reason' => reason } }
      return refuse.call('verifier clock is not a finite time (fail closed)') unless finite?(now_ms)

      trusted = trusted_list(trusted_attestor_keys)
      skew = finite?(clock_skew_ms) ? [0, clock_skew_ms].max : 0
      max_age = [finite?(max_nonce_age_ms) && max_nonce_age_ms.positive? ? max_nonce_age_ms : MAX_ATTESTATION_AGE_MS, MAX_ATTESTATION_AGE_MS].min
      return refuse.call('no attestation document for this action') unless present

      begin
        expected_binding = attestation_binding_b64u(expected)
      rescue StandardError => e
        return refuse.call("attestation binding not constructible: #{e.message}")
      end
      _holder, e_grant, e_epoch, e_nonce = Attest::Common.expected_parts(expected)
      issued = expected.key?('nonceIssuedAt') ? expected['nonceIssuedAt'] : expected['nonce_issued_at']
      d = document.is_a?(Hash) ? document : {} # an Array reads every member as absent
      return refuse.call('attestation binding: PCActn grant_ref differs from expected grant') unless js_eq(dg(ctx, 'pcactn', 'grant_ref'), e_grant)
      unless js_eq(dg(ctx, 'pcactn', 'attestation', 'epoch'), e_epoch)
        return refuse.call('attestation binding: PCActn attestation epoch differs from expected epoch')
      end
      return refuse.call('attestation nonce does not bind to this PCActn') unless js_eq(dg(ctx, 'pcactn', 'attestation', 'quote_digest'), e_nonce)
      return refuse.call('attestation nonce does not match the server-issued nonce') unless js_eq(d['nonce'], e_nonce)

      env = AtlasPca.read_envelope(dg(ctx, 'grant'))
      ab = env.is_a?(Hash) && env['agent_binding'].is_a?(Hash) ? env['agent_binding'] : nil
      has_hw = !hardware_verifier.nil?
      if ab && ab['require_hardware'] == true
        return refuse.call('agent_binding.require_hardware: no hardware verifier is configured (fail closed)') unless has_hw
        unless d['mode'] == 'hardware'
          return refuse.call('agent_binding.require_hardware: attestation document is not hardware-rooted (software mode)')
        end
      end

      if has_hw
        reason = nonce_age_reason(issued, now_ms, skew, max_age)
        return refuse.call(reason) if reason

        hw = hardware_verifier.verify(document, expected, now_ms)
        raise TypeError, "Cannot read properties of #{hw.nil? ? 'undefined' : 'null'} (reading 'ok')" if hw.nil?

        h = hw.is_a?(Hash) ? hw : {}
        unless truthy?(h['ok'])
          return refuse.call("hardware attestation rejected: #{h['reason'].nil? ? 'invalid' : jstr(h['reason'])}")
        end
        return refuse.call('hardware verifier did not confirm report_data binding') unless h['bound'] == true
        return refuse.call('hardware verifier returned no measured identity') unless truthy?(h['measured'])

        identity = h['measured']
      else
        return refuse.call("document mode #{jstr(idv(d, 'mode'))} needs a hardwareVerifier") unless d['mode'] == 'software'
        return refuse.call('attestor key is not trusted') unless d['attestor'].is_a?(String) && trusted.include?(d['attestor'])

        alg = d.key?('alg') ? d['alg'] : UNDEF
        return refuse.call('attestation declares an unknown signature alg') if IntentV2.suite_of(alg).nil?
        return refuse.call('attestation signature does not verify') unless software_signature_ok?(d, alg, pq_pins)
        return refuse.call('attestation is not bound (binding absent)') unless d['binding'].is_a?(String) && !d['binding'].empty?
        return refuse.call('attestation binding mismatch (holder/grant/epoch/nonce)') unless d['binding'] == expected_binding

        case window_decision(now_ms, skew, d['issued_at'], d['expires_at'])
        when :malformed then return refuse.call('malformed attestation validity window')
        when :notyet then return refuse.call('attestation not yet valid')
        when :expired then return refuse.call('attestation expired')
        end
        if num?(issued)
          reason = nonce_age_reason(issued, now_ms, skew, max_age)
          return refuse.call(reason) if reason
        end
        identity = software_identity(d)
      end
      why = match_agent_binding(identity, ab)
      return refuse.call(why) if why

      { 'ok' => true, 'present' => true, 'bound' => true, 'identity' => identity }
    rescue StandardError => e
      refuse.call("attestation verification error (fail closed): #{e.message}")
    end

    # The attestation hook (hooks.attestation of authorize): a lambda from a context {'pcactn', 'grant'} to
    # {'enforced' => true, 'ok', 'reason'?, 'present', 'bound'}. The expected binding comes from `expected_binding` (a lambda from the
    # context to {holderPub, grantRef, epoch, nonce, nonceIssuedAt?} with a server-issued nonce); without it, and without the loud
    # `insecure_self_declared_nonce` opt-out (the binding is then derived from the PCActn itself: no replay protection), the hook fails
    # closed. A nonce of fewer than 128 bits is refused (not in the opt-out mode). `nonce_store` (consume(nonce) -> bool) makes the nonce
    # single use: it is consumed once, and only after the attestation verified and is bound. The verifier carries its assurance label:
    # software, the hardware verifier's own, or unknown for the opt-out.
    def create_attestation_verifier(trusted_attestor_keys: nil, nonce_store: nil, min_nonce_bytes: nil, hardware_verifier: nil,
                                    resolve_document: nil, expected_binding: nil, insecure_self_declared_nonce: false,
                                    max_nonce_age_ms: nil, now: nil, clock_skew_ms: nil, pq_pins: nil)
      trusted = trusted_attestor_keys.is_a?(Array) ? trusted_attestor_keys.dup : []
      resolve = resolve_document || ->(_ctx) { nil }
      clock = now || -> { (Time.now.to_f * 1000).floor }
      insecure = insecure_self_declared_nonce == true
      hook = lambda do |ctx|
        out = lambda do |ok, present, bound, reason = nil|
          r = { 'enforced' => true, 'ok' => ok }
          r['reason'] = reason if truthy?(reason)
          r.merge('present' => present, 'bound' => bound)
        end
        begin
          document = resolve.call(ctx)
          expected = nil
          if expected_binding
            expected = expected_binding.call(ctx)
          elsif insecure
            chain = dg(ctx, 'pcactn', 'cap_chain')
            leaf = chain.is_a?(Array) && !chain.empty? ? chain.last : dg(ctx, 'grant')
            holder = dg(leaf, 'holder')
            expected = { 'holderPub' => holder.is_a?(String) ? holder : '', 'grantRef' => dg(ctx, 'pcactn', 'grant_ref'),
                         'epoch' => dg(ctx, 'pcactn', 'attestation', 'epoch'), 'nonce' => dg(ctx, 'pcactn', 'attestation', 'quote_digest') }
          end
          unless truthy?(expected)
            next out.call(false, truthy?(document), false, 'no server-issued attestation nonce/binding available (fail closed)')
          end
          nonce = expected.is_a?(Hash) ? expected['nonce'] : nil
          if !insecure && !nonce_entropy_ok?(nonce, min_nonce_bytes)
            next out.call(false, truthy?(document), false,
                          'attestation nonce has less than 128 bits of entropy (F-5; use a CSPRNG nonce of >= 16 bytes)')
          end
          verdict = verify_attestation(document: document, ctx: ctx, expected: expected, now_ms: clock.call, trusted_attestor_keys: trusted,
                                       pq_pins: pq_pins, hardware_verifier: hardware_verifier, max_nonce_age_ms: max_nonce_age_ms,
                                       clock_skew_ms: clock_skew_ms)
          if verdict['ok'] && verdict['bound'] && nonce_store && !truthy?(nonce_store.consume(nonce))
            next out.call(false, verdict['present'], false, 'attestation nonce already consumed (replay)')
          end
          out.call(verdict['ok'], verdict['present'], verdict['bound'], verdict['reason'])
        rescue StandardError => e
          out.call(false, false, false, "attestation verification error (fail closed): #{e.message}")
        end
      end
      label = if insecure then { 'level' => 'unknown', 'vendor' => 'insecure-self-declared-nonce' }
              elsif hardware_verifier then AtlasPca.assurance_label_of(hardware_verifier) || { 'level' => 'unknown' }
              else { 'level' => 'software' }
              end
      AtlasPca.set_assurance_label(hook, label['level'], vendor: label['vendor'], awaiting_audit: label['awaiting_audit'], ceremony: label['ceremony'])
    end

    # ---- multi-root N-of-M policy

    # A hardware verifier that requires corroboration from at least `threshold` of its `roots` (independent attestation roots, each
    # {'id', 'verifier', 'required'?, 'suite'?}), so no single vendor's classical root is the sole point of failure: every root verifies the
    # same action; a required root that fails denies; fewer than `threshold` verified (ok, bound, measured) roots deny; the verified roots'
    # measured identities are reconciled (the first non-empty value of a field wins, two different ones deny). Raises (TypeError) at
    # construction on no roots, a threshold that is not an integer in [1, roots.length], an empty or duplicate id.
    class MultiRootVerifier
      IDENT_FIELDS = %w[model_id weights_digest runtime_measurement operator system_prompt_digest tool_manifest_digest].freeze

      def initialize(policy)
        pol = policy.is_a?(Hash) ? policy : {}
        roots = pol['roots']
        raise TypeError, 'createMultiRootVerifier: at least one attestation root is required' unless roots.is_a?(Array) && !roots.empty?

        thr = pol['threshold']
        unless Attestation.integer_number?(thr) && thr >= 1 && thr <= roots.length
          raise TypeError, 'createMultiRootVerifier: threshold must be an integer in [1, roots.length]'
        end

        ids = {}
        roots.each do |r|
          id = r.is_a?(Hash) ? r['id'] : nil
          raise TypeError, 'createMultiRootVerifier: each root needs a non-empty id' unless id.is_a?(String) && !id.empty?
          raise TypeError, "createMultiRootVerifier: duplicate root id '#{id}'" if ids.key?(id)

          ids[id] = true
        end
        @roots = roots.map { |r| r.dup.freeze }.freeze
        @threshold = thr
        AtlasPca.set_assurance_label(self, AtlasPca.multi_root_level(@roots, thr), vendor: "multi-root:#{ids.keys.join('+')}")
      end

      def verify(document, expected, now_ms)
        results = []
        passed = [] # [root index, measured identity]
        host = {}
        @roots.each_with_index do |root, i|
          res = begin
            root['verifier'].verify(document, expected, now_ms)
          rescue StandardError => e
            { 'ok' => false, 'reason' => "root '#{root['id']}' threw (fail closed): #{e.message}" }
          end
          results << res
          if res.is_a?(Hash) && res['ok'] == true && res['bound'] == true && Attestation.truthy?(res['measured'])
            passed << [i, res['measured']]
            res['hostAsserted'].each { |k, v| host["#{root['id']}.#{k}"] = v } if res['hostAsserted'].is_a?(Hash)
          elsif root['required'] == true
            why = res.is_a?(Hash) ? (res['reason'].nil? ? 'invalid' : Attestation.jstr(res['reason'])) : "root '#{root['id']}' returned a malformed result (fail closed)"
            return { 'ok' => false, 'reason' => "required attestation root '#{root['id']}' failed: #{why}" }
          end
        end
        if passed.length < @threshold
          return { 'ok' => false, 'reason' => "multi-root attestation below threshold (#{passed.length}/#{@threshold} independent roots corroborated)" }
        end

        merged = {}
        IDENT_FIELDS.each do |f|
          chosen = nil
          who = nil
          passed.each do |idx, m|
            v = m.is_a?(Hash) ? m[f] : nil
            next unless v.is_a?(String) && !v.empty?

            if chosen.nil?
              chosen = v
              who = idx
            elsif chosen != v
              return { 'ok' => false, 'reason' => "multi-root attestation identity conflict: roots '#{@roots[who]['id']}' and '#{@roots[idx]['id']}' disagree on #{f}" }
            end
          end
          merged[f] = chosen.nil? ? '' : chosen
        end
        measured_w = !merged['weights_digest'].empty? && passed.any? { |_, m| m.is_a?(Hash) && m['weights_measured'] == true && m['weights_digest'] == merged['weights_digest'] }
        measured = { 'model_id' => merged['model_id'], 'weights_digest' => merged['weights_digest'], 'weights_measured' => measured_w,
                     'runtime_measurement' => merged['runtime_measurement'], 'operator' => merged['operator'] }
        %w[system_prompt_digest tool_manifest_digest].each { |k| measured[k] = merged[k] unless merged[k].empty? }
        res = { 'ok' => true, 'bound' => true, 'measured' => measured }
        res['hostAsserted'] = host unless host.empty?
        res
      rescue StandardError => e
        { 'ok' => false, 'reason' => "multi-root attestation error (fail closed): #{e.message}" }
      end
    end

    def create_multi_root_verifier(policy) = MultiRootVerifier.new(policy)

    # ---- accountability anchoring

    # The canonical, domain-separated digest of a verified attestation: the commitment leaf appended to the transparency ledger. `ev` is
    # {identity, binding: {holderPub, grantRef, epoch, nonce}, rootIds?, suite?, verifiedAt}.
    def attestation_evidence_digest(ev)
      e = ev.is_a?(Hash) ? ev : {}
      id = e['identity']
      bd = e['binding']
      raise TypeError, 'attestationEvidenceDigest: identity and binding are required' unless id.is_a?(Hash) && bd.is_a?(Hash)

      g = ->(h, k) { h.key?(k) ? h[k] : UNDEF }
      pick = ->(h, camel, snake) { h.key?(camel) || !h.key?(snake) ? g.call(h, camel) : h[snake] }
      empty = ->(k) { id[k].nil? ? '' : id[k] }
      roots = e['rootIds'].is_a?(Array) ? e['rootIds'] : []
      AtlasPca.hash_canonical(
        { 'domain' => ATTEST_ANCHOR_DOMAIN, 'holder' => pick.call(bd, 'holderPub', 'holder_pub'), 'grant' => pick.call(bd, 'grantRef', 'grant_ref'),
          'epoch' => g.call(bd, 'epoch'), 'nonce' => g.call(bd, 'nonce'), 'model_id' => g.call(id, 'model_id'),
          'weights_digest' => g.call(id, 'weights_digest'), 'weights_measured' => id['weights_measured'] == true,
          'runtime_measurement' => g.call(id, 'runtime_measurement'), 'operator' => g.call(id, 'operator'),
          'system_prompt_digest' => empty.call('system_prompt_digest'), 'tool_manifest_digest' => empty.call('tool_manifest_digest'),
          'roots' => roots.sort_by { |s| s.to_s.encode('UTF-16BE').b }, 'suite' => e['suite'].nil? ? '' : e['suite'],
          'verified_at' => g.call(e, 'verifiedAt') }
      )
    end

    # Anchor a VERIFIED attestation in the transparency ledger for after-the-fact accountability: append its evidence digest as an opaque
    # commitment and, when `guardian` (the guardian KeyPair; with a PQ `alg` and its `pq` key pair the record is post-quantum) is given,
    # sign the resulting tree head. Detection and attribution, not prevention. Fails closed: no ledger raises; with `required`, so does a
    # missing guardian or a failed tree-head signature. Returns {'index', 'commit', 'sth'?}.
    def anchor_attestation_evidence(ev, ledger: nil, guardian: nil, alg: nil, pq: nil, instance_id: nil, now: nil, required: false)
      fail_closed = ->(msg) { raise AnchoringError, "attestation anchoring (fail closed): #{msg}" }
      fail_closed.call('no transparency ledger available') unless ledger.is_a?(AtlasPca::TransparencyLedger)
      required = required == true
      guardian = AtlasPca::KeyPair.new(guardian) if guardian.is_a?(String)
      fail_closed.call('required anchoring needs a guardian secret to sign the tree head') if required && guardian.nil?
      commit = attestation_evidence_digest(ev)
      prev_root = ledger.head['root']
      index = ledger.append_commitment(commit)['index']
      head = ledger.head
      out = { 'index' => index, 'commit' => commit }
      unless guardian.nil?
        t = now ? now.call : (Time.now.to_f * 1000).floor
        begin
          out['sth'] = AtlasPca.sign_tree_head(guardian, { 'instance_id' => instance_id.nil? ? '' : instance_id, 'principal' => ledger.principal,
                                                           'size' => head['size'], 'root' => head['root'], 'prev_root' => prev_root,
                                                           'timestamp' => t }, alg: alg, pq: pq)
        rescue StandardError => e
          fail_closed.call("tree-head signing failed: #{e.message}") if required
        end
      end
      out
    end
  end
end
