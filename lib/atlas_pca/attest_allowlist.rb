# frozen_string_literal: true

module AtlasPca
  # Signed, versioned, expiring measurement-allowlist manifests (the reference's `attest-allowlist`): what a verifier of hardware or
  # software attestations may accept (TDX MRTD / RTMR, SEV-SNP measurements, GCP image digests, NVIDIA measurements and driver versions, Azure
  # MAA signing and chain SPKIs, attestation corroboration digests), published by an issuer whose keys the verifier holds, with a version that
  # only moves forward. verify_allowlist_manifest checks the shape (strict: only the known members, every value in its exact form), the issuer
  # and suite, the signature (a post-quantum suite only under the issuer's registered key), the validity window, the lifetime, the minimum
  # version and the rollback floor; verify_allowlist_durable keeps the highest accepted {version, digest} per issuer in a durable key-value
  # store, so a rollback is refused across restarts; create / sign / revoke build manifests; project_allowlist and the *_policy_fields turn a
  # verified manifest into the policy fields of the vendor verifiers (revoked and expired entries leave the lists).
  # Records are String-keyed Hashes with the reference's member names. A verify refusal is a RESULT ({'ok' => false, 'code', 'reason'}; only the
  # code is part of the contract), construction and build errors raise.
  module AttestAllowlist
    ALLOWLIST_KINDS = %w[tdx-mrtd tdx-rtmr sev-snp-measurement gcp-image-digest nvidia-measurement nvidia-driver-version maa-signing-spki
                         maa-chain-root-spki maa-chain-intermediate-spki attest-corroboration].freeze
    DOMAIN = "pca-attest-allowlist/v1\n"
    HEX96 = /\A[0-9a-f]{96}\z/
    HEX64 = /\A[0-9a-f]{64}\z/
    IMAGE_DIGEST = /\Asha256:[0-9a-f]{64}\z/
    DRIVER_VERSION = /\A[0-9]{1,6}(\.[0-9]{1,6}){1,3}\z/
    CORROBORATION_LABEL = /\Avantages=[1-9][0-9]{0,2};method=[\x20-\x7e]{1,150}\z/
    ISSUER_URL = %r{\Ahttps://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?\z}
    B64U_DIGEST = /\A[A-Za-z0-9_-]{43}\z/
    BODY_KEYS = %w[version issuedAt notBefore expiresAt entries].freeze
    ENTRY_KEYS = %w[kind value label notAfter revoked].freeze
    MANIFEST_KEYS = %w[body issuer alg sig pq_sig].freeze
    MAX_ENTRIES = 10_000

    module_function

    def record?(x) = x.is_a?(Hash)
    def only_keys?(r, allowed) = r.keys.all? { |k| allowed.include?(k) }
    def utf16(s) = SafeRegex.utf16_len(s)

    # a non-negative safe integer epoch (not negative zero)
    def epoch?(x)
      Attestation.safe_int?(x) && x >= 0 && !(x.is_a?(Float) && x.zero? && (1.0 / x).negative?)
    end

    def value_error(kind, value, label)
      case kind
      when 'tdx-mrtd', 'tdx-rtmr', 'sev-snp-measurement', 'nvidia-measurement'
        value.match?(HEX96) ? nil : "#{kind} must be 96 lowercase hex chars"
      when 'gcp-image-digest'
        value.match?(IMAGE_DIGEST) ? nil : 'gcp-image-digest must be sha256:<64 lowercase hex>'
      when 'nvidia-driver-version'
        value.match?(DRIVER_VERSION) && value.length <= 16 ? nil : 'nvidia-driver-version must be a dotted version of at most 16 chars'
      when 'maa-signing-spki'
        return 'maa-signing-spki must be 64 lowercase hex chars' unless value.match?(HEX64)

        label.match?(ISSUER_URL) ? nil : 'maa-signing-spki label must be the https issuer URL (no path, no trailing slash)'
      when 'maa-chain-root-spki', 'maa-chain-intermediate-spki'
        value.match?(HEX64) ? nil : "#{kind} must be 64 lowercase hex chars"
      when 'attest-corroboration'
        return 'attest-corroboration must be a 64 lowercase hex evidence digest' unless value.match?(HEX64)

        label.match?(CORROBORATION_LABEL) ? nil : 'attest-corroboration label must be vantages=<n>;method=<text>'
      end
    end

    # The canonical body of a manifest: exactly the known members, every value valid, entries unique. Raises TypeError with the first problem.
    def parse_body(x)
      raise TypeError, 'body must be an object with exactly version/issuedAt/notBefore/expiresAt/entries' unless record?(x) && only_keys?(x, BODY_KEYS)

      version = x['version']
      issued = x['issuedAt']
      not_before = x['notBefore']
      expires = x['expiresAt']
      entries = x['entries']
      raise TypeError, 'version must be a positive integer' unless Attestation.safe_int?(version) && version >= 1
      raise TypeError, 'issuedAt/notBefore/expiresAt must be integer epoch ms' unless epoch?(issued) && epoch?(not_before) && epoch?(expires)
      raise TypeError, 'notBefore must be before expiresAt' unless not_before < expires
      raise TypeError, 'issuedAt must not be after expiresAt' unless issued <= expires
      raise TypeError, 'entries must be an array (bounded)' unless entries.is_a?(Array) && entries.length <= MAX_ENTRIES

      seen = {}
      out = entries.each_with_index.map do |e, i|
        raise TypeError, "entry #{i}: unexpected shape" unless record?(e) && only_keys?(e, ENTRY_KEYS)

        kind = e['kind']
        value = e['value']
        label = e['label']
        raise TypeError, "entry #{i}: unknown kind" unless kind.is_a?(String) && ALLOWLIST_KINDS.include?(kind)
        raise TypeError, "entry #{i}: value and label must be strings" unless value.is_a?(String) && label.is_a?(String)
        raise TypeError, "entry #{i}: label must be 1..200 printable chars" if utf16(label) < 1 || utf16(label) > 200 || label.match?(/[\x00-\x1f\x7f]/)

        ve = value_error(kind, value, label)
        raise TypeError, "entry #{i}: #{ve}" if ve
        raise TypeError, "entry #{i}: notAfter must be integer epoch ms" if e.key?('notAfter') && !epoch?(e['notAfter'])
        raise TypeError, "entry #{i}: revoked, when present, must be true" if e.key?('revoked') && e['revoked'] != true

        dup_key = "#{kind}\0#{kind == 'maa-signing-spki' ? "#{label}\0" : ''}#{value}"
        raise TypeError, "entry #{i}: duplicate #{kind} value" if seen.key?(dup_key)

        seen[dup_key] = true
        row = { 'kind' => kind, 'value' => value, 'label' => label }
        row['notAfter'] = e['notAfter'] if e.key?('notAfter')
        row['revoked'] = true if e['revoked'] == true
        row
      end
      { 'version' => version, 'issuedAt' => issued, 'notBefore' => not_before, 'expiresAt' => expires, 'entries' => out }
    end

    def signed_bytes(body) = DOMAIN.b + AtlasPca.canon_bytes(body)
    def fail_with(code, reason) = { 'ok' => false, 'code' => code, 'reason' => reason }

    # The public keys of a registered issuer as the suite dispatch takes them: [Ed25519 public key or nil, the trusted PQ key or nil].
    def registered_suite_keys(alg, keys)
      raise TypeError, 'issuer keys are not an object' if keys.nil?

      k = keys.is_a?(Hash) ? keys : {}
      _len, needs_pk, _hy, prim, = SIG_SUITES[alg]
      pk = case prim
           when 'ML-DSA-65' then k['mlDsaPub']
           when 'SLH-DSA-SHA2-128f' then k['slhDsaPub']
           when 'ML-DSA-87' then k['mlDsa87Pub']
           when 'SLH-DSA-SHA2-256s' then k['slhDsa256sPub']
           when 'FN-DSA-512' then k['fnDsa512Pub']
           when 'FN-DSA-1024' then k['fnDsa1024Pub']
           else k['lessCat1Pub']
           end
      [k['edPub'], needs_pk && !pk.nil? ? AtlasPca.resolve_pq_key('', nil, trusted_pk: pk) : nil]
    end

    # Verify a signed manifest. `opts`: {'issuerKeys' => {issuer => {'alg', 'keys' => {edPub?, mlDsaPub?, slhDsaPub?, mlDsa87Pub?,
    # slhDsa256sPub?, ...}, 'notAfter'?}}, 'nowMs' (an integer), 'minVersion'?, 'lastSeenVersion'?, 'lastSeenDigest'?, 'clockSkewMs'?,
    # 'maxLifetimeMs'?}. Returns {'ok' => true, 'body', 'issuer', 'alg', 'version', 'digest'} or {'ok' => false, 'code', 'reason'} with the code
    # one of malformed, unknown-issuer, issuer-expired, alg-mismatch, bad-signature, not-yet-valid, expired, lifetime-too-long,
    # below-min-version, rollback, conflict. In that order; never raises. Numeric options are validated, never coerced: a NaN skew would make both
    # window comparisons false.
    def verify_allowlist_manifest(manifest, opts)
      return fail_with('malformed', 'manifest has an unexpected shape') unless record?(manifest) && only_keys?(manifest, MANIFEST_KEYS)

      o = opts.is_a?(Hash) ? opts : {}
      return fail_with('malformed', 'nowMs must be an integer') unless Attestation.safe_int?(o['nowMs'])

      now = o['nowMs']
      issuer = manifest['issuer']
      alg = manifest['alg']
      sig = manifest['sig']
      has_pq = manifest.key?('pq_sig')
      pq_sig = manifest['pq_sig']
      return fail_with('malformed', 'issuer must be a string') unless issuer.is_a?(String) && utf16(issuer) >= 1 && utf16(issuer) <= 200
      return fail_with('malformed', 'unknown signature alg') unless alg.is_a?(String) && REGISTERED_SUITES.include?(alg) && SIG_SUITES.key?(alg)
      return fail_with('malformed', 'sig must be a string') unless sig.is_a?(String)
      return fail_with('malformed', 'pq_sig must be a string') if has_pq && !pq_sig.is_a?(String)
      return fail_with('malformed', 'pq_sig presence does not match the suite') if SIG_SUITES[alg][2] != has_pq

      begin
        body = parse_body(manifest['body'])
      rescue StandardError => e
        return fail_with('malformed', e.message)
      end
      issuer_keys = o['issuerKeys']
      raise TypeError, 'issuerKeys is not an object' unless issuer_keys.is_a?(Hash)
      return fail_with('unknown-issuer', "issuer '#{issuer}' is not registered") unless issuer_keys.key?(issuer)

      reg = issuer_keys[issuer]
      raise TypeError, 'issuer registration is not an object' if reg.nil?

      r = reg.is_a?(Hash) ? reg : {}
      return fail_with('alg-mismatch', "issuer is registered for '#{Attestation.jstr(r.key?('alg') ? r['alg'] : Attestation::UNDEF)}', manifest claims '#{alg}'") unless r['alg'] == alg

      if r.key?('notAfter')
        na = r['notAfter'].nil? ? 0 : r['notAfter']
        return fail_with('issuer-expired', 'issuer key is past its notAfter') if na.is_a?(Numeric) && !(now <= na)
      end
      ed_pub, pq = registered_suite_keys(alg, r['keys'])
      parts = { 'alg' => alg, 'sig' => sig }
      parts['pq_sig'] = pq_sig if has_pq
      unless AtlasPca.verify_suite(parts, ed_pub, signed_bytes(body), pq)
        return fail_with('bad-signature', 'signature does not verify under the registered issuer key')
      end

      # signature is good: the rest is policy over authentic content
      return fail_with('malformed', 'clockSkewMs must be a finite number') if o.key?('clockSkewMs') && !Attestation.finite?(o['clockSkewMs'])
      return fail_with('malformed', 'maxLifetimeMs must be a finite number') if o.key?('maxLifetimeMs') && !Attestation.finite?(o['maxLifetimeMs'])
      return fail_with('malformed', 'minVersion must be an integer') if o.key?('minVersion') && !Attestation.safe_int?(o['minVersion'])
      return fail_with('malformed', 'lastSeenVersion must be an integer') if o.key?('lastSeenVersion') && !Attestation.safe_int?(o['lastSeenVersion'])

      skew = o.key?('clockSkewMs') ? [0, o['clockSkewMs']].max : 0
      return fail_with('not-yet-valid', 'manifest is not yet valid') if now + skew < body['notBefore']
      return fail_with('expired', 'manifest has expired') if now - skew > body['expiresAt']
      if o.key?('maxLifetimeMs') && body['expiresAt'] - body['notBefore'] > o['maxLifetimeMs']
        return fail_with('lifetime-too-long', 'manifest lifetime exceeds maxLifetimeMs')
      end
      return fail_with('below-min-version', "version #{body['version']} < minVersion #{o['minVersion']}") if o.key?('minVersion') && body['version'] < o['minVersion']

      digest = AtlasPca.hash_canonical(body)
      if o.key?('lastSeenVersion')
        last = o['lastSeenVersion']
        return fail_with('rollback', "version #{body['version']} is older than last seen #{last}") if body['version'] < last
        if body['version'] == last && o.key?('lastSeenDigest') && o['lastSeenDigest'] != digest
          return fail_with('conflict', 'same version as last seen but a different body')
        end
      end
      { 'ok' => true, 'body' => body, 'issuer' => issuer, 'alg' => alg, 'version' => body['version'], 'digest' => digest }
    rescue StandardError => e
      fail_with('malformed', e.message)
    end

    # ---- the durable verification: the highest accepted {version, digest} per issuer at kv key `allowlist/<issuer>` ----

    # {version, digest} of a stored high-water mark, nil when it is anything else.
    def parse_high_water(x)
      return nil unless record?(x) && Attestation.safe_int?(x['version']) && !(x['version'].is_a?(Float) && x['version'].zero? && (1.0 / x['version']).negative?)
      return nil unless x['digest'].is_a?(String) && x['digest'].match?(B64U_DIGEST)

      { version: x['version'], digest: x['digest'] }
    end

    # The updater of the store: a record whose version is already >= ours (or a corrupt one) is kept as it is.
    def update_state(cur, version, digest)
      return cur if cur[0] == :corrupt
      return cur if cur[0] == :val && cur[1] >= version

      [:val, version, digest]
    end

    # `kv` answers get(key) (nil when absent) and update(key) { |current| next value or nil } -> the value now stored (the DurableState
    # contract; a store that also answers keys is asked whether a key whose value reads nil holds a stored null, which is corrupt). A
    # manifest that does not verify against the stored mark, or whose acceptance was not recorded, is refused; the state is written only on success.
    def verify_allowlist_durable(manifest, opts, kv)
      issuer = record?(manifest) && manifest['issuer'].is_a?(String) && utf16(manifest['issuer']) <= 200 ? manifest['issuer'] : nil
      return fail_with('malformed', 'issuer must be a string') if issuer.nil?

      key = "allowlist/#{issuer}"
      raw = kv.get(key)
      raw = :null_stored if raw.nil? && kv.respond_to?(:keys) && kv.keys.include?(key)
      prior = raw.nil? ? nil : parse_high_water(raw)
      read = raw.nil? ? [:missing] : (prior.nil? ? [:corrupt] : [:val, prior[:version], prior[:digest]])
      return fail_with('malformed', 'persisted allowlist high-water mark is corrupt') if read[0] == :corrupt

      o = (opts.is_a?(Hash) ? opts : {}).dup
      o['lastSeenVersion'] = prior[:version] if prior
      o['lastSeenDigest'] = prior[:digest] if prior
      v = verify_allowlist_manifest(manifest, o)
      return v unless v['ok']

      now_kv = nil
      stored = kv.update(key) do |cur|
        c = cur.nil? ? nil : parse_high_water(cur)
        now_kv = cur.nil? ? [:missing] : (c.nil? ? [:corrupt] : [:val, c[:version], c[:digest]])
        nxt = update_state(now_kv, v['version'], v['digest'])
        nxt[0] == :val && nxt != now_kv ? { 'version' => v['version'], 'digest' => v['digest'] } : nil
      end
      if now_kv.nil?
        # the store answered without running the updater: the returned record is the record at update time
        s = stored.nil? ? nil : parse_high_water(stored)
        return fail_with('rollback', 'a newer manifest was accepted concurrently') if s.nil?

        now_kv = [:val, s[:version], s[:digest]]
      end
      after = update_state(now_kv, v['version'], v['digest'])
      return fail_with('rollback', 'a newer manifest was accepted concurrently') if after[0] != :val || after[1] > v['version']
      return fail_with('conflict', 'same version as the stored high-water mark but a different body') if after[1] == v['version'] && after[2] != v['digest']

      v
    rescue StandardError => e
      fail_with('malformed', e.message)
    end

    # ---- build ----

    # The validated copy of a manifest body (raises TypeError on any violation).
    def create_allowlist_manifest(input) = parse_body(input)

    # Sign a body (validated first) under `alg`: `ed` the issuer's Ed25519 KeyPair, `pq` its PQ key pair (ml-dsa-65 / ml-dsa-87 and the
    # hybrids). Raises on an invalid body, an unknown suite or missing key material.
    def sign_allowlist_manifest(body, issuer:, alg:, ed: nil, pq: nil)
      clean = parse_body(body)
      sig, pq_sig = AtlasPca.sign_with_suite(alg, ed, pq, signed_bytes(clean))
      out = { 'body' => clean, 'issuer' => issuer, 'alg' => alg, 'sig' => sig }
      out['pq_sig'] = pq_sig unless pq_sig.nil?
      out
    end

    # The next version of a body with one entry revoked (a tombstone when it is not listed; an MAA signing key is matched by value AND label).
    # `rev`: {'kind', 'value', 'label'?}; `times`: {'issuedAt', 'notBefore', 'expiresAt'}. Raises when the result is invalid.
    def revoke_allowlist_entry(prev, rev, times)
      entries = prev['entries'].map(&:dup)
      hit = entries.find { |e| e['kind'] == rev['kind'] && e['value'] == rev['value'] && (rev['kind'] != 'maa-signing-spki' || e['label'] == rev['label']) }
      if hit
        hit['revoked'] = true
      else
        entries << { 'kind' => rev['kind'], 'value' => rev['value'], 'label' => rev['label'].nil? ? 'revoked' : rev['label'], 'revoked' => true }
      end
      parse_body({ 'version' => prev['version'] + 1 }.merge(times).merge('entries' => entries))
    end

    # The 32-hex-character slot of an NVIDIA driver version (its ASCII hex, zero padded). Raises on anything but a dotted version.
    def driver_version_slot_hex(version)
      raise TypeError, 'invalid driver version' unless version.is_a?(String) && version.match?(DRIVER_VERSION) && version.length <= 16

      version.b.unpack1('H*').ljust(32, '0')
    end

    # ---- projection ----

    # The lists of a verified manifest at `now_ms`: revoked entries (and every entry sharing a revoked kind and value) and entries past their
    # own notAfter are listed apart and left out of the allowlists.
    def project_allowlist(verified, now_ms:)
      body = verified['body']
      out = { 'tdxMrtds' => [], 'tdxRtmrs' => [], 'sevSnpMeasurements' => [], 'imageDigests' => [], 'nvidiaMeasurements' => [],
              'nvidiaDriverVersions' => [], 'nvidiaCcDriverVersions' => [], 'maaSigningSpkis' => {}, 'maaChainRootSpkis' => [],
              'maaChainIntermediateSpkis' => [], 'corroboration' => [], 'revoked' => [], 'expired' => [], 'version' => body['version'],
              'manifestExpiresAt' => body['expiresAt'] }
      denied = {}
      body['entries'].each do |e|
        next unless e['revoked'] == true

        denied["#{e['kind']}\0#{e['value']}"] = true
        out['revoked'] << { 'kind' => e['kind'], 'value' => e['value'], 'label' => e['label'] }
      end
      body['entries'].each do |e|
        next if e['revoked'] == true || denied.key?("#{e['kind']}\0#{e['value']}")

        if e.key?('notAfter') && !(Js.num?(now_ms) && now_ms.to_f.finite? && now_ms <= e['notAfter'])
          out['expired'] << { 'kind' => e['kind'], 'value' => e['value'], 'label' => e['label'] }
          next
        end
        case e['kind']
        when 'tdx-mrtd' then out['tdxMrtds'] << e['value']
        when 'tdx-rtmr' then out['tdxRtmrs'] << e['value']
        when 'sev-snp-measurement' then out['sevSnpMeasurements'] << e['value']
        when 'gcp-image-digest' then out['imageDigests'] << e['value']
        when 'nvidia-measurement' then out['nvidiaMeasurements'] << e['value']
        when 'nvidia-driver-version'
          out['nvidiaDriverVersions'] << e['value']
          out['nvidiaCcDriverVersions'] << driver_version_slot_hex(e['value'])
        when 'maa-signing-spki' then (out['maaSigningSpkis'][e['label']] ||= []) << e['value']
        when 'maa-chain-root-spki' then out['maaChainRootSpkis'] << e['value']
        when 'maa-chain-intermediate-spki' then out['maaChainIntermediateSpkis'] << e['value']
        when 'attest-corroboration' then out['corroboration'] << { 'value' => e['value'], 'label' => e['label'] }
        end
      end
      out
    end

    def azure_maa_policy_fields(p)
      out = {}
      out['tdxMrtds'] = p['tdxMrtds'].dup unless p['tdxMrtds'].empty?
      out['sevSnpMeasurements'] = p['sevSnpMeasurements'].dup unless p['sevSnpMeasurements'].empty?
      out['tdxRtmrs'] = p['tdxRtmrs'].dup unless p['tdxRtmrs'].empty?
      out
    end

    def intel_dcap_policy_fields(p)
      out = { 'mrtds' => p['tdxMrtds'].dup }
      out['rtmrs'] = p['tdxRtmrs'].dup unless p['tdxRtmrs'].empty?
      out
    end

    def sev_snp_policy_fields(p) = { 'measurements' => p['sevSnpMeasurements'].dup }
    def gcp_cs_policy_fields(p) = { 'imageDigests' => p['imageDigests'].dup }

    def nvidia_cc_policy_fields(p)
      out = { 'measurements' => p['nvidiaMeasurements'].dup }
      out['driverVersions'] = p['nvidiaCcDriverVersions'].dup unless p['nvidiaCcDriverVersions'].empty?
      out
    end
  end

  # The transparency anchor of allowlist manifests (the reference's `attest-allowlist-anchor`): an operator keeps an append-only log of the
  # {issuer, version, digest} of every manifest it anchors and signs the log head; a verifier that pins the log key checks the evidence (the
  # head, the entries, the inclusion proof, optionally the consistency proof from a head it cached) for a manifest it has ALREADY verified:
  # the manifest must be in the log, no later version of its issuer may be anchored (a rollback), and the log must never show two digests for
  # one version (a split). Detection and attribution, not prevention.
  module AttestAllowlistAnchor
    ANCHOR_DOMAIN = 'pca-attest-allowlist-anchor/v1'
    MAX_FEED = 100_000
    DAY = 86_400_000

    module_function

    def entry?(e)
      e.is_a?(Hash) && e.length == 3 && e['issuer'].is_a?(String) && SafeRegex.utf16_len(e['issuer']).between?(1, 200) &&
        Attestation.safe_int?(e['version']) && e['version'] >= 1 && e['digest'].is_a?(String) && e['digest'].match?(AttestAllowlist::B64U_DIGEST)
    end

    # The leaf the log stores for an entry.
    def allowlist_anchor_commit(e)
      g = ->(k) { e.is_a?(Hash) && e.key?(k) ? e[k] : Attestation::UNDEF }
      AtlasPca.hash_canonical({ 'domain' => ANCHOR_DOMAIN, 'issuer' => g.call('issuer'), 'version' => g.call('version'), 'digest' => g.call('digest') })
    end

    # {issuer, version, digest} of a verified manifest.
    def anchor_entry_of(v) = { 'issuer' => v['issuer'], 'version' => v['version'], 'digest' => v['digest'] }

    # ---- the operator side ----

    class Log
      attr_reader :ledger, :instance_id, :principal
      attr_accessor :latest_head

      def initialize(instance_id, principal)
        @ledger = AtlasPca::TransparencyLedger.new(principal)
        @instance_id = instance_id
        @principal = principal
        @entries = []
        @latest_head = nil
      end

      def entries = @entries.map(&:dup)
      def latest = @latest_head
      def raw_entries = @entries
    end

    def create_allowlist_anchor_log(instance_id:, principal:) = Log.new(instance_id, principal)

    def sign_head(log, guardian, now_ms, alg, pq)
      h = log.ledger.head
      sth = AtlasPca.sign_tree_head(guardian, { 'instance_id' => log.instance_id, 'principal' => log.principal, 'size' => h['size'], 'root' => h['root'],
                                                 'prev_root' => log.latest_head.nil? ? '' : log.latest_head['root'], 'timestamp' => now_ms },
                                    alg: alg, pq: pq)
      log.latest_head = sth
    end

    # The evidence for the entry at `index`: the latest head, every entry, the inclusion proof and, for a cached head older than the latest, the
    # consistency proof from it. Raises when the log has no signed head or the index is out of range.
    def evidence_for(log, index, cached = nil)
      raise 'evidenceFor: log has no signed head' if log.latest_head.nil?

      out = { 'head' => log.latest_head, 'entries' => log.entries, 'proof' => log.ledger.inclusion_proof(index) }
      if cached.is_a?(Hash) && cached['size'].is_a?(Numeric) && cached['size'].positive? && cached['size'] < log.latest_head['size']
        out['consistency'] = log.ledger.consistency_proof(cached['size'], log.latest_head['size'])
      end
      out
    end

    # Anchor an entry ({issuer, version, digest}, or a verified manifest result) and sign the new head with `guardian` (a KeyPair; `alg` and
    # `pq` for a post-quantum head). The same version anchored again with the same digest is idempotent; another digest for it, or a version
    # lower than one already anchored for the issuer, raises. Returns the evidence for the entry.
    def anchor_allowlist_head(log, what, guardian:, now_ms:, alg: nil, pq: nil)
      raise TypeError, 'anchorAllowlistHead: malformed entry' unless what.is_a?(Hash)

      entry = what.key?('body') ? anchor_entry_of(what) : what.dup
      raise TypeError, 'anchorAllowlistHead: malformed entry' unless entry?(entry)

      entries = log.raw_entries
      same = entries.index { |e| e['issuer'] == entry['issuer'] && e['version'] == entry['version'] }
      if same
        raise 'anchorAllowlistHead: this version is already anchored with a different digest' if entries[same]['digest'] != entry['digest']

        index = same
      else
        max = entries.select { |e| e['issuer'] == entry['issuer'] }.map { |e| e['version'] }.max || 0
        raise "anchorAllowlistHead: version #{entry['version']} is lower than the anchored #{max}" if entry['version'] < max

        index = log.ledger.append_commitment(allowlist_anchor_commit(entry))['index']
        entries << entry
        sign_head(log, guardian, now_ms, alg, pq)
      end
      sign_head(log, guardian, now_ms, alg, pq) if log.latest_head.nil?
      evidence_for(log, index)
    end

    # Re-sign the current head with a new timestamp (freshness for the verifiers). Raises when nothing is anchored yet.
    def refresh_anchor_head(log, guardian:, now_ms:, alg: nil, pq: nil)
      raise 'refreshAnchorHead: nothing anchored yet' if log.ledger.size.zero?

      sign_head(log, guardian, now_ms, alg, pq)
    end

    # ---- the verifier side ----

    # Verify the anchor evidence of an already verified manifest `verified` ({issuer, version, digest, ...}). `opts`: {'trust' => {'logKey',
    # 'instanceId', 'principal', 'witnesses'?, 'pqPins'?}, 'nowMs', 'maxHeadAgeMs'? (default one day), 'clockSkewMs'? (default 60 s),
    # 'cachedHead'?}. Returns {'ok' => true, 'issuer', 'version', 'digest', 'highestAnchoredVersion', 'head'} or {'ok' => false, 'code'
    # (missing-proof, bad-head, stale-head, bad-cache, log-rollback, split-view, inconsistent-with-cache, feed-mismatch, bad-proof,
    # not-anchored, anchored-rollback, log-conflict), 'reason'}. Missing evidence is a refusal, never a pass; never raises.
    def verify_allowlist_anchored(verified, evidence, opts)
      no = ->(code, reason) { { 'ok' => false, 'code' => code, 'reason' => reason } }
      unless evidence.is_a?(Hash) && evidence.key?('proof') && evidence.key?('head') && evidence['entries'].is_a?(Array)
        return no.call('missing-proof', 'no anchor evidence (head + entries + inclusion proof) supplied')
      end

      o = opts.is_a?(Hash) ? opts : {}
      trust = o['trust']
      return no.call('bad-head', 'nowMs must be an integer') unless Attestation.safe_int?(o['nowMs'])

      now = o['nowMs']
      head = evidence['head']
      pins = trust['pqPins']
      unless AtlasPca.verify_tree_head(head, trust['logKey'], trust['witnesses'], pins)
        return no.call('bad-head', 'tree head is not signed by the pinned log key (or lacks the required witness cosignatures)')
      end
      return no.call('bad-head', 'tree head is for a different log') if head['instance_id'] != trust['instanceId'] || head['principal'] != trust['principal']

      skew_ok = !o.key?('clockSkewMs') || Attestation.finite?(o['clockSkewMs'])
      age_ok = !o.key?('maxHeadAgeMs') || Attestation.finite?(o['maxHeadAgeMs'])
      return no.call('bad-head', skew_ok ? 'maxHeadAgeMs must be a finite number' : 'clockSkewMs must be a finite number') unless skew_ok && age_ok

      skew = [0, o.key?('clockSkewMs') ? o['clockSkewMs'] : 60_000].max
      max_age = o.key?('maxHeadAgeMs') ? o['maxHeadAgeMs'] : DAY
      return no.call('stale-head', 'tree head is timestamped in the future') unless Attestation.safe_int?(head['timestamp'])
      return no.call('stale-head', 'tree head is timestamped in the future') unless head['timestamp'] <= now + skew
      return no.call('stale-head', "tree head is older than maxHeadAgeMs (#{Attestation.jstr(max_age)})") unless now - head['timestamp'] <= max_age

      cached = o['cachedHead']
      unless cached.nil?
        if !AtlasPca.verify_tree_head(cached, trust['logKey'], trust['witnesses'], pins) || cached['instance_id'] != trust['instanceId'] ||
           cached['principal'] != trust['principal']
          return no.call('bad-cache', 'the cached head does not verify under the pinned log key')
        end
        return no.call('log-rollback', "head size #{head['size']} < cached #{cached['size']}: the log shrank") if head['size'] < cached['size']
        if head['size'] == cached['size'] && head['root'] != cached['root']
          return no.call('split-view', 'two different roots at the same size: split view / fork')
        end
        if head['size'] > cached['size']
          c = evidence['consistency']
          if c.nil? || !AtlasPca.verify_head_consistency(cached, head, c, trust['logKey'], trust['witnesses'], pins)
            return no.call('inconsistent-with-cache', 'no valid consistency proof from the cached head: forked or truncated log')
          end
        end
      end

      entries = evidence['entries']
      return no.call('feed-mismatch', 'entries do not match the signed tree size') if entries.length > MAX_FEED || entries.length != head['size'] || !entries.all? { |e| entry?(e) }

      commits = entries.map { |e| allowlist_anchor_commit(e) }
      return no.call('feed-mismatch', 'entries do not reproduce the signed root') if AtlasPca.ledger_root_of(commits) != head['root']

      mine = { 'issuer' => verified['issuer'], 'version' => verified['version'], 'digest' => verified['digest'] }
      mine_entries = entries.select { |e| e['issuer'] == mine['issuer'] }
      by_version = {}
      mine_entries.each do |e|
        prior = by_version[e['version']]
        return no.call('log-conflict', "log anchors two different digests for version #{e['version']}") if !prior.nil? && prior != e['digest']

        by_version[e['version']] = e['digest']
      end
      highest = mine_entries.map { |e| e['version'] }.max || 0
      proof = evidence['proof']
      raise TypeError, 'the inclusion proof is null' if proof.nil?
      return no.call('bad-proof', 'inclusion proof size does not match the signed head size') if !proof.is_a?(Hash) || proof['size'] != head['size']
      return no.call('bad-proof', 'inclusion proof does not place this manifest under the signed root') unless AtlasPca.verify_ledger_inclusion(head['root'], proof, allowlist_anchor_commit(mine))
      return no.call('anchored-rollback', "manifest version #{mine['version']} < highest anchored #{highest} for '#{mine['issuer']}'") if mine['version'] < highest
      return no.call('not-anchored', 'this manifest digest is not the one anchored for its version') unless by_version[mine['version']] == mine['digest']

      { 'ok' => true, 'issuer' => mine['issuer'], 'version' => mine['version'], 'digest' => mine['digest'], 'highestAnchoredVersion' => highest,
        'head' => head }
    rescue StandardError => e
      no.call('bad-head', e.message)
    end
  end
end
