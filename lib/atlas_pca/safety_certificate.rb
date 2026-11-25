# frozen_string_literal: true

module AtlasPca
  # Domain separation of the guardian signature over a safety certificate.
  SAFETY_CERT_DOMAIN = "atlas-pca/safety-cert/v1\0"
  SAFETY_CERT_VERSION = 1
  # The only thing the arithmetic bound speaks about.
  SAFETY_CERT_SCOPE = 'risk-budget-bound'
  MAX_SAFETY_CHECKS = 64

  # A signed, machine-readable statement of the risk-budget bound of a grant (the reference's `safety-certificate` module): from a
  # `risk_policy` it derives the bound bMax / kappa (the most risk autonomous actions can add up to between two human co-signs), a
  # human statement and optional check rows (which checks ran, each with an evidence link), signed by the guardian under the
  # Ed25519, ML-DSA-65 or hybrid suite. The verifier never trusts the stated number: it recomputes the bound from the certificate's
  # own parameters and checks the guardian signature over exactly those parameters. It is not a claim that the agent or the system
  # is safe, and the evidence behind a check row is neither fetched nor judged.
  # Records are String-keyed Hashes with the reference's wire members. Issuing raises; verifying never raises.
  module SafetyCertificate
    MAX_CHECK_ID = 64
    MAX_EVIDENCE_URL = 2048
    CHECK_STATUSES = %w[passed failed not_run].freeze
    # the verifier options under their Ruby spelling (the reference's member names are taken as they are)
    OPTION_NAMES = { 'require_checks' => 'requireChecks', 'max_age_ms' => 'maxAgeMs', 'pq_pins' => 'pqPins' }.freeze

    module_function

    def fin?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite?)

    # a safe integer by value (an integral Float counts, negative zero does not), >= 0
    def check_time?(x)
      return x >= 0 && x <= MAX_SAFE if x.is_a?(Integer)

      x.is_a?(Float) && x.finite? && x == x.floor && x <= MAX_SAFE && (x.positive? || (x.zero? && (1.0 / x).positive?))
    end

    # An evidence URL the platform URL parser accepts, with the https scheme and an empty user name and password.
    def plain_https_url?(ref)
      return false if SafeRegex.utf16_len(ref) > MAX_EVIDENCE_URL

      u = WhatwgUrl.parse(ref)
      return false if u.nil? || u['scheme'] != 'https'

      s = ref.scrub.sub(/\A[\x00-\x20]+/, '').delete("\t\n\r")
      authority = s.sub(/\A[^:]*:/, '').sub(/[?#].*\z/m, '').sub(%r{\A[/\\]+}, '')[%r{\A[^/\\]*}]
      # the user name is what stands before the first ':' of the userinfo, the password what follows it
      !authority.include?('@') || ['', ':'].include?(authority.rpartition('@')[0])
    end

    # nil when the check rows are well formed, else the first problem.
    def validate_safety_checks(checks)
      return 'checks must be an array' unless checks.is_a?(Array)
      return "more than #{MAX_SAFETY_CHECKS} checks" if checks.length > MAX_SAFETY_CHECKS

      seen = {}
      checks.each do |c|
        return 'check is not an object' unless c.is_a?(Hash) || c.is_a?(Array)

        k = c.is_a?(Hash) ? c : {} # an array is an object in the reference: every member reads as absent
        id = k['id']
        return 'check id must be a 1..64 char string' unless id.is_a?(String) && !id.empty? && SafeRegex.utf16_len(id) <= MAX_CHECK_ID
        return "duplicate check id '#{id}'" if seen.key?(id)

        seen[id] = true
        return "check '#{id}' has an invalid status" unless CHECK_STATUSES.include?(k['status'])
        return "check '#{id}' has an invalid time" unless check_time?(k['at'])

        e = k['evidence']
        e = {} if e.is_a?(Array)
        return "check '#{id}' has no evidence link" unless e.is_a?(Hash) && e['ref'].is_a?(String)

        case e['kind']
        when 'sha256'
          return "check '#{id}' evidence digest is not 64 lowercase hex" unless e['ref'].match?(/\A[0-9a-f]{64}\z/)
        when 'url'
          return "check '#{id}' evidence URL must be a plain https URL" unless plain_https_url?(e['ref'])
        else
          return "check '#{id}' has an invalid evidence kind"
        end
      end
      nil
    end

    # The bound of a policy: max(0, bMax) / kappa, and 0 when kappa is not above 0. A NaN bMax gives NaN, as in the reference.
    def safety_certificate_bound(p)
      kappa = p['kappa']
      return 0 unless kappa.is_a?(Numeric) && kappa.positive? # false for NaN

      b = p['bMax']
      return Float::NAN unless b.is_a?(Numeric) && !(b.is_a?(Float) && b.nan?)

      (b.negative? ? 0 : b) / kappa.to_f
    end

    # The human-readable statement of the bound (advisory; the machine fields are authoritative).
    def safety_certificate_statement(bound)
      'Arithmetic consequence of the signed risk parameters: between two consecutive human co-signs, the total risk of autonomous ' \
        "actions Σ r(Aᵢ) ≤ #{Predicates.js_number_string(bound)} (= B_max / κ). This is not a claim that the agent or the system is safe."
    end

    # The bytes the guardian signs: the domain, then the canonical claim (the certificate without `sig` and `pq_sig`).
    def safety_certificate_message(cert)
      SAFETY_CERT_DOMAIN.b + AtlasPca.canonical_bytes_lenient(cert.reject { |k, _| %w[sig pq_sig].include?(k) })
    end

    def known_alg?(alg) = alg.is_a?(String) && REGISTERED_SUITES.include?(alg)

    # Issue a signed safety certificate for a grant's `risk_policy`. `guardian` is the guardian's KeyPair; `checks` the rows that ran
    # (validated); `issued_at` epoch milliseconds (default: now); `alg` the suite (default ed25519) and `pq` its PQ key pair
    # (ml-dsa-65 and the hybrid: a PqKeyPair of ML-DSA-65). Raises ArgumentError on a malformed policy, check list or suite.
    def issue_safety_certificate(policy:, guardian:, grant_ref: nil, instance: nil, checks: nil, issued_at: nil, alg: nil, pq: nil)
      bad = AtlasPca.validate_risk_policy(policy)
      raise ArgumentError, "issueSafetyCertificate: #{bad}" if bad
      raise ArgumentError, "issueSafetyCertificate: unknown signature alg '#{alg}'" unless alg.nil? || known_alg?(alg)

      unless checks.nil?
        bad = validate_safety_checks(checks)
        raise ArgumentError, "issueSafetyCertificate: #{bad}" if bad
      end
      bound = safety_certificate_bound(policy)
      claim = { 'v' => SAFETY_CERT_VERSION, 'statement' => safety_certificate_statement(bound), 'scope' => SAFETY_CERT_SCOPE }
      unless checks.nil?
        claim['checks'] = checks.map do |c|
          { 'id' => c['id'], 'status' => c['status'], 'evidence' => { 'kind' => c['evidence']['kind'], 'ref' => c['evidence']['ref'] }, 'at' => c['at'] }
        end
      end
      claim['params'] = %w[bMax kappa theta1 theta2 lambda rho].to_h { |k| [k, policy[k]] }.merge('weights' => policy['weights'].dup)
      claim['bound'] = bound
      claim['blastRadiusPerCheckpoint'] = bound
      claim['grant_ref'] = grant_ref unless grant_ref.nil?
      claim['instance'] = instance unless instance.nil?
      claim['issued_at'] = issued_at.nil? ? (Time.now.to_f * 1000).floor : issued_at
      claim['guardian'] = guardian.public
      unless alg.nil? || alg == 'ed25519'
        # the suite and the guardian's PQ key are signed with the claim: a downgrade or a key swap breaks the signature
        raise ArgumentError, "issueSafetyCertificate: #{alg} needs its PQ key pair" unless pq.respond_to?(:public)

        claim = claim.merge('alg' => alg, 'pq_pk' => pq.public)
      end
      sig, pq_sig = AtlasPca.sign_with_suite(alg, guardian, pq, safety_certificate_message(claim))
      out = claim.merge('sig' => sig)
      out['pq_sig'] = pq_sig unless pq_sig.nil?
      out
    end

    def refused(reason, extra = {}) = { 'ok' => false, 'reason' => reason }.merge(extra)

    # The guardian signature under the certificate's suite: Ed25519 under `guardian`; any other suite only under a PQ key pinned
    # for the guardian (`pqPins[guardian]` must equal the certificate's `pq_pk`). A certificate's own key is never enough.
    def signature_ok?(cert, pins)
      p = { 'sig' => cert['sig'] }
      p['alg'] = cert['alg'] if cert.key?('alg')
      p['pq_sig'] = cert['pq_sig'] if cert.key?('pq_sig')
      pq = nil
      if cert.key?('alg') && cert['alg'] != 'ed25519'
        pq = AtlasPca.resolve_pq_key(cert['guardian'], cert['pq_pk'], pq_pins: pins)
        return false if pq.nil?
      end
      AtlasPca.verify_suite(p, cert['guardian'], safety_certificate_message(cert), pq)
    end

    # Verify a safety certificate. Never raises. In order: shape, scope, the check rows and the parameters; the stated bound and
    # blastRadiusPerCheckpoint against the bound RECOMPUTED from the parameters; the pinned guardian; the guardian signature; then
    # the policy options (after the signature, so an unsigned certificate never learns which check was missing).
    # `opts`: 'guardian' (the pinned guardian key), 'requireChecks' (ids that must be present with status passed), 'maxAgeMs' with
    # 'now' (refuses an older certificate and one issued in the future), 'pqPins' ({guardian => PQ public key}); the snake_case
    # spellings are taken too. Returns {'ok', 'reason'?, 'recomputedBound'?}.
    def verify_safety_certificate(cert, opts = nil)
      o = opts.is_a?(Hash) ? opts.to_h { |k, v| [OPTION_NAMES.fetch(k.to_s, k.to_s), v] } : {}
      return refused('malformed certificate') unless cert.is_a?(Hash) && cert['v'].is_a?(Numeric) && cert['v'] == SAFETY_CERT_VERSION
      return refused('missing guardian/signature') unless cert['sig'].is_a?(String) && cert['guardian'].is_a?(String)
      return refused('unknown scope') unless cert['scope'] == SAFETY_CERT_SCOPE

      if cert.key?('checks')
        bad = validate_safety_checks(cert['checks'])
        return refused("invalid checks: #{bad}") if bad
      end
      params = cert['params'].is_a?(Hash) ? cert['params'] : {}
      bad = AtlasPca.validate_risk_policy(params)
      return refused("invalid parameters: #{bad}") if bad

      bound = safety_certificate_bound(params)
      with = { 'recomputedBound' => bound }
      unless fin?(cert['bound']) && cert['bound'] == bound
        return refused('stated bound does not equal B_max/κ recomputed from the parameters', with)
      end
      unless cert['blastRadiusPerCheckpoint'].is_a?(Numeric) && cert['blastRadiusPerCheckpoint'] == bound
        return refused('blastRadiusPerCheckpoint does not equal the recomputed bound', with)
      end
      return refused('guardian key is not the pinned key', with) if o.key?('guardian') && o['guardian'] != cert['guardian']
      return refused('unknown signature alg', with) if cert.key?('alg') && !known_alg?(cert['alg'])
      return refused('guardian signature does not verify', with) unless signature_ok?(cert, o['pqPins'])

      if o.key?('maxAgeMs')
        now = o['now'].nil? ? (Time.now.to_f * 1000).floor : o['now']
        issued = cert['issued_at']
        return refused('invalid age policy or issue time', with) unless fin?(o['maxAgeMs']) && fin?(now) && fin?(issued)
        return refused('certificate is issued in the future', with) if issued > now
        return refused('certificate is older than maxAgeMs', with) if now - issued > o['maxAgeMs']
      end
      required = o['requireChecks'].nil? ? [] : o['requireChecks']
      (required.is_a?(String) ? required.chars : required).each do |id|
        c = cert['checks']&.find { |k| k['id'] == id }
        return refused("required check '#{id}' is not present", with) if c.nil?
        return refused("required check '#{id}' is #{c['status']}", with) unless c['status'] == 'passed'
      end
      { 'ok' => true, 'recomputedBound' => bound }
    rescue StandardError => e
      refused("malformed certificate: #{e.message}")
    end

    # The certificate as a canonical JSON string.
    def encode_safety_certificate(cert) = AtlasPca.canonicalize_lenient_server_only(cert)

    # A certificate from its JSON string, or nil for anything that is not one: shape-guarded (version, `sig`, `guardian`, `params`)
    # and bounded at MAX_JSON_BYTES. Never raises. Nothing is verified here.
    def decode_safety_certificate(text)
      return nil unless text.is_a?(String) && text.bytesize <= MAX_JSON_BYTES

      v = JsonParser.new(text, true, true, json_text: true).parse_document
      return nil unless v.is_a?(Hash)
      return nil unless v['v'].is_a?(Numeric) && v['v'] == SAFETY_CERT_VERSION && v['sig'].is_a?(String) && v['guardian'].is_a?(String)
      return nil unless v['params'].is_a?(Hash) || v['params'].is_a?(Array)

      v
    rescue StandardError, SystemStackError
      nil
    end

    # The compliance-export row of a certificate that verifies under `opts` (those of verify_safety_certificate): which checks ran
    # and where their evidence is. nil when it does not verify. Not a safety claim.
    def safety_certificate_for_compliance(cert, opts = nil)
      return nil unless verify_safety_certificate(cert, opts)['ok']

      { 'control' => SAFETY_CERT_SCOPE, 'guardian' => cert['guardian'], 'issued_at' => cert['issued_at'], 'bound' => cert['bound'],
        'checks' => (cert['checks'] || []).map do |c|
          e = c['evidence']
          { 'id' => c['id'], 'status' => c['status'], 'evidence' => e['kind'] == 'sha256' ? "sha256:#{e['ref']}" : e['ref'] }
        end }
    end
  end
end
