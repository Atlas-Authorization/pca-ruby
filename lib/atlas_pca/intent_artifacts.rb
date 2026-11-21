# frozen_string_literal: true

module AtlasPca
  # The shared strict-artifact helpers of the intent modules (the reference's `intent-artifacts`) with their JavaScript value semantics: a path segment
  # is tested on its string form, `isPlainObject` is a JSON object that is not an array, a scalar is a string, a boolean or a safe integer, a
  # closed-members check names the first violation, a signed artifact is `domain || strict canonical JSON(body)` under the Ed25519 / ML-DSA-65 /
  # hybrid suites and verifies only under a pinned signer (a PQ key only as pinned). Records are String-keyed Hashes.
  module IntentArtifacts
    UNDEF = IntentV2::UNDEF
    INTENT_NAME_RE_SOURCE = '^[a-z][a-z0-9_]{0,63}$'
    DATA_CLASS_RE_SOURCE = '^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$'
    PARAM_SEGMENT_RE_SOURCE = '^[A-Za-z0-9_-]{1,64}$'
    PARAM_SEGMENT_RE = /\A[A-Za-z0-9_-]{1,64}\z/n
    FORBIDDEN_SEGMENTS = %w[__proto__ constructor prototype].freeze
    SUITE_MEMBERS = %w[alg pq_pk pq_sig].freeze
    PARAM_PREFIX = 'action.params.'

    module_function

    def pm(h, k) = h.is_a?(Hash) && h.key?(k) ? h[k] : UNDEF
    def nullish?(x) = x.nil? || UNDEF.equal?(x)

    def path_segment?(s)
      str = Attestation.jstr(s)
      PARAM_SEGMENT_RE.match?(str.b) && !FORBIDDEN_SEGMENTS.include?(str)
    end

    def plain_object?(v) = v.is_a?(Hash)

    def safe_int?(v) = Attestation.safe_int?(v) && !(v.is_a?(Float) && v.zero? && (1.0 / v).negative?)

    # a clock of the intent session store: a safe integer
    def clock?(v) = safe_int?(v)

    def utf8_len(s) = s.b.length

    def bounded_string?(v, max) = v.is_a?(String) && !v.empty? && Attestation.finite?(max) && utf8_len(v) <= max

    def digest?(v) = v.is_a?(String) && !AtlasPca.b64d(v, 32).nil?

    def scalar?(v) = v.is_a?(String) || v == true || v == false || safe_int?(v)

    # typeof a === typeof b && a === b (an object is never identical to another)
    def scalar_eq(a, b)
      return a.nil? && b.nil? if a.nil? || b.nil?
      return a == b if (a.is_a?(Numeric) && b.is_a?(Numeric)) || (a.is_a?(String) && b.is_a?(String)) || ([true, false].include?(a) && [true, false].include?(b))

      false
    end

    # nil when `o` has exactly the required members plus any optional ones, else the first violation (unknown members first)
    def closed_members(o, required, optional = nil, where = nil)
      opt = optional.nil? ? [] : optional
      w = where.nil? ? 'object' : where
      o.each_key { |k| return "unknown member '#{w}.#{k}'" unless required.include?(k) || opt.include?(k) }
      required.each { |k| return "missing member '#{w}.#{k}'" unless o.key?(k) }
      nil
    end

    def pin_pq_ok?(v) = UNDEF.equal?(v) || (v.is_a?(String) && !v.empty?)

    # nil when the artifact's suite members are well formed, else the reason
    def artifact_suite_error(a)
      return 'artifact must be an object' unless plain_object?(a)

      alg = pm(a, 'alg')
      e = IntentV2.suite_err(alg)
      return e if e

      %w[pq_pk pq_sig].each { |k| return "#{k} must be a string" if !UNDEF.equal?(pm(a, k)) && !pm(a, k).is_a?(String) }
      return 'an ed25519 artifact must not carry pq_pk / pq_sig' if IntentV2.suite_of(alg) == 'ed25519' && (!UNDEF.equal?(pm(a, 'pq_pk')) || !UNDEF.equal?(pm(a, 'pq_sig')))

      nil
    end

    # domain || strict canonical JSON of the artifact without sig / pq_sig. Raises on a non-canonical member.
    def artifact_message(domain, artifact)
      domain.b + AtlasPca.canon_bytes(artifact.reject { |k, _| k == 'sig' || k == 'pq_sig' })
    end

    # Sign `body` under `domain`: `secret` (32 bytes or a KeyPair), `suite` nil or {'alg', 'pq' => the ML-DSA-65 key pair}.
    def sign_artifact(domain, body, secret, suite = nil)
      alg = suite.is_a?(Hash) ? pm(suite, 'alg') : UNDEF
      pq = suite.is_a?(Hash) ? pm(suite, 'pq') : UNDEF
      raise "signArtifact: unknown signature alg '#{Attestation.jstr(alg)}'" if IntentV2.suite_of(alg).nil?

      signer = secret.is_a?(AtlasPca::KeyPair) ? secret : AtlasPca::KeyPair.new(secret)
      AtlasPca.sign_artifact(domain, body, signer, alg: UNDEF.equal?(alg) ? nil : alg, pq: UNDEF.equal?(pq) ? nil : pq)
    end

    # true iff the artifact's signature verifies under the pinned signer (`pin` a public key, or {'pk', 'pq_pk'?}); a PQ key only as pinned. Never raises.
    def verify_artifact_sig(domain, artifact, pin)
      p = pin.is_a?(String) ? { 'pk' => pin } : pin
      sig = pm(artifact, 'sig')
      pk = pm(p, 'pk')
      return false unless sig.is_a?(String) && pk.is_a?(String)

      pq_pk = pm(p, 'pq_pk')
      pins = pq_pk.is_a?(String) ? { pk => pq_pk } : {}
      IntentV2.verify_pinned_suite(pm(artifact, 'alg'), pk, pm(artifact, 'pq_pk'), artifact_message(domain, artifact), sig, pm(artifact, 'pq_sig'), pins)
    rescue StandardError
      false
    end

    def artifact_ref(ref_domain, slot, artifact) = AtlasPca.hash_canonical({ 'd' => ref_domain }.merge(slot => artifact))

    def public_key_b64u(secret) = (secret.is_a?(AtlasPca::KeyPair) ? secret : AtlasPca::KeyPair.new(secret)).public

    def param_segments(path) = (rest = path[PARAM_PREFIX.length..]).empty? ? [''] : rest.split('.', -1)

    # {found, value?} for an `action.params.<a>.<b>...` path (own members of plain objects only)
    def resolve_param_path(params, path)
      return { 'found' => false } unless path.is_a?(String) && path.start_with?(PARAM_PREFIX)

      cur = params
      param_segments(path).each do |s|
        return { 'found' => false } unless path_segment?(s) && plain_object?(cur) && cur.key?(s)

        cur = cur[s]
      end
      { 'found' => true, 'value' => cur }
    end

    def param_path?(path)
      return false unless path.is_a?(String) && path.start_with?(PARAM_PREFIX)

      segs = param_segments(path)
      segs.length.between?(1, 8) && segs.all? { |s| path_segment?(s) }
    end

    # Set `value` at the dotted `path` of `root` (mutated in place), creating intermediate objects; false (nothing more written) when an
    # intermediate is not an object or the leaf exists.
    def set_nested(root, path, value)
      segs = path.split('.', -1)
      segs = [''] if segs.empty?
      cur = root
      segs[0...-1].each do |k|
        return false if k == '__proto__' && !cur.key?(k)

        cur[k] = {} unless cur.key?(k)
        nxt = cur[k]
        return false unless plain_object?(nxt)

        cur = nxt
      end
      last = segs.last
      return false if last == '__proto__' || cur.key?(last)

      cur[last] = value
      true
    end

    def own_get(o, k) = o.is_a?(Hash) && o.key?(k) ? o[k] : nil
    def null_record = {}
    def clock?(v) = safe_int?(v)
  end
end
