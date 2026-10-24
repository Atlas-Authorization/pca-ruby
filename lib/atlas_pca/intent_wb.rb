# frozen_string_literal: true

# Intent Layer v2 wire batch W-B: NORMATIVE conformance rules 16 (world facts, relational dimensions, offer sets), 17
# (per-parameter provenance, label receipts, flow rules) and 18 (classifier verdicts), and their composition
# `decide_intent_wb` (the facts -> provenance -> classes unit of the v2 verification pipeline).
#
# Port of packages/pca/src oracle-facts.ts, offer-set.ts, param-provenance.ts, label-receipts.ts (verifier side),
# intent-classifier.ts, intent-env.ts, the shared plumbing of intent-artifacts.ts and the label lattice of taint.ts. Step
# order, boundaries and reason strings follow the TypeScript reference. Inputs are String-keyed Hashes shaped like the TS
# input interfaces (the `input` objects of primitives.intent_world / intent_provenance / intent_classifier in
# conformance/vectors.json); results are String-keyed Hashes with the TS field names (absent fields are omitted). Every
# public decide function is total: an internal error fails closed where the TS try/catch does.
#
# JS semantics and the strict reference (README "strict values, absent vs null, suite capability"):
#   * ABSENT vs NULL: an absent optional member (WB_UNDEF; never in an output) means empty / default; one PRESENT with JSON
#     null or of the wrong JSON type is malformed and fails closed (`wb_absent`). Containers are closed member sets.
#   * SUITES: every W-B artifact may carry `alg` / `pq_pk` / `pq_sig` (signed over the body without `sig` / `pq_sig`); an
#     `alg` this verifier does not implement fails with `unsupported_suite` before anything else about that artifact; a
#     PQ or hybrid signature verifies only under the PQ key the verifier pinned. Verification goes through the SDK's one
#     suite dispatch (supported_suites / resolve_pq_key / verify_suite in atlas_pca.rb), never a second implementation.
#   * Object key iteration is canonical array-index keys ascending, then insertion order (`wb_js_keys`); every sort is
#     UTF-8 byte order (Ruby String#<=>).
#   * Numbers: an Integer and an integral Float are the same JS number (5 == 5.0); safe integers reject -0.0; true/false
#     are never numbers. Hashed / signed values are normalized to that model before the strict canonicalizer runs.
#   * Regexes are anchored with \A..\z; a string with invalid encoding (a lone surrogate read by the loose parser, WTF-8)
#     never matches an (ASCII) pattern. Prefix tests and splits work on bytes, never raising on such strings.
#   * The clock `now` must be a safe integer (else every fact and every offer set is stale); lists are real Arrays (a
#     string is never iterated); activity needs a non-empty Array, a String offer_set or a Hash policy.
#   * Keyed lookups and tallies are own-member Hashes (prototype-named labels, ids and keys are ordinary keys).
module AtlasPca
  module_function

  # ---- constants --------------------------------------------------------------------------------------------------------

  FACT_DOMAIN = "atlas-pca/fact/v1\x00"
  FACT_REF_DOMAIN = 'atlas-pca/fact-ref/v1'
  MAX_COMMITTED_FACTS = 16
  MAX_WORLDS = 16
  MAX_RELATIONAL = 16
  DEFAULT_WORLD_SKEW_MS = 60_000

  OFFER_SET_DOMAIN = "atlas-pca/offer-set/v1\x00"
  OFFER_SET_REF_DOMAIN = 'atlas-pca/offer-set-ref/v1'
  MAX_OFFERS = 256
  MAX_OFFER_ATTRS = 32
  MAX_QUERY_KEYS = 32

  LABELS_DOMAIN = "atlas-pca/labels/v1\x00"
  LABELS_REF_DOMAIN = 'atlas-pca/labels-ref/v1'
  MAX_LABEL_FIELDS = 64
  PUBLIC_CLASS = 'public'

  LABEL_REF_PREFIX = 'pca-labels:'
  MAX_PROV_PATHS = 32
  MAX_PROV_REFS = 8
  MAX_COMMITTED_LABELS = 16

  INTENT_CLASSIFIER_DOMAIN = "atlas-pca/intent-classifier/v1\x00"
  INTENT_CLASSIFIER_REF_DOMAIN = 'atlas-pca/intent-classifier-ref/v1'
  MAX_COMMITTED_CLASSES = 8
  MAX_CLASSIFIER_LABELS = 32

  WB_INTENT_NAME_RE = /\A[a-z][a-z0-9_]{0,63}\z/
  WB_DATA_CLASS_RE = /\A[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*\z/
  WB_PARAM_SEGMENT_RE = /\A[A-Za-z0-9_-]{1,64}\z/
  WB_PROV_PATH_RE = /\Aaction\.params\.[A-Za-z0-9_]{1,64}\z/
  WB_FORBIDDEN_SEGMENTS = %w[__proto__ constructor prototype].freeze
  WB_ARRAY_INDEX_RE = /\A(?:0|[1-9][0-9]*)\z/
  WB_PARAMS_PREFIX = 'action.params.'
  WB_ENV_WORLD_PREFIX = 'env.world.'

  # taint.ts label lattice: trusted (0) < first_party (1) < tool (2) < web (3) < agent (4); TAINTED = rank >= tool.
  TAINT_LEVELS = %w[trusted first_party tool web agent].freeze
  WB_TAINTED_RANK = 2
  WB_MODES = %w[allow question question_typed deny].freeze

  # A JS `undefined` (absent member).
  WB_UNDEF = Object.new.freeze

  # ---- JS value helpers -------------------------------------------------------------------------------------------------

  # `o?.[k]` on a JSON value: the own member, or WB_UNDEF (absent member, or `o` not an object).
  def wb_get(o, k)
    o.is_a?(Hash) && o.key?(k) ? o[k] : WB_UNDEF
  end

  # `o[k]` where the reference throws on null / undefined (a TypeError the decide functions' rescue reports).
  def wb_member(o, k)
    raise TypeError, "Cannot read properties of #{o.nil? ? 'null' : 'undefined'} (reading '#{k}')" if o.nil? || o.equal?(WB_UNDEF)

    wb_get(o, k)
  end

  # `v ?? d`.
  def wb_dflt(v, d)
    v.nil? || v.equal?(WB_UNDEF) ? d : v
  end

  # `v === undefined ? d : v`: an ABSENT optional member takes its default; a PRESENT one (JSON null included) is returned
  # as is, for the member's own type check to refuse.
  def wb_absent(v, d)
    v.equal?(WB_UNDEF) ? d : v
  end

  # `v !== undefined`.
  def wb_present?(v)
    !v.equal?(WB_UNDEF)
  end

  def wb_num?(v)
    v.is_a?(Integer) || v.is_a?(Float)
  end

  def wb_bool?(v)
    v.equal?(true) || v.equal?(false)
  end

  def wb_neg_zero?(v)
    v.is_a?(Float) && v.zero? && (1.0 / v).negative?
  end

  # intent-artifacts.ts isSafeInt: Number.isSafeInteger and not -0 (an integral Float is the same JS number).
  def wb_safe_int?(v)
    return v.abs <= MAX_SAFE if v.is_a?(Integer)
    return false unless v.is_a?(Float) && v.finite? && v == v.floor && !wb_neg_zero?(v)

    v.abs <= MAX_SAFE
  end

  # A safe-integer JS number as an Integer.
  def wb_int(v)
    v.is_a?(Float) ? v.to_i : v
  end

  # UTF-16 code units of a string (a WTF-8 lone surrogate is one unit, like the U+FFFD TextEncoder writes for it).
  def wb_utf16_len(s)
    s.each_byte.sum { |b| ((b & 0xC0) == 0x80 ? 0 : 1) + (b >= 0xF0 ? 1 : 0) }
  end

  # A non-empty real array (strict activity typing: an object with its own `length` member is not an array).
  def wb_non_empty_array?(v)
    v.is_a?(Array) && !v.empty?
  end

  # A usable clock value: a safe integer (anything else makes every freshness bound fail, i.e. stale; never coerced).
  def wb_clock?(v)
    wb_safe_int?(v)
  end

  # Object.keys order: canonical array-index keys ascending numerically, then the other keys in insertion order.
  def wb_js_keys(h)
    idx = []
    rest = []
    h.each_key do |k|
      if k.is_a?(String) && k.valid_encoding? && WB_ARRAY_INDEX_RE.match?(k) && k.to_i <= 4_294_967_294
        idx << k
      else
        rest << k
      end
    end
    idx.sort_by(&:to_i) + rest
  end

  # An (ASCII) regex test that never raises: a string with invalid encoding does not match, as in JS.
  def wb_re?(re, s)
    s.is_a?(String) && s.valid_encoding? && re.match?(s)
  end

  # `s.startsWith(prefix)` on bytes (never raises on a string with invalid encoding).
  def wb_starts?(s, prefix)
    s.is_a?(String) && s.b.start_with?(prefix.b)
  end

  # `s.endsWith(suffix)` on bytes.
  def wb_ends?(s, suffix)
    s.is_a?(String) && s.b.end_with?(suffix.b)
  end

  # `s.slice(prefix.length)` for a known ASCII prefix.
  def wb_after(s, prefix)
    s.byteslice(prefix.bytesize, s.bytesize - prefix.bytesize)
  end

  # JS `s.split('.')`: keeps empty segments (leading, inner and trailing); "" splits to [""].
  def wb_split_dot(s)
    return [+''] if s.empty?

    s.b.split('.', -1).map { |x| x.force_encoding(Encoding::UTF_8) }
  end

  # ECMAScript Number::toString (diagnostics only). An integer beyond 2^53-1 is the JS number it denotes, i.e. the nearest
  # double, printed with the SHORTEST round-trip digits (String(2 ** 60) is "1152921504606847000", not the exact integer).
  def wb_js_num_str(x)
    if x.is_a?(Integer)
      return x.to_s if x.abs <= MAX_SAFE

      x = x.to_f
    end
    return 'NaN' if x.nan?
    return (x.positive? ? 'Infinity' : '-Infinity') if x.infinite?
    return '0' if x.zero?
    return x.to_i.to_s if x == x.floor && x.abs <= MAX_SAFE

    sign = x.negative? ? '-' : ''
    mant, exp = x.abs.to_s.split('e')
    e = exp.to_i
    ip, fp = mant.split('.')
    fp ||= ''
    all = ip + fp
    stripped = all.sub(/\A0+/, '')
    lead = all.length - stripped.length
    n = ip.length + e - lead # value = 0.<digits> * 10^n
    digits = stripped.sub(/0+\z/, '')
    digits = '0' if digits.empty?
    k = digits.length
    return sign + digits + ('0' * (n - k)) if k <= n && n <= 21
    return "#{sign}#{digits[0, n]}.#{digits[n..]}" if n.positive? && n <= 21
    return "#{sign}0.#{'0' * -n}#{digits}" if n > -6 && n <= 0

    ee = n - 1
    es = (ee.positive? ? '+' : '-') + ee.abs.to_s
    k == 1 ? "#{sign}#{digits}e#{es}" : "#{sign}#{digits[0]}.#{digits[1..]}e#{es}"
  end

  # ECMAScript String(v) for JSON values (template-literal interpolation in reasons).
  def wb_js_str(v)
    return 'undefined' if v.equal?(WB_UNDEF)
    return 'null' if v.nil?
    return v.to_s if wb_bool?(v)
    return v if v.is_a?(String)
    return wb_js_num_str(v) if wb_num?(v)
    return v.map { |x| x.nil? || x.equal?(WB_UNDEF) ? '' : wb_js_str(x) }.join(',') if v.is_a?(Array)

    '[object Object]'
  end

  # JS `a === b` on JSON values (also the scalar equality of the W-B artifacts: same JSON type and value, so 2 == 2.0
  # but 2 != "2" and true != 1).
  def wb_strict_eq?(a, b)
    return a.equal?(b) if a.equal?(WB_UNDEF) || b.equal?(WB_UNDEF)
    return a.nil? && b.nil? if a.nil? || b.nil?
    return wb_bool?(a) && wb_bool?(b) && a == b if wb_bool?(a) || wb_bool?(b)
    return wb_num?(a) && wb_num?(b) && a == b if wb_num?(a) || wb_num?(b) # NaN != NaN, -0.0 == 0, as ===
    return a.is_a?(String) && b.is_a?(String) && a.b == b.b if a.is_a?(String) || b.is_a?(String)

    a.equal?(b) # objects: identity
  end

  # The JS number model of a JSON value for the strict canonicalizer: an integral Float that is a safe integer (not -0.0)
  # is the Integer (JS prints 5.0 as "5"); everything else is left for the canonicalizer to accept or refuse. Containers
  # deeper than MAX_JSON_DEPTH are refused before recursing (as the canonicalizer does).
  def wb_jsnorm(v, depth = 1)
    case v
    when Float
      v.finite? && v == v.floor && v.abs <= MAX_SAFE && !wb_neg_zero?(v) ? v.to_i : v
    when Array
      raise Malformed, 'canonicalize: nesting too deep' if depth > MAX_JSON_DEPTH

      v.map { |x| wb_jsnorm(x, depth + 1) }
    when Hash
      raise Malformed, 'canonicalize: nesting too deep' if depth > MAX_JSON_DEPTH

      v.each_with_object({}) { |(k, x), h| h[k] = wb_jsnorm(x, depth + 1) }
    else
      v
    end
  end

  # strictCanonical bytes of a JSON value (raises Malformed when it has no strict canonical form).
  def wb_canon_bytes(v)
    canon_bytes(wb_jsnorm(v))
  end

  # base64url(sha256(strictCanonical(value))) (raises Malformed when it has no strict canonical form).
  def wb_hash(v)
    hash_canonical(wb_jsnorm(v))
  end

  # ---- shared artifact plumbing (intent-artifacts.ts) -------------------------------------------------------------------

  def wb_path_segment?(s)
    wb_re?(WB_PARAM_SEGMENT_RE, s) && !WB_FORBIDDEN_SEGMENTS.include?(s)
  end

  # Non-empty string of at most `max` UTF-8 bytes (a WTF-8 lone surrogate counts 3, as TextEncoder's U+FFFD).
  def wb_bounded?(v, max)
    v.is_a?(String) && !v.empty? && v.bytesize <= max
  end

  def wb_digest?(v)
    v.is_a?(String) && !b64d(v, 32).nil?
  end

  # A wire scalar: a string, a boolean or a safe integer.
  def wb_scalar?(v)
    v.is_a?(String) || wb_bool?(v) || wb_safe_int?(v)
  end

  # Scalar equality (same JSON type and value).
  def scalar_eq(a, b)
    wb_strict_eq?(a, b)
  end

  # Closed member set check: nil when `o` has exactly the `required` members plus any of `optional`.
  def wb_closed_members(o, required, optional = [], where = 'object')
    wb_js_keys(o).each { |k| return "unknown member '#{where}.#{k}'" unless required.include?(k) || optional.include?(k) }
    required.each { |k| return "missing member '#{where}.#{k}'" unless o.key?(k) }
    nil
  end

  # The optional suite members every W-B artifact may carry.
  WB_SUITE_MEMBERS = %w[alg pq_pk pq_sig].freeze

  # A pin's optional `pq_pk`: absent, or a non-empty string (JSON null is malformed).
  def wb_pin_pq_ok?(v)
    v.equal?(WB_UNDEF) || (v.is_a?(String) && !v.empty?)
  end

  # True iff the SDK's suite dispatch (resolve_suite / suite_dispatch, capability manifest `supported_suites`) can verify
  # `alg` in this runtime.
  def wb_suite_implemented?(alg)
    alg.is_a?(String) && supported_suites.include?(alg)
  end

  # artifactSuiteError (intent-artifacts.ts): nil = usable. `alg` absent = ed25519; a non-string `alg` is malformed; an
  # `alg` this verifier does not implement is `unsupported_suite: '<alg>'`; non-string `pq_pk` / `pq_sig` are malformed; an
  # ed25519 artifact (alg absent or "ed25519") carries neither `pq_pk` nor `pq_sig`.
  def wb_artifact_suite_error(a)
    return 'artifact must be an object' unless a.is_a?(Hash)

    alg = wb_get(a, 'alg')
    unless alg.equal?(WB_UNDEF)
      return 'alg must be a string' unless alg.is_a?(String)
      return "#{UNSUPPORTED_SUITE}: '#{alg}'" unless wb_suite_implemented?(alg)
    end
    %w[pq_pk pq_sig].each { |k| return "#{k} must be a string" if wb_present?(wb_get(a, k)) && !wb_get(a, k).is_a?(String) }
    if (alg.equal?(WB_UNDEF) || alg == 'ed25519') && (wb_present?(wb_get(a, 'pq_pk')) || wb_present?(wb_get(a, 'pq_sig')))
      return 'an ed25519 artifact must not carry pq_pk / pq_sig'
    end

    nil
  end

  # The exact bytes an artifact signature covers: utf8(domain) || strictCanonical(body without `sig` / `pq_sig`), so `alg`
  # and `pq_pk` are signed. Raises on a non-canonical body.
  def wb_artifact_message(domain, artifact)
    body = artifact.reject { |k, _| k == 'sig' || k == 'pq_sig' }
    domain.b + wb_canon_bytes(body)
  end

  # Verify an artifact's signature under a PINNED signer (`{"pk", "pq_pk"?}` or a bare b64u Ed25519 key) through the SDK's
  # suite dispatch (verifyPinnedSuite): ed25519 under the pinned `pk`; any other suite only when the artifact's `pq_pk`
  # equals the pinned `pq_pk` (resolve_pq_key with the pin as pqPins[pk]). The caller has checked wb_artifact_suite_error.
  # Total: false on any malformed input.
  def wb_verify_artifact_sig(domain, artifact, pin)
    pin = { 'pk' => pin } if pin.is_a?(String)
    sig = wb_get(artifact, 'sig')
    pk = wb_get(pin, 'pk')
    return false unless sig.is_a?(String) && pk.is_a?(String)

    alg = wb_get(artifact, 'alg')
    suite = alg.equal?(WB_UNDEF) ? 'ed25519' : alg
    return false unless wb_suite_implemented?(suite)

    msg = wb_artifact_message(domain, artifact)
    sp = { 'alg' => suite, 'sig' => sig }
    pq_sig = wb_get(artifact, 'pq_sig')
    sp['pq_sig'] = pq_sig if wb_present?(pq_sig)
    return verify_suite(sp, pk, msg, nil) if suite == 'ed25519'

    pin_pq = wb_get(pin, 'pq_pk')
    art_pq = wb_get(artifact, 'pq_pk')
    pq = resolve_pq_key(pk, art_pq.equal?(WB_UNDEF) ? nil : art_pq, pq_pins: pin_pq.is_a?(String) ? { pk => pin_pq } : {})
    return false if pq.nil?

    verify_suite(sp, pk, msg, pq)
  rescue StandardError
    false
  end

  # Content address of an artifact (signature included): b64u(sha256(strictCanonical({d, [slot]: artifact}))).
  def wb_artifact_ref(ref_domain, slot, artifact)
    wb_hash({ 'd' => ref_domain, slot => artifact })
  end

  # Resolve an `action.params.<a>.<b>...` path inside `params` (own members only): [found, value].
  def wb_resolve(params, path)
    return [false, nil] unless wb_starts?(path, WB_PARAMS_PREFIX)

    cur = params
    wb_split_dot(wb_after(path, WB_PARAMS_PREFIX)).each do |s|
      return [false, nil] unless wb_path_segment?(s) && cur.is_a?(Hash) && cur.key?(s)

      cur = cur[s]
    end
    [true, cur]
  end

  # resolveParamPath: { "found" => bool, "value" => ... (only when found) }.
  def resolve_param_path(params, path)
    found, value = wb_resolve(params, path)
    found ? { 'found' => true, 'value' => value } : { 'found' => false }
  end

  # A well-formed `action.params.*` path of 1..8 segments.
  def param_path?(path)
    return false unless wb_starts?(path, WB_PARAMS_PREFIX)

    segs = wb_split_dot(wb_after(path, WB_PARAMS_PREFIX))
    segs.length >= 1 && segs.length <= 8 && segs.all? { |s| wb_path_segment?(s) }
  end

  # Set `value` at the nested position of a dotted `path` under `root`; false (nothing set at the leaf) when the path
  # collides with an existing leaf or subtree.
  def wb_set_nested(root, path, value)
    segs = wb_split_dot(path)
    cur = root
    segs[0...-1].each do |k|
      cur[k] = {} unless cur.key?(k)
      nxt = cur[k]
      return false unless nxt.is_a?(Hash)

      cur = nxt
    end
    last = segs[-1]
    return false if cur.key?(last)

    cur[last] = value
    true
  end

  # base64url(sha256(strictCanonical(value))): a label field's `value_digest`. Raises Malformed when non-canonical.
  def value_digest(value)
    wb_hash(value)
  end

  # The content digest a classifier verdict binds. Raises Malformed when non-canonical.
  def classifier_content_digest(value)
    wb_hash(value)
  end

  # ---- rule 16: oracle facts --------------------------------------------------------------------------------------------

  WB_FACT_FIELDS = %w[v kind name subject value t_obs oracle sig].freeze

  # Wire validation of a fact. nil = well-formed.
  def validate_fact_wire(f)
    return 'fact must be an object' unless f.is_a?(Hash)

    m = wb_closed_members(f, WB_FACT_FIELDS, WB_SUITE_MEMBERS, 'fact')
    return m if m
    return 'fact must be {v: 1, kind: "pca-fact"}' if !wb_strict_eq?(f['v'], 1) || !wb_strict_eq?(f['kind'], 'pca-fact')
    return "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$" unless wb_re?(WB_INTENT_NAME_RE, f['name'])
    return "'fact.subject' must be a non-empty string (<= 256 bytes)" unless wb_bounded?(f['subject'], 256)
    unless wb_safe_int?(f['value']) || wb_bounded?(f['value'], 256)
      return "'fact.value' must be a safe integer or a non-empty string (<= 256 bytes)"
    end
    return "'fact.t_obs' must be a non-negative safe integer" if !wb_safe_int?(f['t_obs']) || f['t_obs'].negative?
    return "'fact.oracle' must be a non-empty string (<= 64 bytes)" unless wb_bounded?(f['oracle'], 64)
    return "'fact.sig' must be a string" unless f['sig'].is_a?(String)

    nil
  end

  # The content address committed in `intent_session.facts[]`. Raises Malformed when non-canonical.
  def fact_ref(f)
    wb_artifact_ref(FACT_REF_DOMAIN, 'f', f)
  end

  # The lower median of a non-empty list of integers (index floor((n-1)/2) ascending). Raises on an empty list.
  def lower_median(xs)
    raise ArgumentError, 'lowerMedian: empty' if xs.empty?

    s = xs.sort
    s[(s.length - 1) / 2]
  end

  # floor(a * 10^6 / b) exactly, or nil when b <= 0, a < 0 or the result is not a safe integer.
  def ratio_ppm(a, b)
    return nil if !wb_safe_int?(a) || !wb_safe_int?(b) || !b.positive? || a.negative? # never a non-integer operand

    q = (wb_int(a) * 1_000_000) / wb_int(b)
    q <= MAX_SAFE ? q : nil
  end

  # ---- rule 16 step 6: offer sets ---------------------------------------------------------------------------------------

  WB_OFFER_SET_FIELDS = %w[v kind site session query rank complete offers issued_at kid sig].freeze

  # Wire validation of an offer set. nil = well-formed.
  def validate_offer_set_wire(o)
    return 'offer set must be an object' unless o.is_a?(Hash)

    m = wb_closed_members(o, WB_OFFER_SET_FIELDS, WB_SUITE_MEMBERS, 'offer_set')
    return m if m
    return 'offer set must be {v: 1, kind: "pca-offer-set"}' if !wb_strict_eq?(o['v'], 1) || !wb_strict_eq?(o['kind'], 'pca-offer-set')
    return "'offer_set.site' must be a non-empty string (<= 256 bytes)" unless wb_bounded?(o['site'], 256)
    return "'offer_set.session' must be canonical base64url (32 bytes)" unless wb_digest?(o['session'])

    q = o['query']
    return "'offer_set.query' must be an object with <= #{MAX_QUERY_KEYS} keys" if !q.is_a?(Hash) || q.length > MAX_QUERY_KEYS

    wb_js_keys(q).each { |k| return "'offer_set.query.#{k}' must be a scalar" unless wb_bounded?(k, 64) && wb_scalar?(q[k]) }
    return "'offer_set.rank' must be \"price_asc\"" unless wb_strict_eq?(o['rank'], 'price_asc')
    return "'offer_set.complete' must be a boolean" unless wb_bool?(o['complete'])

    offers = o['offers']
    if !offers.is_a?(Array) || offers.empty? || offers.length > MAX_OFFERS
      return "'offer_set.offers' must hold 1..#{MAX_OFFERS} offers"
    end

    ids = {}
    offers.each_with_index do |of, i|
      return "offer #{i} must be an object" unless of.is_a?(Hash)

      oid = wb_get(of, 'offer_id')
      return "offer #{i}: 'offer_id' must be a non-empty string (<= 128 bytes)" unless wb_bounded?(oid, 128)
      return "offer #{i}: duplicate offer_id" if ids.key?(oid)

      ids[oid] = true
      price = wb_get(of, 'price')
      return "offer #{i}: 'price' must be a non-negative safe integer" if !wb_safe_int?(price) || price.negative?

      attrs = wb_js_keys(of).reject { |k| k == 'offer_id' || k == 'price' }
      return "offer #{i}: more than #{MAX_OFFER_ATTRS} attributes" if attrs.length > MAX_OFFER_ATTRS

      attrs.each { |k| return "offer #{i}: attribute '#{k}' must be a scalar" unless wb_bounded?(k, 64) && wb_scalar?(of[k]) }
    end
    return "'offer_set.issued_at' must be a non-negative safe integer" if !wb_safe_int?(o['issued_at']) || o['issued_at'].negative?
    return "'offer_set.kid' must be a non-empty string (<= 64 bytes)" unless wb_bounded?(o['kid'], 64)
    return "'offer_set.sig' must be a string" unless o['sig'].is_a?(String)

    nil
  end

  # The content address committed in `intent_session.offer_set`. Raises Malformed when non-canonical.
  def offer_set_ref(o)
    wb_artifact_ref(OFFER_SET_REF_DOMAIN, 'o', o)
  end

  # Does an offer satisfy the offer part of the intent filter (every key an own member, scalar-equal)?
  def offer_matches(offer, f)
    return false unless offer.is_a?(Hash) && f.is_a?(Hash)

    wb_js_keys(f).all? { |k| offer.key?(k) && wb_strict_eq?(offer[k], f[k]) }
  end

  # Coverage: the query constrains nothing the filter does not (keys(q) within keys(F.query), equal values).
  def query_covers(query, fq)
    return false unless query.is_a?(Hash) && fq.is_a?(Hash)

    wb_js_keys(query).all? { |k| fq.key?(k) && wb_strict_eq?(fq[k], query[k]) }
  end

  # Policy sanity for an offer policy (nil = well-formed).
  def validate_offer_policy(p)
    return 'offers policy must be an object' unless p.is_a?(Hash)

    cm = wb_closed_members(p, %w[name site_keys max_age_ms offer_param filter], [], 'offers')
    return cm if cm
    return 'offers policy needs a name' unless wb_get(p, 'name').is_a?(String)

    sk = wb_get(p, 'site_keys')
    return 'offers policy needs at least one pinned site key' if !sk.is_a?(Array) || sk.empty?

    kids = {}
    sk.each do |k|
      kid = wb_get(k, 'kid')
      if !k.is_a?(Hash) || !wb_closed_members(k, %w[kid pk], %w[pq_pk], 'site_key').nil? || !wb_bounded?(kid, 64) || !wb_digest?(wb_get(k, 'pk')) || !wb_pin_pq_ok?(wb_get(k, 'pq_pk')) || kids.key?(kid)
        return 'offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk'
      end

      kids[kid] = true
    end
    mx = wb_get(p, 'max_age_ms')
    return 'offers policy: max_age_ms must be a non-negative safe integer' if !wb_safe_int?(mx) || mx.negative?
    return 'offers policy: offer_param must be an action.params.* path' unless wb_starts?(wb_get(p, 'offer_param'), WB_PARAMS_PREFIX)

    f = wb_get(p, 'filter')
    unless f.is_a?(Hash) && wb_closed_members(f, %w[query offer], [], 'filter').nil? && f['query'].is_a?(Hash) && f['offer'].is_a?(Hash)
      return 'offers policy: filter must be exactly {query: {}, offer: {}}'
    end

    [f['query'], f['offer']].each do |part|
      wb_js_keys(part).each { |k| return 'offers policy: filter values must be scalars' unless wb_scalar?(part[k]) }
    end
    nil
  end

  def wb_offer_fail(reason)
    { 'ok' => false, 'reason' => reason }
  end

  # Rule 16 step 6 (the policy is assumed sane). Positional; `committed` / `offer_set` are WB_UNDEF when absent.
  def wb_decide_offer_set(policy, committed, offer_set, params, aud, session, now, skew_ms)
    pe = validate_offer_policy(policy)
    return wb_offer_fail("offers: policy misconfigured (fail closed): #{pe}") if pe
    return wb_offer_fail('offers: the PCActn commits no offer set but the policy requires one') if committed.equal?(WB_UNDEF)
    return wb_offer_fail('offers: the committed offer set was not supplied') if offer_set.equal?(WB_UNDEF)

    w = validate_offer_set_wire(offer_set)
    return wb_offer_fail("offers: #{w}") if w

    os = offer_set
    ref = begin
      offer_set_ref(os)
    rescue StandardError
      return wb_offer_fail('offers: the offer set is not strictly canonical')
    end
    return wb_offer_fail('offers: the supplied offer set does not match the committed reference') unless wb_strict_eq?(ref, committed)

    se = wb_artifact_suite_error(os)
    return wb_offer_fail("offers: signature suite: #{se}") if se

    key = policy['site_keys'].find { |k| wb_strict_eq?(k['kid'], os['kid']) }
    return wb_offer_fail("offers: signing key '#{os['kid']}' is not pinned") if key.nil?
    return wb_offer_fail('offers: bad site signature') unless wb_verify_artifact_sig(OFFER_SET_DOMAIN, os, key)
    return wb_offer_fail('offers: the offer set was issued for another audience') unless wb_strict_eq?(os['site'], aud)
    return wb_offer_fail('offers: the offer set is bound to another session') unless wb_strict_eq?(os['session'], session)
    unless wb_clock?(now) && wb_safe_int?(skew_ms)
      return wb_offer_fail('offers: no usable clock (now must be a safe integer): the offer set counts as stale')
    end
    return wb_offer_fail('offers: the offer set is issued in the future') if wb_int(os['issued_at']) > wb_int(now) + wb_int(skew_ms)
    return wb_offer_fail('offers: the offer set is stale') if wb_int(now) - wb_int(os['issued_at']) > policy['max_age_ms']
    return wb_offer_fail('offers: the offer set is not declared complete') unless os['complete'].equal?(true)
    unless query_covers(os['query'], policy['filter']['query'])
      return wb_offer_fail('offers: the search was narrowed beyond the intent filter (coverage)')
    end

    found, id = wb_resolve(params, policy['offer_param'])
    return wb_offer_fail('offers: the action names no offer id at the declared parameter') unless found && id.is_a?(String)

    chosen = os['offers'].find { |x| wb_strict_eq?(x['offer_id'], id) }
    return wb_offer_fail('offers: the chosen offer is not in the signed offer set') if chosen.nil?

    fo = policy['filter']['offer']
    return wb_offer_fail('offers: the chosen offer does not satisfy the intent filter') unless offer_matches(chosen, fo)

    mn = wb_int(chosen['price'])
    os['offers'].each { |x| mn = wb_int(x['price']) if offer_matches(x, fo) && x['price'] < mn }
    cp = wb_int(chosen['price'])
    { 'ok' => true, 'excess' => cp - mn, 'chosen_price' => cp, 'min_price' => mn }
  end

  # decideOfferSet: `input` = { "policy", "committed"?, "offerSet"?, "params", "aud", "session", "now", "skewMs" } (the
  # TS field names). Returns { "ok" => true, "excess", "chosen_price", "min_price" } or { "ok" => false, "reason" }.
  def decide_offer_set(input)
    return wb_offer_fail('offers: input must be an object') unless input.is_a?(Hash)

    wb_decide_offer_set(wb_get(input, 'policy'), wb_get(input, 'committed'), wb_get(input, 'offerSet'), wb_get(input, 'params'),
                        wb_get(input, 'aud'), wb_get(input, 'session'), wb_get(input, 'now'), wb_get(input, 'skewMs'))
  rescue StandardError => e
    wb_offer_fail("offers: evaluation error (fail closed): #{e.message}")
  end

  # ---- rule 16: policy, activity, decision ------------------------------------------------------------------------------

  # Rule 16 step 0. nil = well-formed.
  def validate_world_policy(p)
    return 'world policy must be an object' unless p.is_a?(Hash)

    # Closed member sets everywhere (README "closed and typed"): an unknown member is malformed.
    cm = wb_closed_members(p, [], %w[skew_ms worlds relational offers], 'policy')
    return cm if cm

    skew = wb_get(p, 'skew_ms')
    return 'skew_ms must be a non-negative safe integer' if wb_present?(skew) && (!wb_safe_int?(skew) || skew.negative?)

    names = {}
    claim = lambda do |n|
      return "dimension name '#{wb_js_str(n)}' must match ^[a-z][a-z0-9_]{0,63}$" unless wb_re?(WB_INTENT_NAME_RE, n)
      return "duplicate dimension name '#{n}'" if names.key?(n)

      names[n] = true
      nil
    end
    worlds = wb_absent(wb_get(p, 'worlds'), []) # absent = []; null or any non-array is malformed
    return "worlds must be a list of at most #{MAX_WORLDS}" if !worlds.is_a?(Array) || worlds.length > MAX_WORLDS

    worlds.each do |w|
      return 'world entry must be an object' unless w.is_a?(Hash)

      wm = wb_closed_members(w, %w[name subject_path oracles freshness_ms min_oracles max_faulty], [], 'world')
      return wm if wm

      e = claim.call(wb_get(w, 'name'))
      return e if e

      wn = w['name']
      return "world '#{wn}': subject_path must be rooted at action." unless wb_starts?(wb_get(w, 'subject_path'), 'action.')

      fr = wb_get(w, 'freshness_ms')
      return "world '#{wn}': freshness_ms must be a non-negative safe integer" if !wb_safe_int?(fr) || fr.negative?

      mf = wb_get(w, 'max_faulty')
      return "world '#{wn}': max_faulty must be a non-negative safe integer" if !wb_safe_int?(mf) || mf.negative?

      mo = wb_get(w, 'min_oracles')
      return "world '#{wn}': min_oracles must be a safe integer >= 2*max_faulty+1" if !wb_safe_int?(mo) || mo < (2 * wb_int(mf)) + 1

      ors = wb_get(w, 'oracles')
      return "world '#{wn}': fewer pinned oracles than min_oracles" if !ors.is_a?(Array) || ors.length < mo

      kids = {}
      ors.each do |o|
        kid = wb_get(o, 'kid')
        if !o.is_a?(Hash) || !wb_closed_members(o, %w[kid pk], %w[pq_pk], 'oracle').nil? || !wb_bounded?(kid, 64) || !wb_digest?(wb_get(o, 'pk')) || !wb_pin_pq_ok?(wb_get(o, 'pq_pk')) || kids.key?(kid)
          return "world '#{wn}': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk"
        end

        kids[kid] = true
      end
    end
    rel = wb_absent(wb_get(p, 'relational'), [])
    return "relational must be a list of at most #{MAX_RELATIONAL}" if !rel.is_a?(Array) || rel.length > MAX_RELATIONAL

    rel.each do |r|
      return 'relational entry must be an object' unless r.is_a?(Hash)

      rm = wb_closed_members(r, %w[name fn a b], [], 'relational')
      return rm if rm

      e = claim.call(wb_get(r, 'name'))
      return e if e

      rn = r['name']
      fn = wb_get(r, 'fn')
      return "relational '#{rn}': fn must be \"sub\" or \"ratio_ppm\"" unless wb_strict_eq?(fn, 'sub') || wb_strict_eq?(fn, 'ratio_ppm')

      [wb_get(r, 'a'), wb_get(r, 'b')].each do |op|
        ok = param_path?(op) || (wb_starts?(op, WB_ENV_WORLD_PREFIX) &&
             names.key?(wb_after(op, WB_ENV_WORLD_PREFIX)) && wb_after(op, WB_ENV_WORLD_PREFIX) != rn)
        unless ok
          return "relational '#{rn}': operand '#{wb_js_str(op)}' must be an action.params path or an earlier env.world dimension"
        end
      end
    end
    offers = wb_get(p, 'offers')
    if wb_present?(offers)
      e = validate_offer_policy(offers) || claim.call(offers['name'])
      return e if e
    end
    nil
  end

  # Is the rule-16 check active (the verdict reports it)? Iff `committed.facts` is a non-empty ARRAY, `committed.offer_set`
  # a STRING, `policy.worlds` / `policy.relational` a non-empty ARRAY, or `policy.offers` a plain object (strict typing).
  def intent_world_active(input)
    return false unless input.is_a?(Hash) # total: a non-object input has no members

    c = wb_dflt(wb_get(input, 'committed'), {})
    p = wb_dflt(wb_get(input, 'policy'), {})
    wb_non_empty_array?(wb_get(c, 'facts')) || wb_get(c, 'offer_set').is_a?(String) ||
      wb_non_empty_array?(wb_get(p, 'worlds')) || wb_non_empty_array?(wb_get(p, 'relational')) || wb_get(p, 'offers').is_a?(Hash)
  end

  def wb_subject_of(action, params, path)
    if path == 'action.resource'
      r = wb_member(action, 'resource')
      return r.is_a?(String) ? r : nil
    end
    if path == 'action.verb'
      v = wb_member(action, 'verb')
      return v.is_a?(String) ? v : nil
    end
    found, value = wb_resolve(params, path)
    found && value.is_a?(String) ? value : nil
  end

  # NORMATIVE rule 16 (`facts`): compute `env.world` for one action. { "ok" => true, "world", "single_source" } or
  # { "ok" => false, "reason" }. First failure wins (steps 0-6 of oracle-facts.ts decideIntentWorld). Never raises.
  def decide_intent_world(input)
    fail = ->(reason) { { 'ok' => false, 'reason' => "facts: #{reason}" } }
    begin
      return fail.call('input must be an object') unless input.is_a?(Hash)

      # ABSENT optional members mean empty / default; PRESENT ones of the wrong JSON type (null included) fail closed.
      policy = wb_absent(wb_member(input, 'policy'), {})
      pe = validate_world_policy(policy)
      return fail.call("policy misconfigured (fail closed): #{pe}") if pe

      skew = wb_dflt(wb_get(policy, 'skew_ms'), DEFAULT_WORLD_SKEW_MS)
      action = wb_get(input, 'action')
      return fail.call('action must be an object') unless action.is_a?(Hash)

      params = wb_absent(wb_get(action, 'params'), {})
      return fail.call('action.params must be an object') unless params.is_a?(Hash)

      committed = wb_absent(wb_get(input, 'committed'), {})
      return fail.call('committed must be an object') unless committed.is_a?(Hash)

      committed_facts = wb_absent(wb_get(committed, 'facts'), [])
      if !committed_facts.is_a?(Array) || committed_facts.length > MAX_COMMITTED_FACTS
        return fail.call("committed facts must be a list of at most #{MAX_COMMITTED_FACTS} digests")
      end

      seen = {}
      committed_facts.each do |d|
        return fail.call('a committed fact digest is not canonical base64url (32 bytes)') unless wb_digest?(d)
        return fail.call('duplicate committed fact digest') if seen.key?(d)

        seen[d] = true
      end
      committed_offer = wb_get(committed, 'offer_set')
      if wb_present?(committed_offer) && !wb_digest?(committed_offer)
        return fail.call('the committed offer_set is not canonical base64url (32 bytes)')
      end

      supplied = wb_absent(wb_get(input, 'facts'), [])
      return fail.call('facts must be an array') unless supplied.is_a?(Array)

      offer_in = wb_get(input, 'offer_set')
      return fail.call('offer_set must be an object') if wb_present?(offer_in) && !offer_in.is_a?(Hash)

      by_ref = {}
      supplied.each do |f|
        next unless validate_fact_wire(f).nil? # an unusable supplied fact can only matter if committed: caught below

        begin
          by_ref[fact_ref(f)] = f
        rescue StandardError
          nil # not strictly canonical (e.g. a lone surrogate): no reference, never matches a commitment
        end
      end
      worlds = wb_absent(wb_get(policy, 'worlds'), [])
      accepted = []
      pairs = {}
      committed_facts.each do |d|
        fact = by_ref.fetch(d, nil)
        return fail.call('a committed fact was not supplied (or is malformed)') if fact.nil?

        se = wb_artifact_suite_error(fact)
        return fail.call("fact signature suite: #{se}") if se

        w = worlds.find { |x| wb_strict_eq?(x['name'], fact['name']) }
        return fail.call("fact for undeclared world '#{fact['name']}'") if w.nil?

        pin = w['oracles'].find { |o| wb_strict_eq?(o['kid'], fact['oracle']) }
        return fail.call("oracle '#{fact['oracle']}' is not pinned for world '#{w['name']}'") if pin.nil?
        return fail.call("bad oracle signature on a '#{w['name']}' fact") unless wb_verify_artifact_sig(FACT_DOMAIN, fact, pin)

        subject = wb_subject_of(action, params, w['subject_path'])
        return fail.call("a '#{w['name']}' fact names another subject") if subject.nil? || !wb_strict_eq?(fact['subject'], subject)

        pair = [w['name'], fact['oracle']]
        return fail.call("two facts from oracle '#{fact['oracle']}' for world '#{w['name']}'") if pairs.key?(pair)

        pairs[pair] = true
        accepted << fact
      end

      now = wb_get(input, 'now')
      world = {}
      single_source = []
      worlds.each do |w|
        # A `now` that is not a safe integer (a string, a fraction, null) is no clock: every fact is stale (never coerced).
        fresh = if wb_clock?(now)
                  accepted.select do |f|
                    wb_strict_eq?(f['name'], w['name']) && wb_int(f['t_obs']) <= wb_int(now) + wb_int(skew) &&
                      wb_int(now) - wb_int(f['t_obs']) <= w['freshness_ms']
                  end
                else
                  []
                end
        if fresh.length < w['min_oracles']
          return fail.call("world '#{w['name']}' has #{fresh.length} fresh fact(s), needs #{wb_js_str(w['min_oracles'])}")
        end

        nums = fresh.select { |f| wb_num?(f['value']) }.map { |f| wb_int(f['value']) }
        if nums.length == fresh.length
          world[w['name']] = lower_median(nums)
        elsif nums.empty?
          v = fresh[0]['value']
          return fail.call("world '#{w['name']}': string facts disagree") if fresh.any? { |f| !wb_strict_eq?(f['value'], v) }

          world[w['name']] = v
        else
          return fail.call("world '#{w['name']}': facts mix integer and string values")
        end
        single_source << w['name'] if w['min_oracles'] == 1
      end

      operand = lambda do |path|
        if wb_starts?(path, WB_ENV_WORLD_PREFIX)
          v = wb_get(world, wb_after(path, WB_ENV_WORLD_PREFIX))
          return wb_safe_int?(v) ? wb_int(v) : nil
        end
        found, value = wb_resolve(params, path)
        found && wb_safe_int?(value) ? wb_int(value) : nil
      end
      wb_absent(wb_get(policy, 'relational'), []).each do |r|
        a = operand.call(r['a'])
        b = operand.call(r['b'])
        return fail.call("relational '#{r['name']}': an operand is missing or not a safe integer") if a.nil? || b.nil?

        v = wb_strict_eq?(r['fn'], 'sub') ? a - b : ratio_ppm(a, b)
        return fail.call("relational '#{r['name']}': result undefined or outside the safe integer range") if v.nil? || !wb_safe_int?(v)

        world[r['name']] = v
      end

      offers = wb_get(policy, 'offers')
      if wb_present?(offers)
        od = wb_decide_offer_set(offers, committed_offer, offer_in, params,
                                 wb_get(input, 'aud'), wb_get(input, 'session'), now, skew)
        return fail.call(od['reason']) unless od['ok']

        world[offers['name']] = od['excess']
      end
      { 'ok' => true, 'world' => world, 'single_source' => single_source }
    rescue StandardError => e
      fail.call("evaluation error (fail closed): #{e.message}")
    end
  end

  # ---- rule 17: label receipts and flow rules ---------------------------------------------------------------------------

  WB_LABELS_FIELDS = %w[v kind site session response_digest fields issued_at kid sig].freeze

  # Wire validation of a label receipt. nil = well-formed.
  def validate_labels_wire(l)
    return 'label receipt must be an object' unless l.is_a?(Hash)

    m = wb_closed_members(l, WB_LABELS_FIELDS, WB_SUITE_MEMBERS, 'labels')
    return m if m
    return 'label receipt must be {v: 1, kind: "pca-labels"}' if !wb_strict_eq?(l['v'], 1) || !wb_strict_eq?(l['kind'], 'pca-labels')
    return "'labels.site' must be a non-empty string (<= 256 bytes)" unless wb_bounded?(l['site'], 256)
    return "'labels.session' must be canonical base64url (32 bytes)" unless wb_digest?(l['session'])
    return "'labels.response_digest' must be canonical base64url (32 bytes)" unless wb_digest?(l['response_digest'])

    fields = l['fields']
    return "'labels.fields' must be an object" unless fields.is_a?(Hash)

    keys = wb_js_keys(fields)
    return "'labels.fields' must hold 1..#{MAX_LABEL_FIELDS} fields" if keys.empty? || keys.length > MAX_LABEL_FIELDS

    keys.each do |k|
      f = fields[k]
      return 'label field paths must be non-empty strings (<= 256 bytes)' unless wb_bounded?(k, 256)
      unless f.is_a?(Hash) && wb_closed_members(f, %w[class value_digest]).nil?
        return "label field '#{k}' must be exactly {class, value_digest}"
      end

      c = f['class']
      return "label field '#{k}': invalid data class" if !c.is_a?(String) || wb_utf16_len(c) > 128 || !wb_re?(WB_DATA_CLASS_RE, c)
      return "label field '#{k}': value_digest must be canonical base64url (32 bytes)" unless wb_digest?(f['value_digest'])
    end
    return "'labels.issued_at' must be a non-negative safe integer" if !wb_safe_int?(l['issued_at']) || l['issued_at'].negative?
    return "'labels.kid' must be a non-empty string (<= 64 bytes)" unless wb_bounded?(l['kid'], 64)
    return "'labels.sig' must be a string" unless l['sig'].is_a?(String)

    nil
  end

  # The content address committed in `intent_session.labels[]` and named by `pca-labels:<ref>#<field>` provenance refs.
  # Raises Malformed when non-canonical.
  def label_receipt_ref(l)
    wb_artifact_ref(LABELS_REF_DOMAIN, 'l', l)
  end

  # isLabelKey: a well-formed pinned label key {site, kid, pk, pq_pk?}.
  def label_key?(k)
    k.is_a?(Hash) && wb_closed_members(k, %w[site kid pk], %w[pq_pk], 'label_key').nil? && wb_bounded?(wb_get(k, 'site'), 256) && wb_bounded?(wb_get(k, 'kid'), 64) && wb_digest?(wb_get(k, 'pk')) &&
      wb_pin_pq_ok?(wb_get(k, 'pq_pk'))
  end

  # Verify a receipt's wire shape and signature under the key pinned for (site, kid). nil = valid. Total.
  def verify_labels(l, keys)
    w = validate_labels_wire(l)
    return w if w
    return 'label keys must be an array' unless keys.is_a?(Array)

    se = wb_artifact_suite_error(l)
    return "signature suite: #{se}" if se

    key = keys.find { |k| k.is_a?(Hash) && wb_strict_eq?(wb_get(k, 'site'), l['site']) && wb_strict_eq?(wb_get(k, 'kid'), l['kid']) }
    return "no pinned label key for site '#{l['site']}' kid '#{l['kid']}'" if key.nil?

    wb_verify_artifact_sig(LABELS_DOMAIN, l, key) ? nil : 'bad label receipt signature'
  end

  # Most specific matching flow pattern for a class (exact > longest `prefix.*` > `*`), or nil.
  def flow_rule_for(rules, cls)
    return nil unless rules.is_a?(Hash) && cls.is_a?(String)
    return cls if rules.key?(cls)

    best = nil
    wb_js_keys(rules).each do |p|
      next unless wb_ends?(p, '.*')

      prefix = p.byteslice(0, p.bytesize - 1) # keeps the dot: 'pii.' matches 'pii.contact', never 'piix'
      best = p if wb_starts?(cls, prefix) && (best.nil? || wb_utf16_len(p) > wb_utf16_len(best))
    end
    return best unless best.nil?

    rules.key?('*') ? '*' : nil
  end

  # May a value of class `cls`, labelled by `origin`, reach the sink audience `aud`? Back to its origin: yes. `public`:
  # yes. Otherwise the most specific flow rule must list `aud`; no matching rule: no.
  def flow_allowed(rules, cls, origin, aud)
    return false unless cls.is_a?(String) && origin.is_a?(String) && aud.is_a?(String)
    return true if wb_strict_eq?(aud, origin) || wb_strict_eq?(cls, PUBLIC_CLASS)

    p = flow_rule_for(rules, cls)
    return false if p.nil?

    sinks = rules[p]
    sinks.is_a?(Array) && sinks.any? { |s| wb_strict_eq?(s, aud) }
  end

  # Validate a flow rule set. nil = well-formed.
  def validate_flow_rules(rules)
    return 'flows must be an object' unless rules.is_a?(Hash)

    wb_js_keys(rules).each do |p|
      sinks = rules[p]
      base = if p == '*' then 'x'
             elsif wb_ends?(p, '.*') then p.byteslice(0, p.bytesize - 2)
             else p
             end
      return "flow pattern '#{p}' is not a class, a 'prefix.*' or '*'" unless wb_re?(WB_DATA_CLASS_RE, base)
      if !sinks.is_a?(Array) || sinks.any? { |s| !wb_bounded?(s, 256) }
        return "flow pattern '#{p}' needs a list of audiences"
      end
    end
    nil
  end

  # Read cell decision (V14, label-receipts.ts decideReadPurpose; conformance `primitives.intent_read_purpose`): input
  # { "fields" => [{ "path", "class", "optional"? }], "purpose", "coverage" => { purpose => [pattern] }, "on_uncovered"? }.
  # Malformed input (fields not an Array of Hashes with String `path` / `class` and an absent or boolean `optional`; a
  # non-String purpose; coverage not a Hash of String Arrays; `on_uncovered` present and not "question" / "deny"; JSON null
  # anywhere) is { "outcome" => "deny", "minimise" => [], "uncovered" => [] }. Otherwise `coverage[purpose]` is an OWN
  # member (an unknown or prototype-named purpose covers nothing but `public`); an uncovered field with `optional: true`
  # is minimised, any other uncovered field is uncovered; both lists are de-duplicated and sorted in UTF-8 BYTE order
  # (U+FFFD before U+1F600); outcome is "allow" when nothing is uncovered, else on_uncovered (default "question").
  # Never raises.
  def decide_read_purpose(input)
    malformed = { 'outcome' => 'deny', 'minimise' => [], 'uncovered' => [] }
    fields = wb_get(input, 'fields')
    purpose = wb_get(input, 'purpose')
    coverage = wb_get(input, 'coverage')
    on_unc = wb_absent(wb_get(input, 'on_uncovered'), 'question')
    return malformed unless fields.is_a?(Array) && purpose.is_a?(String) && coverage.is_a?(Hash) && %w[question deny].include?(on_unc)
    return malformed unless coverage.values.all? { |pats| pats.is_a?(Array) && pats.all? { |x| x.is_a?(String) } }

    fields.each do |f|
      ok = f.is_a?(Hash) && wb_get(f, 'path').is_a?(String) && wb_get(f, 'class').is_a?(String) &&
           (!wb_present?(wb_get(f, 'optional')) || wb_bool?(f['optional']))
      return malformed unless ok
    end
    patterns = coverage.key?(purpose) ? coverage[purpose] : []
    minimise = []
    uncovered = []
    fields.each do |f|
      cls = f['class']
      covered = cls == PUBLIC_CLASS || patterns.any? do |p|
        p == '*' || p == cls || (wb_ends?(p, '.*') && wb_starts?(cls, p.byteslice(0, p.bytesize - 1)))
      end
      next if covered

      (f['optional'].equal?(true) ? minimise : uncovered) << f['path']
    end
    sorted = ->(xs) { xs.uniq { |x| x.b }.sort_by(&:b) }
    { 'outcome' => uncovered.empty? ? 'allow' : on_unc, 'minimise' => sorted.call(minimise), 'uncovered' => sorted.call(uncovered) }
  rescue StandardError
    malformed
  end

  # ---- rule 17: provenance ----------------------------------------------------------------------------------------------

  # True only for the five level names.
  def taint_level?(kind)
    kind.is_a?(String) && TAINT_LEVELS.include?(kind)
  end

  # Rank of a level; an unknown level is the WORST rank (fail closed).
  def taint_rank(kind)
    taint_level?(kind) ? TAINT_LEVELS.index(kind) : TAINT_LEVELS.length - 1
  end

  # A `prov` key: one `action.params.<name>` segment, never a prototype name.
  def prov_path?(k)
    wb_re?(WB_PROV_PATH_RE, k) && !WB_FORBIDDEN_SEGMENTS.include?(wb_after(k, WB_PARAMS_PREFIX))
  end

  # Rule 17 step 0. nil = well-formed.
  def validate_provenance_policy(p)
    return 'provenance policy needs a params map' unless p.is_a?(Hash) && wb_get(p, 'params').is_a?(Hash)

    cm = wb_closed_members(p, %w[params], %w[registry label_keys critical_max material_tainted critical_tainted flows], 'policy')
    return cm if cm

    params = p['params']
    wb_js_keys(params).each do |k|
      return "policy param '#{k}' is not an action.params path" unless param_path?(k)
      unless wb_strict_eq?(params[k], 'material') || wb_strict_eq?(params[k], 'critical')
        return "policy param '#{k}': sensitivity must be material or critical"
      end
    end
    reg = wb_get(p, 'registry')
    if wb_present?(reg)
      return 'registry must be an object' unless reg.is_a?(Hash)

      wb_js_keys(reg).each do |k|
        return "registry entry '#{k}' must map to a taint level" unless wb_bounded?(k, 256) && taint_level?(reg[k])
      end
    end
    lk = wb_get(p, 'label_keys')
    if wb_present?(lk)
      return 'label_keys must be a list' unless lk.is_a?(Array)

      lk.each do |k|
        return 'every label key needs site, kid, a 32-byte pk and an optional string pq_pk' unless label_key?(k)
      end
    end
    cm = wb_get(p, 'critical_max')
    return 'critical_max must be a taint level' if wb_present?(cm) && !taint_level?(cm)

    mt = wb_get(p, 'material_tainted')
    if wb_present?(mt) && !(mt.is_a?(String) && WB_MODES.include?(mt))
      return 'material_tainted must be allow | question | question_typed | deny'
    end

    ct = wb_get(p, 'critical_tainted')
    if wb_present?(ct) && (wb_strict_eq?(ct, 'allow') || !(ct.is_a?(String) && WB_MODES.include?(ct)))
      return 'critical_tainted must be question | question_typed | deny'
    end

    fl = wb_get(p, 'flows')
    if wb_present?(fl)
      e = validate_flow_rules(fl)
      return e if e
    end
    nil
  end

  # Validate the `intent_session.prov` member. nil = well-formed.
  def validate_prov_wire(prov)
    return "'prov' must be an object" unless prov.is_a?(Hash)

    keys = wb_js_keys(prov)
    return "'prov' holds more than #{MAX_PROV_PATHS} paths" if keys.length > MAX_PROV_PATHS

    keys.each do |k|
      return "'prov' key '#{k}' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)" unless prov_path?(k)

      refs = prov[k]
      return "'prov.#{k}' must hold 1..#{MAX_PROV_REFS} refs" if !refs.is_a?(Array) || refs.empty? || refs.length > MAX_PROV_REFS

      refs.each { |r| return "'prov.#{k}' refs must be non-empty strings (<= 256 bytes)" unless wb_bounded?(r, 256) }
    end
    nil
  end

  # Parse `pca-labels:<ref>#<field>` (split at the FIRST '#'): { "receipt", "field" }, or nil when malformed.
  def parse_label_ref(ref)
    return nil unless ref.is_a?(String) && wb_starts?(ref, LABEL_REF_PREFIX)

    rest = wb_after(ref, LABEL_REF_PREFIX)
    i = rest.b.index('#')
    return nil if i.nil?

    receipt = rest.byteslice(0, i)
    field = rest.byteslice(i + 1, rest.bytesize - i - 1)
    wb_digest?(receipt) && !field.empty? ? { 'receipt' => receipt, 'field' => field } : nil
  end

  # NORMATIVE rule 17 (`provenance`): { "outcome" => "pass" | "question" | "deny", "reason"?, "friction"?, "labels",
  # "classes", "env" }. Steps 0-8 of param-provenance.ts decideParamProvenance; first failure wins. Never raises.
  def decide_param_provenance(input)
    labels = {}
    classes = {}
    deny = ->(reason) { { 'outcome' => 'deny', 'reason' => "provenance: #{reason}", 'labels' => labels, 'classes' => classes, 'env' => {} } }
    begin
      return deny.call('input must be an object') unless input.is_a?(Hash)

      policy = wb_member(input, 'policy')
      pe = validate_provenance_policy(policy)
      return deny.call("policy misconfigured (fail closed): #{pe}") if pe

      # ABSENT optional members mean empty / default; PRESENT ones of the wrong JSON type (null included) deny.
      prov = wb_absent(wb_get(input, 'prov'), {})
      we = validate_prov_wire(prov)
      return deny.call(we) if we

      committed = wb_absent(wb_get(input, 'committed_labels'), [])
      if !committed.is_a?(Array) || committed.length > MAX_COMMITTED_LABELS
        return deny.call("committed labels must be a list of at most #{MAX_COMMITTED_LABELS} digests")
      end

      committed_set = {}
      committed.each do |d|
        return deny.call('committed labels must be distinct canonical 32-byte digests') if !wb_digest?(d) || committed_set.key?(d)

        committed_set[d] = true
      end
      action = wb_get(input, 'action')
      return deny.call('action must be an object') unless action.is_a?(Hash)

      params = wb_absent(wb_get(action, 'params'), {})
      return deny.call('action.params must be an object') unless params.is_a?(Hash)

      supplied = wb_absent(wb_get(input, 'labels'), [])
      return deny.call('labels must be an array') unless supplied.is_a?(Array)

      label_keys = wb_absent(wb_get(policy, 'label_keys'), [])
      reg = wb_absent(wb_get(policy, 'registry'), {})
      flows = wb_absent(wb_get(policy, 'flows'), {})
      paths = prov.keys.sort # UTF-8 byte order (compareUtf8)
      paths.each { |p| return deny.call("prov names '#{p}', a parameter the action does not carry") unless wb_resolve(params, p)[0] }
      paths.each do |a|
        paths.each { |b| return deny.call("prov paths '#{a}' and '#{b}' overlap") if a != b && b.start_with?("#{a}.") }
      end

      receipts = {}
      supplied.each do |r|
        receipts[label_receipt_ref(r)] = r if validate_labels_wire(r).nil?
      rescue StandardError
        nil # not strictly canonical: no reference, never matches a commitment
      end
      aud = wb_get(input, 'aud')
      session = wb_get(input, 'session')
      origins = {}

      paths.each do |p|
        value = wb_resolve(params, p)[1]
        ranks = []
        prov[p].each do |ref|
          unless wb_starts?(ref, LABEL_REF_PREFIX)
            # classifyRef against the injected registry (own entries only); anything it cannot vouch for is agent.
            ranks << taint_rank(reg.key?(ref) && taint_level?(reg[ref]) ? reg[ref] : 'agent')
            next
          end
          lr = parse_label_ref(ref)
          return deny.call("malformed label ref on '#{p}'") if lr.nil?
          return deny.call("label ref on '#{p}' names a receipt the PCActn does not commit") unless committed_set.key?(lr['receipt'])

          rc = receipts.fetch(lr['receipt'], nil)
          return deny.call("label receipt for '#{p}' was not supplied") if rc.nil?

          ve = verify_labels(rc, label_keys)
          return deny.call("label receipt for '#{p}': #{ve}") if ve
          return deny.call("label receipt for '#{p}' is bound to another session") unless wb_strict_eq?(rc['session'], session)
          return deny.call("label receipt for '#{p}' has no field '#{lr['field']}'") unless rc['fields'].key?(lr['field'])

          field = rc['fields'][lr['field']]
          match = begin
            wb_hash(value) == field['value_digest']
          rescue StandardError
            false
          end
          ranks << if match
                     taint_rank(wb_strict_eq?(rc['site'], aud) ? 'first_party' : 'tool')
                   else
                     taint_rank('agent')
                   end
          (origins[p] ||= []) << [field['class'], rc['site']]
        end
        labels[p] = ranks.empty? ? 'agent' : TAINT_LEVELS[ranks.max] # joinLabels([]) is TOP
      end
      pol_params = policy['params']
      pol_params.keys.sort.each do |p|
        next if labels.key?(p)

        labels[p] = 'agent' if wb_resolve(params, p)[0]
      end
      origins.keys.sort.each do |p|
        classes[p] = origins[p].map(&:first).uniq.sort
        origins[p].each do |cls, origin|
          unless flow_allowed(flows, cls, origin, aud)
            return deny.call("flow: class '#{cls}' from '#{origin}' may not reach '#{wb_js_str(aud)}' (parameter '#{p}')")
          end
        end
      end
      critical_max = wb_get(policy, 'critical_max')
      cap_rank = taint_rank(wb_absent(critical_max, 'agent'))
      sens = ->(p) { pol_params.key?(p) ? pol_params[p] : WB_UNDEF }
      labels.keys.sort.each do |p|
        if wb_strict_eq?(sens.call(p), 'critical') && taint_rank(labels[p]) > cap_rank
          return deny.call("critical parameter '#{p}' has provenance '#{labels[p]}', above the policy maximum '#{wb_js_str(critical_max)}'")
        end
      end
      question = false
      typed = false
      labels.keys.sort.each do |p|
        s = sens.call(p)
        next if s.equal?(WB_UNDEF) || taint_rank(labels[p]) < WB_TAINTED_RANK

        mode = if wb_strict_eq?(s, 'critical')
                 wb_absent(wb_get(policy, 'critical_tainted'), 'question_typed')
               else
                 wb_absent(wb_get(policy, 'material_tainted'), 'question')
               end
        return deny.call("tainted #{s} parameter '#{p}' (provenance '#{labels[p]}') is denied by policy") if mode == 'deny'

        question = true if %w[question question_typed].include?(mode)
        typed = true if mode == 'question_typed'
      end
      env = {}
      labels.keys.sort.each { |p| return deny.call("provenance paths overlap at '#{p}'") unless wb_set_nested(env, p, labels[p]) }
      if question
        { 'outcome' => 'question', 'reason' => 'provenance: a tainted value needs the principal (lazy question)',
          'friction' => typed ? 'typed' : 'tap', 'labels' => labels, 'classes' => classes, 'env' => env }
      else
        { 'outcome' => 'pass', 'labels' => labels, 'classes' => classes, 'env' => env }
      end
    rescue StandardError => e
      deny.call("evaluation error (fail closed): #{e.message}")
    end
  end

  # ---- rule 18: classifier verdicts -------------------------------------------------------------------------------------

  WB_VERDICT_FIELDS = %w[v kind classifier session content_digest label measurement judge sig].freeze

  # Wire validation of a classifier verdict. nil = well-formed.
  def validate_classifier_verdict_wire(v)
    return 'verdict must be an object' unless v.is_a?(Hash)

    m = wb_closed_members(v, WB_VERDICT_FIELDS, WB_SUITE_MEMBERS, 'verdict')
    return m if m
    if !wb_strict_eq?(v['v'], 1) || !wb_strict_eq?(v['kind'], 'pca-intent-classification')
      return 'verdict must be {v: 1, kind: "pca-intent-classification"}'
    end
    return "'verdict.classifier' must match ^[a-z][a-z0-9_]{0,63}$" unless wb_re?(WB_INTENT_NAME_RE, v['classifier'])
    return "'verdict.session' must be canonical base64url (32 bytes)" unless wb_digest?(v['session'])
    return "'verdict.content_digest' must be canonical base64url (32 bytes)" unless wb_digest?(v['content_digest'])
    return "'verdict.label' must be a non-empty string (<= 64 bytes)" unless wb_bounded?(v['label'], 64)
    return "'verdict.measurement' must be a non-empty string (<= 256 bytes)" unless wb_bounded?(v['measurement'], 256)
    return "'verdict.judge' must be canonical base64url (32 bytes)" unless wb_digest?(v['judge'])
    return "'verdict.sig' must be a string" unless v['sig'].is_a?(String)

    nil
  end

  # The content address committed in `intent_session.classes[]`. Raises Malformed when non-canonical.
  def classifier_verdict_ref(v)
    wb_artifact_ref(INTENT_CLASSIFIER_REF_DOMAIN, 'c', v)
  end

  # Rule 18 step 0. nil = well-formed.
  def validate_classifier_policy(p)
    return 'classifier policy needs a classifiers list' unless p.is_a?(Hash) && wb_get(p, 'classifiers').is_a?(Array)

    cm = wb_closed_members(p, %w[classifiers], [], 'policy')
    return cm if cm

    ids = {}
    p['classifiers'].each do |c|
      cid = wb_get(c, 'id')
      if !c.is_a?(Hash) || !wb_closed_members(c, %w[id param labels keys k], %w[measurements pq_keys], 'classifier').nil?
        return 'every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}'
      end
      if !wb_re?(WB_INTENT_NAME_RE, cid) || ids.key?(cid)
        return 'every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$'
      end

      ids[cid] = true
      return "classifier '#{cid}': param must be an action.params path" unless param_path?(wb_get(c, 'param'))

      labs = wb_get(c, 'labels')
      if !labs.is_a?(Array) || labs.empty? || labs.length > MAX_CLASSIFIER_LABELS
        return "classifier '#{cid}': labels must hold 1..#{MAX_CLASSIFIER_LABELS} strings"
      end
      if labs.any? { |l| !wb_bounded?(l, 64) } || labs.map(&:b).uniq.length != labs.length
        return "classifier '#{cid}': labels must be distinct non-empty strings"
      end

      keys = wb_get(c, 'keys')
      if !keys.is_a?(Array) || keys.empty? || keys.any? { |k| !wb_digest?(k) } || keys.uniq.length != keys.length
        return "classifier '#{cid}': keys must be distinct 32-byte keys"
      end

      k = wb_get(c, 'k')
      return "classifier '#{cid}': k must be an integer in [1, #{keys.length}]" if !wb_safe_int?(k) || k < 1 || k > keys.length

      ms = wb_get(c, 'measurements')
      if wb_present?(ms) && (!ms.is_a?(Array) || ms.any? { |m| !m.is_a?(String) })
        return "classifier '#{cid}': measurements must be a list of strings"
      end
      pq = wb_get(c, 'pq_keys')
      if wb_present?(pq) && (!pq.is_a?(Hash) || pq.any? { |k, v| !keys.include?(k) || !v.is_a?(String) || v.empty? })
        return "classifier '#{cid}': pq_keys must map allowlisted keys to PQ keys"
      end
    end
    nil
  end

  # The pinned signer of a verdict: the allowlisted judge key and, when the classifier pins one (`pq_keys`, own member), its
  # PQ key.
  def wb_judge_pin(c, judge)
    pqk = wb_get(c, 'pq_keys')
    pq = pqk.is_a?(Hash) ? wb_get(pqk, judge) : WB_UNDEF
    pq.equal?(WB_UNDEF) ? { 'pk' => judge } : { 'pk' => judge, 'pq_pk' => pq }
  end

  # Is the rule-18 check active? Iff `committed` or `policy.classifiers` is a non-empty ARRAY (strict typing).
  def classifier_check_active(input)
    return false unless input.is_a?(Hash) # total: a non-object input has no members

    wb_non_empty_array?(wb_get(input, 'committed')) || wb_non_empty_array?(wb_get(wb_get(input, 'policy'), 'classifiers'))
  end

  # NORMATIVE rule 18 (`classes`): { "ok" => true, "classes", "votes" } or { "ok" => false, "reason" }. Steps 0-4 of
  # intent-classifier.ts decideClassifierDimensions; first failure wins. Never raises.
  def decide_classifier_dimensions(input)
    fail = ->(reason) { { 'ok' => false, 'reason' => "classes: #{reason}" } }
    begin
      return fail.call('input must be an object') unless input.is_a?(Hash)

      policy = wb_member(input, 'policy')
      pe = validate_classifier_policy(policy)
      return fail.call("policy misconfigured (fail closed): #{pe}") if pe

      # ABSENT optional members mean empty / default; PRESENT ones of the wrong JSON type (null included) fail.
      committed = wb_absent(wb_get(input, 'committed'), [])
      if !committed.is_a?(Array) || committed.length > MAX_COMMITTED_CLASSES
        return fail.call("committed verdicts must be a list of at most #{MAX_COMMITTED_CLASSES} digests")
      end

      seen = {}
      committed.each do |d|
        return fail.call('committed verdicts must be distinct canonical 32-byte digests') if !wb_digest?(d) || seen.key?(d)

        seen[d] = true
      end
      supplied = wb_absent(wb_get(input, 'verdicts'), [])
      return fail.call('verdicts must be an array') unless supplied.is_a?(Array)

      action = wb_get(input, 'action')
      return fail.call('action must be an object') unless action.is_a?(Hash)

      params = wb_absent(wb_get(action, 'params'), {})
      return fail.call('action.params must be an object') unless params.is_a?(Hash)

      by_ref = {}
      supplied.each do |v|
        next unless validate_classifier_verdict_wire(v).nil?

        begin
          by_ref[classifier_verdict_ref(v)] = v
        rescue StandardError
          nil # not strictly canonical: no reference
        end
      end
      session = wb_get(input, 'session')
      classifiers = policy['classifiers']
      votes = {}
      pairs = {}
      committed.each do |d|
        v = by_ref.fetch(d, nil)
        return fail.call('a committed verdict was not supplied (or is malformed)') if v.nil?

        se = wb_artifact_suite_error(v)
        return fail.call("verdict signature suite: #{se}") if se

        c = classifiers.find { |x| wb_strict_eq?(x['id'], v['classifier']) }
        return fail.call("verdict for undeclared classifier '#{v['classifier']}'") if c.nil?

        cid = c['id']
        return fail.call("classifier '#{cid}': judge key is not on the allowlist") unless c['keys'].any? { |k| wb_strict_eq?(k, v['judge']) }
        return fail.call("classifier '#{cid}': bad verdict signature") unless wb_verify_artifact_sig(INTENT_CLASSIFIER_DOMAIN, v, wb_judge_pin(c, v['judge']))
        return fail.call("classifier '#{cid}': verdict bound to another session") unless wb_strict_eq?(v['session'], session)

        found, content = wb_resolve(params, c['param'])
        return fail.call("classifier '#{cid}': the action carries no '#{c['param']}'") unless found
        return fail.call("classifier '#{cid}': verdict is about other content") if classifier_content_digest(content) != v['content_digest']
        unless c['labels'].any? { |l| wb_strict_eq?(l, v['label']) }
          return fail.call("classifier '#{cid}': label '#{v['label']}' is not in its label set")
        end
        if c.key?('measurements') && c['measurements'].none? { |m| wb_strict_eq?(m, v['measurement']) }
          return fail.call("classifier '#{cid}': measurement is not pinned")
        end

        pair = [cid, v['judge']]
        return fail.call("classifier '#{cid}': two verdicts from one judge") if pairs.key?(pair)

        pairs[pair] = true
        t = (votes[cid] ||= {})
        t[v['label']] = t.fetch(v['label'], 0) + 1
      end
      out = {}
      classifiers.each do |c|
        t = votes.fetch(c['id'], {})
        winners = c['labels'].select { |l| t.fetch(l, 0) >= c['k'] }
        return fail.call("classifier '#{c['id']}': no label reaches the quorum #{wb_js_str(c['k'])}") if winners.empty?
        return fail.call("classifier '#{c['id']}': ambiguous, #{winners.length} labels reach the quorum") if winners.length > 1

        out[c['id']] = winners[0]
      end
      { 'ok' => true, 'classes' => out, 'votes' => votes }
    rescue StandardError => e
      fail.call("evaluation error (fail closed): #{e.message}")
    end
  end

  # ---- composition (intent-env.ts) --------------------------------------------------------------------------------------

  # Set `h[k] = v` unless `v` is undefined (an absent member stays absent).
  def wb_put(h, k, v)
    h[k] = v unless v.equal?(WB_UNDEF)
    h
  end

  # Is the rule-17 check active? Iff `prov` is present (any value, JSON null included: rule 17 then judges it), `labels` is
  # a non-empty ARRAY, or `policy` is a plain object (not nil, not an Array). Strict typing, like rules 16 and 18.
  def intent_provenance_active(x)
    return false unless x.is_a?(Hash) # total: a non-object input has no members

    wb_present?(wb_get(x, 'prov')) || wb_non_empty_array?(wb_get(x, 'labels')) || wb_get(x, 'policy').is_a?(Hash)
  end

  # Which W-B checks a verifier reports (conformance `primitives.intent_wb_active`, reference intentWBActive): input
  # { "intent_session", "policy" => { "world"?, "provenance"?, "classifiers"? } } -> { "facts", "provenance", "classes" }
  # booleans. Members are read strictly: own members of Hashes only (a container absent or not a Hash has none).
  def intent_wb_active(input)
    s = wb_get(input, 'intent_session')
    p = wb_get(input, 'policy')
    committed = wb_put(wb_put({}, 'facts', wb_get(s, 'facts')), 'offer_set', wb_get(s, 'offer_set'))
    prov = wb_put(wb_put(wb_put({}, 'prov', wb_get(s, 'prov')), 'labels', wb_get(s, 'labels')), 'policy', wb_get(p, 'provenance'))
    cls = wb_put({ 'policy' => wb_put({}, 'classifiers', wb_get(p, 'classifiers')) }, 'committed', wb_get(s, 'classes'))
    { 'facts' => intent_world_active(wb_put({ 'committed' => committed }, 'policy', wb_get(p, 'world'))),
      'provenance' => intent_provenance_active(prov), 'classes' => classifier_check_active(cls) }
  end

  # intentWBContextError (intent-env.ts), the shape rule for the W-B context (absent vs null): `intent_session` a Hash;
  # `artifacts` absent or a Hash whose `facts` / `labels` / `verdicts` are absent or Arrays and whose `offer_set` is absent
  # or a Hash; `policy` absent or a Hash whose `world` / `provenance` are absent or Hashes and whose `classifiers` is absent
  # or an Array. JSON null anywhere here is malformed. `input` = { "intent_session", "artifacts"?, "policy"? } (the
  # decide_intent_wb input). nil = well-formed.
  def intent_wb_context_error(input)
    return 'input must be an object' unless input.is_a?(Hash)
    return 'intent_session must be an object' unless wb_get(input, 'intent_session').is_a?(Hash)

    a = wb_get(input, 'artifacts')
    if wb_present?(a)
      return 'artifacts must be an object' unless a.is_a?(Hash)

      am = wb_closed_members(a, [], %w[facts labels verdicts offer_set], 'artifacts')
      return am if am

      %w[facts labels verdicts].each { |k| return "artifacts.#{k} must be an array" if wb_present?(wb_get(a, k)) && !wb_get(a, k).is_a?(Array) }
      return 'artifacts.offer_set must be an object' if wb_present?(wb_get(a, 'offer_set')) && !wb_get(a, 'offer_set').is_a?(Hash)
    end
    p = wb_get(input, 'policy')
    if wb_present?(p)
      return 'policy must be an object' unless p.is_a?(Hash)

      pm = wb_closed_members(p, [], %w[world provenance classifiers], 'policy')
      return pm if pm

      %w[world provenance].each { |k| return "policy.#{k} must be an object" if wb_present?(wb_get(p, k)) && !wb_get(p, k).is_a?(Hash) }
      return 'policy.classifiers must be an array' if wb_present?(wb_get(p, 'classifiers')) && !wb_get(p, 'classifiers').is_a?(Array)
    end
    nil
  end

  # A W-B deny carries the checks and the reason ONLY: no friction, no env, no single_source from an earlier check of the unit
  # (a deny after a provenance question used to keep its `friction`, and a later fail kept the earlier env).
  def wb_deny(checks, reason) = { 'outcome' => 'deny', 'checks' => checks, 'env' => {}, 'reason' => reason }

  # The W-B checks of an Intent Layer v2 verifier, rules 16, 17 and 18 in order (spec section 5): { "outcome" => "admit" |
  # "question" | "deny", "checks" => { "facts"?, "provenance"?, "classes"? => "pass" | "question" | "fail" }, "env" =>
  # { "world"?, "prov"?, "class"? }, "reason"?, "friction"?, "single_source"? }. `input` = { "now", "aud", "session",
  # "action", "intent_session" => { "facts"?, "offer_set"?, "prov"?, "classes"?, "labels"? }, "artifacts"? => { "facts"?,
  # "offer_set"?, "labels"?, "verdicts"? }, "policy"? => { "world"?, "provenance"?, "classifiers"? } }. A malformed W-B
  # context (intent_wb_context_error) fails `facts`, the first check of the unit. Each check is reported only when its
  # member is present or its policy is active; the first failing check denies and later checks are not reported; a
  # provenance question does not end the unit. Never raises: a non-object input is a malformed context and any internal
  # error is a `facts` failure (fail closed).
  def decide_intent_wb(input)
    out = { 'outcome' => 'admit', 'checks' => {}, 'env' => {} }
    ce = intent_wb_context_error(input)
    return wb_deny({ 'facts' => 'fail' }, "facts: the W-B context is malformed: #{ce}") if ce

    s = input['intent_session']
    a = wb_absent(wb_get(input, 'artifacts'), {})
    pol = wb_absent(wb_get(input, 'policy'), {})
    committed = {}
    wb_put(committed, 'facts', wb_get(s, 'facts'))
    wb_put(committed, 'offer_set', wb_get(s, 'offer_set'))
    world_policy = wb_absent(wb_get(pol, 'world'), {})
    if intent_world_active({ 'committed' => committed, 'policy' => world_policy })
      wi = {}
      %w[now aud session action].each { |k| wb_put(wi, k, wb_get(input, k)) }
      wi['committed'] = committed
      wb_put(wi, 'facts', wb_get(a, 'facts'))
      wb_put(wi, 'offer_set', wb_get(a, 'offer_set'))
      wi['policy'] = world_policy
      w = decide_intent_world(wi)
      return wb_deny(out['checks'].merge('facts' => 'fail'), w['reason']) unless w['ok']

      out['checks']['facts'] = 'pass'
      out['env']['world'] = w['world']
      out['single_source'] = w['single_source'] unless w['single_source'].empty?
    end
    s_prov = wb_get(s, 'prov')
    s_labels = wb_get(s, 'labels')
    pol_prov = wb_get(pol, 'provenance')
    if intent_provenance_active(wb_put(wb_put(wb_put({}, 'prov', s_prov), 'labels', s_labels), 'policy', pol_prov))
      pi = {}
      %w[aud session action].each { |k| wb_put(pi, k, wb_get(input, k)) }
      wb_put(pi, 'prov', s_prov)
      wb_put(pi, 'committed_labels', s_labels)
      wb_put(pi, 'labels', wb_get(a, 'labels'))
      pi['policy'] = wb_absent(pol_prov, { 'params' => {} })
      p = decide_param_provenance(pi)
      if p['outcome'] == 'deny'
        return wb_deny(out['checks'].merge('provenance' => 'fail'), p['reason'])
      end

      out['checks']['provenance'] = p['outcome'] == 'question' ? 'question' : 'pass'
      out['env']['prov'] = p['env']
      if p['outcome'] == 'question'
        out['outcome'] = 'question'
        out['reason'] = p['reason']
        out['friction'] = p['friction']
      end
    end
    cls_policy = { 'classifiers' => wb_absent(wb_get(pol, 'classifiers'), []) }
    s_classes = wb_get(s, 'classes')
    if classifier_check_active(wb_put({ 'policy' => cls_policy }, 'committed', s_classes))
      ci = {}
      %w[session action].each { |k| wb_put(ci, k, wb_get(input, k)) }
      wb_put(ci, 'committed', s_classes)
      wb_put(ci, 'verdicts', wb_get(a, 'verdicts'))
      ci['policy'] = cls_policy
      c = decide_classifier_dimensions(ci)
      return wb_deny(out['checks'].merge('classes' => 'fail'), c['reason']) unless c['ok']

      out['checks']['classes'] = 'pass'
      out['env']['class'] = c['classes']
    end
    out
  rescue StandardError, SystemStackError => e
    { 'outcome' => 'deny', 'checks' => { 'facts' => 'fail' }, 'env' => {}, 'reason' => "facts: evaluation error (fail closed): #{e.message}" }
  end
end
