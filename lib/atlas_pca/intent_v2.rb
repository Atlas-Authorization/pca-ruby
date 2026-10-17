# frozen_string_literal: true

# Intent Layer v2, wire batch W-A (conformance rules 13, 14, 15 and the v2 verification pipeline): a port of the STRICT
# TypeScript reference in packages/pca/src - action-schema.ts (verifier side), intent-session.ts,
# intent-session-caveat.ts, intent-acc.ts (verifier side), intent-revocation.ts with the revocation.ts epoch and
# non-membership rules it needs, intent-strict.ts, the pq.ts verifyPinnedSuite seam, and intent-v2.ts (decideIntentV2).
# The W-B unit (rules 16-18) is AtlasPca.decide_intent_wb (intent_wb.rb); the V5 ceilings AtlasPca.decide_layer_ceilings
# (intent_layers.rb).
#
# Strict values (README "Intent Layer v2: strict values, absent vs null, suite capability"): nothing depends on a
# language's coercions.
#   - Numbers are judged by VALUE: Integer 5 and Float 5.0 are the same JSON number (a safe integer; canonical "5");
#     -0.0, fractions, NaN / Infinity, null, numeric strings fail a numeric field closed.
#   - Lists must be Arrays, records Hashes (String keys, own members only; an own "__proto__" key is data). A member
#     ABSENT means empty / default; PRESENT with JSON null it is malformed (only an accumulator's `key: null` is a value).
#   - Regexes anchor the whole string (\A ... \z); a string with a lone surrogate (invalid UTF-8 from the loose parser)
#     never matches. Keys sort by UTF-8 bytes; reasons name the first offending key in JSON (Object.keys) order.
#   - Suite capability: every v2 signature goes through the SDK's own suite dispatch (resolve_suite / verify_suite /
#     resolve_pq_key, SIG_SUITES). An `alg` the dispatch does not implement fails closed with a reason containing
#     `unsupported_suite`; a post-quantum signature verifies only under a PQ key pinned by the trusted side.
# Every public decide / verify function is total: an internal error fails the check being evaluated, where the TS
# try/catch is.
module AtlasPca
  # ======================= strict value helpers (internal) =======================
  module V2JS
    class StrictError < StandardError; end

    # An ABSENT member (distinct from JSON null, nil).
    UNDEF = Object.new.tap { |o| o.define_singleton_method(:inspect) { 'undefined' } }.freeze
    INDEX_RE = /\A(?:0|[1-9][0-9]*)\z/
    MAX_SAFE_INT = (2**53) - 1

    module_function

    def undef?(x) = x.equal?(UNDEF)
    def nullish?(x) = x.nil? || x.equal?(UNDEF)
    # `x ?? d`
    def nullish_or(x, d) = nullish?(x) ? d : x

    # The OWN member `k` of a JSON object, else UNDEF (`ownGet` / the `!== undefined` presence test).
    def prop(o, k) = o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF

    # `o?.[k]` over plain objects (UNDEF when `o` is absent / null / not an object).
    def opt(o, k) = prop(o, k)

    # A String viewed as UTF-8 (the loose parser writes a lone surrogate as WTF-8 bytes: an invalid UTF-8 string).
    def u8(s) = s.encoding == Encoding::UTF_8 ? s : s.dup.force_encoding(Encoding::UTF_8)

    # A string without lone surrogates.
    def ustr?(x) = x.is_a?(String) && u8(x).valid_encoding?
    def bool?(x) = x == true || x == false
    def num?(x) = x.is_a?(Integer) || x.is_a?(Float)
    def neg_zero?(x) = x.is_a?(Float) && x.zero? && (1.0 / x).negative?

    # A safe integer by VALUE (|n| <= 2^53-1), not -0 (`isSafeInt` of intent-strict.ts).
    def int?(x)
      return x.abs <= MAX_SAFE_INT if x.is_a?(Integer)

      x.is_a?(Float) && x.finite? && x == x.truncate && x.abs <= MAX_SAFE_INT && !neg_zero?(x)
    end

    def nonneg?(x) = int?(x) && x >= 0
    # A safe-integer value as a Ruby Integer.
    def ival(x) = x.is_a?(Float) ? x.to_i : x

    # JS truthiness of a JSON value (where the TS tests a value it found, e.g. `if (!doc)`).
    def truthy?(x)
      return false if nullish?(x) || x == false
      return !x.zero? && !(x.is_a?(Float) && x.nan?) if num?(x)
      return !x.empty? if x.is_a?(String)

      true
    end

    # JSON value equality as the TS `===` reads it on JSON values: same type and value (5 === 5.0; strings by bytes;
    # containers by identity).
    def strict_eq(a, b)
      return a.equal?(b) if undef?(a) || undef?(b)
      return bool?(b) && a == b if bool?(a)
      return false if bool?(b)
      return a == b if num?(a) && num?(b)
      return a.b == b.b if a.is_a?(String) && b.is_a?(String)
      return a.nil? && b.nil? if a.nil? || b.nil?

      a.equal?(b)
    end

    # The number of UTF-16 code units (JS `.length`).
    def u16len(s)
      u8(s).b.scan(/[\x00-\xbf]|[\xc0-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xf7][\x80-\xbf]{3}|./n).sum { |c| c.bytesize == 4 ? 2 : 1 }
    end

    # Template interpolation of a JSON value in a reason (diagnostic only).
    def js_str(x)
      return 'undefined' if undef?(x)
      return 'null' if x.nil?
      return x if x.is_a?(String)
      return x.to_i.to_s if x.is_a?(Float) && x.finite? && x == x.truncate && x.abs < 1e21

      x.to_s
    end

    # `Object.keys(h)` order: canonical array-index keys ascending, then the other keys in insertion order.
    def js_keys(h)
      idx, rest = h.keys.partition { |k| k.is_a?(String) && k.match?(INDEX_RE) && k.to_i <= 4_294_967_294 }
      idx.sort_by(&:to_i) + rest
    end

    # The UTF-8 bytes TextEncoder writes (a lone surrogate becomes U+FFFD).
    def te_bytes(s) = u8(s).b.gsub(/\xED[\xA0-\xBF][\x80-\xBF]/n, "\xEF\xBF\xBD".b)

    # compareUtf8 (hash.ts): UTF-8 byte order (equal bytes for distinct strings, possible only with lone surrogates,
    # fall back to the raw bytes).
    def compare_utf8(a, b)
      return 0 if a.b == b.b

      x = te_bytes(a)
      y = te_bytes(b)
      x == y ? a.b <=> b.b : x <=> y
    end

    def sort_utf8(xs) = xs.sort { |a, b| compare_utf8(a, b) }

    # `Object.keys(h).sort().join()` (the names compared here are ASCII, where code-unit and byte order agree).
    def sorted_join(h) = h.keys.map { |k| k.to_s.b }.sort.join(',')

    # `new Set(xs).size === xs.length` for an array of strings.
    def distinct_strs?(xs) = xs.map(&:b).uniq.length == xs.length

    # `re.test(s)` for an anchored ASCII regex.
    def rx?(re, s) = s.is_a?(String) && u8(s).valid_encoding? && u8(s).match?(re)

    # `s.slice(n)` for the ASCII prefix 'action.params.'.
    def slice_from(s, n)
      raise StrictError, 'not a string' unless s.is_a?(String)

      s.length > n ? s[n..] : ''
    end

    # A deep copy with JSON number values: an integral Float becomes the Integer it equals (5.0 IS the JSON number 5 and
    # canonicalises as "5"); -0.0, fractions and non-finite Floats are kept (the strict checks and the canonicaliser
    # refuse them). Symbol keys become String keys. Containers deeper than 64 are kept as they are (the canonicaliser
    # refuses anything deeper than 32 anyway).
    def jsnorm(v, depth = 0)
      return v if depth > 64

      case v
      when Hash then v.each_with_object({}) { |(k, x), h| h[k.is_a?(Symbol) ? k.to_s : k] = jsnorm(x, depth + 1) }
      when Array then v.map { |x| jsnorm(x, depth + 1) }
      when Float then v.finite? && v == v.truncate && !neg_zero?(v) && v.abs <= MAX_SAFE_INT ? v.to_i : v
      else v
      end
    end
  end

  # ======================= the W-A rules (internal implementation) =======================
  module IntentV2
    extend AtlasPca
    extend V2JS
    module_function

    UNDEF = V2JS::UNDEF
    StrictError = V2JS::StrictError

    def bad(reason) = { 'ok' => false, 'reason' => reason }
    def okv(extra = {}) = { 'ok' => true }.merge(extra)
    def in_strs?(x, list) = x.is_a?(String) && list.include?(x)
    # `isStr(v, max)`: a non-empty string without lone surrogates of at most `max` UTF-8 bytes.
    def is_str?(v, max = 256) = ustr?(v) && !v.empty? && v.bytesize <= max
    def b32v?(x) = !b64d(x, 32).nil?
    def present?(o, k) = o.is_a?(Hash) && o.key?(k)

    # ---- suite capability over the SDK's own dispatch (intent-strict.ts suiteCapabilityError, pq.ts) ---------------

    UNSUPPORTED_SUITE = 'unsupported_suite'
    # Names the predicate DSL cannot address: refused as accumulator / monitor ids and schema parameter names.
    RESERVED_NAMES = %w[__proto__ constructor prototype].freeze

    # True iff the SDK's suite dispatch (resolve_suite / verify_suite) can verify `alg` in THIS runtime: its capability
    # manifest `supported_suites` (in the dispatch table AND its backend available, the OpenSSL probe), so a suite in the
    # table whose backend is missing is refused with `unsupported_suite`, and a suite added behind the dispatch is picked
    # up here without a second list.
    def implemented_suite?(alg) = alg.is_a?(String) && AtlasPca.supported_suites.include?(alg)

    # `suiteCapabilityError(alg)`: absent -> nil (ed25519); a non-string -> malformed; a string the dispatch does not
    # implement -> "unsupported_suite: '<alg>'".
    def suite_err(alg)
      return nil if undef?(alg)
      return 'alg must be a string' unless alg.is_a?(String)

      implemented_suite?(alg) ? nil : "#{UNSUPPORTED_SUITE}: '#{alg}'"
    end

    # suite_err for a session root's SHAPE: a registered suite (REGISTERED_SUITES, the TS registry) passes even when this
    # runtime cannot run it, so verify_session_root's verifier-pin checks (no crypto) run before availability, in the
    # reference's order; verify_session_root refuses an unavailable signer suite after the pins.
    def suite_known_err(alg)
      return nil if undef?(alg)
      return 'alg must be a string' unless alg.is_a?(String)

      AtlasPca::REGISTERED_SUITES.include?(alg) ? nil : "#{UNSUPPORTED_SUITE}: '#{alg}'"
    end

    # The suite of an `alg` value (UNDEF -> ed25519; an unimplemented / malformed one -> nil).
    def suite_of(alg)
      return 'ed25519' if undef?(alg)

      implemented_suite?(alg) ? alg : nil
    end

    # `bindSuiteFields(base, alg, pqPk)`: a non-ed25519 suite binds `alg` and `pq_pk` into the signed body (an ABSENT pq_pk
    # cannot be canonicalised: it raises like the TS canonicaliser on `undefined`).
    def bind_suite_fields(base, alg, pq_pk)
      suite = suite_of(alg)
      return base if suite.nil? || suite == 'ed25519'
      raise StrictError, 'canonicalize: unsupported type undefined' if undef?(pq_pk)

      base.merge('alg' => suite, 'pq_pk' => pq_pk)
    end

    # `verifyPinnedSuite(alg, identity, artifactPqPk, msg, {sig, pq_sig}, {pqPins: pins})` through the SDK dispatch:
    # ed25519 verifies under `identity`; any other suite only under a PQ key pinned for `identity`
    # (`pins[identity] == artifact_pq_pk`, resolve_pq_key). Total.
    def verify_pinned_suite(alg, identity, artifact_pq_pk, msg, sig, pq_sig, pins)
      suite = suite_of(alg)
      return false if suite.nil?

      pq = nil
      if suite != 'ed25519'
        pq = resolve_pq_key(identity, undef?(artifact_pq_pk) ? nil : artifact_pq_pk, pq_pins: pins)
        return false if pq.nil?
      end
      p = { 'alg' => suite, 'sig' => sig }
      p['pq_sig'] = pq_sig unless undef?(pq_sig)
      sig.is_a?(String) && identity.is_a?(String) && verify_suite(p, identity, msg, pq)
    rescue StandardError
      false
    end

    # A domain-separated message: utf8(domain) || strictCanonical(body).
    def dmsg(domain, body) = domain.b + canon_bytes(body)

    # ---- rule 14: signed action schemas (action-schema.ts) -------------------------------------------------------

    ACTION_SCHEMA_DOMAIN = "atlas-pca/action-schema/v1\x00"
    ACTION_SCHEMA_REF_DOMAIN = 'atlas-pca/action-schema-ref/v1'
    ACTION_SCHEMA_KIND = 'pca-action-schema'
    SENSITIVITIES = %w[free material critical].freeze
    SCHEMA_REVERSIBILITY = %w[reversible rate_limited irreversible].freeze
    PARAM_TYPES = %w[string integer boolean date set array].freeze
    MAX_SCHEMA_VERBS = 256
    MAX_SCHEMA_PARAMS = 64
    MAX_SCHEMA_VALUES = 256
    DEFAULT_MAX_LEN = 1024
    DEFAULT_MAX_ITEMS = 64
    PARAM_PATH_RE = /\Aaction\.params\.[A-Za-z0-9_]{1,64}\z/
    UNIT_ID_RE = /\A[a-z0-9_]+(?:\.[a-z0-9_]+)*\z/
    PARAMS_PREFIX_LEN = 14 # 'action.params.'.length
    DOC_KEYS = %w[v kind site aud version units state verbs sig].freeze
    VERB_KEYS = %w[verb kind params reversibility reversibility_by mcp openapi harm world effects returns description].freeze
    PARAM_KEYS = %w[type semantic sensitivity required values min max unit max_len items min_items max_items default
                    principal_neutral_default accumulates_into issued_by_site description].freeze
    SIG_KEYS = %w[alg kid value pq_value].freeze

    def param_decl_error(path, d, units)
      return "parameter path '#{path}' is not action.params.<name>" unless rx?(PARAM_PATH_RE, path)
      if RESERVED_NAMES.include?(slice_from(path, PARAMS_PREFIX_LEN))
        return "parameter name '#{path}' is reserved (__proto__ / constructor / prototype)"
      end
      return "#{path}: declaration must be an object" unless d.is_a?(Hash)

      js_keys(d).each { |k| return "#{path}: unknown member '#{k}'" unless PARAM_KEYS.include?(k) }
      t = d['type']
      return "#{path}: unknown type" unless in_strs?(t, PARAM_TYPES)
      return "#{path}: semantic must be a non-empty string" unless is_str?(d['semantic'], 128)
      return "#{path}: unknown sensitivity" unless in_strs?(d['sensitivity'], SENSITIVITIES)
      return "#{path}: required must be a boolean" if d.key?('required') && !bool?(d['required'])

      if d.key?('values')
        vs = d['values']
        if !vs.is_a?(Array) || vs.empty? || vs.length > MAX_SCHEMA_VALUES || !vs.all? { |x| is_str?(x) }
          return "#{path}: values must be 1..#{MAX_SCHEMA_VALUES} strings"
        end
        return "#{path}: values must be distinct" unless distinct_strs?(vs)
        return "#{path}: values apply to string and set only" if t != 'string' && t != 'set'
      end
      return "#{path}: a set needs values" if t == 'set' && !d.key?('values')

      %w[min max].each do |k|
        next unless d.key?(k)
        if !int?(d[k]) || (t != 'integer' && !(t == 'array' && strict_eq(prop(d, 'items'), 'integer')))
          return "#{path}: #{k} must be a safe integer on an integer parameter"
        end
      end
      return "#{path}: min > max" if int?(d['min']) && int?(d['max']) && d['min'] > d['max']
      if d.key?('unit') && (t != 'integer' || !d['unit'].is_a?(String) || !units.is_a?(Hash) || !units.key?(d['unit']))
        return "#{path}: unit must name a declared unit of an integer parameter"
      end
      return "#{path}: max_len must be a positive safe integer" if d.key?('max_len') && (!int?(d['max_len']) || d['max_len'] < 1)
      return "#{path}: items applies to array only" if d.key?('items') && (t != 'array' || !is_str?(d['items'], 64))

      %w[min_items max_items].each do |k|
        next unless d.key?(k)
        return "#{path}: #{k} must be a non-negative safe integer on a set or array" if !nonneg?(d[k]) || (t != 'set' && t != 'array')
      end
      return "#{path}: min_items > max_items" if int?(d['min_items']) && int?(d['max_items']) && d['min_items'] > d['max_items']
      if d.key?('principal_neutral_default') && !bool?(d['principal_neutral_default'])
        return "#{path}: principal_neutral_default must be a boolean"
      end
      return "#{path}: principal_neutral_default needs a default" if d['principal_neutral_default'] == true && !d.key?('default')
      return "#{path}: default must not be null (absent = no default)" if d.key?('default') && d['default'].nil?

      if d.key?('accumulates_into')
        return "#{path}: accumulates_into applies to integer parameters only" if t != 'integer'

        ai = d['accumulates_into']
        return "#{path}: accumulates_into must be 1..8 unit ids" if !ai.is_a?(Array) || ai.empty? || ai.length > 8
        return "#{path}: accumulates_into entries must be unit ids" unless ai.all? { |u| u.is_a?(String) && u16len(u) <= 64 && rx?(UNIT_ID_RE, u) }
        return "#{path}: accumulates_into must be distinct" unless distinct_strs?(ai)
      end
      return "#{path}: issued_by_site must be a boolean" if d.key?('issued_by_site') && !bool?(d['issued_by_site'])
      return "#{path}: description must be a string" if d.key?('description') && !is_str?(d['description'], 1024)

      nil
    end

    def verb_decl_error(v, units)
      return 'verb entry must be an object' unless v.is_a?(Hash)

      js_keys(v).each { |k| return "verb entry: unknown member '#{k}'" unless VERB_KEYS.include?(k) }
      return 'verb entry: verb must be a non-empty string' unless is_str?(v['verb'], 128)

      at = "verb '#{v['verb']}'"
      return "#{at}: kind must be read or write" unless in_strs?(v['kind'], %w[read write])

      params = v['params']
      return "#{at}: params must be an object" unless params.is_a?(Hash)

      names = js_keys(params)
      return "#{at}: more than #{MAX_SCHEMA_PARAMS} parameters" if names.length > MAX_SCHEMA_PARAMS

      names.each do |p|
        e = param_decl_error(p, params[p], units)
        return "#{at}: #{e}" if e
      end
      return "#{at}: unknown reversibility" if v.key?('reversibility') && !in_strs?(v['reversibility'], SCHEMA_REVERSIBILITY)

      if v.key?('reversibility_by')
        r = v['reversibility_by']
        return "#{at}: reversibility_by must be {param, map, default?}" if !r.is_a?(Hash) || r.keys.any? { |k| !%w[param map default].include?(k) }
        return "#{at}: reversibility_by.param must be a declared parameter" if !r['param'].is_a?(String) || !params.key?(r['param'])

        m = r['map']
        if !m.is_a?(Hash) || m.empty? || !m.values.all? { |x| in_strs?(x, SCHEMA_REVERSIBILITY) }
          return "#{at}: reversibility_by.map must map values to reversibility classes"
        end
        return "#{at}: reversibility_by.default is not a reversibility class" if r.key?('default') && !in_strs?(r['default'], SCHEMA_REVERSIBILITY)
      end
      if v.key?('mcp') && (!v['mcp'].is_a?(Hash) || js_keys(v['mcp']).join(',') != 'tool' || !is_str?(v['mcp']['tool'], 128))
        return "#{at}: mcp must be {tool}"
      end
      if v.key?('openapi') && (!v['openapi'].is_a?(Hash) || js_keys(v['openapi']).join(',') != 'operationId' || !is_str?(v['openapi']['operationId'], 128))
        return "#{at}: openapi must be {operationId}"
      end
      %w[harm effects returns].each { |k| return "#{at}: #{k} must be an object" if v.key?(k) && !v[k].is_a?(Hash) }
      return "#{at}: world must be an array" if v.key?('world') && !v['world'].is_a?(Array)
      return "#{at}: description must be a string" if v.key?('description') && !is_str?(v['description'], 1024)

      nil
    end

    # Structural validation of an (optionally unsigned) schema document. nil = well-formed.
    def action_schema_shape_error(doc, signed = true)
      return 'schema is not an object' unless doc.is_a?(Hash)

      js_keys(doc).each { |k| return "unknown member '#{k}'" unless DOC_KEYS.include?(k) }
      return 'unsupported schema version' unless strict_eq(prop(doc, 'v'), 1)
      return "kind must be '#{ACTION_SCHEMA_KIND}'" unless strict_eq(prop(doc, 'kind'), ACTION_SCHEMA_KIND)
      unless is_str?(doc['site'], 2048) && is_str?(doc['aud'], 256) && is_str?(doc['version'], 128)
        return 'site, aud and version must be non-empty strings'
      end

      units = doc.key?('units') ? doc['units'] : nil
      if doc.key?('units')
        return 'units must be an object' unless units.is_a?(Hash)

        js_keys(units).each do |id|
          u = units[id]
          return "unit id '#{id}' is malformed" if !rx?(UNIT_ID_RE, id) || u16len(id) > 64
          return "unit '#{id}' must be an object with a kind" unless u.is_a?(Hash) && is_str?(u['kind'], 64)
          return "unit '#{id}': unknown member" if u.keys.any? { |k| !%w[kind currency exponent].include?(k) }
          return "unit '#{id}': currency must be a string" if u.key?('currency') && !is_str?(u['currency'], 16)
          return "unit '#{id}': exponent must be an integer in [0, 18]" if u.key?('exponent') && !(nonneg?(u['exponent']) && u['exponent'] <= 18)
        end
      end
      return 'state must be an array' if doc.key?('state') && !doc['state'].is_a?(Array)

      verbs = doc['verbs']
      return "verbs must be 1..#{MAX_SCHEMA_VERBS} entries" if !verbs.is_a?(Array) || verbs.empty? || verbs.length > MAX_SCHEMA_VERBS

      seen = {}
      verbs.each do |v|
        e = verb_decl_error(v, units)
        return e if e

        name = v['verb'].b
        return "verb '#{v['verb']}' is declared twice" if seen.key?(name)

        seen[name] = true
      end
      if signed
        s = doc['sig']
        return 'sig must be an object' unless s.is_a?(Hash)

        js_keys(s).each { |k| return "sig: unknown member '#{k}'" unless SIG_KEYS.include?(k) }
        se = suite_err(prop(s, 'alg'))
        return "sig.alg: #{se}" if se
        return 'sig.kid must be a non-empty string' unless is_str?(s['kid'], 128)
        return 'sig.value is not canonical base64url' if b64d(s['value']).nil?
        return 'sig.pq_value is not canonical base64url' if s.key?('pq_value') && b64d(s['pq_value']).nil?
      elsif doc.key?('sig')
        return 'an unsigned schema must not carry sig'
      end
      canon_bytes(doc.reject { |k, _| k == 'sig' }) # raises on a non-strict number / lone surrogate / excessive depth
      nil
    rescue StandardError, SystemStackError => e
      "malformed schema: #{e.message}"
    end

    def schema_message(doc) = dmsg(ACTION_SCHEMA_DOMAIN, doc.reject { |k, _| k == 'sig' })

    # Verify a site-signed schema against the discovery key list: shape, kid, the suite PINNED by the key entry, the
    # signature (a PQ key only as the key entry pins it). Total.
    def verify_action_schema(doc, keys)
      shape = action_schema_shape_error(doc)
      return bad(shape) if shape
      return bad('the schema keys must be an array') unless keys.is_a?(Array)

      sig = doc['sig']
      key = keys.find { |k| k.is_a?(Hash) && strict_eq(prop(k, 'kid'), sig['kid']) }
      return bad("no schema key with kid '#{sig['kid']}'") if key.nil?
      return bad('the schema key pq_pk must be a string') if key.key?('pq_pk') && !key['pq_pk'].is_a?(String)
      return bad('schema key pk is not canonical base64url (32 bytes)') if b64d(key['pk'], 32).nil?

      kse = suite_err(prop(key, 'alg'))
      return bad("schema key: #{kse}") if kse

      ka = suite_of(prop(key, 'alg'))
      return bad('sig.alg does not match the pinned key suite') if ka.nil? || ka != suite_of(prop(sig, 'alg'))

      pq = prop(key, 'pq_pk')
      pins = undef?(pq) ? nil : { key['pk'] => pq }
      unless verify_pinned_suite(ka, key['pk'], pq, schema_message(doc), prop(sig, 'value'), prop(sig, 'pq_value'), pins)
        return bad('schema signature invalid')
      end

      okv
    rescue StandardError, SystemStackError => e
      bad("schema verification error: #{e.message}")
    end

    # The schema's content address (over the whole signed document). Raises on a non-canonical document.
    def action_schema_digest(doc) = hash_canonical({ 'd' => ACTION_SCHEMA_REF_DOMAIN, 's' => doc })

    # The verb entry named `verb`, or nil. A null entry raises (the TS reads `v.verb` on it); other non-objects never match.
    def schema_verb(doc, verb)
      vs = prop(doc, 'verbs')
      return nil unless vs.is_a?(Array)

      vs.find do |v|
        raise StrictError, "Cannot read properties of null (reading 'verb')" if v.nil?

        v.is_a?(Hash) && strict_eq(prop(v, 'verb'), verb)
      end
    end

    DATE_RE = /\A([0-9]{4})-([0-9]{2})-([0-9]{2})\z/
    DAYS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31].freeze

    # `YYYY-MM-DD` and a Gregorian calendar date (years 0001-9999; leap /4 except /100 unless /400).
    def calendar_date?(s)
      return false unless rx?(DATE_RE, s)

      m = DATE_RE.match(u8(s))
      y = m[1].to_i
      mo = m[2].to_i
      d = m[3].to_i
      return false if y < 1 || mo < 1 || mo > 12 || d < 1

      leap = (y % 4).zero? && (!(y % 100).zero? || (y % 400).zero?)
      d <= (mo == 2 && leap ? 29 : DAYS[mo - 1])
    end

    def bt(reason) = { 'code' => 'bad_type', 'reason' => reason }
    def ood(reason) = { 'code' => 'out_of_domain', 'reason' => reason }

    # A declaration member read as the TS does on a decl object (absent -> UNDEF; a non-object decl raises).
    def decl(d, k)
      raise StrictError, "Cannot read properties of #{js_str(d)} (reading '#{k}')" unless d.is_a?(Hash)

      prop(d, k)
    end

    # Value check of one declared parameter: nil = in the declared domain, else {code, reason}.
    def param_value_violation(d, x)
      ml = decl(d, 'max_len')
      max_len = nullish?(ml) ? DEFAULT_MAX_LEN : ml
      t = decl(d, 'type')
      t = nil unless t.is_a?(String)
      case t
      when 'string'
        return bt('expected a string') unless ustr?(x)
        return ood("longer than #{js_str(max_len)} UTF-8 bytes") if x.bytesize > max_len

        vals = decl(d, 'values')
        return ood('not one of the declared values') if !undef?(vals) && vals.none? { |e| strict_eq(e, x) }

        nil
      when 'integer'
        return bt('expected a safe integer') unless int?(x)

        mn = decl(d, 'min')
        return ood("below min #{js_str(mn)}") if !undef?(mn) && x < mn

        mx = decl(d, 'max')
        return ood("above max #{js_str(mx)}") if !undef?(mx) && x > mx

        nil
      when 'boolean'
        bool?(x) ? nil : bt('expected a boolean')
      when 'date'
        return bt('expected a YYYY-MM-DD string') unless x.is_a?(String)

        calendar_date?(x) ? nil : ood('not a calendar date YYYY-MM-DD')
      when 'set'
        return bt('expected an array of strings') unless x.is_a?(Array) && x.all? { |e| e.is_a?(String) }
        return ood('set members must be distinct') unless distinct_strs?(x)

        vals = decl(d, 'values')
        return ood('set member not among the declared values') unless x.all? { |e| vals.any? { |v| strict_eq(v, e) } }

        mi = decl(d, 'min_items')
        ma = decl(d, 'max_items')
        if x.length < (nullish?(mi) ? 0 : mi) || x.length > (nullish?(ma) ? vals.length : ma)
          return ood('set size outside the declared bounds')
        end

        nil
      when 'array'
        return bt('expected an array') unless x.is_a?(Array)

        ints = strict_eq(decl(d, 'items'), 'integer')
        mn = decl(d, 'min')
        mx = decl(d, 'max')
        x.each do |e|
          if ints ? !int?(e) : !(ustr?(e) && e.bytesize <= max_len)
            return bt(ints ? 'array items must be safe integers' : "array items must be strings of at most #{js_str(max_len)} UTF-8 bytes")
          end
          return ood('array item outside min/max') if ints && ((!undef?(mn) && e < mn) || (!undef?(mx) && e > mx))
        end
        mi = decl(d, 'min_items')
        ma = decl(d, 'max_items')
        if x.length < (nullish?(mi) ? 0 : mi) || x.length > (nullish?(ma) ? DEFAULT_MAX_ITEMS : ma)
          return ood('array length outside the declared bounds')
        end

        nil
      else
        bt('unknown declared type')
      end
    end

    # Map an action to Omega_S or to the fail-closed cell (rule 14 step 5). First failure wins: params_not_object,
    # unknown_verb, undeclared_param (params keys in UTF-8 byte order), then per declared path in UTF-8 byte order
    # missing_param / bad_type / out_of_domain. Own members only (an own "__proto__" key is an ordinary undeclared name).
    def conform_action(doc, verb, params)
      return { 'ok' => false, 'code' => 'params_not_object', 'reason' => 'params must be a JSON object' } unless params.is_a?(Hash)

      v = schema_verb(doc, verb)
      return { 'ok' => false, 'code' => 'unknown_verb', 'reason' => "verb '#{js_str(verb)}' is not declared by the schema" } if v.nil?

      vp = v['params']
      sort_utf8(params.keys).each do |k|
        path = "action.params.#{k}"
        unless present?(vp, path)
          return { 'ok' => false, 'code' => 'undeclared_param', 'path' => path, 'reason' => "parameter '#{path}' is not declared for '#{js_str(verb)}'" }
        end
      end
      raise StrictError, 'Cannot convert undefined or null to object' unless vp.is_a?(Hash)

      sort_utf8(vp.keys).each do |path|
        d = vp[path]
        name = slice_from(path, PARAMS_PREFIX_LEN)
        unless params.key?(name)
          next if strict_eq(decl(d, 'required'), false)

          return { 'ok' => false, 'code' => 'missing_param', 'path' => path, 'reason' => "required parameter '#{path}' is missing" }
        end
        b = param_value_violation(d, params[name])
        return { 'ok' => false, 'code' => b['code'], 'path' => path, 'reason' => "'#{path}': #{b['reason']}" } if b
      end
      { 'ok' => true, 'verb' => v }
    end

    # Every integer parameter of a verb entry that feeds `unit`, in UTF-8 byte order.
    def accumulation_params(v, unit)
      vp = prop(v, 'params')
      raise StrictError, 'Cannot convert undefined or null to object' unless vp.is_a?(Hash)

      ks = vp.keys.select do |p|
        d = vp[p]
        next false unless strict_eq(decl(d, 'type'), 'integer')

        ai = nullish_or(prop(d, 'accumulates_into'), [])
        raise StrictError, 'accumulates_into must be an array' unless ai.is_a?(Array)

        ai.any? { |u| strict_eq(u, unit) }
      end
      sort_utf8(ks)
    end

    # `env.canon` for a conforming action: boolean "true"/"false", set = canonical JSON of its members sorted by UTF-8
    # bytes, array = canonical JSON as sent; only PRESENT parameters.
    def canon_projection(doc, verb, params)
      v = schema_verb(doc, verb)
      out = {}
      return out if v.nil?

      sort_utf8(v['params'].keys).each do |path|
        d = v['params'][path]
        name = slice_from(path, PARAMS_PREFIX_LEN)
        next unless params.key?(name)

        x = params[name]
        case d['type']
        when 'boolean' then out[name] = x == true ? 'true' : 'false'
        when 'set' then out[name] = canonicalize(sort_utf8(x))
        when 'array' then out[name] = canonicalize(x)
        end
      end
      out
    end

    # ---- rule 13: the intent_session member, the grant caveat and the session root ----------------------------------

    INTENT_SESSION_CAVEAT = 'intent_session'
    MAX_SESSION_SEQ = 2_147_483_647
    INTENT_SESSION_KIND = 'pca-intent-session'
    INTENT_SESSION_SIG_DOMAIN = "atlas-pca/intent-session/v1\x00"
    INTENT_SESSION_REF_DOMAIN = 'atlas-pca/intent-session-ref/v1'
    INTENT_GOAL_V2_PREFIX = 'pca-intent:v2:'
    MAX_IS_ACC = 16
    MAX_IS_FACTS = 16
    MAX_IS_PROV_PATHS = 32
    MAX_IS_PROV_REFS = 8
    MAX_IS_CLASSES = 8
    MAX_IS_LABELS = 16
    MAX_IS_STRING_BYTES = 256
    INTENT_GOAL_V2C_PREFIX = 'pca-intent:v2c:'
    MAP_FORM_COMMIT = 'commit'
    INTENT_SESSION_FIELDS = %w[session root seq schema acc facts offer_set prov classes labels map_form].freeze
    ACC_ID_RE = /\A[A-Za-z0-9_]{1,64}\z/
    MAX_SESSION_PRINCIPALS = 16
    ROOT_KEYS = %w[v kind session principals intent_ref schema layers accumulators monitors question_uri revocation flows
                   expires_at signer alg pq_pk sig pq_sig].freeze

    # Shape of an `intent_session` grant caveat: exactly {type, session, seq, root, prev?}, prev present iff seq > 0.
    def intent_session_caveat_error(c)
      return 'not an intent_session caveat' unless c.is_a?(Hash) && strict_eq(prop(c, 'type'), INTENT_SESSION_CAVEAT)

      js_keys(c).each { |k| return "intent_session caveat: unknown member '#{k}'" unless %w[type session seq root prev].include?(k) }
      return 'intent_session caveat: session and root must be canonical base64url (32 bytes)' unless b32v?(c['session']) && b32v?(c['root'])
      return 'intent_session caveat: seq must be a safe integer in [0, 2147483647]' if !nonneg?(c['seq']) || c['seq'] > MAX_SESSION_SEQ
      return 'intent_session caveat: prev is present exactly when seq > 0' if (c['seq'] == 0) == c.key?('prev')
      return 'intent_session caveat: prev must be canonical base64url (32 bytes)' if c.key?('prev') && !b32v?(c['prev'])

      nil
    end

    def digest_list_error(v, name, max)
      return "'intent_session.#{name}' must be an array of at most #{max} digests" if !v.is_a?(Array) || v.length > max
      return "'intent_session.#{name}' entries must be canonical base64url (32 bytes)" unless v.all? { |x| b32v?(x) }
      return "'intent_session.#{name}' entries must be distinct" unless distinct_strs?(v)

      nil
    end

    def short_str?(v) = ustr?(v) && !v.empty? && v.bytesize <= MAX_IS_STRING_BYTES

    # Wire validation of the PCActn member `intent_session` (part of the terminal `wire` check). nil = well-formed.
    def validate_intent_session_wire(v)
      return "'intent_session' must be an object" unless v.is_a?(Hash)

      js_keys(v).each { |k| return "unknown field 'intent_session.#{k}'" unless INTENT_SESSION_FIELDS.include?(k) }
      %w[session root seq schema].each { |k| return "missing field 'intent_session.#{k}'" unless v.key?(k) }
      %w[session root schema].each { |k| return "'intent_session.#{k}' is not canonical base64url (32 bytes)" unless b32v?(v[k]) }
      return "'intent_session.seq' must be a safe integer in [0, 2147483647]" if !nonneg?(v['seq']) || v['seq'] > MAX_SESSION_SEQ

      if v.key?('acc')
        acc = v['acc']
        return "'intent_session.acc' must be an array of at most #{MAX_IS_ACC} entries" if !acc.is_a?(Array) || acc.length > MAX_IS_ACC

        ids = {}
        acc.each_with_index do |a, i|
          return "'intent_session.acc[#{i}]' must be an object" unless a.is_a?(Hash)

          js_keys(a).each { |k| return "unknown field 'intent_session.acc[#{i}].#{k}'" unless %w[id post receipt].include?(k) }
          return "'intent_session.acc[#{i}].id' must match [A-Za-z0-9_]{1,64}" unless rx?(ACC_ID_RE, a['id'])
          return "'intent_session.acc' ids must be distinct" if ids.key?(a['id'])

          ids[a['id']] = true
          return "'intent_session.acc[#{i}].post' must be a non-negative safe integer" unless nonneg?(a['post'])
          return "'intent_session.acc[#{i}].receipt' is not canonical base64url (32 bytes)" if a.key?('receipt') && !b32v?(a['receipt'])
        end
      end
      if v.key?('facts')
        e = digest_list_error(v['facts'], 'facts', MAX_IS_FACTS)
        return e if e
      end
      return "'intent_session.offer_set' is not canonical base64url (32 bytes)" if v.key?('offer_set') && !b32v?(v['offer_set'])

      if v.key?('prov')
        pv = v['prov']
        return "'intent_session.prov' must be an object of at most #{MAX_IS_PROV_PATHS} entries" if !pv.is_a?(Hash) || pv.length > MAX_IS_PROV_PATHS

        js_keys(pv).each do |path|
          refs = pv[path]
          return "'intent_session.prov' key '#{path}' is not action.params.<name>" unless rx?(PARAM_PATH_RE, path)
          if !refs.is_a?(Array) || refs.empty? || refs.length > MAX_IS_PROV_REFS || !refs.all? { |r| short_str?(r) }
            return "'intent_session.prov.#{path}' must be 1..#{MAX_IS_PROV_REFS} non-empty strings of at most #{MAX_IS_STRING_BYTES} UTF-8 bytes"
          end
        end
      end
      if v.key?('classes')
        e = digest_list_error(v['classes'], 'classes', MAX_IS_CLASSES)
        return e if e
      end
      if v.key?('labels')
        e = digest_list_error(v['labels'], 'labels', MAX_IS_LABELS)
        return e if e
      end
      return "'intent_session.map_form' must be \"commit\" when present" if v.key?('map_form') && !strict_eq(v['map_form'], MAP_FORM_COMMIT)

      nil
    end

    # The goal a session grant commits to: `pca-intent:v2:<session>:<map_digest>` (`pca-intent:v2c:` over a committed map).
    def intent_goal_v2(session, map_digest, map_form = nil)
      "#{map_form == MAP_FORM_COMMIT ? INTENT_GOAL_V2C_PREFIX : INTENT_GOAL_V2_PREFIX}#{session}:#{map_digest}"
    end

    # The FIRST caveat of `grant` whose type is `intent_session` (as is), or nil.
    def grant_session_caveat(grant)
      return nil unless grant.is_a?(Hash) && grant['caveats'].is_a?(Array)

      grant['caveats'].find { |c| c.is_a?(Hash) && strict_eq(prop(c, 'type'), INTENT_SESSION_CAVEAT) }
    end

    def session_root_shape_error(s, signed = true)
      return 'session root is not an object' unless s.is_a?(Hash)

      js_keys(s).each { |k| return "session root: unknown member '#{k}'" unless ROOT_KEYS.include?(k) }
      return 'not a pca-intent-session v1' unless strict_eq(prop(s, 'v'), 1) && strict_eq(prop(s, 'kind'), INTENT_SESSION_KIND)
      return 'session and intent_ref must be canonical base64url (32 bytes)' unless b32v?(s['session']) && b32v?(s['intent_ref'])

      pr = s['principals']
      return "principals must be 1..#{MAX_SESSION_PRINCIPALS} keys" if !pr.is_a?(Array) || pr.empty? || pr.length > MAX_SESSION_PRINCIPALS

      keys = {}
      pr.each do |p|
        if !p.is_a?(Hash) || p.keys.any? { |k| !%w[key alg pq_pk].include?(k) } || !b32v?(p['key'])
          return 'principals entries are {key, alg?, pq_pk?} with a 32-byte key'
        end

        pe = suite_known_err(prop(p, 'alg'))
        return "principal alg: #{pe}" if pe
        return 'principal pq_pk is not canonical base64url' if p.key?('pq_pk') && b64d(p['pq_pk']).nil?
        return 'principal keys must be distinct' if keys.key?(p['key'])

        keys[p['key']] = true
      end
      sc = s['schema']
      if !sc.is_a?(Hash) || sorted_join(sc) != 'aud,digest' || !sc['aud'].is_a?(String) || sc['aud'].empty? || !b32v?(sc['digest'])
        return 'schema must be {aud, digest}'
      end

      l = s['layers']
      return 'layers must be an object' unless l.is_a?(Hash)

      js_keys(l).each { |k| return "layers: unknown member '#{k}'" unless %w[org std task].include?(k) }
      task = l['task']
      return 'layers.task must be {map_digest}' unless task.is_a?(Hash) && js_keys(task).join(',') == 'map_digest' && b32v?(task['map_digest'])
      if l.key?('org') && (!l['org'].is_a?(Hash) || !b32v?(l['org']['digest']))
        return 'layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)'
      end

      if l.key?('std')
        d = l['std']
        if !d.is_a?(Hash) || sorted_join(d) != 'digest,profile,version' || !d['profile'].is_a?(String) || d['profile'].empty? ||
           d['profile'].bytesize > 128 || !(int?(d['version']) && d['version'] >= 1) || !b32v?(d['digest'])
          return 'layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)'
        end
      end
      accs = s['accumulators']
      return "accumulators must be an array of at most #{MAX_SESSION_ACCUMULATORS}" if !accs.is_a?(Array) || accs.length > MAX_SESSION_ACCUMULATORS

      ids = {}
      accs.each do |a|
        e = accumulator_decl_error(a)
        return e if e
        return 'accumulator and monitor ids must be distinct' if ids.key?(a['id'])

        ids[a['id']] = true
      end
      mons = s['monitors']
      return "monitors must be an array of at most #{MAX_SESSION_MONITORS}" if !mons.is_a?(Array) || mons.length > MAX_SESSION_MONITORS

      mids = {}
      mons.each do |m|
        e = monitor_decl_error(m)
        return e if e
        return 'monitor ids must be distinct' if mids.key?(m['id'])

        mids[m['id']] = true
      end
      q = s['question_uri']
      return 'question_uri must be a non-empty string' if !q.is_a?(String) || q.empty? || q.bytesize > 2048

      if s.key?('revocation')
        r = s['revocation']
        if !r.is_a?(Hash) || r.keys.any? { |k| !%w[epoch_uri max_age_s key pq_pk].include?(k) }
          return 'revocation must be {epoch_uri, max_age_s, key, pq_pk?}'
        end
        return 'revocation.epoch_uri must be a non-empty string' if !r['epoch_uri'].is_a?(String) || r['epoch_uri'].empty?
        return 'revocation.max_age_s must be a non-negative safe integer' unless nonneg?(r['max_age_s'])
        return 'revocation.key (the dedicated revocation authority) is required: canonical base64url (32 bytes)' unless b32v?(r['key'])
        return 'revocation.key must not be a session principal (a dedicated revocation authority)' if keys.key?(r['key'])
        return 'revocation.pq_pk must be canonical base64url' if r.key?('pq_pk') && b64d(r['pq_pk']).nil?
      end
      return 'flows must be an object' if s.key?('flows') && !s['flows'].is_a?(Hash)
      return 'expires_at must be a non-negative safe integer (epoch ms)' unless nonneg?(s['expires_at'])

      if signed
        return 'signer must be canonical base64url (32 bytes)' unless b32v?(s['signer'])
        return 'signer is not one of the session principals' unless keys.key?(s['signer'])

        se = suite_known_err(prop(s, 'alg'))
        return "alg: #{se}" if se
        return 'an ed25519 session root must not carry pq_pk / pq_sig' if suite_of(prop(s, 'alg')) == 'ed25519' && (s.key?('pq_pk') || s.key?('pq_sig'))
        return 'sig must be a string' unless s['sig'].is_a?(String)
      end
      canon_bytes(session_root_body(s))
      nil
    rescue StandardError, SystemStackError => e
      "malformed session root: #{e.message}"
    end

    def session_root_body(s)
      out = %w[v kind session principals intent_ref schema layers accumulators monitors question_uri].to_h { |k| [k, s.fetch(k)] }
      out['revocation'] = s['revocation'] if s.key?('revocation')
      out['flows'] = s['flows'] if s.key?('flows')
      out['expires_at'] = s.fetch('expires_at')
      out
    end

    # Verify S: shape, signer listed, suite signature. R3-01 (fail closed): a non-ed25519 root verifies only under the
    # VERIFIER's pin for its signer (`pq_pins` = context session.pq_pins, a Hash whose member for the signer is a String),
    # never under the root's own principals[].pq_pk; the signer's own entry, when it declares a pq_pk, must agree. An
    # ed25519 root never consults the pins.
    def verify_session_root(s, pq_pins = nil)
      shape = session_root_shape_error(s)
      return bad(shape) if shape

      p = s['principals'].find { |x| strict_eq(x['key'], s['signer']) }
      suite = undef?(prop(s, 'alg')) ? 'ed25519' : prop(s, 'alg') # a registered name (session_root_shape_error)
      pins = nil
      if suite != 'ed25519'
        pin = pq_pins.is_a?(Hash) && pq_pins.key?(s['signer']) ? pq_pins[s['signer']] : nil
        unless pin.is_a?(String)
          return bad("session root suite '#{suite}' needs the signer's PQ key pinned by the verifier (pq_pins); the root's own principals entry proves nothing about who signed it")
        end
        return bad("session root pq_pk does not match the verifier's pin for the signer") unless strict_eq(prop(s, 'pq_pk'), pin)

        entry = prop(p, 'pq_pk')
        return bad("session root pq_pk does not match the signer's principals entry") if !undef?(entry) && !strict_eq(entry, prop(s, 'pq_pk'))

        pins = { s['signer'] => pin }
      end
      se = suite_err(prop(s, 'alg')) # availability in this runtime, AFTER the pins (the reference's order)
      return bad("alg: #{se}") if se

      body = bind_suite_fields(session_root_body(s).merge('signer' => s['signer']), prop(s, 'alg'), prop(s, 'pq_pk'))
      unless verify_pinned_suite(prop(s, 'alg'), s['signer'], prop(s, 'pq_pk'), dmsg(INTENT_SESSION_SIG_DOMAIN, body), prop(s, 'sig'), prop(s, 'pq_sig'), pins)
        return bad('session root signature invalid')
      end

      okv
    rescue StandardError, SystemStackError => e
      bad("malformed session root: #{e.message}")
    end

    # digest(S): the content address of the whole signed session root.
    def session_root_digest(s) = hash_canonical({ 'd' => INTENT_SESSION_REF_DOMAIN, 's' => s })

    # ---- rule 15: accumulators, monitors, receipts, sequencer key sets (intent-acc.ts) -----------------------------

    ACC_AGGS = %w[sum count distinct max].freeze
    MONITOR_KINDS = %w[requires_prior precedes never always responds_within].freeze
    MAX_SESSION_ACCUMULATORS = 16
    MAX_SESSION_MONITORS = 16
    MAX_MONITOR_WITHIN = 64
    ACC_KEYS = %w[id agg val unit sel win key domain_max cap holder].freeze
    ACC_RECEIPT_DOMAIN = "atlas-pca/acc-receipt/v1\x00"
    ACC_RECEIPT_REF_DOMAIN = 'atlas-pca/acc-receipt-ref/v1'
    ACC_RESERVE_DOMAIN = 'atlas-pca/acc-reserve/v1'
    SEQUENCER_KEYS_DOMAIN = "atlas-pca/sequencer-keys/v1\x00"
    SEQUENCER_KEYS_REF_DOMAIN = 'atlas-pca/sequencer-keys-ref/v1'
    KID_RE = /\A[A-Za-z0-9_.:-]{1,64}\z/
    RECEIPT_SKEW_MS = 60_000
    # A receipt lives at most 15 min: issued_at <= expires_at <= issued_at + MAX_RECEIPT_LIFETIME_MS.
    MAX_RECEIPT_LIFETIME_MS = 900_000
    # Defaults of policy.acc: max receipt age at verification (15 min) and max key-set age (1 h).
    DEFAULT_MAX_RECEIPT_AGE_MS = 900_000
    DEFAULT_MAX_KEYSET_AGE_MS = 3_600_000
    RECEIPT_KEYS = %w[v kind session acc seq pre delta post pcactn_digest aud issued_at expires_at kid ledger signer alg pq_pk
                      sig pq_sig].freeze

    # The state set Q of a monitor.
    def monitor_states(m)
      case m['kind']
      when 'requires_prior', 'precedes' then %w[unmet met]
      when 'never' then %w[clean seen]
      when 'always' then %w[ok broken]
      when 'responds_within'
        w = int?(m['within']) ? ival(m['within']) : 0
        ['idle'] + (1..w).map { |i| "pending:#{i}" } + ['missed']
      else raise StrictError, 'monitorStates: unknown kind'
      end
    end

    def predicate_shape_ok?(p)
      p.is_a?(Hash) && (p['verb'].is_a?(String) || (p['verb'].is_a?(Array) && !p['verb'].empty? && p['verb'].all? { |x| x.is_a?(String) }))
    end

    def accumulator_decl_error(a)
      return 'accumulator must be an object' unless a.is_a?(Hash)

      js_keys(a).each { |k| return "accumulator: unknown member '#{k}'" unless ACC_KEYS.include?(k) }
      unless rx?(ACC_ID_RE, a['id']) && !RESERVED_NAMES.include?(a['id'])
        return 'accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype'
      end

      at = "accumulator '#{a['id']}'"
      return "#{at}: unknown agg" unless in_strs?(a['agg'], ACC_AGGS)
      return "#{at}: val must be action.params.<name>" if a.key?('val') && !rx?(PARAM_PATH_RE, a['val'])
      return "#{at}: unit must be a unit id" if a.key?('unit') && !(a['unit'].is_a?(String) && u16len(a['unit']) <= 64 && rx?(UNIT_ID_RE, a['unit']))

      sel = a['sel']
      return "#{at}: sel must be an object" unless sel.is_a?(Hash)

      js_keys(sel).each { |k| return "#{at}: sel has unknown member '#{k}'" unless %w[verbs accumulates_into event].include?(k) }
      if sel.key?('verbs')
        vs = sel['verbs']
        return "#{at}: sel.verbs must be 1..64 verb names" if !vs.is_a?(Array) || vs.empty? || vs.length > 64 || !vs.all? { |v| v.is_a?(String) && !v.empty? }
      end
      return "#{at}: sel.accumulates_into must be a unit id" if sel.key?('accumulates_into') && !rx?(UNIT_ID_RE, sel['accumulates_into'])
      return "#{at}: unknown sel.event" if sel.key?('event') && !in_strs?(sel['event'], %w[intent_required question clarification])

      action_sel = sel.key?('verbs') || sel.key?('accumulates_into')
      return "#{at}: sel names actions (verbs / accumulates_into) or a wallet event, exactly one kind" if action_sel == sel.key?('event')

      w = a['win']
      return "#{at}: win must be an object" unless w.is_a?(Hash)

      wk = prop(w, 'kind')
      if strict_eq(wk, 'task')
        return "#{at}: win {kind: task} has no other member" if w.length != 1
      elsif strict_eq(wk, 'sliding')
        return "#{at}: win sliding needs a positive ms" if sorted_join(w) != 'kind,ms' || !(int?(w['ms']) && w['ms'] > 0)
      elsif strict_eq(wk, 'period')
        return "#{at}: win period needs a positive ms and t0 >= 0" if sorted_join(w) != 'kind,ms,t0' || !(int?(w['ms']) && w['ms'] > 0) || !nonneg?(w['t0'])
      else
        return "#{at}: unknown win kind"
      end
      return "#{at}: key must be null or action.params.<name>" if !(a.key?('key') && a['key'].nil?) && !rx?(PARAM_PATH_RE, a['key'])
      return "#{at}: domain_max must be a non-negative safe integer" if a.key?('domain_max') && !nonneg?(a['domain_max'])
      return "#{at}: cap must be a non-negative safe integer" if a.key?('cap') && !nonneg?(a['cap'])

      h = a['holder']
      return "#{at}: holder must be an object" unless h.is_a?(Hash)

      hk = prop(h, 'kind')
      if strict_eq(hk, 'site_local') || strict_eq(hk, 'wallet')
        return "#{at}: holder #{hk} has no other member" if h.length != 1
      elsif strict_eq(hk, 'sequenced')
        js_keys(h).each { |k| return "#{at}: holder sequenced has unknown member '#{k}'" unless %w[kind uri root root_alg root_pq_pk keys_uri].include?(k) }
        return "#{at}: holder sequenced needs a uri" if !h['uri'].is_a?(String) || h['uri'].empty?
        return "#{at}: holder.root is not canonical base64url (32 bytes)" if b64d(h['root'], 32).nil?

        re = suite_err(prop(h, 'root_alg'))
        return "#{at}: holder.root_alg: #{re}" if re
        return "#{at}: holder.root_pq_pk is not canonical base64url" if h.key?('root_pq_pk') && b64d(h['root_pq_pk']).nil?
        return "#{at}: holder.keys_uri must be a non-empty string" if h.key?('keys_uri') && (!h['keys_uri'].is_a?(String) || h['keys_uri'].empty?)
      else
        return "#{at}: unknown holder kind"
      end
      wallet = strict_eq(hk, 'wallet')
      return "#{at}: wallet events are wallet-held and only wallet events are" if wallet != sel.key?('event')

      unless wallet
        agg = a['agg']
        return "#{at}: #{agg} needs val (or sel.accumulates_into for a sum)" if agg != 'count' && !a.key?('val') && !sel.key?('accumulates_into')
        return "#{at}: #{agg} needs val" if agg != 'sum' && agg != 'count' && !a.key?('val')
        return "#{at}: count takes no val" if agg == 'count' && a.key?('val')
      end
      nil
    end

    def monitor_decl_error(m)
      return 'monitor must be an object' unless m.is_a?(Hash)

      js_keys(m).each { |k| return "monitor: unknown member '#{k}'" unless %w[id kind p q status within].include?(k) }
      unless rx?(ACC_ID_RE, m['id']) && !RESERVED_NAMES.include?(m['id'])
        return 'monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype'
      end

      at = "monitor '#{m['id']}'"
      kind = m['kind']
      return "#{at}: unknown kind" unless in_strs?(kind, MONITOR_KINDS)
      return "#{at}: p must be a predicate" unless predicate_shape_ok?(m['p'])

      needs_q = %w[requires_prior precedes responds_within].include?(kind)
      return "#{at}: q is required exactly for requires_prior / precedes / responds_within" if needs_q != m.key?('q')
      return "#{at}: q must be a predicate" if m.key?('q') && !predicate_shape_ok?(m['q'])
      return "#{at}: status must be admitted or committed" if m.key?('status') && !in_strs?(m['status'], %w[admitted committed])
      return "#{at}: within is required exactly for responds_within" if (kind == 'responds_within') != m.key?('within')
      if m.key?('within') && !(int?(m['within']) && m['within'] >= 1 && m['within'] <= MAX_MONITOR_WITHIN)
        return "#{at}: within must be an integer in 1..#{MAX_MONITOR_WITHIN}"
      end

      nil
    end

    # omega in sel_psi (action selectors only): the verb is listed, or the schema's verb entry has an integer parameter
    # feeding `sel.accumulates_into`.
    def acc_selects(a, verb, schema = UNDEF)
      sel = a['sel']
      return false if sel.key?('event')
      return true if sel['verbs'].is_a?(Array) && sel['verbs'].any? { |x| strict_eq(x, verb) }

      if sel.key?('accumulates_into') && truthy?(schema)
        v = schema_verb(schema, verb)
        return !v.nil? && !accumulation_params(v, sel['accumulates_into']).empty?
      end
      false
    end

    # The canonical key of a `distinct` value: strict canonical JSON of a string or a safe integer, else nil.
    def distinct_key(x)
      return nil unless x.is_a?(String) || int?(x)

      canonicalize(jsnorm(x))
    rescue StandardError
      nil
    end

    # val(omega) for a selected action: {ok, val, key?} or {ok: false, reason}.
    def acc_value_of(a, verb, params, schema = UNDEF)
      read = ->(path) { prop(params, slice_from(path, PARAMS_PREFIX_LEN)) }
      return okv('val' => 1) if a['agg'] == 'count'

      if a['agg'] == 'distinct'
        k = distinct_key(read.call(a['val']))
        return k.nil? ? bad("#{a['val']} must be a string or a safe integer") : okv('val' => 1, 'key' => k)
      end
      if a.key?('val')
        x = read.call(a['val'])
        return nonneg?(x) ? okv('val' => ival(x)) : bad("#{a['val']} must be a non-negative safe integer")
      end
      v = truthy?(schema) ? schema_verb(schema, verb) : nil
      return bad("no schema entry for '#{js_str(verb)}' to read accumulates_into") if v.nil?

      s = 0
      accumulation_params(v, a['sel']['accumulates_into']).each do |p|
        x = read.call(p)
        next if undef?(x)
        return bad("#{p} must be a non-negative safe integer") unless nonneg?(x)

        s += ival(x)
        return bad('accumulated value exceeds 2^53-1') unless s <= MAX_SAFE
      end
      okv('val' => s)
    end

    def pre_want(agg) = { 'sum' => 'sum', 'count' => 'count', 'max' => 'max' }.fetch(agg, 'values')

    def pre_state_error(a, s)
      return 'pre-state must be an object' unless s.is_a?(Hash)

      want = pre_want(a['agg'])
      return "pre-state of a #{a['agg']} accumulator is {#{want}}" if js_keys(s).join(',') != want

      if want == 'values'
        vs = s['values']
        return 'pre-state values must be strings' unless vs.is_a?(Array) && vs.all? { |x| x.is_a?(String) }
        return 'pre-state values must be distinct' unless distinct_strs?(vs)

        return nil
      end
      nonneg?(s[want]) ? nil : "pre-state #{want} must be a non-negative safe integer"
    end

    # The post-action value from the pre-state (nil when it would leave the safe-integer range).
    def combine_acc(a, pre, v)
      post = case a['agg']
             when 'sum' then ival(pre['sum']) + v['val']
             when 'count' then ival(pre['count']) + 1
             when 'max' then [ival(pre['max']), v['val']].max
             else pre['values'].length + (pre['values'].any? { |x| x.b == v['key'].b } ? 0 : 1)
             end
      post <= MAX_SAFE ? post : nil
    end

    # The value of a group this action does NOT feed (post = pre).
    def pre_value(a, pre)
      case a['agg']
      when 'sum' then ival(pre['sum'])
      when 'count' then ival(pre['count'])
      when 'max' then ival(pre['max'])
      else pre['values'].length
      end
    end

    # The reservation digest: the PCActn without `sig`, `pq_sig`, `threshold` and `intent_session`.
    def pcactn_reservation_digest(p)
      body = p.reject { |k, _| %w[sig pq_sig threshold intent_session].include?(k) }
      hash_canonical({ 'd' => ACC_RESERVE_DOMAIN, 'b' => body })
    end

    def acc_receipt_shape_error(r)
      return 'receipt is not an object' unless r.is_a?(Hash)

      js_keys(r).each { |k| return "receipt: unknown member '#{k}'" unless RECEIPT_KEYS.include?(k) }
      return 'not a pca-acc-receipt v1' unless strict_eq(prop(r, 'v'), 1) && strict_eq(prop(r, 'kind'), 'pca-acc-receipt')
      return 'receipt.session is not canonical base64url (32 bytes)' if b64d(r['session'], 32).nil?
      return 'receipt.acc is not an accumulator id' unless rx?(ACC_ID_RE, r['acc'])
      return 'receipt.seq must be a safe integer >= 1' unless int?(r['seq']) && r['seq'] >= 1
      return 'receipt pre / delta / post must be non-negative safe integers' unless nonneg?(r['pre']) && nonneg?(r['delta']) && nonneg?(r['post'])
      return 'receipt.pcactn_digest is not canonical base64url (32 bytes)' if b64d(r['pcactn_digest'], 32).nil?
      return 'receipt.aud must be a non-empty string' if !r['aud'].is_a?(String) || r['aud'].empty?
      return 'receipt.issued_at / expires_at must be non-negative safe integers' unless nonneg?(r['issued_at']) && nonneg?(r['expires_at'])
      unless r['expires_at'] >= r['issued_at'] && r['expires_at'] - r['issued_at'] <= MAX_RECEIPT_LIFETIME_MS
        return "receipt.expires_at must be within #{MAX_RECEIPT_LIFETIME_MS} ms after issued_at"
      end
      return 'receipt.kid must match [A-Za-z0-9_.:-]{1,64}' unless rx?(KID_RE, r['kid'])

      l = r['ledger']
      if !l.is_a?(Hash) || sorted_join(l) != 'head,index' || !nonneg?(l['index']) || b64d(l['head'], 32).nil?
        return 'receipt.ledger must be {index, head}'
      end
      return 'receipt.signer is not canonical base64url (32 bytes)' if b64d(r['signer'], 32).nil?

      se = suite_err(prop(r, 'alg'))
      return "receipt.alg: #{se}" if se
      return 'an ed25519 receipt must not carry pq_pk / pq_sig' if suite_of(prop(r, 'alg')) == 'ed25519' && (r.key?('pq_pk') || r.key?('pq_sig'))
      return 'receipt.sig must be a string' unless r['sig'].is_a?(String)

      nil
    end

    def receipt_body(r)
      out = %w[v kind session acc seq pre delta post pcactn_digest aud issued_at expires_at kid].to_h { |k| [k, r.fetch(k)] }
      out['ledger'] = { 'index' => r['ledger'].fetch('index'), 'head' => r['ledger'].fetch('head') }
      out['signer'] = r.fetch('signer')
      out
    end

    def verify_acc_receipt_signature(r, expected_signer, pins = nil)
      return false if !acc_receipt_shape_error(r).nil? || !strict_eq(r['signer'], expected_signer)

      msg = dmsg(ACC_RECEIPT_DOMAIN, bind_suite_fields(receipt_body(r), prop(r, 'alg'), prop(r, 'pq_pk')))
      verify_pinned_suite(prop(r, 'alg'), r['signer'], prop(r, 'pq_pk'), msg, prop(r, 'sig'), prop(r, 'pq_sig'), pins)
    rescue StandardError, SystemStackError
      false
    end

    # The receipt's content address (what `intent_session.acc[].receipt` carries).
    def acc_receipt_digest(r) = hash_canonical({ 'd' => ACC_RECEIPT_REF_DOMAIN, 'r' => r })

    def sequencer_key_set_shape_error(k)
      return 'key set is not an object' unless k.is_a?(Hash)

      js_keys(k).each { |x| return "key set: unknown member '#{x}'" unless %w[v kind sequencer version issued_at keys alg pq_pk sig pq_sig].include?(x) }
      return 'not a pca-sequencer-keys v1' unless strict_eq(prop(k, 'v'), 1) && strict_eq(prop(k, 'kind'), 'pca-sequencer-keys')
      return 'sequencer is not canonical base64url (32 bytes)' if b64d(k['sequencer'], 32).nil?
      return 'version must be a safe integer >= 1' unless nonneg?(k['version']) && k['version'] >= 1
      return 'issued_at must be a non-negative safe integer' unless nonneg?(k['issued_at'])

      ks = k['keys']
      return 'keys must be 1..256 entries' if !ks.is_a?(Array) || ks.empty? || ks.length > 256

      kids = {}
      ks.each do |e|
        if !e.is_a?(Hash) || e.keys.any? { |x| !%w[kid pk alg pq_pk not_before not_after].include?(x) }
          return 'keys entries are {kid, pk, alg?, pq_pk?, not_before, not_after?}'
        end
        return 'key kids must match [A-Za-z0-9_.:-]{1,64} and be distinct' if !rx?(KID_RE, e['kid']) || kids.key?(e['kid'])

        kids[e['kid']] = true
        return 'key pk is not canonical base64url (32 bytes)' if b64d(e['pk'], 32).nil?

        ae = suite_err(prop(e, 'alg'))
        return "key alg: #{ae}" if ae
        return 'key pq_pk is not canonical base64url' if e.key?('pq_pk') && b64d(e['pq_pk']).nil?
        if !nonneg?(e['not_before']) || (e.key?('not_after') && !(nonneg?(e['not_after']) && e['not_after'] >= e['not_before']))
          return 'key validity must be 0 <= not_before <= not_after'
        end
      end
      se = suite_err(prop(k, 'alg'))
      return "alg: #{se}" if se
      return 'an ed25519 key set must not carry pq_pk / pq_sig' if suite_of(prop(k, 'alg')) == 'ed25519' && (k.key?('pq_pk') || k.key?('pq_sig'))
      return 'sig must be a string' unless k['sig'].is_a?(String)

      nil
    end

    def key_set_body(k)
      { 'v' => k['v'], 'kind' => k['kind'], 'sequencer' => k['sequencer'], 'version' => k['version'], 'issued_at' => k['issued_at'],
        'keys' => k['keys'] }
    end

    # A key set's content address: base64url(sha256(strictCanonical({"d":"atlas-pca/sequencer-keys-ref/v1","k":set}))),
    # signature fields included.
    def sequencer_key_set_digest(ks) = hash_canonical({ 'd' => SEQUENCER_KEYS_REF_DOMAIN, 'k' => ks })

    # The tracked `acc.keyset_versions[root]` is exactly {version, digest}: version a safe integer >= 1, digest canonical
    # base64url of 32 bytes. nil = well-formed.
    def tracked_key_set_error(t)
      return 'a tracked key set must be an object {version, digest}' unless t.is_a?(Hash)

      js_keys(t).each { |k| return "a tracked key set has the unknown member '#{k}'" unless %w[version digest].include?(k) }
      return 'a tracked key set version must be a safe integer >= 1' unless int?(t['version']) && t['version'] >= 1
      return 'a tracked key set digest must be canonical base64url (32 bytes)' unless t['digest'].is_a?(String) && b32v?(t['digest'])

      nil
    end

    # Verify a key set under the session's pinned root (and the root's pinned PQ key for a PQ suite). Total.
    def verify_sequencer_key_set(k, root, root_pq_pk = UNDEF)
      return false unless sequencer_key_set_shape_error(k).nil?
      return false unless strict_eq(k['sequencer'], root)

      pins = undef?(root_pq_pk) ? nil : { root => root_pq_pk }
      msg = dmsg(SEQUENCER_KEYS_DOMAIN, bind_suite_fields(key_set_body(k), prop(k, 'alg'), prop(k, 'pq_pk')))
      verify_pinned_suite(prop(k, 'alg'), root, prop(k, 'pq_pk'), msg, prop(k, 'sig'), prop(k, 'pq_sig'), pins)
    rescue StandardError, SystemStackError
      false
    end

    # Rule 15 step 3 (sequenced). False unless ALL hold: `now` a safe integer and every bound a non-negative safe integer;
    # the receipt well-formed (lifetime <= 15 min), issued_at <= now + 60 s and now - issued_at <= max receipt age
    # (default 15 min); SOME presented key set verifies under holder.root (PQ: holder.root_pq_pk), has version >= the
    # tracked version (when tracked), issued_at <= now + 60 s and now - issued_at <= max key-set age (default 1 h), and
    # lists receipt.kid with pk == signer, not_before <= receipt.issued_at and, when not_after is set,
    # receipt.issued_at <= not_after AND not_after >= now - 60 s (a retired key stops verifying), the entry's suite
    # equal to the receipt's; the receipt verifies under that entry (PQ: pinned by the entry).
    # `fresh` = {'max_receipt_age_ms'?, 'max_keyset_age_ms'?, 'tracked'?, 'min_keyset_version'?} (absent = default / not
    # tracked). `tracked` = {version, digest} of the newest set accepted for the root: a set below its version, or at its
    # version with another digest (equivocation), is skipped; `min_keyset_version` is a bare version floor.
    def verify_receipt_against_holder(r, holder, key_sets, now, fresh = {})
      max_age = fresh.key?('max_receipt_age_ms') ? fresh['max_receipt_age_ms'] : DEFAULT_MAX_RECEIPT_AGE_MS
      max_set_age = fresh.key?('max_keyset_age_ms') ? fresh['max_keyset_age_ms'] : DEFAULT_MAX_KEYSET_AGE_MS
      tracked = fresh.key?('tracked') ? fresh['tracked'] : UNDEF
      min_v = fresh.key?('min_keyset_version') ? fresh['min_keyset_version'] : UNDEF
      return false unless int?(now) && nonneg?(max_age) && nonneg?(max_set_age) && (undef?(tracked) || tracked_key_set_error(tracked).nil?) &&
                          (undef?(min_v) || nonneg?(min_v))
      return false unless key_sets.is_a?(Array) && acc_receipt_shape_error(r).nil?
      return false unless r['issued_at'] <= now + RECEIPT_SKEW_MS && now - r['issued_at'] <= max_age

      key_sets.each do |k|
        next unless verify_sequencer_key_set(k, holder['root'], prop(holder, 'root_pq_pk'))
        next if !undef?(min_v) && k['version'] < min_v
        if !undef?(tracked) && (k['version'] < tracked['version'] ||
                                (k['version'] == tracked['version'] && !strict_eq(sequencer_key_set_digest(k), tracked['digest'])))
          next
        end
        next unless k['issued_at'] <= now + RECEIPT_SKEW_MS && now - k['issued_at'] <= max_set_age

        e = k['keys'].find { |x| strict_eq(x['kid'], r['kid']) }
        next if e.nil? || !strict_eq(e['pk'], r['signer']) || r['issued_at'] < e['not_before']
        next if e.key?('not_after') && (r['issued_at'] > e['not_after'] || e['not_after'] < now - RECEIPT_SKEW_MS)
        next if (suite_of(prop(e, 'alg')) || 'ed25519') != (suite_of(prop(r, 'alg')) || 'x')
        return true if verify_acc_receipt_signature(r, e['pk'], e.key?('pq_pk') ? { e['pk'] => e['pq_pk'] } : nil)
      end
      false
    end

    # The `unsupported_suite` shape refusal of a receipt or of a presented key set (nil when none carries one): reported in
    # place of the generic signature reason so the README token is always in the reason.
    def unsupported_suite_reason(rc, keysets)
      e = acc_receipt_shape_error(rc)
      return e if e&.include?(UNSUPPORTED_SUITE)

      (keysets.is_a?(Array) ? keysets : []).each do |k|
        ke = sequencer_key_set_shape_error(k)
        return "key set #{ke}" if ke&.include?(UNSUPPORTED_SUITE)
      end
      nil
    end

    # Rule 15 step 5d.
    def receipt_arithmetic_ok(a, r, val)
      pre = ival(r['pre'])
      delta = ival(r['delta'])
      post = ival(r['post'])
      case a['agg']
      when 'sum' then delta == val && post == pre + delta
      when 'count' then delta == 1 && post == pre + 1
      when 'max' then delta == val && post == [pre, delta].max
      else (delta.zero? || delta == 1) && post == pre + delta
      end
    end

    # ---- rule 13 step 7: revocation by a dedicated authority, append-only (revocation.ts + intent-revocation.ts) ------

    REVEPOCH_DOMAIN = "atlas-pca/revepoch/v1\x00"
    REVSET_PREFIX = "pca-revset/v1\x00"
    EPOCH_FIELDS = %w[instance_id grant_ref epoch set_size root issued_at not_after].freeze

    def empty_tree = b64e(sha(''.b))

    # The size-bound revocation root: b64u(sha256("pca-revset/v1\0" || canonical({size, tree}))).
    def bind_root(size, tree) = b64e(sha(dmsg(REVSET_PREFIX, { 'size' => size, 'tree' => tree })))

    # revset_root(L): the sorted-set root of the list L taken in order (RFC 6962 tree over leaf SHA-256(0x00 || canonical(id)),
    # node SHA-256(0x01 || l || r); the empty list's tree is base64url(SHA-256(""))).
    def revset_root(list) = bind_root(list.length, list.empty? ? empty_tree : merkle_root(list))

    # Strict shape of a revocation epoch as rule 13 consumes it (revocationEpochShapeError).
    def revocation_epoch_shape_error(ep)
      return 'the revocation epoch must be an object' unless ep.is_a?(Hash)

      %w[instance_id grant_ref root guardian sig].each { |k| return "revocation epoch #{k} must be a string" unless ep[k].is_a?(String) }
      %w[epoch set_size issued_at not_after].each { |k| return "revocation epoch #{k} must be a non-negative safe integer" unless nonneg?(ep[k]) }
      if ep.key?('guardian_epoch') && !nonneg?(ep['guardian_epoch'])
        return 'revocation epoch guardian_epoch must be a non-negative safe integer'
      end

      se = suite_err(prop(ep, 'alg'))
      return "revocation epoch alg: #{se}" if se
      return 'revocation epoch pq_pk must be a string' if ep.key?('pq_pk') && !ep['pq_pk'].is_a?(String)
      return 'revocation epoch pq_sig must be a string' if ep.key?('pq_sig') && !ep['pq_sig'].is_a?(String)

      nil
    end

    # Verify a signed revocation epoch (revocation.ts checkRevocationEpoch, the `pq_artifact` "revocation" format): the
    # guardian signs utf8("atlas-pca/revepoch/v1\0") || canonical(bindSuiteFields({instance_id, grant_ref, epoch,
    # set_size, root, issued_at, not_after}, alg, pq_pk)); a PQ epoch verifies only under a key `pins` pins for the
    # guardian. Total.
    def check_revocation_epoch(ep, guardian_public, now, grant_ref = UNDEF, pins = nil)
      f = ->(reason) { { 'ok' => false, 'reason' => reason } }
      if !ep.is_a?(Hash) || !strict_eq(prop(ep, 'guardian'), guardian_public) || (!undef?(prop(ep, 'alg')) && suite_of(prop(ep, 'alg')).nil?)
        return f.call('revocation epoch not signed by the pinned guardian')
      end
      if !int?(ep['epoch']) || ep['epoch'].negative? || !int?(ep['set_size']) || ep['set_size'].negative? ||
         !int?(ep['issued_at']) || !int?(ep['not_after'])
        return f.call('malformed revocation epoch')
      end

      body = EPOCH_FIELDS.to_h { |k| [k, ep.fetch(k)] }
      msg = dmsg(REVEPOCH_DOMAIN, bind_suite_fields(body, prop(ep, 'alg'), prop(ep, 'pq_pk')))
      unless verify_pinned_suite(prop(ep, 'alg'), guardian_public, prop(ep, 'pq_pk'), msg, prop(ep, 'sig'), prop(ep, 'pq_sig'), pins)
        return f.call('revocation epoch signature invalid')
      end
      return f.call('revocation epoch is for a different grant') if !undef?(grant_ref) && !strict_eq(ep['grant_ref'], grant_ref)
      return f.call('revocation epoch expired (stale revocation root)') unless now <= ep['not_after']
      return f.call('revocation epoch issued in the future') unless ep['issued_at'] <= now + 60_000

      { 'ok' => true }
    rescue StandardError, SystemStackError
      { 'ok' => false, 'reason' => 'revocation epoch check error' }
    end

    # The revoked list is well-formed and is exactly what the epoch signs (root, size, epoch == size).
    def revoked_list_error(ev)
      r = prop(ev, 'revoked')
      return 'revoked must be an array of ids' unless r.is_a?(Array) && r.all? { |x| x.is_a?(String) }
      return 'revoked must be sorted by UTF-8 bytes and distinct' unless (1...r.length).all? { |i| compare_utf8(r[i - 1], r[i]).negative? }

      ep = ev['epoch']
      return 'the epoch must be numbered by its set size and list exactly set_size ids' if r.length != ep['set_size'] || ep['epoch'] != ep['set_size']
      return 'the revoked list is not the signed set (root mismatch)' unless strict_eq(revset_root(r), ep['root'])

      nil
    end

    # The evidence (and the tracked last evidence) is CLOSED: exactly the members `epoch` and `revoked`. Only an EXTRA member
    # is refused here (the first in key order); a missing one fails at the epoch shape / revoked-list steps.
    def closed_evidence_error(ev)
      js_keys(ev).each { |k| return "has the unknown member '#{k}' (it is exactly {epoch, revoked})" unless %w[epoch revoked].include?(k) }
      nil
    end

    def session_revocation_id(session) = "pca-intent:session:#{js_str(session)}"
    def map_revocation_id(map_digest) = "pca-intent:map:#{js_str(map_digest)}"
    def delta_revocation_id(grant_id) = "pca-intent:delta:#{js_str(grant_id)}"
    def profile_revocation_id(profile_id, version) = "pca-intent:profile:#{js_str(profile_id)}@#{js_str(version)}"
    def session_revocation_scope(session) = "pca-intent-session:#{js_str(session)}"
    def profile_revocation_scope(profile_id) = "pca-intent-profile:#{js_str(profile_id)}"

    # The session revocation step (rule 13 step 7, checkSessionRevocation). `ev` = {epoch, revoked}, the full signed list;
    # `last` (UNDEF = not tracked) the last evidence this verifier accepted for the scope. First failure wins:
    #   a. max age a safe integer >= 0, the clock a safe integer, ids an array, the authority a string;
    #   b. a strictly typed epoch whose guardian is the authority;
    #   c. it verifies (signature through the suite dispatch, a PQ epoch only under `pins`), scope, not_after, issued_at;
    #   d. now - issued_at <= max age;
    #   e. revoked is the signed set (strings, strictly ascending by UTF-8 bytes, length == set_size == epoch, root);
    #   f. append-only against `last` (well-formed itself): no rollback, no dropped id, no equivocation;
    #   g. no required id is revoked.
    def check_session_revocation(ev, session:, authority:, ids:, now:, max_age_ms:, scope: UNDEF, pins: nil, last: UNDEF)
      f = ->(reason) { { 'ok' => false, 'reason' => reason } }
      return f.call('revocation max age misconfigured (fail closed)') unless nonneg?(max_age_ms)
      return f.call('the verifier clock is not a safe integer (fail closed)') unless int?(now)
      return f.call('ids must be an array and the authority a key') unless ids.is_a?(Array) && authority.is_a?(String)
      return f.call('no session revocation epoch supplied') unless ev.is_a?(Hash)
      ce = closed_evidence_error(ev)
      return f.call("the revocation evidence #{ce}") if ce

      ep = prop(ev, 'epoch')
      shape = revocation_epoch_shape_error(ep)
      return f.call(shape) if shape
      return f.call('the revocation epoch is not signed by the session revocation authority') unless strict_eq(ep['guardian'], authority)

      r = check_revocation_epoch(ep, ep['guardian'], now, nullish?(scope) ? session_revocation_scope(session) : scope, pins)
      return f.call(nullish_or(r['reason'], 'revocation epoch rejected')) unless r['ok']
      return f.call("the session revocation epoch is older than #{js_str(max_age_ms)} ms") unless now - ep['issued_at'] <= max_age_ms

      le = revoked_list_error(ev)
      return f.call(le) if le

      unless undef?(last)
        if !last.is_a?(Hash) || !closed_evidence_error(last).nil? || !revocation_epoch_shape_error(prop(last, 'epoch')).nil? || !revoked_list_error(last).nil?
          return f.call('the tracked last epoch is malformed (fail closed)')
        end
        return f.call('revocation epoch rollback (older than the last accepted)') if ep['epoch'] < last['epoch']['epoch']

        have = ev['revoked'].to_h { |x| [x.b, true] }
        last['revoked'].each do |id|
          return f.call("the epoch drops '#{id}', revoked in the last accepted epoch (not append-only)") unless have.key?(id.b)
        end
        if ep['epoch'] == last['epoch']['epoch'] && !strict_eq(ep['root'], last['epoch']['root'])
          return f.call('two different revocation sets under one epoch number (equivocation)')
        end
      end
      revoked = ev['revoked'].to_h { |x| [x.b, true] }
      ids.each { |id| return f.call("'#{js_str(id)}' is revoked") if !id.is_a?(String) || revoked.key?(id.b) }
      { 'ok' => true }
    rescue StandardError, SystemStackError => e
      { 'ok' => false, 'reason' => "session revocation check error (fail closed): #{e.message}" }
    end

    # ---- rule 19: the committed intent map and the Z0 disclosure (intent-map-commit.ts) -------------------------------

    MAP_TAG_HEADER = "atlas-pca/intent-map/header/v1\x00"
    MAP_TAG_CELL = "atlas-pca/intent-map/cell/v1\x00"
    MAP_TAG_METRICS = "atlas-pca/intent-map/metrics/v1\x00"
    MAP_TAG_LEARNER = "atlas-pca/intent-map/learner/v1\x00"
    MAP_TAG_NODE = "atlas-pca/intent-map/node/v1\x00"
    MAP_TAG_COMMIT = "atlas-pca/intent-map/commit/v1\x00"
    MAP_TAGS = { 'header' => MAP_TAG_HEADER, 'cell' => MAP_TAG_CELL, 'metrics' => MAP_TAG_METRICS, 'learner' => MAP_TAG_LEARNER }.freeze
    # The OTHER value of a categorical dimension (U+22A5).
    MAP_OTHER = "⊥"
    MAX_MAP_LEAVES = 1 << 24
    MAX_VERB_CELLS = 1 << 20
    MAX_MAP_DIMS = 16
    MAX_MAP_CUTS = 256
    MAX_MAP_VALUES = 256
    MAX_MAP_STRING_BYTES = 256
    MAP_PPM_ONE = 1_000_000
    MAP_METRIC_FIELDS = %w[residual_risk_ppm burden_ppm uncertainty_ppm disagreement_ppm mean_harm_ppm fidelity_est_ppm
                           entropy_mbits questions conflicts].freeze

    # A string without lone surrogates of at most `max` UTF-8 bytes (empty allowed).
    def map_str?(v, max = MAX_MAP_STRING_BYTES) = ustr?(v) && v.bytesize <= max

    # The member set of `o` is within `allowed` and contains every `required` member.
    def closed_members?(o, allowed, required) = o.keys.all? { |k| allowed.include?(k) } && required.all? { |k| o.key?(k) }

    # SHA-256(TAG_kind || salt || strictCanonical(leaf)). Raises on a leaf without a strict canonical form.
    def map_leaf_hash(kind, salt, leaf)
      raise StrictError, 'mapLeafHash: the salt is 32 bytes' unless salt.is_a?(String) && salt.bytesize == 32

      sha(MAP_TAGS.fetch(kind).b + salt.b + canon_bytes(leaf))
    end

    def map_node_hash(l, r) = sha(MAP_TAG_NODE.b + l + r)

    # map_commit = base64url(SHA-256(TAG_COMMIT || u64be(size) || root)).
    def map_commit_of(size, root) = b64e(sha(MAP_TAG_COMMIT.b + [size].pack('Q>') + root))

    def map_tree_root(hs)
      return hs[0] if hs.length == 1

      k = split_point(hs.length)
      map_node_hash(map_tree_root(hs[0, k]), map_tree_root(hs[k..]))
    end

    # RFC 9162 section 2.1.3.2 inclusion verification with the map node hash: the root the audit path of leaf `index` in a
    # tree of `size` leaves recomputes, or nil when the path has the wrong length for (index, size).
    def map_root_from_path(index, size, leaf_hash, path)
      return nil unless index >= 0 && index < size

      fn = index
      sn = size - 1
      r = leaf_hash
      path.each do |p|
        return nil if sn.zero?

        if fn.odd? || fn == sn
          r = map_node_hash(p, r)
          if fn.even?
            while fn.even? && fn != 0
              fn /= 2
              sn /= 2
            end
          end
        else
          r = map_node_hash(r, p)
        end
        fn /= 2
        sn /= 2
      end
      sn.zero? ? r : nil
    end

    # map_commit of a full leaf list [{kind, salt, leaf}, ...] in order (primitives.intent_map_commit). Raises on a
    # malformed list.
    def map_commit_of_leaves(leaves)
      raise StrictError, 'leaves must be a non-empty array' unless leaves.is_a?(Array) && !leaves.empty?

      hs = leaves.map do |l|
        raise StrictError, 'a leaf entry must be {kind, salt, leaf}' unless l.is_a?(Hash) && MAP_TAGS.key?(l['kind']) && l.key?('leaf')

        salt = b64d(l['salt'], 32)
        raise StrictError, 'a leaf salt must be canonical base64url (32 bytes)' if salt.nil?

        map_leaf_hash(l['kind'], salt, l['leaf'])
      end
      map_commit_of(hs.length, map_tree_root(hs))
    end

    def map_dim_path?(p) = p == 'action.resource' || rx?(PARAM_PATH_RE, p)

    # The cells of a numeric dimension as inclusive [lo, hi] ranges (empty ranges dropped).
    def map_num_cells(d)
      out = []
      cur = ival(d['lo'])
      d['cuts'].each do |c|
        c = ival(c)
        out << [cur, c - 1] if cur <= c - 1
        out << [c, c]
        cur = c + 1
      end
      out << [cur, ival(d['hi'])] if cur <= d['hi']
      out
    end

    def map_dim_cells(d) = d['kind'] == 'num' ? map_num_cells(d).length : d['values'].length

    def map_dim_error(d, j)
      return "dims[#{j}] must be an object" unless d.is_a?(Hash)

      kind = prop(d, 'kind')
      if strict_eq(kind, 'num')
        req = %w[kind path lo hi cuts]
        return "dims[#{j}] must be exactly {kind, path, lo, hi, cuts}" unless closed_members?(d, req, req)
        return "dims[#{j}].path must be action.params.<name>" if !map_dim_path?(d['path']) || d['path'] == 'action.resource'
        return "dims[#{j}] lo / hi must be safe integers with lo <= hi" if !int?(d['lo']) || !int?(d['hi']) || d['lo'] > d['hi']
        return "dims[#{j}].cuts must be an array of at most #{MAX_MAP_CUTS}" if !d['cuts'].is_a?(Array) || d['cuts'].length > MAX_MAP_CUTS

        prev = nil
        d['cuts'].each do |c|
          if !int?(c) || (!prev.nil? && c <= prev) || c < d['lo'] || c > d['hi']
            return "dims[#{j}].cuts must be strictly increasing safe integers in [lo, hi]"
          end

          prev = c
        end
        return nil
      end
      if strict_eq(kind, 'cat')
        req = %w[kind path values]
        return "dims[#{j}] must be exactly {kind, path, values}" unless closed_members?(d, req, req)
        return "dims[#{j}].path must be action.resource or action.params.<name>" unless map_dim_path?(d['path'])

        vs = d['values']
        return "dims[#{j}].values must be an array of 1..#{MAX_MAP_VALUES}" if !vs.is_a?(Array) || vs.empty? || vs.length > MAX_MAP_VALUES

        seen = {}
        vs.each_with_index do |v, i|
          return "dims[#{j}].values[#{i}] must be exactly {kind, value}" unless v.is_a?(Hash) && closed_members?(v, %w[kind value], %w[kind value])
          return "dims[#{j}].values[#{i}].kind must be exact, prefix or other" unless in_strs?(v['kind'], %w[exact prefix other])
          return "dims[#{j}].values[#{i}].value must be a string of at most #{MAX_MAP_STRING_BYTES} UTF-8 bytes" unless map_str?(v['value'])

          bad_other = v['kind'] == 'other' ? (i != vs.length - 1 || v['value'] != MAP_OTHER) : (v['kind'] == 'prefix' && v['value'].empty?)
          return "dims[#{j}].values: exactly one other ('#{MAP_OTHER}'), last; prefixes non-empty" if bad_other

          key = "#{v['kind']}:#{v['value']}".b
          return "dims[#{j}].values must be distinct" if seen.key?(key)

          seen[key] = true
        end
        return "dims[#{j}].values must end with the other value" unless vs[-1]['kind'] == 'other'

        return nil
      end
      "dims[#{j}].kind must be num or cat"
    end

    # Shape of a header leaf (closed, typed; `cells` = the product of the dimensions' cell counts). nil = well-formed.
    def map_header_error(h)
      req = %w[verb first cells dims]
      return 'the header leaf must be exactly {verb, first, cells, dims}' unless h.is_a?(Hash) && closed_members?(h, req, req)
      return 'header.verb must be a non-empty string of at most 128 UTF-8 bytes' unless map_str?(h['verb'], 128) && !h['verb'].empty?
      return 'header.first must be a leaf index' unless nonneg?(h['first']) && h['first'] < MAX_MAP_LEAVES
      return "header.cells must be a safe integer in [1, #{MAX_VERB_CELLS}]" unless int?(h['cells']) && h['cells'] >= 1 && h['cells'] <= MAX_VERB_CELLS
      return "header.dims must be an array of at most #{MAX_MAP_DIMS}" if !h['dims'].is_a?(Array) || h['dims'].length > MAX_MAP_DIMS

      paths = {}
      n = 1
      h['dims'].each_with_index do |d, j|
        e = map_dim_error(d, j)
        return "header.#{e}" if e
        return 'header.dims paths must be distinct' if paths.key?(d['path'])

        paths[d['path']] = true
        n *= map_dim_cells(d)
        return 'header: too many cells' if n > MAX_VERB_CELLS
      end
      return "header.cells is not the product of the dimensions' cell counts" if n != h['cells']

      nil
    end

    def map_cell_error(c)
      req = %w[verb cell p_ppm in_grant]
      return 'the cell leaf must be exactly {verb, cell, p_ppm, in_grant}' unless c.is_a?(Hash) && closed_members?(c, req, req)
      return 'cell.verb must be a non-empty string of at most 128 UTF-8 bytes' unless map_str?(c['verb'], 128) && !c['verb'].empty?
      if !c['cell'].is_a?(Array) || c['cell'].length > MAX_MAP_DIMS || !c['cell'].all? { |x| nonneg?(x) }
        return 'cell.cell must be an array of non-negative safe integers'
      end
      return 'cell.p_ppm must be a safe integer in [0, 1000000]' unless nonneg?(c['p_ppm']) && c['p_ppm'] <= MAP_PPM_ONE
      return 'cell.in_grant must be a boolean' unless bool?(c['in_grant'])

      nil
    end

    def map_metrics_error(m)
      unless m.is_a?(Hash) && closed_members?(m, MAP_METRIC_FIELDS + ['log2_vs_mbits'], MAP_METRIC_FIELDS)
        return "the metrics leaf must be exactly {#{MAP_METRIC_FIELDS.join(', ')}, log2_vs_mbits?}"
      end

      (MAP_METRIC_FIELDS + ['log2_vs_mbits']).each do |k|
        next if k == 'log2_vs_mbits' && !m.key?(k)
        return "metrics.#{k} must be a non-negative safe integer" unless nonneg?(m[k])
      end
      nil
    end

    def map_learner_error(l)
      return 'the learner leaf must be exactly {learner_digest}' unless l.is_a?(Hash) && closed_members?(l, ['learner_digest'], ['learner_digest'])

      b32v?(l['learner_digest']) ? nil : 'learner.learner_digest must be canonical base64url (32 bytes)'
    end

    # Cell of omega: per-dimension cell indices of the action under `header` and the flat index, or {'error'}. `resource` is
    # action.resource, `params` the plaintext params (own members).
    def map_cell_of(header, resource, params)
      cell = []
      flat = 0
      header['dims'].each do |d|
        x = d['path'] == 'action.resource' ? resource : (params.is_a?(Hash) ? prop(params, slice_from(d['path'], PARAMS_PREFIX_LEN)) : UNDEF)
        i = -1
        if d['kind'] == 'num'
          i = map_num_cells(d).index { |lo, hi| x >= lo && x <= hi } || -1 if int?(x)
        elsif ustr?(x)
          best = -1
          best_len = -1
          d['values'].each_with_index do |v, k|
            if v['kind'] == 'exact' && v['value'].b == x.b
              best = k
              best_len = Float::INFINITY
              break
            end
            next unless v['kind'] == 'prefix' && x.b.start_with?(v['value'].b) && u16len(v['value']) > best_len

            best = k
            best_len = u16len(v['value'])
          end
          i = best >= 0 ? best : d['values'].length - 1
        end
        return { 'error' => "the action's #{d['path']} lies outside the committed map's dimension" } if i.negative?

        cell << i
        flat = (flat * map_dim_cells(d)) + i
      end
      { 'cell' => cell, 'flat' => flat }
    end

    def map_entry_shape(e, what)
      req = %w[index salt leaf path]
      return "disclosure.#{what} must be exactly {index, salt, leaf, path}" unless e.is_a?(Hash) && closed_members?(e, req, req)
      return "disclosure.#{what}.index must be a non-negative safe integer" unless nonneg?(e['index'])
      return "disclosure.#{what}.salt must be canonical base64url (32 bytes)" unless b32v?(e['salt'])
      if !e['path'].is_a?(Array) || e['path'].length > 64 || !e['path'].all? { |h| b32v?(h) }
        return "disclosure.#{what}.path must be an array of 32-byte digests"
      end

      nil
    end

    # Shape of a Z0 disclosure (closed, typed). nil = well-formed.
    def map_disclosure_error(d)
      req = %w[size header cell metrics]
      return 'the disclosure must be exactly {size, header, cell, metrics}' unless d.is_a?(Hash) && closed_members?(d, req, req)
      return "disclosure.size must be a safe integer in [4, #{MAX_MAP_LEAVES}]" unless int?(d['size']) && d['size'] >= 4 && d['size'] <= MAX_MAP_LEAVES

      %w[header cell metrics].each do |k|
        e = map_entry_shape(d[k], k)
        return e if e
      end
      map_header_error(d['header']['leaf']) || map_cell_error(d['cell']['leaf']) || map_metrics_error(d['metrics']['leaf'])
    end

    # Does the disclosed entry `e` of kind `kind` open `commit` in a tree of `size` leaves?
    def map_opens?(kind, e, size, commit)
      h = map_leaf_hash(kind, b64d(e['salt'], 32), e['leaf'])
      root = map_root_from_path(e['index'], size, h, e['path'].map { |x| b64d(x, 32) })
      !root.nil? && map_commit_of(size, root) == commit
    rescue StandardError, SystemStackError
      false
    end

    # Z0, the `map` check (rule 19, decideMapDisclosure). `params` UNDEF = absent ({}); `max_rr` UNDEF = no epsilon.
    # Returns {'ok' => true, 'cell', 'p_ppm', 'residual_risk_ppm'} or {'ok' => false, 'reason'}. Never raises.
    def decide_map_disclosure(map_commit, action, params, disclosure, max_rr = UNDEF)
      de = map_disclosure_error(disclosure)
      return bad("map disclosure malformed: #{de}") if de
      return bad('the PCActn carries no map commitment') unless b32v?(map_commit)
      return bad('params must be an object') if !undef?(params) && !params.is_a?(Hash)

      prm = undef?(params) ? {} : params
      return bad('the params do not hash to action.params_digest') unless strict_eq(params_digest(prm), prop(action, 'params_digest'))

      d = disclosure
      h = d['header']['leaf']
      return bad("the disclosed header is not the action's verb") unless strict_eq(h['verb'], prop(action, 'verb'))
      unless d['header']['index'] < h['first'] && h['first'] + h['cells'] <= d['size'] - 2
        return bad('the disclosed header does not fit the committed layout')
      end
      return bad('the header leaf does not open the map commitment') unless map_opens?('header', d['header'], d['size'], map_commit)
      return bad('the cell leaf does not open the map commitment') unless map_opens?('cell', d['cell'], d['size'], map_commit)
      return bad('the metrics leaf does not open the map commitment') unless map_opens?('metrics', d['metrics'], d['size'], map_commit)

      w = map_cell_of(h, prop(action, 'resource'), prm)
      return bad(w['error']) if w.key?('error')

      c = d['cell']['leaf']
      if d['cell']['index'] != h['first'] + w['flat'] || !strict_eq(c['verb'], h['verb']) || c['cell'].length != w['cell'].length ||
         c['cell'].each_with_index.any? { |x, i| x != w['cell'][i] }
        return bad("the disclosed cell is not the action's cell")
      end
      return bad("the action's cell is outside the committed grant") unless c['in_grant'] == true
      return bad('the disclosed metrics leaf is not at its committed position') unless d['metrics']['index'] == d['size'] - 2

      rr = d['metrics']['leaf']['residual_risk_ppm']
      return bad("the committed residual risk #{js_str(rr)} ppm exceeds ε = #{js_str(max_rr)}") if !undef?(max_rr) && !(rr <= max_rr)

      okv('cell' => c['cell'].map { |x| ival(x) }, 'p_ppm' => ival(c['p_ppm']), 'residual_risk_ppm' => ival(rr))
    rescue StandardError, SystemStackError => e
      bad("map error (fail closed): #{e.message}")
    end

    # Rule 19 (`map`): reported iff `intent_session.map_form` is "commit" or `policy.map.require` is true.
    def map_step(p, ctx)
      is = opt(p, 'intent_session')
      return bad('this verifier requires a committed map (intent_session.map_form "commit")') unless strict_eq(prop(is, 'map_form'), MAP_FORM_COMMIT)

      intent = opt(p, 'intent')
      return bad('a committed map needs the envelope.intent binding') if undef?(intent)

      disclosure = opt(opt(ctx, 'map'), 'disclosure')
      return bad('no disclosure of the committed map was presented') if undef?(disclosure)

      action = nullish_or(opt(p, 'action'), {})
      d = decide_map_disclosure(prop(intent, 'map_digest'), action, opt(ctx, 'params'), disclosure,
                                opt(opt(opt(ctx, 'policy'), 'map'), 'max_residual_risk_ppm'))
      d['ok'] ? okv : bad(d['reason'])
    end

    # ---- the v2 pipeline (intent-v2.ts) ---------------------------------------------------------------------------

    def opt_obj?(o, k) = !o.key?(k) || o[k].is_a?(Hash)
    def opt_arr?(o, k) = !o.key?(k) || o[k].is_a?(Array)

    # The whole v2 context (intentV2ContextError): ABSENT members mean empty / default; a member PRESENT with null (or of
    # the wrong JSON type) is malformed and fails closed (the members passed to the layers and W-B checks included).
    def intent_v2_context_error(ctx)
      return nil if undef?(ctx)
      return 'the v2 verifier context must be an object' unless ctx.is_a?(Hash)
      return 'policy must be an object' unless opt_obj?(ctx, 'policy')

      if ctx.key?('policy')
        # closed member sets; every flag a JSON boolean and every number a safe integer when present (absent = default)
        pol = ctx['policy']
        js_keys(pol).each { |k| return "policy: unknown member '#{k}'" unless %w[session schema acc map].include?(k) }
        return 'policy.session must be an object' unless opt_obj?(pol, 'session')

        if pol.key?('session')
          ps = pol['session']
          js_keys(ps).each { |k| return "policy.session: unknown member '#{k}'" unless %w[require max_revocation_age_s].include?(k) }
          return 'policy.session.require must be a boolean' if ps.key?('require') && !bool?(ps['require'])
          if ps.key?('max_revocation_age_s') && !nonneg?(ps['max_revocation_age_s'])
            return 'policy.session.max_revocation_age_s must be a non-negative safe integer'
          end
        end
        return 'policy.schema must be an object' unless opt_obj?(pol, 'schema')

        if pol.key?('schema')
          pc = pol['schema']
          js_keys(pc).each { |k| return "policy.schema: unknown member '#{k}'" unless k == 'closed_world' }
          return 'policy.schema.closed_world must be a boolean' if pc.key?('closed_world') && !bool?(pc['closed_world'])
        end
        return 'policy.acc must be an object' unless opt_obj?(pol, 'acc')

        if pol.key?('acc')
          pa = pol['acc']
          js_keys(pa).each { |k| return "policy.acc: unknown member '#{k}'" unless %w[max_receipt_age_s max_keyset_age_s].include?(k) }
          %w[max_receipt_age_s max_keyset_age_s].each do |k|
            return "policy.acc.#{k} must be a non-negative safe integer" if pa.key?(k) && !nonneg?(pa[k])
          end
        end
        return 'policy.map must be an object' unless opt_obj?(pol, 'map')

        if pol.key?('map')
          pm = pol['map']
          js_keys(pm).each { |k| return "policy.map: unknown member '#{k}'" unless %w[require max_residual_risk_ppm].include?(k) }
          return 'policy.map.require must be a boolean' if pm.key?('require') && !bool?(pm['require'])
          if pm.key?('max_residual_risk_ppm') && !nonneg?(pm['max_residual_risk_ppm'])
            return 'policy.map.max_residual_risk_ppm must be a non-negative safe integer'
          end
        end
      end
      return 'params must be an object' unless opt_obj?(ctx, 'params')

      %w[schema session acc].each { |k| return "#{k} must be an object" unless opt_obj?(ctx, k) }
      return 'map must be an object' unless opt_obj?(ctx, 'map')

      js_keys(ctx['map']).each { |k| return "map: unknown member '#{k}'" unless k == 'disclosure' } if ctx.key?('map')
      if ctx.key?('layers')
        l = ctx['layers']
        return 'layers must be an object' unless l.is_a?(Hash)

        js_keys(l).each do |k|
          return "layers: unknown member '#{k}'" unless %w[org site std].include?(k)
          return "layers.#{k} must be {predicates: [...]}" unless l[k].is_a?(Hash) && l[k]['predicates'].is_a?(Array)
        end
      end
      if ctx.key?('wb')
        wb = ctx['wb']
        return 'wb must be an object' unless wb.is_a?(Hash)
        return 'wb.artifacts must be an object' unless opt_obj?(wb, 'artifacts')

        if wb.key?('artifacts')
          ar = wb['artifacts']
          %w[facts labels verdicts].each { |k| return "wb.artifacts.#{k} must be an array" unless opt_arr?(ar, k) }
          return 'wb.artifacts.offer_set must be an object' unless opt_obj?(ar, 'offer_set')
        end
        return 'wb.policy must be an object' unless opt_obj?(wb, 'policy')

        if wb.key?('policy')
          pr = wb['policy']
          return 'wb.policy.world / provenance must be objects' unless opt_obj?(pr, 'world') && opt_obj?(pr, 'provenance')
          return 'wb.policy.classifiers must be an array' unless opt_arr?(pr, 'classifiers')
        end
      end
      nil
    end

    def schema_ctx_error(ctx)
      sc = opt(ctx, 'schema')
      return nil if undef?(sc)
      return 'the schema context must be {docs: [...], keys: [...]}' unless sc.is_a?(Hash) && sc['docs'].is_a?(Array) && sc['keys'].is_a?(Array)

      nil
    end

    def session_ctx_error(ctx)
      se = opt(ctx, 'session')
      return nil if undef?(se)
      return 'the session context must be an object' unless se.is_a?(Hash)
      return 'the session grants must be an array' if se.key?('grants') && !se['grants'].is_a?(Array)
      return 'the session revocation evidence must be an object' if se.key?('revocation') && !se['revocation'].is_a?(Hash)
      return 'the tracked last revocation epoch must be an object' if se.key?('revocation_last') && !se['revocation_last'].is_a?(Hash)
      if se.key?('pq_pins') && (!se['pq_pins'].is_a?(Hash) || se['pq_pins'].values.any? { |v| !v.is_a?(String) })
        return 'the session pq_pins must be an object of strings'
      end

      nil
    end

    def acc_ctx_error(ctx)
      a = opt(ctx, 'acc')
      return nil if undef?(a)
      return 'the accumulator context must be an object' unless a.is_a?(Hash)

      %w[state monitors last_seq keyset_versions].each { |k| return "acc.#{k} must be an object" if a.key?(k) && !a[k].is_a?(Hash) }
      if a.key?('keyset_versions')
        a['keyset_versions'].each_value do |v|
          e = tracked_key_set_error(v)
          return "acc.keyset_versions: #{e}" if e
        end
      end
      %w[receipts sequencer_keys].each { |k| return "acc.#{k} must be an array" if a.key?(k) && !a[k].is_a?(Array) }
      return 'acc.last_seq values must be non-negative safe integers' if a.key?('last_seq') && !a['last_seq'].values.all? { |v| nonneg?(v) }

      nil
    end

    def action_of(p) = opt(p, 'action')

    # The schema doc whose digest is `want` (UNDEF when none); a document that cannot be hashed never matches.
    def doc_by_digest(docs, want)
      docs.each do |d|
        return d if (action_schema_digest(d) == want rescue false) # rubocop:disable Style/RescueModifier
      end
      UNDEF
    end

    # Rule 14 (`schema`). On success {ok, doc}.
    def schema_step(p, ctx)
      ce = schema_ctx_error(ctx)
      return bad(ce) if ce

      is = opt(p, 'intent_session')
      docs = opt(opt(ctx, 'schema'), 'docs')
      return bad('this verifier has no action schema configured') if !docs.is_a?(Array) || docs.empty?

      if undef?(is)
        doc = docs[0]
      else
        doc = doc_by_digest(docs, is['schema'])
        return bad('intent_session.schema names no schema this verifier accepts') unless truthy?(doc)
      end
      v = verify_action_schema(doc, nullish_or(opt(opt(ctx, 'schema'), 'keys'), []))
      return bad("schema does not verify: #{v['reason']}") unless v['ok']
      return bad('schema aud does not match the PCActn aud') unless strict_eq(doc['aud'], opt(p, 'aud'))

      params = opt(ctx, 'params')
      return bad('no plaintext params to check against the schema (closed world needs them)') unless params.is_a?(Hash)
      return bad('params do not hash to action.params_digest') unless strict_eq(params_digest(params), opt(action_of(p), 'params_digest'))

      c = conform_action(doc, js_str(opt(action_of(p), 'verb')), params)
      return bad("schema_violation: #{c['code']}: #{c['reason']}") unless c['ok']

      okv('doc' => doc)
    end

    # The bound, verified session root (shared by rules 13 and 15).
    def bound_root(p, ctx, now)
      is = p['intent_session']
      s = opt(opt(ctx, 'session'), 'root')
      return bad('no session root for this session') if undef?(s)

      # a PQ / hybrid root verifies only under the VERIFIER's pin for its signer (session.pq_pins), never its own principals
      v = verify_session_root(s, opt(opt(ctx, 'session'), 'pq_pins'))
      return bad("session root: #{v['reason']}") unless v['ok']
      return bad('intent_session.root is not the digest of the session root') unless strict_eq(session_root_digest(s), is['root'])
      return bad('the session root names another session') unless strict_eq(s['session'], is['session'])
      return bad('the session root has expired') unless now < s['expires_at']

      okv('S' => s)
    end

    # Rule 13 (`intent_session`).
    def session_step(p, grant, ctx, now)
      max_age_s = opt(opt(opt(ctx, 'policy'), 'session'), 'max_revocation_age_s')
      if !undef?(max_age_s) && !nonneg?(max_age_s)
        return bad('session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)')
      end

      is = opt(p, 'intent_session')
      return bad('this verifier requires an intent_session but the PCActn carries none') if undef?(is)

      ce = session_ctx_error(ctx)
      return bad(ce) if ce

      intent = opt(p, 'intent')
      return bad('an intent_session needs the envelope.intent binding') if undef?(intent)

      r = bound_root(p, ctx, now)
      return r unless r['ok']

      s = r['S']
      return bad('intent.ref is not the session statement') unless strict_eq(s['intent_ref'], intent['ref'])
      return bad('intent_session.schema is not the session schema') unless strict_eq(s['schema']['digest'], is['schema'])
      return bad('the session schema is for another audience') unless strict_eq(s['schema']['aud'], opt(p, 'aud'))
      if is['seq'] == 0 && !strict_eq(intent['map_digest'], s['layers']['task']['map_digest'])
        return bad('a seq-0 action must use the session task map')
      end

      gc = grant_session_caveat(grant)
      ge = intent_session_caveat_error(gc)
      return bad("admitting root: #{ge}") if ge
      if !strict_eq(gc['session'], is['session']) || !strict_eq(gc['root'], is['root']) || !strict_eq(gc['seq'], is['seq'])
        return bad('the admitting root is bound to another session, root or seq')
      end

      principals = s['principals'].map { |x| x['key'] }
      principal = ->(k) { principals.any? { |x| strict_eq(x, k) } }
      return bad('the admitting root is not signed by a session principal') unless principal.call(prop(grant, 'issuer'))

      prior = nullish_or(opt(opt(ctx, 'session'), 'grants'), [])
      seq = ival(is['seq'])
      return bad("the verifier does not hold the #{seq} earlier grants of this session") if !prior.is_a?(Array) || prior.length < seq

      (0...seq).each do |i|
        g = prior[i]
        return bad("session grant #{i} is not a capability") unless g.is_a?(Hash) && g['id'].is_a?(String) && g['issuer'].is_a?(String)

        gse = suite_err(prop(g, 'alg'))
        return bad("session grant #{i}: #{gse}") if gse

        c = grant_session_caveat(g)
        if !intent_session_caveat_error(c).nil? || !strict_eq(c['session'], is['session']) || !strict_eq(c['root'], is['root']) || !strict_eq(c['seq'], i)
          return bad("session grant #{i} does not belong to this session at seq #{i}")
        end
        return bad("session grant #{i} is not signed by a session principal") unless principal.call(g['issuer'])
        return bad("session grant #{i} does not chain to grant #{i - 1}") if i.positive? && !strict_eq(prop(c, 'prev'), prior[i - 1]['id'])
      end
      if seq.positive? && !strict_eq(prop(gc, 'prev'), prior[seq - 1]['id'])
        return bad("the admitting root does not chain to grant #{seq - 1}")
      end

      rev = prop(s, 'revocation')
      if !undef?(rev) || !undef?(max_age_s)
        ages = [undef?(rev) ? UNDEF : prop(rev, 'max_age_s'), max_age_s].reject { |x| undef?(x) }
        max_age_ms = ages.map { |x| ival(x) }.min * 1000
        return bad('revocation: the policy requires a revocation epoch but the session root names no revocation authority') if undef?(rev)

        ids = [session_revocation_id(is['session']), map_revocation_id(intent['map_digest'])] +
              prior[0, seq].map { |g| delta_revocation_id(g['id']) } + [delta_revocation_id(prop(grant, 'id'))]
        std = prop(s['layers'], 'std')
        ids << profile_revocation_id(std['profile'], std['version']) if truthy?(std)
        # only the dedicated authority S.revocation.key signs epochs; a PQ epoch verifies only under S.revocation.pq_pk
        pins = {}
        pins[rev['key']] = rev['pq_pk'] if rev.key?('pq_pk')
        rv = check_session_revocation(opt(opt(ctx, 'session'), 'revocation'), session: is['session'], authority: rev['key'], ids: ids,
                                                                            now: now, max_age_ms: max_age_ms, pins: pins,
                                                                            last: opt(opt(ctx, 'session'), 'revocation_last'))
        return bad("revocation: #{rv['reason']}") unless rv['ok']
      end
      okv
    end

    # Rule 15 (`accumulators`). On success {ok, env: {acc, mon}}.
    def acc_step(p, ctx, now)
      is = p['intent_session']
      r = bound_root(p, ctx, now)
      return r unless r['ok']

      s = r['S']
      ce = acc_ctx_error(ctx) || schema_ctx_error(ctx)
      return bad(ce) if ce

      verb = js_str(opt(action_of(p), 'verb'))
      claims = nullish_or(prop(is, 'acc'), [])
      claims.each do |c|
        a = s['accumulators'].find { |x| strict_eq(x['id'], c['id']) }
        return bad("claim '#{c['id']}' names no accumulator of the session") if a.nil?
        return bad("accumulator '#{c['id']}' is wallet-held and cannot be claimed at a site") if a['holder']['kind'] == 'wallet'
      end
      schema_doc = doc_by_digest(nullish_or(opt(opt(ctx, 'schema'), 'docs'), []), is['schema'])
      params = opt(ctx, 'params')
      env = { 'acc' => {}, 'mon' => {} }
      acc = opt(ctx, 'acc')
      state = nullish_or(opt(acc, 'state'), {})
      s['accumulators'].each do |a|
        id = a['id']
        kind = a['holder']['kind']
        next if kind == 'wallet'
        if a['sel'].key?('accumulates_into') && !truthy?(schema_doc)
          return bad("accumulator '#{id}' selects by accumulates_into but the session schema is not available")
        end

        selected = acc_selects(a, verb, schema_doc)
        claim = claims.find { |c| strict_eq(c['id'], id) }
        pre = prop(state, id)
        unless selected
          return bad("claim '#{id}' for an accumulator this action does not feed") if claim

          if kind == 'site_local' && !undef?(pre)
            pe = pre_state_error(a, pre)
            return bad("accumulator '#{id}': #{pe}") if pe

            env['acc'][id] = { 'post' => pre_value(a, pre) }
          end
          next
        end
        return bad("no claim for accumulator '#{id}' that this action feeds") if claim.nil?
        return bad('no plaintext params to compute accumulator values') unless params.is_a?(Hash)

        unless a['key'].nil?
          name = slice_from(a['key'], PARAMS_PREFIX_LEN)
          return bad("accumulator '#{id}': the key parameter #{a['key']} is missing") unless params.key?(name)

          kd = UNDEF
          if truthy?(schema_doc)
            sv = schema_verb(schema_doc, verb)
            kd = prop(sv['params'], a['key']) unless sv.nil?
          end
          free_text = lambda do
            sem = decl(kd, 'semantic')
            raise StrictError, 'semantic is not a string' unless sem.is_a?(String)

            sem.b.start_with?('text.')
          end
          return bad("accumulator '#{id}': the key must be a schema-declared identity (not free text)") if !truthy?(kd) || free_text.call
        end
        v = acc_value_of(a, verb, params, schema_doc)
        return bad("accumulator '#{id}': #{v['reason']}") unless v['ok']

        if kind == 'site_local'
          return bad("accumulator '#{id}' is site-local: a receipt is not accepted") if claim.key?('receipt')
          return bad("no state for site-local accumulator '#{id}'") if undef?(pre)

          pe = pre_state_error(a, pre)
          return bad("accumulator '#{id}': #{pe}") if pe

          post = combine_acc(a, pre, v)
          return bad("accumulator '#{id}' overflows 2^53-1") if post.nil?
        else
          return bad("accumulator '#{id}' is sequenced: the claim needs a reservation receipt") unless claim.key?('receipt')

          rc = UNDEF
          nullish_or(opt(acc, 'receipts'), []).each do |x|
            next unless (acc_receipt_digest(x) == claim['receipt'] rescue false) # rubocop:disable Style/RescueModifier

            rc = x
            break
          end
          return bad("the reservation receipt for '#{id}' was not presented") unless truthy?(rc)
          keysets = nullish_or(opt(acc, 'sequencer_keys'), [])
          pa = opt(opt(ctx, 'policy'), 'acc')
          tracked = prop(opt(acc, 'keyset_versions'), a['holder']['root'])
          fresh = {}
          fresh['max_receipt_age_ms'] = pa['max_receipt_age_s'] * 1000 if present?(pa, 'max_receipt_age_s')
          fresh['max_keyset_age_ms'] = pa['max_keyset_age_s'] * 1000 if present?(pa, 'max_keyset_age_s')
          fresh['tracked'] = tracked unless undef?(tracked)
          unless verify_receipt_against_holder(rc, a['holder'], keysets, now, fresh)
            # a receipt or key set that names a suite this verifier does not implement is refused with that reason
            se = unsupported_suite_reason(rc, keysets)
            return bad("the reservation receipt for '#{id}': #{se}") if se

            return bad("the reservation receipt for '#{id}' is not signed by a key the session sequencer's root-signed key set lists for its issue time")
          end
          if !strict_eq(rc['session'], is['session']) || !strict_eq(rc['acc'], id) || !strict_eq(rc['aud'], opt(p, 'aud'))
            return bad("the reservation receipt for '#{id}' is for another session, accumulator or audience")
          end
          return bad("the reservation receipt for '#{id}' is for another action") unless strict_eq(rc['pcactn_digest'], pcactn_reservation_digest(p))
          return bad("the reservation receipt for '#{id}' has expired") unless now <= rc['expires_at']

          last = prop(opt(acc, 'last_seq'), id)
          if !undef?(last) && !(rc['seq'] > last)
            return bad("the reservation receipt for '#{id}' replays seq #{js_str(rc['seq'])} (last accepted #{js_str(last)})")
          end
          return bad("the reservation receipt for '#{id}' does not add up") unless receipt_arithmetic_ok(a, rc, v['val'])

          post = ival(rc['post'])
        end
        if a.key?('domain_max') && post > a['domain_max']
          return bad("accumulator '#{id}' post #{post} is outside its domain (max #{js_str(a['domain_max'])})")
        end
        return bad("claimed post #{js_str(claim['post'])} for '#{id}' differs from the verifier's #{post}") unless strict_eq(claim['post'], post)

        env['acc'][id] = { 'post' => post }
      end
      mons = nullish_or(opt(acc, 'monitors'), {})
      s['monitors'].each do |m|
        st = prop(mons, m['id'])
        return bad("no valid state for monitor '#{m['id']}'") unless st.is_a?(String) && monitor_states(m).any? { |q| q.b == st.b }

        env['mon'][m['id']] = { 'state' => st }
      end
      okv('env' => env)
    end

    # Run the v2 checks in pipeline order. Returns {'checks' => [{'name', 'ok', 'reason'?}, ...], 'env' => {...}?,
    # 'schema' => doc?}. Never raises: an internal error fails the check being evaluated.
    def decide_intent_v2(p, grant, ctx, now)
      checks = []
      out = { 'checks' => checks }
      p = jsnorm(p)
      grant = jsnorm(grant)
      ctx = ctx.nil? ? UNDEF : jsnorm(ctx)
      now = jsnorm(now)
      present = !undef?(opt(p, 'intent_session'))
      clock_ok = int?(now)
      ctx_err = intent_v2_context_error(ctx)
      unless ctx_err.nil?
        # a malformed verifier context fails closed: every v2 check that could be reported fails with the reason
        committed = present && strict_eq(prop(opt(p, 'intent_session'), 'map_form'), MAP_FORM_COMMIT)
        (%w[schema intent_session] + (present ? %w[accumulators] : []) + (committed ? %w[map] : [])).each do |name|
          checks << { 'name' => name, 'ok' => false, 'reason' => "malformed v2 context: #{ctx_err}" }
        end
        return out
      end
      run = lambda do |name, &f|
        s = begin
          clock_ok ? f.call : bad('the verifier clock is not a safe integer (fail closed)')
        rescue StandardError, SystemStackError => e
          bad("#{name} error (fail closed): #{e.message}")
        end
        checks << (s['ok'] ? { 'name' => name, 'ok' => true } : { 'name' => name, 'ok' => false, 'reason' => s['reason'] })
        s
      end
      verb = js_str(opt(action_of(p), 'verb'))
      if present || strict_eq(opt(opt(opt(ctx, 'policy'), 'schema'), 'closed_world'), true)
        run.call('schema') do
          s = schema_step(p, ctx)
          if s['ok']
            out['schema'] = s['doc']
            out['env'] = { 'canon' => canon_projection(s['doc'], verb, ctx['params']) }
          end
          s
        end
      end
      run.call('intent_session') { session_step(p, grant, ctx, now) } if present || strict_eq(opt(opt(opt(ctx, 'policy'), 'session'), 'require'), true)
      map_active = strict_eq(prop(opt(p, 'intent_session'), 'map_form'), MAP_FORM_COMMIT) ||
                   strict_eq(opt(opt(opt(ctx, 'policy'), 'map'), 'require'), true)
      params = opt(ctx, 'params')
      action = { 'verb' => verb, 'resource' => js_str(opt(action_of(p), 'resource')), 'params' => params.is_a?(Hash) ? params : {} }
      layers = opt(ctx, 'layers')
      if present && !undef?(layers)
        run.call('layers') do
          canon = out['env'] && out['env']['canon']
          d = AtlasPca.decide_layer_ceilings(layers, { 'action' => action, 'env' => canon ? { 'canon' => canon } : {} })
          d['status'] == 'pass' ? okv : bad(d['reason'])
        end
      end
      unless present
        run.call('map') { map_step(p, ctx) } if map_active
        return out
      end

      run.call('accumulators') do
        s = acc_step(p, ctx, now)
        out['env'] = (out['env'] || {}).merge(s['env']) if s['ok']
        s
      end
      run.call('map') { map_step(p, ctx) } if map_active
      wb = nil
      begin
        is = p['intent_session']
        wbc = opt(ctx, 'wb')
        inp = { 'now' => now, 'aud' => js_str(opt(p, 'aud')), 'session' => is['session'], 'action' => action, 'intent_session' => is }
        arts = opt(wbc, 'artifacts')
        inp['artifacts'] = arts if truthy?(arts)
        inp['policy'] = nullish_or(opt(wbc, 'policy'), {})
        wb = AtlasPca.decide_intent_wb(inp)
      rescue StandardError, SystemStackError => e
        checks << { 'name' => 'facts', 'ok' => false, 'reason' => "W-B error (fail closed): #{e.message}" }
      end
      if wb.is_a?(Hash)
        wchecks = wb['checks'].is_a?(Hash) ? wb['checks'] : {}
        reason = wb['reason']
        %w[facts provenance classes].each do |name|
          c = wchecks[name]
          next if c.nil?

          if c == 'pass'
            checks << { 'name' => name, 'ok' => true }
          else
            why = c == 'question' ? "intent_required: #{reason.nil? ? 'a question is required' : reason}" : (reason.nil? ? 'rejected' : reason)
            checks << { 'name' => name, 'ok' => false, 'reason' => why }
          end
        end
        if wb['outcome'] != 'deny'
          we = wb['env'].is_a?(Hash) ? wb['env'] : {}
          merged = (out['env'] || {}).dup
          %w[world prov class].each { |k| merged[k] = we[k] if truthy?(prop(we, k)) }
          out['env'] = merged
        end
      end
      out
    rescue StandardError, SystemStackError
      out
    end

    # True iff any v2 check would be reported (the PCActn carries `intent_session` or a v2 policy is active).
    def intent_v2_active?(p, ctx)
      ctx = ctx.nil? ? UNDEF : jsnorm(ctx)
      !undef?(opt(p, 'intent_session')) || strict_eq(opt(opt(opt(ctx, 'policy'), 'schema'), 'closed_world'), true) ||
        strict_eq(opt(opt(opt(ctx, 'policy'), 'session'), 'require'), true) || strict_eq(opt(opt(opt(ctx, 'policy'), 'map'), 'require'), true)
    rescue StandardError
      false
    end
  end

  # ======================= public API (module functions of AtlasPca) =======================
  module_function

  INTENT_SESSION_FIELDS = IntentV2::INTENT_SESSION_FIELDS
  ACTION_SCHEMA_DOMAIN = IntentV2::ACTION_SCHEMA_DOMAIN
  ACTION_SCHEMA_REF_DOMAIN = IntentV2::ACTION_SCHEMA_REF_DOMAIN
  INTENT_SESSION_SIG_DOMAIN = IntentV2::INTENT_SESSION_SIG_DOMAIN
  INTENT_SESSION_REF_DOMAIN = IntentV2::INTENT_SESSION_REF_DOMAIN
  ACC_RECEIPT_DOMAIN = IntentV2::ACC_RECEIPT_DOMAIN
  ACC_RECEIPT_REF_DOMAIN = IntentV2::ACC_RECEIPT_REF_DOMAIN
  ACC_RESERVE_DOMAIN = IntentV2::ACC_RESERVE_DOMAIN
  SEQUENCER_KEYS_DOMAIN = IntentV2::SEQUENCER_KEYS_DOMAIN
  REVEPOCH_DOMAIN = IntentV2::REVEPOCH_DOMAIN

  # Intent Layer v2 checks after `intent`: {'checks' => [...], 'env' => ..., 'schema' => ...}. `ctx` is the verifier state
  # (String keys): policy, params, schema {docs, keys}, session {root, grants, revocation {epoch, proofs}}, layers,
  # acc {state, monitors, receipts, last_seq, sequencer_keys}, wb {artifacts, policy}. Never raises.
  def decide_intent_v2(pcactn, grant, ctx, now) = IntentV2.decide_intent_v2(pcactn, grant, ctx, now)
  def intent_v2_active?(pcactn, ctx) = IntentV2.intent_v2_active?(pcactn, ctx)
  def intent_v2_context_error(ctx) = IntentV2.intent_v2_context_error(ctx.nil? ? V2JS::UNDEF : V2JS.jsnorm(ctx))
  def validate_intent_session_wire(v) = IntentV2.validate_intent_session_wire(v)
  def intent_session_caveat_error(c) = IntentV2.intent_session_caveat_error(c)
  def intent_goal_v2(session, map_digest, map_form = nil) = IntentV2.intent_goal_v2(session, map_digest, map_form)
  def grant_session_caveat(grant) = IntentV2.grant_session_caveat(grant)

  def action_schema_shape_error(doc, signed: true) = IntentV2.action_schema_shape_error(V2JS.jsnorm(doc), signed)
  def verify_action_schema(doc, keys) = IntentV2.verify_action_schema(V2JS.jsnorm(doc), V2JS.jsnorm(keys))
  def action_schema_digest(doc) = IntentV2.action_schema_digest(V2JS.jsnorm(doc))
  def schema_verb(doc, verb) = IntentV2.schema_verb(V2JS.jsnorm(doc), verb)
  def conform_action(doc, verb, params) = IntentV2.conform_action(V2JS.jsnorm(doc), verb, V2JS.jsnorm(params))
  def param_value_violation(decl, x) = IntentV2.param_value_violation(V2JS.jsnorm(decl), V2JS.jsnorm(x))
  def accumulation_params(verb_decl, unit) = IntentV2.accumulation_params(V2JS.jsnorm(verb_decl), unit)
  def canon_projection(doc, verb, params) = IntentV2.canon_projection(V2JS.jsnorm(doc), verb, V2JS.jsnorm(params))
  def calendar_date?(s) = IntentV2.calendar_date?(s)

  def session_root_shape_error(s, signed: true) = IntentV2.session_root_shape_error(V2JS.jsnorm(s), signed)
  def verify_session_root(s, pq_pins = nil) = IntentV2.verify_session_root(V2JS.jsnorm(s), pq_pins.nil? ? nil : V2JS.jsnorm(pq_pins))
  def session_root_digest(s) = IntentV2.session_root_digest(V2JS.jsnorm(s))

  def accumulator_decl_error(a) = IntentV2.accumulator_decl_error(V2JS.jsnorm(a))
  def monitor_decl_error(m) = IntentV2.monitor_decl_error(V2JS.jsnorm(m))
  def monitor_states(m) = IntentV2.monitor_states(m)
  def acc_selects(a, verb, schema = V2JS::UNDEF) = IntentV2.acc_selects(a, verb, V2JS.jsnorm(schema))
  def acc_value_of(a, verb, params, schema = V2JS::UNDEF) = IntentV2.acc_value_of(a, verb, V2JS.jsnorm(params), V2JS.jsnorm(schema))
  def distinct_key(x) = IntentV2.distinct_key(x)
  def pre_state_error(a, s) = IntentV2.pre_state_error(a, s)
  def combine_acc(a, pre, v) = IntentV2.combine_acc(a, pre, v)
  def pre_value(a, pre) = IntentV2.pre_value(a, pre)
  def acc_receipt_shape_error(r) = IntentV2.acc_receipt_shape_error(r)
  def verify_acc_receipt_signature(r, expected_signer, pins = nil) = IntentV2.verify_acc_receipt_signature(V2JS.jsnorm(r), expected_signer, pins)
  def acc_receipt_digest(r) = IntentV2.acc_receipt_digest(V2JS.jsnorm(r))
  def pcactn_reservation_digest(p) = IntentV2.pcactn_reservation_digest(V2JS.jsnorm(p))
  def sequencer_key_set_shape_error(k) = IntentV2.sequencer_key_set_shape_error(k)
  def verify_sequencer_key_set(k, root, root_pq_pk = V2JS::UNDEF) = IntentV2.verify_sequencer_key_set(V2JS.jsnorm(k), root, root_pq_pk)

  def sequencer_key_set_digest(ks) = IntentV2.sequencer_key_set_digest(V2JS.jsnorm(ks))
  def tracked_key_set_error(t) = IntentV2.tracked_key_set_error(V2JS.jsnorm(t))

  # `fresh`: {'max_receipt_age_ms'?, 'max_keyset_age_ms'?, 'tracked'? {version, digest}, 'min_keyset_version'?} (absent =
  # default 15 min / 1 h / untracked).
  def verify_receipt_against_holder(r, holder, key_sets, now, fresh = {})
    IntentV2.verify_receipt_against_holder(V2JS.jsnorm(r), V2JS.jsnorm(holder), V2JS.jsnorm(key_sets), V2JS.jsnorm(now), V2JS.jsnorm(fresh))
  rescue StandardError
    false
  end

  def receipt_arithmetic_ok(a, r, val) = IntentV2.receipt_arithmetic_ok(a, r, val)
  def revocation_epoch_shape_error(ep) = IntentV2.revocation_epoch_shape_error(V2JS.jsnorm(ep))
  def revset_root(list) = IntentV2.revset_root(list)

  def check_revocation_epoch(ep, guardian_public, now, grant_ref = V2JS::UNDEF, pins = nil)
    IntentV2.check_revocation_epoch(V2JS.jsnorm(ep), guardian_public, V2JS.jsnorm(now), grant_ref, pins)
  end

  def session_revocation_id(session) = IntentV2.session_revocation_id(session)
  def map_revocation_id(map_digest) = IntentV2.map_revocation_id(map_digest)
  def delta_revocation_id(grant_id) = IntentV2.delta_revocation_id(grant_id)
  def profile_revocation_id(profile_id, version) = IntentV2.profile_revocation_id(profile_id, version)
  def session_revocation_scope(session) = IntentV2.session_revocation_scope(session)
  def profile_revocation_scope(profile_id) = IntentV2.profile_revocation_scope(profile_id)

  # checkSessionRevocation; `ev` = {'epoch', 'revoked'} (the full signed list). `authority:` the dedicated revocation key
  # (S.revocation.key); `scope:` overrides the session scope; `pins:` {key => pq_pk}; `last:` the tracked last evidence.
  def check_session_revocation(ev, session:, authority:, ids:, now:, max_age_ms:, scope: V2JS::UNDEF, pins: nil, last: V2JS::UNDEF)
    IntentV2.check_session_revocation(V2JS.jsnorm(ev), session: session, authority: authority, ids: ids, now: V2JS.jsnorm(now),
                                                         max_age_ms: V2JS.jsnorm(max_age_ms), scope: scope, pins: pins,
                                                         last: V2JS.undef?(last) ? last : V2JS.jsnorm(last))
  end

  # primitives.intent_revocation input {epoch, revoked, session, authority, ids, now, max_age_ms, scope?, last?} (the
  # evidence is every member that is not a parameter) ->
  # {'ok', 'reason'?}. An absent member stays absent (UNDEF) and a null one is null: both refused where the rule reads them.
  def intent_revocation_primitive(input)
    i = V2JS.jsnorm(input)
    g = ->(k) { V2JS.prop(i, k) }
    # the evidence is the input WITHOUT the parameters: every remaining member (an extra one makes it malformed)
    params = %w[session scope authority ids now max_age_ms last]
    ev = i.is_a?(Hash) ? i.reject { |k, _| params.include?(k) } : {}
    IntentV2.check_session_revocation(ev, session: g.call('session'), authority: g.call('authority'), ids: g.call('ids'),
                                          now: g.call('now'), max_age_ms: g.call('max_age_ms'), scope: g.call('scope'), last: g.call('last'))
  rescue StandardError
    { 'ok' => false, 'reason' => 'malformed input' }
  end

  # Rule 19 (V15): the committed map. `map_commit_of_leaves` recomputes the commitment of a full leaf list
  # ([{kind, salt, leaf}], primitives.intent_map_commit); `decide_map_disclosure` is the Z0 decision.
  MAP_TAG_HEADER = IntentV2::MAP_TAG_HEADER
  MAP_TAG_CELL = IntentV2::MAP_TAG_CELL
  MAP_TAG_METRICS = IntentV2::MAP_TAG_METRICS
  MAP_TAG_LEARNER = IntentV2::MAP_TAG_LEARNER
  MAP_TAG_NODE = IntentV2::MAP_TAG_NODE
  MAP_TAG_COMMIT = IntentV2::MAP_TAG_COMMIT

  def map_commit_of_leaves(leaves) = IntentV2.map_commit_of_leaves(V2JS.jsnorm(leaves))
  def map_leaf_hash(kind, salt, leaf) = IntentV2.map_leaf_hash(kind, salt, V2JS.jsnorm(leaf))
  def map_node_hash(l, r) = IntentV2.map_node_hash(l, r)
  def map_commit_of(size, root) = IntentV2.map_commit_of(size, root)
  def map_root_from_path(index, size, leaf_hash, path) = IntentV2.map_root_from_path(index, size, leaf_hash, path)
  def map_num_cells(dim) = IntentV2.map_num_cells(V2JS.jsnorm(dim))
  def map_header_error(h) = IntentV2.map_header_error(V2JS.jsnorm(h))
  def map_cell_error(c) = IntentV2.map_cell_error(V2JS.jsnorm(c))
  def map_metrics_error(m) = IntentV2.map_metrics_error(V2JS.jsnorm(m))
  def map_learner_error(l) = IntentV2.map_learner_error(V2JS.jsnorm(l))
  def map_disclosure_error(d) = IntentV2.map_disclosure_error(V2JS.jsnorm(d))
  def map_cell_of(header, resource, params) = IntentV2.map_cell_of(V2JS.jsnorm(header), V2JS.jsnorm(resource), V2JS.jsnorm(params))

  # decideMapDisclosure: `params` / `max_residual_risk_ppm` omitted = absent.
  def decide_map_disclosure(map_commit:, action:, disclosure:, params: V2JS::UNDEF, max_residual_risk_ppm: V2JS::UNDEF)
    IntentV2.decide_map_disclosure(map_commit, V2JS.jsnorm(action), V2JS.undef?(params) ? params : V2JS.jsnorm(params),
                                   V2JS.jsnorm(disclosure), V2JS.jsnorm(max_residual_risk_ppm))
  end

  # primitives.intent_map input {map_commit, action, params?, disclosure, max_residual_risk_ppm?} -> the decision.
  def intent_map_primitive(input)
    i = V2JS.jsnorm(input)
    g = ->(k) { V2JS.prop(i, k) }
    IntentV2.decide_map_disclosure(g.call('map_commit'), V2JS.nullish_or(g.call('action'), {}), g.call('params'), g.call('disclosure'),
                                   g.call('max_residual_risk_ppm'))
  rescue StandardError
    { 'ok' => false, 'reason' => 'malformed input' }
  end
end
