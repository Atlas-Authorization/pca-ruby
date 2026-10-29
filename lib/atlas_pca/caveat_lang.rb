# frozen_string_literal: true

# Caveat language v2: a port of packages/pca/src/caveat-lang.ts (security contract C-220 to C-229). Six verifier-side
# features, every one of them a RESTRICTION (conjunctive with the rest of the chain; an unknown caveat type stays
# unsatisfied):
#
#   needs_discharge  a third-party caveat, valid only with a signed discharge from a key THE VERIFIER pinned
#   sealed           no hop may be appended below the hop that carries it
#   narrow           a holder-signed per-action or short-lived self-attenuation that rides beside the PCActn (no new hop)
#   max_uses         a lifetime use count spent through the verifier's replay store
#   derive           a bounded, stratified, non-recursive derived-fact check in Kleene three-valued logic
#   spiffe_bound     the presenting workload's verified SPIFFE ID must match
#
# Inputs are String-keyed Hashes shaped like the TypeScript interfaces; results are symbol-keyed Hashes (like
# verify_escalation_answer) except the `bound` caveat records, which keep the String keys the shared vectors use. Reason
# strings are the TypeScript reference's. Every function is total: a malformed input is a refusal, never an exception and
# never an allow.
#
# max_uses and the Ruby store: a use slot is spent with StateStore#consume_once(slot_key, until, now): the first consume
# wins, every later one is refused until the slot's `until` has passed (then the store may forget it). A store without
# consume_once falls back to claim(slot_key, 1), which remembers the slot for the life of the store.
module AtlasPca
  module_function

  CAVEAT_NEEDS_DISCHARGE = 'needs_discharge'
  CAVEAT_SEALED = 'sealed'
  CAVEAT_MAX_USES = 'max_uses'
  CAVEAT_DERIVE = 'derive'
  CAVEAT_SPIFFE_BOUND = 'spiffe_bound'
  K1_CAVEAT_TYPES = [CAVEAT_NEEDS_DISCHARGE, CAVEAT_SEALED, CAVEAT_MAX_USES, CAVEAT_DERIVE, CAVEAT_SPIFFE_BOUND].freeze

  DISCHARGE_DOMAIN = "atlas-pca/discharge/v1\x00"
  DISCHARGE_REF_DOMAIN = 'atlas-pca/discharge-ref/v1'
  DISCHARGE_ACTION_DOMAIN = 'atlas-pca/discharge-action/v1'
  NARROW_DOMAIN = "atlas-pca/narrow/v1\x00"
  MAX_USES_DOMAIN = "atlas-pca/max-uses/v1\x00"
  K1_MAX_LIFETIME_MS = 86_400_000
  MAX_USES_LIMIT = 256
  NARROW_MAX_CAVEATS = 16
  DERIVE_MAX_DEFS = 8
  DERIVE_MAX_NODES = 32
  DERIVE_MAX_DEPTH = 4
  DERIVE_MAX_WINDOW_MS = 30 * 86_400_000
  DERIVE_MAX_HISTORY = 10_000
  SPIFFE_MAX_ID_BYTES = 2048

  K1_NAME_RE = /\A[a-z][a-z0-9_]{0,63}\z/
  K1_ID_RE = /\A[a-z0-9][a-z0-9_.-]{0,63}\z/
  K1_ISSUER_CLASSES = %w[human org workload model artifact].freeze
  K1_OPS = %w[eq neq gte lte in].freeze
  K1_CMP_OPS = %w[eq neq lt lte gt gte].freeze
  K1_NARROW_FORBIDDEN = ['envelope', CAVEAT_SEALED, 'budget_alloc', 'intent_session'].freeze
  K1_D_REQUIRED = %w[v kind caveat_id issuer cap_hash bind claims iat not_after nonce sig].freeze
  K1_D_OPTIONAL = %w[action_digest alg pq_pk pq_sig].freeze
  K1_N_REQUIRED = %w[v kind cap_hash holder caveats iat not_after nonce sig].freeze
  K1_N_OPTIONAL = %w[action_digest alg pq_pk pq_sig].freeze

  # ---- small helpers -----------------------------------------------------------------------------------------------

  def k1_match?(re, s) = s.is_a?(String) && s.valid_encoding? && re.match?(s)

  def k1_str256?(v) = wb_bounded?(v, 256)

  # A wire scalar a claim or constant may hold: a string of 1..256 bytes, a boolean or a safe integer.
  def k1_scalar?(v) = wb_scalar?(v) && (!v.is_a?(String) || k1_str256?(v))

  def k1_type?(c) = c.is_a?(Hash) && c['type'].is_a?(String) && K1_CAVEAT_TYPES.include?(c['type'])

  # Positive integer in [lo, hi] as a JS safe integer.
  def k1_int_in?(v, lo, hi) = wb_safe_int?(v) && v >= lo && v <= hi

  def k1_err_text(err) = err.message.to_s

  # ---- SPIFFE ID syntax ----------------------------------------------------------------------------------------------

  # nil when `s` is a valid SPIFFE ID (spiffe:// + trust domain [a-z0-9._-] + optional path of non-empty [A-Za-z0-9._-]
  # segments that are not . or .., no trailing slash, no query or fragment, at most 2048 bytes), else the reason.
  def spiffe_id_error(s)
    return 'SPIFFE ID must be a non-empty string' unless s.is_a?(String) && !s.empty?
    return 'SPIFFE ID is too long' if s.bytesize > SPIFFE_MAX_ID_BYTES
    return 'SPIFFE ID must begin with spiffe://' unless s.b.start_with?('spiffe://'.b)
    return 'invalid trust domain' unless s.valid_encoding?

    rest = s[9..]
    slash = rest.index('/')
    td = slash.nil? ? rest : rest[0...slash]
    path = slash.nil? ? '' : rest[slash..]
    return 'invalid trust domain' if td.empty? || td.bytesize > 255 || !td.match?(/\A[a-z0-9._-]+\z/)
    return nil if path.empty?
    return 'path must not end with a slash' if path.end_with?('/')

    path.split('/', -1)[1..].each do |seg|
      return 'invalid path segment' if seg.empty? || seg == '.' || seg == '..' || !seg.match?(/\A[A-Za-z0-9._-]+\z/)
    end
    nil
  end

  # ---- hop analysis ------------------------------------------------------------------------------------------------

  # The hops the policy layer sees: the chain (root first), else the grant alone.
  def k1_hops(grant, chain)
    chain.is_a?(Array) && !chain.empty? ? chain : [grant]
  end

  # Every caveat of the leaf hop with the hop that introduced it: [{'caveat', 'hop', 'cap_hash'}], or nil for a malformed
  # chain. Caveat lists are cumulative and append-only, so the caveat at position p was introduced by the first hop whose
  # list is longer than p.
  def bound_caveats(grant, chain = nil)
    hops = k1_hops(grant, chain)
    leaf = hops[-1]
    return nil unless leaf.is_a?(Hash) && leaf['caveats'].is_a?(Array)

    hashes = {}
    leaf['caveats'].each_with_index.map do |caveat, p|
      h = hops.index { |x| x.is_a?(Hash) && x['caveats'].is_a?(Array) && x['caveats'].length > p } || (hops.length - 1)
      hashes[h] = cap_hash(hops[h]) unless hashes.key?(h)
      { 'caveat' => caveat, 'hop' => h, 'cap_hash' => hashes[h] }
    end
  rescue StandardError, SystemStackError
    nil
  end

  # ---- needs_discharge ---------------------------------------------------------------------------------------------

  def k1_require_error(r)
    return 'requirement must be an object' unless r.is_a?(Hash)

    e = wb_closed_members(r, %w[claim op value], [], 'require')
    return e if e
    return 'claim name is malformed' unless k1_match?(K1_NAME_RE, r['claim'])
    return 'op must be eq, neq, gte, lte or in' unless K1_OPS.include?(r['op'])

    v = r['value']
    case r['op']
    when 'in'
      return "'in' needs 1..16 scalar values" unless v.is_a?(Array) && !v.empty? && v.length <= 16 && v.all? { |x| k1_scalar?(x) }
    when 'gte', 'lte'
      return "'#{r['op']}' needs a safe integer" unless wb_safe_int?(v)
    else
      return 'value must be a scalar' unless k1_scalar?(v)
    end
    nil
  end

  # nil when the needs_discharge caveat is well-formed, else the reason.
  def needs_discharge_error(c)
    return 'caveat must be an object' unless c.is_a?(Hash)

    e = wb_closed_members(c, %w[type id issuer issuer_class bind ttl_ms require], ['issuer_spiffe'], 'needs_discharge')
    return e if e
    return 'not a needs_discharge caveat' unless c['type'] == CAVEAT_NEEDS_DISCHARGE
    return 'id is malformed' unless k1_match?(K1_ID_RE, c['id'])
    return 'issuer label is malformed' unless k1_match?(K1_ID_RE, c['issuer'])
    return 'issuer_class must be human, org, workload, model or artifact' unless K1_ISSUER_CLASSES.include?(c['issuer_class'])
    return "bind must be 'chain_hop' or 'action'" unless %w[chain_hop action].include?(c['bind'])
    return 'ttl_ms must be 1..86400000' unless k1_int_in?(c['ttl_ms'], 1, K1_MAX_LIFETIME_MS)
    return 'require must be an array of at most 16 requirements' unless c['require'].is_a?(Array) && c['require'].length <= 16

    c['require'].each do |r|
      re = k1_require_error(r)
      return re if re
    end
    if c.key?('issuer_spiffe')
      se = spiffe_id_error(c['issuer_spiffe'])
      return "issuer_spiffe: #{se}" if se
    end
    nil
  end

  # The digest of the exact PCActn (counter and signature included): a bind-action discharge authorises that one action.
  def discharge_action_digest(pcactn)
    wb_hash({ 'd' => DISCHARGE_ACTION_DOMAIN, 'pcactn' => pcactn })
  end

  # Content address of a discharge (signature included); what a revocation list names.
  def discharge_digest(discharge)
    wb_artifact_ref(DISCHARGE_REF_DOMAIN, 'discharge', discharge)
  end

  # nil when the discharge is well-formed (closed members, canonical digests and nonce, bounded claims and lifetime).
  def discharge_shape_error(a)
    return 'not an object' unless a.is_a?(Hash)

    e = wb_closed_members(a, K1_D_REQUIRED, K1_D_OPTIONAL, 'discharge')
    return e if e
    return 'not a pca-discharge v1' unless a['v'] == 1 && a['kind'] == 'pca-discharge'
    return 'caveat_id is malformed' unless k1_match?(K1_ID_RE, a['caveat_id'])
    return 'issuer label is malformed' unless k1_match?(K1_ID_RE, a['issuer'])
    return 'cap_hash must be canonical base64url (32 bytes)' unless wb_digest?(a['cap_hash'])
    return "bind must be 'chain_hop' or 'action'" unless %w[chain_hop action].include?(a['bind'])

    bad_ad = a['bind'] == 'action' ? !wb_digest?(a['action_digest']) : a.key?('action_digest')
    return 'action_digest is required for bind action and forbidden for chain_hop' if bad_ad
    return 'claims must be an object of at most 16 members' unless a['claims'].is_a?(Hash) && a['claims'].length <= 16

    a['claims'].each { |k, v| return "claim '#{k}' is malformed" unless k1_match?(K1_NAME_RE, k) && k1_scalar?(v) }
    unless wb_safe_int?(a['iat']) && a['iat'] >= 0 && wb_safe_int?(a['not_after']) && a['not_after'] >= 0
      return 'iat and not_after must be non-negative safe integers'
    end
    return 'not_after must be greater than iat' unless a['not_after'] > a['iat']
    return "a discharge lives at most #{K1_MAX_LIFETIME_MS} ms" if a['not_after'] - a['iat'] > K1_MAX_LIFETIME_MS

    nb = a['nonce'].is_a?(String) ? b64d(a['nonce']) : nil
    return 'nonce must be canonical base64url of at least 16 bytes' if nb.nil? || nb.bytesize < 16
    return 'sig must be a string' unless a['sig'].is_a?(String)

    wb_artifact_suite_error(a)
  end

  def k1_claim_holds?(r, claims)
    return false unless claims.key?(r['claim'])

    v = claims[r['claim']]
    case r['op']
    when 'eq' then scalar_eq(v, r['value'])
    when 'neq' then !scalar_eq(v, r['value'])
    when 'gte' then wb_safe_int?(v) && v >= r['value']
    when 'lte' then wb_safe_int?(v) && v <= r['value']
    when 'in' then r['value'].any? { |x| scalar_eq(v, x) }
    else false
    end
  end

  # Verify one discharge against one caveat. `bind` is {'cap_hash', 'action_digest'?, 'pins', 'now', 'revoked'?}: the
  # verifier's own pins decide the key; the discharge is bound to the hop carrying the caveat (and for `action` to the
  # PCActn), inside its window and the caveat's ttl_ms; its claims must satisfy every requirement.
  # {ok: true, digest:, claims:} or {ok: false, reason:}. Total.
  def verify_discharge(discharge, caveat, bind)
    no = ->(r) { { ok: false, reason: r } }
    return no.call('the verifier clock is not a safe integer (fail closed)') unless wb_safe_int?(bind['now'])

    ce = needs_discharge_error(caveat)
    return no.call("malformed needs_discharge caveat: #{ce}") if ce

    c = caveat
    de = discharge_shape_error(discharge)
    return no.call("malformed discharge: #{de}") if de

    d = discharge
    return no.call('the discharge is for another caveat') unless d['caveat_id'] == c['id']
    return no.call('the discharge names another issuer') unless d['issuer'] == c['issuer']
    return no.call('no issuer is pinned') unless bind['pins'].is_a?(Array)

    pins = bind['pins'].select { |p| p.is_a?(Hash) && p['label'] == c['issuer'] }
    return no.call('the issuer is not pinned by this verifier') if pins.empty?
    return no.call('the issuer label is pinned more than once (ambiguous)') if pins.length > 1

    pin = pins[0]
    return no.call('the pinned issuer is not of the class the caveat requires') unless pin['class'] == c['issuer_class']
    if c.key?('issuer_spiffe') && pin['spiffe_id'] != c['issuer_spiffe']
      return no.call('the pinned issuer does not carry the SPIFFE ID the caveat requires')
    end
    return no.call('discharge signature invalid') unless wb_verify_artifact_sig(DISCHARGE_DOMAIN, d, pin)
    return no.call('the discharge binds differently than the caveat requires') unless d['bind'] == c['bind']
    return no.call('the discharge is bound to another hop') unless d['cap_hash'] == bind['cap_hash']
    return no.call('the discharge is bound to another action') if c['bind'] == 'action' && d['action_digest'] != bind['action_digest']
    return no.call('the discharge is from the future') if bind['now'] < d['iat']
    return no.call('the discharge has expired') if bind['now'] > d['not_after']
    return no.call('the discharge lives longer than the caveat allows') if d['not_after'] - d['iat'] > c['ttl_ms']

    digest = discharge_digest(d)
    return no.call('the discharge is revoked') if bind['revoked'].is_a?(Array) && bind['revoked'].include?(digest)

    c['require'].each { |r| return no.call("claim '#{r['claim']}' does not satisfy the caveat") unless k1_claim_holds?(r, d['claims']) }
    { ok: true, digest: digest, claims: d['claims'] }
  rescue StandardError, SystemStackError => e
    { ok: false, reason: "discharge error (fail closed): #{k1_err_text(e)}" }
  end

  # ---- narrow ------------------------------------------------------------------------------------------------------

  # nil when the narrow block is well-formed, else the reason.
  def narrow_shape_error(a)
    return 'not an object' unless a.is_a?(Hash)

    e = wb_closed_members(a, K1_N_REQUIRED, K1_N_OPTIONAL, 'narrow')
    return e if e
    return 'not a pca-narrow v1' unless a['v'] == 1 && a['kind'] == 'pca-narrow'
    return 'cap_hash must be canonical base64url (32 bytes)' unless wb_digest?(a['cap_hash'])
    return 'holder must be canonical base64url (32 bytes)' unless wb_bounded?(a['holder'], 64) && !b64d(a['holder'], 32).nil?
    unless a['caveats'].is_a?(Array) && a['caveats'].length >= 1 && a['caveats'].length <= NARROW_MAX_CAVEATS
      return "caveats must be 1..#{NARROW_MAX_CAVEATS} caveats"
    end

    a['caveats'].each do |c|
      return 'every caveat must be an object with a string type' unless c.is_a?(Hash) && c['type'].is_a?(String)
      return "a narrow block cannot carry a '#{c['type']}' caveat" if K1_NARROW_FORBIDDEN.include?(c['type'])
    end
    return 'action_digest must be canonical base64url (32 bytes)' if a.key?('action_digest') && !wb_digest?(a['action_digest'])
    unless wb_safe_int?(a['iat']) && a['iat'] >= 0 && wb_safe_int?(a['not_after']) && a['not_after'] >= 0
      return 'iat and not_after must be non-negative safe integers'
    end
    return 'not_after must be greater than iat' unless a['not_after'] > a['iat']
    return "a narrow block lives at most #{K1_MAX_LIFETIME_MS} ms" if a['not_after'] - a['iat'] > K1_MAX_LIFETIME_MS

    nb = a['nonce'].is_a?(String) ? b64d(a['nonce']) : nil
    return 'nonce must be canonical base64url of at least 16 bytes' if nb.nil? || nb.bytesize < 16
    return 'sig must be a string' unless a['sig'].is_a?(String)

    wb_artifact_suite_error(a)
  end

  # Verify a narrow block against the chain's leaf: signed by the leaf holder (a non-Ed25519 suite only under the PQ key
  # the leaf's holder_pq commits to), bound to the leaf hop and, when it names one, to this PCActn, inside its window.
  # `bind` is {'now', 'action_digest'?}. {ok: true, caveats:} or {ok: false, reason:}. Total.
  def verify_narrow(narrow, grant, chain, bind)
    no = ->(r) { { ok: false, reason: r } }
    return no.call('the verifier clock is not a safe integer (fail closed)') unless wb_safe_int?(bind['now'])

    e = narrow_shape_error(narrow)
    return no.call("malformed narrow block: #{e}") if e

    n = narrow
    leaf = k1_hops(grant, chain)[-1]
    return no.call('malformed capability chain') unless leaf.is_a?(Hash)
    return no.call('the narrow block is not signed by the leaf holder') unless n['holder'] == leaf['holder']
    return no.call('the narrow block is bound to another hop') unless n['cap_hash'] == cap_hash(leaf)

    pin = { 'pk' => n['holder'] }
    if n.key?('pq_pk') && leaf.key?('holder_pq') && holder_pq_commitment(n['pq_pk']) == leaf['holder_pq']
      pin['pq_pk'] = n['pq_pk']
    end
    return no.call('narrow signature invalid') unless wb_verify_artifact_sig(NARROW_DOMAIN, n, pin)
    return no.call('the narrow block is bound to another action') if n.key?('action_digest') && n['action_digest'] != bind['action_digest']
    return no.call('the narrow block is from the future') if bind['now'] < n['iat']
    return no.call('the narrow block has expired') if bind['now'] > n['not_after']

    { ok: true, caveats: n['caveats'] }
  rescue StandardError, SystemStackError => e
    { ok: false, reason: "narrow error (fail closed): #{k1_err_text(e)}" }
  end

  # ---- max_uses ----------------------------------------------------------------------------------------------------

  # nil when the max_uses caveat is well-formed, else the reason.
  def max_uses_error(c)
    return 'caveat must be an object' unless c.is_a?(Hash)

    e = wb_closed_members(c, %w[type id n until], [], 'max_uses')
    return e if e
    return 'not a max_uses caveat' unless c['type'] == CAVEAT_MAX_USES
    return 'id is malformed' unless k1_match?(K1_ID_RE, c['id'])
    return "n must be 1..#{MAX_USES_LIMIT}" unless k1_int_in?(c['n'], 1, MAX_USES_LIMIT)
    return 'until must be a non-negative safe integer' unless wb_safe_int?(c['until']) && c['until'] >= 0

    nil
  end

  # The store key of use slot `i` of caveat `id` carried by hop `cap`: b64u(sha256(domain NUL cap NUL id NUL i)).
  def max_uses_slot_key(cap, id, i)
    b64e(sha([MAX_USES_DOMAIN, cap.to_s, "\x00", id.to_s, "\x00", i.to_s].map(&:b).join))
  end

  # Spend one use of every max_uses caveat of `bound` ([{'caveat', 'cap_hash'}]), in order, after the rest of the decision
  # allows. Each caveat takes the first free slot of its n (an atomic store.claim(slot_key, 1), so concurrent actions never
  # share a slot). The first exhausted, expired or malformed caveat refuses; slots already taken stay spent.
  # {ok: true, spent:} or {ok: false, reason:}. Total.
  def reserve_max_uses(store, bound, now)
    return { ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' } unless wb_safe_int?(now)

    spent = 0
    ids = {}
    bound.each do |b|
      caveat = b['caveat']
      next unless caveat.is_a?(Hash) && caveat['type'] == CAVEAT_MAX_USES

      err = max_uses_error(caveat)
      return { ok: false, reason: "malformed max_uses caveat: #{err}" } if err

      key = "#{b['cap_hash']}\x00#{caveat['id']}"
      return { ok: false, reason: "duplicate max_uses id '#{caveat['id']}'" } if ids.key?(key)

      ids[key] = true
      return { ok: false, reason: "max_uses '#{caveat['id']}' has expired" } if now >= caveat['until']

      took = false
      i = 0
      while i < caveat['n'] && !took
        slot = max_uses_slot_key(b['cap_hash'], caveat['id'], i)
        r = store.respond_to?(:consume_once) ? store.consume_once(slot, caveat['until'], now) : store.claim(slot, 1)
        took = (r.respond_to?(:ok) ? r.ok : r) == true
        i += 1
      end
      return { ok: false, reason: "max_uses '#{caveat['id']}' is exhausted" } unless took

      spent += 1
    end
    { ok: true, spent: spent }
  rescue StandardError, SystemStackError => e
    { ok: false, reason: "max_uses error (fail closed): #{k1_err_text(e)}" }
  end

  # ---- derive ------------------------------------------------------------------------------------------------------

  def k1_expr_error(x, names, depth, count)
    return "expression nests deeper than #{DERIVE_MAX_DEPTH}" if depth > DERIVE_MAX_DEPTH

    count[0] += 1
    return "more than #{DERIVE_MAX_NODES} expression nodes" if count[0] > DERIVE_MAX_NODES
    return 'expression must be an object' unless x.is_a?(Hash)

    if x.key?('ref')
      e = wb_closed_members(x, ['ref'], [], 'ref')
      return e if e

      return x['ref'].is_a?(String) && names.include?(x['ref']) ? nil : 'ref names no earlier def'
    end
    if x.key?('const')
      e = wb_closed_members(x, ['const'], [], 'const')
      return e if e

      return k1_scalar?(x['const']) ? nil : 'const must be a scalar'
    end
    op = x['op']
    if %w[and or].include?(op)
      e = wb_closed_members(x, %w[op args], [], op)
      return e if e
      return "#{op} needs 1..8 arguments" unless x['args'].is_a?(Array) && x['args'].length >= 1 && x['args'].length <= 8

      x['args'].each do |a|
        r = k1_expr_error(a, names, depth + 1, count)
        return r if r
      end
      return nil
    end
    if op == 'not'
      e = wb_closed_members(x, %w[op arg], [], 'not')
      return e || k1_expr_error(x['arg'], names, depth + 1, count)
    end
    if K1_CMP_OPS.include?(op)
      e = wb_closed_members(x, %w[op a b], [], op)
      return e || k1_expr_error(x['a'], names, depth + 1, count) || k1_expr_error(x['b'], names, depth + 1, count)
    end
    'unknown expression'
  end

  def k1_def_error(d, names, count)
    case d['kind']
    when 'count'
      de = wb_closed_members(d, %w[name kind window_ms], %w[verb resource_prefix], 'count')
      de ||= 'window_ms out of range' unless k1_int_in?(d['window_ms'], 1, DERIVE_MAX_WINDOW_MS)
      de ||= 'verb must be a non-empty string' if d.key?('verb') && !k1_str256?(d['verb'])
      de ||= 'resource_prefix must be a non-empty string' if d.key?('resource_prefix') && !k1_str256?(d['resource_prefix'])
      de
    when 'param'
      de = wb_closed_members(d, %w[name kind path], [], 'param')
      de ||= 'param path is malformed' unless d['path'].is_a?(String) && wb_split_dot(d['path']).length <= 4 && wb_split_dot(d['path']).all? { |s| wb_path_segment?(s) }
      de
    when 'action'
      de = wb_closed_members(d, %w[name kind field], [], 'action')
      de ||= "field must be 'verb' or 'resource'" unless %w[verb resource].include?(d['field'])
      de
    when 'claim'
      de = wb_closed_members(d, %w[name kind caveat_id claim], [], 'claim')
      de ||= 'claim reference is malformed' unless k1_match?(K1_ID_RE, d['caveat_id']) && k1_match?(K1_NAME_RE, d['claim'])
      de
    when 'expr'
      wb_closed_members(d, %w[name kind expr], [], 'expr') || k1_expr_error(d['expr'], names, 1, count)
    else
      'unknown def kind'
    end
  end

  # nil when the derive caveat is well-formed: bounded, closed and non-recursive (a def refers only to earlier defs).
  def derive_error(c)
    return 'caveat must be an object' unless c.is_a?(Hash)

    e = wb_closed_members(c, %w[type id defs check], [], 'derive')
    return e if e
    return 'not a derive caveat' unless c['type'] == CAVEAT_DERIVE
    return 'id is malformed' unless k1_match?(K1_ID_RE, c['id'])
    return "defs must be an array of at most #{DERIVE_MAX_DEFS}" unless c['defs'].is_a?(Array) && c['defs'].length <= DERIVE_MAX_DEFS

    names = {}
    count = [0]
    c['defs'].each do |d|
      return 'def name is malformed' unless d.is_a?(Hash) && k1_match?(K1_NAME_RE, d['name'])
      return "def '#{d['name']}' is defined twice" if names.key?(d['name'])

      de = k1_def_error(d, names, count)
      return "def '#{d['name']}': #{de}" if de

      names[d['name']] = true
    end
    k1_expr_error(c['check'], names, 1, count)
  end

  # Kleene evaluation: true / false / nil (unknown).
  def k1_eval_expr(x, env)
    return env[x['ref']] if x.key?('ref') # absent from env is unknown (nil)
    return x['const'] if x.key?('const')

    op = x['op']
    if op == 'not'
      v = k1_eval_expr(x['arg'], env)
      return wb_bool?(v) ? !v : nil
    end
    if %w[and or].include?(op)
      stop = op == 'or'
      unknown = false
      x['args'].each do |a|
        v = k1_eval_expr(a, env)
        if !wb_bool?(v) then unknown = true
        elsif v == stop then return stop
        end
      end
      return unknown ? nil : !stop
    end
    a = k1_eval_expr(x['a'], env)
    b = k1_eval_expr(x['b'], env)
    return nil if a.nil? || b.nil?
    return scalar_eq(a, b) if op == 'eq'
    return !scalar_eq(a, b) if op == 'neq'
    return nil unless wb_safe_int?(a) && wb_safe_int?(b)

    case op
    when 'lt' then a < b
    when 'lte' then a <= b
    when 'gt' then a > b
    else a >= b
    end
  end

  # Evaluate a WELL-FORMED derive caveat: true only when `check` is exactly true. `inp` is {'now', 'action'?, 'history'?,
  # 'claims'}, claims = {caveat id => claims} of the discharges that verified in this evaluation.
  def evaluate_derive(c, inp)
    env = {}
    act = inp['action'].is_a?(Hash) ? inp['action'] : nil
    c['defs'].each do |d|
      v = nil
      case d['kind']
      when 'count'
        h = inp['history']
        if h.is_a?(Array) && h.length <= DERIVE_MAX_HISTORY
          n = 0
          bad = false
          h.each do |e|
            unless e.is_a?(Hash) && wb_safe_int?(e['t']) && e['verb'].is_a?(String) && e['resource'].is_a?(String)
              bad = true
              break
            end
            in_window = e['t'] > inp['now'] - d['window_ms'] && e['t'] <= inp['now']
            n += 1 if in_window && (!d.key?('verb') || e['verb'] == d['verb']) &&
                      (!d.key?('resource_prefix') || e['resource'].b.start_with?(d['resource_prefix'].b))
          end
          v = bad ? nil : n
        end
      when 'param'
        found, value = wb_resolve(act && act['params'], "action.params.#{d['path']}")
        v = value if found && k1_scalar?(value)
      when 'action'
        f = act && act[d['field']]
        v = f if k1_str256?(f)
      when 'claim'
        cl = inp['claims'].is_a?(Hash) && inp['claims'].key?(d['caveat_id']) ? inp['claims'][d['caveat_id']] : nil
        v = cl[d['claim']] if cl.is_a?(Hash) && cl.key?(d['claim'])
      when 'expr'
        v = k1_eval_expr(d['expr'], env)
      end
      env[d['name']] = v
    end
    r = k1_eval_expr(c['check'], env)
    wb_bool?(r) ? r : nil
  end

  # ---- spiffe_bound ------------------------------------------------------------------------------------------------

  # nil when the spiffe_bound caveat is well-formed (exactly one of spiffe_id and spiffe_prefix, a valid SPIFFE ID).
  def spiffe_bound_error(c)
    return 'caveat must be an object' unless c.is_a?(Hash)

    e = wb_closed_members(c, ['type'], %w[spiffe_id spiffe_prefix], 'spiffe_bound')
    return e if e
    return 'not a spiffe_bound caveat' unless c['type'] == CAVEAT_SPIFFE_BOUND
    return 'exactly one of spiffe_id and spiffe_prefix' if c.key?('spiffe_id') == c.key?('spiffe_prefix')

    spiffe_id_error(c.key?('spiffe_id') ? c['spiffe_id'] : c['spiffe_prefix'])
  end

  # spiffe_id: the peer must equal it. spiffe_prefix: the peer must equal it or lie below it (prefix + "/").
  def k1_spiffe_satisfied?(c, peer)
    return false unless spiffe_bound_error(c).nil? && spiffe_id_error(peer).nil?
    return peer == c['spiffe_id'] if c.key?('spiffe_id')

    pre = c['spiffe_prefix']
    peer == pre || peer.b.start_with?("#{pre}/".b)
  end

  # ---- the K1 evaluator --------------------------------------------------------------------------------------------

  # Evaluate the K1 caveat types of the leaf hop (and of a verified narrow block); other caveats are left to the stock
  # evaluator. `k1` is {'pins'?, 'discharges'?, 'narrow'?, 'action_digest'?, 'revoked_discharges'?, 'spiffe_id'?,
  # 'history'?}; `ctx` is {'now', 'action'?}. Returns {ok:, failed:, reasons:, plain:, bound:}: `failed` the types of the
  # unsatisfied caveats in order ('<malformed>' for one without a string type), `reasons` one per failure, `plain` the
  # verified narrow caveats that are NOT K1 types (evaluate them with the stock evaluator), `bound` the K1 caveats with
  # their hops (hand the max_uses ones to reserve_max_uses once everything allowed).
  def evaluate_k1(grant, chain, k1, ctx)
    failed = []
    reasons = []
    add_fail = lambda do |c, why|
      failed << (c.is_a?(Hash) && c['type'].is_a?(String) ? c['type'] : '<malformed>')
      reasons << why
    end
    result = ->(plain, bound) { { ok: failed.empty?, failed: failed, reasons: reasons, plain: plain, bound: bound } }
    begin
      configured = k1.is_a?(Hash)
      k1 = {} unless configured
      ctx = {} unless ctx.is_a?(Hash)
      base = bound_caveats(grant, chain)
      if base.nil? || !wb_safe_int?(ctx['now'])
        add_fail.call({ 'type' => '<malformed>' }, base.nil? ? 'malformed capability chain' : 'the verifier clock is not a safe integer (fail closed)')
        return result.call([], [])
      end
      # No k1 input at all (not even {}): every K1 caveat is refused, whatever its type.
      unless configured
        mine = base.select { |b| k1_type?(b['caveat']) }
        mine.each { |b| add_fail.call(b['caveat'], 'the caveat language is not configured (no k1 input)') }
        return result.call([], mine)
      end
      now = ctx['now']
      hops = k1_hops(grant, chain)
      leaf_index = hops.length - 1
      bound = base
      plain = []
      if k1.key?('narrow')
        nbind = { 'now' => now }
        nbind['action_digest'] = k1['action_digest'] if k1.key?('action_digest')
        nv = verify_narrow(k1['narrow'], grant, chain, nbind)
        unless nv[:ok]
          add_fail.call({ 'type' => 'narrow' }, nv[:reason])
          return result.call([], bound.select { |b| k1_type?(b['caveat']) })
        end
        leaf_hash = cap_hash(hops[leaf_index])
        bound += nv[:caveats].map { |caveat| { 'caveat' => caveat, 'hop' => leaf_index, 'cap_hash' => leaf_hash } }
        nv[:caveats].each { |c| plain << c unless k1_type?(c) }
      end
      k1_bound = bound.select { |b| k1_type?(b['caveat']) }
      # ids are unique per type across the chain and narrow block
      seen = Hash.new(0)
      k1_bound.each do |b|
        seen["#{b['caveat']['type']}\x00#{b['caveat']['id']}"] += 1 if b['caveat']['id'].is_a?(String)
      end
      dupe = ->(c) { seen["#{c['type']}\x00#{c['id']}"] > 1 }
      claims = {}
      # pass 1: discharges (derive reads their claims)
      k1_bound.each do |b|
        c = b['caveat']
        next unless c['type'] == CAVEAT_NEEDS_DISCHARGE

        bad = needs_discharge_error(c)
        if bad
          add_fail.call(c, bad)
          next
        end
        if dupe.call(c)
          add_fail.call(c, "duplicate needs_discharge id '#{c['id']}'")
          next
        end
        why = 'no discharge presented'
        okd = nil
        (k1['discharges'].is_a?(Array) ? k1['discharges'] : []).each do |d|
          next unless d.is_a?(Hash) && d['caveat_id'] == c['id']

          dbind = { 'cap_hash' => b['cap_hash'], 'pins' => k1['pins'].nil? ? [] : k1['pins'], 'now' => now }
          dbind['action_digest'] = k1['action_digest'] if k1.key?('action_digest')
          dbind['revoked'] = k1['revoked_discharges'] if k1.key?('revoked_discharges')
          v = verify_discharge(d, c, dbind)
          if v[:ok]
            okd = v
            break
          end
          why = v[:reason]
        end
        if okd
          claims[c['id']] = okd[:claims]
        else
          add_fail.call(c, why)
        end
      end
      # pass 2: everything else, in order
      k1_bound.each do |b|
        c = b['caveat']
        case c['type']
        when CAVEAT_SEALED
          e = wb_closed_members(c, ['type'], [], 'sealed')
          if e then add_fail.call(c, e)
          elsif b['hop'] != leaf_index then add_fail.call(c, 'a hop was appended below a sealed hop')
          end
        when CAVEAT_MAX_USES
          e = max_uses_error(c)
          if e then add_fail.call(c, e)
          elsif dupe.call(c) then add_fail.call(c, "duplicate max_uses id '#{c['id']}'")
          elsif now >= c['until'] then add_fail.call(c, "max_uses '#{c['id']}' has expired")
          end
        when CAVEAT_DERIVE
          e = derive_error(c)
          if e then add_fail.call(c, e)
          elsif dupe.call(c) then add_fail.call(c, "duplicate derive id '#{c['id']}'")
          else
            inp = { 'now' => now, 'claims' => claims }
            inp['action'] = ctx['action'] if ctx.key?('action')
            inp['history'] = k1['history'] if k1.key?('history')
            r = evaluate_derive(c, inp)
            add_fail.call(c, r.nil? ? 'derive check is unknown (a fact is missing)' : 'derive check is false') unless r == true
          end
        when CAVEAT_SPIFFE_BOUND
          add_fail.call(c, 'the presenting workload does not carry the required SPIFFE ID') unless k1_spiffe_satisfied?(c, k1['spiffe_id'])
        end
      end
      result.call(plain, k1_bound)
    rescue StandardError, SystemStackError => e
      add_fail.call({ 'type' => '<malformed>' }, "caveat language error (fail closed): #{k1_err_text(e)}")
      result.call([], [])
    end
  end

  # Discharges and a narrow block as presented with a request: headers `PCA-Discharges` (strict unpadded base64url of a JSON
  # array) and `PCA-Narrow` (the same, any JSON value). `headers` is a Hash of name => String; names are case-insensitive,
  # an empty value is absent, and a name present in several case-variants with different values is ambiguous (absent).
  # {ok: true, value: {'discharges'?, 'narrow'?}} or {ok: false, reason:}. Total.
  def presented_k1(headers)
    return { ok: false, reason: 'headers is not a Hash' } unless headers.is_a?(Hash)

    read = lambda do |name|
      vals = headers.select { |k, _| k.to_s.downcase == name }.values.uniq
      vals.length == 1 ? vals[0] : nil
    end
    out = {}
    d = read.call('pca-discharges')
    unless d.nil? || d == ''
      text = AtlasPca.decode_pca_header(d)
      return { ok: false, reason: 'PCA-Discharges is not canonical base64url' } if text.nil?

      arr = AtlasPca.parse_json(text, any_top: true)
      return { ok: false, reason: 'PCA-Discharges must be a JSON array' } unless arr.is_a?(Array)

      out['discharges'] = arr
    end
    n = read.call('pca-narrow')
    unless n.nil? || n == ''
      text = AtlasPca.decode_pca_header(n)
      return { ok: false, reason: 'PCA-Narrow is not canonical base64url' } if text.nil?

      out['narrow'] = AtlasPca.parse_json(text, any_top: true)
    end
    { ok: true, value: out }
  rescue StandardError, SystemStackError => e
    { ok: false, reason: "presented k1 error (fail closed): #{k1_err_text(e)}" }
  end

  # The policy-layer caveat check with the caveat language: the K1 types by evaluate_k1, every other caveat of
  # policy_caveats(grant, chain) plus evaluate_k1's `plain` list by the agent caveat evaluator (evaluate_agent_caveats).
  # `context` is {'now', 'delegation_depth'?, 'recent_action_times'?, 'action' => {verb, resource, params}}.
  # Returns [allow, failed]: stock failures plus K1 failures, sorted (UTF-16 order, like the reference).
  def evaluate_caveats_k1(grant, chain, k1, context)
    ctx = context.is_a?(Hash) ? context : {}
    k = evaluate_k1(grant, chain, k1, ctx)
    pc = policy_caveats(grant, chain)
    stock = pc.is_a?(Array) ? pc.reject { |c| k1_type?(c) } + k[:plain] : pc
    _ok, stock_failed = evaluate_agent_caveats(stock, ctx, { 'action' => ctx['action'] })
    failed = (stock_failed + k[:failed]).sort_by { |s| utf16_key(s) }
    [failed.empty?, failed]
  rescue StandardError, SystemStackError
    [false, ['<evaluation error>']]
  end
end
