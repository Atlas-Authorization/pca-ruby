# frozen_string_literal: true

# Cross-domain mesh proofs (the agent mesh, mesh.ts `verifyMeshProof`). A mesh proof carries a capability chain, one
# witnessed head per issuing domain, per-hop log inclusion and revocation non-membership proofs, and a signed leaf action.
# verify_mesh_proof checks all of it offline and returns the reference's reason and failing hop (-1 when none is named).
#
# Scope: everything verifyMeshProof does, including RFC 9162 consistency proofs from a pinned head. The witness side
# (cosigning, heads publication) is not here: a verifier only needs to check what they produced.
module AtlasPca
  MeshVerdict = Struct.new(:ok, :reason, :hop, keyword_init: true)

  MESH_HEAD_DOMAIN = "atlas-pca/mesh-head/v1\x00"
  MESH_COSIG_DOMAIN = "atlas-pca/mesh-cosig/v1\x00"
  MESH_BINDING_DOMAIN = "atlas-pca/mesh-binding/v1\x00"
  MESH_ACTION_DOMAIN = "atlas-pca/mesh-action/v1\x00"
  MESH_DEFAULT_MAX_HEAD_AGE_MS = 5 * 60_000
  MESH_DEFAULT_MAX_SKEW_MS = 60_000
  MESH_DEFAULT_MAX_CHAIN = 64
  MESH_MAX_COSIGS = 256
  MESH_MAX_PATH = 128

  module_function

  def mesh_fail(reason, hop) = MeshVerdict.new(ok: false, reason: reason, hop: hop)
  def mesh_nat?(x) = V2JS.nonneg?(x)
  def mesh_num?(x) = V2JS.num?(x) && (!x.is_a?(Float) || x.finite?)
  def mesh_str?(x) = x.is_a?(String)
  def mesh_hash(x) = x.is_a?(Hash) ? x : nil

  # JS truthiness of a decoded JSON value.
  def mesh_truthy?(v)
    return false if v.nil? || v == false
    return !(v.zero? || (v.is_a?(Float) && v.nan?)) if V2JS.num?(v)
    return !v.empty? if v.is_a?(String)

    true
  end

  # utf8(domain) || strictCanonical(body), or nil when the body is not canonicalisable.
  def mesh_msg(domain, body)
    domain.b + canon_bytes(body)
  rescue StandardError, SystemStackError
    nil
  end

  def mesh_valid_head(h)
    return nil unless h.is_a?(Hash) && mesh_str?(h['domain']) && mesh_str?(h['root']) && mesh_str?(h['rev_root'])
    return nil unless mesh_nat?(h['size']) && mesh_nat?(h['rev_size']) && mesh_num?(h['timestamp'])

    h['size'].zero? == h['root'].empty? ? h : nil
  end

  def mesh_valid_consistency(c)
    return nil unless c.is_a?(Hash) && mesh_nat?(c['oldSize']) && mesh_nat?(c['newSize'])

    path = c['path']
    return nil unless path.is_a?(Array) && path.length <= MESH_MAX_PATH && path.all? { |p| mesh_str?(p) }

    c
  end

  def mesh_valid_inclusion(i)
    return nil unless i.is_a?(Hash) && mesh_nat?(i['index']) && mesh_nat?(i['size'])

    i['path'].is_a?(Array) && i['path'].length <= MESH_MAX_PATH ? i : nil
  end

  def mesh_valid_action(a)
    return nil unless a.is_a?(Hash) && %w[type resource service_domain nonce].all? { |k| mesh_str?(a[k]) } && mesh_num?(a['at'])
    return nil if a.key?('amount') && !mesh_num?(a['amount'])

    a
  end

  # ---- effective authority ----

  def mesh_strings(v)
    v.is_a?(Array) && v.all? { |x| mesh_str?(x) } ? v : nil
  end

  def mesh_intersect(have, a, b)
    return V2JS.sort_utf8(b.uniq(&:b)) unless have

    a.select { |x| b.any? { |y| x == y } }
  end

  def mesh_subset?(child, parent)
    child.all? { |c| parent.any? { |p| c == p } }
  end

  def mesh_min(cur, v)
    cur.nil? ? v : [cur, v].min
  end

  # effectiveAuthority: the conjunction of the caveats. [authority, nil] or [nil, reason] (an unknown or malformed caveat).
  def mesh_effective(caveats)
    e = { 'actions' => nil, 'prefixes' => [], 'max_amount' => nil, 'expires_at' => nil, 'audience' => nil, 'max_hops' => nil }
    return [nil, 'malformed proof'] unless caveats.is_a?(Array)

    caveats.each do |c|
      return [nil, 'malformed proof'] unless c.is_a?(Hash)

      case c['type']
      when 'scope'
        a = mesh_strings(c['actions'])
        return [nil, 'malformed scope caveat'] if a.nil?

        e['actions'] = mesh_intersect(!e['actions'].nil?, e['actions'], a)
      when 'resource'
        return [nil, 'malformed resource caveat'] unless mesh_str?(c['prefix'])

        e['prefixes'] << c['prefix']
      when 'max_amount'
        return [nil, 'malformed max_amount caveat'] unless mesh_num?(c['max'])

        e['max_amount'] = mesh_min(e['max_amount'], c['max'])
      when 'expires'
        return [nil, 'malformed expires caveat'] unless mesh_num?(c['at'])

        e['expires_at'] = mesh_min(e['expires_at'], c['at'])
      when 'audience'
        d = mesh_strings(c['domains'])
        return [nil, 'malformed audience caveat'] if d.nil?

        e['audience'] = mesh_intersect(!e['audience'].nil?, e['audience'], d)
      when 'max_hops'
        return [nil, 'malformed max_hops caveat'] unless mesh_num?(c['n'])

        e['max_hops'] = mesh_min(e['max_hops'], c['n'])
      else
        return [nil, "unknown caveat type \"#{Predicates.js_string(c.key?('type') ? c['type'] : Predicates::UNDEF)}\" (fail closed)"]
      end
    end
    [e, nil]
  end

  def mesh_narrows?(child, parent)
    return false if !parent['actions'].nil? && (child['actions'].nil? || !mesh_subset?(child['actions'], parent['actions']))
    return false if !parent['audience'].nil? && (child['audience'].nil? || !mesh_subset?(child['audience'], parent['audience']))
    return false if !parent['max_amount'].nil? && (child['max_amount'].nil? || child['max_amount'] > parent['max_amount'])
    return false if !parent['expires_at'].nil? && (child['expires_at'].nil? || child['expires_at'] > parent['expires_at'])
    return false if !parent['max_hops'].nil? && (child['max_hops'].nil? || child['max_hops'] > parent['max_hops'])

    mesh_subset?(parent['prefixes'], child['prefixes'])
  end

  def mesh_num_s(x) = Predicates.js_number_string(x.to_f)

  # The reason the authority does not admit the action, or nil.
  def mesh_admits(e, a, now, chain_len)
    typ = a['type']
    res = a['resource']
    svc = a['service_domain']
    return "action \"#{typ}\" not in scope" if !e['actions'].nil? && !mesh_subset?([typ], e['actions'])

    e['prefixes'].each do |p|
      return "resource \"#{res}\" outside prefix \"#{p}\"" unless res.b.start_with?(p.b)
    end
    if !e['max_amount'].nil? && (!a.key?('amount') || a['amount'] > e['max_amount'])
      return "amount exceeds ceiling #{mesh_num_s(e['max_amount'])}"
    end
    return 'capability expired' if !e['expires_at'].nil? && now > e['expires_at']
    return 'service domain not in audience' if !e['audience'].nil? && !mesh_subset?([svc], e['audience'])
    return "chain exceeds max_hops #{mesh_num_s(e['max_hops'])}" if !e['max_hops'].nil? && chain_len > e['max_hops']

    nil
  end

  # ---- revocation sets and Merkle proofs ----

  def mesh_leaf_ok?(root, size, id, proof)
    psize = proof['size']
    index = proof['index']
    return false unless V2JS.int?(psize) && V2JS.int?(index) && psize == size && index >= 0 && index < size

    sides = path_shape(index.to_i, size.to_i)
    path = proof['path']
    return false unless path.is_a?(Array) && path.length == sides.length

    h = leaf_hash(id)
    path.each_with_index do |step, i|
      return false unless step.is_a?(Hash)

      side = step['side']
      return false unless side == sides[i]

      sib = step['hash'].is_a?(String) ? b64d(step['hash'], 32) : nil
      return false if sib.nil?

      h = side == 'L' ? node_hash(sib, h) : node_hash(h, sib)
    end
    IntentV2.bind_root(size.to_i, b64e(h)) == root
  end

  # verifyNonMembership over an expanded proof {size, lo?, hi?}.
  def mesh_non_membership?(root, nm, id)
    size = nm['size']
    return false unless V2JS.int?(size) && size >= 0

    lo = mesh_hash(nm['lo'])
    hi = mesh_hash(nm['hi'])
    return lo.nil? && hi.nil? && IntentV2.bind_root(0, IntentV2.empty_tree) == root if size.zero?
    return false if lo.nil? && hi.nil?

    lo_idx = hi_idx = 0
    unless lo.nil?
      lo_id = lo['id'].is_a?(String) ? lo['id'] : ''
      lp = mesh_hash(lo['proof'])
      return false if lp.nil? || !(V2JS.compare_utf8(lo_id, id) < 0) || !mesh_leaf_ok?(root, size, lo_id, lp)

      lo_idx = lp['index']
      return false if hi.nil? && lo_idx != size - 1
    end
    unless hi.nil?
      hi_id = hi['id'].is_a?(String) ? hi['id'] : ''
      hp = mesh_hash(hi['proof'])
      return false if hp.nil? || !(V2JS.compare_utf8(id, hi_id) < 0) || !mesh_leaf_ok?(root, size, hi_id, hp)

      hi_idx = hp['index']
      return false if lo.nil? && hi_idx != 0
    end
    return false if !lo.nil? && !hi.nil? && hi_idx != lo_idx + 1

    true
  end

  # verifyLedgerConsistency (RFC 9162 section 2.1.4.2) with strict 32-byte base64url hashes.
  def mesh_consistency?(old_root, new_root, proof)
    first = proof['oldSize']
    second = proof['newSize']
    return false unless V2JS.int?(first) && V2JS.int?(second)

    first = first.to_i
    second = second.to_i
    return false if first.negative? || first > second

    raw = proof['path'].is_a?(Array) ? proof['path'] : []
    return false if raw.length > MESH_MAX_PATH

    empty = IntentV2.empty_tree
    if first.zero?
      return false if !raw.empty? || old_root != empty

      return second.zero? ? new_root == empty : true
    end
    return raw.empty? && old_root == new_root if first == second

    path = []
    if (first & (first - 1)).zero?
      o = old_root.is_a?(String) ? b64d(old_root, 32) : nil
      return false if o.nil?

      path << o
    end
    raw.each do |p|
      b = p.is_a?(String) ? b64d(p, 32) : nil
      return false if b.nil?

      path << b
    end
    return false if path.empty?

    fn = first - 1
    sn = second - 1
    while fn.odd?
      fn >>= 1
      sn >>= 1
    end
    fr = sr = path[0]
    path[1..].each do |c|
      return false if sn.zero?

      if fn.odd? || fn == sn
        fr = node_hash(c, fr)
        sr = node_hash(c, sr)
        while fn.even? && fn != 0
          fn >>= 1
          sn >>= 1
        end
      else
        sr = node_hash(sr, c)
      end
      fn >>= 1
      sn >>= 1
    end
    sn.zero? && b64e(fr) == old_root && b64e(sr) == new_root
  end

  # ---- heads ----

  def mesh_check_head_advance(prev, nxt, proof)
    p = mesh_valid_head(prev)
    return 'malformed head' if p.nil?

    n = mesh_valid_head(nxt)
    return 'malformed head' if n.nil?
    return 'head is for a different domain' if p['domain'] != n['domain']
    return 'head rolls back' if n['size'] < p['size'] || n['rev_size'] < p['rev_size']

    if n['size'] == p['size']
      return 'equivocation (same size, different log)' if n['root'] != p['root']
    else
      c = mesh_valid_consistency(proof)
      return 'consistency proof required for a larger head' if c.nil? || c['oldSize'] != p['size'] || c['newSize'] != n['size']
      return 'head is not consistent with the previous head (fork or rewrite)' unless mesh_consistency?(p['root'], n['root'], c)
    end
    return 'equivocation (revocation set)' if n['rev_size'] == p['rev_size'] && n['rev_root'] != p['rev_root']

    nil
  end

  def mesh_opt(t, k, default)
    return default unless t.key?(k)

    mesh_num?(t[k]) && t[k] >= 0 ? t[k] : nil
  end

  # The validated trust configuration as a Hash, or a reason String.
  def mesh_valid_trust(traw)
    return 'invalid trust configuration' unless traw.is_a?(Hash)

    t = traw
    return 'invalid trust configuration' unless mesh_str?(t['humanPrincipal'])

    ws = mesh_strings(t['witnesses'])
    return 'invalid trust configuration' if ws.nil?

    c = { 'human' => t['humanPrincipal'], 'witnesses' => ws.uniq(&:b) }
    unless mesh_nat?(t['threshold']) && t['threshold'] >= 1 && t['threshold'] <= c['witnesses'].length
      return 'invalid trust configuration: threshold'
    end

    c['threshold'] = t['threshold']
    return 'invalid trust configuration: now' unless mesh_num?(t['now'])

    c['now'] = t['now']
    c['max_head_age'] = mesh_opt(t, 'maxHeadAgeMs', MESH_DEFAULT_MAX_HEAD_AGE_MS)
    return 'invalid trust configuration: maxHeadAgeMs' if c['max_head_age'].nil?

    c['max_skew'] = mesh_opt(t, 'maxClockSkewMs', MESH_DEFAULT_MAX_SKEW_MS)
    return 'invalid trust configuration: maxClockSkewMs' if c['max_skew'].nil?

    if t.key?('maxActionAgeMs')
      c['max_action_age'] = mesh_opt(t, 'maxActionAgeMs', 0)
      return 'invalid trust configuration: maxActionAgeMs' if c['max_action_age'].nil?
    end
    c['max_chain'] = MESH_DEFAULT_MAX_CHAIN
    if t.key?('maxChainLength')
      return 'invalid trust configuration: maxChainLength' unless mesh_nat?(t['maxChainLength']) && t['maxChainLength'] >= 1

      c['max_chain'] = t['maxChainLength']
    end
    ad = mesh_strings(t['allowedDomains'])
    return 'invalid trust configuration: allowedDomains is required' if ad.nil? || ad.empty?

    c['allowed'] = ad
    rd = t['rootDomain']
    unless mesh_str?(rd) && mesh_subset?([rd], ad)
      return 'invalid trust configuration: rootDomain is required and must be in allowedDomains'
    end

    c['root_domain'] = rd
    if t.key?('issuerDomains')
      m = t['issuerDomains']
      return 'invalid trust configuration: issuerDomains' unless m.is_a?(Hash) && m.values.all? { |x| mesh_str?(x) }

      c['issuer_domains'] = m
    end
    if t.key?('pinnedHeads')
      return 'invalid trust configuration: pinnedHeads' unless t['pinnedHeads'].is_a?(Hash)

      c['pinned'] = t['pinnedHeads']
    end
    c['pq_pins'] = t['pqPins'].select { |_, v| mesh_str?(v) } if t['pqPins'].is_a?(Hash)
    c
  end

  def mesh_check_cosigned_head(ch, expected_domain, t, pin_proof)
    chm = mesh_hash(ch) || {}
    h = mesh_hash(chm['head'])
    return 'head is for a different domain' if h.nil? || h['domain'] != expected_domain
    return 'malformed head' if mesh_valid_head(h).nil?

    sig = chm['sig']
    return 'malformed head' unless mesh_str?(sig)

    domain = h['domain']
    m = mesh_msg(MESH_HEAD_DOMAIN, h)
    return 'head not signed by its domain key' if m.nil? || !verify_b64u(domain, m, sig)

    cosigs = chm['cosigs']
    return 'malformed head' unless cosigs.is_a?(Array) && cosigs.length <= MESH_MAX_COSIGS

    good = {}
    cm = mesh_msg(MESH_COSIG_DOMAIN, h)
    cosigs.each do |c|
      next unless c.is_a?(Hash) && mesh_str?(c['witness']) && mesh_str?(c['sig'])

      w = c['witness']
      good[w] = true if t['witnesses'].include?(w) && !good[w] && !cm.nil? && verify_b64u(w, cm, c['sig'])
    end
    return "head has #{good.length}/#{t['threshold']} trusted witness cosignatures" if good.length < t['threshold']

    ts = h['timestamp']
    return 'head timestamp is in the future' if ts > t['now'] + t['max_skew']
    return 'head is stale' if t['now'] - ts > t['max_head_age']

    if t['pinned'] && t['pinned'].key?(domain) && mesh_truthy?(t['pinned'][domain])
      why = mesh_check_head_advance(t['pinned'][domain], h, pin_proof)
      return "#{why} (vs pinned head)" unless why.nil?
    end
    nil
  end

  def mesh_expand_nm(c, leaves)
    return nil unless c.is_a?(Hash) && mesh_nat?(c['size'])

    out = { 'size' => c['size'] }
    %w[lo hi].each do |side|
      next unless c.key?(side)

      ix = c[side]
      return nil unless mesh_nat?(ix) && ix < leaves.length

      out[side] = leaves[ix]
    end
    out
  end

  # Verify a mesh proof end to end, offline. Both arguments are parsed JSON. Total: any malformed input is a verdict
  # (MeshVerdict: ok, reason, hop), never an exception.
  def verify_mesh_proof(proof, trust)
    verify_mesh_proof_unchecked(proof, trust)
  rescue StandardError, SystemStackError
    mesh_fail('malformed proof', -1)
  end

  def verify_mesh_proof_unchecked(proof, trust)
    t = mesh_valid_trust(trust)
    return mesh_fail(t, -1) if t.is_a?(String)
    return mesh_fail('malformed proof', -1) unless proof.is_a?(Hash)

    p = proof
    chain = p['chain']
    hops = p['hops']
    heads = p['heads']
    rev_leaves = p['rev_leaves']
    return mesh_fail('malformed proof', -1) unless [chain, hops, heads, rev_leaves].all?(Array)

    action = mesh_valid_action(p['action'])
    return mesh_fail('malformed action', -1) if !mesh_str?(p['action_sig']) || action.nil?

    if p.key?('pin_proofs')
      arr = p['pin_proofs']
      return mesh_fail('malformed pin proofs', -1) unless arr.is_a?(Array) && arr.length <= MESH_MAX_COSIGS

      arr.each do |x|
        ok = x.is_a?(Hash) && mesh_str?(x['domain']) && !mesh_valid_consistency(x['proof']).nil?
        return mesh_fail('malformed pin proofs', -1) unless ok
      end
    end
    return mesh_fail('chain length out of bounds', -1) if chain.empty? || chain.length > t['max_chain']
    return mesh_fail('evidence tables exceed chain size', -1) if heads.length > chain.length || rev_leaves.length > 2 * chain.length

    why, ok = verify_chain(chain, t['human'], true, nil, t['pq_pins'], nil)
    return mesh_fail("chain: #{why}", -1) unless ok
    return mesh_fail('hop evidence count does not match chain length', -1) if hops.length != chain.length

    rev_leaves.each do |l|
      ok = l.is_a?(Hash) && mesh_str?(l['id']) && !mesh_valid_inclusion(l['proof']).nil?
      return mesh_fail('malformed revocation leaves', -1) unless ok
    end
    used = {}
    hops.each { |h| used[h['head']] = true if h.is_a?(Hash) && mesh_nat?(h['head']) }
    return mesh_fail('unreferenced or missing head in evidence table', -1) if used.length != heads.length

    head_errs = {}
    prev = nil
    chain.each_with_index do |cap, i|
      ev = mesh_hash(hops[i])
      return mesh_fail('malformed hop evidence', i) if ev.nil?

      domain = ev['domain']
      unless mesh_str?(domain) && mesh_nat?(ev['head']) && ev['head'] < heads.length && ev['revocation'].is_a?(Hash)
        return mesh_fail('malformed hop evidence', i)
      end
      return mesh_fail('issuing domain not allowed by policy', i) unless mesh_subset?([domain], t['allowed'])
      return mesh_fail('root capability must be anchored in the pinned root domain', i) if i.zero? && domain != t['root_domain']

      issuer = cap['issuer'].is_a?(String) ? cap['issuer'] : ''
      if i.positive? && t['issuer_domains'] && t['issuer_domains'].key?(issuer) && t['issuer_domains'][issuer] != domain
        return mesh_fail('issuer key is pinned to a different domain', i)
      end

      hi = ev['head'].to_i
      ch = heads[hi]
      unless head_errs.key?(hi)
        head_m = mesh_hash(mesh_hash(ch)&.fetch('head', nil))
        dom = head_m && mesh_str?(head_m['domain']) ? head_m['domain'] : ''
        pin_proof = nil
        if p['pin_proofs'].is_a?(Array)
          hit = p['pin_proofs'].find { |x| x.is_a?(Hash) && x['domain'] == dom }
          pin_proof = hit['proof'] unless hit.nil?
        end
        head_errs[hi] = mesh_check_cosigned_head(ch, dom, t, pin_proof)
      end
      return mesh_fail('malformed proof', -1) unless ch.is_a?(Hash) && !ch['head'].nil? # `ch.head.domain` throws in the reference

      head_m = mesh_hash(ch['head'])
      return mesh_fail('source-domain anchor: head is for a different domain', i) if head_m.nil? || head_m['domain'] != domain
      return mesh_fail("source-domain anchor: #{head_errs[hi]}", i) unless head_errs[hi].nil?

      incl = mesh_valid_inclusion(ev['inclusion'])
      return mesh_fail('hop not included in the issuing domain log', i) if incl.nil? || incl['size'] != head_m['size']
      return mesh_fail('hop not included in the issuing domain log', i) unless verify_inclusion(head_m['root'], incl, cap_hash(cap))

      if i.positive?
        b = mesh_hash(ev['binding'])
        ok = !b.nil? && mesh_str?(b['role']) && mesh_str?(b['sig']) && b['agent'] == cap['issuer'] && b['domain'] == ev['domain']
        return mesh_fail('missing or mismatched domain binding for issuer', i) unless ok

        m = mesh_msg(MESH_BINDING_DOMAIN, { 'agent' => b['agent'], 'domain' => b['domain'], 'role' => b['role'] })
        return mesh_fail('domain binding signature invalid', i) if m.nil? || !verify_b64u(domain, m, b['sig'])
      end

      rev = ev['revocation']
      rev_root = head_m['rev_root']
      id = cap['id'].is_a?(String) ? cap['id'] : ''
      nm_cap = mesh_expand_nm(rev['cap'], rev_leaves)
      return mesh_fail('capability revoked (or revocation proof invalid)', i) if nm_cap.nil? || !mesh_non_membership?(rev_root, nm_cap, id)

      nm_key = mesh_expand_nm(rev['issuer_key'], rev_leaves)
      if nm_key.nil? || !mesh_non_membership?(rev_root, nm_key, "key:#{issuer}")
        return mesh_fail('issuer key revoked (or revocation proof invalid)', i)
      end

      eff, why = mesh_effective(cap['caveats'])
      return mesh_fail(why, i) unless why.nil?
      return mesh_fail('hop widens authority', i) if !prev.nil? && !mesh_narrows?(eff, prev)

      prev = eff
    end

    at = action['at']
    return mesh_fail('action timestamp is in the future', -1) if at > t['now'] + t['max_skew']
    return mesh_fail('action is stale', -1) if t['max_action_age'] && t['now'] - at > t['max_action_age']

    tip = chain[-1]
    am = mesh_msg(MESH_ACTION_DOMAIN, { 'action' => action, 'tip' => cap_hash(tip) })
    return mesh_fail('action not signed by the chain tip holder', -1) if am.nil? || !verify_b64u(tip['holder'], am, p['action_sig'])

    denied = mesh_admits(prev, action, t['now'], chain.length)
    return mesh_fail("action not admitted: #{denied}", -1) unless denied.nil?

    MeshVerdict.new(ok: true, reason: nil, hop: -1)
  end
end
