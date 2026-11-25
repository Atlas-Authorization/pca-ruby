# frozen_string_literal: true

module AtlasPca
  # The rest of the reference's `mesh` module beside the verifier (mesh.rb) and the witness / domain classes (mesh_witness.rb): the
  # public effective authority, the proof size and revocation latency models, the worked example and the fork demonstration, and the
  # federation half: cross-domain capability translation, the federated budget tree and cross-reference commitments. Records are
  # String-keyed Hashes with the reference's member names; keys are AtlasPca::KeyPair. Verifiers never raise; signers and
  # translators raise.
  DEFAULT_MAX_HEAD_AGE_MS = MESH_DEFAULT_MAX_HEAD_AGE_MS
  DEFAULT_MAX_CLOCK_SKEW_MS = MESH_DEFAULT_MAX_CLOCK_SKEW_MS
  DEFAULT_MAX_CHAIN_LENGTH = MESH_DEFAULT_MAX_CHAIN
  MESH_XCAP_DOMAIN = "atlas-pca/mesh-xcap/v1\x00"
  MESH_XANCHOR_DOMAIN = "atlas-pca/mesh-xanchor/v1\x00"
  MESH_ACTION_DIGEST_DOMAIN = "atlas-pca/mesh-action-digest/v1\x00"
  MESH_MAX_BUDGET_DEPTH = MESH_DEFAULT_MAX_CHAIN
  MESH_EA_MEMBERS = { 'actions' => 'actions', 'max_amount' => 'maxAmount', 'expires_at' => 'expiresAt', 'audience' => 'audience',
                      'max_hops' => 'maxHops' }.freeze
  MESH_UNSET = Object.new.freeze # an omitted optional argument (an explicit nil is a given value)

  # The public shape of an internal effective authority: {prefixes, actions?, maxAmount?, expiresAt?, audience?, maxHops?}.
  def self.mesh_authority_out(e)
    out = { 'prefixes' => e['prefixes'] }
    MESH_EA_MEMBERS.each { |src, dst| out[dst] = e[src] unless e[src].nil? }
    out
  end

  # Conjunction of all caveats as one authority; an unknown or malformed caveat fails closed with {'error' => reason}. A caveat
  # list that is not a list, or a null entry, raises (the reference cannot read it); any other non-object entry has no type.
  def self.effective_authority(caveats)
    raise TypeError, 'caveats is not iterable' unless caveats.is_a?(Array)

    bad = caveats.index { |c| !c.is_a?(Hash) }
    e, err = mesh_effective(bad.nil? ? caveats : caveats[0, bad])
    return { 'error' => err } if e.nil?
    return mesh_authority_out(e) if bad.nil?
    raise TypeError, 'a caveat is null' if caveats[bad].nil?

    { 'error' => 'unknown caveat type "undefined" (fail closed)' }
  end

  # The element of a JSON array at a reference index (an in-range integer, or its decimal text): [true, value], else [false, nil].
  def self.mesh_at(list, i)
    i = i.to_i if i.is_a?(String) && i.match?(/\A(0|[1-9][0-9]*)\z/)
    i = i.to_i if i.is_a?(Float) && i.finite? && i == i.floor
    list.is_a?(Array) && i.is_a?(Integer) && i >= 0 && i < list.length ? [true, list[i]] : [false, nil]
  end

  # Byte sizes (canonical JSON) of a proof's parts, plus the size the uncompacted layout (a head copy and inline revocation
  # leaves per hop) would take. Raises on a value that is not a proof.
  def self.mesh_proof_size(p)
    raise TypeError, 'meshProofSize: not a proof' unless p.is_a?(Hash)

    nb = ->(x) { canon_bytes(x).bytesize }
    chain, action, action_sig, heads, leaves, hops = %w[chain action action_sig heads rev_leaves hops].map { |k| p.fetch(k) }
    raise TypeError, 'meshProofSize: hops is not a list' unless hops.is_a?(Array)

    expand = lambda do |c|
      raise TypeError, 'meshProofSize: malformed revocation' unless c.is_a?(Hash)

      out = { 'size' => c.fetch('size') }
      %w[lo hi].each do |side|
        found, leaf = c.key?(side) ? mesh_at(leaves, c[side]) : [false, nil]
        out[side] = leaf if found && mesh_truthy?(leaf)
      end
      out
    end
    hop_bytes = hops.map do |h|
      raise TypeError, 'meshProofSize: malformed hop' unless h.is_a?(Hash) && h['revocation'].is_a?(Hash)

      found, head = mesh_at(heads, h['head'])
      raise TypeError, 'meshProofSize: unknown head' unless found

      nb.call(h.merge('head' => head, 'revocation' => { 'cap' => expand.call(h['revocation']['cap']),
                                                        'issuer_key' => expand.call(h['revocation']['issuer_key']) }))
    end
    uncompacted = nb.call(chain) + nb.call(action) + nb.call(action_sig) + hop_bytes.sum
    { 'total_bytes' => nb.call(p), 'chain_bytes' => nb.call(chain), 'heads_bytes' => nb.call(heads), 'rev_leaves_bytes' => nb.call(leaves),
      'hops_bytes' => nb.call(hops), 'uncompacted_bytes' => uncompacted }
  end

  # Worst-case time from "revocation made" until it is enforced, per verifier posture ({'maxHeadAgeMs', 'headIntervalMs',
  # 'maxClockSkewMs'?, 'pinRefreshMs'?}). Non-finite or negative inputs yield an unusable bound (infinity, not viable).
  def self.revocation_latency_bound(p)
    p = {} unless p.is_a?(Hash)
    ok = ->(x) { mesh_num?(x) && x >= 0 }
    inf = Float::INFINITY
    if !ok.call(p['maxHeadAgeMs']) || !ok.call(p['headIntervalMs']) || (p.key?('maxClockSkewMs') && !ok.call(p['maxClockSkewMs'])) ||
       (p.key?('pinRefreshMs') && !ok.call(p['pinRefreshMs']))
      return { 'published_ms' => inf, 'unpinned_ms' => inf, 'pinned_ms' => inf, 'honest_provers_viable' => false }
    end

    skew = p.key?('maxClockSkewMs') ? p['maxClockSkewMs'] : 0
    unpinned = p['maxHeadAgeMs'] + skew
    { 'published_ms' => p['headIntervalMs'], 'unpinned_ms' => unpinned,
      'pinned_ms' => p.key?('pinRefreshMs') ? [unpinned, p['pinRefreshMs']].min : unpinned,
      'honest_provers_viable' => p['headIntervalMs'] + skew < p['maxHeadAgeMs'] }
  end

  # ---- cross-domain capability translation ----

  def self.mesh_caveat_array?(x) = x.is_a?(Array) && x.all? { |c| c.is_a?(Hash) && c['type'].is_a?(String) }

  def self.mesh_xcap_body(from, to, source_tip, caveats, issued_at)
    { 'v' => 'atlas-pca/mesh-xcap/v1', 'from' => from, 'to' => to, 'source_tip' => source_tip, 'caveats' => caveats, 'issued_at' => issued_at }
  end

  # Translate a capability chain (rooted in Guardian A's grant) into a capability valid in Guardian B's domain: A's chain-tip
  # caveats followed by B's `additional_caveats` (append-only, hence monotone narrowing), signed by the `bridge` KeyPair. Raises on
  # malformed input; verify_translated_capability is the total, fail-closed function.
  def self.translate_capability(chain, from_guardian:, to_guardian:, bridge:, issued_at:, additional_caveats: MESH_UNSET, pq_pins: nil)
    reason, ok = verify_chain(chain, nil, false, nil, pq_pins)
    raise ArgumentError, "translateCapability: invalid source chain: #{reason}" unless ok
    if !MESH_UNSET.equal?(additional_caveats) && !mesh_caveat_array?(additional_caveats)
      raise ArgumentError, 'translateCapability: additionalCaveats must be an array of caveats'
    end
    raise TypeError, 'translateCapability: the bridge is an AtlasPca::KeyPair' unless bridge.is_a?(KeyPair)

    tip = chain[-1]
    caveats = clone_json(tip['caveats']) + clone_json(MESH_UNSET.equal?(additional_caveats) ? [] : additional_caveats)
    source_tip = cap_hash(tip)
    sig = b64e(bridge.sign(mesh_msg(MESH_XCAP_DOMAIN, mesh_xcap_body(from_guardian, to_guardian, source_tip, caveats, issued_at))))
    { 'source' => chain, 'fromGuardian' => from_guardian, 'toGuardian' => to_guardian, 'bridge' => bridge.public, 'source_tip' => source_tip,
      'caveats' => caveats, 'issued_at' => issued_at, 'sig' => sig }
  end

  # The translated effective authority: the conjunction of all translated caveats, or {'error'} on an unknown or malformed caveat.
  def self.translated_effective_authority(tc)
    return { 'error' => 'malformed translated capability' } if !tc.is_a?(Hash) || !mesh_caveat_array?(tc['caveats'])

    effective_authority(tc['caveats'])
  end

  # Verify a translated capability end to end, offline. Total: never raises, fails closed on any malformed input. `opts` carries the
  # reference's option members ('fromGuardian', 'toGuardian', 'bridge', 'rootIssuer', 'now', 'pqPins'); a member that is present is
  # a pin, null included. Returns {'ok' => true, 'from', 'to', 'bridge', 'effective'} or {'ok' => false, 'reason'}.
  def self.verify_translated_capability(tc, opts = {})
    fail = ->(reason) { { 'ok' => false, 'reason' => reason } }
    unless tc.is_a?(Hash) && tc['source'].is_a?(Array) && tc['fromGuardian'].is_a?(String) && tc['toGuardian'].is_a?(String)
      return fail.call('malformed translated capability')
    end
    unless %w[bridge source_tip sig].all? { |k| tc[k].is_a?(String) } && mesh_num?(tc['issued_at']) && mesh_caveat_array?(tc['caveats'])
      return fail.call('malformed translated capability')
    end
    return fail.call('malformed translated capability') if opts.nil?

    opts = {} unless opts.is_a?(Hash)
    reason, ok = verify_chain(tc['source'], opts['rootIssuer'], opts.key?('rootIssuer'), nil, opts['pqPins'])
    return fail.call("source chain: #{reason}") unless ok
    return fail.call('source guardian mismatch') if opts.key?('fromGuardian') && tc['fromGuardian'] != opts['fromGuardian']
    return fail.call('target guardian mismatch') if opts.key?('toGuardian') && tc['toGuardian'] != opts['toGuardian']
    return fail.call('bridge key mismatch') if opts.key?('bridge') && tc['bridge'] != opts['bridge']
    return fail.call('translation does not cross a domain boundary') if tc['fromGuardian'] == tc['toGuardian']

    tip = tc['source'][-1]
    return fail.call('source_tip does not match the source chain tip') if tc['source_tip'] != cap_hash(tip)
    return fail.call('translation drops a source caveat (widening)') if tc['caveats'].length < tip['caveats'].length

    tip['caveats'].each_with_index do |c, j|
      return fail.call("translation altered or reordered source caveat #{j} (widening)") if hash_canonical(tc['caveats'][j]) != hash_canonical(c)
    end
    body = mesh_xcap_body(tc['fromGuardian'], tc['toGuardian'], tc['source_tip'], tc['caveats'], tc['issued_at'])
    return fail.call('translation not signed by the declared bridge key') unless verify_b64u(tc['bridge'], mesh_msg(MESH_XCAP_DOMAIN, body), tc['sig'])

    eff_s, err = mesh_effective(tip['caveats'])
    return fail.call("source caveats: #{err}") if eff_s.nil?

    eff_t, err = mesh_effective(tc['caveats'])
    return fail.call(err) if eff_t.nil?
    return fail.call('translated authority widens the source authority') unless mesh_narrows?(eff_t, eff_s)
    return fail.call('translated capability expired') if opts.key?('now') && !eff_t['expires_at'].nil? && !(AnalyzerJs.fin?(opts['now']) && AnalyzerJs.js_le(opts['now'], eff_t['expires_at'])) # the reference's `>` over any JSON value

    { 'ok' => true, 'from' => tc['fromGuardian'], 'to' => tc['toGuardian'], 'bridge' => tc['bridge'], 'effective' => mesh_authority_out(eff_t) }
  rescue StandardError, SystemStackError
    { 'ok' => false, 'reason' => 'malformed translated capability' }
  end

  # ---- consolidated cross-domain budget ----

  def self.mesh_budget_state?(s)
    return false unless s.is_a?(Hash) && s['nodes'].is_a?(Hash) && s['root'].is_a?(String) && mesh_num?(s['kappa']) && mesh_num?(s['bMax'])
    return false if s['kappa'] <= 0 || s['bMax'].negative? || !s['nodes'].key?(s['root'])

    s['nodes'].each_value.all? do |n|
      n.is_a?(Hash) && n['domain'].is_a?(String) && mesh_num?(n['B']) && !n['B'].negative? && (!n.key?('parent') || n['parent'].is_a?(String))
    end
  end

  # A federated budget rooted at `root_id` (in `root_domain`) with initial budget b0 <= b_max. Fail-closed on a malformed policy or
  # allocation: {'ok' => true, 'state'} or {'ok' => false, 'reason'}.
  def self.create_federated_budget(root_id:, root_domain:, b0:, kappa:, b_max:)
    no = ->(reason) { { 'ok' => false, 'reason' => reason } }
    return no.call('malformed root') if !root_id.is_a?(String) || !root_domain.is_a?(String)
    return no.call('kappa must be finite and > 0') if !mesh_num?(kappa) || kappa <= 0
    return no.call('bMax must be finite and >= 0') if !mesh_num?(b_max) || b_max.negative?
    return no.call('B0 must be finite and >= 0') if !mesh_num?(b0) || b0.negative?
    return no.call('B0 exceeds bMax') if b0 > b_max

    { 'ok' => true, 'state' => { 'nodes' => { root_id => { 'domain' => root_domain, 'B' => b0 } }, 'root' => root_id, 'kappa' => kappa, 'bMax' => b_max } }
  end

  # Allocate a sub-agent budget: a new node `id` (in `domain`) under `parent` with ceiling `alloc` (0 <= alloc <= the parent's
  # CURRENT remaining). A ceiling, not a reservation. Fail-closed on an unknown parent, a duplicate id or an excess allocation.
  def self.allocate_sub(state, id:, domain:, parent:, alloc:)
    no = ->(reason) { { 'ok' => false, 'reason' => reason } }
    return no.call('malformed budget state') unless mesh_budget_state?(state)
    return no.call('malformed allocation') if !id.is_a?(String) || !domain.is_a?(String) || !parent.is_a?(String)
    return no.call('node id already exists') if state['nodes'].key?(id)
    return no.call('unknown parent') unless state['nodes'].key?(parent)

    sub = Risk.sub_budget({ 'B' => state['nodes'][parent]['B'], 'tau' => 0 }, alloc)
    return no.call(sub['reason']) unless sub['ok']

    { 'ok' => true, 'state' => state.merge('nodes' => state['nodes'].merge(id => { 'domain' => domain, 'parent' => parent, 'B' => sub['sub']['B'] })) }
  end

  def self.mesh_budget_path(state, node_id)
    path = []
    cur = node_id
    loop do
      return [nil, 'unknown node'] unless state['nodes'].key?(cur)
      return [nil, 'cycle in budget tree'] if path.include?(cur)
      return [nil, 'budget tree too deep'] if path.length >= MESH_MAX_BUDGET_DEPTH

      path << cur
      break unless state['nodes'][cur].key?('parent')

      cur = state['nodes'][cur]['parent']
    end
    path[-1] == state['root'] ? [path, nil] : [nil, 'node is not rooted at the budget root']
  end

  # Spend `c` at `node_id`: debits that node AND every ancestor up to the root, each exactly once, only if all of them can cover it
  # (atomic; fail-closed with no state change otherwise). Every spend debits the root.
  def self.spend_federated(state, node_id, c)
    no = ->(reason) { { 'ok' => false, 'reason' => reason } }
    return no.call('malformed budget state') unless mesh_budget_state?(state)
    return no.call('malformed node id') unless node_id.is_a?(String)
    return no.call('spend must be finite and >= 0') if !mesh_num?(c) || c.negative?

    path, why = mesh_budget_path(state, node_id)
    return no.call(why) if path.nil?

    root_id = state['root']
    nodes = state['nodes'].dup
    budget = ->(id) { { 'B' => state['nodes'][id]['B'], 'tau' => 0 } }
    if node_id == root_id
      return no.call('root budget insufficient') unless AtlasPca.finite_num(state['nodes'][root_id]['B']) && state['nodes'][root_id]['B'] >= c

      nodes[root_id] = state['nodes'][root_id].merge('B' => Risk.debit(budget.call(root_id), c)['B'])
      return { 'ok' => true, 'state' => state.merge('nodes' => nodes) }
    end
    interior = path[1...-1]
    interior.each { |i| return no.call("ancestor \"#{i}\" budget insufficient") unless AtlasPca.finite_num(state['nodes'][i]['B']) && state['nodes'][i]['B'] >= c }
    dc = Risk.debit_consolidated(budget.call(root_id), budget.call(node_id), c)
    return no.call(dc['reason']) unless dc['ok']

    nodes[node_id] = state['nodes'][node_id].merge('B' => dc['sub']['B'])
    nodes[root_id] = state['nodes'][root_id].merge('B' => dc['parent']['B'])
    interior.each { |i| nodes[i] = state['nodes'][i].merge('B' => Risk.debit(budget.call(i), c)['B']) }
    { 'ok' => true, 'state' => state.merge('nodes' => nodes) }
  end

  # Whatever the shape of the delegation DAG, the total risk of the collective spend between two human recharges is at most
  # bMax / kappa (the single-agent safety bound, covering the whole cross-domain swarm).
  def self.federated_safety_bound(p)
    return 0 if !p.is_a?(Hash) || !mesh_num?(p['bMax']) || !mesh_num?(p['kappa'])

    Risk.safety_bound(p)
  end

  # ---- mutual transparency: the cross-reference linking commitment ----

  # Digest of a mesh action for anchoring (domain-separated, strict canonical).
  def self.mesh_action_digest(action) = hash_canonical({ 'v' => MESH_ACTION_DIGEST_DOMAIN, 'action' => action })

  # The deterministic digest of {action_digest, fromGuardian, toGuardian, nonce, at}: both Guardians anchor THIS value. Raises on a
  # missing member or an unhashable value.
  def self.cross_reference_commit(x)
    raise TypeError, 'crossReferenceCommit: not a cross-reference' if x.nil?

    m = x.is_a?(Hash) ? x : {}
    hash_canonical({ 'v' => 'atlas-pca/mesh-xref/v1', 'action_digest' => m.fetch('action_digest'), 'from' => m.fetch('fromGuardian'),
                     'to' => m.fetch('toGuardian'), 'nonce' => m.fetch('nonce'), 'at' => m.fetch('at') })
  end

  # A Guardian (a KeyPair) signs an anchor binding `commit` at log position `seq`.
  def self.anchor_cross_reference(domain_key, commit, seq)
    { 'domain' => domain_key.public, 'commit' => commit, 'seq' => seq,
      'sig' => b64e(domain_key.sign(mesh_msg(MESH_XANCHOR_DOMAIN, { 'commit' => commit, 'seq' => seq }))) }
  end

  def self.mesh_anchor?(a)
    a.is_a?(Hash) && a['domain'].is_a?(String) && a['commit'].is_a?(String) && mesh_nat?(a['seq']) && a['sig'].is_a?(String)
  end

  def self.mesh_anchor_signed?(a)
    verify_b64u(a['domain'], mesh_msg(MESH_XANCHOR_DOMAIN, { 'commit' => a['commit'], 'seq' => a['seq'] }), a['sig'])
  end

  # Verify a cross-reference: both Guardians' anchors ({'from', 'to'}) commit to the SAME action digest and are each validly
  # signed. Total, fail-closed: {'ok' => true, 'commit'} or {'ok' => false, 'reason'}.
  def self.verify_cross_reference(x, anchors)
    fail = ->(reason) { { 'ok' => false, 'reason' => reason } }
    unless x.is_a?(Hash) && %w[action_digest fromGuardian toGuardian nonce].all? { |k| x[k].is_a?(String) } && mesh_num?(x['at'])
      return fail.call('malformed cross-reference')
    end
    return fail.call('malformed anchors') if !anchors.is_a?(Hash) || !mesh_anchor?(anchors['from']) || !mesh_anchor?(anchors['to'])
    return fail.call('cross-reference must span two distinct domains') if x['fromGuardian'] == x['toGuardian']

    expected = cross_reference_commit(x)
    from = anchors['from']
    to = anchors['to']
    return fail.call('source anchor domain does not match the cross-reference') if from['domain'] != x['fromGuardian']
    return fail.call('target anchor domain does not match the cross-reference') if to['domain'] != x['toGuardian']
    return fail.call('source anchor commits a different action') if from['commit'] != expected
    return fail.call('target anchor commits a different action') if to['commit'] != expected
    return fail.call('source anchor signature invalid') unless mesh_anchor_signed?(from)
    return fail.call('target anchor signature invalid') unless mesh_anchor_signed?(to)

    { 'ok' => true, 'commit' => expected }
  rescue StandardError, SystemStackError
    { 'ok' => false, 'reason' => 'malformed cross-reference' }
  end

  # ---- the worked example ----

  # A PUBLIC, fixed example key: the first 32 bytes of the TEXT of a domain-tagged hash (as the reference builds it). Never a real key.
  def self.mesh_example_key(label) = KeyPair.new(hash_canonical({ 'seed' => "atlas-pca/mesh-example/#{label}" }).b[0, 32])

  # A worked proof with 4 hops across 3 organisations (the human's home is org A): human -> orchestrator (logged in A), orchestrator
  # -> tool agent (A), tool agent -> service agent (B), service agent -> leaf worker (C); the leaf then performs payments.refund
  # for 25 under /orders/42. Org A publishes two successive heads, the second cosigned only after every witness verified the
  # consistency proof. Returns the parts so callers can build variants: {'trust', 'proof', 'evidence', 'domains' => {'A', 'B',
  # 'C'} (MeshDomain), 'witnesses' (MeshWitness), 'keys', 'chain', 'heads' => {'A0', 'A', 'B', 'C'}, 'bindings'}. All keys are fixed
  # public example keys.
  def self.build_mesh_example(now = 1_800_000_000_000)
    keys = %w[human orchestrator tool service leaf].to_h { |k| [k, mesh_example_key(k)] }
    a, b, c = %w[A B C].map { |n| MeshDomain.new("org-#{n}", mesh_example_key("domain-#{n}")) }
    witnesses = [1, 2, 3].map { |i| MeshWitness.new(mesh_example_key("witness-#{i}")) }
    root = mint_root(keys['human'], keys['orchestrator'].public, [
                       { 'type' => 'scope', 'actions' => %w[payments.refund payments.read orders.read] }, { 'type' => 'resource', 'prefix' => '/orders/' },
                       { 'type' => 'max_amount', 'max' => 500 }, { 'type' => 'expires', 'at' => now + 3_600_000 }, { 'type' => 'audience', 'domains' => [c.id] }
                     ])
    c1 = delegate_cap(root, keys['orchestrator'], to_holder: keys['tool'].public,
                                                  added: [{ 'type' => 'scope', 'actions' => %w[payments.refund payments.read] }, { 'type' => 'max_amount', 'max' => 100 }])
    c2 = delegate_cap(c1, keys['tool'], to_holder: keys['service'].public, added: [{ 'type' => 'resource', 'prefix' => '/orders/42' }, { 'type' => 'max_hops', 'n' => 4 }])
    c3 = delegate_cap(c2, keys['service'], to_holder: keys['leaf'].public, added: [{ 'type' => 'scope', 'actions' => ['payments.refund'] }, { 'type' => 'max_amount', 'max' => 50 }])
    chain = [root, c1, c2, c3]
    a.record(root)
    h_a0 = a.publish_head(witnesses, now - 2_000)
    a.record(c1)
    h_a = a.publish_head(witnesses, now - 1_000) # size 1 -> 2: consistency-proven by every witness
    b.record(c2)
    c.record(c3)
    h_b = b.publish_head(witnesses, now - 1_000)
    h_c = c.publish_head(witnesses, now - 1_000)
    b_orch = a.enroll(keys['orchestrator'].public, 'orchestrator')
    b_tool = b.enroll(keys['tool'].public, 'tool-agent')
    b_svc = c.enroll(keys['service'].public, 'service-agent')
    evidence = [a.evidence(root, h_a), a.evidence(c1, h_a, b_orch), b.evidence(c2, h_b, b_tool), c.evidence(c3, h_c, b_svc)]
    action = { 'type' => 'payments.refund', 'resource' => '/orders/42/line/1', 'amount' => 25, 'service_domain' => c.id, 'nonce' => 'n-0001', 'at' => now }
    proof = assemble_mesh_proof(chain, evidence, action, keys['leaf'])
    trust = { 'humanPrincipal' => keys['human'].public, 'witnesses' => witnesses.map(&:id), 'threshold' => 2, 'now' => now,
              'allowedDomains' => [a.id, b.id, c.id], 'rootDomain' => a.id }
    { 'trust' => trust, 'proof' => proof, 'evidence' => evidence, 'domains' => { 'A' => a, 'B' => b, 'C' => c }, 'witnesses' => witnesses, 'keys' => keys,
      'chain' => chain, 'heads' => { 'A0' => h_a0, 'A' => h_a, 'B' => h_b, 'C' => h_c },
      'bindings' => { 'orchestrator' => b_orch, 'tool' => b_tool, 'service' => b_svc } }
  end

  # Witnesses verify real RFC 9162 consistency: a malicious domain rewrites an early log entry and grows the forked log PAST the
  # size the witness last saw. A size-only check would accept it; the consistency proof (computed over the forked log) does not.
  def self.demonstrate_fork_rejection
    k = mesh_example_key('fork-domain')
    hk = mesh_example_key('fork-human')
    mk = ->(n) { mint_root(hk, hk.public, [{ 'type' => 'scope', 'actions' => ["a#{n}"] }]) }
    w = MeshWitness.new(mesh_example_key('fork-witness'))
    honest = MeshDomain.new('X', k)
    honest.record(mk.call(0))
    honest.record(mk.call(1))
    honest.publish_head([w], 100)
    honest.record(mk.call(2))
    honest_ok = begin
      honest.publish_head([w], 200)
      true
    rescue StandardError
      false
    end
    prior = w.last_seen(honest.id)
    fork = MeshDomain.new('X', k) # same key, rewritten history (entry 0 differs), grown past the prior size
    [100, 1, 2, 3].each { |n| fork.record(mk.call(n)) }
    reason = ''
    rejected = false
    begin
      fork.publish_head([w], 300)
    rescue StandardError => e
      rejected = true
      reason = e.message
    end
    { 'honest_extension_cosigned' => honest_ok, 'fork_larger_than_prior' => 4 > prior['size'], 'size_only_check_would_accept' => 4 >= prior['size'],
      'fork_rejected' => rejected, 'fork_reason' => reason }
  end
end
