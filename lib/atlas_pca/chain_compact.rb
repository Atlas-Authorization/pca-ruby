# frozen_string_literal: true

module AtlasPca
  # Compact capability chains (the reference's `chain-compact`) and the cheap pre-authentication chain check. A compact chain is
  # {v, kind, depth, hops_root, leaf}: the root of the Merkle tree over the ordered hop hashes plus the last hop in full. Nothing is
  # trusted from the presentation: a compact chain is accepted only when the verifier's OWN memo holds an entry its own full
  # `verify_chain` produced for `hops_root`, the depth equals the memoized depth and the presented leaf hashes to the memoized last hop.
  CHAIN_HOP_DOMAIN = 'atlas-pca/chain-hop/v1'
  # a memo entry lives at most this long (the chain's caveats may expire sooner; the verifier still evaluates them every time)
  CHAIN_MEMO_MAX_TTL_MS = 3_600_000
  CHAIN_MEMO_DEFAULT_MAX_ENTRIES = 10_000

  module_function

  # The Merkle leaf of one hop: its content hash under a domain tag.
  def hop_leaf(hop) = { 'd' => CHAIN_HOP_DOMAIN, 'hop' => cap_hash(hop) }

  # The handle of a chain: Merkle root over the ordered hop leaves.
  def hops_root(chain) = merkle_root(chain.map { |h| hop_leaf(h) })

  # Fold a chain (root first). Raises on an empty or over-deep chain. Does not verify it (the memo does).
  def compact_chain(chain)
    raise ArgumentError, 'compactChain: the chain must have 1..MAX_CHAIN_DEPTH hops' unless chain.is_a?(Array) && !chain.empty? && chain.length <= MAX_CHAIN_HOPS

    { 'v' => 1, 'kind' => 'pca-chain-compact', 'depth' => chain.length, 'hops_root' => hops_root(chain), 'leaf' => chain[-1] }
  end

  # nil when the compact chain is well-formed.
  def compact_chain_shape_error(c)
    return 'not an object' unless c.is_a?(Hash)

    e = wb_closed_members(c, %w[v kind depth hops_root leaf], [], 'compact chain')
    return e if e
    return 'not a pca-chain-compact v1' unless c['v'].is_a?(Numeric) && c['v'] == 1 && c['kind'] == 'pca-chain-compact'
    return "depth must be 1..#{MAX_CHAIN_HOPS}" unless wb_safe_int?(c['depth']) && c['depth'].between?(1, MAX_CHAIN_HOPS)
    return 'hops_root must be a 43 character digest' unless c['hops_root'].is_a?(String) && c['hops_root'].length == 43
    return 'leaf must be a capability' unless c['leaf'].is_a?(Hash)

    nil
  end

  # The view of a full chain, for symmetry with ChainMemo#resolve (both feed the caveat language).
  def view_of_chain(grant, chain) = chain_view(grant, chain)

  # The verifier-side memo of verified chains. It remembers a chain only after running the full verifier itself, never evicts a live
  # entry when full (one tenant cannot push another out) and resolves a presented compact chain without the middle hops.
  class ChainMemo
    def initialize(max_entries: CHAIN_MEMO_DEFAULT_MAX_ENTRIES, ttl_ms: CHAIN_MEMO_MAX_TTL_MS)
      @entries = {}
      @max = max_entries
      @ttl = [ttl_ms, CHAIN_MEMO_MAX_TTL_MS].min
      @lock = Mutex.new
    end

    def size = @lock.synchronize { @entries.size }

    # Verify `chain` (rooted at `expected_root_issuer`) with the full verifier and remember it; raises when it does not verify or the memo
    # is full of live entries. Returns the compact form a holder presents.
    def remember_verified(chain, expected_root_issuer, now, allowed_suites: nil, pq_pins: nil, trusted_root: nil)
      raise ArgumentError, 'rememberVerified: the clock is not a safe integer' unless AtlasPca.wb_safe_int?(now)

      reason, ok = AtlasPca.verify_chain(chain, expected_root_issuer, true, allowed_suites, pq_pins, trusted_root)
      raise ArgumentError, "rememberVerified: the chain does not verify: #{reason.to_s.empty? ? 'invalid' : reason}" unless ok

      compact = AtlasPca.compact_chain(chain)
      @lock.synchronize do
        prune_locked(now)
        raise ArgumentError, 'rememberVerified: the memo is full of live entries' if !@entries.key?(compact['hops_root']) && @entries.size >= @max

        @entries[compact['hops_root']] = { 'depth' => chain.length, 'hops' => chain.map { |h| AtlasPca.cap_hash(h) },
                                           'counts' => chain.map { |h| h['caveats'].length }, 'expires_at' => now + @ttl }
      end
      compact
    end

    # Drop entries whose time is up.
    def prune(now) = @lock.synchronize { prune_locked(now) }

    # Forget a chain (e.g. when it is revoked).
    def forget(hops_root_value) = @lock.synchronize { !@entries.delete(hops_root_value).nil? }

    # Resolve a presented compact chain against the memo. Total: {'ok' => true, 'view' => ChainView} or {'ok' => false, 'reason' => ...}.
    def resolve(compact, now)
      return { 'ok' => false, 'reason' => 'the verifier clock is not a safe integer (fail closed)' } unless AtlasPca.wb_safe_int?(now)

      e = AtlasPca.compact_chain_shape_error(compact)
      return { 'ok' => false, 'reason' => "malformed compact chain: #{e}" } if e

      m = @lock.synchronize do
        entry = @entries[compact['hops_root']]
        @entries.delete(compact['hops_root']) if entry && !(entry['expires_at'] >= now)
        entry && !(entry['expires_at'] >= now) ? :expired : entry
      end
      return { 'ok' => false, 'reason' => 'the chain is not in this verifier memo (present the full chain)' } if m.nil?
      return { 'ok' => false, 'reason' => 'the memoized chain has expired (present the full chain)' } if m == :expired
      return { 'ok' => false, 'reason' => 'the depth differs from the memoized chain' } if m['depth'] != compact['depth']

      leaf = compact['leaf']
      return { 'ok' => false, 'reason' => 'the leaf is not the memoized last hop' } if AtlasPca.cap_hash(leaf) != m['hops'][m['depth'] - 1]
      return { 'ok' => false, 'reason' => 'the leaf caveats differ from the memoized chain' } unless leaf['caveats'].is_a?(Array) && leaf['caveats'].length == m['counts'][m['depth'] - 1]

      { 'ok' => true, 'view' => ChainView.new(m['depth'], leaf, ->(i) { m['hops'][i] }, ->(i) { m['counts'][i] }) }
    rescue StandardError => e
      { 'ok' => false, 'reason' => "compact chain error (fail closed): #{e.message}" }
    end

    private

    def prune_locked(now) = @entries.delete_if { |_k, v| !(now.is_a?(Numeric) && now.to_f.finite? && v['expires_at'] >= now) }
  end

  # The PQ verification key for a signature by `holder` (a chain leaf / threshold share) under suite `alg`: minted by the resolve_pq_key
  # choke point from the holder's `holder_pq` commitment. nil for ed25519, and nil (so the signature check fails closed) when the
  # artifact's `pq_pk` is not the committed key.
  def holder_pq_key(alg, holder, artifact_pq_pk, holder_pq)
    spec = SIG_SUITES[alg.nil? ? 'ed25519' : alg]
    return nil if spec.nil? || !spec[1]

    resolve_pq_key(holder, artifact_pq_pk, holder_pq: holder_pq)
  end

  # The cheap NECESSARY conditions of a chain, before any state or metering: structure and caps, depth, suite allowlist, parent links, body
  # digests and the Ed25519 half of every hop (never more than MAX_CHAIN_HOPS verifications). A pure-PQ hop passes on structure alone
  # and is decided only by the full verifier. `{'ok' => true, 'pq_hops' => n}` is NEVER an authentication: run `verify_chain` after matching
  # the root to a stored grant. `{'ok' => false, 'reason' => ...}` is final.
  def verify_chain_cheap(chain, expected_root_issuer = nil, allowed_suites: nil)
    arr = chain.is_a?(Array) ? chain : []
    return { 'ok' => false, 'reason' => 'empty chain' } if arr.empty?
    return { 'ok' => false, 'reason' => "chain too long (max #{MAX_CHAIN_HOPS} hops)" } if arr.length > MAX_CHAIN_HOPS
    return { 'ok' => false, 'reason' => CAVEAT_LIMIT_REASON } if caveat_limit_exceeded?(arr)

    pq_hops = 0
    arr.each_with_index do |c, i|
      label = "hop #{i}"
      return { 'ok' => false, 'reason' => "#{label}: malformed capability" } unless hop_well_typed?(c)

      suite = c['alg'].nil? ? 'ed25519' : c['alg']
      return { 'ok' => false, 'reason' => "#{label}: unknown signature alg '#{c['alg']}'" } unless SIG_SUITES.key?(suite)

      pe = suite_policy_error(c['alg'], label, allowed_suites)
      return { 'ok' => false, 'reason' => pe } if pe

      if i.zero?
        return { 'ok' => false, 'reason' => 'hop 0: root must not have a parent' } if c.key?('parent')
        return { 'ok' => false, 'reason' => 'hop 0: root issuer is not the expected principal' } if !expected_root_issuer.nil? && c['issuer'] != expected_root_issuer
      else
        parent = arr[i - 1]
        return { 'ok' => false, 'reason' => "#{label}: broken parent link" } if c['parent'] != cap_hash(parent)
        return { 'ok' => false, 'reason' => "#{label}: issuer is not the parent's bound holder" } if c['issuer'] != parent['holder']
      end
      spec = SIG_SUITES[suite]
      body = body_of(c)
      if suite != 'ed25519'
        body['alg'] = suite
        body['pq_pk'] = c['pq_pk'] if spec[1] && c['pq_pk'].is_a?(String)
      end
      digest = begin
        hash_canonical(body)
      rescue StandardError
        return { 'ok' => false, 'reason' => "#{label}: malformed body" }
      end
      return { 'ok' => false, 'reason' => "#{label}: body digest mismatch" } if digest != c['body_digest'] || c['id'] != c['body_digest']

      # the Ed25519 half: a pure-PQ suite has none (SIG_SUITES length slot 0 is the Ed25519 sig length only for non-PQ and hybrids)
      if suite == 'ed25519' || spec[2]
        signer = i.zero? ? c['issuer'] : arr[i - 1]['holder']
        d = b64d(c['body_digest'], 32)
        return { 'ok' => false, 'reason' => "#{label}: bad signature (not signed by expected key)" } if d.nil? || !verify_b64u(signer, CAP_DOMAIN + d, c['sig'])
      end
      pq_hops += 1 if spec[1]
    end
    { 'ok' => true, 'pq_hops' => pq_hops }
  rescue StandardError => e
    { 'ok' => false, 'reason' => "malformed capability chain: #{e.class}" }
  end
end
