# frozen_string_literal: true

# Leases (verification side): a time-boxed, renewable record with a hard max_ttl, separation of duties and revoke by id, path
# prefix or grant. LeaseRegistry keeps the newest record per lease_id in a durable kv (sharded by lease id). Every function is total.
# Replays packages/pca/conformance/lease-vectors.json. Hashes use String keys.
module AtlasPca
  LEASE_DOMAIN = "atlas-pca/lease/v1\x00".b.freeze
  LEASE_REVOKE_DOMAIN = "atlas-pca/lease-revoke/v1\x00".b.freeze
  LEASE_BODY_KEYS = %w[v lease_id path grant_ref holder requester approvers justification_digest seq issued_at renewed_at expires_at max_ttl authority].freeze
  LEASE_REVOKE_KEYS = %w[v target value revoked_at authority].freeze
  LEASE_PATH_RE = %r{\A[a-z0-9_.-]{1,64}(/[a-z0-9_.-]{1,64}){0,7}\z}

  module_function

  def lease_well_formed?(l)
    return false unless l.is_a?(Hash) && l['v'] == 1 && l['v'].is_a?(Integer)
    return false unless k3_str?(l['lease_id'], 128) && k3_str?(l['grant_ref'], 256) && k3_str?(l['holder'], 128) && k3_str?(l['requester'], 128)
    return false unless k3_str?(l['authority'], 128) && k3_str?(l['justification_digest'], 128) && l['path'].is_a?(String) && l['path'].match?(LEASE_PATH_RE)
    return false unless %w[seq issued_at renewed_at expires_at max_ttl].all? { |k| k3_int?(l[k]) } && l['seq'] >= 1 && l['max_ttl'] >= 1
    return false if l['renewed_at'] < l['issued_at'] || l['expires_at'] <= l['renewed_at'] || (l['seq'] == 1 && l['renewed_at'] != l['issued_at'])

    a = l['approvers']
    a.is_a?(Array) && a.length <= 16 && a.all? { |x| k3_str?(x, 128) }
  end

  def lease_cap(l) = l['issued_at'] + l['max_ttl']

  # Well formed and signed by its authority over exactly its content. Does NOT check the cap.
  def verify_lease(l)
    return false unless lease_well_formed?(l)

    k3_verify_body(LEASE_DOMAIN, LEASE_BODY_KEYS.to_h { |k| [k, l[k]] }, l['authority'], l['sig'])
  rescue StandardError
    false
  end

  def lease_revocation_well_formed?(r)
    return false unless r.is_a?(Hash) && r['v'] == 1 && r['v'].is_a?(Integer) && k3_str?(r['value'], 256) && k3_str?(r['authority'], 128) && k3_int?(r['revoked_at'])
    return false unless %w[lease prefix grant].include?(r['target'])

    r['target'] != 'prefix' || r['value'].match?(LEASE_PATH_RE)
  end

  def verify_lease_revocation(r)
    return false unless lease_revocation_well_formed?(r)

    k3_verify_body(LEASE_REVOKE_DOMAIN, LEASE_REVOKE_KEYS.to_h { |k| [k, r[k]] }, r['authority'], r['sig'])
  rescue StandardError
    false
  end

  def path_under(path, prefix) = path == prefix || path.start_with?("#{prefix}/")

  def lease_covers?(r, l)
    l['issued_at'] <= r['revoked_at'] &&
      (r['target'] == 'lease' ? l['lease_id'] == r['value'] : r['target'] == 'grant' ? l['grant_ref'] == r['value'] : path_under(l['path'], r['value']))
  end

  # A reason or nil. p: { 'minApprovals', 'eligibleApprovers' }.
  def sod_error(l, p = {}, chain = [])
    p = {} unless p.is_a?(Hash)
    k = p['minApprovals'].nil? ? 1 : p['minApprovals']
    return 'minApprovals must be a positive integer' unless k.is_a?(Integer) && k >= 1 && k <= MAX_SAFE

    seen = {}
    l['approvers'].each do |a|
      return 'an approver is listed twice' if seen[a]

      seen[a] = true
      return 'the requester may not approve their own request' if a == l['requester']
      return 'the holder may not approve its own lease' if a == l['holder']
      return "an approver appears in the holder's delegation chain" if chain.include?(a)
      return 'an approver is not eligible' if !p['eligibleApprovers'].nil? && !p['eligibleApprovers'].include?(a)
    end
    l['approvers'].length < k ? "#{l['approvers'].length} approver(s), need #{k}" : nil
  end

  # The registry keeps each lease in the shard its id hashes to (the TS LeaseRegistry layout: `lease/<shards>/<i>`), so an issue,
  # a renewal and a check read and write one small document. A path-prefix or grant revocation is written to EVERY shard; a
  # revocation of one lease id only to that lease's shard. Within a shard each operation is one atomic kv update. The kv is
  # required: a process-local default would forget the revocations on restart (MemoryLeaseKv is for tests and single-process use).
  class LeaseRegistry
    DEFAULT_SHARDS = 16
    META_KEY = 'lease/meta'

    # policy: { 'authorities' => [...], 'minApprovals', 'eligibleApprovers', 'freshJustification', 'maxTtlCeiling' }
    # kv: get(key) + atomic update(key) { |prev| next }. clock: the revocation-pruning clock in ms (default wall clock).
    def initialize(policy, kv = nil, shards: DEFAULT_SHARDS, clock: nil)
      unless AtlasPca.kv_usable?(kv)
        raise TypeError, 'LeaseRegistry: a durable key-value store is required (memoryLeaseKv() is for tests and single-process use)'
      end
      raise RangeError, 'LeaseRegistry: shards must be an integer from 1 to 4096' unless shards.is_a?(Integer) && shards >= 1 && shards <= MAX_KV_SHARDS
      if policy.key?('maxTtlCeiling') && !(policy['maxTtlCeiling'].is_a?(Integer) && policy['maxTtlCeiling'] >= 1 && policy['maxTtlCeiling'] <= MAX_SAFE)
        raise RangeError, 'LeaseRegistry: maxTtlCeiling must be a positive integer'
      end

      @policy = policy
      @kv = kv
      @shards = shards
      @clock = clock || -> { (Time.now.to_f * 1000).to_i }
      @meta_ok = false
      @lock = Mutex.new
    end

    attr_reader :shards

    # The newest record of a lease, or nil.
    def get(id) = shard_of_id(id)['leases'][id]&.fetch('current')

    # The renewal ledger of a lease, oldest first.
    def history(id) = shard_of_id(id)['leases'][id]&.fetch('history') || []

    # { 'current' =>, 'revoked' => bool } (the newest record and whether a stored revocation covers it) or nil.
    def lookup(id)
      st = shard_of_id(id)
      cur = st['leases'][id]&.fetch('current')
      cur.nil? ? nil : { 'current' => cur, 'revoked' => st['revocations'].any? { |r| AtlasPca.lease_covers?(r, cur) } }
    end

    # Revocations held by one shard.
    def shard_revocations(i)
      raise RangeError, 'no such shard' unless i.is_a?(Integer) && i >= 0 && i < @shards
      raise 'shard count mismatch' unless ready?

      load_shard(@kv.get(shard_key(i)))['revocations']
    end

    # Every distinct stored revocation (a prefix / grant revocation sits in all shards).
    def revocations = (0...@shards).flat_map { |i| shard_revocations(i) }.uniq { |r| r['sig'] }

    # { 'ok' => true, 'replaced' =>, 'seq' => } or { 'ok' => false, 'code' => }
    def accept(rec, chain = []) = @lock.synchronize { accept_locked(rec, chain) }

    # { 'ok' => true, 'revoked' => n } or { 'ok' => false, 'code' => }
    def revoke(rec) = @lock.synchronize { revoke_locked(rec) }

    private

    def shard_key(i) = "lease/#{@shards}/#{i}"

    def load_shard(x)
      x.is_a?(Hash) && x['leases'].is_a?(Hash) && x['revocations'].is_a?(Array) ? x : { 'leases' => {}, 'revocations' => [] }
    end

    def ready?
      @meta_ok ||= AtlasPca.kv_pin_shards(@kv, META_KEY, @shards)
    end

    def shard_of_id(id)
      raise 'shard count mismatch' unless ready?

      load_shard(@kv.get(shard_key(AtlasPca.kv_shard_of(id, @shards))))
    end

    # Pruned only when maxTtlCeiling is set: once revoked_at + ceiling is past, every lease it could cover is beyond its own cap.
    def prune(st)
      c = @policy['maxTtlCeiling']
      return if c.nil?

      now = @clock.call
      st['revocations'] = st['revocations'].select { |r| r['revoked_at'] + c >= now }
    end

    def accept_locked(rec, chain)
      return { 'ok' => false, 'code' => 'bad_record' } unless AtlasPca.verify_lease(rec)
      return { 'ok' => false, 'code' => 'unknown_authority' } unless @policy['authorities'].include?(rec['authority'])

      sod = AtlasPca.sod_error(rec, @policy, chain)
      return { 'ok' => false, 'code' => 'sod', 'reason' => sod } unless sod.nil?
      return { 'ok' => false, 'code' => 'over_max_ttl' } if rec['expires_at'] > AtlasPca.lease_cap(rec)
      return { 'ok' => false, 'code' => 'ttl_ceiling' } if @policy.key?('maxTtlCeiling') && rec['max_ttl'] > @policy['maxTtlCeiling']
      return { 'ok' => false, 'code' => 'store_unreachable' } unless ready?

      out = { 'ok' => false, 'code' => 'store_unreachable' }
      fail_with = lambda do |code|
        out = { 'ok' => false, 'code' => code }
        nil
      end
      @kv.update(shard_key(AtlasPca.kv_shard_of(rec['lease_id'], @shards))) do |prev|
        st = load_shard(prev)
        cur = st['leases'][rec['lease_id']]&.fetch('current')
        next fail_with.call('revoked') if st['revocations'].any? { |r| AtlasPca.lease_covers?(r, rec) }

        if cur.nil?
          next fail_with.call('bad_seq') if rec['seq'] != 1
        else
          next fail_with.call('stale_seq') if rec['seq'] < cur['seq']

          if rec['seq'] == cur['seq']
            out = cur['sig'] == rec['sig'] ? { 'ok' => true, 'replaced' => false, 'seq' => rec['seq'] } : { 'ok' => false, 'code' => 'lease_fork' }
            next nil
          end
          next fail_with.call('bad_seq') if rec['seq'] != cur['seq'] + 1
          next fail_with.call('renewal_mismatch') unless %w[authority path grant_ref holder requester max_ttl issued_at].all? { |k| rec[k] == cur[k] }
          next fail_with.call('expired_lease') if rec['renewed_at'] >= cur['expires_at']
          next fail_with.call('not_extending') if rec['renewed_at'] < cur['renewed_at'] || rec['expires_at'] <= cur['expires_at']

          fresh = @policy['freshJustification'].nil? ? true : @policy['freshJustification']
          next fail_with.call('stale_justification') if fresh && rec['justification_digest'] == cur['justification_digest']
        end
        entry = { 'seq' => rec['seq'], 'renewed_at' => rec['renewed_at'], 'expires_at' => rec['expires_at'], 'justification_digest' => rec['justification_digest'] }
        st['leases'][rec['lease_id']] = { 'current' => rec, 'history' => (st['leases'][rec['lease_id']]&.fetch('history') || []) + [entry] }
        prune(st)
        out = { 'ok' => true, 'replaced' => true, 'seq' => rec['seq'] }
        st
      end
      out
    rescue StandardError
      { 'ok' => false, 'code' => 'store_unreachable' }
    end

    def revoke_locked(rec)
      return { 'ok' => false, 'code' => 'bad_record' } unless AtlasPca.verify_lease_revocation(rec)
      return { 'ok' => false, 'code' => 'unknown_authority' } unless @policy['authorities'].include?(rec['authority'])
      return { 'ok' => false, 'code' => 'store_unreachable' } unless ready?

      targets = rec['target'] == 'lease' ? [AtlasPca.kv_shard_of(rec['value'], @shards)] : (0...@shards).to_a
      n = 0
      targets.each do |i|
        @kv.update(shard_key(i)) do |prev|
          st = load_shard(prev)
          st['revocations'] << rec unless st['revocations'].any? { |r| r['sig'] == rec['sig'] }
          n += st['leases'].values.count { |s| AtlasPca.lease_covers?(rec, s['current']) }
          prune(st)
          st
        end
      end
      { 'ok' => true, 'revoked' => n }
    rescue StandardError
      { 'ok' => false, 'code' => 'store_unreachable' }
    end
  end

  # { 'decision' => 'allow', 'lease_id' =>, 'expires_at' => } or { 'decision' => 'deny', 'code' =>[, 'lease_id' =>] }
  def check_lease(presented, registry, now)
    return { 'decision' => 'deny', 'code' => 'bad_input' } unless k3_int?(now)
    return { 'decision' => 'deny', 'code' => 'bad_record' } unless verify_lease(presented)

    id = presented['lease_id']
    deny = ->(code) { { 'decision' => 'deny', 'code' => code, 'lease_id' => id } }
    found = registry.lookup(id)
    return deny.call('unknown_lease') if found.nil?

    cur = found['current']
    return deny.call('superseded') if cur['sig'] != presented['sig']
    return deny.call('revoked') if found['revoked']
    return deny.call('not_yet_valid') if now < cur['renewed_at']
    return deny.call('past_max_ttl') if now >= lease_cap(cur)
    return deny.call('expired') if now >= cur['expires_at']

    { 'decision' => 'allow', 'lease_id' => id, 'expires_at' => cur['expires_at'] }
  rescue StandardError
    { 'decision' => 'deny', 'code' => 'store_unreachable', 'lease_id' => presented.is_a?(Hash) ? presented['lease_id'] : nil }
  end
end
