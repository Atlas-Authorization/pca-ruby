# frozen_string_literal: true

# Leases (verification side): a time-boxed, renewable record with a hard max_ttl, separation of duties and revoke by id, path
# prefix or grant. LeaseRegistry keeps the newest record per lease_id (in memory). Every function is total.
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

  class LeaseRegistry
    # policy: { 'authorities' => [...], 'minApprovals', 'eligibleApprovers', 'freshJustification' }
    def initialize(policy)
      @policy = policy
      @leases = {}
      @revocations = []
    end

    attr_reader :leases, :revocations

    def history(id) = @leases[id] ? @leases[id][:history].dup : []

    # { 'ok' => true, 'replaced' =>, 'seq' => } or { 'ok' => false, 'code' => }
    def accept(rec, chain = [])
      return { 'ok' => false, 'code' => 'bad_record' } unless AtlasPca.verify_lease(rec)
      return { 'ok' => false, 'code' => 'unknown_authority' } unless @policy['authorities'].include?(rec['authority'])

      sod = AtlasPca.sod_error(rec, @policy, chain)
      return { 'ok' => false, 'code' => 'sod', 'reason' => sod } unless sod.nil?
      return { 'ok' => false, 'code' => 'over_max_ttl' } if rec['expires_at'] > AtlasPca.lease_cap(rec)
      return { 'ok' => false, 'code' => 'revoked' } if @revocations.any? { |r| AtlasPca.lease_covers?(r, rec) }

      cur = @leases[rec['lease_id']]&.fetch(:current)
      if cur.nil?
        return { 'ok' => false, 'code' => 'bad_seq' } if rec['seq'] != 1
      else
        return { 'ok' => false, 'code' => 'stale_seq' } if rec['seq'] < cur['seq']
        if rec['seq'] == cur['seq']
          return cur['sig'] == rec['sig'] ? { 'ok' => true, 'replaced' => false, 'seq' => rec['seq'] } : { 'ok' => false, 'code' => 'lease_fork' }
        end
        return { 'ok' => false, 'code' => 'bad_seq' } if rec['seq'] != cur['seq'] + 1
        return { 'ok' => false, 'code' => 'renewal_mismatch' } unless %w[authority path grant_ref holder requester max_ttl issued_at].all? { |k| rec[k] == cur[k] }
        return { 'ok' => false, 'code' => 'expired_lease' } if rec['renewed_at'] >= cur['expires_at']
        return { 'ok' => false, 'code' => 'not_extending' } if rec['renewed_at'] < cur['renewed_at'] || rec['expires_at'] <= cur['expires_at']
        if (@policy['freshJustification'].nil? ? true : @policy['freshJustification']) && rec['justification_digest'] == cur['justification_digest']
          return { 'ok' => false, 'code' => 'stale_justification' }
        end
      end
      entry = { 'seq' => rec['seq'], 'renewed_at' => rec['renewed_at'], 'expires_at' => rec['expires_at'], 'justification_digest' => rec['justification_digest'] }
      @leases[rec['lease_id']] = { current: rec, history: (@leases[rec['lease_id']]&.fetch(:history) || []) + [entry] }
      { 'ok' => true, 'replaced' => true, 'seq' => rec['seq'] }
    rescue StandardError
      { 'ok' => false, 'code' => 'store_unreachable' }
    end

    # { 'ok' => true, 'revoked' => n } or { 'ok' => false, 'code' => }
    def revoke(rec)
      return { 'ok' => false, 'code' => 'bad_record' } unless AtlasPca.verify_lease_revocation(rec)
      return { 'ok' => false, 'code' => 'unknown_authority' } unless @policy['authorities'].include?(rec['authority'])

      @revocations << rec unless @revocations.any? { |r| r['sig'] == rec['sig'] }
      { 'ok' => true, 'revoked' => @leases.values.count { |s| AtlasPca.lease_covers?(rec, s[:current]) } }
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
    cur = registry.leases[id]&.fetch(:current)
    return deny.call('unknown_lease') if cur.nil?
    return deny.call('superseded') if cur['sig'] != presented['sig']
    return deny.call('revoked') if registry.revocations.any? { |r| lease_covers?(r, cur) }
    return deny.call('not_yet_valid') if now < cur['renewed_at']
    return deny.call('past_max_ttl') if now >= lease_cap(cur)
    return deny.call('expired') if now >= cur['expires_at']

    { 'decision' => 'allow', 'lease_id' => id, 'expires_at' => cur['expires_at'] }
  rescue StandardError
    { 'decision' => 'deny', 'code' => 'store_unreachable', 'lease_id' => presented.is_a?(Hash) ? presented['lease_id'] : nil }
  end
end
