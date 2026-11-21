# frozen_string_literal: true

# zc lease: LeaseRegistry storage edge cases (corrupt shards, the pinned shard count, an update that never runs, signature
# de-duplication of stored revocations, the default pruning clock). Signature verification is stubbed: it is not the point here.
module MutationKill
  module ZCLease
    module_function

    AUTH = 'authority-key'

    def base(over = {})
      { 'v' => 1, 'lease_id' => 'L1', 'path' => 'db/prod', 'grant_ref' => 'g1', 'holder' => 'agent', 'requester' => 'alice', 'approvers' => ['bob'],
        'justification_digest' => 'j1', 'seq' => 1, 'issued_at' => 1000, 'renewed_at' => 1000, 'expires_at' => 2000, 'max_ttl' => 5000,
        'authority' => AUTH, 'sig' => 'sig-lease' }.merge(over)
    end

    def rev(over = {})
      { 'v' => 1, 'target' => 'lease', 'value' => 'L1', 'revoked_at' => 1500, 'authority' => AUTH, 'sig' => 'sig-rev' }.merge(over)
    end

    def stubbed(&blk) = ZC.seam(AtlasPca, { verify_lease: ->(_r) { true }, verify_lease_revocation: ->(_r) { true } }, &blk)
    def kv = AtlasPca::MemoryLeaseKv.new
    def reg(kv = self.kv, pol = {}, **o) = AtlasPca::LeaseRegistry.new({ 'authorities' => [AUTH] }.merge(pol), kv, **o)
    def key_of(id, shards = 16) = "lease/#{shards}/#{AtlasPca.kv_shard_of(id, shards)}"

    # an atomic kv that never runs the update block of anything but the shard-count pin
    class DeafKv
      def initialize = @inner = AtlasPca::MemoryLeaseKv.new
      def get(key) = @inner.get(key)
      def update(key, &blk) = key == 'lease/meta' ? @inner.update(key, &blk) : nil
    end
  end

  t('zc lease: a corrupt stored shard reads as an empty one') do
    next true unless ZC.gate?('lease.rb')

    cur = ZCLease.base
    good_lease = { 'L1' => { 'current' => cur, 'history' => [{ 'seq' => 1 }] } }
    garbage = [[], 'text', 5, { 'leases' => 'L1xx', 'revocations' => [] }, { 'leases' => [], 'revocations' => [] }, { 'leases' => good_lease, 'revocations' => 'x' },
               { 'leases' => good_lease }, { 'revocations' => [] }, { 'leases' => good_lease, 'revocations' => { 'a' => 1 } }]
    garbage.each_with_index do |g, i|
      kv = ZCLease.kv
      r = ZCLease.reg(kv)
      ZC.eq("pin #{i}", r.get('nobody'), nil)
      kv.set(ZCLease.key_of('L1'), g)
      ZC.eq("get #{i}", r.get('L1'), nil)
      ZC.eq("history #{i}", r.history('L1'), [])
      ZC.eq("lookup #{i}", r.lookup('L1'), nil)
    end
    kv = ZCLease.kv
    r = ZCLease.reg(kv)
    r.get('nobody')
    revoked = ZCLease.rev
    kv.set(ZCLease.key_of('L1'), { 'leases' => good_lease, 'revocations' => [] })
    ZC.eq('stored lease', r.get('L1'), cur) && ZC.eq('stored history', r.history('L1'), [{ 'seq' => 1 }]) &&
      ZC.eq('not revoked', r.lookup('L1'), { 'current' => cur, 'revoked' => false }) &&
      begin
        kv.set(ZCLease.key_of('L1'), { 'leases' => good_lease, 'revocations' => [revoked] })
        ZC.eq('revoked', r.lookup('L1'), { 'current' => cur, 'revoked' => true })
      end
  end

  t('zc lease: the shard count is pinned once and not re-read after') do
    next true unless ZC.gate?('lease.rb')

    kv = ZCLease.kv
    r = ZCLease.reg(kv)
    ZC.eq('first read', r.get('L1'), nil)
    kv.set('lease/meta', { 'v' => 1, 'shards' => 99 })
    ZC.eq('memoized readiness', r.get('L1'), nil) &&
      ZC.raises('a foreign pin is refused on first use') { ZCLease.reg(kv).get('L1') }
  end

  t('zc lease: an update block that never runs is exactly store_unreachable') do
    next true unless ZC.gate?('lease.rb')

    ZCLease.stubbed do
      ZC.eq('accept', ZCLease.reg(ZCLease::DeafKv.new).accept(ZCLease.base), { 'ok' => false, 'code' => 'store_unreachable' })
    end
  end

  t('zc lease: a revocation is stored once per shard however often it is presented') do
    next true unless ZC.gate?('lease.rb')

    ZCLease.stubbed do
      r = ZCLease.reg
      r.accept(ZCLease.base)
      pre = ZCLease.rev({ 'target' => 'prefix', 'value' => 'db', 'sig' => 'sig-prefix' })
      one = ZCLease.rev({ 'sig' => 'sig-one' })
      ZC.eq('prefix', r.revoke(pre), { 'ok' => true, 'revoked' => 1 }) && ZC.eq('prefix again', r.revoke(pre), { 'ok' => true, 'revoked' => 1 }) &&
        ZC.eq('lease', r.revoke(one), { 'ok' => true, 'revoked' => 1 }) && ZC.eq('lease again', r.revoke(one), { 'ok' => true, 'revoked' => 1 }) &&
        begin
          home = AtlasPca.kv_shard_of('L1', 16)
          (0...16).all? do |i|
            sigs = r.shard_revocations(i).map { |x| x['sig'] }
            ZC.eq("shard #{i}", sigs, i == home ? %w[sig-prefix sig-one] : %w[sig-prefix])
          end
        end
    end
  end

  t('zc lease: the default pruning clock is whole epoch milliseconds') do
    next true unless ZC.gate?('lease.rb')

    ZCLease.stubbed do
      r = ZCLease.reg(ZCLease.kv, { 'maxTtlCeiling' => 500 })
      r.accept(ZCLease.base({ 'max_ttl' => 500, 'issued_at' => 100, 'renewed_at' => 100, 'expires_at' => 400 }))
      home = AtlasPca.kv_shard_of('L1', 16)
      # now = 1062.5 ms: revoked_at + ceiling = 1062 is not past a whole-millisecond clock (1062), but is past 1062.5
      ZC.seam(Time, { now: -> { Time.at(1.0625) } }) { ZC.eq('revoke', r.revoke(ZCLease.rev({ 'revoked_at' => 562, 'sig' => 'sig-a' })), { 'ok' => true, 'revoked' => 1 }) }
      # now = 1000 ms exactly: revoked_at + ceiling = 1000 is kept
      ZC.seam(Time, { now: -> { Time.at(1.0) } }) { ZC.eq('revoke at 1000', r.revoke(ZCLease.rev({ 'revoked_at' => 500, 'sig' => 'sig-b' })), { 'ok' => true, 'revoked' => 1 }) }
      ZC.eq('both kept', r.shard_revocations(home).map { |x| x['sig'] }.sort, %w[sig-a sig-b])
    end
  end
end
