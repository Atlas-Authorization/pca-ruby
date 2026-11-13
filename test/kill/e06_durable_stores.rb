# frozen_string_literal: true

# e06: tests for the durable-kv lease / break-glass / blueprint registries (H15), the blueprint admitted hook (F4), lease
# revocation pruning (F5) and the registry store-conformance kits (F11): lib/atlas_pca/{lease,break_glass,blueprint,
# store_conformance,atomic_kv}.rb. AtlasPca is resolved at CALL time (the oracle re-evaluates it per mutant). Helpers come from
# c26 (real Ed25519 leases) and c30 (real break-glass / blueprint signing); this file loads after both.
require 'securerandom'

module MutationKill
  module E06
    FILES = %w[lease.rb break_glass.rb blueprint.rb store_conformance.rb atomic_kv.rb].freeze

    # a kv whose every call raises (pass_meta: the shard-count pin goes through, everything else raises)
    class ThrowKv
      def initialize(pass_meta: false)
        @pass_meta = pass_meta
        @inner = nil
      end

      def get(_key)
        raise 'down'
      end

      def update(key, &blk)
        raise 'down' unless @pass_meta && key.end_with?('/meta')

        (@inner ||= AtlasPca::MemoryAtomicKv.new).update(key, &blk)
      end
    end

    # a kv whose update is read, wait, write: two writers both see the old value
    class RacyKv
      def initialize
        @m = {}
        @mu = Mutex.new
        @cv = ConditionVariable.new
        @round = Hash.new { |h, k| h[k] = { arrived: 0, inside: 0, open: false } }
      end

      def get(key)
        v = @m[key]
        v.nil? ? nil : Marshal.load(Marshal.dump(v))
      end

      # A non-atomic read-modify-write: every racing caller reads `prev`, then waits (per key) until a second racer has
      # also read before any of them writes, so a lost update manifests regardless of scheduling speed (a wall-clock sleep
      # or short timeout let a late racer run alone under load). Calls from the main thread are serial setup and never wait.
      def update(key)
        prev = get(key)
        rendezvous(key) unless Thread.current == Thread.main
        nxt = yield(prev)
        @m[key] = Marshal.load(Marshal.dump(nxt)) unless nxt.nil?
        get(key)
      end

      private

      def rendezvous(key)
        @mu.synchronize do
          r = @round[key]
          r[:inside] += 1
          r[:arrived] += 1
          if r[:arrived] >= 2 && !r[:open]
            r[:open] = true
            @cv.broadcast
          end
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 30
          until r[:open]
            left = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            break if left <= 0

            @cv.wait(@mu, left)
          end
          r[:inside] -= 1
          @round.delete(key) if r[:inside].zero?
        end
      end
    end

    module_function

    def on?
      f = ENV['MUT_FILE']
      f.nil? || f.empty? || FILES.include?(f)
    end

    def same(got, want, label)
      ok = want.nil? || want == true || want == false ? got.equal?(want) : got == want
      raise "#{label}: got #{got.inspect}, want #{want.inspect}" unless ok

      true
    end

    def raises(cls, msg)
      yield
    rescue StandardError => e
      same(e.class, cls, 'exception class')
      same(e.message, msg, 'exception message')
    else
      raise "expected #{cls}: #{msg}"
    end

    def lz = MutationKill::C26::Lz
    def c30 = MutationKill::C30

    def statuses(report) = report.results.to_h { |r| [r.test, r.status] }

    def threads(n)
      Array.new(n) { |i| Thread.new { yield(i) } }.map(&:value)
    end
  end

  # ------------------------------------------------------------------------------------------------------------------ H15
  t('e06 H15 constructors: no store, or a store without get + update, is refused with the exact texts; a memory kv is accepted') do
    next true unless E06.on?

    pol = { 'authorities' => [], 'reviewers' => [] }
    lease_msg = 'LeaseRegistry: a durable key-value store is required (memoryLeaseKv() is for tests and single-process use)'
    glass_msg = 'BreakGlassRegistry: a durable key-value store is required (memoryLeaseKv() is for tests and single-process use)'
    bp_msg = 'BlueprintRegistry: a durable BlueprintStore is required (MemoryBlueprintKv is for tests and single-process use)'
    get_only = Class.new { def get(_key) = nil }.new
    update_only = Class.new { def update(_key) = nil }.new
    [nil, Object.new, get_only, update_only].each do |kv|
      E06.raises(TypeError, lease_msg) { AtlasPca::LeaseRegistry.new(pol, kv) }
      E06.raises(TypeError, glass_msg) { AtlasPca::BreakGlassRegistry.new(pol, kv) }
      E06.raises(TypeError, bp_msg) { AtlasPca::BlueprintRegistry.new([], kv) }
    end
    E06.raises(TypeError, lease_msg) { AtlasPca::LeaseRegistry.new(pol) }
    E06.raises(TypeError, glass_msg) { AtlasPca::BreakGlassRegistry.new(pol) }
    E06.raises(TypeError, bp_msg) { AtlasPca::BlueprintRegistry.new([]) }
    # the store is checked before the other arguments
    E06.raises(TypeError, lease_msg) { AtlasPca::LeaseRegistry.new(pol, nil, shards: 0) }
    kv = AtlasPca::MemoryAtomicKv.new
    E06.same(AtlasPca::LeaseRegistry.new(pol, kv).is_a?(AtlasPca::LeaseRegistry), true, 'lease')
    E06.same(AtlasPca::BreakGlassRegistry.new(pol, kv).is_a?(AtlasPca::BreakGlassRegistry), true, 'glass')
    E06.same(AtlasPca::BlueprintRegistry.new([], kv).is_a?(AtlasPca::BlueprintRegistry), true, 'blueprint')
    # the shard count is an integer from 1 to 4096
    [0, 4097, -1, '16', 1.5, nil].each do |n|
      E06.raises(RangeError, 'LeaseRegistry: shards must be an integer from 1 to 4096') { AtlasPca::LeaseRegistry.new(pol, kv, shards: n) }
      E06.raises(RangeError, 'BreakGlassRegistry: shards must be an integer from 1 to 4096') { AtlasPca::BreakGlassRegistry.new(pol, kv, shards: n) }
    end
    [1, 4096].each do |n|
      E06.same(AtlasPca::LeaseRegistry.new(pol, kv, shards: n).shards, n, 'lease shards')
      E06.same(AtlasPca::BreakGlassRegistry.new(pol, kv, shards: n).is_a?(AtlasPca::BreakGlassRegistry), true, 'glass shards')
    end
    E06.same(AtlasPca::LeaseRegistry.new(pol, kv).shards, 16, 'default shards')
    true
  end

  t('e06 kv helpers: usable?, shard_of (stable SHA-256 prefix), pin_shards, memory aliases') do
    next true unless E06.on?

    kv = AtlasPca::MemoryAtomicKv.new
    E06.same(AtlasPca.kv_usable?(kv), true, 'memory kv')
    [nil, Object.new, Class.new { def get(_k) = nil }.new, Class.new { def update(_k) = nil }.new].each do |x|
      E06.same(AtlasPca.kv_usable?(x), false, "unusable #{x.inspect}")
    end
    [['L1', 16, 6], ['L3', 16, 14], ['h1', 16, 1], ['h10', 16, 1], ['K1', 16, 3], ['h2', 16, 6], ['L1', 4, 2], ['L1', 4096, 1430],
     ['h1', 4096, 3809], ['K1', 4096, 643], ["café", 4096, 3524], ["café", 16, 4], ['', 16, 2], ['x', 1, 0]].each do |id, n, want|
      E06.same(AtlasPca.kv_shard_of(id, n), want, "shard_of #{id.inspect} #{n}")
    end
    E06.same(AtlasPca::MAX_KV_SHARDS, 4096, 'max shards')
    E06.same(AtlasPca.kv_pin_shards(kv, 'm', 16), true, 'first pin')
    E06.same(kv.get('m'), { 'v' => 1, 'shards' => 16 }, 'stored pin')
    E06.same(AtlasPca.kv_pin_shards(kv, 'm', 16), true, 'same count again')
    E06.same(AtlasPca.kv_pin_shards(kv, 'm', 4), false, 'another count refused')
    E06.same(kv.get('m'), { 'v' => 1, 'shards' => 16 }, 'pin unchanged by a refusal')
    %i[MemoryLeaseKv MemoryBreakGlassKv MemoryBlueprintKv].each do |n|
      E06.same(AtlasPca.const_get(n).equal?(AtlasPca::MemoryAtomicKv), true, "#{n} alias")
    end
    true
  end

  t('e06 H15 lease: a revocation survives in the kv; a NEW registry refuses the signed seq-1 record; sharded layout') do
    next true unless E06.on?

    lz = E06.lz
    pol = { 'authorities' => [lz.pub] }
    kv = AtlasPca::MemoryLeaseKv.new
    a = AtlasPca::LeaseRegistry.new(pol, kv)
    l1 = lz.signed
    E06.same(a.accept(l1), { 'ok' => true, 'replaced' => true, 'seq' => 1 }, 'issue')
    E06.same(kv.get('lease/meta'), { 'v' => 1, 'shards' => 16 }, 'meta')
    doc = kv.get('lease/16/6')
    E06.same(doc['leases'].keys, ['L1'], 'L1 lives in shard 6')
    E06.same(doc['leases']['L1']['current'], l1, 'stored record')
    (0...16).each { |i| E06.same(kv.get("lease/16/#{i}"), nil, "shard #{i} untouched") unless i == 6 }
    E06.same(a.revoke(lz.rsigned), { 'ok' => true, 'revoked' => 1 }, 'revoke by id')
    E06.same((0...16).map { |i| (kv.get("lease/16/#{i}") || { 'revocations' => [] })['revocations'].length }, [0] * 6 + [1] + [0] * 9, 'a lease revocation sits only in its shard')
    prefix = lz.rsigned('target' => 'prefix', 'value' => 'db')
    E06.same(a.revoke(prefix), { 'ok' => true, 'revoked' => 1 }, 'revoke by prefix')
    E06.same((0...16).map { |i| kv.get("lease/16/#{i}")['revocations'].length }, [1] * 6 + [2] + [1] * 9, 'a prefix revocation sits in every shard')
    E06.same(a.revocations, [prefix, lz.rsigned], 'distinct revocations, first seen in shard order')

    b = AtlasPca::LeaseRegistry.new(pol, kv)
    E06.same(b.accept(l1), { 'ok' => false, 'code' => 'revoked' }, 'the signed seq-1 record presented to a new registry')
    E06.same(AtlasPca.check_lease(l1, b, 1500), { 'decision' => 'deny', 'code' => 'revoked', 'lease_id' => 'L1' }, 'check on a new registry')
    E06.same(b.get('L1'), l1, 'get')
    E06.same(b.history('L1'), [{ 'seq' => 1, 'renewed_at' => 1000, 'expires_at' => 2000, 'justification_digest' => 'j1' }], 'history')
    E06.same(b.lookup('L1'), { 'current' => l1, 'revoked' => true }, 'lookup')
    E06.same(b.lookup('nope'), nil, 'lookup of an unknown id')
    E06.same(b.get('nope'), nil, 'get of an unknown id')
    E06.same(b.history('nope'), [], 'history of an unknown id')
    E06.same(b.revocations.length, 2, 'revocations across a new registry')
    E06.raises(RangeError, 'no such shard') { b.shard_revocations(16) }
    E06.raises(RangeError, 'no such shard') { b.shard_revocations(-1) }
    E06.raises(RangeError, 'no such shard') { b.shard_revocations('0') }
    E06.same(b.shard_revocations(6).length, 2, 'shard 6')
    E06.same(b.shard_revocations(0).length, 1, 'shard 0')
    true
  end

  t('e06 H15 lease: another shard count is refused (store_unreachable), a fresh store takes it; two concurrent renewals have one winner') do
    next true unless E06.on?

    lz = E06.lz
    pol = { 'authorities' => [lz.pub] }
    kv = AtlasPca::MemoryLeaseKv.new
    l1 = lz.signed
    AtlasPca::LeaseRegistry.new(pol, kv).accept(l1)
    r4 = AtlasPca::LeaseRegistry.new(pol, kv, shards: 4)
    unreach = { 'ok' => false, 'code' => 'store_unreachable' }
    E06.same(r4.accept(l1), unreach, 'accept with another shard count')
    E06.same(r4.revoke(lz.rsigned), unreach, 'revoke with another shard count')
    E06.same(AtlasPca.check_lease(l1, r4, 1500), { 'decision' => 'deny', 'code' => 'store_unreachable', 'lease_id' => 'L1' }, 'check')
    E06.raises(RuntimeError, 'shard count mismatch') { r4.get('L1') }
    E06.raises(RuntimeError, 'shard count mismatch') { r4.shard_revocations(0) }
    kv4 = AtlasPca::MemoryLeaseKv.new
    f4 = AtlasPca::LeaseRegistry.new(pol, kv4, shards: 4)
    E06.same(f4.accept(l1), { 'ok' => true, 'replaced' => true, 'seq' => 1 }, 'accept with 4 shards')
    E06.same(kv4.get('lease/4/2')['leases'].keys, ['L1'], 'shard 2 of 4')
    E06.same(kv4.get('lease/meta'), { 'v' => 1, 'shards' => 4 }, 'meta 4')

    kv2 = AtlasPca::MemoryLeaseKv.new
    regs = [AtlasPca::LeaseRegistry.new(pol, kv2), AtlasPca::LeaseRegistry.new(pol, kv2)]
    regs[0].accept(l1)
    recs = Array.new(8) { |i| lz.signed({ 'seq' => 2, 'renewed_at' => 1500, 'expires_at' => 3000, 'justification_digest' => "jr#{i}" }) }
    rs = E06.threads(8) { |i| regs[i % 2].accept(recs[i]) }
    E06.same(rs.count { |x| x['ok'] == true }, 1, 'exactly one renewal wins')
    E06.same(rs.reject { |x| x['ok'] == true }.map { |x| x['code'] }.uniq, ['lease_fork'], 'the others are forks')
    win = rs.index { |x| x['ok'] == true }
    E06.same(regs[1].get('L1'), recs[win], 'the stored record is the winner')
    true
  end

  t('e06 H15 lease / break-glass / blueprint: any kv throw is store_unreachable (accept, revoke, use, review, check) and frozen fails closed') do
    next true unless E06.on?

    lz = E06.lz
    c30 = E06.c30
    l1 = lz.signed
    g = c30.sign_grant(c30.grant)
    rv = c30.sign_review(c30.review)
    k1 = c30.pk('op1')
    rec = c30.sign_bp(c30.bp('operator' => k1), 'op1')
    chain = [{ 'issuer' => 'root', 'holder' => 'K1' }, { 'issuer' => 'K1', 'holder' => 'leaf' }]
    [false, true].each do |pass_meta|
      kv = -> { E06::ThrowKv.new(pass_meta: pass_meta) }
      label = "pass_meta=#{pass_meta}"
      lease = AtlasPca::LeaseRegistry.new({ 'authorities' => [lz.pub] }, kv.call)
      E06.same(lease.accept(l1), { 'ok' => false, 'code' => 'store_unreachable' }, "lease accept #{label}")
      E06.same(lease.revoke(lz.rsigned), { 'ok' => false, 'code' => 'store_unreachable' }, "lease revoke #{label}")
      E06.same(AtlasPca.check_lease(l1, lease, 1500), { 'decision' => 'deny', 'code' => 'store_unreachable', 'lease_id' => 'L1' }, "check_lease #{label}")
      glass = AtlasPca::BreakGlassRegistry.new({ 'authorities' => [c30.pk('auth')], 'reviewers' => [c30.pk('rev')] }, kv.call)
      E06.same(glass.accept(g, 1000), { 'ok' => false, 'code' => 'store_unreachable' }, "bg accept #{label}")
      E06.same(glass.use('g1', 'h1', 'd', 1000, true), { 'decision' => 'deny', 'code' => 'store_unreachable', 'id' => 'g1' }, "bg use #{label}")
      E06.same(glass.review(rv, 'h1', 1200), { 'ok' => false, 'code' => 'store_unreachable' }, "bg review #{label}")
      E06.same(glass.frozen('h1', 1200), true, "bg frozen #{label}")
      bp = AtlasPca::BlueprintRegistry.new([k1], kv.call)
      E06.same(bp.accept(rec), { 'ok' => false, 'code' => 'store_unreachable' }, "bp accept #{label}")
      E06.same(AtlasPca.check_blueprints(chain, bp, 100, 'require'), { 'decision' => 'deny', 'code' => 'store_unreachable' }, "bp check #{label}")
      E06.same(AtlasPca.check_blueprints(chain, bp, 100, 'require', 1), { 'decision' => 'deny', 'code' => 'store_unreachable' }, "bp check min_epoch #{label}")
    end
    true
  end

  t('e06 H15 break-glass: max_uses=1 used twice across two registries on one kv, the second is denied; layout; wrong holder; race') do
    next true unless E06.on?

    c30 = E06.c30
    pol = { 'authorities' => [c30.pk('auth')], 'reviewers' => [c30.pk('rev')] }
    kv = AtlasPca::MemoryBreakGlassKv.new
    g = c30.sign_grant(c30.grant('max_uses' => 1))
    a = AtlasPca::BreakGlassRegistry.new(pol, kv)
    b = AtlasPca::BreakGlassRegistry.new(pol, kv)
    E06.same(a.accept(g, 1000), { 'ok' => true, 'replaced' => true }, 'accept')
    E06.same(b.accept(g, 1000), { 'ok' => true, 'replaced' => false }, 'the same grant on another registry')
    E06.same(a.use('g1', 'h1', 'd1', 1000, true), { 'decision' => 'allow', 'id' => 'g1', 'use' => 1, 'remaining' => 0, 'review_due' => 1500 }, 'first use')
    E06.same(b.use('g1', 'h1', 'd2', 1001, true), { 'decision' => 'deny', 'code' => 'budget_exhausted', 'id' => 'g1' }, 'second use on another registry')
    E06.same(kv.get('breakglass/meta'), { 'v' => 1, 'shards' => 16 }, 'meta')
    E06.same(kv.get('breakglass/16/1')['grants']['g1']['uses'], [{ 'n' => 1, 'action_digest' => 'd1', 'at' => 1000 }], 'stored use log (shard of h1)')
    E06.same(kv.get('breakglass/16/1')['grants']['g1']['review'], nil, 'no review stored')
    E06.same(b.uses('h1', 'g1'), [{ 'n' => 1, 'action_digest' => 'd1', 'at' => 1000 }], 'uses')
    b.uses('h1', 'g1')[0]['at'] = 5
    E06.same(b.uses('h1', 'g1')[0]['at'], 1000, 'uses is a copy')
    E06.same(b.uses('h1', 'zz'), [], 'uses of an unknown id')
    # h10 hashes to the same shard as h1: the grant is visible there but belongs to another holder
    E06.same(b.use('g1', 'h10', 'd', 1001, true), { 'decision' => 'deny', 'code' => 'wrong_holder', 'id' => 'g1' }, 'same shard, other holder')
    E06.same(b.use('g1', 'h2', 'd', 1001, true), { 'decision' => 'deny', 'code' => 'unknown_break_glass', 'id' => 'g1' }, 'another shard')
    rv = c30.sign_review(c30.review)
    E06.same(b.review(rv, 'h10', 1200), { 'ok' => false, 'code' => 'unknown_break_glass' }, 'review by another holder of the shard')
    E06.same(b.review(rv, 'h1', 1200), { 'ok' => true, 'replaced' => true }, 'review on another registry')
    E06.same(a.review(rv, 'h1', 1200), { 'ok' => true, 'replaced' => false }, 'the same review again')
    E06.same(a.frozen('h1', 1200), false, 'a justified review does not freeze')
    E06.same(kv.get('breakglass/16/1')['grants']['g1']['review'], rv, 'stored review')
    # a frozen holder shares a shard with others without freezing them
    bad = c30.sign_review(c30.review('outcome' => 'unjustified'))
    kv2 = AtlasPca::MemoryBreakGlassKv.new
    r2 = AtlasPca::BreakGlassRegistry.new(pol, kv2)
    r2.accept(g, 1000)
    r2.use('g1', 'h1', 'd1', 1000, true)
    r2.review(bad, 'h1', 1200)
    E06.same(r2.frozen('h1', 1200), true, 'unjustified freezes the holder')
    E06.same(r2.frozen('h10', 1200), false, 'not the other holder of the shard')
    E06.same(r2.accept(c30.sign_grant(c30.grant('id' => 'g9', 'holder' => 'h10')), 1200), { 'ok' => true, 'replaced' => true }, 'a new grant for the other holder')
    E06.same(r2.accept(c30.sign_grant(c30.grant('id' => 'g8')), 1200), { 'ok' => false, 'code' => 'holder_frozen' }, 'a new grant for the frozen holder')

    kv3 = AtlasPca::MemoryBreakGlassKv.new
    regs = [AtlasPca::BreakGlassRegistry.new(pol, kv3), AtlasPca::BreakGlassRegistry.new(pol, kv3)]
    regs[0].accept(g, 1000)
    rs = E06.threads(8) { |i| regs[i % 2].use('g1', 'h1', "d#{i}", 1000, true) }
    E06.same(rs.count { |x| x['decision'] == 'allow' }, 1, 'exactly one concurrent use allowed')
    E06.same(rs.reject { |x| x['decision'] == 'allow' }.map { |x| x['code'] }.uniq, ['budget_exhausted'], 'the others are over budget')
    true
  end

  t('e06 H15 blueprint: epoch 5 disabled, a NEW registry over the kv refuses the active epoch 4 replay (stale_epoch); layout; heal; fork race') do
    next true unless E06.on?

    c30 = E06.c30
    k1 = c30.pk('op1')
    kv = AtlasPca::MemoryBlueprintKv.new
    a = AtlasPca::BlueprintRegistry.new([k1], kv)
    r5 = c30.sign_bp(c30.bp('operator' => k1, 'epoch' => 5, 'status' => 'disabled'), 'op1')
    r4 = c30.sign_bp(c30.bp('operator' => k1, 'epoch' => 4), 'op1')
    E06.same(a.epoch, 0, 'empty')
    E06.same(a.accept(r5), { 'ok' => true, 'replaced' => true }, 'accept epoch 5')
    b = AtlasPca::BlueprintRegistry.new([k1], kv)
    E06.same(b.accept(r4), { 'ok' => false, 'code' => 'stale_epoch' }, 'replay of the active epoch 4 on a new registry')
    E06.same(b.epoch, 5, 'epoch')
    E06.same(b.get('K1'), r5, 'get')
    E06.same(b.get('nope'), nil, 'get of an unknown key')
    E06.same(kv.get('blueprint/rec/K1'), r5, 'stored record')
    E06.same(kv.get('blueprint/epoch'), { 'v' => 1, 'max' => 5 }, 'stored epoch')
    chain = [{ 'issuer' => 'root', 'holder' => 'K1' }, { 'issuer' => 'K1', 'holder' => 'leaf' }]
    E06.same(AtlasPca.check_blueprints(chain, b, 100, 'require'), { 'decision' => 'deny', 'code' => 'blueprint_disabled', 'blueprint' => 'bp1' }, 'disabled across registries')
    E06.same(AtlasPca.check_blueprints(chain, b, 100, 'require', 6), { 'decision' => 'escalate', 'code' => 'stale_blueprint_state', 'have' => 5, 'need' => 6 }, 'min_epoch 6')
    E06.same(AtlasPca.check_blueprints(chain, b, 100, 'require', 5), { 'decision' => 'deny', 'code' => 'blueprint_disabled', 'blueprint' => 'bp1' }, 'min_epoch 5')
    # the epoch is a maximum over keys, never lowered
    E06.same(b.accept(c30.sign_bp(c30.bp('operator' => k1, 'key' => 'K2', 'epoch' => 2), 'op1')), { 'ok' => true, 'replaced' => true }, 'another key, lower epoch')
    E06.same(b.epoch, 5, 'epoch stays at the maximum')
    r6 = c30.sign_bp(c30.bp('operator' => k1, 'epoch' => 6), 'op1')
    E06.same(b.accept(r6), { 'ok' => true, 'replaced' => true }, 'epoch 6')
    E06.same(b.epoch, 6, 'epoch 6')
    E06.same(b.get('K1'), r6, 'replaced')

    # a record written but the epoch not (a crash between the two): the identical record again heals the epoch
    kv2 = AtlasPca::MemoryBlueprintKv.new
    kv2.set('blueprint/rec/K1', r5)
    h = AtlasPca::BlueprintRegistry.new([k1], kv2)
    E06.same(h.epoch, 0, 'behind after the crash')
    E06.same(h.accept(r5), { 'ok' => true, 'replaced' => false }, 'replay')
    E06.same(h.epoch, 5, 'healed')

    kv3 = AtlasPca::MemoryBlueprintKv.new
    regs = [AtlasPca::BlueprintRegistry.new([k1], kv3), AtlasPca::BlueprintRegistry.new([k1], kv3)]
    recs = Array.new(8) { |i| c30.sign_bp(c30.bp('operator' => k1, 'epoch' => 1, 'issued_at' => i + 1), 'op1') }
    rs = E06.threads(8) { |i| regs[i % 2].accept(recs[i]) }
    E06.same(rs.count { |x| x['ok'] == true }, 1, 'exactly one record per key and epoch')
    E06.same(rs.reject { |x| x['ok'] == true }.map { |x| x['code'] }.uniq, ['epoch_fork'], 'the others are forks')
    true
  end

  # ------------------------------------------------------------------------------------------------------------------ F4
  t('e06 F4 blueprint admitted hook: no hook admission_required; false / non-true / raise not_admitted; true continues; only for pinned') do
    next true unless E06.on?

    c30 = E06.c30
    k1 = c30.pk('op1')
    chain = [{ 'issuer' => 'root', 'holder' => 'K1' }, { 'issuer' => 'K1', 'holder' => 'leaf' }]
    pinned = c30.sign_bp(c30.bp('operator' => k1, 'runtime_pins' => [{ 'model_id' => 'm' }]), 'op1')
    kv = AtlasPca::MemoryBlueprintKv.new
    reg = AtlasPca::BlueprintRegistry.new([k1], kv)
    E06.same(reg.accept(pinned), { 'ok' => true, 'replaced' => true }, 'accept pinned')
    deny = ->(code) { { 'decision' => 'deny', 'code' => code, 'blueprint' => 'bp1' } }
    check = ->(hook = nil) { AtlasPca.check_blueprints(chain, reg, 100, 'require', nil, admitted: hook) }
    E06.same(check.call, deny.call('admission_required'), 'no hook')
    E06.same(AtlasPca.check_blueprints(chain, reg, 100, 'require'), deny.call('admission_required'), 'no keyword')
    E06.same(AtlasPca.check_blueprints(chain, reg, 100, 'any'), deny.call('admission_required'), 'mode any')
    E06.same(check.call(->(_h, _r) { false }), deny.call('not_admitted'), 'false')
    [nil, 1, 'yes', :true, [true], 0].each { |v| E06.same(check.call(->(_h, _r) { v }), deny.call('not_admitted'), "truthy but not true: #{v.inspect}") }
    E06.same(check.call(->(_h, _r) { raise 'boom' }), deny.call('not_admitted'), 'raise')
    E06.same(check.call(->(_h, _r) { raise ArgumentError, 'x' }), deny.call('not_admitted'), 'raise ArgumentError')
    calls = []
    E06.same(check.call(->(h, r) { calls << [h, r] and true }), { 'decision' => 'allow', 'governed' => ['bp1'] }, 'true')
    E06.same(calls, [['leaf', pinned]], 'the hook gets the instance key and the stored record')
    # the hook is reached after status / expiry / depth and before the ceiling
    never = ->(_h, _r) { raise Exception, 'the hook must not run' } # rubocop:disable Lint/RaiseException
    kv.set('blueprint/rec/K1', pinned.merge('status' => 'disabled'))
    E06.same(check.call(never), deny.call('blueprint_disabled'), 'disabled before the hook')
    kv.set('blueprint/rec/K1', pinned.merge('expires_at' => 100))
    E06.same(check.call(never), deny.call('blueprint_expired'), 'expired before the hook')
    kv.set('blueprint/rec/K1', pinned.merge('max_depth' => 0))
    E06.same(check.call(never), deny.call('too_deep'), 'too deep before the hook')
    kv.set('blueprint/rec/K1', pinned.merge('ceiling' => [{ 'type' => 'x' }]))
    E06.same(check.call(->(_h, _r) { true }), deny.call('ceiling_unevaluable'), 'true then the ceiling')
    E06.same(check.call(->(_h, _r) { false }), deny.call('not_admitted'), 'false before the ceiling')
    # an unpinned blueprint never calls the hook
    kv2 = AtlasPca::MemoryBlueprintKv.new
    reg2 = AtlasPca::BlueprintRegistry.new([k1], kv2)
    reg2.accept(c30.sign_bp(c30.bp('operator' => k1), 'op1'))
    E06.same(AtlasPca.check_blueprints(chain, reg2, 100, 'require', nil, admitted: never), { 'decision' => 'allow', 'governed' => ['bp1'] }, 'unpinned')
    true
  end

  # ------------------------------------------------------------------------------------------------------------------ F5
  t('e06 F5 lease revocation pruning: only with maxTtlCeiling, injected clock, boundary kept, revoke prunes too') do
    next true unless E06.on?

    lz = E06.lz
    now = 0
    clock = -> { now }
    kv = AtlasPca::MemoryLeaseKv.new
    reg = AtlasPca::LeaseRegistry.new({ 'authorities' => [lz.pub], 'maxTtlCeiling' => 1000 }, kv, shards: 1, clock: clock)
    ok1 = { 'ok' => true, 'replaced' => true, 'seq' => 1 }
    E06.same(reg.accept(lz.signed('max_ttl' => 1000)), ok1, 'issue')
    rv = lz.rsigned('target' => 'prefix', 'value' => 'db', 'revoked_at' => 0)
    E06.same(reg.revoke(rv), { 'ok' => true, 'revoked' => 0 }, 'revoke at t=0 (issued after it: covers nothing)')
    E06.same(reg.revocations, [rv], 'kept at t=0')
    now = 1000
    E06.same(reg.accept(lz.signed('lease_id' => 'L2', 'grant_ref' => 'g2', 'path' => 'other/x', 'max_ttl' => 1000)), ok1, 'accept at t=1000')
    E06.same(reg.revocations, [rv], 'revoked_at + ceiling == now is kept')
    now = 1001
    E06.same(reg.accept(lz.signed('lease_id' => 'L3', 'grant_ref' => 'g3', 'path' => 'other/y', 'max_ttl' => 1000)), ok1, 'accept at t=1001')
    E06.same(reg.revocations, [], 'past the ceiling: pruned')
    # a revocation is pruned by revoke too: kept exactly at the boundary, dropped one past it
    now = 5000
    r4000 = lz.rsigned('target' => 'grant', 'value' => 'g7', 'revoked_at' => 4000)
    E06.same(reg.revoke(r4000), { 'ok' => true, 'revoked' => 0 }, 'revoke 4000')
    E06.same(reg.revocations, [r4000], '4000 + 1000 >= 5000 kept')
    E06.same(reg.revoke(lz.rsigned('target' => 'grant', 'value' => 'g8', 'revoked_at' => 3999)), { 'ok' => true, 'revoked' => 0 }, 'revoke 3999')
    E06.same(reg.revocations, [r4000], '3999 + 1000 < 5000 dropped at once')

    # no ceiling: nothing is ever pruned
    reg2 = AtlasPca::LeaseRegistry.new({ 'authorities' => [lz.pub] }, AtlasPca::MemoryLeaseKv.new, shards: 1, clock: -> { 10**12 })
    reg2.revoke(rv)
    E06.same(reg2.revocations, [rv], 'no ceiling: kept after revoke')
    reg2.accept(lz.signed)
    E06.same(reg2.revocations, [rv], 'no ceiling: kept after accept')

    # the default clock is the wall clock in ms
    wall = (Time.now.to_f * 1000).to_i
    reg3 = AtlasPca::LeaseRegistry.new({ 'authorities' => [lz.pub], 'maxTtlCeiling' => 1000 }, AtlasPca::MemoryLeaseKv.new, shards: 1)
    reg3.revoke(lz.rsigned('target' => 'grant', 'value' => 'old', 'revoked_at' => wall - 5000))
    E06.same(reg3.revocations, [], 'a revocation older than the ceiling is pruned by the default clock')
    future = lz.rsigned('target' => 'grant', 'value' => 'far', 'revoked_at' => 4_000_000_000_000_000)
    reg3.revoke(future)
    E06.same(reg3.revocations, [future], 'a revocation inside the ceiling is kept by the default clock')
    true
  end

  # ------------------------------------------------------------------------------------------------------------------ F11
  t('e06 F11 kits pass a correct kv: exact statuses (durability skipped when declared non-durable, run when durable)') do
    next true unless E06.on?

    kv = AtlasPca::MemoryAtomicKv.new
    open = -> { kv }
    lease = %w[lease-semantics lease-copies lease-accept-race lease-renewal-race lease-revocation-across-registries lease-revocation-durability]
    glass = %w[break-glass-budget-across-registries break-glass-use-race break-glass-freeze-durability]
    bp = %w[blueprint-epoch-across-registries blueprint-fork-race blueprint-durability]
    kits = [[:run_lease_registry_conformance, 'lease registry', lease], [:run_break_glass_registry_conformance, 'break-glass registry', glass],
            [:run_blueprint_registry_conformance, 'blueprint registry', bp]]
    kits.each do |m, name, tests|
      r = AtlasPca.public_send(m, open, durable: false)
      E06.same(r.name, name, "#{m} name")
      E06.same(r.ok?, true, "#{m} ok (non-durable)")
      want = tests.to_h { |x| [x, x.end_with?('durability') ? 'skip' : 'pass'] }
      E06.same(E06.statuses(r), want, "#{m} statuses non-durable")
      E06.same(r.results.find { |x| x.status == 'skip' }.note, 'the adapter declares durable: false (state dies with the process)', "#{m} skip note")
      r = AtlasPca.public_send(m, open, restart: -> {})
      E06.same(E06.statuses(r), tests.to_h { |x| [x, 'pass'] }, "#{m} statuses durable")
      E06.same(r.ok?, true, "#{m} ok (durable)")
    end
    torn = []
    AtlasPca.run_lease_registry_conformance(open, teardown: -> { torn << 1 })
    E06.same(torn, [1], 'teardown runs once')
    true
  end

  t('e06 F11 kits fail a kv that forgets on restart (amnesia) in the durability check only') do
    next true unless E06.on?

    box = [AtlasPca::MemoryAtomicKv.new]
    open = -> { box[0] }
    restart = -> { box[0] = AtlasPca::MemoryAtomicKv.new }
    { run_lease_registry_conformance: 'lease-revocation-durability', run_break_glass_registry_conformance: 'break-glass-freeze-durability',
      run_blueprint_registry_conformance: 'blueprint-durability' }.each do |m, dur|
      r = AtlasPca.public_send(m, open, restart: restart)
      E06.same(r.ok?, false, "#{m} not ok")
      E06.same(r.failures.map(&:test), [dur], "#{m} fails only #{dur}")
      E06.same(r.results.reject { |x| x.test == dur }.map(&:status).uniq, ['pass'], "#{m} the rest pass")
    end
    true
  end

  t('e06 F11 kits fail a kv whose update is not atomic (racing accept / renewal / use / fork) and a handle that is not a kv') do
    next true unless E06.on?

    racy = E06::RacyKv.new
    r = AtlasPca.run_lease_registry_conformance(-> { racy }, durable: false)
    st = E06.statuses(r)
    E06.same(st['lease-accept-race'], 'fail', 'lease accept race')
    E06.same(st['lease-renewal-race'], 'fail', 'lease renewal race')
    E06.same(st['lease-semantics'], 'pass', 'lease semantics')
    racy = E06::RacyKv.new
    st = E06.statuses(AtlasPca.run_break_glass_registry_conformance(-> { racy }, durable: false))
    E06.same(st['break-glass-use-race'], 'fail', 'break-glass use race')
    E06.same(st['break-glass-budget-across-registries'], 'pass', 'break-glass budget')
    racy = E06::RacyKv.new
    st = E06.statuses(AtlasPca.run_blueprint_registry_conformance(-> { racy }, durable: false))
    E06.same(st['blueprint-fork-race'], 'fail', 'blueprint fork race')
    E06.same(st['blueprint-epoch-across-registries'], 'pass', 'blueprint epoch')

    r = AtlasPca.run_lease_registry_conformance(-> { Object.new })
    E06.same(r.ok?, false, 'not a kv')
    E06.same(r.failures.length, 6, 'every check fails')
    E06.same(r.failures[0].note, 'the kv has no get()', 'the shape message')
    true
  end
end
