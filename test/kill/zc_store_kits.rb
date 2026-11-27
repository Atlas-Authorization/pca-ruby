# frozen_string_literal: true

# zc store kits: the lease / break-glass / blueprint registry conformance kits run against a conforming store (every result and note
# exact, handles opened and closed as the kit promises) and against stores that misbehave in one specific way each.
module MutationKill
  module ZCKit
    module_function

    SU = { 'ok' => false, 'code' => 'store_unreachable' }.freeze

    def meta?(key) = key.end_with?('/meta')

    # a kv that hands out the stored objects themselves (no copies)
    class RefBase
      def initialize = @m = {}
      def get(key) = @m[key]

      def update(key)
        nxt = yield(@m[key])
        @m[key] = nxt unless nxt.nil?
        @m[key]
      end
    end

    # faults: [{ h: handle number(s) | nil, op: :update | :get, nth: call number(s) on that handle | nil, mode: :drop | :forget | :nil | :call, fn: }]
    # :drop = an update that never runs its block; :forget = the block sees no previous value; :nil = a get answers nil; :call = a get answer is passed through fn.
    class Env
      attr_reader :opens, :closed, :restarts, :teardowns, :closed_at_restart

      def initialize(faults: [], ref: false, wipe: false, nil_get_after_restart: false, close_raises: [], gate: nil)
        @gate = gate
        @arrived = 0
        @gate_done = false
        @cv = ConditionVariable.new
        @faults = faults
        @ref = ref
        @wipe = wipe
        @nil_get = nil_get_after_restart
        @close_raises = close_raises
        @base = fresh
        @opens = 0
        @closed = []
        @restarts = 0
        @teardowns = 0
        @closed_at_restart = nil
        @after_restart = false
        @counts = Hash.new(0)
        @lock = Mutex.new
      end

      def base = @base
      def fresh = @ref ? RefBase.new : AtlasPca::MemoryAtomicKv.new
      def factory = -> { open_handle }
      def teardown = -> { @lock.synchronize { @teardowns += 1 } }

      # returns a truthy value on purpose: the kit must not treat it as a handle
      def restart
        lambda do
          @restarts += 1
          @closed_at_restart = @closed.uniq.sort
          @base = fresh if @wipe
          @after_restart = true if @nil_get
          @restarts
        end
      end

      def open_handle
        idx = @lock.synchronize { @opens += 1 }
        Handle.new(self, idx)
      end

      def tick(idx, op) = @lock.synchronize { @counts[[idx, op]] += 1 }

      # gate: { h:, nth:, digest:, expected: }. The update whose record carries `digest` goes first; the others wait for it (or, when
      # none of the `expected` racing updates carries it, for each other) so a refused first update cannot be reordered by the scheduler.
      def gated?(idx, nth) = !@gate.nil? && hit?(@gate[:h], idx) && @gate[:nth] == nth

      def priority?(blk)
        rec = blk.binding.local_variable_get(:rec)
        rec.is_a?(Hash) && rec['justification_digest'] == @gate[:digest]
      rescue StandardError
        false
      end

      def hold(first)
        @lock.synchronize do
          @arrived += 1
          @seen = true if first
          @cv.broadcast
          return if first

          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 3.0
          until @gate_done || (@arrived >= @gate[:expected] && !@seen)
            left = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            break if left <= 0

            @cv.wait(@lock, left)
          end
        end
      end

      def release
        @lock.synchronize do
          @gate_done = true
          @cv.broadcast
        end
      end
      def after_restart? = @after_restart

      def fault(idx, op, nth)
        @faults.find { |f| f[:op] == op && hit?(f[:h], idx) && hit?(f[:nth], nth) }
      end

      def hit?(spec, val) = spec.nil? || (spec.is_a?(Range) ? spec.include?(val) : spec == val)
      def note_closed(idx) = @lock.synchronize { @closed << idx }
      def close_raises?(idx) = @close_raises.include?(idx)
    end

    class Handle
      def initialize(env, idx)
        @env = env
        @idx = idx
      end

      def get(key)
        return @env.base.get(key) if ZCKit.meta?(key)

        n = @env.tick(@idx, :get)
        return nil if @env.after_restart?

        f = @env.fault(@idx, :get, n)
        v = @env.base.get(key)
        return v if f.nil?

        f[:mode] == :nil ? nil : f[:fn].call(v)
      end

      def update(key, &blk)
        return @env.base.update(key, &blk) if ZCKit.meta?(key)

        n = @env.tick(@idx, :update)
        return gated_update(n, key, &blk) if @env.gated?(@idx, n)

        f = @env.fault(@idx, :update, n)
        return nil if f && f[:mode] == :drop
        return @env.base.update(key) { |_prev| blk.call(nil) } if f && f[:mode] == :forget

        @env.base.update(key, &blk)
      end

      def gated_update(_n, key, &blk)
        first = @env.priority?(blk)
        @env.hold(first)
        @env.base.update(key, &blk)
      ensure
        @env.release if first
      end

      def close
        @env.note_closed(@idx)
        raise 'close failed' if @env.close_raises?(@idx)
      end
    end

    def kits = AtlasPca::StoreConformance::Kits
    def by(rep) = rep.results.to_h { |r| [r.test, [r.status, r.note]] }
    def stored(env, field) = env.base.instance_variable_get(:@m).values.select { |v| v.is_a?(Hash) && v[field].is_a?(Hash) }.flat_map { |v| v[field].to_a }

    def lease(env, with_hooks: true, **o)
      hooks = with_hooks ? { restart: env.restart, teardown: env.teardown } : {}
      AtlasPca.run_lease_registry_conformance(env.factory, **hooks, **o)
    end

    def bg(env, with_hooks: true, **o)
      hooks = with_hooks ? { restart: env.restart, teardown: env.teardown } : {}
      AtlasPca.run_break_glass_registry_conformance(env.factory, **hooks, **o)
    end

    def bp(env, with_hooks: true, **o)
      hooks = with_hooks ? { restart: env.restart, teardown: env.teardown } : {}
      AtlasPca.run_blueprint_registry_conformance(env.factory, **hooks, **o)
    end

    def drop(h, op, nth = nil) = { h: h, op: op, nth: nth, mode: :drop }
    def forget(h, nth = nil) = { h: h, op: :update, nth: nth, mode: :forget }
    def nil_get(h, nth = nil) = { h: h, op: :get, nth: nth, mode: :nil }
    def via(h, nth, &fn) = { h: h, op: :get, nth: nth, mode: :call, fn: fn }

    LEASE = %w[lease-semantics lease-copies lease-accept-race lease-renewal-race lease-revocation-across-registries lease-revocation-durability].freeze
    BG = %w[break-glass-budget-across-registries break-glass-use-race break-glass-freeze-durability].freeze
    BP = %w[blueprint-epoch-across-registries blueprint-fork-race blueprint-durability].freeze
    DURABLE_SKIP = 'the adapter declares durable: false (state dies with the process)'
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  t('zc kits: the signing helpers build exactly the documented signed records') do
    next true unless ZC.gate?('store_conformance.rb')

    k = ZCKit.kits
    key = k.signer
    pub = k.pub(key)
    plain = ->(rec) { rec.reject { |kk, _| kk == 'sig' } }
    ok = ->(f, rec) { AtlasPca.send(f, rec) ? true : false }
    lease = k.lease(key)
    rev = k.lease_revocation(key)
    grant = k.grant(key)
    review = k.review(key)
    bp = k.blueprint(key)
    ZC.eq('pub', pub, AtlasPca.b64e(key.raw_public_key)) && ZC.eq('two signers differ', k.pub(k.signer) == pub, false) &&
      ZC.eq('lease', plain.call(lease),
            { 'v' => 1, 'lease_id' => 'L', 'path' => 'conf/x', 'grant_ref' => 'g', 'holder' => 'agent', 'requester' => 'alice', 'approvers' => ['bob'],
              'justification_digest' => 'j1', 'seq' => 1, 'issued_at' => 1000, 'renewed_at' => 1000, 'expires_at' => 2000, 'max_ttl' => 5000, 'authority' => pub }) &&
      ZC.eq('lease verifies', ok.call(:verify_lease, lease), true) && ZC.eq('lease tampered', ok.call(:verify_lease, lease.merge('holder' => 'x')), false) &&
      ZC.eq('lease override', plain.call(k.lease(key, 'seq' => 2, 'lease_id' => 'Z'))['seq'], 2) &&
      ZC.eq('lease override verifies', ok.call(:verify_lease, k.lease(key, 'seq' => 2, 'renewed_at' => 1500, 'expires_at' => 3000)), true) &&
      ZC.eq('revocation', plain.call(rev), { 'v' => 1, 'target' => 'lease', 'value' => 'L', 'revoked_at' => 1500, 'authority' => pub }) &&
      ZC.eq('revocation verifies', ok.call(:verify_lease_revocation, rev), true) &&
      ZC.eq('revocation tampered', ok.call(:verify_lease_revocation, rev.merge('value' => 'M')), false) &&
      ZC.eq('grant', plain.call(grant),
            { 'v' => 1, 'id' => 'g', 'holder' => 'h', 'grant_ref' => 'gr', 'reason_digest' => 'rd', 'max_uses' => 1, 'issued_at' => 1000, 'expires_at' => 2000,
              'review_within' => 500, 'notify_to' => 'n@x', 'authority' => pub }) &&
      ZC.eq('grant verifies', ok.call(:verify_break_glass, grant), true) && ZC.eq('grant tampered', ok.call(:verify_break_glass, grant.merge('id' => 'x')), false) &&
      ZC.eq('review', plain.call(review), { 'v' => 1, 'id' => 'g', 'outcome' => 'unjustified', 'notes_digest' => 'nd', 'at' => 1100, 'reviewer' => pub }) &&
      ZC.eq('review verifies', ok.call(:verify_break_glass_review, review), true) &&
      ZC.eq('review tampered', ok.call(:verify_break_glass_review, review.merge('at' => 1101)), false) &&
      ZC.eq('blueprint', plain.call(bp), { 'v' => 1, 'id' => 'bp', 'key' => 'K', 'ceiling' => [], 'epoch' => 1, 'status' => 'active', 'issued_at' => 1, 'operator' => pub }) &&
      ZC.eq('blueprint verifies', ok.call(:verify_blueprint, bp), true) && ZC.eq('blueprint tampered', ok.call(:verify_blueprint, bp.merge('epoch' => 2)), false)
  end

  t('zc kits: expect, skip_unless and registry_kit helpers') do
    next true unless ZC.gate?('store_conformance.rb')

    sc = AtlasPca::StoreConformance
    failure = lambda do |&blk|
      blk.call
      nil
    rescue sc::Failure => e
      e.message
    end
    teardowns = 0
    out = nil
    seen = []
    kv_a = ZCKit::Env.new
    rep = sc.registry_kit('named', kv_a.factory, nil, -> { teardowns += 1 }) do |report, handle, run, reopen|
      seen << [report.name, run]
      handle.call
      handle.call
      out = reopen.call
    end
    ZC.eq('expect passes', sc.expect(1, 1, 'x'), nil) && ZC.eq('expect fails with both values inspected', failure.call { sc.expect('a', 'b', 'lab') }, 'lab: got "a", want "b"') &&
      ZC.eq('expect nil', failure.call { sc.expect(nil, 1, 'l') }, 'l: got nil, want 1') &&
      ZC.eq('skip_unless passes', sc.skip_unless(true, 'why'), nil) &&
      ZC.raises('skip_unless raises Skip', sc::Skip) { sc.skip_unless(false, 'why') } &&
      ZC.eq('report is returned', rep.class, AtlasPca::ConformanceReport) && ZC.eq('name', seen[0][0], 'named') &&
      ZC.eq('run is twelve hex characters', seen[0][1].match?(/\A\h{12}\z/), true) && ZC.eq('handles opened by reopen', kv_a.opens, 3) &&
      ZC.eq('every handle closed at the end', kv_a.closed.uniq.sort, [1, 2, 3]) && ZC.eq('teardown ran', teardowns, 1) &&
      ZC.eq('reopen returned a handle', out.class, ZCKit::Handle) &&
      ZC.eq('a kv without update is refused', failure.call { sc.registry_kit('n', -> { Object.new.tap { |o| o.define_singleton_method(:get) { |_k| nil } } }, nil, nil) { |_r, h, _run, _re| h.call } },
            'the kv has no update()') &&
      ZC.eq('a kv without get is refused', failure.call { sc.registry_kit('n', -> { Object.new.tap { |o| o.define_singleton_method(:update) { |_k| nil } } }, nil, nil) { |_r, h, _run, _re| h.call } },
            'the kv has no get()')
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  t('zc kits lease: a conforming store passes every test; handles are opened, closed and restarted as promised') do
    next true unless ZC.gate?('store_conformance.rb')

    env = ZCKit::Env.new(close_raises: [14])
    rep = ZCKit.lease(env)
    want = ZCKit::LEASE.to_h { |n| [n, ['pass', n == 'lease-accept-race' ? '16 threads over 4 handles' : '']] }
    ids = ZCKit.stored(env, 'leases').map(&:first)
    ZC.eq('name', rep.name, 'lease registry') && ZC.eq('results', ZCKit.by(rep), want) && ZC.eq('ok', rep.ok?, true) &&
      ZC.eq('order', rep.results.map(&:test), ZCKit::LEASE) &&
      ZC.eq('handles opened', env.opens, 14) && ZC.eq('restarted once', env.restarts, 1) && ZC.eq('torn down once', env.teardowns, 1) &&
      ZC.eq('closed before the restart', env.closed_at_restart, (1..13).to_a) && ZC.eq('every handle closed, a raising close survived', env.closed.uniq.sort, (1..14).to_a) &&
      ZC.eq('lease ids', ids.map { |i| i.split(':')[0] }.sort, %w[copy dur race renew rev sem]) &&
      ZC.eq('lease id shape', ids.all? { |i| i.match?(/\A[a-z]+:\h{12}\z/) }, true) && ZC.eq('one run id', ids.map { |i| i.split(':')[1] }.uniq.length, 1)
  end

  t('zc kits lease: declared process-local and non-durable stores skip what they cannot do') do
    next true unless ZC.gate?('store_conformance.rb')

    e1 = ZCKit::Env.new
    r1 = ZCKit.lease(e1, shared: false)
    e2 = ZCKit::Env.new
    r2 = ZCKit.lease(e2, durable: false)
    e3 = ZCKit::Env.new
    r3 = ZCKit.lease(e3, with_hooks: false, threads: 4, handles: 2, name: 'mine')
    ZC.eq('shared false: one handle per race', ZCKit.by(r1)['lease-accept-race'], ['pass', '16 threads over 1 handles']) && ZC.eq('shared false ok', r1.ok?, true) &&
      ZC.eq('shared false: handles opened', e1.opens, 7) &&
      ZC.eq('durable false: skipped', ZCKit.by(r2)['lease-revocation-durability'], ['skip', ZCKit::DURABLE_SKIP]) && ZC.eq('durable false ok', r2.ok?, true) &&
      ZC.eq('durable false: handles opened', e2.opens, 12) && ZC.eq('durable false: no restart', e2.restarts, 0) &&
      ZC.eq('no hooks needed', r3.ok?, true) && ZC.eq('custom threads and handles', ZCKit.by(r3)['lease-accept-race'], ['pass', '4 threads over 2 handles']) &&
      ZC.eq('custom name', r3.name, 'mine') && ZC.eq('closed with no hooks', e3.closed.uniq.length, e3.opens)
  end

  t('zc kits lease: each failing store is reported by the check that catches it, with the exact message') do
    next true unless ZC.gate?('store_conformance.rb')

    d = ZCKit
    run = ->(faults, **o) { d.by(d.lease(d::Env.new(faults: faults, **o.slice(:ref, :wipe, :nil_get_after_restart, :gate)), threads: 4, handles: 4)) }
    su = d::SU.inspect
    sem = ->(faults) { run.call(faults)['lease-semantics'] }
    pre = lambda do |res, start|
      res[0] == 'fail' && res[1].start_with?(start) || raise("got #{res.inspect}, want a failure starting #{start.inspect}")
    end
    ZC.eq('issue', sem.call([d.drop(1, :update, 1)]), ['fail', "issue: got #{su}, want #{({ 'ok' => true, 'replaced' => true, 'seq' => 1 }).inspect}"]) &&
      ZC.eq('replay', sem.call([d.drop(1, :update, 2)]), ['fail', "replay: got #{su}, want #{({ 'ok' => true, 'replaced' => false, 'seq' => 1 }).inspect}"]) &&
      ZC.eq('fork', sem.call([d.drop(1, :update, 3)]), ['fail', "fork: got #{su}, want #{({ 'ok' => false, 'code' => 'lease_fork' }).inspect}"]) &&
      ZC.eq('renewal', sem.call([d.drop(1, :update, 4)]), ['fail', "renewal: got #{su}, want #{({ 'ok' => true, 'replaced' => true, 'seq' => 2 }).inspect}"]) &&
      ZC.eq('older record', sem.call([d.drop(1, :update, 5)]), ['fail', "older record: got #{su}, want #{({ 'ok' => false, 'code' => 'stale_seq' }).inspect}"]) &&
      pre.call(sem.call([d.nil_get(1, 1)]), 'the newest record: got nil, want {') &&
      ZC.eq('history', sem.call([d.nil_get(1, 2)]), ['fail', 'history: got [], want [1, 2]']) &&
      pre.call(sem.call([d.nil_get(1, 3)]), 'check of the newest: got {') && pre.call(sem.call([d.nil_get(1, 4)]), 'check of a superseded record: got {') &&
      sem.call([d.nil_get(1, 3)])[1].include?('unknown_lease') &&
      ZC.eq('copies', run.call([], ref: true)['lease-copies'], ['fail', 'get must return a copy, not the stored record: got "mallory", want "agent"']) &&
      ZC.eq('accept race, nothing stored', run.call([d.drop(3..6, :update)])['lease-accept-race'], ['fail', "an identical record was refused: #{su}"]) &&
      ZC.eq('accept race, no memory', run.call([d.forget(3..6)])['lease-accept-race'],
            ['fail', "4 of 4 concurrent issues of one record reported 'replaced' (want exactly 1)"]) &&
      ZC.eq('renewal race, losers refused', run.call([d.drop(8..10, :update, 2)])['lease-renewal-race'],
            ['fail', "a losing renewal was not a lease_fork: #{[{ 'ok' => true, 'replaced' => true, 'seq' => 2 }, d::SU, d::SU, d::SU].inspect}"]) &&
      ZC.eq('revoke', run.call([d.drop(11, :update, 2)])['lease-revocation-across-registries'],
            ['fail', "revoke: got #{({ 'ok' => true, 'revoked' => 0 }).inspect}, want #{({ 'ok' => true, 'revoked' => 1 }).inspect}"]) &&
      ZC.eq('accept on another registry', run.call([d.drop(12, :update, 1)])['lease-revocation-across-registries'],
            ['fail', "a record presented to a new registry over the same kv: got #{su}, want #{({ 'ok' => false, 'code' => 'revoked' }).inspect}"]) &&
      pre.call(run.call([d.nil_get(12, 1)])['lease-revocation-across-registries'], 'check: got {') &&
      ZC.eq('revocation lost by a restart', run.call([], wipe: true)['lease-revocation-durability'],
            ['fail', "accept after a restart: got #{({ 'ok' => true, 'replaced' => true, 'seq' => 1 }).inspect}, want #{({ 'ok' => false, 'code' => 'revoked' }).inspect}"]) &&
      pre.call(run.call([], nil_get_after_restart: true)['lease-revocation-durability'], 'check after a restart: got {')
  end

  t('zc kits lease: the default thread and handle counts are 16 and 4') do
    next true unless ZC.gate?('store_conformance.rb')

    env = ZCKit::Env.new(faults: [ZCKit.forget(3..6)])
    rep = AtlasPca.run_lease_registry_conformance(env.factory)
    ZC.eq('16 racing issues', ZCKit.by(rep)['lease-accept-race'], ['fail', "16 of 16 concurrent issues of one record reported 'replaced' (want exactly 1)"]) &&
      ZC.eq('4 handles, no hooks', env.opens, 14)
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  t('zc kits break-glass: a conforming store passes every test; handles are opened, closed and restarted as promised') do
    next true unless ZC.gate?('store_conformance.rb')

    env = ZCKit::Env.new(close_raises: [8])
    rep = ZCKit.bg(env)
    grants = ZCKit.stored(env, 'grants')
    ids = grants.map(&:first)
    holders = grants.map { |_, v| v['rec']['holder'] }
    ZC.eq('name', rep.name, 'break-glass registry') && ZC.eq('results', ZCKit.by(rep), ZCKit::BG.to_h { |n| [n, ['pass', '']] }) && ZC.eq('ok', rep.ok?, true) &&
      ZC.eq('handles opened', env.opens, 8) && ZC.eq('restarted once', env.restarts, 1) && ZC.eq('torn down once', env.teardowns, 1) &&
      ZC.eq('closed before the restart', env.closed_at_restart, (1..7).to_a) && ZC.eq('every handle closed', env.closed.uniq.sort, (1..8).to_a) &&
      ZC.eq('grant ids', ids.sort.map { |i| i.split(':')[1] }, %w[bud frz race]) && ZC.eq('grant id shape', ids.all? { |i| i.match?(/\Ag:[a-z]+:\h{12}\z/) }, true) &&
      ZC.eq('holders', holders.sort.map { |h| h.split(':')[1] }, %w[bud frz race]) && ZC.eq('holder shape', holders.all? { |h| h.match?(/\Ah:[a-z]+:\h{12}\z/) }, true)
  end

  t('zc kits break-glass: process-local and non-durable declarations, and a store with no hooks') do
    next true unless ZC.gate?('store_conformance.rb')

    e1 = ZCKit::Env.new
    r1 = ZCKit.bg(e1, shared: false)
    e2 = ZCKit::Env.new
    r2 = ZCKit.bg(e2, durable: false)
    e3 = ZCKit::Env.new
    r3 = ZCKit.bg(e3, with_hooks: false, name: 'mine')
    ZC.eq('shared false ok', ZCKit.by(r1).values.map(&:first), %w[pass pass pass]) && ZC.eq('shared false: handles opened', e1.opens, 4) &&
      ZC.eq('durable false: skipped', ZCKit.by(r2)['break-glass-freeze-durability'], ['skip', ZCKit::DURABLE_SKIP]) && ZC.eq('durable false: handles opened', e2.opens, 6) &&
      ZC.eq('no hooks needed', r3.ok?, true) && ZC.eq('custom name', r3.name, 'mine') && ZC.eq('default handles', e3.opens, 8)
  end

  t('zc kits break-glass: each failing store is reported by the check that catches it, with the exact message') do
    next true unless ZC.gate?('store_conformance.rb')

    d = ZCKit
    run = ->(faults, **o) { d.by(d.bg(d::Env.new(faults: faults, **o.slice(:ref, :wipe, :nil_get_after_restart, :gate)), threads: 4, handles: 4)) }
    su = d::SU.inspect
    pre = lambda do |res, start|
      res[0] == 'fail' && res[1].start_with?(start) || raise("got #{res.inspect}, want a failure starting #{start.inspect}")
    end
    bud = 'break-glass-budget-across-registries'
    race = 'break-glass-use-race'
    frz = 'break-glass-freeze-durability'
    ZC.eq('accept', run.call([d.drop(1, :update, 1)])[bud], ['fail', "accept: got #{su}, want #{({ 'ok' => true, 'replaced' => true }).inspect}"]) &&
      pre.call(run.call([d.drop(1, :update, 2)])[bud], 'first use: got {') && pre.call(run.call([d.drop(2, :update, 1)])[bud], 'second use on another registry: got {') &&
      run.call([d.drop(2, :update, 1)])[bud][1].include?('store_unreachable') &&
      ZC.eq('use log', run.call([d.nil_get(3, 1)])[race], ['fail', 'the numbered use log: got [], want [1, 2, 3]']) &&
      ZC.eq('no memory', run.call([d.forget(3..6)])[race], ['fail', '0 of 4 concurrent uses of a 3-use grant were allowed (want exactly 3)']) &&
      pre.call(run.call([d.drop(6, :update, 1)])[race], 'a refused use was not budget_exhausted: [') &&
      ZC.eq('review', run.call([d.drop(7, :update, 3)])[frz], ['fail', "review: got #{su}, want #{({ 'ok' => true, 'replaced' => true }).inspect}"]) &&
      ZC.eq('freeze lost by a restart', run.call([], wipe: true)[frz], ['fail', 'frozen after a restart: got false, want true']) &&
      ZC.eq('frozen holder accepts a new grant', run.call([d.forget(8, 1)])[frz],
            ['fail', "a new grant for a frozen holder after a restart: got #{({ 'ok' => true, 'replaced' => true }).inspect}, want #{({ 'ok' => false, 'code' => 'holder_frozen' }).inspect}"]) &&
      ZC.eq('default thread count', d.by(d.bg(d::Env.new(faults: [d.forget(3..6)])))[race], ['fail', '0 of 16 concurrent uses of a 3-use grant were allowed (want exactly 3)'])
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  t('zc kits blueprint: a conforming store passes every test; handles are opened, closed and restarted as promised') do
    next true unless ZC.gate?('store_conformance.rb')

    env = ZCKit::Env.new(close_raises: [8])
    rep = ZCKit.bp(env)
    keys = env.base.instance_variable_get(:@m).keys.select { |k| k.start_with?('blueprint/rec/') }.map { |k| k.delete_prefix('blueprint/rec/') }
    ZC.eq('name', rep.name, 'blueprint registry') && ZC.eq('results', ZCKit.by(rep), ZCKit::BP.to_h { |n| [n, ['pass', '']] }) && ZC.eq('ok', rep.ok?, true) &&
      ZC.eq('handles opened', env.opens, 8) && ZC.eq('restarted once', env.restarts, 1) && ZC.eq('torn down once', env.teardowns, 1) &&
      ZC.eq('closed before the restart', env.closed_at_restart, (1..7).to_a) && ZC.eq('every handle closed', env.closed.uniq.sort, (1..8).to_a) &&
      ZC.eq('keys', keys.sort.map { |k| k.split(':')[1] }, %w[dur ep fork]) && ZC.eq('key shape', keys.all? { |k| k.match?(/\AK:[a-z]+:\h{12}\z/) }, true)
  end

  t('zc kits blueprint: process-local and non-durable declarations, and a store with no hooks') do
    next true unless ZC.gate?('store_conformance.rb')

    e1 = ZCKit::Env.new
    r1 = ZCKit.bp(e1, shared: false)
    e2 = ZCKit::Env.new
    r2 = ZCKit.bp(e2, durable: false)
    e3 = ZCKit::Env.new
    r3 = ZCKit.bp(e3, with_hooks: false, name: 'mine')
    ZC.eq('shared false ok', ZCKit.by(r1).values.map(&:first), %w[pass pass pass]) && ZC.eq('shared false: handles opened', e1.opens, 4) &&
      ZC.eq('durable false: skipped', ZCKit.by(r2)['blueprint-durability'], ['skip', ZCKit::DURABLE_SKIP]) && ZC.eq('durable false: handles opened', e2.opens, 6) &&
      ZC.eq('no hooks needed', r3.ok?, true) && ZC.eq('custom name', r3.name, 'mine') && ZC.eq('default handles', e3.opens, 8)
  end

  t('zc kits blueprint: each failing store is reported by the check that catches it, with the exact message') do
    next true unless ZC.gate?('store_conformance.rb')

    d = ZCKit
    run = ->(faults, **o) { d.by(d.bp(d::Env.new(faults: faults, **o.slice(:ref, :wipe, :nil_get_after_restart, :gate)), threads: 4, handles: 4)) }
    su = d::SU.inspect
    ep = 'blueprint-epoch-across-registries'
    fork = 'blueprint-fork-race'
    dur = 'blueprint-durability'
    active = ->(v) { v.merge('status' => 'active') }
    ZC.eq('accept epoch 5', run.call([d.drop(1, :update, 1)])[ep], ['fail', "accept epoch 5: got #{su}, want #{({ 'ok' => true, 'replaced' => true }).inspect}"]) &&
      ZC.eq('older epoch', run.call([d.drop(2, :update, 1)])[ep], ['fail', "an older epoch on another registry: got #{su}, want #{({ 'ok' => false, 'code' => 'stale_epoch' }).inspect}"]) &&
      ZC.eq('stored record', run.call([d.via(2, 1, &active)])[ep], ['fail', 'the stored record: got "active", want "disabled"']) &&
      ZC.eq('epoch below the accepted one', run.call([d.via(2, 2..3) { |_v| { 'v' => 1, 'max' => 4 } }])[ep], ['fail', 'epoch() is 4, want at least 5']) &&
      ZC.eq('epoch missing', run.call([d.nil_get(2, 2..3)])[ep], ['fail', 'epoch() is 0, want at least 5']) &&
      ZC.eq('copies', run.call([], ref: true)[ep], ['fail', 'get must return a copy, not the stored record: got "active", want "disabled"']) &&
      ZC.eq('no memory', run.call([d.forget(3..6)])[fork], ['fail', '4 of 4 concurrent records for one key and epoch were accepted (want exactly 1)']) &&
      ZC.eq('losers refused', run.call([d.drop(4..6, :update)])[fork],
            ['fail', "a losing record was not an epoch_fork: #{[{ 'ok' => true, 'replaced' => true }, d::SU, d::SU, d::SU].inspect}"]) &&
      ZC.eq('stored record after a restart', run.call([d.via(8, 1, &active)])[dur], ['fail', 'the disabled record after a restart: got "active", want "disabled"']) &&
      ZC.eq('epoch after a restart', run.call([d.via(8, 2..3) { |_v| { 'v' => 1, 'max' => 2 } }])[dur], ['fail', 'epoch() is 2 after a restart, want at least 3']) &&
      ZC.eq('epoch missing after a restart', run.call([d.nil_get(8, 2..3)])[dur], ['fail', 'epoch() is 0 after a restart, want at least 3']) &&
      ZC.eq('older epoch replayed after a restart', run.call([d.forget(8, 1)])[dur],
            ['fail', "a replay of an older epoch after a restart: got #{({ 'ok' => true, 'replaced' => true }).inspect}, want #{({ 'ok' => false, 'code' => 'stale_epoch' }).inspect}"]) &&
      ZC.eq('state lost by a restart', run.call([], wipe: true)[dur][0], 'fail') &&
      ZC.eq('default thread count', d.by(d.bp(d::Env.new(faults: [d.forget(3..6)])))[fork], ['fail', '16 of 16 concurrent records for one key and epoch were accepted (want exactly 1)'])
  end

  t('zc kits: a racing renewal is judged in the order the scheduler gives it, so a first-served duplicate digest is caught') do
    next true unless ZC.gate?('store_conformance.rb')

    env = ZCKit::Env.new(gate: { h: 7..10, nth: 2, digest: 'j1', expected: 4 })
    rep = ZCKit.lease(env, threads: 4, handles: 4)
    ZC.eq('results', ZCKit.by(rep)['lease-renewal-race'], ['pass', '']) && ZC.eq('ok', rep.ok?, true)
  end

  t('zc kits: a store with no handles for the race reports the raised errors, not a shape error') do
    next true unless ZC.gate?('store_conformance.rb')

    raised = 'concurrent calls raised: #<ZeroDivisionError: divided by 0>'
    lease = ZCKit.by(ZCKit.lease(ZCKit::Env.new, threads: 4, handles: 0))
    bp = ZCKit.by(ZCKit.bp(ZCKit::Env.new, threads: 4, handles: 0))
    ZC.eq('lease accept race', lease['lease-accept-race'], ['fail', "4 of 4 #{raised}"]) && ZC.eq('lease renewal race', lease['lease-renewal-race'], ['fail', "4 of 4 #{raised}"]) &&
      ZC.eq('blueprint fork race', bp['blueprint-fork-race'], ['fail', "4 of 4 #{raised}"])
  end
end
