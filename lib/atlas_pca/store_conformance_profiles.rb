# frozen_string_literal: true

# Conformance profiles for the stores behind the operational plane (port of the TypeScript reference, @atlasauth/pca-store-conformance):
# guardian lease stores, transparency-log ledger stores, aggregate budget ledgers, bond-settlement stores and mesh-witness state stores.
# Each profile is a list of checks, each one a single claim driven against YOUR store through an adapter; a check that fails raises
# with the exact mismatch and the run reports it.
#
# An adapter is a ProfileAdapter (name, create and an optional durable flag, default true: declare false ONLY for an in-process
# store; the durability checks are then skipped and reported). create.call returns a fresh, empty, isolated backend as a StoreHandle:
# store (the client), reopen (a callable: another client on the SAME backend; after a restart this is how state is read back),
# optionally crash (kill the backend abruptly, then return a client on whatever survived) and close. Store methods are the
# reference's, snake_cased (cas, read, now; append, size, checkpoint_count, append_checkpoint; reserve, snapshot, commit, release,
# start, expire, durable; read, deposit, commit); records and plans are String-keyed Hashes with the reference's member names.
# Concurrency is real threads.
#
# Not included: the reference's own in-memory / durable-file / defective reference adapters of these profiles (they wrap the
# TypeScript store implementations).
require_relative 'store_conformance_runner'

module AtlasPca
  module StoreConformanceProfiles
    class AssertionFailed < StandardError; end

    MAX_SAFE = (2**53) - 1

    StoreHandle = Struct.new(:store, :reopen, :crash, :close, :adapter_durable)
    ProfileAdapter = Struct.new(:name, :create, :durable)
    Check = Struct.new(:name, :claim, :run, :needs)

    module_function

    # ---- assertions ----------------------------------------------------------------------------------------------------

    # Strict deep equality: a boolean is not a number, objects compare by key set, 1 and 1.0 are one number.
    def same?(a, b)
      if a == true || a == false || b == true || b == false
        (a == true || a == false) && (b == true || b == false) && a == b
      elsif a.is_a?(Numeric) && b.is_a?(Numeric)
        a == b || (a.is_a?(Float) && b.is_a?(Float) && a.nan? && b.nan?)
      elsif a.is_a?(Array) && b.is_a?(Array)
        a.length == b.length && a.zip(b).all? { |x, y| same?(x, y) }
      elsif a.is_a?(Hash) && b.is_a?(Hash)
        a.length == b.length && a.all? { |k, v| b.key?(k) && same?(v, b[k]) }
      else
        a == b
      end
    end

    def eq(got, want, msg = '')
      raise AssertionFailed, "#{msg.empty? ? '' : "#{msg}: "}expected #{want.inspect}, got #{got.inspect}" unless same?(got, want)
    end

    def ok(cond, msg = '')
      raise AssertionFailed, (msg.empty? ? 'assertion failed' : msg) unless cond
    end

    def rejects
      yield
    rescue StandardError
      nil
    else
      raise AssertionFailed, 'expected an error, none was raised'
    end

    # Run every callable at once in its own thread; an exception is re-raised after all have finished.
    def race(fns)
      out = StoreConformanceRunner.parallel(fns)
      out.each { |r| raise r if r.is_a?(Exception) }
      out
    end

    # Start fn without waiting for it; whatever it raises is dropped (an operation in flight at a crash).
    def background(&fn)
      Thread.new do
        fn.call
      rescue Exception # rubocop:disable Lint/RescueException
        nil
      end.tap { |t| t.report_on_exception = false }
    end

    # ---- guardian lease stores -----------------------------------------------------------------------------------------
    # A lease store is read -> record | nil, now -> epoch ms and cas(expected | nil, next) -> bool (replace iff the stored record
    # equals expected, atomically; next epoch never below the stored one).

    DEFAULT_LEASE_SKEW_MS = 1_000
    MAX_LEASE_TTL_MS = 3_600_000
    MAX_HOLDER_LEN = 256

    def int?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite? && x == x.floor)
    def num?(x) = (x.is_a?(Integer) || x.is_a?(Float)) && !(x.is_a?(Float) && x.nan?)
    def finite_num?(x) = num?(x) && !(x.is_a?(Float) && x.infinite?)

    def valid_record?(r)
      r.is_a?(Hash) && r['holder'].is_a?(String) && int?(r['epoch']) && r['epoch'].abs <= MAX_SAFE && r['epoch'] >= 1 &&
        finite_num?(r['expiresAt']) && r['expiresAt'] >= 0
    end

    def lease_opts(holder, o)
      return nil if !holder.is_a?(String) || holder.empty? || holder.length > MAX_HOLDER_LEN

      o = {} unless o.is_a?(Hash)
      skew = o['skewMs'].nil? ? DEFAULT_LEASE_SKEW_MS : o['skewMs']
      ttl = o['ttlMs']
      return nil if !int?(ttl) || ttl < 2 || ttl > MAX_LEASE_TTL_MS
      return nil if !finite_num?(skew) || skew.negative? || skew >= ttl

      [ttl, skew]
    end

    def snapshot(store)
      cur = store.read
      now = store.now
      raise 'corrupt lease state' if !finite_num?(now) || (!cur.nil? && !valid_record?(cur))

      [cur, now]
    end

    def fail_result(reason, extra = {}) = { 'ok' => false, 'reason' => reason }.merge(extra)

    # Take the lease if it is free (never held, released, or expired past the skew). The epoch increments on every takeover.
    def acquire_lease(store, holder, o)
      p = lease_opts(holder, o)
      return fail_result('invalid') unless p

      begin
        cur, now = snapshot(store)
        return fail_result('held') if !cur.nil? && cur['expiresAt'] + p[1] > now && cur['expiresAt'] != 0

        nxt = { 'holder' => holder, 'epoch' => (cur.nil? ? 0 : cur['epoch']) + 1, 'expiresAt' => now + p[0] }
        store.cas(cur, nxt) ? { 'ok' => true, 'lease' => nxt } : fail_result('lost-race')
      rescue StandardError => e
        fail_result('store-error', 'detail' => e.message.empty? ? 'unknown' : e.message)
      end
    end

    # Extend a lease the caller still holds; refused once the holder's own safe window has passed, or after any takeover.
    def renew_lease(store, lease, o)
      p = valid_record?(lease) ? lease_opts(lease['holder'], o) : nil
      return fail_result('invalid') unless p

      begin
        cur, now = snapshot(store)
        return fail_result('stale') if cur.nil? || cur['holder'] != lease['holder'] || cur['epoch'] != lease['epoch']
        return fail_result('expired') if cur['expiresAt'] - p[1] <= now

        nxt = { 'holder' => cur['holder'], 'epoch' => cur['epoch'], 'expiresAt' => now + p[0] }
        store.cas(cur, nxt) ? { 'ok' => true, 'lease' => nxt } : fail_result('lost-race')
      rescue StandardError => e
        fail_result('store-error', 'detail' => e.message.empty? ? 'unknown' : e.message)
      end
    end

    # Give the lease up early (expiresAt 0, epoch kept). Only the current holder at the current epoch can.
    def release_lease(store, lease)
      return fail_result('invalid') unless valid_record?(lease)

      begin
        cur, = snapshot(store)
        return fail_result('stale') if cur.nil? || cur['holder'] != lease['holder'] || cur['epoch'] != lease['epoch'] || cur['expiresAt'] == 0

        nxt = { 'holder' => cur['holder'], 'epoch' => cur['epoch'], 'expiresAt' => 0 }
        store.cas(cur, nxt) ? { 'ok' => true, 'lease' => nxt } : fail_result('lost-race')
      rescue StandardError => e
        fail_result('store-error', 'detail' => e.message.empty? ? 'unknown' : e.message)
      end
    end

    LO = { 'ttlMs' => 600_000, 'skewMs' => 1_000 }.freeze

    def won(s, who)
      r = acquire_lease(s, who, LO)
      ok(r['ok'], "acquire for #{who} failed: #{r['ok'] ? '' : r['reason']}")
      r['lease']
    end

    def lease_empty(h)
      eq(h.store.read, nil)
      ok(finite_num?(h.store.now))
    end

    def lease_first(h)
      l = won(h.store, 'a')
      eq(l['epoch'], 1)
      eq(h.store.read, l)
      ok(l['expiresAt'] > h.store.now)
    end

    def lease_wrong_expected(h)
      s = h.store
      eq(s.cas({ 'holder' => 'x', 'epoch' => 1, 'expiresAt' => 5 }, { 'holder' => 'y', 'epoch' => 2, 'expiresAt' => 9 }), false)
      eq(s.read, nil)
      l = won(s, 'a')
      eq(s.cas(nil, { 'holder' => 'y', 'epoch' => 2, 'expiresAt' => 9 }), false)
      eq(s.read, l)
    end

    def lease_race(h)
      clients = [h.store, h.reopen.call, h.reopen.call, h.reopen.call]
      fns = []
      clients.each_with_index do |c, i|
        fns << -> { acquire_lease(c, "h#{i}a", LO) }
        fns << -> { acquire_lease(c, "h#{i}b", LO) }
      end
      rs = race(fns)
      eq(rs.count { |r| r['ok'] }, 1)
      eq((h.store.read || {})['epoch'], 1)
    end

    def lease_takeover(h)
      a = won(h.store, 'a')
      ok(release_lease(h.store, a)['ok'])
      eq(won(h.store, 'b')['epoch'], 2)
    end

    def lease_epoch_down(h)
      s = h.store
      a = won(s, 'a')
      release_lease(s, a)
      b = won(s, 'b')
      accepted = begin
        s.cas(b, { 'holder' => 'z', 'epoch' => 1, 'expiresAt' => b['expiresAt'] })
      rescue StandardError
        false
      end
      eq(accepted, false)
      eq(s.read, b)
    end

    def lease_stale(h)
      s = h.store
      a = won(s, 'a')
      release_lease(s, a)
      b = won(s, 'b')
      eq(renew_lease(s, a, LO), { 'ok' => false, 'reason' => 'stale' })
      eq(release_lease(s, a), { 'ok' => false, 'reason' => 'stale' })
      eq(s.read, b)
    end

    def lease_reopen(h)
      l = won(h.store, 'a')
      eq(h.reopen.call.read, l)
    end

    def lease_crash(h)
      a = won(h.store, 'a')
      release_lease(h.store, a)
      back = h.crash.call
      eq((back.read || {})['epoch'], 1)
      eq(won(back, 'b')['epoch'], 2)
    end

    def chk(name, claim, needs = nil, &run) = Check.new(name, claim, run, needs)

    GUARDIAN_LEASE_CHECKS = [
      chk('empty-store-has-no-lease', 'a new store has no lease and a finite clock') { |h| lease_empty(h) },
      chk('first-acquire-is-epoch-1', 'the first holder gets epoch 1 and an expiry from the store clock') { |h| lease_first(h) },
      chk('wrong-expected-record-never-writes', 'cas with an expected record that is not the stored one returns false and changes nothing') { |h| lease_wrong_expected(h) },
      chk('racing-acquirers-have-one-winner', 'many contenders at once: exactly one acquires, at epoch 1') { |h| lease_race(h) },
      chk('takeover-after-release-bumps-the-epoch', 'a released lease is free at once and the next holder gets a strictly higher epoch') { |h| lease_takeover(h) },
      chk('epoch-never-goes-down', 'cas refuses a record with a lower epoch even when the expected record matches') { |h| lease_epoch_down(h) },
      chk('stale-holder-cannot-renew-or-release', 'after a takeover the old (holder, epoch) is refused as stale for renew and release') { |h| lease_stale(h) },
      chk('state-survives-reopen', 'an acknowledged lease is there when another client opens the same backend', 'durable') { |h| lease_reopen(h) },
      chk('acknowledged-lease-survives-a-crash', 'after an abrupt backend kill the lease and its epoch are still there, and the next epoch is higher', 'crash') { |h| lease_crash(h) }
    ].freeze

    # ---- ledger stores -------------------------------------------------------------------------------------------------

    def cm(i) = "commit-#{i}-#{'x' * 30}"

    def cp(size, root = nil, prev = '')
      { 'sth' => { 'instance_id' => 'i', 'principal' => 'p', 'size' => size, 'root' => root.nil? ? "root-#{size}" : root, 'prev_root' => prev,
                   'timestamp' => 1, 'guardian' => 'g', 'sig' => 's' } }
    end

    def range(a, b) = Array.new(b - a) { |i| cm(a + i) }
    def all(s) = s.read(0, s.size)

    # A writer that retries until its commit is in, the way a real client does.
    def append_retrying(s, commit)
      loop do
        size = s.size
        r = s.append(size, [commit])
        return size if %w[appended replayed].include?(r['outcome'])
      end
    end

    def led_empty(h)
      s = h.store
      eq(s.size, 0)
      eq(s.read(0, 0), [])
      eq(s.checkpoint_count, 0)
      eq(s.checkpoints(0), [])
    end

    def led_next_position(h)
      s = h.store
      eq(s.append(0, [cm(0)]), { 'outcome' => 'appended', 'size' => 1 })
      eq(s.append(1, [cm(1), cm(2)]), { 'outcome' => 'appended', 'size' => 3 })
      eq(s.read(0, 3), range(0, 3))
      eq(s.read(1, 3), range(1, 3))
      eq(s.read(3, 3), [])
    end

    def led_conflict(h)
      s = h.store
      s.append(0, range(0, 3))
      eq(s.append(5, [cm(9)]), { 'outcome' => 'conflict', 'size' => 3 })
      eq(s.append(2, [cm(9)]), { 'outcome' => 'conflict', 'size' => 3 })
      eq(all(s), range(0, 3))
    end

    def led_replay(h)
      s = h.store
      s.append(0, range(0, 3))
      eq(s.append(0, range(0, 3)), { 'outcome' => 'replayed', 'size' => 3 })
      eq(s.append(1, range(1, 3)), { 'outcome' => 'replayed', 'size' => 3 })
      eq(s.append(0, [cm(0), 'other']), { 'outcome' => 'conflict', 'size' => 3 })
      eq(s.append(2, [cm(2), cm(3)]), { 'outcome' => 'conflict', 'size' => 3 })
      eq(all(s), range(0, 3))
    end

    def led_invalid(h)
      s = h.store
      s.append(0, [cm(0)])
      [[], [''], [cm(1), 7], 'x'].each { |bad| rejects { s.append(1, bad) } }
      [-1, 1.5, Float::NAN].each { |bad| rejects { s.append(bad, [cm(1)]) } }
      eq(all(s), [cm(0)])
      [[-1, 1], [1, 0], [0, 2], [0.5, 1]].each { |f, t| rejects { s.read(f, t) } }
    end

    def led_exact(h)
      odd = ['a"b\\c', "gränt-\u{1F512}- -\u0001", 'x' * 5000, '__proto__', ' leading and trailing ']
      h.store.append(0, odd)
      eq(all(h.store), odd)
    end

    def led_race_one(h)
      clients = [h.store, h.reopen.call, h.reopen.call, h.reopen.call]
      r = race(Array.new(8) { |i| -> { clients[i % 4].append(0, [cm(100 + i)]) } })
      eq(r.count { |x| x['outcome'] == 'appended' }, 1)
      eq(r.count { |x| x['outcome'] == 'conflict' }, 7)
      log = all(h.store)
      eq(log.length, 1)
      ok(range(100, 108).include?(log[0]))
    end

    def led_race_retry(h)
      clients = [h.store, h.reopen.call, h.reopen.call]
      idx = race(Array.new(16) { |i| -> { append_retrying(clients[i % 3], cm(200 + i)) } })
      eq(idx.uniq.length, 16)
      eq(idx.sort, (0...16).to_a)
      log = all(h.store)
      eq(log.sort, range(200, 216).sort)
      idx.each_with_index { |p, i| eq(log[p], cm(200 + i)) }
    end

    def led_batch(h)
      s = h.store
      s.append(0, range(0, 2))
      eq(s.append(5, range(10, 14))['outcome'], 'conflict')
      eq(all(s), range(0, 2))
      eq(s.append(2, range(10, 14)), { 'outcome' => 'appended', 'size' => 6 })
      eq(all(s), range(0, 2) + range(10, 14))
    end

    def led_cp_count(h)
      s = h.store
      s.append(0, range(0, 6))
      eq(s.append_checkpoint(0, cp(2)), { 'outcome' => 'appended', 'count' => 1 })
      eq(s.append_checkpoint(0, cp(2)), { 'outcome' => 'replayed', 'count' => 1 })
      eq(s.append_checkpoint(0, cp(3))['outcome'], 'conflict')
      eq(s.append_checkpoint(2, cp(3))['outcome'], 'conflict')
      eq(s.append_checkpoint(1, cp(5, 'root-5', 'root-2')), { 'outcome' => 'appended', 'count' => 2 })
      eq(s.checkpoints(0).map { |c| c['sth']['size'] }, [2, 5])
      eq(s.checkpoints(1).map { |c| c['sth']['size'] }, [5])
      eq(s.checkpoint_count, 2)
    end

    def led_cp_inside(h)
      s = h.store
      s.append(0, range(0, 4))
      eq(s.append_checkpoint(0, cp(5))['outcome'], 'conflict')
      eq(s.append_checkpoint(0, cp(3))['outcome'], 'appended')
      eq(s.append_checkpoint(1, cp(2))['outcome'], 'conflict')
      eq(s.append_checkpoint(1, cp(3, 'other-root'))['outcome'], 'conflict')
      eq(s.append_checkpoint(1, cp(3))['outcome'], 'appended') # equal size, same root: allowed
      eq(s.append_checkpoint(2, nil)['outcome'], 'conflict')
      eq(s.checkpoint_count, 2)
    end

    def led_cp_race(h)
      h.store.append(0, range(0, 6))
      other = h.reopen.call
      r = race([-> { h.store.append_checkpoint(0, cp(2)) }, -> { other.append_checkpoint(0, cp(3)) },
                -> { h.store.append_checkpoint(0, cp(4)) }, -> { other.append_checkpoint(0, cp(5)) }])
      eq(r.count { |x| x['outcome'] == 'appended' }, 1)
      eq(h.store.checkpoint_count, 1)
    end

    def led_snapshots(h)
      s = h.store
      s.append(0, range(0, 3))
      s.append_checkpoint(0, cp(2))
      s.read(0, 3)[0] = 'mutated'
      c = s.checkpoints(0)
      c[0]['sth']['size'] = 99
      eq(all(s), range(0, 3))
      eq(s.checkpoints(0)[0]['sth']['size'], 2)
    end

    def led_reopen(h)
      h.store.append(0, range(0, 5))
      h.store.append_checkpoint(0, cp(3))
      h.store.append(5, range(5, 7))
      back = h.reopen.call
      eq(all(back), range(0, 7))
      eq(back.checkpoints(0), [cp(3)])
      eq(back.append(7, [cm(7)]), { 'outcome' => 'appended', 'size' => 8 })
    end

    def led_crash(h)
      h.store.append(0, range(0, 3))
      h.store.append_checkpoint(0, cp(2))
      background { h.store.append(3, range(3, 7)) }
      back = h.crash.call
      log = all(back)
      ok([3, 7].include?(log.length), "log has #{log.length} entries") # the batch of four is whole or absent
      eq(log, range(0, log.length))
      eq(back.checkpoints(0), [cp(2)])
      eq(back.append(3, range(3, 7)), { 'outcome' => log.length == 3 ? 'appended' : 'replayed', 'size' => 7 })
      eq(all(back), range(0, 7))
    end

    LEDGER_CHECKS = [
      chk('empty-store-is-empty', 'a new store has no entries and no checkpoints, and reads of the empty range succeed') { |h| led_empty(h) },
      chk('append-assigns-the-next-position', 'an append at the current length adds its commits in order at exactly those positions') { |h| led_next_position(h) },
      chk('append-at-another-position-conflicts-without-trace', 'an append whose expected length is not the current length conflicts, reports the real length, and writes nothing') { |h| led_conflict(h) },
      chk('append-retry-is-a-replay', 'repeating a batch already stored at that position is a replay (a prefix of it too); a different batch there conflicts') { |h| led_replay(h) },
      chk('invalid-input-is-refused', 'empty batches, empty or non-string commits and a bad expected length throw and write nothing') { |h| led_invalid(h) },
      chk('commit-strings-are-stored-exactly', 'unicode, quotes, separators and long commits come back byte for byte') { |h| led_exact(h) },
      chk('racing-appends-at-one-position-have-one-winner', 'clients appending at the same expected length: exactly one is appended, none is lost or duplicated, the log is the winner batch') { |h| led_race_one(h) },
      chk('racing-writers-with-retry-fill-every-position-once', 'sixteen writers each retrying until their commit is in: positions are unique, there are no holes, every commit is present exactly once') { |h| led_race_retry(h) },
      chk('a-batch-is-all-or-nothing', 'a batch that conflicts leaves none of its commits behind, and a batch that lands lands every commit') { |h| led_batch(h) },
      chk('checkpoints-append-by-count-and-replay', 'a checkpoint appends at the exact count; the same one again is a replay; another at that position conflicts') { |h| led_cp_count(h) },
      chk('checkpoints-stay-inside-the-log-and-never-go-back', 'a checkpoint beyond the end of the log, below the previous one, or equal in size with another root is refused') { |h| led_cp_inside(h) },
      chk('racing-checkpoints-have-one-winner', 'checkpoints racing for one position: exactly one lands') { |h| led_cp_race(h) },
      chk('reads-are-snapshots', 'mutating what a read returned cannot change the store') { |h| led_snapshots(h) },
      chk('state-survives-reopen', 'every acknowledged append and checkpoint is visible to a new client after the backend restarts', 'durable') { |h| led_reopen(h) },
      chk('acknowledged-writes-survive-a-crash', 'after an abrupt kill every acknowledged write is present and the log is a prefix of what was written: no holes, no partial batch', 'crash') { |h| led_crash(h) }
    ].freeze

    # ---- budget ledgers ------------------------------------------------------------------------------------------------

    CAP = 200
    KEY = 'principal/alice'
    KEY2 = 'principal/bob'

    def spend(over = {})
      { 'id' => 'spend', 'agg' => 'sum', 'val' => 'action.params.amount', 'sel' => { 'verbs' => ['pay'] }, 'win' => { 'kind' => 'task' }, 'key' => nil,
        'domain_max' => CAP, 'holder' => { 'kind' => 'site_local' }, 'scope' => 'principal' }.merge(over)
    end

    def ev(i, amount, t = 1000) = { 'id' => i, 'verb' => 'pay', 'resource' => 'r', 'params' => { 'amount' => amount }, 't' => t }
    def req(i, amount, extra = {}) = { 'event' => ev(i, amount), 'accumulators' => [spend] }.merge(extra)

    def reserved_total(l, key = KEY) = l.snapshot(key)['events'].reject { |e| e['status'] == 'released' }.sum { |e| e['params']['amount'] }

    def bud_empty(h) = eq(h.store.snapshot(KEY), { 'version' => 0, 'events' => [] })

    def bud_cap(h)
      l = h.store
      a = l.reserve(KEY, req('a', 150))
      eq(a['outcome'], 'reserved')
      eq(a['outcome'] == 'reserved' ? a['post'] : nil, { 'spend' => 150 })
      b = l.reserve(KEY, req('b', 51))
      eq(b['outcome'] == 'over_cap' ? [b['acc'], b['post'], b['cap']] : b, ['spend', 201, CAP])
      eq(l.reserve(KEY, req('c', 50))['outcome'], 'reserved')
      eq(reserved_total(l), CAP)
    end

    def bud_refusal(h)
      l = h.store
      l.reserve(KEY, req('a', 150))
      before = l.snapshot(KEY)
      eq(l.reserve(KEY, req('b', 60))['outcome'], 'over_cap')
      eq(l.snapshot(KEY), before)
    end

    def bud_replay(h)
      l = h.store
      first = l.reserve(KEY, req('a', 150))
      eq(l.reserve(KEY, req('a', 150)), { 'outcome' => 'replayed', 'version' => first['version'], 'status' => 'reserved' })
      eq(l.reserve(KEY, req('a', 10))['outcome'], 'id_conflict')
      eq(reserved_total(l), 150)
      eq(l.reserve(KEY, req('b', 50))['outcome'], 'reserved')
    end

    def bud_cas(h)
      l = h.store
      eq(l.reserve(KEY, req('a', 10, 'expectedVersion' => 0))['outcome'], 'reserved')
      eq(l.reserve(KEY, req('b', 10, 'expectedVersion' => 0)), { 'outcome' => 'conflict', 'version' => 1 })
      eq(l.snapshot(KEY)['events'].length, 1)
      eq(l.reserve(KEY, req('b', 10, 'expectedVersion' => 1))['outcome'], 'reserved')
      eq(l.reserve(KEY, req('a', 10, 'expectedVersion' => 0))['outcome'], 'replayed')
    end

    def bud_race_cap(h)
      clients = [h.store, h.reopen.call, h.reopen.call, h.reopen.call]
      rs = race(Array.new(40) { |i| -> { clients[i % 4].reserve(KEY, req("r#{i}", 30)) } })
      eq(rs.count { |r| r['outcome'] == 'reserved' }, 6)
      eq(rs.count { |r| r['outcome'] == 'over_cap' }, 34)
      eq(reserved_total(h.store), 180)
      eq(h.store.snapshot(KEY)['events'].map { |e| e['id'] }.uniq.length, 6)
    end

    def bud_race_version(h)
      clients = [h.store, h.reopen.call, h.reopen.call]
      rs = race(Array.new(9) { |i| -> { clients[i % 3].reserve(KEY, req("v#{i}", 1, 'expectedVersion' => 0)) } })
      eq(rs.count { |r| r['outcome'] == 'reserved' }, 1)
      eq(rs.count { |r| r['outcome'] == 'conflict' }, 8)
      eq(h.store.snapshot(KEY)['events'].length, 1)
    end

    def bud_race_retry(h)
      clients = [h.store, h.reopen.call, h.reopen.call]
      one = lambda do |c, i|
        loop do
          s = c.snapshot(KEY)
          r = c.reserve(KEY, req("w#{i}", 10, 'expectedVersion' => s['version']))
          return r['outcome'] if r['outcome'] != 'conflict'
        end
      end
      out = race(Array.new(20) { |i| -> { one.call(clients[i % 3], i) } })
      ok(out.all? { |o| o == 'reserved' }, out.join(','))
      eq(reserved_total(h.store), CAP)
      eq(h.store.reserve(KEY, req('extra', 1))['outcome'], 'over_cap')
    end

    def status_or_outcome(r) = r['outcome'] == 'refused' ? r['status'] : r['outcome']

    def bud_settle(h)
      l = h.store
      l.reserve(KEY, req('a', 10))
      l.reserve(KEY, req('b', 10))
      eq(l.commit(KEY, 'ghost')['outcome'], 'unknown')
      eq(l.release(KEY, 'ghost')['outcome'], 'unknown')
      eq(l.commit(KEY, 'a')['outcome'], 'settled')
      eq(l.commit(KEY, 'a')['outcome'], 'replayed')
      eq(status_or_outcome(l.release(KEY, 'a')), 'committed')
      eq(l.release(KEY, 'b')['outcome'], 'settled')
      eq(l.release(KEY, 'b')['outcome'], 'replayed')
      eq(status_or_outcome(l.commit(KEY, 'b')), 'released')
      eq(l.snapshot(KEY)['events'].map { |e| e['status'] }, %w[committed released])
    end

    def bud_release_frees(h)
      l = h.store
      l.reserve(KEY, req('a', 100))
      l.reserve(KEY, req('b', 100))
      eq(l.reserve(KEY, req('c', 1))['outcome'], 'over_cap')
      l.release(KEY, 'a')
      l.commit(KEY, 'b')
      eq(l.reserve(KEY, req('d', 100))['outcome'], 'reserved')
      eq(l.reserve(KEY, req('e', 1))['outcome'], 'over_cap')
    end

    def bud_release_unreserved(h)
      l = h.store
      eq(l.release(KEY, 'ghost')['outcome'], 'unknown')
      eq(l.reserve(KEY, req('a', 201))['outcome'], 'over_cap')
      eq(l.reserve(KEY, req('ghost', 200))['outcome'], 'reserved')
      eq(l.reserve(KEY, req('b', 1))['outcome'], 'over_cap')
    end

    def bud_late_commit(h)
      l = h.store
      l.reserve(KEY, req('a', 200))
      l.release(KEY, 'a')
      l.reserve(KEY, req('b', 200))
      eq(l.commit(KEY, 'a')['outcome'], 'refused')
      l.commit(KEY, 'b')
      eq(l.snapshot(KEY)['events'].count { |e| e['status'] == 'committed' }, 1)
    end

    def bud_expiry(h)
      l = h.store
      l.reserve(KEY, req('a', 40, 'expiresAt' => 500))
      l.reserve(KEY, req('b', 40, 'expiresAt' => 500))
      l.reserve(KEY, req('c', 40))
      l.reserve(KEY, req('d', 40, 'expiresAt' => 500))
      l.commit(KEY, 'b')
      l.start(KEY, 'd')
      eq(l.expire(KEY, 499)['released'], [])
      eq(l.expire(KEY, 500)['released'], ['a'])
      eq(l.expire(KEY, 10_000)['released'], [])
      eq(reserved_total(l), 120)
      eq(l.commit(KEY, 'a')['outcome'], 'refused')
      eq(l.start(KEY, 'a')['outcome'], 'refused')
    end

    def bud_start(h)
      l = h.store
      l.reserve(KEY, req('a', 10, 'expiresAt' => 5))
      l.reserve(KEY, req('b', 10))
      l.reserve(KEY, req('c', 10))
      v = l.snapshot(KEY)['version']
      eq(l.start(KEY, 'ghost')['outcome'], 'unknown')
      eq(l.snapshot(KEY)['version'], v)
      eq(l.start(KEY, 'a')['outcome'], 'settled')
      eq(l.start(KEY, 'a')['outcome'], 'replayed')
      eq(l.expire(KEY, 100)['released'], [])
      eq(l.commit(KEY, 'a')['outcome'], 'settled')
      eq(l.start(KEY, 'a')['outcome'], 'replayed')
      l.start(KEY, 'b')
      eq(l.release(KEY, 'b')['outcome'], 'settled')
      eq(status_or_outcome(l.start(KEY, 'b')), 'released')
      eq(l.snapshot(KEY)['events'].find { |e| e['id'] == 'c' }['started'], nil)
    end

    def bud_keys(h)
      l = h.store
      l.reserve(KEY, req('a', 200))
      eq(l.reserve(KEY2, req('a', 200))['outcome'], 'reserved')
      eq(l.reserve(KEY, req('b', 1))['outcome'], 'over_cap')
      eq(l.snapshot(KEY2)['events'].map { |e| e['id'] }, ['a'])
      eq(l.snapshot(KEY2)['version'], 1)
    end

    def bud_windows(h)
      l = h.store
      w = [spend('win' => { 'kind' => 'period', 'ms' => 1000, 't0' => 0 })]
      eq(l.reserve(KEY, { 'event' => ev('a', 200, 100), 'accumulators' => w })['outcome'], 'reserved')
      eq(l.reserve(KEY, { 'event' => ev('b', 1, 900), 'accumulators' => w })['outcome'], 'over_cap')
      eq(l.reserve(KEY, { 'event' => ev('c', 200, 1100), 'accumulators' => w })['outcome'], 'reserved')
    end

    def bud_evidence(h)
      l = h.store
      l.reserve(KEY, req('a', 10))
      mk = ->(i) { { 'v' => 1, 'key' => KEY, 'id' => i, 'reason' => 'effect_failed', 'at' => 5, 'signer' => 's', 'sig' => 'x' } }
      rejects { l.release(KEY, 'a', mk.call('other')) }
      eq(l.snapshot(KEY)['events'][0]['status'], 'reserved')
      eq(l.release(KEY, 'a', mk.call('a'))['outcome'], 'settled')
      eq(l.snapshot(KEY)['events'][0]['rel'], mk.call('a'))
    end

    def bud_invalid(h)
      l = h.store
      [ev('', 1), ev('x', 1).merge('t' => 0.5), ev('x', 1).merge('verb' => 7)].each do |bad|
        rejects { l.reserve(KEY, { 'event' => bad, 'accumulators' => [spend] }) }
      end
      rejects { l.reserve(KEY, req('x', 1, 'expectedVersion' => -1)) }
      no_max = spend
      no_max.delete('domain_max')
      rejects { l.reserve(KEY, { 'event' => ev('x', 1), 'accumulators' => [no_max] }) }
      eq(l.snapshot(KEY), { 'version' => 0, 'events' => [] })
    end

    def bud_copies(h)
      l = h.store
      l.reserve(KEY, req('a', 10))
      s = l.snapshot(KEY)
      s['events'][0]['status'] = 'released'
      eq(l.snapshot(KEY)['events'][0]['status'], 'reserved')
    end

    def bud_durable_claim(h)
      want = h.adapter_durable != false
      eq(h.store.durable, want, "ledger.durable=#{h.store.durable.inspect} but the adapter declares durable=#{want.inspect}")
    end

    def bud_reopen(h)
      l = h.store
      l.reserve(KEY, req('a', 150))
      l.reserve(KEY, req('b', 50))
      l.commit(KEY, 'a')
      l.release(KEY, 'b')
      back = h.reopen.call
      eq(back.snapshot(KEY)['events'].map { |e| [e['id'], e['status']] }, [%w[a committed], %w[b released]])
      eq(back.reserve(KEY, req('c', 51))['outcome'], 'over_cap')
      eq(back.reserve(KEY, req('c', 50))['outcome'], 'reserved')
    end

    def bud_crash(h)
      h.store.reserve(KEY, req('a', 200))
      background { h.store.reserve(KEY, req('b', 0)) }
      back = h.crash.call
      eq(back.reserve(KEY, req('c', 1))['outcome'], 'over_cap')
      eq(back.snapshot(KEY)['events'][0]['id'], 'a')
    end

    BUDGET_CHECKS = [
      chk('empty-key-is-empty', 'a key nobody reserved on has version 0 and no events') { |h| bud_empty(h) },
      chk('reservation-counts-at-once-and-cap-is-inclusive', 'a reservation counts as soon as it is made; one that would pass the cap is refused with the post-value, one that reaches it exactly is admitted') { |h| bud_cap(h) },
      chk('a-refusal-writes-nothing', 'an over-cap reservation leaves no event and does not move the version') { |h| bud_refusal(h) },
      chk('reserve-retry-is-a-replay', 'the same event again is a replay that changes nothing and does not count twice; another event under the same id conflicts') { |h| bud_replay(h) },
      chk('expected-version-is-compare-and-swap', 'a reservation naming a stale version conflicts and writes nothing; the current version succeeds; a replay wins over a stale version') { |h| bud_cas(h) },
      chk('racing-reserves-never-pass-the-cap', 'forty reservations of 30 racing from four clients against a cap of 200: exactly six land, the total is never above the cap, none is lost or counted twice') { |h| bud_race_cap(h) },
      chk('racing-reserves-at-one-version-have-one-winner', 'clients reserving with the same expected version: exactly one lands, the others conflict') { |h| bud_race_version(h) },
      chk('racing-writers-with-retry-fill-the-cap-exactly', 'twenty writers of 10 each retrying on conflict against a cap of 200: all twenty land, the twenty-first is refused') { |h| bud_race_retry(h) },
      chk('settle-rules', 'commit and release settle only a reservation, are idempotent, and refuse the opposite settlement; an unknown id changes nothing') { |h| bud_settle(h) },
      chk('release-frees-budget-and-commit-keeps-it', 'a released reservation no longer counts; a committed one still does; an open one keeps counting until settled') { |h| bud_release_frees(h) },
      chk('release-without-reserve-credits-nothing', 'releasing an id that was never reserved does not create headroom, now or after the id is reserved later') { |h| bud_release_unreserved(h) },
      chk('a-late-commit-cannot-overspend', 'after a reservation was released and its budget reused, committing it is refused, so the committed total never passes the cap') { |h| bud_late_commit(h) },
      chk('expiry-releases-only-open-reservations-past-their-deadline', 'expire frees a reservation at or after its deadline, never an earlier one, never a committed, started or deadline-less one, and a late commit or start of it is refused') { |h| bud_expiry(h) },
      chk('start-rules', 'start marks an open reservation non-expirable and is idempotent; an unknown id changes nothing; a started one can still be committed, or released (the effect did not happen); a released one cannot start') { |h| bud_start(h) },
      chk('keys-are-independent', 'two keys have their own caps, versions and events') { |h| bud_keys(h) },
      chk('windows-reset-the-count', 'a period window counts only the events of the period of the new event') { |h| bud_windows(h) },
      chk('release-evidence-is-stored-and-bound', 'evidence for the reservation is kept with the released event; evidence for another reservation is refused and the reservation stays open') { |h| bud_evidence(h) },
      chk('invalid-input-is-refused', 'a malformed event or request throws and writes nothing') { |h| bud_invalid(h) },
      chk('snapshots-are-copies', 'mutating what a snapshot returned cannot change the ledger') { |h| bud_copies(h) },
      chk('durable-claim-matches-the-adapter', 'a ledger says durable: true exactly when its adapter declares durability, so a volatile ledger can never satisfy the non-session refusal') { |h| bud_durable_claim(h) },
      chk('state-survives-reopen', 'every acknowledged reserve, commit and release is visible to a new client after the backend restarts, and the cap still holds', 'durable') { |h| bud_reopen(h) },
      chk('acknowledged-writes-survive-a-crash', 'after an abrupt kill every acknowledged reservation still counts, so a crash can only over-restrict, never reset a cap', 'crash') { |h| bud_crash(h) }
    ].freeze

    # ---- bond-settlement stores ----------------------------------------------------------------------------------------

    def rec(claim_id, action, amount, from, to, evidence_digest = '', split = nil)
      r = { 'claimId' => claim_id, 'action' => action, 'amount' => amount, 'from' => from, 'to' => to, 'at' => 1, 'evidenceDigest' => evidence_digest }
      r['split'] = split if Js.truthy?(split)
      r['sig'] = 'sig'
      r
    end

    def open_plan(i, dep, amount, caps = nil)
      caps ||= { 'maxOpenClaims' => 100, 'maxOpenAmount' => 1e9 }
      { 'claimId' => i, 'expect' => 'none', 'next' => 'open', 'open' => { 'amount' => amount, 'depositor' => dep }.merge(caps),
        'moves' => [{ 'account' => dep, 'op' => 'debit', 'amount' => amount }, { 'account' => 'escrow', 'op' => 'credit', 'amount' => amount }],
        'record' => rec(i, 'open', amount, dep, 'escrow') }
    end

    def release_plan(i, dep, amount)
      { 'claimId' => i, 'expect' => 'open', 'next' => 'released',
        'moves' => [{ 'account' => 'escrow', 'op' => 'debit', 'amount' => amount }, { 'account' => dep, 'op' => 'credit', 'amount' => amount }],
        'record' => rec(i, 'release', amount, 'escrow', dep) }
    end

    def slash_plan(i, amount, evidence = 'ev')
      { 'claimId' => i, 'expect' => 'open', 'next' => 'slashed',
        'moves' => [{ 'account' => 'escrow', 'op' => 'debit', 'amount' => amount }, { 'account' => 'chal', 'op' => 'credit', 'amount' => amount / 2.0 },
                    { 'account' => 'treasury', 'op' => 'credit', 'amount' => amount / 2.0 }],
        'record' => rec(i, 'slash', amount, 'escrow', 'treasury', evidence,
                        { 'amount' => amount, 'challengerReward' => amount / 2.0, 'victimCompensation' => 0, 'treasuryRemainder' => amount / 2.0,
                          'challengerAccount' => 'chal', 'victimAccount' => 'pool', 'treasuryAccount' => 'treasury' }) }
    end

    def bal(s, *accounts)
      accounts.map do |a|
        b = s.read({ 'claimId' => '', 'depositor' => a })['balances']
        b.length.positive? && !b[0][1].nil? ? b[0][1] : 0
      end
    end

    def bond_status(s, i)
      b = s.read({ 'claimId' => i })['bond']
      b ? b['status'] : 'none'
    end

    ACCOUNTS = %w[alice bob escrow chal treasury].freeze

    def total(s) = bal(s, *ACCOUNTS).sum
    def outcomes(r) = r.map { |x| x['outcome'] }.sort

    def bond_empty(h)
      eq(h.store.read({ 'claimId' => 'nope', 'depositor' => 'alice' }), { 'balances' => [['alice', 0]], 'openTotals' => { 'count' => 0, 'sum' => 0 }, 'highWater' => 0 })
    end

    def bond_deposit(h)
      s = h.store
      eq(s.deposit('alice', 2.5), 2.5)
      eq(s.deposit('alice', 0.5), 3)
      [0, -1, Float::NAN, Float::INFINITY].each { |bad| rejects { s.deposit('alice', bad) } }
      rejects { s.deposit('', 1) }
      eq(bal(s, 'alice'), [3])
    end

    def bond_open(h)
      s = h.store
      s.deposit('alice', 100)
      plan = open_plan('b1', 'alice', 60)
      eq(s.commit(plan, 500), { 'outcome' => 'committed', 'record' => plan['record'] })
      eq(s.read({ 'claimId' => 'b1', 'depositor' => 'alice' }),
         { 'bond' => { 'claimId' => 'b1', 'amount' => 60, 'depositor' => 'alice', 'status' => 'open', 'records' => [plan['record']] }, 'balances' => [['alice', 40]],
           'openTotals' => { 'count' => 1, 'sum' => 60 }, 'highWater' => 500 })
      eq(bal(s, 'escrow'), [60])
    end

    def bond_overdraft(h)
      s = h.store
      s.deposit('alice', 10)
      eq(s.commit(open_plan('b1', 'alice', 60), 900)['outcome'], 'conflict')
      eq(s.read({ 'claimId' => 'b1', 'depositor' => 'alice' }), { 'balances' => [['alice', 10]], 'openTotals' => { 'count' => 0, 'sum' => 0 }, 'highWater' => 0 })
      eq(bal(s, 'escrow'), [0])
    end

    def bond_open_retry(h)
      s = h.store
      s.deposit('alice', 100)
      plan = open_plan('b1', 'alice', 60)
      s.commit(plan, 1)
      eq(s.commit(plan, 2), { 'outcome' => 'replayed', 'record' => plan['record'] })
      eq(s.commit(open_plan('b1', 'alice', 61), 3)['outcome'], 'conflict')
      eq(s.commit(open_plan('b1', 'bob', 60), 3)['outcome'], 'conflict')
      eq(bal(s, 'alice', 'escrow'), [40, 60])
      eq(s.read({ 'claimId' => 'b1' })['bond']['records'].length, 1)
    end

    def bond_caps(h)
      s = h.store
      s.deposit('alice', 100)
      caps = { 'maxOpenClaims' => 2, 'maxOpenAmount' => 50 }
      eq(s.commit(open_plan('c1', 'alice', 30, caps), 1)['outcome'], 'committed')
      eq(s.commit(open_plan('c2', 'alice', 21, caps), 1)['outcome'], 'conflict') # 30 + 21 > 50
      eq(s.commit(open_plan('c3', 'alice', 20, caps), 1)['outcome'], 'committed')
      eq(s.commit(open_plan('c4', 'alice', 1, caps), 1)['outcome'], 'conflict') # third open claim
      eq(bal(s, 'alice', 'escrow'), [50, 50])
    end

    def bond_settle(h)
      s = h.store
      s.deposit('alice', 100)
      s.commit(open_plan('r', 'alice', 20), 1)
      s.commit(open_plan('s', 'alice', 40), 1)
      rel = release_plan('r', 'alice', 20)
      sl = slash_plan('s', 40)
      eq(s.commit(rel, 2), { 'outcome' => 'committed', 'record' => rel['record'] })
      eq(s.commit(sl, 3), { 'outcome' => 'committed', 'record' => sl['record'] })
      eq(bal(s, 'alice', 'escrow', 'chal', 'treasury'), [60, 0, 20, 20])
      eq(total(s), 100)
      eq([bond_status(s, 'r'), bond_status(s, 's')], %w[released slashed])
      eq(s.read({ 'claimId' => 's' })['bond']['records'], [open_plan('s', 'alice', 40)['record'], sl['record']])
    end

    def bond_phase(h)
      s = h.store
      s.deposit('alice', 100)
      eq(s.commit(release_plan('ghost', 'alice', 5), 9)['outcome'], 'conflict')
      s.commit(open_plan('b', 'alice', 20), 10)
      s.commit(release_plan('b', 'alice', 20), 11)
      snap = -> { [bal(s, 'alice', 'escrow', 'treasury', 'chal'), s.read({ 'claimId' => 'b' })['highWater']] }
      before = snap.call
      eq(s.commit(slash_plan('b', 20), 99)['outcome'], 'conflict')
      eq(snap.call, before)
      eq(bond_status(s, 'b'), 'released')
    end

    def bond_overdraw(h)
      s = h.store
      s.deposit('alice', 100)
      s.commit(open_plan('b', 'alice', 20), 1)
      greedy = slash_plan('b', 20)
      greedy['moves'] = [{ 'account' => 'escrow', 'op' => 'debit', 'amount' => 21 }, { 'account' => 'treasury', 'op' => 'credit', 'amount' => 21 }]
      eq(s.commit(greedy, 5)['outcome'], 'conflict')
      eq(bal(s, 'escrow', 'treasury'), [20, 0])
      eq(bond_status(s, 'b'), 'open')
    end

    def bond_settle_retry(h)
      s = h.store
      s.deposit('alice', 100)
      s.commit(open_plan('b', 'alice', 40), 1)
      sl = slash_plan('b', 40, 'ev-1')
      s.commit(sl, 2)
      again = slash_plan('b', 40, 'ev-1').merge('record' => sl['record'].merge('at' => 77, 'sig' => 'other'))
      eq(s.commit(again, 3), { 'outcome' => 'replayed', 'record' => sl['record'] })
      eq(s.commit(slash_plan('b', 40, 'ev-2'), 3)['outcome'], 'conflict')
      eq(s.commit(release_plan('b', 'alice', 40), 3)['outcome'], 'conflict')
      eq(bal(s, 'alice', 'escrow', 'chal', 'treasury'), [60, 0, 20, 20])
      eq(s.read({ 'claimId' => 'b' })['bond']['records'].length, 2)
    end

    def bond_race_same(h)
      h.store.deposit('alice', 100)
      h.store.commit(open_plan('b', 'alice', 40), 1)
      clients = [h.store] + Array.new(3) { h.reopen.call }
      r = race(Array.new(8) { |i| -> { clients[i % clients.length].commit(release_plan('b', 'alice', 40), 10 + i) } })
      eq(outcomes(r), ['committed'] + (['replayed'] * 7))
      eq(bal(h.store, 'alice', 'escrow'), [100, 0])
      eq(h.store.read({ 'claimId' => 'b' })['bond']['records'].length, 2)
    end

    def bond_race_conflict(h)
      h.store.deposit('alice', 100)
      h.store.commit(open_plan('b', 'alice', 40), 1)
      other = h.reopen.call
      r = race([-> { h.store.commit(release_plan('b', 'alice', 40), 5) }, -> { other.commit(slash_plan('b', 40), 5) },
                -> { h.store.commit(slash_plan('b', 40), 5) }, -> { other.commit(release_plan('b', 'alice', 40), 5) }])
      eq(r.count { |x| x['outcome'] == 'committed' }, 1)
      eq(r.count { |x| x['outcome'] == 'conflict' } + r.count { |x| x['outcome'] == 'replayed' }, 3)
      st = bond_status(h.store, 'b')
      eq(bal(h.store, 'alice', 'escrow', 'chal', 'treasury'), st == 'released' ? [100, 0, 0, 0] : [60, 0, 20, 20])
      eq(total(h.store), 100)
    end

    def bond_race_opens(h)
      h.store.deposit('alice', 100)
      other = h.reopen.call
      r = race([-> { h.store.commit(open_plan('b', 'alice', 60), 1) }, -> { other.commit(open_plan('b', 'alice', 60), 1) },
                -> { h.store.commit(open_plan('b', 'alice', 60), 1) }, -> { other.commit(open_plan('b', 'alice', 50), 1) }])
      eq(r.count { |x| x['outcome'] == 'committed' }, 1)
      eq(bal(h.store, 'alice', 'escrow'), r[3]['outcome'] == 'committed' ? [50, 50] : [40, 60])
      eq(total(h.store), 100)
    end

    def bond_race_overdraw(h)
      h.store.deposit('alice', 100)
      other = h.reopen.call
      r = race(Array.new(6) { |i| -> { (i.odd? ? h.store : other).commit(open_plan("b#{i}", 'alice', 40), 1) } })
      eq(r.count { |x| x['outcome'] == 'committed' }, 2)
      eq(bal(h.store, 'alice', 'escrow'), [20, 80])
    end

    def bond_race_deposits(h)
      other = h.reopen.call
      race(Array.new(16) { |i| -> { (i.odd? ? h.store : other).deposit('alice', 1) } })
      eq(bal(h.store, 'alice'), [16])
    end

    def bond_highwater(h)
      s = h.store
      s.deposit('alice', 100)
      s.commit(open_plan('a', 'alice', 10), 100)
      s.commit(open_plan('b', 'alice', 10), 40)
      eq(s.read({ 'claimId' => '' })['highWater'], 100)
      s.commit(open_plan('c', 'alice', 10), Float::NAN)
      eq(s.read({ 'claimId' => '' })['highWater'], 100)
      s.commit(open_plan('d', 'alice', 10), 101)
      eq(s.read({ 'claimId' => '' })['highWater'], 101)
    end

    def bond_snapshots(h)
      s = h.store
      s.deposit('alice', 100)
      s.commit(open_plan('b', 'alice', 10), 1)
      snap = s.read({ 'claimId' => 'b', 'depositor' => 'alice' })
      snap['bond']['amount'] = 999
      snap['bond']['records'].clear
      begin
        snap['balances'][0][1] = 12_345
      rescue FrozenError
        nil # an immutable pair cannot be changed through a snapshot, which is the point
      end
      again = s.read({ 'claimId' => 'b', 'depositor' => 'alice' })
      eq(again['bond']['amount'], 10)
      eq(again['bond']['records'].length, 1)
      eq(again['balances'], [['alice', 90]])
    end

    def bond_hostile(h)
      s = h.store
      %w[__proto__ constructor toString hasOwnProperty].each do |n|
        s.deposit(n, 50)
        eq(s.commit(open_plan(n, n, 20), 1)['outcome'], 'committed', n)
        eq(bal(s, n), [30], n)
        eq(bond_status(s, n), 'open', n)
      end
      eq(bond_status(s, 'valueOf'), 'none')
      eq(bal(s, 'valueOf'), [0])
    end

    def bond_reopen(h)
      h.store.deposit('alice', 100)
      h.store.commit(open_plan('a', 'alice', 40), 7)
      h.store.commit(open_plan('b', 'alice', 20), 8)
      sl = slash_plan('b', 20)
      h.store.commit(sl, 9)
      back = h.reopen.call
      eq(back.read({ 'claimId' => 'b', 'depositor' => 'alice' }),
         { 'bond' => { 'claimId' => 'b', 'amount' => 20, 'depositor' => 'alice', 'status' => 'slashed', 'records' => [open_plan('b', 'alice', 20)['record'], sl['record']] },
           'balances' => [['alice', 40]], 'openTotals' => { 'count' => 1, 'sum' => 40 }, 'highWater' => 9 })
      eq(bal(back, 'escrow', 'chal', 'treasury'), [40, 10, 10])
      eq(back.commit(sl, 10)['outcome'], 'replayed')
    end

    def bond_crash(h)
      h.store.deposit('alice', 100)
      h.store.commit(open_plan('a', 'alice', 40), 1)
      h.store.commit(open_plan('b', 'alice', 30), 2)
      background { h.store.commit(slash_plan('b', 30), 3) }
      back = h.crash.call
      eq(bond_status(back, 'a'), 'open')
      st = bond_status(back, 'b')
      ok(%w[open slashed].include?(st), "bond b is #{st}")
      eq(bal(back, 'alice', 'escrow', 'chal', 'treasury'), st == 'slashed' ? [30, 40, 15, 15] : [30, 70, 0, 0])
      eq(total(back), 100)
      eq(back.commit(slash_plan('b', 30), 4)['outcome'], st == 'slashed' ? 'replayed' : 'committed')
      eq(bal(back, 'alice', 'escrow', 'chal', 'treasury'), [30, 40, 15, 15])
    end

    BOND_CHECKS = [
      chk('empty-store-reads-empty', 'an unknown bond reads as absent, an unknown account as balance 0, and the time high-water mark starts at 0') { |h| bond_empty(h) },
      chk('deposit-validates-and-accumulates', 'deposit credits exactly, returns the new balance, and refuses a non-positive, non-finite or unnamed deposit') { |h| bond_deposit(h) },
      chk('open-is-atomic-and-recorded', 'an open moves the collateral, stores the row with its record, and raises the high-water mark, all together') { |h| bond_open(h) },
      chk('open-overdraft-refused-without-trace', 'an open the depositor cannot fund is a conflict and leaves balances, bonds and the high-water mark untouched') { |h| bond_overdraft(h) },
      chk('open-retry-is-replayed-and-different-terms-conflict', 'committing the same open again returns the stored record and moves nothing; other terms for that bond conflict') { |h| bond_open_retry(h) },
      chk('open-caps-are-rechecked-at-commit', 'the per-depositor open-claim and open-amount caps hold inside the store, whatever the planner saw') { |h| bond_caps(h) },
      chk('settle-applies-every-move-once', 'a release and a slash apply all their balance moves, store the record, and conserve the total') { |h| bond_settle(h) },
      chk('settle-needs-the-expected-phase', 'settling an absent bond or from the wrong phase is a conflict that changes nothing, high-water mark included') { |h| bond_phase(h) },
      chk('settle-overdraw-refused-without-trace', 'a settlement whose debit would overdraw an account is refused whole: no credit lands, the phase does not change') { |h| bond_overdraw(h) },
      chk('settle-retry-returns-the-stored-record', 'the same settlement again is replayed with the first record and moves nothing; the same action with other evidence conflicts') { |h| bond_settle_retry(h) },
      chk('racing-identical-settles-commit-once', 'eight clients racing the same release: one commits, seven are replays, funds move once') { |h| bond_race_same(h) },
      chk('racing-conflicting-settles-have-one-winner', 'a release racing a slash on one bond: exactly one commits, the books show only the winner, the total is conserved') { |h| bond_race_conflict(h) },
      chk('racing-opens-for-the-same-bond-commit-once', 'concurrent identical opens collect the collateral once; a differing open loses') { |h| bond_race_opens(h) },
      chk('racing-opens-cannot-overdraw', 'concurrent opens by one depositor that together exceed the balance: the sum committed never exceeds what was deposited') { |h| bond_race_overdraw(h) },
      chk('concurrent-deposits-lose-nothing', 'sixteen racing deposits add up exactly') { |h| bond_race_deposits(h) },
      chk('time-high-water-only-moves-forward', 'the recorded time is the maximum of every committed observedAt; a smaller or non-finite one never lowers it') { |h| bond_highwater(h) },
      chk('reads-are-snapshots', 'mutating a returned snapshot cannot change the store') { |h| bond_snapshots(h) },
      chk('hostile-names-are-plain-keys', 'claim and account names such as __proto__, constructor and toString behave like any other name') { |h| bond_hostile(h) },
      chk('state-survives-reopen', 'every acknowledged commit and deposit is visible to a new client after the backend restarts', 'durable') { |h| bond_reopen(h) },
      chk('acknowledged-commits-survive-a-crash', 'after an abrupt kill, every acknowledged transition is present, and a transition that was in flight is applied entirely or not at all', 'crash') { |h| bond_crash(h) }
    ].freeze

    # ---- running a profile ---------------------------------------------------------------------------------------------

    def run_profile(checks, adapter, only)
      results = []
      checks.each do |c|
        next if !only.nil? && !only.include?(c.name)

        if c.needs == 'durable' && adapter.durable == false
          results << { 'name' => c.name, 'status' => 'skip', 'detail' => 'the adapter declares durable: false' }
          next
        end
        h = adapter.create.call
        h.adapter_durable = adapter.durable
        begin
          if c.needs == 'crash' && h.crash.nil?
            results << { 'name' => c.name, 'status' => 'skip', 'detail' => 'the adapter has no crash()' }
            next
          end
          c.run.call(h)
          results << { 'name' => c.name, 'status' => 'pass' }
        rescue StandardError => e # a failing check is a result, not a crash of the run
          results << { 'name' => c.name, 'status' => 'fail', 'detail' => e.message.empty? ? e.class.name : e.message }
        ensure
          h.close&.call
        end
      end
      { 'adapter' => adapter.name, 'status' => results.any? { |x| x['status'] == 'fail' } ? 'fail' : 'pass', 'checks' => results }
    end

    def format_profile(label, r)
      lines = ["pca-store-conformance (#{label}): #{r['adapter']} -> #{r['status'].upcase}"]
      r['checks'].each { |c| lines << "  [#{c['status'].upcase}] #{c['name']}#{Js.truthy?(c['detail']) ? ": #{c['detail'].split("\n").first}" : ''}" }
      lines.join("\n")
    end

    # Run GUARDIAN_LEASE_CHECKS against a guardian lease store: {adapter, status, checks: [{name, status, detail?}]}.
    def run_guardian_lease_store_conformance(adapter, only = nil) = run_profile(GUARDIAN_LEASE_CHECKS, adapter, only)
    # Run LEDGER_CHECKS against a transparency-log ledger store.
    def run_ledger_store_conformance(adapter, only = nil) = run_profile(LEDGER_CHECKS, adapter, only)
    # Run BUDGET_CHECKS against an aggregate budget ledger.
    def run_budget_ledger_conformance(adapter, only = nil) = run_profile(BUDGET_CHECKS, adapter, only)
    # Run BOND_CHECKS against a bond-settlement store.
    def run_bond_store_conformance(adapter, only = nil) = run_profile(BOND_CHECKS, adapter, only)

    def format_lease_report(r) = format_profile('lease store', r)
    def format_ledger_report(r) = format_profile('ledger store', r)
    def format_budget_report(r) = format_profile('budget ledger', r)
    def format_bond_report(r) = format_profile('bond store', r)

    # ---- mesh-witness state stores -------------------------------------------------------------------------------------

    # name, make (a fresh, empty store with load -> state | nil and save(state)), optionally reopen (a callable taking the previous
    # store: a new store object over the same backing storage, a restart) and damage (a callable damaging the backing storage so
    # that load must fail).
    MeshWitnessStoreAdapter = Struct.new(:name, :make, :reopen, :damage, keyword_init: true)

    # the reference's deterministic seed of a label, a capability stand-in per label, and two logs of one domain key with different histories
    def mesh_seed(label) = AtlasPca::KeyPair.new((0...32).map { |i| (label.getbyte(i % label.bytesize) + i) & 0xff }.pack('C*'))

    def mesh_cap(label) = { 'id' => label, 'caveats' => [{ 'type' => 'scope', 'actions' => [label] }] }

    def mesh_two_logs
      honest = MeshDomain.new('d', mesh_seed('domain'))
      fork = MeshDomain.new('d', mesh_seed('domain'))
      honest.record(mesh_cap('a'))
      fork.record(mesh_cap('x'))
      [honest, fork]
    end

    def mesh_state(n)
      { 'seen' => [{ 'head' => { 'domain' => "d#{n}", 'size' => 0, 'root' => '', 'rev_root' => 'r', 'rev_size' => 0, 'timestamp' => n }, 'rev_ids' => [] }] }
    end

    # The store-only cases of the mesh-witness profile (round trip, replace, copy semantics, reopen, damage). The damaged-storage case
    # checks that load throws; the reference's second half (a witness constructed over damaged storage also throws) needs a real witness.
    def mesh_witness_store_cases(a)
      cases = [
        chk('a fresh store loads nothing', '') { |_h| eq(a.make.call.load, nil) },
        chk('save then load returns the same state', '') do |_h|
          s = a.make.call
          s.save(mesh_state(1))
          eq(s.load, mesh_state(1))
        end,
        chk('a later save replaces the earlier one', '') do |_h|
          s = a.make.call
          s.save(mesh_state(1))
          s.save(mesh_state(2))
          eq(s.load, mesh_state(2))
        end,
        chk('load returns a copy: changing it does not change the store', '') do |_h|
          s = a.make.call
          s.save(mesh_state(1))
          s.load['seen'].pop
          eq(s.load, mesh_state(1))
        end,
        chk('save keeps its own copy: changing the argument afterwards does not change the store', '') do |_h|
          s = a.make.call
          st = mesh_state(1)
          s.save(st)
          st['seen'].clear
          eq(s.load, mesh_state(1))
        end,
        chk('a witness persists every cosignature before returning it', '') do |_h|
          s = a.make.call
          w = MeshWitness.new(mesh_seed('w'), store: s)
          honest, = mesh_two_logs
          ch = honest.publish_head([w], 1_000)
          eq(s.load, w.export_state)
          eq(s.load['seen'].map { |x| x['head'] }, [ch['head']])
        end,
        chk('a failed save refuses the cosignature and leaves the witness unchanged', '') do |_h|
          inner = a.make.call
          failing = false
          flaky = Object.new
          flaky.define_singleton_method(:load) { inner.load }
          flaky.define_singleton_method(:save) do |st|
            raise 'disk full' if failing

            inner.save(st)
          end
          w = MeshWitness.new(mesh_seed('w'), store: flaky)
          honest, = mesh_two_logs
          honest.publish_head([w], 1_000)
          before = JSON.generate(w.export_state)
          honest.record(mesh_cap('b'))
          failing = true
          threw = begin
            honest.publish_head([w], 2_000)
            ''
          rescue StandardError => e
            e.message
          end
          eq(threw, 'witness: could not persist state; refusing to cosign')
          eq(JSON.generate(w.export_state), before)
          eq(inner.load, JSON.parse(before))
          failing = false
          ok(honest.publish_head([w], 2_000)['cosigs'].length == 1, 'the same head is cosigned once the disk recovers')
        end
      ]
      if a.reopen
        cases << chk('state survives reopening the store', '') do |_h|
          s = a.make.call
          s.save(mesh_state(3))
          eq(a.reopen.call(s).load, mesh_state(3))
        end
        cases << chk('a restarted witness remembers what it cosigned: it refuses a fork and a rollback', '') do |_h|
          s = a.make.call
          w1 = MeshWitness.new(mesh_seed('w'), store: s)
          honest, fork = mesh_two_logs
          honest.publish_head([w1], 1_000)
          honest.record(mesh_cap('b'))
          honest.publish_head([w1], 2_000)
          w2 = MeshWitness.new(mesh_seed('w'), store: a.reopen.call(s))
          eq(w2.last_seen(honest.id)['size'], 2)
          fork.record(mesh_cap('y'))
          fork.record(mesh_cap('z'))
          rejects { fork.publish_head([w2], 3_000) } # a fork that grew past the remembered size must be refused
          rollback = MeshDomain.new('d', mesh_seed('domain'))
          rollback.record(mesh_cap('a'))
          rejects { rollback.publish_head([w2], 3_000) } # a rollback to the first head must be refused
          ok(honest.publish_head([w2], 3_000)['cosigs'].length == 1, 'the honest log is still cosigned')
        end
      end
      if a.damage
        cases << chk('damaged storage makes load throw, so a witness never starts empty over it', '') do |_h|
          s = a.make.call
          # a state a witness accepts, so that only the damage can make construction fail
          w0 = MeshWitness.new(mesh_seed('w'))
          d0 = MeshDomain.new('d', mesh_seed('domain'))
          d0.record(mesh_cap('a'))
          d0.publish_head([w0], 1_000)
          s.save(w0.export_state)
          a.damage.call(s)
          rejects { s.load } # load must throw on damaged storage
          rejects { MeshWitness.new(mesh_seed('w'), store: s) } # constructing a witness over damaged storage must throw
        end
      end
      cases
    end

    # Run the store-only mesh-witness cases: {adapter, status, checks: [{name, status, detail?}]}.
    def run_mesh_witness_store_conformance(a)
      results = mesh_witness_store_cases(a).map do |c|
        c.run.call(nil)
        { 'name' => c.name, 'status' => 'pass' }
      rescue StandardError => e
        { 'name' => c.name, 'status' => 'fail', 'detail' => e.message.empty? ? e.class.name : e.message }
      end
      { 'adapter' => a.name, 'status' => results.any? { |x| x['status'] == 'fail' } ? 'fail' : 'pass', 'checks' => results }
    end
  end
end
