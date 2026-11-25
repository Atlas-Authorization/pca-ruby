# frozen_string_literal: true

require_relative 'js_compat'
require_relative 'atomic_kv'
require_relative 'collation'

module AtlasPca
  # Guardian high availability: liveness, quorum, degrade mode, signer selection and failover over guardian health facts, plus a durable,
  # FENCED leader lease (at most one holder, a strictly monotone fencing epoch, store-side expiry, "no leader" whenever the store errs).
  # A port of the reference `ha` module, argument shapes included (Hashes with String keys): a malformed set, clock or heartbeat counts
  # as down and the module never fails OPEN (losing quorum or the lease restricts authority, never widens it).
  #
  # Lease safety holds IF the store's compare-and-swap is linearizable and the holder's clock error stays under skew_ms. A downstream
  # that never checks the fencing epoch is not protected: check it with a FenceGuard. A lease store answers #read -> record | nil,
  # #now -> epoch ms and #cas(expected | nil, next) -> true when it replaced the stored record.
  module Ha
    UNDEF = V2JS::UNDEF
    MAX_LEASE_TTL_MS = 3_600_000
    DEFAULT_LEASE_SKEW_MS = 1_000
    MAX_HOLDER_LEN = 256
    MAX_SAFE = 9_007_199_254_740_991

    # Raised by a fenced signer that is not (or is no longer) the leader. #reason: stale | expired | store-error | no-lease.
    class FenceError < StandardError
      attr_reader :reason

      def initialize(reason)
        @reason = reason
        super("fenced: #{reason}")
      end
    end

    module_function

    # o.k of the reference: a null object throws, a non-object has no such member.
    def jprop(o, k)
      raise TypeError, "Cannot read properties of null (reading '#{k}')" if o.nil?

      o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF
    end

    def num?(x) = x.is_a?(Integer) || x.is_a?(Float)
    def finite?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite?)
    def integer?(x) = finite?(x) && x == x.floor
    def safe_integer?(x) = integer?(x) && x.abs <= MAX_SAFE
    def obj?(g) = g.is_a?(Hash) || g.is_a?(Array)

    # o?.k ?? default
    def opt(o, k, default)
      v = o.is_a?(Hash) ? o[k] : nil
      v.nil? ? default : v
    end

    def to_number(x) = x.equal?(UNDEF) ? Float::NAN : Immune.to_num(x)

    # Strict equality of two JSON values of the reference (objects are never equal here).
    def seq?(a, b)
      return a == b if num?(a) && num?(b)
      return a.class == b.class && a == b if a.is_a?(String) || a == true || a == false

      a.equal?(b)
    end

    # The Latin-text approximation of the reference's locale-aware string compare, used only when ICU is not available (see Collation): letters by
    # base letter, then accents, then lower before upper case; punctuation < digits < letters. It does not know ICU's order within punctuation.
    def collation_key(s)
      d = s.unicode_normalize(:nfd)
      base = d.each_char.reject { |c| c.match?(/\p{M}/) }
      [base.map { |c| [c.match?(/\p{Alpha}/) ? 2 : (c.match?(/\p{Nd}/) ? 1 : 0), c.downcase(:fold)] },
       d.each_char.select { |c| c.match?(/\p{M}/) },
       base.map { |c| c.match?(/\p{Lu}/) ? 1 : 0 }]
    end

    def locale_compare(a, b)
      raise TypeError, 'a.localeCompare is not a function' unless a.is_a?(String)

      bs = b.equal?(UNDEF) ? 'undefined' : (b.nil? ? 'null' : Js.string(b))
      Collation.compare(a, bs) || (collation_key(a) <=> collation_key(bs))
    end

    # Guardians flagged healthy AND with a fresh heartbeat at `now`. Fails closed: a malformed set, a non-finite clock or stale window,
    # a non-finite or FUTURE-dated heartbeat, or a non-boolean `healthy` counts as down.
    def live_guardians(guardian_set, now, opts = nil)
      stale = opt(opts, 'staleMs', 30_000)
      gs = guardian_set.nil? ? UNDEF : jprop(guardian_set, 'guardians')
      return [] if !finite?(now) || !finite?(stale) || stale.negative? || !gs.is_a?(Array) || !gs.all? { |g| !g.nil? && obj?(g) }

      gs.select do |g|
        g.is_a?(Hash) && g['healthy'] == true && finite?(g['lastSeen']) && g['lastSeen'] <= now && now - g['lastSeen'] <= stale
      end
    end

    def weight_of(g) = finite?(g['weight']) ? g['weight'] : 0

    # live guardians by weight (high first), then freshest heartbeat, then id
    def order(live)
      live.each_with_index.sort do |(a, i), (b, j)|
        c = weight_of(b) - weight_of(a)
        c = b['lastSeen'] - a['lastSeen'] if c.zero?
        c = locale_compare(a.fetch('id', UNDEF), b.fetch('id', UNDEF)) if c.zero?
        c.zero? ? i <=> j : (c.negative? ? -1 : 1)
      end.map(&:first)
    end

    # {'total', 'live', 'quorum', 'available', 'degraded'}: total and live guardian counts, whether a co-sign quorum is reachable,
    # whether some are live but below quorum. 'quorum' is absent when the set has none.
    def quorum_status(guardian_set, now, opts = nil)
      live = live_guardians(guardian_set, now, opts).length
      gs = guardian_set.nil? ? UNDEF : jprop(guardian_set, 'guardians')
      q = guardian_set.nil? ? UNDEF : jprop(guardian_set, 'quorum')
      out = { 'total' => gs.is_a?(Array) ? gs.length : 0, 'live' => live }
      out['quorum'] = q unless q.equal?(UNDEF)
      out['available'] = integer?(q) && q >= 1 && live >= q
      out['degraded'] = live.positive? && live < to_number(q)
      out
    end

    # 'normal' (quorum available) | 'read-only' (below quorum, some live) | 'halt' (none live, or read-only switched off).
    def degrade_mode(status, policy = nil)
      return 'normal' if (v = jprop(status, 'available')) && !v.equal?(UNDEF) && Js.truthy?(v)

      live = to_number(jprop(status, 'live'))
      live.positive? && !(policy.is_a?(Hash) && policy['allowReadOnly'] == false) ? 'read-only' : 'halt'
    end

    # The `quorum` freshest, highest-weight live guardians; empty when quorum is not available.
    def select_signers(guardian_set, now, opts = nil)
      live = live_guardians(guardian_set, now, opts)
      q = jprop(guardian_set, 'quorum')
      return [] if !integer?(q) || q < 1 || live.length < q

      order(live).first(q.to_i).map { |g| g.fetch('id', nil) }
    end

    # {'primary', 'standbys'}: the preferred live guardian (nil when none is live) and the others in preference order.
    def failover_plan(guardian_set, now, opts = nil)
      live = order(live_guardians(guardian_set, now, opts))
      { 'primary' => live.empty? ? nil : live.first['id'], 'standbys' => live.drop(1).map { |g| g['id'] } }
    end

    # An error string, or nil when the set is well formed (quorum in range, unique non-empty ids).
    def validate_guardian_set(guardian_set)
      return 'guardian set is not an object' unless obj?(guardian_set)

      gs = jprop(guardian_set, 'guardians')
      q = jprop(guardian_set, 'quorum')
      return 'guardian set is empty' if !gs.is_a?(Array) || gs.empty?
      return 'quorum must be an integer ≥ 1' if !integer?(q) || q < 1
      return 'quorum exceeds guardian count' if q > gs.length
      return 'guardian id must be a non-empty string' unless gs.all? { |g| g.is_a?(Hash) && g['id'].is_a?(String) && !g['id'].empty? }
      return 'duplicate guardian ids' if gs.map { |g| g['id'] }.uniq.length != gs.length

      nil
    end

    # ---- durable, fenced leader lease

    def valid_record?(r)
      r.is_a?(Hash) && r['holder'].is_a?(String) && safe_integer?(r['epoch']) && r['epoch'] >= 1 && finite?(r['expiresAt']) && r['expiresAt'] >= 0
    end

    def eq_lease?(a, b)
      return a.equal?(b) if a.nil? || b.nil?

      %w[holder epoch expiresAt].all? { |k| seq?(jprop(a, k), jprop(b, k)) }
    end

    def lease_opts(holder, o)
      return nil if !holder.is_a?(String) || holder.empty? || Js.len16(holder) > MAX_HOLDER_LEN

      skew = opt(o, 'skewMs', DEFAULT_LEASE_SKEW_MS)
      ttl = o.is_a?(Hash) ? o['ttlMs'] : nil
      return nil if !integer?(ttl) || ttl < 2 || ttl > MAX_LEASE_TTL_MS
      return nil if !finite?(skew) || skew.negative? || skew >= ttl

      [ttl, skew]
    end

    # Read the record and the store clock; a corrupt record or clock is a store error (never "free").
    def snapshot(store)
      cur = store.read
      now = store.now
      raise 'corrupt lease state' if !finite?(now) || (!cur.nil? && !valid_record?(cur))

      [cur, now]
    end

    def lease_fail(reason, err = nil)
      r = { 'ok' => false, 'reason' => reason }
      r['detail'] = err.message if err
      r
    end

    def commit(store, cur, nxt) = Js.truthy?(store.cas(cur, nxt)) ? { 'ok' => true, 'lease' => nxt } : lease_fail('lost-race')

    # Take the lease if it is free (never held, released, or expired past the skew); the epoch increments on every takeover.
    # {'ok' => true, 'lease'} or {'ok' => false, 'reason' => invalid | held | lost-race | store-error, 'detail'?}.
    def acquire_lease(store, holder, options)
      p = lease_opts(holder, options)
      return lease_fail('invalid') unless p

      cur, now = snapshot(store)
      return lease_fail('held') if !cur.nil? && !(cur['expiresAt'] + p[1] <= now) && cur['expiresAt'] != 0

      commit(store, cur, { 'holder' => holder, 'epoch' => (cur ? cur['epoch'] : 0) + 1, 'expiresAt' => now + p[0] })
    rescue StandardError => e # a store that errs means no leader
      lease_fail('store-error', e)
    end

    # Extend a lease the caller still holds; refused once the holder's own safe window (expiry minus skew) has passed, or after any takeover.
    def renew_lease(store, lease, options)
      p = valid_record?(lease) ? lease_opts(lease['holder'], options) : nil
      return lease_fail('invalid') unless p

      cur, now = snapshot(store)
      return lease_fail('stale') if cur.nil? || cur['holder'] != lease['holder'] || cur['epoch'] != lease['epoch']
      return lease_fail('expired') unless cur['expiresAt'] - p[1] > now

      commit(store, cur, { 'holder' => cur['holder'], 'epoch' => cur['epoch'], 'expiresAt' => now + p[0] })
    rescue StandardError => e
      lease_fail('store-error', e)
    end

    # Give the lease up early (expiresAt 0, epoch kept); only the current holder at the current epoch can.
    def release_lease(store, lease)
      return lease_fail('invalid') unless valid_record?(lease)

      cur, = snapshot(store)
      return lease_fail('stale') if cur.nil? || cur['holder'] != lease['holder'] || cur['epoch'] != lease['epoch'] || cur['expiresAt'] == 0

      commit(store, cur, { 'holder' => cur['holder'], 'epoch' => cur['epoch'], 'expiresAt' => 0 })
    rescue StandardError => e
      lease_fail('store-error', e)
    end

    # Is this exact (holder, epoch) still the leader with its safe window open, per the store? Any error answers no.
    def assert_fence(store, token, skew_ms = DEFAULT_LEASE_SKEW_MS)
      return { 'ok' => false, 'reason' => 'stale' } if !Js.truthy?(token) || !finite?(skew_ms) || skew_ms.negative?

      cur, now = snapshot(store)
      return { 'ok' => false, 'reason' => 'stale' } if cur.nil? || !seq?(cur['holder'], jprop(token, 'holder')) || !seq?(cur['epoch'], jprop(token, 'epoch'))

      cur['expiresAt'] - skew_ms > now ? { 'ok' => true } : { 'ok' => false, 'reason' => 'expired' }
    rescue StandardError
      { 'ok' => false, 'reason' => 'store-error' }
    end

    # Wrap a co-sign function so it only runs while the caller is the fenced leader: the fence is checked before AND after the
    # signature, and a leader that lost the lease mid-signature gets a FenceError and the signature is discarded. Returns a lambda giving
    # {'result', 'epoch'}. Check-then-sign is inherently racy: the downstream must also admit the epoch with a FenceGuard.
    def fenced_signer(store, get_lease, sign, skew_ms = DEFAULT_LEASE_SKEW_MS)
      lambda do |*args|
        lease = get_lease.call
        raise FenceError, 'no-lease' unless Js.truthy?(lease)

        pre = assert_fence(store, lease, skew_ms)
        raise FenceError, pre['reason'] unless pre['ok']

        result = sign.call(*args)
        post = assert_fence(store, lease, skew_ms)
        raise FenceError, post['reason'] unless post['ok']

        { 'result' => result, 'epoch' => lease['epoch'] }
      end
    end

    def create_fence_guard(initial = 0) = FenceGuard.new(initial)
  end

  # Resource-side fencing: remembers the highest epoch seen and refuses anything lower (a stale ex-leader's late write).
  class FenceGuard
    def initialize(initial = 0)
      @hi = Ha.safe_integer?(initial) && initial.positive? ? initial : 0 # -0 starts at 0 like any other non-positive value
    end

    def admit(epoch)
      return false if !Ha.safe_integer?(epoch) || epoch < 1 || epoch < @hi

      @hi = epoch
      true
    end

    def highest = @hi
  end

  # Reference lease store over any key/value store whose #update is the atomic compare-and-swap (MemoryAtomicKv, SqliteAtomicKv).
  class KvLeaseStore
    def initialize(kv = nil, key: nil, now: nil)
      @kv = kv.nil? ? MemoryAtomicKv.new : kv
      @key = key.nil? ? 'ha/lease' : key
      @now = now
    end

    def read
      v = @kv.get(@key)
      raise 'corrupt lease state' if !v.nil? && !Ha.valid_record?(v)

      v
    end

    # Replace the record iff the stored one equals `expected` (nil = none); the epoch never goes below the stored one.
    def cas(expected, nxt)
      raise 'invalid lease record' unless Ha.valid_record?(nxt)

      matched = false
      @kv.update(@key) do |prev|
        next nil if !prev.nil? && !Ha.valid_record?(prev)
        next nil if !Ha.eq_lease?(prev, expected) || nxt['epoch'] < (prev.nil? ? 0 : prev['epoch'])

        matched = true
        nxt
      end
      matched
    end

    def now = @now ? @now.call : (Time.now.to_f * 1000).to_i
  end
end
