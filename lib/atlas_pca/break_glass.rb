# frozen_string_literal: true

# Break-glass grants (verification side): time-boxed, loud, auto-revoked, with a mandatory signed review. BreakGlassRegistry keeps
# its state in a durable kv, sharded by holder (as the TypeScript registry does). Every function is total.
# Replays packages/pca/conformance/break-glass-vectors.json. Hashes use String keys.
module AtlasPca
  BREAK_GLASS_DOMAIN = "atlas-pca/break-glass/v1\x00".b.freeze
  BREAK_GLASS_REVIEW_DOMAIN = "atlas-pca/break-glass-review/v1\x00".b.freeze
  MAX_BREAK_GLASS_WINDOW_MS = 86_400_000
  MAX_BREAK_GLASS_USES = 16
  MAX_REVIEW_WITHIN_MS = 30 * 86_400_000
  BREAK_GLASS_BODY_KEYS = %w[v id holder grant_ref reason_digest max_uses issued_at expires_at review_within notify_to authority].freeze
  BREAK_GLASS_REVIEW_KEYS = %w[v id outcome notes_digest at reviewer].freeze

  module_function

  def break_glass_well_formed?(b)
    return false unless b.is_a?(Hash) && b['v'] == 1 && b['v'].is_a?(Integer)
    return false unless k3_str?(b['id'], 128) && k3_str?(b['holder'], 128) && k3_str?(b['grant_ref'], 256) && k3_str?(b['reason_digest'], 128)
    return false unless k3_str?(b['notify_to'], 256) && k3_str?(b['authority'], 128)
    return false unless k3_int?(b['max_uses']) && b['max_uses'] >= 1 && b['max_uses'] <= MAX_BREAK_GLASS_USES
    return false unless k3_int?(b['issued_at']) && k3_int?(b['expires_at']) && b['expires_at'] > b['issued_at'] && b['expires_at'] - b['issued_at'] <= MAX_BREAK_GLASS_WINDOW_MS

    k3_int?(b['review_within']) && b['review_within'] >= 1 && b['review_within'] <= MAX_REVIEW_WITHIN_MS
  end

  def verify_break_glass(b)
    return false unless break_glass_well_formed?(b)

    k3_verify_body(BREAK_GLASS_DOMAIN, BREAK_GLASS_BODY_KEYS.to_h { |k| [k, b[k]] }, b['authority'], b['sig'])
  rescue StandardError
    false
  end

  def break_glass_review_well_formed?(r)
    r.is_a?(Hash) && r['v'] == 1 && r['v'].is_a?(Integer) && k3_str?(r['id'], 128) && %w[justified unjustified].include?(r['outcome']) &&
      k3_str?(r['notes_digest'], 128) && k3_int?(r['at']) && k3_str?(r['reviewer'], 128)
  end

  def verify_break_glass_review(r)
    return false unless break_glass_review_well_formed?(r)

    k3_verify_body(BREAK_GLASS_REVIEW_DOMAIN, BREAK_GLASS_REVIEW_KEYS.to_h { |k| [k, r[k]] }, r['reviewer'], r['sig'])
  rescue StandardError
    false
  end

  # State is kept per holder shard (the TS BreakGlassRegistry layout: `breakglass/<shards>/<i>`, shard = hash of the holder), in a
  # durable kv: a use budget, a freeze and a review survive a restart and hold across instances. Each operation is ONE atomic kv
  # update. The kv is required (MemoryBreakGlassKv is for tests and single-process use).
  class BreakGlassRegistry
    DEFAULT_SHARDS = 16
    META_KEY = 'breakglass/meta'

    # policy: { 'authorities' => [...], 'reviewers' => [...] }; kv: get(key) + atomic update(key) { |prev| next }
    def initialize(policy, kv = nil, shards: DEFAULT_SHARDS)
      unless AtlasPca.kv_usable?(kv)
        raise TypeError, 'BreakGlassRegistry: a durable key-value store is required (memoryLeaseKv() is for tests and single-process use)'
      end
      raise RangeError, 'BreakGlassRegistry: shards must be an integer from 1 to 4096' unless shards.is_a?(Integer) && shards >= 1 && shards <= MAX_KV_SHARDS

      @policy = policy
      @kv = kv
      @shards = shards
      @meta_ok = false
      @lock = Mutex.new
    end

    def accept(rec, now) = @lock.synchronize { accept_locked(rec, now) }
    def use(id, holder, action_digest, now, notified) = @lock.synchronize { use_locked(id, holder, action_digest, now, notified) }
    def review(rec, holder, now) = @lock.synchronize { review_locked(rec, holder, now) }
    def frozen(holder, now) = @lock.synchronize { frozen_locked(holder, now) }

    # The numbered use log of a grant, oldest first.
    def uses(holder, id)
      return [] unless ready?

      e = load_shard(@kv.get(key_of(holder)))['grants'][id]
      e.nil? ? [] : e['uses'].map(&:dup)
    end

    private

    def key_of(holder) = "breakglass/#{@shards}/#{AtlasPca.kv_shard_of(holder, @shards)}"

    def load_shard(x) = x.is_a?(Hash) && x['grants'].is_a?(Hash) ? x : { 'grants' => {} }

    def ready?
      @meta_ok ||= AtlasPca.kv_pin_shards(@kv, META_KEY, @shards)
    end

    def accept_locked(rec, now)
      return { 'ok' => false, 'code' => 'bad_record' } unless AtlasPca.verify_break_glass(rec) && AtlasPca.k3_int?(now)
      return { 'ok' => false, 'code' => 'unknown_authority' } unless @policy['authorities'].include?(rec['authority'])
      return { 'ok' => false, 'code' => 'store_unreachable' } unless ready?

      out = { 'ok' => false, 'code' => 'store_unreachable' }
      @kv.update(key_of(rec['holder'])) do |prev|
        st = load_shard(prev)
        cur = st['grants'][rec['id']]
        unless cur.nil?
          out = cur['rec']['sig'] == rec['sig'] ? { 'ok' => true, 'replaced' => false } : { 'ok' => false, 'code' => 'id_conflict' }
          next nil
        end
        if frozen_in?(st, rec['holder'], now)
          out = { 'ok' => false, 'code' => 'holder_frozen' }
          next nil
        end

        st['grants'][rec['id']] = { 'rec' => rec, 'uses' => [], 'review' => nil }
        out = { 'ok' => true, 'replaced' => true }
        st
      end
      out
    rescue StandardError
      { 'ok' => false, 'code' => 'store_unreachable' }
    end

    def use_locked(id, holder, action_digest, now, notified)
      return { 'decision' => 'deny', 'code' => 'bad_input' } unless AtlasPca.k3_str?(id, 128) && AtlasPca.k3_str?(holder, 128) && AtlasPca.k3_str?(action_digest, 128) &&
                                                                    AtlasPca.k3_int?(now) && [true, false].include?(notified)

      out = { 'decision' => 'deny', 'code' => 'store_unreachable', 'id' => id }
      deny = lambda do |code|
        out = { 'decision' => 'deny', 'code' => code, 'id' => id }
        nil
      end
      return out unless ready?

      @kv.update(key_of(holder)) do |prev|
        st = load_shard(prev)
        e = st['grants'][id]
        next deny.call('unknown_break_glass') if e.nil?
        next deny.call('wrong_holder') if e['rec']['holder'] != holder
        next deny.call('holder_frozen') if frozen_in?(st, holder, now)
        next deny.call('revoked') if e['review'] && e['review']['outcome'] == 'unjustified'
        next deny.call('not_yet_valid') if now < e['rec']['issued_at']
        next deny.call('expired') if now >= e['rec']['expires_at']
        next deny.call('budget_exhausted') if e['uses'].length >= e['rec']['max_uses']
        next deny.call('not_notified') unless notified

        e['uses'] << { 'n' => e['uses'].length + 1, 'action_digest' => action_digest, 'at' => now }
        out = { 'decision' => 'allow', 'id' => id, 'use' => e['uses'].length, 'remaining' => e['rec']['max_uses'] - e['uses'].length,
                'review_due' => e['uses'][0]['at'] + e['rec']['review_within'] }
        st
      end
      out
    rescue StandardError
      { 'decision' => 'deny', 'code' => 'store_unreachable', 'id' => id }
    end

    def review_locked(rec, holder, now)
      return { 'ok' => false, 'code' => 'bad_record' } unless AtlasPca.verify_break_glass_review(rec) && AtlasPca.k3_str?(holder, 128) && AtlasPca.k3_int?(now)
      return { 'ok' => false, 'code' => 'unknown_reviewer' } unless @policy['reviewers'].include?(rec['reviewer'])
      return { 'ok' => false, 'code' => 'store_unreachable' } unless ready?

      out = { 'ok' => false, 'code' => 'store_unreachable' }
      fail_with = lambda do |code|
        out = { 'ok' => false, 'code' => code }
        nil
      end
      @kv.update(key_of(holder)) do |prev|
        st = load_shard(prev)
        e = st['grants'][rec['id']]
        next fail_with.call('unknown_break_glass') if e.nil? || e['rec']['holder'] != holder
        next fail_with.call('sod') if rec['reviewer'] == e['rec']['holder'] || rec['reviewer'] == e['rec']['authority']

        unless e['review'].nil?
          out = e['review']['sig'] == rec['sig'] ? { 'ok' => true, 'replaced' => false } : { 'ok' => false, 'code' => 'already_reviewed' }
          next nil
        end
        next fail_with.call('nothing_to_review') if e['uses'].empty?
        next fail_with.call('bad_time') if rec['at'] < e['uses'][0]['at'] || rec['at'] > now

        e['review'] = rec
        out = { 'ok' => true, 'replaced' => true }
        st
      end
      out
    rescue StandardError
      { 'ok' => false, 'code' => 'store_unreachable' }
    end

    def frozen_locked(holder, now)
      return true unless AtlasPca.k3_str?(holder, 128) && AtlasPca.k3_int?(now) # fail closed
      return true unless ready?

      frozen_in?(load_shard(@kv.get(key_of(holder))), holder, now)
    rescue StandardError
      true
    end

    def frozen_in?(st, holder, now)
      st['grants'].values.any? do |e|
        e['rec']['holder'] == holder && (e['review']&.fetch('outcome') == 'unjustified' ||
          (e['review'].nil? && !e['uses'].empty? && now >= e['uses'][0]['at'] + e['rec']['review_within']))
      end
    end
  end
end
