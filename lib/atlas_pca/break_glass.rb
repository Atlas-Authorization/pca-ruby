# frozen_string_literal: true

# Break-glass grants (verification side): time-boxed, loud, auto-revoked, with a mandatory signed review. BreakGlassRegistry is
# in memory, state grouped by holder (as the TypeScript registry shards by holder). Every function is total.
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

  class BreakGlassRegistry
    # policy: { 'authorities' => [...], 'reviewers' => [...] }
    def initialize(policy)
      @policy = policy
      @holders = {} # holder => { id => { rec:, uses: [], review: } }
    end

    def accept(rec, now)
      return { 'ok' => false, 'code' => 'bad_record' } unless AtlasPca.verify_break_glass(rec) && AtlasPca.k3_int?(now)
      return { 'ok' => false, 'code' => 'unknown_authority' } unless @policy['authorities'].include?(rec['authority'])

      st = (@holders[rec['holder']] ||= {})
      cur = st[rec['id']]
      return cur[:rec]['sig'] == rec['sig'] ? { 'ok' => true, 'replaced' => false } : { 'ok' => false, 'code' => 'id_conflict' } unless cur.nil?
      return { 'ok' => false, 'code' => 'holder_frozen' } if frozen_in?(st, rec['holder'], now)

      st[rec['id']] = { rec: rec, uses: [], review: nil }
      { 'ok' => true, 'replaced' => true }
    rescue StandardError
      { 'ok' => false, 'code' => 'store_unreachable' }
    end

    # i: { 'id', 'holder', 'action_digest', 'now', 'notified' }
    def use(id, holder, action_digest, now, notified)
      return { 'decision' => 'deny', 'code' => 'bad_input' } unless AtlasPca.k3_str?(id, 128) && AtlasPca.k3_str?(holder, 128) && AtlasPca.k3_str?(action_digest, 128) &&
                                                                    AtlasPca.k3_int?(now) && [true, false].include?(notified)

      deny = ->(code) { { 'decision' => 'deny', 'code' => code, 'id' => id } }
      st = @holders[holder] || {}
      e = st[id]
      return deny.call('unknown_break_glass') if e.nil?
      return deny.call('holder_frozen') if frozen_in?(st, holder, now)
      return deny.call('revoked') if e[:review] && e[:review]['outcome'] == 'unjustified'
      return deny.call('not_yet_valid') if now < e[:rec]['issued_at']
      return deny.call('expired') if now >= e[:rec]['expires_at']
      return deny.call('budget_exhausted') if e[:uses].length >= e[:rec]['max_uses']
      return deny.call('not_notified') unless notified

      e[:uses] << { 'n' => e[:uses].length + 1, 'action_digest' => action_digest, 'at' => now }
      { 'decision' => 'allow', 'id' => id, 'use' => e[:uses].length, 'remaining' => e[:rec]['max_uses'] - e[:uses].length,
        'review_due' => e[:uses][0]['at'] + e[:rec]['review_within'] }
    rescue StandardError
      { 'decision' => 'deny', 'code' => 'store_unreachable', 'id' => id }
    end

    def review(rec, holder, now)
      return { 'ok' => false, 'code' => 'bad_record' } unless AtlasPca.verify_break_glass_review(rec) && AtlasPca.k3_str?(holder, 128) && AtlasPca.k3_int?(now)
      return { 'ok' => false, 'code' => 'unknown_reviewer' } unless @policy['reviewers'].include?(rec['reviewer'])

      e = (@holders[holder] || {})[rec['id']]
      return { 'ok' => false, 'code' => 'unknown_break_glass' } if e.nil?
      return { 'ok' => false, 'code' => 'sod' } if rec['reviewer'] == e[:rec]['holder'] || rec['reviewer'] == e[:rec]['authority']
      unless e[:review].nil?
        return e[:review]['sig'] == rec['sig'] ? { 'ok' => true, 'replaced' => false } : { 'ok' => false, 'code' => 'already_reviewed' }
      end
      return { 'ok' => false, 'code' => 'nothing_to_review' } if e[:uses].empty?
      return { 'ok' => false, 'code' => 'bad_time' } if rec['at'] < e[:uses][0]['at'] || rec['at'] > now

      e[:review] = rec
      { 'ok' => true, 'replaced' => true }
    rescue StandardError
      { 'ok' => false, 'code' => 'store_unreachable' }
    end

    def frozen(holder, now)
      return true unless AtlasPca.k3_str?(holder, 128) && AtlasPca.k3_int?(now) # fail closed

      frozen_in?(@holders[holder] || {}, holder, now)
    rescue StandardError
      true
    end

    private

    def frozen_in?(st, holder, now)
      st.values.any? do |e|
        e[:rec]['holder'] == holder && (e[:review]&.fetch('outcome') == 'unjustified' ||
          (e[:review].nil? && !e[:uses].empty? && now >= e[:uses][0]['at'] + e[:rec]['review_within']))
      end
    end
  end
end
