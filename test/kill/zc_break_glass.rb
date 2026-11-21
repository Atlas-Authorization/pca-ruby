# frozen_string_literal: true

# zc break-glass: BreakGlassRegistry state handling that the signature-level tests do not reach (corrupt shards, an unready or
# deaf store, the stored record shape, a frozen holder leaving its grants alone). Signature verification is stubbed.
module MutationKill
  module ZCBg
    module_function

    POLICY = { 'authorities' => ['A'], 'reviewers' => ['R'] }.freeze

    def rec(over = {})
      { 'v' => 1, 'id' => 'g1', 'holder' => 'h1', 'grant_ref' => 'gr', 'reason_digest' => 'rd', 'max_uses' => 3, 'issued_at' => 1000,
        'expires_at' => 5000, 'review_within' => 1000, 'notify_to' => 'n', 'authority' => 'A', 'sig' => 'sg1' }.merge(over)
    end

    def review(over = {}) = { 'v' => 1, 'id' => 'g1', 'outcome' => 'justified', 'notes_digest' => 'nd', 'at' => 1600, 'reviewer' => 'R', 'sig' => 'rv1' }.merge(over)
    def stubbed(&blk) = ZC.seam(AtlasPca, { verify_break_glass: ->(_r) { true }, verify_break_glass_review: ->(_r) { true } }, &blk)
    def kv = AtlasPca::MemoryBreakGlassKv.new
    def reg(kv = self.kv) = AtlasPca::BreakGlassRegistry.new(POLICY, kv)
    def key_of(holder, shards = 16) = "breakglass/#{shards}/#{AtlasPca.kv_shard_of(holder, shards)}"
    def seeded_shard = { 'grants' => { 'g1' => { 'rec' => rec, 'uses' => [{ 'n' => 1, 'action_digest' => 'ad', 'at' => 1500 }], 'review' => nil } } }

    # a kv whose shard-count pin disagrees with the registry's: the registry is never ready
    def foreign_kv
      k = self.kv
      k.set('breakglass/meta', { 'v' => 1, 'shards' => 99 })
      k.set(key_of('h1'), seeded_shard)
      k
    end

    # an atomic kv that never runs the update block of anything but the shard-count pin
    class DeafKv
      def initialize = @inner = AtlasPca::MemoryBreakGlassKv.new
      def get(key) = @inner.get(key)
      def update(key, &blk) = key == 'breakglass/meta' ? @inner.update(key, &blk) : nil
    end

    # a kv that hands out the stored objects themselves (no copies)
    class RefKv
      def initialize = @m = {}
      def get(key) = @m[key]

      def update(key)
        nxt = yield(@m[key])
        @m[key] = nxt unless nxt.nil?
        @m[key]
      end
    end
  end

  t('zc break-glass: a corrupt stored shard reads as an empty one') do
    next true unless ZC.gate?('break_glass.rb')

    ['text', 5, [], {}, { 'grants' => 'g1xx' }, { 'grants' => [] }, { 'grants' => nil }, { 'other' => 1 }].each_with_index do |g, i|
      kv = ZCBg.kv
      r = ZCBg.reg(kv)
      ZC.eq("pin #{i}", r.uses('h1', 'g1'), [])
      kv.set(ZCBg.key_of('h1'), g)
      ZC.eq("uses #{i}", r.uses('h1', 'g1'), [])
    end
    true
  end

  t('zc break-glass: the shard count is pinned once and not re-read after') do
    next true unless ZC.gate?('break_glass.rb')

    kv = ZCBg.kv
    r = ZCBg.reg(kv)
    ZC.eq('first read', r.uses('h1', 'g1'), []) &&
      begin
        kv.set(ZCBg.key_of('h1'), ZCBg.seeded_shard)
        kv.set('breakglass/meta', { 'v' => 1, 'shards' => 99 })
        ZC.eq('memoized readiness', r.uses('h1', 'g1'), [{ 'n' => 1, 'action_digest' => 'ad', 'at' => 1500 }])
      end
  end

  t('zc break-glass: a registry whose store is not ready refuses with exact store_unreachable answers') do
    next true unless ZC.gate?('break_glass.rb')

    ZCBg.stubbed do
      r = ZCBg.reg(ZCBg.foreign_kv)
      ZC.eq('uses', r.uses('h1', 'g1'), []) &&
        ZC.eq('accept', r.accept(ZCBg.rec({ 'id' => 'g9', 'sig' => 'sg9' }), 1000), { 'ok' => false, 'code' => 'store_unreachable' }) &&
        ZC.eq('use', r.use('g1', 'h1', 'ad2', 1600, true), { 'decision' => 'deny', 'code' => 'store_unreachable', 'id' => 'g1' }) &&
        ZC.eq('review', r.review(ZCBg.review, 'h1', 2000), { 'ok' => false, 'code' => 'store_unreachable' }) &&
        ZC.eq('frozen', r.frozen('h1', 1000), true) && ZC.eq('frozen, nobody', r.frozen('nobody', 1000), true)
    end
  end

  t('zc break-glass: an update block that never runs leaves the exact default answers') do
    next true unless ZC.gate?('break_glass.rb')

    ZCBg.stubbed do
      r = ZCBg.reg(ZCBg::DeafKv.new)
      ZC.eq('accept', r.accept(ZCBg.rec, 1000), { 'ok' => false, 'code' => 'store_unreachable' }) &&
        ZC.eq('use', r.use('g1', 'h1', 'ad2', 1600, true), { 'decision' => 'deny', 'code' => 'store_unreachable', 'id' => 'g1' }) &&
        ZC.eq('review', r.review(ZCBg.review, 'h1', 2000), { 'ok' => false, 'code' => 'store_unreachable' })
    end
  end

  t('zc break-glass: a stored grant has exactly rec, uses and review; a frozen holder leaves its other grants untouched') do
    next true unless ZC.gate?('break_glass.rb')

    ZCBg.stubbed do
      kv = ZCBg.kv
      r = ZCBg.reg(kv)
      g1 = ZCBg.rec
      ZC.eq('accept', r.accept(g1, 1000), { 'ok' => true, 'replaced' => true }) &&
        ZC.eq('stored shape', kv.get(ZCBg.key_of('h1'))['grants']['g1'], { 'rec' => g1, 'uses' => [], 'review' => nil }) &&
        ZC.eq('use', r.use('g1', 'h1', 'ad1', 1500, true), { 'decision' => 'allow', 'id' => 'g1', 'use' => 1, 'remaining' => 2, 'review_due' => 2500 }) &&
        begin
          before = kv.get(ZCBg.key_of('h1'))
          # 2600 >= first use (1500) + review_within (1000) with no review: the holder is frozen
          ZC.eq('frozen', r.frozen('h1', 2600), true) &&
            ZC.eq('second grant refused', r.accept(ZCBg.rec({ 'id' => 'g2', 'sig' => 'sg2' }), 2600), { 'ok' => false, 'code' => 'holder_frozen' }) &&
            ZC.eq('store untouched', kv.get(ZCBg.key_of('h1')), before) &&
            ZC.eq('the first grant keeps its use', r.uses('h1', 'g1'), [{ 'n' => 1, 'action_digest' => 'ad1', 'at' => 1500 }])
        end
    end
  end

  t('zc break-glass: uses hands out copies of the stored use entries') do
    next true unless ZC.gate?('break_glass.rb')

    ZCBg.stubbed do
      r = ZCBg.reg(ZCBg::RefKv.new)
      r.accept(ZCBg.rec, 1000)
      r.use('g1', 'h1', 'ad1', 1500, true)
      got = r.uses('h1', 'g1')
      got[0]['n'] = 99
      got << { 'n' => 100 }
      ZC.eq('stored entries are unchanged', r.uses('h1', 'g1'), [{ 'n' => 1, 'action_digest' => 'ad1', 'at' => 1500 }])
    end
  end
end
