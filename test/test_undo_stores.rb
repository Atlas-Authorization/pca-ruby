# frozen_string_literal: true

# The undo ledger stores (memory and over a durable kv) against one contract, plus the coordinator helpers.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'
require 'tmpdir'

class TestUndoStores < Minitest::Test
  A = AtlasPca

  def rec(id, state: 'open', ver: 0, window_end: 100, **extra)
    { 'v' => 1, 'id' => id, 'state' => state, 'ver' => ver, 'window_end' => window_end, 'receipts' => [] }.merge(extra.transform_keys(&:to_s))
  end

  def each_store
    yield A::MemoryUndoStore.new, false
    yield A::KvUndoStore.new(A.create_memory_durable_kv, false), false
    Dir.mktmpdir('pca-undo') { |d| yield A::KvUndoStore.new(A.open_durable_state(dir: d), true), true }
  end

  def test_contract
    each_store do |s, durable|
      assert A.undo_store?(s)
      assert_equal durable, s.durable
      assert_nil s.get('a')
      assert_equal({ 'created' => true }, s.create(rec('a')))
      again = s.create(rec('a', ver: 5))
      assert_equal [false, 0], [again['created'], again['record']['ver']]
      assert_equal 0, s.get('a')['ver']
      refute s.replace('a', 3, rec('a', ver: 1))
      assert s.replace('a', 0, rec('a', ver: 1, state: 'vetoed'))
      assert_equal %w[vetoed 1], [s.get('a')['state'], s.get('a')['ver'].to_s]
      assert_raises(A::UndoError) { s.replace('a', 1, rec('b')) }
      refute s.replace('zz', 0, rec('zz'))
      copy = s.get('a')
      copy['state'] = 'mutated'
      assert_equal 'vetoed', s.get('a')['state'] # a store hands out copies
    end
  end

  def test_list_filters_orders_and_limits
    each_store do |s, _|
      s.create(rec('c', window_end: 30, grant_ref: 'g1'))
      s.create(rec('a', window_end: 10, grant_ref: 'g1'))
      s.create(rec('b', window_end: 20, grant_ref: 'g2', bond_ref: 'b1'))
      s.create(rec('d', state: 'finalized', window_end: 5))
      assert_equal %w[a b c], s.list({ 'state' => 'open' }).map { |r| r['id'] }
      assert_equal %w[a b], s.list({ 'state' => 'open', 'window_ended_by' => 20 }).map { |r| r['id'] }
      assert_equal %w[a c], s.list({ 'state' => 'open', 'grant_ref' => 'g1' }).map { |r| r['id'] }
      assert_equal %w[b], s.list({ 'state' => 'open', 'bond_ref' => 'b1' }).map { |r| r['id'] }
      assert_equal %w[a], s.list({ 'state' => 'open', 'limit' => 1 }).map { |r| r['id'] }
      assert_equal %w[d], s.list({ 'state' => 'finalized' }).map { |r| r['id'] }
    end
  end

  def test_ids_and_construction_are_validated
    s = A::MemoryUndoStore.new
    [nil, '', "a\nb", 'x' * 257].each { |id| assert_raises(A::UndoError) { s.create(rec(id)) } }
    assert_raises(A::UndoError) { A::KvUndoStore.new(Object.new, true) }
    assert_raises(A::UndoError) { A::KvUndoStore.new(A.create_memory_durable_kv, 'yes') }
    assert_raises(A::UndoError) { A::KvUndoStore.new(A.create_memory_durable_kv, true).get('') }
    refute A.undo_store?(nil)
    refute A.undo_store?(Object.new)
  end

  def test_a_malformed_stored_record_is_corrupt
    kv = A.create_memory_durable_kv
    kv.set('pca-undo/v1/x', { 'id' => 'x' })
    e = assert_raises(A::UndoError) { A::KvUndoStore.new(kv, false).get('x') }
    assert_equal 'store_corrupt', e.code
  end

  def test_clip_units_never_splits_a_surrogate_pair
    assert_equal 'abc', A.clip_units('abcdef', 3)
    assert_equal 'ab', A.clip_units("ab\u{1F600}cd", 3) # the cut would split the pair
    assert_equal "ab\u{1F600}", A.clip_units("ab\u{1F600}cd", 4)
    assert_equal 'ab', A.clip_units('ab', 5)
  end

  def test_signer_public_missing_components_and_report_effect
    seed = "\x07".b * 32
    assert_equal A::KeyPair.new(seed).public, A.undo_signer_public(seed)
    assert_equal %w[store engine signer_secret audience resolve_grant compensate operations notifier alert], A.missing_undo_components(nil)
    calls = []
    co = Object.new
    co.define_singleton_method(:record_effect) { |id, r| calls << [:effect, id, r]; :rec }
    co.define_singleton_method(:abort) { |id, why| calls << [:abort, id, why]; :aborted }
    co.define_singleton_method(:get) { |id| id == 'x' ? :got : nil }
    assert_equal :rec, A.report_undo_effect(co, 'i', { 'status' => 'committed', 'result' => { 'id' => 't' } })
    assert_equal :aborted, A.report_undo_effect(co, 'i', { 'status' => 'failed' })
    assert_equal :got, A.report_undo_effect(co, 'x', { 'status' => 'pending' })
    assert_raises(A::UndoError) { A.report_undo_effect(co, 'nope', { 'status' => 'uncertain' }) }
    assert_equal [[:effect, 'i', { 'id' => 't' }], [:abort, 'i', 'effect_failed']], calls
  end

  def test_notifier_over_a_dispatcher
    sent = []
    ch = A::ApprovalChannels.text_approval_channel('email', 'send' => ->(b) { sent << b; {} })
    n = A.undo_notifier_from_dispatcher(A::ApprovalChannels.create_approval_dispatcher([ch]), 'undo_url' => ->(t, id) { "https://u/#{id}?t=#{t}" })
    r = { 'id' => 'r1', 'action' => { 'verb' => 'refund', 'resource' => 'ch_1' }, 'compensation' => { 'verb' => 'refund_undo' }, 'window_end' => 1_700_000_000_000, 'opened_at' => 1 }
    out = n.notify({ 'kind' => 'opened', 'record' => r, 'token' => 'tok' })
    assert_equal({ 'delivered' => true }, out)
    assert_match(/Already done: refund on ch_1\. You can undo it until 2023-11-14T22:13:20\.000Z\./, sent[0]['text'])
    none = A.undo_notifier_from_dispatcher(A::ApprovalChannels.create_approval_dispatcher([A::ApprovalChannels.slack_approval_channel]), {})
    assert_equal({ 'delivered' => false, 'reason' => 'no enabled channel' }, none.notify({ 'kind' => 'finalized', 'record' => r }))
  end

  def test_hosted_relay
    seen = nil
    body = JSON.generate('data' => [{ 'record_id' => 'r1', 'veto' => { 'token' => 't', 'at' => 5 } }])
    relay = A.hosted_undo_veto_relay('base_url' => 'https://h//', 'secret_key' => 'sk', 'limit' => 999, 'fetch' => lambda { |url, h|
      seen = [url, h['authorization']]
      { 'ok' => true, 'status' => 200, 'body' => body }
    })
    assert_equal [{ 'id' => 'r1', 'token' => 't', 'at' => 5 }], relay.pending
    assert_equal ['https://h/v1/pca/undo/vetoes?limit=200', 'Bearer sk'], seen
    bad = ->(b, ok = true) { A.hosted_undo_veto_relay('base_url' => 'https://h', 'secret_key' => 's', 'fetch' => ->(*) { { 'ok' => ok, 'status' => ok ? 200 : 500, 'body' => b } }) }
    assert_raises(A::UndoError) { bad.call('{}', false).pending }
    assert_raises(A::UndoError) { bad.call('{}').pending }
    assert_raises(A::UndoError) { bad.call('{"data":[{"record_id":1}]}').pending }
  end
end
