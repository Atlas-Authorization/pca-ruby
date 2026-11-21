# frozen_string_literal: true

# Bond settlement over the durable bond store (StoreBondLedger): exact micro-unit arithmetic, the slash split, the signed records, the fail-closed
# refusals and the retry semantics. Hand-written; the store itself is replayed against the reference in test_ref_core_stores.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestBondSettlement < Minitest::Test
  A = AtlasPca
  S = AtlasPca::BondSettlement
  G = A::KeyPair.new("\x04".b * 32)

  def ledger(clock) = A::StoreBondLedger.new(A::KvBondStore.new(A::MemoryAtomicKv.new), G, clock: -> { clock[0] })

  def test_micro_unit_arithmetic_is_exact
    d = A::BondStoreDocs
    assert_in_delta 0.3, d.exact_add(0.1, 0.2, 1), 0
    assert_equal 0.3, d.exact_add(0.1, 0.2, 1)
    assert_equal 0.999999, d.exact_add(1, 0.000001, -1)
    assert_equal({ 'a' => 2.5 }, d.apply_bond_moves(->(_a) { 5 }, [{ 'account' => 'a', 'op' => 'debit', 'amount' => 2.5 }]))
    assert_raises(ArgumentError) { d.apply_bond_moves(->(_a) { 1 }, [{ 'account' => 'a', 'op' => 'debit', 'amount' => 2 }]) } # an overdraft applies nothing
    assert_equal 1, S.bond_amount(S.default_bond_policy, 0)
    assert_equal 6.6, S.bond_amount({ 'floor' => 1, 'k' => 2, 'maxOpenClaims' => 1, 'maxOpenAmount' => 1 }, 3.3)
  end

  def test_the_slash_split_sums_exactly
    pol = { 'challengerBps' => 5000, 'victimBps' => 4000 }
    s = S.compute_slash_split(100, pol, { 'challengerAccount' => 'ch', 'victimAccount' => 'v', 'treasuryAccount' => 't' })
    assert_equal [50, 40, 10], [s['challengerReward'], s['victimCompensation'], s['treasuryRemainder']].map(&:to_i)
    anon = S.compute_slash_split(7.25, pol, { 'challengerAccount' => nil, 'victimAccount' => 'v', 'treasuryAccount' => 't' })
    assert_equal [7.25, 0], [anon['treasuryRemainder'], anon['challengerReward']]
    f = S.compute_slash_split(10.333333, { 'challengerBps' => 3333, 'victimBps' => 3333 }, { 'challengerAccount' => 'c', 'victimAccount' => 'v', 'treasuryAccount' => 't' })
    d = A::BondStoreDocs
    assert_equal 10.333333, d.exact_add(d.exact_add(f['challengerReward'], f['victimCompensation'], 1), f['treasuryRemainder'], 1)
    assert_raises(ArgumentError) { S.compute_slash_split(1, { 'challengerBps' => 9000, 'victimBps' => 2000 }, { 'victimAccount' => 'v', 'treasuryAccount' => 't' }) }
  end

  def test_open_release_and_retry_semantics
    clock = [1_000]
    b = ledger(clock)
    assert_equal 100, b.deposit('alice', 100)
    assert_equal 'none', b.bond_status('c1')
    rec = b.open_bond('c1', 40, 'alice')
    assert S.verify_settlement(rec, G.public)
    assert_equal [60, 'open'], [b.balance_of('alice'), b.bond_status('c1')]
    assert_equal rec, b.open_bond('c1', 40, 'alice') # a retried open returns the original record
    assert_equal 'conflict', assert_raises(A::BondStoreError) { b.open_bond('c1', 41, 'alice') }.code
    out = b.release_unregistered('c1')
    assert_equal 'release', out['action']
    assert S.verify_settlement(out, G.public)
    assert_equal 100, b.balance_of('alice')
    assert_equal out, b.release_unregistered('c1') # idempotent under retry
    assert_equal 'released', b.bond_status('c1')
  end

  def test_refusals_fail_closed
    b = ledger([1_000])
    b.deposit('alice', 10)
    assert_raises(ArgumentError) { b.open_bond('big', 50, 'alice') } # insufficient balance
    assert_raises(ArgumentError) { b.release_unregistered('nothing') }
    bad = A::StoreBondLedger.new(A::KvBondStore.new(A::MemoryAtomicKv.new), G, clock: -> { Float::NAN })
    assert_equal 'clock_invalid', assert_raises(A::BondStoreError) { bad.open_bond('x', 1, 'alice') }.code
    assert_equal 'store_missing', assert_raises(A::BondStoreError) { A::StoreBondLedger.new(nil, G) }.code
    assert_equal 'guardian_key_missing', assert_raises(A::BondStoreError) { A::StoreBondLedger.new(A::KvBondStore.new(A::MemoryAtomicKv.new), nil) }.code
    assert_includes %w[unregistered store_unavailable], assert_raises(A::BondStoreError) { b.challenge_status('c9') }.code
  end

  def test_a_clock_that_steps_back_cannot_release_early
    clock = [5_000]
    b = ledger(clock)
    b.deposit('alice', 10)
    b.open_bond('c', 5, 'alice')
    clock[0] = 1 # the store's high-water mark keeps "now" from going backwards
    b.release_unregistered('c')
    assert_operator b.get_bond('c')['records'][-1]['at'], :>=, 5_000
  end
end
