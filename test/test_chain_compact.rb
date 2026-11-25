# frozen_string_literal: true

# Compact chains, the verifier memo, the caveat language over a memoized view, the cheap chain check and holder_pq_key.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestChainCompact < Minitest::Test
  A = AtlasPca

  def setup
    @p = A::KeyPair.new("\x01".b * 32)
    @h = A::KeyPair.new("\x02".b * 32)
    @s = A::KeyPair.new("\x03".b * 32)
    @root = A.mint_root(@p, @h.public, [{ 'type' => 'note', 'v' => 1 }])
    @child = A.delegate_cap(@root, @h, to_holder: @s.public, added: [{ 'type' => 'note', 'v' => 2 }])
    @chain = [@root, @child]
  end

  def test_compact_chain_and_shape
    c = A.compact_chain(@chain)
    assert_equal [1, 'pca-chain-compact', 2, A.hops_root(@chain), @child], c.values_at('v', 'kind', 'depth', 'hops_root', 'leaf')
    assert_nil A.compact_chain_shape_error(c)
    assert_match(/depth/, A.compact_chain_shape_error(c.merge('depth' => 0)))
    assert_match(/43/, A.compact_chain_shape_error(c.merge('hops_root' => 'x')))
    assert_match(/unknown member/, A.compact_chain_shape_error(c.merge('z' => 1)))
    assert_equal 'not an object', A.compact_chain_shape_error(nil)
    assert_raises(ArgumentError) { A.compact_chain([]) }
    refute_equal A.hops_root(@chain), A.hops_root([@root])
    refute_equal A.hops_root(@chain), A.hops_root(@chain.reverse)
  end

  def test_memo_remembers_only_verified_chains_and_resolves_a_compact_one
    memo = A::ChainMemo.new
    c = memo.remember_verified(@chain, @p.public, 1000)
    assert_equal 1, memo.size
    r = memo.resolve(c, 2000)
    assert_equal true, r['ok']
    v = r['view']
    assert_equal [2, @child, A.cap_hash(@child), 2], [v.n, v.leaf, v.hash(1), v.count(1)]
    assert_equal 1, v.count(0)
    # the caveat language decides identically through the view
    assert_equal A.bound_caveats(@root, @chain), A.bound_caveats(@root, v)
    assert_equal A.discharge_requests(@root, @chain), A.discharge_requests(@root, v)
    bad = @chain.map(&:dup)
    bad[1]['sig'] = bad[0]['sig']
    assert_raises(ArgumentError) { A::ChainMemo.new.remember_verified(bad, @p.public, 1000) }
    assert_raises(ArgumentError) { A::ChainMemo.new.remember_verified(@chain, @s.public, 1000) }
  end

  def test_resolve_refuses_unknown_wrong_depth_wrong_leaf_and_expired
    memo = A::ChainMemo.new(ttl_ms: 100)
    c = memo.remember_verified(@chain, @p.public, 1000)
    other = A::ChainMemo.new
    assert_match(/not in this verifier memo/, other.resolve(c, 1000)['reason'])
    assert_match(/depth differs/, memo.resolve(c.merge('depth' => 1), 1000)['reason'])
    assert_match(/not the memoized last hop/, memo.resolve(c.merge('leaf' => @root), 1000)['reason'])
    assert_match(/clock/, memo.resolve(c, 1.5)['reason'])
    assert_match(/malformed compact chain/, memo.resolve({}, 1000)['reason'])
    assert_match(/expired/, memo.resolve(c, 1101)['reason'])
    assert_equal 0, memo.size
    refute memo.forget('x')
  end

  def test_full_memo_never_evicts_a_live_entry
    memo = A::ChainMemo.new(max_entries: 1)
    memo.remember_verified(@chain, @p.public, 1000)
    memo.remember_verified(@chain, @p.public, 1001) # the same root refreshes
    assert_raises(ArgumentError) { memo.remember_verified([@root], @p.public, 1002) }
    memo.prune(10_000_000)
    assert_equal 0, memo.size
    memo.remember_verified([@root], @p.public, 10_000_001)
    assert_equal 1, memo.size
  end

  def test_cheap_chain_check
    assert_equal({ 'ok' => true, 'pq_hops' => 0 }, A.verify_chain_cheap(@chain, @p.public))
    assert_equal 'empty chain', A.verify_chain_cheap([])['reason']
    assert_match(/expected principal/, A.verify_chain_cheap(@chain, @s.public)['reason'])
    assert_match(/not allowed/, A.verify_chain_cheap(@chain, nil, allowed_suites: ['ml-dsa-65'])['reason'])
    assert_match(/broken parent link/, A.verify_chain_cheap([@root, @root])['reason'])
    t = @chain.map(&:dup)
    t[1]['caveats'] = t[1]['caveats'] + [{ 'type' => 'x' }]
    assert_match(/body digest mismatch/, A.verify_chain_cheap(t)['reason'])
    f = @chain.map(&:dup)
    f[1]['sig'] = f[0]['sig']
    assert_match(/bad signature/, A.verify_chain_cheap(f)['reason'])
    assert_match(/malformed capability/, A.verify_chain_cheap([{ 'a' => 1 }])['reason'])
    assert_match(/unknown signature alg/, A.verify_chain_cheap([@root.merge('alg' => 'rsa')])['reason'])
  end

  def test_holder_pq_key
    assert_nil A.holder_pq_key(nil, 'h', 'k', nil)
    assert_nil A.holder_pq_key('ed25519', 'h', 'k', nil)
    pk = A.b64e('a'.b * 1952)
    assert_nil A.holder_pq_key('ml-dsa-65', 'h', pk, nil)
    assert_nil A.holder_pq_key('ml-dsa-65', 'h', pk, 'wrong')
    k = A.holder_pq_key('ml-dsa-65', 'h', pk, A.holder_pq_commitment(pk))
    assert_equal [pk, 'holder-commitment'], [k.key, k.source]
  end
end
