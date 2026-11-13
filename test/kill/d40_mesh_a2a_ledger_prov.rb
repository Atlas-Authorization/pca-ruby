# frozen_string_literal: true
# d40: round-3 kill tests for mesh.rb, a2a.rb, ledger.rb, provenance_gate.rb and blueprint.rb (survivors of c27 / c30 / c31).
# Everything under AtlasPca is resolved at CALL time inside each test block. Helpers of c27 (C27, C27M, C27T) are reused.
require 'digest'
require 'openssl'

module MutationKill
  module D40
    # Answers == with true to everything, is not a String / Integer / Hash: a stand-in for "a non-X value that compares equal".
    class AlwaysEq
      def ==(_other) = true
    end

    module_function

    def only?(file) = MutationKill::C27.only?(file)
    def ck(got, want) = MutationKill::C27.ck(got, want)
    def x43 = AtlasPca.b64e(AtlasPca.sha('d40-x'))

    def spy_calls(mod, name, ret = :orig)
      calls = []
      orig = mod.method(name)
      impl = ->(*a) { calls << a; ret == :orig ? orig.call(*a) : ret }
      [calls, impl]
    end
  end

  # ---------------------------------------------------- constants are frozen ----------------------------------------------
  t('d40 a2a: the receipt domain constant is frozen') do
    next true unless D40.only?('a2a.rb')

    AtlasPca::A2A_RECEIPT_DOMAIN.frozen?.equal?(true)
  end

  t('d40 blueprint: the blueprint domain constant is frozen') do
    next true unless D40.only?('blueprint.rb')

    AtlasPca::AGENT_BLUEPRINT_DOMAIN.frozen?.equal?(true)
  end

  t('d40 ledger: the empty tree root constant is frozen') do
    next true unless D40.only?('ledger.rb')

    AtlasPca::EMPTY_TREE_ROOT.frozen?.equal?(true)
  end

  # ---------------------------------------------------------- a2a.rb ------------------------------------------------------
  t('d40 a2a: a shorter hop whose missing tail is nil is still not an extension (length compared first)') do
    next true unless D40.only?('a2a.rb')

    ne = { 'ok' => false, 'failedHop' => 1, 'reason' => 'chain_does_not_extend_previous_hop' }
    D40.ck(AtlasPca.check_a2a_chain_extension([['a', nil], ['a']]), ne) &&
      D40.ck(AtlasPca.check_a2a_chain_extension([['a', nil], ['a', nil]]), { 'ok' => true })
  end

  # --------------------------------------------------------- ledger.rb -----------------------------------------------------
  t('d40 ledger: consistency refuses a non-String old root even when it compares equal to everything') do
    next true unless D40.only?('ledger.rb')

    pf = { 'oldSize' => 0, 'newSize' => 0, 'path' => [] }
    e = AtlasPca::EMPTY_TREE_ROOT
    D40.ck(AtlasPca.verify_ledger_consistency(D40::AlwaysEq.new, e, pf), false) &&
      D40.ck(AtlasPca.verify_ledger_consistency(e, e, pf), true)
  end

  t('d40 ledger: the consistency path bound of 108 is applied before any hash is decoded (b64d spy)') do
    next true unless D40.only?('ledger.rb')

    x = D40.x43
    run = lambda do |n|
      calls, spy = D40.spy_calls(AtlasPca, :b64d)
      r = MutationKill::Seam.with(AtlasPca, { b64d: spy }) do
        AtlasPca.verify_ledger_consistency(x, x, { 'oldSize' => 3, 'newSize' => 4, 'path' => [x] * n })
      end
      [r, calls.length]
    end
    D40.ck(run.(109), [false, 0]) && D40.ck(run.(108), [false, 108])
  end

  t('d40 ledger: head consistency needs both proof sizes safe integers equal to the heads sizes (consistency spy)') do
    next true unless D40.only?('ledger.rb')

    older = { 'instance_id' => 'i', 'principal' => 'p', 'size' => 2, 'root' => 'ra', 'prev_root' => 'r0' }
    newer = { 'instance_id' => 'i', 'principal' => 'p', 'size' => 4, 'root' => 'rb', 'prev_root' => 'ra' }
    run = lambda do |old_size, new_size|
      calls, spy = D40.spy_calls(AtlasPca, :verify_ledger_consistency, true)
      r = MutationKill::Seam.with(AtlasPca, { verify_tree_head: ->(*) { true }, verify_ledger_consistency: spy }) do
        AtlasPca.verify_head_consistency(older, newer, { 'oldSize' => old_size, 'newSize' => new_size, 'path' => [] }, 'g')
      end
      [r, calls.length]
    end
    eq = D40::AlwaysEq.new
    [
      [run.(2, 4), [true, 1]], [run.(2.0, 4.0), [true, 1]],
      [run.(3, 4), [false, 0]], [run.(eq, 4), [false, 0]], [run.(2, 5), [false, 0]], [run.(2, eq), [false, 0]]
    ].all? { |got, want| D40.ck(got, want) }
  end

  # ------------------------------------------------------ provenance_gate.rb ------------------------------------------------
  t('d40 provenance: RFC 9162 inclusion refuses index >= size and a proof node that is not 32 bytes') do
    next true unless D40.only?('provenance_gate.rb')

    leaf = AtlasPca.rfc9162_leaf_hash('d40')
    p32 = 'p' * 32
    p31 = 'p' * 31
    root32 = Digest::SHA256.digest("\x01".b + leaf + p32.b)
    root31 = Digest::SHA256.digest("\x01".b + leaf + p31.b)
    v = ->(*a) { AtlasPca.verify_rfc9162_inclusion(*a) }
    [
      [v.(leaf, 0, 1, [], leaf), true], [v.(leaf, 1, 1, [], leaf), false], [v.(leaf, 2, 1, [], leaf), false],
      [v.(leaf, 0, 2, [p32], root32), true], [v.(leaf, 0, 2, [p31], root31), false]
    ].all? { |got, want| D40.ck(got, want) }
  end

  # ---------------------------------------------------------- mesh.rb -----------------------------------------------------
  t('d40 mesh: mesh_msg is a binary string') do
    next true unless D40.only?('mesh.rb')

    m = AtlasPca.mesh_msg(AtlasPca::MESH_HEAD_DOMAIN, { 'a' => 1 })
    D40.ck(m.encoding, Encoding::BINARY) && D40.ck(m, "atlas-pca/mesh-head/v1\x00".b + '{"a":1}'.b)
  end

  t('d40 mesh: a negative leaf index is refused even when its path shape matches') do
    next true unless D40.only?('mesh.rb')

    root1 = AtlasPca::IntentV2.bind_root(1, AtlasPca.b64e(AtlasPca.leaf_hash('a')))
    lo = ->(idx) { AtlasPca.mesh_leaf_ok?(root1, 1, 'a', { 'size' => 1, 'index' => idx, 'path' => [] }) }
    D40.ck(lo.(0), true) && D40.ck(lo.(-1), false)
  end

  t('d40 mesh: the leaf index reaches path_shape as an Integer') do
    next true unless D40.only?('mesh.rb')

    lhs = C27T.lh(%w[a b c])
    root = AtlasPca::IntentV2.bind_root(3, AtlasPca.b64e(AtlasPca.build(lhs)))
    pf = C27T.incl(lhs, 1).merge('index' => 1.0)
    seen = []
    orig = AtlasPca.method(:path_shape)
    spy = ->(m, n) { seen << [m, n]; orig.call(m, n) }
    r = MutationKill::Seam.with(AtlasPca, { path_shape: spy }) { AtlasPca.mesh_leaf_ok?(root, 3, 'b', pf) }
    D40.ck(r, true) && D40.ck(seen[0].map(&:class), [Integer, Integer]) && D40.ck(seen[0], [1, 3])
  end

  t('d40 mesh: non-membership neighbour proofs must be Hashes before they are checked (leaf spy)') do
    next true unless D40.only?('mesh.rb')

    run = lambda do |nm, id|
      calls, spy = D40.spy_calls(AtlasPca, :mesh_leaf_ok?, true)
      r = MutationKill::Seam.with(AtlasPca, { mesh_leaf_ok?: spy }) { AtlasPca.mesh_non_membership?('r', nm, id) }
      [r, calls.length]
    end
    [
      [run.({ 'size' => 3, 'hi' => { 'id' => 'd', 'proof' => nil } }, 'c'), [false, 0]],
      [run.({ 'size' => 3, 'lo' => { 'id' => 'a', 'proof' => nil } }, 'c'), [false, 0]],
      # a negative size never reaches the leaf check
      [run.({ 'size' => -1, 'lo' => { 'id' => 'a', 'proof' => { 'index' => -2 } } }, 'c'), [false, 0]]
    ].all? { |got, want| D40.ck(got, want) }
  end

  t('d40 mesh: a non-String neighbour id is compared as the empty string') do
    next true unless D40.only?('mesh.rb')

    lhs2 = C27T.lh([''])
    root2 = AtlasPca::IntentV2.bind_root(1, AtlasPca.b64e(AtlasPca.build(lhs2)))
    pf2 = C27T.incl(lhs2, 0)
    seen = []
    orig = AtlasPca::V2JS.method(:compare_utf8)
    spy = ->(a, b) { seen << [a, b]; orig.call(a, b) }
    r = MutationKill::Seam.with(AtlasPca::V2JS, { compare_utf8: spy }) do
      AtlasPca.mesh_non_membership?(root2, { 'size' => 1, 'hi' => { 'id' => 5, 'proof' => pf2 } }, 'a')
    end
    D40.ck(r, false) && D40.ck(seen, [['a', '']])
  end

  t('d40 mesh: consistency path bound of 128 is applied before any hash is decoded (b64d spy)') do
    next true unless D40.only?('mesh.rb')

    x = D40.x43
    run = lambda do |n|
      calls, spy = D40.spy_calls(AtlasPca, :b64d)
      r = MutationKill::Seam.with(AtlasPca, { b64d: spy }) do
        AtlasPca.mesh_consistency?(x, x, { 'oldSize' => 3, 'newSize' => 4, 'path' => [x] * n })
      end
      [r, calls.length]
    end
    D40.ck(run.(129), [false, 0]) && D40.ck(run.(128), [false, 128])
  end

  t('d40 mesh: a cosignature without a String sig is skipped, never verified') do
    next true unless D40.only?('mesh.rb')

    tr = AtlasPca.mesh_valid_trust(C27M.trust)
    h = C27M.head(1, AtlasPca.b64e(AtlasPca.sha('r')))
    cs = C27M.cosig(h)
    calls, spy = D40.spy_calls(AtlasPca, :verify_b64u)
    r = MutationKill::Seam.with(AtlasPca, { verify_b64u: spy }) do
      AtlasPca.mesh_check_cosigned_head(C27M.cosigned(h, [{ 'witness' => cs['witness'], 'sig' => 5 }]), C27M.dom, tr, nil)
    end
    D40.ck(r, 'head has 0/1 trusted witness cosignatures') && D40.ck(calls.length, 1)
  end

  t('d40 mesh: a pinned-heads table is consulted only for a key it holds') do
    next true unless D40.only?('mesh.rb')

    root = AtlasPca.b64e(AtlasPca.sha('r'))
    h = C27M.head(1, root)
    ahead = C27M.head(5, root)
    f = lambda do |pinned|
      tr = AtlasPca.mesh_valid_trust(C27M.trust('pinnedHeads' => pinned))
      AtlasPca.mesh_check_cosigned_head(C27M.cosigned(h), C27M.dom, tr, nil)
    end
    D40.ck(f.(Hash.new(ahead)), nil) && D40.ck(f.({ C27M.dom => ahead }), 'head rolls back (vs pinned head)') && D40.ck(f.({}), nil)
  end

  t('d40 mesh: rootDomain must be a String, not merely something equal to an allowed domain') do
    next true unless D40.only?('mesh.rb')

    want = 'invalid trust configuration: rootDomain is required and must be in allowedDomains'
    D40.ck(AtlasPca.mesh_valid_trust(C27M.trust('rootDomain' => D40::AlwaysEq.new)), want) &&
      D40.ck(AtlasPca.mesh_valid_trust(C27M.trust('rootDomain' => 5)), want)
  end

  t('d40 mesh: a head whose domain is not a String is probed under the empty domain') do
    next true unless D40.only?('mesh.rb')

    seen, spy = D40.spy_calls(AtlasPca, :mesh_check_cosigned_head, nil)
    pf = C27M.proof([C27M.cap(0)], heads: ->(ch) { [ch.merge('head' => ch['head'].merge('domain' => 5))] })
    v = C27M.with_chain({ mesh_check_cosigned_head: spy }) { C27M.vd(C27M.run(pf)) }
    D40.ck(v, [false, 'source-domain anchor: head is for a different domain', 0]) && seen.length == 1 && D40.ck(seen[0][1], '')
  end

  t('d40 mesh: evidence table bounds (heads <= chain, revocation leaves <= 2 * chain)') do
    next true unless D40.only?('mesh.rb')

    leaf = { 'id' => 'x', 'proof' => { 'index' => 0, 'size' => 1, 'path' => [] } }
    bound = [false, 'evidence tables exceed chain size', -1]
    run = lambda do |&edit|
      pf = C27M.proof([C27M.cap(0)])
      edit.call(pf)
      C27M.with_chain { C27M.vd(C27M.run(pf)) }
    end
    D40.ck(run.() { |pf| pf['heads'] << pf['heads'][0] }, bound) &&
      D40.ck(run.() { |pf| pf['rev_leaves'] = [leaf] * 3 }, bound) &&
      D40.ck(run.() { |pf| pf['rev_leaves'] = [leaf] * 2 }, [true, nil, -1])
  end

  t('d40 mesh: an unusable capability or issuer-key revocation proof is refused without a non-membership check') do
    next true unless D40.only?('mesh.rb')

    bad_cap = { 'cap' => { 'size' => 5, 'lo' => 9 }, 'issuer_key' => { 'size' => 0 } }
    bad_key = { 'cap' => { 'size' => 0 }, 'issuer_key' => { 'size' => -1 } }
    run = lambda do |rev|
      calls, spy = D40.spy_calls(AtlasPca, :mesh_non_membership?, true)
      pf = C27M.proof([C27M.cap(0)])
      pf['hops'][0]['revocation'] = rev
      v = C27M.with_chain({ mesh_non_membership?: spy }) { C27M.vd(C27M.run(pf)) }
      [v, calls.length]
    end
    D40.ck(run.(bad_cap), [[false, 'capability revoked (or revocation proof invalid)', 0], 0]) &&
      D40.ck(run.(bad_key), [[false, 'issuer key revoked (or revocation proof invalid)', 0], 1])
  end
end
