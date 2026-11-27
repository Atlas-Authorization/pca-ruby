# frozen_string_literal: true

# The distributed protocol over the mutual-TLS mesh, in BOTH offline modes (trusted dealer and no dealer), n = 3 on loopback, checked
# against the deterministic in-process engine (Compose.compose_clear); the identifiable-abort and refusal cases; and the multi-process
# launcher. Identities come from fixed seeds or are generated per run; nothing is committed.
require_relative 'support/mpc_net_support'
require 'minitest/autorun'
require 'json'
require 'tmpdir'

class TestRefMpcNetProtocol < Minitest::Test
  S = MpcNetSupport
  M = S::M
  N = S::N
  P = S::P
  W = S::W
  Q = 2

  def expected(vectors = S.vectors, q = Q) = M::Compose.compose_clear(vectors, q)

  def assert_agrees(results, vectors = S.vectors, parties = vectors.length)
    want = expected(vectors)
    digests = []
    parties.times do |i|
      r = results[i]
      assert_kind_of P::PartyResult, r, "party #{i}: #{r.inspect[0, 300]}"
      assert_equal want, r.composed, "party #{i}"
      assert r.identifiable_abort
      digests << r.transcript_digest
    end
    assert_equal 1, digests.uniq.length, 'every party saw the same broadcast transcript'
  end

  # no listed node may produce output, and at least one of them names (kind, blamed): an abort frame from a faster party can reach a
  # slower one first, so that one reports a peer-abort instead
  def assert_named(results, nodes, kind, blamed)
    nodes.each { |i| assert_kind_of W::NetAbort, results[i], "node #{i} must not produce output: #{results[i].inspect[0, 200]}" }
    assert nodes.any? { |i| results[i].kind == kind && results[i].blamed == blamed },
           "nobody named #{kind} / #{blamed}: #{nodes.map { |i| results[i].message }.join(' | ')}"
  end

  def test_dealer_mode_agrees_with_the_in_process_engine
    results, = S.run_cluster(n: 3, q: Q, vectors: S.vectors, offline: 'trusted-dealer')
    assert_agrees(results)
    assert_nil results[3], 'the dealer returns nothing'
    assert_equal 'trusted-dealer', results[0].offline_mode
  end

  def test_no_dealer_mode_agrees_with_the_in_process_engine
    results, = S.run_cluster(n: 3, q: Q, vectors: S.vectors, offline: 'no-dealer')
    assert_agrees(results)
    assert_equal 'no-dealer', results[0].offline_mode
    assert_equal 2 * (1 + 3 + Q), results[0].sacrificed_triples
  end

  def test_the_other_decision_vectors_agree_too
    v = [S::DV.new(1, 3, 2), S::DV.new(1, 1, 0), S::DV.new(1, 2, 1)]
    results, = S.run_cluster(n: 3, q: Q, vectors: v, offline: 'trusted-dealer')
    assert_agrees(results, v)
    assert_equal M::ComposedDecision.new(1, 3, 2), results[0].composed
  end

  def test_the_dealer_opt_in_is_required
    assert_raises(ArgumentError) { P.run_dealer(P::DealerConfig.new(n: 3, q: Q, mesh: nil)) }
    e = assert_raises(W::NetAbort) do
      P.run_party(P::PartyConfig.new(id: 0, n: 3, q: Q, input: S.vectors[0], mesh: nil, offline: 'trusted-dealer', session_id: 'x'))
    end
    assert_equal 'local', e.kind
  end

  def test_test_hooks_are_enforced_before_any_traffic
    e = assert_raises(W::NetAbort) do
      P.run_party(P::PartyConfig.new(id: 0, n: 3, q: Q, input: S.vectors[0], mesh: nil, behavior: P::Behavior.new(kind: 'open-lie', round: 'mul0'), session_id: 'x'))
    end
    assert_equal 'local', e.kind
    assert_match(/unsafe_test_hooks/, e.message)
    e = assert_raises(W::NetAbort) do
      P.run_party(P::PartyConfig.new(id: 0, n: 3, q: Q, input: S::DV.new(1, 9, 0), mesh: nil, session_id: 'x'))
    end
    assert_equal 'invalid decision vector', e.message[/invalid decision vector/]
  end

  def test_a_wrong_product_from_the_dealer_is_detected_and_blamed
    fault = M::Spdz::DealerFault.new(1, nil)
    results, = S.run_cluster(n: 3, q: Q, vectors: S.vectors, offline: 'trusted-dealer', dealer: { fault: fault })
    assert_named(results, [0, 1, 2], 'dealer', 3) # the dealer is node n
  end

  def test_a_lying_opened_share_is_named_by_its_pairwise_tag
    results, = S.run_cluster(n: 3, q: Q, vectors: S.vectors, offline: 'trusted-dealer',
                             behaviors: { 1 => P::Behavior.new(kind: 'open-lie', round: 'mul0') })
    assert_named(results, [0, 1, 2], 'mac-check', 1)
  end

  def test_a_bad_pairwise_tag_is_named
    results, = S.run_cluster(n: 3, q: Q, vectors: S.vectors, offline: 'trusted-dealer',
                             behaviors: { 2 => P::Behavior.new(kind: 'bad-tag', round: 'out') })
    assert_named(results, [0, 1, 2], 'mac-check', 2)
  end

  def test_a_non_canonical_field_element_is_refused
    results, = S.run_cluster(n: 3, q: Q, vectors: S.vectors, offline: 'trusted-dealer',
                             behaviors: { 1 => P::Behavior.new(kind: 'noncanonical', round: 'mul0') })
    assert_named(results, [0, 1, 2], 'malformed', 1)
  end

  def test_a_party_that_opens_a_coin_seed_that_does_not_match_its_commitment_is_named
    results, = S.run_cluster(n: 3, q: Q, vectors: S.vectors, offline: 'trusted-dealer',
                             behaviors: { 2 => P::Behavior.new(kind: 'bad-coin-open') })
    assert_named(results, [0, 1, 2], 'commitment', 2)
  end

  def test_a_forged_mac_share_is_caught_by_the_mac_check
    results, = S.run_cluster(n: 3, q: Q, vectors: S.vectors, offline: 'trusted-dealer',
                             behaviors: { 1 => P::Behavior.new(kind: 'mac-lie', round: 'mul0') })
    assert_named(results, [0, 1, 2], 'mac-check', 1)
  end

  def test_a_lying_mac_residual_is_named_by_the_blame_round
    results, = S.run_cluster(n: 3, q: Q, vectors: S.vectors, offline: 'trusted-dealer',
                             behaviors: { 2 => P::Behavior.new(kind: 'sigma-lie') })
    assert_named(results, [0, 1, 2], 'mac-check', 2)
  end

  def test_equivocation_never_yields_an_output
    results, = S.run_cluster(n: 3, q: Q, vectors: S.vectors, offline: 'trusted-dealer',
                             behaviors: { 1 => P::Behavior.new(kind: 'equivocate', round: 'mul0') })
    [0, 1, 2].each { |i| assert_kind_of W::NetAbort, results[i], "node #{i}: #{results[i].inspect[0, 200]}" }
  end

  def test_a_mac_residual_that_does_not_match_its_commitment_is_named
    results, = S.run_cluster(n: 3, q: Q, vectors: S.vectors, offline: 'trusted-dealer',
                             behaviors: { 1 => P::Behavior.new(kind: 'bad-sigma-open') })
    assert_named(results, [0, 1, 2], 'commitment', 1)
  end

  def test_a_wrong_length_array_is_malformed
    results, = S.run_cluster(n: 3, q: Q, vectors: S.vectors, offline: 'trusted-dealer',
                             behaviors: { 1 => P::Behavior.new(kind: 'short-array', round: 'mul0') })
    assert_named(results, [0, 1, 2], 'malformed', 1)
  end

  def test_a_silent_party_is_blamed_by_timeout
    results, = S.run_cluster(n: 3, q: Q, vectors: S.vectors, offline: 'trusted-dealer', recv_timeout_ms: 4_000,
                             behaviors: { 2 => P::Behavior.new(kind: 'silent', round: 'mul0') })
    assert_kind_of P::SilentParty, results[2]
    assert_named(results, [0, 1], 'timeout', 2)
  end

  def test_a_wrong_ot_operand_in_a_triple_product_is_caught_by_the_sacrifice_and_attributed
    results, = S.run_cluster(n: 2, q: Q, vectors: S.vectors.first(2), offline: 'no-dealer',
                             behaviors: { 1 => P::Behavior.new(kind: 'offline-lie') })
    assert_named(results, [0, 1], 'mac-check', 1)
  end

  def test_a_bad_base_ot_proof_is_refused_and_names_its_sender
    results, = S.run_cluster(n: 2, q: Q, vectors: S.vectors.first(2), offline: 'no-dealer',
                             behaviors: { 1 => P::Behavior.new(kind: 'ot-proof-lie') })
    assert_named(results, [0, 1], 'ot-check', 1)
  end

  def test_an_inconsistent_ot_extension_matrix_is_caught_by_the_kos_check
    results, = S.run_cluster(n: 2, q: Q, vectors: S.vectors.first(2), offline: 'no-dealer',
                             behaviors: { 1 => P::Behavior.new(kind: 'ot-u-lie') })
    assert_named(results, [0, 1], 'ot-check', 1)
  end

  def test_the_gadget_seed_exchange_agrees_on_every_seed
    ids = S.identities(3, "gadget-#{SecureRandom.hex(4)}")
    ns = S.nodes(ids)
    session = SecureRandom.hex(8)
    meshes = Array.new(3) { |i| S.mesh(i, ids, ns, session) }
    S.wire(meshes)
    meshes.map { |m| S.spawn_catching { m.connect } }.each { |t| refute_kind_of Exception, t.value }
    seeds = Array.new(3) { |i| ([i] * 32).pack('C*') }
    out = meshes.each_with_index.map do |m, i|
      S.spawn_catching do
        others = (0...3).reject { |j| j == i }
        ex = lambda do |rd, mine, parse|
          others.each { |p| m.send_to(p, rd, mine.call(p)) }
          raw = m.collect(rd, others)
          others.to_h { |p| [p, parse.call(p, raw[p])] }
        end
        io = N::Gadget::Io.new(ex, ->(p, what) { raise W::NetAbort.new('malformed', p, i, what) })
        N::Gadget.agree_gadget_seeds(m, 3, io, seeds[i])
      end
    end.map(&:value)
    out.each { |o| assert_equal seeds, o }
    meshes.each(&:finish)
  end

  # ---- the multi-process launcher: each node is its own OS process ----

  def launch(**o) = N::LaunchLocal.launch(N::LaunchLocal::Options.new(n: 3, q: Q, vectors: S.vectors, recv_timeout_ms: 120_000, kill_after_ms: 600_000, **o))

  def test_the_launcher_runs_no_dealer_parties_as_separate_processes
    l = launch
    assert_equal 3, l.outputs.length
    l.outputs.each do |o|
      assert o.json && o.json['ok'], "node #{o.id}: #{o.stderr} #{o.json.inspect[0, 300]}"
      assert_equal({ 'allow' => 0, 't' => 3, 'rQuant' => 2 }, o.json['result']['composed'])
      assert_equal 'no-dealer', o.json['result']['offlineMode']
    end
  end

  def test_the_launcher_runs_a_trusted_dealer_as_its_own_process
    l = launch(offline: 'trusted-dealer', insecure_trusted_dealer: true)
    assert_equal 4, l.outputs.length
    assert_equal 'dealer', l.outputs[3].role
    assert l.outputs[3].json['ok'], l.outputs[3].stderr
    l.outputs.first(3).each do |o|
      assert o.json && o.json['ok'], "node #{o.id}: #{o.stderr}"
      assert_equal 'trusted-dealer', o.json['result']['offlineMode']
    end
  end

  def test_a_node_refuses_to_start_with_test_hooks_outside_a_test_environment
    cfg = { 'role' => 'party', 'id' => 0, 'n' => 3, 'unsafeTestHooks' => true, 'behavior' => { 'kind' => 'open-lie', 'round' => 'mul0' } }
    saved = ENV.delete(N::LaunchLocal::HOOK_ENV)
    code = nil
    out, = capture_io { code = N::PartyMain.run(cfg) }
    assert_equal 3, code
    j = JSON.parse(out.lines.last)
    refute j['ok']
    assert_match(/refusing to start/, j['error']['message'])
  ensure
    ENV[N::LaunchLocal::HOOK_ENV] = saved if saved
  end

  def test_keygen_writes_a_key_and_a_certificate
    Dir.mktmpdir do |dir|
      out, = capture_io { N::PartyMain.main(['keygen', File.join(dir, 'n0'), 'mpc-node-0']) }
      j = JSON.parse(out)
      assert File.exist?(j['keyPath'])
      assert_equal 64, N::Certs.fingerprint_of(File.read(j['certPath'])).length
    end
  end
end
