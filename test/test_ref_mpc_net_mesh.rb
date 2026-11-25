# frozen_string_literal: true

# The mutual-TLS mesh: pin-only identity, strict framing, the refusal cases, the abort claims and the injectable clock. Identities come
# from fixed seeds (the certificates are self-signed at test time; nothing is committed).
require_relative 'support/mpc_net_support'
require 'minitest/autorun'

class TestRefMpcNetMesh < Minitest::Test
  S = MpcNetSupport
  N = S::N
  W = S::W

  def setup
    @label = "mesh-#{SecureRandom.hex(4)}"
    @session = SecureRandom.hex(8)
  end

  # node 0 listens as the mesh under test; the other node (id 1) is whoever the test makes it
  def rig(count = 2, **opts)
    @ids = S.identities(count, @label)
    @ns = S.nodes(@ids)
    @mesh0 = S.mesh(0, @ids, @ns, @session, connect_timeout_ms: 20_000, recv_timeout_ms: 20_000, **opts)
    @ports = [@mesh0.listen] # held from here on: raw clients dial the port the node really holds
  end

  # connects mesh0 in a thread and a raw client (identity 1) that has said hello; returns [client, connect thread]
  def hello_client(pem = nil, id: 1, seq: 0)
    th = S.spawn_catching { @mesh0.connect }
    c = S.raw_client(@ports[0], pem || @ids[1])
    c.write(S.frame('hello', @session, seq, 'hello', { 'id' => id }))
    [c, th]
  end

  def abort_of(&blk) = assert_raises(W::NetAbort, &blk)

  def teardown
    @mesh0&.fail(W::NetAbort.new('local', nil, 0, 'test over'))
  end

  # bind first: the advertised port is the held port, the ports differ, and nothing probes and releases
  def test_wire_advertises_the_bound_ports
    ids = S.identities(2, @label)
    ns = S.nodes(ids)
    meshes = Array.new(2) { |i| S.mesh(i, ids, ns, @session) }
    ports = S.wire(meshes)
    assert ports.all?(&:positive?)
    refute_equal ports[0], ports[1]
    assert_equal ports[0], meshes[0].listen
    assert_equal 0, ns[0].port, 'the caller\'s node table is never rewritten'
    ports.each { |p| assert_raises(Errno::EADDRINUSE) { TCPServer.new('127.0.0.1', p) } }
    refute N::Timing.respond_to?(:reserve_ports)
    meshes.each { |m| m.fail(W::NetAbort.new('local', nil, 0, 'test over')) }
  end

  def test_honest_three_node_exchange
    ids = S.identities(3, @label)
    ns = S.nodes(ids)
    meshes = Array.new(3) { |i| S.mesh(i, ids, ns, @session, connect_timeout_ms: 30_000) }
    S.wire(meshes)
    meshes.map { |m| S.spawn_catching { m.connect } }.each { |t| refute_kind_of Exception, t.value }
    meshes.each_with_index { |m, i| m.broadcast('r1', { 'from' => i }) }
    meshes.each_with_index do |m, i|
      got = m.collect('r1')
      assert_equal m.peers, got.keys.sort
      got.each { |p, d| assert_equal({ 'from' => p }, d, "node #{i}") }
    end
    meshes.each_with_index do |m, i|
      m.peers.each { |p| assert_equal 2, m.stats.find { |s| s.peer == p }.frames_in, "node #{i} link #{p}: hello + one message" }
    end
    meshes.each(&:finish)
  end

  def test_signatures_verify_only_against_the_pinned_certificate
    rig
    sig = @mesh0.sign('data')
    other = S.mesh(1, @ids, @ns, @session)
    assert other.verify(0, 'data', sig)
    refute other.verify(0, 'other data', sig)
    refute other.verify(1, 'data', sig), 'a node never verifies against itself'
    refute other.verify(9, 'data', sig)
    refute other.verify(0, 'data', 'not a signature')
  end

  def test_pinned_certificate_mismatch_refuses_the_link
    ids = S.identities(3, @label)
    addr = ->(i, pem) { N::NodeAddr.new(id: i, host: '127.0.0.1', port: 0, cert_pem: pem.cert_pem) }
    # node 1 pins a WRONG certificate for node 0, so the real node 0 is not the pinned identity
    m0 = S.mesh(0, ids, [addr.call(0, ids[0]), addr.call(1, ids[1])], @session, connect_timeout_ms: 2_000)
    m1 = S.mesh(1, ids, [addr.call(0, ids[2]), addr.call(1, ids[1])], @session, connect_timeout_ms: 10_000)
    S.wire([m0, m1])
    t0 = S.spawn_catching { m0.connect }
    e = abort_of { m1.connect }
    assert_equal 'identity', e.kind
    assert_equal 0, e.blamed
    t0.value
  ensure
    [m0, m1].compact.each { |m| m.fail(W::NetAbort.new('local', nil, 0, 'done')) }
  end

  def test_the_tamper_hook_needs_explicit_opt_in
    ids = S.identities(2, @label)
    ns = S.nodes(ids, [1, 2])
    assert_raises(ArgumentError) { S.mesh(0, ids, ns, @session, tamper: ->(_ev) { [] }) }
    S.mesh(0, ids, ns, @session, tamper: ->(_ev) { [] }, unsafe_test_hooks: true)
  end

  def test_a_hello_with_the_wrong_party_id_is_refused
    rig
    _c, th = hello_client(id: 7)
    e = th.value
    assert_kind_of W::NetAbort, e
    assert_equal 'identity', e.kind
    assert_equal 1, e.blamed
  end

  def test_an_oversize_length_prefix_is_refused
    rig
    c, th = hello_client
    th.value
    c.write([0x7fffffff].pack('N'))
    e = abort_of { @mesh0.recv(1, 'r', 5_000) }
    assert_equal 'oversize', e.kind
    assert_equal 1, e.blamed
  end

  def test_a_replayed_sequence_number_is_refused
    rig
    c, th = hello_client
    th.value
    c.write(S.frame('msg', @session, 1, 'r', 1))
    c.write(S.frame('msg', @session, 1, 'r', 1))
    e = abort_of { @mesh0.recv(1, 'r', 5_000) }
    assert_equal 'duplicate', e.kind
    assert_equal 1, e.blamed
  end

  def test_a_skipped_sequence_number_is_refused
    rig
    c, th = hello_client
    th.value
    c.write(S.frame('msg', @session, 2, 'r', 1))
    e = abort_of { @mesh0.recv(1, 'r', 5_000) }
    assert_equal 'out-of-order', e.kind
    assert_equal 1, e.blamed
  end

  def test_a_frame_for_the_wrong_round_is_refused
    rig
    c, th = hello_client
    th.value
    c.write(S.frame('msg', @session, 1, 'zzz', 1))
    e = abort_of { @mesh0.recv(1, 'r', 5_000) }
    assert_equal 'wrong-round', e.kind
    assert_equal 1, e.blamed
  end

  def test_a_frame_for_another_session_is_refused
    rig
    c, th = hello_client
    th.value
    c.write(S.frame('msg', 'another-session', 1, 'r', 1))
    e = abort_of { @mesh0.recv(1, 'r', 5_000) }
    assert_equal 'wrong-session', e.kind
  end

  def test_a_frame_of_another_wire_version_is_a_version_abort
    rig
    c, th = hello_client
    th.value
    body = AtlasPca::Js.utf8(AtlasPca::Js.json({ 'v' => 99, 'ty' => 'msg', 'sid' => @session, 'seq' => 1, 'rd' => 'r', 'd' => 1 }))
    c.write([body.bytesize].pack('N') + body)
    assert_equal 'version', abort_of { @mesh0.recv(1, 'r', 5_000) }.kind
  end

  def test_garbage_is_malformed
    rig
    c, th = hello_client
    th.value
    junk = 'not json at all'
    c.write([junk.bytesize].pack('N') + junk)
    assert_equal 'malformed', abort_of { @mesh0.recv(1, 'r', 5_000) }.kind
  end

  def test_an_early_close_is_a_disconnect
    rig
    c, th = hello_client
    th.value
    c.close
    e = abort_of { @mesh0.recv(1, 'r', 5_000) }
    assert_equal 'disconnect', e.kind
    assert_equal 1, e.blamed
  end

  def test_a_silent_peer_is_blamed_after_the_deadline
    rig
    _c, th = hello_client
    th.value
    e = abort_of { @mesh0.recv(1, 'r', 300) }
    assert_equal 'timeout', e.kind
    assert_equal 1, e.blamed
    assert_equal 300, e.deadline_ms
  end

  def test_a_silent_peer_is_blamed_exactly_when_virtual_time_passes_the_deadline
    clock = N::ManualClock.new
    rig(2, clock: clock)
    _c, th = hello_client
    th.value
    waiter = S.spawn_catching { @mesh0.recv(1, 'r', 1_000) }
    S.until_('the receive to arm its timer') { clock.pending.positive? }
    clock.advance(999)
    sleep 0.1
    assert waiter.alive?, 'one millisecond early: no abort yet'
    clock.advance(2)
    e = waiter.value
    assert_kind_of W::NetAbort, e
    assert_equal 'timeout', e.kind
    assert_equal 1_000, e.deadline_ms
  end

  def test_a_client_with_an_unpinned_certificate_never_links
    rig(3)
    stranger = N::Certs.seeded_pem("#{@label}/stranger", 'stranger')
    th = S.spawn_catching { @mesh0.connect }
    c = S.raw_client(@ports[0], stranger)
    c.write(S.frame('hello', @session, 0, 'hello', { 'id' => 1 })) rescue nil # rubocop:disable Style/RescueModifier
    S.until_('the stranger to be rejected at the door') { @mesh0.events.any? { |m| m.start_with?('rejected incoming connection') } }
    assert th.alive?, 'the mesh is still waiting for its real peers'
  end

  def test_a_flooding_peer_is_blamed
    rig(2, max_inbox_frames: 4)
    c, th = hello_client
    th.value
    (1..10).each { |s| c.write(S.frame('msg', @session, s, 'r', s)) }
    S.until_('the flood to poison the mesh') { @mesh0.failed }
    assert_equal 'flood', @mesh0.failed.kind
    assert_equal 1, @mesh0.failed.blamed
  end

  def test_a_forged_abort_claim_blames_the_sender_not_the_accused
    rig(3)
    ids = @ids
    th = S.spawn_catching { @mesh0.connect }
    c1 = S.raw_client(@ports[0], ids[1])
    c1.write(S.frame('hello', @session, 0, 'hello', { 'id' => 1 }))
    c2 = S.raw_client(@ports[0], ids[2])
    c2.write(S.frame('hello', @session, 0, 'hello', { 'id' => 2 }))
    th.value
    c1.write(S.frame('abort', @session, 1, 'abort', { 'kind' => 'timeout', 'blamed' => 2, 'detail' => 'forged' }))
    e = abort_of { @mesh0.recv(2, 'r', 5_000) }
    assert_equal 'peer-abort', e.kind
    assert_equal 1, e.blamed, 'the authenticated sender is blamed'
    assert_equal 2, e.claimed_blame, 'the accusation is recorded as an unverified claim'
  end

  def test_the_frame_faults_each_surface_as_an_attributable_abort
    {
      'duplicate' => 'duplicate', 'skip-seq' => 'out-of-order', 'wrong-round' => 'wrong-round', 'wrong-session' => 'wrong-session',
      'oversize' => 'oversize', 'garbage' => 'malformed', 'extra-field' => 'malformed'
    }.each do |kind, want|
      ids = S.identities(2, "#{@label}/#{kind}")
      ns = S.nodes(ids)
      fault = N::Faults::FrameFault.new(kind: kind, round: 'r')
      m0 = S.mesh(0, ids, ns, @session, connect_timeout_ms: 30_000, recv_timeout_ms: 5_000)
      m1 = S.mesh(1, ids, ns, @session, connect_timeout_ms: 30_000, recv_timeout_ms: 5_000, tamper: N::Faults.tamper_for(fault), unsafe_test_hooks: true)
      S.wire([m0, m1])
      [m0, m1].map { |m| S.spawn_catching { m.connect } }.each { |t| refute_kind_of Exception, t.value }
      m1.send_to(0, 'r', 1)
      e = abort_of { m0.recv(1, 'r', 5_000) }
      assert_equal want, e.kind, kind
      assert_equal 1, e.blamed, kind
    ensure
      [m0, m1].compact.each { |m| m.fail(W::NetAbort.new('local', nil, 0, 'done')) }
    end
  end
end
