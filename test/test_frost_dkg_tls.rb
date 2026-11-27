# frozen_string_literal: true

# The mutual-TLS channel of the FROST DKG over loopback, with certificates generated at test time (ECDSA P-256, self-signed, never committed). The
# link rules are checked against real TLS 1.3 sockets without any timer: a refusal is observed as the server closing the connection, a link as the
# node's own link event. A three-party ceremony then runs end to end over the links (it needs the FROST backend: libsodium through the ffi gem).
require_relative '../lib/atlas_pca'
require 'minitest/autorun'
require 'openssl'
require 'socket'

class TestFrostDkgTls < Minitest::Test
  A = AtlasPca
  CH = AtlasPca::FrostDkgChannel
  T = AtlasPca::FrostDkgTls
  SID = ("\x07" * 32).b

  def self.cert(cn)
    key = OpenSSL::PKey::EC.generate('prime256v1')
    c = OpenSSL::X509::Certificate.new
    c.version = 2
    c.serial = OpenSSL::BN.rand(63)
    c.subject = c.issuer = OpenSSL::X509::Name.parse("/CN=#{cn}")
    c.public_key = key
    c.not_before = Time.now - 3600
    c.not_after = Time.now + 3600
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = ef.issuer_certificate = c
    c.add_extension(ef.create_extension('keyUsage', 'digitalSignature', true))
    c.add_extension(ef.create_extension('extendedKeyUsage', 'serverAuth,clientAuth'))
    c.add_extension(ef.create_extension('subjectAltName', 'IP:127.0.0.1'))
    c.sign(key, OpenSSL::Digest.new('SHA256'))
    [key, c]
  end

  # {id => [key, cert]}
  def self.identities(ids) = ids.to_h { |id| [id, cert("p#{id}")] }

  def start(id, ids, ids_certs, **kw)
    peers = (ids - [id]).map { |o| { 'id' => o, 'certPem' => ids_certs[o][1].to_pem } }
    n = T.start_node(self_id: id, session_id: SID, key_pem: ids_certs[id][0].to_pem, cert_pem: ids_certs[id][1].to_pem, peer_certs: peers, **kw)
    (@nodes ||= []) << n
    n
  end

  def teardown = (@nodes || []).each(&:close)

  def client_ctx(key, cert, server_cert, max: nil)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.cert = cert
    ctx.key = key
    store = OpenSSL::X509::Store.new
    store.add_cert(server_cert)
    ctx.cert_store = store
    ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
    ctx.verify_hostname = false
    ctx.min_version = OpenSSL::SSL::TLS1_2_VERSION
    ctx.max_version = max if max
    ctx
  end

  def dial(port, ctx)
    ssl = OpenSSL::SSL::SSLSocket.new(TCPSocket.new('127.0.0.1', port), ctx)
    ssl.sync_close = true
    ssl.connect
    ssl
  end

  # the server closed the connection (or never accepted it): the next read ends
  def refused?(ssl)
    ssl.read(1).nil?
  rescue StandardError
    true
  end

  def test_the_node_validates_its_pins
    ids = self.class.identities([1, 2])
    other = ids[2]
    assert_raises(ArgumentError) { T.start_node(self_id: 1, session_id: SID, key_pem: ids[1][0].to_pem, cert_pem: ids[1][1].to_pem, peer_certs: [{ 'id' => 1, 'certPem' => ids[1][1].to_pem }]) }
    dup = [{ 'id' => 2, 'certPem' => other[1].to_pem }, { 'id' => 3, 'certPem' => other[1].to_pem }]
    assert_raises(ArgumentError) { T.start_node(self_id: 1, session_id: SID, key_pem: ids[1][0].to_pem, cert_pem: ids[1][1].to_pem, peer_certs: dup) }
  end

  def test_a_pinned_higher_peer_links_once_and_frames_flow_both_ways
    idc = self.class.identities([1, 2])
    node = start(1, [1, 2], idc)
    peer = dial(node.port, client_ctx(idc[2][0], idc[2][1], idc[1][1]))
    assert_equal 'TLSv1.3', peer.ssl_version
    ch = node.connect([{ 'id' => 2, 'host' => '127.0.0.1', 'port' => 1 }], 30_000)
    assert_equal [2], node.linked_ids
    assert_equal [1, [2]], [ch.self_id, ch.peers]

    # a frame from the peer reaches the inbox under the identity of the link
    body = { 'hello' => 1 }
    peer.write(CH.tls_frame_encode(CH.encode_dkg_message(SID, 'round1', body)))
    assert_equal({ 2 => body }, ch.collect('round1', [2], 30_000))

    # a frame to the peer decodes to the same body
    ch.send_to(2, 'share', { 'x' => 2 })
    head = peer.read(4)
    got = CH.decode_dkg_message(peer.read(head.unpack1('N')), SID)
    assert_equal ['share', { 'x' => 2 }], [got['kind'], got['body']]

    # a second connection for the linked identity is refused, and the first link stays
    second = dial(node.port, client_ctx(idc[2][0], idc[2][1], idc[1][1]))
    assert refused?(second)
    assert_equal [2], node.linked_ids
    assert_raises(CH::DkgChannelError) { ch.send_to(9, 'share', {}) }
  end

  def test_an_oversize_frame_fails_the_peer_before_any_allocation
    idc = self.class.identities([1, 2])
    node = start(1, [1, 2], idc)
    peer = dial(node.port, client_ctx(idc[2][0], idc[2][1], idc[1][1]))
    ch = node.connect([{ 'id' => 2, 'host' => '127.0.0.1', 'port' => 1 }], 30_000)
    peer.write([CH::DKG_MAX_MESSAGE_BYTES + 1].pack('N'))
    e = assert_raises(CH::DkgChannelError) { ch.collect('round1', [2], 30_000) }
    assert_equal ['oversize', 2], [e.code, e.peer]
  end

  def test_a_link_that_ends_marks_the_peer_gone
    idc = self.class.identities([1, 2])
    node = start(1, [1, 2], idc)
    peer = dial(node.port, client_ctx(idc[2][0], idc[2][1], idc[1][1]))
    ch = node.connect([{ 'id' => 2, 'host' => '127.0.0.1', 'port' => 1 }], 30_000)
    peer.close
    e = assert_raises(CH::DkgChannelError) { ch.collect('round1', [2], 30_000) }
    assert_equal ['closed', 2], [e.code, e.peer]
  end

  def test_refused_connections_never_link
    idc = self.class.identities([1, 2, 3])
    node = start(1, [1, 2], idc.slice(1, 2))
    foreign = self.class.cert('foreign')
    # a client with a certificate nobody pinned (the handshake itself fails the server's client-certificate check)
    stranger = OpenSSL::SSL::SSLSocket.new(TCPSocket.new('127.0.0.1', node.port), client_ctx(foreign[0], foreign[1], idc[1][1]))
    stranger.sync_close = true
    begin
      stranger.connect
      assert refused?(stranger)
    rescue OpenSSL::SSL::SSLError, SystemCallError, IOError
      pass # refused during the handshake
    end
    # a plaintext client
    plain = TCPSocket.new('127.0.0.1', node.port)
    plain.write("GET / HTTP/1.1\r\n\r\n")
    begin
      assert_nil plain.read(1) # the server closes: no byte of an answer
    rescue SystemCallError, IOError
      pass
    end
    plain.close
    # a TLS 1.2 client
    assert_raises(OpenSSL::SSL::SSLError, SystemCallError, IOError) { dial(node.port, client_ctx(idc[2][0], idc[2][1], idc[1][1], max: OpenSSL::SSL::TLS1_2_VERSION)) }
    assert_equal [], node.linked_ids
  end

  def test_a_lower_numbered_party_that_dials_a_higher_one_is_refused
    idc = self.class.identities([1, 2])
    node = start(2, [1, 2], idc)
    peer = dial(node.port, client_ctx(idc[1][0], idc[1][1], idc[2][1]))
    assert refused?(peer)
    assert_equal [], node.linked_ids
  end

  def test_a_peer_that_shows_a_certificate_that_is_not_pinned_is_never_linked
    idc = self.class.identities([1, 2])
    a = start(1, [1, 2], idc)
    foreign = self.class.cert('foreign')
    b = T.start_node(self_id: 2, session_id: SID, key_pem: idc[2][0].to_pem, cert_pem: idc[2][1].to_pem, peer_certs: [{ 'id' => 1, 'certPem' => foreign[1].to_pem }])
    (@nodes ||= []) << b
    e = assert_raises(CH::DkgChannelError) { b.connect([{ 'id' => 1, 'host' => '127.0.0.1', 'port' => a.port }], 1) }
    assert_equal ['timeout', 1], [e.code, e.peer]
    assert_equal [], a.linked_ids
  end

  def test_an_address_for_a_participant_that_is_not_a_peer_is_refused
    idc = self.class.identities([1, 2])
    node = start(1, [1, 2], idc)
    e = assert_raises(CH::DkgChannelError) { node.connect([{ 'id' => 7, 'host' => '127.0.0.1', 'port' => 1 }], 1) }
    assert_equal 'identity', e.code
  end

  # a 2-of-3 ceremony over real mutual-TLS links: every party ends with the same group key
  def test_a_three_party_ceremony_over_loopback
    begin
      A::Frost.verifying_share("\x01".b * 32)
    rescue LoadError => e
      flunk e.message if %w[true 1].include?(ENV['CI'])
      skip e.message
    end
    ids = [1, 2, 3]
    idc = self.class.identities(ids)
    nodes = ids.to_h { |id| [id, start(id, ids, idc)] }
    addrs = ids.map { |id| { 'id' => id, 'host' => '127.0.0.1', 'port' => nodes[id].port } }
    results = {}
    threads = ids.map do |id|
      Thread.new do
        ch = nodes[id].connect(addrs.reject { |a| a['id'] == id }, 30_000)
        results[id] = A::FrostDkgChannel.run_dkg_over_channel(ch, { 't' => 2, 'participants' => ids, 'sessionId' => SID, 'timeoutMs' => 30_000 })
      rescue StandardError => e
        results[id] = e
      end
    end
    threads.each(&:join)
    ids.each { |id| refute_kind_of StandardError, results[id], "party #{id}: #{results[id].inspect}" }
    gpks = ids.map { |id| results[id]['keyPackage']['groupPublicKey'] }
    assert_equal 1, gpks.uniq.length, 'the parties disagree on the group key'
    assert_equal ids, results[1]['qualified']
  end
end
