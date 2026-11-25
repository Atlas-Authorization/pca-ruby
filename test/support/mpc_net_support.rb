# frozen_string_literal: true

# Shared helpers for the networked MPC driver tests: identities from fixed seeds (the keys are derived from the seed and the
# certificates are self-signed when a test runs, nothing is committed), free loopback ports, an in-process cluster runner and a raw
# TLS client for crafting hostile frames.
require 'openssl'
require 'securerandom'
require 'socket'
require_relative '../../lib/atlas_pca/mpc_net'
require_relative '../../lib/atlas_pca/mpc_net/mesh'
require_relative '../../lib/atlas_pca/mpc_net/protocol'
require_relative '../../lib/atlas_pca/mpc_net/faults'
require_relative '../../lib/atlas_pca/mpc_net/launch_local'
require_relative '../../lib/atlas_pca/mpc_net/party_main'

module MpcNetSupport
  M = AtlasPca::Mpc
  N = M::Net
  W = M::NetWire
  P = N::Protocol
  DV = M::DecisionVector

  module_function

  # one identity per index, all derived from the seed label
  def identities(count, label) = Array.new(count) { |i| N::Certs.seeded_pem("#{label}/#{i}", "mpc-test-#{i}") }

  # ports default to 0: every mesh binds its own port (see wire) and is then told the real ones; no port is probed and released
  def nodes(ids, ports = Array.new(ids.size, 0)) = ids.each_with_index.map { |pem, i| N::NodeAddr.new(id: i, host: '127.0.0.1', port: ports[i], cert_pem: pem.cert_pem) }

  # bind first: every mesh listens on port 0 and keeps it, then each is told its peers' real ports. Meshes are in node-id order; returns the held ports.
  def wire(meshes)
    ports = meshes.map(&:listen)
    meshes.each_with_index { |m, i| ports.each_with_index { |p, j| m.set_peer_port(j, p) unless j == i } }
    ports
  end

  def mesh(i, ids, nodes, session, **opts)
    N::Mesh.new(self_id: i, nodes: nodes, key_pem: ids[i].key_pem, cert_pem: ids[i].cert_pem, session_id: session, listen_host: '127.0.0.1', **opts)
  end

  # polls cond until truthy or ms elapse (the outcome is decided by an observed condition, never a fixed sleep)
  def until_(what, ms = 30_000)
    stop = Process.clock_gettime(Process::CLOCK_MONOTONIC) + (N::Timing.t(ms) / 1000.0)
    loop do
      v = yield
      return v if v
      raise "timed out waiting for: #{what}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > stop

      sleep 0.01
    end
  end

  # runs the block in a thread; the value is the block's value or the exception it raised
  def spawn_catching(&blk)
    Thread.new do
      blk.call
    rescue StandardError => e
      e
    end.tap { |t| t.report_on_exception = false }
  end

  def vectors = [DV.new(1, 2, 1), DV.new(0, 1, 2), DV.new(1, 3, 0)]

  # Runs n parties (and, for the trusted-dealer mode, one dealer as node n) in this process, each on its own mesh and thread.
  # behaviors: { id => Behavior }; faults: { id => FrameFault }; dealer: DealerConfig fields merged in. Returns [results, meshes]
  # where results[i] is the PartyResult / nil (dealer) or the exception that node raised.
  def run_cluster(n:, q:, vectors:, offline:, behaviors: {}, faults: {}, dealer: {}, recv_timeout_ms: 120_000, label: 'cluster')
    count = offline == 'trusted-dealer' ? n + 1 : n
    ids = identities(count, "#{label}/#{SecureRandom.hex(4)}")
    ns = nodes(ids)
    session = SecureRandom.hex(8)
    meshes = Array.new(count) do |i|
      hooks = behaviors.key?(i) || faults.key?(i)
      mesh(i, ids, ns, session, link_to: i == n ? (0...n).to_a : nil, recv_timeout_ms: recv_timeout_ms, connect_timeout_ms: 60_000,
                                tamper: faults[i] && N::Faults.tamper_for(faults[i]), unsafe_test_hooks: hooks)
    end
    wire(meshes)
    threads = Array.new(count) do |i|
      spawn_catching do
        meshes[i].connect
        if i == n
          P.run_dealer(P::DealerConfig.new(**{ insecure_trusted_dealer: true, n: n, q: q, mesh: meshes[i], seed: 4242 }.merge(dealer)))
          nil
        else
          P.run_party(P::PartyConfig.new(id: i, n: n, q: q, input: vectors[i], mesh: meshes[i], offline: offline, insecure_trusted_dealer: offline == 'trusted-dealer',
                                         behavior: behaviors[i], unsafe_test_hooks: behaviors.key?(i), session_id: session))
        end
      end
    end
    results = threads.map(&:value)
    meshes.each { |m| m.failed ? nil : m.finish }
    [results, meshes]
  end

  def frame(ty, sid, seq, rd, d) = W.encode_frame(W::Frame.new(W::WIRE_VERSION, ty, sid, seq, rd, d))

  # a raw TLS 1.3 client with the given identity (no verification of the server: the test pins nothing on this side)
  def raw_client(port, pem)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION
    ctx.key = OpenSSL::PKey.read(pem.key_pem)
    ctx.cert = OpenSSL::X509::Certificate.new(pem.cert_pem)
    ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    tcp = until_("port #{port} to accept") do
      TCPSocket.new('127.0.0.1', port)
    rescue SystemCallError
      nil
    end
    ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
    ssl.sync_close = true
    ssl.connect
    ssl
  end
end
