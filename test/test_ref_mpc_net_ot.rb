# frozen_string_literal: true

# Pairwise base OT over the mutual-TLS mesh (the ot-sender / ot-receiver roles), in process on loopback.
require_relative 'support/mpc_net_support'
require_relative '../lib/atlas_pca/mpc_net/ot_net'
require 'minitest/autorun'

class TestRefMpcNetOt < Minitest::Test
  S = MpcNetSupport
  N = S::N

  def run_pair(kind, count)
    ids = S.identities(2, "ot/#{SecureRandom.hex(4)}")
    ns = S.nodes(ids, N::Timing.reserve_ports(2))
    session = SecureRandom.hex(8)
    meshes = Array.new(2) { |i| S.mesh(i, ids, ns, session, recv_timeout_ms: 120_000, connect_timeout_ms: 60_000) }
    threads = Array.new(2) do |i|
      S.spawn_catching do
        meshes[i].connect
        i.zero? ? N::OtNet.run_ot_sender(meshes[i], 1, kind, count) : N::OtNet.run_ot_receiver(meshes[i], 0, kind, count)
      end
    end
    threads.map(&:value)
  end

  def check(kind)
    snd, rcv = run_pair(kind, 16)
    assert_kind_of N::OtNet::Result, snd, snd.inspect[0, 300]
    assert_kind_of N::OtNet::Result, rcv, rcv.inspect[0, 300]
    assert snd.matched
    assert rcv.matched
    assert_equal 16, snd.count
  end

  def test_ec_base_ot_over_the_mesh = check('ec')

  def test_lwe_base_ot_over_the_mesh
    skip 'liblweot not available' unless AtlasPca::MpcLweOt.available?
    check('lwe')
  end

  def test_unknown_kind_aborts
    snd, = run_pair('rsa', 2)
    assert_kind_of AtlasPca::Mpc::NetWire::NetAbort, snd
  end
end
