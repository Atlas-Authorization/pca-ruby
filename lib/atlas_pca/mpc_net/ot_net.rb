# frozen_string_literal: true

require 'digest'
require_relative '../mpc_net'
require_relative '../mpc_ot'
require_relative '../mpc_lwe_ot'
require_relative 'mesh'

module AtlasPca
  module Mpc
    module Net
      # Pairwise base oblivious transfer OVER THE NETWORK (research prototype): 'ec' is the malicious-secure Chou-Orlandi-style base OT on
      # Ed25519 (Schnorr proof of knowledge, subgroup validation of every received point); 'lwe' is the post-quantum endemic OT over
      # Module-LWE (needs liblweot, see MpcLweOt). A FUNCTIONAL-CORRECTNESS demonstration: afterwards the receiver reveals its choice bits
      # and a hash of each received pad (a demo-only step, NOT part of the OT) so the sender can check the pads over a real network.
      module OtNet
        Result = Struct.new(:kind, :role, :count, :ms, :matched, :pad_digest, keyword_init: true)

        module_function

        def sha_hex(*parts) = Digest::SHA256.hexdigest(parts.map(&:b).join)

        # wraps peer-supplied data parsing so any failure aborts naming the peer
        def parsing(mesh, peer, rd)
          yield
        rescue NetWire::NetAbort
          raise
        rescue StandardError => e
          ne = NetWire::NetAbort.new('malformed', peer, mesh.self_id, "round '#{rd}': #{e.message}")
          mesh.fail(ne)
          raise ne
        end

        def abort_with(mesh, kind, peer, msg)
          ne = NetWire::NetAbort.new(kind, peer, mesh.self_id, msg)
          mesh.fail(ne)
          raise ne
        end

        # binding of a base OT on this mesh: session (hashed to a fixed length), who sends, who receives, which round
        def net_binding(mesh, sender_index, receiver_index, round)
          sid = Digest::SHA256.digest('atlas-pca-mpc/net-session/v2'.b + AtlasPca::Js.utf8(mesh.session_id))
          Ot::BaseOtBinding.new(sid, sender_index, receiver_index, round)
        end

        def lwe!(mesh, peer)
          abort_with(mesh, 'local', nil, 'ot kind lwe needs liblweot (ATLAS_PCA_LIBLWEOT)') unless MpcLweOt.available?
          peer
        end

        def pairs(raw, len = nil)
          raise ArgumentError, 'bad point pair' unless raw.is_a?(Array) && raw.length == 2

          raw.map { |x| NetCodec.unb64(x, len) }
        end

        def run_ot_sender(mesh, peer, kind, count)
          t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          pads = nil
          if kind == 'ec'
            rng = Ot.secure_ot_random
            binding = net_binding(mesh, mesh.self_id, peer, 'ot-ec')
            setup = Ot.mal_base_ot_sender_setup(rng, binding)
            mesh.send_to(peer, 'ot-S', { 'S' => NetCodec.pt_j(setup.s), 'U' => NetCodec.pt_j(setup.proof.u), 'z' => NetWire.hx(setup.proof.z) })
            r_raw = mesh.recv(peer, 'ot-R')
            r = parsing(mesh, peer, 'ot-R') do
              raise ArgumentError, 'bad R array' unless r_raw.is_a?(Array) && r_raw.length == count

              r_raw.map { |x| NetCodec.j_pt(x) }
            end
            begin
              pads = Ot.mal_base_ot_sender_derive(setup.y, setup.t, r, setup.s, binding)
            rescue StandardError => e
              abort_with(mesh, 'malformed', peer, e.message)
            end
          elsif kind == 'lwe'
            lwe!(mesh, peer)
            rng = MpcLweOt::OtRandom.new
            m = mesh.recv(peer, 'ot-recv')
            msg = parsing(mesh, peer, 'ot-recv') do
              unless m.is_a?(Hash) && m['points'].is_a?(Array) && m['rhos'].is_a?(Array) && m['points'].length == count && m['rhos'].length == count
                raise ArgumentError, 'bad receiver message'
              end

              MpcLweOt::ReceiverMessage.new(NetCodec.unb64(m['rn'], 32), m['points'].map { |pp| pairs(pp) }, m['rhos'].map { |x| NetCodec.unb64(x, 32) })
            end
            begin
              sm = MpcLweOt.send_random(msg, rng)
            rescue StandardError => e
              abort_with(mesh, 'malformed', peer, "lwe sender: #{e.message}")
            end
            pads = sm.sender_pads
            mesh.send_to(peer, 'ot-ct', sm.ciphertexts.map { |a, b| [NetCodec.b64(a), NetCodec.b64(b)] })
          else
            abort_with(mesh, 'local', nil, "unknown ot kind #{kind.inspect}")
          end
          # demo-only verification: the receiver reveals choices + pad hashes
          v = mesh.recv(peer, 'ot-verify')
          ok = parsing(mesh, peer, 'ot-verify') do
            unless v.is_a?(Hash) && v['choices'].is_a?(Array) && v['padHashes'].is_a?(Array) && v['choices'].length == count && v['padHashes'].length == count
              raise ArgumentError, 'bad verify message'
            end

            v['choices'].each_with_index.all? { |c, i| c.is_a?(Integer) && (c == 0 || c == 1) && sha_hex(pads[i][c]) == v['padHashes'][i] }
          end
          mesh.send_to(peer, 'ot-done', { 'matched' => ok })
          mesh.finish
          Result.new(kind: kind, role: 'sender', count: count, ms: elapsed_ms(t0), matched: ok, pad_digest: sha_hex(*pads.flatten))
        end

        def run_ot_receiver(mesh, peer, kind, count)
          t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          rng = kind == 'lwe' ? MpcLweOt::OtRandom.new : Ot.secure_ot_random
          choices = rng.bytes(count).bytes.map { |b| b & 1 }
          recv_pads = nil
          if kind == 'ec'
            s_raw = mesh.recv(peer, 'ot-S')
            s, proof = parsing(mesh, peer, 'ot-S') do
              raise ArgumentError, 'bad S message' unless s_raw.is_a?(Hash)

              pr = Ec::SchnorrProof.new(NetCodec.j_pt(s_raw['U']), NetCodec.hex_big(s_raw['z']))
              [NetCodec.j_pt(s_raw['S']), pr]
            end
            begin
              res = Ot.mal_base_ot_receiver_respond(s, proof, choices, rng, net_binding(mesh, peer, mesh.self_id, 'ot-ec'))
            rescue StandardError => e
              abort_with(mesh, e.is_a?(Ot::BaseOtAbort) ? 'commitment' : 'malformed', peer, e.message)
            end
            recv_pads = res.recv_pads
            mesh.send_to(peer, 'ot-R', res.r.map { |pt| NetCodec.pt_j(pt) })
          elsif kind == 'lwe'
            lwe!(mesh, peer)
            message, state = MpcLweOt.receive(choices, rng)
            mesh.send_to(
              peer, 'ot-recv',
              { 'rn' => NetCodec.b64(message.rn), 'points' => message.points.map { |a, b| [NetCodec.b64(a), NetCodec.b64(b)] },
                'rhos' => message.rhos.map { |x| NetCodec.b64(x) } }
            )
            ct_raw = mesh.recv(peer, 'ot-ct')
            cts = parsing(mesh, peer, 'ot-ct') do
              raise ArgumentError, 'bad ciphertext array' unless ct_raw.is_a?(Array) && ct_raw.length == count

              ct_raw.map { |pp| pairs(pp) }
            end
            recv_pads = parsing(mesh, peer, 'ot-ct') { MpcLweOt.recover_random(state, MpcLweOt::SenderMessage.new(cts, [])) }
          else
            abort_with(mesh, 'local', nil, "unknown ot kind #{kind.inspect}")
          end
          mesh.send_to(peer, 'ot-verify', { 'choices' => choices, 'padHashes' => recv_pads.map { |p| sha_hex(p) } })
          d = mesh.recv(peer, 'ot-done')
          matched = d.is_a?(Hash) && d['matched'] == true
          mesh.finish
          Result.new(kind: kind, role: 'receiver', count: count, ms: elapsed_ms(t0), matched: matched, pad_digest: sha_hex(*recv_pads))
        end

        def elapsed_ms(t0) = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round
      end
    end
  end
end
