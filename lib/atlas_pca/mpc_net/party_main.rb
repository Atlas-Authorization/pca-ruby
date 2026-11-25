# frozen_string_literal: true

require 'json'
require_relative '../mpc_net'
require_relative 'certs'
require_relative 'faults'
require_relative 'mesh'
require_relative 'ot_net'
require_relative 'protocol'

module AtlasPca
  module Mpc
    module Net
      # One MPC node (a party or the dealer) as its OWN OS process, talking to the others only over the TLS mesh.
      #
      #   ruby -I lib -e 'require "atlas_pca/mpc_net/party_main"; AtlasPca::Mpc::Net::PartyMain.main(ARGV)' config.json
      #   ... PartyMain.main(["keygen", dir, cn])   writes dir/key.pem and dir/cert.pem and prints their paths
      #
      # The config is a JSON object: role (party | dealer | ot-sender | ot-receiver), ot {kind (ec | lwe), count} for the ot-* roles, id, n, Q, sessionId, input {allow, t, rQuant}, listenHost, nodes
      # [{id, host, port, certPath}], keyPath, certPath, recvTimeoutMs, connectTimeoutMs, offline (trusted-dealer | no-dealer),
      # insecureTrustedDealer, dealerSeed, and the TEST-ONLY behavior {kind, round}, frameFault {kind, round, to, accuse},
      # dealerFault {keepCDelta, partnerCDelta, macFaultAtInput}, unsafeTestHooks (these need unsafeTestHooks AND the environment
      # variable PCA_MPC_UNSAFE_TEST_HOOKS=1, else the node refuses to start). Prints exactly one JSON line: the result or the
      # attributable abort.
      module PartyMain
        module_function

        def main(argv)
          if argv[0] == 'keygen'
            id = Certs.generate_identity(argv[1], argv[2] || 'mpc-node')
            puts JSON.generate({ 'keyPath' => id.key_path, 'certPath' => id.cert_path })
            return
          end
          code = run(JSON.parse(File.read(argv[0])))
          $stdout.flush
          sleep 0.3 # give sockets a moment to flush abort frames, then exit regardless of lingering threads
          exit!(code)
        end

        def out(obj)
          $stdout.puts(JSON.generate(obj))
          $stdout.flush
        end

        def link_json(stats)
          stats.map do |s|
            { 'peer' => s.peer, 'appBytesOut' => s.app_bytes_out, 'appBytesIn' => s.app_bytes_in, 'framesOut' => s.frames_out,
              'framesIn' => s.frames_in, 'tlsBytesWritten' => s.tls_bytes_written, 'tlsBytesRead' => s.tls_bytes_read }
          end
        end

        def result_json(r)
          {
            'id' => r.id, 'n' => r.n, 'Q' => r.q,
            'composed' => { 'allow' => r.composed.allow, 't' => r.composed.t, 'rQuant' => r.composed.r_quant },
            'rounds' => r.rounds.map { |x| { 'rd' => x.rd, 'ms' => x.ms, 'bytesOut' => x.bytes_out, 'bytesIn' => x.bytes_in } },
            'transcriptDigest' => r.transcript_digest, 'wallMs' => r.wall_ms, 'multiplications' => r.multiplications, 'opens' => r.opens,
            'offlineMode' => r.offline_mode, 'macKeys' => r.mac_keys, 'sacrificedTriples' => r.sacrificed_triples,
            'sacrificePartners' => r.sacrifice_partners, 'identifiableAbort' => r.identifiable_abort
          }
        end

        def abort_json(e)
          { 'kind' => e.kind, 'blamed' => e.blamed, 'reporter' => e.reporter, 'claimedKind' => e.claimed_kind, 'claimedBlame' => e.claimed_blame,
            'reason' => e.reason, 'evidence' => e.evidence, 'deadlineMs' => e.deadline_ms, 'message' => e.message }
        end

        def int_or_nil(x) = x.nil? ? nil : Integer(x)

        # runs the node described by cfg (a parsed config) and returns the process exit code
        def run(cfg)
          hooks = !cfg['behavior'].nil? || !cfg['frameFault'].nil? || !cfg['dealerFault'].nil?
          if hooks && !(cfg['unsafeTestHooks'] == true && ENV['PCA_MPC_UNSAFE_TEST_HOOKS'] == '1')
            out({ 'ok' => false, 'role' => cfg['role'], 'id' => cfg['id'],
                  'error' => { 'kind' => 'local', 'blamed' => nil, 'reporter' => cfg['id'],
                               'message' => 'refusing to start: test hooks (behavior/frameFault) are not enabled in this environment' } })
            return 3
          end
          role = cfg['role']
          unless %w[party dealer ot-sender ot-receiver].include?(role)
            out({ 'ok' => false, 'role' => role, 'id' => cfg['id'],
                  'error' => { 'kind' => 'local', 'blamed' => nil, 'reporter' => cfg['id'], 'message' => "unsupported role #{role.inspect}" } })
            return 3
          end
          nodes = cfg['nodes'].map { |x| NodeAddr.new(id: x['id'], host: x['host'], port: x['port'], cert_pem: Certs.read_pem(x['certPath'])) }
          n = cfg['n']
          link_to = role == 'dealer' ? nodes.map(&:id).select { |i| i < n } : nil
          tamper = cfg['frameFault'] ? Faults.tamper_for(Faults.frame_fault(cfg['frameFault'])) : nil
          server = nil
          if cfg['bindFirst'] == true
            # bind first: hold a real listener on this node's own port (0 = the OS picks), report it, then take every peer's real port
            # from one stdin line before anyone dials; the held listener goes to the mesh and is never released
            me = nodes.find { |x| x.id == cfg['id'] }
            server = TCPServer.new(cfg['listenHost'] || '0.0.0.0', me ? me.port : 0)
            me&.port = server.addr[1]
            out({ 'listening' => server.addr[1], 'id' => cfg['id'] })
            line = $stdin.gets
            if line.nil?
              out({ 'ok' => false, 'role' => role, 'id' => cfg['id'],
                    'error' => { 'kind' => 'local', 'blamed' => nil, 'reporter' => cfg['id'], 'message' => 'stdin closed before the port map arrived' } })
              return 3
            end
            JSON.parse(line)['ports'].each { |k, v| nodes.find { |x| x.id == k.to_i }&.port = v unless k.to_i == cfg['id'] }
          end
          mesh = Mesh.new(
            self_id: cfg['id'], nodes: nodes, link_to: link_to, key_pem: Certs.read_pem(cfg['keyPath']), cert_pem: Certs.read_pem(cfg['certPath']),
            session_id: cfg['sessionId'], listen_host: cfg['listenHost'],
            recv_timeout_ms: cfg['recvTimeoutMs'] || 20_000, connect_timeout_ms: cfg['connectTimeoutMs'] || 30_000,
            tamper: tamper, unsafe_test_hooks: hooks, server: server
          )
          t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          begin
            mesh.connect
            connect_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round
            if role == 'dealer'
              df = cfg['dealerFault']
              fault = df && Spdz::DealerFault.new(df['keepCDelta']&.to_i, df['partnerCDelta']&.map { |x| x&.to_i })
              Protocol.run_dealer(
                Protocol::DealerConfig.new(n: n, q: cfg['Q'], mesh: mesh, seed: cfg['dealerSeed']&.to_i,
                                           insecure_trusted_dealer: cfg['insecureTrustedDealer'], fault: fault,
                                           mac_fault_at_input: int_or_nil(df && df['macFaultAtInput']))
              )
              out({ 'ok' => true, 'role' => 'dealer', 'id' => cfg['id'], 'connectMs' => connect_ms, 'links' => link_json(mesh.stats),
                    'events' => mesh.events })
            elsif role.start_with?('ot-')
              k = cfg['ot'] || { 'kind' => 'ec', 'count' => 128 }
              sender = role == 'ot-sender'
              peer = sender ? 1 : 0
              r = sender ? OtNet.run_ot_sender(mesh, peer, k['kind'], k['count']) : OtNet.run_ot_receiver(mesh, peer, k['kind'], k['count'])
              out({ 'ok' => true, 'role' => role, 'connectMs' => connect_ms,
                    'result' => { 'kind' => r.kind, 'role' => r.role, 'count' => r.count, 'ms' => r.ms, 'wasmCurveActive' => false,
                                  'matched' => r.matched, 'padDigest' => r.pad_digest },
                    'links' => link_json(mesh.stats), 'events' => mesh.events })
            else
              i = cfg['input']
              r = Protocol.run_party(
                Protocol::PartyConfig.new(
                  id: cfg['id'], n: n, q: cfg['Q'], input: DecisionVector.new(i['allow'], i['t'], i['rQuant']), mesh: mesh,
                  offline: cfg['offline'], insecure_trusted_dealer: cfg['insecureTrustedDealer'],
                  behavior: cfg['behavior'] && Protocol::Behavior.new(kind: cfg['behavior']['kind'], round: cfg['behavior']['round']),
                  unsafe_test_hooks: hooks ? true : nil, session_id: cfg['sessionId']
                )
              )
              out({ 'ok' => true, 'role' => 'party', 'connectMs' => connect_ms, 'result' => result_json(r), 'links' => link_json(mesh.stats),
                    'events' => mesh.events })
            end
            0
          rescue Protocol::SilentParty
            sleep # stay connected, say nothing: the peers must time out (the launcher's kill ends this process)
          rescue StandardError => e
            ne = e.is_a?(NetWire::NetAbort) ? e : (mesh.failed || NetWire::NetAbort.new('local', nil, cfg['id'], e.message))
            out({ 'ok' => false, 'role' => role, 'id' => cfg['id'], 'error' => abort_json(ne), 'links' => link_json(mesh.stats), 'events' => mesh.events })
            3
          end
        end
      end
    end
  end
end
