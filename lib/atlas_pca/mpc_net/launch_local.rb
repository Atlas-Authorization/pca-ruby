# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'open3'
require 'rbconfig'
require 'securerandom'
require 'tmpdir'
require_relative 'certs'
require_relative 'clock'
require_relative 'faults'
require_relative '../private_file'

module AtlasPca
  module Mpc
    module Net
      # Multi-process launcher: spawns the dealer (when there is one) and each party as its own OS process (party_main) on localhost,
      # generates a fresh per-run identity for each, optionally routes one link through a FaultProxy, and collects each node's
      # one-line JSON verdict. Used by the tests; a real multi-host run uses the same party_main with a config per host.
      module LaunchLocal
        LIB_DIR = File.expand_path('../..', __dir__)
        MAIN = 'require "atlas_pca/mpc_net/party_main"; AtlasPca::Mpc::Net::PartyMain.main(ARGV)'
        HOOK_ENV = 'PCA_MPC_UNSAFE_TEST_HOOKS'

        # json: the node's parsed one-line verdict (nil when it printed none); exit_code nil when it was killed
        NodeOutput = Struct.new(:id, :role, :exit_code, :json, :stderr)
        Launched = Struct.new(:outputs, :wall_ms, :proxy_log)
        # vectors: DecisionVector per party; offline: no-dealer (default) or trusted-dealer (spawns a dealer process, needs
        # insecure_trusted_dealer: true); overrides: { node id => Hash merged over that node's config (config keys, e.g. 'behavior') };
        # wire_fault: { dialer:, target:, fault: WireFault } routes the connection dialer -> target through a faulty TCP proxy;
        # kill_after_ms: hard wall-clock cap per node (kills stragglers)
        Options = Struct.new(:n, :q, :vectors, :recv_timeout_ms, :kill_after_ms, :overrides, :wire_fault, :dealer_seed, :offline,
                             :insecure_trusted_dealer, keyword_init: true)

        module_function

        # the port a node reported on stdout: the first COMPLETE line that is JSON with an Integer `listening` in 1..65535 and, when it has an `id`,
        # that id equal to +id+. Key order is the node's own (Go sorts keys); a partial last line, a non-JSON line or a bad value is never a port.
        def parse_listening(out, id)
          lines = out.split("\n", -1)
          lines.pop # the text after the last newline is not a line yet
          lines.each do |line|
            j = begin
              JSON.parse(line)
            rescue JSON::ParserError
              next
            end
            next unless j.is_a?(Hash) && j['listening'].is_a?(Integer) && j['listening'].between?(1, 65_535)
            next if j.key?('id') && j['id'] != id

            return j['listening']
          end
          nil
        end

        def launch(o)
          n = o.n
          mode = o.offline || 'no-dealer'
          raise ArgumentError, "launch: offline 'trusted-dealer' requires insecure_trusted_dealer: true" if mode == 'trusted-dealer' && o.insecure_trusted_dealer != true

          no_dealer = mode == 'no-dealer'
          node_count = no_dealer ? n : n + 1
          dir = AtlasPca::PrivateFile.mktmpdir('pca-mpc-net-')
          session_id = SecureRandom.hex(8)
          ids = Array.new(node_count) { |i| Certs.generate_identity(File.join(dir, "node#{i}"), "mpc-node-#{i}") }
          t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          # bind first: every node binds port 0 itself and prints {"listening":port}; the full port map is sent on stdin before anyone dials
          procs = Array.new(node_count) do |id|
            nodes = ids.each_with_index.map { |x, j| { 'id' => j, 'host' => '127.0.0.1', 'port' => 0, 'certPath' => x.cert_path } }
            role = !no_dealer && id == n ? 'dealer' : 'party'
            cfg = {
              'role' => role, 'id' => id, 'n' => n, 'Q' => o.q, 'offline' => mode, 'insecureTrustedDealer' => o.insecure_trusted_dealer,
              'sessionId' => session_id, 'listenHost' => '127.0.0.1', 'bindFirst' => true, 'nodes' => nodes, 'keyPath' => ids[id].key_path,
              'certPath' => ids[id].cert_path, 'recvTimeoutMs' => Timing.t(o.recv_timeout_ms || 30_000), 'connectTimeoutMs' => Timing.t(120_000)
            }
            cfg['input'] = { 'allow' => o.vectors[id].allow, 't' => o.vectors[id].t, 'rQuant' => o.vectors[id].r_quant } if id < n
            cfg['dealerSeed'] = o.dealer_seed if id == n && !no_dealer && o.dealer_seed
            cfg.merge!((o.overrides || {})[id] || {})
            cfg.compact!
            hooks = %w[behavior frameFault dealerFault].any? { |k| cfg.key?(k) }
            cfg['unsafeTestHooks'] = true if hooks
            cfg_path = File.join(dir, "cfg#{id}.json")
            AtlasPca::PrivateFile.write(cfg_path, JSON.generate(cfg), binmode: false)
            start_node(id, role, cfg_path, hooks, Timing.t(o.kill_after_ms || 120_000))
          end
          ports = procs.map { |pr| parse_listening(pr.first_line.to_s, pr.id) }
          proxy = nil
          if ports.all?
            proxy_port = 0
            if o.wire_fault
              wf = o.wire_fault
              fault = wf[:fault].dup
              fault.ms = Timing.t(fault.ms) unless fault.ms.nil?
              proxy = FaultProxy.new(0, '127.0.0.1', ports[wf[:target]], fault).listen
              proxy_port = proxy.port
            end
            procs.each_with_index do |pr, id|
              view = ports.each_with_index.to_h { |port, j| [j.to_s, o.wire_fault && id == o.wire_fault[:dialer] && j == o.wire_fault[:target] ? proxy_port : port] }
              begin
                pr.stdin.write(JSON.generate('ports' => view) + "\n")
                pr.stdin.close
              rescue IOError, SystemCallError
                nil # the node already ended; its verdict says why
              end
            end
          else
            procs.each { |pr| pr.kill.call } # a node ended before reporting its port: stop the rest; their verdicts say why
          end
          threads = procs.map { |pr| Thread.new { finish_node(pr) } }
          outputs = threads.map(&:value)
          proxy&.close
          log = proxy ? proxy.log.dup : []
          FileUtils.remove_entry(dir)
          Launched.new(outputs, ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round, log)
        end

        NodeProc = Struct.new(:id, :role, :stdin, :stdout, :stderr, :wait, :first_line, :kill, keyword_init: true)

        def start_node(id, role, cfg_path, hooks, kill_ms)
          env = { HOOK_ENV => hooks ? '1' : nil }
          stdin, stdout, stderr, wait = Open3.popen3(env, RbConfig.ruby, '-I', LIB_DIR, '-e', MAIN, cfg_path)
          kill = lambda do
            Process.kill('KILL', wait.pid)
          rescue StandardError
            nil
          end
          Thread.new { sleep kill_ms / 1000.0; kill.call }.tap { |t| t.report_on_exception = false }
          NodeProc.new(id: id, role: role, stdin: stdin, stdout: stdout, stderr: stderr, wait: wait, first_line: stdout.gets, kill: kill)
        end

        def finish_node(pr)
          so = Thread.new { pr.stdout.read }
          se = Thread.new { pr.stderr.read }
          status = pr.wait.value
          line = (pr.first_line.to_s + so.value.to_s).strip.split("\n").reject(&:empty?).last
          json = begin
            line ? JSON.parse(line) : nil
          rescue JSON::ParserError
            nil
          end
          [pr.stdin, pr.stdout, pr.stderr].each { |io| io.close unless io.closed? }
          NodeOutput.new(pr.id, pr.role, status.exitstatus, json, se.value.to_s[0, 2000])
        end
      end
    end
  end
end
