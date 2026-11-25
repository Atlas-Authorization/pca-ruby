# frozen_string_literal: true

# Multi-process crash harness (port of the TypeScript reference, @atlasauth/pca-store-conformance, crash.ts). Several client PROCESSES
# (each with several clients) run the windowed workload against the same backend and append their histories to per-process files; the
# parent SIGKILLs a random client process every kill_every_ms and starts a replacement under a new identity, so killed processes leave
# PENDING operations. When the adapter has crash, the backend is crashed and restarted once mid-run. The parent waits for EVERY
# writer to exit before reading the histories (a partial history can make a FALSE look unexplained).
require 'json'
require_relative 'private_file'
require 'rbconfig'
require 'securerandom'
require 'tmpdir'
require_relative 'store_conformance_load'

module AtlasPca
  module StoreConformanceCrash
    R = StoreConformanceRunner
    LIB_DIR = File.expand_path('..', __dir__)
    WORKER_CODE = "require 'atlas_pca/store_conformance_worker'; exit(AtlasPca::StoreConformanceWorker.main(ARGV))"

    module_function

    def alive?(pid)
      Process.wait(pid, Process::WNOHANG).nil?
    rescue Errno::ECHILD
      false
    end

    # o: the workload options (clients per process, duration_ms, window_ms, spread, values, retention_ms, op_timeout_ms, namespace, seed)
    # plus 'module' (required), 'options', 'processes' (3), 'kill_every_ms' (400), 'backend_crash' (true), 'dir', 'worker_command'
    # (default: this Ruby running the worker module).
    def run_crash(kind, o)
      g = ->(k, d) { o[k].nil? ? d : o[k] }
      d = o['dir'] || AtlasPca::PrivateFile.mktmpdir('pcasc-hist-')
      duration_ms = g.call('duration_ms', 3000)
      kill_every = g.call('kill_every_ms', 400)
      seed = g.call('seed', SecureRandom.random_number(1 << 31))
      rand = StoreConformanceModel.prng(seed)
      origin = R.clock
      deadline = origin + duration_ms
      base = { 'module' => o['module'], 'options' => g.call('options', {}), 'kind' => kind, 'clients' => g.call('clients', 4),
               'namespace' => g.call('namespace', R.random_namespace), 'window_ms' => g.call('window_ms', 5), 'spread' => g.call('spread', 3),
               'values' => g.call('values', 20), 'retention_ms' => g.call('retention_ms', 600_000), 'op_timeout_ms' => g.call('op_timeout_ms', 5000),
               'origin' => origin, 'deadline' => deadline }
      cmd = o['worker_command'] || [RbConfig.ruby, '-I', LIB_DIR, '-e', WORKER_CODE]
      live = []
      every = []
      n = 0
      spawn_one = lambda do
        proc_id = "p#{n}"
        cfg = base.merge('proc' => proc_id, 'file' => File.join(d, "h-#{proc_id}.jsonl"), 'seed' => seed + (7919 * n))
        n += 1
        pid = Process.spawn(*cmd, JSON.generate(cfg), in: File::NULL, out: File::NULL)
        live << pid
        every << pid
      end
      g.call('processes', 3).times { spawn_one.call }
      control = o['backend_crash'] == false ? nil : StoreConformanceLoad.load_adapter(o['module'], g.call('options', {}))
      kills = backend_crashes = 0
      half = origin + (duration_ms / 2.0)
      begin
        while kill_every.positive? && R.clock + kill_every < deadline
          sleep(kill_every / 1000.0)
          live.select! { |pid| alive?(pid) }
          unless live.empty?
            begin
              Process.kill('KILL', live[rand.call(live.length)])
              kills += 1
            rescue Errno::ESRCH
              nil # it exited on its own a moment ago
            end
            spawn_one.call
          end
          if control&.crash && backend_crashes.zero? && R.clock >= half
            control.crash.call
            control.restart&.call
            backend_crashes += 1
          end
        end
      ensure
        every.each do |pid|
          Process.wait(pid)
        rescue Errno::ECHILD
          nil
        end
        control&.teardown&.call
      end
      text = Dir.children(d).sort.select { |f| f.start_with?('h-') && f.end_with?('.jsonl') }.map { |f| File.read(File.join(d, f), encoding: 'UTF-8') }.join("\n")
      h = StoreConformanceModel.parse_history(text)
      { 'ops' => h['ops'], 'errors' => h['ops'].count { |x| x['res'] == 'unknown' }, 'kills' => kills, 'backendCrashes' => backend_crashes,
        'torn' => h['torn'], 'pending' => h['pending'], 'processes' => n }
    end
  end
end
