# frozen_string_literal: true

# One client process of the multi-process crash harness (AtlasPca::StoreConformanceCrash): load the adapter, run the windowed workload
# on several threads, record the history to a file. Run as
#   ruby -I lib -r atlas_pca/store_conformance_worker -e 'AtlasPca::StoreConformanceWorker.main(ARGV)' '<json config>'
require 'json'
require_relative 'store_conformance_load'

module AtlasPca
  module StoreConformanceWorker
    R = StoreConformanceRunner

    module_function

    def worker_main(cfg)
      adapter = StoreConformanceLoad.load_adapter(cfg['module'], cfg['options'])
      rec = R::FileRecorder.new(cfg['file'], cfg['proc'])
      clients = R.open_clients(adapter, cfg['clients'])
      ctx = { 'rec' => rec, 'retention_ms' => cfg['retention_ms'], 'op_timeout_ms' => cfg['op_timeout_ms'] }
      errs = []
      lock = Mutex.new
      ts = clients.each_with_index.map do |c, i|
        Thread.new do
          R.drive_windowed(c, "#{cfg['proc']}c#{i}", cfg['kind'], ctx, cfg['namespace'], cfg['window_ms'], cfg['spread'], cfg['values'],
                           cfg['origin'], cfg['deadline'], StoreConformanceModel.prng(cfg['seed'] + i))
        rescue Exception => e # rubocop:disable Lint/RescueException
          lock.synchronize { errs << e }
        end
      end
      ts.each(&:join)
      R.close_clients(clients)
      rec.close
      adapter.teardown&.call
      raise errs[0] unless errs.empty?
    end

    # Exit code of the worker command line.
    def main(argv)
      worker_main(JSON.parse(argv[0]))
      0
    rescue Exception => e # rubocop:disable Lint/RescueException
      warn "pca-store-conformance worker: #{e.message}"
      exit(1)
    end
  end
end
