# frozen_string_literal: true

# The linearizability conformance run for replay / counter stores (port of the TypeScript reference, @atlasauth/pca-store-conformance):
# history recording, the workloads (same-key bursts, a windowed concurrent run, a retention run, a durability run), the reference
# adapters (good ones the kit must pass, bad ones it MUST flag) and the run itself with a text or JSON report. Checking is
# AtlasPca::StoreConformanceModel.
#
# A store adapter is a StoreAdapter: open_store.call returns one client on the shared backend (one simulated verifier instance) with
# consume_once(key, retain_until_ms, now_ms) -> true/false and / or advance(stream_key, counter) -> true/false and optionally #close.
# The contract: consume_once is true iff there is no live record for key (live = its stored horizon is >= now_ms), then records
# retain_until_ms; advance is true iff the counter is strictly greater than the stored one, then stores it; both are atomic across
# every client, durable and fail closed (raise when they cannot decide).
#
# The multi-process crash test (child processes killed with SIGKILL, AtlasPca::StoreConformanceCrash) runs when opts['crash'] names the
# adapter ('module' => spec, 'options', 'processes', 'kill_every_ms'); otherwise it is reported as skipped. Operation options are
# String-keyed snake_case: clients, duration_ms, window_ms, spread, values, retention_ms, op_timeout_ms, rounds, revisit_keys,
# namespace, seed, budget, minimize, minimize_limit, tests, crash.
require 'json'
require 'securerandom'
require 'tmpdir'
require 'fileutils'
require_relative 'store_conformance_model'

module AtlasPca
  module StoreConformanceRunner
    M = StoreConformanceModel
    ALL_TESTS = %w[burst concurrent retention durability crash].freeze

    # name, open_store (a callable returning a client), capabilities ('consume_once' / 'advance' / 'durable' flags; durable defaults
    # to true: a replay store that forgets on restart resurrects nonces), restart, crash and teardown callables (all optional).
    StoreAdapter = Struct.new(:name, :open_store, :capabilities, :restart, :crash, :teardown)

    module_function

    # Wall-clock milliseconds with sub-millisecond resolution.
    def clock = Process.clock_gettime(Process::CLOCK_REALTIME, :float_millisecond)

    # ---- recording -----------------------------------------------------------------------------------------------------

    # The invocation is recorded BEFORE the request leaves the client and the response after it completes. An operation that errors
    # or times out keeps an open-ended interval (ret = Infinity, outcome unknown).
    class MemoryRecorder
      attr_reader :ops

      def initialize
        @ops = []
        @lock = Mutex.new
      end

      def invoke(client, kind, key, lo, w)
        op = { 'client' => client, 'kind' => kind, 'key' => key, 'lo' => lo, 'w' => w, 'call' => StoreConformanceRunner.clock, 'ret' => Float::INFINITY, 'res' => 'unknown' }
        @lock.synchronize { @ops << op }
        op
      end

      def complete(op, result)
        return if result == 'unknown'

        op['ret'] = StoreConformanceRunner.clock
        op['res'] = result ? 'true' : 'false'
      end
    end

    # Appends i / r lines to path (one write per event, so a killed process leaves its operations pending); proc must be unique
    # per process incarnation. Read back with StoreConformanceModel.parse_history.
    class FileRecorder
      def initialize(path, proc_id)
        @io = File.open(path, File::WRONLY | File::APPEND | File::CREAT)
        @proc = proc_id
        @seq = 0
        @ids = {}.compare_by_identity
        @lock = Mutex.new
      end

      def invoke(client, kind, key, lo, w)
        op = { 'client' => client, 'kind' => kind, 'key' => key, 'lo' => lo, 'w' => w, 'call' => StoreConformanceRunner.clock, 'ret' => Float::INFINITY, 'res' => 'unknown' }
        @lock.synchronize do
          @seq += 1
          @ids[op] = @seq
          @io.syswrite("#{JSON.generate(['i', @proc, @seq, op['call'], client, kind, key, lo, w])}\n")
        end
        op
      end

      def complete(op, result)
        @lock.synchronize do
          @io.syswrite("#{JSON.generate(['r', @proc, @ids[op], StoreConformanceRunner.clock, result == 'unknown' ? 'unknown' : (result ? 'true' : 'false')])}\n")
        end
      end

      def close = @io.close
    end

    # ---- workloads -----------------------------------------------------------------------------------------------------

    def random_namespace = format('pcasc-%<t>x-%<r>06x', t: (Time.now.to_f * 1000).to_i, r: SecureRandom.random_number(1 << 24))

    # Settle fn.call as a definite boolean, or 'unknown' on an exception, a timeout or a non-boolean answer.
    def settle(timeout_ms, &fn)
      box = []
      t = Thread.new do
        box << [:ok, fn.call]
      rescue Exception => e # rubocop:disable Lint/RescueException -- any failure of the store is an unknown outcome
        box << [:err, e]
      end
      t.report_on_exception = false
      t.join(timeout_ms / 1000.0)
      return 'unknown' if t.alive? || box.empty? || box[0][0] != :ok

      v = box[0][1]
      v == true || v == false ? v : 'unknown'
    end

    # Record and perform one operation. For advance, value is the counter; for consume it is ignored.
    def perform(client_obj, client, kind, key, value, ctx)
      now = (Time.now.to_f * 1000).to_i
      lo = kind == 'consume' ? now : value
      w = kind == 'consume' ? now + ctx['retention_ms'] : value
      op = ctx['rec'].invoke(client, kind, key, lo, w)
      r = settle(ctx['op_timeout_ms']) { kind == 'consume' ? client_obj.consume_once(key, w, now) : client_obj.advance(key, value) }
      ctx['rec'].complete(op, r)
      r
    end

    # Run every callable in its own thread, released together; an exception is returned as a value.
    def parallel(fns)
      gate = Queue.new
      out = Array.new(fns.length)
      ts = fns.each_index.map do |i|
        Thread.new do
          gate.pop
          out[i] = begin
            fns[i].call
          rescue Exception => e # rubocop:disable Lint/RescueException
            e
          end
        end
      end
      fns.length.times { gate << true }
      ts.each(&:join)
      out
    end

    def open_clients(adapter, n) = Array.new(n) { adapter.open_store.call }

    def close_clients(clients) = clients.each { |c| c.close if c.respond_to?(:close) }

    def defaults(o)
      g = ->(k, d) { o[k].nil? ? d : o[k] }
      { 'clients' => g.call('clients', 16), 'duration_ms' => g.call('duration_ms', 2000), 'window_ms' => g.call('window_ms', 5), 'spread' => g.call('spread', 3),
        'values' => g.call('values', 20), 'retention_ms' => g.call('retention_ms', 600_000), 'op_timeout_ms' => g.call('op_timeout_ms', 5000),
        'rounds' => g.call('rounds', 20), 'revisit_keys' => g.call('revisit_keys', 500), 'namespace' => g.call('namespace', random_namespace),
        'seed' => g.call('seed', SecureRandom.random_number(1 << 31)) }
    end

    def unknown_count(ops) = ops.count { |o| o['res'] == 'unknown' }

    # The client loop of the concurrent run: until deadline, pick one of the spread keys of the current window (all clients compute
    # the same window from origin) and operate on it.
    def drive_windowed(c, client, kind, ctx, namespace, window_ms, spread, values, origin, deadline, rand, now = nil)
      now ||= -> { clock }
      while now.call < deadline
        win = ((now.call - origin) / window_ms).floor
        key = "#{namespace}:#{kind}:#{win}:#{rand.call(spread)}"
        perform(c, client, kind, key, rand.call(values), ctx)
      end
    end

    def context(o, rec) = { 'rec' => rec, 'retention_ms' => o['retention_ms'], 'op_timeout_ms' => o['op_timeout_ms'] }

    # rounds times: every client fires one operation at the SAME fresh key at once.
    def run_burst(adapter, kind, opts = nil)
      o = defaults(opts || {})
      rand = M.prng(o['seed'])
      rec = MemoryRecorder.new
      ctx = context(o, rec)
      clients = open_clients(adapter, o['clients'])
      begin
        o['rounds'].times do |r|
          key = "#{o['namespace']}:#{kind}:burst:#{r}"
          vals = clients.map { rand.call(o['values']) }
          parallel(clients.each_with_index.map { |c, i| -> { perform(c, "c#{i}", kind, key, vals[i], ctx) } })
        end
      ensure
        close_clients(clients)
      end
      { 'ops' => rec.ops, 'errors' => unknown_count(rec.ops) }
    end

    # Every client loops on the windowed keys for duration_ms.
    def run_concurrent(adapter, kind, opts = nil)
      o = defaults(opts || {})
      rec = MemoryRecorder.new
      ctx = context(o, rec)
      clients = open_clients(adapter, o['clients'])
      origin = clock
      begin
        parallel(clients.each_with_index.map do |c, i|
          -> { drive_windowed(c, "c#{i}", kind, ctx, o['namespace'], o['window_ms'], o['spread'], o['values'], origin, origin + o['duration_ms'], M.prng(o['seed'] + i)) }
        end)
      ensure
        close_clients(clients)
      end
      { 'ops' => rec.ops, 'errors' => unknown_count(rec.ops) }
    end

    # Write revisit_keys distinct keys (consume once / advance to 1), then revisit every one while it is still live (same counter):
    # each revisit must answer false. Catches early pruning and capacity eviction of live records.
    def run_retention(adapter, kind, opts = nil)
      o = defaults(opts || {})
      rec = MemoryRecorder.new
      ctx = context(o, rec)
      clients = open_clients(adapter, o['clients'])
      keys = Array.new(o['revisit_keys']) { |i| "#{o['namespace']}:#{kind}:keep:#{i}" }
      begin
        %w[write revisit].each do |ps|
          (0...keys.length).step(clients.length) do |i|
            parallel(clients.each_with_index.select { |_c, j| i + j < keys.length }.map { |c, j| -> { perform(c, "#{ps}-c#{j}", kind, keys[i + j], 1, ctx) } })
          end
        end
      ensure
        close_clients(clients)
      end
      { 'ops' => rec.ops, 'errors' => unknown_count(rec.ops) }
    end

    # Consume a key / advance a stream to 7, close the client, restart the backend when the adapter can, open a new client and read
    # back: the key must stay consumed and the counter must not go backwards (7 refused, 8 accepted).
    def run_durability(adapter, kind, opts = nil)
      o = defaults(opts || {})
      rec = MemoryRecorder.new
      ctx = context(o, rec)
      key = "#{o['namespace']}:#{kind}:durable"
      before = adapter.open_store.call
      begin
        perform(before, 'before-restart', kind, key, 7, ctx)
      ensure
        close_clients([before])
      end
      adapter.restart&.call
      after = adapter.open_store.call
      begin
        perform(after, 'after-restart', kind, key, 7, ctx)
        perform(after, 'after-restart', kind, key, 8, ctx) if kind == 'advance'
      ensure
        close_clients([after])
      end
      { 'ops' => rec.ops, 'errors' => unknown_count(rec.ops),
        'note' => adapter.restart ? 'backend restarted between write and read' : 'no restart hook: clients closed and re-opened only' }
    end

    # ---- reference adapters --------------------------------------------------------------------------------------------

    # A client whose methods are the given lambdas.
    class Client
      def initialize(fns)
        fns.each { |k, v| define_singleton_method(k, &v) }
      end
    end

    # A process-local replay / counter store; the knobs reproduce the real mistakes of the bad adapters. Returns an open callable.
    def lock_store(capacity: nil, strict: true, yield_between: false)
      seen = {}
      counters = {}
      lock = Mutex.new
      evict = lambda do |m|
        m.delete(m.each_key.first) while capacity && m.length > capacity
      end
      lambda do
        consume_once = lambda do |k, r, now|
          if yield_between
            until_ = seen[k]
            sleep(0.0005)
            next false if until_ && !(now.is_a?(Numeric) && now.to_f.finite? && until_ < now)

            seen[k] = r
            next true
          end
          lock.synchronize do
            until_ = seen[k]
            next false if until_ && !(now.is_a?(Numeric) && now.to_f.finite? && until_ < now)

            seen[k] = r
            evict.call(seen)
            true
          end
        end
        advance = lambda do |k, c|
          if yield_between
            last = counters[k]
            sleep(0.0005)
            next false if last && !(c > last)

            counters[k] = c
            next true
          end
          lock.synchronize do
            last = counters[k]
            next false if last && (strict ? !(c > last) : c < last)

            counters[k] = c
            evict.call(counters)
            true
          end
        end
        { 'consume_once' => consume_once, 'advance' => advance }
      end
    end

    # GOOD for ONE process: a lock-protected store. Not durable (declared).
    def in_memory_adapter
      o = lock_store
      StoreAdapter.new('in-memory (lock-protected hash)', -> { Client.new(o.call) }, { 'durable' => false })
    end

    # GOOD: a crash-safe file store (SQLite through SqliteAtomicKv), one handle per client, atomic update.
    def durable_file_adapter(directory = nil)
      require 'digest'
      require_relative 'atomic_kv'
      d = directory || Dir.mktmpdir('pcasc-durable-')
      path = File.join(d, 'state.sqlite')
      open_ = lambda do
        kv = SqliteAtomicKv.new(path)
        consume_once = lambda do |key, retain_until, now|
          raise ArgumentError, 'consume_once: retain_until_ms is before now_ms' unless [now, retain_until].all? { |v| v.is_a?(Numeric) && v.to_f.finite? } && retain_until >= now

          first = false
          kv.update("n:#{key}") do |prev|
            next nil if prev.is_a?(Numeric) && !(now.to_f.finite? && prev < now)

            first = true
            retain_until # any old horizon is < now <= retain_until here, so the new one is the larger
          end
          first
        end
        advance = lambda do |key, counter|
          ok = false
          kv.update("c:#{key}") do |prev|
            next nil if prev.is_a?(Numeric) && !(counter > prev)

            ok = true
            counter
          end
          ok
        end
        Client.new('consume_once' => consume_once, 'advance' => advance, 'close' => -> { kv.close })
      end
      # everything is on disk and every client re-opens the file: a restart loses nothing by construction
      StoreAdapter.new("durable file store (#{d})", open_, { 'durable' => true }, -> {})
    end

    # BAD: read, then write after a yield (no transaction / no compare-and-set). Two clients both read "absent".
    def read_then_write_adapter
      o = lock_store(yield_between: true)
      StoreAdapter.new('BAD read-then-write (a yield between check and set)', -> { Client.new(o.call) }, { 'durable' => false })
    end

    # BAD: claims durability but keeps state in process memory, so a restart forgets every consumed key and counter.
    def volatile_adapter
      holder = [lock_store]
      StoreAdapter.new('BAD volatile (state lost on restart)', -> { Client.new(holder[0].call) }, { 'durable' => true }, -> { holder[0] = lock_store })
    end

    # BAD: a bounded cache that evicts the oldest record when full, LIVE or not (capacity eviction / early prune).
    def evicting_adapter(capacity = 64)
      cap = capacity.to_i
      o = lock_store(capacity: cap)
      StoreAdapter.new("BAD evicting cache (capacity #{cap}, evicts live records)", -> { Client.new(o.call) }, { 'durable' => false })
    end

    # BAD: a counter that accepts a value EQUAL to the last one (>= instead of >), so one counter is accepted twice.
    def non_strict_counter_adapter
      o = lock_store(strict: false)
      StoreAdapter.new('BAD non-strict counter (accepts an equal value)', -> { Client.new('advance' => o.call['advance']) }, { 'durable' => false, 'consume_once' => false })
    end

    # Built-in adapters by name; each takes the options Hash.
    REFERENCE_ADAPTERS = {
      'in-memory' => ->(_o) { in_memory_adapter },
      'durable-file' => ->(o) { durable_file_adapter(o['dir']) },
      'bad-read-then-write' => ->(_o) { read_then_write_adapter },
      'bad-volatile' => ->(_o) { volatile_adapter },
      'bad-evicting' => ->(o) { evicting_adapter(o.fetch('capacity', 64)) },
      'bad-non-strict-counter' => ->(_o) { non_strict_counter_adapter }
    }.freeze

    # ---- the run -------------------------------------------------------------------------------------------------------

    # Which operations the adapter implements: declared capabilities win, else what its first client exposes.
    def detect_kinds(adapter)
      caps = adapter.capabilities || {}
      c = adapter.open_store.call
      begin
        kinds = []
        kinds << 'consume' if caps['consume_once'].nil? ? c.respond_to?(:consume_once) : caps['consume_once']
        kinds << 'advance' if caps['advance'].nil? ? c.respond_to?(:advance) : caps['advance']
        kinds
      ensure
        close_clients([c])
      end
    end

    def judge(test, kind, w, opts)
      h = M.check_history(w['ops'], opts)
      definite = h['outcomes']['true'] + h['outcomes']['false']
      status = if !h['violations'].empty? then 'fail'
               elsif !h['unresolved'].empty? || definite.zero? then 'unresolved'
               else 'pass'
               end
      notes = [w['note'], definite.zero? ? 'no definite answer was observed (every call failed or timed out)' : nil].compact.reject(&:empty?)
      out = { 'test' => test, 'kind' => kind, 'status' => status, 'ops' => h['ops'], 'keys' => h['keys'], 'errors' => w['errors'],
              'violations' => h['violations'], 'unresolved' => h['unresolved'].length }
      out['note'] = notes.join('; ') unless notes.empty?
      out
    end

    def skipped(test, kind, note)
      { 'test' => test, 'kind' => kind, 'status' => 'skip', 'ops' => 0, 'keys' => 0, 'errors' => 0, 'violations' => [], 'unresolved' => 0, 'note' => note }
    end

    def run_test(adapter, test, kind, opts = nil)
      opts ||= {}
      if test == 'durability' && (adapter.capabilities || {})['durable'] == false
        return skipped(test, kind, 'the adapter declares durable: false (only correct for one process whose lifetime covers the action lifetime)')
      end

      crash = opts['crash'].is_a?(Hash) ? opts['crash'] : {}
      return skipped(test, kind, 'needs the adapter module path (the crash test runs the adapter in child processes)') if test == 'crash' && !Js.truthy?(crash['module'])

      w = if test == 'crash'
            require_relative 'store_conformance_crash' # lazy: the crash harness needs this module
            StoreConformanceCrash.run_crash(kind, opts.merge(crash))
          else
            { 'burst' => method(:run_burst), 'concurrent' => method(:run_concurrent), 'retention' => method(:run_retention), 'durability' => method(:run_durability) }.fetch(test).call(adapter, kind, opts)
          end
      judge(test, kind, w, opts)
    end

    # Every test for every operation the adapter implements, each history checked for linearizability. opts['tests'] selects tests.
    def run_conformance(adapter, opts = nil)
      opts ||= {}
      kinds = detect_kinds(adapter)
      raise TypeError, "#{adapter.name}: the client implements neither consume_once nor advance" if kinds.empty?

      tests = (opts['tests'] || ALL_TESTS).flat_map { |t| kinds.map { |k| run_test(adapter, t, k, opts) } }
      { 'adapter' => adapter.name, 'status' => M.overall(tests), 'tests' => tests }
    end

    def format_report(r, max_keys = 3) = M.format_report(r, max_keys)
    def report_json(r) = M.report_json(r)
  end
end
