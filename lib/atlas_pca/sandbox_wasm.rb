# frozen_string_literal: true

require 'json'
require 'open3'
require 'openssl'
require 'tmpdir'
require 'fileutils'
require_relative '../atlas_pca'

module AtlasPca
  # WebAssembly hosts for the sandbox handle table (opt-in: `require 'atlas_pca/sandbox_wasm'`; the core-module host needs the
  # `wasmtime` gem, which is loaded lazily and refused with `wasmtime_unavailable` when absent).
  #
  # run_core_module runs a hand-built or compiled core module in-process under wasmtime with an instruction budget (fuel), a wall-clock
  # deadline (epoch interruption), a hard linear-memory cap and no ambient authority: WASI is never configured or linked, the only
  # imports are pca:act.{invoke,handle_count,handle_verb}. run_component runs a component in the pinned reference wasmtime host binary
  # as a subprocess. Both serve the guest only from a Sandbox::HandleTable; the table decides every use.
  module SandboxWasm
    SAFE = 9_007_199_254_740_991
    S = Sandbox
    EPOCH_TICK_MS = 10
    HEX64 = /\A\h{64}\z/

    module_function

    def refuse(reason) = { 'ok' => false, 'reason' => reason }
    def bad_fuel?(fuel) = !fuel.is_a?(Integer) || fuel < 1 || fuel > SAFE

    # Parse only the memory section: {count, min, max, shared} of the first memory, nil = no memory section, :bad = unparseable.
    # A flag above 3 (memory64 and anything newer) reads as shared, so it is refused.
    def memory_limits(bytes)
      b = bytes.b
      return :bad if b.bytesize < 8 || b.getbyte(0) != 0 || b.byteslice(1, 3) != 'asm'

      o = 8
      leb = lambda do
        r = 0
        5.times do |i|
          x = b.getbyte(o)
          raise EOFError if x.nil?

          o += 1
          r += (x & 0x7F) * (2**(7 * i))
          return r if x.nobits?(0x80)
        end
        raise ArgumentError, 'leb'
      end
      while o < b.bytesize
        sid = b.getbyte(o)
        o += 1
        size = leb.call
        stop = o + size
        return :bad if stop > b.bytesize

        if sid == 5
          count = leb.call
          return nil if count.zero?

          flag = b.getbyte(o)
          raise EOFError if flag.nil?

          o += 1
          return { 'count' => count, 'min' => Float::INFINITY, 'max' => nil, 'shared' => true } if flag > 3

          mn = leb.call
          mx = flag.anybits?(1) ? leb.call : nil
          return { 'count' => count, 'min' => mn, 'max' => mx, 'shared' => flag.anybits?(2) }
        end
        o = stop
      end
      nil
    rescue EOFError, ArgumentError
      :bad
    end

    # Run `wasm`'s `entry` export. `fuel` (a positive safe integer) is required: a budget is a decision. Refuses to run (fail closed) if
    # the engine cannot enforce fuel, the wall-clock deadline or the memory cap. Returns {'ok' => true, 'value' => Integer} or
    # {'ok' => false, 'reason' => String}.
    # A runtime memory.grow past the cap makes the guest see -1 (wasmtime's store limiter), exactly like the reference; the
    # declared-maximum check refuses the static cases as memory_limits.
    def run_core_module(table, wasm, entry = 'run', fuel: nil, timeout_ms: 5000, max_module_bytes: 1 << 20, max_memory_pages: 256,
                        max_result_bytes: 1 << 20)
      return refuse('bad_fuel') if bad_fuel?(fuel)
      return refuse('module_size') unless wasm.is_a?(String) && !wasm.empty? && wasm.bytesize <= max_module_bytes

      wasm = wasm.b
      mem = memory_limits(wasm)
      return refuse('malformed_module') if mem == :bad
      if mem && (mem['count'] > 1 || mem['max'].nil? || mem['shared'] || !(mem['min'] <= max_memory_pages) || !(mem['max'] <= max_memory_pages))
        return refuse('memory_limits')
      end

      begin
        require 'wasmtime'
      rescue LoadError
        return refuse('wasmtime_unavailable')
      end
      w = ::Wasmtime
      begin
        engine = w::Engine.new(consume_fuel: true, epoch_interruption: true)
      rescue StandardError
        return refuse('limit_unenforceable:fuel')
      end
      # the epoch ticker runs outside the Ruby GVL, so it can stop a guest that never yields
      return refuse('limit_unenforceable:timeout') unless engine.respond_to?(:start_epoch_interval)

      begin
        mod = w::Module.new(engine, wasm)
      rescue StandardError
        return refuse('malformed_module')
      end
      mod.imports.each do |i|
        func = begin
          i['type'].to_func_type
          true
        rescue StandardError
          false
        end
        return refuse("ambient_import:#{i['module']}.#{i['name']}") unless i['module'] == S::IMPORT_MODULE && func && S::ALLOWED_IMPORTS.include?(i['name'])
      end

      begin
        store = w::Store.new(engine, limits: { memory_size: max_memory_pages * 65_536 })
      rescue StandardError
        return refuse('limit_unenforceable:memory')
      end
      begin
        store.set_fuel(fuel)
      rescue StandardError
        return refuse('limit_unenforceable:fuel')
      end
      ticks = [(timeout_ms.to_f / EPOCH_TICK_MS).ceil, 1].max
      begin
        store.set_epoch_deadline(ticks)
      rescue StandardError
        return refuse('limit_unenforceable:timeout')
      end

      window = lambda do |caller, ptr, len|
        m = begin
          e = caller.export('memory')
          e = e.to_memory if e.respond_to?(:to_memory)
          e.is_a?(w::Memory) ? e : nil
        rescue StandardError
          nil
        end
        p = ptr & 0xFFFFFFFF
        n = len & 0xFFFFFFFF
        m && p + n <= m.data_size ? [m, p, n] : nil
      end
      put = ->(win, data) { win[0].write(win[1], data) unless data.empty? }

      linker = w::Linker.new(engine) # no WASI: the guest has no ambient authority
      linker.func_new(S::IMPORT_MODULE, 'handle_count', [], [:i32]) { |_c| table.size }
      linker.func_new(S::IMPORT_MODULE, 'handle_verb', %i[i32 i32 i32], [:i32]) do |caller, h, ptr, cap|
        verb = table.verb_of(h)
        next S::USE_ERR['unknown_handle'] if verb.nil?

        enc = verb.encode('UTF-8', invalid: :replace, undef: :replace).b
        win = window.call(caller, ptr, cap)
        next S::USE_ERR['bad_memory'] if win.nil?
        next S::USE_ERR['out_too_small'] if enc.bytesize > win[2]

        put.call(win, enc)
        enc.bytesize
      end
      linker.func_new(S::IMPORT_MODULE, 'invoke', %i[i32 i32 i32], [:i32]) do |caller, h, ptr, cap|
        win = window.call(caller, ptr, cap) # validate the output window before a use is spent
        next S::USE_ERR['bad_memory'] if win.nil?

        r = table.use(h)
        next S::USE_ERR[r['reason']] unless r['ok']

        res = r['result']
        next S::USE_ERR['out_too_small'] if !(res.bytesize <= max_result_bytes) || res.bytesize > win[2]

        put.call(win, res)
        res.bytesize
      end

      classify = lambda do |e, instantiating|
        if e.is_a?(w::Trap)
          code = e.code
          next refuse('fuel_exhausted') if code == w::Trap::OUT_OF_FUEL
          next refuse('timeout') if code == w::Trap::INTERRUPT

          next refuse(store.linear_memory_limit_hit? ? 'memory_limits' : 'trap:RuntimeError')
        end
        msg = e.message.to_s.downcase
        next refuse('fuel_exhausted') if msg.include?('all fuel consumed') || msg.include?('out of fuel')
        next refuse('timeout') if msg.include?('interrupt')

        hit = begin
          store.linear_memory_limit_hit?
        rescue StandardError
          false
        end
        next refuse('memory_limits') if hit || (msg.include?('memory') && (msg.include?('minimum') || msg.include?('limit') || msg.include?('exceed')))

        refuse(instantiating ? 'trap:LinkError' : 'trap:RuntimeError')
      end

      engine.start_epoch_interval(EPOCH_TICK_MS)
      begin
        begin
          instance = linker.instantiate(store, mod)
        rescue StandardError => e
          return classify.call(e, true)
        end
        fn = begin
          entry.is_a?(String) ? instance.export(entry)&.to_func : nil
        rescue StandardError
          nil
        end
        return refuse('no_entry') if fn.nil?

        begin
          v = fn.call
        rescue StandardError => e
          return classify.call(e, false)
        end
        v.is_a?(Numeric) ? { 'ok' => true, 'value' => v } : { 'ok' => true, 'value' => 0 }
      ensure
        engine.stop_epoch_interval
      end
    end

    # ------------------------------------------------------------------------------------------------ component host
    MAX_LINE = 32 << 20

    # Run a component (binary or WAT text) in the reference wasmtime host binary, as a subprocess, with an instruction budget.
    # The binary path comes from configuration only (`host:`, else env PCA_WASMTIME_HOST) and is pinned by SHA-256 (`expected_sha256:`,
    # else env PCA_WASMTIME_HOST_SHA256), checked on every call; never a PATH search. The verified bytes are copied into a fresh 0700
    # temp dir and THAT copy is executed, so the file cannot change between the hash and the exec (no TOCTOU window). The child gets an
    # empty environment, no shell and no stderr.
    def run_component(table, component, fuel: nil, timeout_ms: 10_000, host: nil, expected_sha256: nil, max_result_bytes: 1 << 20)
      return refuse('bad_fuel') if bad_fuel?(fuel)

      host ||= ENV.fetch('PCA_WASMTIME_HOST', nil)
      packaged = host.nil? || host.empty?
      host = File.join(__dir__, 'native', Gem.win_platform? ? 'pca-wasmtime-host.exe' : 'pca-wasmtime-host') if packaged # the platform gem's own host, pinned by the digest file shipped beside it
      return refuse('host_missing') unless File.file?(host)

      binary = begin
        File.binread(host)
      rescue SystemCallError
        return refuse('host_missing')
      end
      pin = expected_sha256 || ENV.fetch('PCA_WASMTIME_HOST_SHA256', nil)
      pin ||= (File.read("#{host}.sha256", 128).split.first if packaged && File.file?("#{host}.sha256"))
      return refuse('host_unpinned') unless pin.is_a?(String) && HEX64.match?(pin)
      return refuse('host_hash_mismatch') unless OpenSSL.fixed_length_secure_compare(OpenSSL::Digest::SHA256.hexdigest(binary), pin.downcase)

      dir = Dir.mktmpdir('pca-comp-') # 0700
      stdin = stdout = thr = nil
      begin
        exe = File.join(dir, 'host')
        File.binwrite(exe, binary)
        File.chmod(0o700, exe)
        comp = File.join(dir, 'tool.component')
        File.binwrite(comp, component.b)
        begin
          stdin, stdout, thr = Open3.popen2({}, exe, comp, fuel.to_s, unsetenv_others: true, err: File::NULL, close_others: true)
        rescue SystemCallError
          return refuse('host_unavailable')
        end
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + [timeout_ms, 0].max / 1000.0
        buf = +''.b
        read_line = lambda do
          loop do
            if (i = buf.index("\n"))
              break buf.slice!(0, i + 1)
            end
            break :protocol if buf.bytesize > MAX_LINE

            left = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            break :timeout if left <= 0
            break :timeout unless IO.select([stdout], nil, nil, left)

            chunk = stdout.read_nonblock(65_536, exception: false)
            break :eof if chunk.nil?

            buf << chunk unless chunk == :wait_readable
          end
        end
        reply = lambda do |v|
          stdin.write("#{JSON.generate(v)}\n")
          stdin.flush
        end

        loop do
          line = read_line.call
          return refuse('timeout') if line == :timeout
          return refuse('host_exit') if line == :eof
          return refuse('host_protocol') if line == :protocol

          m = begin
            JSON.parse(line)
          rescue JSON::ParserError
            nil
          end
          return refuse('host_protocol') unless m.is_a?(Hash)
          return refuse(m['fail']) if m['fail'].is_a?(String)

          done = m['done']
          if done.is_a?(Numeric)
            out = { 'ok' => true, 'value' => done }
            out['fuel_used'] = m['fuel_used'] if m['fuel_used'].is_a?(Numeric)
            return out
          end
          h = m['h'].is_a?(Integer) ? m['h'] : 0
          case m['op']
          when 'count' then reply.call({ 'n' => table.size })
          when 'verb'
            v = table.verb_of(h)
            reply.call(v.nil? ? { 'err' => S::USE_ERR['unknown_handle'] } : { 'ok' => v })
          when 'invoke'
            r = table.use(h)
            if !r['ok']
              reply.call({ 'err' => S::USE_ERR[r['reason']] })
            else
              reply.call(!(r['result'].bytesize <= max_result_bytes) ? { 'err' => S::USE_ERR['out_too_small'] } : { 'ok' => r['result'].bytes })
            end
          else
            return refuse('host_protocol')
          end
        end
      rescue Errno::EPIPE, IOError
        refuse('host_exit')
      ensure
        if thr
          begin
            Process.kill('KILL', thr.pid)
          rescue SystemCallError
            nil
          end
        end
        [stdin, stdout].each { |s| s&.close unless s&.closed? }
        thr&.join
        FileUtils.rm_rf(dir)
      end
    end

    # A WebAssembly host whose only authority is the handles minted into `table`: the composition `create_sandbox` returns (the receipt log,
    # the handle table and the two guest hosts over that one table). `run` is the in-process core-module host (instruction budget, wall-clock
    # deadline, memory cap); `run_component` the pinned-subprocess component host.
    class Host
      attr_reader :table, :log

      def initialize(table, log, limits)
        @table = table
        @log = log
        @limits = limits
      end

      def run(wasm, entry = 'run', fuel: nil, timeout_ms: 5000)
        SandboxWasm.run_core_module(@table, wasm, entry, fuel: fuel, timeout_ms: timeout_ms, **@limits)
      end

      def run_component(component, fuel: nil, timeout_ms: 10_000, host: nil, expected_sha256: nil)
        SandboxWasm.run_component(@table, component, fuel: fuel, timeout_ms: timeout_ms, host: host, expected_sha256: expected_sha256,
                                                     max_result_bytes: @limits[:max_result_bytes])
      end
    end

    WASM_PROVABLE_CLASSES = %w[wasi_no_ambient egress_default_deny os_confined].freeze

    # The single entry point (the reference's createSandbox): a receipt log, a handle table whose runtime class is what `runtime_claim`
    # ({'claim', 'trust'}) verifies to (capped at what a WASM host can prove; without a claim that verifies the class is `none`: an operator's
    # say-so does not count) and the guest hosts. `executors` maps a verb to ->(op) { binary String }. A memory without a declared maximum, an
    # import outside `pca:act` or a module over `max_module_bytes` is refused before anything runs.
    def create_sandbox(executors, log: nil, now: nil, max_module_bytes: 1 << 20, max_memory_pages: 256, max_result_bytes: 1 << 20, runtime_claim: nil)
      log ||= S::ReceiptLog.new(now: now)
      proven = runtime_claim ? S.verified_runtime_class(runtime_claim['claim'], runtime_claim['trust']) : 'none'
      cls = WASM_PROVABLE_CLASSES.include?(proven) ? proven : 'none'
      table = S::HandleTable.new(cls, log, executors, now)
      Host.new(table, log, { max_module_bytes: max_module_bytes, max_memory_pages: max_memory_pages, max_result_bytes: max_result_bytes })
    end
  end

  def self.create_sandbox(executors, **opts) = SandboxWasm.create_sandbox(executors, **opts)
end
