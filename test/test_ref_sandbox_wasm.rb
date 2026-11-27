# frozen_string_literal: true

# Sandbox WebAssembly hosts: the in-process wasmtime core-module host (fuel, wall-clock deadline, memory cap, no ambient authority) and
# the pinned-subprocess component host. Tests that need the wasmtime gem skip, with the reason, when it is absent; CI installs it. The
# real component run is guarded by PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/sandbox_wasm'
require 'minitest/autorun'
require 'digest'
require 'rbconfig'
require 'tmpdir'

HAVE_WASMTIME = begin
  require 'wasmtime'
  true
rescue LoadError
  false
end

class TestRefSandboxWasm < Minitest::Test
  S = AtlasPca::Sandbox
  W = AtlasPca::SandboxWasm
  FUEL = 1_000_000
  REAL_HOST = ENV.fetch('PCA_WASMTIME_HOST_BIN', nil)
  REAL_PIN = ENV.fetch('PCA_WASMTIME_HOST_SHA256', nil)

  IN_CI = !ENV.fetch('CI', '').empty? # in CI a missing engine or host is a failure, never a skip

  def need_wasmtime
    return if HAVE_WASMTIME

    flunk('CI must install the wasmtime gem') if IN_CI
    skip('wasmtime gem not installed (gem install wasmtime)')
  end

  def test_ci_has_engine_and_real_host
    skip('CI only') unless IN_CI
    assert HAVE_WASMTIME, 'CI must install the wasmtime gem'
    assert REAL_HOST && REAL_PIN, 'CI must export PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256'
  end

  def res(verb, op) = { 'allow' => true, 'operation' => { 'verb' => verb, 'resource' => 'r', 'params_digest' => AtlasPca.hash_canonical(op['params']), 'id' => 'op1' } }

  def table(executors, verbs = %w[fetch], cls = 'wasi_no_ambient')
    log = S::ReceiptLog.new(now: -> { 0 })
    t = S::HandleTable.new(cls, log, executors, -> { 0 })
    verbs.each do |v|
      op = { 'verb' => v, 'resource' => 'r', 'params' => { 'url' => 'https://example.com/a' } }
      t.mint(res(v, op), op, { 'uses' => 5 })
    end
    [t, log]
  end

  def tool(**kw) = S.build_tool({ 'calls' => [{ 'handle' => 1, 'ptr' => 0, 'cap' => 16 }], 'returns' => 'byte0' }.merge(kw.transform_keys(&:to_s)))
  def run_core(table, wasm, entry = 'run', **kw) = W.run_core_module(table, wasm, entry, **{ fuel: FUEL }.merge(kw))
  def sha(b) = Digest::SHA256.hexdigest(b)
  def reason(r) = r['reason']

  def test_fuel_is_required
    t, = table({})
    [nil, 0, -1, true, 1.5, '9', 2**53].each { |f| assert_equal({ 'ok' => false, 'reason' => 'bad_fuel' }, W.run_core_module(t, tool, fuel: f), f.inspect) }
    assert_equal({ 'ok' => false, 'reason' => 'bad_fuel' }, W.run_component(t, 'x', fuel: 0, host: '/nope'))
  end

  def test_create_sandbox_composes_one_table_over_the_log_and_both_hosts
    sb = AtlasPca.create_sandbox({}, now: -> { 0 }, max_module_bytes: 10)
    assert_equal 'none', sb.table.runtime_class # no claim that verifies: an operator's say-so does not count
    assert_equal 0, sb.table.size
    assert_equal({ 'ok' => false, 'reason' => 'bad_fuel' }, sb.run(tool))
    assert_equal 'module_size', sb.run(tool, fuel: FUEL)['reason'] # the limits given to create_sandbox reach the host
    assert_equal 'bad_fuel', sb.run_component('x', fuel: 0, host: '/nope')['reason']
  end

  def test_module_size_and_malformed
    t, = table({})
    assert_equal 'module_size', reason(run_core(t, ''.b))
    assert_equal 'module_size', reason(run_core(t, tool, max_module_bytes: 10))
    assert_equal 'malformed_module', reason(run_core(t, 'not wasm at all'))
    assert_equal 'malformed_module', reason(run_core(t, "\0asm\1\0\0\0\x01\x09\0".b)) # section overruns the module
  end

  def test_memory_limits_are_refused_before_anything_runs
    t, = table({})
    [{ 'min' => 1, 'max' => nil }, { 'min' => 1, 'max' => 257 }, { 'min' => 300, 'max' => 300 }].each do |mem|
      assert_equal 'memory_limits', reason(run_core(t, tool(memory: mem))), mem.inspect
    end
    shared = tool.dup
    i = shared.index([1, 1, 1].pack('C*'), shared.index("\x05".b))
    shared.setbyte(i + 1, 3) # flag 3 = max + shared
    assert_equal 'memory_limits', reason(run_core(t, shared))
    shared.setbyte(i + 1, 5) # flag above 3 = memory64
    assert_equal 'memory_limits', reason(run_core(t, shared))
    assert_equal({ 'count' => 1, 'min' => 1, 'max' => 2, 'shared' => false }, W.memory_limits(tool(memory: { 'min' => 1, 'max' => 2 })))
    assert_nil W.memory_limits("\0asm\1\0\0\0".b)
  end

  def test_happy_path_writes_result_into_memory_and_logs_a_receipt
    need_wasmtime
    t, log = table({ 'fetch' => ->(_op) { [42, 1, 2, 3].pack('C*') } })
    assert_equal({ 'ok' => true, 'value' => 42 }, run_core(t, tool))
    assert_equal [%w[ok used]], log.entries.map { |e| [e['outcome'], e['reason']] }
    assert S.verify_receipt_chain(log.entries)['ok']
  end

  def test_probe_tool_reads_handle_count_and_verb
    need_wasmtime
    t, = table({}, %w[fetch send])
    assert_equal({ 'ok' => true, 'value' => (2 * 256) + 'f'.ord }, run_core(t, S.build_probe_tool))
    assert_equal({ 'ok' => true, 'value' => 2 * 256 }, run_core(t, S.build_probe_tool(3))) # "fetch" > cap: -3 ignored, byte 0 of memory
  end

  def test_bad_window_spends_no_use_and_small_cap_is_refused
    need_wasmtime
    t, log = table({ 'fetch' => ->(_op) { 'abcd'.b } })
    one = ->(h, ptr, cap) { run_core(t, S.build_tool({ 'calls' => [{ 'handle' => h, 'ptr' => ptr, 'cap' => cap }] })) }
    assert_equal({ 'ok' => true, 'value' => -4 }, one.call(1, 65_530, 100))
    assert_empty log.entries
    assert_equal({ 'ok' => true, 'value' => -3 }, one.call(1, 0, 2))
    assert_equal({ 'ok' => true, 'value' => -1 }, one.call(9, 0, 8)) # unknown handle
    assert_equal({ 'ok' => true, 'value' => -4 }, one.call(1, -8, 16)) # the unsigned 32-bit window check: ptr + len must not wrap
  end

  def test_result_over_max_result_bytes_is_out_too_small
    need_wasmtime
    t, = table({ 'fetch' => ->(_op) { 'x'.b * 10 } })
    assert_equal({ 'ok' => true, 'value' => -3 }, run_core(t, tool(returns: 'last'), max_result_bytes: 4)) # the call's return code, not memory byte 0
  end

  def test_no_entry
    need_wasmtime
    t, = table({ 'fetch' => ->(_op) { "\x07".b } })
    assert_equal({ 'ok' => false, 'reason' => 'no_entry' }, run_core(t, tool, 'missing'))
    assert_equal({ 'ok' => false, 'reason' => 'no_entry' }, run_core(t, tool, 'memory')) # exported, but a memory
  end

  def test_malformed_for_the_engine
    need_wasmtime
    t, = table({})
    assert_equal 'malformed_module', reason(run_core(t, "\0asm\1\0\0\0".b + [1, 1, 0xFF].pack('C*')))
  end

  def test_forbidden_imports_are_refused
    need_wasmtime
    [{ 'module' => 'wasi_snapshot_preview1', 'name' => 'fd_write' }, { 'module' => 'env', 'name' => 'x' }, { 'module' => 'pca:act', 'name' => 'other' }].each do |extra|
      t, log = table({ 'fetch' => ->(_op) { "\x01".b } })
      assert_equal({ 'ok' => false, 'reason' => "ambient_import:#{extra['module']}.#{extra['name']}" }, run_core(t, tool(extra_imports: [extra])))
      assert_empty log.entries
    end
  end

  def test_infinite_loop_stops_on_fuel
    need_wasmtime
    t, = table({ 'fetch' => ->(_op) { "\x01".b } })
    assert_equal({ 'ok' => false, 'reason' => 'fuel_exhausted' }, run_core(t, tool(spin: true), fuel: 50_000))
  end

  def test_infinite_loop_stops_on_the_wall_clock_even_with_huge_fuel
    need_wasmtime
    t, = table({ 'fetch' => ->(_op) { "\x01".b } })
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert_equal({ 'ok' => false, 'reason' => 'timeout' }, run_core(t, tool(spin: true), fuel: 2**52, timeout_ms: 200))
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0, :<, 10
  end

  def grow_module(delta, mem_max)
    body = [0] + S.i32c(delta) + [0x40, 0x00, 0x0B] # memory.grow 0
    out = [0, 0x61, 0x73, 0x6D, 1, 0, 0, 0] + S.section(1, S.vec([[0x60, 0, 1, 0x7F]])) + S.section(3, S.vec([[0]])) +
          S.section(5, S.vec([[1] + S.leb_u(1) + S.leb_u(mem_max)])) + S.section(7, S.vec([S.wstr('run') + [0, 0]])) +
          S.section(10, S.vec([S.leb_u(body.length) + body]))
    out.pack('C*')
  end

  def test_runtime_growth_past_the_declared_maximum_is_stopped
    need_wasmtime
    t, = table({})
    assert_equal({ 'ok' => true, 'value' => 1 }, run_core(t, grow_module(1, 2))) # within the cap: the old size in pages
    assert_equal({ 'ok' => true, 'value' => -1 }, run_core(t, grow_module(5, 2))) # past max: memory.grow fails
    # a cap lower than the declared module is a static refusal, so growth can never be asked for past the cap
    assert_equal 'memory_limits', reason(run_core(t, grow_module(1, 2), max_memory_pages: 1))
  end

  def test_egress_policy_admits_in_policy_and_refuses_out_of_policy
    need_wasmtime
    policy = S::EgressPolicy.new(-> { 0 })
    ok_op = { 'verb' => 'fetch', 'resource' => 'r', 'params' => { 'url' => 'https://example.com/a' } }
    policy.admit(res('fetch', ok_op), ok_op, ->(_op) { { 'method' => 'GET', 'scheme' => 'https', 'host' => 'example.com', 'path' => '/a' } })
    fetch = lambda do |op|
      d = policy.claim({ 'method' => 'GET', 'url' => op['params']['url'] })
      raise 'egress denied' unless d['allow']

      "\x2a".b
    end
    log = S::ReceiptLog.new(now: -> { 0 })
    t = S::HandleTable.new('egress_default_deny', log, { 'fetch' => fetch }, -> { 0 })
    %w[https://example.com/a https://evil.example/a].each do |url|
      op = { 'verb' => 'fetch', 'resource' => 'r', 'params' => { 'url' => url } }
      t.mint(res('fetch', op), op)
    end
    call = ->(h) { run_core(t, S.build_tool({ 'calls' => [{ 'handle' => h, 'ptr' => 0, 'cap' => 8 }], 'returns' => 'last' })) }
    assert_equal({ 'ok' => true, 'value' => 1 }, call.call(1)) # one byte written
    assert_equal({ 'ok' => true, 'value' => S::USE_ERR['executor_error'] }, call.call(2))
    assert_equal %w[ok error], log.entries.map { |e| e['outcome'] }
  end

  # ---------------------------------------------------------------------------------------------------- component host: the pin
  def with_env(vals)
    saved = vals.keys.to_h { |k| [k, ENV.fetch(k, nil)] }
    vals.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    yield
  ensure
    saved.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
  end

  def test_pin_logic
    t, = table({})
    Dir.mktmpdir do |d|
      exe = File.join(d, 'host')
      File.binwrite(exe, "#!/bin/sh\nexit 0\n")
      File.chmod(0o700, exe)
      pin = sha(File.binread(exe))
      go = ->(**k) { W.run_component(t, '(component)', fuel: 10, **k)['reason'] }
      with_env('PCA_WASMTIME_HOST' => nil, 'PCA_WASMTIME_HOST_SHA256' => nil) do
        assert_equal 'host_missing', go.call
        assert_equal 'host_missing', go.call(host: File.join(d, 'absent'), expected_sha256: sha('x'))
        assert_equal 'host_unpinned', go.call(host: exe)
        assert_equal 'host_unpinned', go.call(host: exe, expected_sha256: 'abc')
        assert_equal 'host_hash_mismatch', go.call(host: exe, expected_sha256: '0' * 64)
        assert_equal 'host_exit', go.call(host: exe, expected_sha256: pin) # matches: proceeds to spawn (and the no-op host exits)
      end
      with_env('PCA_WASMTIME_HOST' => exe, 'PCA_WASMTIME_HOST_SHA256' => pin) { assert_equal 'host_exit', go.call } # env config works the same
    end
  end

  FAKE = <<~'RUBY'
    #!%<ruby>s
    require 'json'
    mode = File.read(ARGV[0]).strip
    ask = ->(m) { $stdout.puts(JSON.generate(m)); $stdout.flush; JSON.parse($stdin.gets) }
    case mode
    when 'ok'
      n = ask.call({ 'op' => 'count' })['n']
      v = ask.call({ 'op' => 'verb', 'h' => 1 })
      bad = ask.call({ 'op' => 'verb', 'h' => 99 })
      r = ask.call({ 'op' => 'invoke', 'h' => 1 })
      e = ask.call({ 'op' => 'invoke', 'h' => 2 })
      total = n * 1000 + v['ok'].length * 100 + r['ok'].sum + (e['err'] == -3 ? 0 : 7) + (bad['err'] == -1 ? 0 : 9)
      puts JSON.generate({ 'done' => total, 'fuel_used' => ARGV[1].to_i / 2 })
    when 'fail' then puts JSON.generate({ 'fail' => 'fuel_exhausted' })
    when 'garbage' then puts 'not json'
    when 'hang' then sleep 60
    when 'env' then puts JSON.generate({ 'done' => ENV.keys.count { |k| %%w[HOME PATH USER TMPDIR].include?(k) } })
    end
  RUBY

  def fake(dir)
    exe = File.join(dir, 'fakehost')
    File.write(exe, format(FAKE, ruby: RbConfig.ruby))
    File.chmod(0o700, exe)
    [exe, sha(File.binread(exe))]
  end

  def test_protocol_against_a_fake_host
    Dir.mktmpdir do |d|
      host, pin = fake(d)
      t, log = table({ 'fetch' => ->(_op) { [3, 4].pack('C*') }, 'send' => ->(_op) { 'x'.b * 9 } }, %w[fetch send])
      run_c = ->(mode, **k) { W.run_component(t, mode, fuel: 100, host: host, expected_sha256: pin, **k) }
      assert_equal({ 'ok' => true, 'value' => 2000 + 500 + 7, 'fuel_used' => 50 }, run_c.call('ok', max_result_bytes: 8))
      assert_equal %w[ok ok], log.entries.map { |e| e['outcome'] } # both uses spent; the oversized result is refused to the guest, not the table
      assert_equal({ 'ok' => false, 'reason' => 'fuel_exhausted' }, run_c.call('fail'))
      assert_equal({ 'ok' => false, 'reason' => 'host_protocol' }, run_c.call('garbage'))
      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      assert_equal({ 'ok' => false, 'reason' => 'timeout' }, run_c.call('hang', timeout_ms: 300))
      assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0, :<, 10
      assert_equal({ 'ok' => true, 'value' => 0 }, run_c.call('env')) # an empty environment: no inherited secrets
    end
  end

  def test_temp_dir_is_removed
    Dir.mktmpdir do |d|
      host, pin = fake(d)
      root = File.join(d, 'tmproot')
      Dir.mkdir(root)
      t, = table({})
      with_env('TMPDIR' => root) { W.run_component(t, 'fail', fuel: 5, host: host, expected_sha256: pin) }
      assert_empty Dir.children(root)
    end
  end

  # ------------------------------------------------------------------------------------------------ component host: the real binary
  def test_real_host_reference_component
    unless REAL_HOST && REAL_PIN
      flunk('CI must export PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256') if IN_CI
      skip('set PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256 to run the real wasmtime host')
    end
    go = ->(t, wat, fuel = 10_000_000) { W.run_component(t, wat, fuel: fuel, host: REAL_HOST, expected_sha256: REAL_PIN) }
    t, log = table({ 'fetch' => ->(_op) { [42].pack('C*') } })
    r = go.call(t, S.reference_component_wat)
    assert_equal [true, 42, ['ok']], [r['ok'], r['value'], log.entries.map { |e| e['outcome'] }]
    t, = table({ 'fetch' => ->(_op) { "\x01".b } })
    assert_equal({ 'ok' => false, 'reason' => 'fuel_exhausted' }, go.call(t, S.reference_component_wat({ 'spin' => true }), 100_000))
    r = go.call(t, S.reference_component_wat({ 'extra_import' => 'wasi:cli/environment@0.2.0' }))
    assert_equal false, r['ok']
    assert r['reason'].start_with?('ambient_import:')
    t, log = table({ 'fetch' => ->(_op) { raise 'egress denied' } })
    r = go.call(t, S.reference_component_wat)
    assert_equal [true, S::USE_ERR['executor_error'], ['error']], [r['ok'], r['value'], log.entries.map { |e| e['outcome'] }]
  end
end
