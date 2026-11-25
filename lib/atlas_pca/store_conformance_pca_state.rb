# frozen_string_literal: true

# The `pca-state` profile (port of pca-state.ts of @atlasauth/pca-store-conformance): run the replay store behind the REAL guard
# (AtlasPca.authorize, the full default-deny pipeline) with REAL signed PCActns, and check the replay-state invariant: one action id
# (grant, leaf holder, counter) goes from unconsumed to consumed at most once, however many copies arrive, on however many instances or
# processes, across crashes after the claim and retries after a timeout.
#
#   claim-burst / claim-concurrent / claim-durability   the store's claim contract (AtlasPca.run_state_store_conformance)
#   one-instance        N concurrent copies of one proof to one guard: exactly one admitted, every round
#   instances           the copies spread over K guards, each on its own handle, built with multi_instance: true
#   processes           the same race across K child processes (needs the adapter spec: a file or builtin:<name>)
#   crash-after-claim   admitted, then the instance dies before its handler: the same proof is denied afterwards, the next counter
#                       admitted; with a spec the instance is a child process that SIGKILLs itself right after the admission
#   retry-after-timeout the commit lands but its answer is lost (the guard fails closed) and the retry is denied; a retry on another
#                       instance while the first commit is in flight: exactly one admitted
#
# An adapter is an object with a String #name, #open (a handle responding to #claim, or one with #store and an optional #close),
# and optionally #durable? / #shared? (default true), #restart, #crash, #teardown. Load one with load_adapter: a Ruby file defining
# the constant PcaStateAdapter (an adapter, or a factory taking the options Hash), or builtin:<name>.
require 'json'
require 'rbconfig'
require 'tmpdir'
require_relative '../atlas_pca'
require_relative 'authorize'
require_relative 'agent'
require_relative 'arg_provenance'
require_relative 'store_conformance'
require_relative 'private_file'

module AtlasPca
  module StoreConformancePcaState
    AUDIENCE = 'pca-store-conformance'
    TESTS = %w[claim-burst claim-concurrent claim-durability one-instance instances processes crash-after-claim retry-after-timeout].freeze
    OPERATION = { 'verb' => 'read', 'resource' => 'doc:1', 'params' => {} }.freeze
    # the server-supplied risk inputs of a no-risk operation (r = 0 under any policy)
    RISK = { 'semanticDistance' => 0, 'reversibility' => 1, 'blastRadius' => 0, 'taint' => 0, 'confidence' => 1, 'age' => 0 }.freeze
    PROV_KEY = KeyPair.new(Digest::SHA256.digest('atlas-pca-conformance/pca-state/mediator'))
    PROV_PIN = { 'mediator' => 'pca-state-harness', 'kid' => 'k1', 'pk' => PROV_KEY.public }.freeze
    PROVENANCE = { 'mediators' => [PROV_PIN], 'bundle' => lambda { |_pcactn, op|
      AtlasPca.principal_direct_provenance(AtlasPca::ProvenanceRecorder.new(mediator: PROV_PIN['mediator'], kid: PROV_PIN['kid'], key: PROV_KEY), op)
    } }.freeze

    Handle = Struct.new(:store, :closer) do
      def close = closer&.call
    end

    # A named adapter over a callable that opens a handle (a store, or a Handle).
    class Adapter
      attr_reader :name

      def initialize(name, durable: true, shared: true, restart: nil, crash: nil, teardown: nil, &open)
        @name = name
        @durable = durable
        @shared = shared
        @restart = restart
        @crash = crash
        @teardown = teardown
        @open = open
      end

      def durable? = @durable
      def shared? = @shared
      def restart = @restart&.call
      def crash = @crash&.call
      def teardown = @teardown&.call

      def open
        h = @open.call
        h.respond_to?(:store) ? h : Handle.new(h, h.respond_to?(:close) ? -> { h.close } : nil)
      end
    end

    module_function

    # ---- fixture and guard -------------------------------------------------------------------------------------------------

    # A grant plus pre-signed PCActns (counters 1..n) from one agent, as JSON-able values.
    def fixture(n)
      principal = KeyPair.new(Digest::SHA256.digest('atlas-pca-conformance/pca-state/principal'))
      key = KeyPair.new(Digest::SHA256.digest('atlas-pca-conformance/pca-state/agent'))
      env = { 'predicates' => [{ 'verb' => 'read', 'resource' => 'doc:*' }], 'caveats' => [], 'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
      grant = AtlasPca.mint_grant(principal, key.public, env, 'store conformance')['grant']
      agent = Agent.new(key, grant, AUDIENCE)
      { 'grant' => grant, 'holder' => key.public, 'proofs' => Array.new(n) { agent.act('read', 'doc:1', {}).pcactn } }
    end

    def outcome(r)
      return 'admitted' if r.allow
      return 'replay' if r.checks.is_a?(Hash) && r.checks['replay'] == 'fail'

      'error'
    end

    # One guard over `store`: ->(counter) { 'admitted' | 'replay' | 'error' }.
    def guard(fx, store, multi_instance: false)
      grant = fx['grant']
      lambda do |counter|
        r = AtlasPca.authorize(fx['proofs'][counter - 1], operation: OPERATION, audience: AUDIENCE,
                                                          resolve_grant: ->(ref) { ref == grant['id'] ? grant : nil }, state_store: store,
                                                          is_revoked: ->(_p, _g) { false }, now: (Time.now.to_f * 1000).to_i, plan: 'single-step',
                                                          provenance: PROVENANCE, risk: RISK, multi_instance: multi_instance)
        outcome(r)
      end
    end

    def with_handles(adapter, n)
      hs = Array.new(n) { adapter.open }
      yield hs
    ensure
      hs&.each { |h| h.close rescue nil } # rubocop:disable Style/RescueModifier
    end

    def exactly_one(test, admitted, note = nil)
      { 'test' => test, 'status' => admitted.all? { |n| n == 1 } ? 'pass' : 'fail', 'admitted' => admitted, 'note' => note }
    end

    def skip(test, note) = { 'test' => test, 'status' => 'skip', 'note' => note }

    def race(guards, counter, copies)
      StoreConformance.race(copies) { |i| guards[i % guards.length].call(counter) }.count { |r| r == 'admitted' }
    end

    # ---- the tests ---------------------------------------------------------------------------------------------------------

    def one_instance(adapter, rounds, copies)
      fx = fixture(rounds)
      with_handles(adapter, 1) do |(h)|
        g = guard(fx, h.store)
        exactly_one('one-instance', (1..rounds).map { |r| race([g], r, copies) })
      end
    end

    def instances(adapter, rounds, copies, k)
      return skip('instances', 'the adapter declares shared: false (one instance only)') unless adapter.shared?

      fx = fixture(rounds)
      with_handles(adapter, k) do |hs|
        gs = begin
          hs.map { |h| guard(fx, h.store, multi_instance: true) }
        rescue StandardError => e
          return { 'test' => 'instances', 'status' => 'fail', 'note' => "refused in multi-instance mode: #{e.message}" }
        end
        exactly_one('instances', (1..rounds).map { |r| race(gs, r, copies) }, "#{k} instances")
      end
    end

    # A handle store whose claim commits but whose answer is lost (the first call), or that holds the commit at a gate.
    class Wrapped
      def initialize(inner, &around)
        @inner = inner
        @around = around
      end

      def claim(key, counter) = @around.call(-> { @inner.claim(key, counter) })
      def scope = @inner.respond_to?(:scope) ? @inner.scope : :shared

      def method_missing(name, *args, &blk) = @inner.respond_to?(name) ? @inner.public_send(name, *args, &blk) : super
      def respond_to_missing?(name, priv = false) = @inner.respond_to?(name, priv) || super
    end

    def retry_after_timeout(adapter)
      fx = fixture(4)
      shared = adapter.shared?
      with_handles(adapter, shared ? 2 : 1) do |hs|
        other = hs.last
        lose = true
        lossy = Wrapped.new(hs.first.store) do |commit|
          r = commit.call
          if lose
            lose = false
            raise 'timeout (answer lost after commit)'
          end
          r
        end
        first = guard(fx, lossy).call(1)
        retry_ = guard(fx, other.store).call(1)
        nxt = guard(fx, other.store).call(2)
        entered = Queue.new
        gate = Queue.new
        slow = Wrapped.new(hs.first.store) do |commit|
          entered << true
          gate.pop
          commit.call
        end
        inflight = Thread.new { guard(fx, slow).call(3) }
        entered.pop
        retried = Thread.new { guard(fx, other.store).call(3) }
        sleep 0.05
        gate << true
        pair = [inflight.value, retried.value].count('admitted')
        ok = first == 'error' && retry_ == 'replay' && nxt == 'admitted' && pair == 1
        { 'test' => 'retry-after-timeout', 'status' => ok ? 'pass' : 'fail', 'admitted' => [first == 'admitted' || retry_ == 'admitted' ? 1 : 0, pair],
          'note' => "lost answer: first=#{first}, retry=#{retry_}, next counter=#{nxt}; in-flight retry: #{pair} admitted of 2" }
      end
    end

    def crash_after_claim(adapter, spec, options)
      return skip('crash-after-claim', 'the adapter declares durable: false (state dies with the process)') unless adapter.durable?

      fx = fixture(4)
      h1 = adapter.open
      first = guard(fx, h1.store).call(1)
      adapter.crash
      adapter.restart
      after = nil
      with_handles(adapter, 1) do |(h)|
        g = guard(fx, h.store)
        after = [g.call(1), g.call(2)]
      end
      h1.close rescue nil # rubocop:disable Style/RescueModifier
      ok = first == 'admitted' && after[0] == 'replay' && after[1] == 'admitted'
      notes = ["in process: admitted=#{first}, same proof after #{adapter.respond_to?(:crash) ? 'crash + ' : ''}restart=#{after[0]}, next counter=#{after[1]}"]
      if spec
        AtlasPca::PrivateFile.mktmpdir('pcasc-pstate-crash-') do |dir|
          file = File.join(dir, 'fixture.json')
          AtlasPca::PrivateFile.write(file, JSON.generate(fx), binmode: false)
          base = { 'module' => spec, 'options' => options, 'fixture' => file, 'copies' => 1, 'instances' => 1 }
          killed = run_worker(base.merge('mode' => 'admit-then-die', 'out' => File.join(dir, 'a.jsonl'), 'counter' => 3))
          adapter.restart
          retried = run_worker(base.merge('mode' => 'race', 'out' => File.join(dir, 'b.jsonl'), 'counter' => 3))
          fresh = run_worker(base.merge('mode' => 'race', 'out' => File.join(dir, 'c.jsonl'), 'counter' => 4))
          ok &&= killed[:killed] && killed[:admitted] == 1 && retried[:admitted].zero? && retried[:replays] == 1 && fresh[:admitted] == 1
          notes << "child process: killed after admission=#{killed[:killed] && killed[:admitted] == 1}, retry in a new process admitted #{retried[:admitted]}, next counter admitted #{fresh[:admitted]}"
        end
      else
        notes << 'process half skipped (needs the adapter spec)'
      end
      { 'test' => 'crash-after-claim', 'status' => ok ? 'pass' : 'fail', 'note' => notes.join('; ') }
    end

    # ---- child processes ---------------------------------------------------------------------------------------------------

    def run_worker(cfg)
      lib = File.expand_path('..', __dir__)
      pid = Process.spawn(RbConfig.ruby, '-I', lib, '-r', 'atlas_pca/store_conformance_pca_state', '-e', 'AtlasPca::StoreConformancePcaState.worker_main(ARGV)',
                          JSON.generate(cfg), in: File::NULL, out: File::NULL)
      _, st = Process.wait2(pid)
      read_lines(cfg['out']).then { |lines| { lines: lines, killed: st.signaled? && st.termsig == 9, signaled: st.signaled?, admitted: lines.sum { |l| l['admitted'] }, replays: lines.sum { |l| l['replays'] } } }
    end

    def read_lines(file) = File.exist?(file) ? File.readlines(file).map { |l| JSON.parse(l) } : []

    def processes(adapter, spec, options, rounds, copies, n)
      return skip('processes', 'the adapter declares shared: false (one instance only)') unless adapter.shared?
      return skip('processes', 'needs the adapter spec (the guards run in child processes)') if spec.nil?

      fx = fixture(rounds)
      AtlasPca::PrivateFile.mktmpdir('pcasc-pstate-') do |dir|
        file = File.join(dir, 'fixture.json')
        AtlasPca::PrivateFile.write(file, JSON.generate(fx), binmode: false)
        origin = ((Time.now.to_f * 1000).to_i) + 2500 # time for every process to start and open its handles
        outs = Array.new(n) do |p|
          Thread.new do
            run_worker('module' => spec, 'options' => options, 'mode' => 'race', 'fixture' => file, 'out' => File.join(dir, "p#{p}.jsonl"),
                       'rounds' => rounds, 'origin' => origin, 'round_ms' => 150, 'copies' => copies, 'instances' => 2)
          end
        end.map(&:value)
        admitted = (1..rounds).map { |c| outs.sum { |w| w[:lines].select { |l| l['counter'] == c }.sum { |l| l['admitted'] } } }
        errors = outs.sum { |w| w[:lines].sum { |l| l['errors'] } }
        crashed = outs.count { |w| w[:signaled] || w[:lines].length != rounds }
        r = exactly_one('processes', admitted, "#{n} processes x 2 instances x #{copies} copies per round; #{errors} fail-closed errors#{crashed.positive? ? "; #{crashed} worker(s) did not finish" : ''}")
        crashed.positive? ? r.merge('status' => 'fail') : r
      end
    end

    # Entry of one child process: ruby -r atlas_pca/store_conformance_pca_state -e 'AtlasPca::StoreConformancePcaState.worker_main(ARGV)' '<json>'
    def worker_main(argv)
      cfg = JSON.parse(argv[0])
      adapter = load_adapter(cfg['module'], cfg['options'])
      fx = AtlasPca.parse_json(File.read(cfg['fixture']))
      hs = Array.new(cfg['instances']) { adapter.open }
      gs = hs.map { |h| guard(fx, h.store, multi_instance: cfg['instances'] > 1 || cfg['mode'] == 'race') }
      record = lambda do |counter, rs|
        AtlasPca::PrivateFile.open(cfg['out'], File::WRONLY | File::APPEND | File::CREAT) do |f|
          f.puts JSON.generate('counter' => counter, 'admitted' => rs.count('admitted'), 'replays' => rs.count('replay'), 'errors' => rs.count('error'))
        end
      end
      if cfg['mode'] == 'admit-then-die'
        record.call(cfg['counter'], [gs[0].call(cfg['counter'])])
        Process.kill('KILL', Process.pid) # the instance dies after the claim committed and before any handler ran
        return
      end
      (cfg['rounds'] || 1).times do |r|
        counter = cfg['counter'] || (r + 1)
        at = (cfg['origin'] || 0) + (r * (cfg['round_ms'] || 0))
        sleep(0.005) while (Time.now.to_f * 1000) < at
        record.call(counter, StoreConformance.race(cfg['copies']) { |i| gs[i % gs.length].call(counter) })
      end
      hs.each { |h| h.close rescue nil } # rubocop:disable Style/RescueModifier
      adapter.teardown
    end

    # ---- adapters ----------------------------------------------------------------------------------------------------------

    # BAD: a claim that reads, waits, then writes: two instances both read "fresh" and both admit.
    class ReadThenWriteStore
      def initialize(shared)
        @m = shared
      end

      def scope = :shared

      def claim(key, counter)
        last = @m[key]
        sleep(0.001)
        return ClaimResult.new(false, last) if !last.nil? && counter <= last

        @m[key] = counter
        ClaimResult.new(true)
      end
    end

    def builtin(name, options)
      case name
      when 'in-memory'
        s = MemoryStateStore.new
        Adapter.new('in-memory (MemoryStateStore)', durable: false, shared: false) { s }
      when 'durable-file'
        dir = options['dir'] || AtlasPca::PrivateFile.mktmpdir('pcasc-pstate-durable-')
        Adapter.new("durable SQLite file store (#{dir})") { SqliteStateStore.new(File.join(dir, 'state.db')) }
      when 'bad-read-then-write-claim'
        shared = {}
        Adapter.new('BAD claim as read, wait, write', durable: false) { ReadThenWriteStore.new(shared) }
      when 'bad-volatile'
        store = MemoryStateStore.new
        shared_scope = Class.new(MemoryStateStore) { def scope = :shared }
        Adapter.new('BAD volatile atomic store (claims lost on restart)', restart: -> { store = shared_scope.new }) { store }
      when 'bad-unshared'
        shared_scope = Class.new(MemoryStateStore) { def scope = :shared }
        Adapter.new('BAD per-handle state passed off as shared', durable: false) { shared_scope.new }
      else
        raise ArgumentError, "unknown built-in pca-state adapter '#{name}' (known: in-memory, durable-file, bad-read-then-write-claim, bad-volatile, bad-unshared)"
      end
    end

    def load_adapter(spec, options = nil)
      options ||= {}
      return builtin(spec['builtin:'.length..], options) if spec.start_with?('builtin:')

      load File.expand_path(spec)
      exported = Object.const_defined?(:PcaStateAdapter) ? Object.const_get(:PcaStateAdapter) : nil
      a = exported.respond_to?(:open) ? exported : (exported.respond_to?(:call) ? exported.call(options) : nil)
      raise TypeError, "#{spec}: does not export a pca-state adapter (an object with a String #name and #open)" unless a.respond_to?(:open) && a.respond_to?(:name)

      a
    end

    # ---- the run -----------------------------------------------------------------------------------------------------------

    # Run the profile. spec / options: how a child process loads the adapter again (nil: the process tests are skipped).
    # Returns {'adapter', 'status' ('pass' | 'fail'), 'tests' => [...]}.
    def run(adapter, spec: nil, options: nil, tests: TESTS, rounds: 10, copies: 16, instances: 4, processes: 3)
      options ||= {}
      claim = nil
      claim_rep = lambda do
        claim ||= AtlasPca.run_state_store_conformance(-> { adapter.open.store }, durable: adapter.durable?, shared: adapter.shared?,
                                                                                  crash: -> { adapter.crash }, restart: -> { adapter.restart }, name: adapter.name)
      end
      out = tests.map do |t|
        case t
        when 'claim-burst', 'claim-concurrent', 'claim-durability'
          r = claim_rep.call.results.find { |x| x.test == t }
          { 'test' => t, 'status' => r.status, 'note' => r.note }
        when 'one-instance' then one_instance(adapter, rounds, copies)
        when 'instances' then instances(adapter, rounds, copies, instances)
        when 'processes' then processes(adapter, spec, options, rounds, copies, processes)
        when 'crash-after-claim' then crash_after_claim(adapter, spec, options)
        when 'retry-after-timeout' then retry_after_timeout(adapter)
        else raise ArgumentError, "unknown test #{t}"
        end
      end
      { 'adapter' => adapter.name, 'status' => out.any? { |x| x['status'] == 'fail' } ? 'fail' : 'pass', 'tests' => out }
    ensure
      adapter.teardown
    end

    def format_report(r)
      lines = ["pca-store-conformance (pca-state): #{r['adapter']} -> #{r['status'].upcase}"]
      r['tests'].each do |t|
        adm = t['admitted'] ? "admitted per round [#{t['admitted'].join(',')}]" : ''
        lines << "  [#{t['status'].upcase}] #{t['test'].ljust(20)} #{[adm, t['note'].to_s].reject(&:empty?).join('; ')}"
      end
      lines.join("\n")
    end
  end
end
