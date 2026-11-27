# frozen_string_literal: true

# The command line of the store conformance kit (port of the TypeScript reference, @atlasauth/pca-store-conformance, cli.ts):
#   ruby -I lib -r atlas_pca/store_conformance_cli -e 'exit AtlasPca::StoreConformanceCli.main(ARGV)' -- --adapter ./my_adapter.rb [options]
# Exit codes: 0 pass, 1 a contract violation was found, 3 unresolved (no violation, but not every key could be decided), 2 usage /
# adapter error.
#
# --profile pca-state runs the store behind the real guard (AtlasPca::StoreConformancePcaState; a Ruby adapter file defines PcaStateAdapter).
require 'json'
require_relative 'store_conformance_load'
require_relative 'store_conformance_pca_state'

module AtlasPca
  module StoreConformanceCli
    M = StoreConformanceModel
    R = StoreConformanceRunner

    PCA_STATE_TESTS = %w[claim-burst claim-concurrent claim-durability one-instance instances processes crash-after-claim retry-after-timeout].freeze

    USAGE = <<~TEXT.chomp
      pca-store-conformance --adapter <module|builtin:name> [options]

        --adapter <path>        module exporting a store adapter (default export, 'adapter' or 'createAdapter(options)')
                                or builtin:in-memory | builtin:durable-file | builtin:bad-* (reference adapters)
        --option k=v            passed to the adapter factory (repeatable)
        --tests a,b             subset of: #{R::ALL_TESTS.join(', ')} (default all)
        --clients N             concurrent clients (default 16)
        --duration MS           concurrent run length (default 2000)
        --rounds N              same-key burst rounds (default 20)
        --revisit-keys N        retention run size (default 500)
        --processes N           crash test: client processes alive at once (default 3)
        --kill-every MS         crash test: SIGKILL one client process this often (default 400)
        --budget N              search states per key before it is UNRESOLVED (default 200000)
        --values N              advance tests: counter values are drawn from [0, N) (default 20)
        --seed N                workload PRNG seed, to reproduce a run (default random)
        --json                  print the report as JSON
        --profile pca-state     test the store behind requirePCA instead (a Ruby file defining PcaStateAdapter, an adapter or a factory
                                taking the options Hash, or builtin:in-memory | builtin:durable-file | builtin:bad-*); --tests then takes a subset of:
                                #{PCA_STATE_TESTS.join(', ')}
                                (--rounds = race rounds, default 10; --clients = copies per round, default 16; --processes)

      Exit: 0 pass, 1 violation found, 3 unresolved, 2 usage or adapter error.
    TEXT

    module_function

    # A non-negative finite number as the reference reads it (an integral value is an Integer).
    def num(flag, v)
      n = v.nil? ? Float::NAN : M.js_number_of_string(v)
      raise ArgumentError, "#{flag} needs a non-negative number" if v.nil? || (n.is_a?(Float) && (n.nan? || n.infinite?)) || n.negative?

      n.is_a?(Float) && n == n.floor ? n.to_i : n
    end

    # The reference's argument parsing. The result keeps the reference's member names ('killEveryMs', 'durationMs', ...).
    def parse_cli(argv)
      a = { 'options' => {}, 'json' => false, 'help' => false, 'conf' => {} }
      raw_tests = nil
      i = 0
      nxt = lambda do
        i += 1
        i < argv.length ? argv[i] : nil
      end
      while i < argv.length
        f = argv[i]
        case f
        when '--adapter'
          v = nxt.call
          a['adapter'] = v unless v.nil?
        when '--option'
          kv = nxt.call || ''
          eq = kv.index('=') || -1
          raise ArgumentError, '--option needs k=v' if eq < 1

          a['options'][kv[0, eq]] = kv[(eq + 1)..]
        when '--tests' then raw_tests = (nxt.call || '').split(',').reject(&:empty?)
        when '--profile'
          p = nxt.call
          raise ArgumentError, "--profile: unknown profile #{p.nil? ? 'undefined' : p} (known: pca-state)" unless p == 'pca-state'

          a['profile'] = p
        when '--clients' then a['conf']['clients'] = num(f, nxt.call)
        when '--duration' then a['conf']['durationMs'] = num(f, nxt.call)
        when '--rounds' then a['conf']['rounds'] = num(f, nxt.call)
        when '--revisit-keys' then a['conf']['revisitKeys'] = num(f, nxt.call)
        when '--processes' then a['processes'] = num(f, nxt.call)
        when '--kill-every' then a['killEveryMs'] = num(f, nxt.call)
        when '--budget' then a['conf']['budget'] = num(f, nxt.call)
        when '--values'
          n = num(f, nxt.call)
          raise ArgumentError, '--values needs a positive integer' if !n.is_a?(Integer) || n < 1

          a['conf']['values'] = n
        when '--seed'
          n = num(f, nxt.call)
          raise ArgumentError, '--seed needs a non-negative integer' unless n.is_a?(Integer)

          a['conf']['seed'] = n
        when '--json' then a['json'] = true
        when '-h', '--help' then a['help'] = true
        else raise ArgumentError, "unknown argument #{f}"
        end
        i += 1
      end
      unless raw_tests.nil?
        known = a['profile'] == 'pca-state' ? PCA_STATE_TESTS : R::ALL_TESTS
        bad = raw_tests.reject { |x| known.include?(x) }
        raise ArgumentError, "--tests: unknown test(s) #{bad.empty? ? '(none given)' : bad.join(', ')}" if !bad.empty? || raw_tests.empty?

        a[a['profile'] == 'pca-state' ? 'pcaStateTests' : 'conf'] = a['profile'] == 'pca-state' ? raw_tests : a['conf'].merge('tests' => raw_tests)
      end
      a
    end

    SNAKE = { 'durationMs' => 'duration_ms', 'revisitKeys' => 'revisit_keys' }.freeze

    # --profile pca-state: the store behind the real guard (see StoreConformancePcaState); --rounds = race rounds, --clients = copies per round.
    def main_pca_state(args, out, err)
      ps = StoreConformancePcaState
      begin
        adapter = ps.load_adapter(args['adapter'], args['options'])
      rescue StandardError, ScriptError => e
        err.call("cannot load adapter: #{e.message}")
        return 2
      end
      conf = args['conf']
      kw = { spec: args['adapter'], options: args['options'], tests: args['pcaStateTests'] || ps::TESTS }
      kw[:rounds] = conf['rounds'] if conf['rounds'].is_a?(Integer)
      kw[:copies] = conf['clients'] if conf['clients'].is_a?(Integer)
      kw[:processes] = args['processes'] if args['processes'].is_a?(Integer)
      r = ps.run(adapter, **kw)
      out.call(args['json'] ? JSON.generate(r) : ps.format_report(r))
      r['status'] == 'pass' ? 0 : 1
    rescue StandardError => e
      err.call("conformance run failed: #{e.message}")
      2
    end

    # Runs the command line; returns the exit code. out / err are injectable callables.
    def main(argv, out = ->(s) { puts s }, err = ->(s) { warn s })
      begin
        args = parse_cli(argv.to_a.dup)
      rescue ArgumentError => e
        err.call("#{e.message}\n\n#{USAGE}")
        return 2
      end
      if args['help']
        out.call(USAGE)
        return 0
      end
      unless Js.truthy?(args['adapter'])
        err.call("--adapter is required\n\n#{USAGE}")
        return 2
      end
      return main_pca_state(args, out, err) if args['profile'] == 'pca-state'

      begin
        adapter = StoreConformanceLoad.load_adapter(args['adapter'], args['options'])
      rescue StandardError, ScriptError => e
        err.call("cannot load adapter: #{e.message}")
        return 2
      end
      begin
        crash = { 'module' => args['adapter'], 'options' => args['options'] }
        crash['processes'] = args['processes'] unless args['processes'].nil?
        crash['kill_every_ms'] = args['killEveryMs'] unless args['killEveryMs'].nil?
        conf = args['conf'].to_h { |k, v| [SNAKE.fetch(k, k), v] }
        r = R.run_conformance(adapter, conf.merge('crash' => crash))
        out.call(args['json'] ? M.report_json(r) : M.format_report(r))
        r['status'] == 'pass' ? 0 : (r['status'] == 'fail' ? 1 : 3)
      rescue StandardError => e
        err.call("conformance run failed: #{e.message}")
        2
      ensure
        adapter.teardown&.call
      end
    end
  end
end
