# frozen_string_literal: true

# A reusable conformance helper for the stores behind `authorize`: run the replay / counter and operation-record contracts
# against YOUR store. Pass a factory that opens a handle on the backend (one handle = one verifier instance's connection to
# the shared backend) and read the report.
#
#   report = AtlasPca.run_state_store_conformance(-> { MyStateStore.new(dsn) })   # claim(key, counter) -> ClaimResult
#   raise report.render unless report.ok?
#
# The state-store profile runs the store's #claim(key, counter) as the replay invariant "a counter goes from unconsumed to
# consumed at most once, however many copies arrive":
#
#   claim-sequence     strict increase on one key; replays and older counters refused (with last_counter); keys independent
#   claim-burst        N threads race one (key, counter) on ONE handle, every round, then the next counter: exactly one wins
#   claim-concurrent   the same race spread over K handles (a store only an in-process lock can serialise fails here)
#   claim-durability   a claim survives closing every handle and `restart`
#   crash-after-claim  the instance dies after the admission (`crash` when given): the same counter stays consumed and the
#                      next one is admitted
#
# The operation-store profile checks #create (atomic create-if-absent), #transition (a compare-and-set on the state), #get
# (a copy, never an alias) and durability. A declared durable: false / shared: false (a process-local store) skips the tests
# that need them; everything else is a failure, never a skip. Tests run with real threads on this machine's scheduler: a racy
# store is caught with overwhelming probability per round, so run it more than once for a store you wrote.
require 'securerandom'

module AtlasPca
  StoreTestResult = Struct.new(:test, :status, :note, keyword_init: true) # status: 'pass' | 'fail' | 'skip'

  class ConformanceReport
    attr_reader :name, :results

    def initialize(name)
      @name = name
      @results = []
    end

    # True when nothing failed and at least one test passed.
    def ok?
      @results.none? { |r| r.status == 'fail' } && @results.any? { |r| r.status == 'pass' }
    end

    def failures = @results.select { |r| r.status == 'fail' }

    def render
      @results.map { |r| format('%-4s %s%s', r.status, r.test, r.note.to_s.empty? ? '' : ": #{r.note}") }.join("\n")
    end
  end

  module StoreConformance
    class Skip < StandardError; end
    class Failure < StandardError; end

    module_function

    def check(cond, msg)
      raise Failure, msg unless cond
    end

    # Run fn(i) in n threads released together; returns the results in order (an exception is returned as a value).
    def race(n, &fn)
      gate = Queue.new
      out = Array.new(n)
      threads = Array.new(n) do |i|
        Thread.new do
          gate.pop
          out[i] = begin
            fn.call(i)
          rescue StandardError => e # a store that raises under load is reported, not hidden
            e
          end
        end
      end
      n.times { gate << true }
      threads.each(&:join)
      out
    end

    def check_no_errors(rs)
      errs = rs.grep(StandardError)
      check(errs.empty?, "#{errs.length} of #{rs.length} concurrent calls raised: #{errs.first.inspect}")
    end

    def close(handle)
      handle.close if handle.respond_to?(:close)
    end

    def run_test(report, name)
      note = yield
      report.results << StoreTestResult.new(test: name, status: 'pass', note: note.is_a?(String) ? note : '')
    rescue Skip => e
      report.results << StoreTestResult.new(test: name, status: 'skip', note: e.message)
    rescue Failure => e
      report.results << StoreTestResult.new(test: name, status: 'fail', note: e.message)
    rescue StandardError => e
      report.results << StoreTestResult.new(test: name, status: 'fail', note: "#{e.class}: #{e.message}")
    end

    def claimed?(r)
      r == true || (r.respond_to?(:ok) && r.ok == true) || (r.is_a?(Array) && r[0] == true)
    end

    def last_of(r)
      r.respond_to?(:last_counter) ? r.last_counter : (r.is_a?(Array) ? r[1] : nil)
    end

    def record(id, state = 'pending')
      { 'id' => id, 'state' => state, 'verb' => 'v', 'resource' => '/r', 'params_digest' => 'd', 'reversibility' => 'reversible', 'startedAt' => 1 }
    end
  end

  module_function

  # Run the replay-store contract (see the file header). `open_store` is a callable returning a handle with #claim(key,
  # counter); durable: false / shared: false declare a process-local store (its durability and cross-handle tests are
  # skipped). `crash` kills the backend / instance abruptly and `restart` brings it back (both optional); `teardown` runs last.
  def run_state_store_conformance(open_store, durable: true, shared: true, crash: nil, restart: nil, teardown: nil, threads: 16,
                                  rounds: 5, handles: 4, name: 'state store')
    sc = StoreConformance
    report = ConformanceReport.new(name)
    run = SecureRandom.hex(6)
    opened = []
    handle = lambda do
      h = open_store.call
      opened << h
      sc.check(h.respond_to?(:claim), 'the store has no claim(key, counter)')
      h
    end

    begin
      sc.run_test(report, 'claim-sequence') do
        s = handle.call
        k = "seq:#{run}"
        sc.check(sc.claimed?(s.claim(k, 1)), 'first claim of counter 1 refused')
        r = s.claim(k, 1)
        sc.check(!sc.claimed?(r), 'counter 1 claimed twice')
        sc.check(sc.last_of(r) == 1, "a refused claim must report last_counter=1, got #{r.inspect}")
        sc.check(sc.claimed?(s.claim(k, 5)), 'a larger counter (a gap) must be admitted')
        sc.check(!sc.claimed?(s.claim(k, 3)), 'an older counter was admitted after 5')
        sc.check(!sc.claimed?(s.claim(k, 5)), 'counter 5 claimed twice')
        sc.check(sc.claimed?(s.claim("seq-other:#{run}", 1)), 'another key must be independent')
        nil
      end
      sc.run_test(report, 'claim-burst') do
        s = handle.call
        k = "burst:#{run}"
        (1..rounds).each do |c|
          rs = sc.race(threads) { |_i| s.claim(k, c) }
          sc.check_no_errors(rs)
          wins = rs.count { |r| sc.claimed?(r) }
          sc.check(wins == 1, "round #{c}: #{wins} of #{threads} concurrent claims of counter #{c} were admitted (want exactly 1)")
        end
        "#{rounds} rounds x #{threads} threads"
      end
      sc.run_test(report, 'claim-concurrent') do
        raise StoreConformance::Skip, 'the adapter declares shared: false (a process-local store)' unless shared

        hs = Array.new(handles) { handle.call }
        k = "conc:#{run}"
        (1..rounds).each do |c|
          rs = sc.race(threads) { |i| hs[i % handles].claim(k, c) }
          sc.check_no_errors(rs)
          wins = rs.count { |r| sc.claimed?(r) }
          sc.check(wins == 1, "round #{c}: #{wins} of #{threads} claims over #{handles} handles were admitted (want exactly 1)")
        end
        "#{rounds} rounds x #{threads} threads over #{handles} handles"
      end
      sc.run_test(report, 'claim-durability') do
        raise StoreConformance::Skip, 'the adapter declares durable: false (state dies with the process)' unless durable

        k = "dur:#{run}"
        sc.check(sc.claimed?(handle.call.claim(k, 7)), 'claim refused')
        opened.each { |h| sc.close(h) }
        restart&.call
        sc.check(!sc.claimed?(handle.call.claim(k, 7)), 'counter 7 was admitted again after the handles were closed (the claim was not durable)')
        sc.check(sc.claimed?(handle.call.claim(k, 8)), 'the next counter must be admitted after a restart')
        nil
      end
      sc.run_test(report, 'crash-after-claim') do
        raise StoreConformance::Skip, 'the adapter declares durable: false (state dies with the process)' unless durable

        k = "crash:#{run}"
        sc.check(sc.claimed?(handle.call.claim(k, 1)), 'claim refused')
        # the instance dies right after the admission, before its handler ran: no close, no cleanup
        crash&.call
        restart&.call
        again = handle.call
        sc.check(!sc.claimed?(again.claim(k, 1)), 'the proof admitted before the crash was admitted again')
        sc.check(sc.claimed?(again.claim(k, 2)), 'the next counter must be admitted after the crash')
        nil
      end
    ensure
      opened.each do |h|
        sc.close(h)
      rescue StandardError
        nil
      end
      teardown&.call
    end
    report
  end

  # Run the operation-store contract: #create(record) -> nil | existing, #get(id), #transition(id, from, next) -> bool (see
  # AtlasPca::OperationStore).
  def run_operation_store_conformance(open_store, durable: true, shared: true, restart: nil, teardown: nil, threads: 16, rounds: 5,
                                      handles: 4, name: 'operation store')
    sc = StoreConformance
    report = ConformanceReport.new(name)
    run = SecureRandom.hex(6)
    opened = []
    handle = lambda do
      h = open_store.call
      opened << h
      %i[create get transition].each { |m| sc.check(h.respond_to?(m), "the store has no #{m}()") }
      h
    end

    begin
      sc.run_test(report, 'semantics') do
        s = handle.call
        i = "op-sem:#{run}"
        sc.check(s.get(i).nil?, 'get of an unknown id must be nil')
        sc.check(s.create(sc.record(i)).nil?, 'create of a new id must return nil')
        again = s.create(sc.record(i).merge('verb' => 'other'))
        sc.check(again.is_a?(Hash) && again['verb'] == 'v', 'create of an existing id must return the existing record unchanged')
        sc.check(s.transition("nope:#{run}", 'pending', sc.record('nope')) == false, 'transition of an unknown id must be false')
        sc.check(s.transition(i, 'executing', sc.record(i, 'executing')) == false, 'transition from the wrong state must be false')
        sc.check(s.get(i)['state'] == 'pending', 'a refused transition changed the record')
        sc.check(s.transition(i, 'pending', sc.record(i, 'executing').merge('executingAt' => 2)) == true, 'the transition from the current state must succeed')
        sc.check(s.get(i)['state'] == 'executing' && s.get(i)['executingAt'] == 2, 'the transition did not store the new record')
        sc.check(s.transition(i, 'pending', sc.record(i, 'aborted')) == false, 'the old state must no longer match')
        nil
      end
      sc.run_test(report, 'copies') do
        s = handle.call
        i = "op-copy:#{run}"
        s.create(sc.record(i))
        got = s.get(i)
        got['state'] = 'committed'
        sc.check(s.get(i)['state'] == 'pending', 'get must return a copy, not the stored record')
        mine = sc.record("#{i}-b")
        s.create(mine)
        mine['state'] = 'failed'
        sc.check(s.get("#{i}-b")['state'] == 'pending', 'create must store a copy of the record it was given')
        nil
      end
      sc.run_test(report, 'create-race') do
        s = handle.call
        rounds.times do |r|
          i = "op-create:#{run}:#{r}"
          rs = sc.race(threads) { |_n| s.create(sc.record(i)) }
          sc.check_no_errors(rs)
          wins = rs.count(&:nil?)
          sc.check(wins == 1, "round #{r}: #{wins} of #{threads} concurrent creates reported 'created' (want exactly 1)")
        end
        "#{rounds} rounds x #{threads} threads"
      end
      sc.run_test(report, 'transition-race') do
        s = handle.call
        rounds.times do |r|
          i = "op-cas:#{run}:#{r}"
          s.create(sc.record(i))
          rs = sc.race(threads) { |n| s.transition(i, 'pending', sc.record(i, 'executing').merge('executingAt' => n)) }
          sc.check_no_errors(rs)
          wins = rs.count(true)
          sc.check(wins == 1, "round #{r}: #{wins} of #{threads} concurrent pending->executing transitions succeeded (want exactly 1)")
        end
        "#{rounds} rounds x #{threads} threads"
      end
      sc.run_test(report, 'cross-handle') do
        raise StoreConformance::Skip, 'the adapter declares shared: false (a process-local store)' unless shared

        hs = Array.new(handles) { handle.call }
        i = "op-shared:#{run}"
        rs = sc.race(threads) { |n| hs[n % handles].create(sc.record(i)) }
        sc.check_no_errors(rs)
        sc.check(rs.count(&:nil?) == 1, "creates over #{handles} handles: not exactly one 'created'")
        rs = sc.race(threads) { |n| hs[n % handles].transition(i, 'pending', sc.record(i, 'executing').merge('executingAt' => n)) }
        sc.check_no_errors(rs)
        sc.check(rs.count(true) == 1, "transitions over #{handles} handles: not exactly one success")
        "over #{handles} handles"
      end
      sc.run_test(report, 'durability') do
        raise StoreConformance::Skip, 'the adapter declares durable: false (state dies with the process)' unless durable

        i = "op-dur:#{run}"
        h = handle.call
        h.create(sc.record(i))
        h.transition(i, 'pending', sc.record(i, 'executing').merge('executingAt' => 3))
        opened.each { |x| sc.close(x) }
        restart&.call
        got = handle.call.get(i)
        sc.check(!got.nil? && got['state'] == 'executing' && got['executingAt'] == 3, 'the record did not survive closing every handle')
        nil
      end
    ensure
      opened.each do |h|
        sc.close(h)
      rescue StandardError
        nil
      end
      teardown&.call
    end
    report
  end
end
