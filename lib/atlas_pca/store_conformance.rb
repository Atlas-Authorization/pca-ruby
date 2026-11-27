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
      sc.run_test(report, 'retry-after-timeout') do
        s = handle.call
        other = shared ? handle.call : s
        k = "retry:#{run}"
        # 1. the commit lands, its answer is lost: the retry (another instance when shared) is a replay
        s.claim(k, 1)
        sc.check(!sc.claimed?(other.claim(k, 1)), 'a claim whose answer was lost was admitted again on retry')
        sc.check(sc.claimed?(other.claim(k, 2)), 'the next counter must be admitted after a lost answer')
        # 2. the first commit is still in flight when the caller retries elsewhere: exactly one of the two is admitted
        gate = Queue.new
        inflight = Thread.new do
          gate.pop
          s.claim(k, 3)
        end
        retried = other.claim(k, 3)
        gate << true
        wins = [inflight.value, retried].count { |r| sc.claimed?(r) }
        sc.check(wins == 1, "#{wins} of 2 admitted for a retry while the first commit was in flight (want exactly 1)")
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

  # ---- registry kits: the lease / break-glass / blueprint registries over YOUR atomic kv ------------------------------------
  # `open_kv` returns a handle with #get(key) and the atomic #update(key) { |prev| next } (one handle = one verifier instance's
  # connection to the shared backend). The kits sign their own records with a fresh key. They check what the registries rely on:
  # one atomic update per decision (a racing accept / use / renewal has exactly one winner, across handles), copies, and (durable)
  # that a revocation, a use budget, a freeze or a disabled epoch survives closing every handle and `restart`.
  module StoreConformance
    module Kits
      module_function

      def signer = OpenSSL::PKey.new_raw_private_key('ED25519', SecureRandom.random_bytes(32))
      def pub(key) = AtlasPca.b64e(key.raw_public_key)

      def sign(key, domain, keys, rec)
        body = keys.select { |k| rec.key?(k) }.to_h { |k| [k, rec[k]] }
        rec.merge('sig' => AtlasPca.b64e(key.sign(nil, domain.b + AtlasPca.canon_bytes(body))))
      end

      def lease(key, over = {})
        sign(key, AtlasPca::LEASE_DOMAIN, AtlasPca::LEASE_BODY_KEYS,
             { 'v' => 1, 'lease_id' => 'L', 'path' => 'conf/x', 'grant_ref' => 'g', 'holder' => 'agent', 'requester' => 'alice', 'approvers' => ['bob'],
               'justification_digest' => 'j1', 'seq' => 1, 'issued_at' => 1000, 'renewed_at' => 1000, 'expires_at' => 2000, 'max_ttl' => 5000,
               'authority' => pub(key) }.merge(over))
      end

      def lease_revocation(key, over = {})
        sign(key, AtlasPca::LEASE_REVOKE_DOMAIN, AtlasPca::LEASE_REVOKE_KEYS,
             { 'v' => 1, 'target' => 'lease', 'value' => 'L', 'revoked_at' => 1500, 'authority' => pub(key) }.merge(over))
      end

      def grant(key, over = {})
        sign(key, AtlasPca::BREAK_GLASS_DOMAIN, AtlasPca::BREAK_GLASS_BODY_KEYS,
             { 'v' => 1, 'id' => 'g', 'holder' => 'h', 'grant_ref' => 'gr', 'reason_digest' => 'rd', 'max_uses' => 1, 'issued_at' => 1000, 'expires_at' => 2000,
               'review_within' => 500, 'notify_to' => 'n@x', 'authority' => pub(key) }.merge(over))
      end

      def review(key, over = {})
        sign(key, AtlasPca::BREAK_GLASS_REVIEW_DOMAIN, AtlasPca::BREAK_GLASS_REVIEW_KEYS,
             { 'v' => 1, 'id' => 'g', 'outcome' => 'unjustified', 'notes_digest' => 'nd', 'at' => 1100, 'reviewer' => pub(key) }.merge(over))
      end

      def blueprint(key, over = {})
        sign(key, AtlasPca::AGENT_BLUEPRINT_DOMAIN, AtlasPca::BLUEPRINT_BODY_KEYS,
             { 'v' => 1, 'id' => 'bp', 'key' => 'K', 'ceiling' => [], 'epoch' => 1, 'status' => 'active', 'issued_at' => 1, 'operator' => pub(key) }.merge(over))
      end
    end

    module_function

    def expect(got, want, label)
      check(got == want, "#{label}: got #{got.inspect}, want #{want.inspect}")
    end

    # Shared shell of the three kits: the report, the handle opener (checks the kv shape), cleanup. The block gets
    # (report, handle, opened, run, reopen) where reopen closes every handle, restarts the backend and returns a fresh handle.
    def registry_kit(name, open_kv, restart, teardown)
      report = ConformanceReport.new(name)
      run = SecureRandom.hex(6)
      opened = []
      handle = lambda do
        h = open_kv.call
        opened << h
        %i[get update].each { |m| check(h.respond_to?(m), "the kv has no #{m}()") }
        h
      end
      reopen = lambda do
        opened.each { |h| close(h) }
        restart&.call
        handle.call
      end
      begin
        yield report, handle, run, reopen
      ensure
        opened.each do |h|
          close(h)
        rescue StandardError
          nil
        end
        teardown&.call
      end
      report
    end

    def skip_unless(flag, why)
      raise Skip, why unless flag
    end
  end

  module_function

  # Run the LeaseRegistry contract over a kv (see "registry kits" above).
  def run_lease_registry_conformance(open_kv, durable: true, shared: true, restart: nil, teardown: nil, threads: 16, handles: 4, name: 'lease registry')
    sc = StoreConformance
    sc.registry_kit(name, open_kv, restart, teardown) do |report, handle, run, reopen|
      key = sc::Kits.signer
      pol = { 'authorities' => [sc::Kits.pub(key)] }
      reg = ->(kv = nil) { LeaseRegistry.new(pol, kv || handle.call) }
      rec = ->(tag, over = {}) { sc::Kits.lease(key, { 'lease_id' => "#{tag}:#{run}" }.merge(over)) }
      regs = -> { Array.new(shared ? handles : 1) { reg.call } }
      renew = { 'seq' => 2, 'renewed_at' => 1500, 'expires_at' => 3000 }

      sc.run_test(report, 'lease-semantics') do
        r = reg.call
        r1 = rec.call('sem')
        r2 = rec.call('sem', renew.merge('justification_digest' => 'j2'))
        sc.expect(r.accept(r1), { 'ok' => true, 'replaced' => true, 'seq' => 1 }, 'issue')
        sc.expect(r.accept(r1), { 'ok' => true, 'replaced' => false, 'seq' => 1 }, 'replay')
        sc.expect(r.accept(rec.call('sem', 'justification_digest' => 'jx')), { 'ok' => false, 'code' => 'lease_fork' }, 'fork')
        sc.expect(r.accept(r2), { 'ok' => true, 'replaced' => true, 'seq' => 2 }, 'renewal')
        sc.expect(r.accept(r1), { 'ok' => false, 'code' => 'stale_seq' }, 'older record')
        sc.expect(r.get("sem:#{run}"), r2, 'the newest record')
        sc.expect(r.history("sem:#{run}").map { |e| e['seq'] }, [1, 2], 'history')
        sc.expect(AtlasPca.check_lease(r2, r, 1600), { 'decision' => 'allow', 'lease_id' => "sem:#{run}", 'expires_at' => 3000 }, 'check of the newest')
        sc.expect(AtlasPca.check_lease(r1, r, 1600), { 'decision' => 'deny', 'code' => 'superseded', 'lease_id' => "sem:#{run}" }, 'check of a superseded record')
        nil
      end
      sc.run_test(report, 'lease-copies') do
        r = reg.call
        r.accept(rec.call('copy'))
        r.get("copy:#{run}")['holder'] = 'mallory'
        sc.expect(r.get("copy:#{run}")['holder'], 'agent', 'get must return a copy, not the stored record')
        nil
      end
      sc.run_test(report, 'lease-accept-race') do
        rs0 = regs.call
        r1 = rec.call('race')
        rs = sc.race(threads) { |i| rs0[i % rs0.length].accept(r1) }
        sc.check_no_errors(rs)
        sc.check(rs.all? { |x| x['ok'] == true }, "an identical record was refused: #{rs.find { |x| x['ok'] != true }.inspect}")
        wins = rs.count { |x| x['replaced'] == true }
        sc.check(wins == 1, "#{wins} of #{threads} concurrent issues of one record reported 'replaced' (want exactly 1)")
        "#{threads} threads over #{rs0.length} handles"
      end
      sc.run_test(report, 'lease-renewal-race') do
        rs0 = regs.call
        first = rec.call('renew')
        rs0.each { |r| r.accept(first) } # every handle is warm (shard pin read) before the race, so the renewals really overlap
        rs = sc.race(threads) { |i| rs0[i % rs0.length].accept(rec.call('renew', renew.merge('justification_digest' => "j#{i + 2}"))) }
        sc.check_no_errors(rs)
        wins = rs.count { |x| x['ok'] == true }
        sc.check(wins == 1, "#{wins} of #{threads} concurrent renewals of one lease were accepted (want exactly 1)")
        sc.check(rs.reject { |x| x['ok'] == true }.all? { |x| x['code'] == 'lease_fork' }, "a losing renewal was not a lease_fork: #{rs.inspect}")
        nil
      end
      sc.run_test(report, 'lease-revocation-across-registries') do
        a = reg.call
        r1 = rec.call('rev')
        a.accept(r1)
        sc.expect(a.revoke(sc::Kits.lease_revocation(key, 'value' => "rev:#{run}")), { 'ok' => true, 'revoked' => 1 }, 'revoke')
        b = shared ? reg.call : a
        sc.expect(b.accept(r1), { 'ok' => false, 'code' => 'revoked' }, 'a record presented to a new registry over the same kv')
        sc.expect(AtlasPca.check_lease(r1, b, 1500), { 'decision' => 'deny', 'code' => 'revoked', 'lease_id' => "rev:#{run}" }, 'check')
        nil
      end
      sc.run_test(report, 'lease-revocation-durability') do
        sc.skip_unless(durable, 'the adapter declares durable: false (state dies with the process)')
        a = reg.call
        r1 = rec.call('dur')
        a.accept(r1)
        a.revoke(sc::Kits.lease_revocation(key, 'value' => "dur:#{run}"))
        b = reg.call(reopen.call)
        sc.expect(b.accept(r1), { 'ok' => false, 'code' => 'revoked' }, 'accept after a restart')
        sc.expect(AtlasPca.check_lease(r1, b, 1500), { 'decision' => 'deny', 'code' => 'revoked', 'lease_id' => "dur:#{run}" }, 'check after a restart')
        nil
      end
    end
  end

  # Run the BreakGlassRegistry contract over a kv (see "registry kits" above).
  def run_break_glass_registry_conformance(open_kv, durable: true, shared: true, restart: nil, teardown: nil, threads: 16, handles: 4, name: 'break-glass registry')
    sc = StoreConformance
    sc.registry_kit(name, open_kv, restart, teardown) do |report, handle, run, reopen|
      akey = sc::Kits.signer
      rkey = sc::Kits.signer
      pol = { 'authorities' => [sc::Kits.pub(akey)], 'reviewers' => [sc::Kits.pub(rkey)] }
      reg = ->(kv = nil) { BreakGlassRegistry.new(pol, kv || handle.call) }
      grant = ->(tag, over = {}) { sc::Kits.grant(akey, { 'id' => "g:#{tag}:#{run}", 'holder' => "h:#{tag}:#{run}" }.merge(over)) }
      regs = -> { Array.new(shared ? handles : 1) { reg.call } }

      sc.run_test(report, 'break-glass-budget-across-registries') do
        g = grant.call('bud')
        a = reg.call
        b = shared ? reg.call : a
        sc.expect(a.accept(g, 1000), { 'ok' => true, 'replaced' => true }, 'accept')
        sc.expect(a.use(g['id'], g['holder'], 'd1', 1000, true), { 'decision' => 'allow', 'id' => g['id'], 'use' => 1, 'remaining' => 0, 'review_due' => 1500 }, 'first use')
        sc.expect(b.use(g['id'], g['holder'], 'd2', 1001, true), { 'decision' => 'deny', 'code' => 'budget_exhausted', 'id' => g['id'] }, 'second use on another registry')
        nil
      end
      sc.run_test(report, 'break-glass-use-race') do
        g = grant.call('race', 'max_uses' => 3)
        rs0 = regs.call
        rs0[0].accept(g, 1000)
        rs = sc.race(threads) { |i| rs0[i % rs0.length].use(g['id'], g['holder'], "d#{i}", 1000, true) }
        sc.check_no_errors(rs)
        wins = rs.count { |x| x['decision'] == 'allow' }
        sc.check(wins == 3, "#{wins} of #{threads} concurrent uses of a 3-use grant were allowed (want exactly 3)")
        sc.check(rs.reject { |x| x['decision'] == 'allow' }.all? { |x| x['code'] == 'budget_exhausted' }, "a refused use was not budget_exhausted: #{rs.inspect}")
        sc.expect(rs0[0].uses(g['holder'], g['id']).map { |u| u['n'] }, [1, 2, 3], 'the numbered use log')
        nil
      end
      sc.run_test(report, 'break-glass-freeze-durability') do
        sc.skip_unless(durable, 'the adapter declares durable: false (state dies with the process)')
        g = grant.call('frz')
        a = reg.call
        a.accept(g, 1000)
        a.use(g['id'], g['holder'], 'd1', 1000, true)
        sc.expect(a.review(sc::Kits.review(rkey, 'id' => g['id']), g['holder'], 1200), { 'ok' => true, 'replaced' => true }, 'review')
        b = reg.call(reopen.call)
        sc.expect(b.frozen(g['holder'], 1200), true, 'frozen after a restart')
        sc.expect(b.accept(grant.call('frz', 'id' => "g2:frz:#{run}"), 1200), { 'ok' => false, 'code' => 'holder_frozen' }, 'a new grant for a frozen holder after a restart')
        nil
      end
    end
  end

  # Run the BlueprintRegistry contract over a kv (see "registry kits" above).
  def run_blueprint_registry_conformance(open_kv, durable: true, shared: true, restart: nil, teardown: nil, threads: 16, handles: 4, name: 'blueprint registry')
    sc = StoreConformance
    sc.registry_kit(name, open_kv, restart, teardown) do |report, handle, run, reopen|
      key = sc::Kits.signer
      reg = ->(kv = nil) { BlueprintRegistry.new([sc::Kits.pub(key)], kv || handle.call) }
      bp = ->(tag, over = {}) { sc::Kits.blueprint(key, { 'key' => "K:#{tag}:#{run}" }.merge(over)) }

      sc.run_test(report, 'blueprint-epoch-across-registries') do
        a = reg.call
        b = shared ? reg.call : a
        k = "K:ep:#{run}"
        sc.expect(a.accept(bp.call('ep', 'epoch' => 5, 'status' => 'disabled')), { 'ok' => true, 'replaced' => true }, 'accept epoch 5')
        sc.expect(b.accept(bp.call('ep', 'epoch' => 4)), { 'ok' => false, 'code' => 'stale_epoch' }, 'an older epoch on another registry')
        sc.expect(b.get(k)['status'], 'disabled', 'the stored record')
        sc.check(b.epoch >= 5, "epoch() is #{b.epoch}, want at least 5")
        got = b.get(k)
        got['status'] = 'active'
        sc.expect(b.get(k)['status'], 'disabled', 'get must return a copy, not the stored record')
        nil
      end
      sc.run_test(report, 'blueprint-fork-race') do
        rs0 = Array.new(shared ? handles : 1) { reg.call }
        rs = sc.race(threads) { |i| rs0[i % rs0.length].accept(bp.call('fork', 'issued_at' => i + 1)) }
        sc.check_no_errors(rs)
        wins = rs.count { |x| x['ok'] == true }
        sc.check(wins == 1, "#{wins} of #{threads} concurrent records for one key and epoch were accepted (want exactly 1)")
        sc.check(rs.reject { |x| x['ok'] == true }.all? { |x| x['code'] == 'epoch_fork' }, "a losing record was not an epoch_fork: #{rs.inspect}")
        nil
      end
      sc.run_test(report, 'blueprint-durability') do
        sc.skip_unless(durable, 'the adapter declares durable: false (state dies with the process)')
        reg.call.accept(bp.call('dur', 'epoch' => 3, 'status' => 'disabled'))
        b = reg.call(reopen.call)
        sc.expect(b.get("K:dur:#{run}")['status'], 'disabled', 'the disabled record after a restart')
        sc.check(b.epoch >= 3, "epoch() is #{b.epoch} after a restart, want at least 3")
        sc.expect(b.accept(bp.call('dur', 'epoch' => 2)), { 'ok' => false, 'code' => 'stale_epoch' }, 'a replay of an older epoch after a restart')
        nil
      end
    end
  end
end
