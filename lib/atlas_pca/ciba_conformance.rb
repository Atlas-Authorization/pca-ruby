# frozen_string_literal: true

# Conformance cases for an approval store, plus broker-level cases run over it. Mirrors the TypeScript reference (@atlasauth/pca-ciba).
# Run them against YOUR store:
#
#   report = AtlasPca::CibaConformance.run_approval_store_conformance(-> { MyStore.new }, ->(previous) { MyStore.new })
#   raise report.render unless report.ok?
#
# Each case raises when the store breaks the contract: absent means nil, cas writes only at the expected version and bumps it by
# one, exactly one of many concurrent cas calls wins, returned values are snapshots, and (with reopen) written records survive a
# restart. The broker cases check what the contract is for: exactly one concurrent decision wins and an approval redeems once.
require 'securerandom'
require_relative 'ciba'
require_relative 'store_conformance'

module AtlasPca
  module CibaConformance
    ApprovalStoreCase = Struct.new(:name, :run)
    class CaseFailed < StandardError; end

    SC = StoreConformance

    module_function

    def eq(actual, expected)
      return if actual == expected && actual.class == expected.class

      raise CaseFailed, "expected #{expected.inspect}, got #{actual.inspect}"
    end

    # make: a callable returning a store over a fresh, empty backing location each call. reopen: for a persistent store, a callable
    # taking the previous store and returning a NEW store object over the same backing location, as after a restart.
    def approval_store_cases(make, reopen = nil)
      cases = []
      add = ->(name, &fn) { cases << ApprovalStoreCase.new(name, fn) }

      add.call('an absent key reads nil') { eq(make.call.get('nope'), nil) }

      add.call('cas at version 0 creates the key at version 1 with the whole value') do
        s = make.call
        v = { 'a' => 1, 'nested' => { 'b' => ['x', 2, nil] } }
        eq(s.cas('k', 0, v), true)
        eq(s.get('k'), { 'version' => 1, 'value' => v })
      end

      add.call('cas at version 0 on an existing key is refused and changes nothing') do
        s = make.call
        s.cas('k', 0, 'first')
        eq(s.cas('k', 0, 'second'), false)
        eq(s.get('k'), { 'version' => 1, 'value' => 'first' })
      end

      add.call('cas succeeds only at the current version and bumps it by exactly one') do
        s = make.call
        s.cas('k', 0, 1)
        eq(s.cas('k', 1, 2), true)
        eq(s.cas('k', 1, 3), false) # stale
        eq(s.cas('k', 5, 4), false) # from the future
        eq(s.cas('k', 2, 5), true)
        eq(s.get('k'), { 'version' => 3, 'value' => 5 })
      end

      add.call('cas on a key that does not exist at a non-zero version is refused and creates nothing') do
        s = make.call
        eq(s.cas('k', 1, 'x'), false)
        eq(s.get('k'), nil)
      end

      add.call('keys are independent') do
        s = make.call
        s.cas('a', 0, 'A')
        s.cas('b', 0, 'B')
        s.cas('a', 1, 'A2')
        eq(s.get('a'), { 'version' => 2, 'value' => 'A2' })
        eq(s.get('b'), { 'version' => 1, 'value' => 'B' })
      end

      add.call('a read is a snapshot: changing the returned value does not change the store') do
        s = make.call
        s.cas('k', 0, { 'list' => [1] })
        got = s.get('k')
        got['value']['list'] << 2
        eq(s.get('k'), { 'version' => 1, 'value' => { 'list' => [1] } })
      end

      add.call('a written value is a snapshot: changing it after cas does not change the store') do
        s = make.call
        v = { 'list' => [1] }
        s.cas('k', 0, v)
        v['list'] << 2
        eq(s.get('k'), { 'version' => 1, 'value' => { 'list' => [1] } })
      end

      add.call('exactly one of many concurrent creates wins') do
        s = make.call
        results = SC.race(32) { |i| s.cas('k', 0, i) }
        SC.check_no_errors(results)
        eq(results.select { |r| r == true }, [true])
        stored = s.get('k')
        eq(stored['version'], 1)
        eq(stored['value'], results.index(true))
      end

      add.call('exactly one of many concurrent updates at the same version wins') do
        s = make.call
        s.cas('k', 0, 'base')
        results = SC.race(32) { |i| s.cas('k', 1, i) }
        SC.check_no_errors(results)
        eq(results.count { |r| r == true }, 1)
        eq(s.get('k'), { 'version' => 2, 'value' => results.index(true) })
      end

      add.call('a retry loop over concurrent writers loses no increment') do
        s = make.call
        s.cas('n', 0, 0)
        SC.check_no_errors(SC.race(24) do |_i|
          loop do
            cur = s.get('n')
            break if cur && s.cas('n', cur['version'], cur['value'] + 1)
          end
        end)
        eq(s.get('n'), { 'version' => 25, 'value' => 24 })
      end

      unless reopen.nil?
        add.call('records and their versions survive reopening the store') do
          s = make.call
          s.cas('k', 0, { 'v' => 1 })
          s.cas('k', 1, { 'v' => 2 })
          again = reopen.call(s)
          eq(again.get('k'), { 'version' => 2, 'value' => { 'v' => 2 } })
          eq(again.cas('k', 1, { 'v' => 'stale' }), false)
          eq(again.cas('k', 2, { 'v' => 3 }), true)
        end
      end
      cases
    end

    def step_up
      { 'id' => "su_#{SecureRandom.hex(16)}", 'verb' => 'stripe.payout', 'resource' => 'acct:1', 'params' => { 'amount' => 80, 'currency' => 'USD', 'payee' => 'bob' },
        'tier' => 3, 'reason' => 'conformance', 'goalCommit' => 'A' * 43, 'goal' => 'pay suppliers', 'lineage' => {}, 'r' => 0.5, 'requestedAt' => 1 }
    end

    # Broker-level cases over a store: what the compare-and-set contract is for.
    def approval_broker_cases(make)
      brokers = lambda do |n|
        store = make.call
        Array.new(n) { Ciba.create_durable_ciba_broker('store' => store) }
      end

      concurrent_resolves = lambda do
        bs = brokers.call(8)
        req = bs[0].start(step_up)
        settled = SC.race(8) { |i| bs[i].resolve(req['auth_req_id'], i.even? ? 'approve' : 'deny', "user-#{i}") }
        won = settled.each_index.reject { |i| settled[i].is_a?(Exception) }
        eq(won.length, 1)
        final = bs[0].get(req['auth_req_id'])
        eq(final['decidedBy'], "user-#{won[0]}")
        eq(final['status'], won[0].even? ? 'approved' : 'denied')
      end

      redeems_once = lambda do
        bs = brokers.call(8)
        req = bs[0].start(step_up)
        bs[0].resolve(req['auth_req_id'], 'approve', 'owner')
        outs = SC.race(8) { |i| bs[i].token(req['auth_req_id']) }
        SC.check_no_errors(outs)
        eq(outs.count { |o| o['ok'] }, 1)
      end

      second_broker_sees = lambda do
        a, b = brokers.call(2)
        req = a.start(step_up)
        eq(b.poll(req['auth_req_id'])['status'], 'pending')
        a.resolve(req['auth_req_id'], 'approve', 'owner')
        eq(b.poll(req['auth_req_id'])['status'], 'approved')
        begin
          b.resolve(req['auth_req_id'], 'deny', 'late')
        rescue StandardError
          return
        end
        raise CaseFailed, 'expected a refusal'
      end

      [
        ApprovalStoreCase.new('concurrent resolves through separate brokers: exactly one wins and its decision stands', concurrent_resolves),
        ApprovalStoreCase.new('an approval redeems once even when many brokers redeem at the same time', redeems_once),
        ApprovalStoreCase.new('a second broker over the same store sees the decision of the first', second_broker_sees)
      ]
    end

    # Run the store cases and the broker cases; returns a ConformanceReport (ok?, render).
    def run_approval_store_conformance(make, reopen = nil)
      report = ConformanceReport.new('approval-store')
      (approval_store_cases(make, reopen) + approval_broker_cases(make)).each do |c|
        c.run.call
        report.results << StoreTestResult.new(test: c.name, status: 'pass', note: '')
      rescue StandardError => e
        report.results << StoreTestResult.new(test: c.name, status: 'fail', note: "#{e.class}: #{e.message}")
      end
      report
    end
  end
end
