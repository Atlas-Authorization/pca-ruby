# frozen_string_literal: true

# c20: mutation-kill tests for lib/atlas_pca/store_conformance.rb and lib/atlas_pca/atomic_kv.rb.
# Everything resolves AtlasPca at CALL time (the oracle re-evaluates AtlasPca per mutant); only plain helper classes that do not
# inherit from AtlasPca are defined at load. The sqlite3 gem is replaced by an in-memory fake (the mutation job does not install it).
require 'timeout'
require 'json'

module MutationKill
  module C20
    # ---- state-store conformance harness: a store that records every call and can override results by (kind, counter, nth) ----
    class Env
      attr_reader :events, :claims, :counts, :keys

      def initialize(rule: nil, close_raises: false)
        @events = []
        @claims = []
        @keys = []
        @counts = Hash.new(0)
        @mx = Mutex.new
        @rule = rule
        @close_raises = close_raises
        @next = 0
        @inner = AtlasPca::MemoryStateStore.new
      end

      def factory = -> { open_handle }

      def open_handle
        id = @next
        @next += 1
        @events << [:open, id]
        Handle.new(self, id)
      end

      def claim(hid, key, counter)
        kind = key.split(':', 2)[0]
        n = @mx.synchronize do
          @claims << [hid, kind, counter]
          @keys << key
          @counts[[kind, counter]] += 1
        end
        forced = @rule&.call(kind, counter, n)
        forced.nil? ? @inner.claim(key, counter) : forced
      end

      def closed(hid)
        @events << [:close, hid]
        raise 'close boom' if @close_raises
      end
    end

    class Handle
      def initialize(env, id)
        @env = env
        @id = id
      end

      def claim(key, counter) = @env.claim(@id, key, counter)
      def close = @env.closed(@id)
    end

    # ---- operation-store harness ----
    class OpEnv
      attr_reader :events, :log, :counts

      def initialize(rule: nil, make: nil, isolated: false, close_raises: false)
        @events = []
        @log = []
        @counts = Hash.new(0)
        @mx = Mutex.new
        @rule = rule
        @make = make || -> { AtlasPca::MemoryOperationStore.new }
        @isolated = isolated
        @close_raises = close_raises
        @shared = @make.call
        @next = 0
      end

      def factory = -> { open_handle }

      def open_handle
        id = @next
        @next += 1
        @events << [:open, id]
        OpHandle.new(self, id, @isolated ? @make.call : @shared)
      end

      def call(hid, op, args)
        first = args[0]
        kind = (first.is_a?(Hash) ? first['id'] : first).split(':', 2)[0]
        n = @mx.synchronize do
          @log << [hid, op, kind, Marshal.load(Marshal.dump(args))]
          @counts[[op, kind]] += 1
        end
        r = @rule&.call(op, kind, n, args)
        r ? r[0] : yield
      end

      def closed(hid)
        @events << [:close, hid]
        raise 'close boom' if @close_raises
      end
    end

    class OpHandle
      def initialize(env, id, inner)
        @env = env
        @id = id
        @inner = inner
      end

      def create(rec) = @env.call(@id, :create, [rec]) { @inner.create(rec) }
      def get(id) = @env.call(@id, :get, [id]) { @inner.get(id) }
      def transition(id, from, nxt) = @env.call(@id, :transition, [id, from, nxt]) { @inner.transition(id, from, nxt) }
      def close = @env.closed(@id)
    end

    # ---- fake SQLite3::Database ----
    class Db
      class << self
        attr_accessor :made, :files, :raise_on
      end
      attr_reader :path, :log, :handler, :close_count
      attr_accessor :raise_on_close

      def initialize(path)
        @path = path
        @log = []
        @closed = false
        @close_count = 0
        @snapshot = nil
        Db.made << self
        Db.files[path] ||= {}
      end

      def busy_handler(&blk)
        @handler = blk
      end

      def rows = Db.files[@path]

      def execute(sql, binds = nil)
        @log << [sql, binds]
        err = Db.raise_on&.call(sql, binds)
        raise err if err

        case sql
        when 'BEGIN IMMEDIATE' then @snapshot = rows.dup
        when 'COMMIT' then @snapshot = nil
        when 'ROLLBACK'
          Db.files[@path] = @snapshot if @snapshot
          @snapshot = nil
        when /\AINSERT INTO pca_kv/ then rows[binds[0]] = binds[1]
        end
        []
      end

      def get_first_row(sql, binds)
        @log << [sql, binds]
        v = rows[binds[0]]
        v.nil? ? nil : [v]
      end

      def closed? = @closed

      def close
        @close_count += 1
        raise 'db close boom' if @raise_on_close

        @closed = true
      end
    end

    # an Array that records whether the mutex was held at each push / shift
    class Obs < Array
      attr_reader :owned

      def initialize(mx)
        super()
        @mx = mx
        @owned = []
      end

      def <<(other)
        @owned << [:push, @mx.owned?]
        super
      end

      def shift(*args)
        @owned << [:shift, @mx.owned?]
        super
      end
    end

    # exceptions whose message and to_s differ (pins `e.message` vs interpolating e)
    class OddErr < StandardError
      def message = 'M'
      def to_s = 'T'
    end

    # a claim result whose inspect and to_s differ
    class OddResult
      def ok = false
      def last_counter = 2
      def to_s = 'TOS'
      def inspect = 'INS'
    end

    # a Queue that records its pushes and pops
    class SpyQ < ::Queue
      class << self
        attr_accessor :log
      end

      def <<(v)
        SpyQ.log << [:push, v]
        super
      end

      def pop(*a, **k)
        SpyQ.log << [:pop]
        super
      end
    end

    module_function

    # run the block on its own thread with a deadline: a hang raises Timeout::Error here (an ordinary error = a kill), and cannot be
    # swallowed by the run_test rescue inside the code under test
    def within(sec)
      th = Thread.new do
        Thread.current.report_on_exception = false
        yield
      end
      unless th.join(sec)
        th.kill
        raise Timeout::Error, 'c20 deadline'
      end
      th.value
    end

    def skip?(base) = (f = ENV['MUT_FILE']) && !f.empty? && f != base

    def ck(label, got, want)
      got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    end

    def sc = AtlasPca::StoreConformance
    def win = AtlasPca::ClaimResult.new(true)
    def lose(last = 1) = AtlasPca::ClaimResult.new(false, last)

    def rec(id, state = 'pending')
      { 'id' => id, 'state' => state, 'verb' => 'v', 'resource' => '/r', 'params_digest' => 'd', 'reversibility' => 'reversible', 'startedAt' => 1 }
    end

    def res(rep) = rep.results.map { |r| [r.test, r.status, r.note] }

    def run_s(env, threads: 3, rounds: 2, handles: 2, **kw)
      C20.within(3) { AtlasPca.run_state_store_conformance(env.factory, threads: threads, rounds: rounds, handles: handles, **kw) }
    end

    def run_o(env, threads: 3, rounds: 2, handles: 2, **kw)
      C20.within(3) { AtlasPca.run_operation_store_conformance(env.factory, threads: threads, rounds: rounds, handles: handles, **kw) }
    end

    def closes(ids) = ids.map { |i| [:close, i] }

    def opids(args) = (args[0].is_a?(Hash) ? args[0]['id'] : args[0])

    # the run token: every key / id carries the same 12 hex digits
    def run_of(strings)
      runs = strings.map do |s|
        m = /\A[a-z-]+:([0-9a-f]{12})(?::\d+|-b)?\z/.match(s)
        raise "bad key/id #{s.inspect}" unless m

        m[1]
      end.uniq
      raise "several runs #{runs.inspect}" unless runs.length == 1

      runs[0]
    end

    def state_fail(label, test, note, rule)
      rep = run_s(Env.new(rule: rule))
      got = rep.results.find { |r| r.test == test }
      ck("#{label} status/note", [got.status, got.note], ['fail', note]) && ck("#{label} ok?", rep.ok?, false)
    end

    def op_fail(label, test, note, rule, **kw)
      rep = run_o(OpEnv.new(rule: rule, **kw))
      got = rep.results.find { |r| r.test == test }
      ck("#{label} status/note", [got.status, got.note], ['fail', note]) && ck("#{label} ok?", rep.ok?, false)
    end

    # ---- sqlite fake plumbing ----
    def with_fake_db
      had = Object.const_defined?(:SQLite3)
      old = Object.const_get(:SQLite3) if had
      Object.send(:remove_const, :SQLite3) if had
      mod = Module.new
      mod.const_set(:Database, Db)
      Object.const_set(:SQLite3, mod)
      Db.made = []
      Db.files = {}
      Db.raise_on = nil
      yield
    ensure
      Object.send(:remove_const, :SQLite3) if Object.const_defined?(:SQLite3)
      Object.const_set(:SQLite3, old) if had
    end

    def mk(path = '/k.db', **kw)
      kv = AtlasPca::SqliteAtomicKv.allocate
      reqs = []
      slept = []
      kv.define_singleton_method(:require) { |n| reqs << n; true }
      kv.define_singleton_method(:sleep) { |s| slept << s; nil }
      kv.send(:initialize, path, **kw)
      [kv, reqs, slept]
    end

    def with_clock(vals)
      orig = Process.method(:clock_gettime)
      q = vals.dup
      me = Thread.current
      Process.define_singleton_method(:clock_gettime) { |*a| Thread.current.equal?(me) ? q.shift : orig.call(*a) }
      yield
    ensure
      Process.define_singleton_method(:clock_gettime, orig)
    end

    DDL = 'CREATE TABLE IF NOT EXISTS pca_kv (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)'
    SEL = 'SELECT value FROM pca_kv WHERE key = ?'
    INS = 'INSERT INTO pca_kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
  end

  # ======================================================================================================================
  # store_conformance.rb: report, helpers
  # ======================================================================================================================

  t('c20 ConformanceReport: name, results, ok?, failures, render') do
    next true if C20.skip?('store_conformance.rb')
    r = AtlasPca::StoreTestResult
    rep = AtlasPca::ConformanceReport.new('nm')
    rep2 = AtlasPca::ConformanceReport.new('nm2')
    ok = C20.ck('name', [rep.name, rep.results, rep2.name], ['nm', [], 'nm2']) && C20.ck('not shared', rep.results.equal?(rep2.results), false) &&
         C20.ck('empty ok?', rep.ok?, false)
    mk = ->(*sts) { AtlasPca::ConformanceReport.new('x').tap { |x| sts.each_with_index { |s, i| x.results << r.new(test: "t#{i}", status: s, note: nil) } } }
    ok &&= C20.ck('ok? table', [mk.call('pass').ok?, mk.call('skip').ok?, mk.call('pass', 'skip').ok?, mk.call('pass', 'fail').ok?, mk.call('fail').ok?,
                                mk.call('skip', 'pass', 'skip').ok?, mk.call('fail', 'pass').ok?], [true, false, true, false, false, true, false])
    ok &&= C20.ck('failures', mk.call('pass', 'fail', 'skip', 'fail').failures.map(&:test), %w[t1 t3]) && C20.ck('failures none', mk.call('pass').failures, [])
    rr = AtlasPca::ConformanceReport.new('x')
    rr.results << r.new(test: 'a', status: 'pass', note: nil)
    rr.results << r.new(test: 'b', status: 'skip', note: 'why')
    rr.results << r.new(test: 'c', status: 'fail', note: '')
    rr.results << r.new(test: 'd', status: 'ab', note: nil)
    rr.results << r.new(test: 'e', status: 'fail', note: 5)
    ok && C20.ck('render', rr.render, "pass a\nskip b: why\nfail c\nab   d\nfail e: 5") && C20.ck('render empty', AtlasPca::ConformanceReport.new('z').render, '')
  end

  t('c20 StoreConformance: check, check_no_errors, close, record, claimed?, last_of') do
    next true if C20.skip?('store_conformance.rb')
    sc = C20.sc
    ok = C20.ck('Skip', [sc::Skip.superclass, sc::Failure.superclass], [StandardError, StandardError])
    ok &&= C20.ck('check true', sc.check(true, 'm'), nil)
    ok &&= C20.ck('check false', (begin; sc.check(false, 'the msg'); nil; rescue sc::Failure => e; [e.class, e.message]; end), [sc::Failure, 'the msg'])
    ok &&= C20.ck('check nil', (begin; sc.check(nil, 'q'); nil; rescue sc::Failure => e; e.message; end), 'q')
    ok &&= C20.ck('no errors', [sc.check_no_errors([]), sc.check_no_errors([1, NotImplementedError.new('x'), 'a'])], [nil, nil])
    msg = begin
      sc.check_no_errors([1, RuntimeError.new('x'), ArgumentError.new('y')])
      nil
    rescue sc::Failure => e
      e.message
    end
    ok &&= C20.ck('errors msg', msg, '2 of 3 concurrent calls raised: #<RuntimeError: x>')
    closed = []
    with_close = Class.new { define_method(:close) { closed << :c; :ret } }.new
    ok &&= C20.ck('close', [sc.close(with_close), closed, sc.close(Object.new)], [:ret, [:c], nil])
    ok &&= C20.ck('record default', sc.record('x'), C20.rec('x')) && C20.ck('record state', sc.record('y', 'done'), C20.rec('y', 'done'))
    ok &&= C20.ck('record exact', sc.record('i'), { 'id' => 'i', 'state' => 'pending', 'verb' => 'v', 'resource' => '/r', 'params_digest' => 'd',
                                                    'reversibility' => 'reversible', 'startedAt' => 1 })
    okc = Struct.new(:ok)
    claimed = [[true, true], [false, false], [nil, false], [AtlasPca::ClaimResult.new(true), true], [AtlasPca::ClaimResult.new(false, 3), false],
               [okc.new('yes'), false], [okc.new(true), true], [okc.new(false), false], [Object.new, false], [[true, 9], true], [[false, 1], false], [[], false],
               [[1], false], [{ 0 => true }, false], ['true', false], [5, false], [[true], true]]
    ok &&= C20.ck('claimed?', claimed.map { |v, _| sc.claimed?(v) }, claimed.map(&:last))
    lc = Struct.new(:last_counter)
    last = [[AtlasPca::ClaimResult.new(false, 7), 7], [AtlasPca::ClaimResult.new(true), nil], [[false, 4], 4], [[true], nil], [true, nil], [nil, nil],
            ['ab', nil], [lc.new(3), 3], [{ 1 => 2 }, nil], [Object.new, nil], [[true, 'z'], 'z']]
    ok && C20.ck('last_of', last.map { |v, _| sc.last_of(v) }, last.map(&:last))
  end

  t('c20 StoreConformance.race: ordered results, errors as values, concurrent release, non-standard errors propagate') do
    next true if C20.skip?('store_conformance.rb')
    sc = C20.sc
    C20.within(3) do
      ok = C20.ck('order', sc.race(5) { |i| sleep((5 - i) * 0.002); i * 2 }, [0, 2, 4, 6, 8]) && C20.ck('zero', sc.race(0) { |_i| 1 }, [])
      rs = sc.race(3) { |i| i == 1 ? raise(ArgumentError, "e#{i}") : i }
      ok &&= C20.ck('values', [rs[0], rs[2], rs[1].class, rs[1].message], [0, 2, ArgumentError, 'e1'])
      mx = Mutex.new
      cnt = 0
      together = sc.race(4) do |_i|
        mx.synchronize { cnt += 1 }
        Thread.pass until mx.synchronize { cnt } == 4
        cnt
      end
      ok &&= C20.ck('together', together, [4, 4, 4, 4])
      old = Thread.report_on_exception
      Thread.report_on_exception = false
      raised = begin
        sc.race(2) { |i| i == 0 ? raise(NotImplementedError, 'ni') : i }
        false
      rescue NotImplementedError
        true
      ensure
        Thread.report_on_exception = old
      end
      ok && C20.ck('non-standard propagates', raised, true)
    end
  end

  t('c20 StoreConformance.run_test: pass / skip / fail records, note rules, non-standard errors escape') do
    next true if C20.skip?('store_conformance.rb')
    sc = C20.sc
    sr = AtlasPca::StoreTestResult
    rep = AtlasPca::ConformanceReport.new('x')
    rets = []
    rets << sc.run_test(rep, 'p1') { 'hello' }
    rets << sc.run_test(rep, 'p2') { 5 }
    rets << sc.run_test(rep, 'p3') { nil }
    rets << sc.run_test(rep, 's') { raise sc::Skip, 'skipped because' }
    rets << sc.run_test(rep, 'f') { raise sc::Failure, 'failed because' }
    rets << sc.run_test(rep, 'e') { raise ArgumentError, 'boom' }
    ok = C20.ck('results', rep.results, [sr.new(test: 'p1', status: 'pass', note: 'hello'), sr.new(test: 'p2', status: 'pass', note: ''),
                                         sr.new(test: 'p3', status: 'pass', note: ''), sr.new(test: 's', status: 'skip', note: 'skipped because'),
                                         sr.new(test: 'f', status: 'fail', note: 'failed because'), sr.new(test: 'e', status: 'fail', note: 'ArgumentError: boom')])
    ok &&= C20.ck('returns results', rets.all? { |r| r.equal?(rep.results) }, true)
    rep2 = AtlasPca::ConformanceReport.new('y')
    escaped = begin
      sc.run_test(rep2, 'n') { raise NotImplementedError, 'ni' }
      false
    rescue NotImplementedError
      true
    end
    ok && C20.ck('non-standard escapes', [escaped, rep2.results], [true, []])
  end

  # ======================================================================================================================
  # run_state_store_conformance
  # ======================================================================================================================

  t('c20 run_state_store_conformance: full pass (results, notes, handle use, event order, claim tally)') do
    next true if C20.skip?('store_conformance.rb')
    env = C20::Env.new
    cbs = { restart: -> { env.events << :restart }, crash: -> { env.events << :crash }, teardown: -> { env.events << :teardown } }
    rep = C20.run_s(env, threads: 4, rounds: 2, handles: 2, **cbs)
    ok = C20.ck('name', rep.name, 'state store') && C20.ck('ok?', rep.ok?, true)
    ok &&= C20.ck('results', C20.res(rep), [['claim-sequence', 'pass', ''], ['claim-burst', 'pass', '2 rounds x 4 threads'],
                                            ['claim-concurrent', 'pass', '2 rounds x 4 threads over 2 handles'], ['claim-durability', 'pass', ''],
                                            ['crash-after-claim', 'pass', ''], ['retry-after-timeout', 'pass', '']])
    ok &&= C20.ck('events', env.events, [[:open, 0], [:open, 1], [:open, 2], [:open, 3], [:open, 4], *C20.closes(0..4), :restart, [:open, 5], [:open, 6],
                                         [:open, 7], :crash, :restart, [:open, 8], [:open, 9], [:open, 10], *C20.closes(0..10), :teardown])
    ok &&= C20.ck('claims', env.claims.tally, { [0, 'seq', 1] => 2, [0, 'seq', 5] => 2, [0, 'seq', 3] => 1, [0, 'seq-other', 1] => 1,
                                                [1, 'burst', 1] => 4, [1, 'burst', 2] => 4, [2, 'conc', 1] => 2, [3, 'conc', 1] => 2,
                                                [2, 'conc', 2] => 2, [3, 'conc', 2] => 2, [4, 'dur', 7] => 1, [5, 'dur', 7] => 1, [6, 'dur', 8] => 1,
                                                [7, 'crash', 1] => 1, [8, 'crash', 1] => 1, [8, 'crash', 2] => 1, [9, 'retry', 1] => 1,
                                                [10, 'retry', 1] => 1, [10, 'retry', 2] => 1, [10, 'retry', 3] => 1, [9, 'retry', 3] => 1 })
    run = C20.run_of(env.keys)
    ok && C20.ck('keys', env.keys.uniq.sort, %w[seq seq-other burst conc dur crash retry].map { |k| "#{k}:#{run}" }.sort)
  end

  t('c20 run_state_store_conformance: process-local declarations skip, name is reported, no callbacks needed') do
    next true if C20.skip?('store_conformance.rb')
    env = C20::Env.new
    rep = C20.run_s(env, threads: 3, rounds: 3, durable: false, shared: false, name: 'my store')
    ok = C20.ck('name', rep.name, 'my store') && C20.ck('ok?', rep.ok?, true)
    ok &&= C20.ck('results', C20.res(rep), [['claim-sequence', 'pass', ''], ['claim-burst', 'pass', '3 rounds x 3 threads'],
                                            ['claim-concurrent', 'skip', 'the adapter declares shared: false (a process-local store)'],
                                            ['claim-durability', 'skip', 'the adapter declares durable: false (state dies with the process)'],
                                            ['crash-after-claim', 'skip', 'the adapter declares durable: false (state dies with the process)'],
                                            ['retry-after-timeout', 'pass', '']])
    ok &&= C20.ck('events', env.events, [[:open, 0], [:open, 1], [:open, 2], [:close, 0], [:close, 1], [:close, 2]])
    ok && C20.ck('claims', env.claims.tally, { [0, 'seq', 1] => 2, [0, 'seq', 5] => 2, [0, 'seq', 3] => 1, [0, 'seq-other', 1] => 1, [1, 'burst', 1] => 3,
                                               [1, 'burst', 2] => 3, [1, 'burst', 3] => 3, [2, 'retry', 1] => 2, [2, 'retry', 2] => 1, [2, 'retry', 3] => 2 })
  end

  t('c20 run_state_store_conformance: defaults are 16 threads x 5 rounds x 4 handles') do
    next true if C20.skip?('store_conformance.rb')
    env = C20::Env.new
    rep = C20.within(3) { AtlasPca.run_state_store_conformance(env.factory) }
    ok = C20.ck('results', C20.res(rep), [['claim-sequence', 'pass', ''], ['claim-burst', 'pass', '5 rounds x 16 threads'],
                                          ['claim-concurrent', 'pass', '5 rounds x 16 threads over 4 handles'], ['claim-durability', 'pass', ''],
                                          ['crash-after-claim', 'pass', ''], ['retry-after-timeout', 'pass', '']])
    want = (1..5).flat_map { |c| [[['burst', c], 16], [['conc', c], 16]] }.to_h
    got = env.counts.select { |(k, _), _| %w[burst conc].include?(k) }
    ok &&= C20.ck('counts', got, want)
    ok && C20.ck('conc handles', env.claims.select { |_, k, _| k == 'conc' }.map(&:first).tally, { 2 => 20, 3 => 20, 4 => 20, 5 => 20 })
  end

  t('c20 run_state_store_conformance: every refusal reports its exact message') do
    next true if C20.skip?('store_conformance.rb')
    sf = ->(label, test, note, rule) { C20.state_fail(label, test, note, rule) }
    w = -> { C20.win }
    l = ->(last = 1) { C20.lose(last) }
    seq = 'claim-sequence'
    ok = sf.call('s1', seq, 'first claim of counter 1 refused', ->(k, c, n) { l.call if k == 'seq' && c == 1 && n == 1 })
    ok &&= sf.call('s2', seq, 'counter 1 claimed twice', ->(k, c, n) { w.call if k == 'seq' && c == 1 && n == 2 })
    bad = AtlasPca::ClaimResult.new(false, 2)
    ok &&= sf.call('s3', seq, "a refused claim must report last_counter=1, got #{bad.inspect}", ->(k, c, n) { bad if k == 'seq' && c == 1 && n == 2 })
    nolast = AtlasPca::ClaimResult.new(false)
    ok &&= sf.call('s3b', seq, "a refused claim must report last_counter=1, got #{nolast.inspect}", ->(k, c, n) { nolast if k == 'seq' && c == 1 && n == 2 })
    ok &&= sf.call('s4', seq, 'a larger counter (a gap) must be admitted', ->(k, c, n) { l.call if k == 'seq' && c == 5 && n == 1 })
    ok &&= sf.call('s5', seq, 'an older counter was admitted after 5', ->(k, c, n) { w.call if k == 'seq' && c == 3 && n == 1 })
    ok &&= sf.call('s6', seq, 'counter 5 claimed twice', ->(k, c, n) { w.call if k == 'seq' && c == 5 && n == 2 })
    ok &&= sf.call('s7', seq, 'another key must be independent', ->(k, c, n) { l.call if k == 'seq-other' && c == 1 && n == 1 })
    ok &&= sf.call('b1', 'claim-burst', 'round 2: 3 of 3 concurrent claims of counter 2 were admitted (want exactly 1)', ->(k, c, _n) { w.call if k == 'burst' && c == 2 })
    ok &&= sf.call('b2', 'claim-burst', 'round 1: 0 of 3 concurrent claims of counter 1 were admitted (want exactly 1)', ->(k, c, _n) { l.call if k == 'burst' && c == 1 })
    ok &&= sf.call('b3', 'claim-burst', '1 of 3 concurrent calls raised: #<RuntimeError: boom>', ->(k, c, n) { raise 'boom' if k == 'burst' && c == 1 && n == 1 })
    ok &&= sf.call('c1', 'claim-concurrent', 'round 2: 3 of 3 claims over 2 handles were admitted (want exactly 1)', ->(k, c, _n) { w.call if k == 'conc' && c == 2 })
    ok &&= sf.call('c2', 'claim-concurrent', 'round 1: 0 of 3 claims over 2 handles were admitted (want exactly 1)', ->(k, c, _n) { l.call if k == 'conc' && c == 1 })
    ok &&= sf.call('c3', 'claim-concurrent', '1 of 3 concurrent calls raised: #<RuntimeError: boom>', ->(k, c, n) { raise 'boom' if k == 'conc' && c == 2 && n == 1 })
    ok &&= sf.call('d1', 'claim-durability', 'claim refused', ->(k, c, n) { l.call if k == 'dur' && c == 7 && n == 1 })
    ok &&= sf.call('d2', 'claim-durability', 'counter 7 was admitted again after the handles were closed (the claim was not durable)',
                   ->(k, c, n) { w.call if k == 'dur' && c == 7 && n == 2 })
    ok &&= sf.call('d3', 'claim-durability', 'the next counter must be admitted after a restart', ->(k, c, n) { l.call if k == 'dur' && c == 8 && n == 1 })
    ok &&= sf.call('x1', 'crash-after-claim', 'claim refused', ->(k, c, n) { l.call if k == 'crash' && c == 1 && n == 1 })
    ok &&= sf.call('x2', 'crash-after-claim', 'the proof admitted before the crash was admitted again', ->(k, c, n) { w.call if k == 'crash' && c == 1 && n == 2 })
    ok &&= sf.call('x3', 'crash-after-claim', 'the next counter must be admitted after the crash', ->(k, c, n) { l.call if k == 'crash' && c == 2 && n == 1 })
    rt = 'retry-after-timeout'
    ok &&= sf.call('r1', rt, 'a claim whose answer was lost was admitted again on retry', ->(k, c, n) { w.call if k == 'retry' && c == 1 && n == 2 })
    ok &&= sf.call('r2', rt, 'the next counter must be admitted after a lost answer', ->(k, c, n) { l.call if k == 'retry' && c == 2 && n == 1 })
    ok &&= sf.call('r3', rt, '2 of 2 admitted for a retry while the first commit was in flight (want exactly 1)', ->(k, c, _n) { w.call if k == 'retry' && c == 3 })
    ok && sf.call('r4', rt, '0 of 2 admitted for a retry while the first commit was in flight (want exactly 1)', ->(k, c, _n) { l.call if k == 'retry' && c == 3 })
  end

  t('c20 run_state_store_conformance: array-form claim results are understood') do
    next true if C20.skip?('store_conformance.rb')
    rule = lambda do |k, c, n|
      next [true] if k == 'seq' && c == 1 && n == 1
      next [false, 1] if k == 'seq' && c == 1 && n == 2
    end
    rep = C20.run_s(C20::Env.new(rule: rule))
    got = rep.results.find { |r| r.test == 'claim-sequence' }
    C20.ck('array form', [got.status, got.note], ['pass', ''])
  end

  t('c20 run_state_store_conformance: a store without claim fails every test, a raising close is reported and survived') do
    next true if C20.skip?('store_conformance.rb')
    opened = []
    torn = []
    rep = C20.within(3) { AtlasPca.run_state_store_conformance(-> { Object.new.tap { |o| opened << o } }, teardown: -> { torn << 1 }) }
    note = 'the store has no claim(key, counter)'
    ok = C20.ck('all fail', C20.res(rep), %w[claim-sequence claim-burst claim-concurrent claim-durability crash-after-claim retry-after-timeout].map { |n| [n, 'fail', note] })
    ok &&= C20.ck('ok?', rep.ok?, false) && C20.ck('teardown', torn, [1]) && C20.ck('opened', opened.length, 6)
    env = C20::Env.new(close_raises: true)
    events = env.events
    rep2 = C20.run_s(env, teardown: -> { events << :teardown })
    d = rep2.results.find { |r| r.test == 'claim-durability' }
    ok &&= C20.ck('dur fail', [d.status, d.note], ['fail', 'RuntimeError: close boom']) && C20.ck('six results', rep2.results.length, 6)
    ids = events.select { |e| e.is_a?(Array) && e[0] == :open }.map(&:last)
    ok && C20.ck('teardown last', events.last, :teardown) && C20.ck('every handle closed', ids.all? { |i| events.include?([:close, i]) }, true) &&
      C20.ck('closed in ensure', events.count { |e| e == [:close, 0] }, 2)
  end

  # ======================================================================================================================
  # run_operation_store_conformance
  # ======================================================================================================================

  t('c20 run_operation_store_conformance: full pass (results, notes, events, call tally, argument shapes)') do
    next true if C20.skip?('store_conformance.rb')
    env = C20::OpEnv.new
    cbs = { restart: -> { env.events << :restart }, teardown: -> { env.events << :teardown } }
    rep = C20.run_o(env, threads: 4, rounds: 2, handles: 2, **cbs)
    ok = C20.ck('name', rep.name, 'operation store') && C20.ck('ok?', rep.ok?, true)
    ok &&= C20.ck('results', C20.res(rep), [['semantics', 'pass', ''], ['copies', 'pass', ''], ['create-race', 'pass', '2 rounds x 4 threads'],
                                            ['transition-race', 'pass', '2 rounds x 4 threads'], ['cross-handle', 'pass', 'over 2 handles'],
                                            ['durability', 'pass', '']])
    ok &&= C20.ck('events', env.events, [[:open, 0], [:open, 1], [:open, 2], [:open, 3], [:open, 4], [:open, 5], [:open, 6], *C20.closes(0..6), :restart,
                                         [:open, 7], *C20.closes(0..7), :teardown])
    ok &&= C20.ck('tally', env.counts, { [:get, 'op-sem'] => 4, [:create, 'op-sem'] => 2, [:transition, 'nope'] => 1, [:transition, 'op-sem'] => 3,
                                         [:create, 'op-copy'] => 2, [:get, 'op-copy'] => 3, [:create, 'op-create'] => 8, [:create, 'op-cas'] => 2,
                                         [:transition, 'op-cas'] => 8, [:create, 'op-shared'] => 4, [:transition, 'op-shared'] => 4,
                                         [:create, 'op-dur'] => 1, [:transition, 'op-dur'] => 1, [:get, 'op-dur'] => 1 })
    ids = env.log.map { |e| C20.opids(e[3]) }
    run = C20.run_of(ids)
    i = "op-sem:#{run}"
    sel = ->(op, kind) { env.log.select { |_, o, k, _| o == op && k == kind }.map { |e| e[3] } }
    ok &&= C20.ck('sem create', sel.call(:create, 'op-sem'), [[C20.rec(i)], [C20.rec(i).merge('verb' => 'other')]])
    ok &&= C20.ck('sem gets', sel.call(:get, 'op-sem'), [[i]] * 4)
    ok &&= C20.ck('nope', sel.call(:transition, 'nope'), [["nope:#{run}", 'pending', C20.rec('nope')]])
    ok &&= C20.ck('sem transitions', sel.call(:transition, 'op-sem'), [[i, 'executing', C20.rec(i, 'executing')],
                                                                         [i, 'pending', C20.rec(i, 'executing').merge('executingAt' => 2)],
                                                                         [i, 'pending', C20.rec(i, 'aborted')]])
    c = "op-copy:#{run}"
    ok &&= C20.ck('copy create', sel.call(:create, 'op-copy').map { |a| a[0]['id'] }, [c, "#{c}-b"]) &&
           C20.ck('copy get', sel.call(:get, 'op-copy'), [[c], [c], ["#{c}-b"]])
    ok &&= C20.ck('create-race ids', sel.call(:create, 'op-create').map { |a| a[0]['id'] }.tally, { "op-create:#{run}:0" => 4, "op-create:#{run}:1" => 4 })
    ok &&= C20.ck('cas ids', sel.call(:create, 'op-cas').map { |a| a[0]['id'] }, ["op-cas:#{run}:0", "op-cas:#{run}:1"])
    tr = sel.call(:transition, 'op-cas')
    ok &&= C20.ck('cas args', tr.sort_by { |a| [a[0], a[2]['executingAt']] },
                  (0..1).flat_map { |r| (0..3).map { |n| ["op-cas:#{run}:#{r}", 'pending', C20.rec("op-cas:#{run}:#{r}", 'executing').merge('executingAt' => n)] } })
    ok &&= C20.ck('shared handles', env.log.select { |_, _, k, _| k == 'op-shared' }.map { |h, o, _, _| [h, o] }.tally,
                  { [4, :create] => 2, [5, :create] => 2, [4, :transition] => 2, [5, :transition] => 2 })
    sid = "op-shared:#{run}"
    ok &&= C20.ck('shared create args', sel.call(:create, 'op-shared'), [[C20.rec(sid)]] * 4)
    ok &&= C20.ck('shared transition args', sel.call(:transition, 'op-shared').sort_by { |a| a[2]['executingAt'] },
                  (0..3).map { |n| [sid, 'pending', C20.rec(sid, 'executing').merge('executingAt' => n)] })
    d = "op-dur:#{run}"
    ok && C20.ck('dur', env.log.select { |_, _, k, _| k == 'op-dur' }.map { |h, o, _, a| [h, o, a] },
                 [[6, :create, [C20.rec(d)]], [6, :transition, [d, 'pending', C20.rec(d, 'executing').merge('executingAt' => 3)]], [7, :get, [d]]])
  end

  t('c20 run_operation_store_conformance: process-local declarations skip; defaults are 16 x 5 x 4') do
    next true if C20.skip?('store_conformance.rb')
    env = C20::OpEnv.new
    rep = C20.run_o(env, durable: false, shared: false, name: 'ops')
    ok = C20.ck('name', rep.name, 'ops') && C20.ck('ok?', rep.ok?, true)
    ok &&= C20.ck('results', C20.res(rep), [['semantics', 'pass', ''], ['copies', 'pass', ''], ['create-race', 'pass', '2 rounds x 3 threads'],
                                            ['transition-race', 'pass', '2 rounds x 3 threads'],
                                            ['cross-handle', 'skip', 'the adapter declares shared: false (a process-local store)'],
                                            ['durability', 'skip', 'the adapter declares durable: false (state dies with the process)']])
    ok &&= C20.ck('events', env.events, [[:open, 0], [:open, 1], [:open, 2], [:open, 3], *C20.closes(0..3)])
    env2 = C20::OpEnv.new
    rep2 = C20.within(3) { AtlasPca.run_operation_store_conformance(env2.factory) }
    ok &&= C20.ck('default results', C20.res(rep2), [['semantics', 'pass', ''], ['copies', 'pass', ''], ['create-race', 'pass', '5 rounds x 16 threads'],
                                                     ['transition-race', 'pass', '5 rounds x 16 threads'], ['cross-handle', 'pass', 'over 4 handles'],
                                                     ['durability', 'pass', '']])
    ok &&= C20.ck('default counts', [env2.counts[[:create, 'op-create']], env2.counts[[:transition, 'op-cas']], env2.counts[[:create, 'op-shared']],
                                     env2.counts[[:transition, 'op-shared']]], [80, 80, 16, 16])
    ok && C20.ck('default handles', env2.log.select { |_, o, k, _| k == 'op-shared' && o == :create }.map(&:first).tally, { 4 => 4, 5 => 4, 6 => 4, 7 => 4 })
  end

  t('c20 run_operation_store_conformance: every refusal reports its exact message') do
    next true if C20.skip?('store_conformance.rb')
    of = ->(label, test, note, rule, **kw) { C20.op_fail(label, test, note, rule, **kw) }
    v = Class.new { def [](_k); 'v'; end }.new
    sem = 'semantics'
    ok = of.call('m1', sem, 'get of an unknown id must be nil', ->(o, k, n, _a) { [{ 'x' => 1 }] if o == :get && k == 'op-sem' && n == 1 })
    ok &&= of.call('m2', sem, 'create of a new id must return nil', ->(o, k, n, _a) { [{ 'id' => 'a' }] if o == :create && k == 'op-sem' && n == 1 })
    note3 = 'create of an existing id must return the existing record unchanged'
    ok &&= of.call('m3', sem, note3, ->(o, k, n, _a) { [nil] if o == :create && k == 'op-sem' && n == 2 })
    ok &&= of.call('m3b', sem, note3, ->(o, k, n, _a) { [{ 'verb' => 'other' }] if o == :create && k == 'op-sem' && n == 2 })
    ok &&= of.call('m3c', sem, note3, ->(o, k, n, _a) { [v] if o == :create && k == 'op-sem' && n == 2 })
    ok &&= of.call('m4', sem, 'transition of an unknown id must be false', ->(o, k, n, _a) { [nil] if o == :transition && k == 'nope' && n == 1 })
    ok &&= of.call('m4b', sem, 'transition of an unknown id must be false', ->(o, k, n, _a) { [true] if o == :transition && k == 'nope' && n == 1 })
    ok &&= of.call('m5', sem, 'transition from the wrong state must be false', ->(o, k, n, _a) { [true] if o == :transition && k == 'op-sem' && n == 1 })
    ok &&= of.call('m5b', sem, 'transition from the wrong state must be false', ->(o, k, n, _a) { [nil] if o == :transition && k == 'op-sem' && n == 1 })
    ok &&= of.call('m6', sem, 'a refused transition changed the record', ->(o, k, n, _a) { [{ 'state' => 'executing' }] if o == :get && k == 'op-sem' && n == 2 })
    ok &&= of.call('m7', sem, 'the transition from the current state must succeed', ->(o, k, n, _a) { [false] if o == :transition && k == 'op-sem' && n == 2 })
    ok &&= of.call('m7b', sem, 'the transition from the current state must succeed', ->(o, k, n, _a) { [1] if o == :transition && k == 'op-sem' && n == 2 })
    note8 = 'the transition did not store the new record'
    ok &&= of.call('m8a', sem, note8, ->(o, k, n, _a) { [{ 'state' => 'pending', 'executingAt' => 2 }] if o == :get && k == 'op-sem' && n == 3 })
    ok &&= of.call('m8b', sem, note8, ->(o, k, n, _a) { [{ 'state' => 'executing', 'executingAt' => 9 }] if o == :get && k == 'op-sem' && n == 4 })
    ok &&= of.call('m8c', sem, note8, ->(o, k, n, _a) { [{ 'state' => 'executing', 'executingAt' => 2, 'x' => 1 }.merge('state' => 'aborted')] if o == :get && k == 'op-sem' && n == 3 })
    ok &&= of.call('m9', sem, 'the old state must no longer match', ->(o, k, n, _a) { [true] if o == :transition && k == 'op-sem' && n == 3 })
    ok &&= of.call('m9b', sem, 'the old state must no longer match', ->(o, k, n, _a) { [nil] if o == :transition && k == 'op-sem' && n == 3 })
    ok &&= of.call('copy1', 'copies', 'get must return a copy, not the stored record', nil, make: -> { Class.new(AtlasPca::MemoryOperationStore) { def get(id) = @m[id] }.new })
    nocopy = lambda do
      Class.new(AtlasPca::MemoryOperationStore) do
        def create(record)
          cur = @m[record['id']]
          return cur.dup unless cur.nil?

          @m[record['id']] = record
          nil
        end
      end.new
    end
    ok &&= of.call('copy2', 'copies', 'create must store a copy of the record it was given', nil, make: nocopy)
    idof = ->(a) { C20.opids(a) }
    ok &&= of.call('cr1', 'create-race', "round 1: 3 of 3 concurrent creates reported 'created' (want exactly 1)",
                   ->(o, k, _n, a) { [nil] if o == :create && k == 'op-create' && idof.call(a).end_with?(':1') })
    ok &&= of.call('cr2', 'create-race', "round 0: 0 of 3 concurrent creates reported 'created' (want exactly 1)",
                   ->(o, k, _n, a) { [{ 'id' => 'x' }] if o == :create && k == 'op-create' && idof.call(a).end_with?(':0') })
    ok &&= of.call('cr3', 'create-race', '1 of 3 concurrent calls raised: #<RuntimeError: boom>', ->(o, k, n, _a) { raise 'boom' if o == :create && k == 'op-create' && n == 1 })
    ok &&= of.call('tr1', 'transition-race', 'round 1: 3 of 3 concurrent pending->executing transitions succeeded (want exactly 1)',
                   ->(o, k, _n, a) { [true] if o == :transition && k == 'op-cas' && idof.call(a).end_with?(':1') })
    ok &&= of.call('tr2', 'transition-race', 'round 0: 0 of 3 concurrent pending->executing transitions succeeded (want exactly 1)',
                   ->(o, k, _n, a) { [1] if o == :transition && k == 'op-cas' && idof.call(a).end_with?(':0') })
    ok &&= of.call('tr3', 'transition-race', '1 of 3 concurrent calls raised: #<RuntimeError: boom>', ->(o, k, n, _a) { raise 'boom' if o == :transition && k == 'op-cas' && n == 1 })
    cn = "creates over 2 handles: not exactly one 'created'"
    ok &&= of.call('h1', 'cross-handle', cn, ->(o, k, _n, _a) { [nil] if o == :create && k == 'op-shared' })
    ok &&= of.call('h2', 'cross-handle', cn, ->(o, k, _n, _a) { [{ 'id' => 'x' }] if o == :create && k == 'op-shared' })
    tn = 'transitions over 2 handles: not exactly one success'
    ok &&= of.call('h3', 'cross-handle', tn, ->(o, k, _n, _a) { [true] if o == :transition && k == 'op-shared' })
    ok &&= of.call('h4', 'cross-handle', tn, ->(o, k, _n, _a) { [false] if o == :transition && k == 'op-shared' })
    ok &&= of.call('h5', 'cross-handle', tn, ->(o, k, _n, _a) { [1] if o == :transition && k == 'op-shared' })
    ok &&= of.call('h6', 'cross-handle', '1 of 3 concurrent calls raised: #<RuntimeError: boom>', ->(o, k, n, _a) { raise 'boom' if o == :create && k == 'op-shared' && n == 1 })
    ok &&= of.call('h7', 'cross-handle', '1 of 3 concurrent calls raised: #<RuntimeError: boom>', ->(o, k, n, _a) { raise 'boom' if o == :transition && k == 'op-shared' && n == 1 })
    dn = 'the record did not survive closing every handle'
    ok &&= of.call('u1', 'durability', dn, nil, isolated: true)
    ok &&= of.call('u2', 'durability', dn, ->(o, k, _n, _a) { [nil] if o == :get && k == 'op-dur' })
    ok &&= of.call('u3', 'durability', dn, ->(o, k, _n, _a) { [{ 'state' => 'pending', 'executingAt' => 3 }] if o == :get && k == 'op-dur' })
    ok &&= of.call('u4', 'durability', dn, ->(o, k, _n, _a) { [{ 'state' => 'executing', 'executingAt' => 4 }] if o == :get && k == 'op-dur' })
    ok && of.call('u5', 'durability', dn, ->(o, k, _n, _a) { [{ 'state' => 'executing' }] if o == :get && k == 'op-dur' })
  end

  t('c20 run_operation_store_conformance: a store missing a method fails every test naming the first missing one; close errors are survived') do
    next true if C20.skip?('store_conformance.rb')
    names = %w[semantics copies create-race transition-race cross-handle durability]
    mk = lambda do |*have|
      Class.new do
        have.each { |m| define_method(m) { |*_a| nil } }
      end
    end
    ok = true
    [[%i[get transition], 'create'], [%i[create transition], 'get'], [%i[create get], 'transition'], [%i[create], 'get']].each do |have, miss|
      cls = mk.call(*have)
      rep = C20.within(3) { AtlasPca.run_operation_store_conformance(-> { cls.new }) }
      ok &&= C20.ck("missing #{miss}", C20.res(rep), names.map { |n| [n, 'fail', "the store has no #{miss}()"] })
    end
    torn = []
    rep = C20.within(3) { AtlasPca.run_operation_store_conformance(-> { Object.new }, teardown: -> { torn << 1 }) }
    ok &&= C20.ck('teardown after failures', [torn, rep.ok?], [[1], false])
    env = C20::OpEnv.new(close_raises: true)
    rep2 = C20.run_o(env, teardown: -> { env.events << :teardown })
    d = rep2.results.find { |r| r.test == 'durability' }
    ok && C20.ck('durability close error', [d.status, d.note], ['fail', 'RuntimeError: close boom']) && C20.ck('teardown last', env.events.last, :teardown) &&
      C20.ck('ensure closed', env.events.count { |e| e == [:close, 0] }, 2)
  end

  t('c20 race: the gate is pushed true once per thread and popped once per thread') do
    next true if C20.skip?('store_conformance.rb')
    sc = C20.sc
    C20::SpyQ.log = []
    sc.const_set(:Queue, C20::SpyQ)
    begin
      got = C20.within(3) { sc.race(3) { |i| i + 10 } }
    ensure
      sc.send(:remove_const, :Queue)
    end
    log = C20::SpyQ.log
    C20.ck('result', got, [10, 11, 12]) && C20.ck('log', [log.count([:push, true]), log.count([:pop]), log.length], [3, 3, 6])
  end

  t('c20 Skip / Failure / unexpected errors: the note is e.message, not to_s') do
    next true if C20.skip?('store_conformance.rb')
    sc = C20.sc
    sr = AtlasPca::StoreTestResult
    rep = AtlasPca::ConformanceReport.new('x')
    sk = Class.new(sc::Skip) { def message = 'M'; def to_s = 'T' }
    fl = Class.new(sc::Failure) { def message = 'M'; def to_s = 'T' }
    sc.run_test(rep, 's') { raise sk }
    sc.run_test(rep, 'f') { raise fl }
    sc.run_test(rep, 'e') { raise C20::OddErr }
    C20.ck('notes', rep.results, [sr.new(test: 's', status: 'skip', note: 'M'), sr.new(test: 'f', status: 'fail', note: 'M'),
                                  sr.new(test: 'e', status: 'fail', note: 'MutationKill::C20::OddErr: M')])
  end

  t('c20 run_state_store_conformance: the refused-claim note uses inspect') do
    next true if C20.skip?('store_conformance.rb')
    C20.state_fail('odd', 'claim-sequence', 'a refused claim must report last_counter=1, got INS', ->(k, c, n) { C20::OddResult.new if k == 'seq' && c == 1 && n == 2 })
  end

  t('c20 retry-after-timeout: the in-flight claim only starts after the retry returned') do
    next true if C20.skip?('store_conformance.rb')
    ord = []
    mx = Mutex.new
    rule = lambda do |k, c, n|
      next nil unless k == 'retry' && c == 3

      mx.synchronize { ord << [:in, n] }
      sleep 0.05 if n == 1
      mx.synchronize { ord << [:out, n] }
      nil
    end
    rep = C20.run_s(C20::Env.new(rule: rule), durable: false)
    C20.ck('retry passes', rep.results.find { |r| r.test == 'retry-after-timeout' }.status, 'pass') &&
      C20.ck('order', ord, [[:in, 1], [:out, 1], [:in, 2], [:out, 2]])
  end

  t('c20 copies check: the test really mutates the record it got and the record it gave') do
    next true if C20.skip?('store_conformance.rb')
    gotrec = C20.rec('g')
    mine = nil
    rule = lambda do |o, k, n, a|
      if o == :get && k == 'op-copy' && n == 1
        [gotrec]
      elsif o == :create && k == 'op-copy' && n == 2
        mine = a[0]
        nil
      end
    end
    rep = C20.run_o(C20::OpEnv.new(rule: rule))
    C20.ck('copies pass', rep.results.find { |r| r.test == 'copies' }.status, 'pass') &&
      C20.ck('mutated', [gotrec['state'], mine['state']], %w[committed failed])
  end

  # ======================================================================================================================
  # atomic_kv.rb
  # ======================================================================================================================

  t('c20 MemoryAtomicKv: copies on the way in and out, nil handling, update contract') do
    next true if C20.skip?('atomic_kv.rb')
    mk = AtlasPca::MemoryAtomicKv
    kv = mk.new
    ok = C20.ck('missing', kv.get('a'), nil) && C20.ck('missing nil?', kv.get('a').nil?, true)
    src = { 'a' => [1, { 'b' => 'x' }] }
    ok &&= C20.ck('set returns nil', kv.set('a', src).nil?, true)
    src['a'] << 2
    g = kv.get('a')
    ok &&= C20.ck('stored a copy', g, { 'a' => [1, { 'b' => 'x' }] }) && C20.ck('get distinct', g.equal?(kv.get('a')), false)
    g['a'][1]['b'] = 'y'
    ok &&= C20.ck('get is a copy', kv.get('a'), { 'a' => [1, { 'b' => 'x' }] })
    orig = { 'a' => [1, { 'b' => 'x' }] }
    seen = nil
    r = kv.update('a') { |prev| seen = Marshal.load(Marshal.dump(prev)); prev['a'] << 9; nil }
    ok &&= C20.ck('prev', seen, orig) && C20.ck('nil leaves unchanged', kv.get('a'), orig) && C20.ck('nil returns current', r, orig)
    r['a'] << 1
    ok &&= C20.ck('returned copy', kv.get('a'), orig)
    nxt = { 'n' => [1] }
    got_prev = :unset
    r2 = kv.update('b') { |p| got_prev = p; nxt }
    ok &&= C20.ck('prev nil', got_prev.nil?, true) && C20.ck('update returns value', r2, { 'n' => [1] }) && C20.ck('update return is a copy', r2.equal?(nxt), false)
    nxt['n'] << 2
    ok &&= C20.ck('stored copy of next', kv.get('b'), { 'n' => [1] })
    r2['n'] << 5
    ok &&= C20.ck('returned copy 2', kv.get('b'), { 'n' => [1] })
    miss = kv.update('zz') { nil }
    ok &&= C20.ck('missing nil update', [miss.nil?, kv.get('zz').nil?], [true, true])
    ok &&= C20.ck('copy nil', [mk.copy(nil).nil?, mk.copy(false), mk.copy(0)], [true, false, 0])
    deep = { 'a' => [1, 'z'] }
    cp = mk.copy(deep)
    ok && C20.ck('deep copy', [cp, cp.equal?(deep), cp['a'].equal?(deep['a']), cp['a'][1].equal?(deep['a'][1])], [deep, false, false, false])
  end

  t('c20 MemoryAtomicKv: get, set and update each hold the lock; concurrent updates never lose one') do
    next true if C20.skip?('atomic_kv.rb')
    kv = AtlasPca::MemoryAtomicKv.new
    held = ->(&blk) { begin; kv.update('l') { blk.call; nil }; false; rescue ThreadError; true; end }
    ok = C20.ck('get', held.call { kv.get('l') }, true) && C20.ck('set', held.call { kv.set('l', 1) }, true) && C20.ck('update', held.call { kv.update('l') { 1 } }, true)
    kv.set('n', 0)
    Array.new(4) { Thread.new { 5.times { kv.update('n') { |p| sleep(0.0005); p + 1 } } } }.each(&:join)
    ok && C20.ck('no lost update', kv.get('n'), 20)
  end

  t('c20 SqliteAtomicKv: construction') do
    next true if C20.skip?('atomic_kv.rb')
    C20.with_fake_db do
      kv, reqs, = C20.mk('/k.db')
      db = C20::Db.made[0]
      key = :"atlas_pca_kv_#{kv.object_id}"
      ok = C20.ck('table', AtlasPca::SqliteAtomicKv::TABLE, 'pca_kv') && C20.ck('require', reqs, ['sqlite3']) && C20.ck('one conn', C20::Db.made.length, 1) &&
           C20.ck('path', db.path, '/k.db') && C20.ck('ddl', db.log, [[C20::DDL, nil]]) && C20.ck('default timeout', kv.instance_variable_get(:@timeout_ms), 30_000) &&
           C20.ck('conn key', kv.instance_variable_get(:@conn_key), key) && C20.ck('conns', kv.instance_variable_get(:@conns), [[Process.pid, db]]) &&
           C20.ck('mutex', kv.instance_variable_get(:@conns_mutex).class, Mutex) && C20.ck('thread slot', Thread.current[key], [Process.pid, db])
      kv2, = C20.mk('/k2.db', timeout: 1.2345)
      ok && C20.ck('timeout ms', kv2.instance_variable_get(:@timeout_ms), 1234) && C20.ck('second path', C20::Db.made[1].path, '/k2.db')
    end
  end

  t('c20 SqliteAtomicKv: get reads through one reused connection and parses the JSON') do
    next true if C20.skip?('atomic_kv.rb')
    C20.with_fake_db do
      kv, = C20.mk
      db = C20::Db.made[0]
      C20::Db.files['/k.db']['k'] = '{"a":[1,2]}'
      ok = C20.ck('found', kv.get('k'), { 'a' => [1, 2] }) && C20.ck('missing', kv.get('nope').nil?, true)
      ok && C20.ck('log', db.log, [[C20::DDL, nil], [C20::SEL, ['k']], [C20::SEL, ['nope']]]) && C20.ck('reused', C20::Db.made.length, 1)
    end
  end

  t('c20 SqliteAtomicKv: update is one BEGIN IMMEDIATE .. COMMIT step with the exact statements and return values') do
    next true if C20.skip?('atomic_kv.rb')
    C20.with_fake_db do
      kv, = C20.mk
      db = C20::Db.made[0]
      seen = []
      nxt = { 'n' => 1 }
      r = kv.update('k') { |p| seen << p; nxt }
      ok = C20.ck('first prev', seen, [nil]) && C20.ck('returns next itself', r.equal?(nxt), true)
      ok &&= C20.ck('log', db.log.drop(1), [['BEGIN IMMEDIATE', nil], [C20::SEL, ['k']], [C20::INS, ['k', '{"n":1}']], ['COMMIT', nil]])
      db.log.clear
      r2 = kv.update('k') { |p| seen << p; nil }
      ok &&= C20.ck('second prev', seen[1], { 'n' => 1 }) && C20.ck('nil returns prev', r2, { 'n' => 1 })
      ok &&= C20.ck('no write', db.log, [['BEGIN IMMEDIATE', nil], [C20::SEL, ['k']], ['COMMIT', nil]])
      db.log.clear
      r3 = kv.update('absent') { nil }
      ok &&= C20.ck('absent nil', r3.nil?, true) && C20.ck('absent log', db.log, [['BEGIN IMMEDIATE', nil], [C20::SEL, ['absent']], ['COMMIT', nil]])
      ok && C20.ck('one connection', C20::Db.made.length, 1)
    end
  end

  t('c20 SqliteAtomicKv: set writes JSON, returns nil, leaves nil values alone') do
    next true if C20.skip?('atomic_kv.rb')
    C20.with_fake_db do
      kv, = C20.mk
      db = C20::Db.made[0]
      db.log.clear
      ok = C20.ck('set returns nil', kv.set('k', [1, 'a']).nil?, true)
      ok &&= C20.ck('set log', db.log, [['BEGIN IMMEDIATE', nil], [C20::SEL, ['k']], [C20::INS, ['k', '[1,"a"]']], ['COMMIT', nil]])
      ok &&= C20.ck('roundtrip', kv.get('k'), [1, 'a'])
      kv.set('k', nil)
      ok && C20.ck('nil value is no write', kv.get('k'), [1, 'a'])
    end
  end

  t('c20 SqliteAtomicKv: a failing block or commit rolls back and re-raises the original error') do
    next true if C20.skip?('atomic_kv.rb')
    C20.with_fake_db do
      kv, = C20.mk
      db = C20::Db.made[0]
      kv.set('k', 1)
      db.log.clear
      err = ArgumentError.new('mine')
      raised = begin
        kv.update('k') { raise err }
        nil
      rescue ArgumentError => e
        e
      end
      ok = C20.ck('same error', raised.equal?(err), true) && C20.ck('rollback log', db.log, [['BEGIN IMMEDIATE', nil], [C20::SEL, ['k']], ['ROLLBACK', nil]])
      db.log.clear
      big = Class.new(Exception) # rubocop:disable Lint/InheritException
      raised = begin
        kv.update('k') { raise big, 'bad' }
        nil
      rescue big => e
        e
      end
      ok &&= C20.ck('Exception rolled back too', [raised.class == big, db.log.last], [true, ['ROLLBACK', nil]])
      db.log.clear
      C20::Db.raise_on = ->(sql, _b) { RuntimeError.new('rollback failed') if sql == 'ROLLBACK' }
      raised = begin
        kv.update('k') { raise err }
        nil
      rescue StandardError => e
        e
      end
      ok &&= C20.ck('rollback failure swallowed', [raised.equal?(err), db.log.last], [true, ['ROLLBACK', nil]])
      C20::Db.raise_on = ->(sql, _b) { IOError.new('commit failed') if sql == 'COMMIT' }
      db.log.clear
      raised = begin
        kv.update('k') { 2 }
        nil
      rescue IOError => e
        e.message
      end
      C20::Db.raise_on = nil
      ok && C20.ck('commit failure', [raised, db.log.map(&:first).last(2), kv.get('k')], ['commit failed', %w[COMMIT ROLLBACK], 1])
    end
  end

  t('c20 SqliteAtomicKv: one connection per thread, reopened when closed or after a fork, all registered') do
    next true if C20.skip?('atomic_kv.rb')
    C20.with_fake_db do
      kv, = C20.mk
      key = kv.instance_variable_get(:@conn_key)
      db0 = C20::Db.made[0]
      kv.get('a')
      ok = C20.ck('reuse', C20::Db.made.length, 1)
      other = nil
      Thread.new { kv.get('a'); other = Thread.current[key] }.join
      ok &&= C20.ck('thread conn', [C20::Db.made.length, other[1].equal?(C20::Db.made[1]), other[0]], [2, true, Process.pid])
      ok &&= C20.ck('main unchanged', Thread.current[key], [Process.pid, db0])
      ok &&= C20.ck('registered', kv.instance_variable_get(:@conns), [[Process.pid, db0], [Process.pid, C20::Db.made[1]]])
      db0.close
      kv.get('a')
      ok &&= C20.ck('closed reopens', [C20::Db.made.length, Thread.current[key][1].equal?(C20::Db.made[2])], [3, true])
      Thread.current[key] = [Process.pid + 1, C20::Db.made[2]]
      kv.get('a')
      ok &&= C20.ck('pid change reopens', [C20::Db.made.length, Thread.current[key], Thread.current[key][1].equal?(C20::Db.made[3])], [4, [Process.pid, C20::Db.made[3]], true])
      ok && C20.ck('handler on every connection', C20::Db.made.map { |d| d.handler.nil? }, [false, false, false, false])
    end
  end

  t('c20 SqliteAtomicKv: the busy handler sleeps 2 ms and gives up exactly at the timeout, restarting per wait') do
    next true if C20.skip?('atomic_kv.rb')
    C20.with_fake_db do
      kv, _reqs, slept = C20.mk('/k.db', timeout: 30)
      h = C20::Db.made[0].handler
      got = C20.with_clock([100, 129.999, 130.0, 500, 500.5, 531.0]) { [h.call(0), h.call(1), h.call(2), h.call(0), h.call(1), h.call(2)] }
      ok = C20.ck('30s window', got, [true, true, false, true, true, false]) && C20.ck('sleeps', slept, [0.002] * 6)
      kv2, _r2, slept2 = C20.mk('/k2.db', timeout: 0.5)
      h2 = C20::Db.made[1].handler
      got2 = C20.with_clock([10, 10.4999, 10.5, 10.6]) { [h2.call(0), h2.call(1), h2.call(2), h2.call(3)] }
      kv3, = C20.mk('/k3.db')
      h3 = C20::Db.made[2].handler
      msg = C20.with_clock([5.0]) { begin; h3.call(1); nil; rescue TypeError => e; e.message; end }
      ok &&= C20.ck('first call with count 1 has no start time', msg, "nil can't be coerced into Float") && C20.ck('kv3', kv3.nil?, false)
      ok && C20.ck('0.5s window', got2, [true, true, false, false]) && C20.ck('sleeps 2', slept2, [0.002] * 4) && C20.ck('kv', [kv.nil?, kv2.nil?], [false, false])
    end
  end

  t('c20 SqliteAtomicKv: connection registry is touched under its mutex') do
    next true if C20.skip?('atomic_kv.rb')
    C20.with_fake_db do
      kv, = C20.mk
      key = kv.instance_variable_get(:@conn_key)
      obs = C20::Obs.new(kv.instance_variable_get(:@conns_mutex))
      kv.instance_variable_set(:@conns, obs)
      Thread.current[key] = nil
      kv.get('a')
      kv.close
      C20.ck('owned', obs.owned, [[:push, true], [:shift, true]])
    end
  end

  t('c20 SqliteAtomicKv: close releases every thread connection, skips foreign / closed handles, survives errors, returns nil') do
    next true if C20.skip?('atomic_kv.rb')
    C20.with_fake_db do
      kv, = C20.mk
      key = kv.instance_variable_get(:@conn_key)
      db0 = C20::Db.made[0]
      Thread.new { kv.get('a') }.join
      db1 = C20::Db.made[1]
      foreign = C20::Db.new('/foreign.db')
      kv.instance_variable_get(:@conns) << [Process.pid + 1, foreign]
      pre_closed = C20::Db.new('/pre.db')
      pre_closed.close
      kv.instance_variable_get(:@conns) << [Process.pid, pre_closed]
      bad = C20::Db.new('/bad.db')
      bad.raise_on_close = true
      kv.instance_variable_get(:@conns) << [Process.pid, bad]
      last = C20::Db.new('/last.db')
      kv.instance_variable_get(:@conns) << [Process.pid, last]
      r = kv.close
      ok = C20.ck('returns nil', r.nil?, true) && C20.ck('main + thread closed', [db0.close_count, db0.closed?, db1.close_count, db1.closed?], [1, true, 1, true])
      ok &&= C20.ck('foreign untouched', [foreign.close_count, foreign.closed?], [0, false]) && C20.ck('closed not closed again', pre_closed.close_count, 1)
      ok &&= C20.ck('error swallowed, next closed', [bad.close_count, last.close_count, last.closed?], [1, 1, true])
      ok &&= C20.ck('registry emptied', kv.instance_variable_get(:@conns), []) && C20.ck('slot cleared', Thread.current[key], nil)
      before = C20::Db.made.length
      kv.get('a')
      ok &&= C20.ck('lazily reopened', [C20::Db.made.length, Thread.current[key][1].closed?], [before + 1, false])
      kv.close
      ok && C20.ck('close again', [kv.close, kv.instance_variable_get(:@conns)], [nil, []])
    end
  end
end
