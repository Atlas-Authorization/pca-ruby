# frozen_string_literal: true

# c06: mutation-kill tests for lib/atlas_pca/authorize.rb (part 1: stores, result structs, envelope, tool_schema, helpers).
# Everything resolves AtlasPca at CALL time (the oracle re-evaluates AtlasPca per mutant). Only plain data is memoised.
require 'set'
require 'timeout'
require 'json'

module MutationKill
  module C06
    NOW = 1_792_929_600_000

    # A stand-in for SQLite3::Database (installed over the constant only inside with_fake_sqlite).
    class FakeDB
      class << self
        attr_accessor :made, :changes_next, :row_next
      end
      attr_reader :path, :log, :timeout, :close_count
      attr_accessor :raise_on_close

      def initialize(path)
        @path = path
        @log = []
        @closed = false
        @close_count = 0
        FakeDB.made << self
      end

      def busy_timeout=(v)
        @timeout = v
      end

      def execute(sql, binds = nil)
        @log << [sql, binds]
        []
      end

      def changes = FakeDB.changes_next

      def get_first_row(sql, binds)
        @log << [sql, binds]
        FakeDB.row_next
      end

      def closed? = @closed

      def close
        @close_count += 1
        raise 'boom' if @raise_on_close

        @closed = true
      end
    end

    module_function

    # Raises with the values (a StandardError is a kill; the message helps the CI log) unless got == want.
    def ck(label, got, want)
      got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    end

    def raises(klass, msg = nil)
      yield
      false
    rescue klass => e
      msg.nil? || e.message == msg
    end

    def fx
      @fx ||= AtlasPca.parse_json(File.read(File.expand_path('../../test-data/authorize-fixtures.json', __dir__), encoding: 'UTF-8'), loose: true)
    end

    # read-only like test_authorize.rb's constants: authorize never mutates the proof or the grant (a Marshal copy broke the strict wire profile)
    def kase(name) = fx['cases'].find { |c| c['name'] == name }
    def base = kase('envelope-max-spend-within')
    def aud = fx['audience']

    def wtf(*units)
      units.map { |c| [0xE0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)].pack('C*') }.join.force_encoding('UTF-8')
    end

    def with_fake_sqlite
      had = Object.const_defined?(:SQLite3)
      old = Object.const_get(:SQLite3) if had
      Object.send(:remove_const, :SQLite3) if had
      mod = Module.new
      mod.const_set(:Database, FakeDB)
      Object.const_set(:SQLite3, mod)
      FakeDB.made = []
      FakeDB.changes_next = 0
      FakeDB.row_next = nil
      yield
    ensure
      Object.send(:remove_const, :SQLite3) if Object.const_defined?(:SQLite3)
      Object.const_set(:SQLite3, old) if had
    end

    def mk_sqlite(path = '/p.db', **kw)
      st = AtlasPca::SqliteStateStore.allocate
      reqs = []
      st.define_singleton_method(:require) { |n| reqs << n; true }
      st.send(:initialize, path, **kw)
      [st, reqs]
    end

    def sql_store(placeholders: :question, table: nil, rets: [], sel: nil)
      log = []
      kw = { execute: ->(sql, b) { log << [sql, b]; rets.shift || 0 }, select: ->(sql, b) { log << [sql, b]; sel }, placeholders: placeholders }
      kw[:table] = table unless table.nil?
      [AtlasPca::SqlStateStore.new(**kw), log]
    end
  end

  t('c06 ClaimResult, AuthorizeResult and AuthorizeOptions basics') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    a = AtlasPca::ClaimResult.new(true)
    b = AtlasPca::ClaimResult.new(false, 5)
    r0 = AtlasPca::AuthorizeResult.new(allow: true)
    r1 = AtlasPca::AuthorizeResult.new(allow: false, checks: { 'b' => 'fail', 'a' => 'fail', 'c' => 'pass' })
    o = AtlasPca::AuthorizeOptions
    with_last = Class.new { def last(_k) = nil }.new
    msg = begin
      o.new(escalation_principals: ['k'], state_store: Object.new)
      nil
    rescue ArgumentError => e
      e.message
    end
    ok1 = o.new(escalation_principals: [], state_store: nil)
    o.new(escalation_principals: nil, state_store: Object.new)
    ok3 = o.new(escalation_principals: ['k'], state_store: with_last)
    C06.ck('claim', [a.ok, a.last_counter, b.ok, b.last_counter], [true, nil, false, 5]) &&
      C06.ck('result', [r0.failed_checks, r1.failed_checks, r0.decision, r1.decision], [[], %w[a b], 'allow', 'deny']) &&
      C06.ck('opts msg', msg, 'escalation_principals: the state store must offer last(key) (the history head an answer is bound to)') &&
      C06.ck('opts', [ok1.plan, ok1.require, ok3.escalation_principals], [nil, [], ['k']])
  end

  t('c06 StateStore#consume_once default: validates, claims (key, 1), reads the result') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    sub = Class.new(AtlasPca::StateStore) do
      attr_accessor :ret
      attr_reader :calls

      def claim(key, counter)
        (@calls ||= []) << [key, counter]
        @ret
      end
    end
    s = sub.new
    s.ret = AtlasPca::ClaimResult.new(true)
    r1 = s.consume_once('k', 10, 5)
    c1 = s.calls.dup
    outs = [[AtlasPca::ClaimResult.new(false), false], [true, true], [false, false], [1, false], [nil, false], [AtlasPca::ClaimResult.new(true, 3), true]].map do |ret, _w|
      s.ret = ret
      s.consume_once('k', 10, 5)
    end
    s2 = sub.new
    s2.ret = true
    errs = [
      C06.raises(ArgumentError, 'consume_once: key must be a non-empty string') { s2.consume_once('', 10, 5) },
      C06.raises(ArgumentError, 'consume_once: key must be a non-empty string') { s2.consume_once(:k, 10, 5) },
      C06.raises(ArgumentError, 'consume_once: retain_until and now must be integers') { s2.consume_once('k', 10.0, 5) },
      C06.raises(ArgumentError, 'consume_once: retain_until and now must be integers') { s2.consume_once('k', 10, '5') },
      C06.raises(ArgumentError, 'consume_once: retain_until is before now') { s2.consume_once('k', 4, 5) }
    ]
    C06.ck('first', [r1, c1], [true, [['k', 1]]]) && C06.ck('outs', outs, [false, true, false, false, false, true]) &&
      C06.ck('errs', errs, [true] * 5) && C06.ck('no claim on refusal', s2.calls, nil) && s2.consume_once('k', 5, 5) == true
  end

  t('c06 MemoryStateStore: claim, last and consume_once expiry') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    m = AtlasPca::MemoryStateStore.new
    c1 = m.claim('k', 1)
    c2 = m.claim('k', 1)
    c3 = m.claim('k', 2)
    c4 = m.claim('k', 0)
    o = AtlasPca::MemoryStateStore.new
    seq = [o.consume_once('k', 100, 50), o.consume_once('k', 200, 60), o.consume_once('k', 300, 150), o.consume_once('k', 400, 301)]
    C06.ck('claims', [c1.ok, c1.last_counter, c2.ok, c2.last_counter, c3.ok, c4.ok, c4.last_counter, m.last('k'), m.last('z')],
         [true, nil, false, 1, true, false, 2, 2, nil]) && C06.ck('once', seq, [true, false, false, true]) &&
      C06.raises(ArgumentError) { o.consume_once('', 1, 1) } && C06.raises(ArgumentError) { o.consume_once('k', 1, 2) }
  end

  t('c06 SqlStateStore: identifier and placeholder validation, claim guards, last') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    mk = ->(**kw) { AtlasPca::SqlStateStore.new(execute: ->(*) { 0 }, select: ->(*) { nil }, **kw) }
    id_msg = 'table must be a plain identifier'
    bad = [:abc, 5, 'a-b', '', '1a', 'a' * 64].map { |t| C06.raises(ArgumentError, id_msg) { mk.call(table: t) } }
    good = [mk.call(table: 'a' * 63).table == 'a' * 63, mk.call.table == 'pca_replay', mk.call(table: '_x9').table == '_x9']
    ph = C06.raises(ArgumentError, 'placeholders must be :question or :dollar') { mk.call(placeholders: :bogus) }
    d = mk.call(placeholders: :dollar)
    q = mk.call
    calls = []
    st = AtlasPca::SqlStateStore.new(execute: ->(s, b) { calls << [s, b]; 1 }, select: ->(s, b) { calls << [s, b]; 7 })
    r_key = st.claim(:k, 1)
    r_cnt = st.claim('k', '1')
    r_cnt2 = st.claim('k', 1.0)
    C06.ck('bad', bad, [true] * 6) && C06.ck('good', good, [true] * 3) && ph && d.claim_sql.include?('VALUES ($1, $2)') && q.claim_sql.include?('VALUES (?, ?)') &&
      C06.ck('guard', [r_key.class, r_key.ok, r_key.last_counter, r_cnt.ok, r_cnt.last_counter, r_cnt2.ok, calls], [AtlasPca::ClaimResult, false, nil, false, nil, false, []]) &&
      C06.ck('ddl', q.create_table_sql, 'CREATE TABLE IF NOT EXISTS pca_replay (key TEXT NOT NULL PRIMARY KEY, last_counter BIGINT NOT NULL)') &&
      C06.ck('ddl2', q.create_once_table_sql, 'CREATE TABLE IF NOT EXISTS pca_replay_once (key TEXT NOT NULL PRIMARY KEY, retain_until BIGINT NOT NULL)')
  end

  t('c06 SqlStateStore#claim and #last read the changed-row count and the stored counter exactly') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    st, log = C06.sql_store(rets: [1, 0, 0], sel: 9)
    won = st.claim('k', 3)
    lost = st.claim('k', 3)
    st2, = C06.sql_store(sel: 'x')
    st3, = C06.sql_store(sel: nil)
    st4, = C06.sql_store(sel: 4)
    lost2 = st4.claim('k', 3)
    C06.ck('won', [won.ok, won.last_counter, lost.ok, lost.last_counter, lost2.ok, lost2.last_counter], [true, nil, false, 9, false, 4]) &&
      C06.ck('log', log.first, [st.claim_sql, ['k', 3]]) && C06.ck('select log', log[2], ['SELECT last_counter FROM pca_replay WHERE key = ?', ['k']]) &&
      C06.ck('last', [st.last('k'), st2.last('k'), st3.last('k')], [9, nil, nil])
  end

  t('c06 SqlStateStore#consume_once: exact statements and binds, question and dollar placeholders') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    st, log = C06.sql_store(rets: [0, 1])
    w1 = st.consume_once('k', 100, 50)
    want1 = [['DELETE FROM pca_replay_once WHERE retain_until < ?', [50]],
             ['INSERT INTO pca_replay_once (key, retain_until) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET ' \
              'retain_until = excluded.retain_until WHERE pca_replay_once.retain_until < ?', ['k', 100, 50]]]
    st2, log2 = C06.sql_store(rets: [0, 0, 0])
    w2 = st2.consume_once('k', 100, 50)
    st3, log3 = C06.sql_store(rets: [0, 2, 0], placeholders: :dollar)
    w3 = st3.consume_once('k', 100, 50)
    st4, log4 = C06.sql_store(rets: [0, 1], placeholders: :dollar)
    w4 = st4.consume_once('k', 100, 50)
    st5, log5 = C06.sql_store(rets: [0, 0, 0], table: 'tt')
    st5.consume_once('k', 7, 3)
    st6, log6 = C06.sql_store
    refused = C06.raises(ArgumentError, 'consume_once: key must be a non-empty string') { st6.consume_once('', 1, 1) }
    C06.ck('w1', [w1, log], [true, want1]) &&
      C06.ck('w2', [w2, log2.length, log2[2]], [false, 3, ['UPDATE pca_replay_once SET retain_until = ? WHERE key = ? AND retain_until < ?', [100, 'k', 100]]]) &&
      C06.ck('dollar', [w3, log3[0], log3[1][1], log3[2]],
           [false, ['DELETE FROM pca_replay_once WHERE retain_until < $1', [50]], ['k', 100, 50],
            ['UPDATE pca_replay_once SET retain_until = $1 WHERE key = $2 AND retain_until < $1', [100, 'k']]]) &&
      C06.ck('dollar insert', log3[1][0], 'INSERT INTO pca_replay_once (key, retain_until) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET ' \
                                       'retain_until = excluded.retain_until WHERE pca_replay_once.retain_until < $3') &&
      C06.ck('won dollar', [w4, log4.length], [true, 2]) && C06.ck('table', log5[0][0], 'DELETE FROM tt_once WHERE retain_until < ?') &&
      refused && log6.empty?
  end

  t('c06 SqliteStateStore: requires the gem, opens one connection, creates both tables, executes through it') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    C06.with_fake_sqlite do
      st, reqs = C06.mk_sqlite('/p.db', timeout: 2)
      db = C06::FakeDB.made[0]
      ok = C06.ck('require', reqs, ['sqlite3']) && C06.ck('one conn', C06::FakeDB.made.length, 1) && C06.ck('path', [db.path, db.timeout], ['/p.db', 2000]) &&
           C06.ck('ddl', db.log, [[st.create_table_sql, nil], [st.create_once_table_sql, nil], [st.create_budget_table_sql, nil]]) &&
           C06.ck('conn key', st.instance_variable_get(:@conn_key), :"atlas_pca_sqlite_#{st.object_id}") &&
           C06.ck('conns', st.instance_variable_get(:@conns), [[Process.pid, db]]) &&
           C06.ck('mutex', st.instance_variable_get(:@conns_mutex).class, Mutex)
      C06::FakeDB.changes_next = 1
      won = st.claim('k', 3)
      C06::FakeDB.changes_next = 0
      C06::FakeDB.row_next = [9]
      lost = st.claim('k', 3)
      ok && C06.ck('claim', [won.ok, lost.ok, lost.last_counter, db.log[3], db.log[4]], [true, false, 9, [st.claim_sql, ['k', 3]], [st.claim_sql, ['k', 3]]]) &&
        C06.ck('reused', C06::FakeDB.made.length, 1) && C06.ck('last', [st.last('k')], [9]) &&
        C06.ck('row', (C06::FakeDB.row_next = ['x']; st.last('k')), nil) && C06.ck('nil row', (C06::FakeDB.row_next = nil; st.last('k')), nil)
    end
  end

  t('c06 SqliteStateStore: default and fractional timeouts in milliseconds') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    C06.with_fake_sqlite do
      a, = C06.mk_sqlite('/a.db')
      b, = C06.mk_sqlite('/b.db', timeout: 0.5)
      c, = C06.mk_sqlite('/c.db', timeout: 3, table: 'tt')
      C06.ck('ms', [a, b, c].map { |s| s.instance_variable_get(:@timeout_ms) }, [30_000, 500, 3000]) &&
        C06.ck('timeouts', C06::FakeDB.made.map(&:timeout), [30_000, 500, 3000]) && C06.ck('table', c.table, 'tt') && C06.ck('once', c.create_once_table_sql.include?('tt_once'), true)
    end
  end

  t('c06 SqliteStateStore: a closed or foreign-process connection is replaced; a live one is reused') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    C06.with_fake_sqlite do
      st, = C06.mk_sqlite('/p.db')
      key = st.instance_variable_get(:@conn_key)
      first = C06::FakeDB.made[0]
      st.last('k')
      reused = C06.ck('reuse', C06::FakeDB.made.length, 1)
      first.close
      st.last('k')
      reopened = C06.ck('closed', C06::FakeDB.made.length, 2) && Thread.current[key][1].equal?(C06::FakeDB.made[1]) && Thread.current[key][0] == Process.pid
      Thread.current[key] = [Process.pid + 1, C06::FakeDB.made[1]]
      st.last('k')
      reused && reopened && C06.ck('foreign pid', C06::FakeDB.made.length, 3) && Thread.current[key][1].equal?(C06::FakeDB.made[2])
    end
  end

  t('c06 SqliteStateStore#close: closes this process handles once, skips foreign and closed ones, survives a failing close') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    C06.with_fake_sqlite do
      st, = C06.mk_sqlite('/p.db')
      mine = C06::FakeDB.made[0]
      conns = st.instance_variable_get(:@conns)
      foreign = C06::FakeDB.new('f')
      already = C06::FakeDB.new('a')
      already.close
      bad = C06::FakeDB.new('b')
      bad.raise_on_close = true
      last_ok = C06::FakeDB.new('c')
      conns << [Process.pid + 1, foreign] << [Process.pid, already] << [Process.pid, bad] << [Process.pid, last_ok]
      key = st.instance_variable_get(:@conn_key)
      ret = st.close
      C06.ck('ret', ret, nil) && mine.closed? && last_ok.closed? && C06.ck('foreign', foreign.close_count, 0) && C06.ck('already', already.close_count, 1) &&
        C06.ck('bad', bad.close_count, 1) && C06.ck('emptied', st.instance_variable_get(:@conns), []) && C06.ck('slot', Thread.current[key], nil) &&
        C06.ck('again', st.close, nil)
    end
  end

  t('c06 show: UTF-16 aware JSON string with 48-unit truncation, surrogate pairs combined, lone surrogates escaped') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    s = ->(x) { Timeout.timeout(2) { AtlasPca::ToolSchema.show(x) } }
    q = '"'
    pairs = [[[0xD83D, 0xDE00], "\u{1F600}"], [[0xD800, 0xDC00], "\u{10000}"], [[0xDBFF, 0xDFFF], "\u{10FFFF}"], [[0xD801, 0xDC37], "\u{10437}"]]
    ok = pairs.all? { |u, ch| C06.ck("pair #{u}", s.call(C06.wtf(*u)), q + ch + q) }
    ok && C06.ck('real emoji', s.call("a\u{1F600}b"), "\"a\u{1F600}b\"") &&
      C06.ck('lone high', s.call(C06.wtf(0xD83D)), '"\\ud83d"') && C06.ck('lone high last', s.call('a' + C06.wtf(0xD83D)), '"a\\ud83d"') &&
      C06.ck('lone low', s.call(C06.wtf(0xDC00)), '"\\udc00"') && C06.ck('high then low-1', s.call(C06.wtf(0xD800, 0xDBFF)), '"\\ud800\\udbff"') &&
      C06.ck('high then E000', s.call(C06.wtf(0xD800, 0xE000)), "\"\\ud800\u{E000}\"") &&
      C06.ck('low then high', s.call(C06.wtf(0xDC00, 0xD800)), '"\\udc00\\ud800"') &&
      C06.ck('controls', s.call("\u0001\u001f \u007f\u2028"), "\"\\u0001\\u001f \u007f\u2028\"") &&
      C06.ck('escapes', s.call("\"\\\b\f\n\r\t"), "\"\\\"\\\\\\b\\f\\n\\r\\t\"") &&
      C06.ck('48', s.call('a' * 48), q + ('a' * 48) + q) && C06.ck('49', s.call('a' * 49), q + ('a' * 48) + "\u2026" + q) &&
      C06.ck('pairs fit', s.call("\u{1F600}" * 24), q + ("\u{1F600}" * 24) + q) && C06.ck('pairs cut', s.call("\u{1F600}" * 25), q + ("\u{1F600}" * 24) + "\u2026" + q)
  end

  t('c06 js_eq?: JavaScript === on numbers, booleans and strings') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    j = ->(a, b) { AtlasPca::ToolSchema.js_eq?(a, b) }
    str_like = Object.new
    def str_like.to_str; 'a'; end
    def str_like.==(other); other.is_a?(String); end
    all_eq = Object.new
    def all_eq.==(_other); true; end
    rows = [[1, 1.0, true], [1, 2, false], [1, '1', false], ['1', 1, false], [nil, 1, false], [1, nil, false], [1.5, 1.5, true],
            [true, true, true], [false, false, true], [true, false, false], [true, 1, false], [1, true, false], [true, 'x', false],
            ['x', true, false], [false, nil, false], [nil, false, false], ['a', 'a', true], ['a', 'b', false], [nil, nil, false],
            [nil, 'a', false], ['a', nil, false], [[1], [1], false], [{}, {}, false], ['a', str_like, false], [str_like, 'a', false],
            [all_eq, 'x', false], [Rational(1, 2), all_eq, false], [all_eq, Rational(1, 2), false], [Float::INFINITY, Float::INFINITY, false], [0.0, -0.0, true]]
    rows.each_with_index.all? { |(a, b, w), i| C06.ck("row #{i}", j.call(a, b), w) }
  end

  t('c06 neg0?, int? and non_neg_int? are strict about -0 and non-numbers') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    ts = AtlasPca::ToolSchema
    C06.ck('neg0', [0.0, -0.0, 1.5, 0, -1.0, nil, 'x', -0].map { |x| ts.neg0?(x) }, [false, true, false, false, false, false, false, false]) &&
      C06.ck('int', [3, 2.0, 1.5, -0.0, 0.0, 'x', nil, true, Float::NAN, Float::INFINITY, -4].map { |x| ts.int?(x) },
           [true, true, false, false, true, false, false, false, false, false, true]) &&
      C06.ck('nonneg', [[0, 5], [5, 5], [6, 5], [-1, 5], [-0.0, 5], [2.5, 5], ['1', 5], [nil, 5]].map { |x, m| ts.non_neg_int?(x, m) },
           [true, true, false, false, false, false, false, false])
  end

  t('c06 validate_arg_schema: depth, size and name errors with their exact text') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    ts = AtlasPca::ToolSchema
    absent = ts.opt({}, 'required')
    d = ->(depth) { ts.object_schema_error({}, absent, depth, { nodes: 0 }) }
    n = ->(nodes) { ts.object_schema_error({}, absent, 1, { nodes: nodes }) }
    long = 'a b' + ('x' * 40)
    duck = Object.new
    def duck.hash; 'string'.hash; end
    def duck.eql?(_o); true; end
    ok = C06.ck('depth', [d.call(8), d.call(9)], [nil, 'schema too deep']) && C06.ck('nodes', [n.call(255), n.call(256)], [nil, 'schema too large'])
    ok && C06.ck('nil name', AtlasPca.validate_arg_schema({ 'props' => { nil => { 'type' => 'boolean' } } }), "invalid property name ''") &&
      C06.ck('long name', AtlasPca.validate_arg_schema({ 'props' => { long => { 'type' => 'boolean' } } }), "invalid property name '#{long[0, 32]}'") &&
      C06.ck('duck type', AtlasPca.validate_arg_schema({ 'props' => { 'a' => { 'type' => duck } } }), 'a: unknown type') &&
      C06.ck('type only', AtlasPca.validate_arg_schema({ 'props' => { 'a' => 'string' } }), 'a: unknown type') &&
      C06.ck('bool', AtlasPca.validate_arg_schema({ 'props' => { 'a' => { 'type' => 'boolean', 'const' => true, 'enum' => [true, false] } } }), nil) &&
      C06.ck('bool min', AtlasPca.validate_arg_schema({ 'props' => { 'a' => { 'type' => 'boolean', 'min' => 1 } } }), 'a: unknown spec key') &&
      C06.ck('num', AtlasPca.validate_arg_schema({ 'props' => { 'a' => { 'type' => 'number', 'min' => 1, 'max' => 2 } } }), nil) &&
      C06.ck('bad min', AtlasPca.validate_arg_schema({ 'props' => { 'a' => { 'type' => 'integer', 'min' => 'x' } } }), 'a: bad min') &&
      C06.ck('bad max', AtlasPca.validate_arg_schema({ 'props' => { 'a' => { 'type' => 'integer', 'max' => 'x' } } }), 'a: bad max') &&
      C06.ck('required duck', AtlasPca.validate_arg_schema({ 'props' => { 'string' => { 'type' => 'boolean' } }, 'required' => [duck] }), 'required names an undeclared property') &&
      C06.ck('required ok', AtlasPca.validate_arg_schema({ 'props' => { 'string' => { 'type' => 'boolean' } }, 'required' => ['string'] }), nil)
  end

  t('c06 check_value: node budget and depth boundaries, unknown type, object result') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    ts = AtlasPca::ToolSchema
    bool = { 'type' => 'boolean' }
    arr = lambda do |n|
      spec = bool
      v = true
      n.times do
        spec = { 'type' => 'array', 'items' => spec }
        v = [v]
      end
      [spec, v]
    end
    obj = lambda do |n|
      spec = bool
      v = true
      n.times do
        spec = { 'type' => 'object', 'props' => { 'a' => spec } }
        v = { 'a' => v }
      end
      [spec, v]
    end
    a9 = arr.call(9)
    a10 = arr.call(10)
    o9 = obj.call(9)
    o10 = obj.call(10)
    C06.ck('nodes', [ts.check_value(bool, true, 'p', 0, { n: 9999 }), ts.check_value(bool, true, 'p', 0, { n: 10_000 }), ts.check_value(bool, true, 'p', 0, { n: 0 })],
         [nil, 'p: too many values', nil]) &&
      C06.ck('depth', [ts.check_value(bool, true, 'p', 9, { n: 0 }), ts.check_value(bool, true, 'p', 10, { n: 0 })], [nil, 'p: too deep']) &&
      C06.ck('arr9', ts.check_value(a9[0], a9[1], 'p', 0, { n: 0 }), nil) &&
      C06.ck('arr10', ts.check_value(a10[0], a10[1], 'p', 0, { n: 0 }), "p#{'[0]' * 10}: too deep") &&
      C06.ck('obj9', ts.check_value(o9[0], o9[1], 'p', 0, { n: 0 }), nil) &&
      C06.ck('obj10', ts.check_value(o10[0], o10[1], 'p', 0, { n: 0 }), "p#{'.a' * 10}: too deep") &&
      C06.ck('unknown', ts.check_value({ 'type' => 'weird' }, 1, 'p', 0, { n: 0 }), 'p: unknown type') &&
      C06.ck('counted', (b = { n: 0 }; ts.check_value(a9[0], a9[1], 'p', 0, b); b[:n]), 10) &&
      C06.ck('object nil', ts.check_object({ 'a' => bool }, nil, { 'a' => true }, 'p', 0, { n: 0 }), nil) &&
      C06.ck('object missing', ts.check_object({ 'a' => bool }, ['a'], {}, 'p', 0, { n: 0 }), "p: missing required argument 'a'") &&
      C06.ck('object extra', ts.check_object({ 'a' => bool }, nil, { 'b' => 1 }, 'p', 0, { n: 0 }), 'p: unexpected argument "b"')
  end

  t('c06 evaluate_tool_schema: exactly 10000 value nodes pass, one more is refused; fail-closed rescue text') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    cv = lambda do |schema|
      { 'type' => 'tool_schema', 'tool' => 'pay', 'signature_digest' => 'sd', 'schema' => schema, 'schema_digest' => AtlasPca.hash_canonical(schema),
        'binding_digest' => AtlasPca.hash_canonical({ 'tool' => 'pay', 'signature_digest' => 'sd', 'schema' => schema }) }
    end
    schema = { 'props' => { 'a' => { 'type' => 'array', 'maxItems' => 4096, 'items' => { 'type' => 'array', 'maxItems' => 4096, 'items' => { 'type' => 'boolean' } } } } }
    c = cv.call(schema)
    mk = ->(last) { [Array.new(4096, true), Array.new(4096, true), Array.new(last, true)] }
    ok = AtlasPca.evaluate_tool_schema(c, { 'tool' => 'pay', 'args' => { 'a' => mk.call(1804) } })
    over = AtlasPca.evaluate_tool_schema(c, { 'tool' => 'pay', 'args' => { 'a' => mk.call(1805) } })
    boom = AtlasPca.evaluate_tool_schema(c, { 'tool' => 'pay', 'args' => { 'a' => [] }, 'tool_signature' => Object.new })
    seam = Seam.with(AtlasPca, { hash_canonical: ->(*) { raise TypeError, 'seam' } }) { AtlasPca.evaluate_tool_schema(c, { 'tool' => 'pay', 'args' => {} }) }
    C06.ck('ok', ok, [true, nil]) && C06.ck('over', over, [false, 'args.a[2][1804]: too many values']) &&
      C06.ck('seam', seam, [false, 'evaluation error (fail closed)']) && C06.ck('boom class', boom[0], false)
  end

  t('c06 agent_caveat_satisfied?: shape guards, predicates guards, exact false') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    ac = ->(cv, ctx, actx = nil, tc = nil) { AtlasPca.agent_caveat_satisfied?(cv, ctx, actx, tc) }
    duck_cv = Object.new
    def duck_cv.[](k); { 'type' => 'predicates', 'allow' => [{}] }[k]; end
    duck_ctx = Object.new
    any_true = Object.new
    def any_true.any?; true; end
    any_true_h = { 'a' => 1 }
    pred = { 'type' => 'predicates', 'allow' => [{ 'verb' => 'v' }] }
    Seam.with(AtlasPca, { predicate_matches: ->(*) { true } }) do
      C06.ck('cv not hash', ac.call('x', {}), false) && C06.ck('nil cv', ac.call(nil, {}), false) && C06.ck('ctx not hash', ac.call(pred, 'x', {}), false) &&
        C06.ck('duck cv', ac.call(duck_cv, {}, {}), false) && C06.ck('duck ctx', ac.call(pred, duck_ctx, {}), false) &&
        C06.ck('action_ctx nil', ac.call(pred, {}, nil), false) && C06.ck('action_ctx str', ac.call(pred, {}, 'x'), false) &&
        C06.ck('allow str', ac.call(pred.merge('allow' => 'x'), {}, {}), false) && C06.ck('allow hash', ac.call(pred.merge('allow' => any_true_h), {}, {}), false) &&
        C06.ck('allow nil', ac.call(pred.merge('allow' => nil), {}, {}), false) && C06.ck('allow duck', ac.call(pred.merge('allow' => any_true), {}, {}), false) &&
        C06.ck('ok', ac.call(pred, {}, {}), true)
    end
  end

  t('c06 evaluate_agent_caveats: ctx guard, ctx copy, failed type names') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    cv = { 'type' => 'max_spend', 'usd' => 1 }
    ctx = { 'now' => 1, 'action' => { 'params' => { 'amount' => 5 } } }
    seen = nil
    Seam.with(AtlasPca, { evaluate_caveats: ->(_cvs, c) { seen = c; c['mutated'] = true; [true, []] } }) do
      AtlasPca.evaluate_agent_caveats([cv], ctx)
    end
    C06.ck('ctx kept', ctx.key?('mutated'), false) && seen.key?('mutated') &&
      C06.ck('nil ctx', AtlasPca.evaluate_agent_caveats([cv], nil), [false, ['<evaluation error>']]) &&
      C06.ck('str ctx', AtlasPca.evaluate_agent_caveats([cv], 'x'), [false, ['<evaluation error>']]) &&
      C06.ck('empty with bad ctx', AtlasPca.evaluate_agent_caveats([], 'x'), [true, []]) &&
      C06.ck('names', AtlasPca.evaluate_agent_caveats([{ 'type' => 5 }, 5, { 'type' => 'zz' }, { 'type' => nil }, { 'x' => 1 }], ctx),
           [false, ['<malformed>', '<malformed>', 'zz', '<malformed>', '<malformed>']]) &&
      C06.ck('not array', AtlasPca.evaluate_agent_caveats({}, ctx), [false, ['<malformed caveats>']])
  end

  t('c06 missing_authorize_components, arg_member, operation_of, json_value') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    m = ->(**kw) { AtlasPca.missing_authorize_components(**kw) }
    ful = { audience: 'a', resolve_grant: -> {}, state_store: AtlasPca::MemoryStateStore.new, is_revoked: -> {} }
    jv = ->(x) { AtlasPca.json_value(x) }
    big = jv.call(9_007_199_254_740_992.0)
    ok = jv.call(9_007_199_254_740_991.0)
    C06.ck('none', m.call, %w[audience resolve_grant state_store is_revoked]) && C06.ck('full', m.call(**ful), []) &&
      C06.ck('empty aud', m.call(**ful, audience: ''), ['audience']) && C06.ck('sym aud', m.call(**ful, audience: :a), ['audience']) &&
      C06.ck('store', m.call(**ful, state_store: Object.new), ['state_store']) && C06.ck('nil store', m.call(**ful, state_store: nil), ['state_store']) &&
      C06.ck('arg_member', [AtlasPca.arg_member({ 'a' => 1 }, 'a'), AtlasPca.arg_member({ a: 2 }, 'a'), AtlasPca.arg_member({ 'a' => 1, a: 2 }, 'a'), AtlasPca.arg_member({}, 'a')], [1, 2, 1, nil]) &&
      C06.ck('op ok', AtlasPca.operation_of({ verb: 'v', resource: 'r', params: {} }), { 'verb' => 'v', 'resource' => 'r', 'params' => {} }) &&
      C06.ck('op bad', [nil, 5, {}, { 'verb' => '', 'resource' => 'r', 'params' => {} }, { 'verb' => 'v', 'resource' => '', 'params' => {} },
                      { 'verb' => 'v', 'resource' => 'r', 'params' => [] }, { 'verb' => :v, 'resource' => 'r', 'params' => {} }].map { |o| AtlasPca.operation_of(o) },
           [nil] * 7) &&
      C06.ck('floats', [jv.call(50.0), jv.call(1.5), jv.call(-0.0), jv.call(2.0**60), jv.call(Float::INFINITY), jv.call(7)], [50, 1.5, 0, 2.0**60, Float::INFINITY, 7]) &&
      C06.ck('int class', [jv.call(50.0).class, jv.call(-0.0).class], [Integer, Integer]) && C06.ck('nan', jv.call(Float::NAN).nan?, true) &&
      C06.ck('safe edge', [ok.class, ok, big.class, big], [Integer, 9_007_199_254_740_991, Float, 9_007_199_254_740_992.0]) &&
      C06.ck('nested', jv.call({ a: [2.0, { 'b' => 3.0 }], 'c' => 1.5 }), { 'a' => [2, { 'b' => 3 }], 'c' => 1.5 }) &&
      C06.ck('array', jv.call([1.0, [2.0]]), [1, [2]])
  end

  t('c06 authorize_refuse and decisive_reason') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    r = AtlasPca.authorize_refuse(403, 'x', 'x: why')
    r2 = AtlasPca.authorize_refuse(401, 'y', 'y: no', missing: ['m'], pcactn: { 'a' => 1 })
    d = ->(c, rs) { AtlasPca.decisive_reason(c, rs) }
    C06.ck('refuse', [r.allow, r.status, r.checks, r.reasons, r.reason, r.missing, r.pcactn, r.assurance, r.decision],
         [false, 403, { 'x' => 'fail' }, ['x: why'], 'x: why', nil, nil, { 'x' => { 'outcome' => 'fail' } }, 'deny']) &&
      C06.ck('refuse2', [r2.status, r2.missing, r2.pcactn], [401, ['m'], { 'a' => 1 }]) &&
      C06.ck('op first', d.call({ 'a' => 'fail', 'operation' => 'fail' }, ['a: x', 'operation: y']), 'operation: y') &&
      C06.ck('op later', d.call({ 'a' => 'fail', 'b' => 'pass', 'operation' => 'fail' }, ['a: x', 'operation: y']), 'operation: y') &&
      C06.ck('skip pass', d.call({ 'a' => 'pass', 'b' => 'fail' }, ['a: ok', 'b: bad']), 'b: bad') &&
      C06.ck('find later', d.call({ 'x' => 'fail' }, ['other', 'x: boom']), 'x: boom') &&
      C06.ck('prefix exact', d.call({ 'x' => 'fail' }, ['xy: no', 'x: yes']), 'x: yes') &&
      C06.ck('no hit', d.call({ 'x' => 'fail' }, ['plain', 'second']), 'plain') && C06.ck('denied', d.call({ 'x' => 'fail' }, []), 'denied') &&
      C06.ck('none failing', d.call({ 'x' => 'pass' }, ['r1']), 'r1') && C06.ck('empty', d.call({}, []), 'denied')
  end

  t('c06 coerce_pcactn: Hash, absent, undecodable, JSON text, size cap') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    cp = ->(x) { AtlasPca.coerce_pcactn(x) }
    h = { 'a' => 1 }
    big = '{"a":"' + ('x' * AtlasPca::MAX_ARTIFACT_BYTES) + '"}'
    C06.ck('hash', cp.call(h), [h, nil]) && cp.call(h)[0].equal?(h) && C06.ck('nil', cp.call(nil), [nil, 'absent']) && C06.ck('int', cp.call(5), [nil, 'undecodable']) &&
      C06.ck('text', cp.call('{"a":1}'), [{ 'a' => 1 }, nil]) && C06.ck('garbage', cp.call('garbage'), [nil, 'undecodable']) &&
      C06.ck('array text', cp.call('[1]'), [nil, 'undecodable']) && C06.ck('big', cp.call(big), [nil, 'undecodable'])
  end

  t('c06 read_envelope and root_caveats: non-Array, non-Hash, duck and subclass inputs') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    env_cv = base_env = C06.base['grant']['caveats'][0]
    good = env_cv.reject { |k, _| k == 'type' }
    re = ->(g) { AtlasPca.read_envelope(g) }
    duck = Object.new
    duck.define_singleton_method(:[]) { |k| k == 'caveats' ? [env_cv] : nil }
    sub = Class.new(Hash) { def reject = raise('boom') }.new
    sub.merge!(env_cv)
    ok = C06.ck('plain', re.call({ 'caveats' => [env_cv] }), good) && C06.ck('after junk', re.call({ 'caveats' => [5, 'type', env_cv] }), good) &&
         C06.ck('first wins', re.call({ 'caveats' => [env_cv.merge('goal_commit' => 'first'), env_cv] })['goal_commit'], 'first')
    ok && C06.ck('set', re.call({ 'caveats' => Set[env_cv] }), nil) && C06.ck('duck grant', re.call(duck), nil) && C06.ck('nil', re.call(nil), nil) &&
      C06.ck('str', re.call('caveats'), nil) && C06.ck('not array', re.call({ 'caveats' => 'x' }), nil) && C06.ck('no env', re.call({ 'caveats' => [{ 'type' => 'max_spend' }] }), nil) &&
      re.call({ 'caveats' => [sub] }).equal?(nil) && C06.ck('no goal', re.call({ 'caveats' => [env_cv.merge('goal_commit' => 5)] }), nil) &&
      C06.ck('no preds', re.call({ 'caveats' => [env_cv.merge('predicates' => nil)] }), nil) &&
      C06.ck('no binding', re.call({ 'caveats' => [env_cv.merge('agent_binding' => 'x')] }), nil) &&
      C06.ck('bad risk', re.call({ 'caveats' => [env_cv.merge('risk_policy' => {})] }), nil) &&
      C06.ck('root', AtlasPca.root_caveats({ 'caveats' => [5, 'x', env_cv, env_cv] }), [5, 'x', env_cv]) &&
      C06.ck('root first only', AtlasPca.root_caveats({ 'caveats' => [env_cv, 7, env_cv] }), [7, env_cv]) &&
      C06.ck('root none', AtlasPca.root_caveats({ 'caveats' => [7] }), [7]) && C06.ck('root str', AtlasPca.root_caveats({ 'caveats' => 'x' }), 'x') &&
      C06.ck('root nil', AtlasPca.root_caveats(nil), nil) && C06.ck('root absent', AtlasPca.root_caveats({}), nil) &&
      C06.ck('root hash cs', AtlasPca.root_caveats({ 'caveats' => { 'a' => 1 } }), { 'a' => 1 }) && base_env.equal?(env_cv)
  end

  t('c06 undo_admission: validated admission or nil, symbol keys, array-of-pairs, raising hooks') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    ua = ->(h) { AtlasPca.undo_admission(h, {}, {}, {}) }
    good = { 'id' => 'u1', 'window_end' => 5, 'compensation' => { 'verb' => 'refund', 'resource' => 'r' } }
    want = { 'id' => 'u1', 'window_end' => 5, 'compensation' => { 'verb' => 'refund', 'resource' => 'r' } }
    pairs = [['id', 'u1'], ['window_end', 5], ['compensation', { 'verb' => 'refund', 'resource' => 'r' }]]
    cm = ->(c) { ->(*) { good.merge('compensation' => c) } }
    C06.ck('good', ua.call(->(*) { good }), want) &&
      C06.ck('symbols', ua.call(->(*) { { id: 'u1', window_end: 5, compensation: { verb: 'refund', resource: 'r' } } }), want) &&
      C06.ck('extra dropped', ua.call(->(*) { good.merge('x' => 1, 'compensation' => { 'verb' => 'v', 'resource' => 'r', 'y' => 2 }) }),
           { 'id' => 'u1', 'window_end' => 5, 'compensation' => { 'verb' => 'v', 'resource' => 'r' } }) &&
      C06.ck('nil', ua.call(->(*) {}), nil) && C06.ck('array pairs', ua.call(->(*) { pairs }), nil) && C06.ck('string', ua.call(->(*) { 'x' }), nil) &&
      C06.ck('no comp', ua.call(->(*) { good.reject { |k, _| k == 'compensation' } }), nil) && C06.ck('comp nil', ua.call(cm.call(nil)), nil) &&
      C06.ck('comp array', ua.call(cm.call([['verb', 'v'], ['resource', 'r']])), nil) &&
      C06.ck('verb int', ua.call(cm.call({ 'verb' => 5, 'resource' => 'r' })), nil) && C06.ck('verb empty', ua.call(cm.call({ 'verb' => '', 'resource' => 'r' })), nil) &&
      C06.ck('verb array', ua.call(cm.call({ 'verb' => ['x'], 'resource' => 'r' })), nil) && C06.ck('verb nil', ua.call(cm.call({ 'resource' => 'r' })), nil) &&
      C06.ck('resource int', ua.call(cm.call({ 'verb' => 'v', 'resource' => 5 })), nil) && C06.ck('resource nil', ua.call(cm.call({ 'verb' => 'v' })), nil) &&
      C06.ck('resource empty ok', ua.call(cm.call({ 'verb' => 'v', 'resource' => '' }))&.dig('compensation', 'resource'), '') &&
      C06.ck('bad id', ua.call(->(*) { good.merge('id' => '') }), nil) && C06.ck('bad window', ua.call(->(*) { good.merge('window_end' => -1) }), nil) &&
      C06.ck('window float', ua.call(->(*) { good.merge('window_end' => 1.5) }), nil) && C06.ck('raises', ua.call(->(*) { raise 'x' }), nil) &&
      C06.ck('args', (seen = nil; AtlasPca.undo_admission(->(*a) { seen = a; nil }, :p, :g, :o); seen), %i[p g o])
  end

  t('c06 js_str_of, v2_env and is_authorized_for') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    env = { 'acc' => 1, 'mon' => 2, 'canon' => 3, 'world' => 4, 'prov' => 5, 'class' => 6, 'keep' => 7 }
    orig = env.dup
    r_none = AtlasPca.v2_env({ 'x' => 1 }, {}, {}, 1, env)
    seen = nil
    r_some = Seam.with(AtlasPca::IntentV2, { decide_intent_v2: ->(p, g, v, n) { seen = [p, g, v, n]; { 'env' => { 'acc' => 'new', 'zed' => 9, 'skip' => nil } } } }) do
      AtlasPca.v2_env({ 'intent_session' => 's' }, :g, :v, 3, env)
    end
    r_nonhash = Seam.with(AtlasPca::IntentV2, { decide_intent_v2: ->(*) { { 'env' => { 'a' => 1 } } } }) { AtlasPca.v2_env({ 'intent_session' => 's' }, {}, {}, 1, 'str') }
    r_noenv = Seam.with(AtlasPca::IntentV2, { decide_intent_v2: ->(*) { {} } }) { AtlasPca.v2_env({ 'intent_session' => 's' }, {}, {}, 1, { 'keep' => 1, 'acc' => 2 }) }
    op = AtlasPca::AuthorizedOperation.new(verb: 'v', resource: 'r', params_digest: AtlasPca.params_digest({ 'a' => 1 }), id: 'i')
    res = ->(allow, o = op) { AtlasPca::AuthorizeResult.new(allow: allow, operation: o) }
    iaf = ->(r, o) { AtlasPca.is_authorized_for(r, o) }
    good = { 'verb' => 'v', 'resource' => 'r', 'params' => { 'a' => 1 } }
    C06.ck('undefined', AtlasPca.js_str_of({}, 'a'), 'undefined') && C06.ck('null', AtlasPca.js_str_of({ 'a' => nil }, 'a'), 'null') &&
      C06.ck('num', AtlasPca.js_str_of({ 'a' => 1 }, 'a'), '1') && r_none.equal?(env) && C06.ck('rest', r_some, { 'keep' => 7, 'acc' => 'new', 'zed' => 9 }) &&
      C06.ck('orig untouched', env, orig) && C06.ck('args', seen, [{ 'intent_session' => 's' }, :g, :v, 3]) &&
      C06.ck('non hash env', r_nonhash, { 'a' => 1 }) && C06.ck('no env member', r_noenv, { 'keep' => 1 }) &&
      C06.ck('iaf ok', iaf.call(res.call(true), good), true) && C06.ck('iaf sym', iaf.call(res.call(true), { verb: 'v', resource: 'r', params: { a: 1 } }), true) &&
      C06.ck('iaf float params', iaf.call(res.call(true), good.merge('params' => { 'a' => 1.0 })), true) &&
      C06.ck('iaf verb', iaf.call(res.call(true), good.merge('verb' => 'w')), false) && C06.ck('iaf res', iaf.call(res.call(true), good.merge('resource' => 'q')), false) &&
      C06.ck('iaf params', iaf.call(res.call(true), good.merge('params' => { 'a' => 2 })), false) && C06.ck('iaf denied', iaf.call(res.call(false), good), false) &&
      C06.ck('iaf not result', iaf.call({ 'allow' => true }, good), false) && C06.ck('iaf nil op', iaf.call(res.call(true), nil), false) &&
      C06.ck('iaf no operation', iaf.call(res.call(true, nil), good), false) && C06.ck('iaf bad op', iaf.call(res.call(true), { 'verb' => '' }), false) &&
      C06.ck('iaf allow truthy', iaf.call(res.call('yes'), good), false) &&
      C06.ck('iaf rescue', Seam.with(AtlasPca, { params_copy: ->(_p) { raise 'seam' } }) { iaf.call(res.call(true), good) }, false)
  end
end

# ---- part 2: the authorize pipeline --------------------------------------------------------------------------------------------
module MutationKill
  module C06
    module_function

    def prov_option
      key = AtlasPca::KeyPair.new("\x01".b * 32)
      pin = { 'mediator' => 'conformance-harness', 'kid' => 'k1', 'pk' => key.public }
      rec = AtlasPca::ProvenanceRecorder.new(mediator: pin['mediator'], kid: pin['kid'], key: key)
      { 'mediators' => [pin], 'bundle' => ->(_p, op) { AtlasPca.principal_direct_provenance(rec, op) } }
    end

    def fixture_pcactn = base['steps'][0]['pcactn']

    # authorize over the fixture (an allowing proof); kw overrides, `drop` omits keywords entirely
    def go(pc = :base, grant: nil, op: nil, drop: [], **kw)
      c = base
      s = c['steps'][0]
      g = grant || c['grant']
      opts = { operation: op || s['operation'], audience: aud, resolve_grant: ->(_r) { g }, state_store: AtlasPca::MemoryStateStore.new,
               is_revoked: ->(_p, _g) { false }, now: NOW, plan: 'single-step', provenance: prov_option, risk: ProvHarness::RISK }.merge(kw).reject { |k, _| drop.include?(k) }
      AtlasPca.authorize(pc == :base ? s['pcactn'] : pc, **opts)
    end

    def honest = AtlasPca.verify_pcactn(fixture_pcactn, base['grant'], now: NOW, audience: aud, insecure_skip_plan_root_check: true)

    def core(**over)
      v = honest
      w = AtlasPca::Verdict.new(v.allow, v.checks.dup, v.reason, v.reasons, v.degraded)
      over.each { |k, x| w[k] = x }
      w
    end

    # run the block with verify_pcactn answering `v` (and recording its keywords in `cap`)
    def with_core(v = nil, cap = nil, &blk)
      v ||= core
      Seam.with(AtlasPca, { verify_pcactn: ->(*a, **k) { cap << k if cap; v } }, &blk)
    end

    def eac_seam(caps, script = [])
      { evaluate_agent_caveats: lambda do |cv, cctx, actx = nil, tc = nil|
        i = caps.length
        caps << { cv: cv, cctx: cctx, actx: actx, tc: tc }
        script[i] || [true, []]
      end }
    end

    def with_clock(ms)
      sc = Time.singleton_class
      orig = Time.method(:now)
      sc.send(:define_method, :now) { Time.at(ms / 1000r) }
      yield
    ensure
      sc.send(:define_method, :now, orig)
    end

    def inner0
      { 'verb' => 'payments.send', 'resource' => 'payments/acme', 'params' => { 'amount' => 50, 'currency' => 'usd' }, 'reversibility_class' => 'irreversible' }
    end

    # a replay store with programmable claim / last
    def store_class
      Class.new do
        attr_accessor :ret, :last_val, :last_raises
        attr_reader :claims

        def claim(key, counter)
          (@claims ||= []) << [key, counter]
          raise 'boom' if @ret == :raise

          @ret == :nil ? nil : (@ret.nil? ? AtlasPca::ClaimResult.new(true) : @ret)
        end

        def last(_key)
          raise 'boom' if @last_raises

          @last_val
        end
      end
    end

    def chain_of(p) = p['cap_chain']
  end

  t('c06 authorize: the allowed fixture, every field of the result') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn
    r = C06.go
    pass = %w[counter_format replay revocation plan_root_authorized audience validity grant_ref_bound operation params_digest policy grant_ref]
    C06.ck('top', [r.allow, r.status, r.decision, r.reason, r.failed_checks, r.undo, r.obligations, r.escalation, r.missing],
           [true, 200, 'allow', nil, [], nil, nil, nil, nil]) &&
      C06.ck('passes', pass.map { |n| r.checks[n] }, ['pass'] * pass.length) && C06.ck('attest', r.checks['attestation'], 'not-enforced') &&
      C06.ck('op', [r.operation.verb, r.operation.resource, r.operation.params_digest, r.operation.id],
             ['payments.send', 'payments/acme', p['action']['params_digest'], AtlasPca.hash_canonical(p)]) &&
      C06.ck('pcactn', r.pcactn, p) && C06.ck('assurance', r.assurance.is_a?(Hash) && !r.assurance.empty?, true) && r.verdict.is_a?(AtlasPca::Verdict)
  end

  t('c06 authorize: configuration refusals name what is missing') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn
    shape = ->(r) { [r.allow, r.status, r.checks, r.reasons, r.reason, r.missing, r.assurance, r.pcactn] }
    none = AtlasPca.authorize(p)
    msg = ->(m) { "authorize_config: missing required component(s): #{m.join(', ')} (fail closed)" }
    four = %w[audience resolve_grant state_store is_revoked]
    c1 = shape.call(C06.go(revocation_staleness: 'x'))
    c2 = shape.call(C06.go(plan: 'multi'))
    c3 = shape.call(C06.go(provenance: 'x'))
    c4 = shape.call(C06.go(undo: 5))
    one = ->(m) { [false, 403, { 'authorize_config' => 'fail' }, [msg.call([m])], msg.call([m]), [m], { 'authorize_config' => { 'outcome' => 'fail' } }, nil] }
    C06.ck('none', shape.call(none), [false, 403, { 'authorize_config' => 'fail' }, [msg.call(four)], msg.call(four), four,
                                      { 'authorize_config' => { 'outcome' => 'fail' } }, nil]) &&
      C06.ck('staleness', c1, one.call('revocation_staleness (must be a RevocationStaleness)')) &&
      C06.ck('plan', c2, one.call("plan (only 'single-step' or nil)")) && C06.ck('prov', c3, one.call('provenance (must be a Hash)')) &&
      C06.ck('undo', c4, one.call('undo (must respond to #call)')) &&
      C06.ck('defaults omitted', C06.go(drop: %i[provenance]).checks.key?('authorize_config'), false) &&
      C06.ck('plan nil', C06.go(plan: nil).checks['plan_root_authorized'], 'fail') &&
      C06.ck('plan default', [C06.go(drop: %i[plan]).checks.key?('authorize_config'), C06.go(drop: %i[plan]).checks['plan_root_authorized']], [false, 'fail']) &&
      C06.ck('no op', shape.call(C06.go(op: 5))[0..5],
             [false, 403, { 'operation' => 'fail' }, ['operation: authorize needs the operation to execute (verb, resource, params) (fail closed)'],
              'operation: authorize needs the operation to execute (verb, resource, params) (fail closed)', nil])
  end

  t('c06 authorize: wire, grant and callback refusals (status, check, exact reason, proof echoed)') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn
    sh = ->(r) { [r.status, r.checks, r.reason, r.pcactn] }
    raise_ = ->(*) { raise 'x' }
    C06.ck('absent', sh.call(C06.go(nil)), [401, { 'wire' => 'fail' }, 'wire: no PCActn presented', nil]) &&
      C06.ck('int', sh.call(C06.go(5)), [401, { 'pcactn' => 'fail' }, 'undecodable PCActn: it is not a readable PCActn object (fail closed)', nil]) &&
      C06.ck('garbage', sh.call(C06.go('garbage'))[0..1], [401, { 'pcactn' => 'fail' }]) &&
      C06.ck('grant_ref', sh.call(C06.go(p.merge('grant_ref' => 5))), [401, { 'malformed' => 'fail' }, 'malformed: grant_ref is not a string', p.merge('grant_ref' => 5)]) &&
      C06.ck('resolve raises', sh.call(C06.go(resolve_grant: raise_)), [403, { 'resolve_grant' => 'fail' }, 'resolve_grant: grant resolution failed (fail closed)', p]) &&
      C06.ck('resolve nil', sh.call(C06.go(resolve_grant: ->(_r) {})), [401, { 'grant_ref' => 'fail' }, 'grant_ref: does not resolve to a known grant', p]) &&
      C06.ck('context raises', sh.call(C06.go(context: raise_)), [403, { 'context' => 'fail' }, 'context: the context callback failed (fail closed)', p]) &&
      C06.ck('context array', sh.call(C06.go(context: ->(_p) { [] })),
             [403, { 'context' => 'fail' }, 'context: the context callback must return a Hash (fail closed)', p]) &&
      C06.ck('context nil ok', C06.go(context: ->(_p) {}).allow, true) &&
      C06.ck('intent_v2 raises', sh.call(C06.go(intent_v2: raise_)), [403, { 'intent_v2' => 'fail' }, 'intent_v2: verifier state unavailable (fail closed)', p]) &&
      C06.ck('k1 raises', sh.call(C06.go(k1: raise_)), [403, { 'k1' => 'fail' }, 'k1: verifier caveat-language state unavailable (fail closed)', p]) &&
      C06.ck('k1 array', sh.call(C06.go(k1: [])), [403, { 'k1' => 'fail' }, 'k1: verifier caveat-language state unavailable (fail closed)', p]) &&
      C06.ck('k1 string', C06.go(k1: 'x').status, 403) &&
      C06.ck('plans raises', sh.call(C06.go(plans: Class.new { def context(*); raise 'x'; end }.new)),
             [403, { 'plans' => 'fail' }, 'plans: the plan registry failed (fail closed)', p])
  end

  t('c06 authorize: an internal fault is a 403 naming the class') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    r = Seam.with(AtlasPca, { verify_pcactn: ->(*, **) { raise ArgumentError, 'seam' } }) { C06.go }
    so = Seam.with(AtlasPca, { verify_pcactn: ->(*, **) { raise SystemStackError, 'seam' } }) { C06.go }
    C06.ck('err', [r.allow, r.status, r.checks, r.reason], [false, 403, { 'authorize' => 'fail' }, 'authorize: error (fail closed): ArgumentError']) &&
      C06.ck('stack', so.reason, 'authorize: error (fail closed): SystemStackError')
  end

  t('c06 authorize: the clock defaults to the wall clock in milliseconds (pipeline and workflow gate)') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    r = C06.with_clock(C06::NOW) { C06.go(drop: %i[now]) }
    seen = nil
    gate = ->(_w, _c, _p, _o, now) { seen = now; nil }
    Seam.with(AtlasPca, { authorize_workflow_gate: gate }) do
      C06.with_clock(C06::NOW) { C06.go(drop: %i[now], workflow: {}) }
    end
    cap = []
    C06.with_clock(C06::NOW) { C06.with_core(nil, cap) { C06.go(drop: %i[now]) } }
    C06.ck('allow', [r.allow, r.status], [true, 200]) && C06.ck('gate now', seen, C06::NOW) && C06.ck('core now', cap[0][:now], C06::NOW) &&
      C06.ck('given kept', (seen = nil; Seam.with(AtlasPca, { authorize_workflow_gate: gate }) { C06.go(now: 5, workflow: {}) }; seen), 5)
  end

  t('c06 authorize_workflow_gate: refusals, request mapping, decision mapping, fault') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn
    op = { 'verb' => 'v', 'resource' => 'r', 'params' => { 'a' => 1 } }
    gate = ->(w, c, pc = p, now = 77) { AtlasPca.authorize_workflow_gate(w, c, pc, op, now) }
    sh = ->(r) { [r.allow, r.status, r.checks, r.reasons, r.reason, r.decision] }
    refuse = ->(why) { [false, 403, { 'workflow' => 'fail' }, [why], why, 'deny'] }
    captured = []
    adm = ->(ret) { { admit_step: ->(inp) { captured << inp; ret } } }
    allow = { 'decision' => 'allow' }
    plan_of = ->(pl) { p.merge('plan' => pl) }
    root_of = lambda do |pc|
      captured.clear
      Seam.with(AtlasPca, adm.call(allow)) { gate.call({}, {}, pc) }
      captured[0]['request']['plan_root']
    end
    call = { 'commitment' => 'cm', 'receipts' => ['r1'], 'step' => 's1', 'units' => { 'u' => 2 }, 'goal_digest' => 'gd' }
    ok = C06.ck('not hash', sh.call(gate.call('x', nil)), refuse.call('workflow: the workflow option must be a Hash (fail closed)')) &&
         C06.ck('nil wf', sh.call(gate.call(nil, nil)), refuse.call('workflow: the workflow option must be a Hash (fail closed)')) &&
         C06.ck('no call ok', gate.call({}, nil), nil) && C06.ck('no call required', sh.call(gate.call({ 'required' => true }, nil)),
                                                                    refuse.call('workflow: this call carries no workflow step (fail closed)')) &&
         C06.ck('symbol required', sh.call(gate.call({ required: true }, nil)), refuse.call('workflow: this call carries no workflow step (fail closed)')) &&
         C06.ck('required false', gate.call({ 'required' => false }, nil), nil) && C06.ck('required truthy', gate.call({ 'required' => 1 }, nil), nil) &&
         C06.ck('call str', sh.call(gate.call({}, 'x')), refuse.call('workflow: the call input must be a Hash (fail closed)')) &&
         C06.ck('undecodable', gate.call({}, {}, 'garbage'), nil) && C06.ck('absent pcactn', gate.call({}, {}, nil), nil)
    ok && begin
      Seam.with(AtlasPca, adm.call(allow)) { C06.ck('allow', gate.call({ 'principal' => 'P', 'rs_signer' => 'S' }, call), nil) }
      inp = captured[0]
      C06.ck('inp', [inp['workflow'], inp['principal'], inp['rs_signer'], inp['receipts'], inp['now']], ['cm', 'P', 'S', ['r1'], 77]) &&
        C06.ck('request', inp['request'], { 'step' => 's1', 'verb' => 'v', 'resource' => 'r', 'params' => { 'a' => 1 }, 'units' => { 'u' => 2 }, 'goal_digest' => 'gd',
                                            'plan_root' => p['plan']['root'] })
    end && begin
      captured.clear
      Seam.with(AtlasPca, adm.call(allow)) { gate.call({ principal: 'P', rs_signer: 'S' }, { commitment: 'cm', receipts: [], step: 1, units: nil }) }
      C06.ck('sym keys', [captured[0]['workflow'], captured[0]['principal'], captured[0]['rs_signer'], captured[0]['request']['units'],
                          captured[0]['request']['step'], captured[0]['request']['goal_digest']], ['cm', 'P', 'S', {}, 1, nil])
    end && C06.ck('root string', root_of.call(plan_of.call({ 'root' => 'RR' })), 'RR') && C06.ck('root int', root_of.call(plan_of.call({ 'root' => 5 })), nil) &&
      C06.ck('plan nil', root_of.call(plan_of.call(nil)), nil) && C06.ck('plan string', root_of.call(plan_of.call('root')), nil) &&
      C06.ck('plan no root', root_of.call(plan_of.call({})), nil) && begin
        deny = Seam.with(AtlasPca, adm.call({ 'decision' => 'deny', 'code' => 'c1', 'step' => 2 })) { gate.call({}, {}) }
        deny0 = Seam.with(AtlasPca, adm.call({ 'decision' => 'deny', 'code' => 'c1', 'step' => 0 })) { gate.call({}, {}) }
        esc = Seam.with(AtlasPca, adm.call({ 'decision' => 'escalate', 'code' => 'c2' })) { gate.call({}, {}) }
        bare = Seam.with(AtlasPca, adm.call({ 'decision' => 'deny' })) { gate.call({}, {}) }
        boom = Seam.with(AtlasPca, { admit_step: ->(_i) { raise 'x' } }) { gate.call({}, {}) }
        C06.ck('deny', sh.call(deny), refuse.call('workflow: c1 (step 2)')) && C06.ck('deny step 0', deny0.reason, 'workflow: c1 (step 0)') &&
          C06.ck('escalate', sh.call(esc), [false, 403, { 'workflow' => 'fail' }, ['workflow: c2'], 'workflow: c2', 'escalate']) &&
          C06.ck('bare', bare.reason, 'workflow: refused') && C06.ck('boom', sh.call(boom), refuse.call('workflow: error (fail closed)'))
      end
  end

  t('c06 authorize: an admitted workflow step is the provenance control commitment; a refused one never reaches verification') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    flags = []
    pfc = ->(_o, _g, _p, _op, _b, f) { flags << f.dup; ['pass', nil] }
    allow_gate = { admit_step: ->(_i) { { 'decision' => 'allow' } } }
    Seam.with(AtlasPca, { provenance_flow_check: pfc }.merge(allow_gate)) do
      C06.go(workflow: {}, workflow_call: { 'commitment' => 'c' })
      C06.go(workflow: {}, workflow_call: nil)
      C06.go
    end
    cap = []
    refused = Seam.with(AtlasPca, { admit_step: ->(_i) { { 'decision' => 'deny', 'code' => 'nope' } } }) do
      C06.with_core(nil, cap) { C06.go(workflow: {}, workflow_call: { 'commitment' => 'c' }) }
    end
    C06.ck('flags', flags, [{ 'plan' => false, 'control' => true }, { 'plan' => false, 'control' => false }, { 'plan' => false, 'control' => false }]) &&
      C06.ck('refused', [refused.allow, refused.reason, cap], [false, 'workflow: nope', []])
  end

  t('c06 authorize: the plan registry is consulted only without a context plan; root, status and principal flags') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    plans_class = Class.new do
      attr_reader :calls

      def initialize(ret)
        @ret = ret
        @calls = []
      end

      def context(*a)
        @calls << a
        @ret
      end
    end
    p = C06.fixture_pcactn
    gref = p['grant_ref']
    flags = []
    pfc = ->(_o, _g, _p, _op, _b, f) { flags << f.dup; ['pass', nil] }
    run = lambda do |ret, pc = :base, **kw|
      pl = plans_class.new(ret)
      r = Seam.with(AtlasPca, { provenance_flow_check: pfc }) { C06.go(pc, plans: pl, **kw) }
      [r, pl]
    end
    ctx_plan = ->(_p) { { 'plan' => [] } }
    _, pl1 = run.call(nil, context: ctx_plan)
    _, pl2 = run.call(nil, p.merge('plan' => p['plan'].merge('root' => 5)))
    _, pl3 = run.call(nil, p.merge('plan' => nil))
    _, pl4 = run.call(nil)
    ok = C06.ck('ctx plan wins', pl1.calls, []) && C06.ck('root', pl4.calls, [[gref, p['plan']['root'], C06::NOW]]) &&
         C06.ck('root int', pl2.calls, [[gref, '', C06::NOW]]) && C06.ck('plan nil', pl3.calls, [[gref, '', C06::NOW]])
    ok && begin
      st = lambda do |auth, status|
        flags.clear
        run.call({ 'plan' => nil, 'planAuthorized' => auth, 'status' => status })
        flags[0]['plan']
      end
      C06.ck('flags', [st.call(true, { 'executable' => true }), st.call(false, { 'executable' => true }), st.call(true, { 'executable' => false }),
                       st.call(true, 'x'), st.call(true, nil), st.call(1, { 'executable' => true }), st.call(true, { 'executable' => 1 })],
             [true, false, false, false, false, false, false])
    end && begin
      r, = run.call({ 'plan' => nil, 'planAuthorized' => true, 'status' => { 'executable' => true } })
      bad, = Seam.with(AtlasPca, {}) { run.call({ 'plan' => nil, 'planAuthorized' => true, 'status' => [] }, { 'grant_ref' => gref }) }
      C06.ck('state pass', [r.checks['plan_state'], r.reasons], ['pass', []]) &&
        C06.ck('array status survives to wire', [bad.status, bad.checks['wire']], [401, 'fail'])
    end && begin
      stf = lambda do |status|
        r, = run.call({ 'plan' => nil, 'planAuthorized' => true, 'status' => status })
        [r.checks['plan_state'], r.reasons.select { |x| x.start_with?('plan_state') }]
      end
      C06.ck('reason nil', stf.call({ 'executable' => false, 'state' => 'expired' }), ['fail', ['plan_state: plan is expired']]) &&
        C06.ck('reason empty', stf.call({ 'executable' => false, 'state' => 'expired', 'reason' => '' }), ['fail', ['plan_state: plan is expired']]) &&
        C06.ck('reason set', stf.call({ 'executable' => false, 'state' => 'expired', 'reason' => 'because' }), ['fail', ['plan_state: because']])
    end && begin
      unk = run.call(nil, plan: nil)[0]
      one = run.call(nil)[0]
      C06.ck('unknown', [unk.checks['plan_state'], unk.reasons.select { |x| x.start_with?('plan_state') }],
             ['fail', ["plan_state: plan #{p['plan']['root']} is unknown to the plan registry"]]) && C06.ck('single-step', one.checks.key?('plan_state'), false)
    end
  end

  t('c06 authorize: context keys are strings; k1 keys too (duck keys are kept, symbols are converted)') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    key = Object.new
    def key.to_s; 'reversibility_class'; end
    r_duck = C06.go(context: ->(_p) { { key => 'irreversible' } })
    r_sym = C06.go(context: ->(_p) { { reversibility_class: 'irreversible' } })
    calls = []
    stub = { evaluate_k1: ->(*a) { calls << a; { ok: true, failed: [], reasons: [], plain: [], bound: [] } } }
    nk = Object.new
    def nk.to_s; 'narrow'; end
    Seam.with(AtlasPca, stub) do
      C06.go(k1: { narrow: {} })
      C06.go(k1: { 'narrow' => {} })
      C06.go(k1: { nk => {} })
      C06.go(k1: {})
      C06.go(k1: ->(_p) { { narrow: 1 } })
    end
    C06.ck('duck', r_duck.checks.key?('reversibility'), false) && C06.ck('sym', r_sym.checks['reversibility'], 'pass') && C06.ck('k1 calls', calls.length, 3)
  end

  t('c06 authorize: intent_v2 context merge (env, params), callable and non-Hash values reach the core as built') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    params = { 'amount' => 50, 'currency' => 'usd' }
    seen = lambda do |iv, env = :none|
      cap = []
      kw = env == :none ? {} : { context: ->(_p) { { 'env' => env } } }
      C06.with_core(nil, cap) { C06.go(intent_v2: iv, **kw) }
      cap[0][:intent_v2]
    end
    orig = { 'env' => { 'b' => 2 } }
    got = seen.call(orig, { 'a' => 1 })
    C06.ck('nil + host', seen.call(nil, { 'a' => 1 }), { 'env' => { 'a' => 1 }, 'params' => params }) &&
      C06.ck('nil alone', seen.call(nil), { 'params' => params }) &&
      C06.ck('merge', seen.call({ 'env' => { 'b' => 2, 'a' => 9 } }, { 'a' => 1, 'c' => 3 }), { 'env' => { 'a' => 9, 'c' => 3, 'b' => 2 }, 'params' => params }) &&
      C06.ck('merge env key', got.key?('env'), true) && C06.ck('input kept', orig, { 'env' => { 'b' => 2 } }) &&
      C06.ck('ve not hash', seen.call({ 'env' => 'str' }, { 'a' => 1 }), { 'env' => 'str', 'params' => params }) &&
      C06.ck('host not hash', seen.call({ 'env' => { 'b' => 2 } }, 'h'), { 'env' => { 'b' => 2 }, 'params' => params }) &&
      C06.ck('host absent', seen.call({ 'env' => { 'b' => 2 } }), { 'env' => { 'b' => 2 }, 'params' => params }) &&
      C06.ck('ve nil host hash', seen.call({ 'env' => nil }, { 'a' => 1 }), { 'env' => { 'a' => 1 }, 'params' => params }) &&
      C06.ck('ve nil host none', seen.call({ 'env' => nil }), { 'params' => params }) &&
      C06.ck('own params', seen.call({ 'params' => { 'own' => 1 } }), { 'params' => { 'own' => 1 } }) &&
      C06.ck('string v2', seen.call('x', { 'a' => 1 }), 'x') && C06.ck('callable', seen.call(->(_p) { { 'env' => { 'z' => 1 } } }), { 'env' => { 'z' => 1 }, 'params' => params }) &&
      C06.ck('callable nil', seen.call(->(_p) {}), { 'params' => params })
  end

  t('c06 authorize: a wire failure, and the reasons carried over from the core verdict') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn
    wire = lambda do |reason|
      v = C06.core(allow: false, checks: { 'wire' => false }, reason: reason)
      r = C06.with_core(v) { C06.go }
      [r.allow, r.status, r.checks, r.reasons, r.reason, r.pcactn, r.verdict.equal?(v)]
    end
    pre = [false, 401, { 'wire' => 'fail', 'malformed' => 'fail' }]
    reasons_of = lambda do |reason, reasons|
      arr = reasons.is_a?(Array) ? reasons.dup : reasons
      v = C06.core(allow: false, reason: reason, reasons: arr)
      r = C06.with_core(v) { C06.go }
      [r.reasons, (arr.is_a?(Array) ? arr : nil), r.reasons.equal?(arr)]
    end
    C06.ck('nil', wire.call(nil), pre + [['wire: malformed PCActn'], 'wire: malformed PCActn', p, true]) &&
      C06.ck('empty', wire.call(''), pre + [['wire: malformed PCActn'], 'wire: malformed PCActn', p, true]) &&
      C06.ck('given', wire.call('wire: bad'), pre + [['wire: bad'], 'wire: bad', p, true]) &&
      C06.ck('arr', reasons_of.call('r', %w[a b]), [%w[a b], %w[a b], false]) && C06.ck('nil reason', reasons_of.call(nil, nil)[0], []) &&
      C06.ck('empty reason', reasons_of.call('', nil)[0], []) && C06.ck('one reason', reasons_of.call('z', nil)[0], ['z']) &&
      C06.ck('reasons string', reasons_of.call('z', 'x')[0], ['z']) && C06.ck('reasons string no reason', reasons_of.call(nil, 'x')[0], []) &&
      C06.ck('core allow', C06.with_core(C06.core(reasons: ['stale'])) { C06.go }.reasons, [])
  end

  t('c06 authorize: the revocation outcome decides pass, fail text, and every other value fails closed') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    run = ->(v) { C06.go(is_revoked: ->(_p, _g) { v }) }
    t_ = run.call(true)
    n = run.call(nil)
    s = run.call('false')
    raising = C06.go(is_revoked: ->(_p, _g) { raise 'x' })
    args = []
    C06.go(is_revoked: ->(pc, g) { args << [pc, g]; false })
    C06.ck('true', [t_.allow, t_.checks['revocation'], t_.reasons.include?('revocation: the grant is revoked')], [false, 'fail', true]) &&
      C06.ck('nil', [n.checks['revocation'], n.reasons.include?('revocation: the revocation check failed (fail closed)')], ['fail', true]) &&
      C06.ck('string', s.checks['revocation'], 'fail') && C06.ck('raise', raising.reasons.include?('revocation: the revocation check failed (fail closed)'), true) &&
      C06.ck('args', args, [[C06.fixture_pcactn, C06.base['grant']]]) && C06.ck('false', run.call(false).checks['revocation'], 'pass')
  end

  t('c06 authorize: revocation staleness reaches check_revocation_state with the chain ids, classes and epoch; the verdict decides freshness') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn
    gid = C06.base['grant']['id']
    state = { 'kind' => 'root' }
    ctx = ->(extra = {}) { ->(_p) { { 'revocation_state' => state }.merge(extra) } }
    run = lambda do |ret, pol = AtlasPca::RevocationStaleness.new, pc = :base, **kw|
      calls = []
      r = C06.with_core(nil, nil) do
        Seam.with(AtlasPca, { check_revocation_state: ->(*a, **k) { calls << [a, k]; ret } }) { C06.go(pc, revocation_staleness: pol, **kw) }
      end
      [r, calls]
    end
    r, calls = run.call({ 'ok' => true, 'epoch' => 7 }, AtlasPca::RevocationStaleness.new, :base, context: ctx.call({ 'reversibility_class' => 'rate_limited' }))
    pol = AtlasPca::RevocationStaleness.new
    ok = C06.ck('args', [calls[0][0][1], calls[0][1][:now], calls[0][1][:grant_ref], calls[0][1][:ids], calls[0][1][:signed_class], calls[0][1][:server_class],
                         calls[0][1][:pcactn_epoch]], [state, C06::NOW, p['grant_ref'], [gid], 'irreversible', 'rate_limited', 0]) &&
         C06.ck('policy', calls[0][0][0].class, AtlasPca::RevocationStaleness) && C06.ck('pass', r.checks['freshness'], 'pass') && !pol.nil?
    ok && begin
      r2, c2 = run.call({ 'ok' => false, 'reason' => 'stale root' }, AtlasPca::RevocationStaleness.new, :base, context: ctx.call)
      C06.ck('fail', [r2.checks['freshness'], r2.reasons.include?('freshness: stale root'), c2[0][1][:server_class]], ['fail', true, nil])
    end && begin
      ep = lambda do |fr|
        _, c = run.call({ 'ok' => true }, AtlasPca::RevocationStaleness.new, p.merge('freshness' => fr), context: ctx.call)
        c[0][1][:pcactn_epoch]
      end
      undef_ = AtlasPca::IntentV2::UNDEF
      C06.ck('epoch', [ep.call({ 'epoch' => 3 }), ep.call({ 'epoch' => nil }), ep.call({}).equal?(undef_), ep.call(nil).equal?(undef_), ep.call('x').equal?(undef_),
                       ep.call({ 'epoch' => 'k' })], [3, nil, true, true, true, 'k'])
    end && begin
      ids = lambda do |chain, pol = AtlasPca::RevocationStaleness.new|
        _, c = run.call({ 'ok' => true }, pol, p.merge('cap_chain' => chain), context: ctx.call)
        c[0][1][:ids]
      end
      C06.ck('chain ids', ids.call([{ 'id' => 'a' }, 'id', 5, { 'x' => 1 }, nil]), ['a', nil, nil, nil, nil]) && C06.ck('no chain', ids.call(nil), []) &&
        C06.ck('hook', ids.call([], AtlasPca::RevocationStaleness.new(ids: ->(_p) { %w[h1 h2] })), %w[h1 h2]) &&
        C06.ck('hook raises', ids.call([], AtlasPca::RevocationStaleness.new(ids: ->(_p) { raise 'x' })), [nil])
    end && begin
      _, c3 = run.call({ 'ok' => true }, AtlasPca::RevocationStaleness.new(proofs: ->(i, pc) { [i, pc] }), :base, context: ctx.call)
      hashp = { 'a' => 1 }
      _, c4 = run.call({ 'ok' => true }, AtlasPca::RevocationStaleness.new(proofs: hashp), :base, context: ctx.call)
      _, c5 = run.call({ 'ok' => true }, AtlasPca::RevocationStaleness.new, :base, context: ctx.call)
      C06.ck('proofs callable', c3[0][1][:proofs].call('q'), ['q', p]) && c4[0][1][:proofs].equal?(hashp) && C06.ck('proofs none', c5[0][1][:proofs], nil)
    end
  end

  t('c06 authorize: no revocation state: irreversible actions are refused unless the policy allows an unsigned root') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn
    rev = lambda do |cls| # the action's signed class (core seamed: the signature is not checked)
      p.merge('action' => p['action'].merge('reversibility_class' => cls))
    end
    run = lambda do |pc, pol = AtlasPca::RevocationStaleness.new, **kw|
      r = C06.with_core { C06.go(pc, revocation_staleness: pol, **kw) }
      [r.checks['freshness'], r.reasons.select { |x| x.start_with?('freshness') }]
    end
    msg = ['freshness: no verifiable (guardian-signed) revocation state for an irreversible action']
    C06.ck('irreversible', run.call(:base), ['fail', msg]) &&
      C06.ck('allow unsigned', run.call(:base, AtlasPca::RevocationStaleness.new(allow_unsigned_root_for_irreversible: true)), ['not-enforced', []]) &&
      C06.ck('reversible', run.call(rev.call('reversible')), ['not-enforced', []]) &&
      C06.ck('server stricter', run.call(rev.call('reversible'), AtlasPca::RevocationStaleness.new, context: ->(_p) { { 'reversibility_class' => 'irreversible' } }), ['fail', msg]) &&
      C06.ck('server looser', run.call(rev.call('reversible'), AtlasPca::RevocationStaleness.new, context: ->(_p) { { 'reversibility_class' => 'reversible' } }), ['not-enforced', []]) &&
      C06.ck('no staleness', C06.go.checks.key?('freshness'), false) &&
      C06.ck('action not hash', run.call(p.merge('action' => 'x')), ['fail', msg])
  end

  t('c06 authorize: on_epoch_accepted runs after a successful claim only, with the accepted epoch and the proof') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn
    ctx = ->(_p) { { 'revocation_state' => { 'kind' => 'root' } } }
    run = lambda do |ret, hook, **kw|
      pol = AtlasPca::RevocationStaleness.new(on_epoch_accepted: hook)
      Seam.with(AtlasPca, { check_revocation_state: ->(*, **) { ret } }) { C06.go(context: ctx, revocation_staleness: pol, **kw) }
    end
    calls = []
    hook = ->(e, pc) { calls << [e, pc] }
    ok = run.call({ 'ok' => true, 'epoch' => 7 }, hook)
    n1 = calls.length
    run.call({ 'ok' => true }, hook)
    n2 = calls.length
    run.call({ 'ok' => true, 'epoch' => 8 }, hook, is_revoked: ->(_p, _g) { true })
    n3 = calls.length
    raising = run.call({ 'ok' => true, 'epoch' => 9 }, ->(_e, _p) { raise 'x' })
    nohook = run.call({ 'ok' => true, 'epoch' => 9 }, nil)
    C06.ck('called', [ok.allow, n1, calls[0]], [true, 1, [7, p]]) && C06.ck('no epoch', n2, 1) && C06.ck('denied', n3, 1) &&
      C06.ck('raising hook', [raising.allow, nohook.allow], [true, true])
  end

  t('c06 authorize: operation, grant_ref and params_digest bindings with their exact reasons') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    g = C06.base['grant']
    wrong_verb = C06.go(op: { 'verb' => 'other.verb', 'resource' => 'payments/acme', 'params' => { 'amount' => 50, 'currency' => 'usd' } })
    wrong_res = C06.go(op: { 'verb' => 'payments.send', 'resource' => 'other', 'params' => { 'amount' => 50, 'currency' => 'usd' } })
    wrong_par = C06.go(op: { 'verb' => 'payments.send', 'resource' => 'payments/acme', 'params' => { 'amount' => 400, 'currency' => 'usd' } })
    other_grant = C06.go(grant: g.merge('id' => 'other-id'))
    sel = ->(r, n) { r.reasons.select { |x| x.start_with?("#{n}:") } }
    C06.ck('verb', [wrong_verb.checks['operation'], sel.call(wrong_verb, 'operation')],
           ['fail', ['operation: the proof is for payments.send on payments/acme, but this operation is other.verb on payments/acme']]) &&
      C06.ck('resource', sel.call(wrong_res, 'operation'), ['operation: the proof is for payments.send on payments/acme, but this operation is payments.send on other']) &&
      C06.ck('params', [wrong_par.checks['operation'], wrong_par.checks['params_digest'], sel.call(wrong_par, 'operation'), sel.call(wrong_par, 'params_digest')],
             ['fail', 'fail', ["operation: the proof's params_digest does not match the params of this payments.send operation"],
              ['params_digest: supplied params do not hash to action.params_digest']]) &&
      C06.ck('grant', [other_grant.checks['grant_ref'], sel.call(other_grant, 'grant_ref')], ['fail', ['grant_ref: does not reference the supplied grant']]) &&
      C06.ck('first reason', wrong_verb.reason.start_with?('operation:'), true)
  end

  t('c06 authorize: an action that is not a Hash and a plan that is not a Hash are treated as empty') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn
    act = p.merge('action' => 'verb resource params_digest')
    r = C06.with_core { C06.go(act, op: { 'verb' => 'verb', 'resource' => 'resource', 'params' => {} }) }
    pl = p.merge('plan' => 'node_id root')
    r2 = C06.with_core { C06.go(pl) }
    ch = C06.with_core { C06.go(p.merge('cap_chain' => nil)) }
    C06.ck('action', r.reasons.select { |x| x.start_with?('operation:') },
           ['operation: the proof is for undefined on undefined, but this operation is verb on resource']) &&
      C06.ck('plan', [r2.checks['plan_root_authorized'], r2.reasons.any? { |x| x.start_with?('authorize: error') }], ['fail', false]) &&
      C06.ck('chain nil', [ch.checks.key?('policy'), ch.reasons.any? { |x| x.start_with?('authorize: error') }], [true, false])
  end

  t('c06 authorize: plan nodes from the context: root match, authorization, non-Array, conditions, absent plan') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn
    node = { 'id' => 'n1', 'verb' => 'payments.send', 'resource' => 'payments/acme', 'params_digest' => p['action']['params_digest'], 'reversibility_class' => 'irreversible' }
    run = lambda do |nodes, auth = true, **kw|
      r = C06.go(context: ->(_p) { { 'plan' => nodes, 'plan_authorized' => auth } }, **kw)
      [r.checks['plan_root_authorized'], r.reasons.select { |x| x.start_with?('plan_root_authorized') }]
    end
    C06.ck('match', run.call([node]), ['pass', []]) &&
      C06.ck('unauthorized', run.call([node], false), ['fail', ['plan_root_authorized: the plan root has not been authorized by the principal']]) &&
      C06.ck('unauthorized nil', run.call([node], nil)[0], 'fail') &&
      C06.ck('other root', run.call([node.merge('verb' => 'x')]), ['fail', ['plan_root_authorized: known plan does not match plan.root']]) &&
      C06.ck('set not array', run.call(Set[node])[0], 'fail') && C06.ck('hash not array', run.call({ 'n1' => node })[0], 'fail') &&
      C06.ck('pre changes root', run.call([node.merge('pre' => [{ 'k' => 1 }])])[0], 'fail') &&
      C06.ck('bad nodes', run.call([5, node])[0], 'fail') &&
      C06.ck('no plan', C06.go(plan: nil).reasons.select { |x| x.start_with?('plan_root_authorized') },
             ['plan_root_authorized: default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecure_skip_plan_root_check)'])
  end

  t('c06 authorize: reversibility against the authoritative class, and the effective class the policy sees') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn
    rev = ->(cls) { p.merge('action' => p['action'].merge('reversibility_class' => cls)) }
    caps = []
    run = lambda do |cls, server|
      caps.clear
      r = C06.with_core { Seam.with(AtlasPca, C06.eac_seam(caps)) { C06.go(rev.call(cls), context: ->(_p) { server.nil? ? {} : { 'reversibility_class' => server } }) } }
      [r.checks['reversibility'], r.reasons.select { |x| x.start_with?('reversibility') }, caps[1][:cctx]['reversibility_class'], caps[1][:actx]['action']['reversibility_class']]
    end
    less = ["reversibility: declared class 'reversible' is less restrictive than the authoritative 'irreversible'"]
    C06.ck('less', run.call('reversible', 'irreversible'), ['fail', less, 'irreversible', 'irreversible']) &&
      C06.ck('rate limited', run.call('reversible', 'rate_limited')[0..1], ['fail', ["reversibility: declared class 'reversible' is less restrictive than the authoritative 'rate_limited'"]]) &&
      C06.ck('stricter declared', run.call('irreversible', 'reversible'), ['pass', [], 'irreversible', 'irreversible']) &&
      C06.ck('equal', run.call('rate_limited', 'rate_limited'), ['pass', [], 'rate_limited', 'rate_limited']) &&
      C06.ck('no server class', run.call('reversible', nil), [nil, [], 'reversible', 'reversible']) &&
      C06.ck('unknown server', run.call('reversible', 'weird')[0..1], ['fail', ["reversibility: declared class 'reversible' is less restrictive than the authoritative 'weird'"]]) &&
      C06.ck('server wins on tie', run.call('irreversible', 'weird')[2], 'weird')
  end

  t('c06 authorize: the contexts the caveat evaluators receive (action, depth, class, blast radius, subject, env, tool binding)') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn
    params = { 'amount' => 50, 'currency' => 'usd' }
    caps = []
    run = lambda do |pc = :base, **kw|
      caps.clear
      C06.with_core { Seam.with(AtlasPca, C06.eac_seam(caps)) { C06.go(pc, **kw) } }
      caps.map { |c| c.dup }
    end
    base_caps = run.call
    ok = C06.ck('three calls', base_caps.length, 3) && C06.ck('delegated extra', base_caps[0][:cv], []) &&
         C06.ck('env caveats', base_caps[1][:cv], [{ 'type' => 'max_spend', 'usd' => 100 }]) && C06.ck('root caveats', base_caps[2][:cv], []) &&
         C06.ck('cctx', base_caps[1][:cctx], { 'now' => C06::NOW, 'action' => C06.inner0, 'delegation_depth' => 0, 'reversibility_class' => 'irreversible' }) &&
         C06.ck('actx', base_caps[1][:actx], { 'action' => C06.inner0 }) && C06.ck('tool', base_caps[1][:tc], { 'tool' => 'payments.send', 'args' => params })
    ok && begin
      x = run.call(context: ->(_p) { { 'blast_radius' => 3, 'recent_action_times' => [1, 2], 'subject' => 'S', 'env' => { 'e' => 1 } } })
      C06.ck('extras cctx', x[1][:cctx], { 'now' => C06::NOW, 'action' => C06.inner0, 'delegation_depth' => 0, 'reversibility_class' => 'irreversible', 'blast_radius' => 3,
                                           'recent_action_times' => [1, 2] }) &&
        C06.ck('extras actx', x[1][:actx], { 'action' => C06.inner0, 'subject' => 'S', 'env' => { 'e' => 1 } })
    end && begin
      d = ->(n) { run.call(p.merge('cap_chain' => Array.new(n) { {} }))[1][:cctx]['delegation_depth'] }
      C06.ck('depth', [d.call(0), d.call(1), d.call(2), d.call(3)], [0, 0, 1, 2])
    end && begin
      noclass = p.merge('action' => p['action'].reject { |k, _| k == 'reversibility_class' })
      x = run.call(noclass)
      C06.ck('no class', [x[1][:cctx].key?('reversibility_class'), x[1][:actx]['action'].key?('reversibility_class')], [false, false])
    end && begin
      tb = ->(v) { run.call(p.merge('tool_binding' => v))[1][:tc] }
      C06.ck('binding', tb.call('tb'), { 'tool' => 'payments.send', 'args' => params, 'tool_signature_digest' => 'tb' }) &&
        C06.ck('binding int', tb.call(5), { 'tool' => 'payments.send', 'args' => params })
    end && begin
      v = run.call(p.merge('action' => p['action'].merge('verb' => 5)))[1][:tc]
      C06.ck('verb int', v['tool'], '')
    end
  end

  t('c06 authorize: the plan node supplies the reversibility class only when the action carries none') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn
    noclass = p.merge('action' => p['action'].reject { |k, _| k == 'reversibility_class' })
    rc = lambda do |pc, nodes, **kw|
      caps = []
      C06.with_core { Seam.with(AtlasPca, C06.eac_seam(caps)) { C06.go(pc, context: ->(_p) { { 'plan' => nodes, 'plan_authorized' => true } }, **kw) } }
      caps[1][:cctx]
    end
    n1 = { 'id' => 'n1', 'reversibility_class' => 'rate_limited' }
    C06.ck('found', rc.call(noclass, [n1])['reversibility_class'], 'rate_limited') &&
      C06.ck('after junk', rc.call(noclass, [5, { 'id' => 'zz', 'reversibility_class' => 'costly' }, n1])['reversibility_class'], 'rate_limited') &&
      C06.ck('no match', rc.call(noclass, [{ 'id' => 'zz', 'reversibility_class' => 'costly' }]).key?('reversibility_class'), false) &&
      C06.ck('match without class', rc.call(noclass, [{ 'id' => 'n1' }]).key?('reversibility_class'), false) &&
      C06.ck('action class wins', rc.call(p, [n1])['reversibility_class'], 'irreversible') &&
      C06.ck('node id nil', rc.call(noclass.merge('plan' => p['plan'].reject { |k, _| k == 'node_id' }), [{ 'reversibility_class' => 'costly' }]).key?('reversibility_class'), false) &&
      C06.ck('node id int', rc.call(noclass.merge('plan' => p['plan'].merge('node_id' => 5)), [{ 'id' => 5, 'reversibility_class' => 'costly' }]).key?('reversibility_class'), false) &&
      C06.ck('no plan at all', (caps = []; C06.with_core { Seam.with(AtlasPca, C06.eac_seam(caps)) { C06.go(noclass, plan: nil) } }; caps[1][:cctx].key?('reversibility_class')), false)
  end

  # ---- part 3: caveat language v2, policy, assurance, provenance, replay, escalation, undo --------------------------------------

  t('c06 authorize: evaluate_k1 runs only when a hop carries a K1 caveat or the verifier supplied a narrow block') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    g = C06.base['grant']
    p = C06.fixture_pcactn
    sealed = { 'type' => 'sealed' }
    g2 = g.merge('caveats' => g['caveats'] + [sealed])
    leaf = g.merge('caveats' => g['caveats'] + [sealed])
    arr_duck = Object.new
    arr_duck.define_singleton_method(:[]) { |_k| [{ 'type' => 'sealed' }] }
    run = lambda do |pc, grant: nil, **kw|
      calls = []
      stub = { evaluate_k1: ->(*a) { calls << a; { ok: true, failed: [], reasons: [], plain: [], bound: [] } } }
      r = C06.with_core { Seam.with(AtlasPca, stub) { C06.go(pc, grant: grant, **kw) } }
      [calls.length, r]
    end
    n = ->(*a, **k) { run.call(*a, **k)[0] }
    C06.ck('plain', n.call(p), 0) && C06.ck('leaf k1', n.call(p.merge('cap_chain' => [g, leaf])), 1) && C06.ck('grant k1', n.call(p, grant: g2), 1) &&
      C06.ck('grant k1 empty chain', n.call(p.merge('cap_chain' => []), grant: g2), 1) &&
      C06.ck('int hop', run.call(p.merge('cap_chain' => [g, 5])).then { |c, r| [c, r.reasons.any? { |x| x.start_with?('authorize: error') }] }, [0, false]) &&
      C06.ck('duck hop', n.call(p.merge('cap_chain' => [g, arr_duck, g])), 0) &&
      C06.ck('set caveats', n.call(p.merge('cap_chain' => [g, { 'caveats' => Set[sealed] }, g])), 0) &&
      C06.ck('string caveats', n.call(p.merge('cap_chain' => [g, { 'caveats' => 'sealed' }, g])), 0) &&
      C06.ck('k1 given', n.call(p, k1: {}), 0) && C06.ck('k1 narrow', n.call(p, k1: { 'narrow' => nil }), 1) && C06.ck('k1 callable', n.call(p, k1: ->(_p) { {} }), 0)
  end

  t('c06 authorize: evaluate_k1 receives the grant, the chain, the verifier state with the action digest, and the action context') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    g = C06.base['grant']
    p = C06.fixture_pcactn
    leaf = g.merge('caveats' => g['caveats'] + [{ 'type' => 'sealed' }])
    pk = p.merge('cap_chain' => [g, leaf])
    calls = []
    stub = { evaluate_k1: ->(*a) { calls << a; { ok: true, failed: [], reasons: [], plain: [], bound: [] } } }
    C06.with_core { Seam.with(AtlasPca, stub) { C06.go(pk); C06.go(pk, k1: { 'pins' => 1 }); C06.go(pk, k1: { pins: 2 }) } }
    ctx = { 'now' => C06::NOW, 'action' => C06.inner0 }
    digest = AtlasPca.discharge_action_digest(pk)
    C06.ck('count', calls.length, 3) && C06.ck('grant', calls[0][0], g) && C06.ck('chain', calls[0][1], pk['cap_chain']) &&
      C06.ck('no k1', calls[0][2], nil) && calls[0][2].nil? && C06.ck('ctx', calls[0][3], ctx) &&
      C06.ck('k1', calls[1][2], { 'pins' => 1, 'action_digest' => digest }) && C06.ck('k1 symbol', calls[2][2], { 'pins' => 2, 'action_digest' => digest }) &&
      C06.ck('ctx 2', calls[1][3], ctx)
  end

  t('c06 authorize: delegated caveats: leaf extras plus K1 plain caveats, texts joined, malformed leaf, short leaf, empty chain') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    g = C06.base['grant']
    p = C06.fixture_pcactn
    sealed = { 'type' => 'sealed' }
    m5 = { 'type' => 'max_spend', 'usd' => 5 }
    m7 = { 'type' => 'max_spend', 'usd' => 7 }
    g2 = g.merge('caveats' => g['caveats'] + [sealed])
    k1ret = ->(**o) { { ok: true, failed: [], reasons: [], plain: [], bound: [] }.merge(o) }
    run = lambda do |pc, k1r = nil, script = [], grant: nil|
      caps = []
      stubs = C06.eac_seam(caps, script)
      stubs[:evaluate_k1] = ->(*) { k1r } if k1r
      r = C06.with_core { Seam.with(AtlasPca, stubs) { C06.go(pc, grant: grant) } }
      [caps, r]
    end
    leaf = g.merge('caveats' => g['caveats'] + [sealed, m5])
    caps1, = run.call(p.merge('cap_chain' => [g, leaf]), k1ret.call(plain: [m7]))
    caps2, = run.call(p.merge('cap_chain' => []), k1ret.call(plain: [m7]), grant: g2)
    caps3, r3 = run.call(p.merge('cap_chain' => [g, {}]), k1ret.call, grant: g2)
    caps4, = run.call(p.merge('cap_chain' => [g, g.merge('caveats' => [])]), k1ret.call(plain: [m7]), grant: g2)
    caps5, = run.call(p.merge('cap_chain' => [g, g.merge('caveats' => [])]), k1ret.call, grant: g2)
    _, r6 = run.call(p, k1ret.call(ok: false, failed: %w[sealed x], reasons: %w[r1 r2]), [[false, ['a']]], grant: g2)
    _, r7 = run.call(p, k1ret.call(ok: false, failed: %w[sealed x], reasons: %w[r1 r2]), [[true, []]], grant: g2)
    _, r8 = run.call(p, k1ret.call, [[false, %w[a b]]], grant: g2)
    _, r9 = run.call(p, nil, [[false, %w[a b]]])
    sel = ->(r) { r.reasons.select { |x| x.start_with?('delegated_caveats:') } }
    C06.ck('plain joined', caps1[0][:cv], [m5, m7]) && C06.ck('empty chain', caps2[0][:cv], [m7]) &&
      C06.ck('leaf without caveats', [caps3[0][:cv], r3.reasons.any? { |x| x.start_with?('authorize: error') }], [nil, false]) &&
      C06.ck('short leaf with plain', caps4[0][:cv], [m7]) && C06.ck('short leaf', caps5[0][:cv], []) &&
      C06.ck('k1 fail text', sel.call(r6), ['delegated_caveats: delegation caveat(s) not satisfied: a, sealed, x (r1; r2)']) &&
      C06.ck('k1 only', sel.call(r7), ['delegated_caveats: delegation caveat(s) not satisfied: sealed, x (r1; r2)']) &&
      C06.ck('eac only', [sel.call(r8), r8.checks['delegated_caveats']], [['delegated_caveats: delegation caveat(s) not satisfied: a, b'], 'fail']) &&
      C06.ck('no k1', sel.call(r9), ['delegated_caveats: delegation caveat(s) not satisfied: a, b'])
  end

  t('c06 authorize: root caveats drop the K1 types when the K1 evaluator ran; the envelope caveats are not touched') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    g = C06.base['grant']
    p = C06.fixture_pcactn
    sealed = { 'type' => 'sealed' }
    m9 = { 'type' => 'max_spend', 'usd' => 9 }
    g2 = g.merge('caveats' => g['caveats'] + [sealed, m9])
    caps = []
    stub = C06.eac_seam(caps).merge(evaluate_k1: ->(*) { { ok: true, failed: [], reasons: [], plain: [], bound: [] } })
    C06.with_core { Seam.with(AtlasPca, stub) { C06.go(p, grant: g2) } }
    caps2 = []
    C06.with_core { Seam.with(AtlasPca, C06.eac_seam(caps2)) { C06.go(p, grant: g.merge('caveats' => g['caveats'] + [m9])) } }
    C06.ck('root without k1', caps[2][:cv], [m9]) && C06.ck('env', caps[1][:cv], g['caveats'][0]['caveats']) && C06.ck('plain root', caps2[2][:cv], [m9])
  end

  t('c06 authorize: a max_uses caveat needs a uses_store, is spent only after the counter claim, and a refusal denies') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    g = C06.base['grant']
    p = C06.fixture_pcactn
    sealed = { 'type' => 'sealed' }
    pk = p.merge('cap_chain' => [g, g.merge('caveats' => g['caveats'] + [sealed])])
    mu = { 'caveat' => { 'type' => AtlasPca::CAVEAT_MAX_USES }, 'cap_hash' => 'c' }
    other = { 'caveat' => { 'type' => 'other' }, 'cap_hash' => 'c' }
    k1r = ->(bound) { { ok: true, failed: [], reasons: [], plain: [], bound: bound } }
    calls = []
    run = lambda do |bound, store, spent = { ok: true }, **kw|
      calls.clear
      st = { evaluate_k1: ->(*) { k1r.call(bound) }, reserve_max_uses: ->(*a) { calls << a; spent } }
      C06.with_core { Seam.with(AtlasPca, st) { C06.go(pk, uses_store: store, **kw) } }
    end
    msg = 'max_uses: the chain carries a max_uses caveat and no uses_store was supplied (fail closed)'
    st = C06.store_class.new
    r_nil = run.call([mu], nil)
    r_obj = run.call([mu], Object.new)
    n_obj = calls.length
    r_ok = run.call([mu], st)
    c_ok = calls.dup
    r_mixed = run.call([other, mu], st)
    r_other = run.call([other], nil)
    n_other = calls.length
    r_none = run.call([], nil)
    n_none = calls.length
    r_bad = run.call([mu], st, { ok: false, reason: 'spent out' })
    C06.ck('nil store', [r_nil.allow, r_nil.status, r_nil.checks['max_uses'], r_nil.reasons.include?(msg), r_nil.class], [false, 403, 'fail', true, AtlasPca::AuthorizeResult]) &&
      C06.ck('object store', [r_obj.checks['max_uses'], r_obj.reasons.include?(msg), n_obj], ['fail', true, 0]) &&
      C06.ck('spent', [r_ok.allow, r_ok.checks.key?('max_uses'), c_ok], [true, false, [[st, [mu], C06::NOW]]]) && C06.ck('mixed', r_mixed.allow, true) &&
      C06.ck('other type', [r_other.allow, n_other], [true, 0]) && C06.ck('empty bound', [r_none.allow, n_none], [true, 0]) &&
      C06.ck('refused', [r_bad.allow, r_bad.status, r_bad.checks['max_uses'], r_bad.reasons.include?('max_uses: spent out'), r_bad.class],
             [false, 403, 'fail', true, AtlasPca::AuthorizeResult])
  end

  t('c06 authorize: policy reasons: predicates, envelope caveats, root caveats, evaluation faults, missing envelope') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    g = C06.base['grant']
    p = C06.fixture_pcactn
    pol = ->(r) { r.reasons.select { |x| x.start_with?('policy:') } }
    pr = ->(ret) { Seam.with(AtlasPca, { evaluate_predicates: ->(*) { ret } }) { C06.go } }
    caps = []
    both = Seam.with(AtlasPca, C06.eac_seam(caps, [[true, []], [false, %w[a b]], [false, %w[c d]]])) { C06.go }
    boom = Seam.with(AtlasPca, { evaluate_predicates: ->(*) { raise 'x' } }) { C06.go }
    boom2 = Seam.with(AtlasPca, { evaluate_predicates: ->(*) { raise SystemStackError, 'x' } }) { C06.go }
    noenv = C06.with_core { C06.go(p, grant: g.merge('caveats' => [])) }
    C06.ck('default', [pr.call({ 'allowed' => false }).checks['policy'], pol.call(pr.call({ 'allowed' => false }))],
           ['fail', ['policy: action not permitted by envelope predicates']]) &&
      C06.ck('given', pol.call(pr.call({ 'allowed' => false, 'reason' => 'r' })), ['policy: r']) &&
      C06.ck('nil reason', pol.call(pr.call({ 'allowed' => false, 'reason' => nil })), ['policy: action not permitted by envelope predicates']) &&
      C06.ck('allowed', [pr.call({ 'allowed' => true }).checks['policy'], pol.call(pr.call({ 'allowed' => true }))], ['pass', []]) &&
      C06.ck('both', [both.checks['policy'], pol.call(both)], ['fail', ['policy: caveat(s) not satisfied: a, b', 'policy: root caveat(s) not satisfied: c, d']]) &&
      C06.ck('fault', [boom.checks['policy'], pol.call(boom), pol.call(boom2)], ['fail', ['policy: policy evaluation error (fail closed)'], ['policy: policy evaluation error (fail closed)']]) &&
      C06.ck('no envelope', [noenv.checks['policy'], pol.call(noenv)], ['fail', ['policy: grant carries no valid envelope']])
  end

  t('c06 authorize: a grant that pins the agent needs an attestation this SDK cannot verify') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    g = C06.base['grant']
    p = C06.fixture_pcactn
    env = g['caveats'][0]
    pinned = g.merge('caveats' => [env.merge('agent_binding' => { 'operator' => 'acme' })])
    r = C06.with_core { C06.go(p, grant: pinned) }
    free = C06.with_core { C06.go(p, grant: g.merge('caveats' => [env.merge('agent_binding' => {})])) }
    noenv = C06.with_core { C06.go(p, grant: g.merge('caveats' => [])) }
    C06.ck('pinned', [r.checks['attestation'], r.reasons.select { |x| x.start_with?('attestation:') }],
           ['fail', ['attestation: the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED (no attestation verifier in this SDK: fail closed)']]) &&
      C06.ck('free', free.checks['attestation'], 'not-enforced') && C06.ck('no envelope', noenv.checks['attestation'], 'not-enforced')
  end

  t('c06 authorize: require, status classes and the default-deny of required checks') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    r_req = C06.go(require: ['freshness'])
    r_sym = C06.go(require: :freshness)
    r_cnt = C06.go(require: ['counter'])
    r_aud = C06.go(audience: 'other-aud')
    r_junk = C06.go(require: [5, nil, 'freshness'])
    C06.ck('require', [r_req.allow, r_req.checks['freshness'], r_req.reason], [false, 'fail', 'freshness: required check is absent (default-deny: not enforced by this resource server)']) &&
      C06.ck('symbol', r_sym.checks['freshness'], 'fail') && C06.ck('alias', [r_cnt.allow, r_cnt.checks['replay']], [true, 'pass']) &&
      C06.ck('audience 401', [r_aud.status, r_aud.checks['audience']], [401, 'fail']) && C06.ck('403', C06.go(is_revoked: ->(_p, _g) { true }).status, 403) &&
      C06.ck('junk', r_junk.checks['freshness'], 'fail')
  end

  t('c06 authorize: require_assurance reaches unmet_assurance as given or as the invalid marker; the verdict decides the check') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    seen = []
    run = lambda do |req, ret|
      seen.clear
      Seam.with(AtlasPca, { unmet_assurance: ->(_rep, rq) { seen << rq; ret } }) { C06.go(require_assurance: req) }
    end
    ok = run.call({ 'signature' => 'pq' }, nil)
    s1 = seen.dup
    bad = run.call({ 'signature' => 'pq' }, 'assurance: too weak')
    s_str = (run.call('pq', nil); seen.dup)
    s_arr = (run.call(['a'], nil); seen.dup)
    none = C06.go
    C06.ck('given', [ok.allow, ok.checks['assurance'], s1], [true, 'pass', [{ 'signature' => 'pq' }]]) &&
      C06.ck('unmet', [bad.allow, bad.checks['assurance'], bad.reasons.include?('assurance: too weak')], [false, 'fail', true]) &&
      C06.ck('string', s_str, [{ 'invalid' => true }]) && C06.ck('array', s_arr, [{ 'invalid' => true }]) && C06.ck('absent', none.checks.key?('assurance'), false)
  end

  t('c06 authorize: the result carries the assurance report built from the verdict degradation; refusals keep their own') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    calls = []
    rep = { 'stub' => 1 }
    v = C06.core(degraded: 'DEG')
    r = C06.with_core(v) { Seam.with(AtlasPca, { assurance_report: ->(*a) { calls << a; rep } }) { C06.go } }
    n_before = calls.length
    refused = Seam.with(AtlasPca, { assurance_report: ->(*a) { calls << a; rep } }) { C06.go(5) }
    C06.ck('report', [r.assurance, r.degraded, n_before], [rep, 'DEG', 1]) && C06.ck('args', [calls[0][0], calls[0][1].equal?(r.checks), calls[0][2]], [C06.fixture_pcactn, true, 'DEG']) &&
      C06.ck('refusal kept', [refused.assurance, calls.length], [{ 'pcactn' => { 'outcome' => 'fail' } }, 1])
  end

  t('c06 authorize: the provenance gate outcome becomes the provenance_flow check and its reason') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    run = ->(ret) { Seam.with(AtlasPca, { provenance_flow_check: ->(*) { ret } }) { C06.go } }
    f1 = run.call(['fail', nil])
    f2 = run.call(['fail', 'why'])
    ok = run.call(['pass', nil])
    ne = run.call(['not-enforced', nil])
    sel = ->(r) { r.reasons.select { |x| x.start_with?('provenance_flow:') } }
    C06.ck('refused', [f1.allow, f1.checks['provenance_flow'], sel.call(f1)], [false, 'fail', ['provenance_flow: refused']]) &&
      C06.ck('given', sel.call(f2), ['provenance_flow: why']) && C06.ck('pass', [ok.allow, ok.checks['provenance_flow'], sel.call(ok)], [true, 'pass', []]) &&
      C06.ck('not enforced', [ne.allow, ne.checks['provenance_flow']], [true, 'not-enforced'])
  end

  t('c06 authorize: a carried bond is unsupported unless listed') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn.merge('bond_ref' => 'b1')
    run = ->(**kw) { C06.with_core { C06.go(p, **kw) } }
    r = run.call
    r2 = run.call(allow_unsupported: ['other'])
    r3 = run.call(allow_unsupported: ['bond'])
    r4 = run.call(allow_unsupported: ['bond'], require: ['bond'])
    C06.ck('denied', [r.allow, r.status, r.decision, r.checks['bond'], r.reason, r.reasons.last], [false, 403, 'deny', 'unsupported', AtlasPca::BOND_UNSUPPORTED, AtlasPca::BOND_UNSUPPORTED]) &&
      C06.ck('other', [r2.allow, r2.checks['bond']], [false, 'unsupported']) && C06.ck('listed', [r3.allow, r3.checks['bond']], [true, 'unsupported']) &&
      C06.ck('required', [r4.allow, r4.checks['bond']], [false, 'fail']) && C06.ck('no bond', C06.go.checks.key?('bond'), false)
  end

  t('c06 authorize: the replay key is "<grant id>:<leaf holder>"; no stream (no holder, non-String id) denies before the store is touched') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    g = C06.base['grant']
    p = C06.fixture_pcactn
    gid = g['id']
    msg = 'replay: no counter stream for this proof (fail closed)'
    no_holder = p.merge('cap_chain' => [{ 'id' => gid, 'caveats' => g['caveats'] }])
    st = C06.store_class.new
    r = C06.with_core { C06.go(no_holder, state_store: st) }
    duck = Object.new
    duck.define_singleton_method(:to_str) { gid }
    duck.define_singleton_method(:to_s) { gid }
    duck.define_singleton_method(:==) { |o| o.is_a?(String) }
    st2 = C06.store_class.new
    r2 = C06.with_core { C06.go(p, grant: g.merge('id' => duck), state_store: st2) }
    st3 = C06.store_class.new
    r3 = C06.with_core { C06.go(p.merge('cap_chain' => [5]), state_store: st3) }
    st4 = C06.store_class.new
    r4 = C06.go(state_store: st4)
    C06.ck('no holder', [r.allow, r.status, r.checks['replay'], r.reasons.last, st.claims], [false, 403, 'fail', msg, nil]) &&
      C06.ck('duck id', [r2.allow, r2.checks['replay'], r2.reasons.last, st2.claims], [false, 'fail', msg, nil]) &&
      C06.ck('int hop', [r3.checks['delegated_caveats'], r3.reasons.any? { |x| x.start_with?('authorize: error') }, st3.claims], ['fail', false, nil]) &&
      C06.ck('key', [r4.allow, st4.claims], [true, [["#{gid}:#{p['cap_chain'][-1]['holder']}", 1]]]) &&
      C06.ck('state_key', AtlasPca.state_key('g', 'h'), 'g:h')
  end

  t('c06 authorize: every shape of claim answer, with the replay reason it earns') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    cr = ->(*a) { AtlasPca::ClaimResult.new(*a) }
    run = lambda do |ret|
      st = C06.store_class.new
      st.ret = ret
      r = C06.go(state_store: st)
      [r.allow, r.checks['replay'], r.reasons.select { |x| x.start_with?('replay:') }, r.status]
    end
    already = [false, 'fail', ['replay: 1 was already claimed (replay)'], 403]
    failed = [false, 'fail', ['replay: the replay store failed (fail closed)'], 403]
    last7 = [false, 'fail', ['replay: 1 is not greater than last seen 7 (replay)'], 403]
    ok = [true, 'pass', [], 200]
    C06.ck('true', run.call(true), ok) && C06.ck('false', run.call(false), already) && C06.ck('nil', run.call(:nil), failed) && C06.ck('raise', run.call(:raise), failed) &&
      C06.ck('array true', run.call([true]), ok) && C06.ck('array false', run.call([false, 7]), last7) && C06.ck('claim false last', run.call(cr.call(false, 7)), last7) &&
      C06.ck('claim ok', run.call(cr.call(true)), ok) && C06.ck('claim false', run.call(cr.call(false)), already) && C06.ck('array false bare', run.call([false]), already) &&
      C06.ck('hash', run.call({ 0 => true }), already) && C06.ck('string', run.call('x'), already) && C06.ck('truthy', run.call(1), already)
  end

  t('c06 authorize: an escalation (every failing check escalate-class) carries the request; the head and the replay decide first') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn
    g = C06.base['grant']
    calls = { build: [], ver: [] }
    stubs = { decision_of: ->(_v) { 'escalate' }, build_escalation_request: ->(**k) { calls[:build] << k; { 'req' => 1 } },
              verify_escalation_answer: ->(*a) { calls[:ver] << a; { ok: false, reason: 'unused' } } }
    revoked = ->(_p, _g) { true }
    run = lambda do |pc = :base, last: :none, last_raises: false, **kw|
      calls[:build].clear
      calls[:ver].clear
      st = C06.store_class.new
      st.last_val = last unless last == :none
      st.last_raises = last_raises
      kw[:state_store] = st unless kw.key?(:state_store)
      r = C06.with_core { Seam.with(AtlasPca, stubs) { C06.go(pc, is_revoked: revoked, **kw) } }
      [r, st]
    end
    r, = run.call
    b = calls[:build][0]
    ok1 = C06.ck('esc', [r.allow, r.status, r.decision, r.escalation, r.checks['revocation']], [false, 403, 'escalate', { 'req' => 1 }, 'fail']) &&
          C06.ck('build', [b[:aud], b[:grant], b[:pcactn], b[:last_counter], b[:now], b[:render_digest], b[:reasons].include?('revocation: the grant is revoked')],
                 [C06.aud, g, p, nil, C06::NOW, nil, true]) && C06.ck('no claim', calls[:ver], [])
    ok1 && begin
      run.call(last: 0)
      c0 = calls[:build][0][:last_counter]
      rr, st = run.call(last: 5)
      rb, = run.call(last: 1)
      rx, = run.call(last: 'x')
      cx = calls[:build][0][:last_counter]
      rf, = run.call(last: 2.5)
      cf = calls[:build][0][:last_counter]
      rl, = run.call(last_raises: true)
      cl = calls[:build][0][:last_counter]
      ri, = run.call(state_store: Class.new { def claim(*) = nil }.new)
      ci = calls[:build][0][:last_counter]
      rs, = run.call(p.merge('counter' => '1'), last: 5)
      C06.ck('last 0', c0, 0) &&
        C06.ck('replay', [rr.decision, rr.checks['replay'], rr.reasons.include?('replay: 1 is not greater than last seen 5 (replay)'), rr.escalation, st.claims], ['deny', 'fail', true, nil, nil]) &&
        C06.ck('replay at head', [rb.decision, rb.reasons.include?('replay: 1 is not greater than last seen 1 (replay)')], ['deny', true]) &&
        C06.ck('non integer head', [rx.decision, cx, rf.decision, cf, rl.decision, cl, ri.decision, ci], ['escalate', nil, 'escalate', nil, 'escalate', nil, 'escalate', nil]) &&
        C06.ck('counter not integer', [rs.decision, rs.checks['replay']], ['escalate', 'pass'])
    end
  end

  t('c06 authorize: the render digest, the answer and the principal binding of an escalation') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    g = C06.base['grant']
    p = C06.fixture_pcactn
    calls = { build: [], ver: [] }
    ver = { ok: false, reason: 'bad sig' }
    stubs = { decision_of: ->(_v) { 'escalate' }, build_escalation_request: ->(**k) { calls[:build] << k; { 'req' => 1 } },
              verify_escalation_answer: ->(*a) { calls[:ver] << a; ver } }
    run = lambda do |last: 0, last_raises: false, **kw|
      calls[:build].clear
      calls[:ver].clear
      st = C06.store_class.new
      st.last_val = last
      st.last_raises = last_raises
      r = C06.with_core { Seam.with(AtlasPca, stubs) { C06.go(is_revoked: ->(_p, _g) { true }, state_store: st, **kw) } }
      [r, st]
    end
    ans = { 'a' => 1 }
    sel = ->(r) { r.reasons.select { |x| x.start_with?('escalation:') } }
    render_msg = 'escalation: an approval render is required and none could be recomputed (pass escalation_render:, or insecure_unbound_approval: true)'
    run.call(escalation_render: ->(_p) { 'RD' })
    d1 = calls[:build][0][:render_digest]
    run.call(escalation_render: ->(_p) { raise 'x' })
    d2 = calls[:build][0][:render_digest]
    run.call(escalation_render: 'x')
    d3 = calls[:build][0][:render_digest]
    r_none, = run.call(escalation_answer: ans, escalation_principals: ['pk'])
    v_none = calls[:ver].length
    r_ins, = run.call(escalation_answer: ans, escalation_principals: ['pk'], insecure_unbound_approval: true)
    a_ins = calls[:ver][0]
    r_rd, = run.call(escalation_answer: ans, escalation_principals: ['pk'], escalation_render: ->(_p) { 'RD' })
    a_rd = calls[:ver][0]
    r_raise, = run.call(escalation_answer: ans, escalation_principals: ['pk'], escalation_render: ->(_p) { 'RD' }, last_raises: true)
    v_raise = calls[:ver].length
    C06.ck('render', [d1, d2, d3], ['RD', nil, nil]) &&
      C06.ck('no render', [sel.call(r_none), v_none, r_none.decision], [[render_msg], 0, 'escalate']) &&
      C06.ck('insecure', [sel.call(r_ins), a_ins[0], a_ins[1], a_ins[3], a_ins[2]],
             [['escalation: bad sig'], ans, ['pk'], C06::NOW,
              { 'policy_digest' => AtlasPca.escalation_policy_digest(g), 'action_digest' => AtlasPca.escalation_action_digest(p), 'history_head' => AtlasPca.escalation_history_head(0) }]) &&
      C06.ck('render bind', [a_rd[2], r_rd.decision],
             [{ 'policy_digest' => AtlasPca.escalation_policy_digest(g), 'action_digest' => AtlasPca.escalation_action_digest(p),
                'history_head' => AtlasPca.escalation_history_head(0), 'render_digest' => 'RD' }, 'escalate']) &&
      C06.ck('unknown head', [v_raise, sel.call(r_raise)], [0, []])
  end

  t('c06 authorize: an allow answer admits the escalation; any other verdict leaves it standing') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn
    gid = C06.base['grant']['id']
    holder = p['cap_chain'][-1]['holder']
    ver = nil
    stubs = { decision_of: ->(_v) { 'escalate' }, build_escalation_request: ->(**) { { 'req' => 1 } }, verify_escalation_answer: ->(*) { ver } }
    run = lambda do |v|
      ver = v
      st = C06.store_class.new
      st.last_val = 0
      r = C06.with_core { Seam.with(AtlasPca, stubs) do
        C06.go(is_revoked: ->(_p, _g) { true }, state_store: st, escalation_answer: { 'a' => 1 }, escalation_principals: ['pk'], escalation_render: ->(_p) { 'RD' })
      end }
      [r, st]
    end
    r, st = run.call({ ok: true, decision: 'allow', principal: 'abcdefghijkl' })
    rd, = run.call({ ok: true, decision: 'deny', principal: 'abcdefghijkl' })
    rn, = run.call({ ok: false, decision: 'allow', reason: 'rr' })
    sel = ->(x) { x.reasons.select { |y| y.start_with?('escalation:') } }
    C06.ck('allowed', [r.allow, r.status, r.decision, r.escalation, r.failed_checks, r.checks['revocation'], r.checks['escalation'], sel.call(r), st.claims],
           [true, 200, 'allow', { 'answered_by' => 'abcdefghijkl' }, [], 'pass', 'pass', ['escalation: answered allow by principal abcdefgh'], [["#{gid}:#{holder}", 1]]]) &&
      C06.ck('deny answer', [rd.allow, rd.decision, rd.escalation, sel.call(rd), rd.checks['revocation']], [false, 'escalate', { 'req' => 1 }, ['escalation: the principal answered deny'], 'fail']) &&
      C06.ck('not ok', [rn.allow, rn.decision, sel.call(rn)], [false, 'escalate', ['escalation: rr']])
  end

  t('c06 authorize: an unanswered escalation runs under an undo window; answers and provenance escalations never do') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    p = C06.fixture_pcactn
    g = C06.base['grant']
    we = C06::NOW + 60_000
    adm = { 'id' => 'u1', 'window_end' => we, 'compensation' => { 'verb' => 'refund', 'resource' => 'r' } }
    hook_calls = []
    stubs = { decision_of: ->(_v) { 'escalate' }, build_escalation_request: ->(**) { { 'req' => 1 } },
              verify_escalation_answer: ->(*) { { ok: true, decision: 'deny', principal: 'abcdefghijkl' } } }
    run = lambda do |hook, pc = :base, core: nil, extra_stubs: {}, **kw|
      hook_calls.clear
      h = hook && ->(*a) { hook_calls << a; hook.call(*a) }
      Seam.with(AtlasPca, stubs.merge(extra_stubs)) do
        C06.with_core(core) { C06.go(pc, is_revoked: ->(_p, _g) { true }, undo: h, **kw) }
      end
    end
    r = run.call(->(*) { adm })
    obligation = { 'kind' => 'undo_window', 'params' => { 'id' => 'u1', 'window_end' => we }, 'due' => we }
    ok1 = C06.ck('admitted', [r.allow, r.status, r.decision, r.escalation, r.failed_checks, r.checks['undo_window'], r.checks['revocation'], r.undo, r.obligations],
                 [true, 200, 'allow', nil, [], 'pass', 'pass', adm, [obligation]]) &&
          C06.ck('reason', r.reasons.include?("undo_window: runs now under a veto window until #{we} (compensation refund)"), true) &&
          C06.ck('hook args', hook_calls, [[p, g, { 'verb' => 'payments.send', 'resource' => 'payments/acme', 'params' => { 'amount' => 50, 'currency' => 'usd' } }]])
    ok1 && begin
      nil_hook = run.call(->(*) {})
      raising = run.call(->(*) { raise 'x' })
      none = run.call(nil)
      answered = run.call(->(*) { adm }, escalation_answer: { 'a' => 1 }, escalation_principals: ['pk'], escalation_render: ->(_p) { 'RD' }, state_store: C06.store_class.new.tap { |s| s.last_val = 0 })
      n_answered = hook_calls.length
      prov = run.call(->(*) { adm }, extra_stubs: { provenance_flow_check: ->(*) { ['fail', 'x'] } })
      n_prov = hook_calls.length
      v = C06.core
      v.checks['provenance'] = false
      prov2 = run.call(->(*) { adm }, core: v)
      n_prov2 = hook_calls.length
      C06.ck('nil', [nil_hook.allow, nil_hook.decision, nil_hook.escalation], [false, 'escalate', { 'req' => 1 }]) &&
        C06.ck('raising', [raising.allow, raising.decision], [false, 'escalate']) && C06.ck('no hook', [none.allow, none.decision], [false, 'escalate']) &&
        C06.ck('answered', [answered.allow, answered.decision, n_answered], [false, 'escalate', 0]) &&
        C06.ck('provenance_flow', [prov.allow, prov.decision, n_prov], [false, 'escalate', 0]) &&
        C06.ck('provenance', [prov2.allow, prov2.decision, n_prov2], [false, 'escalate', 0])
    end
  end

  t('c06 authorize: a callable that is not a callable, and the escalation_render faults, are handled without raising') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    r = Seam.with(AtlasPca, { decision_of: ->(_v) { 'escalate' }, build_escalation_request: ->(**) { { 'req' => 1 } } }) do
      C06.go(is_revoked: ->(_p, _g) { true }, escalation_render: 5)
    end
    C06.ck('decision', [r.allow, r.decision], [false, 'escalate'])
  end

  t('c06 authorize: a Hash k1 that happens to respond to call is the verifier state itself, not a callable') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    h = { 'narrow' => {} }
    h.define_singleton_method(:call) { |_p| raise 'must not be called' }
    calls = []
    r = Seam.with(AtlasPca, { evaluate_k1: ->(*a) { calls << a; { ok: true, failed: [], reasons: [], plain: [], bound: [] } } }) { C06.go(k1: h) }
    C06.ck('hash state', [calls.length, r.reasons.any? { |x| x.start_with?('k1:') }, r.checks.key?('k1')], [1, false, false])
  end

  t('c06 authorize: an escalation whose request is nil never opens an undo window (seam over the request builder)') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    hook_calls = []
    stubs = { decision_of: ->(_v) { 'escalate' }, build_escalation_request: ->(**) { nil } }
    adm = { 'id' => 'u1', 'window_end' => C06::NOW + 1, 'compensation' => { 'verb' => 'refund', 'resource' => 'r' } }
    r = Seam.with(AtlasPca, stubs) do
      C06.go(is_revoked: ->(_p, _g) { true }, undo: ->(*a) { hook_calls << a; adm })
    end
    C06.ck('no window', [hook_calls.length, r.undo, r.obligations, r.checks.key?('undo_window')], [0, nil, nil, false])
  end

  t('c06 authorize_unchecked: omitted trailing arguments behave exactly as explicit nil / false') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    c = C06.base
    s = c['steps'][0]
    explicit = [nil, nil, nil, nil, nil, nil, nil, nil, nil, false, nil, nil, nil, nil, nil, nil]
    mk = lambda do |p = s['pcactn'], revoked = false|
      [p, s['operation'], C06.aud, ->(_r) { c['grant'] }, AtlasPca::MemoryStateStore.new, ->(_p, _g) { revoked }, C06::NOW, 'single-step', nil, nil, nil, nil, nil]
    end
    same = lambda do |args_a, args_b, extra = {}|
      ver = []
      stubs = { verify_escalation_answer: ->(*a) { ver << a; { ok: false, reason: 'x' } }, build_escalation_request: ->(**) { { 'req' => 1 } } }.merge(extra)
      Seam.with(AtlasPca, stubs) do
        r1 = AtlasPca.authorize_unchecked(*args_a)
        n1 = ver.length
        r2 = AtlasPca.authorize_unchecked(*args_b, *explicit)
        [r1.to_h == r2.to_h, n1, ver.length - n1, r1.allow, r1.decision]
      end
    end
    plain = same.call(mk.call, mk.call)
    escalate = same.call(mk.call(s['pcactn'], true), mk.call(s['pcactn'], true), { decision_of: ->(_v) { 'escalate' } })
    bond = C06.with_core { same.call(mk.call(s['pcactn'].merge('bond_ref' => 'b'), false), mk.call(s['pcactn'].merge('bond_ref' => 'b'), false)) }
    C06.ck('plain', plain[0..2], [true, 0, 0]) && C06.ck('escalate', escalate[0..2], [true, 0, 0]) && C06.ck('escalate decision', escalate[4], 'escalate') &&
      C06.ck('bond', [bond[0], bond[3]], [true, false])
  end

  t('c06 authorize: respond_to? decides what is callable and what a store offers; method_missing alone grants nothing') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'
    mm = Class.new do
      def initialize(ret)
        @ret = ret
      end

      def method_missing(name, *args)
        name == :call ? @ret : super
      end

      def respond_to_missing?(*)
        false
      end
    end
    store_mm = Class.new do
      def claim(*)
        nil
      end

      def method_missing(name, *args)
        name == :last ? 3 : super
      end

      def respond_to_missing?(*)
        false
      end
    end
    r_k1 = C06.go(k1: mm.new({}))
    build = []
    stubs = { decision_of: ->(_v) { 'escalate' }, build_escalation_request: ->(**k) { build << k; { 'req' => 1 } } }
    r_render = Seam.with(AtlasPca, stubs) { C06.go(is_revoked: ->(_p, _g) { true }, escalation_render: mm.new('RD')) }
    d_render = build[0][:render_digest]
    build.clear
    r_store = Seam.with(AtlasPca, stubs) { C06.go(is_revoked: ->(_p, _g) { true }, state_store: store_mm.new) }
    C06.ck('k1', [r_k1.status, r_k1.checks['k1']], [403, 'fail']) && C06.ck('render', [r_render.decision, d_render], ['escalate', nil]) &&
      C06.ck('store', [r_store.decision, build[0][:last_counter]], ['escalate', nil])
  end
end
