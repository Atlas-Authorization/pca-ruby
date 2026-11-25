# frozen_string_literal: true

# c25: mutation-kill tests for lib/atlas_pca/readside.rb and lib/atlas_pca/read_vault.rb (K5 read-side grants, receipts, sinks,
# tokenisation vault, aggregate reads). Everything resolves AtlasPca at CALL time (the oracle re-evaluates AtlasPca per mutant).
# Signatures are stubbed with a seam over k5_verify_body (the real Ed25519 path is pinned by test_k5.rb + the vault vectors);
# every other check runs for real. Expected values are read off the TS reference (read-vault.ts / readside.ts) via the Ruby port.
require 'timeout'

module MutationKill
  module C25
    LIBS = %w[readside.rb read_vault.rb].freeze
    PRINCIPAL = 'F8t5-ytBIPKx7GXkGY1uCLKOgT_rAeSkAIObheGAgM4'
    RS = '6yzxO_euOl9hQWih-wknLTl3HsS4UjcngV5GbK-O4WM'
    SALT = 'a-per-read-secret-salt'
    MAXS = (2**53) - 1

    # Quacks like a Hash/Array but is neither (is_a?(Hash) / is_a?(Array) are false).
    class Duck
      def initialize(obj)
        @obj = obj
      end

      def method_missing(name, *args, &blk)
        if @obj.respond_to?(name)
          @obj.public_send(name, *args, &blk)
        else
          super
        end
      end

      def respond_to_missing?(name, include_private = false)
        @obj.respond_to?(name, include_private) || super
      end
    end

    # A real Hash whose key? always says yes.
    class AlwaysKey < Hash
      def key?(_key)
        true
      end
    end

    # An object whose == is always true but which is not a String.
    class EqTrue
      def ==(_other)
        true
      end
    end

    # Only to_a (no sort_by).
    class ToA
      def to_a
        %w[b a]
      end
    end

    # An Array that claims another length.
    class FakeLen < Array
      def initialize(arr, len)
        super(arr)
        @len = len
      end

      def length
        @len
      end
    end

    # A draw source scripted by call number and bound.
    class Scripted
      attr_reader :calls

      def initialize(&fun)
        @fun = fun
        @calls = 0
      end

      def uniform(bound)
        @calls += 1
        @fun.call(@calls, bound)
      end
    end

    # A store spy.
    class Spy
      attr_reader :puts_made

      def initialize
        @puts_made = []
      end

      def put(token, entry)
        @puts_made << [token, entry]
      end

      def get(_token)
        nil
      end
    end

    class BoomGet
      def get(_token)
        raise 'boom'
      end
    end

    class BoomPut
      def put(_token, _entry)
        raise 'boom'
      end
    end

    module_function

    def skip?
      f = ENV['MUT_FILE']
      !f.nil? && !f.empty? && !LIBS.include?(f)
    end

    def ck(label, got, want)
      return true if got == want

      raise "#{label}: got #{got.inspect}, want #{want.inspect}"
    end

    def rows(label, rows_)
      rows_.each_with_index { |(name, input, want), i| ck("#{label} ##{i} #{name}", yield(input), want) }
      true
    end

    def labels(prefix, count)
      Array.new(count) { |i| format('%s%02d', prefix, i) }
    end

    def with_verify(ret = true, log = nil, &blk)
      impl = lambda do |dom, body, signer, sig|
        log << [dom, body, signer, sig] if log
        ret.respond_to?(:call) ? ret.call(dom, body, signer, sig) : ret
      end
      MutationKill::Seam.with(AtlasPca, { k5_verify_body: impl }, &blk)
    end

    def entry(**o)
      { 'verb' => 'customers.get', 'resource_prefix' => 'customers/', 'purposes' => ['support'],
        'modes' => { 'pii' => 'last4', 'fin' => 'bucket:100' }, 'default_mode' => 'drop' }.merge(o.transform_keys(&:to_s))
    end

    def sink
      { 'allow' => %w[public ref], 'escalate' => ['fp'] }
    end

    def body(**o)
      { 'v' => 1, 'id' => 'rg-1', 'principal' => PRINCIPAL, 'issued_at' => 1000, 'expires_at' => 2000, 'reads' => [entry],
        'caps' => { 'pii' => 3, 'fin' => 2 }, 'sinks' => { 'ext' => sink, 'int' => { 'allow' => ['pii'], 'escalate' => [] } } }.merge(o.transform_keys(&:to_s))
    end

    def sg(b = body)
      { 'body' => b, 'sig' => 'x' }
    end

    def schema(**o)
      { 'fields' => { 'pii' => 'pii', 'fin' => 'fin' }, 'required' => [] }.merge(o.transform_keys(&:to_s))
    end

    def rin(**o)
      { 'principal' => PRINCIPAL, 'now' => 1500, 'verb' => 'customers.get', 'resource' => 'customers/1', 'purpose' => 'support',
        'salt' => SALT, 'record' => { 'pii' => '123456789', 'fin' => 250 }, 'tighten' => {}, 'counts' => {} }.merge(o.transform_keys(&:to_s))
    end

    def fld(**o)
      { 'class' => 'pii', 'action' => 'masked', 'kind' => 'last4', 'vd' => RS }.merge(o.transform_keys(&:to_s))
    end

    def rc(seq: 0, prev: nil, fields: :dflt, labels: :dflt, issued_at: 1000, **o)
      fields = { 'f1' => fld } if fields == :dflt
      labels = ['pii'] if labels == :dflt
      { 'v' => 1, 'grant' => PRINCIPAL, 'verb' => 'customers.get', 'resource' => 'customers/1', 'purpose' => 'support', 'seq' => seq,
        'prev' => prev, 'fields' => fields, 'labels' => labels, 'issued_at' => issued_at, 'signer' => RS,
        'sig' => 'x' }.merge(o.transform_keys(&:to_s))
    end

    def chain2
      r0 = rc
      r1 = rc(seq: 1, prev: AtlasPca.read_receipt_ref(r0), fields: { 'f2' => fld('class' => 'fin', 'kind' => 'bucket') }, labels: ['fin'])
      [r0, r1]
    end

    def arule(**o)
      { 'verb' => 'orders.sum', 'resource_prefix' => 'orders/', 'purposes' => ['analytics'], 'fns' => %w[count sum], 'min_group' => 2,
        'clamp' => 100, 'epsilon_micro' => 500_000, 'dp' => false }.merge(o.transform_keys(&:to_s))
    end

    def abody(**o)
      { 'v' => 1, 'id' => 'ag-1', 'principal' => PRINCIPAL, 'issued_at' => 1000, 'expires_at' => 2000, 'rules' => [arule],
        'epsilon_budget_micro' => 10_000_000, 'max_queries' => 3 }.merge(o.transform_keys(&:to_s))
    end

    def astate(**o)
      { 'spent_micro' => 7, 'queries' => 0, 'answered' => {} }.merge(o.transform_keys(&:to_s))
    end

    def ain(**o)
      { 'grant' => { 'body' => abody, 'sig' => 'x' }, 'principal' => PRINCIPAL, 'now' => 1500, 'verb' => 'orders.sum',
        'resource' => 'orders/9', 'purpose' => 'analytics', 'fn' => 'count', 'values' => [1, 2, 3], 'salt' => SALT, 'noise' => 'seeded',
        'state' => astate }.merge(o.transform_keys(&:to_s))
    end

    def afail(code, st)
      { 'decision' => 'deny', 'code' => code, 'value' => nil, 'state' => st, 'charged_micro' => 0 }
    end

    def empty_state
      { 'spent_micro' => 0, 'queries' => 0, 'answered' => {} }
    end

    def agg_qd(g, inp, rule)
      AtlasPca.hash_canonical({ 'd' => 'atlas-pca/aggregate-query/v1', 'g' => AtlasPca.aggregate_grant_digest(g), 'verb' => inp['verb'],
                                'resource' => inp['resource'], 'purpose' => inp['purpose'], 'fn' => inp['fn'], 'n' => inp['values'].length,
                                's' => AtlasPca.k5_clamped_sum(inp['values'], rule['clamp']) })
    end
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  # constants and tiny helpers
  # ---------------------------------------------------------------------------------------------------------------------------
  t('c25 readside: constants are exact (domains binary, rank table, salt minimum)') do
    next true if C25.skip?

    ap = AtlasPca
    C25.ck('rank', ap::K5_RANK, { 'show' => 0, 'last4' => 1, 'bucket' => 2, 'token' => 3, 'hash' => 4, 'drop' => 5 }) &&
      C25.ck('salt min', ap::K5_SALT_MIN, 16) &&
      C25.ck('grant domain', ap::READ_GRANT_DOMAIN, "atlas-pca/read-grant/v1\x00".b) &&
      C25.ck('grant domain enc', ap::READ_GRANT_DOMAIN.encoding, Encoding::BINARY) &&
      C25.ck('receipt domain', ap::READ_RECEIPT_DOMAIN, "atlas-pca/read-receipt/v1\x00".b) &&
      C25.ck('receipt domain enc', ap::READ_RECEIPT_DOMAIN.encoding, Encoding::BINARY) &&
      C25.ck('agg domain', ap::AGGREGATE_DOMAIN, "atlas-pca/aggregate-grant/v1\x00".b) &&
      C25.ck('agg domain enc', ap::AGGREGATE_DOMAIN.encoding, Encoding::BINARY) &&
      C25.ck('two48', ap::K5_TWO48, 281_474_976_710_656) &&
      C25.ck('max steps', ap::K5_MAX_STEPS, 100_000)
  end

  t('c25 readside: k5_mode?, k5_rank, k5_sorted, k5_bmp? are exact') do
    next true if C25.skip?

    ap = AtlasPca
    C25.rows('mode', [['show', 'show', true], ['last4', 'last4', true], ['hash', 'hash', true], ['token', 'token', true],
                      ['drop', 'drop', true], ['b1', 'bucket:1', true], ['b100', 'bucket:100', true], ['b9', 'bucket:999999999', true],
                      ['b0', 'bucket:0', false], ['b10', 'bucket:1000000000', false], ['bempty', 'bucket:', false],
                      ['upper', 'Show', false], ['empty', '', false], ['nil', nil, false], ['int', 5, false],
                      ['nl', "show\n", false]]) { |m| ap.k5_mode?(m) } &&
      C25.rows('rank', [%w[show show 0], %w[last4 last4 1], ['b5', 'bucket:5', 2], ['b100', 'bucket:100', 2], %w[token token 3],
                        %w[hash hash 4], %w[drop drop 5]].map { |n, m, r| [n, m, r.to_i] }) { |m| ap.k5_rank(m) } &&
      C25.ck('sorted', ap.k5_sorted(%w[b a é Z]), %w[Z a b é]) &&
      C25.ck('sorted to_a', ap.k5_sorted(C25::ToA.new), %w[a b]) &&
      C25.rows('bmp', [['ascii', 'abc', true], ['ffff', "a\u{FFFF}", true], ['10000', "a\u{10000}", false], ['10001', "\u{10001}", false],
                       ['empty', '', true]]) { |s| ap.k5_bmp?(s) }
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  # k5_valid_entry? / valid_read_grant_body?
  # ---------------------------------------------------------------------------------------------------------------------------
  t('c25 readside: k5_valid_entry? decides every operand and every limit') do
    next true if C25.skip?

    c = C25
    v = ->(e) { AtlasPca.k5_valid_entry?(e) }
    modes32 = c.labels('m', 32).to_h { |k| [k, 'show'] }
    c.rows('entry', [
             ['base', c.entry, true],
             ['nil', nil, false], ['array', [], false], ['string', 'x', false], ['duck', c::Duck.new(c.entry), false],
             ['extra key', c.entry.merge('x' => 1), false], ['missing key', c.entry.reject { |k, _| k == 'verb' }, false],
             ['verb empty', c.entry(verb: ''), false], ['verb 128', c.entry(verb: 'a' * 128), true],
             ['verb 129', c.entry(verb: 'a' * 129), false], ['verb int', c.entry(verb: 5), false],
             ['prefix 512', c.entry(resource_prefix: 'a' * 512), true], ['prefix 513', c.entry(resource_prefix: 'a' * 513), false],
             ['prefix empty', c.entry(resource_prefix: ''), false],
             ['purposes empty', c.entry(purposes: []), false], ['purposes 16', c.entry(purposes: c.labels('p', 16)), true],
             ['purposes 17', c.entry(purposes: c.labels('p', 17)), false], ['purposes unsorted', c.entry(purposes: %w[b a]), false],
             ['purposes dup', c.entry(purposes: %w[a a]), false], ['purposes bad id', c.entry(purposes: ['bad id!']), false],
             ['purposes nil', c.entry(purposes: nil), false],
             ['modes array', c.entry(modes: []), false], ['modes nil', c.entry(modes: nil), false], ['modes empty', c.entry(modes: {}), true],
             ['modes 32', c.entry(modes: modes32), true],
             ['modes 33', c.entry(modes: c.labels('m', 33).to_h { |k| [k, 'show'] }), false],
             ['modes bad key', c.entry(modes: { 'Bad' => 'show' }), false], ['modes bad value', c.entry(modes: { 'ok' => 'bucket:0' }), false],
             ['modes good', c.entry(modes: { 'ok' => 'show' }), true],
             ['default bad', c.entry(default_mode: 'bogus'), false], ['default nil', c.entry(default_mode: nil), false]
           ]) { |e| v.call(e) }
  end

  t('c25 readside: valid_read_grant_body? decides every operand and every limit') do
    next true if C25.skip?

    c = C25
    v = ->(b) { AtlasPca.valid_read_grant_body?(b) }
    sinks16 = c.labels('s', 16).to_h { |k| [k, c.sink] }
    sinks17 = c.labels('s', 17).to_h { |k| [k, c.sink] }
    caps32 = c.labels('c', 32).to_h { |k| [k, 1] }
    caps33 = c.labels('c', 33).to_h { |k| [k, 1] }
    c.rows('body', [
             ['base', c.body, true],
             ['nil', nil, false], ['array', [], false], ['duck', c::Duck.new(c.body), false],
             ['extra key', c.body.merge('x' => 1), false], ['missing sinks', c.body.reject { |k, _| k == 'sinks' }, false],
             ['v 2', c.body(v: 2), false], ['v string', c.body(v: '1'), false], ['v float', c.body(v: 1.0), false],
             ['id bad', c.body(id: 'bad id'), false], ['principal bad', c.body(principal: 'x'), false],
             ['principal nil', c.body(principal: nil), false],
             ['issued neg', c.body(issued_at: -1), false], ['issued float', c.body(issued_at: 1.5), false],
             ['issued max', c.body(issued_at: c::MAXS), true], ['issued over', c.body(issued_at: c::MAXS + 1), false],
             ['expires neg', c.body(expires_at: -1), false], ['expires float', c.body(expires_at: 2.5), false],
             ['expires max', c.body(expires_at: c::MAXS), true], ['expires over', c.body(expires_at: c::MAXS + 1), false],
             ['reads empty', c.body(reads: []), false], ['reads hash', c.body(reads: {}), false], ['reads nil', c.body(reads: nil), false],
             ['reads duck', c.body(reads: c::Duck.new([c.entry])), false],
             ['reads 32', c.body(reads: Array.new(32) { c.entry }), true], ['reads 33', c.body(reads: Array.new(33) { c.entry }), false],
             ['reads bad entry', c.body(reads: [c.entry, c.entry(verb: '')]), false],
             ['caps array', c.body(caps: []), false], ['caps nil', c.body(caps: nil), false], ['caps empty', c.body(caps: {}), true],
             ['caps 32', c.body(caps: caps32), true], ['caps 33', c.body(caps: caps33), false],
             ['caps bad key', c.body(caps: { 'Bad' => 1 }), false], ['caps neg', c.body(caps: { 'ok' => -1 }), false],
             ['caps float', c.body(caps: { 'ok' => 1.5 }), false],
             ['sinks array', c.body(sinks: []), false], ['sinks nil', c.body(sinks: nil), false], ['sinks empty', c.body(sinks: {}), true],
             ['sinks 16', c.body(sinks: sinks16), true], ['sinks 17', c.body(sinks: sinks17), false],
             ['sinks bad key', c.body(sinks: { 'bad key' => c.sink }), false],
             ['sink duck', c.body(sinks: { 'a' => c::Duck.new(c.sink) }), false], ['sink array', c.body(sinks: { 'a' => [] }), false],
             ['sink extra', c.body(sinks: { 'a' => c.sink.merge('x' => []) }), false],
             ['sink missing', c.body(sinks: { 'a' => { 'allow' => [] } }), false],
             ['allow 16', c.body(sinks: { 'a' => { 'allow' => c.labels('a', 16), 'escalate' => [] } }), true],
             ['allow 17', c.body(sinks: { 'a' => { 'allow' => c.labels('a', 17), 'escalate' => [] } }), false],
             ['escalate 16', c.body(sinks: { 'a' => { 'allow' => [], 'escalate' => c.labels('e', 16) } }), true],
             ['escalate 17', c.body(sinks: { 'a' => { 'allow' => [], 'escalate' => c.labels('e', 17) } }), false],
             ['allow unsorted', c.body(sinks: { 'a' => { 'allow' => %w[b a], 'escalate' => [] } }), false],
             ['escalate unsorted', c.body(sinks: { 'a' => { 'allow' => [], 'escalate' => %w[b a] } }), false],
             ['allow nil', c.body(sinks: { 'a' => { 'allow' => nil, 'escalate' => [] } }), false],
             ['escalate nil', c.body(sinks: { 'a' => { 'allow' => [], 'escalate' => nil } }), false],
             ['overlap same', c.body(sinks: { 'a' => { 'allow' => ['a'], 'escalate' => ['a'] } }), false],
             ['overlap partial', c.body(sinks: { 'a' => { 'allow' => %w[a b], 'escalate' => %w[b c] } }), false],
             ['disjoint', c.body(sinks: { 'a' => { 'allow' => %w[a b], 'escalate' => %w[c d] } }), true]
           ]) { |b| v.call(b) } &&
      MutationKill::Seam.with(AtlasPca, { k5_id?: ->(_x) { raise 'boom' } }) { c.ck('rescue is exactly false', v.call(c.body), false) }
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  # k5_grade_grant
  # ---------------------------------------------------------------------------------------------------------------------------
  t('c25 readside: k5_grade_grant codes, order and time window are exact') do
    next true if C25.skip?

    c = C25
    g = ->(sg, principal, now) { AtlasPca.k5_grade_grant(sg, principal, now) }
    log = []
    ok = c.with_verify(true, log) do
      c.rows('grade', [
               ['ok', [c.sg, c::PRINCIPAL, 1500], { 'body' => c.body }],
               ['principal bad', [c.sg, 'x', 1500], { 'code' => 'bad_request' }],
               ['principal nil', [c.sg, nil, 1500], { 'code' => 'bad_request' }],
               ['now neg', [c.sg, c::PRINCIPAL, -1], { 'code' => 'bad_request' }],
               ['now float', [c.sg, c::PRINCIPAL, 1.5], { 'code' => 'bad_request' }],
               ['now nil', [c.sg, c::PRINCIPAL, nil], { 'code' => 'bad_request' }],
               ['now string', [c.sg, c::PRINCIPAL, '1500'], { 'code' => 'bad_request' }],
               ['sg nil', [nil, c::PRINCIPAL, 1500], { 'code' => 'bad_grant' }],
               ['sg duck', [c::Duck.new(c.sg), c::PRINCIPAL, 1500], { 'code' => 'bad_grant' }],
               ['sg extra', [c.sg.merge('z' => 1), c::PRINCIPAL, 1500], { 'code' => 'bad_grant' }],
               ['sg no sig', [{ 'body' => c.body }, c::PRINCIPAL, 1500], { 'code' => 'bad_grant' }],
               ['sg bad body', [c.sg(c.body(v: 2)), c::PRINCIPAL, 1500], { 'code' => 'bad_grant' }],
               ['other principal', [c.sg, c::RS, 1500], { 'code' => 'bad_signature' }],
               ['not yet', [c.sg, c::PRINCIPAL, 999], { 'code' => 'not_yet' }],
               ['at issued', [c.sg, c::PRINCIPAL, 1000], { 'body' => c.body }],
               ['last valid', [c.sg, c::PRINCIPAL, 1999], { 'body' => c.body }],
               ['at expires', [c.sg, c::PRINCIPAL, 2000], { 'code' => 'expired' }],
               ['after expires', [c.sg, c::PRINCIPAL, 2001], { 'code' => 'expired' }]
             ]) { |a| g.call(*a) }
    end
    bad = c.with_verify(false) { c.ck('signature refused', g.call(c.sg, c::PRINCIPAL, 1500), { 'code' => 'bad_signature' }) }
    ok && bad && log.any? &&
      c.ck('verify args', log[0], [AtlasPca::READ_GRANT_DOMAIN, c.body, c::PRINCIPAL, 'x'])
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  # k5_valid_redact_input?
  # ---------------------------------------------------------------------------------------------------------------------------
  t('c25 readside: k5_valid_redact_input? decides every operand and every limit') do
    next true if C25.skip?

    c = C25
    v = ->(a) { AtlasPca.k5_valid_redact_input?(a[0], a[1]) }
    sc = c.schema
    c.rows('redact input', [
             ['base', [c.rin, sc], true],
             ['principal bad', [c.rin(principal: 'x'), sc], false], ['principal nil', [c.rin(principal: nil), sc], false],
             ['now neg', [c.rin(now: -1), sc], false], ['now nil', [c.rin(now: nil), sc], false],
             ['verb empty', [c.rin(verb: ''), sc], false], ['verb 128', [c.rin(verb: 'a' * 128), sc], true],
             ['verb 129', [c.rin(verb: 'a' * 129), sc], false], ['verb int', [c.rin(verb: 5), sc], false],
             ['resource empty', [c.rin(resource: ''), sc], false], ['resource 512', [c.rin(resource: 'a' * 512), sc], true],
             ['resource 513', [c.rin(resource: 'a' * 513), sc], false],
             ['purpose bad', [c.rin(purpose: 'bad id'), sc], false],
             ['salt nil', [c.rin(salt: nil), sc], false], ['salt int', [c.rin(salt: 5), sc], false],
             ['salt 15', [c.rin(salt: 'x' * 15), sc], false], ['salt 16', [c.rin(salt: 'x' * 16), sc], true],
             ['sc nil', [c.rin, nil], false], ['sc array', [c.rin, []], false], ['sc duck', [c.rin, c::Duck.new(sc)], false],
             ['fields array', [c.rin, c.schema(fields: [])], false], ['fields nil', [c.rin, c.schema(fields: nil)], false],
             ['fields duck', [c.rin, c.schema(fields: c::Duck.new({ 'pii' => 'pii' }))], false],
             ['fields bad key', [c.rin, c.schema(fields: { 'bad key!' => 'pii' })], false],
             ['fields bad class', [c.rin, c.schema(fields: { 'pii' => 'Bad' })], false],
             ['required hash', [c.rin, c.schema(required: {})], false], ['required nil', [c.rin, c.schema(required: nil)], false],
             ['required unknown', [c.rin, c.schema(required: ['nope'])], false], ['required known', [c.rin, c.schema(required: ['pii'])], true],
             ['required int, key? lies', [c.rin, c.schema(fields: c::AlwaysKey['pii' => 'pii'], required: [5])], false],
             ['required unknown, key? lies', [c.rin, c.schema(fields: c::AlwaysKey['pii' => 'pii'], required: ['zzz'])], true],
             ['record nil', [c.rin(record: nil), sc], false], ['record float', [c.rin(record: { 'pii' => 1.5 }), sc], false],
             ['record bad key', [c.rin(record: { 'bad key!' => 'x' }), sc], false],
             ['tighten array', [c.rin(tighten: []), sc], false], ['tighten nil', [c.rin(tighten: nil), sc], false],
             ['tighten bad key', [c.rin(tighten: { 'BAD' => 'show' }), sc], false],
             ['tighten bad mode', [c.rin(tighten: { 'pii' => 'bucket:0' }), sc], false],
             ['tighten good', [c.rin(tighten: { 'pii' => 'hash' }), sc], true],
             ['counts array', [c.rin(counts: []), sc], false], ['counts nil', [c.rin(counts: nil), sc], false],
             ['counts bad key', [c.rin(counts: { 'BAD' => 1 }), sc], false], ['counts neg', [c.rin(counts: { 'pii' => -1 }), sc], false],
             ['counts good', [c.rin(counts: { 'pii' => 1 }), sc], true]
           ]) { |a| v.call(a) }
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  # k5_mask
  # ---------------------------------------------------------------------------------------------------------------------------
  t('c25 readside: k5_mask each mode exactly') do
    next true if C25.skip?

    ap = AtlasPca
    salt = C25::SALT
    m = ->(mode, v) { ap.k5_mask(mode, 'pii', v, salt) }
    hash_want = ap.hash_canonical({ 'd' => 'atlas-pca/read-hash/v1', 'salt' => salt, 'c' => 'pii', 'v' => 'val' })
    tok_want = "tok_#{ap.hash_canonical({ 'd' => 'atlas-pca/read-token/v1', 'salt' => salt, 'c' => 'pii', 'v' => 'val' })[0, 22]}"
    C25.rows('mask', [
               ['last4 5', %w[last4 abcde], '****bcde'], ['last4 4', %w[last4 abcd], nil], ['last4 bmp edge', ['last4', "\u{FFFF}abcd"], "****abcd"],
               ['last4 astral', ['last4', "ab\u{1F600}cde"], nil], ['last4 int', ['last4', 12_345], nil],
               ['bucket 250', ['bucket:100', 250], 200], ['bucket 0', ['bucket:100', 0], 0], ['bucket 99', ['bucket:100', 99], 0],
               ['bucket 100', ['bucket:100', 100], 100], ['bucket 7', ['bucket:7', 20], 14], ['bucket neg', ['bucket:100', -1], nil],
               ['bucket float', ['bucket:100', 250.5], nil], ['bucket string', ['bucket:100', '250'], nil], ['bucket true', ['bucket:100', true], nil],
               ['hash', %w[hash val], hash_want], ['token', %w[token val], tok_want],
               ['show', %w[show val], nil], ['drop', %w[drop val], nil], ['bogus', %w[bogus val], nil]
             ]) { |a| m.call(*a) } &&
      C25.ck('token length', tok_want.length, 26)
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  # redact_read
  # ---------------------------------------------------------------------------------------------------------------------------
  t('c25 readside: redact_read tighten-only compares ranks strictly (equal rank keeps the grant mode)') do
    next true if C25.skip?

    c = C25
    ap = AtlasPca
    b = c.body(reads: [c.entry(modes: { 'fin' => 'bucket:100' })], caps: { 'fin' => 2 })
    inp = ->(tighten) { c.rin(grant: c.sg(b), schema: { 'fields' => { 'fin' => 'fin' }, 'required' => [] }, record: { 'fin' => 250 }, tighten: tighten) }
    hash_want = ap.hash_canonical({ 'd' => 'atlas-pca/read-hash/v1', 'salt' => c::SALT, 'c' => 'fin', 'v' => 250 })
    c.with_verify(true) do
      eq = ap.redact_read(inp.call({ 'fin' => 'bucket:50' }))
      weaker = ap.redact_read(inp.call({ 'fin' => 'last4' }))
      shown = ap.redact_read(inp.call({ 'fin' => 'show' }))
      stricter = ap.redact_read(inp.call({ 'fin' => 'hash' }))
      c.ck('equal rank keeps 200', eq['view'], { 'fin' => 200 }) &&
        c.ck('equal rank kind', eq['fields']['fin']['kind'], 'bucket') &&
        c.ck('equal rank decision', [eq['decision'], eq['code']], ['allow', nil]) &&
        c.ck('weaker ignored', weaker['view'], { 'fin' => 200 }) &&
        c.ck('show ignored', shown['view'], { 'fin' => 200 }) &&
        c.ck('stricter wins', stricter['view'], { 'fin' => hash_want }) &&
        c.ck('stricter kind', stricter['fields']['fin']['kind'], 'hash')
    end
  end

  t('c25 readside: redact_read a fault inside is exactly deny bad_request with an empty view') do
    next true if C25.skip?

    c = C25
    c.with_verify(true) do
      MutationKill::Seam.with(AtlasPca, { k5_mask: ->(*) { raise 'boom' } }) do
        r = AtlasPca.redact_read(c.rin(grant: c.sg, schema: c.schema))
        c.ck('rescue', r, { 'decision' => 'deny', 'code' => 'bad_request', 'view' => {}, 'fields' => {}, 'labels' => [], 'counts' => {} })
      end
    end
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  # k5_valid_read_receipt?
  # ---------------------------------------------------------------------------------------------------------------------------
  t('c25 readside: k5_valid_read_receipt? decides every operand and every limit') do
    next true if C25.skip?

    c = C25
    v = ->(r) { AtlasPca.k5_valid_read_receipt?(r) }
    f64 = c.labels('f', 64).to_h { |k| [k, c.fld] }
    f65 = c.labels('f', 65).to_h { |k| [k, c.fld] }
    default_proc_class = Hash.new { 'unclassified' }
    default_proc_class['class'] = 'Bad'
    default_proc_class['action'] = 'masked'
    default_proc_class['kind'] = nil
    default_proc_class['vd'] = c::RS
    c.rows('receipt', [
             ['base', c.rc, true],
             ['nil', nil, false], ['array', [], false], ['duck', c::Duck.new(c.rc), false],
             ['extra key', c.rc.merge('x' => 1), false], ['missing key', c.rc.reject { |k, _| k == 'sig' }, false],
             ['v 2', c.rc(v: 2), false],
             ['grant bad', c.rc(grant: 'x'), false], ['verb empty', c.rc(verb: ''), false], ['verb 128', c.rc(verb: 'a' * 128), true],
             ['verb 129', c.rc(verb: 'a' * 129), false], ['resource empty', c.rc(resource: ''), false],
             ['resource 512', c.rc(resource: 'a' * 512), true], ['resource 513', c.rc(resource: 'a' * 513), false],
             ['purpose bad', c.rc(purpose: 'bad id'), false], ['seq neg', c.rc(seq: -1), false], ['seq float', c.rc(seq: 1.5), false],
             ['seq1 prev ok', c.rc(seq: 1, prev: c::PRINCIPAL), true], ['seq0 prev set', c.rc(seq: 0, prev: c::PRINCIPAL), false],
             ['seq1 prev nil', c.rc(seq: 1, prev: nil), false], ['seq1 prev bad', c.rc(seq: 1, prev: 'bad'), false],
             ['seq0 prev bad', c.rc(seq: 0, prev: 'bad'), false],
             ['issued neg', c.rc(issued_at: -1), false], ['signer bad', c.rc(signer: 'x'), false],
             ['sig nil', c.rc(sig: nil), false], ['sig int', c.rc(sig: 5), false],
             ['labels 32', c.rc(labels: c.labels('l', 32)), true], ['labels 33', c.rc(labels: c.labels('l', 33)), false],
             ['labels unsorted', c.rc(labels: %w[b a]), false], ['labels bad', c.rc(labels: ['BAD']), false], ['labels nil', c.rc(labels: nil), false],
             ['fields array', c.rc(fields: []), false], ['fields nil', c.rc(fields: nil), false],
             ['fields duck', c.rc(fields: c::Duck.new({ 'f1' => c.fld })), false],
             ['fields empty', c.rc(fields: {}), true], ['fields 64', c.rc(fields: f64), true], ['fields 65', c.rc(fields: f65), false],
             ['field bad name', c.rc(fields: { 'bad key!' => c.fld }), false],
             ['field nil', c.rc(fields: { 'f1' => nil }), false], ['field array', c.rc(fields: { 'f1' => [] }), false],
             ['field duck', c.rc(fields: { 'f1' => c::Duck.new(c.fld) }), false],
             ['field extra', c.rc(fields: { 'f1' => c.fld.merge('x' => 1) }), false],
             ['class unclassified', c.rc(fields: { 'f1' => c.fld(class: 'unclassified', action: 'dropped', kind: nil) }), true],
             ['class Bad', c.rc(fields: { 'f1' => c.fld(class: 'Bad') }), false], ['class empty', c.rc(fields: { 'f1' => c.fld(class: '') }), false],
             ['class int', c.rc(fields: { 'f1' => c.fld(class: 5) }), false],
             ['class lies ==', c.rc(fields: { 'f1' => c.fld(class: c::EqTrue.new) }), false],
             ['class Bad, default proc', c.rc(fields: { 'f1' => default_proc_class }), false],
             ['action shown', c.rc(fields: { 'f1' => c.fld(action: 'shown', kind: nil) }), true],
             ['action dropped', c.rc(fields: { 'f1' => c.fld(action: 'dropped', kind: nil) }), true],
             ['action bogus', c.rc(fields: { 'f1' => c.fld(action: 'bogus') }), false],
             ['action nil', c.rc(fields: { 'f1' => c.fld(action: nil) }), false],
             ['kind int', c.rc(fields: { 'f1' => c.fld(kind: 5) }), false], ['kind nil', c.rc(fields: { 'f1' => c.fld(kind: nil) }), true],
             ['vd bad', c.rc(fields: { 'f1' => c.fld(vd: 'x') }), false]
           ]) { |r| v.call(r) }
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  # read_chain_labels
  # ---------------------------------------------------------------------------------------------------------------------------
  t('c25 readside: read_chain_labels verdicts, positions and the rescue are exact') do
    next true if C25.skip?

    c = C25
    ap = AtlasPca
    gd = c::PRINCIPAL
    chain = ->(rcs, now = 1500, signer = c::RS, grant = gd) { ap.read_chain_labels(rcs, signer, grant, now) }
    r0, r1 = c.chain2
    log = []
    first = c.with_verify(true, log) do
      c.ck('two receipts', chain.call([r0, r1]), { 'labels' => %w[fin pii] }) &&
        c.ck('verify args 0', log[0], [ap::READ_RECEIPT_DOMAIN, ap.k5_read_receipt_body(r0), c::RS, 'x']) &&
        c.ck('verify args 1', log[1], [ap::READ_RECEIPT_DOMAIN, ap.k5_read_receipt_body(r1), c::RS, 'x']) &&
        c.ck('empty', chain.call([]), { 'labels' => [] }) &&
        c.ck('one receipt', chain.call([r0]), { 'labels' => ['pii'] })
    end
    second = c.with_verify(true) do
      bad1 = { 'code' => 'bad_receipt', 'at' => 1 }
      bad0 = { 'code' => 'bad_receipt', 'at' => 0 }
      dropped = c.rc(fields: { 'f1' => c.fld, 'f2' => c.fld('class' => 'secret', 'action' => 'dropped', 'kind' => nil) })
      c.rows('chain', [
               ['chain break', [r0, c.rc(seq: 1, prev: c::RS, fields: r1['fields'], labels: ['fin'])], bad1],
               ['shape bad at 1', [r0, c.rc(seq: 1, prev: 'bad')], bad1],
               ['seq off', [c.rc(seq: 1, prev: c::RS)], bad0],
               ['signer other', [c.rc(signer: c::PRINCIPAL)], bad0],
               ['grant other', [c.rc(grant: c::RS)], bad0],
               ['issued at now', [c.rc(issued_at: 1500)], { 'labels' => ['pii'] }],
               ['issued after now', [c.rc(issued_at: 1501)], bad0],
               ['labels understated', [c.rc(labels: [])], bad0],
               ['labels extra', [c.rc(labels: %w[fin pii])], bad0],
               ['dropped excluded', [dropped], { 'labels' => ['pii'] }],
               ['dropped listed', [c.rc(fields: dropped['fields'], labels: %w[pii secret])], bad0],
               ['now neg', [], { 'code' => 'bad_request', 'at' => 0 }]
             ]) { |rcs| chain.call(rcs, rcs.empty? ? -1 : 1500) } &&
        c.rows('now', [['neg', -1], ['nil', nil], ['float', 1.5], ['string', '1']]
                  .map { |n, now| [n, now, { 'code' => 'bad_request', 'at' => 0 }] }) { |now| chain.call([r0], now) } &&
        c.rows('not an array', [['nil', nil], ['hash', {}], ['string', 'x'], ['duck', c::Duck.new([])]]
                  .map { |n, x| [n, x, { 'code' => 'bad_receipt', 'at' => 0 }] }) { |x| chain.call(x) }
    end
    third = c.with_verify(->(_d, b, _s, _g) { b['seq'] != 1 }) do
      c.ck('second signature refused', chain.call([r0, r1]), { 'code' => 'bad_receipt', 'at' => 1 })
    end
    fourth = c.with_verify(false) { c.ck('first signature refused', chain.call([r0]), { 'code' => 'bad_receipt', 'at' => 0 }) }
    fifth = c.with_verify(->(*) { raise 'boom' }) { c.ck('rescue', chain.call([r0, r1]), { 'code' => 'bad_receipt', 'at' => 0 }) }
    first && second && third && fourth && fifth
  end

  # A first receipt is read at the literal key 'prev' (never the empty key): a receipt whose default proc answers the empty key
  # still chains. The stored 'prev' => nil is returned as stored (a default proc only runs for a missing key).
  t('c25 readside: read_chain_labels reads the first receipt at the key prev, not at a default-proc key') do
    next true if C25.skip?

    c = C25
    h = Hash.new { |_hash, key| key == '' ? 'zz' : nil }
    c.rc.each { |k, v| h[k] = v }
    c.with_verify(true) do
      c.ck('first receipt with default proc', AtlasPca.read_chain_labels([h], c::RS, c::PRINCIPAL, 1500), { 'labels' => ['pii'] })
    end
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  # check_sink
  # ---------------------------------------------------------------------------------------------------------------------------
  t('c25 readside: check_sink input checks and the rescue are exact') do
    next true if C25.skip?

    c = C25
    ap = AtlasPca
    inp = ->(**o) { { 'grant' => c.sg, 'principal' => c::PRINCIPAL, 'rs_signer' => c::RS, 'now' => 1500, 'sink' => 'ext', 'receipts' => [] }.merge(o.transform_keys(&:to_s)) }
    deny = ->(code) { { 'decision' => 'deny', 'code' => code, 'labels' => [] } }
    c.with_verify(true) do
      c.rows('sink', [
               ['ok', inp.call, { 'decision' => 'allow', 'code' => nil, 'labels' => [] }],
               ['sink int', inp.call(sink: 5), deny.call('bad_request')], ['sink nil', inp.call(sink: nil), deny.call('bad_request')],
               ['sink array', inp.call(sink: ['ext']), deny.call('bad_request')],
               ['rs bad', inp.call(rs_signer: 'x'), deny.call('bad_request')],
               ['unknown sink', inp.call(sink: 'zzz'), deny.call('unknown_sink')],
               ['grant nil', inp.call(grant: nil), deny.call('bad_grant')],
               ['receipts bad', inp.call(receipts: nil), deny.call('bad_receipt')]
             ]) { |i| ap.check_sink(i) } &&
        MutationKill::Seam.with(ap, { read_chain_labels: ->(*) { raise 'boom' } }) do
          c.ck('rescue', ap.check_sink(inp.call), { 'decision' => 'deny', 'code' => 'bad_request', 'labels' => [] })
        end
    end
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  # vault
  # ---------------------------------------------------------------------------------------------------------------------------
  t('c25 vault: redact_read_with_vault stores exactly the minted tokens, only on allow') do
    next true if C25.skip?

    c = C25
    ap = AtlasPca
    b = c.body(reads: [c.entry(modes: { 'ref' => 'token', 'pii' => 'last4', 'public' => 'show', 'secret' => 'drop', 'fp' => 'hash' })],
               caps: { 'ref' => 3, 'pii' => 3 })
    fields = { 'cust' => 'ref', 'ssn' => 'pii', 'pub' => 'public', 'sec' => 'secret', 'fp1' => 'fp' }
    record = { 'cust' => 'c_77', 'ssn' => '123456789', 'pub' => 'p', 'sec' => 'zz', 'fp1' => 'f' }
    inp = ->(req = []) { c.rin(grant: c.sg(b), schema: { 'fields' => fields, 'required' => req }, record: record) }
    c.with_verify(true) do
      spy = c::Spy.new
      out = ap.redact_read_with_vault(inp.call, spy)
      tok = out['view']['cust']
      ok1 = c.ck('allow', out['decision'], 'allow') && c.ck('token shape', tok.start_with?('tok_'), true) &&
            c.ck('one put', spy.puts_made, [[tok, { 'cls' => 'ref', 'value' => 'c_77', 'grant' => ap.read_grant_digest(b), 'exp' => 2000 }]]) &&
            c.ck('same as redact_read', out, ap.redact_read(inp.call))
      spy2 = c::Spy.new
      esc = ap.redact_read_with_vault(inp.call(['sec']), spy2)
      ok2 = c.ck('escalate', [esc['decision'], esc['code']], %w[escalate required_dropped]) && c.ck('no put on escalate', spy2.puts_made, [])
      spy3 = c::Spy.new
      bad = ap.redact_read_with_vault(c.rin(grant: nil, schema: c.schema), spy3)
      ok3 = c.ck('deny keeps its code', [bad['decision'], bad['code']], %w[deny bad_grant]) && c.ck('no put on deny', spy3.puts_made, [])
      crafted = { 'decision' => 'allow', 'code' => nil, 'view' => { 'a' => 'v', 'b' => 'w' }, 'labels' => [], 'counts' => {},
                  'fields' => { 'a' => { 'class' => 'c', 'action' => 'shown', 'kind' => 'token', 'vd' => 'x' },
                                'b' => { 'class' => 'c', 'action' => 'dropped', 'kind' => 'token', 'vd' => 'x' } } }
      spy4 = c::Spy.new
      MutationKill::Seam.with(ap, { redact_read: ->(_i) { crafted } }) do
        ap.redact_read_with_vault(c.rin(grant: c.sg(b), record: { 'a' => 1, 'b' => 2 }), spy4)
      end
      ok4 = c.ck('only masked tokens', spy4.puts_made, [])
      spy5 = c::Spy.new
      boom = nil
      MutationKill::Seam.with(ap, {}) { boom = ap.redact_read_with_vault(inp.call, c::BoomPut.new) }
      ok5 = c.ck('store fault', boom, { 'decision' => 'deny', 'code' => 'bad_request', 'view' => {}, 'fields' => {}, 'labels' => [], 'counts' => {} }) &&
            c.ck('unused spy', spy5.puts_made, [])
      ok1 && ok2 && ok3 && ok4 && ok5
    end
  end

  t('c25 vault: detokenize verdicts, expiry boundaries and the rescue are exact') do
    next true if C25.skip?

    c = C25
    ap = AtlasPca
    b = c.body
    digest = ap.read_grant_digest(b)
    mk = lambda do |cls = 'ref', exp = 1800, grant = digest|
      st = ap.memory_vault
      st.put('tok_x', { 'cls' => cls, 'value' => 'c_77', 'grant' => grant, 'exp' => exp })
      st
    end
    inp = ->(st = mk.call, **o) { { 'grant' => c.sg(b), 'principal' => c::PRINCIPAL, 'now' => 1500, 'sink' => 'ext', 'token' => 'tok_x', 'store' => st }.merge(o.transform_keys(&:to_s)) }
    no = ->(code) { { 'decision' => 'deny', 'code' => code, 'value' => nil } }
    log = []
    ok = c.with_verify(true, log) do
      c.rows('detok', [
               ['allow', inp.call, { 'decision' => 'allow', 'code' => nil, 'value' => 'c_77' }],
               ['escalate', inp.call(mk.call('fp')), { 'decision' => 'escalate', 'code' => 'label_escalate', 'value' => nil }],
               ['label flow', inp.call(mk.call('pii')), no.call('label_flow')],
               ['int sink allows pii', inp.call(mk.call('pii'), sink: 'int'), { 'decision' => 'allow', 'code' => nil, 'value' => 'c_77' }],
               ['unknown sink', inp.call(sink: 'zzz'), no.call('unknown_sink')],
               ['principal bad', inp.call(principal: 'x'), no.call('bad_request')], ['principal nil', inp.call(principal: nil), no.call('bad_request')],
               ['now neg', inp.call(now: -1), no.call('bad_request')], ['now nil', inp.call(now: nil), no.call('bad_request')],
               ['token int', inp.call(token: 5), no.call('bad_request')], ['token nil', inp.call(token: nil), no.call('bad_request')],
               ['sink int', inp.call(sink: 5), no.call('bad_request')], ['sink nil', inp.call(sink: nil), no.call('bad_request')],
               ['grant nil', inp.call(grant: nil), no.call('bad_grant')], ['grant duck', inp.call(grant: c::Duck.new(c.sg(b))), no.call('bad_grant')],
               ['grant extra', inp.call(grant: c.sg(b).merge('z' => 1)), no.call('bad_grant')],
               ['grant no sig', inp.call(grant: { 'body' => b }), no.call('bad_grant')],
               ['grant bad body', inp.call(grant: c.sg(c.body(v: 2))), no.call('bad_grant')],
               ['other principal', inp.call(principal: c::RS), no.call('bad_signature')],
               ['not yet', inp.call(now: 999), no.call('not_yet')],
               ['at issued', inp.call(mk.call('ref', 5000), now: 1000), { 'decision' => 'allow', 'code' => nil, 'value' => 'c_77' }],
               ['grant expired, token unknown', inp.call(token: 'nope', now: 2000), no.call('expired')],
               ['grant long expired, token unknown', inp.call(token: 'nope', now: 2001), no.call('expired')],
               ['token unknown', inp.call(token: 'nope'), no.call('unknown_token')],
               ['token of another grant', inp.call(mk.call('ref', 1800, c::RS)), no.call('unknown_token')],
               ['token last valid', inp.call(mk.call('ref', 1800), now: 1799), { 'decision' => 'allow', 'code' => nil, 'value' => 'c_77' }],
               ['token expires', inp.call(mk.call('ref', 1800), now: 1800), no.call('expired')],
               ['token expired', inp.call(mk.call('ref', 1800), now: 1900), no.call('expired')]
             ]) { |i| ap.detokenize(i) } &&
        c.ck('verify args', log[0], [ap::READ_GRANT_DOMAIN, b, c::PRINCIPAL, 'x'])
    end
    sig = c.with_verify(false) { c.ck('signature refused', ap.detokenize(inp.call), no.call('bad_signature')) }
    rescued = c.with_verify(true) do
      c.ck('rescue', ap.detokenize(inp.call(c::BoomGet.new)), { 'decision' => 'deny', 'code' => 'bad_request', 'value' => nil })
    end
    ok && sig && rescued
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  # draw source, bernoulli, laplace
  # ---------------------------------------------------------------------------------------------------------------------------
  t('c25 vault: uniform bounds and exact error text') do
    next true if C25.skip?

    c = C25
    ap = AtlasPca
    err = lambda do |n|
      ap.seeded_draws('s').uniform(n)
      nil
    rescue RangeError => e
      e.message
    end
    c.rows('bad bound', [['zero', 0], ['neg', -1], ['float', 1.5], ['nil', nil], ['over', (2**47) + 1]]
              .map { |n, x| [n, x, 'uniform: bad bound'] }) { |x| err.call(x) } &&
      c.ck('bound 1', ap.seeded_draws('s').uniform(1), 0) &&
      c.ck('bound 2**47 in range', ap.seeded_draws('s').uniform(2**47).between?(0, (2**47) - 1), true)
  end

  t('c25 vault: uniform rejects r >= limit (strictly), never exceeds the step cap, and says so') do
    next true if C25.skip?

    c = C25
    ap = AtlasPca
    top = (2**48) - 1 # limit for n = 3 is 2**48 - 1
    d = ap.seeded_draws('s')
    seq = [top, 5]
    d.define_singleton_method(:next48) { seq.shift }
    first = c.ck('r == limit is rejected', d.uniform(3), 2)
    d2 = ap.seeded_draws('s')
    n = 0
    d2.define_singleton_method(:next48) do
      n += 1
      top
    end
    msg = begin
      d2.uniform(3)
      nil
    rescue RangeError => e
      e.message
    end
    first && c.ck('no draw message', msg, 'uniform: no draw') && c.ck('tried exactly the cap', n, 100_000)
  end

  t('c25 vault: bernoulli and laplace give up after exactly the step cap, with exact text') do
    next true if C25.skip?

    c = C25
    ap = AtlasPca
    bern = c::Scripted.new { |_i, _n| 0 }
    msg = begin
      Timeout.timeout(2) { ap.k5_bern_exp_small(bern, 1, 1) }
      nil
    rescue RangeError => e
      e.message
    end
    r1 = c.ck('bernoulli message', msg, 'bernoulli: no termination') && c.ck('bernoulli draws', bern.calls, 100_000)
    lap = c::Scripted.new { |_i, n| n == 3 ? 1 : 0 }
    msg2 = begin
      Timeout.timeout(2) { ap.discrete_laplace(lap, 1, 1) }
      nil
    rescue RangeError => e
      e.message
    end
    r2 = c.ck('laplace message', msg2, 'laplace: no termination') && c.ck('laplace draws', lap.calls, 2 + (3 * 100_001))
    nosample = c::Scripted.new { |i, _n| [1, 0, 3][(i - 1) % 3] }
    msg3 = begin
      Timeout.timeout(2) { ap.discrete_laplace(nosample, 1, 2) }
      nil
    rescue RangeError => e
      e.message
    end
    r1 && r2 && c.ck('no sample message', msg3, 'laplace: no sample') && c.ck('no sample draws', nosample.calls, 300_000)
  end

  t('c25 vault: secure_draws seeds from 32 fresh random bytes; empty_aggregate_state is exact') do
    next true if C25.skip?

    c = C25
    ap = AtlasPca
    a = ap.secure_draws
    b = ap.secure_draws
    sa = a.instance_variable_get(:@seed)
    sb = b.instance_variable_get(:@seed)
    c.ck('class', a.class, ap::SeededDraws) && c.ck('seed 32 bytes', ap.b64d(sa, 32).nil?, false) && c.ck('fresh', sa == sb, false) &&
      c.ck('empty state', ap.empty_aggregate_state, { 'spent_micro' => 0, 'queries' => 0, 'answered' => {} })
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  # aggregates: validators
  # ---------------------------------------------------------------------------------------------------------------------------
  t('c25 vault: k5_valid_agg_rule? decides every operand and every limit') do
    next true if C25.skip?

    c = C25
    v = ->(r) { AtlasPca.k5_valid_agg_rule?(r) }
    c.rows('agg rule', [
             ['base', c.arule, true],
             ['nil', nil, false], ['array', [], false], ['duck', c::Duck.new(c.arule), false],
             ['extra', c.arule.merge('x' => 1), false], ['missing', c.arule.reject { |k, _| k == 'dp' }, false],
             ['verb empty', c.arule(verb: ''), false], ['verb 128', c.arule(verb: 'a' * 128), true], ['verb 129', c.arule(verb: 'a' * 129), false],
             ['prefix empty', c.arule(resource_prefix: ''), false], ['prefix 512', c.arule(resource_prefix: 'a' * 512), true],
             ['prefix 513', c.arule(resource_prefix: 'a' * 513), false],
             ['purposes empty', c.arule(purposes: []), false], ['purposes 16', c.arule(purposes: c.labels('p', 16)), true],
             ['purposes 17', c.arule(purposes: c.labels('p', 17)), false], ['purposes unsorted', c.arule(purposes: %w[b a]), false],
             ['fns empty', c.arule(fns: []), false], ['fns count', c.arule(fns: ['count']), true], ['fns both', c.arule(fns: %w[count sum]), true],
             ['fns unsorted', c.arule(fns: %w[sum count]), false], ['fns dup', c.arule(fns: %w[count count]), false],
             ['fns avg', c.arule(fns: ['avg']), false],
             ['min_group string', c.arule(min_group: 'x'), false], ['min_group 0', c.arule(min_group: 0), false],
             ['min_group 1', c.arule(min_group: 1), true], ['min_group neg', c.arule(min_group: -1), false],
             ['clamp neg', c.arule(clamp: -1), false], ['clamp 1M', c.arule(clamp: 1_000_000), true],
             ['clamp over', c.arule(clamp: 1_000_001), false], ['clamp string', c.arule(clamp: 'x'), false],
             ['eps neg', c.arule(epsilon_micro: -1), false], ['eps max', c.arule(epsilon_micro: 1_073_741_824), true],
             ['eps over', c.arule(epsilon_micro: 1_073_741_825), false],
             ['dp nil', c.arule(dp: nil), false], ['dp string', c.arule(dp: 'true'), false], ['dp int', c.arule(dp: 1), false],
             ['dp true eps 0', c.arule(dp: true, epsilon_micro: 0), false], ['dp true eps 1', c.arule(dp: true, epsilon_micro: 1), true],
             ['dp true eps 2', c.arule(dp: true, epsilon_micro: 2), true], ['dp false eps 0', c.arule(dp: false, epsilon_micro: 0), true],
             ['dp true eps max', c.arule(dp: true, epsilon_micro: 1_073_741_824), true]
           ]) { |r| v.call(r) }
  end

  t('c25 vault: valid_aggregate_grant_body? decides every operand and every limit') do
    next true if C25.skip?

    c = C25
    v = ->(b) { AtlasPca.valid_aggregate_grant_body?(b) }
    c.rows('agg body', [
             ['base', c.abody, true],
             ['nil', nil, false], ['array', [], false], ['duck', c::Duck.new(c.abody), false],
             ['extra', c.abody.merge('x' => 1), false], ['missing', c.abody.reject { |k, _| k == 'rules' }, false],
             ['v 2', c.abody(v: 2), false], ['id bad', c.abody(id: 'bad id'), false], ['principal bad', c.abody(principal: 'x'), false],
             ['issued neg', c.abody(issued_at: -1), false], ['expires neg', c.abody(expires_at: -1), false],
             ['rules empty', c.abody(rules: []), false], ['rules hash', c.abody(rules: {}), false], ['rules nil', c.abody(rules: nil), false],
             ['rules duck', c.abody(rules: c::Duck.new([c.arule])), false],
             ['rules 1', c.abody(rules: [c.arule]), true], ['rules 16', c.abody(rules: Array.new(16) { c.arule }), true],
             ['rules 17', c.abody(rules: Array.new(17) { c.arule }), false],
             ['rules bad', c.abody(rules: [c.arule, c.arule(dp: nil)]), false],
             ['budget neg', c.abody(epsilon_budget_micro: -1), false], ['budget string', c.abody(epsilon_budget_micro: 'x'), false],
             ['max_queries neg', c.abody(max_queries: -1), false], ['max_queries string', c.abody(max_queries: 'x'), false]
           ]) { |b| v.call(b) }
  end

  # ---------------------------------------------------------------------------------------------------------------------------
  # aggregate_read
  # ---------------------------------------------------------------------------------------------------------------------------
  t('c25 vault: aggregate_read refusals are exact (code, state kept or empty, charge 0)') do
    next true if C25.skip?

    c = C25
    ap = AtlasPca
    st = c.astate
    run = ->(i) { ap.aggregate_read(i) }
    keep = ->(code) { c.afail(code, st) }
    drop = ->(code) { c.afail(code, c.empty_state) }
    rule128 = c.abody(rules: [c.arule(verb: 'v' * 128)])
    rule512 = c.abody(rules: [c.arule(resource_prefix: 'orders/')])
    allow_code = ->(i) { r = ap.aggregate_read(i); [r['decision'], r['code']] }
    ok = c.with_verify(true) do
      c.rows('agg refusals', [
               ['state nil', c.ain(state: nil), drop.call('bad_request')],
               ['state duck', c.ain(state: c::Duck.new(c.astate)), drop.call('bad_request')],
               ['spent neg', c.ain(state: c.astate(spent_micro: -1)), drop.call('bad_request')],
               ['queries neg', c.ain(state: c.astate(queries: -1)), drop.call('bad_request')],
               ['answered array', c.ain(state: c.astate(answered: [])), drop.call('bad_request')],
               ['answered duck', c.ain(state: c.astate(answered: c::Duck.new({}))), drop.call('bad_request')],
               ['answered string', c.ain(state: c.astate(answered: { 'q' => 'x' })), drop.call('bad_request')],
               ['answered float', c.ain(state: c.astate(answered: { 'q' => 5.5 })), drop.call('bad_request')],
               ['answered over', c.ain(state: c.astate(answered: { 'q' => c::MAXS + 1 })), drop.call('bad_request')],
               ['answered under', c.ain(state: c.astate(answered: { 'q' => -(c::MAXS + 1) })), drop.call('bad_request')],
               ['principal bad', c.ain(principal: 'x'), keep.call('bad_request')],
               ['principal nil', c.ain(principal: nil), keep.call('bad_request')],
               ['now neg', c.ain(now: -1), keep.call('bad_request')], ['now nil', c.ain(now: nil), keep.call('bad_request')],
               ['grant nil', c.ain(grant: nil), keep.call('bad_grant')], ['grant duck', c.ain(grant: c::Duck.new({ 'body' => c.abody, 'sig' => 'x' })), keep.call('bad_grant')],
               ['grant extra', c.ain(grant: { 'body' => c.abody, 'sig' => 'x', 'z' => 1 }), keep.call('bad_grant')],
               ['grant no sig', c.ain(grant: { 'body' => c.abody }), keep.call('bad_grant')],
               ['grant bad body', c.ain(grant: { 'body' => c.abody(v: 2), 'sig' => 'x' }), keep.call('bad_grant')],
               ['other principal', c.ain(principal: c::RS), keep.call('bad_signature')],
               ['not yet', c.ain(now: 999), keep.call('not_yet')],
               ['expires', c.ain(now: 2000), keep.call('expired')], ['after expires', c.ain(now: 2001), keep.call('expired')],
               ['verb empty', c.ain(verb: ''), keep.call('bad_request')], ['verb 129', c.ain(verb: 'v' * 129), keep.call('bad_request')],
               ['resource empty', c.ain(resource: ''), keep.call('bad_request')],
               ['resource 513', c.ain(resource: "orders/#{'a' * 506}"), keep.call('bad_request')],
               ['purpose bad', c.ain(purpose: 'bad id'), keep.call('bad_request')],
               ['fn avg', c.ain(fn: 'avg'), keep.call('bad_request')], ['fn nil', c.ain(fn: nil), keep.call('bad_request')],
               ['noise other', c.ain(noise: 'other'), keep.call('bad_request')], ['noise nil', c.ain(noise: nil), keep.call('bad_request')],
               ['salt nil', c.ain(salt: nil), keep.call('bad_request')], ['salt int', c.ain(salt: 5), keep.call('bad_request')],
               ['salt 15', c.ain(salt: 'x' * 15), keep.call('bad_request')],
               ['values nil', c.ain(values: nil), keep.call('bad_request')], ['values hash', c.ain(values: {}), keep.call('bad_request')],
               ['values string', c.ain(values: 'abc'), keep.call('bad_request')],
               ['values float', c.ain(values: [1, 1.5]), keep.call('bad_request')],
               ['values over', c.ain(values: [1, c::MAXS + 1]), keep.call('bad_request')],
               ['values under', c.ain(values: [1, -(c::MAXS + 1)]), keep.call('bad_request')],
               ['values 1M+1', c.ain(values: c::FakeLen.new([1, 2], 1_000_001)), keep.call('bad_request')],
               ['verb outside rule', c.ain(verb: 'orders.other'), keep.call('no_read_scope')],
               ['resource outside prefix', c.ain(resource: 'other/9'), keep.call('no_read_scope')],
               ['purpose outside rule', c.ain(purpose: 'other'), keep.call('no_read_scope')],
               ['fn outside rule', c.ain(grant: { 'body' => c.abody(rules: [c.arule(fns: ['count'])]), 'sig' => 'x' }, fn: 'sum'), keep.call('no_read_scope')],
               ['group too small', c.ain(values: [1]), keep.call('group_too_small')],
               ['query cap', c.ain(state: c.astate(queries: 3)), c.afail('query_cap', c.astate(queries: 3))],
               ['epsilon exhausted', c.ain(grant: { 'body' => c.abody(rules: [c.arule(dp: true)]), 'sig' => 'x' }, state: c.astate(spent_micro: 9_500_001)),
                c.afail('epsilon_exhausted', c.astate(spent_micro: 9_500_001))]
             ].map { |n, i, w| [n, i, w] }) { |i| run.call(i) } &&
        c.ck('verb 128 passes', allow_code.call(c.ain(grant: { 'body' => rule128, 'sig' => 'x' }, verb: 'v' * 128)), %w[allow] + [nil]) &&
        c.ck('resource 512 passes', allow_code.call(c.ain(grant: { 'body' => rule512, 'sig' => 'x' }, resource: "orders/#{'a' * 505}")), %w[allow] + [nil]) &&
        c.ck('salt 16 passes', allow_code.call(c.ain(salt: 'x' * 16)), %w[allow] + [nil]) &&
        c.ck('at issued passes', allow_code.call(c.ain(now: 1000)), %w[allow] + [nil]) &&
        c.ck('answered at max passes', allow_code.call(c.ain(state: c.astate(answered: { 'q' => c::MAXS }))), %w[allow] + [nil]) &&
        c.ck('answered at -max passes', allow_code.call(c.ain(state: c.astate(answered: { 'q' => -c::MAXS }))), %w[allow] + [nil]) &&
        c.ck('values at max pass', allow_code.call(c.ain(values: [1, c::MAXS, -c::MAXS])), %w[allow] + [nil]) &&
        c.ck('two values meet min_group', allow_code.call(c.ain(values: [1, 2])), %w[allow] + [nil]) &&
        c.ck('last query before the cap', allow_code.call(c.ain(state: c.astate(queries: 2))), %w[allow] + [nil]) &&
        c.ck('budget exactly met', allow_code.call(c.ain(grant: { 'body' => c.abody(rules: [c.arule(dp: true)]), 'sig' => 'x' },
                                                           state: c.astate(spent_micro: 9_500_000))), %w[allow] + [nil])
    end
    sig = c.with_verify(false) { c.ck('signature refused', run.call(c.ain), keep.call('bad_signature')) }
    ok && sig
  end

  t('c25 vault: aggregate_read accepts exactly 1_000_000 values (length cap)') do
    next true if C25.skip?

    c = C25
    c.with_verify(true) do
      r = AtlasPca.aggregate_read(c.ain(values: c::FakeLen.new([1, 2], 1_000_000)))
      c.ck('1M accepted', [r['decision'], r['code'], r['value']], ['allow', nil, 1_000_000])
    end
  end

  t('c25 vault: aggregate_read answers, charges, and replays exactly') do
    next true if C25.skip?

    c = C25
    ap = AtlasPca
    c.with_verify(true) do
      inp = c.ain
      g = inp['grant']['body']
      rule = g['rules'][0]
      qd = c.agg_qd(g, inp, rule)
      r = ap.aggregate_read(inp)
      want_state = { 'spent_micro' => 7, 'queries' => 1, 'answered' => { qd => 3 } }
      ok1 = c.ck('count', r, { 'decision' => 'allow', 'code' => nil, 'value' => 3, 'state' => want_state, 'charged_micro' => 0 }) &&
            c.ck('input state untouched', inp['state'], c.astate)
      again = ap.aggregate_read(c.ain(state: r['state']))
      ok2 = c.ck('replay', again, { 'decision' => 'allow', 'code' => nil, 'value' => 3, 'state' => want_state, 'charged_micro' => 0 })
      sum_in = c.ain(fn: 'sum', values: [1, 2, 300, -400])
      sum = ap.aggregate_read(sum_in)
      ok3 = c.ck('clamped sum', [sum['decision'], sum['value'], sum['charged_micro']], ['allow', 1 + 2 + 100 - 100, 0])
      dpg = c.abody(rules: [c.arule(dp: true)])
      dpi = c.ain(grant: { 'body' => dpg, 'sig' => 'x' })
      dq = c.agg_qd(dpg, dpi, dpg['rules'][0])
      noise = ap.discrete_laplace(ap.seeded_draws(ap.hash_canonical({ 'd' => 'atlas-pca/aggregate-noise/v1', 'salt' => c::SALT, 'q' => dq })), 500_000, 1_000_000)
      dr = ap.aggregate_read(dpi)
      ok4 = c.ck('dp answer', dr, { 'decision' => 'allow', 'code' => nil, 'value' => 3 + noise,
                                     'state' => { 'spent_micro' => 7 + 500_000, 'queries' => 1, 'answered' => { dq => 3 + noise } }, 'charged_micro' => 500_000 })
      ok1 && ok2 && ok3 && ok4
    end
  end

  t('c25 vault: aggregate_read a fault inside is exactly deny bad_request with the empty state') do
    next true if C25.skip?

    c = C25
    c.with_verify(true) do
      MutationKill::Seam.with(AtlasPca, { aggregate_grant_digest: ->(_g) { raise 'boom' } }) do
        c.ck('rescue', AtlasPca.aggregate_read(c.ain), { 'decision' => 'deny', 'code' => 'bad_request', 'value' => nil,
                                                          'state' => { 'spent_micro' => 0, 'queries' => 0, 'answered' => {} }, 'charged_micro' => 0 })
      end
    end
  end
end
