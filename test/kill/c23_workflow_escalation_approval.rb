# frozen_string_literal: true

# Kill tests for lib/atlas_pca/{workflow,escalation,approval}.rb (round 2, agent c23). Expected values pin the TypeScript
# references packages/pca/src/{workflow,escalation,approval-render}.ts + packages/pca-actions/src/approval-render.ts and the
# shared vectors. Every AtlasPca constant / module is resolved at CALL time inside the test blocks (the oracle re-evaluates
# AtlasPca for every mutant). Signed fixtures (Ed25519 keys, signed workflows and receipts) are built with OpenSSL and
# the canonical encoder only, never with the code under mutation.
require 'openssl'
require 'base64'
require 'digest'
require 'delegate'
require 'timeout'
require 'json'

module MutationKill
  module C23Wea
    module_function

    FD = "atlas-pca/workflow/v1\x00".b
    RD = "atlas-pca/wf-receipt/v1\x00".b
    MAX = 9_007_199_254_740_991

    class StrDuck
      def initialize(s)
        @s = s
      end

      def valid_encoding?
        true
      end

      def to_str
        @s
      end
    end

    class OpDuck
      def to_str
        'eq'
      end

      def ==(_other)
        true
      end
    end

    class RaisingHash < Hash
      def [](_k)
        raise 'c23 boom'
      end
    end

    def skip?(*names) = (f = ENV['MUT_FILE']) && !f.empty? && !names.include?(f)

    def eq(label, got, want)
      return true if got == want && got.class == want.class

      raise "c23 #{label}: got #{got.inspect}, want #{want.inspect}"
    end

    def table(label, fn, rows)
      rows.each { |i, want| eq("#{label} #{i.inspect[0, 80]}", fn.call(i), want) }
      true
    end

    def key(l)
      @keys ||= {}
      @keys[l] ||= OpenSSL::PKey.new_raw_private_key('ED25519', Digest::SHA256.digest("c23/#{l}"))
    end

    def b64u(bin) = Base64.urlsafe_encode64(bin, padding: false).force_encoding(Encoding::UTF_8)
    def pub(l) = b64u(key(l).raw_public_key)
    def dg(n) = b64u(Digest::SHA256.digest("c23-dg/#{n}"))
    def canon(v) = AtlasPca.canon_bytes(v)
    def hc(v) = b64u(Digest::SHA256.digest(canon(v)))
    def sign(dom, body, l) = b64u(key(l).sign(nil, dom + canon(body)))
    def many(n, pre = 'k') = (0...n).to_h { |i| [format("#{pre}%02d", i), 1] }
    def ids(n, pre = 'd') = (0...n).map { |i| format("#{pre}%02d", i) }

    def step_h(id, deps: [], verb: 'v', resource: 'r', pd: nil, sink: nil, deny: [], esc: [], fresh: nil, cost: {})
      { 'id' => id, 'verb' => verb, 'resource' => resource, 'params_digest' => pd, 'deps' => deps, 'sink' => sink,
        'deny_labels' => deny, 'escalate_labels' => esc, 'fresh_ms' => fresh, 'cost' => cost }
    end

    def edge_h(from, field, to, param, op: 'eq', unit: nil, deny: [], promise: nil)
      { 'from' => { 'step' => from, 'field' => field }, 'to' => { 'step' => to, 'param' => param }, 'op' => op, 'unit' => unit,
        'deny_labels' => deny, 'promise' => promise }
    end

    def body_h(steps, edges = [], max: 10, caps: {}, iat: 1000, exp: 5000, root: nil, goal: nil)
      { 'v' => 1, 'id' => 'wf', 'principal' => pub('p'), 'goal_digest' => goal, 'plan_root' => root, 'issued_at' => iat,
        'expires_at' => exp, 'steps' => steps, 'edges' => edges, 'budget' => { 'max_steps' => max, 'caps' => caps } }
    end

    # a shape-valid body (two steps, one edge, one cap)
    def vb(over = {})
      body_h([step_h('a', cost: { 'tok' => 1 }), step_h('b', deps: ['a'], cost: { 'tok' => 1 })], [edge_h('a', 'x', 'b', 'p')],
             max: 3, caps: { 'tok' => 5 }, root: dg('root'), goal: dg('goal')).merge(over)
    end

    def wf_digest(b) = hc({ 'd' => 'atlas-pca/workflow-ref/v1', 'w' => b })
    def val_digest(v) = hc({ 'd' => 'atlas-pca/wf-value/v1', 'v' => v })
    def rref(r) = hc({ 'd' => 'atlas-pca/wf-receipt-ref/v1', 'r' => r })

    def out_h(val = nil, num: nil, unit: nil, labels: [])
      { 'digest' => val_digest(val), 'num' => num, 'unit' => unit, 'labels' => labels }
    end

    def rcpt(b, step, seq, prev, outputs: {}, outcome: 'ok', pd: nil, at: 2000)
      r = { 'v' => 1, 'wf' => wf_digest(b), 'step' => step, 'seq' => seq, 'prev' => prev && rref(prev), 'outcome' => outcome,
            'params_digest' => pd || dg('pd'), 'outputs' => outputs, 'issued_at' => at, 'signer' => pub('rs') }
      r.merge('sig' => sign(RD, r, 'rs'))
    end

    def req_h(step, params: {}, units: {}, verb: 'v', resource: 'r')
      { 'step' => step, 'verb' => verb, 'resource' => resource, 'params' => params, 'units' => units, 'goal_digest' => nil, 'plan_root' => nil }
    end

    def inp(b, receipts, req, now: 3000)
      { 'workflow' => { 'body' => b, 'sig' => sign(FD, b, 'p') }, 'principal' => pub('p'), 'rs_signer' => pub('rs'),
        'receipts' => receipts, 'now' => now, 'request' => req }
    end

    def res(decision, code, step, at = nil, pending = [])
      { 'decision' => decision, 'code' => code, 'step' => step, 'at' => at, 'pending' => pending }
    end

    def rsh(over = {})
      { 'v' => 1, 'wf' => dg('wf'), 'step' => 'a', 'seq' => 0, 'prev' => nil, 'outcome' => 'ok', 'params_digest' => dg('pd'),
        'outputs' => {}, 'issued_at' => 5, 'signer' => pub('rs'), 'sig' => 'sig' }.merge(over)
    end

    def oh(over = {}) = { 'digest' => dg('o'), 'num' => nil, 'unit' => nil, 'labels' => [] }.merge(over)
    def qsh(over = {}) = req_h('a', params: { 'p' => 1 }, units: { 'p' => 'usd' }).merge(over)
    def duck(h) = SimpleDelegator.new(h)

    def st(id, deps = []) = { 'id' => id, 'deps' => deps }
    def eg(from, to) = { 'from' => { 'step' => from }, 'to' => { 'step' => to } }

    def pra(w, p = pub('p'), now = 3000, root = dg('root')) = AtlasPca.plan_root_authorized?(w, p, now, root)
  end

  # ---------------------------------------------------------------------------------------------------------------- constants
  t('c23 workflow: domains are frozen binary strings, limits are exact') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    c.eq('wd', m::WORKFLOW_DOMAIN, "atlas-pca/workflow/v1\x00".b) && c.eq('wd enc', m::WORKFLOW_DOMAIN.encoding, Encoding::BINARY) &&
      c.eq('wd frozen', m::WORKFLOW_DOMAIN.frozen?, true) && c.eq('rd', m::WF_RECEIPT_DOMAIN, "atlas-pca/wf-receipt/v1\x00".b) &&
      c.eq('rd enc', m::WF_RECEIPT_DOMAIN.encoding, Encoding::BINARY) && c.eq('rd frozen', m::WF_RECEIPT_DOMAIN.frozen?, true) &&
      c.eq('limits', m::WORKFLOW_LIMITS, { steps: 64, edges: 256, deps: 16, labels: 16, fields: 32, cost: 8, id: 64 })
  end

  # ---------------------------------------------------------------------------------------------------------------- primitives
  t('c23 workflow: k5_obj? / k5_uint? / k5_one? / k5_b32? exact booleans') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    c.table('obj', ->(x) { m.k5_obj?(x) }, [[{}, true], [[], false], [nil, false], [1, false], ['h', false]]) &&
      c.table('uint', ->(x) { m.k5_uint?(x) },
              [[0, true], [1, true], [C23Wea::MAX, true], [C23Wea::MAX + 1, false], [-1, false], [1.0, false], [1.5, false], ['1', false],
               [nil, false], [true, false]]) &&
      c.table('one', ->(x) { m.k5_one?(x) }, [[1, true], [1.0, false], [2, false], [0, false], ['1', false], [nil, false], [true, false]]) &&
      c.table('b32', ->(x) { m.k5_b32?(x) },
              [[c.dg('1'), true], ['AAAA', false], ['', false], [5, false], [nil, false], [false, false], [c.dg('1') + '=', false]])
  end

  t('c23 workflow: k5_re? / k5_id? / k5_name? / k5_unit? exact') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    c.table('id', ->(x) { m.k5_id?(x) },
            [['a', true], ['a:b.c-d_E', true], ['a' * 64, true], ['a' * 65, false], ['', false], ['a b', false], ['__proto__', false],
             ['__proto__x', true], [5, false], [nil, false], ["a\xFF", false]]) &&
      c.table('name', ->(x) { m.k5_name?(x) }, [['a.b-c_1', true], ['a:b', false], ['a' * 64, true], ['a' * 65, false], ['', false], ['__proto__', false],
                                                 [5, false], [nil, false]]) &&
      c.table('unit', ->(x) { m.k5_unit?(x) }, [['usd', true], ['a:b', true], ['a' * 16, true], ['a' * 17, false], ['', false], ['a b', false], [5, false]]) &&
      c.table('re', ->(x) { m.k5_re?(x, m::K5_ID_RE) },
              [["a\xFF", false], [5, false], [nil, false], [C23Wea::StrDuck.new('abc'), false], ['abc', true], [:abc, false]])
  end

  t('c23 workflow: k5_null_or / k5_keys? / k5_verify_body') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    c.eq('null_or nil', m.k5_null_or(nil) { false }, true) && c.eq('null_or false', m.k5_null_or(5) { false }, false) &&
      c.eq('null_or true', m.k5_null_or(5) { |x| x == 5 }, true) && c.eq('null_or arg', m.k5_null_or(6) { |x| x == 5 }, false) &&
      c.eq('keys ok', m.k5_keys?({ 'a' => 1, 'b' => 2 }, %w[a b]), true) && c.eq('keys other', m.k5_keys?({ 'a' => 1, 'c' => 2 }, %w[a b]), false) &&
      c.eq('keys fewer', m.k5_keys?({ 'a' => 1 }, %w[a b]), false) && c.eq('keys more', m.k5_keys?({ 'a' => 1, 'b' => 2, 'c' => 3 }, %w[a b]), false) &&
      c.eq('keys empty', m.k5_keys?({}, []), true) &&
      c.eq('keys non-hash raises', (begin; m.k5_keys?([], []); false; rescue NoMethodError; true; end), true) && begin
        b = c.vb
        sg = c.sign(c::FD, b, 'p')
        c.eq('vb ok', m.k5_verify_body(c::FD, b, c.pub('p'), sg), true) && c.eq('vb domain', m.k5_verify_body(c::RD, b, c.pub('p'), sg), false) &&
          c.eq('vb nil signer', m.k5_verify_body(c::FD, b, nil, sg), false) && c.eq('vb int signer', m.k5_verify_body(c::FD, b, 5, sg), false) &&
          c.eq('vb other signer', m.k5_verify_body(c::FD, b, c.pub('rs'), sg), false) && c.eq('vb nil sig', m.k5_verify_body(c::FD, b, c.pub('p'), nil), false) &&
          c.eq('vb bad sig', m.k5_verify_body(c::FD, b, c.pub('p'), 'AAAA'), false) &&
          c.eq('vb other body', m.k5_verify_body(c::FD, b.merge('id' => 'other'), c.pub('p'), sg), false) &&
          c.eq('vb fault under it', Seam.with(AtlasPca, { :k3_verify_body => ->(*) { raise 'c23 boom' } }) { m.k5_verify_body(c::FD, b, c.pub('p'), sg) }, false)
      end
  end

  t('c23 workflow: k5_sorted_unique? exact') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    id = m::K5_ID_RE
    c.table('su', ->(a) { m.k5_sorted_unique?(a[0], a[1], a[2]) },
            [[[[], id, 16], true], [[%w[a], id, 16], true], [[%w[a b], id, 16], true], [[%w[b a], id, 16], false], [[%w[a a], id, 16], false],
             [[['a b'], id, 16], false], [[[5], id, 16], false], [[nil, id, 16], false], [['a', id, 16], false], [[{}, id, 16], false],
             [[c.ids(16), id, 16], true], [[c.ids(17), id, 16], false], [[%w[a b], id, 1], false], [[%w[a], id, 1], true],
             [[%w[B a], id, 16], true], [[%w[a B], id, 16], false], [[%w[A], m::K5_LABEL_RE, 16], false], [[%w[a b], m::K5_LABEL_RE, 16], true],
             [[%w[a a], m::K5_LABEL_RE, 16], false], [[%w[ab a], id, 16], false], [[%w[a ab], id, 16], true], [[["a\xFF"], id, 16], false]])
  end

  t('c23 workflow: k5_scalar? / k5_scalar_map? / k5_uint_map? exact') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    mx = C23Wea::MAX
    c.table('scalar', ->(x) { m.k5_scalar?(x) },
            [['s', true], ['', true], [true, true], [false, true], [0, true], [mx, true], [-mx, true], [mx + 1, false], [-(mx + 1), false], [1.0, false],
             [1.5, false], [nil, false], [[], false], [{}, false]]) &&
      c.table('smap', ->(x) { m.k5_scalar_map?(x) },
              [[{}, true], [c.many(32), true], [c.many(33), false], [nil, false], [[], false], [{ 'a b' => 1 }, false], [{ 'a' => nil }, false],
               [{ 'a' => 1.5 }, false], [{ 'a' => 's', 'b' => true, 'c' => false, 'd' => mx }, true], [{ 'a' => [] }, false],
               [c.many(33).merge('k00' => 'x'), false], [{ 'a b' => 1, 'ok' => 'x' }, false]]) &&
      c.table('umap', ->(x) { m.k5_uint_map?(x, 8) },
              [[{}, true], [c.many(8), true], [c.many(9), false], [nil, false], [[], false], [{ 'a b' => 1 }, false], [{ 'a' => -1 }, false],
               [{ 'a' => 1.0 }, false], [{ 'a' => 0 }, true], [{ 'a' => mx }, true], [{ 'a' => mx + 1 }, false], [{ 'a b' => 1, 'ok' => 2 }, false]]) &&
      c.eq('umap max arg', m.k5_uint_map?(c.many(3), 2), false) && c.eq('umap max arg ok', m.k5_uint_map?(c.many(2), 2), true)
  end

  t('c23 workflow: k5_edge_ok? per operator') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    rows = [['le', 1, 1, true], ['le', 0, 1, true], ['le', 2, 1, false], ['ge', 1, 1, true], ['ge', 2, 1, true], ['ge', 0, 1, false],
            ['lt', 0, 1, true], ['lt', 1, 1, false], ['lt', 2, 1, false], ['gt', 2, 1, true], ['gt', 1, 1, false], ['gt', 0, 1, false],
            ['zz', 2, 1, true], ['zz', 1, 1, false]]
    rows.each { |op, v, n, want| c.eq("edge_ok #{op} #{v} #{n}", m.k5_edge_ok?(op, v, n), want) }
    true
  end

  # ---------------------------------------------------------------------------------------------------------------- shapes
  t('c23 workflow: k5_valid_step? accepts the boundary members and refuses each broken one') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    s = ->(over = {}) { c.step_h('a').merge(over) }
    good = [s.call, s.call('verb' => 'v' * 128), s.call('resource' => 'r' * 512), s.call('deps' => c.ids(16)), s.call('deny_labels' => c.ids(16, 'l')),
            s.call('escalate_labels' => c.ids(16, 'l')), s.call('fresh_ms' => 0), s.call('fresh_ms' => C23Wea::MAX), s.call('cost' => c.many(8)),
            s.call('sink' => 'x'), s.call('params_digest' => c.dg('pd')), s.call('id' => 'a' * 64), s.call('deps' => %w[a b]), s.call('cost' => { 'tok' => 0 })]
    bad = [nil, [], 5, 'step', s.call('zz' => 1), s.call.reject { |k, _| k == 'cost' }, s.call('id' => ''), s.call('id' => 'a b'), s.call('id' => '__proto__'),
           s.call('id' => 'a' * 65), s.call('id' => 5), s.call('id' => nil), s.call('verb' => ''), s.call('verb' => nil), s.call('verb' => 'v' * 129),
           s.call('verb' => 5), s.call('resource' => ''), s.call('resource' => 'r' * 513), s.call('resource' => nil),
           s.call('params_digest' => 'zz'), s.call('params_digest' => 5), s.call('params_digest' => 'AAAA'), s.call('deps' => nil), s.call('deps' => 'a'),
           s.call('deps' => %w[b a]), s.call('deps' => %w[a a]), s.call('deps' => ['a b']), s.call('deps' => [5]), s.call('deps' => c.ids(17)),
           s.call('sink' => 'a b'), s.call('sink' => 5), s.call('deny_labels' => ['B']), s.call('deny_labels' => %w[b a]), s.call('deny_labels' => c.ids(17, 'l')),
           s.call('deny_labels' => nil), s.call('escalate_labels' => ['B']), s.call('escalate_labels' => %w[b a]), s.call('escalate_labels' => c.ids(17, 'l')),
           s.call('escalate_labels' => nil), s.call('fresh_ms' => -1), s.call('fresh_ms' => 1.5), s.call('fresh_ms' => '1'),
           s.call('fresh_ms' => C23Wea::MAX + 1), s.call('cost' => nil), s.call('cost' => []), s.call('cost' => { 'a b' => 1 }), s.call('cost' => { 'a' => -1 }),
           s.call('cost' => { 'a' => 1.5 }), s.call('cost' => c.many(9))]
    good.each_with_index { |x, i| c.eq("step good #{i}", m.k5_valid_step?(x), true) }
    bad.each_with_index { |x, i| c.eq("step bad #{i}", m.k5_valid_step?(x), false) }
    true
  end

  t('c23 workflow: k5_valid_edge? accepts the boundary members and refuses each broken one') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    e = ->(over = {}) { c.edge_h('a', 'x', 'b', 'p').merge(over) }
    good = [e.call, e.call('unit' => 'usd'), e.call('unit' => 'u' * 16), e.call('promise' => 'pr'), e.call('deny_labels' => %w[a b])] +
           m::K5_OPS.map { |op| e.call('op' => op) }
    bad = [nil, [], 5, e.call('zz' => 1), e.call.reject { |k, _| k == 'promise' }, e.call('from' => nil), e.call('from' => %w[step field]),
           e.call('from' => { 'step' => 'a', 'field' => 'x', 'zz' => 1 }), e.call('from' => { 'step' => 'a' }), e.call('from' => { 'step' => 'a b', 'field' => 'x' }),
           e.call('from' => { 'step' => 'a', 'field' => 'a b' }), e.call('to' => nil), e.call('to' => %w[step param]),
           e.call('to' => { 'step' => 'b', 'param' => 'p', 'zz' => 1 }), e.call('to' => { 'step' => 'b' }), e.call('to' => { 'step' => 'a b', 'param' => 'p' }),
           e.call('to' => { 'step' => 'b', 'param' => 'a b' }), e.call('op' => 'zz'), e.call('op' => nil), e.call('op' => 5), e.call('op' => C23Wea::OpDuck.new),
           e.call('unit' => 'a b'), e.call('unit' => 'u' * 17), e.call('unit' => 5), e.call('deny_labels' => ['B']), e.call('deny_labels' => %w[b a]),
           e.call('deny_labels' => nil), e.call('promise' => 'a b'), e.call('promise' => 5)]
    good.each_with_index { |x, i| c.eq("edge good #{i}", m.k5_valid_edge?(x), true) }
    bad.each_with_index { |x, i| c.eq("edge bad #{i}", m.k5_valid_edge?(x), false) }
    true
  end

  t('c23 workflow: valid_workflow_body? accepts the limits and refuses each broken member') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    steps = ->(n) { (0...n).map { |i| c.step_h(format('s%02d', i)) } }
    raising = C23Wea::RaisingHash.new
    c.vb.each { |k, v| raising.store(k, v) }
    good = [c.vb, c.vb('steps' => steps.call(64)), c.vb('steps' => steps.call(1)),
            c.vb('edges' => Array.new(256) { c.edge_h('a', 'x', 'b', 'p') }), c.vb('edges' => []),
            c.vb('budget' => { 'max_steps' => 3, 'caps' => c.many(7).merge('tok' => 5) }), c.vb('goal_digest' => nil, 'plan_root' => nil), c.vb('issued_at' => 0),
            c.vb('expires_at' => C23Wea::MAX), c.vb('budget' => { 'max_steps' => 0, 'caps' => { 'tok' => 0 } })]
    bad = [nil, [], 5, 'x', c.duck(c.vb), raising, c.vb('v' => 2), c.vb('v' => 1.0), c.vb('v' => '1'), c.vb('id' => 'a b'), c.vb('id' => nil),
           c.vb('principal' => 'x'), c.vb('principal' => nil), c.vb('goal_digest' => 'x'), c.vb('plan_root' => 'x'), c.vb('issued_at' => -1),
           c.vb('issued_at' => 1.5), c.vb('expires_at' => 'x'), c.vb('expires_at' => nil), c.vb('zz' => 1), c.vb.reject { |k, _| k == 'budget' },
           c.vb('steps' => []), c.vb('steps' => nil), c.vb('steps' => steps.call(65)), c.vb('steps' => c.duck(c.vb['steps'])),
           c.vb('steps' => [c.step_h('a b')]), c.vb('edges' => nil), c.vb('edges' => Array.new(257) { c.edge_h('a', 'x', 'b', 'p') }),
           c.vb('edges' => c.duck(c.vb['edges'])), c.vb('edges' => [c.edge_h('a', 'x', 'b', 'p', op: 'zz')]), c.vb('budget' => nil),
           c.vb('budget' => c.duck({ 'max_steps' => 3, 'caps' => { 'tok' => 5 } })), c.vb('budget' => { 'max_steps' => 3, 'caps' => { 'tok' => 5 }, 'zz' => 1 }),
           c.vb('budget' => { 'max_steps' => 3 }), c.vb('budget' => { 'max_steps' => -1, 'caps' => { 'tok' => 5 } }),
           c.vb('budget' => { 'max_steps' => 1.5, 'caps' => { 'tok' => 5 } }), c.vb('budget' => { 'max_steps' => 3, 'caps' => nil }),
           c.vb('budget' => { 'max_steps' => 3, 'caps' => c.many(9) }), c.vb('budget' => { 'max_steps' => 3, 'caps' => { 'a b' => 1 } }),
           c.vb('budget' => { 'max_steps' => 3, 'caps' => {} })]
    good.each_with_index { |x, i| c.eq("body good #{i}", m.valid_workflow_body?(x), true) }
    bad.each_with_index { |x, i| c.eq("body bad #{i}", m.valid_workflow_body?(x), false) }
    true
  end

  t('c23 workflow: k5_valid_receipt_shape? accepts the limits and refuses each broken member') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    r1 = ->(over = {}) { c.rsh({ 'seq' => 1, 'prev' => c.dg('prev') }.merge(over)) }
    ents = ->(n) { (0...n).to_h { |i| [format('o%02d', i), c.oh] } }
    good = [c.rsh, r1.call, c.rsh('outcome' => 'failed'), c.rsh('outputs' => { 'o' => c.oh }), c.rsh('outputs' => ents.call(32)),
            c.rsh('outputs' => { 'o' => c.oh('num' => 5, 'unit' => 'usd', 'labels' => %w[a b]) }), c.rsh('sig' => 'x'), c.rsh('issued_at' => 0),
            c.rsh('outputs' => { 'o' => c.oh('num' => 0) }), c.rsh('outputs' => { 'o' => c.oh('labels' => c.ids(16, 'l')) })]
    bad = [nil, [], 5, 'r', c.duck(c.rsh), c.rsh('zz' => 1), c.rsh.reject { |k, _| k == 'sig' }, c.rsh('v' => 2), c.rsh('v' => 1.0), c.rsh('v' => '1'),
           c.rsh('wf' => 'x'), c.rsh('wf' => nil), c.rsh('step' => 'a b'), c.rsh('step' => nil), c.rsh('seq' => -1), c.rsh('seq' => 1.5), c.rsh('seq' => 'x'),
           r1.call('prev' => 'x'), c.rsh('prev' => c.dg('prev')), r1.call('prev' => nil), c.rsh('outcome' => 'maybe'), c.rsh('outcome' => nil),
           c.rsh('outcome' => 5), c.rsh('params_digest' => 'x'), c.rsh('params_digest' => nil), c.rsh('issued_at' => -1), c.rsh('issued_at' => 'x'),
           c.rsh('signer' => 'x'), c.rsh('signer' => nil), c.rsh('sig' => 5), c.rsh('sig' => nil), c.rsh('outputs' => nil), c.rsh('outputs' => []),
           c.rsh('outputs' => ents.call(33)), c.rsh('outputs' => { 'a b' => c.oh }), c.rsh('outputs' => { 'o' => 5 }), c.rsh('outputs' => { 'o' => nil }),
           c.rsh('outputs' => { 'o' => c.oh('zz' => 1) }), c.rsh('outputs' => { 'o' => c.oh.reject { |k, _| k == 'digest' } }),
           c.rsh('outputs' => { 'o' => c.oh('digest' => 'x') }), c.rsh('outputs' => { 'o' => c.oh('num' => -1) }),
           c.rsh('outputs' => { 'o' => c.oh('num' => 1.5) }), c.rsh('outputs' => { 'o' => c.oh('unit' => 'a b') }),
           c.rsh('outputs' => { 'o' => c.oh('labels' => ['B']) }), c.rsh('outputs' => { 'o' => c.oh('labels' => %w[b a]) }),
           c.rsh('outputs' => { 'o' => c.oh('labels' => nil) }), c.rsh('outputs' => { 'o' => c.oh('labels' => c.ids(17, 'l')) })]
    good.each_with_index { |x, i| c.eq("receipt good #{i}", m.k5_valid_receipt_shape?(x), true) }
    bad.each_with_index { |x, i| c.eq("receipt bad #{i}", m.k5_valid_receipt_shape?(x), false) }
    true
  end

  t('c23 workflow: k5_valid_request? accepts the limits and refuses each broken member') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    good = [c.qsh, c.qsh('verb' => 'v' * 128), c.qsh('resource' => 'r' * 512), c.qsh('params' => c.many(32)), c.qsh('params' => {}),
            c.qsh('goal_digest' => c.dg('g'), 'plan_root' => c.dg('p')), c.qsh('units' => {}), c.qsh('units' => { 'p' => 'u' * 16 }),
            c.qsh('params' => { 'a' => 's', 'b' => true, 'c' => false })]
    bad = [nil, [], 5, 'q', c.qsh('zz' => 1), c.qsh.reject { |k, _| k == 'units' }, c.qsh('step' => 'a b'), c.qsh('step' => nil), c.qsh('verb' => ''),
           c.qsh('verb' => 'v' * 129), c.qsh('verb' => nil), c.qsh('resource' => ''), c.qsh('resource' => 'r' * 513), c.qsh('resource' => nil),
           c.qsh('params' => nil), c.qsh('params' => []), c.qsh('params' => c.many(33)), c.qsh('params' => { 'a b' => 1 }), c.qsh('params' => { 'a' => nil }),
           c.qsh('params' => { 'a' => 1.5 }), c.qsh('units' => nil), c.qsh('units' => []), c.qsh('units' => { 'a b' => 'usd' }),
           c.qsh('units' => { 'p' => 'a b' }), c.qsh('units' => { 'p' => 5 }), c.qsh('units' => { 'p' => 'u' * 17 }), c.qsh('goal_digest' => 'x'),
           c.qsh('plan_root' => 'x'), c.qsh('goal_digest' => 5), c.qsh('plan_root' => 5)]
    good.each_with_index { |x, i| c.eq("request good #{i}", m.k5_valid_request?(x), true) }
    bad.each_with_index { |x, i| c.eq("request bad #{i}", m.k5_valid_request?(x), false) }
    true
  end

  # ---------------------------------------------------------------------------------------------------------------- DAG
  t('c23 workflow: wf_ancestors is transitive, nil on a cycle, and caches (deadline on a 50-step ladder)') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    chain = m.wf_ancestors({ 'steps' => [c.st('a'), c.st('b', %w[a]), c.st('c', %w[b])] })
    c.eq('chain', chain.transform_values { |s| s.keys.sort }, { 'a' => [], 'b' => ['a'], 'c' => %w[a b] }) &&
      c.eq('cycle', m.wf_ancestors({ 'steps' => [c.st('a', %w[b]), c.st('b', %w[a])] }), nil) &&
      c.eq('self', m.wf_ancestors({ 'steps' => [c.st('a', %w[a])] }), nil) &&
      c.eq('diamond', m.wf_ancestors({ 'steps' => [c.st('a'), c.st('b', %w[a]), c.st('c', %w[a]), c.st('d', %w[b c])] }).transform_values { |s| s.keys.sort },
           { 'a' => [], 'b' => ['a'], 'c' => ['a'], 'd' => %w[a b c] }) && begin
        ladder = (0...50).map { |i| c.st(format('s%02d', i), [i - 1, i - 2].select { |j| j >= 0 }.map { |j| format('s%02d', j) }) }
        out = Timeout.timeout(2) { m.wf_ancestors({ 'steps' => ladder }) }
        c.eq('ladder', out['s49'].size, 49) && c.eq('ladder low', out['s01'].keys, ['s00'])
      end
  end

  t('c23 workflow: wf_dag_error reports each defect with its exact reason') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    e = 'edge does not follow a dependency'
    ok_steps = [c.st('a'), c.st('b', %w[a]), c.st('c', %w[b])]
    c.eq('dup', m.wf_dag_error({ 'steps' => [c.st('a'), c.st('a')], 'edges' => [] }), 'duplicate step id') &&
      c.eq('unknown dep', m.wf_dag_error({ 'steps' => [c.st('a', %w[z])], 'edges' => [] }), 'bad dependency') &&
      c.eq('self dep', m.wf_dag_error({ 'steps' => [c.st('a', %w[a])], 'edges' => [] }), 'bad dependency') &&
      c.eq('cycle', m.wf_dag_error({ 'steps' => [c.st('a', %w[b]), c.st('b', %w[a])], 'edges' => [] }), 'cycle') &&
      c.eq('no dep edge', m.wf_dag_error({ 'steps' => [c.st('a'), c.st('b')], 'edges' => [c.eg('a', 'b')] }), e) &&
      c.eq('unknown to', m.wf_dag_error({ 'steps' => ok_steps, 'edges' => [c.eg('a', 'z')] }), e) &&
      c.eq('unknown from', m.wf_dag_error({ 'steps' => ok_steps, 'edges' => [c.eg('z', 'b')] }), e) &&
      c.eq('reversed', m.wf_dag_error({ 'steps' => ok_steps, 'edges' => [c.eg('b', 'a')] }), e) &&
      c.eq('valid', m.wf_dag_error({ 'steps' => ok_steps, 'edges' => [c.eg('a', 'b'), c.eg('a', 'c'), c.eg('b', 'c')] }), nil) &&
      c.eq('no edges', m.wf_dag_error({ 'steps' => ok_steps, 'edges' => [] }), nil)
  end

  # ---------------------------------------------------------------------------------------------------------------- plan root
  t('c23 workflow: plan_root_authorized? each condition, boundaries, and the fail-closed rescue') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    b = c.body_h([c.step_h('a')], [], root: c.dg('root'))
    sw = { 'body' => b, 'sig' => c.sign(c::FD, b, 'p') }
    bx = b.merge('zz' => 1)
    swx = { 'body' => bx, 'sig' => c.sign(c::FD, bx, 'p') }
    c.eq('ok', c.pra(sw), true) && c.eq('at issued', c.pra(sw, c.pub('p'), 1000), true) && c.eq('before issued', c.pra(sw, c.pub('p'), 999), false) &&
      c.eq('last tick', c.pra(sw, c.pub('p'), 4999), true) && c.eq('at expiry', c.pra(sw, c.pub('p'), 5000), false) &&
      c.eq('float now', c.pra(sw, c.pub('p'), 3000.0), false) && c.eq('nil now', c.pra(sw, c.pub('p'), nil), false) &&
      c.eq('other root', c.pra(sw, c.pub('p'), 3000, c.dg('other')), false) && c.eq('other principal', c.pra(sw, c.pub('rs')), false) &&
      c.eq('foreign sig', c.pra({ 'body' => b, 'sig' => c.sign(c::FD, b, 'rs') }), false) && c.eq('nil w', c.pra(nil), false) &&
      c.eq('array w', c.pra([]), false) && c.eq('duck w', c.pra(c.duck(sw)), false) && c.eq('invalid body', c.pra(swx), false) &&
      c.eq('cycle', c.pra(begin
        cy = c.body_h([c.step_h('a', deps: ['b']), c.step_h('b', deps: ['a'])], [], root: c.dg('root'))
        { 'body' => cy, 'sig' => c.sign(c::FD, cy, 'p') }
      end), false) &&
      c.eq('rescue', Seam.with(AtlasPca, { :valid_workflow_body? => ->(_b) { raise 'c23 boom' } }) { c.pra(sw) }, false)
  end

  # ---------------------------------------------------------------------------------------------------------------- admission
  t('c23 workflow admit: the clock edges, the total fail-closed guard, and the rescue answers') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    b = c.body_h([c.step_h('a')])
    good = c.inp(b, [], c.req_h('a'))
    bad = c.res('deny', 'bad_workflow', nil)
    c.eq('at issued', m.admit_step(c.inp(b, [], c.req_h('a'), now: 1000)), c.res('allow', nil, 'a')) &&
      c.eq('before issued', m.admit_step(c.inp(b, [], c.req_h('a'), now: 999)), c.res('deny', 'not_yet', 'a')) &&
      c.eq('last tick', m.admit_step(c.inp(b, [], c.req_h('a'), now: 4999)), c.res('allow', nil, 'a')) &&
      c.eq('expired', m.admit_step(c.inp(b, [], c.req_h('a'), now: 5000)), c.res('deny', 'expired', 'a')) &&
      c.eq('extra workflow member', m.admit_step(good.merge('workflow' => good['workflow'].merge('zz' => 1))), bad) &&
      c.eq('workflow not a hash', m.admit_step(good.merge('workflow' => c.duck(good['workflow']))), bad) &&
      c.eq('receipts not an array', m.admit_step(good.merge('receipts' => {})), bad) &&
      c.eq('nil input admit', m.admit_step(nil), bad) && c.eq('nil input bind', m.bind_promises(nil), bad)
  end

  t('c23 workflow admit: spent cost counts the receipts already issued') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    run = lambda do |cap, max|
      b = c.body_h([c.step_h('a', cost: { 'tok' => 3 }), c.step_h('b', deps: ['a'], cost: { 'tok' => 3 })], [], max: max, caps: { 'tok' => cap })
      m.admit_step(c.inp(b, [c.rcpt(b, 'a', 0, nil)], c.req_h('b')))
    end
    c.eq('over cap', run.call(5, 10), c.res('deny', 'budget_exceeded', 'b')) && c.eq('at cap', run.call(6, 10), c.res('allow', nil, 'b')) &&
      c.eq('max steps', run.call(6, 1), c.res('deny', 'budget_exceeded', 'b')) && c.eq('max steps ok', run.call(6, 2), c.res('allow', nil, 'b'))
  end

  t('c23 workflow admit: receipts are checked in order (clock edge, duplicates, promise chains)') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    b = c.body_h([c.step_h('a'), c.step_h('b', deps: ['a'])])
    at_now = m.admit_step(c.inp(b, [c.rcpt(b, 'a', 0, nil, at: 3000)], c.req_h('b')))
    one = c.body_h([c.step_h('a')])
    r0 = c.rcpt(one, 'a', 0, nil)
    dup = m.admit_step(c.inp(one, [r0, c.rcpt(one, 'a', 1, r0)], c.req_h('a')))
    late = m.admit_step(c.inp(b, [c.rcpt(b, 'a', 0, nil, at: 3001)], c.req_h('b')))
    promised = lambda do |edges|
      pb = c.body_h([c.step_h('a'), c.step_h('b', deps: ['a'])], edges)
      m.admit_step(c.inp(pb, [c.rcpt(pb, 'b', 0, nil)], c.req_h('a')))
    end
    c.eq('receipt at now', at_now, c.res('allow', nil, 'b')) && c.eq('receipt after now', late, c.res('deny', 'bad_receipt', 'b', 0)) &&
      c.eq('duplicate step receipt', dup, c.res('deny', 'bad_receipt', 'a', 1)) &&
      c.eq('no edge, no promise', promised.call([]), c.res('deny', 'bad_receipt', 'a', 0)) &&
      c.eq('edge without promise', promised.call([c.edge_h('a', 'x', 'b', 'p')]), c.res('deny', 'bad_receipt', 'a', 0)) &&
      c.eq('edge with promise', promised.call([c.edge_h('a', 'x', 'b', 'p', promise: 'pr')]), c.res('allow', nil, 'a')) &&
      c.eq('mixed edges', promised.call([c.edge_h('a', 'x', 'b', 'p', promise: 'pr'), c.edge_h('a', 'y', 'b', 'q')]), c.res('deny', 'bad_receipt', 'a', 0))
  end

  t('c23 workflow admit: edge checks (missing output, digest, unit, relation, value, taint)') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    run = lambda do |edge, outputs, params, units = {}|
      b = c.body_h([c.step_h('a'), c.step_h('b', deps: ['a'])], [edge])
      m.admit_step(c.inp(b, [c.rcpt(b, 'a', 0, nil, outputs: outputs)], c.req_h('b', params: params, units: units)))
    end
    eqe = c.edge_h('a', 'x', 'b', 'p')
    le = c.edge_h('a', 'x', 'b', 'p', op: 'le')
    allow = c.res('allow', nil, 'b')
    c.eq('output absent', run.call(eqe, {}, { 'p' => 1 }), c.res('deny', 'edge_missing', 'b', 0)) &&
      c.eq('param absent', run.call(eqe, { 'x' => c.out_h(1) }, {}), c.res('deny', 'edge_missing', 'b', 0)) &&
      c.eq('eq ok', run.call(eqe, { 'x' => c.out_h(1) }, { 'p' => 1 }), allow) &&
      c.eq('eq mismatch', run.call(eqe, { 'x' => c.out_h(1) }, { 'p' => 2 }), c.res('deny', 'edge_digest', 'b', 0)) &&
      c.eq('unit differs from request', run.call(eqe, { 'x' => c.out_h(1, unit: 'usd') }, { 'p' => 1 }), c.res('deny', 'edge_unit', 'b', 0)) &&
      c.eq('unit differs from edge', run.call(eqe, { 'x' => c.out_h(1) }, { 'p' => 1 }, { 'p' => 'usd' }), c.res('deny', 'edge_unit', 'b', 0)) &&
      c.eq('unit agrees', run.call(c.edge_h('a', 'x', 'b', 'p', unit: 'usd'), { 'x' => c.out_h(1, unit: 'usd') }, { 'p' => 1 }, { 'p' => 'usd' }), allow) &&
      c.eq('le equal', run.call(le, { 'x' => c.out_h(nil, num: 3) }, { 'p' => 3 }), allow) &&
      c.eq('le over', run.call(le, { 'x' => c.out_h(nil, num: 3) }, { 'p' => 4 }), c.res('deny', 'edge_relation', 'b', 0)) &&
      c.eq('le string value', run.call(le, { 'x' => c.out_h(nil, num: 3) }, { 'p' => 's' }), c.res('deny', 'edge_value', 'b', 0)) &&
      c.eq('le no num', run.call(le, { 'x' => c.out_h(nil, num: nil) }, { 'p' => 1 }), c.res('deny', 'edge_value', 'b', 0)) &&
      c.eq('ge ok', run.call(c.edge_h('a', 'x', 'b', 'p', op: 'ge'), { 'x' => c.out_h(nil, num: 3) }, { 'p' => 3 }), allow) &&
      c.eq('lt equal', run.call(c.edge_h('a', 'x', 'b', 'p', op: 'lt'), { 'x' => c.out_h(nil, num: 3) }, { 'p' => 3 }), c.res('deny', 'edge_relation', 'b', 0)) &&
      c.eq('gt ok', run.call(c.edge_h('a', 'x', 'b', 'p', op: 'gt'), { 'x' => c.out_h(nil, num: 3) }, { 'p' => 4 }), allow)
  end

  t('c23 workflow admit: an edge denies the labels it names, at its own index') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    run = lambda do |labels|
      edges = [c.edge_h('a', 'x', 'b', 'p'), c.edge_h('a', 'y', 'b', 'q', deny: ['sec'])]
      b = c.body_h([c.step_h('a'), c.step_h('b', deps: ['a'])], edges)
      outs = { 'x' => c.out_h('A'), 'y' => c.out_h('B', labels: labels) }
      m.admit_step(c.inp(b, [c.rcpt(b, 'a', 0, nil, outputs: outs)], c.req_h('b', params: { 'p' => 'A', 'q' => 'B' })))
    end
    c.eq('named', run.call(['sec']), c.res('deny', 'taint_flow', 'b', 1)) && c.eq('named among others', run.call(%w[oth sec]), c.res('deny', 'taint_flow', 'b', 1)) &&
      c.eq('other label', run.call(['oth']), c.res('allow', nil, 'b')) && c.eq('no label', run.call([]), c.res('allow', nil, 'b'))
  end

  t('c23 workflow admit/bind: a dependency without a receipt, pending edges and promise binding') do
    next true if C23Wea.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    # a missing dependency with no edge at all
    nb = c.body_h([c.step_h('a'), c.step_h('b', deps: ['a'])])
    no_edge = m.admit_step(c.inp(nb, [], c.req_h('b')))
    # c depends on a and b; b's receipt is promised
    steps = [c.step_h('a'), c.step_h('b'), c.step_h('c', deps: %w[a b])]
    edges = [c.edge_h('a', 'x', 'c', 'p'), c.edge_h('b', 'y', 'c', 'q', promise: 'pr')]
    b = c.body_h(steps, edges)
    ra = c.rcpt(b, 'a', 0, nil, outputs: { 'x' => c.out_h('GOOD') })
    wrong = { 'p' => 'WRONG', 'q' => 'Q' }
    rc = c.rcpt(b, 'c', 1, ra, pd: c.hc(wrong))
    bound = m.bind_promises(c.inp(b, [ra, rc], c.req_h('c', params: wrong)))
    admitted = m.admit_step(c.inp(b, [ra], c.req_h('c', params: { 'p' => 'GOOD', 'q' => 'Q' })))
    # g -> d -> c, g's receipt never issued; c has an edge from g
    steps2 = [c.step_h('g'), c.step_h('d', deps: ['g']), c.step_h('c', deps: ['d'])]
    edges2 = [c.edge_h('g', 'x', 'd', 'p', promise: 'pr'), c.edge_h('g', 'y', 'c', 'q')]
    b2 = c.body_h(steps2, edges2)
    rd = c.rcpt(b2, 'd', 0, nil)
    q2 = { 'q' => 'zz' }
    rc2 = c.rcpt(b2, 'c', 1, rd, pd: c.hc(q2))
    pend = m.admit_step(c.inp(b2, [rd], c.req_h('c', params: q2)))
    pend_bound = m.bind_promises(c.inp(b2, [rd, rc2], c.req_h('c', params: q2)))
    # a clean bind: every receipt present, params match
    b3 = c.body_h([c.step_h('a'), c.step_h('b', deps: ['a'])], [c.edge_h('a', 'x', 'b', 'p')])
    ra3 = c.rcpt(b3, 'a', 0, nil, outputs: { 'x' => c.out_h(1) })
    rb3 = c.rcpt(b3, 'b', 1, ra3, pd: c.hc({ 'p' => 1 }))
    clean = m.bind_promises(c.inp(b3, [ra3, rb3], c.req_h('b', params: { 'p' => 1 })))
    c.eq('no edge', no_edge, c.res('deny', 'deps_unmet', 'b')) && c.eq('bind: unmet dep before any edge check', bound, c.res('deny', 'deps_unmet', 'c')) &&
      c.eq('admit: promised dep stays pending', admitted, c.res('allow', nil, 'c', nil, [1])) &&
      c.eq('admit: transitive source pending', pend, c.res('allow', nil, 'c', nil, [1])) &&
      c.eq('bind: pending edge', pend_bound, c.res('deny', 'deps_unmet', 'c')) && c.eq('bind: clean', clean, c.res('allow', nil, 'b'))
  end

  # ---------------------------------------------------------------------------------------------------------------- escalation
  module C23Esc
    module_function

    ESC_D = "atlas-pca/escalation-answer/v1\x00".b
    G = { 'id' => 'g1', 'n' => 3 }.freeze

    def b64u(bin) = Base64.urlsafe_encode64(bin, padding: false).force_encoding(Encoding::UTF_8)
    def key = (@key ||= OpenSSL::PKey.new_raw_private_key('ED25519', Digest::SHA256.digest('c23/esc')))
    def pk = b64u(key.raw_public_key)
    def dg(n) = b64u(Digest::SHA256.digest("c23-esc/#{n}"))
    def hc(v) = b64u(Digest::SHA256.digest(AtlasPca.canon_bytes(v)))

    def base(over = {})
      { 'v' => 1, 'kind' => 'pca-escalation-answer', 'principal' => pk, 'policy_digest' => dg('p'), 'action_digest' => dg('a'),
        'history_head' => dg('h'), 'decision' => 'allow', 'iat' => 100, 'expires_at' => 200, 'nonce' => b64u('n' * 16), 'sig' => b64u('s' * 64) }.merge(over)
    end

    def signed(over = {})
      body = base(over).reject { |k, _| k == 'sig' }
      body.merge('sig' => b64u(key.sign(nil, ESC_D + AtlasPca.canon_bytes(body))))
    end

    def bind(over = {}) = { 'policy_digest' => dg('p'), 'action_digest' => dg('a'), 'history_head' => dg('h') }.merge(over)
    def verify(a, pins = [pk], bd = bind, now = 150) = AtlasPca.verify_escalation_answer(a, pins, bd, now)
    def no(reason) = { ok: false, reason: reason }
    def req(over = {}) = { aud: 'aud', grant: G, pcactn: { 'action' => { 'verb' => 'pay', 'resource' => 'acct' } }, last_counter: nil, reasons: ['r1'], now: 10 }.merge(over)
  end

  t('c23 escalation: build_escalation_request is the exact request') do
    next true if C23Wea.skip?('escalation.rb')

    e = C23Esc
    m = AtlasPca
    r = e.req
    want = { 'v' => 1, 'kind' => 'pca-escalation-request', 'aud' => 'aud', 'policy_digest' => e.hc({ 'd' => 'atlas-pca/escalation-policy/v1', 'grant' => e::G }),
             'action_digest' => e.hc({ 'd' => 'atlas-pca/escalation-action/v1', 'pcactn' => r[:pcactn] }),
             'history_head' => e.hc({ 'd' => 'atlas-pca/escalation-history/v1', 'last_counter' => nil }), 'verb' => 'pay', 'resource' => 'acct',
             'reasons' => ['r1'], 'expires_at' => 10 + 3_600_000 }
    C23Wea.eq('request', m.build_escalation_request(**r), want) &&
      C23Wea.eq('counter', m.build_escalation_request(**r, last_counter: 7)['history_head'], e.hc({ 'd' => 'atlas-pca/escalation-history/v1', 'last_counter' => 7 })) &&
      C23Wea.eq('ttl', m.build_escalation_request(**r, ttl_ms: 5)['expires_at'], 15) &&
      C23Wea.eq('render', m.build_escalation_request(**r, render_digest: 'RD'), want.merge('render_digest' => 'RD')) &&
      C23Wea.eq('aud nil', m.build_escalation_request(**r, aud: nil)['aud'], '') && C23Wea.eq('aud int', m.build_escalation_request(**r, aud: 5)['aud'], '') &&
      C23Wea.eq('reasons cut', m.build_escalation_request(**r, reasons: (1..17).map { |i| "r#{i}" })['reasons'], (1..16).map { |i| "r#{i}" }) &&
      C23Wea.eq('reason text', m.build_escalation_request(**r, reasons: [12, 'x' * 600])['reasons'], ['12', 'x' * 512])
  end

  t('c23 escalation: the verb and resource of a malformed pcactn read as JS String(undefined)') do
    next true if C23Wea.skip?('escalation.rb')

    e = C23Esc
    m = AtlasPca
    odd = [nil, 5, [], 'str', {}, { 'action' => 'x' }, { 'action' => [] }, { 'action' => nil }]
    odd.each do |p|
      q = m.build_escalation_request(**e.req(pcactn: p))
      C23Wea.eq("odd #{p.inspect}", [q['verb'], q['resource']], %w[undefined undefined])
    end
    q = m.build_escalation_request(**e.req(pcactn: { 'action' => { 'verb' => nil, 'resource' => 5 } }))
    w = m.build_escalation_request(**e.req(pcactn: { 'action' => { 'resource' => 'only' } }))
    z = m.build_escalation_request(**e.req(pcactn: { 'action' => { 'verb' => 'only' } }))
    C23Wea.eq('null verb', [q['verb'], q['resource']], %w[null 5]) && C23Wea.eq('no verb', [w['verb'], w['resource']], %w[undefined only]) &&
      C23Wea.eq('no resource', [z['verb'], z['resource']], %w[only undefined])
  end

  t('c23 escalation: escalation_answer_shape_error exact reasons') do
    next true if C23Wea.skip?('escalation.rb')

    e = C23Esc
    m = AtlasPca
    c = C23Wea
    se = ->(a) { m.escalation_answer_shape_error(a) }
    d = 'must be canonical base64url (32 bytes)'
    rows = [[nil, 'not an object'], [[], 'not an object'], ['x', 'not an object'], [e.base('zz' => 1), "unknown member 'answer.zz'"],
            [e.base.reject { |k, _| k == 'sig' }, "missing member 'answer.sig'"], [e.base.reject { |k, _| k == 'v' }, "missing member 'answer.v'"],
            [e.base('v' => 2), 'not a pca-escalation-answer v1'], [e.base('kind' => 'x'), 'not a pca-escalation-answer v1'],
            [e.base('principal' => 'x'), "principal #{d}"],
            [e.base('principal' => nil), "principal #{d}"], [e.base('principal' => 5), "principal #{d}"],
            [e.base('policy_digest' => 'x'), "policy_digest #{d}"], [e.base('policy_digest' => 5), "policy_digest #{d}"],
            [e.base('action_digest' => 'x'), "action_digest #{d}"], [e.base('action_digest' => nil), "action_digest #{d}"],
            [e.base('history_head' => 'x'), "history_head #{d}"], [e.base('history_head' => 5), "history_head #{d}"],
            [e.base('decision' => 'maybe'), "decision must be 'allow' or 'deny'"], [e.base('decision' => 'deny'), nil],
            [e.base('iat' => -1), 'iat and expires_at must be non-negative safe integers'], [e.base('iat' => 1.5), 'iat and expires_at must be non-negative safe integers'],
            [e.base('iat' => 'x'), 'iat and expires_at must be non-negative safe integers'], [e.base('expires_at' => -1), 'iat and expires_at must be non-negative safe integers'],
            [e.base('expires_at' => 'x'), 'iat and expires_at must be non-negative safe integers'],
            [e.base('iat' => 0, 'expires_at' => 5), nil], [e.base('iat' => 0, 'expires_at' => 0), 'expires_at must be greater than iat'],
            [e.base('iat' => 5, 'expires_at' => 5), 'expires_at must be greater than iat'], [e.base('iat' => 6, 'expires_at' => 5), 'expires_at must be greater than iat'],
            [e.base('iat' => 0, 'expires_at' => 86_400_000), nil], [e.base('iat' => 0, 'expires_at' => 86_400_001), 'an answer lives at most 86400000 ms'],
            [e.base('iat' => 100.0, 'expires_at' => 200.0), nil], [e.base('render_digest' => e.dg('r')), nil],
            [e.base('render_digest' => 'x'), "render_digest #{d}"], [e.base('render_digest' => 5), "render_digest #{d}"], [e.base('render_digest' => nil), "render_digest #{d}"],
            [e.base('nonce' => 5), 'nonce must be canonical base64url of at least 16 bytes'], [e.base('nonce' => nil), 'nonce must be canonical base64url of at least 16 bytes'],
            [e.base('nonce' => '!!'), 'nonce must be canonical base64url of at least 16 bytes'], [e.base('nonce' => e.b64u('n' * 15)), 'nonce must be canonical base64url of at least 16 bytes'],
            [e.base('nonce' => e.b64u('n' * 16)), nil], [e.base('nonce' => e.b64u('n' * 17)), nil],
            [e.base('sig' => 5), 'sig must be a string'], [e.base('sig' => nil), 'sig must be a string'],
            [e.base('pq_pk' => 5), 'pq_pk must be a string'], [e.base('pq_sig' => 5), 'pq_sig must be a string'], [e.base('alg' => 5), 'alg must be a string'],
            [e.base('alg' => 'bogus'), "unsupported_suite: unknown signature alg 'bogus'"],
            [e.base('pq_pk' => 'x'), 'an ed25519 artifact must not carry pq_pk / pq_sig'], [e.base('pq_sig' => 'x'), 'an ed25519 artifact must not carry pq_pk / pq_sig'],
            [e.base('alg' => 'ed25519', 'pq_pk' => 'x'), 'an ed25519 artifact must not carry pq_pk / pq_sig'], [e.base('alg' => 'ed25519'), nil], [e.base, nil]]
    rows.each { |a, want| c.eq("shape #{a.inspect[0, 60]}", se.call(a), want) }
    c.eq('resolve_suite message passes through', Seam.with(AtlasPca, { resolve_suite: ->(_p) { [nil, 'custom problem'] } }) { se.call(e.base) }, 'custom problem') &&
      c.eq('unknown alg message is prefixed', Seam.with(AtlasPca, { resolve_suite: ->(_p) { [nil, "unknown signature alg 'q'"] } }) { se.call(e.base) },
           "unsupported_suite: unknown signature alg 'q'") &&
      c.eq('empty-prefix guard', Seam.with(AtlasPca, { resolve_suite: ->(_p) { [nil, 'x'] } }) { se.call(e.base) }, 'x')
  end

  t('c23 escalation: escalation_answer_message is domain || canonical(answer without sig / pq_sig), whole floats only where listed') do
    next true if C23Wea.skip?('escalation.rb')

    e = C23Esc
    m = AtlasPca
    c = C23Wea
    msg = ->(a) { m.escalation_answer_message(a) }
    plain = e.base
    body = plain.reject { |k, _| %w[sig pq_sig].include?(k) }
    want = e::ESC_D + m.canon_bytes(body)
    frac = { 'iat' => 1.5, 'v' => 1.5, 'expires_at' => 2.5 }
    raises = lambda do |a|
      msg.call(a)
      false
    rescue AtlasPca::Malformed
      true
    end
    c.eq('bytes', msg.call(plain), want) && c.eq('encoding', msg.call(plain).encoding, Encoding::BINARY) &&
      c.eq('pq_sig dropped', msg.call(plain.merge('pq_sig' => 'zz')), want) &&
      c.eq('integral floats in v / iat / expires_at', msg.call(plain.merge('v' => 1.0, 'iat' => 100.0, 'expires_at' => 2e2)), want) &&
      c.eq('fractions are kept as they are', msg.call(plain.merge(frac)), e::ESC_D + m.canon_bytes(body.merge(frac))) &&
      c.eq('fraction differs from its truncation', msg.call(plain.merge(frac)) == msg.call(plain.merge('iat' => 1, 'v' => 1, 'expires_at' => 2)), false) &&
      c.eq('whole float in another member raises', raises.call(plain.merge('zz' => 2.0)), true) &&
      c.eq('whole float in decision raises', raises.call(plain.merge('decision' => 2.0)), true) &&
      c.eq('fraction in another member is canonical', msg.call(plain.merge('zz' => 2.5)), e::ESC_D + m.canon_bytes(body.merge('zz' => 2.5))) &&
      c.eq('integer elsewhere stays', msg.call(plain.merge('zz' => 2)), e::ESC_D + m.canon_bytes(body.merge('zz' => 2)))
  end

  t('c23 escalation: verify_escalation_answer reasons, boundaries and the fail-closed rescue') do
    next true if C23Wea.skip?('escalation.rb')

    e = C23Esc
    m = AtlasPca
    c = C23Wea
    a = e.signed
    ok = { ok: true, principal: e.pk, decision: 'allow' }
    other = OpenSSL::PKey.new_raw_private_key('ED25519', Digest::SHA256.digest('c23/esc-other'))
    opk = e.b64u(other.raw_public_key)
    c.eq('ok', e.verify(a), ok) && c.eq('deny answer', e.verify(e.signed('decision' => 'deny')), { ok: true, principal: e.pk, decision: 'deny' }) &&
      c.eq('hash pin', e.verify(a, [{ 'pk' => e.pk }]), ok) && c.eq('second pin', e.verify(a, [opk, e.pk]), ok) &&
      c.eq('clock nan', e.verify(a, [e.pk], e.bind, 1.5), e.no('the verifier clock is not a safe integer (fail closed)')) &&
      c.eq('clock nil', e.verify(a, [e.pk], e.bind, nil), e.no('the verifier clock is not a safe integer (fail closed)')) &&
      c.eq('malformed', e.verify(a.merge('zz' => 1)), e.no("malformed escalation answer: unknown member 'answer.zz'")) &&
      c.eq('not an object', e.verify(nil), e.no('malformed escalation answer: not an object')) &&
      c.eq('unpinned list empty', e.verify(a, []), e.no('no principal is pinned for escalation answers')) &&
      c.eq('unpinned list string', e.verify(a, 'abc'), e.no('no principal is pinned for escalation answers')) &&
      c.eq('unpinned list hash', e.verify(a, { 'a' => 'b' }), e.no('no principal is pinned for escalation answers')) &&
      c.eq('unpinned list nil', e.verify(a, nil), e.no('no principal is pinned for escalation answers')) &&
      c.eq('other key', e.verify(a, [opk]), e.no('the answering principal is not pinned by this verifier')) &&
      c.eq('odd pins', e.verify(a, [5, nil, [], 'x']), e.no('the answering principal is not pinned by this verifier')) &&
      c.eq('hash pin of another key', e.verify(a, [{ 'pk' => opk }]), e.no('the answering principal is not pinned by this verifier')) &&
      c.eq('tampered', e.verify(a.merge('decision' => 'deny')), e.no('escalation answer signature invalid')) &&
      c.eq('policy', e.verify(a, [e.pk], e.bind('policy_digest' => e.dg('x'))), e.no('the answer is bound to another policy')) &&
      c.eq('action', e.verify(a, [e.pk], e.bind('action_digest' => e.dg('x'))), e.no('the answer is bound to another action')) &&
      c.eq('history', e.verify(a, [e.pk], e.bind('history_head' => e.dg('x'))), e.no('the answer is bound to another state of the history')) &&
      c.eq('future', e.verify(a, [e.pk], e.bind, 99), e.no('the answer is from the future')) && c.eq('at iat', e.verify(a, [e.pk], e.bind, 100), ok) &&
      c.eq('at expiry', e.verify(a, [e.pk], e.bind, 200), ok) && c.eq('expired', e.verify(a, [e.pk], e.bind, 201), e.no('the answer has expired')) &&
      c.eq('render demanded, none given', e.verify(a, [e.pk], e.bind('render_digest' => e.dg('r'))), e.no('the answer is not bound to the canonical approval render')) &&
      c.eq('render given, none demanded', e.verify(e.signed('render_digest' => e.dg('r'))), e.no('the answer carries an approval render this verifier did not recompute')) &&
      c.eq('render mismatch', e.verify(e.signed('render_digest' => e.dg('r')), [e.pk], e.bind('render_digest' => e.dg('x'))), e.no('the answer was given for another approval render')) &&
      c.eq('render match', e.verify(e.signed('render_digest' => e.dg('r')), [e.pk], e.bind('render_digest' => e.dg('r'))), ok) &&
      c.eq('bind nil fails closed with the class name', e.verify(a, [e.pk], nil), e.no('escalation answer error (fail closed): NoMethodError'))
  end

  t('c23 escalation: the pinned PQ key reaches the suite verifier only when it is a string') do
    next true if C23Wea.skip?('escalation.rb')

    e = C23Esc
    m = AtlasPca
    c = C23Wea
    a = e.signed
    spy = lambda do |pins|
      calls = []
      r = Seam.with(AtlasPca::IntentV2, { verify_pinned_suite: ->(*args) { calls << args; true } }) { e.verify(a, pins) }
      [r, calls]
    end
    r1, c1 = spy.call([{ 'pk' => e.pk, 'pq_pk' => 'PQK' }])
    r2, c2 = spy.call([{ 'pk' => e.pk }])
    r3, c3 = spy.call([{ 'pk' => e.pk, 'pq_pk' => 5 }])
    r4, c4 = spy.call([e.pk])
    ok = { ok: true, principal: e.pk, decision: 'allow' }
    c.eq('results', [r1, r2, r3, r4], [ok, ok, ok, ok]) && c.eq('pq pinned', c1.map { |x| x[6] }, [{ e.pk => 'PQK' }]) &&
      c.eq('no pq pin', c2.map { |x| x[6] }, [{}]) && c.eq('non-string pq pin', c3.map { |x| x[6] }, [{}]) && c.eq('string pin', c4.map { |x| x[6] }, [{}]) &&
      c.eq('identity', c1.map { |x| x[1] }, [e.pk]) && c.eq('message', c1.map { |x| x[3] }, [m.escalation_answer_message(a)]) &&
      c.eq('sig', c1.map { |x| x[4] }, [a['sig']]) && c.eq('alg / pq absent', c1.map { |x| [x[0], x[2], x[5]] }, [[AtlasPca::V2JS::UNDEF] * 3])
  end

  # ---------------------------------------------------------------------------------------------------------------- approval
  module C23Apr
    module_function

    MAX = 9_007_199_254_740_991
    DD = 'NG0q4MT2WjnViFLG06gRIdbscJXf-PoVdeU5SOZk5Hc'
    WORDS = %w[
      able acid aged also area army atom aunt away baby back ball band bank base bath
      bear beat beef bell belt bend bird blue boat body bold bone book boot born both
      bowl bulb burn bush busy cafe cake calm camp card care cart case cash cast cave
      cell chat chef chip city clay clip club coal coat code coin cold cook cool cope
      copy cord core cost crew crop dark data date dawn deal dear deck deep deer desk
      dial dice diet dish dive door dose down draw drop drum duck dust duty each earn
      east easy edge echo else even ever exit face fact fair fall farm fast fate fern
      file fill film find fine fire firm fish five flag flat flow foam fold folk food
      foot fork form fort four free frog fuel full fund gain game gate gear gift girl
      glad glow goat gold golf good grab gray grid grip grow gulf hair half hall hand
      hard harp hawk head heat help herb hill hint hold hole home hood hook hope horn
      host hour huge hunt idea inch iron isle item jade jazz join joke jump jury just
      keen keep kind king kite knee knot lake lamp land lane last late lawn lead leaf
      lean left lens less lift lime line link lion list live load loan lock logo long
      loop lord loud love luck lung made mail main mask mass mate meal melt menu mild
      milk mind mint mole moon more moss move much nail navy neat neck nest news nice
    ].freeze
    DEF_JSON = <<~'JSON'
{
 "v": 1,
 "kind": "pca-action-def",
 "verb": "acme.pay",
 "title": "Pay",
 "effects": [
  "pay"
 ],
 "resource": {
  "type": "account",
  "id": "*",
  "scope": "one"
 },
 "params": {
  "amount": {
   "type": "integer",
   "role": "money.amount",
   "min": 0,
   "max": 1000000000000,
   "unit": {
    "kind": "money",
    "ccy": {
     "from": "currency"
    },
    "exp": 2
   }
  },
  "currency": {
   "type": "string",
   "max_len": 3
  },
  "payee": {
   "type": "string",
   "role": "party.payee",
   "max_len": 64
  },
  "memo": {
   "type": "string",
   "required": false,
   "max_len": 140
  },
  "to.iban": {
   "type": "string",
   "required": false,
   "max_len": 34
  },
  "to.bank.bic": {
   "type": "string",
   "required": false,
   "max_len": 11
  },
  "n": {
   "type": "integer",
   "required": false,
   "unit": {
    "kind": "count"
   }
  },
  "wait": {
   "type": "duration",
   "required": false
  },
  "flag": {
   "type": "boolean",
   "required": false
  },
  "when": {
   "type": "datetime",
   "required": false
  },
  "day": {
   "type": "date",
   "required": false
  },
  "ref": {
   "type": "object_ref",
   "required": false
  },
  "tags": {
   "type": "array",
   "items": "string",
   "required": false,
   "max_items": 8
  },
  "pick": {
   "type": "set",
   "values": [
    "x",
    "y",
    "z"
   ],
   "required": false
  },
  "fee": {
   "type": "integer",
   "required": false,
   "unit": {
    "kind": "money",
    "ccy": "USD",
    "exp": 0
   }
  }
 },
 "review": {
  "state": "authored"
 }
}
    JSON

    class EqOne
      def ==(other)
        other == 1
      end
    end

    def b64u(bin) = Base64.urlsafe_encode64(bin, padding: false).force_encoding(Encoding::UTF_8)
    def dg(n) = b64u(Digest::SHA256.digest("c23-apr/#{n}"))
    def zero = b64u("\x00".b * 32)
    def defn = JSON.parse(DEF_JSON)

    def kit
      yield
      nil
    rescue AtlasPca::Actions::ActionKitError => e
      [e.code, e.message]
    end

    # the TS message continues with " (no floats, no null, no lone surrogates)"; the prefix is what both sides share
    def kit_prefix
      yield
      nil
    rescue AtlasPca::Actions::ActionKitError => e
      [e.code, e.message.sub(/ \(no floats, no null, no lone surrogates\)\z/, '')]
    end

    def raised(klass)
      yield
      nil
    rescue klass => e
      e.message
    end

    def pay(amount, payee: 'Bilbo', ccy: 'EUR', exp: 2, unreviewed: false)
      { 'v' => 1, 'kind' => 'pca-approval-render', 'verb' => 'acme.pay', 'def_digest' => DD, 'unreviewed' => unreviewed,
        'fields' => [{ 'id' => 'amount', 'class' => 'money.amount', 'value' => amount, 'unit' => { 'kind' => 'money', 'ccy' => ccy, 'exp' => exp } },
                     { 'id' => 'payee', 'class' => 'party.payee', 'value' => payee }] }
    end

    def min_render(unreviewed = true)
      { 'v' => 1, 'kind' => 'pca-approval-render', 'verb' => 'acme.pay', 'def_digest' => DD, 'unreviewed' => unreviewed,
        'fields' => [{ 'id' => 'amount', 'class' => 'money.amount', 'value' => 1250, 'unit' => { 'kind' => 'money', 'ccy' => 'EUR', 'exp' => 2 } },
                     { 'id' => 'currency', 'class' => 'param', 'value' => 'EUR' }, { 'id' => 'payee', 'class' => 'party.payee', 'value' => 'Bilbo' }] }
    end

    def params(over = {}) = { 'amount' => 1250, 'currency' => 'EUR', 'payee' => 'Bilbo' }.merge(over)
  end

  t('c23 approval: the binding-word table is the reference table, in order') do
    next true if C23Wea.skip?('approval.rb')

    a = C23Apr
    m = AtlasPca
    w = a::WORDS
    C23Wea.eq('size', w.length, 256) && C23Wea.eq('words', m::BINDING_WORDS, w) &&
      C23Wea.eq('first six', m.binding_words(a.b64u((0..31).to_a.pack('C*'))), 'able-acid-aged-also-area-army') &&
      C23Wea.eq('high bytes', m.binding_words(a.b64u(((250..255).to_a + ([0] * 26)).pack('C*'))), w[250..255].join('-'))
  end

  t('c23 approval: binding_words / approval_challenge refuse non-digests with their exact message') do
    next true if C23Wea.skip?('approval.rb')

    a = C23Apr
    m = AtlasPca
    c = C23Wea
    cm = 'approvalChallenge: both digests must be canonical 32-byte values'
    bm = 'bindingWords: render digest must be a canonical 32-byte value'
    z = a.zero
    want = a.b64u(Digest::SHA256.digest("atlas-pca/approval-challenge/v1\x00".b + ("\x00".b * 32) + ("\x00".b * 32)))
    c.eq('challenge', m.approval_challenge(z, z), want) &&
      [[5, z], [z, 5], [nil, z], [z, nil], ['AAAA', z], [z, ''], [false, z], [z, false], [[], z]].each_with_index.all? { |(x, y), i|
        c.eq("challenge refuses #{i}", a.raised(ArgumentError) { m.approval_challenge(x, y) }, cm)
      } &&
      [5, nil, '', 'AAAA', false, []].each_with_index.all? { |x, i| c.eq("words refuse #{i}", a.raised(ArgumentError) { m.binding_words(x) }, bm) } &&
      c.eq('words zero', m.binding_words(z), 'able-able-able-able-able-able')
  end

  t('c23 approval: render_digest? / render_safe_int? / render_bounded? / render_closed / render_u16') do
    next true if C23Wea.skip?('approval.rb')

    a = C23Apr
    m = AtlasPca
    c = C23Wea
    mx = a::MAX
    c.table('digest?', ->(x) { m.render_digest?(x) }, [[a.dg('1'), true], [nil, false], [false, false], [5, false], ['AAAA', false], ['', false]]) &&
      c.table('safe_int', ->(x) { m.render_safe_int?(x) },
              [[5, true], [0, true], [-5, true], [mx, true], [mx + 1, false], [-mx, true], [-(mx + 1), false], [3.0, true], [-3.0, true], [0.0, true],
               [-0.0, false], [3.5, false], [Float::INFINITY, false], [-Float::INFINITY, false], [Float::NAN, false], [9_007_199_254_740_991.0, true],
               [9_007_199_254_740_992.0, false], ['1', false], [nil, false], [true, false], [false, false], [[], false]]) &&
      c.table('bounded', ->(x) { m.render_bounded?(x[0], x[1]) },
              [[['a', 1], true], [['ab', 1], false], [['', 1], false], [[5, 1], false], [[nil, 1], false], [['é', 2], true], [['é', 1], false]]) &&
      c.eq('closed ok', m.render_closed({ 'a' => 1 }, %w[a], %w[b]), nil) && c.eq('closed optional', m.render_closed({ 'a' => 1, 'b' => 2 }, %w[a], %w[b]), nil) &&
      c.eq('closed default where / unknown', m.render_closed({ 'zz' => 1 }, %w[a]), "unknown member 'object.zz'") &&
      c.eq('closed default where / missing', m.render_closed({}, %w[a]), "missing member 'object.a'") &&
      c.eq('closed where', m.render_closed({ 'zz' => 1 }, %w[a], [], 'w'), "unknown member 'w.zz'") &&
      c.eq('u16 utf8 bytes', m.render_u16("\xC3\xA9".b), "\x00\xE9".b) && c.eq('u16 ascii', m.render_u16('ab'), "\x00a\x00b".b) &&
      c.eq('u16 invalid', m.render_u16("\xFF".dup.force_encoding('UTF-8')), "\xFF\xFD".b) && c.eq('u16 astral', m.render_u16("\u{1F600}"), "\xD8\x3D\xDE\x00".b)
  end

  t('c23 approval: approval_render_shape_error pins v with a duck that equals 1, and approval_render_digest names the defect') do
    next true if C23Wea.skip?('approval.rb')

    a = C23Apr
    m = AtlasPca
    c = C23Wea
    r = a.min_render
    c.eq('valid', m.approval_render_shape_error(r), nil) &&
      c.eq('duck v', m.approval_render_shape_error(r.merge('v' => C23Apr::EqOne.new)), 'not a pca-approval-render v1') &&
      c.eq('v 2', m.approval_render_shape_error(r.merge('v' => 2)), 'not a pca-approval-render v1') &&
      c.eq('digest ok', m.approval_render_digest(r), m.hash_canonical({ 'd' => 'atlas-pca/approval-render/v1', 'render' => r })) &&
      c.eq('digest message', a.raised(ArgumentError) { m.approval_render_digest({ 'v' => 1 }) }, "approvalRenderDigest: missing member 'render.kind'") &&
      c.eq('digest message v', a.raised(ArgumentError) { m.approval_render_digest(r.merge('v' => 2)) }, 'approvalRenderDigest: not a pca-approval-render v1')
  end

  t('c23 approval: render_flatten, render_value_ok? and render_approval (default unreviewed, integral floats, exact messages)') do
    next true if C23Wea.skip?('approval.rb')

    a = C23Apr
    m = AtlasPca
    c = C23Wea
    d = a.defn
    r = m.render_approval(d, a.params)
    f = m.render_approval(d, a.params('amount' => 1250.0))['fields'][0]['value']
    c.eq('empty first key', m.render_flatten({ '' => { 'a' => 1 } }), { 'a' => 1 }) && c.eq('nested', m.render_flatten({ 'a' => { 'b' => 1 } }), { 'a.b' => 1 }) &&
      c.eq('empty object leaf', m.render_flatten({ 'a' => {} }), { 'a' => {} }) &&
      c.eq('depth cap', m.render_flatten({ 'a' => { 'b' => { 'c' => { 'd' => 1 } } } }), { 'a.b.c' => { 'd' => 1 } }) &&
      c.eq('dot top', a.kit { m.render_flatten({ 'x.y' => 1 }) }, ['render_bad_params', "the parameter key 'x.y' contains a dot"]) &&
      c.eq('dot nested', a.kit { m.render_flatten({ 'a' => { 'b.c' => 1 } }) }, ['render_bad_params', "the parameter key 'b.c' contains a dot"]) &&
      c.table('value_ok', ->(x) { m.render_value_ok?(x[0], x[1]) },
              [[['weird', 1], false], [['integer', 5], true], [['integer', true], false], [['boolean', true], true], [['boolean', 1], false], [['string', 's'], true],
               [['string', 5], false], [['set', [1, 'a', true]], true], [['set', 'x'], false], [['duration', 5], true]]) &&
      c.eq('render', r, a.min_render(true).merge('def_digest' => m::Actions.def_digest(d))) && c.eq('render default is unreviewed', r['unreviewed'], true) &&
      c.eq('render confirmed', m.render_approval(d, a.params, true)['unreviewed'], false) && c.eq('render unconfirmed', m.render_approval(d, a.params, false)['unreviewed'], true) &&
      c.eq('integral float value', [f, f.class], [1250, Integer]) &&
      c.eq('params not an object', a.kit { m.render_approval(d, nil) }, ['render_bad_params', 'params must be an object']) &&
      c.eq('params array', a.kit { m.render_approval(d, []) }, ['render_bad_params', 'params must be an object']) &&
      c.eq('undeclared', a.kit { m.render_approval(d, a.params('x' => 1)) }, ['render_undeclared_param', "'x' is not a parameter of acme.pay"]) &&
      c.eq('missing', a.kit { m.render_approval(d, a.params.reject { |k, _| k == 'amount' }) }, ['render_missing_param', "required parameter 'amount' of acme.pay is missing"]) &&
      c.eq('bad value', a.kit_prefix { m.render_approval(d, a.params('amount' => 'x')) }, ['render_bad_value', "'amount' is not a integer in the canonical domain"]) &&
      c.eq('bad string value', a.kit_prefix { m.render_approval(d, a.params('payee' => 5)) }, ['render_bad_value', "'payee' is not a string in the canonical domain"]) &&
      c.eq('bad currency', a.kit { m.render_approval(d, a.params('currency' => '')) }, ['render_unresolved_currency', "the currency of 'amount' is not a string"])
  end

  t('c23 approval: psd2_get / psd2_fields / psd2_linking exact outputs and messages') do
    next true if C23Wea.skip?('approval.rb')

    a = C23Apr
    m = AtlasPca
    c = C23Wea
    um = 'an unreviewed definition cannot be a payment approval'
    am = 'a payment approval needs exactly one money.amount parameter'
    nm = 'the money.amount parameter has no money unit'
    vm = 'the amount must be a non-negative integer in minor units'
    pm = 'a payment approval needs exactly one non-empty party.payee parameter'
    lk = ->(r) { a.kit { m.psd2_linking(r) } }
    fld = ->(r, i, k, v) { r.merge('fields' => r['fields'].each_with_index.map { |f, j| j == i ? f.merge(k => v) : f }) }
    nofld = ->(r, i, k) { r.merge('fields' => r['fields'].each_with_index.map { |f, j| j == i ? f.reject { |kk, _| kk == k } : f }) }
    got = m.psd2_linking(a.pay(1250))
    fl = m.psd2_linking(a.pay(1250.0, exp: 2.0))
    c.eq('get null', a.raised(TypeError) { m.psd2_get(nil, 'x') }, "Cannot read properties of null (reading 'x')") &&
      c.eq('fields not a function (hash)', a.raised(TypeError) { m.psd2_fields({ 'fields' => {} }, 'c') }, 'r.fields.filter is not a function') &&
      c.eq('fields not a function (nil)', a.raised(TypeError) { m.psd2_fields({ 'fields' => nil }, 'c') }, 'r.fields.filter is not a function') &&
      c.eq('fields select', m.psd2_fields({ 'fields' => [{ 'class' => 'a' }, { 'class' => 'b' }, { 'class' => 'a', 'x' => 1 }] }, 'a'), [{ 'class' => 'a' }, { 'class' => 'a', 'x' => 1 }]) &&
      c.eq('linking', got, { 'amount_minor' => 1250, 'currency' => 'EUR', 'exp' => 2, 'payee' => 'Bilbo' }) &&
      c.eq('float amount becomes an integer', [fl['amount_minor'], fl['amount_minor'].class, fl['exp'], fl['exp'].class], [1250, Integer, 2, Integer]) &&
      c.eq('unreviewed', lk.call(a.pay(1250, unreviewed: true)), ['psd2_unlinkable', um]) &&
      c.eq('no fields', lk.call(a.pay(1).merge('fields' => [])), ['psd2_unlinkable', am]) &&
      c.eq('two amounts', lk.call(a.pay(1).merge('fields' => [a.pay(1)['fields'][0], a.pay(2)['fields'][0].merge('id' => 'b')])), ['psd2_unlinkable', am]) &&
      c.eq('no unit', lk.call(nofld.call(a.pay(1), 0, 'unit')), ['psd2_unlinkable', nm]) &&
      c.eq('unit not money', lk.call(fld.call(a.pay(1), 0, 'unit', { 'kind' => 'count' })), ['psd2_unlinkable', nm]) &&
      c.eq('unit not an object', lk.call(fld.call(a.pay(1), 0, 'unit', 'money')), ['psd2_unlinkable', nm]) &&
      c.eq('negative', lk.call(a.pay(-1)), ['psd2_unlinkable', vm]) && c.eq('string amount', lk.call(a.pay('x')), ['psd2_unlinkable', vm]) &&
      c.eq('fraction', lk.call(a.pay(1.5)), ['psd2_unlinkable', vm]) && c.eq('no value', lk.call(nofld.call(a.pay(1), 0, 'value')), ['psd2_unlinkable', vm]) &&
      c.eq('zero amount', m.psd2_linking(a.pay(0))['amount_minor'], 0) &&
      c.eq('no payee', lk.call(a.pay(1).merge('fields' => [a.pay(1)['fields'][0]])), ['psd2_unlinkable', pm]) &&
      c.eq('empty payee', lk.call(a.pay(1, payee: '')), ['psd2_unlinkable', pm]) && c.eq('numeric payee', lk.call(a.pay(1, payee: 5)), ['psd2_unlinkable', pm]) &&
      c.eq('null payee', lk.call(a.pay(1, payee: nil)), ['psd2_unlinkable', pm]) &&
      c.eq('two payees', lk.call(a.pay(1).merge('fields' => a.pay(1)['fields'] + [{ 'id' => 'q', 'class' => 'party.payee', 'value' => 'x' }])), ['psd2_unlinkable', pm]) &&
      c.eq('absent ccy / exp are left out', m.psd2_linking(fld.call(a.pay(1), 0, 'unit', { 'kind' => 'money' })), { 'amount_minor' => 1, 'payee' => 'Bilbo' })
  end

  t('c23 approval: minor_to_decimal and approval_batch exact values and messages') do
    next true if C23Wea.skip?('approval.rb')

    a = C23Apr
    m = AtlasPca
    c = C23Wea
    mx = a::MAX
    bad = ['psd2_unlinkable', 'minor units must be a non-negative safe integer']
    item = ->(x, **o) { { 'action_digest' => a.dg("i#{x}"), 'render' => a.pay(x, **o) } }
    bm = ->(items) { a.kit { m.approval_batch(items) } }
    ok = m.approval_batch([item.call(mx - 1), item.call(1, payee: 'Frodo')])
    c.table('decimal', ->(x) { m.minor_to_decimal(x[0], x[1]) },
            [[[1250, 2], '12.50'], [[5, 2], '0.05'], [[0, 0], '0'], [[7, 0], '7'], [[1, 18], '0.' + ('0' * 17) + '1'], [[0, 2], '0.00'], [[1250.0, 2], '12.50'],
             [[1250, 2.0], '12.50'], [[5, 0.0], '5']]) &&
      c.eq('minor negative', a.kit { m.minor_to_decimal(-1, 2) }, bad) && c.eq('exp negative', a.kit { m.minor_to_decimal(1, -1) }, bad) &&
      c.eq('exp 19', a.kit { m.minor_to_decimal(1, 19) }, bad) && c.eq('minor unsafe', a.kit { m.minor_to_decimal(mx + 1, 2) }, bad) &&
      c.eq('minor string', a.kit { m.minor_to_decimal('1', 2) }, bad) && c.eq('exp fraction', a.kit { m.minor_to_decimal(1, 1.5) }, bad) &&
      c.eq('empty batch', bm.call([]), ['psd2_unlinkable', 'a batch needs at least one payment']) &&
      c.eq('mixed exponents', bm.call([item.call(1), item.call(1, exp: 3)]), ['psd2_unlinkable', 'currency EUR appears with two exponents']) &&
      c.eq('mixed exponents, other currency', bm.call([item.call(1, ccy: 'JPY', exp: 0), item.call(1, ccy: 'JPY', exp: 2)]),
           ['psd2_unlinkable', 'currency JPY appears with two exponents']) &&
      c.eq('total over', bm.call([item.call(mx - 1), item.call(2, payee: 'Frodo')]), ['psd2_unlinkable', 'the batch total exceeds the safe integer range']) &&
      c.eq('total at the limit', ok['batch']['totals'], [{ 'ccy' => 'EUR', 'exp' => 2, 'minor' => mx }]) && c.eq('batch n', ok['batch']['n'], 2) &&
      c.eq('action digest is the items root', ok['action_digest'], ok['batch']['items_root']) &&
      c.eq('unreviewed item', bm.call([item.call(1, unreviewed: true)]), ['psd2_unlinkable', 'an unreviewed definition cannot be a payment approval'])
  end
end
