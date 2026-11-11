# frozen_string_literal: true

# c32: mutation-kill tests for the remaining survivors of authorize.rb, intent_history.rb, rack_middleware.rb, intent_v2.rb,
# intent_wb.rb, agent.rb, arg_provenance.rb, undo.rb (the attest/* files are in c32b_attest_remaining.rb).
# Everything resolves AtlasPca at CALL time (the oracle re-evaluates AtlasPca per mutant). Reuses MutationKill::C06 / C05Rack helpers.
require 'timeout'
require 'json'
require 'stringio'
require 'digest'

module MutationKill
  module C32
    module_function

    # true when the mutated file (MUT_FILE basename) is none of `names`: these tests then pass at once
    def skip?(*names)
      f = ENV['MUT_FILE']
      !f.nil? && !f.empty? && !names.include?(f)
    end

    def ck(label, got, want)
      got == want || raise("c32 #{label}: got #{got.inspect}, want #{want.inspect}")
    end

    def pc = C06.fixture_pcactn
    def grant = C06.base['grant']

    # a replay store recording every key it is asked about
    def key_store
      Class.new do
        attr_reader :keys

        def initialize
          @keys = []
        end

        def claim(key, _counter)
          @keys << [:claim, key]
          AtlasPca::ClaimResult.new(true)
        end

        def last(key)
          @keys << [:last, key]
          nil
        end
      end.new
    end

    def esc_stubs(extra = {})
      { decision_of: ->(_v) { 'escalate' }, build_escalation_request: ->(**) { { 'req' => 1 } } }.merge(extra)
    end

    def revoked = ->(_p, _g) { true }
  end

  # ================================================================ authorize.rb: stores and structs
  t('c32 authorize: StateStore#claim is abstract, ClaimResult takes 1..2 args, store constructors call super') do
    next true if C32.skip?('authorize.rb')
    abstract = begin
      AtlasPca::StateStore.new.claim('k', 1)
      false
    rescue NotImplementedError
      true
    end
    zero = begin
      AtlasPca::ClaimResult.new
      false
    rescue ArgumentError
      true
    end
    one = AtlasPca::ClaimResult.new(true)
    calls = []
    AtlasPca::StateStore.send(:define_method, :initialize) { |*a| calls << a }
    begin
      AtlasPca::MemoryStateStore.new
      AtlasPca::SqlStateStore.new(execute: ->(*) { 0 }, select: ->(*) { nil })
    ensure
      AtlasPca::StateStore.send(:remove_method, :initialize)
    end
    C32.ck('abstract', abstract, true) && C32.ck('zero args', zero, true) && C32.ck('one', [one.ok, one.last_counter], [true, nil]) &&
      C32.ck('super calls', calls, [[], []])
  end

  t('c32 authorize: SqlStateStore reads only Integer heads; last passes [key]; SqliteStateStore busy timeout is an Integer') do
    next true if C32.skip?('authorize.rb')
    log = []
    ret = 'x'
    st = AtlasPca::SqlStateStore.new(execute: ->(_s, _b) { 0 }, select: ->(s, b) { log << [s, b]; ret })
    r_str = st.claim('k', 1)
    l_str = st.last('k')
    ret = 7
    r_int = st.claim('k', 1)
    l_int = st.last('k')
    sel = 'SELECT last_counter FROM pca_replay WHERE key = ?'
    t_ms = C06.with_fake_sqlite do
      C06.mk_sqlite('/p.db', timeout: 2.0005)
      C06::FakeDB.made[0].timeout
    end
    C32.ck('string head', [r_str.ok, r_str.last_counter, l_str], [false, nil, nil]) && C32.ck('int head', [r_int.ok, r_int.last_counter, l_int], [false, 7, 7]) &&
      C32.ck('binds', log, [[sel, ['k']]] * 4) && C32.ck('timeout', [t_ms, t_ms.class], [2000, Integer])
  end

  t('c32 authorize: root_caveats drops only the first envelope caveat; a non-Hash grant has no caveats') do
    next true if C32.skip?('authorize.rb')
    env = { 'type' => AtlasPca::ENVELOPE_CAVEAT }
    other = { 'type' => 'max_spend', 'usd' => 1 }
    C32.ck('first envelope', AtlasPca.root_caveats({ 'caveats' => [other, env, env] }), [other, env]) &&
      C32.ck('string grant', AtlasPca.root_caveats('caveats'), nil) && C32.ck('non array', AtlasPca.root_caveats({ 'caveats' => 'zz' }), 'zz')
  end

  # ---------------------------------------------------------------- authorize.rb: tool schema internals
  t('c32 authorize: js_eq? never equates a number with a non-number') do
    next true if C32.skip?('authorize.rb')
    j = ->(a, b) { AtlasPca::ToolSchema.js_eq?(a, b) }
    [[1, 'x'], ['x', 1], [1, true], [true, 1], [true, 'x'], ['x', true]].all? { |a, b| j.call(a, b) == false } && j.call(1, 1.0) == true &&
      j.call(true, true) == true && j.call('a', 'a') == true && j.call(1, 2) == false
  end

  t('c32 authorize: show pairs only a HIGH surrogate with a following LOW one; a plain string loops to its end') do
    next true if C32.skip?('authorize.rb')
    s = ->(x) { Timeout.timeout(2) { AtlasPca::ToolSchema.show(x) } }
    C32.ck('a + low', s.call('a' + C06.wtf(0xDC00)), '"a\\udc00"') && C32.ck('D7FF + low', s.call("\u{D7FF}" + C06.wtf(0xDC00)), "\"\u{D7FF}\\udc00\"") &&
      C32.ck('low low', s.call(C06.wtf(0xDC00, 0xDC00)), '"\\udc00\\udc00"') && C32.ck('emoji', s.call("\u{1F600}"), "\"\u{1F600}\"") &&
      C32.ck('DBFF DFFF', s.call(C06.wtf(0xDBFF, 0xDFFF)), "\"\u{10FFFF}\"") && C32.ck('plain', s.call('abc'), '"abc"')
  end

  t('c32 authorize: check_value returns nil for an array and does not fall through to the const check') do
    next true if C32.skip?('authorize.rb')
    spec = { 'type' => 'array', 'items' => { 'type' => 'boolean' }, 'const' => [true] }
    C32.ck('array', AtlasPca::ToolSchema.check_value(spec, [true], 'p', 1, { n: 0 }), nil)
  end

  t('c32 authorize: validate_arg_schema names a non-String property, exactly; spec_error is nil (not false) when valid') do
    next true if C32.skip?('authorize.rb')
    v = ->(k) { AtlasPca.validate_arg_schema({ 'props' => { k => { 'type' => 'boolean' } } }) }
    se = ->(spec) { AtlasPca::ToolSchema.spec_error(spec, 2, { nodes: 0 }) }
    long = 'a-' + ('b' * 40)
    seam_msg = Seam.with(AtlasPca::ToolSchema, { only_keys?: ->(*) { raise 'seam' } }) { AtlasPca.validate_arg_schema({ 'props' => {} }) }
    C32.ck('big int', v.call(2**40), "invalid property name '1099511627776'") && C32.ck('symbol', v.call(:abc), "invalid property name 'abc'") &&
      C32.ck('nil', v.call(nil), "invalid property name ''") && C32.ck('long', v.call(long), "invalid property name '#{long[0, 32]}'") &&
      C32.ck('ok', v.call('ok_1'), nil) && C32.ck('evaluation error', seam_msg, 'schema evaluation error') &&
      [{ 'type' => 'boolean' }, { 'type' => 'string' }, { 'type' => 'number', 'min' => 1 }, { 'type' => 'integer', 'max' => 3 },
       { 'type' => 'array', 'items' => { 'type' => 'boolean' } }].all? { |sp| se.call(sp).nil? }
  end

  t('c32 authorize: evaluate_tool_schema refuses a non-String tool name') do
    next true if C32.skip?('authorize.rb')
    [5, :tool, nil, ''].all? { |tool| AtlasPca.evaluate_tool_schema({ 'type' => 'tool_schema', 'tool' => tool }, {}) == [false, 'malformed tool_schema caveat'] }
  end

  t('c32 authorize: agent caveats: a fault is exactly false; absent contexts default to {}') do
    next true if C32.skip?('authorize.rb')
    f = Seam.with(AtlasPca, { evaluate_tool_schema: ->(*) { raise 'seam' } }) { AtlasPca.agent_caveat_satisfied?({ 'type' => 'tool_schema' }, {}, {}, {}) }
    rec = []
    r = Seam.with(AtlasPca, { agent_caveat_satisfied?: ->(cv, ctx, a, tc) { rec << [cv, ctx, a, tc]; true } }) do
      AtlasPca.evaluate_agent_caveats([{ 'type' => 'x' }], { 'k' => 1 })
    end
    C32.ck('fault', f, false) && C32.ck('defaults', rec, [[{ 'type' => 'x' }, { 'k' => 1 }, {}, {}]]) && C32.ck('result', r, [true, []])
  end

  t('c32 authorize: missing_authorize_components, operation_of and json_value details') do
    next true if C32.skip?('authorize.rb')
    base = { audience: 'a', resolve_grant: ->(_g) {}, state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(*) { false } }
    mc = ->(**kw) { AtlasPca.missing_authorize_components(**base.merge(kw)) }
    op = AtlasPca.operation_of({ verb: 'v', resource: 5, params: {} })
    big = AtlasPca.json_value(-1.0e20)
    arr = AtlasPca.json_value([50.0, { a: 2.0, 5 => 3.0 }])
    C32.ck('ok', mc.call, []) && C32.ck('resolve_grant', mc.call(resolve_grant: 5), ['resolve_grant']) && C32.ck('state_store', mc.call(state_store: nil), ['state_store']) &&
      C32.ck('resource', op, nil) && C32.ck('big', [big.class, big], [Float, -1.0e20]) &&
      C32.ck('array', [arr[0].class, arr[1].keys, arr[1]['a'].class, arr[1][5].class], [Integer, ['a', 5], Integer, Integer])
  end

  t('c32 authorize: coerce_pcactn accepts exactly MAX_ARTIFACT_BYTES (parse seam: only the size cap is under test)') do
    next true if C32.skip?('authorize.rb')
    mx = AtlasPca::MAX_ARTIFACT_BYTES
    at = 'x' * mx
    over = 'x' * (mx + 1)
    parsed = []
    Seam.with(AtlasPca, { parse_json: ->(text, **) { parsed << text.bytesize; { 'ok' => 1 } } }) do
      C32.ck('at', AtlasPca.coerce_pcactn(at), [{ 'ok' => 1 }, nil]) && C32.ck('over', AtlasPca.coerce_pcactn(over), [nil, 'undecodable']) &&
        C32.ck('parsed once', parsed, [mx])
    end
  end

  t('c32 authorize: is_authorized_for needs a real AuthorizeResult and never touches the binding for an invalid operation') do
    next true if C32.skip?('authorize.rb')
    op = AtlasPca::AuthorizedOperation.new(verb: 'v', resource: 'r', params_digest: AtlasPca.params_digest({}), id: 'i')
    good = { verb: 'v', resource: 'r', params: {} }
    duck = Struct.new(:allow, :operation).new(true, op)
    spy = Class.new do
      attr_reader :n

      def verb
        @n = (@n || 0) + 1
        'v'
      end
    end.new
    sres = AtlasPca::AuthorizeResult.new(allow: true, operation: spy)
    C32.ck('real', AtlasPca.is_authorized_for(AtlasPca::AuthorizeResult.new(allow: true, operation: op), good), true) &&
      C32.ck('duck', AtlasPca.is_authorized_for(duck, good), false) && C32.ck('bad op', AtlasPca.is_authorized_for(sres, {}), false) && C32.ck('spy untouched', spy.n, nil)
  end

  # ---------------------------------------------------------------- authorize.rb: the pipeline
  t('c32 authorize: omitted keywords default to nil (plan, intent_policy, intent_v2, allowed_suites, fresh_at); the clock is an Integer') do
    next true if C32.skip?('authorize.rb')
    cap = []
    r = C06.with_core(nil, cap) { C06.go(drop: %i[plan now]) }
    kw = cap[0]
    C32.ck('missing', r.missing, nil) && C32.ck('plan default-deny', r.checks['plan_root_authorized'], 'fail') &&
      C32.ck('forwarded', [kw[:intent_policy].equal?(nil), kw[:allowed_suites].equal?(nil), kw[:fresh_at].equal?(nil), kw[:intent_v2].is_a?(Hash)], [true, true, true, true]) &&
      C32.ck('clock', kw[:now].class, Integer)
  end

  t('c32 authorize: the host env joins the v2 context only when it is a Hash; a Hash v2 that answers #call is not called') do
    next true if C32.skip?('authorize.rb')
    cap = []
    C06.with_core(nil, cap) { C06.go(context: ->(_p) { { 'env' => 'x' } }) }
    C06.with_core(nil, cap) { C06.go(context: ->(_p) { { 'env' => { 'a' => 1 } } }) }
    h = {}
    h.define_singleton_method(:call) { |_p| raise 'boom' }
    r = C06.go(intent_v2: h)
    C32.ck('string env dropped', cap[0][:intent_v2].key?('env'), false) && C32.ck('hash env kept', cap[1][:intent_v2]['env'], { 'a' => 1 }) &&
      C32.ck('hash with call', [r.allow, r.status], [true, 200])
  end

  t('c32 authorize: a verdict that carries an attestation check keeps it; degraded modes reach the assurance report and the denial') do
    next true if C32.skip?('authorize.rb')
    v = C06.core
    v.checks['attestation'] = true
    ok = C06.with_core(v) { C06.go }
    v2 = C06.core
    v2.checks['attestation'] = false
    bad = C06.with_core(v2) { C06.go }
    dv = C06.core(degraded: { 'policy' => 'compat' })
    deg = C06.with_core(dv) { C06.go(require_assurance: {}) }
    C32.ck('pass', ok.checks['attestation'], 'pass') && C32.ck('fail', bad.checks['attestation'], 'fail') &&
      C32.ck('degraded reason', deg.reasons.include?('assurance: policy rests on a degraded compatibility mode (compat); a high-assurance policy never accepts it'), true) &&
      C32.ck('degraded kept', [deg.allow, deg.checks['assurance'], deg.degraded], [false, 'fail', { 'policy' => 'compat' }])
  end

  t('c32 authorize: an unusable plan is never a known root (nil or false root, non-Array plan); node post conditions enter the root') do
    next true if C32.skip?('authorize.rb')
    zz = ->(_p) { { 'plan' => 'zz', 'plan_authorized' => true } }
    pl = C32.pc['plan']
    p_noroot = C32.pc.merge('plan' => pl.reject { |k, _| k == 'root' }, 'action' => C32.pc['action'].reject { |k, _| k == 'reversibility_class' })
    p_false = C32.pc.merge('plan' => pl.merge('root' => false))
    r1 = C06.with_core { C06.go(p_noroot, context: zz) }
    r2 = C06.with_core { C06.go(p_false, context: zz) }
    a = C32.pc['action']
    node = { 'id' => 'n1', 'verb' => a['verb'], 'resource' => a['resource'], 'params_digest' => a['params_digest'], 'reversibility_class' => 'irreversible',
             'pre' => [{ 'k' => 1 }], 'post' => [{ 'k' => 2 }] }
    root = AtlasPca.merkle_root([AtlasPca.plan_leaf('n1', node, AtlasPca.conditions_digest(node['pre'], node['post']))])
    r3 = C06.with_core { C06.go(C32.pc.merge('plan' => pl.merge('root' => root)), context: ->(_p) { { 'plan' => [node], 'plan_authorized' => true } }) }
    want = 'plan_root_authorized: known plan does not match plan.root'
    C32.ck('no root', [r1.checks['plan_root_authorized'], r1.reasons.include?(want)], ['fail', true]) &&
      C32.ck('false root', [r2.checks['plan_root_authorized'], r2.reasons.include?(want)], ['fail', true]) && C32.ck('post enters the root', r3.checks['plan_root_authorized'], 'pass')
  end

  t('c32 authorize: a registered plan is looked up by the proof root only when the plan member is a Hash') do
    next true if C32.skip?('authorize.rb')
    seen = []
    plans = Class.new do
      define_method(:context) { |*a| seen << a; nil }
    end.new
    C06.with_core { C06.go(C32.pc.merge('plan' => 'root'), plans: plans) }
    C32.ck('root0', seen, [[C32.pc['grant_ref'], '', C06::NOW]])
  end

  t('c32 authorize: a non-Array cap_chain is no chain; a non-Hash action is no action (revocation ids / signed class)') do
    next true if C32.skip?('authorize.rb')
    caps = []
    spy = ->(_pol, _state, **kw) { caps << kw; { 'ok' => true, 'epoch' => nil } }
    p8 = C32.pc.merge('action' => 'xx reversibility_class', 'cap_chain' => 'abc')
    Seam.with(AtlasPca, { check_revocation_state: spy }) do
      C06.with_core do
        C06.go(p8, revocation_staleness: AtlasPca::RevocationStaleness.new, context: ->(_p) { { 'revocation_state' => { 'kind' => 'root' } } })
      end
    end
    plain = C06.with_core { C06.go(C32.pc.merge('cap_chain' => 'abc')) }
    C32.ck('ids', caps[0][:ids], []) && C32.ck('signed class', caps[0][:signed_class], nil) &&
      C32.ck('no chain: no delegated check', [plain.checks.key?('policy'), plain.checks.key?('delegated_caveats')], [true, false])
  end

  t('c32 authorize: delegated caveats are the leaf caveats after the grant caveats (non-Array grant caveats count 0, a non-Array leaf is malformed)') do
    next true if C32.skip?('authorize.rb')
    caps3 = [{ 'type' => 'zz1' }, { 'type' => 'zz2' }, { 'type' => 'zz3' }]
    hop = { 'id' => 'h1', 'holder' => 'hh', 'caveats' => caps3 }
    pg = C32.pc.merge('cap_chain' => [hop])
    want = 'delegated_caveats: delegation caveat(s) not satisfied: zz1, zz2, zz3'
    r_str = C06.with_core { C06.go(pg, grant: C32.grant.merge('caveats' => 'zz')) }
    r_none = C06.with_core { C06.go(pg, grant: C32.grant.reject { |k, _| k == 'caveats' }) }
    hop2 = { 'id' => 'h1', 'holder' => 'hh', 'caveats' => 'a' }
    g2 = C32.grant.merge('caveats' => [{ 'type' => 'zz1' }, { 'type' => 'zz2' }])
    r_leaf = C06.with_core { C06.go(C32.pc.merge('cap_chain' => [hop2]), grant: g2) }
    C32.ck('string grant caveats', r_str.reasons.include?(want), true) && C32.ck('absent grant caveats', r_none.reasons.include?(want), true) &&
      C32.ck('non-array leaf caveats', [r_leaf.checks['delegated_caveats'], r_leaf.reasons.include?('delegated_caveats: delegation caveat(s) not satisfied: <malformed caveats>')],
             ['fail', true])
  end

  t('c32 authorize: the counter stream is the LAST hop holder; a non-String holder has no stream; no stream never escalates') do
    next true if C32.skip?('authorize.rb')
    caps = C32.grant['caveats']
    gid = C32.grant['id']
    h0 = { 'id' => 'a', 'holder' => 'h0', 'caveats' => caps }
    h1 = { 'id' => 'b', 'holder' => 'h1', 'caveats' => caps }
    st = C32.key_store
    Seam.with(AtlasPca, C32.esc_stubs) { C06.with_core { C06.go(C32.pc.merge('cap_chain' => [h0, h1]), is_revoked: C32.revoked, state_store: st) } }
    st5 = C32.key_store
    r5 = C06.with_core { C06.go(C32.pc.merge('cap_chain' => [{ 'id' => 'a', 'holder' => 5, 'caveats' => caps }]), state_store: st5) }
    st6 = C32.key_store
    r6 = Seam.with(AtlasPca, C32.esc_stubs) do
      C06.with_core { C06.go(C32.pc.merge('cap_chain' => [{ 'id' => 'a', 'holder' => 5, 'caveats' => caps }]), is_revoked: C32.revoked, state_store: st6) }
    end
    C32.ck('last hop', st.keys[0], [:last, "#{gid}:h1"]) && C32.ck('non-String holder', [r5.allow, st5.keys], [false, []]) &&
      C32.ck('no stream is a deny, not an escalate', [r6.decision, st6.keys], ['deny', []])
  end

  t('c32 authorize: an escalation runs the undo hook only when one is configured') do
    next true if C32.skip?('authorize.rb')
    calls = []
    Seam.with(AtlasPca, C32.esc_stubs(undo_admission: ->(*a) { calls << a; nil })) { C06.go(is_revoked: C32.revoked) }
    C32.ck('no hook, no admission call', calls, [])
  end

  t('c32 authorize: an empty assurance is recomputed from the checks') do
    next true if C32.skip?('authorize.rb')
    res = AtlasPca::AuthorizeResult.new(allow: true, checks: { 'a' => 'pass' }, pcactn: {}, assurance: {})
    r = Seam.with(AtlasPca, { authorize_unchecked: ->(*) { res } }) { AtlasPca.authorize(nil) }
    C32.ck('assurance', r.assurance, { 'a' => { 'outcome' => 'pass' } })
  end

  t('c32 authorize: the workflow step defaults to none; a missing clock is an Integer for the workflow gate; insecure_unbound_approval defaults to false') do
    next true if C32.skip?('authorize.rb')
    r = C06.go(workflow: {})
    r2 = C06.go(workflow: { 'required' => true })
    nows = []
    Seam.with(AtlasPca, { authorize_workflow_gate: ->(_w, _c, _p, _o, now) { nows << now; nil } }) { C06.go(workflow: {}, drop: [:now]) }
    c = C06.base
    s = c['steps'][0]
    ver = []
    stubs = C32.esc_stubs(verify_escalation_answer: ->(*a) { ver << a; { ok: false, reason: 'x' } })
    args = [s['pcactn'], s['operation'], C06.aud, ->(_r) { c['grant'] }, AtlasPca::MemoryStateStore.new, C32.revoked, C06::NOW, 'single-step',
            nil, nil, nil, nil, nil, nil, { 'x' => 1 }, nil, nil, nil, nil, nil, nil, nil]
    d = Seam.with(AtlasPca, stubs) { AtlasPca.authorize_unchecked(*args) }
    C32.ck('no step, not required', [r.allow, r.status], [true, 200]) &&
      C32.ck('required', [r2.allow, r2.reason], [false, 'workflow: this call carries no workflow step (fail closed)']) && C32.ck('workflow clock', nows.map(&:class), [Integer]) &&
      C32.ck('render required, answer not read', [ver.length, d.reasons.include?('escalation: an approval render is required and none could be recomputed (pass escalation_render:, or insecure_unbound_approval: true)')],
             [0, true])
  end

  # ================================================================ intent_history.rb
  module C32H
    module_function

    def acc(over = {})
      { 'id' => 'a', 'agg' => 'sum', 'val' => 'action.params.amount', 'unit' => 'usd', 'sel' => { 'verbs' => ['pay'] }, 'win' => { 'kind' => 'task' },
        'key' => nil, 'holder' => { 'kind' => 'site_local' } }.merge(over)
    end

    def ev(id, params, over = {}) = { 'id' => id, 'status' => 'committed', 't' => 1, 'verb' => 'pay', 'params' => params }.merge(over)

    def cand(params = {}, over = {}) = { 'verb' => 'pay', 'params' => params, 't' => 1 }.merge(over)

    def msg
      yield
      nil
    rescue AtlasPca::HistoryError => e
      e.message
    end
  end

  t('c32 history: in_window boundaries, unknown kinds, and a zero-length period (Infinity / NaN buckets)') do
    next true if C32.skip?('intent_history.rb')
    iw = ->(win, ti, t) { AtlasPca.in_window(win, ti, t) }
    s0 = { 'kind' => 'sliding', 'ms' => 0 }
    per0 = { 'kind' => 'period', 'ms' => 0, 't0' => 0 }
    per = { 'kind' => 'period', 'ms' => 10, 't0' => 0 }
    C32.ck('sliding edge', [iw.call(s0, 5, 5), iw.call(s0, 6, 5), iw.call(s0, 4, 5), iw.call({ 'kind' => 'sliding', 'ms' => 1 }, 5, 5)], [false, true, false, true]) &&
      C32.ck('kinds', [iw.call({ 'kind' => 'task' }, 1, 2), iw.call({ 'kind' => 'zz' }, 1, 2)], [true, false]) &&
      C32.ck('period', [iw.call(per, 3, 9), iw.call(per, 3, 10)], [true, false]) && C32.ck('infinite bucket', iw.call(per0, 5, 5), true) &&
      C32.ck('nan bucket', iw.call(per0, 0, 0), false)
  end

  t('c32 history: acc_key_of reads only own members of a Hash (never a default, a String or an Array)') do
    next true if C32.skip?('intent_history.rb')
    a = { 'key' => 'action.params.k' }
    dflt = Hash.new('dflt')
    rows = [[{ 'k' => 'v' }, '"v"'], [{ 'k' => 7 }, '7'], [{}, nil], [{ 'k' => 1.5 }, nil], [{ 'k' => nil }, nil], [dflt, nil], [nil, nil], ['xk', nil], [['k'], nil]]
    rows.each { |params, want| C32.ck("params #{params.inspect}", AtlasPca.acc_key_of(a, params), want) }
    C32.ck('ungrouped', [AtlasPca.acc_key_of({ 'key' => nil }, {}), AtlasPca.acc_key_of({ 'key' => nil }, nil)], ['•', '•'])
  end

  t('c32 history: history_empty_pre per aggregate') do
    next true if C32.skip?('intent_history.rb')
    pre = ->(agg) { AtlasPca.history_empty_pre(agg) }
    C32.ck('pre', [pre.call('sum'), pre.call('count'), pre.call('max'), pre.call('distinct'), pre.call('zz')],
           [{ 'sum' => 0 }, { 'count' => 0 }, { 'max' => 0 }, { 'values' => [] }, { 'values' => [] }])
  end

  t('c32 history: acc_pre_state raises HistoryError with the exact messages; sums stop at 2^53-1') do
    next true if C32.skip?('intent_history.rb')
    h = C32H
    mx = AtlasPca::MAX_SAFE
    m1 = h.msg { AtlasPca.acc_pre_state(h.acc('key' => 'action.params.k'), [], { 'params' => {}, 't' => 1 }) }
    m2 = h.msg { AtlasPca.acc_pre_state(h.acc, [], { 'params' => {}, 't' => 1.5 }) }
    m3 = h.msg { AtlasPca.acc_pre_state(h.acc, [h.ev('e1', { 'amount' => 1 }, 't' => 1.5)], { 'params' => {}, 't' => 1 }) }
    m4 = h.msg { AtlasPca.acc_pre_state(h.acc, [h.ev('e2', { 'amount' => -1 })], { 'params' => {}, 't' => 1 }) }
    at_max = AtlasPca.acc_pre_state(h.acc, [h.ev('e', { 'amount' => mx })], { 'params' => {}, 't' => 1 })
    m5 = h.msg { AtlasPca.acc_pre_state(h.acc, [h.ev('e', { 'amount' => mx }), h.ev('f', { 'amount' => 1 })], { 'params' => {}, 't' => 1 }) }
    C32.ck('missing key', m1, 'the key parameter action.params.k is missing') && C32.ck('candidate time', m2, 'the candidate time is not a safe integer') &&
      C32.ck('event time', m3, 'event e1: the time is not a safe integer') &&
      C32.ck('event value', m4, 'event e2: action.params.amount must be a non-negative safe integer') && C32.ck('at the cap', at_max, { 'sum' => mx }) &&
      C32.ck('over the cap', m5, 'sum exceeds 2^53-1')
  end

  t('c32 history: acc_pre_state distinct values; an unknown aggregate reads no keys; the key list ignores nil and absent keys (seam)') do
    next true if C32.skip?('intent_history.rb')
    h = C32H
    dist = h.acc('agg' => 'distinct', 'val' => 'action.params.d')
    evs = %w[v2 v1 v1].each_with_index.map { |d, i| h.ev("e#{i}", { 'd' => d }) }
    d_out = AtlasPca.acc_pre_state(dist, evs, { 'params' => {}, 't' => 1 })
    unk = AtlasPca.acc_pre_state(h.acc('agg' => 'avg'), [h.ev('e', { 'amount' => 3 })], { 'params' => {}, 't' => 1 })
    dflt = Hash.new('d')
    dflt['ok'] = true
    dflt['val'] = 1
    run = lambda do |v|
      Seam.with(AtlasPca, { acc_value_of: ->(*) { v } }) { AtlasPca.acc_pre_state(h.acc('agg' => 'distinct'), [h.ev('e', {})], { 'params' => {}, 't' => 1 }) }
    end
    C32.ck('distinct', d_out, { 'values' => ['"v1"', '"v2"'] }) && C32.ck('unknown agg', unk, { 'values' => [] }) &&
      C32.ck('key present but nil', run.call({ 'ok' => true, 'val' => 1, 'key' => nil }), { 'values' => [] }) &&
      C32.ck('key absent, hash default', run.call(dflt), { 'values' => [] }) &&
      C32.ck('key present', run.call({ 'ok' => true, 'val' => 1, 'key' => '"k"' }), { 'values' => ['"k"'] })
  end

  t('c32 history: acc_post candidate errors and overflow have their exact messages') do
    next true if C32.skip?('intent_history.rb')
    h = C32H
    mx = AtlasPca::MAX_SAFE
    bad = h.msg { AtlasPca.acc_post(h.acc, [], h.cand({ 'amount' => -1 })) }
    over = h.msg { AtlasPca.acc_post(h.acc, [h.ev('e', { 'amount' => mx })], h.cand({ 'amount' => 1 })) }
    C32.ck('bad candidate', bad, 'action.params.amount must be a non-negative safe integer') && C32.ck('overflow', over, 'overflow') &&
      C32.ck('ok', AtlasPca.acc_post(h.acc, [], h.cand({ 'amount' => 5 })), 5)
  end

  t('c32 history: monitor_step on responds_within counts down, takes the tighter window, and keeps NaN') do
    next true if C32.skip?('intent_history.rb')
    mon = { 'kind' => 'responds_within', 'p' => { 'verb' => 'a', 'resource' => 'r' }, 'q' => { 'verb' => 'b', 'resource' => 'r' } }
    step = lambda do |q, verb, w|
      AtlasPca.monitor_step(mon.merge('within' => w), q, { 'status' => 'committed', 'verb' => verb, 'resource' => 'r', 'params' => {} })
    end
    rows = [[['idle', 'a', 3], 'pending:3'], [['idle', 'a', nil], 'pending:0'], [['pending:5', 'x', 3], 'pending:4'], [['pending:5', 'a', nil], 'pending:0'],
            [['pending:5', 'a', 10], 'pending:4'], [['pending:5', 'a', 2], 'pending:2'], [['pending:NaN', 'a', 3], 'pending:NaN'],
            [['pending:5', 'a', Float::NAN], 'pending:NaN'], [['pending:1', 'x', 3], 'missed'], [['pending:5', 'b', 3], 'idle'], [['missed', 'a', 3], 'missed']]
    rows.each { |args, want| C32.ck("step #{args.inspect}", step.call(*args), want) }
    other = AtlasPca.monitor_step({ 'kind' => 'zzz' }, 'idle', { 'status' => 'committed', 'verb' => 'a', 'resource' => 'r', 'params' => {} })
    C32.ck('unknown kind keeps the state', other, 'idle')
  end

  # ================================================================ rack_middleware.rb
  t('c32 rack: private guards and defaults (authorize_options nil, call_authorize / call_executor without a step, optional chaining)') do
    next true if C32.skip?('rack_middleware.rb')
    r = MutationKill::C05Rack
    m = r.build(authorize: { state_store: AtlasPca::MemoryStateStore.new })
    nil_opts = m.send(:authorize_options, nil)
    kws = []
    Seam.with(AtlasPca, { authorize: ->(_pc, **kw) { kws << kw; r.allow } }) { m.send(:call_authorize, r.hdr_env, r.pct) }
    mx = r.build(authorize: { operation: ->(_e) { r::OP } }, executor: { operations: AtlasPca::MemoryOperationStore.new })
    spy = r::SpyExec.new { |_blk| AtlasPca::ExecuteOutcome.new(status: 'failed') }
    mx.instance_variable_set(:@executor, spy)
    mx.send(:call_executor, r.hdr_env, r.pct, r::OP)
    sg = r.sig
    sg.instance_variable_set(:@executor, r::SpyExec.new { |_blk| AtlasPca::ExecuteOutcome.new(status: 'failed') })
    nm = begin
      sg.send(:call_executor, r.hdr_env, r.pct, r::OP)
      nil
    rescue NoMethodError => e
      e.name
    end
    C32.ck('nil options', nil_opts.equal?(nil), true) && C32.ck('authorize step', kws[0][:workflow_call].equal?(nil), true) &&
      C32.ck('executor step', spy.kw[:workflow_call].equal?(nil), true) && C32.ck('nil authorize fails at provenance, not at k1', nm, :provenance)
  end

  t('c32 rack: a non-UTF-8-decodable fresh_at header never reaches the JSON parser') do
    next true if C32.skip?('rack_middleware.rb')
    r = MutationKill::C05Rack
    calls = []
    out = Seam.with(AtlasPca, { parse_json: ->(*a, **) { calls << a; raise 'x' } }) do
      r.build(fresh_at: { 'a' => 1 }).send(:fresh_at_policy, { 'HTTP_PCA_FRESH_AT' => 'not base64!' }, {})
    end
    C32.ck('result', out, { 'a' => 1, 'side_carried' => nil }) && C32.ck('parser not called', calls, [])
  end

  t('c32 rack: a recorded reason that is not a String is rendered as text before its refusal doc is chosen') do
    next true if C32.skip?('rack_middleware.rb')
    r = MutationKill::C05Rack
    m = r.build(authorize: { operation: ->(_e) { r::OP } }, executor: { operations: AtlasPca::MemoryOperationStore.new })
    run = lambda do |**o|
      m.instance_variable_set(:@executor, r::SpyExec.new { |_blk| AtlasPca::ExecuteOutcome.new(**o) })
      r.got(m.call(r.hdr_env))
    end
    C32.ck('aborted', run.call(status: 'aborted', reason: :'template: bad'), r.refusal(403, 'operation_aborted', 'template: bad')) &&
      C32.ck('refused', run.call(status: 'refused', reason: :'template: bad'), r.refusal(403, 'access_denied', 'template: bad'))
  end

  t('c32 rack: the request body is decoded as UTF-8 from a private copy, and read only when it is not empty') do
    next true if C32.skip?('rack_middleware.rb')
    r = MutationKill::C05Rack
    orig = AtlasPca.method(:parse_json)
    encs = []
    enc_spy = ->(text, **k) { encs << text.encoding; orig.call(text, **k) }
    frozen = lambda do |text|
      Class.new do
        define_method(:read) { text.freeze }
      end.new
    end
    mw = r.build(workflow: {})
    me = r.build(authorize: { state_store: AtlasPca::MemoryStateStore.new, escalation_principals: ['p'] })
    opts = me.instance_variable_get(:@authorize)
    wf = Seam.with(AtlasPca, { parse_json: enc_spy }) { mw.send(:workflow_call_of, { 'rack.input' => StringIO.new('{"workflow":{"s":1}}'.b) }) }
    ea = Seam.with(AtlasPca, { parse_json: enc_spy }) { me.send(:escalation_answer, { 'rack.input' => StringIO.new('{"escalation_answer":{"b":2}}'.b) }, opts) }
    wf_frozen = mw.send(:workflow_call_of, { 'rack.input' => frozen.call('{"workflow":{"s":1}}') })
    ea_frozen = me.send(:escalation_answer, { 'rack.input' => frozen.call('{"escalation_answer":{"b":2}}') }, opts)
    body_frozen = r.sig.send(:from_body, { 'rack.input' => frozen.call('{"pcactn":{"grant_ref":"g"}}') })
    parsed = []
    stub_parse = ->(*a, **) { parsed << a; raise 'x' }
    wf_empty = Seam.with(AtlasPca, { parse_json: stub_parse }) { mw.send(:workflow_call_of, { 'rack.input' => StringIO.new('') }) }
    ea_empty = Seam.with(AtlasPca, { parse_json: stub_parse }) { me.send(:escalation_answer, { 'rack.input' => StringIO.new('') }, opts) }
    seen = []
    me.define_singleton_method(:strict_object) { |text| seen << text; nil }
    ea_hdr = me.send(:escalation_answer, { 'HTTP_PCA_ESCALATION_ANSWER' => 'not base64!' }, opts)
    C32.ck('workflow utf-8', [wf, encs[0]], [{ 's' => 1 }, Encoding::UTF_8]) && C32.ck('answer utf-8', [ea, encs[1]], [{ 'b' => 2 }, Encoding::UTF_8]) &&
      C32.ck('frozen bodies', [wf_frozen, ea_frozen, body_frozen], [{ 's' => 1 }, { 'b' => 2 }, { 'grant_ref' => 'g' }]) &&
      C32.ck('empty bodies are not parsed', [wf_empty, ea_empty, parsed], [nil, nil, []]) && C32.ck('undecodable header', [ea_hdr, seen], [nil, ['']])
  end

  t('c32 rack: a body that parses to a non-Hash has no workflow step / escalation answer (exactly nil)') do
    next true if C32.skip?('rack_middleware.rb')
    r = MutationKill::C05Rack
    mw = r.build(workflow: {})
    me = r.build(authorize: { state_store: AtlasPca::MemoryStateStore.new, escalation_principals: ['p'] })
    opts = me.instance_variable_get(:@authorize)
    env = -> { { 'rack.input' => StringIO.new('x') } }
    outs = []
    [['has workflow escalation_answer'], [[1]], [5]].each do |parsed|
      Seam.with(AtlasPca, { parse_json: ->(*, **) { parsed[0] } }) do
        outs << mw.send(:workflow_call_of, env.call) << me.send(:escalation_answer, env.call, opts)
      end
    end
    C32.ck('all nil', outs.map { |o| o.equal?(nil) }, [true] * 6)
  end

  # ================================================================ intent_v2.rb
  t('c32 intent_v2: schema_floors_error requires String entries before asking the lookup (duck entry that equals a known name)') do
    next true if C32.skip?('intent_v2.rb')
    duck = Object.new
    def duck.to_str = 'amount_cap'
    def duck.==(_other) = true
    f = { 'risk' => 0, 'esc' => 0, 'rev' => 'reversible', 'blast_ppm' => 0, 'caveats' => [duck], 'context' => [], 'prules' => [] }
    ok = f.merge('caveats' => ['amount_cap'])
    C32.ck('duck refused', AtlasPca::IntentV2.schema_floors_error(f), 'floors.caveats must be an array of known entries') &&
      C32.ck('string accepted', AtlasPca::IntentV2.schema_floors_error(ok), nil)
  end

  t('c32 intent_v2: check_revocation_age needs a real number (a Rational is an unknown age)') do
    next true if C32.skip?('intent_v2.rb')
    now = 1_000_000
    got = AtlasPca::IntentV2.check_revocation_age(Rational(now), now, 1000)
    C32.ck('rational', got, { 'ok' => false, 'reason' => 'revocation state age is unknown (unverifiable revocation state)' }) &&
      C32.ck('integer', AtlasPca::IntentV2.check_revocation_age(now, now, 1000), { 'ok' => true })
  end

  t('c32 intent_v2: the totality rescues return their reason (action schema, session root, decide_intent_v2)') do
    next true if C32.skip?('intent_v2.rb')
    iv = AtlasPca::IntentV2
    schema = Seam.with(iv, { action_schema_shape_error: ->(_d) { raise 'boom' } }) { iv.verify_action_schema({}, []) }
    root = Seam.with(iv, { session_root_shape_error: ->(_s) { raise 'boom' } }) { iv.verify_session_root({}, nil) }
    decided = Seam.with(iv, { model_rules: ->(*) { raise 'boom' } }) { AtlasPca.decide_intent_v2({}, {}, nil, 1) }
    C32.ck('schema', schema, { 'ok' => false, 'reason' => 'schema verification error: boom' }) &&
      C32.ck('session root', root, { 'ok' => false, 'reason' => 'malformed session root: boom' }) && C32.ck('decide keeps what it has', decided, { 'checks' => [] })
  end

  t('c32 intent_v2: the schema step is memoised across the pin and the traits guard') do
    next true if C32.skip?('intent_v2.rb')
    g = C32.grant
    env = g['caveats'][0].merge('actions' => {})
    pinned = g.merge('caveats' => [env])
    n = 0
    Seam.with(AtlasPca::IntentV2, { schema_step: ->(*) { n += 1; { 'ok' => false, 'reason' => 'x' } } }) { AtlasPca.decide_intent_v2({}, pinned, nil, 1) }
    C32.ck('one schema read', n, 1)
  end

  # ---- deadlines: every mutant here loops or recurses without end; the real code answers at once
  t('c32 intent_v2: the map tree root and the audit-path fold terminate and agree with an independent RFC 9162 tree') do
    next true if C32.skip?('intent_v2.rb')
    iv = AtlasPca::IntentV2
    nh = ->(l, r) { iv.map_node_hash(l, r) }
    split = lambda do |n|
      k = 1
      k *= 2 while k * 2 < n
      k
    end
    tree = nil
    tree = lambda do |hs|
      next hs[0] if hs.length == 1

      k = split.call(hs.length)
      nh.call(tree.call(hs[0, k]), tree.call(hs[k..]))
    end
    path = nil
    path = lambda do |m, hs|
      next [] if hs.length == 1

      k = split.call(hs.length)
      m < k ? path.call(m, hs[0, k]) + [tree.call(hs[k..])] : path.call(m - k, hs[k..]) + [tree.call(hs[0, k])]
    end
    begin
      Timeout.timeout(2) do
        (1..9).all? do |n|
          hs = (0...n).map { |i| Digest::SHA256.digest("leaf#{i}") }
          root = tree.call(hs)
          iv.map_tree_root(hs) == root && (0...n).all? { |i| iv.map_root_from_path(i, n, hs[i], path.call(i, hs)) == root }
        end
      end
    rescue SystemStackError
      false
    end
  end

  t('c32 intent_v2: monitor_states of responds_within enumerates exactly the window (bounded work)') do
    next true if C32.skip?('intent_v2.rb')
    got = Timeout.timeout(0.3) { AtlasPca::IntentV2.monitor_states({ 'kind' => 'responds_within', 'within' => 3 }) }
    C32.ck('states', got, %w[idle pending:1 pending:2 pending:3 missed])
  end

  # ================================================================ intent_wb.rb / undo.rb
  t('c32 intent_wb: decide_read_purpose reports a fault as the malformed outcome') do
    next true if C32.skip?('intent_wb.rb')
    cov = Class.new(Hash) { def values = raise('boom') }.new
    out = AtlasPca.decide_read_purpose({ 'fields' => [], 'purpose' => 'p', 'coverage' => cov })
    C32.ck('malformed', out, { 'outcome' => 'deny', 'minimise' => [], 'uncovered' => [] })
  end

  t('c32 undo: undo_receipt_chain_error reads receipts only from a Hash record') do
    next true if C32.skip?('undo.rb')
    rec = Struct.new(:receipts).new([{}])
    C32.ck('struct record', AtlasPca.undo_receipt_chain_error(rec, 'signer'), 'no receipts')
  end

  # ================================================================ agent.rb
  t('c32 agent: plan commitments terminate for every size and every proof verifies (recursion bounds)') do
    next true if C32.skip?('agent.rb')
    nodes = ->(n) { (0...n).map { |i| { 'id' => "n#{i}", 'verb' => 'v', 'resource' => "r#{i}" } } }
    begin
      empty = begin
        AtlasPca.commit_plan([])
        false
      rescue ArgumentError => e
        e.message == 'commit_plan: empty plan'
      end
      empty && (1..6).all? do |n|
        ns = nodes.call(n)
        c = AtlasPca.commit_plan(ns)
        c['root'] == AtlasPca.merkle_root(ns.map { |x| AtlasPca.plan_node_leaf(x) }) &&
          ns.each_with_index.all? { |x, i| c['proofs'][x['id']]['index'] == i && AtlasPca.verify_inclusion(c['root'], c['proofs'][x['id']], AtlasPca.plan_node_leaf(x)) }
      end
    rescue SystemStackError
      false
    end
  end

  # ================================================================ arg_provenance.rb
  t('c32 prov: occurs_as_token and clip terminate (deadlines) and clip keeps a BMP private-use unit') do
    next true if C32.skip?('arg_provenance.rb')
    clip = ->(s) { AtlasPca::ProvenanceRecorder.allocate.send(:clip, s) }
    pair_cut = ('a' * 149) + "\u{1F600}" + ('a' * 149)
    bmp_cut = ('a' * 150) + "\u{E000}" + ('a' * 149)
    Timeout.timeout(2) do
      C32.ck('tokens', [AtlasPca.occurs_as_token('xabab', 'ab'), AtlasPca.occurs_as_token('abcab', 'ab'), AtlasPca.occurs_as_token('ab ab', 'ab'),
                        AtlasPca.occurs_as_token('x ab', 'ab')], [false, false, true, true]) &&
        C32.ck('short', clip.call('abc'), 'abc') && C32.ck('empty', clip.call(''), '-') && C32.ck('halved', clip.call('a' * 300), 'a' * 150) &&
        C32.ck('bmp unit at the cut stays', clip.call(bmp_cut), 'a' * 150) && C32.ck('low surrogate at the cut goes whole', clip.call(pair_cut), 'a' * 149)
    end
  end

  t('c32 prov: the bundle body is decoded as UTF-8 text; the recorder clock is an Integer') do
    next true if C32.skip?('arg_provenance.rb')
    orig = AtlasPca.method(:parse_json)
    encs = []
    out = Seam.with(AtlasPca, { parse_json: ->(text, **k) { encs << text.encoding; orig.call(text, **k) } }) do
      AtlasPca.default_provenance_bundle({ 'rack.input' => StringIO.new('{"pca_provenance":{"a":1}}'.b) })
    end
    rec = AtlasPca::ProvenanceRecorder.new(mediator: 'm', kid: 'k', key: AtlasPca::KeyPair.new("\x31".b * 32))
    clock = rec.instance_variable_get(:@now).call
    C32.ck('bundle', [out, encs], [{ 'a' => 1 }, [Encoding::UTF_8]]) && C32.ck('clock', clock.class, Integer)
  end
end
