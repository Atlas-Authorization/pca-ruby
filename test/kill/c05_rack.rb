# frozen_string_literal: true

require 'stringio'
require 'base64'
require 'json'

# Exact kills for lib/atlas_pca/rack_middleware.rb (PCA 0.5 mutation gate).
#
# The mutation oracle drops AtlasPca and re-evaluates it per mutant, so a class captured at load time is the ORIGINAL one and
# decides nothing about a mutant: 9h_rack_targeted.rb built its signature_only subclass once at load (SigOnly), which left the
# whole file untested. RackT.mw is redefined here to resolve AtlasPca::RackMiddleware on every call; every test below also
# resolves AtlasPca at call time. The authorize / executor wiring is pinned with Seam spies (AtlasPca.authorize,
# AtlasPca.verify_pcactn, a stand-in executor), the host callbacks with recording lambdas.
module MutationKill
  module RackT
    def self.mw = Class.new(AtlasPca::RackMiddleware) { def initialize(app, **o) = super(app, signature_only: true, **o) }
  end

  module C05Rack
    module_function

    F = 'rack_middleware.rb'
    APP = ->(_env) { [200, {}, ['ok']] }
    OP = { 'verb' => 'read', 'resource' => 'doc', 'params' => {} }.freeze
    H = Struct.new(:authorization, :idempotency_key)

    class SpyExec
      attr_reader :args, :kw

      def initialize(&fn)
        @fn = fn
      end

      def call(pcactn, operation, **kw, &blk)
        @args = [pcactn, operation]
        @kw = kw
        @fn.call(blk)
      end
    end

    class Body
      attr_reader :closed

      def initialize(chunks)
        @chunks = chunks
        @closed = false
      end

      def each(&blk) = @chunks.each(&blk)

      def close
        @closed = true
      end
    end

    def klass = AtlasPca::RackMiddleware
    def res = ->(_r) { { 'id' => 'g' } }
    def pct = { 'grant_ref' => 'g' }
    def b64(text) = AtlasPca.b64e(text.b)
    def hdr_env(extra = {}) = { 'HTTP_PCA_ACTION' => AtlasPca.b64e(AtlasPca.canon_bytes(pct)), 'rack.input' => StringIO.new('') }.merge(extra)
    def build(app: APP, **o) = klass.new(app, **{ audience: 'aud', resolve_grant: res }.merge(o))
    def sig(app: APP, **o) = klass.new(app, **{ audience: 'aud', resolve_grant: res, signature_only: true }.merge(o))
    def allow = AtlasPca::AuthorizeResult.new(allow: true, status: 200, checks: {}, verdict: :v, pcactn: :p, operation: :o)

    # the whole response parsed: [status, headers, JSON body]
    def got(resp) = [resp[0], resp[1], JSON.parse(resp[2].join)]

    def refusal(status, code, desc, extra = {})
      [status, { 'content-type' => 'application/json', 'WWW-Authenticate' => %(PCA realm="pca", error="#{code}") },
       { 'error' => code, 'error_description' => desc }.merge(extra).merge('doc' => AtlasPca.refusal_doc(desc))]
    end

    def plain(status, code, desc) = [status, { 'content-type' => 'application/json' }, { 'error' => code, 'error_description' => desc }]

    def ck(label, cond) = cond || raise("c05 rack: #{label}")

    def raises(cls, msg = nil)
      yield
      false
    rescue cls => e
      e.instance_of?(cls) && (msg.nil? || e.message == msg)
    end

    # run m.call(env) with AtlasPca.authorize replaced by a recorder answering `result`
    def run_authorize(m, env, result = allow)
      calls = []
      impl = ->(pcactn, **kw) { calls << [pcactn, kw]; result }
      resp = Seam.with(AtlasPca, { authorize: impl }) { m.call(env) }
      [resp, calls]
    end

    # run m.call(env) with AtlasPca.verify_pcactn replaced by a recorder answering an allowing verdict
    def run_verify(m, env, checks = {})
      calls = []
      impl = ->(pcactn, grant, **kw) { calls << [pcactn, grant, kw]; AtlasPca::Verdict.new(true, checks, nil) }
      resp = Seam.with(AtlasPca, { verify_pcactn: impl }) { m.call(env) }
      [resp, calls]
    end

    def ctor
      k = klass
      r = res
      ops = AtlasPca::MemoryOperationStore.new
      wf = 'workflow: needs the authorize path (not signature_only)'
      ck('aud nil', raises(ArgumentError, 'audience: is required') { k.new(nil, audience: nil, resolve_grant: r) })
      ck('aud empty', raises(ArgumentError, 'audience: is required') { k.new(nil, audience: '', resolve_grant: r) })
      ck('aud int', !raises(ArgumentError) { k.new(nil, audience: 5, resolve_grant: r) })
      ck('resolver', raises(ArgumentError, 'resolve_grant: must respond to #call') { k.new(nil, audience: 'a', resolve_grant: 5) })
      ck('intent_v2', raises(ArgumentError, 'intent_v2: must be a Hash or respond to #call') { k.new(nil, audience: 'a', resolve_grant: r, intent_v2: 5) })
      ck('workflow str', raises(ArgumentError, 'workflow: must be a Hash') { k.new(nil, audience: 'a', resolve_grant: r, workflow: 'x') })
      ck('workflow arr', raises(ArgumentError, 'workflow: must be a Hash') { k.new(nil, audience: 'a', resolve_grant: r, workflow: []) })
      ck('workflow sig', raises(ArgumentError, wf) { k.new(nil, audience: 'a', resolve_grant: r, workflow: {}, signature_only: true) })
      ck('workflow nil sig', !raises(ArgumentError) { k.new(nil, audience: 'a', resolve_grant: r, signature_only: true) })
      ck('workflow ok', !raises(ArgumentError) { k.new(nil, audience: 'a', resolve_grant: r, workflow: {}) })
      ck('step int', raises(ArgumentError, 'workflow_step: must respond to #call') { k.new(nil, audience: 'a', resolve_grant: r, workflow_step: 5) })
      ck('step nil', !raises(ArgumentError) { k.new(nil, audience: 'a', resolve_grant: r, workflow_step: nil) })
      ck('step ok', !raises(ArgumentError) { k.new(nil, audience: 'a', resolve_grant: r, workflow_step: -> {}) })
      ck('exec sig', raises(ArgumentError, 'executor: needs the authorize path (not signature_only)') do
        k.new(nil, audience: 'a', resolve_grant: r, signature_only: true, executor: { operations: ops })
      end)
      ck('exec int', raises(ArgumentError, 'executor: must be a Hash of executor options') { k.new(nil, audience: 'a', resolve_grant: r, executor: 5) })
      ck('exec ops nil', raises(ArgumentError, 'executor: operations: (an OperationStore) is required') { k.new(nil, audience: 'a', resolve_grant: r, executor: { operations: nil }) })
      ck('exec ops obj', raises(ArgumentError, 'executor: operations: (an OperationStore) is required') { k.new(nil, audience: 'a', resolve_grant: r, executor: { operations: Object.new }) })
      ck('exec unknown', raises(ArgumentError, 'executor: unknown option(s) bogus, other') do
        k.new(nil, audience: 'a', resolve_grant: r, executor: { operations: ops, bogus: 1, other: 2 })
      end)
      ck('auth int', raises(ArgumentError, 'authorize: must be an AtlasPca::AuthorizeOptions or a Hash') { k.new(nil, audience: 'a', resolve_grant: r, authorize: 5) })
      ck('auth unknown', raises(ArgumentError, 'authorize: unknown option(s) bogus, zzz') do
        k.new(nil, audience: 'a', resolve_grant: r, authorize: { 'bogus' => 1, 'zzz' => 2 })
      end)
      ck('auth+sig', raises(ArgumentError) { k.new(nil, audience: 'a', resolve_grant: r, signature_only: true, authorize: {}) })
      true
    end

    def option_keys
      store = AtlasPca::MemoryStateStore.new
      vals = { require: ['x'], escalation_principals: ['p'], k1: { 'a' => 1 }, uses_store: Object.new }
      vals.each do |key, v|
        [key, key.to_s].each do |kk|
          m = build(authorize: { state_store: store, kk => v })
          ao = m.instance_variable_get(:@authorize)
          ck("authorize key #{kk.inspect}", ao.public_send(key).equal?(v))
        end
      end
      ops = AtlasPca::MemoryOperationStore.new
      ex = { recheck: ->(_h) { { 'ok' => true } }, recheck_for: 'always', reversibility_class_of: ->(_o) { 'r' }, pending_timeout_ms: 77 }
      iv = { recheck: :@extra, recheck_for: :@recheck_for, reversibility_class_of: :@cls_of, pending_timeout_ms: :@timeout }
      ex.each do |key, v|
        [key, key.to_s].each do |kk|
          e = build(executor: { operations: ops, kk => v }).instance_variable_get(:@executor)
          ck("executor key #{kk.inspect}", e.instance_variable_get(iv[key]).equal?(v))
        end
      end
      e = build(executor: { 'operations' => ops }).instance_variable_get(:@executor)
      ck('executor string operations', e.instance_variable_get(:@ops).equal?(ops))
      ao = AtlasPca::AuthorizeOptions.new(state_store: store)
      ck('options object passes through', build(authorize: ao).instance_variable_get(:@authorize).equal?(ao))
      true
    end

    def verify_wiring
      list = ['ed25519']
      m = sig(allowed_suites: list)
      t0 = (Time.now.to_f * 1000).to_i
      resp, calls = run_verify(m, hdr_env)
      t1 = (Time.now.to_f * 1000).to_i
      ck('allowed', resp[0] == 200)
      pc, grant, kw = calls[0]
      ck('args', pc == pct && grant == { 'id' => 'g' })
      ck('keys', kw.keys.sort == %i[allowed_suites audience fresh_at insecure_skip_plan_root_check intent_policy intent_v2 now])
      ck('wall clock', kw[:now].instance_of?(Integer) && kw[:now] >= t0 && kw[:now] <= t1)
      ck('defaults', kw[:audience] == 'aud' && kw[:intent_policy].nil? && kw[:intent_v2].nil? && kw[:fresh_at].nil?)
      ck('suites snapshot', kw[:allowed_suites] == ['ed25519'] && kw[:allowed_suites].frozen? && !kw[:allowed_suites].equal?(list))
      list << 'ml-dsa-65'
      _, calls2 = run_verify(m, hdr_env)
      ck('suites not widened', calls2[0][2][:allowed_suites] == ['ed25519'])
      _, c3 = run_verify(sig, hdr_env)
      ck('suites nil', c3[0][2][:allowed_suites].nil?)
      _, c4 = run_verify(sig(now: -> { 42 }), hdr_env)
      ck('now callable', c4[0][2][:now] == 42)
      _, c5 = run_verify(sig(now: 7), hdr_env)
      ck('now int', c5[0][2][:now] == 7)
      ta = (Time.now.to_f * 1000).to_i
      _, c6 = run_verify(sig(now: -> {}), hdr_env)
      tb = (Time.now.to_f * 1000).to_i
      ck('now callable nil', c6[0][2][:now].instance_of?(Integer) && c6[0][2][:now] >= ta && c6[0][2][:now] <= tb)
      ip = { 'a' => 1 }
      fa = { 'c' => 3 }
      _, c7 = run_verify(sig(intent_policy: ip, intent_v2: { 'b' => 2 }, fresh_at: fa), hdr_env)
      kw7 = c7[0][2]
      ck('policy forwarded', kw7[:intent_policy].equal?(ip) && kw7[:intent_v2] == { 'b' => 2 } && kw7[:fresh_at].equal?(fa))
      true
    end

    def core_refusals
      ck('no pcactn', got(sig.call('rack.input' => StringIO.new(''))) == refusal(401, 'invalid_pcactn', 'no PCActn presented'))
      seen = []
      [nil, 5, [], {}, true].each do |v|
        env = hdr_env('HTTP_PCA_ACTION' => AtlasPca.b64e(AtlasPca.canon_bytes('grant_ref' => v)))
        ck("grant_ref #{v.inspect}", got(sig(resolve_grant: ->(r) { seen << r; { 'id' => 'g' } }).call(env)) == refusal(401, 'invalid_pcactn', 'malformed PCActn'))
      end
      ck('resolver not reached', seen.empty?)
      ck('unknown grant', got(sig(resolve_grant: ->(_r) {}).call(hdr_env)) == refusal(401, 'invalid_pcactn', 'unknown grant'))
      ck('resolver raises', got(sig(resolve_grant: ->(_r) { raise 'boom' }).call(hdr_env)) == refusal(403, 'access_denied', 'grant resolution failed (fail closed)'))
      ck('v2 raises', got(sig(intent_v2: ->(_p) { raise 'boom' }).call(hdr_env)) ==
                      refusal(403, 'intent_v2_context_error', 'intent v2 verifier state unavailable (fail closed)'))
      # intent_v2: a Hash (even one that answers #call) goes in as is; a callable is asked with the PCActn
      h = { 'b' => 2 }
      called = false
      h.define_singleton_method(:call) { |*| called = true; {} }
      _, c = run_verify(sig(intent_v2: h), hdr_env)
      ck('hash v2 as is', c[0][2][:intent_v2].equal?(h) && !called)
      got_arg = nil
      v2 = { 'q' => 1 }
      _, c2 = run_verify(sig(intent_v2: ->(p) { got_arg = p; v2 }), hdr_env)
      ck('callable v2', got_arg == pct && c2[0][2][:intent_v2].equal?(v2))
      true
    end

    def bond
      m = sig
      seen = nil
      m.define_singleton_method(:forbidden) { |v| seen = v; [403, {}, []] }
      env = hdr_env('HTTP_PCA_ACTION' => AtlasPca.b64e(AtlasPca.canon_bytes('grant_ref' => 'g', 'bond_ref' => 'b')))
      run_verify(m, env, { 'x' => true })
      ck('bond verdict', seen.allow.equal?(false) && seen.checks == { 'x' => true, 'bond' => false } && seen.reason == AtlasPca::BOND_UNSUPPORTED)
      resp, = run_verify(sig, env, { 'x' => true })
      ck('bond refusal', got(resp) == refusal(403, 'access_denied', AtlasPca::BOND_UNSUPPORTED, 'failed_checks' => ['bond']))
      app_ran = false
      run_verify(sig(app: ->(_e) { app_ran = true; [200, {}, []] }), env)
      ck('bond app not run', !app_ran)
      true
    end

    def fresh_at
      f = { 'a' => 1 }
      good = { 'HTTP_PCA_FRESH_AT' => b64('{"x":1}') }
      m = build(fresh_at: f)
      ck('present', m.send(:fresh_at_policy, good, {}) == { 'a' => 1, 'side_carried' => { 'x' => 1 } })
      ck('not mutated', f == { 'a' => 1 })
      ck('pcactn has member', m.send(:fresh_at_policy, good, { 'fresh_at' => 1 }).equal?(f))
      ck('no header', m.send(:fresh_at_policy, {}, {}).equal?(f))
      ck('empty header', m.send(:fresh_at_policy, { 'HTTP_PCA_FRESH_AT' => '' }, {}).equal?(f))
      ck('bad base64', m.send(:fresh_at_policy, { 'HTTP_PCA_FRESH_AT' => 'not base64!' }, {}) == { 'a' => 1, 'side_carried' => nil })
      ck('bad json', m.send(:fresh_at_policy, { 'HTTP_PCA_FRESH_AT' => b64('{"a":') }, {}) == { 'a' => 1, 'side_carried' => nil })
      ck('array top', m.send(:fresh_at_policy, { 'HTTP_PCA_FRESH_AT' => b64('[1]') }, {}) == { 'a' => 1, 'side_carried' => nil })
      ck('side_carried is nil, not false', m.send(:fresh_at_policy, { 'HTTP_PCA_FRESH_AT' => 'not base64!' }, {})['side_carried'].nil?)
      ck('nil policy', build.send(:fresh_at_policy, good, {}).nil?)
      ck('string policy', build(fresh_at: 'x').send(:fresh_at_policy, good, {}) == 'x')
      true
    end

    def workflow
      step = { 's' => 1 }
      refused = refusal(403, 'access_denied', 'workflow: this call carries no workflow step (fail closed)', 'failed_checks' => ['workflow'], 'decision' => 'deny')
      [{ 'required' => true }, { required: true }].each do |wf|
        resp, calls = run_authorize(build(workflow: wf), hdr_env)
        ck("required #{wf}", got(resp) == refused && calls.empty?)
        bad = hdr_env('HTTP_PCA_ACTION' => 'not base64!')
        ck("required precedes the decode #{wf}", got(build(workflow: wf).call(bad)) == refused)
        resp, = run_authorize(build(workflow: wf, workflow_step: ->(_e) { raise 'boom' }), hdr_env)
        ck("raising step is no step #{wf}", got(resp) == refused)
        resp, = run_authorize(build(workflow: wf, workflow_step: ->(_e) {}), hdr_env)
        ck("nil step #{wf}", got(resp) == refused)
        resp, calls = run_authorize(build(workflow: wf, workflow_step: ->(_e) { step }), hdr_env)
        ck("step present #{wf}", resp[0] == 200 && calls[0][1][:workflow_call].equal?(step))
      end
      [{}, { 'required' => false }, { 'required' => 'yes' }, { 'required' => 1 }].each do |wf|
        resp, calls = run_authorize(build(workflow: wf), hdr_env)
        ck("not required #{wf}", resp[0] == 200 && calls.length == 1 && calls[0][1][:workflow_call].nil? && calls[0][1][:workflow] == wf)
      end
      # no workflow option: the callback is never asked and the step is exactly nil
      asked = 0
      resp, calls = run_authorize(build(workflow_step: ->(_e) { asked += 1; step }), hdr_env)
      ck('no workflow option', resp[0] == 200 && asked.zero? && calls[0][1][:workflow_call].nil? && calls[0][1][:workflow].nil?)
      # the callback gets the env
      env = hdr_env
      seen_env = nil
      run_authorize(build(workflow: {}, workflow_step: ->(e) { seen_env = e; step }), env)
      ck('callback env', seen_env.equal?(env))
      # the step from the JSON body
      body = ->(text) { hdr_env('rack.input' => StringIO.new(text)) }
      [['{"workflow":{"s":1}}', { 's' => 1 }], ['{"workflow":5}', 5], ['{}', nil], ['', nil], ['x', nil], ['[1]', nil]].each do |text, want|
        _, calls = run_authorize(build(workflow: {}), body.call(text))
        ck("body #{text.inspect}", calls[0][1][:workflow_call] == want && calls[0][1][:workflow_call].nil? == want.nil?)
      end
      rewound = StringIO.new('{"workflow":{"s":1}}')
      run_authorize(build(workflow: {}), hdr_env('rack.input' => rewound))
      ck('body rewound', rewound.read == '{"workflow":{"s":1}}')
      _, calls = run_authorize(build(workflow: {}), hdr_env('rack.input' => nil))
      ck('input nil', calls[0][1][:workflow_call].nil?)
      once = Class.new { def read = nil }.new
      _, calls = run_authorize(build(workflow: {}), hdr_env('rack.input' => once))
      ck('read nil', calls[0][1][:workflow_call].nil?)
      true
    end

    def wiring
      store = AtlasPca::MemoryStateStore.new
      s = Hash.new { |h, k| h[k] = Object.new }
      revoked = ->(_p, _g) { false }
      opmap = ->(_e) { OP }
      ctx = ->(_p) {}
      bundle = ->(_p, _o) {}
      prov = { 'bundle' => bundle, 'mediators' => [1] }
      ao = AtlasPca::AuthorizeOptions.new(state_store: store, is_revoked: revoked, plan: 'p', context: ctx, require: ['x'], operation: opmap,
                                          escalation_principals: ['pr'], revocation_staleness: s[:rs], plans: s[:plans],
                                          require_assurance: { 'signature' => 'pq' }, k1: nil, uses_store: s[:uses],
                                          escalation_render: s[:render], insecure_unbound_approval: true, provenance: prov, undo: s[:undo])
      rg = res
      wfs = { 's' => 1 }
      wf = { 'x' => 1 }
      ip = { 'i' => 1 }
      v2 = { 'v' => 1 }
      fa = { 'f' => 1 }
      suites = ['ed25519']
      seen = []
      m = klass.new(->(e) { seen << e['pca']; [200, { 'h' => 'v' }, ['ok']] }, audience: 'aud', resolve_grant: rg, now: 1234, authorize: ao,
                                                                                intent_policy: ip, intent_v2: v2, fresh_at: fa, allowed_suites: suites,
                                                                                workflow: wf, workflow_step: ->(_e) { wfs })
      resp, calls = run_authorize(m, hdr_env)
      ck('response', resp == [200, { 'h' => 'v' }, ['ok']])
      pc, kw = calls[0]
      ck('pcactn', pc == pct)
      want = { operation: OP, audience: 'aud', resolve_grant: rg, state_store: store, is_revoked: revoked, now: 1234, plan: 'p', context: ctx,
               intent_policy: ip, intent_v2: v2, allowed_suites: ['ed25519'], require: ['x'], escalation_principals: ['pr'], escalation_answer: nil,
               revocation_staleness: s[:rs], plans: s[:plans], require_assurance: { 'signature' => 'pq' }, fresh_at: fa, k1: nil,
               uses_store: s[:uses], escalation_render: s[:render], insecure_unbound_approval: true, workflow: wf, workflow_call: wfs,
               provenance: prov, undo: s[:undo], risk: nil, threshold_hook: nil, pq_pins: nil, require_risk_inputs: nil, resolve_principal: nil, require_verified_principal: nil, require_passport: nil, passport: nil, enforce_freshness: nil, adaptive: nil, seed_budget: nil, enforce_taint: nil, beacon: nil, require_linked_template: nil, forbid: nil, contracts: nil, multi_instance: AtlasPca.store_shared?(store) }
      ck('keys', kw.keys.sort == want.keys.sort)
      want.each { |k, v| ck("kw #{k}", kw[k] == v && kw[k].nil? == v.nil?) }
      ck('env pca', seen == [{ 'verdict' => :v, 'pcactn' => :p, 'authorization' => allow, 'operation' => :o }])
      [[true, true], ['yes', false], [nil, false], [1, false]].each do |given, expect|
        o = AtlasPca::AuthorizeOptions.new(insecure_unbound_approval: given)
        _, c = run_authorize(build(authorize: o), hdr_env)
        ck("insecure_unbound_approval #{given.inspect}", c[0][1][:insecure_unbound_approval].equal?(expect))
      end
      # defaults: no operation mapping, no configuration
      _, c = run_authorize(build, hdr_env)
      kw = c[0][1]
      ck('defaults', kw[:operation].nil? && kw[:plan].nil? && kw[:require] == [] && kw[:k1].nil? && kw[:workflow].nil? && kw[:workflow_call].nil? &&
                     kw[:provenance].is_a?(Hash) && kw[:provenance]['bundle'].respond_to?(:call) && kw[:allowed_suites].nil?)
      # the Hash form carries the same members
      _, c = run_authorize(build(authorize: { state_store: store, require: ['y'], uses_store: s[:uses], k1: { 'a' => 1 } }), hdr_env)
      kw = c[0][1]
      ck('hash form', kw[:require] == ['y'] && kw[:uses_store].equal?(s[:uses]) && kw[:k1].call(pct) == { 'a' => 1 })
      true
    end

    def operation_mapping
      env = hdr_env
      seen = nil
      _, c = run_authorize(build(authorize: { operation: ->(e) { seen = e; OP } }), env)
      ck('mapped', c[0][1][:operation] == OP && seen.equal?(env))
      _, c = run_authorize(build(authorize: { operation: OP }), hdr_env)
      ck('non-callable mapping', c.length == 1 && c[0][1][:operation].nil?)
      _, c = run_authorize(build, hdr_env)
      ck('no mapping', c.length == 1 && c[0][1][:operation].nil?)
      app_ran = false
      resp, c = run_authorize(build(app: ->(_e) { app_ran = true; [200, {}, []] }, authorize: { operation: ->(_e) { raise 'boom' } }), hdr_env)
      ck('raising mapping', got(resp) == refusal(403, 'access_denied', 'operation: the operation mapping failed (fail closed)', 'failed_checks' => ['operation']) &&
                            c.empty? && !app_ran)
      true
    end

    def denials
      res1 = AtlasPca::AuthorizeResult.new(allow: false, status: 403, checks: { 'a' => 'fail', 'b' => 'pass' }, reason: nil)
      resp, = run_authorize(build, hdr_env, res1)
      ck('403 default reason', got(resp) == refusal(403, 'access_denied', 'denied', 'failed_checks' => ['a'], 'decision' => 'deny'))
      res2 = AtlasPca::AuthorizeResult.new(allow: false, status: 401, checks: { 'a' => 'fail' }, reason: 'r1', decision: 'escalate',
                                           escalation: { 'k' => 'v' }, missing: ['m'])
      resp, = run_authorize(build, hdr_env, res2)
      ck('401 with extras', got(resp) == refusal(401, 'invalid_pcactn', 'r1', 'failed_checks' => ['a'], 'decision' => 'escalate', 'escalation' => { 'k' => 'v' }, 'missing' => ['m']))
      ck('extras order', JSON.parse(resp[2].join).keys == %w[error error_description failed_checks decision escalation missing doc])
      res3 = AtlasPca::AuthorizeResult.new(allow: false, status: 403, checks: {}, reason: 'r3')
      resp, = run_authorize(build, hdr_env, res3)
      ck('403 without extras', got(resp) == refusal(403, 'access_denied', 'r3', 'failed_checks' => [], 'decision' => 'deny') &&
                               JSON.parse(resp[2].join).keys == %w[error error_description failed_checks decision doc])
      true
    end

    def escalation
      st = AtlasPca::MemoryStateStore.new
      m = build(authorize: { state_store: st, escalation_principals: ['p'] })
      ans = ->(env) { run_authorize(m, env)[1][0][1][:escalation_answer] }
      body = ->(text) { hdr_env('rack.input' => StringIO.new(text)) }
      ck('header', ans.call(hdr_env('HTTP_PCA_ESCALATION_ANSWER' => b64('{"a":1}'))) == { 'a' => 1 })
      ck('header not base64', ans.call(hdr_env('HTTP_PCA_ESCALATION_ANSWER' => 'not base64!')).nil?)
      ck('header array', ans.call(hdr_env('HTTP_PCA_ESCALATION_ANSWER' => b64('[1]'))).nil?)
      ck('header wins over body', ans.call(hdr_env('HTTP_PCA_ESCALATION_ANSWER' => b64('{"a":1}'), 'rack.input' => StringIO.new('{"escalation_answer":{"b":2}}'))) == { 'a' => 1 })
      ck('body', ans.call(body.call('{"escalation_answer":{"b":2}}')) == { 'b' => 2 })
      ck('empty header falls to body', ans.call(hdr_env('HTTP_PCA_ESCALATION_ANSWER' => '', 'rack.input' => StringIO.new('{"escalation_answer":{"b":2}}'))) == { 'b' => 2 })
      ['', 'x', '{}', '[1]'].each { |text| ck("body #{text.inspect}", ans.call(body.call(text)).nil?) }
      ck('input nil', ans.call(hdr_env('rack.input' => nil)).nil?)
      ck('read nil', ans.call(hdr_env('rack.input' => Class.new { def read = nil }.new)).nil?)
      rewound = StringIO.new('{"escalation_answer":{"b":2}}')
      ans.call(hdr_env('rack.input' => rewound))
      ck('body rewound', rewound.read == '{"escalation_answer":{"b":2}}')
      # none pinned (nil or empty): the answer is never read
      [nil, []].each do |pins|
        o = AtlasPca::AuthorizeOptions.new(escalation_principals: pins)
        mm = build(authorize: o)
        out = run_authorize(mm, hdr_env('HTTP_PCA_ESCALATION_ANSWER' => b64('{"a":1}')))[1][0][1][:escalation_answer]
        ck("unpinned #{pins.inspect}", out.nil?)
        out = run_authorize(mm, hdr_env('rack.input' => StringIO.new('{"escalation_answer":{"b":2}}')))[1][0][1][:escalation_answer]
        ck("unpinned body #{pins.inspect}", out.nil?)
      end
      true
    end

    def provenance
      m = build
      ck('non-hash passes on', m.send(:provenance_option, {}, 'x') == 'x' && m.send(:provenance_option, {}, [1]) == [1])
      x = 'x'
      ck('same object', m.send(:provenance_option, {}, x).equal?(x))
      env = { 'e' => 1 }
      captured = nil
      Seam.with(AtlasPca, { default_provenance_bundle: ->(e) { captured = e; :bundle } }) do
        [nil, { mediators: [1] }, { 'mediators' => [1] }, { 'bundle' => 'x', 'mediators' => [1] }].each do |given|
          o = m.send(:provenance_option, env, given)
          want_keys = given.nil? ? ['bundle'] : %w[mediators bundle]
          ck("keys #{given.inspect}", o.keys.sort == want_keys.sort)
          ck("mediators #{given.inspect}", given.nil? || o['mediators'] == [1])
          captured = nil
          ck("default bundle #{given.inspect}", o['bundle'].call(nil, nil) == :bundle && captured.equal?(env))
        end
      end
      mine = ->(_p, _o) { :mine }
      o = m.send(:provenance_option, {}, { bundle: mine, 'mediators' => [2] })
      ck('own bundle kept', o == { 'bundle' => mine, 'mediators' => [2] } && o['bundle'].equal?(mine))
      true
    end

    def k1
      m = build
      got_p = nil
      f = m.send(:k1_option, {}, ->(p) { got_p = p; { 'a' => 1 } })
      ck('callable', f.call(:pc) == { 'a' => 1 } && got_p == :pc)
      ck('nil', m.send(:k1_option, {}, nil).nil?)
      h = { 'a' => 1 }
      called = false
      h.define_singleton_method(:call) { |*| called = true; { 'z' => 1 } }
      ck('hash with #call is a hash', m.send(:k1_option, {}, h).call(:x) == { 'a' => 1 } && !called)
      ck('symbol keys', m.send(:k1_option, {}, { a: 1 }).call(:x) == { 'a' => 1 })
      ck('other keys kept', m.send(:k1_option, {}, { 1 => 'x' }).call(:x) == { 1 => 'x' })
      ck('string not callable', raises(TypeError, 'k1 is not a Hash') { m.send(:k1_option, {}, 'x').call(:x) })
      ck('callable nil', raises(TypeError, 'k1 is not a Hash') { m.send(:k1_option, {}, ->(_p) {}).call(:x) })
      ck('callable array', raises(TypeError, 'k1 is not a Hash') { m.send(:k1_option, {}, ->(_p) { [] }).call(:x) })
      true
    end

    def executor_wiring
      st = AtlasPca::MemoryStateStore.new
      bun = ->(_p, _o) {}
      fa = { 'f' => 1 }
      ip = { 'i' => 1 }
      v2 = { 'v' => 1 }
      wf = { 'w' => 1 }
      step = { 's' => 1 }
      m = build(authorize: { state_store: st, operation: ->(_e) { OP }, k1: { 'a' => 1 }, provenance: { 'bundle' => bun }, escalation_principals: ['p'] },
                executor: { operations: AtlasPca::MemoryOperationStore.new }, intent_policy: ip, intent_v2: v2, fresh_at: fa, workflow: wf,
                workflow_step: ->(_e) { step })
      spy = SpyExec.new { |_blk| AtlasPca::ExecuteOutcome.new(status: 'failed') }
      m.instance_variable_set(:@executor, spy)
      resp = m.call(hdr_env('HTTP_PCA_ESCALATION_ANSWER' => b64('{"z":1}')))
      ck('failed', got(resp) == plain(500, 'operation_failed', 'the operation failed'))
      ck('args', spy.args == [pct, OP])
      kw = spy.kw
      ck('kw keys', kw.keys.sort == %i[escalation_answer fresh_at intent_policy intent_v2 k1 provenance workflow workflow_call])
      ck('kw plain', kw[:intent_policy].equal?(ip) && kw[:intent_v2].equal?(v2) && kw[:fresh_at].equal?(fa) && kw[:workflow].equal?(wf) && kw[:workflow_call].equal?(step))
      ck('kw answer', kw[:escalation_answer] == { 'z' => 1 })
      ck('kw k1', kw[:k1].call(pct) == { 'a' => 1 })
      ck('kw provenance', kw[:provenance] == { 'bundle' => bun })
      # unconfigured: k1 is nil, no answer
      m2 = build(executor: { operations: AtlasPca::MemoryOperationStore.new })
      spy2 = SpyExec.new { |_blk| AtlasPca::ExecuteOutcome.new(status: 'failed') }
      m2.instance_variable_set(:@executor, spy2)
      m2.call(hdr_env)
      ck('kw unconfigured', spy2.kw[:k1].nil? && spy2.kw[:escalation_answer].nil? && spy2.kw[:workflow_call].nil? && spy2.kw[:workflow].nil?)
      true
    end

    def executor_block
      az = AtlasPca::AuthorizeResult.new(allow: true, status: 200, checks: {}, verdict: :v, pcactn: :p, operation: :o)
      recorded = nil
      body = Body.new(['é', "\xFF".b, 5])
      seen = nil
      app = ->(e) { seen = e['pca']; [201, { a: 1, 'x-y' => 'z' }, body] }
      m = build(app: app, authorize: { operation: ->(_e) { OP } }, executor: { operations: AtlasPca::MemoryOperationStore.new })
      spy = SpyExec.new do |blk|
        recorded = blk.call(H.new(az, 'idk'))
        AtlasPca::ExecuteOutcome.new(status: 'committed', result: recorded)
      end
      m.instance_variable_set(:@executor, spy)
      resp = m.call(hdr_env)
      bytes = "\xC3\xA9\xFF5".b
      ck('recorded', recorded == { 'status' => 201, 'headers' => { 'a' => '1', 'x-y' => 'z' }, 'body' => Base64.strict_encode64(bytes) })
      ck('env pca', seen == { 'verdict' => :v, 'pcactn' => :p, 'authorization' => az, 'operation' => :o, 'idempotency_key' => 'idk' })
      ck('response', resp == [201, { 'a' => '1', 'x-y' => 'z' }, [bytes]])
      ck('body closed', body.closed)
      # a body without #close is fine
      m2 = build(app: ->(_e) { [200, {}, ['a', 'b']] }, authorize: { operation: ->(_e) { OP } }, executor: { operations: AtlasPca::MemoryOperationStore.new })
      m2.instance_variable_set(:@executor, SpyExec.new { |blk| AtlasPca::ExecuteOutcome.new(status: 'committed', result: blk.call(H.new(az, 'k'))) })
      ck('no close', m2.call(hdr_env) == [200, {}, ['ab'.b]])
      true
    end

    def executor_outcomes
      m = build(authorize: { operation: ->(_e) { OP } }, executor: { operations: AtlasPca::MemoryOperationStore.new })
      run = lambda do |**o|
        m.instance_variable_set(:@executor, SpyExec.new { |_blk| AtlasPca::ExecuteOutcome.new(**o) })
        got(m.call(hdr_env))
      end
      ck('aborted', run.call(status: 'aborted', reason: 'why') == refusal(403, 'operation_aborted', 'why'))
      ck('pending', run.call(status: 'pending') == plain(409, 'operation_in_progress', 'another execution of this operation is in flight'))
      ck('uncertain', run.call(status: 'uncertain', reason: 'u') == plain(409, 'operation_uncertain', 'u'))
      ck('refused', run.call(status: 'refused', reason: 'rr') == refusal(403, 'access_denied', 'rr'))
      ck('failed', run.call(status: 'failed') == plain(500, 'operation_failed', 'the operation failed'))
      den = AtlasPca::AuthorizeResult.new(allow: false, status: 403, checks: { 'c' => 'fail' }, reason: 'dd')
      ck('denied', run.call(status: 'denied', authorization: den) == refusal(403, 'access_denied', 'dd', 'failed_checks' => ['c'], 'decision' => 'deny'))
      ck('aborted nil reason', run.call(status: 'aborted')[2]['error_description'] == '')
      true
    end

    def recorded
      m = build
      unreadable = plain(409, 'operation_uncertain', 'the recorded result is unreadable')
      good = -> { { 'status' => 201, 'headers' => { 'a' => 'b' }, 'body' => Base64.strict_encode64('hi') } }
      rr = ->(res, replayed = false) { m.send(:recorded_response, AtlasPca::ExecuteOutcome.new(status: 'committed', result: res, replayed: replayed)) }
      ck('good', rr.call(good.call) == [201, { 'a' => 'b' }, ['hi']])
      r = good.call
      ck('replayed', rr.call(r, true) == [201, { 'a' => 'b', 'pca-replayed' => 'true' }, ['hi']] && r['headers'] == { 'a' => 'b' })
      ck('not replayed', !rr.call(good.call)[1].key?('pca-replayed'))
      bad = [nil, [], 'x', 5, good.call.merge('status' => '201'), good.call.merge('status' => nil), good.call.merge('headers' => []),
             good.call.merge('headers' => nil), good.call.merge('body' => 5), good.call.merge('body' => nil), good.call.merge('body' => 'not base64!'),
             good.call.merge('body' => 'aGk')]
      bad.each { |b| ck("unreadable #{b.inspect}", got(rr.call(b)) == unreadable) }
      true
    end

    def forbidden_and_json
      m = build
      deny = ->(reason) { AtlasPca::Verdict.new(false, { 'a' => true, 'b' => false, 'c' => false }, reason) }
      [nil, ''].each do |reason|
        ck("reason #{reason.inspect}", got(m.send(:forbidden, deny.call(reason))) == refusal(403, 'access_denied', 'policy denied the action', 'failed_checks' => %w[b c]))
      end
      ck('reason kept', got(m.send(:forbidden, deny.call('why'))) == refusal(403, 'access_denied', 'why', 'failed_checks' => %w[b c]))
      ck('to_json nil', m.send(:to_json, { 'a' => nil }) == '{"a":""}')
      ck('to_json int', m.send(:to_json, { 'a' => 5 }) == '{"a":"5"}')
      ck('to_json str', m.send(:to_json, { 'a' => 'x' }) == '{"a":"x"}')
      ck('to_json hash', m.send(:to_json, { 'k' => { 'b' => 1, 'a' => 2 } }) == '{"k":{"a":2,"b":1}}')
      ck('to_json array', m.send(:to_json, { 'k' => %w[a b] }) == '{"k":["a","b"]}')
      true
    end
  end

  %w[ctor option_keys verify_wiring core_refusals bond fresh_at workflow wiring operation_mapping denials escalation provenance k1
     executor_wiring executor_block executor_outcomes recorded forbidden_and_json].each do |name|
    t("c05 rack middleware: #{name}") do
      next true if DiffUtil.skip?(C05Rack::F)

      C05Rack.send(name)
    end
  end
end
