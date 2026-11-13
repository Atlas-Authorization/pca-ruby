# frozen_string_literal: true

# za_a3: kill tests for AtlasPca.authorize (authorize.rb): the revocation-state gate and its epoch pin, the trust budget key and
# persistence, the threshold step-up rule, the risk-input requirement and the replay head reported beside other failures.
# Reference: packages/pca/src/server/authorize.ts, policy-vm.ts (decide steps 3-5), risk.ts. Reuses C06, F01 and ZaA (za_a1).

module MutationKill
  # a canned policy_risk_step answer (a fresh Hash per call: authorize writes its 'key' into it)
  za_rs = lambda do |over = {}|
    { 'r' => 0.5, 'threshold' => { 't' => 1, 'proof' => 'proof-x' }, 'adm' => {}, 'stored' => nil, 'persist' => false,
      'after' => { 'B' => 8, 'tau' => 1, 'asOf' => 1 }, 'budget_present' => true, 'reasons' => [] }.merge(over)
  end
  za_with_rs = lambda do |over, cap = [], &blk|
    Seam.with(AtlasPca, { policy_risk_step: ->(*a) { cap << a; za_rs.call(over) } }, &blk)
  end

  t('za authorize revocation_staleness: a failed freshness gate stands, the epoch pin merge, and the accepted epoch pin') do
    next true unless ZaA.gate?

    gid = ZaA.gid
    rs = ->(**o) { AtlasPca::RevocationStaleness.new(ids: ->(_p) { [] }, allow_unsigned_root_for_irreversible: true, **o) }
    ctx = ->(st) { ->(_p) { { 'revocation_state' => st } } }
    fresh_fail = { 'max_age_ms' => 10 }
    root = { 'kind' => 'root', 'root' => 'r', 'issued_at' => 1 }
    pinned = lambda do |pin|
      s = AtlasPca::MemoryStateStore.new
      s.raise_pin("#{gid}:epoch", pin) unless pin.nil?
      s
    end
    seen_state = lambda do |st, pin|
      cap = []
      stub = ->(_pol, state, **k) { cap << [state, k]; { 'ok' => true } }
      r = Seam.with(AtlasPca, { check_revocation_state: stub }) { ZaA.go(revocation_staleness: rs.call, context: ctx.call(st), state_store: pinned.call(pin)) }
      [cap.length, cap[0] && cap[0][0], r.checks['freshness'], r.checks.key?('authorize')]
    end
    ZaA.ck('no state, no gate: not enforced', ZaA.go(revocation_staleness: rs.call).checks['freshness'], 'not-enforced') &&
      ZaA.ck('no state: an enforce.freshness failure stands', ZaA.go(revocation_staleness: rs.call, enforce_freshness: fresh_fail).checks['freshness'], 'fail') &&
      begin
        stub = ->(*, **) { { 'ok' => true } }
        ok = Seam.with(AtlasPca, { check_revocation_state: stub }) { ZaA.go(revocation_staleness: rs.call, context: ctx.call(root)) }
        bad = Seam.with(AtlasPca, { check_revocation_state: stub }) { ZaA.go(revocation_staleness: rs.call, context: ctx.call(root), enforce_freshness: fresh_fail) }
        ZaA.ck('a state that passes', ok.checks['freshness'], 'pass') &&
          ZaA.ck('a passing state does not lift an enforce.freshness failure', bad.checks['freshness'], 'fail')
      end &&
      ZaA.ck('symbol keys, the larger of host and pin', seen_state.call({ kind: 'epoch', last_accepted_epoch: 5 }, 3),
             [1, { 'kind' => 'epoch', 'last_accepted_epoch' => 5 }, 'pass', false]) &&
      ZaA.ck('the pin is larger', seen_state.call({ kind: 'epoch', last_accepted_epoch: 5 }, 8), [1, { 'kind' => 'epoch', 'last_accepted_epoch' => 8 }, 'pass', false]) &&
      ZaA.ck('no pin stored', seen_state.call({ 'kind' => 'epoch' }, nil), [1, { 'kind' => 'epoch' }, 'pass', false]) &&
      ZaA.ck('the pin when the host has none', seen_state.call({ 'kind' => 'epoch' }, 3), [1, { 'kind' => 'epoch', 'last_accepted_epoch' => 3 }, 'pass', false]) &&
      ZaA.ck('another kind is handed over unchanged', seen_state.call({ 'kind' => 'root', 'root' => 'r' }, 4), [1, { 'kind' => 'root', 'root' => 'r' }, 'pass', false]) &&
      ZaA.ck('another kind with symbol keys is not converted', seen_state.call({ kind: 'root' }, 4), [1, { kind: 'root' }, 'pass', false]) &&
      ZaA.ck('a state that is not a Hash is handed over as is', seen_state.call('x', 4), [1, 'x', 'pass', false]) &&
      begin
        failing = Class.new(AtlasPca::MemoryStateStore) do
          def pin(key) = key.end_with?(':epoch') ? raise('down') : super
        end
        stub = ->(*, **) { { 'ok' => true } }
        r = Seam.with(AtlasPca, { check_revocation_state: stub }) { ZaA.go(revocation_staleness: rs.call, context: ctx.call({ 'kind' => 'epoch' }), state_store: failing.new) }
        ZaA.ck('a failing pin read denies', [r.allow, r.checks['freshness'], ZaA.why(r, 'freshness')], [false, 'fail', ['the revocation pin store failed (fail closed)']])
      end &&
      begin
        hook = []
        s = AtlasPca::MemoryStateStore.new
        acc = { 'epoch' => 12, 'x' => 1 }
        stub = ->(*, **) { { 'ok' => true, 'epoch' => acc } }
        pc = C06.fixture_pcactn
        r = Seam.with(AtlasPca, { check_revocation_state: stub }) do
          ZaA.go(pc, revocation_staleness: rs.call(on_epoch_accepted: ->(e, p) { hook << [e, p] }), context: ctx.call({ 'kind' => 'epoch' }), state_store: s)
        end
        ZaA.ck('an accepted epoch raises the pin and is reported', [r.allow, s.pin("#{gid}:epoch"), hook], [true, 12, [[acc, pc]]])
      end &&
      begin
        s = AtlasPca::MemoryStateStore.new
        stub = ->(*, **) { { 'ok' => true, 'epoch' => { 'epoch' => nil } } }
        r = Seam.with(AtlasPca, { check_revocation_state: stub }) { ZaA.go(revocation_staleness: rs.call, context: ctx.call({ 'kind' => 'epoch' }), state_store: s) }
        ZaA.ck('an accepted epoch with no number pins nothing', [r.allow, s.pin("#{gid}:epoch")], [true, nil])
      end
  end

  t('za authorize trust budget: the store key, the release flag and persistence at the claim') do
    next true unless ZaA.gate?

    gid = ZaA.gid
    hold = ZaA.holder
    leaf = C06.fixture_pcactn['cap_chain'].last
    args = lambda do |pc = :base, **kw|
      cap = []
      za_with_rs.call({}, cap) { ZaA.go(pc, **kw) }
      [cap[0][11], cap[0][12]]
    end
    ZaA.ck('the holder stream', args.call, ["#{gid}:#{hold}", true]) &&
      ZaA.ck('a holder that is not a String', args.call(C06.fixture_pcactn.merge('cap_chain' => [leaf.merge('holder' => 5)]))[0], "#{gid}:budget") &&
      ZaA.ck('a last hop that is not a Hash', args.call(C06.fixture_pcactn.merge('cap_chain' => [5]))[0], "#{gid}:budget") &&
      ZaA.ck('an empty chain', args.call(C06.fixture_pcactn.merge('cap_chain' => []))[0], "#{gid}:budget") &&
      ZaA.ck('a grant id that is not a String', args.call(grant: C06.base['grant'].merge('id' => 7))[0], '7:budget') &&
      begin
        pol = ->(*) { { 'allowed' => false, 'reason' => 'nope' } }
        r = nil
        cap = []
        Seam.with(AtlasPca, { evaluate_predicates: pol }) { za_with_rs.call({}, cap) { r = ZaA.go } }
        ZaA.ck('a policy failure holds the release back', [cap[0][12], r.checks['policy']], [false, 'fail'])
      end &&
      begin
        caps = []
        cap = []
        Seam.with(AtlasPca, C06.eac_seam(caps, [[false, ['a']]])) { za_with_rs.call({}, cap) { ZaA.go } }
        ZaA.ck('a delegated caveat failure holds the release back', cap[0][12], false)
      end
  end

  t('za authorize trust budget: compare-and-set after the claim, fail closed, optional seam') do
    next true unless ZaA.gate?

    key = "#{ZaA.gid}:#{ZaA.holder}"
    stored = { 'B' => 9, 'tau' => 1, 'asOf' => 1 }
    after = { 'B' => 8, 'tau' => 2, 'asOf' => 2 }
    msg = 'the budget store refused the update (changed concurrently or failed): fail closed'
    cas_store = lambda do |ret|
      Class.new(AtlasPca::MemoryStateStore) do
        attr_accessor :cas_ret, :cas_log

        def budget_cas(key, old, new)
          (self.cas_log ||= []) << [key, old, new]
          raise 'down' if cas_ret == :raise

          cas_ret
        end
      end.new.tap { |s| s.cas_ret = ret }
    end
    run = lambda do |store, persist = true|
      r = za_with_rs.call({ 'persist' => persist, 'stored' => stored, 'after' => after }) { ZaA.go(state_store: store) }
      [r.allow, r.checks['budget'], ZaA.why(r, 'budget'), r.budget]
    end
    s1 = cas_store.call(true)
    ZaA.ck('persisted', [run.call(s1), s1.cas_log], [[true, 'pass', [], after], [[key, stored, after]]]) &&
      ZaA.ck('refused', [false, nil].map { |v| run.call(cas_store.call(v))[0..2] }, [[false, 'fail', [msg]]] * 2) &&
      ZaA.ck('a failing store', run.call(cas_store.call(:raise))[0..2], [false, 'fail', [msg]]) &&
      ZaA.ck('only true is persisted', run.call(cas_store.call(1))[0..2], [false, 'fail', [msg]]) &&
      begin
        s2 = cas_store.call(false)
        ZaA.ck('nothing to persist', [run.call(s2, false)[0..1], s2.cas_log], [[true, 'pass'], nil])
      end &&
      begin
        bare = Class.new(AtlasPca::MemoryStateStore)
        bare.send(:undef_method, :budget_cas)
        ZaA.ck('a store without the seam persists nothing', run.call(bare.new)[0..2], [true, 'pass', []])
      end
  end

  t('za authorize threshold: the step-up rule against the hook, and who may release') do
    next true unless ZaA.gate?

    run = lambda do |t, hook = nil, deny_policy: false|
      pol = ->(*) { { 'allowed' => false, 'reason' => 'nope' } }
      body = -> { za_with_rs.call({ 'threshold' => { 't' => t, 'proof' => 'P' } }) { ZaA.go(threshold_hook: hook) } }
      r = deny_policy ? Seam.with(AtlasPca, { evaluate_predicates: pol }, &body) : body.call
      [r.checks['threshold'], ZaA.why(r, 'threshold').last]
    end
    no_verifier = ->(t) { "t=#{t} (P) required but no threshold verifier is enforced" }
    below = ->(shown, t) { "threshold hook enforced t=#{shown} but the server requires t=#{t} (below the server-derived threshold; derive t from server-held data)" }
    hook = ->(**h) { ->(*) { { enforced: true }.merge(h) } }
    ZaA.ck('t=1 needs nothing', run.call(1), ['not-enforced', nil]) &&
      ZaA.ck('t=2 with no verifier', run.call(2), ['fail', no_verifier.call(2)]) &&
      ZaA.ck('t=3 with no verifier', run.call(3), ['fail', no_verifier.call(3)]) &&
      ZaA.ck('a hook meeting t', run.call(2, hook.call(ok: true, t: 2)), ['pass', nil]) &&
      ZaA.ck('a hook above t', run.call(2, hook.call(ok: true, t: 3)), ['pass', nil]) &&
      ZaA.ck('a hook below t', run.call(2, hook.call(ok: true, t: 1)), ['fail', below.call(1, 2)]) &&
      ZaA.ck('a hook that reports no t', run.call(2, hook.call(ok: true)), ['fail', below.call('unreported', 2)]) &&
      ZaA.ck('a rejecting hook', run.call(2, hook.call(ok: false)).then { |s, _| s }, 'fail') &&
      ZaA.ck('a rejected proof is named', begin
        stub_run = za_with_rs.call({ 'threshold' => { 't' => 2, 'proof' => 'P' } }) { ZaA.go(threshold_hook: hook.call(ok: false)) }
        ZaA.why(stub_run, 'threshold').include?('t=2 required and the threshold proof was rejected')
      end, true) &&
      ZaA.ck('a refused policy is not released: no threshold rule', run.call(3, nil, deny_policy: true), ['not-enforced', nil])
  end

  t('za authorize require_risk_inputs and adaptive: String-typed names and Symbol-keyed policies') do
    next true unless ZaA.gate?

    inputs = lambda do |names, **kw|
      r = C06.go(require_risk_inputs: names, **kw)
      [r.checks['risk_inputs'], ZaA.why(r, 'risk_inputs')]
    end
    lack = ->(names) { ['fail', ["required risk input(s) not supplied by the server: #{names}"]] }
    ZaA.ck('no plan, no distance', inputs.call(['semanticDistance'], risk: {}, plan: nil), lack.call('semanticDistance')) &&
      ZaA.ck('a plan supplies the distance', inputs.call(['semanticDistance'], risk: {}), ['pass', []]) &&
      ZaA.ck('another input is not supplied by a plan', inputs.call(%w[taint semanticDistance], risk: {}), lack.call('taint')) &&
      ZaA.ck('symbol names', inputs.call([:semanticDistance, :taint], risk: ProvHarness::RISK), ['pass', []]) &&
      begin
        tight = F01.go(risk: ProvHarness::RISK.merge('reversibility' => 0.5), adaptive: { theta1: 0, theta2: 0 })
        ZaA.ck('a Symbol-keyed adaptive policy', [tight.allow, tight.checks['adaptive'], ZaA.why(tight, 'adaptive')],
               [false, 'fail', ['tightened policy requires threshold t=3 (grant policy: t=1)']])
      end
  end

  t('za authorize replay head: a consumed counter is reported beside other failures only when the store offers last') do
    next true unless ZaA.gate?

    gid = ZaA.gid
    skey = "#{gid}:#{ZaA.holder}"
    revoked = ->(*) { true }
    replay_text = ->(seen) { "1 is not greater than last seen #{seen} (replay)" }
    with = lambda do |seen|
      s = AtlasPca::MemoryStateStore.new
      s.claim(skey, seen)
      r = C06.go(state_store: s, is_revoked: revoked)
      [r.allow, r.checks['replay'], ZaA.why(r, 'replay')]
    end
    ZaA.ck('a counter at the head', with.call(1), [false, 'fail', [replay_text.call(1)]]) &&
      ZaA.ck('a counter behind the head', with.call(5), [false, 'fail', [replay_text.call(5)]]) &&
      ZaA.ck('a counter ahead of the head', with.call(0), [false, 'pass', []]) &&
      begin
        mm = Class.new do
          define_method(:initialize) { @inner = AtlasPca::MemoryStateStore.new }
          define_method(:claim) { |k, c| @inner.claim(k, c) }
          define_method(:method_missing) { |name, *a, &b| name == :last ? 10 : super(name, *a, &b) }
          define_method(:respond_to_missing?) { |*| false }
        end.new
        r = C06.go(state_store: mm, is_revoked: revoked)
        ZaA.ck('a store that does not offer last is not asked', [r.allow, r.checks['replay'], ZaA.why(r, 'replay')], [false, 'pass', []])
      end
  end
end
