# frozen_string_literal: true

# za_a1: kill tests for AtlasPca.authorize (authorize.rb): the post-quantum issuer pin, the enforce.freshness gate, the enforce.taint gate
# and the liveness beacon. Reference: packages/pca/src/server/{authorize,verify}.ts, pcactn.ts (the freshness gate), beacons.ts.
# Reuses the C06 / F02 / F03 helpers (those files load before this one). AtlasPca is resolved at call time.

module MutationKill
  module ZaA
    module_function

    def gate? = (f = ENV['MUT_FILE']).nil? || f.empty? || f == 'authorize.rb'

    def ck(label, got, want)
      got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    end

    # authorize over the fixture with the core verdict pinned to the honest one (the checks under test are authorize's own)
    def go(pc = :base, **kw) = C06.with_core { C06.go(pc, **kw) }

    def gid = C06.base['grant']['id']

    def holder = C06.fixture_pcactn['cap_chain'].last['holder']

    # the reasons of one check, without the "<check>: " prefix
    def why(res, check) = res.reasons.select { |w| w.start_with?("#{check}: ") }.map { |w| w.delete_prefix("#{check}: ") }
  end

  t('za authorize pq_pins: alg default, pin presence, string-typed pin and key') do
    next true unless ZaA.gate?

    g = C06.base['grant']
    iss = g['issuer']
    run = ->(grant, pins, **kw) { r = ZaA.go(grant: grant, pq_pins: pins, **kw); [r.checks['pq_pin'], ZaA.why(r, 'pq_pin')] }
    classical = 'the grant issuer is pinned to a post-quantum key; a classical grant is refused'
    dflt = Hash.new('xx')
    g.each { |k, v| dflt[k] = v unless k == 'alg' }
    pqg = g.merge('alg' => 'ml-dsa-65', 'pq_pk' => 'PK')
    always = Object.new
    def always.==(_other)
      true
    end
    str_like = Object.new
    def str_like.to_str
      'PK'
    end

    def str_like.==(_other)
      true
    end
    ZaA.ck('a classical grant with no pin for its issuer', run.call(g, {}), ['pass', []]) &&
      ZaA.ck('a non-Hash pin table pins nobody', run.call(g, []), ['pass', []]) &&
      ZaA.ck('a classical grant naming a pinned issuer', run.call(g, { iss => 'PK' }), ['fail', [classical]]) &&
      ZaA.ck('an explicit nil alg is the Ed25519 default', run.call(g.merge('alg' => nil), {}), ['pass', []]) &&
      ZaA.ck('a missing alg member is read as absent, not through a default', run.call(dflt, {}), ['pass', []]) &&
      ZaA.ck('a post-quantum grant matching its pin', run.call(pqg, { iss => 'PK' }), ['pass', []]) &&
      ZaA.ck('a post-quantum grant with another key', run.call(pqg.merge('pq_pk' => 'OTHER'), { iss => 'PK' }),
             ['fail', ['the grant pq_pk does not match the server-side pin']]) &&
      ZaA.ck('a post-quantum grant with no pin for the issuer', run.call(pqg, {}),
             ['fail', ['no server-side PQ pin for the grant issuer (suite ml-dsa-65)']]) &&
      ZaA.ck('a post-quantum grant against a non-Hash table', run.call(pqg, []),
             ['fail', ['no server-side PQ pin for the grant issuer (suite ml-dsa-65)']]) &&
      ZaA.ck('a pin that is not a String is not a match', run.call(pqg, { iss => always }),
             ['fail', ['the grant pq_pk does not match the server-side pin']]) &&
      ZaA.ck('a grant key that is not a String is not a match', run.call(pqg.merge('pq_pk' => str_like), { iss => 'PK' }),
             ['fail', ['the grant pq_pk does not match the server-side pin']]) &&
      ZaA.ck('a pin table default is no pin', run.call(pqg, Hash.new('PK')),
             ['fail', ['no server-side PQ pin for the grant issuer (suite ml-dsa-65)']]) &&
      ZaA.ck('off by default', ZaA.go.checks.key?('pq_pin'), false)
  end

  t('za authorize pq_pins: a classical grant of a pinned issuer is listed once when the core already refused it') do
    next true unless ZaA.gate?

    iss = C06.base['grant']['issuer']
    msg = 'pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused'
    refused = C06.core(allow: false, checks: C06.honest.checks.merge('pq_pin' => false), reasons: [msg], reason: msg)
    r = C06.with_core(refused) { C06.go(pq_pins: { iss => 'PK' }) }
    ZaA.ck('one entry', [r.checks['pq_pin'], r.reasons.count(msg), r.status], ['fail', 1, 401])
  end

  t('za authorize enforce.freshness: option typing, nil members, skew, bounds and the stale text') do
    next true unless ZaA.gate?

    bad = 'freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)'
    missing = 'freshness anchor is missing (empty beacon_ref or non-positive epoch stub)'
    run = ->(pc, opt) { r = ZaA.go(pc, enforce_freshness: opt); [r.checks['freshness'], ZaA.why(r, 'freshness')] }
    pcf = ->(fr) { C06.fixture_pcactn.merge('freshness' => fr) }
    anchor = ->(epoch, ref = 'b') { pcf.call('beacon_ref' => ref, 'epoch' => epoch, 'accumulator_witness' => '') }
    now_epoch = C06::NOW / 60_000
    tight = { 'epoch_ms' => 1, 'now' => 1000, 'max_age_ms' => 10 }
    ZaA.ck('an option that is not a Hash is misconfigured', [run.call(:base, true), run.call(:base, 5)], [['fail', [bad]]] * 2) &&
      ZaA.ck('symbol keys are read', run.call(anchor.call(6), { max_age_ms: 1000, epoch_ms: 1000, now: 5000, clock_skew_ms: 2000 }), ['pass', []]) &&
      ZaA.ck('nil members take their defaults', run.call(anchor.call(now_epoch), { 'max_age_ms' => 60_000, 'epoch_ms' => nil, 'now' => nil, 'clock_skew_ms' => nil }),
             ['pass', []]) &&
      ZaA.ck('a non-numeric epoch_ms', run.call(anchor.call(1), { 'max_age_ms' => 10, 'epoch_ms' => 'x' }), ['fail', [bad]]) &&
      ZaA.ck('a non-numeric max age', run.call(anchor.call(1), { 'max_age_ms' => 'x' }), ['fail', [bad]]) &&
      ZaA.ck('epoch_ms 1 is allowed', run.call(anchor.call(1000), tight), ['pass', []]) &&
      ZaA.ck('one millisecond ahead is the future', run.call(anchor.call(1001), tight), ['fail', ['freshness anchor is in the future']]) &&
      ZaA.ck('a non-numeric skew is none', run.call(anchor.call(1001), tight.merge('clock_skew_ms' => 'x')), ['fail', ['freshness anchor is in the future']]) &&
      ZaA.ck('a negative skew is none', run.call(anchor.call(1001), tight.merge('clock_skew_ms' => -5)), ['fail', ['freshness anchor is in the future']]) &&
      ZaA.ck('a skew allows the near future', run.call(anchor.call(1001), tight.merge('clock_skew_ms' => 1)), ['pass', []]) &&
      ZaA.ck('exactly the max age', run.call(anchor.call(990), tight), ['pass', []]) &&
      ZaA.ck('one past the max age', run.call(anchor.call(989), tight), ['fail', ['freshness anchor is stale (older than 10 ms)']]) &&
      ZaA.ck('the max age prints as a JS number', run.call(anchor.call(1), { 'epoch_ms' => 1, 'now' => 5000, 'max_age_ms' => 1000.0 }),
             ['fail', ['freshness anchor is stale (older than 1000 ms)']]) &&
      ZaA.ck('an anchor that is not a Hash', [[], 'x', nil].map { |fr| run.call(pcf.call(fr), { 'max_age_ms' => 10 }) }, [['fail', [missing]]] * 3) &&
      ZaA.ck('a beacon_ref that is not a String', [5, nil].map { |ref| run.call(anchor.call(1, ref), { 'max_age_ms' => 10 }) }, [['fail', [missing]]] * 2) &&
      ZaA.ck('an empty beacon_ref', run.call(anchor.call(1, ''), { 'max_age_ms' => 10 }), ['fail', [missing]]) &&
      ZaA.ck('an epoch that is not an Integer', ['x', 1.5, nil].map { |e| run.call(anchor.call(e), { 'max_age_ms' => 10 }) }, [['fail', [missing]]] * 3) &&
      ZaA.ck('a non-positive epoch', [0, -1].map { |e| run.call(anchor.call(e), { 'max_age_ms' => 10 }) }, [['fail', [missing]]] * 2) &&
      ZaA.ck('epoch 1 is positive', run.call(anchor.call(1), { 'epoch_ms' => 1, 'now' => 5, 'max_age_ms' => 10 }), ['pass', []]) &&
      ZaA.ck('the largest safe epoch is an anchor (in the future)', run.call(anchor.call(9_007_199_254_740_991), { 'max_age_ms' => 10 }),
             ['fail', ['freshness anchor is in the future']]) &&
      ZaA.ck('one beyond the safe range is no anchor', run.call(anchor.call(9_007_199_254_740_992), { 'max_age_ms' => 10 }), ['fail', [missing]])
  end

  t('za authorize enforce.taint: option typing, symbol keys and the resource graph') do
    next true unless ZaA.gate?

    run = ->(opt, pc = :base) { r = ZaA.go(pc, enforce_taint: opt); [r.checks['taint_gate'], ZaA.why(r, 'taint_gate')] }
    reg = AtlasPca::Taint::InMemoryRegistry.new
    graph = Class.new { def node(id) = id == 'n1' ? { 'id' => id } : nil }.new
    pc = C06.fixture_pcactn.merge('provenance' => C06.fixture_pcactn['provenance'].merge('trusted_refs' => ['n1']))
    unconfigured = run.call({})
    ZaA.ck('a non-Hash option is an unconfigured gate', [run.call(true), run.call(5)], [unconfigured] * 2) &&
      ZaA.ck('unconfigured is a refusal', unconfigured[0], 'fail') &&
      ZaA.ck('symbol keys are read', run.call({ registry: reg, max_taint: 1 }), ['pass', []]) &&
      ZaA.ck('a graph node is first-party', run.call({ 'registry' => reg, 'resource_graph' => graph, 'max_taint' => 0.25 }, pc), ['pass', []]) &&
      ZaA.ck('without the graph the ref is the agent', run.call({ 'registry' => reg, 'max_taint' => 0.25 }, pc)[0], 'fail')
  end

  t('za authorize beacon: acceptance, binding, replay pin, option shapes and the pin writes') do
    next true unless ZaA.gate?

    g1 = ZaA.gid
    pin_key = "#{g1}:beacon"
    mk = ->(seq = 7, **o) { F03.beacon(seq: seq, issued_at: C06::NOW - 1000, scope: g1, **o) }
    pc_for = ->(bk) { C06.fixture_pcactn.merge('freshness' => { 'beacon_ref' => AtlasPca.beacon_ref(bk), 'epoch' => 1, 'accumulator_witness' => '' }) }
    opt = ->(bk, **o) { { 'beacon' => bk, 'issuers' => [F03::ISSUER], 'instance' => F03::INSTANCE }.merge(o.transform_keys(&:to_s)) }
    store = lambda do |pin = nil|
      s = AtlasPca::MemoryStateStore.new
      s.raise_pin(pin_key, pin) unless pin.nil?
      s
    end
    required = 'beacon: required check is not-enforced (default-deny: not enforced by this resource server)'
    bk = mk.call(7)
    s1 = store.call
    ok = ZaA.go(pc_for.call(bk), beacon: opt.call(bk), state_store: s1)
    ZaA.ck('a bound, accepted beacon', [ok.allow, ok.checks['beacon'], s1.pin(pin_key)], [true, 'pass', 7]) &&
      begin
        s2 = store.call
        sym = ZaA.go(pc_for.call(bk), beacon: { beacon: bk, issuers: [F03::ISSUER], instance: F03::INSTANCE }, state_store: s2)
        ZaA.ck('symbol keys', [sym.allow, sym.checks['beacon'], s2.pin(pin_key)], [true, 'pass', 7])
      end &&
      begin
        seen = []
        pc = pc_for.call(bk)
        cb = ZaA.go(pc, beacon: ->(ref, p) { seen << [ref, p]; opt.call(bk) })
        ZaA.ck('a callable gets the grant ref and the proof', [cb.allow, cb.checks['beacon'], seen.length, seen[0][0], seen[0][1].equal?(pc)], [true, 'pass', 1, pc['grant_ref'], true])
      end &&
      begin
        rep = ZaA.go(pc_for.call(bk), beacon: opt.call(bk), state_store: store.call(9))
        ZaA.ck('older than the pin', [rep.allow, rep.checks['beacon'], ZaA.why(rep, 'beacon')], [false, 'fail', ['beacon seq 7 is older than the last accepted 9 (replay)']])
      end &&
      begin
        s3 = store.call(7)
        same = ZaA.go(pc_for.call(bk), beacon: opt.call(bk), state_store: s3)
        ZaA.ck('the same seq is not a replay', [same.allow, same.checks['beacon'], s3.pin(pin_key)], [true, 'pass', 7])
      end &&
      begin
        bad = ZaA.go(pc_for.call({}), beacon: opt.call({}), state_store: store.call(5))
        ZaA.ck('an unverifiable beacon is rejected, never compared with the pin', [bad.checks['beacon'], ZaA.why(bad, 'beacon')], ['fail', ['malformed beacon']])
      end &&
      begin
        poison = { 'v' => 2, 'instance' => 'another', 'poison' => Object.new }
        anchored = C06.fixture_pcactn.merge('freshness' => { 'beacon_ref' => 'x', 'epoch' => 1, 'accumulator_witness' => '' })
        bad = ZaA.go(anchored, beacon: opt.call(poison), state_store: store.call(5))
        ZaA.ck('a rejected beacon is never bound', [bad.checks['beacon'], ZaA.why(bad, 'beacon'), bad.checks.key?('authorize')], ['fail', ['wrong instance'], false])
      end &&
      begin
        extra = mk.call(7, mutate: { 'poison' => Object.new })
        anchored = C06.fixture_pcactn.merge('freshness' => { 'beacon_ref' => 'x', 'epoch' => 1, 'accumulator_witness' => '' })
        rep = ZaA.go(anchored, beacon: opt.call(extra), state_store: store.call(9))
        ZaA.ck('a replayed beacon is never bound', [rep.checks['beacon'], ZaA.why(rep, 'beacon'), rep.checks.key?('authorize')],
               ['fail', ['beacon seq 7 is older than the last accepted 9 (replay)'], false])
      end &&
      begin
        wide = mk.call(7, scope: 'someone-else')
        r = ZaA.go(pc_for.call(wide), beacon: opt.call(wide))
        ZaA.ck('the scope is the grant id', ZaA.why(r, 'beacon'), ['scope not covered'])
      end &&
      begin
        r = ZaA.go(C06.fixture_pcactn.merge('freshness' => []), beacon: opt.call(bk))
        n = ZaA.go(C06.fixture_pcactn.merge('freshness' => nil), beacon: opt.call(bk))
        ZaA.ck('a proof with no anchor does not bind', [r, n].map { |x| [x.checks['beacon'], ZaA.why(x, 'beacon')] },
               [['fail', ['PCActn freshness.beacon_ref does not bind the presented beacon']]] * 2)
      end &&
      ZaA.ck('a beacon of another value does not bind', ZaA.why(ZaA.go(pc_for.call(mk.call(8)), beacon: opt.call(bk)), 'beacon'),
             ['PCActn freshness.beacon_ref does not bind the presented beacon']) &&
      begin
        shapes = ['x', [], { 'beacon' => 'x' }, { 'beacon' => nil }, { 'issuers' => [] }].map do |b|
          r = ZaA.go(pc_for.call(bk), beacon: b)
          [r.checks['beacon'], r.reasons.include?(required), r.checks.key?('authorize')]
        end
        ZaA.ck('a beacon that is no beacon member is not enforced (and denied as required)', shapes, [['fail', true, false]] * 5)
      end &&
      begin
        nomethod = Class.new(AtlasPca::MemoryStateStore) do
          def method_missing(name, *args, &blk) = name == :pin ? 99 : super

          def respond_to_missing?(*) = false
        end
        nomethod.send(:undef_method, :pin)
        r = ZaA.go(pc_for.call(bk), beacon: opt.call(bk), state_store: nomethod.new)
        ZaA.ck('a store without a pin reader has no replay head', [r.checks['beacon'], ZaA.why(r, 'beacon')], ['pass', []])
      end &&
      begin
        cap = []
        stub = ->(*a, **k) { cap << [a, k]; { 'ok' => false } }
        pins = { 'z' => 'y' }
        r = Seam.with(AtlasPca, { verify_liveness_beacon: stub }) { ZaA.go(pc_for.call(bk), beacon: opt.call(bk, pq_pins: pins)) }
        ZaA.ck('a verifier reason is optional', [r.checks['beacon'], ZaA.why(r, 'beacon')], ['fail', ['beacon rejected']]) &&
          ZaA.ck('what the verifier is given', [cap[0][0], cap[0][1]], [[bk], { issuers: [F03::ISSUER], now: C06::NOW, instance: F03::INSTANCE, scope: g1, pq_pins: pins }])
      end &&
      begin
        failing = Class.new(AtlasPca::MemoryStateStore) do
          def raise_pin(key, value) = key.end_with?(':beacon') ? raise('down') : super
        end
        r = ZaA.go(pc_for.call(bk), beacon: opt.call(bk), state_store: failing.new)
        ZaA.ck('a failing pin store denies', [r.allow, r.checks['beacon'], ZaA.why(r, 'beacon')], [false, 'fail', ['the beacon pin store failed (fail closed)']])
      end &&
      begin
        bare = Class.new(AtlasPca::MemoryStateStore)
        bare.send(:undef_method, :raise_pin)
        r = ZaA.go(pc_for.call(bk), beacon: opt.call(bk), state_store: bare.new)
        ZaA.ck('a store without raise_pin simply does not pin', [r.allow, r.checks['beacon']], [true, 'pass'])
      end
  end
end
