# frozen_string_literal: true

# f02: PCA 0.5 hardening F3 rows ported into AtlasPca.authorize: pq_pins, requireVerifiedPrincipal + resolvePrincipal, requirePassport,
# enforce.freshness, requireRiskInputs and the adaptive (tightened) policy. Reference: packages/pca/src/server/{verify,require-pca,authorize}.ts,
# pcactn.ts (the freshness gate). Reuses the C06 authorize helpers (signature-invalid variants of the fixture still reach these checks).

module MutationKill
  module F02
    module_function

    def gate? = (f = ENV['MUT_FILE']).nil? || f.empty? || f == 'authorize.rb'

    def ck(label, got, want)
      got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    end

    def fresh(beacon, epoch) = C06.fixture_pcactn.merge('freshness' => { 'beacon_ref' => beacon, 'epoch' => epoch, 'accumulator_witness' => '' })
    def epoch_now = C06::NOW / 60_000
  end

  t('f02 enforce.freshness: misconfiguration, a stub anchor, the future, stale and a good anchor') do
    next true unless F02.gate?

    gate = ->(pc, **g) { C06.go(pc, enforce_freshness: { 'max_age_ms' => 60_000 }.merge(g.transform_keys(&:to_s))) }
    bad = 'freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)'
    r = ->(x) { [x.checks['freshness'], x.reasons.select { |w| w.start_with?('freshness: ') }.map { |w| w.delete_prefix('freshness: ') }] }
    F02.ck('no max age', r.call(C06.go(enforce_freshness: {})), ['fail', [bad]]) &&
      F02.ck('negative max age', r.call(gate.call(:base, max_age_ms: -1)), ['fail', [bad]]) &&
      F02.ck('epoch_ms zero', r.call(gate.call(:base, epoch_ms: 0)), ['fail', [bad]]) &&
      F02.ck('stub anchor', r.call(gate.call(:base)), ['fail', ['freshness anchor is missing (empty beacon_ref or non-positive epoch stub)']]) &&
      F02.ck('empty beacon', r.call(gate.call(F02.fresh('', F02.epoch_now))), ['fail', ['freshness anchor is missing (empty beacon_ref or non-positive epoch stub)']]) &&
      F02.ck('zero epoch', r.call(gate.call(F02.fresh('b', 0))), ['fail', ['freshness anchor is missing (empty beacon_ref or non-positive epoch stub)']]) &&
      F02.ck('future', r.call(gate.call(F02.fresh('b', F02.epoch_now + 10))), ['fail', ['freshness anchor is in the future']]) &&
      F02.ck('skew allows a near future', r.call(gate.call(F02.fresh('b', F02.epoch_now + 1), clock_skew_ms: 120_000))[0], 'pass') &&
      F02.ck('stale', r.call(gate.call(F02.fresh('b', F02.epoch_now - 10), max_age_ms: 1000)), ['fail', ['freshness anchor is stale (older than 1000 ms)']]) &&
      F02.ck('good', r.call(gate.call(F02.fresh('b', F02.epoch_now))), ['pass', []]) &&
      F02.ck('a custom epoch length', r.call(gate.call(F02.fresh('b', C06::NOW / 1000), epoch_ms: 1000))[0], 'pass') &&
      F02.ck('a custom clock', r.call(gate.call(F02.fresh('b', 5), now: 5 * 60_000, max_age_ms: 0))[0], 'pass') &&
      F02.ck('off by default', C06.go.checks.key?('freshness'), false)
  end

  t('f02 principal: resolve_principal / require_verified_principal') do
    next true unless F02.gate?

    seen = []
    ok = C06.go(resolve_principal: ->(pub, g) { seen << [pub, g['id']]; { verified: true } })
    F02.ck('verified', [ok.allow, ok.checks['principal'], seen], [true, 'pass', [[C06.base['grant']['issuer'], C06.base['grant']['id']]]]) &&
      F02.ck('unverified is not enforced', C06.go(resolve_principal: ->(*) { { 'verified' => false } }).checks['principal'], 'not-enforced') &&
      F02.ck('a nil answer is unverified', C06.go(resolve_principal: ->(*) {}).checks['principal'], 'not-enforced') &&
      F02.ck('a raising resolver is unverified', C06.go(resolve_principal: ->(*) { raise 'x' }).checks['principal'], 'not-enforced') &&
      F02.ck('truthy is not verified', C06.go(resolve_principal: ->(*) { { verified: 1 } }).checks['principal'], 'not-enforced') &&
      begin
        d = C06.go(resolve_principal: ->(*) { { verified: false } }, require_verified_principal: true)
        F02.ck('required and unverified', [d.allow, d.checks['principal'], d.reasons.include?('principal: the grant issuer is not an enrolled, verified principal')], [false, 'fail', true])
      end &&
      F02.ck('required and verified', C06.go(resolve_principal: ->(*) { { verified: true } }, require_verified_principal: true).allow, true) &&
      begin
        n = C06.go(require_verified_principal: true)
        F02.ck('required without a resolver', [n.allow, n.reasons.include?('principal: requireVerifiedPrincipal needs a resolvePrincipal resolver')], [false, true])
      end &&
      F02.ck('not required: no check', C06.go.checks.key?('principal'), false)
  end

  t('f02 passport: require_passport refuses before the counter is spent') do
    next true unless F02.gate?

    store = AtlasPca::MemoryStateStore.new
    r = C06.go(state_store: store, require_passport: { 'trusted_issuers' => ['x'], 'revoked' => ->(*) { false } }, passport: nil)
    skey = "#{C06.base['grant']['id']}:#{C06.fixture_pcactn['cap_chain'].last['holder']}"
    F02.ck('malformed passport', [r.allow, r.checks['passport'], r.reasons.include?('passport: malformed')], [false, 'fail', true]) &&
      F02.ck('the counter is not spent', store.last(skey), nil) &&
      F02.ck('an unknown issuer', C06.go(require_passport: { 'trusted_issuers' => [] }, passport: { 'typ' => 'atlas-pca/passport', 'ver' => 1, 'passport' => {} }).checks['passport'], 'fail') &&
      F02.ck('off by default', C06.go.checks.key?('passport'), false)
  end

  t('f02 requireRiskInputs, the adaptive policy and pq_pins') do
    next true unless F02.gate?

    lacking = C06.go(risk: { 'semanticDistance' => 0 }, require_risk_inputs: %w[taint blastRadius])
    F02.ck('lacking', [lacking.checks['risk_inputs'], lacking.reasons.include?('risk_inputs: required risk input(s) not supplied by the server: taint, blastRadius')], ['fail', true]) &&
      F02.ck('supplied', C06.go(require_risk_inputs: %w[taint blastRadius age]).checks['risk_inputs'], 'pass') &&
      F02.ck('the plan supplies the distance', C06.go(risk: {}, require_risk_inputs: ['semanticDistance']).checks['risk_inputs'], 'pass') &&
      F02.ck('a non-finite input is not supplied', C06.go(risk: ProvHarness::RISK.merge('taint' => Float::NAN), require_risk_inputs: ['taint']).checks['risk_inputs'], 'fail') &&
      F02.ck('a string is not supplied', C06.go(risk: ProvHarness::RISK.merge('taint' => '0'), require_risk_inputs: ['taint']).checks['risk_inputs'], 'fail') &&
      F02.ck('off by default', C06.go.checks.key?('risk_inputs'), false) &&
      begin
        tight = F01.go(risk: ProvHarness::RISK.merge('reversibility' => 0.5), adaptive: { 'theta1' => 0, 'theta2' => 0 })
        F02.ck('adaptive tightens', [tight.allow, tight.checks['adaptive'], tight.reasons.include?("adaptive: tightened policy requires threshold t=3 (grant policy: t=1)")], [false, 'fail', true])
      end &&
      F02.ck('adaptive that does not tighten', F01.go(adaptive: { 'theta1' => 0.25, 'theta2' => 0.6 }).allow, true) &&
      F02.ck('pq pins: an Ed25519 grant needs none', [C06.go(pq_pins: {}).checks['pq_pin'], C06.go.checks.key?('pq_pin')], ['pass', false])
  end
end
