# frozen_string_literal: true
# Rule 22 (`traits`) and the grant pin (`pin`) inside decide_intent_v2, pinned to intent-v2.ts:83-87, 321-325, 614-634 and
# pca-actions/test/verifier.test.ts. The document is the shared honest vector (confirmed verbs), site-signed here.
module MutationKill
  module Rule22
    module_function

    VERB = 'stripe.refund'
    PARAMS = { 'amount' => 1000, 'charge' => 'ch_abcdefgh', 'idempotency_key' => 'k1' }.freeze
    SPEND = { 'weights' => { 'alpha' => 0, 'beta' => 0, 'gamma' => 1, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0 }, 'theta1' => 1, 'theta2' => 1, 'kappa' => 100,
              'lambda' => 0, 'rho' => 0.5, 'bMax' => 1_000_000 }.freeze
    ROOT = 'A' * 43

    def vector
      @vector ||= begin
        dir = [%w[.. .. .. .. packages pca-conformance vectors actions], %w[.. .. conformance actions], %w[.. .. .. conformance actions]]
              .map { |r| File.expand_path(File.join(*r), __dir__) }.find { |d| Dir.exist?(d) }
        AtlasPca.parse_json(File.read(File.join(dir, 'rule22-schema-honest.json'), encoding: 'UTF-8'), loose: true)['input']
      end
    end

    def dup(o) = Marshal.load(Marshal.dump(o))
    def pins = vector['pins']

    # the honest document, citing a pack, optionally patched before the site signs it
    def doc
      d = dup(vector['doc']).merge('pack' => { 'ns' => 'stripe', 'version' => '1.0.0', 'root' => ROOT })
      yield d if block_given?
      V2.sign_schema(d)
    end

    def refund(d) = d['verbs'].find { |v| v['verb'] == VERB }
    def floors = refund(vector['doc'])['floors']
    def digest = refund(vector['doc'])['def']

    def pin(over = {})
      { 'pack' => { 'ns' => 'stripe', 'root' => ROOT }, 'defs' => { VERB => digest }, 'on_new_action' => 'deny', 'max_esc' => 3, 'preauth_esc' => floors['esc'], 'caveats' => floors['caveats'] }.merge(over)
    end

    def grant(env = {})
      cav = { 'type' => AtlasPca::ENVELOPE_CAVEAT, 'goal_commit' => 'c', 'predicates' => [], 'caveats' => [], 'agent_binding' => {}, 'risk_policy' => SPEND }.merge(env)
      { 'id' => 'g1', 'issuer' => 'iss', 'caveats' => [cav] }
    end

    def ctx(d = doc, over = {})
      { 'schema' => { 'docs' => [d], 'keys' => [V2.skey] }, 'reviewers' => pins, 'call_context' => floors['context'], 'params' => PARAMS,
        'policy' => { 'schema' => { 'closed_world' => true } } }.merge(over)
    end

    def pcactn(aud = 'pay') = { 'aud' => aud, 'action' => { 'verb' => VERB, 'resource' => 'x', 'params_digest' => AtlasPca.params_digest(PARAMS) } }
    def decide(g, c, p = pcactn) = AtlasPca.decide_intent_v2(p, g, c, V2::NOW)['checks']
    def named(checks) = checks.to_h { |c| [c['name'], c['ok'] ? true : c['reason']] }
    def pinned(over = {}, c = ctx) = named(decide(grant('actions' => pin(over)), c))
    ESC = 'escalate: the action floors need a caveat, context or confirmation the grant does not provide (rule 22)'
    OVER = 'the action floors exceed what the grant authorizes (rule 22)'
  end

  t('rule 22: control, a consistent v2 schema and an exact pin pass schema, pin, traits, in that order') do
    c = Rule22.decide(Rule22.grant('actions' => Rule22.pin), Rule22.ctx)
    c.map { |x| x['name'] } == %w[schema pin traits] && c.all? { |x| x['ok'] == true }
  end

  t('rule 22: forged floors, a dropped trait and an unknown trait are schema_floor_forged at schema, pin and traits') do
    r = Rule22
    bad = ->(f) { r.pinned({}, r.ctx(r.doc { |d| f.(r.refund(d)) })) }
    lowered = bad.(->(v) { v['floors']['esc'] = 0 })
    p3 = lowered['schema']
    dropped = bad.(->(v) { v['traits'] -= ['pca.money_moving'] })
    unknown = bad.(->(v) { v['traits'] += ['pca.zzz'] })
    p3.start_with?('schema_floor_forged: stripe.refund: schema_floor_forged') && lowered['pin'] == p3 && lowered.keys == %w[schema pin] &&
      dropped['schema'].start_with?('schema_floor_forged: stripe.refund: ') && unknown['schema'].start_with?('schema_floor_forged: ')
  end

  t('rule 22: without reviewers a confirmed verb is unconfirmed, so it must carry every trait') do
    r = Rule22
    c = r.ctx.reject { |k, _| k == 'reviewers' }
    r.pinned({}, c)['schema'].start_with?('schema_floor_forged: ')
  end

  t('rule 22 traits: above max_esc denies, above preauth_esc escalates, a missing caveat or context escalates (no pin: max 3, preauth 0)') do
    r = Rule22
    esc = r.floors['esc']
    r.pinned('max_esc' => esc - 1, 'preauth_esc' => 0)['traits'] == r::OVER &&
      r.pinned('max_esc' => esc, 'preauth_esc' => esc - 1)['traits'] == r::ESC && r.pinned('max_esc' => esc, 'preauth_esc' => esc)['traits'] == true &&
      r.pinned('caveats' => [])['traits'] == r::ESC && r.pinned({}, r.ctx(r.doc, 'call_context' => []))['traits'] == r::ESC &&
      r.pinned({}, r.ctx.reject { |k, _| k == 'call_context' })['traits'] == r::ESC && r.named(r.decide(r.grant, r.ctx))['traits'] == r::ESC
  end

  t('rule 22 traits: envelope caveat types and valid pin caveats both count; a junk envelope entry never does') do
    r = Rule22
    cv = r.floors['caveats']
    p0 = r.pin.reject { |k, _| k == 'caveats' }
    env = ->(list) { r.named(r.decide(r.grant('caveats' => list, 'actions' => p0), r.ctx))['traits'] }
    env.(cv.map { |k| { 'type' => k } }) == true && env.(cv.first(1).map { |k| { 'type' => k } }) == r::ESC && env.([5, nil] + cv.map { |k| { 'type' => k } }) == true &&
      r.named(r.decide(r.grant('caveats' => cv[1..].map { |k| { 'type' => k } }, 'actions' => r.pin('caveats' => cv.first(1))), r.ctx))['traits'] == true
  end

  t('pin: every refusal has the reference reason, with the escalate prefix on an escalating new action') do
    r = Rule22
    other = 'Q' * 43
    r.pinned('pack' => { 'ns' => 'acme', 'root' => r::ROOT })['pin'] == "pack_mismatch: the schema does not come from the pinned pack 'acme'" &&
      r.pinned('defs' => { 'stripe.other' => other })['pin'] == "new_action: the grant does not name 'stripe.refund' (on_new_action: deny)" &&
      r.pinned('defs' => { 'stripe.other' => other }, 'on_new_action' => 'escalate')['pin'] == "escalate: new_action: the grant does not name 'stripe.refund' (on_new_action: escalate)" &&
      r.pinned('defs' => { r::VERB => other })['pin'] == 'def_changed: the definition differs from the pinned digest and no signed evolution record chains to it' &&
      r.pinned('on_new_action' => 'x')['pin'] == "bad_pin: actions.on_new_action must be 'deny' or 'escalate'" &&
      r.named(r.decide(r.grant('actions' => nil), r.ctx))['pin'] == 'bad_pin: actions must be an object'
  end

  t('pin: a pack-only pin needs the exact root; a malformed pin grants no caveats and the defaults max 3, preauth 0') do
    r = Rule22
    only = r.pin.reject { |k, _| k == 'defs' }
    r.named(r.decide(r.grant('actions' => only), r.ctx))['pin'] == true &&
      r.named(r.decide(r.grant('actions' => only.merge('pack' => { 'ns' => 'stripe', 'root' => 'Q' * 43 })), r.ctx))['pin'] ==
        'pack_mismatch: the pack root differs from the pinned root (the grant pins the pack as a whole)' &&
      r.named(r.decide(r.grant('actions' => r.pin('on_new_action' => 'x')), r.ctx))['traits'] == r::ESC
  end

  t('pin: the store inputs reach decide_pin and needs_reapproval is the suffix (seam over decide_pin)') do
    r = Rule22
    seen = nil
    res = { 'ok' => false, 'code' => 'def_changed', 'escalate' => true, 'reason' => 'why', 'needs_reapproval' => 'DIFF' }
    Seam.with(AtlasPca::ActionsRegistry, { decide_pin: lambda { |i|
      seen = i
      res
    } }) do
      out = r.named(r.decide(r.grant('actions' => r.pin), r.ctx(r.doc, 'actions' => { 'records' => [1], 'keys' => [2], 'reapprovals' => [3] })))
      bare = r.named(r.decide(r.grant('actions' => r.pin), r.ctx))
      out['pin'] == 'escalate: def_changed: why (re-approve diff DIFF)' && seen['records'] == [] && seen['keys'] == [] && seen['reapprovals'] == [] &&
        seen['verb'] == r::VERB && seen['grant'] == { 'id' => 'g1', 'issuer' => 'iss' } && bare['pin'] == out['pin']
    end
  end

  t('pin: ctx.actions members reach decide_pin as given') do
    r = Rule22
    seen = nil
    Seam.with(AtlasPca::ActionsRegistry, { decide_pin: lambda { |i|
      seen = i
      { 'ok' => true }
    } }) do
      r.decide(r.grant('actions' => r.pin), r.ctx(r.doc, 'actions' => { 'records' => [1], 'keys' => [2], 'reapprovals' => [3] }))
      seen['records'] == [1] && seen['keys'] == [2] && seen['reapprovals'] == [3] && seen['pin'] == r.pin && seen['doc']['v'] == 2
    end
  end

  t('intent_v2 context: malformed reviewers, call_context and actions fail closed with the reference text') do
    e = ->(c) { AtlasPca.intent_v2_context_error(c) }
    rv = 'reviewers must be {keys: [...]}'
    e.({ 'reviewers' => 5 }) == rv && e.({ 'reviewers' => nil }) == rv && e.({ 'reviewers' => {} }) == rv && e.({ 'reviewers' => { 'keys' => 5 } }) == rv && e.({ 'reviewers' => { 'keys' => [] } }).nil? &&
      e.({ 'call_context' => 'x' }) == 'call_context must be an array of strings' && e.({ 'call_context' => ['a', 1] }) == 'call_context must be an array of strings' && e.({ 'call_context' => ['a'] }).nil? &&
      e.({ 'actions' => 5 }) == 'actions must be an object' && e.({ 'actions' => {} }).nil? &&
      %w[records keys reapprovals].all? { |k| e.({ 'actions' => { k => 5 } }) == "actions.#{k} must be an array" && e.({ 'actions' => { k => [] } }).nil? } &&
      e.({ 'reviewers' => 5, 'params' => 5 }) == rv && e.({ 'actions' => 5, 'params' => 5 }) == 'actions must be an object'
  end

  t('a v1 schema: no integrity check and no traits check; a pinned grant reports pin only; no schema configured stops at pin') do
    r = Rule22
    v1 = V2.schema
    prm = V2.params
    c = { 'schema' => { 'docs' => [v1], 'keys' => [V2.skey] }, 'params' => prm, 'policy' => { 'schema' => { 'closed_world' => true } } }
    p1 = { 'aud' => V2::AUD, 'action' => { 'verb' => 'air.book', 'resource' => 'r', 'params_digest' => AtlasPca.params_digest(prm) } }
    r.decide(r.grant, c, p1).map { |x| [x['name'], x['ok']] } == [['schema', true]] &&
      r.decide(r.grant('actions' => r.pin), c, p1).map { |x| [x['name'], x['ok']] } == [['schema', true], ['pin', false]] &&
      r.named(r.decide(r.grant('actions' => r.pin), { 'params' => r::PARAMS })) == { 'pin' => 'this verifier has no action schema configured' }
  end

  t('Intel js_date_parse: an out-of-range zone offset is NaN, as Date.parse') do
    d = ->(s) { AtlasPca::Attest::Intel.js_date_parse(s) }
    d.('2026-01-01T00:00:00+24:00').nil? && d.('2026-01-01T00:00:00+00:60').nil? && d.('2026-01-01T00:00:00-24:00').nil? &&
      d.('2026-01-01T00:00:00+23:59') == d.('2026-01-01T00:00:00Z') - (((23 * 60) + 59) * 60_000) && d.('2026-01-01T00:00:00-00:01') == d.('2026-01-01T00:00:00Z') + 60_000
  end
end
