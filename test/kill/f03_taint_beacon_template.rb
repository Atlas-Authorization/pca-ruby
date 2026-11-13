# frozen_string_literal: true

# f03: F3 rows ported with their primitives: enforce.taint (AtlasPca::Taint), the liveness beacon (AtlasPca::beacons) and
# requireLinkedTemplate (verify_linked_policy). Reference: packages/pca/src/taint.ts, beacons.ts, policy-link.ts, server/{verify,authorize}.ts,
# formal/dafny/Taint.dfy and Verdict.dfy. Expected values are hand-computed from the reference.

module MutationKill
  module F03
    module_function

    def gate?(*files) = (f = ENV['MUT_FILE']).nil? || f.empty? || files.include?(f)

    def ck(label, got, want)
      got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    end

    def tn = AtlasPca::Taint
    KEY = AtlasPca::KeyPair.new("\x07".b * 32)
    ISSUER = KEY.public
    INSTANCE = 'inst-1'
    NOW = 1_800_000_000_000

    # a signed Ed25519 liveness beacon (TypeScript issueLivenessBeacon): validity 300 s unless given
    def beacon(seq: 1, issued_at: NOW - 1000, validity: 300_000, scope: '*', instance: INSTANCE, mutate: {})
      body = { 'v' => 2, 'instance' => instance, 'scope' => scope, 'epoch' => issued_at.div(60_000), 'seq' => seq, 'issued_at' => issued_at,
               'not_after' => issued_at + validity, 'issuer' => ISSUER }.merge(mutate)
      body.merge('sig' => AtlasPca.b64e(KEY.sign(AtlasPca.liveness_message(body))))
    end

    def check(**o) = { issuers: [ISSUER], now: NOW, instance: INSTANCE, scope: 'g1' }.merge(o)
  end

  t('f03 taint: the label lattice, classification, the join and the fail-closed pre-checks') do
    next true unless F03.gate?('taint.rb')

    tn = F03.tn
    lab = ->(k, id = nil) { id.nil? ? { 'kind' => k } : { 'kind' => k, 'id' => id } }
    reg = tn::InMemoryRegistry.new.record_trusted('t').record_first_party('f').record_tool('o', 'ocr').record_web('w')
    graph = Class.new { def node(id) = id == 'node-1' ? { 'id' => id } : nil }.new
    prov = ->(*refs) { { 'trusted_refs' => refs } }
    ct = ->(*refs) { tn.compute_taint(prov.call(*refs), reg, graph) }
    F03.ck('ranks', %w[trusted first_party tool web agent bogus].map { |k| tn.label_rank({ 'kind' => k }) }, [0, 1, 2, 3, 4, 4]) &&
      F03.ck('a non-hash label is the worst', [tn.label_rank(nil), tn.label_rank('x'), tn.label_rank({ 'kind' => 3 })], [4, 4, 4]) &&
      F03.ck('values', %w[trusted first_party tool web agent].map { |k| tn.taint_value({ 'kind' => k }) }, [0, 0.25, 0.5, 0.75, 1]) &&
      F03.ck('join keeps the worse', tn.join_label(lab.call('web'), lab.call('tool', 'x')), lab.call('web')) &&
      F03.ck('join, equal rank and id', tn.join_label(lab.call('tool', 'x'), lab.call('tool', 'x')), lab.call('tool', 'x')) &&
      F03.ck('join, equal rank, different id collapses', tn.join_label(lab.call('tool', 'x'), lab.call('tool', 'y')), lab.call('tool')) &&
      F03.ck('the empty join is the worst', tn.join_labels([]), lab.call('agent')) &&
      F03.ck('all trusted', ct.call('t', 't').values_at('taint', 'valid'), [0, true]) &&
      F03.ck('first party by registry and by graph', ct.call('t', 'f', 'node-1').values_at('taint', 'valid'), [0.25, true]) &&
      F03.ck('a tool', ct.call('t', 'o')['label'], lab.call('tool', 'ocr')) &&
      F03.ck('the worst wins', ct.call('t', 'f', 'w', 'o').values_at('taint', 'label'), [0.75, lab.call('web')]) &&
      F03.ck('an unverifiable ref is agent with its id', ct.call('t', 'claimed')['label'], lab.call('agent', 'claimed')) &&
      F03.ck('a long ref drops the id', ct.call('x' * 129)['label'], lab.call('agent')) &&
      F03.ck('refs are listed', ct.call('t', 'nope')['refs'], [{ 'ref' => 't', 'label' => lab.call('trusted') }, { 'ref' => 'nope', 'label' => lab.call('agent', 'nope') }]) &&
      F03.ck('no refs is the worst', tn.compute_taint({}, reg).values_at('taint', 'valid'), [1, true]) &&
      F03.ck('empty refs is the worst', ct.call.values_at('taint', 'valid'), [1, true]) &&
      F03.ck('no registry', tn.compute_taint({}, nil), { 'taint' => 1, 'label' => lab.call('agent'), 'refs' => [], 'valid' => false, 'reason' => 'taint: no trusted-input registry' }) &&
      F03.ck('no provenance', tn.compute_taint(nil, reg)['reason'], 'taint: provenance is absent or malformed') &&
      F03.ck('refs not an array', tn.compute_taint({ 'trusted_refs' => 'x' }, reg)['reason'], 'taint: trusted_refs must be an array') &&
      F03.ck('a bad ref', [tn.compute_taint({ 'trusted_refs' => ['t', ''] }, reg)['reason'], tn.compute_taint({ 'trusted_refs' => ['t', 5] }, reg)['reason']],
             ['taint: trusted_refs must be non-empty strings'] * 2) &&
      F03.ck('a throwing registry', tn.compute_taint(prov.call('t'), Class.new { def lookup(_d) = raise('boom') }.new)['reason'], 'taint: evaluation error (fail closed): boom') &&
      F03.ck('a registry label of an unknown kind is not a vouching', tn.compute_taint(prov.call('u'), Class.new { def lookup(_d) = { 'kind' => 'zzz' } }.new, graph)['label'], lab.call('agent', 'u'))
  end

  t('f03 taint: the gate decides by rank against max_taint') do
    next true unless F03.gate?('taint.rb')

    tn = F03.tn
    reg = tn::InMemoryRegistry.new.record_trusted('t').record_first_party('f').record_web('w')
    gate = ->(refs, max) { tn.taint_gate({ 'trusted_refs' => refs }, reg, nil, max) }
    ok = { 'ok' => true }
    F03.ck('trusted under 0', gate.call(['t'], 0), ok) &&
      F03.ck('first party over 0', gate.call(%w[t f], 0), { 'ok' => false, 'reason' => 'information-flow taint 0.25 exceeds policy max 0' }) &&
      F03.ck('first party at 0.25', gate.call(%w[t f], 0.25), ok) &&
      F03.ck('web over 0.5', gate.call(['w'], 0.5), { 'ok' => false, 'reason' => 'information-flow taint 0.75 exceeds policy max 0.5' }) &&
      F03.ck('web at 0.8', gate.call(['w'], 0.8), ok) &&
      F03.ck('anything at 1', gate.call(['nope'], 1), ok) &&
      F03.ck('between ranks rounds down', gate.call(%w[t f], 0.3), ok) &&
      F03.ck('negative is misconfigured', gate.call(['t'], -0.1), { 'ok' => false, 'reason' => 'taint gate misconfigured: maxTaint must be a non-negative number (fail closed)' }) &&
      F03.ck('NaN is misconfigured', gate.call(['t'], Float::NAN)['reason'], 'taint gate misconfigured: maxTaint must be a non-negative number (fail closed)') &&
      F03.ck('a string bound is misconfigured', gate.call(['t'], '1')['ok'], false) &&
      F03.ck('invalid lineage is refused first', tn.taint_gate(nil, reg, nil, -1), { 'ok' => false, 'reason' => 'taint: provenance is absent or malformed' }) &&
      F03.ck('no refs fails closed', gate.call([], 0.9)['ok'], false)
  end

  t('f03 beacons: verification, the hard limits, monotonic acceptance and the decision') do
    next true unless F03.gate?('beacons.rb')

    v = ->(b, **o) { AtlasPca.verify_liveness_beacon(b, **F03.check(**o)) }
    bad = ->(r) { { 'ok' => false, 'reason' => r } }
    F03.ck('valid', v.call(F03.beacon), { 'ok' => true }) &&
      F03.ck('not a beacon', [v.call(nil), v.call({}), v.call(F03.beacon.merge('v' => 1))], [bad.call('malformed beacon')] * 3) &&
      F03.ck('wrong instance', v.call(F03.beacon(instance: 'other')), bad.call('wrong instance')) &&
      F03.ck('issuer not pinned', v.call(F03.beacon, issuers: ['zz']), bad.call('issuer not pinned')) &&
      F03.ck('a tampered body', v.call(F03.beacon.merge('seq' => 2)), bad.call('bad signature')) &&
      F03.ck('a tampered signature', v.call(F03.beacon.merge('sig' => AtlasPca.b64e("\x00".b * 64))), bad.call('bad signature')) &&
      F03.ck('not yet valid', v.call(F03.beacon(issued_at: F03::NOW + 31_000)), bad.call('not yet valid')) &&
      F03.ck('skew allowed', v.call(F03.beacon(issued_at: F03::NOW + 30_000))['ok'], true) &&
      F03.ck('expired', v.call(F03.beacon(issued_at: F03::NOW - 400_000)), bad.call('expired')) &&
      F03.ck('valid until not_after', v.call(F03.beacon(issued_at: F03::NOW - 300_000))['ok'], true) &&
      F03.ck('the hard maximum', v.call(F03.beacon(issued_at: F03::NOW - 1000, validity: 3_600_001)), bad.call('validity exceeds the hard maximum')) &&
      F03.ck('exactly the maximum', v.call(F03.beacon(issued_at: F03::NOW - 1000, validity: 3_600_000))['ok'], true) &&
      F03.ck('empty validity', v.call(F03.beacon(validity: 0)), bad.call('validity exceeds the hard maximum')) &&
      F03.ck('epoch mismatch', v.call(F03.beacon(mutate: { 'epoch' => 1 })), bad.call('epoch does not match issued_at')) &&
      F03.ck('malformed window', v.call(F03.beacon(mutate: { 'seq' => -1 })), bad.call('malformed window')) &&
      F03.ck('scope covered', [v.call(F03.beacon(scope: 'g1'))['ok'], v.call(F03.beacon(scope: '*'))['ok']], [true, true]) &&
      F03.ck('scope not covered', v.call(F03.beacon(scope: 'g2')), bad.call('scope not covered')) &&
      F03.ck('no scope asked', v.call(F03.beacon(scope: 'g2'), scope: nil)['ok'], true) &&
      F03.ck('frozen without a valid beacon', [AtlasPca.frozen_liveness?([], **F03.check), AtlasPca.frozen_liveness?([F03.beacon(instance: 'x')], **F03.check),
                                               AtlasPca.frozen_liveness?([F03.beacon(instance: 'x'), F03.beacon], **F03.check)], [true, true, false]) &&
      F03.ck('accept', [AtlasPca.accept_beacon(nil, { 'seq' => 0 }), AtlasPca.accept_beacon({ 'seq' => 4 }, { 'seq' => 5 })], [{ 'ok' => true }] * 2) &&
      F03.ck('replay', [AtlasPca.accept_beacon({ 'seq' => 4 }, { 'seq' => 4 }), AtlasPca.accept_beacon({ 'seq' => 4 }, { 'seq' => 3 })],
             [bad.call('replayed beacon: seq 4 <= 4'), bad.call('replayed beacon: seq 3 <= 4')]) &&
      F03.ck('malformed acceptance', [nil, {}, { 'seq' => -1 }, { 'seq' => 1.5 }, { 'seq' => 2**53 }].map { |b| AtlasPca.accept_beacon(nil, b) }, [bad.call('malformed beacon')] * 5) &&
      F03.ck('decision table', [[false, true, false, true], [true, false, false, true], [true, true, true, true], [true, true, false, false], [true, true, false, true]]
                                 .map { |a| AtlasPca.beacon_decision(*a) }, %w[not-enforced rejected replayed unbound pass]) &&
      F03.ck('a different beacon, a different ref', AtlasPca.beacon_ref(F03.beacon(seq: 1)) == AtlasPca.beacon_ref(F03.beacon(seq: 2)), false)
  end

  t('f03 beacons: the durable acceptor keeps the highest seq per (instance, scope, issuer)') do
    next true unless F03.gate?('beacons.rb')

    kv = AtlasPca::MemoryAtomicKv.new
    acc = AtlasPca::BeaconAcceptor.new(kv)
    ok = { 'ok' => true }
    F03.ck('first', acc.accept(F03.beacon(seq: 5), **F03.check), ok) &&
      F03.ck('replay of the same', acc.accept(F03.beacon(seq: 5), **F03.check), { 'ok' => false, 'reason' => 'replayed beacon: seq 5 <= 5' }) &&
      F03.ck('replay of an older one', acc.accept(F03.beacon(seq: 4), **F03.check), { 'ok' => false, 'reason' => 'replayed beacon: seq 4 <= 5' }) &&
      F03.ck('a newer one', acc.accept(F03.beacon(seq: 6), **F03.check), ok) &&
      F03.ck('stored', kv.get("beacon-seq/v1/#{JSON.generate([F03::INSTANCE, '*', F03::ISSUER])}"), 6) &&
      F03.ck('another scope is another stream', acc.accept(F03.beacon(seq: 1, scope: 'g1'), **F03.check), ok) &&
      F03.ck('a bad beacon is refused first', acc.accept(F03.beacon(instance: 'x'), **F03.check), { 'ok' => false, 'reason' => 'wrong instance' }) &&
      F03.ck('a store that throws', AtlasPca::BeaconAcceptor.new(Class.new { def update(_k) = raise('down') }.new).accept(F03.beacon, **F03.check),
             { 'ok' => false, 'reason' => 'beacon state unavailable' }) &&
      F03.ck('junk on disk', begin
        kv.set("beacon-seq/v1/#{JSON.generate([F03::INSTANCE, 'g9', F03::ISSUER])}", 'junk')
        acc.accept(F03.beacon(scope: 'g9'), **F03.check, scope: 'g9')
      end, { 'ok' => false, 'reason' => 'beacon state unavailable' }) &&
      begin
        AtlasPca::BeaconAcceptor.new(Object.new)
        raise 'no error'
      rescue TypeError => e
        F03.ck('message', e.message, 'createBeaconAcceptor: a DurableKv is required')
      end
  end

  t('f03 authorize: taint_gate, beacon and template are checks of the pipeline') do
    next true unless F03.gate?('authorize.rb')

    g1 = C06.base['grant']['id']
    reg = AtlasPca::Taint::InMemoryRegistry.new
    off = C06.go
    on = C06.go(enforce_taint: { 'registry' => reg, 'max_taint' => 1 })
    deny = C06.go(enforce_taint: { 'registry' => reg, 'max_taint' => 0.5 })
    pv = C06.fixture_pcactn['provenance'] # trusted_refs [] : the empty lineage is the worst case
    F03.ck('off', off.checks['taint_gate'], 'not-enforced') && F03.ck('on, worst case allowed at 1', [on.allow, on.checks['taint_gate']], [true, 'pass']) &&
      F03.ck('on, worst case refused at 0.5', [deny.allow, deny.checks['taint_gate'], deny.reasons.include?('taint_gate: information-flow taint 1 exceeds policy max 0.5')], [false, 'fail', true]) &&
      F03.ck('the fixture lineage', pv.is_a?(Hash), true) &&
      F03.ck('beacon off', [off.checks['beacon'], off.allow], ['not-enforced', true]) &&
      begin
        none = C06.go(beacon: ->(_ref, _p) {})
        F03.ck('an unavailable beacon denies', [none.allow, none.checks['beacon']], [false, 'fail']) &&
          F03.ck('and says it is required', none.reasons.include?('beacon: required check is not-enforced (default-deny: not enforced by this resource server)'), true)
      end &&
      begin
        b = F03.beacon(issued_at: C06::NOW - 1000, scope: g1)
        bc = { 'beacon' => b, 'issuers' => [F03::ISSUER], 'instance' => F03::INSTANCE }
        unbound = C06.go(beacon: bc)
        F03.ck('a valid beacon the PCActn does not bind', [unbound.allow, unbound.checks['beacon'], unbound.reasons.include?('beacon: PCActn freshness.beacon_ref does not bind the presented beacon')], [false, 'fail', true]) &&
          F03.ck('an unpinned issuer', C06.go(beacon: bc.merge('issuers' => ['x'])).reasons.include?('beacon: issuer not pinned'), true)
      end &&
      F03.ck('template off', off.checks.key?('template'), false) &&
      F03.ck('template: a grant with no template_ref', begin
        t1 = C06.go(require_linked_template: { 'registry' => { 'templates' => {}, 'trusted' => [] } })
        [t1.allow, t1.checks['template'], t1.reasons.include?('template: the grant carries no template_ref')]
      end, [false, 'fail', true])
  end
end
