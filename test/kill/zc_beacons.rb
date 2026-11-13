# frozen_string_literal: true

# zc beacons: the signed message bytes, constants, every refusal path of verify_liveness_beacon, accept_beacon and the acceptor's
# stored-state validation. Expected messages are rebuilt from canon_bytes, never from liveness_message.
module MutationKill
  module ZCBeacon
    module_function

    KEY = AtlasPca::KeyPair.new("\x09".b * 32)
    ISSUER = KEY.public
    INST = 'inst-z'
    NOW = 1_800_000_000_000
    MAX_SEQ = 9_007_199_254_740_991

    def body(seq: 1, issued_at: NOW - 1000, validity: 300_000, scope: '*', instance: INST)
      { 'v' => 2, 'instance' => instance, 'scope' => scope, 'epoch' => issued_at.div(60_000), 'seq' => seq, 'issued_at' => issued_at,
        'not_after' => issued_at + validity, 'issuer' => ISSUER }
    end

    # a signed Ed25519 beacon; `over` replaces fields BEFORE signing
    def beacon(over = {}, **o)
      b = body(**o).merge(over)
      b.merge('sig' => AtlasPca.b64e(KEY.sign(AtlasPca.liveness_message(b))))
    end

    def check(**o) = { issuers: [ISSUER], now: NOW, instance: INST, scope: 'g1' }.merge(o)
    def verify(b, **o) = AtlasPca.verify_liveness_beacon(b, **check(**o))
    def bad(reason) = { 'ok' => false, 'reason' => reason }

    # a read-only beacon lookalike (not a Hash)
    class Lookalike
      def initialize(h) = @h = h
      def [](k) = @h[k]
      def key?(k) = @h.key?(k)
    end
  end

  t('zc beacons: constants') do
    next true unless ZC.gate?('beacons.rb')

    ZC.eq('scope', AtlasPca::GLOBAL_BEACON_SCOPE, '*') && ZC.eq('epoch', AtlasPca::BEACON_EPOCH_MS, 60_000) &&
      ZC.eq('max validity', AtlasPca::BEACON_MAX_VALIDITY_MS, 3_600_000) && ZC.eq('skew', AtlasPca::BEACON_CLOCK_SKEW_MS, 30_000) &&
      ZC.eq('domain bytes', AtlasPca::LIVENESS_DOMAIN.bytes, "atlas-pca/beacon/v2\x00".bytes) &&
      ZC.eq('domain encoding', AtlasPca::LIVENESS_DOMAIN.encoding, Encoding::BINARY) && ZC.eq('domain frozen', AtlasPca::LIVENESS_DOMAIN.frozen?, true)
  end

  t('zc beacons: liveness_message is the domain then the canonical body, suite fields only for a non-Ed25519 suite') do
    next true unless ZC.gate?('beacons.rb')

    b = ZCBeacon.body
    dom = "atlas-pca/beacon/v2\x00".b
    ed = dom + AtlasPca.canon_bytes(b)
    msg = ->(x) { AtlasPca.liveness_message(x) }
    withpk = b.merge('pq_pk' => 'PK1')
    ZC.eq('plain', msg.call(b).bytes, ed.bytes) &&
      ZC.eq('a stray pq_pk is not signed for ed25519', msg.call(withpk).bytes, ed.bytes) &&
      ZC.eq('explicit ed25519', ZC.seam(AtlasPca, { resolve_suite: ->(_p) { ['ed25519', nil] } }) { msg.call(withpk).bytes }, ed.bytes) &&
      ZC.eq('a post-quantum suite', ZC.seam(AtlasPca, { resolve_suite: ->(_p) { ['hybrid-x', nil] } }) { msg.call(withpk).bytes },
            (dom + AtlasPca.canon_bytes(b.merge('alg' => 'hybrid-x', 'pq_pk' => 'PK1'))).bytes) &&
      ZC.eq('a suite without a key', ZC.seam(AtlasPca, { resolve_suite: ->(_p) { ['hybrid-x', nil] } }) { msg.call(b).bytes },
            (dom + AtlasPca.canon_bytes(b.merge('alg' => 'hybrid-x', 'pq_pk' => nil))).bytes) &&
      ZC.eq('no suite adds nothing', ZC.seam(AtlasPca, { resolve_suite: ->(_p) { [nil, 'err'] } }) { msg.call(withpk).bytes }, ed.bytes) &&
      ZC.eq('every field is signed', %w[v instance scope epoch seq issued_at not_after issuer].map { |k| msg.call(b.merge(k => 'zz')).bytes == ed.bytes }, [false] * 8)
  end

  t('zc beacons: beacon_int? is JS Number.isInteger over JSON values') do
    next true unless ZC.gate?('beacons.rb')

    [[0, true], [5, true], [-3, true], [2.0, true], [-0.0, true], [1e300, true], [1.5, false], [Float::NAN, false], [Float::INFINITY, false],
     [-Float::INFINITY, false], ['1', false], [nil, false], [true, false], [[1], false]].each { |x, want| ZC.eq("beacon_int? #{x.inspect}", AtlasPca.beacon_int?(x), want) }
    true
  end

  t('zc beacons: verify_liveness_beacon structure, pinning and the fail-closed rescue') do
    next true unless ZC.gate?('beacons.rb')

    good = ZCBeacon.beacon
    ok = { 'ok' => true }
    mal = ZCBeacon.bad('malformed beacon')
    ZC.eq('valid', ZCBeacon.verify(good), ok) &&
      [nil, 5, [], 'x', 1.5, true].all? { |x| ZC.eq("non-hash #{x.inspect}", ZCBeacon.verify(x), mal) } &&
      ZC.eq('a lookalike that is not a Hash', ZCBeacon.verify(ZCBeacon::Lookalike.new(good)), mal) &&
      ZC.eq('v 1', ZCBeacon.verify(ZCBeacon.beacon({ 'v' => 1 })), mal) && ZC.eq('v missing', ZCBeacon.verify(good.reject { |k, _| k == 'v' }), mal) &&
      ZC.eq('an unknown suite', ZCBeacon.verify(ZCBeacon.beacon({ 'alg' => 'bogus-suite' })), mal) &&
      ZC.eq('a non-string suite', ZCBeacon.verify(ZCBeacon.beacon({ 'alg' => 5 })), mal) &&
      ZC.eq('wrong instance', ZCBeacon.verify(good, instance: 'other'), ZCBeacon.bad('wrong instance')) &&
      ZC.eq('issuers nil', ZCBeacon.verify(good, issuers: nil), ZCBeacon.bad('issuer not pinned')) &&
      ZC.eq('issuers as a String containing the key', ZCBeacon.verify(good, issuers: ZCBeacon::ISSUER), ZCBeacon.bad('issuer not pinned')) &&
      ZC.eq('issuers as a Hash', ZCBeacon.verify(good, issuers: { ZCBeacon::ISSUER => 1 }), ZCBeacon.bad('issuer not pinned')) &&
      ZC.eq('issuers without it', ZCBeacon.verify(good, issuers: ['other']), ZCBeacon.bad('issuer not pinned')) &&
      ZC.eq('issuers empty', ZCBeacon.verify(good, issuers: []), ZCBeacon.bad('issuer not pinned')) &&
      ZC.eq('tampered', ZCBeacon.verify(good.merge('seq' => 2)), ZCBeacon.bad('bad signature')) &&
      ZC.eq('a fault inside is a malformed beacon', ZCBeacon.verify(good, now: nil), mal) &&
      ZC.eq('no scope asked for', AtlasPca.verify_liveness_beacon(ZCBeacon.beacon({}, scope: 'g9'), issuers: [ZCBeacon::ISSUER], now: ZCBeacon::NOW, instance: ZCBeacon::INST), ok) &&
      ZC.eq('another scope asked for', ZCBeacon.verify(ZCBeacon.beacon({}, scope: 'g9')), ZCBeacon.bad('scope not covered')) &&
      ZC.eq('the global scope covers any', ZCBeacon.verify(ZCBeacon.beacon({}, scope: '*'), scope: 'anything'), ok) &&
      ZC.eq('the asked scope', ZCBeacon.verify(ZCBeacon.beacon({}, scope: 'g1')), ok)
  end

  t('zc beacons: the pinned PQ key lookup is given the issuer, the beacon key and the pins') do
    next true unless ZC.gate?('beacons.rb')

    calls = []
    pins = { 'someone' => 'PKX' }
    b = ZCBeacon.beacon.merge('pq_pk' => 'PKX')
    ZC.seam(AtlasPca, { resolve_pq_key: ->(*a, **k) { calls << [a, k]; nil } }) { ZCBeacon.verify(b, pq_pins: pins) }
    ZC.eq('arguments', calls, [[[ZCBeacon::ISSUER, 'PKX'], { pq_pins: pins }]])
  end

  t('zc beacons: the window must be integers, seq non-negative, and the clock skew is exactly 30 s') do
    next true unless ZC.gate?('beacons.rb')

    win = ZCBeacon.bad('malformed window')
    ZC.eq('seq 0 is valid', ZCBeacon.verify(ZCBeacon.beacon(seq: 0)), { 'ok' => true }) &&
      ZC.eq('seq -1', ZCBeacon.verify(ZCBeacon.beacon(seq: -1)), win) &&
      ZC.eq('epoch float', ZCBeacon.verify(ZCBeacon.beacon({ 'epoch' => 1.5 })), win) &&
      ZC.eq('epoch string', ZCBeacon.verify(ZCBeacon.beacon({ 'epoch' => '1' })), win) &&
      ZC.eq('seq float', ZCBeacon.verify(ZCBeacon.beacon({ 'seq' => 1.5 })), win) &&
      ZC.eq('seq nil', ZCBeacon.verify(ZCBeacon.beacon({ 'seq' => nil })), win) &&
      ZC.eq('issued_at float', ZCBeacon.verify(ZCBeacon.beacon({ 'issued_at' => 1.5 })), win) &&
      ZC.eq('not_after string', ZCBeacon.verify(ZCBeacon.beacon({ 'not_after' => 'x' })), win) &&
      # an integral float has no canonical form (a wire 3.0 parses as 3), so it can never carry a valid signature
      ZC.eq('an integer seq other than 0 or 1', ZCBeacon.verify(ZCBeacon.beacon({ 'seq' => 3 })), { 'ok' => true }) &&
      ZC.eq('skew boundary', ZCBeacon.verify(ZCBeacon.beacon({}, issued_at: ZCBeacon::NOW + 30_000)), { 'ok' => true }) &&
      ZC.eq('past the skew', ZCBeacon.verify(ZCBeacon.beacon({}, issued_at: ZCBeacon::NOW + 30_001)), ZCBeacon.bad('not yet valid'))
  end

  t('zc beacons: accept_beacon is strictly monotone over safe-integer seqs and total on hostile input') do
    next true unless ZC.gate?('beacons.rb')

    mal = ZCBeacon.bad('malformed beacon')
    ab = ->(prev, nxt) { AtlasPca.accept_beacon(prev, nxt) }
    ZC.eq('first', ab.call(nil, { 'seq' => 0 }), { 'ok' => true }) && ZC.eq('max safe', ab.call(nil, { 'seq' => ZCBeacon::MAX_SEQ }), { 'ok' => true }) &&
      ZC.eq('above max safe', ab.call(nil, { 'seq' => ZCBeacon::MAX_SEQ + 1 }), mal) && ZC.eq('negative', ab.call(nil, { 'seq' => -1 }), mal) &&
      ZC.eq('float seq', ab.call(nil, { 'seq' => 1.0 }), mal) && ZC.eq('string seq', ab.call(nil, { 'seq' => '1' }), mal) &&
      ZC.eq('no seq', ab.call(nil, {}), mal) && ZC.eq('nil beacon', ab.call(nil, nil), mal) && ZC.eq('string beacon', ab.call(nil, 'x'), mal) &&
      ZC.eq('integer beacon', ab.call(nil, 5), mal) && ZC.eq('array beacon', ab.call(nil, [1]), mal) &&
      ZC.eq('higher', ab.call({ 'seq' => 4 }, { 'seq' => 5 }), { 'ok' => true }) &&
      ZC.eq('equal', ab.call({ 'seq' => 5 }, { 'seq' => 5 }), ZCBeacon.bad('replayed beacon: seq 5 <= 5')) &&
      ZC.eq('lower', ab.call({ 'seq' => 9 }, { 'seq' => 2 }), ZCBeacon.bad('replayed beacon: seq 2 <= 9')) &&
      ZC.eq('previous without seq', begin
        ab.call({}, { 'seq' => 2 })
      rescue ArgumentError => e
        e.message.include?('with nil')
      end, true) &&
      ZC.eq('previous not a hash', begin
        ab.call(true, { 'seq' => 2 })
      rescue ArgumentError => e
        e.message.include?('with nil')
      end, true)
  end

  t('zc beacons: the acceptor refuses a stored seq that is not a non-negative integer') do
    next true unless ZC.gate?('beacons.rb')

    unavailable = ZCBeacon.bad('beacon state unavailable')
    key = "beacon-seq/v1/#{JSON.generate([ZCBeacon::INST, '*', ZCBeacon::ISSUER])}"
    run = lambda do |stored, seq|
      kv = AtlasPca::MemoryLeaseKv.new
      kv.set(key, stored) unless stored.nil?
      acc = AtlasPca::BeaconAcceptor.new(kv)
      [acc.accept(ZCBeacon.beacon(seq: seq), **ZCBeacon.check), kv.get(key)]
    end
    [5.5, -1, -0.5, 'x', true, [1], { 'a' => 1 }].each { |bad| ZC.eq("stored #{bad.inspect}", run.call(bad, 99)[0], unavailable) }
    ZC.eq('nothing stored', run.call(nil, 0), [{ 'ok' => true }, 0]) && ZC.eq('stored 0, seq 1', run.call(0, 1), [{ 'ok' => true }, 1]) &&
      ZC.eq('stored 0, seq 0 is a replay', run.call(0, 0), [ZCBeacon.bad('replayed beacon: seq 0 <= 0'), 0]) &&
      ZC.eq('higher', run.call(3, 4), [{ 'ok' => true }, 4]) && ZC.eq('equal', run.call(4, 4), [ZCBeacon.bad('replayed beacon: seq 4 <= 4'), 4]) &&
      ZC.eq('lower', run.call(4, 2), [ZCBeacon.bad('replayed beacon: seq 2 <= 4'), 4])
  end
end
