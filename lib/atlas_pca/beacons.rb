# frozen_string_literal: true

# Dead-man liveness beacons v2 (audit P2-4). A port of packages/pca/src/beacons.ts (verify, accept, ref, acceptor) and of the beacon
# decision of the verdict combinator (formal/dafny/Verdict.dfy BeaconDecision). A beacon is { v, instance, scope, epoch, seq, issued_at,
# not_after, issuer, sig } (plus alg / pq_pk / pq_sig for a post-quantum suite) signed by a pinned issuer: the grant's principal or the
# operator / guardian. Authority is live only while a valid beacon covers the moment; a PCActn binds one through its signed
# `freshness.beacon_ref` (= beacon_ref(b)). Verification never raises: any failure is a refusal.
module AtlasPca
  GLOBAL_BEACON_SCOPE = '*'
  BEACON_EPOCH_MS = 60_000
  BEACON_MAX_VALIDITY_MS = 60 * 60_000 # no issuer can mint a longer-lived beacon
  BEACON_CLOCK_SKEW_MS = 30_000
  LIVENESS_DOMAIN = "atlas-pca/beacon/v2\x00".b.freeze

  module_function

  # the signed message of a beacon: the domain, then the canonical body (suite fields only for a non-Ed25519 suite)
  def liveness_message(b)
    body = { 'v' => b['v'], 'instance' => b['instance'], 'scope' => b['scope'], 'epoch' => b['epoch'], 'seq' => b['seq'],
             'issued_at' => b['issued_at'], 'not_after' => b['not_after'], 'issuer' => b['issuer'] }
    suite = resolve_suite(b)[0]
    if !suite.nil? && suite != 'ed25519'
      body['alg'] = suite
      body['pq_pk'] = b['pq_pk']
    end
    LIVENESS_DOMAIN + canon_bytes(body)
  end

  # stable reference to a beacon: what the PCActn commits in `freshness.beacon_ref`
  def beacon_ref(b) = hash_canonical(b)

  # { 'ok' => true } or { 'ok' => false, 'reason' }: signature, pinned issuer, instance and scope binding, the hard maximum
  # validity and the freshness window. `pq_pins` maps an issuer to its pinned ML-DSA key (a pure-PQ / hybrid beacon needs one).
  def verify_liveness_beacon(b, issuers:, now:, instance:, scope: nil, pq_pins: nil)
    return { 'ok' => false, 'reason' => 'malformed beacon' } unless b.is_a?(Hash) && b['v'] == 2 && !resolve_suite(b)[0].nil?
    return { 'ok' => false, 'reason' => 'wrong instance' } if b['instance'] != instance
    return { 'ok' => false, 'reason' => 'issuer not pinned' } unless issuers.is_a?(Array) && issuers.include?(b['issuer'])

    pq = resolve_pq_key(b['issuer'], b['pq_pk'], pq_pins: pq_pins)
    msg = liveness_message(b)
    return { 'ok' => false, 'reason' => 'bad signature' } unless verify_suite(b, b['issuer'], msg, pq)

    win = %w[epoch seq issued_at not_after].map { |k| b[k] }
    return { 'ok' => false, 'reason' => 'malformed window' } unless win.all? { |x| beacon_int?(x) } && b['seq'] >= 0
    if b['not_after'] <= b['issued_at'] || b['not_after'] - b['issued_at'] > BEACON_MAX_VALIDITY_MS
      return { 'ok' => false, 'reason' => 'validity exceeds the hard maximum' }
    end
    return { 'ok' => false, 'reason' => 'epoch does not match issued_at' } if b['epoch'] != b['issued_at'].div(BEACON_EPOCH_MS)
    return { 'ok' => false, 'reason' => 'not yet valid' } if now + BEACON_CLOCK_SKEW_MS < b['issued_at']
    return { 'ok' => false, 'reason' => 'expired' } if now > b['not_after']
    if !scope.nil? && b['scope'] != GLOBAL_BEACON_SCOPE && b['scope'] != scope
      return { 'ok' => false, 'reason' => 'scope not covered' }
    end

    { 'ok' => true }
  rescue StandardError, ScriptError, SecurityError, SystemStackError
    { 'ok' => false, 'reason' => 'malformed beacon' }
  end

  # a JS Number.isInteger over a JSON value: an Integer, or an integral finite Float
  def beacon_int?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite? && x == x.truncate)

  # monotonic acceptance: a beacon replaces the stored one only with a STRICTLY higher seq
  def accept_beacon(prev, nxt)
    sq = nxt.is_a?(Hash) ? nxt['seq'] : nil
    return { 'ok' => false, 'reason' => 'malformed beacon' } unless sq.is_a?(Integer) && sq >= 0 && sq <= 9_007_199_254_740_991

    ps = prev.is_a?(Hash) ? prev['seq'] : nil
    return { 'ok' => false, 'reason' => "replayed beacon: seq #{sq} <= #{ps}" } if prev && !(sq > ps)

    { 'ok' => true }
  end

  # frozen unless at least one beacon verifies for (instance, scope, now); absence is a freeze
  def frozen_liveness?(beacons, **opts) = beacons.none? { |b| verify_liveness_beacon(b, **opts)['ok'] }

  # The beacon decision of the verdict combinator: 'not-enforced' | 'rejected' | 'replayed' | 'unbound' | 'pass'.
  def beacon_decision(supplied, verifier_ok, replayed, ref_binds)
    if !supplied then 'not-enforced'
    elsif !verifier_ok then 'rejected'
    elsif replayed then 'replayed'
    elsif !ref_binds then 'unbound'
    else 'pass'
    end
  end

  # Durable replay protection: the highest accepted seq per (instance, scope, issuer) in an atomic kv (get + update), under one atomic
  # read-modify-write. A store that cannot decide refuses the beacon with `beacon state unavailable`.
  class BeaconAcceptor
    def initialize(kv)
      raise TypeError, 'createBeaconAcceptor: a DurableKv is required' unless kv.respond_to?(:update)

      @kv = kv
    end

    def accept(b, **check)
      v = AtlasPca.verify_liveness_beacon(b, **check)
      return v unless v['ok']

      replay_of = nil
      begin
        @kv.update("beacon-seq/v1/#{JSON.generate([b['instance'], b['scope'], b['issuer']])}") do |prev|
          raise TypeError unless prev.nil? || (prev.is_a?(Integer) && prev >= 0)

          if !prev.nil? && !(b['seq'] > prev)
            replay_of = prev
            nil
          else
            b['seq']
          end
        end
      rescue StandardError, ScriptError, SecurityError, SystemStackError
        return { 'ok' => false, 'reason' => 'beacon state unavailable' }
      end
      replay_of.nil? ? { 'ok' => true } : { 'ok' => false, 'reason' => "replayed beacon: seq #{b['seq']} <= #{replay_of}" }
    end
  end
end
