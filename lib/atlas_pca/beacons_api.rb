# frozen_string_literal: true

module AtlasPca
  # The liveness beacon surface of the reference (`beacons`) with its JavaScript value semantics: a clock or a pinned-issuer list of the wrong
  # JSON type behaves as the reference's `+` / `<` / `includes` do (never as a Ruby type error), a beacon whose signed message cannot be formed is
  # `malformed beacon`, and a post-quantum beacon verifies only under a PQ key pinned for its issuer (no unbound opt-out). Records are String-keyed
  # Hashes. `AtlasPca.verify_liveness_beacon` (beacons.rb) is the keyword-argument form of the same check for the rest of the SDK.
  module BeaconsApi
    UNDEF = IntentV2::UNDEF
    GLOBAL_SCOPE = '*'
    BEACON_EPOCH_MS = AtlasPca::BEACON_EPOCH_MS
    BEACON_MAX_VALIDITY_MS = AtlasPca::BEACON_MAX_VALIDITY_MS
    BEACON_CLOCK_SKEW_MS = AtlasPca::BEACON_CLOCK_SKEW_MS

    module_function

    def pm(h, k) = h.is_a?(Hash) && h.key?(k) ? h[k] : UNDEF
    def nullish?(x) = x.nil? || UNDEF.equal?(x)

    # a === b over JSON values (undefined equals only undefined)
    def seq?(a, b) = UNDEF.equal?(a) || UNDEF.equal?(b) ? UNDEF.equal?(a) && UNDEF.equal?(b) : Attestation.js_eq(a, b)

    # Number(x) for the JSON values a clock can hold
    def js_num(x)
      case x
      when Numeric then x
      when nil, false then 0
      when true then 1
      when String
        t = x.strip
        return 0 if t.empty?

        Float(t, exception: false) || Float::NAN
      else Float::NAN
      end
    end

    # `now + 30000` (a string clock concatenates)
    def plus_skew(now)
      return js_num("#{now}#{BEACON_CLOCK_SKEW_MS}") if now.is_a?(String)
      return Float::NAN if UNDEF.equal?(now)

      js_num(now) + BEACON_CLOCK_SKEW_MS
    end

    # The signed bytes: the domain, then the canonical body (alg and pq_pk bound for a non-Ed25519 suite). Raises on an undefined / non-finite member.
    def liveness_beacon_message(b)
      body = %w[v instance scope epoch seq issued_at not_after issuer].to_h { |k| [k, pm(b, k)] }
      AtlasPca::LIVENESS_DOMAIN + AtlasPca.canon_bytes(IntentV2.bind_suite_fields(body, pm(b, 'alg'), pm(b, 'pq_pk')))
    end

    def beacon_ref(b) = AtlasPca.hash_canonical(b)

    # Sign a beacon. `args`: 'issuerSecret' (32 bytes or a KeyPair), 'instance', 'scope'? (absent / null = "*"), 'seq', 'issuedAt', 'validityMs'?
    # (absent / null = 300000), 'suite'? ({'alg', 'pq' => the ML-DSA-65 key pair}). Raises on a bad seq / time / validity or an unknown suite.
    def issue_liveness_beacon(args)
      validity = pm(args, 'validityMs')
      validity = 5 * BEACON_EPOCH_MS if nullish?(validity)
      seq = pm(args, 'seq')
      issued = pm(args, 'issuedAt')
      raise RangeError, 'issueLivenessBeacon: seq must be a non-negative integer' unless Attestation.integer_number?(seq) && seq >= 0
      raise RangeError, 'issueLivenessBeacon: issuedAt must be an integer' unless Attestation.integer_number?(issued) && issued >= 0
      unless Attestation.integer_number?(validity) && validity.positive? && validity <= BEACON_MAX_VALIDITY_MS
        raise RangeError, "issueLivenessBeacon: validity must be in (0, #{BEACON_MAX_VALIDITY_MS}] ms"
      end

      suite = pm(args, 'suite')
      alg = pm(suite, 'alg')
      pq = pm(suite, 'pq')
      pq = nil if UNDEF.equal?(pq)
      secret = pm(args, 'issuerSecret')
      signer = secret.is_a?(AtlasPca::KeyPair) ? secret : AtlasPca::KeyPair.new(secret)
      scope = pm(args, 'scope')
      body = { 'v' => 2, 'instance' => pm(args, 'instance'), 'scope' => nullish?(scope) ? GLOBAL_SCOPE : scope, 'epoch' => issued.to_i.div(BEACON_EPOCH_MS),
               'seq' => seq, 'issued_at' => issued, 'not_after' => issued + validity, 'issuer' => signer.public }
      body = IntentV2.bind_suite_fields(body, alg, pq.respond_to?(:public) ? pq.public : UNDEF)
      msg = liveness_beacon_message(body)
      name = UNDEF.equal?(alg) || alg == 'ed25519' ? nil : alg
      sig, pq_sig = AtlasPca.sign_with_suite(name, signer, pq, msg)
      out = body.merge('sig' => sig)
      out['pq_sig'] = pq_sig unless pq_sig.nil?
      out
    end

    def bad(reason) = { 'ok' => false, 'reason' => reason }

    # {ok, reason?}: never raises. `o`: 'issuers' (pinned issuer keys), 'now', 'instance', 'scope'?, 'pqPins'?.
    def verify_liveness_beacon(b, o)
      return bad('malformed beacon') unless b.is_a?(Hash) && Attestation.js_eq(pm(b, 'v'), 2) && !IntentV2.suite_of(pm(b, 'alg')).nil?
      return bad('wrong instance') unless seq?(pm(b, 'instance'), pm(o, 'instance'))
      return bad('issuer not pinned') unless PassportApi.js_includes(pm(o, 'issuers'), pm(b, 'issuer'))

      msg = liveness_beacon_message(b)
      pins = pm(o, 'pqPins')
      unless IntentV2.verify_pinned_suite(pm(b, 'alg'), pm(b, 'issuer'), pm(b, 'pq_pk'), msg, pm(b, 'sig'), pm(b, 'pq_sig'), pins.is_a?(Hash) ? pins : nil)
        return bad('bad signature')
      end

      epoch, seq, issued, not_after = %w[epoch seq issued_at not_after].map { |k| pm(b, k) }
      return bad('malformed window') unless [epoch, seq, issued, not_after].all? { |x| Attestation.integer_number?(x) } && seq >= 0
      return bad('validity exceeds the hard maximum') if not_after <= issued || not_after - issued > BEACON_MAX_VALIDITY_MS

      return bad('epoch does not match issued_at') unless Attestation.js_eq(epoch, (issued / BEACON_EPOCH_MS.to_f).floor)

      now = pm(o, 'now')
      return bad('not yet valid') if plus_skew(now) < issued
      return bad('expired') unless !UNDEF.equal?(now) && js_num(now) <= not_after

      scope = pm(o, 'scope')
      return bad('scope not covered') if !UNDEF.equal?(scope) && !seq?(pm(b, 'scope'), GLOBAL_SCOPE) && !seq?(pm(b, 'scope'), scope)

      { 'ok' => true }
    rescue StandardError, ScriptError, SecurityError, SystemStackError
      bad('malformed beacon')
    end

    # Monotonic acceptance: a safe-integer seq >= 0 (negative zero refused) strictly above the previous beacon's.
    def accept_beacon(prev, nxt)
      sq = nxt.is_a?(Hash) || nxt.is_a?(Array) ? pm(nxt, 'seq') : UNDEF
      return bad('malformed beacon') unless Attestation.safe_int?(sq) && sq >= 0 && !(sq.is_a?(Float) && sq.zero? && (1.0 / sq).negative?)

      if Attestation.truthy?(prev)
        ps = pm(prev, 'seq')
        return bad("replayed beacon: seq #{Attestation.jstr(sq)} <= #{Attestation.jstr(ps)}") unless sq > js_num(ps)
      end
      { 'ok' => true }
    end

    # true when NO beacon in the list verifies for the check
    def frozen_liveness?(beacons, o) = beacons.none? { |b| verify_liveness_beacon(b, o)['ok'] }

    # Durable replay protection over an atomic kv (#update(key) { |prev| next_or_nil }): the highest accepted seq per (instance, scope, issuer).
    # A store that throws, or holds anything but a safe non-negative integer, refuses with `beacon state unavailable`.
    class Acceptor
      def initialize(kv)
        raise TypeError, 'createBeaconAcceptor: a DurableKv is required' if kv.is_a?(Hash) || !kv.respond_to?(:update)

        @kv = kv
      end

      def self.slot(b) = "beacon-seq/v1/#{JSON.generate([BeaconsApi.pm(b, 'instance'), BeaconsApi.pm(b, 'scope'), BeaconsApi.pm(b, 'issuer')])}"

      def accept(b, check)
        v = BeaconsApi.verify_liveness_beacon(b, check)
        return v unless v['ok']

        replay_of = nil
        seq = b['seq']
        begin
          @kv.update(self.class.slot(b)) do |prev|
            raise TypeError unless prev.nil? || (Attestation.safe_int?(prev) && prev >= 0 && !(prev.is_a?(Float) && prev.zero? && (1.0 / prev).negative?))

            if !prev.nil? && !(seq > prev)
              replay_of = prev
              nil
            else
              seq
            end
          end
        rescue StandardError, ScriptError, SecurityError, SystemStackError
          return BeaconsApi.bad('beacon state unavailable')
        end
        replay_of.nil? ? { 'ok' => true } : BeaconsApi.bad("replayed beacon: seq #{Attestation.jstr(seq)} <= #{Attestation.jstr(replay_of)}")
      end
    end

    def create_beacon_acceptor(kv) = Acceptor.new(kv)
  end
end
