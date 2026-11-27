# frozen_string_literal: true

require_relative 'intent_statement'

module AtlasPca
  # The detached and runtime artifacts of the intent layer beside the statement: the signed attestation of an Intent Map, the signed runtime observation
  # and the verification of a ledger anchoring receipt (the reference's `intent.ts`). Signing is Ed25519 natively (like the statement); verification
  # goes through the verifier-pinned suite dispatch, so a hybrid or pure-PQ artifact verifies only under a pinned key (`opts['pqPins']`).
  module IntentSigned
    UNDEF = V2JS::UNDEF
    INTENT_MAP_SIG_DOMAIN = "atlas-pca/intent-map-sig/v1\0"
    INTENT_OBS_SIG_DOMAIN = "atlas-pca/intent-obs/v1\0"
    INTENT_OBSERVATION_SOURCES = %w[runtime witness elicitation import].freeze
    INTENT_ANCHOR_LOG = 'pca-intent:v1'
    INTENT_ANCHOR_KINDS = %w[statement map observation schema session delta receipt profile evidence].freeze
    MAP_ATT_KEYS = %w[v map_digest intent_ref signer signed_at].freeze
    OBS_KEYS = %w[v map_digest verb values y source observed_at pcactn_digest signer].freeze

    module_function

    def g(o, k) = o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF
    def b32?(v) = !AtlasPca.b64d(v, 32).nil?
    def clock?(v) = V2JS.int?(v) && v >= 0
    def pins_of(opts) = opts.is_a?(Hash) && opts['pqPins'].is_a?(Hash) ? opts['pqPins'] : nil
    def refused(why) = { 'ok' => false, 'reason' => why }
    def body_of(o, keys) = Marshal.load(Marshal.dump(keys.select { |k| o.key?(k) && !o[k].equal?(UNDEF) }.to_h { |k| [k, o[k]] }))

    # ---- Intent Map attestation ----

    # Structural check of an Intent Map (does not replay it): nil when well formed.
    def intent_map_shape_error(m)
      return 'not an intent map v1' unless m.is_a?(Hash) && V2JS.strict_eq(g(m, 'v'), 1) && g(m, 'kind') == 'pca-intent-map'

      ref = g(m, 'intent_ref')
      return 'intent_ref must be null or canonical base64url (32 bytes)' if !ref.nil? && !b32?(ref)

      mt = g(m, 'metrics')
      return 'metrics must be an object' unless mt.is_a?(Hash)

      f = g(mt, 'fidelity_est_ppm')
      return 'metrics.fidelity_est_ppm must be an integer in [0, 1e6]' unless V2JS.int?(f) && f >= 0 && f <= 1_000_000

      r = g(mt, 'residual_risk_ppm')
      return 'metrics.residual_risk_ppm must be a non-negative integer' unless V2JS.int?(r) && r >= 0

      nil
    end

    def map_message(body) = INTENT_MAP_SIG_DOMAIN.b + AtlasPca.strict_bytes(body)

    # A detached signature over the map's digest: {v, map_digest, intent_ref, signer, signed_at, sig}. `signer_secret` is an Ed25519 seed.
    def sign_intent_map_attestation(map, signer_secret, signed_at, suite = nil)
      raise ArgumentError, 'signIntentMapAttestation: only Ed25519 signing is supported natively' if !suite.nil? && ![nil, 'ed25519'].include?(suite['alg'])

      bad = intent_map_shape_error(map)
      raise ArgumentError, "signIntentMapAttestation: #{bad}" if bad
      raise ArgumentError, 'signIntentMapAttestation: signedAt must be a non-negative safe integer' unless clock?(signed_at)

      key = KeyPair.new(signer_secret)
      body = { 'v' => 1, 'map_digest' => IntentMapkit.intent_map_digest(map), 'intent_ref' => map['intent_ref'], 'signer' => key.public, 'signed_at' => signed_at }
      body.merge('sig' => AtlasPca.b64e(key.sign(map_message(body))))
    end

    # Well formed, signature valid and, when `map` is given (pass `UNDEF` for none), its digest and intent_ref match. Never raises.
    def verify_intent_map_attestation(a, map = UNDEF, opts = nil)
      opts ||= {}
      return refused('not an intent map attestation v1') unless a.is_a?(Hash) && V2JS.strict_eq(g(a, 'v'), 1)
      return refused('map_digest is not canonical base64url (32 bytes)') unless b32?(g(a, 'map_digest'))

      ref = g(a, 'intent_ref')
      return refused('intent_ref must be null or canonical base64url (32 bytes)') if !ref.nil? && !b32?(ref)
      return refused('signer is not canonical base64url (32 bytes)') unless b32?(g(a, 'signer'))
      return refused('signed_at must be a non-negative safe integer') unless clock?(g(a, 'signed_at'))
      return refused('signer mismatch') if !opts['expectedSigner'].nil? && a['signer'] != opts['expectedSigner']

      se = IntentStatement.suite_fields_error(a)
      return refused(se) if se

      unless map.equal?(UNDEF)
        bad = intent_map_shape_error(map)
        return refused(bad) if bad
        return refused('map digest mismatch') if IntentMapkit.intent_map_digest(map) != a['map_digest']
        return refused('intent_ref mismatch') if map['intent_ref'] != a['intent_ref']
      end
      msg = map_message(IntentV2.bind_suite_fields(body_of(a, MAP_ATT_KEYS), g(a, 'alg'), g(a, 'pq_pk')))
      return refused('bad signature') unless IntentV2.verify_pinned_suite(g(a, 'alg'), a['signer'], g(a, 'pq_pk'), msg, g(a, 'sig'), g(a, 'pq_sig'), pins_of(opts))

      { 'ok' => true }
    rescue StandardError => e
      refused("malformed intent map attestation: #{e.message}")
    end

    # ---- runtime observations ----

    def obs_shape_error(o)
      return 'not an intent observation v1' unless o.is_a?(Hash) && V2JS.strict_eq(g(o, 'v'), 1)
      return 'map_digest is not canonical base64url (32 bytes)' unless b32?(g(o, 'map_digest'))

      verb = g(o, 'verb')
      return 'verb must be a non-empty string' if !verb.is_a?(String) || verb.empty?

      vals = g(o, 'values')
      return 'values must map paths to numbers or strings' unless vals.is_a?(Hash) && vals.values.all? { |x| x.is_a?(String) || (V2JS.num?(x) && (!x.is_a?(Float) || x.finite?)) }
      return 'y must be 0 or 1' unless [0, 1].any? { |y| V2JS.strict_eq(g(o, 'y'), y) }
      return 'unknown observation source' unless g(o, 'source').is_a?(String) && INTENT_OBSERVATION_SOURCES.include?(o['source'])
      return 'observed_at must be a non-negative safe integer' unless clock?(g(o, 'observed_at'))

      pd = g(o, 'pcactn_digest')
      return 'pcactn_digest is not canonical base64url (32 bytes)' if !pd.equal?(UNDEF) && !b32?(pd)
      return 'signer is not canonical base64url (32 bytes)' unless b32?(g(o, 'signer'))

      nil
    end

    def obs_message(body) = INTENT_OBS_SIG_DOMAIN.b + AtlasPca.strict_bytes(body)

    # Sign a labelled outcome against a map ({map_digest, verb, values, y, source, observed_at, pcactn_digest?}) as its observer.
    def sign_intent_observation(o, signer_secret, suite = nil)
      raise ArgumentError, 'signIntentObservation: only Ed25519 signing is supported natively' if !suite.nil? && ![nil, 'ed25519'].include?(suite['alg'])

      key = KeyPair.new(signer_secret)
      body = body_of(o.merge('v' => 1, 'signer' => key.public), OBS_KEYS)
      bad = obs_shape_error(body)
      raise ArgumentError, "signIntentObservation: #{bad}" if bad

      body.merge('sig' => AtlasPca.b64e(key.sign(obs_message(body))))
    end

    def verify_intent_observation(o, opts = nil)
      opts ||= {}
      bad = obs_shape_error(o)
      return refused(bad) if bad
      return refused('signer mismatch') if !opts['expectedSigner'].nil? && o['signer'] != opts['expectedSigner']

      se = IntentStatement.suite_fields_error(o)
      return refused(se) if se

      msg = obs_message(IntentV2.bind_suite_fields(body_of(o, OBS_KEYS), g(o, 'alg'), g(o, 'pq_pk')))
      return refused('bad signature') unless IntentV2.verify_pinned_suite(g(o, 'alg'), o['signer'], g(o, 'pq_pk'), msg, g(o, 'sig'), g(o, 'pq_sig'), pins_of(opts))

      { 'ok' => true }
    rescue StandardError => e
      refused("malformed intent observation: #{e.message}")
    end

    # ---- ledger anchoring ----

    # A receipt {kind, digest, index, proof, signed_tree_head}: the head is signed by `guardian_public` for the intent log of `instance_id`, and the
    # artifact's leaf is included at `index` under the head's root and size. Never raises.
    def verify_intent_anchor(r, guardian_public, instance_id, pins = nil)
      return refused('unknown anchor kind') unless INTENT_ANCHOR_KINDS.include?(r['kind'])
      return refused('digest is not canonical base64url (32 bytes)') unless b32?(r['digest'])

      h = r['signed_tree_head']
      return refused('not a head of this instance intent log') if h['principal'] != INTENT_ANCHOR_LOG || h['instance_id'] != instance_id
      return refused('tree head signature invalid') unless AtlasPca.verify_tree_head(h, guardian_public, nil, pins)
      return refused('proof does not match the head') if r['proof']['index'] != r['index'] || r['proof']['size'] != h['size']

      leaf = Evidence.anchor_commit(r['kind'], r['digest'])
      return refused('artifact is not included under the signed head') unless AtlasPca.verify_ledger_inclusion(h['root'], r['proof'], leaf)

      { 'ok' => true }
    rescue StandardError => e
      refused("malformed anchor receipt: #{e.message}")
    end
  end
end

module AtlasPca
  # The intent layer as the full verifier loads it (the reference's INTENT_WIRE_EXTENSION and INTENT_EXTENSIONS): the validators of the optional wire
  # slots, and the intent decisions (binding, v2 pipeline, consistency token) the core fold runs. A verifier built without them refuses a PCActn or
  # a policy that needs the layer.
  INTENT_WIRE_EXTENSION = {
    'intent' => ->(v) { AtlasPca.validate_intent_wire(v) },
    'intent_session' => ->(v) { AtlasPca.validate_intent_session_wire(v) },
    'fresh_at' => ->(v) { AtlasPca.validate_fresh_at_wire(v) }
  }.freeze
  INTENT_EXTENSIONS = {
    'wire' => INTENT_WIRE_EXTENSION,
    'intentBinding' => ->(*a) { AtlasPca.decide_intent_binding(*a) },
    'intentV2' => ->(*a) { AtlasPca.decide_intent_v2(*a) },
    'freshAt' => ->(*a) { AtlasPca.decide_fresh_at(*a) }
  }.freeze
end
