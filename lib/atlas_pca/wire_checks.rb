# frozen_string_literal: true

module AtlasPca
  # The wire validator with refusal reasons, the strict-profile number check and the small canonical / base64url / threshold helpers of the
  # reference's `wire`, `hash`, `strict-json`, `keys`, `pcactn` and `threshold` modules.
  PCACTN_WIRE_HOP_KEYS = %w[id issuer holder body_digest caveats sig parent alg pq_pk pq_sig holder_pq].freeze
  MAX_AUD_LEN = 256
  MAX_NONCE_LEN = 128
  MAX_JSON_BYTES = 1 << 20
  # The strict JSON profile's error: the SDK's strict parser raises this class.
  StrictJsonError = Malformed

  module_function

  def wire_obj?(v) = v.is_a?(Hash)
  def wire_int?(v) = safe_int?(v) && !(v.is_a?(Float) && v.zero? && (1.0 / v).negative?)
  def wire_num?(v) = v.is_a?(Numeric) && (!v.is_a?(Float) || v.finite?)
  def wire_str?(v) = v.is_a?(String)

  # Validate the wire form of a PCActn. nil when well-formed, else a short reason. Never raises. Judges presence, JSON type, closed field
  # sets, integer-ness, canonical base64url of every fixed-length byte field and that the signed body admits the strict canonical encoding;
  # not semantic ranges. `ext` ({'intent', 'intent_session', 'fresh_at'} => ->(v) { reason_or_nil }) validates the optional extension
  # slots; without one the slot is refused.
  def validate_wire_v2(p, ext = nil)
    return 'PCActn is not an object' unless wire_obj?(p)

    known = PCACTN_REQUIRED_FIELDS + PCACTN_OPTIONAL_FIELDS
    p.each_key { |k| return "unknown field '#{k}'" unless known.include?(k) }
    PCACTN_REQUIRED_FIELDS.each { |k| return "missing field '#{k}'" unless p.key?(k) }
    begin
      canonicalize(p.reject { |k, _| %w[sig threshold pq_sig].include?(k) })
    rescue StandardError => e
      return e.message
    end
    %w[ver counter iat exp].each { |k| return "'#{k}' must be a safe integer" unless wire_int?(p[k]) }
    return "'aud' must be a non-empty string (<= 256 UTF-8 bytes)" unless wire_str?(p['aud']) && !p['aud'].empty? && p['aud'].bytesize <= MAX_AUD_LEN
    if p.key?('nonce') && !(wire_str?(p['nonce']) && !p['nonce'].empty? && p['nonce'].bytesize <= MAX_NONCE_LEN)
      return "'nonce' must be a non-empty string (<= 128 UTF-8 bytes)"
    end

    sig_err = validate_signature_wire(p)
    return sig_err unless sig_err.nil?
    return "'grant_ref' is not canonical base64url (32 bytes)" if b64d(p['grant_ref'], 32).nil?

    a = p['action']
    return "'action' must be an object" unless wire_obj?(a)

    a.each_key { |k| return "unknown field 'action.#{k}'" unless %w[verb resource params_digest reversibility_class].include?(k) }
    return 'action.verb/resource/reversibility_class must be strings' unless %w[verb resource reversibility_class].all? { |k| wire_str?(a[k]) }
    return "'action.params_digest' is not canonical base64url (32 bytes)" if b64d(a['params_digest'], 32).nil?

    pl = p['plan']
    return "'plan' must be an object" unless wire_obj?(pl)

    pl.each_key { |k| return "unknown field 'plan.#{k}'" unless %w[root inclusion_proof node_id conditions_digest].include?(k) }
    return "'plan.root' is not canonical base64url (32 bytes)" if b64d(pl['root'], 32).nil?
    return "'plan.node_id' must be a string" unless wire_str?(pl['node_id'])
    return "'plan.conditions_digest' must be a canonical base64url string (32 bytes)" if pl.key?('conditions_digest') && b64d(pl['conditions_digest'], 32).nil?

    ip = pl['inclusion_proof']
    return "'plan.inclusion_proof' must be an object" unless wire_obj?(ip)

    ip.each_key { |k| return "unknown field 'plan.inclusion_proof.#{k}'" unless %w[index size path].include?(k) }
    return "'plan.inclusion_proof.index' must be a safe integer" unless wire_int?(ip['index'])
    return "'plan.inclusion_proof.size' must be a safe integer" unless wire_int?(ip['size'])
    return "'plan.inclusion_proof.path' must be an array" unless ip['path'].is_a?(Array)

    ip['path'].each_with_index do |st, i|
      return "proof step #{i} must be an object" unless wire_obj?(st)

      st.each_key { |k| return "unknown field 'path[#{i}].#{k}'" unless %w[side hash].include?(k) }
      return "proof step #{i}: side must be 'L' or 'R'" unless %w[L R].include?(st['side'])
      return "proof step #{i}: hash is not canonical base64url (32 bytes)" if b64d(st['hash'], 32).nil?
    end
    return "'cap_chain' must be an array" unless p['cap_chain'].is_a?(Array)

    p['cap_chain'].each_with_index do |c, i|
      return "cap_chain[#{i}] must be an object" unless wire_obj?(c)

      c.each_key { |k| return "unknown field 'cap_chain[#{i}].#{k}'" unless PCACTN_WIRE_HOP_KEYS.include?(k) }
      %w[id issuer holder body_digest].each { |k| return "cap_chain[#{i}].#{k} is not canonical base64url (32 bytes)" if b64d(c[k], 32).nil? }
      hop_err = validate_signature_wire(c)
      return "cap_chain[#{i}]: #{hop_err}" unless hop_err.nil?
      return "cap_chain[#{i}].parent is not canonical base64url (32 bytes)" if c.key?('parent') && b64d(c['parent'], 32).nil?
      return "cap_chain[#{i}].holder_pq is not canonical base64url (32 bytes)" if c.key?('holder_pq') && b64d(c['holder_pq'], 32).nil?
      return "cap_chain[#{i}].caveats must be an array of {type,...} objects" unless c['caveats'].is_a?(Array) && c['caveats'].all? { |cv| wire_obj?(cv) && wire_str?(cv['type']) }
    end
    at = p['attestation']
    return "'attestation' must be an object with an integer 'epoch'" unless wire_obj?(at) && wire_int?(at['epoch'])
    return 'attestation string fields must be strings' unless %w[quote_digest model_id measurement operator].all? { |k| wire_str?(at[k]) }

    pv = p['provenance']
    return "'provenance' is malformed" unless wire_obj?(pv) && wire_str?(pv['causal_hash']) && wire_num?(pv['taint_level']) && pv['trusted_refs'].is_a?(Array) && pv['trusted_refs'].all? { |s| wire_str?(s) }

    fr = p['freshness']
    return "'freshness' is malformed" unless wire_obj?(fr) && wire_int?(fr['epoch']) && wire_str?(fr['beacon_ref']) && wire_str?(fr['accumulator_witness'])

    rc = p['risk_claim']
    return "'risk_claim' is malformed" unless wire_obj?(rc) && wire_num?(rc['r']) && wire_obj?(rc['inputs'])
    return "'caution' must be a number in [0,1]" if p.key?('caution') && !(wire_num?(p['caution']) && p['caution'] >= 0 && p['caution'] <= 1)
    return "'rationale_commitment' is not canonical base64url (32 bytes)" if p.key?('rationale_commitment') && b64d(p['rationale_commitment'], 32).nil?
    return "'tool_binding' is not canonical base64url (32 bytes)" if p.key?('tool_binding') && b64d(p['tool_binding'], 32).nil?
    return "'progress_step' must be an object" if p.key?('progress_step') && !wire_obj?(p['progress_step'])

    no_intent = ->(slot) { "#{slot} is an Intent Layer extension field and this verifier does not load the intent layer (pass the extension)" }
    { 'intent' => "'intent'", 'intent_session' => "'intent_session'" }.each do |k, label|
      next unless p.key?(k)

      v = ext.is_a?(Hash) ? ext[k] : nil
      return no_intent.call(label) if v.nil?

      err = v.call(p[k])
      return err unless err.nil?
    end
    if p.key?('fresh_at')
      v = ext.is_a?(Hash) ? ext['fresh_at'] : nil
      return "'fresh_at' is a consistency-token extension field and this verifier does not load it (pass the extension)" if v.nil?

      err = v.call(p['fresh_at'])
      return err unless err.nil?
    end
    return "'prohibition_evidence' must be an object or array" if p.key?('prohibition_evidence') && !wire_obj?(p['prohibition_evidence']) && !p['prohibition_evidence'].is_a?(Array)

    if p.key?('threshold')
      th = p['threshold']
      return "'threshold' must be {shares:[...]}" unless wire_obj?(th) && th['shares'].is_a?(Array)

      th['shares'].each_with_index do |s, i|
        return "threshold.shares[#{i}] is malformed" unless wire_obj?(s) && wire_str?(s['role'])
        return "threshold.shares[#{i}].publicKey is not canonical base64url (32 bytes)" if b64d(s['publicKey'], 32).nil?

        e = validate_share_signature_wire(s)
        return "threshold.shares[#{i}]: #{e}" unless e.nil?
      end
    end
    nil
  rescue StandardError => e
    "malformed: #{e.message}"
  end

  # Strict-profile check of one number: an error string or nil.
  def strict_number_error(v)
    return 'non-finite number' if v.is_a?(Float) && !v.finite?
    return 'negative zero' if v.is_a?(Float) && v.zero? && (1.0 / v).negative?
    return (v.abs <= MAX_SAFE ? nil : 'integer outside the safe range (|n| > 2^53-1)') if v.is_a?(Integer) || v == v.floor
    return 'non-integer magnitude below 1e-6 (needs an exponent form; not representable in the canonical decimal form)' if v.abs < 1e-6

    s = Predicates.js_number_string(v)
    return 'non-integer number needs an exponent form (not representable in the canonical decimal form)' if s.match?(/e/i)

    digits = s.delete('-').delete('.').sub(/\A0+/, '')
    digits.length > MAX_DECIMAL_DIGITS ? "non-integer number has more than #{MAX_DECIMAL_DIGITS} significant digits" : nil
  end

  # True when `s` exceeds MAX_ARTIFACT_BYTES UTF-8 bytes (checked before any parsing).
  def artifact_too_large?(s) = s.bytesize > MAX_ARTIFACT_BYTES

  # The strict canonical bytes (what every protocol digest and signature covers), and the LENIENT server-only variant (tolerates exponent /
  # >15-digit numbers; NEVER for a protocol hash).
  def canonical_bytes_strict(v) = canon_bytes(v)
  def canonicalize_lenient_server_only(v) = ActionsImportCommon.lenient(v)
  def canonical_bytes_lenient(v) = canonicalize_lenient_server_only(v).dup.force_encoding('UTF-8').b

  # STRICT base64url (no padding, canonical): the bytes, or nil for ANY deviation; `len` fixes the decoded length.
  def decode_b64u_strict(s, len = nil) = b64d(s, len)

  # A signature / key as base64url, and back (raises ArgumentError on text that is not base64url).
  def encode_sig(bytes) = b64e(bytes)
  def decode_sig(s) = b64d(s) || raise(ArgumentError, 'not base64url')

  # Collect shares into a threshold signature (defensively copied): {'shares' => [...]}.
  def assemble_threshold(shares) = { 'shares' => shares.is_a?(Array) ? shares.dup : [] }
end
