# frozen_string_literal: true

require 'digest'

module AtlasPca
  # Hash-suite agility (the reference's `hash`): the default suite, the suite guard and dispatch, the canonical base64url guard
  # and length, and the small protocol constants the reference exports next to them. The DEFAULT suite is byte-identical to the
  # bare SHA-256 form, so every existing protocol digest is unchanged; `sha384` is the optional stronger-margin variant.
  DEFAULT_HASH_SUITE = 'sha256'
  HASH_LEN = { 'sha256' => 32, 'sha384' => 48 }.freeze

  PCACTN_DEFAULT_TTL_MS = 20 * 60_000
  PCACTN_MAX_LIFETIME_MS = 3_600_000
  PCACTN_MAX_SKEW_MS = 60_000
  # a replay record must outlive the longest acceptable artifact
  REPLAY_MIN_RETENTION_MS = PCACTN_MAX_LIFETIME_MS + (2 * PCACTN_MAX_SKEW_MS)
  PCA_NEED_PARAM = 'pca_need'
  PCA_NEED_DOMAIN = 'atlas-pca/need/v1'
  PCA_GRANT_MAX_DETAILS = 16
  PCA_GRANT_MAX_CHAIN_LEN = 16
  MAX_DETECTOR_RECEIPTS = 32
  UNDO_RELAY_GRACE_MS = 60_000
  MAX_PQ_SIGNER_ENTRIES = 256
  # the reversibility score of each catalog class (1: fully undoable, 0: irreversible)
  CATALOG_REVERSIBILITY_SCORE = { 'reversible' => 1, 'rate_limited' => 0.4, 'costly' => 0.4, 'irreversible' => 0 }.freeze
  # the checks a stateful verifier must run (a `require` list may not drop them), and those an executor adds
  STATEFUL_REQUIRED_CHECKS = %w[counter_format replay revocation plan_root_authorized audience validity grant_ref_bound].freeze
  EXECUTION_REQUIRED_CHECKS = (STATEFUL_REQUIRED_CHECKS + %w[params_digest policy]).freeze

  module_function

  # True iff `s` is a known hash suite. Anything else must fail closed at the caller.
  def hash_suite?(s) = s == 'sha256' || s == 'sha384'

  # Dispatch a raw-byte hash over the selected suite (anything but 'sha384' is SHA-256, as the reference).
  def hash_with_suite(bytes, suite = DEFAULT_HASH_SUITE) = suite == 'sha384' ? Digest::SHA384.digest(bytes.b) : Digest::SHA256.digest(bytes.b)

  # Encoded (unpadded) base64url length of `n` bytes.
  def b64u_len(n) = ((n * 4) / 3.0).ceil

  # True iff `s` is canonical base64url (optionally of an exact decoded byte length).
  def canonical_b64u?(s, len = nil) = !b64d(s, len).nil?
end

module AtlasPca
  module_function

  # The PCActn's `aud`, `iat` and `exp` checked BEFORE any signature verification or metering: a pass proves nothing (the fields are
  # unauthenticated) but a FAIL is final, since the full verifier makes the same audience and validity decisions on the same fields.
  # nil when both pass, else {'check' => 'audience' | 'validity', 'reason' => ...}. `audience` is this verifier's audience id, `now` epoch ms.
  def pcactn_cheap_claims(p, audience:, now:)
    p = {} unless p.is_a?(Hash)
    return { 'check' => 'audience', 'reason' => 'aud does not match this resource server / instance' } unless p['aud'].is_a?(String) && !p['aud'].empty? && p['aud'] == audience
    return { 'check' => 'validity', 'reason' => 'iat and exp must be safe-integer epoch ms' } unless wb_safe_int?(p['iat']) && wb_safe_int?(p['exp'])

    iat = p['iat']
    exp = p['exp']
    # the verified core's ValidityDecision, in its order
    return { 'check' => 'validity', 'reason' => 'the verifier clock is not a safe integer epoch-ms' } unless wb_safe_int?(now)
    return { 'check' => 'validity', 'reason' => 'exp must be greater than iat' } unless exp > iat
    return { 'check' => 'validity', 'reason' => "lifetime exceeds #{PCACTN_MAX_LIFETIME_MS} ms" } if exp - iat > PCACTN_MAX_LIFETIME_MS
    return { 'check' => 'validity', 'reason' => 'iat is in the future (clock skew)' } if iat > now + PCACTN_MAX_SKEW_MS
    return { 'check' => 'validity', 'reason' => 'the PCActn has expired' } if now > exp

    nil
  end
end
