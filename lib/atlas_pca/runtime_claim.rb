# frozen_string_literal: true

# Runtime-class claims (verification side): a statement signed by a pinned attestor that an agent's sandbox runs at a class.
# Valid only for this passport, inside its validity window, over evidence the caller has already verified (its digest is in
# verified_evidence), signed over domain || canonical(claim without sig), with no member beyond the eight. Anything else is
# 'none'. Total. Hashes use String keys.
module AtlasPca
  RUNTIME_CLAIM_DOMAIN = "atlas-pca/runtime-class-claim/v1\x00".b.freeze
  RUNTIME_CLASSES = %w[none os_confined egress_default_deny wasi_no_ambient].freeze
  RUNTIME_CLAIM_KEYS = %w[v class passport_digest evidence_digest iat exp attestor sig].freeze

  module_function

  def verified_runtime_class(claim, pinned_attestors, passport_digest, verified_evidence, now)
    return 'none' unless claim.is_a?(Hash) && claim.keys.sort == RUNTIME_CLAIM_KEYS.sort
    return 'none' unless claim['v'] == 1 && claim['v'].is_a?(Integer) && RUNTIME_CLASSES.include?(claim['class'])
    return 'none' unless k3_str?(claim['attestor'], 128) && k3_str?(claim['passport_digest'], 128) && k3_str?(claim['evidence_digest'], 128)
    return 'none' unless k3_int?(claim['iat']) && k3_int?(claim['exp']) && k3_int?(now)
    return 'none' unless pinned_attestors.include?(claim['attestor']) && claim['passport_digest'] == passport_digest
    return 'none' unless verified_evidence.include?(claim['evidence_digest']) && claim['iat'] <= now && now < claim['exp']

    body = claim.reject { |k, _| k == 'sig' }
    k3_verify_body(RUNTIME_CLAIM_DOMAIN, body, claim['attestor'], claim['sig']) ? claim['class'] : 'none'
  rescue StandardError
    'none'
  end
end
