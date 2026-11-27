# frozen_string_literal: true

module AtlasPca
  # The reference's exported protocol constants under the reference's own names. Where this SDK keeps the value in a module of its own
  # (Dpop, Actions, ...; the opt-in Fndsa::NO_BACKEND_MESSAGE and SigstoreBundle::MEDIA_TYPES stay where they are) the name is an alias of that constant, so there is one source of truth; the rest are the reference's values.
  PCACTN_WIRE_VERSION = 2
  PCACTN_REQUIRED_FIELDS = TOP_REQUIRED
  PCACTN_OPTIONAL_FIELDS = TOP_OPTIONAL
  DEFAULT_SIG_ALG = 'ed25519'
  DEFAULT_REVERSIBILITY_CLASS = DEFAULT_REV
  DEFAULT_FRESHNESS_EPOCH_MS = 60_000
  VALID_THRESHOLDS = [1, 2, 3].freeze
  AGENT_LEAF_SHARE_BINDING_VERSION = '2.1'
  ESCALATION_ACTION_DOMAIN = 'atlas-pca/escalation-action/v1'
  ESCALATION_HISTORY_DOMAIN = 'atlas-pca/escalation-history/v1'
  ESCALATION_POLICY_DOMAIN = 'atlas-pca/escalation-policy/v1'
  TEMPLATE_KIND = 'pca-policy-template'
  TIGHTEN_KIND = 'pca-template-tighten'
  MAX_SLOTS = MAX_TEMPLATE_SLOTS
  REGEX_CACHE_MAX_ENTRIES = SafeRegex::CACHE_MAX_ENTRIES
  DPOP_DEFAULT_MAX_AGE_SEC = Dpop::DEFAULT_MAX_AGE_SEC
  DPOP_JWT_TYP = Dpop::JWT_TYP
  DPOP_MAX_PROOF_BYTES = Dpop::MAX_PROOF_BYTES
  DPOP_CLOCK_SKEW_SEC = Dpop::CLOCK_SKEW_SEC
  DPOP_INMEMORY_MAX_ENTRIES = Dpop::INMEMORY_MAX_ENTRIES
  ACTION_DEF_VERSION = 1
  PARAM_TYPES_V1 = Actions::PARAM_TYPES
  SENSITIVITY_LEVELS = Actions::SENSITIVITY_RANK.keys.freeze
  TAINT_CONTEXT_RE = Actions::TAINT_RE
  DEFAULT_RULES_VERSION = '1.1.0'
  DEFAULT_LEASE_SHARDS = 16
  MAX_LEASE_SHARDS = 4096
  MCC_TRAIT_RE = /\Amcc\.c([0-9]{4})\z/
end
