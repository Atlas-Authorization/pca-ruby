# frozen_string_literal: true

# The reference's protocol constants under its names: aliases agree with the module that owns the value.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestReferenceNames < Minitest::Test
  A = AtlasPca

  def test_aliases_share_the_value_of_their_owner
    assert_same A::TOP_REQUIRED, A::PCACTN_REQUIRED_FIELDS
    assert_same A::TOP_OPTIONAL, A::PCACTN_OPTIONAL_FIELDS
    assert_equal 14, A::PCACTN_REQUIRED_FIELDS.length
    assert_equal [A::Dpop::JWT_TYP, A::Dpop::MAX_PROOF_BYTES], [A::DPOP_JWT_TYP, A::DPOP_MAX_PROOF_BYTES]
    assert_same A::Actions::PARAM_TYPES, A::PARAM_TYPES_V1
    assert_equal %w[free material critical], A::SENSITIVITY_LEVELS
    assert_same A::Actions::TAINT_RE, A::TAINT_CONTEXT_RE
    assert_equal 512, A::REGEX_CACHE_MAX_ENTRIES
  end

  def test_literal_values
    assert_equal [2, 'ed25519', 'reversible', 60_000, [1, 2, 3], '2.1'],
                 [A::PCACTN_WIRE_VERSION, A::DEFAULT_SIG_ALG, A::DEFAULT_REVERSIBILITY_CLASS, A::DEFAULT_FRESHNESS_EPOCH_MS, A::VALID_THRESHOLDS,
                  A::AGENT_LEAF_SHARE_BINDING_VERSION]
    assert_match A::MCC_TRAIT_RE, 'mcc.c5734'
    refute_match A::MCC_TRAIT_RE, 'mcc.c57345'
    assert_equal 'atlas-pca/escalation-action/v1', A::ESCALATION_ACTION_DOMAIN
    assert_equal [16, 4096], [A::DEFAULT_LEASE_SHARDS, A::MAX_LEASE_SHARDS]
  end
end
