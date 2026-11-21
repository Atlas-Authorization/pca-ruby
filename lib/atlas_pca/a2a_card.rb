# frozen_string_literal: true

# A2A 1.0 Agent Card helpers under one name: RFC 8785 canonical bytes (jcs_bytes), the AgentCard schema check (validate_agent_card1),
# signed cards (issue_signed_agent_card / verify_agent_card, JWS over the canonical card minus 'signatures') and the extended card
# derived from a residual policy (extended_agent_card). Cards are String-keyed Hashes; results are Hashes shaped like the
# TypeScript reference (@atlasauth/pca-a2a). The implementations live in AgentcardCard (canonical form, schema, signing) and
# A2aBinding (verification against a JWKS, extended card); this module is the single entry point and is replayed by the A2A tests.
require_relative 'agentcard_card'
require_relative 'a2a_binding'

module AtlasPca
  module A2aCard
    PCA_A2A_EXTENSION_URI = A2aBinding::PCA_A2A_EXTENSION_URI
    PCA_PASSPORT_HEADER = AgentcardCard::PCA_PASSPORT_HEADER

    module_function

    def jcs_bytes(value) = AgentcardCard.jcs_bytes(value)
    def validate_agent_card1(card) = AgentcardCard.validate_agent_card1(card)
    def issue_signed_agent_card(card, signing_key, opts = nil) = AgentcardCard.issue_signed_agent_card(card, signing_key, opts)
    def verify_agent_card(card, opts) = A2aBinding.verify_agent_card(card, opts)
    def extended_agent_card(public_card, opts) = A2aBinding.extended_agent_card(public_card, opts)
  end
end
