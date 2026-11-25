# frozen_string_literal: true

# Replays the TS-reference oracles of negative authority and behavioural contracts over the names the shared vector files do
# not call directly: test-data/ref-prohibitions.json.gz (1637 cases: the constants, validate_when, when_matches?,
# sign_constitution, compose_authority, advance_state, evidence_digest) and test-data/ref-contracts.json.gz (1269 cases: the
# constants, validate_clause, contract_id, sign_contract, embedded_constitution, contract_from_constitution, check_contract,
# advance_contract, check_and_advance_contract). Every fn of each corpus has a handler; a reference throw must be a native raise.
# A signing key is the base64url Ed25519 seed sha256("atlas-pca-conformance/" + label); a trailing argument the reference
# call omits is omitted here too (absent and null differ).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefProhibitionsContracts < Minitest::Test
  P = AtlasPca::Prohibitions
  C = AtlasPca::Contracts

  def self.key(seed)
    raise TypeError, 'a signing key is a base64url seed' unless seed.is_a?(String)

    AtlasPca::KeyPair.from_seed_b64u(seed)
  end

  CORPORA = {
    'prohibitions' => [1637, {
      'constants' => lambda do
        { 'CONSTITUTION_VERSION' => P::CONSTITUTION_VERSION, 'CONSTITUTION_SIG_DOMAIN' => P::CONSTITUTION_SIG_DOMAIN,
          'EVIDENCE_VERSION' => P::EVIDENCE_VERSION, 'SAFETY_EVIDENCE_SIG_DOMAIN' => P::SAFETY_EVIDENCE_SIG_DOMAIN,
          'STATE_DIGEST_DOMAIN' => P::STATE_DIGEST_DOMAIN, 'STATE_CHAIN_DOMAIN' => P::STATE_CHAIN_DOMAIN,
          'MAX_LEDGER' => P::MAX_LEDGER, 'MAX_INVARIANTS' => P::MAX_INVARIANTS, 'MAX_DEADLINE' => P::MAX_DEADLINE }
      end,
      'validateWhen' => ->(w, label) { P.validate_when(w, label) },
      'whenMatches' => ->(w, ctx) { P.when_matches?(w, ctx) },
      'signConstitution' => ->(c, sk) { P.sign_constitution(c, key(sk)) },
      'composeAuthority' => ->(permitted, action, c, state) { P.compose_authority(permitted, action, c, state) },
      'advanceState' => ->(*a) { P.advance_state(*a) }, # the 4th argument (now) is absent or present
      'evidenceDigest' => ->(ev) { P.evidence_digest(ev) }
    }],
    'contracts' => [1269, {
      'constants' => lambda do
        { 'CONTRACT_VERSION' => C::CONTRACT_VERSION, 'CONTRACT_SIG_DOMAIN' => C::CONTRACT_SIG_DOMAIN, 'MAX_CLAUSES' => C::MAX_CLAUSES,
          'MAX_CLAUSE_DEPTH' => C::MAX_CLAUSE_DEPTH }
      end,
      'validateClause' => ->(cl, seen, depth) { C.validate_clause(cl, seen.to_h { |id| [id, true] }, depth) },
      'contractId' => ->(c) { C.contract_id(c) },
      'signContract' => ->(c, sk) { C.sign_contract(c, key(sk)) },
      'embeddedConstitution' => ->(c) { C.embedded_constitution(c) },
      'contractFromConstitution' => ->(c) { C.contract_from_constitution(c) },
      'checkContract' => ->(action, contract, state) { C.check_contract(action, contract, state) },
      'advanceContract' => ->(*a) { C.advance_contract(*a) }, # the options argument is absent or present (null included)
      'checkAndAdvanceContract' => ->(*a) { C.check_and_advance_contract(*a) }
    }]
  }.freeze
  BY_FN = CORPORA.to_h { |name, _| [name, Ref.load(name)] }

  CORPORA.each do |name, (total, handlers)|
    define_method("test_#{name}_every_fn_of_the_corpus_has_a_handler") do
      assert_equal handlers.keys.sort, BY_FN.fetch(name).keys.sort
      assert_equal total, BY_FN.fetch(name).values.sum(&:length)
    end

    handlers.each do |fn, handler|
      define_method("test_#{name}_replay_#{fn}") { Ref.run(self, BY_FN.fetch(name).fetch(fn), handler) }
    end
  end
end
