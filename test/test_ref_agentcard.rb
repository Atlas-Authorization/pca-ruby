# frozen_string_literal: true

# Replays the TS-reference oracle of signed Agent Cards, AgentFacts attestations, hosting handlers and registry entries
# (test-data/ref-agentcard.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/agentcard'
require 'minitest/autorun'

class TestRefAgentcard < Minitest::Test
  A = AtlasPca::Agentcard
  BY_FN = Ref.load('agentcard')
  # the reference quotes its JOSE library after the colon; only the prefix is compared
  COLON = /\A(signature( \d+)? did not verify|could not resolve verification key): .*\z/m

  def self.fix(s) = s.is_a?(String) && s.valid_encoding? ? s.sub(COLON, '\1') : s

  # a reason may carry a lone surrogate (WTF-8): compare as JS JSON
  def self.norm(r)
    return r unless r.is_a?(Hash)

    c = r.dup
    c['reason'] = fix(c['reason']) if c['reason'].is_a?(String)
    if c['attestations'].is_a?(Array)
      c['attestations'] = c['attestations'].map { |a| a.is_a?(Hash) && a['reason'].is_a?(String) ? a.merge('reason' => fix(a['reason'])) : a }
    end
    c
  end

  EQ = lambda do |got, out, _c|
    AtlasPca::Js.json(Ref.sort_keys(Ref.norm(norm(got)))) == AtlasPca::Js.json(Ref.sort_keys(Ref.norm(norm(out))))
  end

  def self.handler(make, default)
    ->(value, path, req) { make.call(value, path.nil? ? default : path).call(req) }
  end

  MAP = {
    'constants' => lambda {
      { 'DEFAULT_ALG' => A::DEFAULT_ALG, 'AGENT_FACTS_CONTEXT' => A::AGENT_FACTS_CONTEXT.dup, 'PCA_ATTESTOR_ID' => A::PCA_ATTESTOR_ID,
        'WELL_KNOWN_AGENT_CARD_PATH' => A::WELL_KNOWN_AGENT_CARD_PATH, 'WELL_KNOWN_AGENT_FACTS_PATH' => A::WELL_KNOWN_AGENT_FACTS_PATH }
    },
    'jcsBytes' => ->(v) { { '$bytes' => Ref.b64e(A.jcs_bytes(v)) } },
    'validateAgentCard1' => ->(c) { A.validate_agent_card1(c) },
    'buildAgentCard' => ->(p, o) { A.build_agent_card(p, Ref.snake(o)) },
    'issueSignedAgentCard' => ->(card, k, x = nil) { A.issue_signed_agent_card(card, k, x) },
    'verifyAgentCard' => ->(card, o) { A.verify_agent_card(card, Ref.snake(o)) },
    'issueAgentFacts' => ->(p, o) { A.issue_agent_facts(p, Ref.snake(o)) },
    'addAttestation' => ->(f, o) { A.add_attestation(f, Ref.snake(o)) },
    'verifyAgentFacts' => ->(f, o) { A.verify_agent_facts(f, Ref.snake(o)) },
    'agentCardHandler' => handler(A.method(:agent_card_handler), A::WELL_KNOWN_AGENT_CARD_PATH),
    'agentFactsHandler' => handler(A.method(:agent_facts_handler), A::WELL_KNOWN_AGENT_FACTS_PATH),
    'toRegistryEntry' => ->(c, f) { A.to_registry_entry(c, f) }
  }.freeze

  def test_every_function_in_the_corpus_is_replayed
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn], compare: EQ) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 449, BY_FN.values.sum(&:length), 'agentcard'
  end

end
