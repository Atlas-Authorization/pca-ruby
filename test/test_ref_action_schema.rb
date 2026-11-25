# frozen_string_literal: true

# Replays the TS-reference oracles of the site-signed action schema (test-data/ref-action-schema.json.gz, 173 cases, and
# test-data/ref-action-schema-draft.json.gz, 104 cases): the exported constants (with the source of the three patterns), the value-dependent
# reversibility class (own-property lookups only), the wallet-floor test, the verb lookup, signing a schema and deriving its key entry under the
# Ed25519, ML-DSA-65 and hybrid suites (byte for byte), verification (reasons compared exactly, except the library text after
# `schema verification error:` and `malformed schema:`), the digest, the MCP reversibility hints and the two drafting importers (todo strings
# compared exactly and in order). Every fn of each corpus has a handler and the totals are asserted. Encodings: {"$num": ...} a non-finite number;
# {"$bytes": {"$seed": label}} the 32-byte Ed25519 secret; a suite is {alg, pqSeed?}. Cases that sign or verify with ML-DSA need a runtime that has
# it (OpenSSL >= 3.5).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefActionSchema < Minitest::Test
  A = AtlasPca
  S = AtlasPca::ActionSchemaApi
  MAIN = Ref.load('action-schema')
  DRAFT = Ref.load('action-schema-draft')
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze
  PQ = A.supported_suites.include?('ml-dsa-65')
  LIBRARY_TEXT = ['schema verification error:', 'malformed schema:'].freeze

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  def self.suite(s)
    return {} unless s.is_a?(Hash)

    { alg: s['alg'], pq: s['pqSeed'] ? A::PqKeyPair.from_seed('ML-DSA-65', s['pqSeed']) : nil }
  end

  HANDLERS = {
    'constants' => -> { S.constants_view },
    'reversibilityOf' => ->(v, params) { S.reversibility_of(v, params) },
    'floorApplies' => ->(sem, floor) { S.floor_applies(sem, floor) },
    'schemaVerb' => ->(doc, verb) { A.schema_verb(doc, verb) },
    'signActionSchema' => ->(doc, kid, secret, s) { A.sign_action_schema(doc, kid, A::KeyPair.new(secret), **suite(s)) },
    'actionSchemaKeyOf' => ->(kid, secret, s) { A.action_schema_key_of(kid, A::KeyPair.new(secret), **suite(s)) },
    'actionSchemaDigest' => ->(doc) { A.action_schema_digest(doc) },
    'verifyActionSchema' => ->(doc, keys) { A.verify_action_schema(doc, keys) },
    'reversibilityFromMcpHints' => ->(a) { A::Mcp.reversibility_from_mcp_hints(a) },
    'draftSchemaFromMcpTools' => ->(tools, site) { A::Mcp.draft_schema_from_mcp_tools(tools, site) },
    'draftSchemaFromOpenApi' => ->(doc, site) { A::Mcp.draft_schema_from_open_api(doc, site) }
  }.freeze

  MAIN_TOTALS = { 'constants' => 1, 'reversibilityOf' => 20, 'floorApplies' => 19, 'schemaVerb' => 9, 'signActionSchema' => 12, 'actionSchemaKeyOf' => 6,
                  'actionSchemaDigest' => 4, 'verifyActionSchema' => 30, 'reversibilityFromMcpHints' => 9, 'draftSchemaFromMcpTools' => 31,
                  'draftSchemaFromOpenApi' => 32 }.freeze
  DRAFT_TOTALS = { 'reversibilityOf' => 72, 'draftSchemaFromOpenApi' => 16, 'reversibilityFromMcpHints' => 9, 'schemaVerb' => 7 }.freeze

  def self.pq_case?(c) = Ref.canon(c['args']).match?(/ml-dsa/)

  def self.same?(got, out, _c)
    if out.is_a?(Hash) && out['ok'] == false && out['reason'].is_a?(String) && got.is_a?(Hash)
      pre = LIBRARY_TEXT.find { |p| out['reason'].start_with?(p) }
      return got['ok'] == false && got['reason'].to_s.start_with?(pre) if pre
    end
    Ref.canon(got) == Ref.canon(out)
  end

  def test_every_fn_of_each_corpus_has_a_handler_and_the_totals_are_pinned
    assert_equal MAIN_TOTALS.keys.sort, MAIN.keys.sort
    assert_equal MAIN_TOTALS, MAIN.transform_values(&:length)
    assert_equal 173, MAIN.values.sum(&:length)
    assert_equal DRAFT_TOTALS, DRAFT.transform_values(&:length)
    assert_equal 104, DRAFT.values.sum(&:length)
    assert_empty((MAIN.keys + DRAFT.keys) - HANDLERS.keys)
  end

  def test_the_post_quantum_cases_run_where_required
    assert PQ, 'this runtime must have ML-DSA-65' if ENV['PCA_REQUIRE_PQ'] == '1'
  end

  { 'action-schema' => MAIN, 'action-schema-draft' => DRAFT }.each do |corpus, by_fn|
    by_fn.each_key do |fn|
      define_method("test_replay_#{corpus.tr('-', '_')}_#{fn}") do
        k = self.class
        handler = HANDLERS.fetch(fn)
        Ref.run(self, by_fn.fetch(fn), ->(*args) { handler.call(*args.map { |a| k.dnum(a) }) }, skip: ->(c) { !PQ && k.pq_case?(c) },
                compare: ->(got, out, c) { k.same?(got, out, c) })
      end
    end
  end
end
