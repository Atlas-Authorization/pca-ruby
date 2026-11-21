# frozen_string_literal: true

# Replays the reference oracle of the hosted action registry (publish gate, verifier view, grant facts, call context, rate keys;
# test-data/ref-actions-hosted-py.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_hosted'
require_relative '../lib/atlas_pca/actions_builtin'
require 'minitest/autorun'

class TestRefActionsHosted < Minitest::Test
  H = AtlasPca::ActionsHosted
  A = AtlasPca::Actions
  BY_FN = Ref.load('actions-hosted-py')

  GRANTS = [{ 'caveats' => [], 'max_esc' => 3, 'preauth_esc' => 0 }, { 'caveats' => %w[amount_cap window bogus], 'max_esc' => 3, 'preauth_esc' => 3 },
            { 'caveats' => %w[amount_cap count_cap resource_scope recipient_scope approval_ref short_expiry rate_cap], 'max_esc' => 1, 'preauth_esc' => 1 },
            { 'caveats' => [], 'max_esc' => 0, 'preauth_esc' => 0 }].freeze
  CTXS = [[], ['fresh_revocation'], %w[fresh_revocation idempotency approval_ref revocable dry_run_first]].freeze

  def self.sample(d)
    d['params'].each_with_object({}) do |(k, p), out|
      next if p['required'] == false

      role = p['role']
      t = p['type']
      out[k] = if role.is_a?(String) && role.start_with?('id.') then 'abc12345'
               elsif t == 'integer' then 7
               elsif t == 'boolean' then true
               elsif p['values'] then p['values'][0]
               elsif t == 'array' then ['x']
               elsif t == 'set' then []
               elsif t == 'datetime' then '2030-01-01T00:00:00Z'
               else 'val'
               end
    end
  end

  # the generator's probe: lookups, provenance, floors and undo plans for the first 6 builtin defs plus the 7th and an unknown verb
  def self.probe(versions, pins)
    alld = AtlasPca::ActionsBuiltin::BUILTIN_DEFS + AtlasPca::ActionsBuiltin::DOMAIN_DEFS
    defs = alld[0, 6] + [alld[6]]
    verbs = defs.map { |d| d['verb'] } + ['unknown.verb']
    v = H.hosted_view(versions, pins)
    { 'versions' => v.versions, 'lookups' => verbs.map { |x| v.lookup(x) }, 'prov' => verbs.map { |x| v.provenance({ 'verb' => x }) },
      'floors' => verbs.flat_map { |x| GRANTS.flat_map { |g| CTXS.map { |c| v.floor(x, g, c) } } },
      'undo' => defs.map { |d| v.undo_plan({ 'verb' => d['verb'], 'params' => sample(d) }) } }
  end

  MAP = {
    'publishGate' => ->(i) { H.publish_gate(i) },
    'hostedVersionDigest' => ->(v) { H.hosted_version_digest(v) },
    'rulesDocError' => ->(x, ns, defs) { H.rules_doc_error(x, ns, defs) },
    'registryOfTraits' => ->(t) { { 'digest' => A.traits_digest(H.registry_of_traits(t)) } },
    'hostedView' => ->(versions, pins) { probe(versions, pins) },
    'grantFactsOf' => ->(g) { H.grant_facts_of(g) },
    'hostedCallContext' => ->(l, p) { H.hosted_call_context(l, p) },
    'rateKeysOf' => ->(c, who) { H.rate_keys_of(c, who) }
  }.freeze

  def test_every_function_is_covered = assert_equal MAP.keys.sort, BY_FN.keys.sort

  MAP.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 91, BY_FN.values.sum(&:length), 'actions-hosted-py'
  end

end
