# frozen_string_literal: true

# Replays the TS-reference oracle of the seeded connector provider catalog (test-data/ref-connectors-providers.json.gz, 40 cases): the 15
# manifests by name (the manifest, its digest, its validity), the structural invariants every built-in holds, the built-in list in
# registration order with its digests and the catalog digest, and the ids outside the catalog (case, whitespace and prototype names are never
# found: a lookup is an exact own-key lookup). Every fn has a handler and the totals are asserted.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefConnectorsProviders < Minitest::Test
  C = AtlasPca::Connectors
  BY_FN = Ref.load('connectors-providers')
  TOTALS = { 'provider' => 15, 'invariants' => 15, 'builtinManifests' => 1, 'unknownProvider' => 9 }.freeze

  def self.manifest(id) = C::BUILTIN_BY_ID.fetch(id)

  HANDLERS = {
    'provider' => lambda { |id|
      m = manifest(id)
      { 'manifest' => m, 'digest' => C.manifest_digest(m), 'valid' => C.validate_manifest(m)['ok'] }
    },
    'invariants' => lambda { |id|
      m = manifest(id)
      { 'defaultScopesSubset' => m['defaultScopes'].all? { |s| m['scopesAvailable'].include?(s) },
        'scopesUnique' => m['scopesAvailable'].uniq.length == m['scopesAvailable'].length, 'idMatchesKey' => m['id'] == id,
        'httpsEndpoints' => [m['authorizeUrl'], m['tokenUrl']].all? { |u| u.start_with?('https://') } }
    },
    'builtinManifests' => lambda {
      { 'ids' => C::BUILTIN_MANIFESTS.map { |m| m['id'] }, 'digests' => C::BUILTIN_MANIFESTS.map { |m| C.manifest_digest(m) },
        'catalogDigest' => C.catalog_digest }
    },
    'unknownProvider' => ->(id) { { 'found' => !C.get_provider(id).nil? } }
  }.freeze

  def test_every_fn_of_the_corpus_has_a_handler_and_the_totals_are_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 40, BY_FN.values.sum(&:length)
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      assert_equal TOTALS.fetch(fn), Ref.run(self, BY_FN.fetch(fn), handler)
    end
  end
end
