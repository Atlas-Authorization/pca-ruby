# frozen_string_literal: true

# Replays the TS-reference oracle of the wire schemas and the structural validator (test-data/ref-schema-dotnet.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/schema'
require 'minitest/autorun'

class TestRefSchema < Minitest::Test
  S = AtlasPca::Schema
  BY_FN = Ref.load('schema-dotnet')

  MAP = {
    'validate' => ->(s, v) { S.validate(s.is_a?(String) ? S::ALL_SCHEMAS[s] : s, v) },
    'schemas' => -> { S::ALL_SCHEMAS }
  }.freeze

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 3216, BY_FN.values.sum(&:length), 'schema-dotnet'
  end

end
