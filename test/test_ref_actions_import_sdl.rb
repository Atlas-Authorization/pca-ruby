# frozen_string_literal: true

# Replays the TS-reference oracle of the GraphQL and gRPC importers, SDL / introspection / .proto / descriptor-set parsers included
# (test-data/ref-actions-import-sdl.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_import_graphql'
require_relative '../lib/atlas_pca/actions_import_grpc'
require 'minitest/autorun'

class TestRefActionsImportSdl < Minitest::Test
  G = AtlasPca::ActionsImportGraphql
  P = AtlasPca::ActionsImportGrpc
  BY_FN = Ref.load('actions-import-sdl')

  # the reference keeps types / messages in a Map: its entries are compared as [key, value] pairs
  def self.gschema(s) = { 'types' => s['types'].map { |k, v| [k, v] } }.merge(s.slice('query', 'mutation', 'subscription'))
  def self.pmodel(m) = { 'messages' => m['messages'].map { |k, v| [k, v] }, 'enums' => m['enums'].map { |k, v| [k, v['values']] }, 'services' => m['services'] }

  # the corpus holds lone surrogates, which JSON.generate refuses: compare the JS-order serialization
  SAME = ->(got, out, _c) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(got))) == AtlasPca::Js.json(Ref.sort_keys(Ref.norm(out))) }

  MAP = {
    'importGraphql' => G.method(:import_graphql),
    'parseGraphqlSdl' => ->(s) { TestRefActionsImportSdl.gschema(G.parse_graphql_sdl(s)) },
    'fromIntrospection' => ->(d) { TestRefActionsImportSdl.gschema(G.from_introspection(d)) },
    'importGrpc' => P.method(:import_grpc),
    'parseProto' => ->(s) { TestRefActionsImportSdl.pmodel(P.parse_proto(s)) },
    'parseDescriptorSet' => ->(b) { TestRefActionsImportSdl.pmodel(P.parse_descriptor_set(b)) }
  }.freeze

  def test_every_function_is_covered
    assert_equal [], BY_FN.keys - MAP.keys
    assert_equal [], MAP.keys - BY_FN.keys
  end

  MAP.each do |fn, call|
    define_method("test_#{fn}_matches_the_reference") { assert_operator Ref.run(self, BY_FN[fn], call, compare: SAME), :>, 0 }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1033, BY_FN.values.sum(&:length), 'actions-import-sdl'
  end

end
