# frozen_string_literal: true

# Replays the TS-reference oracle of the OpenAPI / MCP / JSON Schema / AsyncAPI importers and their shared helpers
# (test-data/ref-actions-import-core.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_import_common'
require_relative '../lib/atlas_pca/actions_import_openapi'
require_relative '../lib/atlas_pca/actions_import_mcp'
require_relative '../lib/atlas_pca/actions_import_jsonschema'
require_relative '../lib/atlas_pca/actions_import_asyncapi'
require 'minitest/autorun'

class TestRefActionsImport < Minitest::Test
  C = AtlasPca::ActionsImportCommon
  BY_FN = Ref.load('actions-import-core')

  MAP = {
    'tokensOf' => C.method(:tokens_of), 'humanize' => C.method(:humanize), 'verbOf' => C.method(:verb_of), 'aliasOf' => C.method(:alias_of),
    'paramSeg' => C.method(:param_seg), 'clip' => C.method(:clip), 'pointer' => C.method(:pointer), 'resolveLimits' => C.method(:resolve_limits),
    'checkParsed' => ->(root, over = nil) { C.check_parsed(root, C.resolve_limits(over)) },
    'textSizeCheck' => ->(text, over = nil) { C.text_size_check(text, C.resolve_limits(over)) },
    'importOpenApi' => AtlasPca::ActionsImportOpenapi.method(:import_openapi), 'importMcp' => AtlasPca::ActionsImportMcp.method(:import_mcp),
    'importJsonSchema' => AtlasPca::ActionsImportJsonschema.method(:import_json_schema),
    'importAsyncApi' => AtlasPca::ActionsImportAsyncapi.method(:import_asyncapi)
  }.freeze

  def test_every_function_is_covered
    assert_equal [], BY_FN.keys - MAP.keys
    assert_equal [], MAP.keys - BY_FN.keys
  end

  MAP.each do |fn, call|
    define_method("test_#{fn}_matches_the_reference") { assert_operator Ref.run(self, BY_FN[fn], call), :>, 0 }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1267, BY_FN.values.sum(&:length), 'actions-import-core'
  end

end
