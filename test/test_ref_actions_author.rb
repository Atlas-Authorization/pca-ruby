# frozen_string_literal: true

# Replays the reference oracles of the authoring shorthands, entry expansion, document loader, action() constructor and the typed param
# builder (test-data/ref-actions-author.json.gz, ref-actions-author-loader.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_author'
require 'minitest/autorun'

class TestRefActionsAuthor < Minitest::Test
  AU = AtlasPca::ActionsAuthor
  LOADER = Ref.load('actions-author-loader')
  FULL = Ref.load('actions-author')
  NAMES = { 'bool' => 'bool_', 'int' => 'int_', 'id' => 'id_', 'enum' => 'enum_', 'set' => 'set_' }.freeze

  # lone surrogates and bad input ride through the messages: compare as JS-order JSON
  CMP = lambda do |got, out, _c|
    js = ->(v) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(v))) }
    js.call(got) == js.call(out)
  end

  MAP = {
    'parseParamShorthand' => AU.method(:parse_param_shorthand),
    'parseResourceShorthand' => AU.method(:parse_resource_shorthand),
    'defaultTitle' => AU.method(:default_title),
    'expandAction' => AU.method(:expand_action),
    'loadActionsValue' => AU.method(:load_actions_value),
    'action' => AU.method(:action),
    'builder' => ->(name, *args) { AU::P.public_send(NAMES.fetch(name, name), *args) }
  }.freeze

  def test_every_function_is_covered = assert_equal [], (LOADER.keys | ['builder']) - MAP.keys

  MAP.each do |fn, call|
    define_method("test_#{fn}") do
      # the shared corpus is replayed for the builder only: its other cases rely on JS undefined members (the loader corpus covers them)
      Ref.run(self, (fn == 'builder' ? FULL : LOADER)[fn], call, compare: CMP)
    end
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 151, LOADER.values.sum(&:length), 'actions-author-loader'
    assert_equal 503, FULL.values.sum(&:length), 'actions-author'
  end

end
