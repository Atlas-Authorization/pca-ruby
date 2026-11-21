# frozen_string_literal: true

# Replays the TS-reference oracle of the connector action catalog (test-data/ref-catalog.json.gz, 75 cases): define_action, the
# fail-closed spec of an unknown verb, the built-in actions with the default catalog's digest and the blast presets, and the
# catalog scenarios (one result per op over build_catalog: get / forConnector / all / resolve / resolveAction / digest /
# assertPinned / extend; an op that raises is {"$err": true}). Every fn and every op has a handler; the total is asserted.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefCatalog < Minitest::Test
  C = AtlasPca::Catalog
  BY_FN = Ref.load('catalog')
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  OPS = {
    'get' => ->(cat, *a) { cat.get(*a) },
    'forConnector' => ->(cat, *a) { cat.for_connector(*a) },
    'all' => ->(cat) { cat.all },
    'resolve' => ->(cat, *a) { cat.resolve(*a) },
    'resolveAction' => ->(cat, verb) { C.resolve_action(cat, verb) },
    'digest' => ->(cat) { C.catalog_digest(cat) },
    'assertPinned' => lambda { |cat, expected|
      C.assert_catalog_pinned(cat, expected == '$self' ? C.catalog_digest(cat) : expected)
      true
    },
    'extend' => lambda { |cat, extra|
      e = C.extend_catalog(cat, extra)
      { 'all' => e.all, 'digest' => C.catalog_digest(e) }
    }
  }.freeze

  def self.scenario(actions, ops)
    cat = C.build_catalog(actions)
    ops.map do |op, *a|
      OPS.fetch(op).call(cat, *a)
    rescue StandardError
      { '$err' => true }
    end
  end

  HANDLERS = {
    'defineAction' => ->(spec) { C.define_action(spec) },
    'uncataloguedSpec' => ->(verb) { C.uncatalogued_spec(verb) },
    'builtin' => -> { { 'actions' => AtlasPca::BUILTIN_ACTIONS, 'digest' => C.catalog_digest(C::DEFAULT_CATALOG), 'blast' => C::BLAST } },
    'catalog' => ->(actions, ops) { scenario(actions, ops) }
  }.freeze

  def test_every_fn_and_every_op_of_the_corpus_has_a_handler
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal 75, BY_FN.values.sum(&:length)
    ops = BY_FN.fetch('catalog').flat_map { |c| c['args'][1].map(&:first) }.uniq
    assert_equal (OPS.keys + ['bogus']).sort, ops.sort, 'the ops of the scenarios (bogus is the unknown op the reference refuses)'
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| self.class.dnum(a) }) })
    end
  end
end
