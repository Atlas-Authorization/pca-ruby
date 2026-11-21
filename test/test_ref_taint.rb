# frozen_string_literal: true

# Replays the TS-reference oracle of the information-flow taint module (test-data/ref-taint.json.gz, 2344 cases): the level names and constants,
# label rank / value / join, the trusted-input registry op scripts, classify_ref and compute_taint over registry and resource-graph specs
# (including a registry or graph that throws and a registry that vouches for any kind). Every fn has a handler and the totals are asserted;
# a reference refusal needs a native exception.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefTaint < Minitest::Test
  T = AtlasPca::Taint
  BY_FN = Ref.load('taint')
  TOTALS = { 'constants' => 1, 'isTaintLevel' => 24, 'labelRank' => 27, 'taintValue' => 27, 'joinLabel' => 400, 'joinLabels' => 25,
             'registry' => 9, 'classifyRef' => 841, 'computeTaint' => 990 }.freeze

  class Fixed
    def initialize(label) = @label = label
    def lookup(_digest) = @label
  end

  class Throwing
    def lookup(_digest) = raise('registry boom')
  end

  class Graph
    def initialize(nodes, throws)
      @nodes = nodes
      @throws = throws
    end

    def node(id)
      raise 'graph boom' if @throws

      @nodes.include?(id) ? { 'id' => id } : nil
    end
  end

  def self.registry(rs)
    return nil if rs.nil?
    return Fixed.new(rs['fixed']) if rs['mode'] == 'fixed'
    return Throwing.new if rs['mode'] == 'throws'

    r = T::InMemoryTrustedInputRegistry.new
    (rs['records'] || []).each { |d, label| r.record(d, label) }
    r
  end

  def self.graph(gs) = gs.nil? || gs.empty? ? nil : Graph.new(gs['nodes'], gs['throws'])
  def self.ctx(c) = [registry(c['registry']), graph(c['graph'])]

  RECORDERS = { 'record' => :record, 'recordTrusted' => :record_trusted, 'recordFirstParty' => :record_first_party, 'recordTool' => :record_tool,
                'recordWeb' => :record_web }.freeze

  def self.registry_ops(ops)
    r = T::InMemoryTrustedInputRegistry.new
    ops.map do |op, *a|
      case op
      when 'lookup' then r.lookup(a[0])
      when 'size' then r.size
      when 'emptyLookup' then T::EMPTY_REGISTRY.lookup(a[0])
      else
        r.public_send(RECORDERS.fetch(op), *a)
        nil
      end
    end
  end

  HANDLERS = {
    'constants' => -> { { 'TAINT_LEVELS' => T::TAINT_LEVELS.to_a, 'BOTTOM' => T::BOTTOM, 'TOP' => T::TOP } },
    'isTaintLevel' => ->(k) { T.is_taint_level(k) },
    'labelRank' => ->(l) { T.label_rank(l) },
    'taintValue' => ->(l) { T.taint_value(l) },
    'joinLabel' => ->(a, b) { T.join_label(a, b) },
    'joinLabels' => ->(ls) { T.join_labels(ls) },
    'registry' => ->(ops) { registry_ops(ops) },
    'classifyRef' => ->(ref, c) { T.classify_ref(ref, *ctx(c)) },
    'computeTaint' => ->(p, c) { T.compute_taint(p, *ctx(c)) }
  }.freeze

  def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 2344, BY_FN.values.sum(&:length)
    assert_equal 150, BY_FN.values.flatten.count { |c| Ref.throws?(c['out']) }
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      assert_equal TOTALS.fetch(fn), Ref.run(self, BY_FN.fetch(fn), handler)
    end
  end
end
