# frozen_string_literal: true

# The LlamaIndex adapter (llamaindex.rb): tool guarding and engine input recording (duck-typed stand-ins, no LlamaIndex gem).
require_relative '../lib/atlas_pca'
require_relative '../lib/atlas_pca/llamaindex'
require 'minitest/autorun'

class TestLlamaindexAdapter < Minitest::Test
  def agent
    principal = AtlasPca::KeyPair.generate
    key = AtlasPca::KeyPair.generate
    env = { 'predicates' => [{ 'verb' => 'refund', 'resource' => 'orders/*' }], 'caveats' => [], 'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
    AtlasPca::Agent.new(key, AtlasPca.mint_grant(principal, key.public, env, 'refund an order')['grant'], 'rs-test')
  end

  class Tool
    attr_reader :metadata

    def initialize = @metadata = { 'name' => 'refund' }
    def call(id:) = "refunded #{id}"
  end

  class Engine
    attr_reader :seen

    def initialize = @seen = []
    def query(text, **_opts) = (@seen << text) && "answer: #{text}"
  end

  def test_guards_call_keeps_metadata_and_refuses_positional_calls
    proofs = []
    t = AtlasPca::Llamaindex.with_pca(agent, 'refund', ->(p) { "orders/#{p['id']}" }, Tool.new, on_proof: ->(pca, _a) { proofs << pca.encoded })
    assert_equal 'refunded 4', t.call(id: 4)
    assert_equal 1, proofs.length
    assert_equal({ 'name' => 'refund' }, t.metadata)
    assert_raises(TypeError) { t.call(4) }
  end

  def test_a_tool_without_call_is_refused
    assert_raises(TypeError) { AtlasPca::Llamaindex.with_pca(agent, 'refund', 'orders/1', Object.new) }
  end

  def test_engine_records_the_principal_request_then_runs
    e = AtlasPca::Llamaindex.with_pca_engine(agent, Engine.new)
    assert_equal 'answer: refund order 4', e.query('refund order 4')
  end
end
