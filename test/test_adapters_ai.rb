# frozen_string_literal: true

# The AI tool-call adapters (adapters.rb, openai.rb, anthropic.rb): bridge, dispatch, refusal and provenance recording.
require_relative '../lib/atlas_pca'
require_relative '../lib/atlas_pca/openai'
require_relative '../lib/atlas_pca/anthropic'
require 'minitest/autorun'

class TestAdaptersAi < Minitest::Test
  A = AtlasPca::Adapters

  def agent
    principal = AtlasPca::KeyPair.generate
    key = AtlasPca::KeyPair.generate
    env = { 'predicates' => [{ 'verb' => 'refund', 'resource' => 'orders/*' }], 'caveats' => [], 'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
    grant = AtlasPca.mint_grant(principal, key.public, env, 'refund an order')['grant']
    AtlasPca::Agent.new(key, grant, 'rs-test')
  end

  MAP = ->(c) { c['name'] == 'refund' ? { verb: 'refund', resource: "orders/#{c['arguments']['id']}" } : nil }

  def test_bridge_signs_and_declines
    ag = agent
    pca = A.bridge_tool_call(ag, { 'name' => 'refund', 'arguments' => { 'id' => 7 } }, MAP)
    assert_equal AtlasPca.decode_pca_header(pca.headers['PCA-Action']), pca.encoded
    assert_nil A.bridge_tool_call(ag, { 'name' => 'other', 'arguments' => {} }, MAP)
  end

  def test_openai_dispatch
    ag = agent
    call = { 'id' => 'c1', 'function' => { 'name' => 'refund', 'arguments' => '{"id":3}' } }
    msg = AtlasPca::OpenAI.dispatch_tool_call(ag, call, MAP, { 'refund' => ->(args, _pca) { { 'ok' => args['id'] } } })
    assert_equal({ 'role' => 'tool', 'tool_call_id' => 'c1', 'content' => '{"ok":3}' }, msg)
    assert_raises(ArgumentError) do
      AtlasPca::OpenAI.dispatch_tool_call(ag, { 'id' => 'c2', 'function' => { 'name' => 'x', 'arguments' => '' } }, MAP, {})
    end
    assert_raises(ArgumentError) do
      AtlasPca::OpenAI.dispatch_tool_call(ag, { 'id' => 'c3', 'function' => { 'name' => 'refund', 'arguments' => '[1]' } }, MAP, {})
    end
  end

  def test_anthropic_errors_not_silent
    ag = agent
    m = ->(b) { b['name'] == 'refund' ? { verb: 'refund', resource: 'orders/1' } : nil }
    declined = AtlasPca::Anthropic.handle_tool_use(ag, { 'type' => 'tool_use', 'id' => 't1', 'name' => 'nope', 'input' => {} }, m, {})
    assert_equal true, declined['is_error']
    raised = AtlasPca::Anthropic.handle_tool_use(ag, { 'type' => 'tool_use', 'id' => 't2', 'name' => 'refund', 'input' => {} }, m,
                                                 { 'refund' => ->(_i, _p) { raise 'boom' } })
    assert_equal ['boom', true], [raised['content'], raised['is_error']]
  end

  def test_guard_fail_fast_denies_out_of_grant_action
    ag = agent
    ran = false
    g = A.guard(ag, 'delete', 'orders/1', ->(_p, _c) { ran = true })
    assert_raises(A::PcaDenied) { g.call({}) }
    refute ran
  end

  def test_message_segments_roles
    assert_equal [], A.message_segments({ 'role' => 'assistant', 'content' => 'x' })
    assert_equal 'principal', A.message_segments({ 'role' => 'user', 'content' => 'hi' }).first['origin']
    assert_equal 'tool', A.message_segments({ 'role' => 'tool', 'content' => 'out' }).first['origin']
    segs = A.message_segments({ 'role' => 'user', 'content' => [{ 'type' => 'tool_result', 'content' => 'r' }, { 'type' => 'text', 'text' => 'a' }] })
    assert_equal %w[principal tool], segs.map { |s| s['origin'] }
  end
end

require_relative '../lib/atlas_pca/langchain'

class TestLangchainAdapter < Minitest::Test
  def agent
    principal = AtlasPca::KeyPair.generate
    key = AtlasPca::KeyPair.generate
    env = { 'predicates' => [{ 'verb' => 'refund', 'resource' => 'orders/*' }], 'caveats' => [], 'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
    AtlasPca::Agent.new(key, AtlasPca.mint_grant(principal, key.public, env, 'refund an order')['grant'], 'rs-test')
  end

  class Tool
    def execute(id:) = "refunded #{id}"
  end

  def test_guards_a_named_method_and_refuses_positional_calls
    seen = []
    t = AtlasPca::Langchain.with_pca(agent, 'refund', ->(p) { "orders/#{p['id']}" }, Tool.new, on_proof: ->(pca, _a) { seen << pca.encoded })
    assert_equal 'refunded 4', t.execute(id: 4)
    assert_equal 1, seen.length
    assert_raises(TypeError) { t.execute(4) }
  end

  def test_denied_action_never_runs
    ran = false
    g = AtlasPca::Langchain.with_pca(agent, 'delete', 'orders/1', ->(**_k) { ran = true })
    assert_raises(AtlasPca::Adapters::PcaDenied) { g.call }
    refute ran
  end
end
