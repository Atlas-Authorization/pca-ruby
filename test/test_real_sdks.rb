# frozen_string_literal: true

# The OpenAI and Anthropic adapters against the real vendor gems (openai, anthropic): real response objects (Symbol enums, model classes
# with accessors) must sign the same proofs as the JSON Hash equivalents. Skips when a gem is not installed; PCA_REAL_SDK_REQUIRED=1
# (the CI workflow) fails instead.
require_relative '../lib/atlas_pca'
require_relative '../lib/atlas_pca/openai'
require_relative '../lib/atlas_pca/anthropic'
require_relative '../lib/atlas_pca/ruby_llm'
require 'minitest/autorun'

class TestRealSdks < Minitest::Test
  A = AtlasPca::Adapters
  MAP = ->(c) { c['name'] == 'refund' ? { verb: 'refund', resource: "orders/#{c['arguments']['id']}" } : nil }

  def agent
    principal = AtlasPca::KeyPair.generate
    key = AtlasPca::KeyPair.generate
    env = { 'predicates' => [{ 'verb' => 'refund', 'resource' => 'orders/*' }], 'caveats' => [], 'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
    AtlasPca::Agent.new(key, AtlasPca.mint_grant(principal, key.public, env, 'refund an order')['grant'], 'rs-test')
  end

  def need(gem_name)
    require gem_name
  rescue LoadError
    flunk "the #{gem_name} gem is required" if ENV['PCA_REAL_SDK_REQUIRED'] == '1'
    skip "the #{gem_name} gem is not installed"
  end

  def test_openai_chat_completion_tool_call
    need 'openai'
    # the vendor's tool-call model itself (a Symbol enum, accessors), built directly: the gem's nested response coercion changes between releases
    call = OpenAI::Chat::ChatCompletionMessageFunctionToolCall.new(id: 'call_1', type: :function, function: { name: 'refund', arguments: '{"id":7}' })
    refute_kind_of Hash, call
    seen = []
    msg = AtlasPca::OpenAI.dispatch_tool_call(agent, call, MAP, { 'refund' => ->(args, pca) { seen << [args, pca.encoded]; { 'ok' => true } } })
    assert_equal 'tool', msg['role']
    assert_equal 'call_1', msg['tool_call_id']
    assert_equal [{ 'id' => 7 }], seen.map(&:first)
    assert_equal({ 'ok' => true }, JSON.parse(msg['content']))
    same = AtlasPca::OpenAI.dispatch_tool_call(agent, { 'id' => 'call_1', 'function' => { 'name' => 'refund', 'arguments' => '{"id":7}' } }, MAP, { 'refund' => ->(_a, _p) { {} } })
    assert_equal 'call_1', same['tool_call_id']
  end

  def test_anthropic_tool_use_block
    need 'anthropic'
    message = Anthropic::Models::Message.new(
      id: 'msg_1', model: 'claude-x', role: :assistant, stop_reason: :tool_use, stop_sequence: nil, type: :message,
      usage: { input_tokens: 1, output_tokens: 1 },
      content: [{ type: :text, text: 'refunding' }, { type: :tool_use, id: 'toolu_1', name: 'refund', input: { id: 7 } }]
    )
    blocks = AtlasPca::Anthropic.extract_tool_uses(message.content)
    assert_equal 1, blocks.length
    seen = []
    out = AtlasPca::Anthropic.handle_tool_uses(agent, blocks, ->(b) { b['name'] == 'refund' ? { verb: 'refund', resource: "orders/#{b['input']['id']}" } : nil },
                                               { 'refund' => ->(input, _pca) { seen << input; { 'ok' => true } } })
    assert_equal 1, out.length
    assert_equal 'toolu_1', out[0]['tool_use_id']
    refute out[0]['is_error'], out[0]['content']
    assert_equal [{ 'id' => 7 }], seen
  end

  def test_ruby_llm_tool
    need 'ruby_llm'
    tool_class = Class.new(RubyLLM::Tool) do
      description 'Refund an order'
      parameter :id, description: 'the order id'

      def name = 'refund'

      def execute(id:) = "refunded #{id}"
    end
    proofs = []
    guarded = AtlasPca::RubyLlm.with_pca(agent, 'refund', ->(p) { "orders/#{p['id']}" }, tool_class.new, on_proof: ->(pca, _p) { proofs << pca })
    assert_equal 'refund', guarded.name
    assert_equal 'refunded 7', guarded.call(id: 7)
    assert_equal 1, proofs.length
    outside = AtlasPca::RubyLlm.with_pca(agent, 'refund', 'users/1', tool_class.new)
    assert_raises(AtlasPca::Adapters::PcaDenied) { outside.call(id: 7) } # outside the grant: refused before the tool runs
  end
end
