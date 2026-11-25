# frozen_string_literal: true

# OpenAI adapter: turn a chat tool_call into a PCActn, run your handler with the proof, return the `tool` message. Duck-typed: tool
# calls may be Hashes or SDK objects (#id, #function.name, #function.arguments); the openai gem is never required. Does not
# authorize; the resource server's verifier decides (the TypeScript reference, @atlasauth/pca-openai).
require 'json'
require_relative 'adapters'

module AtlasPca
  module OpenAI
    module_function

    A = Adapters

    def parse_arguments(raw)
      return {} if raw.nil? || (raw.is_a?(String) && raw.strip.empty?)

      parsed = raw.is_a?(String) ? AtlasPca.parse_json(raw.strip, any_top: true) : A.plain(raw)
      raise ArgumentError, 'dispatchToolCall: tool_call arguments must be a JSON object' unless parsed.is_a?(Hash)

      parsed
    end

    # Build + sign a PCActn for one tool call, run handlers[name].call(args, pca) and return the `tool` message. Raises
    # ArgumentError when mapping declines the tool: no tool runs without a proof.
    def dispatch_tool_call(agent, call, mapping, handlers)
      fn = A.get(call, 'function')
      name = A.get(fn, 'name')
      args = parse_arguments(A.get(fn, 'arguments'))
      pca = A.bridge_tool_call(agent, { 'name' => name, 'arguments' => args }, mapping)
      raise ArgumentError, %(dispatchToolCall: no PCActn for unmapped tool "#{name}" (the mapping declined)) if pca.nil?

      handler = handlers[name]
      result = handler&.call(args, pca)
      content = Js.json(result.nil? ? { 'pca' => pca.encoded } : result)
      A.record_tool_result(agent, name, content) # the tool message re-enters the model's context: untrusted from here on
      { 'role' => 'tool', 'tool_call_id' => A.get(call, 'id'), 'content' => content }
    end

    # A model turn's tool calls, sequentially (each PCActn takes the next counter).
    def dispatch_tool_calls(agent, calls, mapping, handlers)
      calls.map { |c| dispatch_tool_call(agent, c, mapping, handlers) }
    end

    # Wrap `client.chat.completions.create` (or any callable taking messages:) so every model turn first records the
    # conversation's new messages (user turns are the principal, tool turns untrusted).
    def with_pca_completions(agent, create)
      lambda do |*args, **kw, &blk|
        msgs = kw[:messages] || kw['messages'] || (args[0].is_a?(Hash) ? A.get(args[0], 'messages') : nil)
        A.record_messages(agent, msgs)
        create.call(*args, **kw, &blk)
      end
    end
  end
end
