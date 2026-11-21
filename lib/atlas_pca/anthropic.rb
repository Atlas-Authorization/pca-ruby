# frozen_string_literal: true

# Anthropic adapter: turn a Claude tool_use block into a PCActn, run your handler with the proof and return the tool_result block.
# Duck-typed (Hashes or SDK objects: the real gem's blocks carry Symbol enums and Symbol-keyed input, read through Adapters.plain); the anthropic gem is never required. A declined mapping, a missing handler and a raising
# handler all give an is_error tool_result, never a silent run. Does not authorize (the TypeScript reference, @atlasauth/pca-anthropic).
require_relative 'adapters'

module AtlasPca
  module Anthropic
    module_function

    A = Adapters

    def error_result(id, content) = { 'type' => 'tool_result', 'tool_use_id' => id, 'content' => content, 'is_error' => true }

    def handle_tool_use(agent, block, mapping, handlers)
      name = A.get(block, 'name')
      input = A.plain(A.get(block, 'input'))
      id = A.get(block, 'id')
      pca = A.bridge_tool_call(agent, { 'name' => name, 'arguments' => input },
                               ->(b) { mapping.call({ 'name' => b['name'], 'input' => b['arguments'] }) })
      return error_result(id, %(No proof-carrying authority is mapped for tool "#{name}".)) if pca.nil?

      handler = handlers[name]
      return error_result(id, %(No handler registered for tool "#{name}".)) if handler.nil?

      begin
        result = handler.call(input, pca)
        content = Js.json(result.nil? ? { 'pca' => pca.encoded } : result)
        A.record_tool_result(agent, name, content) # re-enters Claude's context: untrusted from here on
        { 'type' => 'tool_result', 'tool_use_id' => id, 'content' => content }
      rescue StandardError => e
        A.record_tool_result(agent, name, e.message)
        error_result(id, e.message)
      end
    end

    def handle_tool_uses(agent, blocks, mapping, handlers)
      blocks.select { |b| A.get(b, 'type').to_s == 'tool_use' }.map { |b| handle_tool_use(agent, b, mapping, handlers) }
    end

    # The tool_use blocks of an assistant message's content array (other blocks ignored).
    def extract_tool_uses(content) = content.select { |b| A.get(b, 'type').to_s == 'tool_use' }

    # Wrap `client.messages.create` (or any callable taking messages:) so every model turn first records the conversation's new
    # messages (user text is the principal; tool_result blocks are untrusted).
    def with_pca_messages(agent, create)
      lambda do |*args, **kw, &blk|
        msgs = kw[:messages] || kw['messages'] || (args[0].is_a?(Hash) ? A.get(args[0], 'messages') : nil)
        A.record_messages(agent, msgs)
        create.call(*args, **kw, &blk)
      end
    end
  end
end
