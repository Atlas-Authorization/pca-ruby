# frozen_string_literal: true

# LlamaIndex adapter: wrap a tool so every `call` / `acall` builds a PCActn first (the TypeScript reference, @atlasauth/pca-llamaindex).
# Duck-typed (no LlamaIndex gem is required): the copy keeps `metadata` and every other attribute. `call` / `acall` are invoked with keyword
# arguments, which become the action's params. Does not authorize; the resource server's verifier decides.
require_relative 'adapters'
require_relative 'langchain'

module AtlasPca
  module Llamaindex
    module_function

    A = Adapters

    # A copy of `tool` whose `call` (and `acall`, when present) fast-fails with PcaDenied on a failing dry run, hands the proof to
    # on_proof.call(pca, args) and then runs the original. A tool with neither raises TypeError.
    def with_pca(agent, verb, resource, tool, on_proof: nil, fail_fast: true)
      wrapped = %i[call acall].select { |m| tool.respond_to?(m) }
      raise TypeError, 'with_pca: the wrapped tool exposes neither call() nor acall()' if wrapped.empty?

      copy = tool.dup
      wrapped.each do |m|
        guarded = Langchain.guard_kwargs(agent, verb, resource, tool.method(m), on_proof: on_proof, fail_fast: fail_fast)
        copy.define_singleton_method(m) { |*args, **kwargs| guarded.call(*args, **kwargs) }
      end
      copy
    end

    # Wrap a chat / query engine or agent so every `chat` / `query` (and `achat` / `aquery`) first records the principal's request (the
    # first argument, or `message:` / `query:` ...; `chat_history` user turns are the principal, tool turns untrusted).
    def with_pca_engine(agent, engine, methods: %i[chat query achat aquery])
      copy = engine.dup
      methods.each do |m|
        next unless engine.respond_to?(m)

        orig = engine.method(m)
        copy.define_singleton_method(m) do |*args, **kwargs, &blk|
          hist = kwargs.key?(:chat_history) ? kwargs[:chat_history] : kwargs[:chatHistory]
          A.record_messages(agent, hist) if hist.is_a?(Array)
          A.record_input(agent, args.empty? ? kwargs : args[0])
          orig.call(*args, **kwargs, &blk)
        end
      end
      copy
    end
  end
end
