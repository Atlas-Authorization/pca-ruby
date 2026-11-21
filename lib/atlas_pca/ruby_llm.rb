# frozen_string_literal: true

require 'delegate'
require_relative 'adapters'

# RubyLLM adapter (the ruby_llm gem, RubyLLM::Tool): wrap a tool so every call a model makes first builds a PCActn, then runs the original.
# The wrapper delegates every member (name, description, parameters ...) to the tool and guards the one entry RubyLLM calls,
# `call(tool_call: nil, **arguments)`: the keyword arguments are the action's params. The ruby_llm gem is never required here. Does not
# authorize: it attaches the proof and, with fail_fast (default), refuses a call outside the grant before the tool runs; the resource
# server's verifier decides.
module AtlasPca
  module RubyLlm
    A = Adapters

    # The tool with a guarded #call. `resource` is a String or a callable (params) -> String; on_proof.call(pca, params) receives the proof.
    class GuardedTool < SimpleDelegator
      def initialize(tool, agent, verb, resource, on_proof, fail_fast)
        super(tool)
        @agent = agent
        @verb = verb
        @resource = resource
        @on_proof = on_proof
        @fail_fast = fail_fast
      end

      def call(tool_call: nil, **arguments)
        run = ->(params, pca) do # a literal ->: SimpleDelegator forwards the `lambda` method and Ruby 3.3+ refuses it
          @on_proof&.call(pca, params)
          kw = params.transform_keys(&:to_sym)
          kw = kw.merge(tool_call: tool_call) unless tool_call.nil?
          __getobj__.call(**kw)
        end
        A.guard(@agent, @verb, @resource, run, fail_fast: @fail_fast).call(A.plain(arguments))
      end
    end

    module_function

    def with_pca(agent, verb, resource, tool, on_proof: nil, fail_fast: true)
      raise TypeError, 'with_pca: the wrapped tool has no #call' unless tool.respond_to?(:call)

      GuardedTool.new(tool, agent, verb, resource, on_proof, fail_fast)
    end
  end
end
