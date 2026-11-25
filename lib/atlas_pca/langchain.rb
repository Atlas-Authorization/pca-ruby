# frozen_string_literal: true

# LangChain.rb adapter: wrap a tool so every call builds a PCActn first (the TypeScript reference, @atlasauth/pca-langchain).
# Duck-typed (langchainrb is never required): a tool is a callable or an object whose named method (e.g. langchainrb's tool
# functions) is called with keyword arguments. A call whose params cannot be bound (positional arguments) is never signed. Does not
# authorize; the resource server's verifier decides.
require_relative 'adapters'

module AtlasPca
  module Langchain
    module_function

    A = Adapters

    # A guarded callable taking keyword arguments: fails fast with PcaDenied on a failing dry run, hands the proof to
    # on_proof.call(pca, args) and then runs fn.call(**args).
    def guard_kwargs(agent, verb, resource, fn, on_proof: nil, fail_fast: true)
      run = lambda do |params, pca|
        on_proof&.call(pca, params)
        fn.call(**params.transform_keys(&:to_sym))
      end
      g = A.guard(agent, verb, resource, run, fail_fast: fail_fast)
      lambda do |*args, **kwargs|
        raise TypeError, 'a PCA-guarded tool takes keyword arguments only' unless args.empty?

        g.call(kwargs.transform_keys(&:to_s))
      end
    end

    # A copy of tool whose method `name` (default :execute) is guarded; anything else keeps its shape. A callable is wrapped directly.
    def with_pca(agent, verb, resource, tool, method: :execute, on_proof: nil, fail_fast: true)
      if tool.respond_to?(:call) && !tool.respond_to?(method)
        return guard_kwargs(agent, verb, resource, tool, on_proof: on_proof, fail_fast: fail_fast)
      end
      raise TypeError, "with_pca: the wrapped tool exposes neither ##{method} nor #call" unless tool.respond_to?(method)

      bound = tool.method(method)
      guarded = guard_kwargs(agent, verb, resource, bound, on_proof: on_proof, fail_fast: fail_fast)
      tool.dup.tap { |copy| copy.define_singleton_method(method) { |*args, **kwargs| guarded.call(*args, **kwargs) } }
    end

    # Wrap an agent executor / graph so every call of the named methods (default :run, :invoke, :stream) first records the principal's
    # input (a string, {input:} or {messages:}: human turns are the principal, tool turns untrusted).
    def with_pca_agent(agent, runnable, methods: %i[run invoke stream])
      copy = runnable.dup
      methods.each do |m|
        next unless runnable.respond_to?(m)

        orig = runnable.method(m)
        copy.define_singleton_method(m) do |input = nil, *rest, **kw, &blk|
          A.record_input(agent, input)
          orig.call(input, *rest, **kw, &blk)
        end
      end
      copy
    end
  end
end
