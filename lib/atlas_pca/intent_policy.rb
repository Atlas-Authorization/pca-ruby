# frozen_string_literal: true

require_relative 'intent_v2'

# Policy plumbing for the intent layer: an outcome as the analyzer's concrete action, and the real evaluator as an admission
# oracle. Native port of the TypeScript reference (@atlasauth/pca-intent).
module AtlasPca
  module IntentPolicy
    ANY_RESOURCE = 'resource:any'

    # A compiled admission oracle for one policy (compile once, query many times).
    class Admitter
      def initialize(policy)
        IntentPolicy.require_analyzer
        @model = AtlasPca::Analyzer.to_model(policy)
      end

      def admits(vs, o) = AtlasPca::Analyzer.admits_action(@model, IntentPolicy.outcome_to_action(vs, o))
      alias admits? admits
    end

    module_function

    # The analyzer ports are a separate module; fail closed with a clear error until it is present.
    def require_analyzer
      require_relative 'analyzer_core'
    rescue LoadError
      raise NotImplementedError, 'intent policy admission needs the analyzer core (analyzer_core.rb)'
    end

    # {predicates, caveats}: a non-array member counts as empty.
    def normalize_policy(p)
      preds = p.is_a?(Hash) ? p['predicates'] : nil
      cavs = p.is_a?(Hash) ? p['caveats'] : nil
      { 'predicates' => preds.is_a?(Array) ? preds : [], 'caveats' => cavs.is_a?(Array) ? cavs : [] }
    end

    def set_path(root, segs, value)
      cur = root
      segs[0...-1].each do |k|
        cur[k] = {} unless cur[k].is_a?(Hash)
        cur = cur[k]
      end
      cur[segs[-1]] = value
    end

    # The outcome as the analyzer's concrete action (params / env / subject trees, reversibility from the verb space).
    def outcome_to_action(vs, o)
      params = {}
      env = {}
      subject = {}
      resource = ANY_RESOURCE
      (o['values'] || {}).each do |path, value|
        segs = path.split('.', -1)
        if path == 'action.resource'
          resource = V2JS.js_str(value)
        elsif segs[0] == 'action' && segs.length > 2 && segs[1] == 'params'
          set_path(params, segs[2..], value)
        elsif segs[0] == 'env' && segs.length > 1
          set_path(env, segs[1..], value)
        elsif segs[0] == 'subject' && segs.length > 1
          set_path(subject, segs[1..], value)
        end
      end
      a = { 'verb' => o['verb'], 'resource' => resource, 'params' => params, 'reversibilityClass' => vs['reversibility'] }
      a['env'] = env unless env.empty?
      a['subject'] = subject unless subject.empty?
      a
    end

    def admitter(policy) = Admitter.new(policy)

    def vs_of(omega, o) = omega['verbs'].find { |v| v['verb'] == o['verb'] }
  end
end
