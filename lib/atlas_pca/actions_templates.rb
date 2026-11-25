# frozen_string_literal: true

# Starter packs a platform can begin from (native port of templates.ts of the TypeScript reference @atlasauth/pca-actions): typical actions
# of five business types in the authoring YAML form, with custom traits and business rules. Every action is an authored draft: a template
# never confirms anything. The data is generated from the reference (actions_templates_data.rb); the namespace is substituted into it.
# The YAML is returned as text.
require_relative 'actions'
require_relative 'actions_templates_data'

module AtlasPca
  module ActionsTemplates
    D = AtlasPca::ActionsTemplatesData
    NS_RE = /\A[a-z][a-z0-9_]{0,31}\z/

    module_function

    # The namespace is interpolated into YAML and trait ids: only a plain lowercase identifier, never the reserved `pca`.
    def check_ns(ns)
      raise AtlasPca::Actions::ActionKitError.new('bad_ns', 'ns must be a lowercase identifier (a-z, 0-9, _; up to 32 characters)') unless ns.is_a?(String) && NS_RE.match?(ns)
      raise AtlasPca::Actions::ActionKitError.new('bad_ns', "the namespace 'pca' is reserved for core traits") if ns == 'pca'

      ns
    end

    def sub(x, ns)
      case x
      when String then x.gsub(D::MARKER) { ns }
      when Array then x.map { |v| sub(v, ns) }
      when Hash then x.transform_values { |v| sub(v, ns) }
      else x
      end
    end

    class StarterTemplate
      attr_reader :id, :title, :description, :ns

      def initialize(raw)
        @id = raw['id']
        @title = raw['title']
        @description = raw['description']
        @ns = raw['ns']
        @traits = raw['traits']
        @yaml = raw['yaml']
      end

      # The pack's custom traits under namespace `ns` (ids `<ns>.<name>`).
      def traits(ns) = ActionsTemplates.sub(@traits, ActionsTemplates.check_ns(ns))

      # The authoring YAML under namespace `ns`, with `rules:` blocks and their examples.
      def yaml(ns) = @yaml.gsub(D::MARKER) { ActionsTemplates.check_ns(ns) }
    end

    STARTER_TEMPLATES = D::TEMPLATES.map { |t| StarterTemplate.new(t) }.freeze

    def starter_template(id) = STARTER_TEMPLATES.find { |t| t.id == id }
  end
end
