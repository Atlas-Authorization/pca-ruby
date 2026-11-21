# frozen_string_literal: true

require 'json'
require_relative 'goal_ontologies_data'

module AtlasPca
  # The shipped intent ontologies and the selector catalog of each domain (the TypeScript reference is @atlasauth/pca-goal
  # `ontologies`). Derived reference data: they read the action definitions, so the port ships the reference output as data.
  module GoalOntologies
    NAMES = %w[calendar_travel code_repos data_access email payments].freeze

    module_function

    def data = (@data ||= JSON.parse(GoalOntologiesData::JSON_TEXT))

    # The intent ontology of a shipped domain (a fresh copy), or nil for an unknown name.
    def shipped_ontology(name)
      o = name.is_a?(String) ? data['ontologies'][name] : nil
      o.nil? ? nil : JSON.parse(JSON.generate(o))
    end

    # The selector catalog {known, verbs} of a shipped domain (a fresh copy), or nil for an unknown name.
    def shipped_catalog(name)
      c = name.is_a?(String) ? data['catalogs'][name] : nil
      c.nil? ? nil : JSON.parse(JSON.generate(c))
    end

    def all_ontologies = NAMES.to_h { |n| [n, shipped_ontology(n)] }
  end
end
