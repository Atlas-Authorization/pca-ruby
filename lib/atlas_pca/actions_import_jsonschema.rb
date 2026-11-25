# frozen_string_literal: true

# One JSON Schema plus a caller-given verb to one def (native port of the JSON Schema importer of the TypeScript reference
# @atlasauth/pca-actions).
require_relative 'actions_import_common'

module AtlasPca
  module ActionsImportJsonschema
    C = AtlasPca::ActionsImportCommon
    A = C::A
    J = C::J

    module_function

    # `opts`: the common import options plus `verb` (required, `<ns>.<noun>.<action>`), `title`, `description`, `effects` (default ["update"]).
    def import_json_schema(schema, opts = nil)
      c = C.new_ctx('jsonschema', schema, opts)
      verb = opts['verb']
      unless verb.is_a?(String) && J.rx?(A::VERB_RE, verb) && verb.start_with?("#{opts['ns']}.")
        raise C::Err.new('bad_verb', "verb must be a valid verb in namespace '#{opts['ns']}'")
      end

      effects = opts['effects']
      effects = ['update'] if effects.nil?
      unless effects.is_a?(Array) && !effects.empty? && effects.all? { |e| e.is_a?(String) && A::EFFECTS.include?(e) }
        raise C::Err.new('bad_effects', 'effects must be 1+ known effects')
      end
      raise C::Err.new('bad_source', 'a JSON Schema must be an object') unless schema.is_a?(Hash)

      bud = C.new_budget(c)
      root = C.resolve_schema(schema, c, bud, verb)
      params = {}
      if root['type'] == 'object' || root['properties'].is_a?(Hash)
        C.flatten_object(root, c, bud, verb, params)
      else
        C.add_todo(c, verb, 'not_object', 'the schema is not an object schema: the def has no parameters')
      end
      title = opts['title']
      description = opts['description']
      C.emit_def(
        c, verb.split('.')[1..].join('_'), effects, 'one', params, {}, verb: verb,
        title: !title.nil? ? title : (root['title'].is_a?(String) ? root['title'] : nil),
        description: !description.nil? ? description : C.clip(root['description'], 600)
      )
      C.finish(c)
    end
  end
end
