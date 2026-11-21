# frozen_string_literal: true

# `import -> suggest` as one call, the text forms the CLI prints and reads (JSON Lines of defs), and the importer registry (native port of
# the pipeline and registry of the TypeScript reference @atlasauth/pca-actions). Pure: no file system, no network. The YAML a
# `defsToYaml` writes needs a YAML emitter; none ships without a dependency, so it is not ported.
require_relative 'actions_import_common'
require_relative 'actions_import_openapi'
require_relative 'actions_import_mcp'
require_relative 'actions_import_graphql'
require_relative 'actions_import_grpc'
require_relative 'actions_import_asyncapi'
require_relative 'actions_import_jsonschema'
require_relative 'actions_import_suggest'
require_relative 'actions_import_model'

module AtlasPca
  module ActionsImportPipeline
    C = AtlasPca::ActionsImportCommon
    S = AtlasPca::ActionsImportSuggest
    M = AtlasPca::ActionsImportModel
    A = C::A
    U16 = C::U16
    Err = C::Err

    MAX_IMPORT_OPS = 20_000

    module_function

    # Import one source of the given kind. Every def is `unreviewed`.
    def import_actions(kind, source, opts = nil)
      case kind
      when 'openapi' then AtlasPca::ActionsImportOpenapi.import_openapi(source, opts)
      when 'mcp' then AtlasPca::ActionsImportMcp.import_mcp(source, opts)
      when 'graphql' then AtlasPca::ActionsImportGraphql.import_graphql(source, opts)
      when 'grpc' then AtlasPca::ActionsImportGrpc.import_grpc(source, opts)
      when 'asyncapi' then AtlasPca::ActionsImportAsyncapi.import_asyncapi(source, opts)
      when 'jsonschema' then AtlasPca::ActionsImportJsonschema.import_json_schema(source, opts)
      else raise Err.new('bad_kind', "unknown import kind '#{AtlasPca::V2JS.js_str(kind)}' (one of #{C::IMPORT_KINDS.join(', ')})")
      end
    end

    # Suggest for already imported defs: new defs (state `suggested`) and the model errors, if any. `o`: mode ("rules" default, "model",
    # "none"), rules, registry, models (adapter objects).
    def suggest_defs(defs, o = nil)
      o = {} if S.pyfalsy?(o)
      mode = S.pyfalsy?(o['mode']) ? 'rules' : o['mode']
      return { 'defs' => defs.dup, 'errors' => [] } if mode == 'none'

      registry = S.pyfalsy?(o['registry']) ? A::CORE_REGISTRY : o['registry']
      rules = S.pyfalsy?(o['rules']) ? S.default_rules : o['rules']
      digest = S.rules_digest(rules)
      out = []
      errors = []
      defs.each do |d|
        s = S.suggest_with_rules(d, rules, registry)
        models = nil
        if mode == 'model'
          run = M.suggest_with_models(d, S.pyfalsy?(o['models']) ? [] : o['models'], registry)
          run['errors'].each { |e| errors << { 'verb' => d['verb'] }.merge(e) }
          s = { 'traits' => S.u16sort(s['traits'] | run['suggestion']['traits']), 'roles' => s['roles'], 'tags' => s['tags'], 'fired' => s['fired'] }
          models = run['models']
        end
        by = { 'rules' => { 'version' => rules['version'], 'digest' => digest, 'fired' => s['fired'] } }
        by['models'] = models unless S.pyfalsy?(models)
        out << S.apply_suggestion(d, s, by)
      end
      { 'defs' => out, 'errors' => errors }
    end

    def import_and_suggest(kind, source, opts, suggest = nil)
      r = import_actions(kind, source, opts)
      s = suggest_defs(r['defs'], suggest)
      r.merge('defs' => s['defs'], 'suggestErrors' => s['errors'])
    end

    # ---- JSON Lines
    # One def per line, strict canonical JSON, sorted by verb: byte-reproducible.
    def defs_to_jsonl(defs)
      sorted = defs.each_with_index.sort_by { |d, i| [U16.units(d['verb']), i] }.map(&:first)
      sorted.map { |d| AtlasPca.canonicalize(d) }.join("\n") + (defs.empty? ? '' : "\n")
    end

    # Parse and validate a JSONL file of defs. Raises ActionKitError('bad_defs') naming the first bad line.
    def jsonl_to_defs(text)
      out = []
      U16.to_pua(text).split("\n", -1).each_with_index do |line, i|
        l = U16.from_pua(line.gsub(C::WS_EDGE, ''))
        next if l.empty?

        begin
          v = AtlasPca::Js.parse(l)
        rescue StandardError
          raise Err.new('bad_defs', "line #{i + 1}: not JSON")
        end
        bad = A.validate_def(v)
        raise Err.new('bad_defs', "line #{i + 1}: #{bad}") unless bad.nil?

        out << v
      end
      out
    end

    # ---- importer registry (the shape the CLI reads)
    # `IMPORTERS[kind](document, {ns, uri?, licence?, verb?})` -> {defs, todo: ["<where>: <message>"]}. Unknown kind: KeyError.
    def run_importer(kind, doc, opts)
      raise KeyError, kind.to_s unless C::IMPORT_KINDS.include?(kind)
      raise ArgumentError, 'a JSON Schema import needs --verb <ns.noun.action>' if kind == 'jsonschema' && S.pyfalsy?(opts['verb'])

      r = import_actions(kind, doc, opts)
      { 'defs' => r['defs'], 'todo' => r['todo'].map { |t| "#{t['where']}: #{t['message']}" } }
    end
  end
end
