# frozen_string_literal: true

module AtlasPca
  # The parts of the action-schema surface the reference exports under their own names: the vocabulary and limit constants (with the source text of
  # the three patterns), the value-dependent reversibility class, and the wallet-floor test, with the reference's value semantics (own-property
  # lookups only; a value of the wrong JSON type behaves as the reference's `includes` / `startsWith` do). The signing, verification, digest, shape and
  # drafting functions live next to their kin (`AtlasPca.sign_action_schema`, `IntentV2.verify_action_schema`, `Mcp.draft_schema_from_open_api`, ...).
  module ActionSchemaApi
    UNDEF = IntentV2::UNDEF
    WELL_KNOWN_PCA_ACTIONS_PATH = '/.well-known/pca-actions.json'
    PARAM_PATH_RE_SOURCE = '^action\.params\.[A-Za-z0-9_]{1,64}$'
    PARAM_PATH_RE_V2_SOURCE = '^action\.params\.[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}$'
    UNIT_ID_RE_SOURCE = '^[a-z0-9_]+(?:\.[a-z0-9_]+)*$'
    PARAM_PREFIX = 'action.params.'

    module_function

    def pm(h, k) = h.is_a?(Hash) && h.key?(k) ? h[k] : UNDEF
    def nullish?(x) = x.nil? || UNDEF.equal?(x)

    # every exported constant of the module, regexes as {"$regex" => source}
    def constants_view
      i = IntentV2
      { 'ACTION_SCHEMA_DOMAIN' => i::ACTION_SCHEMA_DOMAIN, 'ACTION_SCHEMA_REF_DOMAIN' => i::ACTION_SCHEMA_REF_DOMAIN, 'ACTION_SCHEMA_KIND' => i::ACTION_SCHEMA_KIND,
        'WELL_KNOWN_PCA_ACTIONS_PATH' => WELL_KNOWN_PCA_ACTIONS_PATH, 'SENSITIVITIES' => i::SENSITIVITIES, 'SCHEMA_REVERSIBILITY' => i::SCHEMA_REVERSIBILITY,
        'PARAM_TYPES' => i::PARAM_TYPES, 'PARAM_TYPES_V2' => i::PARAM_TYPES_V2, 'SCHEMA_V2_EFFECTS' => i::SCHEMA_V2_EFFECTS, 'SCHEMA_V2_CAVEATS' => i::SCHEMA_V2_CAVEATS,
        'SCHEMA_V2_PRULES' => i::SCHEMA_V2_PRULES, 'SCHEMA_V2_CONTEXT' => i::SCHEMA_V2_CONTEXT, 'SCHEMA_V2_TAGS' => i::SCHEMA_V2_TAGS,
        'SCHEMA_V2_PROVENANCE' => i::SCHEMA_V2_PROVENANCE, 'MAX_SCHEMA_VERBS' => i::MAX_SCHEMA_VERBS, 'MAX_SCHEMA_PARAMS' => i::MAX_SCHEMA_PARAMS,
        'MAX_SCHEMA_VALUES' => i::MAX_SCHEMA_VALUES, 'DEFAULT_MAX_LEN' => i::DEFAULT_MAX_LEN, 'DEFAULT_MAX_ITEMS' => i::DEFAULT_MAX_ITEMS,
        'PARAM_PATH_RE' => { '$regex' => PARAM_PATH_RE_SOURCE }, 'PARAM_PATH_RE_V2' => { '$regex' => PARAM_PATH_RE_V2_SOURCE },
        'UNIT_ID_RE' => { '$regex' => UNIT_ID_RE_SOURCE }, 'WALLET_FLOOR_PREFIXES' => IntentSchema::WALLET_FLOOR_PREFIXES, 'WALLET_FLOOR_EXACT' => IntentSchema::WALLET_FLOOR_EXACT }
    end

    # the lookup key of a parameter value in a reversibility map: a string, a boolean or a safe integer (negative zero excluded), else nil
    def key_of_value(x)
      return x if x.is_a?(String)
      return x.to_s if x == true || x == false
      return Attestation.jstr(x) if Attestation.safe_int?(x) && !(x.is_a?(Float) && x.zero? && (1.0 / x).negative?)

      nil
    end

    # The value-dependent reversibility class: the mapped class of the parameter's value (an unmapped or absent value is the `default`, else
    # irreversible, fail closed), else the declared class, else read -> reversible and anything else irreversible.
    def reversibility_of(verb_decl, params)
      rb = pm(verb_decl, 'reversibility_by')
      if Attestation.truthy?(rb)
        param = pm(rb, 'param')
        raise TypeError, 'v.reversibility_by.param.slice is not a function' unless param.is_a?(String)

        name = param.length >= PARAM_PREFIX.length ? param[PARAM_PREFIX.length..] : ''
        k = params.is_a?(Hash) && params.key?(name) ? key_of_value(params[name]) : nil
        map = pm(rb, 'map')
        return map[k] if !k.nil? && map.is_a?(Hash) && map.key?(k)

        d = pm(rb, 'default')
        return nullish?(d) ? 'irreversible' : d
      end
      r = pm(verb_decl, 'reversibility')
      return r unless nullish?(r)

      pm(verb_decl, 'kind') == 'read' ? 'reversible' : 'irreversible'
    end

    # Whether the wallet floor covers a semantic type: an exact member of floor.exact, or a prefix of floor.prefixes (the defaults when absent).
    def floor_applies(semantic, floor = nil)
      f = nullish?(floor) ? {} : floor
      pre = pm(f, 'prefixes')
      pre = IntentSchema::WALLET_FLOOR_PREFIXES if nullish?(pre)
      ex = pm(f, 'exact')
      ex = IntentSchema::WALLET_FLOOR_EXACT if nullish?(ex)
      return true if PassportApi.js_includes(ex, semantic)

      raise TypeError, 'pre.some is not a function' unless pre.is_a?(Array)
      raise TypeError, 'semantic.startsWith is not a function' unless semantic.is_a?(String)

      pre.any? { |p| semantic.start_with?(Attestation.jstr(p)) }
    end
  end
end
