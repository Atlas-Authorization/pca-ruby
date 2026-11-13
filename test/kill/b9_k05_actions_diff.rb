# frozen_string_literal: true
# k05 the action kit (actions.rb) against pca-actions validate / idpattern / traits / normalize / digest / effective /
# confirmation: test-data/k05-actions.json.gz (tools/pca-audit/k05-oracles/actions-oracle.mts). A registry argument is the
# custom trait list (nil = the core registry); isConfirmed is def_confirmation_error(d, CORE, pins).nil?; effective is
# compared as {confirmed, traits, closure, floor, decl, eff}. cmp "code" (a JS TypeError tail) compares the `<code>:` prefix.
module MutationKill
  module K05Actions
    module_function

    def reg(custom) = custom.nil? ? AtlasPca::Actions::CORE_REGISTRY : AtlasPca::Actions.extend_registry(AtlasPca::Actions::CORE_REGISTRY, custom)

    FNS = {
      'validateDef' => ->(a, _) { AtlasPca::Actions.validate_def(a[0]) },
      'isRole' => ->(a, _) { AtlasPca::Actions.role?(a[0]) },
      'isFormat' => ->(a, _) { AtlasPca::Actions.format?(a[0]) },
      'isContextKey' => ->(a, _) { AtlasPca::Actions.context_key?(a[0]) },
      'paramNameError' => ->(a, _) { AtlasPca::Actions.param_name_error(a[0]) },
      'jsonProfileError' => ->(a, _) { AtlasPca::Actions.json_profile_error(a[0]) },
      'idPatternError' => ->(a, _) { AtlasPca::Actions.id_pattern_error(a[0]) },
      'profileError' => ->(a, _) { AtlasPca::Actions.profile_error(a[0]) },
      'registryError' => ->(a, _) { AtlasPca::Actions.registry_error(a[0], core: a[1] == true) },
      'closure' => ->(a, _) { AtlasPca::Actions.closure(reg(a[0]), a[1]) },
      'floorOf' => ->(a, _) { AtlasPca::Actions.floor_of(reg(a[0]), a[1]) },
      'topTraits' => ->(a, _) { AtlasPca::Actions.top_traits(reg(a[0])) },
      'traitsDigest' => ->(a, _) { AtlasPca::Actions.traits_digest(reg(a[0])) },
      'tablesDigest' => ->(_, _) { AtlasPca::Actions.tables_digest },
      'floorDecision' => ->(a, _) { AtlasPca::Actions.floor_decision(a[0], a[1], a[2]) },
      'worstReversibility' => ->(a, _) { AtlasPca::Actions.worst_reversibility(a[0], a[1]) },
      'sensitivityFloor' => ->(a, _) { AtlasPca::Actions.sensitivity_floor(a[0]) },
      'impliedFromFacts' => ->(a, _) { AtlasPca::Actions.implied_from_facts(a[0]['effects'], a[0]['params'], a[0]['scope'], a[0]['worstRev']) },
      'normalize' => ->(a, _) { AtlasPca::Actions.normalize(a[0]) },
      'defDigest' => ->(a, _) { AtlasPca::Actions.def_digest(a[0]) },
      'declProfile' => ->(a, _) { AtlasPca::Actions.decl_profile(a[0]) },
      'hintTraits' => ->(a, _) { AtlasPca::Actions.hint_traits(a[0]) },
      'effective' => ->(a, _) { AtlasPca::Actions.effective(a[0], AtlasPca::Actions::CORE_REGISTRY, a[1]) },
      'reviewerPinsError' => ->(a, _) { AtlasPca::Actions.reviewer_pins_error(a[0]) },
      'reviewMessage' => ->(a, _) { { '$bytes' => AtlasPca.b64e(AtlasPca::Actions.review_message(a[0])) } },
      'isConfirmed' => ->(a, _) { AtlasPca::Actions.def_confirmation_error(a[0], AtlasPca::Actions::CORE_REGISTRY, a[1]).nil? },
      'factsDigest' => ->(a, _) { AtlasPca::Actions.facts_digest(a[0]) },
      'schemaVerbFloorError' => ->(a, _) { AtlasPca::Actions.schema_verb_floor_error(a[0], AtlasPca::Actions::CORE_REGISTRY, a[1]) },
      'schemaFloorError' => ->(a, _) { AtlasPca::Actions.schema_floor_error(a[0], a[1]) },
      'packRoot' => ->(a, _) { AtlasPca::Actions.pack_root(a[0]) },
      'packProof' => ->(a, _) { AtlasPca::Actions.pack_proof(a[0], a[1]) }
    }.freeze
    SPEC = K05::Spec.new(file: 'k05-actions.json.gz', libs: %w[actions.rb], fns: FNS, cmp: { default: K05::PREFIX }, title: 'actions')
  end
  K05.register(K05Actions::SPEC, K05Actions::FNS.keys)
end
