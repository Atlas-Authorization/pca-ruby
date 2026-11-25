# frozen_string_literal: true

# The built-in connector defs, the domain-vocabulary defs and bindings, and how the built-ins become confirmed (native port of
# builtin.ts, builtin-review.ts and domain.ts of the TypeScript reference @atlasauth/pca-actions). The data is generated from the
# reference (actions_builtin_data.rb). Without a release signing step the built-ins carry no attestation: unconfirmed, maximally dangerous.
require_relative 'actions'
require_relative 'actions_builtin_data'
require_relative 'actions_derive'
require_relative 'actions_review'

module AtlasPca
  module ActionsBuiltin
    A = AtlasPca::Actions
    DATA = AtlasPca::ActionsBuiltinData::DATA

    BUILTIN_DEFS = DATA['builtin']
    DOMAIN_DEFS = DATA['domain']
    LEGACY_CATALOG = DATA['legacyCatalog']
    LEGACY_ONTOLOGY_EFFECT = DATA['legacyOntologyEffect']
    RESOLUTIONS = DATA['resolutions']
    DOMAIN_VERBS = DATA['domainVerbs']
    CORE_PACK_DEFS = BUILTIN_DEFS + DOMAIN_DEFS

    # No pinned release reviewer key and no attestation until a release run signs the built-ins.
    BUILTIN_RELEASE = { 'pins' => nil, 'attestations' => {} }.freeze

    module_function

    # The release pins and registry the built-in attestations verify against ({'pins', 'registry'}); nil before the first release signing.
    def builtin_release_ctx(reg = nil) = BUILTIN_RELEASE['pins'].nil? ? nil : { 'pins' => BUILTIN_RELEASE['pins'], 'registry' => reg || A::CORE_REGISTRY }

    # The review options under which the released built-ins count as confirmed: a signature by the pinned release key, nothing else.
    # Returns {} before the first release signing, else {'attestation_verified' => ->(def) { bool }}.
    def builtin_review_opts(reg = nil)
      ctx = builtin_release_ctx(reg)
      ctx.nil? ? {} : { 'attestation_verified' => ActionsReview.attestation_verifier(ctx['registry'], ctx['pins']) }
    end

    # The built-in defs with their release attestation attached where the package carries one (others stay unconfirmed).
    def released_builtin_defs(defs = nil)
      (defs || BUILTIN_DEFS).map do |d|
        a = BUILTIN_RELEASE['attestations'][d['verb']]
        a.nil? ? d : d.merge('review' => d['review'].merge('state' => 'confirmed', 'attestation' => a))
      end
    end

    # Release step: sign every built-in def (confirm_def over each, final traits = its declared ones). The reviewer secret is the
    # caller's release key and is never stored.
    def sign_builtins(kid:, secret:, ts:, registry: nil, defs: nil)
      (defs || BUILTIN_DEFS).map do |d|
        ActionsReview.confirm_def(d, { 'registry' => registry || A::CORE_REGISTRY, 'reviewer' => { 'kid' => kid, 'secret' => secret },
                                       'final_traits' => A.sort_uniq(d['traits'] || []), 'ts' => ts })
      end
    end

    # The pinned release reviewer keys; nil before the first release signing (then pass pins=nil: nothing is confirmed).
    def builtin_reviewer_pins = BUILTIN_RELEASE['pins']

    # ---- domain.ts: the Goal IR domain vocabularies derived from the defs ----------------------------------------------

    def def_of(verb)
      CORE_PACK_DEFS.find { |x| x['verb'] == verb } || raise(ArgumentError, "domain binding names unknown def '#{verb}'")
    end

    # The `verbs` and `aliases` of a domain ontology, derived from the defs (effect class derived, never assigned).
    def domain_verbs(domain, reg = nil)
      reg ||= A::CORE_REGISTRY
      bindings = DOMAIN_VERBS.fetch(domain)
      onto = ActionsDerive.to_ontology(bindings.map { |b| def_of(b['verb']) }, reg)
      verbs = []
      aliases = {}
      bindings.each do |b|
        d = def_of(b['verb'])
        raise ArgumentError, "domain binding '#{b['id']}' is not an alias of '#{b['verb']}'" unless (d['aliases'] || []).include?(b['id'])

        ov = onto['verbs'].find { |v| v['id'] == b['verb'] }
        params = {}
        b['params'].each do |nl, dp|
          p = ov['params'][dp]
          raise ArgumentError, "domain binding '#{b['id']}' surfaces unknown parameter '#{dp}'" if p.nil?

          params[nl] = p['kind'] == 'money' && !b['ccys'].nil? ? { 'kind' => 'money', 'ccys' => b['ccys'].dup } : p
        end
        verbs << { 'id' => b['id'], 'effect' => ActionsDerive.effect_class(d), 'resource_type' => b['resourceType'], 'params' => params }
        (d['aliases'] || []).each { |a| aliases[a] = b['id'] if a != b['id'] }
      end
      { 'verbs' => verbs, 'aliases' => aliases }
    end

    # The role map of a domain verb for the selector layer: role -> NL parameter names carrying it.
    def domain_roles(domain)
      DOMAIN_VERBS.fetch(domain).to_h do |b|
        d = def_of(b['verb'])
        roles = {}
        b['params'].each do |nl, dp|
          pd = d['params'][dp]
          r = pd.nil? ? nil : pd['role']
          (roles[r] ||= []) << nl unless r.nil?
        end
        [b['id'], roles]
      end
    end
  end
end
