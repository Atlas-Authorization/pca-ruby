# frozen_string_literal: true

# Action kit (native port of the small deterministic core of packages/pca-actions): strict ActionDef parse, normalize and
# canonical digest, the trait registry and its closure/floor algebra, rule 22 (FloorDecision and the schema floor integrity
# check), the pack Merkle root and inclusion proof, and T(d)/eff(d). Integers and sets only; every function is pure.
#
# The shared vectors (packages/pca-conformance/vectors/actions) pin every output byte for byte. ActionSchema v2 parsing and
# the v2 parameter types/formats of conform_action live in intent_v2.rb (the schema module); this module does not grow it.

module AtlasPca
  module Actions
    class ActionKitError < StandardError
      attr_reader :code

      def initialize(code, message)
        super(message)
        @code = code
      end
    end

    ACTION_DEF_KIND = 'pca-action-def'
    DEF_DIGEST_DOMAIN = 'atlas-pca/action-def/v1'
    TRAITS_DIGEST_DOMAIN = 'atlas-pca/action-traits/v1'
    ROLES_DIGEST_DOMAIN = 'atlas-pca/action-roles/v1'
    PACK_DIGEST_DOMAIN = 'atlas-pca/action-pack/v1'

    MAX_VERB_BYTES = 128
    MAX_TITLE_BYTES = 120
    MAX_DESCRIPTION_BYTES = 1024
    MAX_DEF_PARAMS = 64
    MAX_DEF_ALIASES = 16
    MAX_DEF_TRAITS = 32
    MAX_DEF_CONTEXT = 16
    MAX_DEF_SIDE_EFFECTS = 16
    MAX_TRAIT_IMPLIES_DEPTH = 8
    MAX_REGISTRY_TRAITS = 512
    PPM_MAX = 1_000_000

    EFFECTS = %w[read create update delete send pay exec privilege export publish provision sign].freeze
    REVERSIBILITY = %w[reversible rate_limited irreversible].freeze
    REV_RANK = { 'reversible' => 0, 'rate_limited' => 1, 'irreversible' => 2 }.freeze
    BLAST_RADII = %w[one bounded tenant global].freeze
    BLAST_PPM = { 'one' => 50_000, 'bounded' => 300_000, 'tenant' => 700_000, 'global' => 1_000_000 }.freeze
    RESOURCE_SCOPES = %w[one set tenant global].freeze
    SCOPE_BLAST = { 'one' => 'one', 'set' => 'bounded', 'tenant' => 'tenant', 'global' => 'global' }.freeze
    PARAM_TYPES = %w[string integer boolean date datetime duration set array object_ref].freeze
    SENSITIVITY_RANK = { 'free' => 0, 'material' => 1, 'critical' => 2 }.freeze
    PROVENANCE_LEVELS = %w[first_party tool agent].freeze
    CORE_ROLES = %w[
      money.amount money.currency money.fee party.payee party.payer
      contact.email contact.phone contact.address person.name person.dob person.national_id
      credential.secret credential.token credential.key
      path.fs query.sql query.search code.source code.command url.target
      text.message text.public time.not_before time.not_after count.limit bytes.size
    ].freeze
    PARAM_TAGS = %w[pii phi pci secret credential free_text_outbound code path sql].freeze
    PARAM_FORMATS = %w[email url uri_https uuid iban phone_e164 cidr iso_country iso_currency semver sha256].freeze
    UNIT_KINDS = %w[money count bytes duration ratio].freeze
    CAVEAT_KINDS = %w[amount_cap count_cap window resource_scope recipient_scope approval_ref short_expiry rate_cap].freeze
    CONTEXT_KEYS = %w[approval_ref dry_run_first fresh_revocation idempotency revocable sandbox_attested].freeze
    PARAM_RULE_IDS = %w[array_bounded export_bounded id_not_wildcard money_amount_bounded money_has_currency
                        pay_has_idempotency recipient_param_declared secret_not_logged].freeze
    IDEMPOTENCY_MODES = %w[key_param natural none].freeze
    REVIEW_STATES = %w[authored unreviewed suggested confirmed].freeze
    BINDING_KINDS = %w[mcp openapi http graphql grpc asyncapi].freeze
    ID_CLASSES = %w[digits hex alnum slug uuid any_safe].freeze

    ID_ROLE_RE = /\Aid\.[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}\z/
    CUSTOM_ROLE_RE = /\Ax\.[a-z0-9_]+(?:\.[a-z0-9_]+){1,3}\z/
    ID_FORMAT_RE = /\Aid:[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}\z/
    TAINT_RE = /\Asession_taint_max:[a-z_]{1,16}\z/
    VERB_RE = /\A[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){1,5}\z/
    ALIAS_RE = /\A[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,5}\z/
    PARAM_NAME_RE = /\A[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}\z/
    PROVENANCE_TRAIT_RE = /\A[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+\z/
    TRAIT_ID_RE = /\A[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}\z/
    RESOURCE_TYPE_RE = /\A[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,4}\z/
    UNIT_ID_RE = /\A[a-z0-9_]+(?:\.[a-z0-9_]+)*\z/
    CCY_RE = /\A[A-Z]{3}\z/
    RESERVED = %w[__proto__ constructor prototype].freeze
    INT_ROLES = %w[money.amount money.fee count.limit bytes.size].freeze
    PARAM_KEYS = %w[type role required values min max max_len items min_items max_items format unit tags provenance_min
                    sensitivity accumulates default principal_neutral_default description].freeze
    DEF_KEYS = %w[v kind verb aliases title description effects resource params reversibility blast side_effects idempotency
                  context traits audience compensates bindings examples review source since].freeze

    module_function

    # ---- small helpers ---------------------------------------------------------------------------------------------

    def js = AtlasPca::V2JS
    def int?(v) = js.int?(v)
    def nonneg?(v) = js.nonneg?(v)
    def str?(v, max = 256) = js.ustr?(v) && !v.empty? && v.bytesize <= max
    def in?(x, options) = x.is_a?(String) && options.include?(x)
    def sort_uniq(xs) = (xs || []).uniq.sort_by(&:b)
    def context_key?(k) = k.is_a?(String) && js.ustr?(k) && (CONTEXT_KEYS.include?(k) || k.match?(TAINT_RE))
    def rx?(re, s) = js.rx?(re, s)
    def u16key(s) = s.encode('UTF-16BE').b

    def str_list?(v, max, &ok)
      v.is_a?(Array) && v.length <= max && v.all? { |x| x.is_a?(String) && js.ustr?(x) && ok.call(x) } && js.distinct_strs?(v)
    end

    # ---- strict JSON profile + ActionDef validation ----------------------------------------------------------------

    # Plain objects/arrays, NFC strings without lone surrogates, safe integers only, depth <= 32.
    def json_profile_error(v, depth = 0)
      return 'nesting deeper than 32' if depth > 32
      return nil if v.nil? || v == true || v == false
      return (int?(v) ? nil : 'numbers must be safe integers (no floats, no -0)') if v.is_a?(Integer) || v.is_a?(Float)

      if v.is_a?(String)
        return 'string has a lone surrogate' unless js.ustr?(v)

        return js.u8(v).unicode_normalize(:nfc) == js.u8(v) ? nil : 'string is not NFC'
      end
      if v.is_a?(Array)
        v.each { |x| (e = json_profile_error(x, depth + 1)) && (return e) }
        return nil
      end
      if v.is_a?(Hash)
        v.each do |k, x|
          return 'member name is not NFC / has a lone surrogate' unless js.ustr?(k) && js.u8(k).unicode_normalize(:nfc) == js.u8(k)

          (e = json_profile_error(x, depth + 1)) && (return e)
        end
        return nil
      end
      'only JSON values are allowed'
    end

    def role?(r) = r.is_a?(String) && (CORE_ROLES.include?(r) || rx?(ID_ROLE_RE, r) || rx?(CUSTOM_ROLE_RE, r))
    def format?(f) = f.is_a?(String) && (PARAM_FORMATS.include?(f) || rx?(ID_FORMAT_RE, f))

    ID_CLASS_CHARS = begin
      digits = '0123456789'
      lower = ('a'..'z').to_a.join
      { 'digits' => digits, 'hex' => "#{digits}abcdef", 'alnum' => digits + lower + lower.upcase, 'slug' => "#{digits}#{lower}-_",
        'uuid' => "#{digits}abcdef-", 'any_safe' => "#{digits}#{lower}#{lower.upcase}._-:/" }.freeze
    end

    def in_class?(s, c) = s.each_char.all? { |ch| ID_CLASS_CHARS[c].include?(ch) }

    def id_pattern_error(p)
      return nil if p == '*'
      return "resource.id must be '*', {exact} or {prefix, class, len}" unless p.is_a?(Hash)

      keys = p.keys.map(&:b).sort.join(',')
      if keys == 'exact'
        e = p['exact']
        return e.is_a?(String) && js.ustr?(e) && e.length.between?(1, 128) && in_class?(e, 'any_safe') ? nil : 'resource.id.exact must be 1..128 safe characters'
      end
      return "resource.id must be '*', {exact} or {prefix, class, len}" unless keys == 'class,len,prefix'
      return 'resource.id.prefix must be up to 32 safe characters' unless p['prefix'].is_a?(String) && js.ustr?(p['prefix']) && p['prefix'].length <= 32 && in_class?(p['prefix'], 'any_safe')
      return 'resource.id.class is not an id class' unless in?(p['class'], ID_CLASSES)

      ln = p['len']
      return 'resource.id.len must be [min, max] in 1..128' unless ln.is_a?(Array) && ln.length == 2 && ln.all? { |n| int?(n) && n >= 1 && n <= 128 }
      return 'resource.id.len: min > max' if ln[0] > ln[1]
      return 'a uuid id has no prefix and length exactly [36, 36]' if p['class'] == 'uuid' && (p['prefix'] != '' || ln[0] != 36 || ln[1] != 36)

      nil
    end

    def param_name_error(name)
      return "param name '#{name}' is malformed" unless rx?(PARAM_NAME_RE, name)
      return "param name '#{name}' is reserved" if name.split('.').any? { |seg| RESERVED.include?(seg) }

      nil
    end

    def param_error(name, p, names)
      return "#{name}: declaration must be an object" unless p.is_a?(Hash)

      p.each_key { |k| return "#{name}: unknown member '#{k}'" unless PARAM_KEYS.include?(k) }
      return "#{name}: unknown type" unless in?(p['type'], PARAM_TYPES)

      t = p['type']
      return "#{name}: unknown role" if p.key?('role') && !role?(p['role'])
      return "#{name}: role requires an integer parameter" if p['role'].is_a?(String) && INT_ROLES.include?(p['role']) && t != 'integer'
      return "#{name}: required must be a boolean" if p.key?('required') && ![true, false].include?(p['required'])

      if p.key?('values')
        vs = p['values']
        return "#{name}: values must be 1..256 non-empty strings" if !vs.is_a?(Array) || vs.empty? || vs.length > 256 || !vs.all? { |x| str?(x) }
        return "#{name}: values must be distinct" unless js.distinct_strs?(vs)
        return "#{name}: values apply to string and set only" unless %w[string set].include?(t)
      end
      return "#{name}: a set needs values" if t == 'set' && !p.key?('values')

      int_like = %w[integer duration].include?(t) || (t == 'array' && p['items'] == 'integer')
      %w[min max].each { |k| return "#{name}: #{k} must be a safe integer on an integer parameter" if p.key?(k) && (!int?(p[k]) || !int_like) }
      return "#{name}: min > max" if int?(p['min']) && int?(p['max']) && p['min'] > p['max']
      if p.key?('max_len') && (!int?(p['max_len']) || p['max_len'] < 1 || p['max_len'] > 16_777_216 || !%w[string array object_ref].include?(t))
        return "#{name}: max_len must be 1..16777216 on a string or array"
      end
      return "#{name}: items applies to array only" if p.key?('items') && (t != 'array' || !str?(p['items'], 64))

      %w[min_items max_items].each do |k|
        return "#{name}: #{k} must be a non-negative integer on a set or array" if p.key?(k) && (!nonneg?(p[k]) || !%w[set array].include?(t))
      end
      return "#{name}: min_items > max_items" if int?(p['min_items']) && int?(p['max_items']) && p['min_items'] > p['max_items']
      return "#{name}: format must be a known format on a string parameter" if p.key?('format') && (!format?(p['format']) || !%w[string object_ref].include?(t))

      if p.key?('unit')
        u = p['unit']
        return "#{name}: unit applies to integer parameters only" if t != 'integer'
        return "#{name}: unit.kind is not a known kind" unless u.is_a?(Hash) && in?(u['kind'], UNIT_KINDS)

        if u['kind'] == 'money'
          return "#{name}: unit has unknown members" if u.keys.any? { |k| !%w[kind ccy exp].include?(k) }
          return "#{name}: unit.exp must be an integer in 0..18" unless int?(u['exp']) && u['exp'] >= 0 && u['exp'] <= 18

          c = u['ccy']
          if c.is_a?(String)
            return "#{name}: unit.ccy must be an ISO 4217 style code" unless rx?(CCY_RE, c)
          elsif !c.is_a?(Hash) || c.keys != ['from'] || !c['from'].is_a?(String) || !names.include?(c['from'])
            return "#{name}: unit.ccy.from must name a declared parameter"
          end
        elsif u.keys != ['kind']
          return "#{name}: unit has unknown members"
        end
      end
      if p.key?('tags')
        tg = p['tags']
        return "#{name}: tags must be distinct known tags" unless tg.is_a?(Array) && tg.length <= PARAM_TAGS.length && tg.all? { |x| in?(x, PARAM_TAGS) } && js.distinct_strs?(tg)
      end
      return "#{name}: unknown provenance_min" if p.key?('provenance_min') && !in?(p['provenance_min'], PROVENANCE_LEVELS)
      return "#{name}: unknown sensitivity" if p.key?('sensitivity') && !in?(p['sensitivity'], SENSITIVITY_RANK.keys)

      if p.key?('accumulates')
        a = p['accumulates']
        return "#{name}: accumulates applies to integer parameters only" if t != 'integer'
        unless a.is_a?(Array) && !a.empty? && a.length <= 8 && a.all? { |x| x.is_a?(String) && x.length <= 64 && rx?(UNIT_ID_RE, x) } && js.distinct_strs?(a)
          return "#{name}: accumulates must be 1..8 distinct unit ids"
        end
      end
      return "#{name}: default must not be null (absent = no default)" if p.key?('default') && p['default'].nil?
      return "#{name}: principal_neutral_default must be a boolean" if p.key?('principal_neutral_default') && ![true, false].include?(p['principal_neutral_default'])
      return "#{name}: principal_neutral_default needs a default" if p['principal_neutral_default'] == true && !p.key?('default')
      return "#{name}: description must be a string up to #{MAX_DESCRIPTION_BYTES} bytes" if p.key?('description') && !str?(p['description'], MAX_DESCRIPTION_BYTES)

      nil
    end

    BINDING_SHAPES = {
      'mcp' => [%w[tool], []], 'openapi' => [%w[operationId], %w[method path]], 'http' => [%w[method path], []],
      'graphql' => [%w[op field], []], 'grpc' => [%w[service method], []], 'asyncapi' => [%w[channel op], []]
    }.freeze

    def bindings_error(b)
      return 'bindings must be an object' unless b.is_a?(Hash)

      b.each do |k, v|
        return "bindings: unknown kind '#{k}'" unless BINDING_KINDS.include?(k)

        req, opt = BINDING_SHAPES[k]
        return "bindings.#{k} must be an object" unless v.is_a?(Hash)

        v.each_key { |m| return "bindings.#{k}: unknown member '#{m}'" unless (req + opt).include?(m) }
        req.each { |m| return "bindings.#{k}.#{m} must be a non-empty string" unless str?(v[m], 256) }
        opt.each { |m| return "bindings.#{k}.#{m} must be a non-empty string" if v.key?(m) && !str?(v[m], 256) }
      end
      return 'bindings.graphql.op is not a GraphQL operation kind' if b.key?('graphql') && !%w[query mutation subscription].include?(b['graphql']['op'])
      return 'bindings.asyncapi.op must be send or receive' if b.key?('asyncapi') && !%w[send receive].include?(b['asyncapi']['op'])

      nil
    end

    def review_error(r)
      return 'review must be an object' unless r.is_a?(Hash)

      r.each_key { |k| return "review: unknown member '#{k}'" unless %w[state attestation suggested_by provenance].include?(k) }
      return 'review.state is not a review state' unless in?(r['state'], REVIEW_STATES)

      if r.key?('provenance')
        pv = r['provenance']
        return 'review.provenance must be an object' unless pv.is_a?(Hash)

        pv.each do |k, v|
          return "review.provenance: unknown member '#{k}'" unless %w[union adjudicated].include?(k)
          return "review.provenance.#{k} must be a list of at most 32 distinct trait ids" unless v.is_a?(Array) && v.length <= 32 && v.all? { |t| rx?(PROVENANCE_TRAIT_RE, t) } && v.uniq.length == v.length
        end
      end

      if r.key?('attestation')
        a = r['attestation']
        return 'review.attestation must be an object' unless a.is_a?(Hash)

        a.each_key { |k| return "review.attestation: unknown member '#{k}'" unless %w[def_digest traits_digest facts_digest final_traits dismissed reviewer_kid ts sig].include?(k) }
        unless str?(a['def_digest'], 64) && str?(a['traits_digest'], 64) && str?(a['facts_digest'], 64) && str?(a['reviewer_kid'], 128) && nonneg?(a['ts'])
          return 'review.attestation: def_digest, traits_digest, facts_digest, reviewer_kid and ts are required'
        end
        return 'review.attestation.final_traits must be distinct trait ids' unless str_list?(a['final_traits'], MAX_DEF_TRAITS) { |s| rx?(TRAIT_ID_RE, s) }

        d = a['dismissed']
        unless d.is_a?(Array) && d.length <= MAX_DEF_TRAITS && d.all? { |x| x.is_a?(Hash) && x.keys.map(&:b).sort.join(',') == 'reason,trait' && rx?(TRAIT_ID_RE, x['trait']) && str?(x['reason'], 256) }
          return 'review.attestation.dismissed must be {trait, reason} entries'
        end
        return 'review.attestation.sig must be a string' if a.key?('sig') && !str?(a['sig'], 4096)
      end
      nil
    end

    # nil if `x` is a well-formed ActionDef (structure only: registry, prules and lint checks are separate). Never raises.
    def validate_def(x)
      x = js.jsnorm(x)
      je = json_profile_error(x)
      return "not strict JSON: #{je}" if je
      return 'def must be an object' unless x.is_a?(Hash)

      x.each_key { |k| return "unknown member '#{k}'" unless DEF_KEYS.include?(k) }
      return 'unsupported def version' unless js.strict_eq(x['v'], 1)
      return "kind must be '#{ACTION_DEF_KIND}'" unless x['kind'] == ACTION_DEF_KIND

      verb = x['verb']
      return 'verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)' unless verb.is_a?(String) && rx?(VERB_RE, verb) && verb.bytesize <= MAX_VERB_BYTES
      if x.key?('aliases') && (!str_list?(x['aliases'], MAX_DEF_ALIASES) { |s| rx?(ALIAS_RE, s) && s.bytesize <= MAX_VERB_BYTES } || x['aliases'].include?(verb))
        return 'aliases must be distinct verb-shaped names other than the verb'
      end
      return "title must be a non-empty string up to #{MAX_TITLE_BYTES} bytes" unless str?(x['title'], MAX_TITLE_BYTES)
      return 'description must be a string' if x.key?('description') && !str?(x['description'], MAX_DESCRIPTION_BYTES)
      return 'effects must be 1..12 distinct known effects' if !str_list?(x['effects'], EFFECTS.length) { |s| EFFECTS.include?(s) } || x['effects'].empty?

      r = x['resource']
      return 'resource must be {type, id, scope}' unless r.is_a?(Hash) && r.keys.map(&:b).sort.join(',') == 'id,scope,type'
      return 'resource.type is malformed' unless r['type'].is_a?(String) && rx?(RESOURCE_TYPE_RE, r['type']) && r['type'].length <= 128

      ide = id_pattern_error(r['id'])
      return ide if ide
      return 'resource.scope is not a scope' unless in?(r['scope'], RESOURCE_SCOPES)

      params = x['params']
      return 'params must be an object' unless params.is_a?(Hash)

      names = params.keys
      return "more than #{MAX_DEF_PARAMS} parameters" if names.length > MAX_DEF_PARAMS

      names.each do |n|
        ne = param_name_error(n)
        return ne if ne

        names.each { |m| return "param '#{n}' is both a value and the parent of '#{m}'" if m != n && m.start_with?("#{n}.") }
      end
      names.each { |n| (e = param_error(n, params[n], names)) && (return e) }
      if x.key?('reversibility') && !x['reversibility'].is_a?(String)
        rv = x['reversibility']
        return 'reversibility must be a class or {by, map, default?}' if !rv.is_a?(Hash) || rv.keys.any? { |k| !%w[by map default].include?(k) }
        return 'reversibility.by must name a declared parameter' unless rv['by'].is_a?(String) && names.include?(rv['by'])

        m = rv['map']
        return 'reversibility.map must map values to reversibility classes' unless m.is_a?(Hash) && !m.empty? && m.length <= 256 && m.all? { |k, v| str?(k, 128) && in?(v, REVERSIBILITY) }
        return 'reversibility.default is not a class' if rv.key?('default') && !in?(rv['default'], REVERSIBILITY)
      elsif x.key?('reversibility') && !REVERSIBILITY.include?(x['reversibility'])
        return 'unknown reversibility class'
      end
      if x.key?('blast')
        b = x['blast']
        return 'blast must be {radius, ppm?}' if !b.is_a?(Hash) || b.keys.any? { |k| !%w[radius ppm].include?(k) } || !in?(b['radius'], BLAST_RADII)
        return 'blast.ppm must be an integer in 0..1000000' if b.key?('ppm') && !(int?(b['ppm']) && b['ppm'] >= 0 && b['ppm'] <= PPM_MAX)
      end
      if x.key?('side_effects')
        s = x['side_effects']
        unless s.is_a?(Array) && s.length <= MAX_DEF_SIDE_EFFECTS && s.all? { |e| e.is_a?(Hash) && e.keys.map(&:b).sort.join(',') == 'kind,target' && str?(e['target'], 128) && in?(e['kind'], EFFECTS) }
          return 'side_effects must be {target, kind} entries'
        end
      end
      if x.key?('idempotency')
        i = x['idempotency']
        return 'idempotency must be {mode, param?}' if !i.is_a?(Hash) || i.keys.any? { |k| !%w[mode param].include?(k) } || !in?(i['mode'], IDEMPOTENCY_MODES)

        bad = i['mode'] == 'key_param' ? (!i['param'].is_a?(String) || !names.include?(i['param'])) : i.key?('param')
        return 'idempotency.param is required for key_param (a declared parameter) and forbidden otherwise' if bad
      end
      return 'context must be distinct known context keys' if x.key?('context') && !str_list?(x['context'], MAX_DEF_CONTEXT) { |s| context_key?(s) }
      return 'traits must be distinct trait ids' if x.key?('traits') && !str_list?(x['traits'], MAX_DEF_TRAITS) { |s| rx?(TRAIT_ID_RE, s) }
      return "audience must be 'resource'" if x.key?('audience') && x['audience'] != 'resource'
      return 'compensates must be a verb' if x.key?('compensates') && !(x['compensates'].is_a?(String) && rx?(VERB_RE, x['compensates']))
      if x.key?('bindings')
        be = bindings_error(x['bindings'])
        return be if be
      end
      if x.key?('examples')
        ex = x['examples']
        return 'examples must be an array of up to 32 entries' unless ex.is_a?(Array) && ex.length <= 32

        ex.each do |e|
          return 'example must be {params, under?, expect}' if !e.is_a?(Hash) || e.keys.any? { |k| !%w[params under expect].include?(k) } || !e['params'].is_a?(Hash) || !%w[allow escalate deny].include?(e['expect'])
        end
      end
      re = review_error(x['review'])
      return re if re

      if x.key?('source')
        s = x['source']
        unless s.is_a?(Hash) && s.keys.all? { |k| %w[kind uri spec_digest licence imported_at].include?(k) } && str?(s['kind'], 64) && str?(s['uri'], 2048) &&
               str?(s['spec_digest'], 128) && str?(s['licence'], 128) && (!s.key?('imported_at') || nonneg?(s['imported_at']))
          return 'source must be {kind, uri, spec_digest, licence, imported_at?}'
        end
      end
      return 'since must be a string' if x.key?('since') && !str?(x['since'], 64)

      nil
    rescue StandardError, SystemStackError => e
      "malformed def: #{e.message}"
    end

    # ---- profile lattice + trait registry --------------------------------------------------------------------------

    def profile(p = {})
      { 'risk' => p.fetch('risk', 0), 'rev' => p.fetch('rev', 'reversible'), 'blast_ppm' => p.fetch('blast_ppm', 0), 'esc' => p.fetch('esc', 0),
        'caveats' => sort_uniq(p['caveats']), 'context' => sort_uniq(p['context']), 'prules' => sort_uniq(p['prules']) }
    end

    BOTTOM = profile.freeze

    def int_in?(x, lo, hi) = int?(x) && x >= lo && x <= hi

    def profile_error(p)
      return 'profile must be an object' unless p.is_a?(Hash)

      p.each_key { |k| return "profile: unknown member '#{k}'" unless %w[risk rev blast_ppm esc caveats context prules].include?(k) }
      return 'profile.risk must be an integer in 0..3' unless int_in?(p['risk'], 0, 3)
      return 'profile.rev is not a reversibility class' unless in?(p['rev'], REVERSIBILITY)
      return 'profile.blast_ppm must be an integer in 0..1000000' unless int_in?(p['blast_ppm'], 0, PPM_MAX)
      return 'profile.esc must be an integer in 0..3' unless int_in?(p['esc'], 0, 3)

      { 'caveats' => ->(x) { in?(x, CAVEAT_KINDS) }, 'context' => ->(x) { context_key?(x) }, 'prules' => ->(x) { in?(x, PARAM_RULE_IDS) } }.each do |name, ok|
        a = p[name]
        return "profile.#{name} must be an array of known #{name} entries" unless a.is_a?(Array) && a.length <= 64 && a.all? { |x| ok.call(x) }

        (1...a.length).each { |i| return "profile.#{name} must be sorted and distinct" unless (a[i - 1].b <=> a[i].b).negative? }
      end
      nil
    end

    def join(p, q)
      { 'risk' => [p['risk'], q['risk']].max, 'rev' => REV_RANK[p['rev']] >= REV_RANK[q['rev']] ? p['rev'] : q['rev'],
        'blast_ppm' => [p['blast_ppm'], q['blast_ppm']].max, 'esc' => [p['esc'], q['esc']].max,
        'caveats' => sort_uniq(p['caveats'] + q['caveats']), 'context' => sort_uniq(p['context'] + q['context']),
        'prules' => sort_uniq(p['prules'] + q['prules']) }
    end

    def join_all(ps) = ps.reduce(BOTTOM) { |a, b| join(a, b) }
    def subset?(a, b) = a.all? { |x| b.include?(x) }

    def leq(p, q)
      p['risk'] <= q['risk'] && REV_RANK[p['rev']] <= REV_RANK[q['rev']] && p['blast_ppm'] <= q['blast_ppm'] && p['esc'] <= q['esc'] &&
        subset?(p['caveats'], q['caveats']) && subset?(p['context'], q['context']) && subset?(p['prules'], q['prules'])
    end

    # nil if `defs` form a valid registry, else the first reason (ids, distinct, pca. reserved, implies resolve, T5, no cycle, depth <= 8).
    def registry_error(defs, core: false)
      return "a registry holds at most #{MAX_REGISTRY_TRAITS} traits" if !defs.is_a?(Array) || defs.length > MAX_REGISTRY_TRAITS

      by = {}
      defs.each do |t|
        return 'trait must be an object' unless t.is_a?(Hash)

        tid = t['id']
        return "trait id '#{tid}' is malformed" unless tid.is_a?(String) && rx?(TRAIT_ID_RE, tid)
        return "trait '#{tid}': the pca. namespace is reserved for core traits" if tid.start_with?('pca.') && !core
        return "trait '#{tid}' is defined twice" if by.key?(tid)

        im = t['implies']
        return "trait '#{tid}': implies must be up to 8 distinct trait ids" unless im.is_a?(Array) && im.length <= 8 && im.all? { |u| u.is_a?(String) } && js.distinct_strs?(im)

        pe = profile_error(t['floor'])
        return "trait '#{tid}': #{pe}" if pe

        cp = t['card_phrase']
        return "trait '#{tid}': card_phrase must be a non-empty string up to 120 characters" unless cp.is_a?(String) && js.ustr?(cp) && js.u16len(cp).between?(1, 120)

        by[tid] = t
      end
      defs.each do |t|
        t['implies'].each do |u|
          ud = by[u]
          return "trait '#{t['id']}' implies unknown trait '#{u}'" if ud.nil?
          return "trait '#{t['id']}': floor is below the floor of implied '#{u}'" unless leq(ud['floor'], t['floor'])
        end
      end
      depth = {}
      visiting = {}
      walk = lambda do |i|
        return depth[i] if depth.key?(i)
        return -1 if visiting[i]

        visiting[i] = true
        d = 1
        by[i]['implies'].each do |u|
          du = walk.call(u)
          return -1 if du.negative?

          d = [d, du + 1].max
        end
        visiting.delete(i)
        depth[i] = d
      end
      defs.each do |t|
        d = walk.call(t['id'])
        return "trait '#{t['id']}': implies cycle" if d.negative?
        return "trait '#{t['id']}': implies depth #{d} exceeds #{MAX_TRAIT_IMPLIES_DEPTH}" if d > MAX_TRAIT_IMPLIES_DEPTH
      end
      nil
    end

    def build_registry(defs, core: false)
      e = registry_error(defs, core: core)
      raise ActionKitError.new('bad_registry', e) if e

      defs.to_h { |t| [t['id'], t] }
    end

    # Core registry extended with custom traits (which must not use `pca.` and must extend what they imply).
    def extend_registry(base, custom)
      custom = js.jsnorm(custom)
      raise ActionKitError.new('bad_registry', 'custom traits must be an array') unless custom.is_a?(Array)

      custom.each do |c|
        if !c.is_a?(Hash) || !c['id'].is_a?(String) || base.key?(c['id']) || c['id'].start_with?('pca.')
          raise ActionKitError.new('bad_registry', 'custom trait may not redefine a core trait')
        end
      end
      build_registry(base.values + custom, core: true)
    end

    def closure(reg, ids)
      seen = {}
      stack = ids.dup
      until stack.empty?
        i = stack.pop
        next if seen.key?(i)

        t = i.is_a?(String) ? reg[i] : nil
        raise ActionKitError.new('unknown_trait', "unknown trait '#{i}'") if t.nil?

        seen[i] = true
        stack.concat(t['implies'])
      end
      seen.keys.sort_by(&:b)
    end

    def floor_of(reg, ids) = join_all(closure(reg, ids).map { |i| reg[i]['floor'] })

    # FloorDecision(G, call, rho): deny if rho.esc > G.max_esc; escalate if a caveat/context is missing or rho.esc > G.preauth_esc; else allow.
    def floor_decision(g, call, rho)
      return 'deny' if rho['esc'] > g['max_esc']
      return 'escalate' if !subset?(rho['caveats'], g['caveats']) || !subset?(rho['context'], call['context']) || rho['esc'] > g['preauth_esc']

      'allow'
    end

    # [id, implies, own floor, card phrase] - the 22 core traits
    TABLE = [
      ['money_moving', [], { 'risk' => 3, 'rev' => 'rate_limited', 'blast_ppm' => 700_000, 'esc' => 2, 'caveats' => %w[amount_cap count_cap window], 'context' => ['idempotency'], 'prules' => %w[money_has_currency money_amount_bounded pay_has_idempotency] }, 'moves money'],
      ['destructive', [], { 'risk' => 2, 'rev' => 'rate_limited', 'esc' => 1, 'caveats' => ['resource_scope'], 'prules' => ['id_not_wildcard'] }, 'deletes or destroys data'],
      ['irreversible', [], { 'risk' => 2, 'rev' => 'irreversible', 'esc' => 1, 'context' => ['fresh_revocation'] }, 'cannot be undone'],
      ['external_communication', [], { 'risk' => 2, 'rev' => 'irreversible', 'caveats' => %w[recipient_scope rate_cap], 'prules' => ['recipient_param_declared'] }, 'sends to people outside your organisation'],
      ['data_export', [], { 'risk' => 2, 'caveats' => %w[resource_scope count_cap], 'prules' => ['export_bounded'] }, 'exports data'],
      ['privilege_change', [], { 'risk' => 3, 'esc' => 3, 'caveats' => %w[resource_scope short_expiry] }, 'changes who can do what'],
      ['code_execution', [], { 'risk' => 3, 'rev' => 'irreversible', 'esc' => 2, 'caveats' => ['resource_scope'], 'context' => ['sandbox_attested'] }, 'runs code or commands'],
      ['credential_access', [], { 'risk' => 3, 'esc' => 3, 'prules' => ['secret_not_logged'] }, 'reads or handles credentials'],
      ['bulk', [], { 'risk' => 2, 'caveats' => ['count_cap'], 'prules' => ['array_bounded'] }, 'acts on many items at once'],
      ['pii_access', [], { 'risk' => 1, 'caveats' => ['resource_scope'] }, 'touches personal data'],
      ['public_exposure', [], { 'risk' => 2, 'rev' => 'irreversible', 'esc' => 1 }, 'makes content public'],
      ['persistence', [], { 'risk' => 2, 'caveats' => ['short_expiry'], 'context' => ['revocable'] }, 'creates standing access or infrastructure'],
      ['infra_mutation', [], { 'risk' => 2, 'rev' => 'rate_limited', 'caveats' => ['resource_scope'] }, 'changes infrastructure'],
      ['cost_incurring', [], { 'risk' => 1, 'caveats' => ['amount_cap'] }, 'incurs cost'],
      ['legal_binding', [], { 'risk' => 3, 'rev' => 'irreversible', 'esc' => 3 }, 'legally or cryptographically binds you'],
      ['impersonation', ['external_communication'], { 'risk' => 2, 'esc' => 1 }, 'acts as a person'],
      ['network_egress', [], { 'risk' => 1, 'caveats' => ['recipient_scope'] }, 'reaches out to the network'],
      ['financial_data_read', [], { 'risk' => 1, 'caveats' => ['resource_scope'] }, 'reads financial data'],
      ['regulated_data', [], { 'risk' => 2, 'esc' => 1 }, 'handles regulated data'],
      ['scheduled', [], { 'risk' => 2, 'caveats' => %w[short_expiry count_cap] }, 'runs later or repeatedly'],
      ['unreviewed', [], { 'risk' => 3, 'rev' => 'irreversible', 'blast_ppm' => 1_000_000, 'esc' => 2, 'caveats' => %w[approval_ref resource_scope], 'context' => ['dry_run_first'] }, 'has not been reviewed yet'],
      ['agent_spawning', [], { 'risk' => 2, 'caveats' => ['count_cap'] }, 'starts another agent']
    ].freeze

    def core_defs
      floors = {}
      TABLE.map do |name, implies, own, phrase|
        tid = "pca.#{name}"
        imp = implies.map { |n| "pca.#{n}" }
        fl = imp.reduce(profile(own)) { |acc, u| join(acc, floors[u]) }
        floors[tid] = fl
        { 'id' => tid, 'implies' => imp, 'floor' => fl, 'card_phrase' => phrase }
      end
    end

    CORE_TRAIT_DEFS = core_defs.freeze
    CORE_REGISTRY = build_registry(CORE_TRAIT_DEFS, core: true).freeze

    EFFECT_TRAITS = {
      'read' => [], 'create' => [], 'update' => [], 'delete' => ['pca.destructive'], 'send' => ['pca.external_communication'],
      'pay' => ['pca.money_moving'], 'exec' => ['pca.code_execution'], 'privilege' => ['pca.privilege_change'], 'export' => ['pca.data_export'],
      'publish' => ['pca.public_exposure'], 'provision' => %w[pca.persistence pca.scheduled], 'sign' => ['pca.legal_binding']
    }.freeze
    TAG_TRAITS = {
      'pii' => ['pca.pii_access'], 'phi' => %w[pca.pii_access pca.regulated_data], 'pci' => ['pca.regulated_data'],
      'secret' => ['pca.credential_access'], 'credential' => ['pca.credential_access']
    }.freeze
    ROLE_TRAITS = {
      'credential.secret' => ['pca.credential_access'], 'credential.token' => ['pca.credential_access'], 'credential.key' => ['pca.credential_access'],
      'url.target' => ['pca.network_egress']
    }.freeze
    ROLE_SENSITIVITY_FLOOR = {
      'money.amount' => 'critical', 'money.currency' => 'material', 'money.fee' => 'material', 'party.payee' => 'critical', 'party.payer' => 'material',
      'contact.email' => 'material', 'contact.phone' => 'material', 'contact.address' => 'material', 'person.name' => 'material', 'person.dob' => 'material',
      'person.national_id' => 'critical', 'credential.secret' => 'critical', 'credential.token' => 'critical', 'credential.key' => 'critical',
      'code.command' => 'critical', 'query.sql' => 'critical', 'text.message' => 'material'
    }.freeze
    TAG_SENSITIVITY_FLOOR = {
      'pii' => 'material', 'phi' => 'material', 'pci' => 'material', 'secret' => 'critical', 'credential' => 'critical',
      'free_text_outbound' => 'material', 'code' => 'material', 'path' => 'material', 'sql' => 'material'
    }.freeze

    # Digest of a trait registry (sorted by id): what a pack pins as `traits_digest`.
    def traits_digest(reg)
      ts = reg.values.sort_by { |t| t['id'].b }.map { |t| { 'id' => t['id'], 'implies' => t['implies'].sort_by(&:b), 'floor' => t['floor'], 'card_phrase' => t['card_phrase'] } }
      AtlasPca.hash_canonical({ 'd' => TRAITS_DIGEST_DOMAIN, 'traits' => ts })
    end

    def tables_digest
      AtlasPca.hash_canonical({ 'd' => ROLES_DIGEST_DOMAIN, 'roles' => CORE_ROLES, 'effect_traits' => EFFECT_TRAITS, 'role_traits' => ROLE_TRAITS,
                                'tag_traits' => TAG_TRAITS, 'role_sensitivity' => ROLE_SENSITIVITY_FLOOR, 'tag_sensitivity' => TAG_SENSITIVITY_FLOOR })
    end

    # ---- normalize + digest ----------------------------------------------------------------------------------------

    def read_only?(effects) = !effects.empty? && effects.all? { |e| e == 'read' }
    def max_sens(a, b) = SENSITIVITY_RANK[a] >= SENSITIVITY_RANK[b] ? a : b

    def sensitivity_floor(p)
      f = 'free'
      f = max_sens(f, ROLE_SENSITIVITY_FLOOR[p['role']]) if ROLE_SENSITIVITY_FLOOR.key?(p['role'])
      (p['tags'] || []).each { |t| f = max_sens(f, TAG_SENSITIVITY_FLOOR[t]) if TAG_SENSITIVITY_FLOOR.key?(t) }
      f
    end

    def effective_param_sensitivity(p) = max_sens(p.fetch('sensitivity', 'free'), sensitivity_floor(p))
    def declared_reversibility(d) = d.key?('reversibility') ? d['reversibility'] : (read_only?(d['effects']) ? 'reversible' : 'irreversible')

    def max_rev(xs)
      out = 'reversible'
      xs.each { |b| out = b if REV_RANK.key?(b) && REV_RANK[b] > REV_RANK[out] }
      out
    end

    # Conservative class of a (possibly value-dependent) reversibility declaration: the worst class any call can have.
    def worst_reversibility(r, params)
      return r if r.is_a?(String)

      d = params[r['by']]
      mapped = r['map'].values
      domain = nil
      if d.is_a?(Hash)
        domain = %w[true false] if d['type'] == 'boolean'
        domain = d['values'] if d['type'] == 'string' && !d['values'].nil?
      end
      covered = !domain.nil? && domain.all? { |x| r['map'].key?(x) }
      max_rev(covered ? mapped : mapped + [r.fetch('default', 'irreversible')])
    end

    def deep_copy(v)
      case v
      when Hash then v.to_h { |k, x| [k, deep_copy(x)] }
      when Array then v.map { |x| deep_copy(x) }
      else v
      end
    end

    def normalize_param(p)
      out = p.to_h { |k, v| [k, deep_copy(v)] }
      out['required'] = p.fetch('required', true)
      out['tags'] = sort_uniq(p['tags']) if p.key?('tags')
      out['sensitivity'] = effective_param_sensitivity(p)
      if p.key?('accumulates')
        out['accumulates'] = sort_uniq(p['accumulates'])
      else
        u = p['unit']
        out['accumulates'] = ["money.#{u['ccy'].downcase}"] if p['role'] == 'money.amount' && u.is_a?(Hash) && u['kind'] == 'money' && u['ccy'].is_a?(String)
      end
      out
    end

    # The authoring-independent form of a def (assumes validate_def passed): defaults filled, sets sorted, review/examples/source/since removed.
    def normalize(d)
      d = js.jsnorm(d)
      rev = declared_reversibility(d)
      radius = d.key?('blast') ? d['blast']['radius'] : SCOPE_BLAST[d['resource']['scope']]
      params = d['params'].keys.sort_by(&:b).to_h { |k| [k, normalize_param(d['params'][k])] }
      nrev = if rev.is_a?(String) then rev
             else
               { 'by' => rev['by'], 'map' => rev['map'].dup }.tap { |h| h['default'] = rev['default'] if rev.key?('default') }
             end
      idem = { 'mode' => d.key?('idempotency') ? d['idempotency']['mode'] : 'none' }
      idem['param'] = d['idempotency']['param'] if d.key?('idempotency') && d['idempotency'].key?('param')
      out = {
        'v' => 1, 'kind' => d['kind'], 'verb' => d['verb'], 'aliases' => sort_uniq(d['aliases']), 'title' => d['title'],
        'effects' => sort_uniq(d['effects']),
        'resource' => { 'type' => d['resource']['type'], 'id' => deep_copy(d['resource']['id']), 'scope' => d['resource']['scope'] },
        'params' => params, 'reversibility' => nrev,
        'blast' => { 'radius' => radius, 'ppm' => [BLAST_PPM[radius], d.key?('blast') ? d['blast'].fetch('ppm', 0) : 0].max },
        'side_effects' => (d['side_effects'] || []).map { |s| { 'target' => s['target'], 'kind' => s['kind'] } }.sort_by { |s| [u16key(s['target']), s['kind'].b] },
        'idempotency' => idem, 'context' => sort_uniq(d['context']), 'traits' => sort_uniq(d['traits']),
        'bindings' => deep_copy(d.fetch('bindings', {}))
      }
      out['description'] = d['description'] if d.key?('description')
      out['audience'] = d['audience'] if d.key?('audience')
      out['compensates'] = d['compensates'] if d.key?('compensates')
      out
    end

    # b64u(sha256(strictCanonical({d, def: normalize(def)}))). Review state, examples, source and since do not enter it.
    def def_digest(d) = AtlasPca.hash_canonical({ 'd' => DEF_DIGEST_DOMAIN, 'def' => normalize(d) })

    # ---- pack Merkle root + inclusion proof ------------------------------------------------------------------------

    def pack_leaf(digest) = { 'd' => PACK_DIGEST_DOMAIN, 'def' => digest }

    def sorted_digests(digests)
      s = digests.uniq.sort_by(&:b)
      raise ActionKitError.new('duplicate_def', 'a pack lists a def digest twice') if s.length != digests.length
      raise ActionKitError.new('empty_pack', 'a pack has at least one def') if s.empty?

      s
    end

    def pack_root(digests) = AtlasPca.merkle_root(sorted_digests(digests).map { |x| pack_leaf(x) })

    # RFC 6962 inclusion proof of `digest` in the pack made of `digests`: {index, size, path: [{side, hash}]} bottom-up.
    def pack_proof(digests, digest)
      s = sorted_digests(digests)
      raise ActionKitError.new('not_in_pack', 'the digest is not in the pack') unless s.include?(digest)

      i = s.index(digest)
      seg = s.map { |x| AtlasPca.leaf_hash(pack_leaf(x)) }
      idx = i
      path = []
      while seg.length > 1
        k = AtlasPca.split_point(seg.length)
        if idx < k
          path << { 'side' => 'R', 'hash' => AtlasPca.b64e(AtlasPca.build(seg[k..])) }
          seg = seg[0, k]
        else
          path << { 'side' => 'L', 'hash' => AtlasPca.b64e(AtlasPca.build(seg[0, k])) }
          seg = seg[k..]
          idx -= k
        end
      end
      { 'index' => i, 'size' => s.length, 'path' => path.reverse }
    end

    def verify_pack_proof(root, proof, digest) = AtlasPca.verify_inclusion(root, proof, pack_leaf(digest))

    # ---- T(d), decl(d), eff(d) -------------------------------------------------------------------------------------

    # Traits implied by effects, roles, tags, scope and reversibility. params: hashes with type/role/tags/max_items.
    def implied_from_facts(effects, params, scope, worst_rev)
      out = []
      effects.each { |e| out.concat(EFFECT_TRAITS.fetch(e)) } # KeyError on an unknown effect (callers treat it as forged)
      ro = read_only?(effects)
      params.each do |p|
        r = p['role']
        unless r.nil?
          out.concat(ROLE_TRAITS[r]) if ROLE_TRAITS.key?(r)
          out << 'pca.financial_data_read' if ro && r.start_with?('money.')
        end
        (p['tags'] || []).each { |t| out.concat(TAG_TRAITS[t]) if TAG_TRAITS.key?(t) }
        out << 'pca.bulk' if p['type'] == 'array' && p['max_items'].nil?
      end
      out << 'pca.bulk' if !scope.nil? && scope != 'one'
      out << 'pca.irreversible' if worst_rev == 'irreversible'
      sort_uniq(out)
    end

    # ---- the signed human confirmation: the ONLY thing that sets traits below the top of the registry --------------------

    REVIEW_DOMAIN = 'atlas-pca/action-review/v2'
    VERB_FACTS_DOMAIN = 'atlas-pca/action-verb-facts/v1'
    KEY_ROLES = %w[reviewer importer model publisher].freeze
    JS_BLANK = /\A[\s\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]*\z/

    def u16len(s) = s.encode('UTF-16LE').bytesize / 2

    # nil if the pin set is sound (distinct kids, canonical 32-byte keys, known roles, no reviewer that is also a machine key).
    def reviewer_pins_error(p)
      return 'pins must be {keys: [...]}' unless p.is_a?(Hash) && p['keys'].is_a?(Array)

      kids = {}
      machine = {}
      p['keys'].each do |k|
        kid = k.is_a?(Hash) ? k['kid'] : nil
        return 'a pinned key needs a kid' unless kid.is_a?(String) && !kid.empty? && u16len(kid) <= 128
        return "kid '#{kid}' is pinned twice" if kids.key?(kid)

        kids[kid] = true
        return "key '#{kid}': pk is not canonical base64url (32 bytes)" if AtlasPca.b64d(k['pk'], 32).nil?

        r = k['roles']
        return "key '#{kid}': roles must be distinct known roles" unless r.is_a?(Array) && !r.empty? && r.all? { |x| KEY_ROLES.include?(x) } && r.uniq.length == r.length
        return "key '#{kid}': an importer or model key cannot hold the reviewer role" if r.include?('reviewer') && (r.include?('importer') || r.include?('model'))

        %w[not_before not_after].each { |t| return "key '#{kid}': #{t} must be a non-negative integer" if k.key?(t) && !nonneg?(k[t]) }
        machine[k['pk']] = true if r.include?('importer') || r.include?('model')
      end
      p['keys'].each { |k| return "key '#{k['kid']}': the same key material is pinned as an importer or model key" if k['roles'].include?('reviewer') && machine[k['pk']] }
      nil
    end

    # Domain-separated message the reviewer signs: REVIEW_DOMAIN \0 strictCanonical(body).
    def review_message(b)
      dis = b['dismissed'].sort_by { |x| x['trait'].b }.map { |x| { 'trait' => x['trait'], 'reason' => x['reason'] } }
      "#{REVIEW_DOMAIN}\0".b + AtlasPca.canon_bytes({ 'def_digest' => b['def_digest'], 'traits_digest' => b['traits_digest'], 'facts_digest' => b['facts_digest'], 'final_traits' => sort_uniq(b['final_traits']),
                                                     'dismissed' => dis, 'reviewer_kid' => b['reviewer_kid'], 'ts' => b['ts'] })
    end

    # nil iff attestation `a` is valid for the def digest `dd`: accepted registry digest, final traits accepted by the block, a
    # reasoned dismissal, a pinned reviewer key inside its window, and a good signature. Never raises: any failure is a reason.
    def attestation_error(a, dd, reg, pins, facts = nil)
      return 'no reviewer keys are pinned' if pins.nil?

      pe = reviewer_pins_error(pins)
      return "bad pins: #{pe}" if pe
      return 'no attestation' unless a.is_a?(Hash)
      return 'the attestation is unsigned' unless a['sig'].is_a?(String)
      return 'the attestation covers a different def digest' unless dd.is_a?(String) && a['def_digest'] == dd

      td = pins['traits_digests'] || []
      return 'bad pins: traits_digests' unless td.is_a?(Array)
      return 'the attestation was made against a different trait registry' unless a['traits_digest'] == traits_digest(reg) || td.include?(a['traits_digest'])
      return 'the verb facts differ from the facts the reviewer confirmed' if facts && a['facts_digest'] != facts

      ft = a['final_traits']
      dm = a['dismissed']
      return 'malformed attestation' unless ft.is_a?(Array) && ft.all? { |t| t.is_a?(String) } && dm.is_a?(Array) && int?(a['ts']) && a['reviewer_kid'].is_a?(String)
      return 'the final traits are not accepted' unless yield(ft)
      return 'malformed attestation' unless dm.all? { |d| d.is_a?(Hash) && d['trait'].is_a?(String) && d['reason'].is_a?(String) }
      return 'a dismissed trait is also final, or has no reason' if dm.any? { |d| ft.include?(d['trait']) || JS_BLANK.match?(d['reason']) }

      key = pins['keys'].find { |k| k['kid'] == a['reviewer_kid'] }
      return "no pinned key '#{a['reviewer_kid']}'" if key.nil?
      return "key '#{key['kid']}' does not hold the reviewer role" unless key['roles'].include?('reviewer')
      return 'the attestation time is outside the key validity' if (key.key?('not_before') && a['ts'] < key['not_before']) || (key.key?('not_after') && a['ts'] > key['not_after'])

      AtlasPca.verify_b64u(key['pk'], review_message(a), a['sig']) ? nil : 'the attestation signature is invalid'
    rescue StandardError => e
      "malformed attestation: #{e.message}"
    end

    # DEF level: state confirmed, an attestation over this def's digest whose final traits are exactly its declared traits.
    def def_confirmation_error(d, reg, pins)
      return 'review.state is not confirmed' unless d.is_a?(Hash) && d['review'].is_a?(Hash) && d['review']['state'] == 'confirmed'

      attestation_error(d['review']['attestation'], def_digest(d), reg, pins) { |ft| sort_uniq(ft) == sort_uniq(d['traits']) }
    rescue StandardError => e
      "malformed def: #{e.message}"
    end

    # VERB level: the confirmation covers verb['def'] and every final trait is carried by the verb.
    def verb_confirmation_error(v, reg, pins)
      attestation_error(v['confirmation'], v['def'], reg, pins, facts_digest(v)) { |ft| v['traits'].is_a?(Array) && ft.all? { |t| v['traits'].include?(t) } }
    rescue StandardError => e
      "malformed confirmation: #{e.message}"
    end

    # Digest of the verb's facts (everything but traits, floors, confirmation, def): what the reviewer saw.
    def facts_digest(v) = AtlasPca.hash_canonical({ 'd' => VERB_FACTS_DOMAIN, 'verb' => v.reject { |k, _| %w[traits floors confirmation def].include?(k) } })

    def top_traits(reg) = reg.keys.sort_by(&:b)

    # What the def would have if a reviewer signed it as it stands: declared + implied by its own facts. Never enforcement.
    def hint_traits(d)
      n = normalize(d)
      sort_uniq(n['traits'] + implied_from_facts(n['effects'], n['params'].values, n['resource']['scope'], worst_reversibility(n['reversibility'], n['params'])))
    end

    def decl_profile(d)
      n = normalize(d)
      critical = n['params'].values.any? { |p| SENSITIVITY_RANK[effective_param_sensitivity(p)] >= SENSITIVITY_RANK['critical'] }
      profile('risk' => critical ? 2 : (read_only?(n['effects']) ? 0 : 1), 'rev' => worst_reversibility(n['reversibility'], n['params']),
              'blast_ppm' => n['blast']['ppm'], 'context' => n['context'])
    end

    # {confirmed, traits, closure, floor, decl, eff}: eff = decl join F(T(d)). "Unconfirmed means maximally dangerous": without a
    # valid signed confirmation by a pinned reviewer key, T(d) is EVERY trait of the registry.
    def effective(d, reg = CORE_REGISTRY, pins = nil)
      d = js.jsnorm(d)
      confirmed = def_confirmation_error(d, reg, pins).nil?
      tr = confirmed ? hint_traits(d) : top_traits(reg)
      fl = floor_of(reg, tr)
      dp = decl_profile(d)
      { 'confirmed' => confirmed, 'traits' => tr, 'closure' => closure(reg, tr), 'floor' => fl, 'decl' => dp, 'eff' => join(dp, fl) }
    end

    # ---- rule 22: whole-document integrity of the carried traits and floors ----------------------------------------

    PFX = 'action.params.'

    # Recompute from the verb's own visible facts that its `traits` contain every implied trait and that its `floors` are at
    # least the floor of the traits' closure and of the declared reversibility. nil = consistent; else `<code>: <reason>`. Never raises.
    def schema_verb_floor_error(v, reg = CORE_REGISTRY, pins = nil)
      v = js.jsnorm(v)
      return 'schema_floor_forged: not a v2 verb' if !v['effects'].is_a?(Array) || !v['traits'].is_a?(Array) || !v.key?('floors')

      ps = v['params'].map { |path, p| [path[PFX.length..], p] }
      by_name = ps.to_h { |name, p| [name, { 'type' => p['type'] }.tap { |e| e['values'] = p['values'] if p.key?('values') }] }
      if v['reversibility_by']
        rb = v['reversibility_by']
        decl = { 'by' => rb['param'][PFX.length..], 'map' => rb['map'] }
        decl['default'] = rb['default'] if rb.key?('default')
      else
        decl = v.key?('reversibility') ? v['reversibility'] : (v['kind'] == 'read' ? 'reversible' : 'irreversible')
      end
      worst = worst_reversibility(decl, by_name)
      implied = implied_from_facts(v['effects'], ps.map { |_, p| p }, nil, worst)
      implied.each { |t| return "schema_traits_forged: missing implied trait #{t}" unless v['traits'].include?(t) }
      unless verb_confirmation_error(v, reg, pins).nil?
        top_traits(reg).each { |t| return "schema_traits_forged: unconfirmed action must carry every trait (missing #{t})" unless v['traits'].include?(t) }
      end
      fl = floor_of(reg, v['traits'])
      return 'schema_floor_forged: floors are below the floor of the carried traits' unless leq(fl, v['floors'])
      return 'schema_floor_forged: floors.rev is below the declared reversibility' if REV_RANK.fetch(v['floors']['rev'], -1) < REV_RANK.fetch(worst, -1)

      nil
    rescue ActionKitError => e
      "#{e.code}: #{e.message}"
    rescue StandardError => e
      "schema_floor_forged: #{e.message}"
    end

    # Core + the document's own `trait_defs` (checked), and when it carries `traits_digest` the registry must hash to it.
    def registry_of_schema(doc)
      td = doc['trait_defs']
      reg = td.is_a?(Array) && !td.empty? ? extend_registry(CORE_REGISTRY, td) : CORE_REGISTRY
      raise ActionKitError.new('traits_digest_mismatch', "the document's traits_digest does not match its trait registry") if doc.key?('traits_digest') && doc['traits_digest'] != traits_digest(reg)

      reg
    end

    # Rule 22's integrity half for a whole v2 document. nil = consistent. Never raises.
    def schema_floor_error(doc, pins = nil)
      doc = js.jsnorm(doc)
      reg = registry_of_schema(doc)
      doc['verbs'].each do |v|
        e = schema_verb_floor_error(v, reg, pins)
        return "#{v['verb']}: #{e}" if e
      end
      nil
    rescue ActionKitError => e
      "#{e.code}: #{e.message}"
    rescue StandardError => e
      "bad_registry: #{e.message}"
    end
  end
end
