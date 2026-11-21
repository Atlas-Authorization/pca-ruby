# frozen_string_literal: true
# Mutation-kill tests for lib/atlas_pca/actions.rb (the action kit). Expected values pin the reference
# (packages/pca-actions/src/{validate,traits,normalize,effective,confirmation}.ts): exact reason strings, exact return values.
require 'timeout'
require 'openssl'

module MutationKill
  module C01Actions
    module_function

    def skip? = (f = ENV['MUT_FILE']) && !f.empty? && f != 'actions.rb'
    def act = AtlasPca::Actions
    def svf = AtlasPca::Actions::SvfJS
    def js = AtlasPca::V2JS
    def core = AtlasPca::Actions::CORE_REGISTRY

    # exact equality; true / false / nil are compared by identity
    def same(label, got, want)
      ok = want == true || want == false || want.nil? ? got.equal?(want) : got == want
      raise "#{label}: got #{got.inspect}, want #{want.inspect}" unless ok

      true
    end

    def numf(label, got, want)
      ok = got.is_a?(Float) && (want.nan? ? got.nan? : got == want)
      raise "#{label}: got #{got.inspect}, want #{want.inspect}" unless ok

      true
    end

    def raised(cls)
      yield
      raise 'expected an error'
    rescue cls => e
      e
    end

    def ake
      yield
      raise 'expected an ActionKitError'
    rescue AtlasPca::Actions::ActionKitError => e
      [e.code, e.message]
    end

    def sym(x)
      case x
      when Hash then x.to_h { |k, v| [k.to_sym, sym(v)] }
      when Array then x.map { |v| sym(v) }
      else x
      end
    end

    def dd(x) = Marshal.load(Marshal.dump(x))

    # ---- fixtures ---------------------------------------------------------------------------------------------------

    def base
      { 'v' => 1, 'kind' => 'pca-action-def', 'verb' => 'acme.invoice.pay', 'title' => 'Pay', 'effects' => ['pay'],
        'resource' => { 'type' => 'invoice', 'id' => '*', 'scope' => 'one' }, 'params' => {}, 'review' => { 'state' => 'authored' } }
    end

    def vd
      d = base
      yield d if block_given?
      act.validate_def(d)
    end

    VERB_MSG = 'verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)'
    ID_MSG = "resource.id must be '*', {exact} or {prefix, class, len}"
    MIXED = { "\xC3\xA9".b => 1, 'ü' => 2 }.freeze # keys of two encodings: joining them unconverted raises

    KEY = OpenSSL::PKey.new_raw_private_key('ED25519', "\x07".b * 32)
    PK = AtlasPca.b64e(KEY.raw_public_key)
    PINS = { 'keys' => [{ 'kid' => 'rk', 'pk' => PK, 'roles' => ['reviewer'] }] }.freeze
    BOT = { 'risk' => 0, 'rev' => 'reversible', 'blast_ppm' => 0, 'esc' => 0, 'caveats' => [], 'context' => [], 'prules' => [] }.freeze

    def td = (@td ||= act.traits_digest(core))

    # a signed attestation (the signature covers review_message of the final fields unless `sig` is given)
    def att(over = {})
      x = { 'def_digest' => 'dd', 'traits_digest' => td, 'facts_digest' => 'ff', 'final_traits' => ['pca.bulk'], 'dismissed' => [],
            'reviewer_kid' => 'rk', 'ts' => 10 }.merge(over)
      x['sig'] = AtlasPca.b64e(KEY.sign(nil, act.review_message(x))) unless x.key?('sig')
      x
    end

    def ae(attn, dd: 'dd', pins: PINS, facts: nil, accept: true)
      act.attestation_error(attn, dd, core, pins, facts) { |_ft| accept }
    end

    def trait(id, implies = [], floor = act.profile, phrase = 'p') = { 'id' => id, 'implies' => implies, 'floor' => floor, 'card_phrase' => phrase }

    # levels 1..8, eight traits each, every trait implies all eight of the level below: depth 8, 8^7 paths to the bottom
    def diamond
      defs = (1..8).map { |j| trait("x.l1_#{j}") }
      (2..8).each { |k| (1..8).each { |j| defs << trait("x.l#{k}_#{j}", (1..8).map { |i| "x.l#{k - 1}_#{i}" }) } }
      defs
    end

    # a confirmed verb (traits are exactly the signed final traits)
    def cverb(over = {}, traits = [])
      v = { 'verb' => 'acme.x.y', 'effects' => ['update'], 'kind' => 'write', 'params' => {}, 'reversibility' => 'reversible',
            'traits' => traits, 'floors' => BOT.dup, 'def' => 'defd' }.merge(over)
      v['confirmation'] = att('def_digest' => 'defd', 'facts_digest' => 'ff', 'final_traits' => v['traits'])
      v
    end

    def svf_err(v)
      Seam.with(act, { facts_digest: ->(_v) { 'ff' } }) { act.schema_verb_floor_error(v, core, PINS) }
    end

    def confirmed_def
      d = base
      d['traits'] = ['pca.bulk']
      d['review'] = { 'state' => 'confirmed', 'attestation' => att('def_digest' => act.def_digest(d), 'final_traits' => ['pca.bulk']) }
      d
    end
  end

  # ======================================================================================================================
  # validate_def
  # ======================================================================================================================
  t('c01 actions: validate_def accepts the minimal def and a symbol-keyed copy of it (jsnorm)') do
    next true if C01Actions.skip?

    C01Actions.same('base', C01Actions.vd, nil) &&
      C01Actions.same('sym', C01Actions.act.validate_def(C01Actions.sym(C01Actions.base)), nil)
  end

  t('c01 actions: verb and alias limits are 128 bytes, resource.type 128 characters') do
    next true if C01Actions.skip?

    c = C01Actions
    v128 = "#{'a' * 32}.#{'b' * 32}.#{'c' * 32}.#{'d' * 29}"
    v129 = "#{v128}d"
    c.same('verb 128', c.vd { |d| d['verb'] = v128 }, nil)
    c.same('verb 129', c.vd { |d| d['verb'] = v129 }, C01Actions::VERB_MSG)
    c.same('verb int', c.vd { |d| d['verb'] = 5 }, C01Actions::VERB_MSG)
    c.same('verb null', c.vd { |d| d['verb'] = nil }, C01Actions::VERB_MSG)
    amsg = 'aliases must be distinct verb-shaped names other than the verb'
    c.same('alias 128', c.vd { |d| d['aliases'] = [v128] }, nil)
    c.same('alias 129', c.vd { |d| d['aliases'] = [v129] }, amsg)
    c.same('alias = verb', c.vd { |d| d['aliases'] = ['acme.invoice.pay'] }, amsg)
    c.same('alias int', c.vd { |d| d['aliases'] = [5] }, amsg)
    t128 = "#{'a' * 32}.#{'b' * 32}.#{'b' * 32}.#{'b' * 29}"
    c.same('type 128', c.vd { |d| d['resource']['type'] = t128 }, nil)
    c.same('type 129', c.vd { |d| d['resource']['type'] = "#{t128}b" }, 'resource.type is malformed')
    c.same('type int', c.vd { |d| d['resource']['type'] = 5 }, 'resource.type is malformed')
  end

  t('c01 actions: keys of two encodings are a shape error, never a fault (resource, side_effects, id pattern, attestation)') do
    next true if C01Actions.skip?

    c = C01Actions
    c.same('resource', c.vd { |d| d['resource'] = d['resource'].merge(C01Actions::MIXED) }, 'resource must be {type, id, scope}')
    c.same('side_effects', c.vd { |d| d['side_effects'] = [{ 'target' => 't', 'kind' => 'read' }.merge(C01Actions::MIXED)] },
           'side_effects must be {target, kind} entries')
    c.same('id', c.act.id_pattern_error(C01Actions::MIXED.dup), C01Actions::ID_MSG)
    at = { 'def_digest' => 'd', 'traits_digest' => 't', 'facts_digest' => 'f', 'reviewer_kid' => 'k', 'ts' => 1, 'final_traits' => [], 'dismissed' => [] }
    c.same('review ok', c.act.review_error({ 'state' => 'confirmed', 'attestation' => at }), nil)
    c.same('dismissed', c.act.review_error({ 'state' => 'confirmed', 'attestation' => at.merge('dismissed' => [C01Actions::MIXED.dup]) }),
           'review.attestation.dismissed must be {trait, reason} entries')
  end

  t('c01 actions: validate_def non-string operands that a type guard used to hide still refuse with the exact reason') do
    next true if C01Actions.skip?

    c = C01Actions
    pn = 'x'
    c.same('parent', c.vd { |d| d['params'] = { 'a' => { 'type' => 'string' }, 'a.b' => { 'type' => 'string' } } },
           "param 'a' is both a value and the parent of 'a.b'")
    c.same('sibling', c.vd { |d| d['params'] = { 'a' => { 'type' => 'string' }, 'ab' => { 'type' => 'string' } } }, nil)
    c.same('rev by int', c.vd { |d| d['params'] = { pn => { 'type' => 'boolean' } }; d['reversibility'] = { 'by' => 5, 'map' => { 'true' => 'reversible' } } },
           'reversibility.by must name a declared parameter')
    c.same('rev by ok', c.vd { |d| d['params'] = { pn => { 'type' => 'boolean' } }; d['reversibility'] = { 'by' => pn, 'map' => { 'true' => 'reversible' } } }, nil)
    idm = 'idempotency.param is required for key_param (a declared parameter) and forbidden otherwise'
    c.same('idem param int', c.vd { |d| d['idempotency'] = { 'mode' => 'key_param', 'param' => 5 } }, idm)
    c.same('idem param none', c.vd { |d| d['idempotency'] = { 'mode' => 'key_param' } }, idm)
    c.same('idem natural + param', c.vd { |d| d['idempotency'] = { 'mode' => 'natural', 'param' => 'x' } }, idm)
    c.same('compensates int', c.vd { |d| d['compensates'] = 5 }, 'compensates must be a verb')
    c.same('compensates ok', c.vd { |d| d['compensates'] = 'acme.invoice.void' }, nil)
    c.same('effects int', c.vd { |d| d['effects'] = [5] }, 'effects must be 1..12 distinct known effects')
    c.same('effects empty', c.vd { |d| d['effects'] = [] }, 'effects must be 1..12 distinct known effects')
    c.same('context int', c.vd { |d| d['context'] = [5] }, 'context must be distinct known context keys')
    c.same('context ok', c.vd { |d| d['context'] = ['session_taint_max:abc', 'revocable'] }, nil)
    c.same('traits int', c.vd { |d| d['traits'] = [5] }, 'traits must be distinct trait ids')
    c.same('sensitivity', c.vd { |d| d['params'] = { pn => { 'type' => 'string', 'sensitivity' => 'bogus' } } }, 'x: unknown sensitivity')
  end

  t('c01 actions: a fault inside validate_def is a malformed-def reason (seam)') do
    next true if C01Actions.skip?

    c = C01Actions
    Seam.with(c.act, { str?: ->(*) { raise 'boom' } }) { c.same('rescue', c.vd, 'malformed def: boom') }
  end

  # ======================================================================================================================
  # helpers: json profile, id patterns, params, bindings, review
  # ======================================================================================================================
  t('c01 actions: json_profile_error reads a binary-tagged UTF-8 string and member name, and refuses a non-JSON value exactly') do
    next true if C01Actions.skip?

    c = C01Actions
    pe = c.act.method(:json_profile_error)
    c.same('binary string', pe.call("\xC3\xA9".b), nil)
    c.same('binary key', pe.call({ "\xC3\xA9".b => 1 }), nil)
    c.same('nfd string', pe.call("é"), 'string is not NFC')
    c.same('nfd key', pe.call({ "é" => 1 }), 'member name is not NFC / has a lone surrogate')
    c.same('symbol', pe.call(:x), 'only JSON values are allowed')
    c.same('time', pe.call(Time.at(0)), 'only JSON values are allowed')
    c.same('nested symbol', pe.call([1, { 'a' => :x }]), 'only JSON values are allowed')
    c.same('float', pe.call(1.5), 'numbers must be safe integers (no floats, no -0)')
    c.same('null', pe.call(nil), nil)
    c.same('true', pe.call(true), nil)
    c.same('false', pe.call(false), nil)
    c.same('array ok', pe.call([1, 'a', nil]), nil)
    c.same('hash ok', pe.call({ 'a' => [1] }), nil)
    c.same('deep', pe.call((1..34).inject([]) { |acc, _| [acc] }), 'nesting deeper than 32')
  end

  t('c01 actions: role?, format? and context_key? refuse non-strings and lone surrogates') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    c.same('role ok', a.role?('money.amount'), true)
    c.same('role id', a.role?('id.user'), true)
    c.same('role custom', a.role?('x.acme.thing'), true)
    c.same('role int', a.role?(5), false)
    c.same('role nil', a.role?(nil), false)
    c.same('role array', a.role?(['money.amount']), false)
    c.same('format ok', a.format?('email'), true)
    c.same('format id', a.format?('id:user'), true)
    c.same('format int', a.format?(5), false)
    c.same('format array', a.format?(['email']), false)
    c.same('ctx ok', a.context_key?('revocable'), true)
    c.same('ctx taint', a.context_key?('session_taint_max:abc'), true)
    c.same('ctx int', a.context_key?(5), false)
    c.same('ctx lone', a.context_key?("\xED\xA0\x80".dup.force_encoding('UTF-8')), false)
    c.same('ctx unknown', a.context_key?('bogus'), false)
  end

  t('c01 actions: id_pattern_error refuses exact / prefix values that are not strings, with the exact reason') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    ex = 'resource.id.exact must be 1..128 safe characters'
    px = 'resource.id.prefix must be up to 32 safe characters'
    c.same('star', a.id_pattern_error('*'), nil)
    c.same('int', a.id_pattern_error(5), C01Actions::ID_MSG)
    c.same('exact ok', a.id_pattern_error({ 'exact' => 'abc' }), nil)
    c.same('exact 128', a.id_pattern_error({ 'exact' => 'a' * 128 }), nil)
    c.same('exact 129', a.id_pattern_error({ 'exact' => 'a' * 129 }), ex)
    c.same('exact empty', a.id_pattern_error({ 'exact' => '' }), ex)
    c.same('exact int', a.id_pattern_error({ 'exact' => 5 }), ex)
    c.same('exact nil', a.id_pattern_error({ 'exact' => nil }), ex)
    c.same('exact bad char', a.id_pattern_error({ 'exact' => 'a b' }), ex)
    c.same('prefix ok', a.id_pattern_error({ 'prefix' => 'ab', 'class' => 'digits', 'len' => [1, 2] }), nil)
    c.same('prefix int', a.id_pattern_error({ 'prefix' => 5, 'class' => 'digits', 'len' => [1, 2] }), px)
    c.same('prefix nil', a.id_pattern_error({ 'prefix' => nil, 'class' => 'digits', 'len' => [1, 2] }), px)
    c.same('prefix 33', a.id_pattern_error({ 'prefix' => 'a' * 33, 'class' => 'digits', 'len' => [1, 2] }), px)
    c.same('prefix 32', a.id_pattern_error({ 'prefix' => 'a' * 32, 'class' => 'digits', 'len' => [1, 2] }), nil)
    c.same('class', a.id_pattern_error({ 'prefix' => '', 'class' => 'x', 'len' => [1, 2] }), 'resource.id.class is not an id class')
  end

  t('c01 actions: param_error exact reasons for guarded operands, and nil on a valid parameter') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    c.same('valid', a.param_error('x', { 'type' => 'string' }, ['x']), nil)
    c.same('role string', a.param_error('x', { 'type' => 'string', 'role' => 'money.amount' }, ['x']), 'x: role money.amount requires an integer parameter')
    c.same('role int', a.param_error('x', { 'type' => 'integer', 'role' => 'money.amount' }, ['x']), nil)
    c.same('role non-int-role', a.param_error('x', { 'type' => 'string', 'role' => 'party.payee' }, ['x']), nil)
    c.same('items on string', a.param_error('x', { 'type' => 'string', 'items' => 'integer', 'min' => 1 }, ['x']),
           'x: min must be a safe integer on an integer parameter')
    c.same('items on array', a.param_error('x', { 'type' => 'array', 'items' => 'integer', 'min' => 1 }, ['x']), nil)
    c.same('array of strings min', a.param_error('x', { 'type' => 'array', 'items' => 'string', 'min' => 1 }, ['x']),
           'x: min must be a safe integer on an integer parameter')
    unit = ->(ccy) { { 'type' => 'integer', 'unit' => { 'kind' => 'money', 'exp' => 2, 'ccy' => ccy } } }
    fm = 'x: unit.ccy.from must name a declared parameter'
    c.same('ccy from undeclared', a.param_error('x', unit.call({ 'from' => 'cur' }), ['x']), fm)
    c.same('ccy from declared', a.param_error('x', unit.call({ 'from' => 'cur' }), %w[x cur]), nil)
    c.same('ccy from extra', a.param_error('x', unit.call({ 'from' => 'cur', 'z' => 1 }), %w[x cur]), fm)
    c.same('ccy from int', a.param_error('x', unit.call({ 'from' => 5 }), %w[x cur]), fm)
    c.same('ccy int', a.param_error('x', unit.call(5), %w[x cur]), fm)
    c.same('ccy iso', a.param_error('x', unit.call('USD'), ['x']), nil)
    c.same('ccy lower', a.param_error('x', unit.call('usd'), ['x']), 'x: unit.ccy must be an ISO 4217 style code')
    c.same('sensitivity ok', a.param_error('x', { 'type' => 'string', 'sensitivity' => 'critical' }, ['x']), nil)
    c.same('sensitivity bad', a.param_error('x', { 'type' => 'string', 'sensitivity' => 'bogus' }, ['x']), 'x: unknown sensitivity')
    c.same('sensitivity int', a.param_error('x', { 'type' => 'string', 'sensitivity' => 5 }, ['x']), 'x: unknown sensitivity')
    c.same('tags ok', a.param_error('x', { 'type' => 'string', 'tags' => %w[pii phi] }, ['x']), nil)
    c.same('tags dup', a.param_error('x', { 'type' => 'string', 'tags' => %w[pii pii] }, ['x']), 'x: tags must be distinct known tags')
    c.same('tags unknown', a.param_error('x', { 'type' => 'string', 'tags' => ['zzz'] }, ['x']), 'x: tags must be distinct known tags')
  end

  t('c01 actions: bindings_error and review_error answer exactly nil on a valid input') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    c.same('bindings empty', a.bindings_error({}), nil)
    c.same('bindings mcp', a.bindings_error({ 'mcp' => { 'tool' => 't' } }), nil)
    c.same('bindings graphql', a.bindings_error({ 'graphql' => { 'op' => 'bogus', 'field' => 'f' } }), 'bindings.graphql.op is not a GraphQL operation kind')
    c.same('review authored', a.review_error({ 'state' => 'authored' }), nil)
    c.same('review not hash', a.review_error(nil), 'review must be an object')
  end

  # ======================================================================================================================
  # profile lattice + registry
  # ======================================================================================================================
  t('c01 actions: leq is false as soon as any one component of p exceeds q, and true otherwise') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    q = a.profile('risk' => 1, 'rev' => 'rate_limited', 'blast_ppm' => 10, 'esc' => 1, 'caveats' => ['count_cap'], 'context' => ['revocable'], 'prules' => ['bulk'])
    c.same('equal', a.leq(q.dup, q), true)
    c.same('bottom', a.leq(a.profile, q), true)
    c.same('risk', a.leq(q.merge('risk' => 2), q), false)
    c.same('rev', a.leq(q.merge('rev' => 'irreversible'), q), false)
    c.same('blast', a.leq(q.merge('blast_ppm' => 11), q), false)
    c.same('esc', a.leq(q.merge('esc' => 2), q), false)
    c.same('caveats', a.leq(q.merge('caveats' => %w[count_cap rate_cap]), q), false)
    c.same('context', a.leq(q.merge('context' => %w[revocable sandbox_attested]), q), false)
    c.same('prules', a.leq(q.merge('prules' => %w[array_bounded bulk]), q), false)
    c.same('lower rev', a.leq(q.merge('rev' => 'reversible'), q), true)
  end

  t('c01 actions: profile_error requires sorted distinct lists') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    c.same('bottom', a.profile_error(a.profile), nil)
    c.same('sorted', a.profile_error(a.profile.merge('caveats' => %w[count_cap rate_cap])), nil)
    c.same('unsorted', a.profile_error(a.profile.merge('caveats' => %w[rate_cap count_cap])), 'profile.caveats must be sorted and distinct')
    c.same('dup', a.profile_error(a.profile.merge('prules' => %w[array_bounded array_bounded])), 'profile.prules must be sorted and distinct')
    c.same('unknown rule', a.profile_error(a.profile.merge('prules' => %w[bulk])), 'profile.prules must be an array of known prules entries')
    c.same('dup ctx', a.profile_error(a.profile.merge('context' => %w[revocable revocable])), 'profile.context must be sorted and distinct')
  end

  t('c01 actions: registry_error and build_registry: pca. is reserved by default, depth is 8, memoised walk, cycles') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    c.same('ok', a.registry_error([c.trait('x.a')]), nil)
    c.same('pca default', a.registry_error([c.trait('pca.zz')]), "trait 'pca.zz': the pca. namespace is reserved for core traits")
    c.same('pca core', a.registry_error([c.trait('pca.zz')], core: true), nil)
    c.same('bad id', a.registry_error([c.trait('X')]), "trait id 'X' is malformed")
    c.same('int id', a.registry_error([c.trait(5)]), "trait id '5' is malformed")
    c.same('nil id', a.registry_error([c.trait(nil)]), "trait id 'null' is malformed")
    chain = ->(n) { (1..n).map { |i| c.trait("x.t#{i}", i == 1 ? [] : ["x.t#{i - 1}"]) } }
    c.same('depth 8', a.registry_error(chain.call(8)), nil)
    c.same('depth 9', a.registry_error(chain.call(9)), "trait 'x.t9': implies depth 9 exceeds 8")
    c.same('cycle', a.registry_error([c.trait('x.a', ['x.b']), c.trait('x.b', ['x.a'])]), "trait 'x.a': implies cycle")
    c.same('self cycle', a.registry_error([c.trait('x.a', ['x.a'])]), "trait 'x.a': implies cycle")
    c.same('shared child', a.registry_error([c.trait('x.z'), c.trait('x.a', ['x.z']), c.trait('x.b', ['x.z']), c.trait('x.c', %w[x.a x.b])]), nil)
    c.same('build pca', c.ake { a.build_registry([c.trait('pca.zz')]) }, ['bad_registry', "trait 'pca.zz': the pca. namespace is reserved for core traits"])
    c.same('build core', a.build_registry([c.trait('pca.zz')], core: true).keys, ['pca.zz'])
    r = Timeout.timeout(2) { a.registry_error(c.diamond) }
    c.same('diamond', r, nil)
  end

  t('c01 actions: extend_registry accepts symbol keys, refuses a non-array and any redefinition with the exact reason') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    reg = a.extend_registry(c.core, [C01Actions.sym(c.trait('x.symk', [], C01Actions::BOT.dup))])
    c.same('symbols', reg.key?('x.symk') && reg.length == c.core.length + 1, true)
    c.same('not array hash', c.ake { a.extend_registry(c.core, {}) }, ['bad_registry', 'custom traits must be an array'])
    c.same('not array nil', c.ake { a.extend_registry(c.core, nil) }, ['bad_registry', 'custom traits must be an array'])
    redef = ->(id) { "custom trait '#{id}' may not redefine a core trait" }
    c.same('non-hash', c.ake { a.extend_registry(c.core, [5]) }, ['bad_registry', redef.call('5')])
    c.same('no id', c.ake { a.extend_registry(c.core, [{}]) }, ['bad_registry', redef.call('undefined')])
    c.same('id nil', c.ake { a.extend_registry(c.core, [{ 'id' => nil }]) }, ['bad_registry', redef.call('null')])
    c.same('id int', c.ake { a.extend_registry(c.core, [{ 'id' => 5 }]) }, ['bad_registry', redef.call('5')])
    c.same('core id', c.ake { a.extend_registry(c.core, [{ 'id' => 'pca.bulk' }]) }, ['bad_registry', redef.call('pca.bulk')])
    c.same('pca. new', c.ake { a.extend_registry(c.core, [{ 'id' => 'pca.newone' }]) }, ['bad_registry', redef.call('pca.newone')])
    own = a.build_registry([c.trait('x.a')])
    c.same('base id', c.ake { a.extend_registry(own, [{ 'id' => 'x.a' }]) }, ['bad_registry', redef.call('x.a')])
  end

  t('c01 actions: closure is the sorted set of implied traits; an unknown id is an unknown_trait error; the walk is memoised') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    c.same('impersonation', a.closure(c.core, ['pca.impersonation']), %w[pca.external_communication pca.impersonation])
    c.same('dup ids', a.closure(c.core, %w[pca.bulk pca.bulk]), ['pca.bulk'])
    c.same('empty', a.closure(c.core, []), [])
    c.same('unknown', c.ake { a.closure(c.core, ['x.nope']) }, ['unknown_trait', "unknown trait 'x.nope'"])
    c.same('nil', c.ake { a.closure(c.core, [nil]) }, ['unknown_trait', "unknown trait 'null'"])
    c.same('array', c.ake { a.closure(c.core, [%w[a b]]) }, ['unknown_trait', "unknown trait 'a,b'"])
    c.same('int', c.ake { a.closure(c.core, [5]) }, ['unknown_trait', "unknown trait '5'"])
    reg = a.build_registry(c.diamond)
    got = Timeout.timeout(2) { a.closure(reg, ['x.l8_1'] * 8) }
    c.same('diamond size', got.length, 57)
  end

  # ======================================================================================================================
  # sensitivity, reversibility, normalize
  # ======================================================================================================================
  t('c01 actions: read_only?, sensitivity_floor and max_rev') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    c.same('ro empty', a.read_only?([]), false)
    c.same('ro read', a.read_only?(['read']), true)
    c.same('ro mixed', a.read_only?(%w[read pay]), false)
    c.same('sens none', a.sensitivity_floor({}), 'free')
    c.same('sens unknown tag', a.sensitivity_floor({ 'tags' => ['bogus'] }), 'free')
    c.same('sens pii', a.sensitivity_floor({ 'tags' => ['pii'] }), 'material')
    c.same('sens secret', a.sensitivity_floor({ 'tags' => %w[pii secret] }), 'critical')
    c.same('sens role', a.sensitivity_floor({ 'role' => 'money.amount', 'tags' => ['pii'] }), 'critical')
    c.same('rev none', a.max_rev([]), 'reversible')
    c.same('rev unknown', a.max_rev(['bogus']), 'reversible')
    c.same('rev unknown mid', a.max_rev(['rate_limited', 'bogus']), 'rate_limited')
    c.same('rev rl', a.max_rev(%w[rate_limited reversible]), 'rate_limited')
    c.same('rev irr', a.max_rev(%w[irreversible rate_limited]), 'irreversible')
  end

  t('c01 actions: worst_reversibility over booleans, string values and a non-hash parameter') do
    next true if C01Actions.skip?

    c = C01Actions
    w = c.act.method(:worst_reversibility)
    bool = { 'p' => { 'type' => 'boolean' } }
    both = { 'true' => 'reversible', 'false' => 'reversible' }
    c.same('string', w.call('rate_limited', {}), 'rate_limited')
    c.same('covered', w.call({ 'by' => 'p', 'map' => both }, bool), 'reversible')
    c.same('half', w.call({ 'by' => 'p', 'map' => { 'true' => 'reversible' } }, bool), 'irreversible')
    c.same('default', w.call({ 'by' => 'p', 'map' => { 'true' => 'reversible' }, 'default' => 'rate_limited' }, bool), 'rate_limited')
    c.same('mixed', w.call({ 'by' => 'p', 'map' => { 'true' => 'irreversible', 'false' => 'reversible' } }, bool), 'irreversible')
    sv = { 'p' => { 'type' => 'string', 'values' => %w[a b] } }
    c.same('values covered', w.call({ 'by' => 'p', 'map' => { 'a' => 'reversible', 'b' => 'rate_limited' } }, sv), 'rate_limited')
    c.same('values half', w.call({ 'by' => 'p', 'map' => { 'a' => 'reversible' } }, sv), 'irreversible')
    c.same('string no values', w.call({ 'by' => 'p', 'map' => { 'a' => 'reversible' } }, { 'p' => { 'type' => 'string' } }), 'irreversible')
    c.same('integer is no domain', w.call({ 'by' => 'p', 'map' => { 'a' => 'reversible' } }, { 'p' => { 'type' => 'integer', 'values' => ['a'] } }), 'irreversible')
    c.same('undeclared', w.call({ 'by' => 'zz', 'map' => both }, bool), 'irreversible')
    c.same('array param', w.call({ 'by' => 'p', 'map' => { 'a' => 'reversible' } }, { 'p' => [] }), 'irreversible')
    c.same('int param', w.call({ 'by' => 'p', 'map' => { 'a' => 'reversible' } }, { 'p' => 5 }), 'irreversible')
  end

  t('c01 actions: normalize: symbol keys, UTF-16 side-effect order, hash reversibility, money accumulates, deep copies') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    c.same('symbols', a.normalize(c.sym(c.base)), a.normalize(c.base))
    d = c.base
    d['side_effects'] = [{ 'target' => "￿", 'kind' => 'read' }, { 'target' => "\u{10000}", 'kind' => 'read' },
                         { 'target' => 't', 'kind' => 'send' }, { 'target' => 't', 'kind' => 'read' }]
    c.same('side effects', a.normalize(d)['side_effects'],
           [{ 'target' => 't', 'kind' => 'read' }, { 'target' => 't', 'kind' => 'send' }, { 'target' => "\u{10000}", 'kind' => 'read' }, { 'target' => "￿", 'kind' => 'read' }])
    d = c.base
    d['reversibility'] = { 'by' => 'p', 'map' => { 'x' => 'reversible' }, 'extra' => 1 }
    c.same('rev hash', a.normalize(d)['reversibility'], { 'by' => 'p', 'map' => { 'x' => 'reversible' } })
    d['reversibility']['default'] = 'rate_limited'
    c.same('rev hash default', a.normalize(d)['reversibility'], { 'by' => 'p', 'map' => { 'x' => 'reversible' }, 'default' => 'rate_limited' })
    d = c.base
    d['reversibility'] = 'rate_limited'
    c.same('rev string', a.normalize(d)['reversibility'], 'rate_limited')
    money = ->(unit, over = {}) { c.base.tap { |b| b['params'] = { 'a' => { 'type' => 'integer', 'role' => 'money.amount', 'unit' => unit }.merge(over) } } }
    pa = ->(dd) { a.normalize(dd)['params']['a'] }
    c.same('accumulates', pa.call(money.call({ 'kind' => 'money', 'exp' => 2, 'ccy' => 'USD' }))['accumulates'], ['money.usd'])
    c.same('sensitivity', pa.call(money.call({ 'kind' => 'money', 'exp' => 2, 'ccy' => 'USD' }))['sensitivity'], 'critical')
    c.same('required', pa.call(money.call({ 'kind' => 'money', 'exp' => 2, 'ccy' => 'USD' }))['required'], true)
    c.same('not money unit', pa.call(money.call({ 'kind' => 'count', 'ccy' => 'USD' })).key?('accumulates'), false)
    c.same('ccy ref', pa.call(money.call({ 'kind' => 'money', 'exp' => 2, 'ccy' => { 'from' => 'c' } })).key?('accumulates'), false)
    c.same('unit array', pa.call(money.call([])).key?('accumulates'), false)
    c.same('unit nil', pa.call(money.call(nil)).key?('accumulates'), false)
    c.same('explicit', pa.call(money.call({ 'kind' => 'money', 'exp' => 2, 'ccy' => 'USD' }, 'accumulates' => %w[b a b]))['accumulates'], %w[a b])
    nest = ->(leaf, wrap) { 70.times.inject(leaf) { |acc, _| wrap.call(acc) } }
    dh = c.base
    dh['params'] = { 'ph' => { 'type' => 'string', 'default' => nest.call(1, ->(x) { { 'a' => x } }) },
                     'pa' => { 'type' => 'string', 'default' => nest.call(1, ->(x) { [x] }) } }
    n = a.normalize(dh)
    walk = lambda do |node, key|
      66.times { node = node[key] }
      node
    end
    c.same('hash copy', walk.call(n['params']['ph']['default'], 'a').equal?(walk.call(dh['params']['ph']['default'], 'a')), false)
    c.same('hash content', n['params']['ph']['default'] == dh['params']['ph']['default'], true)
    c.same('array copy', walk.call(n['params']['pa']['default'], 0).equal?(walk.call(dh['params']['pa']['default'], 0)), false)
    c.same('array content', n['params']['pa']['default'] == dh['params']['pa']['default'], true)
  end

  # ======================================================================================================================
  # pack
  # ======================================================================================================================
  t('c01 actions: pack digests: duplicate / empty / missing are exact action-kit errors; inclusion proofs verify and terminate') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    c.same('sorted', a.sorted_digests(%w[b a]), %w[a b])
    c.same('dup', c.ake { a.sorted_digests(%w[a a]) }, ['duplicate_def', 'a pack lists a def digest twice'])
    c.same('empty', c.ake { a.sorted_digests([]) }, ['empty_pack', 'a pack has at least one def'])
    c.same('root empty', c.ake { a.pack_root([]) }, ['empty_pack', 'a pack has at least one def'])
    c.same('missing', c.ake { a.pack_proof(%w[a b], 'c') }, ['not_in_pack', 'the digest is not in the pack'])
    (1..6).each do |n|
      ds = (1..n).map { |i| "d#{i}" }
      root = a.pack_root(ds)
      ds.each do |d|
        pr = Timeout.timeout(2) { a.pack_proof(ds, d) }
        c.same("size #{n}", pr['size'], n)
        c.same("index #{n} #{d}", pr['index'], ds.sort_by(&:b).index(d))
        c.same("verify #{n} #{d}", a.verify_pack_proof(root, pr, d), true)
        c.same("verify other #{n} #{d}", a.verify_pack_proof(root, pr, 'zz'), false)
      end
    end
  end

  # ======================================================================================================================
  # reviewer pins, review message, attestations
  # ======================================================================================================================
  t('c01 actions: blank_reason? needs a valid string and reads binary-tagged UTF-8') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    c.same('empty', a.blank_reason?(''), true)
    c.same('spaces', a.blank_reason?(" \t\n"), true)
    c.same('nbsp', a.blank_reason?(" "), true)
    c.same('nbsp binary', a.blank_reason?(" ".b), true)
    c.same('word', a.blank_reason?('a'), false)
    c.same('int', a.blank_reason?(5), false)
    c.same('nil', a.blank_reason?(nil), false)
    c.same('lone surrogate', a.blank_reason?("\xED\xA0\x80".dup.force_encoding('UTF-8')), false)
    c.same('binary non-blank', a.blank_reason?("\xC3\xA9".b), false)
  end

  t('c01 actions: reviewer_pins_error: an importer or model key cannot hold the reviewer role') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    pin = ->(roles) { { 'keys' => [{ 'kid' => 'k', 'pk' => C01Actions::PK, 'roles' => roles }] } }
    em = "key 'k': an importer or model key cannot hold the reviewer role"
    c.same('reviewer', a.reviewer_pins_error(pin.call(['reviewer'])), nil)
    c.same('importer', a.reviewer_pins_error(pin.call(['importer'])), nil)
    c.same('model', a.reviewer_pins_error(pin.call(['model'])), nil)
    c.same('reviewer+importer', a.reviewer_pins_error(pin.call(%w[reviewer importer])), em)
    c.same('reviewer+model', a.reviewer_pins_error(pin.call(%w[reviewer model])), em)
    c.same('not hash key', a.reviewer_pins_error({ 'keys' => [5] }), 'a pinned key needs a kid')
    c.same('no keys', a.reviewer_pins_error({}), 'pins must be {keys: [...]}')
    c.same('twice', a.reviewer_pins_error({ 'keys' => [pin.call(['reviewer'])['keys'][0]] * 2 }), "kid 'k' is pinned twice")
  end

  t('c01 actions: review_message is the domain, a NUL and the canonical body, as bytes, dismissals and final traits sorted') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    b = { 'def_digest' => 'd', 'traits_digest' => 't', 'facts_digest' => 'f', 'final_traits' => %w[b.x a.x a.x],
          'dismissed' => [{ 'trait' => 'z.t', 'reason' => 'r1', 'x' => 1 }, { 'trait' => 'a.t', 'reason' => 'r2' }], 'reviewer_kid' => 'k', 'ts' => 7 }
    want = "atlas-pca/action-review/v2\0".b + AtlasPca.canon_bytes({ 'def_digest' => 'd', 'traits_digest' => 't', 'facts_digest' => 'f',
                                                                      'final_traits' => %w[a.x b.x],
                                                                      'dismissed' => [{ 'trait' => 'a.t', 'reason' => 'r2' }, { 'trait' => 'z.t', 'reason' => 'r1' }],
                                                                      'reviewer_kid' => 'k', 'ts' => 7 })
    got = a.review_message(b)
    c.same('bytes', got, want)
    c.same('encoding', got.encoding, Encoding::BINARY)
    c.same('domain', got.start_with?("atlas-pca/action-review/v2\0".b), true)
  end

  t('c01 actions: attestation_error: every refusal has its exact reason, a good one is nil') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.att
    c.same('good', c.ae(a), nil)
    c.same('no pins', c.ae(a, pins: nil), 'no reviewer keys are pinned')
    c.same('bad pins', c.ae(a, pins: {}), 'bad pins: pins must be {keys: [...]}')
    c.same('attn nil', c.ae(nil), 'no attestation')
    c.same('attn int', c.ae(5), 'no attestation')
    c.same('unsigned', c.ae(a.reject { |k, _| k == 'sig' }), 'the attestation is unsigned')
    c.same('sig int', c.ae(a.merge('sig' => 5)), 'the attestation is unsigned')
    dm = 'the attestation covers a different def digest'
    c.same('def other', c.ae(a, dd: 'other'), dm)
    c.same('def nil', c.ae({ 'sig' => 'x' }, dd: nil), dm)
    c.same('def int', c.ae(a.merge('def_digest' => 5), dd: 5), dm)
    c.same('digests {}', c.ae(a, pins: C01Actions::PINS.merge('traits_digests' => {})), 'bad pins: traits_digests')
    c.same('digests int', c.ae(a, pins: C01Actions::PINS.merge('traits_digests' => 5)), 'bad pins: traits_digests')
    zz = c.att('traits_digest' => 'zz')
    c.same('registry', c.ae(zz), 'the attestation was made against a different trait registry')
    c.same('registry pinned', c.ae(zz, pins: C01Actions::PINS.merge('traits_digests' => ['zz'])), nil)
    fm = 'the verb facts differ from the facts the reviewer confirmed'
    c.same('facts same', c.ae(a, facts: 'ff'), nil)
    c.same('facts other', c.ae(a, facts: 'other'), fm)
    c.same('facts int', c.ae(c.att('facts_digest' => 5, 'sig' => 'x')), fm)
    mal = ->(over) { c.ae(a.merge(over).merge('sig' => 'x')) }
    c.same('ft int', mal.call('final_traits' => 5), 'malformed attestation')
    c.same('ft elem', mal.call('final_traits' => [1]), 'malformed attestation')
    c.same('dm nil', mal.call('dismissed' => nil), 'malformed attestation')
    c.same('ts str', mal.call('ts' => 'x'), 'malformed attestation')
    c.same('kid int', mal.call('reviewer_kid' => 5), 'malformed attestation')
    c.same('not accepted', c.ae(a, accept: false), 'the final traits are not accepted')
    c.same('dm int', mal.call('dismissed' => [5]), 'malformed attestation')
    c.same('dm empty hash', mal.call('dismissed' => [{}]), 'malformed attestation')
    c.same('dm trait int', mal.call('dismissed' => [{ 'trait' => 5, 'reason' => 'r' }]), 'malformed attestation')
    c.same('dm reason int', mal.call('dismissed' => [{ 'trait' => 'x.y', 'reason' => 5 }]), 'malformed attestation')
    fin = 'a dismissed trait is also final, or has no reason'
    c.same('dm final', c.ae(c.att('dismissed' => [{ 'trait' => 'pca.bulk', 'reason' => 'because' }])), fin)
    c.same('dm blank', c.ae(c.att('dismissed' => [{ 'trait' => 'pca.x', 'reason' => '  ' }])), fin)
    c.same('dm empty reason', c.ae(c.att('dismissed' => [{ 'trait' => 'pca.x', 'reason' => '' }])), fin)
    c.same('dm ok', c.ae(c.att('dismissed' => [{ 'trait' => 'pca.agent_spawning', 'reason' => 'fine' }])), nil)
    c.same('unknown kid', c.ae(c.att('reviewer_kid' => 'zz')), "no pinned key 'zz'")
    imp = { 'keys' => [{ 'kid' => 'rk', 'pk' => C01Actions::PK, 'roles' => ['importer'] }] }
    c.same('not reviewer', c.ae(a, pins: imp), "key 'rk' does not hold the reviewer role")
    win = ->(extra) { { 'keys' => [{ 'kid' => 'rk', 'pk' => C01Actions::PK, 'roles' => ['reviewer'] }.merge(extra)] } }
    om = 'the attestation time is outside the key validity'
    c.same('before', c.ae(a, pins: win.call('not_before' => 11)), om)
    c.same('at not_before', c.ae(a, pins: win.call('not_before' => 10)), nil)
    c.same('after', c.ae(a, pins: win.call('not_after' => 9)), om)
    c.same('at not_after', c.ae(a, pins: win.call('not_after' => 10)), nil)
    c.same('bad sig', c.ae(c.att('sig' => AtlasPca.b64e(C01Actions::KEY.sign(nil, 'other')))), 'the attestation signature is invalid')
    c.same('sig garbage', c.ae(c.att('sig' => 'x')), 'the attestation signature is invalid')
    Seam.with(c.act, { traits_digest: ->(_r) { raise 'boom' } }) { c.same('rescue', c.ae(a), 'malformed attestation: boom') }
  end

  t('c01 actions: def_confirmation_error: confirmed only by a signed attestation over this def; faults are malformed-def reasons') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    ns = 'review.state is not confirmed'
    d = c.confirmed_def
    c.same('confirmed', a.def_confirmation_error(d, c.core, C01Actions::PINS), nil)
    c.same('no pins', a.def_confirmation_error(d, c.core, nil), 'no reviewer keys are pinned')
    c.same('nil def', a.def_confirmation_error(nil, c.core, C01Actions::PINS), ns)
    c.same('array def', a.def_confirmation_error([], c.core, C01Actions::PINS), ns)
    c.same('no review', a.def_confirmation_error({}, c.core, C01Actions::PINS), ns)
    c.same('review array', a.def_confirmation_error({ 'review' => [] }, c.core, C01Actions::PINS), ns)
    c.same('review string', a.def_confirmation_error({ 'review' => 'x' }, c.core, C01Actions::PINS), ns)
    c.same('authored', a.def_confirmation_error(d.merge('review' => { 'state' => 'authored' }), c.core, C01Actions::PINS), ns)
    c.same('traits differ', a.def_confirmation_error(d.merge('traits' => ['pca.bulk', 'pca.pii_access']), c.core, C01Actions::PINS), 'the attestation covers a different def digest')
    Seam.with(a, { def_digest: ->(_d) { raise 'boom' } }) { c.same('rescue', a.def_confirmation_error(d, c.core, C01Actions::PINS), 'malformed def: boom') }
  end

  t('c01 actions: verb_confirmation_error: the signed final traits must all be carried by the verb') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    mk = lambda do |traits, ft|
      v = { 'verb' => 'acme.x.y', 'effects' => ['update'], 'traits' => traits, 'floors' => {}, 'def' => 'defd' }
      v['confirmation'] = c.att('def_digest' => 'defd', 'facts_digest' => a.facts_digest(v), 'final_traits' => ft)
      v
    end
    nacc = 'the final traits are not accepted'
    c.same('carried', a.verb_confirmation_error(mk.call(['pca.bulk'], ['pca.bulk']), c.core, C01Actions::PINS), nil)
    c.same('superset', a.verb_confirmation_error(mk.call(%w[pca.bulk pca.pii_access], ['pca.bulk']), c.core, C01Actions::PINS), nil)
    c.same('missing', a.verb_confirmation_error(mk.call([], ['pca.bulk']), c.core, C01Actions::PINS), nacc)
    c.same('traits nil', a.verb_confirmation_error(mk.call(nil, []), c.core, C01Actions::PINS), nacc)
    c.same('traits string', a.verb_confirmation_error(mk.call('pca.bulk', []), c.core, C01Actions::PINS), nacc)
    built = mk.call([], [])
    Seam.with(a, { facts_digest: ->(_v) { raise 'boom' } }) do
      c.same('rescue', a.verb_confirmation_error(built, c.core, C01Actions::PINS), 'malformed confirmation: boom')
    end
  end

  t('c01 actions: effective reads a symbol-keyed confirmed def; unconfirmed means every trait of the registry') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    d = c.confirmed_def
    e = a.effective(c.sym(d), c.core, C01Actions::PINS)
    c.same('confirmed', e['confirmed'], true)
    c.same('traits', e['traits'], %w[pca.bulk pca.irreversible pca.money_moving])
    c.same('closure', e['closure'], a.closure(c.core, e['traits']))
    c.same('floor', e['floor'], a.floor_of(c.core, e['traits']))
    c.same('eff', e['eff'], a.join(a.decl_profile(d), e['floor']))
    u = a.effective(d, c.core)
    c.same('unconfirmed', u['confirmed'], false)
    c.same('all traits', u['traits'], a.top_traits(c.core))
    c.same('all floor', u['floor'], a.floor_of(c.core, a.top_traits(c.core)))
    c.same('wrong pins', a.effective(d, c.core, { 'keys' => [] })['confirmed'], false)
  end

  # ======================================================================================================================
  # rule 22: SvfJS helpers
  # ======================================================================================================================
  t('c01 actions: SvfJS.get / entries / values / own? / iter read like JavaScript') do
    next true if C01Actions.skip?

    c = C01Actions
    s = c.svf
    u = AtlasPca::V2JS::UNDEF
    c.same('get null', c.raised(TypeError) { s.get(nil, 'a') }.message, "Cannot read properties of null (reading 'a')")
    c.same('get undef', c.raised(TypeError) { s.get(u, 'b') }.message, "Cannot read properties of undefined (reading 'b')")
    c.same('get own', s.get({ 'a' => 1 }, 'a'), 1)
    c.same('get missing', s.get({}, 'a').equal?(u), true)
    c.same('get int', s.get(5, 'a').equal?(u), true)
    cm = 'Cannot convert undefined or null to object'
    c.same('entries nil', c.raised(TypeError) { s.entries(nil) }.message, cm)
    c.same('entries undef', c.raised(TypeError) { s.entries(u) }.message, cm)
    c.same('entries hash', s.entries({ 'a' => 1, 'b' => 2 }).map { |k, v| [k, v] }, [['a', 1], ['b', 2]])
    c.same('entries array', s.entries(%w[x y]), [%w[0 x], %w[1 y]])
    c.same('entries string', s.entries('aé'), [%w[0 a], %w[1 é]])
    c.same('entries string enc', s.entries('aé').map { |_, x| x.encoding }, [Encoding::UTF_8, Encoding::UTF_8])
    c.same('entries binary string', s.entries("a\xC3\xA9".b), [%w[0 a], %w[1 é]])
    c.same('entries int', s.entries(5), [])
    c.same('values hash', s.values({ 'a' => 1, 'b' => 2 }), [1, 2])
    c.same('values array', s.values([3, 4]), [3, 4])
    c.same('own nil', c.raised(TypeError) { s.own?(nil, 'a') }.message, cm)
    c.same('own undef', c.raised(TypeError) { s.own?(u, 'a') }.message, cm)
    c.same('own hash yes', s.own?({ 'a' => 1 }, 'a'), true)
    c.same('own hash no', s.own?({ 'a' => 1 }, 'b'), false)
    c.same('own hash nil value', s.own?({ 'a' => nil }, 'a'), true)
    c.same('own array length', s.own?([1, 2], 'length'), true)
    c.same('own array 0', s.own?([1, 2], '0'), true)
    c.same('own array 1', s.own?([1, 2], '1'), true)
    c.same('own array 2', s.own?([1, 2], '2'), false)
    c.same('own array -1', s.own?([1, 2], '-1'), false)
    c.same('own array 01', s.own?([1, 2], '01'), false)
    c.same('own array x', s.own?([1, 2], 'x'), false)
    c.same('own empty 0', s.own?([], '0'), false)
    c.same('own array lone', s.own?([1], "\xED\xA0\x80".dup.force_encoding('UTF-8')), false)
    c.same('own string length', s.own?('ab', 'length'), true)
    c.same('own string 1', s.own?('ab', '1'), true)
    c.same('own string 2', s.own?('ab', '2'), false)
    c.same('own string word', s.own?('ab', 'ab'), false)
    c.same('own int', s.own?(5, 'a'), false)
    c.same('iter array', s.iter([1]), [1])
    c.same('iter string', s.iter('aé'), %w[a é])
    im = 'object is not iterable (cannot read property Symbol(Symbol.iterator))'
    c.same('iter hash', c.raised(TypeError) { s.iter({}) }.message, im)
    c.same('iter int', c.raised(TypeError) { s.iter(5) }.message, im)
    c.same('iter nil', c.raised(TypeError) { s.iter(nil) }.message, im)
  end

  t('c01 actions: SvfJS.num is JavaScript ToNumber') do
    next true if C01Actions.skip?

    c = C01Actions
    n = c.svf.method(:num)
    nan = Float::NAN
    c.numf('nil', n.call(nil), 0.0)
    c.numf('false', n.call(false), 0.0)
    c.numf('true', n.call(true), 1.0)
    c.numf('int', n.call(5), 5.0)
    c.numf('float', n.call(2.5), 2.5)
    c.numf('empty array', n.call([]), 0.0)
    c.numf('array 5', n.call([5]), 5.0)
    c.numf('array 2', n.call(%w[1 2]), nan)
    c.numf('hash', n.call({}), nan)
    c.numf('empty', n.call(''), 0.0)
    c.numf('blank', n.call("   \n"), 0.0)
    c.numf('padded', n.call(' 12 '), 12.0)
    c.numf('binary nbsp', n.call(" 5".b), 5.0)
    c.numf('lone surrogate', n.call("\xED\xA0\x80".dup.force_encoding('UTF-8')), nan)
    c.numf('hex upper', n.call('0x1F'), 31.0)
    c.numf('hex lower', n.call('0xff'), 255.0)
    c.numf('bin', n.call('0b101'), 5.0)
    c.numf('bin upper', n.call('0B11'), 3.0)
    c.numf('oct', n.call('0o17'), 15.0)
    c.numf('bad bin', n.call('0b12'), nan)
    c.numf('bad oct', n.call('0o8'), nan)
    c.numf('bad hex', n.call('0xg'), nan)
    c.numf('inf', n.call('Infinity'), Float::INFINITY)
    c.numf('+inf', n.call('+Infinity'), Float::INFINITY)
    c.numf('-inf', n.call('-Infinity'), -Float::INFINITY)
    c.numf('exp', n.call('1e3'), 1000.0)
    c.numf('lead dot', n.call('.5'), 0.5)
    c.numf('neg lead dot', n.call('-.5'), -0.5)
    c.numf('plus', n.call('+5'), 5.0)
    c.numf('plus dot', n.call('+.5'), 0.5)
    c.numf('trail dot', n.call('5.'), 5.0)
    c.numf('underscore', n.call('1_0'), nan)
    c.numf('word', n.call('abc'), nan)
    c.numf('bare e', n.call('1e'), nan)
    c.numf('two numbers', n.call('1 2'), nan)
  end

  t('c01 actions: SvfJS.includes?, rank and leq') do
    next true if C01Actions.skip?

    c = C01Actions
    s = c.svf
    u = AtlasPca::V2JS::UNDEF
    c.same('array yes', s.includes?(%w[a b], 'a'), true)
    c.same('array no', s.includes?(%w[a b], 'c'), false)
    c.same('array non-string', s.includes?([5], '5'), false)
    c.same('array bytes', s.includes?(["é"], "é".b), true)
    c.same('string yes', s.includes?('abc', 'b'), true)
    c.same('string no', s.includes?('abc', 'd'), false)
    c.same('string bytes', s.includes?("é", "é".b), true)
    c.same('string bytes 2', s.includes?("é".b, "é"), true)
    c.same('nil', c.raised(TypeError) { s.includes?(nil, 'a') }.message, "Cannot read properties of null (reading 'includes')")
    c.same('undef', c.raised(TypeError) { s.includes?(u, 'a') }.message, "Cannot read properties of undefined (reading 'includes')")
    c.same('int', c.raised(TypeError) { s.includes?(5, 'a') }.message, 'b.includes is not a function')
    c.same('hash', c.raised(TypeError) { s.includes?({}, 'a') }.message, 'b.includes is not a function')
    c.same('rank nil', s.rank(nil), nil)
    c.same('rank undef', s.rank(u), nil)
    c.same('rank hash', s.rank({}), nil)
    c.same('rank unknown', s.rank('bogus'), nil)
    c.same('rank rev', s.rank('reversible'), 0)
    c.same('rank array', s.rank(['rate_limited']), 1)
    c.same('rank irr', s.rank('irreversible'), 2)
    pf = { 'risk' => 1, 'rev' => 'rate_limited', 'blast_ppm' => 5, 'esc' => 1, 'caveats' => ['count_cap'], 'context' => ['revocable'], 'prules' => ['bulk'] }
    c.same('leq equal', s.leq(pf, pf.dup), true)
    c.same('leq risk', s.leq(pf, pf.merge('risk' => 0)), false)
    c.same('leq risk str', s.leq(pf, pf.merge('risk' => '1')), true)
    c.same('leq risk absent', s.leq(pf, pf.reject { |k, _| k == 'risk' }), false)
    c.same('leq rev', s.leq(pf, pf.merge('rev' => 'reversible')), false)
    c.same('leq rev unknown', s.leq(pf, pf.merge('rev' => 'bogus')), false)
    c.same('leq rev array', s.leq(pf, pf.merge('rev' => ['irreversible'])), true)
    c.same('leq blast', s.leq(pf, pf.merge('blast_ppm' => 4)), false)
    c.same('leq esc', s.leq(pf, pf.merge('esc' => 0)), false)
    c.same('leq blast ok esc bad', s.leq(pf, pf.merge('blast_ppm' => 9, 'esc' => 0)), false)
    c.same('leq esc ok blast bad', s.leq(pf, pf.merge('blast_ppm' => 4, 'esc' => 9)), false)
    c.same('leq caveats', s.leq(pf, pf.merge('caveats' => [])), false)
    c.same('leq context', s.leq(pf, pf.merge('context' => [])), false)
    c.same('leq prules', s.leq(pf, pf.merge('prules' => [])), false)
  end

  t('c01 actions: SvfJS.worst reads the declaration like JavaScript (key coercion, truthy values, Array.prototype.map)') do
    next true if C01Actions.skip?

    c = C01Actions
    w = c.svf.method(:worst)
    bool = { 'p' => { 'type' => 'boolean' } }
    both = { 'true' => 'reversible', 'false' => 'reversible' }
    c.same('string', w.call('bogus', {}), 'bogus')
    c.same('covered', w.call({ 'by' => 'p', 'map' => both }, bool), 'reversible')
    c.same('half', w.call({ 'by' => 'p', 'map' => { 'true' => 'reversible' } }, bool), 'irreversible')
    c.same('default', w.call({ 'by' => 'p', 'map' => { 'true' => 'reversible' }, 'default' => 'rate_limited' }, bool), 'rate_limited')
    c.same('by array', w.call({ 'by' => ['p'], 'map' => both }, bool), 'reversible')
    c.same('mixed', w.call({ 'by' => 'p', 'map' => { 'true' => 'irreversible', 'false' => 'reversible' } }, bool), 'irreversible')
    c.same('array values rank', w.call({ 'by' => 'p', 'map' => { 'true' => ['reversible'], 'false' => ['reversible'] } }, bool), 'reversible')
    c.same('unranked values', w.call({ 'by' => 'p', 'map' => { 'true' => {}, 'false' => 'rate_limited' } }, bool), 'rate_limited')
    sv = ->(vals) { { 'p' => { 'type' => 'string', 'values' => vals } } }
    sm = { 'a' => 'reversible', 'b' => 'rate_limited' }
    c.same('values covered', w.call({ 'by' => 'p', 'map' => sm }, sv.call(%w[a b])), 'rate_limited')
    c.same('values half', w.call({ 'by' => 'p', 'map' => { 'a' => 'reversible' } }, sv.call(%w[a b])), 'irreversible')
    c.same('values empty array', w.call({ 'by' => 'p', 'map' => { 'x' => 'reversible' } }, sv.call([])), 'reversible')
    c.same('values empty string', w.call({ 'by' => 'p', 'map' => { 'x' => 'reversible' } }, sv.call('')), 'irreversible')
    c.same('values absent', w.call({ 'by' => 'p', 'map' => { 'x' => 'reversible' } }, { 'p' => { 'type' => 'string' } }), 'irreversible')
    c.same('values int', c.raised(TypeError) { w.call({ 'by' => 'p', 'map' => sm }, sv.call(5)) }.message, 'domain.every is not a function')
    c.same('integer', w.call({ 'by' => 'p', 'map' => { 'x' => 'reversible' } }, { 'p' => { 'type' => 'integer', 'values' => ['x'] } }), 'irreversible')
    c.same('undeclared', w.call({ 'by' => 'zz', 'map' => both }, bool), 'irreversible')
    fn = ->(t) { { 'undefined' => t } }
    c.same('fn map length name', w.call([], fn.call({ 'type' => 'string', 'values' => %w[length name] })), 'reversible')
    c.same('fn map other', w.call([], fn.call({ 'type' => 'string', 'values' => %w[length x] })), 'irreversible')
    c.same('fn map boolean', w.call([], fn.call({ 'type' => 'boolean' })), 'irreversible')
    c.same('hash map none', c.raised(TypeError) { w.call({ 'by' => 'p' }, bool) }.message, 'Cannot convert undefined or null to object')
  end

  t('c01 actions: SvfJS.implied: roles, tags, effects, read-only money, de-duplicated and sorted') do
    next true if C01Actions.skip?

    c = C01Actions
    i = c.svf.method(:implied)
    c.same('delete twice', i.call(%w[delete delete], [], 'reversible'), ['pca.destructive'])
    c.same('effect as array', i.call([['pay']], [], 'reversible'), ['pca.money_moving'])
    c.same('unknown effect', c.raised(TypeError) { i.call(['bogus'], [], 'reversible') }.message, 'EFFECT_TRAITS[e] is not iterable')
    c.same('role credential', i.call(['update'], [{ 'role' => 'credential.token' }], 'reversible'), ['pca.credential_access'])
    c.same('role array', i.call(['update'], [{ 'role' => ['url.target'] }], 'reversible'), ['pca.network_egress'])
    c.same('role other', i.call(['update'], [{ 'role' => 'money.amount' }], 'reversible'), [])
    c.same('read money', i.call(['read'], [{ 'role' => 'money.amount' }], 'reversible'), ['pca.financial_data_read'])
    c.same('read other role', i.call(['read'], [{ 'role' => 'person.name' }], 'reversible'), [])
    sm = 'p.role.startsWith is not a function'
    c.same('read role int', c.raised(TypeError) { i.call(['read'], [{ 'role' => 5 }], 'reversible') }.message, sm)
    c.same('read role null', c.raised(TypeError) { i.call(['read'], [{ 'role' => nil }], 'reversible') }.message, sm)
    c.same('write role int', i.call(['update'], [{ 'role' => 5 }], 'reversible'), [])
    c.same('tags', i.call(['update'], [{ 'tags' => %w[pii phi] }], 'reversible'), %w[pca.pii_access pca.regulated_data])
    c.same('tags array elem', i.call(['update'], [{ 'tags' => [['pii']] }], 'reversible'), ['pca.pii_access'])
    c.same('tags null', i.call(['update'], [{ 'tags' => nil }], 'reversible'), [])
    c.same('tags int', c.raised(TypeError) { i.call(['update'], [{ 'tags' => 5 }], 'reversible') }.message,
           'object is not iterable (cannot read property Symbol(Symbol.iterator))')
    c.same('bulk', i.call(['update'], [{ 'type' => 'array' }], 'reversible'), ['pca.bulk'])
    c.same('bounded', i.call(['update'], [{ 'type' => 'array', 'max_items' => 3 }], 'reversible'), [])
    c.same('irreversible', i.call(['update'], [], 'irreversible'), ['pca.irreversible'])
  end

  # ======================================================================================================================
  # rule 22: schema_verb_floor_error / schema_floor_error
  # ======================================================================================================================
  t('c01 actions: schema_verb_floor_error: shape errors and faults carry the exact reference text') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    c.same('nil', a.schema_verb_floor_error(nil), "schema_floor_forged: Cannot read properties of null (reading 'effects')")
    c.same('not v2', a.schema_verb_floor_error({ 'effects' => 'x' }), 'schema_floor_forged: not a v2 verb')
    c.same('no floors', a.schema_verb_floor_error({ 'effects' => [], 'traits' => [] }), 'schema_floor_forged: not a v2 verb')
    c.same('params nil', a.schema_verb_floor_error({ 'effects' => [], 'traits' => [], 'floors' => {}, 'params' => nil }),
           'schema_floor_forged: Cannot convert undefined or null to object')
    rb = ->(prm) { { 'effects' => [], 'traits' => [], 'floors' => {}, 'params' => {}, 'reversibility_by' => { 'param' => prm } } }
    c.same('param int', a.schema_verb_floor_error(rb.call(5)), "schema_floor_forged: Cannot read properties of 5 (reading 'slice')")
    c.same('param nil', a.schema_verb_floor_error(rb.call(nil)), "schema_floor_forged: Cannot read properties of null (reading 'slice')")
    v = { 'effects' => ['update'], 'traits' => [], 'floors' => C01Actions::BOT.dup, 'params' => {}, 'reversibility' => 'reversible' }
    c.same('unconfirmed', a.schema_verb_floor_error(v), 'schema_traits_forged: unconfirmed action must carry every trait (missing pca.agent_spawning)')
    c.same('symbols', a.schema_verb_floor_error(c.sym(v)), 'schema_traits_forged: unconfirmed action must carry every trait (missing pca.agent_spawning)')
    all = a.top_traits(c.core)
    c.same('all traits', a.schema_verb_floor_error(v.merge('traits' => all, 'floors' => a.floor_of(c.core, all))), nil)
    c.same('floors below', a.schema_verb_floor_error(v.merge('traits' => all)), 'schema_floor_forged: floors are below the floor of the carried traits')
  end

  t('c01 actions: schema_verb_floor_error on a confirmed verb: declared reversibility, kind, floors.rev') do
    next true if C01Actions.skip?

    c = C01Actions
    sv = ->(v) { c.svf_err(v) }
    c.same('base', sv.call(c.cverb), nil)
    c.same('symbols', sv.call(c.sym(c.cverb)), nil)
    rl = 'schema_floor_forged: floors.rev is below the declared reversibility'
    c.same('rate_limited below', sv.call(c.cverb({ 'reversibility' => 'rate_limited' })), rl)
    c.same('rate_limited at', sv.call(c.cverb({ 'reversibility' => 'rate_limited', 'floors' => C01Actions::BOT.merge('rev' => 'rate_limited') })), nil)
    c.same('rate_limited above', sv.call(c.cverb({ 'reversibility' => 'rate_limited', 'floors' => C01Actions::BOT.merge('rev' => 'irreversible') })), nil)
    c.same('floors rev array', sv.call(c.cverb({ 'floors' => C01Actions::BOT.merge('rev' => ['irreversible']) })), rl)
    c.same('floors rev array, unknown decl', sv.call(c.cverb({ 'reversibility' => 'bogus', 'floors' => C01Actions::BOT.merge('rev' => ['irreversible']) })), nil)
    c.same('unknown decl', sv.call(c.cverb({ 'reversibility' => 'bogus' })), nil)
    mi = 'schema_traits_forged: missing implied trait pca.irreversible'
    c.same('irreversible missing', sv.call(c.cverb({ 'reversibility' => 'irreversible' })), mi)
    irr = c.act.floor_of(c.core, ['pca.irreversible'])
    c.same('irreversible carried', sv.call(c.cverb({ 'reversibility' => 'irreversible', 'floors' => irr }, ['pca.irreversible'])), nil)
    c.same('irreversible floors low', sv.call(c.cverb({ 'reversibility' => 'irreversible' }, ['pca.irreversible'])),
           'schema_floor_forged: floors are below the floor of the carried traits')
    c.same('kind read', sv.call(c.cverb({ 'reversibility' => nil, 'kind' => 'read' })), nil)
    c.same('kind write', sv.call(c.cverb({ 'reversibility' => nil, 'kind' => 'write' })), mi)
    c.same('kind write absent decl', sv.call(c.cverb({ 'kind' => 'write' }).tap { |v| v.delete('reversibility') }), mi)
    c.same('unknown trait', sv.call(c.cverb({}, ['x.nope'])), "unknown_trait: unknown trait 'x.nope'")
  end

  t('c01 actions: schema_verb_floor_error: reversibility_by resolves its parameter with the 14-character prefix stripped') do
    next true if C01Actions.skip?

    c = C01Actions
    sv = ->(v) { c.svf_err(v) }
    both = { 'true' => 'reversible', 'false' => 'reversible' }
    bool = { 'type' => 'boolean' }
    mi = 'schema_traits_forged: missing implied trait pca.irreversible'
    mk = ->(params, prm, extra = {}) { c.cverb({ 'params' => params, 'reversibility' => 'irreversible', 'reversibility_by' => { 'param' => prm, 'map' => both }.merge(extra) }) }
    c.same('prefixed', sv.call(mk.call({ 'action.params.f' => bool }, 'action.params.f')), nil)
    c.same('rb beats reversibility', sv.call(mk.call({ 'action.params.f' => bool }, 'action.params.f')), nil)
    c.same('any 14 chars stripped', sv.call(mk.call({ 'ZZZZZZZZZZZZZZf' => bool }, 'action.params.f')), nil)
    c.same('different name', sv.call(mk.call({ 'action.params.g' => bool }, 'action.params.f')), mi)
    c.same('short key and short param', sv.call(mk.call({ 'p' => bool }, 'x')), nil)
    c.same('param named null, short string', sv.call(mk.call({ 'action.params.null' => bool }, 'x')), mi)
    c.same('param named null, short array', sv.call(mk.call({ 'action.params.null' => bool }, ['x'])), mi)
    c.same('long array param', sv.call(mk.call({ 'action.params.f' => bool }, (['x'] * 14) + ['f'])), nil)
    c.same('binary param', sv.call(mk.call({ "action.params.é" => bool }, "action.params.é".b)), nil)
    c.same('default used', sv.call(c.cverb({ 'params' => { 'action.params.f' => bool }, 'floors' => C01Actions::BOT.merge('rev' => 'rate_limited'),
                                              'reversibility_by' => { 'param' => 'action.params.f', 'map' => { 'true' => 'reversible' }, 'default' => 'rate_limited' } })), nil)
    c.same('default too low', sv.call(c.cverb({ 'params' => { 'action.params.f' => bool },
                                                'reversibility_by' => { 'param' => 'action.params.f', 'map' => { 'true' => 'reversible' }, 'default' => 'rate_limited' } })),
           'schema_floor_forged: floors.rev is below the declared reversibility')
    c.same('no default', sv.call(c.cverb({ 'params' => { 'action.params.f' => bool },
                                           'reversibility_by' => { 'param' => 'action.params.f', 'map' => { 'true' => 'reversible' } } })), mi)
  end

  t('c01 actions: registry_of_schema and schema_floor_error') do
    next true if C01Actions.skip?

    c = C01Actions
    a = c.act
    c.same('core', a.registry_of_schema({}).equal?(c.core), true)
    c.same('empty trait_defs', a.registry_of_schema({ 'trait_defs' => [] }).equal?(c.core), true)
    c.same('trait_defs string', a.registry_of_schema({ 'trait_defs' => 'x' }).equal?(c.core), true)
    c.same('digest matches', a.registry_of_schema({ 'traits_digest' => a.traits_digest(c.core) }).equal?(c.core), true)
    c.same('digest mismatch', c.ake { a.registry_of_schema({ 'traits_digest' => 'zz' }) },
           ['traits_digest_mismatch', "the document's traits_digest does not match its trait registry"])
    c.same('custom', a.registry_of_schema({ 'trait_defs' => [c.trait('x.a')] }).key?('x.a'), true)
    c.same('empty doc', a.schema_floor_error({ 'verbs' => [] }), nil)
    c.same('symbol doc', a.schema_floor_error({ verbs: [] }), nil)
    c.same('digest', a.schema_floor_error({ 'traits_digest' => 'zz', 'verbs' => [] }),
           "traits_digest_mismatch: the document's traits_digest does not match its trait registry")
    c.same('verb error', a.schema_floor_error({ 'verbs' => [{ 'verb' => 'a.b.c' }] }), 'a.b.c: schema_floor_forged: not a v2 verb')
    Seam.with(a, { registry_of_schema: ->(_d) { raise 'boom' } }) { c.same('rescue', a.schema_floor_error({ 'verbs' => [] }), 'bad_registry: boom') }
  end
end
