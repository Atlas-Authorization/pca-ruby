# frozen_string_literal: true
# intent_v2.rb survivors of the 0.5 full mutation run 41710479412: ActionSchema v2 declarations (param tags, floors, verb kind
# vs effects, confirmation), v2 string formats, duration values and the revocation-age fail-closed rescue, each pinned exactly
# against a well-formed v2 verb (packages/pca-conformance/vectors/actions/schema-verb-ok-007.json, inlined).
module MutationKill
  module V2Schema
    module_function

    def v = AtlasPca::IntentV2
    def dup(o) = Marshal.load(Marshal.dump(o))

    FLOORS = {
      'risk' => 3, 'rev' => 'irreversible', 'blast_ppm' => 1_000_000, 'esc' => 3,
      'caveats' => %w[amount_cap approval_ref count_cap rate_cap recipient_scope resource_scope short_expiry window],
      'context' => %w[dry_run_first fresh_revocation idempotency revocable sandbox_attested],
      'prules' => %w[array_bounded export_bounded id_not_wildcard money_amount_bounded money_has_currency pay_has_idempotency
                     recipient_param_declared secret_not_logged]
    }.freeze
    VERB = {
      'verb' => 'gen7.item.act7', 'kind' => 'write',
      'params' => { 'action.params.p0' => { 'type' => 'datetime', 'semantic' => 'generic.datetime', 'sensitivity' => 'free' } },
      'effects' => %w[pay privilege provision update],
      'traits' => %w[pca.bulk pca.money_moving], 'def' => 'SyLciqqBtMB1cwXrNPGKnRkWRX8_IEuVGmd_htWGh2U',
      'floors' => FLOORS, 'reversibility' => 'irreversible'
    }.freeze
    D32 = 'SyLciqqBtMB1cwXrNPGKnRkWRX8_IEuVGmd_htWGh2U'
    CONFIRMATION = { 'def_digest' => D32, 'traits_digest' => D32, 'facts_digest' => D32, 'final_traits' => %w[pca.bulk],
                     'dismissed' => [], 'reviewer_kid' => 'k1', 'ts' => 0, 'sig' => 'A' * 86 }.freeze

    def verb(**over) = dup(VERB).merge(over.transform_keys(&:to_s))
    def floors(**over) = dup(FLOORS).merge(over.transform_keys(&:to_s))
    def str_decl(**over) = { 'type' => 'string', 'semantic' => 'generic.x', 'sensitivity' => 'free' }.merge(over.transform_keys(&:to_s))
  end

  t('v2 verb: a well-formed write verb (with and without a confirmation) is accepted; kind read needs all-read effects') do
    s = MutationKill::V2Schema
    s.v.verb_decl_error(s.verb, nil, true).nil? &&
      s.v.verb_decl_error(s.verb(confirmation: s::CONFIRMATION), nil, true).nil? &&
      s.v.verb_decl_error(s.verb(confirmation: 5), nil, true) == "verb 'gen7.item.act7': confirmation must be an object" &&
      s.v.verb_decl_error(s.verb(kind: 'read'), nil, true) == "verb 'gen7.item.act7': kind read must hold exactly when every effect is read" &&
      s.v.verb_decl_error(s.verb(kind: 'read', effects: ['read'], floors: s.floors), nil, true).nil?
  end

  t('v2 floors: risk/esc bounds and the known-entry arrays, exactly') do
    s = MutationKill::V2Schema
    re = 'floors.risk and floors.esc must be integers in 0..3'
    s.v.schema_floors_error(s.floors).nil? &&
      [4, -1, '3', nil].all? { |x| s.v.schema_floors_error(s.floors(esc: x)) == re && s.v.schema_floors_error(s.floors(risk: x)) == re } &&
      %w[caveats context prules].all? do |k|
        s.v.schema_floors_error(s.floors(k.to_sym => ['zz_unknown'])) == "floors.#{k} must be an array of known entries" &&
          s.v.schema_floors_error(s.floors(k.to_sym => 'x')) == "floors.#{k} must be an array of known entries"
      end
  end

  t('v2 param declarations: known distinct tags are accepted, others refused') do
    s = MutationKill::V2Schema
    pe = ->(d) { s.v.param_decl_error('action.params.p0', d, nil, true) }
    bad = 'action.params.p0: tags must be distinct known tags'
    pe.(s.str_decl(tags: %w[pii phi])).nil? && pe.(s.str_decl(tags: [])).nil? &&
      pe.(s.str_decl(tags: %w[pii pii])) == bad && pe.(s.str_decl(tags: %w[nope])) == bad && pe.(s.str_decl(tags: 'pii')) == bad
  end

  t('v2 formats: iban (mod 97 over letters and digits), IPv6 cidr, regex formats return a boolean') do
    v = AtlasPca::IntentV2
    v.iban_ok?('GB82WEST12345698765432') == true && v.iban_ok?('GB82WEST12345698765433') == false &&
      v.iban_ok?('DE89370400440532013000') == true &&
      v.cidr_ok?('2001:db8::/32') == true && v.cidr_ok?('::1/128') == true && v.cidr_ok?('2001/32') == false &&
      v.format_check('uuid').call('nope') == false &&
      v.format_check('uuid').call(%w[0a1b2c3d 4e5f 6a7b 8c9d 0e1f2a3b4c5d].join('-')) == true # assembled: a literal reads as an id
  end

  t('v2 values: a duration must be a safe integer (bad_type), exactly') do
    v = AtlasPca::IntentV2
    want = { 'code' => 'bad_type', 'reason' => 'expected a safe integer (milliseconds)' }
    [1.5, '5', nil, true].all? do |x|
      begin
        v.param_value_violation({ 'type' => 'duration' }, x) == want
      rescue StandardError
        false
      end
    end && v.param_value_violation({ 'type' => 'duration' }, 5).nil?
  end

  t('check_revocation_age: an arithmetic fault is the unknown-age refusal, exactly') do
    v = AtlasPca::IntentV2
    v.check_revocation_age(5, 'x', 10) == { 'ok' => false, 'reason' => 'revocation state age is unknown (unverifiable revocation state)' } &&
      v.check_revocation_age(5, 'x', 10, 'revocation epoch') == { 'ok' => false, 'reason' => 'revocation epoch age is unknown (unverifiable revocation state)' }
  end

  t('ActionSchema v2 pack: ns up to 64 bytes, version up to 128') do
    v = AtlasPca::IntentV2
    doc = lambda do |ns, ver|
      { 'v' => 2, 'kind' => v::ACTION_SCHEMA_KIND, 'site' => 's', 'aud' => 'a', 'version' => '1',
        'pack' => { 'ns' => ns, 'version' => ver, 'root' => MutationKill::V2Schema::D32 } }
    end
    pk = 'pack must be {ns, version, root}'
    v.action_schema_shape_error(doc.('n' * 64, '1'), false) != pk && v.action_schema_shape_error(doc.('n' * 65, '1'), false) == pk &&
      v.action_schema_shape_error(doc.('n', 'v' * 128), false) != pk && v.action_schema_shape_error(doc.('n', 'v' * 129), false) == pk
  end

  t('v2 schema: format / rev / traits refusals and the email, IPv4 cidr, object_ref, duration max checks, exactly') do
    s = MutationKill::V2Schema
    v = s.v
    pe = ->(d) { v.param_decl_error('action.params.p0', d, nil, true) }
    fmt = 'action.params.p0: format must be a known format on a string parameter'
    long_email = "#{'a' * 64}@#{(['b' * 63] * 3).join('.')}"
    pe.(s.str_decl(format: 'nope')) == fmt && pe.(s.str_decl(format: 'uuid')).nil? &&
      v.schema_floors_error(s.floors(rev: 'x')) == 'floors.rev is not a reversibility class' &&
      v.verb_decl_error(s.verb(traits: ['BAD']), nil, true) == "verb 'gen7.item.act7': traits must be trait ids" &&
      v.verb_decl_error(s.verb(traits: %w[pca.money_moving pca.bulk]), nil, true) == "verb 'gen7.item.act7': traits must be sorted and distinct" &&
      v.format_check('email').call(long_email) == false && v.format_check('email').call('a@b.co') == true &&
      v.cidr_ok?('10.0.0.0/8') == true && v.cidr_ok?('256.0.0.0/8') == false && v.cidr_ok?('10.0.0.0/33') == false &&
      v.param_value_violation({ 'type' => 'string', 'format' => 'nope' }, 'x') == { 'code' => 'out_of_domain', 'reason' => 'not a valid nope' } &&
      v.param_value_violation({ 'type' => 'object_ref' }, '') == { 'code' => 'bad_type', 'reason' => 'expected a non-empty id string' } &&
      v.param_value_violation({ 'type' => 'object_ref' }, 'id1').nil? &&
      v.param_value_violation({ 'type' => 'duration', 'max' => 10 }, 11) == { 'code' => 'out_of_domain', 'reason' => 'above max 10' } &&
      v.param_value_violation({ 'type' => 'duration', 'max' => 10 }, 10).nil?
  end

  t('V2JS.js_str: Number#toString for large integers and floats (1e+21, 2^53 rounding, negative)') do
    j = AtlasPca::V2JS
    j.js_str(10**21) == '1e+21' && j.js_str(1.0e21) == '1e+21' && j.js_str(2**53 + 1) == '9007199254740992' &&
      j.js_str(-(2**53) - 1) == '-9007199254740992' && j.js_str(2**53) == '9007199254740992' && j.js_str(-5) == '-5' && j.js_str(1.5) == '1.5'
  end

  # Rules 20/21 (model_rules) called directly with the decide_intent_v2 state it reads: out['single_source'] (the W-B facts read
  # from one oracle) and out['schema'] (the schema step's document).
  module V2Model
    module_function

    def grant(extra = {})
      env = { 'type' => AtlasPca::ENVELOPE_CAVEAT, 'goal_commit' => 'g', 'caveats' => [], 'agent_binding' => {},
              'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY,
              'predicates' => [{ 'verb' => 'v', 'resource' => 'r', 'where' => [{ 'field' => 'env.world.balance', 'op' => 'eq', 'value' => 1 }] }] }
      { 'caveats' => [env.merge(extra)] }
    end

    def run_rules(grant, out)
      res = {}
      run = ->(name, &blk) { res[name] = blk.call }
      AtlasPca::IntentV2.model_rules({}, grant, AtlasPca::V2JS::UNDEF, out, run, { 'verb' => 'v', 'resource' => 'r', 'params' => {} })
      res
    end
  end

  t('model_rules: a single-source world fact read by a grant where is refused (rule 21); units read the schema step document') do
    m = MutationKill::V2Model
    tight = m.run_rules(m.grant, { 'single_source' => ['balance'] })
    deny = { 'ok' => false, 'reason' => "a grant's where reads model-derived path(s) env.world.balance: a model may only tighten (move them into tighten[]) (rule 21)" }
    doc = { 'units' => {}, 'verbs' => [{ 'verb' => 'v', 'params' => {} }] }
    want_units = AtlasPca.decide_units({ 'units' => {}, 'schema_units' => {}, 'verb_params' => {}, 'verb' => 'v',
                                         'predicates' => [m.grant['caveats'][0]['predicates']] })
    units = m.run_rules(m.grant('units' => {}), { 'schema' => doc })
    tight == { 'tighten' => deny } && m.run_rules(m.grant, {}) == {} &&
      units['units'] == (want_units['ok'] ? { 'ok' => true } : { 'ok' => false, 'reason' => want_units['reason'] })
  end

  t('decide_intent_v2: a W-B admit without single-source facts still runs rules 20/21 (the grant envelope units check is reported)') do
    m = MutationKill::V2Model
    d = AtlasPca.b64e("\x01".b * 32)
    out = AtlasPca.decide_intent_v2({ 'intent_session' => { 'session' => d } }, m.grant('units' => {}), nil, 1_800_000_000_000)
    plain = AtlasPca.decide_intent_v2({ 'intent_session' => { 'session' => d } }, {}, nil, 1_800_000_000_000)
    out['checks'].count { |c| c['name'] == 'units' } == 1 && plain['checks'].none? { |c| c['name'] == 'units' } && !out.key?('single_source')
  end

  t('v2 schema (shard 64): v1 vs v2 param members/types, 65 floors entries, traits_digest, IPv6 :::, cidr format, datetime, layers') do
    s = MutationKill::V2Schema
    v = s.v
    long = ['amount_cap'] * 65
    dt = { 'type' => 'duration', 'semantic' => 'generic.d', 'sensitivity' => 'free' }
    doc = { 'v' => 2, 'kind' => v::ACTION_SCHEMA_KIND, 'site' => 's', 'aud' => 'a', 'version' => '1', 'traits_digest' => 'x' }
    v.param_decl_error('action.params.p0', s.str_decl(tags: ['pii']), nil) == "action.params.p0: unknown member 'tags'" &&
      v.param_decl_error('action.params.p0', dt, nil, true).nil? &&
      v.param_decl_error('action.params.p0', dt, nil) == 'action.params.p0: unknown type' &&
      v.schema_floors_error(s.floors(caveats: long)) == 'floors.caveats must be an array of known entries' &&
      v.action_schema_shape_error(doc, false) == 'traits_digest must be a canonical base64url SHA-256 digest' &&
      v.cidr_ok?('1:::2/64') == false && v.format_check('cidr').call('10.0.0.0/8') == true &&
      v.param_value_violation({ 'type' => 'datetime' }, '2024-02-29T12:00:00Z').nil? &&
      v.allow_side_predicates(nil, { 'layers' => { 'org' => { 'predicates' => [1] }, 'site' => 5, 'std' => { 'predicates' => [2] } } }) == [nil, [1], nil, [2]]
  end

  t('model_rules: a tighten rule reads the verifier-computed env (out env merged over the host env)') do
    m = MutationKill::V2Model
    rule = { 'id' => 't1', 'when' => { 'field' => 'env.t', 'op' => 'eq', 'value' => 1 }, 'signal' => 'deny' }
    m.run_rules(m.grant('tighten' => [rule]), { 'env' => { 't' => 1 } }) == { 'tighten' => { 'ok' => false, 'reason' => "denied by tighten rule 't1'" } }
  end

  t('v2 schema (shard 10): a parameter that is also the parent of another is refused; non-string floors entries; url format') do
    s = MutationKill::V2Schema
    v = s.v
    d = { 'type' => 'string', 'semantic' => 'generic.x', 'sensitivity' => 'free' }
    two = s.verb(params: { 'action.params.a' => d, 'action.params.a.b' => d })
    v.verb_decl_error(two, nil, true) == "verb 'gen7.item.act7': parameter 'action.params.a' is both a value and the parent of 'action.params.a.b'" &&
      v.verb_decl_error(s.verb(params: { 'action.params.a' => d, 'action.params.ab' => d }), nil, true).nil? &&
      [5, nil, ['amount_cap']].all? { |x| v.schema_floors_error(s.floors(caveats: [x])) == 'floors.caveats must be an array of known entries' } &&
      v.schema_floors_error(s.floors(context: ['session_taint_max:abc'])).nil? &&
      v.format_check('url').call('https://a.example/x') == true && v.format_check('url').call('nope') == false
  end

  t('v2 schema (shard 11): uri_https and id formats, dismissed must be an array, no-envelope model_rules, unsupported_suite_reason nil') do
    s = MutationKill::V2Schema
    v = s.v
    v.format_check('uri_https').call('https://a.example/x') == true && v.format_check('uri_https').call('http://a.example/x') == false &&
      v.format_check('id:acme.order').call('ord_1') == true && v.format_check('id:acme.order').call('bad value!') == false &&
      v.confirmation_shape_error(s::CONFIRMATION.merge('dismissed' => 5)) == 'confirmation: dismissed must be an array' &&
      v.confirmation_shape_error(s::CONFIRMATION.merge('dismissed' => 'abc')) == 'confirmation: dismissed must be an array' &&
      v.confirmation_shape_error(s::CONFIRMATION).nil? &&
      MutationKill::V2Model.run_rules({}, {}) == {} && v.unsupported_suite_reason({}, []).nil?
  end

  t('check_revocation_epoch: an integral Float clock is read as the equal Integer (no Float rounding of now - issued_at)') do
    ep = MutationKill::V2.epoch([], issued: -4, not_after: 2**53 - 1)
    now = (2**53 - 1).to_f # exact; now - issued_at = 2^53 + 3 exactly as Integers, 2^53 + 4 after Float rounding
    AtlasPca.check_revocation_epoch(ep, ep['guardian'], now, AtlasPca::V2JS::UNDEF, nil, max_age_ms: 2**53 + 3) == { 'ok' => true } &&
      AtlasPca.check_revocation_epoch(ep, ep['guardian'], now, AtlasPca::V2JS::UNDEF, nil, max_age_ms: 2**53 + 2)['ok'] == false
  end

  t('v2 schema (shards 9/16): role bounds, 64 dismissed entries, trait_defs shape, semver format') do
    s = MutationKill::V2Schema
    v = s.v
    pe = ->(d) { v.param_decl_error('action.params.p0', d, nil, true) }
    role = 'action.params.p0: role must be a non-empty string'
    dm = ->(n) { s::CONFIRMATION.merge('dismissed' => Array.new(n) { { 'trait' => 'pca.bulk', 'reason' => 'r' } }) }
    td = 'trait_defs must be an array of up to 64 objects'
    doc = ->(x) { { 'v' => 2, 'kind' => v::ACTION_SCHEMA_KIND, 'site' => 's', 'aud' => 'a', 'version' => '1', 'trait_defs' => x } }
    pe.(s.str_decl(role: 'r' * 128)).nil? && pe.(s.str_decl(role: 'r' * 129)) == role && pe.(s.str_decl(role: '')) == role &&
      v.confirmation_shape_error(dm.(64)).nil? && v.confirmation_shape_error(dm.(65)) == 'confirmation: dismissed must be an array' &&
      [5, [5], Array.new(65) { {} }].all? { |x| v.action_schema_shape_error(doc.(x), false) == td } &&
      ![[], [{}], Array.new(64) { {} }].any? { |x| v.action_schema_shape_error(doc.(x), false) == td } &&
      v.format_check('semver').call('1.2.3-rc.1+b.5') == true && v.format_check('semver').call('1.2') == false
  end

  t('v2 schema (shards 18-60): every remaining refusal of floors, confirmation, traits, formats and values, exactly') do
    s = MutationKill::V2Schema
    v = s.v
    c = s::CONFIRMATION
    pe = ->(d) { v.param_decl_error('action.params.p0', d, nil, true) }
    at = "verb 'gen7.item.act7': "
    pvv = ->(d, x) { v.param_value_violation(d, x) }
    ood = ->(r) { { 'code' => 'out_of_domain', 'reason' => r } }
    dig = 'confirmation: def_digest, traits_digest and facts_digest must be canonical base64url SHA-256 digests'
    kid = 'confirmation: reviewer_kid must be a non-empty string'
    ftr = 'confirmation: final_traits must be trait ids'
    [
      v.schema_floors_error(5) == 'floors must be an object',
      v.schema_floors_error(s.floors(caveats: %w[window amount_cap])) == 'floors.caveats must be sorted and distinct',
      v.schema_floors_error(s.floors(caveats: %w[amount_cap amount_cap])) == 'floors.caveats must be sorted and distinct',
      v.schema_floors_error(s.floors(blast_ppm: 1_000_001)) == 'floors.blast_ppm must be an integer in 0..1000000',
      v.schema_floors_error(s.floors(blast_ppm: 0)).nil?,
      AtlasPca.schema_floors_error(s::FLOORS.transform_keys(&:to_sym)).nil?,
      %w[def_digest traits_digest facts_digest].all? { |k| v.confirmation_shape_error(c.merge(k => 'x')) == dig },
      v.confirmation_shape_error(c.merge('final_traits' => 'pca.bulk')) == ftr,
      v.confirmation_shape_error(c.merge('final_traits' => Array.new(65) { 'pca.bulk' })) == ftr,
      v.confirmation_shape_error(c.merge('reviewer_kid' => 'k' * 128)).nil? && v.confirmation_shape_error(c.merge('reviewer_kid' => 'k' * 129)) == kid,
      v.verb_decl_error(s.verb(traits: 'pca.bulk'), nil, true) == "#{at}traits must be trait ids",
      v.verb_decl_error(s.verb(traits: Array.new(65) { 'pca.bulk' }), nil, true) == "#{at}traits must be trait ids",
      pe.(s.str_decl(format: 5)) == 'action.params.p0: format must be a known format on a string parameter',
      pe.(s.str_decl(provenance_min: 'tool')).nil? && pe.(s.str_decl(provenance_min: 'x')) == 'action.params.p0: unknown provenance_min',
      v.cidr_ok?('ab:cd/64') == false && v.cidr_ok?('::1/064') == false && v.cidr_ok?('10.0.0.0/08') == false,
      v.format_check('iban').call('GB82WEST12345698765432') == true,
      pvv.({ 'type' => 'string', 'format' => 'uuid' }, 'x') == ood.('not a valid uuid'),
      pvv.({ 'type' => 'string', 'format' => 'uuid' }, %w[0a1b2c3d 4e5f 6a7b 8c9d 0e1f2a3b4c5d].join('-')).nil?,
      pvv.({ 'type' => 'datetime' }, 5) == { 'code' => 'bad_type', 'reason' => 'expected an RFC 3339 UTC string' },
      pvv.({ 'type' => 'duration' }, -1) == ood.('a duration is not negative'),
      pvv.({ 'type' => 'duration', 'min' => 10 }, 9) == ood.('below min 10') && pvv.({ 'type' => 'duration', 'min' => 10 }, 10).nil?
    ].all?
  end

  t('decide_intent_v2: the W-B facts read from a single oracle are carried out as single_source') do
    w = MutationKill::WB
    f = w.fact(0, 'fare', 5)
    p = { 'aud' => w::AUD, 'action' => { 'verb' => 'air.book', 'resource' => 'r' },
          'intent_session' => { 'session' => w.session, 'facts' => [AtlasPca.fact_ref(f)] } }
    ctx = { 'params' => { 'offer_id' => 'OF-2' },
            'wb' => { 'artifacts' => { 'facts' => [f] },
                      'policy' => { 'world' => { 'worlds' => [w.fare_world('min_oracles' => 1, 'max_faulty' => 0)] } } } }
    out = AtlasPca.decide_intent_v2(p, {}, ctx, w::NOW)
    out['single_source'] == ['fare'] && out['checks'].include?({ 'name' => 'facts', 'ok' => true }) &&
      out['env']['world'] == { 'fare' => 5 }
  end

  t('check_revocation_age / schema_floors_error wrappers: integral Float times are read as Integers; the floors wrapper reports') do
    big = 2**53 - 1
    ok = { 'ok' => true }
    AtlasPca.check_revocation_age(-4.0, big, 2**53 + 3) == ok && AtlasPca.check_revocation_age(-4, big.to_f, 2**53 + 3) == ok &&
      AtlasPca.check_revocation_age(-4, big, 2**53 + 3) == ok && AtlasPca.check_revocation_age(-4, big, 2**53 + 2)['ok'] == false &&
      AtlasPca.check_revocation_age(0, 10, 10.0) == ok && AtlasPca.check_revocation_age(0, 11, 10.0)['reason'] ==
        "revocation state is 11 ms old, over the verifier's maximum of 10 ms (stale revocation state)" &&
      AtlasPca.schema_floors_error(5) == 'floors must be an object'
  end

  t('v2 schema (shards 17/55/56): sha256 format; units over a schema that does not declare the verb') do
    m = MutationKill::V2Model
    doc = { 'units' => {}, 'verbs' => [{ 'verb' => 'other', 'params' => {} }] }
    AtlasPca::IntentV2.format_check('sha256').call('a' * 64) == true && AtlasPca::IntentV2.format_check('sha256').call('A' * 64) == false &&
      m.run_rules(m.grant('units' => {}), { 'schema' => doc }) == { 'units' => { 'ok' => false, 'reason' => "the schema does not declare verb 'v'" } }
  end

  t('v2 schema (shards 19+): verb def digest, effects order, pack shape, non-UTF-8 datetime, exactly') do
    s = MutationKill::V2Schema
    v = AtlasPca::IntentV2
    at = "verb 'gen7.item.act7': "
    doc = lambda do |pack|
      { 'v' => 2, 'kind' => v::ACTION_SCHEMA_KIND, 'site' => 's', 'aud' => 'a', 'version' => '1', 'pack' => pack }
    end
    pk = 'pack must be {ns, version, root}'
    good = { 'ns' => 'n', 'version' => '1', 'root' => s::D32 }
    dt = { 'type' => 'datetime' }
    [
      v.verb_decl_error(s.verb(def: 'x'), nil, true) == "#{at}def must be a canonical base64url SHA-256 digest",
      v.verb_decl_error(s.verb(def: 'A' * 42), nil, true) == "#{at}def must be a canonical base64url SHA-256 digest",
      v.verb_decl_error(s.verb(effects: %w[privilege pay provision update]), nil, true) == "#{at}effects must be sorted and distinct",
      v.verb_decl_error(s.verb(effects: %w[pay pay provision update]), nil, true) == "#{at}effects must be sorted and distinct",
      v.action_schema_shape_error(doc.(good), false) != pk,
      v.action_schema_shape_error(doc.(5), false) == pk,
      v.action_schema_shape_error(doc.(good.merge('root' => 'x')), false) == pk,
      v.action_schema_shape_error(doc.(good.merge('x' => 1)), false) == pk,
      !v.param_value_violation(dt, 'x').nil?,
      v.param_value_violation(dt, "2020-01-01T00:00:00Z\xFF".b) == v.param_value_violation(dt, 'x')
    ].all?
  end

  t('v2 schema (shard 52): dismissed entry shape, object_ref format, duration min/max declarations, exactly') do
    s = MutationKill::V2Schema
    v = s.v
    de = 'confirmation: dismissed entries must be {trait, reason}'
    dm = ->(x) { v.confirmation_shape_error(s::CONFIRMATION.merge('dismissed' => x)) }
    ref = { 'type' => 'object_ref', 'semantic' => 'generic.r', 'sensitivity' => 'free', 'format' => 'id:item' }
    dur = { 'type' => 'duration', 'semantic' => 'generic.d', 'sensitivity' => 'free', 'min' => 1, 'max' => 10 }
    [
      dm.([{ 'trait' => 'pca.bulk', 'reason' => 'r' }]).nil?,
      dm.([5]) == de, dm.([{ 'trait' => 'BAD', 'reason' => 'r' }]) == de, dm.([{ 'trait' => 'pca.bulk', 'reason' => 'r', 'x' => 1 }]) == de,
      v.param_decl_error('action.params.p0', ref, nil, true).nil?,
      v.param_decl_error('action.params.p0', ref.merge('type' => 'integer'), nil, true) == 'action.params.p0: format must be a known format on a string parameter',
      v.param_decl_error('action.params.p0', dur, nil, true).nil?,
      v.param_decl_error('action.params.p0', dur.merge('type' => 'datetime'), nil, true) == 'action.params.p0: min must be a safe integer on an integer parameter'
    ].all?
  end

  t('v2 formats: every regex format accepts its canonical form and refuses a near miss') do
    v = AtlasPca::IntentV2
    uuid = %w[0a1b2c3d 4e5f 6a7b 8c9d 0e1f2a3b4c5d].join('-')
    {
      'email' => ['a@b.example', 'a@b'], 'url' => ['ftp://h/x', 'h/x'], 'uri_https' => ['https://h', 'http://h'],
      'uuid' => [uuid, uuid.upcase], 'phone_e164' => ['+14155550100', '14155550100'], 'iso_country' => %w[GB gb],
      'iso_currency' => %w[USD US], 'semver' => ['1.2.3-rc.1+b', '01.2.3'], 'sha256' => ['a' * 64, 'a' * 63]
    }.all? { |f, (ok, no)| v.format_check(f).call(ok) == true && v.format_check(f).call(no) == false }
  end

  t('model_rules: no envelope but a policy model_polarity still runs rule 21 (no envelope tighten read)') do
    res = {}
    out = {}
    run = ->(name, &blk) { res[name] = blk.call }
    AtlasPca::IntentV2.model_rules({}, {}, { 'policy' => { 'model_polarity' => 'strict' } }, out, run, { 'verb' => 'v', 'resource' => 'r', 'params' => {} })
    res.keys == ['tighten'] && out == {} # a non-legacy outcome leaves no legacy_model_polarity mark
  end

  t('v2 helpers (shards 2-61): taint context floors, digest lists, exact nil/false returns') do
    s = MutationKill::V2Schema
    v = s.v
    d = s::D32
    v.schema_floors_error(s.floors(context: ['session_taint_max:pii'])).nil? &&
      v.schema_floors_error(s.floors(context: ['session_taint_max:PII'])) == 'floors.context must be an array of known entries' &&
      v.digest_list_error([d], 'facts', 4).nil? && v.digest_list_error([d, d], 'facts', 4) == "'intent_session.facts' entries must be distinct"
  end
  t('v2 schema (run 41911752779 shards 1-16): effects bounds, trait order, 64 final_traits, floors members, exactly') do
    s = MutationKill::V2Schema
    v = s.v
    at = "verb 'gen7.item.act7': "
    em = "#{at}effects must be 1..#{v::SCHEMA_V2_EFFECTS.length} known effects"
    tr = "#{at}traits must be sorted and distinct"
    all = v::SCHEMA_V2_EFFECTS.sort
    t64 = (0...64).map { |i| format('pca.t%02d', i) }
    c = ->(ft) { v.confirmation_shape_error(s::CONFIRMATION.merge('final_traits' => ft)) }
    [
      v.verb_decl_error(s.verb(effects: []), nil, true) == em,
      v.verb_decl_error(s.verb(effects: 'update'), nil, true) == em,
      v.verb_decl_error(s.verb(effects: all), nil, true).nil?,
      v.verb_decl_error(s.verb(traits: %w[pca.bulk pca.bulk]), nil, true) == tr,
      v.verb_decl_error(s.verb(traits: %w[pca.money_moving pca.bulk]), nil, true) == tr,
      v.verb_decl_error(s.verb(traits: %w[pca.bulk]), nil, true).nil?,
      c.(t64).nil?,
      c.(t64 + ['pca.t64']) == 'confirmation: final_traits must be trait ids',
      c.(%w[pca.bulk pca.bulk]) == 'confirmation: final_traits must be sorted and distinct',
      v.schema_floors_error(s.floors(x: 1)) == "floors: unknown member 'x'"
    ].all?
  end

  t('v2 formats (run 41911752779): email length 254 exactly, cidr /32, an IBAN letter A (= 10)') do
    v = AtlasPca::IntentV2
    e = ->(n) { "#{'a' * 64}@#{'b' * 63}.#{'c' * 63}.#{'d' * n}" } # 64 + 1 + 63 + 1 + 63 + 1 + n
    ck = ->(f, x) { v.format_check(f).call(x) }
    e.(61).length == 254 && ck.('email', e.(61)) == true && ck.('email', e.(62)) == false &&
      ck.('cidr', '10.0.0.0/32') == true && ck.('cidr', '10.0.0.0/33') == false &&
      ck.('iban', 'AL47212110090000000235698741') == true && ck.('iban', 'AL48212110090000000235698741') == false
  end

  t('optional_wire_ok?: a malformed fresh_at member is false, exactly') do
    AtlasPca.optional_wire_ok?({ 'fresh_at' => 5 }) == false && AtlasPca.optional_wire_ok?({}) == true
  end

  t('confirmation dismissed reason: 256 bytes accepted, 257 refused (TS action-schema.ts:292 isStr(d.reason, 256))') do
    s = MutationKill::V2Schema
    v = s.v
    dm = ->(r) { v.confirmation_shape_error(s::CONFIRMATION.merge('dismissed' => [{ 'trait' => 'pca.bulk', 'reason' => r }])) }
    dm.('r' * 256).nil? && dm.('r' * 257) == 'confirmation: dismissed entries must be {trait, reason}'
  end

  t('intent_goal_v3: Symbol keys give the same string as String keys') do
    d = MutationKill::V2Schema::D32
    AtlasPca.intent_goal_v3({ goal_digest: d, policy_digest: d }) == AtlasPca.intent_goal_v3({ 'goal_digest' => d, 'policy_digest' => d })
  end
end
