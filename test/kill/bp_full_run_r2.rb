# frozen_string_literal: true
# Survivors of full run 42247853290 (intent_v2.rb), pinned to action-schema.ts (paramDeclError / verbDeclError / floors /
# formats), revocation.ts:305 and intent-v2.ts:325 and 629-631 (the rule 22 engine receives exactly these arguments).
module MutationKill
  t('iban: a string the IBAN shape refuses is false even when its mod 97 is 1') do
    v = AtlasPca::IntentV2
    v.iban_ok?('GB820000000012').equal?(false) && v.iban_ok?('GB82WEST12345698765432') == true &&
      v.format_violation({ 'format' => 'iban' }, 'GB820000000012')&.fetch('code') == 'out_of_domain'
  end

  t('cidr: every octet is at most 255, the fourth included') do
    v = AtlasPca::IntentV2
    v.cidr_ok?('1.2.3.255/8') == true && v.cidr_ok?('255.2.3.4/8') == true && v.cidr_ok?('1.2.3.256/8') == false
  end

  t('v2 floors: 0 is a valid risk and esc; a list of exactly 64 known entries is accepted, 65 refused') do
    s = V2Schema
    c = (0...64).map { |i| "session_taint_max:#{('a'.ord + (i / 26)).chr}#{('a'.ord + (i % 26)).chr}" }.sort
    s.v.schema_floors_error(s.floors(risk: 0)).nil? && s.v.schema_floors_error(s.floors(esc: 0)).nil? &&
      s.v.schema_floors_error(s.floors(context: c)).nil? &&
      s.v.schema_floors_error(s.floors(context: (c + ['session_taint_max:zz']).sort)) == 'floors.context must be an array of known entries'
  end

  t('v2 verb: 64 traits, every effect and every tag are accepted; an unknown effect or 13 effects are refused, each with its reason') do
    s = V2Schema
    at = "verb 'gen7.item.act7'"
    ids = (0...64).map { |i| format('pca.t%02d', i) }
    ef = s.v::SCHEMA_V2_EFFECTS.sort
    eb = "#{at}: effects must be 1..12 known effects"
    s.v.verb_decl_error(s.verb(traits: ids), nil, true).nil? &&
      s.v.verb_decl_error(s.verb(traits: ids + ['pca.zz']), nil, true) == "#{at}: traits must be trait ids" &&
      s.v.verb_decl_error(s.verb(effects: ef), nil, true).nil? && s.v.verb_decl_error(s.verb(effects: ef + ['update']), nil, true) == eb &&
      s.v.verb_decl_error(s.verb(effects: %w[pay zz_bogus]), nil, true) == eb &&
      s.v.param_decl_error('action.params.p0', s.str_decl(tags: s.v::SCHEMA_V2_TAGS.sort), nil, true).nil?
  end

  t('v2 confirmation: a bad sig has its own reason') do
    AtlasPca::IntentV2.send(:confirmation_shape_error, V2Schema::CONFIRMATION.merge('sig' => 'x')) == 'confirmation: sig must be a canonical base64url 64-byte signature'
  end

  t('object_ref: exactly max_len bytes is accepted, one more is out of domain') do
    v = AtlasPca::IntentV2
    d = { 'type' => 'object_ref', 'max_len' => 3 }
    v.param_value_violation(d, 'abc').nil? && v.param_value_violation(d, 'abcd') == { 'code' => 'out_of_domain', 'reason' => 'longer than 3 UTF-8 bytes' }
  end

  t('check_revocation_age: a number that is not finite as a double, or a numeric string, is unknown age (revocation.ts:305)') do
    v = AtlasPca::IntentV2
    unknown = { 'ok' => false, 'reason' => 'revocation state age is unknown (unverifiable revocation state)' }
    v.check_revocation_age(10**400, 1000, 10) == unknown && v.check_revocation_age('5', 1000, 10) == unknown
  end

  t('rule 22: the engine gets exactly the string caveat types, the pin tiers or max 3 / preauth 0, and the reviewers as given (seam)') do
    r = Rule22
    seen = []
    pins = []
    Seam.with(AtlasPca::ActionsRegistry, { rule22_decide: lambda { |_doc, _verb, grant, _context|
      seen << grant
      'allow'
    } }) do
      r.decide(r.grant('caveats' => [5, nil, { 'type' => 5 }, { 'type' => 'amount_cap' }]), r.ctx)
      r.decide(r.grant('actions' => r.pin), r.ctx)
    end
    Seam.with(AtlasPca::Actions, { schema_floor_error: lambda { |_doc, p = :none|
      pins << p
      nil
    } }) do
      r.decide(r.grant, r.ctx.reject { |k, _| k == 'reviewers' })
      r.decide(r.grant, r.ctx)
    end
    pin = r.pin
    seen == [{ 'caveats' => ['amount_cap'], 'max_esc' => 3, 'preauth_esc' => 0 },
             { 'caveats' => pin['caveats'], 'max_esc' => 3, 'preauth_esc' => pin['preauth_esc'] }] &&
      pins.first.nil? && pins.last == r.pins
  end
end

# Shards 61-92 of the same run.
module MutationKill
  t('v1 verb: the v2-only members (traits, def, floors, confirmation) are unknown members') do
    s = V2Schema
    v1 = { 'verb' => 'x.y', 'kind' => 'write', 'params' => {} }
    %w[traits def floors confirmation].all? { |k| s.v.verb_decl_error(v1.merge(k => []), nil, false) == "verb entry: unknown member '#{k}'" } &&
      s.v.verb_decl_error(v1, nil, false).nil?
  end

  t('rule 22 traits: no pin and no schema check means no traits check; a failed schema under a pin still lets units report') do
    r = Rule22
    unpinned = r.decide(r.grant, r.ctx.reject { |k, _| k == 'policy' }).map { |c| c['name'] }
    forged = r.ctx(r.doc { |d| r.refund(d)['floors']['esc'] = 0 })
    pinned = r.named(r.decide(r.grant('actions' => r.pin, 'units' => {}), forged))
    !unpinned.include?('traits') && !unpinned.include?('schema') &&
      pinned.keys == %w[schema pin units] && pinned['units'] == pinned['schema'] && pinned['schema'].start_with?('schema_floor_forged: ')
  end
end
