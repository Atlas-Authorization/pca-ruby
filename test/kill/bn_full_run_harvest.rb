# frozen_string_literal: true
# Survivors of full run 42068695024, pinned to action-schema.ts:346 and the floors / confirmation checks, intent-v2.ts:623 and
# revocation.ts (a met age bound does not end the checks).
module MutationKill
  t('v2 verb: bad floors, a bad confirmation ts and a non-object harm or returns are refused, each with its own reason') do
    s = V2Schema
    at = "verb 'gen7.item.act7'"
    bad = s.floors(risk: 99)
    fe = s.v.schema_floors_error(bad)
    !fe.nil? && s.v.verb_decl_error(s.verb(floors: bad), nil, true) == "#{at}: #{fe}" &&
      [-1, 'x'].all? { |ts| s.v.verb_decl_error(s.verb(confirmation: s::CONFIRMATION.merge('ts' => ts)), nil, true) == "#{at}: confirmation: ts must be a non-negative safe integer" } &&
      s.v.verb_decl_error(s.verb(harm: 5), nil, true) == "#{at}: harm must be an object" &&
      s.v.verb_decl_error(s.verb(returns: 5), nil, true) == "#{at}: returns must be an object" &&
      s.v.verb_decl_error(s.verb(harm: {}, returns: {}), nil, true).nil?
  end

  t('schema document: the v2 members are unknown in a v1 document, and known in a v2 one') do
    e = ->(d) { V2Schema.v.action_schema_shape_error(d) }
    %w[pack traits_digest trait_defs].all? { |k| e.({ 'v' => 1, k => {} }) == "unknown member '#{k}'" && !e.({ 'v' => 2, k => {} }).start_with?('unknown member') }
  end

  t('datetime parameter: a malformed value has the reference reason') do
    V2Schema.v.param_value_violation({ 'type' => 'datetime' }, 'x') == { 'code' => 'out_of_domain', 'reason' => 'not an RFC 3339 UTC datetime YYYY-MM-DDTHH:MM:SS[.fff]Z' }
  end

  t('check_revocation_epoch: a met age bound still checks the rollback floor') do
    next true if DiffUtil.skip?('intent_v2.rb')

    e = RevT.ep
    run = ->(**o) { AtlasPca.check_revocation_epoch(e, RevT.fx[:guardian], RevT.fx[:now], AtlasPca::V2JS::UNDEF, nil, max_age_ms: 10**12, **o) }
    run.()['ok'] == true &&
      run.(last_accepted_epoch: e['epoch'] + 1) == { 'ok' => false, 'reason' => "revocation epoch #{e['epoch']} is older than the last accepted #{e['epoch'] + 1} (rollback)" }
  end

  t('rule 22: a pin alone (no session, no closed-world policy) still runs traits on a v2 document; a grant with no envelope too') do
    r = Rule22
    c = r.ctx.reject { |k, _| k == 'policy' }
    r.pinned({}, c) == { 'pin' => true, 'traits' => true } && r.pinned({ 'max_esc' => r.floors['esc'] - 1, 'preauth_esc' => 0 }, c)['traits'] == r::OVER &&
      r.named(r.decide({ 'id' => 'g1', 'issuer' => 'iss', 'caveats' => [] }, r.ctx))['traits'] == r::ESC
  end
end
