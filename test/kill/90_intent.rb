# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'digest'
require 'json'

# Intent Layer M2 kill tests (`envelope.intent`): intent_wire_error, intent_goal / intent_goal_commit,
# intent_policy_active?, root_goal_commit, decide_intent_binding and the `intent` check in verify_pcactn. Every boundary
# is pinned on both sides so an off-by-one, negated or deleted-branch mutant dies. Every AtlasPca constant / helper is
# resolved at CALL time (the oracle replaces the module per mutant): nothing derived from AtlasPca is memoized.
module MutationKill
  module Intent
    module_function

    KEYS = File.expand_path('../../conformance/keys.json', __dir__)
    NOW = 1_800_000_000_000
    AUD = 'rs-intent-kill'
    SALT = 'c2FsdC1pbnRlbnQ'
    MAX_SAFE = 9_007_199_254_740_991
    REQ = 'this verifier requires an intent binding but the PCActn carries none'
    MIS = 'intent policy misconfigured: thresholds must be non-negative safe integers (fail closed)'
    NOENV = 'the root grant carries no envelope goal commitment to bind the intent to'
    OPEN = "intent ref / map_digest / goal_salt do not open the root grant's goal commitment"
    BASE = %w[wire version audience validity chain grant_ref_bound plan_inclusion leaf_signature counter_format].freeze

    def keys = (@keys ||= JSON.parse(File.read(KEYS)))
    def b64(bin) = Base64.urlsafe_encode64(bin, padding: false)
    def ref = b64(Digest::SHA256.digest('ki/ref'))
    def map = b64(Digest::SHA256.digest('ki/map'))
    def other = b64(Digest::SHA256.digest('ki/other'))

    # The goal commitment built WITHOUT the library (literal canonical JSON: keys sorted, NUL escaped as \u0000).
    def commit(salt = SALT, r = ref, m = map)
      json = "{\"d\":\"atlas-pca/goal/v1\\u0000\",\"goal\":\"pca-intent:v1:#{r}:#{m}\",\"salt\":\"#{salt}\"}"
      b64(Digest::SHA256.digest(json.b))
    end

    def env(salt = SALT) = { 'type' => 'envelope', 'goal_commit' => commit(salt) }
    def intent(over = {}) = { 'ref' => ref, 'map_digest' => map, 'goal_salt' => SALT, 'fidelity_ppm' => 950_000,
                              'residual_risk_ppm' => 4_310_000 }.merge(over)
    def without(k) = intent.reject { |kk, _| kk == k }
    def wire(over) = AtlasPca.intent_wire_error(intent(over))
    def decide(i, g, pol = nil) = AtlasPca.decide_intent_binding(i, g, pol)

    def key(name) = OpenSSL::PKey.new_raw_private_key('ED25519', AtlasPca.b64d(keys[name]['seed'], 32))
    def pub(k) = AtlasPca.b64e(k.raw_public_key)

    def root(caveats)
      principal = key('principal')
      r = { 'issuer' => pub(principal), 'holder' => pub(key('agent')), 'caveats' => caveats }
      digest = AtlasPca.hash_canonical(AtlasPca.body_of(r))
      r.merge('id' => digest, 'body_digest' => digest,
              'sig' => AtlasPca.b64e(principal.sign(nil, AtlasPca::CAP_DOMAIN + AtlasPca.b64d(digest, 32))))
    end

    def grant = root([{ 'type' => 'max_spend', 'usd' => 1 }, env])

    # A signed PCActn under `r`; `extra` (e.g. 'intent' => ...) is part of the signed body.
    def pcactn(r, extra = {})
      action = { 'verb' => 'read', 'resource' => 'doc:1', 'params_digest' => AtlasPca.params_digest({ 'q' => 1 }),
                 'reversibility_class' => 'reversible' }
      leaf = AtlasPca.plan_leaf('n1', action, AtlasPca.conditions_digest(nil, nil))
      zero = AtlasPca.b64e("\0".b * 32)
      p = {
        'ver' => 2, 'action' => action, 'grant_ref' => r['id'], 'cap_chain' => [r],
        'plan' => { 'root' => AtlasPca.merkle_root([leaf]), 'node_id' => 'n1', 'inclusion_proof' => { 'index' => 0, 'size' => 1, 'path' => [] } },
        'attestation' => { 'epoch' => 1, 'quote_digest' => zero, 'model_id' => 'm', 'measurement' => zero, 'operator' => 'op' },
        'provenance' => { 'causal_hash' => zero, 'taint_level' => 0, 'trusted_refs' => [] },
        'freshness' => { 'epoch' => 1, 'beacon_ref' => zero, 'accumulator_witness' => zero },
        'counter' => 0, 'risk_claim' => { 'r' => 0, 'inputs' => {} }, 'aud' => AUD, 'iat' => NOW - 1000, 'exp' => NOW + 60_000
      }.merge(extra)
      p.merge('sig' => AtlasPca.b64e(key('agent').sign(nil, AtlasPca.threshold_message(p))))
    end

    def verify(p, g, pol = nil, aud: AUD) = AtlasPca.verify_pcactn(p, g, now: NOW, audience: aud, intent_policy: pol)
    def all_ok = BASE.to_h { |k| [k, true] }
    def with_intent(ok = true) = all_ok.merge('intent' => ok)
  end

  t('intent constants and the closed optional field') do
    AtlasPca::INTENT_GOAL_PREFIX == 'pca-intent:v1:' && AtlasPca::INTENT_GOAL_COMMIT_DOMAIN == "atlas-pca/goal/v1\u0000" &&
      AtlasPca::PPM_ONE == 1_000_000 && AtlasPca::MAX_INTENT_GOAL_SALT_LEN == 128 &&
      AtlasPca::ENVELOPE_INTENT_FIELDS == %w[ref map_digest goal_salt fidelity_ppm residual_risk_ppm] &&
      AtlasPca::TOP_OPTIONAL.include?('intent')
  end

  t('intent wire: well-formed edges (fidelity 0 / 1e6, residual 0 / MAX_SAFE, salt 128 bytes / 1 byte)') do
    i = Intent
    AtlasPca.intent_wire_error(i.intent).nil? && i.wire('fidelity_ppm' => 0).nil? && i.wire('fidelity_ppm' => 1_000_000).nil? &&
      i.wire('residual_risk_ppm' => 0).nil? && i.wire('residual_risk_ppm' => Intent::MAX_SAFE).nil? &&
      i.wire('goal_salt' => "é" * 64).nil? && i.wire('goal_salt' => 'a' * 128).nil? && i.wire('goal_salt' => 'a').nil?
  end

  t('intent wire: not an object / unknown / every missing member') do
    obj = "'intent' must be an object"
    [nil, [Intent.intent], [], 'x', 1, true].all? { |v| AtlasPca.intent_wire_error(v) == obj } &&
      Intent.wire('note' => 'x') == "unknown field 'intent.note'" &&
      AtlasPca.intent_wire_error(Intent.without('ref').merge('extra' => 1)) == "unknown field 'intent.extra'" &&
      Intent.intent.keys.all? { |k| AtlasPca.intent_wire_error(Intent.without(k)) == "missing field 'intent.#{k}'" } &&
      AtlasPca.intent_wire_error({}) == "missing field 'intent.ref'"
  end

  t('intent wire: ref / map_digest canonical 32-byte base64url, ref first') do
    r = "'intent.ref' is not canonical base64url (32 bytes)"
    m = "'intent.map_digest' is not canonical base64url (32 bytes)"
    i = Intent
    i.wire('ref' => i.b64('x' * 31)) == r && i.wire('ref' => i.b64('x' * 33)) == r && i.wire('ref' => "#{i.ref}=") == r &&
      i.wire('ref' => 1) == r && i.wire('ref' => nil) == r && i.wire('map_digest' => i.b64('x' * 31)) == m &&
      i.wire('map_digest' => "+#{i.map[1..]}") == m && i.wire('map_digest' => 1) == m && i.wire('ref' => 1, 'map_digest' => 1) == r
  end

  t('intent wire: goal_salt non-empty UTF-8 string of <= 128 BYTES') do
    s = "'intent.goal_salt' must be a non-empty string (<= 128 UTF-8 bytes)"
    ['', "#{"é" * 64}a", 'a' * 129, "é" * 65, 5, nil, ['a'], 'a'.b, "a\xFF".dup.force_encoding(Encoding::UTF_8)]
      .all? { |bad| Intent.wire('goal_salt' => bad) == s }
  end

  t('intent wire: fidelity_ppm safe integer in [0, 1e6]; residual_risk_ppm safe integer >= 0; fidelity first') do
    f = "'intent.fidelity_ppm' must be a safe integer in [0, 1000000]"
    r = "'intent.residual_risk_ppm' must be a non-negative safe integer"
    [-1, 1_000_001, 1.5, 1.0, '950000', true, false, nil, -0.0, Intent::MAX_SAFE + 1].all? { |b| Intent.wire('fidelity_ppm' => b) == f } &&
      [-1, 0.25, 0.0, '1', true, false, nil, Intent::MAX_SAFE + 1].all? { |b| Intent.wire('residual_risk_ppm' => b) == r } &&
      Intent.wire('fidelity_ppm' => -1, 'residual_risk_ppm' => -1) == f
  end

  t('intent wire: a malformed slot is a terminal wire failure of verify_pcactn') do
    g = Intent.grant
    [nil, [Intent.intent], 'x', Intent.intent('note' => 1), Intent.without('goal_salt'), Intent.intent('fidelity_ppm' => true),
     Intent.intent('residual_risk_ppm' => true), Intent.intent('goal_salt' => "#{"é" * 64}a"),
     Intent.intent('fidelity_ppm' => 1_000_001)].all? { |bad|
      v = Intent.verify(Intent.pcactn(g, 'intent' => bad), g)
      v.allow == false && v.checks == { 'wire' => false }
    } && AtlasPca.wire_ok?(Intent.pcactn(g, 'intent' => Intent.intent))
  end

  t('intent_goal / intent_goal_commit') do
    i = Intent
    AtlasPca.intent_goal(i.ref) == "pca-intent:v1:#{i.ref}" && AtlasPca.intent_goal(i.ref, nil) == "pca-intent:v1:#{i.ref}" &&
      AtlasPca.intent_goal(i.ref, '') == "pca-intent:v1:#{i.ref}" &&
      AtlasPca.intent_goal(i.ref, i.map) == "pca-intent:v1:#{i.ref}:#{i.map}" &&
      AtlasPca.intent_goal_commit(i.ref, i.map, Intent::SALT) == i.commit &&
      AtlasPca.intent_goal_commit(i.ref, i.map, 'other') != i.commit && AtlasPca.intent_goal_commit(i.map, i.ref, Intent::SALT) != i.commit
  end

  t('intent_policy_active?: require exactly true, or a threshold key present (String or Symbol)') do
    [nil, {}, { 'require' => false }, { 'require' => 1 }, { 'require' => 'true' }, { 'require' => nil }, 'min_fidelity_ppm',
     ['min_fidelity_ppm'], 1].none? { |p| AtlasPca.intent_policy_active?(p) } &&
      [{ 'require' => true }, { require: true }, { 'min_fidelity_ppm' => 0 }, { 'max_residual_risk_ppm' => 0 },
       { min_fidelity_ppm: -1 }, { 'max_residual_risk_ppm' => nil }, { 'require' => false, 'min_fidelity_ppm' => 1 }]
        .all? { |p| AtlasPca.intent_policy_active?(p) == true }
  end

  t('root_goal_commit: first envelope wins, non-objects skipped, non-string goal_commit / no caveats list => nil') do
    c = Intent.commit
    e = Intent.env
    AtlasPca.root_goal_commit(Intent.grant) == c && AtlasPca.root_goal_commit({ 'caveats' => [e] }) == c &&
      AtlasPca.root_goal_commit({ 'caveats' => [{ 'type' => 'envelope', 'goal_commit' => 'decoy' }, e] }) == 'decoy' &&
      AtlasPca.root_goal_commit({ 'caveats' => ['envelope', 1, nil, [e], { 'type' => 'Envelope', 'goal_commit' => 'x' }, e] }) == c &&
      AtlasPca.root_goal_commit({ 'caveats' => [{ 'type' => 'envelope', 'goal_commit' => 7 }, e] }).nil? &&
      AtlasPca.root_goal_commit({ 'caveats' => [{ 'type' => 'envelope' }, e] }).nil? &&
      AtlasPca.root_goal_commit({ 'caveats' => [] }).nil? && AtlasPca.root_goal_commit({ 'caveats' => e }).nil? &&
      AtlasPca.root_goal_commit({ 'caveats' => nil }).nil? && AtlasPca.root_goal_commit({}).nil? &&
      AtlasPca.root_goal_commit(nil).nil? && AtlasPca.root_goal_commit([e]).nil?
  end

  t('decide_intent_binding: absent vs active without intent; misconfiguration first') do
    g = { 'caveats' => [Intent.env] }
    [nil, {}, { 'require' => false }, { 'require' => 1 }, 'min_fidelity_ppm'].all? { |p| Intent.decide(nil, g, p) == [:absent, nil] } &&
      Intent.decide(nil, nil) == [:absent, nil] &&
      [{ 'require' => true }, { require: true }, { 'min_fidelity_ppm' => 0 }, { 'max_residual_risk_ppm' => 0 }]
        .all? { |p| Intent.decide(nil, g, p) == [:fail, Intent::REQ] } &&
      Intent.decide(nil, g, { 'min_fidelity_ppm' => -1 }) == [:fail, Intent::MIS]
  end

  t('decide_intent_binding: misconfigured thresholds fail closed; 0 is a valid threshold') do
    g = { 'caveats' => [Intent.env] }
    [{ 'min_fidelity_ppm' => -1 }, { 'max_residual_risk_ppm' => -1 }, { 'min_fidelity_ppm' => 0.5 }, { 'max_residual_risk_ppm' => 0.5 },
     { 'min_fidelity_ppm' => nil }, { 'min_fidelity_ppm' => true }, { 'max_residual_risk_ppm' => '5' }, { min_fidelity_ppm: 1.5 },
     { 'min_fidelity_ppm' => Intent::MAX_SAFE + 1 }, { 'require' => true, 'min_fidelity_ppm' => 0, 'max_residual_risk_ppm' => -1 }]
      .all? { |p| Intent.decide(Intent.intent, g, p) == [:fail, Intent::MIS] } &&
      Intent.decide(Intent.intent('fidelity_ppm' => 0), g, { 'min_fidelity_ppm' => 0, 'max_residual_risk_ppm' => Intent::MAX_SAFE }) == [:pass, nil] &&
      Intent.decide(Intent.intent('residual_risk_ppm' => 0), g, { 'max_residual_risk_ppm' => 0 }) == [:pass, nil]
  end

  t('intent_threshold: valid iff the NUMERIC VALUE is a safe integer >= 0 (integral Floats accepted, -0.0 rejected)') do
    i = Intent
    g = { 'caveats' => [i.env] }
    x = i.intent
    ok = [:pass, nil]
    [0, 1, Intent::MAX_SAFE].all? { |v| AtlasPca.intent_threshold(v) == v } &&
      AtlasPca.intent_threshold(950_000.0) == 950_000 && AtlasPca.intent_threshold(950_000.0).is_a?(Integer) &&
      AtlasPca.intent_threshold(1e6) == 1_000_000 && AtlasPca.intent_threshold(0.0) == 0 &&
      AtlasPca.intent_threshold(9_007_199_254_740_991.0) == Intent::MAX_SAFE &&
      [-1, Intent::MAX_SAFE + 1, -0.0, -1.0, 950_000.5, 0.5, Float::NAN, Float::INFINITY, -Float::INFINITY, 9_007_199_254_740_992.0,
       nil, true, false, '5', [1], { 'a' => 1 }].all? { |v| AtlasPca.intent_threshold(v).nil? } &&
      i.decide(x, g, { 'min_fidelity_ppm' => 950_000.0 }) == ok &&
      i.decide(x, g, { 'min_fidelity_ppm' => 0.0, 'max_residual_risk_ppm' => 4_310_000.0 }) == ok &&
      i.decide(i.intent('fidelity_ppm' => 1_000_000), g, { 'min_fidelity_ppm' => 1e6 }) == ok &&
      i.decide(i.intent('fidelity_ppm' => 999_999), g, { 'min_fidelity_ppm' => 1e6 }) ==
        [:fail, 'intent fidelity 999999 ppm is below the policy minimum 1000000'] &&
      i.decide(x, g, { 'max_residual_risk_ppm' => 4_309_999.0 }) ==
        [:fail, 'intent residual risk 4310000 ppm exceeds the policy maximum 4309999'] &&
      [{ 'min_fidelity_ppm' => -0.0 }, { 'max_residual_risk_ppm' => -0.0 }, { 'min_fidelity_ppm' => 950_000.5 },
       { 'max_residual_risk_ppm' => Float::NAN }, { 'min_fidelity_ppm' => Float::INFINITY }, { 'max_residual_risk_ppm' => 9_007_199_254_740_992.0 }]
        .all? { |p| i.decide(x, g, p) == [:fail, Intent::MIS] } &&
      i.decide(x, g, JSON.parse('{"min_fidelity_ppm":950000.0,"max_residual_risk_ppm":4.31e6}')) == ok &&
      i.decide(x, g, JSON.parse('{"min_fidelity_ppm":-0.0}')) == [:fail, Intent::MIS]
  end

  t('decide_intent_binding: the root grant binding') do
    i = Intent
    e = i.env
    g = { 'caveats' => [{ 'type' => 'max_spend', 'usd' => 1 }, e] }
    i.decide(i.intent, g) == [:pass, nil] && i.decide(i.intent, g, { 'require' => true }) == [:pass, nil] &&
      i.decide(i.intent, g, 'min_fidelity_ppm') == [:pass, nil] &&
      i.decide(i.intent, { 'caveats' => [] }) == [:fail, Intent::NOENV] && i.decide(i.intent, {}) == [:fail, Intent::NOENV] &&
      i.decide(i.intent, 'grant') == [:fail, Intent::NOENV] &&
      i.decide(i.intent, { 'caveats' => [{ 'type' => 'envelope', 'goal_commit' => 7 }] }) == [:fail, Intent::NOENV] &&
      i.decide(i.intent, { 'caveats' => [{ 'type' => 'envelope', 'goal_commit' => 'decoy' }, e] }) == [:fail, Intent::OPEN] &&
      i.decide(i.intent, { 'caveats' => ['x', nil, 3, e] }) == [:pass, nil] &&
      i.decide(i.intent('goal_salt' => 'wrong'), g) == [:fail, Intent::OPEN] &&
      i.decide(i.intent('ref' => i.other), g) == [:fail, Intent::OPEN] &&
      i.decide(i.intent('map_digest' => i.other), g) == [:fail, Intent::OPEN] &&
      i.decide(i.intent('ref' => i.map, 'map_digest' => i.ref), g) == [:fail, Intent::OPEN]
  end

  t('decide_intent_binding: thresholds inclusive, min before max, binding before thresholds; never raises') do
    i = Intent
    g = { 'caveats' => [i.env] }
    x = i.intent
    i.decide(x, g, { 'min_fidelity_ppm' => 950_000 }) == [:pass, nil] && i.decide(x, g, { 'min_fidelity_ppm' => 949_999 }) == [:pass, nil] &&
      i.decide(x, g, { 'min_fidelity_ppm' => 950_001 }) == [:fail, 'intent fidelity 950000 ppm is below the policy minimum 950001'] &&
      i.decide(x, g, { 'max_residual_risk_ppm' => 4_310_000 }) == [:pass, nil] &&
      i.decide(x, g, { 'max_residual_risk_ppm' => 4_310_001 }) == [:pass, nil] &&
      i.decide(x, g, { 'max_residual_risk_ppm' => 4_309_999 }) == [:fail, 'intent residual risk 4310000 ppm exceeds the policy maximum 4309999'] &&
      i.decide(x, g, { 'min_fidelity_ppm' => 950_001, 'max_residual_risk_ppm' => 0 })[1].start_with?('intent fidelity') &&
      i.decide(i.intent('goal_salt' => 'wrong'), g, { 'min_fidelity_ppm' => 950_001 }) == [:fail, Intent::OPEN] &&
      i.decide({ 'fidelity_ppm' => 1 }, g)[0] == :fail &&
      i.decide({ 'fidelity_ppm' => 1 }, g)[1].start_with?('intent binding error (fail closed): ')
  end

  t('verify_pcactn: bound intent reported last; absent is the pre-M2 verdict; active policy without intent fails') do
    i = Intent
    g = i.grant
    bound = i.pcactn(g, 'intent' => i.intent)
    plain = i.pcactn(g)
    [nil, { 'require' => true }, { 'min_fidelity_ppm' => 950_000, 'max_residual_risk_ppm' => 4_310_000 }].all? { |p|
      v = i.verify(bound, g, p)
      v.allow == true && v.checks == i.with_intent && v.checks.keys == Intent::BASE + ['intent'] && v.reason == ''
    } && [nil, {}, { 'require' => false }, { 'require' => 1 }, 'x'].all? { |p|
      v = i.verify(plain, g, p)
      v.allow == true && v.checks == i.all_ok && v.checks.keys == Intent::BASE && !v.checks.key?('intent')
    } && [{ 'require' => true }, { 'min_fidelity_ppm' => 1 }, { max_residual_risk_ppm: 5 }].all? { |p|
      v = i.verify(plain, g, p)
      v.allow == false && v.checks == i.with_intent(false) && v.checks.keys.last == 'intent' && v.reason == "intent: #{Intent::REQ}"
    } && AtlasPca.verify_pcactn(plain, g, now: Intent::NOW, audience: Intent::AUD).checks == i.all_ok
  end

  t('verify_pcactn: intent failures, first envelope wins, envelope not first binds') do
    i = Intent
    g = i.grant
    bound = i.pcactn(g, 'intent' => i.intent)
    v1 = i.verify(bound, g, { 'min_fidelity_ppm' => 950_001 })
    v2 = i.verify(bound, g, { 'max_residual_risk_ppm' => -1 })
    g3 = i.root([{ 'type' => 'envelope', 'goal_commit' => 'decoy' }, i.env])
    v3 = i.verify(i.pcactn(g3, 'intent' => i.intent), g3)
    g4 = i.root([{ 'type' => 'envelope', 'goal_commit' => 7 }])
    v4 = i.verify(i.pcactn(g4, 'intent' => i.intent), g4)
    g5 = i.root([{ 'type' => 'max_spend', 'usd' => 1 }, { 'type' => 'note', 'n' => 1 }, i.env])
    v5 = i.verify(i.pcactn(g5, 'intent' => i.intent), g5)
    v1.allow == false && v1.checks == i.with_intent(false) &&
      v1.reason == 'intent: intent fidelity 950000 ppm is below the policy minimum 950001' &&
      v2.checks == i.with_intent(false) && v2.reason == "intent: #{Intent::MIS}" &&
      v3.allow == false && v3.checks == i.with_intent(false) && v3.reason == "intent: #{Intent::OPEN}" &&
      v4.checks == i.with_intent(false) && v4.reason == "intent: #{Intent::NOENV}" &&
      v5.allow == true && v5.checks == i.with_intent
  end

  t('verify_pcactn: tampering intent after signing fails leaf_signature while intent passes; first reason wins') do
    i = Intent
    g = i.grant
    bound = i.pcactn(g, 'intent' => i.intent)
    v = i.verify(bound.merge('intent' => i.intent('fidelity_ppm' => 999_999)), g)
    w = i.verify(bound, g, { 'min_fidelity_ppm' => 950_001 }, aud: 'other')
    v.allow == false && v.checks == i.all_ok.merge('leaf_signature' => false, 'intent' => true) &&
      v.reason.start_with?('leaf_signature: ') &&
      w.checks['audience'] == false && w.checks['intent'] == false && w.reason.start_with?('audience: ')
  end

  t('verify_pcactn: signed edge values and a 128-byte salt verify') do
    i = Intent
    g = i.grant
    salt = "é" * 64
    g2 = i.root([i.env(salt)])
    [{ 'fidelity_ppm' => 0 }, { 'fidelity_ppm' => 1_000_000 }, { 'residual_risk_ppm' => 0 }, { 'residual_risk_ppm' => Intent::MAX_SAFE }]
      .all? { |o| (v = i.verify(i.pcactn(g, 'intent' => i.intent(o)), g)).allow == true && v.checks == i.with_intent } &&
      i.verify(i.pcactn(g2, 'intent' => i.intent('goal_salt' => salt)), g2).checks == i.with_intent
  end
end
