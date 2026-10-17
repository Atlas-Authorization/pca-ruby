#!/usr/bin/env ruby
# frozen_string_literal: true

# Intent Layer M2 (`envelope.intent`). Plain runner, no test framework:
#   ruby -Ilib test/test_intent.rb   (exit 1 on any failure)
# The shared `intent-*` conformance vectors (conformance.rb) pin the full contract; these are small native checks:
# wire refusals, the absent-policy back-compat verdict, policy misconfiguration, and a positive binding on a PCActn built
# and signed here, whose root grant's goal commitment comes from this library's own canonical hash.
require_relative '../lib/atlas_pca'
require 'json'
require 'openssl'

DIR = File.expand_path('../conformance', __dir__)
JSON_KEYS = JSON.parse(File.read(File.join(DIR, 'keys.json')))

$fails = 0
$count = 0

def check(cond, msg)
  $count += 1
  return if cond

  $fails += 1
  warn "FAIL: #{msg}"
end

seed = ->(n) { AtlasPca.b64d(JSON_KEYS[n]['seed'], 32) }
pk = ->(n) { OpenSSL::PKey.new_raw_private_key('ED25519', seed.call(n)) }
pub = ->(k) { AtlasPca.b64e(k.raw_public_key) }
PRINCIPAL = pk.call('principal')
AGENT = pk.call('agent')
NOW = 1_800_000_000_000
AUD = 'rs-intent'

REF = AtlasPca.b64e(AtlasPca.sha('intent/ref'.b))
MAP = AtlasPca.b64e(AtlasPca.sha('intent/map'.b))
SALT = 'c2FsdC1pbnRlbnQ'
INTENT = { 'ref' => REF, 'map_digest' => MAP, 'goal_salt' => SALT, 'fidelity_ppm' => 950_000,
           'residual_risk_ppm' => 4_310_000 }.freeze
COMMIT = AtlasPca.hash_canonical({ 'd' => "atlas-pca/goal/v1\u0000", 'goal' => "pca-intent:v1:#{REF}:#{MAP}", 'salt' => SALT })

# A signed root grant carrying `caveats`.
mint_root = lambda do |caveats|
  root = { 'issuer' => pub.call(PRINCIPAL), 'holder' => pub.call(AGENT), 'caveats' => caveats }
  digest = AtlasPca.hash_canonical(AtlasPca.body_of(root))
  root.merge('id' => digest, 'body_digest' => digest,
             'sig' => AtlasPca.b64e(PRINCIPAL.sign(nil, AtlasPca::CAP_DOMAIN + AtlasPca.b64d(digest, 32))))
end

# A signed PCActn under `root`, carrying `intent` when given (the slot is part of the signed body).
build = lambda do |root, intent = nil|
  action = { 'verb' => 'read', 'resource' => 'doc:1', 'params_digest' => AtlasPca.params_digest({ 'q' => 1 }),
             'reversibility_class' => 'reversible' }
  leaf = AtlasPca.plan_leaf('n1', action, AtlasPca.conditions_digest(nil, nil))
  zero = AtlasPca.b64e("\0".b * 32)
  p = {
    'ver' => 2, 'action' => action, 'grant_ref' => root['id'], 'cap_chain' => [root],
    'plan' => { 'root' => AtlasPca.merkle_root([leaf]), 'node_id' => 'n1', 'inclusion_proof' => { 'index' => 0, 'size' => 1, 'path' => [] } },
    'attestation' => { 'epoch' => 1, 'quote_digest' => zero, 'model_id' => 'm', 'measurement' => zero, 'operator' => 'op' },
    'provenance' => { 'causal_hash' => zero, 'taint_level' => 0, 'trusted_refs' => [] },
    'freshness' => { 'epoch' => 1, 'beacon_ref' => zero, 'accumulator_witness' => zero },
    'counter' => 0, 'risk_claim' => { 'r' => 0, 'inputs' => {} }, 'aud' => AUD, 'iat' => NOW - 1000, 'exp' => NOW + 60_000
  }
  p['intent'] = intent unless intent.nil?
  p.merge('sig' => AtlasPca.b64e(AGENT.sign(nil, AtlasPca.threshold_message(p))))
end

G = mint_root.call([{ 'type' => 'max_spend', 'usd' => 1 }, { 'type' => 'envelope', 'goal_commit' => COMMIT }])
verify = ->(p, policy = nil, grant = G) { AtlasPca.verify_pcactn(p, grant, now: NOW, audience: AUD, intent_policy: policy) }
BASE_KEYS = AtlasPca::CHECK_ORDER

# ---- positive binding (envelope is the SECOND caveat: the first `envelope` caveat counts)
bound = build.call(G, INTENT)
[nil, { 'require' => true }, { require: true }, { 'min_fidelity_ppm' => 950_000, 'max_residual_risk_ppm' => 4_310_000 }].each do |pol|
  v = verify.call(bound, pol)
  check(v.allow == true && v.checks['intent'] == true, "bound under #{pol.inspect}: #{v.reason} #{v.checks.inspect}")
  check(v.checks.keys == BASE_KEYS + ['intent'], "intent appended after counter: #{v.checks.keys}")
end
check(AtlasPca.intent_goal(REF, MAP) == "pca-intent:v1:#{REF}:#{MAP}", 'intent_goal')
check(AtlasPca.intent_goal_commit(REF, MAP, SALT) == COMMIT, 'intent_goal_commit')

# ---- thresholds and binding mismatches
v = verify.call(bound, { 'min_fidelity_ppm' => 950_001 })
check(v.allow == false && v.checks['intent'] == false && v.reason.start_with?('intent:'), "fidelity floor: #{v.reason}")
v = verify.call(bound, { 'max_residual_risk_ppm' => 4_309_999 })
check(v.allow == false && v.checks['intent'] == false, "residual ceiling: #{v.reason}")
[
  ['no envelope', mint_root.call([])],
  ['first envelope wins', mint_root.call([{ 'type' => 'envelope', 'goal_commit' => 'x' }, { 'type' => 'envelope', 'goal_commit' => COMMIT }])],
  ['goal_commit not a string', mint_root.call([{ 'type' => 'envelope', 'goal_commit' => 7 }])]
].each do |label, g|
  v = verify.call(build.call(g, INTENT), nil, g)
  check(v.allow == false && v.checks['intent'] == false && v.checks['leaf_signature'] == true, "#{label}: #{v.checks.inspect}")
end
v = verify.call(build.call(G, INTENT.merge('goal_salt' => 'wrong')))
check(v.allow == false && v.checks['intent'] == false, "goal_salt mismatch: #{v.reason}")

# ---- signed: tampering after signing breaks the leaf signature, the binding itself still holds
v = verify.call(bound.merge('intent' => INTENT.merge('fidelity_ppm' => 999_999)))
check(v.allow == false && v.checks['leaf_signature'] == false && v.checks['intent'] == true, "unsigned tamper: #{v.checks.inspect}")

# ---- absent intent: no policy (or an inactive one) is the pre-M2 verdict; an active policy fails closed
plain = build.call(G)
[nil, {}, { 'require' => false }, { 'require' => 1 }, 'not-a-hash'].each do |pol|
  v = verify.call(plain, pol)
  check(v.allow == true && v.checks.keys == BASE_KEYS, "absent under #{pol.inspect}: #{v.checks.inspect}")
end
[{ 'require' => true }, { 'min_fidelity_ppm' => 1 }, { max_residual_risk_ppm: 5 }].each do |pol|
  v = verify.call(plain, pol)
  check(v.allow == false && v.checks['intent'] == false && v.checks.keys.last == 'intent', "required under #{pol.inspect}")
end

# ---- policy misconfiguration fails closed (even for a correctly bound intent)
[{ 'min_fidelity_ppm' => -1 }, { 'max_residual_risk_ppm' => 0.5 }, { 'min_fidelity_ppm' => nil },
 { 'min_fidelity_ppm' => true }, { 'max_residual_risk_ppm' => '5' }].each do |pol|
  st, why = AtlasPca.decide_intent_binding(INTENT, G, pol)
  check(st == :fail && why.include?('misconfigured'), "misconfigured #{pol.inspect}: #{st} #{why}")
  check(verify.call(bound, pol).checks['intent'] == false, "misconfigured #{pol.inspect} (verify)")
end

# ---- wire refusals (terminal)
without = ->(k) { INTENT.reject { |kk, _| kk == k } }
[
  'x', nil, [INTENT], INTENT.merge('note' => 'x'), without.call('goal_salt'), without.call('fidelity_ppm'),
  INTENT.merge('ref' => "#{REF}="), INTENT.merge('map_digest' => "+#{MAP[1..]}"), INTENT.merge('ref' => 1),
  INTENT.merge('ref' => AtlasPca.b64e('x'.b * 31)), INTENT.merge('goal_salt' => ''),
  INTENT.merge('goal_salt' => "#{"é" * 64}a"), INTENT.merge('goal_salt' => 5),
  INTENT.merge('fidelity_ppm' => 1_000_001), INTENT.merge('fidelity_ppm' => -1), INTENT.merge('fidelity_ppm' => 1.5),
  INTENT.merge('fidelity_ppm' => '950000'), INTENT.merge('residual_risk_ppm' => -1),
  INTENT.merge('residual_risk_ppm' => 0.25), INTENT.merge('residual_risk_ppm' => true)
].each do |bad|
  v = verify.call(build.call(G, bad))
  check(v.allow == false && v.checks == { 'wire' => false }, "wire refusal #{bad.inspect[0, 60]}: #{v.checks.inspect}")
end
# well-formed edges
salt128 = "é" * 64
g128 = mint_root.call([{ 'type' => 'envelope',
                         'goal_commit' => AtlasPca.intent_goal_commit(REF, MAP, salt128) }])
v = verify.call(build.call(g128, INTENT.merge('goal_salt' => salt128)), nil, g128)
check(v.allow == true && v.checks['intent'] == true, "128-byte salt: #{v.reason}")
[INTENT.merge('fidelity_ppm' => 1_000_000, 'residual_risk_ppm' => 0), INTENT.merge('residual_risk_ppm' => 9_007_199_254_740_991)].each do |ok|
  v = verify.call(build.call(G, ok))
  check(v.allow == true, "edge #{ok.inspect[0, 60]}: #{v.reason}")
end

puts "intent: #{$count} assertions, #{$fails} failures"
exit($fails.zero? ? 0 : 1)
