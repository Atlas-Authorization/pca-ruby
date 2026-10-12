#!/usr/bin/env ruby
# frozen_string_literal: true

# PCA 0.4.1 (reference: packages/pca/src r041-*.test.ts, conformance-r041.test.ts). Plain runner, no test framework:
#   ruby -Ilib test/test_r041.rb   (exit 1 on any failure)
#  - threshold share signatures are validated per suite at the wire stage (`r041-share-*` vectors);
#  - the policy-layer helpers policy_caveats / evaluate_caveats (root caveats outside the envelope are evaluated like
#    delegated ones, incl. max_spend), corpus primitives.caveat_eval;
#  - the PCA-Action header is strict unpadded base64url of strict UTF-8 (decode_pca_header), corpus primitives.pca_header.
require_relative '../lib/atlas_pca/rack_middleware'
require 'stringio'
require 'base64'
require 'json'
require 'openssl'

DIR = File.expand_path('../conformance', __dir__)
DOC = AtlasPca.parse_json(File.read(File.join(DIR, 'vectors.json'), encoding: 'UTF-8'), loose: true)
JSON_KEYS = JSON.parse(File.read(File.join(DIR, 'keys.json')))
SUPPORTED = %w[ed25519 ml-dsa-65 hybrid-ed25519-ml-dsa-65].freeze

$fails = 0
$count = 0

def check(cond, msg)
  $count += 1
  return if cond

  $fails += 1
  warn "FAIL: #{msg}"
end

# Run a block; an exception of any class is a failed check (the red run calls helpers that do not exist yet).
def safely(label)
  yield
rescue Exception => e # rubocop:disable Lint/RescueException
  check(false, "#{label}: raised #{e.class}: #{e.message[0, 160]}")
  nil
end

# ---------------------------------------------------------------- caveat_eval corpus
cases = DOC['primitives']['caveat_eval'] || []
check(cases.length >= 40, "caveat_eval: #{cases.length} cases")
by = cases.to_h { |c| [c['name'], c] }
check(by['r041-root-max-spend-exceeded']['expect']['allow'] == false, 'deny half of the root max_spend pair')
check(by['r041-root-max-spend-within']['expect']['allow'] == true, 'allow half of the root max_spend pair')
ce_bad = 0
cases.each do |c|
  ok = safely("caveat_eval #{c['name']}") do
    got = AtlasPca.evaluate_caveats(AtlasPca.policy_caveats(c['grant'], c['chain']), c['context'])
    want = [c['expect']['allow'], c['expect']['failed']]
    check(got == want, "caveat_eval #{c['name']}: got #{got.inspect} want #{want.inspect}")
    got == want
  end
  ce_bad += 1 unless ok
end

# ---------------------------------------------------------------- evaluate_caveats totality / fail-closed
safely('evaluate_caveats totality') do
  ctx = { 'now' => 1_800_000_000_000, 'action' => { 'params' => { 'amount' => 5 } } }
  ms = ->(usd) { { 'type' => 'max_spend', 'usd' => usd } }
  check(AtlasPca.evaluate_caveats(nil, ctx) == [false, ['<malformed caveats>']], 'nil list')
  check(AtlasPca.evaluate_caveats({}, ctx) == [false, ['<malformed caveats>']], 'Hash list')
  check(AtlasPca.evaluate_caveats('x', ctx) == [false, ['<malformed caveats>']], 'String list')
  check(AtlasPca.evaluate_caveats([], ctx) == [true, []], 'empty list')
  got = AtlasPca.evaluate_caveats(['max_spend', [], { 'type' => 1 }, { 'type' => 'note' }, { 'type' => 'predicates' }], ctx)
  check(got == [false, ['<malformed>', '<malformed>', '<malformed>', 'note', 'predicates']], "malformed/unknown: #{got.inspect}")
  check(AtlasPca.evaluate_caveats([ms.call(5)], ctx)[0] == true, 'int limit')
  check(AtlasPca.evaluate_caveats([ms.call(5.0)], ctx)[0] == true, 'float limit')
  check(AtlasPca.evaluate_caveats([ms.call(4.99)], ctx)[0] == false, 'over limit')
  check(AtlasPca.evaluate_caveats([ms.call(true)], ctx)[0] == false, 'bool limit')
  check(AtlasPca.evaluate_caveats([ms.call(Float::INFINITY)], ctx)[0] == false, 'infinite limit')
  check(AtlasPca.evaluate_caveats([ms.call(Float::NAN)], ctx)[0] == false, 'NaN limit')
  check(AtlasPca.evaluate_caveats([ms.call(5)], { 'now' => 1, 'action' => { 'params' => { 'amount' => true } } })[0] == false, 'bool amount')
  no_now = { 'action' => { 'params' => { 'amount' => 1 } } }
  check(AtlasPca.evaluate_caveats([ms.call(5)], no_now)[0] == true, 'max_spend needs no now')
  check(AtlasPca.evaluate_caveats([{ 'type' => 'budget_alloc', 'limit' => 1 }], no_now)[0] == false, 'budget_alloc needs now')
  check(AtlasPca.evaluate_caveats([ms.call(5)], nil) == [false, ['max_spend']], 'nil ctx')
  check(AtlasPca.evaluate_caveats([ms.call(5)], { 'now' => 1, 'params' => { 'amount' => 1 } })[0] == false, 'top-level params ignored')
  rv = [{ 'type' => 'reversibility_max', 'class' => 'irreversible' }]
  check(AtlasPca.evaluate_caveats(rv, { 'now' => 1, 'action' => { 'reversibility_class' => 'reversible' } })[0] == false,
        'reversibility_max reads ctx.reversibility_class only')
  check(AtlasPca.evaluate_caveats(rv, { 'now' => 1, 'reversibility_class' => 'rate_limited' })[0] == true, 'reversibility_max ok')
  check(AtlasPca.evaluate_caveats(rv, { 'now' => 1, 'reversibility_class' => 'unknown' })[0] == false, 'reversibility_max unknown')
  # symbol-keyed hashes are not JSON objects: no key matches, so nothing is satisfied
  check(AtlasPca.evaluate_caveats([{ type: 'max_spend', usd: 5 }], ctx) == [false, ['<malformed>']], 'symbol keys')
end

# ---------------------------------------------------------------- policy_caveats shapes
safely('policy_caveats shapes') do
  env = { 'type' => 'envelope' }
  a = { 'type' => 'max_spend', 'usd' => 1 }
  b = { 'type' => 'expires', 'at' => 2 }
  grant = { 'caveats' => [a, env, env] }
  check(AtlasPca.policy_caveats(grant, nil) == [a, env], 'first envelope only, nil chain')
  check(AtlasPca.policy_caveats(grant, 'nope') == [a, env], 'non-array chain')
  check(AtlasPca.policy_caveats(grant, []) == [a, env], 'empty chain')
  leaf = { 'caveats' => [a, env, env, b] }
  check(AtlasPca.policy_caveats(grant, [grant, leaf]) == [a, env, b], 'appended hop caveats')
  check(AtlasPca.policy_caveats(grant, [grant, { 'caveats' => 'x' }]) == [a, env], 'leaf caveats not an array')
  check(AtlasPca.policy_caveats(grant, [grant, 'leaf']) == [a, env], 'leaf not an object')
  check(AtlasPca.policy_caveats({}, [leaf]).nil?, 'grant without caveats')
  check(AtlasPca.policy_caveats({ 'caveats' => 'x' }, [leaf]) == 'x', 'grant caveats not an array')
  check(AtlasPca.policy_caveats('grant', [leaf]).nil?, 'grant not an object')
  check(AtlasPca.evaluate_caveats(AtlasPca.policy_caveats({}, [leaf]), { 'now' => 1 }) == [false, ['<malformed caveats>']], 'refused')
  # the input is not mutated
  check(grant['caveats'] == [a, env, env], 'grant caveats untouched')
end

# ---------------------------------------------------------------- pca_header corpus
hdr = DOC['primitives']['pca_header'] || []
check(hdr.length >= 27, "pca_header: #{hdr.length} cases")
ph_bad = 0
hdr.each do |c|
  ok = safely("pca_header #{c['name']}") do
    got = AtlasPca.decode_pca_header(c['input'])
    good = !got.nil? == c['valid'] && (got.nil? || (got == c['text'] && got.encoding == Encoding::UTF_8))
    check(good, "pca_header #{c['name']}: got #{got.inspect} want valid=#{c['valid']}")
    good
  end
  ph_bad += 1 unless ok
end
safely('decode_pca_header non-strings') do
  check(AtlasPca.decode_pca_header(nil).nil?, 'nil')
  check(AtlasPca.decode_pca_header(123).nil?, 'Integer')
  check(AtlasPca.decode_pca_header('').nil?, 'empty')
  check(AtlasPca.decode_pca_header('e30') == '{}', 'e30')
end

# ---------------------------------------------------------------- middleware: every lenient spelling is a 401
vector = DOC['vectors'].find { |v| v['name'] == 'valid-raw-json-format-insensitive' }
pcactn = AtlasPca.parse_json(vector['pcactn_json'])
grant = vector['grant']
canon = AtlasPca.b64e(vector['pcactn_json'].b)
resolver = ->(ref) { ref == pcactn['grant_ref'] ? grant : nil }
app = ->(_env) { [200, {}, ['ok']] }
mw = AtlasPca::RackMiddleware.new(app, audience: vector['context']['aud'], resolve_grant: resolver, now: vector['context']['now'])
env = ->(h) { { 'HTTP_PCA_ACTION' => h, 'rack.input' => StringIO.new('') } }
check(mw.call(env.call(canon))[0] == 200, 'canonical header verifies')
lenient = [
  canon + ('=' * ((4 - (canon.length % 4)) % 4)),
  canon.tr('-_', '+/'),
  Base64.strict_encode64(vector['pcactn_json'].b),
  " #{canon}", "#{canon} ", "#{canon}\t", "#{canon[0, 8]}\n#{canon[8..]}"
].uniq - [canon]
lenient.each do |h|
  status, = mw.call(env.call(h))
  check(status == 401, "lenient header #{h[0, 12].inspect}..: status #{status}")
end
# bytes that are not UTF-8 refuse at the DECODE step (the base64url 401), not at the JSON parser
status, _h, body = mw.call(env.call('__57'))
check(status == 401 && body.join.include?('not canonical base64url'), "non-UTF-8 header: #{status} #{body.join}")

# ---------------------------------------------------------------- per-suite share wire vectors
ran = 0
DOC['vectors'].each do |v|
  next unless v['name'].start_with?('r041-share-')
  next if v['requires'].is_a?(String) && !SUPPORTED.include?(v['requires'])

  ran += 1
  ctx = v['context']
  got = AtlasPca.verify_pcactn(v['pcactn'], v['grant'], now: ctx['now'], audience: ctx['aud'], allowed_suites: ctx['allowed_suites'])
  exp = v['expect']
  check(got.allow == exp['allow'], "#{v['name']}: allow=#{got.allow} want #{exp['allow']} (#{got.reason})")
  exp['checks'].each { |k, w| check(got.checks[k] == w, "#{v['name']}: check #{k}=#{got.checks[k]} want #{w}") }
end
check(ran == 18, "r041-share vectors run: #{ran}")

# ---------------------------------------------------------------- native construction (US-ASCII strings)
# A PCActn built as a Hash straight from the library's own helpers (b64e, hash_canonical, merkle_root, ...), signed, then
# verified: the strings b64e returns must pass the wire's encoding gate (they used to be US-ASCII-tagged and were refused).
safely('native PCActn from library helpers') do
  seed = ->(n) { AtlasPca.b64d(JSON_KEYS[n]['seed'], 32) }
  pk = ->(n) { OpenSSL::PKey.new_raw_private_key('ED25519', seed.call(n)) }
  pub = ->(k) { AtlasPca.b64e(k.raw_public_key) }
  principal = pk.call('principal')
  agent = pk.call('agent')
  check(AtlasPca.b64e('x'.b).encoding == Encoding::UTF_8, "b64e returns UTF-8 (got #{AtlasPca.b64e('x'.b).encoding})")
  root = { 'issuer' => pub.call(principal), 'holder' => pub.call(agent), 'caveats' => [] } # a root carries no `parent` key
  digest = AtlasPca.hash_canonical(AtlasPca.body_of(root))
  root = root.merge('id' => digest, 'body_digest' => digest,
                    'sig' => AtlasPca.b64e(principal.sign(nil, AtlasPca::CAP_DOMAIN + AtlasPca.b64d(digest, 32))))
  action = { 'verb' => 'read', 'resource' => 'doc:1', 'params_digest' => AtlasPca.params_digest({ 'q' => 1 }),
             'reversibility_class' => 'reversible' }
  leaf = AtlasPca.plan_leaf('n1', action, AtlasPca.conditions_digest(nil, nil))
  zero = AtlasPca.b64e("\0".b * 32)
  now = 1_800_000_000_000
  p = {
    'ver' => 2, 'action' => action, 'grant_ref' => digest, 'cap_chain' => [root],
    'plan' => { 'root' => AtlasPca.merkle_root([leaf]), 'node_id' => 'n1', 'inclusion_proof' => { 'index' => 0, 'size' => 1, 'path' => [] } },
    'attestation' => { 'epoch' => 1, 'quote_digest' => zero, 'model_id' => 'm', 'measurement' => zero, 'operator' => 'op' },
    'provenance' => { 'causal_hash' => zero, 'taint_level' => 0, 'trusted_refs' => [] },
    'freshness' => { 'epoch' => 1, 'beacon_ref' => zero, 'accumulator_witness' => zero },
    'counter' => 0, 'risk_claim' => { 'r' => 0, 'inputs' => {} }, 'aud' => 'rs-native', 'iat' => now - 1000, 'exp' => now + 60_000
  }
  p['sig'] = AtlasPca.b64e(agent.sign(nil, AtlasPca.threshold_message(p)))
  v = AtlasPca.verify_pcactn(p, root, now: now, audience: 'rs-native')
  check(v.allow == true, "native PCActn: allow=#{v.allow} (#{v.reason}) #{v.checks.inspect}")
  # the same PCActn with every string re-tagged US-ASCII (as `"...".force_encoding('US-ASCII')` or other libraries give)
  ascii = lambda do |x|
    case x
    when String then x.dup.force_encoding(Encoding::US_ASCII)
    when Array then x.map { |e| ascii.call(e) }
    when Hash then x.to_h { |k, e| [ascii.call(k), ascii.call(e)] }
    else x
    end
  end
  check(AtlasPca.verify_pcactn(ascii.call(p), ascii.call(root), now: now, audience: 'rs-native').allow == true, 'US-ASCII copy (native)')
end

safely('US-ASCII-tagged corpus PCActn; invalid encodings refused') do
  vec = DOC['vectors'].find { |x| x['name'] == 'valid-in-plan-action' }
  ascii = lambda do |x|
    case x
    when String then x.ascii_only? ? x.dup.force_encoding(Encoding::US_ASCII) : x
    when Array then x.map { |e| ascii.call(e) }
    when Hash then x.to_h { |k, e| [ascii.call(k), ascii.call(e)] }
    else x
    end
  end
  ctx = vec['context']
  run = ->(pc) { AtlasPca.verify_pcactn(pc, vec['grant'], now: ctx['now'], audience: ctx['aud']) }
  check(run.call(vec['pcactn']).allow == true, 'corpus vector verifies')
  check(run.call(ascii.call(vec['pcactn'])).allow == true, 'US-ASCII-tagged copy of a valid PCActn verifies')
  bad = {
    'US-ASCII with a high byte' => "a\xFFb".dup.force_encoding(Encoding::US_ASCII),
    'BINARY' => 'node'.b,
    'invalid UTF-8' => "a\xC0\xAF".dup.force_encoding(Encoding::UTF_8),
    'UTF-16LE' => 'node'.encode(Encoding::UTF_16LE)
  }
  bad.each do |label, str|
    pc = vec['pcactn'].merge('plan' => vec['pcactn']['plan'].merge('node_id' => str))
    r = run.call(pc)
    check(r.allow == false && r.checks == { 'wire' => false }, "#{label} string refused at the wire: #{r.checks.inspect}")
    key = vec['pcactn'].merge('progress_step' => { str => 1 })
    r = run.call(key)
    check(r.allow == false && r.checks == { 'wire' => false }, "#{label} key refused at the wire: #{r.checks.inspect}")
  end
end

puts "r041: caveat_eval #{cases.length - ce_bad}/#{cases.length}, pca_header #{hdr.length - ph_bad}/#{hdr.length}, " \
     "share vectors #{ran}; #{$count} assertions, #{$fails} failures"
exit($fails.zero? ? 0 : 1)
