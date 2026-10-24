#!/usr/bin/env ruby
# frozen_string_literal: true

# Plain conformance runner (wire format v2 + v2.1 agent-leaf share binding + PQ crypto-agility).
# Run: ruby sdks/ruby-pca/conformance.rb   (exit 1 on any failure)
require_relative 'lib/atlas_pca'
require 'json'

DIR = File.expand_path('conformance', __dir__)
# loose: the vectors file carries deliberately-bad values (lone surrogates, floats, 40-deep nesting) as
# already-parsed objects; verification re-validates every value. Raw `pcactn_json` goes through the strict profile.
doc = AtlasPca.parse_json(File.read(File.join(DIR, 'vectors.json'), encoding: 'UTF-8'), loose: true)
$fails = 0
$count = 0

def check(cond, msg)
  $count += 1
  return if cond

  $fails += 1
  warn "FAIL: #{msg}"
end

abort 'not a format-2 file' unless doc['format'] == 2 && doc['ver'] == 2

# The SIGNATURE SUITES this Ruby verifier implements in this runtime: its capability manifest (AtlasPca.supported_suites,
# OpenSSL >= 3.5: Ed25519 + ML-DSA-65/87 + SLH-DSA-SHA2-128f/256s and their hybrids; packages/pca/conformance/SUITES.md).
# A vector whose verdict needs a suite outside it is NOT skipped silently: the verifier must deny it with the distinct
# reason unsupported_suite (asserted below, counted). A terminal {wire:false} negative is suite-agnostic and still runs.
SUPPORTED_SIG_SUITES = AtlasPca.supported_suites.freeze

# The concrete signature suite a vector exercises that this verifier does NOT implement, or nil.
# For requires:"pq" that is the LEAF `alg`; for requires:"pq-nonleaf" the first capability-hop `alg` outside
# SUPPORTED_SIG_SUITES. nil for core vectors and vectors that stay entirely within the supported suites.
def unsupported_suite(v)
  p = v['pcactn']
  return nil unless p.is_a?(Hash)

  alg = ->(o) { (o.is_a?(Hash) && o['alg'].is_a?(String)) ? o['alg'] : 'ed25519' }
  case v['requires']
  when 'pq'
    a = alg.call(p)
    SUPPORTED_SIG_SUITES.include?(a) ? nil : a
  when 'pq-nonleaf'
    hops = p['cap_chain'].is_a?(Array) ? p['cap_chain'] : []
    hops.map { |h| alg.call(h) }.find { |a| !SUPPORTED_SIG_SUITES.include?(a) }
  when String
    # 0.4.1: a vector that names one concrete suite (`requires: "ml-dsa-87"`, `"slh-dsa-sha2-128f"`) this verifier lacks.
    r = v['requires']
    r.empty? || SUPPORTED_SIG_SUITES.include?(r) ? nil : r
  end
end

def terminal_wire_false?(exp)
  c = exp['checks']
  c.is_a?(Hash) && c.keys == ['wire'] && c['wire'] == false
end

# The signature suite a pq / pq-nonleaf vector actually exercises (for honest per-suite reporting), whether or
# not this verifier supports it: the LEAF `alg` for requires:"pq"; the first non-ed25519 capability-hop `alg`
# (else ed25519) for requires:"pq-nonleaf".
def exercised_suite(v)
  p = v['pcactn']
  return 'ed25519' unless p.is_a?(Hash)

  alg = ->(o) { (o.is_a?(Hash) && o['alg'].is_a?(String)) ? o['alg'] : 'ed25519' }
  case v['requires']
  when 'pq' then alg.call(p)
  when 'pq-nonleaf'
    hops = p['cap_chain'].is_a?(Array) ? p['cap_chain'] : []
    hops.map { |h| alg.call(h) }.find { |a| a != 'ed25519' } || 'ed25519'
  else 'ed25519'
  end
end

# ---------------------------------------------------------------- vectors
vs = doc['vectors']
abort 'no vectors' if vs.nil? || vs.empty?

$skipped = 0
$ran = 0
per_suite_ran = Hash.new(0)
per_suite_skipped = Hash.new(0)
$v2_unsupported = 0
V2_CHECKS = %w[schema intent_session layers accumulators map facts provenance classes].freeze
vs.each do |v|
  bucket = v['requires'] || 'core'
  suite = unsupported_suite(v)
  # Intent Layer v2: `requires_suite` names the signature suite a vector needs. Implemented here (the dispatch's
  # supported_suites: in the dispatch AND its backend available in this runtime): compared exactly below. Otherwise the
  # verifier must deny, and when the first failing check is a v2 check its reason must contain `unsupported_suite` (a core
  # check failing first only needs the deny).
  rs = v['requires_suite']
  if rs.is_a?(String) && !AtlasPca.supported_suites.include?(rs)
    ctx = v['context']
    got = AtlasPca.verify_pcactn(v['pcactn'], v['grant'], now: ctx['now'], audience: ctx['aud'], intent_v2: ctx['intent_v2'])
    first = got.checks.find { |_, ok| !ok }&.first
    # a vector that names its refusal (reason_contains: e.g. the session-root pin checks) reaches it before the suite work
    rc = v['expect']['reason_contains']
    ok = got.allow == false && (rc.is_a?(String) ? got.reason.to_s.include?(rc) : (!V2_CHECKS.include?(first) || got.reason.to_s.include?('unsupported_suite')))
    check(ok, "#{v['name']}: suite #{rs} is not implemented here: want a deny (unsupported_suite when a v2 check fails first), got allow=#{got.allow} (#{got.reason})")
    $v2_unsupported += 1
    next
  end
  if suite && !terminal_wire_false?(v['expect'])
    $skipped += 1
    per_suite_skipped["#{bucket} | #{suite}"] += 1
    if v['pcactn'].is_a?(Hash)
      ctx = v['context']
      got = AtlasPca.verify_pcactn(v['pcactn'], v['grant'], now: ctx['now'], audience: ctx['aud'])
      check(got.allow == false && got.reason.to_s.include?(AtlasPca::UNSUPPORTED_SUITE),
            "#{v['name']}: suite #{suite} is not supported here: want a deny with unsupported_suite, got allow=#{got.allow} (#{got.reason})")
    end
    next
  end
  $ran += 1
  per_suite_ran["#{bucket} | #{exercised_suite(v)}"] += 1 if bucket != 'core'

  ctx = v['context']
  input = v.key?('pcactn_json') ? v['pcactn_json'] : v['pcactn']
  # Intent Layer M2: an `intent-*` vector may carry `context.intent_policy`; `expect.checks.intent` is present exactly
  # when the check was evaluated (the check-set comparison below covers it).
  # `context.intent_policy_json` (raw JSON TEXT, parsed with the platform parser) wins over `context.intent_policy`.
  ipol = ctx.key?('intent_policy_json') ? AtlasPca.parse_intent_policy_json(ctx['intent_policy_json']) : ctx['intent_policy']
  # Intent Layer v2: `context.intent_v2` is the verifier state (policy, params, schema, session, layers, acc, wb); the v2
  # checks appear in `expect.checks` exactly when reported (the check-set comparison below covers them).
  got = AtlasPca.verify_pcactn(input, v['grant'], now: ctx['now'], audience: ctx['aud'], allowed_suites: ctx['allowed_suites'],
                                                  intent_policy: ipol, intent_v2: ctx['intent_v2'])
  exp = v['expect']
  check(got.allow == exp['allow'], "#{v['name']}: allow=#{got.allow} want #{exp['allow']} (#{got.reason})")
  if exp['reason_contains'].is_a?(String)
    check(got.reason.to_s.include?(exp['reason_contains']), "#{v['name']}: reason #{got.reason.inspect} lacks #{exp['reason_contains']}")
  end
  check(got.checks.keys.sort == exp['checks'].keys.sort, "#{v['name']}: check set #{got.checks.keys} want #{exp['checks'].keys}")
  exp['checks'].each do |k, w|
    check(got.checks[k] == w, "#{v['name']}: check #{k}=#{got.checks[k]} want #{w}")
  end
end

# ------------------------------------------------- v2.1 threshold-share binding
# Every primitives.threshold_share[] entry must verify over the signerSetHash|t-bound share message iff its
# `valid` flag (default true). verify_threshold_share RECOMPUTES the bound message fail-closed, so in
# particular the pre-v2.1 bare-threshold-message agent share and a cross-signer-set replay are REJECTED.
shares = doc['primitives']['threshold_share']
abort 'no threshold_share primitives' if shares.nil? || shares.empty?
$share_accept = 0
$share_reject = 0
$bare_rejected = false
$wrong_set_rejected = false
$share_unsupported = 0
shares.each do |s|
  name = s['name'] || s['role']
  want = s.key?('valid') ? s['valid'] : true
  got = AtlasPca.verify_threshold_share(s)
  # Suite capability: an entry whose `requires` suite this runtime lacks is not compared; it must be refused (fail closed).
  if s['requires'].is_a?(String) && !SUPPORTED_SIG_SUITES.include?(s['requires'])
    $share_unsupported += 1
    check(got == false, "threshold_share #{name}: share under unsupported suite #{s['requires']} verified (want fail closed)")
    next
  end
  check(got == want, "threshold_share #{name}: verified=#{got} want valid=#{want}")
  want ? ($share_accept += 1) : ($share_reject += 1)
  $bare_rejected = true if name == 'agent-bare-rejected' && got == false
  $wrong_set_rejected = true if name == 'agent-bound-wrong-set' && got == false
end
check($bare_rejected, 'v2.1 binding: the pre-v2.1 bare agent share MUST be rejected')
check($wrong_set_rejected, 'v2.1 binding: a cross-signer-set agent share replay MUST be rejected')

# --------------------------------------------------------- pq_artifact primitives
# Representative PQ signatures for the non-leaf transparency/authority surfaces (sth, revocation, beacon,
# bond-settlement, safety-certificate, judge-verdict, software-attestation). Each routes through the SAME
# agility seam as the leaf; the signature over the 32-byte `message` must verify iff `valid`. Entries under
# an unsupported suite need a genuine crypto verdict and are skipped explicitly (never silently passed).
arts = doc['primitives']['pq_artifact']
$art_ran = 0
$art_skipped = 0
art_skipped_suites = Hash.new(0)
if arts.is_a?(Array)
  arts.each do |a|
    alg = a['alg'].is_a?(String) ? a['alg'] : 'ed25519'
    unless SUPPORTED_SIG_SUITES.include?(alg)
      $art_skipped += 1
      art_skipped_suites[alg] += 1
      next
    end
    $art_ran += 1
    want = a.key?('valid') ? a['valid'] : true
    got = AtlasPca.verify_pq_artifact(a)
    check(got == want, "pq_artifact #{a['artifact']}/#{alg}: verified=#{got} want valid=#{want}")
  end
end

# --------------------------------------------------------------- other primitives
prim = doc['primitives']
prim['canonical'].each do |c|
  s = AtlasPca.canonicalize(c['value'])
  check(s == c['expect'], "canonical mismatch: #{s.inspect} vs #{c['expect'].inspect}")
  check(AtlasPca.hash_canonical(c['value']) == c['hash'], "hash mismatch for #{s}")
end

prim['json_parse'].each do |j|
  got = begin
    AtlasPca.parse_json(j['input'], any_top: true)
  rescue AtlasPca::Malformed
    :rejected
  end
  if j['accept']
    check(got != :rejected, "json_parse should accept #{j['input'].inspect}")
    check(got != :rejected && AtlasPca.canonicalize(got) == j['canonical'], "json_parse canonical #{j['input'].inspect}")
  else
    check(got == :rejected, "json_parse should reject #{j['input'].inspect}")
  end
end

prim['b64u'].each do |b|
  ok = !AtlasPca.b64d(b['input'], b['len']).nil?
  check(ok == b['valid'], "b64u #{b['input'].inspect} len=#{b['len'].inspect}: got #{ok} want #{b['valid']}")
end

prim['merkle'].each do |m|
  leaves = m['leaves']
  root = AtlasPca.merkle_root(leaves)
  check(root == m['root'], "merkle root mismatch #{root} vs #{m['root']}")
  m['proofs'].each_with_index do |p, i|
    check(AtlasPca.verify_inclusion(root, p, leaves[i]), "proof #{i} does not verify")
  end
end
check(AtlasPca.params_digest(nil) == prim['params_digest_empty'], 'empty params digest mismatch')

# ------------------------------------------------- standalone chain API: root PQ authority (R4-01)
# primitives.chain_pin[]: verify_chain(chain, expected_root_issuer, ..., pq_pins, trusted_root). A non-ed25519 ROOT needs a
# verifier-side pin or the stored grant. Suite capability: an entry whose `requires` suite this runtime's OpenSSL lacks is
# compared only on its pin refusal (decided on the registered suite, before any crypto); otherwise it must be refused, with
# unsupported_suite when the reference accepts it, and is counted as skipped.
chain_pins = prim['chain_pin'] || []
abort 'no chain_pin primitives' if chain_pins.length < 25
$cp_ran = 0
$cp_skipped = 0
chain_pins.each do |v|
  reason = v['expect']['reason'].to_s
  pin_refusal = reason.start_with?('hop 0: root suite')
  rs, ok = AtlasPca.verify_chain(v['chain'], v['expected_root_issuer'], !v['expected_root_issuer'].nil?, v['allowed_suites'], v['pq_pins'], v['trusted_root'])
  if v['requires'].is_a?(String) && !SUPPORTED_SIG_SUITES.include?(v['requires']) && !pin_refusal
    $cp_skipped += 1
    check(ok == false, "#{v['name']}: accepted under unsupported suite #{v['requires']} (want fail closed)")
    check(rs.to_s.include?(AtlasPca::UNSUPPORTED_SUITE), "#{v['name']}: want an unsupported_suite refusal (#{rs})") if v['expect']['ok']
    next
  end
  $cp_ran += 1
  check(ok == v['expect']['ok'], "#{v['name']}: ok=#{ok} want #{v['expect']['ok']} (#{rs})")
  check(rs == reason, "#{v['name']}: reason #{rs.inspect} want #{reason.inspect}") if pin_refusal
end
check($cp_ran + $cp_skipped == chain_pins.length, 'chain_pin accounting')

# ------------------------------------------------- round 6: whole signer set, signer-set hash, malformed input
# primitives.threshold_set[] (R6-02, R6-03/R6-04): verify_threshold_share == `valid`; entries whose `requires` suite this
# verifier does not implement are skipped with a count.
tset = prim['threshold_set'] || []
abort 'no threshold_set primitives' if tset.length < 50
$ts_ran = 0
$ts_skipped = 0
tset.each do |e|
  if e['requires'] && !SUPPORTED_SIG_SUITES.include?(e['requires'])
    $ts_skipped += 1
    next
  end
  $ts_ran += 1
  got = begin
    AtlasPca.verify_threshold_share(e)
  rescue StandardError => ex
    "raised #{ex.class}"
  end
  check(got == e['valid'], "threshold_set #{e['name']}: got #{got} want #{e['valid']}")
end
# primitives.signer_set_hash[]: UTF-8 byte order, pq_pk carried whenever it is a string (incl. "").
(prim['signer_set_hash'] || []).each do |e|
  h = AtlasPca.signer_set_hash(e['signer_set'])
  check(!h.nil? && AtlasPca.b64e(h) == e['hash'], "signer_set_hash #{e['name']}")
end
# primitives.malformed[] (R6-05): every entry is a clean deny; nothing may raise out of a public entry point.
malformed = prim['malformed'] || []
abort 'no malformed primitives' if malformed.length < 80
malformed.each do |m|
  inp = m['input']
  denied = begin
    case m['api']
    when 'chain'
      _, ok = AtlasPca.verify_chain(inp['chain'], inp['expected_root_issuer'], true)
      ok == false
    when 'threshold_share' then AtlasPca.verify_threshold_share(inp) == false
    when 'pcactn_json'
      AtlasPca.verify_pcactn(inp['text'], inp['grant'], now: inp['now'], audience: inp['aud']).allow == false
    else false
    end
  rescue StandardError => ex
    warn "  #{m['name']} raised #{ex.class}: #{ex.message[0, 80]}"
    false
  end
  check(denied, "malformed #{m['name']} (#{m['api']}): not a clean deny")
end

# ------------------------------------------------- JSON nesting depth (MAX_JSON_DEPTH = 32) on every untrusted entry point
# primitives.depth[] (gen-conformance-depth.mjs): limit-1 / limit / limit+1 and a huge depth per api; `valid` is the
# reference verdict and nothing (not even SystemStackError) may escape. A huge case carries `expand`
# { marker, levels, leaf }: the value is built here ITERATIVELY so the verifier, not this runner, faces the depth.
def depth_nest(levels, leaf)
  v = leaf
  levels.times { v = [v] }
  v
end

def depth_expand(input, ex)
  return input if ex.nil?

  if input.is_a?(Hash) && input['text'].is_a?(String) && input['text'].include?(ex['marker'])
    text = input['text'].sub(ex['marker']) { ('[' * ex['levels']) + AtlasPca.canonicalize(ex['leaf']) + (']' * ex['levels']) }
    return input.merge('text' => text)
  end
  deep = depth_nest(ex['levels'], ex['leaf'])
  stack = [input]
  until stack.empty?
    node = stack.pop
    if node.is_a?(Hash)
      node.each { |k, x| x == ex['marker'] ? (node[k] = deep) : stack.push(x) }
    elsif node.is_a?(Array)
      node.each_index { |i| node[i] == ex['marker'] ? (node[i] = deep) : stack.push(node[i]) }
    end
  end
  input
end

depth_cases = prim['depth'] || []
abort 'no depth primitives' if depth_cases.length < 12
depth_cases.each do |d|
  inp = depth_expand(d['input'], d['expand'])
  got = begin
    case d['api']
    when 'chain'
      _, ok = AtlasPca.verify_chain(inp['chain'], inp['expected_root_issuer'], !inp['expected_root_issuer'].nil?)
      ok
    when 'threshold_share' then AtlasPca.verify_threshold_share(inp)
    when 'pcactn_json'
      AtlasPca.verify_pcactn(inp['text'], inp['grant'], now: inp['now'], audience: inp['aud']).allow
    when 'json_parse'
      begin
        AtlasPca.parse_json(inp['text'], any_top: true)
        true
      rescue AtlasPca::Malformed
        false
      end
    else "unknown api #{d['api']}"
    end
  rescue Exception => e # rubocop:disable Lint/RescueException
    "raised #{e.class}"
  end
  check(got == d['valid'], "depth #{d['name']} (#{d['api']}, depth #{d['depth']}): got #{got} want #{d['valid']}")
end

# ------------------------------------------------------------- 0.4.1 policy helpers + header
# primitives.caveat_eval: evaluate_caveats(policy_caveats(grant, chain), context) == [expect.allow, expect.failed] (root caveats
# outside the envelope are evaluated like delegated ones). primitives.pca_header: decode_pca_header (strict unpadded base64url of
# strict UTF-8) is valid iff `valid`, and then yields `text`.
caveat_eval = prim['caveat_eval'] || []
check(caveat_eval.length >= 40, "caveat_eval: #{caveat_eval.length} cases")
$ce_pass = 0
caveat_eval.each do |c|
  want = [c['expect']['allow'], c['expect']['failed']]
  got = begin
    AtlasPca.evaluate_caveats(AtlasPca.policy_caveats(c['grant'], c['chain']), c['context'])
  rescue Exception => e # rubocop:disable Lint/RescueException
    "raised #{e.class}"
  end
  check(got == want, "caveat_eval #{c['name']}: got #{got.inspect} want #{want.inspect}")
  $ce_pass += 1 if got == want
end
pca_header = prim['pca_header'] || []
check(pca_header.length >= 27, "pca_header: #{pca_header.length} cases")
$ph_pass = 0
pca_header.each do |c|
  ok = begin
    got = AtlasPca.decode_pca_header(c['input'])
    !got.nil? == c['valid'] && (got.nil? || got == c['text'])
  rescue Exception # rubocop:disable Lint/RescueException
    false
  end
  check(ok, "pca_header #{c['name']}")
  $ph_pass += 1 if ok
end

# ------------------------------------------------- Intent Layer v2 primitives (rules 13, 14, 16, 17, 18)
# Function-level tables; reasons are never compared. A table absent from vectors.json (or a function this build lacks) is
# skipped with a count. intent_schema: {sig, digest?, conform {ok, code?, path?}}; intent_revocation: {ok};
# intent_world: ok (+ world, single_source when true); intent_provenance: outcome (+ labels, classes unless deny,
# friction for question); intent_classifier: ok (+ classes when true); intent_wb_active: facts, provenance, classes;
# intent_read_purpose: outcome, minimise, uncovered exactly; intent_map_commit: map_commit; intent_map (rule 19): ok and,
# when ok, cell and p_ppm.
$v2_prim = Hash.new(0)
$v2_prim_skipped = Hash.new(0)
$v2_prim_unsupported = Hash.new(0)
v2_refused = lambda do |refused, ref_accepts, reason|
  refused && (!ref_accepts || reason.to_s.include?(AtlasPca::UNSUPPORTED_SUITE))
end
V2_SUITE_REFUSAL = {
  'intent_world' => ->(i, x) { g = AtlasPca.decide_intent_world(i); v2_refused.call(!g['ok'], x['ok'], g['reason']) },
  'intent_provenance' => lambda { |i, x|
    g = AtlasPca.decide_param_provenance(i)
    v2_refused.call(g['outcome'] == 'deny', x['outcome'] != 'deny', g['reason'])
  },
  'intent_classifier' => ->(i, x) { g = AtlasPca.decide_classifier_dimensions(i); v2_refused.call(!g['ok'], x['ok'], g['reason']) }
}.freeze
v2_table = lambda do |name, fn, &blk|
  rows = prim[name]
  unless rows.is_a?(Array)
    $v2_prim_skipped[name] += 1
    next
  end
  unless AtlasPca.respond_to?(fn)
    $v2_prim_skipped[name] += rows.length
    next
  end
  rows.each do |e|
    ok = begin
      # README "Raw JSON text members": `input_json` (raw text, parsed with the platform parser; a bare -0 stays negative
      # zero) takes precedence over `input`.
      inp = e.key?('input_json') ? AtlasPca.parse_json_text(e['input_json']) : e['input']
      rs = e['requires_suite']
      if rs.is_a?(String) && !SUPPORTED_SIG_SUITES.include?(rs) && V2_SUITE_REFUSAL.key?(name)
        # Suite capability: not compared; refused, with unsupported_suite when the reference accepts it.
        $v2_prim_unsupported[name] += 1
        V2_SUITE_REFUSAL[name].call(inp, e['expect'])
      else
        blk.call(inp, e['expect'])
      end
    rescue Exception => ex # rubocop:disable Lint/RescueException
      warn "  #{name} #{e['name']} raised #{ex.class}: #{ex.message[0, 120]}"
      false
    end
    check(ok, "#{name} #{e['name']}")
    $v2_prim[name] += 1
  end
end
v2_table.call('intent_schema', :verify_action_schema) do |i, x|
  sig = AtlasPca.verify_action_schema(i['schema'], i['keys'])['ok']
  c = AtlasPca.conform_action(i['schema'], i['verb'], i['params'])
  want_c = x['conform']
  sig == x['sig'] && (!x.key?('digest') || AtlasPca.action_schema_digest(i['schema']) == x['digest']) &&
    c['ok'] == want_c['ok'] && c['code'] == want_c['code'] && c['path'] == want_c['path']
end
v2_table.call('intent_revocation', :intent_revocation_primitive) { |i, x| AtlasPca.intent_revocation_primitive(i)['ok'] == x['ok'] }
v2_table.call('intent_world', :decide_intent_world) do |i, x|
  g = AtlasPca.decide_intent_world(i)
  g['ok'] == x['ok'] && (!x['ok'] || (g['world'] == x['world'] && g['single_source'] == x['single_source']))
end
v2_table.call('intent_provenance', :decide_param_provenance) do |i, x|
  g = AtlasPca.decide_param_provenance(i)
  g['outcome'] == x['outcome'] && (x['outcome'] == 'deny' || (g['labels'] == x['labels'] && g['classes'] == x['classes'])) &&
    (x['outcome'] != 'question' || g['friction'] == x['friction'])
end
v2_table.call('intent_classifier', :decide_classifier_dimensions) do |i, x|
  g = AtlasPca.decide_classifier_dimensions(i)
  g['ok'] == x['ok'] && (!x['ok'] || g['classes'] == x['classes'])
end
v2_table.call('intent_wb_active', :intent_wb_active) do |i, x|
  g = AtlasPca.intent_wb_active(i)
  %w[facts provenance classes].all? { |k| g[k] == x[k] }
end
v2_table.call('intent_map_commit', :map_commit_of_leaves) do |i, x|
  AtlasPca.map_commit_of_leaves(i['leaves']) == x['map_commit']
end
v2_table.call('intent_map', :intent_map_primitive) do |i, x|
  g = AtlasPca.intent_map_primitive(i)
  g['ok'] == x['ok'] && (!x['ok'] || (g['cell'] == x['cell'] && g['p_ppm'] == x['p_ppm']))
end
v2_table.call('intent_read_purpose', :decide_read_purpose) do |i, x|
  g = AtlasPca.decide_read_purpose(i)
  %w[outcome minimise uncovered].all? { |k| g[k] == x[k] }
end

# -------------------------------------------------------------------- report
puts '=== PCA Ruby conformance (wire v2 / v2.1) ==='
puts "threshold_set: #{$ts_ran} ran, #{$ts_skipped} skipped; signer_set_hash: #{(prim['signer_set_hash'] || []).length}; malformed: #{malformed.length}; depth: #{depth_cases.length}"
puts "vectors: #{$ran} ran, #{$skipped} skipped of #{vs.length} total"
unless per_suite_ran.empty?
  puts '  pq/pq-nonleaf suites RAN (incl. terminal-wire negatives under unsupported suites):'
  per_suite_ran.sort.each { |k, n| puts "    #{k}: #{n}" }
end
unless per_suite_skipped.empty?
  puts '  pq/pq-nonleaf suites SKIPPED (unimplemented, genuine-crypto verdict):'
  per_suite_skipped.sort.each { |k, n| puts "    #{k}: #{n}" }
end
puts "chain_pin: #{$cp_ran} ran, #{$cp_skipped} skipped of #{chain_pins.length}"
puts "threshold_share: #{$share_unsupported} refused as unsupported_suite (suite outside this runtime's manifest)" if $share_unsupported.positive?
puts "intent v2 primitives refused as unsupported_suite: #{$v2_prim_unsupported.sort.map { |k, n| "#{k} #{n}" }.join(', ')}" unless $v2_prim_unsupported.empty?
puts "threshold_share: #{shares.length} vectors (#{$share_accept} valid accepted, #{$share_reject} invalid rejected)"
puts "  v2.1 bare-agent-share rejected: #{$bare_rejected}; cross-signer-set replay rejected: #{$wrong_set_rejected}"
if arts.is_a?(Array)
  puts "pq_artifact: #{$art_ran} ran, #{$art_skipped} skipped of #{arts.length} total"
  art_skipped_suites.sort.each { |k, n| puts "    skipped #{k}: #{n}" } unless art_skipped_suites.empty?
end
puts "caveat_eval: #{$ce_pass}/#{caveat_eval.length} pass; pca_header: #{$ph_pass}/#{pca_header.length} pass"
puts "intent v2 vectors needing a suite this runtime does not implement (required deny): #{$v2_unsupported}"
puts "intent v2 primitives ran: #{$v2_prim.sort.map { |k, n| "#{k} #{n}" }.join(', ')}"
puts "intent v2 primitives SKIPPED (table or function absent): #{$v2_prim_skipped.sort.map { |k, n| "#{k} #{n}" }.join(', ')}" unless $v2_prim_skipped.empty?
puts "assertions: #{$count}, failures: #{$fails}"
exit($fails.zero? ? 0 : 1)
