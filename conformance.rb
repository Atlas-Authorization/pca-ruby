#!/usr/bin/env ruby
# frozen_string_literal: true

# Plain conformance runner (wire format v2 + v2.1 agent-leaf share binding + PQ crypto-agility).
# Run: ruby sdks/ruby-pca/conformance.rb   (exit 1 on any failure)
require_relative 'lib/atlas_pca'

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

# The SIGNATURE SUITES this Ruby verifier implements, via OpenSSL (Ed25519 raw + ML-DSA-65 raw, >= 3.5).
# These are the THREE cross-impl suites every conformant PCA implementation must agree on (GAP 1): classical
# Ed25519, pure lattice ML-DSA-65 (FIPS-204), and the hybrid Ed25519+ML-DSA-65. The remaining 7 registered
# suites (ml-dsa-87, slh-dsa-sha2-128f/256s, their Ed25519 hybrids, and the SUF-CMA nested hybrid) are NOT
# wired here, so any vector/primitive whose verdict needs a GENUINE signature outcome under one of them is
# skipped explicitly with a count — never silently passed. A terminal {wire:false} negative is suite-agnostic
# (an unknown/oversized `alg`/`pq_*` is rejected at the wire stage, which IS the correct contract verdict), so
# those still run and must pass.
SUPPORTED_SIG_SUITES = %w[ed25519 ml-dsa-65 hybrid-ed25519-ml-dsa-65].freeze

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
vs.each do |v|
  bucket = v['requires'] || 'core'
  suite = unsupported_suite(v)
  if suite && !terminal_wire_false?(v['expect'])
    $skipped += 1
    per_suite_skipped["#{bucket} | #{suite}"] += 1
    next
  end
  $ran += 1
  per_suite_ran["#{bucket} | #{exercised_suite(v)}"] += 1 if bucket != 'core'

  ctx = v['context']
  input = v.key?('pcactn_json') ? v['pcactn_json'] : v['pcactn']
  got = AtlasPca.verify_pcactn(input, v['grant'], now: ctx['now'], audience: ctx['aud'])
  exp = v['expect']
  check(got.allow == exp['allow'], "#{v['name']}: allow=#{got.allow} want #{exp['allow']} (#{got.reason})")
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
shares.each do |s|
  name = s['name'] || s['role']
  want = s.key?('valid') ? s['valid'] : true
  got = AtlasPca.verify_threshold_share(s)
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

# -------------------------------------------------------------------- report
puts '=== PCA Ruby conformance (wire v2 / v2.1) ==='
puts "vectors: #{$ran} ran, #{$skipped} skipped of #{vs.length} total"
unless per_suite_ran.empty?
  puts '  pq/pq-nonleaf suites RAN (incl. terminal-wire negatives under unsupported suites):'
  per_suite_ran.sort.each { |k, n| puts "    #{k}: #{n}" }
end
unless per_suite_skipped.empty?
  puts '  pq/pq-nonleaf suites SKIPPED (unimplemented, genuine-crypto verdict):'
  per_suite_skipped.sort.each { |k, n| puts "    #{k}: #{n}" }
end
puts "threshold_share: #{shares.length} vectors (#{$share_accept} valid accepted, #{$share_reject} invalid rejected)"
puts "  v2.1 bare-agent-share rejected: #{$bare_rejected}; cross-signer-set replay rejected: #{$wrong_set_rejected}"
if arts.is_a?(Array)
  puts "pq_artifact: #{$art_ran} ran, #{$art_skipped} skipped of #{arts.length} total"
  art_skipped_suites.sort.each { |k, n| puts "    skipped #{k}: #{n}" } unless art_skipped_suites.empty?
end
puts "assertions: #{$count}, failures: #{$fails}"
exit($fails.zero? ? 0 : 1)
