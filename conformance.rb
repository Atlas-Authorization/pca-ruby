#!/usr/bin/env ruby
# frozen_string_literal: true

# Plain conformance runner: ruby conformance.rb (exit 1 on any failure)
require_relative 'lib/atlas_pca'

DIR = File.expand_path('conformance', __dir__)
doc = AtlasPca.parse_json(File.read(File.join(DIR, 'vectors.json')))
$fails = 0
$count = 0

def check(cond, msg)
  $count += 1
  return if cond

  $fails += 1
  warn "FAIL: #{msg}"
end

vs = doc['vectors']
abort 'no vectors' if vs.nil? || vs.empty?
vs.each do |v|
  got = AtlasPca.verify_pcactn_core(v['pcactn'], v['grant'])
  exp = v['expect']
  check(got.allow == exp['allow'], "#{v['name']}: allow=#{got.allow} want #{exp['allow']} (#{got.reason})")
  exp['checks'].each do |k, w|
    check(got.checks[k] == w, "#{v['name']}: check #{k}=#{got.checks[k]} want #{w}")
  end
end

prim = doc['primitives']
prim['canonical'].each do |c|
  s = AtlasPca.canonicalize(c['value'])
  check(s == c['expect'], "canonical mismatch: #{s.inspect} vs #{c['expect'].inspect}")
  check(AtlasPca.hash_canonical(c['value']) == c['hash'], "hash mismatch for #{s}")
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

puts "#{vs.length} vectors, #{$count} assertions, #{$fails} failures"
exit($fails.zero? ? 0 : 1)
