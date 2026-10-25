#!/usr/bin/env ruby
# frozen_string_literal: true

# LESS suites through libatlas_less (AtlasPca::LessFfi). Plain runner, no test framework:
#   ruby -Ilib test/test_less.rb   (exit 1 on any failure)
# With the library (sdks/pca-less-c/build.sh, or ATLAS_PCA_LIBLESS): the known answers of
# packages/pca/conformance/less-vectors.json, incl. the seed-padding malleation every verifier must refuse. Without it: both
# suites are out of the manifest and refused with `unsupported_suite`.
require_relative '../lib/atlas_pca'
require 'json'

fails = 0
check = ->(ok, msg) { (fails += 1; warn "FAIL: #{msg}") unless ok }
avail = AtlasPca::LessFfi.available?
s = AtlasPca.supported_suites
check.call(s.include?('less-cat1') == avail && s.include?('hybrid-ed25519-less-cat1') == avail, "manifest #{s}")
if avail
  doc = JSON.parse(File.read(File.expand_path('../conformance/less-vectors.json', __dir__)))
  check.call(doc['vectors'].size >= 25, 'vector count')
  doc['vectors'].each do |v|
    key = doc['keys'][v['key']]
    art = { 'alg' => v['alg'], 'sig' => v['sig'], 'pq_pk' => v.fetch('pq_pk_override', key['pq_pk']) }
    art['pq_sig'] = v['pq_sig'] if v.key?('pq_sig')
    msg = AtlasPca.b64d(v['message'])
    wire_ok = AtlasPca.validate_signature_wire(art).nil?
    allow = wire_ok && AtlasPca.verify_leaf_suite(art, key['ed_pub'], msg)
    check.call(wire_ok == v['expect']['wire_ok'] && allow == v['expect']['allow'], "#{v['name']}: wire #{wire_ok} allow #{allow}")
  end
  puts "LESS: #{doc['vectors'].size} known answers checked"
else
  %w[less-cat1 hybrid-ed25519-less-cat1].each do |alg|
    why = AtlasPca.validate_signature_wire({ 'alg' => alg, 'sig' => 'AA' })
    check.call(why == "#{AtlasPca::UNSUPPORTED_SUITE}: #{alg}", "#{alg}: #{why}")
  end
  puts 'LESS: library absent, suites refused as unsupported'
end
exit(fails.zero? ? 0 : 1)
