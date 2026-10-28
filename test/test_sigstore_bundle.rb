# frozen_string_literal: true

# Offline Sigstore bundle verification (track K9) against the shared vectors
# (packages/pca/conformance/sigstore-vectors.json): `ok` and the refusal `code` must match the reference; on ok the whole `core` must match.
#   ruby -Ilib test/test_sigstore_bundle.rb
require_relative '../lib/atlas_pca/sigstore_bundle'
require 'minitest/autorun'

class TestSigstoreBundle < Minitest::Test
  FILE = [File.expand_path('../conformance/sigstore-vectors.json', __dir__),
          File.expand_path('../conformance/sigstore-vectors.json', __dir__)].find { |p| File.exist?(p) }
  DOC = JSON.parse(File.read(FILE, encoding: 'UTF-8'))
  ROOTS = DOC['roots'].transform_values { |v| AtlasPca.parse_trusted_root(v) }

  def case_named(n) = DOC['cases'].find { |c| c['name'] == n }

  def test_cases
    assert_operator DOC['cases'].length, :>=, 30
    DOC['cases'].each do |c|
      r = AtlasPca.verify_sigstore_bundle_core(c['bundle'], ROOTS[c['roots']])
      assert_equal c['expect']['ok'], r[:ok], "#{c['name']}: #{r[:detail]}"
      assert_equal c['expect']['code'], r[:code], "#{c['name']}: #{r[:detail]}" unless r[:ok]
      assert_equal c['expect']['core'], r[:core], c['name'] if r[:ok]
    end
  end

  def test_slsa_facts
    c = case_named('npm/sigstore-5.0.0')
    r = AtlasPca.verify_sigstore_bundle(c['bundle'], ROOTS[c['roots']])
    assert r[:ok], r.inspect
    f = r[:facts]
    core = c['expect']['core']
    assert_equal [1, core['identity'], core['signed_time'], core['rekor_log_index'], core['subjects']],
                 [f['v'], f['identity'], f['integrated_time'], f['rekor_log_index'], f['subjects']]
    assert f['builder_id'].is_a?(String) && f['build_type'].is_a?(String)
  end

  def test_hostile_input_never_raises
    root = ROOTS['public-good-844a1c6d']
    [nil, 1, 'x', [], {}, { 'verificationMaterial' => {} },
     { 'mediaType' => 'application/vnd.dev.sigstore.bundle.v0.3+json', 'verificationMaterial' => [] }].each do |bad|
      refute AtlasPca.verify_sigstore_bundle_core(bad, root)[:ok]
    end
    ok = case_named('npm/sigstore-5.0.0')['bundle']
    vm = ok['verificationMaterial']
    [[%w[verificationMaterial certificate rawBytes], vm['certificate']['rawBytes'][0, 40]],
     [['verificationMaterial', 'tlogEntries', 0, 'canonicalizedBody'], vm['tlogEntries'][0]['canonicalizedBody'][0..-9]],
     [['verificationMaterial', 'tlogEntries', 0, 'logIndex'], 7],
     [['verificationMaterial', 'tlogEntries', 0, 'inclusionProof', 'hashes'], [nil]],
     [%w[dsseEnvelope payload], 'e30='],
     [%w[dsseEnvelope signatures], [{ 'sig' => nil }]]].each do |path, value|
      b = Marshal.load(Marshal.dump(ok))
      path[0..-2].reduce(b) { |o, k| o[k] }[path[-1]] = value
      r = AtlasPca.verify_sigstore_bundle(b, root)
      refute r[:ok], path.inspect
      assert r[:code], path.inspect
    end
  end

  def test_bad_root
    assert_raises(ArgumentError) { AtlasPca.parse_trusted_root({ 'mediaType' => 'x' }) }
  end
end
