# frozen_string_literal: true

# Runtime-class claims against the shared vectors (packages/pca/conformance/runtime-claim-vectors.json).
#   ruby -Ilib test/test_runtime_claim.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestRuntimeClaim < Minitest::Test
  FILE = File.expand_path('../conformance/runtime-claim-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)
  T = DOC['trust']

  def run_case(claim, now, pinned: T['pinnedAttestors'], evidence: T['verifiedEvidenceDigests'])
    AtlasPca.verified_runtime_class(claim, pinned, T['passportDigest'], evidence, now)
  end

  def test_cases
    assert_operator DOC['cases'].length, :>=, 8
    DOC['cases'].each { |c| assert_equal c['expect'], run_case(c['claim'], c['now']), c['name'] }
  end

  def test_unpinned_or_unverified_evidence_is_none
    c = DOC['cases'][0]
    assert_equal 'wasi_no_ambient', run_case(c['claim'], c['now'])
    assert_equal 'none', run_case(c['claim'], c['now'], pinned: [])
    assert_equal 'none', run_case(c['claim'], c['now'], evidence: [])
    assert_equal 'none', run_case(nil, 0)
  end
end
