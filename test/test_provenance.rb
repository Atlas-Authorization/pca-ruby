# frozen_string_literal: true

# Build provenance (track K9) against the shared vectors (packages/pca/conformance/provenance-vectors.json).
#   ruby -Ilib test/test_provenance.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestProvenance < Minitest::Test
  FILE = [File.expand_path('../conformance/provenance-vectors.json', __dir__),
          File.expand_path('../conformance/provenance-vectors.json', __dir__)].find { |p| File.exist?(p) }
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)['primitives']

  def unhex(h) = [h].pack('H*')

  def test_counts
    assert_equal [44, 45, 7], %w[merkle_inclusion gate model_path].map { |k| DOC[k].length }
  end

  def test_merkle_inclusion
    DOC['merkle_inclusion'].each do |e|
      i = e['input']
      ok = AtlasPca.verify_rfc9162_inclusion(AtlasPca.rfc9162_leaf_hash(unhex(i['leaf_hex'])), i['index'], i['size'],
                                             i['proof_hex'].map { |h| unhex(h) }, unhex(i['root_hex']))
      assert_equal e['expect'], { 'ok' => ok }, e['name']
    end
  end

  def test_gate
    DOC['gate'].each do |e|
      assert_equal e['expect'], AtlasPca.provenance_gate(e['input']).transform_keys(&:to_s), e['name']
    end
  end

  def test_model_path
    DOC['model_path'].each do |e|
      assert_equal e['expect'], { 'model' => AtlasPca.model_derived_path?(e['input']['path']) }, e['name']
    end
  end

  def test_caveat_defaults
    c = AtlasPca.provenance_caveat(issuer: 'ci', min_level: 3, source_repo: 'https://github.com/acme/tool')
    assert_equal({ 'type' => 'needs_discharge', 'id' => 'provenance', 'issuer' => 'ci', 'issuer_class' => 'artifact', 'bind' => 'action', 'ttl_ms' => 300_000,
                   'require' => [{ 'claim' => 'slsa_level', 'op' => 'gte', 'value' => 3 },
                                 { 'claim' => 'source_repo', 'op' => 'eq', 'value' => 'https://github.com/acme/tool' },
                                 { 'claim' => 'runtime_bound', 'op' => 'eq', 'value' => true }] }, c)
  end

  def test_total
    [nil, 1, 'x', [], { 'facts' => {}, 'policy' => {} }].each { |bad| refute AtlasPca.provenance_gate(bad)[:ok] }
    refute AtlasPca.verify_rfc9162_inclusion('', 2**60, 1, nil, '')
  end
end
