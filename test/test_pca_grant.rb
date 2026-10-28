# frozen_string_literal: true

# The `pca_grant` authorization-details type against the shared vectors (packages/pca/conformance/pca-grant-vectors.json).
#   ruby -Ilib test/test_pca_grant.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestPcaGrant < Minitest::Test
  FILE = File.expand_path('../conformance/pca-grant-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)

  def test_digests
    DOC['digest'].each { |v| assert_equal v['digest'], AtlasPca.pca_grant_chain_digest(v['ids']) }
  end

  def test_detail
    DOC['detail'].each do |v|
      code = AtlasPca.validate_pca_grant_detail(v['input'])
      assert_equal v['expect']['ok'], code.nil?, v['name']
      assert_equal v['expect']['code'], code, v['name'] unless code.nil?
    end
  end

  def test_array
    DOC['array'].each do |v|
      details, code = AtlasPca.parse_pca_grant_details(v['input'])
      assert_equal v['expect']['ok'], code.nil?, v['name']
      if code.nil?
        assert_equal v['expect']['count'], details.length, v['name']
      else
        assert_equal v['expect']['code'], code, v['name']
      end
    end
  end

  def test_presentation
    DOC['presentation'].each do |v|
      p = v['presented']
      idx, code = AtlasPca.check_pca_grant_presentation(v['details'], p['resource'], p['chain_ids'], p['proof_verified'])
      assert_equal v['expect']['allow'], code.nil?, v['name']
      if code.nil?
        assert_equal v['expect']['index'], idx, v['name']
      else
        assert_equal v['expect']['code'], code, v['name']
      end
    end
  end

  def test_a_truthy_non_true_is_not_a_proof
    v = DOC['presentation'][0]
    p = v['presented']
    assert_equal 'proof_required', AtlasPca.check_pca_grant_presentation(v['details'], p['resource'], p['chain_ids'], 'yes')[1]
  end
end
