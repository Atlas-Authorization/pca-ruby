# frozen_string_literal: true

# Shared vectors for the forbid-wins certificate (packages/pca/conformance/forbid-certificate-vectors.json, `table`).
#   ruby -Ilib test/test_forbid_certificate.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestForbidCertificate < Minitest::Test
  CONF = File.expand_path('../conformance', __dir__)
  DOC = AtlasPca.parse_json(File.read(File.join(CONF, 'forbid-certificate-vectors.json'), encoding: 'UTF-8'), loose: true)

  def test_table
    assert_operator DOC['table'].length, :>=, 19
    DOC['table'].each do |e|
      got = AtlasPca.forbid_certificate_consistent?(e['certificate'], (e['options'] || {})['precedence'] || [])
      assert_equal e['expect']['consistent'], got, e['name']
    end
  end

  def test_garbage_is_not_consistent
    [nil, 5, [], {}, { 'v' => 1, 'kind' => 'forbid-wins', 'clauses' => 'x' },
     { 'v' => 1, 'kind' => 'forbid-wins', 'clauses' => [nil], 'winner' => {}, 'shadowed' => [] }].each do |bad|
      refute AtlasPca.forbid_certificate_consistent?(bad), bad.inspect
    end
  end
end
