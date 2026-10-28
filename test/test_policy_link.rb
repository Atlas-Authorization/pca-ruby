# frozen_string_literal: true

# Shared vectors for linked policy templates (packages/pca/conformance/policy-link-vectors.json).
#   ruby -Ilib test/test_policy_link.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestPolicyLink < Minitest::Test
  CONF = File.expand_path('../conformance', __dir__)
  DOC = AtlasPca.parse_json(File.read(File.join(CONF, 'policy-link-vectors.json'), encoding: 'UTF-8'), loose: true)
  DEF = DOC['template']['def']

  def test_digest
    assert_equal DOC['template']['digest'], AtlasPca.template_digest(DEF)
  end

  def test_def_errors
    assert_operator DOC['def_errors'].length, :>=, 9
    DOC['def_errors'].each do |e|
      got = AtlasPca.template_def_error(e['def'])
      e['expect'].nil? ? assert_nil(got, e['name']) : assert_equal(e['expect'], got, e['name'])
    end
  end

  def test_instantiate
    assert_operator DOC['instantiate'].length, :>=, 14
    DOC['instantiate'].each do |e|
      assert_equal e['expect'], AtlasPca.instantiate_template(DEF, e['slots']), e['name']
    end
  end

  def test_verify
    DOC['verify'].each do |e|
      got = e['kind'] == 'template' ? AtlasPca.verify_template(e['signed'], e['trusted']) : AtlasPca.verify_tighten(e['signed'], e['trusted'])
      assert_equal e['expect'], got, e['name']
    end
  end

  def test_ref_errors
    DOC['ref_errors'].each do |e|
      got = AtlasPca.template_ref_error(e['ref'])
      e['expect'].nil? ? assert_nil(got, e['name']) : assert_equal(e['expect'], got, e['name'])
    end
  end

  def test_resolve
    DOC['resolve'].each { |e| assert_equal e['expect'], AtlasPca.resolve_link(e['ref'], e['registry']), e['name'] }
  end
end
