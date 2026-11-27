# frozen_string_literal: true

# Policy classes against the shared vectors (packages/pca/conformance/policy-classes-vectors.json). A missing file fails.
#   ruby -Ilib test/test_policy_classes.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestPolicyClasses < Minitest::Test
  FILE = File.expand_path('../conformance/policy-classes-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)

  def test_validate
    assert_operator DOC['validate'].length, :>=, 10
    DOC['validate'].each { |v| assert_equal v['expect']['ok'], AtlasPca.class_verdicts_error(v['input']).nil?, v['name'] }
  end

  def test_decide
    assert_operator DOC['decide'].length, :>=, 8
    DOC['decide'].each { |v| assert_equal v['expect'], AtlasPca.decide_classes(v['input']), v['name'] }
  end

  def test_total_on_hostile_input
    [nil, 1, 'x', {}, [nil], [1], [{}]].each { |x| assert_equal 'deny', AtlasPca.decide_classes(x)['decision'] }
  end
end
