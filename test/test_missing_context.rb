# frozen_string_literal: true

# Typed missing context against the shared vectors (packages/pca/conformance/missing-context-vectors.json). A missing file fails.
#   ruby -Ilib test/test_missing_context.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestMissingContext < Minitest::Test
  FILE = File.expand_path('../conformance/missing-context-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)

  def test_decide
    assert_operator DOC['decide'].length, :>=, 26
    DOC['decide'].each do |v|
      assert_equal v['expect'], AtlasPca.decide_with_missing(v['where'], v['bound'], v['supplied'], v['suppliers']), v['name']
    end
  end

  def test_bind
    assert_operator DOC['bind'].length, :>=, 8
    DOC['bind'].each do |v|
      assert_equal v['expect'], AtlasPca.bind_context(v['bound'], v['supplied'], v['suppliers'] || {}), v['name']
    end
  end

  def test_total_on_hostile_input
    [nil, 1, 'x', [], {}].each do |x|
      r = AtlasPca.decide_with_missing(x, x, x, x)
      assert_equal 'deny', r['decision']
      AtlasPca.bind_context(x, x, {})
    end
  end
end
