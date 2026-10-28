# frozen_string_literal: true

# Decision obligations against the shared vectors (packages/pca/conformance/obligations-vectors.json). A missing file fails.
#   ruby -Ilib test/test_obligations.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestObligations < Minitest::Test
  FILE = File.expand_path('../conformance/obligations-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)

  def test_validate
    refute_empty DOC['validate']
    DOC['validate'].each { |c| assert_equal c['expect']['ok'], AtlasPca.obligations_error(c['input']).nil?, c['name'] }
  end

  def test_merge
    refute_empty DOC['merge']
    DOC['merge'].each do |c|
      got = AtlasPca.merge_obligations(*c['inputs'])
      assert_equal c['expect']['ok'], got['ok'], c['name']
      assert_equal c['expect']['obligations'], got['obligations'], c['name'] if c['expect']['ok']
    end
  end

  def test_gate
    refute_empty DOC['gate']
    DOC['gate'].each do |c|
      got = AtlasPca.pep_obligation_gate(c['decision'], c['answered'], c['obligations'], c['supported'])
      assert_equal c['expect'], got.reject { |k, _| k == 'reason' }, c['name']
    end
  end

  def test_outcome
    refute_empty DOC['outcome']
    DOC['outcome'].each { |c| assert_equal c['expect'], AtlasPca.obligation_outcome(c['obligations'], c['fulfilled'], c['now']), c['name'] }
  end
end
