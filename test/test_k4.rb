# frozen_string_literal: true

# K4 against the shared vectors (packages/pca/conformance/k4-vectors.json). A missing file fails.
#   ruby -Ilib test/test_k4.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestK4 < Minitest::Test
  FILE = File.expand_path('../conformance/k4-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)

  def same(want, got, msg)
    want.nil? ? assert_nil(got, msg) : assert_equal(want, got, msg)
  end

  def test_config
    assert_operator DOC['escalation']['config_cases'].length, :>=, 6
    DOC['escalation']['config_cases'].each { |c| same c['expect'], AtlasPca.pricing_config_error(c['config']), c['name'] }
  end

  def test_decisions
    assert_operator DOC['escalation']['decisions'].length, :>=, 14
    DOC['escalation']['decisions'].each do |c|
      assert_equal c['expect'], AtlasPca.decide_escalation(DOC['escalation']['config'], c['calibration'], c['risk']), c['risk'].to_s
    end
  end

  def test_calibration
    DOC['escalation']['calibration'].each do |c|
      assert_equal c['expect'], AtlasPca.update_calibration(c['config'], c['start'], c['answers'], c['risks']), c['name']
    end
  end

  def test_binding
    assert_operator DOC['network_binding']['cases'].length, :>=, 15
    DOC['network_binding']['cases'].each do |c|
      e = c['expect_in']
      same c['expect'], AtlasPca.verify_network_token_binding(c['binding'], e['grant'], e['holder'], e['issuer_nonce'], e['provider']), c['name']
    end
  end

  def test_erc7715
    assert_operator DOC['erc7715']['cases'].length, :>=, 24
    DOC['erc7715']['cases'].each do |c|
      ctx = c['opts']['contexts'] || {}
      same c['expect'], AtlasPca.verify_granted_permission(c['envelope'], c['sent'], c['got'], c['opts']['allowedManagers'], ->(k) { ctx[k] }), c['name']
    end
  end
end
