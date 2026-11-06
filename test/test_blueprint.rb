# frozen_string_literal: true

# Agent blueprints against the shared vectors (packages/pca/conformance/blueprint-vectors.json).
#   ruby -Ilib test/test_blueprint.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestBlueprint < Minitest::Test
  FILE = File.expand_path('../conformance/blueprint-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)

  def test_records
    assert_equal [true] * 8 + [false], DOC['records'].map { |r| AtlasPca.verify_blueprint(r) }
  end

  def test_scenarios
    assert_operator DOC['scenarios'].length, :>=, 16
    DOC['scenarios'].each do |s|
      reg = AtlasPca::BlueprintRegistry.new([DOC['operator']])
      s['steps'].each do |st|
        got = if st['op'] == 'accept'
                reg.accept(DOC['records'][st['record']])
              else
                o = st['opts']
                AtlasPca.check_blueprints(st['chain'], reg, o['now'], o['mode'], o['minEpoch'])
              end
        assert_equal st['expect'], got, s['name']
      end
    end
  end
end
