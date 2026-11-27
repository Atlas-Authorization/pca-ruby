# frozen_string_literal: true

# Agent blueprints against the shared vectors (packages/pca/conformance/blueprint-vectors.json).
#   ruby -Ilib test/test_blueprint.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestBlueprint < Minitest::Test
  FILE = File.expand_path('../conformance/blueprint-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)

  def test_records
    got = DOC['records'].map { |r| AtlasPca.verify_blueprint(r) }
    assert_operator got.length, :>=, 26
    assert_equal [true] * 8 + [false], got.first(9)
    # records 14..21 are the malformed runtime_pins rows: refused despite a valid signature
    assert_equal [false] * 8, got[14..21]
  end

  def test_scenarios
    assert_operator DOC['scenarios'].length, :>=, 16
    DOC['scenarios'].each do |s|
      reg = AtlasPca::BlueprintRegistry.new([DOC['operator']], AtlasPca::MemoryBlueprintKv.new)
      s['steps'].each do |st|
        got = if st['op'] == 'accept'
                reg.accept(DOC['records'][st['record']])
              else
                o = st['opts']
                # opts.admitted: 'all' | 'none' | [instance keys] is the admitted(holder, blueprint) hook (absent: no hook)
                adm = o['admitted']
                hook = case adm
                       when 'all' then ->(_holder, _bp) { true }
                       when 'none' then ->(_holder, _bp) { false }
                       when Array then ->(holder, _bp) { adm.include?(holder) }
                       end
                AtlasPca.check_blueprints(st['chain'], reg, o['now'], o['mode'], o['minEpoch'], admitted: hook)
              end
        assert_equal st['expect'], got, s['name']
      end
    end
  end
end
