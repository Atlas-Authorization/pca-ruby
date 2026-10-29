# frozen_string_literal: true

# Leases against the shared vectors (packages/pca/conformance/lease-vectors.json). A missing file fails.
#   ruby -Ilib test/test_lease.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestLease < Minitest::Test
  FILE = File.expand_path('../conformance/lease-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)

  def test_scenarios
    assert_operator DOC['scenarios'].length, :>=, 10
    DOC['scenarios'].each do |s|
      reg = AtlasPca::LeaseRegistry.new({ 'authorities' => [DOC['authority']] }.merge(s['policy'] || {}))
      s['steps'].each do |st|
        label = "#{s['name']}: #{st['op']}"
        case st['op']
        when 'accept'
          got = reg.accept(DOC['records'][st['record']], st['chain'] || [])
          e = st['expect']
          assert_equal e['ok'], got['ok'], label
          if e['ok']
            assert_equal e['replaced'], got['replaced'], label
            assert_equal e['seq'], got['seq'], label
          else
            assert_equal e['code'], got['code'], label
          end
        when 'revoke'
          got = reg.revoke(DOC['revocations'][st['revocation']])
          e = st['expect']
          assert_equal e['ok'], got['ok'], label
          e['ok'] ? assert_equal(e['revoked'], got['revoked'], label) : assert_equal(e['code'], got['code'], label)
        when 'check'
          assert_equal st['expect'], AtlasPca.check_lease(DOC['records'][st['record']], reg, st['now']), label
        else
          flunk "unknown op #{st['op']}"
        end
      end
    end
  end

  def test_path_under
    assert AtlasPca.path_under('db/prod/ro', 'db/prod')
    refute AtlasPca.path_under('db/production', 'db/prod')
  end

  def test_total_on_hostile_input
    reg = AtlasPca::LeaseRegistry.new({ 'authorities' => [] })
    [nil, 1, 'x', [], {}].each do |x|
      refute AtlasPca.verify_lease(x)
      refute AtlasPca.verify_lease_revocation(x)
      assert_equal 'bad_record', reg.accept(x)['code']
      assert_equal 'bad_input', AtlasPca.check_lease(x, reg, 1.5)['code']
    end
  end
end
