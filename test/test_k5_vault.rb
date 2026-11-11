# frozen_string_literal: true

# K5 tokenisation vault, aggregate reads and the integer-exact sampler against the shared vectors (a missing file fails).
#   ruby -Ilib test/test_k5_vault.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestK5Vault < Minitest::Test
  DIR = File.expand_path('../conformance', __dir__)
  VA = AtlasPca.parse_json(File.read(File.join(DIR, 'vault-aggregate-vectors.json'), encoding: 'UTF-8'), loose: true)

  def test_sampler_streams
    VA['sampler']['uniform'].each do |u|
      d = AtlasPca.seeded_draws(u['seed'])
      assert_equal u['draws'], u['bounds'].map { |n| d.uniform(n) }
    end
    VA['sampler']['laplace'].each do |l|
      d = AtlasPca.seeded_draws(l['seed'])
      assert_equal l['values'], Array.new(l['values'].length) { AtlasPca.discrete_laplace(d, l['s'], l['t']) }
    end
  end

  def test_uniform_bounds
    d = AtlasPca.seeded_draws('x')
    [0, -1, 2**47 + 1, 1.0, true, nil, '3'].each { |n| assert_raises(RangeError) { d.uniform(n) } }
  end

  def test_vault
    assert_operator VA['vault'].length, :>=, 10
    VA['vault'].each do |c|
      store = AtlasPca.memory_vault
      red = AtlasPca.redact_read_with_vault(c['redact'].merge('grant' => VA['grants']['vault'][c['redact_grant']]), store)
      token = c['token'] || red['view'][c['field']]
      got = AtlasPca.detokenize(c['detok'].merge('grant' => VA['grants']['vault'][c['detok_grant']], 'token' => token, 'store' => store))
      assert_equal c['expect'], got, "vault: #{c['name']}"
    end
  end

  def test_aggregate
    assert_operator VA['aggregate'].length, :>=, 5
    VA['aggregate'].each do |c|
      state = c['initial_state']
      c['steps'].each_with_index do |s, i|
        inp = { 'principal' => VA['keys']['principal'], 'now' => 1_800_000_000_000, 'verb' => 'orders.stats', 'resource' => 'orders/eu',
                'purpose' => 'analytics', 'fn' => 'sum', 'values' => [10, 20, 500, -900], 'salt' => 'a-per-read-secret-salt', 'noise' => 'seeded' }
        inp = inp.merge(s['input']).merge('grant' => VA['grants']['aggregate'][s['input']['grant']], 'state' => state)
        r = AtlasPca.aggregate_read(inp)
        assert_equal s['expect'], r, "aggregate: #{c['name']} step #{i}"
        state = r['state']
      end
    end
  end

  def test_secure_noise_differs
    g = VA['grants']['aggregate']['main']
    dp = VA['aggregate'].flat_map { |c| c['steps'] }.find { |s| s['expect']['charged_micro']&.positive? && s['input']['grant'] == 'main' }
    refute_nil dp
    base = { 'principal' => VA['keys']['principal'], 'now' => 1_800_000_000_000, 'verb' => 'orders.stats', 'resource' => 'orders/eu',
             'purpose' => 'analytics', 'fn' => 'sum', 'values' => [10, 20, 500, -900], 'salt' => 'a-per-read-secret-salt', 'noise' => 'secure',
             'grant' => g, 'state' => AtlasPca.empty_aggregate_state }.merge(dp['input'].reject { |k, _| k == 'grant' }).merge('noise' => 'secure')
    vals = Array.new(8) { AtlasPca.aggregate_read(base)['value'] }
    assert_operator vals.uniq.length, :>, 1
    assert(vals.all?(Integer))
  end

  def test_never_raises
    [nil, 1, {}, { 'state' => 1 }].each { |x| assert_equal 'deny', AtlasPca.aggregate_read(x)['decision'] }
    assert_equal 'deny', AtlasPca.detokenize(nil)['decision']
    assert_equal 'deny', AtlasPca.redact_read_with_vault(nil, AtlasPca.memory_vault)['decision']
  end
end
