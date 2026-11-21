# frozen_string_literal: true

# The libpcazk binding (AtlasPca::ZkNative) over the proof-verification cases of the shared zk oracle (test-data/ref-zk.json.gz,
# fn verifyPolicyVmProof, both curves): the library decides the pairing question, so every case the reference accepts must verify,
# and every case it refuses for the proof, the key or the signals must be refused, in both modes. Cases the reference decides
# before the pairing (context pins, circuit and system tags, envelope members) are not the library's and are left out. In strict
# mode the library also refuses the keys snarkjs tolerates (the quirk cases). Without libpcazk the tests skip; they fail when
# ATLAS_PCA_LIBPCAZK_REQUIRED is 1.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/zk_native'
require 'minitest/autorun'

class TestZkNative < Minitest::Test
  Z = AtlasPca::ZkNative
  CASES = Ref.load('zk').fetch('verifyPolicyVmProof')
  # decided by the envelope gate, not the library (it ignores the proof's protocol and curve members, as snarkjs does)
  GATE_ONLY = %w[protocol- proof-curve-wrong expect-now-wrong expect-thunk-throws expectRiskHash circuit- system- extra-key proof-extra-key].freeze
  CURVE = { 'bn' => 'bn254', 'bls' => 'bls12-381' }.freeze

  def need_lib
    return if Z.available?

    flunk 'libpcazk is required here (ATLAS_PCA_LIBPCAZK_REQUIRED) and could not be loaded' if ENV['ATLAS_PCA_LIBPCAZK_REQUIRED'] == '1'
    skip 'libpcazk not available (set ATLAS_PCA_LIBPCAZK)'
  end

  def of(prefix) = CASES.select { |c| c['name'].start_with?("verifyPolicyVmProof/#{prefix}/") }
  def default_key(prefix) = CASES.find { |c| c['name'] == "verifyPolicyVmProof/#{prefix}/valid" }['args'][1]['verificationKey']

  # the three documents of a case as JSON text, nil when one cannot be written as JSON (a string that is not Unicode text)
  def documents(c, prefix)
    env = c['args'][0]
    return nil unless env.is_a?(Hash)

    key = c['args'][1].is_a?(Hash) ? c['args'][1]['verificationKey'] : nil
    [key.nil? ? default_key(prefix) : key, env['proof'], env['publicSignals']].map { |d| JSON.generate(d) }
  rescue JSON::GeneratorError
    nil
  end

  def test_version
    need_lib
    assert_match(/\A\S+/, Z.version)
  end

  CURVE.each do |prefix, curve|
    define_method("test_replay_#{prefix}_verify_cases") do
      need_lib
      checked = 0
      of(prefix).each do |c|
        stem = c['name'].split('/', 3)[2]
        docs = documents(c, prefix)
        if docs.nil?
          refute_equal true, c['out'], "#{c['name']}: a case that is not JSON cannot be accepted"
          next
        end
        compat = Z.verify(curve, *docs)
        strict = Z.verify(curve, *docs, strict: true)
        if c['out'] == true
          assert_equal({ 'valid' => true, 'reason' => 'ok' }, compat, c['name'])
          assert_equal !stem.start_with?('quirk'), strict['valid'], "#{c['name']}: strict mode verdict"
        elsif GATE_ONLY.none? { |g| stem.start_with?(g) }
          assert_equal [false, false], [compat['valid'], strict['valid']], "#{c['name']}: must be refused in both modes"
          assert_includes Z::REASONS[1..], compat['reason'], c['name']
        else
          next
        end
        checked += 1
      end
      assert_operator checked, :>, 50, "only #{checked} cases replayed"
    end
  end

  def test_both_curves_together_cover_the_corpus
    assert_operator of('bn').length + of('bls').length, :>, 120
  end

  def test_a_key_of_the_other_curve_is_refused
    need_lib
    c = CASES.find { |x| x['name'] == 'verifyPolicyVmProof/bn/valid' }
    docs = documents(c, 'bn')
    assert_equal false, Z.verify('bls12-381', *docs)['valid']
    assert_equal true, Z.verify('bn254', *docs)['valid']
    assert_equal true, Z.verify('bn254', default_key('bn'), c['args'][0]['proof'], c['args'][0]['publicSignals'])['valid'] # documents as values
  end

  def test_usage_errors_raise_and_are_never_a_verdict
    assert_raises(ArgumentError) { Z.verify('bn128', {}, {}, []) }
    assert_raises(ArgumentError) { Z.prove('p256', '', '', {}) }
    need_lib
    assert_equal({ 'valid' => false, 'reason' => 'bad_json' }, Z.verify('bn254', '{', '{}', '[]'))
    assert_raises(ArgumentError) { Z.verify('bn254', { 'x' => Float::NAN }, {}, []) }
    assert_raises(ArgumentError) { Z.prove('bn254', 'wasm', 'zkey', {}, seed: 'short') }
    assert_raises(ArgumentError) { Z.prove('bn254', nil, 'zkey', {}) }
    e = assert_raises(Z::ProveError) { Z.prove('bn254', 'not wasm', 'not a zkey', { 'a' => '1' }, seed: "\0".b * 32) }
    assert_includes %w[prove witness zkey input internal], e.code
    refute_empty e.message
  end
end
