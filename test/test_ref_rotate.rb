# frozen_string_literal: true

# Replays the TS-reference oracle of key rotation (test-data/ref-rotate.json.gz): agent and principal key rotation, compromised
# subtree re-issue, the per-capability compromised-key flow and the all-or-nothing applyRotation over a scripted sink.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefRotate < Minitest::Test
  T = AtlasPca::Rotate
  BY_FN = Ref.load('rotate')
  CLOCK = Ref.clock_ms('rotate')

  def self.key(seed) = seed.nil? ? nil : AtlasPca::KeyPair.from_seed_b64u(seed)

  # absent -> the clock; present but not a number -> NaN, which the reference refuses
  def self.now_of(o)
    return nil unless o.key?('now')

    AtlasPca::Js.num?(o['now']) ? o['now'] : Float::NAN
  end

  # a revokedAt within two minutes of the wall clock or of the corpus generator's frozen clock is printed "<now>" (the reference does the same)
  def self.norm(v)
    case v
    when Array then v.map { |x| norm(x) }
    when Hash
      v.to_h do |k, x|
        now = k == 'revokedAt' && AtlasPca::Js.num?(x) && ((x.to_f - (Time.now.to_f * 1000)).abs < 120_000 || (x.to_f - CLOCK).abs < 120_000)
        [k, now ? '<now>' : norm(x)]
      end
    else v
    end
  end

  def self.reissue(fn) = ->(chain, holder, op) { norm(fn.call(chain, holder, key(op['newSeed']), key(op['ancestorSeed']), op['reason'], now_of(op))) }

  APPLY = lambda do |spec|
    reg = AtlasPca::Revoke::RevocationRegistry.new
    (spec['pre'] || []).each { |i| reg.revoke({ 'kind' => 'cap', 'value' => i, 'reason' => 'pre', 'revokedAt' => CLOCK }) }
    calls = [0]
    sink = Object.new
    sink.define_singleton_method(:revoke) do |inp|
      calls[0] += 1
      raise 'sink down' if spec['failAt'] == calls[0]

      reg.revoke(inp)
    end
    sink.define_singleton_method(:unrevoke) do |k|
      raise 'unrevoke down' if spec['failUnrevoke']

      reg.unrevoke(k)
    end
    sink.define_singleton_method(:lookup) { |k, v| reg.lookup(k, v) }
    result = begin
      T.apply_rotation(sink, spec['records'], spec['reissued'])
    rescue StandardError # only the refusal is compared
      { '$err' => true }
    end
    { 'result' => result, 'list' => norm(reg.list) }
  end

  MAP = {
    'rotateAgentKey' => ->(chain, op) { norm(T.rotate_agent_key(chain, key(op['oldSeed']), key(op['newSeed']), op['reason'], now_of(op))) },
    'rotatePrincipalKey' => lambda do |o|
      hs = o['holderSeeds']
      norm(T.rotate_principal_key(key(o['oldSeed']), key(o['newSeed']), o['chain'], o['oldRoot'], hs&.map { |s| key(s) }, o['reason'], now_of(o)))
    end,
    'revokeAndReissueSubtree' => reissue(T.method(:revoke_and_reissue_subtree)),
    'compromisedKeyFlow' => reissue(T.method(:compromised_key_flow)),
    'applyRotationScenario' => APPLY
  }.freeze

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1239, BY_FN.values.sum(&:length), 'rotate'
  end

end
