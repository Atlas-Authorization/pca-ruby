# frozen_string_literal: true

# Replays the TS-reference oracle of the Wesolowski VDF and PCA timelock (test-data/ref-vdf.json.gz). Big integers cross the corpus
# as decimal strings; JSON numbers stand for JS numbers (Float) where the reference tells them from bigints.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/vdf'
require 'minitest/autorun'

class TestRefVdf < Minitest::Test
  V = AtlasPca::Vdf
  CASES = Ref.load('vdf')

  def self.b(s)
    raise TypeError, 'bigint arg' unless s.is_a?(String)

    Integer(s, 10)
  end

  def self.pf(p) = { 'y' => p['y'].to_s, 'pi' => p['pi'].to_s }

  def self.verdict(sym) = ->(x, y, pi, t, n) { V.send(sym, b(x), b(y), b(pi), t, b(n)) }

  def self.proof_in(p)
    return p unless p.is_a?(Hash)

    f = ->(v) { v.is_a?(String) ? Integer(v, 10) : (v.is_a?(Integer) ? v.to_f : v) }
    %w[y pi].each_with_object(p.dup) { |k, h| h[k] = f.call(p[k]) if p.key?(k) }
  end

  def self.opts(o) = [o['steps'], b(o['N']), o['beacon'], o['allowInsecureDevModulus']]

  MAP = {
    'isProbablePrime' => ->(a) { V.probable_prime?(b(a)) },
    'isMillerRabinProbablePrime' => ->(a) { V.miller_rabin_probable_prime?(b(a)) },
    'isStrongLucasProbablePrime' => ->(a) { V.strong_lucas_probable_prime?(b(a)) },
    'modpow' => ->(a, e, m) { V.modpow(b(a), b(e), b(m)).to_s },
    'gcd' => ->(a, c) { V.gcd(b(a), b(c)).to_s },
    'canonicalVdfOutput' => ->(a, n) { V.canonical_vdf_output(b(a), b(n)).to_s },
    'bigIntToBytes' => ->(a) { { '$bytes' => Ref.b64e(V.big_int_to_bytes(b(a))) } },
    'bytesRoundTrip' => ->(s) { { '$bytes' => Ref.b64e(V.big_int_to_bytes(V.bytes_to_big_int(Ref.b64d(s)))) } },
    'hashToPrime' => ->(a, c, t, n, bits = V::CHALLENGE_PRIME_BITS) { V.hash_to_prime(b(a), b(c), t, b(n), bits).to_s },
    'sequentialSquare' => ->(a, t, n) { V.sequential_square(b(a), t, b(n)).to_s },
    'vdfEval' => ->(x, t, n) { pf(V.vdf_eval(b(x), t, b(n))) },
    'vdfEvalCanonical' => ->(x, t, n) { pf(V.vdf_eval_canonical(b(x), t, b(n))) },
    'vdfVerifyDetailed' => verdict(:vdf_verify_detailed),
    'vdfVerifyCanonicalDetailed' => verdict(:vdf_verify_canonical_detailed),
    'checkProductionModulus' => ->(a) { V.check_production_modulus(b(a)) },
    'deriveTimelockInput' => ->(act, n, bc) { V.derive_timelock_input(act, b(n), bc).to_s },
    'requireTimelock' => lambda { |act, o|
      q = V.require_timelock(act, *opts(o))
      { 'kind' => q['kind'], 'x' => q['x'].to_s, 'steps' => q['steps'], 'N' => q['N'].to_s, 'actionDigest' => q['actionDigest'] }
    },
    'proveTimelockElapsed' => lambda { |act, steps, n, o|
      p = V.prove_timelock_elapsed(act, steps, b(n), o['beacon'], o['allowInsecureDevModulus'])
      { 'kind' => p['kind'], 'y' => p['y'].to_s, 'pi' => p['pi'].to_s, 'steps' => p['steps'] }
    },
    'verifyTimelock' => ->(act, p, o) { V.verify_timelock(act, proof_in(p), *opts(o)) }
  }.freeze

  def test_corpus_is_covered
    assert_equal MAP.keys.sort, CASES.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}_matches_the_reference") { Ref.run(self, CASES[fn], MAP[fn]) }
  end

  def test_dev_modulus_is_refused_by_the_production_screen
    refute V.check_production_modulus(V.insecure_dev_setup(64)['N'])['ok']
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 6673, CASES.values.sum(&:length), 'vdf'
  end

end
