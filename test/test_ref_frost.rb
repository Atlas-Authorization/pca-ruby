# frozen_string_literal: true

# Replays the TS-reference oracle of FROST(Ed25519, SHA-512) threshold signing (test-data/ref-core-frost-java.json.gz, includes the
# RFC 9591 Ed25519 test vectors). Needs libsodium through ffi.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/frost'
require 'minitest/autorun'

class TestRefFrost < Minitest::Test
  i_suck_and_my_tests_are_order_dependent! # the one-shot nonce registry is shared across fns, as in the reference
  F = AtlasPca::Frost
  MAIN = Ref.load('core-frost-java')
  GEN = Ref.load_gen('core-frost-java')
  CASES = Ref.merge_cases(MAIN, GEN)

  # binary Strings become {"$bytes"} so the comparison cannot confuse bytes with text
  def self.wire(v)
    case v
    when Hash then v.to_h { |k, x| [k, wire(x)] }
    when Array then v.map { |x| wire(x) }
    when String then v.encoding == Encoding::BINARY ? { '$bytes' => Ref.b64e(v) } : v
    else v
    end
  end

  def self.keygen(o) = F.trusted_dealer_keygen(o['t'], o['n'], o['secret'], o['coefficients'], o['identifiers'])
  def self.commit(i, share, hr, br) = F.commit({ 'identifier' => i, 'share' => share }, hr, br)

  def self.sign(i, share, gpk, nonces, msg, comms, opts = nil)
    o = opts || {}
    F.sign(i, share, gpk, nonces, msg, comms, o['threshold'], o['verificationShare'], o['verificationShares'])
  end

  def self.flow(o)
    kg = keygen(o)
    by = kg['participantShares'].to_h { |s| [s['identifier'], s] }
    commits = o['signers'].zip(o['randomness']).map { |i, r| commit(i, by[i]['share'], r['hr'], r['br']) }
    comms = commits.map { |c| c['commitment'] }
    vss = o['signers'].map { |i| { 'identifier' => i, 'publicKey' => by[i]['publicKey'] } }
    shares = o['signers'].zip(commits).map do |i, c|
      sign(i, by[i]['share'], kg['groupPublicKey'], { 'hiding' => c['hidingNonce'], 'binding' => c['bindingNonce'] }, o['message'], comms,
           { 'threshold' => o['threshold'], 'verificationShare' => by[i]['publicKey'], 'verificationShares' => vss })
    end
    agg = F.aggregate(o['message'], comms, shares, kg['groupPublicKey'], vss, o['threshold'])
    kg.merge('commitments' => comms, 'sigShares' => shares, 'aggregate' => agg)
  end

  MAP = {
    'scalar' => ->(b) { F.reduce_bytes(b) },
    'isCanonicalScalar' => ->(b) { F.canonical_scalar?(b) },
    'hash' => ->(which, msg) { F.public_send({ 'H1' => :h1, 'H2' => :h2, 'H3' => :h3, 'H4' => :h4, 'H5' => :h5 }.fetch(which), msg) },
    'decodeSafePoint' => ->(b) { F.decode_safe_point(b) },
    'keygen' => ->(o) { keygen(o) },
    'verifyingShare' => ->(s) { F.verifying_share(s) },
    'commit' => ->(i, share, hr, br) { commit(i, share, hr, br) },
    'flow' => ->(o) { flow(o) },
    'sign' => ->(*a) { sign(*a) },
    'aggregate' => ->(msg, comms, shares, gpk, opts) { F.aggregate(msg, comms, shares, gpk, opts['verificationShares'], opts['threshold']) },
    'verifySigShare' => lambda { |o|
      g = o.is_a?(Hash) ? ->(k) { o[k] } : ->(_k) {}
      F.verify_sig_share(g.call('identifier'), g.call('publicKey'), g.call('commitment'), g.call('sigShare'), g.call('signingCommitments'),
                         g.call('groupPublicKey'), g.call('message'))
    },
    'cosign' => lambda { |gpk, quorum, msg, opts = nil|
      sig = F.cosign(gpk, quorum, msg, (opts || {})['threshold'])
      AtlasPca::Ed25519Strict.verify(gpk, msg, sig)
    }
  }.freeze

  def test_corpus_is_covered
    Ref.check_covered(self, CASES, GEN, MAP.keys)
  end

  def test_secret_corpus_present
    Ref.need_gen(self, 'core-frost-java') if GEN.nil?
  end

  MAP.keys.sort.each do |fn|
    define_method("test_#{fn}_matches_the_reference") do
      skip 'ref-core-frost-java-gen.json.gz absent' if CASES[fn].nil? && GEN.nil?
      cases = CASES[fn]
      cases.each { |c| c['args'] = [c['args']] if c['args'].is_a?(Hash) } # flow records its argument object bare
      call = MAP[fn]
      Ref.run(self, cases, ->(*a) { self.class.wire(call.call(*a)) })
    end
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 170, MAIN.values.sum(&:length), 'core-frost-java'
  end

end
