# frozen_string_literal: true

# Replays the TS-reference oracle of the BLS12-381 aggregation layer (PoP ciphersuite, key registry, aggregated capability chain,
# witness cosignatures; test-data/ref-aggsig.json.gz). Needs a built libblst (supranational/blst, shared) through ffi. The corpus
# carries secret-key labels ({"$blssk": label}); the key is derived here as the generator does.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/aggsig'
require 'minitest/autorun'

class TestRefAggsig < Minitest::Test
  A = AtlasPca::Aggsig
  R = A::R

  # sk = (sha256(sha256("atlas-pca-conformance/" + label)) mod (r - 1)) + 1, 32 bytes big-endian
  def self.sk_member(label)
    seed = Digest::SHA256.digest("atlas-pca-conformance/#{label}")
    n = (Digest::SHA256.digest(seed).unpack1('H*').to_i(16) % (R - 1)) + 1
    Ref.b64e([format('%064x', n)].pack('H*'))
  end

  def self.unbls(v)
    case v
    when Hash
      v.size == 1 && v.key?('$blssk') ? { '$bytes' => sk_member(v['$blssk']) } : v.transform_values { |x| unbls(x) }
    when Array then v.map { |x| unbls(x) }
    else v
    end
  end

  CASES = Ref.load('aggsig').transform_values { |cs| unbls(cs) }

  def self.wire(v)
    case v
    when Hash then v.to_h { |k, x| [k, wire(x)] }
    when Array then v.map { |x| wire(x) }
    when String then v.encoding == Encoding::BINARY ? { '$bytes' => Ref.b64e(v) } : v
    else v
    end
  end

  # Register every {pk, pop} pair; nil when any fails (the reference result is then {"registerFailed": true}).
  def self.reg_all(keys)
    out = keys.map do |k|
      r = A.register_key(k['pk'], k['pop'])
      return nil unless r['ok']

      r['key']
    end
    out
  end

  def self.registry(keys)
    reg = A::KeyRegistry.new
    keys.each { |k| break unless reg.register(k['pk'], k['pop'])['ok'] } # the reference harness stops at the first failure
    reg
  end

  def self.with_keys(keys)
    ks = reg_all(keys)
    ks.nil? ? { 'registerFailed' => true } : yield(ks)
  end

  MAP = {
    'publicKeyOf' => ->(sk) { A.public_key_of(sk) },
    'sign' => ->(sk, m) { A.sign(sk, m) },
    'popProve' => ->(sk) { A.pop_prove(sk) },
    'verify' => ->(pk, m, s) { A.verify(pk, m, s) },
    'keyValidate' => ->(pk) { A.key_validate(pk) },
    'registerKey' => lambda { |pk, pop|
      r = A.register_key(pk, pop)
      r['ok'] ? { 'ok' => true } : { 'ok' => false, 'reason' => r['reason'] }
    },
    'aggregate' => ->(sigs) { A.aggregate(sigs) },
    'aggregateVerify' => ->(keys, msgs, agg) { with_keys(keys) { |ks| A.aggregate_verify(ks, msgs, agg) } },
    'fastAggregateVerify' => ->(keys, msg, agg) { with_keys(keys) { |ks| A.fast_aggregate_verify(ks, msg, agg) } },
    'mintBlsRoot' => ->(sk, pub, holder, cav) { A.mint_bls_root(sk, pub, holder, cav) },
    'chainDelegate' => ->(parent, to, cav, sk) { A.bls_delegate(parent, to, cav, sk) },
    'chainAttenuate' => ->(parent, cav, sk) { A.bls_attenuate(parent, cav, sk) },
    'capHash' => ->(c) { A.cap_hash(c) },
    'aggregateChainSignatures' => ->(chain) { A.aggregate_chain_signatures(chain) },
    'verifyAggregatedChain' => ->(chain, agg, keys, root) { A.verify_aggregated_chain(chain, agg, registry(keys), root) },
    'cosignTreeHead' => ->(sth, sk) { A.cosign_tree_head(sth, sk) },
    'verifyWitnessCosignature' => ->(sth, cosig) { A.verify_witness_cosignature(sth, cosig) },
    'aggregateWitnessCosignatures' => ->(cosigs) { A.aggregate_witness_cosignatures(cosigs) },
    'verifyAggregatedWitnessCosignatures' => ->(sth, keys, agg) { with_keys(keys) { |ks| A.verify_aggregated_witness_cosignatures(sth, ks, agg) } }
  }.freeze

  def test_corpus_is_covered
    assert_equal MAP.keys.sort, CASES.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}_matches_the_reference") { Ref.run(self, CASES[fn], ->(*a) { self.class.wire(MAP[fn].call(*a)) }) }
  end
end
