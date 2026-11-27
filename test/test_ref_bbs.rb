# frozen_string_literal: true

# Replays the TS-reference oracle of BBS (BLS12-381-SHA-256) and the capability-credential layer (test-data/ref-bbs.json.gz). Needs
# a built libblst through ffi (PCA_BLST_LIB or on the loader path). The corpus carries no secret keys: {"$bbssk": n} stands for
# KeyGen(32 bytes of n, empty key info), derived here.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/bbs_credential'
require 'minitest/autorun'

class TestRefBbs < Minitest::Test
  B = AtlasPca::Bbs
  C = AtlasPca::BbsCredential

  def self.hex(n) = format('%064x', n)

  def self.unbbs(v)
    case v
    when Hash
      v.size == 1 && v.key?('$bbssk') ? hex(B.key_gen(([v['$bbssk']].pack('C') * 32).b)) : v.transform_values { |x| unbbs(x) }
    when Array then v.map { |x| unbbs(x) }
    else v
    end
  end

  CASES = Ref.load('bbs').transform_values { |cs| unbbs(cs) }

  def self.unhex(s) = s.to_i(16)
  def self.wire(b) = { '$bytes' => Ref.b64e(b) }
  def self.ints(list) = list.map(&:to_i)

  MAP = {
    'hashToScalar' => ->(m, dst) { hex(B.hash_to_scalar(m, dst)) },
    'mapMessageToScalarAsHash' => ->(m) { hex(B.map_message_to_scalar_as_hash(m)) },
    'createGenerators' => ->(n) { B.create_generators(n.to_i).map { |g| wire(g) } },
    'keyGen' => ->(km, ki) { hex(B.key_gen(km, ki)) },
    'skToPk' => ->(sk) { wire(B.sk_to_pk(unhex(sk))) },
    'sign' => ->(sk, pk, hd, ms) { wire(B.sign(unhex(sk), pk, hd, ms)) },
    'verifyDetailed' => ->(pk, sig, hd, ms) { B.verify_detailed(pk, sig, hd, ms).to_h },
    'proofGen' => ->(pk, sig, hd, ph, ms, idx, rs) { wire(B.proof_gen(pk, sig, hd, ph, ms, ints(idx), rs.map { |x| unhex(x) })) },
    'proofVerifyDetailed' => ->(pk, pr, hd, ph, ms, idx) { B.proof_verify_detailed(pk, pr, hd, ph, ms, ints(idx)).to_h },
    'capabilityAttributes' => ->(cap) { C.capability_attributes(cap) },
    'issueCapabilityCredential' => ->(cap, sk, pk, hd) { C.issue_capability_credential(cap, unhex(sk), pk, hd) },
    'verifyCredential' => ->(cred) { C.verify_credential(cred) },
    'verifyPresentation' => lambda { |pres, opts|
      C.verify_presentation(pres, pk: opts['pk'], disclosed: opts['disclosed'], presentation_header: opts['presentationHeader'])
    }
  }.freeze

  def test_corpus_is_covered
    assert_equal MAP.keys.sort, CASES.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}_matches_the_reference") { Ref.run(self, CASES[fn], MAP[fn]) }
  end

  # the randomized presenter: round trip, context binding, unknown attribute, unlinkability
  def test_present_round_trip
    sk = B.key_gen(("\0".b * 32))
    pk = B.sk_to_pk(sk)
    cap = { 'issuer' => 'i', 'holder' => 'h', 'caveats' => [{ 'type' => 'amount' }] }
    cred = C.issue_capability_credential(cap, sk, pk, nil)
    assert C.verify_credential(cred)
    pres = C.present_credential(cred, ['iss'], "\x01".b)
    assert C.verify_presentation(pres)
    assert C.verify_presentation(pres, pk: pk, presentation_header: "\x01".b)
    refute C.verify_presentation(pres, presentation_header: "\x02".b)
    assert_raises(ArgumentError) { C.present_credential(cred, ['nope'], nil) }
    refute_equal pres['proof'], C.present_credential(cred, ['iss'], "\x01".b)['proof']
  end
end
