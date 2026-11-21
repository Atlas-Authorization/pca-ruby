# frozen_string_literal: true

# The official fixtures of draft-irtf-cfrg-bbs-signatures (ciphersuite BLS12-381-SHA-256; byte-identical across draft revisions -06
# through -12), vendored in test-data with provenance, plus the RFC 9380 expand_message_xmd vector. Needs a built libblst.
require 'json'
require 'minitest/autorun'
require_relative '../lib/atlas_pca/bbs'

class TestBbsKat < Minitest::Test
  B = AtlasPca::Bbs
  SUITE = File.expand_path('../test-data/draft-irtf-cfrg-bbs-signatures/bls12-381-sha-256', __dir__)

  def load(rel) = JSON.parse(File.read(File.join(SUITE, rel)))
  def h(s) = [s].pack('H*')
  def hx(b) = b.unpack1('H*')
  def hs(list) = list.map { |s| h(s) }
  def sc(n) = format('%064x', n)

  def test_expand_message_xmd_rfc9380
    out = AtlasPca::Bls12.expand_message_xmd(''.b, 'QUUX-V01-CS02-with-expander-SHA256-128', 0x20)
    assert_equal '68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235', hx(out)
  end

  def test_key_gen_and_sk_to_pk
    k = load('keypair.json')
    sk = B.key_gen(h(k['keyMaterial']), h(k['keyInfo']))
    assert_equal k['keyPair']['secretKey'], hx(B.sk_to_bytes(sk))
    assert_equal k['keyPair']['publicKey'], hx(B.sk_to_pk(sk))
  end

  def test_hash_to_scalar
    f = load('h2s.json')
    assert_equal f['scalar'], sc(B.hash_to_scalar(h(f['message']), h(f['dst'])))
  end

  def test_map_message_to_scalar
    load('MapMessageToScalarAsHash.json')['cases'].each do |c|
      assert_equal c['scalar'], sc(B.map_message_to_scalar_as_hash(h(c['message'])))
    end
  end

  def test_create_generators
    f = load('generators.json')
    gens = B.create_generators(f['MsgGenerators'].length + 1)
    assert_equal f['Q1'], hx(gens[0])
    f['MsgGenerators'].each_with_index { |g, i| assert_equal g, hx(gens[i + 1]) }
  end

  def test_sign_and_verify
    (1..10).each do |i|
      f = load(format('signature/signature%03d.json', i))
      msgs = hs(f['messages'])
      pk = h(f['signerKeyPair']['publicKey'])
      r = B.verify_detailed(pk, h(f['signature']), h(f['header']), msgs)
      if f['result']['valid']
        assert r.ok, f['caseName']
        assert_equal f['signature'], hx(B.sign(f['signerKeyPair']['secretKey'].to_i(16), pk, h(f['header']), msgs)), f['caseName']
      else
        refute r.ok, f['caseName']
        assert_equal B::PAIRING_MISMATCH, r.reason, f['caseName']
      end
    end
  end

  def test_proof_gen_and_verify
    (1..15).each do |i|
      f = load(format('proof/proof%03d.json', i))
      name = f['caseName']
      msgs = hs(f['messages'])
      idx = f['disclosedIndexes']
      disclosed = idx.map { |k| k >= 0 && k < msgs.length ? msgs[k] : ''.b }
      pk = h(f['signerPublicKey'])
      r = B.proof_verify_detailed(pk, h(f['proof']), h(f['header']), h(f['presentationHeader']), disclosed, idx)
      if f['result']['valid']
        assert r.ok, name
        rs = f['trace']['random_scalars']
        scalars = %w[r1 r2 e_tilde r1_tilde r3_tilde].map { |k| rs[k].to_i(16) } + rs['m_tilde_scalars'].map { |x| x.to_i(16) }
        regen = B.proof_gen(pk, h(f['signature']), h(f['header']), h(f['presentationHeader']), msgs, idx, scalars)
        assert_equal f['proof'], hx(regen), name
      else
        refute r.ok, name
      end
    end
  end

  def test_randomized_proof_verifies_and_tampering_fails
    f = load('signature/signature004.json')
    msgs = hs(f['messages'])
    pk = h(f['signerKeyPair']['publicKey'])
    hdr = h(f['header'])
    ph = "\x01\x02\x03".b
    idx = [0, 2]
    sig = h(f['signature'])
    proof = B.proof_gen(pk, sig, hdr, ph, msgs, idx)
    dis = [msgs[0], msgs[2]]
    assert B.proof_verify(pk, proof, hdr, ph, dis, idx)
    refute B.proof_verify(pk, proof, hdr, "\x09".b, dis, idx)
    refute B.proof_verify(pk, proof, hdr, ph, [msgs[0], msgs[1]], idx)
    bad = proof.dup
    bad.setbyte(bad.bytesize - 1, bad.getbyte(bad.bytesize - 1) ^ 1)
    refute B.proof_verify(pk, bad, hdr, ph, dis, idx)
    refute_equal proof, B.proof_gen(pk, sig, hdr, ph, msgs, idx) # unlinkability: two proofs of one signature differ
  end
end
