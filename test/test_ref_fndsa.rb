# frozen_string_literal: true

# Differential replay of the FN-DSA registry, framing, hybrid composition and backend seam (AtlasPca::Fndsa) against the TypeScript reference
# (@atlasauth/pca-fndsa) corpus. The Falcon primitive is not covered (the reference ships none): every case runs through the deterministic
# hash-derived test backend or an explicit stub backend. Byte results are wrapped ({"$bytes"}) so a binary String is never read as text.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/fndsa'
require 'minitest/autorun'

class TestRefFndsa < Minitest::Test
  F = AtlasPca::Fndsa
  COUNT_AND_CASES = Ref.load('fndsa')
  CASES = COUNT_AND_CASES

  def teardown = F.reset_falcon_backend

  def bj(b) = { '$bytes' => Ref.b64e(b) }

  def install(kind)
    F.reset_falcon_backend
    mock = F.register_test_backend
    case kind
    when 'mock' then nil
    when 'none' then F.reset_falcon_backend
    when 'verify-only' then F.set_falcon_backend(F::FalconBackend.new(mock.verify))
    when 'short-sig' then F.set_falcon_backend(F::FalconBackend.new(mock.verify, ->(_sk, _m) { ("\x00" * 10).b }))
    when 'all-true' then F.set_falcon_backend(F::FalconBackend.new(->(*) { true }, mock.sign))
    when 'throws' then F.set_falcon_backend(F::FalconBackend.new(->(*) { raise 'backend exploded' }, mock.sign))
    else raise "unknown kind #{kind}"
    end
  end

  def with(kind)
    install(kind)
    yield
  ensure
    F.reset_falcon_backend
  end

  def suite_hash(a)
    s = F.resolve_fndsa_alg(a)
    return nil if s.nil?

    { 'alg' => s.alg, 'variant' => s.variant, 'hasEd25519' => s.has_ed25519, 'sigBytes' => s.sig_bytes, 'needsPqPk' => s.needs_pq_pk,
      'pqPkBytes' => s.pq_pk_bytes, 'needsPqSig' => s.needs_pq_sig, 'pqSigBytes' => s.pq_sig_bytes, 'fnSigBytes' => s.fn_sig_bytes }
  end

  def go(fn, call) = Ref.run(self, CASES[fn], call)

  def sign_in(inp) = with('mock') { F.sign_pca_with_fndsa(inp['alg'], inp['leaf'], inp['fnDsa'], inp['edSecret']) }

  def verify_in(kind)
    lambda { |inp|
      with(kind) { F.verify_pca_fndsa(inp['alg'], inp['leaf'], inp['holder'], inp['pq_pk'], inp['sig'], inp['pq_sig']) }
    }
  end

  def kat_verify(variant, pk, msg, sig, vectors)
    F.reset_falcon_backend
    F.register_test_backend(vectors)
    F.fndsa_verify(variant, pk, msg, sig)
  ensure
    F.reset_falcon_backend
  end

  def test_corpus_is_covered
    assert_equal 480, CASES.values.sum(&:length)
    assert_equal %w[fndsaLeafMessage fndsaSignKat fndsaSignWith fndsaVerifyKat fndsaVerifyWith hashKat isFnDsaVariant isKnownFnDsaAlg mockKeypair
                    resolveFnDsaAlg signPcaWithFndsa verifyPcaFndsa verifyPcaFndsaNone], CASES.keys.sort
  end

  def test_resolve = go('resolveFnDsaAlg', method(:suite_hash))
  def test_is_known = go('isKnownFnDsaAlg', ->(x) { F.known_fndsa_alg?(x) })
  def test_is_variant = go('isFnDsaVariant', ->(x) { F.fndsa_variant?(x) })
  def test_hash_kat = go('hashKat', ->(seed, n) { bj(F.hash_kat(seed, n)) })
  def test_mock_keypair = go('mockKeypair', ->(v, seed = 'default') { F.mock_keypair(v, seed).transform_values { |b| bj(b) } })
  def test_leaf_message = go('fndsaLeafMessage', ->(leaf, alg, pk) { bj(F.fndsa_leaf_message(leaf, alg, pk)) })
  def test_sign_with = go('fndsaSignWith', ->(k, v, sk, m) { with(k) { bj(F.fndsa_sign(v, sk, m)) } })
  def test_verify_with = go('fndsaVerifyWith', ->(k, v, pk, m, s) { with(k) { F.fndsa_verify(v, pk, m, s) } })
  def test_verify_kat = go('fndsaVerifyKat', method(:kat_verify))
  def test_sign_pca = go('signPcaWithFndsa', ->(inp) { sign_in(inp) })
  def test_verify_pca = go('verifyPcaFndsa', verify_in('mock'))
  def test_verify_pca_none = go('verifyPcaFndsaNone', verify_in('none'))

  def test_sign_kat_table_takes_precedence
    CASES['fndsaSignKat'].each do |c|
      variant = c['name'].split('/')[1]
      sign = lambda do |vectors|
        F.reset_falcon_backend
        F.register_test_backend(vectors)
        bj(F.fndsa_sign(variant, F.mock_keypair(variant, 'ref')['sk'], 'm'.b))
      ensure
        F.reset_falcon_backend
      end
      Ref.run(self, [c], sign)
    end
  end

  def test_no_backend_refuses
    F.reset_falcon_backend
    assert_raises(F::BackendMissing) { F.fndsa_verify('fn-dsa-512', ("\x00" * 897).b, 'm'.b, ("\x00" * 666).b) }
  end
end
