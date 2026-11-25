# frozen_string_literal: true

# BFV risk gate on Microsoft SEAL (ffi over libsealc): replay of the node-seal corpus plus a native round trip.
# Needs libsealc (ATLAS_PCA_LIBSEALC) and, for the replay, the corpus the reference generates (PCA_FHE_SEAL_CORPUS). Both absent skips the
# tests; with PCA_FHE_SEAL_REQUIRED=1 (the FHE workflow) absence fails instead.
require_relative '../lib/atlas_pca/fhe_seal'
require 'json'
require 'zlib'
require 'minitest/autorun'

class TestFheSeal < Minitest::Test
  F = AtlasPca::FheSeal
  REQUIRED = ENV['PCA_FHE_SEAL_REQUIRED'] == '1'

  def setup
    ok = F.available?
    flunk 'libsealc must load (ATLAS_PCA_LIBSEALC, ffi gem)' if REQUIRED && !ok
    skip 'libsealc not available' unless ok
  end

  def policy(kappa, budget)
    w = [0.25, 0.2, 0.2, 0.2, 0.1, 0.05]
    F::Policy.new(scale: 1000, dim: 6, weights_scaled: w.map { |v| (v * 1000).round }, kappa_weights_scaled: w.map { |v| (kappa * v * 1000).round },
                  budget_scaled: (budget * 1e6).round, kappa: kappa)
  end

  def test_replays_the_reference_ciphertexts_to_the_reference_results
    path = ENV['PCA_FHE_SEAL_CORPUS'].to_s
    if path.empty?
      flunk 'PCA_FHE_SEAL_CORPUS must point at the node-seal corpus' if REQUIRED
      skip 'no corpus'
    end
    corpus = JSON.parse(Zlib::GzipReader.open(path, &:read))
    assert_equal F::POLY_MODULUS_DEGREE, corpus['seal']['polyModulusDegree']
    assert_equal F::PLAIN_MODULUS, corpus['seal']['plainModulus']
    assert_operator corpus['cases'].length, :>=, 6
    corpus['cases'].each do |c|
      p = c['policy']
      pol = F::Policy.new(scale: p['scale'], dim: p['dim'], weights_scaled: p['weightsScaled'], kappa_weights_scaled: p['kappaWeightsScaled'],
                          budget_scaled: p['budgetScaled'], kappa: p['kappa'].to_f)
      gate = F.eval_risk_gate(corpus['publicKey'], corpus['galoisKeys'], c['encInputs'], pol)
      # deterministic evaluation: byte-equal once both are re-saved uncompressed
      assert_equal F.canonical_cipher(c['encRiskRaw']), F.canonical_cipher(gate.enc_risk_raw), c['name']
      assert_equal F.canonical_cipher(c['encSlack']), F.canonical_cipher(gate.enc_slack), c['name']
    end
  end

  def test_native_round_trip_matches_plaintext_arithmetic
    keys = F.keygen
    [[[100, 900, 100, 100, 100, 100], 1.0, 0.6], [[1000] * 6, 1.0, 0.5], [[0] * 6, 1.5, 0.25]].each do |x, kappa, budget|
      pol = policy(kappa, budget)
      gate = F.eval_risk_gate(keys.public_key, keys.galois_keys, F.encrypt_risk_inputs(keys.public_key, x), pol)
      v = F.decrypt_verdict(keys.secret_key, gate.enc_risk_raw, gate.enc_slack, pol)
      raw = pol.weights_scaled.zip(x).sum { |w, i| w * i }
      kr = pol.kappa_weights_scaled.zip(x).sum { |w, i| w * i }
      assert_equal F::Verdict.new(raw, pol.budget_scaled - kr, pol.budget_scaled - kr >= 0), v
    end
  end

  def test_all_zero_weights_evaluate_to_zero
    keys = F.keygen
    pol = F::Policy.new(scale: 1000, dim: 6, weights_scaled: [0] * 6, kappa_weights_scaled: [0] * 6, budget_scaled: 5000)
    gate = F.eval_risk_gate(keys.public_key, keys.galois_keys, F.encrypt_risk_inputs(keys.public_key, [5] * 6), pol)
    assert_equal F::Verdict.new(0, 5000, true), F.decrypt_verdict(keys.secret_key, gate.enc_risk_raw, gate.enc_slack, pol)
  end

  def test_create_fhe_context_builds_the_batching_context_and_disposes_it
    c = F.create_fhe_context
    assert_equal F::POLY_MODULUS_DEGREE, c.slot_count
    assert_nil c.dispose
    assert_nil c.dispose # releasing twice frees nothing again
  end

  def test_wrong_key_fails_closed
    a = F.keygen
    b = F.keygen
    pol = policy(1.0, 0.6)
    gate = F.eval_risk_gate(a.public_key, a.galois_keys, F.encrypt_risk_inputs(a.public_key, [1, 2, 3, 4, 5, 6]), pol)
    e = assert_raises(ArgumentError) { F.decrypt_verdict(b.secret_key, gate.enc_risk_raw, gate.enc_slack, pol) }
    assert_match(/noise budget/, e.message)
  end

  def test_malformed_blobs_and_policies_are_refused
    keys = F.keygen
    good = F.encrypt_risk_inputs(keys.public_key, [1, 2, 3, 4, 5, 6])
    [good[0...-8], good + 'AAAA', 'AAAA', 'A' * 64].each { |bad| assert_raises(ArgumentError) { F.assert_seal_blob(bad, 'x') } }
    z = [0] * 6
    [[1000, 5, z, z, 0], [1000, 6, z, z, F::SIGNED_BOUND], [0, 6, z, z, 0], [1000, 6, [0] * 5, z, 0], [1000, 6, z, z, 1.5]].each do |sc, dim, w, k, b|
      pol = F::Policy.new(scale: sc, dim: dim, weights_scaled: w, kappa_weights_scaled: k, budget_scaled: b)
      assert_raises(ArgumentError) { F.require_policy(pol) }
    end
  end
end
