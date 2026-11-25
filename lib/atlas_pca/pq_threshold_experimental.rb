# frozen_string_literal: true

require 'securerandom'

module AtlasPca
  module PqThreshold
    # EXPERIMENTAL, NOT PRODUCTION. NO SECURITY PROOF. TIMING-UNSAFE. RESEARCH / INTEROP ONLY (the reference's `experimental` namespace).
    #
    # Raccoon / Ringtail-style LATTICE-THRESHOLD design plus a TOY additive secret-sharing sketch. It documents the trustless post-quantum
    # threshold future and gives a minimal interop toy; it is not a signature scheme. The sharing is n-of-n over Z_q (every share is required to
    # reconstruct), the arithmetic is variable-time bignum, and nothing here may sign. The shippable post-quantum threshold is the hybrid in
    # PqThreshold (a classical FROST threshold plus an ML-DSA co-signature quorum). Every function is gated behind an explicit opt-in and
    # refuses with the banner without it (fail closed).
    module Experimental
      BANNER = 'EXPERIMENTAL — NOT PRODUCTION. No security proof, timing-unsafe, for research/interop only. ' \
               'The shippable post-quantum threshold step-up is the HYBRID (classical FROST threshold + ML-DSA ' \
               'co-signature quorum) in @atlasauth/pca-pq-threshold; do NOT use this lattice-threshold prototype to sign.'
      EXPERIMENTAL_BANNER = BANNER

      # Toy lattice parameters (a tiny modulus for demonstration; q is the ML-DSA modulus only so the arithmetic looks familiar).
      TOY_DEFAULT_PARAMS = { 'q' => 8_380_417, 'dim' => 4 }.freeze

      # A documented spec of the research design: DATA describing the approach, it performs no cryptography.
      RACCOON_DESIGN = {
        'scheme' => 'Raccoon/Ringtail-style lattice threshold (RESEARCH)',
        'status' => 'research-prototype',
        'productionReady' => false,
        'banner' => BANNER,
        'assumption' => 'Module-LWE / Module-SIS (the same lattice assumptions as ML-DSA / FIPS-204), believed hard for quantum adversaries.',
        'construction' => [
          '1. Distributed key generation: the signing key (a short vector / small polynomial) is SECRET-SHARED across n parties — Raccoon uses additive masking; Ringtail layers a one-time additive mask over a replicated/Shamir-style sharing to reach genuine t-of-n.',
          '2. Each party holds a share s_i such that the shares combine (additively, mod q, per coefficient) to the signing key s.',
          '3. Signing is a masked, multi-round protocol: parties jointly sample commitment randomness, each adds Gaussian NOISE FLOODING to its partial response so the partials leak nothing about the individual shares, and the masked partials are summed.',
          '4. The combined response is accepted only if it passes the standard ML-DSA-style rejection-sampling bound; otherwise the round restarts. The output is a single signature verifiable under ONE ordinary ML-DSA-style public key.',
          '5. A quantum break of a CLASSICAL threshold does not help here — forging requires solving the underlying lattice problem.'
        ].map(&:freeze).freeze,
        'whyNoLibraryYet' => [
          'Distributed discrete Gaussian / noise-flooding sampling with the right parameters is subtle and unimplemented in any audited library.',
          'Parameter selection for the threshold setting is still moving; interop test vectors are not standardised.',
          'No constant-time, side-channel-hardened reference implementation has been published and audited.',
          'The abort/restart rejection-sampling rounds complicate liveness and make a robust networked coordinator non-trivial.'
        ].map(&:freeze).freeze,
        'shippableAlternative' =>
          'Use the HYBRID in @atlasauth/pca-pq-threshold: a classical FROST(Ed25519) t-of-n threshold AND a pqT-of-m ML-DSA-65 co-signature quorum over the same action. ' \
          'It is post-quantum-protected TODAY (a classical threshold break cannot forge the step-up without ALSO forging the ML-DSA quorum) using only audited, available primitives.',
        'parameterSets' => [
          { 'name' => 'Raccoon-128 (illustrative)', 'nistCategory' => 1, 'note' => 'Research parameters only; not implemented here.' }.freeze,
          { 'name' => 'Raccoon-192 (illustrative)', 'nistCategory' => 3, 'note' => 'Matches ML-DSA-65 category; not implemented here.' }.freeze
        ].freeze,
        'references' => [
          'Raccoon: a side-channel-resilient lattice signature (NIST additional-signatures submission).',
          'Ringtail: two-round threshold signatures from lattices.',
          'FIPS-204 (ML-DSA) — the single-party base scheme the threshold variants mirror.'
        ].map(&:freeze).freeze
      }.freeze

      module_function

      # The explicit, loud opt-in: {'iUnderstandThisIsNotProduction' => true} (anything else, including false or absent, refuses).
      def assert_opt_in(opt_in)
        ok = opt_in.is_a?(Hash) && (opt_in['iUnderstandThisIsNotProduction'] == true || opt_in[:iUnderstandThisIsNotProduction] == true)
        raise ArgumentError, "#{BANNER} Pass { iUnderstandThisIsNotProduction: true } to proceed." unless ok
      end

      # Additively secret-share a toy lattice key vector into `n` shares over Z_q, per coefficient: shares 1..n-1 are random, the last absorbs
      # the remainder so the shares sum to the key (mod q). n-of-n, NOT t-of-n and NOT a signature scheme. Returns [{'index' (1-based), 'coeffs'}].
      # `sampler` is ->(q) { coefficient } (default: the OS random source); any value it returns is reduced mod q.
      def additive_share_lattice_key(key, n, opt_in, params = TOY_DEFAULT_PARAMS, sampler = nil)
        assert_opt_in(opt_in)
        raise RangeError, 'additiveShareLatticeKey: n must be an integer in [1, 1024]' unless n.is_a?(Integer) && n >= 1 && n <= 1024
        raise RangeError, "additiveShareLatticeKey: key must have #{params['dim']} coefficients" unless key.is_a?(Array) && key.length == params['dim']

        q = params['q']
        sampler ||= ->(m) { SecureRandom.random_number(m) }
        shares = Array.new(n) { Array.new(params['dim'], 0) }
        params['dim'].times do |c|
          target = (key[c] || 0) % q
          running = 0
          (n - 1).times do |i|
            r = sampler.call(q) % q
            shares[i][c] = r
            running = (running + r) % q
          end
          shares[n - 1][c] = (target - running) % q
        end
        shares.each_with_index.map { |coeffs, i| { 'index' => i + 1, 'coeffs' => coeffs } }
      end

      # Reconstruct the toy lattice key by summing ALL shares' coefficient vectors mod q (n-of-n: every share must be present, no index twice).
      def reconstruct_lattice_key(shares, opt_in, params = TOY_DEFAULT_PARAMS)
        assert_opt_in(opt_in)
        raise RangeError, 'reconstructLatticeKey: need at least one share' if !shares.is_a?(Array) || shares.empty?
        raise RangeError, 'reconstructLatticeKey: duplicate share index' if shares.map { |s| s['index'] }.uniq.length != shares.length

        out = Array.new(params['dim'], 0)
        shares.each do |s|
          raise RangeError, 'reconstructLatticeKey: a share has the wrong dimension' unless s['coeffs'].is_a?(Array) && s['coeffs'].length == params['dim']

          params['dim'].times { |c| out[c] = (out[c] + s['coeffs'][c]) % params['q'] }
        end
        out
      end
    end
  end
end
