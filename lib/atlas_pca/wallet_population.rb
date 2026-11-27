# frozen_string_literal: true

require 'securerandom'
require 'set'
require_relative 'wallet'
require_relative 'intent_learner'

# Opt-in, privacy-preserving population priors for the wallet (PCA Intent Layer v2, V16, T23): one vote per principal, cell and
# period; a central (epsilon, delta)-DP Gaussian release; local-DP randomized response; the mixture prior for the learner and the
# mass it admits beyond the base prior. Native port of the TypeScript reference (@atlasauth/pca-wallet, population). Votes,
# releases and priors are String-keyed Hashes with the reference's member names; the randomness source is an injected callable.
module AtlasPca
  module WalletPopulation
    W = Wallet
    O = IntentOmega
    POPULATION_VOTE_DOMAIN = 'atlas-pca/intent-population-cell/v1'
    BETA_MAX = 0.9

    module_function

    def js_round(x)
      f = x.floor
      x - f >= 0.5 ? f + 1 : f
    end

    def integer?(x) = W.number?(x) && (x.is_a?(Integer) || x.finite?) && x == x.floor

    # Math.max / Math.min: a NaN operand gives NaN.
    def js_max(a, b) = a.is_a?(Float) && a.nan? || b.is_a?(Float) && b.nan? ? Float::NAN : [a, b].max
    def js_min(a, b) = a.is_a?(Float) && a.nan? || b.is_a?(Float) && b.nan? ? Float::NAN : [a, b].min

    # The semantic key of a cell: its coordinates in schema terms, bound to the schema digest and the verb.
    def population_cell_key(schema_digest, vs, idx)
      AtlasPca.hash_canonical({ 'd' => POPULATION_VOTE_DOMAIN, 's' => schema_digest, 'v' => vs['verb'], 'c' => W.coords_of_cell(vs, idx) })
    end

    # Uniform (0, 1) from 53 random bits of the OS CSPRNG.
    def crypto_rand
      b = SecureRandom.random_bytes(8)
      hi = b.byteslice(0, 4).unpack1('N') >> 5
      lo = b.byteslice(4, 4).unpack1('N') >> 6
      ((hi * 67_108_864) + lo + 0.5) / 9_007_199_254_740_992
    end

    # A standard normal draw (Box-Muller) from a uniform source.
    def gaussian(rand)
      u = rand.call
      u = rand.call while u <= 0
      v = rand.call
      Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math::PI * v)
    end

    # Sigma of the Gaussian mechanism for L2 sensitivity (requires epsilon in (0, 1), delta in (0, 1)).
    def gaussian_sigma(epsilon, delta, l2_sensitivity)
      raise ArgumentError, 'gaussianSigma: the classic Gaussian mechanism needs epsilon in (0, 1)' unless epsilon > 0 && epsilon < 1
      raise ArgumentError, 'gaussianSigma: delta must be in (0, 1)' unless delta > 0 && delta < 1
      raise ArgumentError, 'gaussianSigma: sensitivity must be > 0' unless l2_sensitivity > 0

      O.js_div(l2_sensitivity * Math.sqrt(2 * Math.log(1.25 / delta)), epsilon)
    end

    class PopulationAggregator
      attr_reader :schema_digest, :period

      def initialize(schema_digest, period, opts = nil)
        opts = {} if opts.nil?
        raise ArgumentError, 'PopulationAggregator: schemaDigest must be a canonical b64u digest' unless Wallet.b64u32?(schema_digest)

        @schema_digest = schema_digest
        @period = period
        mc = opts['maxCellsPerPrincipal']
        @max_cells = mc.nil? ? 32 : mc
        raise ArgumentError, 'PopulationAggregator: maxCellsPerPrincipal must be a positive integer' unless WalletPopulation.integer?(@max_cells) && @max_cells > 0

        @rand = opts['rand'] || WalletPopulation.method(:crypto_rand)
        @votes = {}
        @per_principal = {}
      end

      # Accept a vote; refuses a second vote on a cell, a vote past the per-principal cell cap, or a foreign schema/period.
      def contribute(v)
        return { 'ok' => false, 'reason' => 'vote for another schema' } if v['schemaDigest'] != @schema_digest
        return { 'ok' => false, 'reason' => 'vote for another period' } if v['period'] != @period || [true, false].include?(v['period'])

        y = v['y']
        return { 'ok' => false, 'reason' => 'y must be 0 or 1' } unless Wallet.number?(y) && (y == 0 || y == 1)

        principal = v['principal']
        return { 'ok' => false, 'reason' => 'an accountable principal is required' } if !principal.is_a?(String) || principal.empty?

        key = v['cellKey']
        mine = @per_principal[principal] || Set.new
        return { 'ok' => false, 'reason' => 'one vote per principal per cell per period (sensitivity 1)' } if mine.include?(key)
        return { 'ok' => false, 'reason' => "at most #{Wallet.js_str(@max_cells)} cells per principal per period" } unless mine.length < @max_cells

        mine << key
        @per_principal[principal] = mine
        c = @votes[key] || { 'yes' => 0, 'total' => 0 }
        @votes[key] = { 'yes' => c['yes'] + y, 'total' => c['total'] + 1 }
        { 'ok' => true }
      end

      # The (epsilon, delta)-DP release. Cells whose noisy count is below minCount are suppressed.
      def release(opts)
        sensitivity = Math.sqrt(2 * @max_cells)
        sigma = WalletPopulation.gaussian_sigma(opts['epsilon'], opts['delta'], sensitivity)
        q_min = opts['qMin'].nil? ? 0.02 : opts['qMin']
        raise ArgumentError, 'release: qMin must be in (0, 0.5)' unless q_min > 0 && q_min < 0.5

        min_count = opts['minCount'].nil? ? 3 * sigma : opts['minCount']
        cells = {}
        @votes.keys.sort_by { |k| IntentOmega.u16key(k) }.each do |key|
          c = @votes[key]
          yes = c['yes'] + (sigma * WalletPopulation.gaussian(@rand))
          total = c['total'] + (sigma * WalletPopulation.gaussian(@rand))
          next unless total >= min_count

          q = WalletPopulation.js_min(1 - q_min, WalletPopulation.js_max(q_min, IntentOmega.js_div(yes, total)))
          cells[key] = { 'q' => q, 'n' => WalletPopulation.js_round(total) }
        end
        { 'v' => 1, 'kind' => 'pca-intent-population-prior', 'schema' => @schema_digest, 'period' => @period, 'epsilon' => opts['epsilon'],
          'delta' => opts['delta'], 'sigma' => sigma, 'sensitivity' => sensitivity, 'cells' => cells }
      end
    end

    # ---- local DP ---------------------------------------------------------------------------------------------------------------

    def rr_keep_probability(epsilon)
      raise ArgumentError, 'randomized response: epsilon must be > 0' unless epsilon > 0 && (epsilon.is_a?(Integer) || epsilon.finite?)

      Math.exp(epsilon) / (1 + Math.exp(epsilon))
    end

    # epsilon-LDP randomized response: report y with probability e^eps/(1+e^eps), else 1 - y.
    def randomized_response(y, epsilon, rand = method(:crypto_rand))
      rand.call < rr_keep_probability(epsilon) ? y : 1 - y
    end

    # Unbiased estimate of the true yes-rate from randomized reports: (ybar - (1 - p)) / (2p - 1).
    def debias_randomized_response(yes_reports, total, epsilon)
      raise ArgumentError, 'debias: bad counts' unless integer?(yes_reports) && integer?(total) && total > 0 && yes_reports >= 0 && yes_reports <= total

      p = rr_keep_probability(epsilon)
      O.js_div(O.js_div(yes_reports, total) - (1 - p), (2 * p) - 1)
    end

    # ---- the mixture prior ----------------------------------------------------------------------------------------------------------

    # The learner's priorMix for a release: weight(theta) = prod_c q_c^{1[c in theta]} (1 - q_c)^{1[c not in theta]} over the released
    # cells of the verb (unreleased cells contribute the constant 1/2 and drop out), mixed with weight beta <= BETA_MAX < 1.
    def population_prior(release, beta)
      raise ArgumentError, "populationPrior: beta must be in [0, #{BETA_MAX}] (full support needs beta < 1)" unless beta >= 0 && beta <= BETA_MAX

      per_verb = {}.compare_by_identity
      tables = lambda do |vs|
        per_verb[vs] ||= begin
          t = { 'cells' => [], 'lq' => [], 'lnq' => [] }
          O.verb_cell_count(vs).times do |c|
            r = release['cells'][population_cell_key(release['schema'], vs, O.decode_cell(vs, c))]
            next unless W.truthy?(r)

            t['cells'] << c
            t['lq'] << O.js_log(r['q'])
            t['lnq'] << O.js_log(1 - r['q'])
          end
          t
        end
      end
      weight = lambda do |vs, contains|
        t = tables.call(vs)
        lw = 0.0
        t['cells'].each_index { |i| lw += contains.call(t['cells'][i]) ? t['lq'][i] : t['lnq'][i] }
        Math.exp(lw)
      end
      { 'beta' => beta, 'weight' => weight }
    end

    # Mass (ppm) of cells admitted only because of the population prior: in the grant with the prior, not without it, after the same
    # observations. Zero at tau = 1 under noise-free answers (T23).
    def prior_admitted_ppm(omega, base, observations, mix)
      rest = base.reject { |k, _| k == 'priorMix' }
      without = AtlasPca::IntentLearner::IntentLearner.replay(omega, rest, observations)
      with_pop = AtlasPca::IntentLearner::IntentLearner.replay(omega, rest.merge('priorMix' => mix), observations)
      a = without.cells
      mass = 0.0
      with_pop.cells.each_with_index { |c, i| mass += c['mass'] if c['inGrant'] && !a[i]['inGrant'] }
      js_round(mass * 1_000_000)
    end
  end
end
