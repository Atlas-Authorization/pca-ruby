# frozen_string_literal: true

require_relative 'intent_omega'
require_relative 'intent_policy'

# Measuring a grant against an intent: Monte Carlo and exact risk / burden / fidelity, the Hoeffding half-width and the Wilson
# interval. Native port of the TypeScript reference (@atlasauth/pca-intent).
module AtlasPca
  module IntentMetrics
    module_function

    def acceptability_of(policy)
      a = IntentPolicy.admitter(policy)
      ->(vs, o) { a.admits(vs, o) ? 1 : 0 }
    end

    def hoeffding_half_width(range_, samples, delta_prime = 0.05)
      o = IntentOmega
      range_ * o.js_sqrt(o.js_div(o.js_log(o.js_div(2, delta_prime)), 2 * samples))
    end

    def measure_grant(omega, grant, acceptability, opts = nil)
      opts ||= {}
      o = IntentOmega
      m = opts.fetch('samples', 20_000)
      harm = opts['harm'] || o::DEFAULT_HARM
      rand = o.rng(opts.fetch('seed', 1))
      g = IntentPolicy.admitter(grant)
      r = b = rm = 0.0
      h_max = 0.0
      m.times do
        vs, out = o.sample_outcome(omega, rand, harm)
        a = acceptability.call(vs, out)
        h = o.harm_of(vs, out, harm)
        h_max = [h_max, h].max
        if g.admits(vs, out)
          r += (1 - a) * h
        else
          b += a
        end
        rm += (1 - a) * h
      end
      r = o.js_div(r, m)
      b = o.js_div(b, m)
      rm = o.js_div(rm, m)
      hm = opts['hMax']
      { 'risk' => r, 'burden' => b, 'riskMax' => rm, 'fidelity' => rm.positive? ? 1 - (r / rm) : 1, 'samples' => m,
        'riskHalfWidth' => hoeffding_half_width(hm.nil? ? h_max : hm, m) }
    end

    # The Monte Carlo form of the learner's residual-risk estimate, for the cross-check.
    def estimate_residual_risk_mc(learner, opts = nil)
      opts ||= {}
      o = IntentOmega
      m = opts.fetch('samples', 20_000)
      rand = o.rng(opts.fetch('seed', 7))
      g = IntentPolicy.admitter(learner.synthesize)
      r = 0.0
      m.times do
        vs, out = o.sample_outcome(learner.omega, rand, learner.harm)
        r += (1 - learner.acceptance(out)) * o.harm_of(vs, out, learner.harm) if g.admits(vs, out)
      end
      o.js_div(r, m)
    end

    # Exact R, B, R_max, F by summing over the cells (no sampling error).
    def measure_grant_exact(omega, grant, acceptability, harm = IntentOmega::DEFAULT_HARM)
      o = IntentOmega
      g = IntentPolicy.admitter(grant)
      r = b = rm = eh = 0.0
      omega['verbs'].each do |vs|
        o.verb_cell_count(vs).times do |c|
          idx = o.decode_cell(vs, c)
          out = o.cell_rep(vs, idx)
          st = o.cell_stats(vs, idx, harm)
          mass = st['mass']
          h = st['harm']
          a = acceptability.call(vs, out)
          eh += mass * h
          rm += mass * (1 - a) * h
          if g.admits(vs, out)
            r += mass * (1 - a) * h
          else
            b += mass * a
          end
        end
      end
      { 'risk' => r, 'burden' => b, 'riskMax' => rm, 'fidelity' => rm.positive? ? 1 - (r / rm) : 1, 'meanHarm' => eh }
    end

    # Wilson score interval for a binomial proportion k/n (default 95%).
    def wilson_interval(k, n, z = 1.959963984540054)
      o = IntentOmega
      return { 'p' => Float::NAN, 'lo' => 0, 'hi' => 1 } unless n.positive?

      p = k.to_f / n
      z2 = z * z
      den = 1 + (z2 / n)
      centre = (p + (z2 / (2 * n))) / den
      half = (z * o.js_sqrt(((p * (1 - p)) / n) + (z2 / (4.0 * n * n)))) / den
      { 'p' => p, 'lo' => o.js_max(0, centre - half), 'hi' => o.js_min(1, centre + half) }
    end
  end
end
