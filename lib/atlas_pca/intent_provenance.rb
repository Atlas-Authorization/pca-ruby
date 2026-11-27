# frozen_string_literal: true

# Provenance on the wallet side and within-grant regret: the fixed banner for a tainted value, the provenance friction floor and the
# regret report. Native port of the TypeScript reference (@atlasauth/pca-intent). A regret case is a Hash {feasible, chosen, admits,
# utility} with callables for admits / utility.
module AtlasPca
  module IntentProvenance
    FRICTION_ORDER = %w[tap hold typed device].freeze

    module_function

    # The fixed banner for a tainted value (nil for trusted / first-party values).
    def provenance_banner(level, what = 'value')
      case level
      when 'web' then "This #{what} was suggested by content on the page, not by you."
      when 'agent' then "This #{what} came from your agent, not from you or the site."
      when 'tool' then "This #{what} came from another service, not from you or this site."
      end
    end

    def tainted?(level) = %w[tool web agent].include?(level)
    alias is_tainted tainted?

    # A tainted critical value is at least typed, a tainted material value at least hold; provenance only raises friction.
    def provenance_friction(base, sensitivity, level)
      floor = if !tainted?(level) then 'tap'
              elsif sensitivity == 'critical' then 'typed'
              else 'hold'
              end
      ib = FRICTION_ORDER.index(base) || -1
      i = [ib, FRICTION_ORDER.index(floor)].max
      i >= 0 ? FRICTION_ORDER[i] : nil
    end

    # Only options inside the effective grant compete; a chosen option outside it is denied (risk, not regret).
    def within_grant_regret(c)
      admitted = c['admits'].call(c['chosen'])
      best = nil
      best_u = -Float::INFINITY
      c['feasible'].each do |o|
        next unless c['admits'].call(o)

        u = c['utility'].call(o)
        if u > best_u
          best_u = u
          best = o
        end
      end
      return { 'regret' => 0, 'best' => best, 'admitted' => admitted } if !admitted || best.nil?

      d = best_u - c['utility'].call(c['chosen'])
      { 'regret' => d.is_a?(Float) && d.nan? || d > 0 ? d : 0, 'best' => best, 'admitted' => admitted }
    end

    def regret_report(cases, scale = 1)
      admitted = 0
      positive = 0
      s = 0.0
      mx = 0
      cases.each do |c|
        r = within_grant_regret(c)
        next unless r['admitted']

        admitted += 1
        s += r['regret']
        positive += 1 if r['regret'] > 0
        mx = r['regret'] if r['regret'] > mx
      end
      mean = admitted.positive? ? s / admitted : 0
      { 'cases' => cases.length, 'admitted' => admitted, 'positive' => positive, 'mean' => mean, 'max' => mx,
        'regret_est_ppm' => (((mean / (scale > 0 ? scale : 1)) * 1_000_000) + 0.5).floor }
    end
  end
end
