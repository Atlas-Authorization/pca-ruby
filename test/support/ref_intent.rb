# frozen_string_literal: true

require_relative 'ref_oracle'

# Comparison for the intent-package oracles: EXACT. Every float these corpora carry is either exactly rounded IEEE arithmetic or computed by
# the deterministic math (det_ln, det_log2, det_exp, det_pow_int: the learner's entropies, prior mix and Occam weights, the map weights,
# the omega cut points, the drift increments); the one libm term is the harmonic-number estimate for a span beyond the exact range. Counts,
# ppm integers, strings and structure are exact as before. The 1e-12 relative tolerance is kept only for the diagnostic statistics (the
# wallet population noise, lnGamma and the incomplete beta functions) in their own replays.
module RefIntent
  module_function

  def cmp = ->(got, out, _case = nil) { Ref.canon(Ref.norm(got)) == Ref.canon(out) }
end
