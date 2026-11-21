# frozen_string_literal: true

require_relative 'ref_oracle'

# Comparison for the intent-package oracles: doubles from transcendental functions match to 1e-12 relative, every other value
# (counts, ppm integers, strings, structure) exactly.
module RefIntent
  module_function

  def close?(a, b)
    if a.is_a?(Hash) && b.is_a?(Hash)
      a.keys.sort == b.keys.sort && a.all? { |k, v| close?(v, b[k]) }
    elsif a.is_a?(Array) && b.is_a?(Array)
      a.length == b.length && a.each_index.all? { |i| close?(a[i], b[i]) }
    elsif [true, false].include?(a) || [true, false].include?(b)
      a.equal?(b)
    elsif a.is_a?(Numeric) && b.is_a?(Numeric)
      return a == b if a.is_a?(Integer) && b.is_a?(Integer)
      return a.nan? && b.nan? if (a.is_a?(Float) && a.nan?) || (b.is_a?(Float) && b.nan?)

      (a - b).abs <= [1e-12 * [a.abs, b.abs].max, 1e-15].max
    else
      Ref.canon(a) == Ref.canon(b)
    end
  end

  def cmp = ->(got, out, _case = nil) { close?(Ref.norm(got), out) }
end
