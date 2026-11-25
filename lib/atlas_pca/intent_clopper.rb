# frozen_string_literal: true

require_relative 'intent_omega'

# Exact Clopper-Pearson upper bounds, computed in integer arithmetic at dyadic points q = a / 2^52 exactly as the formal definition
# is stated; a floating-point bisection only supplies the starting guess. Native port of the TypeScript reference
# (@atlasauth/pca-intent).
module AtlasPca
  module IntentClopper
    CP_GRID_BITS = 52
    CP_TOLERANCE = 2.0**-44
    A = 1 << CP_GRID_BITS
    TOL_UNITS = 1 << (CP_GRID_BITS - 44)

    # log1p: Math.log1p where this Ruby has it, else libm through ffi (the guess and the diagnostic CDF need the libm value).
    LOG1P = begin
      if Math.respond_to?(:log1p)
        Math.method(:log1p)
      else
        require 'ffi'
        libm = Module.new do
          extend FFI::Library
          ffi_lib ['m', 'libm.so.6', 'libm.dylib', FFI::Library::LIBC]
          attach_function :log1p, [:double], :double
        end
        libm.method(:log1p)
      end
    rescue LoadError, StandardError
      ->(x) { u = 1.0 + x; u == 1.0 ? x : (Math.log(u) * x) / (u - 1.0) } # last resort: Kahan's identity, not bit-identical to libm
    end

    module_function

    def log_factorials(n)
      lf = Array.new(n + 1, 0.0)
      (1..n).each { |i| lf[i] = lf[i - 1] + Math.log(i) }
      lf
    end

    # P(X <= k) for X ~ Binomial(n, p) in floating point (guesses and diagnostics, never decisions).
    def binomial_cdf(k, n, p, lf = nil)
      return 1 if k >= n
      return 0 if k.negative?
      return 1 if p <= 0
      return 0 if p >= 1

      lf ||= log_factorials(n.to_i)
      lp = Math.log(p)
      lq = LOG1P.call(-p)
      s = 0.0
      (0..k.floor).each { |i| s += Math.exp(lf[n.to_i] - lf[i] - lf[n.to_i - i] + (i * lp) + ((n - i) * lq)) }
      [1, s].min
    end

    # The exact binary fraction of a finite double x in (0, 1): x = num / 2^exp.
    def double_to_dyadic(x)
      raise ArgumentError, 'doubleToDyadic: need 0 < x < 1' unless IntentOmega.number?(x) && (x.is_a?(Integer) || x.finite?) && x > 0 && x < 1

      e = 0
      y = x.to_f
      while y != y.floor
        y *= 2
        e += 1
        raise ArgumentError, 'doubleToDyadic: not reached' if e > 1100
      end
      { 'num' => y.to_i, 'exp' => e }
    end

    # The numerator N with cdfRec(a / 2^52, n, k) = N / 2^(52 n).
    def cdf_rec_numerator(n, k, a)
      raise ArgumentError, 'cdfRecNumerator: a must be in [0, 2^52]' if a.negative? || a > A

      b = A - a
      kk = [k, n].min
      row = Array.new(kk + 1, 1)
      pw = 1
      n.times do |m|
        nxt = Array.new(kk + 1, 0)
        pw_next = pw * A
        (kk + 1).times do |j|
          nxt[j] = if j >= m + 1
                     pw_next
                   else
                     left = j.zero? ? 0 : row[j - 1]
                     (a * left) + (b * row[j])
                   end
        end
        row = nxt
        pw = pw_next
      end
      row[kk]
    end

    # Exactly decides alpha < cdfRec(a / 2^52, n, k).
    def cdf_exceeds(n, k, a, alpha)
      cdf_rec_numerator(n, k, a) * (1 << alpha['exp']) > alpha['num'] * (A**n)
    end

    def float_guess(k, n, alpha)
      lf = log_factorials(n)
      lo = k.to_f / n
      hi = 1.0
      it = 0
      while it < 200 && hi - lo > 1e-13
        mid = (lo + hi) / 2
        if binomial_cdf(k, n, mid, lf) > alpha
          lo = mid
        else
          hi = mid
        end
        it += 1
      end
      hi
    end

    def clamp(a) = a.negative? ? 0 : (a > A ? A : a)

    def int?(x) = (x.is_a?(Integer) || (x.is_a?(Float) && x.finite? && x == x.floor))

    # A bracket [lo, hi] of at most the tolerance around the point where `exceeds` (antitone) flips, from any start.
    def certify_bracket(start, exceeds)
      hi = start
      step = TOL_UNITS
      while exceeds.call(hi)
        hi = clamp(hi + step)
        step *= 2
      end
      lo = clamp(hi - TOL_UNITS)
      step = TOL_UNITS
      while lo.positive? && !exceeds.call(lo)
        hi = lo
        lo = clamp(lo - step)
        step *= 2
      end
      raise ArgumentError, 'clopperPearsonUpper: unreachable (cdfRec(0) = 1)' if lo.zero? && !exceeds.call(0)

      while hi - lo > TOL_UNITS
        mid = (lo + hi) / 2
        if exceeds.call(mid)
          lo = mid
        else
          hi = mid
        end
      end
      { 'hi' => hi, 'lo' => lo }
    end

    # Exact one-sided upper bound with its certificate: {upper, upperUnits, lowerUnits}.
    def clopper_pearson_certified(k, n, alpha)
      raise ArgumentError, 'clopperPearsonUpper: need integers 0 <= k <= n' unless int?(k) && int?(n) && k >= 0 && n >= 0 && k <= n
      raise ArgumentError, 'clopperPearsonUpper: alpha must be in (0, 1)' unless IntentOmega.number?(alpha) && alpha > 0 && alpha < 1

      k = k.to_i
      n = n.to_i
      return { 'upper' => 1, 'upperUnits' => A, 'lowerUnits' => A } if n.zero? || k == n

      al = double_to_dyadic(alpha)
      start = clamp(((float_guess(k, n, alpha) * (2.0**CP_GRID_BITS)).ceil) + TOL_UNITS)
      br = certify_bracket(start, ->(a) { cdf_exceeds(n, k, a, al) })
      { 'upper' => br['hi'].to_f / (2.0**CP_GRID_BITS), 'upperUnits' => br['hi'], 'lowerUnits' => br['lo'] }
    end

    def clopper_pearson_upper(k, n, alpha) = clopper_pearson_certified(k, n, alpha)['upper']
  end
end
