# frozen_string_literal: true

# DETERMINISTIC MATH (the rule every language follows). libm's log, exp, log2 and pow are not correctly rounded and differ in the last
# digit between implementations, which moves a decision that sits on a boundary (the drift threshold, the next question, a map weight,
# an integer cut point). These functions use only integer arithmetic: fixed point with 96 fractional bits (a value is an integer scaled
# by 2^96), TRUNCATING division (toward zero), and one final conversion of the integer to a double with round-to-nearest-even followed
# by an exact power-of-two scaling.
#   det_ln(x)    ln x for x > 0 (0 and -0 give -Infinity, x < 0 and NaN give NaN): x = m * 2^E, m = M / 2^52 in [1, 2); ln x = E * LN2 + 2 * atanh((M - 2^52) / (M + 2^52)), atanh summed as
#                z + z^3/3 + z^5/5 + ... (z2 = (z*z) / 2^96 truncated) until a term is 0; LN2 = 2 * atanh(1/3).
#   det_log2(x)  the same fixed value divided by LN2 in fixed point ((fixed * 2^96) / LN2, truncating).
#   det_exp(x)   e^x: X = trunc(x * 2^96); k = floor((X + LN2/2) / LN2); r = X - k * LN2; e^r = sum of r^n / n! with term_0 = 2^96,
#                term_n = trunc(trunc(term_{n-1} * r / 2^96) / n), until a term is 0; result = sum * 2^(k - 96).
#   det_pow_int(b, n)  b^n for an integer n >= 0: 1 multiplied by b, n times, in sequence.
module AtlasPca
  module DetMath
    FRAC = 96
    ONE = 1 << FRAC

    module_function

    # truncating (toward zero) integer division, as BigInt `/`
    def tdiv(a, b)
      q = a.abs / b.abs
      (a.negative? != b.negative?) ? -q : q
    end

    # an Integer to the nearest double, ties to even (the contract's single rounding step)
    def to_double(n)
      return n.to_f if n.bit_length <= 53

      neg = n.negative?
      a = n.abs
      shift = a.bit_length - 53
      q = a >> shift
      rem = a & ((1 << shift) - 1)
      half = 1 << (shift - 1)
      q += 1 if rem > half || (rem == half && q.odd?)
      v = Math.ldexp(q.to_f, shift)
      neg ? -v : v
    end

    # 2 * atanh(num / den) in fixed point
    def atanh2(num, den)
      z = tdiv(num << FRAC, den)
      z2 = (z * z) >> FRAC
      term = z
      sum = 0
      i = 1
      until term.zero?
        sum += tdiv(term, i)
        term = (term * z2) >> FRAC
        i += 2
      end
      2 * sum
    end

    LN2 = atanh2(1, 3) # ln 2 = 2 atanh(1/3)

    # fixed-point ln(x) of a positive finite double, or nil
    def ln_fixed(x)
      return nil unless x.is_a?(Float) && x > 0 && x != Float::INFINITY

      scale = 0
      y = x
      if y < 2.0**-1022
        y *= 2.0**64
        scale = 64
      end
      bits = [y].pack('G').unpack1('Q>')
      e = ((bits >> 52) & 0x7ff) - 1023 - scale
      m = (bits & ((1 << 52) - 1)) | (1 << 52)
      (e * LN2) + atanh2(m - (1 << 52), m + (1 << 52))
    end

    def scale96(fixed) = Math.ldexp(to_double(fixed), -FRAC)

    def det_ln(x)
      x = x.to_f
      return -Float::INFINITY if x.zero? # as Math.log: ln 0 = -Infinity (-0 too)
      return Float::NAN unless x > 0
      return x if x == Float::INFINITY
      return 0.0 if x == 1

      scale96(ln_fixed(x))
    end

    def det_log2(x)
      x = x.to_f
      return -Float::INFINITY if x.zero?
      return Float::NAN unless x > 0
      return x if x == Float::INFINITY
      return 0.0 if x == 1

      scale96(tdiv(ln_fixed(x) << FRAC, LN2))
    end

    def det_exp(x)
      x = x.to_f
      return x if x.nan?
      return Float::INFINITY if x > 709.782712893384
      return 0.0 if x < -745.2 # -Infinity too
      return 1.0 if x.zero?

      bits = [x.abs].pack('G').unpack1('Q>')
      be = (bits >> 52) & 0x7ff
      frac = bits & ((1 << 52) - 1)
      m = be.zero? ? frac : frac | (1 << 52)
      sh = (be.zero? ? 1 : be) - 1075 + FRAC # |x| * 2^96 = m * 2^sh
      xx = sh >= 0 ? m << sh : m >> -sh
      xx = -xx if x.negative?
      k = (xx + (LN2 / 2)).div(LN2) # floor division
      r = xx - (k * LN2)
      term = ONE
      sum = ONE
      n = 1
      until term.zero?
        term = tdiv(tdiv(term * r, ONE), n)
        sum += term
        n += 1
      end
      e = k - FRAC
      half = (e / 2.0).truncate
      (to_double(sum) * Math.ldexp(1.0, half)) * Math.ldexp(1.0, e - half)
    end

    def det_pow_int(b, n)
      r = 1.0
      n.times { r *= b }
      r
    end
  end
end
