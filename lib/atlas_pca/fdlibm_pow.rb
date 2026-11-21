# frozen_string_literal: true

module AtlasPca
  # Math.pow as the reference computes it: fdlibm's __ieee754_pow (e_pow.c), statement for statement with the same constants, plus
  # the reference language's rule that (+-1) ** +-Infinity is NaN. The platform pow may round the last bit differently, which would
  # move a cutoff that is compared as an integer; this one does not depend on the platform.
  # Method: log2(x) to extra precision as t1 + t2, y * log2(x) = n + y' with |y'| <= 0.5, x**y = 2**n * exp(y' * ln2).
  module FdLibm
    H = ->(s) { Float(s) } # a hexadecimal floating-point constant, exact
    SIGNIF = 0x7fffffff
    TWO53 = H.call('0x1.0p53')
    HUGE_Y = H.call('0x1.00000ffffffffp31')
    INV_LN2 = H.call('0x1.71547652b82fep0')
    INV_LN2_H = H.call('0x1.71547p+0')
    INV_LN2_L = H.call('0x1.94ae0bf85ddf4p-22')
    BELOW_ONE = H.call('0x1.fffff00000000p-1')
    ABOVE_ONE = H.call('0x1.00000ffffffffp0')
    CP = H.call('0x1.ec709dc3a03fdp-1')
    CP_H = H.call('0x1.ec709ep-1')
    CP_L = -H.call('0x1.e2fe0145b01f5p-28')
    DP_H = H.call('0x1.2b8034p-1')
    DP_L = H.call('0x1.cfdeb43cfd006p-27')
    L1 = H.call('0x1.3333333333303p-1')
    L2 = H.call('0x1.b6db6db6fabffp-2')
    L3 = H.call('0x1.55555518f264dp-2')
    L4 = H.call('0x1.17460a91d4101p-2')
    L5 = H.call('0x1.d864a93c9db65p-3')
    L6 = H.call('0x1.a7e284a454eefp-3')
    OVT = 8.0085662595372944372e-17
    P1 = H.call('0x1.555555555553ep-3')
    P2 = -H.call('0x1.6c16c16bebd93p-9')
    P3 = H.call('0x1.1566aaf25de2cp-14')
    P4 = -H.call('0x1.bbd41c5d26bf1p-20')
    P5 = H.call('0x1.6376972bea4d0p-25')
    LG2 = H.call('0x1.62e42fefa39efp-1')
    LG2_H = H.call('0x1.62e43p-1')
    LG2_L = -H.call('0x1.05c610ca86c39p-29')
    INF = Float::INFINITY

    module_function

    # the high and the low 32 bits of a double, as signed 32-bit integers
    def hi(x) = [x].pack('G').unpack1('l>')
    def lo(x) = [x].pack('G').unpack('l>l>')[1]
    def set_hi(x, h) = [h & 0xffffffff, [x].pack('G').unpack('NN')[1]].pack('NN').unpack1('G')
    def lo0(x) = [[x].pack('G').unpack1('N'), 0].pack('NN').unpack1('G')

    def pow(x, y)
      x = x.to_f
      y = y.to_f
      return 1.0 if y.zero?
      return x + y if x.nan? || y.nan?

      y_abs = y.abs
      x_abs = x.abs
      if y == 2.0
        return x * x
      elsif y == 0.5
        return Math.sqrt(x + 0.0) if x >= -Float::MAX && x >= 0.0
        return (x - x) / (x - x) if x >= -Float::MAX # the square root of a negative number
      elsif y_abs == 1.0
        return y == 1.0 ? x : 1.0 / x
      elsif y_abs == INF
        return y - y if x_abs == 1.0 # (+-1)**+-inf is NaN
        return y >= 0 ? y : 0.0 if x_abs > 1.0

        return y.negative? ? -y : 0.0
      end

      hx = hi(x)
      ix = hx & SIGNIF
      # 0: y is not an integer, 1: an odd integer, 2: an even integer (only needed for x < 0)
      y_is_int = 0
      if hx.negative?
        if y_abs >= TWO53
          y_is_int = 2
        elsif y_abs >= 1.0
          as_int = y_abs.to_i
          y_is_int = 2 - (as_int & 1) if as_int.to_f == y_abs
        end
      end

      if x_abs.zero? || x_abs == INF || x_abs == 1.0
        z = x_abs
        z = 1.0 / z if y.negative?
        if hx.negative?
          if ((ix - 0x3ff00000) | y_is_int).zero?
            z = (z - z) / (z - z) # (-1)**non-integer is NaN
          elsif y_is_int == 1
            z = -1.0 * z
          end
        end
        return z
      end

      n = (hx >> 31) + 1
      return (x - x) / (x - x) if (n | y_is_int).zero? # (x < 0)**non-integer is NaN

      s = (n | (y_is_int - 1)).zero? ? -1.0 : 1.0 # the sign of the result: -1 for negative ** odd integer

      if y_abs > HUGE_Y
        return y.negative? ? s * INF : s * 0.0 if x_abs < BELOW_ONE
        return y.positive? ? s * INF : s * 0.0 if x_abs > ABOVE_ONE

        t = x_abs - 1.0
        w = (t * t) * (0.5 - (t * (0.3333333333333333333333 - (t * 0.25))))
        u = INV_LN2_H * t
        v = (t * INV_LN2_L) - (w * INV_LN2)
        t1 = lo0(u + v)
        t2 = v - (t1 - u)
      else
        n = 0
        if ix < 0x00100000 # subnormal x
          x_abs *= TWO53
          n -= 53
          ix = hi(x_abs)
        end
        n += (ix >> 20) - 0x3ff
        j = ix & 0x000fffff
        ix = j | 0x3ff00000
        if j <= 0x3988E
          k = 0
        elsif j < 0xBB67A
          k = 1
        else
          k = 0
          n += 1
          ix -= 0x00100000
        end
        x_abs = set_hi(x_abs, ix)
        kd = k.to_f
        bp = 1.0 + (0.5 * kd)
        u = x_abs - bp
        v = 1.0 / (x_abs + bp)
        ss = u * v
        s_h = lo0(ss)
        t_h = set_hi(0.0, ((ix >> 1) | 0x20000000) + 0x00080000 + (k << 18))
        t_l = x_abs - (t_h - bp)
        s_l = v * ((u - (s_h * t_h)) - (s_h * t_l))
        s2 = ss * ss
        r = s2 * s2 * (L1 + (s2 * (L2 + (s2 * (L3 + (s2 * (L4 + (s2 * (L5 + (s2 * L6))))))))))
        r += s_l * (s_h + ss)
        s2 = s_h * s_h
        t_h = lo0(3.0 + s2 + r)
        t_l = r - ((t_h - 3.0) - s2)
        u = s_h * t_h
        v = (s_l * t_h) + (t_l * ss)
        p_h = lo0(u + v)
        p_l = v - (p_h - u)
        z_h = CP_H * p_h
        z_l = (CP_L * p_h) + (p_l * CP) + (DP_L * kd)
        t = n.to_f
        t1 = lo0(((z_h + z_l) + (DP_H * kd)) + t)
        t2 = z_l - (((t1 - t) - (DP_H * kd)) - z_h)
      end

      y1 = lo0(y)
      p_l = ((y - y1) * t1) + (y * t2)
      p_h = y1 * t1
      z = p_l + p_h
      j = hi(z)
      i = lo(z)
      if j >= 0x40900000 # z >= 1024
        return s * INF unless ((j - 0x40900000) | i).zero?
        return s * INF if p_l + OVT > z - p_h
      elsif (j & SIGNIF) >= 0x4090cc00 # z <= -1075
        return s * 0.0 unless ((j - (0xc090cc00 - 0x100000000)) | i).zero?
        return s * 0.0 if p_l <= z - p_h
      end

      i = j & SIGNIF
      k = (i >> 20) - 0x3ff
      n = 0
      if i > 0x3fe00000 # |z| > 0.5: n = [z + 0.5]
        n = j + (0x00100000 >> (k + 1))
        n = [n].pack('l>').unpack1('l>') if n.abs > 0x7fffffff # 32-bit wrap, as the original
        k = ((n & SIGNIF) >> 20) - 0x3ff
        t = set_hi(0.0, n & ~(0x000fffff >> k))
        n = ((n & 0x000fffff) | 0x00100000) >> (20 - k)
        n = -n if j.negative?
        p_h -= t
      end
      t = lo0(p_l + p_h)
      u = t * LG2_H
      v = ((p_l - (t - p_h)) * LG2) + (t * LG2_L)
      z = u + v
      w = v - (z - u)
      t = z * z
      t1 = z - (t * (P1 + (t * (P2 + (t * (P3 + (t * (P4 + (t * P5)))))))))
      r = ((z * t1) / (t1 - 2.0)) - (w + (z * w))
      z = 1.0 - (r - z)
      j = hi(z) + (n << 20)
      z = (j >> 20) <= 0 ? Math.ldexp(z, n) : set_hi(z, hi(z) + (n << 20))
      s * z
    end
  end
end
