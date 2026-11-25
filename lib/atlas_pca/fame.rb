# frozen_string_literal: true

require_relative 'bls12'
require_relative 'abe_policy'

module AtlasPca
  # FAME (Agrawal and Chase, ACM CCS 2017, ePrint 2017/807): ciphertext-policy ABE in the type-3 pairing setting, the group
  # arithmetic only (the wire format, validation and AEAD are in Abe). G1/G2 work is blst through ffi, GT work is blst through the
  # GT shim (Bls12::Gt). Same equations, hashing and span program as the TypeScript reference:
  #
  #   Setup     MPK = (h^a1, h^a2, e(g,h)^(d1 a1 + d3), e(g,h)^(d2 a2 + d3)),  MSK = (a1, a2, b1, b2, g^d1, g^d2, g^d3)
  #   KeyGen    pow = (b1 r1, b2 r2, r1 + r2), K0 = h^pow,
  #             K_y,t = (H(y,0,t)^pow0 H(y,1,t)^pow1 H(y,2,t)^pow2 g^sigma_y)^(1/a_(t+1)), K_y,2 = g^-sigma_y,
  #             K'_t = (H0(0,0,t)^pow0 H0(0,1,t)^pow1 H0(0,2,t)^pow2 g^sigma')^(1/a_(t+1)) g^d_(t+1), K'_2 = g^-sigma' g^d3
  #   Encrypt   C0 = (h1^s1, h2^s2, h^(s1+s2)),
  #             C_i,l = H(rho(i),l,0)^s1 H(rho(i),l,1)^s2 prod_j (H0(j,l,0)^s1 H0(j,l,1)^s2)^M[i][j],  K = T1^s1 T2^s2
  #   Decrypt   K = prod_l e(keyProd_l, C0_l) / e(ctProd_l, K0_l) with the tree's Lagrange reconstruction weights
  #
  # The span program is a Shamir sharing down the threshold tree (each t-of-n gate adds t-1 columns; child i gets its parent's row
  # plus i^k in the gate's k-th new column). rho must be injective: a policy naming one attribute twice is refused by the caller.
  module Fame
    # domain-separation tag of the attribute / column random oracles (RFC 9380 SSWU_RO into G1)
    ATTR_DST = 'ATLAS-PCA-ABE:FAME:H-G1:SHA256-SSWU-RO:v1'
    R = Bls12::R

    Mpk = Struct.new(:h1, :h2, :t1, :t2)
    Msk = Struct.new(:a, :b, :g)
    Key = Struct.new(:k0, :kp, :attrs) # attrs: name => [G1, G1, G1]
    Ciphertext = Struct.new(:ct0, :rows)
    Master = Struct.new(:mpk, :msk)
    Encapsulation = Struct.new(:ct, :k)
    Row = Struct.new(:attr, :vec)
    Plan = Struct.new(:row, :xs, :subs)

    module_function

    def g1 = (@g1 ||= Bls12::G1.generator)
    def g2 = (@g2 ||= Bls12::G2.generator)

    # k*P for k non-zero mod r; a zero scalar raises (the reference refuses it)
    def mul(p, k)
      raise ZeroDivisionError, 'scalar is zero' if (k % R).zero?

      p * k
    end

    # ---- random oracles ----

    def hash_to_g1(msg) = Bls12::G1.hash_to(msg, ATTR_DST)

    # H(y, l, t): kind byte 1, length-prefixed UTF-8 attribute, l, t
    def h_attr(attr, l, t)
      a = AtlasPca::Js.utf8(attr)
      hash_to_g1([1].pack('C') + [a.bytesize].pack('N') + a + [l, t].pack('CC'))
    end

    # H0(j, l, t): the column-indexed oracle (kind byte 2)
    def h_col(j, l, t) = hash_to_g1([2].pack('C') + [j].pack('N') + [l, t].pack('CC'))

    # ---- setup / keygen ----

    def setup(a, b, d)
      egh = Bls12::Gt.pairing(g1, g2)
      mpk = Mpk.new(mul(g2, a[0]), mul(g2, a[1]),
                    Bls12::Gt.pow(egh, Bls12.add(Bls12.mul(d[0], a[0]), d[2])), Bls12::Gt.pow(egh, Bls12.add(Bls12.mul(d[1], a[1]), d[2])))
      Master.new(mpk, Msk.new(a, b, [mul(g1, d[0]), mul(g1, d[1]), mul(g1, d[2])]))
    end

    def key_term(pow, sigma, a_inv)
      sum = (yield(0) * pow[0]) + (yield(1) * pow[1]) + (yield(2) * pow[2]) + mul(g1, sigma)
      mul(sum, a_inv)
    end

    def keygen(msk, attrs, r, sigmas, sigma_prime)
      pow = [Bls12.mul(msk.b[0], r[0]), Bls12.mul(msk.b[1], r[1]), Bls12.add(r[0], r[1])]
      a_inv = [Bls12.inv(msk.a[0]), Bls12.inv(msk.a[1])]
      k0 = [mul(g2, pow[0]), mul(g2, pow[1]), mul(g2, pow[2])]
      out = {}
      attrs.each_with_index do |y, i|
        raise ArgumentError, 'fameKeygen: one sigma per attribute is required' if i >= sigmas.length

        sg = sigmas[i]
        out[y] = [key_term(pow, sg, a_inv[0]) { |l| h_attr(y, l, 0) },
                  key_term(pow, sg, a_inv[1]) { |l| h_attr(y, l, 1) },
                  mul(g1, Bls12.sub(0, sg))]
      end
      kp = [key_term(pow, sigma_prime, a_inv[0]) { |l| h_col(0, l, 0) } + msk.g[0],
            key_term(pow, sigma_prime, a_inv[1]) { |l| h_col(0, l, 1) } + msk.g[1],
            mul(g1, Bls12.sub(0, sigma_prime)) + msk.g[2]]
      Key.new(k0, kp, out)
    end

    # ---- span program ----

    # leaves in depth-first order, each with its sparse span-program row (column 0 is the secret column, always 1)
    def build_rows(tree)
      rows = []
      ncols = [1]
      walk_rows(tree, { 0 => 1 }, rows, ncols)
      rows
    end

    def walk_rows(node, vec, rows, ncols)
      if AbePolicy.leaf?(node)
        rows << Row.new(node['attr'], vec)
        return
      end
      t = AbePolicy.t(node)
      base = ncols[0]
      ncols[0] += t - 1
      AbePolicy.of(node).each_with_index do |child, idx|
        cv = vec.dup
        x = idx + 1
        pw = 1
        (1...t).each do |k|
          pw = Bls12.mul(pw, x)
          cv[base + k - 1] = pw
        end
        walk_rows(child, cv, rows, ncols)
      end
    end

    def leaf_count(tree) = AbePolicy.leaf?(tree) ? 1 : AbePolicy.of(tree).sum { |c| leaf_count(c) }

    # first attribute named by two leaves, or nil (FAME needs an injective row labelling)
    def first_repeated_attribute(tree)
      seen = {}
      AbePolicy.leaves(tree).each do |a|
        return a if seen.key?(a)

        seen[a] = true
      end
      nil
    end

    # ---- encrypt ----

    def encrypt(mpk, tree, s)
      rows = build_rows(tree)
      col_memo = {}
      out = rows.map do |row|
        (0...3).map do |l|
          acc = (mul(h_attr(row.attr, l, 0), s[0]) + mul(h_attr(row.attr, l, 1), s[1]))
          row.vec.each do |j, w|
            col = (col_memo["#{j}:#{l}"] ||= mul(h_col(j, l, 0), s[0]) + mul(h_col(j, l, 1), s[1]))
            acc += col * w
          end
          acc
        end
      end
      ct = Ciphertext.new([mul(mpk.h1, s[0]), mul(mpk.h2, s[1]), mul(g2, Bls12.add(s[0], s[1]))], out)
      Encapsulation.new(ct, Bls12::Gt.mul(Bls12::Gt.pow(mpk.t1, s[0]), Bls12::Gt.pow(mpk.t2, s[1])))
    end

    # ---- decrypt ----

    # bottom-up, the first t satisfiable children of every gate; nil when the subtree is not satisfied
    def plan(node, has, offset)
      return has.call(node['attr']) ? Plan.new(offset, nil, nil) : nil if AbePolicy.leaf?(node)

      t = AbePolicy.t(node)
      xs = []
      subs = []
      off = offset
      AbePolicy.of(node).each_with_index do |child, i|
        sub = plan(child, has, off)
        if sub
          xs << (i + 1)
          subs << sub
        end
        break if subs.length >= t

        off += leaf_count(child)
      end
      subs.length < t ? nil : Plan.new(-1, xs, subs)
    end

    def weights(p, w, out)
      if p.subs.nil?
        out[p.row] = w
        return true
      end
      lam = lagrange_at_zero(p.xs)
      return false if lam.nil?

      p.subs.each_with_index.all? { |sub, i| weights(sub, Bls12.mul(w, lam[i]), out) }
    end

    # Lagrange coefficients L_i(0) over Z_r; nil on an empty set, a zero point, or coinciding points
    def lagrange_at_zero(xs)
      return nil if xs.empty?

      seen = {}
      xs.each do |x|
        xr = x % R
        return nil if xr.zero? || seen.key?(xr)

        seen[xr] = true
      end
      xs.each_index.map do |i|
        num = 1
        den = 1
        xs.each_index do |j|
          next if j == i

          num = Bls12.mul(num, xs[j])
          den = Bls12.mul(den, Bls12.sub(xs[j], xs[i]))
        end
        Bls12.mul(num, Bls12.inv(den))
      end
    end

    # row index => reconstruction weight over the rows the key can use; nil when the attribute set does not satisfy the tree
    def reconstruction_weights(tree, has)
      p = plan(tree, has, 0)
      return nil if p.nil?

      out = {}
      weights(p, 1, out) ? out : nil
    end

    # the KEM key (a GT element), or nil when the key does not satisfy the tree (or a pairing input is the identity)
    def decrypt(key, tree, ct)
      rows = AbePolicy.leaves(tree)
      return nil if rows.length != ct.rows.length

      w = reconstruction_weights(tree, ->(a) { key.attrs.key?(a) })
      return nil if w.nil?

      g1s = []
      g2s = []
      (0...3).each do |l|
        ct_prod = Bls12::G1.new
        key_prod = key.kp[l]
        w.each do |row, wt|
          comp = key.attrs[rows[row]]
          c_row = ct.rows[row]
          return nil if comp.nil? || c_row.nil?

          ct_prod += c_row[l] * wt
          key_prod += comp[l] * wt
        end
        g1s << key_prod << -ct_prod
        g2s << ct.ct0[l] << key.k0[l]
      end
      begin
        Bls12::Gt.pairing_product(g1s, g2s)
      rescue ArgumentError
        nil
      end
    end
  end
end
