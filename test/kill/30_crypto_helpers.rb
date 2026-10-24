# frozen_string_literal: true

require 'openssl'

# Exact behaviour of the strict Ed25519 / ML-DSA / suite helpers (public module functions), pinned to kill surviving
# mutants of tools/pca-audit/ruby-mutate: canonical decoding, exact false (never nil / true, never a raise) on bad input.
module MutationKill
  module C
    module_function

    # resolved at CALL time: the mutation oracle replaces the AtlasPca module per mutant, a constant captured at load would
    # keep testing the original code
    def e = AtlasPca::Ed25519Strict
    def le(n) = (0...32).map { |i| (n >> (8 * i)) & 0xff }.pack('C*')
    def by = 4 * 5.pow(e::P - 2, e::P) % e::P # base point y = 4/5

    # the first y whose x^2 = (y^2-1)/(d y^2+1) is a non-residue mod p: no point has that y
    def off_curve_y
      (2..200).find do |y|
        x2 = ((y * y) - 1) * (e::D * y * y + 1).pow(e::P - 2, e::P) % e::P
        x2 != 0 && x2.pow((e::P - 1) / 2, e::P) == e::P - 1
      end
    end

    def sf(v) = v.equal?(false)
  end

  t('Ed25519Strict.decode: y >= p, off-curve, x = 0 sign rules') do
    e = C.e
    e.decode(C.le(e::P)).nil? && e.decode(C.le(e::P + 1)).nil? && e.decode(C.le(e::P - 1)) == [0, e::P - 1, 1, 0] &&
      e.decode(C.le(C.off_curve_y)).nil? &&
      e.decode(C.le(1)) == [0, 1, 1, 0] && e.decode(C.le(1 | (1 << 255))).nil? && e.decode(C.le((e::P - 1) | (1 << 255))).nil? &&
      e.decode(C.le(e::P - 1)) == [0, e::P - 1, 1, 0]
  end
  t('Ed25519Strict.acceptable_point: nil (never a raise) for undecodable, small-order and torsion points') do
    e = C.e
    b = e.decode(C.le(C.by))
    torsion = e.add(b, e.decode(C.le(e::P - 1))) # B + (0,-1): mixed order
    enc = lambda do |pt| # affine re-encoding of an extended point
      zi = pt[2].pow(e::P - 2, e::P)
      x = pt[0] * zi % e::P
      y = pt[1] * zi % e::P
      C.le(y | ((x & 1) << 255))
    end
    e.acceptable_point(C.le(C.off_curve_y)).nil? && e.acceptable_point(C.le(1)).nil? && e.acceptable_point(C.le(e::P - 1)).nil? &&
      e.acceptable_point(enc.call(torsion)).nil? && !e.acceptable_point(C.le(C.by)).nil?
  end
  t('Ed25519Strict.verify: strictly false on bad lengths / points / raise') do
    k = OpenSSL::PKey.new_raw_private_key('ED25519', "\x07".b * 32)
    pub = k.raw_public_key
    sig = k.sign(nil, 'm')
    e = C.e
    e.verify(pub, 'm', sig) == true &&
      [[pub[0, 31], sig], [pub, sig[0, 63]], [pub + "\x00", sig], [C.le(1), sig], [pub, C.le(1) + sig[32, 32]], [nil, sig], [pub, nil]].all? { |p, s| C.sf(e.verify(p, 'm', s)) }
  end
  t('mldsa65_verify / _b64u: strictly false, never true, on bad input') do
    m = AtlasPca
    pk = "\x01".b * m::ML_DSA_65_PUBLIC_KEY_BYTES
    sg = "\x01".b * m::ML_DSA_65_SIGNATURE_BYTES
    [[pk[0, 10], sg], [pk, sg[0, 10]], [nil, sg], [pk, nil], [5, 5]].all? { |a, b| C.sf(m.mldsa65_verify(a, 'm', b)) } &&
      [[m.b64e(pk), 'AA'], ['AA', m.b64e(sg)], [nil, nil], [5, m.b64e(sg)]].all? { |a, b| C.sf(m.mldsa65_verify_b64u(a, 'm', b)) }
  end
  t('resolve_suite exact results', needs: 'ml-dsa-65') do
    r = ->(p) { AtlasPca.resolve_suite(p) }
    r.call({}) == ['ed25519', nil] && r.call({ 'alg' => 'ml-dsa-65' }) == ['ml-dsa-65', nil] &&
      r.call({ 'alg' => 5 }) == [nil, "'alg' must be a string"] && r.call({ 'alg' => nil }) == [nil, "'alg' must be a string"] &&
      r.call({ 'alg' => 'rsa' }) == [nil, "unknown signature alg 'rsa'"]
  end
  t('PinnedPq: private constructor, unforgeable frozen token, frozen instances') do
    pq = AtlasPca::PinnedPq
    k = pq.mint('KEY', 'trusted')
    forged = begin
      pq.send(:new, 'KEY', 'x', Object.new)
      false
    rescue ArgumentError => e
      e.message == 'PinnedPq is minted only by resolve_pq_key'
    end
    public_new = begin
      pq.new('KEY', 'x', pq::MINT)
      false
    rescue NoMethodError
      true
    end
    k.key == 'KEY' && k.source == 'trusted' && k.frozen? && forged && public_new &&
      pq::MINT.frozen? && pq::MINT.instance_of?(Object)
  end
end
