# frozen_string_literal: true

# Replays the TS-reference oracle of the MPC deterministic layer and the SPDZ online phase (test-data/ref-mpc.json.gz). Every random
# draw in the corpus comes from a seeded SplitMix64; bigints travel as decimal strings.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/mpc_spdz'
require 'minitest/autorun'

class TestRefMpc < Minitest::Test
  M = AtlasPca::Mpc
  F = M::Field
  S = M::Spdz

  def self.big(o)
    raise ArgumentError, 'bigint arg' unless o.is_a?(String)

    o.to_i
  end

  # a JavaScript integer argument (a non-integer is the reference's Number.isInteger failure)
  def self.int(o)
    raise ArgumentError, 'not an integer' unless o.is_a?(Numeric) && o.to_f.finite? && o.to_f == o.to_f.round
    return o.positive? ? 2**31 - 1 : -2**31 if o.abs > 1e9

    o.to_i
  end

  def self.dbl(o)
    raise ArgumentError, 'not a number' unless o.is_a?(Numeric)

    o.to_f
  end

  def self.rng(seed) = F::FieldRng.new(big(seed))
  def self.bigs(o) = o.map { |x| x.nil? ? nil : big(x) }
  def self.bigss(o) = o.map { |x| bigs(x) }
  def self.str(a) = a.map { |x| x&.to_s }
  def self.strs(a) = a.map { |x| str(x) }

  def self.vectors(o)
    raise ArgumentError, 'decision vectors must be an array' unless o.is_a?(Array)

    o.map do |e|
      raise ArgumentError, 'decision vector must be an object' unless e.is_a?(Hash)

      M::DecisionVector.new(int(e['allow']), int(e['t']), int(e['rQuant']))
    end
  end

  def self.auth_sv(x) = { 'value' => str(x.value), 'mac' => str(x.mac), 'extraMac' => strs(x.extra_mac) }
  def self.triple(t) = { 'a' => auth_sv(t.a), 'b' => auth_sv(t.b), 'c' => auth_sv(t.c) }
  def self.key(k) = { 'alphaShares' => str(k.alpha_shares), 'alpha' => k.alpha.to_s }

  def self.ctx(c)
    { 'n' => c.n, 'alphaShares' => str(c.alpha_shares), 'alpha' => c.alpha.to_s, 'extraKeys' => c.extra_keys.map { |k| key(k) } }
  end

  def self.devs(o)
    o.map { |d| S::Deviation.new(int(d[0]), int(d[1]), d[2].nil? ? nil : big(d[2]), d[3].nil? ? nil : big(d[3]), d[4].nil? ? nil : int(d[4])) }
  end

  def self.fault(o)
    return nil if o.nil?

    S::DealerFault.new(o['keepCDelta'].nil? ? nil : big(o['keepCDelta']), o['partnerCDelta']&.map { |x| x.nil? ? nil : big(x) })
  end

  def self.opened(l) = l.map { |m| { 'label' => m.label, 'value' => m.value.to_s, 'shares' => str(m.shares) } }
  def self.decision(d) = { 'allow' => d.allow, 't' => d.t, 'rQuant' => d.r_quant }
  def self.partnered(t) = { 'keep' => triple(t.keep), 'partners' => t.partners.map { |p| triple(p) } }

  def self.sv_op(op, x, y)
    case op
    when 'add' then M::Sharing.add_sv(x, y)
    when 'sub' then M::Sharing.sub_sv(x, y)
    else raise ArgumentError, op
    end
  end

  def self.gf_op(a)
    g = M::Gf128
    x = big(a[1])
    case a[0]
    when 'add' then g.add(x, big(a[2]))
    when 'mul' then g.mul(x, big(a[2]))
    when 'mulX' then g.mul_x(x)
    when 'mulByXi' then g.mul_by_xi(x, int(a[2]))
    else raise ArgumentError, a[0]
    end.to_s
  end

  def self.auth_op(a)
    op = a[0]
    g = rng(a[2])
    c = S.setup_mac(int(a[1]), g)
    x = S.auth_share(big(a[3]), c, g)
    y = S.auth_share(big(a[4]), c, g)
    k = big(a[5])
    return { 'val' => S.auth_value(x).to_s } if op == 'open'

    res = case op
          when 'add' then S.add_auth(x, y)
          when 'sub' then S.sub_auth(x, y)
          when 'neg' then S.neg_auth(x)
          when 'scale' then S.scale_auth(x, k)
          when 'addPublic' then S.add_public_auth(x, k, c)
          when 'notBit' then S.not_bit_auth(x, c)
          else raise ArgumentError, op
          end
    val = S.auth_value(res)
    rows = [res.mac, *res.extra_mac]
    keys = S.mac_keys(c)
    ok = rows.each_with_index.all? { |row, l| row.reduce(0) { |s, m| F.fadd(s, m) } == F.fmul(keys[l].alpha, val) }
    { 'res' => auth_sv(res), 'val' => val.to_s, 'okMac' => ok }
  end

  def self.engine_run(a)
    g = rng(a[1])
    c = S.setup_mac(int(a[0]), g, a.length > 4 ? int(a[4]) : S::MAC_KEYS)
    e = S::SpdzEngine.new(c, devs(a[3]))
    outs = a[2].each_with_index.map { |v, i| e.open(S.auth_share(big(v), c, g), "v#{i}").to_s }
    e.mac_check(g)
    { 'outs' => outs, 'count' => e.open_count }
  end

  def self.beaver_auth(a)
    g = rng(a[1])
    c = S.setup_mac(int(a[0]), g)
    e = S::SpdzEngine.new(c, devs(a[4]))
    x = S.auth_share(big(a[2]), c, g)
    y = S.auth_share(big(a[3]), c, g)
    t = S.gen_auth_triple(c, g)
    z = S.beaver_mul_auth(x, y, t, c, e, 'm')
    val = S.auth_value(z)
    out = e.open(z, 'out')
    e.mac_check(g)
    { 'z' => auth_sv(z), 'val' => val.to_s, 'out' => out.to_s, 'opens' => e.open_count }
  end

  def self.sacrifice(a)
    g = rng(a[1])
    c = S.setup_mac(int(a[0]), g)
    f = fault(a[4])
    batch = Array.new(int(a[2])) { |i| S.gen_triple_with_partners(c, g, int(a[3]), i.zero? ? f : nil) }
    { 'certified' => S.sacrifice_verify(batch, c, g, devs(a[5])).map { |t| triple(t) } }
  end

  def self.compose_secure(a)
    r = M::Runner.compose_secure(vectors(a[0]), int(a[1]), big(a[2]))
    { 'composed' => decision(r.composed), 'parties' => r.parties, 'Q' => r.q, 'multiplications' => r.multiplications, 'opened' => opened(r.opened),
      'sharings' => r.sharings.map { |s| { 'label' => s.label, 'party' => s.party, 'secret' => s.secret.to_s, 'shares' => str(s.shares) } },
      'heldShares0' => str(r.views[0].held_shares), 'viewsLen' => r.views.length }
  end

  def self.malicious(a)
    m = a[1]
    d = m['dealer']
    dealer = d && M::SpdzRunner::DealerOptions.new(d['verifyTriples'], d['partners'] && int(d['partners']), fault(d['fault']))
    r = M::SpdzRunner.compose_secure_malicious(vectors(a[0]), q: m['Q'] && int(m['Q']), seed: m['seed'] && big(m['seed']),
                                                deviations: m['deviations'] && devs(m['deviations']),
                                                insecure_trusted_dealer: m['insecureTrustedDealer'] == true, dealer: dealer)
    { 'composed' => decision(r.composed), 'parties' => r.parties, 'Q' => r.q, 'opens' => r.opens, 'multiplications' => r.multiplications,
      'offlineMode' => r.offline_mode, 'triplesVerified' => r.triples_verified, 'macChecked' => r.mac_checked }
  end

  CASES = Ref.load('mpc')

  MAP = {
    'mod' => ->(x) { F.mod(big(x)).to_s },
    'fneg' => ->(x) { F.fneg(big(x)).to_s },
    'fadd' => ->(x, y) { F.fadd(big(x), big(y)).to_s },
    'fsub' => ->(x, y) { F.fsub(big(x), big(y)).to_s },
    'fmul' => ->(x, y) { F.fmul(big(x), big(y)).to_s },
    'fieldRng' => ->(seed, n) { g = rng(seed); Array.new(int(n)) { g.next.to_s } },
    'fieldRngDefault' => ->(n) { g = F::FieldRng.new; Array.new(int(n)) { g.next.to_s } },
    'share' => ->(s, n, seed) { str(M::Sharing.share(big(s), int(n), rng(seed))) },
    'reconstruct' => ->(sh) { M::Sharing.reconstruct(bigs(sh)).to_s },
    'shareConstant' => ->(c, n) { str(M::Sharing.share_constant(big(c), int(n))) },
    'sv' => lambda { |op, x, y = nil|
      xs = bigs(x)
      str(case op
          when 'neg' then M::Sharing.neg_sv(xs)
          when 'scale' then M::Sharing.scale_sv(xs, big(y))
          when 'addPublic' then M::Sharing.add_public_sv(xs, big(y))
          when 'notBit' then M::Sharing.not_bit_sv(xs)
          else sv_op(op, xs, bigs(y))
          end)
    },
    'gf' => ->(*a) { gf_op(a) },
    'encBits' => ->(s) { M::Enc.enc_bits(int(s)) },
    'makeGadget' => ->(s, seed, unsafe) { str(M::Enc.make_gadget(int(s), rng(seed), unsafe == true)) },
    'plainShare' => ->(x) { e = M::Enc.plain_share(big(x)); { 'value' => e.value.to_s, 'bits' => e.bits } },
    'plainGadget' => -> { str(M::Enc.plain_gadget) },
    'randomBits' => ->(m, seed) { M::Enc.random_bits(int(m), rng(seed)) },
    'sampleEnc' => lambda { |s, seed|
      g = rng(seed)
      gad = M::Enc.make_gadget(int(s), g, true)
      e = M::Enc.sample_enc(gad, g)
      { 'gadget' => str(gad), 'e' => { 'value' => e.value.to_s, 'bits' => e.bits } }
    },
    'encValue' => ->(g, bits) { M::Enc.enc_value(bigs(g), bits.map { |b| int(b) }).to_s },
    'genTriple' => ->(n, seed) { t = M::Beaver.gen_triple(int(n), rng(seed)); { 'a' => str(t.a), 'b' => str(t.b), 'c' => str(t.c) } },
    'beaverMul' => lambda { |x, y, ta, tb, tc|
      op = []
      z = M::Beaver.beaver_mul(bigs(x), bigs(y), M::Beaver::Triple.new(bigs(ta), bigs(tb), bigs(tc)), op)
      { 'z' => str(z), 'opened' => opened(op) }
    },
    'thermometerEncode' => ->(v, m) { M::Thermometer.thermometer_encode(dbl(v), int(m)) },
    'thermometerDecode' => ->(bits) { bits.count { |b| b.is_a?(Numeric) && b == 1 } },
    'quantizeR' => ->(r, q) { M::Party.quantize_r(dbl(r), int(q)) },
    'composeClear' => ->(v, q) { decision(M::Compose.compose_clear(vectors(v), int(q))) },
    'assertDecisionVectors' => ->(v, q) { M::Compose.assert_decision_vectors(vectors(v), int(q)) && true },
    'composeSecure' => ->(*a) { compose_secure(a) },
    'setupMac' => ->(n, seed, keys) { ctx(S.setup_mac(int(n), rng(seed), int(keys))) },
    'macSoundnessBits' => ->(k, p = nil) { p.nil? ? S.mac_soundness_bits(int(k)) : S.mac_soundness_bits(int(k), big(p)) },
    'authShare' => lambda { |n, seed, secret|
      g = rng(seed)
      c = S.setup_mac(int(n), g)
      { 'ctx' => ctx(c), 'sv' => auth_sv(S.auth_share(big(secret), c, g)) }
    },
    'authConstant' => ->(n, seed, c) { auth_sv(S.auth_constant(big(c), S.setup_mac(int(n), rng(seed)))) },
    'authOp' => ->(*a) { auth_op(a) },
    'genAuthTriple' => ->(n, seed) { g = rng(seed); triple(S.gen_auth_triple(S.setup_mac(int(n), g), g)) },
    'genTripleWithPartners' => lambda { |*a|
      if a.length == 2
        g = rng(a[1])
        partnered(S.gen_triple_with_partners(S.setup_mac(int(a[0]), g), g))
      else
        g = rng(a[0])
        partnered(S.gen_triple_with_partners(S.setup_mac(2, g), g, int(a[1]), fault(a[2])))
      end
    },
    'sacrifice' => ->(*a) { sacrifice(a) },
    'engineRun' => ->(*a) { engine_run(a) },
    'macResiduals' => lambda { |p, alphas, op, ch|
      ov = op.map { |o| S::OpenedValue.new(big(o['value']), bigss(o['macShares']), '') }
      strs(S.mac_residuals(big(p), bigss(alphas), ov, bigss(ch)))
    },
    'beaverAuth' => ->(*a) { beaver_auth(a) },
    'composeSecureMalicious' => ->(*a) { malicious(a) }
  }.freeze

  def test_corpus_is_covered
    assert_equal MAP.keys.sort, CASES.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}_matches_the_reference") { Ref.run(self, CASES[fn], MAP[fn]) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1570, CASES.values.sum(&:length), 'mpc'
  end

end
