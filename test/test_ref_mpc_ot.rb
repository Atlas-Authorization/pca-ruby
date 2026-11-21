# frozen_string_literal: true

# Replays the TS-reference oracle of the MPC oblivious-transfer stack (test-data/ref-mpc-ot.json.gz). Every random draw in the
# corpus comes from a seeded SplitMix64; bigints travel as decimal strings, bytes as {"$bytes"}.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/mpc_ec'
require_relative '../lib/atlas_pca/mpc_ot'
require_relative '../lib/atlas_pca/mpc_mascot'
require_relative '../lib/atlas_pca/mpc_kem_ot'
require 'minitest/autorun'

class TestRefMpcOt < Minitest::Test
  M = AtlasPca::Mpc
  Ec = M::Ec
  Ot = M::Ot
  Otx = M::Otx
  F = M::Field

  def self.big(o)
    raise ArgumentError, 'bigint arg' unless o.is_a?(String)

    o.to_i
  end

  # a result byte string, kept distinguishable from text by the canonical form
  def self.byt(x) = { '$bytes' => Ref.b64e(x) }

  # a JavaScript integer argument (a non-integer is the reference's Number.isInteger failure)
  def self.int(o)
    raise ArgumentError, 'not an integer' unless o.is_a?(Numeric) && o.to_f.finite? && o.to_f == o.to_f.round
    return o.positive? ? 2**31 - 1 : -2**31 if o.abs > 1e9

    o.to_i
  end

  def self.lng(o)
    raise ArgumentError, 'not an integer' unless o.is_a?(Numeric) && o.to_f.finite? && o.to_f == o.to_f.round

    o.to_i
  end

  def self.ints(o) = o.map { |x| int(x) }
  def self.bigs(o) = o.map { |x| x.nil? ? nil : big(x) }
  def self.strs(a) = a.map { |x| x&.to_s }
  def self.bytl(a) = a.map { |x| byt(x) }
  def self.pairs_out(a) = a.map { |p| [byt(p[0]), byt(p[1])] }
  def self.orng(seed) = Ot.ot_random(Ot.split_mix64(big(seed)))
  def self.flip(b, mask) = b.bytes.map { |x| x ^ mask }.pack('C*')
  ORDER2 = Ec::Point.new(0, Ec::Q - 1, 1, 0)

  def self.tamper(name)
    return nil if name == 'none'

    t = Ot::BaseOtTamper.new
    case name
    when 'S_identity' then t.tamper_s = ->(_p) { Ec::IDENTITY }
    when 'S_order2' then t.tamper_s = ->(_p) { ORDER2 }
    when 'S_other' then t.tamper_s = ->(p) { Ec.add_points(p, Ec::BASE) }
    when 'proof_z' then t.tamper_proof = ->(p) { Ec::SchnorrProof.new(p.u, (p.z + 1) % Ec::L) }
    when 'proof_U' then t.tamper_proof = ->(p) { Ec::SchnorrProof.new(Ec.add_points(p.u, Ec::BASE), p.z) }
    when 'R0_identity' then t.tamper_r = ->(r) { r[0] = Ec::IDENTITY }
    when 'R1_order2' then t.tamper_r = ->(r) { r[1] = ORDER2 if r.length > 1 }
    when 'R_swap' then t.tamper_r = ->(r) { r[0], r[1] = r[1], r[0] if r.length > 1 }
    when 'ct_flip' then t.tamper_ciphertext = ->(ct) { ct[0][0] = flip(ct[0][0], 1) }
    when 'ct_flip1' then t.tamper_ciphertext = ->(ct) { ct[-1][1] = flip(ct[-1][1], 0x80) }
    else raise ArgumentError, name
    end
    t
  end

  def self.bind_in(sess, a, b, round) = Ot::BaseOtBinding.new(Ref.b64d(sess), lng(a), lng(b), round)

  def self.random_ot(a)
    r = Ot.mal_base_random_ot(ints(a[0]), orng(a[1]), tamper(a[2]))
    { 'S' => aff(r.s), 'U' => aff(r.proof.u), 'z' => r.proof.z.to_s, 'R' => r.r.map { |p| aff(p) }, 'senderPads' => pairs_out(r.sender_pads), 'recvPads' => bytl(r.recv_pads) }
  end

  def self.base_ot(a)
    res = Ot.base_ot(a[0], ints(a[1]), orng(a[2]), tamper(a[3]))
    t = res.transcript
    { 'received' => bytl(res.received), 'S' => aff(t.s), 'U' => aff(t.proof.u), 'z' => t.proof.z.to_s, 'R' => t.r.map { |p| aff(p) },
      'ct' => pairs_out(t.ct), 'com' => pairs_out(t.com) }
  end

  def self.channel(a)
    ch = Ot::OtChannel.new(orng(a[3]))
    ch.tamper_u = case a[5]
                  when 'flip00' then ->(u, _r) { u[0] ^= 1 }
                  when 'flipLast' then ->(u, _r) { u[127] ^= 1 << 5 }
                  when 'oversize' then ->(u, _r) { u[3] |= 1 << 5000 }
                  when 'negative' then ->(u, _r) { u[3] = -1 }
                  when 'round2flip' then ->(u, r) { u[10] ^= 2 if r == 1 }
                  end
    outs = Array.new(int(a[4])) do
      e = ch.extend_ot(ints(a[0]), bigs(a[1]), bigs(a[2]))
      { 'received' => strs(e.received), 'uMatrix' => strs(e.u_matrix) }
    end
    bt = ch.base_transcript
    { 'selector' => ch.selector.to_s, 'outs' => outs, 'base' => bt.nil? ? nil : { 'S' => aff(bt.s), 'R' => bt.r.length } }
  end

  def self.kos_chi(a)
    b = Ref.b64d(a[0])
    u = bigs(a[2])
    { 'w' => Ot.kos_chi_words(b, int(a[1]), u, int(a[3])), 'chi' => strs(Ot.kos_challenges(b, int(a[1]), u, int(a[3]))) }
  end

  def self.auth_sv(x) = { 'value' => strs(x.value), 'mac' => strs(x.mac), 'extraMac' => x.extra_mac.map { |r| strs(r) } }
  def self.triple(t) = { 'a' => auth_sv(t.a), 'b' => auth_sv(t.b), 'c' => auth_sv(t.c) }
  def self.key(k) = { 'alphaShares' => strs(k.alpha_shares), 'alpha' => k.alpha.to_s }
  def self.ctx(c) = { 'n' => c.n, 'alphaShares' => strs(c.alpha_shares), 'alpha' => c.alpha.to_s, 'extraKeys' => c.extra_keys.map { |k| key(k) } }

  def self.offline_options(o)
    return nil if o.nil?

    opts = M::Mascot::NoDealerOptions.new
    opts.sacrifice = o['sacrifice'] unless o['sacrifice'].nil?
    opts.sacrifice_partners = int(o['partners']) unless o['partners'].nil?
    opts.mac_keys = int(o['keys']) unless o['keys'].nil?
    opts.stat_sec = int(o['statSec']) unless o['statSec'].nil?
    opts.unsafe_stat_sec = o['unsafe'] == true
    opts.deviation = M::Mascot::OfflineDeviation.new(int(o['dev'][0]), big(o['dev'][1])) unless o['dev'].nil?
    opts
  end

  def self.offline(a)
    n = int(a[0])
    o = a[3]
    off = M::Mascot.make_no_dealer_offline(n, big(a[1]), offline_options(o))
    base = { 'n' => off.n, 'statSec' => off.stat_sec, 'ctx' => ctx(off.mac_context) }
    case a[2]
    when 'ctx' then base
    when 'triple' then base.merge('t' => triple(off.gen_auth_triple))
    when 'input' then base.merge('v' => auth_sv(off.auth_input(big(o['value']), int(o['owner']))))
    when 'multiply'
      x = bigs(o['x'])
      y = bigs(o['y'])
      z = off.ot_share_multiply(x, y)
      base.merge('z' => strs(z), 'sum' => z.reduce(0) { |s, v| F.fadd(s, v) }.to_s,
                 'expect' => F.fmul(x.reduce(0) { |s, v| F.fadd(s, v) }, y.reduce(0) { |s, v| F.fadd(s, v) }).to_s)
    when 'consistency'
      ins = o['values'].each_with_index.map { |v, i| off.auth_input(big(v), i % n) }
      ins[0].value[0] = F.fadd(ins[0].value[0], 1) if o['tamper'] == true
      off.check_input_consistency(ins)
      base.merge('ok' => true)
    else raise ArgumentError, a[2]
    end
  end

  def self.offline_blame(a)
    opts = M::Mascot::NoDealerOptions.new
    opts.deviation = M::Mascot::OfflineDeviation.new(int(a[2]), big(a[3]))
    begin
      M::Mascot.make_no_dealer_offline(int(a[0]), big(a[1]), opts).gen_auth_triple
      { 'aborted' => false }
    rescue M::Mascot::OfflineCheatingAbort => e
      { 'aborted' => true, 'name' => 'OfflineCheatingAbort', 'blamed' => e.blamed }
    end
  end

  def self.vectors(o)
    raise ArgumentError, 'decision vectors must be an array' unless o.is_a?(Array)

    o.map do |e|
      raise ArgumentError, 'decision vector must be an object' unless e.is_a?(Hash)

      M::DecisionVector.new(int(e['allow']), int(e['t']), int(e['rQuant']))
    end
  end

  def self.no_dealer_run(a)
    m = a[1]
    r = M::SpdzRunner.compose_secure_malicious(vectors(a[0]), q: m['Q'] && int(m['Q']), seed: m['seed'] && big(m['seed']))
    { 'composed' => { 'allow' => r.composed.allow, 't' => r.composed.t, 'rQuant' => r.composed.r_quant }, 'parties' => r.parties, 'Q' => r.q,
      'opens' => r.opens, 'multiplications' => r.multiplications, 'offlineMode' => r.offline_mode, 'triplesVerified' => r.triples_verified,
      'macChecked' => r.mac_checked }
  end

  def self.kem_tamper(name)
    t = M::KemOt::KemMalTamper.new
    case name
    when 'badKey' then t.tamper_opened_keys = ->(pk) { pk[0][0], pk[0][1] = pk[0][1], pk[0][0] }
    when 'badSid' then t.tamper_receiver_sid = ->(s) { flip(s, 1) }
    else return nil
    end
    t
  end

  def self.kem_ot(a)
    fn = a[0]
    g = orng(a[3])
    choices = ints(a[2])
    tn = a[4]
    case fn
    when 'kemBaseOT'
      r = M::KemOt.kem_base_ot(a[1], choices, g)
      t = r.transcript
      { 'received' => bytl(r.received),
        'transcript' => { 'publicKeys' => pairs_out(t.public_keys), 'ciphertexts' => pairs_out(t.ciphertexts), 'encrypted' => pairs_out(t.encrypted) } }
    when 'kemBaseOtMal'
      r = M::KemOt.kem_base_ot_mal(a[1], choices, g, kem_tamper(tn))
      t = r.transcript
      { 'received' => bytl(r.received),
        'transcript' => { 'rn' => byt(t.rn), 'commitments' => bytl(t.commitments), 'sn' => byt(t.sn), 'publicKeys' => pairs_out(t.public_keys),
                          'ciphertexts' => pairs_out(t.ciphertexts), 'encrypted' => pairs_out(t.encrypted) } }
    else
      r = M::KemOt.kem_base_ot_mal_random(choices, g, kem_tamper(tn))
      t = r.transcript
      { 'senderSecrets' => pairs_out(r.sender_secrets), 'recvSecrets' => bytl(r.recv_secrets), 'sid' => byt(r.sid),
        'transcript' => { 'rn' => byt(t.rn), 'commitments' => bytl(t.commitments), 'sn' => byt(t.sn), 'publicKeys' => pairs_out(t.public_keys),
                          'ciphertexts' => pairs_out(t.ciphertexts) } }
    end
  end

  def self.kem_pad(a)
    return byt(M::KemOt.kem_ot_pad(0, 0, "\0".b * 32, int(a[0]))) if a.length == 1

    byt(M::KemOt.kem_ot_pad(int(a[0]), int(a[1]), (0...32).to_a.pack('C*'), int(a[2])))
  end

  def self.hybrid_ot(a)
    tn = a[3]
    t = nil
    unless tn.nil?
      t = M::HybridOt::HybridBaseOtTamper.new
      case tn
      when 'ec' then t.ec = tamper('ct_flip')
      when 'ecS' then t.ec = tamper('S_identity')
      when 'enc' then t.tamper_encrypted = ->(e) { e[0][0] = flip(e[0][0], 1) }
      when 'kem' then t.kem = kem_tamper('badKey')
      end
    end
    r = M::HybridOt.hybrid_base_ot(a[0], ints(a[1]), orng(a[2]), t)
    tr = r.transcript
    { 'received' => bytl(r.received), 'sid' => byt(tr.sid), 'ecS' => aff(tr.ec_s), 'kemSid' => byt(tr.kem_sid),
      'encrypted' => pairs_out(tr.encrypted), 'commitments' => pairs_out(tr.commitments) }
  end

  def self.pt(o) = Ec::Point.new(*o.map { |v| big(v) })
  def self.aff(p) = Ec.to_affine(p).then { |x, y| { 'x' => x.to_s, 'y' => y.to_s } }

  def self.ec_op(a)
    case a[0]
    when 'mulBase' then Ec.mul_base(big(a[1])).then { |p| { 'p' => aff(p), 'enc' => byt(Ec.encode_point(p)), 'comp' => byt(Ec.compress_point(p)) } }
    when 'mul' then aff(Ec.mul(big(a[1]), pt(a[2])))
    when 'add' then aff(Ec.add_points(pt(a[1]), pt(a[2])))
    when 'sub' then aff(Ec.sub(pt(a[1]), pt(a[2])))
    when 'neg' then aff(Ec.neg(pt(a[1])))
    when 'dbl' then aff(Ec.dbl(pt(a[1])))
    when 'decompress'
      p = Ec.decompress_point(a[1])
      { 'p' => aff(p), 'onCurve' => Ec.on_curve?(p), 'identity' => Ec.identity?(p), 'prime' => Ec.prime_order?(p), 'inSub' => Ec.in_subgroup?(p) }
    else raise ArgumentError, a[0]
    end
  end

  def self.schnorr(a)
    y = big(a[0])
    nonce = big(a[1])
    ctx = Ref.b64d(a[2])
    s = Ec.mul_base(y)
    proof = Ec.schnorr_prove(y, s, -> { nonce }, ctx)
    forged = Ec::SchnorrProof.new(proof.u, (proof.z + 1) % Ec::L)
    oor = Ec::SchnorrProof.new(proof.u, Ec::L)
    { 'S' => aff(s), 'U' => aff(proof.u), 'z' => proof.z.to_s, 'ok' => Ec.schnorr_verify(s, proof, ctx),
      'badCtx' => Ec.schnorr_verify(s, proof, 'other-ctx'.b), 'forged' => Ec.schnorr_verify(s, forged, ctx),
      'oor' => Ec.schnorr_verify(s, oor, ctx), 'wrongS' => Ec.schnorr_verify(Ec.mul_base(y + 1), proof, ctx),
      'identityS' => Ec.schnorr_verify(Ec::IDENTITY, proof, ctx) }
  end

  MAIN = Ref.load('mpc-ot')
  GEN = Ref.load_gen('mpc-ot')
  CASES = Ref.merge_cases(MAIN, GEN)

  MAP = {
    'ecOp' => ->(*a) { ec_op(a) },
    'ecValidate' => lambda { |o|
      p = pt(o)
      { 'onCurve' => Ec.on_curve?(p), 'identity' => Ec.identity?(p), 'prime' => Ec.prime_order?(p), 'inSubgroup' => Ec.in_subgroup?(p) }
    },
    'ecAssert' => ->(o) { Ec.assert_in_subgroup(pt(o), 'p') },
    'schnorr' => ->(*a) { schnorr(a) },
    'prg' => ->(seed, blk, n) { Otx.prg_column(Ref.b64d(seed), lng(blk), int(n)) },
    'maskTail' => ->(w, nb) { Otx.mask_tail(w.dup, int(nb)) },
    'transpose32' => ->(w) { Otx.transpose32(w.dup, 0) },
    'transposeCols' => ->(w, ww, rows) { Otx.transpose_cols(w, int(ww), int(rows)) },
    'gfMulX' => ->(w) { Otx.gf_mul_x(w.dup) },
    'gfXorInto' => ->(w, v) { Otx.gf_xor_into(w.dup, v, 0) },
    'gfBig' => ->(w) { v = Otx.gf_to_big(w); { 'big' => v.to_s, 'back' => Otx.gf_from_big(v) } },
    'accumColumn' => ->(c, chi) { Otx.accum_column(c, 0, c.length, chi, [0, 0, 0, 0]) },
    'kosCombine' => ->(c, w, chi) { Otx.kos_combine(c, int(w), chi) },
    'tmmo' => ->(rows, n, off, dom) { Otx.tmmo_crh(rows, int(n), Otx::OtTweak.new(lng(off), dom)) },
    'tweakDomain' => ->(b) { Otx.ot_tweak_domain(Ref.b64d(b)) },
    'bigBytes' => ->(v, len) { byt(Otx.big_to_bytes(big(v), int(len))) },
    'bytesBig' => ->(b) { Otx.bytes_to_big(Ref.b64d(b)).to_s },
    'word64' => ->(w, j) { Otx.word64(w, int(j)).to_s },
    'bindingBytes' => ->(s, a, b, r) { byt(Ot.binding_bytes(bind_in(s, a, b, r))) },
    'baseOtKdf' => lambda { |i|
      b0 = Ot.random_binding(orng('4242'), 'base-ot')
      r = [Ec.mul_base(5), Ec.mul_base(6)]
      th = Ot.base_ot_transcript_hash(b0, Ec.mul_base(3), r)
      { 'th' => byt(th), 'k' => byt(Ot.base_ot_kdf(th, int(i), r[0], Ec.mul_base(9))) }
    },
    'randomOt' => ->(*a) { random_ot(a) },
    'baseOt' => ->(*a) { base_ot(a) },
    'channel' => ->(*a) { channel(a) },
    'kosChi' => ->(*a) { kos_chi(a) },
    'offline' => ->(*a) { offline(a) },
    'offlineBlame' => ->(*a) { offline_blame(a) },
    'noDealerRun' => ->(*a) { no_dealer_run(a) },
    'kemOt' => ->(*a) { kem_ot(a) },
    'kemPad' => ->(*a) { kem_pad(a) },
    'hybridOt' => ->(*a) { hybrid_ot(a) },
    'hybridKey' => lambda { |len|
      byt(M::HybridOt.hybrid_transfer_key("\x01".b * 32, 3, 1, "\x02".b * 16, "\x03".b * 32, int(len)))
    }
  }.freeze

  # the ML-KEM transcripts need OpenSSL >= 3.5 (the vetted ML-KEM-768) through ffi
  NEEDS_MLKEM = %w[kemOt hybridOt].freeze

  def test_corpus_is_covered
    Ref.check_covered(self, CASES, GEN, MAP.keys)
  end

  def test_secret_corpus_present
    Ref.need_gen(self, 'mpc-ot') if GEN.nil?
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}_matches_the_reference") do
      skip 'ML-KEM-768 needs OpenSSL >= 3.5' if NEEDS_MLKEM.include?(fn) && !M::Libcrypto.mlkem_available?
      skip 'ref-mpc-ot-gen.json.gz absent' if CASES[fn].nil? && GEN.nil?
      Ref.run(self, CASES[fn], MAP[fn])
    end
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 440, MAIN.values.sum(&:length), 'mpc-ot'
  end

end
