# frozen_string_literal: true

# Replays the TS-reference oracle of the pure parts of the MPC networked runner (test-data/ref-mpc-net.json.gz): the wire codec,
# pairwise-authenticated shares, forensic disclosures and the OT message codecs.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/mpc_net'
require 'minitest/autorun'

class TestRefMpcNet < Minitest::Test
  M = AtlasPca::Mpc
  W = M::NetWire
  Pa = M::NetPa
  Fx = M::NetForensics
  C = M::NetCodec

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

  def self.bigs(o) = o.map { |x| x.nil? ? nil : big(x) }
  def self.strs(a) = a.map { |x| x&.to_s }
  def self.byt(x) = { '$bytes' => Ref.b64e(x) }

  # ---- wire ----
  def self.split(a)
    s = W::FrameSplitter.new
    { 'frames' => a[0].flat_map { |c| s.push(c).map { |f| byt(f) } } }
  end

  def self.net_abort(a)
    op = a[6]
    e = W::NetAbort.new(a[0], a[1].nil? ? nil : int(a[1]), int(a[2]), a[3], a[4], a[5].is_a?(Numeric) ? int(a[5]) : nil, op && op['reason'], op && op['evidence'],
                        op.nil? || op['deadlineMs'].nil? ? nil : int(op['deadlineMs']))
    { 'message' => e.message, 'name' => 'NetAbort', 'kind' => e.kind, 'blamed' => e.blamed, 'reporter' => e.reporter, 'reason' => e.reason,
      'claimedKind' => e.claimed_kind, 'claimedBlame' => e.claimed_blame, 'evidence' => e.evidence, 'deadlineMs' => e.deadline_ms }
  end

  # ---- pairwise-authenticated shares ----
  def self.pa(o) = Pa::PA.new(big(o['x']), bigs(o['tag']), bigs(o['key']))
  def self.aw(o) = Pa::AW.new(pa(o['v']), o['m'].map { |p| pa(p) })
  def self.pa_j(p) = { 'x' => p.x.to_s, 'tag' => strs(p.tag), 'key' => strs(p.key) }
  def self.aw_j(a) = { 'v' => pa_j(a.v), 'm' => a.m.map { |p| pa_j(p) } }

  def self.pa_op(a)
    op = a[0]
    p = pa(a[1])
    n = p.tag.length
    case op
    when 'add' then pa_j(Pa.pa_add(p, pa(a[2])))
    when 'sub' then pa_j(Pa.pa_sub(p, pa(a[2])))
    when 'neg' then pa_j(Pa.pa_neg(p))
    when 'scale' then pa_j(Pa.pa_scale(p, big(a[2])))
    when 'addPublic0' then pa_j(Pa.pa_add_public0(Pa::PaEnv.new(int(a[2]), n, big(a[3]), a[4] == true), p, big(a[5])))
    when 'verify' then Pa.pa_verify(Pa::PaEnv.new(int(a[2]), n, big(a[3]), true), p, int(a[4]), big(a[5]), big(a[6]))
    when 'flat'
      id = int(a[2])
      tg = a[3] == true
      f = Pa.pa_flat(p, id, n, tg)
      { 'f' => strs(f), 'w' => Pa.pa_width(n, tg), 'back' => pa_j(Pa.pa_parse(f, 0, id, n, tg)) }
    else raise ArgumentError, op
    end
  end

  def self.aw_op(a)
    return C.sharings_per_triple(int(a[0])) if a.length == 1

    if a.length == 3
      x = aw(a[0])
      n = x.v.tag.length
      keys = x.m.length
      id = int(a[1])
      tg = a[2] == true
      f = Pa.aw_flat(x, id, n, tg)
      return { 'f' => strs(f), 'w' => Pa.aw_width(n, keys, tg), 'back' => aw_j(Pa.aw_parse(f, 0, id, n, keys, tg)) }
    end
    x = aw(a[0])
    y = aw(a[1])
    n = x.v.tag.length
    alpha = a[2].map { |p| pa(p) }
    tg = a[3] == true
    c = big(a[4])
    { 'add' => aw_j(Pa.w_add(x, y)), 'sub' => aw_j(Pa.w_sub(x, y)), 'neg' => aw_j(Pa.w_neg(x)), 'scale' => aw_j(Pa.w_scale(x, c)),
      'addPublic' => aw_j(Pa.w_add_public(Pa::PaEnv.new(1, n, 7, tg), x, c, alpha)),
      'addPublic0' => aw_j(Pa.w_add_public(Pa::PaEnv.new(0, n, 7, tg), x, c, alpha)) }
  end

  # ---- forensics ----
  def self.side_j(m) = m.map { |k, v| [k, strs(v)] }
  def self.side_in(o) = o.to_h { |e| [int(e[0]), bigs(e[1])] }
  def self.dis(o) = o.map { |s| Fx::SlotDisclosure.new(s['bits'].map { |b| int(b) }, big(s['y']), big(s['z']), side_in(s['recv']), side_in(s['rho'])) }

  def self.forensics(a)
    case a.length
    when 1 then Fx.slots_for(int(a[0]))
    when 3
      if a[0].is_a?(Hash)
        all = a[0].to_h { |k, v| [k.to_i, dis(v)] }
        all.delete(int(a[2])) unless a[2].nil?
        res = Fx.audit_disclosures(all, bigs(a[1]))
        { 'selfBad' => res.self_bad.sort, 'pairBad' => res.pair_bad, 'blame' => (0...3).map { |me| Fx.blame_from(me, res) } }
      else
        Fx.blame_from(int(a[0]), Fx::AuditResult.new(a[1].map { |x| int(x) }, a[2].map { |x| [int(x[0]), int(x[1])] }))
      end
    when 4
      dd = Fx.parse_disclosure(a[0], int(a[1]), int(a[2]), a[3].map { |x| int(x) })
      { 'dd' => dd.map { |s| { 'bits' => s.bits, 'y' => s.y.to_s, 'z' => s.z.to_s, 'recv' => side_j(s.recv), 'rho' => side_j(s.rho) } },
        'back' => Fx.wire_disclosure(dd) }
    when 6 then Fx.disclosure_commit(a[0], int(a[1]), int(a[2]), a[3].to_i, a[4], a[5])
    else raise ArgumentError, 'forensics arity'
    end
  end

  # ---- codecs ----
  def self.codec(a)
    case a[0]
    when 'unb64' then byt(C.unb64(a[1], a[2].nil? ? -1 : int(a[2])))
    when 'b64' then C.b64(a[1])
    when 'hexBig' then C.hex_big(a[1]).to_s
    when 'jPt' then C.pt_j(C.j_pt(a[1]))
    when 'ptJ' then C.pt_j(M::Ec.mul_base(big(a[1])))
    when 'gadgetCommit' then C.gadget_commit(a[1], int(a[2]), a[3])
    when 'gadgetStatement' then byt(C.gadget_statement(a[1], a[2], int(a[3]), a[4]))
    else raise ArgumentError, a[0]
    end
  end

  CASES = Ref.load('mpc-net')

  MAP = {
    'encodeFrame' => ->(f) { byt(W.encode_frame(f)) },
    'split' => ->(*a) { split(a) },
    'peekVersion' => ->(b) { W.peek_version(b) },
    'parseFrame' => ->(b) { W.parse_frame(b) },
    'versionMismatch' => ->(b) { W.version_mismatch(b) },
    'hx' => ->(x) { W.hx(big(x)) },
    'unhx' => ->(s) { W.unhx(s)&.to_s },
    'unhxArray' => ->(a, len) { W.unhx_array(a, int(len))&.map(&:to_s) },
    'netAbort' => ->(*a) { net_abort(a) },
    'abortKinds' => -> { W::ABORT_KINDS.sort },
    'pa' => ->(*a) { pa_op(a) },
    'aw' => ->(*a) { aw_op(a) },
    'forensics' => ->(*a) { forensics(a) },
    'codec' => ->(*a) { codec(a) }
  }.freeze

  def test_corpus_is_covered
    assert_equal CASES.keys.sort, MAP.keys.sort, 'unmapped corpus functions'
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}_matches_the_reference") { Ref.run(self, CASES[fn], MAP[fn]) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 349, CASES.values.sum(&:length), 'mpc-net'
  end

end
