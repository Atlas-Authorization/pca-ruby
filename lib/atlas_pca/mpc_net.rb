# frozen_string_literal: true

require 'base64'
require 'digest'
require_relative '../atlas_pca'
require_relative 'mpc_ec'

module AtlasPca
  module Mpc
    # The pure parts of the networked MPC runner: the length-prefixed JSON frame codec with strict envelope validation, the canonical
    # hex field-element encoding, and the structured abort (NetAbort) that blames a party only when the evidence names one
    # (NetWire); pairwise-authenticated shares (NetPa); forensic disclosures of a failed offline triple (NetForensics); and the
    # canonical encodings and gadget-seed agreement helpers (NetCodec). Sockets, TLS and the distributed protocol driver are not part
    # of this SDK.
    module NetWire
      WIRE_VERSION = 2 # a peer on another version is rejected as a version mismatch
      MAX_FRAME_BYTES = 4 * 1024 * 1024
      ABORT_KINDS = %w[timeout disconnect version malformed oversize duplicate out-of-order wrong-round wrong-session identity commitment ot-check
                       mac-check dealer equivocation flood peer-abort local].freeze
      FRAME_TYPES = %w[hello msg abort].freeze
      HEX61 = /\A(?:0|[1-9a-f][0-9a-f]{0,15})\z/

      # a protocol abort; blamed is nil when the evidence names no culprit (then reason explains why)
      class NetAbort < StandardError
        attr_reader :kind, :blamed, :reporter, :claimed_kind, :claimed_blame, :reason, :evidence, :deadline_ms

        def initialize(kind, blamed, reporter, detail, claimed_kind = nil, claimed_blame = nil, reason = nil, evidence = nil, deadline_ms = nil)
          super("[#{kind}] blamed=#{blamed.nil? ? 'none' : blamed} reporter=#{reporter}: #{detail}")
          @kind = kind
          @blamed = blamed
          @reporter = reporter
          @claimed_kind = claimed_kind
          @claimed_blame = claimed_blame
          @reason = if blamed.nil?
                      reason.nil? || reason.empty? ? 'unattributable: the evidence available to this party does not identify a culprit' : reason
                    end
          @evidence = evidence
          @deadline_ms = deadline_ms
        end
      end

      # a frame: {v, ty, sid, seq, rd, d}
      Frame = Struct.new(:v, :ty, :sid, :seq, :rd, :d)

      module_function

      # length-prefixed (4-byte big-endian) JSON frame; raises when the body exceeds MAX_FRAME_BYTES
      def encode_frame(f)
        f = Frame.new(*%w[v ty sid seq rd d].map { |k| f[k] }) if f.is_a?(Hash)
        body = Js.utf8(Js.json({ 'v' => f.v, 'ty' => f.ty, 'sid' => f.sid, 'seq' => f.seq, 'rd' => f.rd, 'd' => f.d }))
        raise ArgumentError, 'frame too large' if body.bytesize > MAX_FRAME_BYTES

        [body.bytesize].pack('N') + body
      end

      # reassembles length-prefixed frames from arbitrary chunking; an oversize length prefix raises
      class FrameSplitter
        def initialize = @data = ''.b

        def push(chunk)
          @data << chunk.b
          out = []
          off = 0
          loop do
            break if @data.bytesize - off < 4

            len = @data.byteslice(off, 4).unpack1('N')
            raise 'oversize' if len > MAX_FRAME_BYTES
            break if @data.bytesize - off < 4 + len

            out << @data.byteslice(off + 4, len)
            off += 4 + len
          end
          @data = @data.byteslice(off, @data.bytesize - off) if off.positive?
          out
        end
      end

      # ---- envelope validation ----

      # the JavaScript number value of a parsed JSON number (nil for anything else)
      def num(o) = o.is_a?(Numeric) ? o.to_f : nil

      def safe_int?(d) = !d.nil? && d.finite? && d == d.floor && d.abs <= 9_007_199_254_740_991.0
      def neg_zero?(d) = d.zero? && (1.0 / d).negative?

      def parse_object(body)
        text = body.b.force_encoding('UTF-8').scrub("�")
        j = Js.parse(text)
        j.is_a?(Hash) ? j : nil
      rescue StandardError
        nil
      end

      # the envelope version of a body, or nil when it is not a JSON object with a safe-integer v
      def peek_version(body)
        o = parse_object(body)
        return nil if o.nil?

        v = num(o['v'])
        safe_int?(v) && !neg_zero?(v) ? v.to_i : nil
      end

      def envelope_shape_ok?(o)
        return false if o.size != 6 || !o.key?('v')
        return false unless o['ty'].is_a?(String) && FRAME_TYPES.include?(o['ty'])
        return false unless o['sid'].is_a?(String) && o['rd'].is_a?(String)

        seq = num(o['seq'])
        return false if !safe_int?(seq) || seq.negative? || neg_zero?(seq)

        o.key?('d')
      end

      # the frame as a Hash when it is a well-formed envelope of the current version, else nil
      def parse_frame(body)
        o = parse_object(body)
        return nil if o.nil?

        v = num(o['v'])
        return nil if v.nil? || v != WIRE_VERSION || !envelope_shape_ok?(o)

        o
      end

      # the peer's version when the body is a well-formed envelope of a DIFFERENT version, else nil
      def version_mismatch(body)
        o = parse_object(body)
        return nil if o.nil?

        v = num(o['v'])
        return nil if v.nil? || !safe_int?(v) || neg_zero?(v) || v == WIRE_VERSION

        envelope_shape_ok?(o) ? v.to_i : nil
      end

      # ---- canonical field-element hex ----

      def hx(x) = x.to_s(16)

      # canonical lowercase hex without leading zeros of an element below the field prime; nil otherwise
      def unhx(s)
        return nil unless s.is_a?(String) && HEX61.match?(s)

        v = s.to_i(16)
        v < Field::PRIME ? v : nil
      end

      def unhx_array(a, len)
        return nil unless a.is_a?(Array) && a.length == len

        out = a.map { |x| unhx(x) }
        out.any?(&:nil?) ? nil : out
      end
    end

    # Pairwise-authenticated field shares for the identifiable-abort mode of the networked runner: each share carries one tag per
    # verifier and one key per peer, so a bad opening is attributable to the party that sent it. The operations are linear and local.
    module NetPa
      # x with tag[j] (my tag for verifier j) and key[j] (my key for verifying j's share)
      PA = Struct.new(:x, :tag, :key)
      # an authenticated value: a value share plus one MAC share per global key, each pairwise-authenticated
      AW = Struct.new(:v, :m)
      PaEnv = Struct.new(:id, :n, :delta, :tagged)

      module_function

      def zip(a, b, op) = a.each_index.map { |i| Field.public_send(op, a[i], b[i]) }

      def pa_add(a, b) = PA.new(Field.fadd(a.x, b.x), zip(a.tag, b.tag, :fadd), zip(a.key, b.key, :fadd))
      def pa_sub(a, b) = PA.new(Field.fsub(a.x, b.x), zip(a.tag, b.tag, :fsub), zip(a.key, b.key, :fsub))
      def pa_neg(a) = PA.new(Field.fneg(a.x), a.tag.map { |t| Field.fneg(t) }, a.key.map { |k| Field.fneg(k) })
      def pa_scale(a, c) = PA.new(Field.fmul(a.x, c), a.tag.map { |t| Field.fmul(t, c) }, a.key.map { |k| Field.fmul(k, c) })

      # adds a PUBLIC constant to party 0's share (every party applies the same call)
      def pa_add_public0(env, a, c)
        return PA.new(Field.fadd(a.x, c), a.tag, a.key) if env.id.zero?
        return a unless env.tagged

        key = a.key.dup
        key[0] = Field.fsub(key[0], Field.fmul(env.delta, c))
        PA.new(a.x, a.tag, key)
      end

      def w_add(a, b) = AW.new(pa_add(a.v, b.v), a.m.each_index.map { |l| pa_add(a.m[l], b.m[l]) })
      def w_sub(a, b) = AW.new(pa_sub(a.v, b.v), a.m.each_index.map { |l| pa_sub(a.m[l], b.m[l]) })
      def w_neg(a) = AW.new(pa_neg(a.v), a.m.map { |p| pa_neg(p) })
      def w_scale(a, c) = AW.new(pa_scale(a.v, c), a.m.map { |p| pa_scale(p, c) })

      # x + c for a PUBLIC c: party 0's value share moves by c and every MAC share moves by alpha_i * c
      def w_add_public(env, a, c, alpha)
        AW.new(pa_add_public0(env, a.v, c), a.m.each_index.map { |l| pa_add(a.m[l], pa_scale(alpha[l], c)) })
      end

      # verifies peer from's opened share x with tag against my key for that peer
      def pa_verify(env, a, from, x, tag) = Field.fadd(a.key[from], Field.fmul(env.delta, x)) == tag

      # ---- wire codec ----

      def pa_width(n, tagged) = tagged ? 1 + (2 * (n - 1)) : 1

      def pa_flat(a, id, n, tagged)
        out = [a.x]
        if tagged
          n.times { |j| out << a.tag[j] if j != id }
          n.times { |j| out << a.key[j] if j != id }
        end
        out
      end

      def pa_parse(nums, off, id, n, tagged)
        x = nums.fetch(off)
        return PA.new(x, [], []) unless tagged

        tag = Array.new(n, 0)
        key = Array.new(n, 0)
        o = off + 1
        n.times do |j|
          next if j == id

          tag[j] = nums.fetch(o)
          o += 1
        end
        n.times do |j|
          next if j == id

          key[j] = nums.fetch(o)
          o += 1
        end
        PA.new(x, tag, key)
      end

      def aw_width(n, keys, tagged) = (1 + keys) * pa_width(n, tagged)
      def aw_flat(a, id, n, tagged) = pa_flat(a.v, id, n, tagged) + a.m.flat_map { |p| pa_flat(p, id, n, tagged) }

      def aw_parse(nums, off, id, n, keys, tagged)
        w = pa_width(n, tagged)
        AW.new(pa_parse(nums, off, id, n, tagged), Array.new(keys) { |l| pa_parse(nums, off + ((1 + l) * w), id, n, tagged) })
      end
    end

    # Forensic disclosures of a failed offline triple: each party discloses its OT choice bits, operands, claimed product share and
    # the per-peer OT messages; the cross-check names the party whose own data are inconsistent or whose counterpart's transcript
    # disagrees. This module holds the pure parts (strict parsing, audit, blame, the commit-first binding).
    module NetForensics
      # one product item's disclosure; recv and rho are Hashes keyed by peer index (insertion ordered) of arrays of field elements
      SlotDisclosure = Struct.new(:bits, :y, :z, :recv, :rho)
      # self_bad: parties whose own disclosure is inconsistent; pair_bad: ordered [receiver, sender] pairs whose OT transcripts disagree
      AuditResult = Struct.new(:self_bad, :pair_bad)
      DEFAULT_FORENSIC_DEADLINE_MS = 30_000

      module_function

      def slots_for(partners) = 1 + partners

      def side(x) = x.map { |peer, vals| [peer, vals.map { |v| NetWire.hx(v) }] }

      # the wire (JSON) form of a disclosure
      def wire_disclosure(d)
        d.map do |s|
          { 'bits' => s.bits.join, 'y' => NetWire.hx(s.y), 'z' => NetWire.hx(s.z), 'recv' => side(s.recv), 'rho' => side(s.rho) }
        end
      end

      def field(s)
        v = NetWire.unhx(s)
        raise ArgumentError, 'bad field element' if v.nil?

        v
      end

      def js_int(o)
        return nil unless o.is_a?(Numeric)

        d = o.to_f
        d.finite? && d == d.floor && d.abs < 1e9 ? d.to_i : nil
      end

      # strict parse of a peer's disclosure; raises on any deviation from the expected shape
      def parse_disclosure(raw, slots, rows, peers)
        raise ArgumentError, 'bad forensic disclosure' unless raw.is_a?(Array) && raw.length == slots

        raw.map do |r|
          raise ArgumentError, 'bad choice bits' unless r.is_a?(Hash) && r['bits'].is_a?(String) && r['bits'].length == rows && r['bits'].match?(/\A[01]*\z/)

          bits = r['bits'].each_char.map { |c| c == '1' ? 1 : 0 }
          SlotDisclosure.new(bits, field(r['y']), field(r['z']), side_parse(r['recv'], rows, peers), side_parse(r['rho'], rows, peers))
        end
      end

      def side_parse(x, rows, peers)
        raise ArgumentError, 'bad peer table' unless x.is_a?(Array) && x.length == peers.length

        x.each_with_object({}) do |e, m|
          raise ArgumentError, 'bad peer entry' unless e.is_a?(Array) && e.length == 2 && e[0].is_a?(Numeric)

          p = js_int(e[0])
          raise ArgumentError, 'bad peer entry' if p.nil? || !peers.include?(p) || m.key?(p)

          vals = e[1]
          raise ArgumentError, 'bad row table' unless vals.is_a?(Array) && vals.length == rows

          m[p] = vals.map { |v| field(v) }
        end
      end

      # cross-checks every party's disclosure of one failed triple against the public gadget
      def audit_disclosures(all, gadget)
        self_bad = []
        pair_bad = []
        parties = all.keys.sort
        parties.each do |i|
          all[i].each_with_index do |sd, s|
            value = 0
            gadget.each_index { |k| value += gadget[k] if k < sd.bits.length && sd.bits[k] == 1 }
            implied = Field.fmul(Field.mod(value), sd.y)
            parties.each do |p|
              next if p == i

              sd.recv.fetch(p).each { |v| implied = Field.fadd(implied, Field.mod(v)) }
              sd.rho.fetch(p).each { |v| implied = Field.fsub(implied, v) }
            end
            self_bad << i if implied != sd.z
            parties.each do |p|
              next if p == i

              sp = all[p][s]
              rho = sp.rho.fetch(i)
              got = sd.recv.fetch(p)
              y = Field.mod(sp.y)
              bad = gadget.each_index.any? do |k|
                want = Field.fadd(rho[k], k < sd.bits.length && sd.bits[k] == 1 ? Field.fmul(gadget[k], y) : 0)
                Field.mod(got[k]) != want
              end
              pair_bad << [i, p] if bad
            end
          end
        end
        AuditResult.new(self_bad.uniq, pair_bad)
      end

      # the party the verifier me blames, or nil when the evidence cannot name one
      def blame_from(me, r)
        own = r.self_bad.reject { |p| p == me }.min
        return own unless own.nil?

        r.pair_bad.each do |pr|
          return pr[1] if pr[0] == me
          return pr[0] if pr[1] == me
        end
        nil
      end

      # binding commitment to a disclosure: session, party, triple index, deadline, a 256-bit nonce and the canonical wire form
      def disclosure_commit(session_id, party, triple_index, deadline_ms, nonce, wire)
        text = Js.utf8(Js.json([session_id, party, triple_index, deadline_ms, nonce, wire]))
        Digest::SHA256.hexdigest("atlas-pca-mpc/forensic-commit/v1\0".b + text)
      end
    end

    # Canonical encodings of the OT-over-network messages (one accepted string per value) and the gadget-seed agreement helpers:
    # strict base64, minimal lowercase hex field elements, subgroup-validated points, and the commitment / signed statement of the
    # gadget seed exchange.
    module NetCodec
      B64RE = %r{\A[A-Za-z0-9+/]*={0,2}\z}
      HEX255 = /\A(?:0|[1-9a-f][0-9a-f]{0,63})\z/

      module_function

      def b64(u) = [u.b].pack('m0')

      # strict base64: re-encoding must reproduce the input (no trailing-bit or padding aliases); len < 0 (or nil) means any length
      def unb64(s, len = nil)
        raise ArgumentError, 'bad base64' unless s.is_a?(String) && B64RE.match?(s)

        b = begin
          s.unpack1('m0')
        rescue ArgumentError
          raise ArgumentError, 'bad base64'
        end
        raise ArgumentError, 'non-canonical base64' unless b64(b) == s
        raise ArgumentError, 'bad length' if !len.nil? && len >= 0 && b.bytesize != len

        b
      end

      def pt_j(p)
        x, y = Ec.to_affine(p)
        { 'x' => NetWire.hx(x), 'y' => NetWire.hx(y) }
      end

      # canonical lowercase hex without leading zeros of an element below the curve field prime
      def hex_big(s)
        raise ArgumentError, 'bad field element' unless s.is_a?(String) && HEX255.match?(s)

        v = s.to_i(16)
        raise ArgumentError, 'non-canonical field element' if v >= Ec::Q

        v
      end

      # a point from {x, y} canonical hex, validated to be a non-identity prime-order-subgroup point
      def j_pt(v)
        raise ArgumentError, 'bad point' unless v.is_a?(Hash)

        x = hex_big(v['x'])
        y = hex_big(v['y'])
        p = Ec::Point.new(x, y, 1, (x * y) % Ec::Q)
        Ec.assert_in_subgroup(p, 'received point')
        p
      end

      def sharings_per_triple(partners) = 3 + (2 * partners)

      # commitment to a party's gadget seed: SHA-256(tag, session, decimal party, seed) as hex
      def gadget_commit(session_id, party, seed)
        Digest::SHA256.hexdigest('atlas-pca-mpc/gadget-commit'.b + Js.utf8(session_id) + party.to_s.b + seed.b)
      end

      # the exact bytes a party signs in the gadget seed exchange (round is "gd-c" or "gd-o")
      def gadget_statement(session_id, round, signer, value)
        Js.utf8(Js.json(['atlas-pca-mpc/gadget-sig/v1', session_id, round, signer, value]))
      end
    end
  end
end
