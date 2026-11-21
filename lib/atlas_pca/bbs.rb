# frozen_string_literal: true

require 'securerandom'
require_relative 'bls12'

module AtlasPca
  # BBS signatures over BLS12-381, ciphersuite BLS12-381-SHA-256 (BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_), faithful to
  # draft-irtf-cfrg-bbs-signatures (core protocol and octet encodings). Signatures and generators live in G1 (48 bytes compressed),
  # public keys in G2 (96 bytes), scalars are 32 bytes big-endian. All curve work is blst's (through ffi, see Bls12); the scalar
  # field is Integer arithmetic. Byte inputs are Strings (read as bytes), scalars are Integers.
  module Bbs
    MAX_MESSAGES = 1024 # a verifier derives the message count from attacker-supplied lengths
    R = Bls12::R
    CIPHERSUITE_ID = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_'
    API_ID = "#{CIPHERSUITE_ID}H2G_HM2S_"
    SCALAR_LEN = 32
    POINT_LEN = 48
    EXPAND_LEN = 48
    H2S_DST = "#{API_ID}H2S_"
    MAP_DST = "#{API_ID}MAP_MSG_TO_SCALAR_AS_HASH_"
    SEED_DST = "#{API_ID}SIG_GENERATOR_SEED_"
    GEN_DST = "#{API_ID}SIG_GENERATOR_DST_"
    GEN_SEED = "#{API_ID}MESSAGE_GENERATOR_SEED"
    KEYGEN_DST = "#{API_ID}KEYGEN_DST_"
    # P1: the fixed G1 generator of the ciphersuite (draft 7.2.2)
    P1_HEX = 'a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9'

    MALFORMED_SIGNATURE = 'malformed-signature'
    MALFORMED_PUBLIC_KEY = 'malformed-public-key'
    MALFORMED_PROOF = 'malformed-proof'
    DISCLOSED_LENGTH_MISMATCH = 'disclosed-length-mismatch'
    INVALID_DISCLOSED_INDEXES = 'invalid-disclosed-indexes'
    PAIRING_MISMATCH = 'pairing-mismatch'
    CHALLENGE_MISMATCH = 'challenge-mismatch'

    # A verification result: ok, or the stable machine-readable reason.
    Result = Struct.new(:ok, :reason) do
      def ok? = ok
      def to_h = ok ? { 'ok' => true } : { 'ok' => false, 'reason' => reason }
    end
    OK = Result.new(true, nil).freeze

    ParsedSignature = Struct.new(:a, :e)
    ParsedProof = Struct.new(:abar, :bbar, :d, :e_hat, :r1_hat, :r3_hat, :m_hat, :c)

    module_function

    def p1_gen = (@p1_gen ||= Bls12::G1.decode([P1_HEX].pack('H*')))
    def bp2 = (@bp2 ||= Bls12::G2.generator)

    def bytes_arg(v, what)
      raise ArgumentError, "bbs: #{what} must be bytes" unless v.is_a?(String)

      v.b
    end

    def i2osp(n, len) = Bls12.i2osp(n, len)
    def expand(msg, dst, len) = Bls12.expand_message_xmd(msg, dst, len)

    # hash_to_scalar(msg, dst) = OS2IP(expand_message_xmd(msg, dst, 48)) mod r (draft 4.2.2)
    def hash_to_scalar(msg, dst) = Bls12.os2ip(expand(bytes_arg(msg, 'message'), dst, EXPAND_LEN)) % R

    # MapMessageToScalarAsHash: one message octet string to one scalar (draft 4.2)
    def map_message_to_scalar_as_hash(message) = hash_to_scalar(message, MAP_DST)

    def messages_to_scalars(messages) = messages.map { |m| map_message_to_scalar_as_hash(m) }

    def gens(count)
      raise ArgumentError, 'bbs: generator count must be a non-negative integer' unless count.is_a?(Integer) && count >= 0
      raise ArgumentError, "bbs: at most #{MAX_MESSAGES} messages are supported" if count > MAX_MESSAGES + 1

      v = expand(GEN_SEED, SEED_DST, EXPAND_LEN)
      (1..count).map do |i|
        v = expand(v + i2osp(i, 8), SEED_DST, EXPAND_LEN)
        Bls12::G1.hash_to(v, GEN_DST)
      end
    end

    # create_generators(count): the compressed generator sequence (Q_1, H_1, ..., H_{count-1}) (draft 4.1)
    def create_generators(count) = gens(count).map(&:compress)

    # ---- key generation ----

    # KeyGen (draft 3.4.1): at least 32 octets of key material. Never returns 0.
    def key_gen(key_material, key_info = ''.b)
      km = bytes_arg(key_material, 'key material')
      ki = bytes_arg(key_info, 'key info')
      raise ArgumentError, 'bbs: key material must be at least 32 octets' if km.bytesize < 32
      raise ArgumentError, 'bbs: key info must be at most 65535 octets' if ki.bytesize > 65_535

      sk = hash_to_scalar(km + i2osp(ki.bytesize, 2) + ki, KEYGEN_DST)
      raise 'bbs: derived SK is zero (retry with different key material)' if sk.zero?

      sk
    end

    # SkToPk: the 96-byte public key SK * BP2 (draft 3.4.2)
    def sk_to_pk(sk) = (bp2 * sk).compress

    # A fresh { sk:, pk: } from the system CSPRNG; refuses an all-zero entropy source.
    def generate_key_pair
      ikm = SecureRandom.random_bytes(32)
      raise 'bbs: entropy source returned all zeros (RNG failure); refusing to generate a key' if ikm.bytes.all?(&:zero?)

      sk = key_gen(ikm)
      { sk: sk, pk: sk_to_pk(sk) }
    end

    def sk_to_bytes(sk) = i2osp(sk, SCALAR_LEN)

    def sk_from_bytes(bytes)
      raise ArgumentError, 'bbs: SK must be 32 octets' unless bytes.is_a?(String) && bytes.bytesize == SCALAR_LEN

      sk = Bls12.os2ip(bytes)
      raise ArgumentError, 'bbs: SK out of range' if sk.zero? || sk >= R

      sk
    end

    # ---- serialization (draft 4.2.4): points compressed, [:s, n] scalars 32 octets, [:i, n] integers 8 octets ----

    def serialize(els)
      els.map do |el|
        case el
        when Bls12::Point then el.compress
        when Array then el[0] == :s ? i2osp(el[1], SCALAR_LEN) : i2osp(el[1], 8)
        else raise ArgumentError, 'bbs: cannot serialize'
        end
      end.join.b
    end

    # ---- signature octets ----

    def signature_to_octets(a, e) = a.compress + i2osp(e, SCALAR_LEN)

    def octets_to_signature(sig)
      raise ArgumentError, 'bbs: signature must be 80 octets' unless sig.is_a?(String) && sig.bytesize == POINT_LEN + SCALAR_LEN

      s = sig.b
      a = Bls12::G1.decode(s.byteslice(0, POINT_LEN))
      raise ArgumentError, 'bbs: signature point A is the identity' if a.inf?

      e = Bls12.os2ip(s.byteslice(POINT_LEN, SCALAR_LEN))
      raise ArgumentError, 'bbs: signature scalar e out of range' if e <= 0 || e >= R

      ParsedSignature.new(a, e)
    end

    # ---- domain (draft 4.2.3) ----

    def calculate_domain(pk, q1, h, header)
      dom_octs = serialize([[:i, h.length], q1, *h]) + API_ID.b
      hash_to_scalar(pk + dom_octs + i2osp(header.bytesize, 8) + header, H2S_DST)
    end

    # B = P1 + Q_1*domain + sum H_i*msg_i
    def compute_b(q1, h, domain, scalars)
      b = p1_gen + (q1 * domain)
      scalars.each_with_index { |m, i| b += h[i] * m }
      b
    end

    # ---- Sign / Verify ----

    # Sign(SK, PK, header, messages): an 80-octet BBS signature over the ordered message vector.
    def sign(sk, pk, header, messages)
      raise ArgumentError, 'bbs: SK out of range' unless sk.is_a?(Integer) && sk.positive? && sk < R

      pk = bytes_arg(pk, 'public key')
      header = bytes_arg(header, 'header')
      ms = messages_to_scalars(messages)
      g = gens(ms.length + 1)
      q1 = g[0]
      h = g[1..]
      domain = calculate_domain(pk, q1, h, header)
      e = hash_to_scalar(serialize([[:s, sk], *ms.map { |m| [:s, m] }, [:s, domain]]), H2S_DST)
      b = compute_b(q1, h, domain, ms)
      signature_to_octets(b * Bls12.inv(sk + e), e)
    end

    # a decoded public key: strict G2, not the identity; nil when malformed
    def decode_pk(pk)
      w = Bls12::G2.decode(pk)
      w.inf? ? nil : w
    rescue ArgumentError
      nil
    end

    # Verify(PK, signature, header, messages) with a rejection reason; fails closed on any malformed input.
    def verify_detailed(pk, signature, header, messages)
      begin
        parsed = octets_to_signature(signature)
      rescue ArgumentError
        return Result.new(false, MALFORMED_SIGNATURE)
      end
      w = decode_pk(pk)
      return Result.new(false, MALFORMED_PUBLIC_KEY) if w.nil?
      return Result.new(false, DISCLOSED_LENGTH_MISMATCH) if messages.length > MAX_MESSAGES

      pk = pk.b
      header = bytes_arg(header, 'header')
      ms = messages_to_scalars(messages)
      g = gens(ms.length + 1)
      q1 = g[0]
      h = g[1..]
      domain = calculate_domain(pk, q1, h, header)
      b = compute_b(q1, h, domain, ms)
      # e(A, W + BP2*e) == e(B, BP2)
      Bls12.pairing_eq(parsed.a, w + (bp2 * parsed.e), b, bp2) ? OK : Result.new(false, PAIRING_MISMATCH)
    end

    def verify(pk, signature, header, messages) = verify_detailed(pk, signature, header, messages).ok

    # ---- challenge (draft 3.7.4) ----

    def calculate_challenge(abar, bbar, d, t1, t2, idx, msgs, domain, ph)
      els = [[:i, idx.length]]
      idx.each_with_index { |ix, k| els << [:i, ix] << [:s, msgs[k]] }
      els.push(abar, bbar, d, t1, t2, [:s, domain])
      hash_to_scalar(serialize(els) + i2osp(ph.bytesize, 8) + ph, H2S_DST)
    end

    # ---- proof octets ----

    def proof_to_octets(p)
      [p.abar.compress, p.bbar.compress, p.d.compress, i2osp(p.e_hat, SCALAR_LEN), i2osp(p.r1_hat, SCALAR_LEN),
       i2osp(p.r3_hat, SCALAR_LEN), *p.m_hat.map { |m| i2osp(m, SCALAR_LEN) }, i2osp(p.c, SCALAR_LEN)].join.b
    end

    def read_scalar(proof, offset)
      v = Bls12.os2ip(proof.byteslice(offset, SCALAR_LEN))
      raise ArgumentError, 'bbs: proof scalar out of range' if v >= R

      v
    end

    def octets_to_proof(proof)
      raise ArgumentError, 'bbs: malformed proof' unless proof.is_a?(String)

      pr = proof.b
      fixed = (3 * POINT_LEN) + (4 * SCALAR_LEN)
      raise ArgumentError, 'bbs: malformed proof length' if pr.bytesize < fixed || ((pr.bytesize - fixed) % SCALAR_LEN) != 0

      abar = Bls12::G1.decode(pr.byteslice(0, POINT_LEN))
      bbar = Bls12::G1.decode(pr.byteslice(POINT_LEN, POINT_LEN))
      d = Bls12::G1.decode(pr.byteslice(2 * POINT_LEN, POINT_LEN))
      o = 3 * POINT_LEN
      e_hat = read_scalar(pr, o)
      r1_hat = read_scalar(pr, o + SCALAR_LEN)
      r3_hat = read_scalar(pr, o + (2 * SCALAR_LEN))
      o += 3 * SCALAR_LEN
      u = (pr.bytesize - fixed) / SCALAR_LEN
      m_hat = (0...u).map { |i| read_scalar(pr, o + (i * SCALAR_LEN)) }
      c = read_scalar(pr, o + (u * SCALAR_LEN))
      raise ArgumentError, 'bbs: proof contains the identity point' if abar.inf? || bbar.inf? || d.inf?

      ParsedProof.new(abar, bbar, d, e_hat, r1_hat, r3_hat, m_hat, c)
    end

    # ---- index-set helpers ----

    def validate_indexes(indexes, l)
      seen = {}
      indexes.each do |i|
        raise ArgumentError, "bbs: disclosed index #{i.inspect} out of range [0, #{l})" unless i.is_a?(Integer) && i >= 0 && i < l
        raise ArgumentError, "bbs: duplicate disclosed index #{i}" if seen.key?(i)

        seen[i] = true
      end
    end

    def undisclosed_ascending(disclosed, l) = (0...l).reject { |i| disclosed.include?(i) }

    # ---- ProofGen ----

    # ProofGen(PK, signature, header, ph, messages, disclosed_indexes): a zero-knowledge proof of knowledge of the signature that
    # discloses the messages at the given indexes. fixed_random_scalars (5 + undisclosed count scalars) pins the randomness for test
    # vectors ONLY; reusing it across proofs breaks zero-knowledge and unlinkability.
    def proof_gen(pk, signature, header, ph, messages, disclosed_indexes, fixed_random_scalars = nil)
      pk = bytes_arg(pk, 'public key')
      header = bytes_arg(header, 'header')
      ph = bytes_arg(ph, 'presentation header')
      sig = octets_to_signature(signature)
      a = sig.a
      e = sig.e
      ms = messages_to_scalars(messages)
      l = ms.length
      validate_indexes(disclosed_indexes, l)
      disclosed = disclosed_indexes.uniq.sort
      undisclosed = undisclosed_ascending(disclosed, l)
      u = undisclosed.length

      g = gens(l + 1)
      q1 = g[0]
      h = g[1..]
      domain = calculate_domain(pk, q1, h, header)
      b = compute_b(q1, h, domain, ms)

      rs = fixed_random_scalars ? fixed_random_scalars.dup : Array.new(5 + u) { Bls12.os2ip(SecureRandom.random_bytes(EXPAND_LEN)) % R }
      raise ArgumentError, "bbs: expected #{5 + u} random scalars, got #{rs.length}" unless rs.length == 5 + u
      raise ArgumentError, 'bbs: random blinding scalars r1, r2 must be non-zero (RNG failure?)' if rs[0].zero? || rs[1].zero?

      r1, r2, e_tilde, r1_tilde, r3_tilde = rs[0, 5]
      m_tilde = rs[5..]

      d = b * r2
      abar = a * Bls12.mul(r1, r2)
      bbar = (d * r1) - (abar * e)
      t1 = (abar * e_tilde) + (d * r1_tilde)
      t2 = d * r3_tilde
      undisclosed.each_with_index { |ix, k| t2 += h[ix] * m_tilde[k] }

      c = calculate_challenge(abar, bbar, d, t1, t2, disclosed, disclosed.map { |i| ms[i] }, domain, ph)

      r3 = Bls12.inv(r2)
      e_hat = Bls12.add(e_tilde, Bls12.mul(e, c))
      r1_hat = Bls12.sub(r1_tilde, Bls12.mul(r1, c))
      r3_hat = Bls12.sub(r3_tilde, Bls12.mul(r3, c))
      m_hat = undisclosed.each_with_index.map { |ix, k| Bls12.add(m_tilde[k], Bls12.mul(ms[ix], c)) }
      proof_to_octets(ParsedProof.new(abar, bbar, d, e_hat, r1_hat, r3_hat, m_hat, c))
    end

    # ---- ProofVerify ----

    # ProofVerify with a rejection reason. disclosed_messages[k] corresponds to disclosed_indexes[k].
    def proof_verify_detailed(pk, proof, header, ph, disclosed_messages, disclosed_indexes)
      begin
        p = octets_to_proof(proof)
      rescue ArgumentError
        return Result.new(false, MALFORMED_PROOF)
      end
      w = decode_pk(pk)
      return Result.new(false, MALFORMED_PUBLIC_KEY) if w.nil?
      return Result.new(false, DISCLOSED_LENGTH_MISMATCH) if disclosed_messages.length != disclosed_indexes.length

      pk = pk.b
      header = bytes_arg(header, 'header')
      ph = bytes_arg(ph, 'presentation header')
      u = p.m_hat.length
      l = disclosed_indexes.length + u
      return Result.new(false, MALFORMED_PROOF) if l > MAX_MESSAGES

      begin
        validate_indexes(disclosed_indexes, l)
        scalars = messages_to_scalars(disclosed_messages)
      rescue ArgumentError
        return Result.new(false, INVALID_DISCLOSED_INDEXES)
      end
      order = disclosed_indexes.each_with_index.sort_by { |ix, k| [ix, k] }
      undisclosed = undisclosed_ascending(disclosed_indexes, l)

      g = gens(l + 1)
      q1 = g[0]
      h = g[1..]
      domain = calculate_domain(pk, q1, h, header)

      t1 = (p.bbar * p.c) + (p.abar * p.e_hat) + (p.d * p.r1_hat)
      bv = p1_gen + (q1 * domain)
      sorted_idx = []
      sorted_msgs = []
      order.each do |ix, k|
        sorted_idx << ix
        sorted_msgs << scalars[k]
        bv += h[ix] * scalars[k]
      end
      t2 = (bv * p.c) + (p.d * p.r3_hat)
      undisclosed.each_with_index { |ix, k| t2 += h[ix] * p.m_hat[k] }

      cv = calculate_challenge(p.abar, p.bbar, p.d, t1, t2, sorted_idx, sorted_msgs, domain, ph)
      return Result.new(false, CHALLENGE_MISMATCH) unless cv == p.c

      Bls12.pairing_eq(p.abar, w, p.bbar, bp2) ? OK : Result.new(false, PAIRING_MISMATCH)
    end

    def proof_verify(pk, proof, header, ph, disclosed_messages, disclosed_indexes)
      proof_verify_detailed(pk, proof, header, ph, disclosed_messages, disclosed_indexes).ok
    end
  end
end
