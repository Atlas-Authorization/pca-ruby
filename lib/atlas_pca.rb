# frozen_string_literal: true

# Reference verifier for the CORE PCActn checks (wire format v2): strict wire form, freshness binding,
# capability chain, Merkle plan inclusion, strict RFC 8032 Ed25519 leaf signature, counter.
# Stdlib only (OpenSSL >= 3 for the raw Ed25519 equation; torsion / small-order / canonicality are checked here).
# Normative spec: packages/pca/conformance/README.md.
require 'digest'
require 'base64'
require 'openssl'

module AtlasPca
  SIG_DOMAIN = "atlas-pca/actn/v2\x00".b.freeze
  CAP_DOMAIN = "atlas-pca/cap/v1\x00".b.freeze
  DEFAULT_REV = 'reversible'

  MAX_CHAIN_HOPS = 16
  MAX_JSON_DEPTH = 32
  MAX_JSON_CHARS = 1 << 20 # UTF-8 BYTES
  MAX_DECIMAL_DIGITS = 15
  MAX_LIFETIME_MS = 3_600_000
  MAX_SKEW_MS = 60_000
  MAX_SAFE = (2**53) - 1
  CHECK_ORDER = %w[wire version audience validity chain plan_inclusion leaf_signature counter].freeze

  class Malformed < StandardError; end

  Verdict = Struct.new(:allow, :checks, :reason)

  module_function

  # ======================= strict JSON profile =======================
  # Hand-written RFC 8259 parser. Rejects: comments, trailing commas, BOM, non-(SP/TAB/LF/CR) whitespace,
  # duplicate keys (after unescaping), lone surrogates, raw control chars, unknown escapes, depth > 32,
  # input > 2^20 chars, non-canonical numbers. Result must be an object.
  # `loose: true` is ONLY for reading the conformance file itself (it holds deliberately-bad values as
  # already-parsed objects): lone-surrogate escapes become invalid-encoding strings, numbers keep any
  # lexeme (Integer or Float), and depth/length caps are off. Verification re-validates every value anyway.
  class JsonParser
    WS = [0x20, 0x09, 0x0a, 0x0d].freeze
    NUM = /\A-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/n

    def initialize(text, loose, any_top)
      @loose = loose
      @any_top = any_top
      raise Malformed, 'not a string' unless text.is_a?(String)

      t = text.dup.force_encoding('UTF-8')
      raise Malformed, 'invalid UTF-8' unless t.valid_encoding?
      raise Malformed, 'input too long' if !loose && t.bytesize > MAX_JSON_CHARS

      @s = t.b
      @i = 0
    end

    def parse_document
      skip_ws
      raise Malformed, 'document must be an object' unless @any_top || @s.getbyte(@i) == 0x7b

      v = parse_value(1)
      skip_ws
      raise Malformed, 'trailing garbage' if @i != @s.bytesize

      v
    end

    private

    def skip_ws
      @i += 1 while WS.include?(@s.getbyte(@i))
    end

    def parse_value(depth)
      skip_ws
      c = @s.getbyte(@i)
      raise Malformed, 'unexpected end' if c.nil?

      case c
      when 0x7b then parse_object(depth)
      when 0x5b then parse_array(depth)
      when 0x22 then parse_string
      when 0x74 then literal('true', true)
      when 0x66 then literal('false', false)
      when 0x6e then literal('null', nil)
      else parse_number
      end
    end

    def literal(word, val)
      raise Malformed, 'bad literal' unless @s.byteslice(@i, word.bytesize) == word.b

      @i += word.bytesize
      val
    end

    def check_depth(depth)
      raise Malformed, 'nesting too deep' if !@loose && depth > MAX_JSON_DEPTH
    end

    def parse_object(depth)
      check_depth(depth)
      @i += 1
      h = {}
      skip_ws
      if @s.getbyte(@i) == 0x7d
        @i += 1
        return h
      end
      loop do
        skip_ws
        raise Malformed, 'expected string key' unless @s.getbyte(@i) == 0x22

        k = parse_string
        raise Malformed, 'duplicate key' if h.key?(k)

        skip_ws
        raise Malformed, 'expected colon' unless @s.getbyte(@i) == 0x3a

        @i += 1
        h[k] = parse_value(depth + 1)
        skip_ws
        c = @s.getbyte(@i)
        @i += 1
        return h if c == 0x7d
        raise Malformed, 'expected , or }' unless c == 0x2c
      end
    end

    def parse_array(depth)
      check_depth(depth)
      @i += 1
      a = []
      skip_ws
      if @s.getbyte(@i) == 0x5d
        @i += 1
        return a
      end
      loop do
        a << parse_value(depth + 1)
        skip_ws
        c = @s.getbyte(@i)
        @i += 1
        return a if c == 0x5d
        raise Malformed, 'expected , or ]' unless c == 0x2c
      end
    end

    def hex4
      h = @s.byteslice(@i, 4)
      raise Malformed, 'bad \\u escape' unless h && h.bytesize == 4 && h.match?(/\A[0-9a-fA-F]{4}\z/n)

      @i += 4
      h.to_i(16)
    end

    def parse_string
      @i += 1
      out = String.new(encoding: Encoding::BINARY)
      loop do
        c = @s.getbyte(@i)
        raise Malformed, 'unterminated string' if c.nil?

        if c == 0x22
          @i += 1
          return out.force_encoding('UTF-8')
        elsif c < 0x20
          raise Malformed, 'raw control character in string'
        elsif c == 0x5c
          @i += 1
          e = @s.getbyte(@i)
          @i += 1
          case e
          when 0x22 then out << '"'
          when 0x5c then out << '\\'
          when 0x2f then out << '/'
          when 0x62 then out << "\b"
          when 0x66 then out << "\f"
          when 0x6e then out << "\n"
          when 0x72 then out << "\r"
          when 0x74 then out << "\t"
          when 0x75 then unicode_escape(out)
          else raise Malformed, 'unknown escape'
          end
        else
          out << c.chr
          @i += 1
        end
      end
    end

    def unicode_escape(out)
      u = hex4
      if (0xd800..0xdbff).cover?(u)
        if @s.byteslice(@i, 2) == '\\u'.b
          @i += 2
          lo = hex4
          if (0xdc00..0xdfff).cover?(lo)
            out << [0x10000 + ((u - 0xd800) << 10) + (lo - 0xdc00)].pack('U').b
            return
          end
        end
        lone_surrogate!(out, u)
      elsif (0xdc00..0xdfff).cover?(u)
        lone_surrogate!(out, u)
      else
        out << [u].pack('U').b
      end
    end

    def lone_surrogate!(out, unit)
      raise Malformed, 'lone surrogate' unless @loose

      # WTF-8 bytes: deliberately an INVALID UTF-8 string, so verification rejects it at the wire.
      out << [0xe0 | (unit >> 12), 0x80 | ((unit >> 6) & 0x3f), 0x80 | (unit & 0x3f)].pack('C*')
    end

    def parse_number
      m = NUM.match(@s.byteslice(@i, 64 * 1024) || ''.b)
      raise Malformed, 'bad value' if m.nil?

      lex = m[0].dup.force_encoding('UTF-8')
      @i += lex.bytesize
      return loose_number(lex) if @loose

      AtlasPca.strict_number_lexeme(lex)
    end

    def loose_number(lex)
      lex.match?(/[.eE]/) ? Float(lex) : lex.to_i
    end
  end

  # Canonical-form number lexeme (README section 3). Returns Integer or Float.
  def strict_number_lexeme(lex)
    raise Malformed, 'exponent not allowed' if lex.match?(/[eE]/)

    if lex.match?(/\A-?[0-9]+\z/)
      raise Malformed, '-0 rejected' if lex == '-0'

      n = lex.to_i
      raise Malformed, 'unsafe integer' if n.abs > MAX_SAFE

      return n
    end
    raise Malformed, 'trailing fractional zero' if lex.end_with?('0')

    digits = lex.delete('-.').sub(/\A0+/, '')
    raise Malformed, 'too many significant digits' if digits.length > MAX_DECIMAL_DIGITS
    raise Malformed, 'magnitude below 1e-6' if lex.delete('-').to_r < Rational(1, 1_000_000)

    Float(lex)
  end

  # any_top: allow a non-object top-level value (only for the json_parse primitive table; PCActn bodies are objects)
  def parse_json(text, loose: false, any_top: false)
    JsonParser.new(text, loose, any_top).parse_document
  end

  # Value-level number rule for already-parsed objects (and a second line of defence after parsing).
  def number_ok?(n)
    if n.is_a?(Integer)
      n.abs <= MAX_SAFE
    elsif n.is_a?(Float)
      return false if n.nan? || n.infinite? || n == 0 || n == n.floor || n.abs < 1e-6

      plain = fmt_float(n)
      plain.delete('-.').sub(/\A0+/, '').length <= MAX_DECIMAL_DIGITS
    else
      false
    end
  end

  # Whole-object structural validation: depth, numbers, string encodings, key/value types.
  def tree_ok?(v, depth = 1)
    case v
    when nil, true, false then true
    when String then v.encoding == Encoding::UTF_8 && v.valid_encoding?
    when Integer, Float then number_ok?(v)
    when Array then depth <= MAX_JSON_DEPTH && v.all? { |x| tree_ok?(x, depth + 1) }
    when Hash then depth <= MAX_JSON_DEPTH && v.all? { |k, x| tree_ok?(k, 0) && tree_ok?(x, depth + 1) }
    else false
    end
  end

  # ======================= base64url (strict) =======================
  def b64e(bin)
    Base64.urlsafe_encode64(bin, padding: false)
  end

  # Strict RFC 4648 s5: no padding, alphabet only, len % 4 != 1, zero trailing bits (re-encode must match).
  def b64d(str, len = nil)
    return nil unless str.is_a?(String) && str.valid_encoding?
    return nil unless str.match?(/\A[A-Za-z0-9_-]*\z/) && (str.length % 4) != 1

    bin = Base64.urlsafe_decode64(str)
    return nil unless b64e(bin) == str
    return nil if len && bin.bytesize != len

    bin
  rescue ArgumentError
    nil
  end

  # ======================= canonicalization =======================
  def js_string(s)
    raise Malformed, 'invalid string encoding' unless s.valid_encoding?

    out = +'"'
    s.each_char do |c|
      o = c.ord
      out << case c
             when '"' then '\\"'
             when '\\' then '\\\\'
             when "\b" then '\\b'
             when "\f" then '\\f'
             when "\n" then '\\n'
             when "\r" then '\\r'
             when "\t" then '\\t'
             else o < 0x20 ? format('\\u%04x', o) : c
             end
    end
    out << '"'
  end

  def fmt_number(n)
    raise Malformed, 'number outside the canonical form' unless number_ok?(n)

    n.is_a?(Integer) ? n.to_s : fmt_float(n)
  end

  def fmt_float(f)
    return '0' if f == 0

    s = f.to_s
    return s.sub(/\.0\z/, '') unless s.include?('e')

    BigDecimalLike.plain(f)
  end

  # Plain-decimal rendering of a shortest-roundtrip float given in exponent form.
  module BigDecimalLike
    module_function

    def plain(f)
      m, e = f.to_s.split('e')
      sign = m.start_with?('-') ? '-' : ''
      m = m.delete('-')
      int, frac = m.split('.')
      frac ||= ''
      digits = int + frac
      point = int.length + e.to_i
      r = if point <= 0
            "#{sign}0.#{'0' * -point}#{digits}"
          elsif point >= digits.length
            "#{sign}#{digits}#{'0' * (point - digits.length)}"
          else
            "#{sign}#{digits[0, point]}.#{digits[point..]}"
          end
      r.include?('.') ? r.sub(/0+\z/, '').sub(/\.\z/, '') : r
    end
  end

  def ser(v, out)
    case v
    when nil then out << 'null'
    when true then out << 'true'
    when false then out << 'false'
    when String then out << js_string(v)
    when Integer, Float then out << fmt_number(v)
    when Array
      out << '['
      v.each_with_index do |x, i|
        out << ',' if i > 0
        ser(x, out)
      end
      out << ']'
    when Hash
      # Keys sorted BYTEWISE over UTF-8 (== code point order), not UTF-16 code units.
      keys = v.keys.sort_by { |k| k.to_s.b }
      out << '{'
      keys.each_with_index do |k, i|
        out << ',' if i > 0
        out << js_string(k.to_s) << ':'
        ser(v[k], out)
      end
      out << '}'
    else
      raise Malformed, "unsupported type #{v.class}"
    end
    out
  end

  def canonicalize(v)
    ser(v, +'')
  end

  def sha(bin)
    Digest::SHA256.digest(bin)
  end

  def canon_bytes(v)
    canonicalize(v).dup.force_encoding('UTF-8').b
  end

  def hash_canonical(v)
    b64e(sha(canon_bytes(v)))
  end

  # ======================= Merkle (RFC 6962) =======================
  def leaf_hash(leaf)
    sha("\x00".b + canon_bytes(leaf))
  end

  def node_hash(l, r)
    sha("\x01".b + l + r)
  end

  def split_point(n)
    k = 1
    k *= 2 while k * 2 < n
    k
  end

  def build(hs)
    return hs[0] if hs.length == 1

    k = split_point(hs.length)
    node_hash(build(hs[0, k]), build(hs[k..]))
  end

  def merkle_root(leaves)
    raise Malformed, 'empty leaf set' if leaves.empty?

    b64e(build(leaves.map { |l| leaf_hash(l) }))
  end

  # Expected sides (leaf -> root) of the RFC 6962 audit path for leaf `m` in a tree of `n` leaves.
  def path_shape(m, n)
    return [] if n == 1

    k = split_point(n)
    m < k ? path_shape(m, k) + ['R'] : path_shape(m - k, n - k) + ['L']
  end

  def safe_int?(x)
    x.is_a?(Integer) && x.abs <= MAX_SAFE
  end

  # index/size are BOUND to the path shape: size >= 1, 0 <= index < size, every side recomputed.
  def verify_inclusion(root, proof, leaf)
    return false unless proof.is_a?(Hash) && proof['path'].is_a?(Array)

    idx = proof['index']
    size = proof['size']
    return false unless safe_int?(idx) && safe_int?(size) && size >= 1 && idx >= 0 && idx < size

    shape = path_shape(idx, size)
    path = proof['path']
    return false unless path.length == shape.length

    h = leaf_hash(leaf)
    path.each_with_index do |step, i|
      return false unless step.is_a?(Hash)

      side = step['side']
      return false unless side == shape[i]

      sib = b64d(step['hash'], 32)
      return false if sib.nil?

      h = side == 'L' ? node_hash(sib, h) : node_hash(h, sib)
    end
    b64e(h) == root
  rescue StandardError
    false
  end

  def params_digest(params = nil)
    hash_canonical(params.nil? ? {} : params)
  end

  def conditions_digest(pre, post)
    hash_canonical({ 'pre' => pre, 'post' => post })
  end

  def plan_leaf(node_id, action, cond)
    raise Malformed, 'missing node_id' if node_id.nil?

    pd = action['params_digest']
    pd = params_digest(nil) if pd.nil?
    rc = action['reversibility_class']
    rc = DEFAULT_REV if rc.nil?
    { 'node_id' => node_id, 'verb' => action['verb'], 'resource' => action['resource'],
      'params_digest' => pd, 'reversibility_class' => rc, 'conditions' => cond }
  end

  # ======================= strict Ed25519 (RFC 8032) =======================
  module Ed25519Strict
    P = (2**255) - 19
    L = (2**252) + 27_742_317_777_372_353_535_851_937_790_883_648_493
    D = (-121_665 * 121_666.pow(P - 2, P)) % P
    SQRT_M1 = 2.pow((P - 1) / 4, P)
    IDENTITY = [0, 1, 1, 0].freeze # extended (X, Y, Z, T)

    module_function

    def add(a, b)
      x1, y1, z1, t1 = a
      x2, y2, z2, t2 = b
      aa = ((y1 - x1) * (y2 - x2)) % P
      bb = ((y1 + x1) * (y2 + x2)) % P
      cc = (t1 * 2 * D * t2) % P
      dd = (z1 * 2 * z2) % P
      e = bb - aa
      f = dd - cc
      g = dd + cc
      h = bb + aa
      [(e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P]
    end

    def mul(k, pt)
      r = IDENTITY
      q = pt
      while k > 0
        r = add(r, q) if k.odd?
        q = add(q, q)
        k >>= 1
      end
      r
    end

    def identity?(pt)
      pt[0] % P == 0 && (pt[1] - pt[2]) % P == 0
    end

    # Canonical decode; nil if y >= p, off-curve, or x == 0 with the sign bit set.
    def decode(bytes)
      return nil unless bytes.bytesize == 32

      n = bytes.unpack('C*').each_with_index.sum { |b, i| b << (8 * i) }
      sign = n >> 255
      y = n & ((1 << 255) - 1)
      return nil if y >= P

      x2 = ((y * y) - 1) * (D * y * y + 1).pow(P - 2, P) % P
      x = x2.pow((P + 3) / 8, P)
      x = (x * SQRT_M1) % P if (x * x - x2) % P != 0
      return nil if (x * x - x2) % P != 0
      return nil if x == 0 && sign == 1

      x = P - x if (x & 1) != sign
      [x, y, 1, (x * y) % P]
    end

    # Rejects non-canonical, off-curve, small-order, and mixed-order (torsion-carrying) points.
    def acceptable_point(bytes)
      pt = decode(bytes)
      return nil if pt.nil?
      return nil if identity?(mul(8, pt)) # small order (includes identity)
      return nil unless identity?(mul(L, pt)) # torsion component present

      pt
    end

    def verify(pub, msg, sig)
      return false unless pub.bytesize == 32 && sig.bytesize == 64
      return false if acceptable_point(pub).nil?
      return false if acceptable_point(sig.byteslice(0, 32)).nil?

      s = sig.byteslice(32, 32).unpack('C*').each_with_index.sum { |b, i| b << (8 * i) }
      return false if s >= L

      OpenSSL::PKey.new_raw_public_key('ED25519', pub).verify(nil, sig, msg)
    rescue StandardError
      false
    end
  end

  # ======================= B4 post-quantum (ML-DSA-65, FIPS-204) =======================
  # Mirrors packages/pca/src/pq.ts. Absent `alg` (or "ed25519") is byte-identical to the classical wire.
  # ML-DSA-65 verification uses OpenSSL >= 3.5 (raw public key, pure mode, empty context): pk 1952 bytes,
  # sig 3309 bytes. `alg`/`pq_pk` are SIGNED; `sig`/`pq_sig` are stripped from the signed body.
  ML_DSA_65_PUBLIC_KEY_BYTES = 1952
  ML_DSA_65_SIGNATURE_BYTES = 3309
  ED25519_SIGNATURE_BYTES = 64

  # suite name => [sig byte length, needs pq_pk, needs pq_sig]
  SIG_SUITES = {
    'ed25519' => [ED25519_SIGNATURE_BYTES, false, false],
    'ml-dsa-65' => [ML_DSA_65_SIGNATURE_BYTES, true, false],
    'hybrid-ed25519-ml-dsa-65' => [ED25519_SIGNATURE_BYTES, true, true]
  }.freeze

  def mldsa65_verify(pk, msg, sig)
    return false unless pk.bytesize == ML_DSA_65_PUBLIC_KEY_BYTES && sig.bytesize == ML_DSA_65_SIGNATURE_BYTES

    OpenSSL::PKey.new_raw_public_key('ML-DSA-65', pk).verify(nil, sig, msg)
  rescue StandardError
    false
  end

  def mldsa65_verify_b64u(pk_b64u, msg, sig_b64u)
    pk = b64d(pk_b64u, ML_DSA_65_PUBLIC_KEY_BYTES)
    sg = b64d(sig_b64u, ML_DSA_65_SIGNATURE_BYTES)
    return false if pk.nil? || sg.nil?

    mldsa65_verify(pk, msg, sg)
  rescue StandardError
    false
  end

  # Returns [suite_name, nil] for the default/known suite, else [nil, reason] (fail-closed).
  def resolve_suite(p)
    return ['ed25519', nil] unless p.key?('alg')

    alg = p['alg']
    return [nil, "'alg' must be a string"] unless alg.is_a?(String)
    return [nil, "unknown signature alg '#{alg}'"] unless SIG_SUITES.key?(alg)

    [alg, nil]
  end

  # Validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite. Returns nil when well-formed, else a reason.
  def validate_signature_wire(p)
    suite, err = resolve_suite(p)
    return err if suite.nil?

    sig_bytes, needs_pk, needs_sig = SIG_SUITES[suite]
    return "'sig' is not canonical base64url (#{sig_bytes} bytes) for alg '#{suite}'" if b64d(p['sig'], sig_bytes).nil?

    if needs_pk
      return "'pq_pk' is not canonical base64url (#{ML_DSA_65_PUBLIC_KEY_BYTES} bytes)" if b64d(p['pq_pk'], ML_DSA_65_PUBLIC_KEY_BYTES).nil?
    elsif p.key?('pq_pk')
      return "'pq_pk' must be absent for alg '#{suite}'"
    end
    if needs_sig
      return "'pq_sig' is not canonical base64url (#{ML_DSA_65_SIGNATURE_BYTES} bytes)" if b64d(p['pq_sig'], ML_DSA_65_SIGNATURE_BYTES).nil?
    elsif p.key?('pq_sig')
      return "'pq_sig' must be absent for alg '#{suite}'"
    end
    nil
  end

  # Verify the leaf signature under the PCActn's suite. FAIL-CLOSED.
  def verify_leaf_suite(p, holder, msg)
    suite, = resolve_suite(p)
    return false if suite.nil?

    sig = p['sig']
    case suite
    when 'ed25519' then verify_b64u(holder, msg, sig)
    when 'ml-dsa-65' then mldsa65_verify_b64u(p['pq_pk'], msg, sig)
    when 'hybrid-ed25519-ml-dsa-65'
      verify_b64u(holder, msg, sig) && mldsa65_verify_b64u(p['pq_pk'], msg, p['pq_sig'])
    else false
    end
  end

  # ======================= v2.1 threshold-share binding =======================
  # Server-side share verification. The v2.1 clean break binds EVERY role's share (agent included) to the
  # signer set and threshold: the signed bytes are
  #   "atlas-pca/share/<role>\0" || sha256(thresholdMessage) || signerSetHash || t(1 byte)
  # with signerSetHash = sha256("atlas-pca/signerset/v1\0" || canonical(sort_by(role,publicKey)[{publicKey,role}])).
  SIGNERSET_DOMAIN = "atlas-pca/signerset/v1\x00".b.freeze

  # signerSetHash recomputed from the signer set itself (never a caller-supplied hash). nil (fail-closed) if
  # the set is empty or any entry is ill-typed.
  def signer_set_hash(signer_set)
    return nil unless signer_set.is_a?(Array) && !signer_set.empty?

    entries = signer_set.map do |e|
      return nil unless e.is_a?(Hash) && e['publicKey'].is_a?(String) && e['role'].is_a?(String)

      { 'publicKey' => e['publicKey'], 'role' => e['role'] }
    end
    entries.sort_by! { |e| [e['role'].b, e['publicKey'].b] }
    sha(SIGNERSET_DOMAIN + canon_bytes(entries))
  end

  # Verify a threshold share's signature over `msg` under its suite (ed25519 by default; ml-dsa-65 / hybrid
  # dispatch identically to the leaf). FAIL-CLOSED: unknown suite or bad key/sig => false.
  def verify_share_suite(share, msg)
    suite, = resolve_suite(share)
    return false if suite.nil?

    sig = share['sig']
    case suite
    when 'ed25519' then verify_b64u(share['publicKey'], msg, sig)
    when 'ml-dsa-65' then mldsa65_verify_b64u(share['pq_pk'], msg, sig)
    when 'hybrid-ed25519-ml-dsa-65'
      verify_b64u(share['publicKey'], msg, sig) && mldsa65_verify_b64u(share['pq_pk'], msg, share['pq_sig'])
    else false
    end
  end

  # Verify a threshold share against the v2.1 binding. The bound message is RECOMPUTED here from
  # (role, thresholdMessage, signer_set, t) — the vector's precomputed `share_message` / `signer_set_hash`
  # are NOT trusted — then `share.sig` must verify over it. FAIL-CLOSED: any missing / ill-typed field, bad
  # base64url, t not in {1,2,3}, or unknown share suite returns false (never accepted). This is exactly why
  # the pre-v2.1 bare-threshold-message agent share and a cross-signer-set replay are rejected.
  def verify_threshold_share(entry)
    return false unless entry.is_a?(Hash)

    role = entry['role']
    t = entry['t']
    return false unless role.is_a?(String) && !role.empty?
    return false unless t.is_a?(Integer) && [1, 2, 3].include?(t)

    tmsg = b64d(entry['threshold_message'])
    return false if tmsg.nil?

    ssh = signer_set_hash(entry['signer_set'])
    return false if ssh.nil?

    share = entry['share']
    return false unless share.is_a?(Hash)

    bound = "atlas-pca/share/#{role}\x00".b + sha(tmsg) + ssh + [t].pack('C')
    verify_share_suite(share, bound)
  rescue StandardError
    false
  end

  # Verify a post-quantum transparency/authority artifact: the suite `alg` signature over the DECODED 32-byte
  # `message` digest, under `ed_pub` (+ `pq_pk` for lattice/hybrid). Routes through the SAME agility seam as
  # the leaf. FAIL-CLOSED: unknown suite or non-32-byte message => false.
  def verify_pq_artifact(entry)
    return false unless entry.is_a?(Hash)

    msg = b64d(entry['message'], 32)
    return false if msg.nil?

    verify_leaf_suite(entry, entry['ed_pub'], msg)
  rescue StandardError
    false
  end

  # ======================= keys =======================
  def verify_b64u(pub, msg, sig)
    pk = pub.is_a?(String) ? b64d(pub, 32) : nil
    return false if pk.nil?

    sg = sig.is_a?(String) ? b64d(sig, 64) : nil
    return false if sg.nil?

    Ed25519Strict.verify(pk, msg, sg)
  rescue StandardError
    false
  end

  # ======================= capability chain =======================
  def cap_hash(c)
    hash_canonical(c)
  end

  def body_of(c)
    { 'issuer' => c['issuer'], 'holder' => c['holder'], 'caveats' => c['caveats'], 'parent' => c['parent'] }
  end

  # body_of + the suite fields (`alg`, `pq_pk`) bound in for a non-default suite (so a downgrade or ML-DSA
  # key-swap breaks the hop digest), byte-identical to body_of for ed25519. Mirrors signableBody in
  # capability.ts. Returns [body, nil], or [nil, reason] for an unknown `alg` (fail-closed).
  def signable_hop_body(c)
    suite, err = resolve_suite(c)
    return [nil, err] if suite.nil?

    body = body_of(c)
    if suite != 'ed25519'
      body['alg'] = suite
      _, needs_pk, = SIG_SUITES[suite]
      body['pq_pk'] = c['pq_pk'] if needs_pk && c['pq_pk'].is_a?(String)
    end
    [body, nil]
  end

  def check_sig(c, signer, label)
    # Unknown suite => fail-closed (before any hashing), mirroring capability.ts checkSig.
    body, err = signable_hop_body(c)
    return "#{label}: #{err}" if body.nil?

    digest = hash_canonical(body)
    bd = c['body_digest']
    return "#{label}: body digest mismatch" if digest != bd || c['id'] != bd

    d = b64d(bd, 32)
    return "#{label}: bad signature (not signed by expected key)" if d.nil?

    msg = CAP_DOMAIN + d
    # Suite-agile hop verification: ed25519 == verify_b64u(signer, msg, sig); hybrid requires BOTH the
    # Ed25519 `sig` (under `signer`) AND the ML-DSA `pq_sig` (under `pq_pk`); pure ml-dsa-65 verifies `sig`
    # under `pq_pk`. verify_leaf_suite dispatches on the hop's `alg` (the signer is the expected Ed25519 key).
    return "#{label}: bad signature (not signed by expected key)" unless verify_leaf_suite(c, signer, msg)

    ''
  end

  # Returns [reason, ok]
  def verify_chain(chain, expected_root_issuer, have_issuer)
    return ['empty chain', false] if chain.empty?
    return ["chain longer than #{MAX_CHAIN_HOPS} capabilities", false] if chain.length > MAX_CHAIN_HOPS

    root = chain[0]
    return ['hop 0: malformed', false] unless root.is_a?(Hash)
    return ['hop 0: root must not have a parent', false] if root.key?('parent')
    if have_issuer && root['issuer'] != expected_root_issuer
      return ['hop 0: root issuer is not the expected principal', false]
    end

    e = check_sig(root, root['issuer'].is_a?(String) ? root['issuer'] : '', 'hop 0')
    return [e, false] unless e.empty?

    (1...chain.length).each do |i|
      parent = chain[i - 1]
      c = chain[i]
      label = "hop #{i}"
      return ["#{label}: malformed", false] unless parent.is_a?(Hash) && c.is_a?(Hash)
      return ["#{label}: broken parent link", false] if c['parent'] != cap_hash(parent)
      return ["#{label}: issuer is not the parent's bound holder", false] if c['issuer'] != parent['holder']

      e = check_sig(c, parent['holder'].is_a?(String) ? parent['holder'] : '', label)
      return [e, false] unless e.empty?

      pc = parent['caveats'].is_a?(Array) ? parent['caveats'] : []
      cc = c['caveats'].is_a?(Array) ? c['caveats'] : []
      return ["#{label}: drops parent caveat(s)", false] if cc.length < pc.length

      pc.each_index do |j|
        return ["#{label}: caveat #{j} altered or reordered", false] if hash_canonical(cc[j]) != hash_canonical(pc[j])
      end
    end
    ['', true]
  end

  # ======================= wire validation =======================
  TOP_REQUIRED = %w[ver action grant_ref cap_chain plan attestation provenance freshness counter risk_claim
                    aud iat exp sig].freeze
  TOP_OPTIONAL = %w[nonce caution rationale_commitment progress_step prohibition_evidence tool_binding
                    zk_compliance bond_ref threshold alg pq_pk pq_sig].freeze
  ACTION_KEYS = %w[verb resource params_digest reversibility_class].freeze
  PLAN_REQUIRED = %w[root inclusion_proof node_id].freeze
  PROOF_KEYS = %w[index size path].freeze
  HOP_REQUIRED = %w[id issuer holder body_digest caveats sig].freeze
  # B4 crypto-agility (additive) on a hop exactly as at the top level: absent `alg` == ed25519, in which
  # case `pq_pk`/`pq_sig` MUST be absent and the hop is BYTE-IDENTICAL to the pre-B4 wire.
  HOP_OPTIONAL = %w[parent alg pq_pk pq_sig].freeze

  def b32?(x)
    !b64d(x, 32).nil?
  end

  def b64?(x)
    !b64d(x, 64).nil?
  end

  def closed?(h, required, optional = [])
    h.is_a?(Hash) && required.all? { |k| h.key?(k) } && h.keys.all? { |k| required.include?(k) || optional.include?(k) }
  end

  def hop_wire_ok?(c)
    return false unless closed?(c, HOP_REQUIRED, HOP_OPTIONAL)
    return false unless %w[id issuer holder body_digest].all? { |k| b32?(c[k]) }
    # B4 crypto-agility: validate the hop's `alg`/`sig`/`pq_pk`/`pq_sig` per suite, exactly as the leaf.
    # Absent `alg` asserts a 64-byte `sig` and that `pq_pk`/`pq_sig` are absent (byte-identical pre-B4 hop).
    return false unless validate_signature_wire(c).nil? && c['caveats'].is_a?(Array)
    return false unless c['caveats'].all? { |cv| cv.is_a?(Hash) && cv['type'].is_a?(String) }

    !c.key?('parent') || b32?(c['parent'])
  end

  def plan_wire_ok?(plan)
    return false unless closed?(plan, PLAN_REQUIRED, %w[conditions_digest])
    return false unless b32?(plan['root']) && plan['node_id'].is_a?(String)
    return false if plan.key?('conditions_digest') && !b32?(plan['conditions_digest'])

    pr = plan['inclusion_proof']
    return false unless closed?(pr, PROOF_KEYS)
    return false unless safe_int?(pr['index']) && safe_int?(pr['size']) && pr['path'].is_a?(Array)

    pr['path'].all? { |s| s.is_a?(Hash) && closed?(s, %w[side hash]) && %w[L R].include?(s['side']) && b32?(s['hash']) }
  end

  def number?(x)
    (x.is_a?(Integer) || x.is_a?(Float)) && number_ok?(x)
  end

  def optional_wire_ok?(p)
    return false if p.key?('nonce') && !(p['nonce'].is_a?(String) && !p['nonce'].empty? && p['nonce'].bytesize <= 128)
    return false if p.key?('caution') && !(number?(p['caution']) && p['caution'] >= 0 && p['caution'] <= 1)
    return false if p.key?('rationale_commitment') && !b32?(p['rationale_commitment'])
    return false if p.key?('tool_binding') && !b32?(p['tool_binding'])

    th = p['threshold']
    return true unless p.key?('threshold')
    return false unless th.is_a?(Hash)

    sh = th['shares']
    return true if sh.nil?

    return false unless sh.is_a?(Array) && sh.all? do |s|
      s.is_a?(Hash) && s['role'].is_a?(String) && b32?(s['publicKey']) && b64?(s['sig'])
    end

    true
  end

  def strs?(h, keys)
    keys.all? { |k| h[k].is_a?(String) }
  end

  def aux_wire_ok?(p)
    at = p['attestation']
    pv = p['provenance']
    fr = p['freshness']
    rc = p['risk_claim']
    return false unless at.is_a?(Hash) && safe_int?(at['epoch']) && strs?(at, %w[quote_digest model_id measurement operator])
    return false unless pv.is_a?(Hash) && strs?(pv, %w[causal_hash]) && number?(pv['taint_level'])
    return false unless pv['trusted_refs'].is_a?(Array) && pv['trusted_refs'].all? { |x| x.is_a?(String) }
    return false unless fr.is_a?(Hash) && safe_int?(fr['epoch']) && strs?(fr, %w[beacon_ref accumulator_witness])
    return false unless rc.is_a?(Hash) && number?(rc['r']) && rc['inputs'].is_a?(Hash)
    return false if p.key?('progress_step') && !p['progress_step'].is_a?(Hash)
    return false if p.key?('prohibition_evidence') && !(p['prohibition_evidence'].is_a?(Hash) || p['prohibition_evidence'].is_a?(Array))

    true
  end

  # The CLOSED, strictly-typed wire form. A failure here is terminal.
  def wire_ok?(p)
    return false unless p.is_a?(Hash) && tree_ok?(p)
    return false unless closed?(p, TOP_REQUIRED, TOP_OPTIONAL)
    return false unless %w[ver counter iat exp].all? { |k| safe_int?(p[k]) }
    return false unless p['aud'].is_a?(String) && !p['aud'].empty? && p['aud'].bytesize <= 256
    # B4 crypto-agility: validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite (absent `alg` == classical 64-byte sig).
    return false unless validate_signature_wire(p).nil?
    return false unless b32?(p['grant_ref'])

    a = p['action']
    return false unless closed?(a, ACTION_KEYS)
    return false unless a['verb'].is_a?(String) && a['resource'].is_a?(String) && a['reversibility_class'].is_a?(String)
    return false unless b32?(a['params_digest'])

    return false unless p['cap_chain'].is_a?(Array) && p['cap_chain'].all? { |c| hop_wire_ok?(c) }
    return false unless plan_wire_ok?(p['plan'])
    return false unless aux_wire_ok?(p)

    optional_wire_ok?(p)
  rescue StandardError
    false
  end

  # ======================= PCActn =======================
  def threshold_message(p)
    # `sig`, `threshold` and the B4 `pq_sig` are unsigned (stripped); `alg`/`pq_pk` ARE signed.
    body = p.reject { |k, _| k == 'sig' || k == 'threshold' || k == 'pq_sig' }
    SIG_DOMAIN + sha(canon_bytes(body))
  end

  # pcactn: parsed Hash OR raw JSON text (String) which MUST pass the strict profile (failure == wire).
  # Returns Verdict. Wire failure is terminal: checks == { 'wire' => false }.
  def verify_pcactn(pcactn, grant, now:, audience:)
    if pcactn.is_a?(String)
      begin
        pcactn = parse_json(pcactn)
      rescue Malformed
        return Verdict.new(false, { 'wire' => false }, 'wire: strict JSON profile violation')
      end
    end
    return Verdict.new(false, { 'wire' => false }, 'wire: malformed PCActn') unless wire_ok?(pcactn)

    checks = { 'wire' => true }
    reason = ''
    run = lambda do |name, why, &blk|
      ok = begin
        blk.call ? true : false
      rescue StandardError
        false
      end
      checks[name] = ok
      reason = "#{name}: #{why}" if !ok && reason.empty?
    end

    run.call('version', 'unsupported ver') { pcactn['ver'] == 2 }
    run.call('audience', 'audience mismatch') { pcactn['aud'] == audience }
    run.call('validity', 'outside validity window') do
      iat = pcactn['iat']
      exp = pcactn['exp']
      exp > iat && exp - iat <= MAX_LIFETIME_MS && iat <= now + MAX_SKEW_MS && now <= exp
    end

    chain = pcactn['cap_chain']
    run.call('chain', 'capability chain invalid') do
      if chain.empty? || chain.length > MAX_CHAIN_HOPS
        false
      elsif cap_hash(chain[0]) != cap_hash(grant)
        false
      else
        gi = grant['issuer']
        verify_chain(chain, gi, gi.is_a?(String)).last
      end
    end

    plan = pcactn['plan']
    run.call('plan_inclusion', 'action is not a node of the committed plan') do
      cond = plan.key?('conditions_digest') ? plan['conditions_digest'] : conditions_digest(nil, nil)
      verify_inclusion(plan['root'], plan['inclusion_proof'], plan_leaf(plan['node_id'], pcactn['action'], cond))
    end

    run.call('leaf_signature', 'signature does not verify under the leaf holder key') do
      !chain.empty? && verify_leaf_suite(pcactn, chain[-1]['holder'], threshold_message(pcactn))
    end

    run.call('counter', 'not a non-negative safe integer') { safe_int?(pcactn['counter']) && pcactn['counter'] >= 0 }

    CHECK_ORDER.each { |k| checks[k] = false unless checks.key?(k) }
    ordered = CHECK_ORDER.to_h { |k| [k, checks[k]] }
    Verdict.new(ordered.values.all?, ordered, reason)
  end
end
