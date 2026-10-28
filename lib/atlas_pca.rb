# frozen_string_literal: true

# Reference verifier for the CORE PCActn checks (wire format v2): strict wire form, freshness binding,
# capability chain, Merkle plan inclusion, strict RFC 8032 Ed25519 leaf signature, counter_format.
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
  # Shared hard caveat caps (all PCA verifiers): caveat lists are cumulative, so MAX_CAVEATS_PER_HOP bounds a hop's whole
  # list and MAX_CAVEATS_PER_CHAIN the sum over hops (= the work of every attenuation prefix comparison).
  MAX_CAVEATS_PER_HOP = 256
  MAX_CAVEATS_PER_CHAIN = 1024
  CAVEAT_LIMIT_REASON = "chain exceeds caveat limit (max #{MAX_CAVEATS_PER_HOP} per hop, #{MAX_CAVEATS_PER_CHAIN} per chain)".freeze
  MAX_JSON_DEPTH = 32
  MAX_JSON_CHARS = 1 << 20 # UTF-8 BYTES
  # Shared raw wire-size cap of a PCActn JSON document (UTF-8 bytes), checked before any parsing.
  MAX_ARTIFACT_BYTES = 524_288
  ARTIFACT_SIZE_REASON = "artifact exceeds size limit (max #{MAX_ARTIFACT_BYTES} bytes)".freeze
  MAX_DECIMAL_DIGITS = 15
  MAX_LIFETIME_MS = 3_600_000
  MAX_SKEW_MS = 60_000
  MAX_SAFE = (2**53) - 1
  CHECK_ORDER = %w[wire version audience validity chain grant_ref_bound plan_inclusion leaf_signature counter_format].freeze

  class Malformed < StandardError; end

  # `reasons` lists every failing check's reason in pipeline order (nil: only `reason`); `degraded` names a rule that passed degraded.
  Verdict = Struct.new(:allow, :checks, :reason, :reasons, :degraded)

  module_function

  # ======================= strict JSON profile =======================
  # Hand-written RFC 8259 parser. Rejects: comments, trailing commas, BOM, non-(SP/TAB/LF/CR) whitespace,
  # duplicate keys (after unescaping), lone surrogates, raw control chars, unknown escapes, depth > 32,
  # input > 2^20 chars, non-canonical numbers. Result must be an object.
  # `loose: true` is ONLY for reading the conformance file itself (it holds deliberately-bad values as
  # already-parsed objects): lone-surrogate escapes become invalid-encoding strings, numbers keep any
  # lexeme (Integer or Float), and depth/length caps are off. Verification re-validates every value anyway.
  class JsonParser
    # Anchored at the scan position (\G): lets the number / plain-string scans run in place with no substring copy.
    NUM_AT = /\G-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/n
    PLAIN_RUN = /\G[^"\\\x00-\x1f]+/n

    # json_text: the platform-JSON reading of RAW JSON TEXT carried by runners (`*_json` members, see parse_json_text):
    # loose, any top-level value, a duplicate key keeps the LAST value (JSON.parse), and every number is its binary64
    # value (a bare `-0` is negative zero).
    def initialize(text, loose, any_top, json_text: false)
      @loose = loose || json_text
      @any_top = any_top || json_text
      @json_text = json_text
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
      s = @s
      i = @i
      i += 1 while (c = s.getbyte(i)) && (c == 0x20 || c == 0x0a || c == 0x0d || c == 0x09)
      @i = i
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
        raise Malformed, 'duplicate key' if h.key?(k) && !@json_text

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
      # Fast path: a plain run of bytes straight to the closing quote (the overwhelmingly common key / value string).
      m = PLAIN_RUN.match(@s, @i)
      out = m ? m[0] : String.new(encoding: Encoding::BINARY)
      @i += out.bytesize
      if @s.getbyte(@i) == 0x22
        @i += 1
        return out.force_encoding('UTF-8')
      end
      loop do
        c = @s.getbyte(@i)
        raise Malformed, 'unterminated string' if c.nil?

        if c == 0x22
          @i += 1
          return out.force_encoding('UTF-8')
        elsif c >= 0x20 && c != 0x5c
          run = PLAIN_RUN.match(@s, @i)[0]
          out << run
          @i += run.bytesize
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
      m = NUM_AT.match(@s, @i)
      raise Malformed, 'bad value' if m.nil?

      lex = m[0].dup.force_encoding('UTF-8')
      # A lexeme beyond 64 KiB is rejected exactly as before (the old scan window truncated it and left trailing digits).
      raise Malformed, 'bad value' if lex.bytesize > 64 * 1024

      @i += lex.bytesize
      return json_text_number(lex) if @json_text
      return loose_number(lex) if @loose

      AtlasPca.strict_number_lexeme(lex)
    end

    def loose_number(lex)
      lex.match?(/[.eE]/) ? Float(lex) : lex.to_i
    end

    # A number as JSON.parse reads it, by its IEEE-754 binary64 value: a fraction or exponent form (`1.0`, `1e6`, `-0e0`)
    # and an integer beyond 2^53-1 (rounded, like a double) are Floats; `-0` is negative zero (-0.0); any other integer
    # lexeme is the Integer it denotes.
    def json_text_number(lex)
      return -0.0 if lex == '-0'

      i = lex.match?(/[.eE]/) ? nil : lex.to_i
      return i unless i.nil? || i.abs > MAX_SAFE

      f = Float(lex)
      # A negative lexeme whose value is zero (`-0.0`, `-0e0`, `-0E+0`) is negative zero; this does not rely on the
      # platform's float conversion keeping the sign of zero.
      f.zero? && lex.start_with?('-') ? -0.0 : f
    end
  end

  # Canonical-form number lexeme (README section 3). Returns Integer or Float.
  def strict_number_lexeme(lex)
    # Fast path: a short canonical integer (<= 15 digits is always within MAX_SAFE; `-0` and leading zeros do not match).
    return lex.to_i if lex.bytesize <= 15 && lex.match?(/\A(?:0|-?[1-9][0-9]*)\z/)

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
  # The loose mode has no depth cap (it reads the conformance file, which holds 100000-deep values): running out of stack
  # there is a Malformed, never an escaping SystemStackError. The strict profile refuses depth > 32 before recursing.
  def parse_json(text, loose: false, any_top: false)
    JsonParser.new(text, loose, any_top).parse_document
  rescue SystemStackError
    raise Malformed, 'nesting too deep'
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

  # A JSON string: a String tagged UTF-8 whose bytes are valid UTF-8 (object keys are always such strings), or tagged
  # US-ASCII with valid (7-bit) bytes: ASCII is a subset of UTF-8, and Ruby tags many ASCII-only strings US-ASCII (e.g.
  # Base64 output, Integer#to_s). BINARY / other encodings and invalid bytes are refused.
  def utf8_string?(v)
    v.is_a?(String) && (v.encoding == Encoding::UTF_8 || v.encoding == Encoding::US_ASCII) && v.valid_encoding?
  end

  # Whole-object structural validation: depth, numbers, string encodings, key/value types.
  def tree_ok?(v, depth = 1)
    case v
    when nil, true, false then true
    when String then utf8_string?(v)
    when Integer, Float then number_ok?(v)
    when Array then depth <= MAX_JSON_DEPTH && v.all? { |x| tree_ok?(x, depth + 1) }
    when Hash then depth <= MAX_JSON_DEPTH && v.all? { |k, x| utf8_string?(k) && tree_ok?(x, depth + 1) }
    else false
    end
  end

  # ======================= base64url (strict) =======================
  # UTF-8-tagged (Base64 returns US-ASCII), so a PCActn built natively from these strings carries ordinary JSON strings.
  def b64e(bin)
    Base64.urlsafe_encode64(bin, padding: false).force_encoding(Encoding::UTF_8)
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
  JS_ESCAPES = /["\\\x00-\x1f]/

  def js_string(s)
    raise Malformed, 'invalid string encoding' unless s.valid_encoding?
    # Fast path: nothing to escape (no quote, backslash or control char) -> the string is emitted verbatim.
    return "\"#{s}\"" unless s.match?(JS_ESCAPES)

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

  # The strict canonical form (reference canonicalizeStrict): containers deeper than MAX_JSON_DEPTH (the outermost is
  # depth 1) are refused BEFORE recursing, so a hostile value of any depth is a Malformed, never a SystemStackError.
  def ser(v, out, depth = 1)
    case v
    when nil then out << 'null'
    when true then out << 'true'
    when false then out << 'false'
    when String then out << js_string(v)
    when Integer, Float then out << fmt_number(v)
    when Array
      raise Malformed, 'canonicalize: nesting too deep' if depth > MAX_JSON_DEPTH

      out << '['
      v.each_with_index do |x, i|
        out << ',' if i > 0
        ser(x, out, depth + 1)
      end
      out << ']'
    when Hash
      raise Malformed, 'canonicalize: nesting too deep' if depth > MAX_JSON_DEPTH

      # Keys sorted BYTEWISE over UTF-8 (== code point order), not UTF-16 code units.
      keys = v.keys.sort_by { |k| k.to_s.b }
      out << '{'
      keys.each_with_index do |k, i|
        out << ',' if i > 0
        out << js_string(k.to_s) << ':'
        ser(v[k], out, depth + 1)
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

  # ======================= B4 post-quantum suites (FIPS 204 ML-DSA, FIPS 205 SLH-DSA) =======================
  # Mirrors packages/pca/src/pq.ts. Absent `alg` (or "ed25519") is byte-identical to the classical wire. Every PQ
  # primitive is OpenSSL >= 3.5 (raw public key, pure mode, empty context — OpenSSL's defaults for these key types,
  # = @noble/post-quantum): ML-DSA-65 / ML-DSA-87 and SLH-DSA-SHA2-128f / SLH-DSA-SHA2-256s, plus their
  # hybrid-ed25519-* forms and the SUF-CMA hybrid-nested-ed25519-ml-dsa-65 (PQ half over msg || Ed25519 sig bytes).
  # LESS (less-cat1 / hybrid-ed25519-less-cat1) goes through libatlas_less (AtlasPca::LessFfi, the patched reference C of
  # sdks/pca-less-c; variable-length signature). Suite capability (packages/pca/conformance/SUITES.md): a registered suite
  # this verifier cannot run — fn-dsa-512 / fn-dsa-1024 (OpenSSL has no FIPS 206), LESS without libatlas_less, or a PQ suite
  # whose key type the loaded OpenSSL cannot build — fails closed with the distinct reason `unsupported_suite: <alg>`.
  # `alg`/`pq_pk` are SIGNED; `sig`/`pq_sig` are stripped from the signed body.
  ML_DSA_65_PUBLIC_KEY_BYTES = 1952
  ML_DSA_65_SIGNATURE_BYTES = 3309
  ED25519_SIGNATURE_BYTES = 64
  UNSUPPORTED_SUITE = 'unsupported_suite'

  # The closed TS suite registry (SIG_SUITES in pq.ts), in registry order.
  REGISTERED_SUITES = %w[ed25519 ml-dsa-65 hybrid-ed25519-ml-dsa-65 hybrid-nested-ed25519-ml-dsa-65 slh-dsa-sha2-128f
                         hybrid-ed25519-slh-dsa-sha2-128f ml-dsa-87 hybrid-ed25519-ml-dsa-87 slh-dsa-sha2-256s
                         hybrid-ed25519-slh-dsa-sha2-256s fn-dsa-512 fn-dsa-1024 less-cat1 hybrid-ed25519-less-cat1].freeze

  # OpenSSL key type => [public key bytes, signature bytes].
  PQ_PRIMS = {
    'ML-DSA-65' => [ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES],
    'ML-DSA-87' => [2592, 4627],
    'SLH-DSA-SHA2-128f' => [32, 17_088],
    'SLH-DSA-SHA2-256s' => [64, 29_792],
    'LESS-cat1' => [97_484, 1329] # signature: the MAXIMUM (pq_sig_ok?)
  }.freeze

  # suite name => [sig byte length, needs pq_pk, needs pq_sig, PQ primitive (OpenSSL key type) or nil, nested]
  SIG_SUITES = {
    'ed25519' => [ED25519_SIGNATURE_BYTES, false, false, nil, false],
    'ml-dsa-65' => [ML_DSA_65_SIGNATURE_BYTES, true, false, 'ML-DSA-65', false],
    'hybrid-ed25519-ml-dsa-65' => [ED25519_SIGNATURE_BYTES, true, true, 'ML-DSA-65', false],
    'hybrid-nested-ed25519-ml-dsa-65' => [ED25519_SIGNATURE_BYTES, true, true, 'ML-DSA-65', true],
    'slh-dsa-sha2-128f' => [17_088, true, false, 'SLH-DSA-SHA2-128f', false],
    'hybrid-ed25519-slh-dsa-sha2-128f' => [ED25519_SIGNATURE_BYTES, true, true, 'SLH-DSA-SHA2-128f', false],
    'ml-dsa-87' => [4627, true, false, 'ML-DSA-87', false],
    'hybrid-ed25519-ml-dsa-87' => [ED25519_SIGNATURE_BYTES, true, true, 'ML-DSA-87', false],
    'slh-dsa-sha2-256s' => [29_792, true, false, 'SLH-DSA-SHA2-256s', false],
    'hybrid-ed25519-slh-dsa-sha2-256s' => [ED25519_SIGNATURE_BYTES, true, true, 'SLH-DSA-SHA2-256s', false],
    'less-cat1' => [1329, true, false, 'LESS-cat1', false],
    'hybrid-ed25519-less-cat1' => [ED25519_SIGNATURE_BYTES, true, true, 'LESS-cat1', false]
  }.freeze

  PQ_PRIM_AVAILABLE = {} # rubocop:disable Style/MutableConstant -- memo of the runtime capability probe

  # Real capability probe: the loaded OpenSSL can build a raw public key of this type (no version-number gate).
  def pq_prim_available?(prim)
    return PQ_PRIM_AVAILABLE[prim] if PQ_PRIM_AVAILABLE.key?(prim)
    return PQ_PRIM_AVAILABLE[prim] = LessFfi.available? if prim == LessFfi::KEY_TYPE

    PQ_PRIM_AVAILABLE[prim] = begin
      OpenSSL::PKey.new_raw_public_key(prim, "\x00".b * PQ_PRIMS.fetch(prim)[0])
      true
    rescue StandardError
      false
    end
  end

  # The capability manifest: the registered suites this verifier can verify in this runtime, in registry order.
  def supported_suites
    REGISTERED_SUITES.select { |a| SIG_SUITES.key?(a) && (SIG_SUITES[a][3].nil? || pq_prim_available?(SIG_SUITES[a][3])) }
  end

  # `n` is a signature length of `prim` (its fixed length; LESS-cat1: 1,153..1,329 in steps of 16).
  def pq_sig_len_ok?(prim, n)
    return LessFfi.sig_len_ok?(n) if prim == LessFfi::KEY_TYPE

    PQ_PRIMS.key?(prim) && n == PQ_PRIMS[prim][1]
  end

  # Canonical base64url whose decoded length is a signature length of `prim`.
  def pq_sig_ok?(v, prim)
    b = b64d(v)
    !b.nil? && pq_sig_len_ok?(prim, b.bytesize)
  end

  # Exact-length PQ verification over raw bytes (pure, empty context). Never raises.
  def pq_verify(prim, pk, msg, sig)
    pk_len, = PQ_PRIMS[prim]
    return false if pk_len.nil? || pk.bytesize != pk_len || !pq_sig_len_ok?(prim, sig.bytesize)
    return LessFfi.verify(pk, msg, sig) if prim == LessFfi::KEY_TYPE

    OpenSSL::PKey.new_raw_public_key(prim, pk).verify(nil, sig, msg)
  rescue StandardError
    false
  end

  def pq_verify_b64u(prim, pk_b64u, msg, sig_b64u)
    pk_len, = PQ_PRIMS[prim]
    return false if pk_len.nil?

    pk = b64d(pk_b64u, pk_len)
    sg = b64d(sig_b64u)
    return false if pk.nil? || sg.nil?

    pq_verify(prim, pk, msg, sg)
  rescue StandardError
    false
  end

  def mldsa65_verify(pk, msg, sig) = pq_verify('ML-DSA-65', pk, msg, sig)

  def mldsa65_verify_b64u(pk_b64u, msg, sig_b64u) = pq_verify_b64u('ML-DSA-65', pk_b64u, msg, sig_b64u)

  # Returns [suite_name, nil] for the default / a supported suite, else [nil, reason] (fail-closed): a registered suite
  # this runtime cannot verify is `unsupported_suite: <alg>`, anything else `unknown signature alg`.
  def resolve_suite(p)
    return ['ed25519', nil] unless p.key?('alg')

    alg = p['alg']
    return [nil, "'alg' must be a string"] unless alg.is_a?(String)
    return [alg, nil] if supported_suites.include?(alg)
    return [nil, "#{UNSUPPORTED_SUITE}: #{alg}"] if REGISTERED_SUITES.include?(alg)

    [nil, "unknown signature alg '#{alg}'"]
  end

  # Validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite. Returns nil when well-formed, else a reason.
  def validate_signature_wire(p)
    validate_suite_fields(p, true)
  end

  # 0.4.1: a threshold share's `alg`/`sig`/`pq_sig` per suite, exactly like the leaf (absent `alg` == ed25519: a 64-byte
  # `sig` and no `pq_sig`), EXCEPT `pq_pk`: on a share it is an optional echo judged by verify_threshold_share against the
  # signer set, so the wire does not look at it. Mirrors validateShareSignatureWire in packages/pca/src/pq.ts.
  def validate_share_signature_wire(s)
    validate_suite_fields(s, false)
  end

  def validate_suite_fields(p, check_pq_pk)
    suite, err = resolve_suite(p)
    return err if suite.nil?

    sig_bytes, needs_pk, needs_sig, prim, = SIG_SUITES[suite]
    # the PQ signature is `sig` for a pure suite and `pq_sig` for a hybrid; its length rule is the primitive's
    sig_ok = !prim.nil? && !needs_sig ? pq_sig_ok?(p['sig'], prim) : !b64d(p['sig'], sig_bytes).nil?
    return "'sig' is not canonical base64url (#{sig_bytes} bytes) for alg '#{suite}'" unless sig_ok

    pk_len, pq_sig_len = prim.nil? ? [0, 0] : PQ_PRIMS[prim]
    if !check_pq_pk
      # share: `pq_pk` is an optional echo, judged by verify_threshold_share against the signer set
    elsif needs_pk
      return "'pq_pk' is not canonical base64url (#{pk_len} bytes)" if b64d(p['pq_pk'], pk_len).nil?
    elsif p.key?('pq_pk')
      return "'pq_pk' must be absent for alg '#{suite}'"
    end
    if needs_sig
      return "'pq_sig' is not canonical base64url (#{pq_sig_len} bytes)" unless pq_sig_ok?(p['pq_sig'], prim)
    elsif p.key?('pq_sig')
      return "'pq_sig' must be absent for alg '#{suite}'"
    end
    nil
  end

  # An opaque PQ verification key (R3-01 choke point). Instances are minted ONLY by `resolve_pq_key`, so the low-level PQ
  # verification (`verify_suite`) cannot be reached with a `pq_pk` read straight off the artifact being verified.
  class PinnedPq
    MINT = Object.new.freeze
    attr_reader :key, :source

    def initialize(key, source, token)
      raise ArgumentError, 'PinnedPq is minted only by resolve_pq_key' unless token.equal?(MINT)

      @key = key
      @source = source
      freeze
    end
    private_class_method :new

    def self.mint(key, source) = new(key, source, MINT)
  end

  # THE choke point (R3-01), mirroring resolvePqVerifyKey in packages/pca/src/pq.ts. Returns the key to verify under, or nil
  # (REFUSE) when no verifier-side authority vouches for the artifact's `pq_pk`:
  #   1. trusted_pk: a key the verifier itself holds (the stored grant). Used as is.
  #   2. pq_pins[identity] (own entry only): artifact_pk MUST equal the pin; a differing pin is a refusal.
  #   3. holder_pq: artifact_pk must hash to the signer's committed holder_pq (F-2).
  # Natives have no allowUnboundPq: an artifact's own key is never enough.
  def resolve_pq_key(identity, artifact_pk, holder_pq: nil, pq_pins: nil, trusted_pk: nil)
    return PinnedPq.mint(trusted_pk, 'trusted') if trusted_pk.is_a?(String) && !trusted_pk.empty?
    return nil unless artifact_pk.is_a?(String) && !artifact_pk.empty?

    if pq_pins.is_a?(Hash) && identity.is_a?(String) && pq_pins.key?(identity)
      return pq_pins[identity] == artifact_pk ? PinnedPq.mint(artifact_pk, 'pin') : nil
    end
    return PinnedPq.mint(artifact_pk, 'holder-commitment') if holder_pq.is_a?(String) && holder_pq_commitment(artifact_pk) == holder_pq

    nil
  end

  def mldsa65_verify_pinned(pq, msg, sig_b64u)
    return false unless pq.is_a?(PinnedPq)

    mldsa65_verify_b64u(pq.key, msg, sig_b64u)
  end

  # The ONE suite dispatch: `sig` / `pq_sig` of `p` under its suite, the Ed25519 half (if any) under `ed_pub` and checked
  # FIRST (R6-API-04), the PQ half under `pq_pk_b64u`. FAIL-CLOSED: unsupported / unknown suite or any bad part => false.
  def suite_dispatch(p, ed_pub, msg, pq_pk_b64u)
    suite, = resolve_suite(p)
    return false if suite.nil?

    _, _, _, prim, nested = SIG_SUITES[suite]
    sig = p['sig']
    return verify_b64u(ed_pub, msg, sig) if prim.nil?
    return false unless pq_pk_b64u.is_a?(String)
    return pq_verify_b64u(prim, pq_pk_b64u, msg, sig) unless suite.start_with?('hybrid-')
    return false unless verify_b64u(ed_pub, msg, sig)

    pq_msg = msg
    if nested
      ed_sig = b64d(sig, ED25519_SIGNATURE_BYTES)
      return false if ed_sig.nil?

      pq_msg = msg.b + ed_sig
    end
    pq_verify_b64u(prim, pq_pk_b64u, pq_msg, p['pq_sig'])
  rescue StandardError
    false
  end

  # Verify `p`'s signature(s) under its suite. FAIL-CLOSED. The PQ half verifies ONLY under `pq` (a PinnedPq), never under p['pq_pk'].
  def verify_suite(p, holder, msg, pq)
    return false unless pq.nil? || pq.is_a?(PinnedPq)

    suite_dispatch(p, holder, msg, pq&.key)
  end

  # Verify a signature under the ARTIFACT'S OWN `pq_pk`. Only for surfaces whose key is authorised elsewhere (threshold shares,
  # the pq_artifact conformance primitives): it proves nothing about who issued `p`. The chain and the PCActn leaf never call
  # it; they resolve their key through `resolve_pq_key`.
  def verify_leaf_suite(p, holder, msg)
    verify_suite(p, holder, msg, resolve_pq_key(nil, p['pq_pk'], trusted_pk: p['pq_pk']))
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

      row = { 'publicKey' => e['publicKey'], 'role' => e['role'] }
      row['pq_pk'] = e['pq_pk'] if e['pq_pk'].is_a?(String) # additive: a registered PQ key is part of the bound set
      row
    end
    entries.sort_by! { |e| [e['role'].b, e['publicKey'].b] }
    sha(SIGNERSET_DOMAIN + canon_bytes(entries))
  rescue Malformed
    nil # a string that is not valid UTF-8 has no canonical form
  end

  # Verify a threshold share's signature over `msg` under its suite (ed25519 by default; ml-dsa-65 / hybrid
  # dispatch identically to the leaf). FAIL-CLOSED: unknown suite or bad key/sig => false.
  def verify_share_suite(share, msg)
    suite_dispatch(share, share['publicKey'], msg, share['pq_pk'])
  end

  # Verify a threshold share against the v2.1 binding. The bound message is RECOMPUTED here from
  # (role, thresholdMessage, signer_set, t) — the vector's precomputed `share_message` / `signer_set_hash`
  # are NOT trusted — then `share.sig` must verify over it. FAIL-CLOSED: any missing / ill-typed field, bad
  # base64url, t not in {1,2,3}, or unknown share suite returns false (never accepted). This is exactly why
  # the pre-v2.1 bare-threshold-message agent share and a cross-signer-set replay are rejected.
  THRESHOLD_ROLES = %w[agent guardian principal].freeze
  # Registered PQ public-key lengths of every suite (ml-dsa-65/87, slh-dsa-128f/256s, fn-dsa-512/1024, less-cat1),
  # implemented here or not: the signer set is validated exactly like the reference.
  PQ_PK_LENGTHS = [1952, 2592, 32, 64, 897, 1793, 97_484].freeze

  # R6-03: validate the WHOLE signer set like the reference (verifyThreshold / Threshold.dfy BuildReg) and return
  # { role => [publicKey, pq_pk_or_nil] }, or nil if it is malformed: every entry a Hash with a known role and a
  # canonical 32-byte base64url publicKey; a PRESENT pq_pk (JSON null is present) canonical base64url of a registered
  # PQ key length; one key per role, one role per key; a duplicate (role, key) entry only with the same pq_pk.
  def signer_registry(signer_set)
    return nil unless signer_set.is_a?(Array)

    reg = {}
    role_of_key = {}
    signer_set.each do |e|
      return nil unless e.is_a?(Hash)

      role = e['role']
      pk = e['publicKey']
      return nil unless role.is_a?(String) && THRESHOLD_ROLES.include?(role) && pk.is_a?(String) && !b64d(pk, 32).nil?

      pq = nil
      if e.key?('pq_pk')
        pq = e['pq_pk']
        raw = pq.is_a?(String) ? b64d(pq) : nil
        return nil if raw.nil? || !PQ_PK_LENGTHS.include?(raw.bytesize)
      end
      if reg.key?(role)
        return nil unless reg[role] == [pk, pq] # two keys for one role, or a conflicting pq_pk

        next
      end
      return nil if role_of_key.fetch(pk, role) != role # one key under two roles

      reg[role] = [pk, pq]
      role_of_key[pk] = role
    end
    reg
  end

  # Verify a threshold share against the v2.1 binding. The bound message is RECOMPUTED here from
  # (role, thresholdMessage, signer_set, t); the WHOLE signer set is validated first (R6-03), `t` must be 1, 2
  # or 3 (R6-04), the share must be for the ONE key the set registers for `role`, and a role that registers a
  # pq_pk needs a PQ / hybrid share verified ONLY under that registered key (R6-02). TOTAL and FAIL-CLOSED
  # (R6-05): any malformed input (of any JSON shape) returns false, never raises.
  def verify_threshold_share(entry)
    return false unless entry.is_a?(Hash)

    role = entry['role']
    t = entry['t']
    t = t.to_i if t.is_a?(Float) && t.finite? && t == t.to_i # JS number semantics: 1.0 == 1
    return false unless role.is_a?(String)
    return false unless t.is_a?(Integer) && [1, 2, 3].include?(t)

    tmsg = b64d(entry['threshold_message'])
    return false if tmsg.nil?

    reg = signer_registry(entry['signer_set'])
    return false if reg.nil?

    ssh = signer_set_hash(entry['signer_set'])
    return false if ssh.nil?

    share = entry['share']
    return false unless share.is_a?(Hash) && share['role'].is_a?(String) && share['role'] == role
    return false unless reg.key?(role)

    reg_pk, reg_pq = reg[role]
    return false unless share['publicKey'] == reg_pk

    suite, = resolve_suite(share)
    return false if suite.nil?
    # A share that NAMES a pq_pk must name exactly its role's registered one (any suite; a role registering none has
    # nothing it could equal). The key used is always the registered one.
    return false if share.key?('pq_pk') && (!reg_pq.is_a?(String) || share['pq_pk'] != reg_pq)
    # R6-02: a role that registers a pq_pk REQUIRES a PQ (pure or hybrid) share; an ed25519-only share for it
    # is refused (otherwise an Ed25519 break would still forge the role).
    return false if suite == 'ed25519' && !reg_pq.nil?

    tag = ''.b
    if suite != 'ed25519'
      return false unless reg_pq.is_a?(String)

      share = share.merge('pq_pk' => reg_pq) # verify ONLY under the registered PQ key
      tag = "\x00atlas-pca/share-suite/v1\x00#{suite}".b
    end
    bound = "atlas-pca/share/#{role}\x00".b + sha(tmsg) + ssh + [t].pack('C') + tag
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
    body = { 'issuer' => c['issuer'], 'holder' => c['holder'], 'caveats' => c['caveats'], 'parent' => c['parent'] }
    body['holder_pq'] = c['holder_pq'] if c.key?('holder_pq')
    body
  end

  HOLDER_PQ_DOMAIN = "atlas-pca/holder-pq/v1\0".b.freeze

  def holder_pq_commitment(pq_pk)
    b64e(Digest::SHA256.digest(HOLDER_PQ_DOMAIN + pq_pk.dup.force_encoding('UTF-8').b))
  end

  # allowedSuites policy (absent `alg` == ed25519). nil == no policy; [] refuses everything. Returns reason or nil.
  def suite_policy_error(alg, label, allowed)
    return nil if allowed.nil?

    a = alg.nil? ? 'ed25519' : alg
    return nil if a.is_a?(String) && allowed.include?(a)

    "#{label}: signature suite '#{a}' is not allowed by this verifier's suite policy"
  end

  # F-2: a PQ-carrying suite is accepted only under a pq_pk the signer's holder committed to (holder_pq).
  def pq_binding_error(alg, pq_pk, committed, label)
    a = alg.nil? ? 'ed25519' : alg
    return nil unless a.is_a?(String) && SIG_SUITES.key?(a) && SIG_SUITES[a][1]

    unless committed.is_a?(String)
      return "#{label}: suite '#{a}' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)"
    end
    return "#{label}: pq_pk does not match the signer's committed holder_pq (F-2)" unless pq_pk.is_a?(String) && holder_pq_commitment(pq_pk) == committed

    nil
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

  def check_sig(c, signer, label, pq = nil)
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
    # under the resolved `pq` key (never the hop's own pq_pk); the signer is the expected Ed25519 key.
    return "#{label}: bad signature (not signed by expected key)" unless verify_suite(c, signer, msg, pq)

    ''
  end

  # True when a chain breaks the shared caveat caps. Reads raw array lengths only: runs BEFORE any hashing/signature work.
  def caveat_limit_exceeded?(chain)
    total = 0
    chain.each do |c|
      cv = c.is_a?(Hash) ? c['caveats'] : nil
      n = cv.is_a?(Array) ? cv.length : 0
      return true if n > MAX_CAVEATS_PER_HOP

      total += n
      return true if total > MAX_CAVEATS_PER_CHAIN
    end
    false
  end

  ROOT_PQ_PIN_REASON = "hop 0: root suite '%s' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant " \
                       "(policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)"
  ROOT_PQ_PIN_MISMATCH_REASON = "hop 0: root suite '%s': the server-side PQ pin for the root issuer (policy.pqPins) does not match " \
                                "the stored grant's pq_pk (fail closed)"

  # The root hop has no parent holding a holder_pq commitment, so a non-ed25519 root's PQ key must come from a verifier-side
  # authority: the verifier's stored copy of this very grant (trusted_root, same content hash) or a pin for root.issuer.
  # Returns [PinnedPq or nil, reason or nil]; mirrors rootPq in capability.ts. The decision is keyed on the REGISTERED suite
  # (resolveSigAlg in the reference), not on whether this runtime's OpenSSL has it: a PQ root without a verifier-side
  # authority gets the pin reason on every host; one that passes is still refused (unsupported_suite) at the signature.
  def resolve_root_pq(root, pq_pins, trusted_root)
    suite = root.key?('alg') ? root['alg'] : 'ed25519'
    return [nil, nil] if !suite.is_a?(String) || !REGISTERED_SUITES.include?(suite) || suite == 'ed25519'

    pk = root['pq_pk']
    trusted = nil
    if !trusted_root.nil? && pk.is_a?(String)
      begin
        trusted = pk if cap_hash(trusted_root) == cap_hash(root)
      rescue StandardError
        trusted = nil
      end
    end
    # 0.4.2 fail closed: with the stored grant AND a pin for the issuer, both must agree (the grant never overrides a pin).
    issuer = root['issuer']
    if !trusted.nil? && pq_pins.is_a?(Hash) && issuer.is_a?(String) && pq_pins.key?(issuer) && pq_pins[issuer] != trusted
      return [nil, format(ROOT_PQ_PIN_MISMATCH_REASON, suite)]
    end
    key = resolve_pq_key(issuer, pk, pq_pins: pq_pins, trusted_pk: trusted)
    key.nil? ? [nil, format(ROOT_PQ_PIN_REASON, suite)] : [key, nil]
  end

  # Returns [reason, ok]. A non-ed25519 (pure-PQ or hybrid) ROOT is accepted only if `pq_pins[root.issuer]` equals the root's
  # `pq_pk`, or `trusted_root` is the root itself (the verifier's own stored grant); otherwise it is refused (R4-01).
  def verify_chain(chain, expected_root_issuer, have_issuer, allowed_suites = nil, pq_pins = nil, trusted_root = nil)
    verify_chain_unchecked(chain, expected_root_issuer, have_issuer, allowed_suites, pq_pins, trusted_root)
  rescue StandardError => e
    # TOTAL (R6-05): a hostile chain is a refusal, never an exception.
    ["malformed capability chain: #{e.class}", false]
  end

  # Mirrors `wellTyped` in capability.ts: id/issuer/holder/body_digest/sig Strings; alg/pq_pk/pq_sig/holder_pq/parent
  # absent or Strings (JSON null is NOT absent); caveats an Array of Hashes each with a String `type`. A correctly
  # SIGNED but ill-typed hop is refused like in the reference.
  def hop_well_typed?(c)
    return false unless c.is_a?(Hash)
    return false unless %w[id issuer holder body_digest sig].all? { |k| c[k].is_a?(String) }
    return false unless %w[alg pq_pk pq_sig holder_pq parent].all? { |k| !c.key?(k) || c[k].is_a?(String) }

    c['caveats'].is_a?(Array) && c['caveats'].all? { |cv| cv.is_a?(Hash) && cv['type'].is_a?(String) }
  end

  def verify_chain_unchecked(chain, expected_root_issuer, have_issuer, allowed_suites, pq_pins, trusted_root)
    return ['empty chain', false] unless chain.is_a?(Array) && !chain.empty?
    return ["chain longer than #{MAX_CHAIN_HOPS} capabilities", false] if chain.length > MAX_CHAIN_HOPS
    return [CAVEAT_LIMIT_REASON, false] if caveat_limit_exceeded?(chain)

    root = chain[0]
    return ['hop 0: malformed capability', false] unless hop_well_typed?(root)
    return ['hop 0: root must not have a parent', false] if root.key?('parent')
    if have_issuer && root['issuer'] != expected_root_issuer
      return ['hop 0: root issuer is not the expected principal', false]
    end

    pe = suite_policy_error(root['alg'], 'hop 0', allowed_suites)
    return [pe, false] if pe

    root_pq, rerr = resolve_root_pq(root, pq_pins, trusted_root)
    return [rerr, false] if rerr

    e = check_sig(root, root['issuer'].is_a?(String) ? root['issuer'] : '', 'hop 0', root_pq)
    return [e, false] unless e.empty?

    (1...chain.length).each do |i|
      parent = chain[i - 1]
      c = chain[i]
      label = "hop #{i}"
      return ["#{label}: malformed capability", false] unless hop_well_typed?(c)
      return ["#{label}: broken parent link", false] if c['parent'] != cap_hash(parent)
      return ["#{label}: issuer is not the parent's bound holder", false] if c['issuer'] != parent['holder']

      pe = suite_policy_error(c['alg'], label, allowed_suites) || pq_binding_error(c['alg'], c['pq_pk'], parent['holder_pq'], label)
      return [pe, false] if pe

      e = check_sig(c, parent['holder'].is_a?(String) ? parent['holder'] : '', label,
                    resolve_pq_key(parent['holder'], c['pq_pk'], holder_pq: parent['holder_pq']))
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
                    zk_compliance bond_ref threshold alg pq_pk pq_sig intent intent_session fresh_at].freeze
  ACTION_KEYS = %w[verb resource params_digest reversibility_class].freeze
  PLAN_REQUIRED = %w[root inclusion_proof node_id].freeze
  PROOF_KEYS = %w[index size path].freeze
  HOP_REQUIRED = %w[id issuer holder body_digest caveats sig].freeze
  # B4 crypto-agility (additive) on a hop exactly as at the top level: absent `alg` == ed25519, in which
  # case `pq_pk`/`pq_sig` MUST be absent and the hop is BYTE-IDENTICAL to the pre-B4 wire.
  HOP_OPTIONAL = %w[parent alg pq_pk pq_sig holder_pq].freeze

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

    return false if c.key?('holder_pq') && !b32?(c['holder_pq'])

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
    # Intent Layer M2 (SIGNED): the `envelope.intent` slot, when present, is the closed five-member object.
    return false if p.key?('intent') && !intent_wire_error(p['intent']).nil?
    # Intent Layer v2 (SIGNED): the `intent_session` member, when present, passes rule 13's closed wire shape.
    return false if p.key?('intent_session') && !validate_intent_session_wire(p['intent_session']).nil?

    # Consistency token (SIGNED): the `fresh_at` member, when present, passes its closed wire shape (fresh_at.rb).
    return false if p.key?('fresh_at') && !validate_fresh_at_wire(p['fresh_at']).nil?

    th = p['threshold']
    return true unless p.key?('threshold')
    return false unless th.is_a?(Hash)

    sh = th['shares']
    # `threshold` must be {shares:[...]} (reference: wire.ts); a missing/null `shares` is a wire failure, not a pass.
    return false unless sh.is_a?(Array) && sh.all? do |s|
      # 0.4.1: the share signature is validated PER SUITE (it used to be a fixed 64 bytes, so a pure post-quantum share
      # could never be carried).
      s.is_a?(Hash) && s['role'].is_a?(String) && b32?(s['publicKey']) && validate_share_signature_wire(s).nil?
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
  # Suite capability: the `unsupported_suite: <alg>` reason of a wire refusal caused by a registered suite this runtime cannot
  # verify (leaf, capability hop or threshold share), else nil.
  def wire_unsupported_suite(p)
    return nil unless p.is_a?(Hash)

    objs = [p]
    objs.concat(p['cap_chain'].select { |h| h.is_a?(Hash) }) if p['cap_chain'].is_a?(Array)
    th = p['threshold']
    objs.concat(th['shares'].select { |h| h.is_a?(Hash) }) if th.is_a?(Hash) && th['shares'].is_a?(Array)
    objs.each do |o|
      _, err = resolve_suite(o)
      return err if err&.start_with?(UNSUPPORTED_SUITE)
    end
    nil
  end

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

  # ======================= PCA-Action header (0.4.1) =======================
  # Decode a `PCA-Action` header value to the PCActn JSON text (a UTF-8 String), or nil. STRICT, like decodePcaHeader in
  # packages/pca/src/adapters.ts: non-empty; unpadded base64url alphabet only (A-Z a-z 0-9 - _), no `=`, no `+`/`/`, no
  # whitespace anywhere (nothing is stripped), length % 4 != 1, zero unused trailing bits; and the bytes must be valid
  # UTF-8 (no overlong forms, surrogates or truncated sequences). A leading BOM is kept (the strict JSON parser refuses
  # it). Nothing is normalized, so one PCActn has exactly one header spelling.
  def decode_pca_header(value)
    return nil unless value.is_a?(String) && !value.empty?

    bin = b64d(value)
    return nil if bin.nil?

    text = bin.dup.force_encoding(Encoding::UTF_8)
    text.valid_encoding? ? text : nil
  end

  # ======================= policy-layer caveat helpers (0.4.1) =======================
  # The core verifier (verify_pcactn) and RackMiddleware do NOT evaluate caveats. A resource server that enforces a grant's
  # caveats calls evaluate_caveats(policy_caveats(grant, chain), ctx) with its own action params. 0.4.1 security fix (the
  # TypeScript policy layer): caveats on the ROOT grant outside the envelope are enforced exactly like delegated ones; this
  # helper pair includes them.
  ENVELOPE_CAVEAT = 'envelope'
  REVERSIBILITY_ORDER = %w[reversible rate_limited irreversible].freeze

  # Every caveat the policy layer evaluates for an action under `grant` delegated along `chain` (root first), like
  # policyCaveats in packages/pca/src/policy-vm.ts: the grant's caveats without its FIRST `envelope` caveat (order kept),
  # then the caveats the hops appended (`leaf['caveats']` beyond the grant's, leaf = the last chain element). A grant whose
  # `caveats` is not an Array hands that value through (evaluate_caveats refuses it).
  def policy_caveats(grant, chain = nil)
    cs = grant.is_a?(Hash) ? grant['caveats'] : nil
    return cs unless cs.is_a?(Array)

    i = cs.index { |c| c.is_a?(Hash) && c['type'] == ENVELOPE_CAVEAT }
    root = i.nil? ? cs.dup : cs[0...i] + cs[(i + 1)..]
    leaf = chain.is_a?(Array) && !chain.empty? ? chain[-1] : nil
    lc = leaf.is_a?(Hash) ? leaf['caveats'] : nil
    lc.is_a?(Array) ? root + (lc[cs.length..] || []) : root
  end

  # Evaluate a caveat list against an action context. Returns [ok, failed]: ok iff every caveat is satisfied; failed = the
  # unsatisfied caveats' `type` strings in order ('<malformed>' when `type` is not a String). A non-Array list gives
  # [false, ['<malformed caveats>']]. Total: never raises. Fail closed: a type this evaluator does not implement (note,
  # envelope, resource_prefix, predicates, tool_schema, ...) is unsatisfied.
  # `ctx` is a JSON object Hash with String keys: now (epoch ms), delegation_depth?, blast_radius?, reversibility_class?,
  # recent_action_times?, action {verb, resource, reversibility_class, params}. Numbers are Integer / Float (finite). Semantics
  # mirror agentNativeCaveatEvaluator + envelopeCaveatEvaluator (packages/pca/src):
  #  - max_spend {usd}: usd finite >= 0; ctx.action.params (a Hash) has an own finite `amount` with 0 <= amount <= usd, and an
  #    own `currency`, when present, is exactly "usd" or "USD". Does not need `now`.
  #  - everything below needs a finite ctx.now: expires {at} now < at; not_before {at} now >= at; rate {max, per_secs} fewer
  #    than max entries t of recent_action_times with now - per_secs*1000 < t <= now; max_blast_radius {max} blast_radius <=
  #    max; reversibility_max {class} ctx.reversibility_class no more severe than class; delegation_depth {max} depth <= max;
  #    budget_alloc {limit} limit finite >= 0; intent_session {session, seq, root, prev?} (Intent Layer v2) satisfied iff
  #    well-formed (intent_session_caveat_error is nil): it constrains nothing per action.
  def evaluate_caveats(caveats, ctx)
    return [false, ['<malformed caveats>']] unless caveats.is_a?(Array)

    failed = []
    caveats.each do |cv|
      ok = begin
        caveat_satisfied?(cv, ctx)
      rescue StandardError
        false
      end
      next if ok

      t = cv.is_a?(Hash) ? cv['type'] : nil
      failed << (t.is_a?(String) ? t : '<malformed>')
    end
    [failed.empty?, failed]
  end

  # A finite JSON number (Integer, or a finite Float), else nil. true/false are not numbers.
  def finite_num(x)
    f = if x.is_a?(Integer) then x.to_f # as a JSON number reads: a huge integer lexeme is a non-finite double
        elsif x.is_a?(Float) then x
        end
    f&.finite? ? f : nil
  end

  # The action's spend in USD as max_spend reads it (own params.amount, finite >= 0, currency absent / "usd" / "USD").
  def action_spend_usd(action)
    return nil unless action.is_a?(Hash)

    params = action['params']
    return nil unless params.is_a?(Hash) && params.key?('amount')

    amount = finite_num(params['amount'])
    return nil if amount.nil? || amount.negative?
    return nil if params.key?('currency') && params['currency'] != 'usd' && params['currency'] != 'USD'

    amount
  end

  def caveat_satisfied?(cv, ctx)
    return false unless cv.is_a?(Hash) && ctx.is_a?(Hash)

    type = cv['type']
    if type == 'max_spend'
      lim = finite_num(cv['usd'])
      return false if lim.nil? # a negative limit admits nothing: every readable spend is >= 0

      spend = action_spend_usd(ctx['action'])
      return !spend.nil? && spend <= lim
    end
    now = finite_num(ctx['now'])
    return false if now.nil?

    case type
    when 'expires'
      at = finite_num(cv['at'])
      !at.nil? && now < at
    when 'not_before'
      at = finite_num(cv['at'])
      !at.nil? && now >= at
    when 'rate'
      max = finite_num(cv['max'])
      per = finite_num(cv['per_secs'])
      times = ctx['recent_action_times']
      return false if max.nil? || per.nil? || per <= 0 || !times.is_a?(Array)

      lo = now - (per * 1000)
      times.count { |t| (tf = finite_num(t)) && tf > lo && tf <= now } < max
    when 'max_blast_radius'
      max = finite_num(cv['max'])
      br = finite_num(ctx['blast_radius'])
      !max.nil? && !br.nil? && br <= max
    when 'reversibility_max'
      cls = cv['class']
      cur = ctx['reversibility_class']
      # strict types without a separate guard: REVERSIBILITY_ORDER holds only Strings, so a non-String class has no index
      li = REVERSIBILITY_ORDER.index(cls)
      ci = REVERSIBILITY_ORDER.index(cur)
      !li.nil? && !ci.nil? && ci <= li
    when 'delegation_depth'
      max = finite_num(cv['max'])
      d = finite_num(ctx['delegation_depth'])
      !max.nil? && !d.nil? && d <= max
    when 'budget_alloc'
      lim = finite_num(cv['limit'])
      !lim.nil? && lim >= 0
    when 'intent_session'
      # Intent Layer v2 session binding (rule 13): no per-action constraint here; satisfied iff well-formed.
      intent_session_caveat_error(cv).nil?
    else
      false
    end
  end

  # ======================= Intent Layer M2: envelope.intent =======================
  # Normative rules: packages/pca/src/intent-binding.ts and conformance/README.md "Intent binding". The optional
  # top-level `intent` slot is SIGNED (part of the canonical body). The `intent` check runs after `counter` and is
  # reported iff the PCActn carries `intent` OR the verifier's intent policy is ACTIVE; otherwise the verdict is the
  # pre-M2 one.
  INTENT_GOAL_PREFIX = 'pca-intent:v1:'
  # Intent Layer v2 session grants (G_0 and the delta grants D_k): `pca-intent:v2:<session>:<map_digest>` (rule 13).
  INTENT_GOAL_V2_PREFIX = 'pca-intent:v2:'
  # Intent Layer v2 session grants over a COMMITTED map (rule 19): `pca-intent:v2c:<session>:<map_commit>`.
  INTENT_GOAL_V2C_PREFIX = 'pca-intent:v2c:'
  # Goal binding v3: `pca-intent:v3:<goal_digest>:<policy_digest>` (the signed Goal IR plus the compiled policy).
  INTENT_GOAL_V3_PREFIX = 'pca-intent:v3:'
  INTENT_GOAL_COMMIT_DOMAIN = "atlas-pca/goal/v1\x00"
  PPM_ONE = 1_000_000
  MAX_INTENT_GOAL_SALT_LEN = 128
  ENVELOPE_INTENT_FIELDS = %w[ref map_digest goal_salt fidelity_ppm residual_risk_ppm].freeze

  # Wire validation of the `intent` slot: nil when well-formed, else a short reason. Every step is type-guarded, so it
  # does not raise on any JSON value (and wire_ok? rescues anyway).
  def intent_wire_error(v)
    return "'intent' must be an object" unless v.is_a?(Hash)

    unknown = v.keys.find { |k| !ENVELOPE_INTENT_FIELDS.include?(k) }
    return "unknown field 'intent.#{unknown}'" unless unknown.nil?

    missing = ENVELOPE_INTENT_FIELDS.find { |k| !v.key?(k) }
    return "missing field 'intent.#{missing}'" unless missing.nil?
    return "'intent.ref' is not canonical base64url (32 bytes)" unless b32?(v['ref'])
    return "'intent.map_digest' is not canonical base64url (32 bytes)" unless b32?(v['map_digest'])

    gs = v['goal_salt']
    unless utf8_string?(gs) && !gs.empty? && gs.bytesize <= MAX_INTENT_GOAL_SALT_LEN
      return "'intent.goal_salt' must be a non-empty string (<= 128 UTF-8 bytes)"
    end

    fp = v['fidelity_ppm']
    return "'intent.fidelity_ppm' must be a safe integer in [0, 1000000]" unless safe_int?(fp) && fp >= 0 && fp <= PPM_ONE

    rr = v['residual_risk_ppm']
    return "'intent.residual_risk_ppm' must be a non-negative safe integer" unless safe_int?(rr) && rr >= 0

    nil
  end

  # The goal string that binds a grant to an intent statement (and optionally an Intent Map).
  def intent_goal(ref, map_digest = nil)
    INTENT_GOAL_PREFIX + ref + (map_digest.nil? || map_digest.empty? ? '' : ":#{map_digest}")
  end

  # The goal commitment an `envelope.intent` claims the root grant carries. `session` (Intent Layer v2, rule 13 amends
  # rule 12 step 2): when the PCActn carries a wire-valid `intent_session`, the goal is the v2 session goal
  # "pca-intent:v2:" + session + ":" + map_digest instead of the v1 goal; with `map_form` "commit" (rule 19) the goal is
  # "pca-intent:v2c:" + session + ":" + map_digest (the map commitment).
  def intent_goal_commit(ref, map_digest, goal_salt, session = nil, map_form = nil)
    prefix = map_form == 'commit' ? INTENT_GOAL_V2C_PREFIX : INTENT_GOAL_V2_PREFIX
    goal = session.nil? ? intent_goal(ref, map_digest) : "#{prefix}#{session}:#{map_digest}"
    hash_canonical({ 'd' => INTENT_GOAL_COMMIT_DOMAIN, 'goal' => goal, 'salt' => goal_salt })
  end

  # A well-formed `approved_goal`: a closed object of exactly `goal_digest` and `policy_digest`, both canonical
  # base64url of 32 bytes (String or Symbol keys).
  def approved_goal_ref?(v)
    return false unless v.is_a?(Hash) && v.length == 2

    r = v.transform_keys(&:to_s)
    r.length == 2 && b32?(r['goal_digest']) && b32?(r['policy_digest'])
  end

  # The goal v3 string. Raises ArgumentError on a malformed digest: never commit to garbage.
  def intent_goal_v3(ref)
    raise ArgumentError, 'intent_goal_v3: goal_digest and policy_digest must be canonical base64url (32 bytes)' unless approved_goal_ref?(ref)

    r = ref.transform_keys(&:to_s)
    "#{INTENT_GOAL_V3_PREFIX}#{r['goal_digest']}:#{r['policy_digest']}"
  end

  # The goal v3 commitment for a salt (same domain and hash as intent_goal_commit).
  def intent_goal_commit_v3(ref, goal_salt)
    hash_canonical({ 'd' => INTENT_GOAL_COMMIT_DOMAIN, 'goal' => intent_goal_v3(ref), 'salt' => goal_salt })
  end

  # A policy Hash with String keys (Symbol keys are accepted too), or nil when `policy` is not a Hash.
  def normalize_intent_policy(policy)
    policy.is_a?(Hash) ? policy.transform_keys(&:to_s) : nil
  end

  # True iff the policy is active: `require` is exactly true, or a threshold key or `approved_goal` is present.
  def intent_policy_active?(policy)
    pol = normalize_intent_policy(policy)
    !pol.nil? && (pol['require'] == true || pol.key?('min_fidelity_ppm') || pol.key?('max_residual_risk_ppm') ||
                  pol.key?('approved_goal'))
  end

  # RAW JSON TEXT as the platform JSON parser of the reference reads it (conformance README "Raw JSON text members":
  # `pcactn_json` aside, every `*_json` member: `context.intent_policy_json`, a primitive's `input_json`, the diff-fuzz
  # driver's JSON-encoded members). The library's own tokenizer, in a lax mode: any top-level value, every number taken by
  # its binary64 value (`1.0` / `1e6` / an integer beyond 2^53-1 are Floats; a bare `-0`, `-0.0`, `-0e0` are negative
  # zero, which Ruby's JSON would turn into Integer 0), a duplicate key keeps the last value. Numbers are recognised only
  # as tokens, so text inside strings and keys (`":-0,"`) is never touched. Raises Malformed on invalid JSON.
  def parse_json_text(text)
    JsonParser.new(text, false, false, json_text: true).parse_document
  rescue SystemStackError
    raise Malformed, 'nesting too deep'
  end

  # An intent policy from raw JSON TEXT (conformance `intent_policy_json`): parse_json_text (a non-Hash is no policy).
  def parse_intent_policy_json(text) = parse_json_text(text)

  # A policy threshold as an Integer, or nil when misconfigured. Valid iff its NUMERIC VALUE is a safe integer >= 0: an
  # Integer, or an integral Float such as 950000.0 / 1e6; not -0.0, NaN/Infinity, a fraction, > 2^53-1, nil/bool/String.
  def intent_threshold(x)
    return x if x.is_a?(Integer) && x >= 0 && x <= MAX_SAFE
    return nil unless x.is_a?(Float) && x.finite? && x == x.floor && x >= 0 && x <= MAX_SAFE
    return nil if (1.0 / x).negative? # x >= 0 here, so only -0.0 gives -Infinity

    x.to_i
  end

  # The root grant's goal commitment: the FIRST `envelope` caveat's String `goal_commit`, else nil.
  def root_goal_commit(grant)
    return nil unless grant.is_a?(Hash) && grant['caveats'].is_a?(Array)

    env = grant['caveats'].find { |c| c.is_a?(Hash) && c['type'] == 'envelope' }
    env && env['goal_commit'].is_a?(String) ? env['goal_commit'] : nil
  end

  # The `intent` check (rules 0-4). `intent` is the wire-validated slot (nil when absent); `session` the PCActn's
  # `intent_session.session` when it carries one (the v2 goal). Returns [:absent, nil], [:pass, nil] or [:fail, reason].
  # Never raises.
  def decide_intent_binding(intent, grant, policy = nil, session = nil, map_form = nil)
    active = intent_policy_active?(policy)
    return [:absent, nil] if intent.nil? && !active

    pol = normalize_intent_policy(policy) || {}
    lo = intent_threshold(pol['min_fidelity_ppm']) # nil when unset or misconfigured
    hi = intent_threshold(pol['max_residual_risk_ppm'])
    if (pol.key?('min_fidelity_ppm') && lo.nil?) || (pol.key?('max_residual_risk_ppm') && hi.nil?)
      return [:fail, 'intent policy misconfigured: thresholds must be non-negative safe integers (fail closed)']
    end
    v3 = pol.key?('approved_goal')
    if v3 && !approved_goal_ref?(pol['approved_goal'])
      return [:fail, 'intent policy misconfigured: approved_goal digests must be canonical base64url (32 bytes) (fail closed)']
    end
    return [:fail, 'this verifier requires an intent binding but the PCActn carries none'] if intent.nil?

    commit = root_goal_commit(grant)
    return [:fail, 'the root grant carries no envelope goal commitment to bind the intent to'] if commit.nil?
    if v3
      if intent_goal_commit_v3(pol['approved_goal'], intent['goal_salt']) != commit
        return [:fail, "the root grant's goal commitment does not open to the approved goal and compiled policy (v3)"]
      end
    elsif intent_goal_commit(intent['ref'], intent['map_digest'], intent['goal_salt'], session, map_form) != commit
      return [:fail, "intent ref / map_digest / goal_salt do not open the root grant's goal commitment"]
    end
    if lo && intent['fidelity_ppm'] < lo
      return [:fail, "intent fidelity #{intent['fidelity_ppm']} ppm is below the policy minimum #{lo}"]
    end
    if hi && intent['residual_risk_ppm'] > hi
      return [:fail, "intent residual risk #{intent['residual_risk_ppm']} ppm exceeds the policy maximum #{hi}"]
    end

    [:pass, nil]
  rescue StandardError => e
    [:fail, "intent binding error (fail closed): #{e.message}"]
  end

  # ======================= PCActn =======================
  def threshold_message(p)
    # `sig`, `threshold` and the B4 `pq_sig` are unsigned (stripped); `alg`/`pq_pk` ARE signed.
    body = p.reject { |k, _| k == 'sig' || k == 'threshold' || k == 'pq_sig' }
    SIG_DOMAIN + sha(canon_bytes(body))
  end

  # pcactn: parsed Hash OR raw JSON text (String) which MUST pass the strict profile (failure == wire).
  # Returns Verdict. Wire failure is terminal: checks == { 'wire' => false }.
  # intent_policy (Intent Layer M2): optional Hash { 'require' => bool, 'min_fidelity_ppm' => Integer,
  # 'max_residual_risk_ppm' => Integer } (String or Symbol keys, all optional). The `intent` check is reported (after
  # `counter`) iff the PCActn carries `intent` or the policy is active.
  # intent_v2 (Intent Layer v2): optional Hash (String keys) of verifier state + policy: policy {session {require,
  # max_revocation_age_s}, schema {closed_world}}, params, schema {docs, keys}, session {root, grants, revocation {epoch,
  # proofs}}, layers, acc {state, monitors, receipts, last_seq, sequencer_keys}, wb {artifacts, policy}. The v2 checks
  # (schema, intent_session, layers, accumulators, facts, provenance, classes; see decide_intent_v2) follow `intent`, each
  # reported only when the PCActn carries `intent_session` or a v2 policy is active; allow requires all reported ones.
  def verify_pcactn(pcactn, grant, now:, audience:, allowed_suites: nil, intent_policy: nil, intent_v2: nil, fresh_at: nil)
    verify_pcactn_unchecked(pcactn, grant, now: now, audience: audience, allowed_suites: allowed_suites,
                                           intent_policy: intent_policy, intent_v2: intent_v2, fresh_at: fresh_at)
  rescue StandardError => e
    # TOTAL (R6-05): a residual fault on hostile input is a terminal wire refusal, never an exception.
    Verdict.new(false, { 'wire' => false }, "wire: malformed input (#{e.class})")
  end

  def verify_pcactn_unchecked(pcactn, grant, now:, audience:, allowed_suites: nil, intent_policy: nil, intent_v2: nil, fresh_at: nil)
    if pcactn.is_a?(String)
      # FIRST: before any parsing (String#bytesize is the raw byte length)
      return Verdict.new(false, { 'wire' => false }, "wire: #{ARTIFACT_SIZE_REASON}") if pcactn.bytesize > MAX_ARTIFACT_BYTES

      begin
        pcactn = parse_json(pcactn)
      rescue Malformed
        return Verdict.new(false, { 'wire' => false }, 'wire: strict JSON profile violation')
      end
    end
    unless wire_ok?(pcactn)
      return Verdict.new(false, { 'wire' => false }, "wire: #{wire_unsupported_suite(pcactn) || 'malformed PCActn'}")
    end

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
      elsif caveat_limit_exceeded?(chain)
        false
      elsif cap_hash(chain[0]) != cap_hash(grant)
        false
      else
        gi = grant['issuer']
        verify_chain(chain, gi, gi.is_a?(String), allowed_suites, nil, grant).last # chain[0] == grant was checked above
      end
    end

    # grant_ref_bound (normative): the signed grant_ref MUST be a non-empty string byte-equal to the id of the ROOT
    # capability of the presented chain (cap_chain[0].id). Independent of the chain verdict; fail-closed on an
    # empty / malformed chain. Replay state is keyed on grant_ref, so it must not be attacker-chosen.
    run.call('grant_ref_bound', 'grant_ref is not the id of the root capability in cap_chain') do
      gref = pcactn['grant_ref']
      root_id = chain.is_a?(Array) && chain[0].is_a?(Hash) ? chain[0]['id'] : nil
      gref.is_a?(String) && !gref.empty? && root_id.is_a?(String) && gref == root_id
    end

    plan = pcactn['plan']
    run.call('plan_inclusion', 'action is not a node of the committed plan') do
      cond = plan.key?('conditions_digest') ? plan['conditions_digest'] : conditions_digest(nil, nil)
      verify_inclusion(plan['root'], plan['inclusion_proof'], plan_leaf(plan['node_id'], pcactn['action'], cond))
    end

    run.call('leaf_signature', 'signature does not verify under the leaf holder key') do
      if chain.empty?
        false
      else
        lerr = suite_policy_error(pcactn['alg'], 'leaf', allowed_suites) ||
               pq_binding_error(pcactn['alg'], pcactn['pq_pk'], chain[-1]['holder_pq'], 'leaf')
        lerr.nil? && verify_suite(pcactn, chain[-1]['holder'], threshold_message(pcactn),
                                  resolve_pq_key(chain[-1]['holder'], pcactn['pq_pk'], holder_pq: chain[-1]['holder_pq']))
      end
    end

    run.call('counter_format', 'missing or not a non-negative safe integer') { safe_int?(pcactn['counter']) && pcactn['counter'] >= 0 }

    # Intent Layer M2: `intent` check (present iff the PCActn carries `intent` or the policy is active).
    # Intent Layer v2 (rule 13 amends rule 12 step 2): a wire-valid `intent_session` makes the goal the v2 session goal.
    session = pcactn.key?('intent_session') ? pcactn['intent_session']['session'] : nil
    map_form = pcactn.key?('intent_session') ? pcactn['intent_session']['map_form'] : nil
    intent_status, intent_why = decide_intent_binding(pcactn['intent'], grant, intent_policy, session, map_form)

    CHECK_ORDER.each { |k| checks[k] = false unless checks.key?(k) }
    ordered = CHECK_ORDER.to_h { |k| [k, checks[k]] }
    unless intent_status == :absent
      ordered['intent'] = intent_status == :pass
      reason = "intent: #{intent_why}" if intent_status == :fail && reason.empty?
    end
    # Intent Layer v2: schema (14), intent_session (13), layers (V5), accumulators (15), facts / provenance / classes
    # (16-18), each reported only when the PCActn carries `intent_session` or a v2 policy is active.
    v2 = decide_intent_v2(pcactn, grant, intent_v2, now)
    # Consistency token: `fresh_at`, after the intent checks; reported only when the PCActn carries the member, a side-carried
    # token is read, or the policy requires one (otherwise absent: byte-identical to before).
    fa = decide_fresh_at(pcactn, fresh_at, now)
    v2_checks = fa.nil? ? v2['checks'] : v2['checks'] + [fa]
    all_reasons = fold_escalation(reason.empty? ? [] : [reason], v2_checks, {})['reasons']
    v2_checks.each do |c|
      ordered[c['name']] = c['ok'] ? true : false
      reason = "#{c['name']}: #{c['reason'] || 'rejected'}" if !c['ok'] && reason.empty?
    end
    degraded = v2['legacy_model_polarity'] ? { 'tighten' => "model_polarity 'legacy': a grant reads a model-derived value in where (rule 21)" } : nil
    Verdict.new(ordered.values.all?, ordered, reason, all_reasons, degraded)
  end
end

# Intent Layer v2 (each file reopens module AtlasPca): W-A rules 13-15 and the pipeline (intent_v2), W-B rules 16-18
# (intent_wb), the predicate DSL and its regex engine (predicates, safe_regex) and the V5 ceilings (intent_layers).
require_relative 'atlas_pca/less_ffi'
require_relative 'atlas_pca/safe_regex'
require_relative 'atlas_pca/predicates'
require_relative 'atlas_pca/intent_layers'
require_relative 'atlas_pca/intent_wb'
require_relative 'atlas_pca/intent_v2'
require_relative 'atlas_pca/actions'
require_relative 'atlas_pca/actions_registry'
# 0.5: the ternary decision, escalation answers and the full authorize() pipeline (opt-in; verify_pcactn is unchanged).
require_relative 'atlas_pca/decision'
require_relative 'atlas_pca/forbid_certificate'
require_relative 'atlas_pca/policy_link'
require_relative 'atlas_pca/fresh_at'
require_relative 'atlas_pca/pca_grant'
require_relative 'atlas_pca/blueprint'
require_relative 'atlas_pca/k4'
require_relative 'atlas_pca/runtime_claim'
require_relative 'atlas_pca/a2a'
require_relative 'atlas_pca/workflow'
require_relative 'atlas_pca/readside'
require_relative 'atlas_pca/read_vault'
require_relative 'atlas_pca/lease'
require_relative 'atlas_pca/break_glass'
require_relative 'atlas_pca/missing_context'
require_relative 'atlas_pca/policy_classes'
require_relative 'atlas_pca/obligations'
require_relative 'atlas_pca/k3'
require_relative 'atlas_pca/escalation'
require_relative 'atlas_pca/approval'
require_relative 'atlas_pca/passport'
require_relative 'atlas_pca/ledger'
require_relative 'atlas_pca/optimistic'
require_relative 'atlas_pca/intent_history'
require_relative 'atlas_pca/mesh'
require_relative 'atlas_pca/revocation_staleness'
require_relative 'atlas_pca/assurance'
require_relative 'atlas_pca/authorize'
require_relative 'atlas_pca/atomic_kv'
require_relative 'atlas_pca/plan_lifecycle'
require_relative 'atlas_pca/operations'
require_relative 'atlas_pca/stepup'
require_relative 'atlas_pca/store_conformance'
require_relative 'atlas_pca/caveat_lang'
require_relative 'atlas_pca/provenance_gate'
require_relative 'atlas_pca/refusal_help'
require_relative 'atlas_pca/protect'
require_relative 'atlas_pca/agent'
