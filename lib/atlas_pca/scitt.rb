# frozen_string_literal: true

require 'openssl'

# SCITT transparency receipts for Proof-Carrying Authority: RFC 9943 Signed Statements and RFC 9942 COSE Receipts over an
# RFC 9162 SHA-256 Merkle log, with a strict deterministic CBOR codec (RFC 8949 4.2.1) sufficient for COSE_Sign1. Mirrors
# the TypeScript reference (@atlasauth/pca-scitt).
#
# CBOR values: nil, true/false, Integer (safe integers only), a UTF-8 String (text), a BINARY String (byte string), Array,
# Hash (Integer or text keys) and CborTag. Keys: EdDSA takes a 32-byte seed (signing) or a 32-byte public key (verifying);
# any key may also be an OpenSSL::PKey (or DER). ES256 (ECDSA P-256) takes an OpenSSL::PKey::EC. Everything fails closed.
# Options are String-keyed Hashes in snake_case.
module AtlasPca
  module Scitt
    # `code` carries a stable reference error code where the reference has one (e.g. ERR_ENCODING_INVALID_ENCODED_DATA).
    class Error < StandardError
      attr_reader :code

      def initialize(message = nil, code = nil)
        super(message)
        @code = code
      end
    end

    CborTag = Struct.new(:tag, :value)

    COSE_SIGN1_TAG = 18
    HDR_ALG = 1
    HDR_CONTENT_TYPE = 3
    HDR_CWT_CLAIMS = 15
    CWT_ISS = 1
    CWT_SUB = 2
    HDR_VDS = 395
    HDR_VDS_PROOFS = 396
    VDS_RFC9162_SHA256 = 1
    PROOF_TYPE_INCLUSION = -1
    DEFAULT_CONTENT_TYPE = 'application/pca+json'
    ALG_LABEL = { 'EdDSA' => -8, 'ES256' => -7 }.freeze
    P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    P256_HALF_N = P256_N >> 1
    MAX_CBOR_DEPTH = 512 # native stricter: the reference recurses until the engine's stack runs out

    module_function

    # ---- numbers (the reference's single JS number type) ----

    def num?(v) = v.is_a?(Integer) || v.is_a?(Float)
    def neg_zero?(v) = v.is_a?(Float) && v.zero? && (1.0 / v).negative?

    # `Number.isSafeInteger` as an Integer (nil when it is not one); negative zero is an integer here, callers refuse it.
    def safe_int(v)
      case v
      when Integer then v.abs <= MAX_SAFE ? v : nil
      when Float then v.finite? && v == v.floor && v.abs <= MAX_SAFE ? v.to_i : nil
      end
    end

    def int?(v) = !safe_int(v).nil? && !neg_zero?(v)
    def bytes?(v) = v.is_a?(String) && v.encoding == Encoding::BINARY

    # ---- RFC 9162 Merkle tree ----

    def raw(b)
      raise Error, 'expected bytes' unless bytes?(b)

      b
    end

    def sha(*parts) = OpenSSL::Digest::SHA256.digest(parts.join.b)
    def empty_root = sha
    def leaf_hash(entry) = sha("\x00".b, raw(entry))
    def node_hash(left, right) = sha("\x01".b, raw(left), raw(right))

    def split_point(n)
      k = 1
      k *= 2 while k * 2 < n
      k
    end

    # MTH over already-hashed leaves (RFC 9162 2.1.1).
    def tree_hash(leaf_hashes)
      n = leaf_hashes.length
      return empty_root if n.zero?
      return leaf_hashes[0] if n == 1

      k = split_point(n)
      node_hash(tree_hash(leaf_hashes[0, k]), tree_hash(leaf_hashes[k..]))
    end

    # Inclusion path for leaf `index` (RFC 9162 2.1.3.1), bottom-up.
    def inclusion_path(leaf_hashes, index)
      n = leaf_hashes.length
      i = safe_int(index)
      raise Error, 'rfc9162: leaf index out of range' if i.nil? || i.negative? || i >= n
      return [] if n == 1

      k = split_point(n)
      if i < k
        inclusion_path(leaf_hashes[0, k], i) + [tree_hash(leaf_hashes[k..])]
      else
        inclusion_path(leaf_hashes[k..], i - k) + [tree_hash(leaf_hashes[0, k])]
      end
    end

    # Recompute the root from a leaf hash and its path (RFC 9162 2.1.3.2); nil for an invalid (index, size, path).
    def root_from_inclusion_path(leaf, index, size, path)
      i = safe_int(index)
      n = safe_int(size)
      return nil if i.nil? || n.nil? || i.negative? || neg_zero?(index) || n < 1 || i >= n
      return nil if leaf.bytesize != 32 || path.any? { |p| p.bytesize != 32 }

      fn = i
      sn = n - 1
      r = leaf.b
      path.each do |p|
        return nil if sn.zero?

        if fn.odd? || fn == sn
          r = node_hash(p, r)
          if fn.even?
            while fn.even? && fn != 0
              fn >>= 1
              sn >>= 1
            end
          end
        else
          r = node_hash(r, p)
        end
        fn >>= 1
        sn >>= 1
      end
      sn.zero? ? r : nil
    end

    def verify_inclusion_path(leaf, index, size, path, root)
      computed = root_from_inclusion_path(leaf, index, size, path)
      !computed.nil? && computed == root.b
    end

    def subproof(m, d, complete)
      n = d.length
      return complete ? [] : [tree_hash(d)] if m == n

      k = split_point(n)
      if m <= k
        subproof(m, d[0, k], complete) + [tree_hash(d[k..])]
      else
        subproof(m - k, d[k..], false) + [tree_hash(d[0, k])]
      end
    end

    # Consistency proof between the first `m` leaves and all of `leaf_hashes` (RFC 9162 2.1.4.1).
    def consistency_path(leaf_hashes, m)
      i = safe_int(m)
      raise Error, 'rfc9162: consistency size out of range' if i.nil? || i < 1 || i > leaf_hashes.length

      subproof(i, leaf_hashes, true)
    end

    # ECMAScript ToInt32 (the reference tests `first & (first - 1)` with a 32-bit bitwise AND).
    def i32(x)
      x &= 0xFFFFFFFF
      x >= (1 << 31) ? x - (1 << 32) : x
    end

    # RFC 9162 2.1.4.2. A proof from an empty tree is rejected.
    def verify_consistency_path(first, second, first_root, second_root, path)
      a = safe_int(first)
      b = safe_int(second)
      return false if a.nil? || b.nil? || a < 1 || b < a
      return false if first_root.bytesize != 32 || second_root.bytesize != 32 || path.any? { |p| p.bytesize != 32 }
      return path.empty? && first_root.b == second_root.b if a == b
      return false if path.empty?

      nodes = path.map(&:b)
      nodes.unshift(first_root.b) if (i32(a) & i32(a - 1)).zero? # first is an exact power of two
      fn = a - 1
      sn = b - 1
      while fn.odd?
        fn >>= 1
        sn >>= 1
      end
      fr = sr = nodes[0]
      nodes[1..].each do |c|
        return false if sn.zero?

        if fn.odd? || fn == sn
          fr = node_hash(c, fr)
          sr = node_hash(c, sr)
          if fn.even?
            while fn.even? && fn != 0
              fn >>= 1
              sn >>= 1
            end
          end
        else
          sr = node_hash(sr, c)
        end
        fn >>= 1
        sn >>= 1
      end
      sn.zero? && fr == first_root.b && sr == second_root.b
    end

    # ---- deterministic CBOR ----

    def head(major, arg)
      mt = major << 5
      if arg < 24 then [mt | arg].pack('C')
      elsif arg < 0x100 then [mt | 24, arg].pack('CC')
      elsif arg < 0x10000 then [mt | 25, arg].pack('Cn')
      elsif arg < 0x100000000 then [mt | 26, arg].pack('CN')
      else [mt | 27, arg].pack('CQ>')
      end
    end

    def encode_text(s)
      raise Error, 'cbor: text string contains a lone surrogate' unless s.valid_encoding?

      b = s.b
      head(3, b.bytesize) + b
    end

    def encode_key(k)
      if num?(k)
        raise Error, 'cbor: bad integer map key' unless int?(k)

        k = k.to_i
        return k >= 0 ? head(0, k) : head(1, -1 - k)
      end
      raise Error, 'cbor: bad map key' unless k.is_a?(String) && !bytes?(k)

      encode_text(k)
    end

    # Deterministically encode a CBOR value. Raises Error on anything outside the supported profile.
    def encode(v, depth = 0)
      raise Error, 'cbor: nesting too deep' if depth > MAX_CBOR_DEPTH

      case v
      when nil then "\xF6".b
      when false then "\xF4".b
      when true then "\xF5".b
      when Integer, Float
        raise Error, 'cbor: only safe-integer numbers are supported' unless int?(v)

        n = v.to_i
        n >= 0 ? head(0, n) : head(1, -1 - n)
      when String then bytes?(v) ? head(2, v.bytesize) + v : encode_text(v)
      when Array then head(4, v.length) + v.map { |x| encode(x, depth + 1) }.join.b
      when Hash
        entries = v.map { |k, val| [encode_key(k), encode(val, depth + 1)] }.sort_by { |e| e[0] }
        (1...entries.length).each { |i| raise Error, 'cbor: duplicate map key' if entries[i - 1][0] == entries[i][0] }
        head(5, v.length) + entries.map { |k, val| k + val }.join.b
      when CborTag
        raise Error, 'cbor: bad tag' if !int?(v.tag) || v.tag.negative?

        head(6, v.tag.to_i) + encode(v.value, depth + 1)
      else raise Error, 'cbor: unsupported value'
      end
    end

    class Reader
      attr_reader :pos, :buf

      def initialize(buf)
        @buf = buf
        @pos = 0
      end

      def byte
        raise Error, 'cbor: unexpected end of input' if @pos >= @buf.bytesize

        b = @buf.getbyte(@pos)
        @pos += 1
        b
      end

      def take(n)
        raise Error, 'cbor: unexpected end of input' if @pos + n > @buf.bytesize

        s = @buf.byteslice(@pos, n)
        @pos += n
        s
      end

      def uint(n)
        v = 0
        n.times { v = (v * 256) + byte }
        raise Error, 'cbor: integer out of safe range' if v > MAX_SAFE

        v
      end

      def head
        ib = byte
        major = ib >> 5
        info = ib & 0x1F
        raise Error, 'cbor: unsupported simple/float value' if major == 7 && info >= 24
        return [major, info] if info < 24

        [[24, 1, 24], [25, 2, 0x100], [26, 4, 0x10000], [27, 8, 0x100000000]].each do |code, n, floor|
          next unless info == code

          arg = uint(n)
          raise Error, 'cbor: non-minimal integer' if arg < floor

          return [major, arg]
        end
        raise Error, 'cbor: unsupported additional information (indefinite/reserved)'
      end

      def value(depth = 0)
        raise Error, 'cbor: nesting too deep' if depth > MAX_CBOR_DEPTH

        major, arg = head
        case major
        when 0 then arg
        when 1
          raise Error, 'cbor: integer out of safe range' if (-1 - arg).abs > MAX_SAFE

          -1 - arg
        when 2 then take(arg).b
        when 3
          s = take(arg).dup.force_encoding(Encoding::UTF_8)
          raise Error.new('The encoded data was not valid for encoding utf-8', 'ERR_ENCODING_INVALID_ENCODED_DATA') unless s.valid_encoding?

          s
        when 4 then arg.times.map { value(depth + 1) } # not Array.new(arg): a huge claimed length must fail on the missing bytes
        when 5 then map(arg, depth)
        when 6 then CborTag.new(arg, value(depth + 1))
        else
          return false if arg == 20
          return true if arg == 21
          return nil if arg == 22

          raise Error, 'cbor: unsupported simple/float value'
        end
      end

      def map(count, depth)
        out = {}
        prev = nil
        count.times do
          start = @pos
          key = value(depth + 1)
          raise Error, 'cbor: map key must be int or text' unless key.is_a?(Integer) || (key.is_a?(String) && !AtlasPca::Scitt.bytes?(key))

          kb = @buf.byteslice(start, @pos - start)
          raise Error, 'cbor: map keys not canonically ordered / duplicate' if !prev.nil? && (prev <=> kb) >= 0

          prev = kb
          out[key] = value(depth + 1)
        end
        out
      end
    end

    # Strictly decode ONE canonical CBOR value; the whole buffer must be consumed.
    def decode(data)
      raise Error, 'cbor: input must be bytes' unless bytes?(data)

      r = Reader.new(data)
      v = r.value
      raise Error, 'cbor: trailing bytes' if r.pos != data.bytesize

      v
    end

    # ---- signature suites (EdDSA, ES256) ----

    def pkey_of(key)
      case key
      when OpenSSL::PKey::PKey then key
      when String then OpenSSL::PKey.read(key)
      else raise Error, 'not a usable key'
      end
    end

    def ed_pkey?(k) = k.is_a?(OpenSSL::PKey::PKey) && !k.is_a?(OpenSSL::PKey::EC) && !k.is_a?(OpenSSL::PKey::RSA) && k.oid == 'ED25519'

    def ed_public_raw(key)
      return key.b if bytes?(key) && key.bytesize == 32

      k = pkey_of(key)
      raise Error, 'not an Ed25519 public key' unless ed_pkey?(k)

      k.raw_public_key
    end

    def ec_key(key)
      k = pkey_of(key)
      raise Error, 'not a P-256 key' unless k.is_a?(OpenSSL::PKey::EC) && k.group.curve_name == 'prime256v1'

      k
    end

    # A 64-byte IEEE-P1363 signature with 0 < r < n and 0 < s <= n/2 (low-S).
    def canonical_es256?(sig)
      return false if sig.bytesize != 64

      r = sig.byteslice(0, 32).unpack1('H*').to_i(16)
      s = sig.byteslice(32, 32).unpack1('H*').to_i(16)
      r.positive? && r < P256_N && s.positive? && s <= P256_HALF_N
    end

    def sign_bytes(alg, key, msg)
      if alg == 'EdDSA'
        k = bytes?(key) && key.bytesize == 32 ? OpenSSL::PKey.new_raw_private_key('ED25519', key) : pkey_of(key)
        raise Error, 'not an Ed25519 private key' unless ed_pkey?(k)

        return k.sign(nil, msg)
      end
      seq = OpenSSL::ASN1.decode(ec_key(key).sign('SHA256', msg))
      r, s = seq.value.map { |i| i.value.to_i }
      s = P256_N - s if s > P256_HALF_N # low-S: a statement has exactly one valid signature form
      [r, s].map { |x| [format('%064x', x)].pack('H*') }.join
    end

    def verify_bytes(alg, key, msg, sig, allow_high_s = false)
      return AtlasPca::Ed25519Strict.verify(ed_public_raw(key), msg, sig) if alg == 'EdDSA'
      # ECDSA is malleable: a high-S variant would be a second, distinct Merkle leaf for the same statement.
      return false if !allow_high_s && !canonical_es256?(sig)
      return false if allow_high_s && sig.bytesize != 64

      pub = ec_key(key)
      der = OpenSSL::ASN1::Sequence([sig.byteslice(0, 32), sig.byteslice(32, 32)].map { |x| OpenSSL::ASN1::Integer(OpenSSL::BN.new(x, 2)) }).to_der
      pub.verify('SHA256', der, msg)
    rescue OpenSSL::OpenSSLError
      false
    end

    # The COSE_Sign1 Sig_structure (RFC 9052 4.4), external_aad empty.
    def sig_structure(protected_bytes, payload) = encode(['Signature1', protected_bytes, ''.b, payload])

    # ---- Signed Statements ----

    # Sign a PCActn / verdict as a COSE Signed Statement (COSE_Sign1) whose payload is the strict canonical JSON of `payload`.
    # opts: 'subject' (present, even nil, adds the sub claim), 'content_type'.
    def sign_statement(payload, alg, key, issuer, opts = {})
      label = alg.is_a?(String) ? ALG_LABEL[alg] : nil
      ct = opts['content_type']
      claims = { CWT_ISS => issuer }
      claims[CWT_SUB] = opts['subject'] if opts.key?('subject')
      prot = { HDR_ALG => label, HDR_CONTENT_TYPE => ct.nil? ? DEFAULT_CONTENT_TYPE : ct, HDR_CWT_CLAIMS => claims }
      protected_bytes = encode(prot) # an unsupported alg leaves a nil label that no verifier accepts: refuse here
      raise Error, 'cbor: unsupported value' if label.nil?

      payload_bytes = AtlasPca.canon_bytes(payload)
      sig = sign_bytes(alg, key, sig_structure(protected_bytes, payload_bytes))
      encode(CborTag.new(COSE_SIGN1_TAG, [protected_bytes, {}, payload_bytes, sig]))
    end

    # Decode and structurally validate a COSE_Sign1 (tag 18); payload is nil when detached. Raises on any deviation.
    def decode_cose_sign1(data)
      top = decode(data)
      raise Error, 'cose: not a COSE_Sign1 (tag 18)' unless top.is_a?(CborTag) && top.tag == COSE_SIGN1_TAG

      arr = top.value
      raise Error, 'cose: malformed COSE_Sign1 array' unless arr.is_a?(Array) && arr.length == 4

      protected_bytes, unprotected, payload, signature = arr
      raise Error, 'cose: protected must be a bstr' unless bytes?(protected_bytes)
      raise Error, 'cose: unprotected must be a map' unless unprotected.is_a?(Hash)
      raise Error, 'cose: payload must be a bstr or nil' unless bytes?(payload) || payload.nil?
      raise Error, 'cose: signature must be a bstr' unless bytes?(signature)

      pm = protected_bytes.empty? ? {} : decode(protected_bytes)
      raise Error, 'cbor: expected a map' unless pm.is_a?(Hash)

      { 'protectedBytes' => protected_bytes, 'protectedMap' => pm, 'unprotected' => unprotected, 'payload' => payload, 'signature' => signature }
    end

    def alg_of(protected_map)
      raise Error, 'cose: missing alg header' unless protected_map.key?(HDR_ALG)

      label = protected_map[HDR_ALG]
      alg = label == -8 ? 'EdDSA' : label == -7 ? 'ES256' : nil
      raise Error, 'cose: unsupported alg' unless num?(label) && alg

      alg
    end

    # Verify a Signed Statement and say WHY it failed (malformed / missing alg header / unsupported alg / detached payload /
    # non-canonical signature (high-S) / bad signature). Never raises. opts: 'allow_high_s'.
    def check_statement(statement, public_key, opts = {})
      high = (opts || {})['allow_high_s'] == true
      begin
        s = decode_cose_sign1(statement)
      rescue StandardError => e
        return { 'ok' => false, 'reason' => "malformed: #{e.message}" }
      end
      return { 'ok' => false, 'reason' => 'detached payload' } if s['payload'].nil?

      begin
        alg = alg_of(s['protectedMap'])
      rescue StandardError => e
        return { 'ok' => false, 'reason' => e.message.include?('missing') ? 'missing alg header' : 'unsupported alg' }
      end
      begin
        msg = sig_structure(s['protectedBytes'], s['payload'])
        return { 'ok' => true } if verify_bytes(alg, public_key, msg, s['signature'], high)
        if alg == 'ES256' && !canonical_es256?(s['signature']) && verify_bytes(alg, public_key, msg, s['signature'], true)
          return { 'ok' => false, 'reason' => 'non-canonical signature (high-S)' }
        end

        { 'ok' => false, 'reason' => 'bad signature' }
      rescue StandardError
        { 'ok' => false, 'reason' => 'bad signature' }
      end
    end

    def verify_statement(statement, public_key, opts = {}) = check_statement(statement, public_key, opts)['ok']

    # The canonical payload bytes carried by a Signed Statement. Raises on a malformed or detached statement.
    def statement_payload(statement)
      payload = decode_cose_sign1(statement)['payload']
      raise Error, 'cose: statement payload is detached' if payload.nil?

      payload
    end

    # The b64u leaf a statement occupies in the transparency log.
    def statement_leaf(statement) = AtlasPca.b64e(statement.b)

    # ---- inclusion proof codec (RFC 9162) ----

    # Sibling sides (leaf -> root) for `index` in a tree of `size` leaves (RFC 6962 split).
    def sibling_sides(index, size)
      out = []
      idx = index
      n = size
      while n > 1
        k = split_point(n)
        if idx < k
          out << 'R'
          n = k
        else
          out << 'L'
          idx -= k
          n -= k
        end
      end
      out.reverse
    end

    def proof_hashes(proof)
      raise Error, 'scitt: proof path must be an array' unless proof.is_a?(Hash) && proof['path'].is_a?(Array)

      proof['path'].map do |step|
        h = step.is_a?(Hash) ? AtlasPca.b64d(step['hash'], 32) : nil
        raise Error, 'scitt: proof step hash is not a 32-byte b64u hash' unless h

        h
      end
    end

    def encode_inclusion_proof(proof) = encode([proof['size'], proof['index'], proof_hashes(proof)])

    # Decode an RFC 9162 inclusion proof into {index, size, path: [{side, hash}]} (sides re-derived).
    def decode_inclusion_proof(data)
      v = decode(data)
      raise Error, 'scitt: malformed inclusion proof' unless v.is_a?(Array) && v.length == 3

      size, index, sibs = v
      raise Error, 'scitt: proof size/index must be integers' unless num?(size) && num?(index)
      raise Error, 'scitt: proof size/index out of range' if safe_int(size).nil? || safe_int(index).nil? || size < 1 || index.negative? || index >= size
      raise Error, 'scitt: inclusion path must be an array' unless sibs.is_a?(Array)

      sides = sibling_sides(index, size)
      raise Error, 'scitt: inclusion path length does not match (index,size)' if sibs.length != sides.length

      path = sibs.zip(sides).map do |h, side|
        raise Error, 'scitt: inclusion path entry must be a 32-byte bstr' unless bytes?(h) && h.bytesize == 32

        { 'side' => side, 'hash' => AtlasPca.b64e(h) }
      end
      { 'index' => index, 'size' => size, 'path' => path }
    end

    # ---- COSE Receipts (RFC 9942) ----

    # A signed COSE Receipt for `proof` against ledger root `root` (b64u, 32 bytes); the payload is detached (nil).
    # opts: 'issuer' (present adds the iss claim).
    def build_receipt(root, proof, alg, key, opts = {})
      root_bytes = AtlasPca.b64d(root, 32)
      raise Error, 'scitt: tree root is not a 32-byte b64u hash' unless root_bytes

      label = alg.is_a?(String) ? ALG_LABEL[alg] : nil
      prot = { HDR_ALG => label, HDR_VDS => VDS_RFC9162_SHA256 }
      prot[HDR_CWT_CLAIMS] = { CWT_ISS => opts['issuer'] } if opts.key?('issuer')
      protected_bytes = encode(prot)
      raise Error, 'cbor: unsupported value' if label.nil?

      unprotected = { HDR_VDS_PROOFS => { PROOF_TYPE_INCLUSION => [encode_inclusion_proof(proof)] } }
      sig = sign_bytes(alg, key, sig_structure(protected_bytes, root_bytes))
      encode(CborTag.new(COSE_SIGN1_TAG, [protected_bytes, unprotected, nil, sig]))
    end

    def decode_receipt(receipt)
      cose = decode_cose_sign1(receipt)
      vds = cose['protectedMap'][HDR_VDS]
      raise Error, 'scitt: receipt is not RFC9162_SHA256' unless num?(vds) && vds == VDS_RFC9162_SHA256
      raise Error, 'scitt: receipt payload (root) must be 32 bytes' if !cose['payload'].nil? && cose['payload'].bytesize != 32

      proofs = cose['unprotected'][HDR_VDS_PROOFS]
      raise Error, 'scitt: missing verifiable-data-structure-proofs' unless proofs.is_a?(Hash)

      inclusion = proofs[PROOF_TYPE_INCLUSION]
      raise Error, 'scitt: missing inclusion proof' unless inclusion.is_a?(Array) && !inclusion.empty?
      raise Error, 'scitt: inclusion proof must be a bstr' unless bytes?(inclusion[0])

      { 'cose' => cose, 'proof' => decode_inclusion_proof(inclusion[0]) }
    end

    # Verify a COSE Receipt for a Signed Statement; fail closed (never raises). At least one anchor ('tree_root' and/or
    # 'verification_key') is required; the inclusion proof must bind the EXACT statement bytes to the receipt's root; a given
    # 'statement_key' also verifies the statement's own signature. A key that is present in opts is always checked: nil or an
    # empty key is refused, never skipped (only an omitted key means "no key"). opts: 'allow_high_s'.
    def verify_receipt(receipt, statement, opts = {})
      opts ||= {}
      tree_root = opts['tree_root']
      return false if tree_root.nil? && !opts.key?('verification_key') # no anchor

      dec = decode_receipt(receipt)
      proof = dec['proof']
      cose = dec['cose']
      root = root_from_inclusion_path(leaf_hash(statement), proof['index'], proof['size'], proof_hashes(proof))
      return false if root.nil?
      return false if !cose['payload'].nil? && cose['payload'] != root

      high = opts['allow_high_s'] == true
      if opts.key?('verification_key')
        alg = alg_of(cose['protectedMap'])
        return false unless verify_bytes(alg, opts['verification_key'], sig_structure(cose['protectedBytes'], root), cose['signature'], high)
      end
      return false if !tree_root.nil? && tree_root != AtlasPca.b64e(root)
      return false if opts.key?('statement_key') && !verify_statement(statement, opts['statement_key'], { 'allow_high_s' => high })

      true
    rescue StandardError
      false
    end

    # Verify an RFC 9942 / RFC 9162 consistency proof `[old size, new size, [+ bstr]]` between two pinned roots (b64u).
    def verify_consistency_proof(proof, old_root, new_root)
      v = decode(proof)
      return false unless v.is_a?(Array) && v.length == 3

      old_size, new_size, path = v
      return false unless num?(old_size) && num?(new_size) && path.is_a?(Array)
      return false unless path.all? { |h| bytes?(h) }

      r1 = AtlasPca.b64d(old_root, 32)
      r2 = AtlasPca.b64d(new_root, 32)
      return false if r1.nil? || r2.nil?

      verify_consistency_path(old_size, new_size, r1, r2, path)
    rescue StandardError
      false
    end
  end
end
