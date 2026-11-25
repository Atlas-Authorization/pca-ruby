# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require_relative '../atlas_pca'
require_relative 'ratchet_group'

module AtlasPca
  # FROST(Ed25519, SHA-512) threshold signing (RFC 9591): trusted-dealer key split, round-1 commit, round-2 sign, share-verified
  # aggregation and the in-process quorum cosign, native port of the TypeScript reference (@atlasauth/pca-core). The aggregate is an
  # ordinary RFC 8032 Ed25519 signature under the group key.
  #
  # Group and scalar arithmetic run in libsodium (>= 1.0.18, through ffi, bound lazily, fail closed with LoadError when missing):
  # points are 32-byte Ed25519 encodings, every secret scalar is a 32-byte binary String combined with
  # crypto_core_ed25519_scalar_*, never an Integer. Integers appear only for public values (participant identifiers and the
  # Lagrange coefficients derived from them). libsodium refuses the identity and every small-order or mixed-order point; the
  # identity (a zero scalar times a point) is carried as nil and encoded as the canonical identity encoding where the reference does.
  module Frost
    module Sodium
      FUNCS = {
        crypto_core_ed25519_is_valid_point: [[:buffer_in], :int],
        crypto_core_ed25519_add: [%i[buffer_out buffer_in buffer_in], :int],
        crypto_core_ed25519_sub: [%i[buffer_out buffer_in buffer_in], :int],
        crypto_core_ed25519_scalar_reduce: [%i[buffer_out buffer_in], :void],
        crypto_core_ed25519_scalar_add: [%i[buffer_out buffer_in buffer_in], :void],
        crypto_core_ed25519_scalar_mul: [%i[buffer_out buffer_in buffer_in], :void],
        crypto_scalarmult_ed25519_noclamp: [%i[buffer_out buffer_in buffer_in], :int],
        crypto_scalarmult_ed25519_base_noclamp: [%i[buffer_out buffer_in], :int]
      }.freeze
      LOCK = Mutex.new
      @bound = false

      def self.bind!
        return if @bound

        LOCK.synchronize do
          return if @bound

          begin
            require 'ffi'
          rescue LoadError => e
            raise LoadError, "FROST needs the ffi gem and libsodium (#{e.message})"
          end
          lib = Module.new
          lib.extend(FFI::Library)
          begin
            lib.ffi_lib(RatchetGroup::Sodium::LIBS)
          rescue LoadError => e
            raise LoadError, "FROST needs libsodium (apt: libsodium-dev, brew: libsodium): #{e.message}"
          end
          lib.attach_function(:sodium_init, [], :int)
          raise LoadError, 'libsodium could not be initialised' if lib.sodium_init.negative?

          FUNCS.each { |name, (args, ret)| lib.attach_function(name, args, ret) }
          @lib = lib
          @bound = true
        end
      end

      def self.method_missing(name, *args)
        return super unless FUNCS.key?(name)

        bind!
        @lib.public_send(name, *args)
      end

      def self.respond_to_missing?(name, priv = false) = FUNCS.key?(name) || super
    end

    L = RatchetGroup::L
    CONTEXT_STRING = 'FROST-ED25519-SHA512-v1'.b.freeze
    SPENT_COMMITMENT_CAP = 262_144
    ZERO = ("\0".b * 32).freeze
    IDENTITY_ENC = ("\x01".b + ("\0".b * 31)).freeze
    MAX_ID = 9_007_199_254_740_991
    SPENT = {} # rubocop:disable Style/MutableConstant
    SPENT_LOCK = Mutex.new

    module_function

    def buf(n = 32) = "\0".b * n

    # a bytes argument: a String (any encoding) read as its raw bytes
    def bin(x)
      raise TypeError, 'frost: expected bytes' unless x.is_a?(String)

      x.b
    end

    # ---- scalars: 32-byte little-endian strings
    def sc2(fn, a, b)
      r = buf
      Sodium.public_send(:"crypto_core_ed25519_scalar_#{fn}", r, bin(a), bin(b))
      r
    end

    def sc_add(a, b) = sc2(:add, a, b)
    def sc_mul(a, b) = sc2(:mul, a, b)

    # Reduce 0..64 little-endian bytes mod L (the reference's bytesToScalar); more than 64 bytes is refused.
    def reduce_bytes(b)
      b = bin(b)
      raise ArgumentError, 'frost: scalar input longer than 64 bytes' if b.bytesize > 64

      r = buf
      Sodium.crypto_core_ed25519_scalar_reduce(r, b + ("\0".b * (64 - b.bytesize)))
      r
    end

    # A PUBLIC integer (identifier, Lagrange coefficient) as a scalar.
    def int_scalar(i)
      v = i % L
      (0...32).map { |k| (v >> (8 * k)) & 0xFF }.pack('C*')
    end

    def scalar_to_bytes(s) = s.is_a?(String) ? reduce_bytes(s) : int_scalar(s)
    def bytes_to_scalar(b) = reduce_bytes(b)

    def le_int(b) = b.b.reverse.unpack1('H*').to_i(16)

    def canonical_scalar?(b) = b.is_a?(String) && b.bytesize == 32 && le_int(b) < L

    def id?(i) = i.is_a?(Integer) && i.positive? && i <= MAX_ID

    def h2s(m) = reduce_bytes(OpenSSL::Digest::SHA512.digest(m))
    def h1(m) = h2s(CONTEXT_STRING + 'rho'.b + bin(m))
    def h2(m) = h2s(bin(m))
    def h3(m) = h2s(CONTEXT_STRING + 'nonce'.b + bin(m))
    def h4(m) = OpenSSL::Digest::SHA512.digest(CONTEXT_STRING + 'msg'.b + bin(m))
    def h5(m) = OpenSSL::Digest::SHA512.digest(CONTEXT_STRING + 'com'.b + bin(m))

    # ---- points: 32-byte encodings; nil is the identity
    def enc(p) = p.nil? ? IDENTITY_ENC : p

    def mul_base(s)
      s = reduce_bytes(s)
      return nil if s == ZERO

      q = buf
      raise ArgumentError, 'frost: base-point multiplication refused' unless Sodium.crypto_scalarmult_ed25519_base_noclamp(q, s).zero?

      q
    end

    def mul_pt(p, s)
      s = reduce_bytes(s)
      return nil if p.nil? || s == ZERO

      q = buf
      raise ArgumentError, 'frost: point multiplication refused' unless Sodium.crypto_scalarmult_ed25519_noclamp(q, s, p).zero?

      q
    end

    def padd(a, b)
      return b if a.nil?
      return a if b.nil?

      r = buf
      raise ArgumentError, 'frost: point addition refused' unless Sodium.crypto_core_ed25519_add(r, a, b).zero?

      r == IDENTITY_ENC ? nil : r
    end

    # Group-law addition that accepts torsion points (nil when libsodium refuses an input), identity result included.
    def raw_add(a, b)
      r = buf
      Sodium.crypto_core_ed25519_add(r, a, b).zero? ? r : nil
    end

    # Canonical encoding, on the curve, not small order (so not the identity) and L*P = identity, by the group law alone. libsodium 1.0.20
    # and older accept a mixed-order point (P plus order-2 torsion) through is_valid_point, whose subgroup test reads only X of L*P.
    def safe_point?(b)
      return false unless b.is_a?(String) && b.bytesize == 32

      b = b.b
      return false unless raw_add(b, IDENTITY_ENC) == b

      q = b
      3.times { q = raw_add(q, q) or return false }
      return false if q == IDENTITY_ENC

      acc = IDENTITY_ENC
      (L.bit_length - 1).downto(0) do |i|
        acc = raw_add(acc, acc) or return false
        acc = raw_add(acc, b) or return false if L[i] == 1
      end
      acc == IDENTITY_ENC
    end

    # Strict check of any point a caller can influence: 32 bytes, canonical, on the curve, not small order (so not the identity),
    # in the prime-order subgroup. Returns the canonical encoding.
    def decode_safe_point(b)
      raise ArgumentError, 'frost: point must be 32 bytes' unless b.is_a?(String) && b.bytesize == 32

      b = b.b
      unless safe_point?(b) && Sodium.crypto_core_ed25519_is_valid_point(b) == 1
        raise ArgumentError, 'frost: point rejected (not canonical, off the curve, small order or not in the prime-order subgroup)'
      end

      b
    end

    def validate_commitments(lst, threshold = nil)
      raise ArgumentError, 'frost: empty commitment list' unless lst.is_a?(Array) && !lst.empty?

      unless threshold.nil?
        raise ArgumentError, 'frost: invalid threshold' unless id?(threshold)
        raise ArgumentError, "frost: need at least t=#{threshold} commitments (got #{lst.length})" if lst.length < threshold
      end
      seen = {}
      lst.each do |c|
        raise ArgumentError, 'frost: malformed commitment' unless c.is_a?(Hash)
        raise ArgumentError, 'frost: participant identifier must be a positive safe integer' unless id?(c['identifier'])
        raise ArgumentError, "frost: duplicate commitment identifier #{c['identifier']}" if seen.key?(c['identifier'])

        seen[c['identifier']] = true
        decode_safe_point(c['hiding'])
        decode_safe_point(c['binding'])
      end
    end

    # t-of-n split: {groupPublicKey, participantShares: [{identifier, share, publicKey}], groupCommitment}.
    def trusted_dealer_keygen(t, n, secret = nil, coefficients = nil, identifiers = nil)
      unless t.is_a?(Integer) && n.is_a?(Integer) && t >= 1 && t <= n
        raise ArgumentError, "frostTrustedDealerKeygen: need 1 <= t <= n (got t=#{t}, n=#{n})"
      end

      ids = identifiers.nil? ? (1..n).to_a : identifiers
      raise ArgumentError, 'frostTrustedDealerKeygen: identifiers.length must equal n' unless ids.length == n
      raise ArgumentError, 'frostTrustedDealerKeygen: identifiers must be distinct' unless ids.uniq.length == n
      raise ArgumentError, 'frostTrustedDealerKeygen: identifiers must be positive integers' unless ids.all? { |x| x.is_a?(Integer) && x.positive? }

      coeffs = [reduce_bytes(secret.nil? ? SecureRandom.random_bytes(32) : secret)]
      (1...t).each do |i|
        c = coefficients && i - 1 < coefficients.length ? coefficients[i - 1] : nil
        coeffs << reduce_bytes(c.nil? ? SecureRandom.random_bytes(32) : c)
      end
      shares = ids.map do |i|
        x = int_scalar(i)
        acc = ZERO
        coeffs.reverse_each { |a| acc = sc_add(sc_mul(acc, x), a) } # Horner on secret scalars
        { 'identifier' => i, 'share' => acc, 'publicKey' => enc(mul_base(acc)) }
      end
      commit_ = coeffs.map { |a| enc(mul_base(a)) }
      { 'groupPublicKey' => commit_[0], 'participantShares' => shares, 'groupCommitment' => commit_ }
    end

    def verifying_share(share) = enc(mul_base(reduce_bytes(share)))

    # Round 1: a fresh (hiding, binding) nonce pair and the public commitments.
    def commit(participant_share, hiding_randomness = nil, binding_randomness = nil)
      hr = hiding_randomness.nil? ? SecureRandom.random_bytes(32) : hiding_randomness
      br = binding_randomness.nil? ? SecureRandom.random_bytes(32) : binding_randomness
      [hr, br].each { |r| raise ArgumentError, 'frostCommit: nonce randomness must be 32 bytes' unless bin(r).bytesize == 32 }
      sk = reduce_bytes(participant_share['share'])
      hn = h3(hr.b + sk)
      bn = h3(br.b + sk)
      { 'hidingNonce' => hn, 'bindingNonce' => bn,
        'commitment' => { 'identifier' => participant_share['identifier'], 'hiding' => enc(mul_base(hn)), 'binding' => enc(mul_base(bn)) } }
    end

    def sorted(lst) = lst.sort_by { |c| c['identifier'] }

    def binding_factors(group_pk, lst, msg)
      e = lst.map { |c| int_scalar(c['identifier']) + bin(c['hiding']) + bin(c['binding']) }.join.b
      prefix = bin(group_pk) + h4(msg) + h5(e)
      lst.to_h { |c| [c['identifier'], h1(prefix + int_scalar(c['identifier']))] }
    end

    def group_commitment(lst, bf)
      r = nil
      lst.each { |c| r = padd(padd(r, decode_safe_point(c['hiding'])), mul_pt(decode_safe_point(c['binding']), bf[c['identifier']])) }
      r
    end

    # Lagrange coefficient at zero: public integers only.
    def lagrange(participants, i)
      raise ArgumentError, 'frost: identifier not in participant list' unless participants.include?(i)

      num = den = 1
      participants.each do |j|
        next if j == i

        num = num * j % L
        den = den * (j - i) % L
      end
      raise ArgumentError, 'frost: modular inverse of zero' if den.zero?

      lam = num * den.pow(L - 2, L) % L
      raise ArgumentError, 'frost: zero Lagrange coefficient' if lam.zero?

      int_scalar(lam)
    end

    # Round 2: this participant's signature share. One-shot: a nonce pair (and its public commitments) signs once, ever.
    def sign(identifier, share, group_public_key, nonces, message, signing_commitments, threshold = nil, verification_share = nil,
             verification_shares = nil)
      raise ArgumentError, 'frost: participant identifier must be a positive safe integer' unless id?(identifier)

      validate_commitments(signing_commitments, threshold)
      decode_safe_point(group_public_key)
      hn = bin(nonces['hiding'])
      bn = bin(nonces['binding'])
      raise ArgumentError, 'frostSign: zero/zeroized nonce' if hn.bytes.none? { |b| b != 0 } || bn.bytes.none? { |b| b != 0 }
      raise ArgumentError, 'frostSign: hiding and binding nonce must differ' if hn == bn

      lst = sorted(signing_commitments)
      mine = lst.find { |c| c['identifier'] == identifier }
      raise ArgumentError, 'frostSign: this identifier has no commitment in the set' if mine.nil?

      hiding = reduce_bytes(hn)
      binding = reduce_bytes(bn)
      sk = reduce_bytes(share)
      if enc(mul_base(hiding)) != bin(mine['hiding']) || enc(mul_base(binding)) != bin(mine['binding'])
        raise ArgumentError, 'frostSign: own commitment does not match nonces'
      end

      keys = ["h".b + bin(mine['hiding']), "b".b + bin(mine['binding'])]
      raise ArgumentError, 'frostSign: nonces already used (one-shot; reuse would leak the signing share)' if SPENT_LOCK.synchronize { keys.any? { |k| SPENT.key?(k) } }
      if !verification_share.nil? && enc(mul_base(sk)) != decode_safe_point(verification_share)
        raise ArgumentError, 'frostSign: share does not match verification share'
      end

      participants = lst.map { |c| c['identifier'] }
      unless verification_shares.nil?
        acc = nil
        participants.each do |pid|
          vs = verification_shares.find { |v| v['identifier'] == pid }
          raise ArgumentError, "frostSign: missing verification share for #{pid}" if vs.nil?

          acc = padd(acc, mul_pt(decode_safe_point(vs['publicKey']), lagrange(participants, pid)))
        end
        raise ArgumentError, 'frostSign: group public key does not match the verification shares' if enc(acc) != decode_safe_point(group_public_key)
      end
      bf = binding_factors(group_public_key, lst, message)
      r = group_commitment(lst, bf)
      c = h2(enc(r) + bin(group_public_key) + bin(message))
      z = sc_add(sc_add(hiding, sc_mul(binding, bf[identifier])), sc_mul(sc_mul(lagrange(participants, identifier), sk), c))
      SPENT_LOCK.synchronize do
        keys.each { |k| SPENT[k] = nil }
        SPENT.shift while SPENT.size > SPENT_COMMITMENT_CAP
      end
      { 'identifier' => identifier, 'sigShare' => z }
    end

    def verify_sig_share(identifier, public_key, commitment, sig_share, signing_commitments, group_public_key, message)
      validate_commitments(signing_commitments)
      lst = sorted(signing_commitments)
      bf = binding_factors(group_public_key, lst, message)
      return false unless bf.key?(identifier)

      r = group_commitment(lst, bf)
      comm_share = padd(decode_safe_point(commitment['hiding']), mul_pt(decode_safe_point(commitment['binding']), bf[identifier]))
      c = h2(enc(r) + bin(group_public_key) + bin(message))
      lam = lagrange(lst.map { |x| x['identifier'] }, identifier)
      return false unless canonical_scalar?(sig_share['sigShare'])

      lhs = mul_base(bin(sig_share['sigShare']))
      rhs = padd(comm_share, mul_pt(decode_safe_point(public_key), sc_mul(c, lam)))
      enc(lhs) == enc(rhs)
    rescue StandardError
      false
    end

    # Verify every signature share, sum them and return the 64-byte Ed25519 signature; raises unless it verifies.
    def aggregate(message, signing_commitments, sig_shares, group_public_key, verification_shares, threshold = nil)
      validate_commitments(signing_commitments, threshold)
      decode_safe_point(group_public_key)
      lst = sorted(signing_commitments)
      raise ArgumentError, 'frostAggregate: need exactly one signature share per commitment' unless sig_shares.is_a?(Array) && sig_shares.length == lst.length

      seen = {}
      sig_shares.each do |s|
        raise ArgumentError, 'frostAggregate: share from non-signer' unless lst.any? { |c| c['identifier'] == s['identifier'] }
        raise ArgumentError, 'frostAggregate: duplicate signature share' if seen.key?(s['identifier'])

        seen[s['identifier']] = true
      end
      unless verification_shares.is_a?(Array)
        raise ArgumentError, 'frostAggregate: verificationShares are required (every signature share is verified before aggregation)'
      end

      sig_shares.each do |s|
        vs = verification_shares.find { |v| v['identifier'] == s['identifier'] }
        com = lst.find { |c| c['identifier'] == s['identifier'] }
        if vs.nil? || !verify_sig_share(s['identifier'], vs['publicKey'], com, s, lst, group_public_key, message)
          raise ArgumentError, "frostAggregate: invalid signature share from participant #{s['identifier']}"
        end
      end
      r = group_commitment(lst, binding_factors(group_public_key, lst, message))
      z = ZERO
      sig_shares.each { |s| z = sc_add(z, reduce_bytes(s['sigShare'])) }
      sig = enc(r) + z
      raise ArgumentError, 'frostAggregate: aggregate signature does not verify (a share is invalid)' unless Ed25519Strict.verify(bin(group_public_key), bin(message), sig)

      sig
    end

    # Run the whole protocol in process for a quorum of participant shares (the dealer / guardian-tier path).
    def cosign(group_public_key, quorum, message, threshold = nil)
      raise ArgumentError, 'frostCosign: empty signing quorum' unless quorum.is_a?(Array) && !quorum.empty?
      raise ArgumentError, "frostCosign: quorum of #{quorum.length} is below the threshold t=#{threshold}" if !threshold.nil? && quorum.length < threshold

      ids = {}
      quorum.each do |p|
        raise ArgumentError, 'frost: participant identifier must be a positive safe integer' unless id?(p['identifier'])
        raise ArgumentError, "frostCosign: duplicate participant #{p['identifier']} in quorum" if ids.key?(p['identifier'])

        ids[p['identifier']] = true
      end
      vss = quorum.map { |p| { 'identifier' => p['identifier'], 'publicKey' => p['publicKey'] } }
      commits = quorum.map { |p| commit(p) }
      comms = commits.map { |c| c['commitment'] }
      shares = quorum.each_with_index.map do |p, i|
        sign(p['identifier'], p['share'], group_public_key, { 'hiding' => commits[i]['hidingNonce'], 'binding' => commits[i]['bindingNonce'] },
             message, comms, threshold, p['publicKey'], vss)
      end
      aggregate(message, comms, shares, group_public_key, vss, threshold)
    end
  end
end
