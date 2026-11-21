# frozen_string_literal: true

require 'json'
require 'securerandom'
require_relative '../atlas_pca'

module AtlasPca
  # BLS12-381 signature aggregation (IETF proof-of-possession ciphersuite), a rogue-key-safe key registry, the aggregated BLS
  # capability chain and aggregated witness cosignatures (the TypeScript reference, @atlasauth/pca-aggsig).
  #
  # Backend: blst (supranational/blst, constant time, audited) through ffi, bound lazily; a missing library fails closed with
  # LoadError. Build it as a shared library (`./build.sh -shared` in the blst repository) and put libblst.so / libblst.dylib on the
  # loader path. Public keys sit in G1 (48 bytes), signatures in G2 (96 bytes).
  module Aggsig
    SIG_DST = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_'
    POP_DST = 'BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_'
    PUBLIC_KEY_LENGTH = 48
    SIGNATURE_LENGTH = 96
    BLS_SUITE = 'bls12-381-pop'
    MAX_CHAIN_DEPTH = 16
    R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
    CAP_BLS_DOMAIN = "atlas-pca/cap-bls/v1\x00".b.freeze
    STH_WITNESS_BLS_DOMAIN = "atlas-pca/sth-witness-bls/v1\x00".b.freeze
    P1 = 144 # sizeof(blst_p1); the affine form is 96, blst_p2 is 288 (affine 192), a scalar 32
    P1A = 96
    P2 = 288
    P2A = 192

    # the blst entry points this port needs; bound on first use
    module Blst
      # PCA_BLST_LIB names the shared library explicitly (CI builds blst together with the GT shim)
      LIBS = [*ENV['PCA_BLST_LIB'], *Dir.glob(File.join(__dir__, 'native', '{libblst.so,libblst.dylib,blst.dll}')), *%w[blst libblst.so libblst.dylib blst.dll]].freeze
      FUNCS = {
        blst_scalar_from_bendian: [%i[pointer buffer_in], :void],
        blst_sk_check: [[:pointer], :bool],
        blst_sk_to_pk_in_g1: [%i[pointer pointer], :void],
        blst_p1_compress: [%i[pointer pointer], :void],
        blst_p1_uncompress: [%i[pointer buffer_in], :int],
        blst_p1_from_affine: [%i[pointer pointer], :void],
        blst_p1_affine_in_g1: [[:pointer], :bool],
        blst_p1_affine_is_inf: [[:pointer], :bool],
        blst_p1_add_or_double_affine: [%i[pointer pointer pointer], :void],
        blst_p2_compress: [%i[pointer pointer], :void],
        blst_p2_uncompress: [%i[pointer buffer_in], :int],
        blst_p2_affine_in_g2: [[:pointer], :bool],
        blst_p2_add_or_double_affine: [%i[pointer pointer pointer], :void],
        blst_hash_to_g2: [%i[pointer buffer_in size_t buffer_in size_t pointer size_t], :void],
        blst_sign_pk_in_g1: [%i[pointer pointer pointer], :void],
        blst_core_verify_pk_in_g1: [%i[pointer pointer bool buffer_in size_t buffer_in size_t pointer size_t], :int],
        blst_pairing_sizeof: [[], :size_t],
        blst_pairing_init: [%i[pointer bool pointer size_t], :void],
        blst_pairing_aggregate_pk_in_g1: [%i[pointer pointer pointer buffer_in size_t pointer size_t], :int],
        blst_pairing_commit: [[:pointer], :void],
        blst_pairing_finalverify: [%i[pointer pointer], :bool]
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
            raise LoadError, "BLS aggregation needs the ffi gem and libblst (#{e.message})"
          end
          lib = Module.new
          lib.extend(FFI::Library)
          begin
            lib.ffi_lib(LIBS)
          rescue LoadError => e
            raise LoadError, "BLS aggregation needs a built libblst (supranational/blst, ./build.sh -shared): #{e.message}"
          end
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

      def self.mem(n)
        bind!
        FFI::MemoryPointer.new(:uint8, n)
      end

      def self.str(bytes)
        p = mem([bytes.bytesize, 1].max)
        p.put_bytes(0, bytes.b)
        p
      end
    end

    module_function

    def bytes_arg(v, what)
      raise TypeError, "#{what}: expected bytes" unless v.is_a?(String)

      v.b
    end

    def unb64u(s) = AtlasPca.b64d(s) || raise(ArgumentError, 'bad base64url')
    def b64u(b) = AtlasPca.b64e(b)

    def compressed?(b, length) = b.is_a?(String) && b.bytesize == length && (b.getbyte(0) & 0x80) != 0

    # decode a compressed G2 / G1 point into a fresh affine buffer; nil when it is not a point
    def g2_affine(sig)
      a = Blst.mem(P2A)
      Blst.blst_p2_uncompress(a, sig.b).zero? ? a : nil
    end

    def g1_affine(pk)
      a = Blst.mem(P1A)
      Blst.blst_p1_uncompress(a, pk.b).zero? ? a : nil
    end

    # A 96-byte compressed G2 point whose canonical re-encoding is the input (subgroup membership is checked at verify).
    def canonical_signature?(sig)
      return false unless compressed?(sig, SIGNATURE_LENGTH)

      a = g2_affine(sig)
      return false if a.nil?

      reencode_g2(a) == sig.b
    rescue StandardError
      false
    end

    # canonical compressed bytes of an affine G2 point: re-add it to the identity and compress
    def reencode_g2(aff)
      acc = Blst.mem(P2)
      Blst.blst_p2_add_or_double_affine(acc, acc, aff)
      out = Blst.mem(SIGNATURE_LENGTH)
      Blst.blst_p2_compress(out, acc)
      out.read_bytes(SIGNATURE_LENGTH)
    end

    def reencode_g1(aff)
      acc = Blst.mem(P1)
      Blst.blst_p1_add_or_double_affine(acc, acc, aff)
      out = Blst.mem(PUBLIC_KEY_LENGTH)
      Blst.blst_p1_compress(out, acc)
      out.read_bytes(PUBLIC_KEY_LENGTH)
    end

    # the secret key as a blst scalar; refuses anything but 32 bytes with 1 <= n < r
    def sk_scalar(secret_key)
      sk = bytes_arg(secret_key, 'secret key')
      raise ArgumentError, "invalid private key, expected 32 bytes, got #{sk.bytesize}" unless sk.bytesize == 32

      s = Blst.mem(32)
      Blst.blst_scalar_from_bendian(s, sk)
      raise ArgumentError, "expected valid private key: 1 <= n < #{R}" unless Blst.blst_sk_check(s)

      s
    end

    def public_key_of(secret_key)
      p1 = Blst.mem(P1)
      Blst.blst_sk_to_pk_in_g1(p1, sk_scalar(secret_key))
      out = Blst.mem(PUBLIC_KEY_LENGTH)
      Blst.blst_p1_compress(out, p1)
      out.read_bytes(PUBLIC_KEY_LENGTH)
    end

    def key_gen
      sk = SecureRandom.random_number(R - 1) + 1
      raise 'keyGen: entropy source produced the degenerate key 1 (RNG failure); refusing to continue' if sk == 1

      secret = [format('%064x', sk)].pack('H*')
      { 'secret_key' => secret, 'public_key' => public_key_of(secret) }
    end

    KV_CACHE = {} # rubocop:disable Style/MutableConstant
    KV_LOCK = Mutex.new

    # KeyValidate: canonical compressed encoding, on curve, not the identity, in the prime-order subgroup.
    def key_validate(public_key)
      return false unless compressed?(public_key, PUBLIC_KEY_LENGTH)

      pk = public_key.b
      hit = KV_LOCK.synchronize { KV_CACHE[pk] }
      return hit unless hit.nil?

      ok = begin
        a = g1_affine(pk)
        !a.nil? && !Blst.blst_p1_affine_is_inf(a) && reencode_g1(a) == pk && Blst.blst_p1_affine_in_g1(a)
      rescue LoadError
        raise
      rescue StandardError
        false
      end
      KV_LOCK.synchronize { KV_CACHE[pk] = ok if KV_CACHE.size < 4096 }
      ok
    end

    def sign_with(secret_key, msg, dst)
      sk = sk_scalar(secret_key)
      h = Blst.mem(P2)
      d = Blst.str(dst)
      Blst.blst_hash_to_g2(h, msg, msg.bytesize, d, dst.bytesize, nil, 0)
      s = Blst.mem(P2)
      Blst.blst_sign_pk_in_g1(s, h, sk)
      out = Blst.mem(SIGNATURE_LENGTH)
      Blst.blst_p2_compress(out, s)
      out.read_bytes(SIGNATURE_LENGTH)
    end

    def sign(secret_key, msg) = sign_with(secret_key, bytes_arg(msg, 'message'), SIG_DST)
    def pop_prove(secret_key) = sign_with(secret_key, public_key_of(secret_key), POP_DST)

    # the public key was validated by the caller; the signature is subgroup-checked here
    def core_verify(pk, msg, sig, pop)
      pa = g1_affine(pk)
      sa = g2_affine(sig)
      return false if pa.nil? || sa.nil? || !Blst.blst_p2_affine_in_g2(sa)

      dst = pop ? POP_DST : SIG_DST
      m = pop ? pk.b : msg.b
      d = Blst.str(dst)
      Blst.blst_core_verify_pk_in_g1(pa, sa, true, m, m.bytesize, d, dst.bytesize, nil, 0).zero?
    end

    def verify(public_key, msg, sig)
      return false unless canonical_signature?(sig)
      return false unless key_validate(public_key)

      core_verify(public_key.b, bytes_arg(msg, 'message'), sig.b, false)
    rescue LoadError
      raise
    rescue StandardError
      false
    end

    def pop_verify(public_key, pop)
      return false unless canonical_signature?(pop)
      return false unless key_validate(public_key)

      core_verify(public_key.b, ''.b, pop.b, true)
    rescue LoadError
      raise
    rescue StandardError
      false
    end

    def aggregate(sigs)
      raise ArgumentError, 'aggregate: need at least one signature' unless sigs.is_a?(Array) && !sigs.empty?

      sigs.each do |sg|
        raise ArgumentError, 'aggregate: every signature must be a 96-byte compressed G2 point' unless canonical_signature?(sg)
        raise ArgumentError, 'aggregate: signature is not in the G2 subgroup' unless Blst.blst_p2_affine_in_g2(g2_affine(sg)) # noble validates on decode
      end
      acc = Blst.mem(P2)
      sigs.each { |sg| Blst.blst_p2_add_or_double_affine(acc, acc, g2_affine(sg)) }
      out = Blst.mem(SIGNATURE_LENGTH)
      Blst.blst_p2_compress(out, acc)
      out.read_bytes(SIGNATURE_LENGTH)
    end

    def aggregate_public_keys(public_keys)
      raise ArgumentError, 'aggregatePublicKeys: need at least one key' unless public_keys.is_a?(Array) && !public_keys.empty?

      acc = Blst.mem(P1)
      public_keys.each do |pk|
        a = g1_affine(bytes_arg(pk, 'public key')) || raise(ArgumentError, 'aggregatePublicKeys: not a G1 point')
        Blst.blst_p1_add_or_double_affine(acc, acc, a)
      end
      out = Blst.mem(PUBLIC_KEY_LENGTH)
      Blst.blst_p1_compress(out, acc)
      out.read_bytes(PUBLIC_KEY_LENGTH)
    end

    def raw_aggregate_verify(public_keys, msgs, agg_sig)
      return false unless canonical_signature?(agg_sig)
      return false if public_keys.empty? || public_keys.length != msgs.length

      seen = {}
      msgs.each do |m|
        h = bytes_arg(m, 'message')
        return false if seen.key?(h)

        seen[h] = true
      end
      return false unless public_keys.all? { |pk| key_validate(pk) }

      sig = g2_affine(agg_sig)
      return false if sig.nil? || !Blst.blst_p2_affine_in_g2(sig)

      ctx = Blst.mem(Blst.blst_pairing_sizeof)
      dst = Blst.str(SIG_DST)
      Blst.blst_pairing_init(ctx, true, dst, SIG_DST.bytesize)
      public_keys.each_with_index do |pk, i|
        m = msgs[i].b
        return false unless Blst.blst_pairing_aggregate_pk_in_g1(ctx, g1_affine(pk), i.zero? ? sig : nil, m, m.bytesize, nil, 0).zero?
      end
      Blst.blst_pairing_commit(ctx)
      Blst.blst_pairing_finalverify(ctx, nil)
    rescue LoadError
      raise
    rescue StandardError
      false
    end

    def raw_fast_aggregate_verify(public_keys, msg, agg_sig)
      return false unless canonical_signature?(agg_sig)
      return false if public_keys.empty?
      return false unless public_keys.all? { |pk| key_validate(pk) }

      agg_pk = aggregate_public_keys(public_keys.to_a)
      return false unless key_validate(agg_pk)

      core_verify(agg_pk, bytes_arg(msg, 'message'), agg_sig.b, false)
    rescue LoadError
      raise
    rescue StandardError
      false
    end

    # ---- registry: only keys admitted through a proof of possession may enter an aggregate (rogue-key defence)
    TOKEN = Object.new.freeze

    # A public key that passed KeyValidate and proof of possession. Not constructible directly: use register_key().
    class RegisteredKey
      attr_reader :bytes

      def initialize(token, key)
        raise TypeError, 'RegisteredKey cannot be constructed directly; use register_key(public_key, pop)' unless token.equal?(TOKEN)

        @bytes = key.b.freeze
        freeze
      end
    end

    # {"ok" => true, "key" => RegisteredKey} or {"ok" => false, "reason" => String}.
    def register_key(public_key, pop)
      unless public_key.is_a?(String) && pop.is_a?(String)
        return { 'ok' => false, 'reason' => 'public key and proof of possession must be Uint8Arrays' }
      end
      unless key_validate(public_key)
        return { 'ok' => false, 'reason' => 'public key fails KeyValidate (not a canonical, non-identity, prime-order G1 point)' }
      end
      return { 'ok' => false, 'reason' => 'proof of possession is not a 96-byte compressed G2 signature' } unless pop.bytesize == SIGNATURE_LENGTH
      return { 'ok' => false, 'reason' => 'proof of possession does not verify for this key' } unless pop_verify(public_key, pop)

      { 'ok' => true, 'key' => RegisteredKey.new(TOKEN, public_key) }
    end

    def registered_key?(x) = x.is_a?(RegisteredKey)

    class KeyRegistry
      def initialize = @keys = {}

      def register(public_key, pop)
        r = Aggsig.register_key(public_key, pop)
        @keys[public_key.b.unpack1('H*')] = r['key'] if r['ok']
        r
      end

      def get(public_key)
        return nil unless public_key.is_a?(String) && public_key.bytesize == PUBLIC_KEY_LENGTH

        @keys[public_key.b.unpack1('H*')]
      end

      def has?(public_key) = !get(public_key).nil?
      def size = @keys.size
    end

    def check_registered(keys)
      return 'keys must be an array of RegisteredKey' unless keys.is_a?(Array)
      return 'no keys' if keys.empty?

      keys.each_with_index do |k, i|
        return "key #{i} is not a registered key: it was not admitted through registerKey (proof of possession)" unless registered_key?(k)
      end
      nil
    end

    def aggregate_verify(keys, msgs, agg_sig)
      return false unless check_registered(keys).nil?

      raw_aggregate_verify(keys.map(&:bytes), msgs, agg_sig)
    end

    def fast_aggregate_verify(keys, msg, agg_sig)
      return false unless check_registered(keys).nil?
      return false if keys.map(&:bytes).uniq.length != keys.length

      raw_fast_aggregate_verify(keys.map(&:bytes), msg, agg_sig)
    end

    # ---- BLS capability chain (one aggregate signature over every hop)
    def body_of(c) = { 'issuer' => c['issuer'], 'holder' => c['holder'], 'caveats' => c['caveats'], 'parent' => c['parent'] }
    def sig_message(body_digest) = CAP_BLS_DOMAIN + unb64u(body_digest)

    # base64url(sha256(strict canonical of the capability without its signature))
    def cap_hash(c) = AtlasPca.hash_canonical(c.reject { |k, _| k == 'sig' })

    def clone_caveats(cs) = JSON.parse(AtlasPca.canon_bytes(cs).force_encoding('UTF-8'))

    def seal(body, signer_secret)
      body_digest = AtlasPca.hash_canonical(body_of(body))
      sig = b64u(sign(signer_secret, sig_message(body_digest)))
      cap = { 'id' => body_digest, 'issuer' => body['issuer'], 'holder' => body['holder'], 'caveats' => body['caveats'],
              'body_digest' => body_digest, 'sig' => sig, 'suite' => BLS_SUITE }
      cap['parent'] = body['parent'] if body.key?('parent')
      cap
    end

    def bls_public_key(secret_key) = b64u(public_key_of(secret_key))

    def mint_bls_root(principal_secret, principal_public, holder, caveats)
      seal({ 'issuer' => principal_public, 'holder' => holder, 'caveats' => clone_caveats(caveats) }, principal_secret)
    end

    def bls_delegate(parent, to_holder, added_caveats, signer_secret)
      seal({ 'issuer' => parent['holder'], 'holder' => to_holder, 'caveats' => clone_caveats(parent['caveats']) + clone_caveats(added_caveats),
             'parent' => cap_hash(parent) }, signer_secret)
    end

    def bls_attenuate(parent, added_caveats, signer_secret) = bls_delegate(parent, parent['holder'], added_caveats, signer_secret)

    def well_typed?(c)
      return false unless c.is_a?(Hash)
      return false unless %w[id issuer holder body_digest sig].all? { |k| c[k].is_a?(String) }
      return false if c['suite'] != BLS_SUITE
      return false if c.key?('parent') && !c['parent'].is_a?(String)

      cav = c['caveats']
      cav.is_a?(Array) && cav.all? { |cv| cv.is_a?(Hash) && cv['type'].is_a?(String) }
    end

    def aggregate_chain_signatures(chain)
      raise ArgumentError, 'aggregateChainSignatures: empty chain' unless chain.is_a?(Array) && !chain.empty?

      aggregate(chain.map { |c| unb64u(c['sig']) })
    end

    def verify_aggregated_chain(chain, agg_sig, registry, expected_root_principal = nil)
      no = ->(reason) { { 'ok' => false, 'reason' => reason } }
      return no.call('a KeyRegistry of proof-of-possession-verified keys is required') unless registry.respond_to?(:get)
      return no.call('empty chain') unless chain.is_a?(Array) && !chain.empty?
      return no.call("chain too long (max #{MAX_CHAIN_DEPTH} hops)") if chain.length > MAX_CHAIN_DEPTH

      chain.each_with_index { |c, i| return no.call("hop #{i}: malformed capability") unless well_typed?(c) }

      pks = []
      msgs = []
      root = chain[0]
      return no.call('hop 0: root must not have a parent') if root.key?('parent')
      return no.call('hop 0: root issuer is not the expected principal') if !expected_root_principal.nil? && root['issuer'] != expected_root_principal

      chain.each_with_index do |c, i|
        digest = begin
          AtlasPca.hash_canonical(body_of(c))
        rescue StandardError
          return no.call("hop #{i}: malformed body")
        end
        return no.call("hop #{i}: body digest mismatch") if digest != c['body_digest'] || c['id'] != c['body_digest']

        pk = begin
          registry.get(unb64u(c['issuer']))
        rescue StandardError
          return no.call("hop #{i}: malformed issuer key")
        end
        return no.call("hop #{i}: issuer key has no verified proof of possession (not in the registry)") if pk.nil?

        if i.positive?
          parent = chain[i - 1]
          return no.call("hop #{i}: broken parent link") if c['parent'] != cap_hash(parent)
          return no.call("hop #{i}: issuer is not the parent's bound holder") if c['issuer'] != parent['holder']
          return no.call("hop #{i}: drops parent caveat(s)") if c['caveats'].length < parent['caveats'].length

          parent['caveats'].each_index do |j|
            return no.call("hop #{i}: caveat #{j} altered or reordered") if AtlasPca.hash_canonical(c['caveats'][j]) != AtlasPca.hash_canonical(parent['caveats'][j])
          end
        end
        pks << pk
        msgs << sig_message(c['body_digest'])
      end

      begin
        chain.each_with_index do |c, i|
          return no.call("hop #{i}: non-canonical sig encoding") if b64u(unb64u(c['sig'])) != c['sig']
        end
        total = aggregate(chain.map { |c| unb64u(c['sig']) })
        return no.call('hop sig fields do not sum to the aggregate signature') if total != bytes_arg(agg_sig, 'aggregate signature')
      rescue LoadError
        raise
      rescue StandardError
        return no.call('malformed hop sig')
      end

      return no.call('aggregate signature does not verify over all hops') unless aggregate_verify(pks, msgs, agg_sig)

      { 'ok' => true }
    end

    # ---- witnesses: BLS cosignatures over a signed tree head, aggregable into one signature
    def witness_message(h)
      %w[size root prev_root].each { |k| raise TypeError, "canonicalize: undefined value for #{k}" unless h.key?(k) }
      epoch = h['guardian_epoch']
      body = { 'size' => h['size'], 'root' => h['root'], 'prev_root' => h['prev_root'], 'guardian_epoch' => epoch.nil? ? 0 : epoch }
      STH_WITNESS_BLS_DOMAIN + AtlasPca.canon_bytes(body)
    end

    def cosign_tree_head(statement, witness_secret)
      { 'key' => b64u(public_key_of(witness_secret)), 'sig' => b64u(sign(witness_secret, witness_message(statement))), 'suite' => BLS_SUITE }
    end

    def verify_witness_cosignature(statement, cosig)
      return false if !cosig.is_a?(Hash) || cosig['suite'] != BLS_SUITE

      verify(unb64u(cosig['key']), witness_message(statement), unb64u(cosig['sig']))
    rescue LoadError
      raise
    rescue StandardError
      false
    end

    def aggregate_witness_cosignatures(cosigs)
      raise ArgumentError, 'aggregateWitnessCosignatures: empty set' unless cosigs.is_a?(Array) && !cosigs.empty?

      aggregate(cosigs.map { |c| unb64u(c['sig']) })
    end

    def verify_aggregated_witness_cosignatures(statement, witness_keys, agg_sig)
      return false if !witness_keys.is_a?(Array) || witness_keys.empty?
      return false if witness_keys.map(&:bytes).uniq.length != witness_keys.length

      fast_aggregate_verify(witness_keys, witness_message(statement), agg_sig)
    rescue LoadError
      raise
    rescue StandardError
      false
    end
  end
end
