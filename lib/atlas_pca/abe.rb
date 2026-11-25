# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require_relative '../atlas_pca'
require_relative 'fame'

module AtlasPca
  # Proof-carrying encryption: ciphertext-policy ABE (FAME, see Fame) with the payload sealed under AES-256-GCM, the whole header
  # authenticated. Keys, ciphertexts and the master keys are Hashes with the TypeScript reference's member names (String keys), so
  # material crosses languages unchanged. Every parser is fail closed: decrypt returns nil on any deviation and never raises
  # (except LoadError: no library).
  module Abe
    ABE_ALG = 'fame-cpabe-bls12381-type3/aes-256-gcm'
    CEK_INFO = 'atlas-pca-abe/cek/v3'
    SALT_LEN = 16
    R = Bls12::R

    # an invalid policy, master public key or master secret key
    class PcaEncryptionError < ArgumentError; end

    module_function

    # ---- wire helpers ----

    def b64u(b) = AtlasPca.b64e(b)

    # canonical unpadded base64url only; nil otherwise
    def unb64u(o) = AtlasPca.b64d(o)

    def obj(o) = o.is_a?(Hash) ? o : nil
    def two?(o) = o.is_a?(Numeric) && o.to_f == 2.0
    def ill_formed?(s) = !s.valid_encoding?

    def read_g1(x)
      b = unb64u(x)
      return nil if b.nil?

      p = Bls12::G1.decode(b)
      p.inf? ? nil : p
    rescue ArgumentError
      nil
    end

    def read_g2(x)
      b = unb64u(x)
      return nil if b.nil?

      p = Bls12::G2.decode(b)
      p.inf? ? nil : p
    rescue ArgumentError
      nil
    end

    def read_gt(x)
      b = unb64u(x)
      b && Bls12::Gt.element?(b) ? b : nil
    end

    def tri(x)
      return nil unless x.is_a?(Array) && x.length == 3

      out = x.map { |e| yield(e) }
      out.any?(&:nil?) ? nil : out
    end

    def tri1(x) = tri(x) { |e| read_g1(e) }
    def tri2(x) = tri(x) { |e| read_g2(e) }
    def enc(points) = points.map { |p| b64u(p.compress) }

    # ---- scalars ----

    def random_scalar
      loop do
        v = Bls12.os2ip(SecureRandom.random_bytes(64)) % R
        return v unless v.zero?
      end
    end

    def scalar_b64(s) = b64u(Bls12.i2osp(s, 32))

    # exactly one encoding per scalar: 32 bytes, non-zero, and below r
    def canonical_scalar(enc)
      b = unb64u(enc)
      return nil if b.nil? || b.bytesize != 32

      x = Bls12.os2ip(b)
      x.zero? || x >= R ? nil : x
    end

    # ---- setup / keygen ----

    # a fresh master key pair: { 'mpk' =>, 'msk' => }
    def setup
      a = [random_scalar, random_scalar]
      b = [random_scalar, random_scalar]
      d = [random_scalar, random_scalar, random_scalar]
      m = Fame.setup(a, b, d)
      msk = { 'v' => 2, 'curve' => 'bls12-381', 'a' => a.map { |x| scalar_b64(x) }, 'b' => b.map { |x| scalar_b64(x) }, 'g' => enc(m.msk.g) }
      mpk = { 'v' => 2, 'curve' => 'bls12-381', 'h' => enc([m.mpk.h1, m.mpk.h2]), 't' => [b64u(m.mpk.t1), b64u(m.mpk.t2)] }
      { 'mpk' => mpk, 'msk' => msk }
    end

    def scalar_pair(x)
      return nil unless x.is_a?(Array) && x.length == 2

      out = x.map { |e| canonical_scalar(e) }
      out.any?(&:nil?) ? nil : out
    end

    def parse_msk(o)
      m = obj(o)
      raise PcaEncryptionError, 'invalid master secret key' if m.nil? || !two?(m['v'])

      a = scalar_pair(m['a'])
      b = scalar_pair(m['b'])
      g = tri1(m['g'])
      raise PcaEncryptionError, 'invalid master secret key' if a.nil? || b.nil? || g.nil?

      Fame::Msk.new(a, b, g)
    end

    def parse_mpk(o)
      m = obj(o)
      if m && two?(m['v']) && m['h'].is_a?(Array) && m['h'].length == 2 && m['t'].is_a?(Array) && m['t'].length == 2
        h1 = read_g2(m['h'][0])
        h2 = read_g2(m['h'][1])
        t1 = read_gt(m['t'][0])
        t2 = read_gt(m['t'][1])
        return Fame::Mpk.new(h1, h2, t1, t2) if h1 && h2 && t1 && t2
      end
      raise PcaEncryptionError, 'invalid master public key'
    end

    # Issue a decryption key for an explicit set of attribute tokens (empty or ill-formed names are dropped).
    def keygen_for_attributes(msk, attrs)
      m = parse_msk(msk)
      names = attrs.uniq.select { |a| a.is_a?(String) && !a.empty? && !ill_formed?(a) }
      sigmas = names.map { random_scalar }
      key = Fame.keygen(m, names, [random_scalar, random_scalar], sigmas, random_scalar)
      as = names.to_h { |n| [n, { 'k' => enc(key.attrs[n]) }] }
      { 'v' => 2, 'curve' => 'bls12-381', 'k0' => enc(key.k0), 'kp' => enc(key.kp), 'attrs' => as }
    end

    # Issue a key bound to a capability: its capability_attributes plus the extra tokens; the holder is recorded.
    def keygen_for_capability(msk, capability, extra = [], opts = {})
      attrs = capability_attributes(capability, opts)
      extra.each { |a| attrs << a if a.is_a?(String) && !a.empty? }
      key = keygen_for_attributes(msk, attrs)
      key['holder'] = capability['holder'] if capability['holder'].is_a?(String)
      key
    end

    # an untrusted key; a malformed attribute component counts as not held. nil if K0, K' or the container is malformed.
    def parse_key(o)
      k = obj(o)
      return nil if k.nil? || !two?(k['v']) || obj(k['attrs']).nil?

      k0 = tri2(k['k0'])
      kp = tri1(k['kp'])
      return nil if k0.nil? || kp.nil?

      attrs = {}
      k['attrs'].each do |name, comp|
        t = obj(comp) ? tri1(comp['k']) : nil
        attrs[name] = t if t
      end
      Fame::Key.new(k0, kp, attrs)
    end

    # ---- KDF / AEAD ----

    # HKDF-SHA256 (RFC 5869), 32 bytes: the content-encryption key from the KEM key
    def kdf32(ikm, salt, info)
      prk = OpenSSL::HMAC.digest('SHA256', salt.empty? ? "\0".b * 32 : salt, ikm)
      OpenSSL::HMAC.digest('SHA256', prk, info.b + "\x01".b)
    end

    def seal(key, pt, aad)
      iv = SecureRandom.random_bytes(12)
      c = OpenSSL::Cipher.new('aes-256-gcm').encrypt
      c.key = key
      c.iv = iv
      c.auth_data = aad
      ct = pt.empty? ? c.final : c.update(pt) + c.final
      [iv, ct, c.auth_tag(16)]
    end

    def open_gcm(key, iv, ct, tag, aad)
      return nil if key.bytesize != 32 || iv.bytesize != 12 || tag.bytesize != 16

      c = OpenSSL::Cipher.new('aes-256-gcm').decrypt
      c.key = key
      c.iv = iv
      c.auth_tag = tag
      c.auth_data = aad
      ct.empty? ? c.final : c.update(ct) + c.final
    rescue OpenSSL::Cipher::CipherError
      nil
    end

    def aad(c)
      AtlasPca.canon_bytes(%w[v alg salt ct0 tree rows].to_h { |k| [k, c[k]] })
    end

    # ---- encrypt ----

    # Encrypt so that only a key whose attributes satisfy policy opens it. Raises PcaEncryptionError on a bad policy or key.
    def encrypt_for_policy(mpk, policy, plaintext)
      norm = AbePolicy.normalize(policy)
      raise PcaEncryptionError, "invalid policy: #{norm['reason']}" unless norm['ok']

      tree = norm['tree']
      dup = Fame.first_repeated_attribute(tree)
      if dup
        raise PcaEncryptionError, "invalid policy: attribute #{AtlasPca.canonicalize(dup)} is named by more than one leaf (single-use attributes only)"
      end

      pk = parse_mpk(mpk)
      salt = SecureRandom.random_bytes(SALT_LEN)
      e = Fame.encrypt(pk, tree, [random_scalar, random_scalar])
      header = { 'v' => 2, 'alg' => ABE_ALG, 'salt' => b64u(salt), 'ct0' => enc(e.ct.ct0), 'tree' => tree, 'rows' => e.ct.rows.map { |r| enc(r) } }
      begin
        header_aad = aad(header)
      rescue AtlasPca::Malformed
        raise PcaEncryptionError, 'policy cannot be authenticated (header outside the canonical JSON profile)'
      end
      iv, ct, tag = seal(kdf32(e.k, salt, CEK_INFO), plaintext.b, header_aad)
      header.merge('iv' => b64u(iv), 'ct' => b64u(ct), 'tag' => b64u(tag))
    end

    # encrypt a JSON value (the payload layer of decrypt_with_capability)
    def encrypt_tool_payload(mpk, policy, payload) = encrypt_for_policy(mpk, policy, AtlasPca.canon_bytes(payload))

    # ---- parse ----

    def parse_tree(x, gates, budget)
      m = obj(x)
      budget[0] += 1
      return nil if budget[0] > AbePolicy::MAX_POLICY_NODES || m.nil?

      case m['kind']
      when 'leaf'
        a = m['attr']
        return nil if !a.is_a?(String) || a.empty? || ill_formed?(a) || m.size != 2

        AbePolicy.leaf(a)
      when 'gate'
        return nil if gates + 1 > AbePolicy::MAX_POLICY_DEPTH || m.size != 3

        t = m['t']
        of = m['of']
        return nil if !AbePolicy.pos_int?(t) || !of.is_a?(Array) || of.empty?
        return nil if AbePolicy.num(t) > of.length || of.length >= AbePolicy::MAX_POLICY_NODES

        kids = []
        of.each do |b|
          sub = parse_tree(b, gates + 1, budget)
          return nil if sub.nil?

          kids << sub
        end
        AbePolicy.gate(AbePolicy.num(t).to_i, kids)
      end
    end

    def str_tri(x)
      return nil unless x.is_a?(Array) && x.length == 3
      return nil if x.any? { |e| unb64u(e).nil? }

      x.dup
    end

    # validate an untrusted value as a ciphertext; nil (fail closed) on any deviation
    def parse_ciphertext(o)
      x = obj(o)
      return nil if x.nil? || !two?(x['v']) || x['alg'] != ABE_ALG
      return nil if %w[salt iv ct tag].any? { |k| unb64u(x[k]).nil? }

      ct0 = str_tri(x['ct0'])
      tree = parse_tree(x['tree'], 0, [0])
      return nil if ct0.nil? || tree.nil? || !x['rows'].is_a?(Array)
      return nil if x['rows'].length != Fame.leaf_count(tree) || Fame.first_repeated_attribute(tree)

      rows = x['rows'].map { |r| str_tri(r) }
      return nil if rows.any?(&:nil?)

      { 'v' => 2, 'alg' => ABE_ALG, 'salt' => x['salt'], 'ct0' => ct0, 'tree' => tree, 'rows' => rows, 'iv' => x['iv'], 'ct' => x['ct'], 'tag' => x['tag'] }
    end

    # ---- decrypt ----

    # The plaintext iff the key's attributes satisfy the ciphertext's policy and the AEAD authenticates; otherwise nil. Never raises.
    def decrypt(key, ciphertext)
      ct = parse_ciphertext(ciphertext)
      return nil if ct.nil?

      pk = parse_key(key)
      return nil if pk.nil?

      salt = unb64u(ct['salt'])
      iv = unb64u(ct['iv'])
      body = unb64u(ct['ct'])
      tag = unb64u(ct['tag'])
      ct0 = tri2(ct['ct0'])
      rows = ct['rows'].map { |r| tri1(r) }
      return nil if rows.any?(&:nil?) || salt.nil? || iv.nil? || body.nil? || tag.nil? || ct0.nil?

      k = Fame.decrypt(pk, ct['tree'], Fame::Ciphertext.new(ct0, rows))
      return nil if k.nil?

      begin
        header_aad = aad(ct)
      rescue AtlasPca::Malformed
        return nil
      end
      open_gcm(kdf32(k, salt, CEK_INFO), iv, body, tag, header_aad)
    rescue ArgumentError, ZeroDivisionError, TypeError
      nil
    end

    def decrypt_text(key, ciphertext)
      pt = decrypt(key, ciphertext)
      pt&.force_encoding(Encoding::UTF_8)&.scrub("�")
    end

    # { 'ok' => true, 'payload' => } or { 'ok' => false, 'reason' => }
    def decrypt_with_capability(key, ciphertext)
      pt = decrypt(key, ciphertext)
      return { 'ok' => false, 'reason' => 'capability does not satisfy the policy, or ciphertext is invalid' } if pt.nil?

      begin
        { 'ok' => true, 'payload' => AtlasPca.parse_json_text(pt.dup.force_encoding(Encoding::UTF_8).scrub("�")) }
      rescue AtlasPca::Malformed
        { 'ok' => false, 'reason' => 'decrypted payload is not valid JSON' }
      end
    end

    # ---- capability attributes ----

    def act(verb, resource) = "act:#{AtlasPca.canonicalize([verb, resource])}"

    def verbs_of(v)
      return [v] if v.is_a?(String)

      v.is_a?(Array) ? v.select { |e| e.is_a?(String) } : []
    end

    # The canonical attribute set a capability possesses: holder, scope, and (from the ROOT only, never from a delegated
    # hop's own caveats) act/verb/resource tokens. A delegated capability gets scope/act/verb/resource tokens only with a verified
    # chain (root first, ending in the capability); a chain that fails verification yields none (fail closed). opts: 'chain',
    # 'principal', 'pqPins'. Returns the unique tokens in the reference's insertion order (holder, scopes, act, verb, resource); sort with
    # AbePolicy.js_sort for the canonical listing.
    def capability_attributes(cap, opts = {})
      out = []
      return out unless cap.is_a?(Hash)

      opts ||= {}
      scope_source = nil
      env_source = nil
      if opts.key?('chain')
        chain = opts['chain']
        return out unless chain.is_a?(Array) && !chain.empty?

        root = obj(chain[0])
        last = obj(chain[-1])
        return out if root.nil? || last.nil? || last['id'] != cap['id']

        principal = opts['principal'].nil? ? root['issuer'] : opts['principal']
        pins = obj(opts['pqPins'])
        _reason, ok = AtlasPca.verify_chain(chain, principal, principal.is_a?(String), nil, pins, nil)
        return out unless ok

        scope_source = root['caveats']
        env_source = root
      elsif !cap.key?('parent')
        scope_source = cap['caveats']
        env_source = cap
      end
      out << "holder:#{cap['holder']}" if cap['holder'].is_a?(String) && !cap['holder'].empty?
      if scope_source.is_a?(Array)
        scope_source.each do |cv|
          next unless cv.is_a?(Hash)

          out << "scope:#{cv['value']}" if cv['type'] == 'scope' && cv['value'].is_a?(String)
          cv['values'].each { |s| out << "scope:#{s}" if s.is_a?(String) } if cv['type'] == 'scopes' && cv['values'].is_a?(Array)
        end
      end
      env = env_source.nil? ? nil : AtlasPca.read_envelope(env_source)
      if env && env['predicates'].is_a?(Array)
        preds = env['predicates'].select { |p| p.is_a?(Hash) || p.is_a?(Array) }.map { |p| p.is_a?(Hash) ? p : {} } # an array counts, and names no verb or resource
        preds.each { |p| verbs_of(p['verb']).each { |v| out << act(v, p['resource']) } if p['resource'].is_a?(String) }
        if preds.length == 1
          p = preds[0]
          verbs_of(p['verb']).each { |v| out << "verb:#{v}" }
          out << "resource:#{p['resource']}" if p['resource'].is_a?(String)
        end
      end
      out.uniq
    end
  end
end
