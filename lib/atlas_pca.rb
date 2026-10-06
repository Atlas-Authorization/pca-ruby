# frozen_string_literal: true

# Reference verifier for the CORE PCActn checks (M0-M3): capability chain, Merkle plan inclusion,
# Ed25519 leaf signature, counter. Stdlib only (OpenSSL >= 3 for raw Ed25519). Ported from the Go reference verifier.
require 'json'
require 'digest'
require 'base64'
require 'openssl'

module AtlasPca
  SIG_DOMAIN = "atlas-pca/actn/v1\x00".b.freeze
  CAP_DOMAIN = "atlas-pca/cap/v1\x00".b.freeze
  DEFAULT_REV = 'reversible'

  class Malformed < StandardError; end

  Verdict = Struct.new(:allow, :checks, :reason)

  module_function

  def parse_json(text)
    JSON.parse(text)
  end

  # ---- base64url (no padding) ----
  def b64e(bin)
    Base64.urlsafe_encode64(bin, padding: false)
  end

  def b64d(str)
    raise Malformed, 'not a string' unless str.is_a?(String)
    return nil unless str.match?(/\A[A-Za-z0-9_-]*\z/) && str.length % 4 != 1

    Base64.urlsafe_decode64(str)
  rescue ArgumentError
    nil
  end

  # ---- canonicalization ----
  def js_string(s)
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
    if n.is_a?(Integer)
      f = n.to_f
      raise Malformed, 'non-finite number' if f.infinite?
      return n.to_s if n.abs < 2**53

      return fmt_float(f)
    end
    raise Malformed, 'non-finite number' if n.nan? || n.infinite?

    fmt_float(n)
  end

  def fmt_float(f)
    return '0' if f == 0

    # shortest round-trip digits, rendered in plain decimal (Go 'f', -1)
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
      if point <= 0
        "#{sign}0.#{'0' * -point}#{digits}"
      elsif point >= digits.length
        "#{sign}#{digits}#{'0' * (point - digits.length)}"
      else
        "#{sign}#{digits[0, point]}.#{digits[point..]}"
      end.sub(/\.?0+\z/) { |z| z.include?('.') ? '' : z }
    end
  end

  def utf16_key(s)
    s.encode('UTF-16BE').b
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
      keys = v.keys.sort_by { |k| utf16_key(k.to_s) }
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

  # ---- Merkle ----
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

  def verify_inclusion(root, proof, leaf)
    return false unless proof.is_a?(Hash) && proof['path'].is_a?(Array)

    h = leaf_hash(leaf)
    proof['path'].each do |step|
      return false unless step.is_a?(Hash)

      side = step['side']
      return false unless %w[L R].include?(side)

      sib = b64d(step['hash'].is_a?(String) ? step['hash'] : '')
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

  # ---- keys ----
  def verify_b64u(pub, msg, sig)
    pk = pub.is_a?(String) ? b64d(pub) : nil
    return false if pk.nil? || pk.bytesize != 32

    sg = sig.is_a?(String) ? b64d(sig) : nil
    return false if sg.nil? || sg.bytesize != 64

    OpenSSL::PKey.new_raw_public_key('ED25519', pk).verify(nil, sg, msg)
  rescue StandardError
    false
  end

  # ---- capability chain ----
  def cap_hash(c)
    hash_canonical(c)
  end

  def body_of(c)
    { 'issuer' => c['issuer'], 'holder' => c['holder'], 'caveats' => c['caveats'], 'parent' => c['parent'] }
  end

  def check_sig(c, signer, label)
    digest = hash_canonical(body_of(c))
    bd = c['body_digest']
    return "#{label}: body digest mismatch" if digest != bd || c['id'] != bd

    d = b64d(bd)
    return "#{label}: bad signature (not signed by expected key)" if d.nil?

    msg = CAP_DOMAIN + d
    return "#{label}: bad signature (not signed by expected key)" unless verify_b64u(signer, msg, c['sig'])

    ''
  end

  # Returns [reason, ok]
  def verify_chain(chain, expected_root_issuer, have_issuer)
    return ['empty chain', false] if chain.empty?

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

  # ---- PCActn ----
  def threshold_message(p)
    body = p.reject { |k, _| k == 'sig' || k == 'threshold' }
    SIG_DOMAIN + sha(canon_bytes(body))
  end

  def verify_pcactn_core(pcactn, grant)
    v = Verdict.new(false, { 'chain' => false, 'plan_inclusion' => false, 'leaf_signature' => false,
                             'counter' => false }, '')
    failed = false
    fail_check = lambda do |name, why|
      failed = true
      v.checks[name] = false
      v.reason = "#{name}: #{why}" if v.reason.empty?
    end

    begin
      fail_check.call('version', 'unsupported ver') unless pcactn['ver'].is_a?(Integer) && pcactn['ver'] == 1

      chain = pcactn['cap_chain'].is_a?(Array) ? pcactn['cap_chain'] : []
      if chain.empty?
        fail_check.call('chain', 'empty chain')
      elsif cap_hash(chain[0]) != cap_hash(grant)
        fail_check.call('chain', 'chain root is not the grant')
      else
        gi = grant['issuer']
        why, ok = verify_chain(chain, gi, gi.is_a?(String))
        if ok
          v.checks['chain'] = true
        else
          fail_check.call('chain', why)
        end
      end

      plan = pcactn['plan'].is_a?(Hash) ? pcactn['plan'] : {}
      action = pcactn['action'].is_a?(Hash) ? pcactn['action'] : {}
      cond = plan['conditions_digest']
      cond = conditions_digest(nil, nil) unless cond.is_a?(String)
      root = plan['root'].is_a?(String) ? plan['root'] : ''
      proof = plan['inclusion_proof']
      included = begin
        verify_inclusion(root, proof, plan_leaf(plan['node_id'], action, cond))
      rescue Malformed
        false
      end
      if included
        v.checks['plan_inclusion'] = true
      else
        fail_check.call('plan_inclusion', 'action is not a node of the committed plan')
      end

      if chain.empty?
        fail_check.call('leaf_signature', 'signature does not verify under the leaf holder key')
      else
        leaf_cap = chain[-1].is_a?(Hash) ? chain[-1] : {}
        sig = pcactn['sig']
        if sig.is_a?(String) && verify_b64u(leaf_cap['holder'], threshold_message(pcactn), sig)
          v.checks['leaf_signature'] = true
        else
          fail_check.call('leaf_signature', 'signature does not verify under the leaf holder key')
        end
      end

      ctr = pcactn['counter']
      if ctr.is_a?(Integer) && ctr >= 0 && ctr < 2**63
        v.checks['counter'] = true
      else
        fail_check.call('counter', 'missing or not a non-negative integer')
      end

      v.allow = !failed
    rescue StandardError => e
      v.allow = false
      v.reason = "malformed PCActn: #{e.message}"
    end
    v
  end
end
