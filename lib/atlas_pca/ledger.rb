# frozen_string_literal: true

# Transparency-ledger verification (every registered signature suite this runtime implements; PQ keys only under pins): RFC 6962 inclusion, RFC 9162 consistency, signed tree heads, witness
# cosignatures, checkpoint chains, legacy witnessed heads and equivocation. Every function is total: any malformed input
# returns false / a failing verdict, never raises. Verdicts match the shared extension-layer vectors
# (packages/pca/conformance/ledger-vectors.json). A pure-PQ or hybrid artifact verifies only under a PQ key pinned for the identity it
# names (`pins`: { ed25519 identity => ML-DSA public key }); a suite this runtime lacks is refused.
module AtlasPca
  EMPTY_TREE_ROOT = Base64.urlsafe_encode64(Digest::SHA256.digest(''), padding: false).freeze
  STH_DOMAIN = "atlas-pca/sth/v1\x00"
  STH_WITNESS_DOMAIN = "atlas-pca/sth-witness/v2\x00"
  LEDGER_HEAD_DOMAIN = "atlas-pca/ledger-head/v1\x00"
  MAX_CONSISTENCY_PATH = (2 * 53) + 2 # longest path a tree of < 2^53 leaves can need

  module_function

  # JS Number.isSafeInteger over a JSON value.
  def ledger_safe_int?(v)
    decision_safe_int?(v)
  end

  # The artifact's own member, UNDEF when absent (an absent `alg` is ed25519; an explicit null is refused).
  def ledger_m(obj, key)
    obj.key?(key) ? obj[key] : V2JS::UNDEF
  end

  # A signature of `m` (alg / pq_pk / sig / pq_sig) over domain || canonical(bindSuite(base)) under `identity`, suite-agile.
  def ledger_signed?(identity, domain, base, m, pins)
    alg = ledger_m(m, 'alg')
    pq_pk = ledger_m(m, 'pq_pk')
    msg = domain.b + canon_bytes(IntentV2.bind_suite_fields(base, alg, pq_pk))
    IntentV2.verify_pinned_suite(alg, identity, pq_pk, msg, m['sig'], ledger_m(m, 'pq_sig'), pins)
  end

  def verify_ledger_inclusion(root, proof, commit)
    verify_inclusion(root, proof, commit)
  end

  # RFC 9162 s2.1.4.2 consistency of the tree with `old_root` and the tree with `new_root`.
  def verify_ledger_consistency(old_root, new_root, proof)
    return false unless old_root.is_a?(String) && new_root.is_a?(String) && proof.is_a?(Hash)

    first = proof['oldSize']
    second = proof['newSize']
    return false unless ledger_safe_int?(first) && ledger_safe_int?(second)

    first = first.to_i
    second = second.to_i
    return false if first.negative? || first > second

    path_in = proof['path']
    return false unless path_in.is_a?(Array) && path_in.length <= MAX_CONSISTENCY_PATH

    if first.zero?
      return false if !path_in.empty? || old_root != EMPTY_TREE_ROOT

      return second.zero? ? new_root == EMPTY_TREE_ROOT : true
    end
    return path_in.empty? && old_root == new_root if first == second

    path = path_in.map { |p| p.is_a?(String) ? b64d(p) : nil }
    return false if path.any?(&:nil?)

    if (first & (first - 1)).zero?
      o = b64d(old_root)
      return false if o.nil?

      path.unshift(o)
    end
    return false if path.empty?

    fn = first - 1
    sn = second - 1
    while fn.odd?
      fn >>= 1
      sn >>= 1
    end
    fr = sr = path[0]
    path[1..].each do |c|
      return false if sn.zero?

      if fn.odd? || fn == sn
        fr = node_hash(c, fr)
        sr = node_hash(c, sr)
        while fn.even? && fn != 0
          fn >>= 1
          sn >>= 1
        end
      else
        sr = node_hash(sr, c)
      end
      fn >>= 1
      sn >>= 1
    end
    sn.zero? && b64e(fr) == old_root && b64e(sr) == new_root
  rescue StandardError, SystemStackError
    false
  end

  def ledger_witness_body(sth)
    ge = sth['guardian_epoch']
    { 'instance_id' => sth['instance_id'], 'principal' => sth['principal'], 'size' => sth['size'], 'root' => sth['root'],
      'prev_root' => sth['prev_root'], 'guardian_epoch' => ge.nil? ? 0 : ge }
  end

  # One witness cosignature over the head statement, bound to this exact head.
  def verify_witness_cosignature(sth, cosig, witness_public, pins = nil)
    return false unless cosig.is_a?(Hash) && cosig['key'] == witness_public && cosig['sig'].is_a?(String)

    ledger_signed?(witness_public, STH_WITNESS_DOMAIN, ledger_witness_body(sth), cosig, pins)
  rescue StandardError, SystemStackError
    false
  end

  # k-of-n: at least `threshold` DISTINCT trusted witnesses carry a valid cosignature.
  # `pins` nil (absent) falls back to the policy's own pqPins; `{}` is an explicit empty set that replaces them.
  def verify_witness_cosignatures(sth, policy, pins = nil)
    pins = policy['pqPins'] if pins.nil?
    threshold = policy['threshold']
    return false unless ledger_safe_int?(threshold) && threshold >= 0
    return true if threshold.zero?

    trusted = policy['witnessKeys'] || []
    witnesses = sth['witnesses']
    return false if trusted.empty? || !witnesses.is_a?(Array)

    counted = {}
    witnesses.each do |w|
      next unless w.is_a?(Hash) && w['key'].is_a?(String) && w['sig'].is_a?(String)
      next if !trusted.include?(w['key']) || counted.key?(w['key']) || !verify_witness_cosignature(sth, w, w['key'], pins)

      counted[w['key']] = true
      return true if counted.length >= threshold
    end
    counted.length >= threshold
  rescue StandardError, SystemStackError
    false
  end

  # Guardian signature over a signed tree head, plus the witness threshold when `witness_policy` is given.
  # The guardian verifies under `pins` only; the cosigners fall back to the policy's pqPins when `pins` is nil.
  def verify_tree_head(sth, guardian_public, witness_policy = nil, pins = nil)
    return false unless sth.is_a?(Hash) && sth['guardian'] == guardian_public
    return false unless ledger_safe_int?(sth['size']) && sth['size'] >= 0

    body = %w[instance_id principal size root prev_root timestamp].to_h { |k| [k, sth[k]] }
    return false unless ledger_signed?(guardian_public, STH_DOMAIN, body, sth, pins)

    witness_policy.nil? || verify_witness_cosignatures(sth, witness_policy, pins)
  rescue StandardError, SystemStackError
    false
  end

  # Both heads genuine, same log, the proof connects them, and (adjacent heads) newer.prev_root == older.root.
  def verify_head_consistency(older, newer, proof, guardian_public, witness_policy = nil, pins = nil)
    return false unless verify_tree_head(older, guardian_public, witness_policy, pins) &&
                        verify_tree_head(newer, guardian_public, witness_policy, pins)
    return false if older['instance_id'] != newer['instance_id'] || older['principal'] != newer['principal']
    return false unless ledger_safe_int?(proof['oldSize']) && proof['oldSize'] == older['size'] &&
                        ledger_safe_int?(proof['newSize']) && proof['newSize'] == newer['size']
    return false if newer['size'] == older['size'] + 1 && newer['prev_root'] != older['root']

    verify_ledger_consistency(older['root'], newer['root'], proof)
  rescue StandardError, SystemStackError
    false
  end

  # Verify pinned checkpoints end to end. {'ok' => true} or {'ok' => false, 'at' => index of the first bad one}.
  def verify_checkpoint_chain(chain, guardian_public, witness_policy = nil, pins = nil)
    return { 'ok' => false, 'at' => 0 } unless chain.is_a?(Array) && !chain.empty?

    chain.each_with_index do |cp, i|
      return { 'ok' => false, 'at' => i } unless cp.is_a?(Hash) && verify_tree_head(cp['sth'], guardian_public, witness_policy, pins)
      next if i.zero?

      ok = cp['proof'] && verify_head_consistency(chain[i - 1]['sth'], cp['sth'], cp['proof'], guardian_public, witness_policy, pins)
      return { 'ok' => false, 'at' => i } unless ok
    end
    { 'ok' => true }
  rescue StandardError, SystemStackError
    { 'ok' => false, 'at' => 0 }
  end

  # A legacy witness-signed ledger head.
  def verify_witnessed_head(wh, witness_public, pins = nil)
    return false unless wh.is_a?(Hash) && wh['witness'] == witness_public

    body = %w[principal size root].to_h { |k| [k, wh[k]] }
    ledger_signed?(witness_public, LEDGER_HEAD_DOMAIN, body, wh, pins)
  rescue StandardError, SystemStackError
    false
  end

  # Two valid heads of one witness for the same principal and size with different roots.
  def detect_equivocation(a, b, witness_public, pins = nil)
    verify_witnessed_head(a, witness_public, pins) && verify_witnessed_head(b, witness_public, pins) &&
      a['principal'] == b['principal'] && a['size'] == b['size'] && a['root'] != b['root']
  rescue StandardError
    false
  end
end
