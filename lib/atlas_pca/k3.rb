# frozen_string_literal: true

# K3 operational-plane artifacts, VERIFICATION only: signed policy bundles, the decision log (record commits, signed heads,
# Merkle inclusion, stream batches), list-authorized receipts and cursors, and grant management (authority digest / order,
# amendments, revocations, need approvals). Every signature is Ed25519 (strict verify) over DOMAIN-PREFIX bytes ||
# strict canonical JSON(body). Every function is total: malformed input returns the failure value, never raises.
# Verdicts match packages/pca/conformance/k3-vectors.json. Hashes use String keys; verdict hashes use String keys.
require_relative 'fresh_at'

module AtlasPca
  BUNDLE_DOMAIN = "atlas-pca/policy-bundle/v1\x00".b.freeze
  BUNDLE_REF_DOMAIN = 'atlas-pca/policy-bundle-ref/v1'
  RECORD_DOMAIN = 'atlas-pca/decision-record/v1'
  LOG_HEAD_DOMAIN = "atlas-pca/decision-log-head/v1\x00".b.freeze
  LIST_RECEIPT_DOMAIN = "atlas-pca/list-receipt/v1\x00".b.freeze
  LIST_CURSOR_DOMAIN = "atlas-pca/list-cursor/v1\x00".b.freeze
  GRANT_AMEND_DOMAIN = "atlas-pca/grant-amend/v1\x00".b.freeze
  GRANT_REVOKE_DOMAIN = "atlas-pca/grant-revoke/v1\x00".b.freeze
  NEED_APPROVE_DOMAIN = "atlas-pca/need-approve/v1\x00".b.freeze
  BUNDLE_MAX_LIST = 4096
  BUNDLE_VERSION_RE = /\A\d{1,6}(\.\d{1,6}){0,3}\z/

  module_function

  def k3_obj?(x) = x.is_a?(Hash)

  def k3_without(h, *keys) = h.reject { |k, _| keys.include?(k) }

  # ---- policy bundles ----------------------------------------------------------------------------------------------

  def bundle_digest(b)
    hash_canonical({ 'd' => BUNDLE_REF_DOMAIN, 'b' => k3_without(b, 'sigs') })
  rescue StandardError
    nil
  end

  # -1 / 0 / 1; a non-numeric part (NaN in the reference) compares as greater.
  def compare_version(a, b)
    pa = a.to_s.split('.', -1).map { |x| x.match?(/\A\d*\z/) ? x.to_i : Float::NAN }
    pb = b.to_s.split('.', -1).map { |x| x.match?(/\A\d*\z/) ? x.to_i : Float::NAN }
    [pa.length, pb.length].max.times do |i|
      d = (pa[i] || 0) - (pb[i] || 0)
      return (d.is_a?(Float) && d.nan?) || d.positive? ? 1 : -1 unless d.zero?
    end
    0
  end

  def bundle_shape_error(b)
    return 'not a policy bundle' unless k3_obj?(b) && b['v'] == 1 && b['kind'] == 'pca-policy-bundle'
    return 'bad revision or time' unless k3_int?(b['revision']) && b['revision'] >= 1 && k3_int?(b['issued_at'])

    prev_ok = b['revision'] == 1 ? !b.key?('prev') : k3_str?(b['prev'], 128)
    return 'prev must be absent at revision 1 and present after' unless prev_ok

    g = b['grants']
    return 'bad grants' unless g.is_a?(Array) && g.length <= BUNDLE_MAX_LIST && g.all? { |x| k3_str?(x, 128) }

    t = b['template_digests']
    return 'bad template_digests' unless t.is_a?(Array) && t.length <= BUNDLE_MAX_LIST && t.all? { |x| k3_str?(x, 128) }

    %w[schema_digest constitution_digest flow_rules_digest].each do |k|
      return "bad #{k}" if b.key?(k) && !k3_str?(b[k], 128)
    end
    mv = b['min_verifier_version']
    return 'bad min_verifier_version' unless mv.is_a?(String) && mv.match?(BUNDLE_VERSION_RE)

    nil
  end

  # o: 'signers' (pinned b64u keys), 'threshold', 'verifierVersion', 'last' ({'revision','digest'}) (reference spelling).
  def verify_bundle(b, o)
    e = bundle_shape_error(b)
    return { 'ok' => false, 'code' => 'malformed', 'reason' => e } if e

    sigs = b['sigs']
    th = o['threshold']
    unless sigs.is_a?(Array) && sigs.length <= 64 && k3_int?(th) && th >= 1
      return { 'ok' => false, 'code' => 'malformed', 'reason' => 'bad sigs or threshold' }
    end

    pinned = o['signers'].is_a?(Array) ? o['signers'] : []
    body = k3_without(b, 'sigs')
    good = []
    sigs.each do |s|
      next unless k3_obj?(s) && s['signer'].is_a?(String) && pinned.include?(s['signer']) && !good.include?(s['signer'])

      good << s['signer'] if k3_verify_body(BUNDLE_DOMAIN, body, s['signer'], s['sig'])
    end
    if good.length < th
      return { 'ok' => false, 'code' => 'below_threshold', 'reason' => "#{good.length} valid pinned signature(s), need #{th}" }
    end
    if !o['verifierVersion'].is_a?(String) || !o['verifierVersion'].match?(/\A\d{1,6}(\.\d{1,6}){0,3}\z/) || compare_version(o['verifierVersion'], b['min_verifier_version']).negative?
      return { 'ok' => false, 'code' => 'verifier_too_old', 'reason' => "needs verifier >= #{b['min_verifier_version']}" }
    end

    last = o['last']
    if k3_obj?(last)
      rev = b['revision']
      if rev < last['revision']
        return { 'ok' => false, 'code' => 'rollback', 'reason' => "revision #{rev} < accepted #{last['revision']}" }
      end
      if rev == last['revision'] && bundle_digest(b) != last['digest']
        return { 'ok' => false, 'code' => 'broken_chain', 'reason' => 'same revision, different content' }
      end
      if rev == last['revision'] + 1 && b['prev'] != last['digest']
        return { 'ok' => false, 'code' => 'broken_chain', 'reason' => 'prev does not chain to the accepted revision' }
      end
    end
    { 'ok' => true, 'revision' => b['revision'], 'digest' => bundle_digest(b), 'signers' => good }
  rescue StandardError
    { 'ok' => false, 'code' => 'malformed', 'reason' => 'malformed bundle' }
  end

  # ---- decision log ------------------------------------------------------------------------------------------------

  def record_commit(r)
    hash_canonical({ 'd' => RECORD_DOMAIN, 'r' => r })
  rescue StandardError
    nil
  end

  def verify_log_head(h, signer)
    return false unless k3_obj?(h) && h['v'] == 1 && h['signer'] == signer && k3_int?(h['size']) && k3_int?(h['issued_at']) &&
                        h['root'].is_a?(String) && h['last_commit'].is_a?(String)

    k3_verify_body(LOG_HEAD_DOMAIN, k3_without(h, 'sig'), signer, h['sig'])
  rescue StandardError
    false
  end

  # This record is in the log the signed head commits to, and the head is by the pinned signer.
  def verify_record_inclusion(rec, proof, head, signer)
    return false unless verify_log_head(head, signer)

    c = record_commit(rec)
    !c.nil? && verify_inclusion(head['root'], proof, c)
  rescue StandardError
    false
  end

  # Receiver side of the stream. state: {'next','lastCommit'}. Returns {'ok'=>true,'next','lastCommit'} or {'ok'=>false,'reason'}.
  def verify_batch(b, state, signer)
    raise 'batch' unless k3_obj?(b) && k3_obj?(state)

    if b['from'] != state['next']
      return { 'ok' => false, 'reason' => "gap or replay: batch starts at #{b['from']}, expected #{state['next']}" }
    end
    return { 'ok' => false, 'reason' => 'head not signed by the pinned log signer' } unless verify_log_head(b['head'], signer)

    last = state['lastCommit']
    n = state['next']
    b['records'].each do |r|
      return { 'ok' => false, 'reason' => "chain broken at seq #{r['seq']}" } if r['seq'] != n || r['prev'] != last

      last = record_commit(r)
      n += 1
    end
    head = b['head']
    return { 'ok' => false, 'reason' => 'batch is longer than the signed head' } if n > head['size']
    if n == head['size'] && last != head['last_commit']
      return { 'ok' => false, 'reason' => 'batch end does not match the signed head' }
    end

    { 'ok' => true, 'next' => n, 'lastCommit' => last }
  rescue StandardError
    { 'ok' => false, 'reason' => 'malformed batch' }
  end

  # ---- list receipts and cursors -----------------------------------------------------------------------------------

  def objects_digest(objects)
    hash_canonical({ 'd' => 'atlas-pca/list-objects/v1', 'o' => objects })
  rescue StandardError
    nil
  end

  # `objects` (optional): the returned ids; also checks the count and the digest.
  def verify_list_receipt(r, signer, objects = nil)
    return false unless k3_obj?(r) && r['v'] == 1 && r['signer'] == signer && k3_str?(r['subject']) && k3_str?(r['resource_type']) &&
                        k3_int?(r['count']) && k3_int?(r['issued_at'])
    return false unless k3_verify_body(LIST_RECEIPT_DOMAIN, k3_without(r, 'sig'), signer, r['sig'])

    objects.nil? || (objects.is_a?(Array) && objects.length == r['count'] && objects_digest(objects) == r['objects_digest'])
  rescue StandardError
    false
  end

  # b: 'subject', 'resourceType', 'filterId', 'policyDigest', 'relation' ({'relation'}), 'limit' (reference spelling).
  def list_bind(b)
    rel = b['relation'].is_a?(Hash) ? b['relation']['relation'] : nil
    hash_canonical({ 's' => b['subject'], 't' => b['resourceType'], 'f' => b['filterId'], 'p' => b['policyDigest'], 'r' => rel, 'l' => b['limit'] })
  rescue StandardError
    nil
  end

  # Shape, signature by `signer` and (when `bind` is given) that it was issued for exactly those inputs.
  def verify_list_cursor(tok, signer, bind = nil)
    return { 'ok' => false, 'reason' => 'malformed' } unless tok.is_a?(String)

    parts = tok.split('.', -1)
    p64 = parts[0]
    s = parts[1]
    c = begin
      raw = p64.nil? || p64.empty? ? nil : b64d(p64)
      raw && parse_json_text(raw.dup.force_encoding(Encoding::UTF_8).scrub("�"))
    rescue StandardError
      return { 'ok' => false, 'reason' => 'malformed' }
    end
    if parts.length > 2 || !k3_obj?(c) || s.nil? || s.empty? || c['v'] != 1 || !c['bind'].is_a?(String) || !k3_int?(c['skip']) ||
       (c.key?('inner') && !c['inner'].is_a?(String))
      return { 'ok' => false, 'reason' => 'malformed' }
    end
    return { 'ok' => false, 'reason' => 'signature' } if c['signer'] != signer || !k3_verify_body(LIST_CURSOR_DOMAIN, c, signer, s)
    return { 'ok' => false, 'reason' => 'bind' } if !bind.nil? && c['bind'] != list_bind(bind)

    c.key?('inner') ? { 'ok' => true, 'inner' => c['inner'], 'skip' => c['skip'] } : { 'ok' => true, 'skip' => c['skip'] }
  rescue StandardError
    { 'ok' => false, 'reason' => 'malformed' }
  end

  # ---- authority + grant management --------------------------------------------------------------------------------

  def authority_res_covers?(p, r) = p.end_with?('*') ? r.start_with?(p[0...-1]) : p == r

  def authority_res_subset?(small, big)
    small.all? { |s| big.any? { |b| authority_res_covers?(b, s) && (!s.end_with?('*') || b.end_with?('*') || b == s) } }
  end

  def authority_le?(a, b)
    return false unless a['verbs'].all? { |v| b['verbs'].include?(v) } && authority_res_subset?(a['resources'], b['resources'])

    (a['limits'] || {}).each do |k, v|
      bv = (b['limits'] || {})[k]
      return false if !bv.nil? && !(v <= bv)
    end
    (b['limits'] || {}).each_key { |k| return false if (a['limits'] || {})[k].nil? }
    (a['expires_at'] || Float::INFINITY) <= (b['expires_at'] || Float::INFINITY)
  end

  # 'narrower' | 'equal' | 'wider' | 'incomparable'
  def compare_authority(old_a, new_a)
    nle = authority_le?(new_a, old_a)
    ole = authority_le?(old_a, new_a)
    nle && ole ? 'equal' : (nle ? 'narrower' : (ole ? 'wider' : 'incomparable'))
  end

  def authority_digest(a)
    hash_canonical({ 'd' => 'atlas-pca/authority/v1',
                     'a' => a.merge('verbs' => a['verbs'].sort_by { |x| utf16_key(x) }, 'resources' => a['resources'].sort_by { |x| utf16_key(x) }) })
  rescue StandardError
    nil
  end

  # Union. A ceiling or expiry is only ever RAISED by the delta; one the delta omits is kept.
  def merge_authority(a, d)
    limits = {}
    (a['limits'] || {}).each { |k, v| limits[k] = [v, (d['limits'] || {})[k] || v].max }
    exp = a['expires_at'].nil? ? nil : [a['expires_at'], d['expires_at'] || a['expires_at']].max
    out = { 'verbs' => (a['verbs'] + d['verbs']).uniq, 'resources' => (a['resources'] + d['resources']).uniq }
    out['limits'] = limits unless limits.empty?
    out['expires_at'] = exp unless exp.nil?
    out
  end

  def authority_ok?(a)
    k3_obj?(a) && a['verbs'].is_a?(Array) && a['verbs'].length <= 256 && a['verbs'].all? { |v| k3_str?(v, 128) } &&
      a['resources'].is_a?(Array) && a['resources'].length <= 1024 && a['resources'].all? { |v| k3_str?(v, 512) } &&
      (!a.key?('limits') || (k3_obj?(a['limits']) && a['limits'].values.all? { |v| v.is_a?(Numeric) && v.finite? && v >= 0 })) &&
      (!a.key?('expires_at') || k3_int?(a['expires_at']))
  end

  def amend_message(g, action, authority)
    { 'grant' => g['id'], 'rev' => g['rev'], 'action' => action, 'authority' => authority_digest(authority) }
  end

  def grant_revoke_message(id, scope) = { 'grant' => id, 'scope' => scope }

  def need_approve_message(nr, rev, approved)
    { 'need' => nr['id'], 'grant' => nr['grant_id'], 'rev' => rev, 'approved' => approved }
  end

  # cur: {id, rev, principal, agent, status, authority}. Check order is normative: request shape -> authority shape -> active ->
  # classification -> signature (required, then bad; widening needs the PRINCIPAL) -> step-up.
  # Returns {'ok'=>true,'widens'=>,'next'=>authority} or {'ok'=>false,'code'=>}.
  def verify_amendment(cur, req, step_up_ok)
    return { 'ok' => false, 'code' => 'bad_request' } unless k3_obj?(req) && %w[narrow merge replace].include?(req['action'])
    return { 'ok' => false, 'code' => 'bad_request' } unless authority_ok?(req['authority'])
    return { 'ok' => false, 'code' => 'not_active' } if cur['status'] != 'active'

    action = req['action']
    nxt = action == 'merge' ? merge_authority(cur['authority'], req['authority']) : req['authority']
    order = compare_authority(cur['authority'], nxt)
    widens = %w[wider incomparable].include?(order)
    return { 'ok' => false, 'code' => 'not_narrower' } if (!widens && action == 'narrow' && order == 'equal') || (widens && action == 'narrow')

    signed_by = req['signed_by']
    unless req['sig'].is_a?(String) && %w[holder principal].include?(signed_by)
      return { 'ok' => false, 'code' => 'signature_required' }
    end
    return { 'ok' => false, 'code' => 'signature_required' } if widens && signed_by != 'principal'

    signer = signed_by == 'principal' ? cur['principal'] : cur['agent']
    unless k3_verify_body(GRANT_AMEND_DOMAIN, amend_message(cur, action, req['authority']), signer, req['sig'])
      return { 'ok' => false, 'code' => 'bad_signature' }
    end
    return { 'ok' => false, 'code' => 'step_up_required' } if widens && !step_up_ok

    { 'ok' => true, 'widens' => widens, 'next' => nxt }
  rescue StandardError
    { 'ok' => false, 'code' => 'bad_request' }
  end

  # root: {id, principal}. Returns {'ok'=>true,'scope'=>} or {'ok'=>false,'code'=>}.
  def verify_revoke_signature(root, scope, sig)
    return { 'ok' => false, 'code' => 'bad_request' } unless %w[grant agent subtree].include?(scope)
    return { 'ok' => false, 'code' => 'bad_signature' } unless k3_verify_body(GRANT_REVOKE_DOMAIN, grant_revoke_message(root['id'], scope), root['principal'], sig)

    { 'ok' => true, 'scope' => scope }
  rescue StandardError
    { 'ok' => false, 'code' => 'bad_signature' }
  end

  # Principal signature over (need, grant, rev, approved) -> same count -> each approved need names the same verb and resource,
  # amounts only LOWERED and only when adjustable -> step-up. Returns {'ok'=>true,'authority'=>} or {'ok'=>false,'code'=>}.
  def verify_need_approval(nr, g, approved, sig, step_up_ok)
    return { 'ok' => false, 'code' => 'conflict' } if nr['status'] != 'pending'
    unless k3_verify_body(NEED_APPROVE_DOMAIN, need_approve_message(nr, g['rev'], approved), g['principal'], sig)
      return { 'ok' => false, 'code' => 'bad_signature' }
    end
    return { 'ok' => false, 'code' => 'need_not_lowered_only' } unless approved.is_a?(Array) && approved.length == nr['needs'].length

    delta = { 'verbs' => [], 'resources' => [], 'limits' => {} }
    approved.each_with_index do |a, i|
      want = nr['needs'][i]
      return { 'ok' => false, 'code' => 'need_not_lowered_only' } if a['verb'] != want['verb'] || a['resource'] != want['resource']

      (a['limits'] || {}).each do |k, v|
        w = (want['limits'] || {})[k]
        return { 'ok' => false, 'code' => 'need_not_lowered_only' } if w.nil? || v > w
        return { 'ok' => false, 'code' => 'need_not_adjustable' } if v < w && !want['adjustable']
      end
      delta['verbs'] << a['verb']
      delta['resources'] << a['resource']
      # A limit the need names but the principal omitted is not granted at all.
      (a['limits'] || {}).each { |k, v| delta['limits'][k] = [delta['limits'][k] || 0, v].max }
    end
    delta.delete('limits') if delta['limits'].empty?
    return { 'ok' => false, 'code' => 'step_up_required' } unless step_up_ok

    { 'ok' => true, 'authority' => merge_authority(g['authority'], delta) }
  rescue StandardError
    { 'ok' => false, 'code' => 'need_not_lowered_only' }
  end
end
