# frozen_string_literal: true

# The A2A binding (verification side): typed needs (pca_need), per-hop chain extension, the pure gate of AUTH_REQUIRED resumption,
# push-token binding and signed task-update receipts. Every function is total. Replays packages/pca/conformance/a2a-vectors.json.
# Per-hop PCActn verification is the ordinary verifier's job; this is what surrounds it. Hashes use String keys.
module AtlasPca
  A2A_NEED_DOMAIN = 'atlas-pca/need/v1'
  A2A_RECEIPT_DOMAIN = "atlas-pca/a2a-receipt/v1\x00".b.freeze
  A2A_RECEIPT_REF = 'atlas-pca/a2a-receipt-ref/v1'
  A2A_NEED_MEMBERS = %w[v kind verb resource scopes grant_ref limits discharges tier policy_digest].freeze
  A2A_TERMINAL = %w[TASK_STATE_COMPLETED TASK_STATE_FAILED TASK_STATE_CANCELED TASK_STATE_REJECTED].freeze
  A2A_STATES = (A2A_TERMINAL + %w[TASK_STATE_SUBMITTED TASK_STATE_WORKING TASK_STATE_INPUT_REQUIRED TASK_STATE_AUTH_REQUIRED]).freeze

  module_function

  # nil when valid, else the refusal code.
  def a2a_need_error(x)
    return 'bad_shape' unless x.is_a?(Hash)
    return 'unknown_member' unless x.keys.all? { |k| A2A_NEED_MEMBERS.include?(k) }
    return 'bad_version' unless x['v'] == 1
    return 'bad_kind' unless %w[scope grant discharge escalate].include?(x['kind'])
    return 'bad_field' unless k3_str?(x['verb'], 128) && k3_str?(x['resource'], 512)

    if x.key?('scopes')
      sc = x['scopes']
      return 'bad_field' unless sc.is_a?(Array) && sc.length <= 16 && sc.all? { |s| k3_str?(s, 128) && !s.match?(/\s/) }
    end
    %w[grant_ref policy_digest].each { |k| return 'bad_field' if x.key?(k) && !k3_str?(x[k], 128) }
    if x.key?('tier')
      return 'bad_field' unless [2, 3].include?(x['tier']) && x['kind'] == 'escalate'
    end
    if x.key?('limits')
      l = x['limits']
      return 'bad_field' unless l.is_a?(Hash) && l.length <= 16 && l.all? { |k, v| k3_str?(k, 64) && v.is_a?(Numeric) && v >= 0 }
    end
    if x.key?('discharges')
      d = x['discharges']
      return 'bad_field' unless d.is_a?(Array) && d.length <= 16 && d.all? { |e| e.is_a?(Hash) && (e.keys - %w[issuer claim]).empty? && k3_str?(e['issuer'], 512) && k3_str?(e['claim'], 256) }
    end
    return 'bad_field' if x['kind'] == 'escalate' && !x.key?('tier')

    nil
  end

  # [need, nil] or [nil, code]
  def decode_a2a_need(value)
    return [nil, 'bad_base64'] unless value.is_a?(String) && !value.empty?
    return [nil, 'too_long'] if value.length > 2048

    raw = b64d(value)
    return [nil, 'bad_base64'] if raw.nil?

    text = raw.dup.force_encoding(Encoding::UTF_8)
    return [nil, 'bad_utf8'] unless text.valid_encoding?

    parsed = begin
      parse_json(text, any_top: true)
    rescue StandardError
      return [nil, 'bad_json']
    end
    code = a2a_need_error(parsed)
    code ? [nil, code] : [parsed, nil]
  end

  def a2a_need_digest(need) = hash_canonical({ 'd' => A2A_NEED_DOMAIN, 'need' => need })

  # { 'ok' => true } or { 'ok' => false, 'failedHop' =>, 'reason' => }
  def check_a2a_chain_extension(chains)
    prev = nil
    chains.each_with_index do |ids, i|
      return { 'ok' => false, 'failedHop' => i, 'reason' => 'no_chain' } unless ids.is_a?(Array) && !ids.empty?
      if prev && (ids.length < prev.length || prev.each_index.any? { |k| ids[k] != prev[k] })
        return { 'ok' => false, 'failedHop' => i, 'reason' => 'chain_does_not_extend_previous_hop' }
      end

      prev = ids
    end
    { 'ok' => true }
  end

  # nil when the full verifier may now be asked, else the refusal code.
  def a2a_resume_gate(state, need_encoded, answer_digest, proof_action)
    return 'task_not_auth_required' unless ['TASK_STATE_AUTH_REQUIRED', 'auth-required'].include?(state)

    need, = need_encoded.nil? ? [nil, nil] : decode_a2a_need(need_encoded)
    return 'no_valid_need' if need.nil?
    return 'answer_not_bound_to_need' unless answer_digest == a2a_need_digest(need)
    return 'no_proof' if proof_action.nil?
    return 'action_mismatch' unless proof_action['verb'] == need['verb'] && proof_action['resource'] == need['resource']

    nil
  end

  # nil where the reference throws (a salt shorter than 16 characters)
  def a2a_push_token(task_id, chain_ids, salt)
    return nil unless salt.is_a?(String) && salt.length >= 16

    hash_canonical({ 'd' => 'atlas-pca/a2a-push/v1', 'task_id' => task_id, 'chain' => pca_grant_chain_digest(chain_ids), 'salt' => salt })
  end

  # { 'ok' => true } or { 'ok' => false, 'reason' => }
  def check_a2a_push(task_id, chain_ids, salt, token, payload)
    return { 'ok' => false, 'reason' => 'no_token' } unless token.is_a?(String) && !token.empty?
    return { 'ok' => false, 'reason' => 'token_mismatch' } unless token == a2a_push_token(task_id, chain_ids, salt)

    p = payload.is_a?(Hash) ? payload : {}
    [%w[task id], %w[statusUpdate taskId], %w[artifactUpdate taskId]].each do |key, field|
      c = p[key]
      v = c.is_a?(Hash) ? c[field] : nil
      return v == task_id ? { 'ok' => true } : { 'ok' => false, 'reason' => 'task_mismatch' } unless v.nil?
    end
    { 'ok' => false, 'reason' => 'task_mismatch' }
  end

  def a2a_receipt_digest(r) = hash_canonical({ 'd' => A2A_RECEIPT_REF, 'r' => r })

  def verify_a2a_receipt(r, signer)
    return false unless r.is_a?(Hash) && r['v'] == 1 && r['signer'] == signer
    return false unless k3_str?(r['task_id'], 4096) && A2A_STATES.include?(r['state']) && k3_int?(r['seq']) && k3_int?(r['issued_at'])
    return false unless r['chain'].is_a?(String) && !b64d(r['chain'], 32).nil?

    prev = r['prev']
    return false unless prev.nil? || (prev.is_a?(String) && !b64d(prev, 32).nil?)
    return false unless r['seq'].zero? == prev.nil?

    body = %w[v task_id state seq prev chain issued_at signer].each_with_object({}) { |k, h| h[k] = r[k] }
    k3_verify_body(A2A_RECEIPT_DOMAIN, body, signer, r['sig'])
  end

  def check_a2a_receipt_chain(receipts, signer, task_id, chain_ids)
    return { 'ok' => false, 'code' => 'empty' } unless receipts.is_a?(Array) && !receipts.empty?

    chain = pca_grant_chain_digest(chain_ids)
    prev = nil
    receipts.each_with_index do |r, i|
      return { 'ok' => false, 'code' => 'bad_receipt', 'at' => i } unless verify_a2a_receipt(r, signer)
      return { 'ok' => false, 'code' => 'wrong_task', 'at' => i } unless r['task_id'] == task_id
      return { 'ok' => false, 'code' => 'wrong_chain', 'at' => i } unless r['chain'] == chain

      if prev.nil?
        return { 'ok' => false, 'code' => 'bad_start', 'at' => i } unless r['seq'].zero?
      else
        return { 'ok' => false, 'code' => 'after_terminal', 'at' => i } if A2A_TERMINAL.include?(prev['state'])
        unless r['seq'] == prev['seq'] + 1 && r['prev'] == a2a_receipt_digest(prev)
          return { 'ok' => false, 'code' => 'broken_link', 'at' => i }
        end
      end
      prev = r
    end
    { 'ok' => true, 'terminal' => A2A_TERMINAL.include?(prev['state']), 'last_state' => prev['state'] }
  end

  def a2a_may_trigger_next?(receipts, signer, task_id, chain_ids)
    r = check_a2a_receipt_chain(receipts, signer, task_id, chain_ids)
    r['ok'] && r['last_state'] == 'TASK_STATE_COMPLETED'
  end
end
