# frozen_string_literal: true

# K4 (verification side): risk-priced escalation (pricing config, decision, calibration from signed answers), the network-token
# binding and the ERC-7715 granted-permission check. Verdicts match packages/pca/conformance/k4-vectors.json.
# Signatures are Ed25519 (strict) over the UTF-8 bytes of hash_canonical({"kind"=>kind,"body"=>body}) (the digest string); body is the
# signed object without its "sig". Escalation is integer-only. Every function is total. Hashes use String keys.
module AtlasPca
  K4_PPM = 1_000_000
  K4_MAX_MULTIPLIER_PPM = 100 * K4_PPM
  NETWORK_TOKEN_BINDING_KIND = 'pca.network_token_binding'

  module_function

  def k4_int?(n)
    n.is_a?(Integer) && n.abs <= MAX_SAFE
  end

  # nil when the key or signature does not decode; else the strict verification result.
  def k4_sig(pub, kind, obj)
    return nil unless pub.is_a?(String) && obj['sig'].is_a?(String) && b64d(pub) && b64d(obj['sig'])

    body = obj.reject { |k, _| k == 'sig' }
    verify_b64u(pub, hash_canonical('kind' => kind, 'body' => body).b, obj['sig'])
  end

  def k4_luhn?(digits)
    sum = 0
    digits.reverse.each_char.with_index do |c, i|
      n = c.ord - 48
      if i.odd?
        n *= 2
        n -= 9 if n > 9
      end
      sum += n
    end
    (sum % 10).zero?
  end

  def looks_like_pan?(s)
    s.gsub(/[\s\-]/, '').scan(/[0-9]+/).any? { |r| r.length.between?(13, 19) && k4_luhn?(r) }
  end

  def token_ref_error(ref)
    return 'token_ref_malformed' unless ref.is_a?(String) && ref.match?(/\A[A-Za-z0-9_.:\-]{8,128}\z/)

    looks_like_pan?(ref) ? 'token_ref_looks_like_pan' : nil
  end

  # nil = valid, else the reason. provider nil = any.
  def verify_network_token_binding(b, grant, holder, issuer_nonce, provider = nil)
    return 'binding_malformed' unless b.is_a?(Hash) && b['kind'] == NETWORK_TOKEN_BINDING_KIND

    e = token_ref_error(b['token_ref'])
    return e if e

    p = b['provider']
    return 'provider_mismatch' if !p.is_a?(String) || p.empty? || (provider && p != provider)
    return 'grant_digest_mismatch' if b['grant_digest'] != hash_canonical(grant)
    return 'holder_mismatch' if b['holder'] != holder
    return 'issuer_nonce_mismatch' if b['issuer_nonce'] != issuer_nonce
    return 'binding_malformed' unless b64d(b['holder'].to_s) && b64d(b['binding_proof'].to_s)

    body = { 'kind' => NETWORK_TOKEN_BINDING_KIND, 'v' => 1, 'provider' => p, 'token_ref' => b['token_ref'],
             'grant_digest' => b['grant_digest'], 'issuer_nonce' => b['issuer_nonce'], 'holder' => b['holder'] }
    verify_b64u(b['holder'], hash_canonical(body).b, b['binding_proof']) ? nil : 'binding_proof_invalid'
  rescue StandardError
    'binding_malformed'
  end

  def pricing_config_error(c)
    return 'config_malformed' unless c.is_a?(Hash) && c['v'] == 1 && c['v'].is_a?(Integer) &&
                                     %w[principal currency sig].all? { |k| c[k].is_a?(String) }
    return 'config_amounts_invalid' unless %w[interruptionCost maxInterruptionCost hardCeilingLoss epoch].all? { |k| k3_int?(c[k]) }
    return 'config_cost_above_max' if c['interruptionCost'] > c['maxInterruptionCost']
    return 'config_step_invalid' unless k4_int?(c['tightenStepPpm']) && c['tightenStepPpm'].between?(0, K4_MAX_MULTIPLIER_PPM)

    r = k4_sig(c['principal'], 'pca.escalation_pricing', c)
    r.nil? ? 'config_malformed' : (r ? nil : 'config_signature_invalid')
  rescue StandardError
    'config_malformed'
  end

  def k4_ask(reason)
    { 'ask' => true, 'reason' => reason }
  end

  # Ask a person iff min(p * multiplier, 1e12) * loss > interruptionCost * 1e12; anything unexpected asks.
  def decide_escalation(config, cal, a)
    e = pricing_config_error(config)
    return k4_ask(e) if e
    return k4_ask('currency_mismatch') unless a.is_a?(Hash) && a['currency'] == config['currency']
    return k4_ask('risk_input_invalid') unless k3_int?(a['loss']) && k4_int?(a['pBadUpperPpm']) && a['pBadUpperPpm'].between?(0, K4_PPM)

    m = cal.is_a?(Hash) ? cal['multiplierPpm'] : nil
    return k4_ask('calibration_invalid') unless k4_int?(m) && m.between?(K4_PPM, K4_MAX_MULTIPLIER_PPM)
    return k4_ask('above_hard_ceiling') if a['loss'] > config['hardCeilingLoss']

    one = K4_PPM * K4_PPM
    capped = [a['pBadUpperPpm'] * m, one].min
    return k4_ask('expected_loss_exceeds_interruption_cost') if capped * a['loss'] > config['interruptionCost'] * one

    { 'ask' => false, 'reason' => 'expected_loss_within_interruption_cost' }
  end

  def k4_answer_ok?(a, principal)
    a.is_a?(Hash) && a['v'] == 1 && a['principal'] == principal && a['nonce'].is_a?(String) && utf16_len(a['nonce']) >= 8 &&
      a['action_digest'].is_a?(String) && %w[approve deny].include?(a['answer']) &&
      k4_sig(principal, 'pca.escalation_answer', a) == true
  rescue StandardError
    false
  end

  # Fold principal-signed answers into the calibration; the multiplier can only rise. cal = { 'multiplierPpm', 'seen' }.
  def update_calibration(config, cal, answers, risks)
    return cal if pricing_config_error(config)

    mult = cal['multiplierPpm']
    order = cal['seen'].dup
    answers.each do |a|
      next unless k4_answer_ok?(a, config['principal']) && !order.include?(a['nonce'])

      order << a['nonce']
      risk = risks[a['action_digest']]
      next if a['answer'] != 'deny' || risk.nil?

      mult = [K4_MAX_MULTIPLIER_PPM, mult + config['tightenStepPpm']].min unless decide_escalation(config, { 'multiplierPpm' => mult }, risk)['ask']
    end
    { 'multiplierPpm' => [mult, cal['multiplierPpm']].max, 'seen' => order }
  end

  def k4_lower(v)
    v.is_a?(String) ? v.downcase : "\0"
  end

  # nil when what the wallet granted is within the request and the grant. g = { grantDigest, expiresAtSec }.
  def verify_granted_permission(g, sent, got, allowed_managers, context_owner = nil)
    return 'response_malformed' unless got.is_a?(Hash) && got['permission'].is_a?(Hash)

    ctx = got['context']
    return 'context_malformed' unless ctx.is_a?(String) && ctx.match?(/\A0x[0-9a-fA-F]+\z/)

    owner = context_owner&.call(ctx)
    return 'context_bound_to_other_grant' if owner && owner != g['grantDigest']

    m = got['delegationManager']
    return 'delegation_manager_not_allowed' unless m.is_a?(String) && m.match?(/\A0x[0-9a-fA-F]{40}\z/) && allowed_managers.any? { |x| x.downcase == m.downcase }
    return 'chain_mismatch' if k4_lower(got['chainId']) != k4_lower(sent['chainId'])
    return 'recipient_mismatch' if k4_lower(got['to']) != k4_lower(sent['to'])
    return 'from_mismatch' if sent['from'] && k4_lower(got['from']) != k4_lower(sent['from'])

    perm = got['permission']
    sperm = sent['permission']
    return 'permission_type_mismatch' unless perm['type'] == sperm['type'] && %w[native-token-allowance erc20-token-allowance].include?(perm['type'])
    return 'response_malformed' unless perm['data'].is_a?(Hash)

    d = perm['data']
    sd = sperm['data']
    return 'token_mismatch' if (d['tokenAddress'].is_a?(String) ? d['tokenAddress'].downcase : '') != (sd['tokenAddress'].is_a?(String) ? sd['tokenAddress'].downcase : '')

    al = d['allowance']
    return 'amount_malformed' unless al.is_a?(String) && al.match?(/\A0x(0|[1-9a-fA-F][0-9a-fA-F]*)\z/)
    return 'amount_widened' if al.to_i(16) > sd['allowance'].to_i(16)
    return 'adjustment_widened' if perm['isAdjustmentAllowed'] != sperm['isAdjustmentAllowed'] && perm['isAdjustmentAllowed'] == true
    return 'expiry_missing' unless got['rules'].is_a?(Array)

    expiry = nil
    got['rules'].each do |rule|
      return 'unknown_rule_type' unless rule.is_a?(Hash) && rule['type'] == 'expiry'
      return 'duplicate_expiry' unless expiry.nil?

      ts = rule['data'].is_a?(Hash) ? rule['data']['timestamp'] : nil
      return 'expiry_malformed' unless k4_int?(ts)

      expiry = ts
    end
    return 'expiry_missing' if expiry.nil?

    expiry > g['expiresAtSec'] ? 'expiry_extended' : nil
  rescue StandardError
    'response_malformed'
  end
end
