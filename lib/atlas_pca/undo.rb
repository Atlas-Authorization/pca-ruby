# frozen_string_literal: true

# UNDO WINDOWS, the pure layer: a reversible action runs at once and the principal gets a veto window in which it can be undone.
# Port of the TypeScript reference undo.ts (compensation digest, the signed one-click undo token, the signed hash-chained
# audit receipts, the state machine and the window clamp). The coordinator that admits windows, writes the ledger, runs
# compensations and notifies the principal is the TypeScript server (or the hosted ledger); this module lets a Ruby service
# verify undo tokens, receipts and records, and drive the same state machine.
#
#     open --veto (now <= window_end)--> vetoed --compensated--> compensated
#       |                                  |  \--compensation_failed--> compensation_failed --retry--> vetoed
#       +--finalize (now > window_end)--> finalized
#       +--abort (the effect never ran)--> finalized
#
# Hashes use String keys. Every check and transition is total: malformed input is refused, never raised.
module AtlasPca
  UNDO_TOKEN_DOMAIN = "atlas-pca/undo-token/v1\x00"
  UNDO_RECEIPT_DOMAIN = "atlas-pca/undo-receipt/v1\x00"
  UNDO_COMPENSATION_DOMAIN = 'atlas-pca/undo-compensation/v1'
  UNDO_RECEIPT_REF_DOMAIN = 'atlas-pca/undo-receipt-ref/v1'
  UNDO_TOKEN_REF_DOMAIN = 'atlas-pca/undo-token-ref/v1'
  UNDO_TOKEN_KIND = 'pca-undo-token'
  UNDO_RECEIPT_KIND = 'pca-undo-receipt'
  UNDO_MIN_WINDOW_MS = 30_000
  UNDO_DEFAULT_WINDOW_MS = 900_000
  UNDO_MAX_WINDOW_MS = 86_400_000
  UNDO_STATES = %w[open vetoed compensated compensation_failed finalized].freeze
  UNDO_EVENTS = %w[opened vetoed compensated compensation_failed finalized aborted retried effect].freeze
  VETO_VIAS = %w[token operator fraud_proof revocation].freeze
  UNDO_TOKEN_FIELDS = %w[v kind record aud principal compensation_digest render_digest exp signer sig].freeze
  UNDO_RECEIPT_FIELDS = %w[v kind record event state at compensation_digest prev note signer sig].freeze
  UNDO_ID_MAX = 256
  MAX_UNDO_TOKEN_TEXT = 4096

  module_function

  # hashCanonical({d, verb, resource, params, undo_of, def_digest, target_param?}) of a compensating action.
  def compensation_digest(c)
    h = { 'd' => UNDO_COMPENSATION_DOMAIN, 'verb' => c['verb'], 'resource' => c['resource'], 'params' => c['params'],
          'undo_of' => c['undo_of'], 'def_digest' => c['def_digest'] }
    h['target_param'] = c['target_param'] if c.key?('target_param')
    wb_hash(h)
  end

  # A record id: a string of 1..256 UTF-16 code units without control characters.
  def undo_id_ok?(s)
    s.is_a?(String) && !s.empty? && utf16_len(s) <= UNDO_ID_MAX && !s.b.match?(/[\x00-\x1f]/n)
  end

  def undo_message(domain, body) = domain.b + wb_canon_bytes(body)

  def undo_signed_ok?(signer, domain, body, sig)
    verify_b64u(signer, undo_message(domain, body), sig)
  rescue StandardError
    false
  end

  # ---- the one-click undo token -------------------------------------------------------------------------------------------

  # Sign the token for a record {id, aud, principal, compensation_digest, render_digest?, window_end} with the undo service
  # key (an AtlasPca::KeyPair).
  def sign_undo_token(rec, key)
    raise ArgumentError, 'sign_undo_token: the undo service key must be an AtlasPca::KeyPair' unless key.respond_to?(:sign) && key.respond_to?(:public)

    body = { 'v' => 1, 'kind' => UNDO_TOKEN_KIND, 'record' => rec['id'], 'aud' => rec['aud'], 'principal' => rec['principal'],
             'compensation_digest' => rec['compensation_digest'], 'render_digest' => rec['render_digest'].nil? ? '' : rec['render_digest'],
             'exp' => rec['window_end'], 'signer' => key.public }
    body.merge('sig' => b64e(key.sign(undo_message(UNDO_TOKEN_DOMAIN, body))))
  end

  # The first check a token fails, in order: malformed, signer, signature, record, binding, expired; 'ok' when none. The
  # token is valid THROUGH exp (now == exp passes). `rec` is the stored record. Never raises.
  def undo_token_check(token, expected_signer, rec, now)
    return 'malformed' unless token.is_a?(Hash) && token.length == UNDO_TOKEN_FIELDS.length && UNDO_TOKEN_FIELDS.all? { |k| token.key?(k) }

    t = token
    shape = wb_strict_eq?(t['v'], 1) && t['kind'] == UNDO_TOKEN_KIND && undo_id_ok?(t['record']) &&
            %w[aud principal compensation_digest render_digest].all? { |k| t[k].is_a?(String) } && wb_safe_int?(t['exp']) &&
            t['signer'].is_a?(String) && !b64d(t['sig'], 64).nil?
    return 'malformed' unless shape
    return 'signer' unless t['signer'] == expected_signer
    return 'signature' unless undo_signed_ok?(expected_signer, UNDO_TOKEN_DOMAIN, t.reject { |k, _| k == 'sig' }, t['sig'])
    return 'record' unless t['record'] == rec['id']

    render = rec['render_digest'].nil? ? '' : rec['render_digest']
    unless t['aud'] == rec['aud'] && t['principal'] == rec['principal'] && t['compensation_digest'] == rec['compensation_digest'] &&
           t['render_digest'] == render && wb_strict_eq?(t['exp'], rec['window_end'])
      return 'binding'
    end
    return 'expired' if !wb_safe_int?(now) || now > t['exp']

    'ok'
  rescue StandardError
    'malformed'
  end

  # The token as a URL-safe string: base64url of its strict-canonical JSON.
  def encode_undo_token(t) = b64e(wb_canon_bytes(t))

  # Inverse of encode_undo_token: the JSON object, or nil for anything else (empty, over 4096 characters, not strict
  # base64url, not UTF-8, not a JSON object).
  def decode_undo_token(s)
    return nil unless s.is_a?(String) && !s.empty? && s.length <= MAX_UNDO_TOKEN_TEXT

    bin = b64d(s)
    return nil if bin.nil?

    text = bin.dup.force_encoding(Encoding::UTF_8)
    return nil unless text.valid_encoding?

    x = parse_json_text(text)
    x.is_a?(Hash) ? x : nil
  rescue StandardError
    nil
  end

  def undo_token_digest(t) = wb_hash({ 'd' => UNDO_TOKEN_REF_DOMAIN, 't' => t })

  # ---- receipts -----------------------------------------------------------------------------------------------------------

  def undo_receipt_digest(r) = wb_hash({ 'd' => UNDO_RECEIPT_REF_DOMAIN, 'r' => r })

  # Sign the receipt of one transition: body {record, event, state, at, compensation_digest, prev, note}.
  def sign_undo_receipt(body, key)
    b = { 'v' => 1, 'kind' => UNDO_RECEIPT_KIND, 'record' => body['record'], 'event' => body['event'], 'state' => body['state'],
          'at' => body['at'], 'compensation_digest' => body['compensation_digest'], 'prev' => body['prev'], 'note' => body['note'],
          'signer' => key.public }
    b.merge('sig' => b64e(key.sign(undo_message(UNDO_RECEIPT_DOMAIN, b))))
  end

  # True iff `r` has exactly the 11 members, a known event and state, and is signed by `expected_signer`. Never raises.
  def verify_undo_receipt(r, expected_signer)
    return false unless r.is_a?(Hash)

    ok = wb_strict_eq?(r['v'], 1) && r['kind'] == UNDO_RECEIPT_KIND && undo_id_ok?(r['record']) && UNDO_EVENTS.include?(r['event']) &&
         UNDO_STATES.include?(r['state']) && wb_safe_int?(r['at']) && %w[compensation_digest prev note].all? { |k| r[k].is_a?(String) } &&
         r['signer'].is_a?(String) && r['signer'] == expected_signer && !b64d(r['sig'], 64).nil?
    return false unless ok && r.length == UNDO_RECEIPT_FIELDS.length && UNDO_RECEIPT_FIELDS.all? { |k| r.key?(k) }

    undo_signed_ok?(expected_signer, UNDO_RECEIPT_DOMAIN, r.reject { |k, _| k == 'sig' }, r['sig'])
  rescue StandardError
    false
  end

  # nil iff the record's receipts {id, compensation_digest, state, receipts} form a sound chain under `expected_signer`:
  # non-empty, every receipt verifies and names this record and compensation, `prev` links each to the previous one ('' for
  # the first), the first is `opened`, `at` never decreases and the last state is the record's state. Else the reason.
  def undo_receipt_chain_error(rec, expected_signer)
    rs = rec.is_a?(Hash) ? rec['receipts'] : nil
    return 'no receipts' unless rs.is_a?(Array) && !rs.empty?

    prev = ''
    at = nil
    rs.each_with_index do |r, i|
      return "receipt #{i} does not verify" unless verify_undo_receipt(r, expected_signer)
      return "receipt #{i} is for another record" unless r['record'] == rec['id'] && r['compensation_digest'] == rec['compensation_digest']
      return "receipt #{i} does not link to the previous one" unless r['prev'] == prev
      return 'the first receipt is not opened' if i.zero? && r['event'] != 'opened'
      return "receipt #{i} goes back in time" if !at.nil? && r['at'] < at

      prev = undo_receipt_digest(r)
      at = r['at']
    end
    rs[-1]['state'] == rec['state'] ? nil : 'the last receipt does not state the record state'
  rescue StandardError
    'evaluation error (fail closed)'
  end

  # ---- the pure transitions -----------------------------------------------------------------------------------------------

  def undo_refused(code, reason) = { 'outcome' => 'refused', 'code' => code, 'reason' => reason }

  # The state machine, pure: `rec` is not modified. Events: {'kind' => 'veto', 'veto' => {at, via, by}}, finalize,
  # {abort, reason}, {effect, result?}, {compensated, result?}, {compensation_failed, reason}, retry. Returns
  # {'outcome' => 'applied', 'record' => next (ver + 1), 'receipt' => {event, note}}, {'outcome' => 'replayed', 'record'} or
  # {'outcome' => 'refused', 'code', 'reason'}. `now` is the trusted clock (a safe integer). Never raises.
  def undo_transition(rec, ev, now)
    unless rec.is_a?(Hash) && UNDO_STATES.include?(rec['state']) && wb_safe_int?(rec['window_end']) && wb_safe_int?(rec['ver'])
      return undo_refused('invalid', 'malformed record')
    end
    return undo_refused('invalid', 'now must be a safe integer') unless wb_safe_int?(now)

    st = rec['state']
    nxt = lambda do |patch, event, note = ''|
      { 'outcome' => 'applied', 'record' => Marshal.load(Marshal.dump(rec)).merge(patch).merge('ver' => wb_int(rec['ver']) + 1),
        'receipt' => { 'event' => event, 'note' => note } }
    end
    reason_of = ->(n) { utf16_slice(wb_js_str(wb_get(ev, 'reason')), n) }
    with_result = ->(h) { ev.key?('result') ? h.merge('result' => Marshal.load(Marshal.dump(ev['result']))) : h }
    replayed = { 'outcome' => 'replayed', 'record' => rec }
    case ev.is_a?(Hash) ? ev['kind'] : nil
    when 'veto'
      v = ev['veto']
      unless v.is_a?(Hash) && wb_safe_int?(v['at']) && VETO_VIAS.include?(v['via']) && v['by'].is_a?(String) && !v['by'].empty?
        return undo_refused('invalid', 'malformed veto')
      end
      return replayed if %w[vetoed compensated compensation_failed].include?(st)
      return undo_refused('finalized', 'the window is closed and the action is final') if st == 'finalized'
      return undo_refused('window_closed', "the veto window closed at #{rec['window_end']}") if now > rec['window_end']

      nxt.call({ 'state' => 'vetoed', 'veto' => v.dup }, 'vetoed', v['via'])
    when 'finalize'
      return replayed if st == 'finalized'
      return undo_refused('vetoed', "a #{st} record is not finalized") if st != 'open'
      return undo_refused('window_open', "the veto window is open until #{rec['window_end']}") if now <= rec['window_end']

      nxt.call({ 'state' => 'finalized', 'outcome' => { 'at' => now, 'status' => 'finalized' } }, 'finalized')
    when 'abort'
      return replayed if st == 'finalized' && rec['outcome'].is_a?(Hash) && rec['outcome']['status'] == 'aborted'
      return undo_refused('finalized', "a #{st} record cannot be aborted") unless %w[open vetoed].include?(st)
      return undo_refused('effect_recorded', 'the effect ran: it can only be compensated or finalized') if rec.key?('effect')

      nxt.call({ 'state' => 'finalized', 'outcome' => { 'at' => now, 'status' => 'aborted', 'reason' => reason_of.call(512) } }, 'aborted', reason_of.call(128))
    when 'effect'
      return replayed if rec.key?('effect')
      return undo_refused('finalized', "a #{st} record takes no effect report") unless %w[open vetoed].include?(st)

      nxt.call({ 'effect' => with_result.call({ 'at' => now }) }, 'effect')
    when 'compensated'
      return replayed if st == 'compensated'
      return undo_refused('not_vetoed', "a #{st} record is not being compensated") unless %w[vetoed compensation_failed].include?(st)

      nxt.call({ 'state' => 'compensated', 'outcome' => with_result.call({ 'at' => now, 'status' => 'compensated' }) }, 'compensated')
    when 'compensation_failed'
      return replayed if st == 'compensation_failed'
      return undo_refused('not_vetoed', "a #{st} record is not being compensated") if st != 'vetoed'

      nxt.call({ 'state' => 'compensation_failed', 'outcome' => { 'at' => now, 'status' => 'compensation_failed', 'reason' => reason_of.call(512) } },
               'compensation_failed', reason_of.call(128))
    when 'retry'
      return undo_refused('not_failed', "a #{st} record is not retried") if st != 'compensation_failed'
      return undo_refused('invalid', 'malformed record') unless wb_safe_int?(rec['attempt'])

      nxt.call({ 'state' => 'vetoed', 'attempt' => wb_int(rec['attempt']) + 1 }, 'retried')
    else
      undo_refused('invalid', 'unknown event')
    end
  rescue StandardError
    undo_refused('invalid', 'evaluation error (fail closed)')
  end

  # Append the signed receipt of an applied transition to its record (linked to the previous receipt).
  def undo_with_receipt(rec, receipt, at, key)
    rs = rec['receipts'].is_a?(Array) ? rec['receipts'] : []
    r = sign_undo_receipt({ 'record' => rec['id'], 'event' => receipt['event'], 'state' => rec['state'], 'at' => at,
                            'compensation_digest' => rec['compensation_digest'], 'prev' => rs.empty? ? '' : undo_receipt_digest(rs[-1]),
                            'note' => receipt['note'] }, key)
    rec.merge('receipts' => rs + [r])
  end

  def undo_policy(policy, camel, snake)
    return nil unless policy.is_a?(Hash)

    [camel, snake].each { |k| [k, k.to_sym].each { |kk| return policy[kk] if policy.key?(kk) && !policy[kk].nil? } }
    nil
  end

  # Clamp a requested window (ms) into [max(30 s, minMs), min(maxMs, 24 h)] (never below the floor); absent or non-finite ->
  # defaultMs (15 min). Policy keys: minMs / maxMs / defaultMs (or min_ms / max_ms / default_ms).
  def resolve_undo_window(requested, policy = {})
    min = [UNDO_MIN_WINDOW_MS, undo_policy(policy, 'minMs', 'min_ms') || UNDO_MIN_WINDOW_MS].max
    max = [min, [undo_policy(policy, 'maxMs', 'max_ms') || UNDO_MAX_WINDOW_MS, UNDO_MAX_WINDOW_MS].min].max
    finite = (requested.is_a?(Integer) || requested.is_a?(Float)) && requested.to_f.finite?
    want = finite ? requested : (undo_policy(policy, 'defaultMs', 'default_ms') || UNDO_DEFAULT_WINDOW_MS)
    [max, [min, want].max].min.floor
  end

  # The decision obligation an allow under a veto window carries: {kind: undo_window, params: {id, window_end}, due: window_end}.
  def undo_window_obligation(id, window_end)
    { 'kind' => 'undo_window', 'params' => { 'id' => id, 'window_end' => window_end }, 'due' => window_end }
  end
end
