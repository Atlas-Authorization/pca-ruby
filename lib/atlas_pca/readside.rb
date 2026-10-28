# frozen_string_literal: true

# K5 read-side authorization: ports packages/pca/src/readside.ts check for check. A signed read grant decides per data class
# whether a field is shown, masked (last4 | bucket | hash | token) or dropped; tighten-only; read receipts carry the labels of
# what the agent saw and `check_sink` decides where that data may go. Total and pure. String keys; integers only.
# Replays packages/pca/conformance/readside-vectors.json. Requires workflow.rb (shared strict helpers).
module AtlasPca
  READ_GRANT_DOMAIN = "atlas-pca/read-grant/v1\x00".b.freeze
  READ_RECEIPT_DOMAIN = "atlas-pca/read-receipt/v1\x00".b.freeze
  K5_RG_REF = 'atlas-pca/read-grant-ref/v1'
  K5_RR_REF = 'atlas-pca/read-receipt-ref/v1'
  K5_RH = 'atlas-pca/read-hash/v1'
  K5_RT = 'atlas-pca/read-token/v1'
  K5_RV = 'atlas-pca/read-value/v1'
  K5_RANK = { 'show' => 0, 'last4' => 1, 'bucket' => 2, 'token' => 3, 'hash' => 4, 'drop' => 5 }.freeze
  K5_MODE_RE = /\A(show|last4|hash|token|drop|bucket:[1-9][0-9]{0,8})\z/
  K5_SALT_MIN = 16
  K5_ENTRY_KEYS = %w[verb resource_prefix purposes modes default_mode].freeze
  K5_GRANT_KEYS = %w[v id principal issued_at expires_at reads caps sinks].freeze
  K5_RRECEIPT_KEYS = %w[v grant verb resource purpose seq prev fields labels issued_at signer sig].freeze

  module_function

  def k5_mode?(x) = k5_re?(x, K5_MODE_RE)
  def k5_rank(m) = K5_RANK[m.start_with?('bucket:') ? 'bucket' : m]
  def k5_sorted(xs) = xs.to_a.sort_by(&:b)
  def k5_bmp?(s) = s.each_char.all? { |c| c.ord < 0x10000 }

  def k5_valid_entry?(e)
    return false unless e.is_a?(Hash) && k5_keys?(e, K5_ENTRY_KEYS) && k3_str?(e['verb'], 128) && k3_str?(e['resource_prefix'], 512)

    k5_sorted_unique?(e['purposes'], K5_ID_RE, 16) && !e['purposes'].empty? && e['modes'].is_a?(Hash) && e['modes'].length <= 32 &&
      e['modes'].all? { |k, v| k5_re?(k, K5_LABEL_RE) && k5_mode?(v) } && k5_mode?(e['default_mode'])
  end

  # Shape of a read grant body (no signature).
  def valid_read_grant_body?(b)
    return false unless b.is_a?(Hash) && k5_keys?(b, K5_GRANT_KEYS) && k5_one?(b['v'])
    return false unless k5_id?(b['id']) && k5_b32?(b['principal']) && k5_uint?(b['issued_at']) && k5_uint?(b['expires_at'])

    rd = b['reads']
    return false unless rd.is_a?(Array) && !rd.empty? && rd.length <= 32 && rd.all? { |e| k5_valid_entry?(e) }
    return false unless b['caps'].is_a?(Hash) && b['caps'].length <= 32 && b['caps'].all? { |k, v| k5_re?(k, K5_LABEL_RE) && k5_uint?(v) }

    s = b['sinks']
    return false unless s.is_a?(Hash) && s.length <= 16

    s.all? do |k, v|
      k5_id?(k) && v.is_a?(Hash) && k5_keys?(v, %w[allow escalate]) && k5_sorted_unique?(v['allow'], K5_LABEL_RE, 16) &&
        k5_sorted_unique?(v['escalate'], K5_LABEL_RE, 16) && v['allow'].none? { |l| v['escalate'].include?(l) }
    end
  rescue StandardError
    false
  end

  def read_grant_digest(b) = hash_canonical({ 'd' => K5_RG_REF, 'g' => b })
  def read_receipt_ref(r) = hash_canonical({ 'd' => K5_RR_REF, 'r' => r })

  def k5_read_receipt_body(r) = %w[v grant verb resource purpose seq prev fields labels issued_at signer].to_h { |k| [k, r[k]] }

  def k5_read_out(decision, code, counts = {})
    { 'decision' => decision, 'code' => code, 'view' => {}, 'fields' => {}, 'labels' => [], 'counts' => counts }
  end

  # { 'body' => ... } or { 'code' => ... }. A principal that is not a key or a `now` that is not an unsigned safe integer is bad_request.
  def k5_grade_grant(sg, principal, now)
    return { 'code' => 'bad_request' } unless k5_b32?(principal) && k5_uint?(now)
    return { 'code' => 'bad_grant' } unless sg.is_a?(Hash) && k5_keys?(sg, %w[body sig]) && valid_read_grant_body?(sg['body'])

    b = sg['body']
    return { 'code' => 'bad_signature' } if b['principal'] != principal || !k5_verify_body(READ_GRANT_DOMAIN, b, principal, sg['sig'])
    return { 'code' => 'not_yet' } if now < b['issued_at']
    return { 'code' => 'expired' } if now >= b['expires_at']

    { 'body' => b }
  end

  def k5_valid_redact_input?(inp, sc)
    return false unless k5_b32?(inp['principal']) && k5_uint?(inp['now']) && k3_str?(inp['verb'], 128) && k3_str?(inp['resource'], 512)
    return false unless k5_id?(inp['purpose']) && inp['salt'].is_a?(String) && utf16_len(inp['salt']) >= K5_SALT_MIN
    return false unless sc.is_a?(Hash) && sc['fields'].is_a?(Hash) && sc['fields'].all? { |k, v| k5_name?(k) && k5_re?(v, K5_LABEL_RE) }
    return false unless sc['required'].is_a?(Array) && sc['required'].all? { |p| p.is_a?(String) && sc['fields'].key?(p) }
    return false unless k5_scalar_map?(inp['record']) && inp['tighten'].is_a?(Hash) && inp['tighten'].all? { |k, v| k5_re?(k, K5_LABEL_RE) && k5_mode?(v) }

    inp['counts'].is_a?(Hash) && inp['counts'].all? { |k, v| k5_re?(k, K5_LABEL_RE) && k5_uint?(v) }
  end

  # Mask one scalar by `mode`; nil when it cannot be shown (dropped).
  def k5_mask(mode, cls, v, salt)
    if mode == 'last4'
      return nil unless v.is_a?(String) && k5_bmp?(v) && v.each_char.count > 4

      "****#{v.each_char.to_a.last(4).join}"
    elsif mode.start_with?('bucket:')
      n = mode[7..].to_i
      v.is_a?(Integer) && v >= 0 ? v - (v % n) : nil
    elsif mode == 'hash'
      hash_canonical({ 'd' => K5_RH, 'salt' => salt, 'c' => cls, 'v' => v })
    elsif mode == 'token'
      "tok_#{hash_canonical({ 'd' => K5_RT, 'salt' => salt, 'c' => cls, 'v' => v })[0, 22]}"
    end
  end

  # Apply a read grant to one response. `inp` (String keys): grant, principal, now, verb, resource, purpose, schema
  # {fields, required}, record, tighten, salt, counts. Never raises.
  def redact_read(inp)
    g = k5_grade_grant(inp['grant'], inp['principal'], inp['now'])
    return k5_read_out('deny', g['code']) if g.key?('code')

    sc = inp['schema']
    return k5_read_out('deny', 'bad_request') unless k5_valid_redact_input?(inp, sc)

    entry = g['body']['reads'].find { |e| e['verb'] == inp['verb'] && inp['resource'].start_with?(e['resource_prefix']) && e['purposes'].include?(inp['purpose']) }
    return k5_read_out('deny', 'no_read_scope', inp['counts']) if entry.nil?

    fields = {}
    view = {}
    used = {}
    salt = inp['salt']
    k5_sorted(inp['record'].keys).each do |path|
      v = inp['record'][path]
      cls = sc['fields'][path]
      vd = hash_canonical({ 'd' => K5_RV, 'salt' => salt, 'p' => path, 'v' => v })
      if cls.nil?
        fields[path] = { 'class' => 'unclassified', 'action' => 'dropped', 'kind' => nil, 'vd' => vd }
        next
      end
      mode = entry['modes'][cls] || entry['default_mode']
      t = inp['tighten'][cls]
      mode = t if !t.nil? && k5_rank(t) > k5_rank(mode)
      if mode == 'show'
        shown = v
        action = 'shown'
        kind = nil
      else
        shown = k5_mask(mode, cls, v, salt)
        action = 'masked'
        kind = mode.start_with?('bucket:') ? 'bucket' : mode
      end
      if shown.nil?
        fields[path] = { 'class' => cls, 'action' => 'dropped', 'kind' => nil, 'vd' => vd }
        next
      end
      fields[path] = { 'class' => cls, 'action' => action, 'kind' => kind, 'vd' => vd }
      view[path] = shown
      used[cls] = (used[cls] || 0) + 1
    end
    counts = inp['counts'].dup
    used.each do |c, n|
      counts[c] = (counts[c] || 0) + n
      cap = g['body']['caps'][c]
      return k5_read_out('deny', 'read_cap', inp['counts']) if !cap.nil? && counts[c] > cap
    end
    return k5_read_out('escalate', 'required_dropped', inp['counts']) if sc['required'].any? { |p| !view.key?(p) }

    labels = k5_sorted(fields.values.reject { |f| f['action'] == 'dropped' }.map { |f| f['class'] }.uniq)
    { 'decision' => 'allow', 'code' => nil, 'view' => view, 'fields' => fields, 'labels' => labels, 'counts' => counts }
  rescue StandardError
    k5_read_out('deny', 'bad_request')
  end

  def k5_valid_read_receipt?(r)
    return false unless r.is_a?(Hash) && k5_keys?(r, K5_RRECEIPT_KEYS) && k5_one?(r['v'])
    return false unless k5_b32?(r['grant']) && k3_str?(r['verb'], 128) && k3_str?(r['resource'], 512) && k5_id?(r['purpose']) && k5_uint?(r['seq'])
    return false unless k5_null_or(r['prev']) { |x| k5_b32?(x) } && r['seq'].zero? == r['prev'].nil?
    return false unless k5_uint?(r['issued_at']) && k5_b32?(r['signer']) && r['sig'].is_a?(String) && k5_sorted_unique?(r['labels'], K5_LABEL_RE, 32)
    return false unless r['fields'].is_a?(Hash) && r['fields'].length <= 64

    r['fields'].all? do |k, f|
      k5_name?(k) && f.is_a?(Hash) && k5_keys?(f, %w[class action kind vd]) && f['class'].is_a?(String) &&
        (f['class'] == 'unclassified' || k5_re?(f['class'], K5_LABEL_RE)) && %w[shown masked dropped].include?(f['action']) &&
        (f['kind'].nil? || f['kind'].is_a?(String)) && k5_b32?(f['vd'])
    end
  end

  # The labels carried by a verified, unbroken chain of read receipts: { 'labels' => [...] } or { 'code' =>, 'at' => }.
  def read_chain_labels(receipts, rs_signer, grant_digest, now)
    return { 'code' => 'bad_request', 'at' => 0 } unless k5_uint?(now)
    return { 'code' => 'bad_receipt', 'at' => 0 } unless receipts.is_a?(Array)

    all = {}
    prev = nil
    receipts.each_with_index do |r, i|
      bad = { 'code' => 'bad_receipt', 'at' => i }
      return bad unless k5_valid_read_receipt?(r) && r['signer'] == rs_signer && r['grant'] == grant_digest && r['seq'] == i
      return bad if r['issued_at'] > now
      return bad if (prev.nil? ? !r['prev'].nil? : r['prev'] != read_receipt_ref(prev)) || !k5_verify_body(READ_RECEIPT_DOMAIN, k5_read_receipt_body(r), rs_signer, r['sig'])

      # the labels must be exactly the classes of the non-dropped fields: an understated list would launder data
      want = k5_sorted(r['fields'].values.reject { |f| f['action'] == 'dropped' }.map { |f| f['class'] }.uniq)
      return bad if want != r['labels']

      r['labels'].each { |l| all[l] = true }
      prev = r
    end
    { 'labels' => k5_sorted(all.keys) }
  rescue StandardError
    { 'code' => 'bad_receipt', 'at' => 0 }
  end

  # May data read under these receipts reach `sink`? `inp` (String keys): grant, principal, rs_signer, now, sink, receipts.
  def check_sink(inp)
    no = ->(code) { { 'decision' => 'deny', 'code' => code, 'labels' => [] } }
    g = k5_grade_grant(inp['grant'], inp['principal'], inp['now'])
    return no.call(g['code']) if g.key?('code')
    return no.call('bad_request') unless k5_b32?(inp['rs_signer']) && inp['sink'].is_a?(String)

    rule = g['body']['sinks'][inp['sink']]
    return no.call('unknown_sink') if rule.nil?

    c = read_chain_labels(inp['receipts'], inp['rs_signer'], read_grant_digest(g['body']), inp['now'])
    return no.call(c['code']) if c.key?('code')

    labels = c['labels']
    return { 'decision' => 'deny', 'code' => 'label_flow', 'labels' => labels } if labels.any? { |l| !rule['allow'].include?(l) && !rule['escalate'].include?(l) }
    return { 'decision' => 'escalate', 'code' => 'label_escalate', 'labels' => labels } if labels.any? { |l| rule['escalate'].include?(l) }

    { 'decision' => 'allow', 'code' => nil, 'labels' => labels }
  rescue StandardError
    { 'decision' => 'deny', 'code' => 'bad_request', 'labels' => [] }
  end
end
