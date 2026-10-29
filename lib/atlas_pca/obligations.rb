# frozen_string_literal: true

# Decision obligations (the PEP side): validate, merge, gate and outcome. A PEP that cannot perform every obligation on an
# allow turns the allow into a deny. Every function is total. Replays packages/pca/conformance/obligations-vectors.json.
# A missing or null list is the empty list. Hashes use String keys.
module AtlasPca
  # undo_window {id, window_end}: the action runs under a veto window (undo record `id`, open until `window_end`); a PEP that
  # does not run undo windows must not list it as supported (the gate then turns the allow into a deny).
  OBLIGATION_KINDS = %w[log notify redact watermark require_receipt undo_window].freeze
  MAX_OBLIGATIONS = 16
  OBLIGATION_ALLOWED = { 'log' => %w[sink], 'notify' => %w[to], 'redact' => %w[fields], 'watermark' => %w[id], 'require_receipt' => [],
                         'undo_window' => %w[id window_end] }.freeze
  OBLIGATION_FIELD_RE = /\A[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}\z/

  module_function

  def obligation_params_error(kind, p)
    p.each_key { |k| return "unknown parameter '#{k}' for '#{kind}'" unless OBLIGATION_ALLOWED[kind].include?(k) }
    return 'log.sink must be a non-empty string of at most 128 characters' if kind == 'log' && p.key?('sink') && !k3_str?(p['sink'], 128)
    return 'notify.to is required (a non-empty string of at most 256 characters)' if kind == 'notify' && !k3_str?(p['to'], 256)
    return 'watermark.id is required (a non-empty string of at most 128 characters)' if kind == 'watermark' && !k3_str?(p['id'], 128)
    if kind == 'undo_window' && !(k3_str?(p['id'], 128) && k3_int?(p['window_end']))
      return 'undo_window needs id (a non-empty string of at most 128 characters) and window_end (a non-negative safe integer)'
    end
    if kind == 'redact'
      f = p['fields']
      return 'redact.fields must be 1..32 dotted field paths' unless f.is_a?(Array) && !f.empty? && f.length <= 32 && f.all? { |x| x.is_a?(String) && x.match?(OBLIGATION_FIELD_RE) }
      return 'redact.fields has a duplicate' if f.uniq.length != f.length
    end
    nil
  end

  # nil = well formed.
  def obligation_error(o)
    return 'an obligation must be an object' unless o.is_a?(Hash)

    o.each_key { |k| return "unknown member '#{k}'" unless %w[kind params due].include?(k) }
    return "unknown obligation kind '#{o['kind']}'" unless o['kind'].is_a?(String) && OBLIGATION_KINDS.include?(o['kind'])
    return 'due must be a non-negative safe integer' if o.key?('due') && !k3_int?(o['due'])

    p = o.key?('params') ? o['params'] : {}
    return 'params must be an object' unless p.is_a?(Hash)

    obligation_params_error(o['kind'], p)
  end

  # nil = a well-formed, duplicate-free list of at most 16. nil (absent) is the empty list.
  def obligations_error(list)
    return nil if list.nil?
    return 'obligations must be an array' unless list.is_a?(Array)
    return "more than #{MAX_OBLIGATIONS} obligations" if list.length > MAX_OBLIGATIONS

    seen = {}
    list.each_with_index do |o, i|
      e = obligation_error(o)
      return "obligations[#{i}]: #{e}" if e

      key = obligation_key(o)
      return "obligations[#{i}] duplicates an earlier obligation" if seen[key]

      seen[key] = true
    end
    nil
  end

  def obligation_key(o)
    h = { 'kind' => o['kind'], 'params' => o['params'] || {} }
    h['due'] = o['due'] unless o['due'].nil?
    canonicalize(h)
  end

  # { 'ok' => true, 'obligations' => [...] } or { 'ok' => false, 'reason' => }
  def merge_obligations(*lists)
    by = {}
    lists.each do |l|
      e = obligations_error(l)
      return { 'ok' => false, 'reason' => e } if e

      (l || []).each { |o| by[obligation_key(o)] = o }
    end
    return { 'ok' => false, 'reason' => "more than #{MAX_OBLIGATIONS} obligations after merging" } if by.size > MAX_OBLIGATIONS

    { 'ok' => true, 'obligations' => by.keys.sort { |a, b| V2JS.compare_utf8(a, b) }.map { |k| by[k] } }
  rescue StandardError
    { 'ok' => false, 'reason' => 'evaluation error (fail closed)' }
  end

  def pep_obligation_gate(decision, answered, obligations, supported)
    deny = ->(unsupported = [], reason = nil) { { 'decision' => 'deny', 'perform' => [], 'unsupported' => unsupported }.merge(reason ? { 'reason' => reason } : {}) }
    eff = pep_decision(decision, answered)
    return { 'decision' => eff == 'escalate' ? 'escalate' : 'deny', 'perform' => [], 'unsupported' => [] } unless eff == 'allow'

    e = obligations_error(obligations)
    return deny.call([], "malformed obligations: #{e}") if e
    return deny.call([], 'the supported obligation kinds are malformed') unless supported.is_a?(Array) && supported.all?(String)

    list = obligations || []
    missing = list.map { |o| o['kind'] }.reject { |k| supported.include?(k) }.uniq.sort { |a, b| V2JS.compare_utf8(a, b) }
    return deny.call(missing, "the enforcement point does not support obligation(s) #{missing.join(', ')}") unless missing.empty?

    { 'decision' => 'allow', 'perform' => list, 'unsupported' => [] }
  rescue StandardError
    { 'decision' => 'deny', 'perform' => [], 'unsupported' => [], 'reason' => 'evaluation error (fail closed)' }
  end

  def obligation_outcome(obligations, fulfilled, now)
    list = obligations || []
    bad = !obligations_error(obligations).nil? || !fulfilled.is_a?(Array) || !fulfilled.all? { |i| k3_int?(i) } || !k3_int?(now)
    return { 'outcome' => 'escalate', 'overdue' => list.is_a?(Array) ? list.each_index.to_a : [], 'status' => 'obligation_unmet' } if bad

    overdue = list.each_index.select { |i| list[i]['due'] && list[i]['due'] <= now && !fulfilled.include?(i) }
    overdue.empty? ? { 'outcome' => 'ok', 'overdue' => [] } : { 'outcome' => 'escalate', 'overdue' => overdue, 'status' => 'obligation_unmet' }
  rescue StandardError
    { 'outcome' => 'escalate', 'overdue' => [], 'status' => 'obligation_unmet' }
  end
end
