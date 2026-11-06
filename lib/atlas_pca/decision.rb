# frozen_string_literal: true

# Ternary decision, tighten-only model rule (rule 21) and units check (rule 20). Port of packages/pca/src/decision.ts
# (the TypeScript is authoritative; security contract C-50..C-55).
#
# A decision is `deny < escalate < allow`; `meet` (the minimum) is the only combinator, so `escalate` never becomes
# `allow`. Every function is total and never raises; anything malformed fails closed (deny / ok false). Inputs are JSON
# values with String keys, as the JSON readers yield them.
module AtlasPca
  DECISION_RANK = { 'deny' => 0, 'escalate' => 1, 'allow' => 2 }.freeze
  # A failing check whose every reason starts with one of these is "escalate-class" (an unanswered question).
  ESCALATE_REASON_PREFIXES = ['intent_required:', 'escalate:'].freeze
  MODEL_ENV_ROOTS = %w[class prov judge detect].freeze
  MAX_TIGHTEN_RULES = 64
  TIGHTEN_NAME_RE = /\A[a-z][a-z0-9_]{0,63}\z/
  PARAM_PATH_RE = /\Aaction\.params\.[A-Za-z0-9_-]{1,64}\z/

  module_function

  # JS default sort order: UTF-16 code units.
  def utf16_key(s) = s.dup.force_encoding(Encoding::UTF_8).scrub("\uFFFD").encode('UTF-16BE').b

  # JS String(x).slice(0, n): the first n UTF-16 code units (a cut surrogate pair leaves a lone surrogate, as in JS).
  def utf16_slice(str, n)
    units = str.to_s.dup.force_encoding(Encoding::UTF_8).scrub("\uFFFD").encode('UTF-16LE').unpack('v*')
    return str.to_s if units.length <= n

    cut = units[0, n]
    cp = []
    i = 0
    while i < cut.length
      u = cut[i]
      if u >= 0xD800 && u <= 0xDBFF && i + 1 < cut.length && cut[i + 1] >= 0xDC00 && cut[i + 1] <= 0xDFFF
        cp << (0x10000 + ((u - 0xD800) << 10) + (cut[i + 1] - 0xDC00))
        i += 2
      else
        cp << u
        i += 1
      end
    end
    # WTF-8: a lone surrogate keeps its three-byte form (an invalid-encoding String, as the loose JSON reader yields)
    cp.map do |c|
      if c >= 0xD800 && c <= 0xDFFF then [0xE0 | (c >> 12), 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F)].pack('C*')
      else [c].pack('U').b
      end
    end.join.force_encoding(Encoding::UTF_8)
  end

  # Object.keys order of a parsed object: canonical array-index keys first (ascending), then the rest in text order.
  def js_keys(o)
    idx, rest = o.keys.partition { |k| k.match?(/\A(0|[1-9][0-9]{0,9})\z/) && k.to_i < 4_294_967_295 }
    idx.sort_by(&:to_i) + rest
  end

  def utf16_len(s) = s.dup.force_encoding(Encoding::UTF_8).scrub("\uFFFD").encode('UTF-16LE').bytesize / 2

  def decision_safe_int?(v)
    (v.is_a?(Integer) || (v.is_a?(Float) && v.finite? && v == v.floor)) && v.abs <= 9_007_199_254_740_991
  end

  # The minimum of two decisions; anything that is not a decision is a deny.
  def meet(a, b)
    x = a.is_a?(String) ? DECISION_RANK[a] : nil
    y = b.is_a?(String) ? DECISION_RANK[b] : nil
    return 'deny' if x.nil? || y.nil?

    x <= y ? a : b
  end

  # The reasons a verdict lists and its decision: the core reasons first, then every failing v2 check as "name: reason" (a check
  # without a reason adds none; an identical text is listed once); allow only when no check failed, else decision_of over the
  # whole set of checks. `v2` = [{'name', 'ok', 'reason'?}], `checks` = name => pass | fail | ...
  def fold_escalation(core_reasons, v2, checks)
    reasons = core_reasons.dup
    v2.each do |c|
      next if c['ok'] || !c.key?('reason') || c['reason'].nil?

      why = "#{c['name']}: #{c['reason']}"
      reasons << why unless reasons.include?(why)
    end
    decision = checks.value?('fail') ? decision_of({ 'allow' => false, 'checks' => checks, 'reasons' => reasons }) : 'allow'
    { 'reasons' => reasons, 'decision' => decision }
  end

  def meet_all(ds)
    ds.reduce('allow') { |acc, d| meet(acc, d) }
  end

  # A model signal's ceiling: ok -> allow, escalate -> escalate, anything else -> deny.
  def signal_ceiling(sig)
    return 'allow' if sig == 'ok'

    sig == 'escalate' ? 'escalate' : 'deny'
  end

  def tighten(base, signal)
    meet(base, signal_ceiling(signal))
  end

  # The decision of a verdict {allow, checks => {name => pass|fail|...}, reasons => [String]} over the FULL set of check
  # results: allow when allowed; escalate only when at least one check fails and EVERY failing check's reasons are all
  # escalate-class (and it has some); otherwise deny.
  def decision_of(v)
    return 'allow' if v['allow'] == true

    failing = 0
    reasons = v['reasons'].is_a?(Array) ? v['reasons'] : []
    v['checks'].each do |name, status|
      next unless status == 'fail'

      failing += 1
      head = "#{name}: "
      own = reasons.select { |r| r.is_a?(String) && r.start_with?(head) }
      return 'deny' if own.empty?
      return 'deny' unless own.all? { |r| ESCALATE_REASON_PREFIXES.any? { |p| r[head.length..].start_with?(p) } }
    end
    failing.positive? ? 'escalate' : 'deny'
  rescue StandardError
    'deny'
  end

  # What a PEP does with a decision: an escalate admitted only by a verified allow answer; never upgrades a deny.
  def pep_decision(decision, answered)
    return 'allow' if decision == 'escalate' && answered == true

    decision # anything but an answered escalate is returned unchanged, as the reference does
  end

  def model_derived_path?(path, single_source = [])
    return false unless path.is_a?(String)

    seg = path.split('.', -1)
    return false if seg[0] != 'env' || seg.length < 2
    return true if MODEL_ENV_ROOTS.include?(seg[1])
    return false if seg[1] != 'world'

    seg.length == 2 ? !single_source.empty? : single_source.include?(seg[2])
  end

  def collect_condition_paths(c, out, depth)
    return if depth > 64 || !c.is_a?(Hash)

    %w[all_of any_of].each do |k|
      c[k].each { |x| collect_condition_paths(x, out, depth + 1) } if c[k].is_a?(Array)
    end
    collect_condition_paths(c['not'], out, depth + 1) unless c['not'].nil?
    %w[field ref collection].each { |k| out << c[k] if c[k].is_a?(String) }
  end

  # The model-derived paths read by the `where` conditions of grant predicate lists, sorted by UTF-8 bytes.
  def model_paths_read(predicate_lists, single_source = [])
    found = []
    (predicate_lists.is_a?(Array) ? predicate_lists : []).each do |lst|
      next unless lst.is_a?(Array)

      lst.each do |p|
        w = p.is_a?(Hash) ? p['where'] : nil
        w.each { |c| collect_condition_paths(c, found, 0) } if w.is_a?(Array)
      end
    end
    found.uniq.select { |p| model_derived_path?(p, single_source) }.sort_by(&:b) # compareUtf8
  end

  def closed_member_error(o, required, optional, where)
    js_keys(o).each { |k| return "unknown member '#{where}.#{k}'" unless required.include?(k) || optional.include?(k) }
    required.each { |k| return "missing member '#{where}.#{k}'" unless o.key?(k) }
    nil
  end

  # nil when well-formed. `t` is the member's value, ABSENT passing nil-or-missing is the caller's job: a JSON null is
  # malformed (TypeScript: only `undefined` is absent).
  def tighten_list_error(t)
    return 'tighten must be an array' unless t.is_a?(Array)
    return "tighten has more than #{MAX_TIGHTEN_RULES} rules" if t.length > MAX_TIGHTEN_RULES

    ids = {}
    t.each_with_index do |r, i|
      return "tighten[#{i}] must be an object" unless r.is_a?(Hash)

      e = closed_member_error(r, %w[id when signal], %w[reason], "tighten[#{i}]")
      return e if e
      return "tighten[#{i}].id must match ^[a-z][a-z0-9_]{0,63}$" unless r['id'].is_a?(String) && r['id'].match?(TIGHTEN_NAME_RE)
      return "tighten[#{i}].id '#{r['id']}' is a duplicate" if ids.key?(r['id'])

      ids[r['id']] = true
      return "tighten[#{i}].when must be a condition object" unless r['when'].is_a?(Hash)
      return "tighten[#{i}].signal must be 'escalate' or 'deny'" unless %w[escalate deny].include?(r['signal'])
      if r.key?('reason') && !(r['reason'].is_a?(String) && utf16_len(r['reason']) <= 256)
        return "tighten[#{i}].reason must be a string of at most 256 characters"
      end
    end
    nil
  end

  # Rule 21. Typing first: a grant `where` reading a model-derived path is a deny unless polarity is 'legacy'; then the
  # tighten rules in order (true -> its signal, unknown -> escalate); the outcome is the meet. Returns
  # {'outcome' => ok|escalate|deny, 'legacy' =>, 'offending' =>, 'reason' => (when not ok)}.
  def decide_tighten(inp)
    res = lambda do |outcome, legacy, offending, reason = nil|
      out = { 'outcome' => outcome, 'legacy' => legacy, 'offending' => offending }
      out['reason'] = reason unless reason.nil?
      out
    end
    ss = inp['single_source']
    single = ss.is_a?(Array) ? ss.grep(String) : []
    if inp.key?('polarity') && inp['polarity'] != 'legacy'
      return res.call('deny', false, [], "model_polarity must be 'legacy' when present")
    end

    tl = inp['tighten']
    if inp.key?('tighten')
      le = tighten_list_error(tl)
      return res.call('deny', false, [], "malformed tighten list: #{le}") if le
    end
    offending = model_paths_read(inp['predicates'], single)
    legacy = inp['polarity'] == 'legacy' && !offending.empty?
    if !offending.empty? && !legacy
      return res.call('deny', false, offending,
                      "a grant's where reads model-derived path(s) #{offending.join(', ')}: a model may only tighten (move them into tighten[]) (rule 21)")
    end

    out = 'ok'
    reason = nil
    ctx = inp['context'].is_a?(Hash) ? inp['context'] : {}
    (tl || []).each do |r|
      t = evaluate_condition_tri(r['when'], ctx)
      sig = if t == 'true' then r['signal']
            elsif t == 'unknown' then 'escalate'
            end
      next if sig.nil?

      next unless DECISION_RANK[signal_ceiling(sig)] < DECISION_RANK[signal_ceiling(out)]

      out = sig
      reason = if t == 'true'
                 "#{sig == 'deny' ? 'denied by' : 'escalate: asked by'} tighten rule '#{r['id']}'#{r.key?('reason') ? " (#{r['reason']})" : ''}"
               else
                 "escalate: rule '#{r['id']}' could not be decided (a value it reads is missing or ill-typed)"
               end
    end
    res.call(out, legacy, offending, reason)
  rescue StandardError, SystemStackError => e
    res.call('deny', false, [], "evaluation error (fail closed): #{e.class}")
  end

  def unit_tags_error(u)
    return 'units must be an object' unless u.is_a?(Hash)
    return 'units has more than 64 entries' if u.length > 64

    js_keys(u).each do |k|
      t = u[k]
      return "units key '#{k}' must be an action.params.<name> path" unless k.match?(PARAM_PATH_RE)
      return "units['#{k}'] must be an object" unless t.is_a?(Hash)

      e = closed_member_error(t, %w[kind], %w[currency exponent], "units['#{k}']")
      return e if e
      return "units['#{k}'].kind must be a string of 1..64 characters" unless t['kind'].is_a?(String) && (1..64).cover?(utf16_len(t['kind']))
      if t.key?('currency') && !(t['currency'].is_a?(String) && (1..16).cover?(utf16_len(t['currency'])))
        return "units['#{k}'].currency must be a string of 1..16 characters"
      end
      if t.key?('exponent') && !(decision_safe_int?(t['exponent']) && t['exponent'].between?(0, 18))
        return "units['#{k}'].exponent must be an integer in [0, 18]"
      end
    end
    nil
  end

  def unit_tag_text(t)
    return 'no unit' if t.nil?

    "#{t['kind'].nil? ? '?' : Predicates.js_string(t['kind'])}#{t.key?('currency') ? "/#{Predicates.js_string(t['currency'])}" : ''}" \
      "#{t.key?('exponent') ? "/e#{Predicates.js_string(t['exponent'])}" : ''}"
  end

  def same_unit_tag?(a, b)
    %w[kind currency exponent].all? { |k| a[k] == b[k] && a.key?(k) == b.key?(k) }
  end

  def verb_in_scope?(p, verb)
    v = p.is_a?(Hash) ? p['verb'] : nil
    v == '*' || v == verb || (v.is_a?(Array) && v.include?(verb))
  end

  # Rule 20. {verb, units (the policy's tags), schema_units (unit id => tag), verb_params (path => {unit}),
  # predicates}. Returns {'ok' => true} or {'ok' => false, 'reason' => ...}.
  def decide_units(inp)
    fail_with = ->(m) { { 'ok' => false, 'reason' => m } }
    te = unit_tags_error(inp['units'])
    return fail_with.call(te) if te

    tags = inp['units']
    verb = inp['verb']
    return fail_with.call('the verb is missing') unless verb.is_a?(String) && !verb.empty?

    s_units = inp.key?('schema_units') ? inp['schema_units'] : {}
    return fail_with.call('the schema units table must be an object') unless s_units.is_a?(Hash)

    params = inp['verb_params']
    return fail_with.call("the schema does not declare verb '#{verb}'") unless params.is_a?(Hash)

    declared = lambda do |path|
      d = params[path]
      return [false, nil] unless d.is_a?(Hash)

      tag = d['unit'].is_a?(String) ? s_units[d['unit']] : nil
      [true, tag.is_a?(Hash) ? tag : nil]
    end

    tags.keys.sort_by { |k| utf16_key(k) }.each do |path|
      has, tag = declared.call(path)
      next unless has
      if tag.nil? || !same_unit_tag?(tag, tags[path])
        return fail_with.call("'#{path}' is declared as #{unit_tag_text(tag)} by the action schema but the policy term is tagged " \
                              "#{unit_tag_text(tags[path])} (unit confusion)")
      end
    end
    read = []
    (inp['predicates'].is_a?(Array) ? inp['predicates'] : []).each do |lst|
      next unless lst.is_a?(Array)

      lst.each do |p|
        next unless verb_in_scope?(p, verb)

        w = p['where'] if p.is_a?(Hash)
        w.each { |c| collect_condition_paths(c, read, 0) } if w.is_a?(Array)
      end
    end
    read.uniq.sort_by { |k| utf16_key(k) }.each do |path|
      next unless path.match?(PARAM_PATH_RE)

      has, tag = declared.call(path)
      return fail_with.call("a policy term reads '#{path}' (#{unit_tag_text(tag)}) without a unit tag") if has && !tag.nil? && !tags.key?(path)
    end
    { 'ok' => true }
  rescue StandardError, SystemStackError => e
    { 'ok' => false, 'reason' => "evaluation error (fail closed): #{e.class}" }
  end
end
