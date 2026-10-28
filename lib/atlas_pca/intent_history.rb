# frozen_string_literal: true

# Session histories (Intent Layer v2 section 2.1; packages/pca/src/intent-history.ts): the host side of accumulators and
# monitors. The verifier receives the PRE-STATE of the action's group from its own store; these functions compute it from
# the session's event history (window, key, selection and counted statuses applied) and fold a monitor over it. They are
# pure: the store, its lock and the reservation are the host's. A function the reference reports as throwing (a corrupt
# history) raises AtlasPca::HistoryError.
module AtlasPca
  # The session history is corrupt (or the candidate unusable): the caller fails closed.
  class HistoryError < StandardError; end

  module_function

  def history_counted?(status)
    status == 'reserved' || status == 'committed'
  end

  def history_js_floor(x)
    x.finite? ? x.floor : x
  end

  # Does the counted event stamped ti still count at t? task: always; sliding(ms): (t - ms, t]; period(ms, t0): the period
  # containing t; and every event stamped AFTER t (it has not left any window). A time that is not a safe integer is in no
  # window (fail closed).
  def in_window(win, ti, t)
    return false unless V2JS.int?(ti) && V2JS.int?(t)
    return true if ti > t

    case win['kind']
    when 'task' then true
    when 'sliding' then ti > t - win['ms']
    when 'period'
      a = history_js_floor((ti - win['t0']).to_f / win['ms'])
      b = history_js_floor((t - win['t0']).to_f / win['ms'])
      a == b
    else false
    end
  end

  # The canonical key of the grouping parameter, '•' when ungrouped, nil when the parameter is missing.
  def acc_key_of(a, params)
    return '•' if a['key'].nil?

    name = a['key'][('action.params.'.length)..]
    params.is_a?(Hash) && params.key?(name) ? distinct_key(params[name]) : nil
  end

  def history_empty_pre(agg)
    { 'sum' => { 'sum' => 0 }, 'count' => { 'count' => 0 }, 'max' => { 'max' => 0 } }.fetch(agg) { { 'values' => [] } }
  end

  # The pre-state of the accumulator for a candidate action; raises HistoryError on a corrupt history.
  # cand = {'params' =>, 't' =>}.
  def acc_pre_state(a, history, cand, schema = V2JS::UNDEF)
    key = acc_key_of(a, cand['params'])
    raise HistoryError, "the key parameter #{a['key']} is missing" if key.nil?
    raise HistoryError, 'the candidate time is not a safe integer' unless V2JS.int?(cand['t'])

    total = 0
    count = 0
    mx = 0
    vals = []
    history.each do |e|
      counted = history_counted?(e['status'])
      raise HistoryError, "event #{e['id']}: the time is not a safe integer" if counted && !V2JS.int?(e['t'])
      next if !counted || !in_window(a['win'], e['t'], cand['t']) || !acc_selects(a, e['verb'], schema) ||
              acc_key_of(a, e['params']) != key

      v = acc_value_of(a, e['verb'], e['params'], schema)
      raise HistoryError, "event #{e['id']}: #{v['reason']}" unless v['ok']

      total += v['val']
      count += 1
      mx = [mx, v['val']].max
      vals << v['key'] if v.key?('key') && !v['key'].nil?
    end
    case a['agg']
    when 'sum'
      raise HistoryError, 'sum exceeds 2^53-1' if total > MAX_SAFE

      { 'sum' => total }
    when 'count' then { 'count' => count }
    when 'max' then { 'max' => mx }
    else { 'values' => V2JS.sort_utf8(vals.uniq(&:b)) }
    end
  end

  # post(history, omega, t): the pre-state combined with omega when omega is selected, else the pre-state's value.
  # cand = {'verb' =>, 'params' =>, 't' =>}.
  def acc_post(a, history, cand, schema = V2JS::UNDEF)
    pre = !a['key'].nil? && acc_key_of(a, cand['params']).nil? ? history_empty_pre(a['agg']) : acc_pre_state(a, history, cand, schema)
    return pre_value(a, pre) unless acc_selects(a, cand['verb'], schema)

    v = acc_value_of(a, cand['verb'], cand['params'], schema)
    raise HistoryError, v['reason'] unless v['ok']

    post = combine_acc(a, pre, v)
    raise HistoryError, 'overflow' if post.nil?

    post
  end

  def monitor_initial_state(m)
    case m['kind']
    when 'requires_prior', 'precedes' then 'unmet'
    when 'never' then 'clean'
    when 'always' then 'ok'
    else 'idle'
    end
  end

  # JS Number(string) for the text after 'pending:' (NaN when it is not a number).
  def history_js_number(s)
    t = s.strip
    return 0.0 if t.empty?
    return t.to_i(16).to_f if t.match?(/\A0[xX][0-9a-fA-F]+\z/)
    return t[2..].to_i(2).to_f if t.match?(/\A0[bB][01]+\z/)
    return t[2..].to_i(8).to_f if t.match?(/\A0[oO][0-7]+\z/)
    return (t.start_with?('-') ? -Float::INFINITY : Float::INFINITY) if t.match?(/\A[+-]?Infinity\z/)
    return Float(t) if t.match?(/\A[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?\z/)

    Float::NAN
  rescue ArgumentError
    Float::NAN
  end

  # One monitor step on one event; statuses that do not count leave the state unchanged.
  def monitor_step(m, q, e)
    counts = (m['status'].nil? ? 'admitted' : m['status']) == 'committed' ? e['status'] == 'committed' : history_counted?(e['status'])
    return q unless counts

    ctx = { 'action' => { 'verb' => e['verb'], 'resource' => e['resource'], 'params' => e['params'] } }
    case m['kind']
    when 'requires_prior', 'precedes'
      q == 'met' || predicate_matches(m['p'], ctx) ? 'met' : 'unmet'
    when 'never'
      q == 'seen' || predicate_matches(m['p'], ctx) ? 'seen' : 'clean'
    when 'always'
      q == 'broken' || !predicate_matches(m['p'], ctx) ? 'broken' : 'ok'
    when 'responds_within'
      return 'missed' if q == 'missed'

      w = m['within']
      pending = q.start_with?('pending:') ? history_js_number(q['pending:'.length..]) : nil
      unless pending.nil?
        if predicate_matches(m['q'], ctx)
          pending = nil
        elsif pending - 1 <= 0
          return 'missed'
        else
          pending -= 1
        end
      end
      if predicate_matches(m['p'], ctx)
        pending = pending.nil? ? w.to_f : (pending.nan? || w.to_f.nan? ? Float::NAN : [pending, w.to_f].min)
      end
      pending.nil? ? 'idle' : "pending:#{Predicates.js_number_string(pending.to_f)}"
    else q
    end
  end

  # The fold of the monitor over the history (admission order, current statuses).
  def monitor_state(m, history)
    q = monitor_initial_state(m)
    history.each { |e| q = monitor_step(m, q, e) }
    q
  end
end
