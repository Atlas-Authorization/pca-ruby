# frozen_string_literal: true

# Session histories (Intent Layer v2 section 2.1; packages/pca/src/intent-history.ts): the host side of accumulators and
# monitors. The verifier receives the PRE-STATE of the action's group from its own store; these functions compute it from
# the session's event history (window, key, selection and counted statuses applied) and fold a monitor over it. They are
# pure: the store, its lock and the reservation are the host's. A function the reference reports as throwing (a corrupt
# history) raises AtlasPca::HistoryError.
module AtlasPca
  # The session history is corrupt (or the candidate unusable): the caller fails closed.
  class HistoryError < StandardError; end

  EVENT_STATUSES = %w[reserved committed released reverted].freeze
  COUNTED_STATUSES = %w[reserved committed].freeze

  module_function

  def history_counted?(status)
    status == 'reserved' || status == 'committed'
  end

  # The status of a history entry as the reference reads it: a null entry is a corrupt history (reading a member of null throws), any other
  # value that is not an object simply has none.
  def history_status(e)
    raise HistoryError, 'a history entry is null' if e.nil?

    e.is_a?(Hash) ? e['status'] : nil
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

    raise HistoryError, 'the window is missing' if win.nil?
    return false unless win.is_a?(Hash)

    ms = win['ms']
    case win['kind']
    when 'task' then true
    when 'sliding' then V2JS.num?(ms) && ti > t - ms # an absent bound compares false in the reference (NaN)
    when 'period'
      t0 = win['t0']
      return false unless V2JS.num?(ms) && V2JS.num?(t0)

      # the reference divides: with ms = 0 both quotients are infinities of one sign, or one is NaN
      history_js_floor((ti - t0).to_f / ms) == history_js_floor((t - t0).to_f / ms)
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
      counted = history_counted?(history_status(e))
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
    # first, as TS accPost (80ad8c7ff): a host-built declaration is not validated otherwise, and an unknown agg read as distinct
    raise HistoryError, 'accPost: unknown agg' unless IntentV2::ACC_AGGS.include?(a['agg'])

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

  # One monitor step on one event; statuses that do not count leave the state unchanged.
  def monitor_step(m, q, e)
    st = history_status(e)
    counts = (m['status'].nil? ? 'admitted' : m['status']) == 'committed' ? st == 'committed' : history_counted?(st)
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
      pending = q.start_with?('pending:') ? Actions::SvfJS.num(q['pending:'.length..]) : nil
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
    end # a monitor of an unknown kind has no next state on a counted event (undefined in the reference)
  end

  # The fold of the monitor over the history (admission order, current statuses).
  def monitor_state(m, history)
    q = monitor_initial_state(m)
    history.each { |e| q = monitor_step(m, q, e) }
    q
  end

  # The pre-state context a verifier receives: the pre-state of every site-local accumulator for the candidate (an accumulator whose grouping key
  # the candidate lacks is left out: the verifier fails that claim) and the state of every monitor. cand = {'params' =>, 't' =>}. Raises
  # HistoryError on a corrupt history.
  def acc_context_for(root, history, cand, schema = V2JS::UNDEF)
    state = {}
    root['accumulators'].each do |a|
      next unless a['holder']['kind'] == 'site_local'
      next if !a['key'].nil? && acc_key_of(a, cand['params']).nil?

      state[a['id']] = acc_pre_state(a, history, cand, schema)
    end
    monitors = {}
    root['monitors'].each { |m| monitors[m['id']] = monitor_state(m, history) }
    { 'state' => state, 'monitors' => monitors }
  end

  # Admit one action through a session store: under the session's lock read the history, hand the pre-state context to `verify` (a callable
  # returning a verdict with an 'allow' member) and, when it allows, append the event as `reserved`. `store` answers `durable` (true required unless
  # `require_durable` is false: a restart would reset every cap) and `with_session(session) { |tx| }` where tx answers `events`, `append(e)` and
  # `set_status(id, status)`. Returns the verdict.
  def admit_intent_action(store, session:, root:, event:, verify:, schema: V2JS::UNDEF, require_durable: nil)
    if require_durable != false && !(store.respond_to?(:durable) && store.durable == true)
      raise ArgumentError, 'admitIntentAction: the session store is not durable (a restart would reset every cap); use a durable IntentSessionStore'
    end

    store.with_session(session) do |tx|
      acc = acc_context_for(root, tx.events, event, schema)
      v = verify.call(acc)
      tx.append(event.merge('status' => 'reserved')) if V2JS.truthy?(v['allow'])
      v
    end
  end

  # Settle an event of a session (committed / released / reverted); false when the session has no such event.
  def settle_intent_event(store, session, id, status) = store.with_session(session) { |tx| tx.set_status(id, status) }
end
