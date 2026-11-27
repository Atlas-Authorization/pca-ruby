# frozen_string_literal: true

require_relative 'js_compat'
require_relative 'immune'

# The principal's agent console, data layer: a stream of activity events projected into a per-agent view with a threat read (the
# immune system of immune.rb), and the local kill switch. Pure and offline. The freeze set is a LOCAL list a client or gateway
# consults before dispatching; authoritative revocation is the ledger's revocation epoch. Events, views and freeze sets are Hashes
# with the reference's member names (an event: 'at', 'agent', 'verb', 'resource', 'outcome' (auto | step_up | deny | executed),
# optional 'r', 'taint', 'digest', 'goalCommit'; a freeze set: {'frozen' => [agent, ...]}).
module AtlasPca
  EMPTY_FREEZE = { 'frozen' => [].freeze }.freeze
  CONSOLE_OUTCOMES = %w[auto step_up deny executed].freeze

  module_function

  def console_finite?(v) = v.is_a?(Integer) || (v.is_a?(Float) && v.finite?)

  # The activity event of a PCActn and the verifier's outcome: the agent is the leaf holder of the capability chain ('unknown' when
  # the chain names none), the time is `at` or the PCActn's 'iat'. Raises on a PCActn without a chain or an action, or one that has
  # no canonical form.
  def event_from_pcactn(pcactn, outcome, at = nil)
    chain = pcactn['cap_chain']
    action = pcactn['action']
    raise TypeError, "Cannot read properties of undefined (reading 'length')" unless chain.is_a?(Array)
    raise TypeError, "Cannot read properties of undefined (reading 'verb')" unless action.is_a?(Hash)

    leaf = chain.last
    holder = leaf.is_a?(Hash) ? leaf['holder'] : nil
    when_at = at.nil? ? pcactn['iat'] : at
    risk = pcactn['risk_claim']
    prov = pcactn['provenance']
    ev = {}
    ev['at'] = when_at unless when_at.nil?
    ev['agent'] = holder.nil? ? 'unknown' : holder
    ev['verb'] = action['verb'] if action.key?('verb')
    ev['resource'] = action['resource'] if action.key?('resource')
    ev['outcome'] = outcome
    ev['r'] = risk['r'] if risk.is_a?(Hash) && risk.key?('r')
    ev['taint'] = prov['taint_level'] if prov.is_a?(Hash) && prov.key?('taint_level')
    ev['digest'] = pcactn_digest(pcactn)
    ev
  end

  # Project activity events into {'agents' => [summary], 'totals', 'window' => {'from', 'to'}, 'dropped'}. A summary is {'agent',
  # 'actions', 'autos', 'stepUps', 'denies', 'executed', 'totalRisk', 'firstSeen', 'lastSeen', 'threat'}, most threatening first (then
  # most recently seen). An event without a finite time or an agent id cannot be placed or attributed: it is counted in 'dropped'.
  def build_console(events)
    raise TypeError, 'buildConsole: events must be a list' unless events.is_a?(Array)

    kept = events.select do |e|
      e.is_a?(Hash) && console_finite?(e['at']) && e['agent'].is_a?(String) && !e['agent'].empty?
    end
    by_agent = kept.group_by { |e| e['agent'] }
    agents = by_agent.map do |agent, evs|
      ordered = evs.each_with_index.sort_by { |e, i| [e['at'], i] }.map(&:first)
      immune = Immune.initial_state
      counts = CONSOLE_OUTCOMES.to_h { |o| [o, 0] }
      total = 0
      ordered.each do |e|
        r = e['r'].nil? ? 0 : e['r']
        raise TypeError, 'buildConsole: r must be a number' unless r.is_a?(Numeric)

        total += r
        counts[e['outcome']] += 1 if CONSOLE_OUTCOMES.include?(e['outcome'])
        immune = Immune.observe(immune, { 'r' => r, 'at' => e['at'], 'stepUp' => e['outcome'] == 'step_up', 'denied' => e['outcome'] == 'deny' })
      end
      { 'agent' => agent, 'actions' => ordered.length, 'autos' => counts['auto'], 'stepUps' => counts['step_up'], 'denies' => counts['deny'],
        'executed' => counts['executed'], 'totalRisk' => total, 'firstSeen' => ordered.first['at'], 'lastSeen' => ordered.last['at'],
        'threat' => Immune.assess(immune) }
    end
    agents = agents.each_with_index.sort_by { |a, i| [-a['threat']['score'], -a['lastSeen'], i] }.map(&:first)
    totals = %w[actions autos stepUps denies executed].to_h { |k| [k, agents.sum { |a| a[k] }] }
    ats = kept.map { |e| e['at'] }
    { 'agents' => agents, 'totals' => totals, 'window' => { 'from' => ats.empty? ? 0 : ats.min, 'to' => ats.empty? ? 0 : ats.max },
      'dropped' => events.length - kept.length }
  end

  # The agents of a console view whose threat read is not calm.
  def anomalies(view) = view['agents'].reject { |a| a['threat']['level'] == 'calm' }

  # Strict equality of two JSON scalars (a boolean is never a number; NaN equals NaN as in Array#includes).
  def freeze_same?(a, b)
    if a.is_a?(Numeric) && b.is_a?(Numeric)
      (a.respond_to?(:nan?) && a.nan? && b.respond_to?(:nan?) && b.nan?) || a == b
    elsif a.is_a?(Numeric) || b.is_a?(Numeric) then false
    elsif [true, false].include?(a) || [true, false].include?(b) then a.equal?(b)
    else a.class == b.class && a == b
    end
  end

  def frozen_of(set)
    raise TypeError, 'Cannot read properties of the freeze set (frozen)' unless set.is_a?(Hash) && (set['frozen'].is_a?(Array) || set['frozen'].is_a?(String))

    set['frozen']
  end

  # Whether `agent` is frozen. Fail closed: an action with no identifiable agent, or a malformed set, counts as frozen.
  def frozen?(set, agent)
    return true unless agent.is_a?(String) && !agent.empty? && set.is_a?(Hash) && set['frozen'].is_a?(Array)

    set['frozen'].any? { |a| freeze_same?(a, agent) }
  end

  def freeze_sort_key(v)
    s = Js.string(v)
    s.valid_encoding? ? s.encode('UTF-16BE').unpack('n*') : s.b.bytes
  end

  # The set with `agent` frozen: the SAME set when it already is, else a new set whose list is sorted (never mutates). Raises
  # TypeError on an empty or non-string agent.
  def freeze_agent(set, agent)
    raise TypeError, 'freezeAgent: agent must be a non-empty string' unless agent.is_a?(String) && !agent.empty?

    frozen = frozen_of(set)
    return set if frozen.is_a?(String) ? frozen.include?(agent) : frozen.any? { |a| freeze_same?(a, agent) }

    list = (frozen.is_a?(String) ? frozen.chars : frozen) + [agent]
    { 'frozen' => list.each_with_index.sort_by { |a, i| [freeze_sort_key(a), i] }.map(&:first) }
  end

  # A new set without `agent` (never mutates).
  def unfreeze_agent(set, agent)
    frozen = frozen_of(set)
    raise TypeError, 'set.frozen.filter is not a function' unless frozen.is_a?(Array)

    { 'frozen' => frozen.reject { |a| freeze_same?(a, agent) } }
  end

  # Fail closed: an action with no identifiable agent, or a malformed set, is frozen.
  def frozen?(set, agent)
    return true unless agent.is_a?(String) && !agent.empty? && set.is_a?(Hash) && set['frozen'].is_a?(Array)

    set['frozen'].any? { |a| freeze_same?(a, agent) }
  end
end
