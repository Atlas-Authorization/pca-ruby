# frozen_string_literal: true

require_relative 'console'

# A multi-agent session: a root agent and the sub-agents it delegates to, grouped under the ONE signed goal they share, so a
# principal sees the whole team and the console can be scoped to it. A session is a Hash {'root' => agent, 'members' => [agent, ...],
# 'goalCommit' => String} (root first, then each sub-agent in delegation order); the agents are AtlasPca::AgentHandle. Pure.
module AtlasPca
  # Deepest delegation chain a session accepts.
  SESSION_MAX_DEPTH = 32

  module_function

  def session_goal_commit(agent)
    gc = read_envelope(agent.grant)&.fetch('goal_commit', nil)
    gc.nil? ? '' : gc
  end

  # A session of the root agent alone; its goal commitment is the root grant's ('' without a readable envelope).
  def start_session(root) = { 'root' => root, 'members' => [root], 'goalCommit' => session_goal_commit(root) }

  # Add a sub-agent: one attenuated delegation hop under the session's current leaf. Returns {'session' => the new session,
  # 'member' => the sub-agent}; the given session is not changed. Raises RangeError past SESSION_MAX_DEPTH hops.
  def add_member(session, holder: nil, added_caveats: [])
    members = session['members']
    raise RangeError, "addMember: a session is limited to #{SESSION_MAX_DEPTH} delegation hops" if members.length > SESSION_MAX_DEPTH

    member = members.last.sub_agent(holder: holder, added_caveats: added_caveats)
    { 'session' => session.merge('members' => members + [member]), 'member' => member }
  end

  # The holder ids (base64url public keys) of every agent in the session.
  def session_agents(session) = session['members'].map { |m| m.holder.public }

  # A console view of just this session's agents. Raises TypeError on a null event (it has no agent to read).
  def session_console(session, events)
    ids = session_agents(session)
    raise TypeError, 'sessionConsole: events must be a list' unless events.is_a?(Array)
    raise TypeError, "Cannot read properties of null (reading 'agent')" if events.any?(&:nil?)

    build_console(events.select { |e| e.is_a?(Hash) && e['agent'].is_a?(String) && ids.include?(e['agent']) })
  end

  # True iff every member shares the session's goal commitment. Members that all lack one do not share a goal: false.
  def shares_goal?(session)
    gc = session['goalCommit']
    gc != '' && session['members'].all? { |m| session_goal_commit(m) == gc }
  end

  # Depth of the delegation tree (0 = the root only).
  def session_depth(session) = session['members'].length - 1
end
