# frozen_string_literal: true

# Agent-side tool-call bridge for AI frameworks (the TypeScript reference's bridgeToolCall / guard / PcaDenied): wrap a tool so each
# call silently builds a signed PCActn and hands it to the tool with ready-to-send headers. Nothing here authorizes: the resource
# server's verifier decides, and a bypassed wrapper only produces an action that fails server-side.
#
# Provenance: attach a ProvenanceRecorder with Adapters.attach_provenance(agent, recorder); every action then carries its bundle
# (header PCA-Provenance, or the body member pca_provenance when it is too large for a header) and record_principal /
# record_tool_result / record_messages / record_input feed the recorder (the principal's turns are TRUSTED, tool output
# UNTRUSTED). Without a recorder they do nothing.
require 'json'
require_relative '../atlas_pca'
require_relative 'js_compat'

module AtlasPca
  module Adapters
    module_function

    # Raised by guard when the local dry run rejects a call before dispatch.
    class PcaDenied < StandardError
      attr_reader :reason, :verb, :resource

      def initialize(reason, verb, resource)
        super("PCA denied #{verb} on #{resource}: #{reason}")
        @reason = reason
        @verb = verb
        @resource = resource
      end
    end

    # What a guarded dispatch receives: the encoded PCActn JSON, the PCActn and the headers that carry it; provenance is the
    # bundle of this action (send it as body member pca_provenance when it is not in headers).
    PcaCall = Struct.new(:encoded, :pcactn, :headers, :provenance)

    RECORDERS = ObjectSpace::WeakMap.new
    SEEN = ObjectSpace::WeakMap.new

    def attach_provenance(agent, recorder)
      RECORDERS[agent] = recorder
      agent
    end

    def recorder_of(agent)
      return agent.provenance if agent.respond_to?(:provenance) && !agent.provenance.nil?

      RECORDERS.key?(agent) ? RECORDERS[agent] : nil
    end

    def call_of(agent, action, op)
      rec = recorder_of(agent)
      bundle = rec&.for_action(op)
      headers = action.headers
      headers = headers.merge(provenance_headers(bundle)) unless bundle.nil?
      PcaCall.new(AtlasPca.decode_pca_header(action.headers['PCA-Action']), action.pcactn, headers, bundle)
    end

    # nil when the action verifies against the agent's own root grant, else the refusal reason. Never raises.
    def dry_run(agent, action, params = nil)
      v = AtlasPca.verify_pcactn(action.pcactn, agent.chain[0], now: agent.instance_variable_get(:@clock).call, audience: agent.aud,
                                                                authorized_plan_roots: [action.pcactn['plan']['root']])
      return (v.reason || 'denied') unless v.allow

      envelope_refusal(agent, action, params)
    rescue StandardError => e
      "dry run failed (#{e.class.name.split('::').last})"
    end

    # The chain check proves signatures and linkage only; scope is the grants envelopes: every hop must admit the action by its
    # predicates and caveats (a hop only narrows). nil when all admit, else the first refusal reason.
    def envelope_refusal(agent, action, params)
      a = action.pcactn['action']
      act = { 'verb' => a['verb'], 'resource' => a['resource'], 'params' => params.nil? ? {} : params }
      act['reversibility_class'] = a['reversibility_class'] if a['reversibility_class']
      now = agent.instance_variable_get(:@clock).call
      agent.chain.each_with_index do |g, i|
        (g['caveats'] || []).each do |cv|
          next unless cv.is_a?(Hash) && cv['type'] == 'envelope'

          pred = AtlasPca.evaluate_predicates(cv['predicates'], { 'action' => act })
          return pred['reason'] || 'no predicate matched' unless pred['allowed']

          ok, failed = AtlasPca.evaluate_caveats(cv['caveats'] || [], { 'now' => now, 'reversibility_class' => act['reversibility_class'],
                                                                       'delegation_depth' => i, 'recent_action_times' => [] })
          return 'caveat(s) failed: ' + failed.join(', ') unless ok
        end
      end
      nil
    end

    # PCA-Provenance: <base64url canonical JSON> for a bundle that fits PROV_HEADER_MAX; {} otherwise (send it in the body).
    def provenance_headers(bundle)
      return {} if bundle.nil?

      v = AtlasPca.b64e(AtlasPca.strict_bytes(bundle))
      v.length <= AtlasPca::PROV_HEADER_MAX ? { AtlasPca::PROV_HEADER => v } : {}
    end

    # `{name:, arguments:}` -> a PCActn via mapping.call(call) -> {verb:, resource:}; nil when the mapping declines the call
    # (an unmapped tool). No dry run here: an out-of-policy call still yields a signed PCActn and is refused server-side.
    def bridge_tool_call(agent, call, mapping)
      m = mapping.call(call)
      return nil if m.nil? || m == false

      verb = get(m, 'verb')
      resource = get(m, 'resource')
      args = get(call, 'arguments')
      call_of(agent, agent.act(verb, resource, args), { 'verb' => verb, 'resource' => resource, 'params' => args })
    end

    # Wrap run.call(params, pca): build a PCActn for each call, raise PcaDenied on a failing dry run (unless fail_fast is false),
    # then run with the proof and record the tool result. Returns a lambda taking params.
    def guard(agent, verb, resource, run, fail_fast: true)
      lambda do |params|
        res = resource.respond_to?(:call) ? resource.call(params) : resource
        action = agent.act(verb, res, params)
        if fail_fast
          why = dry_run(agent, action, params)
          raise PcaDenied.new(why, verb, res) unless why.nil?
        end
        out = run.call(params, call_of(agent, action, { 'verb' => verb, 'resource' => res, 'params' => params }))
        record_tool_result(agent, verb, out)
        out
      end
    end

    # ----- duck-typed access (a Hash with String or Symbol keys, or an SDK object) -----

    # A JSON-shaped copy of an SDK value: String keys, Symbols (an SDK enum) as Strings, models through #to_h, so a real SDK object signs the
    # same canonical params as the equivalent JSON Hash.
    def plain(v)
      case v
      when Hash then v.to_h { |k, x| [k.to_s, plain(x)] }
      when Array then v.map { |x| plain(x) }
      when Symbol then v.to_s
      when String, Numeric, true, false, nil then v
      else v.respond_to?(:to_h) ? plain(v.to_h) : v
      end
    end

    def get(o, k)
      if o.is_a?(Hash)
        o.key?(k) ? o[k] : o[k.to_sym]
      elsif !o.nil? && o.respond_to?(k)
        o.public_send(k)
      end
    end

    # ----- provenance recording -----

    def record_principal(agent, text)
      recorder_of(agent)&.principal(text)
      nil
    end

    def record_tool_result(agent, tool, output)
      recorder_of(agent)&.tool(tool, output)
      nil
    end

    PRINCIPAL_ROLES = %w[user human].freeze
    MODEL_ROLES = %w[assistant ai model system developer].freeze

    def role_of(m)
      %w[role type].each do |k|
        r = get(m, k)
        return r.to_s if r.is_a?(String) || r.is_a?(Symbol)
      end
      ''
    end

    def first(*vals) = vals.find { |v| !v.nil? }

    # The context segments a chat message adds, by the conversation's own roles: a user / human turn is the PRINCIPAL; a
    # tool_result / tool-result / function_call_output part inside any turn, a tool / function turn and a turn of an unknown role
    # are UNTRUSTED tool output; assistant / system / developer turns add nothing.
    def message_segments(m)
      return [] if m.nil? || m.is_a?(String) || m == true || m == false || m.is_a?(Numeric)

      role = role_of(m).downcase
      return [] if MODEL_ROLES.include?(role)

      content = get(m, 'content')
      tool_name = lambda do |x|
        v = first(*%w[toolName name tool_use_id toolCallId tool_call_id].map { |k| get(x, k) }, get(m, 'name'), get(m, 'tool_call_id'), 'tool')
        Js.string(v)
      end
      unless PRINCIPAL_ROLES.include?(role)
        return [{ 'origin' => 'tool', 'source' => tool_name.call(m), 'content' => content.nil? ? m : content }]
      end
      return [{ 'origin' => 'principal', 'source' => 'user', 'content' => content.nil? ? '' : content }] unless content.is_a?(Array)

      out = []
      text = []
      content.each do |part|
        pt = part.is_a?(Hash) || part.is_a?(Array) || !(part.nil? || part.is_a?(String) || part == true || part == false || part.is_a?(Numeric)) ? part : { 'type' => 'text', 'text' => Js.string(part) }
        t = get(pt, 'type')
        t = '' unless t.is_a?(String)
        if %w[tool_result tool-result function_call_output].include?(t)
          out << { 'origin' => 'tool', 'source' => tool_name.call(pt),
                   'content' => first(get(pt, 'content'), get(pt, 'result'), get(pt, 'output'), pt) }
        elsif get(pt, 'text').is_a?(String)
          text << get(pt, 'text')
        else
          out << { 'origin' => 'principal', 'source' => 'user', 'content' => pt }
        end
      end
      out.unshift({ 'origin' => 'principal', 'source' => 'user', 'content' => text.join("\n") }) unless text.empty?
      out
    end

    def target_recorder(t)
      return nil if t.nil?

      t.respond_to?(:for_action) ? t : recorder_of(t)
    end

    # Record a conversation's new messages in the agent's provenance chain (call it with the whole list before each model turn;
    # messages already recorded are skipped, a shorter list starts over).
    def record_messages(target, messages)
      rec = target_recorder(target)
      return nil if rec.nil? || !messages.is_a?(Array)

      seen = SEEN.key?(rec) ? SEEN[rec] : 0
      (messages.length < seen ? 0 : seen).upto(messages.length - 1) do |i|
        message_segments(messages[i]).each do |seg|
          if seg['origin'] == 'principal'
            rec.principal(seg['content'].is_a?(String) ? seg['content'] : Js.json(seg['content']))
          else
            rec.tool(seg['source'], seg['content'])
          end
        end
      end
      SEEN[rec] = messages.length
      nil
    end

    # What the principal asked for: a string is the principal's message; a message list (or {messages: [...]}) goes through
    # record_messages; a Hash's input / prompt / query / question / message / text string (or message list) is the principal's
    # message. Anything else records nothing (the gate then keeps the context at `agent`: fail closed).
    def record_input(target, input)
      rec = target_recorder(target)
      return nil if rec.nil?

      case input
      when String then rec.principal(input)
      when Array then record_messages(rec, input)
      when Hash
        record_messages(rec, get(input, 'messages')) if get(input, 'messages').is_a?(Array)
        %w[input prompt query question message text].each do |k|
          v = get(input, k)
          if v.is_a?(String) then rec.principal(v)
          elsif v.is_a?(Array) then record_messages(rec, v)
          end
        end
      end
      nil
    end

    # Wrap a framework entry point so its first argument, the principal's request, is recorded before it runs.
    def with_principal_input(target, fn)
      lambda do |*args, **kw, &blk|
        record_input(target, args[0])
        fn.call(*args, **kw, &blk)
      end
    end
  end
end
