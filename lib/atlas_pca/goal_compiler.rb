# frozen_string_literal: true

require 'digest'
require_relative 'goal_codec'
require_relative 'goal_kernel'
require_relative 'goal_normalize'
require_relative 'goal_review'

module AtlasPca
  # The typed front door of the goal compiler (the TypeScript reference is @atlasauth/pca-goal `compiler`): IR values in, IR values
  # out, every decision made by AtlasPca::GoalKernel over token tapes. Plus the canonical policy bytes and digest.
  module GoalCompiler
    IrError = Goal::IrError
    K = GoalKernel
    C = GoalCodec

    module_function

    def first(t)
      x = t[0]
      raise IrError, 'malformed compiler output' unless x && x[0] == 'i'

      x[1]
    end

    def reasons_of(t)
      n = t[1] && t[1][0] == 'i' ? t[1][1] : 0
      (t[2, n] || []).map { |x| x[0] == 's' ? x[1] : '' }
    end

    def decision_of(n) = n == 2 ? 'allow' : (n == 1 ? 'escalate' : 'deny')

    # Type reasons of a goal against an ontology; [] = well typed.
    def typecheck(goal, ont)
      out = K.kernel_call('typecheck', C.encode_goal(goal), C.encode_ontology(ont))
      case first(out)
      when 0 then []
      when 1 then reasons_of(out)
      else raise IrError, 'compiler rejected the input tape'
      end
    end

    # C: Goal -> { 'ok' => true, 'policy' => ... } | { 'ok' => false, 'reasons' => [...] }. Ill-typed goals are rejected, never coerced.
    def compile_goal(goal, ont)
      out = K.kernel_call('compile', C.encode_goal(goal), C.encode_ontology(ont))
      case first(out)
      when 0 then { 'ok' => true, 'policy' => C.decode_policy(out[1..]) }
      when 1 then { 'ok' => false, 'reasons' => reasons_of(out) }
      else raise IrError, 'compiler rejected the input tape'
      end
    end

    # The reference semantics D_G(a, H) (the specification the compiled policy is proved equal to).
    def decide_goal(goal, ont, act, hist)
      out = K.kernel_call('decideg', C.encode_goal(goal), C.encode_ontology(ont), C.encode_act(act), C.encode_hist(hist))
      raise IrError, 'compiler rejected the input tape' unless first(out).zero?

      decision_of(out[1][1])
    end

    # The compiled policy's decision, the witness of an Allow and the separate checker's verdict on it.
    def decide_policy(goal, ont, act, hist)
      out = K.kernel_call('decidep', C.encode_goal(goal), C.encode_ontology(ont), C.encode_act(act), C.encode_hist(hist))
      s = first(out)
      return { 'ok' => false, 'reasons' => reasons_of(out) } if s == 1
      raise IrError, 'compiler rejected the input tape' unless s.zero?

      d = decision_of(out[1][1])
      n = out[3][1]
      bids = out[4, n].map { |x| x[0] == 's' ? x[1] : '' }
      { 'ok' => true, 'decision' => d, 'witness' => d == 'allow' ? { 'gid' => out[2][1], 'bids' => bids } : nil,
        'witnessChecked' => out[4 + n][1] == 1 }
    end

    # The card as a token tape: decode_goal(render_tape(g)) equals g.
    def render_tape(goal)
      out = K.kernel_call('render', C.encode_goal(goal))
      raise IrError, 'goal tape rejected' unless first(out).zero?

      out[1..]
    end

    # Canonical text of a policy (sorted-key JSON, no floats), the input of the policy digest.
    def canonical_policy(p)
      return GoalNormalize.jq(p) unless p.is_a?(Hash) || p.is_a?(Array)
      return "[#{p.map { |x| canonical_policy(x) }.join(',')}]" if p.is_a?(Array)

      "{#{p.keys.sort_by { |k| GoalJs.u16key(k) }.map { |k| "#{GoalNormalize.jq(k)}:#{canonical_policy(p[k])}" }.join(',')}}"
    end

    def policy_digest(p) = AtlasPca.b64e(Digest::SHA256.digest(canonical_policy(p)))

    # The review kernel of the reference (`provedKernel`): compile, policy digest and the reference decision.
    def proved_kernel = GoalReview::ReviewKernel.new(method(:compile_goal), method(:policy_digest), nil, method(:decide_goal), nil)
  end
end
