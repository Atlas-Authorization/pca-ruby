# frozen_string_literal: true

require_relative 'goal_js'
require_relative 'goal_examples'
require_relative 'goal_sign'
require_relative 'escalation'
require_relative 'intent_wb'

module AtlasPca
  # Progressive authorization (the TypeScript reference is @atlasauth/pca-goal `precedent`). Widening is only by an escalation
  # request answered by a principal-signed escalation answer. A verified answer becomes an append-only hash-chained precedent bound
  # to (policy digest, decision cell, the answered action's exact quantities as a ceiling). A recorded cell decision is never
  # flipped except by a principal-signed revocation. P1 the allow set grows only by cells with a valid principal signature bound to
  # the policy digest; P2 no replay of an answer onto another policy digest, cell or beyond the signed ceiling; P3 a Deny is never
  # turned into Allow (precedents act only on Escalate); P4 Escalate never becomes Allow implicitly. NOT covered by any signature:
  # the relation facts (`rels`) and the log itself (the integrity of the head is the verifier's to anchor).
  module GoalPrecedent
    J = GoalJs
    GENESIS = '0' * 64

    module_function

    def unit_key(q)
      u = J.jget(q, 'u')
      J.jget(u, 'k') == 'money' ? "money:#{J.js_str(J.jget(u, 'ccy'))}" : J.js_str(J.jget(u, 'k'))
    end

    # Ceilings are keyed by parameter AND unit (kind + currency): a EUR answer never covers a GBP action.
    def ceilings_of(params)
      out = {}
      params.each_pair { |k, v| out["#{k}|#{unit_key(J.jget(v, 'q'))}"] = J.jget(J.jget(v, 'q'), 'n') if J.jget(v, 'k') == 'q' }
      out
    end

    def case_of(a)
      act = J.jget(J.jget(a, 'pcactn'), 'action')
      { 'act' => GoalExamples.mk_act(J.jget(act, 'verb'), J.jget(act, 'resource'), J.jget(a, 'params')), 'rels' => J.jget(a, 'rels') }
    end

    def sign_revocation(p, secret) = GoalSign.sign_payload('precedent-revocation', p, secret)

    # The answer body for a request: bind it to the request's exact (policy, action, history head); sign it as an escalation answer.
    def answer_body_for(req, o)
      { 'v' => 1, 'kind' => 'pca-escalation-answer', 'principal' => J.jget(o, 'principal'), 'policy_digest' => J.jget(req, 'policy_digest'),
        'action_digest' => J.jget(req, 'action_digest'), 'history_head' => J.jget(req, 'history_head'), 'decision' => J.jget(o, 'decision'),
        'iat' => J.jget(o, 'iat'), 'expires_at' => J.jget(o, 'expires_at'), 'nonce' => J.jget(o, 'nonce') }
    end

    def nz(x) = x.nil? || J.undef?(x) ? nil : x

    def entry_digest(e)
      answered = nz(e['answered'])
      AtlasPca.hash_canonical({
                                'd' => 'atlas-pca/goal-precedent-entry/v1', 'seq' => e['seq'], 'prev' => e['prev'], 'kind' => e['kind'], 'answer' => nz(e['answer']),
                                'answered' => answered && !answered.empty? ? answered.merge('lastCounter' => nz(answered['lastCounter'])) : nil, 'cell' => nz(e['cell']),
                                'ceilings' => nz(e['ceilings']), 'revocation' => nz(e['revocation'])
                              })
    end

    def jstr(x) = J.undef?(x) ? J::UNDEF : Js.json(x)

    class Log
      attr_reader :entries

      def initialize(principals)
        # `principals`: the pinned signers allowed to answer and revoke (the verifier's own list).
        @entries = []
        @principals = principals
      end

      def head = @entries.empty? ? GENESIS : @entries[-1]['digest']

      def pin_for(pk)
        @principals.each { |p| return p if (p.is_a?(String) ? p : GoalJs.jget(p, 'pk')) == pk }
        nil
      end

      # Everything about an answer that does not depend on the clock: shape, pinned signature, bindings, params digest.
      def answer_fault(answer, answered)
        return 'malformed answer' unless AtlasPca.escalation_answer_shape_error(answer).nil?

        pin = pin_for(answer['principal'])
        return 'bad signature' if pin.nil? || !AtlasPca.wb_verify_artifact_sig(AtlasPca::ESCALATION_ANSWER_DOMAIN, answer, pin)

        pcactn = answered['pcactn']
        return 'answer is bound to another action' if answer['action_digest'] != AtlasPca.escalation_action_digest(pcactn)
        return 'answer is bound to another history state' if answer['history_head'] != AtlasPca.escalation_history_head(GoalPrecedent.nz(answered['lastCounter']))
        return 'params do not match the signed action' if AtlasPca.params_digest(answered['params']) != pcactn['action']['params_digest']

        nil
      end

      # Recompute the whole chain (append-only integrity), every signature and binding, and every derived cell and ceiling.
      def verify_chain(space)
        prev = GENESIS
        @entries.each_with_index do |e, i|
          return false if e['seq'] != i || e['prev'] != prev || GoalPrecedent.entry_digest(e) != e['digest']

          if e['kind'] == 'answer'
            return false if !e['answer'] || !e['answered'] || !answer_fault(e['answer'], e['answered']).nil?
            return false if e['cell'] != GoalExamples.cell_key(space, GoalPrecedent.case_of(e['answered'])) ||
                            GoalPrecedent.jstr(e.key?('ceilings') ? e['ceilings'] : J::UNDEF) != GoalPrecedent.jstr(GoalPrecedent.ceilings_of(e['answered']['params']))
          elsif !(e['revocation'] && GoalSign.verify_payload(e['revocation'], 'precedent-revocation', @principals))
            return false
          end
          prev = e['digest']
        end
        true
      rescue StandardError
        false
      end

      def live(policy, cell, now)
        revoked = @entries.select { |e| e['kind'] == 'revocation' }.map { |e| e['revocation']['payload']['target_entry'] }
        @entries.reverse_each do |e|
          return e if e['kind'] == 'answer' && e['answer']['policy_digest'] == policy && e['cell'] == cell && e['answer']['expires_at'] > now && !revoked.include?(e['digest'])
        end
        nil
      end

      # Verify the answer (pinned signer, bound to this grant's policy digest and this exact action and history, unexpired) and
      # record it.
      def append(answer, answered, grant, space, now)
        v = AtlasPca.verify_escalation_answer(answer, @principals, {
                                                'policy_digest' => AtlasPca.escalation_policy_digest(grant), 'action_digest' => AtlasPca.escalation_action_digest(answered['pcactn']),
                                                'history_head' => AtlasPca.escalation_history_head(GoalPrecedent.nz(answered['lastCounter']))
                                              }, now)
        return { 'ok' => false, 'reason' => v[:reason] } unless v[:ok]

        fault = answer_fault(answer, answered)
        return { 'ok' => false, 'reason' => fault } if fault

        cell = GoalExamples.cell_key(space, GoalPrecedent.case_of(answered))
        existing = live(answer['policy_digest'], cell, now)
        return { 'ok' => false, 'reason' => 'conflicts with a recorded decision; revoke it first' } if !existing.nil? && existing['answer']['decision'] != answer['decision']

        { 'ok' => true, 'entry' => push({ 'kind' => 'answer', 'answer' => answer, 'answered' => answered, 'cell' => cell, 'ceilings' => GoalPrecedent.ceilings_of(answered['params']) }) }
      end

      def revoke(rev)
        return { 'ok' => false, 'reason' => 'bad signature' } unless GoalSign.verify_payload(rev, 'precedent-revocation', @principals)

        p = rev['payload']
        unless @entries.any? { |e| e['kind'] == 'answer' && e['digest'] == p['target_entry'] && e['answer']['policy_digest'] == p['policy_digest'] && e['cell'] == p['cell'] }
          return { 'ok' => false, 'reason' => 'no such precedent' }
        end

        { 'ok' => true, 'entry' => push({ 'kind' => 'revocation', 'revocation' => rev }) }
      end

      def push(e)
        base = { 'seq' => @entries.length, 'prev' => head }.merge(e.reject { |_, v| GoalJs.undef?(v) })
        entry = base.merge('digest' => GoalPrecedent.entry_digest(base))
        @entries << entry
        entry
      end

      # The recorded decision covering this case under this policy, if any (cell match, ceilings respected, unexpired, unrevoked).
      def lookup(policy_digest, space, c, now)
        e = live(policy_digest, GoalExamples.cell_key(space, c), now)
        return nil if e.nil?

        ceil = e['ceilings']
        now2 = GoalPrecedent.ceilings_of(GoalJs.jget(GoalJs.jget(c, 'act'), 'params'))
        now2.each { |k, v| return nil if v > (ceil.key?(k) ? ceil[k] : -Float::INFINITY) } # beyond the signed ceiling
        ceil.each_key { |k| return nil unless now2.key?(k) } # same parameters and units as the signed witness
        { 'decision' => e['answer']['decision'], 'entry' => e }
      end
    end

    # Policy decision refined by precedents. Precedents act only on Escalate (P3, P4); a tampered log fails closed.
    def authorize_with_precedents(goal, ont, policy_digest, log, c, now)
      base = GoalExamples.decide_case(goal, ont, c)['decision']
      return { 'decision' => base, 'via' => 'policy' } if base != 'escalate'

      space = GoalExamples.build_space([goal])
      return { 'decision' => 'escalate', 'via' => 'policy' } unless log.verify_chain(space)

      hit = log.lookup(policy_digest, space, c, now)
      return { 'decision' => 'escalate', 'via' => 'policy' } if hit.nil?

      { 'decision' => hit['decision'] == 'allow' ? 'allow' : 'deny', 'via' => 'precedent', 'precedent' => hit['entry'] }
    end
  end
end
