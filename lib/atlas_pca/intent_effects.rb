# frozen_string_literal: true

require_relative 'intent_omega'
require_relative 'intent_policy'
require_relative 'intent_v2'
require_relative 'predicates'

# Outcome verification: postconditions on observed effects, evaluated by the one predicate evaluator. Three-valued: ok, violated,
# pending. Native port of the TypeScript reference (@atlasauth/pca-intent).
module AtlasPca
  module IntentEffects
    UNDEF = V2JS::UNDEF
    INDEX_RE = /\A(?:0|[1-9][0-9]*)\z/

    def self.eff(field) = "env.effect.#{field}"
    def self.pc(id, verb, description, where) = { 'id' => id, 'verb' => verb, 'description' => description, 'where' => where }

    AMT = [{ 'field' => eff('amount'), 'op' => 'lte', 'ref' => 'action.params.amount' }, { 'field' => eff('amount'), 'op' => 'gte', 'value' => 0 }].freeze

    DEFAULT_POSTCONDITIONS = [
      pc('stripe.refund.amount', 'stripe.refund', 'the refunded amount is at most the requested amount', AMT.map(&:dup)),
      pc('stripe.refund.recipient', 'stripe.refund', 'the refund went to the requested recipient', [{ 'field' => eff('recipient'), 'op' => 'eq', 'ref' => 'action.params.recipient' }]),
      pc('stripe.charge.amount', 'stripe.charge', 'the charged amount is at most the requested amount', AMT.map(&:dup)),
      pc('stripe.payout.amount', 'stripe.payout', 'the paid-out amount is at most the requested amount', AMT.map(&:dup)),
      pc('stripe.payout.recipient', 'stripe.payout', 'the payout went to the requested recipient', [{ 'field' => eff('recipient'), 'op' => 'eq', 'ref' => 'action.params.recipient' }]),
      pc('gmail.send.to', 'gmail.send', 'the mail went only to the requested address', [{ 'field' => eff('to'), 'op' => 'eq', 'ref' => 'action.params.to' }]),
      pc('slack.post_message.channel', 'slack.post_message', 'the message was posted in the requested channel', [{ 'field' => eff('channel'), 'op' => 'eq', 'ref' => 'action.params.channel' }]),
      pc('files.write.path', 'files.write', 'the written path is the requested resource', [{ 'field' => eff('path'), 'op' => 'eq', 'ref' => 'action.resource' }]),
      pc('files.delete.path', 'files.delete', 'the deleted path is the requested resource', [{ 'field' => eff('path'), 'op' => 'eq', 'ref' => 'action.resource' }]),
      pc('github.merge_pr.repo', 'github.merge_pr', 'the merge landed in the requested repository', [{ 'field' => eff('repo'), 'op' => 'eq', 'ref' => 'action.resource' }]),
      pc('calendar.create_event.hour', 'calendar.create_event', 'the event starts at the requested hour', [{ 'field' => eff('hour'), 'op' => 'eq', 'ref' => 'env.hour' }])
    ].freeze

    module_function

    def leaves(c, out)
      return unless c.is_a?(Hash)

      if Predicates.group?(c)
        if c.key?('all_of') && c['all_of'].is_a?(Array)
          c['all_of'].each { |x| leaves(x, out) }
        elsif c.key?('any_of') && c['any_of'].is_a?(Array)
          c['any_of'].each { |x| leaves(x, out) }
        elsif c.key?('not')
          leaves(c['not'], out)
        end
        return
      end
      return unless Predicates.leaf?(c)

      d = { 'field' => c['field'] }
      d['ref'] = c['ref'] if c['ref'].is_a?(String)
      out << d
    end

    def get(root, path)
      cur = root
      path.split('.', -1).each do |k|
        if cur.is_a?(Hash) && cur.key?(k)
          cur = cur[k]
        elsif cur.is_a?(Array) && k.match?(INDEX_RE) && k.to_i < cur.length
          cur = cur[k.to_i]
        else
          return UNDEF
        end
      end
      cur
    end

    # The evaluator's context for an action plus its observed effect.
    def effect_context(vs, o, effect)
      a = IntentPolicy.outcome_to_action(vs, o)
      ctx = { 'action' => { 'verb' => a['verb'], 'resource' => a['resource'], 'params' => a['params'], 'reversibility_class' => vs['reversibility'] } }
      ctx['subject'] = a['subject'] if a['subject'] && !a['subject'].empty?
      ctx['env'] = (a['env'] || {}).merge('effect' => effect)
      ctx
    end

    def check_postconditions(vs, o, effect, pcs = nil)
      pcs = DEFAULT_POSTCONDITIONS if pcs.nil?
      ctx = effect_context(vs, o, effect)
      rep = { 'status' => 'ok', 'violated' => [], 'missing' => [], 'checked' => [], 'notApplicable' => [] }
      pcs.each do |pc|
        next if pc['verb'] != o['verb']

        ls = []
        pc['where'].each { |c| leaves(c, ls) }
        if ls.any? { |l| l.key?('ref') && !l['ref'].start_with?('env.effect.') && get(ctx, l['ref']).equal?(UNDEF) }
          rep['notApplicable'] << pc['id']
          next
        end
        need = {}
        ls.each do |l|
          ([l['field']] + (l['ref'] ? [l['ref']] : [])).each { |f| need[f] = nil if f.start_with?('env.effect.') }
        end
        lacking = need.keys.select { |f| get(ctx, f).equal?(UNDEF) }
        unless lacking.empty?
          rep['missing'].concat(lacking)
          next
        end
        rep['checked'] << pc['id']
        r = AtlasPca.evaluate_predicates([{ 'verb' => o['verb'], 'resource' => '*', 'where' => pc['where'] }], ctx)
        rep['violated'] << pc['id'] unless r['allowed']
      end
      rep['missing'] = rep['missing'].uniq.sort_by { |s| IntentOmega.u16key(s) }
      rep['status'] = if !rep['violated'].empty? then 'violated'
                      elsif !rep['missing'].empty? then 'pending'
                      else 'ok'
                      end
      rep
    end

    # Check an executed action's effect and feed the result back: a violation is a negative runtime observation that vetoes the
    # action's cell. `ok` and `pending` change nothing (a met postcondition is not the principal's endorsement).
    def verify_outcome(l, o, effect, pcs = nil)
      require_relative 'intent_mapkit'
      vs = l.omega['verbs'].find { |v| v['verb'] == o['verb'] }
      raise ArgumentError, "verifyOutcome: no verb #{o['verb']} in Ω" if vs.nil?

      report = check_postconditions(vs, o, effect, pcs)
      return { 'report' => report } if report['status'] != 'violated'

      { 'report' => report, 'divergence' => IntentMapkit.apply_divergence(l, o, 0) }
    end
  end
end
