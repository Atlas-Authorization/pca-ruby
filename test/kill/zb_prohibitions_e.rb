# frozen_string_literal: true

# zb_prohibitions_e: boundaries and non-string operands of the prohibition engine that the other zb_prohibitions files
# leave open (packages/pca/src/prohibitions.ts is authoritative). Builds on the helpers of zb_prohibitions_b.rb and
# zb_prohibitions_d.rb.

module MutationKill
  module ZbQ
    # Not a String, but it converts to one and equals it: an array membership test accepts it as the operator "eq".
    class StringLike
      def to_str = 'eq'
      def ==(other) = other == 'eq' || other.equal?(self)
    end
  end

  t('zb prohibitions: a condition operator must itself be a String') do
    next true unless ZbQ.gate?

    q = ZbQ
    p = q::P
    cond = ->(op) { { 'field' => 'action.verb', 'op' => op, 'value' => 'x' } }
    q.ck('string op', p.validate_condition(cond.call('eq')), nil)
    q.ck('string-like op', p.validate_condition(cond.call(q::StringLike.new)), 'unknown condition op [object Object]')
    q.ck('numeric op', p.validate_condition(cond.call(5)), 'unknown condition op 5')
    q.ck('missing op', p.validate_condition({ 'field' => 'action.verb' }), 'unknown condition op undefined')
    true
  end

  t('zb prohibitions: a digest that is not equal to itself never verifies') do
    next true unless ZbQ.gate?

    q = ZbQ
    k = q.kit
    signed = k[:signed]
    d = k[:digests]
    nan = Float::NAN
    q.ck('honest digests', q.vs(signed, d), { 'ok' => true })
    q.ck('action digest NaN', q.vs(signed, d.merge('actionDigest' => nan)), q.no('action digest mismatch (evidence bound to another action)'))
    q.ck('constitution id NaN', q.vs(signed, d.merge('constitutionId' => nan)), q.no('constitution mismatch (evidence bound to another constitution)'))
    q.ck('state digest NaN', q.vs(signed, d.merge('stateDigest' => nan)), q.no('state digest mismatch (evidence bound to another state)'))
    true
  end

  t('zb prohibitions: a ledger of exactly the maximum size is kept, one more is merged or refused') do
    next true unless ZbQ.gate?

    q = ZbQ
    p = q::P
    full = Array.new(p::MAX_LEDGER - 1) { q.entry(q::NOW - 1) }
    rate = { 'id' => 'r', 'kind' => 'rate', 'when' => { 'verb' => 'send' }, 'max' => 10_000, 'window_secs' => 60 }
    r = p.advance_state_strict(q.act('send'), q.con([rate]), q.st('ledger' => { 'r' => full }))
    q.ck('rate ledger at the maximum is admitted', [r['ok'], r['ok'] && r['state']['ledger']['r'].length], [true, p::MAX_LEDGER])
    over = p.advance_state_strict(q.act('send'), q.con([rate]), q.st('ledger' => { 'r' => full + [q.entry(q::NOW - 1)] }))
    q.ck('rate ledger above the maximum is refused', over, { 'ok' => false, 'reason' => 'r: rate ledger overflow' })

    cap = { 'id' => 'c', 'kind' => 'cap', 'when' => { 'verb' => 'pay' }, 'amount' => 'action.params.n', 'max' => 1_000_000 }
    c = p.advance_state_strict(q.act('pay', '/r', { 'n' => 1 }), q.con([cap]), q.st('ledger' => { 'c' => full }))
    q.ck('cap ledger at the maximum is not merged', [c['ok'], c['ok'] && c['state']['ledger']['c'].length, c['ok'] && c['state']['ledger']['c'].sum { |e| e['amount'] }], [true, p::MAX_LEDGER, p::MAX_LEDGER])
    c2 = p.advance_state_strict(q.act('pay', '/r', { 'n' => 1 }), q.con([cap]), q.st('ledger' => { 'c' => full + [q.entry(q::NOW - 1)] }))
    q.ck('cap ledger above the maximum merges the oldest two', [c2['ok'], c2['ok'] && c2['state']['ledger']['c'].length, c2['ok'] && c2['state']['ledger']['c'].sum { |e| e['amount'] }], [true, p::MAX_LEDGER, p::MAX_LEDGER + 1])
    true
  end
end
