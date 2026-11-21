# frozen_string_literal: true

# The undo-window coordinator (AtlasPca.create_undo_coordinator): admission, the durable record, the one-click veto, the compensation at
# most once, finalization, and every fail-closed refusal. Hand-written (no shared corpus exists for the coordinator in any language).
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestUndoCoordinator < Minitest::Test
  A = AtlasPca
  P = A::KeyPair.new("\x01".b * 32)
  H = A::KeyPair.new("\x02".b * 32)
  D43 = 'A' * 43
  ENV_ = { 'predicates' => [{ 'verb' => 'pay', 'resource' => 'invoice:*' }, { 'verb' => 'pay.refund', 'resource' => 'invoice:*' }], 'caveats' => [],
           'risk_policy' => A::DEFAULT_RISK_POLICY }.freeze
  GRANT = A.mint_grant(P, H.public, ENV_, 'pay invoices', salt: 's')['grant']
  OP = { 'verb' => 'pay', 'resource' => 'invoice:1', 'params' => { 'amount' => 5 } }.freeze

  class Engine
    def initialize(plan = { 'def_digest' => D43, 'compensation' => { 'verb' => 'pay.refund', 'params' => {}, 'def_digest' => D43, 'target_param' => 'payment' } })
      @plan = plan
    end

    def plan(_op, _ctx) = @plan
  end

  class Notifier
    attr_reader :notices

    def initialize(deliver = true)
      @deliver = deliver
      @notices = []
    end

    def notify(n)
      @notices << n
      @deliver ? { 'delivered' => true } : { 'delivered' => false, 'reason' => 'no channel' }
    end
  end

  def build(clock, notifier: nil, store: nil, engine: nil, **kw)
    calls = []
    alerts = []
    c = A.create_undo_coordinator({ 'store' => store || A::MemoryUndoStore.new, 'engine' => engine || Engine.new, 'signer_secret' => "\x09".b * 32,
                                    'audience' => 'rs', 'resolve_grant' => ->(_ref, _pc) { GRANT },
                                    'compensate' => ->(call) { calls << call; { 'refund' => 'r1' } },
                                    'operations' => A::MemoryOperationStore.new, 'notifier' => notifier || Notifier.new, 'alert' => ->(a) { alerts << a },
                                    'now' => -> { clock[0] }, 'insecure_volatile_store' => true }.merge(kw.transform_keys(&:to_s)))
    [c, calls, alerts]
  end

  def action(cls = nil)
    ag = A::Agent.new(H, GRANT, 'rs', clock: -> { 1_000 })
    ag.use_plan([{ 'id' => 'n1', 'verb' => 'pay', 'resource' => 'invoice:1', 'params_digest' => A.params_digest({ 'amount' => 5 }),
                   'reversibility_class' => cls }.compact]) if cls
    ag.act('pay', 'invoice:1', { 'amount' => 5 }).pcactn
  end

  def test_veto_with_the_token_compensates_once
    clock = [1_000]
    c, calls, alerts = build(clock)
    adm = c.admit(action, OP, false, GRANT)
    refute adm.key?('refused'), adm['refused']
    info = c.open(adm)
    assert_equal 'undo_window', info['obligation']['kind']
    assert_equal 'open', c.get(adm['id'])['state']
    c.record_effect(adm['id'], { 'id' => 'pay_1' }, true)
    clock[0] = 2_000
    v = c.veto(adm['id'], token: info['token'])
    assert_equal [true, 'compensated', false], [v['ok'], v['record']['state'], v['replayed']]
    assert_equal [{ 'payment' => 'pay_1' }], calls.map { |x| x['operation']['params'] }
    again = c.veto(adm['id'], token: info['token']) # the same veto is a replay: the compensation never runs twice
    assert_equal [true, true, 1, []], [again['ok'], again['replayed'], calls.length, alerts]
  end

  def test_a_bad_token_or_a_late_veto_is_refused
    clock = [1_000]
    c, calls, = build(clock)
    adm = c.admit(action, OP, false, GRANT)
    info = c.open(adm)
    refute c.veto(adm['id'], token: 'not a token')['ok']
    clock[0] = adm['window_end'] + 1
    refute c.veto(adm['id'], token: info['token'])['ok']
    assert_empty calls
  end

  def test_finalize_closes_the_window_and_alerts_an_unreported_effect
    clock = [1_000]
    c, calls, alerts = build(clock)
    adm = c.admit(action, OP, false, GRANT)
    c.open(adm)
    assert_equal [], c.finalize_due # the window is still open
    clock[0] = adm['window_end'] + 5
    assert_equal [adm['id']], c.finalize_due
    assert_equal 'finalized', c.get(adm['id'])['state']
    assert_equal ['effect_unknown'], alerts.map { |a| a['code'] }
    assert_empty calls
  end

  def test_a_window_nobody_was_told_about_is_aborted
    clock = [1_000]
    c, _, alerts = build(clock, notifier: Notifier.new(false))
    adm = c.admit(action, OP, false, GRANT)
    assert_raises(A::UndoError) { c.open(adm) }
    assert_equal 'finalized', c.get(adm['id'])['state']
    assert_equal %w[notify_failed critical], [alerts[0]['code'], alerts[0]['level']]
  end

  def test_admission_refuses_what_is_not_confirmed_reversible
    clock = [1_000]
    c, = build(clock)
    assert c.admit(action('irreversible'), OP, false, GRANT)['refused'].start_with?('the signed class is irreversible')
    none, = build(clock, engine: Engine.new(nil))
    assert_includes none.admit(action, OP, false, GRANT)['refused'], 'not confirmed reversible'
    off, = build(clock, policy: ->(_op, _g) { { 'mode' => 'off' } })
    assert_equal 'policy: undo windows are off', off.admit(action, OP, false, GRANT)['refused']
    only_esc, = build(clock, policy: ->(_op, _g) { { 'mode' => 'escalations' } })
    assert_includes only_esc.admit(action, OP, false, GRANT)['refused'], 'windows only replace approvals'
    refute only_esc.admit(action, OP, true, GRANT).key?('refused')
  end

  def test_a_compensation_the_grant_does_not_allow_is_refused
    wide = Engine.new({ 'def_digest' => D43, 'compensation' => { 'verb' => 'admin.delete', 'params' => {}, 'def_digest' => D43 } })
    c, = build([1_000], engine: wide)
    assert_includes c.admit(action, OP, false, GRANT)['refused'], 'not authorized under the grant'
  end

  def test_a_volatile_store_and_missing_components_fail_closed
    base = { 'store' => A::MemoryUndoStore.new, 'engine' => Engine.new, 'signer_secret' => "\x09".b * 32, 'audience' => 'rs',
             'resolve_grant' => ->(_r, _p) { GRANT }, 'compensate' => ->(_c) {}, 'operations' => A::MemoryOperationStore.new, 'notifier' => Notifier.new,
             'alert' => ->(_a) {} }
    assert_equal 'not_durable', assert_raises(A::UndoError) { A.create_undo_coordinator(base) }.code
    assert_equal 'config', assert_raises(A::UndoError) { A.create_undo_coordinator(base.merge('audience' => '')) }.code
  end

  def test_the_kv_store_and_effect_reporting
    clock = [1_000]
    c, calls, = build(clock, store: A::KvUndoStore.new(A.create_memory_durable_kv, false))
    adm = c.admit(action, OP, false, GRANT)
    c.open(adm)
    assert_equal 0, c.get(adm['id'])['ver']
    rec = A.report_undo_effect(c, adm['id'], { 'status' => 'committed', 'result' => { 'id' => 'p9' } })
    assert_equal({ 'id' => 'p9' }, rec['effect']['result'])
    assert_equal 'compensated', c.veto(adm['id'], operator: 'ops')['record']['state']
    assert_equal({ 'payment' => 'p9' }, calls[0]['operation']['params'])
  end

  def test_the_real_budget_ledger_is_released_on_compensation_with_evidence_only_when_supplied
    [[nil, false], [->(r, how) { A::BudgetLedger.sign_release(r['key'], r['id'], how, 1_000, A::KeyPair.new("\x09".b * 32)) }, true]].each do |evidence, signed|
      clock = [1_000]
      ledger = A::KvBudgetLedger.new(A::MemoryAtomicKv.new, true)
      c, calls, = build(clock, budget: evidence ? { 'ledger' => ledger, 'evidence' => evidence } : ledger)
      adm = c.admit(action, OP, false, GRANT)
      c.open(adm)
      ev = { 'id' => adm['id'], 'verb' => 'pay', 'resource' => 'invoice:1', 'params' => {}, 't' => 1_000 }
      assert_equal 'reserved', ledger.reserve('principal/p', { 'event' => ev, 'accumulators' => [] })['outcome']
      c.hold_budget(adm['id'], [{ 'key' => 'principal/p', 'id' => adm['id'] }])
      c.record_effect(adm['id'], { 'id' => 'pay_1' }, true)
      assert_equal 'compensated', c.veto(adm['id'], operator: 'ops')['record']['state']
      refute_empty calls
      event = ledger.snapshot('principal/p')['events'][0]
      assert_equal 'released', event['status']
      assert_equal signed, event.key?('rel') # no evidence unless the caller supplies it, as the reference
      assert A::BudgetLedger.verify_release(event['rel'], A.undo_signer_public("\x09".b * 32)) if signed
    end
  end

  def test_rollback_on_slash_needs_a_bond_ledger
    c, = build([1_000])
    assert_equal 'config', assert_raises(A::UndoError) { c.rollback_on_slash({ 'claimId' => 'x' }) }.code
  end
end
