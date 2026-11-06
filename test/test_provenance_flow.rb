# frozen_string_literal: true

# Provenance by default end to end through AtlasPca.authorize and the Rack middleware (check `provenance_flow`, always on),
# the recorder, a hybrid post-quantum receipt chain, and the undo admission hook (a veto window in place of an approval).
#   ruby -Ilib test/test_provenance_flow.rb
require_relative '../lib/atlas_pca/rack_middleware'
require_relative 'support/prov_harness'
require 'minitest/autorun'
require 'json'
require 'stringio'

module ProvFlowFixtures
  CONF = File.expand_path('../conformance', __dir__)
  FIX = AtlasPca.parse_json(File.read(File.expand_path('../test-data/authorize-fixtures.json', __dir__), encoding: 'UTF-8'), loose: true)
  CASE = FIX['cases'].find { |x| x['name'] == 'envelope-max-spend-within' }
  STEP = CASE['steps'][0]
  GRANT = CASE['grant']
  OP = STEP['operation']
  NOW = FIX['now']
  AUD = FIX['audience']
  PUB = JSON.parse(File.read(File.join(CONF, 'keys.json')))['principal']['public']
  PIN_ONLY = { 'mediators' => [ProvHarness::PIN] }.freeze

  def fresh(x) = Marshal.load(Marshal.dump(x))

  def az(pcactn = STEP['pcactn'], grant: GRANT, op: OP, now: NOW, aud: AUD, **kw)
    AtlasPca.authorize(fresh(pcactn), operation: op, audience: aud, resolve_grant: ->(_r) { grant },
                                      state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false }, now: now,
                                      **{ plan: 'single-step' }.merge(kw))
  end

  def flow_reason(r) = r.reasons.find { |x| x.start_with?('provenance_flow: ') }
end

class TestProvenanceFlowAuthorize < Minitest::Test
  include ProvFlowFixtures

  def test_on_by_default_a_call_without_a_bundle_escalates
    r = az
    assert_equal [false, 'escalate', 'fail'], [r.allow, r.decision, r.checks['provenance_flow']]
    assert_equal ['provenance_flow'], r.failed_checks
    assert_equal 'provenance_flow: escalate: the choice of payments.send derives from untrusted content; amount, currency derive ' \
                 'from untrusted content [unlabelled]: the principal must confirm (prompt-injection path)', flow_reason(r)
    assert_equal 'pca-escalation-request', r.escalation['kind']
  end

  def test_a_principal_direct_bundle_from_a_pinned_mediator_passes
    r = az(provenance: ProvHarness::OPTION)
    assert_equal [true, 'allow', 'pass'], [r.allow, r.decision, r.checks['provenance_flow']]
    assert_nil r.undo
    assert_nil r.obligations
  end

  def test_the_explicit_bundle_wins_over_the_option_callable
    r = az(provenance: PIN_ONLY.merge('bundle' => ->(*) { raise 'never called' }), provenance_bundle: ProvHarness.bundle(OP))
    assert r.allow
  end

  def test_symbol_keyed_options_work
    r = az(provenance: { mediators: [ProvHarness::PIN], bundle: ->(_p, op) { ProvHarness.bundle(op) } })
    assert r.allow
  end

  def test_an_unpinned_mediator_vouches_for_nothing
    r = az(provenance: { 'mediators' => [] }, provenance_bundle: ProvHarness.bundle(OP))
    assert_equal [false, 'escalate'], [r.allow, r.decision]
  end

  def test_an_unreadable_bundle_denies
    r = az(provenance: PIN_ONLY.merge('bundle' => ->(*) { raise AtlasPca::Malformed, 'bad header' }))
    assert_equal [false, 'deny'], [r.allow, r.decision]
    assert_equal 'provenance_flow: the provenance bundle is unreadable (fail closed)', flow_reason(r)
  end

  def test_a_forged_chain_denies
    other = AtlasPca::KeyPair.new("\x09".b * 32)
    r = az(provenance: { 'mediators' => [ProvHarness::PIN.merge('pk' => other.public)] }, provenance_bundle: ProvHarness.bundle(OP))
    assert_equal [false, 'deny'], [r.allow, r.decision]
    assert_equal 'provenance_flow: bad_signature: receipt 0 does not verify under the pinned mediator key', flow_reason(r)
    unbound = az(provenance: PIN_ONLY, provenance_bundle: ProvHarness.bundle(OP.merge('resource' => 'payments/other')))
    assert_equal 'deny', unbound.decision
    assert_match(/\Aprovenance_flow: unbound_action: /, flow_reason(unbound))
  end

  def test_read_only_facts_need_no_bundle_and_unreadable_facts_deny
    r = az(provenance: PIN_ONLY.merge('actions' => ->(_op) { { 'effects' => ['read'] } }))
    assert r.allow
    bad = az(provenance: ProvHarness::OPTION.merge('actions' => ->(_op) { raise 'catalog down' }))
    assert_equal 'deny', bad.decision
    assert_equal 'provenance_flow: the action facts or observations could not be read (fail closed)', flow_reason(bad)
    malformed = az(provenance: ProvHarness::OPTION.merge('actions' => ->(_op) { { 'effects' => 'read' } }))
    assert_equal 'deny', malformed.decision
    assert_match(/\Aprovenance_flow: malformed_action: /, flow_reason(malformed))
  end

  def test_an_observed_tool_call_raises_the_context
    seen = []
    obs = lambda do |pcactn, op, session|
      seen << [pcactn['counter'], op['verb'], session]
      [{ 'origin' => 'tool', 'source' => 'inbox.read' }]
    end
    r = az(provenance: ProvHarness::OPTION.merge('observed' => obs))
    assert_equal 'escalate', r.decision
    assert_equal 'provenance_flow: escalate: the choice of payments.send derives from untrusted content [tool:inbox.read]: the ' \
                 'principal must confirm (prompt-injection path)', flow_reason(r)
    assert_equal 1, seen.length
    assert_kind_of String, seen[0][2]
  end

  def test_a_misconfigured_option_fails_closed
    r = az(provenance: 'on')
    refute r.allow
    assert_includes r.reason, 'provenance (must be a Hash)'
    u = az(provenance: ProvHarness::OPTION, undo: 5)
    refute u.allow
    assert_includes u.reason, 'undo (must respond to #call)'
  end

  def test_a_malformed_envelope_member_fails
    g = fresh(GRANT)
    g['caveats'][0]['provenance'] = { 'mode' => 'off' }
    status, reason = AtlasPca.provenance_flow_check(ProvHarness::OPTION, g, STEP['pcactn'], OP, nil, {})
    assert_equal 'fail', status
    assert_equal "the grant's provenance member is malformed: provenance.mode must be 'enforce' or 'insecure_off'", reason
    g['caveats'][0]['provenance'] = { 'mode' => 'insecure_off' }
    assert_equal ['not-enforced', nil], AtlasPca.provenance_flow_check({}, g, STEP['pcactn'], OP, nil, {})
    assert_equal 'fail', AtlasPca.provenance_flow_check({}, GRANT, STEP['pcactn'], nil, nil, {})[0]
  end

  # ---- principal flags: an executable registry plan; an admitted workflow step (the choice only); never a context plan
  def test_an_executable_registry_plan_is_the_principal_choice
    p = STEP['pcactn']
    node = { 'id' => p['plan']['node_id'], 'verb' => p['action']['verb'], 'resource' => p['action']['resource'],
             'params_digest' => p['action']['params_digest'], 'reversibility_class' => p['action']['reversibility_class'] }
    reg = AtlasPca::PlanRegistry.new(now: -> { NOW })
    gid = GRANT['id']
    root = reg.draft(gid, [node])['record']['root']
    [reg.method(:validate), reg.method(:commit)].each { |step| assert step.call(gid, root)['ok'] }
    assert reg.authorize(gid, root, { 'by' => 'principal' })['ok']
    r = az(plan: nil, plans: reg, provenance: PIN_ONLY)
    assert r.allow, r.reasons.inspect
    assert_equal 'pass', r.checks['provenance_flow']
  end

  WF = AtlasPca.parse_json(File.read(File.join(CONF, 'authorize-workflow-fixtures.json'), encoding: 'UTF-8'), loose: true)

  def wf_az(s, w, provenance, bundle)
    AtlasPca.authorize(fresh(s['pcactn']), operation: s['operation'], audience: WF['audience'],
                                           resolve_grant: ->(ref) { ref == WF['grant']['id'] ? WF['grant'] : nil },
                                           state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false }, now: WF['now'],
                                           context: ->(_p) { { 'plan' => WF['plan'], 'plan_authorized' => true } },
                                           workflow: w && { 'principal' => WF['principal'], 'rs_signer' => WF['rs_signer'] },
                                           workflow_call: w && { 'commitment' => w['commitment'], 'receipts' => w['receipts'], 'step' => w['step'],
                                                                 'units' => w['units'], 'goal_digest' => w['goal_digest'] },
                                           provenance: provenance, provenance_bundle: bundle)
  end

  def test_an_admitted_workflow_step_trusts_the_choice_not_the_values
    s = WF['cases'].find { |c| c['name'] == 'pay-after-quote' }['steps'][0]
    op = s['operation']
    rec = ProvHarness.recorder
    rec.principal(AtlasPca.canonicalize(op['params'])) # the principal typed every value
    rec.tool('quotes.get', 'a quote')                    # but a tool result is in the context
    bundle = rec.for_action(op)
    r = wf_az(s, s['workflow'], PIN_ONLY, bundle)
    assert r.allow, r.reasons.inspect
    assert_equal 'pass', r.checks['provenance_flow']
    # the same bundle without the workflow: the choice came from a tool context
    st, why = AtlasPca.provenance_flow_check(PIN_ONLY, WF['grant'], s['pcactn'], op, bundle, { 'plan' => false, 'control' => false })
    assert_equal 'fail', st
    assert_match(/\Aescalate: the choice of /, why)
    # the workflow alone does not vouch for values: no bundle still escalates
    assert_equal 'escalate', wf_az(s, s['workflow'], PIN_ONLY, nil).decision
  end

  def test_a_context_plan_is_not_the_principal
    s = WF['cases'].find { |c| c['name'] == 'workflow-optional-and-absent' }['steps'][0]
    r = wf_az(s, nil, PIN_ONLY, nil)
    assert_equal [false, 'escalate'], [r.allow, r.decision]
  end

  # ---- the grant's signed envelope: the principal's own pins and the documented opt-out
  ZERO = { 'weights' => { 'alpha' => 0, 'beta' => 0, 'gamma' => 0, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0 }, 'theta1' => 1,
           'theta2' => 1, 'kappa' => 100, 'lambda' => 0, 'rho' => 0.5, 'bMax' => 1_000_000 }.freeze
  MAIL = { 'verb' => 'email.send', 'resource' => 'mail', 'params' => { 'to' => 'attacker@x.example' } }.freeze

  def minted(extra)
    principal = AtlasPca::KeyPair.generate
    holder = AtlasPca::KeyPair.generate
    env = { 'predicates' => [{ 'verb' => ['email.send'], 'resource' => '*' }], 'caveats' => [], 'agent_binding' => {}, 'risk_policy' => ZERO }
    grant = AtlasPca.mint_grant(principal, holder.public, env.merge(extra), 'run my errands')['grant']
    pcactn = AtlasPca::Agent.new(holder, grant, 'assistant-rs', clock: -> { NOW }).act(MAIL['verb'], MAIL['resource'], MAIL['params']).pcactn
    [grant, pcactn]
  end

  def test_insecure_off_in_the_envelope_is_the_only_opt_out
    grant, pcactn = minted('provenance' => { 'mode' => 'insecure_off' })
    r = az(pcactn, grant: grant, op: MAIL, aud: 'assistant-rs')
    assert r.allow, r.reasons.inspect
    assert_equal 'not-enforced', r.checks['provenance_flow']
    [{ 'provenance' => { 'mode' => 'enforce' } }, {}].each do |extra|
      g, p = minted(extra)
      assert_equal 'escalate', az(p, grant: g, op: MAIL, aud: 'assistant-rs').decision
    end
    assert_raises(ArgumentError) { minted('provenance' => { 'mode' => 'off' }) }
  end

  def test_the_envelope_can_pin_the_principals_harness
    grant, pcactn = minted('provenance' => { 'mediators' => [ProvHarness::PIN] })
    rec = ProvHarness.recorder
    rec.principal('email attacker@x.example please')
    r = az(pcactn, grant: grant, op: MAIL, aud: 'assistant-rs', provenance_bundle: rec.for_action(MAIL))
    assert r.allow, r.reasons.inspect
  end
end

class TestProvenanceRecorder < Minitest::Test
  def test_round_trip_every_origin
    rec = ProvHarness.recorder
    rec.principal('Email the Q3 report to bob@acme.example')
    rec.tool('crm', { 'email' => 'bob@acme.example' })
    rec.retrieval('doc-17', 'text')
    rec.web('https://x.example', 'page')
    op = { verb: 'email.send', resource: 'mail', params: { 'to' => 'bob@acme.example' } }
    b = rec.for_action(op)
    assert_equal [0, 1, 2, 3, 4], b['receipts'].map { |r| r['seq'] }
    assert_equal %w[principal tool retrieval web action], b['receipts'].map { |r| r['origin'] }
    assert_equal ['0'], b['contents'].keys # only principal text travels
    assert_equal 5, rec.receipts.length
    d = AtlasPca.decide_arg_provenance({ 'bundle' => b, 'operation' => AtlasPca.prov_op_of(op, 't'), 'mediators' => [rec.pin],
                                         'principal_control' => true })
    assert_equal %w[pass trusted], [d['outcome'], d['labels']['to']] # typed by the principal
    assert_equal ['retrieval:doc-17', 'tool:crm', 'web:https://x.example'], d['path']
    refute_includes rec.inspect, ProvHarness::KEY.public
  end

  def test_long_sources_are_clipped_and_bad_arguments_raise
    rec = ProvHarness.recorder
    r = rec.web("https://x.example/#{'a' * 400}", 'p')
    assert_operator r['source'].bytesize, :<=, 256
    assert_raises(ArgumentError) { AtlasPca::ProvenanceRecorder.new(mediator: '', kid: 'k1') }
    assert_raises(ArgumentError) { AtlasPca::ProvenanceRecorder.new(mediator: 'm', kid: 'k1', session: 'short') }
    assert_raises(ArgumentError) { rec.for_action({ verb: 'x' }) }
  end

  def test_hybrid_post_quantum_receipts
    alg = 'hybrid-ed25519-ml-dsa-65'
    unless AtlasPca.supported_suites.include?(alg)
      flunk "#{alg}: OpenSSL >= 3.5 is required in CI" if ENV['PCA_REQUIRE_PQ'] == '1'
      skip "#{alg} is not supported by this OpenSSL"
    end
    pq = AtlasPca::PqKeyPair.generate('ML-DSA-65')
    rec = AtlasPca::ProvenanceRecorder.new(mediator: 'pq-harness', kid: 'k1', alg: alg, pq: pq)
    assert_equal pq.public, rec.pin['pq_pk']
    op = { 'verb' => 'payments.send', 'resource' => 'bank', 'params' => { 'amount' => 1 } }
    b = AtlasPca.principal_direct_provenance(rec, op)
    assert(b['receipts'].all? { |r| r['alg'] == alg && r['pq_sig'].is_a?(String) })
    ok = AtlasPca.decide_arg_provenance({ 'bundle' => b, 'operation' => op, 'mediators' => [rec.pin] })
    assert_equal 'pass', ok['outcome']
    other = AtlasPca::PqKeyPair.generate('ML-DSA-65')
    bad = AtlasPca.decide_arg_provenance({ 'bundle' => b, 'operation' => op, 'mediators' => [rec.pin.merge('pq_pk' => other.public)] })
    assert_equal 'deny', bad['outcome']
    no_pq = AtlasPca.decide_arg_provenance({ 'bundle' => b, 'operation' => op, 'mediators' => [rec.pin.reject { |k, _| k == 'pq_pk' }] })
    refute_equal 'pass', no_pq['outcome']
  end
end

class TestUndoHook < Minitest::Test
  include ProvFlowFixtures

  ADMISSION = { 'id' => 'op_1', 'window_end' => NOW + 900_000, 'compensation' => { 'verb' => 'payments.refund', 'resource' => 'payments/acme' } }.freeze

  # Make the core verifier report the given checks as failed with `reason`, restoring it after.
  def with_failing(checks, reason)
    real = AtlasPca.method(:verify_pcactn)
    AtlasPca.define_singleton_method(:verify_pcactn) do |*a, **k|
      v = real.call(*a, **k)
      AtlasPca::Verdict.new(false, v.checks.merge(checks.to_h { |c| [c, false] }), reason)
    end
    yield
  ensure
    AtlasPca.define_singleton_method(:verify_pcactn, real)
  end

  def hook(calls, result = ADMISSION)
    lambda do |pcactn, grant, op|
      calls << [pcactn['counter'], grant['id'], op['verb']]
      raise 'coordinator down' if result == :raise

      result
    end
  end

  # (a) an escalate-class rule, no answer: the hook's admission runs the call now under a veto window
  def test_an_admission_replaces_the_escalation
    calls = []
    with_failing(['stub_rule'], 'stub_rule: intent_required: confirm the amount') do
      plain = az(provenance: ProvHarness::OPTION)
      assert_equal 'escalate', plain.decision
      r = az(provenance: ProvHarness::OPTION, undo: hook(calls))
      assert_equal [true, 'allow', 200], [r.allow, r.decision, r.status]
      assert_equal ADMISSION, r.undo
      assert_equal [AtlasPca.undo_window_obligation('op_1', NOW + 900_000)], r.obligations
      assert_equal %w[pass pass pass], [r.checks['stub_rule'], r.checks['undo_window'], r.checks['provenance_flow']]
      assert_includes r.reasons, "undo_window: runs now under a veto window until #{NOW + 900_000} (compensation payments.refund)"
      assert_equal [[STEP['pcactn']['counter'], GRANT['id'], 'payments.send']], calls
    end
  end

  # (b) a provenance_flow escalation is never undone into an allow
  def test_never_for_a_provenance_flow_escalation
    calls = []
    r = az(undo: hook(calls))
    assert_equal [false, 'escalate'], [r.allow, r.decision]
    with_failing(['stub_rule'], 'stub_rule: intent_required: q') do
      both = az(undo: hook(calls))
      assert_equal 'escalate', both.decision
    end
    assert_empty calls
  end

  # (c) nor for the rule-17 `provenance` check
  def test_never_for_a_rule_17_provenance_escalation
    calls = []
    with_failing(['provenance'], 'provenance: intent_required: q') do
      r = az(provenance: ProvHarness::OPTION, undo: hook(calls))
      assert_equal [false, 'escalate'], [r.allow, r.decision]
    end
    assert_empty calls
  end

  # (d) an escalation answer was presented: the answer path decides, the hook is not consulted
  def test_not_when_an_answer_is_presented
    calls = []
    with_failing(['stub_rule'], 'stub_rule: intent_required: q') do
      r = az(provenance: ProvHarness::OPTION, undo: hook(calls), escalation_principals: [PUB], escalation_answer: { 'junk' => 1 },
             insecure_unbound_approval: true)
      assert_equal [false, 'escalate'], [r.allow, r.decision]
    end
    assert_empty calls
  end

  # (e) a raising or malformed hook is no admission: the escalation stands
  def test_a_raising_or_malformed_hook_leaves_the_escalation
    with_failing(['stub_rule'], 'stub_rule: intent_required: q') do
      [:raise, nil, ADMISSION.merge('window_end' => -1), ADMISSION.merge('compensation' => {})].each do |res|
        calls = []
        r = az(provenance: ProvHarness::OPTION, undo: hook(calls, res))
        assert_equal [false, 'escalate', nil, nil], [r.allow, r.decision, r.undo, r.obligations], res.inspect
        assert_equal 1, calls.length
      end
    end
  end

  # (f) a deny is never upgraded
  def test_not_for_a_deny
    calls = []
    with_failing(%w[stub_rule leaf_signature], 'stub_rule: intent_required: q') do
      r = az(provenance: ProvHarness::OPTION, undo: hook(calls))
      assert_equal [false, 'deny'], [r.allow, r.decision]
    end
    assert_empty calls
  end
end

class TestProvenanceRack < Minitest::Test
  include ProvFlowFixtures

  def mw(**auth)
    AtlasPca::RackMiddleware.new(->(_e) { [200, {}, ['ok']] }, audience: AUD, resolve_grant: ->(_r) { GRANT }, now: NOW,
                                 authorize: { state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false },
                                              operation: ->(_e) { OP }, provenance: PIN_ONLY }.merge(auth))
  end

  def env(extra = {}, body = '')
    { 'HTTP_PCA_ACTION' => AtlasPca.b64e(AtlasPca.canon_bytes(STEP['pcactn'])), 'rack.input' => StringIO.new(body) }.merge(extra)
  end

  def test_reads_the_header_or_the_body_member
    assert_equal 200, mw.call(env({ 'HTTP_PCA_PROVENANCE' => ProvHarness.header(OP) }))[0]
    assert_equal 200, mw.call(env({}, JSON.generate({ 'pca_provenance' => ProvHarness.bundle(OP) })))[0]
  end

  def test_no_bundle_escalates_and_an_unreadable_header_denies
    status, _h, body = mw.call(env)
    b = JSON.parse(body.join)
    assert_equal [403, 'escalate', ['provenance_flow']], [status, b['decision'], b['failed_checks']]
    status, _h, body = mw.call(env({ 'HTTP_PCA_PROVENANCE' => 'not base64!' }))
    assert_equal [403, 'deny'], [status, JSON.parse(body.join)['decision']]
    assert_equal 403, mw.call(env({}, 'not json'))[0] # an unparsable body is no bundle
  end

  def test_the_undo_hook_is_wired_through
    seen = []
    real = AtlasPca.method(:verify_pcactn)
    AtlasPca.define_singleton_method(:verify_pcactn) do |*a, **k|
      v = real.call(*a, **k)
      AtlasPca::Verdict.new(false, v.checks.merge('stub_rule' => false), 'stub_rule: intent_required: q')
    end
    adm = { 'id' => 'op_9', 'window_end' => NOW + 60_000, 'compensation' => { 'verb' => 'payments.refund', 'resource' => 'payments/acme' } }
    m = mw(undo: ->(*) { seen << 1; adm })
    assert_equal 200, m.call(env({ 'HTTP_PCA_PROVENANCE' => ProvHarness.header(OP) }))[0]
    assert_equal [1], seen
  ensure
    AtlasPca.define_singleton_method(:verify_pcactn, real)
  end
end
