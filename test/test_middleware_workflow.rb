# frozen_string_literal: true

# RackMiddleware `workflow:` (C-308) over cases of authorize-workflow-fixtures.json: step supplied via the JSON body member
# `workflow` or the `workflow_step:` callback; valid passes, an edge violation is a 403, required-and-absent is a 403,
# no option is unchanged, and an undecodable PCActn is the pipeline's 401.
#   ruby -Ilib test/test_middleware_workflow.rb
require_relative '../lib/atlas_pca/rack_middleware'
require 'minitest/autorun'
require 'json'
require 'stringio'

class TestMiddlewareWorkflow < Minitest::Test
  F = AtlasPca.parse_json(File.read(File.expand_path('../conformance/authorize-workflow-fixtures.json', __dir__), encoding: 'UTF-8'), loose: true)

  def kase(name) = F['cases'].find { |c| c['name'] == name } || flunk("fixture #{name} missing")

  def build(step_s, wf: { 'principal' => F['principal'], 'rs_signer' => F['rs_signer'] }, **kw)
    mw_wf = wf.nil? ? {} : { workflow: wf }
    AtlasPca::RackMiddleware.new(->(_e) { [200, {}, ['ok']] }, audience: F['audience'], now: F['now'],
                                 resolve_grant: ->(r) { r == F['grant']['id'] ? F['grant'] : nil },
                                 authorize: { state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false },
                                              operation: ->(_e) { step_s['operation'] },
                                              context: ->(_p) { { 'plan' => F['plan'], 'plan_authorized' => true } } },
                                 **mw_wf, **kw)
  end

  def body_env(step_s, with_wf: true)
    h = { 'pcactn' => step_s['pcactn'] }
    h['workflow'] = step_s['workflow'] if with_wf && step_s['workflow']
    { 'rack.input' => StringIO.new(JSON.generate(h)) }
  end

  def reason(r) = JSON.parse(r[2].join)['error_description']

  def test_valid_step_in_body_passes
    s = kase('pay-after-quote')['steps'][0]
    assert_equal 200, build(s).call(body_env(s))[0]
  end

  def test_valid_step_from_callback_passes
    s = kase('pay-after-quote')['steps'][0]
    assert_equal 200, build(s, workflow_step: ->(_e) { s['workflow'] }).call(body_env(s, with_wf: false))[0]
  end

  def test_edge_violation_is_403
    s = kase('amount-over-the-quote')['steps'][0]
    r = build(s).call(body_env(s))
    assert_equal 403, r[0]
    assert_equal 'workflow: edge_relation (step pay)', reason(r)
    assert_equal ['workflow'], JSON.parse(r[2].join)['failed_checks']
  end

  def test_required_and_absent_is_403
    s = kase('workflow-required-but-absent')['steps'][0]
    r = build(s, wf: { 'principal' => F['principal'], 'rs_signer' => F['rs_signer'], 'required' => true }).call(body_env(s))
    assert_equal 403, r[0]
    assert_equal 'workflow: this call carries no workflow step (fail closed)', reason(r)
  end

  def test_required_and_absent_precedes_an_undecodable_pcactn
    s = kase('workflow-required-but-absent')['steps'][0]
    r = build(s, wf: { 'principal' => F['principal'], 'rs_signer' => F['rs_signer'], 'required' => true })
        .call('rack.input' => StringIO.new('{"pcactn":{"bad":1}}'))
    assert_equal 403, r[0]
  end

  def test_undecodable_pcactn_with_a_step_is_the_pipeline_401
    s = kase('pay-after-quote')['steps'][0]
    r = build(s).call('rack.input' => StringIO.new(JSON.generate('pcactn' => 'not-a-pcactn', 'workflow' => s['workflow'])))
    assert_equal 401, r[0]
  end

  def test_no_option_is_unchanged
    s = kase('workflow-optional-and-absent')['steps'][0]
    assert_equal 200, build(s, wf: nil).call(body_env(s))[0]
    s2 = kase('pay-after-quote')['steps'][0]
    assert_equal 200, build(s2, wf: nil).call(body_env(s2))[0] # a body `workflow` member is ignored without the option
  end

  def test_bad_option_raises_at_construction
    s = kase('pay-after-quote')['steps'][0]
    assert_raises(ArgumentError) { build(s, wf: 'x') }
  end
end
