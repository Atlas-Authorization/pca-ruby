# frozen_string_literal: true

# Workflow admission inside AtlasPca.authorize (C-308): replays packages/pca/conformance/authorize-workflow-fixtures.json
# (a missing file fails). One replay store per case; the plan is principal-authorized.
#   ruby -Ilib test/test_authorize_workflow.rb
require_relative '../lib/atlas_pca/rack_middleware'
require_relative 'support/prov_harness'
require 'minitest/autorun'

class TestAuthorizeWorkflow < Minitest::Test
  F = AtlasPca.parse_json(File.read(File.expand_path('../conformance/authorize-workflow-fixtures.json', __dir__), encoding: 'UTF-8'), loose: true)

  def test_format
    assert_equal 'pca-authorize-workflow-fixtures/1', F['format']
    assert_operator F['cases'].length, :>=, 14
  end

  F['cases'].each do |c|
    define_method("test_#{c['name']}") do
      store = AtlasPca::MemoryStateStore.new
      c['steps'].each_with_index do |s, i|
        w = s['workflow']
        r = AtlasPca.authorize(s['pcactn'], operation: s['operation'], audience: F['audience'], resolve_grant: ->(ref) { ref == F['grant']['id'] ? F['grant'] : nil },
                                            state_store: store, is_revoked: ->(_p, _g) { false }, now: F['now'], context: ->(_p) { { 'plan' => F['plan'], 'plan_authorized' => true } },
                                            workflow: { 'principal' => F['principal'], 'rs_signer' => F['rs_signer'], 'required' => c['required'] },
                                            workflow_call: w && { 'commitment' => w['commitment'], 'receipts' => w['receipts'], 'step' => w['step'], 'units' => w['units'], 'goal_digest' => w['goal_digest'] },
                                            provenance: ProvHarness::OPTION)
        e = s['expect']
        assert_equal({ 'allow' => e['allow'], 'decision' => e['decision'], 'status' => e['status'], 'failed' => e['failed'] },
                     { 'allow' => r.allow, 'decision' => r.decision, 'status' => r.status, 'failed' => r.failed_checks }, "#{c['name']} step #{i}")
        assert_includes(r.allow ? '' : r.reason.to_s, e['reason'], "#{c['name']} step #{i} reason") if e.key?('reason')
      end
    end
  end

  def test_no_option_changes_nothing
    c = F['cases'].find { |x| x['name'] == 'workflow-optional-and-absent' }
    s = c['steps'][0]
    r = AtlasPca.authorize(s['pcactn'], operation: s['operation'], audience: F['audience'], resolve_grant: ->(ref) { ref == F['grant']['id'] ? F['grant'] : nil },
                                        state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false }, now: F['now'],
                                        context: ->(_p) { { 'plan' => F['plan'], 'plan_authorized' => true } }, provenance: ProvHarness::OPTION)
    assert r.allow
  end
end
