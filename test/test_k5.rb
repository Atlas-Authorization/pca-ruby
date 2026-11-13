# frozen_string_literal: true

# K5 workflow admission + read-side gates against the shared vectors (a missing file fails).
#   ruby -Ilib test/test_k5.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestK5 < Minitest::Test
  DIR = File.expand_path('../conformance', __dir__)
  W = AtlasPca.parse_json(File.read(File.join(DIR, 'workflow-vectors.json'), encoding: 'UTF-8'), loose: true)
  R = AtlasPca.parse_json(File.read(File.join(DIR, 'readside-vectors.json'), encoding: 'UTF-8'), loose: true)

  def adm(c)
    { 'workflow' => W['workflows'][c['workflow']], 'principal' => c['principal'], 'rs_signer' => c['rs_signer'], 'receipts' => c['receipts'],
      'now' => c['now'], 'request' => c['request'] }
  end

  def test_digests
    assert_equal W['digests']['workflow'], AtlasPca.workflow_digest(W['workflows']['main']['body'])
    W['digests']['values'].each { |v| assert_equal v['digest'], AtlasPca.wf_value_digest(v['value']) }
    assert_equal 4, W['digests']['receipt_refs'].length
    assert_equal R['digests']['grant'], AtlasPca.read_grant_digest(R['grants']['main']['body'])
  end

  def test_admit_and_bind
    assert_operator W['admit'].length, :>=, 10
    W['admit'].each { |c| assert_equal c['expect'], AtlasPca.admit_step(adm(c)), "admit: #{c['name']}" }
    W['bind'].each { |c| assert_equal c['expect'], AtlasPca.bind_promises(adm(c)), "bind: #{c['name']}" }
    W['plan_root'].each do |c|
      assert_equal c['expect'], AtlasPca.plan_root_authorized?(W['workflows'][c['workflow']], c['principal'], c['now'], c['root']), c['name']
    end
  end

  def test_every_code_exercised
    seen = (W['admit'] + W['bind']).map { |c| c['expect']['code'] }.compact
    %w[bad_workflow bad_dag bad_signature not_yet expired goal_mismatch plan_root_mismatch bad_receipt unplanned_step step_mismatch params_mismatch
       already_done budget_exceeded deps_unmet dep_failed stale_dep edge_missing edge_unit edge_digest edge_value edge_relation taint_flow
       pipeline_unconstrained taint_escalate].each { |code| assert_includes seen, code }
  end

  def test_never_raises
    [nil, 1, 'x', [], {}, { 'body' => nil }, { 'body' => {}, 'sig' => 1 }].each do |x|
      r = AtlasPca.admit_step({ 'workflow' => x, 'principal' => W['keys']['principal'], 'rs_signer' => W['keys']['rs'], 'receipts' => [], 'now' => 1, 'request' => x })
      assert_equal 'deny', r['decision']
    end
    assert_equal 'deny', AtlasPca.admit_step(nil)['decision']
    assert_equal 'deny', AtlasPca.admit_step({ 'workflow' => W['workflows']['main'], 'principal' => W['keys']['principal'], 'rs_signer' => W['keys']['rs'], 'receipts' => 'x', 'now' => 1, 'request' => {} })['decision']
    assert_equal 'deny', AtlasPca.redact_read(nil)['decision']
    assert_equal 'deny', AtlasPca.check_sink(nil)['decision']
  end

  def test_redact
    assert_operator R['redact'].length, :>=, 5
    R['redact'].each { |c| assert_equal c['expect'], AtlasPca.redact_read(c['input'].merge('grant' => R['grants'][c['grant']])), "redact: #{c['name']}" }
  end

  def test_masked_view_never_contains_dropped_value
    c = R['redact'].find { |x| x['name'] == 'support-view' }
    text = c['expect']['view'].to_s
    ['sk_live_x', '123-45-6789', 'dev-1', 'c_77', 'not in the schema'].each { |s| refute_includes text, s }
  end

  def test_sinks
    assert_operator R['sinks'].length, :>=, 5
    R['sinks'].each do |c|
      got = AtlasPca.check_sink({ 'grant' => R['grants'][c['grant']], 'principal' => c['principal'], 'rs_signer' => c['rs_signer'], 'now' => c['now'],
                                  'sink' => c['sink'], 'receipts' => c['receipts'] })
      assert_equal c['expect'], got, "sink: #{c['name']}"
    end
    two = R['sinks'].find { |s| s['name'] == 'chain-of-two-public-reads' }
    assert_equal R['digests']['chain_labels'], AtlasPca.read_chain_labels(two['receipts'], R['keys']['rs'], R['digests']['grant'], 1_800_000_000_000)
  end
end
