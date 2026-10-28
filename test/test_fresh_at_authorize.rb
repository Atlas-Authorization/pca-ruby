# frozen_string_literal: true

# `fresh_at:` through AtlasPca.authorize and the Rack middleware (shared vectors: fresh-at-vectors.json).
#   ruby -Ilib test/test_fresh_at_authorize.rb
require_relative '../lib/atlas_pca/rack_middleware'
require 'minitest/autorun'
require 'stringio'

class TestFreshAtAuthorize < Minitest::Test
  FILE = File.expand_path('../conformance/fresh-at-vectors.json', __dir__)
  VECTORS = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)['vectors']
  OP = { verb: 'write', resource: 'db/orders', params: {} }.freeze

  def vec(name) = VECTORS.find { |v| v['name'] == name }

  def authorize(v, policy, pcactn = v['pcactn'])
    AtlasPca.authorize(pcactn, operation: OP, audience: v['context']['aud'], resolve_grant: ->(_) { v['grant'] },
                               state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false },
                               now: v['context']['now'], plan: 'single-step', fresh_at: policy)
  end

  def test_ok
    v = vec('member-equal-state')
    r = authorize(v, v['context']['fresh_at'])
    assert_equal 'pass', r.checks['fresh_at'], r.reason
  end

  def test_stale_escalates
    v = vec('member-stale-revocation_epoch')
    r = authorize(v, v['context']['fresh_at'])
    refute r.allow
    assert_equal 'fail', r.checks['fresh_at']
    # the shared vectors carry no envelope / params, so other authorize checks also fail: the escalate class is the core's
    assert_equal 'escalate', AtlasPca.decision_of({ 'allow' => false, 'reasons' => r.verdict.reasons,
                                                    'checks' => r.verdict.checks.transform_values { |ok| ok ? 'pass' : 'fail' } })
    assert_match(/stale_state/, r.reasons.join)
  end

  def test_member_without_policy_is_refused
    v = vec('member-without-policy')
    r = authorize(v, nil)
    refute r.allow
    assert_equal 'fail', r.checks['fresh_at']
  end

  def test_default_nil_without_member_is_unchanged
    v = vec('no-member-no-policy')
    assert_nil authorize(v, nil).checks['fresh_at']
  end

  def rack(v, policy, header)
    mw = AtlasPca::RackMiddleware.new(->(_e) { [200, {}, ['ok']] }, audience: v['context']['aud'],
                                      resolve_grant: ->(_) { v['grant'] }, now: v['context']['now'], fresh_at: policy,
                                      signature_only: true)
    env = { 'HTTP_PCA_ACTION' => AtlasPca.b64e(AtlasPca.canon_bytes(v['pcactn'])), 'rack.input' => StringIO.new('') }
    env['HTTP_PCA_FRESH_AT'] = header unless header.nil?
    mw.call(env)
  end

  def test_rack_side_carried_header
    v = vec('side-carried-ok')
    policy = v['context']['fresh_at'].reject { |k, _| k == 'side_carried' }
    token = AtlasPca.b64e(AtlasPca.canon_bytes(v['context']['fresh_at']['side_carried']))
    s, = rack(v, policy, token)
    assert_equal 200, s
    s, _h, body = rack(v, policy.merge('require' => true), nil)
    assert_equal 403, s
    assert_includes body.join, 'fresh_at'
    s, _h, body = rack(v, policy, '!!not-base64!!')
    assert_equal 403, s
    assert_includes body.join, 'fresh_at'
  end
end
