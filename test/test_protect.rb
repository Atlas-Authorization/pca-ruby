# frozen_string_literal: true

# AtlasPca.protect (one-call secure defaults), AtlasPca.explain_refusal and the `doc` member of Rack refusal bodies.
#   ruby -Ilib test/test_protect.rb
require_relative '../lib/atlas_pca/rack_middleware'
require 'minitest/autorun'
require 'json'

class TestProtect < Minitest::Test
  FIX = AtlasPca.parse_json(File.read(File.expand_path('../test-data/authorize-fixtures.json', __dir__), encoding: 'UTF-8'),
                            loose: true)
  REFUSALS = 'https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md'
  APP = ->(_env) { [200, { 'content-type' => 'text/plain' }, ['ok']] }

  def kase = FIX['cases'].find { |x| x['name'] == 'envelope-max-spend-within' }
  def step = kase['steps'][0]
  def env_for(pcactn) = { 'HTTP_PCA_ACTION' => AtlasPca.b64e(AtlasPca.canon_bytes(pcactn)) }
  def fresh(obj) = Marshal.load(Marshal.dump(obj))
  def body_of(resp) = JSON.parse(resp[2].join)

  def protect(**o)
    AtlasPca.protect(audience: FIX['audience'], grants: [kase['grant']], operation: ->(_env) { step['operation'] },
                     now: FIX['now'], **o)
  end

  def mw(p) = AtlasPca::RackMiddleware.new(APP, **p.options)

  def test_allows_a_valid_proof_and_refuses_its_replay_with_a_doc
    m = mw(protect)
    assert_equal 200, m.call(env_for(fresh(step['pcactn'])))[0]
    r = m.call(env_for(fresh(step['pcactn'])))
    assert_equal 403, r[0]
    assert_equal "#{REFUSALS}#replay", body_of(r)['doc']
    assert_equal %w[error error_description failed_checks decision doc], body_of(r).keys
  end

  def test_revoke_refuses_every_further_action_under_the_grant
    p = protect
    m = mw(p)
    p.revoke(kase['grant']['id'])
    r = m.call(env_for(fresh(step['pcactn'])))
    assert_equal 403, r[0]
    assert_includes body_of(r)['failed_checks'], 'revocation'
    assert_equal "#{REFUSALS}#revocation", body_of(r)['doc']
  end

  def test_an_extra_revocation_source_is_consulted_too
    seen = []
    m = mw(protect(is_revoked: ->(_pcactn, grant) { seen << grant['id']; true }))
    assert_equal 403, m.call(env_for(fresh(step['pcactn'])))[0]
    assert_equal [kase['grant']['id']], seen
  end

  def test_the_grant_comes_from_the_servers_list_never_the_request
    m = AtlasPca::RackMiddleware.new(APP, **AtlasPca.protect(audience: FIX['audience'], grants: [], operation: ->(_e) { step['operation'] }, now: FIX['now']).options)
    r = m.call(env_for(fresh(step['pcactn'])))
    assert_equal 401, r[0]
    assert_equal "#{REFUSALS}#grant_ref", body_of(r)['doc']
  end

  def test_grants_may_be_a_callable
    p = AtlasPca.protect(audience: FIX['audience'], grants: ->(ref) { ref == kase['grant']['id'] ? kase['grant'] : nil },
                         operation: ->(_e) { step['operation'] }, now: FIX['now'])
    assert_equal 200, mw(p).call(env_for(fresh(step['pcactn'])))[0]
  end

  def test_secure_defaults_and_caller_options_win
    o = protect.options
    assert_kind_of AtlasPca::MemoryStateStore, o[:authorize][:state_store]
    assert_equal 'single-step', o[:authorize][:plan]
    assert_equal FIX['now'], o[:now]
    mine = AtlasPca::MemoryStateStore.new
    o = protect(state_store: mine, plan: nil).options
    assert_same mine, o[:authorize][:state_store]
    assert_nil o[:authorize][:plan]
    assert_same mine, protect(authorize: { 'state_store' => mine }).options[:authorize][:state_store]
  end

  def test_a_wrong_operation_is_refused
    p = AtlasPca.protect(audience: FIX['audience'], grants: [kase['grant']], now: FIX['now'],
                         operation: ->(_e) { { verb: 'payments.send', resource: 'payments/other', params: step['operation']['params'] } })
    r = mw(p).call(env_for(fresh(step['pcactn'])))
    assert_equal 403, r[0]
    assert_equal "#{REFUSALS}#operation", body_of(r)['doc']
  end

  def test_bad_arguments_raise
    ok = ->(_e) {}
    assert_raises(ArgumentError) { AtlasPca.protect(audience: 'a', grants: 5, operation: ok) }
    assert_raises(ArgumentError) { AtlasPca.protect(audience: 'a', grants: [{}], operation: ok) }
    assert_raises(ArgumentError) { AtlasPca.protect(audience: 'a', grants: [], operation: 5) }
    assert_raises(ArgumentError) { AtlasPca.protect(audience: 'a', grants: [], operation: ok, is_revoked: 5) }
    assert_raises(ArgumentError) { AtlasPca.protect(grants: [], operation: ok) }
  end

  def test_a_non_refusal_response_has_no_doc
    m = mw(protect)
    assert_equal 'ok', m.call(env_for(fresh(step['pcactn'])))[2].join
  end

  def test_explain_refusal_by_leading_check
    h = AtlasPca.explain_refusal('replay: 1 is not greater than last seen 1 (replay)')
    assert_equal 'replay', h.check
    assert_equal 'This proof (or an older counter) was already used.', h.meaning
    assert_equal "#{REFUSALS}#replay", h.docs
    assert_equal 'The proof was signed for a different server.', AtlasPca.explain_refusal('audience: audience mismatch').meaning
    assert_equal 'authorize_config', AtlasPca.explain_refusal('authorize_config: missing required component(s): state_store (fail closed)').check
    assert_equal 'threshold', AtlasPca.explain_refusal('threshold: needs a co-signature').check
    assert_equal "#{AtlasPca::PCA_DOCS}/concepts/threshold-and-step-up.md", AtlasPca.explain_refusal('threshold: x').docs
  end

  def test_explain_refusal_finds_a_check_named_inside_the_reason
    assert_equal 'policy', AtlasPca.explain_refusal('Denied. policy: nope').check
  end

  def test_explain_refusal_never_raises_and_has_a_generic_entry
    [nil, 5, '', 'nonsense', :sym, [], { 'a' => 1 }].each do |bad|
      h = AtlasPca.explain_refusal(bad)
      assert_equal 'unknown', h.check
      assert_equal REFUSALS, h.docs
    end
  end

  def test_every_table_row_is_explained_and_frozen
    assert_predicate AtlasPca::REFUSAL_TABLE, :frozen?
    assert_equal 22, AtlasPca::REFUSAL_TABLE.length
    AtlasPca::REFUSAL_TABLE.each { |row| assert_equal row[0], AtlasPca.explain_refusal("#{row[0]}: x").check }
  end

  def test_refusal_doc
    assert_equal "#{REFUSALS}#chain", AtlasPca.refusal_doc('chain: bad')
    assert_equal REFUSALS, AtlasPca.refusal_doc('no PCActn presented')
  end
end
