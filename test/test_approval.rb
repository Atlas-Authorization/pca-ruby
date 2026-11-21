# frozen_string_literal: true

# K7: pinned values and the request member. The shared vectors (test_actions_vectors.rb) cover the rest.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestApproval < Minitest::Test
  ZERO = AtlasPca.b64e("\x00".b * 32)

  def test_challenge_and_words
    c = AtlasPca.approval_challenge(ZERO, ZERO)
    assert_equal 43, c.length
    refute_equal c, AtlasPca.approval_challenge(ZERO, AtlasPca.b64e(("\x00".b * 31) + "\x01".b))
    assert_raises(ArgumentError) { AtlasPca.approval_challenge('AAAA', ZERO) }
    assert_equal 'able-able-able-able-able-able', AtlasPca.binding_words(ZERO)
    assert_equal 256, AtlasPca::BINDING_WORDS.uniq.length
  end

  def test_shape_refuses_an_incomplete_render
    refute_nil AtlasPca.approval_render_shape_error({ 'v' => 1 })
    assert_raises(ArgumentError) { AtlasPca.approval_render_digest({ 'v' => 1 }) }
  end

  def test_request_carries_the_render_digest_only_when_given
    grant = { 'id' => 'g' }
    p = { 'action' => { 'verb' => 'v', 'resource' => 'r' } }
    with = AtlasPca.build_escalation_request(aud: 'a', grant: grant, pcactn: p, last_counter: nil, reasons: ['x'], now: 1, render_digest: 'RD')
    assert_equal 'RD', with['render_digest']
    refute AtlasPca.build_escalation_request(aud: 'a', grant: grant, pcactn: p, last_counter: nil, reasons: ['x'], now: 1).key?('render_digest')
  end
end

class TestUnboundApproval < Minitest::Test
  def test_default_refuses_and_opt_out_documented
    src = File.read(File.expand_path('../lib/atlas_pca/authorize.rb', __dir__))
    assert_includes src, 'if !insecure_unbound_approval && render_digest.nil?'
  end
end
