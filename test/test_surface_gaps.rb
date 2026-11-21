# frozen_string_literal: true

# Small public helpers of the reference that had no native twin: the in-process signer transport, the freeze predicate (fail closed), the intent
# session clock guard, the classifier attestation check and the intent extension tables.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestSurfaceGaps < Minitest::Test
  A = AtlasPca

  def test_the_in_process_transport_forwards_both_rounds_to_its_service
    svc = Struct.new(:identifier) do
      def round1(req) = [:r1, req]
      def round2(req) = [:r2, req]
    end.new(4)
    t = A::FrostNet.in_process_transport(svc)
    assert_equal 4, t.identifier
    assert_equal [:r1, { 'a' => 1 }], t.round1({ 'a' => 1 })
    assert_equal [:r2, {}], t.round2({})
  end

  def test_frozen_fails_closed
    set = { 'frozen' => %w[a b] }
    assert A.frozen?(set, 'a')
    refute A.frozen?(set, 'c')
    [nil, '', 5, ['a']].each { |agent| assert A.frozen?(set, agent), "agent #{agent.inspect}" }
    [nil, {}, { 'frozen' => 'a' }, [], 5].each { |bad| assert A.frozen?(bad, 'a'), "set #{bad.inspect}" }
  end

  def test_clock_is_a_safe_integer
    c = A::IntentArtifacts
    assert c.clock?(0)
    assert c.clock?(1_800_000_000_000)
    [1.5, '5', nil, 2**53, -0.0, Float::NAN].each { |v| refute c.clock?(v), v.inspect }
  end

  def test_a_classifier_verdict_that_is_not_an_object_is_refused_and_errors_fail_closed
    st = A::SemanticThreshold
    assert_equal({ 'ok' => false, 'reason' => 'verdict must be an object' }, st.verify_classifier_attestation(nil, nil))
    r = st.verify_classifier_attestation({ 'measurement' => 'm' }, 5)
    refute r['ok']
    assert_kind_of String, r['reason']
  end

  def test_the_intent_extension_tables
    assert_equal %w[fresh_at intent intent_session], A::INTENT_WIRE_EXTENSION.keys.sort
    assert_equal %w[freshAt intentBinding intentV2 wire], A::INTENT_EXTENSIONS.keys.sort
    assert_equal "'intent' must be an object", A::INTENT_WIRE_EXTENSION['intent'].call(nil)
    assert_equal [:absent, nil], A::INTENT_EXTENSIONS['intentBinding'].call(nil, {}, nil)
  end
end
