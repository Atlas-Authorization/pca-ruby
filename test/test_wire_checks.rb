# frozen_string_literal: true

# validate_wire_v2 reasons, the strict number check and the small canonical / base64url / threshold helpers.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestWireChecks < Minitest::Test
  A = AtlasPca

  def pcactn
    @pcactn ||= begin
      ag = A.create_agent(principal: A::KeyPair.new("\x01".b * 32), goal: 'g', permissions: { 'stripe' => ['refund'] }, limits: { 'refund' => '$500/day' }, aud: 'rs', now: 1_000_000)
      ag.act('stripe.refund', 'charge:ch_1', { 'amount' => 10 }, counter: 1, now: 1_000_001)['pcactn']
    end
  end

  def mutate
    p = Marshal.load(Marshal.dump(pcactn))
    yield p
    A.validate_wire_v2(p)
  end

  def test_a_signed_pcactn_is_well_formed
    assert_nil A.validate_wire_v2(pcactn)
  end

  def test_refusal_reasons
    assert_equal 'PCActn is not an object', A.validate_wire_v2([])
    assert_equal "unknown field 'zz'", mutate { |p| p['zz'] = 1 }
    assert_equal "missing field 'aud'", mutate { |p| p.delete('aud') }
    assert_equal "'ver' must be a safe integer", mutate { |p| p['ver'] = '2' }
    assert_equal "'counter' must be a safe integer", mutate { |p| p['counter'] = 1.5 }
    assert_equal "'aud' must be a non-empty string (<= 256 UTF-8 bytes)", mutate { |p| p['aud'] = '' }
    assert_equal "'nonce' must be a non-empty string (<= 128 UTF-8 bytes)", mutate { |p| p['nonce'] = 'x' * 129 }
    assert_equal "'grant_ref' is not canonical base64url (32 bytes)", mutate { |p| p['grant_ref'] = 'AA' }
    assert_equal "unknown field 'action.x'", mutate { |p| p['action']['x'] = 1 }
    assert_equal "'plan.node_id' must be a string", mutate { |p| p['plan']['node_id'] = 1 }
    assert_equal "unknown field 'plan.inclusion_proof.q'", mutate { |p| p['plan']['inclusion_proof']['q'] = 1 }
    assert_equal "cap_chain[0] must be an object", mutate { |p| p['cap_chain'][0] = 1 }
    assert_equal "unknown field 'cap_chain[0].zz'", mutate { |p| p['cap_chain'][0]['zz'] = 1 }
    assert_equal "cap_chain[0].caveats must be an array of {type,...} objects", mutate { |p| p['cap_chain'][0]['caveats'] = [1] }
    assert_equal "'attestation' must be an object with an integer 'epoch'", mutate { |p| p['attestation'] = {} }
    assert_equal "'provenance' is malformed", mutate { |p| p['provenance']['taint_level'] = 'x' }
    assert_equal "'freshness' is malformed", mutate { |p| p['freshness'] = [] }
    assert_equal "'risk_claim' is malformed", mutate { |p| p['risk_claim']['inputs'] = 1 }
    assert_equal "'caution' must be a number in [0,1]", mutate { |p| p['caution'] = 2 }
    assert_equal "'threshold' must be {shares:[...]}", mutate { |p| p['threshold'] = 1 }
    assert_match(/Intent Layer extension field/, mutate { |p| p['intent'] = {} })
    assert_match(/consistency-token extension field/, mutate { |p| p['fresh_at'] = {} })
  end

  def test_extensions_validate_their_slots
    p = Marshal.load(Marshal.dump(pcactn))
    p['intent'] = { 'a' => 1 }
    assert_nil A.validate_wire_v2(p, { 'intent' => ->(_) {} })
    assert_equal 'bad intent', A.validate_wire_v2(p, { 'intent' => ->(_) { 'bad intent' } })
  end

  def test_strict_number_error
    assert_nil A.strict_number_error(1)
    assert_nil A.strict_number_error(0.5)
    assert_nil A.strict_number_error(2.0**53 - 1)
    assert_equal 'non-finite number', A.strict_number_error(Float::NAN)
    assert_equal 'non-finite number', A.strict_number_error(Float::INFINITY)
    assert_equal 'negative zero', A.strict_number_error(-0.0)
    assert_match(/outside the safe range/, A.strict_number_error(2**53))
    assert_match(/below 1e-6/, A.strict_number_error(1e-7))
    assert_match(/more than 15 significant digits/, A.strict_number_error(0.1234567890123456))
  end

  def test_helpers
    assert A.artifact_too_large?('a' * (A::MAX_ARTIFACT_BYTES + 1))
    refute A.artifact_too_large?('a' * A::MAX_ARTIFACT_BYTES)
    assert_equal A.canon_bytes({ 'b' => 1, 'a' => 2 }), A.canonical_bytes_strict({ 'b' => 1, 'a' => 2 })
    assert_equal '{"a":2,"b":1}', A.canonicalize_lenient_server_only({ 'b' => 1, 'a' => 2 })
    assert_equal A.b64e('hi'), A.encode_sig('hi')
    assert_equal 'hi', A.decode_sig(A.encode_sig('hi'))
    assert_raises(ArgumentError) { A.decode_sig('AB==') }
    assert_nil A.decode_b64u_strict('AB==')
    assert_equal({ 'shares' => [1] }, A.assemble_threshold([1]))
    assert_equal({ 'shares' => [] }, A.assemble_threshold(nil))
    src = [1]
    refute_same src, A.assemble_threshold(src)['shares']
    assert_same A::Malformed, A::StrictJsonError
  end
end
