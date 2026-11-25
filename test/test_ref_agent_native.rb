# frozen_string_literal: true

# Replays the TS-reference oracle of the agent-native surface (test-data/ref-agent-native.json.gz, 1632 cases): caution attestation,
# rationale binding, the tool-schema firewall, envelope introspection and the authority lease. Every fn of the corpus must have a
# handler (an unhandled fn fails the test). Encodings: {"$num": "NaN" | "Infinity" | "-Infinity"} in args; {"$bytes": {"$seed":
# label}} is the 32-byte Ed25519 secret sha256("atlas-pca-conformance/" + label) (the loader turns the seed label into those bytes);
# an out of {"$throws": ...} must be a native raise (the message is not compared); every other reason string is compared exactly.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/agent_native'
require 'minitest/autorun'

class TestRefAgentNative < Minitest::Test
  AN = AtlasPca::AgentNative
  BY_FN = Ref.load('agent-native')

  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze

  # {"$num": ...} -> the non-finite Float (anywhere in the arguments)
  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  def self.key(secret) = AtlasPca::KeyPair.new(secret)

  def self.pad(a, n) = a + ([nil] * [n - a.length, 0].max)

  def self.judge(spec)
    case spec
    when 'true' then ->(_r, _a) { true }
    when 'false' then ->(_r, _a) { false }
    when 'throw' then ->(_r, _a) { raise 'judge' }
    when 'truthy' then ->(_r, _a) { 'yes' }
    when /\Acontains:(.*)\z/m then ->(r, _a) { r.include?(Regexp.last_match(1)) }
    when /\Aaction-verb:(.*)\z/m
      want = Regexp.last_match(1)
      lambda do |_r, a|
        raise TypeError, 'action is null' if a.nil?

        a.is_a?(Hash) && a['verb'] == want
      end
    else raise "unknown judge spec #{spec}"
    end
  end

  def self.constants_hash
    names = %w[CAVEAT_ENVELOPE CAVEAT_EXPIRES CAVEAT_NOT_BEFORE CAVEAT_RATE CAVEAT_MAX_BLAST_RADIUS CAVEAT_REVERSIBILITY_MAX
               CAVEAT_DELEGATION_DEPTH CAVEAT_PREDICATES CAVEAT_TOOL_SCHEMA CAVEAT_MAX_SPEND MAX_CAUTION_REASON_LEN MIN_SALT_BYTES
               MIN_SALT_DISTINCT_BYTES MAX_RATIONALE_LEN MAX_SCHEMA_DEPTH MAX_SCHEMA_NODES MAX_OBJECT_PROPS MAX_ENUM_VALUES
               DEFAULT_MAX_ARRAY_ITEMS ABSOLUTE_MAX_ARRAY_ITEMS DEFAULT_MAX_STRING_LEN ABSOLUTE_MAX_STRING_LEN MAX_VALUE_NODES
               HEARTBEAT_SKEW_MS MAX_LEASE_TTL_MS]
    names.to_h { |n| [n, AN.const_get(n)] }
  end

  HANDLERS = {
    'signCaution' => ->(body, secret) { AN.sign_caution(body, key(secret)) },
    'verifyCaution' => ->(*a) { AN.verify_caution(*pad(a, 3)) },
    'combineCaution' => ->(*a) { AN.combine_caution(*a) },
    'combineSignedCaution' => ->(*a) { AN.combine_signed_caution(*pad(a, 4)) },
    'checkCautionMonotone' => ->(grid) { AN.check_caution_monotone(grid) },
    'isStrongSalt' => ->(s) { AN.strong_salt?(s) },
    'bindRationale' => ->(*a) { AN.bind_rationale(*a) },
    'verifyRationale' => ->(*a) { AN.verify_rationale(*a) }, # 2 args = no action; a given null is hashed as null
    'auditRationale' => ->(c, a, r, j) { AN.audit_rationale(c, a, r, judge(j)) },
    'validateArgSchema' => ->(s) { AN.validate_arg_schema(s) },
    'toolSchemaCaveat' => ->(sig, schema) { AN.tool_schema_caveat(sig, schema) },
    'evaluateToolSchema' => ->(c, call) { AN.evaluate_tool_schema(c, call) },
    'toolSchemaEvaluator' => ->(c, ctx) { AN.tool_schema_evaluator(c, ctx) },
    'predicatesCaveat' => ->(allow) { AN.predicates_caveat(allow) },
    'actionSpendUsd' => ->(a) { AN.action_spend_usd(a) },
    'agentNativeCaveatEvaluator' => ->(c, ctx) { AN.agent_native_caveat_evaluator(c, ctx) },
    'describeEnvelope' => ->(*a) { AN.describe_envelope(*pad(a, 4)) },
    'envelopePermits' => ->(*a) { AN.envelope_permits?(*pad(a, 5)) },
    'envelopePermitsToolCall' => ->(env, call) { AN.envelope_permits_tool_call(env, call) },
    'grantLease' => ->(args) { AN.grant_lease(args) },
    'leaseState' => ->(lease, now) { AN.lease_state(lease, now) },
    'signHeartbeat' => ->(body, secret) { AN.sign_heartbeat(body, key(secret)) },
    'renewLease' => ->(lease, hb, now) { AN.renew_capability_lease(lease, hb, now) },
    'constants' => -> { constants_hash }
  }.freeze

  def test_every_fn_of_the_corpus_has_a_handler
    assert_empty BY_FN.keys - HANDLERS.keys
    assert_empty HANDLERS.keys - BY_FN.keys
    assert_equal 1632, BY_FN.values.sum(&:length)
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      cases = BY_FN.fetch(fn)
      Ref.run(self, cases, ->(*args) { handler.call(*args.map { |a| self.class.dnum(a) }) })
    end
  end
end
