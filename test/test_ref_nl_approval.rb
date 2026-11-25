# frozen_string_literal: true

# Replays the TS-reference oracle of the approval half of natural-language policy authoring (test-data/ref-nl-approval.json.gz, 206 cases): the catalog
# digest, the draft binding and digests, the model's linted policy, the content-addressed draft, a reviewer's v2 and legacy v1 approval (byte for byte:
# Ed25519 is deterministic), loading an approved draft (every rejection code compared exactly) and building an agent from it (only the deterministic
# members of the grant's envelope are compared: the goal commitment carries a random salt). Every fn has a handler and the totals are asserted.
# Encodings: {"$num": ...} a non-finite number; {"$bytes": {"$seed": label}} the 32-byte Ed25519 secret; `extras` null is the default catalog, else
# action specs appended to the built-ins; a completion "THROWS" is a model that fails.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefNlApproval < Minitest::Test
  A = AtlasPca
  NA = AtlasPca::NlApproval
  BY_FN = Ref.load('nl-approval')
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  def self.cat(extras)
    return nil if extras.nil?

    A::BUILTIN_ACTIONS + extras.map { |e| e.merge('verb' => "#{e['connector']}.#{e['action']}") }
  end

  def self.completion(raw) = ->(_prompt) { raw == 'THROWS' ? raise('llm down') : raw }
  def self.kp(seed) = A::KeyPair.new(Digest::SHA256.digest("atlas-pca-conformance/#{seed}"))

  def self.load_opts(opts)
    o = opts.reject { |k, _| k == 'extras' }
    o['catalog'] = cat(opts['extras']) if opts['extras']
    o
  end

  def self.agent_from_approved(a)
    o = load_opts(a['opts'])
    req = o.merge('draft' => a['draft'], 'approval' => a['approval'], 'principal' => kp(a['principalSeed']), 'goal' => a['goal'])
    req['aud'] = a['aud'] if a.key?('aud')
    req['holder'] = kp(a['holderSeed']) if a['holderSeed']
    out = NA.agent_from_approved_nl(req)
    env = A.read_envelope(out['agent'].grant)
    { 'reviewer' => out['reviewer'], 'legacy_unbound_instruction' => out['legacy_unbound_instruction'],
      'envelope' => { 'predicates' => env['predicates'], 'caveats' => env['caveats'], 'risk_policy' => env['risk_policy'], 'agent_binding' => env['agent_binding'] } }
  end

  HANDLERS = {
    'constants' => -> { { 'NL_APPROVAL_DOMAIN' => NA::NL_APPROVAL_DOMAIN, 'NL_APPROVAL_DOMAIN_V2' => NA::NL_APPROVAL_DOMAIN_V2, 'MAX_NL_OUTPUT_BYTES' => NA::MAX_NL_OUTPUT_BYTES, 'MAX_NL_APPROVAL_TTL_MS' => NA::MAX_NL_APPROVAL_TTL_MS } },
    'catalogDigest' => ->(extras) { NA.catalog_digest(cat(extras)) },
    'draftBinding' => ->(ins, extras, model) { NA.draft_binding(ins, cat(extras), model) },
    'draftDigestV2' => ->(perms, limits, cd, binding) { NA.draft_digest_v2(perms, limits, cd, binding) },
    'draftDigest' => ->(perms, limits, cd) { NA.draft_digest(perms, limits, cd) },
    'policyFromNL' => ->(ins, raw, extras, _model) { NA.policy_from_nl(ins, completion(raw), cat(extras)) },
    'draftPolicyFromNL' => ->(ins, raw, extras, model) { NA.draft_policy_from_nl(ins, completion(raw), cat(extras), model) },
    'approveDraft' => ->(draft, secret, opts) { NA.approve_draft(draft, A::KeyPair.new(secret), opts) },
    'approveDraftLegacy' => ->(draft, secret, opts) { NA.approve_draft_legacy_v1(draft, A::KeyPair.new(secret), opts) },
    'loadApproved' => ->(draft, approval, opts) { NA.load_approved_policy(draft, approval, load_opts(opts)) },
    'agentFromApproved' => ->(a) { agent_from_approved(a) }
  }.freeze

  TOTALS = { 'constants' => 1, 'catalogDigest' => 3, 'draftBinding' => 6, 'draftDigestV2' => 10, 'draftDigest' => 7, 'policyFromNL' => 40, 'draftPolicyFromNL' => 42,
             'approveDraft' => 24, 'approveDraftLegacy' => 5, 'loadApproved' => 58, 'agentFromApproved' => 10 }.freeze

  def test_every_fn_of_the_corpus_has_a_handler_and_the_totals_are_pinned
    assert_equal TOTALS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 206, BY_FN.values.sum(&:length)
    assert_empty BY_FN.keys - HANDLERS.keys
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      k = self.class
      Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| k.dnum(a) }) })
    end
  end
end
