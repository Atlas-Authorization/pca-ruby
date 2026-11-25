# frozen_string_literal: true

# Replays the TS-reference oracle of the signed measurement allowlists and their transparency anchor (test-data/ref-attest-allowlist.json.gz,
# 959 cases): verify (every suite, every refusal code and its precedence, the option checks, the strict body and entry shapes, 700 structural
# variants of a signed manifest), the durable high-water mark (op scripts against one in-memory store), create / sign (byte for byte: signing is
# deterministic) / revoke, the driver-version slot, projection and the five policy-field functions, the anchor commit, the operator log (op
# scripts) and verify_allowlist_anchored over the committed anchor conformance vectors. A refusal compares by its code, not its reason text; an
# operator step the reference refuses is {"$throws"} in the result list (compared by presence). Every fn has a handler and the totals are
# asserted. Encodings: {"$num": ...} a non-finite number; the secrets of a key spec / the log guardian are {"$seed": label} members. Cases that
# sign or verify with ML-DSA or SLH-DSA need a runtime that has them (OpenSSL >= 3.5).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefAttestAllowlist < Minitest::Test
  A = AtlasPca
  L = AtlasPca::AttestAllowlist
  N = AtlasPca::AttestAllowlistAnchor
  BY_FN = Ref.load('attest-allowlist')
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze
  PQ = A.supported_suites.include?('ml-dsa-65')

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  # An in-memory durable store (the DurableState contract): values are JSON round-tripped.
  class MemKv
    def initialize = @m = {}
    def get(key) = @m.key?(key) ? JSON.parse(@m[key]) : nil
    def set(key, value) = @m[key] = JSON.generate(value)
    def keys = @m.keys.sort

    def update(key)
      nxt = yield(get(key))
      @m[key] = JSON.generate(nxt) unless nxt.nil?
      get(key)
    end

    def snapshot = @m.transform_values { |v| JSON.parse(v) }
  end

  def self.durable(c)
    kv = MemKv.new
    (c['initial'] || {}).each { |k, v| kv.set(k, v) }
    results = c['steps'].map { |s| L.verify_allowlist_durable(s, c['opts'], kv) }
    { 'results' => results, 'kv' => kv.snapshot }
  end

  def self.sign(body, o)
    spec = o['keySpec']
    prim = spec['alg'].to_s.include?('ml-dsa-87') ? 'ML-DSA-87' : 'ML-DSA-65'
    L.sign_allowlist_manifest(body, issuer: o['issuer'], alg: o['alg'],
                                    ed: spec['edSecret'] ? A::KeyPair.new(Ref.b64d(spec['edSecret'])) : nil,
                                    pq: spec['seed'] ? A::PqKeyPair.from_seed(prim, Ref.b64d(spec['seed'])) : nil)
  end

  def self.anchor_ops(c)
    guardian = A::KeyPair.new(Ref.b64d(c['secret']))
    log = N.create_allowlist_anchor_log(instance_id: c['instanceId'], principal: c['principal'])
    c['ops'].map do |op|
      if op.key?('anchor') then N.anchor_allowlist_head(log, op['anchor'], guardian: guardian, now_ms: op['nowMs'])
      elsif op.key?('refresh') then N.refresh_anchor_head(log, guardian: guardian, now_ms: op['refresh'])
      elsif op.key?('evidenceFor') then N.evidence_for(log, op['evidenceFor'], op['cached'])
      elsif op.key?('latest') then log.latest
      else log.entries
      end
    rescue StandardError
      { '$throws' => true }
    end
  end

  POLICY_FIELDS = { 'azureMaaPolicyFields' => :azure_maa_policy_fields, 'intelDcapPolicyFields' => :intel_dcap_policy_fields,
                    'sevSnpPolicyFields' => :sev_snp_policy_fields, 'gcpCsPolicyFields' => :gcp_cs_policy_fields,
                    'nvidiaCcPolicyFields' => :nvidia_cc_policy_fields }.freeze

  HANDLERS = {
    'constants' => -> { { 'ALLOWLIST_KINDS' => L::ALLOWLIST_KINDS, 'DOMAIN' => L::DOMAIN } },
    'verifyAllowlistManifest' => ->(m, o) { L.verify_allowlist_manifest(m, o) },
    'verifyAllowlistDurable' => ->(c) { durable(c) },
    'createAllowlistManifest' => ->(b) { L.create_allowlist_manifest(b) },
    'signAllowlistManifest' => ->(b, o) { sign(b, o) },
    'revokeAllowlistEntry' => ->(p, r, t) { L.revoke_allowlist_entry(p, r, t) },
    'driverVersionSlotHex' => ->(v) { L.driver_version_slot_hex(v) },
    'projectAllowlist' => ->(v, o) { L.project_allowlist(v, now_ms: o['nowMs']) },
    'policyFields' => ->(fn, p) { L.public_send(POLICY_FIELDS.fetch(fn), p) },
    'anchorCommit' => ->(e) { N.allowlist_anchor_commit(e) },
    'anchorEntryOf' => ->(v) { N.anchor_entry_of(v) },
    'anchorOps' => ->(c) { anchor_ops(c) },
    'verifyAnchored' => ->(c) { N.verify_allowlist_anchored(c['verified'], c['evidence'], c['opts']) }
  }.freeze

  TOTALS = { 'constants' => 1, 'verifyAllowlistManifest' => 744, 'verifyAllowlistDurable' => 23, 'createAllowlistManifest' => 6,
             'signAllowlistManifest' => 10, 'revokeAllowlistEntry' => 11, 'driverVersionSlotHex' => 13, 'projectAllowlist' => 9, 'policyFields' => 45,
             'anchorCommit' => 4, 'anchorEntryOf' => 1, 'anchorOps' => 20, 'verifyAnchored' => 72 }.freeze

  def self.pq_case?(c) = Ref.canon(c['args']).match?(/ml-dsa|slh-dsa/)

  # a refusal compares by its code; a refused operator step by presence
  def self.strip(v)
    case v
    when Hash
      return { '$throws' => true } if v.key?('$throws')

      h = v.transform_values { |x| strip(x) }
      h.delete('reason') if h['ok'] == false && h.key?('code')
      h
    when Array then v.map { |x| strip(x) }
    else v
    end
  end

  def test_every_fn_of_the_corpus_has_a_handler_and_the_totals_are_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 959, BY_FN.values.sum(&:length)
  end

  def test_the_post_quantum_cases_run_where_required
    assert PQ, 'this runtime must have ML-DSA-65' if ENV['PCA_REQUIRE_PQ'] == '1'
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      k = self.class
      Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| k.dnum(a) }) }, skip: ->(c) { !PQ && k.pq_case?(c) },
              compare: ->(got, out, _c) { Ref.canon(k.strip(got)) == Ref.canon(k.strip(out)) })
    end
  end
end
