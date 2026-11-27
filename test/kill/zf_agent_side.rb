# frozen_string_literal: true

# Exact-outcome kill tests for the agent side (lib/atlas_pca/agent.rb) and three constants elsewhere: post-quantum seed and suite
# guards, the provenance header bound (PROV_HEADER_MAX = 8192, adapters.ts), the principal-is-signer and workflow validity checks
# of the K5 signers (workflow.ts signWorkflow), sub-agent delegation under a post-quantum suite, the built-in catalog's frozen
# entries and the attestation helpers' JavaScript whitespace set. Every AtlasPca constant is resolved at CALL time (the oracle
# replaces the module per mutant).
require 'atlas_pca/attest'

module MutationKill
  module ZfAgent
    module_function

    # A post-quantum key pair double (the real one needs OpenSSL >= 3.5): signs every message with fixed bytes.
    class StubPq
      attr_reader :prim, :public

      def initialize(prim, pub)
        @prim = prim
        @public = pub
      end

      def sign(_msg) = ('S' * 8).b
    end

    # Stands in for the OpenSSL pkey OpenSSL::PKey.generate_key returns.
    class FakePkey
      def raw_public_key = ("\x07" * 32).b
    end

    # Answers bytesize and unpack1 like a 32-byte String but is not one.
    class FakeSeed
      def bytesize = 32
      def unpack1(_fmt) = '00' * 32
    end

    # A Hash the validator cannot read: every member read raises.
    class Unreadable < Hash
      def [](_key) = raise('unreadable body')
    end

    def key(seed) = AtlasPca::KeyPair.new([seed].pack('C') * 32)

    def raises?(klass, msg)
      yield
      false
    rescue klass => e
      e.message == msg
    end

    # Run the block with OpenSSL::PKey.generate_key recorded (into log) and answering a fake key.
    def keygen(log, &blk)
      Seam.with(OpenSSL::PKey, { generate_key: ->(*a) { log << a; FakePkey.new } }, &blk)
    end

    def grant_for(principal, holder)
      env = { 'predicates' => [{ 'verb' => 'v', 'resource' => 'r' }], 'caveats' => [], 'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
      AtlasPca.mint_grant(principal, holder.public, env, 'g')['grant']
    end

    def step(id, deps, cost = {})
      { 'id' => id, 'verb' => 'pay', 'resource' => "invoices/#{id}", 'params_digest' => nil, 'deps' => deps, 'sink' => nil,
        'deny_labels' => [], 'escalate_labels' => [], 'fresh_ms' => nil, 'cost' => cost }
    end

    # The producer vector workflow-sign body (two steps s1 -> s2, one edge), principal = pub.
    def workflow(pub)
      { 'v' => 1, 'id' => 'wf-1', 'principal' => pub, 'goal_digest' => nil, 'plan_root' => nil, 'issued_at' => 1_800_000_000_000,
        'expires_at' => 1_800_003_600_000, 'steps' => [step('s1', []), step('s2', ['s1'], { 'pay' => 1 })],
        'edges' => [{ 'from' => { 'step' => 's1', 'field' => 'amount' }, 'to' => { 'step' => 's2', 'param' => 'amount' }, 'op' => 'le',
                      'unit' => 'cents', 'deny_labels' => [], 'promise' => nil }],
        'budget' => { 'max_steps' => 4, 'caps' => { 'pay' => 2 } } }
    end

    def read_grant(pub)
      { 'v' => 1, 'id' => 'rg-1', 'principal' => pub, 'issued_at' => 1_800_000_000_000, 'expires_at' => 1_800_003_600_000,
        'reads' => [{ 'verb' => 'read', 'resource_prefix' => 'customers/', 'purposes' => ['support'],
                      'modes' => { 'email' => 'hash', 'ssn' => 'drop' }, 'default_mode' => 'show' }],
        'caps' => { 'rows' => 100 }, 'sinks' => { 'llm' => { 'allow' => ['public'], 'escalate' => ['pii'] } } }
    end

    def aggregate_grant(pub)
      { 'v' => 1, 'id' => 'ag-1', 'principal' => pub, 'issued_at' => 1_800_000_000_000, 'expires_at' => 1_800_003_600_000,
        'rules' => [{ 'verb' => 'aggregate', 'resource_prefix' => 'orders/', 'purposes' => ['analytics'], 'fns' => %w[count sum],
                      'min_group' => 5, 'clamp' => 1000, 'epsilon_micro' => 100_000, 'dp' => true }],
        'epsilon_budget_micro' => 1_000_000, 'max_queries' => 10 }
    end

    # A provenance bundle whose strict-canonical bytes are exactly n long.
    def prov_of_bytes(n) = { 'x' => 'a' * (n - AtlasPca.strict_bytes({ 'x' => '' }).bytesize) }
  end

  t('zf agent: PqKeyPair refuses a primitive it cannot sign with before any key generation, exactly') do
    z = ZfAgent
    log = []
    refused = z.keygen(log) do
      ['ML-DSA-44', 'Ed25519', 'ml-dsa-65', nil].all? do |prim|
        z.raises?(AtlasPca::UnsupportedSigner, "unsupported_suite: #{prim}") { AtlasPca::PqKeyPair.new(prim) } &&
          z.raises?(AtlasPca::UnsupportedSigner, "unsupported_suite: #{prim}") { AtlasPca::PqKeyPair.from_seed(prim, ("\x01" * 32).b) }
      end
    end
    refused && log.empty?
  end

  t('zf agent: PqKeyPair seed must be a String of exactly the reference length, checked before key generation') do
    z = ZfAgent
    log = []
    refused = z.keygen(log) do
      { 'ML-DSA-65' => 32, 'ML-DSA-87' => 32, 'SLH-DSA-SHA2-128f' => 48, 'SLH-DSA-SHA2-256s' => 96 }.all? do |prim, n|
        msg = "a #{prim} seed is #{n} bytes"
        [0, n - 1, n + 1].all? { |len| z.raises?(ArgumentError, msg) { AtlasPca::PqKeyPair.from_seed(prim, ('x' * len).b) } }
      end &&
        z.raises?(ArgumentError, 'a ML-DSA-65 seed is 32 bytes') { AtlasPca::PqKeyPair.from_seed('ML-DSA-65', z::FakeSeed.new) } &&
        z.raises?(ArgumentError, 'a ML-DSA-65 seed is 32 bytes') { AtlasPca::PqKeyPair.from_seed('ML-DSA-65', [0] * 32) } &&
        z.raises?(ArgumentError, 'a ML-DSA-65 seed is 32 bytes') { AtlasPca::PqKeyPair.from_seed('ML-DSA-65', false) }
    end
    no_keygen = log.empty?
    seed = ("\xab" * 48).b
    made = z.keygen(log) { [AtlasPca::PqKeyPair.generate('ML-DSA-65'), AtlasPca::PqKeyPair.from_seed('SLH-DSA-SHA2-128f', seed)] }
    refused && no_keygen && log == [['ML-DSA-65'], ['SLH-DSA-SHA2-128f', { 'hexseed' => 'ab' * 48 }]] &&
      made.map(&:prim) == %w[ML-DSA-65 SLH-DSA-SHA2-128f] && made.all? { |k| k.public == AtlasPca.b64e(("\x07" * 32).b) }
  end

  t('zf agent: the PCA-Provenance header bound is 8192 base64url characters, inclusive (adapters.ts PROV_HEADER_MAX)') do
    z = ZfAgent
    pc = { 'v' => 1 }
    hdr = ->(bytes) { AtlasPca.pca_headers(pc, provenance: z.prov_of_bytes(bytes)) }
    # 6143 / 6144 / 6145 bytes encode to 8191 / 8192 / 8194 characters (unpadded base64url never has a length of 4k+1, so 8194
    # is the shortest value over the bound)
    at = hdr.call(6144)
    AtlasPca::PROV_HEADER_MAX == 8192 && AtlasPca::PROV_HEADER == 'PCA-Provenance' &&
      hdr.call(6143)['PCA-Provenance']&.length == 8191 &&
      at['PCA-Provenance']&.length == 8192 && at['PCA-Provenance'] == AtlasPca.b64e(AtlasPca.strict_bytes(z.prov_of_bytes(6144))) &&
      at.keys == %w[PCA-Action PCA-Provenance] &&
      hdr.call(6145).keys == ['PCA-Action'] && AtlasPca.b64e('a' * 6145).length == 8194 &&
      AtlasPca.pca_headers(pc).keys == ['PCA-Action'] && AtlasPca.pca_headers(pc, provenance: nil).keys == ['PCA-Action']
  end

  t('zf agent: the K5 signers refuse a body whose principal is not the signing key, naming the signer') do
    z = ZfAgent
    p = z.key(0x41)
    other = z.key(0x42)
    cases = [[:sign_workflow, :workflow], [:sign_read_grant, :read_grant], [:sign_aggregate_grant, :aggregate_grant]]
    cases.all? do |fn, body|
      b = z.public_send(body, other.public)
      ok = AtlasPca.public_send(fn, p, z.public_send(body, p.public))
      z.raises?(ArgumentError, "#{fn}: principal is not the signer") { AtlasPca.public_send(fn, p, b) } &&
        ok.keys == %w[body sig] && ok['body']['principal'] == p.public && AtlasPca.b64d(ok['sig'], 64)
    end
  end

  t('zf agent: sign_workflow refuses a malformed acyclic body and a well-formed cyclic one (workflow.ts signWorkflow)') do
    z = ZfAgent
    p = z.key(0x43)
    msg = 'sign_workflow: malformed workflow'
    good = z.workflow(p.public)
    bad_version = good.merge('v' => 2) # malformed, but its steps form a DAG
    cyclic = good.merge('steps' => [z.step('s1', ['s2']), z.step('s2', ['s1'], { 'pay' => 1 })], 'edges' => [])
    self_dep = good.merge('steps' => [z.step('s1', ['s1'])], 'edges' => [])
    AtlasPca.valid_workflow_body?(bad_version) == false && AtlasPca.wf_dag_error(bad_version).nil? &&
      AtlasPca.valid_workflow_body?(cyclic) == true && AtlasPca.wf_dag_error(cyclic) == 'cycle' &&
      z.raises?(ArgumentError, msg) { AtlasPca.sign_workflow(p, bad_version) } &&
      z.raises?(ArgumentError, msg) { AtlasPca.sign_workflow(p, cyclic) } &&
      z.raises?(ArgumentError, msg) { AtlasPca.sign_workflow(p, self_dep) } &&
      AtlasPca.sign_workflow(p, good)['body'].equal?(good)
  end

  t('zf agent: a body the validator cannot read is malformed (ArgumentError, not the read fault)') do
    z = ZfAgent
    p = z.key(0x44)
    body = z::Unreadable[z.aggregate_grant(p.public)]
    z.raises?(ArgumentError, 'sign_aggregate_grant: malformed grant') { AtlasPca.sign_aggregate_grant(p, body) } &&
      AtlasPca.valid_body?(body) { |b| b['v'] } == false && AtlasPca.valid_body?(1) { |_b| 0 } == true &&
      AtlasPca.valid_body?(1) { |_b| nil } == false
  end

  t('zf agent: envelope_member_error is nil for an envelope whose optional members are absent or valid') do
    env = { 'predicates' => [], 'caveats' => [], 'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
    AtlasPca.envelope_member_error(env).nil? && AtlasPca.envelope_member_error(env.merge('model_polarity' => 'legacy')).nil? &&
      AtlasPca.envelope_member_error(env.merge('units' => 1)) == 'units must be an object'
  end

  t('zf agent: delegate under ed25519 (explicit or default) stays Ed25519 and commits a given to_pq by its public key') do
    z = ZfAgent
    p = z.key(0x45)
    k = z.key(0x46)
    to = z.key(0x47)
    grant = z.grant_for(p, k)
    explicit = AtlasPca::Agent.new(k, grant, 'rs', alg: 'ed25519').delegate(to)
    sub_pq = z::StubPq.new('ML-DSA-65', 'SUBPQ')
    committed = AtlasPca::Agent.new(k, grant, 'rs').delegate(to, [], to_pq: sub_pq)
    hop = committed.chain.last
    explicit.alg.nil? && explicit.pq.nil? && explicit.chain.length == 2 && !explicit.chain.last.key?('alg') &&
      !explicit.chain.last.key?('holder_pq') && explicit.chain.last['holder'] == to.public &&
      committed.alg.nil? && committed.pq.nil? && hop['holder_pq'] == AtlasPca.holder_pq_commitment('SUBPQ') && !hop.key?('alg') &&
      committed.act('v', 'r').pcactn['cap_chain'].length == 2
  end

  t('zf agent: delegate under a post-quantum suite hands the sub-agent the given to_pq and commits it') do
    z = ZfAgent
    p = z.key(0x48)
    k = z.key(0x49)
    to = z.key(0x4a)
    grant = z.grant_for(p, k)
    mine = z::StubPq.new('ML-DSA-65', 'MYPQ')
    sub_pq = z::StubPq.new('ML-DSA-65', 'SUBPQ')
    sub = AtlasPca::Agent.new(k, grant, 'rs', alg: 'ml-dsa-65', pq: mine).delegate(to, [], to_pq: sub_pq)
    hop = sub.chain.last
    sub.pq.equal?(sub_pq) && sub.alg == 'ml-dsa-65' && sub.key.equal?(to) && hop['holder'] == to.public &&
      hop['holder_pq'] == AtlasPca.holder_pq_commitment('SUBPQ') && hop['alg'] == 'ml-dsa-65' && hop['pq_pk'] == 'MYPQ' &&
      hop['issuer'] == k.public
  end

  t('zf catalog: every built-in action spec is frozen, as is the list') do
    acts = AtlasPca::BUILTIN_ACTIONS
    acts.frozen? && acts.length == 21 && acts.all?(&:frozen?) &&
      begin
        acts[0]['blastRadius'] = 0
        false
      rescue FrozenError
        acts[0]['blastRadius'] == 0.9
      end
  end

  t('zf attest: Common::JS_WS is the ECMAScript trim set (WhiteSpace + LineTerminator)') do
    want = [0x9, 0xa, 0xb, 0xc, 0xd, 0x20, 0xa0, 0x1680, *(0x2000..0x200a), 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff]
    ws = AtlasPca::Attest::Common::JS_WS
    ws.frozen? && ws.codepoints.sort == want && ws.codepoints.uniq.length == ws.length &&
      AtlasPca::Attest::Common.js_trim("　﻿ x   ") == 'x' &&
      AtlasPca::Attest::Common.js_trim("​ x") == "​ x"
  end
end
