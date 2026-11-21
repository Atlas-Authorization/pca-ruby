# frozen_string_literal: true

# Replays the TS-reference oracle of the mesh issuing side and the federation primitives (test-data/ref-mesh-issue.json.gz, 787
# cases): the worked example and the fork demonstration, the size and latency models, domain / witness lifecycle scripts,
# cross-domain capability translation, the federated budget tree and cross-reference commitments. Every fn has a handler and the
# total is asserted. A secret is {"$seed": label} = sha256("atlas-pca-conformance/" + label) (script op labels carry the prefix
# "mesh-issue/d/" or "mesh-issue/w/"); a reference throw is a native raise; in a script a refused op is {"$err"} on both sides (the
# text is informative). A case whose chain carries an ML-DSA suite needs a runtime that has it (OpenSSL >= 3.5).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefMeshIssue < Minitest::Test
  A = AtlasPca
  BY_FN = Ref.load('mesh-issue')
  PQ = A.supported_suites.include?('ml-dsa-65')

  def self.key(seed)
    raise TypeError, 'a signing key is a base64url seed' unless seed.is_a?(String)

    A::KeyPair.from_seed_b64u(seed)
  end

  def self.label_key(label) = A::KeyPair.new(Digest::SHA256.digest("atlas-pca-conformance/#{label}"))
  def self.hash_of(v) = v.is_a?(Hash) ? v : {}

  def self.example(now)
    ex = now.nil? ? A.build_mesh_example : A.build_mesh_example(now)
    ex.slice('trust', 'proof', 'evidence', 'chain', 'heads', 'bindings')
      .merge('domains' => ex['domains'].transform_values(&:id), 'witnesses' => ex['witnesses'].map(&:id))
  end

  def self.translate(chain, a)
    kw = { from_guardian: a.fetch('fromGuardian'), to_guardian: a.fetch('toGuardian'), bridge: key(a['bridgeSecret']), issued_at: a.fetch('issued_at') }
    kw[:additional_caveats] = a['additionalCaveats'] if a.key?('additionalCaveats')
    kw[:pq_pins] = a['pqPins'] if a.key?('pqPins')
    A.translate_capability(chain, **kw)
  end

  # a store whose save raises once `fail_after` saves happened
  class FailingStore
    def initialize(fail_after)
      @inner = AtlasPca::MemoryMeshWitnessStore.new
      @saves = 0
      @fail_after = fail_after
    end

    def load = @inner.load

    def save(state)
      @saves += 1
      raise IOError, 'disk' if @saves > @fail_after

      @inner.save(state)
    end
  end

  def self.cap(label) = { 'id' => label, 'issuer' => "iss-#{label}", 'holder' => 'h', 'caveats' => [{ 'type' => 'scope', 'actions' => [label] }] }

  # one script: the state is per case, every op yields one result, a refused op {"$err": message}
  def self.script(ops)
    doms = {}
    ws = {}
    heads = {}
    binds = {}
    stores = {}
    get = ->(m, k) { m.key?(k) ? m[k] : raise(KeyError, "unknown name #{k}") }
    one = lambda do |op|
      case op[0]
      when 'domain' then (doms[op[1]] = A::MeshDomain.new(op[1], label_key("mesh-issue/d/#{op[2]}"))).id
      when 'witness' then (ws[op[1]] = A::MeshWitness.new(label_key("mesh-issue/w/#{op[2]}"))).id
      when 'witnessOpts'
        x = op[3].nil? ? {} : op[3]
        kw = {}
        kw[:store] = get.call(stores, x['store']) if A.mesh_truthy?(x['store'])
        kw[:clock] = -> { x['clock'] } unless x['clock'].nil?
        kw[:max_clock_skew_ms] = x['skew'] unless x['skew'].nil?
        (ws[op[1]] = A::MeshWitness.new(label_key("mesh-issue/w/#{op[2]}"), **kw)).id
      when 'store' then (stores[op[1]] = A::MemoryMeshWitnessStore.new) && true
      when 'failStore' then (stores[op[1]] = FailingStore.new(op[2])) && true
      when 'storeLoad' then get.call(stores, op[1]).load
      when 'record' then get.call(doms, op[1]).record(cap(op[2]))
      when 'revoke'
        get.call(doms, op[1]).revoke(op[2])
        nil
      when 'publish' then heads[op[2]] = get.call(doms, op[1]).publish_head(op[4].map { |w| get.call(ws, w) }, op[3], op[5])
      when 'fork'
        heads[op[1]] = get.call(heads, op[2]).merge(op[3] => op[4])
        nil
      when 'forkHead'
        h = get.call(heads, op[2])
        heads[op[1]] = h.merge('head' => h['head'].merge(op[3] => op[4]))
        nil
      when 'cosign'
        w = get.call(ws, op[1])
        h = get.call(heads, op[2])
        hd = hash_of(h['head'])
        d = doms.values.find { |x| x.id == hd['domain'] } or raise KeyError, 'no such domain'
        consistency = op[3]
        if op[3] == 'domain'
          prev = w.last_seen(hd['domain'])
          consistency = prev ? d.consistency_proof(prev['size'], hd['size']) : nil
        end
        req = { 'head' => h, 'rev_ids' => op[4] == 'domain' ? d.revocation_set_copy.list : op[4] }
        req['consistency'] = consistency if A.mesh_truthy?(consistency)
        w.cosign(req)
      when 'lastSeen' then get.call(ws, op[1]).last_seen(doms.key?(op[2]) ? doms[op[2]].id : op[2])
      when 'export' then get.call(ws, op[1]).export_state
      when 'import'
        get.call(ws, op[1]).import_state(op[2].is_a?(Hash) && op[2].key?('$export') ? get.call(ws, op[2]['$export']).export_state : op[2])
        nil
      when 'restart' then (ws[op[1]] = A::MeshWitness.new(label_key("mesh-issue/w/#{op[3]}"), store: get.call(stores, op[2]))).export_state
      when 'consistency' then op[3].nil? ? get.call(doms, op[1]).consistency_proof(op[2]) : get.call(doms, op[1]).consistency_proof(op[2], op[3])
      when 'enroll' then binds[op[2]] = get.call(doms, op[1]).enroll(op[3], op[4])
      when 'evidence' then get.call(doms, op[1]).evidence(cap(op[2]), get.call(heads, op[3]), op[4].nil? ? nil : get.call(binds, op[4]))
      else raise ArgumentError, 'op'
      end
    end
    ops.map do |op|
      one.call(op)
    rescue StandardError => e
      { '$err' => e.message }
    end
  end

  # a script result with every refusal text removed: both sides must refuse the same ops
  def self.errs(v) = v.is_a?(Array) ? v.map { |x| x.is_a?(Hash) && x.keys == ['$err'] ? { '$err' => true } : x } : v

  HANDLERS = {
    'constants' => lambda do
      { 'DEFAULT_MAX_HEAD_AGE_MS' => A::DEFAULT_MAX_HEAD_AGE_MS, 'DEFAULT_MAX_CLOCK_SKEW_MS' => A::DEFAULT_MAX_CLOCK_SKEW_MS,
        'DEFAULT_MAX_CHAIN_LENGTH' => A::DEFAULT_MAX_CHAIN_LENGTH }
    end,
    'keyRevocationId' => ->(v) { A.key_revocation_id(v) },
    'effectiveAuthority' => ->(caveats) { A.effective_authority(caveats) },
    'buildMeshExample' => ->(now) { example(now) },
    'demonstrateForkRejection' => -> { A.demonstrate_fork_rejection },
    'meshProofSize' => ->(p) { A.mesh_proof_size(p) },
    'revocationLatencyBound' => ->(p) { A.revocation_latency_bound(p) },
    'meshIssue' => ->(ops) { script(ops) },
    'translateCapability' => ->(chain, a) { translate(chain, a) },
    'verifyTranslatedCapability' => ->(*a) { A.verify_translated_capability(*a) }, # the options are absent or present (null included)
    'translatedEffectiveAuthority' => ->(tc) { A.translated_effective_authority(tc) },
    'createFederatedBudget' => lambda do |a|
      a = hash_of(a)
      A.create_federated_budget(root_id: a['rootId'], root_domain: a['rootDomain'], b0: a['B0'], kappa: a['kappa'], b_max: a['bMax'])
    end,
    'allocateSub' => lambda do |state, a|
      a = hash_of(a)
      A.allocate_sub(state, id: a['id'], domain: a['domain'], parent: a['parent'], alloc: a['alloc'])
    end,
    'spendFederated' => ->(state, node_id, c) { A.spend_federated(state, node_id, c) },
    'federatedSafetyBound' => ->(p) { A.federated_safety_bound(p) },
    'meshActionDigest' => ->(action) { A.mesh_action_digest(action) },
    'crossReferenceCommit' => ->(x) { A.cross_reference_commit(x) },
    'anchorCrossReference' => ->(sk, commit, seq) { A.anchor_cross_reference(key(sk), commit, seq) },
    'verifyCrossReference' => ->(x, anchors) { A.verify_cross_reference(x, anchors) }
  }.freeze

  def test_every_fn_of_the_corpus_has_a_handler
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal 787, BY_FN.values.sum(&:length)
  end

  def test_the_post_quantum_cases_run_where_required
    assert PQ, 'this runtime must have ML-DSA (the hybrid-root translation cases)' if ENV['PCA_REQUIRE_PQ'] == '1'
  end

  NEEDS_PQ = ->(c) { !PQ && Ref.canon(c['args']).include?('ml-dsa') }
  SAME_REFUSALS = ->(got, out, _c) { Ref.canon(errs(got)) == Ref.canon(errs(out)) }

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      Ref.run(self, BY_FN.fetch(fn), handler, skip: NEEDS_PQ, compare: fn == 'meshIssue' ? SAME_REFUSALS : nil)
    end
  end

  def test_the_worked_example_verifies_and_a_tampered_one_does_not
    ex = A.build_mesh_example
    assert A.verify_mesh_proof(ex['proof'], ex['trust']).ok
    refute A.verify_mesh_proof(ex['proof'], ex['trust'].merge('humanPrincipal' => ex['keys']['leaf'].public)).ok
  end
end
