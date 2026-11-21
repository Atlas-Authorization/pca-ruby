# frozen_string_literal: true

# The signing side of artifacts this SDK verifies, the bond-settlement / ledger / optimistic producers and the small core helpers,
# replayed over the TS-reference oracles that carry them: the liveness beacon issue (ref-beacons), the registry documents of the
# action kit (ref-action-pin), the catalog risk inputs (ref-core-small-surface), the settlement commitment (ref-core-bond-settlement-java), the coverage pricing and
# the insurance pool (ref-core-sweep-java). Every fn of each corpus has a handler here (or is replayed in full by the test file named in REPLAYED_ELSEWHERE); a fn
# that is in neither fails. The helpers without a corpus are checked against the verifiers of the
# library (a head signed here verifies there) and against values written out from the reference's definitions.
# Encodings: {"$num": ...} is a non-finite number; {"$bytes": {"$seed": label}} the 32-byte secret sha256("atlas-pca-conformance/"
# + label); a suite is {alg, pqSeed?} (the ML-DSA-65 seed; signing is deterministic, so signatures compare byte for byte).
require_relative 'support/ref_oracle'
require_relative 'test_ref_beacons'
require 'minitest/autorun'

class TestRefSiblingPorts < Minitest::Test
  A = AtlasPca
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze
  T0 = 1_800_000_000_000

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  def self.key(secret) = A::KeyPair.new(secret)

  # {alg:, pq:} of a corpus suite ({alg, pqSeed?} or null)
  def self.suite(s)
    return {} unless s.is_a?(Hash)

    { alg: s['alg'], pq: s['pqSeed'] ? A::PqKeyPair.from_seed('ML-DSA-65', s['pqSeed']) : nil }
  end

  def self.beacon(a)
    kw = { seq: a['seq'], issued_at: a['issuedAt'] }
    kw[:instance] = a['instance'] if a.key?('instance') # absent: the reference refuses (so does a missing keyword)
    kw[:scope] = a['scope'] if a.key?('scope')
    kw[:validity_ms] = a['validityMs'] if a.key?('validityMs')
    A.issue_liveness_beacon(key(a['issuerSecret']), **kw, **suite(a['suite']))
  end

  # the pool scenario: one result per step, a refused step is {"$err": "Error"}
  def self.pool(ops)
    pool = nil
    ops.map do |op, *a|
      case op
      when 'new' then (pool = A::InsuranceCapitalPool.new(a[0])).state
      when 'collect' then pool.collect_premium(*a)
      when 'quote' then pool.quote(*a)
      when 'state' then pool.state
      when 'canCover' then pool.can_cover?(a[0])
      when 'pay' then pool.pay_claim(a[0])
      else raise "unknown pool step #{op}"
      end
    rescue ArgumentError, NoMethodError
      { '$err' => 'Error' }
    end
  end

  BS = A::BondSettlement

  def self.op_err = { '$err' => 'Error' }

  # the verifier chain memo: one result per op, a refused op is {"$err": "Error"}
  def self.chain_memo(ops)
    memo = nil
    ops.map do |op|
      case op[0]
      when 'new'
        cfg = op[1].is_a?(Hash) ? op[1] : {}
        kw = {}
        kw[:max_entries] = cfg['maxEntries'] if cfg['maxEntries'].is_a?(Numeric)
        kw[:ttl_ms] = cfg['ttlMs'] if cfg['ttlMs'].is_a?(Numeric)
        memo = A::ChainMemo.new(**kw)
        nil
      when 'remember' then memo.remember_verified(op[1], op[2], op[3])
      when 'resolve'
        r = memo.resolve(op[1], op[2])
        v = r['view']
        r['ok'] ? { 'ok' => true, 'view' => { 'n' => v.n, 'leaf' => v.leaf, 'hashes' => (0...v.n).map { |i| v.hash(i) }, 'counts' => (0...v.n).map { |i| v.count(i) } } } : r
      when 'prune' then memo.prune(op[1]); nil
      when 'forget' then memo.forget(op[1])
      when 'size' then memo.size
      else raise ArgumentError, 'op'
      end
    rescue StandardError
      op_err
    end
  end

  # the receipt log of the reference: appends, head, verify, and edits of the stored log (tamper, swap, drop, truncate, set)
  def self.receipt_chain(ops)
    log = []
    ops.map do |op|
      case op[0]
      when 'append'
        log = A.append_receipt(log, op[1], op[2], op[3])
        log.last
      when 'head' then A.receipt_head(log)
      when 'verify' then A.verify_receipt_chain(log)
      when 'set' then log = Marshal.load(Marshal.dump(op[1])); nil
      when 'tamper'
        log = Marshal.load(Marshal.dump(log))
        op[3] == '$del' ? log[op[1]].delete(op[2]) : log[op[1]][op[2]] = op[3]
        nil
      when 'swap' then log = log.dup; log[op[1]], log[op[2]] = log[op[2]], log[op[1]]; nil
      when 'drop' then log = log.dup; log.delete_at(op[1]); nil
      when 'truncate' then log = log.first(op[1]); nil
      else raise ArgumentError, 'op'
      end
    rescue StandardError
      op_err
    end
  end

  # the corpus oracle: a table of resolutions by disputed input (no table: no oracle)
  def self.oracle(table)
    return nil unless table.is_a?(Hash)

    Class.new { define_method(:resolve) { |input, _snap| table[input] } }.new
  end

  # "@name" strings stand for the named fixture of the case
  def self.resolve_fx(fx, v)
    case v
    when String then v.start_with?('@') ? fx[v[1..]] : v
    when Array then v.map { |x| resolve_fx(fx, x) }
    when Hash then v.transform_values { |x| resolve_fx(fx, x) }
    else v
    end
  end

  # the scripted bond ledger: one result per op, a refused op is {"$err": code}
  def self.bond_ledger(fx, cfg, ops)
    kv = A::MemoryAtomicKv.new
    clock = 1_800_000_000_000
    kw = { clock: -> { clock } }
    kw[:guardian_epoch] = cfg['epoch'] if cfg.key?('epoch') && !cfg['epoch'].nil?
    kw[:escrow_account] = cfg['escrow'] if cfg['escrow'].is_a?(String)
    kw[:bond_policy] = { 'maxOpenClaims' => 100, 'maxOpenAmount' => Float::INFINITY }.merge(cfg['bondPolicy']) if cfg['bondPolicy'].is_a?(Hash)
    kw[:slash_split_policy] = cfg['splitPolicy'] if cfg['splitPolicy'].is_a?(Hash)
    if cfg['windowMs'].is_a?(Hash)
      w = cfg['windowMs']
      kw[:window_policy] = { 'minWindowMs' => w['min'], 'maxWindowMs' => w['max'], 'maxSkewMs' => w['skew'] }
    end
    guardian = A::KeyPair.new(Digest::SHA256.digest('atlas-pca-conformance/bond/guardian'))
    ledger = A::StoreBondLedger.new(A::KvBondStore.new(kv), guardian, **kw)
    ops.map do |op|
      case op[0]
      when 'clock' then clock = op[1]; nil
      when 'deposit' then ledger.deposit(op[1], op[2])
      when 'balance' then ledger.balance_of(op[1])
      when 'status' then ledger.bond_status(op[1])
      when 'bond' then ledger.get_bond(op[1])
      when 'challenge' then ledger.challenge_status(op[1])
      when 'pub' then ledger.guardian_public_key
      when 'openClaim'
        p = resolve_fx(fx, op[1])
        ledger.open_claim(p['claim'], p['pcactn'], p['signerPublic'], p['amount'], p['depositor'], p['exposure'])
      when 'openBond'
        p = resolve_fx(fx, op[1])
        ledger.open_bond(p['claimId'], p['amount'], p['depositor'], p['exposure'])
      when 'release' then ledger.release(op[1])
      when 'releaseUnreg' then ledger.release_unregistered(op[1])
      when 'slash' then ledger.slash_bond(slash_params(fx, op[1]))
      when 'slashDispute' then ledger.slash_bond_on_dispute(slash_params(fx, op[1]))
      when 'slashRevoke' then ledger.slash_bond_on_revocation(slash_params(fx, op[1]))
      when 'slashCounter' then ledger.slash_counter_bond(slash_params(fx, op[1]))
      when 'kvSet' then kv.set('pca-bond-store/v1', op[1])
      when 'kvGet' then kv.get('pca-bond-store/v1')
      else raise ArgumentError, 'op'
      end
    rescue StandardError => e
      { '$err' => A.store_error_code(e) }
    end
  end

  # slash parameters of the ledger: the oracle table becomes an oracle object; fields the reference reads as optional stay absent
  def self.slash_params(fx, raw)
    q = resolve_fx(fx, raw)
    q = q.merge('oracle' => oracle(q['oracleTable'])) if q.key?('oracleTable')
    q
  end


  def self.try_ok
    { 'ok' => true, 'v' => yield }
  rescue StandardError
    { 'ok' => false }
  end

  # the reference's camelCase options of a discovery document, in the native's snake_case
  def self.discovery_options(o)
    map = { 'signatureSuites' => 'signature_suites', 'pcaVersions' => 'pca_versions', 'actionHeader' => 'action_header', 'requiredChecks' => 'required_checks',
            'trustedRoots' => 'trusted_roots', 'obligationsSupported' => 'obligations_supported' }
    o.to_h { |k, v| [map.fetch(k, k), v] }
  end

  # fetch over a scripted transport: records every (url, accept) and answers ok / bad / 500 / throw
  def self.fetch_discovery(base, mode)
    urls = []
    fetch = lambda do |url, headers|
      urls << "#{url}|#{headers['accept']}"
      raise 'boom' if mode == 'throw'

      body = mode == 'bad' ? '{"nope":1}' : '{"audience":"https://rs.example","pca_versions":[2],"signature_suites":["ed25519","ml-dsa-65"],"action_header":"PCA-Action"}'
      { 'ok' => mode != '500', 'status' => mode == '500' ? 500 : 200, 'body' => body }
    end
    { 'doc' => A.fetch_discovery(base, fetch), 'urls' => urls }
  rescue StandardError
    { 'error' => true, 'urls' => urls }
  end

  def self.seed_key(label) = A::KeyPair.new(Digest::SHA256.digest("atlas-pca-conformance/#{label}"))

  def self.from_template(name, overrides)
    h = A.from_template(name, principal: seed_key('small/tpl/p'), goal: 'g', holder: seed_key('small/tpl/h'), now: 1_700_000_000_000,
                              overrides: overrides.is_a?(Hash) ? overrides : nil)
    pol = h.policy
    { 'ok' => true, 'predicates' => pol['predicates'], 'caveats' => pol['caveats'], 'riskPolicy' => pol['riskPolicy'], 'budgetModel' => pol['budgetModel'] }.reject { |_k, v| v.nil? }
  rescue StandardError
    { 'ok' => false }
  end

  def self.policy_builder(ops)
    b = A::PolicyBuilder.new
    ops.each do |op|
      case op[0]
      when 'from' then b = A::PolicyBuilder.from(op[1])
      when 'allow' then b.allow(op[1], op[2])
      when 'limit' then b.limit(op[1], op[2])
      else b.risk(op[1])
      end
    end
    { 'ok' => true, 'built' => b.build }
  rescue StandardError
    { 'ok' => false }
  end

  # the replay guard over one shared in-memory store: each step is one PCActn presented at a clock
  def self.guard_seq(o, steps)
    store = A::ConnectReplay::InMemoryReplayStore.new
    require_nonce = o['requireNonce'] != false
    steps.map do |st|
      A::ConnectReplay.guard_pcactn_replay(store, st['p'], o['aud'], st['now'], o['clockSkewMs'], require_nonce, o['counters'] == true ? store : nil)
    end
  end

  # the undo record lifecycle: the opening receipt, then each event at its clock, every applied transition signed
  def self.undo_lifecycle(rec, steps)
    key = seed_key('small/undo/service')
    cur = A.undo_with_receipt(rec, { 'event' => 'opened', 'note' => '' }, rec['opened_at'], key)
    out = [cur]
    steps.each do |ev, now|
      tr = A.undo_transition(cur, ev, now)
      case tr['outcome']
      when 'applied'
        cur = A.undo_with_receipt(tr['record'], tr['receipt'], now, key)
        out << { 'applied' => ev['kind'], 'record' => cur }
      when 'replayed' then out << { 'replayed' => nil }
      else out << { tr['outcome'] => tr['code'] }
      end
    end
    out << { 'chain' => A.undo_receipt_chain_error(cur, key.public) }
  end

  def self.undo_store(kind, ops)
    st = kind == 'memory' ? A::MemoryUndoStore.new : A::KvUndoStore.new(A::MemoryDurableKv.new, true)
    ops.map do |op|
      case op[0]
      when 'create' then st.create(op[1])
      when 'get' then st.get(op[1])
      when 'replace' then st.replace(op[1], op[2], op[3])
      else st.list(op[1].to_h { |k, v| [{ 'grantRef' => 'grant_ref', 'bondRef' => 'bond_ref', 'windowEndedBy' => 'window_ended_by' }.fetch(k, k), v] })
      end
    rescue A::UndoError => e
      { 'error' => e.code }
    end
  end

  # the underwriter of the coverage quotes of the sweep corpus
  UNDERWRITER = A::KeyPair.new(Digest::SHA256.digest('atlas-pca-conformance/sweep/underwriter'))

  # corpus => {fn => [handler, case count]}
  HANDLERS = {
    'beacons' => { 'issueLivenessBeacon' => [->(a) { beacon(a) }, 36] },
    'action-pin' => {
      'signEvolutionRecord' => [->(rec, kid, sk, s) { A.sign_evolution_record(rec, kid, key(sk), **suite(s)) }, 33],
      'registryKeyOf' => [->(kid, sk, s) { A.registry_key_of(kid, key(sk), **suite(s)) }, 5],
      'signRegistryDoc' => [->(dom, body, kid, sk, s) { A.sign_registry_doc(dom, body, kid, key(sk), **suite(s)) }, 20],
      'signReapproval' => [->(a) { A.sign_reapproval(a['grantId'], a['record'], key(a['principalSecret'])) }, 8],
      'constants' => [-> { action_pin_constants }, 1],
      'verifyEvolutionRecord' => [->(rec, keys) { A::ActionsRegistry.verify_evolution_record(rec, keys) }, 21],
      'verifyRegistrySig' => [->(dom, body, sig, keys) { A::ActionsRegistry.verify_registry_sig(dom, body, sig, keys) }, 6],
      'reapprovalValid' => [->(r, grant_id, issuer, verb, diff) { A::ActionsRegistry.reapproval_valid?(r, grant_id, issuer, verb, diff) }, 17]
    },
    'core-small-surface' => {
      'catalogRisk' => [->(verb, params, grant, taint) { A.catalog_risk(verb, params, grant, taint: taint) }, 110],
      'pcactnCheapClaims' => [->(pc, aud, now) { raise ArgumentError, 'not an object' unless pc.is_a?(Hash); A.pcactn_cheap_claims(pc, audience: aud, now: now) }, 16],
      'goalCommitOf' => [->(goal, salt) { A.goal_commit_of(goal, salt) }, 4],
      'verifyGoalCommit' => [->(commit, goal, salt) { A.verify_goal_commit(commit, goal, salt) }, 16],
      'dischargeRequests' => [->(grant, chain, digest) { A.discharge_requests(grant, chain, digest) }, 7],
      'namedUnmetLimitReason' => [->(preds, ctx) { A.named_unmet_limit_reason(preds, ctx) }, 7],
      'resolveReversibilityClass' => [->(action, plan, node) { A.resolve_reversibility_class(action, plan, node) }, 8],
      'agentCaveatContext' => [->(base, action) { A.agent_caveat_context(base, action) }, 5],
      'assembleThreshold' => [->(shares) { A.assemble_threshold(shares) }, 4],
      'isBudgetAllocCaveat' => [->(cv) { A.budget_alloc_caveat?(cv) }, 8],
      'meetAll' => [->(ds) { A.meet_all(ds) }, 7],
      'escalateThreshold' => [->(rt, min_t) { A::Risk.escalate_threshold(rt, min_t) }, 15],
      'detectorReceiptShapeError' => [->(r) { A::Dataflow.detector_receipt_shape_error(r) }, 25],
      'detectorReceiptRef' => [->(r) { A::Dataflow.detector_receipt_ref(r) }, 25],
      'detectorPolicyError' => [->(pol) { A::Dataflow.detector_policy_error(pol) }, 18],
      'detectorSignal' => [->(input) { A::Dataflow.detector_signal(input) }, 24],
      'guardSeq' => [->(o, steps) { guard_seq(o, steps) }, 19],
      'workflowCommitmentError' => [->(wf, principal, now) { A.workflow_commitment_error(wf, principal, now) }, 180],
      'workflowReceiptError' => [->(w, signer, receipts, now) { (r = A.workflow_receipt_error(w, signer, receipts, now)) && r['at'] }, 171],
      'collectObligations' => [->(rules, ctx) { A.collect_obligations(rules, ctx) }, 18],
      'verifyChainCheap' => [lambda { |chain, root, allowed|
        r = A.verify_chain_cheap(chain, root, allowed_suites: allowed)
        r['ok'] ? { 'ok' => true, 'pqHops' => r['pq_hops'] } : r
      }, 23],
      'holderPqKey' => [->(alg, holder, artifact_pk, holder_pq) { A.holder_pq_key(alg, holder, artifact_pk, holder_pq)&.key }, 9],
      'parseDiscoveryDocument' => [->(v) { A.parse_discovery_document(v) }, 32],
      'parseDiscoveryIntent' => [->(v) { A.parse_discovery_intent(v) }, 15],
      'acceptsSuite' => [->(doc, suite) { A.accepts_suite?(doc, suite) }, 3],
      'buildDiscoveryDocument' => [->(o) { A.build_discovery_document(discovery_options(o)) }, 5],
      'fetchDiscovery' => [->(base, mode) { fetch_discovery(base, mode) }, 6],
      'verifyMembership' => [->(root, proof, id) { A.verify_membership(root, proof, id) }, 135],
      'validateRevocationStaleness' => [lambda { |pol|
        begin
          raise ArgumentError, 'a present null is not a duration' if pol.key?('maxRevocationAgeMs') && pol['maxRevocationAgeMs'].nil? # absent and null are one value natively
          A.validate_revocation_staleness(pol.to_h { |k, v| [k == 'maxRevocationAgeMs' ? 'max_revocation_age_ms' : k, v] })
          { 'ok' => true }
        rescue StandardError
          { 'ok' => false }
        end
      }, 13],
      'isCanonicalCompactJws' => [->(t) { A::Jose.canonical_compact_jws?(t) }, 28],
      'isCanonicalCompactJwsOpaque' => [->(t) { A::Jose.canonical_compact_jws?(t, payload: 'opaque') }, 28],
      'isCanonicalCompactJwsMax' => [->(t) { A::Jose.canonical_compact_jws?(t, max_bytes: 40) }, 28],
      'isCanonicalCompactJwsFive' => [->(t) { A::Jose.canonical_compact_jws?(t, parts: 5) }, 4],
      'assertCanonicalJwsSegments' => [lambda { |prot, sig|
        begin
          { 'ok' => true, 'header' => A::Jose.assert_canonical_jws_segments(prot, sig) }
        rescue StandardError
          { 'ok' => false }
        end
      }, 8],
      'listTemplates' => [-> { A.list_templates }, 1],
      'fromTemplate' => [->(name, ov) { from_template(name, ov) }, 11],
      'policyBuilder' => [->(ops) { policy_builder(ops) }, 9],
      'createLink' => [lambda { |d, slots, bind|
        begin
          { 'ok' => true, 'ref' => A.create_link(d, slots, bind_params: bind == true) }
        rescue StandardError
          { 'ok' => false }
        end
      }, 16],
      'slotsDigest' => [->(slots) { A.slots_digest(slots) }, 8],
      'linkDigest' => [->(ref) { A.link_digest(ref) }, 2],
      'limits' => [-> { { 'MAX_SLOTS' => A::MAX_TEMPLATE_SLOTS, 'MAX_SLOT_STRING' => A::MAX_SLOT_STRING, 'MAX_SLOT_SET' => A::MAX_SLOT_SET, 'TEMPLATE_KIND' => 'pca-policy-template', 'TIGHTEN_KIND' => 'pca-template-tighten' } }, 1],
      'undoLifecycle' => [->(rec, steps) { undo_lifecycle(rec, steps) }, 8],
      'undoStore' => [->(kind, ops) { undo_store(kind, ops) }, 6],
      'catalogReversibilityScore' => [-> { A::CATALOG_REVERSIBILITY_SCORE }, 1],
      'spcExpectation' => [->(r, payee) { try_ok { A::ActionsApprovalProfiles.spc_expectation(r, 'https://shop.example', payee.is_a?(String) ? payee : 'name') } }, 22],
      'cibaApprovalDetails' => [->(r) { try_ok { A::ActionsApprovalProfiles.ciba_approval_details(r) } }, 4]
    },
    'core-bond-settlement-java' => {
      'verifySettlementCommit' => [->(c, salt, rec) { A.verify_settlement_commit(c, salt, rec) }, 31],
      'computeSlashSplit' => [->(amount, policy, dest) { BS.compute_slash_split(amount, policy, dest) }, 198],
      'quantizeUp' => [->(x) { BS.quantize_up(x) }, 22],
      'toMicros' => [->(x) { (m = A::BondStoreDocs.to_micros(x)) && { '$bigint' => m.to_s } }, 22],
      'exactAdd' => [->(a, b, sign) { A::BondStoreDocs.exact_add(a, b, sign) }, 140],
      'applyBondMoves' => [->(bal, moves) { A::BondStoreDocs.apply_bond_moves(->(acct) { bal[acct] || 0 }, moves) }, 10],
      'bondAmount' => [->(policy, exposure) { BS.bond_amount(policy, exposure) }, 234],
      # the reference takes a pin POLICY {pqPins, allowUnboundPq}; the native takes the pin map itself (allowUnboundPq has no native twin), so a bare map is no policy
      'verifySettlement' => [->(rec, pub, policy) { BS.verify_settlement(rec, pub, policy.is_a?(Hash) ? policy['pqPins'] : nil) }, 77],
      'settlementRecordDigest' => [->(rec) { BS.settlement_record_digest(rec) }, 10],
      'settlementCommit' => [->(salt, rec) { BS.settlement_commit(salt, rec) }, 11],
      'settlementEvidenceDigest' => [->(claim, v) { BS.settlement_evidence_digest(claim, v) }, 12],
      'revocationEvidenceDigest' => [->(claim, cap) { BS.revocation_evidence_digest(claim, cap) }, 5],
      'disputeEvidenceDigest' => [->(claim, v) { BS.dispute_evidence_digest(claim, v) }, 5],
      'verifyClaim' => [->(claim, pcactn, pub, now, wp) { A.verify_claim(claim, pcactn, pub, now, wp) }, 117],
      'verifyFraudProof' => [->(claim, proof, grant, snap) { A::OptimisticAdjudication.verify_fraud_proof(claim, proof, grant, snap) }, 149],
      'adjudicateDispute' => [->(claim, dispute, grant, snap, table, margin) { A::OptimisticAdjudication.adjudicate_dispute(claim, dispute, grant, snap, oracle(table), margin) }, 297],
      'ledger' => [->(fx, cfg, ops) { bond_ledger(fx, cfg, ops) }, 111]
    },
    'core-sweep-java' => {
      'priceCoverage' => [->(rep, exposure, opts) { A.price_coverage(rep, exposure, opts) }, 226],
      'pool' => [->(ops) { pool(ops) }, 9],
      'reputation' => [->(input) { A.reputation(input) }, 48],
      'issueCoverageQuote' => [->(rep, exposure, now, ttl, opts) { A.issue_coverage_quote(rep, exposure, UNDERWRITER, now: now, ttl_ms: ttl, opts: opts) }, 43],
      'verifyCoverageQuote' => [lambda { |q, uw, now| # "@u" is the corpus underwriter; a null time is NaN
        A.verify_coverage_quote(q, underwriter: uw == '@u' ? UNDERWRITER.public : uw, now: now.nil? ? Float::NAN : now)
      }, 27],
      'recommendPolicy' => [->(n, r, kappa) { A::BudgetForecast.recommend_policy(n, r, kappa: kappa) }, 110],
      'autonomyBoundOf' => [->(p) { A::BudgetForecast.autonomy_bound_of(p) }, 10],
      'hopsRoot' => [->(chain) { A.hops_root(chain) }, 14],
      'compactChain' => [->(chain) { A.compact_chain(chain) }, 14],
      'hopLeaf' => [->(hop) { A.hop_leaf(hop) }, 5],
      'compactChainShapeError' => [->(c) { A.compact_chain_shape_error(c) }, 27],
      'chainMemo' => [->(ops) { chain_memo(ops) }, 8],
      'receiptFor' => [->(prev, seq, pc, verify, at) { A.receipt_for(prev, seq, pc, verify, at) }, 60],
      'receiptChain' => [->(ops) { receipt_chain(ops) }, 21],
      'semanticSignal' => [->(r) { A::FrontierSignals.semantic_signal(r) }, 26],
      'progressSignal' => [->(r) { A::FrontierSignals.progress_signal(r) }, 26],
      'objectiveSignal' => [->(r) { A::FrontierSignals.objective_signal(r) }, 26],
      'tightenRiskInputs' => [->(base, obj) { A::FrontierSignals.tighten_risk_inputs(base, obj) }, 121],
      'subBudget' => [->(parent, alloc) { A::Risk.sub_budget(parent, alloc) }, 117],
      'debitConsolidated' => [->(parent, sub, c) { A::Risk.debit_consolidated(parent, sub, c) }, 288],
      'debitConsolidatedPath' => [->(path, c) { A::Risk.debit_consolidated_path(path, c) }, 72],
      'rechargeFull' => [->(b_max, now) { A::Risk.recharge_full(nil, b_max, now) }, 28],
      'approveClass' => [->(verbs, ttl, by, now, resource) { A.approve_class(verbs, ttl_ms: ttl, by: by, now: now, resource: resource.is_a?(String) ? resource : nil) }, 75],
      'classApprovalCovers' => [->(a, verb, resource, now) { A.class_approval_covers?(a, verb, resource, now) }, 675],
      'coveredByAny' => [->(l, verb, resource, now) { A.covered_by_any?(l, verb, resource, now) }, 36],
      'recordDecision' => [->(req, decision, by, at) { A.record_decision(req, decision, by, at) }, 2],
      'pendingRequests' => [->(reviews) { A.pending_requests(reviews) }, 5],
      'applyCosign' => [->(b, pol, now, full) { A.apply_cosign(b, pol, now, full: full == true) }, 48]
    }
  }.freeze

  CORPUS = HANDLERS.keys.to_h { |name| [name, Ref.load(name)] }.freeze

  # the fns of a corpus that another test file replays in full (the beacons corpus is replayed by test_ref_beacons.rb with the reference's value
  # semantics; here only this SDK's own signing function is). Nothing is pending: every other fn of every corpus has a handler in this file.
  REPLAYED_ELSEWHERE = { 'beacons' => TestRefBeacons::HANDLERS.keys - ['issueLivenessBeacon'] }.freeze

  def test_every_fn_of_each_corpus_is_replayed
    HANDLERS.each do |corpus, fns|
      all = CORPUS.fetch(corpus).keys
      elsewhere = REPLAYED_ELSEWHERE.fetch(corpus, [])
      assert_empty all - fns.keys - elsewhere, "#{corpus}: fns without a handler"
      assert_empty elsewhere - all, "#{corpus}: fns the corpus does not have"
      assert_empty elsewhere & fns.keys, "#{corpus}: fns replayed here and elsewhere"
    end
  end
  PQ = A.supported_suites.include?('ml-dsa-65')

  # a case that signs with ML-DSA needs a runtime that has it (OpenSSL >= 3.5)
  def self.pq_seed?(v)
    case v
    when Hash then v.key?('pqSeed') || v.each_value.any? { |x| pq_seed?(x) }
    when Array then v.any? { |x| pq_seed?(x) }
    else false
    end
  end

  def self.needs_pq?(c) = !PQ && (pq_seed?(c['args']) || Ref.canon(c['args']).match?(/ml-dsa/))

  def self.action_pin_constants
    r = A::ActionsRegistry
    { 'ACTION_PIN_ON_NEW' => r::ACTION_PIN_ON_NEW, 'EVOLUTION_CLASSES' => r::EVOLUTION_CLASSES, 'EVOLUTION_RECORD_KIND' => r::EVOLUTION_RECORD_KIND,
      'REAPPROVAL_KIND' => r::REAPPROVAL_KIND, 'EVOLUTION_DOMAIN' => r::EVOLUTION_DOMAIN, 'EVOLUTION_DIFF_DOMAIN' => r::EVOLUTION_DIFF_DOMAIN,
      'REAPPROVAL_DOMAIN' => r::REAPPROVAL_DOMAIN, 'MAX_EVOLUTION_STEPS' => r::MAX_EVOLUTION_STEPS, 'MAX_ESC_TIER' => r::MAX_ESC_TIER }
  end

  HANDLERS.each do |corpus, fns|
    fns.each do |fn, (handler, count)|
      define_method("test_replay_#{corpus}_#{fn}") do
        cases = CORPUS.fetch(corpus).fetch(fn)
        assert_equal count, cases.length
        Ref.run(self, cases, ->(*args) { handler.call(*args.map { |a| self.class.dnum(a) }) }, skip: ->(c) { self.class.needs_pq?(c) })
      end
    end
  end

  # ---- helpers without a corpus --------------------------------------------------------------------------------

  def kp(label) = A::KeyPair.new(Digest::SHA256.digest("sibling-ports/#{label}"))
  def d32(label) = A.b64e(Digest::SHA256.digest(label))

  def fraud_case = CORPUS['core-bond-settlement-java']['verifyFraudProof'].find { |c| c['name'] == 'verifyFraudProof/low/ok' }
  def grant = fraud_case['args'][2]
  def snapshot = fraud_case['args'][3]

  def test_constants
    assert_equal A.hash_canonical({}), A::EMPTY_PARAMS_DIGEST
    assert_equal 1, A::TEMPLATE_VERSION
    assert_equal [3, 3], [A::Actions::RISK_MAX, A::Actions::ESC_MAX]
    assert_equal %w[session principal org fleet], A::ACC_SCOPES
    assert_equal 'atlas-pca/acc-receipt-core/v1', A::ACC_RECEIPT_CORE_DOMAIN
  end

  def test_validate_risk_policy
    ok = A::DEFAULT_RISK_POLICY
    assert_nil A.validate_risk_policy(ok)
    w = ->(k, v) { ok.merge('weights' => ok['weights'].merge(k => v)) }
    {
      nil => 'risk_policy must be an object', 5 => 'risk_policy must be an object', 'x' => 'risk_policy must be an object',
      [] => 'risk_policy.weights missing', {} => 'risk_policy.weights missing',
      ok.merge('weights' => nil) => 'risk_policy.weights missing', ok.merge('weights' => 3) => 'risk_policy.weights missing',
      ok.merge('weights' => []) => 'risk_policy.weights.alpha must be finite and >= 0',
      w.call('alpha', -0.1) => 'risk_policy.weights.alpha must be finite and >= 0',
      w.call('zeta', Float::NAN) => 'risk_policy.weights.zeta must be finite and >= 0',
      w.call('gamma', '1') => 'risk_policy.weights.gamma must be finite and >= 0',
      ok.merge('theta1' => Float::INFINITY) => 'risk_policy.theta1 must be finite',
      ok.reject { |k, _| k == 'bMax' } => 'risk_policy.bMax must be finite',
      ok.merge('theta1' => -0.1) => 'risk_policy requires 0 <= theta1 <= theta2',
      ok.merge('theta1' => 0.7, 'theta2' => 0.6) => 'risk_policy requires 0 <= theta1 <= theta2',
      ok.merge('kappa' => 0) => 'risk_policy.kappa must be > 0',
      ok.merge('lambda' => -1) => 'risk_policy lambda/rho/bMax must be >= 0',
      ok.merge('rho' => -1) => 'risk_policy lambda/rho/bMax must be >= 0',
      ok.merge('bMax' => -1) => 'risk_policy lambda/rho/bMax must be >= 0'
    }.each { |pol, want| assert_equal want, A.validate_risk_policy(pol), pol.inspect[0, 80] }
    assert_nil A.validate_risk_policy(ok.merge('theta1' => 0, 'theta2' => 0, 'lambda' => 0, 'rho' => 0, 'bMax' => 0))
    assert_nil A.validate_risk_policy(w.call('alpha', 0))
  end

  def test_revocation_exposure_end_and_state_key
    assert_equal 61_500, A.revocation_exposure_end(1000, 500)
    assert_equal 1500, A.revocation_exposure_end(1000, 500, 0)
    assert_equal 'g:h', A.pca_state_key('g', 'h')
    assert_equal 'aud:a%20b%2F%3A:g:h', A.pca_state_key('g', 'h', nil, 'a b/:')
    assert_equal 'g:h', A.pca_state_key('g', 'h', 'grant-holder', 'aud')
    assert_equal 'aud::g:h', A.pca_state_key('g', 'h', 'audience-grant-holder')
    assert_equal 'aud:x:g:h', A.pca_state_key('g', 'h', 'audience-grant-holder', 'x')
  end

  def test_parse_intent_goal_v2
    s = d32('session')
    m = d32('map')
    assert_equal({ 'session' => s, 'mapDigest' => m }, A.parse_intent_goal_v2("pca-intent:v2:#{s}:#{m}"))
    ["pca-intent:v2:#{s}", "pca-intent:v2:#{s}:#{m}:", "pca-intent:v2:#{s}:#{m}:x", "pca-intent:v1:#{s}:#{m}", "pca-intent:v2:#{s[0, 42]}:#{m}",
     "pca-intent:v2:#{s}:#{m}=", " pca-intent:v2:#{s}:#{m}", '', nil, 5, [s, m]].each { |g| assert_nil A.parse_intent_goal_v2(g), g.inspect }
  end

  def test_validate_intent_wire
    ok = { 'ref' => d32('ref'), 'map_digest' => d32('map'), 'goal_salt' => 's', 'fidelity_ppm' => 1_000_000, 'residual_risk_ppm' => 0 }
    assert_nil A.validate_intent_wire(ok)
    assert_equal "'intent' must be an object", A.validate_intent_wire(nil)
    assert_equal "unknown field 'intent.x'", A.validate_intent_wire(ok.merge('x' => 1))
    assert_equal "missing field 'intent.ref'", A.validate_intent_wire(ok.reject { |k, _| k == 'ref' })
    assert_equal "'intent.fidelity_ppm' must be a safe integer in [0, 1000000]", A.validate_intent_wire(ok.merge('fidelity_ppm' => 1_000_001))
    assert_equal "'intent.fidelity_ppm' must be a safe integer in [0, 1000000]", A.validate_intent_wire(ok.merge('fidelity_ppm' => -0.0))
    assert_equal "'intent.residual_risk_ppm' must be a non-negative safe integer", A.validate_intent_wire(ok.merge('residual_risk_ppm' => -0.0))
    assert_equal "'intent.residual_risk_ppm' must be a non-negative safe integer", A.validate_intent_wire(ok.merge('residual_risk_ppm' => -1))
    assert_equal 0, ok['residual_risk_ppm'] # the input is not rewritten
  end

  def test_provenance_discharge_body
    req = { 'caveat_id' => 'c1', 'issuer' => 'iss', 'cap_hash' => 'h', 'bind' => 'b', 'ttl_ms' => 1000 }
    t = { 'iat' => 10, 'ttl_ms' => 1000, 'nonce' => 'n' }
    want = { 'v' => 1, 'kind' => 'pca-discharge', 'caveat_id' => 'c1', 'issuer' => 'iss', 'cap_hash' => 'h', 'bind' => 'b',
             'claims' => { 'a' => 1 }, 'iat' => 10, 'not_after' => 1010, 'nonce' => 'n' }
    assert_equal want, A.provenance_discharge_body(req, { 'ok' => true, 'claims' => { 'a' => 1 } }, t)
    assert_equal want, A.provenance_discharge_body(req, { ok: true, claims: { 'a' => 1 } }, t)
    with = A.provenance_discharge_body(req.merge('action_digest' => 'ad'), { 'ok' => true, 'claims' => {} }, t.merge('ttl_ms' => 1))
    assert_equal ['ad', 11, {}], with.values_at('action_digest', 'not_after', 'claims')
    refute A.provenance_discharge_body(req, { 'ok' => true, 'claims' => {} }, t).key?('action_digest')
    e = assert_raises(ArgumentError) { A.provenance_discharge_body(req, { 'ok' => false, 'code' => 'no_provenance' }, t) }
    assert_equal 'provenanceDischargeBody: the provenance gate refused (no_provenance)', e.message
    e = assert_raises(ArgumentError) { A.provenance_discharge_body(req, { ok: false, code: 'sym' }, t) }
    assert_equal 'provenanceDischargeBody: the provenance gate refused (sym)', e.message
    e = assert_raises(ArgumentError) { A.provenance_discharge_body(req, { 'ok' => true, 'claims' => {} }, t.merge('ttl_ms' => 1001)) }
    assert_equal 'provenanceDischargeBody: ttl_ms exceeds what the caveat accepts', e.message
  end

  def test_signed_intent_required_signs_the_jit_body
    c = Ref.load('intent-misc2')['signIntentRequired'].find { |x| !Ref.throws?(x['out']) && x['args'][3].nil? }
    body, kid, secret = Ref.dec(c['args'])
    jit = A::IntentJit
    orig = jit.method(:intent_required_body)
    seen = nil
    jit.define_singleton_method(:intent_required_body) do |i|
      seen = i
      body
    end
    begin
      assert_equal Ref.canon(c['out']), Ref.canon(A.signed_intent_required({ 'input' => 1 }, kid, A::KeyPair.new(secret)))
      assert_equal({ 'input' => 1 }, seen)
    ensure
      jit.define_singleton_method(:intent_required_body, orig)
    end
  end

  Verifier = Struct.new(:answer) do
    def verify(_document, _expected, _now) = answer.respond_to?(:call) ? answer.call : answer
  end

  def test_trust_from_attestation
    doc = { 'evidence' => 'x' }
    o = ->(answer) { { 'document' => doc, 'verifier' => Verifier.new(answer), 'expected' => {}, 'now_ms' => 7, 'pinned_attestors' => ['k'], 'passport_digest' => 'pd' } }
    base = { 'pinnedAttestors' => ['k'], 'passportDigest' => 'pd', 'now' => 7 }
    admitted = base.merge('verifiedEvidenceDigests' => [A.hash_canonical(doc)])
    none = base.merge('verifiedEvidenceDigests' => [])
    assert_equal admitted, A::Sandbox.trust_from_attestation(o.call({ 'ok' => true, 'bound' => true }))
    assert_equal admitted, A::Sandbox.trust_from_attestation(o.call({ ok: true, bound: true }))
    [{ 'ok' => true, 'bound' => false }, { 'ok' => false, 'bound' => true }, { 'ok' => true }, { 'ok' => 1, 'bound' => 1 }, nil, true, 'ok',
     -> { raise 'verifier down' }, -> { raise NotImplementedError }].each do |answer|
      assert_equal none, A::Sandbox.trust_from_attestation(o.call(answer)), answer.inspect
    end
  end

  # ---- ledger producer side ------------------------------------------------------------------------------------

  def head = { 'instance_id' => 'ins_1', 'principal' => 'p', 'size' => 2, 'root' => d32('root'), 'prev_root' => d32('prev'), 'timestamp' => T0 }

  def test_sign_tree_head_verifies_under_the_guardian
    g = kp('guardian')
    sth = A.sign_tree_head(g, head.merge('extra' => 1))
    assert_equal %w[guardian instance_id prev_root principal root sig size timestamp], sth.keys.sort
    assert_equal g.public, sth['guardian']
    msg = A::STH_DOMAIN.b + A.canon_bytes(head)
    assert A.verify_b64u(g.public, msg, sth['sig'])
    assert A.verify_tree_head(sth, g.public)
    refute A.verify_tree_head(sth.merge('size' => 3), g.public)
    refute A.verify_tree_head(sth, kp('other').public)
  end

  def test_cosign_tree_head_counts_towards_the_witness_threshold
    g = kp('guardian')
    w = kp('witness')
    sth = A.sign_tree_head(g, head)
    cosig = A.cosign_tree_head(sth, w)
    assert_equal %w[key sig], cosig.keys.sort
    assert_equal w.public, cosig['key']
    assert A.verify_b64u(w.public, A::STH_WITNESS_DOMAIN.b + A.canon_bytes(A.ledger_witness_body(sth)), cosig['sig'])
    assert A.verify_witness_cosignature(sth, cosig, w.public)
    refute A.verify_witness_cosignature(sth.merge('root' => d32('other')), cosig, w.public)
    policy = { 'threshold' => 1, 'witnessKeys' => [w.public] }
    assert A.verify_tree_head(sth.merge('witnesses' => [cosig]), g.public, policy)
    refute A.verify_tree_head(sth, g.public, policy)
  end

  def test_pq_tree_head_binds_the_suite
    skip 'ML-DSA needs OpenSSL >= 3.5' unless PQ
    g = kp('guardian')
    pq = A::PqKeyPair.from_seed('ML-DSA-65', Digest::SHA256.digest('sibling-ports/pq'))
    sth = A.sign_tree_head(g, head, alg: 'hybrid-ed25519-ml-dsa-65', pq: pq)
    assert_equal ['hybrid-ed25519-ml-dsa-65', pq.public], sth.values_at('alg', 'pq_pk')
    assert sth['pq_sig'].is_a?(String)
    assert A.verify_tree_head(sth, g.public, nil, { g.public => pq.public })
    refute A.verify_tree_head(sth, g.public, nil, {})
    cosig = A.cosign_tree_head(sth, g, alg: 'ml-dsa-65', pq: pq)
    assert_equal %w[alg key pq_pk sig], cosig.keys.sort
    assert A.verify_witness_cosignature(sth, cosig, g.public, { g.public => pq.public })
    assert_raises(ArgumentError) { A.sign_tree_head(g, head, alg: 'ml-dsa-65') }
    assert_raises(ArgumentError) { A.sign_tree_head(g, head, alg: 'rot13', pq: pq) }
  end

  def test_entry_commit_and_opening
    p = { 'action' => { 'verb' => 'read' } }
    c = A.entry_commit('s1', p)
    assert_equal A.hash_canonical({ 'salt' => 's1', 'pcactn_digest' => A.hash_canonical(p) }), c
    assert A.verify_opening(c, { 'salt' => 's1', 'pcactn' => p })
    refute A.verify_opening(c, { 'salt' => 's2', 'pcactn' => p })
    refute A.verify_opening(c, { 'salt' => 's1', 'pcactn' => p.merge('x' => 1) })
    refute A.verify_opening(c, nil)
    refute A.verify_opening(c, { 'salt' => 's1', 'pcactn' => Float::NAN })
  end

  # ---- bond settlement leftovers -------------------------------------------------------------------------------

  def test_append_settlement_anchors_the_salted_commitment
    c = CORPUS['core-bond-settlement-java']['verifySettlementCommit'].find { |x| x['name'] == 'verifySettlementCommit/open/ok' }
    commit, salt, record = c['args']
    ledger = A::TransparencyLedger.new('p')
    a = A.append_settlement(ledger, record, salt: salt)
    assert_equal({ 'index' => 0, 'commit' => commit, 'salt' => salt }, a)
    b = A.append_settlement(ledger, record)
    assert_equal 1, b['index']
    assert_equal 16, A.b64d(b['salt'], 16).bytesize
    refute_equal commit, b['commit']
    assert A.verify_settlement_commit(b['commit'], b['salt'], record)
    refute A.verify_settlement_commit(b['commit'], salt, record)
    assert_equal 2, ledger.head['size']
    refute_equal b['salt'], A.append_settlement(ledger, record)['salt']
  end

  def test_pool_accessors_and_messages
    pool = A::InsuranceCapitalPool.new
    assert_equal({ 'initial' => 0, 'premiumsIn' => 0, 'payoutsOut' => 0, 'balance' => 0 }, pool.state)
    pool = A::InsuranceCapitalPool.new(10)
    pool.collect_premium({ 'score' => 1 }, 500)
    pool.pay_claim(4)
    assert_equal [5, 4, 11], [pool.premiums_in, pool.payouts_out, pool.balance]
    e = assert_raises(ArgumentError) { pool.pay_claim(12) }
    assert_equal 'payClaim: insufficient pool capital (need 12, have 11)', e.message
    e = assert_raises(ArgumentError) { pool.pay_claim(0) }
    assert_equal 'payClaim: amount must be a positive finite number', e.message
    assert_raises(ArgumentError) { pool.pay_claim(Float::INFINITY) }
    e = assert_raises(ArgumentError) { A::InsuranceCapitalPool.new(Float::NAN) }
    assert_equal 'InsuranceCapitalPool: initial capital must be a non-negative finite number', e.message
    refute pool.can_cover?(Float::NAN)
    refute pool.can_cover?(-1)
    refute pool.can_cover?('1')
    assert pool.can_cover?(11)
    refute pool.can_cover?(11.5)
  end

  # ---- optimistic producer side --------------------------------------------------------------------------------

  def pcactn(cls = 'reversible') = { 'action' => { 'verb' => 'charge', 'resource' => 'merchant:m1', 'reversibility_class' => cls } }

  def open_claim(claimed_r, **kw)
    A.open_optimistic(pcactn, kp('agent'), bond_ref: 'b1', claimed_r: claimed_r, issued_at: T0, server_now: T0, **kw)
  end

  def test_open_optimistic_passes_the_claim_check
    claim = open_claim(0.25)
    assert_equal({ 'pcactn_digest' => A.pcactn_digest(pcactn), 'bond_ref' => 'b1', 'claimed_r' => 0.25, 'reversibility_class' => 'reversible',
                   'issued_at' => T0, 'challenge_window_ms' => 300_000 }, claim.reject { |k, _| k == 'sig' })
    assert_equal 'ok', A.claim_check(claim, A.pcactn_digest(pcactn), kp('agent').public, T0)
    assert_equal 'signature', A.claim_check(claim, A.pcactn_digest(pcactn), kp('other').public, T0)
    assert_equal 60_000, open_claim(0, challenge_window_ms: 60_000)['challenge_window_ms']
    unknown = A.open_optimistic({ 'action' => { 'verb' => 'x' } }, kp('agent'), bond_ref: 'b', claimed_r: 0, issued_at: T0, server_now: T0)
    assert_equal 'unknown', unknown['reversibility_class']
    assert_equal 'unknown', A.open_optimistic(nil, kp('agent'), bond_ref: 'b', claimed_r: 0, issued_at: T0, server_now: T0)['reversibility_class']
    # issued_at defaults to the server clock; both default to the wall clock
    assert_equal T0, A.open_optimistic(pcactn, kp('agent'), bond_ref: 'b', claimed_r: 0, server_now: T0)['issued_at']
    now = (Time.now.to_f * 1000).floor
    assert_in_delta now, A.open_optimistic(pcactn, kp('agent'), bond_ref: 'b', claimed_r: 0)['issued_at'], 60_000
  end

  def test_open_optimistic_refusals
    e = assert_raises(ArgumentError) { A.open_optimistic(pcactn('irreversible'), kp('agent'), bond_ref: 'b', claimed_r: 0, issued_at: T0, server_now: T0) }
    assert_match(/\AopenOptimistic: irreversible actions cannot use the optimistic fast-path/, e.message)
    [Float::NAN, Float::INFINITY, nil, '0'].each do |r|
      e = assert_raises(ArgumentError) { open_claim(r) }
      assert_equal 'openOptimistic: claimedR must be finite', e.message
    end
    [nil, 1, 86_400_001, Float::NAN].each do |w|
      e = assert_raises(ArgumentError) { open_claim(0, challenge_window_ms: w) }
      assert_match(/\AopenOptimistic: /, e.message)
    end
    assert_raises(ArgumentError) { A.open_optimistic(pcactn, kp('agent'), bond_ref: 'b', claimed_r: 0, issued_at: T0 - 86_400_000, server_now: T0) }
    tight = A::DEFAULT_WINDOW_POLICY.merge('defaultWindowMs' => 2000, 'maxWindowMs' => 2000)
    assert_equal 2000, open_claim(0, window_policy: tight)['challenge_window_ms']
    assert_raises(ArgumentError) { open_claim(0, window_policy: tight, challenge_window_ms: 2001) }
  end

  def test_file_fraud_proof_replays_the_policy_vm
    adj = A::OptimisticAdjudication
    low = open_claim(0)
    proof = A.file_fraud_proof(low, pcactn, grant, snapshot)
    assert_equal 'risk-understated', proof['kind']
    assert_equal 'claimed r=0 but real r=0.100', proof['reason']
    assert_equal({ 'releaseGuardianShare' => true, 'r' => 0.1, 'optimisticAllowed' => true }, proof['decision'])
    assert_equal [low['pcactn_digest'], 'b1', 0, A::DEFAULT_R_MARGIN], proof.values_at('pcactn_digest', 'bond_ref', 'claimed_r', 'r_margin')
    assert_equal snapshot, proof['evidence']
    assert_equal true, adj.verify_fraud_proof(low, proof, grant, snapshot)['fraudulent']
    # the snapshot's own grant member never reaches the evidence, and the supplied grant is the one replayed
    assert_equal snapshot, A.file_fraud_proof(low, pcactn, grant, snapshot.merge('grant' => { 'id' => 'forged' }))['evidence']

    assert_nil A.file_fraud_proof(open_claim(0.1), pcactn, grant, snapshot) # compliant: the claim covers the real risk
    assert_nil A.file_fraud_proof(open_claim(0.05), pcactn, grant, snapshot, r_margin: 0.06)
    assert_equal 0, A.file_fraud_proof(open_claim(0.05), pcactn, grant, snapshot, r_margin: -5)['r_margin']
    assert_equal 'risk-understated', A.file_fraud_proof(open_claim(0.05), pcactn, grant, snapshot, r_margin: Float::NAN)['kind']
    assert_nil A.file_fraud_proof(low, pcactn('rate_limited'), grant, snapshot) # another action cannot be framed
    assert_nil A.file_fraud_proof(low, pcactn, grant, nil)

    irr = A.file_fraud_proof(open_claim(1).merge('reversibility_class' => 'irreversible'), pcactn, grant, snapshot)
    assert_equal %w[irreversible irreversible\ action\ took\ the\ optimistic\ path], irr.values_at('kind', 'reason')

    denied_snapshot = snapshot.merge('action' => { 'action' => snapshot['action']['action'].merge('params' => { 'amount' => 1000 }) })
    denied = A.file_fraud_proof(open_claim(1), pcactn, grant, denied_snapshot)
    assert_equal 'policy-denied', denied['kind']
    assert_match(/\APolicy VM denied the action: ./, denied['reason'])
    assert_equal false, denied['decision']['releaseGuardianShare']
    assert_equal true, adj.verify_fraud_proof(open_claim(1), denied, grant, denied_snapshot)['fraudulent']
  end

  # ---- objective-risk binding ----------------------------------------------------------------------------------

  class Engine
    attr_reader :seen

    def initialize(model_id: 'm1', calibration: 'cal-digest', result: nil, &raises)
      @model_id = model_id
      @calibration = calibration
      @result = result
      @raises = raises
    end

    def embedder_model_id(config) = config['dim'] == 8 ? @model_id : 'other'
    def calibration_digest(_calibration) = @calibration

    def evaluate(action, opts)
      @raises&.call
      @seen = [action, opts]
      @result
    end
  end

  COMMIT = { 'v' => 1, 'embedder' => { 'scheme' => 'native', 'model_id' => 'm1', 'config' => { 'dim' => 8 } }, 'goal' => { 'commit' => 'gc' },
             'registry_digest' => 'rd', 'graph_digest' => 'gd', 'authorized_kinds' => %w[pay], 'scope' => 'acct:1' }.freeze
  VALID = { 'valid' => true, 'inputs' => { 'reversibility' => 0.9, 'blastRadius' => 0.2, 'semanticDistance' => 0.1, 'extra' => 1 }, 'r' => 0.3,
            'evidenceDigest' => 'ed' }.freeze
  INSTANCE = { 'registry' => { 'ops' => [] }, 'graph' => { 'nodes' => [] } }.freeze

  def committed(objective) = grant.merge('caveats' => grant['caveats'].map { |c| c['type'] == 'envelope' ? c.merge('objective_risk' => objective) : c })
  def resolve(objective, **kw) = A.resolve_objective_risk(grant: committed(objective), action: { 'verb' => 'pay' }, instance: INSTANCE, **kw)

  def test_read_objective_commitment
    assert_equal({}, A.read_objective_commitment(grant))
    assert_equal({}, A.read_objective_commitment(nil))
    assert_equal({ 'commitment' => COMMIT }, A.read_objective_commitment(committed(COMMIT)))
    full = COMMIT.merge('calibration_digest' => 'cd', 'denominations' => [], 'on_mismatch' => 'heuristic')
    assert_equal({ 'commitment' => full }, A.read_objective_commitment(committed(full)))
    version = 'objective_risk: unsupported shape/version'
    embedder = 'objective_risk.embedder must be { scheme: "native", model_id, config }'
    {
      nil => version, [] => version, COMMIT.merge('v' => 2) => version, COMMIT.merge('v' => '1') => version,
      COMMIT.merge('embedder' => nil) => embedder,
      COMMIT.merge('embedder' => COMMIT['embedder'].merge('scheme' => 'byo')) => embedder,
      COMMIT.merge('embedder' => COMMIT['embedder'].merge('model_id' => '')) => embedder,
      COMMIT.merge('embedder' => COMMIT['embedder'].merge('config' => [])) => embedder,
      COMMIT.merge('goal' => {}) => 'objective_risk.goal must be a goal commitment',
      COMMIT.merge('goal' => { 'commit' => '' }) => 'objective_risk.goal must be a goal commitment',
      COMMIT.merge('registry_digest' => '') => 'objective_risk needs registry_digest and graph_digest',
      COMMIT.reject { |k, _| k == 'graph_digest' } => 'objective_risk needs registry_digest and graph_digest',
      COMMIT.merge('calibration_digest' => nil) => 'objective_risk.calibration_digest must be a string',
      COMMIT.merge('authorized_kinds' => 'pay') => 'objective_risk.authorized_kinds must be string[]',
      COMMIT.merge('authorized_kinds' => [1]) => 'objective_risk.authorized_kinds must be string[]',
      COMMIT.merge('denominations' => {}) => 'objective_risk.denominations must be an array',
      COMMIT.merge('on_mismatch' => 'allow') => 'objective_risk.on_mismatch must be "deny" or "heuristic"'
    }.each { |objective, why| assert_equal({ 'malformed' => why }, A.read_objective_commitment(committed(objective)), objective.inspect[0, 80]) }
    assert_equal({ 'commitment' => COMMIT.merge('v' => 1.0) }, A.read_objective_commitment(committed(COMMIT.merge('v' => 1.0))))
  end

  def test_resolve_objective_risk_reproduced
    assert_equal({ 'mode' => 'none' }, A.resolve_objective_risk(grant: grant, action: {}, instance: INSTANCE, engine: Engine.new(result: VALID)))
    engine = Engine.new(result: VALID)
    got = resolve(COMMIT, engine: engine)
    assert_equal({ 'mode' => 'objective', 'inputs' => { 'reversibility' => 0.9, 'blastRadius' => 0.2, 'semanticDistance' => 0.1 }, 'r' => 0.3,
                   'evidenceDigest' => 'ed' }, got)
    action, opts = engine.seen
    assert_equal({ 'verb' => 'pay' }, action)
    weights = A.read_envelope(grant)['risk_policy']['weights']
    assert_equal({ 'registry' => INSTANCE['registry'], 'graph' => INSTANCE['graph'], 'authorizedKinds' => %w[pay], 'scope' => 'acct:1',
                   'embedder' => COMMIT['embedder'], 'goal' => COMMIT['goal'], 'commitments' => { 'registryDigest' => 'rd', 'graphDigest' => 'gd' },
                   'denominations' => [], 'weights' => weights, 'taint' => 1, 'age' => 1 }, opts)

    cal = COMMIT.merge('calibration_digest' => 'cal-digest', 'denominations' => ['usd'])
    engine = Engine.new(result: VALID)
    A.resolve_objective_risk(grant: committed(cal), action: {}, instance: INSTANCE.merge('calibration' => { 'set' => 1 }), engine: engine, taint: 0.5, age: 0)
    opts = engine.seen[1]
    assert_equal [{ 'registryDigest' => 'rd', 'graphDigest' => 'gd', 'calibrationDigest' => 'cal-digest' }, ['usd'], 0.5, 0, { 'set' => 1 }],
                 opts.values_at('commitments', 'denominations', 'taint', 'age', 'calibration')
  end

  def test_resolve_objective_risk_fails_closed
    miss = ->(*reasons, on: 'deny') { { 'mode' => 'mismatch', 'reasons' => reasons, 'onMismatch' => on } }
    ok = Engine.new(result: VALID)
    assert_equal miss.call('objective_risk: unsupported shape/version'), resolve(COMMIT.merge('v' => 2), engine: ok)
    assert_equal miss.call('the grant commits objective-risk facts but the instance holds no objective-risk config'),
                 A.resolve_objective_risk(grant: committed(COMMIT), action: {}, instance: nil, engine: ok)
    # the built-in engine refuses the stand-in config of these tests (dim, not dims)
    assert_equal miss.call('objective risk evaluation error (fail closed): native config: dims must be an integer in [8, 65536]'), resolve(COMMIT)
    assert_equal miss.call('embedder model_id does not match the committed one'), resolve(COMMIT, engine: Engine.new(model_id: 'm2', result: VALID))
    cal = COMMIT.merge('calibration_digest' => 'cd')
    assert_equal miss.call('calibration set does not match the committed digest'), resolve(cal, engine: ok) # the instance holds none
    assert_equal miss.call('calibration set does not match the committed digest'),
                 A.resolve_objective_risk(grant: committed(cal), action: {}, instance: INSTANCE.merge('calibration' => {}), engine: ok)
    assert_equal miss.call('a', 'b'), resolve(COMMIT, engine: Engine.new(result: { 'valid' => false, 'reasons' => %w[a b] }))
    assert_equal miss.call('objective risk evaluation error (fail closed): boom'), resolve(COMMIT, engine: Engine.new { raise 'boom' })
    refute_equal 'objective', resolve(COMMIT, engine: Engine.new(result: nil))['mode']

    # a grant asks for the heuristic: honoured only when the instance opts in
    heuristic = COMMIT.merge('on_mismatch' => 'heuristic')
    assert_equal 'deny', resolve(heuristic)['onMismatch']
    opted = INSTANCE.merge('allow_heuristic_fallback' => true)
    assert_equal miss.call('objective risk evaluation error (fail closed): native config: dims must be an integer in [8, 65536]', on: 'heuristic'),
                 A.resolve_objective_risk(grant: committed(heuristic), action: {}, instance: opted)
    assert_equal 'deny', A.resolve_objective_risk(grant: committed(heuristic), action: {}, instance: INSTANCE.merge('allow_heuristic_fallback' => 1))['onMismatch']
    assert_equal 'deny', A.resolve_objective_risk(grant: committed(COMMIT), action: {}, instance: opted)['onMismatch']
    assert_equal 'deny', A.resolve_objective_risk(grant: committed(COMMIT.merge('on_mismatch' => 'deny')), action: {}, instance: opted)['onMismatch']
  end

  # ---- durable store openers -----------------------------------------------------------------------------------

  def test_durable_openers
    require 'tmpdir'
    Dir.mktmpdir('pca-durable-open') do |dir|
      kv = A.open_durable_state(dir: File.join(dir, 'ops'))
      store = A.durable_operation_store(kv)
      assert_kind_of A::KvOperationStore, store
      assert_kind_of A::KvOperationStore, A.durable_operation_store(kv, prefix: 'x:', scope: 'process')
      ledger = A.open_durable_budget_ledger(dir: File.join(dir, 'budget'))
      assert_kind_of A::KvBudgetLedger, ledger
      assert_kind_of A::KvBudgetLedger, A.open_durable_budget_ledger(dir: File.join(dir, 'budget2'), lock_timeout_ms: 500)
    end
  end
end
