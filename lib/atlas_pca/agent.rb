# frozen_string_literal: true

# The agent / issuer side of PCA: produce the proofs this gem's verifier checks. Same wire as the TypeScript reference
# (mintGrant, delegate, buildPCActn, signEscalationAnswer, signDischarge, signPassport, signWorkflow, ...), BYTE-exact
# wherever the algorithm is deterministic (Ed25519, canonical JSON, digests, chain structure); the shared producer vectors
# (producer-vectors.json: fixed keys, nonces and timestamps) pin it.
#
# Values are the same String-keyed Hashes and Arrays the verifier takes. Signing: Ed25519 (OpenSSL) and, with OpenSSL >= 3.5,
# ML-DSA / SLH-DSA and their hybrid suites (randomised, so cross-verified rather than compared byte for byte). fn-dsa-* and
# less-cat1 are verify-only (UnsupportedSigner).
require 'securerandom'

module AtlasPca
  PCA_HEADER = 'PCA-Action'
  DEFAULT_TTL_MS = 20 * 60_000
  GOAL_DOMAIN = "atlas-pca/goal/v1\x00"
  DEFAULT_RISK_POLICY = {
    'weights' => { 'alpha' => 0.25, 'beta' => 0.2, 'gamma' => 0.2, 'delta' => 0.2, 'epsilon' => 0.1, 'zeta' => 0.05 },
    'theta1' => 0.25, 'theta2' => 0.6, 'kappa' => 1, 'lambda' => 0.0005, 'rho' => 0.5, 'bMax' => 1
  }.freeze

  # The suite is registered but this runtime cannot SIGN with it. The message starts `unsupported_suite: `.
  class UnsupportedSigner < StandardError; end

  # An Ed25519 identity. #public is the base64url key id every artifact names.
  class KeyPair
    attr_reader :public

    def self.generate = new(SecureRandom.random_bytes(32))
    def self.from_seed_b64u(seed) = new(AtlasPca.b64d(seed, 32) || raise(ArgumentError, 'an Ed25519 seed is 32 canonical base64url bytes'))

    def initialize(seed)
      raise ArgumentError, 'an Ed25519 seed is 32 bytes' unless seed.is_a?(String) && seed.bytesize == 32

      @pkey = OpenSSL::PKey.new_raw_private_key('ED25519', seed.b)
      @public = AtlasPca.b64e(@pkey.raw_public_key)
    end

    def sign(msg) = @pkey.sign(nil, msg.b)
    def inspect = "#<AtlasPca::KeyPair public=#{@public}>" # never print the secret
  end

  # A post-quantum key pair (OpenSSL >= 3.5): prim is 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128f' or 'SLH-DSA-SHA2-256s'.
  class PqKeyPair
    attr_reader :prim, :public

    def self.generate(prim) = new(prim)

    def initialize(prim)
      @prim = prim
      @pkey = OpenSSL::PKey.generate_key(prim)
      @public = AtlasPca.b64e(@pkey.raw_public_key)
    rescue StandardError, NotImplementedError
      raise UnsupportedSigner, "unsupported_suite: #{prim} (needs OpenSSL >= 3.5)"
    end

    def sign(msg) = @pkey.sign(nil, msg.b)
    def inspect = "#<AtlasPca::PqKeyPair #{@prim}>"
  end

  module_function

  # Signature parts of msg under alg (nil == ed25519): [sig_b64u, pq_sig_b64u_or_nil]. Hybrid: sig is Ed25519 and pq_sig the PQ
  # signature over the SAME message (nested: over msg || the Ed25519 signature). A pure PQ suite puts the PQ signature in sig.
  def sign_with_suite(alg, ed, pq, msg)
    alg ||= 'ed25519'
    spec = SIG_SUITES[alg]
    unless spec
      raise UnsupportedSigner, "unsupported_suite: #{alg}" if REGISTERED_SUITES.include?(alg)

      raise ArgumentError, "unknown signature alg #{alg.inspect}"
    end
    _len, needs_pk, needs_pq_sig, prim, nested = spec
    unless needs_pk
      raise ArgumentError, 'ed25519 needs an Ed25519 key' if ed.nil?

      return [b64e(ed.sign(msg)), nil]
    end
    raise UnsupportedSigner, "unsupported_suite: #{alg}" if prim == 'LESS-cat1'
    raise ArgumentError, "#{alg} needs a #{prim} key pair" unless pq && pq.prim == prim
    return [b64e(pq.sign(msg)), nil] unless needs_pq_sig

    raise ArgumentError, "#{alg} needs an Ed25519 key" if ed.nil?

    e = ed.sign(msg)
    [b64e(e), b64e(pq.sign(nested ? msg.b + e : msg))]
  end

  def bind_suite(body, alg, pq)
    return body.dup if alg.nil? || alg == 'ed25519'
    raise ArgumentError, "#{alg} needs a post-quantum key pair" if pq.nil?

    body.merge('alg' => alg, 'pq_pk' => pq.public)
  end

  # body + sig (and alg/pq_pk/pq_sig for a non-default suite): the signature covers utf8(domain) || strictCanonical(body).
  def sign_artifact(domain, body, ed, alg: nil, pq: nil)
    full = bind_suite(body, alg, pq)
    sig, pq_sig = sign_with_suite(alg, ed, pq, domain.b + strict_bytes(full))
    full['sig'] = sig
    full['pq_sig'] = pq_sig if pq_sig
    full
  end

  def sign_body(ed, domain, body) = b64e(ed.sign(domain.b + strict_bytes(body)))

  # Strict canonical bytes: raises on a value outside the strict JSON profile (the verifiers would refuse it).
  def strict_bytes(v)
    parse_json(canonicalize(v), any_top: true) # round trip through the strict parser proves the text is in profile
    canon_bytes(v)
  end

  # Salted commitment to the plaintext goal.
  def goal_commit_of(goal, salt) = hash_canonical({ 'd' => GOAL_DOMAIN, 'goal' => goal, 'salt' => salt })

  def seal_cap(issuer, holder, caveats, parent, holder_pq, ed, alg, pq)
    body = { 'issuer' => issuer, 'holder' => holder, 'caveats' => caveats, 'parent' => parent }
    body['holder_pq'] = holder_pq if holder_pq
    digest = hash_canonical(bind_suite(body, alg, pq))
    sig, pq_sig = sign_with_suite(alg, ed, pq, CAP_DOMAIN + b64d(digest, 32))
    cap = { 'id' => digest, 'issuer' => issuer, 'holder' => holder, 'caveats' => caveats, 'body_digest' => digest, 'sig' => sig }
    cap['parent'] = parent if parent
    cap['holder_pq'] = holder_pq if holder_pq
    if alg && alg != 'ed25519'
      cap['alg'] = alg
      cap['pq_pk'] = pq.public
      cap['pq_sig'] = pq_sig if pq_sig
    end
    cap
  end

  def clone_json(v) = parse_json(canonicalize(v), any_top: true)

  # A root capability signed by the principal. holder_pq is the holder's PQ public key (b64u), committed as holder_pq.
  def mint_root(principal, holder, caveats, holder_pq: nil, alg: nil, pq: nil)
    seal_cap(principal.public, holder, clone_json(caveats), nil, holder_pq && holder_pq_commitment(holder_pq), principal, alg, pq)
  end

  # A child capability: caveats = parent.caveats ++ added (append-only, so never wider), signed by the parent's holder.
  # to_holder nil keeps the holder (and its holder_pq); otherwise it is rebound to a sub-agent.
  def delegate_cap(parent, signer, to_holder: nil, added: [], holder_pq: nil, alg: nil, pq: nil)
    holder = to_holder || parent['holder']
    hp = if holder_pq then holder_pq_commitment(holder_pq)
         elsif holder == parent['holder'] then parent['holder_pq']
         end
    seal_cap(parent['holder'], holder, clone_json(parent['caveats']) + clone_json(added), cap_hash(parent), hp, signer, alg, pq)
  end

  def attenuate_cap(parent, added, signer, **kw) = delegate_cap(parent, signer, added: added, **kw)

  def risk_policy_error(p)
    w = p.is_a?(Hash) ? p['weights'] : nil
    return 'risk_policy.weights missing' unless w.is_a?(Hash)

    %w[alpha beta gamma delta epsilon zeta].each do |k|
      return "risk_policy.weights.#{k} must be finite and >= 0" unless w[k].is_a?(Numeric) && w[k].finite? && w[k] >= 0
    end
    %w[theta1 theta2 kappa lambda rho bMax].each do |k|
      return "risk_policy.#{k} must be finite" unless p[k].is_a?(Numeric) && p[k].finite?
    end
    return 'risk_policy requires 0 <= theta1 <= theta2' if p['theta1'].negative? || p['theta2'] < p['theta1']
    return 'risk_policy.kappa must be > 0' unless p['kappa'].positive?
    return 'risk_policy lambda/rho/bMax must be >= 0' if p['lambda'].negative? || p['rho'].negative? || p['bMax'].negative?

    nil
  end

  # Root Intent Grant: a root capability whose first caveat is the policy envelope ('predicates', 'caveats', 'agent_binding',
  # 'risk_policy', optional 'units'/'tighten'/'actions'/'provenance'/...). Only the salted hash of goal goes in the grant. Returns
  # { 'grant', 'goal_commit', 'goal_salt' }. Shortcut: the optional envelope members are signed as given; the verifier refuses
  # a malformed one.
  def mint_grant(principal, holder, envelope, goal, salt: nil, holder_pq: nil, alg: nil, pq: nil)
    raise ArgumentError, 'mint_grant: goal required' unless goal.is_a?(String) && !goal.empty?
    raise ArgumentError, 'mint_grant: envelope.predicates and envelope.caveats required' unless envelope['predicates'] && envelope['caveats']

    bad = risk_policy_error(envelope['risk_policy'])
    raise ArgumentError, "mint_grant: #{bad}" if bad
    raise ArgumentError, "mint_grant: model_polarity must be 'legacy' when present" if envelope.key?('model_polarity') && envelope['model_polarity'] != 'legacy'
    if envelope.key?('provenance')
      pe = prov_envelope_error(envelope['provenance'])
      raise ArgumentError, "mint_grant: #{pe}" if pe
    end

    salt ||= b64e(SecureRandom.random_bytes(16))
    env = { 'type' => 'envelope', 'goal_commit' => goal_commit_of(goal, salt), 'predicates' => envelope['predicates'],
            'caveats' => envelope['caveats'], 'agent_binding' => envelope['agent_binding'] || {}, 'risk_policy' => envelope['risk_policy'] }
    %w[objective_risk progress units tighten model_polarity template_ref actions provenance].each { |k| env[k] = envelope[k] unless envelope[k].nil? }
    grant = mint_root(principal, holder, [env], holder_pq: holder_pq, alg: alg, pq: pq)
    { 'grant' => grant, 'goal_commit' => env['goal_commit'], 'goal_salt' => salt }
  end

  # ---- plan + PCActn ----

  def plan_node_leaf(n)
    plan_leaf(n['id'], n, conditions_digest(n['pre'], n['post']))
  end

  def plan_prove(hs, idx, out)
    return if hs.length == 1

    k = split_point(hs.length)
    if idx < k
      plan_prove(hs[0...k], idx, out)
      out << { 'side' => 'R', 'hash' => b64e(build(hs[k..])) }
    else
      plan_prove(hs[k..], idx - k, out)
      out << { 'side' => 'L', 'hash' => b64e(build(hs[0...k])) }
    end
  end

  def plan_hashes(nodes)
    raise ArgumentError, 'commit_plan: empty plan' if nodes.empty?

    ids = nodes.map { |n| n['id'] }
    dup = ids.find { |i| ids.count(i) > 1 }
    raise ArgumentError, "commit_plan: duplicate node id #{dup}" if dup

    nodes.map { |n| leaf_hash(plan_node_leaf(n)) }
  end

  # Merkle commitment of a plan (RFC 6962 shape, domain separated): { 'root', 'proofs' => { id => inclusion proof } }. A node is
  # { 'id', 'verb', 'resource', 'params_digest'?, 'reversibility_class'?, 'pre'?, 'post'? }.
  def commit_plan(nodes)
    hs = plan_hashes(nodes)
    proofs = {}
    nodes.each_with_index do |n, i|
      path = []
      plan_prove(hs, i, path)
      proofs[n['id']] = { 'index' => i, 'size' => hs.length, 'path' => path }
    end
    { 'root' => b64e(build(hs)), 'proofs' => proofs }
  end

  # Sign a PCActn body (without 'sig') with the leaf holder's key under the suite.
  def sign_pcactn(body, leaf, alg: nil, pq: nil)
    full = bind_suite(body, alg, pq)
    sig, pq_sig = sign_with_suite(alg, leaf, pq, threshold_message(full))
    full['sig'] = sig
    full['pq_sig'] = pq_sig if pq_sig
    full
  end

  # A complete signed PCActn for plan node node_id (wire format v2). extra holds the optional SIGNED slots by wire name (nonce,
  # caution, rationale_commitment, progress_step, prohibition_evidence, tool_binding, intent, intent_session, fresh_at; also
  # provenance / attestation / freshness / risk_claim to replace the empty stubs).
  def build_pcactn(grant:, chain:, plan:, node_id:, counter:, signer:, aud:, params: nil, iat: nil, exp: nil, ttl_ms: DEFAULT_TTL_MS,
                   extra: {}, alg: nil, pq: nil)
    raise ArgumentError, 'build_pcactn: aud (audience) is required' unless aud.is_a?(String) && !aud.empty?

    node = plan.find { |n| n['id'] == node_id } or raise ArgumentError, "build_pcactn: unknown plan node #{node_id}"
    digest = params_digest(params)
    raise ArgumentError, "build_pcactn: params do not match plan node #{node_id}'s params_digest" if node['params_digest'] && node['params_digest'] != digest

    hs = plan_hashes(plan)
    path = []
    idx = plan.index(node)
    plan_prove(hs, idx, path)
    iat ||= (Time.now.to_f * 1000).to_i
    body = {
      'ver' => 2,
      'action' => { 'verb' => node['verb'], 'resource' => node['resource'], 'params_digest' => digest,
                    'reversibility_class' => node['reversibility_class'] || DEFAULT_REV },
      'grant_ref' => grant['id'], 'cap_chain' => chain,
      'plan' => { 'root' => b64e(build(hs)), 'inclusion_proof' => { 'index' => idx, 'size' => hs.length, 'path' => path },
                  'node_id' => node_id, 'conditions_digest' => conditions_digest(node['pre'], node['post']) },
      'attestation' => { 'quote_digest' => '', 'epoch' => 0, 'model_id' => 'unattested', 'measurement' => '', 'operator' => 'unattested' },
      'provenance' => { 'causal_hash' => '', 'taint_level' => 0, 'trusted_refs' => [] },
      'freshness' => { 'beacon_ref' => '', 'epoch' => 0, 'accumulator_witness' => '' },
      'counter' => counter, 'risk_claim' => { 'r' => 0, 'inputs' => {} },
      'aud' => aud, 'iat' => iat, 'exp' => exp || (iat + ttl_ms)
    }
    extra.each { |k, v| body[k] = v unless v.nil? }
    sign_pcactn(body, signer, alg: alg, pq: pq)
  end

  # HTTP headers the native middleware reads: PCA-Action (base64url of the PCActn JSON) and, when given, PCA-Discharges
  # (base64url JSON array), PCA-Narrow and PCA-Escalation-Answer.
  def pca_headers(pcactn, discharges: [], narrow: nil, escalation_answer: nil)
    enc = ->(v) { b64e(canon_bytes(v)) }
    h = { PCA_HEADER => enc.call(pcactn) }
    h['PCA-Discharges'] = enc.call(discharges) unless discharges.empty?
    h['PCA-Narrow'] = enc.call(narrow) if narrow
    h['PCA-Escalation-Answer'] = enc.call(escalation_answer) if escalation_answer
    h
  end

  # ---- escalation answer, discharge, narrow ----

  # The approving principal's signed answer ('allow' or 'deny') to an escalation request (a Hash carrying 'policy_digest',
  # 'action_digest', 'history_head' and, K7, the 'render_digest' the approver saw).
  def sign_escalation_answer(principal, request, decision, iat, expires_at, nonce: nil, alg: nil, pq: nil)
    raise ArgumentError, "decision must be 'allow' or 'deny'" unless %w[allow deny].include?(decision)

    body = { 'v' => 1, 'kind' => 'pca-escalation-answer', 'principal' => principal.public, 'policy_digest' => request['policy_digest'],
             'action_digest' => request['action_digest'], 'history_head' => request['history_head'], 'decision' => decision,
             'iat' => iat, 'expires_at' => expires_at, 'nonce' => nonce || b64e(SecureRandom.random_bytes(16)) }
    body['render_digest'] = request['render_digest'] if request['render_digest'].is_a?(String)
    sign_artifact("atlas-pca/escalation-answer/v1\x00", body, principal, alg: alg, pq: pq)
  end

  def needs_discharge_caveat(id, issuer, issuer_class, require_claims, bind: 'chain_hop', ttl_ms: 300_000, issuer_spiffe: nil)
    c = { 'type' => 'needs_discharge', 'id' => id, 'issuer' => issuer, 'issuer_class' => issuer_class, 'bind' => bind,
          'ttl_ms' => ttl_ms, 'require' => require_claims }
    c['issuer_spiffe'] = issuer_spiffe if issuer_spiffe
    c
  end

  def sealed_caveat = { 'type' => 'sealed' }
  def max_uses_caveat(id, n, until_ms) = { 'type' => 'max_uses', 'id' => id, 'n' => n, 'until' => until_ms }

  # The pinned third party's discharge of a needs_discharge caveat (cap_hash_of_hop = cap_hash of the hop carrying it; bind
  # 'action' also needs the discharge_action_digest of the exact PCActn).
  def sign_discharge(issuer, caveat_id, issuer_label, cap_hash_of_hop, claims, iat, not_after, bind: 'chain_hop', action_digest: nil,
                     nonce: nil, alg: nil, pq: nil)
    body = { 'v' => 1, 'kind' => 'pca-discharge', 'caveat_id' => caveat_id, 'issuer' => issuer_label, 'cap_hash' => cap_hash_of_hop,
             'bind' => bind, 'claims' => claims, 'iat' => iat, 'not_after' => not_after, 'nonce' => nonce || b64e(SecureRandom.random_bytes(16)) }
    body['action_digest'] = action_digest if action_digest
    sign_artifact("atlas-pca/discharge/v1\x00", body, issuer, alg: alg, pq: pq)
  end

  # The leaf holder's self-attenuation, presented beside the PCActn.
  def sign_narrow(holder, leaf_cap_hash, caveats, iat, not_after, action_digest: nil, nonce: nil, alg: nil, pq: nil)
    body = { 'v' => 1, 'kind' => 'pca-narrow', 'cap_hash' => leaf_cap_hash, 'holder' => holder.public, 'caveats' => caveats,
             'iat' => iat, 'not_after' => not_after, 'nonce' => nonce || b64e(SecureRandom.random_bytes(16)) }
    body['action_digest'] = action_digest if action_digest
    sign_artifact("atlas-pca/narrow/v1\x00", body, holder, alg: alg, pq: pq)
  end

  # ---- passport ----

  def passport_fingerprint(p)
    hash_canonical({ 'd' => 'atlas-pca/passport/v1', 'model_id' => p['model_id'], 'weights_digest' => p['weights_digest'],
                     'system_prompt_digest' => p['system_prompt_digest'], 'tool_manifest_digest' => p['tool_manifest_digest'],
                     'runtime_measurement' => p['runtime_measurement'], 'operator' => p['operator'],
                     'hardware_rooted' => p['hardware_rooted'] })
  end

  # Fill 'id' from the content fingerprint of the identity.
  def issue_passport(identity) = identity.merge('id' => passport_fingerprint(identity))

  # Sign a passport for the agent key subject. Fail closed: a hardware_rooted passport needs evidence.
  def sign_passport(passport, issuer, subject, exp, iat: nil, nbf: nil, evidence: nil, alg: nil, pq: nil)
    raise ArgumentError, 'sign_passport: passport.id is not the fingerprint of its identity (use issue_passport)' if passport['id'] != passport_fingerprint(passport)
    raise ArgumentError, 'sign_passport: hardware_rooted requires attestation evidence (fail closed)' if passport['hardware_rooted'] == true && evidence.nil?

    iat ||= passport['issued_at']
    nbf ||= iat
    raise ArgumentError, 'sign_passport: exp must be after nbf' unless exp > nbf

    body = { 'typ' => 'atlas-pca/passport', 'ver' => 1, 'passport' => passport, 'iss' => issuer.public, 'sub' => subject,
             'iat' => iat, 'nbf' => nbf, 'exp' => exp }
    body['evidence'] = { 'at' => iat }.merge(evidence) if evidence
    sign_artifact("atlas-pca/passport-sig/v1\x00", body, issuer, alg: alg, pq: pq)
  end

  # ---- workflow, receipts, read grants, aggregate grants, fresh_at ----

  def signed_by_principal(body, ed, domain, what)
    raise ArgumentError, "#{what}: principal is not the signer" unless body['principal'] == ed.public

    { 'body' => body, 'sig' => sign_body(ed, domain, body) }
  end

  def sign_workflow(principal, body) = signed_by_principal(body, principal, "atlas-pca/workflow/v1\x00", 'sign_workflow')
  def sign_read_grant(principal, body) = signed_by_principal(body, principal, "atlas-pca/read-grant/v1\x00", 'sign_read_grant')
  def sign_aggregate_grant(principal, body) = signed_by_principal(body, principal, "atlas-pca/aggregate-grant/v1\x00", 'sign_aggregate_grant')

  # A receipt output for value (string, bool or integer); num carries the integer an edge may compare.
  def wf_output(value, labels: [], unit: nil, num: false)
    { 'digest' => wf_value_digest(value), 'num' => num && value.is_a?(Integer) ? value : nil, 'unit' => unit, 'labels' => labels.sort }
  end

  # The resource server's signed receipt for a workflow step; prev is the previous receipt of the workflow.
  def sign_step_receipt(rs, workflow, step, outcome, params_dig, outputs, issued_at, prev: nil)
    base = { 'v' => 1, 'wf' => workflow_digest(workflow), 'step' => step, 'seq' => prev ? prev['seq'] + 1 : 0,
             'prev' => prev ? wf_receipt_ref(prev) : nil, 'outcome' => outcome, 'params_digest' => params_dig, 'outputs' => outputs,
             'issued_at' => issued_at, 'signer' => rs.public }
    base.merge('sig' => sign_body(rs, "atlas-pca/wf-receipt/v1\x00", base))
  end

  # A signed consistency token: the high-water mark of the verifier-side state a write produced.
  def sign_fresh_at(signer, scope, state, issued_at)
    base = { 'v' => 1, 'scope' => scope, 'revocation_epoch' => state['revocation_epoch'], 'ledger_tree_size' => state['ledger_tree_size'],
             'budget_version' => state['budget_version'], 'policy_revision' => state['policy_revision'],
             'policy_digest' => state['policy_digest'], 'issued_at' => issued_at, 'signer' => signer.public }
    base.merge('sig' => sign_body(signer, "atlas-pca/fresh-at/v1\x00", base))
  end

  # One signed action: the pcactn, the headers to send and the plan node it was built for.
  Action = Struct.new(:pcactn, :headers, :node_id)

  # An agent holding a grant (or a delegated chain): keeps the replay counter, picks nonces and builds the headers. Thread safe.
  # Persist the counter (on_counter) if the process can restart: a lower counter is refused as a replay.
  class Agent
    attr_reader :key, :grant, :chain, :aud
    attr_accessor :alg, :pq, :ttl_ms

    def initialize(key, grant, aud, chain: nil, counter: 0, clock: -> { (Time.now.to_f * 1000).to_i }, on_counter: nil, alg: nil, pq: nil)
      @key = key
      @grant = grant
      @aud = aud
      @chain = chain || [grant]
      @counter = counter
      @clock = clock
      @on_counter = on_counter
      @alg = alg
      @pq = pq
      @ttl_ms = DEFAULT_TTL_MS
      @plan = nil
      @lock = Mutex.new
    end

    # Commit to a multi-step plan; #act then signs against the matching node (and its Merkle proof).
    def use_plan(nodes)
      @plan = nodes
      self
    end

    # Build and sign the PCActn for one action. Without a committed plan it commits a one-node plan for the action.
    def act(verb, resource, params = nil, extra: {}, node_id: nil, **)
      if @plan
        node_id ||= @plan.find { |n| n['verb'] == verb && n['resource'] == resource }&.fetch('id')
        raise ArgumentError, "act: no node of the committed plan matches #{verb} #{resource}" unless node_id

        plan = @plan
      else
        node_id ||= 'n1'
        plan = [{ 'id' => node_id, 'verb' => verb, 'resource' => resource, 'params_digest' => AtlasPca.params_digest(params) }]
      end
      n = @lock.synchronize do
        @counter += 1
        @on_counter&.call(@counter)
        @counter
      end
      extra = { 'nonce' => AtlasPca.b64e(SecureRandom.random_bytes(16)) }.merge(extra)
      p = AtlasPca.build_pcactn(grant: @grant, chain: @chain, plan: plan, node_id: node_id, counter: n, signer: @key, aud: @aud,
                                params: params, iat: @clock.call, ttl_ms: @ttl_ms, extra: extra, alg: @alg, pq: @pq)
      Action.new(p, AtlasPca.pca_headers(p), node_id)
    end

    # A sub-agent signing with `to` (a KeyPair), holding this chain plus one narrower hop (caveats are only ever appended).
    def delegate(to, caveats = [])
      cap = AtlasPca.delegate_cap(@chain.last, @key, to_holder: to.public, added: caveats, alg: @alg, pq: @pq)
      Agent.new(to, @grant, @aud, chain: @chain + [cap], clock: @clock, alg: @alg, pq: @pq)
    end
  end
end
