# frozen_string_literal: true

require 'json'

# More producer-side signers: the artifacts an agent, a principal, a guardian, a site or a resource server signs beyond the
# grant and the PCActn (agent.rb). Same wire as the TypeScript reference, byte for byte for Ed25519 and for the deterministic
# PQ suites. Every signer runs the reference's checks before signing and raises ArgumentError on a malformed body (fail
# closed), with the reference's refusal text (`signCaution: ...`).
#
# Suites: the functions that take `alg:` / `pq:` sign under any suite this runtime can sign (sign_with_suite); a suite it cannot
# sign raises UnsupportedSigner (`unsupported_suite: <alg>`).
module AtlasPca
  PQ_BIND_DOMAIN = "atlas-pca/pq-binding/v2\x00"
  SHARE_SUITE_TAG = "\x00atlas-pca/share-suite/v1\x00"
  CAUTION_DOMAIN = 'atlas-pca/caution/v1'
  HEARTBEAT_DOMAIN = 'atlas-pca/lease-hb/v2'
  PROGRESS_SIG_DOMAIN = 'atlas-pca/progress-step/v2'
  INTENT_REQUIRED_DOMAIN = "atlas-pca/intent-required/v1\x00"
  MAX_CAUTION_REASON_LEN = 64
  CAUTION_REASON_RE = /\A[A-Za-z0-9_.:-]+\z/
  INTENT_REQUIRED_KEYS = %w[v kind session map_digest schema pcactn_digest action_digest cell reason question_id friction
                            delivered_to expires_at sig].freeze
  QUESTION_ID_RE = /\A[A-Za-z0-9_-]{1,64}\z/
  FRICTIONS = %w[tap hold typed device].freeze

  module_function

  # ---- threshold shares (threshold.ts signShare / signPreparedShare) ----------------------------------------------------

  # Sign already-computed share bytes (the share message a step-up hands a principal device). Ed25519 gives
  # {role, publicKey, sig}, byte-identical to the pre-agility share; another suite adds `alg` (and `pq_sig` for a hybrid). The
  # role's PQ public key is registered in the signer set, not carried in the share.
  def sign_prepared_share(role, key, prepared, alg: nil, pq: nil)
    a = alg.nil? ? 'ed25519' : alg
    raise ArgumentError, "signPreparedShare: unknown signature alg '#{a}'" unless REGISTERED_SUITES.include?(a)

    sig, pq_sig = sign_with_suite(a, key, pq, prepared)
    share = { 'role' => role, 'publicKey' => key.public, 'sig' => sig }
    return share if a == 'ed25519'

    share['alg'] = a
    share['pq_sig'] = pq_sig if pq_sig
    share
  end

  # The v2.1 bound share message "atlas-pca/share/<role>\0" || sha256(message) || signerSetHash || t [|| suite tag].
  def share_message(role, message, signer_set, t, alg = nil)
    raise ArgumentError, 'shareMessage: t must be 1, 2 or 3' unless [1, 2, 3].include?(t) && !t.is_a?(Float)

    ssh = signer_set_hash(signer_set)
    raise ArgumentError, 'shareMessage: malformed signer set' if ssh.nil?

    tag = alg.nil? || alg == 'ed25519' ? ''.b : (SHARE_SUITE_TAG + alg).b
    "atlas-pca/share/#{role}\x00".b + sha(message.b) + ssh + [t].pack('C') + tag
  end

  # A role's EXPLICIT threshold share (agent, guardian or principal) over the bound share message (`message` is the PCActn's
  # threshold message). The share can only be replayed into the same signer set and threshold.
  def sign_threshold_share(role, key, message, signer_set, t, alg: nil, pq: nil)
    sign_prepared_share(role, key, share_message(role, message, signer_set, t, alg), alg: alg, pq: pq)
  end

  # ---- PQ key binding (pq.ts signPqBinding / pqPinFor) ----------------------------------------------------------------------

  def pq_binding_message(ed, pq, epoch, aud) = PQ_BIND_DOMAIN.b + "#{ed}\x00#{pq}\x00#{epoch}\x00#{aud}".b

  # An identity's signed statement "this PQ key is mine, as of `epoch`, for audience `aud`". `epoch` grows on every rotation
  # (>= 1).
  def sign_pq_binding(key, pq_public, epoch, aud)
    raise ArgumentError, 'signPqBinding: epoch must be a positive safe integer' unless safe_int?(epoch) && epoch >= 1
    raise ArgumentError, 'signPqBinding: aud (the instance/audience id) is required' unless aud.is_a?(String) && !aud.empty?

    { 'ed' => key.public, 'pq' => pq_public, 'epoch' => epoch, 'aud' => aud,
      'sig' => b64e(key.sign(pq_binding_message(key.public, pq_public, epoch, aud))) }
  end

  # The one-entry PQ pin {ed => pq} of a binding that verifies for `aud`, else nil. Never raises.
  def pq_pin_for(binding, aud)
    return nil unless binding.is_a?(Hash) && binding['ed'].is_a?(String) && binding['sig'].is_a?(String) && binding['pq'].is_a?(String)
    return nil unless aud.is_a?(String) && !aud.empty? && binding['aud'] == aud && safe_int?(binding['epoch']) && binding['epoch'] >= 1

    pk = b64d(binding['pq'])
    return nil if pk.nil? || !PQ_PK_LENGTHS.include?(pk.bytesize)

    msg = pq_binding_message(binding['ed'], binding['pq'], binding['epoch'], binding['aud'])
    verify_b64u(binding['ed'], msg, binding['sig']) ? { binding['ed'] => binding['pq'] } : nil
  rescue StandardError
    nil
  end

  # ---- agent-native: caution, lease heartbeat (agent-native.ts) -------------------------------------------------------------

  def domain_body_bytes(domain, body) = canon_bytes({ 'd' => domain, 'b' => body })

  def caution_body_error(b)
    return 'not an object' unless b.is_a?(Hash)
    return 'action_digest required' unless b['action_digest'].is_a?(String) && !b['action_digest'].empty?
    return 'holder required' unless b['holder'].is_a?(String) && !b['holder'].empty?

    c = b['caution']
    return 'caution must be a finite number in [0,1]' unless (c.is_a?(Integer) || (c.is_a?(Float) && c.finite?)) && c >= 0 && c <= 1

    if b.key?('reason')
      r = b['reason']
      return 'invalid reason' unless r.is_a?(String) && r.length <= MAX_CAUTION_REASON_LEN && CAUTION_REASON_RE.match?(r)
    end
    nil
  end

  # The holder's signed caution claim about an action ({action_digest, caution in [0,1], reason?, holder}).
  def sign_caution(body, holder)
    err = caution_body_error(body)
    raise ArgumentError, "signCaution: #{err}" if err

    clean = { 'action_digest' => body['action_digest'], 'caution' => body['caution'], 'holder' => body['holder'] }
    clean['reason'] = body['reason'] if body.key?('reason')
    clean.merge('sig' => b64e(holder.sign(domain_body_bytes(CAUTION_DOMAIN, clean))))
  end

  # The lease holder's signed liveness proof ({cap_id, seq, at, holder, lease_issued_at}).
  def sign_heartbeat(body, holder)
    raise ArgumentError, 'signHeartbeat: body must be an object' unless body.is_a?(Hash)

    clean = %w[cap_id seq at holder lease_issued_at].to_h do |k|
      raise ArgumentError, "signHeartbeat: #{k} is required" unless body.key?(k)

      [k, body[k]]
    end
    clean.merge('sig' => b64e(holder.sign(domain_body_bytes(HEARTBEAT_DOMAIN, clean))))
  end

  # The holder's signed progress step {step, holder, sig}: Ed25519 over the binding of the step to the holder, goal, action,
  # before/after state, sequence, chain link and step digest (progress.ts signProgressStep). A step missing a bound member is
  # refused (the reference cannot canonicalize it either).
  def sign_progress_step(step, holder)
    raise ArgumentError, 'signProgressStep: step must be an object' unless step.is_a?(Hash)

    bound = [%w[goal_commitment goal_commitment], %w[action_digest action_digest], %w[before_digest before_digest],
             %w[after_digest after_digest], %w[seq seq], %w[prev prev], %w[step_digest digest]]
    b = { 'holder' => holder.public }
    bound.each do |name, member|
      raise ArgumentError, "signProgressStep: step.#{member} is required" unless step.key?(member)

      b[name] = step[member]
    end
    { 'step' => step, 'holder' => holder.public, 'sig' => b64e(holder.sign(domain_body_bytes(PROGRESS_SIG_DOMAIN, b))) }
  end

  # ---- read receipt (readside.ts signReadReceipt, resource-server side) -----------------------------------------------------

  # The resource server's signed receipt for a read under `grant` (the read grant BODY); `prev` is the previous receipt.
  def sign_read_receipt(rs, grant, verb, resource, purpose, fields, labels, issued_at, prev: nil)
    base = { 'v' => 1, 'grant' => read_grant_digest(grant), 'verb' => verb, 'resource' => resource, 'purpose' => purpose,
             'seq' => prev ? prev['seq'] + 1 : 0, 'prev' => prev ? read_receipt_ref(prev) : nil, 'fields' => fields, 'labels' => labels,
             'issued_at' => issued_at, 'signer' => rs.public }
    base.merge('sig' => sign_body(rs, READ_RECEIPT_DOMAIN, base))
  end

  # ---- cross-domain mesh (mesh.ts signMeshAction / assembleMeshProof) -------------------------------------------------------

  # The leaf holder's signature over {action, tip = cap_hash(last hop)}.
  def sign_mesh_action(chain, action, leaf)
    raise ArgumentError, 'signMeshAction: empty chain' unless chain.is_a?(Array) && !chain.empty?

    b64e(leaf.sign(mesh_msg(MESH_ACTION_DOMAIN, { 'action' => action, 'tip' => cap_hash(chain[-1]) })))
  end

  # A compact mesh proof: hops issued against the same head share one table entry (their cosignatures merged by witness),
  # identical revocation bracketing leaves are carried once, and the leaf holder signs the action.
  def assemble_mesh_proof(chain, hops, action, leaf, pin_proofs: nil)
    heads = []
    head_idx = {}
    leaves = []
    leaf_idx = {}
    leaf_of = lambda do |lp|
      k = JSON.generate(lp)
      unless leaf_idx.key?(k)
        leaf_idx[k] = leaves.length
        leaves << lp
      end
      leaf_idx[k]
    end
    compact = lambda do |n|
      out = { 'size' => n['size'] }
      out['lo'] = leaf_of.call(n['lo']) if n['lo']
      out['hi'] = leaf_of.call(n['hi']) if n['hi']
      out
    end
    out_hops = hops.map do |ev|
      h = ev['head']
      k = "#{h['sig']}|#{JSON.generate(h['head'])}"
      if head_idx.key?(k)
        entry = heads[head_idx[k]]
        have = entry['cosigs'].map { |c| c['witness'] }
        h['cosigs'].each { |c| entry['cosigs'] << c unless have.include?(c['witness']) }
      else
        head_idx[k] = heads.length
        heads << { 'head' => h['head'], 'sig' => h['sig'], 'cosigs' => h['cosigs'].dup }
      end
      o = { 'domain' => ev['domain'], 'head' => head_idx[k], 'inclusion' => ev['inclusion'],
            'revocation' => { 'cap' => compact.call(ev['revocation']['cap']), 'issuer_key' => compact.call(ev['revocation']['issuer_key']) } }
      o['binding'] = ev['binding'] if ev['binding']
      o
    end
    proof = { 'chain' => chain, 'heads' => heads, 'rev_leaves' => leaves, 'hops' => out_hops, 'action' => action,
              'action_sig' => sign_mesh_action(chain, action, leaf) }
    proof['pin_proofs'] = pin_proofs if pin_proofs && !pin_proofs.empty?
    proof
  end

  # ---- Intent v2 session root and session grant (intent-session.ts) ---------------------------------------------------------

  # Sign the session root S as one of its principals (the signer's Ed25519 key must be listed in `principals`).
  def sign_session_root(body, principal, alg: nil, pq: nil)
    bad = session_root_shape_error(body, signed: false)
    raise ArgumentError, "signSessionRoot: #{bad}" if bad
    raise ArgumentError, 'signSessionRoot: the signer is not one of the session principals' unless body['principals'].any? { |p| p.is_a?(Hash) && p['key'] == principal.public }

    base = IntentV2.session_root_body(body).merge('signer' => principal.public)
    sign_artifact(INTENT_SESSION_SIG_DOMAIN, base, principal, alg: alg, pq: pq)
  end

  # G_0 (seq 0) or a delta grant D_k: a principal-signed root capability whose caveats are the envelope (goal
  # `pca-intent:v2:<session>:<map_digest>`, or `v2c` over a committed map) and the `intent_session` caveat. Returns
  # {'grant', 'goal_salt'} (the salt goes in the PCActn's `intent.goal_salt`). `holder` is the holder's public key.
  def mint_session_grant(principal, holder, session:, seq:, root:, map_digest:, predicates:, prev: nil, map_form: nil, caveats: nil,
                         agent_binding: nil, risk_policy: nil, salt: nil, holder_pq: nil, alg: nil, pq: nil)
    sc = { 'type' => 'intent_session', 'session' => session, 'seq' => seq, 'root' => root }
    sc['prev'] = prev unless prev.nil?
    bad = intent_session_caveat_error(sc)
    raise ArgumentError, "mintSessionGrant: #{bad}" if bad
    raise ArgumentError, 'mintSessionGrant: mapDigest must be canonical base64url (32 bytes)' unless map_digest.is_a?(String) && b32?(map_digest)

    goal_salt = salt.nil? ? b64e(SecureRandom.random_bytes(16)) : salt
    envelope = { 'type' => 'envelope', 'goal_commit' => goal_commit_of(intent_goal_v2(session, map_digest, map_form), goal_salt),
                 'predicates' => predicates, 'caveats' => caveats.nil? ? [] : caveats,
                 'agent_binding' => agent_binding.nil? ? {} : agent_binding, 'risk_policy' => risk_policy.nil? ? DEFAULT_RISK_POLICY : risk_policy }
    { 'grant' => mint_root(principal, holder, [envelope, sc], holder_pq: holder_pq, alg: alg, pq: pq), 'goal_salt' => goal_salt }
  end

  # ---- site-signed documents: action schema, intent_required, labels; oracle facts; offer sets -----------------------------

  def site_sig(alg, kid, sig, pq_sig)
    s = { 'alg' => alg.nil? ? 'ed25519' : alg, 'kid' => kid, 'value' => sig }
    s['pq_value'] = pq_sig if pq_sig
    s
  end

  # Sign an action schema as the site: `sig = {alg, kid, value, pq_value?}` over utf8(domain) || strictCanonical(doc). `kid`
  # names the site's discovery key entry (action_schema_key_of).
  def sign_action_schema(doc, kid, site, alg: nil, pq: nil)
    bad = action_schema_shape_error(doc, signed: false)
    raise ArgumentError, "signActionSchema: #{bad}" if bad

    sig, pq_sig = sign_with_suite(alg, site, pq, ACTION_SCHEMA_DOMAIN.b + strict_bytes(doc.reject { |k, _| k == 'sig' }))
    doc.merge('sig' => site_sig(alg, kid, sig, pq_sig))
  end

  # The discovery key entry {kid, alg, pk, pq_pk?} a verifier pins for a site signer.
  def action_schema_key_of(kid, site, alg: nil, pq: nil)
    a = alg.nil? ? 'ed25519' : alg
    raise ArgumentError, "unknown signature alg #{a.inspect}" unless REGISTERED_SUITES.include?(a)

    k = { 'kid' => kid, 'alg' => a, 'pk' => site.public }
    k['pq_pk'] = pq.public if a != 'ed25519' && pq
    k
  end

  def cell_coords_error(c)
    return 'coords must be an object of 1..64 dimensions' unless c.is_a?(Hash) && c.length.between?(1, 64)

    c.each do |k, v|
      return 'a coordinate path must be 1..256 characters' unless k.is_a?(String) && utf16_length(k).between?(1, 256)

      if v.is_a?(Array) && v.length == 2 && v.all? { |x| safe_int?(x) }
        return "coords '#{k}': need 0 <= lo <= hi" unless v[0] >= 0 && v[0] <= v[1]
      elsif v.is_a?(Array) && v.length.between?(1, 256) && v.all? { |x| x.is_a?(String) }
        return "coords '#{k}': values must be distinct" unless v.uniq.length == v.length
      else
        return "coords '#{k}': an index range [lo, hi] or a value set"
      end
    end
    nil
  end

  # The reference's shape check of an UNSIGNED `pca-intent-required` v1 body (the signer's pre-check).
  def intent_required_shape_error(b)
    return 'not an object' unless b.is_a?(Hash)

    b.each_key { |k| return "unknown member '#{k}'" unless INTENT_REQUIRED_KEYS.include?(k) }
    return 'not a pca-intent-required v1' unless b['v'] == 1 && b['v'] != true && b['kind'] == 'pca-intent-required'

    %w[session map_digest schema pcactn_digest action_digest].each do |k|
      return "#{k} must be canonical base64url (32 bytes)" unless b[k].is_a?(String) && b32?(b[k])
    end
    cell = b['cell']
    unless cell.is_a?(Hash) && cell.keys.sort == %w[coords verb] && cell['verb'].is_a?(String) && !cell['verb'].empty?
      return 'cell must be {verb, coords}'
    end

    ce = cell_coords_error(cell['coords'])
    return ce if ce
    return "reason must be 'uncertain'" unless b['reason'] == 'uncertain'
    return 'question_id must match [A-Za-z0-9_-]{1,64}' unless b['question_id'].is_a?(String) && QUESTION_ID_RE.match?(b['question_id'])
    return 'unknown friction tier' unless FRICTIONS.include?(b['friction'])
    return "delivered_to must be 'wallet' or 'agent'" unless %w[wallet agent].include?(b['delivered_to'])
    return 'expires_at must be a non-negative safe integer' unless safe_int?(b['expires_at']) && b['expires_at'] >= 0
    return 'an unsigned body must not carry sig' if b.key?('sig')

    nil
  end

  # The site's signed `pca-intent-required` v1 body: `sig = {alg, kid, value, pq_value?}` over
  # utf8(domain) || strictCanonical(body), pinned by the same discovery key entry as the action schema.
  def sign_intent_required(body, kid, site, alg: nil, pq: nil)
    bad = intent_required_shape_error(body)
    raise ArgumentError, "signIntentRequired: #{bad}" if bad

    sig, pq_sig = sign_with_suite(alg, site, pq, INTENT_REQUIRED_DOMAIN.b + strict_bytes(body))
    body.merge('sig' => site_sig(alg, kid, sig, pq_sig))
  end

  # A site's signed label receipt (`pca-labels` v1).
  def sign_labels(body, key, alg: nil, pq: nil) = sign_artifact(LABELS_DOMAIN, { 'v' => 1, 'kind' => 'pca-labels' }.merge(body), key, alg: alg, pq: pq)

  # An oracle's signed fact (`pca-fact` v1).
  def sign_fact(body, key, alg: nil, pq: nil) = sign_artifact(FACT_DOMAIN, { 'v' => 1, 'kind' => 'pca-fact' }.merge(body), key, alg: alg, pq: pq)

  # A site's signed offer set (the body carries its own v / kind).
  def sign_offer_set(body, key, alg: nil, pq: nil) = sign_artifact(OFFER_SET_DOMAIN, body, key, alg: alg, pq: pq)

  # ---- linked policy templates (policy-link.ts signTemplate / signTighten) --------------------------------------------------

  # The principal's signed policy template {def, signer, sig}.
  def sign_template(definition, key)
    e = template_def_error(definition)
    raise ArgumentError, "signTemplate: #{e}" if e

    { 'def' => definition, 'signer' => key.public, 'sig' => b64e(key.sign(link_message(TEMPLATE_SIG_DOMAIN, template_digest(definition)))) }
  end

  # The principal's signed tighten overlay {overlay, signer, sig} (it can only add where conditions and caveats).
  def sign_tighten(overlay, key)
    e = tighten_overlay_error(overlay)
    raise ArgumentError, "signTighten: #{e}" if e

    { 'overlay' => overlay, 'signer' => key.public, 'sig' => b64e(key.sign(link_message(TIGHTEN_SIG_DOMAIN, hash_canonical(overlay)))) }
  end

  # ---- revocation epoch (revocation.ts signRevocationEpoch, guardian side) ---------------------------------------------------

  # The guardian's signed revocation epoch over {instance_id, grant_ref, epoch, set_size, root, issued_at, not_after}; a
  # non-ed25519 suite binds `alg` and `pq_pk` into the signed bytes.
  def sign_revocation_epoch(guardian, body, alg: nil, pq: nil)
    fields = IntentV2::EPOCH_FIELDS.to_h do |k|
      raise ArgumentError, "signRevocationEpoch: #{k} is required" unless body.key?(k)

      [k, body[k]]
    end
    sig, pq_sig = sign_with_suite(alg, guardian, pq, REVEPOCH_DOMAIN.b + strict_bytes(bind_suite(fields, alg, pq)))
    out = fields.merge('guardian' => guardian.public, 'sig' => sig)
    return out if alg.nil? || alg == 'ed25519'

    out['alg'] = alg
    out['pq_pk'] = pq.public
    out['pq_sig'] = pq_sig if pq_sig
    out
  end
end
