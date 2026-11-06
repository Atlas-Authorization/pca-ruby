# frozen_string_literal: true

# Verifier-side revocation staleness (T9; the TypeScript RevocationStalenessPolicy and the staleness branch of
# createRevocationChecker). The signer chooses an epoch's not_after; this lets the VERIFIER cap how old
# (now - issued_at) the revocation state may be, with a stricter window for actions that cannot be undone. The action's
# class is the stricter of the server's authoritative class and the PCActn's signed reversibility_class; a missing or
# unknown class counts as irreversible (fail closed).
#
# Off unless a RevocationStaleness is given (`AtlasPca.authorize(..., revocation_staleness:)`).
module AtlasPca
  REVOCATION_EPOCH_REFRESH_MS = 60_000
  REVOCATION_EPOCH_VALIDITY_MS = 5 * 60_000
  # Default window for an irreversible action: two refresh periods.
  REVOCATION_IRREVERSIBLE_MAX_AGE_MS = 2 * REVOCATION_EPOCH_REFRESH_MS

  # Severity over both vocabularies a verifier sees (the RS strictness enum and the caveat enum); unknown = most restrictive.
  CLASS_RANK = { 'reversible' => 0, 'rate_limited' => 1, 'costly' => 1, 'irreversible' => 2 }.freeze

  # The staleness policy. Every window is a positive finite number of milliseconds (a malformed one raises ArgumentError at
  # construction, never at request time).
  #   max_revocation_age_ms                 maximum age for any action (default 5 minutes)
  #   staleness                             { 'irreversible' => ms, 'rate_limited' => ms } ('costly' is the old name of 'rate_limited'), each capped by max_revocation_age_ms
  #                                         (defaults: irreversible 2 minutes; rate_limited = the maximum)
  #   allow_unsigned_root_for_irreversible  accept state that is not guardian-signed (a bare root) for an irreversible action
  #   guardian_public                       the pinned guardian key (base64url) a signed epoch must verify under
  #   pq_pins                               { <guardian key> => <pq_pk> } for a PQ / hybrid epoch
  #   on_epoch_accepted                     ->(epoch, pcactn) called after an ADMITTED action whose epoch passed every check
  #   ids                                   ->(pcactn) the capability ids that need a non-membership proof (default: every id in
  #                                         the PCActn's cap_chain; a revoked ancestor kills its descendants)
  #   proofs                                ->(id, pcactn) or a Hash keyed by id: the non-membership proof for a capability id.
  #                                         A missing proof source or proof DENIES (fail closed); pass `ids: ->(_p) { [] }` to
  #                                         check freshness only
  RevocationStaleness = Struct.new(:max_revocation_age_ms, :staleness, :allow_unsigned_root_for_irreversible,
                                   :guardian_public, :pq_pins, :on_epoch_accepted, :ids, :proofs) do
    def initialize(max_revocation_age_ms: nil, staleness: nil, allow_unsigned_root_for_irreversible: false,
                   guardian_public: nil, pq_pins: nil, on_epoch_accepted: nil, ids: nil, proofs: nil)
      st = staleness.nil? ? nil : staleness
      unless max_revocation_age_ms.nil? || AtlasPca.positive_ms?(max_revocation_age_ms)
        raise ArgumentError, 'max_revocation_age_ms must be a positive number of milliseconds'
      end
      unless st.nil? || st.is_a?(Hash)
        raise ArgumentError, 'staleness must be a Hash'
      end
      st = st&.transform_keys(&:to_s)
      %w[irreversible rate_limited costly].each do |k|
        if st&.key?(k) && !AtlasPca.positive_ms?(st[k])
          raise ArgumentError, "staleness.#{k} must be a positive number of milliseconds"
        end
      end
      raise ArgumentError, 'ids must be callable' unless ids.nil? || ids.respond_to?(:call)
      raise ArgumentError, 'proofs must be callable or a Hash' unless proofs.nil? || proofs.respond_to?(:call) || proofs.is_a?(Hash)

      super(max_revocation_age_ms, st, allow_unsigned_root_for_irreversible == true, guardian_public, pq_pins, on_epoch_accepted,
            ids, proofs)
    end
  end

  module_function

  def positive_ms?(v)
    (v.is_a?(Integer) || v.is_a?(Float)) && v.to_f.finite? && v.positive?
  end

  def class_rank(c)
    c.is_a?(String) ? CLASS_RANK.fetch(c, 2) : 2
  end

  # The stricter of the server's class and the signed one. Unknown or missing = irreversible.
  def effective_reversibility(server_class, signed_class)
    rank = [server_class.nil? ? 0 : class_rank(server_class), class_rank(signed_class)].max
    rank >= 2 ? 'irreversible' : (rank == 1 ? 'rate_limited' : 'reversible')
  end

  # The maximum age of revocation state the policy allows for an action of `cls`.
  def revocation_max_age_ms(policy, cls)
    pol = policy.is_a?(RevocationStaleness) ? policy : RevocationStaleness.new(**(policy || {}).transform_keys(&:to_sym))
    max = pol.max_revocation_age_ms.nil? ? REVOCATION_EPOCH_VALIDITY_MS : pol.max_revocation_age_ms
    st = pol.staleness || {}
    case cls
    when 'irreversible' then [max, st.fetch('irreversible', REVOCATION_IRREVERSIBLE_MAX_AGE_MS)].min
    when 'costly', 'rate_limited' then [max, st.fetch('rate_limited') { st.fetch('costly', max) }].min
    else max
    end
  end

  # verifyNonMembership: true iff `proof` ({size, lo?, hi?} of leaf proofs) shows `id` is NOT in the sorted revocation set the
  # size-bound `root` commits to. A revoked id has no valid proof. Total.
  def verify_non_membership(root, proof, id)
    return false unless root.is_a?(String) && id.is_a?(String) && proof.is_a?(Hash)

    mesh_non_membership?(root, proof, id)
  rescue StandardError
    false
  end

  # The revocation-state gate (createRevocationChecker). Returns
  # { 'ok' => true, 'epoch'? } or { 'ok' => false, 'reason' }. `state` is the revocation state this verification relies on:
  #   { 'kind' => 'epoch', 'epoch' => <guardian-signed epoch>, 'root'?, 'last_accepted_epoch'? }  checked against the
  #     guardian key (signature, grant binding, expiry, rollback, the PCActn's freshness.epoch) and, with a policy, the
  #     per-class age cap; a given 'root' must equal the epoch's
  #   { 'kind' => 'root', 'root' => str, 'issued_at' => ms | nil }  state that is not signed: with a policy it is refused for
  #     an irreversible action (unless allowed) and held to the same age cap via the time YOUR trusted source issued it
  #     (nil = unknown = denied)
  #   nil: no signed epoch (denied)
  # `policy` nil = staleness off: a signed epoch is still verified, with no verifier-side cap.
  # `ids` (nil = none to prove): the capability ids that must each carry a valid non-membership proof against the state's root;
  # `proofs` is a ->(id) callable or a Hash keyed by id (nil or absent = no proof = denied). Total.
  def check_revocation_state(policy, state, now:, grant_ref: IntentV2::UNDEF, signed_class: nil, server_class: nil,
                             pcactn_epoch: IntentV2::UNDEF, guardian_public: nil, ids: nil, proofs: nil)
    cls = max_age = nil
    unless policy.nil?
      cls = effective_reversibility(server_class, signed_class)
      max_age = revocation_max_age_ms(policy, cls)
    end
    st = state.is_a?(Hash) ? state.transform_keys(&:to_s) : {}
    root = st['root']
    accepted = nil
    case st['kind']
    when 'epoch'
      ep = st['epoch']
      gp = guardian_public.nil? ? policy&.guardian_public : guardian_public
      return { 'ok' => false, 'reason' => 'no signed revocation epoch' } unless ep.is_a?(Hash) && gp.is_a?(String) && !gp.empty?

      opts = { pcactn_epoch: pcactn_epoch }
      opts[:last_accepted_epoch] = st['last_accepted_epoch'] if st.key?('last_accepted_epoch')
      opts[:max_age_ms] = max_age unless max_age.nil?
      pins = policy&.pq_pins
      chk = check_revocation_epoch(ep, gp, now, grant_ref, pins.nil? || pins.empty? ? nil : pins, **opts)
      return chk unless chk['ok']
      return { 'ok' => false, 'reason' => 'revocation root does not match the signed epoch' } if !root.nil? && root != ep['root']

      root = ep['root']
      accepted = ep
    when 'root'
      unless policy.nil?
        if cls == 'irreversible' && !policy.allow_unsigned_root_for_irreversible
          return { 'ok' => false, 'reason' => 'unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)' }
        end

        age = check_revocation_age(st['issued_at'], now, max_age, 'revocation root')
        return age unless age['ok']
      end
    else
      return { 'ok' => false, 'reason' => 'no signed revocation epoch' }
    end
    return { 'ok' => false, 'reason' => 'no revocation root' } if root.nil? || root == ''

    (ids || []).each do |id|
      proof = proofs.respond_to?(:call) ? proofs.call(id) : (proofs.is_a?(Hash) ? proofs[id] : nil)
      return { 'ok' => false, 'reason' => "no non-membership proof for #{id}" } if proof.nil?
      return { 'ok' => false, 'reason' => "capability #{id} is revoked or proof invalid" } unless verify_non_membership(root, proof, id)
    end
    accepted.nil? ? { 'ok' => true } : { 'ok' => true, 'epoch' => accepted }
  rescue StandardError
    { 'ok' => false, 'reason' => 'revocation state check error (fail closed)' }
  end
end
