# frozen_string_literal: true

# The producer side of the transparency ledger: the salted commitment of a PCActn and its opening check, the guardian-signed tree head
# and a witness cosignature of one. The verifiers are in ledger.rb: each signature is over the message they rebuild (domain, then the
# canonical body with the suite fields bound), so a head signed here verifies there under the same pins.
module AtlasPca
  module_function

  # The salted commitment of a PCActn: hash_canonical({salt, pcactn_digest}).
  def entry_commit(salt, pcactn) = hash_canonical({ 'salt' => salt, 'pcactn_digest' => pcactn_digest(pcactn) })

  # True when the opening {salt, pcactn} reproduces the commit. Total: a malformed opening is false.
  def verify_opening(commit, opening)
    entry_commit(opening['salt'], opening['pcactn']) == commit
  rescue StandardError, SystemStackError
    false
  end

  # A guardian-signed tree head over {instance_id, principal, size, root, prev_root, timestamp} (the suite bound into the signed bytes).
  # `guardian` is an AtlasPca::KeyPair; for a post-quantum suite pass alg and the guardian's PqKeyPair.
  def sign_tree_head(guardian, head, alg: nil, pq: nil)
    body = %w[instance_id principal size root prev_root timestamp].to_h { |k| [k, head[k]] }
    sign_bound_body(STH_DOMAIN, body, guardian, alg, pq).merge('guardian' => guardian.public)
  end

  # A witness cosignature {key, sig, alg?, pq_pk?, pq_sig?} over the tree-head statement of `sth` (bound to this exact head).
  def cosign_tree_head(sth, witness, alg: nil, pq: nil)
    signed = sign_bound_body(STH_WITNESS_DOMAIN, ledger_witness_body(sth), witness, alg, pq)
    { 'key' => witness.public }.merge(signed.slice('sig', 'alg', 'pq_pk', 'pq_sig'))
  end
end
