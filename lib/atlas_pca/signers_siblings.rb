# frozen_string_literal: true

# The signing side of artifacts this SDK otherwise only verifies: liveness beacons, accumulator-commitment receipts and sequencer
# key sets, classifier verdicts, and the registry-signed documents of the action kit (evolution records, re-approvals). Each is the
# exact counterpart of the verifier already in the library: it signs the message that verifier rebuilds, under the same domain, with
# the key material of the requested suite (`alg` + the signer's post-quantum key pair `pq` for a non-Ed25519 suite). Keys are
# AtlasPca::KeyPair; a post-quantum pair is an AtlasPca::PqKeyPair.
module AtlasPca
  # The scopes an accumulator's state is shared across.
  ACC_SCOPES = %w[session principal org fleet].freeze
  ACC_RECEIPT_CORE_DOMAIN = 'atlas-pca/acc-receipt-core/v1'
  ACC_RECEIPT_CORE_FIELDS = %w[v kind session acc seq pre delta post pcactn_digest aud issued_at expires_at].freeze

  module_function

  # body with its suite fields bound, signed over domain || canonical(that) (the shape the verifiers rebuild): body + sig (and
  # alg / pq_pk / pq_sig for a non-default suite).
  def sign_bound_body(domain, body, key, alg, pq)
    full = bind_suite(body, alg, pq)
    sig, pq_sig = sign_with_suite(alg, key, pq, domain.b + canon_bytes(full))
    full = full.merge('sig' => sig)
    pq_sig.nil? ? full : full.merge('pq_sig' => pq_sig)
  end

  # A signed liveness beacon (Ed25519 by default). seq and issued_at are integers >= 0, validity_ms (default five epochs) is in
  # (0, BEACON_MAX_VALIDITY_MS]; a nil scope is the global scope. Raises RangeError outside those bounds.
  def issue_liveness_beacon(issuer, instance:, seq:, issued_at:, scope: nil, validity_ms: nil, alg: nil, pq: nil)
    validity = validity_ms.nil? ? 5 * BEACON_EPOCH_MS : validity_ms
    raise RangeError, 'issueLivenessBeacon: seq must be a non-negative integer' unless beacon_int?(seq) && seq >= 0
    raise RangeError, 'issueLivenessBeacon: issuedAt must be an integer' unless beacon_int?(issued_at) && issued_at >= 0
    unless beacon_int?(validity) && validity.positive? && validity <= BEACON_MAX_VALIDITY_MS
      raise RangeError, "issueLivenessBeacon: validity must be in (0, #{BEACON_MAX_VALIDITY_MS}] ms"
    end

    body = { 'v' => 2, 'instance' => instance, 'scope' => scope.nil? ? GLOBAL_BEACON_SCOPE : scope, 'epoch' => issued_at.div(BEACON_EPOCH_MS), 'seq' => seq,
             'issued_at' => issued_at, 'not_after' => issued_at + validity, 'issuer' => issuer.public }
    sign_bound_body(LIVENESS_DOMAIN, body, issuer, alg, pq)
  end

  # The content of the receipt a sequencer signs (no ledger position, no signature fields): the digest the log leaf commits to.
  def acc_receipt_core_digest(r)
    hash_canonical({ 'd' => ACC_RECEIPT_CORE_DOMAIN, 'r' => ACC_RECEIPT_CORE_FIELDS.to_h { |k| [k, r[k]] } })
  end

  # A sequencer-signed accumulator receipt. `body` is the receipt without signer / alg / pq_pk / sig / pq_sig; the signer is the
  # sequencer's identity. Raises ArgumentError when the result is not a well-formed receipt.
  def sign_acc_receipt(body, sequencer, alg: nil, pq: nil)
    base = IntentV2.send(:receipt_body, body.merge('signer' => sequencer.public))
    pq_pk = alg.nil? || alg == 'ed25519' ? nil : pq&.public
    msg = ACC_RECEIPT_DOMAIN.b + canon_bytes(IntentV2.bind_suite_fields(base, alg, pq_pk.nil? ? V2JS::UNDEF : pq_pk))
    sig, pq_sig = sign_with_suite(alg, sequencer, pq, msg)
    out = base.merge('sig' => sig)
    out = out.merge('alg' => alg, 'pq_pk' => pq_pk) unless alg.nil? || alg == 'ed25519'
    out = out.merge('pq_sig' => pq_sig) unless pq_sig.nil?
    bad = acc_receipt_shape_error(out)
    raise ArgumentError, "signAccReceipt: #{bad}" if bad

    out
  end

  # The sequencer's signed key set (signing-key rotation without restarting sessions), signed by its root key.
  def sign_sequencer_key_set(body, root, alg: nil, pq: nil)
    base = JSON.parse(JSON.generate(IntentV2.send(:key_set_body, body.merge('sequencer' => root.public))))
    pq_pk = alg.nil? || alg == 'ed25519' ? nil : pq&.public
    msg = SEQUENCER_KEYS_DOMAIN.b + canon_bytes(IntentV2.bind_suite_fields(base, alg, pq_pk.nil? ? V2JS::UNDEF : pq_pk))
    sig, pq_sig = sign_with_suite(alg, root, pq, msg)
    out = base.merge('sig' => sig)
    out = out.merge('alg' => alg, 'pq_pk' => pq_pk) unless alg.nil? || alg == 'ed25519'
    out = out.merge('pq_sig' => pq_sig) unless pq_sig.nil?
    bad = IntentV2.sequencer_key_set_shape_error(out)
    raise ArgumentError, "signSequencerKeySet: #{bad}" if bad

    out
  end

  # Order-independent helper for hosts: the distinct keys in canonical (UTF-8 byte) order.
  def sorted_distinct(keys) = keys.to_a.uniq.sort { |a, b| a.b <=> b.b }

  # A classifier's signed verdict; `judge` is derived from the signing key.
  def sign_classifier_verdict(body, key, alg: nil, pq: nil)
    sign_artifact(INTENT_CLASSIFIER_DOMAIN, { 'v' => 1, 'kind' => 'pca-intent-classification' }.merge(body).merge('judge' => key.public), key, alg: alg, pq: pq)
  end

  # `sig` = {alg, kid, value, pq_value?} of `body` under `domain` as a registry key (`kid` names the pinned key entry).
  def sign_registry_doc(domain, body, kid, registry, alg: nil, pq: nil)
    sig, pq_sig = sign_with_suite(alg, registry, pq, ActionsRegistry.message(domain, body))
    site_sig(alg, kid, sig, pq_sig)
  end

  # The registry key entry {kid, alg, pk, pq_pk?} a verifier pins for a registry signer.
  def registry_key_of(kid, registry, alg: nil, pq: nil) = action_schema_key_of(kid, registry, alg: alg, pq: pq)

  # An evolution record signed as the registry. Raises ArgumentError for a malformed record.
  def sign_evolution_record(rec, kid, registry, alg: nil, pq: nil)
    bad = ActionsRegistry.evolution_record_error(rec, false)
    raise ArgumentError, "signEvolutionRecord: #{bad}" if bad

    rec.merge('sig' => sign_registry_doc(ActionsRegistry::EVOLUTION_DOMAIN, rec, kid, registry, alg: alg, pq: pq))
  end

  # The principal's approval of one evolution step for one grant (`grant_id` is grant['id']; `principal` the key that minted it).
  def sign_reapproval(grant_id, record, principal)
    body = { 'v' => 1, 'kind' => ActionsRegistry::REAPPROVAL_KIND, 'grant' => grant_id, 'verb' => record['verb'],
             'diff' => ActionsRegistry.evolution_diff_digest(record) }
    value, = sign_with_suite(nil, principal, nil, ActionsRegistry.message(ActionsRegistry::REAPPROVAL_DOMAIN, body))
    body.merge('sig' => { 'alg' => 'ed25519', 'value' => value })
  end
end
