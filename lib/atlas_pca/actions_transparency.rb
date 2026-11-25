# frozen_string_literal: true

# Append a signed action pack to a SCITT transparency log (RFC 9943) and verify the receipt (native port of transparency.ts of the
# TypeScript reference @atlasauth/pca-actions). The statement is a COSE Signed Statement over {ns, version, digest, root, prev}; the
# receipt is the log's signed inclusion proof. Keys are the scitt module's native key forms.
require_relative 'actions_registry'
require_relative 'scitt'
require_relative 'scitt_log'

module AtlasPca
  module ActionsTransparency
    PACK_STATEMENT_CONTENT_TYPE = 'application/pca-action-pack+json'

    module_function

    # The payload the registry signs into the log (small: the digest, not the pack).
    def pack_statement_payload(p)
      { 'v' => 1, 'kind' => 'pca-action-pack-statement', 'ns' => p['ns'], 'version' => p['version'], 'digest' => ActionsRegistry.pack_digest(p), 'root' => p['root'], 'prev' => p['prev'] }
    end

    # Sign the pack's statement with the registry's COSE key (signer: {alg, key, issuer}) and register it: {statement, receipt, index, root}.
    def append_pack_to_log(pack, service, signer)
      statement = Scitt.sign_statement(pack_statement_payload(pack), signer['alg'], signer['key'], signer['issuer'],
                                       { 'subject' => "#{pack['ns']}@#{pack['version']}", 'content_type' => PACK_STATEMENT_CONTENT_TYPE })
      r = ScittLog.register_statement(statement, service)
      { 'statement' => statement, 'receipt' => r['receipt'], 'index' => r['index'], 'root' => r['root'] }
    end

    def statement_for?(pack, statement) = Scitt.statement_payload(statement) == AtlasPca.canon_bytes(pack_statement_payload(pack))

    # Does `entry` prove `pack` is in the log? The statement must be the pack's own and signed by the registry, the receipt by the log. Never raises.
    def verify_pack_log_entry(pack, entry, keys, tree_root = nil)
      ok = Scitt.verify_receipt(entry['receipt'], entry['statement'], { 'tree_root' => tree_root, 'verification_key' => keys['log'], 'statement_key' => keys['registry'] })
      ok ? statement_for?(pack, entry['statement']) : false
    rescue StandardError
      false
    end
  end
end
