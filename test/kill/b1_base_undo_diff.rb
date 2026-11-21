# frozen_string_literal: true
# base undo windows (undo.rb) against the TS reference undo.ts: test-data/base-undo.json.gz (tools/pca-audit/oracles-base/
# undo-oracle.mts). Secrets are base64url Ed25519 seeds, passed as raw 32-byte seeds.
module MutationKill
  module BaseUndo
    key = ->(sk) { AtlasPca.b64d(sk) } # the raw secret, as the reference takes it (a non-32-byte one is signer_missing)
    FNS = {
      'compensationDigest' => ->(a, _) { AtlasPca.compensation_digest(a[0]) },
      'signUndoToken' => ->(a, _) { AtlasPca.sign_undo_token(a[0], key.call(a[1])) },
      'undoTokenCheck' => ->(a, _) { AtlasPca.undo_token_check(*a) },
      'encodeUndoToken' => ->(a, _) { AtlasPca.encode_undo_token(a[0]) },
      'undoTokenDigest' => ->(a, _) { AtlasPca.undo_token_digest(a[0]) },
      'decodeUndoToken' => ->(a, _) { AtlasPca.decode_undo_token(a[0]) },
      'signUndoReceipt' => ->(a, _) { AtlasPca.sign_undo_receipt(a[0], key.call(a[1])) },
      'undoReceiptDigest' => ->(a, _) { AtlasPca.undo_receipt_digest(a[0]) },
      'verifyUndoReceipt' => ->(a, _) { AtlasPca.verify_undo_receipt(a[0], a[1]) },
      'undoReceiptChainError' => ->(a, _) { AtlasPca.undo_receipt_chain_error(a[0], a[1]) },
      'undoTransition' => ->(a, _) { AtlasPca.undo_transition(*a) },
      'resolveUndoWindow' => ->(a, _) { AtlasPca.resolve_undo_window(a[0], a[1]) }
    }.freeze
    CMP = { default: Base::EXACT }.freeze
    SPEC = Base::Spec.new(file: 'base-undo.json.gz', libs: %w[undo.rb], fns: FNS, cmp: CMP, title: 'undo')
  end
  Base.register(BaseUndo::SPEC, BaseUndo::FNS.keys)
end
