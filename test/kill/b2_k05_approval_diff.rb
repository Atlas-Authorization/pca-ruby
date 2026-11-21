# frozen_string_literal: true
# k05 canonical approval render (approval.rb) against approval-render.ts + pca-actions approval-render.ts: test-data/
# k05-approval.json.gz (tools/pca-audit/k05-oracles/approval-oracle.mts). render_approval is the unreviewed render (no def in
# the oracle carries a signed confirmation, so confirmed = false). spcExpectation / cibaApprovalDetails: the Ruby port has
# no SPC / CIBA helpers (skipped, see SKIP).
module MutationKill
  module K05Approval
    FNS = {
      'approvalRenderShapeError' => ->(a, _) { AtlasPca.approval_render_shape_error(a[0]) },
      'approvalRenderDigest' => ->(a, _) { AtlasPca.approval_render_digest(a[0]) },
      'approvalChallengeB64u' => ->(a, _) { AtlasPca.approval_challenge(a[0], a[1]) },
      'bindingWords' => ->(a, _) { AtlasPca.binding_words(a[0]) },
      'renderApproval' => ->(a, _) { AtlasPca.render_approval(a[0], a[1], false) },
      'validateDef' => ->(a, _) { AtlasPca::Actions.validate_def(a[0]) },
      'psd2Linking' => ->(a, _) { AtlasPca.psd2_linking(a[0]) },
      'minorToDecimal' => ->(a, _) { AtlasPca.minor_to_decimal(a[0], a[1]) },
      'approvalBatch' => ->(a, _) { AtlasPca.approval_batch(a[0]) },
      'spcExpectation' => ->(_, _) { nil },
      'cibaApprovalDetails' => ->(_, _) { nil }
    }.freeze
    # the TS batch carries the challenge as bytes; the Ruby one as its base64url text
    BATCH = lambda do |got, out, c|
      o = out.is_a?(Hash) && out['challenge'].is_a?(Hash) ? out.merge('challenge' => out['challenge']['$bytes']) : out
      K05::EXACT.call(got, o, c)
    end
    CMP = { default: K05::EXACT, 'approvalBatch' => BATCH }.freeze
    SKIP = ->(c) { %w[spcExpectation cibaApprovalDetails].include?(c['fn']) ? 'no SPC / CIBA helpers in the Ruby port' : nil }
    SPEC = K05::Spec.new(file: 'k05-approval.json.gz', libs: %w[approval.rb], fns: FNS, cmp: CMP, skip: SKIP, title: 'approval')
  end
  K05.register(K05Approval::SPEC, K05Approval::FNS.keys - %w[spcExpectation cibaApprovalDetails])
end
