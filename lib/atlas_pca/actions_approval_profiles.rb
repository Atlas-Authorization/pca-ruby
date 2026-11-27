# frozen_string_literal: true

# The remaining approval profiles of approval-profiles.ts of the TypeScript reference @atlasauth/pca-actions: the Secure Payment
# Confirmation expectation and the CIBA / RAR authorization_details entry. PSD2 linking, minor units and batches are in approval.rb.
require_relative 'approval'

module AtlasPca
  module ActionsApprovalProfiles
    module_function

    # What a WebAuthn assertion verifier must find in the signed `clientData.payment`. The payee value is the name or the origin the browser shows.
    def spc_expectation(r, top_origin, payee_as = 'name')
      link = AtlasPca.psd2_linking(r)
      out = { 'topOrigin' => top_origin, 'total' => { 'currency' => link['currency'], 'value' => AtlasPca.minor_to_decimal(link['amount_minor'], link['exp']) } }
      out[payee_as == 'name' ? 'payeeName' : 'payeeOrigin'] = link['payee']
      out
    end

    # RFC 9396 authorization_details entry carrying the canonical render, plus the speakable match code.
    def ciba_approval_details(r)
      render_digest = AtlasPca.approval_render_digest(r)
      { 'authorization_details' => [{ 'type' => 'pca_approval', 'render' => r, 'render_digest' => render_digest }], 'match_code' => AtlasPca.binding_words(render_digest) }
    end
  end
end
