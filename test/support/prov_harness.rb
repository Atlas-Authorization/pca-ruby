# frozen_string_literal: true

# The conformance harness's provenance mediator (the same pin the TypeScript harnesses use: Ed25519 seed = 32 bytes of 0x01,
# mediator `conformance-harness`, kid `k1`). The shared authorize fixtures carry no bundles, so a replay with the gate on (it is
# always on) presents a principal-direct bundle built by this SDK's own recorder and pins the harness key: the operation then
# comes straight from the principal, exactly as in the reference replays. The gate is never switched off here.
require_relative '../../lib/atlas_pca'

module ProvHarness
  KEY = AtlasPca::KeyPair.new("\x01".b * 32)
  PIN = { 'mediator' => 'conformance-harness', 'kid' => 'k1', 'pk' => KEY.public }.freeze

  module_function

  def recorder = AtlasPca::ProvenanceRecorder.new(mediator: PIN['mediator'], kid: PIN['kid'], key: KEY)

  # A principal-direct bundle for `op` (a fresh session per call).
  def bundle(op) = AtlasPca.principal_direct_provenance(recorder, op)

  # The `provenance:` option: the harness pin, and a principal-direct bundle for whatever operation the call binds.
  OPTION = { 'mediators' => [PIN], 'bundle' => ->(_pcactn, op) { ProvHarness.bundle(op) } }.freeze

  # The bundle as the PCA-Provenance request header value.
  def header(op) = AtlasPca.b64e(AtlasPca.canon_bytes(bundle(op)))
end
