# frozen_string_literal: true
# k05 the cross-domain agent mesh (mesh.rb) and the Merkle primitives under it (ledger.rb verify_ledger_consistency,
# revocation_staleness.rb verify_non_membership) against mesh.ts / ledger.ts / revocation.ts: test-data/k05-mesh.json.gz
# (tools/pca-audit/k05-oracles/mesh-oracle.mts). The mesh verdict compared is {ok, reason?, hop?}; effectiveAuthority is the
# TS object (camelCase members, absent when unset) or {error}.
module MutationKill
  module K05Mesh
    EA_KEYS = { 'actions' => 'actions', 'prefixes' => 'prefixes', 'max_amount' => 'maxAmount', 'expires_at' => 'expiresAt',
                'audience' => 'audience', 'max_hops' => 'maxHops' }.freeze
    FNS = {
      'verifyMeshProof' => lambda do |a, _|
        v = AtlasPca.verify_mesh_proof(a[0], a[1])
        h = { 'ok' => v.ok }
        h['reason'] = v.reason unless v.reason.nil?
        h['hop'] = v.hop unless v.hop.nil? || v.hop == -1 # the reference names no hop (absent) where Ruby says -1
        h
      end,
      'checkHeadAdvance' => ->(a, _) { AtlasPca.mesh_check_head_advance(a[0], a[1], a[2]) },
      'verifyLedgerConsistency' => ->(a, _) { AtlasPca.verify_ledger_consistency(a[0], a[1], a[2]) },
      'verifyNonMembership' => ->(a, _) { AtlasPca.verify_non_membership(a[0], a[1], a[2]) },
      'effectiveAuthority' => lambda do |a, _|
        e, err = AtlasPca.mesh_effective(a[0])
        next { 'error' => err } if e.nil?

        e.each_with_object({}) { |(k, v), h| h[EA_KEYS.fetch(k)] = v unless v.nil? }
      end
    }.freeze
    SPEC = K05::Spec.new(file: 'k05-mesh.json.gz', libs: %w[mesh.rb ledger.rb revocation_staleness.rb], fns: FNS, cmp: { default: K05::EXACT },
                         title: 'mesh')
  end
  K05.register(K05Mesh::SPEC, K05Mesh::FNS.keys)
end
