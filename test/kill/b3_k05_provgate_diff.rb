# frozen_string_literal: true
# k05 build provenance as a K1 discharge (provenance_gate.rb) against provenance-gate.ts: test-data/k05-provgate.json.gz
# (tools/pca-audit/k05-oracles/provgate-oracle.mts). Inclusion args are base64url text (the oracle's wire form).
module MutationKill
  module K05ProvGate
    bin = ->(s) { AtlasPca.b64d(s) || raise(ArgumentError, 'not base64url') }
    FNS = {
      'provenanceFactsError' => ->(a, _) { AtlasPca.provenance_facts_error(a[0]) },
      'provenancePolicyError' => ->(a, _) { AtlasPca.provenance_policy_error(a[0]) },
      'provenanceGate' => ->(a, _) { AtlasPca.provenance_gate(a[0]) },
      'verifyRfc9162Inclusion' => ->(a, _) { AtlasPca.verify_rfc9162_inclusion(bin.call(a[0]), a[1], a[2], a[3].map { |x| bin.call(x) }, bin.call(a[4])) },
      'rfc9162LeafHash' => ->(a, _) { { '$bytes' => AtlasPca.b64e(AtlasPca.rfc9162_leaf_hash(bin.call(a[0]))) } },
      'provenanceCaveat' => ->(a, _) { AtlasPca.provenance_caveat(**a[0].transform_keys(&:to_sym)) }
    }.freeze
    SPEC = K05::Spec.new(file: 'k05-provgate.json.gz', libs: %w[provenance_gate.rb], fns: FNS, cmp: { default: K05::EXACT }, title: 'provenance gate')
  end
  K05.register(K05ProvGate::SPEC, K05ProvGate::FNS.keys)
end
