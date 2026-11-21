# frozen_string_literal: true
# k05 the caveat language v2 (caveat_lang.rb) and the K1 request headers against caveat-lang.ts + require-pca.ts presentedK1:
# test-data/k05-caveatlang.json.gz (tools/pca-audit/k05-oracles/caveatlang-oracle.mts). A trailing argument the reference
# omitted is absent here too (nil). dischargeRequests: the Ruby port has no discharge-request builder (skipped).
module MutationKill
  module K05CaveatLang
    FNS = {
      'spiffeIdError' => ->(a, _) { AtlasPca.spiffe_id_error(a[0]) },
      'needsDischargeError' => ->(a, _) { AtlasPca.needs_discharge_error(a[0]) },
      'dischargeShapeError' => ->(a, _) { AtlasPca.discharge_shape_error(a[0]) },
      'narrowShapeError' => ->(a, _) { AtlasPca.narrow_shape_error(a[0]) },
      'maxUsesError' => ->(a, _) { AtlasPca.max_uses_error(a[0]) },
      'maxUsesSlotKey' => ->(a, _) { AtlasPca.max_uses_slot_key(a[0], a[1], a[2]) },
      'spiffeBoundError' => ->(a, _) { AtlasPca.spiffe_bound_error(a[0]) },
      'deriveError' => ->(a, _) { AtlasPca.derive_error(a[0]) },
      'evaluateDerive' => ->(a, _) { AtlasPca.evaluate_derive(a[0], a[1]) },
      'verifyDischarge' => ->(a, _) { AtlasPca.verify_discharge(a[0], a[1], a[2]) },
      'verifyNarrow' => ->(a, _) { AtlasPca.verify_narrow(a[0], a[1], a[2], a[3]) },
      'boundCaveats' => ->(a, _) { AtlasPca.bound_caveats(a[0], a[1]) },
      'dischargeRequests' => ->(_, _) { nil },
      'evaluateK1' => ->(a, _) { AtlasPca.evaluate_k1(a[0], a[1], a[2], a[3]) },
      'evaluateCaveatsK1' => lambda do |a, _|
        allow, failed = AtlasPca.evaluate_caveats_k1(a[0], a[1], a[2], a[3])
        { 'allow' => allow, 'failed' => failed }
      end,
      # the reference records {ok: true, value} or {ok: false} (its throw); the Ruby refusal also carries a reason
      'presentedK1' => lambda do |a, _|
        r = AtlasPca.presented_k1(a[0])
        r[:ok] ? { 'ok' => true, 'value' => r[:value] } : { 'ok' => false }
      end
    }.freeze
    SKIP = ->(c) { c['fn'] == 'dischargeRequests' ? 'no discharge-request builder in the Ruby port' : nil }
    SPEC = K05::Spec.new(file: 'k05-caveatlang.json.gz', libs: %w[caveat_lang.rb], fns: FNS, cmp: { default: K05::EXACT }, skip: SKIP,
                         title: 'caveat language')
  end
  K05.register(K05CaveatLang::SPEC, K05CaveatLang::FNS.keys - ['dischargeRequests'])
end
