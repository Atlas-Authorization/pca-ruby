# frozen_string_literal: true
# base the prohibition engine (prohibitions.rb) against the TS reference prohibitions.ts: test-data/base-prohibitions.json.gz
# (tools/pca-audit/oracles-base/prohibitions-oracle.mts; 21781 cases). A signing secret is the base64url Ed25519 seed; a
# trailing argument the reference call omits is omitted here too (absent and null differ). The module is resolved at call time.
module MutationKill
  module BaseProhibitions
    FILE = 'base-prohibitions.json.gz'
    TOTAL = 21_781
    pr = -> { AtlasPca::Prohibitions }
    FNS = {
      'validateInvariant' => ->(a, _) { pr.call.validate_invariant(a[0]) },
      'validateConstitution' => ->(a, _) { pr.call.validate_constitution(a[0]) },
      'stateProblem' => ->(a, _) { pr.call.state_problem(a[0]) },
      'canonicalState' => ->(a, _) { pr.call.canonical_state(a[0]) },
      'stateDigest' => ->(a, _) { pr.call.state_digest(a[0]) },
      'tickState' => ->(a, _) { pr.call.tick_state(a[0], a[1]) },
      'emptyState' => ->(a, _) { pr.call.empty_state(a[0]) },
      'checkProhibitions' => ->(a, _) { pr.call.check_prohibitions(a[0], a[1], a[2]) },
      'advanceStateStrict' => ->(a, _) { pr.call.advance_state_strict(*a) },
      'proveSafety' => ->(a, _) { pr.call.prove_safety(a[0], a[1], a[2]) },
      'verifySafetyEvidence' => ->(a, _) { pr.call.verify_safety_evidence(a[0], a[1], a[2], a[3]) },
      'safetyBindingId' => ->(a, _) { pr.call.safety_binding_id(a[0], a[1]) },
      'signSafetyEvidence' => ->(a, _) { pr.call.sign_safety_evidence(a[0], AtlasPca::KeyPair.from_seed_b64u(a[1]), a[2]) },
      'verifySignedSafetyEvidence' => ->(a, _) { pr.call.verify_signed_safety_evidence(a[0], a[1]) },
      'checkAndAdvance' => ->(a, _) { pr.call.check_and_advance(*a) },
      'verifyConstitution' => ->(a, _) { pr.call.verify_constitution(*a) },
      'constitutionId' => ->(a, _) { pr.call.constitution_id(a[0]) },
      'whenAffirmative' => ->(a, _) { pr.call.when_affirmative?(a[0], a[1]) }
    }.freeze
    SPEC = Base::Spec.new(file: FILE, libs: %w[prohibitions.rb], fns: FNS, cmp: { default: Base::EXACT }, title: 'prohibitions')
  end
  Base.register(BaseProhibitions::SPEC, BaseProhibitions::FNS.keys)

  t("base prohibitions differential (TS oracle): #{BaseProhibitions::TOTAL} cases, every fn of the corpus is replayed") do
    next true if DiffUtil.skip?('prohibitions.rb')

    n = Hash.new(0)
    if (g = Base::CACHE[BaseProhibitions::FILE]) then g.each { |fn, cs| n[fn] = cs.length }
    else Base.stream(BaseProhibitions::FILE) { |c| n[c['fn']] += 1 }
    end
    unmapped = n.keys - BaseProhibitions::FNS.keys
    warn "base prohibitions: #{n.values.sum} cases, unmapped fns #{unmapped.inspect}" unless n.values.sum == BaseProhibitions::TOTAL && unmapped.empty?
    n.values.sum == BaseProhibitions::TOTAL && unmapped.empty?
  end
end
