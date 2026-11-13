# frozen_string_literal: true
# k05 the action-kit registry layer (actions_registry.rb; pack proofs in actions.rb) against action-pin.ts and pca-actions
# pack / registry / rule22 / digest: test-data/k05-actionregistry.json.gz (tools/pca-audit/k05-oracles/actionregistry-oracle.mts).
# verifyRegistrySig / verifyEvolutionRecord compare null-or-reason; verifyPack {ok, digest, verbs} or the refusal; packTracker
# (the TS tracker with keepContent: false, keyed by the oracle's ALLKEYS = the keys of verifyPack/p1) compares ok / status / code,
# the reason only for bad_pack. textPrefix: the reference message up to an engine-specific tail.
module MutationKill
  module K05ActionRegistry
    module_function

    FILE = 'k05-actionregistry.json.gz'

    def all_keys
      @all_keys ||= begin
        pick = ->(c) { c['name'] == 'verifyPack/p1' ? c['args'][1] : nil }
        if (g = K05::CACHE[FILE])
          g['verifyPack'].filter_map(&pick).first
        else
          k = nil
          K05.stream(FILE) { |c| k ||= pick.call(c) }
          k
        end
      end
    end

    def tracker(steps)
      t = AtlasPca::ActionsRegistry::PackTracker.new(all_keys)
      steps.map do |p, s|
        r = t.accept(p, s)
        o = { 'ok' => r['ok'] }
        %w[status code].each { |k| o[k] = r[k] if r.key?(k) }
        o['reason'] = r['reason'] if r['code'] == 'bad_pack'
        o
      end
    end

    TRACK = lambda do |got, out, c|
      want = out.is_a?(Array) ? out.map { |r| r['code'] == 'bad_pack' ? r : r.reject { |k, _| k == 'reason' } } : out
      K05::PREFIX.call(got, want, c)
    end

    FNS = {
      'compareVersions' => ->(a, _) { AtlasPca::ActionsRegistry.compare_versions(a[0], a[1]) <=> 0 },
      'packDefs' => ->(a, _) { AtlasPca::ActionsRegistry.pack_defs(a[0], a[1]).map { |d| d['verb'] } },
      'evolutionRecordError' => ->(a, _) { AtlasPca::ActionsRegistry.evolution_record_error(a[0], a[1]) },
      'evolutionDiffDigest' => ->(a, _) { AtlasPca::ActionsRegistry.evolution_diff_digest(a[0]) },
      'verifyRegistrySig' => ->(a, _) { (r = AtlasPca::ActionsRegistry.verify_registry_sig(*a))['ok'] ? nil : r['reason'] },
      'verifyEvolutionRecord' => ->(a, _) { (r = AtlasPca::ActionsRegistry.verify_evolution_record(a[0], a[1]))['ok'] ? nil : r['reason'] },
      'reapprovalValid' => ->(a, _) { AtlasPca::ActionsRegistry.reapproval_valid?(*a) },
      'actionPinError' => ->(a, _) { AtlasPca::ActionsRegistry.action_pin_error(a[0]) },
      'decidePin' => ->(a, _) { AtlasPca::ActionsRegistry.decide_pin(a[0]) },
      'packShapeError' => ->(a, _) { AtlasPca::ActionsRegistry.pack_shape_error(a[0], a[1]) },
      'verifyPack' => lambda do |a, _|
        r = AtlasPca::ActionsRegistry.verify_pack(a[0], a[1], a[2])
        r['ok'] ? { 'ok' => true, 'digest' => r['digest'], 'verbs' => r['defs'].map { |d| d['verb'] } } : r
      end,
      'packTracker' => ->(a, _) { tracker(a[0]) },
      'rule22Decide' => ->(a, _) { AtlasPca::ActionsRegistry.rule22_decide(*a) },
      'verifyPackProof' => ->(a, _) { AtlasPca::Actions.verify_pack_proof(a[0], a[1], a[2]) }
    }.freeze
    SPEC = K05::Spec.new(file: FILE, libs: %w[actions_registry.rb], fns: FNS, cmp: { default: K05::PREFIX, 'packTracker' => TRACK },
                         title: 'action registry')
  end
  K05.register(K05ActionRegistry::SPEC, K05ActionRegistry::FNS.keys)
end
