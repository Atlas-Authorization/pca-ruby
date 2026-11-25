# frozen_string_literal: true

# Signed action packs, the producer side (the reference's pca-actions `pack`): shard_defs, build_pack (sort, chain to the previous version,
# derive and sign the evolution, shard, sign the pack) and verify_upgrade (a pack is the successor of the previous one and its signed evolution
# is EXACTLY the computed change). The verifier half (ActionsRegistry.verify_pack, also reachable as verify_action_pack) is in actions_registry.
# Signing is Ed25519 (the registry key suite of this SDK).
require_relative 'actions'
require_relative 'actions_registry'
require_relative 'actions_evolve'

module AtlasPca
  module ActionsPack
    A = AtlasPca::Actions
    R = AtlasPca::ActionsRegistry
    E = AtlasPca::ActionsEvolve

    DEFAULT_SHARD_DEFS = 512 # largest shard the builder writes by default
    MAX_PACK_DEFS = 4096

    module_function

    def verb_key(d) = d.is_a?(Hash) && d['verb'].is_a?(String) ? R.u16key(d['verb']) : ''.b

    # Shard names are the resource family (`resource.type` first segment) of the defs, split in order into chunks of `max`.
    def shard_defs(defs, max = DEFAULT_SHARD_DEFS)
      max = max.to_i if max.is_a?(Float) && max.finite? && max == max.floor
      raise A::ActionKitError.new('bad_shard_size', 'the shard size must be a positive integer') unless max.is_a?(Integer) && max >= 1

      fam = {}
      defs.each { |d| (fam[(d['resource']['type'].split('.', -1)[0] || '')] ||= []) << d }
      out = []
      fam.keys.sort_by { |f| R.u16key(f) }.each do |f|
        lst = fam[f]
        lst.each_slice(max).with_index(1) do |chunk, n|
          out << { 'name' => lst.length > max ? "#{f}-#{n}" : f, 'defs' => chunk }
        end
      end
      out
    end

    # Build, chain and sign a pack: {'pack', 'shards'}. `prev` is {'pack', 'shards'?} (the previous signed pack and its shard documents): it
    # chains `prev` and derives the signed evolution. `shard` (true, or {'max'?, 'uri'? => ->(name) { uri }}) shards the pack (always above
    # MAX_PACK_DEFS defs). `secret` is the registry's 32-byte Ed25519 seed. Raises ActionKitError on any inconsistency.
    def build_pack(ns, version, stability, defs, source, kid, secret, reg: nil, prev: nil, shard: nil, attestation_verified: nil)
      reg ||= A::CORE_REGISTRY
      ds = defs.sort_by { |d| verb_key(d) }
      de = R.sorted_unique_defs_error(ds)
      raise A::ActionKitError.new('bad_pack', de) if de
      raise A::ActionKitError.new('empty_pack', 'a pack has at least one def') if ds.empty?

      prev_defs = []
      if prev
        prev_defs = R.pack_defs(prev['pack'], prev['shards'])
        raise A::ActionKitError.new('bad_chain', 'the previous pack is of another namespace') if prev['pack']['ns'] != ns
        raise A::ActionKitError.new('bad_chain', 'the version must increase') if R.compare_versions(version, prev['pack']['version']) <= 0
      end
      evolution = E.sign_evolution(E.evolution_records(ns, prev_defs, ds, reg, attestation_verified), kid, secret)
      root = A.pack_root(ds.map { |d| A.def_digest(d) })
      want_shards = !shard.nil? && shard != false ? true : ds.length > MAX_PACK_DEFS
      shards = {}
      body = ds
      if want_shards
        opts = shard.is_a?(Hash) ? shard : {}
        refs = []
        shard_defs(ds, opts.key?('max') ? opts['max'] : DEFAULT_SHARD_DEFS).each do |s|
          doc = { 'v' => 1, 'kind' => R::PACK_SHARD_KIND, 'ns' => ns, 'version' => version, 'name' => s['name'], 'defs' => s['defs'] }
          shards[s['name']] = doc
          uri = opts['uri'].respond_to?(:call) ? opts['uri'].call(s['name']) : "shards/#{s['name']}.json"
          refs << { 'name' => s['name'], 'digest' => R.shard_digest(doc), 'uri' => uri }
        end
        body = { 'shards' => refs }
      end
      unsigned = { 'v' => 1, 'kind' => R::ACTION_PACK_KIND, 'ns' => ns, 'version' => version, 'stability' => stability,
                   'traits_digest' => A.traits_digest(reg), 'roles_digest' => A.tables_digest, 'rules_digest' => R.rules_digest, 'root' => root,
                   'defs' => body, 'source' => source, 'prev' => prev ? R.pack_digest(prev['pack']) : nil, 'evolution' => evolution }
      pe = R.pack_shape_error(unsigned, false)
      raise A::ActionKitError.new('bad_pack', pe) if pe

      sig = { 'alg' => 'ed25519', 'kid' => kid, 'value' => AtlasPca.b64e(AtlasPca::KeyPair.new(secret).sign(R.message(R::PACK_SIG_DOMAIN, unsigned))) }
      { 'pack' => unsigned.merge('sig' => sig), 'shards' => shards }
    end

    # Verify `nxt` as the successor of `prev`: both verify, same namespace, `nxt['prev']` is `prev`'s digest, the version increases and the signed
    # evolution is EXACTLY the computed change (a registry cannot sign `narrow` for a widening def). {'ok' => true} or {'ok' => false, 'reason'}.
    def verify_upgrade(prev, nxt, keys, prev_shards = nil, shards = nil, reg: nil, attestation_verified: nil)
      a = R.verify_pack(prev, keys, prev_shards)
      return { 'ok' => false, 'reason' => "previous pack: #{a['reason']}" } unless a['ok']

      b = R.verify_pack(nxt, keys, shards)
      return { 'ok' => false, 'reason' => "pack: #{b['reason']}" } unless b['ok']
      return { 'ok' => false, 'reason' => 'the packs are of different namespaces' } if nxt['ns'] != prev['ns']
      return { 'ok' => false, 'reason' => 'chain gap: prev does not name the previous pack' } if nxt['prev'] != a['digest']
      return { 'ok' => false, 'reason' => 'the version does not increase' } if R.compare_versions(nxt['version'], prev['version']) <= 0

      ee = E.evolution_error(nxt['ns'], a['defs'], b['defs'], nxt['evolution'], keys, reg || A::CORE_REGISTRY, attestation_verified)
      ee.nil? ? { 'ok' => true } : { 'ok' => false, 'reason' => ee }
    end
  end

  module ActionsRegistry
    # the reference's verifyActionPack (its pack verifier under the package-level name)
    def self.verify_action_pack(pack, keys, shards = nil) = verify_pack(pack, keys, shards)

    # The trait engine the verifier's rule 22 (`traits`) calls: `schema_error` is the integrity half (the document's traits and materialized floors
    # recomputed from the verb's visible facts and the carried registry; nil iff consistent), `decide` the decision half ('deny' | 'escalate' |
    # 'allow' of the verb's floors against what the grant provides and the call context).
    class Rule22Engine
      def schema_error(doc, reviewers = nil)
        AtlasPca::Actions.schema_floor_error(doc, reviewers)
      rescue StandardError => e
        "schema_floor_forged: #{e.message}"
      end

      def decide(doc, verb, grant, context) = ActionsRegistry.rule22_decide(doc, verb, grant, context)
    end

    RULE22_ENGINE = Rule22Engine.new.freeze
  end
end
