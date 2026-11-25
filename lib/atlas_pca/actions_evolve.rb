# frozen_string_literal: true

# Signed per-definition changes between two versions of a pack (native port of evolve.ts of the TypeScript reference
# @atlasauth/pca-actions): the unsigned records, Ed25519 registry signing and the whole-change consistency check. Record shape and
# signature verification are in actions_registry.rb.
require_relative 'actions'
require_relative 'actions_diff'
require_relative 'actions_registry'
require_relative 'agent'

module AtlasPca
  module ActionsEvolve
    A = AtlasPca::Actions
    R = AtlasPca::ActionsRegistry

    module_function

    def by_verb(defs)
      m = {}
      defs.each do |d|
        raise A::ActionKitError.new('duplicate_def', "verb '#{d['verb']}' appears twice") if m.key?(d['verb'])

        m[d['verb']] = d
      end
      m
    end

    # The unsigned records that take `prev` to `nxt` (sorted by verb). A verb rename is `removed` + `added`.
    def evolution_records(ns, prev, nxt, reg = A::CORE_REGISTRY, verifier = nil)
      a = by_verb(prev)
      b = by_verb(nxt)
      out = []
      (a.keys | b.keys).sort_by { |v| A.u16key(v) }.each do |verb|
        o = a[verb]
        n = b[verb]
        base = { 'v' => 1, 'kind' => R::EVOLUTION_RECORD_KIND, 'ns' => ns, 'verb' => verb }
        if o.nil?
          out << base.merge('from' => nil, 'to' => A.def_digest(n), 'class' => 'added', 'reasons' => [])
        elsif n.nil?
          out << base.merge('from' => A.def_digest(o), 'to' => nil, 'class' => 'removed', 'reasons' => [])
        else
          f = A.def_digest(o)
          t = A.def_digest(n)
          next if f == t

          d = ActionsDiff.diff_defs(o, n, reg, verifier)
          out << base.merge('from' => f, 'to' => t, 'class' => d['class'], 'reasons' => d['reasons'])
        end
      end
      out
    end

    # Sign the records as the registry (Ed25519 over the evolution domain and the strict canonical record).
    def sign_evolution(records, kid, secret)
      kp = AtlasPca::KeyPair.new(secret)
      records.map do |r|
        bad = R.evolution_record_error(r, false)
        raise ArgumentError, "signEvolutionRecord: #{bad}" if bad

        r.merge('sig' => { 'alg' => 'ed25519', 'kid' => kid, 'value' => AtlasPca.b64e(kp.sign(R.message(R::EVOLUTION_DOMAIN, r))) })
      end
    end

    def key_of(r)
      js = A.js
      [js.js_str(r['verb']), js.js_str(r['from']), js.js_str(r['to']), js.js_str(r['class']), R.evolution_diff_digest(r)].join('|')
    end

    # Does `records` EXACTLY describe the change from prev to nxt? Every record verifies under the pinned registry keys and names `ns`;
    # none is missing or extra; each class is the one the diff computes. nil = consistent, else the reason.
    def evolution_error(ns, prev, nxt, records, keys, reg = A::CORE_REGISTRY, verifier = nil)
      records.each do |r|
        v = R.verify_evolution_record(r, keys)
        return "evolution record: #{v['reason']}" unless v['ok']
        return "evolution record names namespace '#{A.js.js_str(r['ns'])}', not '#{ns}'" if r['ns'] != ns
      end
      want = evolution_records(ns, prev, nxt, reg, verifier).map { |r| key_of(r) }.sort_by { |s| A.u16key(s) }
      have = records.map { |r| key_of(r.reject { |k, _| k == 'sig' }) }.sort_by { |s| A.u16key(s) }
      return "evolution has #{have.length} records, the change needs #{want.length}" if want.length != have.length
      return 'evolution records do not match the computed change (a missing, extra or mis-classified record)' if want.zip(have).any? { |w, h| w != h }

      nil
    rescue StandardError => e
      "evolution error: #{e.message}"
    end
  end
end
