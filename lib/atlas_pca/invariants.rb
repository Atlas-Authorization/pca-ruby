# frozen_string_literal: true

require 'openssl'
require_relative 'risk'
require_relative 'prohibitions'
require_relative 'forbid_certificate'

# Property-based machine-checking of PCA's core safety invariants: attenuation monotonicity, budget soundness, fail-closed
# behaviour and determinism, run against the real AtlasPca core (nothing is re-implemented). Port of the TypeScript reference
# (@atlasauth/pca-invariants).
#
# The arbitraries are stdlib generators over a Random (the reference uses a property-testing library with its own generator and
# shrinking; neither is reproduced, so a given seed explores different cases than the reference). A property is a callable
# `prop.(rng) -> true/false`; check_invariants runs each one num_runs times from a fixed seed and reports a failing case's seed.
module AtlasPca
  module Invariants
    module_function

    DEFAULT_SEED = 20_260_108
    DEFAULT_NUM_RUNS = 1000
    EPS = 1e-9

    # ---- primitive generators ----------------------------------------------------------------------------------------------

    def int(rng, lo, hi) = rng.rand(lo..hi)

    # A double in [lo, hi], the endpoints included on purpose.
    def dbl(rng, lo, hi)
      r = rng.rand
      return lo if r < 0.08
      return hi if r < 0.16

      lo + ((hi - lo) * rng.rand)
    end

    def string(rng, lo = 0, hi = 10) = Array.new(rng.rand(lo..hi)) { rng.rand(0x20..0x7E).chr }.join

    def array(rng, lo, hi, &gen) = Array.new(rng.rand(lo..hi)) { gen.call(rng) }

    def bool(rng) = rng.rand < 0.5

    # 32 random bytes: a reproducible Ed25519 secret seed.
    def arb_seed32(rng) = Array.new(32) { rng.rand(256) }.pack('C*')

    # {secret_key, public_key, pub (b64url), signer}: any 32 bytes is a valid Ed25519 secret.
    def key_pair_from_seed(seed)
      signer = AtlasPca::KeyPair.new(seed)
      { 'secret_key' => seed, 'public_key' => OpenSSL::PKey.new_raw_private_key('ED25519', seed.b).raw_public_key,
        'pub' => signer.public, 'signer' => signer }
    end

    # ---- predicates, actions, caveat contexts -------------------------------------------------------------------------------

    VERBS = %w[read write delete transfer list admin].freeze
    RESOURCES = ['/acct/a', '/acct/b', '/docs/1', '/docs/2', '/x/y', '/'].freeze
    LEAF_OPS = %w[eq ne in nin lt lte gt gte prefix exists].freeze
    LEAF_FIELDS = %w[subject.role subject.tier env.ip action.verb action.resource action.params.amount].freeze

    def arb_verb(rng) = VERBS.sample(random: rng)
    def arb_resource(rng) = bool(rng) ? RESOURCES.sample(random: rng) : string(rng)

    def arb_leaf_condition(rng)
      pick = rng.rand(0..3)
      value = case pick
              when 0 then string(rng)
              when 1 then int(rng, -10, 10)
              when 2 then bool(rng)
              else array(rng, 0, 3) { |r| string(r) }
              end
      { 'field' => LEAF_FIELDS.sample(random: rng), 'op' => LEAF_OPS.sample(random: rng), 'value' => value }
    end

    def arb_predicate(rng)
      k = rng.rand(0..2)
      verb = case k
             when 0 then arb_verb(rng)
             when 1 then array(rng, 1, 3) { |r| arb_verb(r) }
             else '*'
             end
      rk = rng.rand(0..3)
      p = { 'verb' => verb }
      case rk
      when 1 then p['resource'] = '*'
      when 2 then p['resource'] = ['/acct/*', '/docs/*'].sample(random: rng)
      when 3 then p['resource'] = arb_resource(rng)
      end
      p['where'] = array(rng, 0, 2) { |r| arb_leaf_condition(r) } if bool(rng)
      p
    end

    def arb_predicate_list(rng) = array(rng, 1, 4) { |r| arb_predicate(r) }

    def arb_action_context(rng)
      action = { 'verb' => arb_verb(rng), 'resource' => arb_resource(rng) }
      if bool(rng)
        params = {}
        %w[amount target reason].sample(rng.rand(0..3), random: rng).each do |key|
          params[key] = case rng.rand(0..2)
                        when 0 then string(rng)
                        when 1 then int(rng, -5, 100)
                        else bool(rng)
                        end
        end
        action['params'] = params
      end
      ctx = { 'action' => action }
      role = %w[admin user guest].sample(random: rng)
      tier = int(rng, 0, 5)
      ip = string(rng)
      ctx['subject'] = { 'role' => role, 'tier' => tier } if bool(rng)
      ctx['env'] = { 'ip' => ip } if bool(rng)
      ctx
    end

    REVERSIBILITY = %w[reversible rate_limited irreversible teleport].freeze

    def arb_caveat_context(rng)
      ctx = { 'now' => int(rng, 0, 10_000_000) }
      ctx['blast_radius'] = dbl(rng, 0, 1) if bool(rng)
      ctx['reversibility_class'] = REVERSIBILITY.sample(random: rng) if bool(rng)
      ctx['delegation_depth'] = int(rng, 0, 20) if bool(rng)
      ctx['recent_action_times'] = array(rng, 0, 6) { |r| int(r, 0, 10_000_000) } if bool(rng)
      ctx
    end

    # An action + caveat context together: one point at which to probe a chain's effective authority.
    def arb_eval_point(rng) = { 'action' => arb_action_context(rng), 'cav_ctx' => arb_caveat_context(rng) }

    # ---- attenuating delegation chains -------------------------------------------------------------------------------------

    def arb_caveat_spec(rng)
      case rng.rand(0..6)
      when 0 then { 'k' => 'expires', 'at' => int(rng, 0, 10_000_000) }
      when 1 then { 'k' => 'not_before', 'at' => int(rng, 0, 10_000_000) }
      when 2 then { 'k' => 'rate', 'max' => int(rng, 1, 10), 'per_secs' => int(rng, 1, 3600) }
      # quantized to 3 decimals so the limit is canonical-wire-safe
      when 3 then { 'k' => 'max_blast_radius', 'max' => int(rng, 0, 1000) / 1000.0 }
      when 4 then { 'k' => 'reversibility_max', 'cls' => %w[reversible rate_limited irreversible].sample(random: rng) }
      when 5 then { 'k' => 'delegation_depth', 'max' => int(rng, 0, 20) }
      else { 'k' => 'budget_frac', 'frac' => dbl(rng, 0, 1) }
      end
    end

    BUDGET_ALLOC_BASE = 1_000_000

    def spec_to_caveat(spec, alloc)
      case spec['k']
      when 'expires', 'not_before' then { 'type' => spec['k'], 'at' => spec['at'] }
      when 'rate' then { 'type' => 'rate', 'max' => spec['max'], 'per_secs' => spec['per_secs'] }
      when 'max_blast_radius' then { 'type' => 'max_blast_radius', 'max' => spec['max'] }
      when 'reversibility_max' then { 'type' => 'reversibility_max', 'class' => spec['cls'] }
      when 'delegation_depth' then { 'type' => 'delegation_depth', 'max' => spec['max'] }
      when 'budget_frac'
        base = alloc['running'].finite? ? alloc['running'] : BUDGET_ALLOC_BASE
        # frac in [0,1] and base a non-negative integer: an integer <= the previous allocation (monotone, canonical-wire-safe)
        limit = (base * spec['frac']).floor
        alloc['running'] = limit
        { 'type' => 'budget_alloc', 'limit' => limit }
      else raise ArgumentError, "unknown caveat spec #{spec['k'].inspect}"
      end
    end

    # A signed, legally-attenuating chain from a model {principal_seed, holder0_seed, root_specs, hops: [{holder_seed, added_specs}],
    # predicates}. Returns {caps, predicates, root_issuer, holders}.
    def build_chain(m)
      alloc = { 'running' => Float::INFINITY }
      principal = key_pair_from_seed(m['principal_seed'])
      holder0 = key_pair_from_seed(m['holder0_seed'])
      root = AtlasPca.mint_root(principal['signer'], holder0['pub'], m['root_specs'].map { |s| spec_to_caveat(s, alloc) })
      caps = [root]
      holders = [holder0['pub']]
      prev = root
      signer = holder0['signer'] # the next hop is signed by the key the parent is bound to
      m['hops'].each do |hop|
        to = key_pair_from_seed(hop['holder_seed'])
        cap = AtlasPca.delegate_cap(prev, signer, to_holder: to['pub'], added: hop['added_specs'].map { |s| spec_to_caveat(s, alloc) })
        caps << cap
        holders << to['pub']
        prev = cap
        signer = to['signer']
      end
      { 'caps' => caps, 'predicates' => m['predicates'], 'root_issuer' => principal['pub'], 'holders' => holders }
    end

    def arb_chain(rng)
      build_chain({
                    'principal_seed' => arb_seed32(rng), 'holder0_seed' => arb_seed32(rng),
                    'root_specs' => array(rng, 1, 4) { |r| arb_caveat_spec(r) },
                    'hops' => array(rng, 0, 5) do |r|
                      { 'holder_seed' => arb_seed32(r), 'added_specs' => array(r, 0, 3) { |q| arb_caveat_spec(q) } }
                    end,
                    'predicates' => arb_predicate_list(rng)
                  })
    end

    # ---- risk policy / inputs / budget -------------------------------------------------------------------------------------

    def arb_risk_weights(rng) = %w[alpha beta gamma delta epsilon zeta].to_h { |k| [k, dbl(rng, 0, 2)] }

    # A well-formed risk policy: kappa > 0, 0 <= theta1 <= theta2, the rest finite >= 0.
    def arb_risk_policy(rng)
      theta1 = dbl(rng, 0, 1)
      { 'weights' => arb_risk_weights(rng), 'theta1' => theta1, 'theta2' => theta1 + dbl(rng, 0, 1), 'kappa' => dbl(rng, 0.001, 5),
        'lambda' => dbl(rng, 0, 0.01), 'rho' => dbl(rng, 0, 2), 'bMax' => dbl(rng, 0, 10) }
    end

    def arb_risk_inputs(rng) = %w[semanticDistance reversibility blastRadius taint confidence age].to_h { |k| [k, dbl(rng, 0, 1)] }

    def arb_trust_budget(rng)
      b = { 'B' => dbl(rng, 0, 10), 'tau' => int(rng, 0, 10_000_000) }
      b['asOf'] = int(rng, 0, 10_000_000) if bool(rng)
      b
    end

    def arb_risk_deltas(rng) = %w[dSem dBlast dTaint dAge dRev dConf].to_h { |k| [k, dbl(rng, 0, 1)] }

    def clamp01(x) = x < 0 ? 0 : (x > 1 ? 1 : x)

    # A risk input that is >= base in every risk-increasing axis and <= in every protective axis.
    def worsen(base, d)
      {
        'semanticDistance' => clamp01(base['semanticDistance'] + d['dSem']),
        'blastRadius' => clamp01(base['blastRadius'] + d['dBlast']),
        'taint' => clamp01(base['taint'] + d['dTaint']),
        'age' => clamp01(base['age'] + d['dAge']),
        'reversibility' => clamp01(base['reversibility'] - d['dRev']),
        'confidence' => clamp01(base['confidence'] - d['dConf'])
      }
    end

    # ---- 1. attenuation monotonicity ---------------------------------------------------------------------------------------

    def auth_allowed?(caveats, predicates, pt)
      return false unless AtlasPca.evaluate_predicates(predicates, pt['action'])['allowed']

      AtlasPca.evaluate_caveats(caveats, pt['cav_ctx'])[0]
    end

    def alloc_limits(caveats)
      caveats.filter_map do |cv|
        cv['limit'] if cv.is_a?(Hash) && cv['type'] == 'budget_alloc' && cv['limit'].is_a?(Numeric)
      end
    end

    # verify_chain answers [reason, ok]
    def chain_ok?(caps, root) = AtlasPca.verify_chain(caps, root, true)[1] == true

    # A legal chain verifies; each hop's caveats extend its parent's append-only; budget_alloc limits never grow; and at every probe
    # point the per-hop verdict is monotone non-increasing root to leaf (a delegate step can only shrink or preserve authority).
    def attenuation_monotonicity_property
      lambda do |rng|
        chain = arb_chain(rng)
        points = array(rng, 1, 5) { |r| arb_eval_point(r) }
        caps = chain['caps']
        return false unless chain_ok?(caps, chain['root_issuer'])

        (1...caps.length).each do |i|
          parent = caps[i - 1]['caveats']
          child = caps[i]['caveats']
          return false if child.length < parent.length

          parent.each_index { |j| return false if AtlasPca.hash_canonical(child[j]) != AtlasPca.hash_canonical(parent[j]) }
        end
        leaf = caps[-1]
        return false unless AtlasPca.allocations_monotone_error(leaf['caveats']).nil?

        limits = alloc_limits(leaf['caveats'])
        (1...limits.length).each { |i| return false if limits[i] > limits[i - 1] }
        points.each do |pt|
          ancestor_allowed = true
          caps.each do |cap|
            allowed = auth_allowed?(cap['caveats'], chain['predicates'], pt)
            return false if allowed && !ancestor_allowed # a true after a false would be a widening

            ancestor_allowed = allowed
          end
        end
        true
      end
    end

    # ---- 2. budget soundness -----------------------------------------------------------------------------------------------

    # r is clamped to [0, 1] and a pointwise-worse input never yields a lower r.
    def risk_monotone_property
      lambda do |rng|
        policy = arb_risk_policy(rng)
        inputs = arb_risk_inputs(rng)
        deltas = arb_risk_deltas(rng)
        r = AtlasPca::Risk.risk_score(inputs, policy['weights'])
        return false unless r >= 0 && r <= 1

        r_worse = AtlasPca::Risk.risk_score(worsen(inputs, deltas), policy['weights'])
        return false unless r_worse >= 0 && r_worse <= 1

        r_worse + EPS >= r
      end
    end

    # Whenever admit lets an action proceed without a human, the admitted cost kappa*r is covered by the budget; and safety_bound is
    # exactly bMax/kappa.
    def admission_soundness_property
      lambda do |rng|
        policy = arb_risk_policy(rng)
        inputs = arb_risk_inputs(rng)
        budget = arb_trust_budget(rng)
        return false unless AtlasPca.risk_policy_error(policy).nil?

        r = AtlasPca::Risk.risk_score(inputs, policy['weights'])
        c = AtlasPca::Risk.cost(r, policy['kappa'])
        adm = AtlasPca::Risk.admit(r, budget, policy)
        if adm['metered']
          return false if adm['t'] >= 3
          return false unless budget['B'] + EPS >= c
        end
        if adm['admit']
          return false if adm['t'] != 1 || !adm['metered']
          return false unless budget['B'] + EPS >= c
        end
        expected = policy['kappa'] > 0 ? [0, policy['bMax']].max / policy['kappa'].to_f : 0
        (AtlasPca::Risk.safety_bound(policy) - expected).abs <= EPS
      end
    end

    # From a full budget, any sequence of machine-only actions debiting kappa*r never drives B negative and the total admitted risk
    # obeys Sum(r) <= bMax/kappa.
    def cumulative_budget_bound_property
      lambda do |rng|
        policy = arb_risk_policy(rng)
        seq = array(rng, 1, 40) { |r| arb_risk_inputs(r) }
        bound = AtlasPca::Risk.safety_bound(policy)
        b = [0, policy['bMax']].max
        sum_r = 0.0
        seq.each do |inputs|
          r = AtlasPca::Risk.risk_score(inputs, policy['weights'])
          adm = AtlasPca::Risk.admit(r, { 'B' => b, 'tau' => 0, 'asOf' => 0 }, policy)
          next unless adm['metered'] && adm['t'] < 3

          c = AtlasPca::Risk.cost(r, policy['kappa'])
          return false unless b + EPS >= c

          b = [0, b - c].max
          sum_r += r
          return false if b < -EPS
          return false unless policy['kappa'] * sum_r <= policy['bMax'] + 1e-6
          return false unless sum_r <= bound + 1e-6
        end
        true
      end
    end

    # ---- 3. fail-closed ----------------------------------------------------------------------------------------------------

    KNOWN_CAVEAT_TYPES = %w[expires not_before rate max_blast_radius reversibility_max delegation_depth budget_alloc max_spend
                            intent_session].freeze

    UNDECIDABLES = [
      ->(f) { { 'field' => "#{f}.definitely_absent", 'op' => 'eq', 'value' => 'x' } }, # missing field
      ->(f) { { 'field' => f, 'op' => 'lt', 'value' => 5 } }, # string field vs number: incomparable
      ->(f) { { 'field' => f, 'op' => 'in', 'value' => 'not-an-array' } }, # non-array operand
      ->(f) { { 'field' => f, 'op' => 'eq' } }, # no value and no ref
      ->(f) { { 'field' => f, 'op' => 'member_of', 'value' => 'g', 'collection' => 'env.no_such_collection' } } # missing collection
    ].freeze

    # Every structurally undecidable leaf evaluates to 'unknown' (never 'true'), so a predicate carrying it never grants.
    def undecidable_leaf_fails_closed_property
      lambda do |rng|
        make = UNDECIDABLES.sample(random: rng)
        verb = %w[read write delete].sample(random: rng)
        resource = '/x'
        ctx = { 'action' => { 'verb' => verb, 'resource' => resource }, 'subject' => { 'role' => 'admin' } }
        leaf = make.call('subject.role')
        return false if AtlasPca.evaluate_condition_tri(leaf, ctx) == 'true'
        return false unless AtlasPca.evaluate_condition(leaf, ctx) == false

        AtlasPca.evaluate_predicates([{ 'verb' => verb, 'resource' => resource, 'where' => [leaf] }], ctx)['allowed'] == false
      end
    end

    # not / all_of / any_of over undecidable or empty children fail closed (never 'true').
    def undecidable_groups_fail_closed_property
      lambda do |_rng|
        ctx = { 'action' => { 'verb' => 'read', 'resource' => '/x' }, 'subject' => { 'role' => 'admin' } }
        child = { 'field' => 'subject.role', 'op' => 'lt', 'value' => 5 }
        [{ 'not' => child }, { 'all_of' => [] }, { 'any_of' => [] }, { 'all_of' => [child] }, { 'any_of' => [child] }].none? do |c|
          AtlasPca.evaluate_condition_tri(c, ctx) == 'true'
        end
      end
    end

    # member_of over a cyclic adjacency terminates with a correct verdict and fails closed on an unreachable target.
    def member_of_cycle_safe_property
      lambda do |rng|
        target = %w[a b c z].sample(random: rng)
        rel = { 'a' => ['b'], 'b' => %w[a c] } # a -> b -> a is a cycle; c hangs off b; z is absent
        ctx = { 'action' => { 'verb' => 'read', 'resource' => '/x' }, 'subject' => { 'g' => 'a' }, 'env' => { 'rel' => rel } }
        tri = AtlasPca.evaluate_condition_tri({ 'field' => 'subject.g', 'op' => 'member_of', 'value' => target, 'collection' => 'env.rel' }, ctx)
        tri == (%w[a b c].include?(target) ? 'true' : 'false')
      end
    end

    # An unknown caveat type is never satisfied, so a caveat set containing it is never ok.
    def unknown_caveat_type_denies_property
      lambda do |rng|
        t = string(rng, 1, 12)
        t = string(rng, 1, 12) while KNOWN_CAVEAT_TYPES.include?(t)
        cav = { 'type' => t }
        ctx = { 'now' => int(rng, 0, 10_000_000) }
        return false unless AtlasPca.caveat_satisfied?(cav, ctx) == false

        AtlasPca.evaluate_caveats([cav], ctx)[0] == false
      end
    end

    ALL_MUTATIONS = %w[tamper-caveat drop-leaf-caveat swap-holder break-parent bad-sig wrong-root-issuer suite-mismatch break-id
                       append-forged-hop].freeze

    def deep_copy(v) = Marshal.load(Marshal.dump(v))

    # A legal chain mutated by one of nine attacks (tampered or dropped caveat, swapped holder, broken parent link, bad signature,
    # wrong root issuer, mismatched suite, broken id, appended unsigned hop) never verifies.
    def forged_chain_rejected_property
      lambda do |rng|
        chain = arb_chain(rng)
        mutation = ALL_MUTATIONS.sample(random: rng)
        pick = int(rng, 0, 1_000_000)
        aux_seed = arb_seed32(rng)
        caps = chain['caps']
        root = chain['root_issuer']
        return false unless chain_ok?(caps, root)

        n = caps.length
        idx = pick % n
        aux = key_pair_from_seed(aux_seed)
        rejects = ->(m) { AtlasPca.verify_chain(m, root, true)[1] == false }
        m = deep_copy(caps)
        case mutation
        when 'tamper-caveat'
          m[idx]['caveats'] += [{ 'type' => 'expires', 'at' => 999 }]
          rejects.call(m)
        when 'drop-leaf-caveat'
          return true if m[n - 1]['caveats'].empty? # inapplicable: trivially pass

          m[n - 1]['caveats'] = m[n - 1]['caveats'][0...-1]
          rejects.call(m)
        when 'swap-holder'
          m[idx]['holder'] = aux['pub'] # changes the signed body: digest mismatch
          rejects.call(m)
        when 'break-parent'
          return true if n < 2

          m[[1, idx].max]['parent'] = AtlasPca.hash_canonical({ 'bogus' => aux_seed.bytesize, 'tag' => 'not-a-real-parent' })
          rejects.call(m)
        when 'bad-sig'
          m[idx]['sig'] = AtlasPca.b64e(aux['signer'].sign([1, 2, 3, 4].pack('C*'))) # well-formed but wrong: other bytes, other key
          rejects.call(m)
        when 'wrong-root-issuer'
          return true if aux['pub'] == root

          AtlasPca.verify_chain(caps, aux['pub'], true)[1] == false
        when 'suite-mismatch'
          m[idx]['alg'] = 'ml-dsa-65' # the suite fields are bound into body_digest, so this must be rejected
          rejects.call(m)
        when 'break-id'
          m[idx]['id'] = AtlasPca.hash_canonical({ 'not' => 'the-body-digest', 'n' => idx })
          rejects.call(m)
        else
          # append-forged-hop: issued as if from the leaf, but signed by a key that is not the leaf's holder
          forged = AtlasPca.delegate_cap(caps[n - 1], aux['signer'], to_holder: aux['pub'], added: [])
          rejects.call(caps + [forged])
        end
      end
    end

    def arb_unsigned_capability(rng)
      { 'id' => string(rng), 'issuer' => string(rng), 'holder' => string(rng), 'caveats' => array(rng, 0, 3) { |r| { 'type' => string(r) } },
        'body_digest' => string(rng), 'sig' => string(rng) }
    end

    # Arbitrary never-signed chains (including the empty chain) never verify.
    def garbage_chain_rejected_property
      lambda do |rng|
        AtlasPca.verify_chain(array(rng, 0, 4) { |r| arb_unsigned_capability(r) }, nil, false)[1] == false
      end
    end

    # ---- 4. determinism ----------------------------------------------------------------------------------------------------

    # verify_chain, evaluate_predicates, evaluate_caveats, risk_score, required_threshold and admit are deterministic.
    def determinism_property
      lambda do |rng|
        chain = arb_chain(rng)
        pt = arb_eval_point(rng)
        preds = arb_predicate_list(rng)
        policy = arb_risk_policy(rng)
        inputs = arb_risk_inputs(rng)
        budget = arb_trust_budget(rng)
        return false if AtlasPca.verify_chain(chain['caps'], chain['root_issuer'], true) != AtlasPca.verify_chain(chain['caps'], chain['root_issuer'], true)

        p1 = AtlasPca.evaluate_predicates(preds, pt['action'])
        p2 = AtlasPca.evaluate_predicates(preds, pt['action'])
        return false if p1['allowed'] != p2['allowed'] || p1['reason'] != p2['reason']

        leaf = chain['caps'][-1]
        c1 = AtlasPca.evaluate_caveats(leaf['caveats'], pt['cav_ctx'])
        c2 = AtlasPca.evaluate_caveats(leaf['caveats'], pt['cav_ctx'])
        return false if c1[0] != c2[0] || c1[1].join('|') != c2[1].join('|')

        r1 = AtlasPca::Risk.risk_score(inputs, policy['weights'])
        return false if r1 != AtlasPca::Risk.risk_score(inputs, policy['weights'])
        return false if AtlasPca::Risk.required_threshold(r1, policy) != AtlasPca::Risk.required_threshold(r1, policy)

        AtlasPca::Risk.admit(r1, budget, policy) == AtlasPca::Risk.admit(r1, budget, policy)
      end
    end

    # Forbid-wins is monotone and order-independent: adding a forbid clause can only move a decision down, a forbid that matches
    # always denies whatever the permits say, and the decision does not depend on the clause order.
    def forbid_monotone_property
      ranks = { 'deny' => 0, 'escalate' => 1, 'allow' => 2 }
      mk = ->(kind, ps, tag) { ps.each_with_index.map { |w, i| { 'id' => "#{tag}#{i}", 'kind' => kind, 'when' => w } } }
      lambda do |rng|
        permits = arb_predicate_list(rng)
        forbids = arb_predicate_list(rng)
        extra = arb_predicate_list(rng)
        pt = arb_eval_point(rng)
        rot = int(rng, 0, 5)
        base = mk.call('permit', permits, 'p') + mk.call('escalate', extra, 'e')
        with_forbid = base + mk.call('forbid', forbids, 'f')
        before = AtlasPca.decide_clauses(base, pt['action'])['decision']
        after = AtlasPca.decide_clauses(with_forbid, pt['action'])['decision']
        return false if ranks[after] > ranks[before] # adding a forbid must never grow the admit set
        return false if forbids.any? { |w| AtlasPca::Prohibitions.when_matches?(w, pt['action']) } && after != 'deny' # a matching forbid beats every permit

        k = rot % with_forbid.length
        AtlasPca.decide_clauses(with_forbid[k..] + with_forbid[0...k], pt['action'])['decision'] == after
      end
    end

    # ---- runner / registry -------------------------------------------------------------------------------------------------

    def assert_property(prop, num_runs, seed)
      rng = Random.new(seed)
      num_runs.times do |i|
        case_seed = rng.rand(2**64)
        raise "property failed after #{i + 1} run(s) (seed #{seed}, case seed #{case_seed})" unless prop.call(Random.new(case_seed)) == true
      end
    end

    # A named invariant whose #run(num_runs, seed) executes its property-based check (raises on a counterexample).
    class Invariant
      attr_reader :name

      def initialize(name, make)
        @name = name
        @make = make
      end

      def run(num_runs, seed) = Invariants.assert_property(@make.call, num_runs, seed)
    end

    INVARIANTS = [
      Invariant.new('attenuation-monotonicity', -> { attenuation_monotonicity_property }),
      Invariant.new('risk-wellformed-and-monotone', -> { risk_monotone_property }),
      Invariant.new('admission-soundness', -> { admission_soundness_property }),
      Invariant.new('cumulative-budget-bound', -> { cumulative_budget_bound_property }),
      Invariant.new('fail-closed:undecidable-leaf', -> { undecidable_leaf_fails_closed_property }),
      Invariant.new('fail-closed:undecidable-groups', -> { undecidable_groups_fail_closed_property }),
      Invariant.new('fail-closed:member-of-cycle-safe', -> { member_of_cycle_safe_property }),
      Invariant.new('fail-closed:unknown-caveat-type', -> { unknown_caveat_type_denies_property }),
      Invariant.new('fail-closed:forged-chain-rejected', -> { forged_chain_rejected_property }),
      Invariant.new('fail-closed:garbage-chain-rejected', -> { garbage_chain_rejected_property }),
      Invariant.new('forbid-monotone', -> { forbid_monotone_property }),
      Invariant.new('determinism', -> { determinism_property })
    ].freeze

    # a JS safe integer: an Integer (or integral finite Float) within 2^53 - 1; never a boolean
    def safe_int?(v)
      return v.abs <= (2**53) - 1 if v.is_a?(Integer)

      v.is_a?(Float) && v.finite? && v == v.floor && v.abs <= (2**53) - 1
    end

    # Machine-check every invariant. opts (String keys): 'num_runs', 'seed', 'bail', 'invariants' (the registry, default INVARIANTS).
    # Returns one {name, ok, numRuns, seed, error?} per invariant; ok false with an error is a surfaced counterexample (a candidate
    # core bug). Raises ArgumentError on a non-positive run count or a non-integer seed (zero cases would pass vacuously).
    def check_invariants(opts = {})
      runs = opts['num_runs'].nil? ? DEFAULT_NUM_RUNS : opts['num_runs']
      sd = opts['seed'].nil? ? DEFAULT_SEED : opts['seed']
      raise ArgumentError, 'checkInvariants: numRuns must be a positive integer' if !safe_int?(runs) || runs < 1
      raise ArgumentError, 'checkInvariants: seed must be an integer' unless safe_int?(sd)

      runs = runs.to_i
      sd = sd.to_i
      results = []
      (opts['invariants'] || INVARIANTS).each do |inv|
        inv.run(runs, sd)
        results << { 'name' => inv.name, 'ok' => true, 'numRuns' => runs, 'seed' => sd }
      rescue StandardError => e # a counterexample or a core fault is reported, not raised
        results << { 'name' => inv.name, 'ok' => false, 'numRuns' => runs, 'seed' => sd, 'error' => e.message }
        break if opts['bail']
      end
      results
    end
  end
end
