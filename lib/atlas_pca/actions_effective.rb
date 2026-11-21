# frozen_string_literal: true

# From an ActionDef to T(d), decl(d) and eff_R(d) with a caller-supplied confirmation verifier, plus the structural param rules
# (native port of effective.ts of the TypeScript reference @atlasauth/pca-actions). Actions.effective is the pinned-key form of the same.
require_relative 'actions'

module AtlasPca
  module ActionsEffective
    A = AtlasPca::Actions

    module_function

    def profile_eq(p, q) = A.leq(p, q) && A.leq(q, p)

    # Traits implied by a NORMALIZED def's own facts.
    def implied_traits(n)
      A.implied_from_facts(n['effects'], n['params'].values, n['resource']['scope'], A.worst_reversibility(n['reversibility'], n['params']))
    end

    # True iff the caller's verifier says the def carries a valid signed review. Absent => never.
    def confirmed?(d, verifier = nil) = !verifier.nil? && verifier.call(d) == true

    def traits_of_with(d, reg, verifier = nil) = confirmed?(d, verifier) ? A.hint_traits(d) : A.top_traits(reg)

    # {confirmed, traits, closure, floor, eff, decl, hint:{traits,closure,floor,eff}, clamps}; the verifier replaces the pinned keys.
    def effective_with(d, reg, verifier = nil)
      d = A.js.jsnorm(d)
      decl = A.decl_profile(d)
      view = lambda do |traits|
        floor = A.floor_of(reg, traits)
        { 'traits' => traits, 'closure' => A.closure(reg, traits), 'floor' => floor, 'eff' => A.join(decl, floor) }
      end
      hint = view.call(A.hint_traits(d))
      confirmed = confirmed?(d, verifier)
      main = confirmed ? hint : view.call(A.top_traits(reg))
      clamps = []
      clamps << { 'field' => 'rev', 'declared' => decl['rev'], 'floor' => hint['floor']['rev'] } if d.key?('reversibility') && A::REV_RANK[decl['rev']] < A::REV_RANK[hint['floor']['rev']]
      clamps << { 'field' => 'blast_ppm', 'declared' => decl['blast_ppm'], 'floor' => hint['floor']['blast_ppm'] } if d.key?('blast') && decl['blast_ppm'] < hint['floor']['blast_ppm']
      main.merge('confirmed' => confirmed, 'decl' => decl, 'hint' => hint, 'clamps' => clamps)
    end

    # The hint profile after adding trait `t` to the declared traits (never lower). Analysis only.
    def eff_with_trait(d, t, reg)
      d2 = d.merge('traits' => (d['traits'] || []) + [t])
      effective_with(d2, reg)['hint']['eff']
    end

    # Structural param rules (among `ids`) the def violates. A def violating a rule its traits require is not loadable.
    def prules_violations(d, ids = A::PARAM_RULE_IDS)
      n = A.normalize(d)
      ps = n['params'].values
      with_role = ->(&pred) { ps.select { |p| !p['role'].nil? && pred.call(p['role']) } }
      money_ok = lambda do |p|
        u = p['unit']
        next false if !u || u['kind'] != 'money'

        ccy = u['ccy']
        next true if ccy.is_a?(String)

        c = ccy.is_a?(Hash) ? n['params'][ccy['from']] : nil
        !c.nil? && c['role'] == 'money.currency' && c['format'] == 'iso_currency'
      end
      ids.reject do |rid|
        case rid
        when 'money_has_currency' then with_role.call { |r| %w[money.amount money.fee].include?(r) }.all? { |p| money_ok.call(p) }
        when 'money_amount_bounded' then with_role.call { |r| r == 'money.amount' }.all? { |p| p['type'] == 'integer' && p.key?('min') && p.key?('max') }
        when 'id_not_wildcard' then !(n['resource']['id'] == '*' && n['resource']['scope'] == 'one')
        when 'recipient_param_declared' then n['audience'] == 'resource' || !with_role.call { |r| r == 'party.payee' || r.start_with?('contact.') }.empty?
        when 'array_bounded' then ps.select { |p| p['type'] == 'array' }.all? { |p| !p['max_items'].nil? }
        when 'export_bounded' then n['resource']['scope'] == 'one' || with_role.call { |r| r == 'count.limit' }.any? { |p| p.key?('max') }
        when 'secret_not_logged' then with_role.call { |r| r.start_with?('credential.') }.all? { |p| (p['tags'] || []).include?('secret') }
        when 'pay_has_idempotency' then !n['effects'].include?('pay') || n['idempotency']['mode'] != 'none'
        else true
        end
      end
    end

    # Rules the effective profile requires but the def does not satisfy (the load-time check).
    def required_prules_violated(d, eff) = prules_violations(d, eff['prules'])
  end
end
