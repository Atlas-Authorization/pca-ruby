# frozen_string_literal: true

require 'openssl'
require_relative 'js_compat'

# Payments for PCA, matching the TypeScript reference (@atlasauth/pca-payments): a payment mandate as a Root Intent Grant,
# the charge decision, the charge PCActn, Shared Payment Token limits, spend rails, the Stripe Issuing adapter and agent network
# tokens (payments_rails.rb, payments_token.rb). Values are the reference's JSON shapes (String-keyed Hashes with its camelCase
# members); an OPTIONS hash is String-keyed snake_case. Inputs follow JavaScript semantics where the reference does (an absent
# member is UNDEF, truthiness, coercing arithmetic), so a hostile mandate or charge is refused or priced exactly as the reference
# does. This package carries no policy engine: the charge decision takes the PCA policy decision function as an injected
# callable `decide.call(decide_input) -> policy_decision`; HTTP is injected too (a partner transport is `post.call(path, body)`).
module AtlasPca
  module Payments
    UNDEF = Object.new.freeze # a JSON member that is absent (distinct from null)

    CHARGE_REVERSIBILITY_CLASS = 'reversible'
    CHARGE_VERB = 'charge'
    AMOUNT_NOT_MINOR_UNITS = 'amount_not_integer_minor_units'
    MERCHANT_INVALID = 'merchant_invalid'
    STRIPE_WEBHOOK_TOLERANCE_SEC = 300
    STRIPE_API_VERSION = '2025-03-31.basil'
    NETWORK_TOKEN_BINDING_KIND = 'pca.network_token_binding'
    MAX_CAS_ATTEMPTS = 8
    MAX_SAFE = (2**53) - 1

    # code: verified_grant_required | mandate_grant_mismatch | mandate_terms_mismatch.
    class MandateGrantError < StandardError
      attr_reader :code

      def initialize(code, message)
        super(message)
        @code = code
      end
    end

    class ChargeStoreError < StandardError; end

    module_function

    # ---- JS-semantics helpers -------------------------------------------------------------------------------------------

    def undef?(v) = v.equal?(UNDEF)
    def nullish?(v) = v.nil? || undef?(v)
    def num?(v) = v.is_a?(Integer) || v.is_a?(Float)
    def finite?(v) = v.is_a?(Integer) || (v.is_a?(Float) && v.finite?)

    def safe_int?(v)
      return v.abs <= MAX_SAFE if v.is_a?(Integer)

      v.is_a?(Float) && v.finite? && v == v.floor && v.abs <= MAX_SAFE
    end

    def neg_zero?(v) = v.is_a?(Float) && v.zero? && (1.0 / v).negative?
    def truthy?(v) = undef?(v) ? false : Js.truthy?(v)

    # `o.k`: TypeError for null / undefined, UNDEF for a missing member or a primitive.
    def prop(o, k)
      raise TypeError, "Cannot read properties of #{o.nil? ? 'null' : 'undefined'} (reading '#{k}')" if nullish?(o)

      o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF
    end

    def optprop(o, k) = nullish?(o) ? UNDEF : prop(o, k)

    # `v.length`: TypeError for null / undefined, UNDEF when there is none.
    def length(v)
      raise TypeError, "Cannot read properties of undefined (reading 'length')" if nullish?(v)
      return Js.len16(v) if v.is_a?(String)
      return v.length if v.is_a?(Array)

      v.is_a?(Hash) && v.key?('length') ? v['length'] : UNDEF
    end

    # A user-supplied option hash: reading a member off anything else is a TypeError.
    def opt(o, k)
      raise TypeError, 'options must be an object' unless o.is_a?(Hash)

      o.key?(k) ? o[k] : nil
    end

    # JS ToNumber for the JSON types (null 0, true 1, numeric strings, one-element arrays), NaN otherwise.
    def to_number(x)
      case x
      when nil, false then 0.0
      when true then 1.0
      when Integer then x.to_f
      when Float then x
      when String then string_to_number(x)
      when Array
        return 0.0 if x.empty?
        return string_to_number(x[0].nil? ? '' : Js.string(x[0])) if x.length == 1 && !x[0].is_a?(Array) && !x[0].is_a?(Hash)

        Float::NAN
      else Float::NAN
      end
    end

    JS_DEC = /\A[+-]?(?:\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?)\z/

    def string_to_number(x)
      s = Js.trim(x.dup.force_encoding('UTF-8').scrub)
      return 0.0 if s.empty?
      return Float(s.sub(/\A([+-]?)\./) { "#{Regexp.last_match(1)}0." }.sub(/\.(?=[eE]|\z)/, '.0')) if s.match?(JS_DEC) && s.ascii_only?
      return Float::INFINITY if ['Infinity', '+Infinity'].include?(s)
      return -Float::INFINITY if s == '-Infinity'
      return s[2..].to_i(16).to_f if s.match?(/\A0[xX][0-9a-fA-F]+\z/)
      return s[2..].to_i(8).to_f if s.match?(/\A0[oO][0-7]+\z/)
      return s[2..].to_i(2).to_f if s.match?(/\A0[bB][01]+\z/)

      Float::NAN
    end

    def gt0?(v) = to_number(v) > 0

    def spread_list(v)
      return v.dup if v.is_a?(Array)
      return v.chars if v.is_a?(String)

      raise TypeError, 'object is not iterable'
    end

    def spread_obj(v)
      return v.dup if v.is_a?(Hash)
      return v.each_with_index.to_h { |c, i| [i.to_s, c] } if v.is_a?(Array)
      return v.chars.each_with_index.to_h { |c, i| [i.to_s, c] } if v.is_a?(String)

      {}
    end

    # String(v) as a template literal renders it.
    def tostr(v) = undef?(v) ? 'undefined' : Js.string(v)

    def js_div(a, b) = to_number(a) / to_number(b)

    def js_round(x)
      return x if x.nan? || x.infinite?

      r = x.floor
      (x - r >= 0.5 ? r + 1 : r).to_f
    end

    def js_floor(x) = x.nan? || x.infinite? ? x : x.floor.to_f

    def js_min(a, b)
      x = to_number(a)
      y = to_number(b)
      x.nan? || y.nan? ? Float::NAN : [x, y].min
    end

    def js_max(a, b)
      x = to_number(a)
      y = to_number(b)
      x.nan? || y.nan? ? Float::NAN : [x, y].max
    end

    # An integral float is returned as an Integer so a whole number serialises as one.
    def num(v) = v.is_a?(Float) && v.finite? && v == v.floor && v.abs < 2**63 ? v.to_i : v

    # JS strict equality for JSON values.
    def seq?(a, b)
      return a.equal?(b) if undef?(a) || undef?(b)
      return a.equal?(b) if [true, false].include?(a) || [true, false].include?(b)
      return a == b if num?(a) && num?(b)

      a.class == b.class && a == b
    end

    # The UTF-16BE code units of a string (a lone surrogate, WTF-8, is its own unit), for the JS string order.
    def u16(s)
      return s.encode('UTF-16BE').b if s.valid_encoding?

      s.b.split(/(\xED[\xA0-\xBF][\x80-\xBF])/n).map do |part|
        if part.match?(/\A\xED[\xA0-\xBF][\x80-\xBF]\z/n)
          b = part.bytes
          [((b[0] & 0x0f) << 12) | ((b[1] & 0x3f) << 6) | (b[2] & 0x3f)].pack('n')
        else
          part.dup.force_encoding('UTF-8').encode('UTF-16BE').b
        end
      end.join.b
    end

    def js_gt?(a, b)
      return (u16(a) <=> u16(b)) == 1 if a.is_a?(String) && b.is_a?(String)

      to_number(a) > to_number(b)
    end

    def drop(h) = h.reject { |_, v| undef?(v) }

    def hash_of(v)
      raise TypeError, 'canonicalize: unsupported type undefined' if undef?(v)

      AtlasPca.hash_canonical(v)
    end

    def now_ms = (Time.now.to_f * 1000).to_i

    # ---- mandate --------------------------------------------------------------------------------------------------------

    # A merchant id that cannot act as a resource pattern: no `*`, no control characters (matched on bytes: a lone surrogate is fine).
    def plain_id?(x) = x.is_a?(String) && !x.empty? && !x.b.match?(/[*\x00-\x1f\x7f]/n)

    # A non-negative safe integer (amounts are integer minor units).
    def minor_units?(x) = safe_int?(x) && x >= 0 && !neg_zero?(x)

    def validate(p)
      g = ->(k) { prop(p, k) }
      unless g.call('strict_minor_units') == false
        rep = g.call('replenish_per_cosign')
        { 'perTransactionCap' => g.call('per_transaction_cap'), 'autoApproveThreshold' => g.call('auto_approve_threshold'),
          'cumulativeCap' => g.call('cumulative_cap'), 'replenishPerCosign' => nullish?(rep) ? 0 : rep }.each do |k, v|
          raise ArgumentError, "buildPaymentMandate: #{k} must be a safe integer in minor units (strictMinorUnits)" unless safe_int?(v)
        end
      end
      m = g.call('merchants')
      raise ArgumentError, 'buildPaymentMandate: at least one allowlisted merchant is required' unless m.is_a?(Array) && !m.empty?
      raise ArgumentError, 'buildPaymentMandate: merchant ids must be non-empty strings' if m.any? { |x| !x.is_a?(String) || x.empty? }
      raise ArgumentError, 'buildPaymentMandate: merchant ids must not contain `*` or control characters' unless m.all? { |x| plain_id?(x) }

      cur = g.call('currency')
      raise ArgumentError, 'buildPaymentMandate: currency is required' unless cur.is_a?(String) && !cur.empty?

      x = g.call('per_transaction_cap')
      y = g.call('auto_approve_threshold')
      cap = g.call('cumulative_cap')
      raise ArgumentError, 'buildPaymentMandate: perTransactionCap (X) must be a finite number > 0' if !finite?(x) || x <= 0
      raise ArgumentError, 'buildPaymentMandate: autoApproveThreshold (Y) must satisfy 0 ≤ Y ≤ X' if !finite?(y) || y.negative? || y > x
      raise ArgumentError, 'buildPaymentMandate: cumulativeCap must be a finite number ≥ perTransactionCap (X)' if !finite?(cap) || cap < x

      pm = g.call('period_ms')
      raise ArgumentError, 'buildPaymentMandate: periodMs must be a finite number > 0 when given' if !undef?(pm) && (!finite?(pm) || pm <= 0)

      mx = g.call('max_transactions_per_period')
      if !undef?(mx) && ((!safe_int?(mx) && !(finite?(mx) && mx == mx.floor)) || mx <= 0)
        raise ArgumentError, 'buildPaymentMandate: maxTransactionsPerPeriod must be a positive integer when given'
      end

      rep = g.call('replenish_per_cosign')
      return if undef?(rep) || (finite?(rep) && !rep.negative?)

      raise ArgumentError, 'buildPaymentMandate: replenishPerCosign must be a finite number ≥ 0 when given'
    end

    def cond(field, op, value) = drop({ 'field' => field, 'op' => op, 'value' => value })

    # One predicate per merchant, each carrying the currency, category and hard-ceiling guards.
    def mandate_predicates(terms)
      merchants = prop(terms, 'merchants')
      raise TypeError, 'terms.merchants.map is not a function' unless merchants.is_a?(Array)

      merchants.map do |m|
        conds = [cond('action.params.amount', 'lte', prop(terms, 'perTransactionCap')),
                 cond('action.params.currency', 'eq', prop(terms, 'currency')),
                 cond('action.params.amount', 'gte', 0)]
        cats = prop(terms, 'categories')
        n = length(cats)
        conds << cond('action.params.category', 'in', cats) if !undef?(n) && gt0?(n)
        { 'verb' => 'charge', 'resource' => "merchant:#{tostr(m)}", 'where' => conds }
      end
    end

    # The envelope caveats: period window, velocity cap, and the bonded / refundable reversibility floor.
    def mandate_caveats(terms)
      cv = []
      ps = prop(terms, 'periodStart')
      cv << { 'type' => 'not_before', 'at' => ps } if gt0?(ps)
      pe = prop(terms, 'periodEnd')
      cv << { 'type' => 'expires', 'at' => pe } unless undef?(pe)
      mx = prop(terms, 'maxTransactionsPerPeriod')
      if !undef?(mx) && !undef?(pe)
        per = js_max(1, js_round(js_div(to_number(pe) - to_number(ps), 1000.0)))
        cv << { 'type' => 'rate', 'max' => mx, 'per_secs' => num(per) }
      end
      cv << { 'type' => 'reversibility_max', 'class' => 'reversible' }
      cv
    end

    # The risk policy that makes "spend = risk" exact: only blast radius weighs, theta1 = theta2 = Y/X, kappa = X, bMax = cap.
    def mandate_risk_policy(terms, replenish_per_cosign)
      a = prop(terms, 'autoApproveThreshold')
      x = prop(terms, 'perTransactionCap')
      th = num(js_div(a, x))
      drop({ 'weights' => { 'alpha' => 0, 'beta' => 0, 'gamma' => 1, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0 },
             'theta1' => th, 'theta2' => th, 'kappa' => x, 'lambda' => 0, 'rho' => replenish_per_cosign,
             'bMax' => prop(terms, 'cumulativeCap') })
    end

    # The most an agent can spend autonomously between two human co-signs: safetyBound * kappa (equals cumulativeCap).
    def auto_spend_bound(mandate)
      p = prop(mandate, 'policy')
      kappa = prop(p, 'kappa')
      b_max = prop(p, 'bMax')
      bound = to_number(kappa) > 0 ? js_div(js_max(0, b_max), kappa) : 0
      num(bound * to_number(kappa))
    end

    # Encode params (options, snake_case) as a PCA Root Intent Grant envelope plus the initial trust budget.
    # principal_secret is the 32-byte Ed25519 seed that signs the grant.
    def build_payment_mandate(params)
      validate(params)
      g = ->(k) { prop(params, k) }
      now = finite?(g.call('now')) ? g.call('now') : now_ms
      period_start = finite?(g.call('period_start')) ? g.call('period_start') : now
      cats = g.call('categories')
      terms = { 'merchants' => g.call('merchants').dup, 'categories' => truthy?(cats) ? spread_list(cats) : [], 'currency' => g.call('currency'),
                'perTransactionCap' => g.call('per_transaction_cap'), 'autoApproveThreshold' => g.call('auto_approve_threshold'),
                'cumulativeCap' => g.call('cumulative_cap'), 'periodStart' => period_start }
      terms['periodEnd'] = num(period_start + g.call('period_ms')) unless undef?(g.call('period_ms'))
      terms['maxTransactionsPerPeriod'] = g.call('max_transactions_per_period') unless undef?(g.call('max_transactions_per_period'))
      rep = g.call('replenish_per_cosign')
      policy = mandate_risk_policy(terms, nullish?(rep) ? terms['cumulativeCap'] : rep)
      goal = g.call('goal')
      if nullish?(goal)
        goal = format('spend ≤ %s %s autonomously / ≤ %s with co-sign, ≤ %s cumulative, at [%s]', tostr(terms['autoApproveThreshold']),
                      terms['currency'], tostr(terms['perTransactionCap']), tostr(terms['cumulativeCap']), terms['merchants'].join(', '))
      end
      principal = KeyPair.new(g.call('principal_secret'))
      raise ArgumentError, 'buildPaymentMandate: principalPublic is not the public key of principalSecret' if g.call('principal_public') != principal.public

      salt = g.call('goal_salt')
      holder = g.call('agent_public')
      raise TypeError, 'canonicalize: unsupported type undefined' if undef?(holder)

      minted = AtlasPca.mint_grant(principal, holder,
                                   { 'predicates' => mandate_predicates(terms), 'caveats' => mandate_caveats(terms), 'agent_binding' => {},
                                     'risk_policy' => policy }, goal, salt: undef?(salt) ? nil : salt)
      { 'grant' => minted['grant'], 'policy' => policy, 'budget' => { 'B' => terms['cumulativeCap'], 'tau' => now, 'asOf' => now },
        'terms' => terms, 'goalCommit' => minted['goal_commit'], 'goalSalt' => minted['goal_salt'] }
    end

    # ---- charge decision ------------------------------------------------------------------------------------------------

    def charge_params(mandate, charge)
      cur = prop(charge, 'currency')
      p = { 'amount' => prop(charge, 'amount'), 'currency' => undef?(cur) ? prop(prop(mandate, 'terms'), 'currency') : cur }
      cat = prop(charge, 'category')
      p['category'] = cat unless undef?(cat)
      drop(p)
    end

    # The action a charge denotes: the verb / resource / params the predicates and risk read.
    def charge_action_context(mandate, charge)
      { 'action' => { 'verb' => CHARGE_VERB, 'resource' => "merchant:#{tostr(prop(charge, 'merchant'))}",
                      'params' => charge_params(mandate, charge), 'reversibility_class' => CHARGE_REVERSIBILITY_CLASS } }
    end

    def container?(v) = v.is_a?(Hash) || v.is_a?(Array)

    def bind_to_verified_grant(mandate, verified_grant)
      unless container?(verified_grant)
        raise MandateGrantError.new('verified_grant_required',
                                    "a verified (or stored) grant is required; the mandate's own grant is never the authority")
      end
      if !container?(mandate) || hash_of(prop(mandate, 'grant')) != hash_of(verified_grant)
        raise MandateGrantError.new('mandate_grant_mismatch', 'the mandate grant is not the verified grant')
      end

      env = AtlasPca.read_envelope(verified_grant)
      same = ->(a, b) { hash_of(a) == hash_of(b) }
      terms = prop(mandate, 'terms')
      policy = prop(mandate, 'policy')
      if env.nil? || !truthy?(terms) || !truthy?(policy) || !same.call(env['predicates'], mandate_predicates(terms)) ||
         !same.call(env['caveats'], mandate_caveats(terms)) || !same.call(env['risk_policy'], policy)
        raise MandateGrantError.new('mandate_terms_mismatch', 'the mandate terms / policy are not the ones signed into the verified grant')
      end

      b_max = env['risk_policy']['bMax']
      budget = optprop(mandate, 'budget')
      b = undef?(budget) ? UNDEF : optprop(budget, 'B')
      bb = finite?(b) ? [0, [b, b_max].min].max : 0
      out = spread_obj(mandate)
      out['grant'] = verified_grant
      nb = spread_obj(budget)
      nb['B'] = bb
      out['budget'] = nb
      out
    end

    # The decide input for a charge: risk collapses to the normalised amount (spend = risk). A mandate whose grant, terms or
    # policy differ from verified_grant is refused (MandateGrantError).
    def charge_decide_input(mandate0, charge, now, verified_grant)
      mandate = bind_to_verified_grant(mandate0, verified_grant)
      x = prop(prop(mandate, 'terms'), 'perTransactionCap')
      amount = prop(charge, 'amount')
      amount = finite?(amount) ? amount : Float::INFINITY
      blast = to_number(x) > 0 ? js_div(amount, x) : 1
      ctx = { 'reversibilityClass' => CHARGE_REVERSIBILITY_CLASS }
      recent = prop(charge, 'recentChargeTimes')
      ctx['recentActionTimes'] = recent unless undef?(recent)
      { 'grant' => verified_grant, 'action' => charge_action_context(mandate, charge),
        'risk' => { 'semanticDistance' => 0, 'reversibility' => 1, 'blastRadius' => blast, 'taint' => 0, 'confidence' => 1, 'age' => 0 },
        'budget' => mandate['budget'], 'now' => now, 'caveatContext' => ctx }
    end

    # Run a charge through the PCA decision against the grant you VERIFIED (or loaded from your own store). Pure: reads the
    # mandate budget (clamped to the signed bMax) and returns the next one in 'budgetAfter'. decide is the PCA policy engine.
    def authorize_charge(mandate0, charge, verified_grant, decide)
      mandate = bind_to_verified_grant(mandate0, verified_grant)
      now = prop(charge, 'now')
      now = finite?(now) ? now : now_ms
      raw = decide.call(charge_decide_input(mandate, charge, now, verified_grant))
      amount = prop(charge, 'amount')
      merchant = prop(charge, 'merchant')
      refusal = if !minor_units?(amount) then AMOUNT_NOT_MINOR_UNITS elsif !plain_id?(merchant) then MERCHANT_INVALID end
      decision = refusal.nil? ? raw : refused_decision(raw, refusal, mandate['budget'])
      outcome = if !Js.truthy?(decision['releaseGuardianShare']) then 'deny' elsif Js.truthy?(decision['admit']) then 'auto' else 'step_up' end
      policy = mandate['policy']
      terms = mandate['terms']
      budget = mandate['budget']
      exact = outcome == 'auto' && minor_units?(amount) && seq?(policy['kappa'], terms['perTransactionCap']) &&
              safe_int?(budget.key?('B') ? budget['B'] : UNDEF)
      cost = if outcome != 'auto' then 0 elsif exact then amount else Risk.cost(decision['r'], policy['kappa']) end
      { 'outcome' => outcome, 't' => decision['requiredThreshold']['t'], 'r' => decision['r'],
        'requiredThreshold' => decision['requiredThreshold'], 'cost' => cost, 'budgetBefore' => budget,
        'budgetAfter' => exact ? decision['budget'].merge('B' => budget['B'] - amount) : decision['budget'],
        'reasons' => decision['reasons'], 'decision' => decision }
    end

    def refused_decision(raw, refusal, budget)
      reasons = raw['reasons']
      raise TypeError, 'reasons is not iterable' unless reasons.is_a?(Array)

      raw.merge('admit' => false, 'releaseGuardianShare' => false, 'reasons' => [refusal] + reasons, 'budget' => budget)
    end

    # Advance the mandate's budget after a decision (functional).
    def settle_charge(mandate, decision) = spread_obj(mandate).merge('budget' => prop(decision, 'budgetAfter'))

    def nz(x) = finite?(x) && x > 0 ? x : 0

    def recharge(b, rho, b_max, now)
      bb = prop(b, 'B')
      total = bb.is_a?(String) ? bb + Js.string(nz(rho)) : to_number(bb) + nz(rho)
      { 'B' => num(js_min(nz(b_max), total)), 'tau' => now, 'asOf' => now }
    end

    # Apply a human co-sign: restore autonomous budget by rho, or fully re-confirm to bMax with { 'full' => true }. The only
    # way the budget goes up.
    def apply_human_cosign(mandate, now, opts = UNDEF)
      opts = {} if undef?(opts)
      full = truthy?(prop(opts, 'full'))
      policy = prop(mandate, 'policy')
      budget = if full
                 { 'B' => nz(prop(policy, 'bMax')), 'tau' => now, 'asOf' => now }
               else
                 recharge(prop(mandate, 'budget'), prop(policy, 'rho'), prop(policy, 'bMax'), now)
               end
      spread_obj(mandate).merge('budget' => budget)
    end

    def valid_record?(r)
      return false unless r.is_a?(Hash)

      v = r['version']
      b = r['budget']
      safe_int?(v) && !neg_zero?(v) && b.is_a?(Hash) && finite?(b['B']) && finite?(b['tau']) && finite?(b['asOf'])
    end

    def check_store!(store)
      return if store && store.respond_to?(:get) && store.respond_to?(:compare_and_set)

      raise ChargeStoreError, 'a ChargeBudgetStore with get and compare_and_set is required'
    end

    # authorize_charge against the DURABLE cumulative budget in store (get(key) -> { 'budget', 'version' } | nil;
    # compare_and_set(key, expected_version | nil, budget) -> bool). An auto debit is committed with a compare-and-set before it
    # is returned; losing the race re-reads and re-decides; persistent contention returns a deny.
    def authorize_charge_atomic(mandate, charge, verified_grant, store, decide, key = nil)
      check_store!(store)
      key = AtlasPca.hash_canonical(verified_grant) if key.nil?
      MAX_CAS_ATTEMPTS.times do
        rec = store.get(key)
        raise ChargeStoreError, 'the store returned a malformed budget record' if !rec.nil? && !valid_record?(rec)

        m = rec ? spread_obj(mandate).merge('budget' => rec['budget']) : mandate
        d = authorize_charge(m, charge, verified_grant, decide)
        return d if d['outcome'] != 'auto'
        return d if store.compare_and_set(key, rec ? rec['version'] : nil, d['budgetAfter'])
      end
      d = authorize_charge(mandate, charge, verified_grant, decide)
      d.merge('outcome' => 'deny', 't' => 3, 'cost' => 0, 'budgetAfter' => d['budgetBefore'], 'reasons' => ['budget_store_conflict'] + d['reasons'])
    end

    # apply_human_cosign against the DURABLE budget, committed with a compare-and-set so a co-sign racing a charge is never
    # lost or applied twice. Call it only after verifying the human co-sign; persistent contention raises. opts: key, full.
    def apply_human_cosign_atomic(mandate, verified_grant, store, now, opts = nil)
      check_store!(store)
      opts ||= {}
      key = opts['key'].nil? ? AtlasPca.hash_canonical(verified_grant) : opts['key']
      MAX_CAS_ATTEMPTS.times do
        rec = store.get(key)
        raise ChargeStoreError, 'the store returned a malformed budget record' if !rec.nil? && !valid_record?(rec)

        bound = bind_to_verified_grant(rec ? spread_obj(mandate).merge('budget' => rec['budget']) : mandate, verified_grant)
        nxt = apply_human_cosign(bound, now, { 'full' => opts['full'] == true })['budget']
        return nxt if store.compare_and_set(key, rec ? rec['version'] : nil, nxt)
      end
      raise ChargeStoreError, 'could not commit the co-sign: the budget record kept changing'
    end

    # ---- charge as a proof-carrying action --------------------------------------------------------------------------------

    # The committed plan node for a charge; params_digest is pinned to the charge params so the leaf reconciles with the PCActn.
    def charge_plan_node(mandate, charge, id)
      { 'id' => id, 'verb' => CHARGE_VERB, 'resource' => "merchant:#{tostr(prop(charge, 'merchant'))}",
        'reversibility_class' => CHARGE_REVERSIBILITY_CLASS, 'params_digest' => hash_of(charge_params(mandate, charge)) }
    end

    # A signed PCActn for a charge: { 'pcactn', 'node' }. opts: signer_secret (32-byte seed), aud, counter, chain?, node_id?, now?.
    def charge_to_pcactn(mandate, charge, opts)
      raise ArgumentError, 'chargeToPCActn: amount must be a non-negative integer in minor units' unless minor_units?(prop(charge, 'amount'))

      node_id = opt(opts, 'node_id')
      counter = opts.key?('counter') ? opts['counter'] : UNDEF
      node_id = "charge:#{tostr(prop(charge, 'merchant'))}:#{tostr(counter)}" if node_id.nil?
      node = charge_plan_node(mandate, charge, node_id)
      x = prop(prop(mandate, 'terms'), 'perTransactionCap')
      amount = prop(charge, 'amount')
      amount = finite?(amount) ? amount : x
      r = x > 0 ? js_div(amount, x) : 1
      r = r < 0 ? 0 : (r > 1 ? 1 : r)
      params = charge_params(mandate, charge)
      chain = opts['chain']
      chain = [mandate['grant']] if chain.nil?
      pcactn = AtlasPca.build_pcactn(grant: chain[0], chain: chain, plan: [node], node_id: node_id, counter: opts['counter'],
                                     signer: KeyPair.new(opts['signer_secret']), aud: opts['aud'], params: params, iat: opts['now'],
                                     extra: { 'risk_claim' => { 'r' => num(r), 'inputs' => params.merge('blastRadius' => num(r)) } })
      { 'pcactn' => pcactn, 'node' => node }
    end
  end
end

require_relative 'payments_rails'
require_relative 'payments_token'
