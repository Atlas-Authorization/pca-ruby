# frozen_string_literal: true

require 'base64'
require_relative 'ap2_chain'

# AP2, part 4: the PCA terms bridge (PCA payment mandate -> AP2 open mandates), the PCActn bound to the closed AP2 payment, the
# verification of the PCA side of a verified AP2 chain, and the settlement payloads (x402, Stripe shared payment tokens). See ap2.rb.
module AtlasPca
  module Ap2
    # Raised when verify_pca_binding lacks the server-held state the policy decision needs (code: mandate_required |
    # charge_history_required).
    class PcaBindingError < StandardError
      attr_reader :code

      def initialize(code, message)
        super(message)
        @code = code
      end
    end

    module_function

    # ---- PCA terms -> AP2 open mandates ---------------------------------------------------------------------------------

    # A PCA term as integer minor units; anything else (a major-unit float from an older mandate) is refused.
    def minor_term(v, name)
      raise Ap2Error, "PCA term #{name} must be a non-negative integer in minor units, got #{str(v)}" if !safe_int?(v) || v.negative? || neg0?(v)

      v
    end

    # The `x_pca` claim of an open mandate: the principal-signed grant and the terms it was minted from.
    def pca_open_claim(mandate)
      { 'v' => PCA_BINDING_VERSION, 'grant' => to_json_value(g(mandate, 'grant')), 'terms' => to_json_value(g(mandate, 'terms')) }
    end

    def open_expiry(terms, o)
      pe = g(terms, 'periodEnd')
      raise TypeError, 'periodEnd is not a number' unless undef?(pe) || num?(pe)

      period_end = undef?(pe) ? nil : (pe / 1000.0).floor
      exp = o['exp']
      exp = period_end if exp.nil?
      raise Ap2Error, 'exp is required when the PCA terms have no period end' if exp.nil?
      raise Ap2Error, 'exp must not exceed the PCA period end' if !period_end.nil? && !(exp <= period_end)

      exp
    end

    def merchants_for(terms, merchants)
      iter_list(g(terms, 'merchants')).map do |mid|
        m = iter_list(merchants).find { |x| seq?(g(x, 'id'), mid) }
        raise Ap2Error, "no merchant descriptor supplied for PCA merchant #{str(mid)}" if m.nil?

        m
      end
    end

    # Next representable double above a positive finite `x`.
    def next_up(x) = [[x].pack('E').unpack1('Q<') + 1].pack('Q<').unpack1('E')

    # The value of AP2 `payment.budget.max` for a PCA cap in integer minor units. The official AP2 SDK reads it as `int(max * 100)`
    # whatever the currency, a major-unit reader as `max * 10^exponent`: the value emitted never lets EITHER read more than the cap
    # (nudged up by at most a few ulps when `cap / divisor` falls just under the exact decimal). Raises when no exact representation
    # exists.
    def ap2_budget_max(cap_minor, currency)
      cap = minor_term(cap_minor, 'cumulativeCap')
      e = currency_exponent(currency)
      sdk_target = e <= 2 ? cap : (cap.to_f / (10**(e - 2))).floor
      d = cap.to_f / (10**[e, 2].max)
      8.times do
        break unless d.positive? && (d * 100).truncate < sdk_target

        d = next_up(d)
      end
      if (d * 100).truncate != sdk_target || js_round(d * (10**e)) > cap
        raise Ap2Error, "cumulativeCap #{str(cap)} #{str(currency)} has no exact AP2 budget.max representation"
      end

      d
    end

    # What the two readers of an AP2 `budget.max` read, in minor units of `currency`: the SDK (`int(max * 100)`) and a major-unit reader.
    def ap2_budget_reads(max, currency)
      e = currency_exponent(currency)
      raise Ap2Error, "budget.max must be a finite non-negative number, got #{str(max)}" if !num?(max) || !finite?(max) || max.negative?

      { 'sdk' => (max.to_f * 100).truncate.to_f, 'major' => js_round(max.to_f * (10**e)).to_f }
    end

    # The AP2 open payment constraints a set of PCA terms denotes (PCA terms are integer minor units of the mandate currency;
    # `budget.max` is derived by ap2_budget_max).
    def payment_constraints_from_terms(terms, merchants, checkout_reference)
      cur = g(terms, 'currency')
      per_tx = minor_term(g(terms, 'perTransactionCap'), 'perTransactionCap')
      budget_max = ap2_budget_max(g(terms, 'cumulativeCap'), cur)
      recurrence = compact({ 'type' => 'payment.agent_recurrence', 'frequency' => 'ON_DEMAND' })
      mt = g(terms, 'maxTransactionsPerPeriod')
      recurrence['max_occurrences'] = mt unless undef?(mt)
      [
        compact({ 'type' => 'payment.amount_range', 'currency' => cur, 'min' => 0, 'max' => per_tx }),
        { 'type' => 'payment.allowed_payees', 'allowed' => merchants_for(terms, merchants) },
        { 'type' => 'payment.reference', 'conditional_transaction_id' => checkout_reference },
        compact({ 'type' => 'payment.budget', 'currency' => cur, 'max' => budget_max }),
        recurrence
      ]
    end

    def from_pca_input(mandate, o, constraints)
      out = { 'issuer' => o['issuer'], 'agent_jwk' => o['agent_jwk'], 'iat' => o['iat'] }
      out['exp'] = open_expiry(g(mandate, 'terms'), o)
      out['pca'] = pca_open_claim(mandate)
      out['constraints'] = constraints.call
      out['salt'] = o['salt'] if truthy?(o.key?('salt') ? o['salt'] : UNDEF)
      out
    end

    # Issue the open payment mandate for a PCA mandate (grant + terms), chained to o['checkout_reference']. o: issuer, agent_jwk,
    # merchants, iat, exp?, salt?, checkout_reference.
    def open_payment_mandate_from_pca(mandate, o)
      issue_open_payment_mandate(from_pca_input(mandate, o, -> { payment_constraints_from_terms(g(mandate, 'terms'), o['merchants'], o['checkout_reference']) }))
    end

    # Issue the open checkout mandate for a PCA mandate: the merchant allowlist and the acceptable line items (o['line_items']).
    def open_checkout_mandate_from_pca(mandate, o)
      issue_open_checkout_mandate(from_pca_input(mandate, o, lambda {
        [{ 'type' => 'checkout.line_items', 'items' => o['line_items'] },
         { 'type' => 'checkout.allowed_merchants', 'allowed' => merchants_for(g(mandate, 'terms'), o['merchants']) }]
      }))
    end

    # ---- the closed payment: PCActn bound to the AP2 mandate ------------------------------------------------------------

    # The value the PCActn's signed `nonce` must equal for these AP2 facts (transactionId, payeeId, amount, currency, instrumentId,
    # openHash, agentJkt).
    def pca_binding_nonce(f) = "ap2:#{AtlasPca.hash_canonical({ 'v' => PCA_BINDING_VERSION }.merge(spread(f)))}"

    # amount / cap, clamped to [0, 1] and rounded UP to 12 decimals (PCA's canonical encoding refuses numbers with more than 15
    # significant digits; rounding up can only raise the risk the threshold policy sees).
    def risk_ratio(amount, cap)
      r = cap > 0 ? amount.to_f / cap : 1
      [1, [0, ((r * 1e12) - 1e-6).ceil / 1e12].max].min
    end

    # Build the `x_pca` claim of a closed payment mandate: a PCActn authorising exactly this charge. i: mandate (the PCA mandate:
    # grant + terms), open (the open payment mandate token), agent_jwk, agent_secret (the grant holder's 32-byte Ed25519 seed),
    # audience, counter, transaction_id, payee, amount ({ 'amount', 'currency' }), instrument_id, category?, now? (epoch ms), cosign?
    # (callable over the built PCActn returning the threshold shares).
    def build_pca_payment_binding(i)
      amount = i['amount']
      major = minor_term(amount['amount'], 'amount') # the charge amount is integer minor units, as in the mandate
      payee = i['payee']
      charge = { 'merchant' => payee['id'], 'amount' => major, 'currency' => amount['currency'] }
      charge['category'] = i['category'] if i.key?('category')
      mandate = i['mandate']
      facts = { 'transactionId' => i['transaction_id'], 'payeeId' => payee['id'], 'amount' => amount['amount'], 'currency' => amount['currency'],
                'instrumentId' => i['instrument_id'], 'openHash' => sd_hash_of(parse_sd_jwt_hop(i['open'])), 'agentJkt' => jwk_thumbprint(i['agent_jwk']) }
      risk = risk_ratio(major, mandate['terms']['perTransactionCap'])
      node_id = "ap2:#{str(i['transaction_id'])}"
      params = Payments.charge_params(mandate, charge)
      node = Payments.charge_plan_node(mandate, charge, node_id)
      built = AtlasPca.build_pcactn(grant: mandate['grant'], chain: [mandate['grant']], plan: [node], node_id: node_id, counter: i['counter'],
                                    signer: KeyPair.new(i['agent_secret']), aud: i['audience'], params: params, iat: i['now'],
                                    extra: { 'nonce' => pca_binding_nonce(facts), 'risk_claim' => { 'r' => risk, 'inputs' => params.merge('blastRadius' => risk) } })
      pcactn = i['cosign'] ? built.merge('threshold' => i['cosign'].call(built)) : built
      claim_charge = { 'amount' => major, 'currency' => amount['currency'] }
      claim_charge['category'] = i['category'] if i.key?('category')
      { 'v' => PCA_BINDING_VERSION, 'charge' => claim_charge, 'pcactn' => to_json_value(pcactn) }
    end

    # ---- verification of the PCA side of a verified AP2 chain -----------------------------------------------------------

    def includes?(lst, v)
      return lst.any? { |x| seq?(x, v) } if lst.is_a?(Array)

      lst.is_a?(String) && v.is_a?(String) && lst.include?(v)
    end

    def find_type(constraints, t)
      iter_list(constraints).each { |c| return c if g(c, 'type') == t }
      UNDEF
    end

    # Check the open mandate's constraints never exceed the PCA terms (the AP2 side only narrows the grant).
    def constraints_within_terms(open_, terms)
      cur = g(terms, 'currency')
      per_tx = minor_term(g(terms, 'perTransactionCap'), 'perTransactionCap')
      constraints = g(open_, 'constraints')
      rng = find_type(constraints, 'payment.amount_range')
      return 'open mandate has no amount_range to compare with the PCA per-transaction cap' if undef?(rng)
      return 'amount_range currency differs from the PCA terms' unless seq?(g(rng, 'currency'), cur)
      return "amount_range.max #{str(g(rng, 'max'))} exceeds the PCA per-transaction cap #{str(per_tx)}" unless le?(g(rng, 'max'), per_tx)

      payees = find_type(constraints, 'payment.allowed_payees')
      if !undef?(payees) && iter_list(g(payees, 'allowed')).any? { |m| !includes?(g(terms, 'merchants'), g(m, 'id')) }
        return 'allowed_payees names a merchant outside the PCA allowlist'
      end
      return 'open mandate has no allowed_payees; the PCA allowlist would not be enforced on the AP2 side' if undef?(payees)

      budget = find_type(constraints, 'payment.budget')
      return 'open mandate has no budget to compare with the PCA cumulative cap' if undef?(budget)
      return 'budget exceeds the PCA cumulative cap' unless seq?(g(budget, 'currency'), cur)

      reads = ap2_budget_reads(g(budget, 'max'), cur)
      cap_minor = minor_term(g(terms, 'cumulativeCap'), 'cumulativeCap')
      return 'budget exceeds the PCA cumulative cap' unless reads['sdk'] <= cap_minor && reads['major'] <= cap_minor

      rec = find_type(constraints, 'payment.agent_recurrence')
      max_tx = g(terms, 'maxTransactionsPerPeriod')
      if !undef?(max_tx) && (undef?(rec) || undef?(g(rec, 'max_occurrences')) || !le?(g(rec, 'max_occurrences'), max_tx))
        return 'max_occurrences is missing or exceeds the PCA transaction limit'
      end

      period_end = g(terms, 'periodEnd')
      if !undef?(period_end) && (undef?(g(open_, 'exp')) || !le?(g(open_, 'exp'), (pe_s = to_number(period_end) / 1000).finite? ? pe_s.floor : pe_s))
        return 'open mandate outlives the PCA period'
      end

      nil
    end

    # A core verdict reason as the reference words it (`chain` is `cap_chain`, `freshness_anchor` is `freshness`).
    def ts_reason(reason)
      return reason unless reason.is_a?(String)

      head, sep, rest = reason.partition(': ')
      reason = "#{{ 'chain' => 'cap_chain', 'freshness_anchor' => 'freshness' }.fetch(head, head)}#{sep}#{rest}" unless sep.empty?
      reason += ' / suite' if reason == 'leaf_signature: signature does not verify under the leaf holder key'
      reason
    end

    # Verify the PCA side of a verified AP2 payment chain: the grant in the open mandate (signed by the expected principal, consistent
    # with the terms it claims and with the open constraints), and the closed mandate's PCActn (valid under that grant, for this
    # audience, committing to exactly this AP2 charge). Run it after verify_payment_chain. `decide` is the PCA policy engine (the
    # decision runs on the server-held mandate, never skipped). i: open, closed, open_hash, expected_principal, audience, mandate
    # (REQUIRED), recent_charge_times (REQUIRED when the mandate limits the charge count), pq_pins?, now?, hooks? ({ 'attestation'?,
    # 'threshold'?, 'revocation'? => callable ctx -> { 'enforced', 'ok', 'reason'?, 't'? } }). The core freshness / taint gates are not
    # available natively: any `enforce` member is refused (fail closed). Returns { 'ok' => true, pcactn, grant, terms } or
    # { 'ok' => false, 'reason' }; raises PcaBindingError when the mandate or history is missing.
    def verify_pca_binding(i, decide)
      raise Ap2Error, 'verify_pca_binding needs the PCA policy engine as `decide`' unless decide.respond_to?(:call)

      mandate = i.is_a?(Hash) && i.key?('mandate') ? i['mandate'] : UNDEF
      unless mandate.is_a?(Hash)
        raise PcaBindingError.new('mandate_required', 'verifyPcaBinding needs the server-held PCA mandate (its live budget); the policy decision is never skipped')
      end

      terms_of_mandate = mandate['terms']
      max_tx_m = terms_of_mandate.is_a?(Hash) && terms_of_mandate.key?('maxTransactionsPerPeriod') ? terms_of_mandate['maxTransactionsPerPeriod'] : UNDEF
      recent = i['recent_charge_times']
      if !undef?(max_tx_m) && !(recent.is_a?(Array) && recent.all? { |t| finite?(t) })
        raise PcaBindingError.new('charge_history_required', 'the mandate limits the charge count: pass recentChargeTimes from your own records')
      end

      refuse = ->(reason) { { 'ok' => false, 'reason' => reason } }
      begin
        oc = g(g(i, 'open'), 'x_pca')
        if !oc.is_a?(Hash) || !seq?(oc.key?('v') ? oc['v'] : UNDEF, PCA_BINDING_VERSION) || !oc['grant'].is_a?(Hash) || !oc['terms'].is_a?(Hash)
          return refuse.call('open mandate carries no x_pca grant')
        end

        grant = oc['grant']
        terms = oc['terms']
        why, chain_ok = AtlasPca.verify_chain([grant], i['expected_principal'], !i['expected_principal'].nil?, nil, i['pq_pins'])
        return refuse.call("PCA grant: #{why.nil? ? 'invalid' : why}") unless chain_ok

        env = AtlasPca.read_envelope(grant)
        return refuse.call('PCA grant has no envelope') if env.nil?

        if AtlasPca.hash_canonical(env['predicates']) != AtlasPca.hash_canonical(Payments.mandate_predicates(terms)) ||
           AtlasPca.hash_canonical(env['caveats']) != AtlasPca.hash_canonical(Payments.mandate_caveats(terms))
          return refuse.call('x_pca terms do not match the grant envelope')
        end

        rp = env['risk_policy']
        if !seq?(g(rp, 'kappa'), g(terms, 'perTransactionCap')) || !seq?(g(rp, 'bMax'), g(terms, 'cumulativeCap'))
          return refuse.call('x_pca terms do not match the grant risk policy')
        end

        within = constraints_within_terms(i['open'], terms)
        return refuse.call(within) if within

        closed = i['closed']
        cc = g(closed, 'x_pca')
        if !cc.is_a?(Hash) || !seq?(cc.key?('v') ? cc['v'] : UNDEF, PCA_BINDING_VERSION) || !cc['pcactn'].is_a?(Hash) || !cc['charge'].is_a?(Hash)
          return refuse.call('closed mandate carries no x_pca PCActn')
        end

        pcactn = cc['pcactn']
        charge = cc['charge']
        amt = g(closed, 'payment_amount')
        payee = g(closed, 'payee')
        if !seq?(g(charge, 'currency'), g(amt, 'currency')) || !seq?(g(charge, 'amount'), g(amt, 'amount'))
          return refuse.call('x_pca charge differs from the mandate payment_amount')
        end

        cats = g(terms, 'categories')
        raise TypeError, "Cannot read properties of #{cats.nil? ? 'null' : 'undefined'} (reading 'length')" if undef?(cats) || cats.nil?

        category = g(charge, 'category')
        if (cats.is_a?(Array) || cats.is_a?(String) ? cats.length : 0) > 0 && (!category.is_a?(String) || !includes?(cats, category))
          return refuse.call('x_pca charge lacks an allowed category')
        end

        # the t the threshold hook REPORTS it enforced: a hook built for a smaller t cannot satisfy a charge that needs more
        hooks = i['hooks'].is_a?(Hash) ? i['hooks'] : {}
        enforce = i['enforce'].is_a?(Hash) ? i['enforce'] : {}
        return refuse.call('PCActn: an enforce gate (freshness / taint) is not supported by this verifier (fail closed)') unless enforce.empty?

        enforced_t = UNDEF
        now = i['now']
        verdict = AtlasPca.verify_pcactn(pcactn, grant, now: now.nil? ? (Time.now.to_f * 1000).to_i : now, audience: i['audience'],
                                                        insecure_skip_plan_root_check: true, pq_pins: i['pq_pins'])
        return refuse.call("PCActn: #{verdict.reason.nil? ? 'rejected' : ts_reason(verdict.reason)}") unless verdict.allow

        hook_ctx = { 'pcactn' => pcactn, 'grant' => grant }
        hook_ctx['nowEpoch'] = now unless now.nil?
        %w[attestation threshold revocation].each do |name|
          hook = hooks[name]
          next if hook.nil?

          res = hook.call(hook_ctx)
          enforced_t = res['t'] if name == 'threshold' && truthy?(g(res, 'enforced')) && truthy?(g(res, 'ok')) && num?(g(res, 't'))
          if truthy?(g(res, 'enforced')) && !truthy?(g(res, 'ok'))
            why = g(res, 'reason')
            return refuse.call("PCActn: #{name}: #{undef?(why) || why.nil? ? 'rejected' : str(why)}")
          end
        end

        action = g(pcactn, 'action')
        if !seq?(g(action, 'verb'), 'charge') || !seq?(g(action, 'resource'), "merchant:#{str(g(payee, 'id'))}")
          return refuse.call('PCActn action is not a charge at this payee')
        end

        params = { 'amount' => g(charge, 'amount'), 'currency' => g(charge, 'currency') }
        params['category'] = category if category.is_a?(String)
        raise Ap2Error, 'canonical JSON cannot encode an undefined charge member' if undef?(params['amount']) || undef?(params['currency'])
        return refuse.call('PCActn params do not commit to the x_pca charge') unless seq?(g(action, 'params_digest'), AtlasPca.params_digest(params))

        agent_jwk = g(g(g(i, 'open'), 'cnf'), 'jwk')
        facts = { 'transactionId' => g(closed, 'transaction_id'), 'payeeId' => g(payee, 'id'), 'amount' => g(amt, 'amount'), 'currency' => g(amt, 'currency'),
                  'instrumentId' => g(g(closed, 'payment_instrument'), 'id'), 'openHash' => i.key?('open_hash') ? i['open_hash'] : UNDEF,
                  'agentJkt' => jwk_thumbprint(agent_jwk) }
        raise Ap2Error, 'canonical JSON cannot encode an undefined binding fact' if facts.values.any? { |v| undef?(v) }
        return refuse.call('PCActn nonce does not bind this AP2 transaction, open mandate and agent key') unless seq?(g(pcactn, 'nonce'), pca_binding_nonce(facts))

        per_tx = minor_term(g(terms, 'perTransactionCap'), 'perTransactionCap')
        return refuse.call('payment exceeds the PCA per-transaction cap') unless fin_num?(g(amt, 'amount')) && le?(g(amt, 'amount'), per_tx)

        # the agent may not understate the risk of its own charge; a charge whose risk needs a human co-sign (t > 1) needs a threshold verifier
        recomputed = risk_ratio(g(amt, 'amount'), g(terms, 'perTransactionCap'))
        claimed = g(g(pcactn, 'risk_claim'), 'r')
        return refuse.call('PCActn understates the risk of this charge') unless num?(claimed) && claimed >= recomputed - 1e-9

        need = Risk.required_threshold(claimed, rp)
        if need['t'] > 1 && !truthy?(hooks['threshold'])
          return refuse.call("this charge needs a threshold of #{need['t']} (human co-sign); supply hooks.threshold to verify it")
        end
        if need['t'] > 1 && !(num?(enforced_t) && enforced_t >= need['t'])
          return refuse.call("this charge needs a threshold of #{need['t']} but the threshold hook enforced t=#{undef?(enforced_t) ? 'unreported' : str(enforced_t)}; " \
                           "build it with createThresholdVerifier({ t: #{need['t']} })")
        end
        if !seq?(g(amt, 'currency'), g(terms, 'currency')) || !includes?(g(terms, 'merchants'), g(payee, 'id'))
          return refuse.call('payment currency or payee is outside the PCA terms')
        end

        return refuse.call('the supplied PCA mandate is not the one in the open mandate') if AtlasPca.hash_canonical(mandate.key?('grant') ? mandate['grant'] : nil) != AtlasPca.hash_canonical(grant)

        # `grant` was verified above under the caller-pinned principal; the decision is bound to it
        spend = { 'merchant' => g(payee, 'id'), 'amount' => g(amt, 'amount'), 'currency' => g(amt, 'currency') }
        spend['category'] = category if category.is_a?(String)
        spend['recentChargeTimes'] = recent.nil? ? [] : recent
        spend['now'] = now unless now.nil?
        decision = Payments.authorize_charge(mandate, spend, grant, decide)
        return refuse.call("PCA denies this charge: #{decision['reasons'].map { |r| str(r) }.join('; ')}") if decision['outcome'] == 'deny'
        if decision['outcome'] == 'step_up' && !(num?(enforced_t) && enforced_t >= 2)
          return refuse.call('PCA requires a human co-sign for this charge and no verified threshold (t >= 2) was enforced')
        end

        { 'ok' => true, 'pcactn' => pcactn, 'grant' => grant, 'terms' => terms }
      rescue StandardError => e # totality: any fault is a refusal carrying the message
        refuse.call(e.message)
      end
    end

    # ---- settlement backends (structural only, no network) --------------------------------------------------------------

    # Integer minor units to an integer string of atomic units: scales by `10 ** (decimals - exponent)` exactly; when the asset has
    # fewer decimals than the currency the division must be exact. Raises otherwise (fail closed).
    def to_atomic_units(amount, decimals)
      if !num?(decimals) || !finite?(decimals) || decimals != decimals.to_f.truncate || decimals.negative? || decimals > 18
        raise Ap2RangeError, "x402: decimals must be an integer in 0..18, got #{str(decimals)}"
      end

      amt = g(amount, 'amount')
      if !safe_int?(amt) || amt.negative? || neg0?(amt)
        raise Ap2RangeError, "x402: amount #{str(amt)} cannot be expressed in atomic units with #{str(decimals)} decimals"
      end

      decimals = decimals.to_i
      exp = currency_exponent(g(amount, 'currency'))
      minor = amt.to_i
      return (minor * (10**(decimals - exp))).to_s if decimals >= exp

      div = 10**(exp - decimals)
      unless (minor % div).zero?
        raise Ap2RangeError, "x402: amount #{str(amt)} cannot be expressed in atomic units with #{str(decimals)} decimals"
      end

      (minor / div).to_s
    end

    def ctx_get(ctx, k) = ctx.is_a?(Hash) ? ctx[k] : nil

    # Coinbase x402 adapter: the HTTP 402 `Payment Required` challenge (`accepts`) plus the `X-PAYMENT` request header (standard
    # base64 of the JSON payment payload). The payload is a placeholder envelope, not a signed authorization: the real rail settles
    # on-chain. ctx: network, decimals, resource_url, pay_to, asset, max_timeout_seconds.
    module X402Settlement
      module_function

      def rail = 'x402'

      def settle(payment, ctx = nil)
        network = Ap2.ctx_get(ctx, 'network')
        network = 'base-sepolia' if network.nil?
        dec = Ap2.ctx_get(ctx, 'decimals')
        amt = payment['payment_amount']
        requirement = {
          'scheme' => 'exact', 'network' => network,
          'maxAmountRequired' => Ap2.to_atomic_units(amt, dec.nil? ? 6 : dec), # x402 v1: a string in ATOMIC token units
          'resource' => Ap2.ctx_get(ctx, 'resource_url').nil? ? '' : Ap2.ctx_get(ctx, 'resource_url'),
          'description' => "AP2 payment mandate #{Ap2.str(payment['transaction_id'])}",
          'payTo' => Ap2.ctx_get(ctx, 'pay_to').nil? ? payment['payee']['id'] : Ap2.ctx_get(ctx, 'pay_to'),
          'asset' => Ap2.ctx_get(ctx, 'asset').nil? ? amt['currency'] : Ap2.ctx_get(ctx, 'asset'),
          'mimeType' => 'application/json',
          'maxTimeoutSeconds' => Ap2.ctx_get(ctx, 'max_timeout_seconds').nil? ? 60 : Ap2.ctx_get(ctx, 'max_timeout_seconds')
        }
        x_payment = Base64.strict_encode64(Js.utf8(Ap2.stringify({ 'x402Version' => 1, 'scheme' => 'exact', 'network' => network,
                                                                  'payload' => { 'transactionId' => payment['transaction_id'], 'amount' => amt['amount'],
                                                                                 'currency' => amt['currency'] } })))
        { 'rail' => 'x402', 'amount' => amt, 'merchant' => payment['payee']['id'],
          'payload' => { 'httpStatus' => 402, 'x402Version' => 1, 'error' => 'X-PAYMENT header is required', 'accepts' => [requirement],
                         'header' => { 'X-PAYMENT' => x_payment } } }
      end
    end

    # Stripe Shared Payment Token adapter: a shared token the buyer's agent grants the merchant to pull a bounded amount. The token is
    # the mandate's payment instrument id, never a raw PAN. ctx: pay_to.
    module StripeSptSettlement
      module_function

      def rail = 'stripe-spt'

      def settle(payment, ctx = nil)
        inst = payment['payment_instrument']
        if inst['type'] != 'shared_payment_token'
          raise Ap2Error, "stripe-spt: the payment instrument must be of type shared_payment_token, got #{Ap2.str(inst.key?('type') ? inst['type'] : UNDEF)}"
        end

        payload = { 'shared_payment_token' => inst['id'], 'amount' => payment['payment_amount']['amount'],
                    'currency' => Payments.lower(payment['payment_amount']['currency']) }
        payload['on_behalf_of'] = ctx['pay_to'] if Ap2.truthy?(Ap2.ctx_get(ctx, 'pay_to'))
        { 'rail' => 'stripe-spt', 'amount' => payment['payment_amount'], 'merchant' => payment['payee']['id'], 'payload' => payload }
      end
    end

    def x402_settlement = X402Settlement
    def stripe_spt_settlement = StripeSptSettlement
  end
end
