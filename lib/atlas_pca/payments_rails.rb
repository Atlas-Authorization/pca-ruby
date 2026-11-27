# frozen_string_literal: true

require 'openssl'
require_relative 'payments'

# Payments, part 2: Shared Payment Token limits, spend rails (card limits, a real-time authorization callback, settlement
# reconciliation) and the Stripe Issuing adapter. See payments.rb.
module AtlasPca
  module Payments
    module_function

    # The usage_limits of a Stripe Shared Payment Token that fits what the mandate lets an agent spend WITHOUT a co-sign: at most
    # the auto-approve threshold and the remaining autonomous budget, lowercase currency, expiring with the mandate period.
    def shared_payment_token_limits(mandate, now)
      raise TypeError, 'sharedPaymentTokenLimits: now must be an epoch-ms time' unless finite?(now)

      t = prop(mandate, 'terms')
      budget = js_floor(to_number(prop(prop(mandate, 'budget'), 'B')))
      mx = js_min(prop(t, 'autoApproveThreshold'), budget)
      unless safe_int?(mx) && mx > 0
        raise ArgumentError, 'sharedPaymentTokenLimits: no autonomous spend capacity is left; a human co-sign is needed'
      end

      pe = prop(t, 'periodEnd')
      # an infinite period end would serialize as a null expires_at, which a token provider reads as no expiry
      raise TypeError, 'sharedPaymentTokenLimits: periodEnd must be an epoch-ms time' if !undef?(pe) && !finite?(pe)
      raise ArgumentError, 'sharedPaymentTokenLimits: the mandate period has ended' if !undef?(pe) && !(to_number(now) < to_number(pe))

      out = { 'currency' => lower(prop(t, 'currency')), 'max_amount' => mx.to_i }
      out['expires_at'] = num(js_floor(js_div(pe, 1000.0))) unless undef?(pe)
      out
    end

    def lower(s)
      raise TypeError, 's.toLowerCase is not a function' unless s.is_a?(String)

      s.downcase
    end

    def upper(s)
      raise TypeError, 's.toUpperCase is not a function' unless s.is_a?(String)

      s.upcase
    end

    # Action-kit convention: a trait `mcc.c5734` says the verb may spend in MCC 5734. Traits only narrow.
    def categories_from_traits(traits)
      raise TypeError, 'traits is not iterable' unless traits.is_a?(Array) || traits.is_a?(String)

      out = []
      (traits.is_a?(String) ? traits.chars : traits).each do |t|
        m = t.is_a?(String) ? t.b.match(/\Amcc\.c([0-9]{4})\z/n) : nil
        out << m[1].dup.force_encoding('UTF-8') if m
      end
      out.uniq.sort
    end

    # The limits an instrument for this mandate may carry (amounts from shared_payment_token_limits; categories are the
    # mandate's allowlist narrowed by the action's mcc traits). opts: action_traits, allow_any_category.
    def rail_limits(mandate, now, opts = UNDEF)
      opts = {} if undef?(opts)
      spt = shared_payment_token_limits(mandate, now)
      total = num(js_floor(to_number(prop(prop(mandate, 'budget'), 'B'))))
      t = prop(mandate, 'terms')
      from_mandate = spread_list(prop(t, 'categories'))
      traits = prop(opts, 'action_traits')
      from_traits = categories_from_traits(nullish?(traits) ? [] : traits)
      if !from_mandate.empty? && !from_traits.empty?
        cats = from_mandate.select { |c| from_traits.include?(c) }.sort
        raise ArgumentError, 'railLimits: the action traits and the mandate categories do not intersect; nothing may be spent' if cats.empty?
      else
        cats = (from_mandate.empty? ? from_traits : from_mandate).sort
      end
      if cats.empty? && prop(opts, 'allow_any_category') != true
        raise ArgumentError, 'railLimits: no category control (mandate categories or mcc.* traits); pass allowAnyCategory to accept any merchant category'
      end

      out = { 'currency' => upper(prop(t, 'currency')), 'perAuthorizationMax' => spt['max_amount'], 'totalMax' => total,
              'categories' => cats, 'merchants' => spread_list(prop(t, 'merchants')) }
      out['expiresAt'] = spt['expires_at'] * 1000 if spt.key?('expires_at')
      out
    end

    def decline(*reasons) = { 'approved' => false, 'reasons' => reasons }

    # A real-time authorization callback that answers from authorize_charge_atomic inside a latency budget. Total: a step-up,
    # a deny, an unknown card, a timeout, an exception are all declines. opts: instruments (callable instrument_id -> { 'mandate',
    # 'grant', 'budget_key'? } | nil), store, decide, latency_budget_ms (default 1500), now (callable -> ms), on_step_up (callable
    # (authorization, decision)). Returns a callable authorization -> { 'approved', 'reasons', 'decision'? }.
    def create_rail_authorizer(opts)
      budget_ms = opts['latency_budget_ms']
      budget_ms = 1500 if budget_ms.nil?
      raise ArgumentError, 'createRailAuthorizer: latencyBudgetMs must be positive' if !finite?(budget_ms) || budget_ms <= 0

      clock = opts['now'] || -> { now_ms }
      decide_one = lambda do |a|
        next decline('malformed_authorization') unless a.is_a?(Hash) && a['id'].is_a?(String) && a['instrumentId'].is_a?(String) && !a['id'].empty?

        amount = a['amount']
        next decline('amount_not_positive_minor_units') unless safe_int?(amount) && amount > 0
        next decline('currency_missing') unless a['currency'].is_a?(String) && !a['currency'].empty?
        next decline('merchant_unknown') unless a['merchantId'].is_a?(String) && !a['merchantId'].empty?

        inst = opts['instruments'].call(a['instrumentId'])
        next decline('instrument_unknown') if inst.nil?

        charge = { 'merchant' => a['merchantId'], 'amount' => amount, 'currency' => upper(a['currency']), 'now' => clock.call }
        charge['category'] = a['mcc'] if a.key?('mcc')
        d = authorize_charge_atomic(inst['mandate'], charge, inst['grant'], opts['store'], opts['decide'], inst['budget_key'])
        next { 'approved' => true, 'reasons' => [], 'decision' => d } if d['outcome'] == 'auto'

        if d['outcome'] == 'step_up'
          begin
            opts['on_step_up']&.call(a, d)
          rescue StandardError # a failing notifier must not change the answer
            nil
          end
          next { 'approved' => false, 'reasons' => ['step_up_required'] + d['reasons'], 'decision' => d }
        end
        { 'approved' => false, 'reasons' => d['reasons'].empty? ? ['denied'] : d['reasons'].dup, 'decision' => d }
      end

      lambda do |a|
        res = nil
        th = Thread.new do
          Thread.current.report_on_exception = false
          res = decide_one.call(a)
        rescue StandardError
          res = decline('authorizer_error')
        end
        # a decision that finishes after the timeout may still have debited the budget (an under-spend, the safe direction)
        th.join(budget_ms / 1000.0).nil? ? decline('latency_budget_exceeded') : res
      end
    end

    # Compare what settled with what PCA approved: commit only on an exact fit; anything else says freeze the grant.
    def reconcile_settlement(approved, s)
      reasons = []
      reasons << 'authorization_id_mismatch' unless seq?(prop(s, 'authorizationId'), prop(approved, 'id'))
      reasons << 'settled_more_than_approved' if js_gt?(prop(s, 'amount'), prop(approved, 'amount'))
      sc = prop(s, 'currency')
      raise TypeError, 's.currency.toUpperCase is not a function' unless sc.is_a?(String)

      reasons << 'currency_mismatch' if upper(sc) != upper(prop(approved, 'currency'))
      reasons << 'merchant_mismatch' unless seq?(prop(s, 'merchantId'), prop(approved, 'merchantId'))
      reasons << 'second_capture' if js_gt?(prop(s, 'captures'), 1)
      reasons.empty? ? { 'ok' => true } : { 'ok' => false, 'reasons' => reasons, 'action' => 'freeze_grant' }
    end

    # ---- Stripe Issuing adapter ---------------------------------------------------------------------------------------------

    # The form parameters for POST /v1/issuing/cards (virtual, active) that carry the rail limits. opts: category_names
    # (MCC -> Stripe category), cardholder, metadata. Raises when an MCC has no Stripe category name.
    def stripe_card_params(limits, opts)
      p = { 'cardholder' => opts.fetch('cardholder'), 'type' => 'virtual', 'status' => 'active',
            'currency' => lower(limits.fetch('currency')),
            'spending_controls[spending_limits][0][amount]' => tostr(limits.fetch('perAuthorizationMax')),
            'spending_controls[spending_limits][0][interval]' => 'per_authorization',
            'spending_controls[spending_limits][1][amount]' => tostr(limits.fetch('totalMax')),
            'spending_controls[spending_limits][1][interval]' => 'all_time' }
      names = opts.fetch('category_names')
      limits.fetch('categories').each_with_index do |mcc, i|
        name = names.is_a?(Hash) ? names[mcc] : nil
        raise ArgumentError, "stripeCardParams: no Stripe category name for MCC #{mcc}" if name.nil?

        p["spending_controls[allowed_categories][#{i}]"] = name
      end
      (opts['metadata'] || {}).each { |k, v| p["metadata[#{k}]"] = v }
      p
    end

    def sign_stripe_payload(raw_body, secret, t_sec)
      t = tostr(t_sec)
      "t=#{t},v1=#{OpenSSL::HMAC.hexdigest('SHA256', Js.utf8(secret), Js.utf8("#{t}.#{tostr(raw_body)}"))}"
    end

    # Verify a `Stripe-Signature` header over the RAW body. Total: false on anything malformed, stale or mismatched.
    def verify_stripe_signature(raw_body, header, secret, now_sec, tolerance_sec = STRIPE_WEBHOOK_TOLERANCE_SEC)
      return false if !header.is_a?(String) || !secret.is_a?(String) || secret.empty? || !(finite?(tolerance_sec) && tolerance_sec > 0)

      t = nil
      v1 = []
      header.scrub.split(',', -1).each do |part|
        i = part.index('=')
        next if i.nil?

        k = Js.trim(part[0, i])
        v = Js.trim(part[i + 1..])
        if k == 't' then t = v elsif k == 'v1' then v1 << v end
      end
      return false if t.nil? || !t.match?(/\A[0-9]{1,12}\z/) || v1.empty?
      return false unless (now_sec - t.to_i).abs <= tolerance_sec

      want = OpenSSL::HMAC.digest('SHA256', Js.utf8(secret), Js.utf8("#{t}.#{tostr(raw_body)}"))
      v1.any? { |s| s.match?(/\A[0-9a-f]{64}\z/) && OpenSSL.fixed_length_secure_compare([s].pack('H*'), want) }
    rescue StandardError
      false
    end

    # Normalise an `issuing_authorization.request` event; nil when it is not a well-formed request with a pending amount.
    def stripe_authorization_from_event(event)
      return nil unless event.is_a?(Hash) && event['type'] == 'issuing_authorization.request'

      data = event['data']
      a = data.is_a?(Hash) ? data['object'] : nil
      a = nil unless a.is_a?(Hash)
      pending = a && a['pending_request'].is_a?(Hash) ? a['pending_request'] : nil
      card = a && a['card'].is_a?(Hash) ? a['card'] : nil
      merchant = a && a['merchant_data'].is_a?(Hash) ? a['merchant_data'] : nil
      return nil if a.nil? || pending.nil? || !a['id'].is_a?(String) || !(card && card['id']).is_a?(String)

      amount = pending['amount']
      currency = pending['currency']
      return nil if !num?(amount) || !currency.is_a?(String)

      out = { 'id' => a['id'], 'instrumentId' => card['id'], 'amount' => amount, 'currency' => currency }
      nid = merchant && merchant['network_id']
      out['merchantId'] = nid if nid.is_a?(String) && !nid.empty?
      cc = merchant && merchant['category_code']
      out['mcc'] = cc if cc.is_a?(String)
      out
    end

    def reply(status, body, version)
      { 'status' => status, 'headers' => { 'Stripe-Version' => version, 'Content-Type' => 'application/json' }, 'body' => Js.json(body) }
    end

    # The HTTP handler body for the `issuing_authorization.request` endpoint (callable: { 'rawBody', 'signature' } -> { 'status',
    # 'headers', 'body' }). Bad signature: 400 (nothing is decided). A request event gets 200 { approved } from the PCA decision;
    # any other event type gets 200 {}. `amount` is never sent. opts: secret, authorize (callable RailAuthorization -> verdict),
    # stripe_version, now_sec (callable), tolerance_sec. REQUIRED OPERATOR SETTING: set the Issuing authorization timeout
    # response to DECLINE and turn Autopilot off.
    def create_stripe_issuing_webhook(opts)
      version = Js.truthy?(opts['stripe_version']) ? opts['stripe_version'] : STRIPE_API_VERSION
      now_sec = opts['now_sec'] || -> { Time.now.to_i }
      lambda do |req|
        raw = req.fetch('rawBody')
        tol = opts['tolerance_sec']
        unless verify_stripe_signature(raw, req['signature'], opts['secret'], now_sec.call, tol.nil? ? STRIPE_WEBHOOK_TOLERANCE_SEC : tol)
          next reply(400, { 'error' => 'bad_signature' }, version)
        end

        event = begin
          Js.parse_no_duplicates(raw) # a duplicate member is refused (JSON.parse keeps the last)
        rescue AtlasPca::Malformed
          next reply(400, { 'error' => 'bad_json' }, version)
        end
        next reply(200, {}, version) unless event.is_a?(Hash) && event['type'] == 'issuing_authorization.request'

        auth = stripe_authorization_from_event(event)
        next reply(200, { 'approved' => false }, version) if auth.nil?

        reply(200, { 'approved' => opts['authorize'].call(auth)['approved'] == true }, version)
      end
    end

    # Normalise an `issuing_transaction.created` capture into a settlement (a capture's amount is negative in Stripe's ledger).
    def stripe_settlement_from_transaction(txn)
      return nil unless txn.is_a?(Hash)

      m = txn['merchant_data'].is_a?(Hash) ? txn['merchant_data'] : nil
      return nil if txn['type'] != 'capture' || !txn['authorization'].is_a?(String) || !num?(txn['amount']) || !txn['currency'].is_a?(String)

      out = { 'authorizationId' => txn['authorization'], 'amount' => num(-txn['amount']), 'currency' => txn['currency'] }
      out['merchantId'] = m['network_id'] if m && m['network_id'].is_a?(String)
      out['captures'] = 1
      out
    end
  end
end
