# frozen_string_literal: true

require_relative 'ap2_mandates'

# AP2, part 3: issuing open mandates, presenting closed ones (KB-SD-JWT hops), verifying a delegation chain, a purchase and the
# single-use redeem ledger. See ap2.rb. Options are String-keyed snake_case Hashes.
module AtlasPca
  module Ap2
    module_function

    # ---- issuing open mandates ------------------------------------------------------------------------------------------

    def sign_root(c, mandate, b)
      element = b.element(mandate)
      issuer = c['issuer']
      typ = c['typ']
      header = { 'typ' => typ.nil? ? ROOT_TYP : typ }
      header['kid'] = issuer['kid'] if issuer.key?('kid')
      header['x5c'] = issuer['x5c'] if truthy?(issuer.key?('x5c') ? issuer['x5c'] : UNDEF)
      alg = c['sd_alg']
      sign_sd_jwt({ 'header' => header, 'payload' => { 'delegate_payload' => [element], '_sd_alg' => alg.nil? ? 'sha-256' : alg },
                    'disclosures' => b.disclosures, 'private_key' => issuer['private_key'] })
    end

    def common_claims(c)
      jwk = assert_p256_jwk(c['agent_jwk'], 'agentJwk')
      iat = c.key?('iat') ? c['iat'] : UNDEF
      exp = c.key?('exp') ? c['exp'] : UNDEF
      raise Ap2Error, 'open mandate: need integer iat < exp (epoch seconds)' if !safe_int?(iat) || !safe_int?(exp) || exp <= iat

      out = { 'cnf' => { 'jwk' => { 'crv' => 'P-256', 'kty' => 'EC', 'x' => jwk['x'], 'y' => jwk['y'] } }, 'iat' => iat, 'exp' => exp }
      out[PCA_CLAIM] = c['pca'] if truthy?(c.key?('pca') ? c['pca'] : UNDEF)
      out
    end

    def sd_payment_constraint(c, b)
      t = g(c, 'type')
      return { 'type' => t, 'allowed' => iter_list(g(c, 'allowed')).map { |x| b.element(x) } } if t == 'payment.allowed_payees' || t == 'payment.allowed_payment_instruments'

      c
    end

    def sd_checkout_constraint(c, b)
      t = g(c, 'type')
      return { 'type' => t, 'allowed' => iter_list(g(c, 'allowed')).map { |x| b.element(x) } } if t == 'checkout.allowed_merchants'

      items = iter_list(g(c, 'items')).map do |it|
        compact({ 'id' => g(it, 'id'), 'acceptable_items' => iter_list(g(it, 'acceptable_items')).map { |x| b.element(x) }, 'quantity' => g(it, 'quantity') })
      end
      compact({ 'type' => t, 'items' => items })
    end

    def assert_well_formed(wrapped, problems, what, plain_constraints)
      p = problems.call(wrapped.merge('constraints' => plain_constraints))
      raise Ap2Error, "#{what}: #{p.join('; ')}" unless p.empty?
    end

    # Issue an open Payment Mandate (`mandate.payment.open.1`) as a signed SD-JWT. input: issuer ({ 'private_key', 'kid'?, 'x5c'? }),
    # agent_jwk, iat, exp, constraints, payee?, payment_amount?, payment_instrument?, pisp?, execution_date?, pca?, sd_alg?, salt?
    # (callable), typ?.
    def issue_open_payment_mandate(input)
      b = disclosure_builder(input['sd_alg'], input['salt'])
      mandate = { 'vct' => VCT_PAYMENT_OPEN, 'constraints' => iter_list(input['constraints']).map { |c| sd_payment_constraint(c, b) } }
      %w[payee payment_amount payment_instrument pisp].each do |key|
        mandate[key] = input[key] if truthy?(input.key?(key) ? input[key] : UNDEF)
      end
      mandate['execution_date'] = input['execution_date'] if input.key?('execution_date')
      mandate.update(common_claims(input))
      assert_well_formed(mandate, method(:open_payment_mandate_problems), 'open payment mandate', input['constraints'])
      sign_root(input, mandate, b)
    end

    # Issue an open Checkout Mandate (`mandate.checkout.open.1`) as a signed SD-JWT (same input as the payment form, `constraints` are
    # checkout constraints).
    def issue_open_checkout_mandate(input)
      b = disclosure_builder(input['sd_alg'], input['salt'])
      mandate = { 'vct' => VCT_CHECKOUT_OPEN, 'constraints' => iter_list(input['constraints']).map { |c| sd_checkout_constraint(c, b) } }
      mandate.update(common_claims(input))
      assert_well_formed(mandate, method(:open_checkout_mandate_problems), 'open checkout mandate', input['constraints'])
      sign_root(input, mandate, b)
    end

    # ---- presenting closed mandates (KB-SD-JWT hops) --------------------------------------------------------------------

    def present_hop(c, build)
      raise Ap2Error, 'closed mandate: aud and nonce are required' if !truthy?(c.key?('aud') ? c['aud'] : UNDEF) || !truthy?(c.key?('nonce') ? c['nonce'] : UNDEF)
      raise Ap2Error, 'closed mandate: iat must be an integer' unless safe_int?(c.key?('iat') ? c['iat'] : UNDEF)

      prev = parse_sd_jwt_hop(c['open'])
      b = disclosure_builder(prev['sdAlg'], c['salt'])
      mandate = build.call(b)
      element = b.element(mandate)
      mode = c['hash_mode']
      mode = 'sd_hash' if mode.nil?
      payload = { 'delegate_payload' => [element], 'iat' => c['iat'], 'aud' => c['aud'], 'nonce' => c['nonce'] }
      payload[mode] = mode == 'sd_hash' ? sd_hash_of(prev) : issuer_jwt_hash_of(prev)
      payload['_sd_alg'] = prev['sdAlg']
      hop = sign_sd_jwt({ 'header' => { 'typ' => 'kb+sd-jwt' }, 'payload' => payload, 'disclosures' => b.disclosures,
                          'private_key' => c['agent_key']['privateKey'] })
      "#{c['open']}~#{hop}" # hops are joined by "~~": the preceding token's own trailing "~" plus one separator "~"
    end

    # Present a closed Payment Mandate (`mandate.payment.1`) on top of an open payment mandate. input: open, agent_key
    # ({ 'privateKey', 'publicJwk' }), aud, nonce, iat, transaction_id, payee, payment_amount, payment_instrument, pisp?,
    # execution_date?, risk_data?, exp?, pca?, hash_mode?, salt?.
    def present_closed_payment(input)
      build = lambda do |_b|
        mandate = compact({ 'vct' => VCT_PAYMENT, 'transaction_id' => input.key?('transaction_id') ? input['transaction_id'] : UNDEF,
                            'payee' => input.key?('payee') ? input['payee'] : UNDEF,
                            'payment_amount' => input.key?('payment_amount') ? input['payment_amount'] : UNDEF,
                            'payment_instrument' => input.key?('payment_instrument') ? input['payment_instrument'] : UNDEF })
        mandate['pisp'] = input['pisp'] if truthy?(input.key?('pisp') ? input['pisp'] : UNDEF)
        mandate['execution_date'] = input['execution_date'] if input.key?('execution_date')
        mandate['risk_data'] = input['risk_data'] if truthy?(input.key?('risk_data') ? input['risk_data'] : UNDEF)
        mandate['exp'] = input['exp'] if input.key?('exp')
        mandate[PCA_CLAIM] = input['pca'] if truthy?(input.key?('pca') ? input['pca'] : UNDEF)
        p = payment_mandate_problems(mandate)
        raise Ap2Error, "closed payment mandate: #{p.join('; ')}" unless p.empty?

        mandate
      end
      present_hop(input, build)
    end

    # Present a closed Checkout Mandate (`mandate.checkout.1`) on top of an open checkout mandate (input as above with checkout_jwt).
    def present_closed_checkout(input)
      build = lambda do |b|
        prev_alg = parse_sd_jwt_hop(input['open'])['sdAlg']
        jwt = input.key?('checkout_jwt') ? input['checkout_jwt'] : UNDEF
        mandate = { '_sd' => [b.property('checkout_jwt', jwt)], 'vct' => VCT_CHECKOUT, 'checkout_hash' => sd_digest(jwt, prev_alg) }
        mandate['exp'] = input['exp'] if input.key?('exp')
        mandate[PCA_CLAIM] = input['pca'] if truthy?(input.key?('pca') ? input['pca'] : UNDEF)
        p = checkout_mandate_problems(mandate.merge('checkout_jwt' => jwt))
        raise Ap2Error, "closed checkout mandate: #{p.join('; ')}" unless p.empty?

        mandate
      end
      present_hop(input, build)
    end

    # ---- verifying a delegation chain -----------------------------------------------------------------------------------

    # Split a `~~`-joined chain into hops, each restored to `<jwt>~<d>...~`.
    def split_chain(token)
      raise Ap2Error, 'chain: empty' if !token.is_a?(String) || token.empty?

      parts = token.split('~~', -1)
      raise Ap2Error, "chain: more than #{MAX_HOPS} hops" if parts.length > MAX_HOPS

      parts.each_with_index.map { |p, i| i == parts.length - 1 ? p : "#{p}~" }
    end

    def check_times(label, o, now, skew)
      exp = o.key?('exp') ? o['exp'] : UNDEF
      iat = o.key?('iat') ? o['iat'] : UNDEF
      unless undef?(exp)
        raise Ap2Error, "#{label}: exp must be an integer" if !safe_int?(exp) || neg0?(exp)
        raise Ap2Error, "#{label}: expired at #{str(exp)}" unless finite?(now) && finite?(skew) && now <= exp + skew
      end
      return if undef?(iat)
      raise Ap2Error, "#{label}: iat must be an integer" if !safe_int?(iat) || neg0?(iat)
      raise Ap2Error, "#{label}: iat is in the future" unless finite?(now) && finite?(skew) && iat <= now + skew
    end

    def delegate_mandate(claims, label)
      dp = claims.key?('delegate_payload') ? claims['delegate_payload'] : UNDEF
      raise Ap2Error, "#{label}: delegate_payload missing" unless dp.is_a?(Array)
      raise Ap2Error, "#{label}: delegate_payload must disclose exactly one mandate (got #{dp.length})" if dp.length != 1 || !dp[0].is_a?(Hash)

      dp[0]
    end

    def cnf_jwk(mandate, label)
      cnf = mandate['cnf']
      raise Ap2Error, "#{label}: no cnf.jwk to delegate to" if !cnf.is_a?(Hash) || !cnf['jwk'].is_a?(Hash)

      assert_p256_jwk(cnf['jwk'], "#{label} cnf.jwk")
    end

    # Verify one key-binding hop against its predecessor (signature, typ, binding hash, times, aud/nonce). prev = { 'hop', 'mandate' };
    # o = { 'terminal', 'expected_audience'?, 'expected_nonce'?, 'now', 'skew' }. Returns { 'index' => -1, 'kind', 'hop', 'claims', 'mandate' }.
    def verify_kb_hop(hop, prev, o, label)
      typ = hop['header'].key?('typ') ? hop['header']['typ'] : UNDEF
      terminal = o['terminal']
      allowed = terminal ? TYP_TERMINAL : TYP_INTERMEDIATE
      raise Ap2Error, "#{label}: typ must be one of #{allowed.join(', ')}" if !typ.is_a?(String) || !allowed.include?(typ)
      raise Ap2Error, "#{label}: crit headers are not supported" if hop['header'].key?('crit')

      key = cnf_jwk(prev['mandate'], 'preceding mandate')
      raise Ap2Error, "#{label}: signature does not verify under the preceding mandate's cnf.jwk" unless verify_hop_signature(hop, key)

      claims = process_disclosures(hop['payload'], hop['disclosures'], hop['sdAlg'])
      has_sd = claims.key?('sd_hash')
      has_iss = claims.key?('issuer_jwt_hash')
      raise Ap2Error, "#{label}: exactly one of sd_hash / issuer_jwt_hash is required" if has_sd == has_iss

      expected = has_sd ? sd_hash_of(prev['hop']) : issuer_jwt_hash_of(prev['hop'])
      actual = has_sd ? claims['sd_hash'] : claims['issuer_jwt_hash']
      raise Ap2Error, "#{label}: #{has_sd ? 'sd_hash' : 'issuer_jwt_hash'} does not match the preceding hop" unless seq?(actual, expected)
      raise Ap2Error, "#{label}: iat is required" unless claims.key?('iat')

      check_times(label, claims, o['now'], o['skew'])
      mandate = delegate_mandate(claims, label)
      check_times("#{label} mandate", mandate, o['now'], o['skew'])
      has_cnf = mandate['cnf'].is_a?(Hash)
      raise Ap2Error, "#{label}: a terminal hop must not carry cnf" if terminal && has_cnf
      raise Ap2Error, "#{label}: an intermediate hop requires cnf" if !terminal && !has_cnf

      if terminal
        aud = o.key?('expected_audience') ? o['expected_audience'] : UNDEF
        raise Ap2Error, "#{label}: aud mismatch" if undef?(aud) || !seq?(claims.key?('aud') ? claims['aud'] : UNDEF, aud)

        nonce = o.key?('expected_nonce') ? o['expected_nonce'] : UNDEF
        raise Ap2Error, "#{label}: nonce mismatch" if undef?(nonce) || !seq?(claims.key?('nonce') ? claims['nonce'] : UNDEF, nonce)
      end
      { 'index' => -1, 'kind' => terminal ? 'terminal' : 'intermediate', 'hop' => hop, 'claims' => claims, 'mandate' => mandate }
    end

    # Verify a whole chain: root signature, then every hop in order. Never raises; reports the reason. o: resolve_issuer_key
    # (callable header -> public JWK or nil), expected_audience and expected_nonce (both required), now?, clock_skew_seconds?
    # (default 60). Returns { 'ok' => true, 'hops' } or { 'ok' => false, 'reason' }.
    def verify_delegation_chain(token, o)
      unless truthy?(o.key?('expected_audience') ? o['expected_audience'] : UNDEF) && truthy?(o.key?('expected_nonce') ? o['expected_nonce'] : UNDEF)
        raise Ap2Error, 'verify: expectedAudience and expectedNonce are required'
      end

      now = o['now']
      now = Time.now.to_i if now.nil?
      skew = o['clock_skew_seconds']
      skew = 60 if skew.nil?
      segments = split_chain(token).map { |s| parse_sd_jwt_hop(s) }
      root = segments[0]
      raise Ap2Error, 'root: crit headers are not supported' if root['header'].key?('crit')

      issuer_key = o.fetch('resolve_issuer_key').call(root['header'])
      raise Ap2Error, 'root: no issuer key for this header' unless truthy?(issuer_key)
      raise Ap2Error, 'root: signature does not verify under the issuer key' unless verify_hop_signature(root, issuer_key)

      root_claims = process_disclosures(root['payload'], root['disclosures'], root['sdAlg'])
      check_times('root', root_claims, now, skew)
      root_mandate = delegate_mandate(root_claims, 'root')
      check_times('root mandate', root_mandate, now, skew)
      hops = [{ 'index' => 0, 'kind' => 'root', 'hop' => root, 'claims' => root_claims, 'mandate' => root_mandate }]
      (1...segments.length).each do |i|
        v = verify_kb_hop(segments[i], hops[i - 1], { 'terminal' => i == segments.length - 1, 'expected_audience' => o['expected_audience'],
                                                      'expected_nonce' => o['expected_nonce'], 'now' => now, 'skew' => skew }, "hop #{i}")
        hops << v.merge('index' => i)
      end
      { 'ok' => true, 'hops' => hops }
    rescue StandardError => e # never raises
      { 'ok' => false, 'reason' => e.message }
    end

    def pair(r)
      raise Ap2Error, "expected an open mandate followed by one closed mandate, got #{r['hops'].length} hop(s)" if r['hops'].length != 2

      [r['hops'][0], r['hops'][1]]
    end

    def require_open_expiry(m, label)
      raise Ap2Error, "#{label}: an open mandate must carry exp" unless safe_int?(m.key?('exp') ? m['exp'] : UNDEF)
    end

    # Verify an open+closed checkout chain, the merchant-signed checkout, its hash, and the open constraints. o is the chain options
    # plus resolve_merchant_key(header). Returns { 'ok' => true, open, closed, checkoutJwt, checkout, openHash, hops } or
    # { 'ok' => false, 'reason', 'violations'? }.
    def verify_checkout_chain(token, o)
      r = verify_delegation_chain(token, o)
      return r unless r['ok']

      begin
        open_hop, closed_hop = pair(r)
        open_ = open_hop['mandate']
        closed = closed_hop['mandate']
        op = open_checkout_mandate_problems(open_)
        raise Ap2Error, "open checkout mandate: #{op.join('; ')}" unless op.empty?

        require_open_expiry(open_, 'open checkout mandate')
        cp = checkout_mandate_problems(closed)
        raise Ap2Error, "closed checkout mandate: #{cp.join('; ')}" unless cp.empty?

        alg = closed_hop['hop']['sdAlg']
        raise Ap2Error, 'checkout_hash does not match checkout_jwt' if sd_digest(closed['checkout_jwt'], alg) != closed['checkout_hash']

        jwt = parse_jwt(closed['checkout_jwt'], 'checkout_jwt')
        key = o.fetch('resolve_merchant_key').call(jwt['header'])
        raise Ap2Error, 'checkout_jwt: no merchant key for this header' unless truthy?(key)
        raise Ap2Error, 'checkout_jwt: merchant signature does not verify' unless verify_jwt_es256(jwt, key)

        checkout = project_checkout(jwt['payload'])
        violations = check_checkout_constraints(open_, checkout)
        return { 'ok' => false, 'reason' => "open checkout constraints violated: #{violations.join('; ')}", 'violations' => violations } unless violations.empty?

        { 'ok' => true, 'open' => open_, 'closed' => closed, 'checkoutJwt' => closed['checkout_jwt'], 'checkout' => checkout,
          'openHash' => sd_hash_of(open_hop['hop']), 'hops' => r['hops'] }
      rescue StandardError => e
        { 'ok' => false, 'reason' => e.message }
      end
    end

    # Verify an open+closed payment chain and every open payment constraint. o is the chain options plus open_checkout_hash (the open
    # checkout mandate's `sd_hash`), context? (usage state) and expected_transaction_id? (the closed checkout's `checkout_hash`).
    def verify_payment_chain(token, o)
      r = verify_delegation_chain(token, o)
      return r unless r['ok']

      begin
        open_hop, closed_hop = pair(r)
        open_ = open_hop['mandate']
        closed = closed_hop['mandate']
        op = open_payment_mandate_problems(open_)
        raise Ap2Error, "open payment mandate: #{op.join('; ')}" unless op.empty?

        require_open_expiry(open_, 'open payment mandate')
        cp = payment_mandate_problems(closed)
        raise Ap2Error, "closed payment mandate: #{cp.join('; ')}" unless cp.empty?

        expected = o.key?('expected_transaction_id') ? o['expected_transaction_id'] : UNDEF
        raise Ap2Error, 'transaction_id does not match the checkout being settled' if !undef?(expected) && !seq?(closed['transaction_id'], expected)

        now = o['now']
        opts = { 'open_checkout_hash' => o['open_checkout_hash'], 'now' => now.nil? ? Time.now.to_i : now }
        opts['context'] = o['context'] if truthy?(o.key?('context') ? o['context'] : UNDEF)
        violations = check_payment_constraints(open_, closed, opts)
        return { 'ok' => false, 'reason' => "open payment constraints violated: #{violations.join('; ')}", 'violations' => violations } unless violations.empty?

        { 'ok' => true, 'open' => open_, 'closed' => closed, 'openHash' => sd_hash_of(open_hop['hop']), 'hops' => r['hops'] }
      rescue StandardError => e
        { 'ok' => false, 'reason' => e.message }
      end
    end

    # Verify a complete purchase: the checkout chain, then the payment chain bound to it, and that the payment settles what the merchant
    # quoted (payee, currency, total). o: resolve_issuer_key, resolve_merchant_key, checkout and payment ({ 'expected_audience',
    # 'expected_nonce' }), context?, now?, clock_skew_seconds?.
    def verify_purchase(checkout_token, payment_token, o)
      base = { 'resolve_issuer_key' => o.fetch('resolve_issuer_key') }
      base['now'] = o['now'] unless o['now'].nil?
      base['clock_skew_seconds'] = o['clock_skew_seconds'] unless o['clock_skew_seconds'].nil?
      copts = base.merge(spread(o['checkout']))
      copts['resolve_merchant_key'] = o.fetch('resolve_merchant_key')
      co = verify_checkout_chain(checkout_token, copts)
      return { 'ok' => false, 'reason' => "checkout: #{co['reason']}" } unless co['ok']

      popts = base.merge(spread(o['payment']))
      popts['open_checkout_hash'] = co['openHash']
      popts['expected_transaction_id'] = co['closed']['checkout_hash']
      popts['context'] = o['context'] if truthy?(o.key?('context') ? o['context'] : UNDEF)
      pay = verify_payment_chain(payment_token, popts)
      return { 'ok' => false, 'reason' => "payment: #{pay['reason']}" } unless pay['ok']

      total = checkout_total(co['checkout'])
      return { 'ok' => false, 'reason' => 'checkout: needs exactly one total entry' } if total.nil?

      amt = pay['closed']['payment_amount']
      return { 'ok' => false, 'reason' => 'payment currency differs from the checkout currency' } if amt['currency'] != co['checkout']['currency']
      if amt['amount'] != total
        return { 'ok' => false, 'reason' => "payment amount #{Js.string(amt['amount'])} differs from the checkout total #{Js.string(total)}" }
      end

      merchant = co['checkout']['merchant']
      return { 'ok' => false, 'reason' => 'checkout: no merchant to compare the payee with' } unless truthy?(merchant)
      return { 'ok' => false, 'reason' => 'payee differs from the checkout merchant' } if merchant['id'] != pay['closed']['payee']['id']

      { 'ok' => true, 'checkout' => co, 'payment' => pay }
    end

    # ---- the redeem ledger ----------------------------------------------------------------------------------------------

    # verify_purchase plus single use and server-owned cumulative state. The usage context comes from `ledger`, never from the
    # caller; a missing or failing ledger denies. A ledger responds to reserve(open_mandate_hash, transaction_id, amount_minor) ->
    # context Hash | 'replayed' and release(open_mandate_hash, transaction_id). o is the verify_purchase options without context.
    def redeem_purchase(checkout_token, payment_token, o, ledger)
      return { 'ok' => false, 'reason' => 'ledger_required' } if ledger.nil? || !ledger.respond_to?(:reserve) || !ledger.respond_to?(:release)

      # a zero context is the most permissive one for budget and recurrence, so a failure here is final
      first = verify_purchase(checkout_token, payment_token, o.merge('context' => { 'totalAmount' => 0, 'totalUses' => 0 }))
      return first unless first['ok']

      open_hash = first['payment']['openHash']
      tx_id = first['payment']['closed']['transaction_id']
      amount = first['payment']['closed']['payment_amount']['amount']
      begin
        ctx = ledger.reserve(open_hash, tx_id, amount)
      rescue StandardError
        return { 'ok' => false, 'reason' => 'ledger_unavailable' }
      end
      return { 'ok' => false, 'reason' => 'replayed' } if ctx == 'replayed'

      final = verify_purchase(checkout_token, payment_token, o.merge('context' => ctx))
      unless final['ok']
        begin
          ledger.release(open_hash, tx_id)
        rescue StandardError
          nil # the reservation stays: a failed release only ever over-counts spend
        end
      end
      final
    end
  end
end
