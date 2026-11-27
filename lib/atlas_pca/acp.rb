# frozen_string_literal: true

require 'base64'
require_relative 'js_compat'
require_relative 'jose'
require_relative 'whatwg_url'
require_relative 'agentcard_card'

# Agentic Commerce Protocol (ACP) and x402 for PCA, byte-identical to the TypeScript reference (@atlasauth/pca-acp):
# delegated one-time payment tokens minted FROM a PCActn (the proof's spend cap, merchant and category allowlists and
# human-present requirement gate issuance), their settlement-time verification, the x402 v1 challenge and the injectable
# settle flow, x402 v2 (requirements, headers, negotiation), its HTTP transport and Stripe Shared Payment Granted Tokens.
# No network is performed: the verifier, settler and single-use store are injected (a store is any object with
# #claim(jti, expires_at_ms) -> true | false). Where the reference awaits, these functions are synchronous.
# Options Hashes (mint, verify, challenges, verifier) are String-keyed snake_case; data objects (caveats, authority, request,
# claims, requirements, payloads) keep the reference's camelCase wire keys. A settle step returning nil yields no receipt.
module AtlasPca
  module Acp
    ACP_DELEGATED_TOKEN_VERSION = 1
    ACP_DELEGATED_TOKEN_TYPE = 'acp-delegated-payment'
    SPEND_CAP_CAVEAT = 'max_amount'
    MERCHANT_ALLOW_CAVEAT = 'merchant_allow'
    MERCHANT_CATEGORY_CAVEAT = 'merchant_category'
    HUMAN_PRESENT_CAVEAT = 'human_present'
    X402_VERSION_1 = 1
    X402_VERSION_2 = 2
    X402_SUPPORTED_VERSIONS = [2, 1].freeze
    X402_V2_PAYMENT_REQUIRED_HEADER = 'PAYMENT-REQUIRED'
    X402_PAYMENT_SIGNATURE_HEADER = 'PAYMENT-SIGNATURE'
    X402_PAYMENT_RESPONSE_HEADER = 'PAYMENT-RESPONSE'
    X402_HTTP_STATUS = { 'payment_required' => 402, 'malformed' => 400, 'failed' => 402, 'internal_error' => 500, 'settled' => 200 }.freeze
    STRIPE_SPT_OBJECT = 'shared_payment.granted_token'
    UNDEFINED = AgentcardCard::UNDEFINED

    # A delegated payment token cannot be minted: the request exceeds the proof's authority (or the input is malformed).
    class AcpAuthorityError < StandardError; end

    module_function

    # ---- JavaScript value semantics ----

    def undef?(v) = v.equal?(UNDEFINED)
    def get(o, k) = AgentcardCard.get(o, k)
    def member(o, k) = AgentcardCard.member(o, k)
    def nullish(v, default) = AgentcardCard.nullish(v, default)
    def s(v) = undef?(v) ? 'undefined' : Js.string(v)
    def js_num(v) = Predicates.js_number_string(v)
    def num?(v) = Js.num?(v)
    def obj?(v) = v.is_a?(Hash)
    def truthy(v) = Js.truthy?(undef?(v) ? nil : v)
    def finite?(v) = num?(v) && (v.is_a?(Integer) || v.finite?)
    def safe_int?(v) = num?(v) && Js.safe_integer?(v)
    def amount?(v) = safe_int?(v) && v.positive?
    def int?(v) = safe_int?(v) && !Js.neg_zero?(v)
    def non_empty?(v) = v.is_a?(String) && !v.empty?
    def now_ms = Process.clock_gettime(Process::CLOCK_REALTIME, :millisecond)

    def opt(o, k) = get(o, k)

    # x.toLowerCase(): only a String has it (anything else throws).
    def lower(x)
      raise TypeError, 'toLowerCase is not a function' unless x.is_a?(String)

      AgentcardCard.lower(x)
    end

    # Match an ASCII-only pattern against any String (a lone surrogate included) without an encoding error.
    def full?(re, str) = str.b.match?(re)

    NUM_RE = /\A[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\z/n

    # Number(v) for a JSON value or undefined (NaN where the reference yields it).
    def to_number(v)
      return Float::NAN if undef?(v)
      return 0.0 if v.nil? || v == false
      return 1.0 if v == true
      return v.to_f if num?(v)
      return to_number(s(v)) if v.is_a?(Array) || v.is_a?(Hash)

      return Float::NAN unless v.to_s.valid_encoding? # a lone surrogate is no number

      t = Js.trim(v.to_s)
      return 0.0 if t.empty?
      return Float::INFINITY if ['Infinity', '+Infinity'].include?(t)
      return -Float::INFINITY if t == '-Infinity'
      if t.length > 2 && t[0] == '0' && 'xXoObB'.include?(t[1])
        base, re = { 'x' => [16, /\A[0-9a-fA-F]+\z/], 'o' => [8, /\A[0-7]+\z/], 'b' => [2, /\A[01]+\z/] }[t[1].downcase]
        return t[2..].match?(re) ? t[2..].to_i(base).to_f : Float::NAN
      end
      t.b.match?(NUM_RE) ? t.to_f : Float::NAN
    end

    # a > b where a is a number and b may be any value (coerced by ToNumber, so NaN compares false).
    def gt(a, b) = a.to_f > to_number(b)
    # a <= b under the same coercion; a refusal reads as !le so a NaN bound refuses.
    def le(a, b) = a.to_f <= to_number(b)

    def each_item(x)
      case x
      when Array then x
      when String then x.chars
      when Hash then x.keys
      else raise TypeError, 'value is not iterable'
      end
    end

    # ---- caveat vocabulary ----

    def spend_cap_caveat(max_amount, currency = UNDEFINED)
      out = { 'type' => SPEND_CAP_CAVEAT, 'max' => max_amount }
      out['currency'] = currency unless undef?(currency)
      out
    end

    def merchant_allow_caveat(merchants) = { 'type' => MERCHANT_ALLOW_CAVEAT, 'merchants' => merchants.to_a }
    def merchant_category_caveat(categories) = { 'type' => MERCHANT_CATEGORY_CAVEAT, 'categories' => categories.to_a }
    def human_present_caveat(required = true) = { 'type' => HUMAN_PRESENT_CAVEAT, 'required' => required }

    def string_array(v, label)
      raise AcpAuthorityError, "malformed #{label} caveat: expected a string[] (fail closed)" unless v.is_a?(Array) && v.all?(String)

      v
    end

    # Collapse a leaf capability's cumulative caveats into its effective payment authority: the tightest cap, intersected
    # allowlists, a sticky human-present requirement. A malformed PAYMENT caveat raises (fail closed); other types are ignored.
    def extract_payment_authority(caveats)
      raise TypeError, 'caveats is not iterable' unless caveats.is_a?(Array) || caveats.is_a?(String)

      max_amount = UNDEFINED
      currency = UNDEFINED
      merchants = nil
      categories = nil
      human = false
      each_item(caveats).each do |c|
        case get(c, 'type')
        when SPEND_CAP_CAVEAT
          mx = member(c, 'max')
          if !num?(mx) || !safe_int?(mx) || mx.negative? || Js.neg_zero?(mx)
            raise AcpAuthorityError, 'malformed max_amount caveat: max must be an integer >= 0 in minor units (fail closed)'
          end

          max_amount = undef?(max_amount) ? mx : [max_amount, mx].min
          cur = member(c, 'currency')
          unless undef?(cur)
            raise AcpAuthorityError, 'malformed max_amount caveat: currency must be a non-empty string (fail closed)' unless non_empty?(cur)
            if !undef?(currency) && currency != cur
              raise AcpAuthorityError, "conflicting spend-cap currencies \"#{currency}\" vs \"#{cur}\" (fail closed)"
            end

            currency = cur
          end
        when MERCHANT_ALLOW_CAVEAT
          lst = string_array(member(c, 'merchants'), 'merchant_allow')
          merchants = merchants.nil? ? lst.uniq : merchants.select { |m| lst.include?(m) }
        when MERCHANT_CATEGORY_CAVEAT
          lst = string_array(member(c, 'categories'), 'merchant_category')
          categories = categories.nil? ? lst.uniq : categories.select { |m| lst.include?(m) }
        when HUMAN_PRESENT_CAVEAT
          req = member(c, 'required')
          raise AcpAuthorityError, 'malformed human_present caveat: required must be a boolean (fail closed)' unless [true, false].include?(req)

          human ||= req
        end
      end
      out = {}
      out['maxAmount'] = max_amount unless undef?(max_amount)
      out['currency'] = currency unless undef?(currency)
      out.merge('merchants' => merchants, 'categories' => categories, 'humanPresentRequired' => human)
    end

    # Check a concrete purchase request against a payment authority. Pure and fail-closed: an over-cap amount, a forbidden
    # currency, a merchant or category outside the allowlist or a missing human-present signal returns {'ok' => false, ...}.
    def check_payment_authority(authority, request)
      amount = get(request, 'amount')
      currency = get(request, 'currency')
      merchant = get(request, 'merchant')
      return { 'ok' => false, 'reason' => 'amount must be a positive integer in minor units' } unless amount?(amount)
      return { 'ok' => false, 'reason' => 'currency must be a non-empty string' } unless non_empty?(currency)
      return { 'ok' => false, 'reason' => 'merchant must be a non-empty string' } unless non_empty?(merchant)

      a_cur = member(authority, 'currency')
      if !undef?(a_cur) && a_cur != currency
        return { 'ok' => false, 'reason' => "currency \"#{currency}\" is not the authorized currency \"#{s(a_cur)}\"" }
      end

      cap = member(authority, 'maxAmount')
      if !undef?(cap) && !(int?(cap) && cap >= 0)
        return { 'ok' => false, 'reason' => 'authorized spend cap is not a non-negative integer (fail closed)' }
      end
      if !undef?(cap) && !le(amount, cap)
        return { 'ok' => false, 'reason' => "amount #{js_num(amount)} exceeds the authorized spend cap #{s(cap)}" }
      end

      merchants = member(authority, 'merchants')
      if !merchants.nil? && !undef?(merchants) && !merchants.include?(merchant)
        return { 'ok' => false, 'reason' => "merchant \"#{merchant}\" is not in the authorized allowlist" }
      end

      categories = member(authority, 'categories')
      if !categories.nil? && !undef?(categories)
        category = member(request, 'category')
        return { 'ok' => false, 'reason' => 'the proof constrains merchant categories but no category was supplied' } if undef?(category)
        unless each_item(categories).any? { |x| x.is_a?(String) && x == category }
          return { 'ok' => false, 'reason' => "category \"#{s(category)}\" is not in the authorized allowlist" }
        end
      end
      if truthy(member(authority, 'humanPresentRequired')) && member(request, 'humanPresent') != true
        return { 'ok' => false, 'reason' => 'the proof requires a human-present charge but humanPresent was not asserted' }
      end

      { 'ok' => true }
    end

    # ---- delegated payment token ----

    def leaf_capability(pca)
      chain = get(pca, 'cap_chain')
      raise AcpAuthorityError, 'PCActn carries no capability chain (fail closed)' unless chain.is_a?(Array) && !chain.empty?

      chain[-1]
    end

    def authority_ref(pca)
      leaf = leaf_capability(pca)
      action = get(pca, 'action')
      ref = { 'digest' => AtlasPca.hash_canonical(pca), 'aud' => get(pca, 'aud'), 'grant_ref' => get(pca, 'grant_ref'),
              'leaf_holder' => get(leaf, 'holder'), 'verb' => get(action, 'verb'), 'resource' => get(action, 'resource'),
              'params_digest' => get(action, 'params_digest') }
      ref.reject { |_, v| undef?(v) }
    end

    def compact(h) = h.reject { |_, v| undef?(v) }

    # Mint a one-time ACP delegated payment token (a compact EdDSA JWS) FROM a PCActn, bound to session, merchant, amount,
    # currency and expiry, carrying the proof's authority BY REFERENCE (pca.digest). The proof's caveats gate issuance; an
    # over-authority request, an expiry in the past or one that would outlive the proof raises AcpAuthorityError. opts: amount,
    # currency, merchant, session, expires_at, payment_method, signing_key (a private JWK or key), alg, category, human_present,
    # issuer, kid, jti, now.
    def mint_delegated_payment_token(pca, opts)
      now_o = opt(opts, 'now')
      now = finite?(now_o) ? now_o : now_ms
      authority = extract_payment_authority(get(leaf_capability(pca), 'caveats'))
      req = compact({ 'amount' => opt(opts, 'amount'), 'currency' => opt(opts, 'currency'), 'merchant' => opt(opts, 'merchant') })
      %w[category human_present].each do |k|
        req[k == 'human_present' ? 'humanPresent' : k] = opts[k] unless undef?(opt(opts, k))
      end
      check = check_payment_authority(authority, req)
      raise AcpAuthorityError, "refused: #{check['reason'] || 'request exceeds the proof authority'}" unless check['ok']

      exp_at = opt(opts, 'expires_at')
      raise AcpAuthorityError, 'refused: expiresAt must be a finite epoch-ms timestamp' unless finite?(exp_at)
      raise AcpAuthorityError, 'refused: expiresAt is not in the future' if exp_at <= now
      if !(finite?(get(pca, 'exp')) && le(exp_at, get(pca, 'exp')))
        raise AcpAuthorityError, "refused: token expiry #{js_num(exp_at)} would outlive the proof's exp #{s(get(pca, 'exp'))}"
      end

      session = opt(opts, 'session')
      raise AcpAuthorityError, 'refused: a session id is required' unless truthy(session)

      ref = authority_ref(pca)
      jti = opt(opts, 'jti')
      if jti.nil? || undef?(jti)
        seed = pca.merge('nonce' => "acp:#{s(session)}:#{s(opt(opts, 'merchant'))}:#{s(opt(opts, 'amount'))}:" \
                                    "#{s(opt(opts, 'currency'))}:#{s(exp_at)}:#{ref['digest']}")
        jti = AtlasPca.hash_canonical(seed)
      end
      claims = { 'typ' => ACP_DELEGATED_TOKEN_TYPE, 'ver' => ACP_DELEGATED_TOKEN_VERSION, 'jti' => jti, 'session' => session,
                 'merchant' => opt(opts, 'merchant'), 'amount' => opt(opts, 'amount'), 'currency' => opt(opts, 'currency'),
                 'iat' => now, 'exp' => exp_at, 'paymentMethod' => AgentcardCard.spread(opt(opts, 'payment_method')),
                 'humanPresent' => opt(opts, 'human_present') == true }
      claims['category'] = opts['category'] unless undef?(opt(opts, 'category'))
      claims['iss'] = opts['issuer'] unless undef?(opt(opts, 'issuer'))
      claims['pca'] = ref
      claims = compact(claims)
      alg_o = opt(opts, 'alg')
      alg = alg_o.nil? || undef?(alg_o) ? 'EdDSA' : alg_o
      sk = opt(opts, 'signing_key')
      key = AgentcardCard.jwk?(sk) ? AgentcardCard.signing_key(sk, alg) : sk
      header = { 'alg' => alg, 'typ' => ACP_DELEGATED_TOKEN_TYPE }
      header['kid'] = opts['kid'] unless undef?(opt(opts, 'kid'))
      prot = AgentcardCard.b64u(Js.utf8(Js.json(header)))
      body = AgentcardCard.b64u(Js.utf8(Js.json(claims)))
      "#{prot}.#{body}.#{AgentcardCard.b64u(Jose.jws_sign(alg, key, "#{prot}.#{body}".b))}"
    end

    def payment_method?(v) = v.is_a?(Hash) && v['type'].is_a?(String)

    def parse_claims(payload)
      parsed = begin
        Js.parse(payload.dup.force_encoding('UTF-8').scrub("�"))
      rescue AtlasPca::Malformed
        return nil
      end
      return nil unless parsed.is_a?(Hash)

      c = parsed
      return nil if c['typ'] != ACP_DELEGATED_TOKEN_TYPE || !num?(c['ver']) || c['ver'] != ACP_DELEGATED_TOKEN_VERSION

      return nil if !c['jti'].is_a?(String) || !c['session'].is_a?(String) || !c['merchant'].is_a?(String) || !amount?(c['amount']) ||
                    !c['currency'].is_a?(String) || !finite?(c['iat']) || !finite?(c['exp']) || c['jti'].empty? || c['session'].empty? ||
                    c['merchant'].empty? || c['currency'].empty? || ![true, false].include?(c['humanPresent']) ||
                    !payment_method?(c['paymentMethod'])

      p = c['pca']
      return nil unless p.is_a?(Hash) && %w[digest aud grant_ref leaf_holder verb resource params_digest].all? { |k| p[k].is_a?(String) }

      parsed
    end

    def verify_binding(token, opts)
      alg_o = opt(opts, 'alg')
      alg = alg_o.nil? || undef?(alg_o) ? 'EdDSA' : alg_o
      now_o = opt(opts, 'now')
      now = finite?(now_o) ? now_o : now_ms
      claims = nil
      begin
        Jose.assert_canonical_compact_jws(token) # canonical-spelling gate BEFORE the signature check
        vk = opt(opts, 'verify_key')
        key = AgentcardCard.jwk?(vk) ? AgentcardCard.import_verify_key(vk, alg) : (undef?(vk) ? nil : vk)
        raise Jose::Error, 'Invalid key for this operation' if key.equal?(AgentcardCard::BAD_KEY)

        payload, = Jose.compact_verify(token, key, algorithms: [alg])
        claims = parse_claims(payload)
      rescue StandardError => e # every refusal reads the same, with the library's own words
        return { 'ok' => false, 'reason' => "token signature did not verify: #{e.message}" }
      end
      return { 'ok' => false, 'reason' => 'token payload is not a well-formed delegated payment token' } if claims.nil?

      em = opt(opts, 'expected_merchant')
      if claims['merchant'] != em || !em.is_a?(String)
        return { 'ok' => false, 'reason' => "token merchant \"#{claims['merchant']}\" does not match expected \"#{s(em)}\"", 'claims' => claims }
      end

      amount = opt(opts, 'amount')
      unless amount?(amount)
        return { 'ok' => false, 'reason' => 'settlement amount must be a positive integer in minor units', 'claims' => claims }
      end
      if amount > claims['amount']
        return { 'ok' => false, 'claims' => claims,
                 'reason' => "settlement amount #{js_num(amount)} exceeds the token's authorized amount #{js_num(claims['amount'])}" }
      end
      return { 'ok' => false, 'reason' => 'the delegated payment token has expired', 'claims' => claims } if now > claims['exp']

      es = opt(opts, 'expected_session')
      if !undef?(es) && (!es.is_a?(String) || claims['session'] != es)
        return { 'ok' => false, 'reason' => "token session \"#{claims['session']}\" does not match expected \"#{s(es)}\"", 'claims' => claims }
      end

      ec = opt(opts, 'expected_currency')
      if !undef?(ec) && (!ec.is_a?(String) || claims['currency'] != ec)
        return { 'ok' => false, 'reason' => "token currency \"#{claims['currency']}\" does not match expected \"#{s(ec)}\"", 'claims' => claims }
      end

      grant = opt(opts, 'grant')
      pca = opt(opts, 'pc_actn')
      if !undef?(grant) && undef?(pca)
        return { 'ok' => false, 'reason' => 'a grant was supplied without the pcActn to re-verify (fail closed)', 'claims' => claims }
      end

      unless undef?(pca)
        if AtlasPca.hash_canonical(pca) != claims['pca']['digest']
          return { 'ok' => false, 'claims' => claims,
                   'reason' => 'pcactn_digest mismatch: the supplied proof is not the one that minted this token' }
        end
        unless undef?(grant)
          roots = opt(opts, 'authorized_plan_roots')
          aud = opt(opts, 'audience')
          v = AtlasPca.verify_pcactn(pca, grant, now: now, audience: undef?(aud) ? nil : aud, authorized_plan_roots: undef?(roots) ? nil : roots,
                                                 insecure_skip_plan_root_check: opt(opts, 'insecure_skip_plan_root_check') == true)
          result = { 'allow' => v.allow ? true : false, 'checks' => v.checks.dup, 'reason' => v.reason }
          unless v.allow
            return { 'ok' => false, 'claims' => claims, 'pcaResult' => result,
                     'reason' => "bound proof failed to verify: #{Js.truthy?(v.reason) ? v.reason : 'denied'}" }
          end

          return { 'ok' => true, 'claims' => claims, 'pcaResult' => result }
        end
      end
      { 'ok' => true, 'claims' => claims }
    end

    # Verify a delegated payment token at settlement: the signature, then merchant, amount, expiry, session and currency
    # bindings and, with a pc_actn, the proof's digest (end to end with a grant). Strict by default: a single_use store and an
    # expected_currency are required, and after every other check the token's jti is claimed once. Fails CLOSED on every
    # mismatch, an already redeemed token or an unavailable store.
    def verify_delegated_payment_token(token, opts)
      su = opt(opts, 'single_use')
      if opt(opts, 'strict') != false
        unless truthy(su) && su.respond_to?(:claim)
          return { 'ok' => false, 'reason' => 'strict settlement requires a singleUse store (fail closed)' }
        end

        cur = opt(opts, 'expected_currency')
        return { 'ok' => false, 'reason' => 'strict settlement requires expectedCurrency (fail closed)' } unless non_empty?(cur)
      end
      res = verify_binding(token, opts)
      return res if !res['ok'] || undef?(su)

      claims = res['claims']
      first = begin
        su.claim(claims['jti'], claims['exp']) == true
      rescue StandardError # a store that is down never admits a token
        return { 'ok' => false, 'reason' => 'single-use store unavailable (fail closed)', 'claims' => claims }
      end
      first ? res : { 'ok' => false, 'reason' => 'the delegated payment token was already redeemed', 'claims' => claims }
    end

    # ---- x402 v1 ----

    # The HTTP 402 challenge for a protected resource (x402 v1 'accepts' entry and body). Raises TypeError on anything the v1
    # wire would make invalid (a non-positive-integer amount, no pay_to or currency, a bad timeout).
    def x402_challenge(resource, opts)
      amount = opt(opts, 'amount')
      raise TypeError, 'x402Challenge: amount must be a positive integer in atomic/minor units' unless amount?(amount)

      pay_to = opt(opts, 'pay_to')
      currency = opt(opts, 'currency')
      raise TypeError, 'x402Challenge: payTo is required' unless non_empty?(pay_to)
      raise TypeError, 'x402Challenge: currency (the x402 asset) is required' unless non_empty?(currency)

      timeout = nullish(opt(opts, 'max_timeout_seconds'), 60)
      raise TypeError, 'x402Challenge: maxTimeoutSeconds must be a positive integer' if !safe_int?(timeout) || timeout <= 0

      requirement = { 'maxTimeoutSeconds' => timeout, 'scheme' => nullish(opt(opts, 'scheme'), 'exact'),
                      'network' => nullish(opt(opts, 'network'), 'base-sepolia'), 'maxAmountRequired' => js_num(amount),
                      'resource' => resource,
                      'description' => nullish(opt(opts, 'description'), "Payment required for #{s(resource)}"), 'payTo' => pay_to,
                      'asset' => currency, 'mimeType' => nullish(opt(opts, 'mime_type'), 'application/json') }
      { 'status' => 402, 'headers' => { 'Content-Type' => 'application/json' },
        'body' => { 'x402Version' => 1, 'error' => nullish(opt(opts, 'error'), 'X-PAYMENT header is required'), 'accepts' => [requirement] } }
    end

    # Gate an x402 settlement on a verified, PCActn-bound payment. opts['verify'] (payload -> {ok, reason?, claims?}) is required;
    # a refusal answers a fresh 402 (fail closed), otherwise the optional opts['settle'] step (payload, claims -> receipt) runs and
    # its non-nil return value becomes the receipt.
    def x402_settle(payload, opts)
      norm = normalize_x402_payload(payload)
      return { 'settled' => false, 'status' => 402, 'reason' => norm['reason'] } unless norm['ok']

      v = opts['verify'].call(payload)
      unless Js.truthy?(v['ok'])
        out = { 'settled' => false, 'status' => 402, 'reason' => nullish(v['reason'], 'payment verification failed') }
        out['claims'] = v['claims'] if Js.truthy?(v['claims'])
        return out
      end
      unless v.key?('claims')
        return { 'settled' => false, 'status' => 402, 'reason' => 'verifier admitted the payment but returned no claims (fail closed)' }
      end

      receipt = Js.truthy?(opts['settle']) ? opts['settle'].call(payload, v['claims']) : nil
      out = { 'settled' => true, 'status' => 200, 'claims' => v['claims'] }
      out['receipt'] = receipt unless receipt.nil?
      out
    end

    # Adapt verify_delegated_payment_token into the 'verify' step of x402_settle: it reads the token from the payload of either
    # version and verifies its binding and bound proof. Strict by default: expected_merchant and amount must come from the server
    # (the payload's own are never read) and a store and currency are required.
    def acp_x402_verifier(opts)
      lambda do |payload|
        norm = normalize_x402_payload(payload)
        return { 'ok' => false, 'reason' => norm['reason'] } unless norm['ok']

        offered = opt(opts, 'offered')
        if norm['version'] == 2 && !undef?(offered) && !x402_accepted_matches(offered, norm['accepted'])
          return { 'ok' => false, 'reason' => 'x402 v2 payload.accepted is not one of the requirements this server offered' }
        end

        em = opt(opts, 'expected_merchant')
        amt = opt(opts, 'amount')
        if opt(opts, 'strict') != false && (undef?(em) || undef?(amt))
          return { 'ok' => false, 'reason' => 'strict settlement requires the server to supply expectedMerchant and amount (fail closed)' }
        end

        merchant = nullish(em, member(norm, 'merchant'))
        return { 'ok' => false, 'reason' => 'x402 payload has no merchant to check the token against' } unless non_empty?(merchant)

        amount = nullish(amt, member(norm, 'amount'))
        return { 'ok' => false, 'reason' => 'x402 payload has no amount to check the token against' } unless num?(amount) && amount?(amount)

        o2 = { 'expected_merchant' => merchant, 'amount' => amount, 'verify_key' => opt(opts, 'verify_key') }
        %w[alg now expected_session expected_currency pc_actn grant audience authorized_plan_roots insecure_skip_plan_root_check
           single_use strict].each { |k| o2[k] = opts[k] unless undef?(opt(opts, k)) }
        res = verify_delegated_payment_token(norm['token'], o2)
        out = { 'ok' => res['ok'] }
        out['reason'] = res['reason'] unless res['reason'].nil?
        out['claims'] = res['claims'] if Js.truthy?(res['claims'])
        out
      end
    end

    # Map VERIFIED token claims to the ACP delegate_payment allowance; raises AcpAuthorityError when a claim cannot be expressed
    # in the ACP shape (currency not three letters, merchant over 256 characters, expiry not a date).
    def to_acp_allowance(claims)
      raise AcpAuthorityError, 'allowance: amount must be a positive integer in minor units' unless amount?(get(claims, 'amount'))

      cur = claims['currency']
      currency = cur.is_a?(String) ? AgentcardCard.lower(cur) : ''
      raise AcpAuthorityError, 'allowance: currency must be a three-letter ISO-4217 code' unless full?(/\A[a-z]{3}\z/n, currency)

      merchant = claims['merchant']
      session = claims['session']
      unless merchant.is_a?(String) && !merchant.empty? && Js.len16(merchant) <= 256
        raise AcpAuthorityError, 'allowance: merchant_id must be 1 to 256 characters'
      end
      raise AcpAuthorityError, 'allowance: checkout_session_id is required' unless non_empty?(session)

      exp = claims['exp']
      raise AcpAuthorityError, 'allowance: expiry is not a valid time' unless finite?(exp)

      at = begin
        iso_from_ms(exp)
      rescue ArgumentError
        raise AcpAuthorityError, 'allowance: expiry is not a valid time'
      end
      { 'reason' => 'one_time', 'max_amount' => claims['amount'], 'currency' => currency, 'checkout_session_id' => session,
        'merchant_id' => merchant, 'expires_at' => at }
    end

    # new Date(ms).toISOString(): ArgumentError for an out-of-range time.
    def iso_from_ms(ms)
      raise ArgumentError, 'Invalid time value' if !num?(ms) || (ms.is_a?(Float) && !ms.finite?) || ms.abs > 8.64e15

      days, rem = ms.to_i.divmod(86_400_000)
      z = days + 719_468
      era = z.div(146_097)
      doe = z - (era * 146_097)
      yoe = (doe - doe.div(1460) + doe.div(36_524) - doe.div(146_096)).div(365)
      y = yoe + (era * 400)
      doy = doe - ((365 * yoe) + yoe.div(4) - yoe.div(100))
      mp = ((5 * doy) + 2).div(153)
      d = doy - (((153 * mp) + 2).div(5)) + 1
      m = mp < 10 ? mp + 3 : mp - 9
      y += 1 if m <= 2
      ys = y.between?(0, 9999) ? format('%04d', y) : "#{y.positive? ? '+' : '-'}#{format('%06d', y.abs)}"
      format('%s-%02d-%02dT%02d:%02d:%02d.%03dZ', ys, m, d, rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60, rem % 1000)
    end

    # ---- x402 v2 ----

    CAIP2 = /\A[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}\z/n
    PRINTABLE = /\A[\x20-\x7e]*\z/n
    ATOMIC = /\A(?:0|[1-9][0-9]*)\z/n
    B64_SHAPE = %r{\A[A-Za-z0-9+/]+={0,2}\z}n

    def absolute_http?(u)
      return false unless u.is_a?(String)

      r = WhatwgUrl.parse(u)
      !r.nil? && %w[http https].include?(r['scheme'])
    end

    # Problems with a ResourceInfo (empty = valid).
    def resource_info_problems(r)
      return ['resource must be an object'] unless obj?(r)

      p = []
      p << 'resource.url must be an absolute http(s) URL' unless absolute_http?(r['url'])
      %w[description mimeType].each { |k| p << "resource.#{k} must be a string" if r.key?(k) && !r[k].is_a?(String) }
      sn = member(r, 'serviceName')
      p << 'resource.serviceName must be printable ASCII up to 32 characters' if !undef?(sn) && !(sn.is_a?(String) && Js.len16(sn) <= 32 && full?(PRINTABLE, sn))
      tags = member(r, 'tags')
      if !undef?(tags) && !(tags.is_a?(Array) && tags.length <= 5 && tags.all? { |t| t.is_a?(String) && Js.len16(t) <= 32 && full?(PRINTABLE, t) })
        p << 'resource.tags must be up to 5 printable ASCII strings of up to 32 characters'
      end
      icon = member(r, 'iconUrl')
      p << 'resource.iconUrl must be an absolute http(s) URL up to 2048 characters' if !undef?(icon) && !(absolute_http?(icon) && Js.len16(icon) <= 2048)
      p
    end

    # Problems with one v2 PaymentRequirements (empty = valid).
    def requirement_v2_problems(q)
      return ['requirements must be an object'] unless obj?(q)

      p = []
      p << 'scheme is required' unless non_empty?(q['scheme'])
      p << 'network must be a CAIP-2 identifier' if !q['network'].is_a?(String) || !full?(CAIP2, q['network'])
      p << 'amount must be a positive decimal string of atomic units' if !q['amount'].is_a?(String) || !full?(ATOMIC, q['amount']) || q['amount'] == '0'
      p << 'asset is required' unless non_empty?(q['asset'])
      p << 'payTo is required' unless non_empty?(q['payTo'])
      t = q['maxTimeoutSeconds']
      p << 'maxTimeoutSeconds must be a positive integer' if !num?(t) || !safe_int?(t) || t <= 0
      p << 'extra must be an object' if q.key?('extra') && !obj?(q['extra'])
      p
    end

    # Problems with a v2 PaymentRequired (empty = valid).
    def payment_required_v2_problems(pr)
      return ['PaymentRequired must be an object'] unless obj?(pr)

      p = []
      v = pr['x402Version']
      p << 'x402Version must be 2' if !num?(v) || v != 2
      p << 'error must be a string' if pr.key?('error') && !pr['error'].is_a?(String)
      p.concat(resource_info_problems(pr['resource']))
      acc = pr['accepts']
      if !acc.is_a?(Array) || acc.empty?
        p << 'accepts must be a non-empty array'
      else
        acc.each_with_index { |q, i| p.concat(requirement_v2_problems(q).map { |m| "accepts[#{i}].#{m}" }) }
      end
      if pr.key?('extensions')
        ex = pr['extensions']
        if obj?(ex)
          Js.js_keys(ex).each do |k|
            v = ex[k]
            p << "extensions.#{k} needs info and schema objects" if !obj?(v) || !obj?(v['info']) || !obj?(v['schema'])
          end
        else
          p << 'extensions must be an object'
        end
      end
      p
    end

    def b64_encode(obj) = [Js.utf8(Js.json(obj))].pack('m0')

    # Decode a header value like Node's Buffer.from(v, 'base64') behind the shape gate, then JSON.parse it.
    def b64_decode(value, name)
      raise TypeError, "x402: #{name} is not base64" if !value.is_a?(String) || !B64_SHAPE.match?(value.b)

      t = value.b.sub(/=+\z/, '')
      t = t[0...-1] if t.length % 4 == 1
      begin
        Js.parse((t + ('=' * (-t.length % 4))).unpack1('m').force_encoding('UTF-8').scrub("�"))
      rescue AtlasPca::Malformed
        raise TypeError, "x402: #{name} is not JSON"
      end
    end

    # Encode a PaymentRequired for the PAYMENT-REQUIRED header (validates first; raises TypeError).
    def encode_payment_required_header(pr)
      problems = payment_required_v2_problems(pr)
      raise TypeError, "x402: #{problems.join('; ')}" unless problems.empty?

      b64_encode(pr)
    end

    # Decode and validate a PAYMENT-REQUIRED header value; raises TypeError on bad base64, bad JSON or an invalid object.
    def decode_payment_required_header(value)
      doc = b64_decode(value, 'PAYMENT-REQUIRED')
      problems = payment_required_v2_problems(doc)
      raise TypeError, "x402: #{problems.join('; ')}" unless problems.empty?

      doc
    end

    # The v2 402 challenge: JSON body plus the base64 PAYMENT-REQUIRED header; refuses anything the v2 spec makes invalid.
    def x402_challenge_v2(resource, opts)
      amount = opt(opts, 'amount')
      raise TypeError, 'x402Challenge: amount must be a positive integer in atomic units' if !num?(amount) || !safe_int?(amount) || amount <= 0

      info = resource.is_a?(String) ? { 'url' => resource } : AgentcardCard.spread(resource)
      req = { 'scheme' => nullish(opt(opts, 'scheme'), 'exact'), 'network' => opt(opts, 'network'), 'amount' => js_num(amount),
              'asset' => opt(opts, 'asset'), 'payTo' => opt(opts, 'pay_to'),
              'maxTimeoutSeconds' => nullish(opt(opts, 'max_timeout_seconds'), 60) }
      req['extra'] = opts['extra'] unless undef?(opt(opts, 'extra'))
      body = { 'x402Version' => 2, 'error' => nullish(opt(opts, 'error'), 'PAYMENT-SIGNATURE header is required'), 'resource' => info,
               'accepts' => [compact(req)] }
      body['extensions'] = opts['extensions'] unless undef?(opt(opts, 'extensions'))
      header = encode_payment_required_header(body)
      { 'status' => 402, 'headers' => { 'Content-Type' => 'application/json', X402_V2_PAYMENT_REQUIRED_HEADER => header }, 'body' => body }
    end

    def includes?(lst, v) = each_item(lst).any? { |x| num?(x) && x == v }

    # The highest x402 version both sides speak, or nil (answer 402 v1 with an error, never guess). offered is what the client
    # says it speaks (UNDEFINED or empty means [1] only; a null raises, as the reference does).
    def x402_negotiate(offered = UNDEFINED, supported = X402_SUPPORTED_VERSIONS)
      mine = each_item(supported).select { |v| num?(v) && [1, 2].include?(v) }
      raise TypeError, "Cannot read properties of null (reading 'length')" if offered.nil?

      theirs = if undef?(offered)
                 [1]
               else
                 raise TypeError, 'offered has no length' unless offered.respond_to?(:length)

                 offered.length.zero? ? [1] : offered
               end
      mine.sort.reverse_each { |v| return v.to_i if includes?(theirs, v) }
      nil
    end

    def stable(v)
      return Js.json(v) unless v.is_a?(Array) || v.is_a?(Hash)
      return "[#{v.map { |x| stable(x) }.join(',')}]" if v.is_a?(Array)

      "{#{v.keys.sort_by { |k| AgentcardCard.u16key(k) }.map { |k| "#{Js.json(k)}:#{stable(v[k])}" }.join(',')}}"
    end

    # True when accepted (echoed by the client in its v2 payload) is exactly one of the requirements the server offered.
    def x402_accepted_matches(offered, accepted)
      return false unless requirement_v2_problems(accepted).empty?

      a = stable(accepted)
      each_item(offered).any? { |o| stable(o) == a }
    end

    # Read a client payload of either version. v1: the token, merchant and amount are top-level members. v2: the token is
    # payload.token and the echoed accepted must be a valid v2 requirement (the merchant is never read from a v2 payload and the
    # amount only from accepted.amount).
    def normalize_x402_payload(raw)
      return { 'ok' => false, 'reason' => 'x402 payment payload is not an object' } unless obj?(raw)

      ver = member(raw, 'x402Version')
      if num?(ver) && ver == 2
        inner = raw['payload']
        unless obj?(inner) && inner['token'].is_a?(String) && !inner['token'].empty?
          return { 'ok' => false, 'reason' => 'x402 v2 payload is missing payload.token' }
        end

        problems = requirement_v2_problems(raw['accepted'])
        return { 'ok' => false, 'reason' => "x402 v2 payload.accepted is invalid: #{problems.join('; ')}" } unless problems.empty?

        accepted = raw['accepted']
        out = { 'ok' => true, 'version' => 2, 'token' => inner['token'], 'accepted' => accepted }
        amount = accepted['amount'].to_f
        out['amount'] = amount.to_i if safe_int?(amount)
        return out
      end
      return { 'ok' => false, 'reason' => "unsupported x402Version #{s(ver)}" } if !undef?(ver) && !(num?(ver) && ver == 1)
      return { 'ok' => false, 'reason' => 'x402 payment payload is missing a token' } unless raw['token'].is_a?(String)

      out = { 'ok' => true, 'version' => 1, 'token' => raw['token'] }
      out['merchant'] = raw['merchant'] if raw['merchant'].is_a?(String)
      out['amount'] = raw['amount'] if num?(raw['amount'])
      out
    end

    # ---- x402 v2 HTTP transport ----

    # Problems with a v2 PaymentPayload (empty = valid).
    def payment_payload_v2_problems(p)
      return ['PaymentPayload must be an object'] unless obj?(p)

      out = []
      v = p['x402Version']
      out << 'x402Version must be 2' if !num?(v) || v != 2
      out.concat(resource_info_problems(p['resource'])) if p.key?('resource')
      out.concat(requirement_v2_problems(p['accepted']).map { |m| "accepted.#{m}" })
      out << 'payload must be an object' unless obj?(p['payload'])
      out << 'extensions must be an object' if p.key?('extensions') && !obj?(p['extensions'])
      out
    end

    # Problems with a SettlementResponse (empty = valid). A success must not carry an errorReason; a failure must.
    def settlement_response_problems(r)
      return ['SettlementResponse must be an object'] unless obj?(r)

      out = []
      success = member(r, 'success')
      tx = member(r, 'transaction')
      net = member(r, 'network')
      er = member(r, 'errorReason')
      out << 'success must be a boolean' unless [true, false].include?(success)
      if !tx.is_a?(String)
        out << 'transaction must be a string'
      elsif success == true && tx.empty?
        out << 'a successful settlement needs a transaction'
      end
      out << 'network must be a CAIP-2 identifier' if !net.is_a?(String) || !full?(CAIP2, net)
      out << 'errorReason must be a string' if !undef?(er) && !er.is_a?(String)
      out << 'errorReason must be omitted on success' if success == true && !undef?(er)
      out << 'errorReason is required on failure' if success == false && !non_empty?(er)
      out << 'payer must be a string' if r.key?('payer') && !r['payer'].is_a?(String)
      out << 'amount must be a decimal string of atomic units' if r.key?('amount') && !(r['amount'].is_a?(String) && full?(ATOMIC, r['amount']))
      out << 'extensions must be an object' if r.key?('extensions') && !obj?(r['extensions'])
      out
    end

    def encode_header(obj, problems)
      raise TypeError, "x402: #{problems.join('; ')}" unless problems.empty?

      b64_encode(obj)
    end

    # Encode a PaymentPayload for the PAYMENT-SIGNATURE request header (validates first; raises TypeError).
    def encode_payment_signature_header(p) = encode_header(p, payment_payload_v2_problems(p))

    # Decode and validate a PAYMENT-SIGNATURE header value; raises TypeError on bad base64, bad JSON or an invalid object.
    def decode_payment_signature_header(value)
      doc = b64_decode(value, 'PAYMENT-SIGNATURE')
      problems = payment_payload_v2_problems(doc)
      raise TypeError, "x402: #{problems.join('; ')}" unless problems.empty?

      doc
    end

    # Encode a SettlementResponse for the PAYMENT-RESPONSE response header.
    def encode_payment_response_header(r) = encode_header(r, settlement_response_problems(r))

    def decode_payment_response_header(value)
      doc = b64_decode(value, 'PAYMENT-RESPONSE')
      problems = settlement_response_problems(doc)
      raise TypeError, "x402: #{problems.join('; ')}" unless problems.empty?

      doc
    end

    # Server side: read the client's PAYMENT-SIGNATURE header (case-insensitive, first value of a list). A missing header is 402
    # (answer with a PAYMENT-REQUIRED challenge); a present but undecodable or invalid one is 400. Never raises.
    def read_payment_signature(headers)
      v = UNDEFINED
      headers.each do |k, val|
        next unless lower(k) == X402_PAYMENT_SIGNATURE_HEADER.downcase

        v = val.is_a?(Array) ? (val.empty? ? UNDEFINED : val[0]) : val
        break
      end
      if undef?(v) || v == ''
        return { 'ok' => false, 'status' => X402_HTTP_STATUS['payment_required'], 'reason' => 'PAYMENT-SIGNATURE header is required' }
      end

      begin
        { 'ok' => true, 'payload' => decode_payment_signature_header(v) }
      rescue StandardError => e # never raises: any failure is a malformed header
        { 'ok' => false, 'status' => X402_HTTP_STATUS['malformed'], 'reason' => e.message }
      end
    end

    # Server side: the status and PAYMENT-RESPONSE header for a settlement outcome (a success is 200 and needs the transaction; a
    # failure is 402 with success false, the reason and an empty transaction unless one was broadcast). Raises TypeError if the
    # response would be invalid.
    def x402_settlement_response(outcome, network)
      raise TypeError, 'outcome is not an object' unless outcome.is_a?(Hash)

      if truthy(outcome.key?('settled') ? outcome['settled'] : nil)
        body = { 'success' => true, 'transaction' => member(outcome, 'transaction'), 'network' => network }
        %w[payer amount].each { |k| body[k] = outcome[k] if outcome.key?(k) }
      else
        tx = member(outcome, 'transaction')
        body = { 'success' => false, 'errorReason' => member(outcome, 'reason'), 'transaction' => tx.nil? || undef?(tx) ? '' : tx,
                 'network' => network }
        body['payer'] = outcome['payer'] if outcome.key?('payer')
      end
      body = compact(body)
      settled = truthy(outcome['settled'])
      { 'status' => settled ? X402_HTTP_STATUS['settled'] : X402_HTTP_STATUS['failed'],
        'headers' => { X402_PAYMENT_RESPONSE_HEADER => encode_payment_response_header(body) } }
    end

    # Client side: the request header to attach on the retry, from a payload built for an offered requirement.
    def x402_payment_signature_headers(p) = { X402_PAYMENT_SIGNATURE_HEADER => encode_payment_signature_header(p) }

    # ---- Stripe Shared Payment Granted Tokens ----

    SPT_REASONS = %w[consumed expired resolved revoked].freeze
    SPT_ID = /\Aspt_[A-Za-z0-9_]+\z/n
    LOWER3 = /\A[a-z]{3}\z/n

    def currency3?(v) = v.is_a?(String) && full?(LOWER3, v)

    # Problems with a Shared Payment Granted Token object (empty = well formed).
    def stripe_spt_problems(t)
      return ['the token must be an object'] unless obj?(t)

      p = []
      p << "object must be \"#{STRIPE_SPT_OBJECT}\"" if t['object'] != STRIPE_SPT_OBJECT
      p << 'id must be an spt_ identifier' if !t['id'].is_a?(String) || !full?(SPT_ID, t['id'])
      p << 'created must be an integer timestamp' unless int?(t['created'])
      p << 'livemode must be a boolean' unless [true, false].include?(t['livemode'])
      da = member(t, 'deactivated_at')
      p << 'deactivated_at must be null or an integer timestamp' if !da.nil? && !int?(da)
      dr = member(t, 'deactivated_reason')
      p << 'deactivated_reason must be null or one of consumed, expired, resolved, revoked' if !dr.nil? && !(dr.is_a?(String) && SPT_REASONS.include?(dr))
      u = t['usage_limits']
      if obj?(u)
        p << 'usage_limits.currency must be a lowercase three-letter code' unless currency3?(u['currency'])
        p << 'usage_limits.max_amount must be a non-negative integer in minor units' if !int?(u['max_amount']) || u['max_amount'].negative?
        ea = u['expires_at']
        p << 'usage_limits.expires_at must be an integer timestamp' if !ea.nil? && !int?(ea)
      else
        p << 'usage_limits is required'
      end
      ud = t['usage_details']
      unless ud.nil?
        c = obj?(ud) ? ud['amount_captured'] : nil
        if !obj?(c) || !int?(c['value']) || c['value'].negative? || !currency3?(c['currency'])
          p << 'usage_details.amount_captured needs a non-negative integer value and a lowercase currency'
        end
      end
      %w[payment_method_details agent_details shared_metadata].each do |k|
        p << "#{k} must be null or an object" if !t[k].nil? && !obj?(t[k])
      end
      pmd = t['payment_method_details']
      p << 'payment_method_details.type must be a string' if obj?(pmd) && !pmd['type'].is_a?(String)
      p
    end

    # Parse a Shared Payment Granted Token; raises TypeError listing every problem.
    def parse_stripe_spt(t)
      problems = stripe_spt_problems(t)
      raise TypeError, "stripe spt: #{problems.join('; ')}" unless problems.empty?

      t
    end

    # Can this token still be used for this capture? Refuses a malformed token, a deactivated or expired one, the wrong mode, a
    # different currency, a non-integer amount and one above max_amount minus what was already captured.
    def stripe_spt_usable(t, use)
      problems = stripe_spt_problems(t)
      return { 'ok' => false, 'reason' => "malformed token: #{problems[0]}" } unless problems.empty?

      now = get(use, 'now')
      amount = get(use, 'amount')
      if !int?(now) || !int?(amount) || amount <= 0
        return { 'ok' => false, 'reason' => 'now and amount must be integers and the amount positive' }
      end

      lm = nullish(member(use, 'livemode'), true)
      return { 'ok' => false, 'reason' => 'the token is in the wrong mode' } if ![true, false].include?(lm) || lm != t['livemode']
      return { 'ok' => false, 'reason' => "the token is deactivated (#{t['deactivated_reason']})" } unless t['deactivated_reason'].nil?
      return { 'ok' => false, 'reason' => 'the token is deactivated' } if !t['deactivated_at'].nil? && t['deactivated_at'] <= now

      lim = t['usage_limits']
      return { 'ok' => false, 'reason' => 'the token has expired' } if num?(lim['expires_at']) && now >= lim['expires_at']

      cur = use['currency']
      return { 'ok' => false, 'reason' => 'the capture currency differs from the token currency' } if lim['currency'] != lower(cur)

      captured = obj?(t['usage_details']) ? t['usage_details']['amount_captured'] : nil
      if !captured.nil? && captured['currency'] != lim['currency']
        return { 'ok' => false, 'reason' => 'the captured amount is in another currency' }
      end

      remaining = lim['max_amount'] - (captured.nil? ? 0 : captured['value'])
      if amount > remaining
        return { 'ok' => false, 'reason' => "the amount #{js_num(amount)} exceeds the remaining #{js_num(remaining)}" }
      end

      { 'ok' => true }
    end

    # The usage_limits to request for a PCA authority: lowercase currency, integer minor units, expiry in whole seconds (rounded
    # down). Raises TypeError on anything invalid.
    def stripe_usage_limits_for(authority)
      ma = get(authority, 'maxAmount')
      cur = authority['currency']
      exp = member(authority, 'expiresAtMs')
      raise TypeError, 'stripe spt: maxAmount must be a positive integer in minor units' if !int?(ma) || ma <= 0
      raise TypeError, 'stripe spt: currency must be a three-letter code' if !cur.is_a?(String) || !full?(/\A[A-Za-z]{3}\z/n, cur)
      raise TypeError, 'stripe spt: expiresAtMs must be a positive epoch-ms time' if !undef?(exp) && !(finite?(exp) && exp.positive?)

      out = { 'currency' => cur.downcase, 'max_amount' => ma }
      out['expires_at'] = (exp.to_f / 1000).floor unless undef?(exp)
      out
    end

    # A Shared Payment Token may be no wider than the delegated payment token (and so the PCA proof) it serves: same currency,
    # max_amount not above the delegated amount, and an expiry present and not after the delegated token's.
    def stripe_spt_within_claims(t, claims)
      problems = stripe_spt_problems(t)
      return { 'ok' => false, 'reason' => "malformed token: #{problems[0]}" } unless problems.empty?

      lim = t['usage_limits']
      amount = get(claims, 'amount')
      exp = get(claims, 'exp')
      if lim['currency'] != lower(get(claims, 'currency'))
        return { 'ok' => false, 'reason' => 'the token currency differs from the delegated currency' }
      end
      if !(finite?(amount) && le(lim['max_amount'], amount))
        return { 'ok' => false, 'reason' => "max_amount #{js_num(lim['max_amount'])} exceeds the delegated amount #{s(amount)}" }
      end
      return { 'ok' => false, 'reason' => 'the token has no expiry' } unless num?(lim['expires_at'])
      return { 'ok' => false, 'reason' => 'the token outlives the delegated payment token' } if !(finite?(exp) && le(lim['expires_at'] * 1000, exp))

      { 'ok' => true }
    end
  end
end
