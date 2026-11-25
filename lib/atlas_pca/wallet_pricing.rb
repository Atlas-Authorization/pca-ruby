# frozen_string_literal: true

require_relative 'wallet'

# Risk-priced escalation of the wallet: ask a human iff pBadUpper * loss > interruptionCost, in integer arithmetic (probabilities in
# ppm, money in minor units; no floats, no randomness, no clock). Every input is explicit and comes from a principal-SIGNED
# configuration; anything missing, out of range or unsigned means ASK. The only learned component is a per-principal multiplier that
# scales P(bad) UP, so it can only add asks; asking less needs a principal-signed autonomy raise. Native port of the TypeScript
# reference (@atlasauth/pca-wallet, escalation-pricing). Signing takes the principal's AtlasPca::KeyPair.
module AtlasPca
  module WalletPricing
    W = Wallet
    UNDEF = Wallet::UNDEF
    PPM = 1_000_000
    MAX_MULTIPLIER_PPM = 100 * PPM

    module_function

    def minor?(n) = W.safe_int?(n) && n >= 0
    def one?(v) = W.number?(v) && v == 1
    def msg(kind, body) = AtlasPca.hash_canonical({ 'kind' => kind, 'body' => body }).b

    def sig_of(key, kind, body) = AtlasPca.b64e(key.sign(msg(kind, body)))

    def unb64u(s) = (s.is_a?(String) ? AtlasPca.b64d(s) : nil) || raise(ArgumentError, 'bad base64url')

    def check(principal, kind, body, sig)
      pk = unb64u(principal)
      sg = unb64u(sig)
      return false unless pk.bytesize == 32 && sg.bytesize == 64

      AtlasPca::Ed25519Strict.verify(pk, msg(kind, body), sg)
    rescue ArgumentError, TypeError
      raise
    rescue StandardError
      false
    end

    def sign_pricing_config(body, key) = body.merge('sig' => sig_of(key, 'pca.escalation_pricing', body))

    # Why a signed pricing configuration is refused, or nil (a pure function of its content).
    def pricing_config_error(c)
      return 'config_malformed' unless c.is_a?(Hash)

      x = c
      return 'config_malformed' if !one?(x['v']) || !x['principal'].is_a?(String) || !x['currency'].is_a?(String) || !x['sig'].is_a?(String)
      unless minor?(x['interruptionCost']) && minor?(x['maxInterruptionCost']) && minor?(x['hardCeilingLoss']) && minor?(x['epoch'])
        return 'config_amounts_invalid'
      end
      return 'config_cost_above_max' if x['interruptionCost'] > x['maxInterruptionCost']

      step = x['tightenStepPpm']
      return 'config_step_invalid' if !W.safe_int?(step) || step.negative? || step > MAX_MULTIPLIER_PPM

      body = x.reject { |k, _| k == 'sig' }
      check(x['principal'], 'pca.escalation_pricing', body, x['sig']) ? nil : 'config_signature_invalid'
    rescue StandardError # any decoding or hashing failure is a malformed configuration
      'config_malformed'
    end

    def fresh_calibration = { 'multiplierPpm' => PPM, 'seen' => [] }

    # Pure and total: {ask, reason}. Anything unverifiable or out of range asks.
    def decide_escalation(config, cal, a)
      e = pricing_config_error(config)
      return { 'ask' => true, 'reason' => e } unless e.nil?
      return { 'ask' => true, 'reason' => 'currency_mismatch' } if !a.is_a?(Hash) || a['currency'] != config['currency']

      loss = a['loss']
      p = a['pBadUpperPpm']
      if !minor?(loss) || W.neg_zero?(loss) || !W.safe_int?(p) || p.negative? || W.neg_zero?(p) || p > PPM
        return { 'ask' => true, 'reason' => 'risk_input_invalid' }
      end

      mult = cal.is_a?(Hash) ? cal['multiplierPpm'] : nil
      return { 'ask' => true, 'reason' => 'calibration_invalid' } unless W.safe_int?(mult) && mult >= PPM && mult <= MAX_MULTIPLIER_PPM
      return { 'ask' => true, 'reason' => 'above_hard_ceiling' } if loss > config['hardCeilingLoss']

      pe = p.to_i * mult.to_i
      capped = pe > PPM * PPM ? PPM * PPM : pe
      lhs = capped * loss.to_i
      rhs = config['interruptionCost'].to_i * PPM * PPM
      return { 'ask' => true, 'reason' => 'expected_loss_exceeds_interruption_cost' } if lhs > rhs

      { 'ask' => false, 'reason' => 'expected_loss_within_interruption_cost' }
    end

    def sign_answer(body, key) = body.merge('sig' => sig_of(key, 'pca.escalation_answer', body))

    def answer_ok?(a, principal)
      return false if !a.is_a?(Hash) || !one?(a['v']) || a['principal'] != principal

      nonce = a['nonce']
      ad = a['action_digest']
      return false if !nonce.is_a?(String) || IntentOmega.u16len(nonce) < 8 || !ad.is_a?(String) || !%w[approve deny].include?(a['answer'])

      check(principal, 'pca.escalation_answer', a.reject { |k, _| k == 'sig' }, a['sig'])
    rescue StandardError
      false
    end

    # Fold signed answers into the calibration. A DENY the principal gave to an action that the CURRENT pricing would have
    # auto-approved is a miss and adds tightenStepPpm (capped); anything else changes nothing. The multiplier never decreases.
    def update_calibration(config, cal, answers, risks)
      return cal unless pricing_config_error(config).nil?

      mult = cal['multiplierPpm']
      seen = cal['seen'].to_set
      order = cal['seen'].dup
      answers.each do |a|
        next if !answer_ok?(a, config['principal']) || seen.include?(a['nonce'])

        seen << a['nonce']
        order << a['nonce']
        risk = risks.key?(a['action_digest']) ? risks[a['action_digest']] : UNDEF
        next if a['answer'] != 'deny' || risk.equal?(UNDEF)

        mult = [MAX_MULTIPLIER_PPM, mult + config['tightenStepPpm']].min unless decide_escalation(config, { 'multiplierPpm' => mult, 'seen' => [] }, risk)['ask']
      end
      { 'multiplierPpm' => [mult, cal['multiplierPpm']].max, 'seen' => order }
    end

    def sign_autonomy_raise(b, key) = b.merge('sig' => sig_of(key, 'pca.autonomy_raise', b))

    # A higher interruption cost means fewer asks. Needs the principal's signature, a strictly newer epoch and a cost within
    # maxInterruptionCost; raises ArgumentError otherwise.
    def apply_autonomy_raise(config, raise_, key)
      ok = begin
        b = raise_.reject { |k, _| k == 'sig' }
        one?(raise_['v']) && raise_['principal'] == config['principal'] && check(config['principal'], 'pca.autonomy_raise', b, raise_['sig'])
      rescue StandardError
        false
      end
      raise ArgumentError, 'applyAutonomyRaise: signature or principal invalid' unless ok
      raise ArgumentError, 'applyAutonomyRaise: epoch must advance' unless raise_['epoch'] > config['epoch']

      cost = raise_['newInterruptionCost']
      raise ArgumentError, 'applyAutonomyRaise: above the configured maximum' if !minor?(cost) || cost > config['maxInterruptionCost']

      body = config.reject { |k, _| k == 'sig' }
      body['interruptionCost'] = cost
      body['epoch'] = raise_['epoch']
      sign_pricing_config(body, key)
    end
  end
end
