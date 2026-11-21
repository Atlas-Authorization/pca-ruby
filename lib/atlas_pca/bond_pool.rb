# frozen_string_literal: true

# Bond settlement leftovers: anchoring a signed settlement record in the transparency ledger as a salted commitment, the check of
# that commitment, the coverage pricing curve, and the finite insurance capital pool that funds victim compensation.
require 'securerandom'

module AtlasPca
  module_function

  # True iff salt + record reproduce the anchored commit. Never raises (it is part of an external audit).
  def verify_settlement_commit(commit, salt, record)
    BondSettlement.settlement_commit(salt, record) == commit
  rescue StandardError, SystemStackError
    false
  end

  # Appends a settlement record into a TransparencyLedger as a salted commitment: {'index', 'commit', 'salt'}. The salt defaults to
  # 16 random bytes; pass `salt` for deterministic output. The caller keeps {record, salt} as the off-log opening.
  def append_settlement(ledger, record, salt: nil)
    salt = b64e(SecureRandom.random_bytes(16)) if salt.nil?
    commit = BondSettlement.settlement_commit(salt, record)
    { 'index' => ledger.append_commitment(commit)['index'], 'commit' => commit, 'salt' => salt }
  end

  # Prices coverage of `exposure` for a subject with reputation `rep` ({'score' => 0..1}): premium = baseRate * exposure *
  # (1 + riskLoad * (1 - score)), declined below minScore. `opts`: {'baseRate' (0.01), 'riskLoad' (4), 'minScore' (0.25)}. A
  # score outside [0, 1] is declined; an exposure that is not a finite number prices as 0. Advisory: never an authorization.
  # {'declined', 'premium', 'coverage', 'rationale'}.
  def price_coverage(rep, exposure, opts = nil)
    opts = {} unless opts.is_a?(Hash)
    base_rate = opts['baseRate'].nil? ? 0.01 : opts['baseRate']
    risk_load = opts['riskLoad'].nil? ? 4 : opts['riskLoad']
    min_score = opts['minScore'].nil? ? 0.25 : opts['minScore']
    score = rep.is_a?(Hash) ? rep['score'] : nil
    unless Risk.fin?(score) && score >= 0 && score <= 1
      return { 'declined' => true, 'premium' => 0, 'coverage' => 0, 'rationale' => 'invalid reputation score' }
    end

    num = ->(x) { Predicates.js_number_string(x) }
    fix = ->(x) { AnalyzerJs.to_fixed(x, 2) }
    exp = Risk.fin?(exposure) ? [0, exposure].max : 0
    if score < min_score
      return { 'declined' => true, 'premium' => 0, 'coverage' => 0,
               'rationale' => "reputation #{fix.call(score)} below underwriting floor #{num.call(min_score)}" }
    end

    load = 1 + (risk_load * (1 - score))
    { 'declined' => false, 'premium' => base_rate * exp * load, 'coverage' => exp,
      'rationale' => "base #{num.call(base_rate)} × exposure #{num.call(exp)} × load #{fix.call(load)} (score #{fix.call(score)})" }
  end

  # A finite, fail-closed insurance capital pool. Premiums (priced by AtlasPca.price_coverage) are credited; victim payouts are
  # debited and REFUSED when they exceed the free capital, so the pool never pays what it does not hold. The three ledgers (initial,
  # premiums in, payouts out) always reconcile to the balance.
  class InsuranceCapitalPool
    attr_reader :premiums_in, :payouts_out

    def initialize(initial = 0)
      ok = (initial.is_a?(Integer) || (initial.is_a?(Float) && initial.finite?)) && initial >= 0
      raise ArgumentError, 'InsuranceCapitalPool: initial capital must be a non-negative finite number' unless ok

      @initial = initial
      @premiums_in = 0
      @payouts_out = 0
    end

    def balance = @initial + @premiums_in - @payouts_out

    # {'initial', 'premiumsIn', 'payoutsOut', 'balance'}
    def state = { 'initial' => @initial, 'premiumsIn' => @premiums_in, 'payoutsOut' => @payouts_out, 'balance' => balance }

    # Prices coverage of `exposure` for `rep` WITHOUT touching the pool.
    def quote(rep, exposure, opts = nil) = AtlasPca.price_coverage(rep, exposure, opts)

    # Prices coverage and, unless declined, credits the premium: {'pricing', 'state'}.
    def collect_premium(rep, exposure, opts = nil)
      pricing = quote(rep, exposure, opts)
      premium = pricing['premium']
      if !pricing['declined'] && premium.is_a?(Numeric) && !(premium.is_a?(Float) && premium.nan?) && premium.positive?
        unless (premium.is_a?(Integer) || (premium.is_a?(Float) && premium.finite?)) && premium >= 0
          raise ArgumentError, 'collectPremium: priced premium is not a non-negative finite number'
        end

        @premiums_in += premium
      end
      { 'pricing' => pricing, 'state' => state }
    end

    # True iff the pool holds at least `amount` of free capital.
    def can_cover?(amount)
      (amount.is_a?(Integer) || (amount.is_a?(Float) && amount.finite?)) && amount >= 0 && balance >= amount
    end

    # Pays `amount` of victim compensation out of the pool. Raises when it is not a positive finite number or exceeds the capital.
    def pay_claim(amount)
      raise ArgumentError, 'payClaim: amount must be a positive finite number' unless (amount.is_a?(Integer) || (amount.is_a?(Float) && amount.finite?)) && amount.positive?
      if amount > balance
        js = Predicates.method(:js_number_string)
        raise ArgumentError, "payClaim: insufficient pool capital (need #{js.call(amount)}, have #{js.call(balance)})"
      end

      @payouts_out += amount
      state
    end
  end
end
