# frozen_string_literal: true

# Explainable reputation over observed outcomes and the signed coverage quote (the reference's `reputation` and
# `reputation-evidence` modules; price_coverage and the insurance pool are in bond_pool.rb). A reputation is derived only from
# what happened: the outcomes of a subject's actions and its disputes, de-duplicated by id. Unusable input is the lowest score,
# never the neutral "unproven" one. disputes_from_settlements takes disputes only from guardian-signed settlement records, so a
# subject cannot be given a dispute nobody adjudicated. Advisory: never an authorization.
module AtlasPca
  MAX_REPUTATION_RECORDS = 100_000
  COVERAGE_QUOTE_DOMAIN = "atlas-pca/coverage-quote/v1\0"
  REPUTATION_OUTCOMES = %w[auto step_up deny executed].freeze

  module_function

  # nil when a reputation input ({'subject', 'events'?, 'disputes'?}) is usable, else the reason.
  def validate_reputation_input(input)
    subject = input.is_a?(Hash) ? input['subject'] : nil
    return 'subject must be a non-empty string' unless subject.is_a?(String) && !subject.empty?

    events = input.key?('events') ? input['events'] : []
    disputes = input.key?('disputes') ? input['disputes'] : []
    return 'events and disputes must be arrays' unless events.is_a?(Array) && disputes.is_a?(Array)
    return 'too many records' if events.length > MAX_REPUTATION_RECORDS || disputes.length > MAX_REPUTATION_RECORDS
    return 'event with an unknown outcome' if events.any? { |e| !(e.is_a?(Hash) && REPUTATION_OUTCOMES.include?(e['outcome'])) }

    disputes.each do |d|
      return 'dispute without an id' unless d.is_a?(Hash) && d['id'].is_a?(String) && !d['id'].empty?
      return 'dispute for another subject' unless d['subject'] == subject
      return 'dispute.slashed must be a boolean' unless [true, false].include?(d['slashed'])
      return 'dispute.at must be finite and >= 0' unless Risk.fin?(d['at']) && d['at'] >= 0
      return 'dispute.amount must be finite and >= 0' if d.key?('amount') && !(Risk.fin?(d['amount']) && d['amount'] >= 0)
    end
    nil
  end

  # The reputation of a subject: {'subject', 'actions', 'autos', 'stepUps', 'denies', 'slashes', 'disputes', 'score' in [0, 1],
  # 'factors'}. No history is 0.5 ("unproven"); denials, step-ups and slashed disputes lower a clean 1; an invalid input is 0
  # with the factor "invalid input: <reason>". Never raises.
  def reputation(input)
    bad = validate_reputation_input(input)
    counts = { 'actions' => 0, 'autos' => 0, 'stepUps' => 0, 'denies' => 0, 'slashes' => 0, 'disputes' => 0 }
    if bad
      subject = input.is_a?(Hash) ? input['subject'] : nil
      subject = subject.nil? ? '' : Predicates.js_string(subject)
      return { 'subject' => subject }.merge(counts, 'score' => 0, 'factors' => ["invalid input: #{bad}"])
    end
    events = input['events'] || []
    disputes = (input['disputes'] || []).uniq { |d| d['id'] }
    actions = events.length
    outcome = ->(o) { events.count { |e| e['outcome'] == o } }
    step_ups = outcome.call('step_up')
    denies = outcome.call('deny')
    slashes = disputes.count { |d| d['slashed'] }
    out = { 'subject' => input['subject'], 'actions' => actions, 'autos' => outcome.call('auto'), 'stepUps' => step_ups, 'denies' => denies,
            'slashes' => slashes, 'disputes' => disputes.length }
    return out.merge('score' => 0.5, 'factors' => ['unproven (no history)']) if actions.zero? && disputes.empty?

    score = 1
    factors = []
    if actions.positive?
      deny_rate = denies.to_f / actions
      step_up_rate = step_ups.to_f / actions
      if deny_rate.positive?
        score -= 0.6 * deny_rate
        factors << "deny rate #{AnalyzerJs.to_fixed(deny_rate * 100, 0)}%"
      end
      if step_up_rate.positive?
        score -= 0.15 * step_up_rate
        factors << "step-up rate #{AnalyzerJs.to_fixed(step_up_rate * 100, 0)}%"
      end
    end
    # slashes dominate: each one is a heavy penalty, saturating at 0.8
    if slashes.positive?
      score -= [0.8, 0.3 * slashes].min
      factors << "#{slashes} slashed dispute#{slashes > 1 ? 's' : ''}"
    end
    factors << 'clean history' if factors.empty?
    out.merge('score' => [0, [1, score].min].max, 'factors' => factors)
  end

  def coverage_quote_message(claim) = COVERAGE_QUOTE_DOMAIN.b + canonical_bytes_lenient(claim)

  def reputation_score?(score) = Risk.fin?(score) && score >= 0 && score <= 1

  # A coverage quote signed by the underwriter (a KeyPair): the price of covering `exposure` for the subject of `rep` (a
  # reputation), valid from `now` for `ttl_ms`. `opts`: the pricing options of price_coverage. Raises ArgumentError unless the
  # exposure is finite and >= 0, now and ttl_ms are finite with ttl_ms > 0, and the score is in [0, 1].
  def issue_coverage_quote(rep, exposure, underwriter, now:, ttl_ms:, opts: nil)
    raise ArgumentError, 'issueCoverageQuote: exposure must be finite and >= 0' unless Risk.fin?(exposure) && exposure >= 0
    raise ArgumentError, 'issueCoverageQuote: now and ttlMs must be finite, ttlMs > 0' unless Risk.fin?(now) && Risk.fin?(ttl_ms) && ttl_ms.positive?
    raise ArgumentError, 'issueCoverageQuote: invalid reputation score' unless reputation_score?(rep['score'])

    opts = {} unless opts.is_a?(Hash)
    base_rate = opts['baseRate'].nil? ? 0.01 : opts['baseRate']
    risk_load = opts['riskLoad'].nil? ? 4 : opts['riskLoad']
    min_score = opts['minScore'].nil? ? 0.25 : opts['minScore']
    p = price_coverage(rep, exposure, { 'baseRate' => base_rate, 'riskLoad' => risk_load, 'minScore' => min_score })
    # an absent subject is `undefined` in the reference, which the canonicalizer refuses
    raise TypeError, 'canonicalize: unsupported type undefined' unless rep.key?('subject')

    claim = { 'v' => 1, 'subject' => rep['subject'], 'score' => rep['score'], 'exposure' => exposure, 'baseRate' => base_rate, 'riskLoad' => risk_load,
              'minScore' => min_score, 'declined' => p['declined'], 'premium' => p['premium'], 'coverage' => p['coverage'], 'issued_at' => now,
              'expires_at' => now + ttl_ms, 'underwriter' => underwriter.public }
    claim.merge('sig' => b64e(underwriter.sign(coverage_quote_message(claim))))
  end

  # Verify a coverage quote under the pinned `underwriter` key at `now`: shape, the underwriter, the signature, the validity
  # window, and the price recomputed from the quote's own terms. {'ok' => true} or {'ok' => false, 'reason' => 'malformed' |
  # 'underwriter' | 'signature' | 'not-yet-valid' | 'expired' | 'price-mismatch'}. Never raises.
  def verify_coverage_quote(quote, underwriter:, now:)
    no = ->(reason) { { 'ok' => false, 'reason' => reason } }
    return no.call('malformed') unless quote.is_a?(Hash) && quote['v'].is_a?(Numeric) && quote['v'] == 1 && quote['sig'].is_a?(String)

    numbers = %w[score exposure baseRate riskLoad minScore premium coverage issued_at expires_at]
    unless numbers.all? { |k| Risk.fin?(quote[k]) } && [true, false].include?(quote['declined']) && quote['subject'].is_a?(String)
      return no.call('malformed')
    end
    return no.call('underwriter') unless underwriter.is_a?(String) && underwriter == quote['underwriter']
    return no.call('signature') unless verify_b64u(quote['underwriter'], coverage_quote_message(quote.reject { |k, _| k == 'sig' }), quote['sig'])
    return no.call('not-yet-valid') unless Risk.fin?(now) && now >= quote['issued_at']
    return no.call('expired') if now >= quote['expires_at']

    p = price_coverage({ 'score' => quote['score'] }, quote['exposure'],
                       { 'baseRate' => quote['baseRate'], 'riskLoad' => quote['riskLoad'], 'minScore' => quote['minScore'] })
    same = p['declined'] == quote['declined'] && p['premium'] == quote['premium'] && p['coverage'] == quote['coverage']
    same ? { 'ok' => true } : no.call('price-mismatch')
  rescue StandardError
    { 'ok' => false, 'reason' => 'malformed' }
  end

  # The disputes of a set of settlement records: only a record that verifies under the guardian key (`pins`: the PQ pins of
  # verify_settlement) and whose bond has a known subject counts; an open bond is not an outcome. `subject_of` answers a claim id
  # with its subject or nil (a callable, or a Hash). {'disputes' => [{'id', 'subject', 'slashed', 'at', 'amount'}], 'rejected'}.
  def disputes_from_settlements(records, guardian_public, subject_of, pins = nil)
    lookup = subject_of.is_a?(Hash) ? ->(id) { subject_of[id] } : subject_of
    disputes = []
    rejected = 0
    records.each do |r|
      subject = r.is_a?(Hash) && r['claimId'].is_a?(String) ? lookup.call(r['claimId']) : nil
      if subject.nil? || !BondSettlement.verify_settlement(r, guardian_public, pins)
        rejected += 1
        next
      end
      next if r['action'] == 'open'

      d = { 'id' => BondSettlement.settlement_record_digest(r), 'subject' => subject, 'slashed' => r['action'] == 'slash', 'at' => r['at'] }
      d['amount'] = r['amount'] if r.key?('amount')
      disputes << d
    end
    { 'disputes' => disputes, 'rejected' => rejected }
  end
end
