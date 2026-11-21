# frozen_string_literal: true

# Forbid-wins certificate check (security contract C-241). Port of `certificateConsistent` in
# packages/pca/src/forbid-certificate.ts (the TypeScript is authoritative).
#
# A certificate lists, per policy clause, whether it matched ('true' / 'unknown' / 'false'). The decision, the winner and the
# shadowed list follow from that table alone: any matched forbid denies (the most authoritative signer is named, ties by id);
# otherwise no matched permit denies; otherwise a matched escalate clause escalates; otherwise allow. No predicate evaluator
# is needed. Total: any malformed certificate is not consistent (never raises).
module AtlasPca
  FORBID_CERT_KINDS = %w[permit forbid escalate].freeze
  FORBID_CERT_VALUES = %w[true false unknown].freeze

  FORBID_CERT_VERSION = 1
  FORBID_CERT_KIND = 'forbid-wins'
  MAX_CLAUSES = 512

  module_function

  def forbid_certificate_consistent?(cert, precedence = [])
    return false unless cert.is_a?(Hash) && cert['v'] == 1 && cert['kind'] == 'forbid-wins' && cert['clauses'].is_a?(Array)

    rows = cert['clauses']
    winner = cert['winner']
    shadowed = cert['shadowed']
    return false unless winner.is_a?(Hash) && shadowed.is_a?(Array)
    return rows.empty? && cert['decision'] == 'deny' && winner['id'].nil? && shadowed.empty? if winner['kind'] == 'malformed'

    prec = Array(precedence)
    ok = rows.all? do |r|
      r.is_a?(Hash) && r['id'].is_a?(String) && FORBID_CERT_KINDS.include?(r['kind']) && FORBID_CERT_VALUES.include?(r['value'])
    end
    return false unless ok

    rank = ->(r) { prec.index(r['signer']) || prec.length } # an unlisted (or absent) signer ranks last
    hit = ->(kind) { rows.select { |r| r['kind'] == kind && r['value'] != 'false' } }
    forbids = hit.call('forbid').sort_by { |r| [rank.call(r), utf16_key(r['id'])] }
    permits = hit.call('permit')
    escalates = hit.call('escalate')
    if forbids.any? then win, decision, kind = forbids[0], 'deny', 'forbid'
    elsif permits.empty? then win, decision, kind = nil, 'deny', 'none'
    elsif escalates.any? then win, decision, kind = escalates[0], 'escalate', 'escalate'
    else win, decision, kind = permits[0], 'allow', 'permit'
    end
    others = (forbids + permits + escalates).reject { |r| r.equal?(win) }.map { |r| r['id'] }
    cert['decision'] == decision && winner['kind'] == kind && winner['id'] == win&.fetch('id') && shadowed == others
  rescue StandardError
    false # a certificate that cannot be read is not consistent
  end

  # ---- the decision witness and the certificate (port of decideClauses / certify / checkForbidCertificate) ----

  # Nil = the clause list is well formed (distinct ids, known kinds, a predicate for each); else the exact reason.
  def clauses_error(clauses)
    return 'clauses must be an array' unless clauses.is_a?(Array)
    return "more than #{MAX_CLAUSES} clauses" if clauses.length > MAX_CLAUSES

    seen = {}
    clauses.each_with_index do |c, i|
      return "clauses[#{i}] must be an object" unless c.is_a?(Hash)

      id = c['id']
      return "clauses[#{i}].id must be a string of 1..128 characters" if !id.is_a?(String) || id.empty? || Prohibitions.jlen(id) > 128
      return "clauses[#{i}].id '#{id}' is a duplicate" if seen.key?(id)

      seen[id] = true
      return "clauses[#{i}].kind must be permit, forbid or escalate" if !c['kind'].is_a?(String) || !FORBID_CERT_KINDS.include?(c['kind'])
      if c.key?('signer') && (!c['signer'].is_a?(String) || Prohibitions.jlen(c['signer']) > 256)
        return "clauses[#{i}].signer must be a string of at most 256 characters"
      end
      return "clauses[#{i}].when must be a predicate object" unless c['when'].is_a?(Hash)
    end
    nil
  end

  # Permit: plain DSL ('true' | 'false'). Forbid / escalate: veto polarity (clean match 'true', cannot-decide 'unknown', clean miss 'false').
  def clause_value(c, ctx)
    return predicate_matches(c['when'], ctx) ? 'true' : 'false' if c['kind'] == 'permit'
    return 'false' unless Prohibitions.when_matches?(c['when'], ctx)

    predicate_matches(c['when'], ctx) ? 'true' : 'unknown'
  end

  def clause_rank(signer, precedence)
    i = signer.nil? ? nil : precedence.index(signer)
    i.nil? ? precedence.length : i # an unlisted signer ranks last
  end

  def malformed_clause_decision
    { 'decision' => 'deny', 'witness' => { 'winner' => { 'kind' => 'malformed', 'id' => nil }, 'shadowed' => [] }, 'values' => [] }
  end

  # Decide a clause list against an action. `opts`: 'precedence' (signers, most authoritative first), 'permitSigners'.
  def decide_clauses(clauses, ctx, opts = nil)
    return malformed_clause_decision unless clauses_error(clauses).nil?

    a = ctx.is_a?(Hash) ? ctx['action'] : nil
    return malformed_clause_decision if !a.is_a?(Hash) || !a['verb'].is_a?(String) || !a['resource'].is_a?(String)

    opts ||= {}
    precedence = opts['precedence'] || []
    permit_signers = opts['permitSigners']
    active = clauses.map { |c| c['kind'] != 'permit' || permit_signers.nil? || (!c['signer'].nil? && permit_signers.include?(c['signer'])) }
    values = clauses.each_with_index.map { |c, i| { 'id' => c['id'], 'kind' => c['kind'], 'value' => active[i] ? clause_value(c, ctx) : 'false' } }
    hit = ->(k) { clauses.each_index.select { |i| clauses[i]['kind'] == k && values[i]['value'] != 'false' }.map { |i| clauses[i] } }
    forbids = hit.call('forbid').sort_by { |c| [clause_rank(c['signer'], precedence), utf16_key(c['id'])] }
    permits = hit.call('permit')
    escalates = hit.call('escalate')
    others = ->(win) { (forbids + permits + escalates).reject { |c| c.equal?(win) }.map { |c| c['id'] } }
    if forbids.any?
      w = forbids[0]
      kind = 'forbid'
      decision = 'deny'
    elsif permits.empty?
      w = nil
      kind = 'none'
      decision = 'deny'
    elsif escalates.any?
      w = escalates[0]
      kind = 'escalate'
      decision = 'escalate'
    else
      w = permits[0]
      kind = 'permit'
      decision = 'allow'
    end
    { 'decision' => decision, 'witness' => { 'winner' => { 'kind' => kind, 'id' => w&.fetch('id') }, 'shadowed' => others.call(w) }, 'values' => values }
  rescue StandardError, SystemStackError
    malformed_clause_decision
  end

  # The canonical certificate for a decision.
  def certify_clauses(clauses, ctx, opts = nil)
    d = decide_clauses(clauses, ctx, opts)
    by_id = clauses.to_h { |c| [c['id'], c] }
    { 'v' => FORBID_CERT_VERSION, 'kind' => FORBID_CERT_KIND, 'policy' => hash_canonical(clauses), 'action' => hash_canonical(ctx),
      'decision' => d['decision'], 'winner' => d['witness']['winner'], 'shadowed' => d['witness']['shadowed'],
      'clauses' => d['values'].map do |v|
        row = { 'id' => v['id'], 'kind' => v['kind'] }
        s = by_id[v['id']]['signer']
        row['signer'] = s unless s.nil?
        row.merge('value' => v['value'])
      end }
  end

  # Recompute the certificate from the clauses and the action; it must match byte for byte (canonical form).
  def check_forbid_certificate(cert, clauses, ctx, opts = nil)
    return { 'ok' => false, 'reason' => 'malformed clauses' } unless clauses_error(clauses).nil?
    return { 'ok' => false, 'reason' => 'certificate table does not entail its decision' } unless forbid_certificate_consistent?(cert, (opts || {})['precedence'] || [])
    return { 'ok' => false, 'reason' => 'certificate does not match the recomputed decision' } if hash_canonical(certify_clauses(clauses, ctx, opts)) != hash_canonical(cert)

    { 'ok' => true }
  rescue StandardError, SystemStackError
    { 'ok' => false, 'reason' => 'certificate check error (fail closed)' }
  end
end
