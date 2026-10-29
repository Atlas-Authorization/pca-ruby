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
end
