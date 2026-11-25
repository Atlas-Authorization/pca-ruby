# frozen_string_literal: true

# The confirmation flow and signed review attestations (native port of import/review.ts of the TypeScript reference
# @atlasauth/pca-actions): the attestation verdict with its reasons, review status, the review queue and view, and the producer side
# (confirm_def). A def WITHOUT a valid attestation has the top of the registry as its effective traits; one counts only when a key
# pinned with the reviewer role signed this exact def digest.
require_relative 'actions'
require_relative 'actions_confirmation'
require_relative 'actions_derive'
require_relative 'actions_effective'
require_relative 'js_compat'

module AtlasPca
  module ActionsReview
    A = AtlasPca::Actions
    E = AtlasPca::ActionsEffective
    UNDEF = AtlasPca::V2JS::UNDEF
    SUSPECT = %w[pca.money_moving pca.privilege_change pca.code_execution pca.destructive pca.external_communication].freeze
    NEXT = %w[pca.credential_access pca.data_export pca.regulated_data pca.public_exposure pca.infra_mutation pca.legal_binding pca.impersonation pca.persistence].freeze

    module_function

    def fail_v(reason, detail) = { 'ok' => false, 'reason' => reason, 'detail' => detail }

    # Number.isSafeInteger(v) and not -0 (any sign: a negative ts is judged later by the key validity).
    def safe_ts?(v) = A.js.int?(v)

    # {ok: true, kid} iff the confirmation is valid, else {ok: false, reason, detail}. Never raises.
    def verify_attestation_verdict(d, reg, pins)
      pe = A.reviewer_pins_error(pins)
      return fail_v('bad_pins', pe) if pe

      review = d.is_a?(Hash) ? d['review'] : nil
      return fail_v('not_confirmed', 'review.state is not confirmed') if (review || {})['state'] != 'confirmed'
      return fail_v('no_attestation', 'a confirmed def carries an attestation') unless review.key?('attestation')

      a = review['attestation']
      return fail_v('malformed', "Cannot read properties of null (reading 'sig')") if a.nil?

      a = {} unless a.is_a?(Hash) # a scalar or array has no members: unsigned
      return fail_v('no_signature', 'the attestation is unsigned') unless a['sig'].is_a?(String)
      return fail_v('malformed', 'the attestation facts_digest must be a string') unless a['facts_digest'].is_a?(String)

      ft = a['final_traits']
      dis = a['dismissed']
      if !ft.is_a?(Array) || !ft.all?(String) || !dis.is_a?(Array) || !dis.all? { |x| x.is_a?(Hash) && x['trait'].is_a?(String) && x['reason'].is_a?(String) } ||
         !safe_ts?(a['ts']) || !a['reviewer_kid'].is_a?(String)
        return fail_v('malformed', 'the attestation final_traits, dismissed, ts or reviewer_kid is malformed')
      end
      return fail_v('digest_mismatch', 'the def changed after it was reviewed') if a['def_digest'] != A.def_digest(d)

      accepted = [A.traits_digest(reg)] + (pins['traits_digests'] || [])
      return fail_v('traits_digest_mismatch', 'the trait registry changed since the review') unless accepted.include?(a['traits_digest'])
      return fail_v('final_traits_mismatch', "the attested final traits are not the def's declared traits") if A.sort_uniq(ft) != A.sort_uniq(d['traits'])
      return fail_v('dismissed_conflict', 'a dismissed trait is also final, or has no reason') if dis.any? { |x| ft.include?(x['trait']) || A.blank_reason?(x['reason']) }

      key = pins['keys'].find { |k| k['kid'] == a['reviewer_kid'] }
      return fail_v('unknown_reviewer', "no pinned key '#{a['reviewer_kid']}'") if key.nil?
      return fail_v('not_a_reviewer', "key '#{key['kid']}' does not hold the reviewer role") unless key['roles'].include?('reviewer')
      return fail_v('outside_validity', 'the attestation time is outside the key validity') if (key.key?('not_before') && a['ts'] < key['not_before']) || (key.key?('not_after') && a['ts'] > key['not_after'])

      return { 'ok' => true, 'kid' => key['kid'] } if AtlasPca.verify_b64u(key['pk'], A.review_message(a.reject { |k, _| k == 'sig' }), a['sig'])

      fail_v('bad_signature', 'the attestation signature is invalid')
    rescue StandardError => e
      fail_v('malformed', e.message)
    end

    # The callback the algebra takes: a confirmed def counts only if the attestation verdict is ok.
    def attestation_verifier(reg, pins) = ->(d) { verify_attestation_verdict(d, reg, pins)['ok'] }

    # The state that counts: a `confirmed` def with an invalid attestation is `stale` (it behaves as unreviewed).
    def review_status(d, reg, pins)
      return d['review']['state'] if d['review']['state'] != 'confirmed'

      verify_attestation_verdict(d, reg, pins)['ok'] ? 'confirmed' : 'stale'
    end

    # Defs whose confirmation no longer holds go back to `unreviewed` (the attestation is dropped).
    def revert_stale(d, reg, pins)
      return d if review_status(d, reg, pins) != 'stale'

      d.merge('review' => d['review'].reject { |k, _| k == 'attestation' }.merge('state' => 'unreviewed'))
    end

    def intrinsic(d, reg) = E.effective_with(d, reg)['hint']

    # 0 = a core suspect trait (money, privilege, code, destructive, outbound communication), 1 = other risky, 2 = the rest.
    def review_priority(d, reg)
      cl = intrinsic(d, reg)['closure']
      return 0 if SUSPECT.any? { |t| cl.include?(t) }
      return 1 if NEXT.any? { |t| cl.include?(t) }

      2
    end

    # Defs in review order: suspect traits first, then by risk (highest first), then by verb.
    def review_queue_order(defs, reg)
      defs.map { |d| [review_priority(d, reg), intrinsic(d, reg)['eff']['risk'], d] }.sort_by { |p, r, d| [p, -r, A.u16key(d['verb'])] }.map(&:last)
    end

    def sj(o, k) = o.key?(k) ? AtlasPca::Js.json(o[k]) : 'undefined'

    # What the reviewer is shown: the def's facts, the traits it would carry once signed, the policy card and (with `previous`) what changed.
    def prepare_review(d, reg, previous = nil)
      eff = E.effective_with(d, reg)
      shown = eff.merge(eff['hint']).merge('confirmed' => true)
      sb = d['review']['suggested_by'] || {}
      changes = []
      unless previous.nil?
        skip = %w[review examples source since]
        a = previous.reject { |k, _| skip.include?(k) }
        b = d.reject { |k, _| skip.include?(k) }
        changes = (a.keys | b.keys).select { |k| sj(a, k) != sj(b, k) }.sort_by { |k| A.u16key(k) }
      end
      {
        'verb' => d['verb'], 'def_digest' => A.def_digest(d), 'state' => d['review']['state'], 'declared_traits' => A.sort_uniq(d['traits']),
        'implied_traits' => E.implied_traits(A.normalize(d)), 'suggested' => sb['added'].nil? ? { 'traits' => [], 'roles' => {}, 'tags' => {} } : sb['added'],
        'effective' => eff, 'card' => ActionsDerive.card_of(d, shown, reg), 'changes' => changes, 'priority' => review_priority(d, reg)
      }
    end

    def bad_confirm(msg) = raise(A::ActionKitError.new('bad_confirm', msg))

    # Review one def: validate the decision, write the final traits, sign an attestation over the resulting digest, return the confirmed def.
    # o: {registry, reviewer: {kid, secret}, pins?, final_traits, dismissed?, ts}. Raises bad_confirm / undismissed_suggestion / not_reviewer.
    def confirm_def(d, o)
      reg = o['registry']
      ts = o['ts']
      bad_confirm('ts must be a non-negative integer') if !safe_ts?(ts) || ts.negative?
      final = A.sort_uniq(o['final_traits'])
      bad_confirm('final traits must be distinct') if final.length != o['final_traits'].length
      final.each do |t|
        bad_confirm("unknown trait '#{t}'") if !t.is_a?(String) || !A::TRAIT_ID_RE.match?(t) || !reg.key?(t)
        bad_confirm("'pca.unreviewed' is the review marker, not a final trait") if t == 'pca.unreviewed'
      end
      dismissed = (o['dismissed'] || []).map { |x| { 'trait' => x['trait'], 'reason' => x['reason'] } }
      dset = []
      dismissed.each do |x|
        bad_confirm("dismissed trait '#{x['trait']}' needs a reason (1..256 characters)") if !x['reason'].is_a?(String) || AtlasPca::Js.trim(x['reason']).empty? || A.u16len(x['reason']) > 256
        bad_confirm("trait '#{x['trait']}' is dismissed twice") if dset.include?(x['trait'])

        dset << x['trait']
        bad_confirm("trait '#{x['trait']}' is both final and dismissed") if final.include?(x['trait'])
      end
      sb = d['review']['suggested_by'] || {}
      shown = A.sort_uniq((d['traits'] || []) + (((sb['added'] || {})['traits']) || []))
      covered = A.closure(reg, A.sort_uniq(final + E.implied_traits(A.normalize(d))))
      shown.each do |t|
        next if final.include?(t) || covered.include?(t)

        raise A::ActionKitError.new('undismissed_suggestion', "trait '#{t}' was suggested and is not in the final set: record it as dismissed with a reason") unless dset.include?(t)
      end
      dset.each { |t| bad_confirm("trait '#{t}' was never suggested; nothing to dismiss") unless shown.include?(t) }
      rv = o['reviewer']
      if o['pins'] && !(o['pins'].respond_to?(:empty?) && o['pins'].empty?)
        pe = A.reviewer_pins_error(o['pins'])
        bad_confirm(pe) if pe
        key = o['pins']['keys'].find { |k| k['kid'] == rv['kid'] }
        raise A::ActionKitError.new('not_reviewer', "key '#{rv['kid']}' is not pinned with the reviewer role") if key.nil? || !key['roles'].include?('reviewer')
        raise A::ActionKitError.new('not_reviewer', "the secret does not belong to the pinned key '#{rv['kid']}'") if key['pk'] != AtlasPca::KeyPair.new(rv['secret']).public
      end
      body = d.merge('traits' => final)
      body.delete('traits') if final.empty?
      digest = A.def_digest(body)
      att = ActionsConfirmation.sign_review({ 'def_digest' => digest, 'traits_digest' => A.traits_digest(reg), 'facts_digest' => A.facts_digest(ActionsDerive.to_schema_verb(body, reg)['verb']),
                                              'final_traits' => final, 'dismissed' => dismissed, 'reviewer_kid' => rv['kid'], 'ts' => ts }, rv['secret'])
      out = body.merge('review' => d['review'].merge('state' => 'confirmed', 'attestation' => att))
      bad = A.validate_def(out)
      bad_confirm("the confirmed def is invalid: #{bad}") unless bad.nil?
      out
    end
  end
end
