# frozen_string_literal: true

# Signed human confirmation, producer side (native port of the signing half of confirmation.ts of the TypeScript reference
# @atlasauth/pca-actions). The verifier half (review_message, verb_confirmation_error) lives in actions.rb.
require_relative 'actions'
require_relative 'agent'

module AtlasPca
  module ActionsConfirmation
    A = AtlasPca::Actions

    module_function

    # True iff the dismissal reason is nothing but whitespace and the C0 separators.
    def blank_reason(s) = A.blank_reason?(s)

    def review_message(b) = A.review_message(b)

    # nil iff this schema verb carries a VALID human confirmation (confirmation.ts wording); else the reason. Never raises.
    def verb_confirmation_error(v, reg, pins)
      js = A.js
      return 'no reviewer keys are pinned' if pins.nil?

      pe = A.reviewer_pins_error(pins)
      return "bad pins: #{pe}" if pe
      return 'no confirmation' unless v.key?('confirmation')

      a = v['confirmation']
      return 'confirmation is not an object' if a.nil? || !(a.is_a?(Hash) || a.is_a?(Array))
      return 'the confirmation is unsigned' unless a.is_a?(Hash) && a['sig'].is_a?(String)
      return 'the confirmation covers a different def digest' if !v['def'].is_a?(String) || a['def_digest'] != v['def']

      accepted = [A.traits_digest(reg)] + (pins['traits_digests'] || [])
      return 'the confirmation was made against a different trait registry' unless accepted.include?(a['traits_digest'])
      return 'the verb facts differ from the facts the reviewer confirmed' if !a['facts_digest'].is_a?(String) || a['facts_digest'] != A.facts_digest(v)

      ft = a['final_traits']
      dm = a['dismissed']
      return 'malformed confirmation' if !ft.is_a?(Array) || !dm.is_a?(Array) || !js.int?(a['ts']) || js.neg_zero?(a['ts']) || !a['reviewer_kid'].is_a?(String)

      carried = case v['traits'] # new Set(v.traits ?? []): a string contributes its characters, a non-iterable throws
                when nil then []
                when Array then v['traits']
                when String then v['traits'].chars
                else raise TypeError, 'value is not iterable'
                end
      return 'the verb does not carry every trait the reviewer signed' if ft.any? { |t| !t.is_a?(String) || !carried.include?(t) }
      return 'a dismissed trait is also final, or has no reason' if dm.any? { |d| !d.is_a?(Hash) || !d['trait'].is_a?(String) || !d['reason'].is_a?(String) || ft.include?(d['trait']) || A.blank_reason?(d['reason']) }

      key = pins['keys'].find { |k| k['kid'] == a['reviewer_kid'] }
      return "no pinned key '#{a['reviewer_kid']}'" if key.nil?
      return "key '#{key['kid']}' does not hold the reviewer role" unless key['roles'].include?('reviewer')
      return 'the confirmation time is outside the key validity' if (key.key?('not_before') && a['ts'] < key['not_before']) || (key.key?('not_after') && a['ts'] > key['not_after'])

      AtlasPca.verify_b64u(key['pk'], A.review_message(a.reject { |k, _| k == 'sig' }), a['sig']) ? nil : 'the confirmation signature is invalid'
    rescue StandardError => e
      "malformed confirmation: #{e.message}"
    end

    # The ReviewRef for body `b` (final_traits sorted and distinct, dismissed sorted by trait), signed with a 32-byte Ed25519 seed.
    def sign_review(b, secret)
      raise ArgumentError, 'the reviewer key must be a 32-byte Ed25519 secret' unless secret.is_a?(String) && secret.bytesize == 32

      norm = b.dup
      norm['final_traits'] = A.sort_uniq(b['final_traits'])
      norm['dismissed'] = b['dismissed'].sort_by { |d| A.u16key(d['trait']) }
      norm.merge('sig' => AtlasPca.b64e(AtlasPca::KeyPair.new(secret).sign(A.review_message(norm))))
    end
  end
end
