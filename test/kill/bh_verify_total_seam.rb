# frozen_string_literal: true
# verify_pcactn's TOTAL rescue (R6-05) is reached by no input on the current code, so it is pinned through a seam: the
# checked body raises, and the public entry must return the terminal wire refusal, exactly, instead of raising.
module MutationKill
  t('verify_pcactn: a fault under it is the terminal wire refusal, never an exception (seam)') do
    orig = AtlasPca.method(:verify_pcactn_unchecked)
    AtlasPca.define_singleton_method(:verify_pcactn_unchecked) { |*, **| raise TypeError, 'seam' }
    begin
      v = AtlasPca.verify_pcactn({}, {}, now: 0, audience: 'a')
      v.instance_of?(AtlasPca::Verdict) && v.allow == false && v.checks == { 'wire' => false } &&
        v.reason == 'wire: malformed input (TypeError)' && v.reasons.nil? && v.degraded.nil?
    ensure
      AtlasPca.define_singleton_method(:verify_pcactn_unchecked, orig)
    end
  end
end
