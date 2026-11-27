# frozen_string_literal: true
# Premises that ledger proofs rest on, asserted on every CI Ruby so a Ruby that disagrees fails the suite instead of silently
# invalidating an equivalent-mutant entry (the mutation workflow pins ruby-version '3.3').
module MutationKill
  t('ledger premise: Kernel#Float reads a leading +, a bare leading ., and both together, itself (js_number .sub entries)') do
    Float('+1.5') == 1.5 && Float('.5') == 0.5 && Float('-.5') == -0.5 && Float('+.5') == 0.5 && Float('+5') == 5.0 && Float('-5') == -5.0
  end
end
