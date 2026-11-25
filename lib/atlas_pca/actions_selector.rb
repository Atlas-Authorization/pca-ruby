# frozen_string_literal: true

# Trait selectors and the registry-growth semantics (native port of selector.ts of the TypeScript reference @atlasauth/pca-actions).
module AtlasPca
  module ActionsSelector
    module_function

    # An unknown selector kind yields nil (falsy), as the reference.
    def selector_matches(s, closure)
      cl = closure.to_a
      case s['k']
      when 'trait' then cl.include?(s.fetch('id'))
      when 'all_of' then s.fetch('ids').all? { |i| cl.include?(i) }
      when 'any_of' then s.fetch('ids').any? { |i| cl.include?(i) }
      when 'not' then !selector_matches(s.fetch('s'), cl)
      when 'and' then selector_matches(s.fetch('a'), cl) ? (selector_matches(s.fetch('b'), cl) ? true : false) : false
      end
    end

    # Unconfirmed = maximally dangerous: every prohibit selector matches it, no allow selector ever does.
    def selector_matches_for(s, mode, closure, confirmed)
      return mode == 'prohibit' unless confirmed

      selector_matches(s, closure)
    end

    def selector_has_not(s)
      case s['k']
      when 'not' then true
      when 'and' then selector_has_not(s.fetch('a')) || selector_has_not(s.fetch('b'))
      else false
      end
    end

    def any_of?(x)
      case x['k']
      when 'any_of' then true
      when 'and' then any_of?(x.fetch('a')) || any_of?(x.fetch('b'))
      else false
      end
    end

    # T7 typing rule for an ALLOW selector: no negation, and any_of only in a pinned allow. nil = allowed.
    def allow_selector_error(s, pinned)
      return 'an allow selector must not use negation: the absence of a trait is never a safety claim' if selector_has_not(s)
      return 'any_of in an allow selector requires the grant to be pinned to a pack digest' if !pinned && any_of?(s)

      nil
    end

    def policy_decision(p, verb, closure, confirmed)
      cl = closure.to_a
      return 'deny' if p.fetch('prohibit').any? { |s| selector_matches_for(s, 'prohibit', cl, confirmed) }
      return(p['on_new_action'] == 'escalate' ? 'escalate' : 'deny') unless p.fetch('pinned').include?(verb)

      p.fetch('allow').any? { |s| selector_matches_for(s, 'allow', cl, confirmed) } ? 'allow' : 'deny'
    end
  end
end
