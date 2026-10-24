# frozen_string_literal: true
# The PUBLIC-API twin of a differential case (the Intent Layer v2 public layer, intent_v2.rb "public API" section).
#
# Why: every AtlasPca.<intent v2 fn> is a one-line wrapper `IntentV2.fn(V2JS.jsnorm(arg), ...)`; jsnorm is the documented
# contract that a caller may pass Symbol keys and integral Floats (5.0 IS the JSON number 5). The differential oracles feed
# values parsed from JSON (String keys, Integer numbers) and most of them call IntentV2.* directly, so a mutant that drops
# a jsnorm, swaps a wrapper argument, deletes a wrapper def or a re-exported constant was invisible to all of them: 203 of the
# 674 intent_v2.rb survivors of run 39902549441 sat in that layer (another 80 in V2JS). A twin runs the same oracle case
# through the PUBLIC wrapper with every argument the wrapper normalizes rewritten to its non-JSON spelling (Symbol keys,
# integral Floats); the answer must be the oracle's.
module MutationKill
  module PubTwin
    module_function

    MAX_SAFE = (2**53) - 1

    # Symbol keys (a key that is not valid UTF-8 - a lone surrogate - has no Symbol: kept) and integral Floats, deeply.
    def twin(x)
      case x
      when Hash then x.to_h { |k, v| [k.is_a?(String) && k.valid_encoding? ? k.to_sym : k, twin(v)] }
      when Array then x.map { |v| twin(v) }
      when Integer then x.abs <= MAX_SAFE ? x.to_f : x
      else x
      end
    end

    # true when the twin changes anything at all (a scalar string twin proves nothing about the wrapper's jsnorm)
    def differs?(x) = !twin(x).eql?(x)
  end
end
