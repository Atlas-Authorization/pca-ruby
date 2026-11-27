# frozen_string_literal: true

require_relative 'js_compat'
require_relative 'predicates'

module AtlasPca
  # Data-flow governance, DLP for agents: declare data classes (a resource matcher plus the maximum taint that may flow to them
  # autonomously) and evaluate an action's provenance against them. Pure and offline. An ADVISORY HEURISTIC: taint levels are labels
  # something upstream attached; this checks them against ceilings and never tracks data through a program.
  #
  # A policy is {'classes' => [{'name','resource','verbs'?,'maxTaintForAuto','hardDenyAbove'?}], 'defaultMaxTaintForAuto'?}; a context is
  # {'verb','resource','taint','trustedRefs'?}; a result is {'outcome' => allow|step_up|deny, 'class'?, 'reason'?}.
  module Dlp
    module_function

    def num?(x) = Js.num?(x) && !(x.is_a?(Float) && x.nan?)

    def matches?(pattern, resource)
      return true if pattern == '*'
      raise ArgumentError, 'DLP: a class resource must be a string' unless pattern.is_a?(String)

      if pattern.end_with?('*')
        raise ArgumentError, 'DLP: the resource must be a string' unless resource.is_a?(String)

        return resource.start_with?(pattern[0...-1])
      end
      pattern == resource
    end

    def specificity(pattern)
      return 0 if pattern == '*'
      return pattern.length - 1 if pattern.end_with?('*')

      pattern.length + 1000 # exact beats any prefix
    end

    # a malformed ceiling sorts first, so the policy then denies instead of picking a lenient sibling; an absent ceiling sorts last
    def strictness(cls)
      return Float::INFINITY unless cls.key?('maxTaintForAuto')

      m = cls['maxTaintForAuto']
      num?(m) ? m.to_f : -Float::INFINITY
    end

    def verb_matches?(cls, verb)
      vs = cls['verbs']
      return true unless Js.truthy?(vs)
      return vs.include?(verb) if vs.is_a?(Array)
      return vs.include?(verb.is_a?(String) ? verb : Js.string(verb)) if vs.is_a?(String)

      raise ArgumentError, 'DLP: verbs must be a list'
    end

    # JS Array#sort comparator result of a numeric difference (NaN and 0 are ties)
    def cmp(x) = x.nan? || x.zero? ? 0 : (x.negative? ? -1 : 1)

    # The most specific matching class (longest non-wildcard prefix wins, exact beats prefix); of equals the STRICTEST wins. nil for none.
    def class_for(classes, ctx)
      applicable = []
      classes.each do |c|
        raise ArgumentError, 'DLP: a class must be an object' unless c.is_a?(Hash)

        applicable << c if matches?(c['resource'], ctx['resource']) && verb_matches?(c, ctx['verb'])
      end
      return nil if applicable.empty?

      applicable.each_with_index.min_by do |c, i|
        [-specificity(c['resource']), strictness(c), i]
      end.first
    end

    # A ceiling that is present but not a number would make every comparison false and allow everything.
    def malformed?(policy, cls)
      if cls
        return (cls.key?('maxTaintForAuto') && !num?(cls['maxTaintForAuto'])) || (cls.key?('hardDenyAbove') && !num?(cls['hardDenyAbove']))
      end
      policy.key?('defaultMaxTaintForAuto') && !num?(policy['defaultMaxTaintForAuto'])
    end

    def result(outcome, cls, reason)
      r = { 'outcome' => outcome }
      r['class'] = cls['name'] if cls && cls.key?('name')
      r['reason'] = reason if reason
      r
    end

    # Evaluate an action's data flow against the DLP policy. Fails CLOSED: a malformed policy or ceiling is a deny, and a taint that is
    # not a finite number is treated as maximally tainted so it can never beat a ceiling.
    def evaluate_dlp(policy, ctx)
      return result('deny', nil, 'malformed DLP policy') unless policy.is_a?(Hash) && policy['classes'].is_a?(Array)

      cls = class_for(policy['classes'], ctx)
      return result('deny', cls, 'malformed DLP policy: ceilings must be numbers') if malformed?(policy, cls)

      src = cls || policy
      key = cls ? 'maxTaintForAuto' : 'defaultMaxTaintForAuto'
      return result('allow', cls, nil) unless src.key?(key) # no ceiling at all: nothing to compare against

      max = src[key]
      t = ctx['taint']
      bad = !(num?(t) && !(t.is_a?(Float) && t.infinite?)) # an unreadable taint can never beat a ceiling, not even an infinite one
      taint = bad ? Float::INFINITY : t
      label = cls && !cls['name'].nil? ? Js.string(cls['name']) : '<default>'
      if cls && cls.key?('hardDenyAbove') && (bad || taint > cls['hardDenyAbove'])
        return result('deny', cls, "taint #{Js.string(taint)} exceeds hard ceiling #{Js.string(cls['hardDenyAbove'])} for '#{label}'")
      end
      return result('step_up', cls, "taint #{Js.string(taint)} > #{Js.string(max)} for '#{label}' — needs human review") if bad || taint > max

      result('allow', cls, nil)
    end

    # Preset: PII resources accept only clean (taint 0) autonomously; secrets hard-deny any taint.
    def default_dlp_policy(opts = {})
      raise ArgumentError, 'defaultDlpPolicy: opts must not be null' if opts.nil?

      classes = []
      classes << { 'name' => 'pii', 'resource' => opts['piiResource'], 'maxTaintForAuto' => 0, 'hardDenyAbove' => 2 } if Js.truthy?(opts['piiResource'])
      classes << { 'name' => 'secrets', 'resource' => opts['secretsResource'], 'maxTaintForAuto' => 0, 'hardDenyAbove' => 0 } if Js.truthy?(opts['secretsResource'])
      { 'classes' => classes }
    end
  end
end
