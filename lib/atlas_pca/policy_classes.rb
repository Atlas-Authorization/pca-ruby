# frozen_string_literal: true

# Policy classes (packages/pca/src/policy-classes.ts): a decision is the meet of every class consulted; denied_by / escalated_by
# name who said no. Fail-strict and total. Replays packages/pca/conformance/policy-classes-vectors.json.
module AtlasPca
  POLICY_CLASSES = %w[constitution regulatory org blueprint user].freeze
  MAX_POLICY_CLASSES = POLICY_CLASSES.length
  POLICY_CLASS_KEYS = %w[class revision digest decision].freeze

  module_function

  # nil = a well-formed list: closed members, known classes, each at most once.
  def class_verdicts_error(list)
    return 'policy classes must be an array' unless list.is_a?(Array)
    return "more than #{MAX_POLICY_CLASSES} policy classes" if list.length > MAX_POLICY_CLASSES

    seen = {}
    list.each_with_index do |v, i|
      return "policy_classes[#{i}] must be an object" unless v.is_a?(Hash)

      v.each_key { |k| return "policy_classes[#{i}] has unknown member '#{k}'" unless POLICY_CLASS_KEYS.include?(k) }
      return "policy_classes[#{i}].class is not a known class" unless v['class'].is_a?(String) && POLICY_CLASSES.include?(v['class'])
      return "policy class '#{v['class']}' appears twice" if seen[v['class']]

      seen[v['class']] = true
      return "policy_classes[#{i}].revision must be a non-negative safe integer" unless k3_int?(v['revision']) && v['revision'] >= 0
      return "policy_classes[#{i}].digest invalid" unless v['digest'].is_a?(String) && !v['digest'].empty? && v['digest'].length <= 128
      return "policy_classes[#{i}].decision must be allow, escalate or deny" unless %w[allow escalate deny].include?(v['decision'])
    end
    nil
  end

  def decide_classes(list)
    none = ->(reason) { { 'decision' => 'deny', 'classes' => [], 'denied_by' => [], 'escalated_by' => [], 'reason' => reason } }
    return none.call('no_policy_class') if list.is_a?(Array) && list.empty?

    e = class_verdicts_error(list)
    return none.call("malformed policy classes: #{e}") if e

    classes = list.sort_by { |v| POLICY_CLASSES.index(v['class']) }.map { |v| POLICY_CLASS_KEYS.to_h { |k| [k, v[k]] } }
    { 'decision' => meet_all(classes.map { |c| c['decision'] }), 'classes' => classes,
      'denied_by' => classes.select { |c| c['decision'] == 'deny' }.map { |c| c['class'] },
      'escalated_by' => classes.select { |c| c['decision'] == 'escalate' }.map { |c| c['class'] } }
  rescue StandardError
    none.call('evaluation error (fail closed)')
  end
end
