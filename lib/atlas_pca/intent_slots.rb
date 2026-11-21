# frozen_string_literal: true

# Structured intent slots: the machine-readable half of an intent statement, compiled into the policy they literally describe.
# Native port of the TypeScript reference (@atlasauth/pca-intent).
module AtlasPca
  module IntentSlots
    module_function

    def slot_conds(sc)
      out = []
      p = sc['path']
      out << { 'field' => p, 'op' => 'gte', 'value' => sc['min'] } unless sc['min'].nil?
      out << { 'field' => p, 'op' => 'lte', 'value' => sc['max'] } unless sc['max'].nil?
      any_of = []
      any_of << { 'field' => p, 'op' => 'in', 'value' => sc['oneOf'].dup } if sc['oneOf'].is_a?(Array) && !sc['oneOf'].empty?
      (sc['prefixOneOf'] || []).each { |x| any_of << { 'field' => p, 'op' => 'prefix', 'value' => x } }
      if any_of.length == 1
        out << any_of[0]
      elsif any_of.length > 1
        out << { 'any_of' => any_of }
      end
      out << { 'field' => p, 'op' => 'nin', 'value' => sc['noneOf'].dup } if sc['noneOf'].is_a?(Array) && !sc['noneOf'].empty?
      out
    end

    # One predicate per slot verb.
    def slots_to_policy(slots)
      preds = slots['verbs'].map do |verb|
        where = []
        slots['constraints'].each { |c| where.concat(slot_conds(c)) if c['verb'].nil? || c['verb'] == verb }
        pr = { 'verb' => verb, 'resource' => '*' }
        pr['where'] = where unless where.empty?
        pr
      end
      { 'predicates' => preds, 'caveats' => [] }
    end
  end
end
